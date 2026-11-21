"""
Net365 saved numbers, saved card (one-tap pay) and automated chat updates.

Everything here is OPT-IN:
  * Saved numbers: the customer taps "Save" after a purchase. Phone / meter numbers are stored encrypted.
  * Saved card: the customer chooses "Pay and save card" once. We keep only Paystack's reusable
    authorization token (never card numbers) and charge it later through Paystack, after the customer's
    Net365 PIN. This is not a wallet: Net365 holds no balance.
  * Updates: short "what Net365 can do" tips, promos and re-top-up nudges in chat, capped in frequency,
    only in daytime, stopped by "stop updates".
"""
import hashlib
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone

import requests
from flask import Blueprint, jsonify, request, g

import net365_whatsapp as W

log = logging.getLogger(__name__)
sv_bp = Blueprint("saved_cards_and_numbers", __name__)
_d = {}
_schema_done = False


# --------------------------------------------------------------------------- settings
def _on(name, default="false"):
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def card_enabled():
    return _on("SAVED_CARD_ENABLED", "false")


def _card_max():
    try:
        return float(os.getenv("SAVED_CARD_MAX_NGN", "20000"))
    except ValueError:
        return 20000.0


def _conn():
    return _d["db"].get_db_connection()


def _ensure():
    global _schema_done
    if _schema_done:
        return
    c = _conn()
    for sql in (
        """CREATE TABLE IF NOT EXISTS saved_beneficiaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT NOT NULL,
            label TEXT, target_enc TEXT NOT NULL, target_hash TEXT NOT NULL, target_mask TEXT,
            operator_id TEXT, operator_name TEXT, biller_id TEXT, biller_name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_used_at TEXT,
            UNIQUE(user_id, kind, target_hash))""",
        """CREATE TABLE IF NOT EXISTS saved_cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, auth_enc TEXT NOT NULL,
            signature TEXT, last4 TEXT, brand TEXT, bank TEXT, exp TEXT, email TEXT,
            active INTEGER NOT NULL DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, signature))""",
        """CREATE TABLE IF NOT EXISTS chat_engage (
            wa_number TEXT PRIMARY KEY, last_sent_at TEXT, idx INTEGER NOT NULL DEFAULT 0,
            sent_count INTEGER NOT NULL DEFAULT 0)""",
        "CREATE INDEX IF NOT EXISTS idx_saved_ben_user ON saved_beneficiaries(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_saved_cards_user ON saved_cards(user_id)",
    ):
        try:
            c.execute(sql)
        except Exception:
            log.exception("saved schema step failed")
    try:
        c.commit()
    except Exception:
        pass
    _schema_done = True


def _hash(kind, value):
    return hashlib.sha256(f"{os.getenv('SECRET_KEY', '')}|{kind}|{value}".encode()).hexdigest()


def _payload(tx):
    p = tx.get("payload") or {}
    if isinstance(p, str):
        import json
        try:
            p = json.loads(p)
        except Exception:
            p = {}
    try:
        p = _d["decrypt_payload"](dict(p)) if _d.get("decrypt_payload") else p
    except Exception:
        pass
    return p


def _plain(v):
    """Decrypt a PII field that may be encrypted or already plain."""
    try:
        out = _d["decrypt"](v)
        return out if out else v
    except Exception:
        return v


def _national(phone):
    digits = re.sub(r"\D", "", str(phone or ""))
    if digits.startswith("234") and len(digits) == 13:
        digits = digits[3:]
    elif digits.startswith("0") and len(digits) == 11:
        digits = digits[1:]
    return digits[-10:] if len(digits) >= 10 else digits


def _link_user(wa):
    """(link, user_id) for a non-guest linked chat, else (link, None)."""
    link = W._get_link(wa) if wa else None
    if not link or link.get("is_guest"):
        return link, None
    return link, link.get("user_id")


# --------------------------------------------------------------------------- saved numbers
def _view(r):
    return {"id": r["id"], "kind": r["kind"], "label": r["label"], "masked": r["target_mask"],
            "operator_name": r["operator_name"], "biller_name": r["biller_name"]}


def already_saved(user_id, tx_type, payload):
    _ensure()
    if tx_type == "topup":
        kind, target = "airtime", _national(_plain(payload.get("phone")))
    elif tx_type == "utility":
        kind, target = "utility", str(payload.get("subscriber_account") or "").strip()
    else:
        return True
    if not target:
        return True
    row = _conn().execute("SELECT id FROM saved_beneficiaries WHERE user_id=? AND kind=? AND target_hash=?",
                          (user_id, kind, _hash(kind, target))).fetchone()
    return bool(row)


def card_for_user(user_id):
    _ensure()
    row = _conn().execute("SELECT * FROM saved_cards WHERE user_id=? AND active=1 ORDER BY id DESC LIMIT 1",
                          (user_id,)).fetchone()
    return dict(row) if row else None


def save_card_from_auth(user_id, email, auth):
    """Keep Paystack's reusable authorization (opt-in: only called when the customer chose to save)."""
    if not card_enabled() or not isinstance(auth, dict):
        return False
    code = auth.get("authorization_code")
    if not code or not auth.get("reusable") or str(auth.get("channel") or "card") != "card":
        return False
    _ensure()
    if _d["encrypt"]("probe") == "probe":
        log.error("Refusing to save a card token: ENCRYPTION_KEY is not set, so it would be stored in plain text.")
        return False
    sig = auth.get("signature") or code
    c = _conn()
    try:
        c.execute("UPDATE saved_cards SET active=0 WHERE user_id=?", (user_id,))
        c.execute(
            "INSERT INTO saved_cards (user_id, auth_enc, signature, last4, brand, bank, exp, email, active) "
            "VALUES (?,?,?,?,?,?,?,?,1) ON CONFLICT(user_id, signature) DO UPDATE SET "
            "auth_enc=excluded.auth_enc, active=1, last4=excluded.last4",
            (user_id, _d["encrypt"](code), sig, str(auth.get("last4") or "")[:4],
             str(auth.get("card_type") or auth.get("brand") or "").strip()[:20], str(auth.get("bank") or "")[:40],
             f"{auth.get('exp_month', '')}/{auth.get('exp_year', '')}", email))
        c.commit()
        log.info("Saved card ••%s for user %s", auth.get("last4"), user_id)
        return True
    except Exception:
        log.exception("save card failed")
        return False


# --------------------------------------------------------------------------- charging
def _charge(card, email, total, reference):
    """Charge a saved Paystack authorization. Returns (ok, message)."""
    key = os.getenv("PAYSTACK_SECRET_KEY", "")
    if not key:
        return False, "Card payments are not configured."
    try:
        r = requests.post(
            "https://api.paystack.co/transaction/charge_authorization",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"authorization_code": _d["decrypt"](card["auth_enc"]), "email": email,
                  "amount": int(round(total * 100)), "currency": "NGN", "reference": reference},
            timeout=45)
        body = r.json() if r.content else {}
        data = body.get("data") or {}
        if r.status_code == 200 and body.get("status") and str(data.get("status")).lower() == "success":
            return True, ""
        return False, str(data.get("gateway_response") or body.get("message") or "The card was not charged.")[:120]
    except Exception as e:
        log.exception("charge_authorization failed")
        return False, "Could not reach the card processor."


def _mark_failed(reference):
    try:
        c = _conn()
        c.execute("UPDATE transactions SET status='failed', updated_at=CURRENT_TIMESTAMP WHERE reference=? "
                  "AND status='pending'", (reference,))
        c.commit()
    except Exception:
        log.exception("mark failed")


# --------------------------------------------------------------------------- engagement
def _tips():
    tips = [
        ("📱 Airtime in 20 seconds", "Top up any Nigerian network from right here. No app, no forms.",
         [("📱 Buy airtime", "AIRTIME")]),
        ("⚡ Pay electricity & cable TV", "Prepaid or postpaid meters, DStv, GOtv and more. Your token arrives right here.",
         [("⚡ Pay a bill", "BILLS")]),
        ("⭐ Save your numbers", "Save Mum's number or your meter once, then top up in two taps.",
         [("⭐ My saved", "SAVED"), ("📱 Airtime", "AIRTIME")]),
        ("🎁 Invite friends, earn points", "Share your link. You earn Net365 points when friends join and buy.",
         [("🎁 Invite friends", "INVITE")]),
        ("🎮 Earn points on every purchase", "Points, levels and streaks. Check *offers* for deals from our partners.",
         [("📣 Offers", "OFFERS"), ("📱 Airtime", "AIRTIME")]),
    ]
    try:
        import net365_giftcards as GC
        if GC.enabled():
            tips.insert(2, ("🎁 Gift cards", "Steam, Netflix, Spotify and more, paid in naira. Codes delivered here.",
                            [("🎁 Gift cards", "GIFTCARD")]))
    except Exception:
        pass
    return tips


def _lagos_hour():
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo("Africa/Lagos")).hour
    except Exception:
        return (datetime.now(timezone.utc).hour + 1) % 24


def _engage_message(link, idx):
    """Pick one message for this chat. Returns a dict for the bot or None."""
    wa, uid = link["wa_number"], link.get("user_id")
    base = os.getenv("NET365_PUBLIC_URL", "").rstrip("/")
    # 1) personalised re-top-up nudge (linked users with a saved number not used for 3 weeks)
    if uid and not link.get("is_guest"):
        row = _conn().execute(
            "SELECT * FROM saved_beneficiaries WHERE user_id=? AND kind='airtime' "
            "AND COALESCE(last_used_at, created_at) <= datetime('now','-21 days') ORDER BY RANDOM() LIMIT 1",
            (uid,)).fetchone()
        if row:
            row = dict(row)
            return {"title": f"📱 Time to top up {row['label']}?",
                    "body": "It has been a while. Two taps and it's done.",
                    "buttons": [{"id": f"SV_{row['id']}", "title": f"Top up {str(row['label'])[:16]}"}]}
    # 2) every other message: a real promo if one exists, otherwise a tip
    if idx % 2 == 1:
        ad = W._pick_ad("topup", 0, f"engage-{wa}-{idx}", uid)
        if ad and ad.get("id"):
            return {"title": ad.get("title") or "From Net365", "body": (ad.get("body") or "")[:220],
                    "sponsored": ad.get("sponsored"), "advertiser": ad.get("advertiser"),
                    "ad_url": f"{base}/go/ad/{ad['id']}?r=engage" if ad.get("has_url") and base else None,
                    "cta": ad.get("cta") or "Learn more",
                    "buttons": [{"id": "AIRTIME", "title": "📱 Buy airtime"}]}
    tips = _tips()
    t = tips[(idx // 2) % len(tips)] if idx % 2 == 0 else tips[idx % len(tips)]
    return {"title": t[0], "body": t[1], "buttons": [{"id": i, "title": n} for n, i in t[2]]}


def engage_run_once(force_hour=None):
    """Send at most ENGAGE_MAX_PER_RUN updates to eligible chats. Returns the number sent."""
    if not _on("ENGAGE_ENABLED", "false"):
        return 0
    _ensure()
    hour = _lagos_hour() if force_hour is None else force_hour
    if not (int(os.getenv("ENGAGE_FROM_HOUR", "9")) <= hour < int(os.getenv("ENGAGE_TO_HOUR", "20"))):
        return 0
    channels = {x.strip() for x in os.getenv("ENGAGE_CHANNELS", "telegram").split(",") if x.strip()}
    gap = max(1, int(os.getenv("ENGAGE_MIN_DAYS", "3")))
    cap = max(1, int(os.getenv("ENGAGE_MAX_PER_RUN", "20")))
    W._ensure_schema() if not getattr(W, "_schema_ready", False) else None
    c = _conn()
    rows = c.execute(
        "SELECT l.* FROM whatsapp_links l LEFT JOIN chat_engage e ON e.wa_number = l.wa_number "
        "WHERE l.active = 1 AND COALESCE(l.ads_opt_out,0) = 0 "
        "AND (e.last_sent_at IS NULL OR e.last_sent_at <= datetime('now', ?)) LIMIT 500",
        (f"-{gap} days",)).fetchall()
    sent = 0
    for r in rows:
        if sent >= cap:
            break
        link = dict(r)
        chan = "telegram" if str(link["wa_number"]).startswith("999") else "whatsapp"
        if chan not in channels:
            continue
        if link.get("is_guest"):
            n = c.execute("SELECT COUNT(*) FROM transactions WHERE user_id=? AND status='fulfilled'",
                          (link["user_id"],)).fetchone()[0]
            if not n:
                continue
        e = c.execute("SELECT idx FROM chat_engage WHERE wa_number=?", (link["wa_number"],)).fetchone()
        idx = int(e[0]) if e else 0
        # claim first so two processes can never send the same message twice
        c.execute("INSERT INTO chat_engage (wa_number, last_sent_at, idx, sent_count) "
                  "VALUES (?, CURRENT_TIMESTAMP, ?, 1) ON CONFLICT(wa_number) DO UPDATE SET "
                  "last_sent_at=CURRENT_TIMESTAMP, idx=idx+1, sent_count=sent_count+1", (link["wa_number"], idx + 1))
        c.commit()
        try:
            msg = _engage_message(link, idx)
            if msg and W._post_to_bot({"wa": link["wa_number"], "kind": "engage", **msg}):
                sent += 1
            else:
                c.execute("UPDATE chat_engage SET last_sent_at=NULL WHERE wa_number=?", (link["wa_number"],))
                c.commit()
        except Exception:
            log.exception("engage send failed")
    if sent:
        log.info("Engagement: sent %s update(s)", sent)
    return sent


_loop_started = False


def start_engagement_loop():
    global _loop_started
    if _loop_started or not _on("ENGAGE_ENABLED", "false"):
        return
    _loop_started = True
    poll = max(5, int(os.getenv("ENGAGE_POLL_MINUTES", "30"))) * 60

    def loop():
        time.sleep(60)
        while True:
            try:
                engage_run_once()
            except Exception:
                log.exception("engagement loop")
            time.sleep(poll)

    threading.Thread(target=loop, daemon=True, name="chat-engage").start()
    log.info("Chat engagement messages enabled (every %s min, channels=%s)", poll // 60,
             os.getenv("ENGAGE_CHANNELS", "telegram"))


# --------------------------------------------------------------------------- routes
def init_saved(app, *, login_required, db, encrypt, decrypt, decrypt_payload, server_fee_for,
               finalize, limit_check, utility_down):
    _d.update(db=db, encrypt=encrypt, decrypt=decrypt, decrypt_payload=decrypt_payload,
              server_fee_for=server_fee_for, finalize=finalize, limit_check=limit_check,
              utility_down=utility_down)
    _ensure()

    def body():
        return W._body()

    # ---- bot-secret endpoints (the bot acts for a chat) -------------------------------------
    @sv_bp.route("/api/whatsapp/saved/list", methods=["POST"])
    @W.bot_required
    def sv_list():
        _ensure()
        link, uid = _link_user(W._wa(body()))
        if not uid:
            return jsonify({"success": True, "linked": False, "items": [], "card": None, "card_enabled": card_enabled()})
        rows = _conn().execute("SELECT * FROM saved_beneficiaries WHERE user_id=? "
                               "ORDER BY COALESCE(last_used_at, created_at) DESC LIMIT 10", (uid,)).fetchall()
        card = card_for_user(uid) if card_enabled() else None
        return jsonify({"success": True, "linked": True, "items": [_view(dict(r)) for r in rows],
                        "card": ({"last4": card["last4"], "brand": card["brand"]} if card else None),
                        "card_enabled": card_enabled()})

    @sv_bp.route("/api/whatsapp/saved/add", methods=["POST"])
    @W.bot_required
    def sv_add():
        _ensure()
        d = body()
        link, uid = _link_user(W._wa(d))
        if not uid:
            return jsonify({"success": False, "code": "ACCOUNT_REQUIRED"}), 403
        tx = db.get_transaction(str(d.get("reference") or ""))
        if not tx or tx.get("user_id") != uid or tx.get("status") != "fulfilled":
            return jsonify({"success": False, "error": "not_found"}), 404
        p = _payload(tx)
        n = _conn().execute("SELECT COUNT(*) FROM saved_beneficiaries WHERE user_id=?", (uid,)).fetchone()[0]
        if tx.get("tx_type") == "topup":
            kind, target = "airtime", _national(_plain(p.get("phone")))
            mask = W._mask_phone(target)
            label = f"{p.get('operator_name') or 'Airtime'} {mask}".strip()
            extra = (str(p.get("operator_id") or ""), p.get("operator_name"), None, None)
        elif tx.get("tx_type") == "utility":
            kind, target = "utility", str(p.get("subscriber_account") or "").strip()
            mask = W._mask_account(target)
            label = f"{p.get('biller_name') or 'Bill'} {mask}".strip()
            extra = (None, None, str(p.get("biller_id") or ""), p.get("biller_name"))
        else:
            return jsonify({"success": False, "error": "unsupported"}), 400
        if not target:
            return jsonify({"success": False, "error": "no_target"}), 400
        h = _hash(kind, target)
        ex = _conn().execute("SELECT id, label FROM saved_beneficiaries WHERE user_id=? AND kind=? AND target_hash=?",
                             (uid, kind, h)).fetchone()
        if ex:
            return jsonify({"success": True, "id": ex[0], "label": ex[1], "already": True})
        if n >= int(os.getenv("SAVED_MAX_PER_USER", "10")):
            return jsonify({"success": False, "code": "LIMIT", "error": "You have 10 saved items. Remove one first."}), 400
        c = _conn()
        cur = c.execute(
            "INSERT INTO saved_beneficiaries (user_id, kind, label, target_enc, target_hash, target_mask, "
            "operator_id, operator_name, biller_id, biller_name, last_used_at) VALUES (?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)",
            (uid, kind, label[:40], encrypt(target), h, mask, *extra))
        c.commit()
        return jsonify({"success": True, "id": cur.lastrowid, "label": label[:40], "already": False})

    @sv_bp.route("/api/whatsapp/saved/rename", methods=["POST"])
    @W.bot_required
    def sv_rename():
        d = body()
        link, uid = _link_user(W._wa(d))
        label = re.sub(r"[^\w .'\-]", "", str(d.get("label") or ""))[:30].strip()
        if not uid or not label:
            return jsonify({"success": False}), 400
        c = _conn()
        c.execute("UPDATE saved_beneficiaries SET label=? WHERE id=? AND user_id=?", (label, d.get("id"), uid))
        c.commit()
        return jsonify({"success": True, "label": label})

    @sv_bp.route("/api/whatsapp/saved/delete", methods=["POST"])
    @W.bot_required
    def sv_delete():
        d = body()
        link, uid = _link_user(W._wa(d))
        if not uid:
            return jsonify({"success": False}), 403
        c = _conn()
        cur = c.execute("DELETE FROM saved_beneficiaries WHERE id=? AND user_id=?", (d.get("id"), uid))
        c.commit()
        return jsonify({"success": True, "deleted": cur.rowcount})

    @sv_bp.route("/api/whatsapp/saved/get", methods=["POST"])
    @W.bot_required
    def sv_get():
        d = body()
        link, uid = _link_user(W._wa(d))
        if not uid:
            return jsonify({"success": False}), 403
        r = _conn().execute("SELECT * FROM saved_beneficiaries WHERE id=? AND user_id=?", (d.get("id"), uid)).fetchone()
        if not r:
            return jsonify({"success": False, "error": "not_found"}), 404
        r = dict(r)
        c = _conn()
        c.execute("UPDATE saved_beneficiaries SET last_used_at=CURRENT_TIMESTAMP WHERE id=?", (r["id"],))
        c.commit()
        target = _plain(decrypt(r["target_enc"]))
        out = {"success": True, "kind": r["kind"], "label": r["label"]}
        if r["kind"] == "airtime":
            out.update(national=target, operator_id=r["operator_id"], operator_name=r["operator_name"])
        else:
            out.update(account=target, biller_id=r["biller_id"], biller_name=r["biller_name"])
        return jsonify(out)

    @sv_bp.route("/api/whatsapp/card/status", methods=["POST"])
    @W.bot_required
    def card_status():
        link, uid = _link_user(W._wa(body()))
        card = card_for_user(uid) if (uid and card_enabled()) else None
        return jsonify({"success": True, "enabled": bool(uid) and card_enabled(),
                        "card": ({"last4": card["last4"], "brand": card["brand"]} if card else None)})

    @sv_bp.route("/api/whatsapp/card/remove", methods=["POST"])
    @W.bot_required
    def card_remove():
        link, uid = _link_user(W._wa(body()))
        if not uid:
            return jsonify({"success": False}), 403
        c = _conn()
        cur = c.execute("UPDATE saved_cards SET active=0 WHERE user_id=? AND active=1", (uid,))
        c.commit()
        return jsonify({"success": True, "removed": cur.rowcount})

    # ---- one-tap pay with the saved card (acts as the user; the bot gets the token after the PIN) -------
    @sv_bp.route("/api/saved/pay", methods=["POST"])
    @login_required
    def saved_pay():
        _ensure()
        if not card_enabled():
            return jsonify({"success": False, "error": "Saved cards are not available yet."}), 503
        uid = g.current_user_id
        if W.is_guest_user(uid):
            return jsonify({"success": False, "code": "ACCOUNT_REQUIRED", "error": "Link a free Net365 account first."}), 403
        card = card_for_user(uid)
        if not card:
            return jsonify({"success": False, "code": "NO_CARD", "error": "No saved card."}), 400
        d = request.get_json(silent=True) or {}
        kind = str(d.get("type") or "")
        user = db.get_user(uid) or {}
        email = user.get("email")
        if not email:
            return jsonify({"success": False, "error": "Your account needs an email address."}), 400
        src = str(d.get("source") or "")
        src = src if src in ("telegram", "whatsapp") else None
        payload = {"email": email, "user_id": uid, "payment_method": "saved_card"}
        if src:
            payload["source"] = src
        try:
            if kind == "topup":
                service = float(d.get("amount"))
                if service < 50 or service > 1000000 or not d.get("operator_id") or not d.get("phone"):
                    raise ValueError("bad topup")
                fee = server_fee_for(service, "NGN")
                total, tx_type = round(service + fee, 2), "topup"
                payload.update(operator_id=d["operator_id"], phone=encrypt(str(d["phone"])), country_code="NG",
                               operator_name=str(d.get("operator_name") or "")[:40],
                               service_amount=service, fee_amount=fee)
            elif kind == "utility":
                if utility_down():
                    return jsonify({"success": False, "code": "PROVIDER_UNAVAILABLE",
                                    "error": "Bill payments are temporarily unavailable. You have not been charged."}), 503
                service = float(d.get("amount"))
                if service <= 0 or not d.get("biller_id") or not d.get("subscriber_account"):
                    raise ValueError("bad bill")
                fee = server_fee_for(service, "NGN")
                total, tx_type = round(service + fee, 2), "utility"
                payload.update(biller_id=d["biller_id"], subscriber_account=str(d["subscriber_account"]),
                               amount=service, currency="NGN", biller_name=str(d.get("biller_name") or "")[:60],
                               service_amount=service, fee_amount=fee)
            elif kind == "giftcard":
                import net365_giftcards as GC
                if not GC.enabled():
                    return jsonify({"success": False, "error": "Gift cards are not available yet."}), 503
                p = GC._find(int(d.get("product_id")))
                den = next((x for x in (p or {}).get("denominations", [])
                            if abs(x["recipient"] - float(d.get("denomination"))) < 1e-6), None)
                if not p or not den:
                    raise ValueError("bad card")
                total, tx_type = float(GC.price_ngn(p, den)), "giftcard"
                payload.update(product_id=p["id"], product_name=p["name"], denomination=den["recipient"],
                               cost_usd=den["cost_usd"], country_code=p["country"])
            else:
                raise ValueError("bad type")
        except (TypeError, ValueError, KeyError):
            return jsonify({"success": False, "error": "That purchase is not valid."}), 400

        if total > _card_max():
            return jsonify({"success": False, "code": "CARD_LIMIT",
                            "error": f"One-tap card payments are limited to ₦{_card_max():,.0f}. Use Pay now for larger amounts."}), 400
        msg = limit_check(uid, total)
        if msg:
            return jsonify({"success": False, "code": "LIMIT_EXCEEDED", "error": msg}), 400

        reference = f"PSK_SC{int(time.time())}{secrets.token_hex(4).upper()}"
        db.create_pending(reference=reference, tx_type=tx_type, provider="paystack", amount=total,
                          currency="NGN", payload=payload, user_id=uid)
        ok, why = _charge(card, email, total, reference)
        if not ok:
            _mark_failed(reference)
            return jsonify({"success": False, "code": "CARD_NOT_CHARGED",
                            "error": f"Your card could not be charged ({why}). Use Pay now instead."}), 402
        res = _d["finalize"](reference)
        if res.get("success"):
            return jsonify({"success": True, "status": "fulfilled", "reference": reference, "amount": total})
        # Charged but delivery is delayed: the customer is told, and the sweeper retries (never charged twice)
        return jsonify({"success": True, "status": "processing", "reference": reference, "amount": total}), 202

    app.register_blueprint(sv_bp)
    start_engagement_loop()

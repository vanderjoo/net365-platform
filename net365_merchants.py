"""
Net365 business payments (user-to-business), chat first.

COMPLIANCE DESIGN: Net365 never holds, pools or settles merchant money.
  * The customer pays on Paystack's hosted page (Paystack is the licensed collector).
  * Paystack settles straight to the merchant's own bank account through a Paystack subaccount.
  * Net365 only receives its disclosed fee, as Paystack's split "transaction_charge".
  * Net365 stores no full account numbers (last 4 only) and no balances.
Have your lawyer and Paystack confirm this model for your account before going live
(see LAUNCH_CHECKLIST.md). Merchants start 'pending' and are approved by you.
"""
import logging
import os
import re
import secrets
import time
from datetime import datetime

import requests
from flask import Blueprint, jsonify, request, g

import net365_whatsapp as W

log = logging.getLogger(__name__)
mc_bp = Blueprint("merchants", __name__)
_d = {}
_schema_done = False
_bank_cache = {"at": 0.0, "items": []}

CATEGORIES = [("shop", "🛍️ Shop / store"), ("food", "🍲 Food & drinks"), ("school", "🎓 School / training"),
              ("faith", "⛪ Faith / community"), ("services", "🛠️ Services"), ("other", "📦 Other")]
CATEGORY_IDS = {c for c, _ in CATEGORIES}


def _on(name, default="false"):
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def enabled():
    return _on("MERCHANTS_ENABLED", "false")


def _f(name, default):
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return float(default)


def merchant_fee(amount):
    """Net365's disclosed share, taken from the merchant's side of the split."""
    fee = amount * _f("MERCHANT_FEE_PERCENT", 1.0) / 100.0
    fee = max(fee, _f("MERCHANT_FEE_MIN_NGN", 0))
    fee = min(fee, _f("MERCHANT_FEE_MAX_NGN", 500))
    return round(fee, 2)


def _conn():
    return _d["db"].get_db_connection()


def _ensure():
    global _schema_done
    if _schema_done:
        return
    c = _conn()
    for sql in (
        """CREATE TABLE IF NOT EXISTS merchants (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, code TEXT NOT NULL UNIQUE,
            business_name TEXT NOT NULL, category TEXT, bank_code TEXT, bank_name TEXT, account_last4 TEXT,
            account_name TEXT, subaccount_code TEXT, status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP)""",
        """CREATE TABLE IF NOT EXISTS merchant_payments (
            reference TEXT PRIMARY KEY, merchant_id INTEGER NOT NULL, payer_user_id INTEGER, amount REAL NOT NULL,
            fee REAL NOT NULL DEFAULT 0, note TEXT, status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, paid_at TEXT)""",
        "CREATE INDEX IF NOT EXISTS idx_merchants_user ON merchants(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_mpay_merchant ON merchant_payments(merchant_id, created_at)",
    ):
        try:
            c.execute(sql)
        except Exception:
            log.exception("merchant schema step failed")
    try:
        c.commit()
    except Exception:
        pass
    _schema_done = True


# --------------------------------------------------------------------------- Paystack helpers
def _ps(method, path, **kw):
    key = os.getenv("PAYSTACK_SECRET_KEY", "")
    if not key:
        return None, "Paystack is not configured."
    try:
        r = requests.request(method, f"https://api.paystack.co{path}", headers={"Authorization": f"Bearer {key}"},
                             timeout=30, **kw)
        body = r.json() if r.content else {}
        if r.status_code == 200 and body.get("status"):
            return body, None
        return None, str(body.get("message") or f"Paystack error {r.status_code}")[:160]
    except Exception:
        log.exception("paystack call failed")
        return None, "Could not reach Paystack."


def banks():
    if time.time() - _bank_cache["at"] < 86400 and _bank_cache["items"]:
        return _bank_cache["items"]
    items, nxt = [], None
    for _ in range(8):
        params = {"country": "nigeria", "perPage": 100, "use_cursor": "true"}
        if nxt:
            params["next"] = nxt
        body, err = _ps("GET", "/bank", params=params)
        if err or not body:
            break
        items += [{"code": b["code"], "name": b["name"]} for b in body.get("data", []) if b.get("active", True)]
        nxt = (body.get("meta") or {}).get("next")
        if not nxt:
            break
    if items:
        _bank_cache.update(at=time.time(), items=items)
    return _bank_cache["items"]


def _search_banks(q):
    q = re.sub(r"[^a-z0-9 ]", "", str(q or "").lower()).strip()
    if len(q) < 2:
        return []
    return [b for b in banks() if q in b["name"].lower()][:8]


def _make_code(name):
    base = re.sub(r"[^A-Z]", "", name.upper())[:5] or "SHOP"
    c = _conn()
    for _ in range(20):
        code = f"{base}{secrets.randbelow(90) + 10}"
        if not c.execute("SELECT 1 FROM merchants WHERE code=?", (code,)).fetchone():
            return code
    return f"{base}{secrets.token_hex(2).upper()}"


def _merchant_by_code(code):
    code = re.sub(r"[^A-Za-z0-9]", "", str(code or "")).upper()[:12]
    if not code:
        return None
    r = _conn().execute("SELECT * FROM merchants WHERE code=?", (code,)).fetchone()
    return dict(r) if r else None


def _bot_username():
    return os.getenv("TELEGRAM_BOT_USERNAME", "Net365_Bot").lstrip("@")


def _share_link(code):
    return f"https://t.me/{_bot_username()}?start=pay_{code}"


# --------------------------------------------------------------------------- settlement hooks
def fulfil_merchant(reference, payload, tx):
    """Nothing to deliver: Paystack settles the merchant directly. Record it and tell the owner."""
    c = _conn()
    c.execute("UPDATE merchant_payments SET status='paid', paid_at=CURRENT_TIMESTAMP WHERE reference=?", (reference,))
    try:
        c.commit()
    except Exception:
        pass
    return {"status": "success", "settlement": "paystack_split_direct_to_merchant",
            "merchant_id": payload.get("merchant_id"), "amount": tx.get("amount")}


def notify_merchant_paid(reference):
    """Tell the business owner (in chat) that a payment came in. Idempotent. Never raises."""
    try:
        _ensure()
        row = _conn().execute("SELECT * FROM merchant_payments WHERE reference=?", (reference,)).fetchone()
        if not row or row["status"] != "paid":
            return
        m = _conn().execute("SELECT * FROM merchants WHERE id=?", (row["merchant_id"],)).fetchone()
        link = W.chat_link_for_user(m["user_id"]) if m else None
        if not link:
            return
        c = _conn()
        cur = c.execute("INSERT OR IGNORE INTO bot_notifications (reference, status) VALUES (?, 'sending')",
                        (reference + ":m",))
        try:
            c.commit()
        except Exception:
            pass
        if cur.rowcount == 0:
            return
        W._post_to_bot({"wa": link["wa_number"], "kind": "merchant_paid", "reference": reference,
                        "amount": float(row["amount"]), "fee": float(row["fee"]), "note": row["note"],
                        "business": m["business_name"]})
    except Exception:
        log.exception("merchant paid notice failed")


# --------------------------------------------------------------------------- routes
def init_merchants(app, *, login_required, db, admin_required, limit_check, init_paystack, return_url_for):
    _d.update(db=db, limit_check=limit_check, init_paystack=init_paystack)
    _ensure()

    def body():
        return W._body()

    def owner(wa):
        link = W._get_link(wa) if wa else None
        if not link or link.get("is_guest"):
            return link, None
        return link, link.get("user_id")

    @mc_bp.route("/api/whatsapp/merchant/banks", methods=["POST"])
    @W.bot_required
    def m_banks():
        if not enabled():
            return jsonify({"success": True, "enabled": False})
        return jsonify({"success": True, "enabled": True, "items": _search_banks(body().get("q"))})

    @mc_bp.route("/api/whatsapp/merchant/resolve", methods=["POST"])
    @W.bot_required
    def m_resolve():
        d = body()
        acct, code = re.sub(r"\D", "", str(d.get("account_number") or "")), str(d.get("bank_code") or "")
        if len(acct) != 10 or not code.isdigit():
            return jsonify({"success": False, "error": "Enter a valid 10-digit account number."}), 400
        res, err = _ps("GET", "/bank/resolve", params={"account_number": acct, "bank_code": code})
        if err:
            return jsonify({"success": False, "error": "We could not verify that account. Check the bank and number."}), 400
        return jsonify({"success": True, "account_name": (res.get("data") or {}).get("account_name")})

    @mc_bp.route("/api/whatsapp/merchant/register", methods=["POST"])
    @W.bot_required
    def m_register():
        _ensure()
        if not enabled():
            return jsonify({"success": False, "error": "Business payments are not available yet."}), 503
        d = body()
        link, uid = owner(W._wa(d))
        if not uid:
            return jsonify({"success": False, "code": "ACCOUNT_REQUIRED",
                            "error": "Link a free Net365 account to accept payments."}), 403
        if _conn().execute("SELECT 1 FROM merchants WHERE user_id=?", (uid,)).fetchone():
            return jsonify({"success": False, "error": "You already have a business registered."}), 400
        name = re.sub(r"[^\w &'.\-]", "", str(d.get("business_name") or "")).strip()[:40]
        cat = str(d.get("category") or "other")
        cat = cat if cat in CATEGORY_IDS else "other"
        bank_code = str(d.get("bank_code") or "")
        acct = re.sub(r"\D", "", str(d.get("account_number") or ""))
        if len(name) < 3 or len(acct) != 10 or not bank_code.isdigit():
            return jsonify({"success": False, "error": "Please check the business name, bank and account number."}), 400
        res, err = _ps("GET", "/bank/resolve", params={"account_number": acct, "bank_code": bank_code})
        if err:
            return jsonify({"success": False, "error": "We could not verify that bank account."}), 400
        acct_name = (res.get("data") or {}).get("account_name") or ""
        sub, err = _ps("POST", "/subaccount", json={
            "business_name": name, "settlement_bank": bank_code, "account_number": acct,
            "percentage_charge": _f("MERCHANT_FEE_PERCENT", 1.0)})
        if err:
            log.error("subaccount create failed: %s", err)
            return jsonify({"success": False, "error": "We could not set up settlement for that account."}), 502
        bank_name = next((b["name"] for b in banks() if b["code"] == bank_code), "")
        status = "active" if _on("MERCHANTS_AUTO_APPROVE", "false") else "pending"
        code = _make_code(name)
        c = _conn()
        c.execute("INSERT INTO merchants (user_id, code, business_name, category, bank_code, bank_name, account_last4, "
                  "account_name, subaccount_code, status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                  (uid, code, name, cat, bank_code, bank_name, acct[-4:], acct_name, (sub.get("data") or {}).get("subaccount_code"), status))
        c.commit()
        return jsonify({"success": True, "code": code, "status": status, "account_name": acct_name,
                        "link": _share_link(code)})

    @mc_bp.route("/api/whatsapp/merchant/mine", methods=["POST"])
    @W.bot_required
    def m_mine():
        _ensure()
        link, uid = owner(W._wa(body()))
        row = _conn().execute("SELECT * FROM merchants WHERE user_id=?", (uid,)).fetchone() if uid else None
        if not row:
            return jsonify({"success": True, "has": False, "linked": bool(uid), "enabled": enabled()})
        m = dict(row)
        t = _conn().execute("SELECT COUNT(*), COALESCE(SUM(amount),0) FROM merchant_payments WHERE merchant_id=? "
                            "AND status='paid' AND paid_at >= datetime('now','start of day')", (m["id"],)).fetchone()
        a = _conn().execute("SELECT COUNT(*), COALESCE(SUM(amount),0) FROM merchant_payments WHERE merchant_id=? "
                            "AND status='paid'", (m["id"],)).fetchone()
        recent = _conn().execute("SELECT amount, note, paid_at FROM merchant_payments WHERE merchant_id=? "
                                 "AND status='paid' ORDER BY paid_at DESC LIMIT 5", (m["id"],)).fetchall()
        return jsonify({"success": True, "has": True, "code": m["code"], "business_name": m["business_name"],
                        "status": m["status"], "bank_name": m["bank_name"], "account_last4": m["account_last4"],
                        "today_count": t[0], "today_total": float(t[1]), "all_count": a[0], "all_total": float(a[1]),
                        "recent": [{"amount": float(r[0]), "note": r[1], "at": r[2]} for r in recent],
                        "link": _share_link(m["code"])})

    @mc_bp.route("/api/whatsapp/merchant/lookup", methods=["POST"])
    @W.bot_required
    def m_lookup():
        _ensure()
        if not enabled():
            return jsonify({"success": True, "enabled": False})
        m = _merchant_by_code(body().get("code"))
        if not m:
            return jsonify({"success": True, "enabled": True, "found": False})
        return jsonify({"success": True, "enabled": True, "found": True, "active": m["status"] == "active",
                        "business_name": m["business_name"], "category": m["category"], "code": m["code"]})

    # ---- the customer pays (acts as the user; guests allowed with the guest caps) ---------------
    @mc_bp.route("/api/merchants/pay-init", methods=["POST"])
    @login_required
    def m_pay_init():
        _ensure()
        if not enabled():
            return jsonify({"success": False, "error": "Business payments are not available yet."}), 503
        uid = g.current_user_id
        d = request.get_json(silent=True) or {}
        _ce = W.chat_purchase_error(uid, d.get("amount"), "NGN")  # frozen chat / PIN above the step-up amount
        if _ce:
            return jsonify(_ce[0]), _ce[1]
        m = _merchant_by_code(d.get("code"))
        if not m or m["status"] != "active" or not m.get("subaccount_code"):
            return jsonify({"success": False, "error": "That business is not accepting payments right now."}), 404
        if m["user_id"] == uid:
            return jsonify({"success": False, "error": "You cannot pay your own business."}), 400
        try:
            amount = round(float(d.get("amount")), 2)
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Enter a valid amount."}), 400
        cap = _f("MERCHANT_MAX_NGN", 200000)
        if amount < 100 or amount > cap:
            return jsonify({"success": False, "error": f"Amounts must be between ₦100 and ₦{cap:,.0f}."}), 400
        guest = W.is_guest_user(uid)
        if guest:
            msg = W.guest_limit_error(uid, amount)
            if msg:
                return jsonify({"success": False, "code": "LIMIT_EXCEEDED", "error": msg}), 400
            email = W.guest_receipt_email(uid)
            if not email:
                return jsonify({"success": False, "code": "EMAIL_NEEDED", "error": "An email address is needed for your receipt."}), 400
        else:
            msg = _d["limit_check"](uid, amount)
            if msg:
                return jsonify({"success": False, "code": "LIMIT_EXCEEDED", "error": msg}), 400
            email = (db.get_user(uid) or {}).get("email")
            if not email:
                return jsonify({"success": False, "error": "Your account needs an email address."}), 400
        note = re.sub(r"[^\w .,'#\-]", "", str(d.get("note") or ""))[:60]
        fee = merchant_fee(amount)
        reference = f"PSK_MC{int(time.time())}{secrets.token_hex(4).upper()}"
        url, ref, err = _d["init_paystack"](
            email, amount, reference, return_url_for(d.get("return_url")),
            {"subaccount": m["subaccount_code"], "transaction_charge": int(round(fee * 100)), "bearer": "subaccount",
             "metadata": {"merchant_id": m["id"], "merchant": m["code"]}})
        if not url:
            return jsonify({"success": False, "error": err or "Could not start the payment."}), 502
        payload = {"merchant_id": m["id"], "merchant_code": m["code"], "merchant_name": m["business_name"],
                   "note": note, "email": email, "user_id": uid, "service_amount": amount, "fee_amount": 0}
        if str(d.get("source") or "") in ("telegram", "whatsapp"):
            payload["source"] = d["source"]
        db.create_pending(reference=reference, tx_type="merchant", provider="paystack", amount=amount,
                          currency="NGN", payload=payload, user_id=uid)
        c = _conn()
        c.execute("INSERT INTO merchant_payments (reference, merchant_id, payer_user_id, amount, fee, note) "
                  "VALUES (?,?,?,?,?,?)", (reference, m["id"], uid, amount, fee, note))
        c.commit()
        return jsonify({"success": True, "authorization_url": url, "reference": reference, "amount": amount,
                        "merchant_name": m["business_name"]})

    # ---- admin: approve / suspend -------------------------------------------------------------
    @mc_bp.route("/api/admin/merchants", methods=["GET"])
    @admin_required
    def admin_list():
        _ensure()
        rows = _conn().execute("SELECT id, user_id, code, business_name, category, bank_name, account_last4, "
                               "account_name, status, created_at FROM merchants ORDER BY id DESC LIMIT 200").fetchall()
        return jsonify({"success": True, "merchants": [dict(r) for r in rows]})

    @mc_bp.route("/api/admin/merchants/<int:mid>/status", methods=["POST"])
    @admin_required
    def admin_status(mid):
        st = str((request.get_json(silent=True) or {}).get("status") or "")
        if st not in ("active", "pending", "suspended"):
            return jsonify({"success": False, "error": "status must be active, pending or suspended"}), 400
        c = _conn()
        cur = c.execute("UPDATE merchants SET status=? WHERE id=?", (st, mid))
        c.commit()
        return jsonify({"success": bool(cur.rowcount), "status": st})

    app.register_blueprint(mc_bp)

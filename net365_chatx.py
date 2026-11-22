"""Receipt contact + remembered accounts for the Telegram and WhatsApp bots.

The bot (server.js) asks these routes for the customer's number and email so nobody types them again:

  POST /api/chat/contact/get       {wa}                     -> phone, email and where each came from, plus numbers used before
  POST /api/chat/contact/set       {wa, phone? , email?}    -> remember a different number / email for chat receipts
  POST /api/chat/accounts/list     {wa, kind}               -> smartcards / meters used before ("tv:dstv", "util:ikeja:prepaid" ...)
  POST /api/chat/accounts/remember {wa, kind, ref, label}   -> keep a verified smartcard / meter for next time

All routes need the bot secret (X-Bot-Secret), like /api/whatsapp/*. Where the number comes from, in this order:
  1. a number the customer saved in the chat ("my contact" > change number)
  2. the phone on the Net365 account
  3. the number most recently paid for in the transactions table
The email is the one the customer saved in chat, otherwise the account email. Changing it here NEVER changes the account login email.
A customer can only ever see their own data: everything is looked up from the chat that is linked to them.
"""
import json
import logging
import re

from flask import Blueprint, jsonify

logger = logging.getLogger("net365.chatx")
chatx_bp = Blueprint("net365_chatx", __name__)

_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-']{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")
_KIND = re.compile(r"^[a-z0-9:_\-]{1,60}$")
_REF = re.compile(r"^[A-Za-z0-9\-_/ ]{4,40}$")
_ready = False


def _wa_mod():
    import net365_whatsapp as w
    return w


def _conn():
    return _wa_mod()._conn()


def _schema():
    global _ready
    if _ready:
        return
    c = _conn()
    c.execute("CREATE TABLE IF NOT EXISTS chat_contacts (wa_number TEXT PRIMARY KEY, phone TEXT, email TEXT, "
              "updated_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    c.execute("CREATE TABLE IF NOT EXISTS chat_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT NOT NULL, "
              "ref TEXT NOT NULL, label TEXT, last_used TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, kind, ref))")
    c.commit()
    _ready = True


def _local_phone(raw):
    """08012345678 for any Nigerian way of writing it; '' when it is not a Nigerian mobile number."""
    d = re.sub(r"\D", "", str(raw or ""))
    if d.startswith("234") and len(d) == 13:
        d = "0" + d[3:]
    elif len(d) == 10 and d[0] in "789":
        d = "0" + d
    return d if re.match(r"^0[789][01]\d{8}$", d) else ""


def _mask_email(e):
    try:
        n, d = e.split("@", 1)
        return (n[:1] + "***@" + d) if len(n) > 1 else ("*@" + d)
    except Exception:
        return ""


def _mask_ref(r):
    r = str(r)
    return (r[:3] + "••••" + r[-3:]) if len(r) > 7 else r


def _link(data):
    w = _wa_mod()
    wa = w._wa(data)
    return wa, (w._get_link(wa) if wa else None)


def _history(user_id, limit=120):
    """Decoded payloads of this customer's own recent transactions, newest first."""
    w = _wa_mod()
    rows = _conn().execute("SELECT tx_type, status, created_at, payload FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
                           (user_id, limit)).fetchall()
    out = []
    for r in rows:
        try:
            pl = r["payload"]
            pl = json.loads(pl) if isinstance(pl, str) else (pl or {})
            if w._decrypt:
                pl = w._decrypt(dict(pl))
        except Exception:
            pl = {}
        out.append((r["tx_type"], r["status"], pl if isinstance(pl, dict) else {}))
    return out


def _used_phones(user_id):
    """Numbers this customer paid for before, most recent first, with what it was for."""
    seen, out = set(), []
    for tx_type, status, pl in _history(user_id):
        if status not in ("fulfilled", "completed", "success", "pending"):
            continue
        p = _local_phone(pl.get("phone"))
        if not p or p in seen:
            continue
        seen.add(p)
        what = {"topup": "airtime", "data": "data", "tv": "TV", "subscription": "TV", "education": "education"}.get(tx_type, "")
        out.append({"phone": p, "for": what})
    return out


def _account_row(user_id):
    return _conn().execute("SELECT id, email, phone, is_guest FROM users WHERE id = ?", (user_id,)).fetchone()


@chatx_bp.route("/api/chat/contact/get", methods=["POST"])
def chat_contact_get():
    w = _wa_mod()
    return _guard(_contact_get)


def _guard(fn):
    # same bot-secret rule as every /api/whatsapp route
    return _wa_mod().bot_required(fn)()


def _contact_get():
    w = _wa_mod()
    _schema()
    wa, link = _link(w._body())
    if not link:
        return jsonify({"success": True, "linked": False})
    user = _account_row(link["user_id"])
    if not user or w._blocked_user(w._db.get_user(link["user_id"])):
        return jsonify({"success": True, "linked": False})
    saved = _conn().execute("SELECT phone, email FROM chat_contacts WHERE wa_number = ?", (wa,)).fetchone()
    guest = bool(user["is_guest"]) or bool(link.get("is_guest"))
    used = _used_phones(link["user_id"])

    phone, psrc = "", ""
    if saved and _local_phone(saved["phone"]):
        phone, psrc = _local_phone(saved["phone"]), "saved"
    elif not guest and _local_phone(user["phone"]):
        phone, psrc = _local_phone(user["phone"]), "account"
    elif used:
        phone, psrc = used[0]["phone"], "history"

    email, esrc = "", ""
    if saved and saved["email"] and _EMAIL.match(saved["email"]):
        email, esrc = saved["email"], "saved"
    elif guest and link.get("receipt_email"):
        email, esrc = link["receipt_email"], "chat"
    elif not guest and user["email"]:
        email, esrc = user["email"], "account"

    others = [u for u in used if u["phone"] != phone][:4]
    return jsonify({"success": True, "linked": True, "guest": guest, "phone": phone, "phone_source": psrc,
                    "email": email, "email_masked": _mask_email(email), "email_source": esrc, "recent_phones": others})


@chatx_bp.route("/api/chat/contact/set", methods=["POST"])
def chat_contact_set():
    return _guard(_contact_set)


def _contact_set():
    w = _wa_mod()
    _schema()
    data = w._body()
    wa, link = _link(data)
    if not link:
        return jsonify({"success": False, "error": "unknown_chat"}), 404
    phone = _local_phone(data.get("phone")) if data.get("phone") else ""
    email = str(data.get("email") or "").strip().lower()
    if data.get("phone") and not phone:
        return jsonify({"success": False, "error": "bad_phone"}), 400
    if email and not _EMAIL.match(email):
        return jsonify({"success": False, "error": "bad_email"}), 400
    if not phone and not email:
        return jsonify({"success": False, "error": "nothing_to_save"}), 400
    c = _conn()
    c.execute("INSERT OR IGNORE INTO chat_contacts (wa_number) VALUES (?)", (wa,))
    if phone:
        c.execute("UPDATE chat_contacts SET phone = ?, updated_at = CURRENT_TIMESTAMP WHERE wa_number = ?", (phone, wa))
    if email:
        c.execute("UPDATE chat_contacts SET email = ?, updated_at = CURRENT_TIMESTAMP WHERE wa_number = ?", (email, wa))
    c.commit()
    return jsonify({"success": True})


def _kind_matches(kind, tx_type, pl):
    """Does this past transaction belong to the picker `kind` ("tv:dstv", "util:ikeja:prepaid", "util:<biller id>")?"""
    if kind.startswith("tv:"):
        return tx_type in ("tv", "subscription") and str(pl.get("product") or "").lower() == kind[3:]
    if kind.startswith("util:"):
        want = kind[5:].split(":")
        if tx_type == "electricity" and len(want) == 2:
            mt = "postpaid" if str(pl.get("meter_type") or "").lower().startswith("post") else "prepaid"
            return str(pl.get("disco") or pl.get("key") or "").lower() == want[0] and mt == want[1]
        return tx_type == "utility" and str(pl.get("biller_id") or "") == want[0]
    return False


@chatx_bp.route("/api/chat/accounts/list", methods=["POST"])
def chat_accounts_list():
    return _guard(_accounts_list)


def _accounts_list():
    w = _wa_mod()
    _schema()
    data = w._body()
    wa, link = _link(data)
    kind = str(data.get("kind") or "")
    if not link or not _KIND.match(kind):
        return jsonify({"success": True, "items": []})
    uid = link["user_id"]
    items, seen = [], set()
    for r in _conn().execute("SELECT ref, label FROM chat_accounts WHERE user_id = ? AND kind = ? ORDER BY last_used DESC LIMIT 6", (uid, kind)):
        seen.add(r["ref"])
        items.append({"ref": r["ref"], "masked": _mask_ref(r["ref"]), "label": r["label"] or ""})
    if len(items) < 3:  # also what this customer paid for before, even if it was bought on the web
        for tx_type, status, pl in _history(uid):
            ref = re.sub(r"\s+", "", str(pl.get("subscriber_account") or ""))
            if ref and ref not in seen and _REF.match(ref) and _kind_matches(kind, tx_type, pl):
                seen.add(ref)
                items.append({"ref": ref, "masked": _mask_ref(ref), "label": str(pl.get("customer_name") or "")[:40]})
                if len(items) >= 3:
                    break
    return jsonify({"success": True, "items": items[:3]})


@chatx_bp.route("/api/chat/accounts/remember", methods=["POST"])
def chat_accounts_remember():
    return _guard(_accounts_remember)


def _accounts_remember():
    w = _wa_mod()
    _schema()
    data = w._body()
    wa, link = _link(data)
    kind = str(data.get("kind") or "")
    ref = re.sub(r"\s+", "", str(data.get("ref") or ""))
    if not link or not _KIND.match(kind) or not _REF.match(ref):
        return jsonify({"success": False, "error": "bad_request"}), 400
    label = re.sub(r"[<>\u0000-\u001f]", " ", str(data.get("label") or ""))[:60].strip()
    c = _conn()
    c.execute("INSERT INTO chat_accounts (user_id, kind, ref, label) VALUES (?,?,?,?) "
              "ON CONFLICT(user_id, kind, ref) DO UPDATE SET label = CASE WHEN excluded.label != '' THEN excluded.label ELSE label END, "
              "last_used = CURRENT_TIMESTAMP", (link["user_id"], kind, ref, label))
    c.commit()
    return jsonify({"success": True})


def init_chatx(app):
    """Register the routes. Call once, after init_whatsapp_banking(). Skips routes another module already provides."""
    existing = {r.rule for r in app.url_map.iter_rules()}
    if "/api/chat/contact/get" in existing:
        logger.info("chat contact routes already provided elsewhere; skipping net365_chatx")
        return
    app.register_blueprint(chatx_bp)
    logger.info("Chat contact memory ready (receipt number/email + remembered accounts)")

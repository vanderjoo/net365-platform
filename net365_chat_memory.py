"""Net365 chat contact memory: the receipt number and email that the WhatsApp and Telegram bots remember for a linked customer.

Why this exists
    The bots must never ask a customer for their number or email again once Net365 holds it. The number lives on the ACCOUNT
    (the same place the website profile and the admin edit it), so a number added on the website, in admin or in a chat shows up
    in every other place. This module is the single read/write door for the bots, and it never creates users or touches money.

Routes (bot secret only, same protection as the other /api/bot/* routes)
    POST /api/bot/contact/get    {wa}                      -> {linked, phone, phone_source, phone_verified, email, email_masked, email_source}
    POST /api/bot/contact/set    {wa, phone?|email?}       -> same payload. A phone is also saved on the account (unverified).
    POST /api/bot/contact/debug  {wa}                      -> why a number is or is not found (masked, for the asking chat only)
    POST /api/bot/contact/share  {wa, phone, own:true}     -> Telegram "Share my number": Telegram vouches, so it is saved VERIFIED.

Where each value comes from (first match wins)
    phone : number saved from a chat  ->  the account's number (verified or typed)  ->  the old users.phone column
    email : email saved from a chat   ->  the account's sign-in email
"""
import logging
import re
from datetime import datetime, timezone

from flask import jsonify, request

log = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,120}\.[A-Za-z]{2,}$")
_db = None


def _conn():
    return _db.get_db_connection()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure_schema():
    c = _conn()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS chat_contact_prefs (
            user_id INTEGER PRIMARY KEY, phone TEXT, email TEXT, updated_at TEXT NOT NULL)""")
        c.commit()
    finally:
        c.close()


def _chat_link(wa):
    """(user_id, is_guest) of the ACTIVE link for this chat, or (None, False). Guests are real rows too, so a Telegram
    customer who never linked an account still gets remembered."""
    wa = str(wa or "").strip()
    if not wa:
        return None, False
    digits = re.sub(r"\D", "", wa)
    c = _conn()
    try:
        for key in dict.fromkeys([wa, digits, "+" + digits]):
            if not key:
                continue
            r = c.execute("SELECT user_id, is_guest FROM whatsapp_links WHERE wa_number = ? AND active = 1 ORDER BY rowid DESC LIMIT 1", (key,)).fetchone()
            if r is not None:
                return int(r[0]), bool(r[1])
    finally:
        c.close()
    return None, False


def _user_for_chat(wa):
    """The real (non-guest) account linked to this chat, or None."""
    uid, guest = _chat_link(wa)
    return None if guest else uid


def _wa_number_local(wa):
    """The WhatsApp chat id IS the customer's phone number (Telegram ids start 999 and are not numbers)."""
    d = re.sub(r"\D", "", str(wa or ""))
    if not d or d.startswith("999"):
        return ""
    if d.startswith("234") and len(d) == 13:
        d = "0" + d[3:]
    return d if re.fullmatch(r"0[789][01]\d{8}", d) else ""


def _guest_email(uid):
    try:
        c = _conn()
        try:
            r = c.execute("SELECT receipt_email FROM whatsapp_links WHERE user_id = ? AND is_guest = 1 AND active = 1", (uid,)).fetchone()
        finally:
            c.close()
        return str((r[0] if r else "") or "")
    except Exception:
        return ""


def _mask_email(e):
    n, _, d = str(e or "").partition("@")
    return f"{n[:1]}***@{d}" if d else ""


def _local_ng(e164):
    """+2348031234567 -> 08031234567. Chat receipts are Nigerian numbers; anything else is not offered."""
    e = str(e164 or "")
    return "0" + e[4:] if e.startswith("+234") and len(e) == 14 else ""


def _account_phone(uid):
    try:
        import net365_identity as ident
        ep = ident.effective_phone(uid)
        if ep:
            return _local_ng(ep["e164"]), bool(ep.get("verified"))
    except Exception:
        log.debug("chat memory: identity lookup failed", exc_info=True)
    try:
        c = _conn()
        try:
            r = c.execute("SELECT phone FROM users WHERE id = ?", (uid,)).fetchone()
        finally:
            c.close()
        raw = str((r[0] if r else "") or "").strip()
        d = re.sub(r"\D", "", raw)
        if d.startswith("234") and len(d) == 13:
            d = "0" + d[3:]
        if re.fullmatch(r"0[789][01]\d{8}", d):
            return d, False
    except Exception:
        pass
    return "", False


def _payload(uid, wa="", guest=False):
    c = _conn()
    try:
        pref = c.execute("SELECT phone, email FROM chat_contact_prefs WHERE user_id = ?", (uid,)).fetchone()
        u = c.execute("SELECT email FROM users WHERE id = ?", (uid,)).fetchone()
    finally:
        c.close()
    acc_phone, verified = ("", False) if guest else _account_phone(uid)
    pref_phone = str((pref[0] if pref else "") or "")
    pref_email = str((pref[1] if pref else "") or "")
    acc_email = _guest_email(uid) if guest else str((u[0] if u else "") or "")
    chat_phone = _wa_number_local(wa)
    phone = pref_phone or acc_phone or chat_phone
    email = pref_email or acc_email
    psrc = "saved" if pref_phone else ("account" if acc_phone else ("chat" if chat_phone else ""))
    return {"success": True, "linked": True, "guest": bool(guest),
            "phone": phone, "phone_source": psrc if phone else "",
            "phone_verified": bool((verified and phone and phone == acc_phone) or (psrc == "chat" and not guest)),
            "email": email, "email_masked": _mask_email(email), "email_source": ("saved" if pref_email else "account") if email else ""}


def _save_pref(uid, phone=None, email=None):
    c = _conn()
    try:
        c.execute("INSERT OR IGNORE INTO chat_contact_prefs (user_id, updated_at) VALUES (?, ?)", (uid, _now()))
        if phone is not None:
            c.execute("UPDATE chat_contact_prefs SET phone = ?, updated_at = ? WHERE user_id = ?", (phone, _now(), uid))
        if email is not None:
            c.execute("UPDATE chat_contact_prefs SET email = ?, updated_at = ? WHERE user_id = ?", (email, _now(), uid))
        c.commit()
    finally:
        c.close()


def init_chat_memory(app, db, bot_required):
    global _db
    _db = db
    _ensure_schema()

    @app.post("/api/bot/contact/get")
    @bot_required
    def bot_contact_get():
        wa = (request.get_json(silent=True) or {}).get("wa")
        uid, guest = _chat_link(wa)
        if not uid:
            ph = _wa_number_local(wa)           # no record yet: a WhatsApp chat still knows its own number
            return jsonify(success=True, linked=False, **({"phone": ph, "phone_source": "chat"} if ph else {}))
        if not guest:
            try:                                # a linked WhatsApp chat proved its number: adopt it once (never overwrites)
                import net365_identity as ident
                if _wa_number_local(wa):
                    ident.adopt_chat_number(uid, re.sub(r"\D", "", str(wa)))
            except Exception:
                log.debug("chat memory: adopt failed", exc_info=True)
        return jsonify(_payload(uid, wa, guest))

    @app.post("/api/bot/contact/set")
    @bot_required
    def bot_contact_set():
        d = request.get_json(silent=True) or {}
        uid, guest = _chat_link(d.get("wa"))
        if not uid:
            return jsonify(success=False, linked=False, error_code="link_required"), 200
        if d.get("phone") is not None:
            try:
                import net365_identity as ident
                e164, region, err = ident.normalize_phone(d.get("phone"), "NG")
            except Exception:
                ident, e164, region, err = None, None, None, "invalid"
            local = _local_ng(e164)
            if err or not local:
                return jsonify(success=False, error_code="invalid_phone", error="Send a Nigerian number like 08012345678."), 400
            _save_pref(uid, phone=local)
            if not guest and ident:               # also put it on the account, so the website and admin show the same number
                try:
                    ident.save_unverified(uid, e164, region)
                except Exception:
                    log.debug("chat memory: could not mirror the number to the account", exc_info=True)
        if d.get("email") is not None:
            em = str(d.get("email") or "").strip()
            if not _EMAIL_RE.match(em):
                return jsonify(success=False, error_code="invalid_email", error="That does not look like an email address."), 400
            _save_pref(uid, email=em)
            if guest:                             # guests keep one receipt email on their chat link
                try:
                    c = _conn()
                    try:
                        c.execute("UPDATE whatsapp_links SET receipt_email = ? WHERE user_id = ? AND is_guest = 1", (em.lower(), uid)); c.commit()
                    finally:
                        c.close()
                except Exception:
                    log.debug("chat memory: guest receipt email not mirrored", exc_info=True)
        return jsonify(_payload(uid, d.get("wa"), guest))

    @app.post("/api/bot/contact/share")
    @bot_required
    def bot_contact_share():
        d = request.get_json(silent=True) or {}
        if d.get("own") is not True:
            return jsonify(success=False, error_code="not_own_contact"), 400
        uid = _user_for_chat(d.get("wa"))
        if not uid:
            return jsonify(success=False, error_code="link_required"), 200
        try:
            import net365_identity as ident
            ok, res = ident.bind_telegram_contact(uid, d.get("phone"))
        except Exception:
            log.exception("chat memory: telegram share failed")
            return jsonify(success=False, error_code="unavailable"), 503
        if not ok:
            code = (res or {}).get("error") or "invalid"
            return jsonify(success=False, error_code=code), (409 if code == "phone_in_use" else 400)
        local = _local_ng(ident.normalize_phone("+" + re.sub(r"\D", "", str(d.get("phone") or "")))[0])
        if local:
            _save_pref(uid, phone=local)
        return jsonify(_payload(uid))

    @app.post("/api/bot/contact/debug")
    @bot_required
    def bot_contact_debug():
        """Explains, for the asking chat only, why a number or email is or is not found. Nothing is shown in full."""
        wa = str((request.get_json(silent=True) or {}).get("wa") or "").strip()
        digits = re.sub(r"\D", "", wa)
        keys = [k for k in dict.fromkeys([wa, digits, "+" + digits]) if k]
        rows = []
        c = _conn()
        try:
            for k in keys:
                for r in c.execute("SELECT user_id, is_guest, active FROM whatsapp_links WHERE wa_number = ?", (k,)).fetchall():
                    rows.append({"guest": bool(r[1]), "active": bool(r[2]), "uid": int(r[0])})
        except Exception as e:
            return jsonify(success=True, module=True, error="links_table: " + str(e)[:80])
        finally:
            c.close()
        out = {"success": True, "module": True, "links": [{"guest": r["guest"], "active": r["active"]} for r in rows]}
        uid, guest = _chat_link(wa)
        out["linked"] = bool(uid and not guest)
        out["guest"] = bool(uid and guest)
        if uid:
            p = _payload(uid, wa, guest)
            acc_phone, verified = ("", False) if guest else _account_phone(uid)
            out.update(phone=bool(p["phone"]), phone_source=p["phone_source"], phone_on_account=bool(acc_phone), phone_verified=bool(verified),
                       email=bool(p["email"]), email_source=p["email_source"])
        return jsonify(out)

    log.info("Chat contact memory ready (/api/bot/contact/get|set|share)")

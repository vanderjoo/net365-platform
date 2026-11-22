"""My profile > Contact details: edit the name, and add / change the phone number with an SMS code.

  GET   /api/account/contact          -> {phone, phone_verified, pending_phone, sms_available}
  POST  /api/account/phone/request    {phone}  saves the number on the account (marked NOT verified) and texts a 6-digit code to it
  POST  /api/account/phone/confirm    {code}   the right code marks the number VERIFIED
  PATCH /api/account/profile          {full_name}

Rules that keep this safe:
  * Signed-in customers only; every change applies to the signed-in customer's own account.
  * The number is saved only if the SMS was actually accepted by the SMS provider. If sending fails, the old number is restored.
  * A number already used by another account is refused.
  * Codes: 6 digits, stored only as a salted hash, valid 10 minutes, 5 wrong tries then a new code is needed,
    one new code per 45 seconds and at most 5 per hour per customer.
  * Changing the number clears its verified status until the new code is entered. The sign-in email is never touched here.
"""
import hashlib
import hmac
import logging
import re
import secrets
import time
from datetime import datetime, timedelta

from flask import g, jsonify, request

logger = logging.getLogger("net365.account")

CODE_MINUTES = 10
RESEND_SECONDS = 45
MAX_PER_HOUR = 5
MAX_TRIES = 5


def normalize_phone(raw):
    """+234XXXXXXXXXX for Nigerian numbers (any common way of typing them); other countries must start with + (E.164). '' if invalid."""
    s = str(raw or "").strip()
    d = re.sub(r"\D", "", s)
    if not d:
        return ""
    if s.startswith("+"):
        return "+" + d if 8 <= len(d) <= 15 else ""
    if d.startswith("234") and len(d) == 13:
        return "+" + d
    if d.startswith("0") and len(d) == 11:
        return "+234" + d[1:]
    if len(d) == 10 and d[0] in "789":
        return "+234" + d
    if d.startswith("00") and 10 <= len(d) <= 17:
        return "+" + d[2:]
    return ""


def init_account(app, get_conn, login_required, send_sms, sms_configured, rate_limit=None, sender_id="Net365"):
    """get_conn: sqlite connection factory (row_factory=sqlite3.Row). send_sms(contacts, message, sender_id) -> {"sent": n, ...}.
    sms_configured: callable returning True when an SMS provider is set up."""
    limit = rate_limit or (lambda *a, **k: (lambda f: f))

    def schema():
        c = get_conn()
        c.execute("CREATE TABLE IF NOT EXISTS phone_otps (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, phone TEXT NOT NULL, "
                  "salt TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TEXT NOT NULL, tries INTEGER DEFAULT 0, "
                  "created_at TEXT DEFAULT CURRENT_TIMESTAMP, used INTEGER DEFAULT 0)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_phone_otps_user ON phone_otps(user_id, id)")
        c.commit()

    try:
        schema()
    except Exception as e:
        logger.warning("phone_otps table not ready: %s", e)

    def now():
        return datetime.utcnow()

    def fmt(t):
        return t.strftime("%Y-%m-%d %H:%M:%S")

    def digest(salt, code):
        return hashlib.sha256((salt + ":" + code).encode()).hexdigest()

    def active_otp(c, uid):
        return c.execute("SELECT * FROM phone_otps WHERE user_id = ? AND used = 0 AND expires_at > ? ORDER BY id DESC LIMIT 1",
                         (uid, fmt(now()))).fetchone()

    @app.route("/api/account/contact", methods=["GET"])
    @login_required
    def account_contact():
        schema()
        c = get_conn()
        u = c.execute("SELECT phone, phone_verified FROM users WHERE id = ?", (g.current_user_id,)).fetchone()
        otp = active_otp(c, g.current_user_id)
        pending = u["phone"] if (u and otp and not u["phone_verified"] and normalize_phone(u["phone"]) == otp["phone"]) else None
        return jsonify({"success": True, "phone": (u["phone"] if u else None), "phone_verified": bool(u and u["phone_verified"]),
                        "pending_phone": pending, "sms_available": bool(sms_configured())})

    @app.route("/api/account/phone/request", methods=["POST"])
    @login_required
    @limit(max_requests=12, window_seconds=600)
    def account_phone_request():
        schema()
        uid = g.current_user_id
        phone = normalize_phone((request.get_json(silent=True) or {}).get("phone"))
        if not phone:
            return jsonify({"success": False, "error": "Enter a valid phone number, like 0803 123 4567 or +234 803 123 4567."}), 400
        if not sms_configured():
            return jsonify({"success": False, "error": "SMS is not available right now. Please try again later."}), 503
        c = get_conn()
        t = now()
        last = c.execute("SELECT created_at FROM phone_otps WHERE user_id = ? ORDER BY id DESC LIMIT 1", (uid,)).fetchone()
        if last:
            try:
                age = (t - datetime.strptime(str(last["created_at"])[:19], "%Y-%m-%d %H:%M:%S")).total_seconds()
                if age < RESEND_SECONDS:
                    return jsonify({"success": False, "error": "Please wait %d seconds before asking for another code." % int(RESEND_SECONDS - age)}), 429
            except ValueError:
                pass
        hour = c.execute("SELECT COUNT(*) FROM phone_otps WHERE user_id = ? AND created_at > ?", (uid, fmt(t - timedelta(hours=1)))).fetchone()[0]
        if hour >= MAX_PER_HOUR:
            return jsonify({"success": False, "error": "Too many codes requested. Please try again in an hour."}), 429
        # the number may be stored as typed at sign-up; compare in canonical form
        for r in c.execute("SELECT id, phone FROM users WHERE phone IS NOT NULL AND phone != '' AND id != ?", (uid,)).fetchall():
            if normalize_phone(r["phone"]) == phone:
                return jsonify({"success": False, "error": "That number is already linked to another Net365 account. Use a different number or contact support."}), 409
        me = c.execute("SELECT phone, phone_verified FROM users WHERE id = ?", (uid,)).fetchone()
        old_phone, old_verified = (me["phone"], me["phone_verified"]) if me else (None, 0)

        code = "%06d" % secrets.randbelow(1000000)
        salt = secrets.token_hex(8)
        msg = "Your Net365 verification code is %s. It expires in %d minutes. Never share this code with anyone." % (code, CODE_MINUTES)
        try:
            res = send_sms([phone.lstrip("+")], msg, sender_id) or {}
        except Exception as e:
            logger.error("verification SMS failed: %s", e)
            res = {"sent": 0}
        if not res.get("sent"):
            logger.warning("verification SMS not accepted for user %s: %s", uid, res)
            return jsonify({"success": False, "error": "We could not send the code. Check the number and try again."}), 502
        # saved only now that the SMS has gone out; stays unverified until the code is entered
        try:
            c.execute("UPDATE phone_otps SET used = 1 WHERE user_id = ? AND used = 0", (uid,))
            c.execute("INSERT INTO phone_otps (user_id, phone, salt, code_hash, expires_at) VALUES (?,?,?,?,?)",
                      (uid, phone, salt, digest(salt, code), fmt(t + timedelta(minutes=CODE_MINUTES))))
            same = normalize_phone(old_phone) == phone
            c.execute("UPDATE users SET phone = ?, phone_verified = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                      (phone, 1 if (same and old_verified) else 0, uid))
            c.commit()
        except Exception as e:  # for example the unique phone constraint
            c.rollback()
            logger.error("could not save phone for user %s: %s", uid, e)
            return jsonify({"success": False, "error": "That number could not be saved. Use a different number or contact support."}), 409
        return jsonify({"success": True, "phone": phone, "verified": bool(same and old_verified), "expires_minutes": CODE_MINUTES})

    @app.route("/api/account/phone/confirm", methods=["POST"])
    @login_required
    @limit(max_requests=20, window_seconds=600)
    def account_phone_confirm():
        schema()
        uid = g.current_user_id
        code = re.sub(r"\D", "", str((request.get_json(silent=True) or {}).get("code") or ""))
        if len(code) != 6:
            return jsonify({"success": False, "error": "Enter the 6-digit code."}), 400
        c = get_conn()
        otp = active_otp(c, uid)
        if not otp:
            return jsonify({"success": False, "error": "That code has expired. Tap Resend code to get a new one."}), 400
        if (otp["tries"] or 0) >= MAX_TRIES:
            return jsonify({"success": False, "error": "Too many wrong tries. Tap Resend code to get a new one."}), 429
        if not hmac.compare_digest(digest(otp["salt"], code), otp["code_hash"]):
            c.execute("UPDATE phone_otps SET tries = tries + 1 WHERE id = ?", (otp["id"],))
            c.commit()
            return jsonify({"success": False, "error": "That code is not correct."}), 400
        u = c.execute("SELECT phone FROM users WHERE id = ?", (uid,)).fetchone()
        if not u or normalize_phone(u["phone"]) != otp["phone"]:
            return jsonify({"success": False, "error": "This code was for a different number. Request a new code."}), 400
        c.execute("UPDATE phone_otps SET used = 1 WHERE id = ?", (otp["id"],))
        c.execute("UPDATE users SET phone_verified = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (uid,))
        c.commit()
        return jsonify({"success": True, "phone": otp["phone"]})

    @app.route("/api/account/profile", methods=["PATCH"])
    @login_required
    @limit(max_requests=20, window_seconds=600)
    def account_profile_patch():
        name = re.sub(r"[<>\u0000-\u001f]", " ", re.sub(r"\s+", " ", str((request.get_json(silent=True) or {}).get("full_name") or ""))).strip()
        if len(name) < 2 or len(name) > 120:
            return jsonify({"success": False, "error": "Please enter your full name (2 to 120 characters)."}), 400
        c = get_conn()
        c.execute("UPDATE users SET full_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (name, g.current_user_id))
        c.commit()
        return jsonify({"success": True, "full_name": name})

    logger.info("Account contact routes ready (phone verification by SMS)")

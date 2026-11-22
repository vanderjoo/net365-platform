"""
Net365 account administration + self-service contact details.

Admin (X-Admin-Secret):
    GET   /api/admin/users/deleted                      deleted-accounts audit list (with remarks)
    POST  /api/admin/users/<id>/restore                 restore a deleted account (remarks required)
    PATCH /api/admin/users/<id>                         edit name / email / phone (+ optional verification sends)
    POST  /api/admin/users/<id>/send-email-verification email code to the account's email
    POST  /api/admin/users/<id>/send-phone-verification SMS code to the account's phone

Customer (signed in):
    GET   /api/account/contact                          name, email, phone, verification state
    PATCH /api/account/profile                          change full name
    POST  /api/account/phone/request                    send an SMS code to a new number
    POST  /api/account/phone/confirm                    enter the code; only then the number is saved as verified

A phone number only becomes "verified" (and usable for transactions) after the customer types the
code that was texted to it. Deleted accounts are never erased: they stay in user_deletion_audit with
who deleted them, when and why.
"""
import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import time

from flask import g, jsonify, request

logger = logging.getLogger(__name__)

CODE_TTL_SECONDS = 10 * 60
MAX_ATTEMPTS = 5
MAX_SENDS_PER_HOUR = 5
MIN_REMARKS = 5
DEFAULT_REGION = os.getenv("DEFAULT_PHONE_REGION", "NG")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")


# ---------------------------------------------------------------- helpers
def normalize_phone(raw, region=None):
    """Return an E.164 number like +2348012345678, or None when it is not a plausible phone number."""
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        import phonenumbers
        num = phonenumbers.parse(raw, region or DEFAULT_REGION)
        if phonenumbers.is_possible_number(num) and phonenumbers.is_valid_number(num):
            return phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        return None
    except Exception:
        pass
    digits = re.sub(r"\D", "", raw)
    if raw.startswith("+"):
        return "+" + digits if 8 <= len(digits) <= 15 else None
    if digits.startswith("00") and 10 <= len(digits) <= 17:
        return "+" + digits[2:]
    if (region or DEFAULT_REGION) == "NG":
        if digits.startswith("0") and len(digits) == 11:
            return "+234" + digits[1:]
        if digits.startswith("234") and len(digits) == 13:
            return "+" + digits
        if len(digits) == 10 and digits[0] in "789":
            return "+234" + digits
    return None


def _digits(s):
    return re.sub(r"\D", "", s or "")


def _same_number(a, b):
    """Compare two stored numbers by their last 9 digits so 0803... and +234803... match."""
    da, db_ = _digits(a), _digits(b)
    return len(da) >= 7 and len(db_) >= 7 and da[-9:] == db_[-9:]


def _conn(db):
    c = db.get_db_connection()
    c.row_factory = sqlite3.Row
    return c


def _ensure_tables(c):
    c.execute(
        """CREATE TABLE IF NOT EXISTS user_deletion_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email TEXT, full_name TEXT, phone TEXT,
            status_before TEXT,
            remarks TEXT NOT NULL,
            deleted_by TEXT,
            deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            restored_at TIMESTAMP, restored_by TEXT, restore_remarks TEXT
        )"""
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_del_audit_user ON user_deletion_audit(user_id)")
    c.execute(
        """CREATE TABLE IF NOT EXISTS contact_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            channel TEXT NOT NULL,
            target TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            expires_at REAL NOT NULL,
            attempts INTEGER DEFAULT 0,
            consumed INTEGER DEFAULT 0,
            created_at REAL NOT NULL,
            requested_by TEXT
        )"""
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_contact_ver_user ON contact_verifications(user_id, channel)")


def _hash_code(user_id, channel, target, code):
    key = (os.getenv("SECRET_KEY") or os.getenv("ENCRYPTION_KEY") or "net365-contact").encode()
    return hmac.new(key, f"{user_id}|{channel}|{target}|{code}".encode(), hashlib.sha256).hexdigest()


def _new_code():
    return f"{secrets.randbelow(1_000_000):06d}"


def _user_row(c, uid):
    return c.execute(
        "SELECT id, email, phone, full_name, account_status, status_reason, email_verified, phone_verified, created_at FROM users WHERE id=?",
        (uid,),
    ).fetchone()


def _public(row):
    return {k: row[k] for k in row.keys()} if row else None


def _clean_text(s, limit):
    s = re.sub(r"[\x00-\x1f\x7f]", "", str(s or "")).strip()
    return s[:limit]


# ---------------------------------------------------------------- audit (used by main.py's DELETE route)
def record_user_deletion(db, user, remarks, deleted_by):
    """Write the audit row for a soft delete. The user's row itself is kept (account_status = 'deleted')."""
    c = _conn(db)
    try:
        _ensure_tables(c)
        c.execute(
            "INSERT INTO user_deletion_audit (user_id, email, full_name, phone, status_before, remarks, deleted_by) VALUES (?,?,?,?,?,?,?)",
            (user.get("id"), user.get("email"), user.get("full_name"), user.get("phone"),
             user.get("account_status") or "active", remarks, deleted_by),
        )
        c.commit()
    finally:
        c.close()


def clean_remarks(raw):
    r = _clean_text(raw, 1000)
    return r if len(r) >= MIN_REMARKS else None


# ---------------------------------------------------------------- init
def init_accounts(app, db, login_required, admin_required, rate_limit, send_email, send_sms, sms_ready,
                  log_event, admin_identity):
    """send_email(to, subject, message, wait_seconds=0) -> bool ; send_sms(e164, text) -> bool ;
    sms_ready() -> bool ; admin_identity() -> str (who is acting, for the audit trail)."""

    c = _conn(db)
    try:
        _ensure_tables(c)
        c.commit()
    finally:
        c.close()

    def _kill_sessions(uid):
        try:
            return db.kill_user_sessions(uid)
        except Exception as e:
            logger.warning("could not kill sessions for %s: %s", uid, e)
            return 0

    def _store_code(c, uid, channel, target, requested_by):
        """Create a new code (older unused ones are invalidated). Enforces a per-user hourly send cap."""
        hour_ago = time.time() - 3600
        sent = c.execute(
            "SELECT COUNT(*) FROM contact_verifications WHERE user_id=? AND channel=? AND created_at>?", (uid, channel, hour_ago)
        ).fetchone()[0]
        if sent >= MAX_SENDS_PER_HOUR:
            return None
        c.execute("UPDATE contact_verifications SET consumed=1 WHERE user_id=? AND channel=? AND consumed=0", (uid, channel))
        code = _new_code()
        c.execute(
            "INSERT INTO contact_verifications (user_id, channel, target, code_hash, expires_at, created_at, requested_by) VALUES (?,?,?,?,?,?,?)",
            (uid, channel, target, _hash_code(uid, channel, target, code), time.time() + CODE_TTL_SECONDS, time.time(), requested_by),
        )
        return code

    def _send_phone_code(uid, target, requested_by):
        """-> (ok, error_message, http_status)"""
        if not sms_ready():
            return False, "No SMS provider is configured (set TERMII_API_KEY, TWILIO_* or AT_*).", 503
        c = _conn(db)
        try:
            code = _store_code(c, uid, "phone", target, requested_by)
            c.commit()
        finally:
            c.close()
        if code is None:
            return False, "Too many codes requested. Try again in an hour.", 429
        ok = False
        try:
            ok = bool(send_sms(target, f"Your Net365 verification code is {code}. It expires in 10 minutes. Never share this code."))
        except Exception as e:
            logger.error("SMS send failed for user %s: %s", uid, e)
        if not ok:
            return False, "The SMS could not be sent right now. Please try again.", 502
        return True, None, 200

    # ================================================================ ADMIN
    @app.route("/api/admin/users/deleted", methods=["GET"], endpoint="acct_deleted_list")
    @admin_required
    def deleted_list():
        q = (request.args.get("q") or "").strip()
        c = _conn(db)
        try:
            _ensure_tables(c)
            sql = ("SELECT a.*, u.account_status AS current_status FROM user_deletion_audit a "
                   "LEFT JOIN users u ON u.id = a.user_id")
            params = []
            if q:
                sql += " WHERE a.email LIKE ? OR a.full_name LIKE ? OR a.phone LIKE ? OR a.remarks LIKE ?"
                params = [f"%{q}%"] * 4
            sql += " ORDER BY a.id DESC LIMIT 200"
            rows = [dict(r) for r in c.execute(sql, params).fetchall()]
        finally:
            c.close()
        return jsonify({"success": True, "deleted": rows})

    @app.route("/api/admin/users/<int:uid>/restore", methods=["POST"], endpoint="acct_restore")
    @admin_required
    def restore_user(uid):
        data = request.get_json(silent=True) or {}
        remarks = clean_remarks(data.get("remarks") or data.get("reason"))
        if not remarks:
            return jsonify({"success": False, "error": f"Remarks are required (at least {MIN_REMARKS} characters)."}), 400
        user = db.get_user(uid)
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        if (user.get("account_status") or "active") != "deleted":
            return jsonify({"success": False, "error": "This account is not deleted."}), 409
        who = admin_identity()
        db.set_account_status(uid, "active", f"Restored: {remarks}")
        c = _conn(db)
        try:
            _ensure_tables(c)
            c.execute(
                "UPDATE user_deletion_audit SET restored_at=CURRENT_TIMESTAMP, restored_by=?, restore_remarks=? "
                "WHERE id=(SELECT MAX(id) FROM user_deletion_audit WHERE user_id=? AND restored_at IS NULL)",
                (who, remarks, uid),
            )
            c.commit()
        finally:
            c.close()
        log_event(user_id=uid, event_type="account_restored", details={"remarks": remarks, "admin": who}, status="success")
        return jsonify({"success": True, "message": "Account restored."})

    @app.route("/api/admin/users/<int:uid>", methods=["PATCH"], endpoint="acct_admin_update")
    @admin_required
    def admin_update_user(uid):
        data = request.get_json(silent=True) or {}
        c = _conn(db)
        try:
            row = _user_row(c, uid)
            if not row:
                return jsonify({"success": False, "error": "User not found"}), 404
            if (row["account_status"] or "active") == "deleted":
                return jsonify({"success": False, "error": "Restore this account before editing it."}), 409

            sets, vals, changes = [], [], {}
            sessions_killed = 0

            if "full_name" in data:
                name = _clean_text(data.get("full_name"), 120)
                if len(name) < 2:
                    return jsonify({"success": False, "error": "Name must be at least 2 characters."}), 400
                if name != (row["full_name"] or ""):
                    sets.append("full_name=?"); vals.append(name)
                    changes["full_name"] = [row["full_name"], name]

            new_email = None
            if "email" in data:
                new_email = _clean_text(data.get("email"), 254).lower()
                if not EMAIL_RE.match(new_email):
                    return jsonify({"success": False, "error": "Enter a valid email address."}), 400
                if new_email != (row["email"] or "").lower():
                    clash = c.execute("SELECT id FROM users WHERE lower(email)=? AND id!=?", (new_email, uid)).fetchone()
                    if clash:
                        return jsonify({"success": False, "error": "That email belongs to another account."}), 409
                    sets += ["email=?", "email_verified=0"]
                    vals.append(new_email)
                    changes["email"] = [row["email"], new_email]
                else:
                    new_email = None

            new_phone = None
            if "phone" in data:
                raw = _clean_text(data.get("phone"), 40)
                if raw == "":
                    if row["phone"]:
                        sets += ["phone=NULL", "phone_verified=0"]
                        changes["phone"] = [row["phone"], None]
                else:
                    e164 = normalize_phone(raw)
                    if not e164:
                        return jsonify({"success": False, "error": "That phone number does not look valid. Use 0803... or +234803..."}), 400
                    if e164 != row["phone"]:
                        for other in c.execute("SELECT id, phone FROM users WHERE phone IS NOT NULL AND phone!='' AND id!=? AND phone_verified=1", (uid,)).fetchall():
                            if _same_number(other["phone"], e164):
                                return jsonify({"success": False, "error": "That number is verified on another account."}), 409
                        sets += ["phone=?", "phone_verified=0"]
                        vals.append(e164)
                        new_phone = e164
                        changes["phone"] = [row["phone"], e164]

            if sets:
                c.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", vals + [uid])
                c.commit()
                if "email" in changes:
                    sessions_killed = _kill_sessions(uid)   # the email is the login identity: force a fresh sign-in
            updated = _public(_user_row(c, uid))
        finally:
            c.close()

        who = admin_identity()
        if changes:
            log_event(user_id=uid, event_type="account_updated_by_admin", details={"changes": changes, "admin": who, "sessions_killed": sessions_killed}, status="success")
            if "email" in changes and changes["email"][0]:
                try:   # tell the OLD address, so a hijack by an admin mistake or a stolen secret is visible
                    send_email(changes["email"][0], "Your Net365 email was changed",
                               f"The email on your Net365 account was changed to {changes['email'][1]} by our support team. If this was not expected, contact support@net365co.com.")
                except Exception as e:
                    logger.warning("old-email notice failed: %s", e)

        sent = {}
        if data.get("send_email_verification") and updated and updated.get("email"):
            sent["email"] = _admin_send_email_code(updated)
        if data.get("send_phone_verification") and updated and updated.get("phone"):
            sent["phone"] = _admin_send_phone_code(updated, who)
        return jsonify({"success": True, "user": updated, "changed": list(changes.keys()), "verification_sent": sent})

    def _admin_send_email_code(user):
        try:
            code = db.create_verification_otp(user["email"], otp_type="email", ttl_minutes=30)
            ok = bool(send_email(
                user["email"], "Verify your Net365 email",
                f'Your verification code is <span class="amount">{code}</span>. It expires in 30 minutes. Enter it in the app to verify your email.',
                wait_seconds=10))
            return {"sent": ok, "error": None if ok else "Email provider did not confirm delivery. Check Admin > Alerts."}
        except Exception as e:
            logger.error("admin email verification failed for %s: %s", user.get("id"), e)
            return {"sent": False, "error": "Could not create or send the code."}

    def _admin_send_phone_code(user, who):
        e164 = normalize_phone(user.get("phone"))
        if not e164:
            return {"sent": False, "error": "The stored phone number is not a valid number. Edit it first."}
        ok, err, _ = _send_phone_code(user["id"], e164, f"admin:{who}")
        return {"sent": ok, "error": err}

    @app.route("/api/admin/users/<int:uid>/send-email-verification", methods=["POST"], endpoint="acct_send_email_ver")
    @admin_required
    def send_email_verification(uid):
        c = _conn(db)
        try:
            row = _user_row(c, uid)
        finally:
            c.close()
        if not row:
            return jsonify({"success": False, "error": "User not found"}), 404
        if (row["account_status"] or "active") == "deleted":
            return jsonify({"success": False, "error": "This account is deleted."}), 409
        if not row["email"]:
            return jsonify({"success": False, "error": "This account has no email."}), 400
        res = _admin_send_email_code(dict(row))
        log_event(user_id=uid, event_type="admin_sent_email_verification", details={"admin": admin_identity(), "ok": res["sent"]}, status="success" if res["sent"] else "failed")
        return jsonify({"success": res["sent"], "error": res["error"]}), (200 if res["sent"] else 502)

    @app.route("/api/admin/users/<int:uid>/send-phone-verification", methods=["POST"], endpoint="acct_send_phone_ver")
    @admin_required
    def send_phone_verification(uid):
        c = _conn(db)
        try:
            row = _user_row(c, uid)
        finally:
            c.close()
        if not row:
            return jsonify({"success": False, "error": "User not found"}), 404
        if (row["account_status"] or "active") == "deleted":
            return jsonify({"success": False, "error": "This account is deleted."}), 409
        if not row["phone"]:
            return jsonify({"success": False, "error": "This account has no phone number. Add one first."}), 400
        e164 = normalize_phone(row["phone"])
        if not e164:
            return jsonify({"success": False, "error": "The stored phone number is not valid. Edit it first."}), 400
        ok, err, status = _send_phone_code(uid, e164, f"admin:{admin_identity()}")
        log_event(user_id=uid, event_type="admin_sent_phone_verification", details={"admin": admin_identity(), "ok": ok}, status="success" if ok else "failed")
        return jsonify({"success": ok, "error": err}), status

    # ================================================================ CUSTOMER
    @app.route("/api/account/contact", methods=["GET"], endpoint="acct_contact")
    @login_required
    def my_contact():
        c = _conn(db)
        try:
            row = _user_row(c, g.current_user_id)
            _ensure_tables(c)
            pending = c.execute(
                "SELECT target FROM contact_verifications WHERE user_id=? AND channel='phone' AND consumed=0 AND expires_at>? ORDER BY id DESC LIMIT 1",
                (g.current_user_id, time.time()),
            ).fetchone()
        finally:
            c.close()
        return jsonify({
            "success": True,
            "full_name": row["full_name"], "email": row["email"], "email_verified": bool(row["email_verified"]),
            "phone": row["phone"], "phone_verified": bool(row["phone_verified"]),
            "pending_phone": pending["target"] if pending else None,
            "sms_available": bool(sms_ready()),
        })

    @app.route("/api/account/profile", methods=["PATCH"], endpoint="acct_profile_update")
    @login_required
    @rate_limit(max_requests=20, window_seconds=300)
    def update_my_profile():
        data = request.get_json(silent=True) or {}
        name = _clean_text(data.get("full_name"), 120)
        if len(name) < 2:
            return jsonify({"success": False, "error": "Please enter your full name."}), 400
        c = _conn(db)
        try:
            old = _user_row(c, g.current_user_id)["full_name"]
            c.execute("UPDATE users SET full_name=? WHERE id=?", (name, g.current_user_id))
            c.commit()
        finally:
            c.close()
        log_event(user_id=g.current_user_id, event_type="profile_name_changed", details={"from": old, "to": name}, status="success")
        return jsonify({"success": True, "full_name": name})

    @app.route("/api/account/phone/request", methods=["POST"], endpoint="acct_phone_request")
    @login_required
    @rate_limit(max_requests=6, window_seconds=600)
    def phone_request():
        data = request.get_json(silent=True) or {}
        e164 = normalize_phone(data.get("phone"))
        if not e164:
            return jsonify({"success": False, "error": "That phone number does not look valid. Use 0803... or +234803..."}), 400
        uid = g.current_user_id
        c = _conn(db)
        try:
            for other in c.execute("SELECT id, phone FROM users WHERE phone IS NOT NULL AND phone!='' AND id!=? AND phone_verified=1", (uid,)).fetchall():
                if _same_number(other["phone"], e164):
                    return jsonify({"success": False, "error": "That number is already linked to another account."}), 409
            me = _user_row(c, uid)
            if me["phone_verified"] and me["phone"] == e164:
                return jsonify({"success": False, "error": "That number is already verified on your account."}), 409
            # The number is SAVED NOW, as unverified, whether or not the SMS goes out.
            # It only becomes verified when the customer enters the code (see phone_confirm).
            if me["phone"] != e164:
                c.execute("UPDATE users SET phone=?, phone_verified=0 WHERE id=?", (e164, uid))
                c.commit()
                saved_change = [me["phone"], e164]
            else:
                saved_change = None
        finally:
            c.close()
        if saved_change:
            log_event(user_id=uid, event_type="phone_added_unverified", details={"phone_tail": e164[-4:], "replaced": bool(saved_change[0])}, status="success")
        ok, err, _status = _send_phone_code(uid, e164, "self")
        log_event(user_id=uid, event_type="phone_code_requested", details={"phone_tail": e164[-4:], "sms_sent": ok}, status="success" if ok else "failed")
        return jsonify({"success": True, "saved": True, "phone": e164, "phone_verified": False,
                        "sms_sent": ok, "sms_error": err, "expires_in": CODE_TTL_SECONDS})

    @app.route("/api/account/phone/confirm", methods=["POST"], endpoint="acct_phone_confirm")
    @login_required
    @rate_limit(max_requests=12, window_seconds=600)
    def phone_confirm():
        data = request.get_json(silent=True) or {}
        code = re.sub(r"\D", "", str(data.get("code") or ""))
        if len(code) != 6:
            return jsonify({"success": False, "error": "Enter the 6-digit code from the SMS."}), 400
        uid = g.current_user_id
        c = _conn(db)
        try:
            v = c.execute(
                "SELECT * FROM contact_verifications WHERE user_id=? AND channel='phone' AND consumed=0 ORDER BY id DESC LIMIT 1", (uid,)
            ).fetchone()
            if not v or v["expires_at"] < time.time():
                return jsonify({"success": False, "error": "That code has expired. Request a new one."}), 400
            if v["attempts"] >= MAX_ATTEMPTS:
                c.execute("UPDATE contact_verifications SET consumed=1 WHERE id=?", (v["id"],))
                c.commit()
                return jsonify({"success": False, "error": "Too many wrong attempts. Request a new code."}), 429
            if not hmac.compare_digest(v["code_hash"], _hash_code(uid, "phone", v["target"], code)):
                c.execute("UPDATE contact_verifications SET attempts=attempts+1 WHERE id=?", (v["id"],))
                c.commit()
                return jsonify({"success": False, "error": "That code is not correct."}), 400
            # the number could have been verified elsewhere since the code was sent
            for other in c.execute("SELECT id, phone FROM users WHERE phone IS NOT NULL AND phone!='' AND id!=? AND phone_verified=1", (uid,)).fetchall():
                if _same_number(other["phone"], v["target"]):
                    return jsonify({"success": False, "error": "That number is already linked to another account."}), 409
            c.execute("UPDATE contact_verifications SET consumed=1 WHERE id=?", (v["id"],))
            c.execute("UPDATE users SET phone=?, phone_verified=1 WHERE id=?", (v["target"], uid))
            c.commit()
            phone = v["target"]
        finally:
            c.close()
        log_event(user_id=uid, event_type="phone_verified", details={"phone_tail": phone[-4:]}, status="success")
        try:
            db.create_notification(uid, "Phone number verified", "Your phone number is verified and can now be used for transactions.", "success")
        except Exception:
            pass
        return jsonify({"success": True, "phone": phone, "phone_verified": True})

    return {
        "normalize_phone": normalize_phone,
        "record_user_deletion": record_user_deletion,
        "send_email_code": _admin_send_email_code,                 # (user_dict) -> {"sent": bool, "error": str|None}
        "send_phone_code": lambda user, who="admin": _admin_send_phone_code(user, who),
    }

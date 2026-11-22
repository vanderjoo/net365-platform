"""Net365 Unified Identity and Profile Completion engine.

One Net365 identity per customer, whatever door they came through (Google, email and password,
WhatsApp, Telegram). This module owns the phone-number part of that identity:

  * E.164 normalisation and validation for any country
  * OTP proof of ownership (expiry, attempt limits, resend cooldown, hourly and daily caps)
  * a verified-phone table with a database-level uniqueness guarantee (one verified number, one account)
  * a single "is this profile complete?" check that every channel and every money route can ask
  * safe adoption of a WhatsApp number (the chat already proved it) without ever creating a duplicate
  * an audit trail and an admin audit report

Design rules (what this module will never do)
  * It never creates a user, never changes a user id, and never touches wallets, balances, orders or referrals.
  * It never overwrites a phone number that is already on the account without a fresh OTP on the new number.
  * It does not alter the existing `users` table. Everything lives in its own tables, so the migration
    is additive and can be rolled back by simply not registering the module.
  * Accounts that already had a phone number before this module was first started are "grandfathered":
    they keep working, and are only nudged to verify. Accounts with no phone at all (for example Google
    sign-ups) must add and verify one before money moves.

Policy: verification is OPTIONAL. By default (IDENTITY_MODE=off) nothing is ever blocked and nobody is redirected: every
service works with or without a verified number. Customers without one get gentle reminder EMAILS only (a few over
about three months, each with a one-tap opt-out), and a verified number simply makes receipts, token alerts and account
recovery work better. IDENTITY_MODE=enforce remains available if the business ever wants to require it; log records what
enforce would have blocked.

Modes (env IDENTITY_MODE): off (default, optional) | log | enforce.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from flask import jsonify, request, g

try:  # the best validator available; a built-in fallback is used if it is not installed
    import phonenumbers
    from phonenumbers import NumberParseException, PhoneNumberFormat
except Exception:  # pragma: no cover
    phonenumbers = None

logger = logging.getLogger(__name__)

OTP_DIGITS = 6
OTP_TTL_SECONDS = 10 * 60
OTP_MAX_ATTEMPTS = 5
RESEND_COOLDOWN_SECONDS = 45
MAX_SENDS_PER_USER_HOUR = 5
MAX_SENDS_PER_NUMBER_HOUR = 3
MAX_SENDS_PER_NUMBER_DAY = 10
MAX_BURNED_CODES_HOUR = 3          # then verification is locked for a while
LOCK_MINUTES = 30
MAX_PHONE_CHANGES_PER_30_DAYS = 2

_db = None
_deliver = None          # callable(e164, message) -> bool
_notify_email = None     # callable(email, subject, message) -> any
_sms_ready = None        # callable() -> bool: is a real SMS provider configured?
_lock = threading.Lock()


# ----------------------------------------------------------------------------- helpers
def _now():
    return datetime.now(timezone.utc)


def _iso(dt=None):
    return (dt or _now()).isoformat(timespec="seconds")


def mode():
    m = os.getenv("IDENTITY_MODE", "off").strip().lower()
    return m if m in ("enforce", "log", "off") else "off"


def _conn():
    # Same convention as the rest of the project: the connection helper may hand back a shared connection.
    return _db.get_db_connection()


def _val(row, key, idx=0, default=None):
    if row is None:
        return default
    try:
        return row[key]
    except Exception:
        try:
            return row[idx]
        except Exception:
            return default


def _secret():
    return (os.getenv("IDENTITY_SECRET") or os.getenv("SECRET_KEY") or os.getenv("FLASK_SECRET_KEY") or "net365-identity").encode()


def _code_hash(otp_id, code):
    return hmac.new(_secret(), f"{otp_id}:{code}".encode(), hashlib.sha256).hexdigest()


def mask_phone(e164):
    d = re.sub(r"\D", "", str(e164 or ""))
    if len(d) < 7:
        return ""
    return f"+{d[:3]}{'•' * max(2, len(d) - 7)}{d[-4:]}"


# ----------------------------------------------------------------------------- phone numbers
# Fallback rules used only when the `phonenumbers` package is missing: dial code, national length range.
_FALLBACK = {
    "NG": ("234", 10, 10), "GH": ("233", 9, 9), "KE": ("254", 9, 9), "ZA": ("27", 9, 9), "US": ("1", 10, 10),
    "CA": ("1", 10, 10), "GB": ("44", 10, 10), "AE": ("971", 8, 9), "IN": ("91", 10, 10), "FR": ("33", 9, 9),
    "DE": ("49", 7, 12), "CM": ("237", 8, 9), "SN": ("221", 9, 9), "CI": ("225", 8, 10), "TZ": ("255", 9, 9),
    "UG": ("256", 9, 9), "ET": ("251", 9, 9), "EG": ("20", 9, 10), "BR": ("55", 10, 11), "ES": ("34", 9, 9),
    "IT": ("39", 9, 11), "PK": ("92", 10, 10), "PH": ("63", 10, 10), "CN": ("86", 10, 11), "AU": ("61", 9, 9),
}
_NG_RE = re.compile(r"^[789][01]\d{8}$")


def countries():
    """Every dialling region the validator knows, for the country picker. The browser names them (Intl.DisplayNames)."""
    out = []
    if phonenumbers:
        for cc in sorted(phonenumbers.SUPPORTED_REGIONS):
            try:
                out.append({"cc": cc, "dial": str(phonenumbers.country_code_for_region(cc))})
            except Exception:
                pass
    else:
        out = [{"cc": cc, "dial": v[0]} for cc, v in sorted(_FALLBACK.items())]
    return out


def normalize_phone(raw, country=None):
    """-> (e164 or None, region or None, error_code or None).

    `raw` may be national ("0803 123 4567"), international ("+234 803 123 4567", "00234...") or a bare
    country-code number. `country` is the ISO region the customer picked (used for national formats).
    """
    s = str(raw or "").strip()
    cc = (str(country or "").strip().upper() or None)
    if not s:
        return None, None, "empty"
    if s.startswith("00"):
        s = "+" + s[2:]
    if phonenumbers:
        try:
            num = phonenumbers.parse(s, None if s.startswith("+") else cc)
        except NumberParseException:
            return None, cc, "invalid"
        if not phonenumbers.is_valid_number(num):
            return None, cc, "invalid"
        region = phonenumbers.region_code_for_number(num) or cc
        return phonenumbers.format_number(num, PhoneNumberFormat.E164), region, None
    # ---- fallback
    digits = re.sub(r"\D", "", s)
    if s.startswith("+"):
        for rc, (dial, lo, hi) in sorted(_FALLBACK.items(), key=lambda kv: -len(kv[1][0])):
            if digits.startswith(dial) and lo <= len(digits) - len(dial) <= hi:
                nat = digits[len(dial):]
                if dial == "234" and not _NG_RE.match(nat):
                    continue
                return "+" + digits, rc, None
        return None, cc, "invalid"
    if cc in _FALLBACK:
        dial, lo, hi = _FALLBACK[cc]
        nat = digits[len(dial):] if digits.startswith(dial) and len(digits) - len(dial) >= lo else digits.lstrip("0")
        if cc == "NG" and not _NG_RE.match(nat):
            return None, cc, "invalid"
        if lo <= len(nat) <= hi:
            return "+" + dial + nat, cc, None
    return None, cc, "invalid"


def national_display(e164):
    """Nigerian numbers are shown the way Nigerians write them (0803...); everything else stays international."""
    if str(e164).startswith("+234") and len(e164) == 14:
        return "0" + e164[4:]
    return e164


def guess_country():
    """Best guess of the visitor's country from edge headers, then Accept-Language. Never blocks; defaults to NG."""
    for h in ("CF-IPCountry", "X-Vercel-IP-Country", "X-Country-Code", "CloudFront-Viewer-Country"):
        v = (request.headers.get(h) or "").strip().upper()
        if re.fullmatch(r"[A-Z]{2}", v) and v not in ("XX", "T1"):
            return v
    m = re.search(r"-([A-Za-z]{2})\b", request.headers.get("Accept-Language", ""))
    return m.group(1).upper() if m else "NG"


# ----------------------------------------------------------------------------- schema
def ensure_schema():
    c = _conn()
    c.execute("""CREATE TABLE IF NOT EXISTS user_phones (
        user_id INTEGER PRIMARY KEY,
        phone_e164 TEXT NOT NULL,
        country TEXT,
        verified INTEGER NOT NULL DEFAULT 0,
        verified_at TEXT,
        source TEXT,
        changes INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL)""")
    # The database itself refuses a second account claiming the same verified number.
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_user_phones_verified ON user_phones(phone_e164) WHERE verified = 1")
    c.execute("CREATE INDEX IF NOT EXISTS ix_user_phones_phone ON user_phones(phone_e164)")
    c.execute("""CREATE TABLE IF NOT EXISTS phone_verifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        phone_e164 TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        ip TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL)""")
    c.execute("CREATE INDEX IF NOT EXISTS ix_phone_ver_user ON phone_verifications(user_id, created_at)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_phone_ver_phone ON phone_verifications(phone_e164, created_at)")
    c.execute("""CREATE TABLE IF NOT EXISTS identity_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, event TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS phone_claims (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, code_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL, expires_at TEXT NOT NULL)""")
    c.execute("CREATE INDEX IF NOT EXISTS ix_phone_claims_hash ON phone_claims(code_hash, status)")
    c.execute("""CREATE TABLE IF NOT EXISTS identity_reminders (
        user_id INTEGER PRIMARY KEY, first_seen TEXT NOT NULL, next_due TEXT NOT NULL,
        sent_count INTEGER NOT NULL DEFAULT 0, last_sent_at TEXT, opted_out INTEGER NOT NULL DEFAULT 0)""")
    c.execute("CREATE INDEX IF NOT EXISTS ix_identity_reminders_due ON identity_reminders(opted_out, next_due)")
    c.execute("CREATE TABLE IF NOT EXISTS identity_meta (k TEXT PRIMARY KEY, v TEXT)")
    # Everyone who exists today is grandfathered if they already had a phone. Recorded once, never moved.
    if not c.execute("SELECT 1 FROM identity_meta WHERE k='grandfather_max_user_id'").fetchone():
        try:
            mx = _val(c.execute("SELECT COALESCE(MAX(id),0) AS m FROM users").fetchone(), "m", 0, 0)
        except Exception:
            mx = 0
        c.execute("INSERT OR IGNORE INTO identity_meta (k, v) VALUES ('grandfather_max_user_id', ?)", (str(int(mx or 0)),))
        c.execute("INSERT OR IGNORE INTO identity_meta (k, v) VALUES ('activated_at', ?)", (_iso(),))
    # The chat link table may not exist yet in a fresh database; identities are recorded there when present.
    c.execute("""CREATE TABLE IF NOT EXISTS net365_identities (
        provider TEXT NOT NULL, subject TEXT NOT NULL, user_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (provider, subject))""")
    c.commit()


def _event(user_id, event, detail=""):
    try:
        c = _conn()
        c.execute("INSERT INTO identity_events (user_id, event, detail, created_at) VALUES (?,?,?,?)",
                  (user_id, event, str(detail)[:300], _iso()))
        c.commit()
    except Exception:
        logger.warning("identity: could not write event %s", event, exc_info=True)


def _grandfather_max():
    try:
        r = _conn().execute("SELECT v FROM identity_meta WHERE k='grandfather_max_user_id'").fetchone()
        return int(_val(r, "v", 0, 0) or 0)
    except Exception:
        return 0


# ----------------------------------------------------------------------------- reading a profile
def _legacy_phone(user_id):
    """The phone stored on the old users row, if any. Unverified by definition."""
    try:
        r = _conn().execute("SELECT phone FROM users WHERE id = ?", (user_id,)).fetchone()
        return str(_val(r, "phone", 0, "") or "").strip()
    except Exception:
        return ""


def _is_guest(user_id):
    try:
        from net365_whatsapp import is_guest_user
        return bool(is_guest_user(user_id))
    except Exception:
        return False


def get_phone_row(user_id):
    r = _conn().execute("SELECT * FROM user_phones WHERE user_id = ?", (user_id,)).fetchone()
    return r


def effective_phone(user_id):
    """The best phone we hold for this account: {'e164','national','verified','source'} or None.
    Verified number first, then the unverified one the customer typed at sign-up."""
    row = get_phone_row(user_id)
    if row is not None:
        e = _val(row, "phone_e164", 1)
        return {"e164": e, "national": national_display(e), "verified": bool(_val(row, "verified", 3)),
                "source": _val(row, "source", 5)}
    legacy = _legacy_phone(user_id)
    if legacy:
        e, _rg, err = normalize_phone(legacy, "NG")
        if e:
            return {"e164": e, "national": national_display(e), "verified": False, "source": "legacy"}
    return None


def profile_status(user_id):
    """The single completeness check. Cheap, read-only, safe to call on every request."""
    ph = effective_phone(user_id)
    guest = _is_guest(user_id)
    grandfathered = bool(ph and not ph["verified"] and ph["source"] == "legacy" and int(user_id) <= _grandfather_max())
    complete = bool(guest or (ph and ph["verified"]) or grandfathered)
    missing = [] if complete else ["phone"]
    return {
        "complete": complete,
        "missing": missing,
        "phone": ({"masked": mask_phone(ph["e164"]), "national": ph["national"], "verified": ph["verified"]} if ph else None),
        "needs_verification": bool(ph and not ph["verified"] and not guest),   # nudge, not a block, when grandfathered
        "grandfathered": grandfathered,
        "guest": guest,
        "mode": mode(),
    }


def gate_error(user_id):
    """None when the account may move money, otherwise (json_body, http_status)."""
    if mode() == "off" or not user_id:
        return None
    try:
        st = profile_status(user_id)
    except Exception:
        logger.warning("identity: status check failed; allowing the request", exc_info=True)
        return None
    if st["complete"]:
        return None
    if mode() == "log":
        _event(user_id, "would_block", request.path if request else "")
        return None
    base = (os.getenv("NET365_PUBLIC_URL") or os.getenv("FRONTEND_URL") or "").rstrip("/")
    return ({"success": False, "error_code": "PROFILE_INCOMPLETE", "missing": st["missing"],
             "error": "Please add and verify your mobile number before making a payment. It only takes a minute.",
             "complete_profile_url": f"{base}/complete-profile"}, 403)


# ----------------------------------------------------------------------------- OTP
def _count(sql, args):
    return int(_val(_conn().execute(sql, args).fetchone(), "n", 0, 0) or 0)


def start_verification(user_id, e164, ip="", country=None):
    """Create and send a code. -> (ok, payload). payload carries 'error' (a code) and 'retry_after' when not ok."""
    now = _now()
    c = _conn()
    # Is this number already a verified identity somewhere else? Do not spend an SMS, do not reveal whose.
    owner = c.execute("SELECT user_id FROM user_phones WHERE phone_e164 = ? AND verified = 1", (e164,)).fetchone()
    if owner is not None and int(_val(owner, "user_id", 0)) != int(user_id):
        _event(user_id, "phone_conflict", mask_phone(e164))
        return False, {"error": "phone_in_use"}
    # Locked after repeated wrong guesses
    since_h = _iso(now - timedelta(hours=1))
    burned = _count("SELECT COUNT(*) AS n FROM phone_verifications WHERE user_id=? AND status='burned' AND created_at>=?", (user_id, since_h))
    if burned >= MAX_BURNED_CODES_HOUR:
        return False, {"error": "locked", "retry_after": LOCK_MINUTES * 60}
    last = c.execute("SELECT created_at FROM phone_verifications WHERE user_id=? ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    if last is not None:
        try:
            wait = RESEND_COOLDOWN_SECONDS - (now - datetime.fromisoformat(_val(last, "created_at", 0))).total_seconds()
            if wait > 0:
                return False, {"error": "cooldown", "retry_after": int(wait) + 1}
        except Exception:
            pass
    if _count("SELECT COUNT(*) AS n FROM phone_verifications WHERE user_id=? AND created_at>=?", (user_id, since_h)) >= MAX_SENDS_PER_USER_HOUR:
        return False, {"error": "too_many", "retry_after": 3600}
    if _count("SELECT COUNT(*) AS n FROM phone_verifications WHERE phone_e164=? AND created_at>=?", (e164, since_h)) >= MAX_SENDS_PER_NUMBER_HOUR:
        return False, {"error": "too_many", "retry_after": 3600}
    if _count("SELECT COUNT(*) AS n FROM phone_verifications WHERE phone_e164=? AND created_at>=?", (e164, _iso(now - timedelta(days=1)))) >= MAX_SENDS_PER_NUMBER_DAY:
        return False, {"error": "too_many", "retry_after": 86400}
    # Replacing a verified number is rate-limited too (account-takeover hygiene)
    cur = get_phone_row(user_id)
    if cur is not None and _val(cur, "verified", 3) and _val(cur, "phone_e164", 1) != e164:
        if int(_val(cur, "changes", 6, 0) or 0) >= MAX_PHONE_CHANGES_PER_30_DAYS and \
                _count("SELECT COUNT(*) AS n FROM identity_events WHERE user_id=? AND event='phone_changed' AND created_at>=?",
                       (user_id, _iso(now - timedelta(days=30)))) >= MAX_PHONE_CHANGES_PER_30_DAYS:
            return False, {"error": "change_limit"}

    code = "".join(secrets.choice("0123456789") for _ in range(OTP_DIGITS))
    c.execute("UPDATE phone_verifications SET status='superseded' WHERE user_id=? AND status='pending'", (user_id,))
    cur2 = c.execute("INSERT INTO phone_verifications (user_id, phone_e164, code_hash, ip, created_at, expires_at) VALUES (?,?,?,?,?,?)",
                     (user_id, e164, "", str(ip)[:64], _iso(now), _iso(now + timedelta(seconds=OTP_TTL_SECONDS))))
    otp_id = cur2.lastrowid
    c.execute("UPDATE phone_verifications SET code_hash=? WHERE id=?", (_code_hash(otp_id, code), otp_id))
    c.commit()

    msg = f"Your Net365 verification code is {code}. It expires in {OTP_TTL_SECONDS // 60} minutes. Never share it with anyone."
    sent = False
    try:
        sent = bool(_deliver(e164, msg)) if _deliver else False
    except Exception:
        logger.exception("identity: SMS delivery failed")
    if not sent and os.getenv("IDENTITY_DEV_OTP", "").lower() == "true":
        logger.warning("IDENTITY_DEV_OTP: code for %s is %s", mask_phone(e164), code)
        sent = True
    if not sent:
        c.execute("UPDATE phone_verifications SET status='undelivered' WHERE id=?", (otp_id,))
        c.commit()
        _event(user_id, "otp_undelivered", mask_phone(e164))
        return False, {"error": "sms_unavailable"}
    _event(user_id, "otp_sent", mask_phone(e164))
    out = {"sent": True, "masked": mask_phone(e164), "expires_in": OTP_TTL_SECONDS, "resend_in": RESEND_COOLDOWN_SECONDS}
    if os.getenv("IDENTITY_DEV_OTP", "").lower() == "true" and os.getenv("IDENTITY_DEV_OTP_ECHO", "").lower() == "true":
        out["dev_code"] = code
    return True, out


def check_code(user_id, code):
    """-> (ok, payload). On success the number is bound to the account as verified."""
    code = re.sub(r"\D", "", str(code or ""))
    if len(code) != OTP_DIGITS:
        return False, {"error": "bad_code"}
    c = _conn()
    row = c.execute("SELECT * FROM phone_verifications WHERE user_id=? AND status='pending' ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    if row is None:
        return False, {"error": "no_pending"}
    otp_id, e164 = _val(row, "id", 0), _val(row, "phone_e164", 2)
    try:
        expired = _now() > datetime.fromisoformat(_val(row, "expires_at", 8))
    except Exception:
        expired = True
    if expired:
        c.execute("UPDATE phone_verifications SET status='expired' WHERE id=?", (otp_id,))
        c.commit()
        return False, {"error": "expired"}
    attempts = int(_val(row, "attempts", 4, 0) or 0) + 1
    if not hmac.compare_digest(_code_hash(otp_id, code), str(_val(row, "code_hash", 3))):
        if attempts >= OTP_MAX_ATTEMPTS:
            c.execute("UPDATE phone_verifications SET attempts=?, status='burned' WHERE id=?", (attempts, otp_id))
            c.commit()
            _event(user_id, "otp_burned", mask_phone(e164))
            return False, {"error": "too_many_attempts"}
        c.execute("UPDATE phone_verifications SET attempts=? WHERE id=?", (attempts, otp_id))
        c.commit()
        return False, {"error": "wrong_code", "attempts_left": OTP_MAX_ATTEMPTS - attempts}
    ok, res = _bind_verified(user_id, e164, source="otp")
    if ok:
        c.execute("UPDATE phone_verifications SET attempts=?, status='used' WHERE id=?", (attempts, otp_id))
        c.commit()
    return ok, res


def _bind_verified(user_id, e164, source):
    """Attach a PROVEN number to the account. The unique index is the final word on duplicates."""
    c = _conn()
    now = _iso()
    prev = get_phone_row(user_id)
    try:
        if prev is None:
            c.execute("INSERT INTO user_phones (user_id, phone_e164, country, verified, verified_at, source, created_at, updated_at) "
                      "VALUES (?,?,?,?,?,?,?,?)", (user_id, e164, None, 1, now, source, now, now))
            changed = False
        else:
            old = _val(prev, "phone_e164", 1)
            changed = bool(_val(prev, "verified", 3)) and old != e164
            c.execute("UPDATE user_phones SET phone_e164=?, verified=1, verified_at=?, source=?, updated_at=?, changes=changes+? WHERE user_id=?",
                      (e164, now, source, now, 1 if changed else 0, user_id))
        c.commit()
    except sqlite3.IntegrityError:
        try:
            c.rollback()
        except Exception:
            pass
        _event(user_id, "phone_conflict", mask_phone(e164))
        return False, {"error": "phone_in_use"}
    # Keep the old users.phone column useful for older code, but only fill it when it is empty. Never overwrite.
    try:
        c.execute("UPDATE users SET phone = ? WHERE id = ? AND (phone IS NULL OR TRIM(phone) = '')", (e164, user_id))
        c.commit()
    except Exception:
        pass
    _event(user_id, "phone_changed" if changed else "phone_verified", f"{source} {mask_phone(e164)}")
    if changed and _notify_email:
        try:
            u = _db.get_user(user_id) or {}
            if u.get("email"):
                _notify_email(u["email"], "Your Net365 phone number was changed",
                              f"The verified phone number on your Net365 account was changed to {mask_phone(e164)}. "
                              "If this was not you, secure your account and contact support immediately.")
        except Exception:
            logger.warning("identity: change notice failed", exc_info=True)
    return True, {"verified": True, "masked": mask_phone(e164), "national": national_display(e164)}


def adopt_chat_number(user_id, wa_digits):
    """A linked WhatsApp chat already proved this number belongs to the person on it. Adopt it as verified so the
    customer is never asked twice, but only when it is safe: the account has no verified number yet and nobody
    else holds this one. Never overwrites. Returns True when the account now has a verified number from this call."""
    try:
        e164, _rg, err = normalize_phone("+" + re.sub(r"\D", "", str(wa_digits or "")))
        if not e164 or _is_guest(user_id):
            return False
        row = get_phone_row(user_id)
        if row is not None and _val(row, "verified", 3):
            return False
        ok, res = _bind_verified(user_id, e164, source="whatsapp")
        return bool(ok)
    except Exception:
        logger.warning("identity: adopt_chat_number failed", exc_info=True)
        return False


def record_identity(user_id, provider, subject):
    """Remember that this external identity (google sub, telegram id, ...) belongs to this account.
    If it already belongs to a DIFFERENT account, log the conflict and change nothing."""
    if not subject:
        return True
    try:
        c = _conn()
        r = c.execute("SELECT user_id FROM net365_identities WHERE provider=? AND subject=?", (provider, str(subject))).fetchone()
        if r is None:
            c.execute("INSERT OR IGNORE INTO net365_identities (provider, subject, user_id) VALUES (?,?,?)", (provider, str(subject), user_id))
            c.commit()
            return True
        if int(_val(r, "user_id", 0)) != int(user_id):
            _event(user_id, "identity_conflict", f"{provider} already linked to user {_val(r, 'user_id', 0)}")
            return False
        return True
    except Exception:
        logger.warning("identity: record_identity failed", exc_info=True)
        return True



# ----------------------------------------------------------------------------- methods without SMS
CLAIM_TTL_SECONDS = 15 * 60
CLAIM_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O/1/I so it survives being read aloud or retyped
MAX_CLAIMS_PER_USER_HOUR = 6
MAX_BAD_CLAIMS_PER_CHAT_HOUR = 8


def bot_whatsapp_number():
    return re.sub(r"\D", "", os.getenv("WHATSAPP_BOT_NUMBER", ""))


def sms_ready():
    if os.getenv("IDENTITY_DEV_OTP", "").lower() == "true":
        return True
    try:
        return bool(_sms_ready and _sms_ready())
    except Exception:
        return False


def methods():
    """Which ways of proving a number are available right now. The page shows only these."""
    return {"whatsapp": bool(bot_whatsapp_number()), "sms": sms_ready(),
            "telegram": bool(os.getenv("TELEGRAM_BOT_USERNAME", "").strip())}


def _claim_hash(code):
    return hmac.new(_secret(), ("claim:" + str(code).upper()).encode(), hashlib.sha256).hexdigest()


def _new_claim(user_id, channel):
    """One pending claim per account; a new one cancels the old. -> (ok, code)."""
    now = _now()
    c = _conn()
    if _count("SELECT COUNT(*) AS n FROM phone_claims WHERE user_id=? AND created_at>=?", (user_id, _iso(now - timedelta(hours=1)))) >= MAX_CLAIMS_PER_USER_HOUR:
        return False, None
    c.execute("UPDATE phone_claims SET status='superseded' WHERE user_id=? AND status='pending'", (user_id,))
    code = "N365-" + "".join(secrets.choice(CLAIM_ALPHABET) for _ in range(6))
    c.execute("INSERT INTO phone_claims (user_id, code_hash, created_at, expires_at) VALUES (?,?,?,?)",
              (user_id, _claim_hash(code), _iso(now), _iso(now + timedelta(seconds=CLAIM_TTL_SECONDS))))
    c.commit()
    _event(user_id, "claim_started", channel)
    return True, code


def start_telegram_claim(user_id):
    """Same idea through Telegram: the page opens the bot with the code, the bot asks for 'Share my number', and
    Telegram itself vouches for the number. -> (ok, payload)"""
    uname = os.getenv("TELEGRAM_BOT_USERNAME", "").strip().lstrip("@")
    if not uname:
        return False, {"error": "telegram_unavailable"}
    ok, code = _new_claim(user_id, "telegram")
    if not ok:
        return False, {"error": "too_many", "retry_after": 3600}
    return True, {"code": code, "link": f"https://t.me/{uname}?start=vf_{code}", "bot": "@" + uname, "expires_in": CLAIM_TTL_SECONDS}


def complete_claim_with_contact(code, phone_raw, chat_key):
    """The Telegram bot got an OWN contact (Telegram-verified) plus the claim code from the web page. The number is bound
    to the web account that created the claim. -> (ok, payload)"""
    code = str(code or "").strip().upper()
    who = hashlib.sha256(("claim-chat:" + str(chat_key)).encode()).hexdigest()[:16]
    c = _conn()
    since = _iso(_now() - timedelta(hours=1))
    if _count("SELECT COUNT(*) AS n FROM identity_events WHERE event='claim_fail' AND detail=? AND created_at>=?", (who, since)) >= MAX_BAD_CLAIMS_PER_CHAT_HOUR:
        return False, {"error": "rate_limited"}
    digits = re.sub(r"\D", "", str(phone_raw or ""))
    e164, _rg, err = normalize_phone("+" + digits) if digits else (None, None, "empty")
    row = c.execute("SELECT * FROM phone_claims WHERE code_hash=? AND status='pending' ORDER BY id DESC LIMIT 1", (_claim_hash(code),)).fetchone() if e164 else None
    if row is None:
        _event(None, "claim_fail", who)
        return False, {"error": "invalid_code" if e164 else "invalid"}
    try:
        expired = _now() > datetime.fromisoformat(_val(row, "expires_at", 5))
    except Exception:
        expired = True
    if expired:
        c.execute("UPDATE phone_claims SET status='expired' WHERE id=?", (_val(row, "id", 0),))
        c.commit()
        return False, {"error": "expired"}
    ok, res = _bind_verified(int(_val(row, "user_id", 1)), e164, source="telegram_claim")
    c.execute("UPDATE phone_claims SET status=? WHERE id=?", ("used" if ok else "refused", _val(row, "id", 0)))
    c.commit()
    return ok, res


def start_whatsapp_claim(user_id):
    """Reverse verification: the customer sends this code to Net365's WhatsApp number. A message that arrives FROM a
    number proves the sender controls it, with no SMS provider and no cost. -> (ok, payload)."""
    num = bot_whatsapp_number()
    if not num:
        return False, {"error": "whatsapp_unavailable"}
    ok, code = _new_claim(user_id, "whatsapp")
    if not ok:
        return False, {"error": "too_many", "retry_after": 3600}
    from urllib.parse import quote
    text = f"VERIFY {code}"
    return True, {"code": code, "text": text, "link": f"https://wa.me/{num}?text={quote(text)}",
                  "number": "+" + num, "expires_in": CLAIM_TTL_SECONDS}


def complete_claim(code, wa_digits):
    """Called by the WhatsApp bot when someone sends a claim code. The sender's number becomes the verified number.
    -> (ok, payload). Single use, expires, rate-limited per chat, and the duplicate rules still apply."""
    wa = re.sub(r"\D", "", str(wa_digits or ""))
    code = str(code or "").strip().upper()
    if wa.startswith("999"):                      # Telegram chat ids carry no phone number
        return False, {"error": "use_telegram"}
    who = hashlib.sha256(("claim-chat:" + wa).encode()).hexdigest()[:16]
    c = _conn()
    since = _iso(_now() - timedelta(hours=1))
    if _count("SELECT COUNT(*) AS n FROM identity_events WHERE event='claim_fail' AND detail=? AND created_at>=?", (who, since)) >= MAX_BAD_CLAIMS_PER_CHAT_HOUR:
        return False, {"error": "rate_limited"}
    e164, _rg, err = normalize_phone("+" + wa)
    row = c.execute("SELECT * FROM phone_claims WHERE code_hash=? AND status='pending' ORDER BY id DESC LIMIT 1", (_claim_hash(code),)).fetchone() if e164 else None
    if row is None:
        _event(None, "claim_fail", who)
        return False, {"error": "invalid_code"}
    try:
        expired = _now() > datetime.fromisoformat(_val(row, "expires_at", 5))
    except Exception:
        expired = True
    if expired:
        c.execute("UPDATE phone_claims SET status='expired' WHERE id=?", (_val(row, "id", 0),))
        c.commit()
        return False, {"error": "expired"}
    uid = int(_val(row, "user_id", 1))
    ok, res = _bind_verified(uid, e164, source="whatsapp_claim")
    c.execute("UPDATE phone_claims SET status=? WHERE id=?", ("used" if ok else "refused", _val(row, "id", 0)))
    c.commit()
    return ok, res


def bind_telegram_contact(user_id, phone_raw):
    """Telegram verified this number itself and the bot confirmed it is the sender's OWN contact."""
    digits = re.sub(r"\D", "", str(phone_raw or ""))
    e164, _rg, err = normalize_phone("+" + digits) if digits else (None, None, "empty")
    if not e164:
        return False, {"error": err or "invalid"}
    if _is_guest(user_id):
        return False, {"error": "link_required"}
    return _bind_verified(user_id, e164, source="telegram")


# ----------------------------------------------------------------------------- email reminders (the only nudge)
# Days after the customer is first seen without a verified number. Five emails in about three months, then silence.
REMINDER_OFFSET_DAYS = (1, 4, 10, 40, 100)
REMINDER_BATCH = 50                     # per sweep, so a big first run never floods the mail provider
_reminder_thread = None


def _public_base():
    return (os.getenv("NET365_PUBLIC_URL") or os.getenv("FRONTEND_URL") or "").rstrip("/")


def _unsub_token(user_id):
    return hmac.new(_secret(), f"unsub:{user_id}".encode(), hashlib.sha256).hexdigest()[:24]


def reminders_enabled():
    return os.getenv("IDENTITY_REMINDERS", "true").strip().lower() not in ("false", "0", "off", "no")


def _has_verified(user_id):
    r = get_phone_row(user_id)
    return bool(r is not None and _val(r, "verified", 3))


def _reminder_email(name, user_id):
    base = _public_base()
    first = (str(name or "").strip().split(" ")[0] or "there")
    subject = "Add your phone number to Net365 (optional, 30 seconds)"
    body = (
        f"Hi {first},\n\n"
        "Everything on Net365 works as it is. If you like, you can confirm your mobile number to get more out of your account:\n\n"
        "  - receipts and electricity tokens delivered straight to your phone\n"
        "  - a faster way back into your account if you ever lose access\n"
        "  - extra protection on your payments\n\n"
        "It takes about 30 seconds and costs nothing. Confirm it through WhatsApp or Telegram, no code to type:\n"
        f"{base}/complete-profile\n\n"
        "No pressure, and nothing stops working if you skip it.\n\n"
        "Do not want these reminders? One tap and they stop for good:\n"
        f"{base}/api/identity/reminders/unsubscribe?u={user_id}&t={_unsub_token(user_id)}\n\n"
        "The Net365 team"
    )
    return subject, body


def sweep_reminders(limit=REMINDER_BATCH, dry_run=False):
    """Find customers without a verified number whose next reminder is due and email them. Safe to run from several
    workers at once (each reminder is claimed atomically) and safe to run often. -> counts."""
    out = {"enrolled": 0, "due": 0, "sent": 0, "skipped": 0, "failed": 0, "dry_run": bool(dry_run)}
    if not (reminders_enabled() or dry_run) or _db is None:
        return out
    c = _conn()
    now = _now()
    # 1. enrol everyone who has an email, no verified number and is not blocked. Existing customers get their first
    #    reminder a day after the first sweep, never all at once on deploy.
    base_sql = ("INSERT OR IGNORE INTO identity_reminders (user_id, first_seen, next_due) "
                "SELECT u.id, ?, ? FROM users u WHERE TRIM(COALESCE(u.email,'')) <> '' "
                "AND NOT EXISTS (SELECT 1 FROM user_phones p WHERE p.user_id = u.id AND p.verified = 1) "
                "AND NOT EXISTS (SELECT 1 FROM identity_reminders r WHERE r.user_id = u.id)")
    args = (_iso(now), _iso(now + timedelta(days=REMINDER_OFFSET_DAYS[0])))
    if not dry_run:
        try:
            cur = c.execute(base_sql + " AND COALESCE(u.account_status,'active') NOT IN ('suspended','blocked','deleted')", args)
        except sqlite3.OperationalError:   # no account_status column
            cur = c.execute(base_sql, args)
        out["enrolled"] = max(0, cur.rowcount or 0)
        c.commit()
    rows = c.execute("SELECT * FROM identity_reminders WHERE opted_out=0 AND sent_count < ? AND next_due <= ? ORDER BY next_due LIMIT ?",
                     (len(REMINDER_OFFSET_DAYS), _iso(now), int(limit))).fetchall()
    out["due"] = len(rows)
    if dry_run:
        return out
    for r in rows:
        uid = int(_val(r, "user_id", 0))
        due = _val(r, "next_due", 2)
        sent_count = int(_val(r, "sent_count", 3) or 0)
        if _has_verified(uid) or _is_guest(uid):
            c.execute("UPDATE identity_reminders SET opted_out=1 WHERE user_id=?", (uid,)); c.commit()
            out["skipped"] += 1
            continue
        # claim: only one worker wins this row; if the send fails it is retried in 6 hours
        claim = c.execute("UPDATE identity_reminders SET next_due=? WHERE user_id=? AND next_due=?",
                          (_iso(now + timedelta(hours=6)), uid, due))
        c.commit()
        if (claim.rowcount or 0) != 1:
            continue
        u = {}
        try:
            u = _db.get_user(uid) or {}
        except Exception:
            pass
        email = str(u.get("email") or "").strip()
        if not email or (u.get("account_status") or "active") in ("suspended", "blocked", "deleted"):
            c.execute("UPDATE identity_reminders SET opted_out=1 WHERE user_id=?", (uid,)); c.commit()
            out["skipped"] += 1
            continue
        try:
            subject, body = _reminder_email(u.get("full_name"), uid)
            ok = _notify_email(email, subject, body) if _notify_email else False
            ok = ok is not False
        except Exception:
            logger.exception("identity: reminder email failed for user %s", uid)
            ok = False
        if ok:
            n = sent_count + 1
            first_seen = datetime.fromisoformat(_val(r, "first_seen", 1))
            nxt = first_seen + timedelta(days=REMINDER_OFFSET_DAYS[n]) if n < len(REMINDER_OFFSET_DAYS) else now + timedelta(days=3650)
            if nxt <= now:
                nxt = now + timedelta(days=7)
            c.execute("UPDATE identity_reminders SET sent_count=?, last_sent_at=?, next_due=? WHERE user_id=?", (n, _iso(now), _iso(nxt), uid))
            c.commit()
            _event(uid, "reminder_sent", f"#{n}")
            out["sent"] += 1
        else:
            out["failed"] += 1
    return out


def _reminder_loop(interval):
    import time as _t
    _t.sleep(300)   # let the app finish starting
    while True:
        try:
            sweep_reminders()
        except Exception:
            logger.warning("identity: reminder sweep failed", exc_info=True)
        _t.sleep(interval)


def start_reminder_thread(interval_seconds=3600):
    global _reminder_thread
    if _reminder_thread is not None or not reminders_enabled():
        return False
    _reminder_thread = threading.Thread(target=_reminder_loop, args=(interval_seconds,), daemon=True, name="identity-reminders")
    _reminder_thread.start()
    return True


def audit():
    """Read-only health report for the admin."""
    c = _conn()
    out = {}
    out["users"] = _count("SELECT COUNT(*) AS n FROM users", ())
    out["verified_phones"] = _count("SELECT COUNT(*) AS n FROM user_phones WHERE verified=1", ())
    out["legacy_phone_unverified"] = _count(
        "SELECT COUNT(*) AS n FROM users u WHERE TRIM(COALESCE(u.phone,''))<>'' AND NOT EXISTS (SELECT 1 FROM user_phones p WHERE p.user_id=u.id AND p.verified=1)", ())
    out["no_phone_at_all"] = _count(
        "SELECT COUNT(*) AS n FROM users u WHERE TRIM(COALESCE(u.phone,''))='' AND NOT EXISTS (SELECT 1 FROM user_phones p WHERE p.user_id=u.id)", ())
    dups = c.execute("SELECT phone_e164, COUNT(*) AS n FROM user_phones GROUP BY phone_e164 HAVING COUNT(*)>1").fetchall()
    out["duplicate_phone_numbers"] = [{"phone": mask_phone(_val(r, "phone_e164", 0)), "accounts": _val(r, "n", 1)} for r in dups]
    out["grandfather_max_user_id"] = _grandfather_max()
    out["mode"] = mode()
    out["reminders"] = {"enabled": reminders_enabled(),
                        "enrolled": _count("SELECT COUNT(*) AS n FROM identity_reminders", ()),
                        "opted_out": _count("SELECT COUNT(*) AS n FROM identity_reminders WHERE opted_out=1", ()),
                        "emails_sent": _count("SELECT COALESCE(SUM(sent_count),0) AS n FROM identity_reminders", ())}
    return out


# ----------------------------------------------------------------------------- routes
_ERR = {
    "empty": "Enter your mobile number.",
    "invalid": "That number does not look right for the country you picked. Check it and try again.",
    "phone_in_use": "This number is already registered with another Net365 account. Sign in to that account, or contact support if it is yours.",
    "locked": "Too many wrong attempts. Please wait a while before trying again.",
    "cooldown": "Please wait a moment before asking for another code.",
    "too_many": "Too many codes requested. Please try again later.",
    "change_limit": "This number was changed too many times recently. Please contact support.",
    "sms_unavailable": "We could not send the code right now. Please try again in a minute.",
    "bad_code": "Enter the 6-digit code.",
    "no_pending": "Request a new code first.",
    "expired": "That code has expired. Request a new one.",
    "too_many_attempts": "Too many wrong attempts. Request a new code.",
    "wrong_code": "That code is not right.",
    "whatsapp_unavailable": "WhatsApp verification is not available right now.",
    "telegram_unavailable": "Telegram verification is not available right now.",
}


def init_identity(app, db, login_required, rate_limit, send_sms=None, send_email=None, admin_required=None, page_path=None, sms_ready=None):
    """Create the tables and register the routes. Safe to call once at start-up."""
    global _db, _deliver, _notify_email, _sms_ready
    _db, _deliver, _notify_email, _sms_ready = db, send_sms, send_email, sms_ready
    ensure_schema()

    @app.get("/api/identity/countries")
    def identity_countries():
        return jsonify(success=True, countries=countries(), detected=guess_country(), validator="phonenumbers" if phonenumbers else "basic")

    @app.get("/api/identity/methods")
    def identity_methods():
        m = methods()
        return jsonify(success=True, methods=m, default="whatsapp" if m["whatsapp"] else ("sms" if m["sms"] else "none"))

    @app.post("/api/identity/whatsapp/start")
    @login_required
    @rate_limit(max_requests=12, window_seconds=600)
    def identity_whatsapp_start():
        ok, res = start_whatsapp_claim(g.current_user_id)
        if not ok:
            code = res.get("error", "whatsapp_unavailable")
            return jsonify(success=False, error_code=code, error=_ERR.get(code, "Could not start verification"),
                           retry_after=res.get("retry_after")), (429 if code == "too_many" else 503)
        return jsonify(success=True, **res)

    @app.post("/api/identity/telegram/start")
    @login_required
    @rate_limit(max_requests=12, window_seconds=600)
    def identity_telegram_start():
        ok, res = start_telegram_claim(g.current_user_id)
        if not ok:
            code = res.get("error", "telegram_unavailable")
            return jsonify(success=False, error_code=code, error=_ERR.get(code, "Could not start verification"),
                           retry_after=res.get("retry_after")), (429 if code == "too_many" else 503)
        return jsonify(success=True, **res)

    @app.get("/api/identity/status")
    @login_required
    def identity_status():
        return jsonify(success=True, **profile_status(g.current_user_id))

    @app.post("/api/identity/phone/start")
    @login_required
    @rate_limit(max_requests=12, window_seconds=600)
    def identity_phone_start():
        d = request.get_json(silent=True) or {}
        e164, region, err = normalize_phone(d.get("phone"), d.get("country"))
        if err:
            return jsonify(success=False, error_code=err, error=_ERR.get(err, "Invalid number")), 400
        ok, res = start_verification(g.current_user_id, e164, ip=request.headers.get("X-Forwarded-For", request.remote_addr or ""), country=region)
        if not ok:
            code = res.get("error", "sms_unavailable")
            http = 409 if code == "phone_in_use" else 429 if code in ("cooldown", "too_many", "locked") else 503 if code == "sms_unavailable" else 400
            return jsonify(success=False, error_code=code, error=_ERR.get(code, "Could not send the code"), retry_after=res.get("retry_after")), http
        return jsonify(success=True, **res)

    @app.post("/api/identity/phone/verify")
    @login_required
    @rate_limit(max_requests=20, window_seconds=600)
    def identity_phone_verify():
        d = request.get_json(silent=True) or {}
        ok, res = check_code(g.current_user_id, d.get("code"))
        if not ok:
            code = res.get("error", "bad_code")
            http = 409 if code == "phone_in_use" else 429 if code in ("too_many_attempts",) else 400
            return jsonify(success=False, error_code=code, error=_ERR.get(code, "Could not verify"), attempts_left=res.get("attempts_left")), http
        return jsonify(success=True, **res, status=profile_status(g.current_user_id))

    @app.get("/api/identity/reminders/unsubscribe")
    def identity_unsubscribe():
        try:
            uid = int(request.args.get("u", "0"))
        except ValueError:
            uid = 0
        tok = str(request.args.get("t", ""))
        if uid and hmac.compare_digest(tok, _unsub_token(uid)):
            c = _conn()
            now = _iso()
            c.execute("INSERT INTO identity_reminders (user_id, first_seen, next_due, opted_out) VALUES (?,?,?,1) "
                      "ON CONFLICT(user_id) DO UPDATE SET opted_out=1", (uid, now, now))
            c.commit()
            _event(uid, "reminder_opt_out", "")
            msg, code = "You will not get any more phone-number reminders from Net365. Everything on your account keeps working as before.", 200
        else:
            msg, code = "This link is not valid. Please use the link from your latest email.", 400
        html = ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
                "<title>Net365</title><body style=\"font-family:system-ui,sans-serif;background:#eef2f7;display:grid;place-items:center;min-height:100vh;margin:0\">"
                f"<div style=\"background:#fff;border-radius:20px;padding:28px;max-width:420px;margin:16px;box-shadow:0 20px 60px -30px rgba(0,0,0,.4)\"><b style=\"letter-spacing:.14em\">NET365</b>"
                f"<p style=\"color:#334155;line-height:1.6\">{msg}</p></div>")
        return html, code, {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}

    if admin_required:
        @app.post("/api/admin/identity/reminders/run")
        @admin_required
        def identity_reminders_run():
            d = request.get_json(silent=True) or {}
            return jsonify(success=True, result=sweep_reminders(limit=int(d.get("limit") or REMINDER_BATCH), dry_run=bool(d.get("dry_run"))))

        @app.get("/api/admin/identity/audit")
        @admin_required
        def identity_audit():
            return jsonify(success=True, audit=audit())

    if page_path:
        from flask import send_file

        @app.get("/complete-profile")
        def complete_profile_page():
            resp = send_file(page_path, mimetype="text/html")
            resp.headers["Cache-Control"] = "no-store"
            return resp

    start_reminder_thread()
    logger.info("identity engine ready (mode=%s, validator=%s)", mode(), "phonenumbers" if phonenumbers else "basic")


if __name__ == "__main__":  # python net365_identity.py  -> prints the audit report for the configured database
    import sys
    try:
        import database as _d
        _db = _d
        ensure_schema()
        import json
        print(json.dumps(audit(), indent=2))
    except Exception as e:  # pragma: no cover
        print("Run this from the app folder where database.py lives:", e)
        sys.exit(1)

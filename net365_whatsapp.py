"""
Net365 WhatsApp Banking — account-linking & PIN service.

The Node WhatsApp bot (server.js) talks to Net365 through this blueprint. It does three things:

  1. LINK   a WhatsApp number to a Net365 account (email OTP proves ownership, user sets a 4-digit PIN)
  2. AUTH   a linked number: check the PIN (5 wrong tries -> 30 minute lock) and hand the bot a
            *short-lived* (5 min) Net365 session token
  3. UNLINK a number

The bot then uses that token as `Authorization: Bearer <token>` against the normal Net365 API
(/api/payment/init, /api/wallet/fund, /api/dashboard/summary, /api/user/transactions), so every
existing rule — wallet balance checks, currency checks, receipts, emails — applies unchanged.
The bot revokes the token (POST /api/auth/logout) as soon as the action finishes.

Every route here requires the header  X-Bot-Secret: <WHATSAPP_BOT_SECRET>.
Keep that secret on the bot server only: anyone holding it can act for any linked WhatsApp user.

Register in app.py (see bottom of this file).
"""
import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, jsonify, request

logger = logging.getLogger("net365.whatsapp")

wa_bp = Blueprint("whatsapp_banking", __name__)

_db = None
_send_email = None

PIN_MAX_FAILS = 5
PIN_LOCK_MINUTES = 30
OTP_MAX_WRONG = 5
OTP_WRONG_WINDOW_MIN = 15
OTP_MAX_SENDS = 3
OTP_SEND_WINDOW_MIN = 60
SESSION_MINUTES = 5
PBKDF2_ROUNDS = 120_000

_WA_RE = re.compile(r"^\d{8,15}$")
_PIN_RE = re.compile(r"^\d{4}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_WEAK_PINS = {"0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888",
              "9999", "1234", "4321", "1212", "2580", "0123", "1004", "2000", "2024", "2025", "2026"}


# --------------------------------------------------------------------------- setup
def init_whatsapp_banking(app, db_module, send_email_fn):
    """Create tables and register the blueprint. Safe to call once at startup."""
    global _db, _send_email
    _db = db_module
    _send_email = send_email_fn
    _ensure_schema()
    app.register_blueprint(wa_bp)
    if not os.getenv("WHATSAPP_BOT_SECRET", "").strip():
        logger.warning("WHATSAPP_BOT_SECRET is not set - /api/whatsapp/* will refuse all requests")
    else:
        logger.info("WhatsApp banking API enabled")


def _conn():
    # Never close: the project's get_db_connection() may hand back a shared connection.
    return _db.get_db_connection()


def _ensure_schema():
    c = _conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS whatsapp_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wa_number TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL,
            pin_salt TEXT NOT NULL,
            pin_hash TEXT NOT NULL,
            pin_failed INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            linked_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_used_at TEXT
        )
        """
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_wa_links_user ON whatsapp_links(user_id)")
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS whatsapp_link_attempts (
            wa_number TEXT PRIMARY KEY,
            sends INTEGER NOT NULL DEFAULT 0,
            sends_window_start TEXT,
            wrong INTEGER NOT NULL DEFAULT 0,
            wrong_window_start TEXT
        )
        """
    )
    try:
        c.commit()
    except Exception:
        pass


# --------------------------------------------------------------------------- helpers
def _now():
    return datetime.utcnow()


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _parse(s):
    try:
        return datetime.strptime(str(s)[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def bot_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        expected = os.getenv("WHATSAPP_BOT_SECRET", "").strip()
        if not expected:
            return jsonify({"success": False, "error": "not_configured"}), 503
        given = request.headers.get("X-Bot-Secret", "")
        if not hmac.compare_digest(given.encode(), expected.encode()):
            return jsonify({"success": False, "error": "forbidden"}), 403
        return fn(*a, **kw)

    return wrapper


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _wa(data):
    wa = re.sub(r"\D", "", str(data.get("wa") or ""))
    return wa if _WA_RE.match(wa) else None


def _hash_pin(pin, salt):
    # Salted + slow. A 4-digit PIN is weak by nature, so the real protection is the lockout below.
    pepper = os.getenv("WHATSAPP_PIN_PEPPER", "")
    return hashlib.pbkdf2_hmac("sha256", (pin + pepper).encode(), bytes.fromhex(salt), PBKDF2_ROUNDS).hex()


def _get_link(wa):
    row = _conn().execute(
        "SELECT * FROM whatsapp_links WHERE wa_number = ? AND active = 1", (wa,)
    ).fetchone()
    return dict(row) if row else None


def _attempts_row(wa):
    c = _conn()
    c.execute("INSERT OR IGNORE INTO whatsapp_link_attempts (wa_number) VALUES (?)", (wa,))
    return dict(c.execute("SELECT * FROM whatsapp_link_attempts WHERE wa_number = ?", (wa,)).fetchone())


def _window_value(count, start, minutes):
    """Return the current count, or 0 when the window has expired."""
    st = _parse(start)
    if not st or _now() - st > timedelta(minutes=minutes):
        return 0
    return int(count or 0)


def _blocked_user(user):
    return (not user) or (user.get("account_status") or "active") in ("blocked", "deleted", "suspended")


def _mint_session(user_id):
    """Short-lived session. Uses the sqlite 'YYYY-MM-DD HH:MM:SS' UTC format so the
    expires_at > datetime('now') check in db.get_session is exact to the second."""
    token = secrets.token_urlsafe(32)
    expires = _fmt(_now() + timedelta(minutes=SESSION_MINUTES))
    _conn().execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires),
    )
    try:
        _conn().commit()
    except Exception:
        pass
    return token


def _mask_email(email):
    try:
        name, dom = email.split("@", 1)
        return (name[:1] + "***@" + dom) if len(name) > 1 else ("*@" + dom)
    except Exception:
        return "your email"


# --------------------------------------------------------------------------- routes
@wa_bp.route("/api/whatsapp/status", methods=["POST"])
@bot_required
def wa_status():
    wa = _wa(_body())
    if not wa:
        return jsonify({"success": False, "error": "bad_number"}), 400
    link = _get_link(wa)
    if not link:
        return jsonify({"success": True, "linked": False})
    user = _db.get_user(link["user_id"])
    if _blocked_user(user):
        return jsonify({"success": True, "linked": False, "blocked": True})
    first = str(user.get("full_name") or "").strip().split(" ")[0] or "there"
    return jsonify({"success": True, "linked": True, "first_name": first})


@wa_bp.route("/api/whatsapp/link/start", methods=["POST"])
@bot_required
def wa_link_start():
    data = _body()
    wa = _wa(data)
    email = str(data.get("email") or "").strip().lower()
    if not wa or not _EMAIL_RE.match(email):
        return jsonify({"success": False, "error": "bad_input"}), 400

    row = _attempts_row(wa)
    sends = _window_value(row["sends"], row["sends_window_start"], OTP_SEND_WINDOW_MIN)
    if sends >= OTP_MAX_SENDS:
        return jsonify({"success": False, "error": "too_many_codes"}), 429
    start = row["sends_window_start"] if sends else _fmt(_now())
    _conn().execute(
        "UPDATE whatsapp_link_attempts SET sends = ?, sends_window_start = ? WHERE wa_number = ?",
        (sends + 1, start, wa),
    )

    generic = {"success": True, "masked_email": _mask_email(email)}
    user = _db.get_user_by_email(email)
    if _blocked_user(user):
        return jsonify(generic)  # same answer whether or not the account exists

    try:
        code = _db.create_verification_otp(email, otp_type="whatsapp_link", ttl_minutes=10)
        _send_email(
            email,
            "Link WhatsApp to your Net365 account",
            f'Your Net365 WhatsApp code is <span class="amount">{code}</span>. '
            f"It expires in 10 minutes. If you did not ask to link WhatsApp, ignore this email "
            f"and do not share the code with anyone.",
        )
    except Exception:
        logger.exception("could not send WhatsApp link OTP")
    return jsonify(generic)


@wa_bp.route("/api/whatsapp/link/confirm", methods=["POST"])
@bot_required
def wa_link_confirm():
    data = _body()
    wa = _wa(data)
    email = str(data.get("email") or "").strip().lower()
    code = re.sub(r"\D", "", str(data.get("code") or ""))
    pin = str(data.get("pin") or "")
    if not wa or not _EMAIL_RE.match(email) or len(code) != 6:
        return jsonify({"success": False, "error": "bad_input"}), 400
    if not _PIN_RE.match(pin):
        return jsonify({"success": False, "error": "bad_pin_format"}), 400
    if pin in _WEAK_PINS:
        return jsonify({"success": False, "error": "weak_pin"}), 400

    row = _attempts_row(wa)
    wrong = _window_value(row["wrong"], row["wrong_window_start"], OTP_WRONG_WINDOW_MIN)
    if wrong >= OTP_MAX_WRONG:
        return jsonify({"success": False, "error": "too_many_attempts"}), 429

    if not _db.verify_otp(email, code, otp_type="whatsapp_link"):
        start = row["wrong_window_start"] if wrong else _fmt(_now())
        _conn().execute(
            "UPDATE whatsapp_link_attempts SET wrong = ?, wrong_window_start = ? WHERE wa_number = ?",
            (wrong + 1, start, wa),
        )
        return jsonify({"success": False, "error": "bad_code", "attempts_left": max(0, OTP_MAX_WRONG - wrong - 1)}), 400

    user = _db.get_user_by_email(email)
    if _blocked_user(user):
        return jsonify({"success": False, "error": "account_unavailable"}), 403

    salt = secrets.token_hex(16)
    pin_hash = _hash_pin(pin, salt)
    c = _conn()
    # one WhatsApp number per account, one account per number
    c.execute("DELETE FROM whatsapp_links WHERE user_id = ? OR wa_number = ?", (user["id"], wa))
    c.execute(
        "INSERT INTO whatsapp_links (wa_number, user_id, pin_salt, pin_hash) VALUES (?, ?, ?, ?)",
        (wa, user["id"], salt, pin_hash),
    )
    c.execute("UPDATE whatsapp_link_attempts SET wrong = 0, sends = 0 WHERE wa_number = ?", (wa,))
    try:
        c.commit()
    except Exception:
        pass
    try:
        _send_email(
            email,
            "WhatsApp linked to your Net365 account",
            f"The WhatsApp number ending {wa[-4:]} was just linked to your Net365 account. "
            f"If this was not you, reply to this email or contact support@net365co.com immediately.",
        )
    except Exception:
        pass
    first = str(user.get("full_name") or "").strip().split(" ")[0] or "there"
    return jsonify({"success": True, "first_name": first})


@wa_bp.route("/api/whatsapp/auth", methods=["POST"])
@bot_required
def wa_auth():
    """Body: {wa, pin?}  ->  {token}. PIN is required for wallet spending, balance and history."""
    data = _body()
    wa = _wa(data)
    if not wa:
        return jsonify({"success": False, "error": "bad_number"}), 400
    link = _get_link(wa)
    if not link:
        return jsonify({"success": False, "error": "not_linked"}), 404

    locked = _parse(link.get("locked_until"))
    if locked and locked > _now():
        mins = max(1, int((locked - _now()).total_seconds() // 60) + 1)
        return jsonify({"success": False, "error": "locked", "retry_minutes": mins}), 423

    user = _db.get_user(link["user_id"])
    if _blocked_user(user):
        return jsonify({"success": False, "error": "account_unavailable"}), 403

    if data.get("require_pin", True):
        pin = str(data.get("pin") or "")
        ok = bool(_PIN_RE.match(pin)) and hmac.compare_digest(
            _hash_pin(pin, link["pin_salt"]), link["pin_hash"]
        )
        if not ok:
            fails = int(link.get("pin_failed") or 0) + 1
            until = _fmt(_now() + timedelta(minutes=PIN_LOCK_MINUTES)) if fails >= PIN_MAX_FAILS else None
            _conn().execute(
                "UPDATE whatsapp_links SET pin_failed = ?, locked_until = ? WHERE id = ?",
                (0 if until else fails, until, link["id"]),
            )
            if until:
                return jsonify({"success": False, "error": "locked", "retry_minutes": PIN_LOCK_MINUTES}), 423
            return jsonify({"success": False, "error": "bad_pin", "attempts_left": PIN_MAX_FAILS - fails}), 401

    _conn().execute(
        "UPDATE whatsapp_links SET pin_failed = 0, locked_until = NULL, last_used_at = ? WHERE id = ?",
        (_fmt(_now()), link["id"]),
    )
    token = _mint_session(user["id"])
    first = str(user.get("full_name") or "").strip().split(" ")[0] or "there"
    return jsonify({"success": True, "token": token, "first_name": first})


@wa_bp.route("/api/whatsapp/unlink", methods=["POST"])
@bot_required
def wa_unlink():
    data = _body()
    wa = _wa(data)
    if not wa:
        return jsonify({"success": False, "error": "bad_number"}), 400
    link = _get_link(wa)
    if not link:
        return jsonify({"success": True})
    pin = str(data.get("pin") or "")
    locked = _parse(link.get("locked_until"))
    if locked and locked > _now():
        return jsonify({"success": False, "error": "locked"}), 423
    ok = bool(_PIN_RE.match(pin)) and hmac.compare_digest(_hash_pin(pin, link["pin_salt"]), link["pin_hash"])
    if not ok:
        fails = int(link.get("pin_failed") or 0) + 1
        until = _fmt(_now() + timedelta(minutes=PIN_LOCK_MINUTES)) if fails >= PIN_MAX_FAILS else None
        _conn().execute(
            "UPDATE whatsapp_links SET pin_failed = ?, locked_until = ? WHERE id = ?",
            (0 if until else fails, until, link["id"]),
        )
        return jsonify({"success": False, "error": "locked" if until else "bad_pin"}), 401
    _conn().execute("DELETE FROM whatsapp_links WHERE id = ?", (link["id"],))
    return jsonify({"success": True})


# --------------------------------------------------------------------------- app.py registration
# Add this inside ReloadlyWebApp.__init__ (next to the ads_bp block), after db.init_db():
#
#     try:
#         from net365_whatsapp import init_whatsapp_banking
#         init_whatsapp_banking(self.app, db, send_email_notification)
#     except Exception as e:
#         logger.warning(f"WhatsApp banking API not loaded: {e}")

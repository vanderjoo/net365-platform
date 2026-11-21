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
import threading
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, jsonify, make_response, request

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
_PIN_RE = re.compile(r"^\d{4,6}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_WEAK_PINS = {"0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888",
              "9999", "1234", "4321", "1212", "2580", "0123", "1004", "2000", "2024", "2025", "2026",
              "123456", "654321", "121212", "112233", "123123", "696969", "159753", "000000", "111111"}


def _is_weak_pin(pin):
    """Repeats (1111, 777777), straight runs (1234, 98765) and a short blocklist."""
    if pin in _WEAK_PINS or len(set(pin)) == 1:
        return True
    d = [int(x) for x in pin]
    steps = {d[i + 1] - d[i] for i in range(len(d) - 1)}
    return steps in ({1}, {-1})


# --------------------------------------------------------------------------- setup
def init_whatsapp_banking(app, db_module, send_email_fn):
    """Create tables and register the blueprint. Safe to call once at startup."""
    global _db, _send_email
    _db = db_module
    _send_email = send_email_fn
    _ensure_schema()
    app.register_blueprint(wa_bp)
    _start_retry_thread()
    if not os.getenv("WHATSAPP_BOT_SECRET", "").strip():
        logger.warning("WHATSAPP_BOT_SECRET is not set - /api/whatsapp/* will refuse all requests")
    else:
        logger.info("WhatsApp banking API enabled")


_welcome_hook = None


def set_welcome_hook(fn):
    """app.py gives us send_welcome_once(user_id, email, first_name, source). Called when a recently created account is linked
    to a chat, so accounts created through Telegram/WhatsApp sign-up pages get the CEO welcome too (once only)."""
    global _welcome_hook
    _welcome_hook = fn


def _conn():
    # Never close: the project's get_db_connection() may hand back a shared connection.
    return _db.get_db_connection()


_schema_ready = False


def _ensure_schema():
    """Create/upgrade tables. Every step is independent and idempotent, so one failure (for example a
    locked table) can never stop the others, and it is safe to call again at any time."""
    global _schema_ready
    c = _conn()

    def run(sql, what):
        try:
            c.execute(sql)
            return True
        except Exception as e:
            if "duplicate column" not in str(e).lower():
                logger.warning("schema step failed (%s): %s", what, e)
            return False

    run("""
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
        )""", "whatsapp_links")
    run("CREATE INDEX IF NOT EXISTS idx_wa_links_user ON whatsapp_links(user_id)", "idx")
    run("""
        CREATE TABLE IF NOT EXISTS whatsapp_link_attempts (
            wa_number TEXT PRIMARY KEY,
            sends INTEGER NOT NULL DEFAULT 0,
            sends_window_start TEXT,
            wrong INTEGER NOT NULL DEFAULT 0,
            wrong_window_start TEXT
        )""", "attempts")
    try:
        cols = {r[1] for r in c.execute("PRAGMA table_info(whatsapp_links)").fetchall()}
        for col, ddl in (("is_guest", "INTEGER NOT NULL DEFAULT 0"), ("receipt_email", "TEXT"),
                         ("ads_opt_out", "INTEGER NOT NULL DEFAULT 0"), ("last_ad_at", "TEXT"),
                         ("frozen", "INTEGER NOT NULL DEFAULT 0"), ("frozen_at", "TEXT")):
            if col not in cols:
                run(f"ALTER TABLE whatsapp_links ADD COLUMN {col} {ddl}", f"add {col}")
        ucols = {r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()}
        if "is_guest" not in ucols:
            run("ALTER TABLE users ADD COLUMN is_guest INTEGER NOT NULL DEFAULT 0", "users.is_guest")
    except Exception as e:
        logger.warning("schema column check failed: %s", e)
    run("""CREATE TABLE IF NOT EXISTS chat_sessions (
            token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, wa_number TEXT,
            pin_verified INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""", "chat_sessions")
    run("""CREATE TABLE IF NOT EXISTS chat_google_links (
            token_hash TEXT PRIMARY KEY, wa_number TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            user_id INTEGER, email TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, expires_at TEXT NOT NULL)""", "chat_google_links")
    run("""CREATE TABLE IF NOT EXISTS net365_identities (
            provider TEXT NOT NULL, subject TEXT NOT NULL, user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (provider, subject))""", "net365_identities")
    ok = run("CREATE TABLE IF NOT EXISTS bot_notifications ("
             "reference TEXT PRIMARY KEY, created_at TEXT DEFAULT CURRENT_TIMESTAMP, status TEXT)",
             "bot_notifications")
    try:
        c.commit()
    except Exception:
        pass
    _schema_ready = bool(ok)


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
        if not _schema_ready:
            _ensure_schema()
        return fn(*a, **kw)

    return wrapper


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _wa(data):
    wa = re.sub(r"\D", "", str(data.get("wa") or ""))
    return wa if _WA_RE.match(wa) else None


def _hash_pin(pin, salt):
    """Legacy PBKDF2 hash (kept so existing PINs still verify; they are upgraded to Argon2 on next use)."""
    pepper = os.getenv("WHATSAPP_PIN_PEPPER", "")
    return hashlib.pbkdf2_hmac("sha256", (pin + pepper).encode(), bytes.fromhex(salt), PBKDF2_ROUNDS).hex()


try:
    from argon2 import PasswordHasher as _PH
    from argon2.exceptions import VerifyMismatchError as _VME, InvalidHashError as _IHE
    _ph = _PH(time_cost=2, memory_cost=19456, parallelism=1)  # ~OWASP minimum, fine for a free-tier box
except Exception:  # argon2-cffi missing: fall back to PBKDF2 (still salted + lockout)
    _ph = None


def _make_pin_hash(pin, salt):
    """Returns the value to store in pin_hash. Argon2id when available (salt is embedded in the hash)."""
    if _ph:
        return _ph.hash(pin + os.getenv("WHATSAPP_PIN_PEPPER", ""))
    return _hash_pin(pin, salt)


def _verify_pin_hash(pin, salt, stored):
    """-> (ok, new_hash_or_None). new_hash is set when a legacy PBKDF2 PIN verified and should be upgraded."""
    if not pin or not _PIN_RE.match(pin) or not stored:
        return False, None
    if str(stored).startswith("$argon2"):
        if not _ph:
            return False, None
        try:
            _ph.verify(stored, pin + os.getenv("WHATSAPP_PIN_PEPPER", ""))
        except Exception:
            return False, None
        try:
            if _ph.check_needs_rehash(stored):
                return True, _ph.hash(pin + os.getenv("WHATSAPP_PIN_PEPPER", ""))
        except Exception:
            pass
        return True, None
    ok = hmac.compare_digest(_hash_pin(pin, salt), stored)
    return ok, (_make_pin_hash(pin, salt) if ok and _ph else None)


def _check_link_pin(link, pin):
    ok, newh = _verify_pin_hash(pin, link["pin_salt"], link["pin_hash"])
    if ok and newh:
        try:
            _conn().execute("UPDATE whatsapp_links SET pin_hash = ? WHERE id = ?", (newh, link["id"]))
        except Exception:
            logger.exception("pin rehash failed")
    return ok


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


def _mint_session(user_id, wa=None, pin_verified=False):
    """Short-lived session. Uses the sqlite 'YYYY-MM-DD HH:MM:SS' UTC format so the
    expires_at > datetime('now') check in db.get_session is exact to the second."""
    token = secrets.token_urlsafe(32)
    expires = _fmt(_now() + timedelta(minutes=SESSION_MINUTES))
    _conn().execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires),
    )
    try:  # remember that this token came from a chat, and whether the PIN was just proven
        _conn().execute("INSERT OR REPLACE INTO chat_sessions (token, user_id, wa_number, pin_verified) VALUES (?,?,?,?)",
                        (token, user_id, wa, 1 if pin_verified else 0))
        _conn().execute("DELETE FROM chat_sessions WHERE created_at < datetime('now','-1 day')")
    except Exception:
        logger.exception("chat_sessions write failed")
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
@wa_bp.route("/api/whatsapp/interest", methods=["POST"])
@bot_required
def wa_interest():
    """Ask Net365 logs what customers ask for that Net365 does not do yet (Starlink, betting, flights...),
    so the team can see demand by country. Stores a short hash of the chat id, never the number itself."""
    data = _body()
    wa = _wa(data)
    service = re.sub(r"[^a-z0-9_ -]", "", str(data.get("service") or "").lower())[:40]
    country = re.sub(r"[^A-Za-z]", "", str(data.get("country") or "")).upper()[:2]
    query = re.sub(r"[\r\n\t]+", " ", str(data.get("query") or "")).strip()[:160]
    if not wa or not service:
        return jsonify({"success": False, "error": "bad_request"}), 400
    who = hashlib.sha256(("net365-interest:" + wa).encode()).hexdigest()[:16]
    try:
        c = _conn()
        c.execute("""CREATE TABLE IF NOT EXISTS service_interest (
            id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT NOT NULL, service TEXT NOT NULL,
            country TEXT, query TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_service_interest ON service_interest(service, country)")
        dup = c.execute("SELECT 1 FROM service_interest WHERE who=? AND service=? AND created_at >= datetime('now','-1 day')",
                        (who, service)).fetchone()
        if not dup:
            c.execute("INSERT INTO service_interest (who, service, country, query) VALUES (?,?,?,?)",
                      (who, service, country, query))
        c.commit()
        return jsonify({"success": True})
    except Exception:
        logger.exception("interest log failed")
        return jsonify({"success": False, "error": "server"}), 500


@wa_bp.route("/api/whatsapp/commands", methods=["GET"])
@bot_required
def wa_commands():
    """Machine-readable command catalogue for the chat interfaces. Advertises entry points only; it never
    authorizes or executes a transaction (payment always needs the customer to tap Pay now)."""
    cmds = [
        ("menu", "Show the Net365 menu"), ("airtime", "Buy airtime step by step"),
        ("airtime 2000 mtn", "One-line airtime: amount and network (then send the number)"),
        ("recharge mtn 500", "Same thing, words in any order"),
        ("airtime 08012345678 500", "One-line airtime to a number; shows a confirm card before you pay"),
        ("bills", "Electricity and cable TV"), ("giftcards", "Gift cards and vouchers"),
        ("spending", "This month's spending, budget and insights"), ("budget 30000", "Set a monthly budget"),
        ("reports", "Weekly or monthly money reports"), ("ask <question>", "Ask about your spending in plain words"),
        ("schedules", "Airtime and bill reminders"), ("history", "Recent transactions"), ("saved", "Saved numbers and meters"),
        ("status", "Track an order"), ("again", "Repeat a recent top-up"), ("link", "Link a Net365 account"),
        ("unlink", "Unlink this chat"), ("help", "Help and support"), ("cancel", "Cancel the current flow"),
    ]
    return jsonify({"success": True, "commands": [{"command": c, "description": d} for c, d in cmds]})


@wa_bp.route("/api/whatsapp/status", methods=["POST"])
@bot_required
def wa_status():
    wa = _wa(_body())
    if not wa:
        return jsonify({"success": False, "error": "bad_number"}), 400
    link = _get_link(wa)
    if not link:
        return jsonify({"success": True, "google": google_chat_enabled(), "linked": False, "guest": False})
    user = _db.get_user(link["user_id"])
    if _blocked_user(user):
        return jsonify({"success": True, "google": google_chat_enabled(), "linked": False, "blocked": True})
    if link.get("is_guest"):
        return jsonify({"success": True, "google": google_chat_enabled(), "linked": False, "guest": True,
                        "has_email": bool(link.get("receipt_email")),
                        "masked_email": _mask_email(link["receipt_email"]) if link.get("receipt_email") else None,
                        "ads_opt_out": bool(link.get("ads_opt_out"))})
    first = str(user.get("full_name") or "").strip().split(" ")[0] or "there"
    others = []
    try:
        for r in _conn().execute("SELECT wa_number FROM whatsapp_links WHERE user_id = ? AND active = 1 AND wa_number != ?",
                                 (link["user_id"], wa)).fetchall():
            others.append(chat_source_for_link({"wa_number": r[0]}))
    except Exception:
        pass
    return jsonify({"success": True, "google": google_chat_enabled(), "linked": True, "guest": False, "first_name": first,
                    "masked_email": _mask_email(user.get("email") or ""), "also_linked": sorted(set(others)),
                    "ads_opt_out": bool(link.get("ads_opt_out")), "frozen": bool(link.get("frozen"))})


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

    sent = True
    try:
        code = _db.create_verification_otp(email, otp_type="whatsapp_link", ttl_minutes=10)
        # Plain text on purpose: the sender HTML-escapes the message, so markup in it showed up as literal tags.
        body = (f"Your Net365 chat-linking code (WhatsApp or Telegram) is {code}. "
                f"It expires in 10 minutes. If you did not ask to link a chat, ignore this email "
                f"and do not share the code with anyone.")
        try:
            # wait_seconds makes the sender report a real success/failure instead of "dispatched" (the default fire-and-forget).
            sent = _send_email(email, "Link your chat to your Net365 account", body, wait_seconds=12)
        except TypeError:
            sent = _send_email(email, "Link your chat to your Net365 account", body)   # a sender without wait_seconds
    except Exception:
        logger.exception("could not send WhatsApp link OTP")
        sent = False
    if sent is False:
        logger.error("LINK CODE NOT SENT (chat ending %s): the email provider did not confirm delivery. "
                     "Check RESEND_API_KEY / MAILGUN_API_KEY + MAILGUN_DOMAIN / SMTP_* on the Flask service.", wa[-4:])
        # our failure must not use up the customer's 3 codes per hour
        _conn().execute("UPDATE whatsapp_link_attempts SET sends = MAX(sends - 1, 0) WHERE wa_number = ?", (wa,))
        return jsonify({"success": False, "error": "email_unavailable"}), 503
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
    if _is_weak_pin(pin):
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

    return jsonify(_complete_link(wa, user, email, pin, "email"))


def _complete_link(wa, user, email, pin, via="email"):
    """Shared by the email-code and Google routes: ownership of the account was already proven by the caller.
    Applies the PIN, moves guest history, keeps one chat per channel per account. Returns the response dict."""
    salt = secrets.token_hex(16)
    pin_hash = _make_pin_hash(pin, salt)
    c = _conn()
    # progressive registration: carry the guest's history and points over to the real account
    old = c.execute("SELECT user_id, is_guest FROM whatsapp_links WHERE wa_number = ?", (wa,)).fetchone()
    if old and old["is_guest"] and int(old["user_id"]) != int(user["id"]):
        gid = int(old["user_id"])
        for tbl in ("transactions", "points_ledger"):
            try:
                c.execute(f"UPDATE {tbl} SET user_id = ? WHERE user_id = ?", (user["id"], gid))
            except Exception:
                logger.exception("guest upgrade: could not move %s", tbl)
        try:
            from net365_geoint import move_owner
            move_owner(gid, int(user["id"]))
        except Exception:
            logger.exception("guest upgrade: could not move location data")
        c.execute("UPDATE users SET account_status = 'deleted' WHERE id = ? AND is_guest = 1", (gid,))
    # One account per chat, and one chat PER CHANNEL per account: an account can have one Telegram chat and one
    # WhatsApp number linked at the same time. Linking a second chat on the SAME channel moves the account to it,
    # and the chat that lost the link is told (it used to be unlinked silently).
    this_channel = chat_source_for_link({"wa_number": wa})
    displaced = []
    for r in c.execute("SELECT wa_number FROM whatsapp_links WHERE user_id = ? AND wa_number != ?", (user["id"], wa)).fetchall():
        if chat_source_for_link({"wa_number": r[0]}) == this_channel:
            displaced.append(r[0])
    for w_old in displaced:
        c.execute("DELETE FROM whatsapp_links WHERE wa_number = ?", (w_old,))
    prev = c.execute("SELECT user_id FROM whatsapp_links WHERE wa_number = ?", (wa,)).fetchone()
    c.execute("DELETE FROM whatsapp_links WHERE wa_number = ?", (wa,))
    c.execute(
        "INSERT INTO whatsapp_links (wa_number, user_id, pin_salt, pin_hash) VALUES (?, ?, ?, ?)",
        (wa, user["id"], salt, pin_hash),
    )
    # Ownership of this mailbox was proven (email code or Google sign-in), so the address is proven: mark it verified so payments
    # are not refused afterwards with "verify your email".
    try:
        c.execute("UPDATE users SET email_verified = 1 WHERE id = ? AND COALESCE(email_verified, 0) = 0", (user["id"],))
    except Exception:
        logger.exception("could not mark email verified on link")
    c.execute("UPDATE whatsapp_link_attempts SET wrong = 0, sends = 0 WHERE wa_number = ?", (wa,))
    try:
        c.commit()
    except Exception:
        pass
    try:
        if _welcome_hook:
            created = _parse(user.get("created_at"))
            to_addr = str(user.get("email") or email or "").strip()
            if created and _now() - created < timedelta(days=3) and to_addr:
                _welcome_hook(int(user["id"]), to_addr, user.get("full_name") or "", "chat")
    except Exception:
        logger.exception("welcome email hook failed")
    try:
        _send_email(
            email,
            "A chat was linked to your Net365 account",
            f"The {chat_source_for_link({'wa_number': wa}).title()} chat ending {wa[-4:]} was just linked to your Net365 account. "
            f"If this was not you, reply to this email or contact support@net365co.com immediately.",
        )
    except Exception:
        pass
    for w_old in displaced:
        try:
            threading.Thread(target=_post_to_bot, args=({"wa": w_old, "kind": "engage", "title": "Account moved",
                "body": "Your Net365 account is now linked to a different chat on this channel, so this chat is no longer linked. "
                        "Reply link to connect an account again."},), daemon=True).start()
        except Exception:
            pass
    _apply_pending_referral(wa, user)
    first = str(user.get("full_name") or "").strip().split(" ")[0] or "there"
    return {"success": True, "first_name": first, "masked_email": _mask_email(email),
            "moved_from_other_chat": bool(displaced), "switched_account": bool(prev and int(prev[0]) != int(user["id"]))}


# --------------------------------------------------------------------------- Google sign-in for chats (NET365 ID)
# Flow: bot asks /google/start -> customer opens the one-time link in a browser -> Google signs them in (the same OAuth
# client as the website) -> app.py's callback hands the verified Google identity to google_link_finish() -> the chat
# is told to continue -> customer chooses a 4-digit PIN -> /google/confirm links the chat. Google proves control of the
# Google account only; the PIN still guards every sensitive action. Matching an email never links a chat by itself:
# the link token is bound to ONE chat id, is single-use and expires in 10 minutes.
GOOGLE_LINK_MINUTES = 10


def google_chat_enabled():
    return bool(os.getenv("GOOGLE_CLIENT_ID", "").strip() and os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
                and os.getenv("NET365_PUBLIC_URL", "").strip().startswith("https://")
                and os.getenv("GOOGLE_CHAT_LINK_ENABLED", "true").strip().lower() in ("1", "true", "yes", "on"))


def _th(raw):
    return hashlib.sha256(("gl|" + str(raw)).encode()).hexdigest()


@wa_bp.route("/api/whatsapp/google/start", methods=["POST"])
@bot_required
def wa_google_start():
    wa = _wa(_body())
    if not wa:
        return jsonify({"success": False, "error": "bad_number"}), 400
    if not google_chat_enabled():
        return jsonify({"success": False, "error": "not_configured"}), 200
    link = _get_link(wa)
    if link and not link.get("is_guest"):
        return jsonify({"success": False, "error": "already_linked"}), 409
    c = _conn()
    n = c.execute("SELECT COUNT(*) FROM chat_google_links WHERE wa_number = ? AND created_at >= datetime('now','-1 hour')", (wa,)).fetchone()[0]
    if n >= 6:
        return jsonify({"success": False, "error": "too_many"}), 429
    raw = secrets.token_urlsafe(24)
    c.execute("UPDATE chat_google_links SET status = 'replaced' WHERE wa_number = ? AND status IN ('pending','verified')", (wa,))
    c.execute("INSERT INTO chat_google_links (token_hash, wa_number, expires_at) VALUES (?,?,?)",
              (_th(raw), wa, _fmt(_now() + timedelta(minutes=GOOGLE_LINK_MINUTES))))
    try:
        c.commit()
    except Exception:
        pass
    base = os.getenv("NET365_PUBLIC_URL", "").rstrip("/")
    return jsonify({"success": True, "url": f"{base}/api/chat/google/begin?t={raw}", "minutes": GOOGLE_LINK_MINUTES})


@wa_bp.route("/api/chat/google/begin", methods=["GET"])
def chat_google_begin():
    from flask import session, redirect
    raw = str(request.args.get("t") or "")[:80]
    row = _conn().execute("SELECT status, expires_at FROM chat_google_links WHERE token_hash = ?", (_th(raw),)).fetchone() if raw else None
    exp = _parse(row["expires_at"]) if row else None
    if not row or row["status"] != "pending" or not exp or exp < _now() or not google_chat_enabled():
        return _google_page(False, "This sign-in link has expired or was already used. Go back to the chat and ask for a new one.")
    # The OAuth state and our chat token live in a cookie set on THIS host. Google sends the browser back to the host in
    # GOOGLE_REDIRECT_URI; if that is a different host the cookie is not there, the callback treats it as an ordinary website
    # sign-in and the chat never hears about it. So begin on the callback's own host first.
    try:
        from urllib.parse import urlparse
        cb_host = urlparse(os.getenv("GOOGLE_REDIRECT_URI", "").strip()).netloc
        if cb_host and cb_host.lower() != request.host.lower():
            logger.info("chat google begin: moving from host %s to callback host %s so the cookie survives", request.host, cb_host)
            return redirect(f"https://{cb_host}/api/chat/google/begin?t={raw}")
    except Exception:
        logger.exception("chat google host check failed")
    session["chat_link_token"] = raw
    logger.info("chat google begin ok on host %s (callback host %s)", request.host, os.getenv("GOOGLE_REDIRECT_URI", "") or "same")
    return redirect("/api/auth/google/login")


def _google_page(ok, msg):
    import html as _h
    colour = "#E53935" if not ok else "#FF6D00"
    title = "You are signed in" if ok else "Sign-in not completed"
    body = (f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>Net365</title><style>body{{margin:0;background:#121214;color:#fff;font-family:-apple-system,Segoe UI,Roboto,sans-serif;'
            f'display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}}.c{{max-width:380px;text-align:center}}'
            f'.b{{height:4px;border-radius:2px;background:linear-gradient(90deg,#E53935,#FF6D00);margin-bottom:28px}}h1{{font-size:22px;margin:0 0 10px}}'
            f'p{{color:#b8b8c0;line-height:1.5}}small{{color:{colour}}}</style></head><body><div class="c"><div class="b"></div>'
            f'<h1>{_h.escape(title)}</h1><p>{_h.escape(msg)}</p><small>NET365</small></div></body></html>')
    resp = make_response(body)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------------------- one-tap "connect this chat" (website sign-in)
# The bot's "Sign in / Sign up" button calls /web/start. The customer opens the one-time link:
#   * already signed in to net365 in this browser  -> one confirm button, no password, no email code;
#   * not signed in                               -> Google button, or sign in on the site then reload this page.
# Confirming marks the SAME chat_google_links token 'verified', so the bot's existing "I have signed in" -> PIN -> link steps
# (/google/check, /google/confirm) finish the job. The token is bound to ONE chat, single use, 10 minutes.
def _web_session_user():
    """The real (non-guest, non-blocked) Net365 user signed in on the website in THIS browser, or None."""
    try:
        tok = (request.cookies.get(os.getenv("SESSION_COOKIE_NAME", "net365_session")) or "").strip()
        sess = _db.get_session(tok) if tok else None
        user = _db.get_user(sess["user_id"]) if sess and sess.get("user_id") else None
        if user and not _blocked_user(user) and not user.get("is_guest"):
            return user
    except Exception:
        logger.exception("web session lookup failed")
    return None


def _pending_chat_token(raw):
    row = _conn().execute("SELECT wa_number, status, expires_at FROM chat_google_links WHERE token_hash = ?", (_th(raw),)).fetchone() if raw else None
    exp = _parse(row["expires_at"]) if row else None
    return row if (row and row["status"] == "pending" and exp and exp >= _now()) else None


def _link_shell(title, inner, status=200):
    import html as _h
    body = (f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>Net365</title><style>body{{margin:0;background:#121214;color:#fff;font-family:-apple-system,Segoe UI,Roboto,sans-serif;'
            f'display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}}.c{{max-width:400px;width:100%;text-align:center}}'
            f'.b{{height:4px;border-radius:2px;background:linear-gradient(90deg,#E53935,#FF6D00);margin-bottom:28px}}h1{{font-size:22px;margin:0 0 10px}}'
            f'p{{color:#b8b8c0;line-height:1.5}}.w{{background:#1c1c20;border-radius:10px;padding:12px 14px;font-size:14px;color:#b8b8c0;margin:16px 0}}'
            f'.btn{{display:block;width:100%;box-sizing:border-box;border:0;border-radius:10px;padding:14px;font-size:16px;font-weight:600;color:#fff;'
            f'background:linear-gradient(90deg,#E53935,#FF6D00);text-decoration:none;cursor:pointer;margin:10px 0}}'
            f'.btn.alt{{background:#2a2a30}}small{{color:#FF6D00}}</style></head><body><div class="c"><div class="b"></div>'
            f'<h1>{_h.escape(title)}</h1>{inner}<small>NET365</small></div></body></html>')
    resp = make_response(body, status)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@wa_bp.route("/api/whatsapp/web/start", methods=["POST"])
@bot_required
def wa_web_start():
    wa = _wa(_body())
    if not wa:
        return jsonify({"success": False, "error": "bad_number"}), 400
    base = os.getenv("NET365_PUBLIC_URL", "").strip().rstrip("/")
    if not base.startswith("https://"):
        return jsonify({"success": False, "error": "not_configured"}), 200
    link = _get_link(wa)
    if link and not link.get("is_guest"):
        return jsonify({"success": False, "error": "already_linked"}), 409
    c = _conn()
    n = c.execute("SELECT COUNT(*) FROM chat_google_links WHERE wa_number = ? AND created_at >= datetime('now','-1 hour')", (wa,)).fetchone()[0]
    if n >= 6:
        return jsonify({"success": False, "error": "too_many"}), 429
    raw = secrets.token_urlsafe(24)
    c.execute("UPDATE chat_google_links SET status = 'replaced' WHERE wa_number = ? AND status IN ('pending','verified')", (wa,))
    c.execute("INSERT INTO chat_google_links (token_hash, wa_number, expires_at) VALUES (?,?,?)",
              (_th(raw), wa, _fmt(_now() + timedelta(minutes=GOOGLE_LINK_MINUTES))))
    try:
        c.commit()
    except Exception:
        pass
    return jsonify({"success": True, "url": f"{base}/api/chat/web/begin?t={raw}", "minutes": GOOGLE_LINK_MINUTES})


@wa_bp.route("/api/chat/web/begin", methods=["GET"])
def chat_web_begin():
    import html as _h
    raw = str(request.args.get("t") or "")[:80]
    row = _pending_chat_token(raw)
    if not row:
        return _google_page(False, "This sign-in link has expired or was already used. Go back to the chat and ask for a new one.")
    chan = chat_source_for_link({"wa_number": row["wa_number"]}).title()
    user = _web_session_user()
    if user:
        nonce = secrets.token_urlsafe(16)
        inner = (f'<p>You are signed in to Net365 as <b>{_h.escape(_mask_email(user.get("email") or ""))}</b>.</p>'
                 f'<p>Connect your <b>{_h.escape(chan)}</b> chat to this account?</p>'
                 f'<div class="w">Only continue if <b>you</b> just tapped <i>Sign in / Sign up</i> in your own {_h.escape(chan)} chat. '
                 f'If someone sent you this link, do not continue: they could use your account.</div>'
                 f'<form method="post" action="/api/chat/web/confirm"><input type="hidden" name="t" value="{_h.escape(raw)}">'
                 f'<input type="hidden" name="n" value="{nonce}"><button class="btn" type="submit">Yes, connect my {_h.escape(chan)}</button></form>'
                 f'<p style="font-size:13px">Not you? Close this page.</p>')
        resp = _link_shell("Connect your chat", inner)
        resp.set_cookie("n365_cl", nonce, max_age=600, httponly=True, secure=request.is_secure, samesite="Lax")
        return resp
    gl = (f'<a class="btn" href="/api/chat/google/begin?t={_h.escape(raw)}">Continue with Google</a>') if google_chat_enabled() else ""
    site = os.getenv("FRONTEND_URL", "").strip().rstrip("/") or os.getenv("NET365_PUBLIC_URL", "").strip().rstrip("/")
    inner = (f'<p>Sign in to Net365 to connect your <b>{_h.escape(chan)}</b> chat.</p>{gl}'
             f'<a class="btn alt" href="{_h.escape(site)}" target="_blank" rel="noopener">Sign in or create an account</a>'
             f'<p style="font-size:13px">After signing in on Net365 in this browser, come back here and refresh this page. '
             f'You will see one button to connect your chat. No email code needed.</p>')
    return _link_shell("Sign in to continue", inner)


@wa_bp.route("/api/chat/web/confirm", methods=["POST"])
def chat_web_confirm():
    raw = str(request.form.get("t") or "")[:80]
    nonce = str(request.form.get("n") or "")
    cookie_nonce = str(request.cookies.get("n365_cl") or "")
    if not nonce or not cookie_nonce or not hmac.compare_digest(nonce, cookie_nonce):
        return _google_page(False, "This page expired. Go back to the chat and ask for a new link.")
    if not _pending_chat_token(raw):
        return _google_page(False, "This sign-in link has expired or was already used. Go back to the chat and ask for a new one.")
    user = _web_session_user()
    if not user:
        return _google_page(False, "You are not signed in to Net365 in this browser. Sign in, then open the link from your chat again.")
    resp = google_link_finish(raw, user, None)
    resp.delete_cookie("n365_cl")
    return resp


def google_link_finish(raw, user, info):
    """Called by the Google callback in app.py once Google has verified the address. Returns a branded page."""
    try:
        c = _conn()
        row = c.execute("SELECT wa_number, status, expires_at FROM chat_google_links WHERE token_hash = ?", (_th(raw),)).fetchone()
        exp = _parse(row["expires_at"]) if row else None
        if not row or row["status"] != "pending" or not exp or exp < _now():
            return _google_page(False, "This sign-in link has expired or was already used. Go back to the chat and ask for a new one.")
        if _blocked_user(user):
            return _google_page(False, "This Net365 account is not available. Contact support@net365co.com.")
        sub = str((info or {}).get("sub") or "")
        if sub:
            ident = c.execute("SELECT user_id FROM net365_identities WHERE provider = 'google' AND subject = ?", (sub,)).fetchone()
            if ident and int(ident[0]) != int(user["id"]):
                return _google_page(False, "This Google account is already tied to a different Net365 account. Contact support@net365co.com.")
            if not ident:
                c.execute("INSERT OR IGNORE INTO net365_identities (provider, subject, user_id) VALUES ('google', ?, ?)", (sub, user["id"]))
        c.execute("UPDATE chat_google_links SET status = 'verified', user_id = ?, email = ? WHERE token_hash = ?",
                  (user["id"], str(user.get("email") or "").lower(), _th(raw)))
        try:
            c.commit()
        except Exception:
            pass
        wa = row["wa_number"]
        threading.Thread(target=_deliver_to_bot, args=({"wa": wa, "kind": "google_ok", "masked_email": _mask_email(user.get("email") or "")},),
                         daemon=True).start()
        return _google_page(True, f"Signed in as {_mask_email(user.get('email') or '')}. Go back to your chat and tap Continue to choose your PIN.")
    except Exception:
        logger.exception("google chat link failed")
        return _google_page(False, "Something went wrong. Go back to the chat and try again.")


def _verified_google(wa):
    row = _conn().execute("SELECT token_hash, user_id, email, expires_at FROM chat_google_links WHERE wa_number = ? AND status = 'verified' "
                          "ORDER BY created_at DESC LIMIT 1", (wa,)).fetchone()
    exp = _parse(row["expires_at"]) if row else None
    return row if (row and exp and exp >= _now()) else None


@wa_bp.route("/api/whatsapp/google/check", methods=["POST"])
@bot_required
def wa_google_check():
    wa = _wa(_body())
    if not wa:
        return jsonify({"success": False, "error": "bad_number"}), 400
    row = _verified_google(wa)
    if row:
        return jsonify({"success": True, "status": "verified", "masked_email": _mask_email(row["email"] or "")})
    pend = _conn().execute("SELECT 1 FROM chat_google_links WHERE wa_number = ? AND status = 'pending' AND expires_at >= ?", (wa, _fmt(_now()))).fetchone()
    return jsonify({"success": True, "status": "pending" if pend else "expired"})


@wa_bp.route("/api/whatsapp/google/confirm", methods=["POST"])
@bot_required
def wa_google_confirm():
    data = _body()
    wa = _wa(data)
    pin = str(data.get("pin") or "")
    if not wa:
        return jsonify({"success": False, "error": "bad_number"}), 400
    if not _PIN_RE.match(pin):
        return jsonify({"success": False, "error": "bad_pin_format"}), 400
    if _is_weak_pin(pin):
        return jsonify({"success": False, "error": "weak_pin"}), 400
    row = _verified_google(wa)
    if not row:
        return jsonify({"success": False, "error": "not_verified"}), 400
    link = _get_link(wa)
    if link and not link.get("is_guest"):
        return jsonify({"success": False, "error": "already_linked"}), 409
    user = _db.get_user(row["user_id"])
    if _blocked_user(user):
        return jsonify({"success": False, "error": "account_unavailable"}), 403
    # single use: claim the token before linking
    cur = _conn().execute("UPDATE chat_google_links SET status = 'used' WHERE token_hash = ? AND status = 'verified'", (row["token_hash"],))
    if cur.rowcount != 1:
        return jsonify({"success": False, "error": "not_verified"}), 400
    out = _complete_link(wa, user, row["email"] or user.get("email") or "", pin, "google")
    return jsonify(out)


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

    if link.get("is_guest") and data.get("require_pin", True):
        return jsonify({"success": False, "error": "guest_no_pin"}), 403

    if link.get("frozen"):
        return jsonify({"success": False, "error": "frozen"}), 423

    if data.get("require_pin", True):
        pin = str(data.get("pin") or "")
        ok = _check_link_pin(link, pin)
        if not ok:
            fails = int(link.get("pin_failed") or 0) + 1
            until = _fmt(_now() + timedelta(minutes=PIN_LOCK_MINUTES)) if fails >= PIN_MAX_FAILS else None
            _conn().execute(
                "UPDATE whatsapp_links SET pin_failed = ?, locked_until = ? WHERE id = ?",
                (0 if until else fails, until, link["id"]),
            )
            if until:
                _alert_owner(user, "Net365 PIN locked after wrong attempts",
                             f"Your {chat_source_for_link(link).title()} chat PIN was entered wrongly {PIN_MAX_FAILS} times, so the chat is locked for "
                             f"{PIN_LOCK_MINUTES} minutes. If this was not you, reply *freeze* in the chat or contact support@net365co.com.")
                return jsonify({"success": False, "error": "locked", "retry_minutes": PIN_LOCK_MINUTES}), 423
            return jsonify({"success": False, "error": "bad_pin", "attempts_left": PIN_MAX_FAILS - fails}), 401

    _conn().execute(
        "UPDATE whatsapp_links SET pin_failed = 0, locked_until = NULL, last_used_at = ? WHERE id = ?",
        (_fmt(_now()), link["id"]),
    )
    token = _mint_session(user["id"], wa, bool(data.get("require_pin", True)))
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
    ok = _check_link_pin(link, pin)
    if not ok:
        fails = int(link.get("pin_failed") or 0) + 1
        until = _fmt(_now() + timedelta(minutes=PIN_LOCK_MINUTES)) if fails >= PIN_MAX_FAILS else None
        _conn().execute(
            "UPDATE whatsapp_links SET pin_failed = ?, locked_until = ? WHERE id = ?",
            (0 if until else fails, until, link["id"]),
        )
        return jsonify({"success": False, "error": "locked" if until else "bad_pin"}), 401
    _conn().execute("DELETE FROM whatsapp_links WHERE id = ?", (link["id"],))
    try:
        _conn().commit()
    except Exception:
        pass
    try:
        u = _db.get_user(link["user_id"]) or {}
        if _send_email and u.get("email"):
            _send_email(u["email"], "Chat disconnected from your Net365 account",
                        f"The {chat_source_for_link(link).title()} chat ending {str(link['wa_number'])[-4:]} was disconnected from your Net365 account. "
                        f"If this was not you, contact support@net365co.com.")
    except Exception:
        logger.exception("unlink email failed")
    return jsonify({"success": True})




# --------------------------------------------------------------------------- freeze + step-up
STEPUP_AMOUNT_NGN = float(os.getenv("STEPUP_AMOUNT_NGN", "20000"))
STEPUP_AMOUNT_FOREIGN = float(os.getenv("STEPUP_AMOUNT_FOREIGN", "50"))  # USD/EUR/GBP-sized currencies


def _alert_owner(user, subject, text):
    try:
        if _send_email and user and user.get("email"):
            _send_email(user["email"], subject, text)
    except Exception:
        logger.exception("security alert email failed")


@wa_bp.route("/api/whatsapp/freeze", methods=["POST"])
@bot_required
def wa_freeze():
    """Emergency stop from the chat itself. No PIN on purpose: anyone who lost a phone must be able to stop it fast.
    Un-freezing needs the PIN. Freezing never moves money; it only blocks chat purchases for this account."""
    wa = _wa(_body())
    link = _get_link(wa) if wa else None
    if not link or link.get("is_guest"):
        return jsonify({"success": False, "error": "not_linked"}), 404
    c = _conn()
    c.execute("UPDATE whatsapp_links SET frozen = 1, frozen_at = ? WHERE user_id = ?", (_fmt(_now()), link["user_id"]))
    try:  # kill any live chat sessions of this user straight away
        toks = [r[0] for r in c.execute("SELECT token FROM chat_sessions WHERE user_id = ?", (link["user_id"],)).fetchall()]
        for t in toks:
            c.execute("DELETE FROM sessions WHERE token = ?", (t,))
        c.execute("DELETE FROM chat_sessions WHERE user_id = ?", (link["user_id"],))
    except Exception:
        logger.exception("freeze: session cleanup failed")
    _alert_owner(_db.get_user(link["user_id"]), "Your Net365 chat access is frozen",
                 f"Chat purchases on your Net365 account were frozen from the {chat_source_for_link(link).title()} chat ending "
                 f"{str(wa)[-4:]}. Unfreeze it in the chat with your PIN. If this was not you, contact support@net365co.com.")
    return jsonify({"success": True, "frozen": True})


@wa_bp.route("/api/whatsapp/unfreeze", methods=["POST"])
@bot_required
def wa_unfreeze():
    data = _body()
    wa = _wa(data)
    link = _get_link(wa) if wa else None
    if not link or link.get("is_guest"):
        return jsonify({"success": False, "error": "not_linked"}), 404
    locked = _parse(link.get("locked_until"))
    if locked and locked > _now():
        return jsonify({"success": False, "error": "locked"}), 423
    if not _check_link_pin(link, str(data.get("pin") or "")):
        fails = int(link.get("pin_failed") or 0) + 1
        until = _fmt(_now() + timedelta(minutes=PIN_LOCK_MINUTES)) if fails >= PIN_MAX_FAILS else None
        _conn().execute("UPDATE whatsapp_links SET pin_failed = ?, locked_until = ? WHERE id = ?",
                        (0 if until else fails, until, link["id"]))
        return jsonify({"success": False, "error": "locked" if until else "bad_pin",
                        "attempts_left": max(0, PIN_MAX_FAILS - fails)}), 401
    _conn().execute("UPDATE whatsapp_links SET frozen = 0, frozen_at = NULL, pin_failed = 0, locked_until = NULL WHERE user_id = ?",
                    (link["user_id"],))
    _alert_owner(_db.get_user(link["user_id"]), "Your Net365 chat access is active again",
                 f"Chat purchases were unfrozen from the {chat_source_for_link(link).title()} chat ending {str(wa)[-4:]}. "
                 f"If this was not you, contact support@net365co.com.")
    return jsonify({"success": True, "frozen": False})


def _bearer_token():
    h = request.headers.get("Authorization", "")
    return h[7:].strip() if h.lower().startswith("bearer ") else ""


def chat_purchase_error(user_id, amount, currency="NGN"):
    """Server-side gate for purchases made through a chat-minted token. Returns (json_dict, status) or None.
    Web/app sessions are not in chat_sessions, so they are never affected. Guests are capped far below the step-up amount."""
    try:
        tok = _bearer_token()
        if not tok:
            return None
        row = _conn().execute("SELECT pin_verified, wa_number FROM chat_sessions WHERE token = ? AND user_id = ?",
                              (tok, user_id)).fetchone()
        if not row:
            return None
        frozen = _conn().execute("SELECT 1 FROM whatsapp_links WHERE user_id = ? AND frozen = 1 AND active = 1", (user_id,)).fetchone()
        if frozen:
            return {"success": False, "code": "FROZEN", "error": "Chat purchases are frozen on this account."}, 423
        if is_guest_user(user_id) or row[0]:
            return None
        try:
            amt = float(amount)
        except (TypeError, ValueError):
            return None
        cur = str(currency or "NGN").upper()
        limit = STEPUP_AMOUNT_NGN if cur == "NGN" else STEPUP_AMOUNT_FOREIGN
        if amt >= limit:
            return {"success": False, "code": "PIN_REQUIRED",
                    "error": "Enter your PIN to confirm this purchase.", "stepup_amount": limit}, 403
    except Exception:
        logger.exception("chat_purchase_error failed")
        return {"success": False, "code": "PIN_REQUIRED", "error": "Enter your PIN to confirm this purchase."}, 403
    return None


# --------------------------------------------------------------------------- guest identity
# Telegram/WhatsApp users can buy without an account. Their identity is the chat id (never the
# username). A guest is a real users row flagged is_guest=1 with NO email, NO password and NO wallet,
# so every existing code path (transactions, points, receipts) works unchanged. The caps below are
# enforced server-side in /api/payment/init, not in the bot.
GUEST_PER_TX_NGN = float(os.getenv("GUEST_PER_TX_NGN", "5000"))
GUEST_DAILY_NGN = float(os.getenv("GUEST_DAILY_NGN", "10000"))


def is_guest_user(user_id):
    try:
        row = _conn().execute("SELECT is_guest FROM users WHERE id = ?", (user_id,)).fetchone()
        return bool(row and row[0])
    except Exception:
        return False


def guest_receipt_email(user_id):
    try:
        row = _conn().execute(
            "SELECT receipt_email FROM whatsapp_links WHERE user_id = ? AND is_guest = 1 AND active = 1",
            (user_id,)).fetchone()
        return row[0] if row and row[0] else None
    except Exception:
        return None


def guest_limit_error(user_id, amount):
    """Extra caps for guests, on top of the global launch limits. Returns a message or None."""
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return "Invalid amount"
    if amount > GUEST_PER_TX_NGN:
        return (f"Guest purchases are limited to ₦{GUEST_PER_TX_NGN:,.0f} each. "
                f"Create a free Net365 account (reply *link*) for higher limits.")
    row = _conn().execute(
        "SELECT COALESCE(SUM(amount),0) FROM transactions WHERE user_id = ? "
        "AND created_at >= datetime('now','-1 day') AND status IN ('pending','paid','processing','fulfilled')",
        (user_id,)).fetchone()
    used = float(row[0] or 0)
    if used + amount > GUEST_DAILY_NGN:
        return (f"Guest daily limit reached (₦{GUEST_DAILY_NGN:,.0f} per 24h). "
                f"Create a free Net365 account (reply *link*) for higher limits.")
    return None


@wa_bp.route("/api/whatsapp/guest/start", methods=["POST"])
@bot_required
def wa_guest_start():
    wa = _wa(_body())
    if not wa:
        return jsonify({"success": False, "error": "bad_number"}), 400
    link = _get_link(wa)
    if link:
        return jsonify({"success": True, "guest": bool(link.get("is_guest"))})
    c = _conn()
    cur = c.execute(
        "INSERT INTO users (full_name, account_status, email_verified, is_guest, currency) "
        "VALUES (?, 'active', 0, 1, 'NGN')", ("Chat guest",))
    uid = cur.lastrowid
    salt = secrets.token_hex(16)
    # random, never disclosed PIN hash: a guest can never pass a PIN check
    try:
        c.execute("INSERT INTO whatsapp_links (wa_number, user_id, pin_salt, pin_hash, is_guest) VALUES (?,?,?,?,1)",
                  (wa, uid, salt, secrets.token_hex(32)))
        c.commit()
        return jsonify({"success": True, "guest": True})
    except Exception:
        # Another worker may have created this chat between our first lookup and insert.
        try:
            c.rollback()
        except Exception:
            pass
        existing = _get_link(wa)
        if existing:
            return jsonify({"success": True, "guest": bool(existing.get("is_guest"))})
        logger.exception("could not create guest identity")
        return jsonify({"success": False, "error": "guest_create_failed"}), 503


@wa_bp.route("/api/whatsapp/guest/email", methods=["POST"])
@bot_required
def wa_guest_email():
    data = _body()
    wa = _wa(data)
    email = str(data.get("email") or "").strip().lower()
    if not wa or not _EMAIL_RE.match(email):
        return jsonify({"success": False, "error": "bad_input"}), 400
    link = _get_link(wa)
    if not link or not link.get("is_guest"):
        return jsonify({"success": False, "error": "not_guest"}), 404
    _conn().execute("UPDATE whatsapp_links SET receipt_email = ? WHERE id = ?", (email, link["id"]))
    try:
        _conn().commit()
    except Exception:
        pass
    return jsonify({"success": True, "masked_email": _mask_email(email)})


@wa_bp.route("/api/whatsapp/ads", methods=["POST"])
@bot_required
def wa_ads_pref():
    data = _body()
    wa = _wa(data)
    link = _get_link(wa) if wa else None
    if not link:
        return jsonify({"success": False, "error": "unknown_chat"}), 404
    _conn().execute("UPDATE whatsapp_links SET ads_opt_out = ? WHERE id = ?",
                    (1 if data.get("opt_out") else 0, link["id"]))
    try:
        _conn().commit()
    except Exception:
        pass
    return jsonify({"success": True, "opt_out": bool(data.get("opt_out"))})




# --------------------------------------------------------------------------- repeat / status / invite
def _user_topups(user_id, limit=30, types=("topup",)):
    """Recent top-up rows for ONE user, payload decoded and phone decrypted. Ownership is the user_id filter."""
    import json as _json
    rows = _conn().execute(
        "SELECT reference, status, amount, currency, created_at, payload, tx_type FROM transactions "
        "WHERE user_id = ? AND tx_type IN (%s) ORDER BY created_at DESC LIMIT ?" % ",".join("?" * len(types)),
        (user_id, *types, limit)).fetchall()
    out = []
    for r in rows:
        try:
            pl = r["payload"]
            pl = _json.loads(pl) if isinstance(pl, str) else (pl or {})
            if _decrypt:
                pl = _decrypt(dict(pl))
        except Exception:
            pl = {}
        out.append({"reference": r["reference"], "status": r["status"], "tx_type": r["tx_type"], "amount": r["amount"],
                    "currency": r["currency"], "created_at": r["created_at"], "payload": pl})
    return out


def _national(p):
    d = re.sub(r"\D", "", str(p or ""))
    if d.startswith("234"):
        d = d[3:]
    return d.lstrip("0")


@wa_bp.route("/api/whatsapp/recent", methods=["POST"])
@bot_required
def wa_recent():
    wa = _wa(_body())
    link = _get_link(wa) if wa else None
    if not link:
        return jsonify({"success": False, "error": "unknown_chat"}), 404
    seen, items = set(), []
    for t in _user_topups(link["user_id"]):
        pl = t["payload"]
        if t["status"] not in ("fulfilled", "completed", "success"):
            continue
        nat = _national(pl.get("phone"))
        if not re.match(r"^[789][01]\d{8}$", nat) or nat in seen or not pl.get("operator_id"):
            continue
        seen.add(nat)
        items.append({"national": nat, "operator_id": str(pl.get("operator_id")),
                      "operator_name": pl.get("operator_name") or "Network",
                      "amount": float(pl.get("service_amount") or t["amount"] or 0)})
        if len(items) >= 3:
            break
    return jsonify({"success": True, "items": items})


@wa_bp.route("/api/whatsapp/order", methods=["POST"])
@bot_required
def wa_order():
    data = _body()
    wa = _wa(data)
    link = _get_link(wa) if wa else None
    if not link:
        return jsonify({"success": False, "error": "unknown_chat"}), 404
    ref = str(data.get("reference") or "").strip()
    tops = _user_topups(link["user_id"], 10, types=("topup", "utility", "giftcard"))
    if ref:
        tops = [t for t in tops if t["reference"] == ref]
    if not tops:
        return jsonify({"success": True, "found": False})
    t = tops[0]
    return jsonify({"success": True, "found": True, "reference": t["reference"], "status": t["status"],
                    "amount": float(t["payload"].get("service_amount") or t["amount"] or 0),
                    "phone_masked": _mask_phone(t["payload"].get("phone")), "created_at": str(t["created_at"])[:16],
                    "kind": t.get("tx_type"),
                    "label": (t["payload"].get("biller_name") or t["payload"].get("product_name") or "")})


@wa_bp.route("/api/whatsapp/invite", methods=["POST"])
@bot_required
def wa_invite():
    wa = _wa(_body())
    link = _get_link(wa) if wa else None
    if not link:
        return jsonify({"success": False, "error": "unknown_chat"}), 404
    if link.get("is_guest"):
        return jsonify({"success": True, "guest": True})
    user = _db.get_user(link["user_id"]) or {}
    code = user.get("referral_code")
    # Some versions of get_user() return a deliberately limited profile and omit
    # referral_code. Read it directly when the column exists, without assuming a schema.
    if not code:
        try:
            cols = {row[1] for row in _conn().execute("PRAGMA table_info(users)").fetchall()}
            if "referral_code" in cols:
                row = _conn().execute("SELECT referral_code FROM users WHERE id = ?", (link["user_id"],)).fetchone()
                code = row[0] if row else None
        except Exception:
            logger.exception("could not read referral code for chat invite")
    base = os.getenv("NET365_PUBLIC_URL", "").rstrip("/")
    if not code or not base:
        return jsonify({"success": True, "guest": False, "available": False})
    return jsonify({"success": True, "guest": False, "available": True, "url": f"{base}/?ref={code}", "code": code})

# --------------------------------------------------------------------------- ad click redirect
@wa_bp.route("/go/ad/<int:ad_id>")
def go_ad(ad_id):
    """Track a click from a chat message, then send the person to the ad's own https link."""
    from flask import redirect
    public = os.getenv("NET365_PUBLIC_URL", "").rstrip("/") or "/"
    dest = public
    try:
        row = _conn().execute("SELECT cta_url FROM success_page_ads WHERE id = ? AND active = 1", (ad_id,)).fetchone()
        url = (row[0] if row else "") or ""
        if url.startswith("https://"):
            dest = url
        _db.record_success_page_ad_event(ad_id, "click", reference=request.args.get("r"),
                                         device_type="chat")
    except Exception:
        logger.exception("ad click tracking failed")
    return redirect(dest, code=302)


# --------------------------------------------------------------------------- post-purchase message
HOUSE_PROMOS = [
    ("🎁 Share Net365", "Send a friend your link — when they buy their first airtime, you both earn Net365 points."),
    ("📲 Never run out", "Reply *airtime* any time. Your next top-up takes about 20 seconds."),
    ("🧾 Make it yours", "Create a free Net365 account (reply *link*) to keep your history and unlock higher limits."),
    ("⚡ Pay bills too", "Net365 is growing: electricity, TV and data are on the way. Stay tuned."),
]
_decrypt = None


def set_decryptor(fn):
    global _decrypt
    _decrypt = fn


def _mask_phone(p):
    p = re.sub(r"\D", "", str(p or ""))
    if p.startswith("234") and len(p) == 13:
        p = "0" + p[3:]
    elif len(p) == 10 and p[0] in "789":
        p = "0" + p
    return (p[:4] + "••••" + p[-3:]) if len(p) >= 8 else ""


def _find_token(obj, depth=0):
    """Best-effort: prepaid electricity tokens come back inside the biller result under a 'token'-like key."""
    if depth > 4 or obj is None:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if re.search(r"token|pin", str(k), re.I) and isinstance(v, (str, int)) and 4 <= len(str(v)) <= 200:
                return str(v)
        for v in obj.values():
            t = _find_token(v, depth + 1)
            if t:
                return t
    elif isinstance(obj, list):
        for v in obj[:5]:
            t = _find_token(v, depth + 1)
            if t:
                return t
    return None


def _mask_account(a):
    a = re.sub(r"\s", "", str(a or ""))
    return (a[:2] + "•" * max(2, len(a) - 5) + a[-3:]) if len(a) >= 6 else ""


def _link_for_source(user_id, source):
    """The chat link to notify: the one on the channel the customer paid from (an account can have Telegram AND WhatsApp)."""
    rows = [dict(r) for r in _conn().execute("SELECT * FROM whatsapp_links WHERE user_id = ? AND active = 1 ORDER BY id DESC",
                                              (user_id,)).fetchall()]
    for r in rows:
        if chat_source_for_link(r) == source:
            return r
    return rows[0] if rows else None


def _deliver_to_bot(body, attempts=3):
    """POST a notice to the bot. On free hosting the bot may be asleep (about a minute to wake), so wake it with a harmless
    GET and retry instead of giving up after one 10-second try. Runs on a background thread. True when delivered."""
    import requests as _rq
    url = os.getenv("CHAT_BOT_NOTIFY_URL", "http://127.0.0.1:3001/internal/notify")
    headers = {"X-Bot-Secret": os.getenv("WHATSAPP_BOT_SECRET", "")}
    for i in range(attempts):
        try:
            r = _rq.post(url, json=body, headers=headers, timeout=20 if i == 0 else 75)
            if r.status_code == 200:
                try:
                    if r.json().get("ok") is False:  # the bot answered but could not reach the chat provider
                        logger.warning("bot notify attempt %s: bot could not send to the chat", i + 1)
                        time.sleep(2 * (i + 1))
                        continue
                except Exception:
                    pass
                return True
            logger.warning("bot notify attempt %s answered %s", i + 1, r.status_code)
            if r.status_code in (401, 403):
                return False  # wrong secret: retrying will not help
        except Exception as e:
            logger.warning("bot notify attempt %s failed: %s", i + 1, e)
        try:
            _rq.get(_bot_base() + "/health", timeout=75)  # wake a sleeping bot
        except Exception:
            pass
        time.sleep(2 * (i + 1))
    return False


_retry_state = {"started": False, "skip": set()}


def retry_missed_notifications(max_items=20):
    """Self-healing: re-send completion notices for chat orders delivered in the last 3 hours that never reached the
    chat. Idempotent (bot_notifications is claimed atomically), so it is safe with several workers."""
    done = 0
    try:
        if not _schema_ready:
            _ensure_schema()
        rows = _conn().execute(
            "SELECT t.reference FROM transactions t LEFT JOIN bot_notifications b ON b.reference = t.reference "
            "WHERE lower(t.status) = 'fulfilled' AND t.tx_type IN ('topup','utility','giftcard','merchant','data','tv','education','electricity','insurance') AND b.reference IS NULL "
            "AND t.created_at >= datetime('now','-3 hours') ORDER BY t.created_at DESC LIMIT 60").fetchall()
        for r in rows:
            ref = r[0]
            if ref in _retry_state["skip"]:
                continue
            notify_after_fulfillment(ref)
            if _conn().execute("SELECT 1 FROM bot_notifications WHERE reference = ?", (ref,)).fetchone():
                done += 1
            else:
                _retry_state["skip"].add(ref)  # not a chat order, or no chat link: do not look at it again
            if done >= max_items:
                break
    except Exception:
        logger.exception("retry_missed_notifications failed")
    return done


def _start_retry_thread():
    try:
        every = int(os.getenv("CHAT_NOTIFY_RETRY_SECONDS", "120"))
    except ValueError:
        every = 120
    if every <= 0 or _retry_state["started"]:
        return
    _retry_state["started"] = True

    def loop():
        time.sleep(45)
        while True:
            try:
                n = retry_missed_notifications()
                if n:
                    logger.info("chat notices re-sent: %s", n)
            except Exception:
                logger.exception("chat notice retry loop")
            time.sleep(max(30, every))

    threading.Thread(target=loop, name="chat-notice-retry", daemon=True).start()


def notify_after_fulfillment(reference):
    """Called once a purchase (top-up, bill or gift card) is delivered. Builds the in-chat completion
    message (confirmation + points + one promo + one headline), asks the bot to send it, and emails
    a confirmation where Net365 does not already. Idempotent per reference; never raises."""
    try:
        if os.getenv("CHAT_POST_PURCHASE_ENABLED", "true").strip().lower() not in ("1", "true", "yes", "on"):
            return
        tx = _db.get_transaction(reference)
        if not tx or tx.get("status") != "fulfilled" or not tx.get("user_id"):
            return
        payload = tx.get("payload") or {}
        if isinstance(payload, str):
            import json as _json
            payload = _json.loads(payload)
        if payload.get("source") not in ("telegram", "whatsapp"):
            return
        if not _schema_ready:
            _ensure_schema()
        c = _conn()
        link = _link_for_source(tx["user_id"], payload.get("source"))
        if not link:
            return
        cur = c.execute("INSERT OR IGNORE INTO bot_notifications (reference, status) VALUES (?, 'sending')", (reference,))
        try:
            c.commit()
        except Exception:
            pass
        if cur.rowcount == 0:
            return

        kind = tx.get("tx_type") if tx.get("tx_type") in ("utility", "giftcard", "merchant") else ("utility" if tx.get("tx_type") in ("data", "tv", "education", "electricity", "insurance") else "topup")
        if _decrypt:
            try:
                payload = _decrypt(dict(payload))
            except Exception:
                pass
        guest = bool(link.get("is_guest"))
        email = link.get("receipt_email") if guest else (_db.get_user(tx["user_id"]) or {}).get("email")
        result = tx.get("reloadly_result")
        if isinstance(result, str):
            try:
                import json as _json
                result = _json.loads(result)
            except Exception:
                result = {}

        extra = {}
        if kind == "topup":
            amount = float(payload.get("service_amount") or tx.get("amount") or 0)
            extra = {"phone_masked": _mask_phone(payload.get("phone")), "operator": payload.get("operator_name"),
                     "currency": str(tx.get("currency") or payload.get("currency") or "NGN").upper(),
                     "country": str(payload.get("country_code") or "NG").upper()}
        elif kind == "utility":
            amount = float(payload.get("service_amount") or tx.get("amount") or 0)
            extra = {"biller_name": payload.get("biller_name") or "your biller",
                     "account_masked": _mask_account(payload.get("subscriber_account")),
                     "token": _find_token(result)}
        elif kind == "merchant":
            amount = float(tx.get("amount") or 0)
            extra = {"merchant_name": payload.get("merchant_name") or "the business", "note": payload.get("note") or ""}
        else:  # giftcard
            amount = float(tx.get("amount") or 0)
            cards = []
            try:
                from net365_giftcards import fetch_codes
                tid = (result or {}).get("transactionId")
                if tid:
                    cards = fetch_codes(tid)
            except Exception:
                logger.exception("gift-card code fetch failed")
            _help = ""
            try:
                from net365_giftcards import redeem_help
                _help = redeem_help(payload.get("product_id")) if payload.get("product_id") else ""
            except Exception:
                pass
            extra = {"product": payload.get("product_name") or "Gift card",
                     "denomination": payload.get("denomination"), "cards": cards, "redeem_help": _help}

        pts = None
        try:
            import net365_rewards as rw
            award = rw.award_for_transaction(tx)
            s = rw.summary(int(tx["user_id"]))
            pts = {"earned": award.get("points", 0), "total": s["total"], "level": s["level_title"],
                   "emoji": s["level_emoji"], "next_at": s["next_at"], "next_title": s["next_title"],
                   "streak": s["streak"], "new_level": award.get("new_level"),
                   "next_unlock": s["next_unlock"], "guest": guest}
        except Exception:
            logger.exception("chat rewards summary failed")

        ad = tip = None
        if not link.get("ads_opt_out"):
            ad = _pick_ad(kind, amount, reference, tx["user_id"])
            try:
                import net365_rewards as rw
                h = rw.get_headlines("pro", 1)
                tip = h[0] if h else None
            except Exception:
                pass

        try:
            if not guest:
                _sp = spending_summary(tx["user_id"])
                if _sp and _sp.get("budget_pct") is not None and _sp["budget_pct"] >= 80:
                    extra["budget_note"] = f"{_sp['budget_pct']}% of your monthly budget used" + (" (over budget)" if _sp["budget_pct"] >= 100 else f", {_sp['days_left']} days left")
        except Exception:
            pass

        # Opt-in helpers: offer to save the number / meter, and confirm a newly saved card
        try:
            _foreign = kind == "topup" and str(payload.get("country_code") or "NG").upper() != "NG"
            if not guest and kind in ("topup", "utility") and not _foreign:
                from net365_saved import already_saved, card_for_user, card_enabled
                if not already_saved(tx["user_id"], tx.get("tx_type"), payload):
                    extra["save_ref"] = reference
                if payload.get("save_card") and card_enabled():
                    cd = card_for_user(tx["user_id"])
                    if cd:
                        extra["card_saved"] = cd.get("last4")
            elif not guest and payload.get("save_card"):
                from net365_saved import card_for_user, card_enabled
                cd = card_for_user(tx["user_id"]) if card_enabled() else None
                if cd:
                    extra["card_saved"] = cd.get("last4")
        except Exception:
            logger.exception("save helpers failed")

        rate_ref = None
        try:
            from net365_ratings import mark_asked
            rate_ref = mark_asked(tx["user_id"], reference, payload.get("source"), kind,
                                  extra.get("country"), extra.get("operator") or extra.get("product") or extra.get("biller_name"))
        except Exception:
            logger.exception("rating prompt failed")

        body = {
            "rate_ref": rate_ref,
            "wa": link["wa_number"], "reference": reference, "kind": kind, "amount": amount,
            "email_masked": _mask_email(email) if email else None, "guest": guest,
            "points": pts, "ad": ad, "tip": tip,
            "click_base": (os.getenv("NET365_PUBLIC_URL", "").rstrip("/") + "/go/ad/") if ad and ad.get("id") else None,
            **extra,
        }
        delivered = _deliver_to_bot(body)
        if delivered:
            c.execute("UPDATE bot_notifications SET status = 'sent' WHERE reference = ?", (reference,))
        else:
            # Do not leave the marker behind: it would block every later retry (the retry job picks this order up again).
            c.execute("DELETE FROM bot_notifications WHERE reference = ?", (reference,))
            try:
                c.execute("DELETE FROM service_ratings WHERE reference = ? AND rating IS NULL", (reference,))
            except Exception:
                pass
            logger.error("chat completion notice for %s was NOT delivered to the bot (%s). Check CHAT_BOT_NOTIFY_URL points at the "
                         "bot's public https address and WHATSAPP_BOT_SECRET is identical on both services.", reference, _bot_base())
        try:
            c.commit()
        except Exception:
            pass

        if _send_email and email:
            try:
                if kind == "giftcard":
                    lines = "".join(
                        f"<br>Code: <b>{x['number']}</b>" + (f" &nbsp; PIN: <b>{x['pin']}</b>" if x["pin"] else "")
                        + (f"<br>Redeem: {x['url']}" if x["url"] else "") for x in extra["cards"])
                    _send_email(email, f"Your {extra['product']} gift card",
                                f"Thank you for your purchase. Reference: {reference}.{lines or '<br>Your code is being prepared; reply <b>giftcard</b> in the chat to receive it.'}"
                                f"<br><br>Keep this email private: anyone with the code can use it.")
                elif kind == "merchant":
                    _send_email(email, "Your Net365 payment receipt",
                                f"Your payment of ₦{amount:,.0f} to {extra.get('merchant_name')} was completed.\nReference: {reference}")
                elif guest and kind == "utility":
                    _send_email(email, "Your Net365 bill payment is complete",
                                f"Your payment of ₦{amount:,.0f} to {extra.get('biller_name')} for {extra.get('account_masked') or 'your account'} was completed."
                                + (f"\nToken: {extra['token']}" if extra.get("token") else "") + f"\nReference: {reference}")
                elif guest and kind == "topup":
                    _send_email(email, "Your Net365 airtime top-up is complete",
                                f"Your top-up of ₦{amount:,.0f} for {extra.get('phone_masked') or 'your number'} was delivered. "
                                f"Reference: {reference}. Thank you for using Net365. "
                                f"Create a free Net365 account in the chat (send <b>link</b>) to keep your history and earn rewards.")
            except Exception:
                logger.exception("confirmation email failed")
    except Exception:
        logger.exception("post-purchase chat notification failed")



# --------------------------------------------------------------------------- spending / reports (engine: net365_money_intelligence)
def _mi():
    import net365_money_intelligence as mi
    return mi


def get_budget(user_id):
    try:
        mi = _mi()
        c = _conn()
        mi._ensure_schema(c)
        return mi.get_budget(c, user_id)
    except Exception:
        return None


def spending_summary(user_id, period="monthly", completed=False):
    """Compact chat view of one customer's completed payments. Never raises (returns None on failure)."""
    try:
        mi = _mi()
        c = _conn()
        return mi.chat_summary(mi.build_report(c, user_id, period, completed=completed))
    except Exception:
        logger.exception("spending summary failed")
        return None


def send_chat_report(user_id, summary):
    """Push a scheduled report into the customer's linked chat. True if delivered."""
    link = chat_link_for_user(user_id)
    if not link or link.get("is_guest"):
        return False
    try:
        return _post_to_bot({"wa": link["wa_number"], "kind": "report", **summary})
    except Exception:
        logger.exception("chat report failed")
        return False


def _account_link():
    wa = _wa(_body())
    link = _get_link(wa) if wa else None
    return wa, link


@wa_bp.route("/api/whatsapp/spending", methods=["POST"])
@bot_required
def wa_spending():
    data = _body()
    wa = _wa(data)
    link = _get_link(wa) if wa else None
    if not link:
        return jsonify({"success": False, "error": "unknown_chat"}), 404
    if link.get("is_guest"):
        return jsonify({"success": True, "guest": True})
    period = data.get("period") if data.get("period") in ("daily", "weekly", "monthly") else "monthly"
    s = spending_summary(link["user_id"], period)
    if s is None:
        return jsonify({"success": False, "error": "unavailable"}), 503
    return jsonify({"success": True, "guest": False, **s})


@wa_bp.route("/api/whatsapp/budget", methods=["POST"])
@bot_required
def wa_budget():
    data = _body()
    wa = _wa(data)
    link = _get_link(wa) if wa else None
    if not link or link.get("is_guest"):
        return jsonify({"success": False, "error": "account_required"}), 403
    uid = link["user_id"]
    mi = _mi()
    c = _conn()
    mi._ensure_schema(c)
    if "amount" in data:
        try:
            mi.set_budget(c, uid, float(data.get("amount") or 0))
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "bad_amount"}), 400
    return jsonify({"success": True, "budget": mi.get_budget(c, uid)})


@wa_bp.route("/api/whatsapp/ask", methods=["POST"])
@bot_required
def wa_ask():
    data = _body()
    wa = _wa(data)
    link = _get_link(wa) if wa else None
    if not link or link.get("is_guest"):
        return jsonify({"success": False, "error": "account_required"}), 403
    q = str(data.get("question") or "").strip()[:500]
    if not q:
        return jsonify({"success": False, "error": "empty"}), 400
    try:
        mi = _mi()
        c = _conn()
        mi._ensure_schema(c)
        return jsonify({"success": True, "answer": mi.answer_question(c, link["user_id"], q)})
    except Exception:
        logger.exception("ask failed")
        return jsonify({"success": False, "error": "unavailable"}), 503


@wa_bp.route("/api/whatsapp/report_prefs", methods=["POST"])
@bot_required
def wa_report_prefs():
    """Read or change how this customer receives money reports. Reports go to this chat and/or the VERIFIED account email."""
    data = _body()
    wa = _wa(data)
    link = _get_link(wa) if wa else None
    if not link or link.get("is_guest"):
        return jsonify({"success": False, "error": "account_required"}), 403
    uid = link["user_id"]
    mi = _mi()
    c = _conn()
    mi._ensure_schema(c)
    email, verified = mi._user_email(c, uid)
    if "period" in data:
        period, channel = data.get("period"), data.get("channel") or "chat"
        if period == "off":
            c.execute("UPDATE financial_report_preferences SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?", (uid,))
        else:
            if period not in ("daily", "weekly", "monthly") or channel not in ("chat", "email", "both"):
                return jsonify({"success": False, "error": "bad_choice"}), 400
            if channel in ("email", "both") and not (email and verified):
                return jsonify({"success": False, "error": "email_not_verified"}), 400
            c.execute("INSERT INTO financial_report_preferences (user_id, period, channel, email_enabled, email, enabled, updated_at) VALUES (?,?,?,?,?,1,CURRENT_TIMESTAMP) "
                      "ON CONFLICT(user_id) DO UPDATE SET period=excluded.period, channel=excluded.channel, email_enabled=excluded.email_enabled, email=excluded.email, enabled=1, updated_at=CURRENT_TIMESTAMP",
                      (uid, period, channel, 1 if channel in ("email", "both") else 0, email if channel in ("email", "both") else None))
        try:
            c.commit()
        except Exception:
            pass
    row = c.execute("SELECT period, channel, enabled FROM financial_report_preferences WHERE user_id = ?", (uid,)).fetchone()
    pref = {"period": row["period"], "channel": row["channel"], "enabled": bool(row["enabled"])} if row else {"period": None, "channel": None, "enabled": False}
    return jsonify({"success": True, "prefs": pref, "email_ok": bool(email and verified)})


# --------------------------------------------------------------------------- Telegram Mini App pass-through
# The Mini App page and its one data call live in the bot service (which holds the bot token and verifies Telegram's
# signed login data). This just exposes them on the main domain, e.g. https://net365co.com/app.
def _bot_base():
    return os.getenv("CHAT_BOT_NOTIFY_URL", "http://127.0.0.1:3001/internal/notify").rsplit("/internal/notify", 1)[0]


@wa_bp.route("/app", methods=["GET"])
def miniapp_page():
    import requests as _rq
    try:
        r = _rq.get(_bot_base() + "/app", timeout=8)
    except Exception:
        return ("The Net365 app is unavailable right now. Please try again shortly.", 503)
    if r.status_code != 200:
        return ("The Net365 app is not available.", 404)
    resp = make_response(r.text)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@wa_bp.route("/app/api/me", methods=["POST"])
def miniapp_me():
    import requests as _rq
    raw = request.get_data(cache=False)
    if len(raw) > 8192:
        return jsonify({"ok": False, "error": "too_large"}), 413
    try:
        r = _rq.post(_bot_base() + "/app/api/me", data=raw, headers={"Content-Type": "application/json"}, timeout=10)
    except Exception:
        return jsonify({"ok": False, "error": "unavailable"}), 503
    resp = make_response(r.content, r.status_code)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _post_to_bot(body):
    import requests as _rq
    url = os.getenv("CHAT_BOT_NOTIFY_URL", "http://127.0.0.1:3001/internal/notify")
    r = _rq.post(url, json=body, headers={"X-Bot-Secret": os.getenv("WHATSAPP_BOT_SECRET", "")}, timeout=10)
    return r.status_code == 200


def chat_link_for_user(user_id):
    """The user's active chat link (or None). Never raises."""
    try:
        if not _schema_ready:
            _ensure_schema()
        row = _conn().execute("SELECT * FROM whatsapp_links WHERE user_id = ? AND active = 1 "
                              "ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
        return dict(row) if row else None
    except Exception:
        logger.exception("chat link lookup failed")
        return None


def chat_source_for_link(link):
    """'telegram' when the stored chat id carries the 999 prefix, otherwise 'whatsapp'."""
    return "telegram" if str((link or {}).get("wa_number", "")).startswith("999") else "whatsapp"


def send_chat_price_alert(user_id, info):
    """Tell the customer in their linked chat that a scheduled price moved. True if it was sent."""
    link = chat_link_for_user(user_id)
    if not link:
        return False
    try:
        return _post_to_bot({"wa": link["wa_number"], "kind": "price_alert", **info})
    except Exception:
        logger.exception("chat price alert failed")
        return False


def send_chat_reminder(user_id, info):
    """Schedule reminder with a pay link, sent into the user's linked chat. True if it was sent."""
    link = chat_link_for_user(user_id)
    if not link:
        return False
    try:
        return _post_to_bot({"wa": link["wa_number"], "kind": "reminder", **info})
    except Exception:
        logger.exception("chat reminder failed")
        return False


def notify_delay(reference):
    """Tell the customer, once, that they have paid and delivery is delayed (we retry automatically)."""
    try:
        if os.getenv("CHAT_POST_PURCHASE_ENABLED", "true").strip().lower() not in ("1", "true", "yes", "on"):
            return
        tx = _db.get_transaction(reference)
        if not tx or not tx.get("user_id"):
            return
        payload = tx.get("payload") or {}
        if isinstance(payload, str):
            import json as _json
            payload = _json.loads(payload)
        if payload.get("source") not in ("telegram", "whatsapp"):
            return
        link = chat_link_for_user(tx["user_id"])
        if not link:
            return
        c = _conn()
        cur = c.execute("INSERT OR IGNORE INTO bot_notifications (reference, status) VALUES (?, 'sending')",
                        (reference + ":delay",))
        try:
            c.commit()
        except Exception:
            pass
        if cur.rowcount == 0:
            return
        kind = tx.get("tx_type") if tx.get("tx_type") in ("utility", "giftcard") else ("utility" if tx.get("tx_type") in ("data", "tv", "education", "electricity", "insurance") else "topup")
        _post_to_bot({"wa": link["wa_number"], "kind": "delay", "for_kind": kind, "reference": reference,
                      "amount": float(tx.get("amount") or 0)})
    except Exception:
        logger.exception("delay notice failed")


def _pick_ad(kind, amount, reference, user_id):
    """One promo for a chat message: a matching sponsored ad if there is one, otherwise a Net365 house promo."""
    try:
        ads = _db.get_receipt_ads(tx_type=kind, country="NG", amount=amount, device_type="telegram")
        a = (ads or {}).get("primary") or (ads or {}).get("secondary")
        if a:
            _db.record_success_page_ad_event(a["id"], "impression", reference=reference,
                                             user_id=user_id, device_type="chat", country="NG")
            return {"id": a["id"], "title": a.get("headline"), "body": a.get("subheadline") or a.get("body"),
                    "cta": a.get("cta_text") or "Learn more", "sponsored": bool(a.get("sponsored")),
                    "advertiser": a.get("advertiser_name"),
                    "has_url": bool((a.get("cta_url") or "").startswith("https://"))}
    except Exception:
        logger.exception("chat ad lookup failed")
    t, b = HOUSE_PROMOS[int(time.time() // 3600) % len(HOUSE_PROMOS)]
    return {"id": None, "title": t, "body": b, "cta": None, "sponsored": False, "has_url": False}


@wa_bp.route("/api/whatsapp/offers", methods=["POST"])
@bot_required
def wa_offers():
    """The 'Offers' menu: up to 3 active promotions, click-tracked. Respects 'stop ads'."""
    wa = _wa(_body())
    link = _get_link(wa) if wa else None
    base = os.getenv("NET365_PUBLIC_URL", "").rstrip("/") + "/go/ad/"
    if not link or link.get("ads_opt_out"):
        return jsonify({"success": True, "items": [], "opted_out": bool(link and link.get("ads_opt_out"))})
    items, seen = [], set()
    try:
        ads = _db.get_receipt_ads(tx_type=None, country="NG", amount=None, device_type="telegram") or {}
        for slot in ("primary", "secondary", "tertiary"):
            a = ads.get(slot)
            if not a or a["id"] in seen:
                continue
            seen.add(a["id"])
            _db.record_success_page_ad_event(a["id"], "impression", reference="offers",
                                             user_id=link["user_id"], device_type="chat", country="NG")
            items.append({"id": a["id"], "title": a.get("headline"), "body": a.get("subheadline") or a.get("body"),
                          "cta": a.get("cta_text") or "Open", "sponsored": bool(a.get("sponsored")),
                          "advertiser": a.get("advertiser_name"),
                          "url": f"{base}{a['id']}?r=offers" if str(a.get("cta_url") or "").startswith("https://") else None})
    except Exception:
        logger.exception("offers lookup failed")
    return jsonify({"success": True, "items": items})


_resend_at = {}


@wa_bp.route("/api/whatsapp/giftcards/resend", methods=["POST"])
@bot_required
def wa_gc_resend():
    """Re-fetch the codes of the user's latest delivered gift card (we never store codes)."""
    wa = _wa(_body())
    link = _get_link(wa) if wa else None
    if not link or link.get("is_guest"):
        return jsonify({"success": False, "error": "unknown_chat"}), 404
    if time.time() - _resend_at.get(wa, 0) < 60:
        return jsonify({"success": False, "error": "slow_down"}), 429
    _resend_at[wa] = time.time()
    import json as _json
    row = _conn().execute(
        "SELECT reference, reloadly_result, payload FROM transactions WHERE user_id = ? AND tx_type = 'giftcard' "
        "AND status = 'fulfilled' ORDER BY created_at DESC LIMIT 1", (link["user_id"],)).fetchone()
    if not row:
        return jsonify({"success": True, "found": False})
    try:
        res = _json.loads(row["reloadly_result"]) if isinstance(row["reloadly_result"], str) else (row["reloadly_result"] or {})
        pl = _json.loads(row["payload"]) if isinstance(row["payload"], str) else (row["payload"] or {})
        from net365_giftcards import fetch_codes
        cards = fetch_codes(res.get("transactionId"), tries=2, wait=1.0) if res.get("transactionId") else []
    except Exception:
        logger.exception("gift-card resend failed")
        cards = []
    return jsonify({"success": True, "found": True, "reference": row["reference"],
                    "product": pl.get("product_name") or "Gift card", "cards": cards})


@wa_bp.route("/api/whatsapp/utility/resend", methods=["POST"])
@bot_required
def wa_utility_resend():
    """Show again the electricity token (or bill receipt) of the customer's own latest delivered bill.
    Linked accounts only, own transactions only, and at most one request a minute per chat."""
    data = _body()
    wa = _wa(data)
    link = _get_link(wa) if wa else None
    if not link or link.get("is_guest"):
        return jsonify({"success": False, "error": "unknown_chat"}), 404
    if time.time() - _resend_at.get(wa, 0) < 60:
        return jsonify({"success": False, "error": "slow_down"}), 429
    _resend_at[wa] = time.time()
    import json as _json
    ref = re.sub(r"[^A-Za-z0-9_\-]", "", str(data.get("reference") or ""))[:60]
    q = ("SELECT reference, reloadly_result, payload, amount, updated_at FROM transactions WHERE user_id = ? "
         "AND tx_type IN ('utility','data','tv','education','electricity','insurance') AND status = 'fulfilled'")
    args = [link["user_id"]]
    if ref:
        q += " AND reference = ?"
        args.append(ref)
    row = _conn().execute(q + " ORDER BY created_at DESC LIMIT 1", args).fetchone()
    if not row:
        return jsonify({"success": True, "found": False})
    try:
        res = _json.loads(row["reloadly_result"]) if isinstance(row["reloadly_result"], str) else (row["reloadly_result"] or {})
        pl = _json.loads(row["payload"]) if isinstance(row["payload"], str) else (row["payload"] or {})
    except Exception:
        res, pl = {}, {}
    return jsonify({"success": True, "found": True, "reference": row["reference"],
                    "biller": pl.get("biller_name") or "Bill payment", "meter": _mask_account(pl.get("subscriber_account")),
                    "amount": float(row["amount"] or 0), "token": _find_token(res)})


# --------------------------------------------------------------------------- contact memory (receipt number + email)
# A linked customer should never be asked for their number or email again. The bot asks this endpoint first and only
# prompts when nothing is on file. Order of trust for the number: one the customer saved in chat > the one on the account >
# the WhatsApp number of this very chat (Telegram has none). The email comes from the account; a customer may save a
# different one for receipts. Changing it here never changes the sign-in email of the account.
_contact_ready = False
_NG_LOCAL = re.compile(r"^0[789][01]\d{8}$")


def _ng_local(p):
    d = re.sub(r"\D", "", str(p or ""))
    if re.match(r"^234[789][01]\d{8}$", d):
        d = "0" + d[3:]
    return d if _NG_LOCAL.match(d) else ""


def _contact_schema():
    global _contact_ready
    if _contact_ready:
        return
    c = _conn()
    c.execute("CREATE TABLE IF NOT EXISTS chat_contact_prefs (user_id INTEGER PRIMARY KEY, phone TEXT, email TEXT, updated_at TEXT)")
    c.commit()
    _contact_ready = True


def _user_contact_row(uid):
    try:
        cols = {r[1] for r in _conn().execute("PRAGMA table_info(users)").fetchall()}
        want = [x for x in ("phone", "email", "full_name") if x in cols]
        if not want:
            return {}
        row = _conn().execute("SELECT %s FROM users WHERE id = ?" % ", ".join(want), (uid,)).fetchone()
        return dict(row) if row else {}
    except Exception:
        logger.exception("contact memory: could not read the account")
        return {}


def _usable_email(e):
    e = str(e or "").strip()
    return e if _EMAIL_RE.match(e) and len(e) <= 160 and not e.lower().endswith(("@chat.invalid", "@guest.invalid", ".invalid")) else ""


def _contact_for(wa, link):
    prefs = _conn().execute("SELECT phone, email FROM chat_contact_prefs WHERE user_id = ?", (link["user_id"],)).fetchone()
    prefs = dict(prefs) if prefs else {}
    acct = _user_contact_row(link["user_id"])
    phone, psrc = "", ""
    if _ng_local(prefs.get("phone")):
        phone, psrc = _ng_local(prefs.get("phone")), "saved"
    elif _ng_local(acct.get("phone")):
        phone, psrc = _ng_local(acct.get("phone")), "account"
    elif not str(wa).startswith("999") and _ng_local(wa):
        phone, psrc = _ng_local(wa), "chat"
    email, esrc = "", ""
    if _usable_email(prefs.get("email")):
        email, esrc = _usable_email(prefs.get("email")), "saved"
    elif _usable_email(acct.get("email")):
        email, esrc = _usable_email(acct.get("email")), "account"
    first = str(acct.get("full_name") or "").strip().split(" ")[0]
    return {"phone": phone, "phone_source": psrc, "phone_masked": _mask_phone(phone),
            "email": email, "email_source": esrc, "email_masked": _mask_email(email) if email else "", "first_name": first}


@wa_bp.route("/api/chat/contact/get", methods=["POST"])
@bot_required
def chat_contact_get():
    wa = _wa(_body())
    link = _get_link(wa) if wa else None
    if not link:
        return jsonify({"success": True, "linked": False})
    if link.get("is_guest"):
        return jsonify({"success": True, "linked": False, "guest": True})
    _contact_schema()
    d = _contact_for(wa, link)
    d.update({"success": True, "linked": True})
    return jsonify(d)


@wa_bp.route("/api/chat/contact/set", methods=["POST"])
@bot_required
def chat_contact_set():
    body = _body()
    wa = _wa(body)
    link = _get_link(wa) if wa else None
    if not link or link.get("is_guest"):
        return jsonify({"success": False, "error": "account_required"}), 403
    _contact_schema()
    c = _conn()
    uid = link["user_id"]
    cur = c.execute("SELECT phone, email FROM chat_contact_prefs WHERE user_id = ?", (uid,)).fetchone()
    phone = cur["phone"] if cur else None
    email = cur["email"] if cur else None
    if "phone" in body:
        if body.get("phone") in (None, ""):
            phone = None
        else:
            p = _ng_local(body.get("phone"))
            if not p:
                return jsonify({"success": False, "error": "bad_phone"}), 400
            phone = p
    if "email" in body:
        if body.get("email") in (None, ""):
            email = None
        else:
            e = _usable_email(body.get("email"))
            if not e:
                return jsonify({"success": False, "error": "bad_email"}), 400
            email = e
    c.execute("INSERT INTO chat_contact_prefs (user_id, phone, email, updated_at) VALUES (?,?,?,?) "
              "ON CONFLICT(user_id) DO UPDATE SET phone = excluded.phone, email = excluded.email, updated_at = excluded.updated_at",
              (uid, phone, email, _fmt(_now())))
    c.commit()
    d = _contact_for(wa, link)
    d.update({"success": True, "linked": True})
    return jsonify(d)


# --------------------------------------------------------------------------- invites, contacts and joining from chat
# A member can invite people from WhatsApp or Telegram. The bot never cold-messages anyone (that breaks WhatsApp and Telegram rules):
# it hands the member a ready-to-send message and link. A friend who opens the bot with a code is remembered, and the referral
# is recorded when that chat links an account, using the same rules as POST /api/referral/apply.
_INVITE_CODE_RE = re.compile(r"^[A-Za-z0-9-]{4,24}$")


def _invite_schema():
    c = _conn()
    c.execute("CREATE TABLE IF NOT EXISTS chat_referral_pending (wa_number TEXT PRIMARY KEY, code TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    c.execute("CREATE TABLE IF NOT EXISTS chat_invites (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT, phone TEXT NOT NULL, "
              "channel TEXT, joined_user_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, phone))")
    c.commit()


def _digits(p):
    return re.sub(r"\D", "", str(p or ""))


def _intl_phone(raw):
    """Nigerian numbers become 234XXXXXXXXXX; any other number must be written with its country code (+1..., 44...). Returns digits or ''."""
    ng = _ng_local(raw)
    if ng:
        return "234" + ng[1:]
    d = _digits(raw)
    return d if str(raw or "").strip().startswith("+") and 8 <= len(d) <= 15 else ""


def _referrer_by_code(code):
    code = str(code or "").strip().upper()
    if not _INVITE_CODE_RE.match(code):
        return None
    row = _conn().execute("SELECT id, full_name FROM users WHERE UPPER(TRIM(referral_code)) = ?", (code,)).fetchone()
    return dict(row) if row else None


def _member_by_phone(intl):
    """Is this number already a Net365 member? Compared on the last 10 digits."""
    tail = _digits(intl)[-10:]
    if len(tail) < 10:
        return None
    try:
        for r in _conn().execute("SELECT id, phone FROM users WHERE phone IS NOT NULL AND phone != ''").fetchall():
            if _digits(r["phone"])[-10:] == tail:
                return int(r["id"])
    except Exception:
        logger.exception("invite: member lookup failed")
    return None


def _apply_pending_referral(wa, user):
    """Called once a chat has linked a real account. Records the referral the friend arrived with; never raises."""
    try:
        _invite_schema()
        c = _conn()
        p = c.execute("SELECT code FROM chat_referral_pending WHERE wa_number = ?", (wa,)).fetchone()
        if not p:
            return
        c.execute("DELETE FROM chat_referral_pending WHERE wa_number = ?", (wa,))
        ref = _referrer_by_code(p["code"])
        uid = int(user["id"])
        if ref and int(ref["id"]) != uid and not c.execute(
                "SELECT id FROM referrals WHERE referred_id = ? AND status IN ('pending', 'completed')", (uid,)).fetchone():
            c.execute("INSERT INTO referrals (referrer_id, referred_id, status, created_at) VALUES (?, ?, 'pending', CURRENT_TIMESTAMP)", (int(ref["id"]), uid))
            me = _user_contact_row(uid)
            if me.get("phone"):
                c.execute("UPDATE chat_invites SET joined_user_id = ? WHERE user_id = ? AND joined_user_id IS NULL AND substr(phone, -10) = ?",
                          (uid, int(ref["id"]), _digits(me["phone"])[-10:]))
        c.commit()
    except Exception:
        logger.exception("could not apply the pending chat referral")


@wa_bp.route("/api/chat/invite/info", methods=["POST"])
@bot_required
def chat_invite_info():
    wa = _wa(_body())
    link = _get_link(wa) if wa else None
    if not link:
        return jsonify({"success": False, "error": "unknown_chat"}), 404
    if link.get("is_guest"):
        return jsonify({"success": True, "guest": True})
    _invite_schema()
    c = _conn()
    uid = int(link["user_id"])
    code = (c.execute("SELECT referral_code FROM users WHERE id = ?", (uid,)).fetchone() or [None])[0] if "referral_code" in {r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()} else None
    base = os.getenv("NET365_PUBLIC_URL", "").rstrip("/")
    ref = c.execute("SELECT COUNT(*) FROM referrals WHERE referrer_id = ?", (uid,)).fetchone()[0]
    done = c.execute("SELECT COUNT(*) FROM referrals WHERE referrer_id = ? AND status = 'completed'", (uid,)).fetchone()[0]
    invited = c.execute("SELECT COUNT(*) FROM chat_invites WHERE user_id = ?", (uid,)).fetchone()[0]
    first = str(_user_contact_row(uid).get("full_name") or "").strip().split(" ")[0]
    return jsonify({"success": True, "guest": False, "available": bool(code and base), "code": code, "url": f"{base}/?ref={code}" if code and base else "",
                    "first_name": first, "joined": int(ref), "rewarded": int(done), "invited": int(invited)})


@wa_bp.route("/api/chat/invite/contact", methods=["POST"])
@bot_required
def chat_invite_contact():
    body = _body()
    wa = _wa(body)
    link = _get_link(wa) if wa else None
    if not link or link.get("is_guest"):
        return jsonify({"success": False, "error": "account_required"}), 403
    name = re.sub(r"\s+", " ", str(body.get("name") or "")).strip()[:40]
    intl = _intl_phone(body.get("phone"))
    if not intl:
        return jsonify({"success": False, "error": "bad_phone"}), 400
    _invite_schema()
    c = _conn()
    uid = int(link["user_id"])
    mine = _digits(_user_contact_row(uid).get("phone"))[-10:]
    if mine and intl[-10:] == mine:
        return jsonify({"success": False, "error": "own_number"}), 400
    member = _member_by_phone(intl)
    cnt = c.execute("SELECT COUNT(*) FROM chat_invites WHERE user_id = ?", (uid,)).fetchone()[0]
    ex = c.execute("SELECT id FROM chat_invites WHERE user_id = ? AND phone = ?", (uid, intl)).fetchone()
    if not ex and cnt >= 200:
        return jsonify({"success": False, "error": "limit"}), 429
    if ex:
        c.execute("UPDATE chat_invites SET name = COALESCE(NULLIF(?, ''), name), channel = ? WHERE id = ?", (name, chat_source_for_link({"wa_number": wa}), ex["id"]))
    else:
        c.execute("INSERT INTO chat_invites (user_id, name, phone, channel) VALUES (?, ?, ?, ?)", (uid, name, intl, chat_source_for_link({"wa_number": wa})))
    c.commit()
    return jsonify({"success": True, "phone": intl, "name": name, "already_member": member is not None, "repeat": bool(ex)})


@wa_bp.route("/api/chat/invite/list", methods=["POST"])
@bot_required
def chat_invite_list():
    wa = _wa(_body())
    link = _get_link(wa) if wa else None
    if not link or link.get("is_guest"):
        return jsonify({"success": False, "error": "account_required"}), 403
    _invite_schema()
    uid = int(link["user_id"])
    items = []
    for r in _conn().execute("SELECT name, phone, joined_user_id FROM chat_invites WHERE user_id = ? ORDER BY id DESC LIMIT 30", (uid,)).fetchall():
        joined = bool(r["joined_user_id"]) or _member_by_phone(r["phone"]) is not None
        items.append({"name": r["name"] or "", "masked": _mask_phone(_ng_local("0" + r["phone"][3:]) if r["phone"].startswith("234") else "+" + r["phone"][:3] + "•••" + r["phone"][-3:]),
                      "phone": r["phone"], "joined": joined})
    return jsonify({"success": True, "items": items})


@wa_bp.route("/api/chat/referral/claim", methods=["POST"])
@bot_required
def chat_referral_claim():
    """A friend opened the bot with someone's invite code. Remember it until they link an account."""
    body = _body()
    wa = _wa(body)
    link = _get_link(wa) if wa else None
    if not wa:
        return jsonify({"success": False, "error": "unknown_chat"}), 404
    if link and not link.get("is_guest"):
        return jsonify({"success": True, "member": True})
    ref = _referrer_by_code(body.get("code"))
    if not ref:
        return jsonify({"success": False, "error": "invalid_code"}), 404
    _invite_schema()
    c = _conn()
    c.execute("INSERT INTO chat_referral_pending (wa_number, code) VALUES (?, ?) ON CONFLICT(wa_number) DO UPDATE SET code = excluded.code, created_at = CURRENT_TIMESTAMP",
              (wa, str(body.get("code")).strip().upper()))
    c.commit()
    return jsonify({"success": True, "member": False, "referrer_first_name": str(ref.get("full_name") or "").strip().split(" ")[0]})


# --------------------------------------------------------------------------- public bot insights (aggregate only)
# Feeds the public /bots page. Only totals and breakdowns: no names, numbers, emails, references or single transactions.
# Small groups (under 5) are folded into "Other" so nobody can be picked out. Cached for five minutes.
_INSIGHTS = {"at": 0.0, "data": None}
_OK_STATUS = ("success", "successful", "completed", "complete", "delivered", "paid")


def _insights_compute():
    c = _conn()
    out = {"success": True, "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "window_days": 30}
    out["links"] = {"telegram": os.getenv("TELEGRAM_BOT_USERNAME", "").strip().lstrip("@"), "whatsapp": re.sub(r"\D", "", os.getenv("WHATSAPP_BOT_NUMBER", ""))}
    try:
        links = c.execute("SELECT wa_number, COALESCE(is_guest, 0) AS g FROM whatsapp_links").fetchall()
    except Exception:
        links = []
    m = {"whatsapp": 0, "telegram": 0, "guests": 0}
    for r in links:
        if r["g"]:
            m["guests"] += 1
        else:
            m["telegram" if str(r["wa_number"]).startswith("999") else "whatsapp"] += 1
    out["members"] = {**m, "total": m["whatsapp"] + m["telegram"]}
    cols = {r[1] for r in c.execute("PRAGMA table_info(transactions)").fetchall()}
    src = next((x for x in ("source", "channel") if x in cols), None)
    when = next((x for x in ("created_at", "timestamp", "date") if x in cols), None)
    if not (src and when):
        out["orders"] = None
        return out
    status = "status" if "status" in cols else None
    kind = next((x for x in ("type", "service_type", "category") if x in cols), None)
    amt = next((x for x in ("amount", "total_amount") if x in cols), None)
    sel = f"{src} AS s, {when} AS w" + (f", {status} AS st" if status else "") + (f", {kind} AS k" if kind else "") + (f", {amt} AS a" if amt else "")
    rows = c.execute(f"SELECT {sel} FROM transactions WHERE LOWER({src}) IN ('whatsapp','telegram') AND {when} >= datetime('now', '-30 days')").fetchall()
    ch = {"whatsapp": 0, "telegram": 0}
    ok = vol = 0
    by_kind, by_hour, by_day = {}, [0] * 24, {}
    for r in rows:
        s = str(r["s"]).lower()
        ch[s] = ch.get(s, 0) + 1
        good = (str(r["st"]).lower() in _OK_STATUS) if status else True
        ok += 1 if good else 0
        if good and amt:
            try:
                vol += float(r["a"] or 0)
            except Exception:
                pass
        if kind:
            k = str(r["k"] or "other").lower()[:24]
            by_kind[k] = by_kind.get(k, 0) + 1
        w = str(r["w"] or "")
        try:
            by_hour[int(w[11:13])] += 1
        except Exception:
            pass
        by_day[w[:10]] = by_day.get(w[:10], 0) + 1
    total = len(rows)
    big = sorted(((k, v) for k, v in by_kind.items() if v >= 5), key=lambda x: -x[1])[:6]
    rest = sum(v for k, v in by_kind.items()) - sum(v for _, v in big)
    mix = [{"type": k, "count": v} for k, v in big] + ([{"type": "other", "count": rest}] if rest else [])
    days = []
    for i in range(13, -1, -1):
        d = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        days.append({"d": d, "n": by_day.get(d, 0)})
    out["orders"] = {"total": total, "success": ok, "success_rate": round(100.0 * ok / total, 1) if total else None, "volume_ngn": round(vol) if amt else None,
                     "by_channel": ch, "mix": mix, "by_hour_utc": by_hour, "daily": days}
    try:
        out["invites"] = {"saved": c.execute("SELECT COUNT(*) FROM chat_invites").fetchone()[0]}
    except Exception:
        out["invites"] = {"saved": 0}
    return out


@wa_bp.route("/api/bots/insights", methods=["GET"])
def bots_insights():
    now = time.time()
    if not _INSIGHTS["data"] or now - _INSIGHTS["at"] > 300:
        try:
            _INSIGHTS["data"] = _insights_compute()
            _INSIGHTS["at"] = now
        except Exception:
            logger.exception("bot insights failed")
            return jsonify({"success": False}), 503
    resp = make_response(jsonify(_INSIGHTS["data"]))
    resp.headers["Cache-Control"] = "public, max-age=120"
    return resp


# --------------------------------------------------------------------------- /bots page funnel (counts only)
# Answers "is the page bringing people to the bots?". Stores an event name, a source tag and a day. No IP, cookie, number or account.
# A chat that starts from a Telegram link is counted once, using a one-way hash that cannot be turned back into the chat id.
_EVENTS = ("view", "click_wa", "click_tg", "qr_view")
_SRC_RE = re.compile(r"^[a-z0-9_]{1,20}$")
_EV_HITS = {}


def _funnel_schema():
    c = _conn()
    c.execute("CREATE TABLE IF NOT EXISTS bot_page_events (id INTEGER PRIMARY KEY AUTOINCREMENT, day TEXT NOT NULL, event TEXT NOT NULL, src TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 1, "
              "UNIQUE(day, event, src))")
    c.execute("CREATE TABLE IF NOT EXISTS bot_start_seen (h TEXT PRIMARY KEY, day TEXT NOT NULL, src TEXT NOT NULL)")
    c.commit()


def _bump(event, src):
    _funnel_schema()
    c = _conn()
    day = datetime.utcnow().strftime("%Y-%m-%d")
    c.execute("INSERT INTO bot_page_events (day, event, src, n) VALUES (?, ?, ?, 1) ON CONFLICT(day, event, src) DO UPDATE SET n = n + 1", (day, event, src))
    c.commit()


def _clean_src(v):
    v = str(v or "direct").strip().lower()
    return v if _SRC_RE.match(v) else "other"


@wa_bp.route("/api/bots/event", methods=["POST"])
def bots_event():
    """Public and anonymous. Whitelisted event names only, and a small per-visitor rate limit."""
    key = (request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "?")
    now = time.time()
    hits = [x for x in _EV_HITS.get(key, []) if now - x < 60]
    if len(hits) >= 30:
        return jsonify({"success": False}), 429
    hits.append(now)
    _EV_HITS[key] = hits
    if len(_EV_HITS) > 5000:
        _EV_HITS.clear()
    body = request.get_json(silent=True) or {}
    ev = str(body.get("event") or "")
    if ev not in _EVENTS:
        return jsonify({"success": False, "error": "bad_event"}), 400
    try:
        _bump(ev, _clean_src(body.get("src")))
    except Exception:
        logger.exception("bot page event failed")
        return jsonify({"success": False}), 503
    return jsonify({"success": True})


@wa_bp.route("/api/chat/attribution", methods=["POST"])
@bot_required
def chat_attribution():
    """The bot saw a Telegram /start with a source tag from the website. Counted once per chat."""
    body = _body()
    wa = _wa(body)
    if not wa:
        return jsonify({"success": False}), 400
    src = _clean_src(body.get("src"))
    h = hashlib.sha256(("bot-start:" + wa + ":" + os.getenv("WHATSAPP_BOT_SECRET", "")).encode()).hexdigest()[:24]
    _funnel_schema()
    c = _conn()
    if c.execute("SELECT 1 FROM bot_start_seen WHERE h = ?", (h,)).fetchone():
        return jsonify({"success": True, "new": False})
    c.execute("INSERT INTO bot_start_seen (h, day, src) VALUES (?, ?, ?)", (h, datetime.utcnow().strftime("%Y-%m-%d"), src))
    c.commit()
    _bump("bot_start", src)
    return jsonify({"success": True, "new": True})


@wa_bp.route("/api/admin/chatbots/funnel", methods=["GET"])
def bots_funnel_admin():
    """Owner view: page visits, taps, Telegram starts by source, and new chats per day. Needs X-Admin-Secret (denied when unset)."""
    sec = os.getenv("ADMIN_SECRET", "")
    if not sec or not secrets.compare_digest(request.headers.get("X-Admin-Secret", ""), sec):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    _funnel_schema()
    c = _conn()
    days = 30
    rows = c.execute("SELECT day, event, src, n FROM bot_page_events WHERE day >= date('now', ?)", (f"-{days} days",)).fetchall()
    by_src, tot, daily = {}, {}, {}
    for r in rows:
        s = by_src.setdefault(r["src"], {})
        s[r["event"]] = s.get(r["event"], 0) + r["n"]
        tot[r["event"]] = tot.get(r["event"], 0) + r["n"]
        if r["event"] == "view":
            daily[r["day"]] = daily.get(r["day"], 0) + r["n"]
    views = tot.get("view", 0)
    taps = tot.get("click_wa", 0) + tot.get("click_tg", 0)
    series = [{"d": (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")} for i in range(days - 1, -1, -1)]
    for x in series:
        x["views"] = daily.get(x["d"], 0)
    # new chats per day: the number that shows whether the bots are actually growing
    cols = {r[1] for r in c.execute("PRAGMA table_info(whatsapp_links)").fetchall()}
    created = next((x for x in ("created_at", "linked_at", "updated_at") if x in cols), None)
    new_chats = None
    if created:
        new_chats = {}
        for r in c.execute(f"SELECT substr({created}, 1, 10) AS d, wa_number, COALESCE(is_guest, 0) AS g FROM whatsapp_links WHERE {created} >= date('now', ?)", (f"-{days} days",)).fetchall():
            e = new_chats.setdefault(r["d"], {"whatsapp": 0, "telegram": 0})
            e["telegram" if str(r["wa_number"]).startswith("999") else "whatsapp"] += 1
    return jsonify({"success": True, "window_days": days, "totals": {**tot, "tap_rate": round(100.0 * taps / views, 1) if views else None},
                    "by_source": by_src, "daily_views": series, "new_chats_by_day": new_chats,
                    "note": "bot_start counts Telegram chats that arrived from a tagged link. WhatsApp starts cannot be tied to the page."})


# --------------------------------------------------------------------------- app.py registration
# Add this inside ReloadlyWebApp.__init__ (next to the ads_bp block), after db.init_db():
#
#     try:
#         from net365_whatsapp import init_whatsapp_banking
#         init_whatsapp_banking(self.app, db, send_email_notification)
#     except Exception as e:
#         logger.warning(f"WhatsApp banking API not loaded: {e}")

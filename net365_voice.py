"""NET365 VOICE - customer feedback, complaint tickets, feature votes and NPS (core).

One store for every channel (Telegram, WhatsApp, later web). Owner is the Net365 user id, so a customer's tickets and votes
follow them across chats. Guests can report a failed order too.

Rules this module keeps:
* Consent domains stay separate: giving feedback never opts anyone into marketing (that lives in net365_discover).
* Ticket updates are service messages about the customer's own case, not promotions.
* No card numbers or PINs are kept: long digit runs are redacted before anything is stored, and the chat warns about it.
* Surveys are sampled and rate-limited (NPS at most every VOICE_NPS_DAYS days, only for a sampled share of linked customers).
* Nothing here can change an order, a payment or a balance.
"""
import hashlib
import logging
import os
import re
import secrets
import threading
from datetime import datetime, timezone

from flask import Blueprint, jsonify, make_response, request

import net365_whatsapp as W

log = logging.getLogger("net365.voice")
vo_bp = Blueprint("voice", __name__)
_d = {}
_ready = False

TICKET_CATEGORIES = {
    "failed": "Failed or slow transaction",
    "missing": "Payment taken, service not received",
    "wrong": "Wrong amount or wrong service",
    "login": "Login or account problem",
    "security": "Security concern",
    "support": "Poor customer service",
    "other": "Something else",
}
STATUSES = ("OPEN", "UNDER_REVIEW", "IN_PROGRESS", "RESOLVED", "CONFIRMED", "REOPENED")
ADMIN_SETTABLE = ("OPEN", "UNDER_REVIEW", "IN_PROGRESS", "RESOLVED")
STATUS_TEXT = {"OPEN": "Open", "UNDER_REVIEW": "Under review", "IN_PROGRESS": "In progress", "RESOLVED": "Resolved",
               "CONFIRMED": "Closed (you confirmed)", "REOPENED": "Reopened"}
FEATURE_STATUSES = ("idea", "considering", "most_requested", "building", "soon", "released")
CUSTOMER_VISIBLE_FEATURES = ("considering", "most_requested", "building", "soon")
SEED_FEATURES = [
    ("International money transfers", "considering"), ("Send money to friends (P2P)", "considering"),
    ("More gift cards", "considering"), ("International bill payments", "considering"),
    ("Travel bookings", "considering"), ("Shopping marketplace", "considering"),
    ("Subscription management", "considering"), ("More payment methods", "considering"),
]
APP_RATINGS = {4: "I love it", 3: "It's good", 2: "It needs improvement", 1: "I'm having difficulties"}

MAX_TICKETS_PER_DAY = 5
MAX_FEEDBACK_PER_DAY = 15
MAX_VOTES = 5


def _i(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def enabled():
    return os.getenv("VOICE_ENABLED", "true").strip().lower() in ("1", "true", "yes", "on")


def _conn():
    return _d["db"].get_db_connection()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def ensure_schema():
    global _ready
    if _ready:
        return
    c = _conn()
    stmts = [
        """CREATE TABLE IF NOT EXISTS voice_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_no TEXT UNIQUE NOT NULL, user_id INTEGER NOT NULL, channel TEXT,
            category TEXT, reference TEXT, message TEXT, status TEXT NOT NULL DEFAULT 'OPEN',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP, resolved_at TEXT, confirmed_at TEXT)""",
        "CREATE INDEX IF NOT EXISTS idx_vt_user ON voice_tickets(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_vt_status ON voice_tickets(status)",
        """CREATE TABLE IF NOT EXISTS voice_ticket_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, status TEXT, note TEXT, by_who TEXT,
            at TEXT DEFAULT CURRENT_TIMESTAMP)""",
        """CREATE TABLE IF NOT EXISTS voice_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, channel TEXT, kind TEXT, score INTEGER, text TEXT,
            sentiment TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""",
        "CREATE INDEX IF NOT EXISTS idx_vf_kind ON voice_feedback(kind, created_at)",
        """CREATE TABLE IF NOT EXISTS voice_features (
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'considering',
            note TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)""",
        """CREATE TABLE IF NOT EXISTS voice_feature_votes (
            feature_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (feature_id, user_id))""",
        """CREATE TABLE IF NOT EXISTS voice_nps (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, channel TEXT, score INTEGER, comment TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP)""",
        "CREATE TABLE IF NOT EXISTS voice_nps_asked (user_id INTEGER PRIMARY KEY, asked_at TEXT)",
    ]
    for s in stmts:
        try:
            c.execute(s)
        except Exception:
            log.exception("voice schema step failed")
            return
    try:
        if c.execute("SELECT COUNT(*) FROM voice_features").fetchone()[0] == 0:
            for title, st in SEED_FEATURES:
                c.execute("INSERT INTO voice_features (title, status) VALUES (?,?)", (title, st))
    except Exception:
        log.exception("voice seed failed")
    try:
        c.commit()
    except Exception:
        pass
    _ready = True


# --------------------------------------------------------------------------- text helpers
_LONG_DIGITS = re.compile(r"\d[\d\s\-]{10,}\d")


def clean(text, limit=1000):
    """Trim, collapse whitespace, and remove anything that looks like a card/account number (never stored)."""
    t = re.sub(r"\s+", " ", str(text or "")).strip()[:limit]
    return _LONG_DIGITS.sub("[number removed]", t)


_FEATURE_WORDS = re.compile(r"\b(i wish|please add|can you add|could you add|should add|add (a |an )?\w+|would like (you )?to|i'd like (you )?to|"
                            r"why (don't|can't|not)|introduce|launch|support for|allow me to|i want to be able|it would be (nice|great|good))\b", re.I)
_COMPLAINT_WORDS = re.compile(r"\b(fail(ed|s|ure)?|not received|didn'?t receive|never (got|received|came)|deducted|debited|slow|too long|"
                              r"error|wrong|refund|scam|stuck|pending for|problem|issue|complain|bad|worst|unable|can'?t|cannot|charged twice|double)\b", re.I)
_PRAISE_WORDS = re.compile(r"\b(love|great|excellent|amazing|awesome|thank(s| you)|good job|fast|perfect|best|happy|nice)\b", re.I)


def classify(text):
    """Rule-based (no AI, no outside call): 'feature' | 'complaint' | 'praise' | 'other'."""
    t = str(text or "")
    if _FEATURE_WORDS.search(t) and not re.search(r"\b(fail|not received|deducted|refund|scam)\w*", t, re.I):
        return "feature"
    if _COMPLAINT_WORDS.search(t):
        return "complaint"
    if _PRAISE_WORDS.search(t):
        return "praise"
    return "other"


def sentiment(text=None, score=None, scale=4):
    if score is not None:
        frac = (float(score) - 1) / max(1, scale - 1)
        return "positive" if frac >= 0.66 else ("negative" if frac <= 0.34 else "neutral")
    k = classify(text)
    return {"praise": "positive", "complaint": "negative", "feature": "neutral"}.get(k, "neutral")


# --------------------------------------------------------------------------- identity
def _who(data):
    """Bot request -> (wa, link, user_id, channel). Guests have a link too, so they can report a failed order."""
    wa = W._wa(data)
    link = W._get_link(wa) if wa else None
    if not link:
        return wa, None, None, None
    return wa, link, int(link["user_id"]), W.chat_source_for_link(link)


def _count_today(table, user_id, extra=""):
    return _conn().execute(f"SELECT COUNT(*) FROM {table} WHERE user_id = ? AND created_at >= datetime('now','-1 day') {extra}",
                           (user_id,)).fetchone()[0]


# --------------------------------------------------------------------------- tickets
def _last_reference(user_id):
    try:
        r = _conn().execute("SELECT reference FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
        return str(r[0]) if r and r[0] else None
    except Exception:
        return None


def _owns_reference(user_id, ref):
    try:
        return bool(_conn().execute("SELECT 1 FROM transactions WHERE user_id = ? AND reference = ?", (user_id, ref)).fetchone())
    except Exception:
        return False


def create_ticket(user_id, channel, category, text, reference=None):
    ensure_schema()
    if category not in TICKET_CATEGORIES:
        category = "other"
    msg = clean(text)
    if len(msg) < 5:
        return None, "too_short"
    if _count_today("voice_tickets", user_id) >= MAX_TICKETS_PER_DAY:
        return None, "too_many"
    ref = None
    if reference and _owns_reference(user_id, str(reference)[:80]):
        ref = str(reference)[:80]
    elif category in ("failed", "missing", "wrong"):
        ref = _last_reference(user_id)
    c = _conn()
    no = "NV-" + secrets.token_hex(3).upper()
    c.execute("INSERT INTO voice_tickets (ticket_no, user_id, channel, category, reference, message) VALUES (?,?,?,?,?,?)",
              (no, user_id, channel, category, ref, msg))
    tid = c.execute("SELECT id FROM voice_tickets WHERE ticket_no = ?", (no,)).fetchone()[0]
    c.execute("INSERT INTO voice_ticket_history (ticket_id, status, note, by_who) VALUES (?,?,?,?)", (tid, "OPEN", "Created by customer", "customer"))
    try:
        c.commit()
    except Exception:
        pass
    return {"ticket_no": no, "category": category, "reference": ref, "status": "OPEN"}, None


def my_tickets(user_id, limit=5):
    ensure_schema()
    rows = _conn().execute("SELECT ticket_no, category, status, reference, created_at, updated_at FROM voice_tickets "
                           "WHERE user_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit)).fetchall()
    return [{"ticket_no": r[0], "category": r[1], "category_label": TICKET_CATEGORIES.get(r[1], r[1]), "status": r[2],
             "status_label": STATUS_TEXT.get(r[2], r[2]), "reference": r[3], "created_at": r[4], "updated_at": r[5]} for r in rows]


def confirm_ticket(user_id, ticket_no, fixed):
    ensure_schema()
    c = _conn()
    row = c.execute("SELECT id, status FROM voice_tickets WHERE ticket_no = ? AND user_id = ?", (str(ticket_no)[:20], user_id)).fetchone()
    if not row or row[1] != "RESOLVED":
        return None
    new = "CONFIRMED" if fixed else "REOPENED"
    c.execute("UPDATE voice_tickets SET status = ?, updated_at = ?, confirmed_at = CASE WHEN ? = 'CONFIRMED' THEN ? ELSE confirmed_at END WHERE id = ?",
              (new, _now(), new, _now(), row[0]))
    c.execute("INSERT INTO voice_ticket_history (ticket_id, status, note, by_who) VALUES (?,?,?,?)",
              (row[0], new, "Customer says it is fixed" if fixed else "Customer says it is NOT fixed", "customer"))
    try:
        c.commit()
    except Exception:
        pass
    return new


def _notify_customer(ticket, status, note):
    """Service message about the customer's own case: chat (origin channel) and email. Never blocked by promo settings."""
    uid = ticket["user_id"]
    try:
        link = W._link_for_source(uid, ticket["channel"])
        if link:
            body = {"wa": link["wa_number"], "kind": "voice",
                    "text": f"*Update on your report {ticket['ticket_no']}*\n\nStatus: {STATUS_TEXT.get(status, status)}"
                            + (f"\n\n{note}" if note else "")
                            + ("\n\nIs it sorted now?" if status == "RESOLVED" else "")}
            if status == "RESOLVED":
                body["buttons"] = [{"id": f"TKT_FIXED_{ticket['ticket_no']}", "title": "Yes, it's fixed"},
                                   {"id": f"TKT_NOT_{ticket['ticket_no']}", "title": "Not fixed"}]
            threading.Thread(target=W._deliver_to_bot, args=(body,), daemon=True).start()
    except Exception:
        log.exception("voice: chat notice failed")
    try:
        u = _d["db"].get_user(uid) or {}
        if u.get("email") and not u.get("is_guest") and W._send_email:
            W._send_email(u["email"], f"Update on your Net365 report {ticket['ticket_no']}",
                          f"Your report {ticket['ticket_no']} is now: {STATUS_TEXT.get(status, status)}." + (f"\n\n{note}" if note else "")
                          + "\n\nQuestions? Reply to this email or contact support@net365co.com.")
    except Exception:
        log.exception("voice: email notice failed")


def set_status(ticket_no, status, note, who="admin"):
    ensure_schema()
    if status == "REOPENED":
        status = "OPEN"
    if status not in ADMIN_SETTABLE:
        return None, "bad_status"
    c = _conn()
    row = c.execute("SELECT id, user_id, channel, ticket_no, status FROM voice_tickets WHERE ticket_no = ?", (str(ticket_no)[:20],)).fetchone()
    if not row:
        return None, "not_found"
    if row["status"] == "CONFIRMED":
        return None, "closed"
    note = clean(note, 400)
    c.execute("UPDATE voice_tickets SET status = ?, updated_at = ?, resolved_at = CASE WHEN ? = 'RESOLVED' THEN ? ELSE resolved_at END WHERE id = ?",
              (status, _now(), status, _now(), row["id"]))
    c.execute("INSERT INTO voice_ticket_history (ticket_id, status, note, by_who) VALUES (?,?,?,?)", (row["id"], status, note, who))
    try:
        c.commit()
    except Exception:
        pass
    _notify_customer(dict(row), status, note)
    return {"ticket_no": row["ticket_no"], "status": status}, None


# --------------------------------------------------------------------------- feedback, suggestions, ratings
def add_feedback(user_id, channel, kind, text=None, score=None, scale=4):
    ensure_schema()
    if _count_today("voice_feedback", user_id) >= MAX_FEEDBACK_PER_DAY:
        return None
    t = clean(text, 600) if text else None
    s = sentiment(t, score, scale) if (score is not None or t) else "neutral"
    c = _conn()
    cur = c.execute("INSERT INTO voice_feedback (user_id, channel, kind, score, text, sentiment) VALUES (?,?,?,?,?,?)",
                    (user_id, channel, kind, score, t, s))
    try:
        c.commit()
    except Exception:
        pass
    return cur.lastrowid


def list_features(user_id):
    ensure_schema()
    q = ",".join("?" * len(CUSTOMER_VISIBLE_FEATURES))
    rows = _conn().execute(
        f"SELECT f.id, f.title, f.status, (SELECT COUNT(*) FROM voice_feature_votes v WHERE v.feature_id = f.id) votes, "
        f"(SELECT 1 FROM voice_feature_votes v WHERE v.feature_id = f.id AND v.user_id = ?) mine "
        f"FROM voice_features f WHERE f.status IN ({q}) ORDER BY votes DESC, f.id LIMIT 10", (user_id, *CUSTOMER_VISIBLE_FEATURES)).fetchall()
    return [{"id": r[0], "title": r[1], "status": r[2], "votes": r[3], "voted": bool(r[4])} for r in rows]


def toggle_vote(user_id, feature_id):
    ensure_schema()
    c = _conn()
    f = c.execute("SELECT status FROM voice_features WHERE id = ?", (feature_id,)).fetchone()
    if not f or f[0] not in CUSTOMER_VISIBLE_FEATURES:
        return None, "not_found"
    had = c.execute("SELECT 1 FROM voice_feature_votes WHERE feature_id = ? AND user_id = ?", (feature_id, user_id)).fetchone()
    if had:
        c.execute("DELETE FROM voice_feature_votes WHERE feature_id = ? AND user_id = ?", (feature_id, user_id))
        voted = False
    else:
        if c.execute("SELECT COUNT(*) FROM voice_feature_votes WHERE user_id = ?", (user_id,)).fetchone()[0] >= MAX_VOTES:
            return None, "vote_limit"
        c.execute("INSERT OR IGNORE INTO voice_feature_votes (feature_id, user_id) VALUES (?,?)", (feature_id, user_id))
        voted = True
    n = c.execute("SELECT COUNT(*) FROM voice_feature_votes WHERE feature_id = ?", (feature_id,)).fetchone()[0]
    try:
        c.commit()
    except Exception:
        pass
    return {"voted": voted, "votes": n}, None


def nps_due(user_id, is_guest=False):
    """True (and recorded as asked) when this customer should get the 0-10 question now."""
    ensure_schema()
    if is_guest or not enabled():
        return False
    days = _i("VOICE_NPS_DAYS", 90)
    pct = max(0, min(100, _i("VOICE_NPS_SAMPLE_PCT", 25)))
    c = _conn()
    r = c.execute("SELECT 1 FROM voice_nps_asked WHERE user_id = ? AND asked_at >= datetime('now', ?)", (user_id, f"-{days} days")).fetchone()
    if r:
        return False
    bucket = int(hashlib.sha256(f"nps|{user_id}|{datetime.now(timezone.utc).strftime('%Y-%m')}".encode()).hexdigest()[:6], 16) % 100
    if bucket >= pct:
        return False
    c.execute("INSERT OR REPLACE INTO voice_nps_asked (user_id, asked_at) VALUES (?,?)", (user_id, _now()))
    try:
        c.commit()
    except Exception:
        pass
    return True


def record_nps(user_id, channel, score, comment=None):
    ensure_schema()
    try:
        score = int(score)
    except (TypeError, ValueError):
        return False
    if not 0 <= score <= 10:
        return False
    c = _conn()
    c.execute("INSERT INTO voice_nps (user_id, channel, score, comment) VALUES (?,?,?,?)", (user_id, channel, score, clean(comment, 300) or None))
    try:
        c.commit()
    except Exception:
        pass
    return True


# --------------------------------------------------------------------------- admin numbers
def summary(days=30):
    ensure_schema()
    c = _conn()
    since = f"-{max(1, int(days))} days"
    one = lambda sql, *a: c.execute(sql, a).fetchone()[0]
    fb = {r[0]: r[1] for r in c.execute("SELECT sentiment, COUNT(*) FROM voice_feedback WHERE created_at >= datetime('now', ?) GROUP BY sentiment", (since,))}
    kinds = {r[0]: r[1] for r in c.execute("SELECT kind, COUNT(*) FROM voice_feedback WHERE created_at >= datetime('now', ?) GROUP BY kind", (since,))}
    app_avg = c.execute("SELECT ROUND(AVG(score),2), COUNT(*) FROM voice_feedback WHERE kind = 'app_rating' AND created_at >= datetime('now', ?)", (since,)).fetchone()
    nps_rows = [r[0] for r in c.execute("SELECT score FROM voice_nps WHERE created_at >= datetime('now', ?)", (since,))]
    nps = None
    if nps_rows:
        prom = sum(1 for s in nps_rows if s >= 9)
        det = sum(1 for s in nps_rows if s <= 6)
        nps = {"score": round(100 * (prom - det) / len(nps_rows)), "responses": len(nps_rows), "promoters": prom,
               "passives": len(nps_rows) - prom - det, "detractors": det}
    res_h = c.execute("SELECT AVG((julianday(resolved_at) - julianday(created_at)) * 24) FROM voice_tickets WHERE resolved_at IS NOT NULL "
                      "AND created_at >= datetime('now', ?)", (since,)).fetchone()[0]
    by_cat = [{"category": r[0], "label": TICKET_CATEGORIES.get(r[0], r[0]), "count": r[1]} for r in
              c.execute("SELECT category, COUNT(*) n FROM voice_tickets WHERE created_at >= datetime('now', ?) GROUP BY category ORDER BY n DESC", (since,))]
    by_chan = [{"channel": r[0] or "-", "tickets": r[1]} for r in
               c.execute("SELECT channel, COUNT(*) FROM voice_tickets WHERE created_at >= datetime('now', ?) GROUP BY channel", (since,))]
    feats = [{"id": r[0], "title": r[1], "status": r[2], "votes": r[3]} for r in
             c.execute("SELECT f.id, f.title, f.status, (SELECT COUNT(*) FROM voice_feature_votes v WHERE v.feature_id = f.id) n "
                       "FROM voice_features f ORDER BY n DESC, f.id LIMIT 20")]
    ideas = [{"id": r[0], "text": r[1], "channel": r[2], "created_at": r[3]} for r in
             c.execute("SELECT id, text, channel, created_at FROM voice_feedback WHERE kind = 'suggestion' ORDER BY id DESC LIMIT 20")]
    svc = c.execute("SELECT ROUND(AVG(rating),2), COUNT(rating) FROM service_ratings WHERE rating IS NOT NULL AND rated_at >= datetime('now', ?)", (since,)).fetchone() \
        if c.execute("SELECT 1 FROM sqlite_master WHERE name = 'service_ratings'").fetchone() else (None, 0)
    return {
        "days": days,
        "feedback": {"total": sum(kinds.values()), "by_kind": kinds, "positive": fb.get("positive", 0), "neutral": fb.get("neutral", 0), "negative": fb.get("negative", 0)},
        "app_rating": {"average_out_of_4": app_avg[0], "responses": app_avg[1]},
        "order_rating": {"average_out_of_3": svc[0], "responses": svc[1]},
        "nps": nps,
        "tickets": {"open": one("SELECT COUNT(*) FROM voice_tickets WHERE status IN ('OPEN','UNDER_REVIEW','IN_PROGRESS','REOPENED')"),
                    "waiting_confirmation": one("SELECT COUNT(*) FROM voice_tickets WHERE status = 'RESOLVED'"),
                    "closed": one("SELECT COUNT(*) FROM voice_tickets WHERE status = 'CONFIRMED'"),
                    "created_in_period": one("SELECT COUNT(*) FROM voice_tickets WHERE created_at >= datetime('now', ?)", since),
                    "avg_resolution_hours": round(res_h, 1) if res_h is not None else None,
                    "by_category": by_cat, "by_channel": by_chan},
        "features": feats, "recent_ideas": ideas,
    }


# --------------------------------------------------------------------------- routes
def init_voice(app, db_module, admin_required):
    _d["db"] = db_module
    ensure_schema()

    def guard():
        if not enabled():
            return jsonify({"success": False, "error": "disabled"}), 503
        return None

    # ---- customer (bot) ----
    @vo_bp.route("/api/whatsapp/voice/ticket", methods=["POST"])
    @W.bot_required
    def v_ticket():
        if guard():
            return guard()
        d = W._body()
        wa, link, uid, ch = _who(d)
        if not uid:
            return jsonify({"success": False, "error": "not_linked"}), 404
        t, err = create_ticket(uid, ch, str(d.get("category") or "other"), d.get("text"), d.get("reference"))
        if err:
            return jsonify({"success": False, "error": err}), (429 if err == "too_many" else 400)
        return jsonify({"success": True, **t, "category_label": TICKET_CATEGORIES.get(t["category"])})

    @vo_bp.route("/api/whatsapp/voice/tickets", methods=["POST"])
    @W.bot_required
    def v_tickets():
        wa, link, uid, ch = _who(W._body())
        if not uid:
            return jsonify({"success": False, "error": "not_linked"}), 404
        return jsonify({"success": True, "tickets": my_tickets(uid)})

    @vo_bp.route("/api/whatsapp/voice/ticket/confirm", methods=["POST"])
    @W.bot_required
    def v_confirm():
        d = W._body()
        wa, link, uid, ch = _who(d)
        if not uid:
            return jsonify({"success": False, "error": "not_linked"}), 404
        new = confirm_ticket(uid, d.get("ticket_no"), bool(d.get("fixed")))
        return jsonify({"success": bool(new), "status": new})

    @vo_bp.route("/api/whatsapp/voice/say", methods=["POST"])
    @W.bot_required
    def v_say():
        """Free text from the customer. Complaint -> ticket, feature wish -> suggestion, otherwise a comment."""
        if guard():
            return guard()
        d = W._body()
        wa, link, uid, ch = _who(d)
        if not uid:
            return jsonify({"success": False, "error": "not_linked"}), 404
        text = clean(d.get("text"))
        if len(text) < 5:
            return jsonify({"success": False, "error": "too_short"}), 400
        kind = classify(text)
        if kind == "complaint":
            t, err = create_ticket(uid, ch, "other", text)
            if err == "too_many":
                return jsonify({"success": False, "error": "too_many"}), 429
            return jsonify({"success": True, "kind": "complaint", **t})
        add_feedback(uid, ch, "suggestion" if kind == "feature" else "comment", text)
        return jsonify({"success": True, "kind": kind})

    @vo_bp.route("/api/whatsapp/voice/rate", methods=["POST"])
    @W.bot_required
    def v_rate():
        if guard():
            return guard()
        d = W._body()
        wa, link, uid, ch = _who(d)
        if not uid:
            return jsonify({"success": False, "error": "not_linked"}), 404
        try:
            score = int(d.get("score"))
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "bad_score"}), 400
        if score not in APP_RATINGS:
            return jsonify({"success": False, "error": "bad_score"}), 400
        fid = add_feedback(uid, ch, "app_rating", d.get("text"), score, 4)
        return jsonify({"success": bool(fid)})

    @vo_bp.route("/api/whatsapp/voice/features", methods=["POST"])
    @W.bot_required
    def v_features():
        wa, link, uid, ch = _who(W._body())
        if not uid:
            return jsonify({"success": False, "error": "not_linked"}), 404
        return jsonify({"success": True, "features": list_features(uid), "max_votes": MAX_VOTES})

    @vo_bp.route("/api/whatsapp/voice/vote", methods=["POST"])
    @W.bot_required
    def v_vote():
        d = W._body()
        wa, link, uid, ch = _who(d)
        if not uid:
            return jsonify({"success": False, "error": "not_linked"}), 404
        try:
            fid = int(d.get("feature_id"))
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "bad_feature"}), 400
        r, err = toggle_vote(uid, fid)
        if err:
            return jsonify({"success": False, "error": err}), (409 if err == "vote_limit" else 404)
        return jsonify({"success": True, **r})

    @vo_bp.route("/api/whatsapp/voice/suggest", methods=["POST"])
    @W.bot_required
    def v_suggest():
        if guard():
            return guard()
        d = W._body()
        wa, link, uid, ch = _who(d)
        if not uid:
            return jsonify({"success": False, "error": "not_linked"}), 404
        text = clean(d.get("text"), 500)
        if len(text) < 5:
            return jsonify({"success": False, "error": "too_short"}), 400
        return jsonify({"success": bool(add_feedback(uid, ch, "suggestion", text))})

    @vo_bp.route("/api/whatsapp/voice/nps/due", methods=["POST"])
    @W.bot_required
    def v_nps_due():
        wa, link, uid, ch = _who(W._body())
        if not uid:
            return jsonify({"success": True, "due": False})
        return jsonify({"success": True, "due": nps_due(uid, bool(link.get("is_guest")))})

    @vo_bp.route("/api/whatsapp/voice/nps", methods=["POST"])
    @W.bot_required
    def v_nps():
        d = W._body()
        wa, link, uid, ch = _who(d)
        if not uid:
            return jsonify({"success": False, "error": "not_linked"}), 404
        return jsonify({"success": record_nps(uid, ch, d.get("score"), d.get("comment"))})

    # ---- admin ----
    @vo_bp.route("/api/admin/voice/summary", methods=["GET"])
    @admin_required
    def a_summary():
        try:
            days = int(request.args.get("days", 30))
        except ValueError:
            days = 30
        return jsonify({"success": True, **summary(days)})

    @vo_bp.route("/api/admin/voice/tickets", methods=["GET"])
    @admin_required
    def a_tickets():
        ensure_schema()
        st = str(request.args.get("status") or "").upper()
        sql = ("SELECT t.ticket_no, t.category, t.status, t.channel, t.reference, t.message, t.created_at, t.updated_at, "
               "COALESCE(u.full_name,'') FROM voice_tickets t LEFT JOIN users u ON u.id = t.user_id ")
        args = ()
        if st in STATUSES:
            sql += "WHERE t.status = ? "
            args = (st,)
        sql += "ORDER BY t.id DESC LIMIT 100"
        rows = _conn().execute(sql, args).fetchall()
        keys = ("ticket_no", "category", "status", "channel", "reference", "message", "created_at", "updated_at", "customer")
        return jsonify({"success": True, "tickets": [dict(zip(keys, r)) for r in rows]})

    @vo_bp.route("/api/admin/voice/tickets/<ticket_no>", methods=["GET"])
    @admin_required
    def a_ticket(ticket_no):
        ensure_schema()
        r = _conn().execute("SELECT id, ticket_no, category, status, channel, reference, message, created_at FROM voice_tickets WHERE ticket_no = ?",
                            (ticket_no[:20],)).fetchone()
        if not r:
            return jsonify({"success": False, "error": "not_found"}), 404
        hist = _conn().execute("SELECT status, note, by_who, at FROM voice_ticket_history WHERE ticket_id = ? ORDER BY id", (r[0],)).fetchall()
        return jsonify({"success": True, "ticket": dict(zip(("id", "ticket_no", "category", "status", "channel", "reference", "message", "created_at"), r)),
                        "history": [dict(zip(("status", "note", "by", "at"), h)) for h in hist]})

    @vo_bp.route("/api/admin/voice/tickets/<ticket_no>/status", methods=["POST"])
    @admin_required
    def a_status(ticket_no):
        d = request.get_json(silent=True) or {}
        r, err = set_status(ticket_no, str(d.get("status") or "").upper(), d.get("note"))
        if err:
            return jsonify({"success": False, "error": err}), (404 if err == "not_found" else 400)
        return jsonify({"success": True, **r})

    @vo_bp.route("/api/admin/voice/features", methods=["POST"])
    @admin_required
    def a_feature_save():
        ensure_schema()
        d = request.get_json(silent=True) or {}
        status = str(d.get("status") or "considering")
        if status not in FEATURE_STATUSES:
            return jsonify({"success": False, "error": "bad_status"}), 400
        c = _conn()
        fid = d.get("id")
        if fid:
            row = c.execute("SELECT status FROM voice_features WHERE id = ?", (int(fid),)).fetchone()
            if not row:
                return jsonify({"success": False, "error": "not_found"}), 404
            c.execute("UPDATE voice_features SET status = ?, title = COALESCE(?, title), note = COALESCE(?, note), updated_at = ? WHERE id = ?",
                      (status, clean(d.get("title"), 120) or None, clean(d.get("note"), 300) or None, _now(), int(fid)))
            if status == "released" and row[0] != "released":  # tell the people who voted for it
                voters = [r[0] for r in c.execute("SELECT user_id FROM voice_feature_votes WHERE feature_id = ?", (int(fid),))]
                title = c.execute("SELECT title FROM voice_features WHERE id = ?", (int(fid),)).fetchone()[0]
                for uid in voters:
                    link = W._link_for_source(uid, "telegram") or W._link_for_source(uid, "whatsapp")
                    if link:
                        threading.Thread(target=W._deliver_to_bot, args=({"wa": link["wa_number"], "kind": "voice",
                                         "text": f"*You asked, we built it*\n\n\"{title}\" is now available. Thank you for voting."},), daemon=True).start()
        else:
            title = clean(d.get("title"), 120)
            if len(title) < 3:
                return jsonify({"success": False, "error": "title_needed"}), 400
            c.execute("INSERT INTO voice_features (title, status, note) VALUES (?,?,?)", (title, status, clean(d.get("note"), 300) or None))
            fid = c.execute("SELECT MAX(id) FROM voice_features").fetchone()[0]
        try:
            c.commit()
        except Exception:
            pass
        return jsonify({"success": True, "id": int(fid)})

    @vo_bp.route("/api/admin/voice/feedback", methods=["GET"])
    @admin_required
    def a_feedback():
        ensure_schema()
        kind = str(request.args.get("kind") or "")
        sql = "SELECT id, kind, score, text, sentiment, channel, created_at FROM voice_feedback "
        args = ()
        if kind:
            sql += "WHERE kind = ? "
            args = (kind,)
        rows = _conn().execute(sql + "ORDER BY id DESC LIMIT 100", args).fetchall()
        return jsonify({"success": True, "items": [dict(zip(("id", "kind", "score", "text", "sentiment", "channel", "created_at"), r)) for r in rows]})

    @vo_bp.route("/admin/voice", methods=["GET"])
    def a_page():
        here = os.path.dirname(os.path.abspath(__file__))
        try:
            html = open(os.path.join(here, "voice_admin.html"), encoding="utf-8").read()
        except OSError:
            return "voice_admin.html missing", 404
        resp = make_response(html)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    app.register_blueprint(vo_bp)
    log.info("NET365 VOICE routes registered")

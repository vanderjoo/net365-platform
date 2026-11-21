"""
Net365 service ratings: "How was it?" after a delivered order.

* Asked only AFTER a successful delivery (never on failures), and not on every order: the first delivered order,
  then at most once every RATING_COOLDOWN_DAYS (default 7). One question per order reference, ever.
* Service rating (CSAT) is a 5-point scale: 5 Excellent, 4 Good, 3 Average, 2 Poor, 1 Very poor. A 1 or 2 is treated as a
  problem and may carry a short note, which support can read. (The 0-10 recommend question is NPS and lives elsewhere.)
* Older 3-point ratings (3 great, 2 ok, 1 problem) are converted once to 5 / 3 / 1 when this module starts.
* Owner is the Net365 user id, so the web and the chat bots share one history. No phone numbers are stored here.
* Admin summary: /api/admin/ratings (by operator, country, channel, plus recent problems).

Nothing here can change an order or a payment.
"""
import logging
import os

from flask import Blueprint, jsonify, request

import net365_whatsapp as W

log = logging.getLogger(__name__)
rt_bp = Blueprint("ratings", __name__)
_d = {}
_schema_done = False

SCALE = 5
LABELS = {5: "Excellent", 4: "Good", 3: "Average", 2: "Poor", 1: "Very poor"}
PROBLEM_MAX = 2          # a rating of 1 or 2 is a service problem
LEGACY_TO_5 = {3: 5, 2: 3, 1: 1}


def label_for_average(avg):
    """Classification band for an average on the 1-5 scale."""
    try:
        a = float(avg)
    except (TypeError, ValueError):
        return None
    for floor, name in ((4.5, "Excellent"), (3.5, "Good"), (2.5, "Average"), (1.5, "Poor")):
        if a >= floor:
            return name
    return "Very poor"


def _conn():
    return _d["db"].get_db_connection()


def _cooldown():
    try:
        return max(0, int(os.getenv("RATING_COOLDOWN_DAYS", "7")))
    except ValueError:
        return 7


def _ensure():
    global _schema_done
    if _schema_done:
        return
    c = _conn()
    try:
        c.execute(
            """CREATE TABLE IF NOT EXISTS service_ratings (
                reference TEXT PRIMARY KEY, user_id INTEGER NOT NULL, channel TEXT, kind TEXT, country TEXT, operator TEXT,
                rating INTEGER, comment TEXT, asked_at TEXT DEFAULT CURRENT_TIMESTAMP, rated_at TEXT)"""
        )
        c.commit()
        # one-time move from the old 3-point scale: add a scale column, convert old answers, mark everything as 5-point
        try:
            c.execute("ALTER TABLE service_ratings ADD COLUMN scale INTEGER")
            c.commit()
        except Exception:
            pass  # column already exists
        c.execute("UPDATE service_ratings SET rating = CASE rating WHEN 3 THEN 5 WHEN 2 THEN 3 WHEN 1 THEN 1 ELSE rating END "
                  "WHERE scale IS NULL AND rating IS NOT NULL")
        c.execute("UPDATE service_ratings SET scale = 5 WHERE scale IS NULL")
        c.commit()
    except Exception:
        log.exception("ratings schema failed")
        return
    _schema_done = True


def should_ask(user_id, reference):
    """True when this order may be rated and the customer has not been asked recently."""
    if os.getenv("RATINGS_ENABLED", "true").strip().lower() not in ("1", "true", "yes", "on"):
        return False
    _ensure()
    c = _conn()
    if c.execute("SELECT 1 FROM service_ratings WHERE reference=?", (reference,)).fetchone():
        return False
    days = _cooldown()
    row = c.execute("SELECT 1 FROM service_ratings WHERE user_id=? AND asked_at >= datetime('now', ?)",
                    (user_id, f"-{days} days")).fetchone()
    return row is None


def mark_asked(user_id, reference, channel=None, kind=None, country=None, operator=None):
    """Records that the question is being asked. Returns the reference to put on the buttons, or None."""
    try:
        if not user_id or not reference or not should_ask(user_id, reference):
            return None
        c = _conn()
        c.execute("INSERT OR IGNORE INTO service_ratings (reference, user_id, channel, kind, country, operator, scale) VALUES (?,?,?,?,?,?,5)",
                  (reference, int(user_id), channel, kind, (country or "")[:2].upper() or None, (operator or "")[:60] or None))
        c.commit()
        return reference
    except Exception:
        log.exception("ratings: mark_asked failed")
        return None


def rate(user_id, reference, rating, comment=None, scale=5):
    """Stores the rating (1-5) for the owner's own order. scale=3 converts an old 3-point answer. Returns True when stored."""
    _ensure()
    try:
        rating = int(rating)
        scale = int(scale)
    except (TypeError, ValueError):
        return False
    if scale == 3:
        rating = LEGACY_TO_5.get(rating, 0)
    if rating not in LABELS or not user_id or not reference:
        return False
    c = _conn()
    row = c.execute("SELECT user_id, rating FROM service_ratings WHERE reference=?", (reference,)).fetchone()
    if not row or int(row[0]) != int(user_id):
        return False
    note = str(comment or "").strip()[:300] or None
    if row[1] is None:
        c.execute("UPDATE service_ratings SET rating=?, comment=?, rated_at=CURRENT_TIMESTAMP WHERE reference=?", (rating, note, reference))
    elif note:  # already rated: only a note may be added, the score cannot be changed
        c.execute("UPDATE service_ratings SET comment=? WHERE reference=?", (note, reference))
    else:
        return False
    c.commit()
    return True


def summary(days=30):
    _ensure()
    c = _conn()
    since = f"-{max(1, int(days))} days"

    def group(col):
        rows = c.execute(
            f"SELECT COALESCE({col},'-') k, COUNT(rating) n, ROUND(AVG(rating),2) avg, "
            f"SUM(CASE WHEN rating<={PROBLEM_MAX} THEN 1 ELSE 0 END) problems, "
            f"SUM(CASE WHEN rating>=4 THEN 1 ELSE 0 END) happy FROM service_ratings "
            f"WHERE rating IS NOT NULL AND rated_at >= datetime('now', ?) GROUP BY k ORDER BY problems DESC, n DESC", (since,)).fetchall()
        return [{"key": r[0], "ratings": r[1], "average": r[2], "band": label_for_average(r[2]),
                 "problems": r[3], "satisfied_pct": round(100.0 * (r[4] or 0) / r[1], 1) if r[1] else None} for r in rows]

    asked = c.execute("SELECT COUNT(*) FROM service_ratings WHERE asked_at >= datetime('now', ?)", (since,)).fetchone()[0]
    answered = c.execute("SELECT COUNT(*) FROM service_ratings WHERE rating IS NOT NULL AND rated_at >= datetime('now', ?)", (since,)).fetchone()[0]
    problems = c.execute(
        f"SELECT reference, channel, kind, country, operator, comment, rated_at, rating FROM service_ratings WHERE rating<={PROBLEM_MAX} "
        "AND rated_at >= datetime('now', ?) ORDER BY rated_at DESC LIMIT 50", (since,)).fetchall()
    tot = c.execute("SELECT COUNT(rating), ROUND(AVG(rating),2), SUM(CASE WHEN rating>=4 THEN 1 ELSE 0 END) FROM service_ratings "
                    "WHERE rating IS NOT NULL AND rated_at >= datetime('now', ?)", (since,)).fetchone()
    dist = {str(k): 0 for k in sorted(LABELS, reverse=True)}
    for k, n in c.execute("SELECT rating, COUNT(*) FROM service_ratings WHERE rating IS NOT NULL AND rated_at >= datetime('now', ?) "
                          "GROUP BY rating", (since,)).fetchall():
        dist[str(k)] = n
    overall = {"ratings": tot[0] or 0, "average": tot[1], "band": label_for_average(tot[1]),
               "score_pct": round(float(tot[1]) / SCALE * 100, 1) if tot[1] is not None else None,
               "satisfied_pct": round(100.0 * (tot[2] or 0) / tot[0], 1) if tot[0] else None, "distribution": dist}
    return {"days": days, "scale": {str(k): v for k, v in sorted(LABELS.items(), reverse=True)},
            "asked": asked, "answered": answered, "response_rate_pct": round(100.0 * answered / asked, 1) if asked else None,
            "overall": overall,
            "by_operator": group("operator"), "by_country": group("country"), "by_channel": group("channel"),
            "recent_problems": [dict(zip(("reference", "channel", "kind", "country", "operator", "comment", "rated_at", "rating"), p)) for p in problems]}


def init_ratings(app, db_module, login_required, admin_required):
    _d.update(db=db_module)
    _ensure()

    @rt_bp.route("/api/whatsapp/rate", methods=["POST"])
    @W.bot_required
    def rt_bot_rate():
        d = W._body()
        wa = W._wa(d)
        link = W._get_link(wa) if wa else None
        ok = rate((link or {}).get("user_id"), str(d.get("reference") or "")[:80], d.get("rating"), d.get("comment"), d.get("scale") or 5)
        return jsonify({"success": bool(ok)})

    @rt_bp.route("/api/ratings", methods=["POST"])
    @login_required
    def rt_web_rate():
        from flask import g
        d = request.get_json(silent=True) or {}
        # the existing website sends the old 1-3 answers without a scale; new clients send scale=5
        ok = rate(g.current_user_id, str(d.get("reference") or "")[:80], d.get("rating"), d.get("comment"), d.get("scale") or (3 if str(d.get("rating")) in ("1", "2", "3") else 5))
        return jsonify({"success": bool(ok)})

    @rt_bp.route("/api/admin/ratings", methods=["GET"])
    @admin_required
    def rt_admin():
        try:
            days = int(request.args.get("days", 30))
        except ValueError:
            days = 30
        return jsonify({"success": True, **summary(days)})

    app.register_blueprint(rt_bp)

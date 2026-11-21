"""
net365_rewards.py - points, levels, streaks and curated headlines for the Net365 success page.

Design rules (deliberate):
  * Points are awarded ONLY by the server, ONLY for a transaction whose status is 'fulfilled',
    and at most once per transaction (UNIQUE reference). The browser can never grant points.
  * Points have no cash value. Nothing here pays out money or airtime. Redemption is a later,
    separately switched-on step (REWARDS_REDEEM_ENABLED), so there is no liability at soft launch.
  * No randomness and no paid chance-based prizes (that would be a lottery / loot box under
    Nigerian law). Every unlock is deterministic: reach the points, get the unlock.
  * Children never get accounts. "Play" mode is a display mode on a parent's device; points
    go to the paying adult's account, and no data is collected from the child.

Wire-up (in app.py, after `app = web_app.app` and after db is ready):
    from net365_rewards import init_rewards
    init_rewards(app, db.get_db_connection, admin_required)
"""
import logging
import os
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request, session

logger = logging.getLogger(__name__)
rewards_bp = Blueprint("rewards", __name__)

_get_conn = None
_admin_required = None

POINTS_PER_100_NGN = 1          # 1 point per N100 spent on fulfilled services
POINTS_CAP_PER_TX = 50          # one big payment cannot farm points
DAILY_STREAK_BONUS = 5          # first fulfilled payment on a new consecutive day
MAX_POINTS_PER_DAY = 200        # hard daily ceiling per user

# (min_points, level, title, emoji)
LEVELS = [
    (0, 1, "Starter", "🌱"),
    (50, 2, "Explorer", "🧭"),
    (150, 3, "Power Explorer", "🚀"),
    (400, 4, "Net Ranger", "🛡️"),
    (900, 5, "Net Champion", "🏆"),
    (2000, 6, "Net Legend", "👑"),
]

# Deterministic unlocks. 'kind' is cosmetic/informational only: no cash value.
UNLOCKS = [
    (50, "Explorer badge", "🧭"),
    (150, "Gold receipt theme", "✨"),
    (400, "Early access to new Net365 features", "🛡️"),
    (900, "Priority support badge", "🏆"),
    (2000, "Legend status on your profile", "👑"),
]


def _redeem_enabled():
    return os.getenv("REWARDS_REDEEM_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")


def init_rewards_db(get_conn):
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS points_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            reference TEXT NOT NULL UNIQUE,
            points INTEGER NOT NULL,
            reason TEXT,
            day TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_points_user_day ON points_ledger(user_id, day)")
    c.execute("""
        CREATE TABLE IF NOT EXISTS points_headlines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            source TEXT,
            url TEXT,
            audience TEXT NOT NULL DEFAULT 'pro',
            active INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )""")
    conn.commit()


def _today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def level_for(total):
    cur = LEVELS[0]
    for row in LEVELS:
        if total >= row[0]:
            cur = row
    nxt = next((r for r in LEVELS if r[0] > total), None)
    return cur, nxt


def _streak(conn, user_id):
    rows = conn.execute(
        "SELECT DISTINCT day FROM points_ledger WHERE user_id = ? ORDER BY day DESC LIMIT 60", (user_id,)
    ).fetchall()
    days = [r[0] for r in rows]
    if not days:
        return 0
    today = datetime.now(timezone.utc).date()
    expect = today if days[0] == today.isoformat() else today - timedelta(days=1)
    if days[0] != expect.isoformat():
        return 0
    n = 0
    for d in days:
        if d == expect.isoformat():
            n += 1
            expect -= timedelta(days=1)
        else:
            break
    return n


def summary(user_id):
    """Everything the success page needs about one user."""
    conn = _get_conn()
    total = conn.execute(
        "SELECT COALESCE(SUM(points),0) FROM points_ledger WHERE user_id = ?", (user_id,)
    ).fetchone()[0]
    cur, nxt = level_for(total)
    span = (nxt[0] - cur[0]) if nxt else 1
    pct = 100 if not nxt else int(round((total - cur[0]) * 100 / span))
    return {
        "total": int(total),
        "level": cur[1], "level_title": cur[2], "level_emoji": cur[3],
        "next_at": nxt[0] if nxt else None,
        "next_title": nxt[2] if nxt else None,
        "progress_pct": max(0, min(100, pct)),
        "streak": _streak(conn, user_id),
        "unlocked": [{"name": n, "emoji": e, "at": p} for p, n, e in UNLOCKS if total >= p],
        "next_unlock": next(({"name": n, "emoji": e, "at": p} for p, n, e in UNLOCKS if total < p), None),
        "redeem_enabled": _redeem_enabled(),
    }


def award_for_transaction(tx):
    """Idempotently award points for a fulfilled transaction.

    Returns {"awarded": bool, "points": int, "new_level": bool, "new_unlocks": [...]}.
    Safe to call on every page load: the UNIQUE(reference) constraint makes repeats a no-op.
    """
    out = {"awarded": False, "points": 0, "new_level": False, "new_unlocks": []}
    try:
        if not tx or tx.get("status") != "fulfilled" or not tx.get("user_id"):
            return out
        user_id = int(tx["user_id"])
        ref = str(tx["reference"])
        conn = _get_conn()

        if conn.execute("SELECT 1 FROM points_ledger WHERE reference = ?", (ref,)).fetchone():
            return out

        before = summary(user_id)
        amount = float(tx.get("amount") or 0)
        if str(tx.get("currency") or "NGN").upper() == "NGN":
            pts = min(POINTS_CAP_PER_TX, int(amount // 100) * POINTS_PER_100_NGN)
        else:
            pts = 5
        pts = max(pts, 1)
        reason = "purchase"

        today = _today()
        first_today = conn.execute(
            "SELECT 1 FROM points_ledger WHERE user_id = ? AND day = ? LIMIT 1", (user_id, today)
        ).fetchone() is None
        if first_today and before["streak"] >= 1:
            pts += DAILY_STREAK_BONUS
            reason = "purchase+streak"

        used_today = conn.execute(
            "SELECT COALESCE(SUM(points),0) FROM points_ledger WHERE user_id = ? AND day = ?",
            (user_id, today),
        ).fetchone()[0]
        pts = max(0, min(pts, MAX_POINTS_PER_DAY - int(used_today)))
        if pts <= 0:
            return out

        cur = conn.execute(
            "INSERT OR IGNORE INTO points_ledger (user_id, reference, points, reason, day, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (user_id, ref, pts, reason, today, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        if cur.rowcount == 0:
            return out

        after = summary(user_id)
        out.update(awarded=True, points=pts, new_level=after["level"] > before["level"])
        out["new_unlocks"] = [u for u in after["unlocked"] if u["at"] > before["total"]]
        return out
    except Exception as e:  # rewards must never break the payment page
        logger.error(f"rewards award failed: {e}")
        return out


def get_headlines(audience="pro", limit=5):
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT id, title, source, url FROM points_headlines "
            "WHERE active = 1 AND audience IN ('all', ?) ORDER BY sort_order ASC, id DESC LIMIT ?",
            (audience, int(limit)),
        ).fetchall()
        return [{"id": r[0], "title": r[1], "source": r[2], "url": r[3]} for r in rows]
    except Exception as e:
        logger.warning(f"headlines lookup failed: {e}")
        return []


def _safe_url(u):
    u = (u or "").strip()
    return u if u.startswith("https://") else ""


@rewards_bp.get("/api/rewards/me")
def rewards_me():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"success": False, "error": "login_required"}), 401
    return jsonify({"success": True, "rewards": summary(int(uid)),
                    "levels": [{"at": a, "level": l, "title": t, "emoji": e} for a, l, t, e in LEVELS],
                    "unlocks": [{"at": a, "name": n, "emoji": e} for a, n, e in UNLOCKS]})


@rewards_bp.get("/api/rewards/headlines")
def rewards_headlines():
    aud = "kids" if request.args.get("mode") == "kids" else "pro"
    return jsonify({"success": True, "headlines": get_headlines(aud)})


def _register_admin_routes(bp, admin_required):
    @bp.get("/api/admin/rewards/headlines")
    @admin_required
    def admin_list_headlines():
        rows = _get_conn().execute(
            "SELECT id, title, source, url, audience, active, sort_order FROM points_headlines ORDER BY id DESC LIMIT 200"
        ).fetchall()
        return jsonify({"success": True, "headlines": [
            dict(zip(("id", "title", "source", "url", "audience", "active", "sort_order"), r)) for r in rows]})

    @bp.post("/api/admin/rewards/headlines")
    @admin_required
    def admin_add_headline():
        d = request.get_json(silent=True) or {}
        title = (d.get("title") or "").strip()[:140]
        if not title:
            return jsonify({"success": False, "error": "title required"}), 400
        aud = d.get("audience") if d.get("audience") in ("pro", "all", "kids") else "pro"
        conn = _get_conn()
        conn.execute(
            "INSERT INTO points_headlines (title, source, url, audience, active, sort_order, created_at) "
            "VALUES (?,?,?,?,1,?,?)",
            (title, (d.get("source") or "")[:60], _safe_url(d.get("url")), aud,
             int(d.get("sort_order") or 0), datetime.now(timezone.utc).isoformat()))
        conn.commit()
        return jsonify({"success": True})

    @bp.delete("/api/admin/rewards/headlines/<int:hid>")
    @admin_required
    def admin_delete_headline(hid):
        conn = _get_conn()
        conn.execute("DELETE FROM points_headlines WHERE id = ?", (hid,))
        conn.commit()
        return jsonify({"success": True})


def init_rewards(app, get_conn, admin_required):
    global _get_conn, _admin_required
    _get_conn, _admin_required = get_conn, admin_required
    init_rewards_db(get_conn)
    _register_admin_routes(rewards_bp, admin_required)
    app.register_blueprint(rewards_bp)
    logger.info("Rewards module ready (points are non-cash; redemption %s)",
                "ON" if _redeem_enabled() else "OFF")

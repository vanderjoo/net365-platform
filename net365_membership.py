"""NET365 membership, step 1: permanent membership number, Founders rank and badge.

Rules
  * A membership number (N365-000042) is issued once, to a customer with a verified email, in the order they qualify.
    The number IS the Founders rank. It is permanent and never reused, even if the account is later deleted.
  * Founders category comes from the rank: 1-100 Founders 100, 101-1,000 Pioneer 1,000, 1,001-10,000 Early Adopter 10,000.
    Later numbers keep their membership number but get no founders badge (edit FOUNDERS below to add more).
  * Two further fields are stored separately so they can change independently later: loyalty_tier, premium_status.
    Nothing sets them in step 1.
  * Every issue is written to membership_history.
  * On first start the existing verified customers are numbered in sign-up order (users.created_at, then id). This runs
    once and is recorded in membership_meta.

  GET  /api/membership                       the signed-in customer's membership (also inside GET /api/profile as "membership")
  GET  /api/admin/membership/summary         counts per category and how many verified customers are still waiting
  POST /api/admin/membership/backfill        {"dry_run": true|false}  number any verified customer who has none yet, in sign-up order
  GET  /api/admin/membership/history?user_id=
"""
import logging
import sqlite3
import time
from flask import g, jsonify, request

logger = logging.getLogger("net365.membership")

# (highest rank, category key, badge name, member title, badge key used by the page)
FOUNDERS = [
    (100, "FOUNDERS_100", "Founders 100", "Founding Member", "f100"),
    (1000, "FOUNDERS_1000", "Pioneer 1,000", "Pioneer Member", "f1000"),
    (10000, "FOUNDERS_10000", "Early Adopter 10,000", "Early Adopter", "f10000"),
]

_state = {}


def _conn():
    return _state["conn"]()


def _close(c):
    try:
        c.close()
    except Exception:
        pass


def _schema():
    c = _conn()
    try:
        c.execute("CREATE TABLE IF NOT EXISTS memberships (user_id INTEGER PRIMARY KEY, founders_rank INTEGER UNIQUE, founders_category TEXT, "
                  "membership_no TEXT UNIQUE, loyalty_tier TEXT, premium_status TEXT, issue_source TEXT, issued_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        c.execute("CREATE TABLE IF NOT EXISTS membership_history (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT NOT NULL, "
                  "from_value TEXT, to_value TEXT, reason TEXT, actor TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_membership_history_user ON membership_history(user_id, id)")
        c.execute("CREATE TABLE IF NOT EXISTS membership_meta (k TEXT PRIMARY KEY, v TEXT)")
        c.commit()
    finally:
        _close(c)


def number_text(rank):
    return "N365-%06d" % int(rank)


def category_for(rank):
    for top, key, label, title, badge in FOUNDERS:
        if rank <= top:
            return key
    return None


def _cat_info(key):
    for top, k, label, title, badge in FOUNDERS:
        if k == key:
            return {"key": k, "badge": badge, "label": label, "title": title, "limit": top}
    return None


def _eligible(user):
    try:
        return bool(user["email_verified"])
    except (KeyError, IndexError, TypeError):
        return False


def _issue_in(c, uid, source):
    """Inside an open write transaction. Returns the rank issued, or None when the customer already has one."""
    if c.execute("SELECT 1 FROM memberships WHERE user_id = ?", (uid,)).fetchone():
        return None
    row = c.execute("SELECT v FROM membership_meta WHERE k = 'next_rank'").fetchone()
    if row:
        rank = int(row["v"])
    else:   # first ever issue: continue after anything already in the table
        m = c.execute("SELECT COALESCE(MAX(founders_rank), 0) AS m FROM memberships").fetchone()["m"]
        rank = int(m) + 1
    c.execute("INSERT INTO membership_meta (k, v) VALUES ('next_rank', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (str(rank + 1),))
    cat = category_for(rank)
    c.execute("INSERT INTO memberships (user_id, founders_rank, founders_category, membership_no, issue_source) VALUES (?,?,?,?,?)",
              (uid, rank, cat, number_text(rank), source))
    c.execute("INSERT INTO membership_history (user_id, kind, from_value, to_value, reason, actor) VALUES (?,?,?,?,?,?)",
              (uid, "issued", "", number_text(rank) + (" " + cat if cat else ""), source, "system"))
    return rank


def _write(fn):
    """Run fn(connection) as one write transaction. Retries once if the database is busy."""
    for attempt in (0, 1):
        c = _conn()
        try:
            c.execute("BEGIN IMMEDIATE")
            out = fn(c)
            c.commit()
            return out
        except sqlite3.OperationalError as e:
            try:
                c.rollback()
            except Exception:
                pass
            if attempt == 0 and "lock" in str(e).lower():
                time.sleep(0.4)
                continue
            raise
        except Exception:
            try:
                c.rollback()
            except Exception:
                pass
            raise
        finally:
            _close(c)


def _meta(c, k):
    r = c.execute("SELECT v FROM membership_meta WHERE k = ?", (k,)).fetchone()
    return r["v"] if r else None


def waiting_users(c):
    return c.execute("SELECT u.id FROM users u LEFT JOIN memberships m ON m.user_id = u.id WHERE m.user_id IS NULL AND u.email_verified = 1 "
                     "ORDER BY COALESCE(u.created_at, ''), u.id").fetchall()


def backfill(dry_run=False):
    """Number every verified customer who has none, oldest sign-up first. Safe to repeat."""
    _schema()
    if dry_run:
        c = _conn()
        try:
            rows = waiting_users(c)
            nxt = _meta(c, "next_rank") or str(int(c.execute("SELECT COALESCE(MAX(founders_rank),0) AS m FROM memberships").fetchone()["m"]) + 1)
        finally:
            _close(c)
        return {"dry_run": True, "would_issue": len(rows), "first_number": number_text(int(nxt)), "last_number": number_text(int(nxt) + max(len(rows) - 1, 0)) if rows else None}

    def run(c):
        ids = [r["id"] for r in waiting_users(c)]
        for uid in ids:
            _issue_in(c, uid, "backfill by sign-up order")
        c.execute("INSERT INTO membership_meta (k, v) VALUES ('backfilled', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (str(int(time.time())),))
        return len(ids)
    return {"dry_run": False, "issued": _write(run)}


def ensure(uid):
    """Issue a number if this customer qualifies and has none. Never raises."""
    try:
        _schema()
        c = _conn()
        try:
            if c.execute("SELECT 1 FROM memberships WHERE user_id = ?", (uid,)).fetchone():
                return
            user = c.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
            if not user or not _eligible(user):
                return
            done = _meta(c, "backfilled")
        finally:
            _close(c)
        if not done:                 # old customers must be numbered first, in sign-up order
            backfill(False)
        else:
            _write(lambda c: _issue_in(c, uid, "email verified"))
    except Exception as e:
        logger.warning("membership issue failed for %s: %s", uid, e)


def get(uid):
    """Membership block for the profile. status: issued | pending (email not verified yet)."""
    ensure(uid)
    try:
        c = _conn()
        try:
            m = c.execute("SELECT * FROM memberships WHERE user_id = ?", (uid,)).fetchone()
        finally:
            _close(c)
    except Exception as e:
        logger.warning("membership read failed for %s: %s", uid, e)
        return None
    if not m:
        return {"status": "pending", "number": "", "rank": None, "category": None, "badge": None,
                "message": "Verify your email to receive your permanent Net365 membership number."}
    info = _cat_info(m["founders_category"])
    return {"status": "issued", "number": m["membership_no"], "rank": m["founders_rank"], "category": m["founders_category"],
            "badge": ({k: info[k] for k in ("badge", "label", "title")} if info else None),
            "loyalty_tier": m["loyalty_tier"], "premium_status": m["premium_status"],
            "since": str(m["issued_at"] or "")[:10],
            "message": ("Permanent. Your place as %s is never lost." % info["label"]) if info else "Your permanent Net365 membership number."}


def init_membership(app, get_conn, login_required, admin_required):
    _state["conn"] = get_conn
    try:
        _schema()
        c = _conn()
        try:
            done = _meta(c, "backfilled")
        finally:
            _close(c)
        if not done:
            r = backfill(False)
            logger.info("membership: numbered %s existing verified customers by sign-up order", r["issued"])
    except Exception as e:
        logger.warning("membership not ready: %s", e)

    @app.route("/api/membership", methods=["GET"])
    @login_required
    def membership_me():
        resp = jsonify({"success": True, "membership": get(g.current_user["id"])})
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.route("/api/admin/membership/summary", methods=["GET"])
    @admin_required
    def membership_summary():
        _schema()
        c = _conn()
        try:
            per = {r["founders_category"] or "NUMBER_ONLY": r["n"] for r in c.execute("SELECT founders_category, COUNT(*) AS n FROM memberships GROUP BY founders_category")}
            total = c.execute("SELECT COUNT(*) AS n FROM memberships").fetchone()["n"]
            waiting = len(waiting_users(c))
            nxt = _meta(c, "next_rank")
        finally:
            _close(c)
        return jsonify({"success": True, "issued": total, "waiting_verified": waiting, "next_number": number_text(int(nxt)) if nxt else number_text(total + 1),
                        "by_category": per, "categories": [{"key": k, "label": l, "up_to": t} for t, k, l, _, _ in FOUNDERS]})

    @app.route("/api/admin/membership/backfill", methods=["POST"])
    @admin_required
    def membership_backfill():
        dry = bool((request.get_json(silent=True) or {}).get("dry_run", True))
        try:
            return jsonify(dict(success=True, **backfill(dry)))
        except Exception as e:
            logger.exception("membership backfill failed")
            return jsonify({"success": False, "error": "Backfill failed: %s" % e}), 500

    @app.route("/api/admin/membership/history", methods=["GET"])
    @admin_required
    def membership_history():
        uid = request.args.get("user_id", type=int)
        c = _conn()
        try:
            if uid:
                rows = c.execute("SELECT * FROM membership_history WHERE user_id = ? ORDER BY id DESC LIMIT 100", (uid,)).fetchall()
            else:
                rows = c.execute("SELECT * FROM membership_history ORDER BY id DESC LIMIT 100").fetchall()
        finally:
            _close(c)
        return jsonify({"success": True, "history": [dict(r) for r in rows]})

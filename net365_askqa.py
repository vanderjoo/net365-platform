"""Ask Net365: log what customers ask, show the admin how each question was handled, and let the admin reply.

Customer side (public, rate limited):
  POST /api/ask/log        {question, outcome, shown, matched, visitor, email?}  -> {id}
  POST /api/ask/feedback   {id, visitor, helpful}     "Did this answer your question?" No re-opens the question for the admin
  POST /api/ask/contact    {id, visitor, email}       a guest leaves an email so the team can reply
  GET  /api/ask/replies?visitor=KEY                   replies from the team that this customer has not seen yet
  POST /api/ask/replies/seen {ids, visitor}

Admin (admin.html > Ask Net365):
  GET  /api/admin/ask?filter=open|wrong|all           questions with how they were handled, plus counts
  POST /api/admin/ask/<id>/answer {answer, in_app, email}   reply: shown live in the Ask box, in the notification bell, and/or by email
  POST /api/admin/ask/<id>/flag   {flag: correct | wrong | close}

outcome: action (opened a screen), answered (a scenario answer), unanswered (no reliable answer, the customer was told the team
will get back to them), other.  A question is "open" when it was unanswered or the customer said the answer did not help.
Long digit strings (phone, meter, card numbers) are masked before saving.
"""
import logging
import re
import threading
import time

from flask import jsonify, request

logger = logging.getLogger("net365.askqa")

_state = {}
_lock = threading.Lock()
_hits = {}
OUTCOMES = ("action", "answered", "unanswered", "other")
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}$")
VK = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


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
        c.execute("CREATE TABLE IF NOT EXISTS ask_questions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, visitor TEXT, email TEXT, country TEXT, "
                  "question TEXT NOT NULL, outcome TEXT, shown TEXT, matched TEXT, status TEXT DEFAULT 'auto', feedback TEXT, admin_flag TEXT, "
                  "admin_answer TEXT, answered_by TEXT, answered_at TEXT, delivered TEXT, seen INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ask_status ON ask_questions(status, id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ask_visitor ON ask_questions(visitor, seen)")
        c.commit()
    finally:
        _close(c)


def _mask(t):
    t = re.sub(r"\s+", " ", str(t or "")).strip()[:300]
    t = re.sub(r"\d{7,}", lambda m: "•" * (len(m.group(0)) - 3) + m.group(0)[-3:], t)   # phone, meter, card numbers
    return re.sub(r"[<>\u0000-\u001f]", " ", t)


def _plain(t, n):
    return re.sub(r"[<>\u0000-\u001f]", " ", re.sub(r"\s+", " ", str(t or ""))).strip()[:n]


def _limited(key, n, per):
    now = time.time()
    with _lock:
        arr = [t for t in _hits.get(key, []) if now - t < per]
        if len(arr) >= n:
            _hits[key] = arr
            return True
        arr.append(now)
        _hits[key] = arr
        if len(_hits) > 20000:
            _hits.clear()
    return False


def init_askqa(app, get_conn, admin_required, get_user=None, get_client_ip=None, notify=None, send_email=None):
    """get_user() -> the signed-in user dict or None (get_authenticated_user). notify(user_id, title, message) adds a bell notification.
    send_email(to, subject, message) sends an email. Either may be None."""
    _state["conn"] = get_conn
    try:
        _schema()
    except Exception as e:
        logger.warning("ask log tables not ready: %s", e)

    def ip():
        try:
            return (get_client_ip() if get_client_ip else request.remote_addr) or "?"
        except Exception:
            return request.remote_addr or "?"

    def me():
        try:
            u = get_user() if get_user else None
            return u if u and u.get("id") else None
        except Exception:
            return None

    def vk_of(b):
        v = str(b.get("visitor") or request.args.get("visitor") or "")
        return v if VK.match(v) else ""

    def owns(row, user, vk):
        return bool(row) and ((user and row["user_id"] == user.get("id")) or (vk and row["visitor"] == vk))

    @app.route("/api/ask/log", methods=["POST"])
    def ask_log():
        if _limited("log:" + ip(), 30, 60):
            return jsonify({"success": False}), 429
        b = request.get_json(silent=True) or {}
        q = _mask(b.get("question"))
        if len(q) < 2:
            return jsonify({"success": False}), 400
        outcome = b.get("outcome") if b.get("outcome") in OUTCOMES else "other"
        user, vk = me(), vk_of(b)
        email = str(b.get("email") or "").strip()[:254]
        email = email if EMAIL.match(email) else ""
        status = "open" if outcome == "unanswered" else "auto"
        _schema()
        c = _conn()
        try:
            cur = c.execute("INSERT INTO ask_questions (user_id, visitor, email, country, question, outcome, shown, matched, status) VALUES (?,?,?,?,?,?,?,?,?)",
                            (user.get("id") if user else None, vk, email, str(b.get("country") or "")[:2].upper(), q, outcome, _plain(b.get("shown"), 200),
                             _plain(b.get("matched"), 40), status))
            c.commit()
            qid = cur.lastrowid
        finally:
            _close(c)
        return jsonify({"success": True, "id": qid, "signed_in": bool(user)})

    def load(c, qid):
        return c.execute("SELECT * FROM ask_questions WHERE id = ?", (qid,)).fetchone()

    @app.route("/api/ask/feedback", methods=["POST"])
    def ask_feedback():
        if _limited("fb:" + ip(), 30, 60):
            return jsonify({"success": False}), 429
        b = request.get_json(silent=True) or {}
        user, vk = me(), vk_of(b)
        c = _conn()
        try:
            row = load(c, int(b.get("id") or 0))
            if not owns(row, user, vk):
                return jsonify({"success": False}), 404
            good = bool(b.get("helpful"))
            c.execute("UPDATE ask_questions SET feedback = ?, status = CASE WHEN ? THEN status ELSE 'open' END WHERE id = ?", ("up" if good else "down", 1 if good else 0, row["id"]))
            c.commit()
        finally:
            _close(c)
        return jsonify({"success": True})

    @app.route("/api/ask/contact", methods=["POST"])
    def ask_contact():
        if _limited("ct:" + ip(), 10, 60):
            return jsonify({"success": False}), 429
        b = request.get_json(silent=True) or {}
        email = str(b.get("email") or "").strip()[:254]
        if not EMAIL.match(email):
            return jsonify({"success": False, "error": "Enter a valid email address."}), 400
        user, vk = me(), vk_of(b)
        c = _conn()
        try:
            row = load(c, int(b.get("id") or 0))
            if not owns(row, user, vk):
                return jsonify({"success": False}), 404
            c.execute("UPDATE ask_questions SET email = ? WHERE id = ?", (email, row["id"]))
            c.commit()
        finally:
            _close(c)
        return jsonify({"success": True})

    @app.route("/api/ask/replies", methods=["GET"])
    def ask_replies():
        user, vk = me(), vk_of({})
        if not user and not vk:
            return jsonify({"success": True, "replies": []})
        c = _conn()
        try:
            rows = c.execute("SELECT id, question, admin_answer, answered_at FROM ask_questions WHERE seen = 0 AND admin_answer IS NOT NULL AND admin_answer != '' "
                             "AND ((? IS NOT NULL AND user_id = ?) OR (? != '' AND visitor = ?)) ORDER BY id LIMIT 5",
                             (user.get("id") if user else None, user.get("id") if user else None, vk, vk)).fetchall()
        finally:
            _close(c)
        resp = jsonify({"success": True, "replies": [dict(r) for r in rows]})
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.route("/api/ask/replies/seen", methods=["POST"])
    def ask_replies_seen():
        b = request.get_json(silent=True) or {}
        user, vk = me(), vk_of(b)
        ids = [int(i) for i in (b.get("ids") or []) if str(i).isdigit()][:20]
        c = _conn()
        try:
            for i in ids:
                row = load(c, i)
                if owns(row, user, vk):
                    c.execute("UPDATE ask_questions SET seen = 1 WHERE id = ?", (i,))
            c.commit()
        finally:
            _close(c)
        return jsonify({"success": True})

    # ------------------------------------------------------------------ admin
    @app.route("/api/admin/ask", methods=["GET"])
    @admin_required
    def ask_admin_list():
        flt = request.args.get("filter", "open")
        where = {"open": "status = 'open'", "wrong": "(admin_flag = 'wrong' OR feedback = 'down')", "all": "1=1"}.get(flt, "status = 'open'")
        _schema()
        c = _conn()
        try:
            rows = c.execute("SELECT q.*, u.email AS user_email, u.full_name AS user_name FROM ask_questions q LEFT JOIN users u ON u.id = q.user_id "
                             "WHERE " + where.replace("status", "q.status").replace("admin_flag", "q.admin_flag").replace("feedback", "q.feedback") +
                             " ORDER BY q.id DESC LIMIT 200").fetchall()
            n = lambda w: c.execute("SELECT COUNT(*) AS n FROM ask_questions WHERE " + w).fetchone()["n"]
            counts = {"total": n("1=1"), "open": n("status = 'open'"), "unanswered": n("outcome = 'unanswered'"), "answered": n("outcome = 'answered'"),
                      "thumbs_down": n("feedback = 'down'"), "thumbs_up": n("feedback = 'up'"), "flagged_wrong": n("admin_flag = 'wrong'")}
        finally:
            _close(c)
        out = []
        for r in rows:
            d = dict(r)
            d["contact"] = d.get("user_email") or d.get("email") or ""
            d["who"] = d.get("user_name") or ("Guest" if not d.get("user_id") else "Customer %s" % d["user_id"])
            d["online_possible"] = bool(d.get("user_id") or d.get("visitor"))
            for k in ("visitor", "user_email"):
                d.pop(k, None)
            out.append(d)
        return jsonify({"success": True, "counts": counts, "questions": out})

    @app.route("/api/admin/ask/<int:qid>/answer", methods=["POST"])
    @admin_required
    def ask_admin_answer(qid):
        b = request.get_json(silent=True) or {}
        ans = re.sub(r"[<>]", " ", str(b.get("answer") or "")).strip()[:1500]
        if len(ans) < 2:
            return jsonify({"success": False, "error": "Write the answer first."}), 400
        want_app, want_mail = bool(b.get("in_app", True)), bool(b.get("email", True))
        c = _conn()
        try:
            row = c.execute("SELECT q.*, u.email AS user_email FROM ask_questions q LEFT JOIN users u ON u.id = q.user_id WHERE q.id = ?", (qid,)).fetchone()
            if not row:
                return jsonify({"success": False, "error": "Question not found."}), 404
            delivered = []
            if want_app and (row["user_id"] or row["visitor"]):
                delivered.append("on the page")     # shown in the Ask box the next time (or while) they are online
            if want_app and row["user_id"] and notify:
                try:
                    notify(row["user_id"], "Reply from Net365", ans)
                    delivered.append("bell")
                except Exception as e:
                    logger.warning("ask reply notification failed: %s", e)
            to = row["user_email"] or row["email"]
            if want_mail and to and send_email:
                try:
                    send_email(to, "Your question to Net365", "You asked: %s\n\n%s\n\nNet365" % (row["question"], ans))
                    delivered.append("email")
                except Exception as e:
                    logger.warning("ask reply email failed: %s", e)
            c.execute("UPDATE ask_questions SET admin_answer = ?, answered_by = 'admin', answered_at = CURRENT_TIMESTAMP, status = 'answered', delivered = ?, seen = 0 WHERE id = ?",
                      (ans, ", ".join(delivered), qid))
            c.commit()
        finally:
            _close(c)
        if not delivered:
            return jsonify({"success": True, "delivered": [], "warning": "Saved, but there was no way to reach this customer (a guest who left no email and has no page open)."})
        return jsonify({"success": True, "delivered": delivered})

    @app.route("/api/admin/ask/<int:qid>/flag", methods=["POST"])
    @admin_required
    def ask_admin_flag(qid):
        flag = (request.get_json(silent=True) or {}).get("flag")
        if flag not in ("correct", "wrong", "close"):
            return jsonify({"success": False}), 400
        c = _conn()
        try:
            if flag == "close":
                c.execute("UPDATE ask_questions SET status = 'closed' WHERE id = ?", (qid,))
            elif flag == "wrong":
                c.execute("UPDATE ask_questions SET admin_flag = 'wrong', status = CASE WHEN status IN ('answered','closed') THEN status ELSE 'open' END WHERE id = ?", (qid,))
            else:
                c.execute("UPDATE ask_questions SET admin_flag = 'correct', status = CASE WHEN status = 'open' AND outcome != 'unanswered' THEN 'closed' ELSE status END WHERE id = ?", (qid,))
            c.commit()
        finally:
            _close(c)
        return jsonify({"success": True})

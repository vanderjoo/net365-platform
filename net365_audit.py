"""
Net365 audit trail: who did what, when, from where, and whether it worked.

Install (app.py, inside ReloadlyWebApp.__init__ right after db.init_db()):

    from net365_audit import init_audit
    init_audit(self.app, db, admin_required, get_client_ip, get_authenticated_user)

What it records AUTOMATICALLY (no route edits): sign-up, login (and failed login), logout, password change/reset,
email verify/resend, Google sign-in, every admin write action, payments/checkouts, wallet, schedules, bulk jobs,
chat link / unlink / freeze, PIN failures, support/chat messages, webhooks.
What needs one extra line where the event happens inside a function (SMS code sent, code entered...):

    from net365_audit import audit
    audit("sms_code_sent", actor_type="user", actor_id=uid, target=masked_phone, details={"provider": "termii"})

SECURITY RULES BUILT IN
  * Passwords, PINs, OTP codes, tokens, card data and secrets are NEVER stored. Events say "code verified" / "code wrong".
  * Emails and phones are masked in the log.
  * The table is append-only from the app, and each row carries a hash of the previous row so tampering is detectable
    (GET /api/admin/audit/verify).
  * Logging can never break a request: every error is swallowed.
"""
import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime

from flask import g, jsonify, request

logger = logging.getLogger("net365.audit")

_db = None
_lock = threading.Lock()
_get_user = None
_get_ip = None
LOG_ADMIN_VIEWS = os.getenv("AUDIT_LOG_ADMIN_VIEWS", "false").strip().lower() in ("1", "true", "yes", "on")

SENSITIVE = re.compile(r"pass|pwd|pin$|^pin|otp|^code$|token|secret|card|cvv|authorization|api_?key|signature|hash", re.I)
EMAIL_RE = re.compile(r"^([^@\s])[^@\s]*(@.+)$")


def mask_email(v):
    m = EMAIL_RE.match(str(v or "").strip())
    return f"{m.group(1)}***{m.group(2)}" if m else str(v or "")[:40]


def mask_phone(v):
    d = re.sub(r"\D", "", str(v or ""))
    return (d[:3] + "****" + d[-3:]) if len(d) >= 8 else ("***" + d[-2:] if d else "")


def scrub(obj, depth=0):
    """Copy of a dict that is safe to store: secrets dropped, emails/phones masked, values shortened."""
    if depth > 3:
        return "..."
    if isinstance(obj, dict):
        out = {}
        for k, v in list(obj.items())[:40]:
            ks = str(k)
            if SENSITIVE.search(ks):
                out[ks] = "[hidden]"
            elif re.search(r"email", ks, re.I):
                out[ks] = mask_email(v)
            elif re.search(r"phone|msisdn|^wa$|mobile|number", ks, re.I):
                out[ks] = mask_phone(v)
            else:
                out[ks] = scrub(v, depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        return [scrub(x, depth + 1) for x in list(obj)[:10]]
    if isinstance(obj, (int, float, bool)) or obj is None:
        return obj
    return str(obj)[:160]


# (path regex, methods, action, category, log only failures?)
RULES = [
    (r"^/api/auth/register$", "POST", "signup", "account", False),
    (r"^/api/auth/login$", "POST", "login", "auth", False),
    (r"^/api/auth/logout$", "POST", "logout", "auth", False),
    (r"^/api/auth/change-password$", "POST", "password_changed", "auth", False),
    (r"^/api/auth/forgot-password$", "POST", "password_reset_requested", "auth", False),
    (r"^/api/auth/reset-password$", "POST", "password_reset_done", "auth", False),
    (r"^/api/auth/verify-email$", "POST", "email_code_entered", "verification", False),
    (r"^/api/auth/resend-otp$", "POST", "email_code_sent", "verification", False),
    (r"^/api/auth/google/(login|callback)$", "GET", "google_signin", "auth", False),
    # phone / identity module (SMS and WhatsApp codes). Exact paths depend on net365_identity.py; this catches the usual ones.
    (r"^/api/(identity|profile|phone)/.*(send|request|start).*$", "POST", "sms_code_sent", "verification", False),
    (r"^/api/(identity|profile|phone)/.*(verify|confirm|check).*$", "POST", "sms_code_entered", "verification", False),
    (r"^/api/payment/(init)$", "POST", "payment_started", "payment", False),
    (r"^/api/(wallet|cart|services|electricity|insurance|utilities)/.*(fund|transfer|checkout|pay|utility)$", "POST", "checkout", "payment", False),
    (r"^/api/scheduler/schedules.*$", "POST|PUT|DELETE", "schedule_changed", "schedule", False),
    (r"^/api/bulk/.*$", "POST", "bulk_recharge", "payment", False),
    (r"^/api/user/contacts.*$", "POST|DELETE", "contact_changed", "account", False),
    (r"^/api/settings$", "PUT", "settings_changed", "account", False),
    (r"^/api/receipt-ads/campaigns.*$", "POST", "ad_campaign", "ads", False),
    (r"^/api/chat/messages$", "POST", "chat_message_sent", "support", False),
    (r"^/webhooks/.*$", "POST", "webhook_received", "system", False),
    (r"^/api/whatsapp/link/(start|confirm)$", "POST", "chat_link_step", "chat", False),
    (r"^/api/whatsapp/(unlink|freeze|unfreeze|google/confirm)$", "POST", "chat_security_action", "chat", False),
    (r"^/api/whatsapp/auth$", "POST", "chat_pin_check", "chat", True),
    (r"^/api/whatsapp/guest/start$", "POST", "chat_guest_started", "chat", False),
    (r"^/api/whatsapp/voice/(ticket|reply)$", "POST", "support_ticket_activity", "support", False),
    # any admin write; specific names come from the path itself (see _admin_action)
    (r"^/api/admin/.*$", "POST|PUT|PATCH|DELETE", "admin_action", "admin", False),
    (r"^/api/(debug|balance|utilities/transactions).*$", "GET", "admin_view", "admin", False),
]
_COMPILED = [(re.compile(p), set(m.split("|")), a, c, f) for p, m, a, c, f in RULES]
NOISY_ADMIN_GET = re.compile(r"/api/admin/(chat|audit|visitors|alerts|adcredits/overview)|/api/admin/.*/(stats|summary)$")


def _admin_action(path, method):
    """Readable action name from an admin path, e.g. /api/admin/users/12/block -> admin_user_block."""
    p = re.sub(r"/\d+", "/<id>", path.replace("/api/admin/", "", 1)).strip("/")
    parts = [x for x in p.split("/") if x and x != "<id>"]
    return "admin_" + "_".join(parts[:3]).replace("-", "_") + ("_" + method.lower() if method == "DELETE" else "")


def _conn():
    return _db.get_db_connection()


def init_audit(app, db_module, admin_required, get_client_ip, get_authenticated_user):
    global _db, _get_user, _get_ip
    _db, _get_user, _get_ip = db_module, get_authenticated_user, get_client_ip
    _ensure_schema()

    @app.before_request
    def _audit_before():
        try:
            g._audit_rule = None
            path, method = request.path, request.method
            for rx, methods, action, cat, fail_only in _COMPILED:
                if method in methods and rx.match(path):
                    if cat == "admin" and method == "GET" and (not LOG_ADMIN_VIEWS or NOISY_ADMIN_GET.search(path)):
                        return
                    g._audit_rule = (action, cat, fail_only)
                    break
            if g._audit_rule:
                g._audit_actor = _resolve_actor()
        except Exception:
            g._audit_rule = None

    @app.after_request
    def _audit_after(resp):
        try:
            rule = getattr(g, "_audit_rule", None)
            if not rule:
                return resp
            action, cat, fail_only = rule
            code = resp.status_code
            if fail_only and code < 400:
                return resp
            if cat == "admin" and action == "admin_action":
                action = _admin_action(request.path, request.method)
            actor = getattr(g, "_audit_actor", None) or {"type": "anonymous", "id": None, "label": ""}
            body = {}
            if request.mimetype == "application/json":
                body = request.get_json(silent=True) or {}
            if actor["type"] == "anonymous" and cat in ("auth", "account"):   # login/signup: take the user from the response
                rj = resp.get_json(silent=True) if resp.mimetype == "application/json" else None
                u = (rj or {}).get("user") or {}
                if u.get("id"):
                    actor = {"type": "user", "id": u.get("id"), "label": mask_email(u.get("email"))}
                elif isinstance(body, dict) and body.get("email"):
                    actor = {"type": "anonymous", "id": None, "label": mask_email(body.get("email"))}
            if cat == "chat" and isinstance(body, dict) and body.get("wa"):
                wa = str(body["wa"])
                actor = {"type": "chat", "id": None, "label": ("telegram " if wa.startswith("999") else "whatsapp ") + "..." + wa[-4:]}
            if cat == "admin":
                actor = _admin_actor(actor, code)
                if code in (401, 403):
                    action = "admin_denied"
            if action == "login":
                action = "login" if code < 400 else "login_failed"
            if action in ("email_code_entered", "sms_code_entered"):
                action += "_ok" if code < 400 else "_wrong"
            target = ", ".join(f"{k}={v}" for k, v in (request.view_args or {}).items())[:120]
            details = scrub(body) if isinstance(body, dict) else {}
            if code >= 400:
                try:
                    details["error"] = str((resp.get_json(silent=True) or {}).get("error") or "")[:160]
                except Exception:
                    pass
            audit(action, actor_type=actor["type"], actor_id=actor["id"], actor_label=actor["label"], category=cat,
                  target=target, status=("success" if code < 400 else "denied" if code in (401, 403) else "failed"),
                  http_status=code, details=details)
        except Exception:
            logger.debug("audit after_request failed", exc_info=True)
        return resp

    @app.route("/admin_audit.js", methods=["GET"])
    def _audit_js():
        from flask import send_from_directory
        return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "admin_audit.js", mimetype="application/javascript")

    @app.route("/api/admin/audit", methods=["GET"])
    @admin_required
    def admin_audit_list():
        a = request.args
        where, params = ["1=1"], []
        for col, key in (("actor_type", "actor_type"), ("category", "category"), ("status", "status")):
            if a.get(key):
                where.append(f"{col} = ?"); params.append(a[key])
        if a.get("action"):
            where.append("action LIKE ?"); params.append(f"%{a['action']}%")
        if a.get("actor"):
            where.append("(actor_label LIKE ? OR CAST(actor_id AS TEXT) = ?)"); params += [f"%{a['actor']}%", a["actor"]]
        if a.get("ip"):
            where.append("ip = ?"); params.append(a["ip"])
        if a.get("q"):
            where.append("(target LIKE ? OR details LIKE ? OR path LIKE ?)"); params += [f"%{a['q']}%"] * 3
        if a.get("start"):
            where.append("date(ts) >= ?"); params.append(a["start"])
        if a.get("end"):
            where.append("date(ts) <= ?"); params.append(a["end"])
        limit = min(a.get("limit", 100, type=int), 500)
        offset = max(a.get("offset", 0, type=int), 0)
        c = _conn()
        try:
            total = c.execute(f"SELECT COUNT(*) FROM audit_log WHERE {' AND '.join(where)}", params).fetchone()[0]
            rows = c.execute(f"SELECT id,ts,actor_type,actor_id,actor_label,action,category,target,status,http_status,ip,user_agent,path,method,details "
                             f"FROM audit_log WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
        finally:
            c.close()
        return jsonify({"success": True, "total": total, "logs": [dict(r) for r in rows]})

    @app.route("/api/admin/audit/stats", methods=["GET"])
    @admin_required
    def admin_audit_stats():
        days = min(request.args.get("days", 7, type=int), 365)
        c = _conn()
        try:
            q = lambda sql: [dict(r) for r in c.execute(sql, (f"-{days} days",)).fetchall()]
            return jsonify({"success": True, "days": days,
                            "by_category": q("SELECT category, COUNT(*) n FROM audit_log WHERE ts >= datetime('now', ?) GROUP BY category ORDER BY n DESC"),
                            "by_status": q("SELECT status, COUNT(*) n FROM audit_log WHERE ts >= datetime('now', ?) GROUP BY status"),
                            "failed_logins": q("SELECT actor_label, ip, COUNT(*) n FROM audit_log WHERE action='login_failed' AND ts >= datetime('now', ?) GROUP BY actor_label, ip ORDER BY n DESC LIMIT 10"),
                            "wrong_codes": q("SELECT actor_label, ip, COUNT(*) n FROM audit_log WHERE action LIKE '%code_entered_wrong' AND ts >= datetime('now', ?) GROUP BY actor_label, ip ORDER BY n DESC LIMIT 10"),
                            "admin_denied": q("SELECT ip, COUNT(*) n FROM audit_log WHERE action='admin_denied' AND ts >= datetime('now', ?) GROUP BY ip ORDER BY n DESC LIMIT 10")})
        finally:
            c.close()

    @app.route("/api/admin/audit/verify", methods=["GET"])
    @admin_required
    def admin_audit_verify():
        """Walks the whole chain. ok=false and first_bad_id tell you where a row was altered or removed."""
        c = _conn()
        try:
            prev, n = "", 0
            for r in c.execute("SELECT id, prev_hash, row_hash, ts, actor_type, actor_id, action, target, status, details FROM audit_log ORDER BY id"):
                if r["prev_hash"] != prev or r["row_hash"] != _hash(prev, r["ts"], r["actor_type"], r["actor_id"], r["action"], r["target"], r["status"], r["details"]):
                    return jsonify({"success": True, "ok": False, "first_bad_id": r["id"], "checked": n})
                prev, n = r["row_hash"], n + 1
            return jsonify({"success": True, "ok": True, "checked": n})
        finally:
            c.close()

    logger.info("Audit trail enabled (admin views logged: %s)", LOG_ADMIN_VIEWS)


def _ensure_schema():
    c = _conn()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor_type TEXT, actor_id INTEGER, actor_label TEXT,
            action TEXT NOT NULL, category TEXT, target TEXT, status TEXT, http_status INTEGER, ip TEXT, user_agent TEXT,
            path TEXT, method TEXT, details TEXT, prev_hash TEXT, row_hash TEXT)""")
        for ix in ("ts", "action", "actor_id", "category", "status", "ip"):
            c.execute(f"CREATE INDEX IF NOT EXISTS idx_audit_{ix} ON audit_log({ix})")
    finally:
        c.close()


def _resolve_actor():
    try:
        u = _get_user()
        if u:
            return {"type": "user", "id": u.get("id"), "label": mask_email(u.get("email") or u.get("full_name") or "")}
    except Exception:
        pass
    return {"type": "anonymous", "id": None, "label": ""}


def _admin_actor(actor, code):
    """The admin panel uses one shared secret, so the person is whatever the panel says in X-Admin-User (self-declared)."""
    who = (request.headers.get("X-Admin-User") or "").strip()[:60]
    if code in (401, 403):
        return {"type": "anonymous", "id": None, "label": "bad admin secret"}
    return {"type": "admin", "id": None, "label": (who + " (self-declared)") if who else "admin (shared secret)"}


def _hash(prev, ts, atype, aid, action, target, status, details):
    return hashlib.sha256("|".join(str(x) for x in (prev, ts, atype, aid, action, target, status, details)).encode()).hexdigest()


def audit(action, actor_type="system", actor_id=None, actor_label="", category="", target="", status="success",
          http_status=None, details=None):
    """Write one audit row. Safe to call from anywhere; never raises."""
    try:
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        det = json.dumps(scrub(details or {}), ensure_ascii=False)[:2000]
        ip = ua = path = method = None
        try:
            ip = _get_ip() if _get_ip else None
            ua = (request.headers.get("User-Agent") or "")[:200]
            path, method = request.path, request.method
        except RuntimeError:
            pass
        with _lock:
            c = _conn()
            try:
                row = c.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
                prev = row["row_hash"] if row else ""
                h = _hash(prev, ts, actor_type, actor_id, action, str(target)[:200], status, det)
                c.execute("INSERT INTO audit_log (ts,actor_type,actor_id,actor_label,action,category,target,status,http_status,ip,user_agent,path,method,details,prev_hash,row_hash) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (ts, actor_type, actor_id, actor_label, action, category, str(target)[:200], status, http_status, ip, ua, path, method, det, prev, h))
            finally:
                c.close()
    except Exception:
        logger.debug("audit write failed", exc_info=True)

"""net365_support.py - support tickets and incidents for every channel, with an agent desk.

Customers (website, mobile app, WhatsApp, Telegram) open tickets and incidents, follow them and reply. Support agents read,
reply, assign, escalate, resolve and add private notes. Replies reach the customer in the channel they used, by email and
in the app. Every agent action and every view of a ticket is written to an audit log.

Customer, website and mobile (logged in):
  POST /api/support/tickets                 {category, message, reference?, subject?, channel?}
  GET  /api/support/tickets                 my tickets (+ how many are waiting for me)
  GET  /api/support/tickets/<no>            the conversation (private agent notes are never shown)
  POST /api/support/tickets/<no>/reply      {message}
  POST /api/support/tickets/<no>/confirm    {fixed: true|false}
Chats (bot secret): the contract the bot already speaks, so "Report a problem" and "My reports" work as they are
  POST /api/whatsapp/voice/ticket           {wa, category, text}   -> {ticket_no, category_label, reference}
  POST /api/whatsapp/voice/tickets          {wa}                   -> {tickets: [...]}
  POST /api/whatsapp/voice/ticket/confirm   {wa, ticket_no, fixed}
  POST /api/whatsapp/voice/reply            {wa, ticket_no, text}  (customer answers an agent from the chat)
Agents (X-Admin-Secret, optional X-Admin-Actor to name the agent):
  GET  /admin/support                       the agent desk (a page)
  GET  /api/admin/support/tickets|stats|tickets/<no>
  POST /api/admin/support/tickets/<no>/reply|note|status|assign|priority

Environment (all optional):
  SUPPORT_ALERT_EMAIL        where new incidents are announced (default: SUPPORT_EMAIL or support@net365co.com)
  SUPPORT_NOTIFY_ALL=false   also email every new ticket, not only incidents
  SUPPORT_MAX_PER_DAY=5      new tickets one customer may open per 24 hours
  SUPPORT_SLA_TICKET_HOURS=24  SUPPORT_SLA_INCIDENT_HOURS=2     response targets (the figures in Terms 15.4)
  SUPPORT_AUTOCLOSE_DAYS=3   a resolved ticket nobody confirmed is closed after this many days
"""
import html
import logging
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone

from flask import Blueprint, g, jsonify, make_response, request

logger = logging.getLogger(__name__)
support_bp = Blueprint("support", __name__)
_ctx = {"db": None, "email": None, "ready": False}
_lock = threading.Lock()

CATS = {"failed": "Failed or slow transaction", "missing": "Payment taken, service not received", "wrong": "Wrong amount or wrong service",
        "login": "Login or account problem", "security": "Security concern", "support": "Poor customer service", "other": "Something else"}
STATUSES = ("OPEN", "UNDER_REVIEW", "IN_PROGRESS", "WAITING_CUSTOMER", "RESOLVED", "CONFIRMED", "REOPENED")
OPEN_STATES = ("OPEN", "UNDER_REVIEW", "IN_PROGRESS", "WAITING_CUSTOMER", "REOPENED")
PRIORITIES = ("low", "normal", "high", "urgent")
CHANNELS = ("web", "mobile", "telegram", "whatsapp")
INCIDENT_WORDS = re.compile(r"(unauthori[sz]ed|did not (authori[sz]e|make|do)|didn'?t (authori[sz]e|make|do)|not me\b|hack|stolen|takeover|taken over|"
                            r"someone (logged|accessed|used)|scam|fraud|phish|lost (my )?(phone|sim)|sim swap|debited twice|double debit)", re.I)
_NO_RE = re.compile(r"^NV-[A-Z0-9]{6}$")


# ----------------------------------------------------------------------------------------------- helpers
def _conn():
    return _ctx["db"].get_db_connection()


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _s(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _env_int(name, default):
    try:
        return int(float(os.getenv(name, default)))
    except (TypeError, ValueError):
        return int(default)


def _luhn(num):
    digits = [int(d) for d in num][::-1]
    return sum(d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2) for i, d in enumerate(digits)) % 10 == 0


def clean_text(text, limit=4000):
    """Trim, drop control characters, and mask anything that looks like a card number (Terms 15.6)."""
    t = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(text or "")).strip()[:limit]

    def mask(m):
        raw = re.sub(r"\D", "", m.group(0))
        return "[card number removed]" if 13 <= len(raw) <= 19 and _luhn(raw) else m.group(0)

    return re.sub(r"\b(?:\d[ -]?){13,19}\b", mask, t)


def ensure_schema():
    if _ctx["ready"]:
        return
    with _lock:
        if _ctx["ready"]:
            return
        c = _conn()
        c.execute("""CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_no TEXT NOT NULL UNIQUE, user_id INTEGER, chat_id TEXT, channel TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'ticket', category TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'normal',
            status TEXT NOT NULL DEFAULT 'OPEN', subject TEXT, reference TEXT, assignee TEXT, sla_due_at TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_customer_at TEXT, last_agent_at TEXT, resolved_at TEXT,
            unread_customer INTEGER NOT NULL DEFAULT 0)""")
        c.execute("""CREATE TABLE IF NOT EXISTS support_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, sender TEXT NOT NULL, sender_name TEXT, body TEXT NOT NULL,
            channel TEXT, internal INTEGER NOT NULL DEFAULT 0, delivery TEXT, created_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS support_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT, action TEXT, ticket_no TEXT, detail TEXT)""")
        for ix in ("CREATE INDEX IF NOT EXISTS ix_st_user ON support_tickets(user_id, status)",
                   "CREATE INDEX IF NOT EXISTS ix_st_chat ON support_tickets(chat_id, status)",
                   "CREATE INDEX IF NOT EXISTS ix_st_status ON support_tickets(status, kind, sla_due_at)",
                   "CREATE INDEX IF NOT EXISTS ix_sm_ticket ON support_messages(ticket_id, id)"):
            c.execute(ix)
        c.commit()
        _ctx["ready"] = True


def _audit(actor, action, ticket_no="", detail=""):
    try:
        c = _conn()
        c.execute("INSERT INTO support_audit (ts, actor, action, ticket_no, detail) VALUES (?,?,?,?,?)",
                  (_s(_now()), str(actor)[:60], action, ticket_no, str(detail)[:300]))
        c.commit()
    except Exception:
        logger.exception("support audit write failed")


def _row(r):
    return dict(r) if r is not None else None


def _ticket(no):
    ensure_schema()
    return _row(_conn().execute("SELECT * FROM support_tickets WHERE ticket_no = ?", (no,)).fetchone())


def _new_no():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    for _ in range(20):
        no = "NV-" + "".join(secrets.choice(alphabet) for _ in range(6))
        if not _conn().execute("SELECT 1 FROM support_tickets WHERE ticket_no = ?", (no,)).fetchone():
            return no
    raise RuntimeError("could not allocate a ticket number")


def _add_message(ticket_id, sender, name, body, channel=None, internal=False):
    c = _conn()
    cur = c.execute("INSERT INTO support_messages (ticket_id, sender, sender_name, body, channel, internal, created_at) VALUES (?,?,?,?,?,?,?)",
                    (ticket_id, sender, name, body, channel, 1 if internal else 0, _s(_now())))
    c.commit()
    return cur.lastrowid


def _user_email(user_id):
    if not user_id:
        return None, ""
    try:
        r = _conn().execute("SELECT email, full_name FROM users WHERE id = ?", (user_id,)).fetchone()
        email = (r[0] or "").strip() if r else ""
        return (email if "@" in email and not email.endswith(".invalid") else None), (r[1] or "" if r else "")
    except Exception:
        return None, ""


def _link_user(chat_id):
    """user id linked to a chat (guest accounts included), or None when this chat has no record yet."""
    try:
        r = _conn().execute("SELECT user_id FROM whatsapp_links WHERE wa_number = ?", (chat_id,)).fetchone()
        return int(r[0]) if r else None
    except Exception:
        return None


def _latest_reference(user_id):
    """The customer's most recent order reference, so a report about an order arrives with it attached."""
    if not user_id:
        return None
    try:
        r = _conn().execute("SELECT reference FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
        return str(r[0])[:80] if r and r[0] else None
    except Exception:
        return None


def _owns(t, user_id=None, chat_id=None):
    return bool(t and ((user_id and t["user_id"] and int(t["user_id"]) == int(user_id)) or (chat_id and t["chat_id"] and t["chat_id"] == chat_id)))


def _sweep():
    """Close resolved tickets nobody confirmed after SUPPORT_AUTOCLOSE_DAYS. Cheap; runs when tickets are listed."""
    try:
        cutoff = _s(_now() - timedelta(days=max(1, _env_int("SUPPORT_AUTOCLOSE_DAYS", 3))))
        c = _conn()
        c.execute("UPDATE support_tickets SET status = 'CONFIRMED', updated_at = ? WHERE status = 'RESOLVED' AND resolved_at <= ?", (_s(_now()), cutoff))
        c.commit()
    except Exception:
        logger.exception("support sweep failed")


# ----------------------------------------------------------------------------------------------- core actions
def classify(category, text):
    if category == "security" or INCIDENT_WORDS.search(text or ""):
        return "incident", ("urgent" if category == "security" else "high")
    return "ticket", "normal"


def create_ticket(user_id, chat_id, channel, category, text, reference=None, subject=None):
    """-> (result dict, http status)."""
    ensure_schema()
    category = category if category in CATS else "other"
    body = clean_text(text)
    if len(body) < 8:
        return {"success": False, "error": "too_short", "message": "Please give a little more detail."}, 400
    key_sql, key_arg = ("user_id = ?", user_id) if user_id else ("chat_id = ?", chat_id)
    n = _conn().execute(f"SELECT COUNT(*) FROM support_tickets WHERE {key_sql} AND created_at >= ?", (key_arg, _s(_now() - timedelta(hours=24)))).fetchone()[0]
    if n >= _env_int("SUPPORT_MAX_PER_DAY", 5):
        return {"success": False, "error": "too_many"}, 429
    kind, priority = classify(category, body)
    sla_h = _env_int("SUPPORT_SLA_INCIDENT_HOURS", 2) if kind == "incident" else _env_int("SUPPORT_SLA_TICKET_HOURS", 24)
    ref = clean_text(reference, 80) if reference else _latest_reference(user_id)
    no, now = _new_no(), _now()
    c = _conn()
    cur = c.execute("INSERT INTO support_tickets (ticket_no, user_id, chat_id, channel, kind, category, priority, status, subject, reference, sla_due_at, "
                    "created_at, updated_at, last_customer_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (no, user_id, chat_id, channel, kind, category, priority, "OPEN", clean_text(subject, 120) or CATS[category], ref,
                     _s(now + timedelta(hours=sla_h)), _s(now), _s(now), _s(now)))
    c.commit()
    _add_message(cur.lastrowid, "customer", None, body, channel)
    _audit("customer", "ticket_created", no, f"{kind}/{category} via {channel}")
    threading.Thread(target=_announce_new, args=(no,), daemon=True).start()
    return {"success": True, "ticket_no": no, "kind": kind, "category": category, "category_label": CATS[category], "reference": ref or "",
            "status": "OPEN", "priority": priority}, 200


def customer_reply(t, text, channel):
    body = clean_text(text)
    if len(body) < 2:
        return {"success": False, "error": "too_short"}, 400
    if t["status"] == "CONFIRMED":
        return {"success": False, "error": "closed", "message": "This ticket is closed. Please open a new one."}, 409
    flood = _conn().execute("SELECT COUNT(*) FROM support_messages WHERE ticket_id = ? AND sender = 'customer' AND created_at >= ?",
                            (t["id"], _s(_now() - timedelta(minutes=10)))).fetchone()[0]
    if flood >= 8:
        return {"success": False, "error": "slow_down"}, 429
    _add_message(t["id"], "customer", None, body, channel)
    new_status = "REOPENED" if t["status"] == "RESOLVED" else ("IN_PROGRESS" if t["status"] == "WAITING_CUSTOMER" else t["status"])
    c = _conn()
    c.execute("UPDATE support_tickets SET status = ?, updated_at = ?, last_customer_at = ?, unread_customer = 0 WHERE id = ?",
              (new_status, _s(_now()), _s(_now()), t["id"]))
    c.commit()
    _audit("customer", "customer_reply", t["ticket_no"], channel)
    threading.Thread(target=_announce_reply, args=(t["ticket_no"],), daemon=True).start()
    return {"success": True, "status": new_status}, 200


def confirm_ticket(t, fixed):
    if t["status"] not in ("RESOLVED", "CONFIRMED", "REOPENED"):
        return {"success": False, "error": "not_resolved"}, 409
    status = "CONFIRMED" if fixed else "REOPENED"
    c = _conn()
    c.execute("UPDATE support_tickets SET status = ?, updated_at = ?, last_customer_at = ? WHERE id = ?", (status, _s(_now()), _s(_now()), t["id"]))
    c.commit()
    if not fixed:
        _add_message(t["id"], "customer", None, "The customer says this is not fixed.", None)
    _audit("customer", "confirm_fixed" if fixed else "reopen", t["ticket_no"])
    return {"success": True, "status": status}, 200


def agent_reply(t, actor, text, resolve=False, wait=False):
    body = clean_text(text)
    if not body:
        return {"success": False, "error": "empty"}, 400
    status = "RESOLVED" if resolve else ("WAITING_CUSTOMER" if wait else "IN_PROGRESS")
    c = _conn()
    c.execute("UPDATE support_tickets SET status = ?, updated_at = ?, last_agent_at = ?, unread_customer = 1, resolved_at = ?, "
              "assignee = COALESCE(assignee, ?) WHERE id = ?",
              (status, _s(_now()), _s(_now()), _s(_now()) if resolve else None, actor, t["id"]))
    c.commit()
    mid = _add_message(t["id"], "agent", actor, body, t["channel"])
    _audit(actor, "agent_reply", t["ticket_no"], "resolved" if resolve else status)
    result = deliver(t, body, resolve)
    c = _conn()
    c.execute("UPDATE support_messages SET delivery = ? WHERE id = ?", (",".join(f"{k}:{v}" for k, v in result.items()), mid))
    c.commit()
    return {"success": True, "status": status, "delivery": result}, 200


# ----------------------------------------------------------------------------------------------- delivery to the customer
def deliver(t, body, resolved=False):
    """Chat message (WhatsApp/Telegram), email and in-app notification. Each leg is independent; one failing never blocks another.
    WhatsApp only allows free-form replies for 24 hours after the customer's last message, which is why email always goes too."""
    out = {}
    no = t["ticket_no"]
    head = f"*Update on {no}*\n\n{body}"
    buttons = ([{"id": f"TKT_FIXED_{no}", "title": "Yes, it is fixed"}, {"id": f"TKT_NOT_{no}", "title": "Not fixed"}] if resolved
               else [{"id": f"SUPPORT_REPLY_{no}", "title": "Reply"}])
    if resolved:
        head += "\n\nIs this sorted now?"
    if t.get("chat_id"):
        try:
            from net365_whatsapp import _deliver_to_bot
            out["chat"] = "sent" if _deliver_to_bot({"wa": t["chat_id"], "kind": "voice", "text": head, "buttons": buttons}) else "failed"
        except Exception:
            logger.exception("support chat delivery failed")
            out["chat"] = "failed"
    email, name = _user_email(t.get("user_id"))
    if email and _ctx["email"]:
        try:
            ok = _ctx["email"](email, f"Net365 support: update on {no}",
                               f"Hello {name.split(' ')[0] if name else 'there'},\n\n{body}\n\nTicket: {no}. "
                               f"{'If this fixed it, no action is needed. If not, reply in the app or chat and we will reopen it.' if resolved else 'You can reply in the app or in your chat.'}")
            out["email"] = "sent" if ok is not False else "failed"
        except Exception:
            logger.exception("support email delivery failed")
            out["email"] = "failed"
    if t.get("user_id"):
        try:
            _ctx["db"].create_notification(t["user_id"], f"Support update: {no}", body[:200], "info")
            out["app"] = "sent"
        except Exception:
            out["app"] = "skipped"
    return out


def _announce_new(no):
    """Tell the support team. Incidents always; every ticket only when SUPPORT_NOTIFY_ALL=true."""
    try:
        t = _ticket(no)
        if not t or not _ctx["email"]:
            return
        if t["kind"] != "incident" and os.getenv("SUPPORT_NOTIFY_ALL", "false").strip().lower() not in ("1", "true", "yes", "on"):
            return
        first = _conn().execute("SELECT body FROM support_messages WHERE ticket_id = ? ORDER BY id LIMIT 1", (t["id"],)).fetchone()
        to = os.getenv("SUPPORT_ALERT_EMAIL") or os.getenv("SUPPORT_EMAIL") or "support@net365co.com"
        tag = "INCIDENT" if t["kind"] == "incident" else "Ticket"
        _ctx["email"](to, f"[{tag}] {t['ticket_no']}: {CATS.get(t['category'], t['category'])} ({t['priority']}, via {t['channel']})",
                      f"{tag} {t['ticket_no']} opened via {t['channel']}.\nCategory: {CATS.get(t['category'])}\nOrder reference: {t['reference'] or 'none'}\n"
                      f"Reply due by: {t['sla_due_at']} UTC\n\nCustomer wrote:\n{(first[0] if first else '')[:1200]}\n\nOpen the agent desk: /admin/support")
    except Exception:
        logger.exception("support announce failed")


def _announce_reply(no):
    """A customer answered: re-alert the team only for incidents (tickets show up in the desk)."""
    try:
        t = _ticket(no)
        if t and t["kind"] == "incident" and _ctx["email"]:
            to = os.getenv("SUPPORT_ALERT_EMAIL") or os.getenv("SUPPORT_EMAIL") or "support@net365co.com"
            _ctx["email"](to, f"[INCIDENT] {no}: customer replied", f"The customer replied on incident {no}. Open the agent desk: /admin/support")
    except Exception:
        logger.exception("support reply announce failed")


# ----------------------------------------------------------------------------------------------- views
def _public_ticket(t):
    return {"ticket_no": t["ticket_no"], "kind": t["kind"], "category": t["category"], "category_label": CATS.get(t["category"], t["category"]),
            "status": t["status"], "subject": t["subject"], "reference": t["reference"] or "", "channel": t["channel"],
            "created_at": t["created_at"], "updated_at": t["updated_at"], "waiting_for_you": bool(t["unread_customer"])}


def _thread(t, include_internal=False):
    sql = "SELECT id, sender, sender_name, body, channel, internal, delivery, created_at FROM support_messages WHERE ticket_id = ?"
    if not include_internal:
        sql += " AND internal = 0"
    rows = _conn().execute(sql + " ORDER BY id", (t["id"],)).fetchall()
    keys = ("id", "sender", "name", "body", "channel", "internal", "delivery", "created_at")
    out = []
    for r in rows:
        d = dict(zip(keys, tuple(r)))
        if not include_internal:
            d.pop("delivery"); d.pop("internal")
            d["name"] = "Net365 Support" if d["sender"] == "agent" else None
        out.append(d)
    return out


# ----------------------------------------------------------------------------------------------- init + routes
def init_support(app, db_module, login_required, admin_required, bot_required, send_email_fn=None):
    _ctx.update(db=db_module, email=send_email_fn)
    try:
        ensure_schema()
    except Exception as e:
        logger.warning("support tables not ready: %s", e)

    def _channel(d, default="web"):
        ch = str((d or {}).get("channel") or default).lower()
        return ch if ch in ("web", "mobile") else default

    # ---- website / mobile
    @support_bp.route("/api/support/tickets", methods=["POST"])
    @login_required
    def sup_create():
        d = request.get_json(silent=True) or {}
        res, code = create_ticket(g.current_user_id, None, _channel(d), str(d.get("category") or "other"), d.get("message"), d.get("reference"), d.get("subject"))
        return jsonify(res), code

    @support_bp.route("/api/support/tickets", methods=["GET"])
    @login_required
    def sup_list():
        ensure_schema(); _sweep()
        rows = _conn().execute("SELECT * FROM support_tickets WHERE user_id = ? ORDER BY updated_at DESC LIMIT 50", (g.current_user_id,)).fetchall()
        ts = [_public_ticket(dict(r)) for r in rows]
        return jsonify({"success": True, "tickets": ts, "open": sum(1 for x in ts if x["status"] in OPEN_STATES),
                        "waiting_for_you": sum(1 for x in ts if x["waiting_for_you"] and x["status"] != "CONFIRMED")})

    def _mine(no):
        t = _ticket(no) if _NO_RE.match(str(no)) else None
        return t if _owns(t, user_id=g.current_user_id) else None

    @support_bp.route("/api/support/tickets/<no>", methods=["GET"])
    @login_required
    def sup_get(no):
        t = _mine(no)
        if not t:
            return jsonify({"success": False, "error": "not_found"}), 404
        c = _conn(); c.execute("UPDATE support_tickets SET unread_customer = 0 WHERE id = ?", (t["id"],)); c.commit()
        return jsonify({"success": True, "ticket": _public_ticket(t), "messages": _thread(t)})

    @support_bp.route("/api/support/tickets/<no>/reply", methods=["POST"])
    @login_required
    def sup_reply(no):
        t = _mine(no)
        if not t:
            return jsonify({"success": False, "error": "not_found"}), 404
        res, code = customer_reply(t, (request.get_json(silent=True) or {}).get("message"), _channel(request.get_json(silent=True)))
        return jsonify(res), code

    @support_bp.route("/api/support/tickets/<no>/confirm", methods=["POST"])
    @login_required
    def sup_confirm(no):
        t = _mine(no)
        if not t:
            return jsonify({"success": False, "error": "not_found"}), 404
        res, code = confirm_ticket(t, bool((request.get_json(silent=True) or {}).get("fixed")))
        return jsonify(res), code

    # ---- chats: only register a route the app does not already serve, so nothing is silently shadowed
    existing = {r.rule for r in app.url_map.iter_rules()}

    def bot_route(path, **kw):
        def deco(fn):
            if path in existing:
                logger.warning("support: %s is already served elsewhere; keeping that one", path)
                return fn
            return support_bp.route(path, **kw)(bot_required(fn))
        return deco

    def _wa():
        d = request.get_json(silent=True) or {}
        wa = re.sub(r"\D", "", str(d.get("wa") or ""))
        return (wa if re.match(r"^\d{8,15}$", wa) else None), d

    @bot_route("/api/whatsapp/voice/ticket", methods=["POST"])
    def bot_ticket():
        wa, d = _wa()
        if not wa:
            return jsonify({"success": False, "error": "bad_number"}), 400
        uid = _link_user(wa)
        if uid is None:
            return jsonify({"success": False, "error": "not_linked"}), 404
        res, code = create_ticket(uid, wa, "telegram" if wa.startswith("999") else "whatsapp", str(d.get("category") or "other"), d.get("text"), d.get("reference"))
        return jsonify(res), code

    @bot_route("/api/whatsapp/voice/tickets", methods=["POST"])
    def bot_tickets():
        wa, _ = _wa()
        if not wa:
            return jsonify({"success": False, "error": "bad_number"}), 400
        uid = _link_user(wa)
        if uid is None:
            return jsonify({"success": False, "error": "not_linked"}), 404
        ensure_schema(); _sweep()
        rows = _conn().execute("SELECT * FROM support_tickets WHERE chat_id = ? OR user_id = ? ORDER BY updated_at DESC LIMIT 8", (wa, uid)).fetchall()
        return jsonify({"success": True, "tickets": [_public_ticket(dict(r)) for r in rows]})

    @bot_route("/api/whatsapp/voice/ticket/confirm", methods=["POST"])
    def bot_confirm():
        wa, d = _wa()
        t = _ticket(str(d.get("ticket_no") or "")) if wa and _NO_RE.match(str(d.get("ticket_no") or "")) else None
        if not t or not _owns(t, user_id=_link_user(wa), chat_id=wa):
            return jsonify({"success": False, "error": "not_found"}), 404
        res, code = confirm_ticket(t, bool(d.get("fixed")))
        return jsonify(res), code

    @bot_route("/api/whatsapp/voice/reply", methods=["POST"])
    def bot_reply():
        wa, d = _wa()
        no = str(d.get("ticket_no") or "")
        t = _ticket(no) if wa and _NO_RE.match(no) else None
        if not t or not _owns(t, user_id=_link_user(wa), chat_id=wa):
            return jsonify({"success": False, "error": "not_found"}), 404
        res, code = customer_reply(t, d.get("text"), "telegram" if wa.startswith("999") else "whatsapp")
        return jsonify(res), code

    # ---- agent desk
    def actor():
        return (re.sub(r"[^A-Za-z0-9 ._@-]", "", request.headers.get("X-Admin-Actor", ""))[:40] or "admin")

    @support_bp.route("/api/admin/support/tickets", methods=["GET"])
    @admin_required
    def adm_list():
        ensure_schema(); _sweep()
        where, args = [], []
        for col, key in (("status", "status"), ("kind", "kind"), ("category", "category"), ("assignee", "assignee"), ("channel", "channel")):
            v = request.args.get(key)
            if v:
                where.append(f"{col} = ?"); args.append(v)
        if request.args.get("open") == "1":
            where.append("status IN (%s)" % ",".join("?" * len(OPEN_STATES))); args += list(OPEN_STATES)
        q = (request.args.get("q") or "").strip()
        if q:
            where.append("(ticket_no LIKE ? OR reference LIKE ? OR subject LIKE ?)"); args += [f"%{q[:40]}%"] * 3
        limit = max(1, min(200, request.args.get("limit", 100, type=int)))
        rows = _conn().execute("SELECT * FROM support_tickets" + (" WHERE " + " AND ".join(where) if where else "") +
                               " ORDER BY CASE kind WHEN 'incident' THEN 0 ELSE 1 END, CASE WHEN status IN ('CONFIRMED') THEN 1 ELSE 0 END, updated_at DESC LIMIT ?",
                               (*args, limit)).fetchall()
        now = _s(_now())
        out = []
        for r in rows:
            d = dict(r)
            d["overdue"] = bool(d["status"] in OPEN_STATES and d["sla_due_at"] and d["sla_due_at"] < now and not d["last_agent_at"])
            d["category_label"] = CATS.get(d["category"], d["category"])
            out.append(d)
        return jsonify({"success": True, "tickets": out})

    @support_bp.route("/api/admin/support/stats", methods=["GET"])
    @admin_required
    def adm_stats():
        ensure_schema(); _sweep()
        c = _conn(); now = _s(_now()); ph = ",".join("?" * len(OPEN_STATES))
        one = lambda sql, a=(): c.execute(sql, a).fetchone()[0] or 0
        return jsonify({"success": True,
                        "open": one(f"SELECT COUNT(*) FROM support_tickets WHERE status IN ({ph})", OPEN_STATES),
                        "open_incidents": one(f"SELECT COUNT(*) FROM support_tickets WHERE kind='incident' AND status IN ({ph})", OPEN_STATES),
                        "overdue": one(f"SELECT COUNT(*) FROM support_tickets WHERE status IN ({ph}) AND last_agent_at IS NULL AND sla_due_at < ?", (*OPEN_STATES, now)),
                        "unassigned": one(f"SELECT COUNT(*) FROM support_tickets WHERE status IN ({ph}) AND assignee IS NULL", OPEN_STATES),
                        "resolved_today": one("SELECT COUNT(*) FROM support_tickets WHERE resolved_at >= ?", (_s(_now() - timedelta(hours=24)),)),
                        "by_channel": {r[0]: r[1] for r in c.execute(f"SELECT channel, COUNT(*) FROM support_tickets WHERE status IN ({ph}) GROUP BY channel", OPEN_STATES)}})

    def _admin_ticket(no):
        return _ticket(no) if _NO_RE.match(str(no)) else None

    @support_bp.route("/api/admin/support/tickets/<no>", methods=["GET"])
    @admin_required
    def adm_get(no):
        t = _admin_ticket(no)
        if not t:
            return jsonify({"success": False, "error": "not_found"}), 404
        _audit(actor(), "viewed", no)
        email, name = _user_email(t["user_id"])
        t["customer"] = {"name": name, "email": email, "chat": (t["chat_id"][:3] + "…" + t["chat_id"][-3:]) if t["chat_id"] else None}
        t["category_label"] = CATS.get(t["category"], t["category"])
        return jsonify({"success": True, "ticket": t, "messages": _thread(t, include_internal=True)})

    @support_bp.route("/api/admin/support/tickets/<no>/reply", methods=["POST"])
    @admin_required
    def adm_reply(no):
        t = _admin_ticket(no)
        if not t:
            return jsonify({"success": False, "error": "not_found"}), 404
        d = request.get_json(silent=True) or {}
        res, code = agent_reply(t, actor(), d.get("message"), resolve=bool(d.get("resolve")), wait=bool(d.get("wait")))
        return jsonify(res), code

    @support_bp.route("/api/admin/support/tickets/<no>/note", methods=["POST"])
    @admin_required
    def adm_note(no):
        t = _admin_ticket(no)
        body = clean_text((request.get_json(silent=True) or {}).get("message"))
        if not t or not body:
            return jsonify({"success": False, "error": "bad_request"}), 400
        _add_message(t["id"], "agent", actor(), body, None, internal=True)
        _audit(actor(), "note", no)
        return jsonify({"success": True})

    def _update(no, col, value, action):
        t = _admin_ticket(no)
        if not t:
            return jsonify({"success": False, "error": "not_found"}), 404
        c = _conn()
        c.execute(f"UPDATE support_tickets SET {col} = ?, updated_at = ? WHERE id = ?", (value, _s(_now()), t["id"]))
        c.commit()
        _audit(actor(), action, no, str(value))
        return jsonify({"success": True, col: value})

    @support_bp.route("/api/admin/support/tickets/<no>/status", methods=["POST"])
    @admin_required
    def adm_status(no):
        st = str((request.get_json(silent=True) or {}).get("status") or "").upper()
        return _update(no, "status", st, "status") if st in STATUSES else (jsonify({"success": False, "error": "bad_status"}), 400)

    @support_bp.route("/api/admin/support/tickets/<no>/assign", methods=["POST"])
    @admin_required
    def adm_assign(no):
        who = re.sub(r"[^A-Za-z0-9 ._@-]", "", str((request.get_json(silent=True) or {}).get("assignee") or ""))[:40] or None
        return _update(no, "assignee", who, "assign")

    @support_bp.route("/api/admin/support/tickets/<no>/priority", methods=["POST"])
    @admin_required
    def adm_priority(no):
        p = str((request.get_json(silent=True) or {}).get("priority") or "").lower()
        return _update(no, "priority", p, "priority") if p in PRIORITIES else (jsonify({"success": False, "error": "bad_priority"}), 400)

    @support_bp.route("/admin/support", methods=["GET"])
    def adm_page():
        resp = make_response(DESK_HTML)       # a shell only: every call it makes needs the admin secret
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    app.register_blueprint(support_bp)
    logger.info("Support desk ready (tickets, incidents, chats, agent desk at /admin/support)")


DESK_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Net365 Support Desk</title><style>
:root{--bg:#f4f6fa;--c:#fff;--t:#1e293b;--m:#64748b;--l:#e2e8f0;--a:#E53935;--g:#1baf7a;--o:#eb6834}
@media (prefers-color-scheme:dark){:root{--bg:#121214;--c:#1c1c20;--t:#e8e8ec;--m:#9a9aa6;--l:#2c2c34}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
header{display:flex;gap:12px;align-items:center;padding:12px 16px;background:var(--c);border-bottom:1px solid var(--l);flex-wrap:wrap}
header h1{font-size:17px;margin:0 auto 0 0}button,select,input,textarea{font:inherit;color:inherit;background:var(--c);border:1px solid var(--l);border-radius:8px;padding:7px 10px}
button{cursor:pointer}button.p{background:var(--a);border-color:var(--a);color:#fff}button.g{background:var(--g);border-color:var(--g);color:#fff}
.kp{display:flex;gap:10px;padding:12px 16px;flex-wrap:wrap}.k{background:var(--c);border:1px solid var(--l);border-radius:10px;padding:8px 14px;min-width:110px}.k b{display:block;font-size:22px}.k.hot b{color:var(--a)}
.main{display:grid;grid-template-columns:minmax(300px,420px) 1fr;gap:12px;padding:0 16px 16px}@media(max-width:860px){.main{grid-template-columns:1fr}}
.panel{background:var(--c);border:1px solid var(--l);border-radius:12px;min-height:300px;overflow:hidden}
.bar{display:flex;gap:6px;padding:10px;border-bottom:1px solid var(--l);flex-wrap:wrap}.bar input{flex:1;min-width:100px}
.row{padding:10px 12px;border-bottom:1px solid var(--l);cursor:pointer}.row:hover,.row.on{background:rgba(229,57,53,.07)}.row .s{color:var(--m);font-size:12px}
.b{display:inline-block;font-size:11px;font-weight:700;padding:1px 8px;border-radius:99px;border:1px solid var(--l);margin-right:4px}.b.i{border-color:var(--a);color:var(--a)}.b.o{border-color:var(--o);color:var(--o)}
.thread{padding:12px;max-height:56vh;overflow:auto}.m{margin:8px 0;padding:9px 12px;border-radius:10px;max-width:86%;white-space:pre-wrap;word-wrap:break-word}
.m.customer{background:rgba(100,116,139,.14)}.m.agent{background:rgba(27,175,122,.15);margin-left:auto}.m.internal{background:rgba(235,104,52,.15);border:1px dashed var(--o)}
.m small{display:block;color:var(--m);font-size:11px}.reply{padding:10px;border-top:1px solid var(--l)}.reply textarea{width:100%;min-height:80px;margin-bottom:8px}
.acts{display:flex;gap:6px;flex-wrap:wrap}.empty{padding:40px;text-align:center;color:var(--m)}#gate{max-width:360px;margin:12vh auto;background:var(--c);padding:22px;border-radius:14px;border:1px solid var(--l)}#gate input{width:100%;margin:8px 0}
</style></head><body>
<div id="gate"><h2 style="margin:0 0 6px">Support Desk</h2><div style="color:var(--m)">Enter the admin secret. It is kept only in this browser tab.</div>
<input id="sec" type="password" placeholder="Admin secret" autocomplete="off"><input id="who" placeholder="Your name (shown in the audit log)"><button class="p" id="go" style="width:100%">Open desk</button><div id="ge" style="color:var(--a);margin-top:8px"></div></div>
<div id="app" style="display:none"><header><h1>Net365 Support Desk</h1><button id="rf">Refresh</button></header><div class="kp" id="kp"></div>
<div class="main"><div class="panel"><div class="bar"><select id="fs"><option value="open">Open</option><option value="">All</option><option value="incident">Incidents</option><option value="RESOLVED">Resolved</option><option value="CONFIRMED">Closed</option></select><input id="fq" placeholder="Ticket, order ref or text"></div><div id="list"></div></div>
<div class="panel" id="det"><div class="empty">Choose a ticket</div></div></div></div>
<script>
var SEC='',WHO='',CUR=null;function $(i){return document.getElementById(i)}
function esc(s){var d=document.createElement('div');d.textContent=s==null?'':String(s);return d.innerHTML}
function api(p,o){o=o||{};o.headers=Object.assign({'X-Admin-Secret':SEC,'X-Admin-Actor':WHO,'Content-Type':'application/json'},o.headers||{});return fetch(p,o).then(function(r){return r.json().then(function(d){d._s=r.status;return d})})}
function post(p,b){return api(p,{method:'POST',body:JSON.stringify(b||{})})}
$('go').onclick=function(){SEC=$('sec').value;WHO=$('who').value.trim()||'agent';api('/api/admin/support/stats').then(function(d){if(d.success){try{sessionStorage.setItem('n365s',JSON.stringify([SEC,WHO]))}catch(e){}$('gate').style.display='none';$('app').style.display='block';load()}else $('ge').textContent='Wrong secret'})};
try{var sv=JSON.parse(sessionStorage.getItem('n365s')||'null');if(sv){$('sec').value=sv[0];$('who').value=sv[1];$('go').click()}}catch(e){}
$('rf').onclick=function(){load()};$('fs').onchange=load;var qt;$('fq').oninput=function(){clearTimeout(qt);qt=setTimeout(load,300)};
function load(){api('/api/admin/support/stats').then(function(s){$('kp').innerHTML=[['Open',s.open],['Incidents',s.open_incidents,1],['Overdue',s.overdue,1],['Unassigned',s.unassigned],['Resolved 24h',s.resolved_today]].map(function(k){return '<div class="k'+(k[2]&&k[1]?' hot':'')+'"><span>'+k[0]+'</span><b>'+(k[1]||0)+'</b></div>'}).join('')});
var f=$('fs').value,q='/api/admin/support/tickets?limit=100'+(f==='open'?'&open=1':f==='incident'?'&kind=incident&open=1':f?'&status='+f:'')+($('fq').value?'&q='+encodeURIComponent($('fq').value):'');
api(q).then(function(d){var l=d.tickets||[];$('list').innerHTML=l.length?l.map(function(t){return '<div class="row'+(CUR===t.ticket_no?' on':'')+'" data-n="'+esc(t.ticket_no)+'"><div>'+(t.kind==='incident'?'<span class="b i">INCIDENT</span>':'')+(t.overdue?'<span class="b o">OVERDUE</span>':'')+'<b>'+esc(t.ticket_no)+'</b> <span class="b">'+esc(t.status)+'</span></div><div>'+esc(t.category_label)+'</div><div class="s">'+esc(t.channel)+' · '+esc(t.updated_at)+(t.assignee?' · '+esc(t.assignee):'')+'</div></div>'}).join(''):'<div class="empty">Nothing here</div>';
[].forEach.call($('list').querySelectorAll('.row'),function(r){r.onclick=function(){open_(r.getAttribute('data-n'))}})})}
function open_(n){CUR=n;api('/api/admin/support/tickets/'+n).then(function(d){if(!d.success){$('det').innerHTML='<div class="empty">'+esc(d.error)+'</div>';return}var t=d.ticket,c=t.customer||{};
$('det').innerHTML='<div class="bar"><div style="flex:1"><b>'+esc(t.ticket_no)+'</b> '+(t.kind==='incident'?'<span class="b i">INCIDENT</span>':'')+'<span class="b">'+esc(t.status)+'</span><div class="s" style="color:var(--m)">'+esc(t.category_label)+' · '+esc(t.channel)+' · order '+esc(t.reference||'none')+' · '+esc(c.name||'')+' '+esc(c.email||c.chat||'')+' · due '+esc(t.sla_due_at||'')+'</div></div>'+
'<select id="pr">'+['low','normal','high','urgent'].map(function(p){return '<option'+(p===t.priority?' selected':'')+'>'+p+'</option>'}).join('')+'</select><button id="as">'+(t.assignee?'Assigned: '+esc(t.assignee):'Assign to me')+'</button></div>'+
'<div class="thread">'+d.messages.map(function(m){return '<div class="m '+(m.internal?'internal':m.sender)+'"><small>'+(m.internal?'PRIVATE NOTE · ':'')+esc(m.sender==='agent'?m.name:'Customer')+' · '+esc(m.created_at)+(m.delivery?' · '+esc(m.delivery):'')+'</small>'+esc(m.body)+'</div>'}).join('')+'</div>'+
'<div class="reply"><textarea id="rb" placeholder="Reply to the customer (it is sent to their chat, email and app)"></textarea><div class="acts"><button class="p" id="rs">Send reply</button><button class="g" id="rr">Reply and mark resolved</button><button id="rw">Reply, waiting on customer</button><button id="rn">Save as private note</button></div></div>';
var th=document.querySelector('.thread');th.scrollTop=th.scrollHeight;
$('pr').onchange=function(){post('/api/admin/support/tickets/'+n+'/priority',{priority:this.value}).then(load)};$('as').onclick=function(){post('/api/admin/support/tickets/'+n+'/assign',{assignee:WHO}).then(function(){open_(n);load()})};
function send(extra,path){var b=$('rb').value.trim();if(!b)return;post('/api/admin/support/tickets/'+n+path,Object.assign({message:b},extra)).then(function(r){if(!r.success)alert(r.error||'failed');open_(n);load()})}
$('rs').onclick=function(){send({}, '/reply')};$('rr').onclick=function(){send({resolve:true},'/reply')};$('rw').onclick=function(){send({wait:true},'/reply')};$('rn').onclick=function(){send({},'/note')}})}
</script></body></html>"""

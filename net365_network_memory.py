"""
Net365 network memory: "which operator did this number last deliver on?"

Why: numbers get ported. A past success is useful evidence, but today's detection is newer evidence. So this module only
REMEMBERS; the web page and the chat bots compare it with live detection and ask the customer when the two disagree
("This number was on MTN before. We now detect Airtel. Did you move?").

* One row per (owner, number, country). Owner is the Net365 user id, so a delivery on the website teaches the
  chat bots and the other way round. The phone number is stored only as a salted hash, never in plain text.
* Written when a top-up is DELIVERED (success), or when the customer confirms their network.
* Cleared when a top-up fails with an operator/number error, so a ported number corrects itself after one failure.
* Entries older than NETWORK_MEMORY_DAYS (default 90) are ignored.

Nothing here can change a payment by itself. It is a hint that the caller must compare with detection.
"""
import hashlib
import logging
import os
import re
from datetime import datetime, timedelta

from flask import Blueprint, g, jsonify, request

import net365_whatsapp as W

log = logging.getLogger(__name__)
nm_bp = Blueprint("network_memory", __name__)
_d = {}
_schema_done = False


def _days():
    try:
        return max(1, int(os.getenv("NETWORK_MEMORY_DAYS", "90")))
    except ValueError:
        return 90


def _conn():
    return _d["db"].get_db_connection()


def _ensure():
    global _schema_done
    if _schema_done:
        return
    c = _conn()
    try:
        c.execute(
            """CREATE TABLE IF NOT EXISTS number_networks (
                owner INTEGER NOT NULL, number_hash TEXT NOT NULL, country TEXT NOT NULL DEFAULT 'NG',
                operator_id TEXT NOT NULL, operator_name TEXT, source TEXT,
                successes INTEGER NOT NULL DEFAULT 0, last_success_at TEXT, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (owner, number_hash, country))"""
        )
        c.commit()
    except Exception:
        log.exception("network memory schema failed")
        return
    _schema_done = True


def _digits(phone, country):
    d = re.sub(r"\D", "", str(phone or ""))
    country = (country or "NG").upper()
    if country == "NG":
        if d.startswith("234") and len(d) == 13:
            d = d[3:]
        elif d.startswith("0") and len(d) == 11:
            d = d[1:]
        return d[-10:] if len(d) >= 10 else ""
    # Abroad: the same number can arrive with or without its country code, so use its last 9 digits.
    return d[-9:] if len(d) >= 9 else ""


def _hash(phone, country):
    n = _digits(phone, country)
    if not n:
        return None
    return hashlib.sha256(f"{os.getenv('SECRET_KEY', '')}|netmem|{(country or 'NG').upper()}|{n}".encode()).hexdigest()


def _cc(country):
    c = re.sub(r"[^A-Za-z]", "", str(country or "NG")).upper()[:2]
    return c if len(c) == 2 else "NG"


def _view(row):
    if not row:
        return {"found": False}
    r = dict(row)
    ts = max(str(r.get("last_success_at") or ""), str(r.get("updated_at") or "")) or None  # a confirmation refreshes it too
    try:
        when = datetime.fromisoformat(str(ts).replace("Z", "")) if ts else None
    except ValueError:
        when = None
    if when and datetime.utcnow() - when > timedelta(days=_days()):
        return {"found": False, "expired": True}
    return {"found": True, "operator_id": r["operator_id"], "operator_name": r["operator_name"], "source": r["source"],
            "successes": r["successes"], "last_success_at": r["last_success_at"],
            "age_days": (datetime.utcnow() - when).days if when else None}


# --------------------------------------------------------------------------- core (also called by fulfilment)
def lookup(owner, phone, country="NG"):
    _ensure()
    h = _hash(phone, _cc(country))
    if not owner or not h:
        return {"found": False}
    row = _conn().execute("SELECT * FROM number_networks WHERE owner=? AND number_hash=? AND country=?",
                          (owner, h, _cc(country))).fetchone()
    return _view(row)


def remember(owner, phone, country, operator_id, operator_name, source, success=False):
    """Upsert. A confirmed or delivered operator replaces whatever was stored before."""
    _ensure()
    country = _cc(country)
    h = _hash(phone, country)
    if not owner or not h or not operator_id:
        return False
    c = _conn()
    ex = c.execute("SELECT operator_id, successes FROM number_networks WHERE owner=? AND number_hash=? AND country=?",
                   (owner, h, country)).fetchone()
    if ex:
        same = str(ex[0]) == str(operator_id)
        n = (ex[1] + 1 if success else ex[1]) if same else (1 if success else 0)
        c.execute("UPDATE number_networks SET operator_id=?, operator_name=?, source=?, successes=?, "
                  "last_success_at=CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE last_success_at END, "
                  "updated_at=CURRENT_TIMESTAMP WHERE owner=? AND number_hash=? AND country=?",
                  (str(operator_id), operator_name, source, n, 1 if success else 0, owner, h, country))
    else:
        c.execute("INSERT INTO number_networks (owner, number_hash, country, operator_id, operator_name, source, successes, last_success_at) "
                  "VALUES (?,?,?,?,?,?,?,CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END)",
                  (owner, h, country, str(operator_id), operator_name, source, 1 if success else 0, 1 if success else 0))
    c.commit()
    return True


def forget(owner, phone, country, operator_id=None):
    _ensure()
    country = _cc(country)
    h = _hash(phone, country)
    if not owner or not h:
        return 0
    c = _conn()
    if operator_id:
        cur = c.execute("DELETE FROM number_networks WHERE owner=? AND number_hash=? AND country=? AND operator_id=?",
                        (owner, h, country, str(operator_id)))
    else:
        cur = c.execute("DELETE FROM number_networks WHERE owner=? AND number_hash=? AND country=?", (owner, h, country))
    c.commit()
    return cur.rowcount


def record_success(user_id, phone, country, operator_id, operator_name=None):
    """Called by fulfilment after a top-up was DELIVERED. Never raises."""
    try:
        name = operator_name
        if not name:
            try:
                name = (_d["operator_lookup"](operator_id) or {}).get("name")
            except Exception:
                name = None
        remember(user_id, phone, country, operator_id, name, "delivered", success=True)
    except Exception:
        log.exception("network memory: record_success failed")


_OPERATOR_ERR = re.compile(r"invalid|operator|number|recipient|not supported|unsupported|msisdn|network", re.I)


def record_failure(user_id, phone, country, operator_id, error_text):
    """Called when a top-up failed. Only an operator/number type of error clears the memory (an outage must not)."""
    try:
        if operator_id and _OPERATOR_ERR.search(str(error_text or "")):
            forget(user_id, phone, country, operator_id)
    except Exception:
        log.exception("network memory: record_failure failed")


# --------------------------------------------------------------------------- routes
def _bot_owner(data):
    wa = W._wa(data)
    link = W._get_link(wa) if wa else None
    return (link or {}).get("user_id")


def init_network_memory(app, db_module, login_required, operator_lookup=None):
    _d.update(db=db_module, operator_lookup=operator_lookup)
    _ensure()

    @nm_bp.route("/api/whatsapp/netmem/get", methods=["POST"])
    @W.bot_required
    def nm_bot_get():
        d = W._body()
        return jsonify({"success": True, **lookup(_bot_owner(d), d.get("number"), d.get("country"))})

    @nm_bp.route("/api/whatsapp/netmem/set", methods=["POST"])
    @W.bot_required
    def nm_bot_set():
        d = W._body()
        ok = remember(_bot_owner(d), d.get("number"), d.get("country"), d.get("operator_id"),
                      str(d.get("operator_name") or "")[:60], "confirmed" if d.get("source") != "chosen" else "chosen")
        return jsonify({"success": bool(ok)})

    @nm_bp.route("/api/whatsapp/netmem/clear", methods=["POST"])
    @W.bot_required
    def nm_bot_clear():
        d = W._body()
        return jsonify({"success": True, "cleared": forget(_bot_owner(d), d.get("number"), d.get("country"))})

    @nm_bp.route("/api/network-memory", methods=["GET"])
    @login_required
    def nm_web_get():
        return jsonify({"success": True, **lookup(g.current_user_id, request.args.get("phone"), request.args.get("country"))})

    @nm_bp.route("/api/network-memory", methods=["POST"])
    @login_required
    def nm_web_set():
        d = request.get_json(silent=True) or {}
        ok = remember(g.current_user_id, d.get("phone"), d.get("country"), d.get("operator_id"),
                      str(d.get("operator_name") or "")[:60], "confirmed")
        return jsonify({"success": bool(ok)})

    app.register_blueprint(nm_bp)

"""net365_smartshare.py - NET365 Smart Share: location-aware recharge identities, one-time recharge requests and gifting.

A customer keeps a permanent recharge identity (code, shareable link, QR; the code defaults to their referral code) that says WHERE the services for them are:
country, state, city, preferred network, preferred services. Someone in London, Lagos or Aba can open it and Net365 shows
what can be bought for that person where they are. Three locations are kept apart on purpose:
  current location     where the person is now (approximate, from the connection; never stored here)
  registered location  the country the customer declared when signing up (not used by this module)
  service location     where the service has to happen = the beneficiary's country/state/city saved on the identity
The payer's location never decides which provider is used: the service location does. Location only informs what is offered.
Nothing here moves money. A payer always confirms amount, number and price in the normal Recharge / Bills flows.

Customer (logged in):
  GET  /api/share/me                      my identity + my open requests
  POST /api/share/me                      {name, country, state, city, network, services[], share_phone, phone, discoverable}
  POST /api/share/me/rotate               new code; the old one stops working
  GET  /api/share/search?q=               find a beneficiary by code, or by name/city when they chose to be discoverable
  POST /api/share/open/<code>             the beneficiary's number, only if they chose to share it (each use is logged)
  POST /api/share/requests                {service, amount, currency, note}  ->  one-time request code (valid 7 days)
  POST /api/share/requests/<code>/cancel
Public (rate limited, never returns an email, a full number or a user id):
  GET  /api/share/lookup/<code>           what the identity owner chose to show
  GET  /api/share/requests/<code>         a recharge request
  GET  /api/geo/context                   {country, region, city} from Cloudflare's visitor headers when they are switched on

Environment (all optional):  SHARE_REQUEST_DAYS=7   SHARE_MAX_OPEN_REQUESTS=20
"""
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from flask import Blueprint, g, jsonify, request

logger = logging.getLogger(__name__)
share_bp = Blueprint("smartshare", __name__)
_ctx = {"db": None, "ip": None, "ref": None, "profile": None, "ready": False}
_lock = threading.Lock()
_hits = defaultdict(deque)

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0, O, 1, I: codes are read aloud and typed from screenshots
SERVICES = ("airtime", "data", "electricity", "tv", "giftcards", "education")
CODE_RE = re.compile(r"^NET365-[A-Z0-9]{6}$")
REQ_RE = re.compile(r"^NSR-[A-Z0-9]{6}$")
ISO_RE = re.compile(r"^[A-Z]{2}$")


def _conn():
    return _ctx["db"].get_db_connection()


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _s(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _env_int(name, default):
    try:
        return max(1, int(os.getenv(name, default)))
    except (TypeError, ValueError):
        return default


def _ip():
    try:
        return (_ctx["ip"]() if _ctx["ip"] else request.remote_addr) or "?"
    except Exception:
        return request.remote_addr or "?"


def limited(key, limit, window):
    """True when `key` already used `limit` hits inside `window` seconds (and records this hit otherwise)."""
    now = time.time()
    with _lock:
        q = _hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return True
        q.append(now)
        if len(_hits) > 5000:  # keep memory flat under a flood of different callers
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > window][:1000]:
                _hits.pop(k, None)
    return False


def clean(text, limit):
    t = re.sub(r"[<>\u0000-\u001f]", " ", str(text or ""))
    return re.sub(r"\s+", " ", t).strip()[:limit]


def mask_phone(p):
    p = re.sub(r"\D", "", str(p or ""))
    return (p[:4] + "•••" + p[-3:]) if len(p) >= 8 else ""


def ensure_schema():
    if _ctx["ready"]:
        return
    with _lock:
        if _ctx["ready"]:
            return
        c = _conn()
        c.execute("""CREATE TABLE IF NOT EXISTS share_identities (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE, code TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL, country TEXT NOT NULL, state TEXT, city TEXT, network TEXT, services TEXT NOT NULL DEFAULT '[]',
            phone TEXT, share_phone INTEGER NOT NULL DEFAULT 0, discoverable INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS share_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL, service TEXT NOT NULL,
            amount REAL, currency TEXT, note TEXT, status TEXT NOT NULL DEFAULT 'OPEN', expires_at TEXT NOT NULL, created_at TEXT NOT NULL,
            opened_count INTEGER NOT NULL DEFAULT 0, paid_by INTEGER, paid_ref TEXT, paid_at TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS share_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, user_id INTEGER, action TEXT NOT NULL, ref TEXT, ip TEXT)""")
        c.execute("CREATE INDEX IF NOT EXISTS ix_sr_user ON share_requests(user_id, status)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_si_find ON share_identities(discoverable, display_name)")
        c.commit()
        _ctx["ready"] = True


def _audit(user_id, action, ref=""):
    try:
        c = _conn()
        c.execute("INSERT INTO share_audit (ts, user_id, action, ref, ip) VALUES (?,?,?,?,?)", (_s(_now()), user_id, action, ref, _ip()))
        c.commit()
    except Exception as e:  # an audit failure must never block the customer
        logger.warning("share audit failed: %s", e)


def _new_code(prefix, table):
    for _ in range(12):
        code = prefix + "".join(secrets.choice(ALPHABET) for _ in range(6))
        if not _conn().execute("SELECT 1 FROM %s WHERE code = ?" % table, (code,)).fetchone():
            return code
    raise RuntimeError("could not allocate a code")


def _adopt_or_new(uid):
    try:
        ref = str(_ctx["ref"](uid) or "").strip().upper() if _ctx["ref"] else ""
    except Exception:
        ref = ""
    if CODE_RE.match(ref) and not _conn().execute("SELECT 1 FROM share_identities WHERE code = ?", (ref,)).fetchone():
        return ref
    return _new_code("NET365-", "share_identities")


def _identity_by_user(uid):
    r = _conn().execute("SELECT * FROM share_identities WHERE user_id = ?", (uid,)).fetchone()
    return dict(r) if r else None


def _identity_by_code(code):
    r = _conn().execute("SELECT * FROM share_identities WHERE code = ?", (str(code or "").upper(),)).fetchone() if CODE_RE.match(str(code or "").upper()) else None
    return dict(r) if r else None


def _services(row):
    try:
        v = json.loads(row.get("services") or "[]")
        return [x for x in v if x in SERVICES]
    except Exception:
        return []


def public_view(row):
    """What a stranger may see. Never the user id, email or a full number."""
    return {"code": row["code"], "name": row["display_name"], "country": row["country"], "state": row.get("state") or "", "city": row.get("city") or "",
            "network": row.get("network") or "", "services": _services(row), "can_recharge": bool(row.get("share_phone") and row.get("phone")),
            "phone_hint": mask_phone(row.get("phone")) if row.get("share_phone") else ""}


def own_view(row):
    d = public_view(row)
    d.update({"phone": row.get("phone") or "", "share_phone": bool(row.get("share_phone")), "discoverable": bool(row.get("discoverable")), "updated_at": row.get("updated_at")})
    return d


def _request_view(r, ident=None):
    r = dict(r)
    status = r["status"]
    if status == "OPEN" and r["expires_at"] < _s(_now()):
        status = "EXPIRED"
    ident = ident or (_conn().execute("SELECT * FROM share_identities WHERE user_id = ?", (r["user_id"],)).fetchone())
    ident = dict(ident) if ident else None
    return {"code": r["code"], "service": r["service"], "amount": r["amount"], "currency": r["currency"] or "", "note": r["note"] or "", "status": status,
            "expires_at": r["expires_at"], "created_at": r["created_at"], "beneficiary": public_view(ident) if ident else None}


def mark_request_paid(code, payer_user_id, reference):
    """For the payment flow to call once a request has really been paid. Not exposed over HTTP."""
    ensure_schema()
    c = _conn()
    cur = c.execute("UPDATE share_requests SET status = 'PAID', paid_by = ?, paid_ref = ?, paid_at = ? WHERE code = ? AND status = 'OPEN' AND expires_at >= ?",
                    (payer_user_id, str(reference)[:80], _s(_now()), code, _s(_now())))
    c.commit()
    return cur.rowcount == 1


def init_smartshare(app, db_module, login_required, client_ip_fn=None, referral_code_fn=None, profile_fn=None):
    """referral_code_fn(user_id) -> the account's existing NET365-XXXXXX code. When given, a new identity adopts it, so one code
    serves referrals and recharges. profile_fn(user_id) -> the user's record (full_name, phone) so the form arrives pre-filled. Rotating the identity code later does not change the referral code."""
    _ctx.update(db=db_module, ip=client_ip_fn, ref=referral_code_fn, profile=profile_fn)
    try:
        ensure_schema()
    except Exception as e:
        logger.warning("smart share tables not ready: %s", e)

    def no_store(resp):
        resp.headers["Cache-Control"] = "no-store"
        return resp

    _geo_cache = {}   # ip -> (country, region, city, expires): a visitor is looked up once, not on every page load

    def _geo_from_ip(ip):
        """Country for a public IP when the site is not behind Cloudflare. Uses the existing ip_intel lookup (cached 6 hours).
        Never raises; returns ("", "", "") for private/unknown addresses or when every lookup source is down."""
        try:
            import ipaddress
            ipo = ipaddress.ip_address(ip)
            if ipo.is_private or ipo.is_loopback or ipo.is_link_local or ipo.is_reserved:
                return "", "", ""
        except Exception:
            return "", "", ""
        hit = _geo_cache.get(ip)
        if hit and hit[3] > time.time():
            return hit[0], hit[1], hit[2]
        cc = rg = city = ""
        try:
            import ip_intel
            info = ip_intel.lookup_remote(ip) or {}
            cc = str(info.get("country") or "").strip().upper()
            rg, city = clean(info.get("region"), 60), clean(info.get("city"), 60)
        except Exception as e:
            logger.debug("geo fallback failed for %s: %s", ip, e)
        if not ISO_RE.match(cc):
            cc = ""
        # remember a miss for 10 minutes so a failing lookup service is not hammered
        _geo_cache[ip] = (cc, rg, city, time.time() + (6 * 3600 if cc else 600))
        if len(_geo_cache) > 5000:
            _geo_cache.clear()
        return cc, rg, city

    @share_bp.route("/api/geo/context", methods=["GET"])
    def geo_context():
        h = request.headers
        cc = (h.get("CF-IPCountry") or "").strip().upper()
        if not ISO_RE.match(cc) or cc in ("XX", "T1"):
            cc = ""
        region, city, source = clean(h.get("CF-Region"), 60), clean(h.get("CF-IPCity"), 60), "connection"
        if not cc and not limited("geo:" + _ip(), 30, 60):      # no Cloudflare headers: look the address up
            cc, region, city = _geo_from_ip(_ip())
            source = "ip"
        return no_store(jsonify({"success": True, "country": cc, "region": region, "city": city, "source": source if cc else "none"}))

    @share_bp.route("/api/share/defaults", methods=["GET"])
    @login_required
    def share_defaults():
        """What the system already knows, so the customer confirms instead of typing. Read-only, nothing is saved."""
        u = {}
        try:
            u = dict(_ctx["profile"](g.current_user_id) or {}) if _ctx["profile"] else {}
        except Exception as e:
            logger.warning("share defaults: profile lookup failed: %s", e)
        h = request.headers
        cc = (h.get("CF-IPCountry") or "").strip().upper()
        if not ISO_RE.match(cc) or cc in ("XX", "T1"):
            cc = ""
        name = clean(str(u.get("full_name") or "").split(" ")[0], 40)
        phone = re.sub(r"[^\d+]", "", str(u.get("phone") or ""))[:16]
        return no_store(jsonify({"success": True, "name": name, "phone": phone, "country": cc, "region": clean(h.get("CF-Region"), 60), "city": clean(h.get("CF-IPCity"), 60)}))

    @share_bp.route("/api/share/me", methods=["GET"])
    @login_required
    def share_me():
        ensure_schema()
        ident = _identity_by_user(g.current_user_id)
        rows = _conn().execute("SELECT * FROM share_requests WHERE user_id = ? ORDER BY id DESC LIMIT 20", (g.current_user_id,)).fetchall()
        return no_store(jsonify({"success": True, "identity": own_view(ident) if ident else None, "requests": [_request_view(r, ident) for r in rows]}))

    @share_bp.route("/api/share/me", methods=["POST"])
    @login_required
    def share_save():
        ensure_schema()
        d = request.get_json(silent=True) or {}
        name = clean(d.get("name"), 40)
        country = str(d.get("country") or "").strip().upper()
        if not name:
            return jsonify({"success": False, "error": "name_required", "message": "Add the name people will see."}), 400
        if not ISO_RE.match(country):
            return jsonify({"success": False, "error": "country_required", "message": "Choose the country where the services are used."}), 400
        services = [s for s in (d.get("services") or []) if s in SERVICES][:6]
        phone = re.sub(r"[^\d+]", "", str(d.get("phone") or ""))[:16]
        share_phone = bool(d.get("share_phone")) and len(re.sub(r"\D", "", phone)) >= 7
        if d.get("share_phone") and not share_phone:
            return jsonify({"success": False, "error": "phone_invalid", "message": "Enter a valid number, or switch off sharing it."}), 400
        now = _s(_now())
        c = _conn()
        cur = _identity_by_user(g.current_user_id)
        fields = (name, country, clean(d.get("state"), 60), clean(d.get("city"), 60), clean(d.get("network"), 40), json.dumps(services), phone if phone else None,
                  1 if share_phone else 0, 1 if d.get("discoverable") else 0, now)
        if cur:
            c.execute("""UPDATE share_identities SET display_name=?, country=?, state=?, city=?, network=?, services=?, phone=?, share_phone=?, discoverable=?, updated_at=?
                         WHERE user_id = ?""", fields + (g.current_user_id,))
        else:
            c.execute("""INSERT INTO share_identities (display_name, country, state, city, network, services, phone, share_phone, discoverable, updated_at, user_id, code, created_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", fields + (g.current_user_id, _adopt_or_new(g.current_user_id), now))
        c.commit()
        _audit(g.current_user_id, "identity_save")
        return no_store(jsonify({"success": True, "identity": own_view(_identity_by_user(g.current_user_id))}))

    @share_bp.route("/api/share/me/rotate", methods=["POST"])
    @login_required
    def share_rotate():
        ensure_schema()
        if not _identity_by_user(g.current_user_id):
            return jsonify({"success": False, "error": "no_identity"}), 404
        if limited("rot:%s" % g.current_user_id, 5, 3600):
            return jsonify({"success": False, "error": "slow_down"}), 429
        c = _conn()
        c.execute("UPDATE share_identities SET code = ?, updated_at = ? WHERE user_id = ?", (_new_code("NET365-", "share_identities"), _s(_now()), g.current_user_id))
        c.commit()
        _audit(g.current_user_id, "identity_rotate")
        return no_store(jsonify({"success": True, "identity": own_view(_identity_by_user(g.current_user_id))}))

    @share_bp.route("/api/share/lookup/<code>", methods=["GET"])
    def share_lookup(code):
        ensure_schema()
        if limited("lk:" + _ip(), 40, 300):
            return jsonify({"success": False, "error": "slow_down"}), 429
        row = _identity_by_code(code)
        if not row:
            return no_store(jsonify({"success": False, "error": "not_found"})), 404
        return no_store(jsonify({"success": True, "identity": public_view(row)}))

    @share_bp.route("/api/share/search", methods=["GET"])
    @login_required
    def share_search():
        ensure_schema()
        q = clean(request.args.get("q"), 60)
        if len(q) < 3:
            return jsonify({"success": True, "results": []})
        if limited("sr:%s" % g.current_user_id, 30, 300):
            return jsonify({"success": False, "error": "slow_down"}), 429
        out = []
        exact = _identity_by_code(q)
        if exact:
            out.append(exact)
        like = re.sub(r"[%_\\]", "", q) + "%"
        rows = _conn().execute("""SELECT * FROM share_identities WHERE discoverable = 1 AND user_id != ? AND (display_name LIKE ? OR city LIKE ?)
                                  ORDER BY display_name LIMIT 8""", (g.current_user_id, like, like)).fetchall()
        seen = {r["code"] for r in out}
        out += [dict(r) for r in rows if r["code"] not in seen]
        return no_store(jsonify({"success": True, "results": [public_view(r) for r in out[:8]]}))

    @share_bp.route("/api/share/open/<code>", methods=["POST"])
    @login_required
    def share_open(code):
        ensure_schema()
        if limited("op:%s" % g.current_user_id, 20, 3600):
            return jsonify({"success": False, "error": "slow_down"}), 429
        row = _identity_by_code(code)
        if not row:
            return jsonify({"success": False, "error": "not_found"}), 404
        if not (row.get("share_phone") and row.get("phone")):
            return no_store(jsonify({"success": True, "phone": "", "shared": False}))
        _audit(g.current_user_id, "number_opened", row["code"])
        return no_store(jsonify({"success": True, "phone": row["phone"], "shared": True}))

    @share_bp.route("/api/share/requests", methods=["POST"])
    @login_required
    def req_create():
        ensure_schema()
        ident = _identity_by_user(g.current_user_id)
        if not ident:
            return jsonify({"success": False, "error": "no_identity", "message": "Set up your digital identity first."}), 400
        d = request.get_json(silent=True) or {}
        service = str(d.get("service") or "").lower()
        if service not in SERVICES:
            return jsonify({"success": False, "error": "service_invalid"}), 400
        try:
            amount = float(d.get("amount")) if d.get("amount") not in (None, "") else None
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "amount_invalid"}), 400
        if amount is not None and not (0 < amount <= 10000000):
            return jsonify({"success": False, "error": "amount_invalid", "message": "Enter an amount above zero."}), 400
        c = _conn()
        open_n = c.execute("SELECT COUNT(*) FROM share_requests WHERE user_id = ? AND status = 'OPEN' AND expires_at >= ?", (g.current_user_id, _s(_now()))).fetchone()[0]
        if open_n >= _env_int("SHARE_MAX_OPEN_REQUESTS", 20):
            return jsonify({"success": False, "error": "too_many", "message": "You have too many open requests. Cancel one first."}), 429
        code = _new_code("NSR-", "share_requests")
        exp = _now() + timedelta(days=_env_int("SHARE_REQUEST_DAYS", 7))
        c.execute("INSERT INTO share_requests (code, user_id, service, amount, currency, note, expires_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
                  (code, g.current_user_id, service, amount, clean(d.get("currency"), 3).upper() or None, clean(d.get("note"), 140) or None, _s(exp), _s(_now())))
        c.commit()
        _audit(g.current_user_id, "request_create", code)
        return no_store(jsonify({"success": True, "request": _request_view(c.execute("SELECT * FROM share_requests WHERE code = ?", (code,)).fetchone(), ident)}))

    @share_bp.route("/api/share/requests/<code>", methods=["GET"])
    def req_get(code):
        ensure_schema()
        if limited("rq:" + _ip(), 40, 300):
            return jsonify({"success": False, "error": "slow_down"}), 429
        code = str(code or "").upper()
        r = _conn().execute("SELECT * FROM share_requests WHERE code = ?", (code,)).fetchone() if REQ_RE.match(code) else None
        if not r:
            return no_store(jsonify({"success": False, "error": "not_found"})), 404
        c = _conn(); c.execute("UPDATE share_requests SET opened_count = opened_count + 1 WHERE id = ?", (r["id"],)); c.commit()
        return no_store(jsonify({"success": True, "request": _request_view(r)}))

    @share_bp.route("/api/share/requests/<code>/cancel", methods=["POST"])
    @login_required
    def req_cancel(code):
        ensure_schema()
        c = _conn()
        cur = c.execute("UPDATE share_requests SET status = 'CANCELLED' WHERE code = ? AND user_id = ? AND status = 'OPEN'", (str(code or "").upper(), g.current_user_id))
        c.commit()
        if cur.rowcount != 1:
            return jsonify({"success": False, "error": "not_found"}), 404
        _audit(g.current_user_id, "request_cancel", str(code).upper())
        return jsonify({"success": True})

    app.register_blueprint(share_bp)
    logger.info("Smart Share ready")

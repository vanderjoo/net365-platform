"""net365_shield.py - proactive protection: detect hostile visitors, block them at once, tell the team, and keep a list of bad IPs.

What it does
  1. Scores every visitor on hostile behaviour (scanner paths like /.env, attack tools, injection payloads in the URL, password
     guessing, bursts of 404/403/429). Enough points inside a short window and the IP is blocked automatically.
  2. A blocked IP is refused by the app straight away (403) and, for serious offences, pushed to a Cloudflare IP list so it is stopped
     at Cloudflare's edge and never reaches the server again. Blocks expire and escalate: a repeat offender is blocked for longer.
  3. The team gets an email the moment a block happens (IP, country, network, reason, evidence, one-click unblock link).
  4. Every block is sent to PostHog as a "security_block" event so it can be charted and alerted on there.
  5. Nothing here can lock out your own systems: private addresses, an allow-list (env + admin), and webhook/bot paths are never blocked.

Shared mobile networks (CGNAT): many Nigerian customers share one public IP. So "soft" evidence (wrong passwords, 404s, 429s) only ever
causes SHORT local blocks and is never sent to Cloudflare, unless the same IP keeps coming back. "Hard" evidence (attack tools, scanner paths,
injection payloads) is what earns long blocks and the Cloudflare push.

Environment (all optional; with none set the shield still blocks locally and logs)
  SHIELD_ENABLED=true            SHIELD_ENFORCE=true (false = watch and alert only, never refuse a request)
  SHIELD_THRESHOLD=100           points inside SHIELD_WINDOW_SECONDS=600 that trigger a block
  SHIELD_ALLOW_IPS=1.2.3.4,10.0.0.0/8   never blocked (your office, monitoring, payment/telecom callbacks, the bot server)
  SHIELD_EXEMPT_PREFIXES=/webhooks/,/api/whatsapp/,/internal/   paths that are neither scored nor refused
  SHIELD_ALERT_EMAIL=...         where block alerts go (falls back to SECURITY_EMAIL, SUPPORT_ALERT_EMAIL, SUPPORT_EMAIL)
  SHIELD_EMAIL_MAX_PER_HOUR=10   alert emails per hour (extra blocks are counted and reported in the next email)
  SHIELD_LINK_SECRET=...         signs the unblock link (falls back to ADMIN_SECRET)
  CF_API_TOKEN, CF_ACCOUNT_ID    Cloudflare: token needs "Account > Account Filter Lists > Edit"
  CF_BLOCK_LIST_ID               id of the list (created for you by POST /api/admin/shield/cloudflare/setup)
  CF_LIST_MAX_ITEMS=9000         stop pushing when the list is this full (check your Cloudflare plan's limit)
  POSTHOG_API_KEY, POSTHOG_HOST  (host default https://us.i.posthog.com)
"""
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import threading
import time
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote_plus

from flask import Blueprint, jsonify, make_response, request

logger = logging.getLogger(__name__)
shield_bp = Blueprint("shield", __name__)
_ctx = {"db": None, "email": None, "get_ip": None, "ready": False}
_lock = threading.RLock()
_blocks = {}            # ip -> {"until": epoch|None (None = permanent), "reason", "cls", "cf": bool}
_allow_nets = []        # parsed from env + admin
_score = defaultdict(deque)   # ip -> deque[(epoch, points, label)]
_cache = {"loaded": 0.0}
_mail = {"sent": deque(), "suppressed": 0}

HARD_LABELS = {"attack_tool", "scanner_path", "payload"}
POINTS = {"attack_tool": 100, "scanner_path": 50, "payload": 50, "login_fail": 10, "otp_fail": 12, "rate_limited": 5, "not_found": 3}
DURATIONS_HARD = (60, 24 * 60, 7 * 24 * 60)     # minutes: 1st, 2nd, 3rd+ offence
DURATIONS_SOFT = (15, 60, 6 * 60)

SCANNER_RE = re.compile(r"(/\.env|/\.git|/\.svn|/\.ds_store|/\.aws|/\.ssh|/id_rsa|/wp-(login|admin|content|includes|json)|/xmlrpc\.php|/phpmyadmin|/pma/|"
                        r"/cgi-bin|/boaform|/actuator|/vendor/phpunit|/phpinfo|/server-status|/admin\.php|/shell|/eval-stdin|/solr/|/jenkins|/manager/html|"
                        r"/hnap1|/owa/|/autodiscover|/remote/login|/etc/passwd|/backup\.(sql|zip|tar)|/db\.sql|/config\.(php|json|yml|bak)|\.\./)", re.I)
TOOL_RE = re.compile(r"(sqlmap|nikto|nuclei|masscan|zgrab|nmap|dirbuster|gobuster|wpscan|acunetix|havij|hydra|metasploit|ffuf|feroxbuster|"
                     r"netsparker|burpcollaborator|\bzmap\b|l9explore|leakix)", re.I)
PAYLOAD_RE = re.compile(r"(\bunion\b.{0,20}\bselect\b|information_schema|\bsleep\s*\(\s*\d|benchmark\s*\(|'\s*or\s*'?1'?\s*=\s*'?1|;\s*drop\s+table|"
                        r"<script|javascript:|onerror\s*=|\$\{jndi:|\.\./\.\./|/etc/passwd|base64_decode\s*\(|\bcmd=|\bexec\s*\()", re.I)


# ----------------------------------------------------------------------------------------------- helpers
def _conn():
    return _ctx["db"].get_db_connection()


def _now():
    return datetime.now(timezone.utc)


def _s(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_bool(name, default):
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


def norm_ip(ip):
    try:
        return str(ipaddress.ip_address(str(ip or "").strip()))
    except ValueError:
        return None


def _parse_nets(text):
    out = []
    for part in re.split(r"[,\s]+", text or ""):
        if part:
            try:
                out.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                logger.warning("shield: ignoring bad allow-list entry %r", part)
    return out


def is_allowed(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True          # unparseable: never block something we cannot name
    if a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified or a.is_reserved:
        return True
    return any(a in n for n in _allow_nets)


def _exempt(path):
    pref = tuple(p.strip() for p in os.getenv("SHIELD_EXEMPT_PREFIXES", "/webhooks/,/api/whatsapp/,/internal/").split(",") if p.strip())
    return path.startswith(pref)


def ensure_schema():
    if _ctx["ready"]:
        return
    with _lock:
        if _ctx["ready"]:
            return
        c = _conn()
        c.execute("""CREATE TABLE IF NOT EXISTS shield_blocks (
            ip TEXT PRIMARY KEY, until_ts TEXT, permanent INTEGER NOT NULL DEFAULT 0, reason TEXT, cls TEXT, offences INTEGER NOT NULL DEFAULT 1,
            country TEXT, cf_pushed INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1)""")
        c.execute("""CREATE TABLE IF NOT EXISTS shield_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, ip TEXT, kind TEXT, detail TEXT)""")
        c.execute("CREATE TABLE IF NOT EXISTS shield_allow (ip TEXT PRIMARY KEY, note TEXT, created_at TEXT)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_se_ts ON shield_events(ts)")
        c.commit()
        _ctx["ready"] = True


def _event(ip, kind, detail=""):
    try:
        c = _conn()
        c.execute("INSERT INTO shield_events (ts, ip, kind, detail) VALUES (?,?,?,?)", (_s(_now()), ip, kind, str(detail)[:500]))
        c.commit()
    except Exception:
        logger.exception("shield event write failed")


def reload_cache(force=False):
    """Every worker reads the shared tables now and then, so a block made by one worker is enforced by all of them."""
    if not force and time.time() - _cache["loaded"] < 20:
        return
    with _lock:
        _cache["loaded"] = time.time()
        try:
            ensure_schema()
            c = _conn()
            nets = _parse_nets(os.getenv("SHIELD_ALLOW_IPS", ""))
            for r in c.execute("SELECT ip FROM shield_allow").fetchall():
                nets += _parse_nets(r[0])
            _allow_nets[:] = nets
            fresh = {}
            now = time.time()
            for r in c.execute("SELECT ip, until_ts, permanent, reason, cls, cf_pushed FROM shield_blocks WHERE active = 1").fetchall():
                until = None
                if not r[2]:
                    try:
                        until = datetime.strptime(r[1], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
                    except Exception:
                        continue
                    if until <= now:
                        continue
                fresh[r[0]] = {"until": until, "reason": r[3], "cls": r[4], "cf": bool(r[5])}
            _blocks.clear()
            _blocks.update(fresh)
        except Exception:
            logger.exception("shield cache reload failed")


def is_blocked(ip):
    b = _blocks.get(ip)
    if not b:
        return False
    return b["until"] is None or b["until"] > time.time()


# ----------------------------------------------------------------------------------------------- Cloudflare
class Cloudflare:
    base = "https://api.cloudflare.com/client/v4"

    @staticmethod
    def configured():
        return bool(os.getenv("CF_API_TOKEN") and os.getenv("CF_ACCOUNT_ID"))

    @staticmethod
    def list_id():
        return os.getenv("CF_BLOCK_LIST_ID") or _ctx.get("cf_list_id") or ""

    @classmethod
    def _req(cls, method, path, body=None, timeout=8):
        req = urllib.request.Request(cls.base + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                     headers={"Authorization": "Bearer " + os.getenv("CF_API_TOKEN", ""), "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode() or "{}")
        except Exception as e:
            logger.warning("cloudflare %s %s failed: %s", method, path.split("?")[0], type(e).__name__)
            return {"success": False, "errors": [str(type(e).__name__)]}

    @classmethod
    def setup(cls):
        acct = os.getenv("CF_ACCOUNT_ID")
        found = cls._req("GET", f"/accounts/{acct}/rules/lists")
        for item in found.get("result") or []:
            if item.get("name") == "net365_blocklist":
                _ctx["cf_list_id"] = item["id"]
                return {"success": True, "list_id": item["id"], "created": False}
        made = cls._req("POST", f"/accounts/{acct}/rules/lists", {"name": "net365_blocklist", "kind": "ip", "description": "Net365 Shield: hostile IPs (managed automatically)"})
        if made.get("success"):
            _ctx["cf_list_id"] = made["result"]["id"]
            return {"success": True, "list_id": made["result"]["id"], "created": True}
        return {"success": False, "errors": made.get("errors")}

    @classmethod
    def add(cls, ip, comment):
        lid = cls.list_id()
        if not (cls.configured() and lid):
            return False
        count = _conn().execute("SELECT COUNT(*) FROM shield_blocks WHERE cf_pushed = 1 AND active = 1").fetchone()[0]
        if count >= _env_int("CF_LIST_MAX_ITEMS", 9000):
            logger.warning("shield: Cloudflare list is full (%s); not pushing %s", count, ip)
            return False
        r = cls._req("POST", f"/accounts/{os.getenv('CF_ACCOUNT_ID')}/rules/lists/{lid}/items", [{"ip": ip, "comment": comment[:200]}])
        return bool(r.get("success"))

    @classmethod
    def remove(cls, ip):
        lid = cls.list_id()
        if not (cls.configured() and lid):
            return False
        base = f"/accounts/{os.getenv('CF_ACCOUNT_ID')}/rules/lists/{lid}/items"
        found = cls._req("GET", base + "?search=" + ip)
        ids = [{"id": i["id"]} for i in (found.get("result") or []) if i.get("ip") == ip]
        if not ids:
            return True
        return bool(cls._req("DELETE", base, {"items": ids}).get("success"))


def _posthog(ip, event, props):
    key = os.getenv("POSTHOG_API_KEY")
    if not key:
        return
    def go():
        try:
            req = urllib.request.Request(os.getenv("POSTHOG_HOST", "https://us.i.posthog.com").rstrip("/") + "/capture/", method="POST",
                                         data=json.dumps({"api_key": key, "event": event, "distinct_id": "ip:" + ip, "properties": props}).encode(),
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=6).read()
        except Exception as e:
            logger.warning("posthog capture failed: %s", type(e).__name__)
    threading.Thread(target=go, daemon=True).start()


# ----------------------------------------------------------------------------------------------- alerting
def _link_secret():
    return (os.getenv("SHIELD_LINK_SECRET") or os.getenv("ADMIN_SECRET") or "").encode()


def _unblock_token(ip, exp):
    return hmac.new(_link_secret(), f"{ip}|{exp}".encode(), hashlib.sha256).hexdigest()[:40]


def _unblock_link(ip):
    base = (os.getenv("NET365_PUBLIC_URL") or "").rstrip("/")
    if not _link_secret():
        return ""
    exp = int(time.time()) + 48 * 3600
    return f"{base}/shield/unblock?ip={ip}&exp={exp}&t={_unblock_token(ip, exp)}"


def _alert(ip, reason, minutes, cls, country, org, evidence, cf_state, offences):
    send = _ctx.get("email")
    if not send:
        return
    now = time.time()
    q = _mail["sent"]
    while q and now - q[0] > 3600:
        q.popleft()
    if len(q) >= _env_int("SHIELD_EMAIL_MAX_PER_HOUR", 10):
        _mail["suppressed"] += 1
        return
    q.append(now)
    extra = ""
    if _mail["suppressed"]:
        extra = f"\n(+{_mail['suppressed']} further blocks since the last email were not emailed. See /admin/shield.)\n"
        _mail["suppressed"] = 0
    to = os.getenv("SHIELD_ALERT_EMAIL") or os.getenv("SECURITY_EMAIL") or os.getenv("SUPPORT_ALERT_EMAIL") or os.getenv("SUPPORT_EMAIL") or "support@net365co.com"
    link = _unblock_link(ip)
    body = (f"Net365 Shield blocked an IP address.\n\nIP: {ip}\nCountry: {country or 'unknown'}\nNetwork: {org or 'unknown'}\n"
            f"Reason: {reason}\nSeverity: {'HIGH (hostile tooling or probing)' if cls == 'hard' else 'LOW (looks like guessing or noise; short block)'}\n"
            f"Blocked for: {'permanently' if minutes is None else f'{minutes} minutes'}  (offence number {offences})\nCloudflare edge block: {cf_state}\n\n"
            f"Evidence:\n{evidence}\n{extra}\n"
            + (f"If this is a customer or your own system, unblock it here (valid 48 hours):\n{link}\n" if link else "To unblock, open /admin/shield.\n"))
    try:
        send(to, f"[Net365 Shield] Blocked {ip} ({'high' if cls == 'hard' else 'low'}): {reason}", body)
    except Exception:
        logger.exception("shield alert email failed")


# ----------------------------------------------------------------------------------------------- blocking
def block_ip(ip, reason, cls="hard", minutes=None, permanent=False, evidence="", country=None, org=None, actor="shield", alert=True):
    """Block now. minutes=None picks the escalating default for this IP (1st/2nd/3rd offence). Returns the block record or None."""
    ip = norm_ip(ip)
    if not ip or is_allowed(ip):
        return None
    ensure_schema()
    with _lock:
        c = _conn()
        row = c.execute("SELECT offences, active, until_ts, permanent FROM shield_blocks WHERE ip = ?", (ip,)).fetchone()
        if row and row[1] and (row[3] or (row[2] and row[2] > _s(_now()))) and not permanent and actor == "shield":
            return _blocks.get(ip)                      # already blocked: do not stack offences on a refused IP
        offences = (row[0] + 1) if row else 1
        if permanent:
            minutes = None
        elif minutes is None:
            table = DURATIONS_HARD if cls == "hard" else DURATIONS_SOFT
            minutes = table[min(offences, len(table)) - 1]
        until_ts = None if permanent else _s(_now() + timedelta(minutes=minutes))
        push_cf = permanent or cls == "hard" or offences >= 2
        c.execute("INSERT INTO shield_blocks (ip, until_ts, permanent, reason, cls, offences, country, cf_pushed, created_at, updated_at, active) VALUES (?,?,?,?,?,?,?,0,?,?,1) "
                  "ON CONFLICT(ip) DO UPDATE SET until_ts=excluded.until_ts, permanent=excluded.permanent, reason=excluded.reason, cls=excluded.cls, "
                  "offences=excluded.offences, country=excluded.country, updated_at=excluded.updated_at, active=1",
                  (ip, until_ts, 1 if permanent else 0, reason[:200], cls, offences, country, _s(_now()), _s(_now())))
        c.commit()
        _blocks[ip] = {"until": None if permanent else time.time() + minutes * 60, "reason": reason, "cls": cls, "cf": False}
    _event(ip, "block", f"{actor}: {reason} ({cls}, {'permanent' if permanent else str(minutes) + 'm'}, offence {offences})")
    logger.warning("SHIELD blocked %s: %s (%s, %s)", ip, reason, cls, "permanent" if permanent else f"{minutes}m")

    def after():
        cf_state = "not used (soft evidence stays local)" if not push_cf else "not configured"
        if push_cf and Cloudflare.configured() and Cloudflare.list_id():
            ok = Cloudflare.add(ip, f"{reason} {_s(_now())}")
            cf_state = "pushed: blocked at the edge" if ok else "FAILED (still blocked in the app)"
            if ok:
                try:
                    cc = _conn(); cc.execute("UPDATE shield_blocks SET cf_pushed = 1 WHERE ip = ?", (ip,)); cc.commit()
                    _blocks.get(ip, {})["cf"] = True
                except Exception:
                    pass
        _posthog(ip, "security_block", {"reason": reason, "class": cls, "minutes": minutes, "permanent": permanent, "offences": offences, "country": country, "network": org,
                                         "cloudflare": cf_state, "actor": actor, "$process_person_profile": False})
        if alert:
            _alert(ip, reason, minutes, cls, country, org, evidence or reason, cf_state, offences)
    threading.Thread(target=after, daemon=True).start()
    return _blocks.get(ip)


def unblock_ip(ip, actor="admin"):
    ip = norm_ip(ip)
    if not ip:
        return False
    ensure_schema()
    with _lock:
        c = _conn()
        c.execute("UPDATE shield_blocks SET active = 0, updated_at = ? WHERE ip = ?", (_s(_now()), ip))
        c.commit()
        _blocks.pop(ip, None)
        _score.pop(ip, None)
    _event(ip, "unblock", actor)
    threading.Thread(target=Cloudflare.remove, args=(ip,), daemon=True).start()
    return True


def _sweep_loop():
    """Expire blocks (locally and at Cloudflare). Offence counts are kept so a returning IP is blocked for longer."""
    while True:
        time.sleep(60)
        try:
            ensure_schema()
            c = _conn()
            rows = c.execute("SELECT ip, cf_pushed FROM shield_blocks WHERE active = 1 AND permanent = 0 AND until_ts <= ?", (_s(_now()),)).fetchall()
            for ip, cf in rows:
                c.execute("UPDATE shield_blocks SET active = 0, updated_at = ? WHERE ip = ?", (_s(_now()), ip))
                c.commit()
                _blocks.pop(ip, None)
                if cf:
                    Cloudflare.remove(ip)
                _event(ip, "expired", "")
            c.execute("DELETE FROM shield_events WHERE ts < ?", (_s(_now() - timedelta(days=60)),))
            c.commit()
        except Exception:
            logger.exception("shield sweep failed")


# ----------------------------------------------------------------------------------------------- scoring
def note(ip, label, evidence, country=None, org=None):
    """Add points for hostile behaviour; block when the recent total crosses the threshold."""
    if is_allowed(ip) or is_blocked(ip):
        return
    now = time.time()
    win = _env_int("SHIELD_WINDOW_SECONDS", 600)
    with _lock:
        q = _score[ip]
        q.append((now, POINTS[label], label, evidence))
        while q and now - q[0][0] > win:
            q.popleft()
        if len(_score) > 20000:                       # bound memory
            for k in list(_score)[:5000]:
                _score.pop(k, None)
        total = sum(p for _, p, _, _ in q)
        if total < _env_int("SHIELD_THRESHOLD", 100):
            return
        labels = [lb for _, _, lb, _ in q]
        hard = any(lb in HARD_LABELS for lb in labels)
        lines = "\n".join(f"  {datetime.fromtimestamp(t, timezone.utc).strftime('%H:%M:%S')}  {lb}  {ev}" for t, _, lb, ev in list(q)[-12:])
        reason = ("Hostile probing" if hard else "Repeated failures") + ": " + ", ".join(sorted(set(labels)))
        _score.pop(ip, None)
    block_ip(ip, reason, "hard" if hard else "soft", evidence=f"{total} points in {win // 60} minutes.\n{lines}", country=country, org=org)


def _inspect_request(ip, path, query, ua, method, status, country):
    if _exempt(path):
        return
    ev = f"{method} {path[:120]} -> {status}"
    if ua and TOOL_RE.search(ua):
        note(ip, "attack_tool", ev + f" UA={ua[:60]}", country)
        return
    if SCANNER_RE.search(path):
        note(ip, "scanner_path", ev, country)
        return
    if query and PAYLOAD_RE.search(unquote_plus(query)[:600]):
        note(ip, "payload", ev + " (injection pattern in the URL)", country)
        return
    if method == "POST" and path == "/api/auth/login" and status in (400, 401, 403):
        note(ip, "login_fail", ev, country)
    elif method == "POST" and path.startswith("/api/auth/verify") and status in (400, 401, 403):
        note(ip, "otp_fail", ev, country)
    elif status == 429:
        note(ip, "rate_limited", ev, country)
    elif status == 404 and not path.startswith("/static/"):
        note(ip, "not_found", ev, country)


# ----------------------------------------------------------------------------------------------- init
def init_shield(app, db_module, admin_required, get_client_ip, send_email_fn=None):
    _ctx.update(db=db_module, email=send_email_fn, get_ip=get_client_ip)
    if not _env_bool("SHIELD_ENABLED", True):
        logger.info("shield disabled (SHIELD_ENABLED=false)")
        return
    try:
        ensure_schema(); reload_cache(force=True)
    except Exception as e:
        logger.warning("shield tables not ready: %s", e)
        return
    threading.Thread(target=_sweep_loop, daemon=True).start()
    enforce = lambda: _env_bool("SHIELD_ENFORCE", True)

    @app.before_request
    def _shield_before():
        try:
            reload_cache()
            ip = norm_ip(get_client_ip())
            if ip and enforce() and is_blocked(ip) and not _exempt(request.path) and request.path != "/shield/unblock":
                if request.path.startswith("/api/"):
                    return jsonify({"success": False, "error": "Access denied."}), 403
                return make_response("Access denied.", 403)
        except Exception:
            logger.debug("shield before_request failed", exc_info=True)
        return None

    @app.after_request
    def _shield_after(resp):
        try:
            ip = norm_ip(get_client_ip())
            if ip and resp.status_code != 403:
                _inspect_request(ip, request.path, request.query_string.decode("latin-1")[:800], request.headers.get("User-Agent", ""),
                                 request.method, resp.status_code, request.headers.get("CF-IPCountry"))
        except Exception:
            logger.debug("shield after_request failed", exc_info=True)
        return resp

    # ---- one-click unblock from the alert email (a page, then a POST: a link alone never changes anything)
    def _valid_link(ip, exp, t):
        try:
            return _link_secret() and int(exp) > time.time() and hmac.compare_digest(_unblock_token(ip, int(exp)), t or "")
        except Exception:
            return False

    @shield_bp.route("/shield/unblock", methods=["GET", "POST"])
    def unblock_page():
        ip, exp, t = norm_ip(request.values.get("ip")), request.values.get("exp"), request.values.get("t")
        if not ip or not _valid_link(ip, exp, t):
            return make_response("This link is invalid or has expired. Open /admin/shield instead.", 400)
        if request.method == "POST":
            unblock_ip(ip, actor="email-link")
            return make_response(f"{html.escape(ip)} has been unblocked.", 200)
        page = (f"<!doctype html><meta name=viewport content='width=device-width'><body style='font-family:sans-serif;max-width:420px;margin:40px auto;padding:0 16px'>"
                f"<h3>Unblock {html.escape(ip)}?</h3><form method=post><input type=hidden name=ip value='{html.escape(ip)}'><input type=hidden name=exp value='{html.escape(str(exp))}'>"
                f"<input type=hidden name=t value='{html.escape(t)}'><button style='padding:12px 18px;font-size:16px'>Yes, unblock</button></form></body>")
        r = make_response(page); r.headers["Cache-Control"] = "no-store"; return r

    # ---- admin API
    def actor():
        return re.sub(r"[^A-Za-z0-9 ._@-]", "", request.headers.get("X-Admin-Actor", ""))[:40] or "admin"

    @shield_bp.route("/api/admin/shield/status", methods=["GET"])
    @admin_required
    def sh_status():
        reload_cache(force=True)
        c = _conn()
        one = lambda sql, a=(): c.execute(sql, a).fetchone()[0] or 0
        day = _s(_now() - timedelta(hours=24))
        return jsonify({"success": True, "enforcing": enforce(), "active_blocks": len(_blocks), "blocked_24h": one("SELECT COUNT(*) FROM shield_events WHERE kind='block' AND ts >= ?", (day,)),
                        "cloudflare": {"configured": Cloudflare.configured(), "list_id": bool(Cloudflare.list_id()), "pushed": one("SELECT COUNT(*) FROM shield_blocks WHERE cf_pushed=1 AND active=1")},
                        "posthog": bool(os.getenv("POSTHOG_API_KEY")), "email_to": bool(os.getenv("SHIELD_ALERT_EMAIL") or os.getenv("SECURITY_EMAIL") or os.getenv("SUPPORT_EMAIL")),
                        "threshold": _env_int("SHIELD_THRESHOLD", 100), "allow_entries": len(_allow_nets)})

    @shield_bp.route("/api/admin/shield/blocks", methods=["GET"])
    @admin_required
    def sh_blocks():
        rows = _conn().execute("SELECT ip, until_ts, permanent, reason, cls, offences, country, cf_pushed, created_at FROM shield_blocks WHERE active = 1 ORDER BY updated_at DESC LIMIT 300").fetchall()
        keys = ("ip", "until", "permanent", "reason", "class", "offences", "country", "cloudflare", "since")
        return jsonify({"success": True, "blocks": [dict(zip(keys, tuple(r))) for r in rows]})

    @shield_bp.route("/api/admin/shield/events", methods=["GET"])
    @admin_required
    def sh_events():
        rows = _conn().execute("SELECT ts, ip, kind, detail FROM shield_events ORDER BY id DESC LIMIT ?", (max(1, min(500, request.args.get("limit", 100, type=int))),)).fetchall()
        return jsonify({"success": True, "events": [dict(zip(("ts", "ip", "kind", "detail"), tuple(r))) for r in rows]})

    @shield_bp.route("/api/admin/shield/block", methods=["POST"])
    @admin_required
    def sh_block():
        d = request.get_json(silent=True) or {}
        ip = norm_ip(d.get("ip"))
        if not ip:
            return jsonify({"success": False, "error": "bad_ip"}), 400
        if is_allowed(ip):
            return jsonify({"success": False, "error": "allow_listed_or_private"}), 409
        mins = d.get("minutes")
        rec = block_ip(ip, str(d.get("reason") or "Blocked by an administrator")[:150], "hard", minutes=int(mins) if str(mins or "").isdigit() else None,
                       permanent=bool(d.get("permanent")), actor=actor(), alert=False)
        return jsonify({"success": bool(rec), "block": bool(rec)})

    @shield_bp.route("/api/admin/shield/unblock", methods=["POST"])
    @admin_required
    def sh_unblock():
        ok = unblock_ip((request.get_json(silent=True) or {}).get("ip"), actor=actor())
        return jsonify({"success": ok}), (200 if ok else 400)

    @shield_bp.route("/api/admin/shield/allow", methods=["GET", "POST", "DELETE"])
    @admin_required
    def sh_allow():
        c = _conn()
        if request.method == "GET":
            return jsonify({"success": True, "allow": [dict(zip(("ip", "note", "created_at"), tuple(r))) for r in c.execute("SELECT ip, note, created_at FROM shield_allow").fetchall()],
                            "from_env": os.getenv("SHIELD_ALLOW_IPS", "")})
        d = request.get_json(silent=True) or {}
        try:
            net = str(ipaddress.ip_network(str(d.get("ip") or "").strip(), strict=False))
        except ValueError:
            return jsonify({"success": False, "error": "bad_ip"}), 400
        if request.method == "POST":
            c.execute("INSERT OR REPLACE INTO shield_allow (ip, note, created_at) VALUES (?,?,?)", (net, str(d.get("note") or "")[:100], _s(_now())))
        else:
            c.execute("DELETE FROM shield_allow WHERE ip = ?", (net,))
        c.commit(); reload_cache(force=True)
        _event(net, "allow_" + ("add" if request.method == "POST" else "remove"), actor())
        return jsonify({"success": True})

    @shield_bp.route("/api/admin/shield/cloudflare/setup", methods=["POST"])
    @admin_required
    def sh_cf_setup():
        if not Cloudflare.configured():
            return jsonify({"success": False, "error": "set CF_API_TOKEN and CF_ACCOUNT_ID first"}), 400
        r = Cloudflare.setup()
        if r.get("success"):
            r["next"] = ("Set CF_BLOCK_LIST_ID=" + r["list_id"] + " in your environment, then in Cloudflare: Security > WAF > Custom rules > Create rule: "
                         "expression (ip.src in $net365_blocklist), action Block. Put your own IPs in SHIELD_ALLOW_IPS first.")
        return jsonify(r), (200 if r.get("success") else 502)

    @shield_bp.route("/api/admin/shield/test-email", methods=["POST"])
    @admin_required
    def sh_test_email():
        _alert("203.0.113.9", "Test alert (nothing was blocked)", 60, "hard", "NG", "Example network", "This is a test from /admin/shield.", "not applicable", 1)
        return jsonify({"success": True})

    @shield_bp.route("/admin/shield", methods=["GET"])
    def sh_page():
        r = make_response(DESK_HTML); r.headers["Content-Type"] = "text/html; charset=utf-8"; r.headers["Cache-Control"] = "no-store"; return r

    app.register_blueprint(shield_bp)
    logger.info("Net365 Shield active (enforce=%s, cloudflare=%s, posthog=%s)", enforce(), Cloudflare.configured(), bool(os.getenv("POSTHOG_API_KEY")))


DESK_HTML = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Net365 Shield</title>
<style>:root{--bg:#f5f6f8;--c:#fff;--t:#1e293b;--m:#64748b;--l:#e2e8f0}@media(prefers-color-scheme:dark){:root{--bg:#121214;--c:#1c1c20;--t:#e8e8ec;--m:#9a9aa6;--l:#2c2c34}}
body{margin:0;background:var(--bg);color:var(--t);font:14px -apple-system,Segoe UI,Roboto,sans-serif}main{max-width:1000px;margin:0 auto;padding:16px}
.card{background:var(--c);border:1px solid var(--l);border-radius:12px;padding:14px;margin-bottom:14px}h2{margin:0 0 10px;font-size:16px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:7px 6px;border-bottom:1px solid var(--l);vertical-align:top}th{color:var(--m);font-weight:600}
input,button{font:inherit;padding:8px 10px;border-radius:8px;border:1px solid var(--l);background:var(--c);color:var(--t)}button{cursor:pointer;font-weight:600}.go{background:#E53935;color:#fff;border-color:#E53935}
.k{display:flex;gap:10px;flex-wrap:wrap}.k div{flex:1;min-width:120px}.k b{font-size:22px;display:block}.m{color:var(--m)}.hi{color:#c93434;font-weight:700}.ok{color:#16803c;font-weight:700}</style></head><body><main>
<div class=card><h2>Net365 Shield</h2><div id=gate><input id=sec type=password placeholder="Admin secret" autocomplete=off> <button class=go id=in>Open</button></div><div id=st class=k></div><p class=m id=cfg></p></div>
<div class=card><h2>Blocked now</h2><div style="overflow:auto"><table id=bl></table></div>
<p><input id=nip placeholder="IP to block"> <input id=nr placeholder="Reason"> <button id=nb class=go>Block 24h</button> <button id=np>Block permanently</button></p></div>
<div class=card><h2>Never block (allow-list)</h2><div id=al class=m></div><p><input id=aip placeholder="IP or range, e.g. 41.58.0.0/16"> <input id=an placeholder="Note"> <button id=ab>Add</button></p></div>
<div class=card><h2>Recent activity</h2><div style="overflow:auto"><table id=ev></table></div><p><button id=te>Send a test alert email</button> <button id=cs>Set up Cloudflare list</button></p></div></main>
<script>
var S=sessionStorage.getItem('n365adm')||'';var $=function(i){return document.getElementById(i)};
function api(p,o){o=o||{};o.headers={'X-Admin-Secret':S,'Content-Type':'application/json','X-Admin-Actor':'shield-desk'};return fetch(p,o).then(function(r){return r.json().then(function(d){return{ok:r.ok,d:d}})})}
function row(t,cells){var tr=document.createElement('tr');cells.forEach(function(c){var td=document.createElement(t);if(c&&c.nodeType)td.appendChild(c);else td.textContent=c==null?'':c;tr.appendChild(td)});return tr}
function fill(id,head,rows){var t=$(id);while(t.firstChild)t.removeChild(t.firstChild);t.appendChild(row('th',head));rows.forEach(function(r){t.appendChild(row('td',r))})}
function btn(label,fn){var b=document.createElement('button');b.textContent=label;b.onclick=fn;return b}
function load(){api('/api/admin/shield/status').then(function(r){if(!r.ok){$('gate').style.display='';return}$('gate').style.display='none';var d=r.d;$('st').textContent='';
[['Blocked now',d.active_blocks],['Blocked in 24h',d.blocked_24h],['At Cloudflare',d.cloudflare.pushed],['Mode',d.enforcing?'Enforcing':'Watch only']].forEach(function(x){var e=document.createElement('div'),b=document.createElement('b');b.textContent=x[1];e.appendChild(b);e.appendChild(document.createTextNode(x[0]));$('st').appendChild(e)});
$('cfg').textContent='Cloudflare: '+(d.cloudflare.configured?(d.cloudflare.list_id?'connected':'token set, list not set up'):'not configured')+' | PostHog: '+(d.posthog?'on':'off')+' | Alert email: '+(d.email_to?'set':'default')+' | Threshold: '+d.threshold+' points';
api('/api/admin/shield/blocks').then(function(r){fill('bl',['IP','Why','Class','Offences','Until','Edge',''],r.d.blocks.map(function(b){return[b.ip,b.reason,b['class'],b.offences,b.permanent?'permanent':b.until,b.cloudflare?'yes':'no',btn('Unblock',function(){api('/api/admin/shield/unblock',{method:'POST',body:JSON.stringify({ip:b.ip})}).then(load)})]}))});
api('/api/admin/shield/allow').then(function(r){$('al').textContent=(r.d.from_env?'From environment: '+r.d.from_env+'. ':'')+(r.d.allow.length?'':'No entries added here yet.');r.d.allow.forEach(function(a){var s=document.createElement('span');s.textContent=a.ip+(a.note?' ('+a.note+')':'')+' ';s.appendChild(btn('x',function(){api('/api/admin/shield/allow',{method:'DELETE',body:JSON.stringify({ip:a.ip})}).then(load)}));$('al').appendChild(s);$('al').appendChild(document.createTextNode('  '))})});
api('/api/admin/shield/events?limit=60').then(function(r){fill('ev',['Time (UTC)','IP','What','Detail'],r.d.events.map(function(e){return[e.ts,e.ip,e.kind,e.detail]}))})})}
$('in').onclick=function(){S=$('sec').value;sessionStorage.setItem('n365adm',S);load()};
$('nb').onclick=function(){api('/api/admin/shield/block',{method:'POST',body:JSON.stringify({ip:$('nip').value,reason:$('nr').value,minutes:1440})}).then(function(r){if(!r.ok)alert(r.d.error||'failed');load()})};
$('np').onclick=function(){api('/api/admin/shield/block',{method:'POST',body:JSON.stringify({ip:$('nip').value,reason:$('nr').value,permanent:true})}).then(function(r){if(!r.ok)alert(r.d.error||'failed');load()})};
$('ab').onclick=function(){api('/api/admin/shield/allow',{method:'POST',body:JSON.stringify({ip:$('aip').value,note:$('an').value})}).then(function(r){if(!r.ok)alert('Not a valid IP or range');load()})};
$('te').onclick=function(){api('/api/admin/shield/test-email',{method:'POST'}).then(function(){alert('Test email sent')})};
$('cs').onclick=function(){api('/api/admin/shield/cloudflare/setup',{method:'POST'}).then(function(r){alert(r.d.next||JSON.stringify(r.d))})};
if(S)load();
</script></body></html>"""

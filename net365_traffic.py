"""net365_traffic.py - request-level traffic analytics and abuse monitoring for Net365.

What it adds (all additive; a failure here never breaks a customer request):

  * request_log table: one row per request with timestamp, IP, User-Agent, method, HTTP status,
    requested URL, session id, referrer, response time, ASN and a bot classification.
  * Separate human / automated classification (human | bot | suspicious).
  * Rate limiting on login/auth endpoints (shared across workers) and a generous per-IP limit on
    the rest of /api (per worker).
  * Repeated 404/403 monitoring per IP, with an optional temporary auto-block.
  * Metadata-only logging of POST/PUT/PATCH/DELETE to sensitive endpoints. Request bodies are
    never stored.
  * /api/admin/traffic/* JSON endpoints and the /admin/traffic dashboard page.

Environment (all optional):
  TRAFFIC_LOG_ENABLED=true          master switch for logging
  TRAFFIC_RETENTION_DAYS=30         rows older than this are purged
  TRAFFIC_LOG_STATIC=false          also log css/js/images/fonts
  TRAFFIC_RATE_LIMIT=true           master switch for the limiter
  TRAFFIC_AUTH_RPM=20               auth endpoints, requests per minute per IP (shared store)
  TRAFFIC_API_RPM=600               other /api endpoints, requests per minute per IP (per worker)
  TRAFFIC_ERR_THRESHOLD=15          404+403 count within TRAFFIC_ERR_WINDOW_MIN that flags an IP
  TRAFFIC_ERR_WINDOW_MIN=10
  TRAFFIC_AUTOBLOCK_MIN=0           >0: block a flagged IP for this many minutes (0 = monitor only)
  TRAFFIC_ASN_URL=https://ipwho.is/{ip}   ASN lookup endpoint (JSON with connection.asn / .org)
  TRAFFIC_ASN_ENABLED=true
"""

import ipaddress
import json
import os
import queue
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from flask import jsonify, request, g, send_from_directory

SID_COOKIE = "n365_sid"  # our own analytics id. Deliberately NOT the login cookie.

SENSITIVE_PREFIXES = (
    "/api/auth/", "/api/payment/", "/api/public/payment/", "/api/public/topup/", "/api/cart/",
    "/api/wallet/", "/api/utilities/pay", "/api/utilities/confirm", "/api/bulk/", "/api/admin/",
    "/api/giftcards/", "/api/user/", "/webhooks/", "/api/whatsapp/", "/api/business/",
)
AUTH_PATHS = (
    "/api/auth/login", "/api/auth/register", "/api/auth/forgot", "/api/auth/reset",
    "/api/auth/verify", "/api/auth/resend", "/api/auth/google", "/api/auth/otp",
)
RATE_EXEMPT_PREFIXES = ("/webhooks/", "/api/admin/", "/payment/", "/static/")
STATIC_RE = re.compile(r"\.(css|js|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|otf|mp4|webm|json|txt|xml)$", re.I)
SENSITIVE_QS_KEYS = re.compile(r"(token|pass|secret|key|code|otp|pin|auth|session|signature)", re.I)

SCANNER_PATH_RE = re.compile(
    r"(/\.env|/\.git|/wp-(login|admin|content|includes)|/xmlrpc\.php|/phpmyadmin|/pma/|/cgi-bin|/boaform|"
    r"/actuator|/vendor/phpunit|/config\.(php|json|yml)|/\.aws|/\.ssh|/server-status|/admin\.php|"
    r"/shell|/eval-stdin|/solr/|/console/?$|/etc/passwd|\.\./|/backup\.(sql|zip|tar)|/db\.sql)", re.I)
AUTOMATION_UA_RE = re.compile(
    r"(curl/|wget/|python-requests|python-urllib|httpx|aiohttp|go-http-client|java/|okhttp/[\d.]+$|"
    r"libwww|scrapy|node-fetch|axios/|got \(|postman|insomnia|headlesschrome|phantomjs|selenium|"
    r"puppeteer|playwright|httpclient|masscan|nmap|nikto|sqlmap|zgrab|nuclei|dirbuster|gobuster|"
    r"bot\b|crawler|spider|slurp|scanner)", re.I)

_Q = queue.Queue(maxsize=20000)
_state = {"started": False, "lock": threading.Lock(), "table_ready": False}
_asn_cache = {}          # ip -> (asn, org, expires)
_asn_pending = set()
_api_hits = {}           # per-worker sliding window for general /api limiter
_api_lock = threading.Lock()
_blocked = {}            # ip -> unix expiry (per worker)
_blocked_lock = threading.Lock()


def _env_bool(name, default):
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _env_int(name, default):
    try:
        return int(float(os.getenv(name, default)))
    except (TypeError, ValueError):
        return int(default)


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_reserved or a.is_link_local
    except ValueError:
        return True


# ---------------------------------------------------------------- classification
def classify(ua, path, detect_bot=None):
    """Return (bot_class, bot_name, reason). bot_class: human | bot | suspicious."""
    ua = ua or ""
    if SCANNER_PATH_RE.search(path or ""):
        return "suspicious", "scanner", "probe path"
    if detect_bot:
        try:
            is_bot, name = detect_bot(ua)
            if is_bot:
                return "bot", name or "bot", "known bot signature"
        except Exception:
            pass
    if not ua.strip():
        return "bot", "no-user-agent", "empty user agent"
    m = AUTOMATION_UA_RE.search(ua)
    if m:
        return "bot", m.group(1).strip("/ ").lower()[:30], "automation user agent"
    if len(ua) < 20:
        return "suspicious", "short-user-agent", "implausibly short user agent"
    return "human", None, ""


def _clean_url(path, query_string):
    """Path plus query with values of sensitive keys removed (tokens, codes, passwords)."""
    if not query_string:
        return path[:500]
    parts = []
    for kv in query_string.split("&")[:20]:
        k, _, v = kv.partition("=")
        parts.append(f"{k}=[redacted]" if SENSITIVE_QS_KEYS.search(k) else kv[:80])
    return (path + "?" + "&".join(parts))[:500]


def _is_sensitive(method, path):
    if method not in ("POST", "PUT", "PATCH", "DELETE"):
        return False
    return path.startswith(SENSITIVE_PREFIXES)


# ---------------------------------------------------------------- storage
_SCHEMA = """
CREATE TABLE IF NOT EXISTS request_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    method TEXT,
    status INTEGER,
    url TEXT,
    session_id TEXT,
    referrer TEXT,
    response_ms INTEGER,
    asn TEXT,
    asn_org TEXT,
    bot_class TEXT,
    bot_name TEXT,
    bot_reason TEXT,
    country TEXT,
    user_id INTEGER,
    sensitive INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_reqlog_ts ON request_log(ts);
CREATE INDEX IF NOT EXISTS idx_reqlog_ip_ts ON request_log(ip, ts);
CREATE INDEX IF NOT EXISTS idx_reqlog_status_ts ON request_log(status, ts);
CREATE TABLE IF NOT EXISTS ip_asn (
    ip TEXT PRIMARY KEY, asn TEXT, org TEXT, fetched_at TEXT
);
CREATE TABLE IF NOT EXISTS traffic_blocks (
    ip TEXT PRIMARY KEY, until_ts TEXT, reason TEXT, created_at TEXT
);
"""


def _ensure_tables(get_conn):
    if _state["table_ready"]:
        return
    conn = get_conn()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
        _state["table_ready"] = True
    finally:
        conn.close()


def _writer(get_conn, logger):
    last_purge = 0.0
    while True:
        batch = []
        try:
            batch.append(_Q.get(timeout=5))
            while len(batch) < 200:
                batch.append(_Q.get_nowait())
        except queue.Empty:
            pass
        if batch:
            try:
                conn = get_conn()
                try:
                    conn.executemany(
                        "INSERT INTO request_log (ts, ip, user_agent, method, status, url, session_id, referrer, "
                        "response_ms, asn, asn_org, bot_class, bot_name, bot_reason, country, user_id, sensitive) "
                        "VALUES (:ts,:ip,:user_agent,:method,:status,:url,:session_id,:referrer,:response_ms,"
                        ":asn,:asn_org,:bot_class,:bot_name,:bot_reason,:country,:user_id,:sensitive)",
                        batch,
                    )
                    conn.commit()
                finally:
                    conn.close()
            except Exception as e:
                logger.warning(f"traffic: could not write {len(batch)} rows: {e}")
        if time.time() - last_purge > 3600:
            last_purge = time.time()
            try:
                days = max(1, _env_int("TRAFFIC_RETENTION_DAYS", 30))
                conn = get_conn()
                try:
                    conn.execute("DELETE FROM request_log WHERE ts < datetime('now', ?)", (f"-{days} days",))
                    conn.execute("DELETE FROM traffic_blocks WHERE until_ts < datetime('now')")
                    conn.commit()
                finally:
                    conn.close()
            except Exception as e:
                logger.debug(f"traffic: purge failed: {e}")


def _asn_lookup_worker(get_conn, logger):
    """Resolve ASN for IPs seen in traffic, one at a time, cached in ip_asn for 30 days."""
    import requests
    url_tpl = os.getenv("TRAFFIC_ASN_URL", "https://ipwho.is/{ip}")
    while True:
        try:
            ip = _asn_pending_q.get(timeout=10)
        except queue.Empty:
            continue
        try:
            r = requests.get(url_tpl.format(ip=ip), timeout=5)
            j = r.json() if r.status_code == 200 else {}
            conn_info = j.get("connection") or {}
            asn = conn_info.get("asn") or j.get("asn") or ""
            org = conn_info.get("org") or conn_info.get("isp") or j.get("org") or ""
            asn = f"AS{asn}" if str(asn).isdigit() else str(asn or "")
            _asn_cache[ip] = (asn, org, time.time() + 86400)
            conn = get_conn()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO ip_asn (ip, asn, org, fetched_at) VALUES (?,?,?,datetime('now'))",
                    (ip, asn, org),
                )
                if asn:
                    conn.execute(
                        "UPDATE request_log SET asn=?, asn_org=? WHERE ip=? AND asn IS NULL "
                        "AND ts >= datetime('now','-2 days')", (asn, org, ip))
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"traffic: ASN lookup failed for {ip}: {e}")
            _asn_cache[ip] = ("", "", time.time() + 900)
        finally:
            _asn_pending.discard(ip)
            time.sleep(0.4)  # be polite to the free lookup service


_asn_pending_q = queue.Queue(maxsize=500)


def _asn_for(ip, get_conn):
    """Cached ASN, or None (and a background lookup is queued)."""
    if not ip or _is_private(ip) or not _env_bool("TRAFFIC_ASN_ENABLED", True):
        return None, None
    hit = _asn_cache.get(ip)
    if hit and hit[2] > time.time():
        return (hit[0] or None), (hit[1] or None)
    try:
        conn = get_conn()
        try:
            row = conn.execute(
                "SELECT asn, org FROM ip_asn WHERE ip=? AND fetched_at >= datetime('now','-30 days')", (ip,)
            ).fetchone()
        finally:
            conn.close()
        if row:
            _asn_cache[ip] = (row[0] or "", row[1] or "", time.time() + 86400)
            return (row[0] or None), (row[1] or None)
    except Exception:
        pass
    if ip not in _asn_pending:
        try:
            _asn_pending.add(ip)
            _asn_pending_q.put_nowait(ip)
        except queue.Full:
            _asn_pending.discard(ip)
    return None, None


# ---------------------------------------------------------------- rate limiting / blocking
def _is_blocked(ip):
    with _blocked_lock:
        exp = _blocked.get(ip)
        if exp and exp > time.time():
            return True
        if exp:
            _blocked.pop(ip, None)
    return False


def _block(ip, minutes):
    with _blocked_lock:
        _blocked[ip] = time.time() + minutes * 60


def _api_hit(ip, limit, window=60):
    now = time.time()
    with _api_lock:
        arr = [t for t in _api_hits.get(ip, []) if now - t < window]
        arr.append(now)
        _api_hits[ip] = arr
        if len(_api_hits) > 5000:  # bound memory
            for k in list(_api_hits)[:1000]:
                _api_hits.pop(k, None)
        return len(arr) > limit


# ---------------------------------------------------------------- init
def init_traffic(app, get_db_connection, admin_required, get_client_ip, get_user=None,
                 rate_hit_db=None, detect_bot=None, logger=None, auth_cookie_name=None):
    import logging
    logger = logger or logging.getLogger(__name__)

    try:
        _ensure_tables(get_db_connection)
    except Exception as e:
        logger.warning(f"traffic: tables not ready, analytics disabled: {e}")
        return

    if not _state["started"]:
        with _state["lock"]:
            if not _state["started"]:
                _state["started"] = True
                threading.Thread(target=_writer, args=(get_db_connection, logger), daemon=True).start()
                if _env_bool("TRAFFIC_ASN_ENABLED", True):
                    threading.Thread(target=_asn_lookup_worker, args=(get_db_connection, logger), daemon=True).start()

    log_enabled = _env_bool("TRAFFIC_LOG_ENABLED", True)
    limit_enabled = _env_bool("TRAFFIC_RATE_LIMIT", True)
    log_static = _env_bool("TRAFFIC_LOG_STATIC", False)

    @app.before_request
    def _traffic_before():
        g._t0 = time.perf_counter()
        path = request.path
        try:
            ip = get_client_ip()
            g._ip = ip
            if _is_blocked(ip) and not path.startswith("/api/admin/"):
                return jsonify({"success": False, "error": "Too many suspicious requests. Try again later."}), 429
            if not limit_enabled or request.method == "OPTIONS":
                return None
            if path.startswith(RATE_EXEMPT_PREFIXES) or not path.startswith("/api/"):
                return None
            if request.method == "POST" and path.startswith(AUTH_PATHS):
                limit = _env_int("TRAFFIC_AUTH_RPM", 20)
                try:
                    over = rate_hit_db(f"{ip}|auth", 60) > limit if rate_hit_db else _api_hit(f"auth|{ip}", limit)
                except Exception:
                    over = _api_hit(f"auth|{ip}", limit)
                if over:
                    resp = jsonify({"success": False, "error": "Too many attempts. Please wait a minute and try again."})
                    resp.headers["Retry-After"] = "60"
                    return resp, 429
            elif _api_hit(f"api|{ip}", _env_int("TRAFFIC_API_RPM", 600)):
                resp = jsonify({"success": False, "error": "Too many requests. Please slow down."})
                resp.headers["Retry-After"] = "60"
                return resp, 429
        except Exception as e:
            logger.debug(f"traffic before_request failed: {e}")
        return None

    @app.after_request
    def _traffic_after(response):
        try:
            if not log_enabled:
                return response
            path = request.path
            if path.startswith("/api/admin/traffic"):
                return response  # the dashboard polling itself would drown the log
            if not log_static and STATIC_RE.search(path) and response.status_code < 400:
                return response

            sid = request.cookies.get(SID_COOKIE)
            if not sid:
                sid = secrets.token_urlsafe(12)
                response.set_cookie(SID_COOKIE, sid, max_age=60 * 60 * 24 * 365, httponly=True,
                                    samesite="Lax", secure=request.is_secure)

            ip = getattr(g, "_ip", None) or get_client_ip()
            ua = request.headers.get("User-Agent", "")[:400]
            cls, bot_name, reason = classify(ua, path, detect_bot)
            asn, org = _asn_for(ip, get_db_connection)

            user_id = None
            if _is_sensitive(request.method, path) and get_user:
                try:
                    u = get_user()
                    user_id = (u or {}).get("id")
                except Exception:
                    user_id = None

            ref = request.headers.get("Referer", "")
            if ref:  # drop query strings from referrers; they can carry tokens
                p = urlsplit(ref)
                ref = f"{p.scheme}://{p.netloc}{p.path}"[:300]

            ms = int((time.perf_counter() - getattr(g, "_t0", time.perf_counter())) * 1000)
            row = {
                "ts": _now_iso(), "ip": ip, "user_agent": ua, "method": request.method,
                "status": response.status_code, "url": _clean_url(path, request.query_string.decode("latin-1")),
                "session_id": sid, "referrer": ref, "response_ms": ms, "asn": asn, "asn_org": org,
                "bot_class": cls, "bot_name": bot_name, "bot_reason": reason,
                "country": request.headers.get("CF-IPCountry") or None, "user_id": user_id,
                "sensitive": 1 if _is_sensitive(request.method, path) else 0,
            }
            try:
                _Q.put_nowait(row)
            except queue.Full:
                pass  # shed load rather than slow the customer down

            # repeated 404/403 monitoring + optional auto-block
            if response.status_code in (403, 404):
                _note_error(ip, get_db_connection, logger)
        except Exception as e:
            logger.debug(f"traffic after_request failed: {e}")
        return response

    # ------------------------------------------------------------ admin API
    def _hours():
        return max(1, min(24 * 30, request.args.get("hours", 24, type=int)))

    def _since(h):
        return (datetime.now(timezone.utc) - timedelta(hours=h)).strftime("%Y-%m-%d %H:%M:%S")

    def _q(sql, args=()):
        conn = get_db_connection()
        try:
            return [dict(r) for r in conn.execute(sql, args).fetchall()]
        finally:
            conn.close()

    @app.route("/api/admin/traffic/summary", methods=["GET"])
    @admin_required
    def traffic_summary():
        h = _hours()
        s = _since(h)
        tot = _q(
            "SELECT COUNT(*) total, COUNT(DISTINCT session_id) sessions, COUNT(DISTINCT ip) ips, "
            "SUM(bot_class='human') human, SUM(bot_class='bot') bot, SUM(bot_class='suspicious') suspicious, "
            "SUM(status>=200 AND status<300) s2xx, SUM(status>=300 AND status<400) s3xx, "
            "SUM(status>=400 AND status<500) s4xx, SUM(status>=500) s5xx, "
            "SUM(status=404) s404, SUM(status=403) s403, SUM(status=429) s429, SUM(sensitive=1) sensitive, "
            "ROUND(AVG(response_ms),1) avg_ms, MAX(response_ms) max_ms "
            "FROM request_log WHERE ts >= ?", (s,))[0]
        # p95 response time (SQLite has no percentile function)
        n = tot.get("total") or 0
        p95 = None
        if n:
            r = _q("SELECT response_ms FROM request_log WHERE ts >= ? AND response_ms IS NOT NULL "
                   "ORDER BY response_ms LIMIT 1 OFFSET ?", (s, int(n * 0.95)))
            p95 = r[0]["response_ms"] if r else None
        tot["p95_ms"] = p95
        split = {}
        for cls in ("human", "bot", "suspicious"):
            split[cls] = _q(
                "SELECT COUNT(*) requests, COUNT(DISTINCT session_id) sessions, COUNT(DISTINCT ip) ips, "
                "ROUND(AVG(response_ms),1) avg_ms, SUM(status>=400) errors FROM request_log "
                "WHERE ts >= ? AND bot_class = ?", (s, cls))[0]
        fmt = "%Y-%m-%d %H:00" if h > 48 else "%Y-%m-%d %H:%M"
        grain = "strftime('%Y-%m-%d %H:00', ts)" if h > 48 else "strftime('%Y-%m-%d %H:', ts) || printf('%02d', (CAST(strftime('%M', ts) AS INTEGER)/10)*10)"
        series = _q(
            f"SELECT {grain} t, SUM(bot_class='human') human, SUM(bot_class!='human') automated "
            "FROM request_log WHERE ts >= ? GROUP BY t ORDER BY t", (s,))
        return jsonify({
            "success": True, "hours": h, "totals": tot, "by_class": split, "series": series,
            "top_urls": _q("SELECT substr(url,1,120) url, COUNT(*) hits, SUM(status>=400) errors FROM request_log "
                           "WHERE ts >= ? GROUP BY substr(url,1,120) ORDER BY hits DESC LIMIT 15", (s,)),
            "top_referrers": _q("SELECT CASE WHEN referrer='' THEN '(direct)' ELSE substr(referrer,1,80) END referrer, "
                                "COUNT(*) hits FROM request_log WHERE ts >= ? AND bot_class='human' "
                                "GROUP BY 1 ORDER BY hits DESC LIMIT 10", (s,)),
            "top_asns": _q("SELECT COALESCE(asn,'(unresolved)') asn, COALESCE(MAX(asn_org),'') org, COUNT(*) hits, "
                           "SUM(bot_class!='human') automated FROM request_log WHERE ts >= ? "
                           "GROUP BY COALESCE(asn,'(unresolved)') ORDER BY hits DESC LIMIT 12", (s,)),
            "top_bots": _q("SELECT COALESCE(bot_name,'-') name, bot_class, COUNT(*) hits FROM request_log "
                           "WHERE ts >= ? AND bot_class!='human' GROUP BY name, bot_class ORDER BY hits DESC LIMIT 12", (s,)),
            "slowest": _q("SELECT substr(url,1,100) url, COUNT(*) hits, ROUND(AVG(response_ms),0) avg_ms, "
                          "MAX(response_ms) max_ms FROM request_log WHERE ts >= ? GROUP BY substr(url,1,100) "
                          "HAVING hits >= 3 ORDER BY avg_ms DESC LIMIT 8", (s,)),
        })

    @app.route("/api/admin/traffic/recent", methods=["GET"])
    @admin_required
    def traffic_recent():
        h = _hours()
        limit = min(request.args.get("limit", 100, type=int), 500)
        where, args = ["ts >= ?"], [_since(h)]
        for col, key in (("bot_class", "class"), ("method", "method"), ("ip", "ip"), ("session_id", "session")):
            v = request.args.get(key)
            if v:
                where.append(f"{col} = ?")
                args.append(v)
        st = request.args.get("status")
        if st and st.isdigit():
            if len(st) == 1:
                where.append("status >= ? AND status < ?")
                args += [int(st) * 100, int(st) * 100 + 100]
            else:
                where.append("status = ?")
                args.append(int(st))
        q = request.args.get("q")
        if q:
            where.append("url LIKE ?")
            args.append(f"%{q[:60]}%")
        rows = _q(f"SELECT * FROM request_log WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?", (*args, limit))
        return jsonify({"success": True, "count": len(rows), "requests": rows})

    @app.route("/api/admin/traffic/errors", methods=["GET"])
    @admin_required
    def traffic_errors():
        h = _hours()
        minimum = request.args.get("min", 5, type=int)
        rows = _q(
            "SELECT ip, MAX(asn) asn, MAX(asn_org) asn_org, MAX(bot_class) bot_class, "
            "SUM(status=404) n404, SUM(status=403) n403, COUNT(*) errors, COUNT(DISTINCT url) distinct_urls, "
            "MIN(ts) first_seen, MAX(ts) last_seen, substr(MAX(user_agent),1,80) user_agent "
            "FROM request_log WHERE ts >= ? AND status IN (403,404) GROUP BY ip HAVING errors >= ? "
            "ORDER BY errors DESC LIMIT 100", (_since(h), minimum))
        for r in rows:
            r["blocked"] = _is_blocked(r["ip"])
            r["sample_urls"] = [x["url"] for x in _q(
                "SELECT DISTINCT substr(url,1,100) url FROM request_log WHERE ip=? AND status IN (403,404) "
                "AND ts >= ? ORDER BY id DESC LIMIT 4", (r["ip"], _since(h)))]
        return jsonify({"success": True, "hours": h, "threshold": _env_int("TRAFFIC_ERR_THRESHOLD", 15),
                        "autoblock_minutes": _env_int("TRAFFIC_AUTOBLOCK_MIN", 0), "ips": rows})

    @app.route("/api/admin/traffic/sensitive", methods=["GET"])
    @admin_required
    def traffic_sensitive():
        h = _hours()
        limit = min(request.args.get("limit", 100, type=int), 500)
        rows = _q("SELECT ts, ip, asn, method, url, status, response_ms, user_id, session_id, bot_class, "
                  "substr(user_agent,1,80) user_agent FROM request_log WHERE ts >= ? AND sensitive = 1 "
                  "ORDER BY id DESC LIMIT ?", (_since(h), limit))
        return jsonify({"success": True, "count": len(rows), "requests": rows})

    @app.route("/api/admin/traffic/block", methods=["POST"])
    @admin_required
    def traffic_block():
        d = request.get_json(silent=True) or {}
        ip, minutes = str(d.get("ip") or "").strip(), int(d.get("minutes") or 60)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"success": False, "error": "Invalid IP"}), 400
        if d.get("unblock"):
            with _blocked_lock:
                _blocked.pop(ip, None)
            return jsonify({"success": True, "unblocked": ip})
        _block(ip, max(1, min(minutes, 60 * 24 * 7)))
        return jsonify({"success": True, "blocked": ip, "minutes": minutes,
                        "note": "Held in memory on this worker; use a Cloudflare rule for a permanent block."})

    @app.route("/admin_traffic.js")
    def traffic_js():
        resp = send_from_directory(os.path.dirname(os.path.abspath(__file__)), "admin_traffic.js",
                                   mimetype="application/javascript")
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.route("/admin/traffic")
    def traffic_page():
        # Shell only: every API call it makes is gated by admin_required (X-Admin-Secret header).
        return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "admin_traffic.html")

    logger.info("Traffic analytics ready (request_log, rate limits, 404/403 monitor, /admin/traffic)")


def _note_error(ip, get_conn, logger):
    """Count recent 403/404 for this IP; flag (and optionally block) when over the threshold."""
    minutes = _env_int("TRAFFIC_AUTOBLOCK_MIN", 0)
    if minutes <= 0 or not ip or _is_private(ip) or _is_blocked(ip):
        return
    window = max(1, _env_int("TRAFFIC_ERR_WINDOW_MIN", 10))
    threshold = _env_int("TRAFFIC_ERR_THRESHOLD", 15)
    key = f"err|{ip}"
    now = time.time()
    with _api_lock:
        arr = [t for t in _api_hits.get(key, []) if now - t < window * 60]
        arr.append(now)
        _api_hits[key] = arr
        over = len(arr) >= threshold
    if over:
        _block(ip, minutes)
        logger.warning(f"traffic: blocked {ip} for {minutes} min after {threshold}+ 403/404 in {window} min")

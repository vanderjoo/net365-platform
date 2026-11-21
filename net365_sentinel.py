"""
NET365 SENTINEL - threat detection, scoring and automated defence.

Design rules (these protect real customers):
  * Evidence, not geography. Country, hosting provider or cloud network NEVER block anyone on their own. They only
    amplify a score when real attack behaviour has already been seen.
  * Runs in MAXIMUM mode by default (upgrade migration sets it once; you can still switch in the Security tab).
    Maximum enforces automatically: IPs showing real attack evidence are blocked for 12 hours (24h on a second
    offence, 7 days after that), and an account whose OWN session sends injection payloads is deactivated for
    12 hours (sessions ended, restored automatically). Every automatic action is emailed to you with the evidence.
    Observation / Adaptive remain available. (Manual blocks you create always apply.)
  * Account holds only ever target the account that sent the attack payloads. A customer who merely shares an IP
    address (mobile CGNAT) with an attacker is never deactivated, and an account under brute-force attack is never
    locked out by the attacker's behaviour (that would hand attackers a way to lock out real customers).
  * Never touches payment-provider webhooks, bot endpoints or health checks (SENTINEL_EXEMPT_PREFIXES). Those are
    protected by their own signatures / secrets, not by IP trust.
  * Admin keeps a way in: a request carrying the correct X-Admin-Secret is never blocked, so you can always unblock.
  * Fail open: if SENTINEL itself errors, the request goes through. It can never take the site down.
  * Financial protection is separate: blocking an IP is not your wallet/payment defence. The app's own limits,
    signature checks and idempotency stay in charge.

Layers: IP intelligence (cache only on the request path) | behaviour | attack patterns | reputation (optional AbuseIPDB)
        | risk score 0-100 | defence (monitor, rate-limit, challenge, restrict, block).

Score bands (Observation records them; Adaptive/Maximum enforce them):
   0-19 normal | 20-39 low suspicion (monitor) | 40-59 suspicious (rate-limit) | 60-79 high risk (challenge: sensitive
   actions refused) | 80-89 very high (restricted 15 min) | 90-100 critical (blocked 24h, repeat offenders 7 days).
   Maximum mode lowers every band by 10. Automatic block/restrict also needs 2+ distinct kinds of evidence.

Environment (all optional):
  SENTINEL_ENABLED=true  SENTINEL_MODE=observation|adaptive|maximum (first-run default; the admin switch is stored in DB)
  SENTINEL_AUTO_BLOCK_MINUTES=720          first automatic IP block in Maximum mode (12h); 2nd offence x2; 3rd+ 7 days
  SENTINEL_ACCOUNT_HOLD_HOURS=12           how long an attacking account is deactivated
  SENTINEL_NEVER_HOLD_USER_IDS=1,2         account ids that are never deactivated automatically (owner / staff)
  SENTINEL_ALERT_EMAIL=you@example.com     where action reports go (falls back to SHIELD_ALERT_EMAIL, SECURITY_EMAIL, SUPPORT_EMAIL)
  SENTINEL_EMAIL_MAX_PER_HOUR=12           email cap per hour; extra actions are counted and reported in the next email
  SENTINEL_FORCE_MODE=observation   emergency override that beats the DB setting
  SENTINEL_ALLOW_IPS=1.2.3.4,10.0.0.0/8   never scored or blocked (your office, monitoring, bot server)
  SENTINEL_ADMIN_ALLOW_IPS=1.2.3.4        if set, /admin and /api/admin answer 404 to every other IP
  SENTINEL_EXEMPT_PREFIXES=/webhooks/,/api/whatsapp/,...   extra paths that bypass SENTINEL entirely
  SENTINEL_RATE_WARN=100 SENTINEL_RATE_FLOOD=250   requests per minute per IP (shared mobile networks: keep generous)
  SENTINEL_ABUSEIPDB_KEY=...              optional reputation lookups (cached 24h, only for IPs already showing signals)
  SENTINEL_ALERT_TELEGRAM_BOT_TOKEN / SENTINEL_ALERT_TELEGRAM_CHAT_ID / SENTINEL_ALERT_WEBHOOK_URL   critical alerts
  SENTINEL_RETENTION_DAYS=90 (raw IPs in old events are hashed after 30 days)
"""
import csv
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timedelta

from flask import Response, jsonify, request

log = logging.getLogger("net365.sentinel")

MODES = ("observation", "adaptive", "maximum")
SIGNAL_WINDOW = 900  # seconds a signal keeps counting toward the score
# Evidence strong enough that Maximum mode acts on it without waiting for a second kind of evidence
HARD_KINDS = {"scanner_tool", "command_injection", "sql_injection", "directory_traversal", "credential_stuffing", "payment_replay"}
# Payloads that, when sent from a LOGGED-IN session, mean that account is being used to attack the platform
INJECTION_KINDS = {"sql_injection", "command_injection", "directory_traversal"}
HOLD_PREFIX = "SENTINEL auto-hold"

DEFAULT_EXEMPT = (
    "/webhooks/", "/api/whatsapp/", "/api/telegram/", "/api/health", "/healthz", "/static/", "/favicon",
    "/robots.txt", "/sitemap.xml", "/payment/callback", "/api/auth/google/callback", "/n365_tracker.js", "/admin_insights.js", "/admin_sentinel.js",
)
AUTH_FAIL_STATUS = {
    "/api/auth/login": (401, 403),
    "/api/auth/verify-email": (400, 401, 403),
    "/api/auth/reset-password": (400, 401, 403),
    "/api/auth/change-password": (400, 401, 403),
}
SENSITIVE_PREFIXES = (
    "/api/auth/login", "/api/auth/register", "/api/auth/forgot-password", "/api/auth/reset-password",
    "/api/auth/verify-email", "/api/auth/resend-otp", "/api/auth/change-password",
    "/api/wallet", "/api/payment", "/api/bulk", "/api/utilities", "/api/scheduler", "/api/balance",
    "/api/referral", "/api/transaction",
)
MONEY_PREFIXES = ("/api/wallet", "/api/payment", "/api/bulk", "/api/utilities", "/api/transaction", "/api/balance")
STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map", ".webp", ".ttf")

RECON_PATHS = re.compile(
    r"(/wp-(admin|login|content|includes)|/xmlrpc\.php|/\.env|/\.git|/\.aws|/\.ssh|/\.svn|/\.htaccess|/\.ds_store|"
    r"/phpmyadmin|/pma/|/adminer|/phpinfo|/config\.(php|json|yml|yaml|bak)|/actuator|/vendor/phpunit|/cgi-bin|"
    r"/boaform|/server-status|/id_rsa|/etc/passwd|\.(sql|bak|old|orig|swp|tar|tgz|zip|7z|rar)$|/backup|/db\.sqlite|"
    r"/api/(debug|v1/\.\./)|/console$|/manager/html|/solr/|/jenkins|/\.well-known/\.\.)", re.I)
SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|acunetix|nessus|zgrab|dirbuster|gobuster|wpscan|nuclei|havij|openvas|burp|"
    r"metasploit|w3af|arachni|feroxbuster|ffuf|wfuzz|hydra|medusa|netsparker|appscan|fimap|commix)", re.I)
TOOL_UA = re.compile(r"^(python-requests|python-urllib|curl|wget|go-http-client|libwww-perl|java/|okhttp/[0-2]|aiohttp|httpx|scrapy|node-fetch|axios)", re.I)

SQLI = [re.compile(p, re.I | re.S) for p in (
    r"\bunion\b[\s/*()+]+(all[\s/*()+]+)?select\b",
    r"\bselect\b.{1,60}\bfrom\b.{1,60}\b(information_schema|sqlite_master|pg_catalog|mysql\.user)\b",
    r"(['\"])\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    r"\bor\b\s+1\s*=\s*1\b",
    r";\s*(drop|delete|insert|update|alter|truncate)\s+\w+",
    r"\b(sleep|benchmark|pg_sleep)\s*\(\s*\d",
    r"\bwaitfor\s+delay\b",
    r"\bload_file\s*\(",
    r"\b(sqlite_master|information_schema)\b",
    r"'\s*;\s*--",
)]
XSS = [re.compile(p, re.I | re.S) for p in (
    r"<\s*script\b", r"\bon(error|load|click|mouseover|focus|toggle)\s*=", r"javascript\s*:",
    r"<\s*(iframe|object|embed|svg)\b[^>]*", r"<\s*img[^>]+\bsrc\s*=\s*['\"]?\s*x\b",
)]
TRAVERSAL = [re.compile(p, re.I) for p in (
    r"\.\./", r"\.\.\\", r"%2e%2e", r"/etc/(passwd|shadow|hosts)\b", r"\bboot\.ini\b", r"/proc/self", r"\bfile://",
)]
CMDI = [re.compile(p, re.I) for p in (
    r"[;|&`]\s*(cat|wget|curl|nc|ncat|bash|sh|powershell|python|perl)\s+[/\-\w.]", r"\$\{jndi:", r"\b(eval|exec|system)\s*\(\s*['\"$]",
)]
SKIP_KEYS = re.compile(r"(pass|pin|token|secret|otp|card|cvv|signature|hash)", re.I)

CRAWLERS = {  # UA fragment -> reverse-DNS suffixes that prove it is really that crawler
    "googlebot": (".googlebot.com", ".google.com"),
    "bingbot": (".search.msn.com",),
    "yandex": (".yandex.ru", ".yandex.net", ".yandex.com"),
    "baiduspider": (".baidu.com", ".baidu.jp"),
    "applebot": (".applebot.apple.com",),
}
CRAWLER_CLAIM = re.compile(r"(googlebot|bingbot|yandex|baiduspider|applebot|duckduckbot|facebookexternalhit|linkedinbot|twitterbot)", re.I)

_d = {}
_lock = threading.RLock()
_hits = defaultdict(deque)       # ip -> request timestamps (60s)
_money = defaultdict(deque)      # ip -> money-path timestamps (60s)
_notfound = defaultdict(deque)   # ip -> 404 timestamps (60s)
_authfail = defaultdict(deque)   # ip -> (ts, account_hash)
_acct = defaultdict(deque)       # account_hash -> (ts, ip)
_signals = defaultdict(deque)    # ip -> (ts, points, kind, detail)
_cooldown = {}                   # (ip, kind) -> ts for once-per signals
_replay = defaultdict(deque)     # (ip, path, bodyhash) -> ts
_event_gap = {}                  # (ip, kind) -> last stored ts
_counters = defaultdict(int)
_crawler = {}                    # ip -> (verified bool, expires)
_crawler_pending = set()
_asn_seen = {}
_cfg = {"mode": None, "lockdown": False, "loaded": 0}
_blocks = {"ips": {}, "nets": [], "asn": {}, "loaded": 0}
_allow = {"nets": [], "loaded": 0}
_ready = False
_started = False


# ---------------------------------------------------------------- helpers
def _env_bool(name, default=True):
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return int(default)


def _now():
    return time.time()


def _utc(ts=None):
    return datetime.utcfromtimestamp(ts if ts is not None else _now()).strftime("%Y-%m-%d %H:%M:%S")


def _conn():
    return _d["db"].get_db_connection()


def _salt():
    return os.getenv("SECRET_KEY", "") or "net365"


def _hash(value):
    return hashlib.sha256(f"{_salt()}|{value}".encode()).hexdigest()[:12]


def _exempt_prefixes():
    extra = [p.strip() for p in os.getenv("SENTINEL_EXEMPT_PREFIXES", "").split(",") if p.strip()]
    return tuple(DEFAULT_EXEMPT) + tuple(extra)


def _parse_nets(text):
    nets = []
    for part in str(text or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            log.warning("SENTINEL: ignoring bad network %r", part)
    return nets


def _valid_ip(ip):
    try:
        return ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None


def _is_private(ip):
    a = _valid_ip(ip)
    return (not a) or a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast


def _in_nets(ip, nets):
    a = _valid_ip(ip)
    if not a:
        return False
    for n in nets:
        try:
            if a in n:
                return True
        except TypeError:
            continue
    return False


def _band(score):
    return ("Trusted / normal" if score < 20 else "Low suspicion" if score < 40 else "Suspicious" if score < 60 else
            "High risk" if score < 80 else "Very high risk" if score < 90 else "Critical threat")


def _severity(score):
    return ("info" if score < 20 else "low" if score < 40 else "medium" if score < 60 else
            "high" if score < 80 else "very_high" if score < 90 else "critical")


def _bump(key, n=1):
    with _lock:
        _counters[key] += n


# ---------------------------------------------------------------- schema + settings
def ensure_schema():
    global _ready
    if _ready:
        return
    c = _conn()
    stmts = [
        """CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, ip TEXT, kind TEXT NOT NULL, severity TEXT,
            points INTEGER DEFAULT 0, score INTEGER DEFAULT 0, action TEXT, mode TEXT, method TEXT, path TEXT,
            user_agent TEXT, country TEXT, org TEXT, asn TEXT, detail TEXT, ref TEXT)""",
        "CREATE INDEX IF NOT EXISTS idx_sec_events_ts ON security_events(ts)",
        "CREATE INDEX IF NOT EXISTS idx_sec_events_ip ON security_events(ip)",
        """CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY, reason TEXT, level TEXT, source TEXT, strikes INTEGER DEFAULT 1,
            created_at TEXT, expires_at TEXT, created_by TEXT)""",
        """CREATE TABLE IF NOT EXISTS blocked_networks (
            asn TEXT PRIMARY KEY, reason TEXT, created_at TEXT, expires_at TEXT, created_by TEXT)""",
        """CREATE TABLE IF NOT EXISTS security_exceptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT UNIQUE, note TEXT, created_at TEXT, created_by TEXT)""",
        """CREATE TABLE IF NOT EXISTS security_scores (
            ip TEXT PRIMARY KEY, peak_score INTEGER DEFAULT 0, strikes INTEGER DEFAULT 0, last_seen TEXT, last_kind TEXT)""",
        """CREATE TABLE IF NOT EXISTS security_audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, target TEXT, detail TEXT)""",
        """CREATE TABLE IF NOT EXISTS security_settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)""",
        """CREATE TABLE IF NOT EXISTS security_counters (
            hour TEXT NOT NULL, key TEXT NOT NULL, n INTEGER DEFAULT 0, PRIMARY KEY (hour, key))""",
        """CREATE TABLE IF NOT EXISTS threat_intelligence (
            ip TEXT PRIMARY KEY, source TEXT, confidence INTEGER, detail TEXT, checked_at TEXT)""",
        """CREATE TABLE IF NOT EXISTS account_holds (
            user_id INTEGER PRIMARY KEY, until TEXT NOT NULL, reason TEXT, ref TEXT, ip TEXT, created_at TEXT)""",
        """CREATE TABLE IF NOT EXISTS security_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, channel TEXT, subject TEXT, ok INTEGER, detail TEXT)""",
    ]
    for s in stmts:
        c.execute(s)
    _ready = True


def _setting(key, default=None):
    try:
        r = _conn().execute("SELECT value FROM security_settings WHERE key = ?", (key,)).fetchone()
        return r["value"] if r else default
    except Exception:
        return default


def _set_setting(key, value):
    _conn().execute(
        "INSERT INTO security_settings (key, value, updated_at) VALUES (?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at", (key, str(value), _utc()))
    _cfg["loaded"] = 0


def _load_cfg(force=False):
    if not force and _now() - _cfg["loaded"] < 10:
        return
    try:
        mode = os.getenv("SENTINEL_FORCE_MODE", "").strip().lower()
        if mode not in MODES:
            mode = _setting("mode") or os.getenv("SENTINEL_MODE", "maximum").strip().lower()
        _cfg["mode"] = mode if mode in MODES else "maximum"
        _cfg["lockdown"] = _setting("lockdown", "0") == "1"
    except Exception:
        _cfg["mode"] = _cfg["mode"] or "maximum"
    _cfg["loaded"] = _now()


def mode():
    _load_cfg()
    return _cfg["mode"] or "maximum"


def _load_lists(force=False):
    if not force and _now() - _blocks["loaded"] < 15:
        return
    try:
        c = _conn()
        now = _utc()
        c.execute("DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at < ? AND level != 'manual_permanent'", (now,))
        ips, nets = {}, []
        for r in c.execute("SELECT ip, level, reason, expires_at FROM blocked_ips").fetchall():
            exp = None
            if r["expires_at"]:
                try:
                    exp = datetime.strptime(r["expires_at"], "%Y-%m-%d %H:%M:%S").timestamp() - (time.timezone if False else 0)
                    exp = (datetime.strptime(r["expires_at"], "%Y-%m-%d %H:%M:%S") - datetime(1970, 1, 1)).total_seconds()
                except ValueError:
                    exp = None
            item = {"level": r["level"], "reason": r["reason"], "exp": exp}
            if "/" in (r["ip"] or ""):
                try:
                    nets.append((ipaddress.ip_network(r["ip"], strict=False), item))
                except ValueError:
                    pass
            else:
                ips[r["ip"]] = item
        asn = {}
        for r in c.execute("SELECT asn, reason, expires_at FROM blocked_networks").fetchall():
            asn[str(r["asn"]).upper().replace("AS", "")] = r["reason"]
        _blocks.update(ips=ips, nets=nets, asn=asn, loaded=_now())
        _allow["nets"] = _parse_nets(os.getenv("SENTINEL_ALLOW_IPS", "")) + _parse_nets(
            ",".join(r["value"] for r in c.execute("SELECT value FROM security_exceptions").fetchall()))
        _allow["loaded"] = _now()
    except Exception:
        log.exception("SENTINEL: list refresh failed")
        _blocks["loaded"] = _now()


def _blocked_entry(ip):
    _load_lists()
    now = _now()
    e = _blocks["ips"].get(ip)
    if e and (e["exp"] is None or e["exp"] > now):
        return e
    if _blocks["nets"]:
        a = _valid_ip(ip)
        if a:
            for n, item in _blocks["nets"]:
                try:
                    if a in n and (item["exp"] is None or item["exp"] > now):
                        return item
                except TypeError:
                    continue
    if _blocks["asn"]:
        asn = _asn_of(ip)
        if asn and asn in _blocks["asn"]:
            return {"level": "network", "reason": "network blocked: " + str(_blocks["asn"][asn] or ""), "exp": None}
    return None


def _asn_of(ip):
    if ip in _asn_seen:
        return _asn_seen[ip]
    try:
        from ip_intel import IPIntel
        info = IPIntel._read_cache(ip)
        if info and info.get("asn"):
            v = str(info["asn"]).upper().replace("AS", "").strip()
            _asn_seen[ip] = v
            return v
        IPIntel.enqueue(ip)
    except Exception:
        pass
    return None


def _intel(ip):
    """Cache-only network info (never a network call on the request path)."""
    try:
        from ip_intel import IPIntel
        return IPIntel._read_cache(ip) or {}
    except Exception:
        return {}


def _is_allowed(ip):
    _load_lists()
    return _in_nets(ip, _allow["nets"])


# ---------------------------------------------------------------- signals + scoring
def _add(ip, kind, points, detail="", once=0):
    """Record one piece of evidence against an IP. Returns True if it was recorded."""
    now = _now()
    with _lock:
        if once:
            last = _cooldown.get((ip, kind), 0)
            if now - last < once:
                return False
            _cooldown[(ip, kind)] = now
        _signals[ip].append((now, int(points), kind, str(detail)[:160]))
        if len(_signals[ip]) > 200:
            _signals[ip].popleft()
    return True


def _score(ip):
    now = _now()
    with _lock:
        q = _signals.get(ip)
        if not q:
            return 0, [], set()
        while q and now - q[0][0] > SIGNAL_WINDOW:
            q.popleft()
        if not q:
            _signals.pop(ip, None)
            return 0, [], set()
        total = sum(p for _, p, _, _ in q)
        kinds = {k for _, _, k, _ in q if _ > 0} if False else {k for _, p, k, _ in q if p > 0}
        reasons = []
        seen = set()
        for _, p, k, d in reversed(q):
            if k not in seen and p > 0:
                seen.add(k)
                reasons.append(f"{k}: {d}" if d else k)
    # amplifier: hosting/VPN networks only matter once real evidence exists
    if total > 0:
        info = _intel(ip)
        if str(info.get("ip_kind") or info.get("kind") or "").lower() in ("cloud", "hosting", "vpn", "proxy"):
            total += 10
            reasons.append("network: hosting/VPN (amplifier only)")
    try:
        r = _conn().execute("SELECT strikes FROM security_scores WHERE ip = ?", (ip,)).fetchone() if total >= 40 else None
        if r and r["strikes"]:
            total += min(15, 5 * int(r["strikes"]))
            reasons.append(f"history: {r['strikes']} earlier block(s)")
    except Exception:
        pass
    return min(100, total), reasons, kinds


def _thresholds():
    shift = 10 if mode() == "maximum" else 0
    return {"monitor": 20 - shift, "ratelimit": 40 - shift, "challenge": 60 - shift, "restrict": 80 - shift, "block": 90 - shift}


def _decide(score, kinds):
    t = _thresholds()
    need = 1 if (mode() == "maximum" and (kinds & HARD_KINDS)) else 2
    if score >= t["block"] and len(kinds) >= need:
        return "block"
    if score >= t["restrict"] and len(kinds) >= need:
        return "restrict"
    if score >= t["challenge"]:
        return "challenge"
    if score >= t["ratelimit"]:
        return "ratelimit"
    if score >= t["monitor"]:
        return "monitor"
    return "allow"


# ---------------------------------------------------------------- inspection
def _decode(s):
    s = str(s)
    for _ in range(2):
        try:
            n = urllib.parse.unquote_plus(s)
        except Exception:
            break
        if n == s:
            break
        s = n
    return s


def _scan_text(text):
    """Return list of (kind, points, detail) for attack patterns found in one string."""
    out = []
    if not text:
        return out
    t = _decode(text)[:4000]
    for rx in SQLI:
        if rx.search(t):
            out.append(("sql_injection", 30, "SQL pattern")); break
    for rx in XSS:
        if rx.search(t):
            out.append(("xss", 20, "script injection pattern")); break
    for rx in TRAVERSAL:
        if rx.search(t):
            out.append(("directory_traversal", 40, "path traversal pattern")); break
    for rx in CMDI:
        if rx.search(t):
            out.append(("command_injection", 35, "command/JNDI pattern")); break
    return out


def _walk_strings(obj, out, depth=0):
    if len(out) >= 150 or depth > 5:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if SKIP_KEYS.search(str(k)):
                continue
            _walk_strings(v, out, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj[:60]:
            _walk_strings(v, out, depth + 1)
    elif isinstance(obj, str):
        out.append(obj[:2000])


def _body_info(path):
    """(strings to scan, body hash, account hash) for small JSON/form bodies on non-exempt paths."""
    strings, bh, acct = [], None, None
    try:
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return strings, bh, acct
        ctype = (request.content_type or "").lower()
        if ctype.startswith("multipart/") or (request.content_length or 0) > 65536:
            return strings, bh, acct
        raw = request.get_data(cache=True) or b""
        if raw:
            bh = hashlib.sha1(raw).hexdigest()[:16]
        data = request.get_json(silent=True) if "json" in ctype else None
        if data is None and "form" in ctype:
            data = request.form.to_dict()
        if isinstance(data, dict):
            _walk_strings(data, strings)
            ident = data.get("email") or data.get("phone") or data.get("username")
            if ident and path.startswith("/api/auth/"):
                acct = _hash(str(ident).strip().lower()[:120])
    except Exception:
        pass
    return strings, bh, acct


def _trim(dq, horizon, now):
    while dq and now - (dq[0][0] if isinstance(dq[0], tuple) else dq[0]) > horizon:
        dq.popleft()


# ---------------------------------------------------------------- crawler verification
def _verify_crawler(ip, ua):
    def work():
        ok = False
        try:
            low = (ua or "").lower()
            suffixes = ()
            for frag, sfx in CRAWLERS.items():
                if frag in low:
                    suffixes = sfx
                    break
            if suffixes:
                host = socket.gethostbyaddr(ip)[0].lower()
                if host.endswith(suffixes):
                    ok = ip in {x[4][0] for x in socket.getaddrinfo(host, None)}
        except Exception:
            ok = False
        _crawler[ip] = (ok, _now() + 86400)
        _crawler_pending.discard(ip)
    t = threading.Thread(target=work, daemon=True)
    t.start()


def _crawler_state(ip, ua):
    """'verified' | 'unverified' | 'unknown' | None (does not claim to be a crawler)."""
    if not ua or not CRAWLER_CLAIM.search(ua):
        return None
    ent = _crawler.get(ip)
    if ent and ent[1] > _now():
        return "verified" if ent[0] else "unverified"
    low = ua.lower()
    if not any(f in low for f in CRAWLERS):
        return "unknown"  # claims a crawler that has no reverse-DNS proof (duckduck/linkedin/...): neutral
    if ip not in _crawler_pending:
        _crawler_pending.add(ip)
        _verify_crawler(ip, ua)
    return "unknown"


# ---------------------------------------------------------------- events + alerts
def _event(ip, kind, points, score, action, detail="", path="", method=""):
    gap_key = (ip, kind)
    now = _now()
    if now - _event_gap.get(gap_key, 0) < 30 and action in ("allow", "monitor"):
        return None
    _event_gap[gap_key] = now
    if len(_event_gap) > 20000:
        _event_gap.clear()
    ref = hashlib.sha1(f"{ip}{now}{kind}".encode()).hexdigest()[:10].upper()
    info = _intel(ip)
    try:
        _conn().execute(
            "INSERT INTO security_events (ts, ip, kind, severity, points, score, action, mode, method, path, user_agent, country, org, asn, detail, ref) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (_utc(), ip, kind, _severity(score), int(points), int(score), action, mode(), method, (path or "")[:200],
             (request.headers.get("User-Agent", "") if request else "")[:160], info.get("country") or info.get("country_code"),
             (info.get("org_name") or info.get("org") or "")[:80], info.get("asn"), str(detail)[:300], ref))
    except Exception:
        log.exception("SENTINEL: event write failed")
        return None
    if score >= 80 or action in ("block", "restrict"):
        _notify(ip, kind, score, action, detail, ref)
    return ref


def _notify(ip, kind, score, action, detail, ref):
    key = ("notify", ip, datetime.utcnow().strftime("%Y%m%d%H"))
    if key in _cooldown:
        return
    _cooldown[key] = _now()
    msg = f"NET365 SENTINEL {action.upper()} - score {score} ({_band(score)}) - {kind} - {detail} - ref {ref} - mode {mode()}"

    def push():
        sent = []
        tok = os.getenv("SENTINEL_ALERT_TELEGRAM_BOT_TOKEN") or os.getenv("INTEL_ALERT_TELEGRAM_BOT_TOKEN")
        chat = os.getenv("SENTINEL_ALERT_TELEGRAM_CHAT_ID") or os.getenv("INTEL_ALERT_TELEGRAM_CHAT_ID")
        hook = os.getenv("SENTINEL_ALERT_WEBHOOK_URL") or os.getenv("INTEL_ALERT_WEBHOOK_URL")
        for ch, url, body in (
            ("telegram", f"https://api.telegram.org/bot{tok}/sendMessage" if tok and chat else None,
             json.dumps({"chat_id": chat, "text": msg}).encode()),
            ("webhook", hook, json.dumps({"text": msg, "source": "net365-sentinel", "ref": ref}).encode()),
        ):
            if not url:
                continue
            ok, det = 0, ""
            try:
                req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=6).read()
                ok = 1
            except Exception as e:
                det = str(e)[:120]
            sent.append((ch, ok, det))
        try:
            c = _conn()
            if not sent:
                sent = [("log", 1, "no push channel configured")]
            for ch, ok, det in sent:
                c.execute("INSERT INTO security_notifications (ts, channel, subject, ok, detail) VALUES (?,?,?,?,?)", (_utc(), ch, msg[:200], ok, det))
        except Exception:
            pass
    threading.Thread(target=push, daemon=True).start()


def _audit(actor, action, target="", detail=""):
    try:
        _conn().execute("INSERT INTO security_audit_logs (ts, actor, action, target, detail) VALUES (?,?,?,?,?)",
                        (_utc(), actor, action, str(target)[:120], str(detail)[:300]))
    except Exception:
        log.exception("SENTINEL: audit write failed")


# ---------------------------------------------------------------- reports to the owner + account holds
_mail = {"sent": deque(), "suppressed": 0}
_acct_inj = defaultdict(deque)   # user_id -> timestamps of requests carrying injection payloads


def _alert_to():
    for k in ("SENTINEL_ALERT_EMAIL", "SHIELD_ALERT_EMAIL", "SECURITY_EMAIL", "SUPPORT_ALERT_EMAIL", "SUPPORT_EMAIL"):
        v = os.getenv(k, "").strip()
        if v:
            return v
    return "support@net365co.com"


def _email(subject, body):
    """Email the owner. Capped per hour so an attack cannot flood the inbox; the overflow is counted and reported."""
    send = _d.get("email")
    if not send:
        return False
    now = _now()
    with _lock:
        q = _mail["sent"]
        while q and now - q[0] > 3600:
            q.popleft()
        if len(q) >= _env_int("SENTINEL_EMAIL_MAX_PER_HOUR", 12):
            _mail["suppressed"] += 1
            return False
        q.append(now)
        extra = ""
        if _mail["suppressed"]:
            extra = (f"\n\n({_mail['suppressed']} further automatic action(s) since the last email were not emailed. "
                     "Full list: Security tab > Live threat monitor, or Export CSV.)")
            _mail["suppressed"] = 0
    try:
        send(_alert_to(), subject, body + extra)
        return True
    except Exception:
        log.exception("SENTINEL: alert email failed")
        return False


def _human_minutes(m):
    if not m:
        return "permanently"
    return f"{int(m)} minutes" if m < 120 else (f"{int(round(m / 60.0))} hours" if m < 2880 else f"{int(round(m / 1440.0))} days")


def _block_minutes(strikes):
    """Maximum: 12h, then 24h, then 7 days. Adaptive keeps its original 24h / 7 days."""
    if mode() == "maximum":
        base = max(15, _env_int("SENTINEL_AUTO_BLOCK_MINUTES", 720))
        return base if strikes < 1 else (base * 2 if strikes == 1 else 10080)
    return 10080 if strikes >= 1 else 1440


def _mask_email(e):
    e = str(e or "")
    if "@" not in e:
        return "no email"
    a, b = e.split("@", 1)
    return (a[:2] + "***@" + b) if len(a) > 2 else ("***@" + b)


def _user_id():
    """The logged-in account behind this request, or None. Only called when a request already carries attack evidence."""
    fn = _d.get("user_fn")
    if not callable(fn):
        return None
    try:
        v = fn()
        return int(v) if v else None
    except Exception:
        return None


def _never_hold(uid):
    ids = {x.strip() for x in os.getenv("SENTINEL_NEVER_HOLD_USER_IDS", "").split(",") if x.strip()}
    return str(uid) in ids


def hold_account(uid, ip, reason, ref="", hours=None):
    """Deactivate one account for N hours: status becomes 'suspended', every session is ended, and the sweep restores it
    automatically. Accounts that are already blocked, deleted or suspended by a person are left exactly as they are."""
    try:
        hours = hours or _env_int("SENTINEL_ACCOUNT_HOLD_HOURS", 12)
        if not uid or _never_hold(uid):
            return None
        c = _conn()
        u = c.execute("SELECT id, email, account_status FROM users WHERE id = ?", (uid,)).fetchone()
        if not u or (u["account_status"] or "active") != "active":
            return None
        until = _utc(_now() + hours * 3600)
        c.execute("INSERT INTO account_holds (user_id, until, reason, ref, ip, created_at) VALUES (?,?,?,?,?,?) "
                  "ON CONFLICT(user_id) DO UPDATE SET until=excluded.until, reason=excluded.reason, ref=excluded.ref, "
                  "ip=excluded.ip, created_at=excluded.created_at", (uid, until, str(reason)[:200], ref, ip, _utc()))
        db = _d["db"]
        db.set_account_status(uid, "suspended", f"{HOLD_PREFIX} until {until} UTC (ref {ref}): {reason}"[:240])
        try:
            killed = db.kill_user_sessions(uid)
        except Exception:
            killed = 0
        try:
            db.create_notification(uid, "Account temporarily restricted",
                                   "Unusual activity was detected on your account, so it has been restricted for your protection. "
                                   f"It will be restored automatically in about {hours} hours. Contact support if you need help sooner.", "warning")
        except Exception:
            pass
        _audit("sentinel", "account_hold", f"user {uid}", f"{hours}h ref {ref}: {reason}")
        return {"user_id": uid, "until": until, "hours": hours, "email": _mask_email(u["email"]), "sessions_ended": killed, "ref": ref}
    except Exception:
        log.exception("SENTINEL: account hold failed")
        return None


def release_account(uid, actor="sentinel", note="hold ended"):
    """End a hold. Restores the account only if it is still the status Sentinel set (never undoes a person's decision)."""
    c = _conn()
    c.execute("DELETE FROM account_holds WHERE user_id = ?", (uid,))
    u = c.execute("SELECT account_status, status_reason FROM users WHERE id = ?", (uid,)).fetchone()
    if u and u["account_status"] == "suspended" and str(u["status_reason"] or "").startswith(HOLD_PREFIX):
        _d["db"].set_account_status(uid, "active", f"{HOLD_PREFIX} ended: {note}")
        _audit(actor, "account_released", f"user {uid}", note)
        return True
    return False


def _restore_expired_holds():
    c = _conn()
    rows = c.execute("SELECT user_id, reason, ref FROM account_holds WHERE until <= ?", (_utc(),)).fetchall()
    for r in rows:
        try:
            if release_account(r["user_id"], note="12h hold expired"):
                try:
                    _d["db"].create_notification(r["user_id"], "Account restored", "Your account is active again. Thank you for your patience.", "info")
                except Exception:
                    pass
                _email(f"[Net365 Sentinel] Account #{r['user_id']} restored", f"The automatic hold on account #{r['user_id']} has ended and the account is active again.\n"
                       f"Original reason: {r['reason']} (ref {r['ref']}).\nIf you want it held longer, suspend it from the Users tab.")
        except Exception:
            log.exception("SENTINEL: hold restore failed")


def _report_action(action, ip, minutes, score, reasons, ref, path="", held=None):
    """Tell the owner exactly what Sentinel did and why, while they were away. Restricts (15 min) are only logged."""
    if action == "restrict" and not held:
        return
    info = _intel(ip)
    where = ", ".join(x for x in (info.get("city"), info.get("country") or info.get("country_code")) if x) or "unknown"
    net = f"{info.get('org_name') or info.get('org') or 'unknown'} {info.get('asn') or ''}".strip()
    did = []
    if action in ("block", "restrict"):
        did.append(f"- Blocked IP {ip} for {_human_minutes(minutes)} (it cannot reach the site until then).")
    if held:
        did.append(f"- Deactivated account #{held['user_id']} ({held['email']}) for {held['hours']} hours (until {held['until']} UTC). "
                   f"{held['sessions_ended']} session(s) ended. It restores automatically.")
    subject = "[Net365 Sentinel] " + ("BLOCKED + ACCOUNT DEACTIVATED" if (held and action == "block") else
                                      "ACCOUNT DEACTIVATED" if held else "BLOCKED") + f" {ip}"
    body = ("NET365 SENTINEL acted automatically (mode: %s).\n\nWhat it did:\n%s\n\nWho / where:\n- IP: %s\n- Location: %s\n- Network: %s\n"
            "- Risk score: %s (%s)\n- Request: %s\n\nWhy (evidence):\n%s\n\nReference: %s\n\n"
            "If this was a mistake: Admin > Security > Blocks & allow-list > Unblock (IP) or Release now (account). "
            "Time shown is UTC.") % (mode(), "\n".join(did) or "- Recorded the evidence only.", ip, where, net, score, _band(score), (path or "n/a")[:100],
                                      "\n".join("- " + r for r in (reasons or [])[:6]) or "- see Security tab", ref or "n/a")
    _email(subject, body)


def _hold_for_injection(ip, inj, action, path):
    """Decide whether the account behind this request should be deactivated. It must be this account's own request that
    carried the payloads, and either the IP is already being blocked/restricted or the account did it twice in 10 minutes."""
    uid = _user_id()
    if not uid:
        return None
    now = _now()
    with _lock:
        q = _acct_inj[uid]
        q.append(now)
        while q and now - q[0] > 600:
            q.popleft()
        n = len(q)
        if len(_acct_inj) > 5000:
            _acct_inj.clear()
    if not (action in ("block", "restrict") or n >= 2):
        return None
    ref = hashlib.sha1(f"hold{uid}{now}".encode()).hexdigest()[:10].upper()
    held = hold_account(uid, ip, f"{', '.join(inj)} payloads sent from this account's own session", ref)
    if held:
        _event(ip, "account_hold", 0, 90, "hold", f"user {uid} held {held['hours']}h ({', '.join(inj)}) ref {ref}", path, request.method)
    return held


# ---------------------------------------------------------------- blocking
def block_ip(ip, minutes, reason, level="auto", by="sentinel", strikes=None):
    ip = str(ip).strip()
    if "/" in ip:
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            return False
    elif not _valid_ip(ip):
        return False
    expires = None if not minutes else _utc(_now() + int(minutes) * 60)
    c = _conn()
    if strikes is None:
        r = c.execute("SELECT strikes FROM security_scores WHERE ip = ?", (ip,)).fetchone()
        strikes = (r["strikes"] if r else 0) + 1
    c.execute(
        "INSERT INTO blocked_ips (ip, reason, level, source, strikes, created_at, expires_at, created_by) VALUES (?,?,?,?,?,?,?,?) "
        "ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, level=excluded.level, source=excluded.source, strikes=excluded.strikes, "
        "created_at=excluded.created_at, expires_at=excluded.expires_at, created_by=excluded.created_by",
        (ip, str(reason)[:200], level, "auto" if by == "sentinel" else "manual", strikes, _utc(), expires, by))
    c.execute(
        "INSERT INTO security_scores (ip, peak_score, strikes, last_seen, last_kind) VALUES (?,?,?,?,?) "
        "ON CONFLICT(ip) DO UPDATE SET strikes=?, last_seen=excluded.last_seen", (ip, 0, strikes, _utc(), level, strikes))
    _blocks["loaded"] = 0
    _load_lists(True)
    return True


def unblock_ip(ip):
    c = _conn()
    n = c.execute("DELETE FROM blocked_ips WHERE ip = ?", (str(ip).strip(),)).rowcount
    with _lock:
        _signals.pop(ip, None)
        for k in [k for k in _cooldown if k[0] == ip]:
            _cooldown.pop(k, None)
    _load_lists(True)
    return n


# ---------------------------------------------------------------- the request hooks
def _is_exempt(path):
    return path.startswith(_exempt_prefixes())


def _is_static(path):
    return path.lower().endswith(STATIC_EXT)


def _deny(kind, status, ref, retry=None, message=None):
    wants_json = request.path.startswith("/api/") or "application/json" in (request.headers.get("Accept", "") + request.headers.get("Content-Type", ""))
    msgs = {
        "block": "Access from your network has been blocked for security reasons.",
        "restrict": "Your access is temporarily restricted for security reasons. Please try again later.",
        "challenge": "We need to verify this request. Please wait a minute and try again.",
        "ratelimit": "Too many requests. Please slow down and try again shortly.",
        "lockdown": "This service is temporarily unavailable. Existing payments are not affected. Please try again soon.",
    }
    text = message or msgs.get(kind, "Request refused.")
    codes = {"block": "SECURITY_BLOCKED", "restrict": "SECURITY_RESTRICTED", "challenge": "CHALLENGE_REQUIRED",
             "ratelimit": "RATE_LIMITED", "lockdown": "LOCKDOWN"}
    if wants_json:
        resp = jsonify({"success": False, "error": text, "error_code": codes.get(kind, "DENIED"), "reference": ref})
    else:
        body = (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
                f"<title>Access limited</title><body style='font-family:system-ui;max-width:520px;margin:12vh auto;padding:0 20px;color:#1e293b'>"
                f"<h2>Access limited</h2><p>{text}</p><p style='color:#64748b;font-size:13px'>Reference: {ref or 'n/a'}. "
                f"If you think this is a mistake, contact support with this reference.</p>")
        resp = Response(body, mimetype="text/html")
    resp.status_code = status
    if retry:
        resp.headers["Retry-After"] = str(retry)
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _admin_secret_ok():
    getter = _d.get("admin_secret")
    secret = getter() if callable(getter) else getter
    provided = request.headers.get("X-Admin-Secret", "")
    if not secret or not provided:
        return False
    try:
        import secrets as _s
        return _s.compare_digest(provided, secret)
    except Exception:
        return False


def _before():
    try:
        if not _env_bool("SENTINEL_ENABLED", True):
            return None
        path = request.path or "/"
        if _is_exempt(path):
            return None
        ip = _d["get_ip"]()
        if not ip or ip == "unknown":
            return None
        now = _now()
        method = request.method
        _bump("requests")
        _load_cfg()
        m = _cfg["mode"]
        private = _is_private(ip)
        allowed = private or _is_allowed(ip)
        is_admin_path = path.startswith("/api/admin") or path == "/admin" or path.startswith("/admin/")
        admin_ok = _admin_secret_ok() if is_admin_path or path.startswith("/api/") else False

        # optional: hide the admin surface from everyone but your own network
        if is_admin_path and not allowed:
            only = _parse_nets(os.getenv("SENTINEL_ADMIN_ALLOW_IPS", ""))
            if only and not _in_nets(ip, only):
                _add(ip, "admin_recon", 25, path, once=5)
                return _deny("block", 404, None, message="Not found")

        # manual / stored blocks apply in every mode (an admin decided), unless the caller proves admin
        entry = None if allowed else _blocked_entry(ip)
        if entry and not admin_ok:
            _bump("blocked")
            return _deny("block" if entry["level"] != "restrict" else "restrict", 403 if entry["level"] != "restrict" else 429,
                         None, retry=900 if entry["level"] == "restrict" else None)

        if allowed:
            return None

        ua = request.headers.get("User-Agent", "")
        static = _is_static(path)
        crawler = _crawler_state(ip, ua)
        sensitive = path.startswith(SENSITIVE_PREFIXES)
        money = path.startswith(MONEY_PREFIXES)
        mutating = method in ("POST", "PUT", "PATCH", "DELETE")

        # --- emergency lockdown: stop new logins/registrations/money actions, keep pages + webhooks alive
        if _cfg["lockdown"] and sensitive and mutating and not admin_ok:
            _bump("lockdown_denied")
            return _deny("lockdown", 503, None, retry=120)

        if not static:
            with _lock:
                h = _hits[ip]
                h.append(now)
                _trim(h, 60, now)
                rate = len(h)
                if money and mutating:
                    mq = _money[ip]
                    mq.append(now)
                    _trim(mq, 60, now)
                    mrate = len(mq)
                else:
                    mrate = 0
            warn, flood = _env_int("SENTINEL_RATE_WARN", 100), _env_int("SENTINEL_RATE_FLOOD", 250)
            if crawler != "verified":
                if rate > flood:
                    _add(ip, "request_flood", 45, f"{rate} requests/min", once=60)
                elif rate > warn:
                    _add(ip, "api_abuse", 20, f"{rate} requests/min", once=60)
                if mrate > 15:
                    _add(ip, "payment_abuse", 30, f"{mrate} money actions/min", once=60)

        # --- user agent
        if ua and SCANNER_UA.search(ua):
            _add(ip, "scanner_tool", 60, SCANNER_UA.search(ua).group(0).lower(), once=300)
        elif mutating and sensitive and not ua:
            _add(ip, "no_user_agent", 8, path, once=300)
        elif mutating and path.startswith("/api/auth/") and TOOL_UA.match(ua or ""):
            _add(ip, "scripted_client", 10, (ua or "")[:30], once=300)
        if crawler == "unverified":
            _add(ip, "spoofed_crawler", 25, "claims to be a search crawler but reverse-DNS check failed", once=600)

        # --- reconnaissance paths
        if RECON_PATHS.search(path):
            _add(ip, "recon_probe", 15, path[:60], once=2)

        # --- attack patterns in URL and body
        hits = []
        for k, p, d in _scan_text(path + "?" + request.query_string.decode("latin-1", "ignore")):
            hits.append((k, p, d))
        bh = acct = None
        if mutating and not static:
            strings, bh, acct = _body_info(path)
            for s in strings:
                for k, p, d in _scan_text(s):
                    hits.append((k, p, d))
        seen = set()
        for k, p, d in hits:
            if k in seen:
                continue
            seen.add(k)
            _add(ip, k, p, f"{d} on {path[:60]}", once=3)
        inj = sorted(k for k in seen if k in INJECTION_KINDS)   # payloads carried by THIS request (not the shared IP)

        # --- replay of the exact same money request
        if money and mutating and bh:
            with _lock:
                rq = _replay[(ip, path, bh)]
                rq.append(now)
                _trim(rq, 20, now)
                n = len(rq)
                if len(_replay) > 5000:
                    _replay.clear()
            if n >= 4:
                _add(ip, "payment_replay", 25, f"same request {n}x in 20s", once=60)

        # remember the account for failure tracking in after_request
        request.environ["sentinel.acct"] = acct
        request.environ["sentinel.ip"] = ip

        score, reasons, kinds = _score(ip)
        action = _decide(score, kinds)
        if score > 0:
            _bump("flagged")
        enforce = m in ("adaptive", "maximum") and crawler != "verified" and not admin_ok

        # Account hold (Maximum): only when THIS request, from a logged-in session, carried injection payloads.
        held = None
        if inj and m == "maximum" and not admin_ok and crawler != "verified":
            held = _hold_for_injection(ip, inj, action, path)

        if action in ("block", "restrict") and enforce:
            minutes = 15 if action == "restrict" else None
            if action == "block":
                r = _conn().execute("SELECT strikes FROM security_scores WHERE ip = ?", (ip,)).fetchone()
                minutes = _block_minutes(r["strikes"] if (r and r["strikes"]) else 0)
            ref = _event(ip, kinds and sorted(kinds)[0] or "threat", 0, score, action, "; ".join(reasons[:4]), path, method)
            block_ip(ip, minutes, "; ".join(reasons[:3]) or "automatic", level=action, by="sentinel")
            _bump("blocked" if action == "block" else "restricted")
            _report_action(action, ip, minutes, score, reasons, ref, path, held)
            return _deny(action, 403 if action == "block" else 429, ref, retry=900 if action == "restrict" else None)
        if held:
            _bump("account_holds")
            _report_action("hold", ip, None, score, reasons or [f"{', '.join(inj)} payloads from a logged-in account"], held["ref"], path, held)
            return _deny("block", 403, held["ref"], message="Your account has been temporarily restricted for security reasons. Please contact support if you think this is a mistake.")
        if action == "challenge" and enforce and sensitive and mutating:
            ref = _event(ip, "challenge", 0, score, "challenge", "; ".join(reasons[:3]), path, method)
            _bump("challenged")
            return _deny("challenge", 429, ref, retry=60)
        if action == "ratelimit" and enforce and not static and rate > 30:
            _bump("ratelimited")
            return _deny("ratelimit", 429, None, retry=30)

        # record the evidence (observation or below enforcement thresholds)
        if score >= _thresholds()["monitor"] or hits or (ua and SCANNER_UA.search(ua)):
            newest = None
            with _lock:
                q = _signals.get(ip)
                if q:
                    newest = q[-1]
            kind = newest[2] if newest else "threat"
            detail = "; ".join(reasons[:4])
            act = action if m != "observation" else f"{action} (observed)"
            pts = {k_: p_ for k_, p_, _ in hits}
            if len(pts) > 1:  # one request carried several attack types: log each so the dashboard counts them all
                for k_, p_ in pts.items():
                    _event(ip, k_, p_, score, act, detail, path, method)
            else:
                _event(ip, kind, newest[1] if newest else 0, score, act, detail, path, method)
        return None
    except Exception:
        log.exception("SENTINEL before_request failed (request allowed)")
        return None


def _after(resp):
    try:
        if not _env_bool("SENTINEL_ENABLED", True):
            return resp
        path = request.path or "/"
        if _is_exempt(path):
            return resp
        ip = request.environ.get("sentinel.ip")
        if ip and not _is_private(ip) and not _is_allowed(ip):
            st = resp.status_code
            now = _now()
            acct = request.environ.get("sentinel.acct")
            if path in AUTH_FAIL_STATUS and st in AUTH_FAIL_STATUS[path]:
                with _lock:
                    q = _authfail[ip]
                    q.append((now, acct or "?"))
                    _trim(q, 600, now)
                    per_acct = defaultdict(int)
                    for _, a in q:
                        per_acct[a] += 1
                    same, distinct, total = max(per_acct.values()), len(per_acct), len(q)
                    if acct:
                        aq = _acct[acct]
                        aq.append((now, ip))
                        _trim(aq, 600, now)
                        spread = {x for _, x in aq}
                        acct_fail = len(aq)
                    else:
                        spread, acct_fail = set(), 0
                _add(ip, "auth_failure", 6, path, once=2)
                if same >= 6:
                    _add(ip, "brute_force", 35, f"{same} failed attempts on one account", once=300)
                if distinct >= 8 and total >= 10:
                    _add(ip, "credential_stuffing", 40, f"{distinct} different accounts tried", once=300)
                    # clearly automated (many accounts, many tries): block at once in Maximum
                    if mode() == "maximum" and distinct >= 15 and total >= 20 and not _blocked_entry(ip):
                        mins = _block_minutes(0)
                        if block_ip(ip, mins, f"credential stuffing: {distinct} accounts tried", level="auto"):
                            _event(ip, "credential_stuffing", 0, 90, "block", f"{distinct} different accounts, {total} failures in 10 min", path, request.method)
                            _report_action("block", ip, mins, 90, [f"credential stuffing: {distinct} different accounts, {total} failed logins in 10 minutes"], "", path)
                if acct_fail >= 10 and len(spread) >= 3:
                    k = ("ato", acct)
                    if now - _cooldown.get(k, 0) > 3600:
                        _cooldown[k] = now
                        _event(ip, "account_takeover_attempt", 0, 70, "alert",
                               f"{acct_fail} failures on one account from {len(spread)} IPs (account ref {acct})", path, request.method)
                        # The victim account is NOT locked (that would let an attacker lock out a real customer). Block this
                        # IP only if it also shows other bad behaviour, and tell the owner.
                        sc = _score(ip)[0]
                        if mode() == "maximum" and sc >= 40 and not _blocked_entry(ip):
                            mins = _block_minutes(0)
                            if block_ip(ip, mins, "account takeover attempt + other attack evidence", level="auto"):
                                _report_action("block", ip, mins, max(sc, 70), [f"{acct_fail} failed logins on one account from {len(spread)} IPs", f"score {sc} from other evidence"], "", path)
            elif (path.startswith("/api/admin") or path == "/admin") and st == 401:
                _add(ip, "admin_probe", 25, "wrong admin secret", once=1)
            elif st == 404 and not _is_static(path):
                with _lock:
                    nq = _notfound[ip]
                    nq.append(now)
                    _trim(nq, 60, now)
                    n = len(nq)
                if n > 15 and _crawler_state(ip, request.headers.get("User-Agent", "")) != "verified":
                    _add(ip, "path_scanning", 25, f"{n} not-found requests/min", once=60)
            # opportunistic tidy
            if len(_hits) > 20000:
                _prune()
        # light, additive hardening headers (only if the app has not set them)
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        if request.is_secure or request.headers.get("X-Forwarded-Proto", "") == "https":
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    except Exception:
        log.exception("SENTINEL after_request failed")
    return resp


def _prune():
    now = _now()
    with _lock:
        for d in (_hits, _money, _notfound):
            for k in [k for k, q in d.items() if not q or now - q[-1] > 120]:
                d.pop(k, None)
        for k in [k for k, q in _signals.items() if not q or now - q[-1][0] > SIGNAL_WINDOW]:
            _signals.pop(k, None)
        for d in (_authfail, _acct):
            for k in [k for k, q in d.items() if not q or now - q[-1][0] > 600]:
                d.pop(k, None)
        for k in [k for k, ts in _cooldown.items() if now - ts > 7200]:
            _cooldown.pop(k, None)
        if len(_replay) > 2000:
            _replay.clear()


# ---------------------------------------------------------------- public API for the rest of the app
def report(ip, kind, points=20, detail="", user_id=None):
    """Let app code add evidence, e.g. report(ip, 'wallet_manipulation', 40, 'negative amount', user_id=uid).
    With user_id, in Maximum mode and 40+ points, that account is deactivated for the hold period."""
    try:
        if ip and not _is_private(ip) and not _is_allowed(ip):
            _add(ip, str(kind)[:40], max(0, min(60, int(points))), detail)
            score, reasons, kinds = _score(ip)
            _event(ip, str(kind)[:40], points, score, "reported", detail)
            if user_id and mode() == "maximum" and int(points) >= 40:
                ref = hashlib.sha1(f"rep{user_id}{_now()}".encode()).hexdigest()[:10].upper()
                h = hold_account(user_id, ip, f"{kind}: {detail}", ref)
                if h:
                    _event(ip, "account_hold", 0, 90, "hold", f"user {user_id} held {h['hours']}h ({kind}) ref {ref}")
                    _report_action("hold", ip, None, score, [f"{kind}: {detail}"], ref, "", h)
    except Exception:
        log.exception("SENTINEL report failed")


# ---------------------------------------------------------------- background work
def _flush_counters():
    with _lock:
        snap = dict(_counters)
        _counters.clear()
    if not snap:
        return
    hour = datetime.utcnow().strftime("%Y-%m-%d %H:00")
    c = _conn()
    for k, n in snap.items():
        c.execute("INSERT INTO security_counters (hour, key, n) VALUES (?,?,?) ON CONFLICT(hour, key) DO UPDATE SET n = n + excluded.n", (hour, k, n))


def _reputation(ip):
    key = os.getenv("SENTINEL_ABUSEIPDB_KEY", "").strip()
    if not key or _is_private(ip):
        return
    try:
        r = _conn().execute("SELECT checked_at FROM threat_intelligence WHERE ip = ?", (ip,)).fetchone()
        if r and r["checked_at"] and r["checked_at"] > _utc(_now() - 86400):
            return
        req = urllib.request.Request(f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90",
                                     headers={"Key": key, "Accept": "application/json"})
        data = json.loads(urllib.request.urlopen(req, timeout=5).read().decode())["data"]
        conf = int(data.get("abuseConfidenceScore") or 0)
        _conn().execute("INSERT INTO threat_intelligence (ip, source, confidence, detail, checked_at) VALUES (?,?,?,?,?) "
                        "ON CONFLICT(ip) DO UPDATE SET confidence=excluded.confidence, detail=excluded.detail, checked_at=excluded.checked_at",
                        (ip, "abuseipdb", conf, f"reports={data.get('totalReports')}", _utc()))
        if conf >= 75:
            _add(ip, "bad_reputation", 30, f"AbuseIPDB confidence {conf}", once=3600)
    except Exception as e:
        log.debug("reputation lookup failed: %s", e)


def _housekeeping():
    n = 0
    while True:
        time.sleep(30)
        n += 1
        try:
            _flush_counters()
            _prune()
            _restore_expired_holds()
            if os.getenv("SENTINEL_ABUSEIPDB_KEY"):
                with _lock:
                    cands = [ip for ip, q in _signals.items() if q and sum(p for _, p, _, _ in q) >= 20][:3]
                for ip in cands:
                    _reputation(ip)
            if n % 120 == 0:  # about hourly
                days = _env_int("SENTINEL_RETENTION_DAYS", 90)
                c = _conn()
                c.execute("DELETE FROM security_events WHERE ts < ?", (_utc(_now() - days * 86400),))
                c.execute("DELETE FROM security_counters WHERE hour < ?", (_utc(_now() - days * 86400)[:13],))
                c.execute("DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at < ?", (_utc(_now() - 30 * 86400),))
                old = _utc(_now() - 30 * 86400)
                for r in c.execute("SELECT DISTINCT ip FROM security_events WHERE ts < ? AND ip NOT LIKE 'h:%' LIMIT 500", (old,)).fetchall():
                    c.execute("UPDATE security_events SET ip = ? WHERE ip = ? AND ts < ?", ("h:" + _hash(r["ip"]), r["ip"], old))
        except Exception:
            log.exception("SENTINEL housekeeping failed")


# ---------------------------------------------------------------- admin API
def _rows(sql, *a):
    return [dict(r) for r in _conn().execute(sql, a).fetchall()]


def _actor():
    return "admin:" + (_d["get_ip"]() or "?")


def init_sentinel(app, db_module, admin_required, get_ip, admin_secret=None, send_email=None, user_fn=None):
    """Register SENTINEL. Safe to call once, after the Flask app and routes exist.
    send_email(to, subject, body) emails the owner a report of every automatic action; user_fn() returns the logged-in
    user id for the current request (used only to deactivate an account that is itself sending attack payloads)."""
    global _started
    _d.update(db=db_module, get_ip=get_ip, admin_secret=admin_secret, email=send_email, user_fn=user_fn)
    ensure_schema()
    _load_cfg(True)
    _load_lists(True)
    # One-time upgrade: the platform now defends actively. Later manual changes in the Security tab are respected.
    try:
        if _setting("mode_default_v2") != "1":
            _set_setting("mode_default_v2", "1")
            if not os.getenv("SENTINEL_FORCE_MODE", "").strip() and _setting("mode") != "maximum":
                _set_setting("mode", "maximum")
                _audit("system", "mode_changed", "maximum", "default switched to Maximum on upgrade")
            _load_cfg(True)
    except Exception:
        log.exception("SENTINEL: mode migration failed")

    # run before every other before_request handler, so attackers are stopped before any app code runs
    app.before_request_funcs.setdefault(None, []).insert(0, _before)
    app.after_request(_after)

    @app.route("/admin_sentinel.js")
    def sentinel_js():
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin_sentinel.js")
        try:
            with open(p, "rb") as f:
                resp = Response(f.read(), mimetype="application/javascript")
            resp.headers["Cache-Control"] = "no-cache"
            return resp
        except OSError:
            return Response("/* admin_sentinel.js missing */", mimetype="application/javascript", status=404)

    @app.route("/api/admin/sentinel/overview", methods=["GET"])
    @admin_required
    def sentinel_overview():
        try:
            hours = max(1, min(720, int(request.args.get("hours", 24))))
        except ValueError:
            hours = 24
        _flush_counters()
        _load_cfg(True)
        _load_lists(True)
        since = _utc(_now() - hours * 3600)
        c = _conn()
        cnt = {r["key"]: r["n"] for r in _rows("SELECT key, SUM(n) AS n FROM security_counters WHERE hour >= ? GROUP BY key", since[:13] + ":00")}
        sev = {r["severity"]: r["n"] for r in _rows("SELECT severity, COUNT(*) AS n FROM security_events WHERE ts >= ? GROUP BY 1", since)}
        by_kind = _rows("SELECT kind, COUNT(*) AS n, MAX(score) AS max_score FROM security_events WHERE ts >= ? GROUP BY 1 ORDER BY n DESC LIMIT 20", since)
        top = _rows("""SELECT ip, COUNT(*) AS events, MAX(score) AS max_score, MAX(ts) AS last_seen,
                       MAX(country) AS country, MAX(org) AS org,
                       (SELECT action FROM security_events e2 WHERE e2.ip = e.ip ORDER BY id DESC LIMIT 1) AS last_action,
                       (SELECT kind FROM security_events e3 WHERE e3.ip = e.ip ORDER BY score DESC, id DESC LIMIT 1) AS main_kind
                    FROM security_events e WHERE ts >= ? AND ip IS NOT NULL GROUP BY ip ORDER BY max_score DESC, events DESC LIMIT 15""", since)
        for t in top:
            t["band"] = _band(t["max_score"] or 0)
        fmt = "%Y-%m-%d %H:00" if hours <= 72 else "%Y-%m-%d"
        sub = 13 if hours <= 72 else 10
        timeline = _rows(f"SELECT substr(ts,1,{sub}) AS bucket, COUNT(*) AS events, "
                         f"SUM(CASE WHEN action IN ('block','restrict') THEN 1 ELSE 0 END) AS blocked FROM security_events WHERE ts >= ? GROUP BY 1 ORDER BY 1", since)
        live = _rows("SELECT id, ts, ip, country, org, kind, severity, score, action, path, detail, ref FROM security_events ORDER BY id DESC LIMIT 40")
        for e in live:
            e["band"] = _band(e["score"] or 0)
        blocks_now = c.execute("SELECT COUNT(*) FROM blocked_ips WHERE expires_at IS NULL OR expires_at > ?", (_utc(),)).fetchone()[0]
        high_risk = len({e["ip"] for e in _rows("SELECT ip FROM security_events WHERE ts >= ? AND score >= 60", since)})
        kinds_count = lambda *ks: sum(r["n"] for r in by_kind if r["kind"] in ks)
        return jsonify({
            "success": True, "hours": hours, "mode": _cfg["mode"], "forced_mode": bool(os.getenv("SENTINEL_FORCE_MODE")),
            "lockdown": _cfg["lockdown"], "thresholds": _thresholds(),
            "kpis": {
                "requests_monitored": cnt.get("requests", 0), "flagged_requests": cnt.get("flagged", 0),
                "threat_events": sum(sev.values()), "active_blocks": blocks_now, "active_holds": c.execute("SELECT COUNT(*) FROM account_holds WHERE until > ?", (_utc(),)).fetchone()[0], "high_risk_sources": high_risk,
                "blocked_requests": cnt.get("blocked", 0) + cnt.get("restricted", 0), "challenged": cnt.get("challenged", 0),
                "rate_limited": cnt.get("ratelimited", 0), "lockdown_denied": cnt.get("lockdown_denied", 0),
                "brute_force": kinds_count("brute_force", "credential_stuffing", "auth_failure"),
                "injection_attempts": kinds_count("sql_injection", "xss", "command_injection", "directory_traversal"),
                "api_abuse": kinds_count("api_abuse", "request_flood", "payment_abuse", "payment_replay"),
                "recon": kinds_count("recon_probe", "admin_probe", "path_scanning", "admin_recon", "scanner_tool"),
                "critical": sev.get("critical", 0) + sev.get("very_high", 0),
            },
            "severity": sev, "by_kind": by_kind, "top_sources": top, "timeline": timeline, "live": live,
            "allow_count": c.execute("SELECT COUNT(*) FROM security_exceptions").fetchone()[0],
            "asn_blocks": c.execute("SELECT COUNT(*) FROM blocked_networks").fetchone()[0],
            "abuseipdb": bool(os.getenv("SENTINEL_ABUSEIPDB_KEY")),
            "alerts_configured": bool(os.getenv("SENTINEL_ALERT_WEBHOOK_URL") or os.getenv("INTEL_ALERT_WEBHOOK_URL") or
                                      ((os.getenv("SENTINEL_ALERT_TELEGRAM_BOT_TOKEN") or os.getenv("INTEL_ALERT_TELEGRAM_BOT_TOKEN")) and
                                       (os.getenv("SENTINEL_ALERT_TELEGRAM_CHAT_ID") or os.getenv("INTEL_ALERT_TELEGRAM_CHAT_ID")))),
            "admin_ip_lock": bool(os.getenv("SENTINEL_ADMIN_ALLOW_IPS")),
            "workers_note": "Counters and live scores are per server process; blocks, settings and events are shared through the database.",
        })

    @app.route("/api/admin/sentinel/events", methods=["GET"])
    @admin_required
    def sentinel_events():
        try:
            limit = max(1, min(500, int(request.args.get("limit", 100))))
            min_score = max(0, int(request.args.get("min_score", 0)))
        except ValueError:
            limit, min_score = 100, 0
        ip = (request.args.get("ip") or "").strip()
        sql, args = "SELECT * FROM security_events WHERE score >= ?", [min_score]
        if ip:
            sql += " AND ip = ?"
            args.append(ip)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        _audit(_actor(), "events_viewed", ip or "all", f"min_score={min_score}")
        return jsonify({"success": True, "events": _rows(sql, *args)})

    @app.route("/api/admin/sentinel/blocks", methods=["GET"])
    @admin_required
    def sentinel_blocks():
        _load_lists(True)
        return jsonify({
            "success": True,
            "holds": _rows("SELECT h.user_id, h.until, h.reason, h.ref, h.ip, h.created_at, u.email FROM account_holds h LEFT JOIN users u ON u.id = h.user_id ORDER BY h.created_at DESC LIMIT 100"),
            "ips": _rows("SELECT ip, reason, level, source, strikes, created_at, expires_at, created_by FROM blocked_ips ORDER BY created_at DESC LIMIT 300"),
            "networks": _rows("SELECT asn, reason, created_at, created_by FROM blocked_networks ORDER BY created_at DESC"),
            "allow": _rows("SELECT id, value, note, created_at, created_by FROM security_exceptions ORDER BY id DESC"),
            "env_allow": [str(n) for n in _parse_nets(os.getenv("SENTINEL_ALLOW_IPS", ""))],
            "exempt_prefixes": list(_exempt_prefixes()),
        })

    def _json():
        return request.get_json(silent=True) or {}

    @app.route("/api/admin/sentinel/block", methods=["POST"])
    @admin_required
    def sentinel_block():
        d = _json()
        ip = str(d.get("ip") or "").strip()
        try:
            minutes = int(d.get("minutes") or 0)
        except (TypeError, ValueError):
            minutes = 0
        if not ip:
            return jsonify({"success": False, "error": "ip required"}), 400
        if _is_allowed(ip) or _is_private(ip.split("/")[0]):
            return jsonify({"success": False, "error": "That address is private or on the allow list."}), 400
        if ip == _d["get_ip"]():
            return jsonify({"success": False, "error": "That is your own address. Blocking it would lock you out."}), 400
        ok = block_ip(ip, minutes, d.get("reason") or "manual block", level="manual" if minutes else "manual_permanent", by=_actor())
        _audit(_actor(), "block_ip", ip, f"minutes={minutes} reason={d.get('reason')}")
        return jsonify({"success": bool(ok)}), (200 if ok else 400)

    @app.route("/api/admin/sentinel/holds/release", methods=["POST"])
    @admin_required
    def sentinel_release_hold():
        try:
            uid = int(_json().get("user_id"))
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "user_id required"}), 400
        restored = release_account(uid, actor=_actor(), note="released by admin")
        _audit(_actor(), "hold_released", f"user {uid}", f"restored={restored}")
        return jsonify({"success": True, "restored": restored})

    @app.route("/api/admin/sentinel/unblock", methods=["POST"])
    @admin_required
    def sentinel_unblock():
        ip = str(_json().get("ip") or "").strip()
        n = unblock_ip(ip)
        _audit(_actor(), "unblock_ip", ip, f"rows={n}")
        return jsonify({"success": True, "removed": n})

    @app.route("/api/admin/sentinel/allow", methods=["POST", "DELETE"])
    @admin_required
    def sentinel_allow():
        d = _json()
        if request.method == "DELETE":
            _conn().execute("DELETE FROM security_exceptions WHERE value = ?", (str(d.get("value") or "").strip(),))
            _audit(_actor(), "allow_removed", d.get("value"))
            _blocks["loaded"] = 0
            _load_lists(True)
            return jsonify({"success": True})
        val = str(d.get("value") or "").strip()
        if not _parse_nets(val):
            return jsonify({"success": False, "error": "Enter an IP address or CIDR range."}), 400
        _conn().execute("INSERT OR REPLACE INTO security_exceptions (value, note, created_at, created_by) VALUES (?,?,?,?)",
                        (val, str(d.get("note") or "")[:120], _utc(), _actor()))
        unblock_ip(val)
        _audit(_actor(), "allow_added", val, d.get("note"))
        _load_lists(True)
        return jsonify({"success": True})

    @app.route("/api/admin/sentinel/block-network", methods=["POST", "DELETE"])
    @admin_required
    def sentinel_block_network():
        d = _json()
        asn = re.sub(r"[^0-9]", "", str(d.get("asn") or ""))
        if not asn:
            return jsonify({"success": False, "error": "ASN number required (for example 14061)."}), 400
        if request.method == "DELETE":
            _conn().execute("DELETE FROM blocked_networks WHERE asn = ?", (asn,))
            _audit(_actor(), "network_unblocked", "AS" + asn)
        else:
            _conn().execute("INSERT OR REPLACE INTO blocked_networks (asn, reason, created_at, expires_at, created_by) VALUES (?,?,?,?,?)",
                            (asn, str(d.get("reason") or "manual")[:120], _utc(), None, _actor()))
            _audit(_actor(), "network_blocked", "AS" + asn, d.get("reason"))
        _load_lists(True)
        return jsonify({"success": True})

    @app.route("/api/admin/sentinel/mode", methods=["POST"])
    @admin_required
    def sentinel_mode():
        m = str(_json().get("mode") or "").lower()
        if m not in MODES:
            return jsonify({"success": False, "error": "mode must be observation, adaptive or maximum"}), 400
        _set_setting("mode", m)
        _audit(_actor(), "mode_changed", m)
        _load_cfg(True)
        return jsonify({"success": True, "mode": _cfg["mode"], "forced": bool(os.getenv("SENTINEL_FORCE_MODE"))})

    @app.route("/api/admin/sentinel/lockdown", methods=["POST"])
    @admin_required
    def sentinel_lockdown():
        on = bool(_json().get("on"))
        _set_setting("lockdown", "1" if on else "0")
        _audit(_actor(), "lockdown_on" if on else "lockdown_off", "")
        _load_cfg(True)
        if on:
            _notify(_d["get_ip"]() or "admin", "emergency_lockdown", 100, "lockdown", "enabled by admin", "ADMIN")
        return jsonify({"success": True, "lockdown": _cfg["lockdown"]})

    @app.route("/api/admin/sentinel/audit", methods=["GET"])
    @admin_required
    def sentinel_audit():
        return jsonify({"success": True, "audit": _rows("SELECT ts, actor, action, target, detail FROM security_audit_logs ORDER BY id DESC LIMIT 200"),
                        "notifications": _rows("SELECT ts, channel, subject, ok, detail FROM security_notifications ORDER BY id DESC LIMIT 30")})

    @app.route("/api/admin/sentinel/report.csv", methods=["GET"])
    @admin_required
    def sentinel_report():
        try:
            days = max(1, min(90, int(request.args.get("days", 7))))
        except ValueError:
            days = 7
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["time_utc", "ip", "country", "network", "kind", "severity", "score", "action", "mode", "path", "detail", "ref"])
        for r in _rows("SELECT * FROM security_events WHERE ts >= ? ORDER BY id DESC LIMIT 20000", _utc(_now() - days * 86400)):
            w.writerow([r["ts"], r["ip"], r["country"], r["org"], r["kind"], r["severity"], r["score"], r["action"], r["mode"], r["path"], r["detail"], r["ref"]])
        _audit(_actor(), "report_exported", f"{days}d")
        return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=sentinel_{days}d.csv"})

    if not _started and _env_bool("SENTINEL_BACKGROUND", True):
        _started = True
        threading.Thread(target=_housekeeping, daemon=True, name="sentinel-housekeeping").start()
    log.info("NET365 SENTINEL active (mode=%s). Webhook, bot and health paths are exempt.", _cfg["mode"])

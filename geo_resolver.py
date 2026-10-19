"""Visitor geolocation fallback for Net365.

Why this exists: log_page_visit() only reads Cloudflare's CF-IPCountry / CF-IPCity headers.
Those headers do not exist when the site is served straight from Railway (or when Cloudflare's
"Add visitor location headers" transform is off), so the Country and City columns stay empty.

This module fills them in from the visitor's IP, in a background thread so a slow lookup can
never delay a page, and it can backfill rows that were saved without a location.

Providers (env GEO_PROVIDER, default "auto"):
  maxmind  offline GeoLite2-City database (set GEOIP_DB_PATH, pip install geoip2). No IP ever
           leaves your server. Recommended for production and for data-protection compliance.
  ipwhois  https://ipwho.is (free, no key). Sends the visitor IP to a third party.
  ipinfo   https://ipinfo.io (set IPINFO_TOKEN). Sends the visitor IP to a third party.
  off      disable lookups.
  auto     maxmind if GEOIP_DB_PATH points to a file, otherwise ipwhois.

Other env vars: GEO_MIN_INTERVAL (seconds between API calls, default 0.7),
GEO_BACKFILL_ON_START (default true), GEO_BACKFILL_LIMIT (default 300).
"""
import ipaddress
import logging
import os
import queue
import threading
import time

import requests

log = logging.getLogger(__name__)

HIT_TTL = 30 * 24 * 3600     # cache a successful lookup for 30 days
MISS_TTL = 3600              # retry a failed lookup after an hour
CACHE_MAX = 20000
_GEO_COLUMNS = ("country", "city", "region", "timezone")


def is_public_ip(value):
    """True for a routable public address (not private, loopback, link-local, etc.)."""
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    return addr.is_global


def _clean(value, limit=80):
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] if text else None


def _normalise(country, city, region, timezone):
    country = _clean(country, 8)                 # do not truncate: "Nigeria" must not become "NI"
    country = country.upper() if country and len(country) == 2 and country.isalpha() else None
    if not country:
        return None
    return {"country": country, "city": _clean(city), "region": _clean(region),
            "timezone": _clean(timezone, 64)}


class GeoResolver:
    _lock = threading.Lock()
    _cache = {}                      # ip -> (expires_at, result or None)
    _pending = set()
    _queue = queue.Queue(maxsize=2000)
    _thread = None
    _get_conn = None
    _columns = None
    _reader = None
    _reader_path = None
    _last_call = 0.0
    stats = {"resolved": 0, "failed": 0, "rows_updated": 0, "dropped": 0, "last_error": ""}

    # ------------------------------------------------------------------ setup
    @classmethod
    def configure(cls, get_conn, backfill_on_start=None):
        """get_conn: callable returning a sqlite3 connection (db.get_db_connection)."""
        cls._get_conn = staticmethod(get_conn)
        if backfill_on_start is None:
            backfill_on_start = os.getenv("GEO_BACKFILL_ON_START", "true").lower() in ("1", "true", "yes")
        if backfill_on_start and cls.provider() != "off":
            def delayed():
                time.sleep(25)       # let the app finish creating its tables first
                try:
                    cls.backfill(int(os.getenv("GEO_BACKFILL_LIMIT", "300")))
                except Exception as exc:
                    log.warning("Geo backfill at startup failed: %s", exc)
            threading.Thread(target=delayed, daemon=True, name="geo-backfill-start").start()

    @classmethod
    def provider(cls):
        choice = os.getenv("GEO_PROVIDER", "auto").strip().lower()
        if choice == "auto":
            path = os.getenv("GEOIP_DB_PATH", "").strip()
            return "maxmind" if path and os.path.exists(path) else "ipwhois"
        return choice if choice in ("maxmind", "ipwhois", "ipinfo", "off") else "off"

    # ---------------------------------------------------------------- lookups
    @classmethod
    def _lookup_maxmind(cls, ip):
        path = os.getenv("GEOIP_DB_PATH", "").strip()
        if cls._reader is None or cls._reader_path != path:
            import geoip2.database          # pip install geoip2
            cls._reader = geoip2.database.Reader(path)
            cls._reader_path = path
        r = cls._reader.city(ip)
        sub = r.subdivisions.most_specific.name if r.subdivisions else None
        return _normalise(r.country.iso_code, r.city.name, sub, r.location.time_zone)

    @classmethod
    def _throttle(cls):
        gap = float(os.getenv("GEO_MIN_INTERVAL", "0.7"))
        wait = cls._last_call + gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        cls._last_call = time.monotonic()

    @classmethod
    def _lookup_ipwhois(cls, ip):
        cls._throttle()
        r = requests.get(f"https://ipwho.is/{ip}", timeout=4,
                         params={"fields": "success,message,country_code,city,region,timezone"})
        r.raise_for_status()
        d = r.json()
        if not d.get("success", False):
            raise ValueError(d.get("message") or "lookup refused")
        tz = d.get("timezone")
        tz = tz.get("id") if isinstance(tz, dict) else tz
        return _normalise(d.get("country_code"), d.get("city"), d.get("region"), tz)

    @classmethod
    def _lookup_ipinfo(cls, ip):
        token = os.getenv("IPINFO_TOKEN", "").strip()
        if not token:
            raise ValueError("IPINFO_TOKEN is not set")
        cls._throttle()
        r = requests.get(f"https://ipinfo.io/{ip}", timeout=4,
                         headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        r.raise_for_status()
        d = r.json()
        return _normalise(d.get("country"), d.get("city"), d.get("region"), d.get("timezone"))

    @classmethod
    def lookup(cls, ip):
        """Resolve one IP (cached). Returns a dict or None. Blocks on the network: call from a worker."""
        ip = str(ip or "").strip()
        provider = cls.provider()
        if provider == "off" or not is_public_ip(ip):
            return None
        now = time.time()
        with cls._lock:
            hit = cls._cache.get(ip)
            if hit and hit[0] > now:
                return hit[1]
        try:
            fn = {"maxmind": cls._lookup_maxmind, "ipwhois": cls._lookup_ipwhois,
                  "ipinfo": cls._lookup_ipinfo}[provider]
            result = fn(ip)
            if result:
                cls.stats["resolved"] += 1
            else:
                cls.stats["failed"] += 1
        except Exception as exc:
            result = None
            cls.stats["failed"] += 1
            cls.stats["last_error"] = f"{type(exc).__name__}: {exc}"[:200]
            log.debug("Geo lookup failed for %s: %s", ip, exc)
        with cls._lock:
            if len(cls._cache) >= CACHE_MAX:
                for key in [k for k, v in cls._cache.items() if v[0] <= now][:CACHE_MAX // 4] or \
                           list(cls._cache)[:CACHE_MAX // 4]:
                    cls._cache.pop(key, None)
            cls._cache[ip] = (now + (HIT_TTL if result else MISS_TTL), result)
        return result

    # --------------------------------------------------------------------- DB
    @classmethod
    def _visitor_columns(cls, conn):
        if cls._columns is None:
            cls._columns = {row[1] for row in conn.execute("PRAGMA table_info(visitor_logs)").fetchall()}
        return cls._columns

    @classmethod
    def apply(cls, ip, geo):
        """Write a location onto every visitor_logs row for this IP that is missing one.
        Never overwrites a value that is already there (for example from Cloudflare)."""
        if not geo or cls._get_conn is None:
            return 0
        conn = cls._get_conn()
        try:
            cols = cls._visitor_columns(conn)
            sets, params = [], []
            for col in _GEO_COLUMNS:                       # fixed whitelist, never user input
                if col in cols and geo.get(col):
                    sets.append(f"{col} = CASE WHEN {col} IS NULL OR {col} = '' THEN ? ELSE {col} END")
                    params.append(geo[col])
            if not sets:
                return 0
            cur = conn.execute(
                f"UPDATE visitor_logs SET {', '.join(sets)} WHERE ip_address = ? "
                "AND (country IS NULL OR country = '' OR city IS NULL OR city = '')",
                (*params, ip))
            conn.commit()
            cls.stats["rows_updated"] += max(cur.rowcount, 0)
            return cur.rowcount
        finally:
            conn.close()

    # ----------------------------------------------------------------- worker
    @classmethod
    def _ensure_worker(cls):
        with cls._lock:
            if cls._thread and cls._thread.is_alive():
                return
            cls._thread = threading.Thread(target=cls._run, daemon=True, name="geo-resolver")
            cls._thread.start()

    @classmethod
    def _run(cls):
        while True:
            ip = cls._queue.get()
            with cls._lock:
                cls._pending.discard(ip)     # removed first so a visit that arrives mid-lookup re-queues
            try:
                cls.apply(ip, cls.lookup(ip))
            except Exception as exc:
                cls.stats["last_error"] = f"{type(exc).__name__}: {exc}"[:200]
                log.warning("Geo update failed for %s: %s", ip, exc)

    @classmethod
    def enqueue(cls, ip):
        """Non-blocking. Safe to call on every visit."""
        ip = str(ip or "").strip()
        if cls.provider() == "off" or not is_public_ip(ip):
            return False
        with cls._lock:
            if ip in cls._pending:
                return False
            cls._pending.add(ip)
        try:
            cls._queue.put_nowait(ip)
        except queue.Full:
            with cls._lock:
                cls._pending.discard(ip)
            cls.stats["dropped"] += 1
            return False
        cls._ensure_worker()
        return True

    # --------------------------------------------------------------- backfill
    @classmethod
    def missing_count(cls):
        if cls._get_conn is None:
            return 0
        conn = cls._get_conn()
        try:
            row = conn.execute(
                "SELECT COUNT(DISTINCT ip_address) FROM visitor_logs WHERE ip_address IS NOT NULL "
                "AND ip_address NOT IN ('', 'unknown') AND (country IS NULL OR country = '' "
                "OR city IS NULL OR city = '')").fetchone()
            return int(row[0] or 0)
        finally:
            conn.close()

    @classmethod
    def backfill(cls, limit=300):
        """Queue the most recent IPs whose rows lack a country or city. Returns how many were queued."""
        if cls._get_conn is None or cls.provider() == "off":
            return 0
        limit = max(1, min(int(limit), 2000))
        conn = cls._get_conn()
        try:
            rows = conn.execute(
                "SELECT ip_address FROM visitor_logs WHERE ip_address IS NOT NULL "
                "AND ip_address NOT IN ('', 'unknown') AND (country IS NULL OR country = '' "
                "OR city IS NULL OR city = '') GROUP BY ip_address "
                "ORDER BY MAX(visited_at) DESC LIMIT ?", (limit * 4,)).fetchall()
        finally:
            conn.close()
        now, queued = time.time(), 0
        for row in rows:
            ip = row[0]
            with cls._lock:
                miss = cls._cache.get(ip)
            if miss and miss[1] is None and miss[0] > now:
                continue                      # recently failed: do not let it crowd out new ones
            if cls.enqueue(ip):
                queued += 1
                if queued >= limit:
                    break
        return queued

    @classmethod
    def status(cls):
        return {"provider": cls.provider(), "queue": cls._queue.qsize(), "cache": len(cls._cache),
                **cls.stats}

# ip_intel.py
"""
Net365 IP Intelligence
======================
Resolves the organization / ASN / company / bot-class behind a visitor IP,
so the admin panel can show WHO is visiting (Microsoft, Amazon, a data
center, an AI crawler, etc.) instead of just a raw IP string.

Design:
  * Tier 1 — Local CIDR table for well-known corporate + cloud ranges.
             Zero latency, zero API calls, works offline.
  * Tier 2 — HTTP lookup against ipwhois.app / ipinfo.io / ip-api.com
             (whichever answers first), cached in SQLite forever.
  * Never blocks the request path. Enrichment always runs on a daemon
    worker thread. The visitor row is inserted immediately with
    org_name=NULL and updated a moment later.

Usage from app.py:
    from ip_intel import IPIntel
    IPIntel.ensure_schema(db.get_db_connection)
    IPIntel.enqueue(ip_address)          # non-blocking, dedup'd
    IPIntel.start_worker()               # call once at boot
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import queue
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tier 1 — Local CIDR table
# ---------------------------------------------------------------------------
# Keys are human labels. Values are lists of CIDR blocks. Keep this short and
# accurate — it's the fast path, not the only path. Add ranges you care about;
# anything not listed falls through to the HTTP lookup.
#
# Sources: Microsoft's published Azure ranges, AWS ip-ranges.json, Google
# Cloud, Cloudflare's public list, plus a few well-known SaaS/CDN blocks.
# ---------------------------------------------------------------------------
KNOWN_RANGES: Dict[str, Dict[str, object]] = {
    # ── Hyperscalers / clouds ──────────────────────────────────────────
    "Microsoft (Azure / Office 365)": {
        "asn": "AS8075", "org": "Microsoft Corporation", "kind": "cloud",
        "cidrs": [
            "13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10", "52.0.0.0/8",
            "104.40.0.0/13", "13.107.0.0/16", "40.96.0.0/12",
            "52.96.0.0/12", "52.112.0.0/14", "52.120.0.0/14",
            "150.171.0.0/16", "204.79.197.0/24",
        ],
    },
    "Amazon (AWS / CloudFront)": {
        "asn": "AS16509", "org": "Amazon.com, Inc.", "kind": "cloud",
        "cidrs": [
            "3.0.0.0/8", "13.32.0.0/15", "13.224.0.0/14", "18.0.0.0/8",
            "34.192.0.0/12", "35.152.0.0/13", "52.0.0.0/8", "54.0.0.0/8",
            "99.77.0.0/16", "99.82.0.0/16", "205.251.192.0/18",
        ],
    },
    "Google (GCP / Googlebot)": {
        "asn": "AS15169", "org": "Google LLC", "kind": "cloud",
        "cidrs": [
            "8.8.4.0/24", "8.8.8.0/24", "34.64.0.0/10", "35.184.0.0/13",
            "66.249.64.0/19", "72.14.192.0/18", "74.125.0.0/16",
            "142.250.0.0/15", "172.217.0.0/16", "209.85.128.0/17",
        ],
    },
    "Cloudflare": {
        "asn": "AS13335", "org": "Cloudflare, Inc.", "kind": "cdn",
        "cidrs": [
            "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
            "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
            "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
            "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
            "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
        ],
    },
    "DigitalOcean": {
        "asn": "AS14061", "org": "DigitalOcean, LLC", "kind": "vps",
        "cidrs": [
            "64.225.0.0/16", "104.131.0.0/16", "104.236.0.0/16",
            "138.68.0.0/16", "142.93.0.0/16", "143.198.0.0/16",
            "157.245.0.0/16", "159.65.0.0/16", "159.89.0.0/16",
            "161.35.0.0/16", "164.90.0.0/16", "165.22.0.0/16",
            "167.71.0.0/16", "174.138.0.0/16", "178.128.0.0/16",
            "188.166.0.0/16", "206.189.0.0/16", "209.97.0.0/16",
        ],
    },
    "Linode / Akamai": {
        "asn": "AS63949", "org": "Akamai Technologies", "kind": "vps",
        "cidrs": [
            "45.33.0.0/16", "45.56.0.0/16", "45.79.0.0/16",
            "50.116.0.0/16", "66.175.208.0/20", "69.164.192.0/18",
            "96.126.96.0/19", "139.144.0.0/16", "170.187.128.0/17",
            "172.104.0.0/15", "173.255.192.0/18", "192.155.80.0/20",
        ],
    },
    "Oracle Cloud": {
        "asn": "AS31898", "org": "Oracle Corporation", "kind": "cloud",
        "cidrs": [
            "129.146.0.0/16", "129.213.0.0/16", "130.35.0.0/16",
            "132.145.0.0/16", "138.1.0.0/16", "140.91.0.0/16",
            "150.136.0.0/16", "152.67.0.0/16", "158.101.0.0/16",
            "192.29.0.0/16",
        ],
    },
    # ── CDNs / edge / security ────────────────────────────────────────
    "Fastly": {
        "asn": "AS54113", "org": "Fastly, Inc.", "kind": "cdn",
        "cidrs": ["23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
                  "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
                  "185.31.16.0/22", "199.27.72.0/21"],
    },
    "Akamai": {
        "asn": "AS20940", "org": "Akamai Technologies", "kind": "cdn",
        "cidrs": ["23.0.0.0/12", "23.32.0.0/11", "23.192.0.0/11",
                  "96.6.0.0/15", "96.16.0.0/15", "104.64.0.0/10",
                  "184.24.0.0/13", "184.50.0.0/15", "184.84.0.0/14"],
    },
    # ── AI crawlers (declared user-agents, matched via reverse DNS later) ─
    "OpenAI": {
        "asn": "AS135377", "org": "OpenAI, L.L.C.", "kind": "ai",
        "cidrs": ["20.102.0.0/16", "172.203.0.0/16", "13.65.0.0/16"],
    },
    "Anthropic (ClaudeBot)": {
        "asn": "AS399358", "org": "Anthropic, PBC", "kind": "ai",
        "cidrs": ["160.79.104.0/23", "34.162.0.0/16"],
    },
    "Perplexity": {
        "asn": "AS394477", "org": "Perplexity AI", "kind": "ai",
        "cidrs": ["44.208.0.0/13", "3.130.0.0/16"],
    },
    # ── Africa / Nigeria ISPs (the ones you'll actually see) ──────────
    "MTN Nigeria": {
        "asn": "AS29465", "org": "MTN Nigeria Communications", "kind": "isp",
        "cidrs": ["41.58.0.0/16", "41.184.0.0/16", "41.190.0.0/16",
                  "102.89.0.0/16", "105.112.0.0/14", "197.210.0.0/16"],
    },
    "Glo (Globacom)": {
        "asn": "AS37282", "org": "Globacom Limited", "kind": "isp",
        "cidrs": ["41.155.0.0/16", "41.203.64.0/18", "41.206.0.0/16",
                  "197.211.0.0/16"],
    },
    "Airtel Nigeria": {
        "asn": "AS36873", "org": "Airtel Networks Limited", "kind": "isp",
        "cidrs": ["41.58.128.0/17", "41.189.0.0/16", "105.112.0.0/16",
                  "197.210.128.0/17"],
    },
    "9mobile Nigeria": {
        "asn": "AS37076", "org": "Emerging Markets Telecommunication Services",
        "kind": "isp",
        "cidrs": ["41.138.0.0/16", "41.221.0.0/16", "197.210.0.0/18"],
    },
    "Spectranet": {
        "asn": "AS37027", "org": "Spectranet Limited", "kind": "isp",
        "cidrs": ["41.78.0.0/17", "197.211.0.0/18"],
    },
    "Smile Communications": {
        "asn": "AS37662", "org": "Smile Communications", "kind": "isp",
        "cidrs": ["41.86.0.0/16", "41.221.128.0/17"],
    },
    # ── Known VPN / privacy egress ────────────────────────────────────
    "Mullvad VPN": {
        "asn": "AS20473", "org": "Mullvad VPN", "kind": "vpn",
        "cidrs": ["45.83.220.0/22", "185.65.134.0/23", "194.132.36.0/22"],
    },
    "NordVPN": {
        "asn": "AS9009", "org": "NordVPN", "kind": "vpn",
        "cidrs": ["45.14.224.0/19", "194.31.12.0/22", "194.242.60.0/22"],
    },
}

# Flatten once for fast lookup
_FLAT: list = []
for _label, _meta in KNOWN_RANGES.items():
    for _cidr in _meta["cidrs"]:
        try:
            _FLAT.append((
                ipaddress.ip_network(_cidr, strict=False),
                _label,
                _meta["asn"],
                _meta["org"],
                _meta["kind"],
            ))
        except ValueError as e:
            logger.warning(f"ip_intel: bad CIDR {_cidr} in {_label}: {e}")

# Sort by prefix length descending so /24 matches before /8
_FLAT.sort(key=lambda r: r[0].prefixlen, reverse=True)


def classify_local(ip: str) -> Optional[Dict[str, str]]:
    """Fast, offline lookup. Returns dict or None."""
    if not ip or ip in ("unknown", "127.0.0.1", "::1"):
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback or addr.is_reserved:
        return {
            "org_name": "Private / Local network",
            "asn": None,
            "ip_kind": "private",
            "label": "Private / Local network",
            "source": "local",
        }
    for net, label, asn, org, kind in _FLAT:
        if addr in net:
            return {
                "org_name": org,
                "asn": asn,
                "ip_kind": kind,
                "label": label,
                "source": "local",
            }
    return None


# ---------------------------------------------------------------------------
# Tier 2 — HTTP lookup with failover
# ---------------------------------------------------------------------------
_HOSTING_WORDS = ("amazon", "aws", "microsoft", "azure", "google", "cloud", "digitalocean", "linode", "ovh", "hetzner",
                  "oracle", "vultr", "contabo", "hosting", "datacenter", "data center", "server", "colo", "leaseweb",
                  "choopa", "m247", "scaleway", "alibaba", "tencent", "rackspace", "heroku", "railway", "vercel", "netlify")
_VPN_WORDS = ("vpn", "proxy", "tor exit", "mullvad", "nord", "expressvpn", "surfshark", "privateinternet", "proton")
_CDN_WORDS = ("cloudflare", "akamai", "fastly", "cloudfront", "edgecast", "incapsula", "imperva", "stackpath")
_ISP_WORDS = ("telecom", "mobile", "communications", "broadband", "cable", "wireless", "networks", "network", "internet",
              "isp", "mtn", "airtel", "globacom", "glo ", "9mobile", "etisalat", "spectranet", "smile", "vodafone",
              "orange", "safaricom", "comcast", "verizon", "at&t", "spectrum", "virgin", "telkom", "telstra", "bt ")


def _asn(value) -> Optional[str]:
    v = str(value or "").strip().upper()
    if not v:
        return None
    return v if v.startswith("AS") else f"AS{v}"


def _norm(text: str) -> str:
    return "".join(ch for ch in (text or "").lower() if ch.isalnum())


def _classify_kind(org: str, isp: str = "", hosting: bool = False, proxy: bool = False) -> str:
    """cloud | hosting | cdn | vpn | isp | business. 'business' = the organisation differs from the ISP that
    carries it, which usually means a company or institution rather than a home or mobile subscriber."""
    text = f"{org or ''} {isp or ''}".lower()
    if proxy or any(k in text for k in _VPN_WORDS):
        return "vpn"
    if any(k in text for k in _CDN_WORDS):
        return "cdn"
    if hosting or any(k in text for k in _HOSTING_WORDS):
        return "hosting"
    if org and isp and _norm(org) != _norm(isp) and _norm(isp) not in _norm(org) and _norm(org) not in _norm(isp):
        return "business"
    if any(k in text for k in _ISP_WORDS):
        return "isp"
    return "isp"


def _parse_ipwhois_app(d):
    if d.get("success") is False:
        return None
    org = d.get("org") or d.get("isp")
    return {"org_name": org, "asn": _asn(d.get("asn")), "ip_kind": _classify_kind(org, d.get("isp") or ""),
            "country": d.get("country_code"), "city": d.get("city"), "region": d.get("region")}


def _parse_ipinfo(d):
    raw = d.get("org") or ""
    if not raw:
        return None
    asn = raw.split(" ", 1)[0] if raw.upper().startswith("AS") else None
    name = raw.split(" ", 1)[1] if asn and " " in raw else raw
    return {"org_name": name or None, "asn": _asn(asn), "ip_kind": _classify_kind(name),
            "country": d.get("country"), "city": d.get("city"), "region": d.get("region")}


def _parse_ip_api(d):
    if d.get("status") != "success":
        return None
    org, isp = d.get("org") or "", d.get("isp") or ""
    return {"org_name": org or isp, "asn": _asn((d.get("as") or "").split(" ", 1)[0]),
            "ip_kind": _classify_kind(org, isp, hosting=bool(d.get("hosting")), proxy=bool(d.get("proxy"))),
            "country": d.get("countryCode"), "city": d.get("city"), "region": d.get("regionName")}


_HTTP_SOURCES = [
    {"name": "ipwhois.app", "url": "https://ipwhois.app/json/{ip}", "parse": _parse_ipwhois_app},
    {"name": "ipinfo.io", "url": "https://ipinfo.io/{ip}/json", "parse": _parse_ipinfo},
    {"name": "ip-api.com",
     "url": "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,hosting,proxy",
     "parse": _parse_ip_api},
]

# Visible in /api/admin/visitors/geo-status so a failing lookup source is easy to spot.
REMOTE = {"ok": 0, "fail": 0, "last_error": "", "last_ok_source": ""}


def _kind_from_usage(usage: str) -> str:
    return _classify_kind(usage or "")


def _kind_from_org(org: str) -> str:
    return _classify_kind(org or "")


def lookup_remote(ip: str) -> Optional[Dict[str, str]]:
    for src in _HTTP_SOURCES:
        try:
            r = requests.get(
                src["url"].format(ip=ip),
                timeout=4,
                headers={"User-Agent": "Net365-Admin/1.0 (+https://net365co.com)"},
            )
            if r.status_code != 200:
                REMOTE["fail"] += 1
                REMOTE["last_error"] = f"{src['name']}: HTTP {r.status_code}"
                continue
            parsed = src["parse"](r.json())
            if parsed and parsed.get("org_name"):
                parsed["source"] = src["name"]
                REMOTE["ok"] += 1
                REMOTE["last_ok_source"] = src["name"]
                return parsed
            REMOTE["fail"] += 1
            REMOTE["last_error"] = f"{src['name']}: no organisation in answer"
        except Exception as e:
            REMOTE["fail"] += 1
            REMOTE["last_error"] = f"{src['name']}: {type(e).__name__}: {e}"[:200]
            logger.debug(f"ip_intel: {src['name']} failed for {ip}: {e}")
            continue
    return None


# ---------------------------------------------------------------------------
# Enricher — cache table + non-blocking worker
# ---------------------------------------------------------------------------
class IPIntel:
    _queue: "queue.Queue[str]" = queue.Queue(maxsize=10000)
    _pending: set = set()
    _pending_lock = threading.Lock()
    _worker_thread: Optional[threading.Thread] = None
    _running = False
    _db_factory = None            # callable returning a sqlite connection
    _CACHE_TTL_DAYS = 90
    _MISS_SECONDS = 600           # do not re-query a source that just failed for this IP
    _start_lock = threading.Lock()
    _miss: dict = {}
    _vcols = None
    stats = {"resolved": 0, "failed": 0, "rows_updated": 0, "last_error": ""}

    # ---------- schema ----------
    @classmethod
    def ensure_schema(cls, db_factory):
        """db_factory: a zero-arg callable that returns a fresh DB connection."""
        cls._db_factory = db_factory
        try:
            conn = db_factory()
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS ip_intel (
                    ip_address   TEXT PRIMARY KEY,
                    org_name     TEXT,
                    asn          TEXT,
                    ip_kind      TEXT,
                    label        TEXT,
                    country      TEXT,
                    city         TEXT,
                    source       TEXT,
                    resolved_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_ip_intel_org ON ip_intel(org_name)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_ip_intel_kind ON ip_intel(ip_kind)")

            # ── Add enrichment columns to visitor_logs if missing. ─────
            # NOTE: the app's visit table is named `visitor_logs`, not
            # `visitors`. An earlier version of this file targeted the wrong
            # table, so the ALTERs silently failed and the columns never
            # got created. Fixed here.
            existing = {
                row[1] for row in c.execute("PRAGMA table_info(visitor_logs)").fetchall()
            }
            for col, typ in [
                ("org_name",  "TEXT"),
                ("asn",       "TEXT"),
                ("ip_kind",   "TEXT"),
                # is_bot / bot_name are also added by db.log_visitor's own
                # auto-migration, but listing them here is harmless (idempotent).
                ("is_bot",    "INTEGER DEFAULT 0"),
                ("bot_name",  "TEXT"),
            ]:
                if col not in existing:
                    try:
                        c.execute(f"ALTER TABLE visitor_logs ADD COLUMN {col} {typ}")
                    except sqlite3.OperationalError:
                        pass

            # Indexes for the companies aggregation query
            try:
                c.execute(
                    "CREATE INDEX IF NOT EXISTS idx_visitor_logs_org_name "
                    "ON visitor_logs(org_name)"
                )
                c.execute(
                    "CREATE INDEX IF NOT EXISTS idx_visitor_logs_ip_kind "
                    "ON visitor_logs(ip_kind)"
                )
            except sqlite3.OperationalError:
                pass

            conn.commit()
            conn.close()
            logger.info("ip_intel: schema ready")
        except Exception as e:
            logger.error(f"ip_intel: schema setup failed: {e}")

    # ---------- cache ----------
    @classmethod
    def _read_cache(cls, ip: str) -> Optional[Dict[str, str]]:
        if not cls._db_factory:
            return None
        try:
            conn = cls._db_factory()
            c = conn.cursor()
            row = c.execute(
                "SELECT org_name, asn, ip_kind, label, country, city, source, resolved_at "
                "FROM ip_intel WHERE ip_address = ?",
                (ip,),
            ).fetchone()
            conn.close()
            if not row:
                return None
            row = dict(row) if isinstance(row, sqlite3.Row) else dict(zip(
                ["org_name","asn","ip_kind","label","country","city","source","resolved_at"], row
            ))
            # Expire stale entries (re-resolve once a quarter)
            try:
                ts = datetime.fromisoformat(str(row["resolved_at"]).replace("Z",""))
                if (datetime.utcnow() - ts).days > cls._CACHE_TTL_DAYS:
                    return None
            except Exception:
                pass
            return row
        except Exception:
            return None

    @classmethod
    def _write_cache(cls, ip: str, info: Dict[str, str]) -> None:
        if not cls._db_factory:
            return
        try:
            conn = cls._db_factory()
            c = conn.cursor()
            c.execute("""
                INSERT INTO ip_intel (ip_address, org_name, asn, ip_kind, label, country, city, source, resolved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(ip_address) DO UPDATE SET
                    org_name   = excluded.org_name,
                    asn        = excluded.asn,
                    ip_kind    = excluded.ip_kind,
                    label      = excluded.label,
                    country    = COALESCE(excluded.country, ip_intel.country),
                    city       = COALESCE(excluded.city,    ip_intel.city),
                    source     = excluded.source,
                    resolved_at= CURRENT_TIMESTAMP
            """, (
                ip,
                info.get("org_name"),
                info.get("asn"),
                info.get("ip_kind"),
                info.get("label"),
                info.get("country"),
                info.get("city"),
                info.get("source"),
            ))

            conn.commit()
            conn.close()
        except Exception as e:
            cls.stats["last_error"] = f"cache write: {type(e).__name__}: {e}"[:200]
            logger.warning(f"ip_intel: cache write failed for {ip}: {e}")
        # Fan the answer out to every visitor row from this IP (org/ASN/kind and, when missing, country/city/region).
        cls._apply_rows(ip, info, overwrite_org=True)

    @classmethod
    def _apply_rows(cls, ip: str, info: Dict[str, str], overwrite_org: bool = False) -> int:
        """Write what we know about this IP onto every visitor_logs row that still lacks it.
        Cloudflare-supplied location is never overwritten."""
        if not cls._db_factory or not info:
            return 0
        try:
            conn = cls._db_factory()
            try:
                if cls._vcols is None:
                    cls._vcols = {row[1] for row in conn.execute("PRAGMA table_info(visitor_logs)").fetchall()}
                sets, params = [], []

                def fill(col, val, overwrite=False):
                    if col in cls._vcols and val:
                        if overwrite:
                            sets.append(f"{col} = ?")
                        else:
                            sets.append(f"{col} = CASE WHEN {col} IS NULL OR {col} = '' THEN ? ELSE {col} END")
                        params.append(val)

                fill("org_name", info.get("org_name"), overwrite_org)
                fill("asn", info.get("asn"), overwrite_org)
                fill("ip_kind", info.get("ip_kind"), overwrite_org)
                fill("country", info.get("country"))
                fill("city", info.get("city"))
                fill("region", info.get("region"))
                if not sets:
                    return 0
                missing = " OR ".join(f"{c} IS NULL OR {c} = ''" for c in ("org_name", "ip_kind", "country", "city")
                                      if c in cls._vcols)
                where = "ip_address = ?" if overwrite_org else f"ip_address = ? AND ({missing})"
                cur = conn.execute(f"UPDATE visitor_logs SET {', '.join(sets)} WHERE {where}", (*params, ip))
                conn.commit()
                cls.stats["rows_updated"] += max(cur.rowcount, 0)
                return cur.rowcount
            finally:
                conn.close()
        except Exception as e:
            cls.stats["last_error"] = f"row update: {type(e).__name__}: {e}"[:200]
            logger.warning(f"ip_intel: row update failed for {ip}: {e}")
            return 0

    # ---------- worker ----------
    @classmethod
    def start_worker(cls):
        """Start (or restart) the background thread. Safe to call repeatedly: a thread that is gone, for example
        because the server process forked after start-up, is replaced."""
        with cls._start_lock:
            if cls._worker_thread and cls._worker_thread.is_alive():
                return
            cls._running = True
            cls._worker_thread = threading.Thread(target=cls._loop, name="ip-intel-worker", daemon=True)
            cls._worker_thread.start()
            logger.info("ip_intel: worker started")

    @classmethod
    def stop_worker(cls):
        cls._running = False

    @classmethod
    def _loop(cls):
        while cls._running:
            try:
                ip = cls._queue.get(timeout=2)
            except queue.Empty:
                continue
            with cls._pending_lock:
                cls._pending.discard(ip)     # first, so a visit that arrives mid-lookup is queued again
            try:
                cls._resolve_now(ip)
            except Exception as e:
                cls.stats["last_error"] = f"{type(e).__name__}: {e}"[:200]
                logger.warning(f"ip_intel: resolve failed for {ip}: {e}")

    @classmethod
    def enqueue(cls, ip: str) -> None:
        """Non-blocking. Safe to call from a request handler. Every visit is queued (even from a cached IP)
        because the new visit's row still needs its organisation filled in."""
        if not ip or ip in ("unknown",) or str(ip).startswith("h:"):
            return
        t = cls._miss.get(ip)
        if t and time.time() - t < cls._MISS_SECONDS:
            return
        with cls._pending_lock:
            if ip in cls._pending:
                return
            cls._pending.add(ip)
        try:
            cls._queue.put_nowait(ip)
        except queue.Full:
            with cls._pending_lock:
                cls._pending.discard(ip)
            return
        cls.start_worker()                   # self-heal: the thread may have died after a process fork

    @classmethod
    def _resolve_now(cls, ip: str) -> Optional[Dict[str, str]]:
        cached = cls._read_cache(ip)
        if cached:
            cls._apply_rows(ip, cached)      # known IP, new visit: just copy the answer onto the new row
            return cached
        local = classify_local(ip)
        if local and local.get("ip_kind") == "private":
            info = local
        else:
            # Remote answer first (ASN data is authoritative); the coarse local table is only a fallback
            info = lookup_remote(ip) or local
        if info:
            cls.stats["resolved"] += 1
            cls._write_cache(ip, info)
            cls._miss.pop(ip, None)
        else:
            cls.stats["failed"] += 1
            cls._miss[ip] = time.time()
            if len(cls._miss) > 5000:
                cls._miss.clear()
        return info

    # ---------- synchronous helper (admin views, "resolve now" buttons) ----------
    @classmethod
    def lookup(cls, ip: str, force: bool = False) -> Optional[Dict[str, str]]:
        if not force:
            t = cls._miss.get(ip)
            if t and time.time() - t < cls._MISS_SECONDS:
                return None
            cached = cls._read_cache(ip)
            if cached:
                cls._apply_rows(ip, cached)
                return cached
        local = classify_local(ip)
        info = local if (local and local.get("ip_kind") == "private") else (lookup_remote(ip) or local)
        if info:
            cls._write_cache(ip, info)
            cls._miss.pop(ip, None)
        else:
            cls._miss[ip] = time.time()
        return info

    @classmethod
    def status(cls) -> Dict[str, object]:
        t = cls._worker_thread
        return {"worker_alive": bool(t and t.is_alive()), "queue": cls._queue.qsize(), "pending": len(cls._pending),
                **cls.stats, "remote": dict(REMOTE)}


# ---------------------------------------------------------------------------
# Bot / crawler detection from User-Agent (no network needed)
# ---------------------------------------------------------------------------
_BOT_PATTERNS = [
    ("Googlebot",    ("googlebot",)),
    ("Bingbot",      ("bingbot", "msnbot")),
    ("GPTBot",       ("gptbot",)),
    ("ChatGPT-User", ("chatgpt-user", "oai-searchbot")),
    ("ClaudeBot",    ("claudebot", "anthropic-ai")),
    ("PerplexityBot",("perplexitybot",)),
    ("Amazonbot",    ("amazonbot",)),
    ("Applebot",     ("applebot",)),
    ("Bytespider",   ("bytespider",)),
    ("YandexBot",    ("yandexbot",)),
    ("DuckDuckBot",  ("duckduckbot",)),
    ("FacebookBot",  ("facebookexternalhit", "facebookbot")),
    ("LinkedInBot",  ("linkedinbot",)),
    ("Slackbot",     ("slackbot",)),
    ("Discordbot",   ("discordbot",)),
    ("TelegramBot",  ("telegrambot",)),
    ("WhatsApp",     ("whatsapp",)),
    ("Twitterbot",   ("twitterbot",)),
    ("AhrefsBot",    ("ahrefsbot",)),
    ("SemrushBot",   ("semrushbot",)),
    ("MJ12bot",      ("mj12bot",)),
    ("DotBot",       ("dotbot",)),
    ("PetalBot",     ("petalbot",)),
    ("UptimeRobot",  ("uptimerobot",)),
    ("Pingdom",      ("pingdom",)),
    ("StatusCake",   ("statuscake",)),
    ("curl",         ("curl/",)),
    ("wget",         ("wget/",)),
    ("python-requests", ("python-requests", "python-urllib")),
    ("Go-http-client", ("go-http-client",)),
    ("Headless Chrome", ("headlesschrome", "headless chrome")),
    ("Selenium",     ("selenium",)),
    ("PhantomJS",    ("phantomjs",)),
]


def detect_bot(user_agent: str) -> Tuple[bool, Optional[str]]:
    """Return (is_bot, bot_name)."""
    if not user_agent:
        return True, "Empty UA"
    ua = user_agent.lower()
    for name, needles in _BOT_PATTERNS:
        if any(n in ua for n in needles):
            return True, name
    # Generic heuristics
    if any(k in ua for k in ("bot", "crawler", "spider", "scraper")):
        return True, "Unknown bot"
    return False, None
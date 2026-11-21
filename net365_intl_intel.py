"""
NET365 International Intelligence (Sentinel add-on)
===================================================
Turns raw visitor rows into an answer to "who is visiting, from where, and what should I do about it?".

  * VERIFIED crawlers: a visitor whose user-agent says Googlebot/Bingbot/Applebot/Yandex/Baidu is only labelled
    "verified" after a reverse-DNS lookup of its IP ends in the crawler owner's domain AND a forward lookup of that
    hostname returns the same IP. Otherwise it is "spoofed". Results are cached in `bot_verification`.
  * CLASSIFICATION: every visitor IP gets one label and one recommended action (allow / monitor / alert).
    Labels describe the NETWORK and BEHAVIOUR, never the person. A datacenter address is not hostile by itself.
  * BEHAVIOUR: peak requests per minute, distinct pages, and Sentinel's own recon/attack events for the same IP.
  * REPORT: GET /api/admin/sentinel/intelligence?days=7 feeds the "International" tab (admin_intl.js).

Nothing here blocks anyone. It only classifies and recommends. Fails soft: any error returns an empty report.
Register once, after init_sentinel():
    from net365_intl_intel import register_intl_intel
    register_intl_intel(app, db, admin_required)
"""
import ipaddress
import logging
import os
import queue
import socket
import threading
import time
from datetime import datetime, timedelta

from flask import Response, jsonify, request

log = logging.getLogger("net365.intl")

# claimed crawler (matched on visitors.bot_name or user-agent) -> hostname suffixes that prove ownership
VERIFIABLE = {
    "googlebot": (".googlebot.com", ".google.com"),
    "bingbot": (".search.msn.com",),
    "applebot": (".applebot.apple.com",),
    "yandexbot": (".yandex.ru", ".yandex.net", ".yandex.com"),
    "baiduspider": (".baidu.com", ".baidu.jp"),
}
AI_BOTS = ("gptbot", "chatgpt-user", "claudebot", "perplexitybot", "bytespider", "amazonbot")
PREVIEW_BOTS = ("facebookbot", "linkedinbot", "slackbot", "discordbot", "telegrambot", "whatsapp", "twitterbot")
SEO_BOTS = ("ahrefsbot", "semrushbot", "mj12bot", "dotbot", "petalbot")
UPTIME_BOTS = ("uptimerobot", "pingdom", "statuscake")
SCRIPT_BOTS = ("curl", "wget", "python-requests", "go-http-client", "headless chrome", "selenium", "phantomjs", "empty ua")
PROBE_KINDS = ("recon_probe", "scanner_tool", "path_scanning", "admin_probe", "admin_recon", "sql_injection", "xss",
               "directory_traversal", "command_injection", "brute_force", "credential_stuffing", "spoofed_crawler")

LABELS = {
    "verified_crawler": ("Verified search crawler", "allow"),
    "spoofed_crawler": ("Claims to be a search crawler, failed verification", "alert"),
    "pending_crawler": ("Claims to be a search crawler (checking)", "monitor"),
    "ai_crawler": ("AI / data crawler", "monitor"),
    "preview_bot": ("Link-preview bot", "allow"),
    "seo_crawler": ("SEO / marketing crawler", "monitor"),
    "uptime_monitor": ("Uptime monitor", "allow"),
    "scripted_client": ("Scripted or headless client", "monitor"),
    "unknown_bot": ("Unidentified bot", "monitor"),
    "probing": ("Probing for weaknesses", "alert"),
    "high_rate": ("Unusually high request rate", "alert"),
    "datacenter": ("Datacenter / cloud / VPN visitor", "monitor"),
    "organisation": ("Organisation network (unconfirmed)", "monitor"),
    "consumer": ("Residential or mobile visitor", "allow"),
    "unresolved": ("Network not yet identified", "monitor"),
}

_ready = False
_q = queue.Queue(maxsize=2000)
_pending = set()
_worker = None
_lock = threading.Lock()
_d = {}
_cols = {}


def _conn():
    return _d["db"].get_db_connection()


def _utc(ts=None):
    return datetime.utcfromtimestamp(ts if ts is not None else time.time()).strftime("%Y-%m-%d %H:%M:%S")


def ensure_schema():
    global _ready
    if _ready:
        return
    c = _conn()
    c.execute("""CREATE TABLE IF NOT EXISTS bot_verification (
        ip TEXT NOT NULL, claimed TEXT NOT NULL, verified INTEGER DEFAULT 0, host TEXT, checked_at TEXT,
        PRIMARY KEY (ip, claimed))""")
    _ready = True


# ---------------------------------------------------------------- crawler verification
def _claimed(bot_name, ua):
    low = f"{bot_name or ''} {ua or ''}".lower()
    for k in VERIFIABLE:
        if k in low:
            return k
    return None


def verify_crawler(ip, claimed):
    """Reverse DNS must end in the owner's domain and forward DNS of that host must return the same IP."""
    sfx = VERIFIABLE.get(claimed)
    if not sfx:
        return False, ""
    try:
        ipaddress.ip_address(ip)
        host = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
        if not host.endswith(sfx):
            return False, host
        fwd = {x[4][0] for x in socket.getaddrinfo(host, None)}
        return (ip in fwd), host
    except Exception as e:
        return False, f"lookup failed: {type(e).__name__}"


def _loop():
    socket.setdefaulttimeout(4)
    while True:
        ip, claimed = _q.get()
        try:
            ok, host = verify_crawler(ip, claimed)
            c = _conn()
            c.execute("INSERT INTO bot_verification (ip, claimed, verified, host, checked_at) VALUES (?,?,?,?,?) "
                      "ON CONFLICT(ip, claimed) DO UPDATE SET verified=excluded.verified, host=excluded.host, "
                      "checked_at=excluded.checked_at", (ip, claimed, 1 if ok else 0, host[:120], _utc()))
        except Exception:
            log.debug("bot verification failed", exc_info=True)
        finally:
            with _lock:
                _pending.discard((ip, claimed))
            time.sleep(0.2)


def _enqueue(ip, claimed):
    global _worker
    key = (ip, claimed)
    with _lock:
        if key in _pending:
            return
        _pending.add(key)
    try:
        _q.put_nowait(key)
    except queue.Full:
        with _lock:
            _pending.discard(key)
        return
    with _lock:
        if not (_worker and _worker.is_alive()):
            _worker = threading.Thread(target=_loop, daemon=True, name="intl-bot-verify")
            _worker.start()


# ---------------------------------------------------------------- classification
def classify(row, verification, probe_kinds, peak_rpm):
    """row: dict with bot_name, is_bot, user_agent, ip_kind. Returns (label_key, reasons[])."""
    bot = (row.get("bot_name") or "").lower()
    ua = row.get("user_agent") or ""
    kind = (row.get("ip_kind") or "").lower()
    reasons = []
    claimed = _claimed(bot, ua)
    if claimed:
        v = verification.get(claimed)
        if v is None:
            return "pending_crawler", [f"claims {claimed}, reverse-DNS check queued"]
        if v["verified"]:
            return "verified_crawler", [f"{claimed}: {v['host']} confirmed both ways"]
        return "spoofed_crawler", [f"claims {claimed} but host is '{v['host'] or 'unknown'}'"]
    if probe_kinds:
        return "probing", [f"Sentinel saw: {', '.join(sorted(probe_kinds)[:4])}"]
    if peak_rpm >= 120:
        return "high_rate", [f"{peak_rpm} requests in one minute"]
    if any(b in bot for b in AI_BOTS):
        return "ai_crawler", [row.get("bot_name")]
    if any(b in bot for b in PREVIEW_BOTS):
        return "preview_bot", [row.get("bot_name")]
    if any(b in bot for b in SEO_BOTS):
        return "seo_crawler", [row.get("bot_name")]
    if any(b in bot for b in UPTIME_BOTS):
        return "uptime_monitor", [row.get("bot_name")]
    if any(b in bot for b in SCRIPT_BOTS):
        return "scripted_client", [row.get("bot_name")]
    if row.get("is_bot"):
        return "unknown_bot", [row.get("bot_name") or "bot-like user agent"]
    if kind in ("cloud", "hosting", "vpn", "proxy", "vps"):
        return "datacenter", [f"network type: {kind}"]
    if kind == "business":
        return "organisation", ["organisation differs from its ISP"]
    if kind in ("isp", "cdn"):
        return "consumer", ["ISP / mobile network"]
    return "unresolved", ["no organisation data yet"]


# ---------------------------------------------------------------- report
def _vcols(c):
    if "v" not in _cols:
        _cols["v"] = {r[1] for r in c.execute("PRAGMA table_info(visitor_logs)").fetchall()}
    return _cols["v"]


def build_report(days, home_country="NG"):
    ensure_schema()
    c = _conn()
    cols = _vcols(c)

    def col(n, alias=None):
        return n if n in cols else f"NULL AS {alias or n}"

    since = _utc(time.time() - days * 86400)
    rows = [dict(r) for r in c.execute(
        f"SELECT id, ip_address, {col('user_agent')}, {col('country')}, {col('city')}, {col('org_name')}, {col('asn')}, "
        f"{col('ip_kind')}, {col('is_bot')}, {col('bot_name')}, {col('path')}, visited_at "
        "FROM visitor_logs WHERE visited_at >= ? AND ip_address IS NOT NULL AND ip_address != '' "
        "ORDER BY id DESC LIMIT 60000", (since,)).fetchall()]

    by_ip = {}
    for r in rows:
        ip = r["ip_address"]
        e = by_ip.get(ip)
        if e is None:
            e = by_ip[ip] = {"ip": ip, "hits": 0, "paths": set(), "minutes": {}, "first": r["visited_at"], "last": r["visited_at"],
                             "row": r}
        e["hits"] += 1
        if r.get("path"):
            e["paths"].add(r["path"])
        m = str(r["visited_at"])[:16]
        e["minutes"][m] = e["minutes"].get(m, 0) + 1
        if r["visited_at"] and str(r["visited_at"]) < str(e["first"]):
            e["first"] = r["visited_at"]
        # prefer the row that has the most information
        if not e["row"].get("org_name") and r.get("org_name"):
            e["row"] = r

    verification = {}
    for r in c.execute("SELECT ip, claimed, verified, host FROM bot_verification").fetchall():
        verification.setdefault(r["ip"], {})[r["claimed"]] = {"verified": bool(r["verified"]), "host": r["host"]}

    probes = {}
    try:
        for r in c.execute("SELECT ip, kind FROM security_events WHERE ts >= ?", (since,)).fetchall():
            if r["kind"] in PROBE_KINDS:
                probes.setdefault(r["ip"], set()).add(r["kind"])
    except Exception:
        pass

    out, queued = [], 0
    counts, countries, orgs = {}, {}, {}
    for ip, e in by_ip.items():
        row = e["row"]
        if str(ip).startswith("h:"):
            continue
        claimed = _claimed(row.get("bot_name"), row.get("user_agent"))
        ver = verification.get(ip, {})
        if claimed and claimed not in ver and queued < 25 and not _private(ip):
            _enqueue(ip, claimed)
            queued += 1
        peak = max(e["minutes"].values()) if e["minutes"] else 0
        label, reasons = classify(row, ver, probes.get(ip, set()), peak)
        text, action = LABELS[label]
        cc = (row.get("country") or "").upper() or "??"
        item = {"ip": ip, "label": label, "label_text": text, "action": action, "reasons": reasons[:3],
                "country": cc, "city": row.get("city"), "org": row.get("org_name"), "asn": row.get("asn"),
                "network_type": row.get("ip_kind"), "bot_name": row.get("bot_name"), "hits": e["hits"],
                "pages": len(e["paths"]), "peak_per_minute": peak, "first_seen": e["first"], "last_seen": e["last"],
                "international": cc not in (home_country, "??")}
        out.append(item)
        counts[label] = counts.get(label, 0) + 1
        c_ = countries.setdefault(cc, {"country": cc, "ips": 0, "hits": 0, "bots": 0, "alerts": 0, "datacenter": 0, "consumer": 0})
        c_["ips"] += 1
        c_["hits"] += e["hits"]
        if label not in ("consumer", "organisation", "datacenter", "unresolved", "probing", "high_rate"):
            c_["bots"] += 1
        if action == "alert":
            c_["alerts"] += 1
        if label == "datacenter":
            c_["datacenter"] += 1
        if label == "consumer":
            c_["consumer"] += 1
        key = (row.get("org_name") or "Unidentified", row.get("asn") or "")
        o = orgs.setdefault(key, {"org": key[0], "asn": key[1], "country": cc, "ips": 0, "hits": 0,
                                  "label": label, "network_type": row.get("ip_kind")})
        o["ips"] += 1
        o["hits"] += e["hits"]

    out.sort(key=lambda x: ({"alert": 0, "monitor": 1, "allow": 2}[x["action"]], -x["hits"]))
    summary = [{"label": k, "text": LABELS[k][0], "action": LABELS[k][1], "ips": v}
               for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]
    intl = [x for x in out if x["international"]]
    return {
        "success": True, "days": days, "home_country": home_country, "total_ips": len(out),
        "alerts": sum(1 for x in out if x["action"] == "alert"), "international_ips": len(intl),
        "summary": summary,
        "countries": sorted(countries.values(), key=lambda x: -x["hits"])[:30],
        "organisations": sorted(orgs.values(), key=lambda x: -x["hits"])[:30],
        "visitors": out[:200],
        "verification_pending": queued,
        "notes": [
            "Labels describe the network and behaviour of an address, not the person using it.",
            "A datacenter or VPN address is monitored, not treated as hostile: uptime checks, payment webhooks and many customers on VPNs use them.",
            "'Organisation network' and 'potential customer' are guesses from the network owner and are unconfirmed.",
            "This report never blocks anyone. Blocking stays a manual decision in the Security tab.",
        ],
    }


def _private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_reserved
    except ValueError:
        return True


# ---------------------------------------------------------------- wiring
def register_intl_intel(app, db_module, admin_required):
    _d["db"] = db_module
    try:
        ensure_schema()
    except Exception:
        log.exception("intl intel schema failed")

    @app.route("/api/admin/sentinel/intelligence", methods=["GET"])
    @admin_required
    def intl_report():
        try:
            days = max(1, min(90, int(request.args.get("days", 7))))
        except ValueError:
            days = 7
        try:
            return jsonify(build_report(days, os.getenv("HOME_COUNTRY", "NG").upper()))
        except Exception as e:
            log.exception("intelligence report failed")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/admin_intl.js")
    def intl_js():
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin_intl.js")
        try:
            with open(p, "rb") as f:
                r = Response(f.read(), mimetype="application/javascript")
            r.headers["Cache-Control"] = "no-cache"
            return r
        except OSError:
            return Response("/* admin_intl.js missing */", mimetype="application/javascript", status=404)

    log.info("International intelligence registered")

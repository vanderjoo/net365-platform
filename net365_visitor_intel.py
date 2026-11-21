"""
Net365 Visitor Intelligence & Prospect Identification (admin only).

Turns the raw visitor_logs rows into one pseudonymous profile per visitor:

  * Identity       NET365-VISITOR-000125 style ids (sequential, stored as a salted hash; no raw IP is returned)
  * New / returning, registered, funded, customer, repeat customer (journey stage)
  * Organisation   ISP / ASN / organisation, network type, corporate-network flag
  * Bots           crawlers, AI crawlers, link-preview bots, monitors, scripts, automated browsers
  * Behaviour      pages visited, navigation sequence, classification of the journey
  * Engagement     0-100 score with the reasons behind it (a heuristic, not a measurement of intent)
  * Prospect signal  deliberately "UNCONFIRMED": browsing + network patterns never declare anyone an investor
  * Conversion     visitors -> registrations -> funded wallets -> first transaction -> repeat customers, CAC, MAU
  * Alerts         in-dashboard list, optional Telegram / webhook push

Endpoints (all admin_required):
  GET  /api/admin/insights/intel/overview?days=30        audience charts + summary counts
  GET  /api/admin/insights/intel/visitors?days=30&segment=all|new|returning|high|corporate|prospect|registered|bots&q=
  GET  /api/admin/insights/intel/conversion?days=30
  GET  /api/admin/insights/intel/alerts[?all=1]          POST .../alerts/seen   POST .../alerts/scan

Privacy: profiles are keyed by IP or account id but only the salted hash and the derived label leave the server.
Organisation is a property of the NETWORK, not proof of who is browsing; nothing here identifies a person.
Every admin read of the visitor list is written to intel_audit.
"""
import hashlib
import json
import logging
import os
import re
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from flask import jsonify, request

import net365_insights as I

log = logging.getLogger("net365.intel")

PAGES = {"/": "Homepage", "/scheduler": "Scheduler", "/analytics": "Analytics", "/business": "Business",
         "/utilities": "Utilities", "/giftcards": "Gift cards"}
PRODUCT_PATHS = {"/scheduler", "/analytics", "/business", "/utilities", "/giftcards"}
NETWORK = {"isp": "Consumer / ISP", "business": "Business network", "cloud": "Cloud / hosting (unverified)",
           "hosting": "Cloud / hosting (unverified)", "vps": "Cloud / hosting (unverified)", "vpn": "VPN / proxy",
           "cdn": "CDN / edge", "ai": "AI crawler network", "bot": "Crawler network", "private": "Private network"}
NOT_CORPORATE = {"isp", "cloud", "hosting", "vps", "vpn", "cdn", "ai", "bot", "private"}
FINANCE_WORDS = ("capital", "venture", "partners", "investment", "investments", "fund", "holdings", "bank", "financial",
                 "finance", "asset management", "equity", "securities", "fintech", "payments", "insurance")
BOT_CLASS = {
    "AI crawler": ("GPTBot", "ChatGPT-User", "ClaudeBot", "PerplexityBot", "Bytespider", "Amazonbot"),
    "Search crawler": ("Googlebot", "Bingbot", "YandexBot", "DuckDuckBot", "Applebot", "PetalBot"),
    "SEO crawler": ("AhrefsBot", "SemrushBot", "MJ12bot", "DotBot"),
    "Link preview": ("FacebookBot", "LinkedInBot", "Slackbot", "Discordbot", "TelegramBot", "WhatsApp", "Twitterbot"),
    "Uptime monitor": ("UptimeRobot", "Pingdom", "StatusCake"),
    "Script / scanner": ("curl", "wget", "python-requests", "Go-http-client", "Empty UA"),
    "Automated browser": ("Headless Chrome", "Selenium", "PhantomJS"),
}
REFERRERS = [("Google", r"google\."), ("Bing", r"bing\."), ("DuckDuckGo", r"duckduckgo"), ("Yahoo", r"yahoo\."),
             ("LinkedIn", r"linkedin|lnkd\.in"), ("Facebook", r"facebook|fb\.com|fb\.me"), ("Instagram", r"instagram"),
             ("X / Twitter", r"twitter|x\.com|t\.co$"), ("WhatsApp", r"whatsapp|wa\.me"), ("Telegram", r"telegram|t\.me"),
             ("YouTube", r"youtube|youtu\.be"), ("TikTok", r"tiktok")]
_CACHE = {}
_ready = False


# ------------------------------------------------------------------ small helpers
def _salt():
    return os.getenv("SECRET_KEY") or os.getenv("FLASK_SECRET_KEY") or "net365"


def _key_hash(key):
    """Same hash the retention job writes over old raw IPs, so a visitor keeps one id after IP anonymisation."""
    if key.startswith("ip:h:"):
        return key[5:]
    raw = key[3:] if key.startswith("ip:") else key
    return hashlib.sha256(f"{_salt()}|{raw}".encode()).hexdigest()[:12]


def _chunks(seq, n=400):
    seq = list(seq)
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def referrer_source(ref, own_host=""):
    if not ref:
        return "Direct"
    try:
        from urllib.parse import urlsplit
        host = (urlsplit(ref).hostname or "").lower()
    except Exception:
        return "Other"
    if not host:
        return "Direct"
    if own_host and host == own_host.split(":")[0].lower():
        return "Own site"
    for name, rx in REFERRERS:
        if re.search(rx, host):
            return name
    return host[:40]


def bot_class(name):
    for cls, names in BOT_CLASS.items():
        if name in names:
            return cls
    return "Unclassified bot"


def _page_name(p):
    p = (p or "").split("?")[0] or "/"
    return PAGES.get(p, p[:30])


def ensure_schema():
    global _ready
    if _ready:
        return
    c = I._db()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS intel_visitor_registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT, key_hash TEXT UNIQUE NOT NULL, first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS intel_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, kind TEXT NOT NULL,
            severity TEXT NOT NULL, label TEXT, title TEXT, detail TEXT, day TEXT, seen INTEGER DEFAULT 0,
            UNIQUE(kind, label, day))""")
        c.execute("""CREATE TABLE IF NOT EXISTS intel_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, detail TEXT, remote TEXT, at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        _ready = True
    finally:
        c.close()


def _labels(c, hashes):
    """key_hash -> 'NET365-VISITOR-000125'. New hashes get the next sequential number (ordered as given)."""
    hashes = list(dict.fromkeys(hashes))
    for part in _chunks(hashes):
        c.executemany("INSERT OR IGNORE INTO intel_visitor_registry (key_hash) VALUES (?)", [(h,) for h in part])
    out = {}
    for part in _chunks(hashes):
        q = ",".join("?" * len(part))
        for r in c.execute(f"SELECT id, key_hash FROM intel_visitor_registry WHERE key_hash IN ({q})", part).fetchall():
            out[r["key_hash"]] = "NET365-VISITOR-%06d" % r["id"]
    return out


# ------------------------------------------------------------------ scoring and classification
def _clusters(hits, gap=30):
    """Split a visitor's hits into visits (a pause of more than `gap` minutes starts a new visit)."""
    visits, cur = [], []
    for h in hits:
        if cur and (h[0] - cur[-1][0]) > timedelta(minutes=gap):
            visits.append(cur)
            cur = []
        cur.append(h)
    if cur:
        visits.append(cur)
    return visits


def _score(distinct, product, visits, span_s, logged_in, customer):
    pts = min(distinct, 6) * 8 + min(product, 4) * 4
    pts += (12 if visits >= 2 else 0) + (8 if visits >= 4 else 0)
    pts += min(span_s / 60.0, 8) * 1.5
    pts += 8 if logged_in else 0
    pts += 10 if customer else 0
    return int(min(100, round(pts)))


def _tier(score):
    return "HIGH" if score >= 55 else ("MEDIUM" if score >= 30 else "LOW")


def _profile(rec, own_host):
    hits = rec["hits"]
    visits = _clusters(hits)
    seq = []
    for _, p in hits:
        name = _page_name(p)
        if not seq or seq[-1] != name:
            seq.append(name)
    counts = Counter(_page_name(p) for _, p in hits)
    distinct = len(counts)
    product = len({p.split("?")[0] for _, p in hits if p.split("?")[0] in PRODUCT_PATHS})
    span = sum((v[-1][0] - v[0][0]).total_seconds() for v in visits)
    n_visits = len(visits)
    returning = n_visits >= 2 or rec["seen_before"]
    kind = (rec["kind"] or "").lower() or None
    org = rec["org"]
    org_l = (org or "").lower()
    finance_org = any(w in org_l for w in FINANCE_WORDS) and kind not in ("hosting", "cloud", "vps", "cdn", "vpn", "ai", "bot")
    corporate = bool(org) and (kind == "business" or finance_org or (kind not in NOT_CORPORATE and kind is not None))
    stage_rank = 1 if returning else 0
    if rec["uid"]:
        stage_rank = max(stage_rank, 2)
    if rec["funded"]:
        stage_rank = max(stage_rank, 3)
    if rec["buys"] >= 1:
        stage_rank = max(stage_rank, 4)
    if rec["buys"] >= 2:
        stage_rank = max(stage_rank, 5)
    stage = ["Visitor", "Returning visitor", "Registered", "Funded wallet", "Customer", "Repeat customer"][stage_rank]
    score = _score(distinct, product, n_visits, span, bool(rec["uid"]), rec["buys"] >= 1)
    tier = _tier(score)

    signals, prospect = [], False
    if not rec["bot"]:
        if corporate:
            signals.append("Business network" if kind == "business" else "Organisation network")
        if finance_org:
            signals.append("Finance-related organisation name")
        if product >= 3:
            signals.append(f"Explored {product} product pages")
        if returning:
            signals.append("Returned to the site")
        prospect = (corporate and product >= 2 and distinct >= 3) or (finance_org and product >= 2) \
            or (corporate and returning and distinct >= 3)

    suspected = (not rec["bot"]) and kind in ("hosting", "cloud", "vps") and distinct <= 1
    if rec["bot"]:
        classification = f"Automated: {bot_class(rec['bot_name'])}"
    elif suspected:
        classification = "Possible automated or cloud-hosted browser (unverified)"
    elif product >= 3 and distinct >= 4:
        classification = "Multi-page product exploration"
    elif returning and distinct >= 2:
        classification = "Returning evaluator"
    elif rec["uid"]:
        classification = "Registered user browsing"
    elif distinct <= 1 and n_visits <= 1:
        classification = "Single-page visit"
    else:
        classification = "Casual browsing"

    if rec["bot"]:
        action = "No action. Block only if it becomes abusive."
    elif prospect:
        action = "Monitor subsequent visits. Do not assume identity or intent."
    elif suspected:
        action = "Treat as unverified automated traffic."
    elif tier == "HIGH" and not rec["uid"]:
        action = "Strong interest. Consider an on-site sign-up prompt or follow-up campaign."
    elif stage_rank >= 4:
        action = "Existing customer. Nudge towards repeat purchases."
    else:
        action = "No action needed."

    status = "BOT" if rec["bot"] else ("RETURNING VISITOR" if returning else "NEW VISITOR")
    return {
        "label": rec["label"], "status": status, "headline": f"{status} — {tier} ENGAGEMENT" if not rec["bot"] else "AUTOMATED TRAFFIC",
        "is_new": not returning, "bot": rec["bot"], "bot_name": rec["bot_name"], "bot_class": bot_class(rec["bot_name"]) if rec["bot"] else None,
        "tier": tier, "score": score, "stage": stage, "stage_rank": stage_rank, "registered": bool(rec["uid"]),
        "visits": n_visits, "hits": len(hits), "first_seen": hits[0][0].isoformat(timespec="minutes"),
        "last_seen": hits[-1][0].isoformat(timespec="minutes"), "span_minutes": round(span / 60.0, 1),
        "country": rec["country"], "city": rec["city"], "region": rec["region"],
        "organization": org or "Pending identification", "org_known": bool(org), "asn": rec["asn"],
        "network": NETWORK.get(kind, "Pending identification"), "kind": kind,
        "corporate": corporate, "device": rec["device"], "device_model": rec["model"], "os": rec["os"], "browser": rec["browser"],
        "referrer": referrer_source(rec["ref"], own_host),
        "pages": [{"name": n, "count": c} for n, c in sorted(counts.items(), key=lambda kv: -kv[1])],
        "journey": " → ".join(seq[:12]) + (" …" if len(seq) > 12 else ""),
        "classification": classification, "suspected_automation": suspected,
        "investor_likelihood": "UNCONFIRMED" if prospect else "NO SIGNAL", "signals": signals, "action": action,
    }


# ------------------------------------------------------------------ data collection (cached 45 s)
def _collect(days, own_host=""):
    ck = ("collect", days)
    hit = _CACHE.get(ck)
    if hit and time.time() - hit[0] < 45:
        return hit[1]
    ensure_schema()
    now = I._now()
    start = now - timedelta(days=days)
    c = I._db()
    try:
        cols = {r[1] for r in c.execute("PRAGMA table_info(visitor_logs)").fetchall()}
        if not cols:
            return {"profiles": [], "humans": [], "bots": [], "rows": 0, "days": days}
        want = ["user_id", "ip_address", "device_type", "device_model", "os_name", "browser", "path", "referrer", "visited_at",
                "country", "city", "region", "org_name", "asn", "ip_kind", "is_bot", "bot_name"]
        sel = ", ".join(col if col in cols else f"NULL AS {col}" for col in want)
        rows = c.execute(f"SELECT {sel} FROM visitor_logs WHERE visited_at >= ? ORDER BY visited_at LIMIT 200000",
                         (I._fmt(start),)).fetchall()
        excluded = {x.strip() for x in os.getenv("INSIGHTS_EXCLUDE_IPS", "").split(",") if x.strip()}
        recs = {}
        for r in rows:
            ip = r["ip_address"] or ""
            if ip in excluded or not (ip or r["user_id"]):
                continue
            bot = bool(r["is_bot"])
            key = f"u:{r['user_id']}" if (r["user_id"] and not bot) else f"ip:{ip}"
            dt = I._dt(r["visited_at"])
            if not dt:
                continue
            rec = recs.get(key)
            if rec is None:
                rec = recs[key] = {"key": key, "uid": r["user_id"] if key.startswith("u:") else None, "ip": ip, "hits": [],
                                   "bot": bot, "bot_name": r["bot_name"], "country": None, "city": None, "region": None, "org": None,
                                   "asn": None, "kind": None, "device": None, "model": None, "os": None, "browser": None,
                                   "ref": r["referrer"] or "", "seen_before": False, "funded": False, "buys": 0}
            rec["hits"].append((dt + I.LAGOS_OFFSET, r["path"] or "/"))
            for src, dst in (("country", "country"), ("city", "city"), ("region", "region"), ("org_name", "org"), ("asn", "asn"),
                             ("ip_kind", "kind"), ("device_type", "device"), ("device_model", "model"), ("os_name", "os"),
                             ("browser", "browser")):
                if r[src]:
                    rec[dst] = r[src]
        for rec in recs.values():
            rec["hits"].sort(key=lambda h: h[0])

        # who was seen before this window (so "returning" works on short ranges)
        ips = [r["ip"] for r in recs.values() if r["ip"] and not r["uid"] and not r["ip"].startswith("h:")]
        uids = [r["uid"] for r in recs.values() if r["uid"]]
        prior_ip, prior_uid = set(), set()
        for part in _chunks(ips):
            q = ",".join("?" * len(part))
            prior_ip.update(x[0] for x in c.execute(
                f"SELECT DISTINCT ip_address FROM visitor_logs WHERE visited_at < ? AND ip_address IN ({q})", [I._fmt(start)] + part))
        for part in _chunks(uids):
            q = ",".join("?" * len(part))
            prior_uid.update(x[0] for x in c.execute(
                f"SELECT DISTINCT user_id FROM visitor_logs WHERE visited_at < ? AND user_id IN ({q})", [I._fmt(start)] + part))
        # customer facts for logged-in visitors
        facts = {}
        for part in _chunks(uids):
            q = ",".join("?" * len(part))
            for r in c.execute(
                    "SELECT user_id, SUM(CASE WHEN tx_type = 'wallet_funding' THEN 1 ELSE 0 END) AS fund, "
                    "SUM(CASE WHEN tx_type != 'wallet_funding' THEN 1 ELSE 0 END) AS buys FROM transactions "
                    f"WHERE status IN ('fulfilled','completed') AND user_id IN ({q}) GROUP BY user_id", part):
                facts[r["user_id"]] = (r["fund"] or 0, r["buys"] or 0)
        # labels (sequential ids ordered by first appearance)
        order = sorted(recs.values(), key=lambda r: r["hits"][0][0])
        for rec in order:
            rec["kh"] = _key_hash(rec["key"])
        labels = _labels(c, [r["kh"] for r in order])
        profiles = []
        for rec in order:
            rec["label"] = labels.get(rec["kh"], "NET365-VISITOR-??????")
            rec["seen_before"] = (rec["uid"] in prior_uid) if rec["uid"] else (rec["ip"] in prior_ip)
            if rec["uid"] in facts:
                rec["funded"], rec["buys"] = bool(facts[rec["uid"]][0]), facts[rec["uid"]][1]
            p = _profile(rec, own_host)
            p["_hits"] = rec["hits"]
            p["_ref_raw"] = rec["ref"]
            profiles.append(p)
        out = {"profiles": profiles, "rows": len(rows), "days": days, "start": start}
        out["humans"] = [p for p in profiles if not p["bot"]]
        out["bots"] = [p for p in profiles if p["bot"]]
        _CACHE[ck] = (time.time(), out)
        if len(_CACHE) > 20:
            _CACHE.clear()
        return out
    finally:
        c.close()


def _pub(p):
    return {k: v for k, v in p.items() if not k.startswith("_")}


# ------------------------------------------------------------------ audience (aggregates)
def build_overview(days, own_host=""):
    data = _collect(days, own_host)
    humans, bots = data["humans"], data["bots"]
    today = (I._now() + I.LAGOS_OFFSET).date()
    daily = {}
    hour = Counter()
    for p in data["profiles"]:
        for dt, _ in p["_hits"]:
            d = dt.date().isoformat()
            a = daily.setdefault(d, {"visits": 0, "visitors": set(), "bots": 0})
            if p["bot"]:
                a["bots"] += 1
            else:
                a["visits"] += 1
                a["visitors"].add(p["label"])
                hour[dt.hour] += 1
    series = []
    for i in range(days):
        d = (today - timedelta(days=days - 1 - i)).isoformat()
        a = daily.get(d, {"visits": 0, "visitors": set(), "bots": 0})
        series.append({"day": d, "visits": a["visits"], "visitors": len(a["visitors"]), "bots": a["bots"]})

    def top(counter, n=10, key="name"):
        return [{key: k, "count": v} for k, v in counter.most_common(n)]

    countries = Counter(p["country"] for p in humans if p["country"])
    cities = Counter((f"{p['city']}, {p['country']}" if p["country"] else p["city"]) for p in humans if p["city"])
    kinds = Counter(p["network"] for p in humans)
    devices = Counter((p["device"] or "Unknown") for p in humans)
    oss = Counter((p["os"] or "Unknown") for p in humans)
    browsers = Counter((p["browser"] or "Unknown") for p in humans)
    refs = Counter(p["referrer"] for p in humans)
    paths = Counter()
    for p in humans:
        for pg in p["pages"]:
            paths[pg["name"]] += pg["count"]
    flows = Counter(p["journey"] for p in humans if "→" in p["journey"])
    orgs = {}
    for p in humans:
        if not p["org_known"]:
            continue
        o = orgs.setdefault(p["organization"], {"organization": p["organization"], "kind": p["kind"], "network": p["network"],
                                                "visitors": 0, "visits": 0, "corporate": p["corporate"], "country": p["country"]})
        o["visitors"] += 1
        o["visits"] += p["visits"]
    org_list = sorted(orgs.values(), key=lambda o: (-o["visitors"], -o["visits"]))[:15]
    bot_names = Counter(p["bot_name"] or "Unknown" for p in bots)
    bot_classes = Counter(p["bot_class"] for p in bots)
    n = len(humans) or 1
    out = {
        "success": True, "days": days,
        "summary": {
            "visitors": len(humans), "visits": sum(p["visits"] for p in humans),
            "new": sum(1 for p in humans if p["is_new"]), "returning": sum(1 for p in humans if not p["is_new"]),
            "registered": sum(1 for p in humans if p["registered"]), "corporate": sum(1 for p in humans if p["corporate"]),
            "high_engagement": sum(1 for p in humans if p["tier"] == "HIGH"),
            "prospect_signals": sum(1 for p in humans if p["investor_likelihood"] == "UNCONFIRMED"),
            "suspected_automation": sum(1 for p in humans if p["suspected_automation"]),
            "bot_visitors": len(bots), "bot_hits": sum(p["hits"] for p in bots),
            "countries": len(countries), "avg_engagement": round(sum(p["score"] for p in humans) / n, 1) if humans else 0,
        },
        "coverage": {
            "organization_pct": round(100 * sum(1 for p in humans if p["org_known"]) / n),
            "city_pct": round(100 * sum(1 for p in humans if p["city"]) / n),
            "country_pct": round(100 * sum(1 for p in humans if p["country"]) / n),
        },
        "daily": series, "by_hour": [{"hour": h, "count": hour.get(h, 0)} for h in range(24)],
        "countries": top(countries), "cities": top(cities), "networks": top(kinds), "devices": top(devices),
        "os": top(oss), "browsers": top(browsers), "referrers": top(refs, 10, "source"), "pages": top(paths),
        "flows": [{"flow": k, "count": v} for k, v in flows.most_common(8)], "organizations": org_list,
        "bots": {"classes": top(bot_classes, 8), "names": top(bot_names, 10)}, "device_signals": _device_signals(days),
        "note": "Visitors are counted per IP address or account, so several people sharing one mobile network can appear as one visitor.",
    }
    return out


def _device_signals(days):
    c = I._db()
    try:
        if not c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='visitor_signals'").fetchone():
            return {}
        since = I._fmt(I._now() - timedelta(days=days))
        rows = c.execute("SELECT screen_w, connection, language FROM visitor_signals WHERE captured_at >= ? LIMIT 50000", (since,)).fetchall()

        def bucket(w):
            return "Under 400 px" if w < 400 else ("400-767 px" if w < 768 else ("768-1279 px" if w < 1280 else "1280 px and up"))

        scr = Counter(bucket(r["screen_w"]) for r in rows if r["screen_w"])
        con = Counter(r["connection"] for r in rows if r["connection"])
        lang = Counter((r["language"] or "")[:5] for r in rows if r["language"])
        top = lambda cn: [{"name": k, "count": v} for k, v in cn.most_common(6)]
        return {"samples": len(rows), "screens": top(scr), "connections": top(con), "languages": top(lang)}
    except Exception:
        return {}
    finally:
        c.close()


# ------------------------------------------------------------------ visitor list
def build_visitors(days, segment="all", q="", limit=100, own_host=""):
    data = _collect(days, own_host)
    seg = {
        "all": lambda p: not p["bot"], "new": lambda p: not p["bot"] and p["is_new"],
        "returning": lambda p: not p["bot"] and not p["is_new"], "high": lambda p: not p["bot"] and p["tier"] == "HIGH",
        "corporate": lambda p: not p["bot"] and p["corporate"], "prospect": lambda p: p["investor_likelihood"] == "UNCONFIRMED",
        "registered": lambda p: not p["bot"] and p["registered"], "bots": lambda p: p["bot"],
        "suspected": lambda p: p["suspected_automation"],
    }.get(segment, lambda p: not p["bot"])
    ql = (q or "").strip().lower()
    rows = [p for p in data["profiles"] if seg(p)]
    if ql:
        def hay(p):
            return " ".join(str(x or "") for x in (p["label"], p["organization"], p["country"], p["city"], p["browser"], p["os"],
                                                   p["referrer"], p["journey"], p["classification"], p["network"])).lower()
        rows = [p for p in rows if ql in hay(p)]
    rows.sort(key=lambda p: p["last_seen"], reverse=True)
    if segment in ("high", "prospect"):
        rows.sort(key=lambda p: (-p["score"], p["last_seen"]))
    try:
        c = I._db()
        try:
            ensure_schema()
            c.execute("INSERT INTO intel_audit (action, detail, remote) VALUES (?,?,?)",
                      ("visitor_list_viewed", f"segment={segment} q={'yes' if ql else 'no'} days={days}", I._client_ip()[:45]))
        finally:
            c.close()
    except Exception:
        pass
    return {"success": True, "days": days, "segment": segment, "total": len(rows), "visitors": [_pub(p) for p in rows[:limit]],
            "scoring": "Engagement 0-100: pages viewed (up to 48), product pages (16), return visits (20), time on site (12), "
                       "logged in (8), customer (10). HIGH 55+, MEDIUM 30-54. A heuristic, not a measure of intent.",
            "prospect_note": "Prospect signals are always UNCONFIRMED. Network and browsing patterns cannot identify a person or an investor."}


# ------------------------------------------------------------------ conversion
def build_conversion(days):
    ensure_schema()
    now = I._now()
    start = now - timedelta(days=days)
    s0 = I._fmt(start)
    c = I._db()
    try:
        regs = c.execute("SELECT id, created_at FROM users WHERE created_at >= ?", (s0,)).fetchall()
        reg_ids = [r["id"] for r in regs]
        reg_at = {r["id"]: I._dt(r["created_at"]) for r in regs}
        funded, bought, repeat, first_buy = set(), set(), set(), {}
        for part in _chunks(reg_ids):
            q = ",".join("?" * len(part))
            for r in c.execute(
                    "SELECT user_id, SUM(CASE WHEN tx_type='wallet_funding' THEN 1 ELSE 0 END) AS f, "
                    "SUM(CASE WHEN tx_type!='wallet_funding' THEN 1 ELSE 0 END) AS b, "
                    "MIN(CASE WHEN tx_type!='wallet_funding' THEN created_at END) AS fb FROM transactions "
                    f"WHERE status IN ('fulfilled','completed') AND user_id IN ({q}) GROUP BY user_id", part):
                if r["f"]:
                    funded.add(r["user_id"])
                if r["b"]:
                    bought.add(r["user_id"])
                if (r["b"] or 0) >= 2:
                    repeat.add(r["user_id"])
                if r["fb"]:
                    first_buy[r["user_id"]] = I._dt(r["fb"])
        gaps = sorted(g for g in ((first_buy[u] - reg_at[u]).total_seconds() / 86400.0 for u in first_buy if reg_at.get(u) and first_buy[u]) if g >= 0)
        median_days = round(gaps[len(gaps) // 2], 1) if gaps else None
        # window-level facts
        cust = c.execute("SELECT user_id, COUNT(*) AS n FROM transactions WHERE status IN ('fulfilled','completed') AND "
                         "tx_type != 'wallet_funding' AND user_id IS NOT NULL AND created_at >= ? GROUP BY user_id", (s0,)).fetchall()
        customers = len(cust)
        repeaters = sum(1 for r in cust if r["n"] >= 2)
        since30 = I._fmt(now - timedelta(days=30))
        act = set(x[0] for x in c.execute("SELECT DISTINCT user_id FROM visitor_logs WHERE user_id IS NOT NULL AND visited_at >= ?", (since30,)))
        act.update(x[0] for x in c.execute("SELECT DISTINCT user_id FROM transactions WHERE user_id IS NOT NULL AND created_at >= ? "
                                           "AND status IN ('fulfilled','completed')", (since30,)))
        first_ever = {r["user_id"]: I._dt(r["f"]) for r in c.execute(
            "SELECT user_id, MIN(created_at) AS f FROM transactions WHERE status IN ('fulfilled','completed') AND "
            "tx_type != 'wallet_funding' AND user_id IS NOT NULL GROUP BY user_id")}
        new_customers = sum(1 for r in cust if first_ever.get(r["user_id"]) and first_ever[r["user_id"]] >= start)
    finally:
        c.close()
    ov = build_overview(days)
    visitors = ov["summary"]["visitors"]
    pct = lambda a, b: round(100 * a / b, 1) if b else None
    spend = I._env_f("MARKETING_SPEND_NGN_MONTHLY", 0)
    cac = round(spend * days / 30.0 / new_customers) if spend and new_customers else None
    steps = [
        {"label": "Unique visitors", "count": visitors},
        {"label": "Returning visitors", "count": ov["summary"]["returning"]},
        {"label": "Registered (new accounts)", "count": len(regs)},
        {"label": "Funded wallet", "count": len(funded)},
        {"label": "Made a purchase", "count": len(bought)},
        {"label": "Repeat customers", "count": len(repeat)},
    ]
    return {
        "success": True, "days": days, "steps": steps,
        "metrics": {
            "unique_visitors": visitors, "monthly_active_users": len(act),
            "visitor_to_registration_pct": pct(len(regs), visitors),
            "registration_to_funded_pct": pct(len(funded), len(regs)),
            "registration_to_first_transaction_pct": pct(len(bought), len(regs)),
            "median_days_to_first_transaction": median_days,
            "customers": customers, "new_customers": new_customers,
            "repeat_transaction_rate_pct": pct(repeaters, customers),
            "customer_acquisition_cost": cac, "marketing_spend_set": bool(spend),
        },
        "note": "Registration, funding and purchase steps follow the accounts created in this period. "
                "Set MARKETING_SPEND_NGN_MONTHLY to see customer acquisition cost.",
    }


# ------------------------------------------------------------------ alerts
def _notify(a):
    try:
        import requests
        msg = f"\U0001F514 {a['title']}\n{a['detail']}"
        tok, chat = os.getenv("INTEL_ALERT_TELEGRAM_BOT_TOKEN", ""), os.getenv("INTEL_ALERT_TELEGRAM_CHAT_ID", "")
        if tok and chat:
            requests.post(f"https://api.telegram.org/bot{tok}/sendMessage", json={"chat_id": chat, "text": msg}, timeout=6)
        url = os.getenv("INTEL_ALERT_WEBHOOK_URL", "")
        if url:
            requests.post(url, json={"text": msg, "content": msg}, timeout=6)
    except Exception:
        log.debug("alert push failed", exc_info=True)


def scan_alerts(own_host=""):
    """Create alerts from the last 24 h of activity. One alert per kind, visitor and day."""
    ensure_schema()
    _CACHE.pop(("collect", 1), None)
    data = _collect(1, own_host)
    today = (I._now() + I.LAGOS_OFFSET).date().isoformat()
    push_min = {"high": 2, "medium": 1, "low": 0}.get((os.getenv("INTEL_ALERT_PUSH_MIN", "high")).lower(), 2)
    rank = {"high": 2, "medium": 1, "low": 0}
    new = []
    c = I._db()
    try:
        for p in data["humans"]:
            cand = []
            where = ", ".join(x for x in (p["city"], p["country"]) if x) or "unknown location"
            who = f"{p['label']} ({p['organization']}, {where})"
            if p["investor_likelihood"] == "UNCONFIRMED":
                cand.append(("prospect_signal", "high", "Possible business or investor interest (UNCONFIRMED)",
                             f"{who}: {', '.join(p['signals']) or p['classification']}. Journey: {p['journey']}. {p['action']}"))
            if p["tier"] == "HIGH" and not p["registered"]:
                cand.append(("high_engagement", "medium", "High-engagement visitor", f"{who}: {p['classification']}. Journey: {p['journey']}"))
            if p["corporate"] and p["hits"] >= 2:
                cand.append(("corporate_visit", "medium", "Visit from an organisation network", f"{who}: {p['hits']} page views. Journey: {p['journey']}"))
            if p["visits"] >= 3 and not p["registered"]:
                cand.append(("returning_visitor", "medium", "Unregistered visitor returned 3+ times today", f"{who}: {p['visits']} visits."))
            for kind, sev, title, detail in cand:
                cur = c.execute("INSERT OR IGNORE INTO intel_alerts (kind, severity, label, title, detail, day) VALUES (?,?,?,?,?,?)",
                                (kind, sev, p["label"], title, detail[:500], today))
                if cur.rowcount:
                    new.append({"title": title, "detail": detail, "severity": sev})
    finally:
        c.close()
    for a in new:
        if rank[a["severity"]] >= push_min:
            _notify(a)
    return len(new)


def _scan_loop():
    time.sleep(90)
    while True:
        try:
            scan_alerts()
        except Exception:
            log.debug("alert scan failed", exc_info=True)
        time.sleep(max(1, int(I._env_f("INTEL_SCAN_MINUTES", 5))) * 60)


# ------------------------------------------------------------------ wiring
def register(app, admin_required):
    ensure_schema()

    def days_arg():
        return I._days_arg()

    def host():
        return request.host

    def wrap(fn, name):
        def view():
            try:
                return jsonify(fn())
            except Exception as e:
                log.exception("intel %s failed", name)
                return jsonify({"success": False, "error": f"{type(e).__name__}: {e}"}), 500
        view.__name__ = "intel_" + name
        return view

    app.add_url_rule("/api/admin/insights/intel/overview", "intel_overview",
                     admin_required(wrap(lambda: build_overview(days_arg(), host()), "overview")), methods=["GET"])
    app.add_url_rule("/api/admin/insights/intel/visitors", "intel_visitors", admin_required(wrap(
        lambda: build_visitors(days_arg(), request.args.get("segment", "all"), request.args.get("q", ""),
                               max(1, min(request.args.get("limit", 100, type=int), 300)), host()), "visitors")), methods=["GET"])
    app.add_url_rule("/api/admin/insights/intel/conversion", "intel_conversion",
                     admin_required(wrap(lambda: build_conversion(days_arg()), "conversion")), methods=["GET"])

    def alerts_get():
        ensure_schema()
        c = I._db()
        try:
            allrows = request.args.get("all") == "1"
            rows = c.execute("SELECT id, created_at, kind, severity, label, title, detail, seen FROM intel_alerts "
                             + ("" if allrows else "WHERE seen = 0 ") + "ORDER BY id DESC LIMIT 60").fetchall()
            unseen = c.execute("SELECT COUNT(*) FROM intel_alerts WHERE seen = 0").fetchone()[0]
            return {"success": True, "unseen": unseen, "alerts": [dict(r) for r in rows]}
        finally:
            c.close()

    def alerts_seen():
        ensure_schema()
        ids = (request.get_json(silent=True) or {}).get("ids")
        c = I._db()
        try:
            if ids and isinstance(ids, list):
                ids = [int(x) for x in ids[:200] if str(x).isdigit()]
                c.execute(f"UPDATE intel_alerts SET seen = 1 WHERE id IN ({','.join('?' * len(ids))})", ids) if ids else None
            else:
                c.execute("UPDATE intel_alerts SET seen = 1")
        finally:
            c.close()
        return {"success": True}

    app.add_url_rule("/api/admin/insights/intel/alerts", "intel_alerts", admin_required(wrap(alerts_get, "alerts")), methods=["GET"])
    app.add_url_rule("/api/admin/insights/intel/alerts/seen", "intel_alerts_seen", admin_required(wrap(alerts_seen, "alerts_seen")), methods=["POST"])
    app.add_url_rule("/api/admin/insights/intel/alerts/scan", "intel_alerts_scan",
                     admin_required(wrap(lambda: {"success": True, "created": scan_alerts(host())}, "alerts_scan")), methods=["POST"])
    if os.getenv("INTEL_ALERTS", "true").strip().lower() in ("1", "true", "yes", "on") and os.getenv("INSIGHTS_PURGE", "true").lower() != "false":
        threading.Thread(target=_scan_loop, daemon=True, name="intel-alert-scan").start()
    log.info("Visitor intelligence routes registered")

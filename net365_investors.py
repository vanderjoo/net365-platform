"""net365_investors.py - investor-intelligence layer for Net365 analytics.

Answers, at ORGANISATION level: which organisations look at our investor pages, how often they
come back, where they came from, and how deeply they engage. Four things are tracked:

  * verified company networks   - see "Evidence tiers" below
  * repeat visits               - distinct days / returning sessions per organisation
  * referral sources            - referrer domain + utm_source/medium/campaign (first touch)
  * engagement                  - page views, time on page, scroll depth, clicks, downloads

Evidence tiers (the dashboard never presents a guess as a fact):
  verified      - someone from that organisation submitted the investor-interest form and CONFIRMED the
                  email link sent to a non-free-provider address. A real person, a real email domain.
  corroborated  - a network-inferred organisation whose name matches a verified email domain.
  inferred      - only the visitor's network (ASN owner) points to an organisation. That is a hint, not an
                  identity: many investors sit behind consumer ISPs, VPNs or cloud proxies and are invisible.

Privacy by design:
  * Consumer ISPs, mobile carriers and hosting/VPN networks are never listed as "companies".
  * Raw IP addresses are not stored here; only a salted hash (for counting distinct visitors) plus the ASN.
  * Honours Do-Not-Track and Global Privacy Control: those visitors are not recorded.
  * Individuals are not profiled: sessions are anonymous unless the person identifies themselves.
  * Add a line to your privacy policy and show a notice on the investor page (investors.html has one).
  * Events older than INVESTOR_RETENTION_DAYS (default 180) are deleted.

Environment (all optional):
  INVESTOR_PATHS=/investors,/pitch,/deck,/data-room,/invest    prefixes that count as investor-facing
  INVESTOR_RETENTION_DAYS=180
  INVESTOR_HASH_SALT=<random string>                            falls back to the Flask SECRET_KEY
  INVESTOR_EXCLUDE_ASNS=AS123,AS456       never treat these networks as companies
  INVESTOR_INCLUDE_ASNS=AS789             always treat these networks as companies (e.g. a known fund)
  INVESTOR_NOTIFY_EMAIL=you@net365co.com  get an email when an investor confirms interest
"""

import csv
import hashlib
import hmac
import io
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from flask import jsonify, request, redirect, send_from_directory, Response

HERE = os.path.dirname(os.path.abspath(__file__))
SID_COOKIE = "n365_sid"  # shared with net365_traffic
EVENT_TYPES = {"view", "time", "scroll", "click", "download", "section", "form_open", "form_submit"}
FREE_EMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com", "outlook.com", "live.com",
    "msn.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
    "zoho.com", "yandex.com", "rocketmail.com", "yahoo.co.uk", "hotmail.co.uk",
}

# --- network classification --------------------------------------------------
_CONSUMER = re.compile(
    r"\b(mtn|airtel|glo\b|globacom|9mobile|etisalat|safaricom|vodafone|orange|telkom|spectranet|smile|"
    r"swift networks|ipnx|cobranet|fibreone|comcast|verizon|at&t|t-mobile|sprint|charter|cox comm|"
    r"virgin media|sky broadband|bt\b|british telecommunications|talktalk|bell canada|rogers|telus|"
    r"telecom|telecommunications|telephone|broadband|cable|wireless|mobile|cellular|gsm|isp\b|"
    r"internet service|internet services|residential|dsl|fibre|fiber to)\b", re.I)
_HOSTING = re.compile(
    r"(amazon|aws|google cloud|google llc|microsoft|azure|digitalocean|ovh|hetzner|cloudflare|linode|akamai|"
    r"vultr|alibaba|tencent|oracle|m247|datacamp|leaseweb|contabo|choopa|rackspace|scaleway|fastly|"
    r"hosting|cloud|data ?cent(er|re)|server|vpn|proxy|colo(cation)?|zscaler|netskope|tor exit)", re.I)
_EDU = re.compile(r"(universit|college|school|institute of|polytechnic|academic|research network)", re.I)
_GOV = re.compile(r"(ministry|government|federal|state of|department of|parliament|council|agency)", re.I)


def network_type(asn, org):
    """consumer | hosting | education | government | organisation | unknown"""
    a = (asn or "").upper()
    if a in {x.strip().upper() for x in os.getenv("INVESTOR_INCLUDE_ASNS", "").split(",") if x.strip()}:
        return "organisation"
    if a in {x.strip().upper() for x in os.getenv("INVESTOR_EXCLUDE_ASNS", "").split(",") if x.strip()}:
        return "consumer"
    o = org or ""
    if not o:
        return "unknown"
    if _HOSTING.search(o):
        return "hosting"
    if _CONSUMER.search(o):
        return "consumer"
    if _EDU.search(o):
        return "education"
    if _GOV.search(o):
        return "government"
    return "organisation"


COMPANY_TYPES = ("organisation", "education", "government")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS investor_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, day TEXT NOT NULL,
    session_id TEXT, ip_hash TEXT, asn TEXT, org TEXT, net_type TEXT, country TEXT,
    path TEXT, event TEXT, value REAL, label TEXT,
    referrer_domain TEXT, utm_source TEXT, utm_medium TEXT, utm_campaign TEXT
);
CREATE INDEX IF NOT EXISTS idx_inv_ev_ts ON investor_events(ts);
CREATE INDEX IF NOT EXISTS idx_inv_ev_asn ON investor_events(asn, day);
CREATE INDEX IF NOT EXISTS idx_inv_ev_sid ON investor_events(session_id);
CREATE TABLE IF NOT EXISTS investor_leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL, name TEXT, email TEXT, email_domain TEXT, corporate INTEGER DEFAULT 0,
    org_name TEXT, role TEXT, message TEXT, session_id TEXT, ip_hash TEXT, asn TEXT, net_org TEXT,
    token_hash TEXT, confirmed_at TEXT, status TEXT DEFAULT 'unconfirmed'
);
CREATE INDEX IF NOT EXISTS idx_inv_lead_email ON investor_leads(email);
"""


def _paths():
    raw = os.getenv("INVESTOR_PATHS", "/investors,/pitch,/deck,/data-room,/invest")
    return tuple(p.strip() for p in raw.split(",") if p.strip())


def _is_investor_path(path):
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in _paths())


def _domain(url):
    try:
        h = urlsplit(url).netloc.lower().split(":")[0]
        return h[4:] if h.startswith("www.") else h
    except Exception:
        return ""


def init_investors(app, get_db_connection, admin_required, get_client_ip, rate_hit_db=None,
                   send_email=None, asn_for=None, base_url="", logger=None):
    import logging
    logger = logger or logging.getLogger(__name__)

    conn = get_db_connection()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()

    salt = (os.getenv("INVESTOR_HASH_SALT") or app.config.get("SECRET_KEY") or "net365").encode()

    def ip_hash(ip):
        return hmac.new(salt, (ip or "").encode(), hashlib.sha256).hexdigest()[:20]

    def q(sql, args=()):
        c = get_db_connection()
        try:
            return [dict(r) for r in c.execute(sql, args).fetchall()]
        finally:
            c.close()

    def do_not_track():
        return request.headers.get("DNT") == "1" or request.headers.get("Sec-GPC") == "1"

    def since(days):
        return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    # purge old data once an hour, in the background
    def purger():
        while True:
            time.sleep(3600)
            try:
                d = max(30, int(os.getenv("INVESTOR_RETENTION_DAYS", "180")))
                c = get_db_connection()
                try:
                    c.execute("DELETE FROM investor_events WHERE ts < datetime('now', ?)", (f"-{d} days",))
                    c.execute("DELETE FROM investor_leads WHERE status='unconfirmed' AND created_at < datetime('now','-30 days')")
                    c.commit()
                finally:
                    c.close()
            except Exception as e:
                logger.debug(f"investor purge failed: {e}")
    threading.Thread(target=purger, daemon=True).start()

    # ------------------------------------------------------------ public: pages + beacon
    @app.route("/investors")
    def investors_page():
        resp = send_from_directory(HERE, "investors.html")
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.route("/investor_track.js")
    def investor_track_js():
        resp = send_from_directory(HERE, "investor_track.js", mimetype="application/javascript")
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    _hits = {}

    @app.route("/api/investors/event", methods=["POST"])
    def investor_event():
        if do_not_track():
            return ("", 204)
        d = request.get_json(silent=True) or {}
        path = str(d.get("path") or "")[:200]
        ev = str(d.get("event") or "")
        if ev not in EVENT_TYPES or not _is_investor_path(path):
            return ("", 204)
        ip = get_client_ip()
        now = time.time()
        arr = [t for t in _hits.get(ip, []) if now - t < 60] + [now]
        _hits[ip] = arr
        if len(_hits) > 4000:
            for k in list(_hits)[:1000]:
                _hits.pop(k, None)
        if len(arr) > 90:
            return ("", 429)
        sid = request.cookies.get(SID_COOKIE) or str(d.get("sid") or "")[:40] or secrets.token_urlsafe(10)
        asn, org = (asn_for(ip) if asn_for else (None, None))
        ntype = network_type(asn, org)
        ref = str(d.get("referrer") or "")
        try:
            value = max(0.0, min(float(d.get("value") or 0), 36000.0))
        except (TypeError, ValueError):
            value = 0.0
        row = (
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            sid, ip_hash(ip), asn, org, ntype, request.headers.get("CF-IPCountry"),
            path, ev, value, str(d.get("label") or "")[:80],
            _domain(ref)[:80], str(d.get("utm_source") or "")[:60], str(d.get("utm_medium") or "")[:60],
            str(d.get("utm_campaign") or "")[:80],
        )
        try:
            c = get_db_connection()
            try:
                c.execute("INSERT INTO investor_events (ts, day, session_id, ip_hash, asn, org, net_type, country, path, "
                          "event, value, label, referrer_domain, utm_source, utm_medium, utm_campaign) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
                c.commit()
            finally:
                c.close()
        except Exception as e:
            logger.debug(f"investor event insert failed: {e}")
        if not asn and asn_for:
            # the network lookup runs in the background; fill it in once it has had time to finish
            threading.Timer(10, backfill_asn, (ip, ip_hash(ip))).start()
        return ("", 204)

    def backfill_asn(ip, h):
        try:
            asn, org = asn_for(ip)
            if not asn:
                return
            c = get_db_connection()
            try:
                c.execute("UPDATE investor_events SET asn=?, org=?, net_type=? WHERE ip_hash=? AND (asn IS NULL OR asn='') "
                          "AND ts >= datetime('now','-1 day')", (asn, org, network_type(asn, org), h))
                c.commit()
            finally:
                c.close()
        except Exception as e:
            logger.debug(f"investor asn backfill failed: {e}")

    @app.route("/api/investors/interest", methods=["POST"])
    def investor_interest():
        d = request.get_json(silent=True) or {}
        ip = get_client_ip()
        try:
            if rate_hit_db and rate_hit_db(f"{ip}|investor-interest", 3600) > 5:
                return jsonify({"success": False, "error": "Too many requests. Please try again later."}), 429
        except Exception:
            pass
        email = str(d.get("email") or "").strip().lower()
        name = str(d.get("name") or "").strip()[:100]
        if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}", email) or len(name) < 2:
            return jsonify({"success": False, "error": "Please enter your name and a valid email address."}), 400
        domain = email.split("@", 1)[1]
        corporate = 0 if domain in FREE_EMAIL else 1
        token = secrets.token_urlsafe(24)
        asn, org = (asn_for(ip) if asn_for else (None, None))
        sid = request.cookies.get(SID_COOKIE) or ""
        c = get_db_connection()
        try:
            c.execute("INSERT INTO investor_leads (created_at, name, email, email_domain, corporate, org_name, role, message, "
                      "session_id, ip_hash, asn, net_org, token_hash) VALUES (datetime('now'),?,?,?,?,?,?,?,?,?,?,?,?)",
                      (name, email, domain, corporate, str(d.get("organisation") or "")[:120], str(d.get("role") or "")[:80],
                       str(d.get("message") or "")[:1000], sid, ip_hash(ip), asn, org,
                       hashlib.sha256(token.encode()).hexdigest()))
            c.commit()
        finally:
            c.close()
        link = f"{base_url.rstrip('/')}/api/investors/confirm?token={token}"
        if send_email:
            try:
                send_email(email, "Confirm your interest in Net365",
                           f"Hello {name},\n\nThanks for your interest in Net365. Please confirm your email address:\n\n{link}\n\n"
                           f"If you did not request this, ignore this message and nothing will happen.")
            except Exception as e:
                logger.warning(f"investor confirm email failed: {e}")
        return jsonify({"success": True, "message": "Thank you. Please check your email to confirm."})

    @app.route("/api/investors/confirm", methods=["GET"])
    def investor_confirm():
        token = request.args.get("token", "")
        th = hashlib.sha256(token.encode()).hexdigest()
        c = get_db_connection()
        try:
            row = c.execute("SELECT id, name, email, org_name, corporate FROM investor_leads WHERE token_hash=? "
                            "AND created_at >= datetime('now','-7 days')", (th,)).fetchone()
            if row:
                c.execute("UPDATE investor_leads SET confirmed_at=datetime('now'), status='confirmed' WHERE id=?", (row["id"],))
                c.commit()
        finally:
            c.close()
        if row and send_email and os.getenv("INVESTOR_NOTIFY_EMAIL"):
            try:
                send_email(os.getenv("INVESTOR_NOTIFY_EMAIL"), "Investor interest confirmed",
                           f"{row['name']} <{row['email']}> ({row['org_name'] or 'no organisation given'}) confirmed interest. "
                           f"Corporate email: {'yes' if row['corporate'] else 'no'}.")
            except Exception:
                pass
        return redirect("/investors?confirmed=1" if row else "/investors?confirmed=0")

    # ------------------------------------------------------------ admin analytics
    def _days():
        return max(1, min(365, request.args.get("days", 30, type=int)))

    def organisations(days):
        """One row per network that looks like an organisation, plus verified identities."""
        s = since(days)
        rows = q(
            "SELECT asn, MAX(org) org, MAX(net_type) net_type, COUNT(DISTINCT session_id) sessions, "
            "COUNT(DISTINCT day) active_days, COUNT(DISTINCT ip_hash) visitors, "
            "SUM(event='view') page_views, ROUND(SUM(CASE WHEN event='time' THEN value ELSE 0 END),0) seconds, "
            "MAX(CASE WHEN event='scroll' THEN value ELSE 0 END) max_scroll, "
            "SUM(event='click') clicks, SUM(event='download') downloads, SUM(event='section') sections, "
            "MIN(ts) first_seen, MAX(ts) last_seen, MAX(country) country "
            "FROM investor_events WHERE ts >= ? AND asn IS NOT NULL AND asn != '' "
            "AND net_type IN ('organisation','education','government') GROUP BY asn", (s,))
        leads = q("SELECT id, name, email_domain, org_name, role, asn, status, corporate, created_at, confirmed_at "
                  "FROM investor_leads WHERE created_at >= ?", (s,))
        by_asn = {}
        for L in leads:
            if L["status"] == "confirmed" and L["corporate"]:
                by_asn.setdefault(L["asn"] or "", []).append(L)
        out = []
        for r in rows:
            r["repeat"] = r["active_days"] >= 2
            confirmed = by_asn.get(r["asn"], [])
            name_tokens = re.findall(r"[a-z]{4,}", (r["org"] or "").lower())
            corroborated = any(any(t in (L["email_domain"] or "") for t in name_tokens) for L in leads
                               if L["status"] == "confirmed" and L["corporate"])
            r["tier"] = "verified" if confirmed else ("corroborated" if corroborated else "inferred")
            r["verified_contacts"] = [{"name": L["name"], "domain": L["email_domain"], "role": L["role"]} for L in confirmed]
            r["score"] = score(r, bool(confirmed))
            out.append(r)
        out.sort(key=lambda x: (-x["score"], x["last_seen"] or ""))
        return out

    def score(r, verified):
        """Transparent engagement score (0-100). Weights are shown in the dashboard."""
        s = min(r["active_days"], 5) * 8                    # up to 40: coming back on different days
        s += min(r["page_views"], 12) * 2                   # up to 24: pages viewed
        s += min((r["seconds"] or 0) / 60.0, 10) * 1.5      # up to 15: minutes spent
        s += 6 if (r["max_scroll"] or 0) >= 75 else 0       # read to the end
        s += 10 if (r["downloads"] or 0) else 0             # took a document
        s += 5 if (r["clicks"] or 0) else 0
        s += 25 if verified else 0                          # confirmed real person
        return int(min(100, round(s)))

    @app.route("/api/admin/investors/summary", methods=["GET"])
    @admin_required
    def investors_summary():
        days, s = _days(), since(_days())
        orgs = organisations(days)
        tot = q("SELECT COUNT(DISTINCT session_id) sessions, COUNT(DISTINCT ip_hash) visitors, SUM(event='view') page_views, "
                "SUM(event='download') downloads FROM investor_events WHERE ts >= ?", (s,))[0]
        leads = q("SELECT COUNT(*) total, SUM(status='confirmed') confirmed, SUM(status='confirmed' AND corporate=1) corporate "
                  "FROM investor_leads WHERE created_at >= ?", (s,))[0]
        hidden = q("SELECT COUNT(DISTINCT session_id) n FROM investor_events WHERE ts >= ? AND "
                   "(net_type IN ('consumer','hosting','unknown') OR net_type IS NULL)", (s,))[0]["n"]
        sources = q(
            "SELECT CASE WHEN utm_source!='' THEN 'utm:'||utm_source WHEN referrer_domain!='' THEN referrer_domain ELSE '(direct)' END source, "
            "MAX(utm_medium) medium, MAX(utm_campaign) campaign, COUNT(DISTINCT session_id) sessions, "
            "COUNT(DISTINCT CASE WHEN net_type IN ('organisation','education','government') THEN asn END) orgs, "
            "SUM(event='download') downloads FROM investor_events WHERE ts >= ? AND event='view' GROUP BY source "
            "ORDER BY sessions DESC LIMIT 15", (s,))
        pages = q(
            "SELECT path, SUM(event='view') views, COUNT(DISTINCT session_id) sessions, "
            "COUNT(DISTINCT CASE WHEN net_type IN ('organisation','education','government') THEN asn END) orgs, "
            "ROUND(AVG(CASE WHEN event='time' THEN value END),0) avg_seconds, "
            "COUNT(DISTINCT CASE WHEN event='scroll' AND value>=75 THEN session_id END) read_to_end, "
            "SUM(event='click') clicks, SUM(event='download') downloads FROM investor_events WHERE ts >= ? "
            "GROUP BY path ORDER BY views DESC LIMIT 20", (s,))
        trend = q("SELECT day t, COUNT(DISTINCT session_id) sessions, "
                  "COUNT(DISTINCT CASE WHEN net_type IN ('organisation','education','government') THEN asn END) orgs "
                  "FROM investor_events WHERE ts >= ? GROUP BY day ORDER BY day", (s,))
        return jsonify({
            "success": True, "days": days, "paths": list(_paths()),
            "kpis": {
                "sessions": tot["sessions"] or 0, "page_views": tot["page_views"] or 0, "downloads": tot["downloads"] or 0,
                "organisations": len(orgs), "repeat_orgs": sum(1 for o in orgs if o["repeat"]),
                "verified_orgs": sum(1 for o in orgs if o["tier"] == "verified"),
                "interest_requests": leads["total"] or 0, "confirmed_investors": leads["confirmed"] or 0,
                "corporate_confirmed": leads["corporate"] or 0, "unattributable_sessions": hidden,
            },
            "top_organisations": orgs[:10], "sources": sources, "pages": pages, "trend": trend,
        })

    @app.route("/api/admin/investors/organisations", methods=["GET"])
    @admin_required
    def investors_orgs():
        orgs = organisations(_days())
        tier = request.args.get("tier")
        if tier:
            orgs = [o for o in orgs if o["tier"] == tier]
        return jsonify({"success": True, "organisations": orgs})

    @app.route("/api/admin/investors/organisation/<asn>", methods=["GET"])
    @admin_required
    def investors_org_detail(asn):
        s = since(_days())
        events = q("SELECT ts, session_id, path, event, value, label, referrer_domain, utm_source, utm_medium, utm_campaign "
                   "FROM investor_events WHERE asn=? AND ts >= ? ORDER BY id DESC LIMIT 300", (asn, s))
        for e in events:
            e["session_id"] = (e["session_id"] or "")[:6]  # anonymous; shown only to tell sessions apart
        days = q("SELECT day, COUNT(DISTINCT session_id) sessions, SUM(event='view') views FROM investor_events "
                 "WHERE asn=? AND ts >= ? GROUP BY day ORDER BY day", (asn, s))
        return jsonify({"success": True, "asn": asn, "days": days, "events": events})

    @app.route("/api/admin/investors/leads", methods=["GET"])
    @admin_required
    def investors_leads():
        rows = q("SELECT id, created_at, name, email, email_domain, corporate, org_name, role, message, asn, net_org, status, confirmed_at "
                 "FROM investor_leads WHERE created_at >= ? ORDER BY id DESC LIMIT 200", (since(_days()),))
        return jsonify({"success": True, "leads": rows})

    @app.route("/api/admin/investors/export.csv", methods=["GET"])
    @admin_required
    def investors_export():
        orgs = organisations(_days())
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["asn", "organisation", "tier", "score", "sessions", "active_days", "page_views", "seconds", "max_scroll",
                    "downloads", "first_seen", "last_seen", "verified_contacts"])
        for o in orgs:
            w.writerow([o["asn"], o["org"], o["tier"], o["score"], o["sessions"], o["active_days"], o["page_views"], o["seconds"],
                        o["max_scroll"], o["downloads"], o["first_seen"], o["last_seen"],
                        "; ".join(f"{c['name']} @{c['domain']}" for c in o["verified_contacts"])])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=investor-organisations.csv"})

    logger.info("Investor intelligence ready (/investors, /api/investors/*, /api/admin/investors/*)")

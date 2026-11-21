"""
Net365 Insights: visitor intelligence + transaction / revenue / profit reporting.

What it adds
  * A first-party visitor id (cookie n365_vid), set ONLY after the visitor accepts analytics
    (cookie n365_consent=1). Set INSIGHTS_REQUIRE_CONSENT=false to skip that check.
  * visitor_events (funnel steps) and visitor_profile (first-touch source, visits, linked user).
  * POST /api/track for browser events (whitelisted, PII keys dropped).
  * Server-side events you call from payment code: log_event("payment_started"|"fulfilled"|...).
  * Admin report endpoints used by the Insights tab:
        GET /api/admin/insights/overview?days=30   revenue, fees, estimated profit, charts data, cohorts
        GET /api/admin/insights/funnel?days=30     visitor funnel
        GET /api/admin/insights/sources?days=30    which traffic source produced paying customers
  * Retention: events older than INSIGHTS_EVENT_DAYS (365) are deleted, and raw IPs in visitor_logs
    older than INSIGHTS_IP_DAYS (30) are replaced by a salted hash.

Profit is an ESTIMATE:
    fee charged to customer
  + provider margin   (PROFIT_PROVIDER_MARGIN_PCT % of the airtime/bill amount; your Reloadly discount)
  - gateway cost      (PAYSTACK_FEE_PCT / FLUTTERWAVE_FEE_PCT / GATEWAY_FEE_PCT, flat NGN 100 on Paystack >= 2500)
  - referral bonuses  (wallet credits whose reference starts with REFBONUS-)
Only NGN rows are included in money totals.
"""
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from datetime import date, datetime, timedelta

from flask import g, has_request_context, jsonify, request, send_from_directory

log = logging.getLogger("net365.insights")

_d = {}
_ready = False
BASE = os.path.dirname(os.path.abspath(__file__))
COOKIE = "n365_vid"
CONSENT_COOKIE = "n365_consent"
_VID_RE = re.compile(r"^v_[a-f0-9]{32}$")
SUCCESS = ("fulfilled", "completed")
FAILED = ("failed", "fulfillment_failed")
LAGOS_OFFSET = timedelta(hours=1)  # Lagos has no DST
OPERATORS = {"49": "MTN", "50": "Glo", "51": "Airtel", "52": "9mobile"}
TRACKED_PATHS = {"/", "/scheduler", "/analytics", "/business", "/utilities", "/giftcards"}
CLIENT_EVENTS = {
    "consent_granted", "phone_entered", "network_detected", "amount_selected", "payment_redirected",
    "signup_started", "signup_completed", "ad_seen", "ad_clicked", "referral_code_used",
}
FUNNEL = ["landing", "phone_entered", "network_detected", "amount_selected", "payment_started", "fulfilled"]
FUNNEL_LABELS = {
    "landing": "Visited", "phone_entered": "Entered phone", "network_detected": "Network found",
    "amount_selected": "Chose amount", "payment_started": "Started payment", "fulfilled": "Recharge delivered",
}


# ------------------------------------------------------------------ helpers
def _db():
    return _d["db"].get_db_connection()


def _now():
    return datetime.utcnow()


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _num(x):
    try:
        v = float(x)
        return v if v == v and abs(v) != float("inf") else 0.0
    except (TypeError, ValueError):
        return 0.0


def _env_f(name, default):
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return float(default)


def _require_consent():
    return os.getenv("INSIGHTS_REQUIRE_CONSENT", "true").strip().lower() in ("1", "true", "yes", "on")


def _consented():
    return (not _require_consent()) or request.cookies.get(CONSENT_COOKIE) == "1"


def _days_arg(default=30):
    try:
        return max(1, min(int(request.args.get("days", default)), 365))
    except (TypeError, ValueError):
        return default


def _client_ip():
    return (request.headers.get("CF-Connecting-IP", "").strip()
            or (request.headers.get("X-Forwarded-For", "").split(",")[0].strip())
            or request.remote_addr or "")


def classify_referrer(ref, host=""):
    if not ref:
        return "direct"
    try:
        from urllib.parse import urlsplit
        h = (urlsplit(ref).hostname or "").lower()
    except Exception:
        return "other"
    if not h:
        return "direct"
    if host and h == host.split(":")[0].lower():
        return "internal"
    if re.search(r"google\.|bing\.|duckduckgo|yahoo\.|yandex", h):
        return "search"
    if re.search(r"facebook|fb\.|instagram|twitter|x\.com|t\.co|linkedin|tiktok|whatsapp|wa\.me|telegram|t\.me|youtube", h):
        return "social"
    if re.search(r"mail\.|gmail|outlook|yahoo\.com/mail", h):
        return "email"
    return "referral"


def _clean_props(p):
    """Keep small, harmless values only. Anything that looks like personal data is dropped."""
    out = {}
    if not isinstance(p, dict):
        return out
    for k, v in list(p.items())[:12]:
        k = str(k)[:30]
        if re.search(r"phone|email|name|account|token|password|pin|card", k, re.I):
            continue
        if isinstance(v, bool):
            out[k] = v
        elif isinstance(v, (int, float)) and v == v:
            out[k] = v
        elif isinstance(v, str):
            out[k] = v[:80]
    return out


def visitor_id():
    """The current visitor's id (or None). Safe to call anywhere, including outside a request."""
    try:
        if has_request_context():
            v = getattr(g, "_n365_vid", None) or request.cookies.get(COOKIE)
            return v if v and _VID_RE.match(v) else None
    except Exception:
        pass
    return None


# ------------------------------------------------------------------ schema
def ensure_schema():
    global _ready
    if _ready:
        return
    c = _db()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS visitor_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, visitor_id TEXT, session_id TEXT, user_id INTEGER,
            event TEXT NOT NULL, props TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ve_event ON visitor_events(event, created_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ve_visitor ON visitor_events(visitor_id)")
        c.execute("""CREATE TABLE IF NOT EXISTS visitor_profile (
            visitor_id TEXT PRIMARY KEY, user_id INTEGER, first_seen TIMESTAMP, last_seen TIMESTAMP,
            visits INTEGER DEFAULT 1, first_source TEXT, first_medium TEXT, first_campaign TEXT,
            first_referrer_class TEXT, first_country TEXT, device_class TEXT, last_path TEXT)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_vp_first_seen ON visitor_profile(first_seen)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_vp_user ON visitor_profile(user_id)")
        c.execute("""CREATE TABLE IF NOT EXISTS visitor_signals (
            id INTEGER PRIMARY KEY AUTOINCREMENT, visitor_id TEXT, session_id TEXT, user_id INTEGER,
            screen_w INTEGER, screen_h INTEGER, viewport_w INTEGER, viewport_h INTEGER, timezone TEXT, language TEXT,
            touch INTEGER, connection TEXT, referrer_class TEXT, utm_source TEXT, utm_medium TEXT, utm_campaign TEXT,
            local_hour INTEGER, local_dow INTEGER, captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_vs_visitor ON visitor_signals(visitor_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_vs_captured ON visitor_signals(captured_at)")
        _ready = True
    finally:
        c.close()


# ------------------------------------------------------------------ event capture
def log_event(event, props=None, visitor_id_=None, user_id=None, session_id=None):
    """Record one event. Never raises. Server-side funnel events call this directly."""
    try:
        ensure_schema()
        vid = visitor_id_ or visitor_id()
        c = _db()
        try:
            c.execute("INSERT INTO visitor_events (visitor_id, session_id, user_id, event, props) VALUES (?,?,?,?,?)",
                      (vid, session_id, user_id, str(event)[:40], json.dumps(_clean_props(props or {}))))
            if vid and user_id:
                c.execute("UPDATE visitor_profile SET user_id = ? WHERE visitor_id = ? AND user_id IS NULL", (user_id, vid))
        finally:
            c.close()
    except Exception:
        log.debug("insights log_event failed", exc_info=True)


def _record_landing(vid, path, referrer, utm, country, device, host):
    try:
        ensure_schema()
        rclass = classify_referrer(referrer, host)
        c = _db()
        try:
            row = c.execute("SELECT last_seen FROM visitor_profile WHERE visitor_id = ?", (vid,)).fetchone()
            new_visit = True
            if row and row["last_seen"]:
                try:
                    new_visit = (_now() - datetime.fromisoformat(str(row["last_seen"]))) > timedelta(minutes=30)
                except ValueError:
                    pass
            now = _fmt(_now())
            if not row:
                source = (utm.get("utm_source") or (rclass if rclass != "internal" else "direct"))[:60]
                c.execute("""INSERT OR IGNORE INTO visitor_profile (visitor_id, first_seen, last_seen, visits, first_source,
                             first_medium, first_campaign, first_referrer_class, first_country, device_class, last_path)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                          (vid, now, now, 1, source, (utm.get("utm_medium") or "")[:60], (utm.get("utm_campaign") or "")[:60],
                           rclass, country, device, path))
            else:
                c.execute("UPDATE visitor_profile SET last_seen = ?, visits = visits + ?, last_path = ? WHERE visitor_id = ?",
                          (now, 1 if new_visit else 0, path, vid))
            if new_visit:
                c.execute("INSERT INTO visitor_events (visitor_id, event, props) VALUES (?, 'landing', ?)",
                          (vid, json.dumps({"path": path, "ref": rclass, "country": country, "device": device,
                                            "utm_source": (utm.get("utm_source") or "")[:40]})))
        finally:
            c.close()
    except Exception:
        log.debug("insights landing failed", exc_info=True)


def _is_bot(ua):
    try:
        from ip_intel import detect_bot
        return detect_bot(ua)[0]
    except Exception:
        return not ua


def _before():
    try:
        v = request.cookies.get(COOKIE)
        g._n365_vid = v if v and _VID_RE.match(v) else None
        g._n365_new = False
        if (not g._n365_vid and request.method == "GET" and request.path in TRACKED_PATHS and _consented()
                and not _is_bot(request.headers.get("User-Agent", ""))):
            g._n365_vid = "v_" + secrets.token_hex(16)
            g._n365_new = True
    except Exception:
        pass


def _set_cookie(resp, vid):
    resp.set_cookie(COOKIE, vid, max_age=31536000, httponly=True, samesite="Lax", secure=request.is_secure, path="/")


TRACKER_TAG = '<script src="/n365_tracker.js" defer></script>'


def _inject_tracker(resp):
    """Add the tracker <script> to public HTML pages so no template needs editing."""
    try:
        if os.getenv("INSIGHTS_INJECT_TRACKER", "true").strip().lower() not in ("1", "true", "yes", "on"):
            return
        if resp.status_code != 200 or resp.direct_passthrough or "html" not in (resp.mimetype or ""):
            return
        if resp.headers.get("Content-Encoding"):
            return
        body = resp.get_data(as_text=True)
        i = body.rfind("</body>")
        if i < 0 or "n365_tracker.js" in body:
            return
        resp.set_data(body[:i] + TRACKER_TAG + body[i:])
    except Exception:
        log.debug("insights inject failed", exc_info=True)


def _after(resp):
    try:
        if request.method == "GET" and request.path in TRACKED_PATHS:
            _inject_tracker(resp)
        if request.method != "GET" or request.path not in TRACKED_PATHS or resp.status_code >= 400:
            return resp
        vid = getattr(g, "_n365_vid", None)
        if not vid or not _consented():
            return resp
        ua = request.headers.get("User-Agent", "")
        if _is_bot(ua):
            return resp
        excluded = {x.strip() for x in os.getenv("INSIGHTS_EXCLUDE_IPS", "").split(",") if x.strip()}
        if _client_ip() in excluded:
            return resp
        if getattr(g, "_n365_new", False):
            _set_cookie(resp, vid)
        utm = {k: request.args.get(k) for k in ("utm_source", "utm_medium", "utm_campaign")}
        device = "mobile" if re.search(r"mobi|android|iphone", ua, re.I) else "desktop"
        threading.Thread(target=_record_landing, daemon=True, args=(
            vid, request.path, request.headers.get("Referer", ""), utm,
            (request.headers.get("CF-IPCountry") or "")[:2] or None, device, request.host)).start()
    except Exception:
        pass
    return resp


# ------------------------------------------------------------------ reporting
def _gateway_cost(provider, amount, cur):
    if cur != "NGN":
        return 0.0
    p = (provider or "").lower()
    if p in ("", "wallet"):
        return 0.0
    if p == "paystack":
        cost = amount * _env_f("PAYSTACK_FEE_PCT", 1.5) / 100 + (100 if amount >= 2500 else 0)
        return min(cost, 2000.0)
    if p == "flutterwave":
        return min(amount * _env_f("FLUTTERWAVE_FEE_PCT", 1.4) / 100, 2000.0)
    return amount * _env_f("GATEWAY_FEE_PCT", 1.5) / 100


def _payload(p):
    if isinstance(p, dict):
        return p
    try:
        return json.loads(p) if p else {}
    except (TypeError, ValueError):
        return {}


def _dt(s):
    try:
        return datetime.fromisoformat(str(s).replace("T", " ").split(".")[0].replace("Z", ""))
    except (TypeError, ValueError):
        return None


def _load(c, start, end):
    has_err = any(r[1] == "fulfillment_error" for r in c.execute("PRAGMA table_info(transactions)").fetchall())
    rows = c.execute(
        "SELECT reference, user_id, tx_type, provider, amount, currency, status, payload, created_at, "
        + ("fulfillment_error" if has_err else "NULL AS fulfillment_error") + " "
        "FROM transactions WHERE created_at >= ? AND created_at < ? AND tx_type != 'wallet_funding' "
        "ORDER BY created_at LIMIT 100000", (_fmt(start), _fmt(end))).fetchall()
    out = []
    margin_pct = _env_f("PROFIT_PROVIDER_MARGIN_PCT", 0)
    for r in rows:
        p = _payload(r["payload"])
        amt = _num(r["amount"])
        cur = (r["currency"] or "NGN").upper()
        ok = (r["status"] or "").lower() in SUCCESS
        fee = _num(p.get("fee_amount"))
        svc = _num(p.get("service_amount")) or max(amt - fee, 0)
        dt = _dt(r["created_at"])
        local = dt + LAGOS_OFFSET if dt else None
        money = ok and cur == "NGN"
        cost = _gateway_cost(r["provider"], amt, cur) if money else 0.0
        margin = svc * margin_pct / 100 if money else 0.0
        label = (p.get("operator_name") or OPERATORS.get(str(p.get("operator_id") or ""))
                 or p.get("biller_name") or ("Other" if r["tx_type"] == "topup" else (r["tx_type"] or "Other").title()))
        out.append({
            "ref": r["reference"], "uid": r["user_id"], "type": r["tx_type"] or "unknown", "provider": (r["provider"] or "n/a").lower(),
            "amount": amt, "cur": cur, "status": (r["status"] or "").lower(), "ok": ok, "fee": fee if money else 0.0,
            "svc": svc, "cost": cost, "margin": margin, "profit": (fee + margin - cost) if money else 0.0,
            "local": local, "label": label, "err": (r["fulfillment_error"] or "")[:70], "vid": p.get("visitor_id"),
            "cust": r["user_id"] or p.get("email") or r["reference"],
        })
    return out


def _kpis(rows, first_seen, since, referral_cost):
    ok = [r for r in rows if r["ok"] and r["cur"] == "NGN"]
    failed = [r for r in rows if r["status"] in FAILED]
    cutoff = _now() - timedelta(minutes=60)
    abandoned = sum(1 for r in rows if r["status"] == "pending" and r["local"] and r["local"] - LAGOS_OFFSET < cutoff)
    custs = {r["cust"] for r in ok}
    new = len({r["uid"] for r in ok if r["uid"] and first_seen.get(r["uid"]) and first_seen[r["uid"]] >= since})
    volume = sum(r["amount"] for r in ok)
    fees = sum(r["fee"] for r in ok)
    gw = sum(r["cost"] for r in ok)
    margin = sum(r["margin"] for r in ok)
    profit = fees + margin - gw - referral_cost
    done = len(ok) + len(failed)
    return {
        "volume": round(volume, 2), "fees": round(fees, 2), "provider_margin": round(margin, 2), "gateway_cost": round(gw, 2),
        "referral_cost": round(referral_cost, 2), "profit": round(profit, 2),
        "transactions": len(ok), "failed": len(failed), "abandoned": abandoned,
        "success_rate": round(100 * len(ok) / done, 1) if done else None,
        "avg_ticket": round(volume / len(ok), 2) if ok else 0, "customers": len(custs), "new_customers": new,
        "profit_margin_pct": round(100 * profit / volume, 2) if volume else None,
    }


def _delta(cur, prev):
    out = {}
    for k, v in cur.items():
        pv = prev.get(k)
        out[k] = round(100 * (v - pv) / abs(pv), 1) if isinstance(v, (int, float)) and isinstance(pv, (int, float)) and pv else None
    return out


def _bucket(rows, keyf):
    agg = {}
    for r in rows:
        if not r["ok"] or r["cur"] != "NGN":
            continue
        k = keyf(r)
        if k is None:
            continue
        a = agg.setdefault(k, {"count": 0, "volume": 0.0, "fees": 0.0, "profit": 0.0})
        a["count"] += 1
        a["volume"] += r["amount"]
        a["fees"] += r["fee"]
        a["profit"] += r["profit"]
    return agg


def _round(d):
    return {k: (round(v, 2) if isinstance(v, float) else v) for k, v in d.items()}


def _cohorts(c, today):
    rows = c.execute("SELECT user_id, created_at FROM transactions WHERE user_id IS NOT NULL AND status IN ('fulfilled','completed') "
                     "AND tx_type != 'wallet_funding' ORDER BY created_at LIMIT 200000").fetchall()
    weeks = {}
    for r in rows:
        dt = _dt(r["created_at"])
        if dt:
            weeks.setdefault(r["user_id"], set()).add((dt + LAGOS_OFFSET).date().toordinal() // 7)
    now_w = today.toordinal() // 7
    cohorts = {}
    for uid, ws in weeks.items():
        first = min(ws)
        if now_w - first <= 7:
            cohorts.setdefault(first, []).append(ws)
    out = []
    for w in sorted(cohorts):
        members = cohorts[w]
        ret = []
        for k in range(5):
            ret.append(None if w + k > now_w else round(100 * sum(1 for ws in members if (w + k) in ws) / len(members)))
        out.append({"cohort": date.fromordinal(w * 7 + 1).isoformat(), "size": len(members), "retention": ret})
    return out


def build_overview(days):
    ensure_schema()
    now = _now()
    start, prev_start = now - timedelta(days=days), now - timedelta(days=2 * days)
    c = _db()
    try:
        cur_rows = _load(c, start, now + timedelta(minutes=1))
        prev_rows = _load(c, prev_start, start)
        first_seen = {}
        for r in c.execute("SELECT user_id, MIN(created_at) AS f FROM transactions WHERE user_id IS NOT NULL AND status IN ('fulfilled','completed') "
                           "AND tx_type != 'wallet_funding' GROUP BY user_id").fetchall():
            first_seen[r["user_id"]] = _dt(r["f"])

        def refcost(a, b):
            try:
                v = c.execute("SELECT COALESCE(SUM(amount),0) FROM wallet_transactions WHERE reference LIKE 'REFBONUS-%' AND type='credit' "
                              "AND UPPER(COALESCE(currency,'NGN'))='NGN' AND created_at >= ? AND created_at < ?", (_fmt(a), _fmt(b))).fetchone()[0]
                return _num(v)
            except Exception:
                return 0.0

        cur_k = _kpis(cur_rows, first_seen, start, refcost(start, now + timedelta(minutes=1)))
        prev_k = _kpis(prev_rows, first_seen, prev_start, refcost(prev_start, start))

        today = (now + LAGOS_OFFSET).date()
        by_day = _bucket(cur_rows, lambda r: r["local"].date().isoformat() if r["local"] else None)
        fail_day = {}
        for r in cur_rows:
            if r["status"] in FAILED and r["local"]:
                k = r["local"].date().isoformat()
                fail_day[k] = fail_day.get(k, 0) + 1
        daily = []
        for i in range(days):
            d = (today - timedelta(days=days - 1 - i)).isoformat()
            a = by_day.get(d, {"count": 0, "volume": 0, "fees": 0, "profit": 0})
            daily.append({"day": d, "failed": fail_day.get(d, 0), **_round(a)})

        by_hour_d = _bucket(cur_rows, lambda r: r["local"].hour if r["local"] else None)
        by_dow_d = _bucket(cur_rows, lambda r: r["local"].weekday() if r["local"] else None)
        by_hour = [{"hour": h, **_round(by_hour_d.get(h, {"count": 0, "volume": 0, "fees": 0, "profit": 0}))} for h in range(24)]
        names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        by_dow = [{"day": names[i], **_round(by_dow_d.get(i, {"count": 0, "volume": 0, "fees": 0, "profit": 0}))} for i in range(7)]

        def listify(d, key="name", limit=12):
            items = sorted(d.items(), key=lambda kv: kv[1]["volume"], reverse=True)[:limit]
            return [{key: k, **_round(v)} for k, v in items]

        by_type = listify(_bucket(cur_rows, lambda r: r["type"]))
        by_network = listify(_bucket(cur_rows, lambda r: r["label"]))

        gw = {}
        for r in cur_rows:
            if r["status"] == "pending":
                continue
            a = gw.setdefault(r["provider"], {"attempts": 0, "ok": 0, "failed": 0, "volume": 0.0})
            a["attempts"] += 1
            if r["ok"]:
                a["ok"] += 1
                if r["cur"] == "NGN":
                    a["volume"] += r["amount"]
            elif r["status"] in FAILED:
                a["failed"] += 1
        by_gateway = [{"provider": k, **_round(v), "success_rate": round(100 * v["ok"] / v["attempts"], 1) if v["attempts"] else None}
                      for k, v in sorted(gw.items(), key=lambda kv: kv[1]["attempts"], reverse=True)]

        reasons = {}
        for r in cur_rows:
            if r["status"] in FAILED:
                k = re.sub(r"\d{6,}", "#", r["err"] or "Unknown reason")
                reasons[k] = reasons.get(k, 0) + 1
        failures = [{"reason": k, "count": v} for k, v in sorted(reasons.items(), key=lambda kv: kv[1], reverse=True)[:8]]

        return {
            "success": True, "days": days, "currency": "NGN",
            "kpis": cur_k, "previous": prev_k, "delta": _delta(cur_k, prev_k),
            "daily": daily, "by_hour": by_hour, "by_dow": by_dow, "by_type": by_type, "by_network": by_network,
            "by_gateway": by_gateway, "failures": failures, "cohorts": _cohorts(c, today),
            "other_currency_transactions": sum(1 for r in cur_rows if r["ok"] and r["cur"] != "NGN"),
            "assumptions": {
                "provider_margin_pct": _env_f("PROFIT_PROVIDER_MARGIN_PCT", 0),
                "note": "Profit is an estimate: fee + provider margin - gateway cost - referral bonuses. "
                        "Set PROFIT_PROVIDER_MARGIN_PCT to your Reloadly discount to include it. Gift cards and merchant payments may carry no fee.",
            },
        }
    finally:
        c.close()


def build_funnel(days):
    ensure_schema()
    since = _fmt(_now() - timedelta(days=days))
    c = _db()
    try:
        counts = {r["event"]: r["n"] for r in c.execute(
            "SELECT event, COUNT(DISTINCT visitor_id) AS n FROM visitor_events WHERE created_at >= ? AND visitor_id IS NOT NULL GROUP BY event", (since,)).fetchall()}
        totals = {r["event"]: r["n"] for r in c.execute(
            "SELECT event, COUNT(*) AS n FROM visitor_events WHERE created_at >= ? GROUP BY event", (since,)).fetchall()}
        steps, first, prev = [], None, None
        for ev in FUNNEL:
            n = counts.get(ev, 0)
            first = n if first is None else first
            steps.append({"event": ev, "label": FUNNEL_LABELS[ev], "visitors": n, "events": totals.get(ev, 0),
                          "pct_of_first": round(100 * n / first, 1) if first else None,
                          "pct_of_prev": round(100 * n / prev, 1) if prev else None})
            prev = n
        extras = {k: totals.get(k, 0) for k in ("fulfillment_failed", "signup_started", "signup_completed", "ad_seen", "ad_clicked", "referral_code_used")}
        return {"success": True, "days": days, "steps": steps, "extras": extras,
                "note": "Funnel counts only visitors who accepted analytics. 'Recharge delivered' also counts guests without a cookie in the events total."}
    finally:
        c.close()


def build_sources(days):
    ensure_schema()
    now = _now()
    start = now - timedelta(days=days)
    c = _db()
    try:
        label = {}
        agg = {}
        for r in c.execute("SELECT visitor_id, first_source FROM visitor_profile WHERE first_seen >= ?", (_fmt(start),)).fetchall():
            label[r["visitor_id"]] = r["first_source"] or "direct"
            agg.setdefault(label[r["visitor_id"]], {"visitors": 0, "buyers": set(), "orders": 0, "volume": 0.0, "fees": 0.0})["visitors"] += 1
        for r in _load(c, start, now + timedelta(minutes=1)):
            if not r["ok"] or r["cur"] != "NGN" or not r["vid"]:
                continue
            lab = label.get(r["vid"])
            if lab is None:
                row = c.execute("SELECT first_source FROM visitor_profile WHERE visitor_id = ?", (r["vid"],)).fetchone()
                lab = (row["first_source"] if row else None) or "unknown"
            a = agg.setdefault(lab, {"visitors": 0, "buyers": set(), "orders": 0, "volume": 0.0, "fees": 0.0})
            a["buyers"].add(r["cust"])
            a["orders"] += 1
            a["volume"] += r["amount"]
            a["fees"] += r["fee"]
        out = [{"source": k, "visitors": v["visitors"], "buyers": len(v["buyers"]), "orders": v["orders"],
                "volume": round(v["volume"], 2), "fees": round(v["fees"], 2),
                "conversion_pct": round(100 * len(v["buyers"]) / v["visitors"], 1) if v["visitors"] else None}
               for k, v in agg.items()]
        out.sort(key=lambda x: (x["volume"], x["visitors"]), reverse=True)
        return {"success": True, "days": days, "sources": out[:25],
                "note": "Needs visitor_id stored in the transaction payload (see integration step). Older transactions are not attributed."}
    finally:
        c.close()


# ------------------------------------------------------------------ retention
def purge():
    """Delete old events and replace old raw IPs with a salted hash. Safe to run repeatedly."""
    try:
        ensure_schema()
        c = _db()
        try:
            ev_days = int(_env_f("INSIGHTS_EVENT_DAYS", 365))
            c.execute("DELETE FROM visitor_events WHERE created_at < ?", (_fmt(_now() - timedelta(days=ev_days)),))
            c.execute("DELETE FROM visitor_signals WHERE captured_at < ?",
                      (_fmt(_now() - timedelta(days=int(_env_f("INSIGHTS_SIGNAL_DAYS", 180)))),))
            ip_days = int(_env_f("INSIGHTS_IP_DAYS", 30))
            salt = os.getenv("SECRET_KEY") or os.getenv("FLASK_SECRET_KEY") or "net365"
            rows = c.execute("SELECT id, ip_address FROM visitor_logs WHERE visited_at < ? AND ip_address IS NOT NULL "
                             "AND ip_address NOT LIKE 'h:%' AND ip_address != '' LIMIT 3000",
                             (_fmt(_now() - timedelta(days=ip_days)),)).fetchall()
            for r in rows:
                h = "h:" + hashlib.sha256(f"{salt}|{r['ip_address']}".encode()).hexdigest()[:12]
                c.execute("UPDATE visitor_logs SET ip_address = ? WHERE id = ?", (h, r["id"]))
        finally:
            c.close()
    except Exception:
        log.debug("insights purge failed", exc_info=True)


def _purge_loop():
    time.sleep(60)
    while True:
        purge()
        time.sleep(6 * 3600)


# ------------------------------------------------------------------ wiring
def init_insights(app, db_module, admin_required, rate_limit=None, get_user_id=None):
    """Call once after the Flask app exists:
        init_insights(app, db, admin_required, rate_limit=rate_limit, get_user_id=lambda: (get_authenticated_user() or {}).get("id"))
    """
    _d.update(db=db_module)
    ensure_schema()
    app.before_request(_before)
    app.after_request(_after)

    def track():
        data = request.get_json(silent=True) or {}
        event = str(data.get("event") or "")
        if event not in CLIENT_EVENTS or not _consented():
            return ("", 204)
        if _is_bot(request.headers.get("User-Agent", "")):
            return ("", 204)
        vid = request.cookies.get(COOKIE)
        vid = vid if vid and _VID_RE.match(vid) else None
        new_vid = False
        if not vid:
            vid, new_vid = "v_" + secrets.token_hex(16), True
        raw = data.get("props") if isinstance(data.get("props"), dict) else {}
        uid = None
        try:
            uid = get_user_id() if get_user_id else None
        except Exception:
            uid = None
        if event == "consent_granted":
            utm = {k: raw.get(k) for k in ("utm_source", "utm_medium", "utm_campaign")}
            device = "mobile" if re.search(r"mobi|android|iphone", request.headers.get("User-Agent", ""), re.I) else "desktop"
            _record_landing(vid, str(raw.get("path") or "/")[:100], str(raw.get("ref") or "")[:300], utm,
                            (request.headers.get("CF-IPCountry") or "")[:2] or None, device, request.host)
        else:
            log_event(event, raw, visitor_id_=vid, user_id=uid, session_id=str(data.get("session_id") or "")[:40] or None)
        resp = app.make_response(("", 204))
        if new_vid:
            _set_cookie(resp, vid)
        return resp

    if rate_limit:
        track = rate_limit(max_requests=120, window_seconds=60)(track)
    app.add_url_rule("/api/track", "insights_track", track, methods=["POST"])

    try:  # visitor intelligence (profiles, prospect signals, conversion, alerts)
        import net365_visitor_intel
        net365_visitor_intel.register(app, admin_required)
    except Exception:
        log.exception("visitor intelligence not loaded")

    def signals():
        if not _consented() or _is_bot(request.headers.get("User-Agent", "")):
            return ("", 204)
        data = request.get_json(silent=True) or {}

        def i(k, lo=0, hi=100000):
            try:
                v = int(data.get(k))
                return v if lo <= v <= hi else None
            except (TypeError, ValueError):
                return None

        def s(k, n=60):
            v = data.get(k)
            return str(v)[:n] if isinstance(v, (str, int, float)) and v != "" else None

        tz, hour, dow = s("timezone", 64), None, None
        if tz:
            try:
                from zoneinfo import ZoneInfo
                now_local = datetime.now(ZoneInfo(tz))
                hour, dow = now_local.hour, now_local.weekday()
            except Exception:
                tz = None
        uid = None
        try:
            uid = get_user_id() if get_user_id else None
        except Exception:
            uid = None
        ensure_schema()
        c = _db()
        try:
            c.execute("""INSERT INTO visitor_signals (visitor_id, session_id, user_id, screen_w, screen_h, viewport_w, viewport_h,
                         timezone, language, touch, connection, referrer_class, utm_source, utm_medium, utm_campaign, local_hour, local_dow)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (visitor_id(), s("session_id", 40), uid, i("screen_w"), i("screen_h"), i("viewport_w"), i("viewport_h"),
                       tz, s("language", 20), 1 if i("touch", 0, 1) else 0, s("connection", 12),
                       s("referrer_class", 12), s("utm_source", 60), s("utm_medium", 60), s("utm_campaign", 60), hour, dow))
        finally:
            c.close()
        return ("", 204)

    if rate_limit:
        signals = rate_limit(max_requests=30, window_seconds=60)(signals)
    app.add_url_rule("/api/visitor/signals", "insights_signals", signals, methods=["POST"])

    def _static(name):
        def view():
            r = send_from_directory(BASE, name, mimetype="application/javascript")
            r.headers["Cache-Control"] = "no-cache"
            return r
        view.__name__ = "insights_static_" + name.replace(".", "_")
        return view

    app.add_url_rule("/n365_tracker.js", "insights_tracker_js", _static("n365_tracker.js"))
    app.add_url_rule("/admin_insights.js", "insights_admin_js", _static("admin_insights.js"))

    @app.route("/api/admin/insights/overview", methods=["GET"])
    @admin_required
    def insights_overview():
        try:
            return jsonify(build_overview(_days_arg()))
        except Exception as e:
            log.exception("insights overview failed")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/admin/insights/funnel", methods=["GET"])
    @admin_required
    def insights_funnel():
        try:
            return jsonify(build_funnel(_days_arg()))
        except Exception as e:
            log.exception("insights funnel failed")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/admin/insights/sources", methods=["GET"])
    @admin_required
    def insights_sources():
        try:
            return jsonify(build_sources(_days_arg()))
        except Exception as e:
            log.exception("insights sources failed")
            return jsonify({"success": False, "error": str(e)}), 500

    if os.getenv("INSIGHTS_PURGE", "true").strip().lower() in ("1", "true", "yes", "on"):
        threading.Thread(target=_purge_loop, daemon=True, name="insights-purge").start()
    log.info("Insights routes registered")

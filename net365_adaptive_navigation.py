"""NET365 NEURAL NAVIGATION: the adaptive menu ranking engine for the WhatsApp and Telegram bots.

One engine, many channels. It learns which services each customer (and everyone) uses, when, and how often they finish a
purchase, then returns an ORDER of service ids. The bots only render that order; they never decide it. If this module is
missing, slow or broken, the bots show the default menu, so it can never take the menu down.

What it does
    * records navigation events (tap, search, checkout, complete) with duplicate protection
    * ranks services per customer: personal use, global popularity, time of day / day of week, successful purchases,
      calendar demand (month end, Mondays, school periods) and the default order as a prior
    * stays calm: decay, a minimum-evidence rule, a margin a service must beat before it overtakes another, and a minimum
      time between rearrangements, so the menu does not jump every time the customer opens the bot
    * customer control: pin favourites, lock the arrangement, auto mode, reset, recommended services
    * admin control: weights, default order, promo boosts, emergency override, on/off, and stats

Privacy: events carry a short one-way hash of the chat id, never the number, name or message text.
Failed purchases never count as a preference: only a completed purchase scores a "complete".

Routes (bot secret)  POST /api/bot/nav/order  {wa}                       -> {order, mode, pins, fallback}
                     POST /api/bot/nav/event  {wa, service, event}       -> {ok}
                     POST /api/bot/nav/prefs  {wa, action, service?}     -> {mode, pins, order, recommended}
Routes (admin)       GET  /api/admin/nav/stats     GET/POST /api/admin/nav/config
"""
import hashlib
import json
import logging
import math
import re
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import jsonify, request

log = logging.getLogger(__name__)

# The eight main-menu slots, in the default order, and the extra services that are learned about but not ranked into the grid.
POOL = ["AIRTIME", "DATA", "UTILITY_ELECTRICITY", "UTILITY_CABLE", "INVITE", "EDU", "HISTORY", "ASKNET"]
EXTRA = ["GIFTCARD", "SPENDING", "SCHEDULE", "INTL", "SAVED", "BIZ", "REPORTS"]
ALL = POOL + EXTRA
EVENT_WEIGHT = {"tap": 1.0, "search": 1.5, "checkout": 2.0, "complete": 4.0}
MAX_PINS = 3

CFG_DEFAULT = {
    "enabled": True,              # master switch: off = everybody sees the default order
    "auto_default": True,         # new customers start in auto mode
    "default_order": POOL,
    "override_order": [],         # emergency override: when set, everybody sees exactly this order
    "w_prior": 0.25, "w_user": 1.0, "w_global": 0.5, "w_time": 0.35, "w_success": 0.4, "w_pred": 0.3,
    "half_life_user_days": 14, "half_life_global_days": 7,
    "min_events": 5,              # fewer personal events than this: treated as a new customer (cold start)
    "margin": 0.15,               # a service must beat the one above it by this much to overtake it
    "min_rearrange_hours": 12,    # the order is recomputed at most this often per customer
    "promo": {},                  # {"DATA": 0.2}: promotional priority, capped at 0.3
}

_db = None
_lock = threading.Lock()
_cfg_cache = {"at": 0.0, "v": None}
_glob_cache = {"at": 0.0, "v": None}
_order_cache = {}
LAGOS = timezone(timedelta(hours=1))


def _conn():
    return _db.get_db_connection()


def _now():
    return datetime.now(timezone.utc)


def _who(wa):
    return hashlib.sha256(("nav|" + re.sub(r"\D", "", str(wa or ""))).encode()).hexdigest()[:20]


def _ensure_schema():
    c = _conn()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS nav_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT NOT NULL, service TEXT NOT NULL, event TEXT NOT NULL,
            ts INTEGER NOT NULL, dow INTEGER NOT NULL, band INTEGER NOT NULL)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_nav_events_who ON nav_events(who, ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_nav_events_ts ON nav_events(ts)")
        c.execute("""CREATE TABLE IF NOT EXISTS nav_prefs (
            who TEXT PRIMARY KEY, mode TEXT NOT NULL DEFAULT 'auto', pins TEXT NOT NULL DEFAULT '[]',
            last_order TEXT, last_rearranged INTEGER, updated INTEGER, reset_at INTEGER NOT NULL DEFAULT 0)""")
        try:
            c.execute("ALTER TABLE nav_prefs ADD COLUMN reset_at INTEGER NOT NULL DEFAULT 0")
        except Exception:
            pass
        c.execute("CREATE TABLE IF NOT EXISTS nav_rearrange_log (ts INTEGER NOT NULL, moved INTEGER NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS nav_config (k TEXT PRIMARY KEY, v TEXT)")
        c.commit()
    finally:
        c.close()


# ----------------------------------------------------------------------------- config
def get_config(force=False):
    if not force and _cfg_cache["v"] is not None and time.time() - _cfg_cache["at"] < 60:
        return _cfg_cache["v"]
    cfg = json.loads(json.dumps(CFG_DEFAULT))
    try:
        c = _conn()
        try:
            r = c.execute("SELECT v FROM nav_config WHERE k = 'config'").fetchone()
        finally:
            c.close()
        if r and r[0]:
            saved = json.loads(r[0])
            if isinstance(saved, dict):
                cfg.update({k: v for k, v in saved.items() if k in cfg})
    except Exception:
        log.debug("nav: config read failed", exc_info=True)
    cfg["default_order"] = _clean_order(cfg.get("default_order")) or list(POOL)
    cfg["override_order"] = _clean_order(cfg.get("override_order"), partial=True)
    _cfg_cache.update(at=time.time(), v=cfg)
    return cfg


def _clean_order(order, partial=False):
    """Only known main-menu services, no duplicates. A complete order lists all eight; a partial one (override) may list fewer."""
    out = []
    for s in order or []:
        s = str(s).upper()
        if s in POOL and s not in out:
            out.append(s)
    if not partial and out:
        out += [s for s in POOL if s not in out]
    return out


def _save_config(patch):
    cfg = dict(get_config(force=True))
    for k, v in patch.items():
        if k not in CFG_DEFAULT:
            continue
        d = CFG_DEFAULT[k]
        if isinstance(d, bool):
            cfg[k] = bool(v)
        elif isinstance(d, (int, float)) and not isinstance(d, bool):
            cfg[k] = max(0.0, float(v)) if isinstance(d, float) else max(0, int(v))
        elif k == "promo" and isinstance(v, dict):
            cfg[k] = {str(s).upper(): min(0.3, max(0.0, float(x))) for s, x in v.items() if str(s).upper() in POOL}
        elif k in ("default_order", "override_order") and isinstance(v, list):
            cfg[k] = _clean_order(v, partial=(k == "override_order"))
    c = _conn()
    try:
        c.execute("INSERT INTO nav_config (k, v) VALUES ('config', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (json.dumps(cfg),))
        c.commit()
    finally:
        c.close()
    _cfg_cache["v"] = None
    _glob_cache["v"] = None
    _order_cache.clear()
    return get_config(force=True)


# ----------------------------------------------------------------------------- learning
def _band(hour):
    return 0 if hour < 6 else 1 if hour < 12 else 2 if hour < 18 else 3


def record_event(wa, service, event="tap"):
    """Returns True when stored. Ignores unknown services/events and an identical event from the same chat within 5 seconds."""
    service, event = str(service or "").upper(), str(event or "tap").lower()
    if service not in ALL or event not in EVENT_WEIGHT:
        return False
    who = _who(wa)
    now = _now()
    loc = now.astimezone(LAGOS)
    ts = int(now.timestamp())
    c = _conn()
    try:
        dup = c.execute("SELECT 1 FROM nav_events WHERE who = ? AND service = ? AND event = ? AND ts >= ?", (who, service, event, ts - 5)).fetchone()
        if dup:
            return False
        c.execute("INSERT INTO nav_events (who, service, event, ts, dow, band) VALUES (?,?,?,?,?,?)", (who, service, event, ts, loc.weekday(), _band(loc.hour)))
        if ts % 97 == 0:  # light housekeeping: keep 120 days
            c.execute("DELETE FROM nav_events WHERE ts < ?", (ts - 120 * 86400,))
        c.commit()
    finally:
        c.close()
    _order_cache.pop(who, None)
    return True


def _norm(d):
    m = max(d.values()) if d else 0
    return {k: (v / m if m > 0 else 0.0) for k, v in d.items()}


def _global_stats(cfg):
    """Everyone's popularity and time pattern. Cached 15 minutes: it changes slowly and is the same for every customer."""
    if _glob_cache["v"] is not None and time.time() - _glob_cache["at"] < 900:
        return _glob_cache["v"]
    now = int(time.time())
    hl = max(1.0, float(cfg["half_life_global_days"]))
    pop, by_dow, by_band, total, dow_tot, band_tot = {}, {}, {}, 0, {}, {}
    c = _conn()
    try:
        rows = c.execute("SELECT service, event, ts, dow, band FROM nav_events WHERE ts >= ? AND service IN (%s)" % ",".join("?" * len(POOL)),
                         (now - 60 * 86400, *POOL)).fetchall()
    finally:
        c.close()
    for s, ev, ts, dow, band in rows:
        w = EVENT_WEIGHT.get(ev, 1.0) * 0.5 ** (((now - ts) / 86400.0) / hl)
        pop[s] = pop.get(s, 0.0) + w
        total += 1
        by_dow[(s, dow)] = by_dow.get((s, dow), 0) + 1
        by_band[(s, band)] = by_band.get((s, band), 0) + 1
        dow_tot[dow] = dow_tot.get(dow, 0) + 1
        band_tot[band] = band_tot.get(band, 0) + 1
        by_dow[("*", s)] = by_dow.get(("*", s), 0) + 1
    v = {"pop": _norm(pop), "by_dow": by_dow, "by_band": by_band, "dow_tot": dow_tot, "band_tot": band_tot, "total": total}
    _glob_cache.update(at=time.time(), v=v)
    return v


def _time_affinity(g, svc, dow, band):
    """How much busier than usual this service is on this weekday and at this time of day. Roughly -0.5 .. +1; 0 without enough data."""
    tot = g["total"]
    n_s = g["by_dow"].get(("*", svc), 0)
    if tot < 60 or n_s < 8:
        return 0.0
    out = []
    for cnt, ctot in ((g["by_dow"].get((svc, dow), 0), g["dow_tot"].get(dow, 0)), (g["by_band"].get((svc, band), 0), g["band_tot"].get(band, 0))):
        if ctot < 20:
            continue
        ratio = (cnt / ctot) / (n_s / tot)
        out.append(max(-0.5, min(1.0, ratio - 1.0)))
    return sum(out) / len(out) if out else 0.0


def _predict(now_local):
    """Calendar demand that recurs: salary/month end, Mondays, school registration. Boosts are small and only nudge."""
    d, m, wd = now_local.day, now_local.month, now_local.weekday()
    b = {s: 0.0 for s in POOL}
    if wd == 0:
        b["AIRTIME"] += 1.0                         # airtime demand rises on Mondays
    if d >= 25 or d <= 3:
        b["UTILITY_ELECTRICITY"] += 1.0             # month end / salary week
        b["UTILITY_CABLE"] += 0.6
        b["AIRTIME"] += 0.3
    if m in (1, 2, 3, 6, 7, 8, 9):
        b["EDU"] += 0.6 if m in (1, 2, 3, 6, 7) else 0.3   # exam and school registration periods
    if wd >= 5:
        b["DATA"] += 0.3
    if (m == 12 and d >= 10) or (m == 11 and d >= 20):
        b["INVITE"] += 0.15                         # festive sharing
    return b


def _user_stats(who, cfg, since=0):
    now = int(time.time())
    hl = max(1.0, float(cfg["half_life_user_days"]))
    pts, taps, comps, n = {}, {}, {}, 0
    c = _conn()
    try:
        rows = c.execute("SELECT service, event, ts FROM nav_events WHERE who = ? AND ts >= ?", (who, max(now - 90 * 86400, since))).fetchall()
    finally:
        c.close()
    for s, ev, ts in rows:
        if s not in POOL:
            continue
        pts[s] = pts.get(s, 0.0) + EVENT_WEIGHT.get(ev, 1.0) * 0.5 ** (((now - ts) / 86400.0) / hl)
        if ev == "tap":
            taps[s] = taps.get(s, 0) + 1
            n += 1
        elif ev == "complete":
            comps[s] = comps.get(s, 0) + 1
    return _norm(pts), taps, comps, n


def _scores(who, cfg, now_local, since=0):
    g = _global_stats(cfg)
    u, taps, comps, n = _user_stats(who, cfg, since)
    alpha = 0.0 if n < cfg["min_events"] else min(1.0, n / 20.0)     # cold start: lean on everyone else
    pred = _predict(now_local)
    default = cfg["default_order"]
    band = _band(now_local.hour)
    out = {}
    for i, s in enumerate(POOL):
        prior = (len(default) - default.index(s)) / float(len(default)) if s in default else 0.0
        conv = comps.get(s, 0) / (taps.get(s, 0) + 1.0)             # completed purchases per tap: failures never count
        promo = min(0.3, float(cfg["promo"].get(s, 0.0)))
        out[s] = (cfg["w_prior"] * prior + alpha * cfg["w_user"] * u.get(s, 0.0) + cfg["w_global"] * g["pop"].get(s, 0.0)
                  + cfg["w_time"] * _time_affinity(g, s, now_local.weekday(), band) + alpha * cfg["w_success"] * min(1.0, conv)
                  + cfg["w_pred"] * pred[s] + promo)
    return out, n


def _stabilise(last, score, margin):
    """Start from the order the customer already sees; a service only overtakes the one above it when it is clearly ahead."""
    order = [s for s in last if s in POOL] + [s for s in POOL if s not in last]
    for _ in range(len(order)):
        moved = False
        for i in range(1, len(order)):
            a, b = order[i - 1], order[i]
            if score[b] > score[a] + margin * max(abs(score[a]), 0.05):
                order[i - 1], order[i] = b, a
                moved = True
        if not moved:
            break
    return order


# ----------------------------------------------------------------------------- per-customer order
def _get_prefs(who, cfg):
    c = _conn()
    try:
        r = c.execute("SELECT mode, pins, last_order, last_rearranged, reset_at FROM nav_prefs WHERE who = ?", (who,)).fetchone()
    finally:
        c.close()
    if not r:
        return {"mode": "auto" if cfg["auto_default"] else "locked", "pins": [], "last_order": None, "last_rearranged": 0, "reset_at": 0}
    try:
        pins = [p for p in json.loads(r[1] or "[]") if p in POOL][:MAX_PINS]
    except Exception:
        pins = []
    try:
        last = [p for p in json.loads(r[2] or "null") or [] if p in POOL]
    except Exception:
        last = []
    return {"mode": r[0] or "auto", "pins": pins, "last_order": last or None, "last_rearranged": int(r[3] or 0), "reset_at": int(r[4] or 0)}


def _put_prefs(who, mode=None, pins=None, last_order=None, rearranged=None):
    c = _conn()
    try:
        c.execute("INSERT OR IGNORE INTO nav_prefs (who, updated) VALUES (?, ?)", (who, int(time.time())))
        if mode is not None:
            c.execute("UPDATE nav_prefs SET mode = ? WHERE who = ?", (mode, who))
        if pins is not None:
            c.execute("UPDATE nav_prefs SET pins = ? WHERE who = ?", (json.dumps(pins), who))
        if last_order is not None:
            c.execute("UPDATE nav_prefs SET last_order = ? WHERE who = ?", (json.dumps(last_order), who))
        if rearranged is not None:
            c.execute("UPDATE nav_prefs SET last_rearranged = ? WHERE who = ?", (rearranged, who))
        c.execute("UPDATE nav_prefs SET updated = ? WHERE who = ?", (int(time.time()), who))
        c.commit()
    finally:
        c.close()


def order_for(wa):
    """The service order for this chat. Never raises: any problem returns the default order with fallback=True."""
    cfg = get_config()
    try:
        if not cfg["enabled"]:
            return {"order": list(cfg["default_order"]), "mode": "off", "pins": [], "fallback": True}
        if cfg["override_order"]:
            o = cfg["override_order"] + [s for s in cfg["default_order"] if s not in cfg["override_order"]]
            return {"order": o, "mode": "override", "pins": [], "fallback": False}
        who = _who(wa)
        hit = _order_cache.get(who)
        if hit and time.time() - hit[0] < 600:
            return hit[1]
        prefs = _get_prefs(who, cfg)
        last = prefs["last_order"] or list(cfg["default_order"])
        now = time.time()
        if prefs["mode"] == "locked":
            base, rearranged = last, False
        elif now - prefs["last_rearranged"] < cfg["min_rearrange_hours"] * 3600 and prefs["last_order"]:
            base, rearranged = last, False                                  # calm: not time to move things yet
        else:
            sc, _n = _scores(who, cfg, _now().astimezone(LAGOS), prefs["reset_at"])
            base = _stabilise(last, sc, cfg["margin"])
            rearranged = base != last
            _put_prefs(who, last_order=base, rearranged=int(now))
            if rearranged:
                c = _conn()
                try:
                    c.execute("INSERT INTO nav_rearrange_log (ts, moved) VALUES (?, 1)", (int(now),)); c.commit()
                finally:
                    c.close()
        pins = prefs["pins"]
        order = pins + [s for s in base if s not in pins]
        res = {"order": order, "mode": prefs["mode"], "pins": pins, "fallback": False}
        _order_cache[who] = (time.time(), res)
        if len(_order_cache) > 20000:
            _order_cache.clear()
        return res
    except Exception:
        log.exception("nav: order failed, using the default menu")
        return {"order": list(cfg["default_order"]), "mode": "auto", "pins": [], "fallback": True}


def recommended_for(wa, limit=2):
    """Services worth a look: ones the customer rarely uses that others do, plus simple cross-sell rules. Never pushes a pinned one."""
    cfg = get_config()
    who = _who(wa)
    try:
        prefs = _get_prefs(who, cfg)
        u, taps, comps, n = _user_stats(who, cfg, prefs["reset_at"])
        g = _global_stats(cfg)
        recs = []
        if u.get("AIRTIME", 0) >= 0.5 and not taps.get("DATA"):
            recs.append(("DATA", "You top up airtime often. Data bundles can save you money."))
        if taps.get("UTILITY_ELECTRICITY") and not taps.get("UTILITY_CABLE") and len(recs) < limit:
            recs.append(("UTILITY_CABLE", "You pay electricity here. You can pay your TV subscription the same way."))
        for s in sorted(POOL, key=lambda x: -g["pop"].get(x, 0)):
            if len(recs) >= limit:
                break
            if s not in taps and s not in prefs["pins"] and s not in [r[0] for r in recs] and g["pop"].get(s, 0) > 0.3:
                recs.append((s, "Popular with Net365 customers."))
        return [{"service": s, "why": w} for s, w in recs[:limit] if s not in prefs["pins"]]
    except Exception:
        log.debug("nav: recommendations failed", exc_info=True)
        return []


def apply_action(wa, action, service=None):
    cfg = get_config()
    who = _who(wa)
    prefs = _get_prefs(who, cfg)
    service = str(service or "").upper()
    if action == "pin":
        if service not in POOL:
            return {"ok": False, "error": "unknown_service"}
        pins = [p for p in prefs["pins"] if p != service]
        if len(pins) >= MAX_PINS:
            return {"ok": False, "error": "too_many_pins", "max": MAX_PINS}
        _put_prefs(who, pins=pins + [service])
    elif action == "unpin":
        _put_prefs(who, pins=[p for p in prefs["pins"] if p != service])
    elif action == "lock":
        cur = order_for(wa)
        _put_prefs(who, mode="locked", last_order=[s for s in cur["order"] if s not in prefs["pins"]] or None)
    elif action == "auto":
        _put_prefs(who, mode="auto", rearranged=0)
    elif action == "reset":
        now = int(time.time())
        c = _conn()
        try:   # back to the default menu, auto mode, no pins; what was learned before this moment is no longer used
            c.execute("INSERT OR REPLACE INTO nav_prefs (who, mode, pins, last_order, last_rearranged, updated, reset_at) VALUES (?,?,?,?,?,?,?)",
                      (who, "auto" if cfg["auto_default"] else "locked", "[]", json.dumps(cfg["default_order"]), now, now, now))
            c.commit()
        finally:
            c.close()
    elif action != "get":
        return {"ok": False, "error": "unknown_action"}
    _order_cache.pop(who, None)
    cur = order_for(wa)
    return {"ok": True, "mode": cur["mode"], "pins": cur["pins"], "order": cur["order"], "recommended": recommended_for(wa)}


# ----------------------------------------------------------------------------- admin analytics
def stats():
    now = int(time.time())
    out = {"events_7d": 0, "popular": [], "growing": [], "declining": [], "conversion": {}, "rearrangements_7d": 0, "customers_7d": 0,
           "by_day": {}, "personalised_customers": 0, "locked_customers": 0}
    c = _conn()
    try:
        def counts(a, b):
            d = {}
            for s, n in c.execute("SELECT service, COUNT(*) FROM nav_events WHERE ts >= ? AND ts < ? AND event IN ('tap','search') GROUP BY service", (a, b)).fetchall():
                d[s] = n
            return d
        cur, prev = counts(now - 7 * 86400, now + 1), counts(now - 14 * 86400, now - 7 * 86400)
        out["events_7d"] = int(c.execute("SELECT COUNT(*) FROM nav_events WHERE ts >= ?", (now - 7 * 86400,)).fetchone()[0])
        out["customers_7d"] = int(c.execute("SELECT COUNT(DISTINCT who) FROM nav_events WHERE ts >= ?", (now - 7 * 86400,)).fetchone()[0])
        out["popular"] = [{"service": s, "taps": n} for s, n in sorted(cur.items(), key=lambda x: -x[1])]
        growth = []
        for s in set(cur) | set(prev):
            a, b = cur.get(s, 0), prev.get(s, 0)
            growth.append({"service": s, "this_week": a, "last_week": b, "change_pct": round((a - b) * 100.0 / b, 1) if b else None})
        out["growing"] = sorted([g for g in growth if g["this_week"] > g["last_week"]], key=lambda g: -(g["this_week"] - g["last_week"]))[:5]
        out["declining"] = sorted([g for g in growth if g["this_week"] < g["last_week"]], key=lambda g: g["this_week"] - g["last_week"])[:5]
        for s, t, k in c.execute("SELECT service, SUM(CASE WHEN event='tap' THEN 1 ELSE 0 END), SUM(CASE WHEN event='complete' THEN 1 ELSE 0 END) "
                                 "FROM nav_events WHERE ts >= ? GROUP BY service", (now - 7 * 86400,)).fetchall():
            out["conversion"][s] = {"taps": int(t or 0), "completed": int(k or 0), "rate_pct": round((k or 0) * 100.0 / t, 1) if t else None}
        out["rearrangements_7d"] = int(c.execute("SELECT COUNT(*) FROM nav_rearrange_log WHERE ts >= ?", (now - 7 * 86400,)).fetchone()[0])
        for dow, n in c.execute("SELECT dow, COUNT(*) FROM nav_events WHERE ts >= ? GROUP BY dow", (now - 28 * 86400,)).fetchall():
            out["by_day"][["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][dow]] = n
        out["personalised_customers"] = int(c.execute("SELECT COUNT(*) FROM nav_prefs").fetchone()[0])
        out["locked_customers"] = int(c.execute("SELECT COUNT(*) FROM nav_prefs WHERE mode = 'locked'").fetchone()[0])
    finally:
        c.close()
    cfg = get_config()
    out["global_ranking"] = _scores("global-view", cfg, _now().astimezone(LAGOS))[0]
    out["config"] = cfg
    return out


# ----------------------------------------------------------------------------- routes
def init_adaptive_navigation(app, db, bot_required, admin_required=None):
    global _db
    _db = db
    _ensure_schema()

    @app.post("/api/bot/nav/order")
    @bot_required
    def nav_order():
        return jsonify(success=True, **order_for((request.get_json(silent=True) or {}).get("wa")))

    @app.post("/api/bot/nav/event")
    @bot_required
    def nav_event():
        d = request.get_json(silent=True) or {}
        items = d.get("events") if isinstance(d.get("events"), list) else [d]
        n = 0
        for it in items[:10]:
            if isinstance(it, dict) and record_event(d.get("wa"), it.get("service"), it.get("event") or "tap"):
                n += 1
        return jsonify(success=True, stored=n)

    @app.post("/api/bot/nav/prefs")
    @bot_required
    def nav_prefs():
        d = request.get_json(silent=True) or {}
        r = apply_action(d.get("wa"), str(d.get("action") or "get"), d.get("service"))
        return jsonify(success=bool(r.get("ok")), **r), (200 if r.get("ok") else 400)

    if admin_required:
        @app.get("/api/admin/nav/stats")
        @admin_required
        def nav_admin_stats():
            return jsonify(success=True, **stats())

        @app.route("/api/admin/nav/config", methods=["GET", "POST"])
        @admin_required
        def nav_admin_config():
            if request.method == "POST":
                return jsonify(success=True, config=_save_config(request.get_json(silent=True) or {}))
            return jsonify(success=True, config=get_config(force=True))

    log.info("Neural Navigation ready (/api/bot/nav/order|event|prefs)")

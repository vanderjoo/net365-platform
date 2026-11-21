"""
Net365 Ad Engine, Phase 4: Manual / Assisted / Auto modes and a careful learning loop.

The three modes (set separately for the success page and for receipt emails)
  MANUAL    the engine does exactly what Phase 3 does: your priorities and rules decide. Nothing is analysed or changed.
  ASSISTED  the engine studies the click data and QUEUES suggestions (shift an ad up/down, pause a weak ad, aim an ad at the
            transaction type it works best on). Nothing changes until you press Apply.
  AUTO      the engine applies small priority shifts by itself, inside the limits below. Pausing an ad is applied only if you
            allow it ("auto_pause"); aiming an ad at one transaction type always waits for you. Every change is logged and
            can be undone with one click.

How it learns (and why it will not fool itself)
  * It compares each ad with the OTHER ads of the same kind (Boost, paid Dominant, paid Basic) on the same surface, over the last
    N days. Click rate is compared with a two-proportion z-test; an ad is moved only when the difference is statistically clear.
  * An ad needs a minimum number of views before it is judged, and so does the rest of its group.
  * NEW ads get a trial: until they reach the trial views they get a small boost so every new ad is actually seen.
  * A share of impressions ignores learning on purpose (exploration), so a weak start never buries an ad for good.
  * Shifts are small steps per run, and capped below the gap between source priorities, so learning can NEVER put a Boost ad
    above a paid ad, or a Basic above a Dominant. Learning changes the order inside a kind, never what anyone paid for.
  * An ad can be frozen: learning leaves it alone.

Known limit: some email security scanners open links automatically, which can inflate email clicks. Treat email learning
with more caution than success-page learning; keep it in Assisted until you trust the numbers.

Installed automatically by init_adserve(); nothing to add in app.py.
"""
from __future__ import annotations

import json
import logging
import math
import threading
import time
import zlib
from datetime import datetime, timedelta, timezone

from flask import jsonify, request

logger = logging.getLogger(__name__)

_ready = False
_cache = {"t": 0.0, "s": None, "st_t": 0.0, "st": None, "last": 0.0}
_run_lock = threading.Lock()

MODES = ("manual", "assisted", "auto")
SURFACES = ("success", "email")

DEFAULTS = {
    "mode_success": "manual",
    "mode_email": "manual",
    "window_days": "14",        # how far back the analysis looks
    "trial_views": "100",       # an ad below this many views in the window is still on trial
    "min_views": "200",         # views an ad (and the rest of its group) need before it is judged
    "max_shift": "20",          # most priority points learning may add or remove (also capped below the tier gap)
    "max_step": "5",            # most points one run may move an ad
    "explore_pct": "15",        # % of impressions that ignore learning, so every ad keeps being seen
    "confidence_z": "1.64",     # 1.28 = 90%, 1.64 = 95%, 2.33 = 99% (one-sided)
    "auto_pause": "0",          # may Auto mode pause a clearly failing ad?
    "interval_minutes": "60",   # how often the background check may run
}


# ------------------------------------------------------------------ plumbing
def _se():
    import net365_adserve as se
    return se


def _conn():
    return _se()._conn()


def _commit(c):
    return _se()._commit(c)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _ts(dt=None):
    return (dt or _now()).strftime("%Y-%m-%d %H:%M:%S")


def _schema():
    c = _conn()
    try:
        c.execute("CREATE TABLE IF NOT EXISTS ad_learn_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        c.execute("""CREATE TABLE IF NOT EXISTS ad_learn_state (
            source TEXT NOT NULL, ad_id INTEGER NOT NULL, surface TEXT NOT NULL,
            bonus REAL NOT NULL DEFAULT 0, frozen INTEGER NOT NULL DEFAULT 0, updated_at TEXT,
            PRIMARY KEY (source, ad_id, surface))""")
        c.execute("""CREATE TABLE IF NOT EXISTS ad_learn_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, surface TEXT NOT NULL,
            source TEXT NOT NULL, ad_id INTEGER NOT NULL,
            kind TEXT NOT NULL,                 -- shift | pause | target
            reason TEXT, detail TEXT,           -- detail = JSON with the numbers and what to restore on undo
            prev_value REAL, new_value REAL,
            status TEXT NOT NULL,               -- pending | applied | auto_applied | dismissed | undone | superseded
            decided_by TEXT, decided_at TEXT)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_adlearn_log ON ad_learn_log(status, id)")
        _commit(c)
    finally:
        c.close()


# ------------------------------------------------------------------ settings
def settings(force=False):
    if not force and _cache["s"] is not None and time.time() - _cache["t"] < 5:
        return _cache["s"]
    s = dict(DEFAULTS)
    try:
        c = _conn()
        try:
            for r in c.execute("SELECT key, value FROM ad_learn_settings").fetchall():
                if r["key"] in DEFAULTS:
                    s[r["key"]] = r["value"]
        finally:
            c.close()
    except Exception:
        logger.warning("adlearn: settings unreadable; defaults used", exc_info=True)
    _cache.update(t=time.time(), s=s)
    return s


def _f(key, default):
    try:
        return float(settings().get(key, default))
    except (TypeError, ValueError):
        return default


def mode(surface):
    m = str(settings().get("mode_" + surface, "manual"))
    return m if m in MODES else "manual"


_RANGES = {"window_days": (1, 90), "trial_views": (0, 100000), "min_views": (10, 100000), "max_shift": (0, 100),
           "max_step": (0, 50), "explore_pct": (0, 100), "confidence_z": (1.0, 4.0), "interval_minutes": (5, 1440)}


def save_settings(updates):
    saved = {}
    for k, v in (updates or {}).items():
        if k not in DEFAULTS:
            return False, f"Unknown setting: {k}", {}
        if k.startswith("mode_"):
            if str(v) not in MODES:
                return False, f"{k} must be manual, assisted or auto", {}
            v = str(v)
        elif k == "auto_pause":
            v = "1" if str(v).lower() in ("1", "true", "yes", "on") else "0"
        else:
            try:
                n = float(v)
            except (TypeError, ValueError):
                return False, f"{k} must be a number", {}
            lo, hi = _RANGES[k]
            if n < lo or n > hi:
                return False, f"{k} must be between {lo} and {hi}", {}
            v = str(int(n)) if n == int(n) else str(n)
        saved[k] = v
    c = _conn()
    try:
        for k, v in saved.items():
            c.execute("INSERT INTO ad_learn_settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))
        _commit(c)
    finally:
        c.close()
    _cache["t"] = 0.0
    return True, "", saved


def cap():
    """Most points learning may move an ad: the admin's max_shift, kept strictly below the smallest gap between source priorities
    so learning can never lift an ad over a higher kind."""
    mx = _f("max_shift", 20)
    try:
        vals = sorted(set(float(x) for x in _se()._priority().values()))
        gaps = [b - a for a, b in zip(vals, vals[1:]) if b - a > 0]
        if gaps:
            mx = min(mx, max(0.0, min(gaps) / 2.0 - 0.5))      # two ads can each move toward the other, so keep half the gap
    except Exception:
        pass
    return max(0.0, mx)


# ------------------------------------------------------------------ state (learned bonus per ad per surface)
def _states(force=False):
    if not force and _cache["st"] is not None and time.time() - _cache["st_t"] < 5:
        return _cache["st"]
    out = {}
    try:
        c = _conn()
        try:
            for r in c.execute("SELECT * FROM ad_learn_state").fetchall():
                out[(r["surface"], r["source"], int(r["ad_id"]))] = dict(r)
        finally:
            c.close()
    except Exception:
        logger.warning("adlearn: state unreadable", exc_info=True)
    _cache.update(st=out, st_t=time.time())
    return out


def _set_state(surface, source, ad_id, bonus=None, frozen=None):
    c = _conn()
    try:
        cur = c.execute("SELECT bonus, frozen FROM ad_learn_state WHERE surface=? AND source=? AND ad_id=?", (surface, source, ad_id)).fetchone()
        b = float(cur["bonus"]) if cur else 0.0
        fz = int(cur["frozen"]) if cur else 0
        b = b if bonus is None else float(bonus)
        fz = fz if frozen is None else (1 if frozen else 0)
        c.execute("INSERT INTO ad_learn_state(source, ad_id, surface, bonus, frozen, updated_at) VALUES(?,?,?,?,?,?) "
                  "ON CONFLICT(source, ad_id, surface) DO UPDATE SET bonus=excluded.bonus, frozen=excluded.frozen, updated_at=excluded.updated_at",
                  (source, ad_id, surface, b, fz, _ts()))
        _commit(c)
    finally:
        c.close()
    _cache["st_t"] = 0.0


def serving_bonus(surface, key, ref=""):
    """Points the learning loop adds to an ad's score for this one view. 0 in Manual, for frozen ads, and for the exploration
    share of impressions. New ads on trial get a small lift so they are actually seen. Never raises."""
    try:
        if not _ready or mode(surface) == "manual":
            return 0.0
        source, ad_id = key
        st = _states().get((surface, source, int(ad_id)))
        if st and st["frozen"]:
            return 0.0
        if (zlib.crc32(f"{ref}|explore|{key}".encode()) % 1000) / 10.0 < _f("explore_pct", 15):
            return 0.0
        bonus = float(st["bonus"]) if st else 0.0
        if _on_trial(surface, source, int(ad_id)):
            bonus += cap() / 2.0
        return max(-cap(), min(cap(), bonus))
    except Exception:
        return 0.0


_trial_cache = {}


def _on_trial(surface, source, ad_id):
    """Fewer than trial_views impressions in the window. Cached for a minute; the serve path must stay cheap."""
    k = (surface, source, ad_id)
    hit = _trial_cache.get(k)
    if hit and time.time() - hit[0] < 60:
        return hit[1]
    tv = int(_f("trial_views", 100))
    if tv <= 0:
        return False
    c = _conn()
    try:
        since = _ts(_now() - timedelta(days=int(_f("window_days", 14))))
        n = c.execute("SELECT COUNT(*) FROM ad_events WHERE surface=? AND ad_source=? AND ad_id=? AND event='impression' AND ts >= ?",
                      (surface, source, ad_id, since)).fetchone()[0]
    finally:
        c.close()
    _trial_cache[k] = (time.time(), n < tv)
    return n < tv


# ------------------------------------------------------------------ statistics
def _z(k1, n1, k2, n2):
    """Two-proportion z. Positive when group 1 clicks more. 0 when it cannot be computed."""
    if n1 <= 0 or n2 <= 0:
        return 0.0
    p = (k1 + k2) / float(n1 + n2)
    if p <= 0 or p >= 1:
        return 0.0
    se = math.sqrt(p * (1 - p) * (1.0 / n1 + 1.0 / n2))
    return (k1 / float(n1) - k2 / float(n2)) / se if se else 0.0


def _titles(c):
    t = {}
    for r in c.execute("SELECT id, title FROM boost_ads").fetchall():
        t[("boost", r["id"])] = r["title"]
    for r in c.execute("SELECT id, title, campaign_tier FROM receipt_promos WHERE source='sponsored'").fetchall():
        t[("promo", r["id"])] = r["title"]
    return t


def _tiers(c):
    t = {}
    for r in c.execute("SELECT id, campaign_tier FROM receipt_promos WHERE source='sponsored'").fetchall():
        t[r["id"]] = r["campaign_tier"] or "basic"
    return t


def ad_stats(surface):
    """Per-ad numbers for the window, with each ad's comparison against the rest of its kind."""
    since = _ts(_now() - timedelta(days=int(_f("window_days", 14))))
    minv, zthr = int(_f("min_views", 200)), _f("confidence_z", 1.64)
    c = _conn()
    try:
        titles, tiers = _titles(c), _tiers(c)
        rows = c.execute("SELECT ad_source, ad_id, SUM(event='impression') v, SUM(event='click') k FROM ad_events "
                         "WHERE surface=? AND ad_source IN ('boost','promo') AND ts >= ? GROUP BY ad_source, ad_id", (surface, since)).fetchall()
    finally:
        c.close()
    ads = []
    for r in rows:
        v, k = int(r["v"] or 0), min(int(r["k"] or 0), int(r["v"] or 0))
        src, aid = r["ad_source"], int(r["ad_id"])
        kind = "boost" if src == "boost" else "paid_" + tiers.get(aid, "basic")
        ads.append({"source": src, "ad_id": aid, "kind": kind, "title": titles.get((src, aid), f"#{aid}"), "views": v, "clicks": k})
    states = _states(force=True)
    for a in ads:
        grp = [x for x in ads if x["kind"] == a["kind"]]
        gv, gk = sum(x["views"] for x in grp), sum(x["clicks"] for x in grp)
        rv, rk = gv - a["views"], gk - a["clicks"]
        a["ctr"] = (a["clicks"] / a["views"]) if a["views"] else None
        a["rest_ctr"] = (rk / rv) if rv else None
        a["ratio"] = (a["ctr"] / a["rest_ctr"]) if (a["ctr"] is not None and a["rest_ctr"]) else None
        a["z"] = round(_z(a["clicks"], a["views"], rk, rv), 2) if rv else 0.0
        a["judged"] = a["views"] >= minv and rv >= minv
        a["trial"] = a["views"] < int(_f("trial_views", 100))
        a["significant"] = a["judged"] and abs(a["z"]) >= zthr
        st = states.get((surface, a["source"], a["ad_id"]))
        a["bonus"] = float(st["bonus"]) if st else 0.0
        a["frozen"] = bool(st and st["frozen"])
    return sorted(ads, key=lambda x: (x["kind"], -x["views"]))


def _segment_target(surface, a, since):
    """Does this ad do clearly better on one transaction type? Returns (tx_type, ratio, z, views) or None."""
    c = _conn()
    try:
        rows = c.execute("SELECT tx_type, SUM(event='impression') v, SUM(event='click') k FROM ad_events WHERE surface=? AND ad_source=? "
                         "AND ad_id=? AND ts >= ? AND tx_type IS NOT NULL GROUP BY tx_type", (surface, a["source"], a["ad_id"], since)).fetchall()
    finally:
        c.close()
    segs = [(r["tx_type"], int(r["v"] or 0), int(r["k"] or 0)) for r in rows]
    tv, tk = sum(s[1] for s in segs), sum(s[2] for s in segs)
    best = None
    for t, v, k in segs:
        rv, rk = tv - v, tk - k
        if v < max(30, int(_f("min_views", 200)) // 2) or rv < max(30, int(_f("min_views", 200)) // 2):
            continue
        z = _z(k, v, rk, rv)
        p_rest = rk / rv if rv else 0
        ratio = (k / v) / p_rest if p_rest else 0
        if z >= _f("confidence_z", 1.64) and ratio >= 2.0 and (not best or z > best[2]):
            best = (t, round(ratio, 2), round(z, 2), v)
    return best


# ------------------------------------------------------------------ proposals, applying, undoing
def _rule_for(source, ad_id):
    return _se().rules(force=True).get((source, int(ad_id))) or {}


def _merge_rule(source, ad_id, **changes):
    cur = _rule_for(source, ad_id)
    data = {k: cur.get(k) for k in ("priority_bonus", "paused", "start_date", "end_date", "hour_start", "hour_end",
                                    "tx_types", "min_amount", "max_amount", "note")}
    data.update(changes)
    data.update(source=source, ad_id=ad_id)
    ok, err = _se().save_rule(data)
    if not ok:
        raise ValueError(err)


def _log(surface, a, kind, reason, detail, prev, new, status, by):
    c = _conn()
    try:
        if status == "pending":
            c.execute("UPDATE ad_learn_log SET status='superseded' WHERE status='pending' AND surface=? AND source=? AND ad_id=? AND kind=?",
                      (surface, a["source"], a["ad_id"], kind))
        cur = c.execute("INSERT INTO ad_learn_log (created_at, surface, source, ad_id, kind, reason, detail, prev_value, new_value, status, "
                        "decided_by, decided_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (_ts(), surface, a["source"], a["ad_id"], kind, reason, json.dumps(detail), prev, new, status,
                         by if status != "pending" else None, _ts() if status != "pending" else None))
        _commit(c)
        return cur.lastrowid
    finally:
        c.close()


def _do(entry):
    """Carry out one logged change. Fills in what undo needs to restore."""
    d = json.loads(entry["detail"] or "{}")
    s, src, aid = entry["surface"], entry["source"], int(entry["ad_id"])
    if entry["kind"] == "shift":
        _set_state(s, src, aid, bonus=entry["new_value"])
    elif entry["kind"] == "pause":
        d["was_paused"] = int(_rule_for(src, aid).get("paused") or 0)
        _merge_rule(src, aid, paused=1)
    elif entry["kind"] == "target":
        d["was_types"] = _rule_for(src, aid).get("tx_types") or ""
        _merge_rule(src, aid, tx_types=d["tx_type"])
    return d


def propose(surface):
    """Study the data for one surface and return the changes the engine would make: [(kind, ad, reason, detail, prev, new)]."""
    out = []
    zthr, mxstep, lim = _f("confidence_z", 1.64), _f("max_step", 5), cap()
    since = _ts(_now() - timedelta(days=int(_f("window_days", 14))))
    for a in ad_stats(surface):
        if a["frozen"] or not a["judged"] or a["trial"]:
            continue
        cur = a["bonus"]
        target = 0.0
        if a["significant"] and a["ratio"] is not None:
            target = lim * math.tanh(1.5 * (a["ratio"] - 1.0))
        step = max(-mxstep, min(mxstep, target - cur))
        new = round(max(-lim, min(lim, cur + step)), 1)
        if abs(new - cur) >= 0.5:
            why = (f"click rate {a['ctr']*100:.1f}% vs {a['rest_ctr']*100:.1f}% for similar ads over {a['views']} views (z {a['z']})"
                   if a["significant"] else "the difference is no longer clear, so the shift is easing back toward zero")
            out.append(("shift", a, why, {"views": a["views"], "clicks": a["clicks"], "z": a["z"], "ratio": a["ratio"]}, cur, new))
        if a["significant"] and a["z"] <= -zthr and a["ratio"] is not None and a["ratio"] < 0.25 and a["views"] >= 3 * int(_f("min_views", 200)):
            if not _rule_for(a["source"], a["ad_id"]).get("paused"):
                out.append(("pause", a, f"click rate {a['ctr']*100:.1f}% is under a quarter of {a['rest_ctr']*100:.1f}% for similar ads",
                            {"views": a["views"], "z": a["z"]}, 0, 1))
        if a["views"] >= 2 * int(_f("min_views", 200)) and not _rule_for(a["source"], a["ad_id"]).get("tx_types"):
            seg = _segment_target(surface, a, since)
            if seg:
                out.append(("target", a, f"clicks {seg[1]}x better on '{seg[0]}' purchases than on the rest ({seg[3]} views, z {seg[2]})",
                            {"tx_type": seg[0], "ratio": seg[1], "z": seg[2]}, 0, 0))
    return out


def run(surface, by="auto"):
    """Analyse one surface and queue (Assisted) or apply (Auto) the result. Returns a small summary."""
    m = mode(surface)
    if m == "manual":
        return {"surface": surface, "mode": m, "skipped": "manual mode: nothing analysed", "queued": 0, "applied": 0}
    queued = applied = 0
    allow_pause = str(settings().get("auto_pause")) == "1"
    for kind, a, why, detail, prev, new in propose(surface):
        auto_ok = m == "auto" and (kind == "shift" or (kind == "pause" and allow_pause))
        if auto_ok:
            eid = _log(surface, a, kind, why, detail, prev, new, "auto_applied", "auto")
            entry = {"surface": surface, "source": a["source"], "ad_id": a["ad_id"], "kind": kind, "new_value": new, "detail": json.dumps(detail)}
            try:
                d = _do(entry)
                c = _conn()
                try:
                    c.execute("UPDATE ad_learn_log SET detail=? WHERE id=?", (json.dumps(d), eid)); _commit(c)
                finally:
                    c.close()
                applied += 1
            except Exception:
                logger.warning("adlearn: could not apply %s for %s", kind, a["ad_id"], exc_info=True)
                _mark(eid, "dismissed", "auto")
        else:
            _log(surface, a, kind, why, detail, prev, new, "pending", None)
            queued += 1
    return {"surface": surface, "mode": m, "queued": queued, "applied": applied}


def _mark(eid, status, by):
    c = _conn()
    try:
        c.execute("UPDATE ad_learn_log SET status=?, decided_by=?, decided_at=? WHERE id=?", (status, by, _ts(), eid)); _commit(c)
    finally:
        c.close()


def _entry(eid):
    c = _conn()
    try:
        r = c.execute("SELECT * FROM ad_learn_log WHERE id=?", (eid,)).fetchone()
        return dict(r) if r else None
    finally:
        c.close()


def apply_suggestion(eid, by="admin"):
    e = _entry(eid)
    if not e or e["status"] != "pending":
        return False, "That suggestion is no longer pending"
    try:
        d = _do(e)
    except ValueError as ex:
        return False, str(ex)
    c = _conn()
    try:
        c.execute("UPDATE ad_learn_log SET detail=?, status='applied', decided_by=?, decided_at=? WHERE id=?", (json.dumps(d), by, _ts(), eid)); _commit(c)
    finally:
        c.close()
    return True, ""


def dismiss_suggestion(eid, by="admin"):
    e = _entry(eid)
    if not e or e["status"] != "pending":
        return False, "That suggestion is no longer pending"
    _mark(eid, "dismissed", by)
    return True, ""


def undo(eid, by="admin"):
    e = _entry(eid)
    if not e or e["status"] not in ("applied", "auto_applied"):
        return False, "Only an applied change can be undone"
    d = json.loads(e["detail"] or "{}")
    try:
        if e["kind"] == "shift":
            _set_state(e["surface"], e["source"], int(e["ad_id"]), bonus=e["prev_value"])
        elif e["kind"] == "pause":
            _merge_rule(e["source"], int(e["ad_id"]), paused=int(d.get("was_paused") or 0))
        elif e["kind"] == "target":
            _merge_rule(e["source"], int(e["ad_id"]), tx_types=d.get("was_types") or "")
    except ValueError as ex:
        return False, str(ex)
    _mark(eid, "undone", by)
    return True, ""


# ------------------------------------------------------------------ background tick
def tick():
    """Called after serving. At most once per interval, and only when some surface is not Manual, run the analysis in the
    background so a customer's page never waits for it. Never raises."""
    try:
        if not _ready or all(mode(s) == "manual" for s in SURFACES):
            return
        if time.time() - _cache["last"] < _f("interval_minutes", 60) * 60:
            return
        if not _run_lock.acquire(blocking=False):
            return
        _cache["last"] = time.time()

        def work():
            try:
                for s in SURFACES:
                    run(s)
            except Exception:
                logger.warning("adlearn: background run failed", exc_info=True)
            finally:
                _run_lock.release()
        threading.Thread(target=work, daemon=True).start()
    except Exception:
        pass


# ------------------------------------------------------------------ admin API
def overview():
    c = _conn()
    try:
        log = [dict(r) for r in c.execute("SELECT * FROM ad_learn_log ORDER BY id DESC LIMIT 80").fetchall()]
        titles = _titles(c)
    finally:
        c.close()
    for r in log:
        r["title"] = titles.get((r["source"], int(r["ad_id"])), f"#{r['ad_id']}")
    return {"settings": dict(settings(force=True)), "cap": round(cap(), 1),
            "stats": {s: ad_stats(s) for s in SURFACES}, "pending": [r for r in log if r["status"] == "pending"],
            "log": [r for r in log if r["status"] != "pending"]}


def init_adlearn(app, admin_required):
    global _ready
    try:
        _schema()
        _ready = True
    except Exception:
        logger.exception("adlearn: schema setup failed; learning stays off")
        return

    def body():
        return request.get_json(silent=True) or {}

    @app.get("/api/admin/adlearn")
    @admin_required
    def adlearn_overview():
        try:
            return jsonify(success=True, **overview())
        except Exception as e:
            logger.exception("adlearn overview failed")
            return jsonify(success=False, error=str(e)), 500

    @app.post("/api/admin/adlearn/settings")
    @admin_required
    def adlearn_settings():
        ok, err, saved = save_settings(body())
        if not ok:
            return jsonify(success=False, error=err), 400
        logger.warning("ADLEARN: settings changed %s", saved)
        return jsonify(success=True, saved=saved)

    @app.post("/api/admin/adlearn/run")
    @admin_required
    def adlearn_run():
        try:
            return jsonify(success=True, results=[run(s, "admin") for s in SURFACES])
        except Exception as e:
            logger.exception("adlearn run failed")
            return jsonify(success=False, error=str(e)), 500

    def act(fn):
        try:
            eid = int(body().get("id"))
        except (TypeError, ValueError):
            return jsonify(success=False, error="id is required"), 400
        ok, err = fn(eid)
        return (jsonify(success=True), 200) if ok else (jsonify(success=False, error=err), 400)

    @app.post("/api/admin/adlearn/apply")
    @admin_required
    def adlearn_apply():
        return act(apply_suggestion)

    @app.post("/api/admin/adlearn/dismiss")
    @admin_required
    def adlearn_dismiss():
        return act(dismiss_suggestion)

    @app.post("/api/admin/adlearn/undo")
    @admin_required
    def adlearn_undo():
        return act(undo)

    @app.post("/api/admin/adlearn/freeze")
    @admin_required
    def adlearn_freeze():
        d = body()
        try:
            if d.get("surface") not in SURFACES or d.get("source") not in ("boost", "promo"):
                raise ValueError
            _set_state(d["surface"], d["source"], int(d["ad_id"]), frozen=bool(d.get("frozen")))
        except (ValueError, TypeError, KeyError):
            return jsonify(success=False, error="surface, source and ad_id are required"), 400
        return jsonify(success=True)

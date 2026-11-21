"""
Net365 Ad Engine, Phase 3: one selector for every ad that can appear after a payment.

What it adds on top of Phase 2
  * PRIORITY INDEX: each source has a base priority (paid Dominant > paid Basic > Boost by default). The admin can also give a single
    ad a bonus, or pause it, without touching the campaign itself.
  * SEVERAL ADS AT ONCE: the success page fills its free slots (primary, secondary, tertiary) with the best-ranked ads, never two
    from the same advertiser on one page.
  * PACING: among equal priorities, the ad that is furthest behind on its purchased views goes first, so budgets burn evenly.
  * FREQUENCY CAPS: per person, per ad per day (shared with Phase 2), per ad per week, and a total engine ads per person per day.
  * SCHEDULE AND TARGETING RULES per ad (admin only): start/end date, hours of the day (Lagos time), transaction types, amount band.
  * PER-SURFACE CONTROL: which sources may run on the success page and in receipt emails, and how many slots the engine may fill.
  * EXPLAINABLE: a Preview in admin shows the ranking for a made-up customer and the reason each other ad was left out.
  * SAFE: switched off by default (Phase 2 behaviour is unchanged until "engine_on" is 1); a page refresh shows the same ads and uses
    no extra views; every failure falls back to "no ad" and never breaks the payment page or the email.

Installed automatically by init_adcredits(); nothing to add in app.py.
"""
from __future__ import annotations

import json
import logging
import time
import zlib
from datetime import datetime, timedelta, timezone

from flask import jsonify, request

logger = logging.getLogger(__name__)

_ready = False
_cache = {"t": 0.0, "s": None, "rules_t": 0.0, "rules": None}

SOURCES = ("paid_dominant", "paid_basic", "boost")
SLOT_ORDER = ("primary", "secondary", "tertiary")

DEFAULTS = {
    "engine_on": "0",                                        # master switch: 0 = Phase 2 behaviour
    "success_slots": "3",                                    # most ads the engine may add to the success page
    "email_slots": "1",
    "success_sources": "paid_dominant,paid_basic,boost",     # which sources may run on the success page
    "email_sources": "boost",
    "priority": json.dumps({"paid_dominant": 100, "paid_basic": 70, "boost": 50}),
    "pacing_weight": "20",                                   # points for an ad that is fully behind on delivery
    "variety_weight": "5",                                   # small stable shuffle so equal ads rotate
    "ad_week_cap": "6",                                      # views of one ad per person per 7 days
    "user_day_cap": "12",                                    # engine ads per person per day, all ads together
    "one_per_advertiser": "1",                               # never two ads from one advertiser on one page
}


# ------------------------------------------------------------------ plumbing
def _ac():
    import net365_adcredits as ac
    return ac


def _conn():
    return _ac()._conn()


def _commit(c):
    return _ac()._commit(c)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _lagos_hour(now=None):
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo("Africa/Lagos")).hour if now is None else int(now)
    except Exception:
        return ((_now().hour + 1) % 24) if now is None else int(now)


def _lagos_date():
    return (_now() + timedelta(hours=1)).strftime("%Y-%m-%d")


def _schema():
    c = _conn()
    try:
        c.execute("CREATE TABLE IF NOT EXISTS ad_serve_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        c.execute("""CREATE TABLE IF NOT EXISTS ad_serve_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,              -- boost | promo
            ad_id INTEGER NOT NULL,
            priority_bonus REAL NOT NULL DEFAULT 0,
            paused INTEGER NOT NULL DEFAULT 0,
            start_date TEXT, end_date TEXT,    -- YYYY-MM-DD, Lagos date, inclusive
            hour_start INTEGER, hour_end INTEGER,
            tx_types TEXT,                     -- comma list, empty = all
            min_amount REAL, max_amount REAL,
            note TEXT,
            updated_at TEXT NOT NULL)""")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_adserve_rule ON ad_serve_rules(source, ad_id)")
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
            for r in c.execute("SELECT key, value FROM ad_serve_settings").fetchall():
                if r["key"] in DEFAULTS:
                    s[r["key"]] = r["value"]
        finally:
            c.close()
    except Exception:
        logger.warning("adserve: settings unreadable; defaults used", exc_info=True)
    _cache.update(t=time.time(), s=s)
    return s


def _i(key, default):
    try:
        return int(float(settings().get(key, default)))
    except (TypeError, ValueError):
        return default


def _f(key, default):
    try:
        return float(settings().get(key, default))
    except (TypeError, ValueError):
        return default


def _priority():
    base = json.loads(DEFAULTS["priority"])
    try:
        base.update({k: float(v) for k, v in json.loads(settings().get("priority") or "{}").items() if k in SOURCES})
    except Exception:
        pass
    return base


def _sources(surface):
    raw = settings().get("success_sources" if surface == "success" else "email_sources", "")
    return {x.strip() for x in str(raw).split(",") if x.strip() in SOURCES}


def active():
    """True when the engine should choose ads (Phase 3). Otherwise Phase 2 behaviour runs unchanged."""
    return _ready and str(settings().get("engine_on")) == "1"


def save_settings(updates):
    """Validate and store admin changes. Returns (ok, error, saved)."""
    saved = {}
    for k, v in (updates or {}).items():
        if k not in DEFAULTS:
            return False, f"Unknown setting: {k}", {}
        if k == "priority":
            try:
                d = v if isinstance(v, dict) else json.loads(v)
                v = json.dumps({s: max(0.0, min(1000.0, float(d[s]))) for s in SOURCES if s in d})
            except Exception:
                return False, "priority must look like {\"boost\": 50, ...}", {}
        elif k in ("success_sources", "email_sources"):
            items = v if isinstance(v, list) else str(v).split(",")
            clean = [x.strip() for x in items if x.strip()]
            bad = [x for x in clean if x not in SOURCES]
            if bad:
                return False, f"Unknown source: {bad[0]}", {}
            v = ",".join(clean)
        elif k in ("engine_on", "one_per_advertiser"):
            v = "1" if str(v).lower() in ("1", "true", "yes", "on") else "0"
        else:
            try:
                n = float(v)
            except (TypeError, ValueError):
                return False, f"{k} must be a number", {}
            if n < 0 or n > 1000:
                return False, f"{k} must be between 0 and 1000", {}
            if k in ("success_slots", "email_slots") and n > 3:
                return False, f"{k} can be at most 3", {}
            v = str(int(n)) if n == int(n) else str(n)
        saved[k] = str(v)
    c = _conn()
    try:
        for k, v in saved.items():
            c.execute("INSERT INTO ad_serve_settings(key, value) VALUES(?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))
        _commit(c)
    finally:
        c.close()
    _cache["t"] = 0.0
    return True, "", saved


# ------------------------------------------------------------------ rules
def rules(force=False):
    if not force and _cache["rules"] is not None and time.time() - _cache["rules_t"] < 5:
        return _cache["rules"]
    out = {}
    try:
        c = _conn()
        try:
            for r in c.execute("SELECT * FROM ad_serve_rules").fetchall():
                out[(r["source"], int(r["ad_id"]))] = dict(r)
        finally:
            c.close()
    except Exception:
        logger.warning("adserve: rules unreadable", exc_info=True)
    _cache.update(rules=out, rules_t=time.time())
    return out


def save_rule(data):
    src = str(data.get("source") or "")
    if src not in ("boost", "promo"):
        return False, "source must be boost or promo"
    try:
        ad_id = int(data.get("ad_id"))
    except (TypeError, ValueError):
        return False, "ad_id is required"

    def num(k, lo, hi, as_int=False):
        v = data.get(k)
        if v in (None, ""):
            return None
        try:
            n = float(v)
        except (TypeError, ValueError):
            raise ValueError(f"{k} must be a number")
        if n < lo or n > hi:
            raise ValueError(f"{k} must be between {lo} and {hi}")
        return int(n) if as_int else n

    def day(k):
        v = str(data.get(k) or "").strip()
        if not v:
            return None
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            raise ValueError(f"{k} must be YYYY-MM-DD")
        return v

    try:
        bonus = num("priority_bonus", -100, 100) or 0.0
        hs, he = num("hour_start", 0, 23, True), num("hour_end", 0, 23, True)
        mn, mx = num("min_amount", 0, 1e9), num("max_amount", 0, 1e9)
        sd, ed = day("start_date"), day("end_date")
    except ValueError as e:
        return False, str(e)
    if (hs is None) != (he is None):
        return False, "Set both hour_start and hour_end, or neither"
    if sd and ed and sd > ed:
        return False, "start_date is after end_date"
    if mn is not None and mx is not None and mn > mx:
        return False, "min_amount is above max_amount"
    types = ",".join(t.strip().lower() for t in str(data.get("tx_types") or "").split(",") if t.strip())
    c = _conn()
    try:
        c.execute("""INSERT INTO ad_serve_rules(source, ad_id, priority_bonus, paused, start_date, end_date, hour_start, hour_end,
                     tx_types, min_amount, max_amount, note, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                     ON CONFLICT(source, ad_id) DO UPDATE SET priority_bonus=excluded.priority_bonus, paused=excluded.paused,
                     start_date=excluded.start_date, end_date=excluded.end_date, hour_start=excluded.hour_start,
                     hour_end=excluded.hour_end, tx_types=excluded.tx_types, min_amount=excluded.min_amount,
                     max_amount=excluded.max_amount, note=excluded.note, updated_at=excluded.updated_at""",
                  (src, ad_id, bonus, 1 if str(data.get("paused")).lower() in ("1", "true", "yes", "on") else 0, sd, ed, hs, he,
                   types or None, mn, mx, str(data.get("note") or "")[:200], _now().strftime("%Y-%m-%d %H:%M:%S")))
        _commit(c)
    finally:
        c.close()
    _cache["rules_t"] = 0.0
    return True, ""


def delete_rule(source, ad_id):
    c = _conn()
    try:
        c.execute("DELETE FROM ad_serve_rules WHERE source=? AND ad_id=?", (source, int(ad_id)))
        _commit(c)
    finally:
        c.close()
    _cache["rules_t"] = 0.0


def _rule_reason(rule, ctx, hour):
    """'' when the rule lets the ad run, otherwise why not."""
    if not rule:
        return ""
    if rule.get("paused"):
        return "paused by admin"
    today = _lagos_date()
    if rule.get("start_date") and today < rule["start_date"]:
        return "not started yet"
    if rule.get("end_date") and today > rule["end_date"]:
        return "ended"
    hs, he = rule.get("hour_start"), rule.get("hour_end")
    if hs is not None and he is not None:
        inside = hs <= hour <= he if hs <= he else (hour >= hs or hour <= he)       # 22 -> 5 wraps midnight
        if not inside:
            return "outside its hours"
    if rule.get("tx_types"):
        if str(ctx.get("tx_type") or "").lower() not in rule["tx_types"].split(","):
            return "other transaction type"
    amt = ctx.get("amount")
    if rule.get("min_amount") is not None and (amt is None or amt < rule["min_amount"]):
        return "amount below its band"
    if rule.get("max_amount") is not None and (amt is None or amt > rule["max_amount"]):
        return "amount above its band"
    return ""


# ------------------------------------------------------------------ candidates
def _paid_reason(r, tier, ctx, hour, level):
    if level == "off":
        return "paid ads are off on the success page"
    if level == "sponsored" and tier != "dominant":
        return "only Dominant paid ads allowed"
    if tier == "dominant":
        return ""
    if r["target_tx_type"] and str(ctx.get("tx_type") or "").lower() != str(r["target_tx_type"]).lower():
        return "other transaction type"
    amt = ctx.get("amount")
    if r["target_min_amount"] is not None and (amt is None or amt < r["target_min_amount"]):
        return "amount below target"
    if r["target_max_amount"] is not None and (amt is None or amt > r["target_max_amount"]):
        return "amount above target"
    hs, he = r["target_hour_start"], r["target_hour_end"]
    if hs is not None and he is not None:
        inside = hs <= hour <= he if hs <= he else (hour >= hs or hour <= he)
        if not inside:
            return "outside target hours"
    return ""


def _boost_city_reason(b, city, pilot, unknown_show, ac):
    if pilot and (not city or ac._norm(city) not in pilot):
        if not (not city and unknown_show):
            return "viewer is outside the pilot cities"
    if b["city"]:
        if city:
            if ac._norm(city) != ac._norm(b["city"]):
                return "other city"
        elif not unknown_show:
            return "viewer city unknown"
    return ""


def _usage(c, viewer):
    """(per-ad day counts, per-ad week counts, total day count) for this person from the event log."""
    if not viewer:
        return {}, {}, 0
    today = _now().strftime("%Y-%m-%d")
    week = (_now() - timedelta(days=7)).strftime("%Y-%m-%d")
    day, wk, total = {}, {}, 0
    try:
        for r in c.execute("SELECT ad_source, ad_id, ts FROM ad_events WHERE user_id=? AND event='impression' AND ts >= ? "
                           "AND ad_source IN ('boost','promo')", (viewer, week)).fetchall():
            k = (r["ad_source"], int(r["ad_id"]))
            wk[k] = wk.get(k, 0) + 1
            if str(r["ts"]) >= today:
                day[k] = day.get(k, 0) + 1
                total += 1
    except Exception:
        pass
    return day, wk, total


def _stable(ref, key):
    return (zlib.crc32(f"{ref}|{key}".encode()) % 1000) / 1000.0


def rank(surface, ctx, hour=None):
    """Ranked candidates (best first) and the ads left out with a reason. Reads only; nothing is consumed."""
    ac = _ac()
    hour = _lagos_hour(hour)
    allowed = _sources(surface)
    prio = _priority()
    rl = rules()
    viewer = ctx.get("user_id")
    ref = ctx.get("reference") or ""
    city = ctx.get("city") or (ac.viewer_city(viewer) if viewer else None)
    pilot = [ac._norm(x) for x in ac._cities()]
    unknown_show = ac.settings().get("unknown_location") == "show"
    level = ac.settings().get("paid_on_success", "off") if surface == "success" else "off"
    pacing, variety = _f("pacing_weight", 20), _f("variety_weight", 5)
    week_cap, day_cap, freq = _i("ad_week_cap", 6), _i("user_day_cap", 12), ac._i("freq_cap", 3)
    ranked, out = [], []

    c = _conn()
    try:
        day_use, week_use, total_today = _usage(c, viewer)

        def consider(cand, why):
            (out.append({**_brief(cand), "why": why}) if why else ranked.append(cand))

        if "boost" in allowed and ac.enabled() and str(ac.settings().get("boost_on_" + ("success" if surface == "success" else "email"))) == "1":
            for b in c.execute("SELECT * FROM boost_ads WHERE status='approved' AND views_used < views_total "
                               "ORDER BY id LIMIT 200").fetchall():
                b = dict(b)
                rule = rl.get(("boost", b["id"]))
                cand = {"source": "boost", "key": ("boost", b["id"]), "row": b, "tier": "boost", "advertiser": b["user_id"],
                        "label": b["title"], "left_frac": 1.0 - b["views_used"] / max(1, b["views_total"]), "rule": rule}
                why = ""
                if viewer and b["user_id"] == viewer:
                    why = "the advertiser's own ad"
                why = why or _boost_city_reason(b, city, pilot, unknown_show, ac) or _rule_reason(rule, ctx, hour)
                cand["score"] = prio["boost"] + (rule["priority_bonus"] if rule else 0) + pacing * cand["left_frac"] \
                    + variety * _stable(ref, cand["key"]) + _learned(surface, cand["key"], ref)
                consider(cand, why)

        paid_tiers = [t for t, s in (("dominant", "paid_dominant"), ("basic", "paid_basic")) if s in allowed]
        if paid_tiers and surface == "success":
            for r in c.execute("SELECT * FROM receipt_promos WHERE source='sponsored' AND status='approved' "
                               "AND campaign_tier IN ('dominant','basic') AND impressions_delivered < impressions_purchased "
                               "ORDER BY id LIMIT 200").fetchall():
                r = dict(r)
                tier = r["campaign_tier"]
                if tier not in paid_tiers:
                    continue
                rule = rl.get(("promo", r["id"]))
                cand = {"source": "promo", "key": ("promo", r["id"]), "row": r, "tier": tier, "advertiser": r["advertiser_user_id"],
                        "label": r["title"],
                        "left_frac": 1.0 - r["impressions_delivered"] / max(1, r["impressions_purchased"]), "rule": rule}
                why = _paid_reason(r, tier, ctx, hour, level) or _rule_reason(rule, ctx, hour)
                cand["score"] = prio["paid_" + tier] + (rule["priority_bonus"] if rule else 0) + pacing * cand["left_frac"] \
                    + variety * _stable(ref, cand["key"]) + _learned(surface, cand["key"], ref)
                consider(cand, why)

        # frequency caps (shared by every source)
        kept = []
        for cand in ranked:
            k = cand["key"]
            why = ""
            if viewer:
                if day_use.get(k, 0) >= freq:
                    why = "daily cap for this person"
                elif week_use.get(k, 0) >= week_cap:
                    why = "weekly cap for this person"
                elif total_today >= day_cap:
                    why = "this person has reached the daily total"
            if why:
                out.append({**_brief(cand), "why": why})
            else:
                kept.append(cand)
    finally:
        c.close()
    kept.sort(key=lambda x: (-x["score"], x["row"]["id"]))
    return kept, out


def _learned(surface, key, ref):
    """Phase 4 learned priority points for this ad on this surface (0 in Manual mode or if learning is unavailable)."""
    try:
        import net365_adlearn as al
        return al.serving_bonus(surface, key, ref)
    except Exception:
        return 0.0


def _tick():
    try:
        import net365_adlearn as al
        al.tick()
    except Exception:
        pass


def _brief(cand):
    return {"source": cand["source"], "id": cand["row"]["id"], "tier": cand["tier"], "label": cand["label"],
            "score": round(cand.get("score", 0), 1)}


def _choose(ranked, slots):
    """Top `slots` ads, never two from the same advertiser when that rule is on."""
    once = str(settings().get("one_per_advertiser")) == "1"
    seen, picked = set(), []
    for cand in ranked:
        adv = cand.get("advertiser")
        if once and adv is not None and adv in seen:
            continue
        picked.append(cand)
        if adv is not None:
            seen.add(adv)
        if len(picked) >= slots:
            break
    return picked


# ------------------------------------------------------------------ serving
def _consume(c, cand, surface, ctx):
    """Record the impression and use up one view. Returns True when it was a new view."""
    ac = _ac()
    src = "boost" if cand["source"] == "boost" else "promo"
    row = cand["row"]
    is_new = ac._record(surface, src, row["id"], ctx.get("reference"), ctx)
    if is_new:
        if src == "boost":
            cur = c.execute("UPDATE boost_ads SET views_used = views_used + 1 WHERE id=? AND views_used < views_total", (row["id"],))
            if cur.rowcount:
                c.execute("UPDATE boost_ads SET status='completed' WHERE id=? AND views_used >= views_total", (row["id"],))
        else:
            c.execute("UPDATE receipt_promos SET impressions_delivered = impressions_delivered + 1 WHERE id=?", (row["id"],))
        _commit(c)
    return is_new


def _as_success_ad(cand, ref):
    ac = _ac()
    r = cand["row"]
    if cand["source"] == "boost":
        return ac._boost_as_success_ad(r, ref)
    return {"id": -int(r["id"]), "headline": r["title"], "subheadline": "", "body": r["body"],
            "cta_text": r["cta_text"] or "Learn more",
            "cta_url": ac._tracked("success", r["id"], ref, "promo") or (r["cta_url"] or ""),
            "cta_action": "", "advertiser_name": "", "sponsored": True}


def _already_served(surface, ref):
    """Ads this payment already showed (a page refresh): the same ads again, in the same order, using nothing."""
    if not ref:
        return []
    c = _conn()
    try:
        rows = c.execute("SELECT ad_source, ad_id FROM ad_events WHERE surface=? AND reference=? AND event='impression' "
                         "AND ad_source IN ('boost','promo') ORDER BY id", (surface, ref)).fetchall()
        out = []
        for r in rows:
            if r["ad_source"] == "boost":
                b = c.execute("SELECT * FROM boost_ads WHERE id=?", (r["ad_id"],)).fetchone()
                if b and b["status"] in ("approved", "completed"):
                    out.append({"source": "boost", "row": dict(b), "tier": "boost", "key": ("boost", b["id"])})
            else:
                p = c.execute("SELECT * FROM receipt_promos WHERE id=? AND source='sponsored'", (r["ad_id"],)).fetchone()
                if p:
                    out.append({"source": "promo", "row": dict(p), "tier": p["campaign_tier"], "key": ("promo", p["id"])})
        return out
    finally:
        c.close()


def serve_success(ads, ctx):
    """Fill the success page's free slots. Takes and returns the {primary, secondary, tertiary} dict. Never raises."""
    ads = dict(ads or {})
    try:
        slots = _i("success_slots", 3)
        ref = ctx.get("reference")
        chosen = _already_served("success", ref)
        fresh = not chosen
        if fresh:
            ranked, _ = rank("success", ctx)
            chosen = _choose(ranked, slots)
        chosen = chosen[:slots]
        c = _conn()
        try:
            for cand in chosen:
                if fresh and not _consume(c, cand, "success", ctx):
                    continue
                ad = _as_success_ad(cand, ref)
                if cand["tier"] == "dominant":
                    old = ads.get("primary")
                    ads["primary"] = ad
                    if old:
                        for k in ("secondary", "tertiary"):
                            if not ads.get(k):
                                ads[k] = old
                                break
                else:
                    for k in SLOT_ORDER:
                        if not ads.get(k):
                            ads[k] = ad
                            break
        finally:
            c.close()
    except Exception:
        logger.warning("adserve: serve_success failed", exc_info=True)
    _tick()
    return ads


def serve_email(promo, ctx):
    """A receipt email: engine ad replaces an empty or house promo. Paid promos chosen elsewhere keep their place."""
    try:
        if promo and str(promo.get("source") or "house") != "house":
            return promo
        if _i("email_slots", 1) < 1:
            return promo
        ref = ctx.get("reference")
        prior = _already_served("email", ref)
        if prior:
            cand = prior[0]
        else:
            ranked, _ = rank("email", ctx)
            picked = _choose(ranked, 1)
            if not picked:
                return promo
            cand = picked[0]
            c = _conn()
            try:
                if not _consume(c, cand, "email", ctx):
                    return promo
            finally:
                c.close()
        b = cand["row"]
        ac = _ac()
        _tick()
        return {"id": b["id"], "title": b["title"], "body": b["body"], "cta_text": b.get("cta_text") or "Learn more",
                "cta_url": ac._tracked("email", b["id"], ref, "boost") or b["cta_url"], "source": "boost", "_boost": True}
    except Exception:
        logger.warning("adserve: serve_email failed", exc_info=True)
        return promo


def preview(surface, ctx, hour=None):
    ranked, out = rank(surface, ctx, hour)
    slots = _i("success_slots" if surface == "success" else "email_slots", 1)
    chosen = _choose(ranked, slots)
    ids = {id(x) for x in chosen}
    shown = [_brief(x) for x in chosen]
    for x in ranked:
        if id(x) not in ids:
            out.append({**_brief(x), "why": "lower ranked than the free slots" if len(chosen) >= slots else "same advertiser already shown"})
    return {"would_show": shown, "left_out": out, "slots": slots, "engine_on": str(settings().get("engine_on")) == "1"}


# ------------------------------------------------------------------ admin API
def _today_stats():
    c = _conn()
    try:
        today = _now().strftime("%Y-%m-%d")
        rows = c.execute("SELECT surface, ad_source, COUNT(*) n FROM ad_events WHERE event='impression' AND ts >= ? "
                         "GROUP BY surface, ad_source", (today,)).fetchall()
        return [{"surface": r["surface"], "source": r["ad_source"], "views": r["n"]} for r in rows]
    finally:
        c.close()


def _ad_list():
    c = _conn()
    try:
        out = []
        for b in c.execute("SELECT id, title, business_name, city, views_used, views_total FROM boost_ads WHERE status='approved' "
                           "ORDER BY id DESC LIMIT 200").fetchall():
            out.append({"source": "boost", "id": b["id"], "title": b["title"], "owner": b["business_name"] or "",
                        "city": b["city"] or "", "used": b["views_used"], "total": b["views_total"]})
        for p in c.execute("SELECT id, title, campaign_tier, impressions_delivered, impressions_purchased FROM receipt_promos "
                           "WHERE source='sponsored' AND status='approved' ORDER BY id DESC LIMIT 200").fetchall():
            out.append({"source": "promo", "id": p["id"], "title": p["title"], "owner": p["campaign_tier"],
                        "city": "", "used": p["impressions_delivered"], "total": p["impressions_purchased"]})
        return out
    finally:
        c.close()


def init_adserve(app, admin_required):
    global _ready
    try:
        _schema()
        _ready = True
    except Exception:
        logger.exception("adserve: schema setup failed; engine stays off")
        return

    try:
        from net365_adlearn import init_adlearn
        init_adlearn(app, admin_required)
    except ImportError:
        logger.info("adlearn module not installed; Phase 3 serving only")
    except Exception:
        logger.exception("adlearn: init failed; learning stays off")

    @app.get("/api/admin/adserve")
    @admin_required
    def adserve_admin_overview():
        try:
            return jsonify(success=True, settings=dict(settings(force=True)), priority=_priority(),
                           rules=list(rules(force=True).values()), ads=_ad_list(), today=_today_stats(), sources=list(SOURCES))
        except Exception as e:
            logger.exception("adserve overview failed")
            return jsonify(success=False, error=str(e)), 500

    @app.post("/api/admin/adserve/settings")
    @admin_required
    def adserve_admin_settings():
        ok, err, saved = save_settings(request.get_json(silent=True) or {})
        if not ok:
            return jsonify(success=False, error=err), 400
        logger.warning("ADSERVE: settings changed %s", list(saved.keys()))
        return jsonify(success=True, saved=saved)

    @app.post("/api/admin/adserve/rule")
    @admin_required
    def adserve_admin_rule():
        ok, err = save_rule(request.get_json(silent=True) or {})
        return (jsonify(success=True), 200) if ok else (jsonify(success=False, error=err), 400)

    @app.post("/api/admin/adserve/rule/delete")
    @admin_required
    def adserve_admin_rule_delete():
        d = request.get_json(silent=True) or {}
        try:
            delete_rule(str(d.get("source") or ""), int(d.get("ad_id")))
        except (TypeError, ValueError):
            return jsonify(success=False, error="ad_id is required"), 400
        return jsonify(success=True)

    @app.get("/api/admin/adserve/preview")
    @admin_required
    def adserve_admin_preview():
        a = request.args
        surface = "email" if a.get("surface") == "email" else "success"
        try:
            amount = float(a["amount"]) if a.get("amount") else None
            hour = int(a["hour"]) if a.get("hour") not in (None, "") else None
        except ValueError:
            return jsonify(success=False, error="amount and hour must be numbers"), 400
        ctx = {"user_id": None, "reference": "preview", "tx_type": a.get("tx_type") or "", "amount": amount,
               "city": a.get("city") or None}
        try:
            return jsonify(success=True, **preview(surface, ctx, hour))
        except Exception as e:
            logger.exception("adserve preview failed")
            return jsonify(success=False, error=str(e)), 500

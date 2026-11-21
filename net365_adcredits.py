"""
net365_adcredits.py - Phase 2: ad views earned by transacting, spent on Boost ads.

What this does:
  * Every fulfilled recharge/bill payment earns the payer "ad views" (credits counted in views, never naira).
  * Credits are held for a while (so refunds can cancel them), then become spendable, and expire if unused.
  * A business spends views on a small Boost ad. Admin approves it. It is shown on the success page and in
    receipt emails until its views run out.
  * An inventory meter limits how many views can be promised, so credits never exceed what Net365 can show.
  * Everything is OFF until admin switches "Credits enabled" on. Admin controls every number below.

Rules kept on purpose:
  * Ad views are promotional: no cash value, not transferable, no cash-out, earn-only (no buying them).
  * Earning is decided by the server at fulfilment, never by the browser.
  * Every function that touches a payment path swallows its own errors. Credits can never break a payment.
  * Reversal after a refund: the earned entry is cancelled; if already spent the balance can go negative
    against future earnings (nothing already shown is pulled back).

Wire-up (in app.py, next to init_adengine):
    from net365_adcredits import init_adcredits
    init_adcredits(self.app, db, admin_required, login_required)
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
import zlib
from datetime import datetime, timedelta, timezone

from flask import g, jsonify, request

logger = logging.getLogger(__name__)

_db = None
_ready = False
_lock = threading.Lock()
_cache = {"t": 0.0, "settings": None, "meter_t": 0.0, "meter": None}

# transactions.tx_type -> service name used for the earning percentage
EARN_SERVICES = {"topup": "airtime", "data": "data", "electricity": "electricity", "utility": "electricity",
                 "tv": "tv", "education": "education", "insurance": "insurance"}
SERVICE_NAMES = ("airtime", "data", "electricity", "tv", "education", "insurance")

DEFAULTS = {
    "enabled": "0",                    # master switch
    "rollout_pct": "100",              # % of users who can earn (ramp up 10 -> 50 -> 100)
    "holdout_pct": "10",               # % of eligible users who earn nothing, to measure the effect
    "earn_pct": json.dumps({s: 3 for s in SERVICE_NAMES}),   # % of the estimated fee returned as views (a ceiling)
    "fee_estimate_pct": "2.5",         # Net365's customer fee as % of the service amount (estimate)
    "view_value_ngn": "1",             # naira value of one view; used only to size earnings
    "min_amount_ngn": "500",           # smaller payments earn nothing
    "hold_hours": "48",
    "expiry_days": "90",
    "daily_cap": "50",                 # most views one user can earn per day
    "boost_share_cap": "30",           # % of unsold inventory credits may be backed by
    "cold_start_daily_views": "200",   # assumed daily ad views until real traffic exists
    "views_per_tx": "2",               # ad views one transaction produces (success page + email)
    "pilot_cities": "",                # comma list; empty = all cities
    "boost_allow_national": "0",       # may a Boost ad be shown nationwide?
    "unknown_location": "hide",        # viewer city unknown: show or hide city-targeted Boost ads
    "boost_approval": "admin",         # admin = every ad is reviewed; auto = word filter only
    "boost_on_success": "1",
    "boost_on_email": "1",
    "paid_on_success": "off",          # off | sponsored | all : paid Marketplace campaigns on the success page
    "freq_cap": "3",                   # views of one ad per person per day
    "boost_min_views": "20",
    "boost_max_views": "2000",
    "max_active_boosts": "3",
    "blocked_words": "casino,betting,forex,crypto,investment doubler,adult,porn,loan shark",
}


# ------------------------------------------------------------------ small helpers
def _now():
    return datetime.now(timezone.utc)


def _iso(dt=None):
    return (dt or _now()).isoformat(timespec="seconds")


def _conn():
    return _db.get_db_connection()


def _commit(c):
    c.commit()
    try:
        if c.in_transaction:
            c.execute("COMMIT")
    except Exception:
        pass


def _ensure_schema():
    c = _conn()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS ad_credit_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            views INTEGER NOT NULL,
            reference TEXT,
            ref_earn_id INTEGER,
            note TEXT,
            created_at TEXT NOT NULL,
            available_at TEXT,
            expires_at TEXT)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_adcl_user ON ad_credit_ledger(user_id, id)")
        c.execute("""CREATE UNIQUE INDEX IF NOT EXISTS uq_adcl_kind_ref
                     ON ad_credit_ledger(kind, reference) WHERE reference IS NOT NULL""")
        c.execute("CREATE TABLE IF NOT EXISTS ad_credit_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        c.execute("""CREATE TABLE IF NOT EXISTS boost_ads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            business_name TEXT,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            cta_text TEXT,
            cta_url TEXT NOT NULL,
            city TEXT,
            views_total INTEGER NOT NULL,
            views_used INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            reject_reason TEXT,
            compliance_ack_at TEXT,
            arcon_cert TEXT,
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            reviewed_by TEXT)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_boost_status ON boost_ads(status)")
        _commit(c)
    finally:
        c.close()


# ------------------------------------------------------------------ settings
def settings(force=False):
    if not force and _cache["settings"] is not None and time.time() - _cache["t"] < 5:
        return _cache["settings"]
    s = dict(DEFAULTS)
    try:
        c = _conn()
        try:
            for r in c.execute("SELECT key, value FROM ad_credit_settings").fetchall():
                if r["key"] in DEFAULTS:
                    s[r["key"]] = r["value"]
        finally:
            c.close()
    except Exception:
        logger.warning("adcredits: could not read settings; using defaults", exc_info=True)
    _cache.update(t=time.time(), settings=s, meter_t=0.0)
    return s


def _f(key, default=0.0):
    try:
        return float(settings().get(key, DEFAULTS.get(key)))
    except (TypeError, ValueError):
        return float(default)


def _i(key, default=0):
    return int(_f(key, default))


def enabled():
    return _ready and str(settings().get("enabled", "0")) == "1"


def _earn_pct():
    try:
        d = json.loads(settings().get("earn_pct") or "{}")
        return {k: float(v) for k, v in d.items()}
    except Exception:
        return {s: 3.0 for s in SERVICE_NAMES}


def _cities():
    return [c.strip() for c in str(settings().get("pilot_cities") or "").split(",") if c.strip()]


def _norm(city):
    return re.sub(r"\s+", " ", str(city or "").strip().casefold())


_RANGES = {"rollout_pct": (0, 100), "holdout_pct": (0, 50), "fee_estimate_pct": (0, 20), "view_value_ngn": (0.1, 1000),
           "min_amount_ngn": (0, 1000000), "hold_hours": (0, 720), "expiry_days": (7, 730), "daily_cap": (0, 100000),
           "boost_share_cap": (0, 100), "cold_start_daily_views": (0, 10000000), "views_per_tx": (0, 20),
           "freq_cap": (1, 100), "boost_min_views": (1, 100000), "boost_max_views": (1, 1000000), "max_active_boosts": (1, 50)}
_FLAGS = ("enabled", "boost_allow_national", "boost_on_success", "boost_on_email")
_CHOICES = {"unknown_location": ("hide", "show"), "boost_approval": ("admin", "auto"),
            "paid_on_success": ("off", "sponsored", "all")}


def save_settings(updates):
    """Validate and store. Returns (ok, error_or_None, saved_dict)."""
    clean = {}
    for k, v in (updates or {}).items():
        if k not in DEFAULTS:
            return False, f"Unknown setting: {k}", {}
        if k in _FLAGS:
            clean[k] = "1" if (v is True or str(v).strip().lower() in ("1", "true", "yes", "on")) else "0"
        elif k in _RANGES:
            try:
                n = float(v)
            except (TypeError, ValueError):
                return False, f"{k} must be a number", {}
            lo, hi = _RANGES[k]
            if not (lo <= n <= hi):
                return False, f"{k} must be between {lo} and {hi}", {}
            clean[k] = str(int(n)) if float(n).is_integer() else str(n)
        elif k in _CHOICES:
            if str(v) not in _CHOICES[k]:
                return False, f"{k} must be one of: {', '.join(_CHOICES[k])}", {}
            clean[k] = str(v)
        elif k == "earn_pct":
            try:
                d = v if isinstance(v, dict) else json.loads(v)
                out = {}
                for svc, pct in d.items():
                    if svc not in SERVICE_NAMES:
                        return False, f"Unknown service: {svc}", {}
                    pct = float(pct)
                    if not (0 <= pct <= 20):
                        return False, "Earning percentage must be between 0 and 20", {}
                    out[svc] = pct
            except Exception:
                return False, "earn_pct must be a mapping of service to percentage", {}
            merged = _earn_pct()
            merged.update(out)
            clean[k] = json.dumps(merged)
        elif k == "pilot_cities":
            clean[k] = ",".join(c.strip()[:40] for c in str(v or "").split(",") if c.strip())[:500]
        elif k == "blocked_words":
            clean[k] = ",".join(w.strip().lower()[:40] for w in str(v or "").split(",") if w.strip())[:1000]
    c = _conn()
    try:
        for k, v in clean.items():
            c.execute("INSERT INTO ad_credit_settings (key,value) VALUES (?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))
        _commit(c)
    finally:
        c.close()
    settings(force=True)
    return True, None, clean


# ------------------------------------------------------------------ ledger maths
def _state(user_id, now_iso=None):
    """Balance for one user, computed from the ledger. Returns available, held, expired, earned, spent, reversed."""
    now_iso = now_iso or _iso()
    c = _conn()
    try:
        rows = c.execute("SELECT id, kind, views, ref_earn_id, available_at, expires_at FROM ad_credit_ledger "
                         "WHERE user_id = ? ORDER BY id", (user_id,)).fetchall()
    finally:
        c.close()
    items, spends, reverses = {}, 0, []
    earned = reversed_total = 0
    for r in rows:
        if r["kind"] in ("earn", "release"):
            items[r["id"]] = {"rem": int(r["views"]), "av": r["available_at"] or "", "ex": r["expires_at"] or "9999"}
            if r["kind"] == "earn":
                earned += int(r["views"])
        elif r["kind"] == "spend":
            spends += -int(r["views"])
        elif r["kind"] == "reverse":
            reverses.append(r)
            reversed_total += -int(r["views"])
    debt = 0
    for r in reverses:
        it = items.get(r["ref_earn_id"])
        if it is None:
            debt += -int(r["views"])
            continue
        left = it["rem"] + int(r["views"])
        if left < 0:
            debt += -left
            left = 0
        it["rem"] = left
    consume = spends
    for it in sorted(items.values(), key=lambda x: x["ex"]):
        take = min(it["rem"], consume)
        it["rem"] -= take
        consume -= take
    debt += consume            # views spent that were later reversed (refund after spending)
    avail = held = expired = 0
    for it in items.values():
        if it["ex"] <= now_iso:
            expired += it["rem"]
        elif it["av"] > now_iso:
            held += it["rem"]
        else:
            avail += it["rem"]
    avail = max(0, avail - debt)
    soonest = None
    if avail:
        live = [it for it in items.values() if it["rem"] > 0 and it["av"] <= now_iso < it["ex"]]
        if live:
            soonest = min(it["ex"] for it in live)
    return {"available": int(avail), "held": int(held), "expired": int(expired), "earned": int(earned),
            "spent": int(spends), "reversed": int(reversed_total), "debt": int(debt), "next_expiry": soonest}


def balance(user_id):
    try:
        return _state(user_id)
    except Exception:
        logger.warning("adcredits: balance failed", exc_info=True)
        return {"available": 0, "held": 0, "expired": 0, "earned": 0, "spent": 0, "reversed": 0, "debt": 0,
                "next_expiry": None}


# ------------------------------------------------------------------ inventory meter
def meter(force=False):
    """How many views credits may be backed by, and how much is already promised."""
    if not force and _cache["meter"] is not None and time.time() - _cache["meter_t"] < 60:
        return _cache["meter"]
    c = _conn()
    try:
        types = tuple(EARN_SERVICES.keys())
        ph = ",".join("?" for _ in types)
        row = c.execute(f"SELECT COUNT(*) AS n, MIN(created_at) AS first FROM transactions "
                        f"WHERE status = 'fulfilled' AND tx_type IN ({ph}) AND created_at >= datetime('now','-14 days')",
                        types).fetchone()
        n, first = int(row["n"] or 0), row["first"]
        days_obs = 0.0
        if first:
            try:
                f = datetime.fromisoformat(str(first).replace(" ", "T")).replace(tzinfo=timezone.utc)
                days_obs = max(1.0, min(14.0, (_now() - f).total_seconds() / 86400.0))
            except ValueError:
                days_obs = 1.0
        cold = n < 20 or days_obs < 3
        daily = _f("cold_start_daily_views", 200) if cold else (n / days_obs) * _f("views_per_tx", 2)
        try:
            backlog = c.execute("SELECT COALESCE(SUM(impressions_purchased - impressions_delivered),0) FROM receipt_promos "
                                "WHERE source='sponsored' AND status='approved' "
                                "AND impressions_purchased > impressions_delivered").fetchone()[0]
        except Exception:
            backlog = 0
        reserved = c.execute("SELECT COALESCE(SUM(views_total - views_used),0) FROM boost_ads "
                             "WHERE status IN ('pending','approved','paused')").fetchone()[0]
        uids = [r[0] for r in c.execute("SELECT DISTINCT user_id FROM ad_credit_ledger LIMIT 20000").fetchall()]
    finally:
        c.close()
    now_iso = _iso()
    in_wallets = 0
    for uid in uids:
        try:
            st = _state(uid, now_iso)
            in_wallets += st["available"] + st["held"]
        except Exception:
            pass
    horizon = _f("expiry_days", 90)
    pool = max(0.0, daily * horizon - float(backlog or 0)) * _f("boost_share_cap", 30) / 100.0
    liability = in_wallets + int(reserved or 0)
    headroom = pool - liability
    mult = 0.0 if headroom <= 0 else min(1.0, headroom / max(1.0, 0.25 * pool))
    out = {"daily_views_forecast": round(daily, 1), "using_cold_start": bool(cold), "fulfilled_14d": n,
           "paid_backlog_views": int(backlog or 0), "pool_views": int(pool), "in_wallets": int(in_wallets),
           "reserved_in_boost_ads": int(reserved or 0), "outstanding_views": int(liability),
           "headroom_views": int(headroom), "multiplier": round(mult, 3)}
    _cache.update(meter=out, meter_t=time.time())
    return out


# ------------------------------------------------------------------ earning
def _bucket(tag, user_id):
    return zlib.crc32(f"{tag}:{user_id}".encode()) % 100


def eligible_user(user_id):
    """Rollout and holdout: deterministic per user so a person is always in the same group."""
    if _bucket("rollout", user_id) >= _i("rollout_pct", 100):
        return False
    if _bucket("holdout", user_id) < _i("holdout_pct", 0):
        return False
    return True


def award_for_reference(reference):
    """Called when a transaction is marked fulfilled. Idempotent. Never raises."""
    out = {"awarded": False, "views": 0, "reason": None}
    try:
        if not enabled() or not reference:
            out["reason"] = "disabled"
            return out
        c = _conn()
        try:
            tx = c.execute("SELECT user_id, tx_type, amount, currency, status FROM transactions WHERE reference = ?",
                           (reference,)).fetchone()
        finally:
            c.close()
        if not tx or tx["status"] != "fulfilled" or not tx["user_id"]:
            out["reason"] = "not_fulfilled"
            return out
        service = EARN_SERVICES.get(str(tx["tx_type"] or "").lower())
        if not service:
            out["reason"] = "service_not_eligible"
            return out
        if str(tx["currency"] or "NGN").upper() != "NGN":
            out["reason"] = "currency"
            return out
        amount = float(tx["amount"] or 0)
        if amount < _f("min_amount_ngn", 500):
            out["reason"] = "below_minimum"
            return out
        uid = int(tx["user_id"])
        if not eligible_user(uid):
            out["reason"] = "not_in_rollout"
            return out
        pct = _earn_pct().get(service, 0.0)
        fee = amount * _f("fee_estimate_pct", 2.5) / (100.0 + _f("fee_estimate_pct", 2.5))
        base = fee * pct / 100.0 / max(0.1, _f("view_value_ngn", 1))
        mult = meter()["multiplier"]
        views = int(base * mult)
        if views < 1 and base > 0 and mult >= 0.5:
            views = 1
        if views < 1:
            out["reason"] = "meter_limit" if mult < 0.5 else "too_small"
            return out
        today = _now().strftime("%Y-%m-%d")
        c = _conn()
        try:
            got = c.execute("SELECT COALESCE(SUM(views),0) FROM ad_credit_ledger WHERE user_id = ? AND kind='earn' "
                            "AND created_at >= ?", (uid, today)).fetchone()[0]
            views = min(views, max(0, _i("daily_cap", 50) - int(got)))
            if views < 1:
                out["reason"] = "daily_cap"
                return out
            now = _now()
            cur = c.execute(
                "INSERT OR IGNORE INTO ad_credit_ledger (user_id, kind, views, reference, note, created_at, available_at, expires_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (uid, "earn", views, reference, f"{service} payment", _iso(now),
                 _iso(now + timedelta(hours=_i("hold_hours", 48))), _iso(now + timedelta(days=_i("expiry_days", 90)))))
            _commit(c)
            if cur.rowcount:
                out.update(awarded=True, views=views, reason="ok")
            else:
                out["reason"] = "already_awarded"
        finally:
            c.close()
        return out
    except Exception:
        logger.warning("adcredits: award failed", exc_info=True)
        out["reason"] = "error"
        return out


def reverse_for_reference(reference, reason="refund"):
    """Cancel the credit earned by a transaction that was refunded. Idempotent. Never raises."""
    try:
        if not _ready or not reference:
            return False
        c = _conn()
        try:
            e = c.execute("SELECT id, user_id, views FROM ad_credit_ledger WHERE kind='earn' AND reference = ?",
                          (reference,)).fetchone()
            if not e:
                return False
            cur = c.execute(
                "INSERT OR IGNORE INTO ad_credit_ledger (user_id, kind, views, reference, ref_earn_id, note, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (e["user_id"], "reverse", -int(e["views"]), reference, e["id"], reason, _iso()))
            _commit(c)
            _cache["meter_t"] = 0.0
            return cur.rowcount > 0
        finally:
            c.close()
    except Exception:
        logger.warning("adcredits: reverse failed", exc_info=True)
        return False


# ------------------------------------------------------------------ Boost ads
_URL_OK = re.compile(r"^https://[^\s<>\"']{4,500}$", re.I)


def _blocked_hit(*texts):
    words = [w for w in str(settings().get("blocked_words") or "").split(",") if w]
    blob = " ".join(str(t or "") for t in texts).lower()
    for w in words:
        if w and w in blob:
            return w
    return None


def create_boost(user_id, data):
    """Spend views on a new Boost ad. Returns (ok, error_or_None, boost_id)."""
    if not enabled():
        return False, "Ad credits are not switched on yet.", None
    title = str(data.get("title") or "").strip()
    body = str(data.get("body") or "").strip()
    cta_text = str(data.get("cta_text") or "").strip()
    cta_url = str(data.get("cta_url") or "").strip()
    name = str(data.get("business_name") or "").strip()
    city = str(data.get("city") or "").strip()
    cert = str(data.get("arcon_cert") or "").strip()[:60]
    try:
        views = int(data.get("views"))
    except (TypeError, ValueError):
        return False, "Enter how many views to spend.", None
    if not (5 <= len(title) <= 80):
        return False, "Title must be 5 to 80 characters.", None
    if not (20 <= len(body) <= 240):
        return False, "Message must be 20 to 240 characters.", None
    if len(cta_text) > 24:
        return False, "Button text can be at most 24 characters.", None
    if not _URL_OK.match(cta_url):
        return False, "The link must start with https://", None
    if not (2 <= len(name) <= 60):
        return False, "Enter your business name (2 to 60 characters).", None
    if not data.get("compliance_ack"):
        return False, "Please confirm your ad follows Nigerian advertising rules.", None
    hit = _blocked_hit(title, body, name)
    if hit:
        return False, f"This kind of ad is not allowed on Net365 (\"{hit}\").", None
    lo, hi = _i("boost_min_views", 20), _i("boost_max_views", 2000)
    if not (lo <= views <= hi):
        return False, f"Spend between {lo} and {hi} views on one ad.", None
    allowed = _cities()
    if city:
        if allowed and _norm(city) not in [_norm(x) for x in allowed]:
            return False, "Boost ads are not available in that city yet. Available: " + ", ".join(allowed), None
    else:
        if str(settings().get("boost_allow_national")) != "1":
            return False, "Please choose the city your ad is for.", None
    status = "pending"
    if settings().get("boost_approval") == "auto":
        status = "approved"
    c = _conn()
    try:
        c.execute("BEGIN IMMEDIATE")
        active = c.execute("SELECT COUNT(*) FROM boost_ads WHERE user_id=? AND status IN ('pending','approved','paused')",
                           (user_id,)).fetchone()[0]
        if active >= _i("max_active_boosts", 3):
            c.execute("ROLLBACK")
            return False, "You already have the maximum number of active Boost ads.", None
        st = _state(user_id)          # read through another connection; the write lock above keeps it consistent
        if st["available"] < views:
            c.execute("ROLLBACK")
            return False, f"You have {st['available']} views available.", None
        now = _iso()
        cur = c.execute(
            "INSERT INTO boost_ads (user_id, business_name, title, body, cta_text, cta_url, city, views_total, status, "
            "compliance_ack_at, arcon_cert, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (user_id, name, title, body, cta_text or "Learn more", cta_url, city, views, status, now, cert or None, now))
        bid = cur.lastrowid
        c.execute("INSERT INTO ad_credit_ledger (user_id, kind, views, reference, note, created_at) VALUES (?,?,?,?,?,?)",
                  (user_id, "spend", -views, f"boost:{bid}", f"Boost ad #{bid}", now))
        _commit(c)
        _cache["meter_t"] = 0.0
        return True, None, bid
    except Exception:
        try:
            c.execute("ROLLBACK")
        except Exception:
            pass
        logger.warning("adcredits: create_boost failed", exc_info=True)
        return False, "Could not create the ad. Please try again.", None
    finally:
        try:
            c.close()
        except Exception:
            pass


def _release_unused(c, boost):
    """Give the unused views of a Boost ad back to its owner."""
    left = int(boost["views_total"]) - int(boost["views_used"])
    if left > 0:
        now = _now()
        c.execute("INSERT OR IGNORE INTO ad_credit_ledger (user_id, kind, views, reference, note, created_at, available_at, expires_at) "
                  "VALUES (?,?,?,?,?,?,?,?)",
                  (boost["user_id"], "release", left, f"boostrel:{boost['id']}", f"Unused views, Boost ad #{boost['id']}",
                   _iso(now), _iso(now), _iso(now + timedelta(days=_i("expiry_days", 90)))))
    return left


def set_boost_status(boost_id, new_status, by="admin", reason=None, owner_id=None):
    """approve | reject | pause | resume | cancel. Returns (ok, error)."""
    c = _conn()
    try:
        b = c.execute("SELECT * FROM boost_ads WHERE id = ?", (boost_id,)).fetchone()
        if not b or (owner_id is not None and b["user_id"] != owner_id):
            return False, "Ad not found."
        cur, now = b["status"], _iso()
        if new_status == "approved" and cur in ("pending", "paused"):
            c.execute("UPDATE boost_ads SET status='approved', reviewed_at=?, reviewed_by=?, reject_reason=NULL WHERE id=?",
                      (now, by, boost_id))
        elif new_status == "rejected" and cur in ("pending", "approved", "paused"):
            _release_unused(c, b)
            c.execute("UPDATE boost_ads SET status='rejected', reject_reason=?, reviewed_at=?, reviewed_by=? WHERE id=?",
                      ((reason or "Not approved")[:200], now, by, boost_id))
        elif new_status == "paused" and cur == "approved":
            c.execute("UPDATE boost_ads SET status='paused' WHERE id=?", (boost_id,))
        elif new_status == "resume" and cur == "paused":
            c.execute("UPDATE boost_ads SET status='approved' WHERE id=?", (boost_id,))
        elif new_status == "cancelled" and cur in ("pending", "approved", "paused"):
            _release_unused(c, b)
            c.execute("UPDATE boost_ads SET status='cancelled' WHERE id=?", (boost_id,))
        else:
            return False, f"Cannot do that to an ad that is {cur}."
        _commit(c)
        _cache["meter_t"] = 0.0
        return True, None
    finally:
        c.close()


# ------------------------------------------------------------------ serving
def viewer_city(user_id=None, ip=None):
    """Best known city: what we last saw for this user, else for this IP. Imprecise on mobile networks."""
    try:
        c = _conn()
        try:
            if user_id:
                r = c.execute("SELECT city FROM visitor_logs WHERE user_id = ? AND city IS NOT NULL AND city != '' "
                              "ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
                if r and r[0]:
                    return str(r[0])
            if ip:
                r = c.execute("SELECT city FROM visitor_logs WHERE ip_address = ? AND city IS NOT NULL AND city != '' "
                              "ORDER BY id DESC LIMIT 1", (ip,)).fetchone()
                if r and r[0]:
                    return str(r[0])
        finally:
            c.close()
    except Exception:
        pass
    return None


def _tracked(surface, ad_id, reference, src):
    try:
        import net365_adengine as ae
        return ae.tracked_url(surface, ad_id, reference, ad_source=src)
    except Exception:
        return ""


def _record(surface, src, ad_id, reference, ctx):
    try:
        import net365_adengine as ae
        return ae.record_event(surface, src, ad_id, "impression", reference=reference, user_id=ctx.get("user_id"),
                               tx_type=ctx.get("tx_type"), amount=ctx.get("amount"), city=ctx.get("city"))
    except Exception:
        return True   # tracking unavailable: do not block serving


def _existing_boost_for(surface, reference):
    if not reference:
        return None
    try:
        c = _conn()
        try:
            r = c.execute("SELECT ad_id FROM ad_events WHERE surface=? AND ad_source='boost' AND event='impression' "
                          "AND reference=? LIMIT 1", (surface, reference)).fetchone()
            return int(r[0]) if r else None
        finally:
            c.close()
    except Exception:
        return None


def _boost_by_id(bid):
    c = _conn()
    try:
        r = c.execute("SELECT * FROM boost_ads WHERE id = ?", (bid,)).fetchone()
        return dict(r) if r else None
    finally:
        c.close()


def pick_boost(surface, ctx):
    """Choose a Boost ad for this view and use up one of its views. Returns the ad row (dict) or None."""
    try:
        if not enabled():
            return None
        key = "boost_on_success" if surface == "success" else "boost_on_email"
        if str(settings().get(key)) != "1":
            return None
        ref = ctx.get("reference")
        prior = _existing_boost_for(surface, ref)       # page refresh: same ad, no extra view used
        if prior:
            b = _boost_by_id(prior)
            return b if b and b["status"] in ("approved", "completed") else None
        city = ctx.get("city") or (viewer_city(ctx.get("user_id")) if ctx.get("user_id") else None)
        pilot = [_norm(x) for x in _cities()]
        unknown_show = settings().get("unknown_location") == "show"
        if pilot and (not city or _norm(city) not in pilot):
            if not (not city and unknown_show):
                return None
        c = _conn()
        try:
            rows = c.execute("SELECT * FROM boost_ads WHERE status='approved' AND views_used < views_total "
                             "ORDER BY (views_used * 1.0 / views_total) ASC, id ASC LIMIT 50").fetchall()
            viewer = ctx.get("user_id")
            cap = _i("freq_cap", 3)
            today = _now().strftime("%Y-%m-%d")
            for r in rows:
                if viewer and r["user_id"] == viewer:
                    continue                                      # never show a business its own ad
                if r["city"]:
                    if city:
                        if _norm(city) != _norm(r["city"]):
                            continue
                    elif not unknown_show:
                        continue
                if viewer:
                    try:
                        seen = c.execute("SELECT COUNT(*) FROM ad_events WHERE ad_source='boost' AND ad_id=? "
                                         "AND user_id=? AND event='impression' AND ts >= ?",
                                         (r["id"], viewer, today)).fetchone()[0]
                        if seen >= cap:
                            continue
                    except Exception:
                        pass
                is_new = _record(surface, "boost", r["id"], ref, ctx)
                if is_new:
                    cur = c.execute("UPDATE boost_ads SET views_used = views_used + 1 WHERE id = ? AND views_used < views_total",
                                    (r["id"],))
                    if cur.rowcount:
                        c.execute("UPDATE boost_ads SET status='completed' WHERE id=? AND views_used >= views_total",
                                  (r["id"],))
                    _commit(c)
                d = dict(r)
                return d
        finally:
            c.close()
    except Exception:
        logger.warning("adcredits: pick_boost failed", exc_info=True)
    return None


def _boost_as_success_ad(b, reference):
    return {"id": -int(b["id"]), "headline": b["title"], "subheadline": b.get("business_name") or "",
            "body": b["body"], "cta_text": b.get("cta_text") or "Learn more",
            "cta_url": _tracked("success", b["id"], reference, "boost") or b["cta_url"],
            "cta_action": "", "advertiser_name": b.get("business_name") or "", "sponsored": False, "boost": True}


def _paid_for_success(level, ctx):
    """A paid Marketplace campaign for the success page. level: sponsored | all. Returns (ad_dict, tier) or None."""
    reference = ctx.get("reference")
    c = _conn()
    try:
        rows = c.execute("SELECT * FROM receipt_promos WHERE source='sponsored' AND status='approved' "
                         "AND campaign_tier IN ('dominant','basic') AND impressions_delivered < impressions_purchased "
                         "ORDER BY CASE campaign_tier WHEN 'dominant' THEN 0 ELSE 1 END, impressions_delivered ASC, id ASC").fetchall()
        for r in rows:
            tier = r["campaign_tier"]
            if level == "sponsored" and tier != "dominant":
                continue
            if tier != "dominant":
                if r["target_tx_type"] and str(ctx.get("tx_type") or "").lower() != str(r["target_tx_type"]).lower():
                    continue
                amt = ctx.get("amount")
                if r["target_min_amount"] is not None and (amt is None or amt < r["target_min_amount"]):
                    continue
                if r["target_max_amount"] is not None and (amt is None or amt > r["target_max_amount"]):
                    continue
            is_new = _record("success", "promo", r["id"], reference, ctx)
            if is_new:
                c.execute("UPDATE receipt_promos SET impressions_delivered = impressions_delivered + 1 WHERE id = ?", (r["id"],))
                _commit(c)
            ad = {"id": -int(r["id"]), "headline": r["title"], "subheadline": "", "body": r["body"],
                  "cta_text": r["cta_text"] or "Learn more",
                  "cta_url": _tracked("success", r["id"], reference, "promo") or (r["cta_url"] or ""),
                  "cta_action": "", "advertiser_name": "", "sponsored": True}
            return ad, tier
    finally:
        c.close()
    return None


def fill_success_slots(ads, ctx):
    """Add paid and Boost ads to the success page slots. Paid first, then Boost. Never raises."""
    ads = dict(ads or {})
    try:
        if not _ready:
            return ads
        try:
            import net365_adserve as _se
            if _se.active():
                return _se.serve_success(ads, ctx)          # Phase 3: priority, caps and rules
        except ImportError:
            pass
        level = settings().get("paid_on_success", "off")
        if level in ("sponsored", "all"):
            got = _paid_for_success(level, ctx)
            if got:
                ad, tier = got
                if tier == "dominant":
                    if ads.get("primary") and not ads.get("secondary"):
                        ads["secondary"] = ads["primary"]
                    ads["primary"] = ad
                elif not ads.get("secondary"):
                    ads["secondary"] = ad
                elif not ads.get("tertiary"):
                    ads["tertiary"] = ad
        if enabled() and (not ads.get("secondary") or not ads.get("tertiary")):
            b = pick_boost("success", ctx)
            if b:
                ad = _boost_as_success_ad(b, ctx.get("reference"))
                if not ads.get("secondary"):
                    ads["secondary"] = ad
                else:
                    ads["tertiary"] = ad
    except Exception:
        logger.warning("adcredits: fill_success_slots failed", exc_info=True)
    return ads


def email_promo(promo, ctx):
    """For receipt emails: a Boost ad replaces an empty or house promo. Paid campaigns keep first claim."""
    try:
        try:
            import net365_adserve as _se
            if _se.active():
                return _se.serve_email(promo, ctx)           # Phase 3
        except ImportError:
            pass
        if not enabled():
            return promo
        if promo and str(promo.get("source") or "house") != "house":
            return promo
        b = pick_boost("email", ctx)
        if not b:
            return promo
        return {"id": b["id"], "title": b["title"], "body": b["body"], "cta_text": b.get("cta_text") or "Learn more",
                "cta_url": _tracked("email", b["id"], ctx.get("reference"), "boost") or b["cta_url"],
                "source": "boost", "_boost": True}
    except Exception:
        return promo


# ------------------------------------------------------------------ admin totals
def totals():
    c = _conn()
    try:
        uids = [r[0] for r in c.execute("SELECT DISTINCT user_id FROM ad_credit_ledger LIMIT 20000").fetchall()]
        spent_views_used = c.execute("SELECT COALESCE(SUM(views_used),0) FROM boost_ads").fetchone()[0]
        pending = c.execute("SELECT COUNT(*) FROM boost_ads WHERE status='pending'").fetchone()[0]
        live = c.execute("SELECT COUNT(*) FROM boost_ads WHERE status='approved'").fetchone()[0]
    finally:
        c.close()
    now_iso = _iso()
    agg = {"earned": 0, "spent": 0, "reversed": 0, "expired": 0, "available": 0, "held": 0, "debt": 0}
    for uid in uids:
        st = _state(uid, now_iso)
        for k in agg:
            agg[k] += st[k]
    agg.update(users_with_credits=len(uids), boost_views_shown=int(spent_views_used), boost_pending=int(pending),
               boost_live=int(live))
    return agg


# ------------------------------------------------------------------ routes
def _public_boost(b):
    return {k: b[k] for k in ("id", "business_name", "title", "body", "cta_text", "cta_url", "city", "views_total",
                              "views_used", "status", "reject_reason", "created_at")}


def init_adcredits(app, db, admin_required, login_required):
    global _db, _ready
    _db = db
    try:
        _ensure_schema()
        _ready = True
    except Exception:
        logger.exception("adcredits: schema setup failed; credits disabled")
        return
    try:
        from net365_adserve import init_adserve
        init_adserve(app, admin_required)
    except ImportError:
        logger.info("adserve module not installed; Phase 2 serving only")
    except Exception:
        logger.exception("adserve: init failed; Phase 2 serving only")

    @app.get("/api/adcredits/me")
    @login_required
    def adcredits_me():
        uid = g.current_user_id
        st = balance(uid)
        c = _conn()
        try:
            led = [dict(r) for r in c.execute(
                "SELECT kind, views, note, created_at, available_at, expires_at FROM ad_credit_ledger "
                "WHERE user_id=? ORDER BY id DESC LIMIT 20", (uid,)).fetchall()]
            boosts = [_public_boost(r) for r in c.execute(
                "SELECT * FROM boost_ads WHERE user_id=? ORDER BY id DESC LIMIT 50", (uid,)).fetchall()]
        finally:
            c.close()
        s = settings()
        return jsonify(success=True, enabled=enabled(), balance=st, ledger=led, boosts=boosts,
                       config={"cities": _cities(), "allow_national": s.get("boost_allow_national") == "1",
                               "min_views": _i("boost_min_views", 20), "max_views": _i("boost_max_views", 2000),
                               "hold_hours": _i("hold_hours", 48), "expiry_days": _i("expiry_days", 90),
                               "approval": s.get("boost_approval")})

    @app.post("/api/adcredits/boost")
    @login_required
    def adcredits_boost_create():
        ok, err, bid = create_boost(g.current_user_id, request.get_json(silent=True) or {})
        if not ok:
            return jsonify(success=False, error=err), 400
        return jsonify(success=True, boost_id=bid, balance=balance(g.current_user_id),
                       message="Your Boost ad was submitted for review." if settings().get("boost_approval") == "admin"
                       else "Your Boost ad is live.")

    @app.post("/api/adcredits/boost/<int:bid>/<action>")
    @login_required
    def adcredits_boost_action(bid, action):
        m = {"pause": "paused", "resume": "resume", "cancel": "cancelled"}
        if action not in m:
            return jsonify(success=False, error="Unknown action"), 400
        ok, err = set_boost_status(bid, m[action], by=f"user:{g.current_user_id}", owner_id=g.current_user_id)
        if not ok:
            return jsonify(success=False, error=err), 400
        return jsonify(success=True, balance=balance(g.current_user_id))

    @app.get("/api/admin/adcredits/overview")
    @admin_required
    def adcredits_admin_overview():
        try:
            s = dict(settings(force=True))
            s["earn_pct"] = _earn_pct()
            return jsonify(success=True, settings=s, meter=meter(force=True), totals=totals(), services=list(SERVICE_NAMES))
        except Exception as e:
            logger.exception("adcredits overview failed")
            return jsonify(success=False, error=str(e)), 500

    @app.post("/api/admin/adcredits/settings")
    @admin_required
    def adcredits_admin_settings():
        ok, err, saved = save_settings(request.get_json(silent=True) or {})
        if not ok:
            return jsonify(success=False, error=err), 400
        logger.warning("ADCREDITS: settings changed %s", list(saved.keys()))
        return jsonify(success=True, saved=saved)

    @app.get("/api/admin/adcredits/user")
    @admin_required
    def adcredits_admin_user():
        q = str(request.args.get("q") or "").strip()
        if not q:
            return jsonify(success=False, error="Enter a user id or email"), 400
        c = _conn()
        try:
            r = c.execute("SELECT id, email FROM users WHERE id = ? OR lower(email) = lower(?) LIMIT 1",
                          (int(q) if q.isdigit() else -1, q)).fetchone()
            if not r:
                return jsonify(success=False, error="User not found"), 404
            led = [dict(x) for x in c.execute(
                "SELECT id, kind, views, reference, note, created_at, available_at, expires_at FROM ad_credit_ledger "
                "WHERE user_id=? ORDER BY id DESC LIMIT 100", (r["id"],)).fetchall()]
        finally:
            c.close()
        return jsonify(success=True, user={"id": r["id"], "email": r["email"]}, balance=balance(r["id"]), ledger=led)

    @app.post("/api/admin/adcredits/reverse")
    @admin_required
    def adcredits_admin_reverse():
        ref = str((request.get_json(silent=True) or {}).get("reference") or "").strip()
        if not ref:
            return jsonify(success=False, error="Reference required"), 400
        ok = reverse_for_reference(ref, "manual reversal by admin")
        return jsonify(success=ok, error=None if ok else "Nothing to reverse for that reference (not found, or already reversed)")

    @app.get("/api/admin/adcredits/boost")
    @admin_required
    def adcredits_admin_boost_list():
        status = str(request.args.get("status") or "pending")
        c = _conn()
        try:
            sql = ("SELECT b.*, u.email AS owner_email FROM boost_ads b LEFT JOIN users u ON u.id = b.user_id "
                   + ("" if status == "all" else "WHERE b.status = ? ") + "ORDER BY b.id DESC LIMIT 100")
            rows = c.execute(sql, () if status == "all" else (status,)).fetchall()
            out = []
            for r in rows:
                d = _public_boost(r)
                d.update(owner_email=r["owner_email"], arcon_cert=r["arcon_cert"], compliance_ack_at=r["compliance_ack_at"])
                out.append(d)
        finally:
            c.close()
        return jsonify(success=True, boosts=out)

    @app.post("/api/admin/adcredits/boost/<int:bid>/<action>")
    @admin_required
    def adcredits_admin_boost_action(bid, action):
        m = {"approve": "approved", "reject": "rejected", "pause": "paused", "resume": "resume", "cancel": "cancelled"}
        if action not in m:
            return jsonify(success=False, error="Unknown action"), 400
        reason = (request.get_json(silent=True) or {}).get("reason")
        ok, err = set_boost_status(bid, m[action], by="admin", reason=reason)
        if not ok:
            return jsonify(success=False, error=err), 400
        return jsonify(success=True)

    logger.info("Ad credits module ready (enabled=%s)", enabled())

"""
net365_adengine.py - Phase 1: ad event tracking for every surface (email, receipt, success page, mobile).

What this phase does (and only this):
  * One table, ad_events, records every ad view and click with the context it happened in
    (service type, amount band, hour, country, city, device). Nothing else in the app changes behaviour.
  * Email ads get a tracked link: /r/ad/email/<ad_id>. The destination is ALWAYS read from the database,
    never from the URL, so it cannot be used as an open redirect.
  * Admin gets a read-only summary: views, clicks and click rate per surface, plus the top ads.

Design rules:
  * Tracking must never break a payment, a receipt or an email. Every public function swallows errors.
  * A view is recorded once per (surface, source, ad, transaction reference). Refreshing the success page
    does not create extra views.
  * This module does not change which ad is shown. Selection is untouched until a later phase.

Wire-up (in app.py, next to init_rewards):
    from net365_adengine import init_adengine
    init_adengine(self.app, db, admin_required, FRONTEND_URL)
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from flask import jsonify, redirect, request

logger = logging.getLogger(__name__)

SURFACES = ("email", "receipt", "success", "mobile")
SOURCES = ("promo", "success", "boost")      # promo = receipt_promos table, success = success_page_ads table
EVENTS = ("impression", "click")

_db = None
_frontend_url = ""
_ready = False


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn():
    return _db.get_db_connection()


def enabled():
    """Tracking is on unless ADENGINE_TRACKING=0 is set. Lets you switch it off without removing code."""
    return os.getenv("ADENGINE_TRACKING", "1").strip().lower() not in ("0", "false", "no", "off")


def amount_band(amount):
    """Coarse amount bucket so context is useful without storing exact amounts."""
    try:
        a = float(amount)
    except (TypeError, ValueError):
        return None
    if a < 1000:
        return "under_1k"
    if a < 5000:
        return "1k_5k"
    if a < 20000:
        return "5k_20k"
    if a < 100000:
        return "20k_100k"
    return "100k_plus"


def _ensure_schema():
    c = _conn()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS ad_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            surface TEXT NOT NULL,
            ad_source TEXT NOT NULL,
            ad_id INTEGER NOT NULL,
            event TEXT NOT NULL,
            reference TEXT,
            user_id INTEGER,
            tx_type TEXT,
            amount_band TEXT,
            hour INTEGER,
            country TEXT,
            city TEXT,
            device TEXT)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ad_events_ts ON ad_events(ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ad_events_ad ON ad_events(ad_source, ad_id, event)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ad_events_surface ON ad_events(surface, event, ts)")
        # One impression per ad per transaction per surface. Clicks are not deduplicated.
        c.execute("""CREATE UNIQUE INDEX IF NOT EXISTS uq_ad_events_impression
                     ON ad_events(surface, ad_source, ad_id, reference)
                     WHERE event = 'impression' AND reference IS NOT NULL""")
        c.commit()
    finally:
        c.close()


def record_event(surface, ad_source, ad_id, event, reference=None, user_id=None, tx_type=None,
                 amount=None, hour=None, country=None, city=None, device=None):
    """Record one ad view or click. Returns True if a new row was written. Never raises."""
    try:
        if not enabled() or not _ready:
            return False
        if surface not in SURFACES or ad_source not in SOURCES or event not in EVENTS or not ad_id:
            return False
        if hour is None:
            hour = datetime.now().hour
        c = _conn()
        try:
            cur = c.execute(
                "INSERT OR IGNORE INTO ad_events (ts, surface, ad_source, ad_id, event, reference, user_id, "
                "tx_type, amount_band, hour, country, city, device) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (_now(), surface, ad_source, int(ad_id), event, (str(reference)[:80] if reference else None),
                 user_id, (str(tx_type)[:30] if tx_type else None), amount_band(amount), hour,
                 (str(country)[:8] if country else None), (str(city)[:60] if city else None),
                 (str(device)[:20] if device else None)))
            c.commit()
            return cur.rowcount > 0
        finally:
            c.close()
    except Exception:
        logger.warning("adengine: could not record event", exc_info=True)
        return False


def tracked_url(surface, ad_id, reference=None, ad_source="promo"):
    """Absolute tracked link for an ad's button, or '' if tracking is off or unavailable."""
    try:
        if not enabled() or not _ready or not _frontend_url or not ad_id:
            return ""
        url = f"{_frontend_url}/r/ad/{surface}/{int(ad_id)}"
        q = []
        if ad_source != "promo":
            q.append(f"src={ad_source}")
        if reference:
            from urllib.parse import quote
            q.append(f"ref={quote(str(reference)[:80], safe='')}")
        return url + ("?" + "&".join(q) if q else "")
    except Exception:
        return ""


def track_email_promo(promo, context):
    """Called when an email is about to carry a promo. Records the view and returns the promo with its
    button pointed at the tracked link. If anything is off, returns the promo unchanged."""
    try:
        if not promo or not promo.get("id") or not enabled() or not _ready or promo.get("_boost"):
            return promo      # Boost ads are tracked when they are chosen
        ctx = context or {}
        record_event("email", "promo", promo["id"], "impression",
                     reference=ctx.get("reference"), user_id=ctx.get("user_id"),
                     tx_type=ctx.get("tx_type"), amount=ctx.get("amount"))
        link = tracked_url("email", promo["id"], ctx.get("reference"))
        if link and promo.get("cta_url"):
            promo = dict(promo)
            promo["cta_url"] = link
        return promo
    except Exception:
        return promo


def _destination(ad_source, ad_id):
    """The real destination, read from the database. Returns '' if the ad has none."""
    c = _conn()
    try:
        if ad_source == "promo":
            row = c.execute("SELECT cta_url FROM receipt_promos WHERE id = ?", (ad_id,)).fetchone()
        elif ad_source == "success":
            row = c.execute("SELECT cta_url FROM success_page_ads WHERE id = ?", (ad_id,)).fetchone()
        elif ad_source == "boost":
            row = c.execute("SELECT cta_url FROM boost_ads WHERE id = ? AND status IN ('approved','completed','paused')",
                            (ad_id,)).fetchone()
        else:
            return ""
        return (row[0] or "").strip() if row else ""
    finally:
        c.close()


def _safe_target(url):
    """Only https links, or a path on our own site. Anything else goes to the home page."""
    url = (url or "").strip()
    if url.startswith("https://"):
        return url
    if url.startswith("/") and not url.startswith("//"):
        return f"{_frontend_url}{url}"
    return _frontend_url or "/"


def summary(days=7):
    """Views, clicks and click rate per surface, plus the top ads. Plain numbers from the table."""
    days = max(1, min(int(days or 7), 365))
    c = _conn()
    try:
        since = f"-{days} days"
        rows = c.execute(
            "SELECT surface, "
            "SUM(CASE WHEN event='impression' THEN 1 ELSE 0 END) AS views, "
            "SUM(CASE WHEN event='click' THEN 1 ELSE 0 END) AS clicks "
            "FROM ad_events WHERE ts >= datetime('now', ?) GROUP BY surface", (since,)).fetchall()
        by_surface = {s: {"views": 0, "clicks": 0, "click_rate": None} for s in SURFACES}
        for r in rows:
            v, k = int(r["views"] or 0), int(r["clicks"] or 0)
            by_surface[r["surface"]] = {"views": v, "clicks": k,
                                        "click_rate": round(100.0 * k / v, 2) if v else None}
        top = c.execute(
            "SELECT surface, ad_source, ad_id, "
            "SUM(CASE WHEN event='impression' THEN 1 ELSE 0 END) AS views, "
            "SUM(CASE WHEN event='click' THEN 1 ELSE 0 END) AS clicks "
            "FROM ad_events WHERE ts >= datetime('now', ?) GROUP BY surface, ad_source, ad_id "
            "ORDER BY views DESC LIMIT 15", (since,)).fetchall()
        top_ads = []
        for r in top:
            v, k = int(r["views"] or 0), int(r["clicks"] or 0)
            title = None
            try:
                tbl = {"promo": "receipt_promos", "boost": "boost_ads"}.get(r["ad_source"], "success_page_ads")
                t = c.execute(f"SELECT title FROM {tbl} WHERE id = ?", (r["ad_id"],)).fetchone()
                title = t[0] if t else None
            except Exception:
                pass
            top_ads.append({"surface": r["surface"], "source": r["ad_source"], "ad_id": r["ad_id"],
                            "title": title, "views": v, "clicks": k,
                            "click_rate": round(100.0 * k / v, 2) if v else None})
        total = c.execute("SELECT COUNT(*) FROM ad_events").fetchone()[0]
        return {"days": days, "by_surface": by_surface, "top_ads": top_ads, "total_events": int(total),
                "tracking_enabled": enabled()}
    finally:
        c.close()


def init_adengine(app, db, admin_required, frontend_url=""):
    global _db, _frontend_url, _ready
    _db = db
    _frontend_url = (frontend_url or "").rstrip("/")
    try:
        _ensure_schema()
        _ready = True
    except Exception:
        logger.exception("adengine: schema setup failed; tracking disabled")
        return

    @app.get("/r/ad/<surface>/<int:ad_id>")
    def adengine_click(surface, ad_id):
        src = request.args.get("src", "promo")
        if surface not in SURFACES or src not in SOURCES:
            return redirect(_frontend_url or "/", code=302)
        try:
            target = _safe_target(_destination(src, ad_id))
        except Exception:
            target = _frontend_url or "/"
        record_event(surface, src, ad_id, "click", reference=request.args.get("ref"))
        resp = redirect(target, code=302)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.get("/api/admin/adengine/summary")
    @admin_required
    def adengine_summary():
        try:
            return jsonify(success=True, **summary(request.args.get("days", 7)))
        except Exception as e:
            logger.exception("adengine summary failed")
            return jsonify(success=False, error=str(e)), 500

    logger.info("Ad engine tracking ready (surfaces: %s)", ", ".join(SURFACES))

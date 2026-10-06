"""
NET365 SMART MEDIA / ADS ENGINE
Drop-in Flask + SQLite module.

Integration:
    from net365_ads_backend import ads_bp, init_ads_db
    app.register_blueprint(ads_bp)
    init_ads_db("/mnt/data/net365.db")

This module is intentionally independent of the existing recharge/payment code.
The /api/ads/recommend endpoint is server-driven; mobile.html does not contain
advertiser-selection logic.
"""

from flask import Blueprint, jsonify, request, session
import sqlite3
import json
from datetime import datetime, timezone

ads_bp = Blueprint("net365_ads", __name__)

DEFAULT_ADS = [
    {
        "id": "demo-smartphone-25",
        "campaign_id": "demo-electronics-001",
        "type": "sponsored_offer",
        "category": "electronics",
        "badge": "SMART OFFER",
        "sponsored": True,
        "accent": "#7C3AED",
        "accent2": "#22D3EE",
        "icon": "fa-mobile-screen-button",
        "kicker": "Because you recently recharged",
        "title": "Save up to 25% on selected smartphones",
        "description": "Discover device offers from participating merchants.",
        "offer_value": "25% OFF",
        "offer_label": "Selected smartphones",
        "cta": "Explore Phones",
        "footer": "Sponsored offer",
        "landing_url": "#",
        "tx_types": ["topup"],
        "countries": [],
        "currencies": [],
        "operator_ids": [],
        "priority": 50,
    },
    {
        "id": "demo-solar-15",
        "campaign_id": "demo-energy-001",
        "type": "sponsored_offer",
        "category": "energy",
        "badge": "SMART ENERGY",
        "sponsored": True,
        "accent": "#F59E0B",
        "accent2": "#22D3EE",
        "icon": "fa-solar-panel",
        "kicker": "Because you recently paid a utility bill",
        "title": "Save on solar & backup power",
        "description": "Explore participating solar, inverter and battery offers.",
        "offer_value": "15% OFF",
        "offer_label": "Selected energy solutions",
        "cta": "Explore Solar",
        "footer": "Sponsored offer",
        "landing_url": "#",
        "tx_types": ["utility"],
        "countries": ["NG"],
        "currencies": ["NGN"],
        "operator_ids": [],
        "priority": 60,
    },
    {
        "id": "demo-net365-data",
        "campaign_id": "net365-cross-service-001",
        "type": "smart_offer",
        "category": "connectivity",
        "badge": "NET365 PICK",
        "sponsored": False,
        "accent": "#22D3EE",
        "accent2": "#7C3AED",
        "icon": "fa-wifi",
        "kicker": "Keep your connection going",
        "title": "You may need data next",
        "description": "Move from airtime to a data bundle in a few taps.",
        "offer_value": "One-tap recharge",
        "offer_label": "Data bundles",
        "cta": "Browse Data",
        "footer": "Net365 recommendation",
        "landing_url": "#",
        "action": "utilities",
        "tx_types": ["topup"],
        "countries": [],
        "currencies": [],
        "operator_ids": [],
        "priority": 40,
    },
]


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def init_ads_db(db_path):
    con = sqlite3.connect(db_path)
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS ad_campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_key TEXT UNIQUE NOT NULL,
                campaign_json TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS ad_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                ad_id TEXT,
                campaign_id TEXT,
                placement TEXT,
                tx_type TEXT,
                amount REAL,
                currency TEXT,
                country TEXT,
                operator_id TEXT,
                operator_name TEXT,
                visitor_id TEXT,
                user_id INTEGER,
                metadata_json TEXT,
                created_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE INDEX IF NOT EXISTS idx_ad_events_campaign
            ON ad_events(campaign_id, event, created_at)
        """)
        con.execute("""
            CREATE INDEX IF NOT EXISTS idx_ad_events_visitor
            ON ad_events(visitor_id, created_at)
        """)
        con.execute("""
            CREATE INDEX IF NOT EXISTS idx_ad_campaigns_active
            ON ad_campaigns(active)
        """)

        now = _utc_now()
        for ad in DEFAULT_ADS:
            con.execute("""
                INSERT OR IGNORE INTO ad_campaigns
                (campaign_key, campaign_json, active, created_at, updated_at)
                VALUES (?, ?, 1, ?, ?)
            """, (ad["id"], json.dumps(ad), now, now))
        con.commit()
    finally:
        con.close()


def _get_db_path():
    # Set NET365_DB_PATH in your app/environment if your database is elsewhere.
    import os
    return os.environ.get("NET365_DB_PATH", "/mnt/data/net365.db")


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).upper() for x in value]
    return [str(value).upper()]


def _campaign_matches(ad, ctx):
    tx_type = str(ctx.get("tx_type") or "").lower()
    country = str(ctx.get("country") or "").upper()
    currency = str(ctx.get("currency") or "").upper()
    operator_id = str(ctx.get("operator_id") or "")

    tx_types = [x.lower() for x in _as_list(ad.get("tx_types"))]
    countries = _as_list(ad.get("countries"))
    currencies = _as_list(ad.get("currencies"))
    operators = [str(x) for x in (ad.get("operator_ids") or [])]

    if tx_types and tx_type not in tx_types:
        return False
    if countries and country not in countries:
        return False
    if currencies and currency not in currencies:
        return False
    if operators and operator_id not in operators:
        return False
    return True


def _score(ad, ctx):
    score = int(ad.get("priority", 0))

    # Contextual relevance boosts.
    if ctx.get("tx_type") in (ad.get("tx_types") or []):
        score += 40
    if ctx.get("country") in (ad.get("countries") or []):
        score += 20
    if ctx.get("currency") in (ad.get("currencies") or []):
        score += 10
    if ctx.get("operator_id") and str(ctx.get("operator_id")) in [str(x) for x in (ad.get("operator_ids") or [])]:
        score += 15

    # Net365 recommendations get a small boost when there is no paid campaign
    # that is more contextually relevant.
    if not ad.get("sponsored"):
        score += 5

    return score


def _recently_shown(con, ad_id, visitor_id, hours=24):
    if not visitor_id:
        return False
    row = con.execute("""
        SELECT 1
        FROM ad_events
        WHERE ad_id = ?
          AND visitor_id = ?
          AND event = 'impression'
          AND created_at >= datetime('now', ?)
        LIMIT 1
    """, (str(ad_id), str(visitor_id), f"-{int(hours)} hours")).fetchone()
    return bool(row)


@ads_bp.post("/api/ads/recommend")
def recommend_ad():
    ctx = request.get_json(silent=True) or {}
    visitor_id = ctx.get("visitor_id")
    con = sqlite3.connect(_get_db_path())
    try:
        rows = con.execute("""
            SELECT campaign_json
            FROM ad_campaigns
            WHERE active = 1
        """).fetchall()

        candidates = []
        for (raw,) in rows:
            try:
                ad = json.loads(raw)
            except Exception:
                continue

            if not _campaign_matches(ad, ctx):
                continue

            if _recently_shown(con, ad.get("id"), visitor_id, 24):
                continue

            ad["_score"] = _score(ad, ctx)
            candidates.append(ad)

        if not candidates:
            return jsonify({"success": False, "error": "no_eligible_ad"}), 404

        candidates.sort(
            key=lambda x: (int(x.get("_score", 0)), int(x.get("priority", 0))),
            reverse=True
        )
        winner = candidates[0]
        winner.pop("_score", None)

        # Never trust an arbitrary client-side user_id as authorization.
        # It is only an analytics hint; the actual logged-in user can be
        # resolved from your existing session/auth layer if desired.
        return jsonify({
            "success": True,
            "ad": winner,
            "context": {
                "placement": ctx.get("placement"),
                "currency": ctx.get("currency"),
                "country": ctx.get("country"),
                "operator_id": ctx.get("operator_id"),
                "tx_type": ctx.get("tx_type")
            }
        })
    finally:
        con.close()


@ads_bp.post("/api/ads/event")
def record_ad_event():
    body = request.get_json(silent=True) or {}
    event = str(body.get("event") or "").lower()

    allowed = {
        "impression", "view", "click", "dismiss", "save", "share",
        "conversion", "conversion_value"
    }
    if event not in allowed:
        return jsonify({"success": False, "error": "invalid_event"}), 400

    con = sqlite3.connect(_get_db_path())
    try:
        con.execute("""
            INSERT INTO ad_events (
                event, ad_id, campaign_id, placement, tx_type, amount,
                currency, country, operator_id, operator_name,
                visitor_id, user_id, metadata_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event,
            body.get("ad_id"),
            body.get("campaign_id"),
            body.get("placement"),
            body.get("tx_type"),
            float(body["amount"]) if body.get("amount") not in (None, "") else None,
            body.get("currency"),
            body.get("country"),
            str(body.get("operator_id")) if body.get("operator_id") is not None else None,
            body.get("operator_name"),
            body.get("visitor_id"),
            # Prefer the authenticated session's user id if your app stores it.
            session.get("user_id") or body.get("user_id"),
            json.dumps(body, separators=(",", ":")),
            _utc_now()
        ))
        con.commit()
        return jsonify({"success": True})
    finally:
        con.close()


@ads_bp.get("/api/ads/health")
def ads_health():
    return jsonify({"success": True, "service": "net365-smart-media"})

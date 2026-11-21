"""
Net365 GEOINT (core slice): voluntary, consent-based customer location for the chat bots.

What it does
  * A customer can SHARE a location in Telegram or WhatsApp, or TYPE a state/country. Nothing is collected unless they
    take that action and have said yes to the consent text (version GEOINT_CONSENT_VERSION).
  * Coordinates are stored COARSE (rounded to 2 decimals, about 1 km). Exact GPS is never stored.
  * Every record carries its source (GPS_TELEGRAM, GPS_WHATSAPP, CUSTOMER_SELECTED), accuracy, timestamps and consent.
  * Country and Nigerian state are derived offline (state = nearest state capital) and labelled approximate. They are a
    hint for relevance (for example which electricity company probably serves you), never proof of where someone is.
  * Live locations: only the FIRST point of a Telegram live location is used. Updates are never requested or tracked.
  * Customers can view, update, revoke consent and delete everything. Revoking or deleting removes the coordinates.
  * Records expire after GEOINT_RETENTION_DAYS (default 90) and only the latest 5 per customer are kept.
  * Admin sees counts only (country/state/source/channel), never coordinates. Every admin read is audited.

What it never does: block or change a payment, use location for fraud decisions, share location with advertisers,
or make location a requirement for any service.
"""
import hashlib
import logging
import math
import os
import re
from datetime import datetime, timedelta

from flask import jsonify, request, g

import net365_whatsapp as W

log = logging.getLogger("net365.geoint")
CONSENT_VERSION = os.getenv("GEOINT_CONSENT_VERSION", "2026-11-v1")
_d = {}
_ready = False

SOURCES = {"telegram": "GPS_TELEGRAM", "whatsapp": "GPS_WHATSAPP", "selected": "CUSTOMER_SELECTED"}
# Relative confidence of each source (documented hierarchy: shared GPS above customer-selected; never "verified")
CONFIDENCE = {"GPS_TELEGRAM": "high", "GPS_WHATSAPP": "high", "CUSTOMER_SELECTED": "low"}

NG_STATES = {  # state: (capital lat, lng) -> nearest capital is the approximate state
    "Abia": (5.53, 7.49), "Adamawa": (9.21, 12.48), "Akwa Ibom": (5.05, 7.93), "Anambra": (6.21, 7.07), "Bauchi": (10.31, 9.84),
    "Bayelsa": (4.92, 6.26), "Benue": (7.73, 8.52), "Borno": (11.83, 13.15), "Cross River": (4.95, 8.33), "Delta": (6.20, 6.73),
    "Ebonyi": (6.32, 8.11), "Edo": (6.34, 5.63), "Ekiti": (7.62, 5.22), "Enugu": (6.46, 7.55), "FCT": (9.06, 7.49),
    "Gombe": (10.29, 11.17), "Imo": (5.49, 7.03), "Jigawa": (11.76, 9.34), "Kaduna": (10.52, 7.44), "Kano": (12.00, 8.52),
    "Katsina": (12.99, 7.60), "Kebbi": (12.45, 4.20), "Kogi": (7.80, 6.74), "Kwara": (8.50, 4.55), "Lagos": (6.52, 3.38),
    "Nasarawa": (8.49, 8.52), "Niger": (9.61, 6.55), "Ogun": (7.16, 3.35), "Ondo": (7.25, 5.19), "Osun": (7.77, 4.56),
    "Oyo": (7.38, 3.95), "Plateau": (9.90, 8.86), "Rivers": (4.82, 7.03), "Sokoto": (13.06, 5.24), "Taraba": (8.89, 11.36),
    "Yobe": (11.75, 11.96), "Zamfara": (12.17, 6.66),
}
ALIASES = {"abuja": "FCT", "fct": "FCT", "federal capital territory": "FCT", "akwaibom": "Akwa Ibom", "cross-river": "Cross River"}
# very coarse boxes (min_lat, max_lat, min_lng, max_lng) for non-Nigerian countries; None of this is precise
BOXES = {"GH": (4.7, 11.2, -3.3, 1.2), "KE": (-4.7, 5.0, 33.9, 41.9), "ZA": (-35.0, -22.0, 16.4, 33.0), "GB": (49.8, 60.9, -8.7, 1.8),
         "US": (24.0, 49.5, -125.0, -66.9), "IN": (6.5, 35.7, 68.0, 97.5), "AE": (22.5, 26.1, 51.5, 56.4)}
COUNTRY_NAMES = {"NG": "Nigeria", "GH": "Ghana", "KE": "Kenya", "ZA": "South Africa", "GB": "United Kingdom", "US": "United States",
                 "IN": "India", "AE": "United Arab Emirates", "CA": "Canada", "CM": "Cameroon", "SN": "Senegal", "TZ": "Tanzania",
                 "UG": "Uganda", "EG": "Egypt", "DE": "Germany", "FR": "France"}
COUNTRY_ALIASES = {"uk": "GB", "england": "GB", "britain": "GB", "usa": "US", "america": "US", "uae": "AE", "dubai": "AE"}
# Which electricity distribution companies usually serve a state. A hint only: the customer confirms by meter/bill.
DISCOS = {
    "Lagos": ["Eko Electric (EKEDC)", "Ikeja Electric (IKEDC)"], "Ogun": ["Ikeja Electric (IKEDC)", "Ibadan Electric (IBEDC)"],
    "Oyo": ["Ibadan Electric (IBEDC)"], "Osun": ["Ibadan Electric (IBEDC)"], "Kwara": ["Ibadan Electric (IBEDC)"],
    "FCT": ["Abuja Electric (AEDC)"], "Niger": ["Abuja Electric (AEDC)"], "Kogi": ["Abuja Electric (AEDC)"], "Nasarawa": ["Abuja Electric (AEDC)", "Jos Electric (JED)"],
    "Rivers": ["Port Harcourt Electric (PHED)"], "Bayelsa": ["Port Harcourt Electric (PHED)"], "Akwa Ibom": ["Port Harcourt Electric (PHED)"], "Cross River": ["Port Harcourt Electric (PHED)"],
    "Kano": ["Kano Electric (KEDCO)"], "Jigawa": ["Kano Electric (KEDCO)"], "Katsina": ["Kano Electric (KEDCO)"],
    "Enugu": ["Enugu Electric (EEDC)"], "Abia": ["Enugu Electric (EEDC)"], "Imo": ["Enugu Electric (EEDC)"], "Anambra": ["Enugu Electric (EEDC)"], "Ebonyi": ["Enugu Electric (EEDC)"],
    "Edo": ["Benin Electric (BEDC)"], "Delta": ["Benin Electric (BEDC)"], "Ondo": ["Benin Electric (BEDC)"], "Ekiti": ["Benin Electric (BEDC)"],
    "Kaduna": ["Kaduna Electric (KAEDCO)"], "Zamfara": ["Kaduna Electric (KAEDCO)"], "Sokoto": ["Kaduna Electric (KAEDCO)"], "Kebbi": ["Kaduna Electric (KAEDCO)"],
    "Plateau": ["Jos Electric (JED)"], "Bauchi": ["Jos Electric (JED)"], "Gombe": ["Jos Electric (JED)"], "Benue": ["Jos Electric (JED)"],
    "Yobe": ["Yola Electric (YEDC)"], "Borno": ["Yola Electric (YEDC)"], "Adamawa": ["Yola Electric (YEDC)"], "Taraba": ["Yola Electric (YEDC)"],
}


def _conn():
    return _d["db"].get_db_connection()


def _days():
    try:
        return max(1, int(os.getenv("GEOINT_RETENTION_DAYS", "90")))
    except ValueError:
        return 90


def _enabled():
    return os.getenv("GEOINT_ENABLED", "true").strip().lower() in ("1", "true", "yes", "on")


def _now():
    return datetime.utcnow()


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def ensure_schema():
    global _ready
    if _ready:
        return
    c = _conn()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS customer_location_intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER NOT NULL, is_guest INTEGER NOT NULL DEFAULT 0,
            channel TEXT, channel_user_ref TEXT, location_source TEXT NOT NULL, latitude REAL, longitude REAL,
            accuracy_meters REAL, state TEXT, country TEXT, country_code TEXT,
            consent_status TEXT NOT NULL, consent_version TEXT, consent_timestamp TEXT,
            location_timestamp TEXT, recorded_at TEXT DEFAULT CURRENT_TIMESTAMP, expires_at TEXT NOT NULL,
            is_live_location INTEGER NOT NULL DEFAULT 0, message_ref TEXT)""")
        for ix in ("customer_id", "channel", "country_code", "location_timestamp", "expires_at"):
            c.execute(f"CREATE INDEX IF NOT EXISTS idx_cli_{ix} ON customer_location_intelligence({ix})")
        c.execute("""CREATE TABLE IF NOT EXISTS geoint_consent (
            user_id INTEGER PRIMARY KEY, status TEXT NOT NULL, version TEXT, channel TEXT, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS geoint_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, target_user INTEGER, detail TEXT, at TEXT DEFAULT CURRENT_TIMESTAMP)""")
        c.commit()
        _ready = True
    except Exception:
        log.exception("geoint schema failed")


def _audit(actor, action, target=None, detail=""):
    try:
        _conn().execute("INSERT INTO geoint_audit (actor, action, target_user, detail) VALUES (?,?,?,?)", (actor, action, target, str(detail)[:200]))
        _conn().commit()
    except Exception:
        log.exception("geoint audit failed")


# ------------------------------------------------------------------ geography (offline, approximate)
def _km(a, b, c, d):
    r = 6371.0
    p1, p2 = math.radians(a), math.radians(c)
    dp, dl = p2 - p1, math.radians(d - b)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def valid_coords(lat, lng):
    try:
        lat, lng = float(lat), float(lng)
    except (TypeError, ValueError):
        return None
    if not (math.isfinite(lat) and math.isfinite(lng)) or abs(lat) > 90 or abs(lng) > 180 or (lat == 0 and lng == 0):
        return None
    return lat, lng


def resolve(lat, lng):
    """Approximate country (and Nigerian state) from coordinates, offline. Unknown is a valid answer."""
    best = min(((_km(lat, lng, c[0], c[1]), s) for s, c in NG_STATES.items()), key=lambda x: x[0])
    if best[0] <= 220 and 4.0 <= lat <= 14.0 and 2.6 <= lng <= 14.8:
        return {"country_code": "NG", "country": "Nigeria", "state": best[1]}
    for cc, (a, b, c_, d) in BOXES.items():
        if a <= lat <= b and c_ <= lng <= d:
            return {"country_code": cc, "country": COUNTRY_NAMES[cc], "state": None}
    return {"country_code": None, "country": None, "state": None}


def parse_selection(text):
    """Customer-typed place -> {country_code, country, state} or None."""
    t = re.sub(r"[^a-z ]", " ", str(text or "").lower()).strip()
    t = re.sub(r"\s+", " ", t).replace(" state", "")
    if not t or len(t) > 40:
        return None
    if t in ALIASES:
        return {"country_code": "NG", "country": "Nigeria", "state": ALIASES[t]}
    for s in NG_STATES:
        if s.lower() == t:
            return {"country_code": "NG", "country": "Nigeria", "state": s}
    if t in COUNTRY_ALIASES:
        cc = COUNTRY_ALIASES[t]
        return {"country_code": cc, "country": COUNTRY_NAMES[cc], "state": None}
    for cc, n in COUNTRY_NAMES.items():
        if n.lower() == t:
            return {"country_code": cc, "country": n, "state": None}
    return None


# ------------------------------------------------------------------ data
def _ref(channel, chat):
    return hashlib.sha256(f"{os.getenv('SECRET_KEY', '')}|geo|{channel}|{chat}".encode()).hexdigest()[:24]


def purge_expired():
    try:
        ensure_schema()
        c = _conn()
        cur = c.execute("DELETE FROM customer_location_intelligence WHERE expires_at < ?", (_fmt(_now()),))
        c.commit()
        return cur.rowcount
    except Exception:
        log.exception("geoint purge failed")
        return 0


def consent_status(user_id):
    ensure_schema()
    r = _conn().execute("SELECT status, version FROM geoint_consent WHERE user_id = ?", (user_id,)).fetchone()
    if not r:
        return "none"
    # a new consent text means the old yes no longer applies
    return r["status"] if (r["status"] != "granted" or r["version"] == CONSENT_VERSION) else "none"


def set_consent(user_id, status, channel):
    if status not in ("granted", "declined", "revoked"):
        return False
    ensure_schema()
    c = _conn()
    c.execute("INSERT INTO geoint_consent (user_id, status, version, channel, updated_at) VALUES (?,?,?,?,CURRENT_TIMESTAMP) "
              "ON CONFLICT(user_id) DO UPDATE SET status=excluded.status, version=excluded.version, channel=excluded.channel, updated_at=CURRENT_TIMESTAMP",
              (user_id, status, CONSENT_VERSION, channel))
    if status != "granted":
        c.execute("DELETE FROM customer_location_intelligence WHERE customer_id = ?", (user_id,))  # revoke = remove the data
    c.commit()
    _audit("customer", f"consent_{status}", user_id, channel)
    return True


def save_location(user_id, is_guest, channel, chat, source, lat, lng, accuracy, geo, live=False, message_ref=None, ts=None):
    ensure_schema()
    if consent_status(user_id) != "granted":
        return {"saved": False, "error": "no_consent"}
    purge_expired()
    c = _conn()
    now = _now()
    c.execute("""INSERT INTO customer_location_intelligence (customer_id, is_guest, channel, channel_user_ref, location_source, latitude, longitude,
                 accuracy_meters, state, country, country_code, consent_status, consent_version, consent_timestamp, location_timestamp, expires_at,
                 is_live_location, message_ref)
                 SELECT ?,?,?,?,?,?,?,?,?,?,?, 'granted', ?, updated_at, ?, ?, ?, ? FROM geoint_consent WHERE user_id = ?""",
              (user_id, 1 if is_guest else 0, channel, _ref(channel, chat), source,
               None if lat is None else round(lat, 2), None if lng is None else round(lng, 2),
               None if accuracy is None else min(float(accuracy), 100000.0), geo.get("state"), geo.get("country"), geo.get("country_code"),
               CONSENT_VERSION, ts or _fmt(now), _fmt(now + timedelta(days=_days())), 1 if live else 0, str(message_ref or "")[:40], user_id))
    c.execute("DELETE FROM customer_location_intelligence WHERE customer_id = ? AND id NOT IN "
              "(SELECT id FROM customer_location_intelligence WHERE customer_id = ? ORDER BY id DESC LIMIT 5)", (user_id, user_id))
    c.commit()
    return {"saved": True}


def profile(user_id):
    ensure_schema()
    purge_expired()
    st = consent_status(user_id)
    out = {"consent": st, "consent_version": CONSENT_VERSION, "has_location": False}
    r = _conn().execute("SELECT * FROM customer_location_intelligence WHERE customer_id = ? ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    if r and st == "granted":
        out.update({"has_location": True, "state": r["state"], "country": r["country"], "country_code": r["country_code"],
                    "source": r["location_source"], "confidence": CONFIDENCE.get(r["location_source"], "low"),
                    "accuracy_note": "approximate (about 1 km)" if r["latitude"] is not None else "chosen by you",
                    "updated": r["location_timestamp"], "expires": r["expires_at"], "live_ignored": bool(r["is_live_location"])})
        if r["country_code"] == "NG" and r["state"] in DISCOS:
            out["disco_hint"] = DISCOS[r["state"]]
    return out


def delete_all(user_id):
    ensure_schema()
    c = _conn()
    n = c.execute("DELETE FROM customer_location_intelligence WHERE customer_id = ?", (user_id,)).rowcount
    c.execute("INSERT INTO geoint_consent (user_id, status, version, channel, updated_at) VALUES (?,?,?,?,CURRENT_TIMESTAMP) "
              "ON CONFLICT(user_id) DO UPDATE SET status='revoked', updated_at=CURRENT_TIMESTAMP", (user_id, "revoked", CONSENT_VERSION, "delete"))
    c.commit()
    _audit("customer", "deleted", user_id, f"{n} rows")
    return n


def move_owner(old_id, new_id):
    """A guest chat became a real account: its location data follows (consent too, unless the account already chose)."""
    try:
        ensure_schema()
        c = _conn()
        c.execute("UPDATE customer_location_intelligence SET customer_id = ?, is_guest = 0 WHERE customer_id = ?", (new_id, old_id))
        have = c.execute("SELECT 1 FROM geoint_consent WHERE user_id = ?", (new_id,)).fetchone()
        if have:
            c.execute("DELETE FROM geoint_consent WHERE user_id = ?", (old_id,))
        else:
            c.execute("UPDATE geoint_consent SET user_id = ? WHERE user_id = ?", (new_id, old_id))
        c.commit()
    except Exception:
        log.exception("geoint move_owner failed")


# ------------------------------------------------------------------ routes
def _owner(data):
    wa = W._wa(data)
    link = W._get_link(wa) if wa else None
    return wa, link


def init_geoint(app, db_module, login_required, admin_required):
    _d.update(db=db_module)
    ensure_schema()

    @app.route("/api/whatsapp/geo/profile", methods=["POST"])
    @W.bot_required
    def geo_bot_profile():
        wa, link = _owner(W._body())
        if not wa or not link:
            return jsonify({"success": True, "enabled": _enabled(), "linked": False, "consent": "none"})
        return jsonify({"success": True, "enabled": _enabled(), "linked": True, **profile(link["user_id"])})

    @app.route("/api/whatsapp/geo/consent", methods=["POST"])
    @W.bot_required
    def geo_bot_consent():
        d = W._body()
        wa, link = _owner(d)
        if not _enabled() or not link:
            return jsonify({"success": False, "error": "unavailable"}), 400
        ok = set_consent(link["user_id"], str(d.get("status") or ""), W.chat_source_for_link(link))
        return jsonify({"success": bool(ok)}), (200 if ok else 400)

    @app.route("/api/whatsapp/geo/location", methods=["POST"])
    @W.bot_required
    def geo_bot_location():
        d = W._body()
        wa, link = _owner(d)
        if not _enabled() or not link:
            return jsonify({"success": False, "error": "unavailable"}), 400
        ch = W.chat_source_for_link(link)
        ll = valid_coords(d.get("lat"), d.get("lng"))
        if not ll:
            return jsonify({"success": False, "error": "bad_coordinates"}), 400
        acc = d.get("accuracy")
        try:
            acc = float(acc) if acc is not None else None
            if acc is not None and (acc < 0 or not math.isfinite(acc)):
                acc = None
        except (TypeError, ValueError):
            acc = None
        geo = resolve(*ll)
        r = save_location(link["user_id"], link.get("is_guest"), ch, wa, SOURCES[ch], ll[0], ll[1], acc, geo,
                          live=bool(d.get("live")), message_ref=d.get("message_id"))
        if not r.get("saved"):
            return jsonify({"success": False, "error": r.get("error")}), 403
        return jsonify({"success": True, "saved": True, **{k: geo[k] for k in ("country", "country_code", "state")}, "known": bool(geo["country_code"]),
                        "disco_hint": DISCOS.get(geo["state"]) if geo["country_code"] == "NG" else None})

    @app.route("/api/whatsapp/geo/select", methods=["POST"])
    @W.bot_required
    def geo_bot_select():
        d = W._body()
        wa, link = _owner(d)
        if not _enabled() or not link:
            return jsonify({"success": False, "error": "unavailable"}), 400
        geo = parse_selection(d.get("text"))
        if not geo:
            return jsonify({"success": False, "error": "not_found"}), 404
        r = save_location(link["user_id"], link.get("is_guest"), W.chat_source_for_link(link), wa, SOURCES["selected"], None, None, None, geo)
        if not r.get("saved"):
            return jsonify({"success": False, "error": r.get("error")}), 403
        return jsonify({"success": True, **geo, "disco_hint": DISCOS.get(geo["state"]) if geo["country_code"] == "NG" else None})

    @app.route("/api/whatsapp/geo/delete", methods=["POST"])
    @W.bot_required
    def geo_bot_delete():
        wa, link = _owner(W._body())
        if not link:
            return jsonify({"success": True, "deleted": 0})
        return jsonify({"success": True, "deleted": delete_all(link["user_id"])})

    # ---- website / app customers (same data, their own account only)
    @app.route("/api/geoint/profile", methods=["GET"])
    @login_required
    def geo_web_profile():
        return jsonify({"success": True, **profile(g.current_user_id)})

    @app.route("/api/geoint/consent", methods=["POST"])
    @login_required
    def geo_web_consent():
        status = str((request.get_json(silent=True) or {}).get("status") or "")
        ok = set_consent(g.current_user_id, status, "web")
        return jsonify({"success": bool(ok)}), (200 if ok else 400)

    @app.route("/api/geoint/location", methods=["DELETE"])
    @login_required
    def geo_web_delete():
        return jsonify({"success": True, "deleted": delete_all(g.current_user_id)})

    # ---- admin: counts only, never coordinates
    @app.route("/api/admin/geoint/overview", methods=["GET"])
    @admin_required
    def geo_admin_overview():
        purge_expired()
        c = _conn()
        q = lambda sql, *a: [dict(r) for r in c.execute(sql, a).fetchall()]
        total = c.execute("SELECT COUNT(DISTINCT customer_id) FROM customer_location_intelligence").fetchone()[0]
        out = {
            "success": True, "customers_with_location": total,
            "by_source": q("SELECT location_source AS key, COUNT(DISTINCT customer_id) AS n FROM customer_location_intelligence GROUP BY 1 ORDER BY n DESC"),
            "by_channel": q("SELECT channel AS key, COUNT(DISTINCT customer_id) AS n FROM customer_location_intelligence GROUP BY 1 ORDER BY n DESC"),
            "by_country": q("SELECT COALESCE(country,'Unknown') AS key, COUNT(DISTINCT customer_id) AS n FROM customer_location_intelligence GROUP BY 1 ORDER BY n DESC LIMIT 30"),
            "by_state": q("SELECT state AS key, COUNT(DISTINCT customer_id) AS n FROM customer_location_intelligence WHERE state IS NOT NULL GROUP BY 1 ORDER BY n DESC LIMIT 40"),
            "guests": c.execute("SELECT COUNT(DISTINCT customer_id) FROM customer_location_intelligence WHERE is_guest = 1").fetchone()[0],
            "updates_per_day": q("SELECT substr(recorded_at,1,10) AS day, COUNT(*) AS n FROM customer_location_intelligence GROUP BY 1 ORDER BY 1 DESC LIMIT 30"),
            "consent": {r["status"]: r["n"] for r in q("SELECT status, COUNT(*) AS n FROM geoint_consent GROUP BY 1")},
            "retention_days": _days(), "consent_version": CONSENT_VERSION,
            "note": "Counts only. Exact coordinates are never stored (rounded to about 1 km) and are not shown here.",
        }
        cs = out["consent"]
        asked = sum(cs.values())
        out["consent_acceptance_rate"] = round(100 * cs.get("granted", 0) / asked) if asked else None
        _audit("admin", "overview_viewed", None, request.remote_addr or "")
        return jsonify(out)

    log.info("GEOINT core routes registered")

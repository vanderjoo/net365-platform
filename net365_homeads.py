"""Adverts under "Ask Net365" on the home page. Net365's own messages and partner/sponsor adverts, managed in admin.html > Home Adverts.

  GET    /api/ads/home?country=NG          what the home page shows now (public, no cookies needed)
  POST   /api/ads/home/<id>/event          {"event": "view" | "click"}  (public, rate limited, counted once per visitor per hour)
  GET    /api/admin/home-ads               every advert with its counts, plus settings
  POST   /api/admin/home-ads               create (no id) or update (id) an advert
  DELETE /api/admin/home-ads/<id>
  POST   /api/admin/home-ads/settings      {"animation": "first" | "fallback" | "off", "rotate": 4..30}

The built-in Net365 chat animation is the default content. Setting "animation":
  first    the animation is the first slide and your adverts follow (default)
  fallback the animation shows only when there is no live advert
  off      adverts only (the page still falls back to the animation if there are none)

Only https:// addresses (or paths starting with /) are accepted for the image and the button. Everything is shown as plain text.
"""
import logging
import re
import threading
import time
from datetime import datetime

from flask import jsonify, request

logger = logging.getLogger("net365.homeads")

_state = {}
_lock = threading.Lock()
_seen = {}  # (ip, ad, event) -> time: one count per visitor per hour
ISO = re.compile(r"^[A-Z]{2}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
KINDS = ("net365", "partner")


def _conn():
    return _state["conn"]()


def _close(c):
    try:
        c.close()
    except Exception:
        pass


def _schema():
    c = _conn()
    try:
        c.execute("CREATE TABLE IF NOT EXISTS home_ads (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT, image_url TEXT, "
                  "cta_label TEXT, cta_url TEXT, kind TEXT DEFAULT 'net365', sponsor TEXT, active INTEGER DEFAULT 1, starts_on TEXT, ends_on TEXT, "
                  "countries TEXT, sort INTEGER DEFAULT 0, views INTEGER DEFAULT 0, clicks INTEGER DEFAULT 0, "
                  "created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        c.execute("CREATE TABLE IF NOT EXISTS home_ad_settings (k TEXT PRIMARY KEY, v TEXT)")
        c.commit()
    finally:
        _close(c)


def _setting(c, k, default):
    r = c.execute("SELECT v FROM home_ad_settings WHERE k = ?", (k,)).fetchone()
    return (r["v"] if r else None) or default


def _settings(c):
    anim = _setting(c, "animation", "first")
    try:
        rot = max(4, min(30, int(_setting(c, "rotate", "7"))))
    except ValueError:
        rot = 7
    return {"animation": anim if anim in ("first", "fallback", "off") else "first", "rotate": rot}


def _clean(v, n):
    return re.sub(r"[<>\u0000-\u001f]", " ", re.sub(r"\s+", " ", str(v or ""))).strip()[:n]


def _url(v, allow_empty=True):
    """https:// address or a path on this site. Anything else (javascript:, data:, http:) is refused."""
    v = str(v or "").strip()
    if not v:
        return "" if allow_empty else None
    if len(v) > 500 or re.search(r"[\s<>\"']", v):
        return None
    if v.startswith("/") and not v.startswith("//"):
        return v
    if re.match(r"^https://[^\s/]+\.[^\s/]+", v):
        return v
    return None


def _today():
    return datetime.utcnow().strftime("%Y-%m-%d")


def _public(r):
    return {"id": r["id"], "title": r["title"], "body": r["body"] or "", "image_url": r["image_url"] or "", "cta_label": r["cta_label"] or "",
            "cta_url": r["cta_url"] or "", "kind": r["kind"] if r["kind"] in KINDS else "net365", "sponsor": r["sponsor"] or ""}


def _admin_row(r):
    d = _public(r)
    d.update(active=bool(r["active"]), starts_on=r["starts_on"] or "", ends_on=r["ends_on"] or "", countries=r["countries"] or "", sort=r["sort"] or 0,
             views=r["views"] or 0, clicks=r["clicks"] or 0)
    d["live"] = bool(r["active"]) and (not r["starts_on"] or r["starts_on"] <= _today()) and (not r["ends_on"] or r["ends_on"] >= _today())
    return d


def init_homeads(app, get_conn, admin_required, get_client_ip=None):
    """get_conn: returns a sqlite connection with row_factory=sqlite3.Row (db.get_db_connection)."""
    _state["conn"] = get_conn
    try:
        _schema()
    except Exception as e:
        logger.warning("home adverts tables not ready: %s", e)

    def ip():
        try:
            return (get_client_ip() if get_client_ip else request.remote_addr) or "?"
        except Exception:
            return request.remote_addr or "?"

    @app.route("/api/ads/home", methods=["GET"])
    def homeads_public():
        cc = str(request.args.get("country") or "").upper()[:2]
        cc = cc if ISO.match(cc) else ""
        _schema()
        c = _conn()
        try:
            st = _settings(c)
            rows = c.execute("SELECT * FROM home_ads WHERE active = 1 AND (starts_on IS NULL OR starts_on = '' OR starts_on <= ?) "
                             "AND (ends_on IS NULL OR ends_on = '' OR ends_on >= ?) ORDER BY sort ASC, id DESC", (_today(), _today())).fetchall()
        finally:
            _close(c)
        ads = []
        for r in rows:
            want = [x for x in (r["countries"] or "").upper().replace(" ", "").split(",") if x]
            if want and cc and cc not in want:
                continue
            if want and not cc:        # country unknown: show only adverts that are not country-specific
                continue
            ads.append(_public(r))
        resp = jsonify({"success": True, "settings": st, "ads": ads[:12]})
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.route("/api/ads/home/<int:ad_id>/event", methods=["POST"])
    def homeads_event(ad_id):
        ev = str((request.get_json(silent=True) or {}).get("event") or "")
        if ev not in ("view", "click"):
            return jsonify({"success": False}), 400
        key, now = (ip(), ad_id, ev), time.time()
        with _lock:
            if now - _seen.get(key, 0) < 3600:
                return jsonify({"success": True, "counted": False})
            _seen[key] = now
            if len(_seen) > 20000:
                for k in [k for k, t in _seen.items() if now - t > 3600][:10000]:
                    _seen.pop(k, None)
        c = _conn()
        try:
            col = "views" if ev == "view" else "clicks"
            c.execute("UPDATE home_ads SET %s = COALESCE(%s, 0) + 1 WHERE id = ?" % (col, col), (ad_id,))
            c.commit()
        finally:
            _close(c)
        return jsonify({"success": True, "counted": True})

    @app.route("/api/admin/home-ads", methods=["GET"])
    @admin_required
    def homeads_admin_list():
        _schema()
        c = _conn()
        try:
            rows = c.execute("SELECT * FROM home_ads ORDER BY sort ASC, id DESC").fetchall()
            st = _settings(c)
        finally:
            _close(c)
        return jsonify({"success": True, "settings": st, "ads": [_admin_row(r) for r in rows]})

    @app.route("/api/admin/home-ads", methods=["POST"])
    @admin_required
    def homeads_admin_save():
        b = request.get_json(silent=True) or {}
        title, body = _clean(b.get("title"), 80), _clean(b.get("body"), 160)
        if not title:
            return jsonify({"success": False, "error": "Give the advert a title."}), 400
        image, cta = _url(b.get("image_url")), _url(b.get("cta_url"))
        if image is None:
            return jsonify({"success": False, "error": "The image must be a full https:// address (or a path starting with /)."}), 400
        if cta is None:
            return jsonify({"success": False, "error": "The button link must be a full https:// address (or a path starting with /)."}), 400
        label = _clean(b.get("cta_label"), 24)
        if cta and not label:
            label = "Learn more"
        kind = b.get("kind") if b.get("kind") in KINDS else "net365"
        sponsor = _clean(b.get("sponsor"), 60)
        if kind == "partner" and not sponsor:
            return jsonify({"success": False, "error": "Name the sponsor for a partner advert. It is shown as Sponsored."}), 400
        starts, ends = str(b.get("starts_on") or "").strip(), str(b.get("ends_on") or "").strip()
        for d in (starts, ends):
            if d and not DATE.match(d):
                return jsonify({"success": False, "error": "Dates must look like 2026-12-31."}), 400
        if starts and ends and ends < starts:
            return jsonify({"success": False, "error": "The end date is before the start date."}), 400
        ccs = [x for x in str(b.get("countries") or "").upper().replace(" ", "").split(",") if x]
        if any(not ISO.match(x) for x in ccs):
            return jsonify({"success": False, "error": "Countries are two-letter codes separated by commas, for example NG,GH."}), 400
        try:
            sort = int(b.get("sort") or 0)
        except (TypeError, ValueError):
            sort = 0
        vals = (title, body, image, label, cta, kind, sponsor, 1 if b.get("active", True) else 0, starts, ends, ",".join(ccs), sort)
        _schema()
        c = _conn()
        try:
            ad_id = b.get("id")
            if ad_id:
                c.execute("UPDATE home_ads SET title=?, body=?, image_url=?, cta_label=?, cta_url=?, kind=?, sponsor=?, active=?, starts_on=?, ends_on=?, "
                          "countries=?, sort=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", vals + (int(ad_id),))
            else:
                cur = c.execute("INSERT INTO home_ads (title, body, image_url, cta_label, cta_url, kind, sponsor, active, starts_on, ends_on, countries, sort) "
                                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", vals)
                ad_id = cur.lastrowid
            c.commit()
            row = c.execute("SELECT * FROM home_ads WHERE id = ?", (int(ad_id),)).fetchone()
        finally:
            _close(c)
        return jsonify({"success": True, "ad": _admin_row(row)})

    @app.route("/api/admin/home-ads/<int:ad_id>", methods=["DELETE"])
    @admin_required
    def homeads_admin_delete(ad_id):
        c = _conn()
        try:
            c.execute("DELETE FROM home_ads WHERE id = ?", (ad_id,))
            c.commit()
        finally:
            _close(c)
        return jsonify({"success": True})

    @app.route("/api/admin/home-ads/settings", methods=["POST"])
    @admin_required
    def homeads_admin_settings():
        b = request.get_json(silent=True) or {}
        anim = b.get("animation") if b.get("animation") in ("first", "fallback", "off") else None
        try:
            rot = max(4, min(30, int(b.get("rotate")))) if b.get("rotate") not in (None, "") else None
        except (TypeError, ValueError):
            rot = None
        if anim is None and rot is None:
            return jsonify({"success": False, "error": "Nothing to change."}), 400
        _schema()
        c = _conn()
        try:
            for k, v in (("animation", anim), ("rotate", rot)):
                if v is not None:
                    c.execute("INSERT INTO home_ad_settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, str(v)))
            c.commit()
            st = _settings(c)
        finally:
            _close(c)
        return jsonify({"success": True, "settings": st})

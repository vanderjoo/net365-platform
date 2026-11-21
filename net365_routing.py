"""Net365 provider routing policy.

Decides which processor (VTpass or Reloadly) Net365 tries first for each service, learns from
outcomes, and lets an admin override the order. Customers never see any of this: no provider name
is shown on any customer screen, receipt or bot message.

Default policy
    electricity, tv, education, data, insurance : VTpass first, Reloadly on standby
    airtime                                     : Reloadly first, VTpass on standby

How the order is decided (highest priority first)
    1. Admin override for the service (mode 'vtpass' or 'reloadly')  -> that provider first.
    2. Admin "auto" mode                                                -> best efficiency score first.
    3. Default order above.
    In every mode a provider that the admin marked down, or that Net365 senses is down
    (recent run of failures), is moved to the back so the other one is tried first. It is retried
    automatically after a cool-down so a recovered provider comes back by itself.

This module only reads/writes its own two tables. It never touches wallets or transactions.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone, timedelta
from flask import jsonify, request

logger = logging.getLogger(__name__)

PROVIDERS = ("vtpass", "reloadly")
SERVICES = ("airtime", "electricity", "tv", "education", "data", "insurance")
MODES = ("default", "auto", "vtpass", "reloadly")
DEFAULT_ORDER = {
    "airtime": ("reloadly", "vtpass"),
    "electricity": ("vtpass", "reloadly"),
    "tv": ("vtpass", "reloadly"),
    "education": ("vtpass", "reloadly"),
    "data": ("vtpass", "reloadly"),
    "insurance": ("vtpass", "reloadly"),
}
# Which services each provider can actually take today (reflects what the fulfilment code has wired up).
CAPABLE = {
    "vtpass": set(SERVICES),
    "reloadly": {"airtime", "electricity"},
}

SCORE_WINDOW_DAYS = 7
SENSE_RUN = 4                 # this many failures in a row ...
SENSE_WINDOW_SECONDS = 20 * 60  # ... within this window means "looks down"
SENSE_COOLDOWN_SECONDS = 10 * 60  # then wait this long before trying it first again

_db = None
_lock = threading.Lock()
_cache = {"t": 0.0, "modes": {}, "flags": {}}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn():
    return _db.get_db_connection()


def _ensure_schema():
    conn = _conn()
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS provider_routing (
            service TEXT PRIMARY KEY,
            mode TEXT NOT NULL DEFAULT 'default',
            updated_at TEXT NOT NULL,
            updated_by TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS provider_flags (
            provider TEXT PRIMARY KEY,
            down INTEGER NOT NULL DEFAULT 0,
            note TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            updated_by TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS provider_outcomes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            service TEXT NOT NULL,
            ok INTEGER NOT NULL,
            reference TEXT,
            created_at TEXT NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_provider_outcomes ON provider_outcomes(provider, service, created_at)")
        conn.commit()
    finally:
        conn.close()


def _load():
    """Admin modes and flags, cached for a few seconds so every purchase does not hit the database."""
    if time.time() - _cache["t"] < 5:
        return _cache["modes"], _cache["flags"]
    modes, flags = {}, {}
    try:
        conn = _conn()
        try:
            for r in conn.execute("SELECT service, mode FROM provider_routing").fetchall():
                modes[r["service"]] = r["mode"]
            for r in conn.execute("SELECT provider, down, note FROM provider_flags").fetchall():
                flags[r["provider"]] = {"down": bool(r["down"]), "note": r["note"] or ""}
        finally:
            conn.close()
    except Exception:
        logger.exception("routing: could not load policy; using defaults")
    _cache.update(t=time.time(), modes=modes, flags=flags)
    return modes, flags


def _invalidate():
    _cache["t"] = 0.0


def record(provider, service, ok, reference=None):
    """Remember how an attempt ended. Only call with a DEFINITE outcome (delivered, or certainly not accepted)."""
    provider = str(provider or "").lower()
    service = str(service or "").lower()
    if provider not in PROVIDERS or service not in SERVICES:
        return
    try:
        conn = _conn()
        try:
            conn.execute("INSERT INTO provider_outcomes (provider, service, ok, reference, created_at) VALUES (?,?,?,?,?)",
                         (provider, service, 1 if ok else 0, str(reference or "")[:80], _now()))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        logger.warning("routing: could not record outcome", exc_info=True)


def stats(provider, service=None, days=SCORE_WINDOW_DAYS):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    q = "SELECT COUNT(*) AS n, COALESCE(SUM(ok),0) AS s FROM provider_outcomes WHERE provider=? AND created_at>=?"
    args = [provider, since]
    if service:
        q += " AND service=?"
        args.append(service)
    conn = _conn()
    try:
        r = conn.execute(q, args).fetchone()
    finally:
        conn.close()
    n, s = int(r["n"] or 0), int(r["s"] or 0)
    # Smoothed so one lucky/unlucky order does not swing the score: starts at 50 and moves with evidence.
    score = round((s + 1) / (n + 2) * 100, 1)
    return {"attempts": n, "success": s, "failed": n - s, "score": score}


def _auto_down(provider, service):
    """True while the provider looks down: a run of recent failures with no success in between."""
    since = (datetime.now(timezone.utc) - timedelta(seconds=SENSE_WINDOW_SECONDS)).isoformat(timespec="seconds")
    try:
        conn = _conn()
        try:
            rows = conn.execute(
                "SELECT ok, created_at FROM provider_outcomes WHERE provider=? AND service=? AND created_at>=? "
                "ORDER BY id DESC LIMIT ?", (provider, service, since, SENSE_RUN)).fetchall()
        finally:
            conn.close()
    except Exception:
        return False
    if len(rows) < SENSE_RUN or any(r["ok"] for r in rows):
        return False
    try:
        last = datetime.fromisoformat(rows[0]["created_at"])
        return (datetime.now(timezone.utc) - last).total_seconds() < SENSE_COOLDOWN_SECONDS
    except Exception:
        return False


def is_down(provider, service):
    _, flags = _load()
    return bool((flags.get(provider) or {}).get("down")) or _auto_down(provider, service)


def order(service):
    """Providers to try for this service, best first. Never empty."""
    service = str(service or "").lower()
    base = list(DEFAULT_ORDER.get(service, ("vtpass", "reloadly")))
    capable = [p for p in base if service in CAPABLE.get(p, ())] or base
    modes, _ = _load()
    mode = modes.get(service, "default")
    if mode in PROVIDERS and mode in capable:
        ranked = [mode] + [p for p in capable if p != mode]
    elif mode == "auto":
        try:
            ranked = sorted(capable, key=lambda p: (-stats(p, service)["score"], capable.index(p)))
        except Exception:
            ranked = capable
    else:
        ranked = capable
    healthy = [p for p in ranked if not is_down(p, service)]
    down = [p for p in ranked if p not in healthy]
    return healthy + down


def init_routing(app, db, admin_required):
    """Create the tables and register the admin-only routes."""
    global _db
    _db = db
    _ensure_schema()

    def _admin_name():
        try:
            from flask import g
            u = getattr(g, "current_user", None) or {}
            return str(u.get("email") or getattr(g, "current_user_id", "") or "admin")[:80]
        except Exception:
            return "admin"

    @app.get("/api/admin/routing")
    @admin_required
    def admin_routing_get():
        modes, flags = _load()
        out = []
        for svc in SERVICES:
            row = {"service": svc, "mode": modes.get(svc, "default"), "default_order": list(DEFAULT_ORDER[svc]),
                   "effective_order": order(svc), "providers": {}}
            for p in PROVIDERS:
                if svc not in CAPABLE[p]:
                    row["providers"][p] = {"supported": False}
                    continue
                st = stats(p, svc)
                st.update(supported=True, down=is_down(p, svc), auto_down=_auto_down(p, svc))
                row["providers"][p] = st
            out.append(row)
        prov = {p: {"down": bool((flags.get(p) or {}).get("down")), "note": (flags.get(p) or {}).get("note", ""),
                    "overall": stats(p)} for p in PROVIDERS}
        return jsonify(success=True, services=out, providers=prov, modes=list(MODES))

    @app.post("/api/admin/routing")
    @admin_required
    def admin_routing_set():
        d = request.get_json(silent=True) or {}
        svc, mode = str(d.get("service") or "").lower(), str(d.get("mode") or "").lower()
        if svc not in SERVICES or mode not in MODES:
            return jsonify(success=False, error="Unknown service or mode"), 400
        if mode in PROVIDERS and svc not in CAPABLE[mode]:
            return jsonify(success=False, error=f"{mode} cannot take {svc} yet"), 400
        conn = _conn()
        try:
            conn.execute("INSERT INTO provider_routing (service, mode, updated_at, updated_by) VALUES (?,?,?,?) "
                         "ON CONFLICT(service) DO UPDATE SET mode=excluded.mode, updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                         (svc, mode, _now(), _admin_name()))
            conn.commit()
        finally:
            conn.close()
        _invalidate()
        logger.warning(f"ROUTING: {svc} mode set to {mode} by {_admin_name()}")
        return jsonify(success=True, service=svc, mode=mode, effective_order=order(svc))

    @app.post("/api/admin/routing/provider")
    @admin_required
    def admin_routing_provider():
        d = request.get_json(silent=True) or {}
        prov = str(d.get("provider") or "").lower()
        if prov not in PROVIDERS:
            return jsonify(success=False, error="Unknown provider"), 400
        down = 1 if d.get("down") else 0
        note = str(d.get("note") or "").strip()[:300]
        conn = _conn()
        try:
            conn.execute("INSERT INTO provider_flags (provider, down, note, updated_at, updated_by) VALUES (?,?,?,?,?) "
                         "ON CONFLICT(provider) DO UPDATE SET down=excluded.down, note=excluded.note, "
                         "updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                         (prov, down, note, _now(), _admin_name()))
            conn.commit()
        finally:
            conn.close()
        _invalidate()
        logger.warning(f"ROUTING: provider {prov} down={bool(down)} by {_admin_name()}")
        return jsonify(success=True, provider=prov, down=bool(down))

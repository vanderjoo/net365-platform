"""Net365 recovery engine: what happens when a customer has PAID but the provider could not deliver.

Every paid order ends one of three ways: delivered, refunded, or visibly waiting (retry / needs review).

Classification of a failed order (from the error text recorded when fulfilment failed)
    UNKNOWN   the provider may or may not have taken the order ("could not confirm", timeouts on submit)
              -> NEVER retried or refunded automatically. It goes to the admin "needs review" list.
    TRANSIENT the provider certainly did not take it and the cause is temporary (maintenance, low provider
              balance, 5xx, unavailable) -> retried on the admin's schedule, then refunded.
    PERMANENT the provider certainly refused it (e.g. "016 TRANSACTION FAILED", bad meter) -> refunded at once.

Everything is controlled from the admin tab (policy per service, maintenance windows, test mode, pause switch).
Refund routes: wallet credit, Paystack refund API (original payment), or manual (queued for an admin).
Refund modes: auto (system does it) or approval (queued until an admin approves).
In test mode no money moves: refunds are recorded as 'simulated'.

This module only touches its own tables, plus: wallet credit (existing function) and a status update on the
failed order once it has been refunded.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from datetime import datetime, timezone, timedelta
from flask import jsonify, request

logger = logging.getLogger(__name__)

SERVICES = ("airtime", "electricity", "tv", "education", "data", "insurance")
TX_SERVICE = {"topup": "airtime", "electricity": "electricity", "tv": "tv", "education": "education",
              "data": "data", "insurance": "insurance", "utility": "electricity"}
ROUTES = ("wallet", "original", "manual")
MODES = ("auto", "approval")
HARD_MAX_ATTEMPTS = 10          # no admin setting can exceed this

DEFAULT_POLICY = {
    "airtime":     dict(max_attempts=3, gap_minutes=5,  window_minutes=30, refund_route="wallet",   refund_mode="auto",     refund_fee=1),
    "data":        dict(max_attempts=3, gap_minutes=5,  window_minutes=30, refund_route="wallet",   refund_mode="auto",     refund_fee=1),
    "electricity": dict(max_attempts=5, gap_minutes=6,  window_minutes=30, refund_route="wallet",   refund_mode="auto",     refund_fee=1),
    "tv":          dict(max_attempts=5, gap_minutes=6,  window_minutes=30, refund_route="wallet",   refund_mode="auto",     refund_fee=1),
    "education":   dict(max_attempts=3, gap_minutes=5,  window_minutes=30, refund_route="wallet",   refund_mode="approval", refund_fee=1),
    "insurance":   dict(max_attempts=3, gap_minutes=5,  window_minutes=30, refund_route="manual",   refund_mode="approval", refund_fee=1),
}

_UNKNOWN = ("not retrying elsewhere", "could not confirm", "unknown state", "no response")
_TRANSIENT = ("low wallet", "insufficient", "balance", "unavailable", "maintenance", "suspended", "not reachable",
              "temporar", "server error", " 500", " 502", " 503", " 504", "bad gateway", "try again later", "service is down",
              "currently not available", "provider is down")

_db = None
_cache = {"t": 0.0, "policy": {}, "settings": {}, "maint": {}}


def _now():
    return datetime.now(timezone.utc)


def _iso(dt=None):
    return (dt or _now()).isoformat(timespec="seconds")


def _conn():
    return _db.get_db_connection()


def _ensure_schema():
    c = _conn()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS recovery_policy (
            service TEXT PRIMARY KEY, max_attempts INTEGER NOT NULL, gap_minutes INTEGER NOT NULL, window_minutes INTEGER NOT NULL,
            refund_route TEXT NOT NULL, refund_mode TEXT NOT NULL, refund_fee INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT, updated_by TEXT)""")
        c.execute("CREATE TABLE IF NOT EXISTS recovery_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        c.execute("""CREATE TABLE IF NOT EXISTS service_maintenance (
            service TEXT PRIMARY KEY, active INTEGER NOT NULL DEFAULT 0, until TEXT, message TEXT NOT NULL DEFAULT '',
            updated_at TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS recovery_attempts (
            reference TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, last_attempt TEXT, first_seen TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS refund_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT NOT NULL UNIQUE, user_id INTEGER, service TEXT,
            amount REAL NOT NULL, currency TEXT NOT NULL DEFAULT 'NGN', route TEXT, mode TEXT,
            status TEXT NOT NULL, reason TEXT, note TEXT, created_at TEXT NOT NULL, processed_at TEXT, processed_by TEXT,
            gateway_ref TEXT)""")
        c.commit()
    finally:
        c.close()


def _load(force=False):
    if not force and time.time() - _cache["t"] < 5:
        return _cache
    policy, settings, maint = {}, {}, {}
    try:
        c = _conn()
        try:
            for r in c.execute("SELECT * FROM recovery_policy").fetchall():
                policy[r["service"]] = dict(r)
            for r in c.execute("SELECT key, value FROM recovery_settings").fetchall():
                settings[r["key"]] = r["value"]
            for r in c.execute("SELECT * FROM service_maintenance").fetchall():
                maint[r["service"]] = dict(r)
        finally:
            c.close()
    except Exception:
        logger.exception("recovery: could not load settings; using defaults")
    _cache.update(t=time.time(), policy=policy, settings=settings, maint=maint)
    return _cache


def policy(service):
    base = dict(DEFAULT_POLICY.get(service, DEFAULT_POLICY["electricity"]))
    base.update({k: v for k, v in (_load()["policy"].get(service) or {}).items() if k in base and v is not None})
    base["max_attempts"] = max(0, min(int(base["max_attempts"]), HARD_MAX_ATTEMPTS))
    return base


def setting(key, default=""):
    return _load()["settings"].get(key, default)


def test_mode():
    return str(setting("test_mode", "0")) == "1"


def retries_paused():
    return str(setting("pause_retries", "0")) == "1"


# ---------------------------------------------------------------- maintenance
def maintenance(service):
    """(blocked, message). Applies to new payments. A window with an end time lifts itself."""
    st = _load()
    for key in ("*", service):
        m = st["maint"].get(key)
        if not m or not m.get("active"):
            continue
        until = m.get("until")
        if until:
            try:
                if _now() >= datetime.fromisoformat(until):
                    continue
            except ValueError:
                pass
        msg = m.get("message") or "This service is temporarily unavailable. Please try again shortly."
        if until:
            msg += f" Expected back: {until.replace('T', ' ')[:16]} UTC."
        return True, msg
    return False, ""


def maintenance_block(service):
    """Flask helper: (response, status) to return from a checkout route, or None."""
    blocked, msg = maintenance(service)
    if blocked:
        return jsonify({"success": False, "code": "MAINTENANCE", "error": msg}), 503
    return None


# ---------------------------------------------------------------- classification
def classify(error_text):
    t = str(error_text or "").lower()
    if any(k in t for k in _UNKNOWN):
        return "unknown"
    if any(k in t for k in _TRANSIENT):
        return "transient"
    return "permanent"


# ---------------------------------------------------------------- refunds
def _paystack_refund(reference, amount):
    import requests
    key = os.getenv("PAYSTACK_SECRET_KEY")
    if not key:
        return False, "PAYSTACK_SECRET_KEY is not set", ""
    body = {"transaction": reference}
    if amount:
        body["amount"] = int(round(float(amount) * 100))
    try:
        r = requests.post("https://api.paystack.co/refund", json=body, headers={"Authorization": f"Bearer {key}"}, timeout=20)
        d = r.json() if r.content else {}
        if r.status_code in (200, 201) and d.get("status"):
            return True, str(d.get("message") or "Refund initiated"), str((d.get("data") or {}).get("id") or "")
        return False, str(d.get("message") or f"Paystack HTTP {r.status_code}"), ""
    except Exception as e:
        return False, f"Paystack unreachable: {e}", ""


def _execute_refund(row, by):
    """Move the money. Returns (status, note, gateway_ref). Never raises."""
    ref, uid, amount, cur, route = row["reference"], row["user_id"], float(row["amount"]), row["currency"], row["route"]
    if test_mode():
        return "simulated", f"TEST MODE: would refund {cur} {amount:,.2f} via {route}", ""
    try:
        if route == "wallet":
            if not uid:
                return "failed", "No user to credit", ""
            res = _db.credit_wallet(user_id=uid, amount=amount, currency=cur,
                                    description=f"Refund for order {ref}", reference=f"AUTOREFUND-{ref}"[:80],
                                    metadata={"original_reference": ref, "by": by})
            if res and res.get("success"):
                return "processed", "Credited to the customer's Net365 wallet", ""
            return "failed", str((res or {}).get("error") or "Wallet credit failed"), ""
        if route == "original":
            ok, note, gref = _paystack_refund(ref, amount)
            return ("processed" if ok else "failed"), note, gref
    except Exception as e:
        logger.exception("recovery: refund failed")
        return "failed", str(e), ""
    return "queued", "Manual refund: refund in your gateway dashboard, then press 'Mark done'", ""


def _mark_order_refunded(ref):
    try:
        c = _conn()
        try:
            c.execute("UPDATE transactions SET status='refunded', updated_at=CURRENT_TIMESTAMP WHERE reference=? "
                      "AND status IN ('fulfillment_failed','pending')", (ref,))
            c.commit()
        finally:
            c.close()
        try:  # ad credits earned by this order (if any) are cancelled
            from net365_adcredits import reverse_for_reference
            reverse_for_reference(ref, "order refunded")
        except Exception:
            pass
    except Exception:
        logger.warning("recovery: could not mark order refunded", exc_info=True)


def _notify(uid, ref, status):
    if not uid:
        return
    try:
        if status == "processed":
            _db.create_notification(uid, "Refund issued", f"We could not complete your order {ref}. Your money has been refunded.", "info")
        elif status in ("queued", "approved"):
            _db.create_notification(uid, "Refund on the way", f"We could not complete your order {ref}. Your refund is being processed.", "info")
    except Exception:
        pass


def open_refund(tx, service, reason, status_override=None):
    """Create the refund record for a failed paid order (once). Executes it when the policy says auto."""
    ref = tx["reference"]
    pol = policy(service)
    amount = float(tx.get("amount") or 0)
    if amount <= 0:
        return None
    route = pol["refund_route"]
    # 'original' only works for Paystack payments; anything else is a manual refund
    if route == "original" and str(tx.get("provider") or "").lower() != "paystack":
        route = "manual"
    c = _conn()
    try:
        exists = c.execute("SELECT status FROM refund_queue WHERE reference=?", (ref,)).fetchone()
        if exists:
            return exists["status"]
        status = status_override or ("approved" if pol["refund_mode"] == "auto" else "queued")
        c.execute("INSERT INTO refund_queue (reference, user_id, service, amount, currency, route, mode, status, reason, created_at) "
                  "VALUES (?,?,?,?,?,?,?,?,?,?)",
                  (ref, tx.get("user_id"), service, amount, tx.get("currency") or "NGN", route, pol["refund_mode"], status,
                   str(reason)[:400], _iso()))
        c.commit()
    finally:
        c.close()
    logger.warning(f"RECOVERY: refund record opened for {ref} ({service}, {amount}, route={route}, status={status}): {reason}")
    if status == "approved":
        process_refund(ref, "system")
    return status


def process_refund(reference, by="admin"):
    c = _conn()
    try:
        row = c.execute("SELECT * FROM refund_queue WHERE reference=?", (reference,)).fetchone()
        if not row or row["status"] not in ("approved", "queued", "failed", "simulated"):
            return None
        row = dict(row)
    finally:
        c.close()
    status, note, gref = _execute_refund(row, by)
    c = _conn()
    try:
        c.execute("UPDATE refund_queue SET status=?, note=?, gateway_ref=?, processed_at=?, processed_by=? WHERE reference=?",
                  (status if status != "queued" else "queued", note, gref, _iso(), by, reference))
        c.commit()
    finally:
        c.close()
    if status == "processed":
        _mark_order_refunded(reference)
    _notify(row["user_id"], reference, status)
    return status


# ---------------------------------------------------------------- the sweep (called by the pending sweeper every minute)
def _attempts(ref):
    c = _conn()
    try:
        r = c.execute("SELECT * FROM recovery_attempts WHERE reference=?", (ref,)).fetchone()
        return dict(r) if r else None
    finally:
        c.close()


def _bump(ref):
    c = _conn()
    try:
        c.execute("INSERT INTO recovery_attempts (reference, attempts, last_attempt, first_seen) VALUES (?,1,?,?) "
                  "ON CONFLICT(reference) DO UPDATE SET attempts=attempts+1, last_attempt=excluded.last_attempt",
                  (ref, _iso(), _iso()))
        c.commit()
    finally:
        c.close()


def sweep():
    """Look at paid-but-failed orders of the hub services. Returns the references to re-run now.
    Also opens refund records / review items. Safe to call every minute."""
    retry = []
    try:
        c = _conn()
        try:
            rows = c.execute(
                "SELECT reference, user_id, tx_type, amount, currency, provider, fulfillment_error, created_at "
                "FROM transactions WHERE status='fulfillment_failed' AND tx_type IN ('electricity','data','tv','education','insurance') "
                "AND created_at >= datetime('now','-3 days') ORDER BY created_at ASC LIMIT 40").fetchall()
        finally:
            c.close()
    except Exception:
        logger.exception("recovery sweep: query failed")
        return retry
    for r in rows:
        tx = dict(r)
        service = TX_SERVICE.get(tx["tx_type"])
        if not service:
            continue
        ref, err = tx["reference"], tx.get("fulfillment_error") or ""
        kind = classify(err)
        c = _conn()
        try:
            known = c.execute("SELECT status FROM refund_queue WHERE reference=?", (ref,)).fetchone()
        finally:
            c.close()
        if known:
            continue
        if kind == "unknown":
            open_refund(tx, service, f"NEEDS REVIEW: provider state unknown ({err[:200]})", status_override="review")
            continue
        if kind == "permanent":
            open_refund(tx, service, f"Provider refused the order: {err[:200]}")
            continue
        # transient: retry on the admin's schedule
        pol = policy(service)
        blocked, _ = maintenance(service)
        if blocked or retries_paused():
            continue                                # waiting for maintenance to end; attempts are not used up
        a = _attempts(ref)
        n = (a or {}).get("attempts", 0)
        try:
            created = datetime.fromisoformat(str(tx["created_at"]).replace(" ", "T")).replace(tzinfo=timezone.utc)
        except ValueError:
            created = _now() - timedelta(minutes=pol["window_minutes"] + 1)
        window_over = (_now() - created) > timedelta(minutes=pol["window_minutes"])
        if n >= pol["max_attempts"] or window_over:
            open_refund(tx, service, f"Retries exhausted after {n} attempts: {err[:200]}")
            continue
        last = None
        if a and a.get("last_attempt"):
            try:
                last = datetime.fromisoformat(a["last_attempt"])
            except ValueError:
                pass
        if last and (_now() - last) < timedelta(minutes=pol["gap_minutes"]):
            continue
        _bump(ref)
        retry.append(ref)
    return retry


# ---------------------------------------------------------------- admin routes
def init_recovery(app, db, admin_required):
    global _db
    _db = db
    _ensure_schema()

    @app.get("/api/admin/recovery")
    @admin_required
    def admin_recovery_get():
        _load(True)
        c = _conn()
        try:
            queue = [dict(r) for r in c.execute("SELECT * FROM refund_queue ORDER BY id DESC LIMIT 100").fetchall()]
        finally:
            c.close()
        maint = _load()["maint"]
        return jsonify(success=True, policy={s: policy(s) for s in SERVICES}, routes=list(ROUTES), modes=list(MODES),
                       settings={"test_mode": test_mode(), "pause_retries": retries_paused()},
                       maintenance={k: v for k, v in maint.items()}, queue=queue, hard_max=HARD_MAX_ATTEMPTS)

    @app.post("/api/admin/recovery/policy")
    @admin_required
    def admin_recovery_policy():
        d = request.get_json(silent=True) or {}
        svc = str(d.get("service") or "").lower()
        if svc not in SERVICES:
            return jsonify(success=False, error="Unknown service"), 400
        cur = policy(svc)
        try:
            new = dict(max_attempts=int(d.get("max_attempts", cur["max_attempts"])), gap_minutes=int(d.get("gap_minutes", cur["gap_minutes"])),
                       window_minutes=int(d.get("window_minutes", cur["window_minutes"])), refund_fee=1 if d.get("refund_fee", cur["refund_fee"]) else 0)
        except (TypeError, ValueError):
            return jsonify(success=False, error="Numbers only"), 400
        new["refund_route"] = str(d.get("refund_route", cur["refund_route"])).lower()
        new["refund_mode"] = str(d.get("refund_mode", cur["refund_mode"])).lower()
        if new["refund_route"] not in ROUTES or new["refund_mode"] not in MODES:
            return jsonify(success=False, error="Unknown refund route or mode"), 400
        if not (0 <= new["max_attempts"] <= HARD_MAX_ATTEMPTS) or not (1 <= new["gap_minutes"] <= 720) or not (1 <= new["window_minutes"] <= 4320):
            return jsonify(success=False, error=f"Attempts 0-{HARD_MAX_ATTEMPTS}, gap 1-720 min, window 1-4320 min"), 400
        c = _conn()
        try:
            c.execute("INSERT INTO recovery_policy (service,max_attempts,gap_minutes,window_minutes,refund_route,refund_mode,refund_fee,updated_at,updated_by) "
                      "VALUES (?,?,?,?,?,?,?,?,'admin') ON CONFLICT(service) DO UPDATE SET max_attempts=excluded.max_attempts, "
                      "gap_minutes=excluded.gap_minutes, window_minutes=excluded.window_minutes, refund_route=excluded.refund_route, "
                      "refund_mode=excluded.refund_mode, refund_fee=excluded.refund_fee, updated_at=excluded.updated_at, updated_by='admin'",
                      (svc, new["max_attempts"], new["gap_minutes"], new["window_minutes"], new["refund_route"], new["refund_mode"], new["refund_fee"], _iso()))
            c.commit()
        finally:
            c.close()
        _load(True)
        logger.warning(f"RECOVERY: policy for {svc} set to {new}")
        return jsonify(success=True, service=svc, policy=policy(svc))

    @app.post("/api/admin/recovery/setting")
    @admin_required
    def admin_recovery_setting():
        d = request.get_json(silent=True) or {}
        key = str(d.get("key") or "")
        if key not in ("test_mode", "pause_retries"):
            return jsonify(success=False, error="Unknown setting"), 400
        c = _conn()
        try:
            c.execute("INSERT INTO recovery_settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                      (key, "1" if d.get("value") else "0"))
            c.commit()
        finally:
            c.close()
        _load(True)
        logger.warning(f"RECOVERY: setting {key} = {bool(d.get('value'))}")
        return jsonify(success=True, key=key, value=bool(d.get("value")))

    @app.post("/api/admin/recovery/maintenance")
    @admin_required
    def admin_recovery_maintenance():
        d = request.get_json(silent=True) or {}
        svc = str(d.get("service") or "").lower()
        if svc != "*" and svc not in SERVICES:
            return jsonify(success=False, error="Unknown service"), 400
        until = str(d.get("until") or "").strip() or None
        if until:
            try:
                dt = datetime.fromisoformat(until)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                until = dt.isoformat(timespec="minutes")
            except ValueError:
                return jsonify(success=False, error="Invalid end time"), 400
        c = _conn()
        try:
            c.execute("INSERT INTO service_maintenance (service,active,until,message,updated_at) VALUES (?,?,?,?,?) "
                      "ON CONFLICT(service) DO UPDATE SET active=excluded.active, until=excluded.until, message=excluded.message, updated_at=excluded.updated_at",
                      (svc, 1 if d.get("active") else 0, until, str(d.get("message") or "").strip()[:240], _iso()))
            c.commit()
        finally:
            c.close()
        _load(True)
        logger.warning(f"RECOVERY: maintenance {svc} active={bool(d.get('active'))} until={until}")
        return jsonify(success=True)

    @app.post("/api/admin/recovery/refund")
    @admin_required
    def admin_recovery_refund():
        """action: approve (run it now) | reject | done (manual refund completed elsewhere) | retry-failed."""
        d = request.get_json(silent=True) or {}
        ref, action = str(d.get("reference") or ""), str(d.get("action") or "")
        c = _conn()
        try:
            row = c.execute("SELECT * FROM refund_queue WHERE reference=?", (ref,)).fetchone()
            if not row:
                return jsonify(success=False, error="Refund not found"), 404
            if action == "reject":
                c.execute("UPDATE refund_queue SET status='rejected', processed_at=?, processed_by='admin' WHERE reference=? AND status IN ('queued','review','failed')", (_iso(), ref))
                c.commit()
                return jsonify(success=True, status="rejected")
            if action == "done":
                c.execute("UPDATE refund_queue SET status='processed', note='Marked done by admin (manual refund)', processed_at=?, processed_by='admin' WHERE reference=? AND status IN ('queued','review','failed','approved')", (_iso(), ref))
                c.commit()
                _mark_order_refunded(ref)
                return jsonify(success=True, status="processed")
            if action == "approve":
                c.execute("UPDATE refund_queue SET status='approved' WHERE reference=? AND status IN ('queued','review','failed','simulated')", (ref,))
                c.commit()
        finally:
            c.close()
        if action not in ("approve", "retry-failed"):
            return jsonify(success=False, error="Unknown action"), 400
        st = process_refund(ref, "admin")
        return jsonify(success=st is not None, status=st)

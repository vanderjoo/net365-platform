"""
Net365 admin alerts + reliable email outbox.

Why this exists
---------------
send_email_notification() is fire-and-forget: if the provider times out (it did, on Railway, while
SMTP port 587 was blocked) the message is simply lost and nobody is told. For security alerts that
is the worst possible behaviour. This module puts every alert in a database outbox first, tries to
send it immediately on a background thread, and keeps retrying (with back-off) for up to 24 hours.
Every outcome is logged, and /api/admin/alerts/status shows what is pending or failed.

Wiring (done in main.py):
    alerts = init_alerts(app, db.get_db_connection, send_email_notification, admin_required)
    alerts["send_email"]        -> drop-in for send_email_notification(to, subject, message, ...)
    alerts["send_admin_alert"]  -> send_admin_alert(subject, message, severity="warning")

Environment:
    ADMIN_ALERT_EMAILS   comma separated list of recipients (preferred)
    ADMIN_EMAIL          fallback single recipient
"""
import logging
import os
import re
import sqlite3
import threading
import time

from flask import jsonify, request

logger = logging.getLogger(__name__)

# seconds to wait before attempt 2, 3, 4 ... (the last value repeats)
BACKOFF = [30, 120, 600, 1800, 3600]
MAX_ATTEMPTS = 14
MAX_AGE_SECONDS = 24 * 3600
SWEEP_EVERY = 30

_state = {"get_conn": None, "send": None, "started": False}
_lock = threading.Lock()


def _conn():
    c = _state["get_conn"]()
    c.row_factory = sqlite3.Row
    return c


def _ensure_table():
    c = _conn()
    try:
        c.execute(
            """CREATE TABLE IF NOT EXISTS email_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                to_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                kind TEXT DEFAULT 'alert',
                status TEXT DEFAULT 'pending',
                attempts INTEGER DEFAULT 0,
                next_attempt REAL,
                last_error TEXT,
                created_at REAL,
                sent_at REAL
            )"""
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_outbox_status ON email_outbox(status, next_attempt)")
        c.commit()
    finally:
        c.close()


def recipients():
    raw = os.getenv("ADMIN_ALERT_EMAILS") or os.getenv("ADMIN_EMAIL") or ""
    out = []
    for part in re.split(r"[,;\s]+", raw):
        part = part.strip().lower()
        if part and "@" in part and part not in out:
            out.append(part)
    return out


def _mask(email):
    name, _, dom = email.partition("@")
    return (name[:1] + "***@" + dom) if name else email


def enqueue(to_email, subject, message, kind="alert", dispatch_now=True):
    """Store the email, then try to send it right away on a background thread."""
    now = time.time()
    c = _conn()
    try:
        cur = c.execute(
            "INSERT INTO email_outbox (to_email, subject, message, kind, status, attempts, next_attempt, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', 0, ?, ?)",
            (to_email, subject, message, kind, now, now),
        )
        c.commit()
        row_id = cur.lastrowid
    finally:
        c.close()
    if dispatch_now:
        threading.Thread(target=_attempt, args=(row_id,), daemon=True, name=f"outbox-{row_id}").start()
    return row_id


def _attempt(row_id):
    """Claim a row atomically (safe with several workers), send it, record the result."""
    now = time.time()
    c = _conn()
    try:
        claimed = c.execute(
            "UPDATE email_outbox SET next_attempt = ? WHERE id = ? AND status = 'pending' AND next_attempt <= ?",
            (now + 120, row_id, now),
        ).rowcount
        c.commit()
        if claimed != 1:
            return
        row = c.execute("SELECT * FROM email_outbox WHERE id = ?", (row_id,)).fetchone()
    finally:
        c.close()
    if not row:
        return

    ok, err = False, None
    try:
        # wait_seconds makes the sender report a real success/failure instead of "dispatched"
        ok = bool(_state["send"](row["to_email"], row["subject"], row["message"], wait_seconds=20))
        if not ok:
            err = "provider reported failure or timed out (see earlier log lines)"
    except Exception as e:  # never let a worker thread die
        err = str(e)[:300]

    attempts = (row["attempts"] or 0) + 1
    c = _conn()
    try:
        if ok:
            c.execute(
                "UPDATE email_outbox SET status='sent', attempts=?, sent_at=?, last_error=NULL WHERE id=?",
                (attempts, time.time(), row_id),
            )
            logger.info("ALERT EMAIL sent to %s (outbox #%s, attempt %s): %s", _mask(row["to_email"]), row_id, attempts, row["subject"])
        else:
            too_old = (time.time() - (row["created_at"] or time.time())) > MAX_AGE_SECONDS
            if attempts >= MAX_ATTEMPTS or too_old:
                c.execute("UPDATE email_outbox SET status='failed', attempts=?, last_error=? WHERE id=?", (attempts, err, row_id))
                logger.error("ALERT EMAIL GIVE UP for %s (outbox #%s) after %s attempts: %s", _mask(row["to_email"]), row_id, attempts, err)
            else:
                delay = BACKOFF[min(attempts - 1, len(BACKOFF) - 1)]
                c.execute(
                    "UPDATE email_outbox SET attempts=?, last_error=?, next_attempt=? WHERE id=?",
                    (attempts, err, time.time() + delay, row_id),
                )
                logger.warning("ALERT EMAIL attempt %s failed for %s (outbox #%s): %s. Retrying in %ss", attempts, _mask(row["to_email"]), row_id, err, delay)
        c.commit()
    finally:
        c.close()


def _sweeper():
    while True:
        time.sleep(SWEEP_EVERY)
        try:
            c = _conn()
            try:
                ids = [r["id"] for r in c.execute(
                    "SELECT id FROM email_outbox WHERE status='pending' AND next_attempt <= ? ORDER BY id LIMIT 20",
                    (time.time(),),
                ).fetchall()]
            finally:
                c.close()
            for i in ids:
                _attempt(i)
        except Exception as e:
            logger.warning("email outbox sweeper error: %s", e)


def send_admin_alert(subject, message, severity="warning"):
    """Queue an alert for every admin recipient. Returns how many were queued (0 = nobody configured)."""
    to_list = recipients()
    if not to_list:
        logger.error("ADMIN ALERT NOT SENT (no recipient): set ADMIN_ALERT_EMAILS on the platform service. Subject: %s", subject)
        return 0
    tag = {"critical": "CRITICAL", "warning": "WARNING", "info": "INFO"}.get(str(severity).lower(), "ALERT")
    subj = f"[Net365 {tag}] {subject}"
    for to in to_list:
        try:
            enqueue(to, subj, message, kind="alert")
        except Exception as e:
            logger.error("could not queue admin alert for %s: %s", _mask(to), e)
    return len(to_list)


def reliable_send_email(to_email, subject, message, **kwargs):
    """Drop-in for send_email_notification(to, subject, message): same arguments, but it is queued and retried.
    Returns True as soon as the message is safely queued. Calls that carry an attachment go straight through."""
    if kwargs.get("attachment"):
        return _state["send"](to_email, subject, message, **kwargs)
    try:
        enqueue(to_email, subject, message, kind="reliable")
        return True
    except Exception as e:
        logger.error("outbox unavailable (%s); sending directly", e)
        return _state["send"](to_email, subject, message)


def init_alerts(app, get_conn, send_email, admin_required):
    _state["get_conn"] = get_conn
    _state["send"] = send_email
    _ensure_table()
    with _lock:
        if not _state["started"]:
            _state["started"] = True
            threading.Thread(target=_sweeper, daemon=True, name="email-outbox-sweeper").start()

    rc = recipients()
    if not rc:
        logger.warning("Admin alerts: NO recipient configured. Set ADMIN_ALERT_EMAILS=you@yourdomain.com on the platform service.")
    else:
        logger.info("Admin alerts: recipients=%s", ", ".join(_mask(x) for x in rc))
        if any(x.endswith("@net365.com") for x in rc):
            logger.warning("Admin alerts: a recipient ends in @net365.com (your domain is net365co.com). Check ADMIN_ALERT_EMAILS / ADMIN_EMAIL.")

    @app.route("/api/admin/alerts/status", methods=["GET"], endpoint="alerts_status")
    @admin_required
    def alerts_status():
        c = _conn()
        try:
            counts = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) AS n FROM email_outbox GROUP BY status").fetchall()}
            recent = [
                {"id": r["id"], "to": _mask(r["to_email"]), "subject": r["subject"], "status": r["status"], "attempts": r["attempts"],
                 "last_error": r["last_error"], "created_at": r["created_at"], "sent_at": r["sent_at"]}
                for r in c.execute("SELECT * FROM email_outbox ORDER BY id DESC LIMIT 15").fetchall()
            ]
        finally:
            c.close()
        provider = "resend" if os.getenv("RESEND_API_KEY") else ("mailgun_api" if (os.getenv("MAILGUN_API_KEY") and os.getenv("MAILGUN_DOMAIN")) else ("smtp" if os.getenv("SMTP_PASSWORD") else None))
        return jsonify({
            "success": True,
            "recipients": [_mask(x) for x in rc],
            "recipient_count": len(recipients()),
            "provider": provider,
            "from_email": os.getenv("FROM_EMAIL") or None,
            "counts": counts,
            "recent": recent,
            "hints": ([] if recipients() else ["No recipient: set ADMIN_ALERT_EMAILS."]) +
                     (["FROM_EMAIL is a free-mail address; most inboxes reject mail sent 'from Gmail' by another server. Use an address on your verified domain."]
                      if (os.getenv("FROM_EMAIL") or "").split("@")[-1].lower() in ("gmail.com", "yahoo.com", "outlook.com", "googlemail.com") else []),
        })

    @app.route("/api/admin/alerts/test", methods=["POST"], endpoint="alerts_test")
    @admin_required
    def alerts_test():
        """Sends a test alert and waits for the real provider answer (up to ~25s)."""
        to_list = recipients()
        if not to_list:
            return jsonify({"success": False, "error": "No recipient configured. Set ADMIN_ALERT_EMAILS."}), 400
        results = {}
        for to in to_list:
            try:
                ok = bool(send_email(to, "[Net365 TEST] Admin alert delivery check",
                                     "If you can read this, security alerts will reach you. Sent from the admin panel.", wait_seconds=25))
            except Exception as e:
                ok = False
                results[_mask(to)] = f"error: {e}"
                continue
            results[_mask(to)] = "accepted by provider" if ok else "FAILED (check the platform logs and your email provider)"
        return jsonify({"success": all(v == "accepted by provider" for v in results.values()), "results": results})

    @app.route("/api/admin/alerts/retry", methods=["POST"], endpoint="alerts_retry")
    @admin_required
    def alerts_retry():
        c = _conn()
        try:
            c.execute("UPDATE email_outbox SET status='pending', next_attempt=?, attempts=0, created_at=? WHERE status='failed'", (time.time(), time.time()))
            c.commit()
            ids = [r["id"] for r in c.execute("SELECT id FROM email_outbox WHERE status='pending'").fetchall()]
        finally:
            c.close()
        for i in ids[:50]:
            threading.Thread(target=_attempt, args=(i,), daemon=True).start()
        return jsonify({"success": True, "retrying": len(ids)})

    return {"send_email": reliable_send_email, "send_admin_alert": send_admin_alert, "enqueue": enqueue}

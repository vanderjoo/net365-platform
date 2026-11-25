"""
Net365 - one phone number, one master table.

MASTER  : user_phones  (what the payment gate, the Telegram bot and the WhatsApp bot read)
MIRROR  : users.phone + users.phone_verified  (what the website profile and the admin user list show)

Before this module the website profile and the admin "Edit user" wrote only the mirror, while the gate and the bots read
only the master, so a number typed in one place was invisible in the other. Now:

  website profile / admin edit  -> write users.*  -> after_request hook copies it into user_phones   (push)
  Telegram / WhatsApp / identity page -> write user_phones (net365_identity) -> copied into users.*  (pull, done inside identity)
  admin override  POST /api/admin/users/<id>/phone  -> writes both, can mark verified / unverified

The verify-before-payment gate is NOT touched: it still needs a verified number in user_phones.
"""
import logging
import re
import sqlite3
from datetime import datetime, timezone

from flask import g, jsonify, request

logger = logging.getLogger("net365.phone_unify")

_ident = None


def _iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _v(row, key, idx=0, default=None):
    if row is None:
        return default
    try:
        return row[key]
    except Exception:
        try:
            return row[idx]
        except Exception:
            return default


def _norm(raw):
    """-> e164 or None. Accepts 0803..., 803..., 234803..., +234803..., and foreign numbers with +."""
    raw = str(raw or "").strip()
    if not raw:
        return None
    try:
        e, _region, err = _ident.normalize_phone(raw, "NG")
        return None if err else e
    except Exception:
        return None


def _users_cols(c):
    try:
        return {str(_v(r, "name", 1)) for r in c.execute("PRAGMA table_info(users)").fetchall()}
    except Exception:
        return set()


# ------------------------------------------------------------------------------------------------ push: users -> master
def push_users_to_master(uid, source="profile"):
    """The website profile / admin edit just wrote users.phone + users.phone_verified: make user_phones say the same.
    Returns a short status string for the log."""
    c = _ident._conn()
    row = c.execute("SELECT phone, phone_verified FROM users WHERE id = ?", (uid,)).fetchone()
    if row is None:
        return "no_user"
    raw = _v(row, "phone", 0, "")
    verified = 1 if int(_v(row, "phone_verified", 1, 0) or 0) else 0
    cur = c.execute("SELECT * FROM user_phones WHERE user_id = ?", (uid,)).fetchone()
    e164 = _norm(raw)
    if not str(raw or "").strip():                       # number removed
        if cur is not None:
            c.execute("DELETE FROM user_phones WHERE user_id = ?", (uid,))
            c.commit()
            return "removed"
        return "none"
    if not e164:
        return "invalid"
    now = _iso()
    try:
        if cur is None:
            c.execute("INSERT INTO user_phones (user_id, phone_e164, country, verified, verified_at, source, created_at, updated_at) "
                      "VALUES (?,?,?,?,?,?,?,?)", (uid, e164, None, verified, now if verified else None, source, now, now))
        else:
            same = _v(cur, "phone_e164", 1) == e164
            was = 1 if _v(cur, "verified", 3) else 0
            if same and was == verified:
                return "same"
            changed = 1 if (not same and was) else 0
            c.execute("UPDATE user_phones SET phone_e164=?, verified=?, verified_at=?, source=?, updated_at=?, changes=changes+? "
                      "WHERE user_id=?",
                      (e164, verified, now if verified else None, source, now, changed, uid))
        c.commit()
    except sqlite3.IntegrityError:
        try:
            c.rollback()
        except Exception:
            pass
        logger.warning("phone sync: %s is already verified on another account; user %s not changed in user_phones", e164[-4:], uid)
        return "phone_in_use"
    return "pushed"


# ------------------------------------------------------------------------------------------------ pull: master -> users
def pull_master_to_users(uid):
    """user_phones (bots / identity) changed: copy it onto users.phone and users.phone_verified for the profile and admin."""
    c = _ident._conn()
    cur = c.execute("SELECT * FROM user_phones WHERE user_id = ?", (uid,)).fetchone()
    if cur is None:
        return "none"
    cols = _users_cols(c)
    e164 = _v(cur, "phone_e164", 1)
    ver = 1 if _v(cur, "verified", 3) else 0
    sets, args = ["phone = ?"], [e164]
    if "phone_verified" in cols:
        sets.append("phone_verified = ?"); args.append(ver)
    if "phone_verified_at" in cols:
        sets.append("phone_verified_at = ?"); args.append(_v(cur, "verified_at", 4) if ver else None)
    args.append(uid)
    c.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", args)
    c.commit()
    return "pulled"


# ------------------------------------------------------------------------------------------------ one-time clean-up
def reconcile_all():
    """Run once at start-up: fix every account where the two places disagree.
    Rule: a VERIFIED number beats an unverified one; if both or neither are verified, the number the customer or admin
    typed on the website (users.phone) wins, because that is the one they can see."""
    c = _ident._conn()
    cols = _users_cols(c)
    if "phone" not in cols:
        return {}
    pv = "COALESCE(u.phone_verified,0)" if "phone_verified" in cols else "0"
    rows = c.execute(f"SELECT u.id AS id, u.phone AS phone, {pv} AS pv FROM users u").fetchall()
    stats = {"pushed": 0, "pulled": 0, "same": 0, "skipped": 0}
    for r in rows:
        uid, raw, upv = _v(r, "id", 0), _v(r, "phone", 1, ""), int(_v(r, "pv", 2, 0) or 0)
        cur = c.execute("SELECT * FROM user_phones WHERE user_id = ?", (uid,)).fetchone()
        e_users = _norm(raw)
        try:
            if cur is None:
                if e_users:
                    stats["pushed" if push_users_to_master(uid, "legacy") == "pushed" else "skipped"] += 1
                continue
            e_master, mver = _v(cur, "phone_e164", 1), 1 if _v(cur, "verified", 3) else 0
            if (e_users == e_master) and (upv == mver):
                stats["same"] += 1
            elif not e_users:
                stats["pulled" if pull_master_to_users(uid) == "pulled" else "skipped"] += 1
            elif e_users == e_master:                    # same number, flags differ: trust the verified one
                if mver and not upv or (mver and upv):
                    pull_master_to_users(uid); stats["pulled"] += 1
                else:
                    push_users_to_master(uid, "legacy"); stats["pushed"] += 1
            elif mver and not upv:
                pull_master_to_users(uid); stats["pulled"] += 1
            else:
                r2 = push_users_to_master(uid, "legacy")
                stats["pushed" if r2 == "pushed" else "skipped"] += 1
        except Exception:
            logger.warning("phone reconcile failed for user %s", uid, exc_info=True)
            stats["skipped"] += 1
    logger.info("Phone unify: reconcile done %s", stats)
    return stats


# ------------------------------------------------------------------------------------------------ wiring
_USER_PATHS = re.compile(r"/(account/phone/|user/phone/|user/account|user/profile|auth/profile)")
_ADMIN_USER = re.compile(r"^/api/admin/users/(\d+)(/.*)?$")


def _uid_from_response(resp):
    try:
        d = resp.get_json(silent=True) or {}
        u = d.get("user") or {}
        return int(u.get("id") or d.get("user_id") or 0) or None
    except Exception:
        return None


def init_phone_unify(app, db, admin_required, identity_module, admin_identity=None):
    global _ident
    _ident = identity_module
    try:
        reconcile_all()
    except Exception:
        logger.warning("phone unify: start-up reconcile failed", exc_info=True)

    @app.after_request
    def _phone_sync_after(resp):
        try:
            if resp.status_code >= 400 or request.method not in ("POST", "PUT", "PATCH"):
                return resp
            p = request.path
            uid, src = None, "profile"
            m = _ADMIN_USER.match(p)
            if m and not p.endswith("/phone"):
                uid, src = int(m.group(1)), "admin"
            elif p == "/api/admin/users" and request.method == "POST":
                uid, src = _uid_from_response(resp), "admin"
            elif _USER_PATHS.search(p):
                uid = getattr(g, "current_user_id", None)
            if uid:
                push_users_to_master(int(uid), src)
        except Exception:
            logger.warning("phone sync after_request failed", exc_info=True)
        return resp

    @app.get("/api/admin/users/<int:uid>/phone")
    @admin_required
    def admin_phone_get(uid):
        c = _ident._conn()
        u = c.execute("SELECT phone, phone_verified FROM users WHERE id = ?", (uid,)).fetchone()
        m = c.execute("SELECT * FROM user_phones WHERE user_id = ?", (uid,)).fetchone()
        return jsonify(success=True, user_id=uid,
                       profile={"phone": _v(u, "phone", 0, ""), "verified": bool(_v(u, "phone_verified", 1, 0))},
                       master=({"phone": _v(m, "phone_e164", 1), "verified": bool(_v(m, "verified", 3)),
                                "source": _v(m, "source", 5), "changes": _v(m, "changes", 6, 0)} if m is not None else None))

    @app.post("/api/admin/users/<int:uid>/phone")
    @admin_required
    def admin_phone_set(uid):
        """Admin help desk: set and/or verify / unverify a customer's number. Writes the master AND the mirror."""
        d = request.get_json(silent=True) or {}
        c = _ident._conn()
        if c.execute("SELECT 1 FROM users WHERE id = ?", (uid,)).fetchone() is None:
            return jsonify(success=False, error="User not found"), 404
        who = admin_identity() if callable(admin_identity) else "admin"
        cur = c.execute("SELECT * FROM user_phones WHERE user_id = ?", (uid,)).fetchone()
        if d.get("remove") is True:
            c.execute("DELETE FROM user_phones WHERE user_id = ?", (uid,))
            cols = _users_cols(c)
            c.execute("UPDATE users SET phone = NULL" + (", phone_verified = 0" if "phone_verified" in cols else "") + " WHERE id = ?", (uid,))
            c.commit()
            _ident._event(uid, "admin_phone_removed", who)
            return jsonify(success=True, removed=True)
        raw = d.get("phone")
        e164 = _norm(raw) if raw not in (None, "") else (_v(cur, "phone_e164", 1) if cur is not None else None)
        if raw not in (None, "") and not e164:
            return jsonify(success=False, error="That phone number does not look valid. Use 0803... or +234803..."), 400
        if not e164:
            u = c.execute("SELECT phone FROM users WHERE id = ?", (uid,)).fetchone()
            e164 = _norm(_v(u, "phone", 0, ""))
        if not e164:
            return jsonify(success=False, error="This customer has no number yet. Enter one."), 400
        verified = bool(d.get("verified")) if d.get("verified") is not None else bool(cur is not None and _v(cur, "verified", 3) and _v(cur, "phone_e164", 1) == e164)
        now = _iso()
        try:
            if cur is None:
                c.execute("INSERT INTO user_phones (user_id, phone_e164, country, verified, verified_at, source, created_at, updated_at) "
                          "VALUES (?,?,?,?,?,?,?,?)", (uid, e164, None, 1 if verified else 0, now if verified else None, "admin", now, now))
            else:
                changed = 1 if (_v(cur, "verified", 3) and _v(cur, "phone_e164", 1) != e164) else 0
                c.execute("UPDATE user_phones SET phone_e164=?, verified=?, verified_at=?, source='admin', updated_at=?, changes=changes+? WHERE user_id=?",
                          (e164, 1 if verified else 0, now if verified else None, now, changed, uid))
            c.commit()
        except sqlite3.IntegrityError:
            try:
                c.rollback()
            except Exception:
                pass
            return jsonify(success=False, error="That number is already verified on another account."), 409
        pull_master_to_users(uid)
        _ident._event(uid, "admin_phone_verified" if verified else "admin_phone_set", f"{who} {_ident.mask_phone(e164)}")
        return jsonify(success=True, phone=e164, verified=verified)

    logger.info("Phone unify ready: user_phones is the master; profile, admin and bots now share one number")
    return True

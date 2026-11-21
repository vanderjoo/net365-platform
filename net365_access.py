"""net365_access.py - guest / interactive demo / free evaluation access for Net365.

Extends the existing authentication; it does not replace it:
  * An evaluation account is an ordinary row in `users` (created with db.create_user, signed in with
    db.create_session and the normal session cookie). Everything evaluation-specific lives in side
    tables keyed by user_id, so the users table and every existing customer are untouched.
  * Account type, account status and execution environment are three separate columns.

Tables (all additive):
  evaluation_accounts  one row per evaluation account: type, status, environment, expiry, org details,
                       hashed browser id, test wallet, sandbox key hash, claim/upgrade timestamps
  evaluation_events    activity log (anonymous visitors too): demo runs, dashboard views, API docs, etc.
  evaluation_requests  extension / production-access / enquiry queue for the team
  demo_transactions    every SIMULATED transaction (anonymous demo, evaluation wallet, sandbox API)

Isolation: this module imports no payment, wallet or provider code. Nothing here can create a payment,
call Paystack/Stripe/Flutterwave/Reloadly, or touch the real wallet. Simulated results are produced
locally and are always labelled "simulated": true.

Enforcement: a before_request guard blocks every state-changing request from an evaluation account
(active, expired or suspended) unless the path is on a short allow-list. It is fail-closed, so a money
route added in future is protected without anyone remembering to list it.

Retention: evaluation records are never deleted. Tables carry triggers that abort DELETE. Expiry only
changes status to 'expired'. Personal data can be removed with the admin "anonymise" action, which blanks
identifying fields and keeps the record, its history and its conversion data.
"""

import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from flask import jsonify, make_response, request

ACCOUNT_TYPES = ["guest", "demo", "evaluation_personal", "evaluation_business",
                 "customer_personal", "customer_business", "admin"]
ACCOUNT_STATUSES = ["active", "expired", "suspended", "upgraded"]
ACCOUNT_ENVIRONMENTS = ["demo", "sandbox", "production"]
INTEL_CLASSES = ["personal_prospect", "business_prospect", "integration_prospect",
                 "strategic_partner", "investor_enquiry"]

BID_COOKIE = "n365_eval_bid"
SYNTHETIC_DOMAIN = "evaluation.net365.invalid"   # .invalid can never receive mail
TEST_WALLET_NGN = 100000.0

COUNTRIES = {"Nigeria": "NGN", "Ghana": "GHS", "Kenya": "KES"}
OPERATORS = {"MTN", "Airtel", "Glo", "9mobile", "Vodacom", "Telecel", "AirtelTigo", "Safaricom"}
SERVICES = {"Airtime", "Data"}
PAY_METHODS = {"Wallet (simulated)", "Card (simulated)", "Bank transfer (simulated)"}
DEMO_FEE_PCT = 2.5   # display only in simulations; real fees are computed by the payment code

# Writes an evaluation account may make. Everything else that changes state is refused.
WRITE_ALLOW = ("/api/auth/", "/api/evaluation/", "/api/demo/", "/api/sandbox/", "/api/access/",
               "/api/investors/")
EVENT_WHITELIST = {"explore", "demo_open", "api_docs", "services_view", "pricing_view", "utilities_view",
                   "scheduler_view", "investor_view", "cta_click"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evaluation_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    account_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    environment TEXT NOT NULL DEFAULT 'sandbox',
    started_at TEXT NOT NULL, expires_at TEXT NOT NULL, extended_count INTEGER DEFAULT 0,
    browser_id_hash TEXT, ip_hash TEXT, country TEXT, source TEXT,
    org_name TEXT, contact_name TEXT, contact_email TEXT, contact_email_verified_at TEXT,
    use_case TEXT, expected_volume TEXT, org_country TEXT, profile_completed_at TEXT,
    claimed_email TEXT, claimed_at TEXT, upgraded_at TEXT,
    test_balance REAL DEFAULT 100000,
    sandbox_key_hash TEXT, sandbox_key_prefix TEXT, sandbox_key_issued_at TEXT,
    intel_class_manual TEXT, notes TEXT,
    last_seen_at TEXT, anonymised_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_eval_browser_type ON evaluation_accounts(browser_id_hash, account_type);
CREATE INDEX IF NOT EXISTS idx_eval_status ON evaluation_accounts(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_eval_keyhash ON evaluation_accounts(sandbox_key_hash);
CREATE TABLE IF NOT EXISTS evaluation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, day TEXT NOT NULL, user_id INTEGER, anon_id TEXT, event TEXT NOT NULL,
    detail TEXT, country TEXT, ip_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_evev_user ON evaluation_events(user_id, ts);
CREATE INDEX IF NOT EXISTS idx_evev_event ON evaluation_events(event, ts);
CREATE TABLE IF NOT EXISTS evaluation_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, kind TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
    org_name TEXT, contact_name TEXT, contact_email TEXT, message TEXT, details TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP, decided_at TEXT, decision_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_evreq_status ON evaluation_requests(status, kind);
CREATE TABLE IF NOT EXISTS demo_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference TEXT UNIQUE NOT NULL, environment TEXT NOT NULL,   -- 'demo' | 'sandbox'
    user_id INTEGER, anon_id TEXT, country TEXT, operator TEXT, service TEXT, phone_tail TEXT,
    amount REAL, fee REAL, total REAL, currency TEXT, payment_method TEXT,
    status TEXT, message TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_demo_user ON demo_transactions(user_id, created_at);
CREATE TRIGGER IF NOT EXISTS trg_eval_accounts_keep BEFORE DELETE ON evaluation_accounts
  BEGIN SELECT RAISE(ABORT, 'evaluation accounts are retained; use the anonymise action'); END;
CREATE TRIGGER IF NOT EXISTS trg_eval_events_keep BEFORE DELETE ON evaluation_events
  BEGIN SELECT RAISE(ABORT, 'evaluation history is retained'); END;
CREATE TRIGGER IF NOT EXISTS trg_eval_requests_keep BEFORE DELETE ON evaluation_requests
  BEGIN SELECT RAISE(ABORT, 'evaluation requests are retained'); END;
"""


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _plus_days(days, base=None):
    b = datetime.strptime(base, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) if base else datetime.now(timezone.utc)
    return (b + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def _iso(ts):
    return (ts or "").replace(" ", "T") + "Z" if ts else None


def _days_left(expires_at):
    try:
        d = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)
        return max(0, int(d.total_seconds() // 86400) + (1 if d.total_seconds() % 86400 else 0))
    except Exception:
        return 0


def _sha(s):
    return hashlib.sha256((s or "").encode()).hexdigest()


def _eval_days():
    try:
        return max(1, int(os.getenv("EVAL_DAYS", "30")))
    except ValueError:
        return 30


def simulate_transaction(country, operator, service, amount, method, phone=None):
    """Pure function: never touches a database, a payment gateway or a provider."""
    if country not in COUNTRIES:
        return None, "Choose a supported country."
    if operator not in OPERATORS:
        return None, "Choose a supported operator."
    if service not in SERVICES:
        return None, "Choose airtime or data."
    if method not in PAY_METHODS:
        return None, "Choose a demonstration payment method."
    try:
        amount = round(float(amount), 2)
    except (TypeError, ValueError):
        return None, "Enter an amount."
    if amount < 100 or amount > 50000:
        return None, "Enter an amount between 100 and 50,000."
    fee = round(amount * DEMO_FEE_PCT / 100, 2)
    tail = re.sub(r"\D", "", phone or "")[-4:]
    # Documented test numbers for sandbox/evaluation users: ...0000 fails, ...1111 stays pending.
    status, message = "SIMULATED_SUCCESS", "Simulated delivery completed. Nothing was charged or sent."
    if tail == "0000":
        status, message = "SIMULATED_FAILED", "Simulated provider failure (test number ending 0000)."
    elif tail == "1111":
        status, message = "SIMULATED_PENDING", "Simulated provider timeout (test number ending 1111)."
    return {"country": country, "operator": operator, "service": service, "amount": amount, "fee": fee,
            "total": round(amount + fee, 2), "currency": COUNTRIES[country], "payment_method": method,
            "status": status, "message": message, "phone_tail": tail}, None


def init_access(app, *, get_conn, get_authenticated_user, create_user, create_session, set_auth_cookie,
                get_user_by_email, create_otp, verify_otp, send_email, admin_required, get_client_ip,
                rate_hit_db=None, frontend_url="", notify_email=None, logger=None):
    import logging
    logger = logger or logging.getLogger(__name__)

    c0 = get_conn()
    try:
        c0.executescript(_SCHEMA)
        c0.commit()
    finally:
        c0.close()

    salt = (os.getenv("ACCESS_HASH_SALT") or app.config.get("SECRET_KEY") or "net365").encode()
    import hmac as _hmac

    def iph(ip):
        return _hmac.new(salt, (ip or "").encode(), hashlib.sha256).hexdigest()[:20]

    def q(sql, args=(), one=False):
        c = get_conn()
        try:
            rows = [dict(r) for r in c.execute(sql, args).fetchall()]
        finally:
            c.close()
        return (rows[0] if rows else None) if one else rows

    def run(sql, args=()):
        c = get_conn()
        try:
            cur = c.execute(sql, args)
            c.commit()
            return cur.lastrowid, cur.rowcount
        finally:
            c.close()

    _cache = {}

    def drop_cache(uid):
        _cache.pop(uid, None)

    def profile(uid):
        """Evaluation row for a user, with expiry applied (status flips to 'expired', never deleted)."""
        hit = _cache.get(uid)
        if hit and hit[0] > time.time():
            return hit[1]
        row = q("SELECT * FROM evaluation_accounts WHERE user_id=?", (uid,), one=True)
        if row and row["status"] == "active" and row["expires_at"] <= _now():
            run("UPDATE evaluation_accounts SET status='expired' WHERE user_id=? AND status='active'", (uid,))
            row["status"] = "expired"
            log_event(uid, None, "evaluation_expired", None)
        _cache[uid] = (time.time() + 15, row)
        return row

    def log_event(uid, anon, event, detail=None):
        try:
            ip = get_client_ip() if request else ""
        except Exception:
            ip = ""
        try:
            run("INSERT INTO evaluation_events (ts, day, user_id, anon_id, event, detail, country, ip_hash) VALUES (?,?,?,?,?,?,?,?)",
                (_now(), _now()[:10], uid, anon, event,
                 (json.dumps(detail, default=str)[:500] if detail is not None else None),
                 (request.headers.get("CF-IPCountry") if request else None), iph(ip)))
        except Exception as e:
            logger.debug(f"evaluation event failed: {e}")

    _seen = {}

    def enrich_user(user):
        """Adds evaluation fields to a sanitized user dict. Normal customers are returned unchanged."""
        try:
            if not user or not user.get("id"):
                return user
            p = profile(user["id"])
            if not p:
                return user
            is_eval = p["account_type"].startswith("evaluation_") and p["status"] != "upgraded"
            user["account_type"] = p["account_type"]
            user["account_status"] = user.get("account_status") or "active"
            user["evaluation_status"] = p["status"]
            user["account_environment"] = p["environment"]
            user["is_evaluation"] = bool(is_eval)
            if is_eval:
                user["evaluation_type"] = "business" if p["account_type"] == "evaluation_business" else "personal"
                user["evaluation_expires_at"] = _iso(p["expires_at"])
                user["evaluation_days_left"] = _days_left(p["expires_at"])
                if p["org_name"]:
                    user["organisation"] = p["org_name"]
                # dashboard activity / return visits: at most one event per hour per account
                if _seen.get(user["id"], 0) < time.time() - 3600:
                    _seen[user["id"]] = time.time()
                    log_event(user["id"], None, "dashboard_view")
                    run("UPDATE evaluation_accounts SET last_seen_at=? WHERE user_id=?", (_now(), user["id"]))
        except Exception as e:
            logger.debug(f"enrich_user failed: {e}")
        return user

    # ------------------------------------------------------------ helpers
    def same_site():
        origin = request.headers.get("Origin")
        if not origin:
            return True  # non-browser client; browsers always send Origin on cross-site POST
        host = urlsplit(origin).netloc.lower()
        ok = {request.host.lower()}
        if frontend_url:
            ok.add(urlsplit(frontend_url).netloc.lower())
        extra = os.getenv("ACCESS_ALLOWED_ORIGINS", "")
        ok.update(urlsplit(x.strip()).netloc.lower() for x in extra.split(",") if x.strip())
        return host in ok

    _mem = {}

    def limited(key, window, limit):
        try:
            if rate_hit_db:
                return rate_hit_db(key, window) > limit
        except Exception:
            pass
        now = time.time()
        arr = [t for t in _mem.get(key, []) if now - t < window] + [now]
        _mem[key] = arr
        return len(arr) > limit

    def current_eval():
        user = get_authenticated_user()
        if not user:
            return None, None, (jsonify({"success": False, "error": "Authentication required"}), 401)
        p = profile(user["id"])
        if not p:
            return user, None, (jsonify({"success": False, "error": "This is not an evaluation account."}), 400)
        return user, p, None

    def public_user(uid):
        u = get_authenticated_user()
        base = {k: v for k, v in (u or {}).items() if k not in ("password_hash", "password", "session_token", "token")}
        return enrich_user(base)

    def classify(p, c):
        """Prospect class. Investor interest needs explicit evidence; a network or IP alone never counts."""
        if p.get("intel_class_manual") in INTEL_CLASSES:
            return p["intel_class_manual"]
        if c.get("investor_enquiry"):
            return "investor_enquiry"
        if p["account_type"] in ("evaluation_business", "customer_business"):
            if c.get("partner_request"):
                return "strategic_partner"
            if p.get("sandbox_key_issued_at") or c.get("sandbox_txns", 0) >= 3 or c.get("api_docs", 0) >= 3:
                return "integration_prospect"
            return "business_prospect"
        return "personal_prospect"

    def counts_for(uid, email_domain=None):
        out = {}
        r = q("SELECT SUM(environment='sandbox') s, SUM(environment='demo') d FROM demo_transactions WHERE user_id=?", (uid,), one=True) or {}
        out["sandbox_txns"], out["demo_txns"] = r.get("s") or 0, r.get("d") or 0
        out["api_docs"] = (q("SELECT COUNT(*) n FROM evaluation_events WHERE user_id=? AND event='api_docs'", (uid,), one=True) or {}).get("n", 0)
        reqs = q("SELECT kind FROM evaluation_requests WHERE user_id=?", (uid,))
        out["investor_enquiry"] = any(x["kind"] == "investor_enquiry" for x in reqs)
        out["partner_request"] = any(x["kind"] in ("production_access", "partnership") for x in reqs)
        out["active_days"] = (q("SELECT COUNT(DISTINCT day) n FROM evaluation_events WHERE user_id=?", (uid,), one=True) or {}).get("n", 0)
        if email_domain:
            try:
                out["investor_enquiry"] = out["investor_enquiry"] or bool(q(
                    "SELECT 1 x FROM investor_leads WHERE email_domain=? AND status='confirmed' LIMIT 1", (email_domain,), one=True))
            except Exception:
                pass
        return out

    # ------------------------------------------------------------ the fail-closed guard
    _blocked_logged = {}

    @app.before_request
    def evaluation_guard():
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None
        path = request.path
        if path.startswith(WRITE_ALLOW) or path.startswith("/api/admin/"):
            return None
        if not (request.cookies or request.headers.get("Authorization")):
            return None
        try:
            user = get_authenticated_user()
            p = profile(user["id"]) if user else None
        except Exception:
            return None
        if not p or (p["status"] == "upgraded" and p["environment"] == "production"):
            return None
        expired = p["status"] == "expired"
        if _blocked_logged.get(user["id"], 0) < time.time() - 300:
            _blocked_logged[user["id"]] = time.time()
            log_event(user["id"], None, "blocked_live_action", {"path": path, "status": p["status"]})
        return jsonify({
            "success": False,
            "error_code": "EVALUATION_EXPIRED" if expired else "EVALUATION_ACCOUNT",
            "error": ("Your evaluation has ended. Extend it or upgrade to continue." if expired else
                      "Evaluation accounts use simulated transactions only. Claim and upgrade your account to make live payments."),
            "actions": ["extend", "claim", "upgrade"],
        }), 403

    # ------------------------------------------------------------ expiry sweeper (status only, no deletes)
    def sweeper():
        while True:
            time.sleep(1800)
            try:
                run("UPDATE evaluation_accounts SET status='expired' WHERE status='active' AND expires_at <= ?", (_now(),))
            except Exception as e:
                logger.debug(f"evaluation sweeper failed: {e}")
    threading.Thread(target=sweeper, daemon=True).start()

    # ------------------------------------------------------------ provisioning
    def bid_cookie(resp, bid):
        resp.set_cookie(BID_COOKIE, bid, max_age=60 * 60 * 24 * 365, httponly=True, samesite="Lax",
                        secure=request.is_secure, path="/")
        return resp

    @app.route("/api/evaluation/start", methods=["POST"])
    def evaluation_start():
        if not same_site():
            return jsonify({"success": False, "error": "Request blocked."}), 403
        d = request.get_json(silent=True) or {}
        etype = "business" if str(d.get("evaluation_type")) == "business" else "personal"
        atype = f"evaluation_{etype}"
        ip = get_client_ip()
        if limited(f"{iph(ip)}|eval-start-h", 3600, 6) or limited(f"{iph(ip)}|eval-start-d", 86400, 20):
            return jsonify({"success": False, "error": "Too many evaluation requests from this network. Please try again later."}), 429

        existing_user = get_authenticated_user()
        if existing_user and not profile(existing_user["id"]):
            return jsonify({"success": False, "error": "You are signed in to a Net365 account. Sign out to start a separate evaluation."}), 409

        company = str(d.get("company_name") or "").strip()[:120]
        if etype == "business" and len(company) < 2:
            return jsonify({"success": False, "error": "Enter your organisation name to start a business evaluation."}), 400
        contact_email = str(d.get("contact_email") or "").strip().lower()[:200]
        if contact_email and not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}", contact_email):
            return jsonify({"success": False, "error": "That contact email does not look valid."}), 400

        bid = request.cookies.get(BID_COOKIE) or secrets.token_urlsafe(24)
        bh = _sha(bid)

        # Resume: the same browser gets its own evaluation back instead of a duplicate account.
        row = q("SELECT * FROM evaluation_accounts WHERE browser_id_hash=? AND account_type=?", (bh, atype), one=True)
        created = False
        if row is None:
            email = f"eval-{uuid.uuid4().hex[:20]}@{SYNTHETIC_DOMAIN}"
            name = f"{company} (evaluation)" if etype == "business" else "Evaluation user"
            uid = create_user(email=email, password=secrets.token_urlsafe(32), full_name=name, phone=None, referral_code=None)
            if not uid:
                logger.error("evaluation: create_user failed")
                return jsonify({"success": False, "error": "Could not create the evaluation account. Please try again."}), 500
            try:
                run("INSERT INTO evaluation_accounts (user_id, account_type, status, environment, started_at, expires_at, "
                    "browser_id_hash, ip_hash, country, source, org_name, contact_email, last_seen_at, test_balance) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (uid, atype, "active", "sandbox", _now(), _plus_days(_eval_days()), bh, iph(ip),
                     request.headers.get("CF-IPCountry"), str(d.get("source") or request.args.get("utm_source") or "")[:60],
                     company or None, contact_email or None, _now(), TEST_WALLET_NGN))
                created = True
            except sqlite3.IntegrityError:   # two clicks raced: use the winner's account
                row = q("SELECT * FROM evaluation_accounts WHERE browser_id_hash=? AND account_type=?", (bh, atype), one=True)
            if created:
                row = q("SELECT * FROM evaluation_accounts WHERE user_id=?", (uid,), one=True)
                log_event(uid, None, "evaluation_started", {"type": etype, "org": bool(company)})
        else:
            drop_cache(row["user_id"])
            row = profile(row["user_id"])

        if row["status"] == "suspended":
            return jsonify({"success": False, "error": "This evaluation has been suspended. Contact Net365."}), 403
        if row["status"] == "upgraded":
            return jsonify({"success": False, "error": "This evaluation was upgraded. Please sign in with your Net365 account."}), 409

        token = create_session(row["user_id"])
        user = build_user(row["user_id"])
        if not created:
            log_event(row["user_id"], None, "evaluation_resumed", {"type": etype})
        resp = make_response(jsonify({"success": True, "resumed": not created, "user": user,
                                      "message": "Evaluation ready." if created else "Welcome back. Your evaluation was resumed."}))
        set_auth_cookie(resp, token)
        return bid_cookie(resp, bid)

    def build_user(uid):
        r = q("SELECT * FROM users WHERE id=?", (uid,), one=True)
        if not r:
            return None
        for k in ("password_hash", "password", "session_token", "token"):
            r.pop(k, None)
        return enrich_user(r)

    # ------------------------------------------------------------ evaluation dashboard API
    @app.route("/api/evaluation/me", methods=["GET"])
    def evaluation_me():
        user, p, err = current_eval()
        if err:
            return err
        hist = q("SELECT reference, environment, operator, service, amount, total, currency, status, created_at "
                 "FROM demo_transactions WHERE user_id=? ORDER BY id DESC LIMIT 20", (user["id"],))
        is_eval = p["account_type"].startswith("evaluation_") and p["status"] != "upgraded"
        perms = (["browse", "simulate_transactions", "test_wallet", "history", "analytics"] if p["status"] == "active" else
                 ["browse", "extend", "claim", "upgrade"]) if is_eval else ["standard_customer"]
        if p["account_type"] == "evaluation_business" and p["status"] == "active":
            perms += ["sandbox_api", "bulk_testing", "production_request"]
        return jsonify({
            "success": True, "simulated": True,
            "account": {"type": p["account_type"], "status": p["status"], "environment": p["environment"],
                        "started_at": _iso(p["started_at"]), "expires_at": _iso(p["expires_at"]),
                        "days_left": _days_left(p["expires_at"]), "extensions": p["extended_count"],
                        "organisation": p["org_name"], "claimed": bool(p["claimed_at"]),
                        "claimed_email": p["claimed_email"], "profile_complete": bool(p["profile_completed_at"]),
                        "contact_verified": bool(p["contact_email_verified_at"]),
                        "has_sandbox_key": bool(p["sandbox_key_hash"]), "sandbox_key_prefix": p["sandbox_key_prefix"]},
            "test_wallet": {"currency": "NGN", "balance": round(p["test_balance"] or 0, 2), "label": "Evaluation wallet (test money)"},
            "permissions": perms, "history": hist,
            "test_numbers": {"ending 0000": "simulated failure", "ending 1111": "simulated pending/timeout", "any other": "simulated success"},
        })

    @app.route("/api/evaluation/simulate", methods=["POST"])
    def evaluation_simulate():
        user, p, err = current_eval()
        if err:
            return err
        if p["status"] != "active":
            return jsonify({"success": False, "error_code": "EVALUATION_EXPIRED", "error": "Your evaluation has ended. Extend or upgrade to continue."}), 403
        d = request.get_json(silent=True) or {}
        if limited(f"eval-sim|{user['id']}", 60, 30):
            return jsonify({"success": False, "error": "Slow down a little."}), 429
        sim, e = simulate_transaction(d.get("country"), d.get("operator"), d.get("service"), d.get("amount"),
                                      d.get("payment_method") or "Wallet (simulated)", d.get("phone"))
        if e:
            return jsonify({"success": False, "error": e}), 400
        ref = "EVAL-" + secrets.token_hex(5).upper()
        # test wallet only: atomic debit, never below zero, never the real wallet
        spend = sim["total"] if sim["status"] != "SIMULATED_FAILED" else 0
        c = get_conn()
        try:
            cur = c.execute("UPDATE evaluation_accounts SET test_balance = test_balance - ? WHERE user_id=? AND test_balance >= ?",
                            (spend, user["id"], spend))
            if cur.rowcount == 0:
                c.rollback()
                return jsonify({"success": False, "error": "Your test wallet is empty. Reset it from the evaluation panel."}), 400
            c.execute("INSERT INTO demo_transactions (reference, environment, user_id, country, operator, service, phone_tail, amount, fee, total, "
                      "currency, payment_method, status, message) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (ref, "sandbox", user["id"], sim["country"], sim["operator"], sim["service"], sim["phone_tail"], sim["amount"],
                       sim["fee"], sim["total"], sim["currency"], sim["payment_method"], sim["status"], sim["message"]))
            c.commit()
        finally:
            c.close()
        drop_cache(user["id"])
        log_event(user["id"], None, "sandbox_txn", {"ref": ref, "status": sim["status"], "amount": sim["amount"]})
        bal = q("SELECT test_balance b FROM evaluation_accounts WHERE user_id=?", (user["id"],), one=True)["b"]
        return jsonify({"success": True, "simulated": True, "reference": ref, "transaction": sim, "test_balance": round(bal, 2)})

    @app.route("/api/evaluation/wallet/reset", methods=["POST"])
    def evaluation_wallet_reset():
        user, p, err = current_eval()
        if err:
            return err
        if p["status"] != "active":
            return jsonify({"success": False, "error": "Evaluation is not active."}), 403
        run("UPDATE evaluation_accounts SET test_balance=? WHERE user_id=?", (TEST_WALLET_NGN, user["id"]))
        drop_cache(user["id"])
        log_event(user["id"], None, "test_wallet_reset")
        return jsonify({"success": True, "test_balance": TEST_WALLET_NGN})

    # ------------------------------------------------------------ claim (email verification) / extend / upgrade
    def send_code(email, purpose):
        code = create_otp(email, otp_type="email", ttl_minutes=10)
        send_email(email, f"Your Net365 {purpose} code",
                   f'Your verification code is <span class="amount">{code}</span>. It expires in 10 minutes.')

    EMAIL_RE = r"[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}"

    @app.route("/api/evaluation/claim/start", methods=["POST"])
    def claim_start():
        user, p, err = current_eval()
        if err:
            return err
        if not same_site():
            return jsonify({"success": False, "error": "Request blocked."}), 403
        email = str((request.get_json(silent=True) or {}).get("email") or "").strip().lower()
        if not re.fullmatch(EMAIL_RE, email) or email.endswith("." + SYNTHETIC_DOMAIN.split(".", 1)[1]) or email.endswith(SYNTHETIC_DOMAIN):
            return jsonify({"success": False, "error": "Enter a valid email address."}), 400
        if limited(f"claim|{user['id']}", 600, 3):
            return jsonify({"success": False, "error": "Too many codes requested. Wait a few minutes."}), 429
        other = get_user_by_email(email)
        if other and other.get("id") != user["id"]:
            return jsonify({"success": False, "error_code": "EMAIL_IN_USE",
                            "error": "That email already has a Net365 account. Sign in with it instead."}), 409
        try:
            send_code(email, "evaluation claim")
        except Exception as e:
            logger.error(f"claim code failed: {e}")
            return jsonify({"success": False, "error": "Could not send the code. Try again."}), 502
        log_event(user["id"], None, "claim_started")
        return jsonify({"success": True, "message": "We sent a 6-digit code to that email."})

    @app.route("/api/evaluation/claim/verify", methods=["POST"])
    def claim_verify():
        user, p, err = current_eval()
        if err:
            return err
        d = request.get_json(silent=True) or {}
        email, code = str(d.get("email") or "").strip().lower(), str(d.get("code") or "").strip()
        if limited(f"claimv|{user['id']}", 600, 8):
            return jsonify({"success": False, "error": "Too many attempts."}), 429
        if not verify_otp(email, code, otp_type="email"):
            return jsonify({"success": False, "error": "Invalid or expired code."}), 400
        other = get_user_by_email(email)
        if other and other.get("id") != user["id"]:
            return jsonify({"success": False, "error_code": "EMAIL_IN_USE", "error": "That email already has a Net365 account."}), 409
        c = get_conn()
        try:
            c.execute("UPDATE users SET email=?, email_verified=1 WHERE id=?", (email, user["id"]))
            c.execute("UPDATE evaluation_accounts SET claimed_email=?, claimed_at=? WHERE user_id=?", (email, _now(), user["id"]))
            c.commit()
        finally:
            c.close()
        drop_cache(user["id"])
        log_event(user["id"], None, "claim_completed", {"domain": email.split("@")[1]})
        return jsonify({"success": True, "email": email,
                        "next": "To sign in on other devices, use 'Forgot password' with this email to choose a password.",
                        "user": build_user(user["id"])})

    @app.route("/api/evaluation/extend", methods=["POST"])
    def evaluation_extend():
        user, p, err = current_eval()
        if err:
            return err
        if p["status"] in ("upgraded", "suspended"):
            return jsonify({"success": False, "error": "This account cannot be extended."}), 400
        if p["account_type"] == "evaluation_business":
            rid, _ = run("INSERT INTO evaluation_requests (user_id, kind, org_name, contact_email, message) VALUES (?,?,?,?,?)",
                         (user["id"], "extension", p["org_name"], p["contact_email"], str((request.get_json(silent=True) or {}).get("message") or "")[:1000]))
            log_event(user["id"], None, "extension_requested")
            notify("Evaluation extension requested", f"{p['org_name']} asked to extend its Net365 evaluation (request #{rid}).")
            return jsonify({"success": True, "pending": True, "message": "Extension requested. Net365 will review it for qualified business prospects."})
        if not p["claimed_at"]:
            return jsonify({"success": False, "error_code": "CLAIM_REQUIRED", "error": "Verify your email to extend your evaluation."}), 400
        if (p["extended_count"] or 0) >= 1:
            return jsonify({"success": False, "error": "You have already used your extension. Upgrade to continue."}), 400
        base = p["expires_at"] if p["status"] == "active" else _now()
        run("UPDATE evaluation_accounts SET expires_at=?, status='active', extended_count=extended_count+1 WHERE user_id=?",
            (_plus_days(_eval_days(), base), user["id"]))
        drop_cache(user["id"])
        log_event(user["id"], None, "extended")
        return jsonify({"success": True, "user": build_user(user["id"])})

    @app.route("/api/evaluation/upgrade", methods=["POST"])
    def evaluation_upgrade():
        user, p, err = current_eval()
        if err:
            return err
        if p["status"] == "upgraded":
            return jsonify({"success": False, "error": "Already upgraded."}), 400
        if p["status"] == "suspended":
            return jsonify({"success": False, "error": "This account is suspended."}), 403
        if not p["claimed_at"]:
            return jsonify({"success": False, "error_code": "CLAIM_REQUIRED",
                            "error": "Verify your email first so the account becomes yours."}), 400
        if p["account_type"] == "evaluation_business":
            run("INSERT INTO evaluation_requests (user_id, kind, org_name, contact_name, contact_email, message) VALUES (?,?,?,?,?,?)",
                (user["id"], "production_access", p["org_name"], p["contact_name"], p["claimed_email"],
                 str((request.get_json(silent=True) or {}).get("message") or "Upgrade to a business account")[:1000]))
            log_event(user["id"], None, "upgrade_requested", {"type": "business"})
            notify("Business upgrade requested", f"{p['org_name']} requested production access.")
            return jsonify({"success": True, "pending": True, "message": "Request received. Net365 will contact you to complete business onboarding."})
        run("UPDATE evaluation_accounts SET account_type='customer_personal', status='upgraded', environment='production', upgraded_at=? WHERE user_id=?",
            (_now(), user["id"]))
        drop_cache(user["id"])
        log_event(user["id"], None, "upgraded", {"type": "personal"})
        return jsonify({"success": True, "user": build_user(user["id"]), "message": "Your account is now a standard Net365 account."})

    def notify(subject, body):
        if notify_email:
            try:
                send_email(notify_email, subject, body)
            except Exception:
                pass

    # ------------------------------------------------------------ business onboarding + sandbox key
    @app.route("/api/evaluation/business/profile", methods=["POST"])
    def business_profile():
        user, p, err = current_eval()
        if err:
            return err
        if p["account_type"] != "evaluation_business":
            return jsonify({"success": False, "error": "Business evaluation only."}), 400
        d = request.get_json(silent=True) or {}
        org, name = str(d.get("organisation") or p["org_name"] or "").strip()[:120], str(d.get("contact_name") or "").strip()[:100]
        email = str(d.get("work_email") or "").strip().lower()
        if len(org) < 2 or len(name) < 2 or not re.fullmatch(EMAIL_RE, email):
            return jsonify({"success": False, "error": "Organisation, your name and a valid work email are required."}), 400
        if limited(f"bizp|{user['id']}", 600, 3):
            return jsonify({"success": False, "error": "Too many attempts."}), 429
        run("UPDATE evaluation_accounts SET org_name=?, contact_name=?, contact_email=?, contact_email_verified_at=NULL, use_case=?, "
            "expected_volume=?, org_country=?, profile_completed_at=? WHERE user_id=?",
            (org, name, email, str(d.get("use_case") or "")[:500], str(d.get("expected_volume") or "")[:60],
             str(d.get("country") or "")[:60], _now(), user["id"]))
        drop_cache(user["id"])
        try:
            send_code(email, "business evaluation")
        except Exception as e:
            logger.error(f"business code failed: {e}")
            return jsonify({"success": False, "error": "Could not send the code."}), 502
        log_event(user["id"], None, "business_profile_saved", {"domain": email.split("@")[1]})
        return jsonify({"success": True, "message": "Profile saved. Enter the code we emailed to your work address."})

    @app.route("/api/evaluation/business/verify", methods=["POST"])
    def business_verify():
        user, p, err = current_eval()
        if err:
            return err
        if p["account_type"] != "evaluation_business" or not p["profile_completed_at"]:
            return jsonify({"success": False, "error": "Complete the organisation profile first."}), 400
        if limited(f"bizv|{user['id']}", 600, 8):
            return jsonify({"success": False, "error": "Too many attempts."}), 429
        code = str((request.get_json(silent=True) or {}).get("code") or "").strip()
        if not verify_otp(p["contact_email"], code, otp_type="email"):
            return jsonify({"success": False, "error": "Invalid or expired code."}), 400
        run("UPDATE evaluation_accounts SET contact_email_verified_at=? WHERE user_id=?", (_now(), user["id"]))
        drop_cache(user["id"])
        log_event(user["id"], None, "business_email_verified")
        return jsonify({"success": True})

    @app.route("/api/evaluation/business/credentials", methods=["POST"])
    def business_credentials():
        user, p, err = current_eval()
        if err:
            return err
        if p["account_type"] != "evaluation_business" or p["status"] != "active":
            return jsonify({"success": False, "error": "Sandbox credentials need an active business evaluation."}), 403
        if not p["profile_completed_at"] or not p["contact_email_verified_at"]:
            return jsonify({"success": False, "error_code": "PROFILE_REQUIRED",
                            "error": "Complete the organisation profile and verify your work email to receive sandbox credentials."}), 400
        if limited(f"bizk|{user['id']}", 3600, 5):
            return jsonify({"success": False, "error": "Too many key requests."}), 429
        key = "n365_sbx_" + secrets.token_hex(20)
        run("UPDATE evaluation_accounts SET sandbox_key_hash=?, sandbox_key_prefix=?, sandbox_key_issued_at=? WHERE user_id=?",
            (_sha(key), key[:14], _now(), user["id"]))
        drop_cache(user["id"])
        log_event(user["id"], None, "sandbox_key_issued")
        return jsonify({"success": True, "api_key": key, "note": "Shown once. Store it securely; generating a new key revokes this one.",
                        "base_url": "/api/sandbox/v1", "docs": "/api/sandbox/v1/openapi.json"})

    @app.route("/api/evaluation/production-request", methods=["POST"])
    def production_request():
        user, p, err = current_eval()
        if err:
            return err
        d = request.get_json(silent=True) or {}
        kind = d.get("kind") if d.get("kind") in ("production_access", "partnership", "investor_enquiry", "business_enquiry") else "production_access"
        if limited(f"req|{user['id']}", 3600, 5):
            return jsonify({"success": False, "error": "Too many requests."}), 429
        if kind == "production_access" and p["account_type"] == "evaluation_business" and not p["contact_email_verified_at"]:
            return jsonify({"success": False, "error_code": "PROFILE_REQUIRED", "error": "Verify your work email before requesting production access."}), 400
        rid, _ = run("INSERT INTO evaluation_requests (user_id, kind, org_name, contact_name, contact_email, message, details) VALUES (?,?,?,?,?,?,?)",
                     (user["id"], kind, p["org_name"], p["contact_name"], p["contact_email"] or p["claimed_email"],
                      str(d.get("message") or "")[:1500], json.dumps({"volume": str(d.get("expected_volume") or "")[:60]})))
        log_event(user["id"], None, "request_" + kind)
        notify(f"Net365 {kind.replace('_', ' ')}", f"{p['org_name'] or 'An evaluation user'} submitted request #{rid} ({kind}).")
        return jsonify({"success": True, "request_id": rid, "message": "Thank you. Net365 will be in touch."})

    # ------------------------------------------------------------ anonymous demo + public beacons
    def anon_id():
        return request.cookies.get(BID_COOKIE) and _sha(request.cookies.get(BID_COOKIE))[:16] or iph(get_client_ip())

    @app.route("/api/demo/simulate", methods=["POST"])
    def demo_simulate():
        d = request.get_json(silent=True) or {}
        ip = get_client_ip()
        if limited(f"{iph(ip)}|demo", 600, 40):
            return jsonify({"success": False, "error": "Too many demo runs. Please wait a few minutes."}), 429
        sim, e = simulate_transaction(d.get("country"), d.get("operator"), d.get("service"), d.get("amount"),
                                      d.get("payment_method") or "Wallet (simulated)", None)
        if e:
            return jsonify({"success": False, "error": e}), 400
        ref = "DEMO-" + secrets.token_hex(5).upper()
        a = anon_id()
        run("INSERT INTO demo_transactions (reference, environment, anon_id, country, operator, service, phone_tail, amount, fee, total, currency, "
            "payment_method, status, message) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ref, "demo", a, sim["country"], sim["operator"], sim["service"], "", sim["amount"], sim["fee"], sim["total"], sim["currency"],
             sim["payment_method"], sim["status"], sim["message"]))
        u = get_authenticated_user()
        log_event(u["id"] if u else None, a, "demo_txn", {"ref": ref, "country": sim["country"], "operator": sim["operator"]})
        return jsonify({"success": True, "simulated": True, "reference": ref, "transaction": sim,
                        "label": "SIMULATION: no payment was taken and nothing was delivered."})

    @app.route("/api/demo/sample", methods=["GET"])
    def demo_sample():
        """Static sample data for the demonstration dashboard. Fabricated, labelled as such."""
        log_event(None, anon_id(), "demo_open", {"what": "sample_dashboard"})
        return jsonify({"success": True, "simulated": True, "label": "Sample data for demonstration only",
            "wallets": [{"currency": "NGN", "balance": 148250.00}, {"currency": "USD", "balance": 312.40}, {"currency": "GBP", "balance": 95.10}],
            "history": [{"reference": "DEMO-A1B2C3", "type": "Airtime", "operator": "MTN", "amount": 5000, "status": "Delivered"},
                        {"reference": "DEMO-D4E5F6", "type": "Electricity", "operator": "Eko DisCo", "amount": 15000, "status": "Delivered"},
                        {"reference": "DEMO-G7H8I9", "type": "Data", "operator": "Airtel", "amount": 3000, "status": "Delivered"},
                        {"reference": "DEMO-J1K2L3", "type": "Airtime", "operator": "Glo", "amount": 2000, "status": "Failed, refund pending"}],
            "analytics": {"monthly_spend": [42000, 51000, 47500, 63000, 58200, 71000], "success_rate": 98.4, "avg_delivery_seconds": 3.2},
            "scheduled": [{"label": "Mum's MTN airtime", "amount": 2000, "next_run": "1st of each month"}],
            "bulk": {"rows": 250, "delivered": 247, "failed": 3}})

    _ev_rate = {}

    @app.route("/api/access/event", methods=["POST"])
    def access_event():
        d = request.get_json(silent=True) or {}
        ev = str(d.get("event") or "")
        if ev not in EVENT_WHITELIST or limited(f"{iph(get_client_ip())}|acc", 60, 60):
            return ("", 204)
        u = get_authenticated_user()
        log_event(u["id"] if u else None, anon_id(), ev, {"label": str(d.get("label") or "")[:60]})
        return ("", 204)

    # ------------------------------------------------------------ sandbox API (business evaluation)
    def sandbox_auth():
        key = request.headers.get("X-API-Key") or (request.headers.get("Authorization", "")[7:] if request.headers.get("Authorization", "").lower().startswith("bearer ") else "")
        if not key.startswith("n365_sbx_"):
            return None, (jsonify({"success": False, "error": "Missing or invalid sandbox API key."}), 401)
        p = q("SELECT * FROM evaluation_accounts WHERE sandbox_key_hash=?", (_sha(key),), one=True)
        if not p:
            return None, (jsonify({"success": False, "error": "Invalid sandbox API key."}), 401)
        p = profile(p["user_id"])
        if p["status"] != "active":
            return None, (jsonify({"success": False, "error": "Evaluation is not active.", "status": p["status"]}), 403)
        if limited(f"sbx|{p['user_id']}", 60, 120):
            return None, (jsonify({"success": False, "error": "Rate limit: 120 requests per minute."}), 429)
        return p, None

    def sandbox_txn(p, d):
        sim, e = simulate_transaction(d.get("country", "Nigeria"), d.get("operator"), d.get("service", "Airtime"), d.get("amount"),
                                      "Wallet (simulated)", d.get("phone"))
        if e:
            return None, e
        ref = "SBX-" + secrets.token_hex(6).upper()
        spend = sim["total"] if sim["status"] != "SIMULATED_FAILED" else 0
        c = get_conn()
        try:
            cur = c.execute("UPDATE evaluation_accounts SET test_balance = test_balance - ? WHERE user_id=? AND test_balance >= ?", (spend, p["user_id"], spend))
            if cur.rowcount == 0:
                c.rollback()
                return None, "Insufficient test balance. Reset it from the evaluation panel."
            c.execute("INSERT INTO demo_transactions (reference, environment, user_id, country, operator, service, phone_tail, amount, fee, total, "
                      "currency, payment_method, status, message) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (ref, "sandbox", p["user_id"], sim["country"], sim["operator"], sim["service"], sim["phone_tail"], sim["amount"], sim["fee"],
                       sim["total"], sim["currency"], "api", sim["status"], sim["message"]))
            c.commit()
        finally:
            c.close()
        drop_cache(p["user_id"])
        sim["reference"] = ref
        return sim, None

    @app.route("/api/sandbox/v1/topup", methods=["POST"])
    def sandbox_topup():
        p, err = sandbox_auth()
        if err:
            return err
        sim, e = sandbox_txn(p, request.get_json(silent=True) or {})
        if e:
            return jsonify({"success": False, "error": e}), 400
        log_event(p["user_id"], None, "sandbox_api_txn", {"ref": sim["reference"], "status": sim["status"]})
        return jsonify({"success": True, "simulated": True, "transaction": sim})

    @app.route("/api/sandbox/v1/bulk", methods=["POST"])
    def sandbox_bulk():
        p, err = sandbox_auth()
        if err:
            return err
        items = (request.get_json(silent=True) or {}).get("items")
        if not isinstance(items, list) or not 1 <= len(items) <= 100:
            return jsonify({"success": False, "error": "Send 1 to 100 items."}), 400
        out = []
        for it in items:
            sim, e = sandbox_txn(p, it if isinstance(it, dict) else {})
            out.append({"success": e is None, "error": e, "transaction": sim})
        log_event(p["user_id"], None, "sandbox_bulk", {"items": len(items)})
        return jsonify({"success": True, "simulated": True, "results": out,
                        "summary": {"total": len(out), "ok": sum(1 for o in out if o["success"])}})

    @app.route("/api/sandbox/v1/transactions/<ref>", methods=["GET"])
    def sandbox_get(ref):
        p, err = sandbox_auth()
        if err:
            return err
        r = q("SELECT reference, operator, service, amount, fee, total, currency, status, message, created_at FROM demo_transactions "
              "WHERE reference=? AND user_id=?", (ref, p["user_id"]), one=True)
        return (jsonify({"success": True, "simulated": True, "transaction": r}) if r else (jsonify({"success": False, "error": "Not found"}), 404))

    @app.route("/api/sandbox/v1/balance", methods=["GET"])
    def sandbox_balance():
        p, err = sandbox_auth()
        if err:
            return err
        return jsonify({"success": True, "simulated": True, "currency": "NGN", "balance": round(profile(p["user_id"])["test_balance"], 2)})

    @app.route("/api/sandbox/v1/openapi.json", methods=["GET"])
    def sandbox_docs():
        log_event(None, anon_id(), "api_docs", {"doc": "sandbox_openapi"})
        u = get_authenticated_user()
        if u:
            log_event(u["id"], None, "api_docs")
        return jsonify({"openapi": "3.0.3", "info": {"title": "Net365 Sandbox API", "version": "1.0",
            "description": "Simulated only. Nothing is charged or delivered. Test numbers: ending 0000 fails, ending 1111 stays pending."},
            "servers": [{"url": "/api/sandbox/v1"}],
            "components": {"securitySchemes": {"ApiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}},
            "security": [{"ApiKey": []}],
            "paths": {
              "/topup": {"post": {"summary": "Simulate an airtime or data top-up",
                 "requestBody": {"content": {"application/json": {"schema": {"type": "object", "required": ["operator", "amount", "phone"],
                   "properties": {"country": {"type": "string", "enum": list(COUNTRIES)}, "operator": {"type": "string"},
                                  "service": {"type": "string", "enum": sorted(SERVICES)}, "amount": {"type": "number", "minimum": 100, "maximum": 50000},
                                  "phone": {"type": "string"}}}}}}}},
              "/bulk": {"post": {"summary": "Simulate up to 100 top-ups in one call"}},
              "/transactions/{reference}": {"get": {"summary": "Fetch a simulated transaction"}},
              "/balance": {"get": {"summary": "Test wallet balance"}}}})

    # ------------------------------------------------------------ admin
    def classify_row(r):
        dom = (r.get("claimed_email") or r.get("contact_email") or "").split("@")[-1] or None
        c = counts_for(r["user_id"], dom if dom and dom not in ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com") else None)
        return classify(r, c), c

    def rows_since(days=None):
        sql = "SELECT * FROM evaluation_accounts"
        args = ()
        if days:
            sql += " WHERE started_at >= ?"
            args = (_plus_days(-days),)
        return q(sql + " ORDER BY id DESC LIMIT 5000", args)

    @app.route("/api/admin/evaluations/summary", methods=["GET"])
    @admin_required
    def admin_eval_summary():
        days = max(1, min(365, request.args.get("days", 90, type=int)))
        rows = rows_since(days)
        now = _now()
        total = len(rows)
        eff = lambda r: "expired" if (r["status"] == "active" and r["expires_at"] <= now) else r["status"]
        by_class = {k: 0 for k in INTEL_CLASSES}
        sums = {"claimed": 0, "upgraded": 0, "returned": 0, "keys": 0, "profiles": 0}
        for r in rows:
            cl, c = classify_row(r)
            by_class[cl] += 1
            sums["claimed"] += 1 if r["claimed_at"] else 0
            sums["upgraded"] += 1 if r["status"] == "upgraded" else 0
            sums["returned"] += 1 if c["active_days"] >= 2 else 0
            sums["keys"] += 1 if r["sandbox_key_issued_at"] else 0
            sums["profiles"] += 1 if r["profile_completed_at"] else 0
        ev = lambda name, d=days: (q("SELECT COUNT(*) n FROM evaluation_events WHERE event=? AND ts >= ?", (name, _plus_days(-d)), one=True) or {}).get("n", 0)
        dt = q("SELECT SUM(environment='demo' AND user_id IS NULL) anon, SUM(environment='sandbox') sandbox FROM demo_transactions WHERE created_at >= ?", (_plus_days(-days),), one=True) or {}
        reqs = q("SELECT kind, status, COUNT(*) n FROM evaluation_requests GROUP BY kind, status")
        return jsonify({"success": True, "days": days, "kpis": {
            "started": total, "personal": sum(1 for r in rows if r["account_type"] == "evaluation_personal"),
            "business": sum(1 for r in rows if r["account_type"] == "evaluation_business"),
            "active": sum(1 for r in rows if eff(r) == "active"), "expired": sum(1 for r in rows if eff(r) == "expired"),
            "suspended": sum(1 for r in rows if r["status"] == "suspended"), "claimed": sums["claimed"], "upgraded": sums["upgraded"],
            "returned": sums["returned"], "conversion_pct": round(100 * sums["upgraded"] / total, 1) if total else 0,
            "claim_pct": round(100 * sums["claimed"] / total, 1) if total else 0,
            "sandbox_keys": sums["keys"], "business_profiles": sums["profiles"],
            "demo_runs_anonymous": dt.get("anon") or 0, "sandbox_transactions": dt.get("sandbox") or 0,
            "explore_clicks": ev("explore"), "demo_opens": ev("demo_open"), "api_docs_views": ev("api_docs"),
            "blocked_live_actions": ev("blocked_live_action")},
            "by_class": by_class, "requests": reqs,
            "note": "Investor class needs explicit evidence (a confirmed investor interest form, an investor enquiry, or a manual tag). A network or IP address never sets it."})

    @app.route("/api/admin/evaluations/list", methods=["GET"])
    @admin_required
    def admin_eval_list():
        t, s = request.args.get("type"), request.args.get("status")
        rows = rows_since(request.args.get("days", 365, type=int))
        out, now = [], _now()
        for r in rows:
            st = "expired" if (r["status"] == "active" and r["expires_at"] <= now) else r["status"]
            if t and r["account_type"] != t or s and st != s:
                continue
            cl, c = classify_row(r)
            out.append({"id": r["id"], "user_id": r["user_id"], "type": r["account_type"], "status": st, "environment": r["environment"],
                        "organisation": r["org_name"], "contact": r["contact_name"], "email": r["claimed_email"] or r["contact_email"],
                        "email_verified": bool(r["claimed_at"] or r["contact_email_verified_at"]), "country": r["country"], "source": r["source"],
                        "started_at": r["started_at"], "expires_at": r["expires_at"], "days_left": _days_left(r["expires_at"]) if st == "active" else 0,
                        "last_seen_at": r["last_seen_at"], "active_days": c["active_days"], "demo_txns": c["demo_txns"],
                        "sandbox_txns": c["sandbox_txns"], "api_docs": c["api_docs"], "has_key": bool(r["sandbox_key_hash"]),
                        "intel_class": cl, "manual_class": bool(r["intel_class_manual"]), "anonymised": bool(r["anonymised_at"])})
            if len(out) >= 300:
                break
        return jsonify({"success": True, "evaluations": out})

    @app.route("/api/admin/evaluations/<int:eid>", methods=["GET"])
    @admin_required
    def admin_eval_detail(eid):
        r = q("SELECT * FROM evaluation_accounts WHERE id=?", (eid,), one=True)
        if not r:
            return jsonify({"success": False, "error": "Not found"}), 404
        for k in ("sandbox_key_hash", "browser_id_hash", "ip_hash"):
            r.pop(k, None)
        return jsonify({"success": True, "account": r,
                        "events": q("SELECT ts, event, detail, country FROM evaluation_events WHERE user_id=? ORDER BY id DESC LIMIT 200", (r["user_id"],)),
                        "transactions": q("SELECT reference, environment, operator, total, currency, status, created_at FROM demo_transactions WHERE user_id=? ORDER BY id DESC LIMIT 50", (r["user_id"],)),
                        "requests": q("SELECT id, kind, status, message, created_at, decided_at FROM evaluation_requests WHERE user_id=? ORDER BY id DESC", (r["user_id"],))})

    @app.route("/api/admin/evaluations/<int:eid>/action", methods=["POST"])
    @admin_required
    def admin_eval_action(eid):
        d = request.get_json(silent=True) or {}
        act = d.get("action")
        r = q("SELECT * FROM evaluation_accounts WHERE id=?", (eid,), one=True)
        if not r:
            return jsonify({"success": False, "error": "Not found"}), 404
        uid = r["user_id"]
        if act == "extend":
            days = max(1, min(180, int(d.get("days") or _eval_days())))
            base = r["expires_at"] if r["status"] == "active" and r["expires_at"] > _now() else _now()
            run("UPDATE evaluation_accounts SET expires_at=?, status=CASE WHEN status='upgraded' THEN status ELSE 'active' END, extended_count=extended_count+1 WHERE id=?",
                (_plus_days(days, base), eid))
        elif act == "suspend":
            run("UPDATE evaluation_accounts SET status='suspended' WHERE id=?", (eid,))
        elif act == "reactivate":
            run("UPDATE evaluation_accounts SET status=CASE WHEN expires_at > ? THEN 'active' ELSE 'expired' END WHERE id=? AND status='suspended'", (_now(), eid))
        elif act == "classify":
            cl = d.get("intel_class") or None
            if cl is not None and cl not in INTEL_CLASSES:
                return jsonify({"success": False, "error": "Unknown class"}), 400
            run("UPDATE evaluation_accounts SET intel_class_manual=? WHERE id=?", (cl, eid))
        elif act == "note":
            run("UPDATE evaluation_accounts SET notes=? WHERE id=?", (str(d.get("note") or "")[:1000], eid))
        elif act == "anonymise":
            run("UPDATE evaluation_accounts SET contact_name=NULL, contact_email=NULL, claimed_email=NULL, org_name=CASE WHEN org_name IS NULL THEN NULL ELSE 'Anonymised' END, "
                "use_case=NULL, notes=NULL, anonymised_at=? WHERE id=?", (_now(), eid))
            if r["account_type"].startswith("evaluation_"):   # never touch an upgraded customer's login
                run("UPDATE users SET email=?, full_name='Anonymised' WHERE id=?", (f"anonymised-{uid}@{SYNTHETIC_DOMAIN}", uid))
        else:
            return jsonify({"success": False, "error": "Unknown action"}), 400
        drop_cache(uid)
        log_event(uid, None, "admin_" + str(act))
        return jsonify({"success": True})

    @app.route("/api/admin/evaluations/requests", methods=["GET"])
    @admin_required
    def admin_eval_requests():
        st = request.args.get("status")
        rows = q("SELECT * FROM evaluation_requests" + (" WHERE status=?" if st else "") + " ORDER BY id DESC LIMIT 200", (st,) if st else ())
        return jsonify({"success": True, "requests": rows})

    @app.route("/api/admin/evaluations/requests/<int:rid>", methods=["POST"])
    @admin_required
    def admin_eval_request_decide(rid):
        d = request.get_json(silent=True) or {}
        decision = d.get("decision")
        req = q("SELECT * FROM evaluation_requests WHERE id=?", (rid,), one=True)
        if not req or decision not in ("approved", "declined"):
            return jsonify({"success": False, "error": "Invalid request"}), 400
        run("UPDATE evaluation_requests SET status=?, decided_at=?, decision_note=? WHERE id=?", (decision, _now(), str(d.get("note") or "")[:500], rid))
        if decision == "approved" and req["user_id"]:
            if req["kind"] == "extension":
                run("UPDATE evaluation_accounts SET expires_at=?, status='active', extended_count=extended_count+1 WHERE user_id=?", (_plus_days(_eval_days()), req["user_id"]))
            elif req["kind"] == "production_access":
                run("UPDATE evaluation_accounts SET account_type='customer_business', status='upgraded', environment='production', upgraded_at=? WHERE user_id=?", (_now(), req["user_id"]))
            drop_cache(req["user_id"])
        log_event(req["user_id"], None, f"request_{decision}", {"kind": req["kind"]})
        return jsonify({"success": True})

    logger.info("Access layer ready (/api/evaluation/*, /api/demo/*, /api/sandbox/v1/*, admin evaluations)")
    return {"enrich_user": enrich_user, "profile": profile}

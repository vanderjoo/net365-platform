"""Net365 unified identity: account type, tier, workspaces, capabilities and the Affiliate programme.

One login (users) can hold a primary account type and extra workspaces (an Individual who starts a business, becomes an agent,
a developer, or joins the Affiliate programme). Wallet, history and customer ID never change.

  GET  /api/profile/account-types   types, fields, benefits, verification rules, tiers (public)
  GET  /api/profile                 profile card, capabilities, workspaces, affiliate programme, nav keys
  POST /api/profile/setup           choose or change the primary type: {account_type, country, details{}}
  POST /api/profile/update          country / business details
  POST /api/profile/activate        add a workspace or join Affiliate: {kind, details{}}
  POST /api/profile/tier-request    ask for a tier change: {tier}
  POST /api/admin/profile/<uid>     admin: tier, verification, type, workspace status (X-Admin-Secret)

Tables (created on start): account_profiles, account_workspaces, affiliate_profiles, account_audit_logs.
Not built yet: account_members / roles / permissions (multi-user corporate teams).
"""
import json
import logging
import re
from datetime import datetime

from flask import g, jsonify, request

logger = logging.getLogger("net365.profile")

TIERS = {"Starter": "Basic account.", "Standard": "Expanded transaction capabilities.",
         "Premium": "Advanced services and higher limits.", "Enterprise": "Customised corporate services."}
VERIFICATION = ("Unverified", "Pending", "Verified", "Rejected")
ECOSYSTEMS = {"personal": "Personal", "business": "Business", "ecosystem": "Ecosystem"}

_F = lambda k, label, req=False, kind="text", opts=None, ph="": {"key": k, "label": label, "required": req, "type": kind, "options": opts or [], "placeholder": ph}
COUNTRY = _F("country", "Country", True, "text", None, "Nigeria")

ACCOUNT_TYPES = {
    "individual": {"label": "Individual", "ecosystem": "personal", "icon": "user", "business": False,
                   "blurb": "Payments and everyday digital services.",
                   "benefits": ["Airtime, data, bills and TV", "Scheduled payments", "Rewards and referrals"],
                   "for": "People paying for themselves and family.", "verification": "Email confirmation.",
                   "fields": [COUNTRY]},
    "sme": {"label": "SME / Business", "ecosystem": "business", "icon": "store", "business": True,
            "blurb": "Grow your business, manage payments and advertise.",
            "benefits": ["Business wallet and bulk recharge", "Transaction reports", "Advertising credits"],
            "for": "Shops, small companies and freelancers.", "verification": "Business details reviewed by our team.",
            "fields": [_F("business_name", "Business name", True), _F("reg_status", "Registration status", True, "select", ["Registered", "Not yet registered"]),
                       _F("business_category", "Business category", True, "select", ["Retail", "Telecoms and airtime", "Services", "Food and hospitality", "Education", "Technology", "Other"]),
                       _F("business_email", "Business email", False, "email"), _F("contact_person", "Contact person", True),
                       _F("business_address", "Business address", False), COUNTRY]},
    "corporate": {"label": "Corporate", "ecosystem": "business", "icon": "building", "business": True,
                  "blurb": "Enterprise payment management and business integrations.",
                  "benefits": ["Multi-user finance teams", "Approval flows", "Dedicated support"],
                  "for": "Registered companies and organisations.", "verification": "Company registration and authorised representative checked.",
                  "fields": [_F("business_name", "Registered company name", True), _F("reg_no", "Registration number", True), _F("tax_id", "Tax identification number"),
                             _F("representative", "Authorised representative", True), _F("business_email", "Corporate email", True, "email"),
                             _F("business_address", "Business address", True), COUNTRY]},
    "developer": {"label": "Developer / API", "ecosystem": "ecosystem", "icon": "code", "business": True,
                  "blurb": "Integrate Net365 services into your applications.",
                  "benefits": ["API keys and webhooks", "Integration analytics", "Airtime, data and bills endpoints"],
                  "for": "Developers and companies building apps.", "verification": "Application and organisation reviewed before live keys.",
                  "fields": [_F("business_name", "Developer or organisation name", True), _F("app_name", "Application name", True),
                             _F("integration", "Intended integration", True, "select", ["Airtime and data", "Utilities and bills", "Wallet and payments", "Several of these"]),
                             _F("website", "Website or application URL", False, "url"), COUNTRY]},
    "agent": {"label": "Agent / Reseller", "ecosystem": "ecosystem", "icon": "network-wired", "business": True,
              "blurb": "Sell digital services and earn commissions.",
              "benefits": ["Wholesale pricing", "Sub-accounts for your sellers", "Commission reports"],
              "for": "Shops, kiosks and distributors.", "verification": "Identity and trading location checked.",
              "fields": [_F("business_name", "Trading name", True), _F("location", "Town or state", True), _F("contact_person", "Contact person", True), COUNTRY]},
    "partner": {"label": "Strategic Partner", "ecosystem": "ecosystem", "icon": "handshake", "business": True,
                "blurb": "Build commercial and technology partnerships.",
                "benefits": ["Partner desk", "Co-built services", "Joint reporting"],
                "for": "Telcos, banks, fintechs and platforms.", "verification": "Reviewed by the partnerships team.",
                "fields": [_F("business_name", "Organisation", True), _F("partnership_type", "Partnership type", True, "select", ["Commercial", "Technology", "Distribution"]),
                           _F("contact_person", "Contact person", True), _F("website", "Website", False, "url"), COUNTRY]},
}

# capability key -> label. Every account has the CORE ones.
CAPS = {
    "wallet": "Wallet", "airtime": "Airtime and data", "utilities": "Utilities and TV", "scheduled": "Scheduled payments", "referral": "Rewards and referrals",
    "business_wallet": "Business wallet", "bulk": "Bulk recharge", "reports": "Transaction reports", "advertising": "Advertising credits", "merchant": "Merchant services",
    "team": "Team access and approvals", "api": "Business API", "reseller": "Wholesale pricing and sub-accounts", "partner_desk": "Partner desk",
    "affiliate": "Affiliate commissions",
}
CORE = ("wallet", "airtime", "utilities", "scheduled", "referral")
TYPE_CAPS = {
    "individual": CORE,
    "sme": CORE + ("business_wallet", "bulk", "reports", "advertising", "merchant", "api"),
    "corporate": CORE + ("business_wallet", "bulk", "reports", "advertising", "merchant", "api", "team"),
    "developer": CORE + ("api", "reports"),
    "agent": CORE + ("bulk", "reports", "reseller"),
    "partner": CORE + ("reports", "api", "partner_desk"),
}
CURRENCY = {
    "nigeria": "NGN", "ghana": "GHS", "kenya": "KES", "south africa": "ZAR", "tanzania": "TZS", "uganda": "UGX", "rwanda": "RWF",
    "ethiopia": "ETB", "egypt": "EGP", "morocco": "MAD", "algeria": "DZD", "tunisia": "TND", "senegal": "XOF", "cote d'ivoire": "XOF",
    "cameroon": "XAF", "benin": "XOF", "togo": "XOF", "burkina faso": "XOF", "mali": "XOF", "niger": "XOF", "sierra leone": "SLE",
    "liberia": "LRD", "gambia": "GMD", "guinea": "GNF", "zambia": "ZMW", "zimbabwe": "USD", "malawi": "MWK", "mozambique": "MZN",
    "botswana": "BWP", "namibia": "NAD", "angola": "AOA", "dr congo": "CDF", "republic of the congo": "XAF", "gabon": "XAF",
    "sudan": "SDG", "somalia": "USD", "mauritius": "MUR", "united kingdom": "GBP", "united states": "USD", "canada": "CAD",
    "ireland": "EUR", "france": "EUR", "germany": "EUR", "spain": "EUR", "italy": "EUR", "netherlands": "EUR", "portugal": "EUR",
    "belgium": "EUR", "switzerland": "CHF", "united arab emirates": "AED", "saudi arabia": "SAR", "qatar": "QAR", "india": "INR",
    "pakistan": "PKR", "bangladesh": "BDT", "china": "CNY", "philippines": "PHP", "brazil": "BRL", "australia": "AUD",
}

_state = {}


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
        c.execute("CREATE TABLE IF NOT EXISTS account_profiles (user_id INTEGER PRIMARY KEY, account_type TEXT NOT NULL DEFAULT 'individual', "
                  "tier TEXT, verification_status TEXT, country TEXT DEFAULT 'Nigeria', currency TEXT DEFAULT 'NGN', business_name TEXT, "
                  "business_reg_no TEXT, details TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        try:
            c.execute("ALTER TABLE account_profiles ADD COLUMN details TEXT")
        except Exception:
            pass
        c.execute("CREATE TABLE IF NOT EXISTS account_workspaces (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT NOT NULL, "
                  "status TEXT NOT NULL DEFAULT 'Pending', details TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, kind))")
        c.execute("CREATE TABLE IF NOT EXISTS affiliate_profiles (user_id INTEGER PRIMARY KEY, status TEXT NOT NULL DEFAULT 'Active', "
                  "audience TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        c.execute("CREATE TABLE IF NOT EXISTS account_audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, actor TEXT, action TEXT, "
                  "detail TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        c.commit()
    finally:
        _close(c)


def customer_id(uid):
    return "N365-%08d" % int(uid)


def referral_id(uid):
    return "N365-REF-%04d" % int(uid)


def _col(row, name, default=None):
    try:
        return row[name] if name in row.keys() else default
    except Exception:
        return default


def _status(user):
    st = str(_col(user, "status", "") or "").strip().lower()
    if st in ("suspended", "blocked", "banned", "disabled", "closed"):
        return st.capitalize()
    if _col(user, "is_active", 1) in (0, False, "0"):
        return "Suspended"
    return "Active"


def _fmt_date(raw):
    s = str(raw or "").replace("T", " ").split(".")[0]
    for f, n in (("%Y-%m-%d %H:%M:%S", 19), ("%Y-%m-%d", 10)):
        try:
            return datetime.strptime(s[:n], f).strftime("%d %B %Y").lstrip("0")
        except ValueError:
            continue
    return ""


def _clean(v, n=120):
    return re.sub(r"\s+", " ", str(v or "")).strip()[:n]


def _audit(c, uid, actor, action, detail=""):
    c.execute("INSERT INTO account_audit_logs (user_id, actor, action, detail) VALUES (?, ?, ?, ?)", (uid, actor, action, _clean(detail, 400)))


def _default_verification(atype, user):
    if ACCOUNT_TYPES[atype]["business"]:
        return "Pending"
    return "Verified" if _col(user, "email_verified", 0) else "Unverified"


def _check_details(atype, details, country=None):
    """Whitelist and require the fields of this type. Returns (clean, error)."""
    out, details = {}, details or {}
    for f in ACCOUNT_TYPES[atype]["fields"]:
        v = _clean(details.get(f["key"]) if f["key"] != "country" else (country or details.get("country")), 160)
        if f["options"] and v and v not in f["options"]:
            return None, "Choose a valid option for %s." % f["label"].lower()
        if f["type"] == "email" and v and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            return None, "Enter a valid %s." % f["label"].lower()
        if f["type"] == "url" and v and not re.match(r"^https?://", v, re.I):
            return None, "%s must start with http:// or https://" % f["label"]
        if f["required"] and not v:
            return None, "%s is required." % f["label"]
        if v:
            out[f["key"]] = v
    return out, None


def _get_or_create(uid):
    _schema()
    c = _conn()
    try:
        user = c.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if not user:
            return None, None
        row = c.execute("SELECT * FROM account_profiles WHERE user_id = ?", (uid,)).fetchone()
        if not row:
            c.execute("INSERT INTO account_profiles (user_id, account_type, tier, verification_status) VALUES (?, 'individual', 'Starter', ?)",
                      (uid, _default_verification("individual", user)))
            c.commit()
            row = c.execute("SELECT * FROM account_profiles WHERE user_id = ?", (uid,)).fetchone()
        row = dict(row)
        fix = {}
        if row["tier"] not in TIERS:
            fix["tier"] = "Standard" if row["account_type"] == "individual" else "Starter"
        if row["account_type"] == "individual" and row["verification_status"] == "Unverified" and _col(user, "email_verified", 0):
            fix["verification_status"] = "Verified"
        if fix:
            c.execute("UPDATE account_profiles SET %s WHERE user_id = ?" % ", ".join(k + " = ?" for k in fix), list(fix.values()) + [uid])
            c.commit()
            row.update(fix)
        return dict(user), row
    finally:
        _close(c)


def _extras(uid):
    c = _conn()
    try:
        ws = [dict(r) for r in c.execute("SELECT kind, status, details, created_at FROM account_workspaces WHERE user_id = ? ORDER BY id", (uid,)).fetchall()]
        aff = c.execute("SELECT status, audience FROM affiliate_profiles WHERE user_id = ?", (uid,)).fetchone()
        return ws, (dict(aff) if aff else None)
    finally:
        _close(c)


def _tier_label(prof):
    t = prof.get("tier") or "Starter"
    return ("Business " + t) if ACCOUNT_TYPES[prof["account_type"]]["ecosystem"] == "business" and t in ("Standard", "Premium") else t


def _capabilities(prof, ws, aff):
    status = {k: "unavailable" for k in CAPS}
    verified = prof.get("verification_status") == "Verified"
    for k in TYPE_CAPS[prof["account_type"]]:
        status[k] = "active" if (k in CORE or verified) else "pending"
    for w in ws:
        if w["kind"] in TYPE_CAPS:
            for k in TYPE_CAPS[w["kind"]]:
                if status[k] != "active":
                    status[k] = "active" if w["status"] == "Verified" else ("pending" if w["status"] != "Rejected" else status[k])
    if aff:
        status["affiliate"] = "active" if aff["status"] == "Active" else "pending"
    return [{"key": k, "label": CAPS[k], "status": status[k]} for k in CAPS]


def _nav(prof, ws, aff):
    kinds = {prof["account_type"]} | {w["kind"] for w in ws}
    nav = {"business": bool(kinds - {"individual"}), "developers": bool(kinds & {"developer", "partner"}), "affiliate": bool(aff)}
    return nav


def _membership(uid):
    """Membership number, Founders rank and badge (net365_membership.py). None when that module is not installed."""
    try:
        import net365_membership
        return net365_membership.get(uid)
    except Exception:
        return None


def _card(user, prof):
    uid = user["id"]
    t = ACCOUNT_TYPES[prof["account_type"]]
    ws, aff = _extras(uid)
    try:
        details = json.loads(prof.get("details") or "{}")
    except ValueError:
        details = {}
    return {
        "customer_name": user.get("full_name") or "", "customer_id": customer_id(uid),
        "account_type": prof["account_type"], "account_type_label": t["label"], "ecosystem": ECOSYSTEMS[t["ecosystem"]],
        "account_status": _status(user), "verification_status": prof.get("verification_status") or "Unverified",
        "account_tier": _tier_label(prof), "tier": prof.get("tier"), "tier_note": TIERS.get(prof.get("tier"), ""),
        "registration_date": _fmt_date(user.get("created_at")), "country": prof.get("country") or "Nigeria",
        "primary_currency": prof.get("currency") or "NGN", "referral_id": referral_id(uid), "referral_code": user.get("referral_code") or "",
        "business_name": prof.get("business_name") or "", "details": details, "email": user.get("email") or "", "phone": user.get("phone") or "",
        "is_business": t["business"],
        "capabilities": _capabilities(prof, ws, aff), "nav": _nav(prof, ws, aff),
        "workspaces": [{"kind": w["kind"], "label": ACCOUNT_TYPES[w["kind"]]["label"], "status": w["status"]} for w in ws if w["kind"] in ACCOUNT_TYPES],
        "affiliate": {"status": aff["status"]} if aff else None,
        "membership": _membership(uid),
    }


def _types_payload():
    keys = ("label", "ecosystem", "icon", "business", "blurb", "benefits", "for", "verification", "fields")
    return [dict(key=k, **{x: v[x] for x in keys}) for k, v in ACCOUNT_TYPES.items()]


def init_profile(app, get_conn, login_required, admin_required):
    """get_conn: function returning a sqlite connection with row_factory=sqlite3.Row (db.get_db_connection)."""
    _state["conn"] = get_conn
    try:
        _schema()
    except Exception as e:
        logger.warning("account profile tables not ready: %s", e)

    def out(uid):
        user, prof = _get_or_create(uid)
        return jsonify({"success": True, "profile": _card(user, prof)})

    def fail(msg, code=400):
        return jsonify({"success": False, "error": msg}), code

    @app.route("/api/profile/account-types", methods=["GET"])
    def profile_types():
        return jsonify({"success": True, "types": _types_payload(), "tiers": [{"name": k, "note": v} for k, v in TIERS.items()],
                        "ecosystems": ECOSYSTEMS})

    @app.route("/api/profile", methods=["GET"])
    @login_required
    def profile_get():
        user, prof = _get_or_create(g.current_user["id"])
        if not user:
            return fail("Account not found", 404)
        resp = jsonify({"success": True, "profile": _card(user, prof)})
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.route("/api/profile/setup", methods=["POST"])
    @login_required
    def profile_setup():
        body = request.get_json(silent=True) or {}
        atype = str(body.get("account_type") or "").strip().lower()
        if atype not in ACCOUNT_TYPES:
            return fail("Choose a valid account type.")
        uid = g.current_user["id"]
        user, prof = _get_or_create(uid)
        if not user:
            return fail("Account not found", 404)
        if prof["verification_status"] == "Verified" and ACCOUNT_TYPES[prof["account_type"]]["business"] and atype != prof["account_type"]:
            return fail("A verified business account can only be changed by support.", 403)
        details, err = _check_details(atype, body.get("details") or {"business_name": body.get("business_name")}, body.get("country"))
        if err:
            return fail(err)
        changed = atype != prof["account_type"]
        country = details.get("country") or prof.get("country") or "Nigeria"
        c = _conn()
        try:
            ver = _default_verification(atype, user) if changed else prof["verification_status"]
            tier = prof["tier"] if not changed else ("Standard" if atype == "individual" and ver == "Verified" else "Starter")
            c.execute("UPDATE account_profiles SET account_type = ?, tier = ?, verification_status = ?, country = ?, currency = ?, "
                      "business_name = COALESCE(NULLIF(?, ''), business_name), details = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                      (atype, tier, ver, country, CURRENCY.get(country.lower(), prof.get("currency") or "NGN"),
                       details.get("business_name", ""), json.dumps(details), uid))
            _audit(c, uid, "user", "type_set" if changed else "details_saved", atype)
            c.commit()
        finally:
            _close(c)
        return out(uid)

    @app.route("/api/profile/update", methods=["POST"])
    @login_required
    def profile_update():
        body = request.get_json(silent=True) or {}
        uid = g.current_user["id"]
        user, prof = _get_or_create(uid)
        if not user:
            return fail("Account not found", 404)
        country = _clean(body.get("country"), 60) or prof.get("country") or "Nigeria"
        merged = {}
        try:
            merged = json.loads(prof.get("details") or "{}")
        except ValueError:
            pass
        for f in ACCOUNT_TYPES[prof["account_type"]]["fields"]:
            if f["key"] != "country" and body.get(f["key"]) is not None:
                merged[f["key"]] = _clean(body[f["key"]], 160)
        merged["country"] = country
        c = _conn()
        try:
            c.execute("UPDATE account_profiles SET country = ?, currency = ?, business_name = COALESCE(NULLIF(?, ''), business_name), details = ?, "
                      "updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                      (country, CURRENCY.get(country.lower(), prof.get("currency") or "NGN"), merged.get("business_name", ""), json.dumps(merged), uid))
            _audit(c, uid, "user", "details_saved", "")
            c.commit()
        finally:
            _close(c)
        return out(uid)

    @app.route("/api/profile/activate", methods=["POST"])
    @login_required
    def profile_activate():
        body = request.get_json(silent=True) or {}
        kind = str(body.get("kind") or "").strip().lower()
        uid = g.current_user["id"]
        user, prof = _get_or_create(uid)
        if not user:
            return fail("Account not found", 404)
        c = _conn()
        try:
            if kind == "affiliate":
                c.execute("INSERT OR IGNORE INTO affiliate_profiles (user_id, status, audience) VALUES (?, 'Active', ?)", (uid, _clean(body.get("audience"), 120)))
                _audit(c, uid, "user", "affiliate_joined", "")
            elif kind in ACCOUNT_TYPES and kind != "individual":
                if kind == prof["account_type"]:
                    return fail("This is already your main account type.")
                details, err = _check_details(kind, body.get("details") or {}, body.get("country"))
                if err:
                    return fail(err)
                c.execute("INSERT OR IGNORE INTO account_workspaces (user_id, kind, status, details) VALUES (?, ?, 'Pending', ?)", (uid, kind, json.dumps(details)))
                _audit(c, uid, "user", "workspace_requested", kind)
            else:
                return fail("Choose something to activate.")
            c.commit()
        finally:
            _close(c)
        return out(uid)

    @app.route("/api/profile/tier-request", methods=["POST"])
    @login_required
    def profile_tier_request():
        tier = str((request.get_json(silent=True) or {}).get("tier") or "")
        if tier not in TIERS:
            return fail("Choose a valid tier.")
        c = _conn()
        try:
            _audit(c, g.current_user["id"], "user", "tier_requested", tier)
            c.commit()
        finally:
            _close(c)
        return jsonify({"success": True, "message": "Request received. Our team will contact you about %s." % tier})

    @app.route("/api/admin/profile/<int:uid>", methods=["POST"])
    @admin_required
    def profile_admin(uid):
        body = request.get_json(silent=True) or {}
        user, prof = _get_or_create(uid)
        if not user:
            return fail("Account not found", 404)
        sets, vals = [], []
        if body.get("account_type") in ACCOUNT_TYPES:
            sets.append("account_type = ?"); vals.append(body["account_type"])
        if body.get("verification_status") in VERIFICATION:
            sets.append("verification_status = ?"); vals.append(body["verification_status"])
        if body.get("tier") in TIERS:
            sets.append("tier = ?"); vals.append(body["tier"])
        c = _conn()
        try:
            if sets:
                c.execute("UPDATE account_profiles SET %s, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?" % ", ".join(sets), vals + [uid])
            w = body.get("workspace")
            if isinstance(w, dict) and w.get("kind") in ACCOUNT_TYPES and w.get("status") in ("Pending", "Verified", "Rejected"):
                c.execute("UPDATE account_workspaces SET status = ? WHERE user_id = ? AND kind = ?", (w["status"], uid, w["kind"]))
                sets.append("workspace")
            if not sets:
                return fail("Nothing to change.")
            _audit(c, uid, "admin", "admin_update", json.dumps({k: v for k, v in body.items() if k != "details"})[:300])
            c.commit()
        finally:
            _close(c)
        return out(uid)

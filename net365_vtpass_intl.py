"""Net365 overseas airtime / data / pins through VTpass (serviceID foreign-airtime), paid with Paystack in naira.

Who serves which country
    Every country has exactly ONE owner: "vtpass" or "reloadly". Nigeria is not in this table (it keeps its own routing).
    Until an admin switches a country to VTpass it stays with Reloadly (card payment through Stripe, as before), so deploying
    this file changes nothing by itself. A VTpass-owned country is never sent to Reloadly, and a Reloadly-owned country is never
    sent to VTpass: no clashes, no double orders, no "which processor" decision at checkout.

Payment
    VTpass countries are paid in NGN through Paystack only. The customer sees a naira price; VTpass charges Net365's VTpass wallet.
    The price is always taken from VTpass's own variation list on the server, never from the request.

Safety (same rules as the other VTpass products)
    * the order row is claimed in provider_attempts BEFORE VTpass is called (unique reference + provider), so a double click,
      a second worker or a webhook retry can never buy twice;
    * an unclear answer (timeout, pending) is requeried with the SAME provider and never sent anywhere else;
    * only a definite refusal is treated as failed, which sends the payment to the normal refund path.
"""
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone

from flask import jsonify, request, g

import net365_providers as _np

log = logging.getLogger(__name__)

SERVICE_ID = "foreign-airtime"
# Countries VTpass lists today. The live list from VTpass is used when it can be fetched; this is only the fallback.
VTPASS_FALLBACK = {"CM": ("Cameroon", "XAF", "237"), "GH": ("Ghana", "GHS", "233"), "RW": ("Rwanda", "RWF", "250"),
                   "SZ": ("Eswatini", "SZL", "268"), "YE": ("Yemen", "YER", "967")}
OWNERS = ("vtpass", "reloadly")

_db = None
_deps = {}
_cache = {}
_owner_cache = {"t": 0.0, "rows": {}}
_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn():
    return _db.get_db_connection()


def _ensure_schema():
    c = _conn()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS intl_country_routes (
            country TEXT PRIMARY KEY, provider TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT)""")
        c.commit()
    finally:
        c.close()


# ------------------------------------------------------------------------------------------- ownership
def _owners():
    if time.time() - _owner_cache["t"] < 5:
        return _owner_cache["rows"]
    rows = {}
    try:
        c = _conn()
        try:
            for r in c.execute("SELECT country, provider FROM intl_country_routes").fetchall():
                rows[str(r["country"]).upper()] = str(r["provider"]).lower()
        finally:
            c.close()
    except Exception:
        log.exception("intl routes: could not read the table; every country stays with Reloadly")
    _owner_cache.update(t=time.time(), rows=rows)
    return rows


def owner(country):
    """'vtpass' or 'reloadly' for a foreign country. Nigeria is not routed here ('nigeria')."""
    cc = str(country or "").upper()
    if cc == "NG":
        return "nigeria"
    return _owners().get(cc, "reloadly")


def vtpass_owns(country):
    return owner(country) == "vtpass"


# ------------------------------------------------------------------------------------------- VTpass catalogue
def _adapter():
    a = _np._registry().get("vtpass")
    return a if a and a.configured() else None


def _get(path, params=None):
    a = _adapter()
    if not a:
        raise RuntimeError("VTpass is not configured")
    r = a.http.get(a.base + path, params=params or {}, headers=a._get_headers(), timeout=(5, 20))
    return r.json() or {}


def _cached(key, ttl, fn):
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    try:
        val = fn()
    except Exception as e:
        log.warning("VTpass international lookup %s failed: %s", key, e)
        return hit[1] if hit else None            # a stale list beats none
    if val:
        _cache[key] = (time.time(), val)
    return val if val else (hit[1] if hit else val)


def countries():
    """[{code, name, currency, prefix, flag}] as VTpass lists them (Nigeria excluded: it has its own flow)."""
    def load():
        j = _get("/get-international-airtime-countries")
        rows = ((j.get("content") or {}).get("countries")) or []
        return [{"code": str(r.get("code") or "").upper(), "name": r.get("name") or "", "currency": r.get("currency") or "",
                 "prefix": str(r.get("prefix") or ""), "flag": r.get("flag") or ""}
                for r in rows if str(r.get("code") or "").upper() not in ("", "NG")]
    got = _cached("countries", 6 * 3600, load)
    if got:
        return got
    return [{"code": cc, "name": n, "currency": cur, "prefix": p, "flag": ""} for cc, (n, cur, p) in VTPASS_FALLBACK.items()]


def country_info(cc):
    cc = str(cc or "").upper()
    return next((c for c in countries() if c["code"] == cc), None)


def product_types(cc):
    def load():
        j = _get("/get-international-airtime-product-types", {"code": cc})
        return [{"id": str(r.get("product_type_id")), "name": r.get("name") or ""} for r in (j.get("content") or []) if r.get("product_type_id") is not None]
    return _cached(f"types:{cc}", 3600, load) or []


def operators(cc, product_type_id):
    def load():
        j = _get("/get-international-airtime-operators", {"code": cc, "product_type_id": product_type_id})
        return [{"id": str(r.get("operator_id")), "name": r.get("name") or "", "image": r.get("operator_image") or ""}
                for r in (j.get("content") or []) if r.get("operator_id") is not None]
    return _cached(f"ops:{cc}:{product_type_id}", 3600, load) or []


def _num(x):
    try:
        return float(str(x).replace(",", ""))
    except (TypeError, ValueError):
        return 0.0


def variations(operator_id, product_type_id):
    """Priced variations for one operator: [{code, name, fixed, price_ngn, rate}].
    VTpass: a FIXED variation costs its naira equivalent (charged_amount); a FLEXIBLE one costs variation_rate x the local amount.
    A variation whose naira price cannot be worked out is left out, so a customer is never sold something we cannot price."""
    def load():
        j = _get("/service-variations", {"serviceID": SERVICE_ID, "operator_id": operator_id, "product_type_id": product_type_id})
        content = j.get("content") or {}
        rows = content.get("variations") or content.get("varations") or []
        out = []
        for v in rows:
            code = str(v.get("variation_code") or "")
            if not code:
                continue
            fixed = str(v.get("fixedPrice") or "").strip().lower() in ("yes", "true", "1")
            if fixed:
                price = _num(v.get("charged_amount") or v.get("chargedAmount") or v.get("variation_amount_ngn"))
                if price <= 0:
                    log.warning("VTpass variation %s has no naira price (fields: %s); skipped", code, sorted(v.keys()))
                    continue
                out.append({"code": code, "name": str(v.get("name") or ""), "fixed": True, "price_ngn": round(price, 2), "rate": 0.0})
            else:
                rate = _num(v.get("variation_rate") or v.get("rate"))
                if rate <= 0:
                    log.warning("VTpass flexible variation %s has no rate (fields: %s); skipped", code, sorted(v.keys()))
                    continue
                out.append({"code": code, "name": str(v.get("name") or ""), "fixed": False, "price_ngn": 0.0, "rate": rate})
        return out
    return _cached(f"var:{operator_id}:{product_type_id}", 1800, load) or []


def find_variation(operator_id, product_type_id, code):
    return next((v for v in variations(operator_id, product_type_id) if v["code"] == str(code)), None)


def price_ngn(var, local_amount=None):
    """Naira VTpass will charge for this variation (fixed price, or rate x local amount for a flexible one)."""
    if var["fixed"]:
        return round(var["price_ngn"], 2)
    amt = _num(local_amount)
    return round(var["rate"] * amt, 2) if amt > 0 else 0.0


def full_number(country, raw):
    """Digits only, in international form without '+': 233241234567. '' if it cannot be a phone number."""
    info = country_info(country) or {}
    prefix = str(info.get("prefix") or VTPASS_FALLBACK.get(str(country).upper(), ("", "", ""))[2])
    d = re.sub(r"\D", "", str(raw or ""))
    if prefix and d.startswith(prefix) and len(d) > len(prefix) + 5:
        n = d
    else:
        n = prefix + d.lstrip("0")
    return n if 8 <= len(n) <= 15 else ""


# ------------------------------------------------------------------------------------------- fulfilment
def fulfil(reference, tx, payload):
    """Buy the order from VTpass after Paystack has confirmed payment. Returns a result dict on success / pending and RAISES on a
    definite refusal (so the payment goes to the normal refund path). Safe to call twice for the same reference."""
    a = _adapter()
    if not a or not _np.provider_ready("vtpass"):
        raise Exception("International airtime is not available right now")
    cc = str(payload.get("country_code") or "").upper()
    op_id, pt_id, code = str(payload.get("operator_id") or ""), str(payload.get("product_type_id") or ""), str(payload.get("variation_code") or "")
    phone = re.sub(r"\D", "", str(payload.get("phone") or ""))
    email = str(payload.get("email") or "")
    paid = float(tx.get("amount") or 0)
    if tx.get("currency", "NGN") != "NGN" or not (cc and op_id and pt_id and code and phone):
        raise Exception("Incomplete international order")
    try:
        service_amount = float(payload.get("service_amount") or paid)
    except (TypeError, ValueError):
        service_amount = paid
    var = find_variation(op_id, pt_id, code)
    if not var:
        raise Exception("That product is no longer available")
    local_amount = payload.get("local_amount")
    now_price = price_ngn(var, local_amount)
    tol = float(os.getenv("VTPASS_INTL_PRICE_TOLERANCE", "0.03"))
    if now_price <= 0 or now_price > service_amount * (1 + tol) + 0.01:
        raise Exception(f"International price changed (now {now_price}, paid for {service_amount})")

    _np._ensure_schema()
    att_id, rid = _np._claim(reference, a, "intl_airtime", cc, service_amount, phone)
    if att_id is None:
        return _existing(a, reference)

    body = {"request_id": rid, "serviceID": SERVICE_ID, "billersCode": phone, "variation_code": code, "phone": phone,
            "operator_id": op_id, "country_code": cc, "product_type_id": pt_id, "email": email or "customer@net365co.com"}
    if not var["fixed"]:
        body["amount"] = _num(local_amount)
    t0 = time.time()
    try:
        r = a.http.post(a.base + "/pay", json=body, headers=a._post_headers(), timeout=(5, 25))
        if r.status_code in (401, 403):
            o = _np.outcome(_np.FAILED, f"http_{r.status_code}", "provider rejected our credentials", fault=True)
        else:
            try:
                o = a._parse(r.json(), r.status_code)
            except ValueError:
                o = _np.outcome(_np.PENDING, f"http_{r.status_code}", "unreadable answer", fault=True)
    except Exception as e:                         # network error: only "never connected" counts as a definite failure
        import requests as _rq
        o = _np._http_error_outcome(e) if isinstance(e, _rq.RequestException) else _np.outcome(_np.PENDING, "adapter_error", type(e).__name__, fault=True)
    ms = int((time.time() - t0) * 1000)
    if o["status"] == _np.PENDING:
        _np._update(att_id, o, ms)
        o = _np._poll(a, att_id, rid, o)
    _np._update(att_id, o, ms)
    _np._breaker_record("vtpass", o["status"] == _np.SUCCESS, o["fault"] and o["status"] != _np.SUCCESS)
    if o["status"] == _np.FAILED:
        raise Exception(o["message"] or "International top-up failed at provider")
    return _result(o, reference, var, now_price)


def _result(o, reference, var, price):
    return {"status": "success", "transactionId": o.get("provider_ref") or f"vtpass-{reference}", "amount": price, "currency": "NGN",
            "provider": "vtpass", "plan": var.get("name", ""), "token": o.get("token") or "", "pending": o["status"] == _np.PENDING,
            "full_result": {k: v for k, v in o.items() if k != "raw"}}


def _existing(a, reference):
    c = _conn()
    try:
        p = c.execute("SELECT * FROM provider_attempts WHERE reference = ? AND provider = 'vtpass' ORDER BY id DESC LIMIT 1", (reference,)).fetchone()
    finally:
        c.close()
    if not p:
        raise Exception("Order is already being processed")
    p = dict(p)
    if p["status"] == "failed":
        raise Exception(p.get("message") or "International top-up failed at provider")
    o = _np.outcome(_np.SUCCESS if p["status"] == "success" else _np.PENDING, p["code"], p["message"], p["provider_ref"], p["token"])
    if p["status"] != "success":
        q = a.requery(p["request_id"])
        if q["status"] == _np.FAILED:
            raise Exception(q["message"] or "International top-up failed at provider")
        if q["status"] != _np.PENDING:
            _np._update(p["id"], q, status=q["status"])
            o = q
    return _result(o, reference, {"name": ""}, float(p.get("amount") or 0))


# ------------------------------------------------------------------------------------------- routes
def init_vtpass_intl(app, db, admin_required, login_required, email_verified_required, platform_fn,
                     fee_fn, encrypt_pii, return_url_fn, limit_error_fn, chat_error_fn=None):
    """Registers: public catalogue routes, the Paystack checkout, and the admin ownership table."""
    global _db
    _db = db
    _ensure_schema()
    _deps.update(platform=platform_fn)

    def ready():
        return bool(_adapter()) and _np.enabled()

    @app.get("/api/intl/route")
    def intl_route():
        cc = str(request.args.get("country") or "").upper()
        if len(cc) != 2 or not cc.isalpha():
            return jsonify(success=False, error="Invalid country"), 400
        o = owner(cc)
        return jsonify(success=True, country=cc, provider=o, vtpass=(o == "vtpass" and ready()))

    @app.get("/api/intl/vtpass/countries")
    def intl_vt_countries():
        if not ready():
            return jsonify(success=True, countries=[])
        out = [c for c in countries() if vtpass_owns(c["code"])]
        return jsonify(success=True, countries=out)

    def _guard(cc):
        if not ready():
            return jsonify(success=False, error="International airtime is not available right now"), 503
        if not vtpass_owns(cc):
            return jsonify(success=False, error="This country is not served here"), 404
        return None

    @app.get("/api/intl/vtpass/catalog")
    def intl_vt_catalog():
        """?country=GH -> product types and operators; ?country&operator_id&product_type_id -> priced variations."""
        cc = str(request.args.get("country") or "").upper()
        bad = _guard(cc)
        if bad:
            return bad
        pt, op = request.args.get("product_type_id"), request.args.get("operator_id")
        if not pt:
            types = product_types(cc)
            if not types:
                return jsonify(success=False, error="Nothing available for this country right now"), 503
            return jsonify(success=True, country=cc, currency=(country_info(cc) or {}).get("currency", ""), product_types=types)
        if pt not in {t["id"] for t in product_types(cc)}:
            return jsonify(success=False, error="Unknown product type"), 400
        if not op:
            return jsonify(success=True, country=cc, operators=operators(cc, pt))
        if op not in {o["id"] for o in operators(cc, pt)}:
            return jsonify(success=False, error="Unknown operator"), 400
        return jsonify(success=True, country=cc, variations=variations(op, pt))

    @app.post("/api/intl/vtpass/checkout")
    @login_required
    @email_verified_required
    def intl_vt_checkout():
        d = request.get_json(silent=True) or {}
        user_id = g.current_user_id
        cc = str(d.get("country") or "").upper()
        bad = _guard(cc)
        if bad:
            return bad
        op, pt, code = str(d.get("operator_id") or ""), str(d.get("product_type_id") or ""), str(d.get("variation_code") or "")
        src = str(d.get("source") or "")
        if pt not in {t["id"] for t in product_types(cc)} or op not in {o["id"] for o in operators(cc, pt)}:
            return jsonify(success=False, error="Pick the network again"), 409
        var = find_variation(op, pt, code)
        if not var:
            return jsonify(success=False, error="That product is no longer available. Please pick again."), 409
        local_amount = None
        if not var["fixed"]:
            local_amount = _num(d.get("local_amount"))
            if local_amount <= 0:
                return jsonify(success=False, error="Enter the amount to send"), 400
        service_amount = price_ngn(var, local_amount)
        if service_amount <= 0:
            return jsonify(success=False, error="Price unavailable right now. Please try again shortly."), 503
        if service_amount > float(os.getenv("VTPASS_INTL_MAX_NGN", "100000")):
            return jsonify(success=False, error="That is above the maximum for one overseas top-up."), 400
        phone = full_number(cc, d.get("phone"))
        if not phone:
            return jsonify(success=False, error="That does not look like a valid phone number"), 400
        fee = fee_fn(service_amount) if src in ("telegram", "whatsapp") else 0.0
        charge = round(service_amount + fee, 2)
        if chat_error_fn:
            ce = chat_error_fn(user_id, charge)
            if ce:
                return jsonify(ce[0]), ce[1]
        le = limit_error_fn(user_id, charge)
        if le:
            return jsonify(success=False, code="LIMIT_EXCEEDED", error=le), 400
        user = db.get_user(user_id) or {}
        email = str(d.get("email") or "").strip() or user.get("email") or os.getenv("DEFAULT_PAYMENT_EMAIL", f"user_{user_id}@net365.com")
        result = _deps["platform"]().create_payment(amount=charge, currency="NGN", email=email, return_url=return_url_fn(d.get("return_url")),
                                                    provider="paystack")
        if not (result.get("success") and result.get("reference")):
            return jsonify(result), 502
        info = country_info(cc) or {}
        op_name = next((o["name"] for o in operators(cc, pt) if o["id"] == op), "")
        payload = {"country_code": cc, "operator_id": op, "operator_name": op_name[:60], "product_type_id": pt, "variation_code": code,
                   "plan": var["name"][:80], "local_amount": local_amount, "local_currency": info.get("currency", ""),
                   "phone": encrypt_pii(phone), "service_amount": service_amount, "fee_amount": fee, "biller_name": f"{info.get('name', cc)} {op_name}"[:60],
                   "currency": "NGN", "email": email, "user_id": user_id, "payment_method": "paystack"}
        if src in ("telegram", "whatsapp"):
            payload["source"] = src
        db.create_pending(reference=result["reference"], tx_type="intl_vtpass", provider=result.get("provider", "paystack"),
                          amount=charge, currency="NGN", payload=payload, user_id=user_id)
        return jsonify(success=True, authorization_url=result.get("authorization_url") or result.get("checkout_url"), reference=result["reference"],
                       amount=charge, service_amount=service_amount, fee_amount=fee, plan=var["name"], country=cc)

    # ---- admin: who owns which country
    @app.get("/api/admin/intl-routes")
    @admin_required
    def admin_intl_routes_get():
        rows = _owners()
        vt = {c["code"]: c for c in countries()}
        out = [{"country": cc, "name": c["name"], "currency": c["currency"], "vtpass_capable": True, "owner": rows.get(cc, "reloadly")} for cc, c in sorted(vt.items())]
        extra = [{"country": cc, "name": cc, "currency": "", "vtpass_capable": cc in vt, "owner": p} for cc, p in sorted(rows.items()) if cc not in vt]
        return jsonify(success=True, countries=out + extra, ready=ready(),
                       note="Countries not listed are served by Reloadly (card payment through Stripe).")

    @app.post("/api/admin/intl-routes")
    @admin_required
    def admin_intl_routes_set():
        d = request.get_json(silent=True) or {}
        cc, prov = str(d.get("country") or "").upper(), str(d.get("provider") or "").lower()
        if len(cc) != 2 or not cc.isalpha() or cc == "NG" or prov not in OWNERS:
            return jsonify(success=False, error="Invalid country or provider"), 400
        if prov == "vtpass" and not any(c["code"] == cc for c in countries()):
            return jsonify(success=False, error="VTpass does not serve this country"), 400
        if prov == "vtpass" and not ready():
            return jsonify(success=False, error="VTpass is not ready (keys, or PROVIDER_ROUTER_ENABLED)"), 409
        who = "admin"
        try:
            u = getattr(g, "current_user", None) or {}
            who = str(u.get("email") or "admin")[:80]
        except Exception:
            pass
        c = _conn()
        try:
            c.execute("INSERT INTO intl_country_routes (country, provider, updated_at, updated_by) VALUES (?,?,?,?) "
                      "ON CONFLICT(country) DO UPDATE SET provider=excluded.provider, updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                      (cc, prov, _now(), who))
            c.commit()
        finally:
            c.close()
        _owner_cache["t"] = 0.0
        log.warning("INTL ROUTE: %s now served by %s (%s)", cc, prov, who)
        return jsonify(success=True, country=cc, provider=prov)

    log.info("VTpass international airtime module loaded (a country is served by VTpass only after an admin switches it)")

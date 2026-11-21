"""
Net365 provider router: one front door for Nigerian airtime, data and electricity, many suppliers behind it.

How a purchase is routed
  1. Idempotency: a reference that already has a successful / pending attempt is NEVER bought again.
  2. Candidates: providers that are configured, switched on, support the service + network, and whose circuit breaker is closed.
  3. Order: best score first. Score = recent success rate for that network (24h) + the discount you earn from the provider
     - a small penalty for slowness + an admin priority bonus.
  4. FAILOVER ONLY ON A DEFINITE FAILURE. If the provider answers "failed / rejected / not processed" (or we could not even
     connect), the next provider is tried. If the answer is unknown (timeout, pending, 5xx after sending) we ask the SAME
     provider again (requery) and never send the order elsewhere: that is how double deliveries and double charges happen.
  5. Still unknown after the polling window: the order is returned as PENDING and a background reconciler keeps requerying.
     If it later turns out failed, the attempt is flagged "needs_action" for you (refund / redeliver), never auto-retried.
  6. All providers failed definitively: the caller may use Reloadly (fallback_ok=True).

Switches (all off by default): PROVIDER_ROUTER_ENABLED=true turns routing on.
Each provider also needs its own keys (see the adapters). Nothing here changes an order unless a provider is configured.
"""
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import requests
from flask import Blueprint, jsonify, request

log = logging.getLogger(__name__)
pv_bp = Blueprint("providers", __name__)
_d = {}
_schema_done = False
_lock = threading.Lock()
_breaker = {}          # provider -> {"fails": n, "open_until": ts}
_hooks = {"on_resolved": None}

SUCCESS, PENDING, FAILED = "success", "pending", "failed"


def _on(name, default="false"):
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def enabled():
    return _on("PROVIDER_ROUTER_ENABLED", "false")


def _conn():
    return _d["db"].get_db_connection()


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _s(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _lagos_stamp():
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo("Africa/Lagos")).strftime("%Y%m%d%H%M")
    except Exception:
        return (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y%m%d%H%M")


# ------------------------------------------------------------------------------------------- numbers / networks
_PREFIX = {
    "mtn": ("0803", "0806", "0703", "0706", "0813", "0816", "0810", "0814", "0903", "0906", "0913", "0916", "07025", "07026", "0704"),
    "airtel": ("0802", "0808", "0708", "0812", "0701", "0902", "0901", "0904", "0907", "0912"),
    "glo": ("0805", "0807", "0705", "0815", "0811", "0905", "0915"),
    "9mobile": ("0809", "0818", "0817", "0909", "0908"),
}


def local_number(phone):
    """08012345678 from +234 801 234 5678 / 2348012345678 / 8012345678. '' when it is not a Nigerian mobile number."""
    d = re.sub(r"\D", "", str(phone or ""))
    if d.startswith("234") and len(d) == 13:
        d = "0" + d[3:]
    elif len(d) == 10 and d[0] in "789":
        d = "0" + d
    return d if re.fullmatch(r"0[789][01]\d{8}", d) else ""


def network_from_name(name):
    n = str(name or "").lower()
    if "mtn" in n:
        return "mtn"
    if "airtel" in n:
        return "airtel"
    if "glo" in n:
        return "glo"
    if "9mobile" in n or "etisalat" in n or "t2" in n:
        return "9mobile"
    return ""


def network_for(operator_name, phone):
    """The operator the customer CHOSE wins (numbers can be ported); the number's prefix is only the fallback."""
    n = network_from_name(operator_name)
    if n:
        return n
    p = local_number(phone)
    for net, prefixes in _PREFIX.items():
        if p and p.startswith(prefixes):
            return net
    return ""


_DISCOS = [  # keyword in the biller name -> short key
    ("ikeja", "ikeja"), ("eko", "eko"), ("abuja", "abuja"), ("ibadan", "ibadan"), ("enugu", "enugu"), ("benin", "benin"),
    ("aba", "aba"), ("jos", "jos"), ("kaduna", "kaduna"), ("kano", "kano"), ("port", "portharcourt"), ("yola", "yola"),
]


def disco_for(name):
    n = str(name or "").lower()
    for kw, key in _DISCOS:
        if re.search(r"\b" + kw, n):
            return key
    return ""


# ------------------------------------------------------------------------------------------- outcome
def outcome(status, code="", message="", provider_ref="", token="", fault=False, raw=None):
    """status: success | pending | failed.  fault=True when a FAILED answer is the provider's problem (counts against its health);
    a failure caused by the customer's data (bad number, amount out of range) must not trip the breaker."""
    return {"status": status, "code": str(code or ""), "message": str(message or "")[:300], "provider_ref": str(provider_ref or ""),
            "token": str(token or ""), "fault": bool(fault), "raw": raw}


def _http_error_outcome(e):
    """Map a requests exception to an outcome. Only errors that prove the request never reached the provider are 'failed'."""
    if isinstance(e, requests.exceptions.ConnectTimeout):
        return outcome(FAILED, "connect_timeout", "could not connect", fault=True)
    if isinstance(e, requests.exceptions.ConnectionError):
        msg = str(e).lower()
        if any(t in msg for t in ("name or service", "failed to resolve", "connection refused", "nodename nor servname", "max retries")) \
                and "remotedisconnected" not in msg and "reset by peer" not in msg:
            return outcome(FAILED, "connect_error", "could not connect", fault=True)
    return outcome(PENDING, "no_response", f"no clear answer: {type(e).__name__}", fault=True)


# ------------------------------------------------------------------------------------------- adapters
class Adapter:
    name = "base"
    services = ()

    def configured(self):
        return False

    def supports(self, service, network):
        return service in self.services

    def buy(self, service, request_id, **kw):          # -> outcome
        raise NotImplementedError

    def requery(self, request_id):                     # -> outcome
        raise NotImplementedError

    def make_request_id(self, reference):
        return reference

    def balance(self):
        return None

    def new_http(self):
        s = requests.Session()
        s.headers["User-Agent"] = "Net365-Router/1.0"
        return s


class VTpassAdapter(Adapter):
    """VTpass REST API. Verified against their public docs: auth headers (GET: api-key + public-key, POST: api-key + secret-key),
    /requery, request_id rule (first 12 chars = Lagos YYYYMMDDHHMM) and the response-code table. Service IDs for airtime/data
    and the electricity IDs come from their Service ID list: confirm them in your sandbox (override with VTPASS_DISCO_MAP)."""
    name = "vtpass"
    services = ("airtime", "data", "electricity", "tv", "education", "insurance")
    # TV and education products (VTpass serviceIDs from their docs). Label is what the customer sees.
    TV = {"dstv": "DStv", "gotv": "GOtv", "startimes": "StarTimes", "showmax": "Showmax"}
    EDU = {"waec": "WAEC result checker PIN", "waec-registration": "WAEC registration PIN", "jamb": "JAMB PIN (UTME / Direct Entry)"}
    # Insurance products (VTpass serviceID -> label). Motor third-party first; confirm the exact IDs and the field list in your sandbox.
    INSURANCE = {"ui-insure": "Third-party motor insurance"}
    # Fields VTpass needs to issue a motor policy. Only these are ever sent; each is validated by the caller.
    INSURANCE_FIELDS = ("Insured_Name", "Plate_Number", "Chasis_Number", "vehicle_Make", "vehicle_Model", "vehicle_Color",
                        "YearofMake", "engine_capacity", "state", "lga", "email")
    AIRTIME = {"mtn": "mtn", "airtel": "airtel", "glo": "glo", "9mobile": "etisalat"}
    DISCO_LABEL = {"ikeja": "Ikeja Electric (IKEDC)", "eko": "Eko Electric (EKEDC)", "abuja": "Abuja Electric (AEDC)",
                   "ibadan": "Ibadan Electric (IBEDC)", "enugu": "Enugu Electric (EEDC)", "benin": "Benin Electric (BEDC)",
                   "aba": "Aba Power", "jos": "Jos Electric (JED)", "kaduna": "Kaduna Electric (KAEDCO)",
                   "kano": "Kano Electric (KEDCO)", "portharcourt": "Port Harcourt Electric (PHED)", "yola": "Yola Electric (YEDC)"}
    DISCO = {"ikeja": "ikeja-electric", "eko": "eko-electric", "abuja": "abuja-electric", "ibadan": "ibadan-electric",
             "enugu": "enugu-electric", "benin": "benin-electric", "aba": "aba-electric", "jos": "jos-electric",
             "kaduna": "kaduna-electric", "kano": "kano-electric", "portharcourt": "portharcourt-electric", "yola": "yola-electric"}
    DEFINITE_FAIL = {"016", "091", "040", "010", "011", "012", "013", "017", "018", "019", "021", "022", "023", "024",
                     "025", "026", "027", "028", "030", "031", "032", "034", "035", "085", "087"}
    # codes that are the CUSTOMER's data, not the provider's health
    USER_FAULT = {"010", "011", "012", "013", "017", "019", "026", "031", "032"}
    PENDING_CODES = {"099", "089", "001", "044", "083", "014"}

    def __init__(self):
        self.http = self.new_http()

    @property
    def base(self):
        live = os.getenv("VTPASS_ENV", "sandbox").strip().lower() == "live"
        return "https://vtpass.com/api" if live else "https://sandbox.vtpass.com/api"

    def configured(self):
        return bool(os.getenv("VTPASS_API_KEY") and os.getenv("VTPASS_SECRET_KEY") and os.getenv("VTPASS_PUBLIC_KEY"))

    def supports(self, service, network):
        if service == "airtime" or service == "data":
            return network in self.AIRTIME
        if service == "tv":
            return network in self.TV
        if service == "education":
            return network in self.EDU
        if service == "insurance":
            return network in self.INSURANCE
        return service == "electricity"

    def _post_headers(self):
        return {"api-key": os.getenv("VTPASS_API_KEY", ""), "secret-key": os.getenv("VTPASS_SECRET_KEY", "")}

    def _get_headers(self):
        return {"api-key": os.getenv("VTPASS_API_KEY", ""), "public-key": os.getenv("VTPASS_PUBLIC_KEY", "")}

    def make_request_id(self, reference):
        suffix = re.sub(r"[^A-Za-z0-9]", "", str(reference))[-24:]
        return _lagos_stamp() + suffix

    def _disco_map(self):
        m = dict(self.DISCO)
        try:
            m.update(json.loads(os.getenv("VTPASS_DISCO_MAP", "") or "{}"))
        except Exception:
            pass
        return m

    def balance(self):
        try:
            r = self.http.get(self.base + "/balance", headers=self._get_headers(), timeout=(5, 15))
            return r.json().get("contents", {}).get("balance")
        except Exception:
            return None

    def plans(self, network):
        """Data plans for one network: [{code, name, price}]. Prices come from VTpass, never from the customer."""
        sid = self.AIRTIME.get(network)
        if not sid:
            return []
        r = self.http.get(self.base + "/service-variations", params={"serviceID": sid + "-data"},
                          headers=self._get_headers(), timeout=(5, 20))
        content = (r.json() or {}).get("content") or {}
        rows = content.get("variations") or content.get("varations") or []     # VTpass spells it both ways
        out = []
        for v in rows:
            try:
                out.append({"code": str(v["variation_code"]), "name": str(v.get("name", "")),
                            "price": float(v.get("variation_amount") or 0)})
            except (KeyError, TypeError, ValueError):
                continue
        return [p for p in out if p["price"] > 0]

    def catalog(self, product):
        """Fixed-price catalogue for a TV/education product: [{code, name, price}]. Prices come from VTpass, never the customer."""
        if product not in self.TV and product not in self.EDU and product not in self.INSURANCE:
            return []
        r = self.http.get(self.base + "/service-variations", params={"serviceID": product},
                          headers=self._get_headers(), timeout=(5, 20))
        content = (r.json() or {}).get("content") or {}
        rows = content.get("variations") or content.get("varations") or []
        out = []
        for v in rows:
            try:
                out.append({"code": str(v["variation_code"]), "name": str(v.get("name", "")),
                            "price": float(v.get("variation_amount") or 0)})
            except (KeyError, TypeError, ValueError):
                continue
        return [p for p in out if p["price"] > 0]

    def verify(self, product, billers_code, variation_code=""):
        """Smartcard / JAMB profile check via /merchant-verify. Returns {ok, name, status, due_date, bouquet, renewal_amount, message}."""
        if product not in ("dstv", "gotv", "startimes", "jamb"):
            return {"ok": True, "name": "", "message": "no verification for this product"}
        body = {"serviceID": product, "billersCode": str(billers_code)}
        if product == "jamb":
            body["type"] = variation_code or "utme-no-mock"
        try:
            r = self.http.post(self.base + "/merchant-verify", json=body, headers=self._post_headers(), timeout=(5, 20))
            j = r.json()
        except Exception as e:
            return {"ok": False, "unavailable": True, "message": "Could not reach the verification service. Please try again."}
        return self._parse_verify(j)

    def verify_meter(self, disco, meter, meter_type="prepaid"):
        """Check a meter number with the distribution company before the customer pays. {ok, name, address, min_amount, message}."""
        sid = self._disco_map().get(disco)
        if not sid:
            return {"ok": False, "message": "This electricity company is not available through VTpass."}
        body = {"serviceID": sid, "billersCode": str(meter), "type": "postpaid" if str(meter_type).lower().startswith("post") else "prepaid"}
        try:
            r = self.http.post(self.base + "/merchant-verify", json=body, headers=self._post_headers(), timeout=(5, 20))
            j = r.json()
        except Exception:
            return {"ok": False, "unavailable": True, "message": "Could not reach the verification service. Please try again."}
        content = j.get("content") if isinstance(j, dict) else None
        if not isinstance(content, dict) or str(j.get("code")) != "000" or content.get("error") or content.get("WrongBillersCode") is True:
            return {"ok": False, "message": str((content or {}).get("error") or j.get("response_description") or "Meter number not recognised.")[:160]}
        def num(k):
            try:
                return float(content.get(k))
            except (TypeError, ValueError):
                return None
        return {"ok": True, "name": str(content.get("Customer_Name") or "").strip(), "address": str(content.get("Address") or "").strip()[:120],
                "min_amount": num("Min_Purchase_Amount"), "message": ""}

    @staticmethod
    def _parse_verify(j):
        content = j.get("content") if isinstance(j, dict) else None
        if not isinstance(content, dict) or str(j.get("code")) != "000" or content.get("error") or content.get("WrongBillersCode") is True:
            return {"ok": False, "message": str((content or {}).get("error") or j.get("response_description") or "Could not verify this number.")[:160]}
        name = str(content.get("Customer_Name") or "").strip()
        if not name:
            return {"ok": False, "message": "Could not verify this number."}
        def num(k):
            try:
                return float(content.get(k))
            except (TypeError, ValueError):
                return None
        return {"ok": True, "name": name, "status": str(content.get("Status") or ""), "due_date": str(content.get("Due_Date") or "")[:10],
                "bouquet": str(content.get("Current_Bouquet") or ""), "renewal_amount": num("Renewal_Amount"),
                "balance": num("Balance"), "message": ""}

    def buy(self, service, request_id, **kw):
        phone = kw.get("phone", "")
        amount = kw.get("amount")
        body = {"request_id": request_id, "amount": int(round(float(amount))), "phone": phone}
        if service == "airtime":
            body["serviceID"] = self.AIRTIME[kw["network"]]
        elif service == "data":
            body["serviceID"] = self.AIRTIME[kw["network"]] + "-data"
            body["billersCode"] = phone
            body["variation_code"] = kw.get("variation_code", "")
            if not body["variation_code"]:
                return outcome(FAILED, "no_plan", "data plan code missing")
        elif service in ("tv", "education"):
            prod = kw.get("network", "")
            if prod not in self.TV and prod not in self.EDU:
                return outcome(FAILED, "no_product", "unknown product")
            if not kw.get("variation_code"):
                return outcome(FAILED, "no_plan", "plan code missing")
            body.update({"serviceID": prod, "variation_code": kw["variation_code"], "billersCode": kw.get("account") or phone})
            if prod in ("dstv", "gotv"):
                body["subscription_type"] = "renew" if kw.get("subscription_type") == "renew" else "change"
            if service == "education" and prod != "jamb":
                body["quantity"] = int(kw.get("quantity") or 1)
                body.pop("billersCode", None)
        elif service == "insurance":
            prod = kw.get("network", "")
            extra = kw.get("extra") or {}
            if prod not in self.INSURANCE or not kw.get("variation_code"):
                return outcome(FAILED, "no_plan", "insurance product or cover type missing")
            missing = [f for f in self.INSURANCE_FIELDS if not str(extra.get(f) or "").strip()]
            if missing:
                return outcome(FAILED, "no_details", "missing: " + ", ".join(missing))
            body.update({"serviceID": prod, "variation_code": kw["variation_code"], "billersCode": str(extra["Plate_Number"])})
            body.update({f: str(extra[f]).strip()[:80] for f in self.INSURANCE_FIELDS})
        else:
            sid = self._disco_map().get(kw.get("disco", ""))
            if not sid:
                return outcome(FAILED, "no_disco", "unknown electricity company")
            body.update({"serviceID": sid, "billersCode": kw.get("account", ""),
                         "variation_code": "postpaid" if str(kw.get("meter_type", "prepaid")).lower().startswith("post") else "prepaid"})
        try:
            r = self.http.post(self.base + "/pay", json=body, headers=self._post_headers(), timeout=(5, 25))
        except requests.RequestException as e:
            return _http_error_outcome(e)
        if r.status_code in (401, 403):
            return outcome(FAILED, f"http_{r.status_code}", "provider rejected our credentials", fault=True)
        try:
            j = r.json()
        except Exception:
            return outcome(PENDING, f"http_{r.status_code}", "unreadable answer", fault=True)
        return self._parse(j, r.status_code)

    def requery(self, request_id):
        try:
            r = self.http.post(self.base + "/requery", json={"request_id": request_id}, headers=self._post_headers(), timeout=(5, 20))
            j = r.json()
        except requests.RequestException as e:
            return outcome(PENDING, "no_response", f"requery failed: {type(e).__name__}")
        except Exception:
            return outcome(PENDING, "unreadable", "requery unreadable")
        return self._parse(j, r.status_code, requery=True)

    @staticmethod
    def _delivery(j, content):
        """What the customer must receive: electricity token, WAEC serial+PIN, JAMB PIN, insurance certificate link, voucher."""
        def get(k):
            return j.get(k) or content.get(k)
        cards = get("cards")
        if isinstance(cards, list) and cards:
            parts = []
            for c in cards:
                if isinstance(c, dict):
                    parts.append("Serial: %s  PIN: %s" % (c.get("Serial") or c.get("serial") or "-", c.get("Pin") or c.get("pin") or "-"))
            if parts:
                return " | ".join(parts)[:280]
        for k in ("purchased_code", "token", "Token", "Pin", "certUrl"):
            v = get(k)
            if v:
                return re.sub(r"^\s*(token|pin)\s*:?\s*", "", str(v), flags=re.I).strip()[:280]
        toks = get("tokens")
        if isinstance(toks, list) and toks:
            return " | ".join(str(t) for t in toks)[:280]
        return ""

    def _parse(self, j, http_status, requery=False):
        code = str(j.get("code") or j.get("response_description") or "")
        content = j.get("content") or {}
        tx = content.get("transactions") if isinstance(content, dict) else None
        tx = tx if isinstance(tx, dict) else {}
        status = str(tx.get("status") or "").lower()
        ref = tx.get("transactionId") or j.get("requestId") or ""
        token = self._delivery(j, content if isinstance(content, dict) else {})
        if code == "000":
            if status == "delivered":
                return outcome(SUCCESS, code, "delivered", ref, token, raw=j)
            if status in ("failed", "reversed", "rejected"):
                return outcome(FAILED, code, f"provider says {status}", ref, fault=True, raw=j)
            return outcome(PENDING, code, status or "processing", ref, token, raw=j)      # initiated / pending / unknown
        if requery and code == "015":                                                    # they have no such request id
            return outcome(PENDING, "015", "provider has no record yet", raw=j)
        if code in self.PENDING_CODES:
            return outcome(PENDING, code, j.get("response_description", "processing"), ref, raw=j)
        if code in self.DEFINITE_FAIL:
            return outcome(FAILED, code, j.get("response_description", "failed"), ref, fault=code not in self.USER_FAULT, raw=j)
        return outcome(PENDING, code or f"http_{http_status}", "unrecognised answer: treated as pending", ref, fault=True, raw=j)


class FlutterwaveAdapter(Adapter):
    """Flutterwave Bill Payments (v3). The public page confirms the request body (country, customer_id, amount, optional
    reference) and that the first answer is 'pending' with the final result by webhook / status check. It does NOT show the
    URL paths, and the biller/item codes are account-specific, so they are configuration, not guesses:
        FLW_SECRET_KEY            (falls back to FLUTTERWAVE_SECRET_KEY, which the app already uses for payments)
        FLW_BILL_PAY_URL          e.g. https://api.flutterwave.com/v3/billers/{biller_code}/items/{item_code}/payment
        FLW_BILL_STATUS_URL       e.g. https://api.flutterwave.com/v3/bills/{reference}
        FLW_PRODUCTS              {"airtime:mtn":{"biller_code":"...","item_code":"..."}, "electricity:ikeja":{...}, ...}
    Copy the exact URLs and codes from your Flutterwave dashboard / API reference. The adapter stays OFF until all are set,
    and supports only the products listed in FLW_PRODUCTS."""
    name = "flutterwave"
    services = ("airtime", "data", "electricity")

    def __init__(self):
        self.http = self.new_http()

    def _key(self):
        return os.getenv("FLW_SECRET_KEY") or os.getenv("FLUTTERWAVE_SECRET_KEY") or ""

    def _products(self):
        try:
            return json.loads(os.getenv("FLW_PRODUCTS", "") or "{}")
        except Exception:
            return {}

    def configured(self):
        return bool(self._key() and os.getenv("FLW_BILL_PAY_URL") and os.getenv("FLW_BILL_STATUS_URL") and self._products())

    def _product(self, service, network="", disco=""):
        return self._products().get(f"{service}:{network or disco}")

    def supports(self, service, network):
        return service in self.services and bool(self._products())

    def _h(self):
        return {"Authorization": "Bearer " + self._key(), "Content-Type": "application/json"}

    def make_request_id(self, reference):
        return re.sub(r"[^A-Za-z0-9_-]", "", str(reference))[:60]

    def buy(self, service, request_id, **kw):
        prod = self._product(service, kw.get("network", ""), kw.get("disco", ""))
        if not prod:
            return outcome(FAILED, "no_product", "product not configured")
        customer = kw.get("account") if service == "electricity" else kw.get("phone")
        url = os.getenv("FLW_BILL_PAY_URL").format(biller_code=prod.get("biller_code", ""), item_code=prod.get("item_code", ""))
        body = {"country": "NG", "customer_id": customer, "amount": float(kw["amount"]), "reference": request_id}
        try:
            r = self.http.post(url, json=body, headers=self._h(), timeout=(5, 25))
        except requests.RequestException as e:
            return _http_error_outcome(e)
        if r.status_code in (401, 403):
            return outcome(FAILED, f"http_{r.status_code}", "provider rejected our credentials", fault=True)
        try:
            j = r.json()
        except Exception:
            return outcome(PENDING, f"http_{r.status_code}", "unreadable answer", fault=True)
        return self._parse(j, r.status_code)

    def requery(self, request_id):
        try:
            r = self.http.get(os.getenv("FLW_BILL_STATUS_URL").format(reference=request_id), headers=self._h(), timeout=(5, 20))
            return self._parse(r.json(), r.status_code)
        except requests.RequestException as e:
            return outcome(PENDING, "no_response", f"requery failed: {type(e).__name__}")
        except Exception:
            return outcome(PENDING, "unreadable", "requery unreadable")

    def _parse(self, j, http_status):
        data = j.get("data") if isinstance(j.get("data"), dict) else {}
        top = str(j.get("status") or "").lower()
        inner = str(data.get("status") or data.get("transaction_status") or "").lower()
        ref = data.get("flw_ref") or data.get("tx_ref") or data.get("reference") or ""
        token = data.get("recharge_token") or ""
        extra = data.get("extra")
        if not token and extra and re.search(r"\d{8,}", str(extra)):
            token = str(extra)
        if inner in ("successful", "success", "completed", "delivered") or (top == "success" and inner in ("successful", "success")):
            return outcome(SUCCESS, "success", "delivered", ref, token, raw=j)
        if inner in ("failed", "reversed", "cancelled", "error") or top == "error":
            return outcome(FAILED, inner or top, str(j.get("message", "failed")), ref, fault=http_status >= 500 or "balance" in str(j.get("message", "")).lower(), raw=j)
        if top == "success":
            return outcome(PENDING, "pending", "accepted, awaiting final status", ref, token, raw=j)   # create answers 'pending' first
        return outcome(PENDING, f"http_{http_status}", "unrecognised answer: treated as pending", ref, fault=True, raw=j)


class StubAdapter(Adapter):
    """A slot for a provider whose API details we do not have yet (Interswitch, Onafriq...). Never configured, never routed."""
    def __init__(self, name):
        self.name = name


def _registry():
    if "adapters" not in _d:
        _d["adapters"] = {a.name: a for a in (VTpassAdapter(), FlutterwaveAdapter(), StubAdapter("interswitch"), StubAdapter("onafriq"))}
    return _d["adapters"]


# ------------------------------------------------------------------------------------------- data plan catalogue
_plan_cache = {}


def data_plans(network, max_age=3600):
    """Cached plan list for a network from the first configured provider that has one (1 hour). [] when unavailable."""
    hit = _plan_cache.get(network)
    if hit and time.time() - hit[0] < max_age:
        return hit[1]
    for a in _registry().values():
        if a.configured() and hasattr(a, "plans") and a.supports("data", network):
            try:
                plans = a.plans(network)
            except Exception as e:
                log.warning("plan list from %s failed: %s", a.name, e)
                continue
            if plans:
                _plan_cache[network] = (time.time(), plans)
                return plans
    return hit[1] if hit else []          # a stale list beats no list


def find_plan(network, code):
    for p in data_plans(network):
        if p["code"] == str(code):
            return p
    return None


_cat_cache = {}


def service_catalog(product, max_age=1800):
    """Cached TV/education plan list for one product ([] when unavailable; a stale list beats none)."""
    hit = _cat_cache.get(product)
    if hit and time.time() - hit[0] < max_age:
        return hit[1]
    a = _registry().get("vtpass")
    if a and a.configured():
        try:
            rows = a.catalog(product)
            if rows:
                _cat_cache[product] = (time.time(), rows)
                return rows
        except Exception as e:
            log.warning("catalogue %s failed: %s", product, e)
    return hit[1] if hit else []


def find_service_plan(product, code):
    for p in service_catalog(product):
        if p["code"] == str(code):
            return p
    return None


def verify_account(product, billers_code, variation_code=""):
    a = _registry().get("vtpass")
    if not a or not a.configured():
        return {"ok": False, "unavailable": True, "message": "Service not available right now."}
    return a.verify(product, billers_code, variation_code)


def list_discos():
    """Electricity companies VTpass can pay: [{key, label}]. Empty when VTpass is not configured."""
    a = _registry().get("vtpass")
    if not a or not a.configured():
        return []
    m = a._disco_map()
    return [{"key": k, "label": a.DISCO_LABEL.get(k, k.replace("-", " ").title())} for k in m]


def verify_meter(disco, meter, meter_type="prepaid"):
    a = _registry().get("vtpass")
    if not a or not a.configured():
        return {"ok": False, "unavailable": True, "message": "Service not available right now."}
    return a.verify_meter(disco, meter, meter_type)


def provider_ready(name):
    """Is this provider configured, switched on in admin and not paused by its circuit breaker?"""
    a = _registry().get(name)
    if not a or not a.configured():
        return False
    try:
        _ensure_schema()
        on, _ = _setting(name)
        return bool(on) and not _breaker_open(name)
    except Exception:
        return False


# ------------------------------------------------------------------------------------------- storage
def _ensure_schema():
    global _schema_done
    if _schema_done:
        return
    with _lock:
        if _schema_done:
            return
        c = _conn()
        try:
            c.execute("""CREATE TABLE IF NOT EXISTS provider_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT NOT NULL, provider TEXT NOT NULL, service TEXT NOT NULL,
                network TEXT, amount REAL, phone_tail TEXT, request_id TEXT, provider_ref TEXT, status TEXT NOT NULL,
                code TEXT, message TEXT, token TEXT, latency_ms INTEGER, fault INTEGER DEFAULT 0, needs_action INTEGER DEFAULT 0,
                handled INTEGER DEFAULT 0, polls INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT)""")
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_pa_ref_provider ON provider_attempts(reference, provider)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_pa_status ON provider_attempts(status, updated_at)")
            c.execute("""CREATE TABLE IF NOT EXISTS provider_settings (
                provider TEXT PRIMARY KEY, enabled INTEGER DEFAULT 1, priority REAL DEFAULT 0, updated_at TEXT)""")
            c.commit()
            _schema_done = True
        finally:
            c.close()


def _setting(name):
    c = _conn()
    try:
        r = c.execute("SELECT enabled, priority FROM provider_settings WHERE provider = ?", (name,)).fetchone()
        return (bool(r["enabled"]), float(r["priority"] or 0)) if r else (True, 0.0)
    finally:
        c.close()


def _stats(provider, network, hours=24, limit=40):
    """(success_rate, avg_latency_s, sample) over the last finished attempts. Smoothed so a new provider starts neutral."""
    c = _conn()
    try:
        rows = c.execute(
            "SELECT status, fault, latency_ms FROM provider_attempts WHERE provider = ? AND (? = '' OR network = ?) "
            "AND status IN ('success','failed') AND updated_at >= ? ORDER BY id DESC LIMIT ?",
            (provider, network or "", network or "", _s(_now() - timedelta(hours=hours)), limit)).fetchall()
    finally:
        c.close()
    # a failure that was the customer's data is not the provider's fault
    rows = [r for r in rows if r["status"] == "success" or r["fault"]]
    n = len(rows)
    ok = sum(1 for r in rows if r["status"] == "success")
    lat = [r["latency_ms"] for r in rows if r["latency_ms"]]
    return (ok + 2) / (n + 3), (sum(lat) / len(lat) / 1000.0 if lat else 3.0), n


def _discount_pct(name):
    try:
        return float(os.getenv(f"PROVIDER_DISCOUNT_PCT_{name.upper()}", "0") or 0)
    except ValueError:
        return 0.0


def _breaker_open(name):
    b = _breaker.get(name)
    return bool(b and b["open_until"] > time.time())


def _breaker_record(name, ok, fault):
    b = _breaker.setdefault(name, {"fails": 0, "open_until": 0})
    if ok:
        b["fails"] = 0
    elif fault:
        b["fails"] += 1
        if b["fails"] >= int(os.getenv("PROVIDER_BREAKER_FAILS", "4")):
            b["open_until"] = time.time() + int(os.getenv("PROVIDER_BREAKER_SECONDS", "180"))
            b["fails"] = 0
            log.warning("provider %s paused for %ss after repeated failures", name, os.getenv("PROVIDER_BREAKER_SECONDS", "180"))


def rank(service, network, disco=""):
    """[(score, adapter)] best first, with the reasoning, for routing and for the admin preview."""
    out = []
    for name, a in _registry().items():
        row = {"provider": name, "eligible": False, "why": ""}
        if not a.configured():
            row["why"] = "not configured"
        elif not a.supports(service, network or disco):
            row["why"] = "does not support this service/network"
        else:
            on, prio = _setting(name)
            if not on:
                row["why"] = "switched off in admin"
            elif _breaker_open(name):
                row["why"] = "paused (recent failures)"
            else:
                rate, lat, n = _stats(name, network)
                score = 100.0 * rate + 10.0 * _discount_pct(name) - 1.0 * lat + prio
                row.update(eligible=True, score=round(score, 2), success_rate=round(rate, 3), avg_seconds=round(lat, 2),
                           sample=n, discount_pct=_discount_pct(name), priority=prio)
        row["_a"] = a
        out.append(row)
    out.sort(key=lambda r: (not r["eligible"], -r.get("score", 0)))
    return out


# ------------------------------------------------------------------------------------------- routing
def _claim(reference, adapter, service, network, amount, phone):
    """Insert the attempt BEFORE calling the provider. The unique (reference, provider) index makes a double click or a second
    worker lose the race instead of buying twice. Returns (row_id, request_id) or (None, None)."""
    rid = adapter.make_request_id(reference)
    c = _conn()
    try:
        c.execute("INSERT INTO provider_attempts (reference, provider, service, network, amount, phone_tail, request_id, status, created_at, updated_at) "
                  "VALUES (?,?,?,?,?,?,?,?,?,?)",
                  (reference, adapter.name, service, network, float(amount), str(phone or "")[-4:], rid, "initiated", _s(_now()), _s(_now())))
        c.commit()
        return c.execute("SELECT id FROM provider_attempts WHERE reference = ? AND provider = ?", (reference, adapter.name)).fetchone()["id"], rid
    except Exception as e:
        if "unique" in str(e).lower():
            return None, None
        raise
    finally:
        c.close()


def _update(att_id, o, latency_ms=None, status=None):
    c = _conn()
    try:
        c.execute("UPDATE provider_attempts SET status = ?, code = ?, message = ?, provider_ref = COALESCE(NULLIF(?, ''), provider_ref), "
                  "token = COALESCE(NULLIF(?, ''), token), latency_ms = COALESCE(?, latency_ms), fault = ?, updated_at = ? WHERE id = ?",
                  (status or o["status"], o["code"], o["message"], o["provider_ref"], o["token"], latency_ms, 1 if o["fault"] else 0,
                   _s(_now()), att_id))
        c.commit()
    finally:
        c.close()


def _poll(adapter, att_id, request_id, first):
    """Ask the SAME provider for the final state, for a few seconds. Returns the last outcome."""
    deadline = time.time() + float(os.getenv("PROVIDER_POLL_SECONDS", "12"))
    last = first
    while time.time() < deadline:
        time.sleep(float(os.getenv("PROVIDER_POLL_INTERVAL", "3")))
        o = adapter.requery(request_id)
        if o["status"] != PENDING:
            return o
        last = {**last, "provider_ref": o["provider_ref"] or last["provider_ref"], "token": o["token"] or last["token"]}
    return last


def _result(att, o, tried):
    return {"status": o["status"], "provider": att, "provider_ref": o["provider_ref"], "token": o["token"], "code": o["code"],
            "message": o["message"], "tried": tried, "fallback_ok": o["status"] == FAILED}


def route_purchase(reference, service, network="", phone="", amount=0, account="", disco="", variation_code="", meter_type="prepaid", quantity=1, subscription_type="", only="", extra=None):
    """Never raises. Returns {status: success|pending|failed|error, provider, provider_ref, token, tried: [...], fallback_ok}.
    fallback_ok is True ONLY when it is certain no provider accepted the order, so the caller may use Reloadly.
    only="vtpass" restricts the order to that provider (the customer chose it); extra carries service-specific fields (insurance)."""
    tried = []
    last_fail = {}
    try:
        _ensure_schema()
        reference = str(reference)
        # 1) idempotency: never buy the same reference twice
        c = _conn()
        try:
            prior = [dict(r) for r in c.execute("SELECT * FROM provider_attempts WHERE reference = ? ORDER BY id", (reference,)).fetchall()]
        finally:
            c.close()
        for p in prior:
            if p["status"] in ("success", "pending", "initiated"):
                ad = _registry().get(p["provider"])
                o = outcome(SUCCESS if p["status"] == "success" else PENDING, p["code"], p["message"], p["provider_ref"], p["token"])
                if p["status"] != "success" and ad:
                    q = ad.requery(p["request_id"])
                    if q["status"] != PENDING:
                        _update(p["id"], q, status=q["status"])
                        o = q
                return _result(p["provider"], o, [p["provider"]])
        done = {p["provider"] for p in prior}

        kw = dict(phone=local_number(phone), amount=amount, network=network, account=account, disco=disco,
                  variation_code=variation_code, meter_type=meter_type, quantity=quantity, subscription_type=subscription_type, extra=extra or {})
        if service in ("airtime", "data") and not kw["phone"]:
            return {"status": "failed", "provider": "", "tried": [], "fallback_ok": True, "message": "not a Nigerian mobile number"}

        for row in rank(service, network, disco):
            if not row["eligible"] or row["provider"] in done or (only and row["provider"] != only):
                continue
            ad = row["_a"]
            att_id, rid = _claim(reference, ad, service, network or disco, amount, kw["phone"] or account)
            if att_id is None:           # another worker is already buying this reference: do not touch it
                return {"status": "pending", "provider": ad.name, "tried": tried, "fallback_ok": False, "message": "already in progress"}
            t0 = time.time()
            try:
                o = ad.buy(service, rid, **kw)
            except Exception as e:       # a bug inside an adapter: we do not know whether anything was sent
                log.exception("adapter %s crashed", ad.name)
                o = outcome(PENDING, "adapter_error", f"{type(e).__name__}", fault=True)
            ms = int((time.time() - t0) * 1000)
            tried.append(ad.name)
            if o["status"] == PENDING:
                _update(att_id, o, ms)
                o = _poll(ad, att_id, rid, o)
            _update(att_id, o, ms)
            _breaker_record(ad.name, o["status"] == SUCCESS, o["fault"] and o["status"] != SUCCESS)
            if o["status"] == SUCCESS:
                return _result(ad.name, o, tried)
            if o["status"] == PENDING:    # unknown: keep it with this provider, the reconciler finishes it
                log.warning("order %s still pending at %s (%s)", reference, ad.name, o["code"])
                return _result(ad.name, o, tried)
            log.info("provider %s failed order %s: %s %s", ad.name, reference, o["code"], o["message"])
            last_fail = o
        return {"status": "failed", "provider": "", "tried": tried, "fallback_ok": True, "code": last_fail.get("code", ""),
                "message": ("no provider could take this order" + (f" (last: {last_fail['code']} {last_fail['message']})" if last_fail else ""))}
    except Exception as e:
        log.exception("router error")
        # if a provider may already have been called, the caller must NOT fall back
        return {"status": "error", "provider": tried[-1] if tried else "", "tried": tried, "fallback_ok": not tried, "message": str(e)[:200]}


# ------------------------------------------------------------------------------------------- reconciliation
def reconcile(limit=30):
    """Requery attempts that are still unknown. A late FAILURE or a late success after the order was already shown as done is
    reported through the on_resolved hook and flagged needs_action when money or airtime may be missing."""
    _ensure_schema()
    n = 0
    c = _conn()
    try:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM provider_attempts WHERE status IN ('pending','initiated') AND updated_at <= ? ORDER BY id LIMIT ?",
            (_s(_now() - timedelta(seconds=30)), limit)).fetchall()]
    finally:
        c.close()
    for p in rows:
        ad = _registry().get(p["provider"])
        if not ad or not ad.configured():
            continue
        o = ad.requery(p["request_id"])
        age_min = (_now() - datetime.strptime(p["created_at"][:19], "%Y-%m-%d %H:%M:%S")).total_seconds() / 60
        if o["status"] == PENDING and o["code"] == "015" and age_min > 10:      # provider never saw it
            o = outcome(FAILED, "015", "provider has no record after 10 minutes", fault=True)
        cc = _conn()
        try:
            cc.execute("UPDATE provider_attempts SET polls = polls + 1 WHERE id = ?", (p["id"],))
            cc.commit()
        finally:
            cc.close()
        if o["status"] == PENDING:
            if age_min > 24 * 60:        # a day unresolved: a human must look
                _flag(p["id"])
            continue
        _apply_outcome(p, o)
        n += 1
    return n


def _apply_outcome(p, o, flip=False):
    """Record a final provider answer for an attempt row `p`. Shared by the reconciler and the VTpass webhook.
    flip=True means the attempt was already final (success/failed) and the provider has now said the opposite
    (e.g. delivered, then reversed): that always needs a human, so it is flagged."""
    _update(p["id"], o)
    _breaker_record(p["provider"], o["status"] == SUCCESS, o["fault"] and o["status"] != SUCCESS)
    if o["status"] == FAILED:
        _flag(p["id"])
        log.critical("PROVIDER %s FAILED AFTER ACCEPT: order %s (%s) needs refund or redelivery", p["provider"], p["reference"], p["code"])
    elif flip:
        _flag(p["id"])
        log.critical("PROVIDER %s CHANGED A FINAL ANSWER: order %s was %s, now %s (%s): check it", p["provider"], p["reference"], p["status"], o["status"], o["code"])
    try:
        if _hooks["on_resolved"]:
            _hooks["on_resolved"](p["reference"], p["provider"], o)
    except Exception:
        log.exception("on_resolved hook failed")


def _flag(att_id):
    c = _conn()
    try:
        c.execute("UPDATE provider_attempts SET needs_action = 1 WHERE id = ?", (att_id,))
        c.commit()
    finally:
        c.close()


# ------------------------------------------------------------------------------------------- VTpass webhook
def handle_vtpass_transaction(data):
    """transaction-update (delivered / failed) and reversal (code 040). The webhook body is only a nudge: we find our attempt by
    requestId and ASK VTpass (requery) for the real state, so a forged or stale webhook cannot deliver or refund anything."""
    rid = str((data or {}).get("requestId") or "").strip()
    if not rid:
        return "no requestId"
    _ensure_schema()
    c = _conn()
    try:
        row = c.execute("SELECT * FROM provider_attempts WHERE provider = 'vtpass' AND request_id = ? ORDER BY id DESC LIMIT 1", (rid,)).fetchone()
    finally:
        c.close()
    if not row:
        log.warning("vtpass webhook for unknown requestId %s", rid)
        return "unknown request"
    p = dict(row)
    ad = _registry().get("vtpass")
    if not ad or not ad.configured():
        return "vtpass not configured"
    o = ad.requery(rid)
    if o["status"] == PENDING:
        return "still pending at provider"
    if p["status"] == o["status"]:
        return "already up to date"
    final_before = p["status"] in (SUCCESS, FAILED)
    _apply_outcome(p, o, flip=final_before)
    return f"{p['status']} -> {o['status']}"


def _variation_event_table():
    c = _conn()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS provider_variation_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, service_id TEXT, added INTEGER, updated INTEGER, removed INTEGER,
            removed_codes TEXT, updated_codes TEXT, affected_schedules TEXT, handled INTEGER DEFAULT 0, created_at TEXT)""")
        c.commit()
    finally:
        c.close()


def _schedules_using(service_id, codes):
    """Active data/TV schedules that store one of these variation codes (read-only: we only report them)."""
    codes = {str(x) for x in codes if x}
    if not codes:
        return []
    c = _conn()
    try:
        rows = c.execute("SELECT id, metadata FROM scheduler_schedules WHERE status = 'active' AND metadata IS NOT NULL").fetchall()
    finally:
        c.close()
    base = service_id[:-5] if service_id.endswith("-data") else service_id
    hits = []
    for r in rows:
        try:
            m = json.loads(r["metadata"] or "{}")
        except Exception:
            continue
        prod = str(m.get("product") or "").lower()
        if str(m.get("variation_code") or "") in codes and prod in (base, VTpassAdapter.AIRTIME.get(prod, "\0"), service_id):
            hits.append(r["id"])
    return hits


def handle_vtpass_variations(j):
    """variations-update: drop the cached plan list for that service so the next request (and the warm-up below) fetches VTpass's
    current prices, and record which saved schedules point at a code VTpass removed. Prices are re-fetched from VTpass, never
    taken from the webhook body."""
    sid = str(j.get("serviceID") or "").strip().lower()
    if not sid:
        return "no serviceID"
    ar = j.get("actionRequired") if isinstance(j.get("actionRequired"), dict) else {}
    def codes(k):
        return [str(x) for x in ((ar.get(k) or {}).get("variation_codes") or [])]
    removed, updated = codes("removed"), codes("updated")
    summ = j.get("summary") if isinstance(j.get("summary"), dict) else {}

    ad = _registry().get("vtpass")
    refreshed = ""
    if sid.endswith("-data"):
        net = next((n for n, s in VTpassAdapter.AIRTIME.items() if s == sid[:-5]), "")
        if net:
            _plan_cache.pop(net, None)
            refreshed = f"data:{net}"
            if ad and ad.configured():
                data_plans(net)
    elif sid in VTpassAdapter.TV or sid in VTpassAdapter.EDU or sid in VTpassAdapter.INSURANCE:
        _cat_cache.pop(sid, None)
        refreshed = f"catalog:{sid}"
        if ad and ad.configured():
            service_catalog(sid)

    affected = _schedules_using(sid, removed + updated)
    _variation_event_table()
    c = _conn()
    try:
        c.execute("INSERT INTO provider_variation_events (service_id, added, updated, removed, removed_codes, updated_codes, affected_schedules, created_at) "
                  "VALUES (?,?,?,?,?,?,?,?)",
                  (sid, int(summ.get("added_variation_codes") or 0), int(summ.get("updated_variation_codes") or len(updated)),
                   int(summ.get("removed_variation_codes") or len(removed)), json.dumps(removed[:500]), json.dumps(updated[:500]),
                   json.dumps(affected[:200]), _s(_now())))
        c.commit()
    finally:
        c.close()
    if removed and affected:
        log.warning("VTpass removed plan codes for %s; %d saved schedules use a removed/changed code: %s", sid, len(affected), affected[:20])
    return f"refreshed={refreshed or 'none (service not cached)'} removed={len(removed)} updated={len(updated)} schedules_affected={len(affected)}"


def process_vtpass_event(payload):
    t = str((payload or {}).get("type") or "")
    if t == "transaction-update":
        return handle_vtpass_transaction(payload.get("data") or {})
    if t == "variations-update":
        return handle_vtpass_variations(payload)
    return "ignored"


def _loop():
    while True:
        time.sleep(int(os.getenv("PROVIDER_RECONCILE_SECONDS", "60")))
        try:
            if enabled():
                reconcile()
        except Exception:
            log.exception("reconcile loop")


# ------------------------------------------------------------------------------------------- admin
def init_providers(app, db_module, admin_required, on_resolved=None):
    _d["db"] = db_module
    _hooks["on_resolved"] = on_resolved
    try:
        _ensure_schema()
    except Exception as e:
        log.warning("provider tables not ready: %s", e)

    @pv_bp.route("/api/data/plans", methods=["GET"])
    def data_plans_route():
        net = request.args.get("network", "").lower()
        if net not in ("mtn", "airtel", "glo", "9mobile"):
            return jsonify({"error": "network must be mtn, airtel, glo or 9mobile"}), 400
        plans = data_plans(net) if enabled() else []
        return jsonify({"network": net, "plans": plans, "available": bool(plans)})

    @pv_bp.route("/webhooks/vtpass", methods=["POST"])
    def vtpass_webhook():
        """VTpass -> Net365: transaction-update (delivered/failed), reversal (code 040) and variations-update.
        Set the URL in your VTpass profile as https://YOUR-DOMAIN/webhooks/vtpass?token=<VTPASS_WEBHOOK_SECRET>
        (or send the same value in an X-Webhook-Token header). Acknowledge first, work in the background."""
        from webhook_security import verify_vtpass_token, vtpass_ip_allowed
        if not os.getenv("VTPASS_WEBHOOK_SECRET", "").strip():
            log.error("VTpass webhook rejected: VTPASS_WEBHOOK_SECRET is not set")
            return jsonify({"error": "Webhook not configured"}), 503
        ip = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "")
        if not vtpass_ip_allowed(ip):
            return jsonify({"error": "forbidden"}), 403
        if not verify_vtpass_token(request.headers.get("X-Webhook-Token") or request.args.get("token") or ""):
            return jsonify({"error": "invalid token"}), 401
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"response": "success"}), 200          # nothing usable; do not make VTpass retry forever
        t = str(payload.get("type") or "")
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        if t == "transaction-update":
            tx = ((data.get("content") or {}).get("transactions") or {})
            wid = f"vtpass:{data.get('requestId')}:{tx.get('status')}:{data.get('code')}"
        elif t == "variations-update":
            wid = f"vtpass-var:{payload.get('serviceID')}:{payload.get('datetime')}"
        else:
            return jsonify({"response": "success"}), 200
        db = _d["db"]

        def work():
            try:
                if db.has_processed_webhook(wid):
                    return
                result = process_vtpass_event(payload)
                db.record_webhook(wid, str(data.get("requestId") or payload.get("serviceID") or ""))
                log.info("vtpass webhook %s: %s", wid, result)
            except Exception:
                log.exception("vtpass webhook processing failed for %s (the reconciler will still catch pending orders)", wid)
        threading.Thread(target=work, daemon=True, name="vtpass-webhook").start()
        return jsonify({"response": "success"}), 200

    @pv_bp.route("/api/admin/providers", methods=["GET"])
    @admin_required
    def providers_status():
        out = []
        for name, a in _registry().items():
            on, prio = _setting(name)
            item = {"provider": name, "configured": a.configured(), "switched_on": on, "priority": prio,
                    "paused": _breaker_open(name), "discount_pct": _discount_pct(name)}
            if a.configured():
                item["balance"] = a.balance()
            out.append(item)
        c = _conn()
        try:
            n = c.execute("SELECT COUNT(*) AS n FROM provider_attempts WHERE needs_action = 1 AND handled = 0").fetchone()["n"]
        finally:
            c.close()
        return jsonify({"router_enabled": enabled(), "needs_action": n, "providers": out})

    @pv_bp.route("/api/admin/providers/preview", methods=["GET"])
    @admin_required
    def providers_preview():
        rows = rank(request.args.get("service", "airtime"), request.args.get("network", ""), request.args.get("disco", ""))
        return jsonify({"order": [{k: v for k, v in r.items() if k != "_a"} for r in rows]})

    @pv_bp.route("/api/admin/providers/setting", methods=["POST"])
    @admin_required
    def providers_setting():
        j = request.get_json(silent=True) or {}
        name = str(j.get("provider", ""))
        if name not in _registry():
            return jsonify({"error": "unknown provider"}), 400
        on, prio = _setting(name)
        if "enabled" in j:
            on = bool(j["enabled"])
        if "priority" in j:
            prio = max(-100.0, min(100.0, float(j["priority"])))
        c = _conn()
        try:
            c.execute("INSERT INTO provider_settings (provider, enabled, priority, updated_at) VALUES (?,?,?,?) "
                      "ON CONFLICT(provider) DO UPDATE SET enabled = excluded.enabled, priority = excluded.priority, updated_at = excluded.updated_at",
                      (name, 1 if on else 0, prio, _s(_now())))
            c.commit()
        finally:
            c.close()
        return jsonify({"ok": True, "provider": name, "enabled": on, "priority": prio})

    @pv_bp.route("/api/admin/providers/attempts", methods=["GET"])
    @admin_required
    def providers_attempts():
        ref = request.args.get("reference", "")
        only = request.args.get("needs_action") == "1"
        sql, args = "SELECT * FROM provider_attempts", []
        conds = []
        if ref:
            conds.append("reference = ?")
            args.append(ref)
        if only:
            conds.append("needs_action = 1 AND handled = 0")
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY id DESC LIMIT 100"
        c = _conn()
        try:
            rows = [dict(r) for r in c.execute(sql, args).fetchall()]
        finally:
            c.close()
        for r in rows:
            r.pop("token", None)           # tokens stay out of admin lists
        return jsonify({"attempts": rows})

    @pv_bp.route("/api/admin/providers/handled", methods=["POST"])
    @admin_required
    def providers_handled():
        i = int((request.get_json(silent=True) or {}).get("id", 0))
        c = _conn()
        try:
            c.execute("UPDATE provider_attempts SET handled = 1 WHERE id = ?", (i,))
            c.commit()
        finally:
            c.close()
        return jsonify({"ok": True})

    @pv_bp.route("/api/admin/providers/reconcile", methods=["POST"])
    @admin_required
    def providers_reconcile():
        return jsonify({"resolved": reconcile()})

    app.register_blueprint(pv_bp)
    threading.Thread(target=_loop, daemon=True, name="provider-reconcile").start()
    log.info("Provider router ready (%s). Set PROVIDER_ROUTER_ENABLED=true to route.", "ON" if enabled() else "OFF")

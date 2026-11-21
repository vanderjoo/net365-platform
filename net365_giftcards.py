"""
net365_giftcards.py - gift cards for Net365 (chat bot first, web later).

What it does
  * Reads the Reloadly Gift Cards catalogue (cached) and normalises it.
  * Prices every card on the SERVER in naira: Reloadly cost x live USD/NGN rate x (1 + markup).
    The client only ever says WHICH card and WHICH denomination; it can never set a price.
  * /api/giftcards/init creates the Paystack payment and a pending 'giftcard' transaction.
  * fulfil_giftcard() runs from _finalize_transaction after the payment is verified: it places the
    Reloadly order. The redeem codes are NOT stored in our database; they are fetched from Reloadly
    when they are delivered (chat + email) and can be fetched again for a resend.

Safety rules (deliberate)
  * Switched off unless GIFTCARDS_ENABLED=true.
  * Linked accounts only (no guests): gift-card codes are cash-like and a prime fraud target.
  * Only USD-priced products whose recipient currency equals the sender currency are offered, so
    there is no denomination/currency ambiguity. Only FIXED denominations are offered for now.
  * Per-card cap (GIFTCARD_MAX_NGN) and the global launch limits still apply.
  * Codes are never written to logs.

!! Verify once in the Reloadly SANDBOX before trusting it with real money: the request/response
!! field names below follow Reloadly's Gift Cards v1 API as documented, but this module could not
!! be run against the live sandbox from the build environment (it is tested with a mock).
"""
import logging
import math
import os
import re
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
import hmac

import requests
from flask import Blueprint, jsonify, request, g

logger = logging.getLogger("net365.giftcards")
gc_bp = Blueprint("giftcards", __name__)

_deps = {}
_cache = {"at": 0.0, "products": []}
_cache_lock = threading.Lock()

CATALOG_TTL = 30 * 60
POPULAR = ["steam", "playstation", "xbox", "google play", "itunes", "apple", "amazon",
           "netflix", "spotify", "uber", "roblox", "nintendo", "razer"]


def enabled():
    return os.getenv("GIFTCARDS_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")


def _markup():
    try:
        return float(os.getenv("GIFTCARD_MARKUP_PERCENT", "7"))
    except ValueError:
        return 7.0


def _max_ngn():
    try:
        return float(os.getenv("GIFTCARD_MAX_NGN", "100000"))
    except ValueError:
        return 100000.0


# --------------------------------------------------------------------------- Reloadly client
class GiftcardClient:
    def __init__(self, credentials):
        self.c = credentials
        sandbox = str(getattr(credentials.environment, "value", credentials.environment)).lower() == "sandbox"
        self.base = "https://giftcards-sandbox.reloadly.com" if sandbox else "https://giftcards.reloadly.com"
        self.session = requests.Session()
        self._token = None
        self._exp = None
        self._lock = threading.Lock()

    def _auth(self):
        with self._lock:
            if self._token and self._exp and datetime.now() < self._exp:
                return self._token
            r = self.session.post(self.c.auth_url, json={
                "client_id": self.c.client_id, "client_secret": self.c.client_secret,
                "grant_type": "client_credentials", "audience": self.base}, timeout=30)
            r.raise_for_status()
            d = r.json()
            self._token = d["access_token"]
            self._exp = datetime.now() + timedelta(seconds=max(60, int(d.get("expires_in", 3600)) - 300))
            return self._token

    def _req(self, method, path, **kw):
        headers = {"Accept": "application/com.reloadly.giftcards-v1+json",
                   "Authorization": f"Bearer {self._auth()}"}
        r = self.session.request(method, f"{self.base}{path}", headers=headers, timeout=30, **kw)
        if r.status_code == 401:
            self._token = None
        r.raise_for_status()
        return r.json() if r.content else {}

    def products(self, iso):
        d = self._req("GET", f"/countries/{iso}/products")
        return d if isinstance(d, list) else d.get("content", [])

    def product(self, product_id):
        return self._req("GET", f"/products/{int(product_id)}")

    def order(self, body):
        return self._req("POST", "/orders", json=body)

    def balance(self):
        return self._req("GET", "/accounts/balance")

    def cards(self, transaction_id):
        d = self._req("GET", f"/orders/transactions/{int(transaction_id)}/cards")
        return d if isinstance(d, list) else d.get("content", [])


_client = None


def _api():
    global _client
    if _client is None:
        _client = GiftcardClient(_deps["credentials"])
    return _client


# --------------------------------------------------------------------------- catalogue + pricing
def _usd_to_ngn():
    return float(_deps["usd_to_ngn"]())


def _normalise(p):
    """Keep only products we can sell safely. Returns a dict or None."""
    try:
        if str(p.get("denominationType", "")).upper() != "FIXED":
            return None
        if str(p.get("status", "ACTIVE")).upper() not in ("ACTIVE", ""):
            return None
        rc, sc = str(p.get("recipientCurrencyCode", "")).upper(), str(p.get("senderCurrencyCode", "")).upper()
        if rc != "USD" or sc != "USD":
            return None
        denoms = p.get("fixedRecipientDenominations") or []
        mp = p.get("fixedRecipientToSenderDenominationsMap") or {}
        out = []
        for d in denoms:
            cost = mp.get(str(d), mp.get(str(float(d)), d))
            out.append({"recipient": float(d), "cost_usd": float(cost)})
        if not out:
            return None
        return {
            "id": int(p["productId"]), "name": str(p.get("productName") or "Gift card")[:60],
            "brand": str((p.get("brand") or {}).get("brandName") or p.get("productName") or "")[:40],
            "country": str((p.get("country") or {}).get("isoName") or p.get("countryCode") or "US").upper(),
            "denominations": sorted(out, key=lambda x: x["recipient"]),
            "fee_usd": float(p.get("senderFee") or 0), "fee_pct": float(p.get("senderFeePercentage") or 0),
            "redeem": str(((p.get("redeemInstruction") or {}).get("concise")) or "")[:300],
        }
    except Exception:
        return None


def catalogue(force=False):
    with _cache_lock:
        if not force and _cache["products"] and time.time() - _cache["at"] < CATALOG_TTL:
            return _cache["products"]
    items = []
    for iso in [c.strip().upper() for c in os.getenv("GIFTCARD_CATALOG_COUNTRIES", "US").split(",") if c.strip()]:
        try:
            for p in _api().products(iso):
                n = _normalise(p)
                if n:
                    items.append(n)
        except Exception as e:
            logger.warning("gift-card catalogue fetch failed for %s: %s", iso, e)
    if items:
        with _cache_lock:
            _cache.update(at=time.time(), products=items)
        return items
    with _cache_lock:
        return _cache["products"]  # stale is better than nothing


def price_ngn(product, denom):
    """Server-side customer price (NGN, rounded up to the next N10) for one denomination."""
    cost = float(denom["cost_usd"])
    usd = cost * (1 + product["fee_pct"] / 100.0) + product["fee_usd"]
    ngn = usd * _usd_to_ngn() * (1 + _markup() / 100.0)
    return int(math.ceil(ngn / 10.0) * 10)


def _find(product_id):
    for p in catalogue():
        if p["id"] == int(product_id):
            return p
    return None


def _view(p):
    return {"id": p["id"], "name": p["name"], "brand": p["brand"], "country": p["country"],
            "redeem": p["redeem"],
            "denominations": [{"value": d["recipient"], "price_ngn": price_ngn(p, d)} for d in p["denominations"]]}


# --------------------------------------------------------------------------- routes
def _bot_required(fn):
    @wraps(fn)
    def w(*a, **kw):
        expected = os.getenv("WHATSAPP_BOT_SECRET", "").strip()
        given = request.headers.get("X-Bot-Secret", "")
        if not expected or not hmac.compare_digest(given.encode(), expected.encode()):
            return jsonify({"success": False, "error": "forbidden"}), 403
        return fn(*a, **kw)
    return w


@gc_bp.route("/api/whatsapp/giftcards/search", methods=["POST"])
@_bot_required
def gc_search():
    if not enabled():
        return jsonify({"success": True, "enabled": False})
    q = str((request.get_json(silent=True) or {}).get("q") or "").strip().lower()[:40]
    items = catalogue()
    if not items:
        return jsonify({"success": True, "enabled": True, "items": [], "unavailable": True})
    if q:
        hits = [p for p in items if q in p["name"].lower() or q in p["brand"].lower()]
    else:
        def rank(p):
            n = (p["brand"] + " " + p["name"]).lower()
            for i, w in enumerate(POPULAR):
                if w in n:
                    return i
            return 99
        hits = sorted([p for p in items if rank(p) < 99], key=rank)
    out = []
    for p in hits[:8]:
        prices = [price_ngn(p, d) for d in p["denominations"]]
        out.append({"id": p["id"], "name": p["name"], "country": p["country"], "from_ngn": min(prices)})
    return jsonify({"success": True, "enabled": True, "items": out})


@gc_bp.route("/api/whatsapp/giftcards/product", methods=["POST"])
@_bot_required
def gc_product():
    if not enabled():
        return jsonify({"success": True, "enabled": False})
    p = _find((request.get_json(silent=True) or {}).get("id") or 0) if str((request.get_json(silent=True) or {}).get("id") or "").isdigit() else None
    if not p:
        return jsonify({"success": False, "error": "not_found"}), 404
    return jsonify({"success": True, "enabled": True, "product": _view(p)})


def init_giftcards(app, *, login_required, credentials, db, platform, usd_to_ngn, safe_return_url, is_guest_user):
    _deps.update(credentials=credentials, db=db, platform=platform, usd_to_ngn=usd_to_ngn)

    @gc_bp.route("/api/giftcards/init", methods=["POST"])
    @login_required
    def gc_init():
        if not enabled():
            return jsonify({"success": False, "error": "Gift cards are not available yet."}), 503
        uid = g.current_user_id
        if is_guest_user(uid):
            return jsonify({"success": False, "code": "ACCOUNT_REQUIRED",
                            "error": "Link a free Net365 account to buy gift cards."}), 403
        d = request.get_json(silent=True) or {}
        p = _find(d.get("product_id") or 0) if str(d.get("product_id") or "").isdigit() else None
        if not p:
            return jsonify({"success": False, "error": "That card is not available."}), 404
        try:
            want = float(d.get("denomination"))
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Choose a card value."}), 400
        den = next((x for x in p["denominations"] if abs(x["recipient"] - want) < 1e-6), None)
        if not den:
            return jsonify({"success": False, "error": "That value is not offered for this card."}), 400
        total = price_ngn(p, den)
        if total > _max_ngn():
            return jsonify({"success": False, "error": f"Gift cards are limited to ₦{_max_ngn():,.0f} each for now."}), 400
        lim = _deps.get("limit_check")
        if lim:
            msg = lim(uid, total)
            if msg:
                return jsonify({"success": False, "code": "LIMIT_EXCEEDED", "error": msg}), 400
        user = db.get_user(uid) or {}
        email = user.get("email")
        if not email:
            return jsonify({"success": False, "error": "Your account needs an email address."}), 400
        res = platform.create_payment(amount=float(total), currency="NGN", email=email,
                                      return_url=safe_return_url(d.get("return_url")), provider="paystack")
        if not (res.get("success") and res.get("reference")):
            return jsonify({"success": False, "error": res.get("error") or "Could not start the payment."}), 502
        payload = {"product_id": p["id"], "product_name": p["name"], "denomination": den["recipient"],
                   "cost_usd": den["cost_usd"], "country_code": p["country"], "email": email, "user_id": uid}
        if str(d.get("source") or "") in ("telegram", "whatsapp"):
            payload["source"] = d["source"]
        if d.get("save_card"):
            payload["save_card"] = True
        db.create_pending(reference=res["reference"], tx_type="giftcard", provider=res.get("provider", "paystack"),
                          amount=float(total), currency="NGN", payload=payload, user_id=uid)
        return jsonify({"success": True, "authorization_url": res.get("authorization_url") or res.get("checkout_url"),
                        "reference": res["reference"], "amount": total})

    app.register_blueprint(gc_bp)
    logger.info("Gift cards module ready (%s)", "ON" if enabled() else "OFF - set GIFTCARDS_ENABLED=true")


def set_limit_check(fn):
    _deps["limit_check"] = fn


# --------------------------------------------------------------------------- fulfilment
def fulfil_giftcard(reference, payload, tx):
    """Place the Reloadly order for a verified payment. Raises on failure (caller marks it failed).
    Returns a small result dict WITHOUT the redeem codes."""
    if not enabled():
        raise Exception("Gift cards are switched off")
    body = {
        "productId": int(payload["product_id"]), "countryCode": payload.get("country_code") or "US",
        "quantity": 1, "unitPrice": float(payload["denomination"]),
        "customIdentifier": str(reference)[:36], "preOrder": False,
        "senderName": "Net365", "recipientEmail": payload.get("email"),
    }
    r = _api().order(body)
    status = str(r.get("status", "")).upper()
    tid = r.get("transactionId") or r.get("id")
    if not tid or status in ("FAILED", "REFUNDED", "ERROR"):
        raise Exception(r.get("message") or "Gift card order failed")
    return {"status": "success", "transactionId": tid, "provider": "reloadly-giftcards",
            "product": payload.get("product_name"), "denomination": payload.get("denomination"),
            "order_status": status}


def redeem_help(product_id):
    """Short "how to redeem" text for a product (Reloadly's own redeem instruction). '' if unavailable."""
    try:
        p = _api().product(int(product_id)) or {}
        return str(((p.get("redeemInstruction") or {}).get("concise")) or "").strip()[:300]
    except Exception:
        return ""


def fetch_codes(transaction_id, tries=5, wait=2.0):
    """Fetch the redeem codes from Reloadly (never stored by us). Returns [{number, pin, url}]."""
    out = []
    for i in range(tries):
        try:
            cards = _api().cards(transaction_id)
        except Exception as e:
            logger.warning("gift-card code fetch attempt %s failed: %s", i + 1, type(e).__name__)
            cards = []
        for c in cards or []:
            out.append({"number": str(c.get("cardNumber") or ""), "pin": str(c.get("pinCode") or ""),
                        "url": str(c.get("redemptionUrl") or "")})
        if out:
            return out
        time.sleep(wait)
    return out

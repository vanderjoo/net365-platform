import os
import hmac
import hashlib
import json


def _secret(name):
    return os.getenv(name, '').strip()


def verify_paystack_signature(payload: bytes, signature: str) -> bool:
    secret = _secret('PAYSTACK_SECRET_KEY')
    if not secret or not signature:
        return False
    digest = hmac.new(secret.encode(), payload, hashlib.sha512).hexdigest()
    return hmac.compare_digest(digest, signature)


def verify_vtpass_token(provided: str) -> bool:
    # VTpass webhooks carry no signature, so the URL (or an X-Webhook-Token header) carries a shared secret.
    # Fails closed: with no VTPASS_WEBHOOK_SECRET set, nothing is accepted.
    secret = _secret('VTPASS_WEBHOOK_SECRET')
    if not secret or not provided:
        return False
    return hmac.compare_digest(secret, provided.strip())


def vtpass_ip_allowed(ip: str) -> bool:
    # Optional extra layer: VTPASS_WEBHOOK_IPS="1.2.3.4,5.6.7.8". Empty = no IP restriction.
    allowed = [x.strip() for x in _secret('VTPASS_WEBHOOK_IPS').split(',') if x.strip()]
    return (not allowed) or (ip or '') in allowed


def verify_flutterwave_signature(payload: bytes, signature: str) -> bool:
    # Flutterwave's webhook verification depends on the configured secret hash.
    # Support the standard NET365 secret-hash header value.
    secret = _secret('FLUTTERWAVE_SECRET_HASH')
    if not secret or not signature:
        return False
    return hmac.compare_digest(secret, signature)

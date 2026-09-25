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


def verify_flutterwave_signature(payload: bytes, signature: str) -> bool:
    # Flutterwave's webhook verification depends on the configured secret hash.
    # Support the standard NET365 secret-hash header value.
    secret = _secret('FLUTTERWAVE_SECRET_HASH')
    if not secret or not signature:
        return False
    return hmac.compare_digest(secret, signature)

# ============ STANDARD IMPORTS ============
import sys
import io
import os
import uuid
import logging

# ============ WINDOWS CONSOLE / UNICODE FIX ============
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    os.environ["PYTHONIOENCODING"] = "utf-8"

# ============ LOGGING SETUP ============
# Must run BEFORE any code below calls logger.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

# ============ LOAD .env ============
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("Loaded .env file using python-dotenv")
except ImportError:
    print("python-dotenv not installed, using system environment variables")

# ============ SMTP DIAGNOSTICS ============
_smtp_host_check = os.getenv("SMTP_HOST")
if _smtp_host_check:
    print(f"SMTP_HOST loaded as: [{_smtp_host_check}]")
else:
    print("SMTP_HOST not set — email sending will use the default (smtp.mailgun.org)")
print(f"SMTP_PORT loaded as: [{os.getenv('SMTP_PORT', '587 (default)')}]")
_smtp_user_check = os.getenv("SMTP_USER")
_smtp_pass_check = os.getenv("SMTP_PASSWORD")
print(f"SMTP_USER loaded: [{'SET as ' + _smtp_user_check if _smtp_user_check else 'NOT SET'}]")
print(f"SMTP_PASSWORD loaded: [{'SET' if _smtp_pass_check else 'NOT SET'}]")
_resend_check = os.getenv("RESEND_API_KEY")
_mg_check = os.getenv("MAILGUN_API_KEY") and os.getenv("MAILGUN_DOMAIN")
if _resend_check:
    print("Email provider: Resend API (HTTPS)")
elif _mg_check:
    print(f"Email provider: Mailgun API (HTTPS), domain {os.getenv('MAILGUN_DOMAIN')}, base {os.getenv('MAILGUN_API_BASE', 'https://api.mailgun.net')}")
elif _smtp_user_check and _smtp_pass_check:
    print("Email provider: SMTP only. NOTE: Render free services block SMTP ports 25/465/587, so mail will fail there. "
          "Set RESEND_API_KEY or MAILGUN_API_KEY + MAILGUN_DOMAIN.")
else:
    print("⚠️ WARNING: no email provider configured. Set RESEND_API_KEY, or MAILGUN_API_KEY + MAILGUN_DOMAIN "
          "(HTTPS, works on Render). Until then every email (login codes, chat-link codes, receipts) is silently skipped.")

# ============ ENVIRONMENT VARIABLES CHECK ============
print("=" * 60)
print("ENVIRONMENT VARIABLES CHECK")
print("=" * 60)
print(f"RELOADLY_CLIENT_ID: {os.getenv('RELOADLY_CLIENT_ID', 'NOT SET')[:15] if os.getenv('RELOADLY_CLIENT_ID') else 'NOT SET'}...")
print(f"RELOADLY_CLIENT_SECRET: {'SET' if os.getenv('RELOADLY_CLIENT_SECRET') else 'NOT SET'}")
print(f"RELOADLY_ENVIRONMENT: {os.getenv('RELOADLY_ENVIRONMENT', 'NOT SET')}")
print(f"PAYMENT_SERVICE_URL: {os.getenv('PAYMENT_SERVICE_URL', 'NOT SET')}")
print(f"PUBLIC_URL: {os.getenv('PUBLIC_URL', 'NOT SET')}")
print(f"FRONTEND_URL: {os.getenv('FRONTEND_URL', 'NOT SET')}")
print(f"EXCHANGE_RATE_INTERVAL: {os.getenv('EXCHANGE_RATE_INTERVAL', '300')} seconds")
print("=" * 60 + "\n")

# ============ ENCRYPTION SETUP ============
# This must come AFTER logger exists (it uses logger.warning).
_ENV = os.getenv("ENVIRONMENT", "").lower()
_ENCRYPTION_KEY_RAW = os.getenv("ENCRYPTION_KEY")

_encryption_key_valid = False
_encryption_key_error = "not set"   # always defined

if _ENCRYPTION_KEY_RAW:
    try:
        from cryptography.fernet import Fernet as _Fernet
        _Fernet(_ENCRYPTION_KEY_RAW.encode())
        _encryption_key_valid = True
        _encryption_key_error = None
    except Exception as _e:
        _encryption_key_valid = False
        _encryption_key_error = str(_e)

# Build the global `cipher` — encrypt_pii/decrypt_pii depend on this existing.
cipher = None
if _encryption_key_valid:
    try:
        from cryptography.fernet import Fernet
        cipher = Fernet(_ENCRYPTION_KEY_RAW.encode())
    except Exception as _e:
        logger.error(f"Failed to construct Fernet cipher: {_e}")
        cipher = None

if _ENV == "production":
    if not _encryption_key_valid:
        raise ValueError(
            f"ENCRYPTION_KEY is required and must be a valid Fernet key in production "
            f"(problem: {_encryption_key_error}). Generate one with: "
            f"python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    logger.info("✅ Production mode: ENCRYPTION_KEY is set and valid")
else:
    if not _encryption_key_valid:
        logger.warning(
            f"⚠️  ENCRYPTION_KEY {_encryption_key_error} — PII will be stored in plaintext. "
            f"Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    else:
        logger.info("✅ Development mode: ENCRYPTION_KEY set and valid")
# ==========================================================

import requests
import json
import uuid
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import logging
from dataclasses import dataclass
from enum import Enum
from functools import wraps
import time
import base64
import threading
import re
import hashlib
import sqlite3
from urllib.parse import urlsplit, urlunsplit, quote
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

import database as db
from ip_intel import IPIntel, detect_bot
from webhook_security import verify_paystack_signature, verify_flutterwave_signature
from net365_ua import DeviceDetector, parse_device_model
from geo_resolver import GeoResolver, is_public_ip

GeoResolver.configure(db.get_db_connection)

# ============ CHECK ENCRYPTION KEY IN PRODUCTION ============
if (os.getenv("ENVIRONMENT", "").lower() == "production"
        or os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("RAILWAY_PROJECT_ID")):
    if not os.getenv("ENCRYPTION_KEY"):
        raise ValueError(
            "ENCRYPTION_KEY required in production! Please set ENCRYPTION_KEY in .env file."
        )
    print("✅ Production mode: ENCRYPTION_KEY is set")
else:
    if not os.getenv("ENCRYPTION_KEY"):
        print("⚠️ WARNING: ENCRYPTION_KEY not set! PII will be stored in plaintext.")
        print("   Set ENCRYPTION_KEY in .env file for security.")


# ============ EXCHANGE RATE SERVICE WITH AUTO-REFRESH ============
def _env_float_early(name, default):
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return float(default)


class ExchangeRateService:
    """Dynamic exchange rate service with automatic refresh"""

    FALLBACK_RATES = {
        # ── units per 1 USD ───────────────────────────────────────────
        "USD": 1.0,
        "NGN": _env_float_early("FALLBACK_NGN_PER_USD", 1350.0),   # set to today's rate on Railway
        "GBP": 0.79,       # 1 USD ≈ 0.79 GBP  ← was 1.25 (wrong direction)
        "EUR": 0.92,       # 1 USD ≈ 0.92 EUR  ← was 1.08 (wrong direction)
        "CAD": 1.36,       # 1 USD ≈ 1.36 CAD
        "AUD": 1.52,       # 1 USD ≈ 1.52 AUD
        "NZD": 1.66,
        "BRL": 5.05,
        "MXN": 17.20,
        "ARS": 900.0,
        "CLP": 950.0,
        "COP": 4000.0,
        "PEN": 3.75,
        "JPY": 150.0,
        "CNY": 7.20,
        "HKD": 7.82,
        "SGD": 1.34,
        "MYR": 4.72,
        "THB": 35.80,
        "VND": 24500.0,
        "PHP": 56.50,
        "IDR": 15800.0,
        "INR": 83.20,
        "PKR": 278.0,
        "BDT": 110.0,
        "AED": 3.67,
        "SAR": 3.75,
        "EGP": 48.50,
        "TRY": 32.0,
        "GHS": 15.5,
        "KES": 150.0,
        "ZAR": 18.5,
        "UGX": 3800.0,
        "TZS": 2600.0,
        "CHF": 0.90,
        "SEK": 10.5,
        "NOK": 10.8,
        "DKK": 6.9,
        "PLN": 4.0,
        "KRW": 1330.0,
        "ILS": 3.75,
    }

    # Cache
    _cache = {}
    _last_update = None
    _update_interval = 300
    _lock = threading.Lock()
    _thread = None
    _running = False
    _update_count = 0
    _last_success = None
    _api_sources = [
        {
            "name": "exchangerate-api",
            "url": "https://api.exchangerate-api.com/v4/latest/USD",
            "parser": lambda d: d.get("rates", {}),
        },
        {
            "name": "frankfurter",
            "url": "https://api.frankfurter.app/latest?from=USD",
            "parser": lambda d: d.get("rates", {}),
        },
        {
            "name": "currencyapi",
            "url": "https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/usd.min.json",
            "parser": lambda d: {k.upper(): v for k, v in d.get("usd", {}).items()},
        },
    ]

    @classmethod
    def start_auto_refresh(cls, interval_seconds: int = 300):
        if cls._running:
            logger.info("Exchange rate auto-refresh already running")
            return

        cls._update_interval = max(interval_seconds, 60)
        cls._running = True
        cls._thread = threading.Thread(target=cls._auto_refresh_loop, daemon=True)
        cls._thread.start()
        logger.info(
            f"Started exchange rate auto-refresh every {cls._update_interval} seconds"
        )
        cls._fetch_rates()

    @classmethod
    def stop_auto_refresh(cls):
        cls._running = False
        if cls._thread:
            cls._thread.join(timeout=2)
        logger.info("Stopped exchange rate auto-refresh")

    @classmethod
    def _auto_refresh_loop(cls):
        while cls._running:
            try:
                time.sleep(cls._update_interval)
                if cls._running:
                    cls._fetch_rates()
            except Exception as e:
                logger.error(f"Auto-refresh error: {e}")

    @classmethod
    def _fetch_rates(cls):
        with cls._lock:
            try:
                rates = cls._fetch_from_multiple_sources()
                if rates and len(rates) > 0:
                    for currency, rate in rates.items():
                        cls._cache[currency.upper()] = rate

                    cls._last_update = datetime.now()
                    cls._update_count += 1
                    cls._last_success = datetime.now()

                    for currency, rate in rates.items():
                        if currency.upper() in cls.FALLBACK_RATES:
                            cls.FALLBACK_RATES[currency.upper()] = rate

                    logger.info(
                        f"✅ Exchange rates updated successfully at {cls._last_update.isoformat()}"
                    )
                    logger.info(
                        f"   Rates: USD/NGN={cls.get_ngn_to_usd():.2f}, USD/GBP={cls.get_rate('GBP'):.4f}, USD/EUR={cls.get_rate('EUR'):.4f}"
                    )
                    return True
                else:
                    logger.warning(
                        "No rates fetched from any source, keeping existing rates"
                    )
                    return False
            except Exception as e:
                logger.error(f"Error fetching exchange rates: {e}")
                return False

    _last_live = 0.0

    @classmethod
    def rates_are_live(cls, max_age_seconds: int = 6 * 3600) -> bool:
        """True only if a real (non-fallback) rate fetch succeeded recently."""
        return (time.time() - cls._last_live) < max_age_seconds

    @classmethod
    def _fetch_from_multiple_sources(cls) -> Dict[str, float]:
        for source in cls._api_sources:
            try:
                response = requests.get(source["url"], timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    rates = source["parser"](data)
                    if rates and len(rates) > 0:
                        if "NGN" in rates or "NGN" in str(rates).upper():
                            cls._last_live = time.time()
                            logger.info(f"✅ Got rates from {source['name']}")
                            return {k.upper(): v for k, v in rates.items()}
            except Exception as e:
                logger.warning(f"Source {source['name']} failed: {e}")
                continue

        logger.warning("All API sources failed, using fallback rates")
        return cls.FALLBACK_RATES.copy()

    @classmethod
    def get_rate(cls, from_currency: str, to_currency: str = "USD") -> float:
        from_currency = from_currency.upper()
        to_currency = to_currency.upper()

        if from_currency == to_currency:
            return 1.0

        if from_currency in cls._cache:
            rate_to_usd = cls._cache[from_currency]
        else:
            rate_to_usd = cls.FALLBACK_RATES.get(from_currency, 1.0)

        if to_currency == "USD":
            return rate_to_usd

        if to_currency in cls._cache:
            target_rate = cls._cache[to_currency]
        else:
            target_rate = cls.FALLBACK_RATES.get(to_currency, 1.0)

        return rate_to_usd / target_rate

    @classmethod
    def get_ngn_to_usd(cls) -> float:
        return cls.get_rate("NGN", "USD")

    @classmethod
    def get_usd_to_ngn(cls) -> float:
        rate = cls.get_ngn_to_usd()
        return 1 / rate if rate > 0 else 1.0

    @classmethod
    def convert(
        cls, amount: float, from_currency: str, to_currency: str = "USD"
    ) -> float:
        if amount <= 0:
            return 0.0

        rate = cls.get_rate(from_currency, to_currency)
        result = amount / rate if from_currency != "USD" else amount * rate
        return round(result, 2)

    @classmethod
    def get_status(cls) -> Dict:
        return {
            "last_update": cls._last_update.isoformat() if cls._last_update else None,
            "last_success": (
                cls._last_success.isoformat() if cls._last_success else None
            ),
            "update_count": cls._update_count,
            "update_interval": cls._update_interval,
            "is_running": cls._running,
            "cached_currencies": list(cls._cache.keys()),
            "ngn_to_usd": cls.get_ngn_to_usd(),
            "gbp_to_usd": cls.get_rate("GBP"),
            "eur_to_usd": cls.get_rate("EUR"),
        }

    @classmethod
    def force_refresh(cls) -> bool:
        logger.info("Forcing exchange rate refresh...")
        return cls._fetch_rates()

    @classmethod
    def set_update_interval(cls, interval_seconds: int):
        if interval_seconds < 60:
            interval_seconds = 60
        cls._update_interval = interval_seconds
        logger.info(f"Update interval changed to {interval_seconds} seconds")


# ============ UTILITY BILLER AMOUNT VALIDATION ============
class UtilityBillerValidator:
    """Validate utility biller amounts against biller limits"""

    BILLER_LIMITS = {
        # Nigeria - Electricity
        38: {
            "min": 500,
            "max": 50000,
            "name": "Eko Electric",
            "valid_amounts": [
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        39: {
            "min": 500,
            "max": 50000,
            "name": "Ikeja Electric",
            "valid_amounts": [
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        40: {
            "min": 500,
            "max": 50000,
            "name": "Kaduna Electric",
            "valid_amounts": [
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        41: {
            "min": 500,
            "max": 50000,
            "name": "Kano Electric",
            "valid_amounts": [
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        42: {
            "min": 500,
            "max": 50000,
            "name": "Abuja Electric",
            "valid_amounts": [
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        43: {
            "min": 500,
            "max": 50000,
            "name": "Port Harcourt Electric",
            "valid_amounts": [
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        44: {
            "min": 500,
            "max": 50000,
            "name": "Benin Electric",
            "valid_amounts": [
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        45: {
            "min": 500,
            "max": 50000,
            "name": "Enugu Electric",
            "valid_amounts": [
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        46: {
            "min": 500,
            "max": 50000,
            "name": "Ibadan Electric",
            "valid_amounts": [
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        47: {
            "min": 500,
            "max": 50000,
            "name": "Jos Electric",
            "valid_amounts": [
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        # Nigeria - Cable TV
        53: {
            "min": 1000,
            "max": 30000,
            "name": "DSTV",
            "valid_amounts": [
                1000,
                1500,
                2000,
                2500,
                3000,
                4000,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                12000,
                15000,
                18000,
                20000,
                25000,
                30000,
            ],
        },
        54: {
            "min": 500,
            "max": 15000,
            "name": "GOtv",
            "valid_amounts": [
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                12000,
                15000,
            ],
        },
        55: {
            "min": 500,
            "max": 15000,
            "name": "Startimes",
            "valid_amounts": [
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
                6000,
                7000,
                8000,
                9000,
                10000,
                12000,
                15000,
            ],
        },
        # Nigeria - Airtime
        49: {
            "min": 50,
            "max": 5000,
            "name": "MTN Nigeria",
            "valid_amounts": [
                50,
                100,
                200,
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
            ],
        },
        50: {
            "min": 50,
            "max": 5000,
            "name": "Glo Nigeria",
            "valid_amounts": [
                50,
                100,
                200,
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
            ],
        },
        51: {
            "min": 50,
            "max": 5000,
            "name": "Airtel Nigeria",
            "valid_amounts": [
                50,
                100,
                200,
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
            ],
        },
        52: {
            "min": 50,
            "max": 5000,
            "name": "9mobile Nigeria",
            "valid_amounts": [
                50,
                100,
                200,
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                3500,
                4000,
                4500,
                5000,
            ],
        },
        # Kenya
        201: {
            "min": 50,
            "max": 10000,
            "name": "Safaricom Kenya",
            "valid_amounts": [
                50,
                100,
                200,
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                4000,
                5000,
                7500,
                10000,
            ],
        },
        202: {
            "min": 50,
            "max": 10000,
            "name": "Airtel Kenya",
            "valid_amounts": [
                50,
                100,
                200,
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                4000,
                5000,
                7500,
                10000,
            ],
        },
        203: {
            "min": 100,
            "max": 50000,
            "name": "Kenya Power",
            "valid_amounts": [
                100,
                200,
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                4000,
                5000,
                7500,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        # Ghana
        301: {
            "min": 50,
            "max": 5000,
            "name": "MTN Ghana",
            "valid_amounts": [
                50,
                100,
                200,
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                4000,
                5000,
            ],
        },
        302: {
            "min": 50,
            "max": 5000,
            "name": "Vodafone Ghana",
            "valid_amounts": [
                50,
                100,
                200,
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                4000,
                5000,
            ],
        },
        303: {
            "min": 100,
            "max": 50000,
            "name": "ECG Ghana",
            "valid_amounts": [
                100,
                200,
                500,
                1000,
                1500,
                2000,
                3000,
                4000,
                5000,
                7500,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        # South Africa
        401: {
            "min": 50,
            "max": 5000,
            "name": "Vodacom SA",
            "valid_amounts": [
                50,
                100,
                200,
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                4000,
                5000,
            ],
        },
        402: {
            "min": 50,
            "max": 5000,
            "name": "MTN SA",
            "valid_amounts": [
                50,
                100,
                200,
                500,
                1000,
                1500,
                2000,
                2500,
                3000,
                4000,
                5000,
            ],
        },
        403: {
            "min": 100,
            "max": 50000,
            "name": "Eskom SA",
            "valid_amounts": [
                100,
                200,
                500,
                1000,
                1500,
                2000,
                3000,
                4000,
                5000,
                7500,
                10000,
                15000,
                20000,
                30000,
                40000,
                50000,
            ],
        },
        # UK
        501: {
            "min": 10,
            "max": 500,
            "name": "British Gas",
            "valid_amounts": [
                10,
                20,
                30,
                40,
                50,
                75,
                100,
                150,
                200,
                250,
                300,
                400,
                500,
            ],
        },
        502: {
            "min": 10,
            "max": 500,
            "name": "E.ON UK",
            "valid_amounts": [
                10,
                20,
                30,
                40,
                50,
                75,
                100,
                150,
                200,
                250,
                300,
                400,
                500,
            ],
        },
        # Europe
        601: {
            "min": 10,
            "max": 500,
            "name": "EDF France",
            "valid_amounts": [
                10,
                20,
                30,
                40,
                50,
                75,
                100,
                150,
                200,
                250,
                300,
                400,
                500,
            ],
        },
        602: {
            "min": 10,
            "max": 500,
            "name": "E.ON Germany",
            "valid_amounts": [
                10,
                20,
                30,
                40,
                50,
                75,
                100,
                150,
                200,
                250,
                300,
                400,
                500,
            ],
        },
    }

    DEFAULT_LIMITS = {
        "min": 50,
        "max": 5000,
        "valid_amounts": [
            50,
            100,
            200,
            500,
            1000,
            1500,
            2000,
            2500,
            3000,
            3500,
            4000,
            4500,
            5000,
        ],
    }

    @classmethod
    def get_biller_limits(cls, biller_id: int) -> Dict:
        return cls.BILLER_LIMITS.get(biller_id, cls.DEFAULT_LIMITS)

    @classmethod
    def validate_amount(cls, biller_id: int, amount: float) -> Dict:
        limits = cls.get_biller_limits(biller_id)
        min_amount = limits.get("min", 50)
        max_amount = limits.get("max", 5000)
        valid_amounts = limits.get("valid_amounts", [])

        if amount < min_amount:
            return {
                "valid": False,
                "adjusted": float(min_amount),
                "message": f"Amount is below minimum of {min_amount}. Adjusted to {min_amount}.",
                "original": amount,
            }

        if amount > max_amount:
            return {
                "valid": False,
                "adjusted": float(max_amount),
                "message": f"Amount exceeds maximum of {max_amount}. Adjusted to {max_amount}.",
                "original": amount,
            }

        if valid_amounts and amount not in valid_amounts:
            closest = min(valid_amounts, key=lambda x: abs(x - amount))
            return {
                "valid": False,
                "adjusted": float(closest),
                "message": f"Amount adjusted to nearest valid amount: {closest}",
                "original": amount,
            }

        return {
            "valid": True,
            "adjusted": float(amount),
            "message": "Amount is valid",
            "original": amount,
        }

    @classmethod
    def get_valid_amounts(cls, biller_id: int) -> List[float]:
        limits = cls.get_biller_limits(biller_id)
        return limits.get("valid_amounts", [])


# ============ SUPPORTED CURRENCIES CONFIGURATION ============
# Stripe currencies with no minor unit: amounts are whole units, NOT cents. Used both when creating a
# checkout session and when verifying what was paid (dividing these by 100 would under-report 100x).
STRIPE_ZERO_DECIMAL = {
    "bif", "clp", "djf", "gnf", "jpy", "kmf", "krw", "mga",
    "pyg", "rwf", "ugx", "vnd", "vuv", "xaf", "xof", "xpf",
}

SUPPORTED_CURRENCIES = {
    # ── Local / primary ──────────────────────────────────────────────
    "NGN": {"name": "Nigerian Naira",   "symbol": "₦",   "gateway": "paystack",    "min_amount": 100,  "step": 100, "is_local": True,  "country": "NG", "decimals": 2},
    "USD": {"name": "US Dollar",        "symbol": "$",   "gateway": "stripe",      "min_amount": 1,    "step": 1,   "is_local": False, "country": "US", "decimals": 2},
    "GBP": {"name": "Pound Sterling",   "symbol": "£",   "gateway": "stripe",      "min_amount": 1,    "step": 1,   "is_local": False, "country": "GB", "decimals": 2},
    "EUR": {"name": "Euro",             "symbol": "€",   "gateway": "stripe",      "min_amount": 1,    "step": 1,   "is_local": False, "country": "EU", "decimals": 2},

    # ── Americas ─────────────────────────────────────────────────────
    "CAD": {"name": "Canadian Dollar",  "symbol": "CA$", "gateway": "stripe",      "min_amount": 1,    "step": 1,   "is_local": False, "country": "CA", "decimals": 2},

    # ── Asia-Pacific ─────────────────────────────────────────────────
    "AUD": {"name": "Australian Dollar","symbol": "A$",  "gateway": "stripe",      "min_amount": 1,    "step": 1,   "is_local": False, "country": "AU", "decimals": 2},
    "NZD": {"name": "New Zealand Dollar","symbol": "NZ$","gateway": "stripe",      "min_amount": 1,    "step": 1,   "is_local": False, "country": "NZ", "decimals": 2},
    "CNY": {"name": "Chinese Yuan",     "symbol": "CN¥", "gateway": "stripe",      "min_amount": 10,   "step": 5,   "is_local": False, "country": "CN", "decimals": 2},
    "VND": {"name": "Vietnamese Dong",  "symbol": "₫",   "gateway": "stripe",      "min_amount": 20000,"step": 5000,"is_local": False, "country": "VN", "decimals": 0},
    "INR": {"name": "Indian Rupee",     "symbol": "₹",   "gateway": "stripe",      "min_amount": 50,   "step": 10,  "is_local": False, "country": "IN", "decimals": 2},
    "PKR": {"name": "Pakistani Rupee",  "symbol": "₨",   "gateway": "stripe",      "min_amount": 200,  "step": 50,  "is_local": False, "country": "PK", "decimals": 2},
    "BDT": {"name": "Bangladeshi Taka", "symbol": "৳",   "gateway": "stripe",      "min_amount": 100,  "step": 50,  "is_local": False, "country": "BD", "decimals": 2},

    # ── Middle East / North Africa ───────────────────────────────────

    # ── Africa (Flutterwave territory) ───────────────────────────────
    "GHS": {"name": "Ghanaian Cedi",    "symbol": "₵",   "gateway": "flutterwave", "min_amount": 5,    "step": 1,   "is_local": False, "country": "GH", "decimals": 2},
    "KES": {"name": "Kenyan Shilling",  "symbol": "KSh", "gateway": "flutterwave", "min_amount": 100,  "step": 50,  "is_local": False, "country": "KE", "decimals": 2},
    "ZAR": {"name": "South African Rand","symbol": "R",  "gateway": "stripe",      "min_amount": 20,   "step": 10,  "is_local": False, "country": "ZA", "decimals": 2},
    "UGX": {"name": "Ugandan Shilling", "symbol": "USh", "gateway": "flutterwave", "min_amount": 3000, "step": 1000,"is_local": False, "country": "UG", "decimals": 0},
    "TZS": {"name": "Tanzanian Shilling","symbol": "TSh","gateway": "flutterwave", "min_amount": 2000, "step": 1000,"is_local": False, "country": "TZ", "decimals": 0},
    # ── Asia-Pacific ────────────────────────────────────────────────
    "JPY": {"name": "Japanese Yen",     "symbol": "¥",    "gateway": "stripe", "min_amount": 100,   "step": 50,   "is_local": False, "country": "JP", "decimals": 0},
    "SGD": {"name": "Singapore Dollar",  "symbol": "S$",   "gateway": "stripe", "min_amount": 2,     "step": 1,    "is_local": False, "country": "SG", "decimals": 2},
    "HKD": {"name": "Hong Kong Dollar",  "symbol": "HK$",  "gateway": "stripe", "min_amount": 10,    "step": 5,    "is_local": False, "country": "HK", "decimals": 2},
    "MYR": {"name": "Malaysian Ringgit", "symbol": "RM",   "gateway": "stripe", "min_amount": 5,     "step": 1,    "is_local": False, "country": "MY", "decimals": 2},
    "THB": {"name": "Thai Baht",         "symbol": "฿",    "gateway": "stripe", "min_amount": 30,    "step": 10,   "is_local": False, "country": "TH", "decimals": 2},
    "IDR": {"name": "Indonesian Rupiah", "symbol": "Rp",   "gateway": "stripe", "min_amount": 15000, "step": 5000, "is_local": False, "country": "ID", "decimals": 0},
    "PHP": {"name": "Philippine Peso",   "symbol": "₱",    "gateway": "stripe", "min_amount": 50,    "step": 10,   "is_local": False, "country": "PH", "decimals": 2},
    "KRW": {"name": "South Korean Won",  "symbol": "₩",    "gateway": "stripe", "min_amount": 1000,  "step": 500,  "is_local": False, "country": "KR", "decimals": 0},

    # ── Middle East ─────────────────────────────────────────────────
    "AED": {"name": "UAE Dirham",       "symbol": "د.إ",  "gateway": "stripe", "min_amount": 5,     "step": 1,    "is_local": False, "country": "AE", "decimals": 2},
    "SAR": {"name": "Saudi Riyal",      "symbol": "﷼",    "gateway": "stripe", "min_amount": 5,     "step": 1,    "is_local": False, "country": "SA", "decimals": 2},
    "QAR": {"name": "Qatari Riyal",     "symbol": "ر.ق",  "gateway": "stripe", "min_amount": 5,     "step": 1,    "is_local": False, "country": "QA", "decimals": 2},
    "KWD": {"name": "Kuwaiti Dinar",    "symbol": "د.ك",  "gateway": "stripe", "min_amount": 2,     "step": 1,    "is_local": False, "country": "KW", "decimals": 3},
    "BHD": {"name": "Bahraini Dinar",   "symbol": "ب.د",  "gateway": "stripe", "min_amount": 2,     "step": 1,    "is_local": False, "country": "BH", "decimals": 3},
    "OMR": {"name": "Omani Rial",       "symbol": "ر.ع",  "gateway": "stripe", "min_amount": 2,     "step": 1,    "is_local": False, "country": "OM", "decimals": 3},
    "ILS": {"name": "Israeli Shekel",   "symbol": "₪",    "gateway": "stripe", "min_amount": 5,     "step": 1,    "is_local": False, "country": "IL", "decimals": 2},
    "TRY": {"name": "Turkish Lira",     "symbol": "₺",    "gateway": "stripe", "min_amount": 20,    "step": 10,   "is_local": False, "country": "TR", "decimals": 2},
    "EGP": {"name": "Egyptian Pound",   "symbol": "E£",   "gateway": "stripe", "min_amount": 30,    "step": 10,   "is_local": False, "country": "EG", "decimals": 2},

    # ── Latin America ───────────────────────────────────────────────
    "BRL": {"name": "Brazilian Real",   "symbol": "R$",   "gateway": "stripe", "min_amount": 5,     "step": 1,    "is_local": False, "country": "BR", "decimals": 2},
    "MXN": {"name": "Mexican Peso",     "symbol": "MX$",  "gateway": "stripe", "min_amount": 20,    "step": 10,   "is_local": False, "country": "MX", "decimals": 2},
    "ARS": {"name": "Argentine Peso",   "symbol": "AR$",  "gateway": "stripe", "min_amount": 100,   "step": 50,   "is_local": False, "country": "AR", "decimals": 2},
    "CLP": {"name": "Chilean Peso",     "symbol": "CL$",  "gateway": "stripe", "min_amount": 500,   "step": 100,  "is_local": False, "country": "CL", "decimals": 0},
    "COP": {"name": "Colombian Peso",   "symbol": "CO$",  "gateway": "stripe", "min_amount": 3000,  "step": 1000, "is_local": False, "country": "CO", "decimals": 2},
    "PEN": {"name": "Peruvian Sol",     "symbol": "S/",   "gateway": "stripe", "min_amount": 5,     "step": 1,    "is_local": False, "country": "PE", "decimals": 2},

    # ── Other currencies already referenced ─────────────────────────
    "CHF": {"name": "Swiss Franc",      "symbol": "CHF",  "gateway": "stripe", "min_amount": 1,     "step": 1,    "is_local": False, "country": "CH", "decimals": 2},
    "SEK": {"name": "Swedish Krona",    "symbol": "kr",   "gateway": "stripe", "min_amount": 10,    "step": 1,    "is_local": False, "country": "SE", "decimals": 2},
    "NOK": {"name": "Norwegian Krone",  "symbol": "kr",   "gateway": "stripe", "min_amount": 10,    "step": 1,    "is_local": False, "country": "NO", "decimals": 2},
    "DKK": {"name": "Danish Krone",     "symbol": "kr",   "gateway": "stripe", "min_amount": 10,    "step": 1,    "is_local": False, "country": "DK", "decimals": 2},
    "PLN": {"name": "Polish Zloty",     "symbol": "zł",   "gateway": "stripe", "min_amount": 5,     "step": 1,    "is_local": False, "country": "PL", "decimals": 2},
}

# ============================================================
# COUNTRY_CURRENCY_MAP — mirrors the frontend's GATEWAY_CONFIG
# country -> currency mapping. Used by /api/payment/init to reject a
# currency that doesn't match the recharge's destination country
# (e.g. NGN for a US topup), which is what let a ₦5.13 payment intent
# get created for a US recharge and crash deep inside
# _finalize_transaction trying to convert it to USD.
# ============================================================
COUNTRY_CURRENCY_MAP = {
    "NG": "NGN", "GH": "GHS", "KE": "KES", "ZA": "ZAR", "UG": "UGX", "TZ": "TZS",
    "US": "USD", "CA": "CAD",
    "GB": "GBP", "EU": "EUR", "FR": "EUR", "DE": "EUR", "IT": "EUR", "ES": "EUR",
    "NL": "EUR", "BE": "EUR", "AT": "EUR", "IE": "EUR", "PT": "EUR", "FI": "EUR", "GR": "EUR",
    "CH": "CHF", "SE": "SEK", "NO": "NOK", "DK": "DKK", "PL": "PLN",
    "AU": "AUD", "NZ": "NZD", "JP": "JPY", "CN": "CNY", "HK": "HKD", "SG": "SGD",
    "MY": "MYR", "TH": "THB", "ID": "IDR", "PH": "PHP", "IN": "INR", "KR": "KRW",
    "AE": "AED", "SA": "SAR", "QA": "QAR", "KW": "KWD", "BH": "BHD", "OM": "OMR",
    "IL": "ILS", "TR": "TRY", "EG": "EGP",
    "BR": "BRL", "MX": "MXN", "AR": "ARS", "CL": "CLP", "CO": "COP", "PE": "PEN",
}

# ============ SANDBOX FALLBACK OPERATORS ============
# Reloadly's sandbox endpoint rejects real phone numbers on /operators/auto-detect
# (returns HTTP 400), which means the frontend can't resolve an operator_id and
# the downstream top-up fails with "Missing operator_id or phone".
#
# This used to be a hardcoded table of per-country operator IDs here. The
# problem: they were guesses (only NG was ever confirmed against a real
# Reloadly sandbox dashboard), and a wrong ID fails silently downstream
# rather than loudly — it just sends a test top-up to the wrong operator.
#
# Replaced by ReloadlyPlatform._sandbox_operator_fallback(), which asks
# Reloadly's own /operators/countries/{code} endpoint which operators
# genuinely exist for a country (that endpoint returns real data even in
# sandbox) and uses one of them. No hardcoded IDs, nothing to verify by
# hand, and it covers every country Reloadly supports automatically.

# ============ ENCRYPTION SETUP ============

# ============================================================
# NETWORK NORMALIZATION
# ============================================================
# Maps whatever a customer typed (case-insensitive, allowing common
# misspellings and legacy names) to a single canonical network name.
# Contact records always store the canonical form, so downstream code
# has exactly one value to match against.
NETWORK_ALIASES = {
    # MTN
    "mtn": "MTN",
    "mtn nigeria": "MTN",
    "mtn ng": "MTN",
    # Glo
    "glo": "Glo",
    "glo nigeria": "Glo",
    "globacom": "Glo",
    # Airtel
    "airtel": "Airtel",
    "airtel nigeria": "Airtel",
    "airtel ng": "Airtel",
    "zain": "Airtel",       # legacy name
    "celtel": "Airtel",     # legacy name
    # 9mobile
    "9mobile": "9mobile",
    "9 mobile": "9mobile",
    "9mob": "9mobile",
    "etisalat": "9mobile",  # legacy name
}

def normalize_network(raw: str) -> str:
    """Turn a customer-supplied network string into a canonical name.

    Returns "" if the input is empty or unrecognized, so callers can
    distinguish "no network given" from a real value.
    """
    if not raw:
        return ""
    key = str(raw).strip().lower()
    # Collapse multiple spaces so "MTN  Nigeria" becomes "mtn nigeria"
    key = " ".join(key.split())
    return NETWORK_ALIASES.get(key, "")


try:
    from cryptography.fernet import Fernet

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    print("WARNING: cryptography not installed. PII will be stored in plaintext!")

# (Encryption key setup lives near the top of this file; not repeated here.)

def encrypt_pii(data: str) -> str:
    if not data or not cipher:
        return data
    try:
        return cipher.encrypt(data.encode()).decode()
    except Exception:
        logger.error("encrypt_pii failed; value NOT encrypted", exc_info=True)
        return data


def decrypt_pii(data: str) -> str:
    if not data or not cipher:
        return data
    try:
        return cipher.decrypt(data.encode()).decode()
    except Exception:
        # Plaintext rows saved before a key existed land here too; only warn.
        logger.warning("decrypt_pii: value could not be decrypted (plaintext or wrong key)")
        return data


def decrypt_payload(payload: Dict) -> Dict:
    if not payload:
        return payload
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except:
            return payload
    for field in ["phone", "email", "subscriber_account"]:
        if field in payload and payload[field]:
            try:
                decrypted = decrypt_pii(payload[field])
                if decrypted != payload[field]:
                    payload[field] = decrypted
            except Exception:
                pass
    return payload


# ============ PASSWORD HASHING ============
# Password hashing lives in database.py (single source of truth — see
# database.hash_password / database.verify_password). Removed the separate,
# never-called bcrypt implementation that used to live here to avoid two
# independent hashing schemes drifting apart in the same codebase.

# ============ SECURITY HELPERS ============
# ============ EMAIL VERIFICATION TOGGLE ============
# Set to True to require users to verify their email (via OTP) before funding wallets,
# making payments, or creating schedules. Set to False to disable this requirement
# entirely — useful during testing, or if you're not ready to enforce it yet.
# Can also be controlled via environment variable without touching this file:
#   EMAIL_VERIFICATION_REQUIRED=true   (enable)
#   EMAIL_VERIFICATION_REQUIRED=false  (disable, or just leave it unset)
EMAIL_VERIFICATION_REQUIRED = (
    os.getenv("EMAIL_VERIFICATION_REQUIRED", "false").lower() == "true"
)

# ============ SMS PROVIDER CONFIG (Business page) ============
# No SMS provider is wired up yet. Set ONE of these provider's credentials as environment
# variables to enable real sending, then implement the matching branch in
# send_sms_via_provider() below:
#   Termii:          TERMII_API_KEY
#   Twilio:          TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER
#   Africa's Talking: AFRICASTALKING_API_KEY, AFRICASTALKING_USERNAME
SMS_PROVIDER_NAME = None
if os.getenv("TERMII_API_KEY"):
    SMS_PROVIDER_NAME = "termii"
elif os.getenv("TWILIO_ACCOUNT_SID") and os.getenv("TWILIO_AUTH_TOKEN"):
    SMS_PROVIDER_NAME = "twilio"
elif os.getenv("AFRICASTALKING_API_KEY"):
    SMS_PROVIDER_NAME = "africastalking"
SMS_PROVIDER_CONFIGURED = SMS_PROVIDER_NAME is not None


def send_sms_via_provider(contacts: list, message: str, sender_id: str) -> Dict:
    """Dispatch SMS via whichever provider is configured (checked at startup from env vars)."""
    if not contacts:
        return {
            "sent": 0,
            "failed": 0,
            "provider": SMS_PROVIDER_NAME,
            "note": "No contacts to send to",
        }
    if SMS_PROVIDER_NAME == "termii":
        return _send_sms_termii(contacts, message, sender_id)
    elif SMS_PROVIDER_NAME == "twilio":
        return _send_sms_twilio(contacts, message, sender_id)
    elif SMS_PROVIDER_NAME == "africastalking":
        return _send_sms_africastalking(contacts, message, sender_id)
    return {
        "sent": 0,
        "failed": len(contacts),
        "provider": None,
        "note": "No SMS provider configured",
    }


def _send_sms_termii(contacts: list, message: str, sender_id: str) -> Dict:
    api_key = os.getenv("TERMII_API_KEY")
    try:
        resp = requests.post(
            "https://api.ng.termii.com/api/sms/send/bulk",
            json={
                "api_key": api_key,
                "to": contacts,
                "from": sender_id,
                "sms": message,
                "type": "plain",
                "channel": "generic",
            },
            timeout=30,
        )
        data = resp.json() if resp.content else {}
        if resp.status_code == 200 and data.get("message_id"):
            return {
                "sent": len(contacts),
                "failed": 0,
                "provider": "termii",
                "message_id": data.get("message_id"),
            }
        return {
            "sent": 0,
            "failed": len(contacts),
            "provider": "termii",
            "errors": [data.get("message", f"HTTP {resp.status_code}")],
        }
    except Exception as e:
        logger.error(f"Termii SMS dispatch failed: {e}")
        return {
            "sent": 0,
            "failed": len(contacts),
            "provider": "termii",
            "errors": [str(e)],
        }


def _send_sms_twilio(contacts: list, message: str, sender_id: str) -> Dict:
    sid = os.getenv("TWILIO_ACCOUNT_SID")
    token = os.getenv("TWILIO_AUTH_TOKEN")
    from_number = os.getenv("TWILIO_FROM_NUMBER")
    sent, failed, errors = 0, 0, []
    # Twilio has no native bulk-send endpoint — one API call per recipient.
    for number in contacts:
        try:
            resp = requests.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
                data={"To": number, "From": from_number, "Body": message},
                auth=(sid, token),
                timeout=15,
            )
            if resp.status_code in (200, 201):
                sent += 1
            else:
                failed += 1
                errors.append(f"{number}: HTTP {resp.status_code}")
        except Exception as e:
            failed += 1
            errors.append(f"{number}: {str(e)}")
    return {"sent": sent, "failed": failed, "provider": "twilio", "errors": errors[:10]}


def _send_sms_africastalking(contacts: list, message: str, sender_id: str) -> Dict:
    api_key = os.getenv("AFRICASTALKING_API_KEY")
    username = os.getenv("AFRICASTALKING_USERNAME")
    try:
        resp = requests.post(
            "https://api.africastalking.com/version1/messaging",
            data={
                "username": username,
                "to": ",".join(contacts),
                "message": message,
                "from": sender_id,
            },
            headers={"apiKey": api_key, "Accept": "application/json"},
            timeout=30,
        )
        data = resp.json() if resp.content else {}
        recipients = (data.get("SMSMessageData") or {}).get("Recipients", [])
        sent = sum(
            1
            for r in recipients
            if str(r.get("status", "")).lower().startswith("success")
        )
        failed = len(recipients) - sent
        errors = [
            f"{r.get('number')}: {r.get('status')}"
            for r in recipients
            if not str(r.get("status", "")).lower().startswith("success")
        ]
        if not recipients:
            return {
                "sent": 0,
                "failed": len(contacts),
                "provider": "africastalking",
                "errors": ["No recipients in provider response"],
            }
        return {
            "sent": sent,
            "failed": failed,
            "provider": "africastalking",
            "errors": errors[:10],
        }
    except Exception as e:
        logger.error(f"Africa's Talking SMS dispatch failed: {e}")
        return {
            "sent": 0,
            "failed": len(contacts),
            "provider": "africastalking",
            "errors": [str(e)],
        }


ADMIN_SECRET = os.getenv("ADMIN_SECRET", "")
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "net365_session")
# Secure cookies are ON by default whenever the site is served over HTTPS (any https:// PUBLIC_URL
# or FRONTEND_URL, which is what Railway uses). Set SESSION_COOKIE_SECURE=false only for plain-http
# local development.
_scs_raw = os.getenv("SESSION_COOKIE_SECURE", "").strip().lower()
if _scs_raw:
    SESSION_COOKIE_SECURE = _scs_raw in ("1", "true", "yes", "on")
else:
    SESSION_COOKIE_SECURE = any(
        (os.getenv(_k, "") or "").lower().startswith("https://")
        for _k in ("PUBLIC_URL", "FRONTEND_URL")
    )

# ---- Soft-launch safety switches -------------------------------------------------------------
# WALLET_ENABLED=false  -> no wallet funding, wallet payments, wallet utilities, bulk/scheduled wallet
#                          spending. Customers pay per purchase through a licensed payment provider.
# WALLET_TRANSFERS_ENABLED stays false until the regulatory position is confirmed.
def _env_flag(name, default):
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")

WALLET_ENABLED = _env_flag("WALLET_ENABLED", False)   # fail-safe: off unless explicitly enabled
WALLET_TRANSFERS_ENABLED = _env_flag("WALLET_TRANSFERS_ENABLED", False)

# Per-user spending caps, in NGN (0 disables a cap). Defaults suit a small soft launch.
LIMIT_PER_TX_NGN = float(os.getenv("LIMIT_PER_TX_NGN", "20000"))
LIMIT_DAILY_NGN = float(os.getenv("LIMIT_DAILY_NGN", "50000"))


def validate_password_strength(password):
    """Server-side password policy. Returns an error string, or None if the password is acceptable."""
    if not isinstance(password, str) or not password:
        return "Password is required"
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if len(password) > 128:
        return "Password must be 128 characters or fewer"
    if password.strip() == "" or password.lower() in {
        "password", "password1", "12345678", "123456789", "qwertyui", "11111111", "iloveyou",
    }:
        return "That password is too easy to guess. Please choose another."
    return None
SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
SESSION_COOKIE_MAX_AGE = int(os.getenv("SESSION_COOKIE_MAX_AGE", str(60 * 60 * 24 * 7)))
# Optional parent-domain cookie for deployments where the authenticated app and
# payment-return endpoint live on different Net365 subdomains. Leave blank for
# localhost/single-origin deployments.
SESSION_COOKIE_DOMAIN = os.getenv("SESSION_COOKIE_DOMAIN", "").strip() or None
# ============ FEATURE FLAGS ============
# Referral bonuses are OFF by default during the soft launch. Turn on by
# setting REFERRAL_BONUS_ENABLED=true in your .env file (or your hosting
# environment) once you're ready to run the program.
def is_referral_bonus_enabled() -> bool:
    """Read the env switch fresh every time (same rule as database.process_pending_referrals)."""
    return os.getenv("REFERRAL_BONUS_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")


REFERRAL_BONUS_ENABLED = (
    os.getenv("REFERRAL_BONUS_ENABLED", "false").lower() == "true"
)

logger = logging.getLogger(__name__)

wallet_transfer_lock = threading.Lock()
_finalize_lock = threading.Lock()

try:
    from config import ReloadlyCredentials, Environment
except ImportError:

    class Environment(Enum):
        SANDBOX = "sandbox"
        LIVE = "live"

    @dataclass
    class ReloadlyCredentials:
        client_id: str
        client_secret: str
        environment: Environment
        base_url: str = ""
        auth_url: str = ""
        audience: str = ""

        @classmethod
        def from_env(cls):
            env = os.getenv("RELOADLY_ENVIRONMENT", "sandbox").lower()
            environment = Environment.SANDBOX if env == "sandbox" else Environment.LIVE

            client_id = os.getenv("RELOADLY_CLIENT_ID", "").strip()
            client_secret = os.getenv("RELOADLY_CLIENT_SECRET", "").strip()

            if environment == Environment.SANDBOX:
                base_url = "https://topups-sandbox.reloadly.com"
                auth_url = "https://auth.reloadly.com/oauth/token"
                audience = "https://topups-sandbox.reloadly.com"
            else:
                base_url = "https://topups.reloadly.com"
                auth_url = "https://auth.reloadly.com/oauth/token"
                audience = "https://topups.reloadly.com"

            return cls(
                client_id=client_id,
                client_secret=client_secret,
                environment=environment,
                base_url=base_url,
                auth_url=auth_url,
                audience=audience,
            )


DEFAULT_RETURN_URL = os.getenv(
    "DEFAULT_RETURN_URL", "http://127.0.0.1:5557/payment/success"
).rstrip("/")
PUBLIC_URL = os.getenv("PUBLIC_URL", "").rstrip("/")
PAYMENT_SERVICE_URL = os.getenv(
    "PAYMENT_SERVICE_URL", PUBLIC_URL or "http://127.0.0.1:5557"
).rstrip("/")
FRONTEND_URL = os.getenv("FRONTEND_URL", PAYMENT_SERVICE_URL).rstrip("/")

# Payment returns must land on the same canonical customer origin that owns the
# Net365 authentication cookie. This prevents the common "payment succeeded,
# then user appears logged out" experience caused by crossing hosts/subdomains.
PAYMENT_RETURN_URL = f"{FRONTEND_URL}/payment/success"

def _safe_payment_return_url(candidate=None):
    """Return a safe, same-origin Net365 payment return URL.

    We intentionally do not accept arbitrary redirect destinations from the
    browser. A customer may return from a payment provider, but the final
    destination remains the configured Net365 frontend origin.
    """
    configured = PAYMENT_RETURN_URL
    if not FRONTEND_URL:
        # No FRONTEND_URL configured: a relative URL is useless to a payment
        # gateway, so fall back to this request's own origin.
        try:
            configured = request.host_url.rstrip("/") + "/payment/success"
        except Exception:
            pass
        return configured
    if not candidate:
        return configured
    try:
        wanted = urlsplit(candidate)
        allowed = urlsplit(FRONTEND_URL)
        if (wanted.scheme, wanted.netloc) == (allowed.scheme, allowed.netloc):
            path = wanted.path or "/payment/success"
            if path == "/payment/success":
                return urlunsplit((allowed.scheme, allowed.netloc, path, wanted.query, ""))
    except Exception:
        pass
    return configured

try:
    import stripe

    STRIPE_AVAILABLE = True
    print("✅ Stripe library loaded successfully")
except ImportError:
    STRIPE_AVAILABLE = False
    logger.warning("Stripe library not installed. Install with: pip install stripe")

try:
    from authlib.integrations.flask_client import OAuth

    AUTH_LIB_AVAILABLE = True
except ImportError:
    AUTH_LIB_AVAILABLE = False
    logger.warning("Authlib not installed. Google OAuth disabled.")


def generate_reference(prefix: str = "PSK") -> str:
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    unique_id = str(uuid.uuid4())[:8].upper()
    return f"{prefix}_{timestamp}_{unique_id}"


# ============ SANDBOX AMOUNT ADAPTER ============
class SandboxAmountAdapter:
    BILLER_AMOUNT_MAP = {
        49: {
            "valid_amounts": [50, 100, 200, 500, 1000, 2000, 5000],
            "min": 50,
            "max": 5000,
            "default": 200,
            "name": "MTN Nigeria",
        },
        50: {
            "valid_amounts": [50, 100, 200, 500, 1000, 2000, 5000],
            "min": 50,
            "max": 5000,
            "default": 200,
            "name": "Glo Nigeria",
        },
        51: {
            "valid_amounts": [50, 100, 200, 500, 1000, 2000, 5000],
            "min": 50,
            "max": 5000,
            "default": 200,
            "name": "Airtel Nigeria",
        },
        52: {
            "valid_amounts": [50, 100, 200, 500, 1000, 2000, 5000],
            "min": 50,
            "max": 5000,
            "default": 200,
            "name": "9mobile Nigeria",
        },
    }
    DEFAULT_VALID_AMOUNTS = [100, 200, 500, 1000, 2000, 5000]
    DEFAULT_MIN = 100
    DEFAULT_MAX = 5000
    DEFAULT_AMOUNT = 500

    @classmethod
    def get_biller_config(cls, biller_id: int) -> Dict:
        return cls.BILLER_AMOUNT_MAP.get(
            biller_id,
            {
                "valid_amounts": cls.DEFAULT_VALID_AMOUNTS,
                "min": cls.DEFAULT_MIN,
                "max": cls.DEFAULT_MAX,
                "default": cls.DEFAULT_AMOUNT,
                "name": f"Unknown Biller {biller_id}",
            },
        )

    @classmethod
    def adjust_amount(cls, biller_id: int, requested_amount: float) -> float:
        config = cls.get_biller_config(biller_id)
        valid_amounts = config["valid_amounts"]
        min_amount = config["min"]
        max_amount = config["max"]
        default_amount = config["default"]

        if requested_amount < min_amount:
            return float(min_amount)
        if requested_amount > max_amount:
            return float(max_amount)

        closest_amount = min(valid_amounts, key=lambda x: abs(x - requested_amount))
        if requested_amount > 0:
            diff_percentage = (
                abs(closest_amount - requested_amount) / requested_amount * 100
            )
            if diff_percentage > 20:
                return float(default_amount)
        return float(closest_amount)

    @classmethod
    def get_mock_biller_details(cls, biller_id: int) -> Dict:
        config = cls.get_biller_config(biller_id)
        return {
            "id": biller_id,
            "billerId": biller_id,
            "name": config["name"],
            "minAmount": config["min"],
            "maxAmount": config["max"],
            "defaultAmount": config["default"],
            "validAmounts": config["valid_amounts"],
            "isSandbox": True,
            "type": "UTILITY",
            "countryISOCode": "NG",
        }


# ============ RELOADLY API CLIENT ============
class ReloadlyAPI:
    def __init__(self, credentials: ReloadlyCredentials):
        self.credentials = credentials
        self.token = None
        self.token_expiry = None
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "Reloadly-Python-Client/1.0", "Accept": "application/json"}
        )
        self._lock = threading.Lock()

    def authenticate(self) -> str:
        url = self.credentials.auth_url
        payload = {
            "client_id": self.credentials.client_id,
            "client_secret": self.credentials.client_secret,
            "grant_type": "client_credentials",
            "audience": self.credentials.audience,
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        try:
            logger.info(f"Authenticating with Reloadly...")
            response = self.session.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            self.token = data["access_token"]
            expires_in = data.get("expires_in", 3600) - 300
            self.token_expiry = datetime.now() + timedelta(seconds=max(expires_in, 60))
            logger.info(f"Token acquired, expires at {self.token_expiry}")
            return self.token
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            raise

    def get_token(self) -> str:
        with self._lock:
            if (
                not self.token
                or not self.token_expiry
                or datetime.now() >= self.token_expiry
            ):
                self.authenticate()
            return self.token

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict:
        max_retries = 3

        for attempt in range(max_retries):
            try:
                token = self.get_token()
                url = f"{self.credentials.base_url}{endpoint}"

                headers = {
                    "Accept": "application/com.reloadly.topups-v1+json",
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "Reloadly-Python-Client/1.0",
                }
                if "headers" in kwargs:
                    headers.update(kwargs.pop("headers"))

                kwargs.setdefault("timeout", 20)  # never hang a worker on Reloadly
                response = self.session.request(method, url, headers=headers, **kwargs)

                if response.status_code == 401:
                    logger.warning(
                        f"Token expired on attempt {attempt + 1}, refreshing..."
                    )
                    self.token = None
                    self.token_expiry = None
                    continue

                response.raise_for_status()

                if response.status_code == 204:
                    return {}

                return response.json()

            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    logger.error(
                        f"API request failed after {max_retries} attempts: {str(e)}"
                    )
                    raise
                logger.warning(
                    f"Request failed (attempt {attempt + 1}): {str(e)}, retrying..."
                )
                time.sleep(1)

        raise Exception("Max retries exceeded")


# ============ RELOADLY UTILITIES API ============
class ReloadlyUtilitiesAPI:
    def __init__(self, credentials: ReloadlyCredentials):
        self.credentials = credentials
        if credentials.environment == Environment.SANDBOX:
            self.utilities_base_url = "https://utilities-sandbox.reloadly.com"
            self.utilities_audience = "https://utilities-sandbox.reloadly.com"
        else:
            self.utilities_base_url = "https://utilities.reloadly.com"
            self.utilities_audience = "https://utilities.reloadly.com"
        self.utilities_token = None
        self.utilities_token_expiry = None
        self.session = requests.Session()
        self._biller_cache = (
            {}
        )  # biller_id (str) -> raw Reloadly biller record, populated by get_billers()
        self.session.headers.update(
            {"User-Agent": "Reloadly-Python-Client/1.0", "Accept": "application/json"}
        )
        self._lock = threading.Lock()

    def authenticate_utilities(self) -> str:
        url = self.credentials.auth_url
        payload = {
            "client_id": self.credentials.client_id,
            "client_secret": self.credentials.client_secret,
            "grant_type": "client_credentials",
            "audience": self.utilities_audience,
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        try:
            logger.info(
                f"Authenticating Utilities API with audience {self.utilities_audience}..."
            )
            response = self.session.post(url, json=payload, headers=headers, timeout=30)

            if response.status_code != 200:
                logger.error(f"Utilities authentication failed: {response.status_code}")
                logger.error(f"Response: {response.text[:500]}")
                response.raise_for_status()

            data = response.json()
            self.utilities_token = data["access_token"]
            expires_in = data.get("expires_in", 3600) - 300
            self.utilities_token_expiry = datetime.now() + timedelta(
                seconds=max(expires_in, 60)
            )
            logger.info(
                f"Successfully authenticated Utilities API, expires at {self.utilities_token_expiry}"
            )
            return self.utilities_token

        except requests.exceptions.RequestException as e:
            logger.error(f"Utilities authentication failed: {str(e)}")
            if hasattr(e, "response") and e.response is not None:
                logger.error(f"Status: {e.response.status_code}")
                logger.error(f"Response: {e.response.text[:500]}")
            raise

    def get_utilities_token(self) -> str:
        with self._lock:
            if (
                not self.utilities_token
                or not self.utilities_token_expiry
                or datetime.now() >= self.utilities_token_expiry
            ):
                logger.info("Utilities token expired or missing. Refreshing...")
                self.authenticate_utilities()
            return self.utilities_token

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict:
        max_retries = 3

        for attempt in range(max_retries):
            try:
                token = self.get_utilities_token()
                url = f"{self.utilities_base_url}{endpoint}"

                headers = {
                    "Accept": "application/com.reloadly.utilities-v1+json",
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "Reloadly-Python-Client/1.0",
                }
                if "headers" in kwargs:
                    headers.update(kwargs.pop("headers"))

                kwargs.setdefault("timeout", 20)  # never hang a worker on Reloadly
                response = self.session.request(method, url, headers=headers, **kwargs)

                if response.status_code == 401:
                    logger.warning(
                        f"Utilities token expired on attempt {attempt + 1}, refreshing..."
                    )
                    self.utilities_token = None
                    self.utilities_token_expiry = None
                    continue

                response.raise_for_status()

                if response.status_code == 204:
                    return {}

                return response.json()

            except requests.exceptions.RequestException as e:
                status_code = None
                if hasattr(e, "response") and e.response is not None:
                    status_code = e.response.status_code
                    logger.error(f"Utilities API status: {status_code}")
                    try:
                        error_details = e.response.json()
                        logger.error(
                            f"Reloadly Utilities Error Details: {json.dumps(error_details, indent=2)}"
                        )
                    except Exception:
                        logger.error(f"Response body: {e.response.text[:500]}")

                if status_code is not None and 400 <= status_code < 500:
                    raise

                if attempt == max_retries - 1:
                    logger.error(
                        f"Utilities API request failed after {max_retries} attempts: {str(e)}"
                    )
                    raise

                logger.warning(
                    f"Utilities request failed (attempt {attempt + 1}): {str(e)}, retrying..."
                )
                time.sleep(1)

        raise Exception("Max retries exceeded")

    def get_billers(
        self,
        biller_id=None,
        name=None,
        biller_type=None,
        service_type=None,
        country_iso_code=None,
        page: int = 1,
        size: int = 10,
    ) -> List[Dict]:
        params = {"page": page, "size": size}
        if biller_id:
            params["id"] = biller_id
        if name:
            params["name"] = name
        if biller_type:
            params["billerType"] = biller_type
        if service_type:
            params["serviceType"] = service_type
        if country_iso_code:
            params["countryISOCode"] = country_iso_code
        try:
            result = self._make_request("GET", "/billers", params=params)
            content = (
                result["content"]
                if isinstance(result, dict) and "content" in result
                else result
            )
            if isinstance(content, list):
                for b in content:
                    if isinstance(b, dict):
                        bid = b.get("billerId") or b.get("id") or b.get("biller_id")
                        if bid:
                            self._biller_cache[str(bid)] = b
            return content
        except Exception as e:
            logger.error(f"Error fetching billers: {e}")
            return []

    def get_biller_by_id(self, biller_id: int) -> Dict:
        # Prefer a record we already have from a successful list call — GET /billers/{id}
        # has 404'd for every biller ID tried so far in sandbox (5, 9, 501), even ones
        # that came straight from a working list response, so falling straight to the
        # cache avoids a doomed round-trip and, when available, gives us real data
        # instead of the hardcoded SandboxAmountAdapter guess.
        cached = self._biller_cache.get(str(biller_id))
        if cached:
            return cached
        try:
            result = self._make_request("GET", f"/billers/{biller_id}")
            if isinstance(result, dict) and "content" in result and result["content"]:
                return result["content"][0]
            return result
        except Exception as e:
            logger.warning(
                f"Could not fetch real biller {biller_id} from Reloadly ({e}); using local fallback data"
            )
            return SandboxAmountAdapter.get_mock_biller_details(biller_id)

    def pay_bill(
        self,
        biller_id: int,
        subscriber_account: str,
        amount: float,
        reference_id: str,
        use_local_amount: bool = True,
        additional_info: Optional[Dict] = None,
        amount_id: Optional[int] = None,
    ) -> Dict:
        import uuid

        clean_account = str(subscriber_account).strip()

        # FIX: Truncate reference_id to max 36 characters for Reloadly
        if len(reference_id) > 36:
            reference_id = reference_id[:36]
            logger.warning(f"Truncated reference_id to 36 chars: {reference_id}")

        def fresh_reference() -> str:
            # Reloadly rejects a reference it has already seen (REFERENCE_ID_ALREADY_USED),
            # even for an attempt that itself failed. Every retry needs its own reference.
            base = reference_id[:26]
            return f"{base}-{uuid.uuid4().hex[:8]}"[:36]

        payload = {
            "subscriberAccountNumber": clean_account,
            "amount": f"{amount:.2f}",
            "billerId": biller_id,
            "useLocalAmount": use_local_amount,
            "referenceId": reference_id,
        }
        if amount_id:
            payload["amountId"] = amount_id
        if additional_info:
            payload["additionalInfo"] = additional_info

        try:
            resp = self._make_request("POST", "/pay", json=payload)
            if isinstance(resp, dict):
                resp["_amount_charged"] = amount
            return resp
        except Exception as first_error:
            error_code = ""
            error_message = ""
            resp = getattr(first_error, "response", None)
            if resp is not None:
                try:
                    body = resp.json()
                    error_code = str(body.get("errorCode", "")).lower()
                    error_message = str(body.get("message", "")).lower()
                except Exception:
                    pass
            is_amount_error = "amount" in error_code or "amount" in error_message
            is_reference_error = (
                "reference" in error_code or "reference" in error_message
            )

            if not (is_amount_error or is_reference_error):
                # Not something a retry can fix (biller down, invalid account, etc) —
                # but before giving up, check whether Reloadly actually processed this
                # despite the error response (see _verify_transaction_by_reference).
                verified = self._verify_transaction_by_reference(reference_id)
                if verified:
                    logger.warning(
                        f"pay_bill: /pay reported failure for reference {reference_id}, but Reloadly's "
                        f"own transaction records show it actually succeeded — reporting success, not failure."
                    )
                    verified["_amount_charged"] = verified.get("amount", amount)
                    verified["_verified_after_error"] = True
                    return verified
                raise

            # One retry, using REAL limits from Reloadly's own biller record — not a
            # hardcoded guess table — and always a fresh reference_id.
            try:
                real_biller = self.get_biller_by_id(biller_id)
                real_min = (
                    real_biller.get("minLocalTransactionAmount")
                    or real_biller.get("localMinAmount")
                    or real_biller.get("minAmount")
                )
                real_max = (
                    real_biller.get("maxLocalTransactionAmount")
                    or real_biller.get("localMaxAmount")
                    or real_biller.get("maxAmount")
                )
                retry_amount = amount
                if real_min is not None and retry_amount < float(real_min):
                    retry_amount = float(real_min)
                if real_max is not None and retry_amount > float(real_max):
                    retry_amount = float(real_max)

                payload["amount"] = f"{retry_amount:.2f}"
                payload["referenceId"] = fresh_reference()
                logger.info(
                    f"Retrying bill payment for biller {biller_id} with amount {retry_amount:.2f} "
                    f"(Reloadly real limits: min={real_min}, max={real_max})"
                )
                retry_resp = self._make_request("POST", "/pay", json=payload)
                if isinstance(retry_resp, dict):
                    retry_resp["_amount_charged"] = retry_amount
                return retry_resp
            except Exception:
                # Before giving up, check whether Reloadly actually processed one of our
                # attempts despite the synchronous error response. This has been observed
                # to happen — the /pay call reports failure but the transaction shows up
                # as completed in Reloadly's own records. Trusting the synchronous
                # response alone here would cause us to refund a bill that was genuinely
                # paid.
                for attempted_ref in (reference_id, payload.get("referenceId")):
                    if not attempted_ref:
                        continue
                    verified = self._verify_transaction_by_reference(attempted_ref)
                    if verified:
                        logger.warning(
                            f"pay_bill: /pay reported failure for reference {attempted_ref}, but Reloadly's "
                            f"own transaction records show it actually succeeded — reporting success, not failure."
                        )
                        verified["_amount_charged"] = verified.get("amount", amount)
                        verified["_verified_after_error"] = True
                        return verified
                # Give up cleanly rather than cycling through more fabricated guesses.
                raise first_error

    def _verify_transaction_by_reference(self, reference_id: str) -> Optional[Dict]:
        """Check Reloadly's own transaction records for a specific reference_id, to catch
        cases where the synchronous /pay response claimed failure but the payment actually
        went through. Returns the matching record if it looks genuinely successful, else None.
        """
        try:
            results = self.get_transactions(reference_id=reference_id, size=5)
            for tx in results or []:
                if not isinstance(tx, dict):
                    continue
                status = str(tx.get("status", "")).upper()
                if status in ("FAILED", "ERROR", "DECLINED"):
                    continue
                # Any record found for our exact reference that isn't explicitly marked
                # failed is treated as real evidence the payment went through. Normalize
                # the shape so callers' existing success checks (which look for
                # 'transactionId' or a recognizable 'status') work regardless of exactly
                # which field names Reloadly's /transactions list uses.
                normalized = dict(tx)
                normalized["transactionId"] = (
                    tx.get("transactionId")
                    or tx.get("id")
                    or tx.get("billPaymentId")
                    or reference_id
                )
                normalized["status"] = (
                    status
                    if status in ("SUCCESS", "COMPLETED", "PENDING")
                    else "COMPLETED"
                )
                return normalized
        except Exception as e:
            logger.warning(
                f"Could not verify transaction by reference {reference_id}: {e}"
            )
        return None

    def get_transactions(
        self,
        reference_id=None,
        status=None,
        service_type=None,
        biller_type=None,
        biller_country_code=None,
        start_date=None,
        end_date=None,
        page: int = 1,
        size: int = 10,
    ) -> List[Dict]:
        params = {"page": page, "size": size}
        if not start_date:
            start_date = (datetime.now() - timedelta(days=30)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        if not end_date:
            end_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        params["startDate"] = start_date
        params["endDate"] = end_date
        if reference_id:
            params["referenceId"] = reference_id
        if status:
            params["status"] = status
        if service_type:
            params["serviceType"] = service_type
        if biller_type:
            params["billerType"] = biller_type
        if biller_country_code:
            params["billerCountryCode"] = biller_country_code

        try:
            result = self._make_request("GET", "/transactions", params=params)
            if isinstance(result, dict) and "content" in result:
                return result["content"]
            return result
        except Exception as e:
            logger.error(f"Error fetching utility transactions: {e}")
            return []

    def get_transaction_by_id(self, transaction_id: str) -> Dict:
        try:
            return self._make_request("GET", f"/transactions/{transaction_id}")
        except Exception as e:
            logger.error(f"Error fetching transaction {transaction_id}: {e}")
            return {"error": str(e)}

    def validate_account(self, biller_id: int, subscriber_account: str) -> Dict:
        if self.credentials.environment == Environment.SANDBOX:
            return {
                "status": "success",
                "customerName": f"Customer_{subscriber_account[-4:]}",
                "accountNumber": subscriber_account,
                "billerId": biller_id,
                "valid": True,
                "isSandbox": True,
            }
        payload = {"billerId": biller_id, "subscriberAccountNumber": subscriber_account}
        return self._make_request("POST", "/validate", json=payload)


# ============ RELOADLY PLATFORM ============
class ReloadlyPlatform:
    def __init__(self, credentials: ReloadlyCredentials):
        self.api = ReloadlyAPI(credentials)
        self.credentials = credentials
        self.payment_processor = None
        self._operator_cache = {}
        self.utilities_api = None

        self.COUNTRY_CURRENCY_MAP = {
            "NG": "NGN",
            "US": "USD",
            "GB": "GBP",
            "GH": "GHS",
            "KE": "KES",
            "ZA": "ZAR",
            "IN": "INR",
            "CA": "CAD",
            "AU": "AUD",
            "EU": "EUR",
            "FR": "EUR",
            "DE": "EUR",
        }

    def get_country_code(self, input_code: str) -> str:
        if not input_code:
            return "NG"
        clean_input = input_code.strip().upper()
        if len(clean_input) == 2:
            return clean_input
        return clean_input[:2] if len(clean_input) >= 2 else "NG"

    def get_balance(self) -> Dict:
        try:
            return self.api._make_request("GET", "/accounts/balance")
        except Exception as e:
            return {"balance": 0, "currency": "USD", "error": str(e)}

    def get_countries(self) -> List[Dict]:
        try:
            return self.api._make_request("GET", "/countries")
        except Exception as e:
            logger.error(f"Error fetching countries: {e}")
            return []

    def get_operator_by_id(self, operator_id: int) -> Dict:
        if operator_id in self._operator_cache:
            return self._operator_cache[operator_id]
        try:
            result = self.api._make_request("GET", f"/operators/{operator_id}")
            self._operator_cache[operator_id] = result
            return result
        except Exception:
            return {
                "id": operator_id,
                "name": f"Operator {operator_id}",
                "status": "UNKNOWN",
            }

    def get_operators_by_country(self, country_code: str, **kwargs) -> List[Dict]:
        normalized_code = self.get_country_code(country_code)
        params = {
            "includeBundles": True,
            "includeData": True,
            "includePin": True,
            "suggestedAmountsMap": True,
            "suggestedAmounts": True,
        }
        params.update(kwargs)
        try:
            operators = self.api._make_request(
                "GET", f"/operators/countries/{normalized_code}", params=params
            )
            default_currency = self.COUNTRY_CURRENCY_MAP.get(normalized_code, "USD")
            for op in operators:
                if not op.get("currencyCode"):
                    op["currencyCode"] = default_currency
                if not op.get("localCurrencyCode") and default_currency:
                    op["localCurrencyCode"] = default_currency
            return operators
        except Exception as e:
            logger.error(f"Error fetching operators for {normalized_code}: {e}")
            fallback_operators = [
                {
                    "operatorId": 49,
                    "name": "MTN Nigeria",
                    "currencyCode": "NGN",
                    "localCurrencyCode": "NGN",
                    "status": "ACTIVE",
                    "minAmount": 0.04,
                    "maxAmount": 160.77,
                },
                {
                    "operatorId": 50,
                    "name": "Glo Nigeria",
                    "currencyCode": "NGN",
                    "localCurrencyCode": "NGN",
                    "status": "ACTIVE",
                    "minAmount": 0.04,
                    "maxAmount": 160.77,
                },
                {
                    "operatorId": 51,
                    "name": "Airtel Nigeria",
                    "currencyCode": "NGN",
                    "localCurrencyCode": "NGN",
                    "status": "ACTIVE",
                    "minAmount": 0.04,
                    "maxAmount": 160.77,
                },
                {
                    "operatorId": 52,
                    "name": "9mobile Nigeria",
                    "currencyCode": "NGN",
                    "localCurrencyCode": "NGN",
                    "status": "ACTIVE",
                    "minAmount": 0.04,
                    "maxAmount": 160.77,
                },
            ]
            if normalized_code == "NG":
                return fallback_operators
            return []

    def get_operators_for_country(
        self, country_code: str, service_type: str = "all"
    ) -> List[Dict]:
        operators = self.get_operators_by_country(country_code)
        if service_type == "airtime":
            return [op for op in operators if not op.get("data", True)]
        return operators

    def _format_phone_for_topup(self, phone: str, country_code: str = "NG") -> str:
        """Format a phone number for a one-time top-up.

        Normalizes user input (strip spaces, dashes, leading zeros, etc.),
        prepends the country code if absent, and validates against the
        country's expected length. Returns "" for anything unusable.
        """
        if not phone:
            return ""

        clean = re.sub(r"[^0-9]", "", phone)
        if not clean:
            return ""

        country_code = country_code.upper().strip()

        # ─────────────────────────────────────────────────────────────
        # Same country-format table used by _format_phone_for_schedule.
        # (country_code, min_total_digits, max_total_digits)
        # ─────────────────────────────────────────────────────────────
        COUNTRY_FORMATS = {
            # North America
            "US": ("1",   11, 11), "CA": ("1",   11, 11),
            # Europe
            "GB": ("44",  12, 12), "IE": ("353", 11, 12), "FR": ("33",  11, 11),
            "DE": ("49",  11, 13), "IT": ("39",  11, 13), "ES": ("34",  11, 11),
            "PT": ("351", 11, 12), "NL": ("31",  11, 11), "BE": ("32",  11, 12),
            "AT": ("43",  11, 13), "CH": ("41",  11, 11), "SE": ("46",  11, 12),
            "NO": ("47",  10, 10), "DK": ("45",  10, 10), "FI": ("358", 12, 12),
            "PL": ("48",  11, 11), "CZ": ("420", 12, 12), "HU": ("36",  11, 11),
            "GR": ("30",  12, 12), "RO": ("40",  11, 11),
            # Asia-Pacific
            "AU": ("61",  11, 11), "NZ": ("64",  10, 11), "JP": ("81",  11, 11),
            "CN": ("86",  13, 13), "HK": ("852", 11, 11), "SG": ("65",  10, 10),
            "MY": ("60",  11, 12), "TH": ("66",  11, 11), "VN": ("84",  11, 12),
            "PH": ("63",  12, 12), "ID": ("62",  11, 13), "IN": ("91",  12, 12),
            "PK": ("92",  12, 12), "BD": ("880", 13, 13), "LK": ("94",  11, 11),
            "KR": ("82",  11, 12), "TW": ("886", 12, 12),
            # Middle East / North Africa
            "AE": ("971", 12, 12), "SA": ("966", 12, 12), "QA": ("974", 11, 11),
            "KW": ("965", 11, 11), "BH": ("973", 11, 11), "OM": ("968", 11, 11),
            "JO": ("962", 12, 12), "LB": ("961", 10, 11), "IL": ("972", 12, 12),
            "TR": ("90",  12, 12), "EG": ("20",  12, 12), "MA": ("212", 12, 12),
            "DZ": ("213", 12, 12), "TN": ("216", 11, 11),
            # Latin America
            "BR": ("55",  12, 13), "MX": ("52",  12, 13), "AR": ("54",  12, 13),
            "CL": ("56",  11, 11), "CO": ("57",  12, 12), "PE": ("51",  11, 11),
            "VE": ("58",  12, 12), "EC": ("593", 12, 12), "UY": ("598", 11, 12),
            "PY": ("595", 12, 12), "BO": ("591", 11, 11),
            # Sub-Saharan Africa
            "NG": ("234", 13, 13), "GH": ("233", 12, 12), "KE": ("254", 12, 12),
            "ZA": ("27",  11, 11), "TZ": ("255", 12, 12), "UG": ("256", 12, 12),
            "RW": ("250", 12, 12), "ET": ("251", 12, 12), "MW": ("265", 12, 12),
            "ZM": ("260", 12, 12), "ZW": ("263", 12, 12), "MZ": ("258", 12, 12),
            "CM": ("237", 12, 12), "CI": ("225", 11, 11), "SN": ("221", 12, 12),
            "AO": ("244", 12, 12),
        }

        entry = COUNTRY_FORMATS.get(country_code)
        if not entry:
            logger.warning(f"Topup: no phone format defined for '{country_code}'")
            return ""

        target_cc, min_len, max_len = entry

        # 1. Strip leading zeros (users type local-style: 08036939103, 07719497751)
        while clean.startswith("0"):
            clean = clean[1:]

        # 2. Prepend the country code if not already present
        if not clean.startswith(target_cc):
            clean = target_cc + clean

        # 3. Validate length — reject rather than truncate
        actual_len = len(clean)
        if actual_len < min_len or actual_len > max_len:
            logger.warning(
                f"Topup: {country_code} phone '{phone}' normalized to '{clean}' "
                f"({actual_len} digits), outside expected range {min_len}-{max_len}"
            )
            return ""

        return clean

    def _format_phone_for_schedule(self, phone: str, country_code: str = "NG") -> Tuple[str, bool]:
        """Format phone for scheduled payments - accepts various formats"""
        if not phone:
            return "", False

        # Remove all non-digits
        clean = re.sub(r"[^0-9]", "", phone)
        if not clean:
            return "", False

        country_code = country_code.upper().strip()
        
        # For Nigeria
        if country_code == "NG":
            # Remove all leading zeros
            while clean.startswith("0"):
                clean = clean[1:]
            
            # Check if it already has 234
            if clean.startswith("234"):
                # If it's 13 digits, keep it
                if len(clean) == 13:
                    return clean, True
                # If it's 14 digits, trim to 13
                elif len(clean) == 14:
                    clean = clean[:13]
                    return clean, True
                # If it's more than 14 digits, it's invalid
                elif len(clean) > 14:
                    return clean, False
            
            # If it's 10 digits (local format), add 234
            if len(clean) == 10:
                clean = "234" + clean
            # If it's 11 digits (local format with extra digit), add 234 and trim
            elif len(clean) == 11:
                clean = "234" + clean
                clean = clean[:13]  # Trim to 13 digits
            # If it's less than 10 digits, it's invalid
            elif len(clean) < 10:
                return clean, False
            # If it's more than 10 digits but doesn't have 234, it's invalid
            else:
                return clean, False
            
            # Final validation - must be exactly 13 digits and start with 234
            if len(clean) != 13 or not clean.startswith("234"):
                return clean, False
            
            return clean, True
        
        # For US/Canada
        if country_code in ("US", "CA"):
            while clean.startswith("0"):
                clean = clean[1:]
            
            # Check if it already has 1
            if clean.startswith("1"):
                if len(clean) == 11:
                    return clean, True
                elif len(clean) == 12:
                    clean = clean[:11]
                    return clean, True
            
            # If it's 10 digits, add 1
            if len(clean) == 10:
                clean = "1" + clean
            
            if len(clean) != 11 or not clean.startswith("1"):
                return clean, False
            return clean, True
        
        # For other countries
        # ─────────────────────────────────────────────────────────────────
        # Comprehensive country-code table.
        #
        # Each entry is (country_code, min_total_digits, max_total_digits)
        # where "total" includes the country code prefix.
        #
        # Reloadly is picky about exactly how many digits a number has for
        # each country — too short and it's not a number, too long and it's
        # been padded. These bounds are the accepted ranges per ITU E.164
        # and Reloadly's own operator validation.
        # ─────────────────────────────────────────────────────────────────
        COUNTRY_FORMATS = {
            # ── North America (NANP) ─────────────────────────────────
            "US": ("1",   11, 11),   # 1 + 10
            "CA": ("1",   11, 11),   # 1 + 10

            # ── Europe ───────────────────────────────────────────────
            "GB": ("44",  12, 12),   # 44 + 10
            "IE": ("353", 11, 12),   # 353 + 7-9
            "FR": ("33",  11, 11),   # 33 + 9
            "DE": ("49",  11, 13),   # 49 + 9-11
            "IT": ("39",  11, 13),   # 39 + 9-11 (includes mobile leading 3)
            "ES": ("34",  11, 11),   # 34 + 9
            "PT": ("351", 11, 12),   # 351 + 9
            "NL": ("31",  11, 11),   # 31 + 9
            "BE": ("32",  11, 12),   # 32 + 9-10
            "AT": ("43",  11, 13),   # 43 + 9-11
            "CH": ("41",  11, 11),   # 41 + 9
            "SE": ("46",  11, 12),   # 46 + 9-10
            "NO": ("47",  10, 10),   # 47 + 8
            "DK": ("45",  10, 10),   # 45 + 8
            "FI": ("358", 12, 12),   # 358 + 9-10
            "PL": ("48",  11, 11),   # 48 + 9
            "CZ": ("420", 12, 12),   # 420 + 9
            "HU": ("36",  11, 11),   # 36 + 9
            "GR": ("30",  12, 12),   # 30 + 10
            "RO": ("40",  11, 11),   # 40 + 9

            # ── Asia-Pacific ────────────────────────────────────────
            "AU": ("61",  11, 11),   # 61 + 9
            "NZ": ("64",  10, 11),   # 64 + 8-9
            "JP": ("81",  11, 11),   # 81 + 10
            "CN": ("86",  13, 13),   # 86 + 11
            "HK": ("852", 11, 11),   # 852 + 8
            "SG": ("65",  10, 10),   # 65 + 8
            "MY": ("60",  11, 12),   # 60 + 9-10
            "TH": ("66",  11, 11),   # 66 + 9
            "VN": ("84",  11, 12),   # 84 + 9-10
            "PH": ("63",  12, 12),   # 63 + 10
            "ID": ("62",  11, 13),   # 62 + 9-11
            "IN": ("91",  12, 12),   # 91 + 10
            "PK": ("92",  12, 12),   # 92 + 10
            "BD": ("880", 13, 13),   # 880 + 10
            "LK": ("94",  11, 11),   # 94 + 9
            "KR": ("82",  11, 12),   # 82 + 9-10
            "TW": ("886", 12, 12),   # 886 + 9

            # ── Middle East / North Africa ──────────────────────────
            "AE": ("971", 12, 12),   # 971 + 9
            "SA": ("966", 12, 12),   # 966 + 9
            "QA": ("974", 11, 11),   # 974 + 8
            "KW": ("965", 11, 11),   # 965 + 8
            "BH": ("973", 11, 11),   # 973 + 8
            "OM": ("968", 11, 11),   # 968 + 8
            "JO": ("962", 12, 12),   # 962 + 9
            "LB": ("961", 10, 11),   # 961 + 7-8
            "IL": ("972", 12, 12),   # 972 + 9
            "TR": ("90",  12, 12),   # 90 + 10
            "EG": ("20",  12, 12),   # 20 + 10
            "MA": ("212", 12, 12),   # 212 + 9
            "DZ": ("213", 12, 12),   # 213 + 9
            "TN": ("216", 11, 11),   # 216 + 8

            # ── Latin America ───────────────────────────────────────
            "BR": ("55",  12, 13),   # 55 + 10-11
            "MX": ("52",  12, 13),   # 52 + 10
            "AR": ("54",  12, 13),   # 54 + 10-11
            "CL": ("56",  11, 11),   # 56 + 9
            "CO": ("57",  12, 12),   # 57 + 10
            "PE": ("51",  11, 11),   # 51 + 9
            "VE": ("58",  12, 12),   # 58 + 10
            "EC": ("593", 12, 12),   # 593 + 9
            "UY": ("598", 11, 12),   # 598 + 8-9
            "PY": ("595", 12, 12),   # 595 + 9
            "BO": ("591", 11, 11),   # 591 + 8

            # ── Sub-Saharan Africa ──────────────────────────────────
            "NG": ("234", 13, 13),   # 234 + 10
            "GH": ("233", 12, 12),   # 233 + 9
            "KE": ("254", 12, 12),   # 254 + 9
            "ZA": ("27",  11, 11),   # 27 + 9
            "TZ": ("255", 12, 12),   # 255 + 9
            "UG": ("256", 12, 12),   # 256 + 9
            "RW": ("250", 12, 12),   # 250 + 9
            "ET": ("251", 12, 12),   # 251 + 9
            "MW": ("265", 12, 12),   # 265 + 9
            "ZM": ("260", 12, 12),   # 260 + 9
            "ZW": ("263", 12, 12),   # 263 + 9
            "MZ": ("258", 12, 12),   # 258 + 9
            "CM": ("237", 12, 12),   # 237 + 9
            "CI": ("225", 11, 11),   # 225 + 8
            "SN": ("221", 12, 12),   # 221 + 9
            "AO": ("244", 12, 12),   # 244 + 9
        }

        entry = COUNTRY_FORMATS.get(country_code)
        if not entry:
            logger.warning(
                f"Schedule: no phone format defined for country '{country_code}'"
            )
            return "", False

        target_cc, min_len, max_len = entry

        # ─────────────────────────────────────────────────────────────
        # Normalization steps
        # ─────────────────────────────────────────────────────────────

        # 1. Strip all leading zeros (users type local-style numbers like
        #    "07719497751" out of habit — every country has its own
        #    national prefix that is dropped when internationalizing).
        while clean.startswith("0"):
            clean = clean[1:]

        # 2. If the user typed the number WITHOUT the country code, add it.
        #    If they typed it WITH the country code, leave it alone.
        if not clean.startswith(target_cc):
            clean = target_cc + clean

        # ─────────────────────────────────────────────────────────────
        # 3. Validate against the country's expected length range.
        #
        #    Return (cleaned, False) for anything out of range so the
        #    caller can reject the schedule. Do NOT silently truncate —
        #    truncating a too-long number produces a DIFFERENT phone
        #    number that may belong to someone else.
        # ─────────────────────────────────────────────────────────────
        actual_len = len(clean)

        if actual_len < min_len:
            logger.warning(
                f"Schedule: {country_code} phone '{phone}' normalized to "
                f"'{clean}' ({actual_len} digits), below minimum {min_len}"
            )
            return clean, False

        if actual_len > max_len:
            logger.warning(
                f"Schedule: {country_code} phone '{phone}' normalized to "
                f"'{clean}' ({actual_len} digits), above maximum {max_len}. "
                f"Refusing to truncate — user must re-enter the number."
            )
            return clean, False

        return clean, True
        
    def convert_ngn_to_usd(self, ngn_amount: float) -> float:
        if ngn_amount <= 0:
            return 0.0

        rate = ExchangeRateService.get_ngn_to_usd()
        usd_amount = ngn_amount / rate
        usd_amount = round(usd_amount, 2)

        if (
            self.credentials.environment.value == "sandbox"
            and usd_amount < 0.50
            and ngn_amount > 0
        ):
            usd_amount = 0.50

        return usd_amount

    def convert_to_usd(self, amount: float, currency: str) -> float:
        currency = currency.upper()
        if amount <= 0:
            return 0.0

        if currency == "USD":
            return round(amount, 2)

        rate = ExchangeRateService.get_rate(currency, "USD")
        if rate:
            usd_amount = amount / rate
            return round(usd_amount, 2)

        if currency == "NGN":
            return self.convert_ngn_to_usd(amount)

        return round(amount, 2)

    def make_topup(
        self,
        operator_id: str,
        amount: str,
        recipient_phone: Dict[str, str],
        use_local_amount: bool = False,
        custom_identifier: Optional[str] = None,
        recipient_email: Optional[str] = None,
        is_async: bool = True,
    ) -> Dict:
        country_code = recipient_phone["countryCode"].upper()
        clean_number = self._format_phone_for_topup(
            recipient_phone["number"], country_code
        )

        if not clean_number:
            return {
                "status": "FAILED",
                "error": "Invalid phone number",
                "message": "Phone number is required and must contain only digits",
            }

        try:
            amount_float = float(amount)
            if amount_float <= 0:
                return {
                    "status": "FAILED",
                    "error": "Invalid amount",
                    "message": "Amount must be greater than 0",
                }

            # ─────────────────────────────────────────────────────────────
            # Snap to the operator's accepted denominations.
            #
            # Reloadly operators come in two flavors:
            #   - RANGE:  accepts any amount between minAmount and maxAmount
            #   - FIXED:  accepts ONLY the exact values in fixedAmounts
            #             (or localFixedAmounts for local-currency requests)
            #
            # Sending an amount that isn't in a FIXED operator's list returns
            # a 400. Most US carriers are RANGE (why US "just worked"), most
            # UK/European carriers are FIXED (why UK always 400'd).
            # ─────────────────────────────────────────────────────────────
            try:
                op = self.get_operator_by_id(int(operator_id))
            except (ValueError, TypeError):
                op = {}

            denom_type = (op.get("denominationType") or "").upper()

            if denom_type == "FIXED":
                if use_local_amount:
                    valid = op.get("localFixedAmounts") or []
                else:
                    valid = op.get("fixedAmounts") or []

                if valid:
                    closest = min(valid, key=lambda x: abs(float(x) - amount_float))
                    if abs(float(closest) - amount_float) > 0.01:
                        logger.warning(
                            f"Operator {operator_id} ({op.get('name')}) is FIXED; "
                            f"snapping {amount_float:.2f} -> {float(closest):.2f}. "
                            f"Valid amounts: {valid}"
                        )
                    amount_float = float(closest)
                else:
                    logger.error(
                        f"Operator {operator_id} is FIXED but Reloadly returned "
                        f"no fixedAmounts list. Cannot determine a valid amount."
                    )
                    return {
                        "status": "FAILED",
                        "error": "Invalid amount for this operator",
                        "message": (
                            f"Operator {operator_id} only accepts fixed amounts, "
                            f"but none were returned by Reloadly."
                        ),
                    }

            elif denom_type == "RANGE":
                mn = op.get("minAmount")
                mx = op.get("maxAmount")
                if mn is not None and amount_float < float(mn):
                    logger.warning(
                        f"Operator {operator_id} is RANGE; clamping "
                        f"{amount_float:.2f} up to min {float(mn):.2f}"
                    )
                    amount_float = float(mn)
                if mx is not None and amount_float > float(mx):
                    logger.warning(
                        f"Operator {operator_id} is RANGE; clamping "
                        f"{amount_float:.2f} down to max {float(mx):.2f}"
                    )
                    amount_float = float(mx)

            # In sandbox, Reloadly accepts a narrower set of test amounts
            # regardless of the operator's real denomination rules. Apply
            # this AFTER the FIXED/RANGE snap so production is unaffected.
            # In sandbox, Reloadly accepts a narrower set of test amounts
            # regardless of the operator's real denomination rules. Apply
            # this ONLY if the operator isn't FIXED — otherwise we'd
            # overwrite the correct denomination with a sandbox amount.
            if (self.credentials.environment.value == "sandbox"
                    and denom_type != "FIXED"):
                sandbox_amounts = [
                    0.50, 1.00, 5.00, 10.00, 15.00, 20.00, 25.00, 50.00, 100.00,
                ]
                closest = min(sandbox_amounts, key=lambda x: abs(x - amount_float))
                if abs(closest - amount_float) / max(amount_float, 0.01) < 0.1:
                    amount_float = closest
                else:
                    amount_float = 5.00
                logger.info(f"Sandbox: using amount ${amount_float:.2f}")
            elif self.credentials.environment.value == "sandbox":
                logger.info(
                    f"Sandbox: operator is FIXED, keeping snapped amount "
                    f"${amount_float:.2f} (sandbox may still reject — expected)"
                )

            amount_str = f"{amount_float:.2f}"
        except ValueError as e:
            logger.error(f"Invalid amount format: {amount}")
            return {
                "status": "FAILED",
                "error": "Invalid amount format",
                "message": str(e),
            }

        payload = {
            "operatorId": str(operator_id),
            "amount": amount_str,
            "useLocalAmount": use_local_amount,
            "recipientPhone": {"countryCode": country_code, "number": clean_number},
        }
        if custom_identifier:
            payload["customIdentifier"] = custom_identifier
        if recipient_email:
            payload["recipientEmail"] = recipient_email

        logger.info(f"Making top-up request: {payload}")

        endpoint = "/topups-async" if is_async else "/topups"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/com.reloadly.topups-v1+json",
        }

        try:
            result = self.api._make_request(
                "POST", endpoint, json=payload, headers=headers
            )
            return result
        except Exception as e:
            logger.error(f"Top-up API error: {e}")
            if "400" in str(e):
                # The $1 / $5 / $10 retry cascade below only helps in the rare
                # case where a sandbox operator accepts one amount but not
                # another. For production operator IDs (49/50/51/52) it will
                # 400 every time — three extra doomed requests per record.
                # Off by default; enable with RELOADLY_SANDBOX_AMOUNT_RETRY=true
                # if you're actively probing sandbox amounts.
                if "400" in str(e):
                    if (
                        self.credentials.environment.value == "sandbox"
                        and os.getenv("RELOADLY_SANDBOX_AMOUNT_RETRY", "false").lower() == "true"
                    ):
                        for test_amount in [1.00, 5.00, 10.00]:
                            try:
                                payload["useLocalAmount"] = True
                                payload["amount"] = str(test_amount)
                                logger.info(
                                    f"Trying with amount ${test_amount} and useLocalAmount=True"
                                )
                                result = self.api._make_request(
                                    "POST", endpoint, json=payload, headers=headers
                                )
                                if result.get("status") != "FAILED":
                                    return result
                            except Exception:
                                continue
                    return {
                        "status": "FAILED",
                        "error": "Invalid operator or phone number",
                        "message": f"The operator ID {operator_id} or phone number {clean_number} is invalid. Please check and try again.",
                    }
                raise

    def _get_utilities_api(self):
        if not self.utilities_api:
            self.utilities_api = ReloadlyUtilitiesAPI(self.credentials)
        return self.utilities_api

    def get_utility_billers(self, **kwargs) -> List[Dict]:
        try:
            api = self._get_utilities_api()
            return api.get_billers(**kwargs)
        except Exception as e:
            logger.error(f"Error fetching utility billers: {e}")
            return []

    def get_utility_biller_by_id(self, biller_id: int) -> Dict:
        try:
            api = self._get_utilities_api()
            return api.get_biller_by_id(biller_id)
        except Exception as e:
            logger.error(f"Error fetching biller {biller_id}: {e}")
            return {
                "id": biller_id,
                "name": f"Biller {biller_id}",
                "billerId": biller_id,
            }

    def validate_utility_account(self, biller_id: int, subscriber_account: str) -> Dict:
        try:
            api = self._get_utilities_api()
            return api.validate_account(biller_id, subscriber_account)
        except Exception as e:
            logger.error(f"Error validating account: {e}")
            return {
                "valid": True,
                "customerName": f"Customer_{subscriber_account[-4:]}",
                "accountNumber": subscriber_account,
                "billerId": biller_id,
            }

    def pay_utility_bill(
        self,
        biller_id: int,
        subscriber_account: str,
        amount: float,
        reference_id: str,
        use_local_amount: bool = True,
        additional_info: Optional[Dict] = None,
        amount_id: Optional[int] = None,
    ) -> Dict:
        try:
            api = self._get_utilities_api()
            return api.pay_bill(
                biller_id=biller_id,
                subscriber_account=subscriber_account,
                amount=amount,
                reference_id=reference_id,
                use_local_amount=use_local_amount,
                additional_info=additional_info,
                amount_id=amount_id,
            )
        except Exception as e:
            logger.error(f"Error paying utility bill: {e}")
            return {"error": str(e)}

    def get_utility_transactions(self, **kwargs) -> List[Dict]:
        try:
            api = self._get_utilities_api()
            return api.get_transactions(**kwargs)
        except Exception as e:
            logger.error(f"Error fetching utility transactions: {e}")
            return []

    def get_utility_transaction_by_id(self, transaction_id: str) -> Dict:
        try:
            api = self._get_utilities_api()
            return api.get_transaction_by_id(transaction_id)
        except Exception as e:
            logger.error(f"Error fetching utility transaction {transaction_id}: {e}")
            return {"error": str(e)}

    def create_payment(
        self,
        amount: float,
        currency: str = "NGN",
        operator_id: str = None,
        phone: str = None,
        country_code: str = None,
        email: str = None,
        return_url: str = None,
        provider: str = None,
    ) -> Dict:
        currency = (currency or "NGN").upper()

        if currency not in SUPPORTED_CURRENCIES:
            return {"success": False, "error": f"Unsupported currency: {currency}"}

        if not provider:
            provider = SUPPORTED_CURRENCIES[currency]["gateway"]
        else:
            provider = provider.lower()

        if (
            provider not in GATEWAY_CURRENCIES
            or currency not in GATEWAY_CURRENCIES[provider]
        ):
            return {
                "success": False,
                "error": f"{provider} does not support {currency}",
            }

        if provider == "paystack":
            api_key = os.getenv("PAYSTACK_SECRET_KEY")
        elif provider == "flutterwave":
            api_key = os.getenv("FLUTTERWAVE_SECRET_KEY")
        else:
            api_key = os.getenv("STRIPE_SECRET_KEY")

        if not api_key:
            return {"success": False, "error": f"{provider} secret key not configured"}

        if not email:
            email = os.getenv("DEFAULT_PAYMENT_EMAIL", "customer@net365.com")

        self.payment_processor = PaymentProcessor(provider, api_key)
        metadata = {
            "operator_id": operator_id or "",
            "phone": phone or "",
            "country_code": country_code or "",
        }

        if operator_id is None and phone is None:
            description = f"Utility bill payment of {amount} {currency}"
        else:
            description = f"Airtime top-up for {phone}" if phone else "Wallet funding"

        return self.payment_processor.create_payment_intent(
            amount=amount,
            currency=currency,
            description=description,
            metadata=metadata,
            email=email,
            return_url=return_url,
            provider=provider,
        )

    def verify_payment(self, reference: str, provider: str = None) -> Dict:
        if not provider:
            if reference.startswith("PSK"):
                provider = "paystack"
            elif reference.startswith("FLW"):
                provider = "flutterwave"
            elif reference.startswith("STR") or reference.startswith("cs_"):
                provider = "stripe"
            else:
                provider = "paystack"

        if provider == "paystack":
            api_key = os.getenv("PAYSTACK_SECRET_KEY")
            self.payment_processor = PaymentProcessor("paystack", api_key)
            return self.payment_processor.verify_paystack_payment(reference)
        elif provider == "flutterwave":
            api_key = os.getenv("FLUTTERWAVE_SECRET_KEY")
            self.payment_processor = PaymentProcessor("flutterwave", api_key)
            return self.payment_processor.verify_flutterwave_payment(reference)
        elif provider == "stripe":
            if not STRIPE_AVAILABLE:
                return {"success": False, "error": "Stripe library not installed"}
            api_key = os.getenv("STRIPE_SECRET_KEY")
            self.payment_processor = PaymentProcessor("stripe", api_key)
            return self.payment_processor.verify_stripe_payment(reference)
        else:
            return {"success": False, "error": f"Unsupported provider: {provider}"}
            
            
    def auto_detect_operator(self, phone: str, country_code: str = "NG") -> Dict:
        """Call Reloadly's operator auto‑detect endpoint."""
        import re
        # Remove any non‑digit characters except leading '+'
        clean_phone = re.sub(r'[^0-9+]', '', phone)
        # Ensure country code is uppercase
        country_code = country_code.upper()
        params = {
            "phone": clean_phone,       # ← Changed from "phoneNumber"
            "countryCode": country_code
        }
        try:
            result = self.api._make_request("GET", "/operators/auto-detect", params=params)
            # Reloadly returns the operator object directly
            return {"success": True, "operator": result}
        except Exception as e:
            logger.error(f"Auto‑detect failed for {phone}: {e}")
            return {"success": False, "error": str(e)}

    # In-memory cache for _sandbox_operator_fallback — operator lists for a
    # country barely change, so there's no reason to hit Reloadly on every
    # keystroke a tester makes. Keyed by country code.
    _sandbox_fallback_cache: Dict[str, Dict] = {}
    _sandbox_fallback_cache_ts: Dict[str, float] = {}
    _SANDBOX_FALLBACK_TTL_SECONDS = 3600  # 1 hour

    def _sandbox_operator_fallback(self, country_code: str) -> Optional[Dict]:
        """Return a REAL, verified operator for `country_code` to use when
        Reloadly's phone-based auto-detect endpoint rejects a number.

        Why this exists: Reloadly's sandbox only recognizes its own test
        phone numbers on /operators/auto-detect — any real number 400s there,
        in every country, every time. That's a sandbox limitation, not a
        signal the number or country is unsupported.

        This used to be solved with a hardcoded table of guessed operator
        IDs per country (unverified, and wrong for every country except NG).
        Guessed IDs are a liability: an incorrect one doesn't fail loudly,
        it just sends the top-up to the wrong place.

        Instead, this asks Reloadly's own /operators/countries/{code}
        endpoint — which DOES return real data in sandbox — which operators
        actually exist for this country, and uses one of them. Zero hardcoded
        IDs, zero manual verification, and it automatically covers every
        country Reloadly supports rather than a short hand-maintained list.
        """
        now = time.time()
        cached = self._sandbox_fallback_cache.get(country_code)
        cached_at = self._sandbox_fallback_cache_ts.get(country_code, 0)
        if cached is not None and (now - cached_at) < self._SANDBOX_FALLBACK_TTL_SECONDS:
            return cached

        try:
            operators = self.get_operators_by_country(country_code)
        except Exception as e:
            logger.warning(f"sandbox fallback: could not fetch operators for {country_code}: {e}")
            return None

        if not operators:
            return None

        # Prefer a plain ACTIVE operator (not a data bundle or PIN-only
        # product) so the fallback mirrors an ordinary airtime top-up as
        # closely as possible. Fall back to whatever's returned if nothing
        # matches that exactly — some countries only have bundle operators.
        active = [op for op in operators if str(op.get("status", "")).upper() == "ACTIVE"]
        plain = [op for op in active if not op.get("data") and not op.get("pin")]
        chosen = (plain or active or operators)[0]

        operator_id = chosen.get("operatorId") or chosen.get("id")
        if not operator_id:
            return None

        result = {
            "operatorId": str(operator_id),
            "id": str(operator_id),
            "name": f"{chosen.get('name', 'Unknown operator')} (sandbox test operator)",
            "currencyCode": chosen.get("currencyCode"),
            "localCurrencyCode": chosen.get("localCurrencyCode"),
        }
        self._sandbox_fallback_cache[country_code] = result
        self._sandbox_fallback_cache_ts[country_code] = now
        return result


# ============ PAYMENT PROCESSOR ============
class PaymentProcessor:
    def __init__(self, provider: str = "paystack", api_key: Optional[str] = None):
        self.provider = provider
        self.api_key = api_key
        self.paystack_base_url = "https://api.paystack.co"
        self.flutterwave_base_url = "https://api.flutterwave.com/v3"
        if provider == "stripe" and STRIPE_AVAILABLE:
            stripe.api_key = api_key

    def init_paystack_payment(
        self, email: str, amount: float, reference: str = None, return_url: str = None,
        extra: Optional[Dict] = None,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        # Returns (authorization_url, reference, error_detail). error_detail is
        # None on success. Previously a non-200 Paystack response (bad email,
        # bad amount, account issue, etc.) was silently discarded — the
        # caller only ever saw a generic "Failed to initialize Paystack
        # payment", with Paystack's actual explanation thrown away. That's
        # the single biggest blind spot in diagnosing a gateway-specific
        # failure, so it's now captured and threaded all the way back.
        if not self.api_key:
            return None, None, "Paystack secret key not configured on the server"
        reference = reference or generate_reference("PSK")
        amount_kobo = int(round(float(amount) * 100))
        return_url = return_url or os.getenv("PAYSTACK_RETURN_URL", DEFAULT_RETURN_URL)
        callback_url = f"{PAYMENT_SERVICE_URL}/payment/callback?return_url={quote(str(return_url), safe='')}&reference={reference}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "email": email,
            "amount": amount_kobo,
            "currency": "NGN",
            "reference": reference,
            "callback_url": callback_url,
        }
        if extra:
            payload.update(extra)  # e.g. subaccount / transaction_charge / bearer for business payments
        try:
            response = requests.post(
                f"{self.paystack_base_url}/transaction/initialize",
                headers=headers,
                json=payload,
                timeout=30,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("status"):
                    return data["data"]["authorization_url"], reference, None
                # HTTP 200 but Paystack flagged status:false — their message
                # (e.g. "Invalid email address") is in data["message"].
                err = data.get("message", "Paystack rejected the request (no detail given)")
                logger.error(f"Paystack init rejected (200 but status:false): {err} | payload={payload}")
                return None, None, err
            # Non-200 — Paystack usually still returns a JSON body with a
            # "message" explaining why (invalid key, invalid params, etc.).
            try:
                err_body = response.json()
                err = err_body.get("message", response.text[:300])
            except Exception:
                err = response.text[:300] or f"HTTP {response.status_code}"
            logger.error(f"Paystack init failed: HTTP {response.status_code} — {err} | payload={payload}")
            return None, None, f"Paystack error ({response.status_code}): {err}"
        except Exception as e:
            logger.error(f"Paystack init error: {str(e)}")
            return None, None, f"Could not reach Paystack: {e}"

    def init_flutterwave_payment(
        self,
        email: str,
        amount: float,
        currency: str = "NGN",
        reference: str = None,
        return_url: str = None,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        # Returns (authorization_url, reference, error_detail) — same pattern
        # as init_paystack_payment/init_stripe_payment, for the same reason:
        # don't silently discard the gateway's actual rejection reason.
        flutterwave_secret_key = os.getenv("FLUTTERWAVE_SECRET_KEY")
        if not flutterwave_secret_key:
            return None, None, "Flutterwave secret key not configured on the server"
        reference = reference or generate_reference("FLW")
        return_url = return_url or os.getenv(
            "FLUTTERWAVE_RETURN_URL", DEFAULT_RETURN_URL
        )
        callback_url = f"{PAYMENT_SERVICE_URL}/payment/callback?return_url={quote(str(return_url), safe='')}&reference={reference}"
        headers = {
            "Authorization": f"Bearer {flutterwave_secret_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "tx_ref": reference,
            "amount": f"{amount:.2f}",
            "currency": currency.upper(),
            "redirect_url": callback_url,
            "customer": {"email": email, "name": "Customer"},
            "customizations": {
                "title": "Net365 Top-up",
                "description": f"Top-up of {currency} {amount:,.2f}",
            },
        }
        try:
            response = requests.post(
                f"{self.flutterwave_base_url}/payments",
                headers=headers,
                json=payload,
                timeout=30,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return data["data"]["link"], reference, None
                err = data.get("message", "Flutterwave rejected the request (no detail given)")
                logger.error(f"Flutterwave init rejected (200 but status!=success): {err} | payload={payload}")
                return None, None, err
            try:
                err_body = response.json()
                err = err_body.get("message", response.text[:300])
            except Exception:
                err = response.text[:300] or f"HTTP {response.status_code}"
            logger.error(f"Flutterwave init failed: HTTP {response.status_code} — {err} | payload={payload}")
            return None, None, f"Flutterwave error ({response.status_code}): {err}"
        except Exception as e:
            logger.error(f"Flutterwave init error: {str(e)}")
            return None, None, f"Could not reach Flutterwave: {e}"

    def init_stripe_payment(
        self,
        email: str,
        amount: float,
        currency: str = "USD",
        reference: str = None,
        return_url: str = None,
        description: str = "Airtime Top-up",
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        # Returns (checkout_url, reference, error_detail_or_session_id).
        # On SUCCESS the 3rd element is the Stripe session id (unchanged
        # behavior — callers rely on this). On FAILURE the 3rd element is
        # now an error string instead of always being None, so a rejection
        # reason isn't silently thrown away.
        if not STRIPE_AVAILABLE:
            return None, None, "Stripe library not installed on the server"
        if not self.api_key:
            return None, None, "Stripe secret key not configured on the server"

        reference = reference or generate_reference("STR")
        return_url = return_url or os.getenv("STRIPE_RETURN_URL", DEFAULT_RETURN_URL)

        try:
            # Stripe expects amounts in the smallest currency unit — but some
            # currencies are zero-decimal (JPY, VND, IDR, CLP, UGX, TZS, KRW,
            # etc.). For those, send the raw integer amount as-is.
            #
            # BUG FIXED: this used to set amount_cents inside the if/else
            # below, then unconditionally overwrite it on the next line with
            # int(amount * 100) regardless of which branch ran — so every
            # zero-decimal-currency payment (JPY, UGX, KRW, TZS...) was
            # silently charged 100x. NGN/USD were never affected by this
            # specific bug (neither is zero-decimal).
            if currency.lower() in STRIPE_ZERO_DECIMAL:
                amount_cents = int(round(amount))
            else:
                amount = round(amount, 2)
                amount_cents = int(round(amount * 100))

            session = stripe.checkout.Session.create(
            #payment_method_types=["card"],
                line_items=[
                    {
                        "price_data": {
                            "currency": currency.lower(),
                            "product_data": {
                                "name": "Net365 Top-up",
                                "description": description
                                or f"Top-up of {amount} {currency}",
                            },
                            "unit_amount": amount_cents,
                        },
                        "quantity": 1,
                    }
                ],
                mode="payment",
                success_url=f"{PAYMENT_SERVICE_URL}/payment/success?session_id={{CHECKOUT_SESSION_ID}}&reference={reference}",
                cancel_url=f"{PAYMENT_SERVICE_URL}/payment/cancel?reference={reference}",
                customer_email=email,
                metadata={
                    "reference": reference,
                    "amount": str(amount),
                    "currency": currency,
                },
            )
            logger.info(f"Created Stripe Checkout Session: {session.id}")
            return session.url, reference, session.id
        except stripe.error.StripeError as e:
            # Stripe's own exception types carry a human-readable .user_message
            # or str(e) — e.g. "Amount must be at least R10.00" or "No such
            # currency: 'xyz'". This is exactly the detail that was being
            # thrown away before.
            err = getattr(e, "user_message", None) or str(e)
            logger.error(f"Stripe init error ({type(e).__name__}): {err}")
            return None, None, f"Stripe error: {err}"
        except Exception as e:
            logger.error(f"Stripe init error: {str(e)}")
            return None, None, f"Could not reach Stripe: {e}"

    def verify_flutterwave_payment(self, reference: str) -> Dict:
        flutterwave_secret_key = os.getenv("FLUTTERWAVE_SECRET_KEY")
        if not flutterwave_secret_key:
            return {"success": False, "error": "Flutterwave not configured"}
        headers = {
            "Authorization": f"Bearer {flutterwave_secret_key}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.get(
                # Numeric id -> /transactions/{id}/verify. Our own tx_ref (a string) must use the
                # by-reference endpoint, otherwise Flutterwave cannot find it.
                (f"{self.flutterwave_base_url}/transactions/{reference}/verify"
                 if str(reference).isdigit()
                 else f"{self.flutterwave_base_url}/transactions/verify_by_reference?tx_ref={quote(str(reference), safe='')}"),
                headers=headers,
                timeout=30,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    payment_data = data.get("data") or {}
                    fw_status = str(payment_data.get("status") or "").lower()
                    # The envelope "status":"success" only means the API call worked.
                    # The PAYMENT status is data.status.
                    if fw_status not in ("successful", "completed"):
                        return {
                            "success": False,
                            "pending": fw_status in ("pending", "processing", "new"),
                            "status": fw_status,
                            "error": f"Payment status: {fw_status or 'unknown'}",
                        }
                    returned_ref = str(payment_data.get("tx_ref") or "")
                    # When verifying by numeric transaction id, tx_ref is not our lookup key.
                    if not str(reference).isdigit() and returned_ref != str(reference):
                        logger.error(
                            f"Flutterwave reference mismatch: asked {reference}, got {returned_ref}"
                        )
                        return {"success": False, "error": "Reference mismatch"}
                    return {
                        "success": True,
                        "status": fw_status,
                        "amount": float(payment_data.get("amount", 0)),
                        "currency": payment_data.get("currency", "NGN"),
                        "reference": returned_ref,
                        "customer": payment_data.get("customer", {}),
                    }
            return {"success": False, "error": "Verification failed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def verify_paystack_payment(self, reference: str) -> Dict:
        if not self.api_key:
            return {"success": False, "error": "Paystack not configured"}
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.get(
                f"{self.paystack_base_url}/transaction/verify/{reference}",
                headers=headers,
                timeout=30,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("status"):
                    payment_data = data.get("data") or {}
                    ps_status = str(payment_data.get("status") or "").lower()
                    # data["status"] is True whenever the API call worked, even for
                    # abandoned/failed payments. The payment itself is data.status.
                    if ps_status != "success":
                        return {
                            "success": False,
                            "pending": ps_status in ("ongoing", "pending", "processing", "queued", "abandoned"),
                            "status": ps_status,
                            "error": f"Payment status: {ps_status or 'unknown'}",
                        }
                    returned_ref = str(payment_data.get("reference") or "")
                    if returned_ref != str(reference):
                        logger.error(
                            f"Paystack reference mismatch: asked {reference}, got {returned_ref}"
                        )
                        return {"success": False, "error": "Reference mismatch"}
                    return {
                        "success": True,
                        "status": ps_status,
                        "amount": float(payment_data.get("amount", 0)) / 100,
                        "currency": payment_data.get("currency", "NGN"),
                        "reference": returned_ref,
                        "customer": payment_data.get("customer", {}),
                        "authorization": payment_data.get("authorization") or None,
                    }
            return {"success": False, "error": "Verification failed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def verify_stripe_payment(self, session_id: str) -> Dict:
        if not STRIPE_AVAILABLE:
            return {"success": False, "error": "Stripe library not installed"}

        try:
            logger.info(f"Verifying Stripe session: {session_id}")
            session = stripe.checkout.Session.retrieve(session_id)
            logger.info(
                f"Stripe session retrieved: status={session.payment_status}, id={session.id}"
            )

            if session.payment_status in ("paid", "no_payment_required"):
                return {
                    "success": True,
                    "status": "success",
                    "reference": session_id,
                    "amount": (
                        float(session.amount_total)
                        if str(session.currency).lower() in STRIPE_ZERO_DECIMAL
                        else float(session.amount_total) / 100
                    ),
                    "currency": session.currency.upper(),
                    "customer": session.customer_details,
                    "metadata": session.metadata,
                }
            else:
                return {
                    "success": False,
                    "pending": session.payment_status == "unpaid" and getattr(session, "status", "") != "expired",
                    "status": session.payment_status,
                    "error": f"Payment status: {session.payment_status}",
                }
        except stripe.error.InvalidRequestError as e:
            logger.error(f"Stripe invalid request error: {e}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Stripe verification error: {str(e)}")
            return {"success": False, "error": str(e)}

    def create_payment_intent(
        self,
        amount: float,
        currency: str = "NGN",
        description: str = "Top-up",
        metadata: Optional[Dict] = None,
        email: Optional[str] = None,
        return_url: Optional[str] = None,
        provider: str = None,
    ) -> Dict:
        currency = currency.upper()

        if not email:
            email = os.getenv("DEFAULT_PAYMENT_EMAIL", "customer@net365.com")
            logger.warning(f"No email for payment, using default: {email}")

        logger.info(
            f"Creating payment intent: amount={amount}, currency={currency}, provider={provider}, email={email}"
        )

        if provider == "paystack":
            auth_url, reference, error_detail = self.init_paystack_payment(
                email=email, amount=amount, return_url=return_url
            )
            if auth_url:
                return {
                    "success": True,
                    "authorization_url": auth_url,
                    "reference": reference,
                    "provider": "paystack",
                    "currency": currency,
                    "amount": amount,
                }
            return {
                "success": False,
                "error": error_detail or "Failed to initialize Paystack payment",
            }

        elif provider == "flutterwave":
            auth_url, reference, error_detail = self.init_flutterwave_payment(
                email=email, amount=amount, currency=currency, return_url=return_url
            )
            if auth_url:
                return {
                    "success": True,
                    "authorization_url": auth_url,
                    "reference": reference,
                    "provider": "flutterwave",
                    "currency": currency,
                    "amount": amount,
                }
            return {
                "success": False,
                "error": error_detail or "Failed to initialize Flutterwave payment",
            }

        elif provider == "stripe":
            if not STRIPE_AVAILABLE:
                return {"success": False, "error": "Stripe library not installed"}
            auth_url, reference, session_id_or_error = self.init_stripe_payment(
                email=email,
                amount=amount,
                currency=currency,
                reference=generate_reference("STR"),
                return_url=return_url,
                description=description,
            )
            if auth_url:
                return {
                    "success": True,
                    "authorization_url": auth_url,
                    "checkout_url": auth_url,
                    "reference": reference,
                    "stripe_session_id": session_id_or_error,
                    "provider": "stripe",
                    "currency": currency,
                    "amount": amount,
                }
            return {
                "success": False,
                "error": session_id_or_error or "Failed to initialize Stripe payment",
            }

        else:
            return {"success": False, "error": f"Unsupported provider: {provider}"}


# ============ WEB INTERFACE ============
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    session,
    g,
    make_response,
    url_for,
    send_from_directory,
)

PAYMENT_COUNTRY_CONFIG = {
    # ── Africa ──────────────────────────────────────────────────────
    "NG": {"currency": "NGN", "provider": "paystack",    "alternatives": ["flutterwave", "stripe"]},
    "GH": {"currency": "GHS", "provider": "flutterwave", "alternatives": ["stripe"]},
    "KE": {"currency": "KES", "provider": "flutterwave", "alternatives": ["stripe"]},
    "ZA": {"currency": "ZAR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "UG": {"currency": "UGX", "provider": "flutterwave", "alternatives": []},
    "TZ": {"currency": "TZS", "provider": "flutterwave", "alternatives": []},

    # ── North America ───────────────────────────────────────────────
    "US": {"currency": "USD", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "CA": {"currency": "CAD", "provider": "stripe",      "alternatives": ["flutterwave"]},

    # ── Europe ──────────────────────────────────────────────────────
    "GB": {"currency": "GBP", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "EU": {"currency": "EUR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "FR": {"currency": "EUR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "DE": {"currency": "EUR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "IT": {"currency": "EUR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "ES": {"currency": "EUR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "NL": {"currency": "EUR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "BE": {"currency": "EUR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "AT": {"currency": "EUR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "IE": {"currency": "EUR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "PT": {"currency": "EUR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "CH": {"currency": "CHF", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "SE": {"currency": "SEK", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "NO": {"currency": "NOK", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "DK": {"currency": "DKK", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "PL": {"currency": "PLN", "provider": "stripe",      "alternatives": ["flutterwave"]},

    # ── Asia-Pacific ────────────────────────────────────────────────
    "AU": {"currency": "AUD", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "NZ": {"currency": "NZD", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "JP": {"currency": "JPY", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "SG": {"currency": "SGD", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "HK": {"currency": "HKD", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "MY": {"currency": "MYR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "TH": {"currency": "THB", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "ID": {"currency": "IDR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "PH": {"currency": "PHP", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "IN": {"currency": "INR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "KR": {"currency": "KRW", "provider": "stripe",      "alternatives": ["flutterwave"]},

    # ── Middle East ─────────────────────────────────────────────────
    "AE": {"currency": "AED", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "SA": {"currency": "SAR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "QA": {"currency": "QAR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "KW": {"currency": "KWD", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "BH": {"currency": "BHD", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "OM": {"currency": "OMR", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "IL": {"currency": "ILS", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "TR": {"currency": "TRY", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "EG": {"currency": "EGP", "provider": "stripe",      "alternatives": ["flutterwave"]},

    # ── Latin America ───────────────────────────────────────────────
    "BR": {"currency": "BRL", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "MX": {"currency": "MXN", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "AR": {"currency": "ARS", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "CL": {"currency": "CLP", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "CO": {"currency": "COP", "provider": "stripe",      "alternatives": ["flutterwave"]},
    "PE": {"currency": "PEN", "provider": "stripe",      "alternatives": ["flutterwave"]},
}

GATEWAY_CURRENCIES = {
    "paystack": ["NGN"],

    "stripe": [
        # Africa
        "ZAR",
        # North America
        "USD", "CAD",
        # Europe
        "GBP", "EUR", "CHF", "SEK", "NOK", "DKK", "PLN",
        # Asia-Pacific
        "AUD", "NZD", "JPY", "SGD", "HKD", "MYR", "THB",
        "IDR", "PHP", "INR", "KRW",
        # Middle East
        "AED", "SAR", "QAR", "KWD", "BHD", "OMR", "ILS", "TRY", "EGP",
        # Latin America
        "BRL", "MXN", "ARS", "CLP", "COP", "PEN",
        # NGN also supported by Stripe for international cards
        "NGN",
    ],

    "flutterwave": [
        "NGN", "GHS", "KES", "ZAR", "UGX", "TZS",
        "USD", "EUR", "GBP",
    ],

    "wallet": list(SUPPORTED_CURRENCIES.keys()),
}


def get_request_country(request):
    for value in (
        request.headers.get("CF-IPCountry"),
        request.headers.get("X-Country-Code"),
    ):
        if value and len(value.strip()) == 2:
            return value.strip().upper()
    return "NG"


def recommended_payment(country):
    country = (country or "NG").upper()
    return {
        "country": country,
        **PAYMENT_COUNTRY_CONFIG.get(
            country,
            # Unlisted country: use its own currency via Stripe when we know it. Defaulting
            # everyone to NGN/Paystack was what made foreign numbers show naira.
            ({"currency": COUNTRY_CURRENCY_MAP.get(country), "provider": "stripe", "alternatives": ["flutterwave"]}
             if COUNTRY_CURRENCY_MAP.get(country) in SUPPORTED_CURRENCIES
             else {"currency": "NGN", "provider": "paystack", "alternatives": ["stripe"]}),
        ),
    }


_access_enrich_user = None


def sanitize_user(user):
    if not user:
        return None
    clean = dict(user)
    for key in ("password_hash", "password", "session_token", "token"):
        clean.pop(key, None)
    try:
        from net365_identity import profile_status as _ps
        if clean.get("id"):
            clean["profile"] = _ps(clean["id"])
    except Exception:
        pass
    _enrich = globals().get("_access_enrich_user")
    if _enrich:
        try:
            clean = _enrich(clean)
        except Exception:
            pass
    return clean


def _get_request_token():
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        return token.strip()
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


def get_authenticated_user():
    token = _get_request_token()
    if not token:
        return None
    try:
        session_data = db.get_session(token)
    except Exception:
        return None
    if not session_data:
        return None
    user_id = session_data.get("user_id") if isinstance(session_data, dict) else None
    if not user_id:
        return None
    try:
        return db.get_user(user_id)
    except Exception:
        return None



                
                
                

               
               

        # ============ ADMIN: ALL RECEIPT ADS ============
        @self.app.route("/api/admin/receipt-ads/all", methods=["GET"])
        @admin_required
        def admin_list_all_receipt_ads():
            """Get all receipt ads for admin."""
            limit = min(request.args.get("limit", 50, type=int), 100)
            offset = max(request.args.get("offset", 0, type=int), 0)
            campaigns = db.get_all_sponsored_campaigns(limit, offset)
            return jsonify(
                {"success": True, "campaigns": campaigns, "count": len(campaigns)}
            )

        # ============ ADD THESE ROUTES TO setup_routes() ============
        # Place them after the existing admin routes (around where you have admin_create_user, etc.)
        @self.app.route("/api/debug/session", methods=["GET"])
        @admin_required
        def debug_session():
            """Debug endpoint — shows what the server sees about the current session."""
            token = _get_request_token()
            result = {
                "cookie_name": SESSION_COOKIE_NAME,
                "cookie_received": bool(token),
                "session_found_in_db": False,
                "user_id": None,
                "all_cookies": list(request.cookies.keys()),
                "config": {
                    "SESSION_COOKIE_SECURE": SESSION_COOKIE_SECURE,
                    "SESSION_COOKIE_SAMESITE": SESSION_COOKIE_SAMESITE,
                    "SESSION_COOKIE_DOMAIN": SESSION_COOKIE_DOMAIN,
                    "FRONTEND_URL": FRONTEND_URL,
                    "PUBLIC_URL": PUBLIC_URL,
                    "PAYMENT_SERVICE_URL": PAYMENT_SERVICE_URL,
                },
                "request_host": request.host,
                "request_origin": request.headers.get("Origin"),
                "request_referer": request.headers.get("Referer"),
            }
            if token:
                session_data = db.get_session(token)
                if session_data:
                    result["session_found_in_db"] = True
                    result["user_id"] = session_data.get("user_id")
            return jsonify(result)
    
        # ============ PROMOTIONS MANAGEMENT API ============
        @self.app.route("/api/admin/promotions", methods=["GET"])
        @admin_required
        def admin_get_promotions():
            """Get all promotions with pagination."""
            limit = min(request.args.get("limit", 50, type=int), 100)
            offset = max(request.args.get("offset", 0, type=int), 0)
            promotions = db.get_all_promotions(limit, offset)
            return jsonify({"success": True, "promotions": promotions})

        @self.app.route("/api/admin/promotions", methods=["POST"])
        @admin_required
        def admin_create_promotion():
            """Create a new promotion."""
            data = request.json or {}

            required = ["name", "title", "body"]
            missing = [f for f in required if not data.get(f)]
            if missing:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"Missing required fields: {', '.join(missing)}",
                        }
                    ),
                    400,
                )

            promo_id = db.create_promotion(
                name=data.get("name"),
                title=data.get("title"),
                body=data.get("body"),
                cta_text=data.get("cta_text"),
                cta_url=data.get("cta_url"),
                promo_type=data.get("promo_type", "standard"),
                category=data.get("category", "general"),
                icon=data.get("icon", "🎁"),
                brand_color=data.get("brand_color", "#4f46e5"),
                background_color=data.get("background_color", "#f5f3ff"),
                text_color=data.get("text_color", "#1e293b"),
                active=data.get("active", True),
                priority=data.get("priority", 0),
                start_date=data.get("start_date"),
                end_date=data.get("end_date"),
                target_tx_type=data.get("target_tx_type"),
                target_min_amount=data.get("target_min_amount"),
                target_max_amount=data.get("target_max_amount"),
                target_customer_type=data.get("target_customer_type"),
                target_hour_start=data.get("target_hour_start"),
                target_hour_end=data.get("target_hour_end"),
                target_days=data.get("target_days"),
                max_impressions=data.get("max_impressions"),
                max_clicks=data.get("max_clicks"),
                metadata=data.get("metadata"),
                created_by=(
                    g.current_user.get("id") if hasattr(g, "current_user") else None
                ),
            )

            if promo_id:
                return jsonify(
                    {
                        "success": True,
                        "promotion_id": promo_id,
                        "message": "Promotion created successfully",
                    }
                )
            return (
                jsonify({"success": False, "error": "Failed to create promotion"}),
                500,
            )

        @self.app.route("/api/admin/promotions/<int:promo_id>", methods=["GET"])
        @admin_required
        def admin_get_promotion(promo_id):
            """Get a specific promotion."""
            promo = db.get_promotion(promo_id)
            if not promo:
                return jsonify({"success": False, "error": "Promotion not found"}), 404
            return jsonify({"success": True, "promotion": promo})

        @self.app.route("/api/admin/promotions/<int:promo_id>", methods=["PUT"])
        @admin_required
        def admin_update_promotion(promo_id):
            """Update a promotion."""
            data = request.json or {}
            result = db.update_promotion(promo_id, **data)
            if result:
                return jsonify(
                    {"success": True, "message": "Promotion updated successfully"}
                )
            return (
                jsonify({"success": False, "error": "Failed to update promotion"}),
                500,
            )

        @self.app.route("/api/admin/promotions/<int:promo_id>", methods=["DELETE"])
        @admin_required
        def admin_delete_promotion(promo_id):
            """Delete a promotion."""
            if db.delete_promotion(promo_id):
                return jsonify({"success": True, "message": "Promotion deleted"})
            return jsonify({"success": False, "error": "Promotion not found"}), 404

        # ============ BRAND COLORS MANAGEMENT ============
        @self.app.route("/api/admin/brand-colors", methods=["GET"])
        @admin_required
        def admin_get_brand_colors():
            """Get all brand colors."""
            brands = db.get_all_brand_colors()
            return jsonify({"success": True, "brands": brands})

        @self.app.route("/api/admin/brand-colors", methods=["POST"])
        @admin_required
        def admin_upsert_brand_colors():
            """Create or update brand colors."""
            data = request.json or {}
            required = ["advertiser_id", "advertiser_name", "primary_color"]
            missing = [f for f in required if not data.get(f)]
            if missing:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"Missing required fields: {', '.join(missing)}",
                        }
                    ),
                    400,
                )

            result = db.upsert_brand_colors(
                advertiser_id=data["advertiser_id"],
                advertiser_name=data["advertiser_name"],
                primary_color=data["primary_color"],
                secondary_color=data.get("secondary_color"),
                accent_color=data.get("accent_color"),
                text_color=data.get("text_color"),
                background_color=data.get("background_color"),
                logo_url=data.get("logo_url"),
            )

            if result:
                return jsonify({"success": True, "message": "Brand colors saved"})
            return (
                jsonify({"success": False, "error": "Failed to save brand colors"}),
                500,
            )

        @self.app.route("/api/admin/brand-colors/<advertiser_id>", methods=["DELETE"])
        @admin_required
        def admin_delete_brand_colors(advertiser_id):
            """Delete brand colors for an advertiser."""
            conn = db.get_db_connection()
            c = conn.cursor()
            try:
                c.execute(
                    "DELETE FROM brand_colors WHERE advertiser_id = ?", (advertiser_id,)
                )
                conn.commit()
                if c.rowcount > 0:
                    return jsonify({"success": True, "message": "Brand colors deleted"})
                return jsonify({"success": False, "error": "Brand not found"}), 404
            except Exception as e:
                logger.error(f"Failed to delete brand colors: {e}")
                return jsonify({"success": False, "error": str(e)}), 500
            finally:
                conn.close()



def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = get_authenticated_user()
        if not user:
            return jsonify({"success": False, "error": "Authentication required"}), 401
        if (user.get("account_status") or "active") in ("blocked", "deleted"):
            # Defense-in-depth: even if an existing session wasn't explicitly killed when
            # the account was blocked, a blocked account should never pass this gate.
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "This account has been blocked.",
                        "error_code": "ACCOUNT_BLOCKED",
                    }
                ),
                403,
            )
        g.current_user = user
        g.current_user_id = user.get("id")
        return func(*args, **kwargs)

    return wrapper


def email_verified_required(func):
    """Blocks money-moving actions until the account's email is verified — but only when
    EMAIL_VERIFICATION_REQUIRED is turned on (see the toggle near ADMIN_SECRET above).
    When off, this is a no-op. Must be stacked UNDER @login_required (so it runs after
    g.current_user_id is set):
        @login_required
        @email_verified_required
        def some_route(): ...
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Verified mobile number: every money route that already checks the email also checks this.
        try:
            from net365_identity import gate_error as _id_gate
            _ge = _id_gate(getattr(g, "current_user_id", None))
            if _ge:
                return jsonify(_ge[0]), _ge[1]
        except ImportError:
            pass
        if not EMAIL_VERIFICATION_REQUIRED:
            return func(*args, **kwargs)
        user_id = getattr(g, "current_user_id", None)
        try:
            from net365_whatsapp import is_guest_user
            if user_id and is_guest_user(user_id):
                return func(*args, **kwargs)
        except Exception:
            pass
        if not user_id or not db.is_user_verified(user_id):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Please verify your email before doing this. Check your inbox for a verification code, or request a new one.",
                        "error_code": "EMAIL_NOT_VERIFIED",
                    }
                ),
                403,
            )
        return func(*args, **kwargs)

    return wrapper


def set_auth_cookie(response, token):
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite=SESSION_COOKIE_SAMESITE,
        domain=SESSION_COOKIE_DOMAIN,
        path="/",
    )
    return response


def require_owned_transaction(reference, user_id):
    tx = db.get_transaction(reference) if reference else None
    if not tx:
        return None, (
            jsonify({"success": False, "error": "Transaction not found"}),
            404,
        )
    owner = tx.get("user_id")
    if owner is not None and str(owner) != str(user_id):
        return None, (
            jsonify({"success": False, "error": "Transaction not found"}),
            404,
        )
    return tx, None


def parse_user_agent(ua_string: str) -> Dict[str, str]:
    """Lightweight User-Agent parser — no external dependency. Covers the common cases
    well enough for visitor analytics; not meant to be exhaustive like a full UA database.
    """
    ua = (ua_string or "").lower()

    if "ipad" in ua:
        device_type = "Tablet"
    elif "tablet" in ua or ("android" in ua and "mobile" not in ua):
        device_type = "Tablet"
    elif any(k in ua for k in ("mobi", "iphone", "android")):
        device_type = "Mobile"
    elif not ua:
        device_type = "Unknown"
    else:
        device_type = "Desktop"

    if "windows" in ua:
        os_name = "Windows"
    elif "mac os" in ua or "macintosh" in ua:
        os_name = "macOS"
    elif "iphone" in ua or "ipad" in ua or "ios" in ua:
        os_name = "iOS"
    elif "android" in ua:
        os_name = "Android"
    elif "linux" in ua:
        os_name = "Linux"
    elif not ua:
        os_name = "Unknown"
    else:
        os_name = "Other"

    if "edg/" in ua or "edga" in ua or "edgios" in ua:
        browser = "Edge"
    elif "opr/" in ua or "opera" in ua:
        browser = "Opera"
    elif "chrome" in ua or "crios" in ua:
        browser = "Chrome"
    elif "fxios" in ua or "firefox" in ua:
        browser = "Firefox"
    elif "safari" in ua:
        browser = "Safari"
    elif not ua:
        browser = "Unknown"
    else:
        browser = "Other"

    return {"device_type": device_type, "os": os_name, "browser": browser}


# Device model parsing lives in net365_ua.py (imported at the top). Do not re-define it here.


def get_client_ip() -> str:
    # Behind Cloudflare, X-Forwarded-For can start with a client-supplied value, while
    # CF-Connecting-IP is set by Cloudflare itself.
    cf_ip = request.headers.get("CF-Connecting-IP", "").strip()
    if cf_ip:
        return cf_ip
    forwarded = request.headers.get("X-Forwarded-For", "")
    parts = [p.strip() for p in forwarded.split(",") if p.strip()]
    for p in parts:                       # first public address: skips internal proxy hops (10.x, 100.64.x ...)
        if is_public_ip(p):
            return p
    real = request.headers.get("X-Real-IP", "").strip()
    if real and is_public_ip(real):
        return real
    if parts:
        return parts[0]
    return request.remote_addr or "unknown"


# Page routes to log as visits. Deliberately NOT logging /api/* — this app polls its own
# APIs every few seconds per page load, so logging every API call would flood the table
# with noise rather than meaningful visit data.
VISITOR_TRACKED_PATHS = {"/", "/scheduler", "/analytics", "/business", "/utilities", "/giftcards"}




def log_page_visit():
    """Log one page visit + kick off background IP enrichment.

    Enrichment (org / ASN / ip_kind) runs asynchronously via IPIntel so a
    slow external lookup can never delay the response to the visitor.
    Bot classification is done inline from the User-Agent — it's pure
    string matching, no network, so it's cheap enough to do here.

    Device model detection combines:
      - Sec-CH-UA-Model client hint (modern Chrome/Edge on Android)
      - User-Agent parsing (Safari, Firefox, older Android, others)
    Apple never reveals exact models — iOS visitors always log as "iPhone"
    or "iPad", which is a hard limit set by Apple, not a bug here.
    """
    try:
        if request.path not in VISITOR_TRACKED_PATHS:
            return

        ua = request.headers.get("User-Agent", "")
        ua_info = parse_user_agent(ua)

        # NEW: extract the device model. Request object is passed so the
        # helper can read Sec-CH-UA-Model, which is the only way to
        # recover the model from modern Chrome. Returns "" when nothing
        # meaningful could be determined — the DB stores NULL in that case.
        try:
            device_model = parse_device_model(ua, request_obj=request) or None
        except Exception as e:
            # Never let model parsing break visitor logging.
            logger.debug(f"parse_device_model failed: {e}")
            logger.warning(f"parse_device_model failed: {e}", exc_info=True)
            device_model = None

        # Bot classification (offline, no network call)
        is_bot, bot_name = detect_bot(ua)

        user_id = None
        visitor_name = None
        try:
            user = get_authenticated_user()
            if user:
                user_id = user.get("id")
                visitor_name = user.get("full_name") or user.get("email")
        except Exception:
            pass

        ip = get_client_ip()

        # Build the payload once. If db.log_visitor doesn't yet accept the
        # new kwargs (device_model, is_bot, bot_name), we retry without
        # them below rather than losing the whole visit record.
        payload = {
            "user_id": user_id,
            "visitor_name": visitor_name,
            "ip_address": ip,
            "user_agent": ua,
            "device_type": ua_info["device_type"],
            "device_model": device_model,       # ← NEW
            "os_name": ua_info["os"],
            "browser": ua_info["browser"],
            "path": request.path,
            "referrer": request.headers.get("Referer", ""),
            "session_id": request.cookies.get(SESSION_COOKIE_NAME, ""),
            # Cloudflare headers — None (not "") when absent so the DB
            # stores a real NULL, which the aggregate queries filter on
            # (`country IS NOT NULL AND country != ''`).
            "country": request.headers.get("CF-IPCountry") or None,
            "city": request.headers.get("CF-IPCity") or None,
            "region": request.headers.get("CF-IPRegion") or None,
            "timezone": request.headers.get("CF-IPTimezone") or None,
            # --- bot classification ---
            "is_bot": 1 if is_bot else 0,
            "bot_name": bot_name,
        }

        try:
            db.log_visitor(**payload)
        except TypeError as e:
            logger.warning(
                f"db.log_visitor rejected new kwargs ({e}); retrying without "
                f"device_model/is_bot/bot_name — fix database.log_visitor signature."
            )
            for _k in ("device_model", "is_bot", "bot_name"):
                payload.pop(_k, None)
            db.log_visitor(**payload)

        # Fire-and-forget enrichment. Never blocks the request path.
        # IPIntel.enqueue() dedupes in-memory and short-circuits on cache hits,
        # so calling it on every visit is cheap.
        if ip and ip != "unknown":
            try:
                IPIntel.enqueue(ip)
            except Exception as e:
                # Enrichment failures must never break visitor logging.
                logger.debug(f"IPIntel.enqueue failed for {ip}: {e}")

            # Country / city fallback. Cloudflare's headers are missing when the site is
            # served directly from Railway, so resolve the location from the IP in the
            # background and write it onto this visit's row (never overwrites CF values).
            if not payload.get("country") or not payload.get("city"):
                try:
                    GeoResolver.enqueue(ip)
                except Exception as e:
                    logger.debug(f"GeoResolver.enqueue failed for {ip}: {e}")

    except TypeError as e:
        # A TypeError that reaches here means something other than the
        # new-kwargs mismatch — treat as a real bug.
        logger.error(f"Visitor logging signature mismatch (BUG): {e}", exc_info=True)
    except Exception as e:
        logger.warning(f"Visitor logging failed (non-fatal): {e}")

def _enrich_visit_rows(logs, max_ips=8, budget=5.0):
    """Resolve Organization / Kind / Country / City for the visitor rows being viewed, in parallel with a
    time budget. Background workers do the same thing, but this guarantees the admin sees data even when
    a worker thread died (for example after a gunicorn fork) or a lookup source was briefly down.
    Returns how many IPs were attempted."""
    try:
        todo = []
        for v in logs:
            ip = str(v.get("ip_address") or "")
            if not ip or ip.startswith("h:") or ip in todo:
                continue
            if not (v.get("org_name") and v.get("ip_kind") and v.get("city")):
                todo.append(ip)
            if len(todo) >= max_ips:
                break
        if not todo:
            return 0
        from concurrent.futures import ThreadPoolExecutor, wait

        def work(ip):
            try:
                IPIntel.lookup(ip)                    # writes org / ASN / kind (and city when known) onto every row of this IP
                geo = GeoResolver.lookup(ip)
                if geo:
                    GeoResolver.apply(ip, geo)
            except Exception as e:
                logger.debug(f"inline enrichment failed for {ip}: {e}")

        ex = ThreadPoolExecutor(max_workers=6)
        futs = [ex.submit(work, ip) for ip in todo]
        wait(futs, timeout=budget)
        ex.shutdown(wait=False)
        return len(todo)
    except Exception as e:
        logger.debug(f"_enrich_visit_rows failed: {e}")
        return 0


def admin_required(func):
    """Gates admin-only endpoints behind ADMIN_SECRET. Denies access by default if
    ADMIN_SECRET isn't set — an unset secret should never mean 'open to everyone'."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Header only: secrets in URLs end up in access logs, browser history and Referer headers.
        provided = request.headers.get("X-Admin-Secret", "")
        if not ADMIN_SECRET or not secrets.compare_digest(provided, ADMIN_SECRET):
            return jsonify({"success": False, "error": "Unauthorized"}), 401
        return func(*args, **kwargs)

    return wrapper


def _live_rates_block(currency):
    """Error text if a non-NGN payment must be refused because only stale fallback rates are available.
    REQUIRE_LIVE_RATES (default true) controls this; set false to accept fallback rates."""
    try:
        if str(currency or "NGN").upper() == "NGN":
            return None
        if os.getenv("REQUIRE_LIVE_RATES", "true").strip().lower() not in ("1", "true", "yes", "on"):
            return None
        if ExchangeRateService.rates_are_live():
            return None
    except Exception:
        return None
    logger.error(f"Refusing {currency} payment: exchange rates are not live (fallback only)")
    return "International top-ups are temporarily unavailable. Please try again shortly or pay in NGN."


def _env_float(name, default):
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return float(default)


def server_fee_for(service_amount, currency="NGN"):
    """THE fee rule (server-authoritative). Customer pays airtime + this fee.
    FEE_PERCENT (default 2.5) of the airtime; FEE_MIN_NGN (default 0) is a floor for NGN only."""
    pct = _env_float("FEE_PERCENT", 2.5)
    fee = float(service_amount) * pct / 100.0
    if str(currency or "").upper() == "NGN":
        fee = max(fee, _env_float("FEE_MIN_NGN", 0))
    return round(fee, 2)


def split_topup_amounts(data, total_amount, user_id=None):
    """Work out (service_amount, fee_amount) for a top-up. The SERVER owns the fee.

    `amount` is what the customer pays (airtime + fee). Reloadly must only ever receive the airtime
    part. If the client sends no service_amount we derive it from the total using the fee rule. If it
    does, the fee implied (total - service_amount) must cover the required fee, allowing only a small
    rounding tolerance plus, when a referral code was sent, the configured referral discount
    (REFERRAL_DISCOUNT_MAX, default 50). Anything less is refused, so a edited request cannot
    buy airtime without the fee.
    Returns (service_amount, fee_amount) or raises ValueError.
    """
    total_amount = round(float(total_amount), 2)
    currency = str((data or {}).get("currency") or "NGN").upper()
    raw = (data or {}).get("service_amount")
    if raw in (None, "", 0, "0"):
        # Invert total = service + fee(service). Exact for pure percent; refined for the NGN floor.
        pct = _env_float("FEE_PERCENT", 2.5)
        service_amount = round(total_amount / (1 + pct / 100.0), 2)
        if currency == "NGN":
            floor = _env_float("FEE_MIN_NGN", 0)
            if total_amount - service_amount < floor:
                service_amount = round(total_amount - floor, 2)
    else:
        service_amount = round(float(raw), 2)
    if service_amount <= 0 or service_amount > total_amount + 1e-9:
        raise ValueError("Invalid recharge amount or checkout total")
    fee_paid = round(total_amount - service_amount, 2)
    required = server_fee_for(service_amount, currency)
    allowed_discount = 0.0
    _code = str((data or {}).get("referral_code") or "").strip()
    if _code:
        # Only a real code that is not the buyer's own earns the discount allowance.
        try:
            _owner = db.get_referral_code_owner(_code)
        except Exception:
            _owner = None
        if _owner and (user_id is None or _owner.get("id") != user_id):
            allowed_discount = _env_float("REFERRAL_DISCOUNT_MAX", 50)
    if fee_paid + allowed_discount + 0.02 < required:
        logger.warning(
            f"FEE MISMATCH: total={total_amount} service={service_amount} paid_fee={fee_paid} "
            f"required={required} {currency}"
        )
        raise ValueError("Fee mismatch")
    return service_amount, fee_paid


_rate_table_ready = False
_rate_mem = {}
_rate_mem_lock = threading.Lock()


def _rate_limit_ip() -> str:
    """Client IP for throttling. On Railway the edge appends the real client address as the LAST
    X-Forwarded-For entry; earlier entries can be forged by the caller, so we never use them."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        last = forwarded.split(",")[-1].strip()
        if last:
            return last
    return request.remote_addr or "unknown"


def _rate_hit_db(key: str, window_seconds: int) -> int:
    """Fixed-window counter stored in SQLite, so every gunicorn worker (and restart) shares it."""
    global _rate_table_ready
    bucket = int(time.time() // window_seconds)
    conn = db.get_db_connection()
    try:
        if not _rate_table_ready:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS rate_limits ("
                "k TEXT NOT NULL, bucket INTEGER NOT NULL, hits INTEGER NOT NULL DEFAULT 0, "
                "PRIMARY KEY (k, bucket))"
            )
            _rate_table_ready = True
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO rate_limits (k, bucket, hits) VALUES (?, ?, 1) "
            "ON CONFLICT(k, bucket) DO UPDATE SET hits = hits + 1",
            (key, bucket),
        )
        hits = conn.execute(
            "SELECT hits FROM rate_limits WHERE k = ? AND bucket = ?", (key, bucket)
        ).fetchone()[0]
        if secrets.randbelow(200) == 0:  # occasional cleanup of old windows
            conn.execute("DELETE FROM rate_limits WHERE bucket < ?", (bucket - 2,))
        conn.execute("COMMIT")
        return int(hits)
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


def _rate_hit_memory(key: str, window_seconds: int) -> int:
    now = time.time()
    with _rate_mem_lock:
        arr = [t for t in _rate_mem.get(key, []) if now - t < window_seconds]
        arr.append(now)
        _rate_mem[key] = arr
        return len(arr)


def rate_limit(max_requests=10, window_seconds=60):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = f"{_rate_limit_ip()}|{func.__name__}"
            try:
                hits = _rate_hit_db(key, window_seconds)
            except Exception as e:  # never take an endpoint down because the limiter failed
                logger.warning(f"rate_limit: shared store unavailable ({e}); using in-memory counter")
                hits = _rate_hit_memory(key, window_seconds)
            if hits > max_requests:
                resp = jsonify({"success": False, "error": "Too many requests. Please slow down and try again shortly."})
                resp.headers["Retry-After"] = str(window_seconds)
                return resp, 429
            return func(*args, **kwargs)

        return wrapper

    return decorator


# Routes that move customer wallet money. Blocked server-side when WALLET_ENABLED is false, because
# hiding a button in the UI does not stop someone calling the API directly.
_WALLET_BLOCKED_PATHS = (
    "/api/wallet/fund",
    "/api/wallet/utility",
    "/api/receipt-ads/campaigns",
)


def _wallet_policy_guard():
    """before_request: enforce wallet / transfer policy for every API call."""
    if request.method not in ("POST", "PUT", "PATCH") or not request.path.startswith("/api/"):
        return None
    path = request.path
    if path.rstrip("/") == "/api/wallet/transfer" and not WALLET_TRANSFERS_ENABLED:
        return jsonify({"success": False, "code": "TRANSFERS_DISABLED",
                        "error": "Wallet transfers are not available."}), 403
    if WALLET_ENABLED:
        return None
    blocked = any(path.startswith(p) for p in _WALLET_BLOCKED_PATHS)
    if not blocked and path.startswith("/api/bulk/recharge"):
        # Bulk recharge pays from the wallet unless a gateway is named (it may arrive as a form field
        # or JSON). Gateway-paid bulk recharges stay available.
        body = request.get_json(silent=True)
        method = request.form.get("payment_method") or (
            body.get("payment_method") if isinstance(body, dict) else None
        ) or "wallet"
        blocked = str(method).strip().lower() == "wallet"
    if not blocked:
        body = request.get_json(silent=True)
        if isinstance(body, dict):
            method = str(body.get("provider") or body.get("payment_method") or "").strip().lower()
            blocked = method == "wallet"
    if blocked:
        return jsonify({"success": False, "code": "WALLET_DISABLED",
                        "error": "Wallet payments are not available right now. Please pay by card or bank transfer."}), 403
    return None


def _purchase_limit_error(user_id, amount, currency, per_tx_amount=None):
    """Return an error string if this payment would break the per-transaction or daily cap (NGN only).
    per_tx_amount: size to test against the per-transaction cap when it differs from `amount`
    (a cart is several deliveries paid at once: each item is checked per-transaction, the whole
    cart counts toward the daily cap)."""
    if str(currency or "NGN").upper() != "NGN":
        return None
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return "Invalid amount"
    _tx_size = float(per_tx_amount) if per_tx_amount is not None else amount
    if LIMIT_PER_TX_NGN > 0 and _tx_size > LIMIT_PER_TX_NGN:
        return f"During our launch period the maximum per transaction is ₦{LIMIT_PER_TX_NGN:,.0f}."
    if LIMIT_DAILY_NGN > 0:
        try:
            conn = db.get_db_connection()
            try:
                row = conn.execute(
                    "SELECT COALESCE(SUM(amount), 0) FROM transactions "
                    "WHERE user_id = ? AND UPPER(COALESCE(currency,'NGN')) = 'NGN' "
                    "AND created_at >= datetime('now', '-1 day') "
                    "AND COALESCE(tx_type,'') != 'cart' "
                    "AND status IN ('pending','paid','processing','fulfilled')",
                    (user_id,),
                ).fetchone()
            finally:
                conn.close()
            used = float(row[0] or 0)
            if used + amount > LIMIT_DAILY_NGN:
                left = max(0.0, LIMIT_DAILY_NGN - used)
                return (f"Daily limit reached. During our launch period you can spend up to "
                        f"₦{LIMIT_DAILY_NGN:,.0f} per 24 hours (₦{left:,.0f} left).")
        except Exception as e:
            logger.warning(f"daily limit check failed for user {user_id}: {e}")
    return None


# ============ SAFE API RESPONSE DECORATOR ============
def safe_api_response(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"API error in {func.__name__}: {str(e)}", exc_info=True)
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "An internal error occurred. Please try again later.",
                        "reference": generate_reference("ERR"),
                    }
                ),
                500,
            )

    return wrapper


# ============ UTILITY FALLBACK BILLERS ============
FALLBACK_BILLERS = [
    {
        "id": 49,
        "name": "MTN Nigeria",
        "type": "AIRTIME_TOPUP",
        "countryISOCode": "NG",
        "billerId": 49,
    },
    {
        "id": 50,
        "name": "Glo Nigeria",
        "type": "AIRTIME_TOPUP",
        "countryISOCode": "NG",
        "billerId": 50,
    },
    {
        "id": 51,
        "name": "Airtel Nigeria",
        "type": "AIRTIME_TOPUP",
        "countryISOCode": "NG",
        "billerId": 51,
    },
    {
        "id": 52,
        "name": "9mobile Nigeria",
        "type": "AIRTIME_TOPUP",
        "countryISOCode": "NG",
        "billerId": 52,
    },
    {
        "id": 38,
        "name": "Eko Electric",
        "type": "ELECTRICITY_BILL_PAYMENT",
        "countryISOCode": "NG",
        "billerId": 38,
    },
    {
        "id": 39,
        "name": "Ikeja Electric",
        "type": "ELECTRICITY_BILL_PAYMENT",
        "countryISOCode": "NG",
        "billerId": 39,
    },
    {
        "id": 40,
        "name": "Kaduna Electric",
        "type": "ELECTRICITY_BILL_PAYMENT",
        "countryISOCode": "NG",
        "billerId": 40,
    },
    {
        "id": 41,
        "name": "Kano Electric",
        "type": "ELECTRICITY_BILL_PAYMENT",
        "countryISOCode": "NG",
        "billerId": 41,
    },
    {
        "id": 42,
        "name": "Abuja Electric",
        "type": "ELECTRICITY_BILL_PAYMENT",
        "countryISOCode": "NG",
        "billerId": 42,
    },
    {
        "id": 53,
        "name": "DSTV",
        "type": "CABLE_BILL_PAYMENT",
        "countryISOCode": "NG",
        "billerId": 53,
    },
    {
        "id": 54,
        "name": "GOtv",
        "type": "CABLE_BILL_PAYMENT",
        "countryISOCode": "NG",
        "billerId": 54,
    },
]


# ============ NIGERIAN NETWORK PREFIX LOOKUP ============
# Fallback for when Reloadly's auto-detect rejects a number (common in sandbox,
# where placeholder numbers like 2348000001000 aren't accepted). Maps Nigerian
# mobile prefixes to their Reloadly operator IDs.
NIGERIAN_PREFIX_TO_OPERATOR = {
    # MTN Nigeria (operator 49): 0803, 0806, 0703, 0706, 0813, 0816, 0810, 0814, 0903, 0906, 0913, 0916
    "803": 49, "806": 49, "703": 49, "706": 49, "813": 49, "816": 49,
    "810": 49, "814": 49, "903": 49, "906": 49, "913": 49, "916": 49,
    # Glo Nigeria (operator 50): 0805, 0807, 0705, 0815, 0811, 0905, 0915
    "805": 50, "807": 50, "705": 50, "815": 50, "811": 50, "905": 50, "915": 50,
    # Airtel Nigeria (operator 51): 0802, 0808, 0708, 0812, 0701, 0902, 0901, 0904, 0907, 0912
    "802": 51, "808": 51, "708": 51, "812": 51, "701": 51, "902": 51,
    "901": 51, "904": 51, "907": 51, "912": 51,
    # 9mobile Nigeria (operator 52): 0809, 0817, 0818, 0908, 0909
    "809": 52, "817": 52, "818": 52, "908": 52, "909": 52,
}

def detect_operator_from_prefix(phone: str, country_code: str = "NG"):
    """Local fallback: map a Nigerian phone number to its Reloadly operator ID
    using a static prefix table. Returns an operator dict or None."""
    if (country_code or "").upper() != "NG":
        return None
    clean = re.sub(r"[^0-9]", "", phone or "")
    while clean.startswith("0"):
        clean = clean[1:]
    if not clean.startswith("234"):
        return None
    # Strip leading 234, then take the next 3 digits as the prefix
    local = clean[3:]
    if len(local) < 3:
        return None
    prefix = local[:3]
    operator_id = NIGERIAN_PREFIX_TO_OPERATOR.get(prefix)
    if not operator_id:
        return None
    names = {49: "MTN Nigeria", 50: "Glo Nigeria", 51: "Airtel Nigeria", 52: "9mobile Nigeria"}
    return {"operatorId": operator_id, "id": operator_id, "name": names.get(operator_id, "Network operator")}

_NG_NET_LABEL = {"mtn": "MTN", "glo": "Glo", "airtel": "Airtel", "9mobile": "9mobile"}
_NG_OP_KEY = {49: "mtn", 50: "glo", 51: "airtel", 52: "9mobile"}


def _ng_network_key(operator_id=None, name=None):
    """mtn | glo | airtel | 9mobile, from an operator id or a name like 'Airtel Nigeria'; None if unknown."""
    try:
        k = _NG_OP_KEY.get(int(operator_id))
        if k:
            return k
    except (TypeError, ValueError):
        pass
    n = str(name or operator_id or "").lower()
    for key in ("9mobile", "etisalat", "mtn", "glo", "airtel"):
        if key in n:
            return "9mobile" if key == "etisalat" else key
    return None


def network_mismatch_error(phone, operator_id=None, operator_name=None, confirmed=False):
    """If a Nigerian number's prefix belongs to a different network than the one chosen, return a 409 payload.
    Numbers can be ported between networks, so the customer may confirm and continue (confirmed=True)."""
    if confirmed:
        return None
    try:
        chosen = _ng_network_key(operator_id, operator_name)
        det = detect_operator_from_prefix(re.sub(r"\D", "", str(phone or "")) if str(phone or "").startswith(("+", "234")) else
                                          "234" + re.sub(r"\D", "", str(phone or "")).lstrip("0"), "NG")
        detected = _NG_OP_KEY.get((det or {}).get("operatorId"))
    except Exception:
        return None
    if chosen and detected and chosen != detected:
        return {"success": False, "code": "NETWORK_MISMATCH", "chosen": _NG_NET_LABEL[chosen], "detected": _NG_NET_LABEL[detected],
                "detected_key": detected,
                "error": f"This number looks like an {_NG_NET_LABEL[detected]} number, but you selected {_NG_NET_LABEL[chosen]}. "
                         f"Recharging the wrong network sends your money to the wrong place. If the number was ported to {_NG_NET_LABEL[chosen]}, you can continue."}
    return None


# ============ EMAIL NOTIFICATION / TRANSACTION PROMOTION ENGINE ============
def _get_transaction_promo(
    user_id=None, reference=None, tx_type=None, amount=None, created_at=None
):
    """Return the same rotating/targeted promotion used by receipts."""
    try:
        if not user_id:
            return None
        receipt_number = (
            db.count_user_fulfilled_transactions(user_id, before_reference=reference)
            if reference
            else 1
        )
        try:
            tx_hour = datetime.fromisoformat(
                str(created_at or "").replace("Z", "")
            ).hour
        except (ValueError, TypeError):
            tx_hour = datetime.now().hour
        context = {
            "tx_type": str(tx_type or "").lower(),
            "amount": amount,
            "is_new_customer": receipt_number == 1,
            "hour": tx_hour,
        }
        promo = db.get_receipt_promo_for_slot(receipt_number, context=context)
        if promo and promo.get("cta_url") == "/settings#referral":
            user = db.get_user(user_id)
            if user and user.get("referral_code"):
                promo = dict(promo)
                promo["body"] = (
                    promo.get("body", "")
                    + f"\n\nYour referral code: {user['referral_code']}"
                )
        try:
            from net365_adcredits import email_promo as _boost_email_promo
            promo = _boost_email_promo(promo, {"user_id": user_id, "reference": reference,
                                               "tx_type": str(tx_type or "").lower(), "amount": amount})
        except Exception:
            pass
        return promo
    except Exception as e:
        logger.error(f"Transaction email promo lookup failed (non-fatal): {e}")
        return None


def _build_email_promo_html(promo):
    """
    Premium Net365 promotional card.
    Designed for notification emails, receipts, and service confirmations.
    """

    if not promo:
        return ""

    import html as _html

    title = _html.escape(str(promo.get("title") or "Discover more on Net365"))

    body = _html.escape(str(promo.get("body") or "")).replace("\n", "<br>")

    cta_text = _html.escape(str(promo.get("cta_text") or ""))

    cta_url = str(promo.get("cta_url") or "").strip()

    if cta_url.startswith("/"):
        cta_href = f"{FRONTEND_URL.rstrip('/')}{cta_url}"
    elif cta_url.startswith(("https://", "http://")):
        cta_href = cta_url
    else:
        cta_href = FRONTEND_URL

    cta_html = ""

    if cta_text:
        cta_html = f"""
        <table role="presentation" cellpadding="0" cellspacing="0"
               border="0" style="margin-top:24px;">
            <tr>
                <td style="border-radius:6px;background:#D95B1F;">
                    <a href="{_html.escape(cta_href, quote=True)}"
                       style="display:inline-block;
                              padding:13px 25px;
                              font-family:Arial,sans-serif;
                              font-size:13px;
                              font-weight:bold;
                              letter-spacing:0.3px;
                              color:#FFFFFF;
                              text-decoration:none;
                              border-radius:6px;">
                        {cta_text} &nbsp; →
                    </a>
                </td>
            </tr>
        </table>
        """

    return f"""
    <table role="presentation" width="100%" cellpadding="0"
           cellspacing="0" border="0"
           style="margin-top:30px;">

        <tr>
            <td style="background:#241713;
                       border-radius:12px;
                       padding:30px 28px;
                       border:1px solid #5A3528;">

                <div style="font-family:Arial,sans-serif;
                            font-size:10px;
                            font-weight:bold;
                            letter-spacing:2px;
                            color:#E8A06E;
                            text-transform:uppercase;
                            margin-bottom:14px;">
                    NET365 EXCLUSIVE
                </div>

                <div style="font-family:Georgia,serif;
                            font-size:25px;
                            line-height:1.25;
                            font-weight:bold;
                            color:#FFF9F2;
                            margin-bottom:14px;">
                    {title}
                </div>

                <div style="font-family:Arial,sans-serif;
                            font-size:14px;
                            line-height:1.7;
                            color:#E8D8C5;">
                    {body}
                </div>

                {cta_html}

            </td>
        </tr>

    </table>
    """

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr  # <-- Add this import


def send_branded_email(to_email, subject, html_body, text_body=None, from_name=None, from_email=None, reply_to=None):
    """Sends a fully custom HTML email and WAITS for the provider's answer. Returns (ok, error_text).

    If the provider refuses the requested sender (the usual cause is a sender address that is not verified for the sending
    domain), it retries once with the standard sender (FROM_EMAIL), keeping the display name and the Reply-To. Never raises."""
    smtp_host = os.getenv("SMTP_HOST", "smtp.mailgun.org")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    if not _https_email_configured() and (not smtp_user or not smtp_password):
        return False, "no email provider configured (set RESEND_API_KEY, or MAILGUN_API_KEY + MAILGUN_DOMAIN, or SMTP_*)"
    std_from = os.getenv("FROM_EMAIL") or smtp_user or f"support@{os.getenv('MAILGUN_DOMAIN') or 'net365co.com'}"
    from_email = (from_email or std_from).strip()
    from_name = from_name or os.getenv("FROM_NAME", "Net365 Support")
    reply_to = reply_to or os.getenv("REPLY_TO") or from_email
    subject = _clean_subject(subject)
    senders = [from_email] + ([std_from] if std_from.lower() != from_email.lower() else [])
    last_err = None
    for addr in senders:
        try:
            if _https_email_configured():
                res = {}
                if _send_via_https_provider(formataddr((from_name, addr)), to_email, subject, html_body, None, None, res, text_body, reply_to):
                    return True, None
                last_err = str(res.get("error") or "the email provider did not accept the message")
            else:
                msg = MIMEMultipart("alternative")
                msg["From"] = formataddr((from_name, addr))
                msg["To"] = to_email
                msg["Subject"] = subject
                msg["Reply-To"] = reply_to
                if text_body:
                    msg.attach(MIMEText(text_body, "plain"))
                msg.attach(MIMEText(html_body, "html"))
                if smtp_port == 465:
                    with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                        server.login(smtp_user, smtp_password)
                        server.send_message(msg)
                else:
                    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                        server.starttls()
                        server.login(smtp_user, smtp_password)
                        server.send_message(msg)
                return True, None
        except Exception as e:
            last_err = str(e)[:300]
        logger.warning(f"Email to {to_email} refused with sender {addr}: {last_err}")
    return False, last_err


def _welcome_content(first_name):
    """(subject, html, text) of the CEO welcome email."""
    import html as _html
    name = (first_name or "there").strip() or "there"
    safe_name = _html.escape(name)
    subject = f"Welcome to Net365, {name}!"
    html_body = f"""<!DOCTYPE html>
<html><body style="font-family:Arial,sans-serif;background:#f8fafc;padding:24px;">
  <div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:12px;
              border:1px solid #e2e8f0;overflow:hidden;">
    <div style="background:linear-gradient(145deg,#E53935 0%,#991B1B 100%);
                padding:28px;text-align:center;color:#fff;">
      <div style="font-size:26px;font-weight:800;letter-spacing:1px;">NET365</div>
      <div style="font-size:11px;letter-spacing:2px;opacity:.85;margin-top:4px;">
        CONNECT · TRANSACT · GROW
      </div>
    </div>
    <div style="padding:28px;color:#1e293b;line-height:1.7;font-size:15px;">
      <p>Hi {safe_name},</p>
      <p>Welcome to <strong>Net365</strong>.</p>
      <p>I'm Chijioke C. Igbokwe, Founder &amp; CEO of Net365 Communications, and I
         personally want to thank you for joining us.</p>
      <p>We started Net365 with a simple mission: to make digital services easier to
         access, simpler to manage, and available to individuals and businesses
         wherever they are.</p>
      <p><strong>Through your new account, you can instantly access:</strong></p>
      <ul style="padding-left:20px;">
        <li><strong>Everyday Utilities</strong> — Airtime, data, and bill payments</li>
        <li><strong>Business Tools</strong> — Messaging and digital communication services</li>
        <li><strong>Digital Products</strong> — Multi-use tools designed to help you scale</li>
      </ul>
      <p>We're building much more than a service marketplace — we're creating an
         ecosystem designed to help you connect, transact, and grow.</p>
      <p>Since we're constantly improving, your feedback is invaluable. Simply reply
         directly to this email if there's anything you'd like us to add, improve, or
         do differently.</p>
      <p><strong>Welcome to the Net365 family.</strong> We're thrilled to have you onboard.</p>
      <p style="margin-top:24px;">Warm regards,<br>
         <strong>Chijioke C. Igbokwe</strong><br>
         Founder &amp; CEO, NET365 COMMUNICATIONS LTD</p>
    </div>
    <div style="padding:16px 28px;background:#f8fafc;border-top:1px solid #e2e8f0;
                color:#94a3b8;font-size:11px;text-align:center;">
      You're receiving this because you created a Net365 account.<br>
      © 2026 Net365 Communications Ltd. · support@net365co.com
    </div>
  </div>
</body></html>"""
    text_body = (f"Hi {name},\n\nWelcome to Net365.\n\nI'm Chijioke C. Igbokwe, Founder & CEO of Net365 Communications, and I personally "
                 f"want to thank you for joining us.\n\nThrough your new account you can instantly access everyday utilities (airtime, data and "
                 f"bill payments), business tools and digital products.\n\nYour feedback is invaluable. Simply reply to this email if there is "
                 f"anything you would like us to add, improve or do differently.\n\nWelcome to the Net365 family.\n\nWarm regards,\n"
                 f"Chijioke C. Igbokwe\nFounder & CEO, NET365 COMMUNICATIONS LTD\n")
    return subject, html_body, text_body


def send_welcome_email(to_email: str, first_name: str = "") -> bool:
    """Sends the CEO welcome email now and returns whether the provider accepted it. The result is always logged
    (it used to be discarded on the HTTPS path, so a rejected sender address failed silently)."""
    subject, html_body, text_body = _welcome_content(first_name)
    ok, err = send_branded_email(
        to_email, subject, html_body, text_body,
        from_name=os.getenv("WELCOME_FROM_NAME", "Chijioke C. Igbokwe, Founder & CEO"),
        from_email=os.getenv("WELCOME_FROM_EMAIL", "ceo@net365co.com"),
        reply_to=os.getenv("WELCOME_REPLY_TO", "ceo@net365co.com"))
    if ok:
        logger.info(f"Welcome email sent to {to_email}")
    else:
        logger.error(f"Welcome email FAILED for {to_email}: {err}")
    return ok


def send_welcome_once(user_id, email, first_name="", source="web") -> bool:
    """Starts the welcome email for a new customer in the background, AT MOST ONCE per account (a failed attempt may be retried
    up to 3 times by a later call). Safe to call from every place an account is created or first linked. Never raises.
    Returns True when an attempt was started."""
    try:
        email = (email or "").strip()
        if not user_id or not email or "@" not in email:
            return False
        conn = db.get_db_connection()
        conn.execute("CREATE TABLE IF NOT EXISTS welcome_emails (user_id INTEGER PRIMARY KEY, email TEXT, source TEXT, status TEXT, "
                     "attempts INTEGER NOT NULL DEFAULT 0, error TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, sent_at TEXT)")
        cur = conn.execute("INSERT OR IGNORE INTO welcome_emails (user_id, email, source, status, attempts) VALUES (?,?,?,'sending',1)",
                           (int(user_id), email, str(source)[:20]))
        if cur.rowcount != 1:
            cur = conn.execute("UPDATE welcome_emails SET status='sending', attempts=attempts+1 WHERE user_id=? AND status='failed' AND attempts<3",
                               (int(user_id),))
            if cur.rowcount != 1:
                return False
        import threading as _threading

        def _worker():
            ok, err = False, None
            try:
                ok = send_welcome_email(email, first_name)
                err = None if ok else "provider refused the message (see the log line above)"
            except Exception as e:
                err = str(e)[:300]
                logger.error(f"Welcome email worker crashed for {email}: {e}")
            try:
                c2 = db.get_db_connection()
                c2.execute("UPDATE welcome_emails SET status=?, error=?, sent_at=CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE sent_at END WHERE user_id=?",
                           ("sent" if ok else "failed", err, 1 if ok else 0, int(user_id)))
            except Exception:
                logger.exception("could not record the welcome email result")

        _threading.Thread(target=_worker, daemon=True).start()
        return True
    except Exception as e:
        logger.error(f"Welcome email dispatch error for {email}: {e}")
        return False




import os
import smtplib
import logging
import threading
import html as _html
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Make sure this is defined somewhere in your app config
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://net365co.com")


def _send_via_mailgun_api(mg_domain, mg_api_key, from_addr, to_email, subject, html_body, attachment, attachment_name, _result, text_body=None, reply_to=None):
    """Sends via Mailgun's HTTPS API instead of raw SMTP. Used automatically
    whenever MAILGUN_API_KEY is set, because outbound SMTP (port 587/465/25)
    is commonly blocked or silently dropped by PaaS hosts like Railway —
    that's what a 'timed out' error sending mail (rather than an auth or
    delivery error) almost always means. The API call goes out over normal
    HTTPS (443), which is never blocked the same way."""
    try:
        files = [("attachment", (attachment_name, attachment))] if (attachment and attachment_name) else None
        resp = requests.post(
            f"{os.getenv('MAILGUN_API_BASE', 'https://api.mailgun.net').rstrip('/')}/v3/{mg_domain}/messages",
            auth=("api", mg_api_key),
            data={k: v for k, v in {"from": from_addr, "to": [to_email], "subject": subject, "html": html_body,
                                    "text": text_body, "h:Reply-To": reply_to}.items() if v},
            files=files,
            timeout=15,
        )
        if resp.status_code == 200:
            try:
                _mid = resp.json().get("id")
            except Exception:
                _mid = None
            logger.info(f"Email accepted by Mailgun for {to_email} id={_mid}")
            _result["success"] = True
            _result["id"] = _mid
        else:
            logger.error(f"Mailgun API error {resp.status_code} sending to {to_email}: {resp.text[:300]}")
            _result["success"] = False
            _result["error"] = f"HTTP {resp.status_code}: {resp.text[:300]}"
    except Exception as e:
        logger.error(f"Mailgun API request failed for {to_email}: {e}")
        _result["success"] = False
        _result["error"] = str(e)


def _send_via_resend(api_key, from_addr, to_email, subject, html_body, attachment, attachment_name, _result, text_body=None, reply_to=None):
    """Sends via Resend's HTTPS API (port 443), so it works on hosts that block SMTP (Render free tier)."""
    try:
        import base64 as _b64
        payload = {"from": from_addr, "to": [to_email], "subject": subject, "html": html_body}
        if text_body:
            payload["text"] = text_body
        if reply_to:
            payload["reply_to"] = reply_to
        if attachment and attachment_name:
            payload["attachments"] = [{"filename": attachment_name, "content": _b64.b64encode(attachment).decode()}]
        resp = requests.post("https://api.resend.com/emails", json=payload,
                             headers={"Authorization": f"Bearer {api_key}"}, timeout=15)
        if resp.status_code in (200, 201, 202):
            try:
                _mid = resp.json().get("id")
            except Exception:
                _mid = None
            logger.info(f"Email accepted by Resend for {to_email} id={_mid}")
            _result["success"] = True
            _result["id"] = _mid
        else:
            logger.error(f"Resend API error {resp.status_code} sending to {to_email}: {resp.text[:300]}")
            _result["success"] = False
            _result["error"] = f"HTTP {resp.status_code}: {resp.text[:300]}"
    except Exception as e:
        logger.error(f"Resend API request failed for {to_email}: {e}")
        _result["success"] = False
        _result["error"] = str(e)


def _https_email_configured():
    """True when an HTTPS email provider is set up (no SMTP needed)."""
    return bool(os.getenv("RESEND_API_KEY") or (os.getenv("MAILGUN_API_KEY") and os.getenv("MAILGUN_DOMAIN")))


def _send_via_https_provider(from_addr, to_email, subject, html_body, attachment, attachment_name, _result, text_body=None, reply_to=None):
    """Resend first when RESEND_API_KEY is set, otherwise Mailgun's API. Retries once on a transient (5xx/timeout) failure."""
    for attempt in (1, 2):
        _result.clear()
        if os.getenv("RESEND_API_KEY"):
            _send_via_resend(os.getenv("RESEND_API_KEY"), from_addr, to_email, subject, html_body, attachment, attachment_name,
                             _result, text_body, reply_to)
        else:
            _send_via_mailgun_api(os.getenv("MAILGUN_DOMAIN"), os.getenv("MAILGUN_API_KEY"), from_addr, to_email,
                                  subject, html_body, attachment, attachment_name, _result, text_body, reply_to)
        err = str(_result.get("error") or "")
        if _result.get("success") or attempt == 2 or not (err.startswith("HTTP 5") or "timed out" in err.lower() or "connection" in err.lower()):
            break
        time.sleep(2)
    return _result.get("success")


def _deliver_smtp_message(smtp_host, smtp_port, smtp_user, smtp_password, msg, to_email, _result):
    """Runs the actual network I/O. Called on a background thread so that a slow/hung
    DNS lookup or SMTP handshake (not bounded by smtplib's timeout= param) can never
    block the Flask/gunicorn worker handling the HTTP request."""
    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
        logger.info(f"Email sent to {to_email}")
        _result["success"] = True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        _result["success"] = False
        _result["error"] = str(e)


_EMOJI_RE = re.compile("[\U0001F000-\U0001FFFF\u2600-\u27BF\u2B00-\u2BFF\uFE0F\u200D]+")


def _clean_subject(subject):
    """Subjects without emoji or line breaks: emoji-heavy subjects are a common reason Gmail files mail under Spam."""
    t = _EMOJI_RE.sub("", str(subject or "")).replace("\r", " ").replace("\n", " ")
    return re.sub(r"\s{2,}", " ", t).strip()[:140] or "Net365 notification"


def send_service_receipt(user_id, payload, subject, body, tx_type, reference, amount):
    """Every successful purchase (airtime, data, electricity, cable TV, education, insurance) emails a receipt with the
    Net365 promo block. It goes to the email the customer confirmed at checkout, falling back to the account email.
    Never raises: a failed email must not affect a delivered order."""
    try:
        to = str((payload or {}).get("email") or "").strip()
        if not to or "@" not in to or to.endswith("@net365.com"):
            to = str(((db.get_user(user_id) if user_id else None) or {}).get("email") or "").strip()
        if not to:
            return False
        return send_email_notification(
            to, subject, body, include_promo=True,
            promo_context={"user_id": user_id, "reference": reference, "tx_type": tx_type, "amount": amount})
    except Exception as e:
        logger.warning(f"{tx_type} receipt email failed for {reference}: {e}")
        return False


def send_email_notification(
    to_email: str,
    subject: str,
    message: str,
    attachment: Optional[bytes] = None,
    attachment_name: Optional[str] = None,
    include_promo: bool = False,
    promo_context: Optional[Dict] = None,
    wait_seconds: float = 0,
) -> bool:
    """
    Builds and sends the email. The actual SMTP connection always happens on a
    background daemon thread so it can never hang the calling request.

    wait_seconds:
      0 (default)  -> fire-and-forget. Returns True as soon as the send is dispatched;
                       use this for receipts/notifications where nobody checks the result.
      > 0          -> blocks up to wait_seconds for a real success/failure result (used by
                       flows like OTP delivery that need to tell the user whether it worked).
                       If the send hasn't finished by then, returns False immediately without
                       waiting any further — the send still completes in the background.
    """
    smtp_host = os.getenv("SMTP_HOST", "smtp.mailgun.org")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("FROM_EMAIL") or smtp_user
    from_name = os.getenv("FROM_NAME", "Net365 Support")
    reply_to = os.getenv("REPLY_TO") or from_email

    _https_ok = _https_email_configured()
    if not _https_ok and (not smtp_user or not smtp_password):
        logger.warning("No email provider configured (set RESEND_API_KEY, or MAILGUN_API_KEY + MAILGUN_DOMAIN, or SMTP_*), skipping email notification")
        return False
    if not from_email:
        _dom = os.getenv("MAILGUN_DOMAIN") or "net365co.com"
        from_email = f"support@{_dom}"

    try:
        subject = _clean_subject(subject)
        msg = MIMEMultipart("alternative" if not attachment else "mixed")
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg["Reply-To"] = reply_to
        text_body = (f"{subject}\n\n{message}\n\nOpen your dashboard: {FRONTEND_URL}\n\n"
                     f"Net365. Need help? support@net365co.com")

        promo_html = ""
        if include_promo:
            context = promo_context or {}
            try:
                promo = _get_transaction_promo(
                    user_id=context.get("user_id"),
                    reference=context.get("reference"),
                    tx_type=context.get("tx_type"),
                    amount=context.get("amount"),
                    created_at=context.get("created_at"),
                )
                try:
                    from net365_adengine import track_email_promo as _ae_track
                    promo = _ae_track(promo, context)
                except Exception:
                    pass
                promo_html = _build_email_promo_html(promo)
            except NameError:
                logger.warning("Promo helpers not available, skipping promo block")

        safe_subject = _html.escape(str(subject))
        safe_message = _html.escape(str(message)).replace("\n", "<br>")
        # Several flows (signup, reset and chat-link codes) wrap the code in <span class="amount">. Escaping turned that
        # into visible text, so allow back exactly this one tag and nothing else.
        safe_message = (safe_message.replace('&lt;span class=&quot;amount&quot;&gt;', '<span class="amount">')
                                    .replace('&lt;/span&gt;', '</span>'))

        html_body = f"""
        <html>
        <head>
        <style>
            body {{
                font-family: 'Segoe UI', Arial, sans-serif;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background: #f8fafc;
            }}
            .header {{
                background: linear-gradient(135deg, #E53935 0%, #FF6D00 100%);
                color: white;
                padding: 32px 28px 28px 28px;
                text-align: center;
                border-radius: 16px 16px 0 0;
            }}
            .header h1 {{ margin: 0; font-size: 32px; font-weight: 800; }}
            .header .sub {{
                font-size: 11px; opacity: 0.85; letter-spacing: 2px;
                text-transform: uppercase; margin-top: 4px;
            }}
            .content {{
                padding: 28px; background: #ffffff;
                border: 1px solid #e2e8f0; border-top: none;
                border-radius: 0 0 16px 16px;
            }}
            .content h2 {{ color: #1e293b; font-size: 20px; margin-top: 0; }}
            .content p {{ color: #475569; line-height: 1.7; font-size: 15px; }}
            .message-box {{
                background: #fff5f2; border-left: 4px solid #E53935;
                padding: 16px 20px; border-radius: 8px; margin: 16px 0;
            }}
            .message-box p {{ margin: 0; color: #1e293b; }}
            .button {{
                background: linear-gradient(135deg, #E53935 0%, #FF6D00 100%);
                color: white; padding: 14px 32px; text-decoration: none;
                border-radius: 999px; display: inline-block;
                font-weight: 700; font-size: 14px;
            }}
            .footer {{
                text-align: center; padding: 20px 28px;
                background: #f8fafc; border-radius: 0 0 16px 16px;
                border: 1px solid #e2e8f0; border-top: none;
            }}
            .footer p {{ margin: 0; color: #94a3b8; font-size: 12px; }}
            .footer .link {{ color: #E53935; text-decoration: none; font-weight: 600; }}
            .divider {{ height: 1px; background: #e2e8f0; margin: 16px 0; }}
        </style>
        </head>
        <body>
            <div class="header">
                <h1>NET365</h1>
                <div class="sub">DIGITAL PAYMENTS · TRANSACTION RECEIPT</div>
            </div>
            <div class="content">
                <h2>{safe_subject}</h2>
                <div class="message-box"><p>{safe_message}</p></div>
                {promo_html}
                <p style="text-align:center;margin-top:24px;margin-bottom:0;">
                    <a href="{_html.escape(FRONTEND_URL, quote=True)}" class="button">
                        View in Dashboard
                    </a>
                </p>
            </div>
            <div class="footer">
                <p>
                    &copy; 2026 Net365. All rights reserved.<br>
                    <span style="font-size:11px;color:#94a3b8;">
                        This is an automated receipt from Net365.
                    </span>
                </p>
                <div class="divider"></div>
                <p>Need help? Contact
                    <a href="mailto:support@net365co.com" class="link">support@net365co.com</a>
                </p>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        if attachment and attachment_name:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment)
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition", f"attachment; filename={attachment_name}"
            )
            msg.attach(part)

        # ⬇️ THE KEY FIX: SMTP I/O runs on a background thread, never on the
        # request thread. A hung DNS lookup or blocked outbound port can no
        # longer take down the Flask/gunicorn worker (see WORKER TIMEOUT crash).
        # Prefer Mailgun's HTTPS API (port 443) over raw SMTP (port 587) when a
        # MAILGUN_API_KEY is configured — Railway (like many PaaS hosts) can
        # silently drop outbound SMTP traffic, which shows up as a plain
        # socket "timed out" rather than an auth/delivery error.
        mailgun_api_key = os.getenv("MAILGUN_API_KEY")
        mailgun_domain = os.getenv("MAILGUN_DOMAIN") or (
            smtp_user.split("@", 1)[1] if smtp_user and "@" in smtp_user else None
        )

        _result: Dict = {}
        if _https_ok:
            t = threading.Thread(
                target=_send_via_https_provider,
                args=(f"{from_name} <{from_email}>", to_email, subject, html_body, attachment, attachment_name, _result, text_body, reply_to),
                daemon=True,
            )
        else:
            t = threading.Thread(
                target=_deliver_smtp_message,
                args=(smtp_host, smtp_port, smtp_user, smtp_password, msg, to_email, _result),
                daemon=True,
            )
        t.start()

        if wait_seconds > 0:
            t.join(wait_seconds)
            if t.is_alive():
                logger.warning(
                    f"Email to {to_email} still in flight after {wait_seconds}s wait; "
                    f"not blocking the request further (it will finish in the background)"
                )
                return False
            return bool(_result.get("success"))

        # Fire-and-forget: don't block the caller/request at all.
        return True

    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False



def _notify_owner_of_topup(
    user_id: int,
    reference: str,
    amount: float,
    currency: str,
    phone: str,
    tx_type: str = "airtime",
    extra_note: str = "",
) -> None:
    """Send the account owner a confirmation email for a completed top-up.
    Safe to call from background threads — never uses `g` or `request`.
    """
    try:
        user = db.get_user(user_id)
    except Exception as e:
        logger.error(f"_notify_owner_of_topup: could not load user {user_id}: {e}")
        return

    if not user or not user.get("email"):
        logger.warning(f"_notify_owner_of_topup: user {user_id} has no email on file")
        return

    label = "Airtime Recharge" if tx_type == "airtime" else tx_type.title()
    subject = f"✅ Net365 {label} Successful — {reference}"
    note = f"\n\n{extra_note}" if extra_note else ""

    try:
        send_email_notification(
            user["email"],
            subject,
            (
                f"Your {label.lower()} was completed successfully.\n\n"
                f"Amount: {currency} {amount:,.2f}\n"
                f"Phone: {phone}\n"
                f"Reference: {reference}"
                f"{note}"
            ),
            include_promo=True,
            promo_context={
                "user_id": user_id,
                "reference": reference,
                "tx_type": tx_type,
                "amount": amount,
            },
        )
    except Exception as e:
        logger.error(f"_notify_owner_of_topup: email failed for {reference}: {e}")
        
        
# ============ RECEIPT GENERATION ============
# ============ REPLACE YOUR EXISTING generate_receipt WITH THIS ============


def generate_receipt(transaction: Dict) -> bytes:
    """Generate a beautiful, brand-aware receipt with promotions."""

    # Fetch promotions and brand colors
    promo = None
    brand_colors = None
    try:
        user_id = transaction.get("user_id")
        reference = transaction.get("reference")

        if user_id:
            receipt_number = db.count_user_fulfilled_transactions(
                user_id, before_reference=reference
            )

            try:
                tx_hour = datetime.fromisoformat(
                    str(transaction.get("created_at", "")).replace("Z", "")
                ).hour
            except (ValueError, TypeError):
                tx_hour = datetime.now().hour

            # Get provider/biller name for brand lookup
            provider = transaction.get("provider", "").lower()
            tx_type = (transaction.get("tx_type") or "").lower()

            # Try to get brand colors from the provider
            brand_colors = db.get_brand_colors(provider)

            # If no brand colors found, check payload for advertiser info
            if not brand_colors:
                payload = transaction.get("payload", {})
                if payload.get("advertiser"):
                    brand_colors = db.get_brand_colors(payload.get("advertiser"))

            context = {
                "tx_type": tx_type,
                "amount": transaction.get("amount"),
                "is_new_customer": receipt_number == 1,
                "hour": tx_hour,
                "day_of_week": datetime.now().weekday(),
                "user_id": user_id,
            }

            # Try to get a promotion first (new engine)
            promotions = db.get_active_promotions(context)
            if promotions:
                promo = promotions[0]  # Highest priority promotion
                db.track_promotion_impression(promo["id"])

            # Fallback to legacy promo system if no promotions found
            if not promo:
                promo = db.get_receipt_promo_for_slot(receipt_number, context=context)
                if promo and promo.get("cta_url") == "/settings#referral":
                    user = db.get_user(user_id)
                    if user and user.get("referral_code"):
                        promo = dict(promo)
                        promo["body"] = (
                            promo["body"]
                            + f"\n\nYour referral code: {user['referral_code']}"
                        )

    except Exception as e:
        logger.error(f"Promo lookup failed (non-fatal): {e}")
        promo = None

    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            HRFlowable,
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
        from xml.sax.saxutils import escape as xml_escape

        # ---- Brand Colors (with defaults) ----
        def hex_to_reportlab(hex_color: str):
            hex_color = hex_color or "#4f46e5"
            hex_color = hex_color.lstrip("#")
            if len(hex_color) == 3:
                hex_color = "".join([c * 2 for c in hex_color])
            return colors.Color(
                int(hex_color[0:2], 16) / 255.0,
                int(hex_color[2:4], 16) / 255.0,
                int(hex_color[4:6], 16) / 255.0,
            )

        # Default Net365 colors
        default_primary = colors.Color(0.31, 0.27, 0.89)  # #4f46e5
        default_secondary = colors.Color(0.49, 0.23, 0.93)  # #7c3aed
        default_accent = colors.Color(0.02, 0.71, 0.83)  # #06b6d4

        # Use brand colors if available
        if brand_colors:
            primary_color = hex_to_reportlab(
                brand_colors.get("primary_color", "#4f46e5")
            )
            secondary_color = hex_to_reportlab(
                brand_colors.get("secondary_color", "#7c3aed")
            )
            accent_color = hex_to_reportlab(brand_colors.get("accent_color", "#06b6d4"))
            text_color = hex_to_reportlab(brand_colors.get("text_color", "#ffffff"))
            bg_color = hex_to_reportlab(brand_colors.get("background_color", "#f8fafc"))
            brand_name = brand_colors.get("advertiser_name", "Net365")
        else:
            primary_color = default_primary
            secondary_color = default_secondary
            accent_color = default_accent
            text_color = colors.white
            bg_color = colors.Color(0.95, 0.95, 0.99)
            brand_name = "Net365"

        # ---- Helper Functions ----
        def receipt_safe(text) -> str:
            text = "" if text is None else str(text)
            text = text.replace("\u20a6", "NGN ")
            return xml_escape(text)

        def _receipt_safe(text) -> str:
            return receipt_safe(text)

        # ---- Status Mapping ----
        _RECEIPT_STATUS_MAP = {
            "fulfilled": ("PAYMENT SUCCESSFUL", "green"),
            "completed": ("PAYMENT SUCCESSFUL", "green"),
            "paid": ("PAYMENT SUCCESSFUL", "green"),
            "success": ("PAYMENT SUCCESSFUL", "green"),
            "pending": ("PAYMENT PENDING", "amber"),
            "processing": ("PROCESSING", "amber"),
            "failed": ("PAYMENT FAILED", "red"),
            "fulfillment_failed": ("FULFILLMENT FAILED", "red"),
            "cancelled": ("CANCELLED", "red"),
        }

        def receipt_status_style(status: str):
            key = (status or "").lower()
            label, tone = _RECEIPT_STATUS_MAP.get(
                key, (key.upper() or "UNKNOWN", "grey")
            )
            palette = {
                "green": (
                    colors.Color(0.06, 0.63, 0.42),
                    colors.Color(0.90, 0.98, 0.94),
                ),
                "amber": (
                    colors.Color(0.83, 0.55, 0.05),
                    colors.Color(1.00, 0.96, 0.86),
                ),
                "red": (colors.Color(0.86, 0.20, 0.24), colors.Color(1.00, 0.92, 0.92)),
                "grey": (
                    colors.Color(0.45, 0.45, 0.48),
                    colors.Color(0.93, 0.93, 0.94),
                ),
            }
            fg, bg = palette[tone]
            return label, fg, bg

        # ---- Chrome Drawing with Brand Colors ----
        def draw_chrome(c, doc):
            width, height = c._pagesize

            # Gradient rail - brand color to accent
            rail_w = 4
            for i in range(40):
                frac = i / 40
                col = colors.Color(
                    primary_color.red + (accent_color.red - primary_color.red) * frac,
                    primary_color.green
                    + (accent_color.green - primary_color.green) * frac,
                    primary_color.blue
                    + (accent_color.blue - primary_color.blue) * frac,
                )
                c.setFillColor(col)
                c.rect(
                    0,
                    height - (height / 40) * (i + 1),
                    rail_w,
                    height / 40 + 0.5,
                    stroke=0,
                    fill=1,
                )

            # Header gradient
            band_h = 96
            for i in range(60):
                frac = i / 60
                col = colors.Color(
                    primary_color.red
                    + (secondary_color.red - primary_color.red) * frac,
                    primary_color.green
                    + (secondary_color.green - primary_color.green) * frac,
                    primary_color.blue
                    + (secondary_color.blue - primary_color.blue) * frac,
                )
                c.setFillColor(col)
                x0 = rail_w + (width - rail_w) * frac
                c.rect(
                    x0,
                    height - band_h,
                    (width - rail_w) / 60 + 1,
                    band_h,
                    stroke=0,
                    fill=1,
                )

            # Accent seam
            c.setFillColor(accent_color)
            c.rect(rail_w, height - band_h - 2, width - rail_w, 2, stroke=0, fill=1)

            # Decorative dots
            c.setFillColor(colors.Color(1, 1, 1, alpha=0.18))
            for row in range(5):
                for col_i in range(8):
                    dx = width - 0.9 * inch - col_i * 8
                    dy = height - 18 - row * 8
                    c.circle(dx, dy, 1.1, stroke=0, fill=1)

            # Brand wordmark
            c.setFillColor(text_color)
            c.setFont("Helvetica-Bold", 22)
            c.drawString(0.75 * inch, height - 46, brand_name.upper())
            c.setFont("Helvetica", 9)
            c.setFillColor(
                colors.Color(
                    text_color.red, text_color.green, text_color.blue, alpha=0.85
                )
            )
            c.drawString(
                0.75 * inch, height - 62, "DIGITAL PAYMENTS \u00b7 TRANSACTION RECEIPT"
            )

            # Footer
            footer_y = 0.55 * inch
            faint = colors.Color(0.90, 0.91, 0.96)
            slate = colors.Color(0.42, 0.45, 0.53)

            c.setStrokeColor(faint)
            c.setLineWidth(0.6)
            c.line(0.75 * inch, footer_y + 20, width - 0.75 * inch, footer_y + 20)

            c.setFont("Helvetica", 7.5)
            c.setFillColor(slate)
            c.drawString(
                0.75 * inch,
                footer_y + 8,
                "This is a system-generated receipt and does not require a signature or stamp.",
            )
            c.drawString(
                0.75 * inch,
                footer_y - 3,
                f"Generated {datetime.now().strftime('%d %b %Y, %H:%M')} \u00b7 {brand_name} \u00b7 support@net365co.com",
            )
            c.drawRightString(width - 0.75 * inch, footer_y + 8, f"Page {doc.page}")

            # Decorative verification block
            seed = sum(
                ord(ch) for ch in (getattr(doc, "_receipt_reference", "") or "NET365")
            )
            sq = 3.2
            base_x = width - 0.75 * inch - 16 * (sq + 1)
            base_y = footer_y - 3
            for i in range(16):
                on = (seed >> (i % 16)) & 1
                c.setFillColor(primary_color if on else faint)
                c.rect(base_x + i * (sq + 1), base_y, sq, sq * 2, stroke=0, fill=1)

        # ---- BUILD THE RECEIPT ----
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            topMargin=1.25 * inch,
            bottomMargin=1.0 * inch,
            leftMargin=0.85 * inch,
            rightMargin=0.75 * inch,
        )
        doc._receipt_reference = transaction.get("reference", "")
        styles = getSampleStyleSheet()

        story = []
        status = transaction.get("status", "unknown")
        status_label, status_fg, status_bg = receipt_status_style(status)
        ref = receipt_safe(transaction.get("reference", "N/A"))

        # ---- Top: Reference + Status Pill ----
        pill_style = ParagraphStyle(
            "Pill",
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=status_fg,
            alignment=TA_CENTER,
            leading=11,
        )
        pill = Table(
            [[Paragraph(status_label, pill_style)]],
            colWidths=[1.7 * inch],
            rowHeights=[0.28 * inch],
        )
        pill.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), status_bg),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ("BOX", (0, 0), (-1, -1), 0.75, status_fg),
                ]
            )
        )
        top_row = Table(
            [
                [
                    Paragraph(
                        f"<font color='#6b7280' size=8>REFERENCE</font><br/>"
                        f"<font face='Courier' size=11>{ref}</font>",
                        styles["Normal"],
                    ),
                    pill,
                ]
            ],
            colWidths=[3.9 * inch, 1.85 * inch],
        )
        top_row.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        story.append(top_row)
        story.append(Spacer(1, 14))

        # ---- Hero Amount Panel ----
        amount = transaction.get("amount", 0) or 0
        currency = receipt_safe(transaction.get("currency", "NGN"))

        hero_label_style = ParagraphStyle(
            "HeroLabel",
            fontName="Helvetica",
            fontSize=8.5,
            textColor=colors.Color(0.42, 0.45, 0.53),
            alignment=TA_CENTER,
        )
        hero_amount_style = ParagraphStyle(
            "HeroAmount",
            fontName="Helvetica-Bold",
            fontSize=28,
            textColor=primary_color,
            alignment=TA_CENTER,
            leading=32,
        )
        hero = Table(
            [
                [Paragraph("AMOUNT", hero_label_style)],
                [Paragraph(f"{currency} {amount:,.2f}", hero_amount_style)],
            ],
            colWidths=[5.75 * inch],
        )
        hero.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                    ("TOPPADDING", (0, 0), (0, 0), 12),
                    ("BOTTOMPADDING", (0, 0), (0, 0), 0),
                    ("TOPPADDING", (0, 1), (0, 1), 2),
                    ("BOTTOMPADDING", (0, 1), (0, 1), 14),
                    ("LINEABOVE", (0, 0), (-1, 0), 1.2, accent_color),
                    ("LINEBELOW", (0, -1), (-1, -1), 1.2, accent_color),
                ]
            )
        )
        story.append(hero)
        story.append(Spacer(1, 18))

        # ---- Transaction Details ----
        label_style = ParagraphStyle(
            "Label",
            fontName="Helvetica",
            fontSize=8.5,
            textColor=colors.Color(0.42, 0.45, 0.53),
            leading=11,
        )
        section_head = ParagraphStyle(
            "SectionHead",
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=colors.Color(0.42, 0.45, 0.53),
            leading=12,
            spaceAfter=2,
        )
        value_style = ParagraphStyle(
            "RowVal",
            fontName="Helvetica",
            fontSize=10,
            textColor=colors.Color(0.11, 0.11, 0.15),
            alignment=TA_RIGHT,
            leading=13,
        )

        story.append(Paragraph("TRANSACTION DETAILS", section_head))
        story.append(
            HRFlowable(
                width="100%", thickness=0.75, color=colors.Color(0.90, 0.91, 0.96)
            )
        )
        story.append(Spacer(1, 4))

        rows = [
            ("Date & Time", transaction.get("created_at", "N/A")),
            (
                "Type",
                (transaction.get("tx_type") or "Unknown").replace("_", " ").title(),
            ),
            ("Status", status.replace("_", " ").title()),
            ("Payment Method", transaction.get("provider", "Unknown")),
        ]
        payload = transaction.get("payload") or {}
        if payload.get("phone"):
            rows.append(("Phone", payload.get("phone")))
        if payload.get("email"):
            rows.append(("Email", payload.get("email")))
        if payload.get("subscriber_account"):
            rows.append(("Account", payload.get("subscriber_account")))

        table_data = []
        for lbl, val in rows:
            table_data.append(
                [
                    Paragraph(receipt_safe(lbl), label_style),
                    Paragraph(receipt_safe(val), value_style),
                ]
            )
        t = Table(table_data, colWidths=[2.25 * inch, 3.5 * inch])
        t.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    (
                        "LINEBELOW",
                        (0, 0),
                        (-1, -2),
                        0.5,
                        colors.Color(0.90, 0.91, 0.96),
                    ),
                ]
            )
        )
        story.append(t)
        story.append(Spacer(1, 22))

        # ---- Thank You Message ----
        thanks_style = ParagraphStyle(
            "Thanks",
            fontName="Helvetica",
            fontSize=9.5,
            textColor=colors.Color(0.42, 0.45, 0.53),
            leading=13,
        )
        status_key = status.lower()
        if status_key in ("fulfilled", "completed", "paid", "success"):
            story.append(Paragraph("Thank you for choosing Net365.", thanks_style))
        elif status_key in ("pending", "processing"):
            story.append(
                Paragraph(
                    "Your transaction is still processing — this receipt will update once it settles.",
                    thanks_style,
                )
            )
        else:
            story.append(
                Paragraph(
                    "This transaction did not complete. Contact support if you were charged.",
                    thanks_style,
                )
            )

        # ---- PROMOTIONAL SECTION (Brand-Aware) ----
        if promo:
            story.append(Spacer(1, 20))

            # Use promotion's brand color or default
            promo_brand_color = hex_to_reportlab(promo.get("brand_color", "#4f46e5"))
            promo_bg_color = hex_to_reportlab(promo.get("background_color", "#f5f3ff"))
            promo_text_color = hex_to_reportlab(promo.get("text_color", "#1e293b"))
            promo_icon = promo.get("icon", "🎁")
            promo_category = promo.get("category", "general")

            promo_title_style = ParagraphStyle(
                "PromoTitle",
                fontName="Helvetica-Bold",
                fontSize=11.5,
                textColor=promo_brand_color,
                leading=14,
            )
            promo_body_style = ParagraphStyle(
                "PromoBody",
                fontName="Helvetica",
                fontSize=9.5,
                textColor=promo_text_color,
                leading=13,
            )
            tag_style = ParagraphStyle(
                "Tag",
                fontName="Helvetica-Bold",
                fontSize=7,
                textColor=colors.white,
                alignment=TA_CENTER,
            )

            # Category tag
            tag = Table(
                [[Paragraph(promo_category.upper(), tag_style)]],
                colWidths=[0.85 * inch],
                rowHeights=[0.18 * inch],
            )
            tag.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), promo_brand_color),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ]
                )
            )

            # Body with icon
            body_html = f"{promo_icon} {receipt_safe(promo['body'])}".replace(
                "\n", "<br/>"
            )
            cta_line = ""
            if promo.get("cta_text"):
                cta_url = receipt_safe(promo.get("cta_url") or "")
                cta_line = (
                    f"<br/><br/><font color='{promo.get('brand_color', '#4f46e5')}'><b>"
                    f"&#8594; {receipt_safe(promo['cta_text'])}</b></font>"
                    + (
                        f" <font size=8 color='#888888'>({cta_url})</font>"
                        if cta_url
                        else ""
                    )
                )

            promo_content = Table(
                [
                    [tag],
                    [Paragraph(receipt_safe(promo["title"]), promo_title_style)],
                    [Paragraph(body_html + cta_line, promo_body_style)],
                ],
                colWidths=[5.75 * inch],
            )
            promo_content.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), promo_bg_color),
                        (
                            "BOX",
                            (0, 0),
                            (-1, -1),
                            0.75,
                            colors.Color(
                                promo_brand_color.red * 0.8,
                                promo_brand_color.green * 0.8,
                                promo_brand_color.blue * 0.8,
                                0.6,
                            ),
                        ),
                        ("LEFTPADDING", (0, 0), (-1, -1), 14),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
                        ("TOPPADDING", (0, 0), (0, 0), 10),
                        ("BOTTOMPADDING", (0, 0), (0, 0), 4),
                        ("TOPPADDING", (0, 1), (0, 1), 2),
                        ("BOTTOMPADDING", (0, 1), (0, 1), 4),
                        ("TOPPADDING", (0, 2), (0, 2), 0),
                        ("BOTTOMPADDING", (0, 2), (0, 2), 12),
                    ]
                )
            )
            story.append(promo_content)

        doc.build(story, onFirstPage=draw_chrome, onLaterPages=draw_chrome)
        return buffer.getvalue()

    except ImportError:
        # Text fallback
        logger.warning("reportlab not installed, generating text receipt")
        promo_text = ""
        if promo:
            cta_line = (
                f"\n        → {promo['cta_text']} ({promo.get('cta_url', '')})"
                if promo.get("cta_text")
                else ""
            )
            promo_text = f"""
        ----------------------------------------
        {promo['title']}
        {promo['body']}{cta_line}
        """
        receipt_text = f"""
        ========================================
                    Net365 Receipt
        ========================================
        
        Transaction ID: {transaction.get('reference', 'N/A')}
        Date: {transaction.get('created_at', 'N/A')}
        Type: {transaction.get('tx_type', 'Unknown')}
        Status: {transaction.get('status', 'Unknown')}
        Amount: {transaction.get('currency', 'NGN')} {transaction.get('amount', 0):.2f}
        Payment Method: {transaction.get('provider', 'Unknown')}
        
        ========================================
        Thank you for using Net365!
        ========================================
        {promo_text}
        """
        return receipt_text.encode("utf-8")
    except Exception as e:
        logger.error(f"Failed to generate receipt: {e}")
        return None


# ============ EVENT LOGGING FUNCTIONS ============
def log_event(
    user_id: int, event_type: str, details: Dict, status: str = "success"
) -> bool:
    conn = db.get_db_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS user_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,            -- NULL for guest checkouts
            event_type TEXT NOT NULL,
            status TEXT DEFAULT 'success',
            details TEXT,
            reference TEXT,
            amount REAL,
            currency TEXT DEFAULT 'NGN',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_user_events_user_id ON user_events(user_id)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_user_events_created_at ON user_events(created_at)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_user_events_event_type ON user_events(event_type)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_user_events_reference ON user_events(reference)"
    )

    try:
        c.execute(
            """
            INSERT INTO user_events (user_id, event_type, status, details, reference, amount, currency)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                user_id,
                event_type,
                status,
                json.dumps(details) if details else None,
                details.get("reference") if details else None,
                details.get("amount") if details else None,
                details.get("currency", "NGN") if details else "NGN",
            ),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to log event: {e}")
        return False


def get_user_events(
    user_id: int, limit: int = 50, offset: int = 0, event_type: str = None
) -> List[Dict]:
    conn = db.get_db_connection()
    c = conn.cursor()

    query = "SELECT * FROM user_events WHERE user_id = ?"
    params = [user_id]

    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    try:
        events = c.execute(query, params).fetchall()
        result = []
        for event in events:
            e = dict(event)
            if e.get("details"):
                try:
                    e["details"] = json.loads(e["details"])
                except:
                    pass
            result.append(e)
        return result
    except Exception as e:
        logger.error(f"Failed to get user events: {e}")
        return []


# ============ SCHEDULER FUNCTIONS ============
def get_available_wallet_balance(
    user_id: int, preferred_currency: str, amount: float
) -> Dict:
    currency = (preferred_currency or "NGN").upper()
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        amount = 0.0

    wallet = db.get_wallet(user_id, currency)
    if not wallet:
        return {"available": False, "currency": currency, "balance": 0.0}

    balance = float(
        wallet.get("available_balance")
        if wallet.get("available_balance") is not None
        else wallet.get("balance", 0) or 0
    )
    return {"available": balance >= amount, "currency": currency, "balance": balance}


# ============ FIX: TIMEZONE-AWARE CALCULATE_NEXT_RUN ============
# Replace the existing calculate_next_run function in app.py


def calculate_next_run(
    frequency: str,
    day_of_month: int,
    time: str,
    day_of_week: int,
    month: int,
    event_date: str = None,
    timezone_str: str = "Africa/Lagos",
) -> Optional[str]:
    """Calculate the next run time with proper timezone handling."""
    from datetime import datetime, timedelta, timezone as dt_timezone
    from zoneinfo import ZoneInfo
    import calendar

    UTC = dt_timezone.utc

    # Default to WAT if no timezone specified
    if not timezone_str:
        timezone_str = "Africa/Lagos"

    try:
        tz = ZoneInfo(timezone_str)
    except Exception:
        try:
            tz = ZoneInfo("Africa/Lagos")
        except Exception:
            # Container has no tz database (slim image without tzdata).
            # Lagos has no DST, so a fixed UTC+1 is exactly equivalent.
            tz = dt_timezone(timedelta(hours=1))
            logger.error("No tz database found; add 'tzdata' to requirements.txt")
        logger.warning(
            f"Invalid timezone '{timezone_str}', falling back to Africa/Lagos"
        )

    # Get current time in the user's timezone
    now = datetime.now(tz)

    freq = str(frequency or "monthly").lower()
    time_str = str(time or "09:00")

    try:
        hour, minute = [int(x) for x in time_str.split(":", 1)]
        hour = min(max(hour, 0), 23)
        minute = min(max(minute, 0), 59)
    except (ValueError, TypeError):
        hour, minute = 9, 0

    def at_time(value: datetime) -> datetime:
        return value.replace(hour=hour, minute=minute, second=0, microsecond=0)

    def safe_day(year: int, month: int, day: int) -> int:
        return min(max(int(day or 1), 1), calendar.monthrange(year, month)[1])

    def add_months(year: int, month: int, months: int):
        index = (month - 1) + months
        year += index // 12
        month = (index % 12) + 1
        return year, month

    if freq == "once":
        if event_date:
            try:
                event_dt = datetime.fromisoformat(
                    str(event_date).replace("Z", "+00:00")
                )
                if event_dt.tzinfo is None:
                    event_dt = event_dt.replace(tzinfo=tz)
                else:
                    event_dt = event_dt.astimezone(tz)
                next_run = at_time(event_dt)
                if next_run <= now:
                    return None
                # Convert to UTC for storage
                return next_run.astimezone(UTC).isoformat()
            except (ValueError, TypeError):
                return None
        return None

    if freq == "daily":
        next_run = at_time(now)
        if next_run <= now:
            next_run += timedelta(days=1)
        return next_run.astimezone(UTC).isoformat()

    if freq == "weekly":
        target_day = min(max(int(day_of_week or 0), 0), 6)
        days_ahead = (target_day - now.weekday()) % 7
        next_run = at_time(now + timedelta(days=days_ahead))
        if next_run <= now:
            next_run += timedelta(days=7)
        return next_run.astimezone(UTC).isoformat()

    if freq == "monthly":
        target_day = max(int(day_of_month or 1), 1)
        year, month = now.year, now.month
        next_run = at_time(
            datetime(year, month, safe_day(year, month, target_day), tzinfo=tz)
        )
        if next_run <= now:
            year, month = add_months(year, month, 1)
            next_run = at_time(
                datetime(year, month, safe_day(year, month, target_day), tzinfo=tz)
            )
        return next_run.astimezone(UTC).isoformat()

    if freq == "quarterly":
        target_day = max(int(day_of_month or 1), 1)
        current_quarter_month = ((now.month - 1) // 3) * 3 + 1
        year, month = now.year, current_quarter_month
        next_run = at_time(
            datetime(year, month, safe_day(year, month, target_day), tzinfo=tz)
        )
        if next_run <= now:
            year, month = add_months(year, month, 3)
            next_run = at_time(
                datetime(year, month, safe_day(year, month, target_day), tzinfo=tz)
            )
        return next_run.astimezone(UTC).isoformat()

    if freq == "yearly":
        target_month = min(max(int(month or 1), 1), 12)
        target_day = max(int(day_of_month or 1), 1)
        year = now.year
        next_run = at_time(
            datetime(
                year, target_month, safe_day(year, target_month, target_day), tzinfo=tz
            )
        )
        if next_run <= now:
            year += 1
            next_run = at_time(
                datetime(
                    year,
                    target_month,
                    safe_day(year, target_month, target_day),
                    tzinfo=tz,
                )
            )
        return next_run.astimezone(UTC).isoformat()

    if freq == "event" and event_date:
        try:
            event_dt = datetime.fromisoformat(str(event_date).replace("Z", "+00:00"))
            if event_dt.tzinfo is None:
                event_dt = event_dt.replace(tzinfo=tz)
            else:
                event_dt = event_dt.astimezone(tz)
            next_run = at_time(event_dt)
            if next_run <= now:
                try:
                    next_run = next_run.replace(year=next_run.year + 1)
                except ValueError:  # Feb 29 -> Feb 28
                    next_run = next_run.replace(year=next_run.year + 1, day=28)
            return next_run.astimezone(UTC).isoformat()
        except (ValueError, TypeError):
            return None

    return None



def normalize_next_run(value) -> Optional[str]:
    """Force any datetime representation into canonical ISO-8601 UTC with offset.
    Returns None if the input is unusable — callers should recompute in that case."""
    from datetime import timezone
    if not value:
        return None
    try:
        if isinstance(value, datetime):
            dt = value
        else:
            s = str(value).strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)

        if dt.tzinfo is None:
            # Assume UTC for naive inputs (this is the safest default for
            # values that came from calculate_next_run, which always emits UTC)
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        return dt.isoformat()
    except (ValueError, TypeError, AttributeError):
        logger.warning(f"normalize_next_run: could not parse {value!r}")
        return None

# ============ HELPER: SANDBOX UTILITY FALLBACK ============
def handle_sandbox_utility_fallback(
    platform,
    biller_id,
    subscriber_account,
    currency,
    reference,
    run_reference,
    user_id,
    debit_amount,
    wallet_currency=None,
) -> Dict:
    """Last-resort fallback for sandbox utility payments: ask Reloadly for this biller's
    real limits and try its actual minimum, rather than guessing arbitrary amounts. Also
    reconciles the wallet against debit_amount (what was already taken) so the ledger
    always matches what was actually charged, whatever the final amount turns out to be.
    """
    wallet_currency = wallet_currency or currency
    try:
        api = platform._get_utilities_api()
        real_biller = api.get_biller_by_id(biller_id)
        real_min = (
            real_biller.get("minLocalTransactionAmount")
            or real_biller.get("localMinAmount")
            or real_biller.get("minAmount")
        )
        candidates = [float(real_min)] if real_min is not None else []
    except Exception as e:
        logger.warning(f"Could not fetch real biller limits for sandbox fallback: {e}")
        candidates = []
    # Last-resort generic guesses only if we couldn't get real data at all.
    candidates += [200, 100, 50, 500, 1000]

    for test_amount in candidates:
        try:
            test_ref = (
                f"sandbox-util-{reference}-{int(test_amount)}-{uuid.uuid4().hex[:6]}"[
                    :36
                ]
            )
            test_result = platform.pay_utility_bill(
                biller_id=biller_id,
                subscriber_account=subscriber_account,
                amount=test_amount,
                reference_id=test_ref,
                use_local_amount=True,
            )

            if test_result.get("transactionId") or str(
                test_result.get("status", "")
            ).upper() in ("SUCCESS", "COMPLETED"):
                logger.info(
                    f"Sandbox: Scheduled utility payment succeeded with amount {test_amount}"
                )

                # Reconcile: the wallet was already debited `debit_amount` before this
                # fallback ran. If the amount that actually succeeded differs, adjust.
                diff = round(debit_amount - test_amount, 2)
                if abs(diff) > 0.005:
                    if diff > 0:
                        db.credit_wallet(
                            user_id=user_id,
                            amount=diff,
                            currency=wallet_currency,
                            description=f"Adjustment: sandbox biller charged less than reserved",
                            reference=f"ADJ-{run_reference}",
                            metadata={
                                "original_reference": run_reference,
                                "debited": debit_amount,
                                "charged": test_amount,
                            },
                        )
                    else:
                        adj_result = db.debit_wallet(
                            user_id=user_id,
                            amount=abs(diff),
                            currency=wallet_currency,
                            description=f"Adjustment: sandbox biller charged more than reserved",
                            reference=f"ADJ-{run_reference}",
                            metadata={
                                "original_reference": run_reference,
                                "debited": debit_amount,
                                "charged": test_amount,
                            },
                        )
                        if not adj_result.get("success"):
                            logger.warning(
                                f"Could not collect underpaid sandbox adjustment for {run_reference} — needs manual review"
                            )

                # Log the successful sandbox transaction
                db.create_reloadly_transaction(
                    reference=run_reference,
                    user_id=user_id,
                    transaction_type="utility",
                    amount=test_amount,
                    status="completed",
                    provider_transaction_id=f"sandbox-util-{run_reference}",
                    result={
                        "sandbox": True,
                        "message": f"Sandbox utility payment processed with amount {test_amount}",
                    },
                    currency=currency,
                )
                db.mark_fulfilled(
                    run_reference, {"sandbox": True, "amount": test_amount}
                )

                db.create_notification(
                    user_id,
                    "Utility Payment Successful ✅ (Sandbox)",
                    f"{currency} {test_amount:,.2f} paid for {subscriber_account} (Scheduled - Sandbox)",
                    "success",
                )

                log_event(
                    user_id=user_id,
                    event_type="schedule_run",
                    details={
                        "schedule_id": None,
                        "name": "Scheduled Utility Payment (Sandbox Fallback)",
                        "amount": test_amount,
                        "currency": currency,
                        "biller_id": biller_id,
                        "account": subscriber_account,
                        "sandbox": True,
                    },
                    status="success",
                )

                user = db.get_user(user_id)
                if user and user.get("email"):
                    send_email_notification(
                        user["email"],
                        "✅ Utility Payment Successful (Sandbox)",
                        f"Your scheduled utility payment was executed successfully in sandbox mode.\n\n"
                        f"Account: {subscriber_account}\nAmount: {currency} {test_amount:,.2f}\n"
                        f"Reference: {run_reference}",
                        include_promo=True,
                        promo_context={
                            "user_id": user_id,
                            "reference": run_reference,
                            "tx_type": "utility",
                            "amount": test_amount,
                        },
                    )

                return {
                    "success": True,
                    "result": {"sandbox": True, "amount": test_amount},
                    "reference": run_reference,
                }
        except Exception as e:
            logger.warning(
                f"Sandbox utility fallback with amount {test_amount} failed: {e}"
            )
            continue

    return {"success": False, "error": "All sandbox fallback attempts failed"}


# ============ ADD TO app.py - Promotion Application on Transactions ============


def apply_promotion_to_transaction(
    user_id: int,
    amount: float,
    service_type: str,
    promo_code: str = None,
    transaction_ref: str = None,
) -> Dict:
    """
    Apply the best available promotion to a transaction.
    Returns the discount details and whether to use promotion.
    """
    try:
        # Get active promotions for this service type
        context = {
            "user_id": user_id,
            "amount": amount,
            "service_type": service_type,
            "is_new_customer": db.count_user_fulfilled_transactions(user_id) == 0,
        }

        # Get active promotions
        promotions = db.get_active_promotions(context)

        # If promo_code provided, find matching promotion
        if promo_code:
            for promo in promotions:
                if promo.get("coupon_code", "").upper() == promo_code.upper():
                    # Check usage limit
                    if db.track_promotion_usage(promo["id"], user_id):
                        return db.calculate_promotion_discount(
                            promo, amount, service_type
                        )
            return {
                "discount_amount": 0,
                "applied_value": 0,
                "new_total": amount,
                "message": "Invalid or expired promo code",
            }

        # Find best promotion (highest discount)
        best_discount = 0
        best_result = None

        for promo in promotions:
            # Skip if no discount value
            if not promo.get("discount_value"):
                continue

            # Skip referral promos (handled separately)
            if promo.get("is_referral"):
                continue

            # Check usage limit
            if not db.track_promotion_usage(promo["id"], user_id):
                continue

            result = db.calculate_promotion_discount(promo, amount, service_type)
            if result.get("discount_amount", 0) > best_discount:
                best_discount = result.get("discount_amount", 0)
                best_result = result

        if best_result:
            return best_result

        return {
            "discount_amount": 0,
            "applied_value": 0,
            "new_total": amount,
            "message": "No applicable promotion",
        }

    except Exception as e:
        logger.error(f"Error applying promotion: {e}")
        return {
            "discount_amount": 0,
            "applied_value": 0,
            "new_total": amount,
            "message": "Promotion error",
        }


# ============ ADD TO app.py - Referral Token Processing ============


# ============ FIX: SCHEDULER UTILITY PAYMENT HANDLING ============
# ============ FIX: SCHEDULER TRANSACTION LOGGING ============
# Add this to app.py - replace the existing _execute_schedule_fulfillment function
# or add this missing create_pending call


# Circuit breaker for the bill-payment provider. When Reloadly Utilities fails with a server-side error
# (for example "Failed to retrieve balance"), stop taking customers' money for bills for a few minutes
# instead of charging them for something we cannot deliver.
_UTIL_STATE = {"down_until": 0.0, "reason": ""}
_UTIL_ERR_HINTS = ("server error", "balance", "timed out", "timeout", " 502", " 503", " 504", "service unavailable")


def _utility_provider_down():
    return time.time() < _UTIL_STATE["down_until"]


def _utility_trip(error_text):
    t = str(error_text or "").lower()
    if any(h in t for h in _UTIL_ERR_HINTS):
        mins = max(1, int(os.getenv("UTILITY_BREAKER_MINUTES", "10") or 10))
        _UTIL_STATE["down_until"] = time.time() + mins * 60
        _UTIL_STATE["reason"] = str(error_text)[:200]
        logger.error(f"Bill payments PAUSED for {mins} min (provider error): {_UTIL_STATE['reason']}")


def _bg_return_url():
    """Payment return URL for work done outside a web request (scheduler, sweeper)."""
    try:
        return _safe_payment_return_url(None)
    except Exception:
        base = (os.getenv("PUBLIC_URL") or os.getenv("FRONTEND_URL") or "").rstrip("/")
        return (base + "/payment/success") if base else None


def _svc_schedule_quote(schedule: Dict) -> Dict:
    """Look up today's real price for a TV / data schedule (plan price, or the smartcard's renewal price).
    Returns {ok, error, unavailable, price, plan, product, code, mode, acct, contact, cust_name, renewal, meta}."""
    import net365_providers as _np
    service_type = str(schedule.get("service_type") or "").lower()
    meta = schedule.get("metadata") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta or "{}")
        except Exception:
            meta = {}
    product = str(meta.get("product") or "").lower()
    code = str(meta.get("variation_code") or "")
    mode = "renew" if str(meta.get("subscription_type")) == "renew" else "change"
    raw_acct = re.sub(r"\s", "", str(schedule.get("subscriber_account") or ""))
    contact = _np.local_number(str(schedule.get("phone") or meta.get("contact_phone") or ""))
    out = {"ok": False, "meta": meta, "product": product, "code": code, "mode": mode, "contact": contact,
           "cust_name": "", "renewal": 0.0}
    if not _np.enabled():
        out.update(unavailable=True, error="This service is not available right now. It will try again at the next run.")
        return out
    if not product or (not code and not (service_type == "tv" and mode == "renew" and product in ("dstv", "gotv"))):
        out["error"] = "This schedule is missing its provider or plan. Please edit and fix."
        return out
    if service_type == "data":
        if not contact:
            out["error"] = "Missing phone number for the data bundle."
            return out
        plan = _np.find_plan(product, code)
        acct = contact
    else:
        plan = _np.find_service_plan(product, code) if code else {"name": "Renew current bouquet", "price": 0}
        acct = contact if product == "showmax" else raw_acct
        if not acct:
            out["error"] = "Missing smartcard number."
            return out
        if not contact:
            out["error"] = "Add a contact phone number to this schedule (the provider needs one)."
            return out
    if not plan:
        out["error"] = "That plan is no longer available. Please edit the schedule and pick another."
        return out
    price = float(plan["price"])
    if service_type == "tv" and product in ("dstv", "gotv", "startimes"):
        v = _np.verify_account(product, acct)
        if v.get("unavailable"):
            out.update(unavailable=True, error="Smartcard check is unavailable right now. It will try again at the next run.")
            return out
        if not v.get("ok"):
            out["error"] = v.get("message") or "The smartcard could not be verified. Please check the number."
            return out
        out["cust_name"] = v.get("name", "")
        if product in ("dstv", "gotv") and mode == "renew":
            out["renewal"] = float(v.get("renewal_amount") or 0)
            if out["renewal"] <= 0:
                out["error"] = "The current renewal price is not available. Please try again later."
                return out
            price = out["renewal"]
    out.update(ok=True, price=price, plan=plan, acct=acct)
    return out


def _schedule_price_alert(schedule: Dict, user_id: int, old: float, new: float, when_text: str = "") -> None:
    """Tell the customer a scheduled TV / data price moved (chat, in-app and email)."""
    up = new > old
    name = str(schedule.get("name") or "Your schedule")
    if up:
        body = (f'The price of "{name}" has gone UP from ₦{old:,.2f} to ₦{new:,.2f}. '
                f"We will send your pay link at the usual time with the new price. Nothing is charged unless you tap it. "
                f"You can pause or edit the schedule if you do not want it.")
        title = "📈 Scheduled price went up"
    else:
        body = (f'Good news: the price of "{name}" has gone DOWN from ₦{old:,.2f} to ₦{new:,.2f}. '
                f"We will send your pay link at the usual time with the lower price.")
        title = "📉 Scheduled price went down"
    try:
        db.create_notification(user_id, title, body, "warning" if up else "success")
    except Exception:
        logger.exception("price alert notification failed")
    sent = False
    try:
        from net365_whatsapp import send_chat_price_alert
        sent = send_chat_price_alert(user_id, {"name": name, "old": old, "new": new, "when": when_text})
    except Exception:
        logger.exception("price alert chat failed")
    if not sent:
        try:
            user = db.get_user(user_id) or {}
            if user.get("email"):
                send_email_notification(user["email"], title, body)
        except Exception:
            logger.exception("price alert email failed")


def _schedule_send_pay_link(schedule: Dict, user_id: int, platform) -> Dict:
    """Pay-link scheduler (no wallet): when a schedule is due, create a normal Paystack payment for the
    top-up or bill, and send the customer the link in their linked chat (or by email). When they pay,
    the usual finalize + completion message takes over. Nothing is charged without the customer tapping pay."""
    service_type = str(schedule.get("service_type") or "airtime").lower()
    currency = str(schedule.get("currency") or "NGN").upper()
    try:
        amount = float(schedule.get("amount") or 0)
    except (TypeError, ValueError):
        amount = 0
    if amount <= 0:
        return {"success": False, "error": "Invalid scheduled amount"}
    if currency != "NGN":
        return {"success": False, "error": "Pay-link schedules support NGN only for now."}
    user = db.get_user(user_id) or {}
    email = user.get("email")
    if not email:
        return {"success": False, "error": "Your account needs an email address."}

    country_code = str(schedule.get("country_code") or "NG").upper()
    payload = {"email": email, "user_id": user_id, "schedule_id": schedule.get("id"),
               "schedule_name": schedule.get("name"), "is_scheduled": True, "country_code": country_code}
    if service_type == "airtime":
        phone, operator_id = schedule.get("phone"), schedule.get("operator_id")
        if not phone or not operator_id:
            return {"success": False, "error": "Missing operator or phone number"}
        _fp, ok = platform._format_phone_for_schedule(phone, country_code)
        if not ok:
            return {"success": False, "error": f"Invalid {country_code} phone number: '{phone}'"}
        tx_type, target = "topup", "0" + re.sub(r"\D", "", str(phone))[-10:]
        payload.update({"operator_id": operator_id, "phone": encrypt_pii(phone)})
    elif service_type == "utility":
        biller_id, acct = schedule.get("biller_id"), schedule.get("subscriber_account")
        if not biller_id or not acct:
            return {"success": False, "error": "Missing biller or account number"}
        try:
            if _utility_provider_down():
                return {"success": False, "error": "Bill payments are temporarily unavailable. Nothing was charged; this schedule will try again at its next run."}
        except Exception:
            pass
        try:
            v = UtilityBillerValidator.validate_amount(int(biller_id), amount)
            if not v["valid"]:
                amount = v["adjusted"]
        except (ValueError, TypeError):
            return {"success": False, "error": f"Invalid biller_id: {biller_id}"}
        tx_type = "utility"
        a = str(acct)
        target = (a[:2] + "••••" + a[-3:]) if len(a) > 6 else a
        payload.update({"biller_id": biller_id, "subscriber_account": acct, "amount": amount,
                        "currency": "NGN", "biller_name": str(schedule.get("biller_name") or "")[:60]})
    elif service_type in ("tv", "data"):
        # TV subscriptions (DStv / GOtv / StarTimes / Showmax) and data bundles, bought through the provider router.
        # The price is looked up fresh on every run (renewal prices and plan prices change). A rise beyond the customer's
        # limit is never charged: they are told instead.
        import net365_providers as _np
        q = _svc_schedule_quote(schedule)
        if not q["ok"]:
            return {"success": False, "error": q["error"]}
        meta, product, code, mode = q["meta"], q["product"], q["code"], q["mode"]
        contact, plan, acct = q["contact"], q["plan"], q["acct"]
        cust_name, renewal, new_price = q["cust_name"], q["renewal"], q["price"]
        old_price = amount
        # Only a limit the customer set themselves can stop the link: they tap to pay, so a normal price change is
        # simply shown to them (and they were warned hours earlier).
        try:
            cap = float(meta.get("max_amount") or 0)
        except (TypeError, ValueError):
            cap = 0.0
        if cap > 0 and new_price > cap + 0.009:
            msg = (f'"{schedule.get("name")}" was not charged: the price is now ₦{new_price:,.2f}, above your limit of ₦{cap:,.2f}. '
                   f"Edit the schedule to approve the new price.")
            try:
                db.create_notification(user_id, "⏰ Scheduled payment paused", msg, "warning")
            except Exception:
                pass
            try:
                send_email_notification(email, "Your scheduled Net365 payment needs your approval", msg)
            except Exception:
                pass
            return {"success": False, "error": f"Price rose to ₦{new_price:,.2f} (limit ₦{cap:,.2f}). Customer notified."}
        amount = new_price
        tx_type = service_type
        label = _np.VTpassAdapter.TV.get(product) or product.upper()
        biller = (f"{label} {plan['name']}" if service_type == "tv" else str(plan["name"]))[:60]
        target = (acct[:2] + "••••" + acct[-3:]) if len(acct) > 6 else acct
        payload.update({"product": product, "network": product if service_type == "data" else "", "variation_code": code,
                        "phone": encrypt_pii(contact), "subscriber_account": encrypt_pii(acct),
                        "quantity": 1, "subscription_type": mode if service_type == "tv" and product in ("dstv", "gotv") else "",
                        "renewal_amount": renewal, "biller_name": biller, "customer_name": cust_name,
                        "currency": "NGN", "payment_method": "paystack"})
    else:
        return {"success": False, "error": f"Unsupported service type: {service_type}"}

    fee = server_fee_for(amount, "NGN")
    total = round(amount + fee, 2)
    link = None
    try:
        from net365_whatsapp import chat_link_for_user, chat_source_for_link
        link = chat_link_for_user(user_id)
        if link:
            payload["source"] = chat_source_for_link(link)
    except Exception:
        link = None
    payload["service_amount"], payload["fee_amount"] = amount, fee

    res = platform.create_payment(amount=total, currency="NGN", operator_id=payload.get("operator_id"),
                                  phone=schedule.get("phone") if tx_type == "topup" else None,
                                  country_code=country_code, email=email, return_url=_bg_return_url(),
                                  provider="paystack")
    if not (res.get("success") and res.get("reference")):
        return {"success": False, "error": res.get("error") or "Could not create the payment link"}
    db.create_pending(reference=res["reference"], tx_type=tx_type, provider=res.get("provider", "paystack"),
                      amount=total, currency="NGN", payload=payload, user_id=user_id)
    pay_url = res.get("authorization_url") or res.get("checkout_url")

    old_price = locals().get("old_price", amount)
    if service_type in ("tv", "data") and abs(amount - old_price) > 0.009:
        try:                                    # remember today's price so the next comparison starts from it
            _c = db.get_db_connection()
            _c.execute("UPDATE scheduler_schedules SET amount = ? WHERE id = ? AND user_id = ?",
                       (amount, schedule.get("id"), user_id))
            _c.commit()
            _c.close()
        except Exception:
            logger.exception("could not store the new schedule price")
    sent = False
    try:
        from net365_whatsapp import send_chat_reminder
        sent = send_chat_reminder(user_id, {
            "reference": res["reference"], "name": schedule.get("name") or "Scheduled payment",
            "service": "airtime" if tx_type == "topup" else "bill", "target": target,
            "biller_name": payload.get("biller_name"), "amount": amount, "fee": fee, "total": total, "url": pay_url,
            "old_amount": old_price if abs(amount - old_price) > 0.009 else None})
    except Exception:
        logger.exception("schedule chat reminder failed")
    if not sent:
        try:
            send_email_notification(
                email, f"⏰ Your scheduled Net365 payment is due: {schedule.get('name') or ''}",
                f"Your scheduled {'airtime top-up' if tx_type == 'topup' else 'bill payment'} of ₦{amount:,.2f} "
                f"for {target} is due.\n\nTotal with service fee: ₦{total:,.2f}\nPay securely here: {pay_url}\n\n"
                f"It is only paid when you tap the link. Ignore this email to skip.")
        except Exception:
            logger.exception("schedule reminder email failed")
    try:
        db.create_notification(user_id, "⏰ Payment due",
                               f'"{schedule.get("name")}" is due: ₦{total:,.2f}. Tap the link we sent to pay.', "info")
    except Exception:
        pass
    return {"success": True, "reminder_sent": True, "chat": bool(sent), "reference": res["reference"]}


def _wallet_airtime_via_router(reference, data, phone, service_amount, rt):
    """Nigerian airtime paid from the Net365 Wallet, offered to the provider router (VTpass / Flutterwave ...) in naira.
    Same rule as card-paid airtime: returns a Reloadly-shaped result when the router accepted the order, None when it is
    CERTAIN nothing was accepted (the caller may then use Reloadly), and RAISES when the outcome is unknown, so the caller
    keeps the wallet debit for review instead of refunding or ordering twice."""
    import net365_providers as _np
    if not _np.enabled():
        return None
    routed = _np.route_purchase(reference=reference, service="airtime",
                                network=_np.network_for(data.get("operator_name"), phone),
                                phone=phone, amount=service_amount)
    if routed.get("status") in ("success", "pending"):
        logger.info(f"Wallet airtime {reference} routed via {routed.get('provider')} ({routed.get('status')})")
        rt.record("vtpass", "airtime", True, reference)
        return {"status": "SUCCESSFUL" if routed["status"] == "success" else "PENDING",
                "transactionId": routed.get("provider_ref") or f"{routed.get('provider')}-{reference}",
                "provider": routed.get("provider"), "routed": True}
    if not routed.get("fallback_ok"):
        raise Exception("Provider router could not confirm the order; not retrying elsewhere: " + str(routed.get("message") or ""))
    rt.record("vtpass", "airtime", False, reference)
    return None


def _execute_schedule_fulfillment(schedule: Dict, user_id: int, platform) -> Dict:
    import uuid

    service_type = str(schedule.get("service_type") or "airtime").lower()
    amount = float(schedule.get("amount") or 0)
    currency = str(schedule.get("currency") or "NGN").upper()
    wallet_currency = str(schedule.get("wallet_currency") or currency).upper()
    schedule_id = schedule.get("id")

    if service_type in ("tv", "data"):
        # Subscriptions and bundles always go through a pay link the customer confirms (prices move, so no silent debit).
        return _schedule_send_pay_link(schedule, user_id, platform)

    if not WALLET_ENABLED or str(schedule.get("pay_mode") or "").lower() == "link":
        return _schedule_send_pay_link(schedule, user_id, platform)

    if amount <= 0:
        return {"success": False, "error": "Invalid scheduled amount"}

    if currency not in SUPPORTED_CURRENCIES:
        return {"success": False, "error": f"Unsupported currency: {currency}"}

    if wallet_currency != currency:
        return {
            "success": False,
            "error": f"Wallet currency {wallet_currency} does not match payment currency {currency}.",
        }

    operator_id = schedule.get("operator_id")
    phone = schedule.get("phone")
    country_code = str(schedule.get("country_code") or "NG").upper()
    biller_id = schedule.get("biller_id")
    subscriber_account = schedule.get("subscriber_account")

    if service_type == "airtime":
        if not operator_id or not phone:
            return {"success": False, "error": "Missing operator or phone number"}

        formatted_phone, is_valid = platform._format_phone_for_schedule(
            phone, country_code
        )
        if not is_valid:
            return {
                "success": False,
                "error": (
                    f"Scheduled payments require a valid {country_code} phone number. "
                    f"Received: '{phone}'. Please re-enter using international format "
                    f"(e.g. without a leading 0) and try again."
                ),
            }
        phone = formatted_phone

    elif service_type == "utility":
        if not biller_id or not subscriber_account:
            return {"success": False, "error": "Missing biller or account number"}

        try:
            biller_id_int = int(biller_id)
            validation = UtilityBillerValidator.validate_amount(biller_id_int, amount)
            if not validation["valid"]:
                logger.warning(
                    f"Scheduled utility amount validation: {validation['message']}"
                )
                amount = validation["adjusted"]
        except (ValueError, TypeError):
            return {"success": False, "error": f"Invalid biller_id: {biller_id}"}
    else:
        return {"success": False, "error": f"Unsupported service type: {service_type}"}

    # Check wallet balance
    balance_info = get_available_wallet_balance(user_id, wallet_currency, amount)
    if not balance_info.get("available"):
        return {
            "success": False,
            "error": f'Insufficient funds in {wallet_currency} wallet. Available: {wallet_currency} {balance_info.get("balance", 0):.2f}',
        }

    run_reference = f"SCHED-{schedule_id}-{uuid.uuid4().hex[:12]}"
    debit_done = False
    provider_called = False

    # For utility payments, resolve the amount we intend to send to Reloadly BEFORE
    # debiting the wallet
    debit_amount = amount
    if service_type == "utility":
        try:
            biller_limits = UtilityBillerValidator.get_biller_limits(int(biller_id))
            debit_amount = max(
                biller_limits.get("min", 50),
                min(amount, biller_limits.get("max", 5000)),
            )
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Invalid biller_id for validation: {e}"}

    try:
        # ============ DEBIT WALLET ============
        debit_result = db.debit_wallet(
            user_id=user_id,
            amount=debit_amount,
            description=f'Scheduled {service_type} - {schedule.get("name")}',
            reference=run_reference,
            currency=wallet_currency,
            metadata={
                "schedule_id": schedule_id,
                "service_type": service_type,
                "currency": currency,
            },
        )
        if not debit_result.get("success"):
            return {
                "success": False,
                "error": f'Failed to debit wallet: {debit_result.get("error")}',
            }
        debit_done = True

        # ============ FIX: CREATE PENDING TRANSACTION RECORD ============
        # This ensures the transaction appears in the transactions table
        tx_type = "airtime" if service_type == "airtime" else "utility"
        payload = {
            "schedule_id": schedule_id,
            "schedule_name": schedule.get("name"),
            "service_type": service_type,
            "operator_id": operator_id if service_type == "airtime" else None,
            "phone": phone if service_type == "airtime" else None,
            "country_code": country_code if service_type == "airtime" else None,
            "biller_id": biller_id if service_type == "utility" else None,
            "subscriber_account": (
                subscriber_account if service_type == "utility" else None
            ),
            "is_scheduled": True,
        }

        db.create_pending(
            reference=run_reference,
            tx_type=tx_type,
            provider="wallet",
            amount=debit_amount,
            currency=wallet_currency,
            payload=payload,
            user_id=user_id,
        )

        # ============ EXECUTE PAYMENT ============
        if service_type == "airtime":
            # Airtime top-up (existing logic)
            usd_amount = platform.convert_to_usd(amount, currency)

            if platform.credentials.environment.value == "sandbox":
                sandbox_valid_amounts = [
                    0.50,
                    1.00,
                    5.00,
                    10.00,
                    15.00,
                    20.00,
                    25.00,
                    50.00,
                    100.00,
                ]
                closest = min(sandbox_valid_amounts, key=lambda x: abs(x - usd_amount))
                usd_amount = (
                    closest
                    if abs(closest - usd_amount) / max(usd_amount, 0.01) < 0.2
                    else 5.00
                )
                logger.info(f"Sandbox: using amount ${usd_amount:.2f}")

            provider_called = True
            result = (
                platform.make_topup(
                    operator_id=str(operator_id),
                    amount=str(round(usd_amount, 2)),
                    recipient_phone={"countryCode": country_code, "number": phone},
                    use_local_amount=False,
                    custom_identifier=f"scheduled-{schedule_id}-{uuid.uuid4().hex[:8]}",
                    is_async=True,
                )
                or {}
            )

            transaction_id = result.get("transactionId") or result.get("id")
            provider_status = str(result.get("status") or "").upper()
            if transaction_id and provider_status != "FAILED":
                # ============ LOG SUCCESSFUL AIRTIME TRANSACTION ============
                db.create_reloadly_transaction(
                    reference=run_reference,
                    user_id=user_id,
                    transaction_type="airtime",
                    amount=amount,
                    status="completed",
                    provider_transaction_id=str(transaction_id),
                    result=result,
                    currency=currency,
                )
                db.mark_fulfilled(run_reference, result)

                # ============ FIX: Create transaction in main table if not already ============
                # Check if transaction already exists in main table
                existing_tx = db.get_transaction(run_reference)
                if not existing_tx:
                    db.create_pending(
                        reference=run_reference,
                        tx_type="airtime",
                        provider="wallet",
                        amount=amount,
                        currency=currency,
                        payload={
                            "schedule_id": schedule_id,
                            "schedule_name": schedule.get("name"),
                            "operator_id": operator_id,
                            "phone": phone,
                            "country_code": country_code,
                            "is_scheduled": True,
                            "transaction_id": str(transaction_id),
                        },
                        user_id=user_id,
                    )
                    db.mark_fulfilled(run_reference, result)

                log_event(
                    user_id=user_id,
                    event_type="schedule_run",
                    details={
                        "schedule_id": schedule_id,
                        "name": schedule.get("name"),
                        "amount": amount,
                        "currency": currency,
                        "phone": phone,
                        "operator_id": operator_id,
                        "result": result,
                    },
                    status="success",
                )
                user = db.get_user(user_id)
                if user and user.get("email"):
                    send_email_notification(
                        user["email"],
                        f'✅ Schedule Executed: {schedule.get("name")}',
                        f"Your scheduled {service_type} for {phone} was executed successfully.\n\nAmount: {currency} {amount:.2f}",
                        include_promo=True,
                        promo_context={
                            "user_id": user_id,
                            "reference": run_reference,
                            "tx_type": service_type,
                            "amount": amount,
                        },
                    )
                return {"success": True, "result": result, "reference": run_reference}

            # ============ REFUND ON FAILURE ============
            refund = db.credit_wallet(
                user_id=user_id,
                amount=amount,
                currency=wallet_currency,
                description=f'Refund for failed scheduled airtime {schedule.get("name")}',
                reference=f"REFUND-{run_reference}",
                metadata={
                    "original_reference": run_reference,
                    "provider_result": result,
                },
            )
            return {
                "success": False,
                "error": result.get("message")
                or result.get("error")
                or "Top-up failed",
                "refunded": refund.get("success", False),
                "needs_review": not refund.get("success", False),
                "reference": run_reference,
            }

        # ============ UTILITY PAYMENT ============
        local_amount = debit_amount
        logger.info(
            f"Scheduled utility: using amount {currency} {local_amount:.2f} for biller {biller_id}"
        )

        unique_ref = f"sched-util-{schedule_id}-{uuid.uuid4().hex[:8]}"[:36]

        provider_called = True
        result = (
            platform.pay_utility_bill(
                biller_id=int(biller_id),
                subscriber_account=subscriber_account,
                amount=local_amount,
                reference_id=unique_ref,
                use_local_amount=True,
            )
            or {}
        )

        transaction_id = result.get("transactionId") or result.get("id")
        status = str(result.get("status", "")).upper()

        if transaction_id and status not in ("FAILED", "ERROR"):
            # Reconcile amount
            charged_amount = result.get("_amount_charged")
            if (
                charged_amount is not None
                and abs(float(charged_amount) - debit_amount) > 0.005
            ):
                charged_amount = float(charged_amount)
                diff = round(debit_amount - charged_amount, 2)
                if diff > 0:
                    db.credit_wallet(
                        user_id=user_id,
                        amount=diff,
                        currency=wallet_currency,
                        description=f'Adjustment: biller charged less than reserved for {schedule.get("name")}',
                        reference=f"ADJ-{run_reference}",
                        metadata={
                            "original_reference": run_reference,
                            "debited": debit_amount,
                            "charged": charged_amount,
                        },
                    )
                elif diff < 0:
                    adj_result = db.debit_wallet(
                        user_id=user_id,
                        amount=abs(diff),
                        currency=wallet_currency,
                        description=f'Adjustment: biller charged more than reserved for {schedule.get("name")}',
                        reference=f"ADJ-{run_reference}",
                        metadata={
                            "original_reference": run_reference,
                            "debited": debit_amount,
                            "charged": charged_amount,
                        },
                    )
                    if not adj_result.get("success"):
                        logger.warning(
                            f"Could not collect underpaid adjustment of {wallet_currency} {abs(diff):.2f} "
                            f"for {run_reference} (insufficient balance) — payment already succeeded, needs manual review"
                        )
                local_amount = charged_amount

            # ============ LOG SUCCESSFUL UTILITY TRANSACTION ============
            db.create_reloadly_transaction(
                reference=run_reference,
                user_id=user_id,
                transaction_type="utility",
                amount=local_amount,
                status="completed",
                provider_transaction_id=str(transaction_id),
                result=result,
                currency=currency,
            )

            # ============ FIX: Ensure transaction exists in main table ============
            existing_tx = db.get_transaction(run_reference)
            if not existing_tx:
                db.create_pending(
                    reference=run_reference,
                    tx_type="utility",
                    provider="wallet",
                    amount=local_amount,
                    currency=currency,
                    payload={
                        "schedule_id": schedule_id,
                        "schedule_name": schedule.get("name"),
                        "biller_id": biller_id,
                        "subscriber_account": subscriber_account,
                        "is_scheduled": True,
                        "transaction_id": str(transaction_id),
                    },
                    user_id=user_id,
                )
                db.mark_fulfilled(run_reference, result)

            db.create_notification(
                user_id,
                "Utility Payment Successful ✅",
                f"{currency} {amount:,.2f} paid for {subscriber_account} (Scheduled)",
                "success",
            )

            log_event(
                user_id=user_id,
                event_type="schedule_run",
                details={
                    "schedule_id": schedule_id,
                    "name": schedule.get("name"),
                    "amount": amount,
                    "currency": currency,
                    "biller_id": biller_id,
                    "account": subscriber_account,
                    "result": result,
                    "scheduled": True,
                },
                status="success",
            )

            # ============ FIX: Send email notification on success ============
            user = db.get_user(user_id)
            if user and user.get("email"):
                send_email_notification(
                    user["email"],
                    f'✅ Utility Payment Successful: {schedule.get("name")}',
                    f"Your scheduled utility payment was executed successfully.\n\n"
                    f'Biller: {schedule.get("biller_name") or biller_id}\n'
                    f"Account: {subscriber_account}\n"
                    f"Amount: {currency} {amount:,.2f}\n"
                    f"Reference: {run_reference}",
                    include_promo=True,
                    promo_context={
                        "user_id": user_id,
                        "reference": run_reference,
                        "tx_type": "utility",
                        "amount": amount,
                    },
                )

            return {"success": True, "result": result, "reference": run_reference}

        # ============ HANDLE SANDBOX FALLBACK ============
        if platform.credentials.environment.value == "sandbox":
            logger.warning(
                f"Scheduled utility payment failed with amount {local_amount}, trying sandbox fallback"
            )
            sandbox_result = handle_sandbox_utility_fallback(
                platform,
                int(biller_id),
                subscriber_account,
                currency,
                str(schedule_id),
                run_reference,
                user_id,
                debit_amount,
                wallet_currency,
            )
            if sandbox_result.get("success"):
                return sandbox_result

        # ============ REFUND ON FAILURE ============
        refund = db.credit_wallet(
            user_id=user_id,
            amount=debit_amount,
            currency=wallet_currency,
            description=f'Refund for failed scheduled utility payment {schedule.get("name")}',
            reference=f"REFUND-{run_reference}",
            metadata={"original_reference": run_reference, "provider_result": result},
        )

        log_event(
            user_id=user_id,
            event_type="schedule_run",
            details={
                "schedule_id": schedule_id,
                "name": schedule.get("name"),
                "amount": amount,
                "currency": currency,
                "biller_id": biller_id,
                "account": subscriber_account,
                "error": result.get("message")
                or result.get("error", "Utility payment failed"),
            },
            status="failed",
        )

        return {
            "success": False,
            "error": result.get("message")
            or result.get("error")
            or "Utility payment failed",
            "refunded": refund.get("success", False),
            "needs_review": not refund.get("success", False),
            "reference": run_reference,
        }

    except Exception as exc:
        logger.exception(f"Schedule fulfillment error: {exc}")

        if debit_done and provider_called:
            return {
                "success": False,
                "error": "Provider response could not be confirmed. Transaction requires review before refund.",
                "needs_review": True,
                "reference": run_reference,
                "detail": str(exc),
            }

        if debit_done:
            refund = db.credit_wallet(
                user_id=user_id,
                amount=debit_amount if "debit_amount" in locals() else amount,
                currency=wallet_currency,
                description=f'Refund for failed scheduled payment {schedule.get("name")}',
                reference=f"REFUND-{run_reference}",
                metadata={"original_reference": run_reference, "reason": str(exc)},
            )
            return {
                "success": False,
                "error": str(exc),
                "refunded": refund.get("success", False),
                "needs_review": not refund.get("success", False),
                "reference": run_reference,
            }

        return {"success": False, "error": str(exc)}


def _finalize_schedule_run(
    schedule_id: str, user_id: int, schedule: Dict, result: Dict
) -> Dict:
    """Apply the outcome of _execute_schedule_fulfillment to the schedule row and notify
    the user. Shared by the manual 'Execute Now' endpoint and the automatic trigger loop
    so both paths behave identically and can never drift apart."""
    conn = db.get_db_connection()
    c = conn.cursor()

    if result.get("success"):
        c.execute(
            """
            UPDATE scheduler_schedules 
            SET last_run = CURRENT_TIMESTAMP, status = 'completed', 
                last_error = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        """,
            (schedule_id, user_id),
        )

        if schedule.get("frequency") and schedule.get("frequency") != "once":
            next_run = calculate_next_run(
                schedule["frequency"],
                schedule.get("day_of_month", 1),
                schedule.get("time", "09:00"),
                schedule.get("day_of_week", 0),
                schedule.get("month", 1),
                schedule.get("event_date"),
                schedule.get("timezone") or "Africa/Lagos",
            )
            if next_run:
                c.execute(
                    """
                    UPDATE scheduler_schedules 
                    SET next_run = ?, status = 'active'
                    WHERE id = ? AND user_id = ?
                """,
                    (next_run, schedule_id, user_id),
                )

        conn.commit()
        conn.close()  # release the SQLite handle before notifying (was leaked)

        log_event(
            user_id=user_id,
            event_type="schedule_run",
            details={
                "schedule_id": schedule_id,
                "name": schedule.get("name"),
                "result": result.get("result"),
            },
            status="success",
        )
        if not result.get("reminder_sent"):
            db.create_notification(
                user_id,
                "✅ Schedule Executed",
                f'Schedule "{schedule.get("name")}" executed successfully.',
                "success",
            )
        return {"success": True, "status": "completed", "needs_review": False}

    review_required = bool(result.get("needs_review"))
    if review_required:
        logger.critical(
            f"REFUND FAILED after failed scheduled run {result.get('reference')}: "
            f"customer was debited and NOT refunded — needs manual review"
        )
    schedule_status = "needs_review" if review_required else "failed"
    c.execute(
        """
        UPDATE scheduler_schedules 
        SET last_run = CURRENT_TIMESTAMP, status = ?, 
            last_error = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
    """,
        (
            schedule_status,
            result.get("error", "Execution failed"),
            schedule_id,
            user_id,
        ),
    )
    conn.commit()
    conn.close()  # release the SQLite handle (was leaked)

    log_event(
        user_id=user_id,
        event_type="schedule_run",
        details={
            "schedule_id": schedule_id,
            "name": schedule.get("name"),
            "error": result.get("error"),
        },
        status="failed",
    )
    db.create_notification(
        user_id,
        "⚠️ Schedule Requires Review" if review_required else "❌ Schedule Failed",
        (
            f'Schedule "{schedule.get("name")}" requires review: {result.get("error", "Unknown error")}'
            if review_required
            else f'Schedule "{schedule.get("name")}" failed: {result.get("error", "Unknown error")}'
        ),
        "warning" if review_required else "error",
    )
    return {
        "success": False,
        "status": schedule_status,
        "needs_review": review_required,
    }


class ScheduleAutoRunner:
    """Background thread that fires due schedules automatically, without a human clicking
    'Execute Now'. Mirrors ExchangeRateService's thread pattern above.

    IMPORTANT — only run this in ONE process. If you deploy app.py behind multiple
    gunicorn/uwsgi workers, each worker would otherwise try to fire the same due schedule
    at once. That's exactly what scheduler_worker.py's env var (NET365_SCHEDULER_ENABLED)
    is for: run this loop in exactly one dedicated process (scheduler_worker.py), and
    leave it off in your regular web workers.
    """

    _thread = None
    _running = False
    _platform = None
    _poll_seconds = 30

    @classmethod
    def start(cls, platform, poll_seconds: int = 30):
        if cls._running:
            logger.info("Schedule auto-runner already running")
            return
        cls._platform = platform
        cls._poll_seconds = max(poll_seconds, 10)
        cls._running = True
        cls._thread = threading.Thread(target=cls._loop, daemon=True)
        cls._thread.start()
        logger.info(f"Started schedule auto-runner, polling every {cls._poll_seconds}s")

    @classmethod
    def stop(cls):
        cls._running = False
        if cls._thread:
            cls._thread.join(timeout=2)
        logger.info("Stopped schedule auto-runner")

    @classmethod
    def _loop(cls):
        while cls._running:
            try:
                cls._tick()
            except Exception as e:
                logger.error(f"Schedule auto-runner tick error: {e}")
            time.sleep(cls._poll_seconds)

    @classmethod
    def _price_watch(cls, conn, c, candidates, now_utc):
        """A few hours before a TV / data schedule is due, look up today's price and tell the customer if it moved
        (up or down). Done once per due date; a failed lookup is retried after 30 minutes."""
        lead = float(os.getenv("NET365_PRICE_WATCH_HOURS", "6") or 6)
        if lead <= 0:
            return
        from datetime import timedelta as _td
        for r in candidates:
            norm = normalize_next_run(r["next_run"])
            if not norm:
                continue
            due_at = datetime.fromisoformat(norm)
            if due_at <= now_utc or due_at - now_utc > _td(hours=lead):
                continue
            row = c.execute("SELECT * FROM scheduler_schedules WHERE id = ? AND user_id = ? AND status = 'active'",
                            (r["id"], r["user_id"])).fetchone()
            if not row:
                continue
            sch = dict(row)
            if str(sch.get("service_type") or "").lower() not in ("tv", "data"):
                continue
            try:
                meta = json.loads(sch.get("metadata") or "{}") if isinstance(sch.get("metadata"), str) else dict(sch.get("metadata") or {})
            except Exception:
                meta = {}
            if meta.get("price_watch_run") == norm:
                continue
            retry = meta.get("price_watch_retry")
            if retry:
                try:
                    if datetime.fromisoformat(retry) > now_utc:
                        continue
                except Exception:
                    pass
            sch["metadata"] = meta
            q = _svc_schedule_quote(sch)
            if q.get("unavailable") or not q.get("ok"):
                if q.get("unavailable"):
                    meta["price_watch_retry"] = (now_utc + _td(minutes=30)).isoformat()
                else:                                   # a real problem (card invalid, plan gone): tell them once
                    meta["price_watch_run"] = norm
                    try:
                        db.create_notification(r["user_id"], "⚠️ Scheduled payment needs attention",
                                               f'"{sch.get("name")}": {q.get("error")}', "warning")
                    except Exception:
                        pass
            else:
                meta["price_watch_run"] = norm
                meta.pop("price_watch_retry", None)
                old, new = float(sch.get("amount") or 0), float(q["price"])
                if abs(new - old) > 0.009:
                    try:
                        _schedule_price_alert(sch, r["user_id"], old, new)
                    except Exception:
                        logger.exception("price alert failed")
                    if old and meta.get("max_amount") and new > float(meta["max_amount"]) + 0.009:
                        pass                            # the due-time run will hold it and tell them again
            c.execute("UPDATE scheduler_schedules SET metadata = ? WHERE id = ? AND user_id = ? AND status = 'active'",
                      (json.dumps(meta), r["id"], r["user_id"]))
            conn.commit()

    @classmethod
    def _tick(cls):
        conn = db.get_db_connection()
        c = conn.cursor()
        from datetime import timezone as _tz

        now_utc = datetime.now(_tz.utc)

        # next_run may be stored in mixed formats (naive, 'Z', '+00:00', with or
        # without milliseconds), so a SQL string comparison is unreliable.
        # Parse each value and compare real datetimes instead.
        candidates = c.execute(
            """
            SELECT id, user_id, next_run FROM scheduler_schedules
            WHERE status = 'active' AND next_run IS NOT NULL
        """
        ).fetchall()

        # Heartbeat (~every 10 ticks) so the logs prove the runner is alive and
        # show what it is waiting for.
        cls._tick_count = getattr(cls, "_tick_count", 0) + 1
        if cls._tick_count % 10 == 1:
            logger.info(
                f"Schedule auto-runner heartbeat: {len(candidates)} active schedule(s), "
                f"now(UTC)={now_utc.isoformat(timespec='seconds')}, "
                f"next_runs={[str(r['next_run']) for r in candidates[:5]]}"
            )

        due = []
        for r in candidates:
            norm = normalize_next_run(r["next_run"])
            if not norm:
                logger.warning(
                    f"Schedule {r['id']} has unparseable next_run {r['next_run']!r}"
                )
                continue
            if datetime.fromisoformat(norm) <= now_utc:
                due.append(r)

        try:
            cls._price_watch(conn, c, candidates, now_utc)
        except Exception as e:
            logger.error(f"Price watch error: {e}")

        for row in due:
            schedule_id, user_id = row["id"], row["user_id"]

            # Atomic claim: only one caller can flip status active -> processing.
            # If two ticks (or two processes) race on the same schedule, only the
            # winner's UPDATE affects a row, so the schedule can never fire twice.
            claimed = c.execute(
                """
                UPDATE scheduler_schedules SET status = 'processing', updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ? AND status = 'active'
            """,
                (schedule_id, user_id),
            )
            conn.commit()
            if claimed.rowcount == 0:
                continue

            try:
                schedule_row = c.execute(
                    "SELECT * FROM scheduler_schedules WHERE id = ? AND user_id = ?",
                    (schedule_id, user_id),
                ).fetchone()
                if not schedule_row:
                    continue
                schedule = dict(schedule_row)

                if schedule.get("service_type") == "airtime" and (
                    not schedule.get("country_code")
                    or not schedule.get("operator_id")
                    or not schedule.get("phone")
                ):
                    _finalize_schedule_run(
                        schedule_id,
                        user_id,
                        schedule,
                        {
                            "success": False,
                            "error": "Schedule is missing country, operator, or phone number. Please edit and fix.",
                        },
                    )
                    continue

                if schedule.get("service_type") == "utility" and (
                    not schedule.get("biller_id")
                    or not schedule.get("subscriber_account")
                ):
                    _finalize_schedule_run(
                        schedule_id,
                        user_id,
                        schedule,
                        {
                            "success": False,
                            "error": "Schedule is missing biller or account number. Please edit and fix.",
                        },
                    )
                    continue

                logger.info(
                    f"Auto-triggering schedule {schedule_id} ('{schedule.get('name')}') — due at {schedule.get('next_run')}"
                )
                result = _execute_schedule_fulfillment(schedule, user_id, cls._platform)
                _finalize_schedule_run(schedule_id, user_id, schedule, result)

            except Exception as e:
                logger.exception(
                    f"Auto-runner failed to execute schedule {schedule_id}: {e}"
                )
                try:
                    c.execute(
                        """
                        UPDATE scheduler_schedules 
                        SET status = 'needs_review', last_error = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ? AND user_id = ?
                    """,
                        (str(e), schedule_id, user_id),
                    )
                    conn.commit()
                except Exception:
                    pass

        try:
            conn.close()  # one handle per tick; release it explicitly
        except Exception:
            pass


class SMSCampaignAutoRunner:
    """Background thread that dispatches scheduled SMS campaigns automatically once their
    scheduled_for time is reached. Same pattern as ScheduleAutoRunner above — same
    single-process caveat applies (see that class's docstring)."""

    _thread = None
    _running = False
    _poll_seconds = 30

    @classmethod
    def start(cls, poll_seconds: int = 30):
        if cls._running:
            logger.info("SMS campaign auto-runner already running")
            return
        cls._poll_seconds = max(poll_seconds, 10)
        cls._running = True
        cls._thread = threading.Thread(target=cls._loop, daemon=True)
        cls._thread.start()
        logger.info(
            f"Started SMS campaign auto-runner, polling every {cls._poll_seconds}s"
        )

    @classmethod
    def stop(cls):
        cls._running = False
        if cls._thread:
            cls._thread.join(timeout=2)
        logger.info("Stopped SMS campaign auto-runner")

    @classmethod
    def _loop(cls):
        while cls._running:
            try:
                cls._tick()
            except Exception as e:
                logger.error(f"SMS campaign auto-runner tick error: {e}")
            time.sleep(cls._poll_seconds)

    @classmethod
    def _tick(cls):
        due = db.get_due_sms_campaigns()
        for campaign in due:
            campaign_id = campaign["id"]
            # Atomic claim, same reasoning as the payment scheduler: prevents this
            # campaign from being dispatched twice if two ticks (or processes) race.
            if not db.claim_sms_campaign_for_dispatch(campaign_id):
                continue
            try:
                contacts = json.loads(campaign.get("contacts_json") or "[]")
                if not contacts:
                    db.update_sms_campaign_result(
                        campaign_id,
                        "failed",
                        0,
                        0,
                        {
                            "note": "No contacts were saved with this campaign — nothing to send."
                        },
                    )
                    continue
                logger.info(
                    f"Auto-dispatching SMS campaign {campaign_id} ('{campaign.get('name')}') "
                    f"to {len(contacts)} recipients"
                )
                result = send_sms_via_provider(
                    contacts,
                    campaign.get("message", ""),
                    campaign.get("sender_id", "Net365"),
                )
                status = "sent" if result.get("sent", 0) > 0 else "failed"
                db.update_sms_campaign_result(
                    campaign_id,
                    status,
                    result.get("sent", 0),
                    result.get("failed", 0),
                    result,
                )
            except Exception as e:
                logger.exception(
                    f"Auto-runner failed to dispatch SMS campaign {campaign_id}: {e}"
                )
                try:
                    db.update_sms_campaign_result(
                        campaign_id, "failed", 0, 0, {"note": str(e)}
                    )
                except Exception:
                    pass


# ============ FLASK APP ============
class ReloadlyWebApp:
    def __init__(self, credentials: ReloadlyCredentials):
        self.credentials = credentials
        self.platform = ReloadlyPlatform(credentials)
        self.app = Flask(__name__)
        flask_secret = os.getenv("FLASK_SECRET_KEY", "").strip()
        if not flask_secret:
            _is_production = (
                os.getenv("ENVIRONMENT", "").lower() == "production"
                or os.getenv("FLASK_ENV", "").lower() == "production"
                or bool(os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("RAILWAY_PROJECT_ID"))
                or bool(os.getenv("RENDER_SERVICE_ID"))
            )
            if _is_production:
                raise ValueError("FLASK_SECRET_KEY is required in production deployments")
            flask_secret = "net365-development-secret-change-me"
            logger.warning("FLASK_SECRET_KEY not set; using development-only fallback")
        self.app.secret_key = flask_secret
        self.app.config["SESSION_COOKIE_HTTPONLY"] = True
        self.app.config["SESSION_COOKIE_SECURE"] = SESSION_COOKIE_SECURE
        self.app.config["SESSION_COOKIE_SAMESITE"] = SESSION_COOKIE_SAMESITE
        self.app.config["SESSION_COOKIE_DOMAIN"] = SESSION_COOKIE_DOMAIN
        self.app.config["SESSION_COOKIE_PATH"] = "/"

        db.init_db()
        db.ensure_success_page_ads_schema()
        # ---- IP intelligence (org / ASN / bot detection) ----
        IPIntel.ensure_schema(db.get_db_connection)
        IPIntel.start_worker()
        # Net365 Smart Media: initialize the ad campaign/event tables and expose
        # /api/ads/recommend, /api/ads/event and /api/ads/health.
        # The module is deployed alongside app.py; ad failures must never affect payments.
        try:
            from net365_ads_backend import ads_bp, init_ads_db

            # Path resolution:
            #   1. NET365_DB_PATH env var, if set — this is what production
            #      (Railway) uses, pointing at the mounted persistent volume
            #      (/mnt/data/net365.db).
            #   2. Otherwise, fall back to a net365.db sitting next to this
            #      file — which is correct on any developer machine
            #      (Windows, macOS, Linux) with no env configuration needed.
            #
            # The old hardcoded "/mnt/data/net365.db" default was Linux-only:
            # on Windows that directory doesn't exist, so SQLite raised
            # "unable to open database file" every startup, and the Smart
            # Media subsystem silently stayed offline on dev machines.
            _default_ads_db = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "net365.db",
            )
            ads_db_path = os.getenv("NET365_DB_PATH", _default_ads_db)
            init_ads_db(ads_db_path)
            if "net365_ads" not in self.app.blueprints:
                self.app.register_blueprint(ads_bp)
            logger.info("Net365 Smart Media routes registered using %s", ads_db_path)
        except Exception as ads_init_error:
            # Fail visibly in logs but keep the payment/recharge app bootable.
            logger.exception("Net365 Smart Media could not initialize: %s", ads_init_error)
        # Terms of Service: versioned document, proof of acceptance, web + mobile + chat endpoints.
        try:
            from net365_legal import init_legal
            from net365_whatsapp import bot_required as _bot_required
            init_legal(self.app, db, login_required, admin_required, _bot_required, get_client_ip)
        except ImportError:
            logger.warning("net365_legal.py not found: Terms acceptance is not active")
        except Exception as _legal_err:
            logger.error(f"Terms module failed to start: {_legal_err}")
        # Support tickets and incidents for web, mobile, WhatsApp and Telegram, with an agent desk at /admin/support.
        try:
            from net365_support import init_support
            from net365_whatsapp import bot_required as _bot_required_s
            init_support(self.app, db, login_required, admin_required, _bot_required_s, send_email_notification)
        except ImportError:
            logger.warning("net365_support.py not found: support tickets are not active")
        except Exception as _sup_err:
            logger.error(f"Support module failed to start: {_sup_err}")
        # Shield: scores hostile visitors, blocks them (app + Cloudflare edge), emails the team, reports to PostHog. Admin page: /admin/shield.
        # Smart Share: location-aware recharge identity, one-time requests, gifting. Also serves /api/geo/context.
        try:
            from net365_smartshare import init_smartshare
            init_smartshare(self.app, db, login_required, get_client_ip,
                            referral_code_fn=lambda uid: db.get_referral_code_by_user_id(uid))
        except ImportError:
            logger.warning("net365_smartshare.py not found: Smart Share is not active")
        except Exception as _ss_err:
            logger.error(f"Smart Share failed to start: {_ss_err}")
        # Account profile: types, tiers, workspaces, Affiliate programme.
        try:
            from net365_profile import init_profile
            init_profile(self.app, db.get_db_connection, login_required, admin_required)
        except ImportError:
            logger.warning("net365_profile.py not found: account profiles are not active")
        except Exception as _pf_err:
            logger.error(f"Account profile module failed to start: {_pf_err}")
        # Home adverts under Ask Net365 (managed in admin.html > Home Adverts).
        try:
            from net365_homeads import init_homeads
            init_homeads(self.app, db.get_db_connection, admin_required, get_client_ip)
        except ImportError:
            logger.warning("net365_homeads.py not found: home adverts are not active (the chat animation still shows)")
        except Exception as _ha_err:
            logger.error(f"Home adverts failed to start: {_ha_err}")
        # Membership: permanent number, Founders rank and badge (existing verified customers are numbered by sign-up order on first start).
        try:
            from net365_membership import init_membership
            init_membership(self.app, db.get_db_connection, login_required, admin_required)
        except ImportError:
            logger.warning("net365_membership.py not found: membership numbers are not active")
        except Exception as _mb_err:
            logger.error(f"Membership failed to start: {_mb_err}")
        # Ask Net365 question log, with admin replies (admin.html > Ask Net365).
        try:
            from net365_askqa import init_askqa
            init_askqa(self.app, db.get_db_connection, admin_required, get_authenticated_user, get_client_ip,
                       notify=lambda _uid, _t, _m: db.create_notification(_uid, _t, _m, "info"),
                       send_email=lambda _to, _s, _m: send_email_notification(_to, _s, _m))
        except ImportError:
            logger.warning("net365_askqa.py not found: Ask Net365 questions are not logged")
        except Exception as _aq_err:
            logger.error(f"Ask Net365 log failed to start: {_aq_err}")
        # Reliable admin email: every alert is stored, sent at once, and retried for 24h (see net365_alerts.py).
        _mail_fn = send_email_notification
        _admin_alert_fn = None
        try:
            from net365_alerts import init_alerts
            _al = init_alerts(self.app, db.get_db_connection, send_email_notification, admin_required)
            _mail_fn = _al["send_email"]
            _admin_alert_fn = _al["send_admin_alert"]
            self.app.config["NET365_SEND_ADMIN_ALERT"] = _admin_alert_fn
            self.app.extensions["net365_send_email"] = _mail_fn
        except Exception as _al_err:
            logger.error(f"Admin alerts outbox NOT loaded (emails stay fire-and-forget): {_al_err}", exc_info=True)

        # Account admin (soft-delete audit, admin edit, SMS-confirmed phone numbers).
        try:
            from net365_accounts import init_accounts

            def _acct_send_sms(e164, text):
                num = e164 if SMS_PROVIDER_NAME == "twilio" else e164.lstrip("+")
                res = send_sms_via_provider([num], text, os.getenv("SMS_SENDER_ID", "Net365"))
                return bool(res and res.get("sent"))

            self._accounts = init_accounts(
                self.app, db, login_required, admin_required, rate_limit,
                send_email=send_email_notification, send_sms=_acct_send_sms,
                sms_ready=lambda: bool(SMS_PROVIDER_CONFIGURED),
                log_event=log_event, admin_identity=lambda: get_client_ip(),
            )
            logger.info("Account admin module loaded (edit user, deleted audit, phone verification routes are live)")
        except Exception as _acct_err:
            logger.error(f"Account admin module NOT loaded: {_acct_err}", exc_info=True)

        try:
            from net365_shield import init_shield
            init_shield(self.app, db, admin_required, get_client_ip, _mail_fn)
        except ImportError:
            logger.warning("net365_shield.py not found: the shield is not active")
        except Exception as _shield_err:
            logger.error(f"Shield failed to start: {_shield_err}")

        # WhatsApp banking: account linking + PIN auth for the Node bot (needs WHATSAPP_BOT_SECRET).
        try:
            from net365_whatsapp import init_whatsapp_banking
            init_whatsapp_banking(self.app, db, send_email_notification)
            from net365_whatsapp import set_decryptor
            set_decryptor(decrypt_payload)
            try:
                from net365_whatsapp import set_welcome_hook
                set_welcome_hook(send_welcome_once)
            except ImportError:
                # An older net365_whatsapp.py on the server must not stop everything after this line from loading.
                logger.warning("net365_whatsapp.py is out of date (no set_welcome_hook): chat sign-up welcome emails are off. Deploy the latest file.")
            # Money Intelligence: one reporting engine for the web API, the bots and scheduled reports (additive; moves no money).
            try:
                import net365_money_intelligence as _mi
                from net365_whatsapp import send_chat_report as _send_chat_report
                _mi.set_decryptor(decrypt_payload)
                _mi.init_money_intelligence(self.app, db, login_required, send_email_notification, _send_chat_report)
            except Exception as _mi_err:
                logger.exception("Money Intelligence could not initialize: %s", _mi_err)
            from net365_whatsapp import is_guest_user as _is_guest_user
            from net365_giftcards import init_giftcards, set_limit_check
            init_giftcards(
                self.app, login_required=login_required, credentials=self.credentials, db=db,
                platform=self.platform, usd_to_ngn=lambda: ExchangeRateService.get_rate("NGN", "USD"),
                safe_return_url=_safe_payment_return_url, is_guest_user=_is_guest_user,
            )
            set_limit_check(lambda uid, amt: _purchase_limit_error(uid, amt, "NGN"))
            try:
                from net365_saved import init_saved
                init_saved(
                    self.app, login_required=login_required, db=db, encrypt=encrypt_pii, decrypt=decrypt_pii,
                    decrypt_payload=decrypt_payload, server_fee_for=server_fee_for,
                    finalize=self._finalize_transaction,
                    limit_check=lambda uid, amt: _purchase_limit_error(uid, amt, "NGN"),
                    utility_down=_utility_provider_down,
                )
                from net365_network_memory import init_network_memory
                init_network_memory(
                    self.app, db, login_required,
                    operator_lookup=lambda oid: self.platform.get_operator_by_id(int(oid)),
                )
                from net365_ratings import init_ratings
                init_ratings(self.app, db, login_required, admin_required)
                try:
                    from net365_milestones import init_milestones
                    init_milestones(
                        self.app, db, admin_required,
                        lambda to, subject, html, text: send_branded_email(
                            to, subject, html, text, from_name=os.getenv("MILESTONE_FROM_NAME", "Net365")),
                        public_url=PUBLIC_URL, frontend_url=FRONTEND_URL,
                    )
                except Exception as _ms:
                    logger.warning(f"Milestones not loaded: {_ms}")
                try:
                    from net365_providers import init_providers

                    def _provider_resolved(reference, provider, o):
                        """A pending provider order reached its final state: keep the order row honest."""
                        try:
                            st = "completed" if o["status"] == "success" else "failed"
                            conn = db.get_db_connection()
                            try:
                                conn.execute("UPDATE reloadly_transactions SET status = ? WHERE reference = ? AND status = 'processing'",
                                             (st, reference))
                                conn.commit()
                            finally:
                                conn.close()
                        except Exception as _he:
                            logger.warning(f"provider resolve update failed for {reference}: {_he}")

                    init_providers(self.app, db, admin_required, on_resolved=_provider_resolved)
                except Exception as _pv:
                    logger.warning(f"Provider router not loaded: {_pv}")
                try:
                    from net365_routing import init_routing
                    init_routing(self.app, db, admin_required)
                except Exception as _rt_e:
                    logger.warning(f"Provider routing policy not loaded: {_rt_e}")
                try:
                    from net365_identity import init_identity

                    _WA_OTP = os.getenv("IDENTITY_WHATSAPP_OTP", "").lower() == "true" and bool(os.getenv("WHATSAPP_BOT_SECRET"))

                    def _identity_whatsapp(e164, message):
                        """Send the code to the customer's own WhatsApp through the bot. Because it goes to the number they
                        typed, receiving it proves they control that number."""
                        _m = re.search(r"\b(\d{6})\b", message)
                        if not _m:
                            return False
                        try:
                            _url = os.getenv("CHAT_BOT_NOTIFY_URL", "http://127.0.0.1:3001/internal/notify")
                            _r = requests.post(
                                _url,
                                json={"wa": e164.lstrip("+"), "kind": "otp", "code": _m.group(1)},
                                headers={"X-Bot-Secret": os.getenv("WHATSAPP_BOT_SECRET", "")},
                                timeout=30,
                            )
                            return _r.status_code == 200 and bool((_r.json() or {}).get("ok"))
                        except Exception as _we:
                            logger.warning(f"identity: WhatsApp code delivery failed: {_we}")
                            return False

                    def _identity_sms(e164, message):
                        if SMS_PROVIDER_CONFIGURED:
                            num = e164 if SMS_PROVIDER_NAME == "twilio" else e164.lstrip("+")
                            res = send_sms_via_provider([num], message, os.getenv("SMS_SENDER_ID", "Net365"))
                            if res and res.get("sent"):
                                return True
                        return _identity_whatsapp(e164, message) if _WA_OTP else False

                    init_identity(
                        self.app, db, login_required, rate_limit,
                        send_sms=_identity_sms,
                        send_email=lambda to, subj, msg: send_email_notification(to, subj, msg),
                        admin_required=admin_required,
                        page_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "complete_profile.html"),
                        sms_ready=lambda: SMS_PROVIDER_CONFIGURED or _WA_OTP,
                    )
                except Exception as _id_e:
                    logger.warning(f"Identity engine not loaded: {_id_e}")
                try:
                    from net365_recovery import init_recovery
                    init_recovery(self.app, db, admin_required)
                except Exception as _rc_e:
                    logger.warning(f"Recovery engine not loaded: {_rc_e}")
                try:
                    from net365_geoint import init_geoint
                    init_geoint(self.app, db, login_required, admin_required)
                except Exception as _ge:
                    logger.warning(f"GEOINT not loaded: {_ge}")
                from net365_merchants import init_merchants
                init_merchants(
                    self.app, login_required=login_required, db=db, admin_required=admin_required,
                    limit_check=lambda uid, amt: _purchase_limit_error(uid, amt, "NGN"),
                    init_paystack=lambda email, amt, ref, ret, extra: PaymentProcessor(
                        "paystack", os.getenv("PAYSTACK_SECRET_KEY")).init_paystack_payment(email, amt, ref, ret, extra),
                    return_url_for=_safe_payment_return_url,
                )
            except Exception as _e2:
                logger.error(f"Saved/merchant modules failed to start: {_e2}")
        except Exception as e:
            logger.warning(f"WhatsApp banking API not loaded: {e}")
        # Rewards: points/levels/streaks for the success page. Non-cash; failures never affect payments.
        try:
            from net365_rewards import init_rewards
            init_rewards(self.app, db.get_db_connection, admin_required)
        except Exception as e:
            logger.warning(f"Rewards module not loaded: {e}")
        # Ad engine (phase 1): ad view/click tracking for every surface. Never affects payments.
        try:
            from net365_adengine import init_adengine
            init_adengine(self.app, db, admin_required, FRONTEND_URL)
        except Exception as e:
            logger.warning(f"Ad engine not loaded: {e}")
        # Ad credits (phase 2): ad views earned by transacting, spent on Boost ads. OFF until admin enables it.
        try:
            from net365_adcredits import init_adcredits
            init_adcredits(self.app, db, admin_required, login_required)
        except Exception as e:
            logger.warning(f"Ad credits not loaded: {e}")
        self.setup_routes()
        self._start_pending_sweeper()
        self.app.before_request(_wallet_policy_guard)

        def _public_app_config():
            """Lets the web pages hide wallet features that the server will refuse anyway."""
            return jsonify({
                "success": True,
                "wallet_enabled": WALLET_ENABLED,
                "transfers_enabled": WALLET_TRANSFERS_ENABLED,
                "limits": {"per_transaction_ngn": LIMIT_PER_TX_NGN, "daily_ngn": LIMIT_DAILY_NGN},
            })
        self.app.add_url_rule("/api/app/config", "public_app_config", _public_app_config, methods=["GET"])
        self.app.before_request(log_page_visit)

        # Request-level analytics, rate limiting, 404/403 monitoring (never blocks a customer on failure).
        try:
            from net365_traffic import init_traffic
            init_traffic(
                self.app, db.get_db_connection, admin_required, get_client_ip,
                get_user=get_authenticated_user, rate_hit_db=_rate_hit_db, detect_bot=detect_bot, logger=logger,
            )
        except Exception as e:
            logger.warning(f"Traffic analytics not loaded: {e}")

        # Investor intelligence: organisation-level engagement with investor-facing pages.
        try:
            from net365_investors import init_investors
            try:
                import net365_traffic as _nt
                _asn_fn = lambda _ip: _nt._asn_for(_ip, db.get_db_connection)
            except Exception:
                _asn_fn = None  # investors works without the traffic module (no network lookups)
            init_investors(
                self.app, db.get_db_connection, admin_required, get_client_ip, rate_hit_db=_rate_hit_db,
                send_email=send_email_notification, asn_for=_asn_fn,
                base_url=FRONTEND_URL, logger=logger,
            )
        except Exception as e:
            logger.error(f"Investor intelligence NOT loaded: {e}", exc_info=True)

        # Guest / demo / free-evaluation access (side tables; fail-closed guard for evaluation accounts).
        try:
            from net365_access import init_access
            global _access_enrich_user
            _acc = init_access(
                self.app, get_conn=db.get_db_connection, get_authenticated_user=get_authenticated_user,
                create_user=db.create_user, create_session=db.create_session, set_auth_cookie=set_auth_cookie,
                get_user_by_email=db.get_user_by_email, create_otp=db.create_verification_otp,
                verify_otp=db.verify_otp, send_email=send_email_notification, admin_required=admin_required,
                get_client_ip=get_client_ip, rate_hit_db=lambda k, w: _rate_hit_db(k, w),
                frontend_url=FRONTEND_URL, notify_email=os.getenv("EVAL_NOTIFY_EMAIL") or None, logger=logger,
            )
            _access_enrich_user = _acc["enrich_user"]
        except Exception as e:
            logger.error(f"Access/evaluation module NOT loaded: {e}", exc_info=True)

        # Visitor analytics + sales/profit reports (consent-based; failures never affect the site).
        try:
            from net365_insights import init_insights
            init_insights(
                self.app, db, admin_required, rate_limit=rate_limit,
                get_user_id=lambda: (get_authenticated_user() or {}).get("id"),
            )
        except Exception as e:
            logger.error(f"Insights module NOT loaded (Reports tab will be empty): {e}", exc_info=True)

        # NET365 SENTINEL: threat detection + automated defence. Starts in OBSERVATION mode (detects and logs,
        # never auto-blocks) until you switch it in the Security tab. Fails open: an error here never blocks traffic.
        try:
            import inspect as _inspect
            from net365_sentinel import init_sentinel
            _sk = {"admin_secret": lambda: ADMIN_SECRET}
            _sparams = _inspect.signature(init_sentinel).parameters
            _hooked = next((n for n in ("send_email", "email_sender", "send_mail", "mailer", "notify_email") if n in _sparams), None)
            if _hooked:
                _sk[_hooked] = _mail_fn
                logger.info(f"Sentinel mail hook: connected through '{_hooked}' (queued, retried for 24h)")
            else:
                logger.warning(
                    "Sentinel mail hook: init_sentinel accepts no mail function (parameters: %s). "
                    "Block alerts depend on Sentinel's own code. Test delivery with POST /api/admin/alerts/test.",
                    ", ".join(_sparams),
                )
            init_sentinel(self.app, db, admin_required, get_client_ip, **_sk)
        except Exception as e:
            logger.error(f"SENTINEL NOT loaded (site is running without it): {e}", exc_info=True)

        # International Intelligence (admin "International" tab): serves /api/admin/sentinel/intelligence and /admin_intl.js.
        # Needs visitor_logs (written by Sentinel/visitor tracking). Read-only; never blocks anyone.
        try:
            from net365_intl_intel import register_intl_intel
            register_intl_intel(self.app, db, admin_required)
        except Exception as e:
            logger.error(f"International intelligence NOT loaded (admin International tab will show 404): {e}", exc_info=True)

        rate_interval = int(os.getenv("EXCHANGE_RATE_INTERVAL", 300))
        ExchangeRateService.start_auto_refresh(rate_interval)
        logger.info(f"Exchange rate auto-refresh started (interval: {rate_interval}s)")

        # Only start the automatic scheduler trigger loop in the single process
        # designated for it (scheduler_worker.py sets this env var). This is
        # deliberate: if app.py runs behind multiple web workers, only one of them
        # should own the clock, or the same due schedule could fire more than once.
        if os.getenv("NET365_SCHEDULER_ENABLED", "false").lower() == "true":
            poll_seconds = int(os.getenv("SCHEDULER_POLL_INTERVAL", 30))
            ScheduleAutoRunner.start(self.platform, poll_seconds)
            logger.info(f"Schedule auto-runner ENABLED (polling every {poll_seconds}s)")
            SMSCampaignAutoRunner.start(poll_seconds)
            logger.info(
                f"SMS campaign auto-runner ENABLED (polling every {poll_seconds}s)"
            )
            try:
                import net365_money_intelligence as _mi_runner
                from net365_whatsapp import send_chat_report as _scr
                _mi_runner.MoneyReportRunner.start(db, send_email_notification, _scr)
            except Exception:
                logger.exception("Money Intelligence report runner could not start")
        else:
            logger.info(
                "Schedule auto-runner DISABLED in this process (NET365_SCHEDULER_ENABLED is not 'true'). "
                "Schedules will only run when 'Execute Now' is clicked, or from a process that has this "
                "env var set — e.g. run scheduler_worker.py as one dedicated process in production."
            )

    def _find_transaction_by_stripe_session(
        self, session_id: str, tx_type: Optional[str] = None
    ) -> Optional[Dict]:
        """Find a transaction whose payload references the given Stripe session ID.

        NOTE: payload is stored Fernet-encrypted (see encrypt_pii in /api/payment/init),
        so a plain SQL LIKE against the raw column cannot match a plaintext session ID.
        We therefore scan recent transactions in Python, decrypt each payload, and
        compare. This is O(N) in recent transactions — acceptable because finalization
        only runs a handful of times per payment and the window is bounded.
        """
        if not session_id:
            return None

        try:
            conn = db.get_db_connection()
            c = conn.cursor()

            # Only consider transactions from the last 7 days — Stripe sessions
            # expire well before that, and this keeps the scan bounded.
            c.execute(
                """
                SELECT * FROM transactions
                WHERE provider = 'stripe'
                  AND created_at >= datetime('now', '-7 days')
                ORDER BY created_at DESC
                LIMIT 200
                """
            )
            rows = c.fetchall()

            for row in rows:
                tx = dict(row)

                # Optional filter — caller can narrow to a specific tx_type
                # (e.g. 'wallet_funding' or 'topup') when they know it.
                if tx_type and tx.get("tx_type") != tx_type:
                    continue

                raw_payload = tx.get("payload")
                if not raw_payload:
                    continue

                # decrypt_payload handles both the encrypted-string case and the
                # already-decrypted-dict case, so this is safe either way.
                payload = decrypt_payload(raw_payload)
                if not isinstance(payload, dict):
                    continue

                # Check the fields where the session ID might live.
                candidates = (
                    payload.get("stripe_session_id"),
                    payload.get("session_id"),
                    payload.get("checkout_session_id"),
                )
                if session_id in candidates:
                    tx["payload"] = payload  # return the decrypted form
                    return tx

            return None

        except Exception as e:
            logger.error(f"Error finding Stripe transaction for session {session_id}: {e}")
            return None


    def _find_stripe_session_for_reference(self, reference: str) -> Optional[str]:
        """Reverse lookup: given our internal reference (STR_...), find the
        Stripe checkout session ID (cs_...) that was created for it.

        First tries the local DB (fast, works offline), then falls back to
        asking Stripe directly by scanning recent sessions for a metadata.reference
        match. The Stripe fallback is what recovers transactions whose payload
        predates the fix that persists stripe_session_id at init time.
        """
        if not reference:
            return None

        # ── 1. Local DB scan ────────────────────────────────────────────────
        try:
            conn = db.get_db_connection()
            c = conn.cursor()
            c.execute(
                """
                SELECT * FROM transactions
                WHERE reference = ?
                  AND provider = 'stripe'
                LIMIT 1
                """,
                (reference,),
            )
            row = c.fetchone()
            if row:
                tx = dict(row)
                payload = decrypt_payload(tx.get("payload"))
                if isinstance(payload, dict):
                    sid = (
                        payload.get("stripe_session_id")
                        or payload.get("session_id")
                        or payload.get("checkout_session_id")
                    )
                    if sid and str(sid).startswith("cs_"):
                        logger.info(
                            f"_find_stripe_session_for_reference: local DB hit "
                            f"{reference} → {sid}"
                        )
                        return sid
        except Exception as e:
            logger.warning(
                f"_find_stripe_session_for_reference: DB lookup failed for "
                f"{reference}: {e}"
            )

        # ── 2. Ask Stripe ───────────────────────────────────────────────────
        # This is the recovery path for transactions created before the init-time
        # persistence fix landed. Stripe lets us filter sessions by metadata.
        if not STRIPE_AVAILABLE or not os.getenv("STRIPE_SECRET_KEY"):
            return None

        try:
            # Stripe doesn't support server-side metadata filtering on list(), so
            # we page through recent sessions and match client-side. Keep the scan
            # short — a session older than ~100 entries is almost certainly stale.
            sessions = stripe.checkout.Session.list(limit=100)
            for _i, s in enumerate(sessions.auto_paging_iter()):
                if _i >= 100:  # auto_paging_iter is unbounded; cap the scan
                    break
                meta = getattr(s, "metadata", None) or {}
                try:
                    meta_ref = meta.get("reference")
                except Exception:
                    meta_ref = None
                if meta_ref == reference:
                    logger.info(
                        f"_find_stripe_session_for_reference: Stripe lookup hit "
                        f"{reference} → {s.id}"
                    )
                    return s.id
        except Exception as e:
            logger.warning(
                f"_find_stripe_session_for_reference: Stripe list failed for "
                f"{reference}: {e}"
            )

        return None

    def _finalize_transaction(self, reference: str) -> Dict:
        if not reference:
            return {"success": False, "error": "Missing reference"}

        with _finalize_lock:
            # Everything up to the fulfillment lock used to be unprotected: any
            # DB error here (get_transaction, decrypt_payload, try_lock_for_fulfillment)
            # would propagate straight out of _finalize_transaction, past
            # /payment/success (which has no try/except of its own), and Flask
            # would return a raw 500 Internal Server Error instead of redirecting
            # the user back to the app. Wrapping it turns that into a clean
            # {"success": False} result, which the route already knows how to
            # handle (redirects with status=processing instead of crashing).
            try:
                max_retries = 5
                tx = None
                for attempt in range(max_retries):
                    try:
                        tx = db.get_transaction(reference)
                        break
                    except sqlite3.OperationalError as e:
                        if "database is locked" in str(e) and attempt < max_retries - 1:
                            time.sleep(0.5 * (attempt + 1))
                            continue
                        raise

                stripe_session_id = None

                if not tx and (reference.startswith("cs_") or reference.startswith("cs_test_")):
                    stripe_session_id = reference
                    tx = self._find_transaction_by_stripe_session(reference)
                    if tx:
                        logger.info(f"Found transaction {tx['reference']} for Stripe session {reference}")
                        reference = tx["reference"]

                if not tx:
                    return {"success": False, "error": f"Unknown reference: {reference}"}

                if tx.get("payload"):
                    tx["payload"] = decrypt_payload(tx["payload"])

                payload = tx.get("payload", {})

                logger.info(
                    f"Finalizing transaction: reference={reference}, tx_type={tx.get('tx_type')}, provider={tx.get('provider')}, status={tx.get('status')}"
                )

                if tx["status"] == "fulfilled":
                    return {
                        "success": True,
                        "already_fulfilled": True,
                        "result": tx["reloadly_result"],
                    }

                if not db.try_lock_for_fulfillment(reference):
                    logger.info(f"Transaction {reference} is already being processed, waiting...")
                    time.sleep(1)
                    tx = db.get_transaction(reference)
                    if tx and tx["status"] == "fulfilled":
                        return {"success": True, "already_fulfilled": True}
                    return {"success": False, "error": "Transaction is being processed"}
            except Exception as e:
                logger.error(f"FINALIZE PRE-CHECK FAILED for {reference}: {e}")
                import traceback
                logger.error(traceback.format_exc())
                return {"success": False, "error": str(e)}

            try:
                verify_reference = reference

                if tx.get("provider") == "stripe":
                    stripe_session_id = payload.get("stripe_session_id")
                    if stripe_session_id and str(stripe_session_id).startswith("cs_"):
                        verify_reference = stripe_session_id
                        logger.info(f"Using Stripe session ID from payload: {stripe_session_id}")
                    elif reference.startswith("cs_"):
                        verify_reference = reference
                        logger.info(f"Using Stripe session ID from reference: {reference}")
                    else:
                        # Neither the payload nor the reference gave us a session ID.
                        # This is exactly the failure mode that was making top-ups die with
                        # "No such checkout.session: STR_...". Recover it.
                        recovered = self._find_stripe_session_for_reference(reference)
                        if recovered:
                            verify_reference = recovered
                            logger.info(
                                f"Recovered Stripe session ID {recovered} for reference {reference}"
                            )
                        else:
                            logger.error(
                                f"Stripe transaction {reference} has no session ID in payload and "
                                f"none could be recovered from Stripe — verification will fail."
                            )

                try:
                    if tx.get("provider") == "cart":
                        verify_result = self._verify_cart_child(tx, payload)
                    else:
                        verify_result = self.platform.verify_payment(verify_reference, tx.get("provider"))
                    logger.info("Payment verification result: " + str({k: v for k, v in verify_result.items() if k != "authorization"}))
                    if verify_result.get("success") and payload.get("save_card") and verify_result.get("authorization") \
                            and tx.get("user_id"):
                        try:
                            from net365_saved import save_card_from_auth
                            save_card_from_auth(tx["user_id"], payload.get("email"), verify_result["authorization"])
                        except Exception:
                            logger.exception("saving opted-in card failed")
                except Exception as e:
                    logger.error(f"Payment verification error: {e}")
                    db.mark_fulfillment_failed(reference, f"Verification error: {str(e)}")
                    return {"success": False, "error": f"Verification error: {str(e)}"}

                if not verify_result.get("success"):
                    tx_check = db.get_transaction(reference)
                    if tx_check and tx_check["status"] == "fulfilled":
                        return {"success": True, "already_fulfilled": True}

                    if tx.get("tx_type") == "wallet_funding":
                        try:
                            wallet_tx = db.get_wallet_transaction_by_reference(reference)
                            if wallet_tx and wallet_tx.get("type") == "credit":
                                logger.info(f"Wallet funding {reference} already processed")
                                db.mark_fulfilled(reference, {"already_processed": True})
                                return {"success": True, "already_fulfilled": True}
                        except Exception as e:
                            logger.error(f"Error checking wallet transaction: {e}")

                    if tx.get("provider") == "stripe" and verify_reference == reference:
                        stripe_session_id = payload.get("stripe_session_id")
                        if stripe_session_id and stripe_session_id.startswith("cs_"):
                            logger.info(f"Retrying Stripe verification with session ID: {stripe_session_id}")
                            try:
                                verify_result = self.platform.verify_payment(stripe_session_id, "stripe")
                                logger.info(f"Stripe retry verification result: {verify_result}")
                            except Exception as e:
                                logger.error(f"Stripe retry verification error: {e}")

                    if not verify_result.get("success"):
                        if verify_result.get("pending"):
                            # Customer hasn't finished paying yet: put it back so a later
                            # webhook/verify can complete it; don't fail it.
                            try:
                                _c = db.get_db_connection()
                                _c.execute(
                                    "UPDATE transactions SET status='pending', updated_at=CURRENT_TIMESTAMP "
                                    "WHERE reference=? AND status='processing'",
                                    (reference,),
                                )
                                _c.close()
                            except Exception as _e:
                                logger.error(f"Could not revert {reference} to pending: {_e}")
                            return {
                                "success": False,
                                "pending": True,
                                "error": "Payment not completed yet",
                            }
                        db.mark_fulfillment_failed(
                            reference,
                            f'Payment not confirmed: {verify_result.get("error")}',
                        )
                        return {
                            "success": False,
                            "error": "Payment not confirmed",
                            "detail": verify_result,
                        }

                # ── Binding checks: the verified payment must be OUR payment ──
                if tx.get("provider") == "stripe":
                    _meta = verify_result.get("metadata")
                    try:
                        _meta_ref = _meta.get("reference") if _meta else None
                    except Exception:
                        _meta_ref = None
                    if _meta_ref and _meta_ref != reference:
                        logger.error(
                            f"Stripe metadata.reference {_meta_ref} != {reference}; refusing"
                        )
                        db.mark_fulfillment_failed(reference, "Stripe session does not belong to this transaction")
                        return {"success": False, "error": "Payment does not match this transaction"}
                try:
                    _paid = float(verify_result.get("amount") or 0)
                    _due = float(tx.get("amount") or 0)
                    _pc = str(verify_result.get("currency") or "").upper()
                    _tc = str(tx.get("currency") or "").upper()
                    if _pc and _tc and _pc == _tc and _due > 0:
                        if _paid + 0.02 < _due:  # gateways return the exact amount; allow only rounding
                            logger.error(f"Underpayment on {reference}: paid {_paid} {_pc}, due {_due}")
                            db.mark_fulfillment_failed(
                                reference, f"Underpaid: received {_paid} {_pc}, expected {_due}"
                            )
                            return {"success": False, "error": "Amount paid is less than amount due"}
                except (TypeError, ValueError):
                    pass

                tx_type = tx.get("tx_type", "topup")
                result = {}
                user_id = tx.get("user_id")

                # -----------------------------------------------------------------
                # 1. WALLET FUNDING
                # -----------------------------------------------------------------
                if tx_type == "wallet_funding":
                    if not user_id:
                        raise Exception("User ID not found for wallet funding")

                    user = db.get_user(user_id)
                    if not user:
                        raise Exception(f"User with ID {user_id} not found")

                    wallet_currency = (
                        payload.get("wallet_currency")
                        or tx.get("currency")
                        or verify_result.get("currency")
                        or "NGN"
                    ).upper()
                    amount = float(verify_result.get("amount", tx.get("amount", 0)))

                    logger.info(f"Executing wallet funding: user={user_id}, amount={amount}, currency={wallet_currency}")

                    credit_result = db.credit_wallet(
                        user_id=user_id,
                        amount=amount,
                        currency=wallet_currency,
                        description=f'Wallet funding via {tx.get("provider", "payment")} - Reference: {reference}',
                        reference=reference,
                        metadata={
                            "payment_reference": reference,
                            "provider": tx.get("provider"),
                        },
                    )
                    logger.info(f"Wallet credit result: {credit_result}")

                    if credit_result.get("success"):
                        # ---------------------------------------------------------
                        # Referral bonus handling.
                        #
                        # IMPORTANT: this block used to hardcode a 5% bonus and
                        # credit the referrer unconditionally, completely bypassing
                        # the admin kill-switch in referral_bonus_config. That meant
                        # toggling bonuses OFF in Admin > Bonus/Commission had no
                        # effect on wallet-funding-triggered referrals — they kept
                        # paying out.
                        #
                        # Now we:
                        #   1. Consult the authoritative config first; skip entirely
                        #      if bonuses are disabled.
                        #   2. Use the admin-configured percentage and min/max
                        #      rather than hardcoding 5%.
                        #   3. Wrap the whole thing in its own try/except so a
                        #      referral-side failure can never block the customer's
                        #      wallet funding from completing.
                        # ---------------------------------------------------------
                        referrer_id = None
                        referrer_user = None
                        user_email = None

                        try:
                            user_data = db.get_user_by_id(user_id)
                            if user_data:
                                referrer_id = user_data.get("referred_by")
                                user_email = user_data.get("email")
                                if referrer_id and referrer_id != user_id:
                                    logger.info(f"✅ User {user_id} was referred by user {referrer_id}")
                                    referrer_user = db.get_user_by_id(referrer_id)
                                    if referrer_user:
                                        logger.info(f"Referrer found: {referrer_user.get('email')}")
                        except Exception as e:
                            logger.error(f"Error processing referral: {e}")
                            import traceback
                            logger.error(traceback.format_exc())

                        # Credit referrer bonus — but respect the admin kill-switch
                        if referrer_id and referrer_id != user_id:
                            try:
                                bonus_config = db.get_referral_bonus_config()

                                if not is_referral_bonus_enabled() or not bonus_config.get("enabled", False):
                                    logger.info(
                                        f"⏸️ Referral bonus skipped for referrer {referrer_id} — "
                                        f"bonuses disabled by admin"
                                    )
                                    try:
                                        log_event(
                                            user_id=referrer_id,
                                            event_type="referral_bonus_skipped",
                                            details={
                                                "reason": "bonuses_disabled",
                                                "referred_id": user_id,
                                                "trigger_reference": reference,
                                                "trigger_amount": amount,
                                                "would_have_been_percentage": bonus_config.get("bonus_percentage"),
                                            },
                                            status="skipped",
                                        )
                                    except Exception as e:
                                        logger.warning(f"Could not write skip audit event: {e}")
                                else:
                                    # Use the admin-configured rate, not a hardcoded 5%.
                                    bonus_percentage = float(
                                        bonus_config.get("bonus_percentage") or 0
                                    )
                                    bonus_min = float(bonus_config.get("min_bonus") or 0)
                                    bonus_max = float(bonus_config.get("max_bonus") or 0)

                                    if bonus_percentage <= 0:
                                        logger.info(
                                            f"⏸️ Referral bonus skipped for referrer {referrer_id} — "
                                            f"configured percentage is {bonus_percentage}"
                                        )
                                    else:
                                        bonus_amount = amount * (bonus_percentage / 100)
                                        if bonus_min > 0:
                                            bonus_amount = max(bonus_amount, bonus_min)
                                        if bonus_max > 0:
                                            bonus_amount = min(bonus_amount, bonus_max)
                                        bonus_amount = round(bonus_amount, 2)
                                        bonus_currency = wallet_currency

                                        logger.info(
                                            f"💰 Crediting referral bonus: {bonus_currency} "
                                            f"{bonus_amount:,.2f} ({bonus_percentage}%) to referrer "
                                            f"{referrer_id}"
                                        )
                                        bonus_credit_result = db.credit_wallet(
                                            referrer_id,
                                            bonus_amount,
                                            currency=bonus_currency,
                                            description=f"Referral bonus from user {user_id}'s transaction",
                                            reference=f"REFBONUS-{reference}",
                                            metadata={
                                                "type": "referral_bonus",
                                                "referrer_id": referrer_id,
                                                "referred_id": user_id,
                                                "trigger_reference": reference,
                                                "trigger_amount": amount,
                                                "bonus_percentage": bonus_percentage,
                                                "bonus_amount": bonus_amount,
                                                "config_source": "wallet_funding",
                                            },
                                        )

                                        if bonus_credit_result.get("success"):
                                            logger.info(
                                                f"✅ Referral bonus credited to referrer {referrer_id}"
                                            )
                                            db.create_notification(
                                                referrer_id,
                                                "🎉 Referral Bonus Earned!",
                                                (
                                                    f"You earned {bonus_currency} "
                                                    f"{bonus_amount:,.2f} "
                                                    f"({bonus_percentage}% of your referral's "
                                                    f"transaction)!"
                                                ),
                                                "success",
                                            )
                                            if referrer_user and referrer_user.get("email"):
                                                try:
                                                    send_email_notification(
                                                        referrer_user["email"],
                                                        "🎉 You've Earned a Referral Bonus!",
                                                        (
                                                            f"Congratulations! You earned "
                                                            f"{bonus_currency} {bonus_amount:,.2f} "
                                                            f"({bonus_percentage}% of your "
                                                            f"referral's transaction)."
                                                        ),
                                                        include_promo=True,
                                                        promo_context={
                                                            "user_id": referrer_id,
                                                            "reference": f"REFBONUS-{reference}",
                                                            "tx_type": "referral",
                                                            "amount": bonus_amount,
                                                        },
                                                    )
                                                except Exception as e:
                                                    logger.error(
                                                        f"Failed to send email to referrer: {e}"
                                                    )
                                        else:
                                            logger.error(
                                                f"❌ Failed to credit referral bonus: "
                                                f"{bonus_credit_result}"
                                            )
                            except Exception as e:
                                logger.error(f"❌ Error giving referral bonus: {e}")
                                import traceback
                                logger.error(traceback.format_exc())

                        # Notify the user who funded their wallet
                        db.create_notification(
                            user_id,
                            "💰 Wallet Funded Successfully!",
                            f"Your wallet has been credited with {wallet_currency} {amount:,.2f}",
                            "success"
                        )
                        if user_email:
                            try:
                                send_email_notification(
                                    user_email,
                                    f"💰 Wallet Funded: {wallet_currency} {amount:,.2f}",
                                    f"Your wallet has been funded with {wallet_currency} {amount:,.2f}.\n\nReference: {reference}",
                                    include_promo=True,
                                    promo_context={
                                        "user_id": user_id,
                                        "reference": reference,
                                        "tx_type": "wallet_deposit",
                                        "amount": amount,
                                    },
                                )
                            except Exception as e:
                                logger.error(f"Failed to send email to user: {e}")

                        result = {
                            "status": "success",
                            "amount": amount,
                            "currency": wallet_currency,
                            "transaction_id": credit_result.get("transaction_id"),
                            "new_balance": credit_result.get("new_balance"),
                        }
                    else:
                        raise Exception(f'Failed to credit wallet: {credit_result.get("error")}')

                # -----------------------------------------------------------------
                # 2. AIRTIME TOP‑UP (manual / gateway)
                # -----------------------------------------------------------------
                elif tx_type == "topup":
                    # Payload must contain operator_id, phone, country_code
                    operator_id = payload.get("operator_id")
                    phone = payload.get("phone")
                    country_code = payload.get("country_code", "NG")
                    email = payload.get("email")
                    if not email and tx.get("user_id"):
                        try:
                            _u = db.get_user(tx["user_id"])
                            email = (_u or {}).get("email")
                        except Exception:
                            email = None

                    if not operator_id or not phone:
                        raise Exception("Missing operator_id or phone in transaction payload")

                    # Format phone number for Reloadly
                    formatted_phone = self.platform._format_phone_for_topup(phone, country_code)
                    if not formatted_phone:
                        raise Exception("Invalid phone number format")

                    # Convert amount to USD (Reloadly top‑ups are in USD).
                    # If the currency is already USD — which it now will be
                    # for any international destination, thanks to the
                    # currency/country validation in /api/payment/init —
                    # use it directly rather than round-tripping through
                    # convert_to_usd again. Domestic NG (NGN) still goes
                    # through the FX helper exactly as before.
                    amount = float(tx.get("amount", 0))  # what the customer paid (airtime + fee)
                    currency = tx.get("currency", "NGN")
                    # Deliver only the airtime part. Older transactions created before the split was
                    # stored have no service_amount and keep the previous behaviour (full amount).
                    try:
                        service_amount = float(payload.get("service_amount") or amount)
                    except (TypeError, ValueError):
                        service_amount = amount
                    if service_amount <= 0 or service_amount > amount + 1e-9:
                        service_amount = amount
                    # Nigerian airtime: ask the provider router first (VTpass / Flutterwave ...), in naira, no FX.
                    # Reloadly below stays the fallback, and is used ONLY when the router is certain nothing was accepted.
                    # Airtime policy: Reloadly first by default (the admin can flip it to VTpass, and Net365 moves to the other
                    # processor by itself when one looks down). The second processor is only tried when the first one has
                    # DEFINITELY not accepted the order, so a customer can never be served twice.
                    import net365_routing as _rt
                    _ng_naira = str(country_code).upper() == "NG" and currency == "NGN"
                    reloadly_first = _ng_naira and _rt.order("airtime")[0] == "reloadly"
                    routed = None

                    def _route_airtime_via_router():
                        _routed = None
                        try:
                            import net365_providers as _np
                            if _np.enabled():
                                _routed = _np.route_purchase(
                                    reference=reference, service="airtime",
                                    network=_np.network_for(payload.get("operator_name"), phone),
                                    phone=phone, amount=service_amount)
                                if _routed.get("status") in ("success", "pending"):
                                    logger.info(f"Airtime {reference} routed via {_routed.get('provider')} ({_routed.get('status')})")
                                    _rt.record("vtpass", "airtime", True, reference)
                                elif not _routed.get("fallback_ok"):
                                    raise Exception("Provider router could not confirm the order; not retrying elsewhere: "
                                                    + str(_routed.get("message") or ""))
                                else:
                                    _rt.record("vtpass", "airtime", False, reference)
                        except Exception as _re:
                            if "not retrying elsewhere" in str(_re):
                                raise
                            logger.exception(f"Provider router error for {reference}: {_re}")
                            _routed = None
                        return _routed

                    if _ng_naira and not reloadly_first:
                        routed = _route_airtime_via_router()
                    use_routed = bool(routed and routed.get("status") in ("success", "pending"))

                    if use_routed:
                        usd_amount = service_amount
                        topup_result = {"status": "SUCCESSFUL" if routed["status"] == "success" else "PENDING",
                                        "transactionId": routed.get("provider_ref") or f"{routed.get('provider')}-{reference}",
                                        "provider": routed.get("provider"), "routed": True}
                    else:
                        if currency == "USD":
                            usd_amount = service_amount
                        else:
                            usd_amount = self.platform.convert_to_usd(service_amount, currency)
                        if usd_amount <= 0:
                            raise Exception(f"Unable to convert {service_amount} {currency} to USD")

                        # Execute Reloadly top‑up
                        topup_result = self.platform.make_topup(
                            operator_id=str(operator_id),
                            amount=str(round(usd_amount, 2)),
                            recipient_phone={"countryCode": country_code, "number": formatted_phone},
                            use_local_amount=False,
                            custom_identifier=f"topup-{reference}",
                            recipient_email=email,
                            is_async=True,
                        )
                        if _ng_naira:
                            _rl_ok = topup_result.get("status") != "FAILED" and bool(topup_result.get("transactionId"))
                            _rt.record("reloadly", "airtime", _rl_ok, reference)
                            if not _rl_ok and reloadly_first:
                                # Reloadly definitely did not take it: use the standby processor.
                                routed = _route_airtime_via_router()
                                if routed and routed.get("status") in ("success", "pending"):
                                    use_routed = True
                                    usd_amount = service_amount
                                    topup_result = {"status": "SUCCESSFUL" if routed["status"] == "success" else "PENDING",
                                                    "transactionId": routed.get("provider_ref") or f"{routed.get('provider')}-{reference}",
                                                    "provider": routed.get("provider"), "routed": True}

                    # Check failure
                    if topup_result.get("status") == "FAILED" or not topup_result.get("transactionId"):
                        error_msg = topup_result.get("message") or topup_result.get("error") or "Top-up failed at provider"
                        raise Exception(error_msg)

                    # Build success result
                    result = {
                        "status": "success",
                        "transactionId": topup_result.get("transactionId"),
                        "amount": service_amount if use_routed else usd_amount,
                        "currency": currency if use_routed else "USD",
                        "original_amount": amount,
                        "service_amount": service_amount,
                        "fee_amount": round(amount - service_amount, 2),
                        "original_currency": currency,
                        "provider": topup_result.get("provider", "reloadly") if use_routed else "reloadly",
                        "full_result": topup_result,
                    }

                    # The airtime is already delivered at this point. Bookkeeping failures below must
                    # never turn a delivered top-up into "fulfillment_failed" (a retry could re-deliver).
                    try:
                        db.create_reloadly_transaction(
                            reference=reference,
                            user_id=user_id,
                            transaction_type="airtime",
                            amount=amount,
                            status="processing" if (use_routed and routed.get("status") == "pending") else "completed",
                            provider_transaction_id=topup_result.get("transactionId"),
                            result=topup_result,
                            currency=currency,
                        )
                    except Exception as e:
                        logger.critical(
                            f"Airtime DELIVERED for {reference} (provider id {topup_result.get('transactionId')}) "
                            f"but reloadly_transactions insert failed: {e}"
                        )

                    # Remember which operator this number was delivered on (a hint for next time; never blocks delivery)
                    try:
                        import net365_network_memory as _nm
                        _nm.record_success(tx.get("user_id"), phone, country_code, operator_id, payload.get("operator_name"))
                    except Exception as e:
                        logger.warning(f"Network memory not updated for {reference}: {e}")

                    # Notify user
                    if user_id:
                        try:
                            db.create_notification(
                                user_id,
                                "Airtime Recharge Successful ✅",
                                f"{currency} {service_amount:,.2f} recharge completed for {formatted_phone}.",
                                "success"
                            )
                        except Exception as e:
                            logger.warning(f"Success notification failed for {reference}: {e}")

                    user = db.get_user(user_id) if user_id else None
                    if user and user.get("email"):
                        try:
                            send_email_notification(
                                user["email"],
                                f"Net365 Airtime Recharge Receipt — {reference}",
                                f"Your airtime recharge was completed successfully.\n\nAirtime: {currency} {service_amount:,.2f}\nFee: {currency} {amount - service_amount:,.2f}\nTotal paid: {currency} {amount:,.2f}\nPhone: {formatted_phone}\nReference: {reference}",
                                include_promo=True,
                                promo_context={
                                    "user_id": user_id,
                                    "reference": reference,
                                    "tx_type": "airtime",
                                    "amount": amount,
                                },
                            )
                        except Exception as e:
                            logger.error(f"Failed to send recharge email: {e}")

                # -----------------------------------------------------------------
                # 2b. ELECTRICITY FROM THE BILLS HUB. The customer may have chosen VTpass or Reloadly; otherwise the router picks.
                #     A chosen provider is never silently swapped: if it cannot take the order the payment goes to the refund path.
                # -----------------------------------------------------------------
                elif tx_type == "electricity":
                    import net365_providers as _np
                    pref = str(payload.get("provider_pref") or "auto")
                    disco = str(payload.get("disco") or "")
                    meter = str(payload.get("subscriber_account") or "")
                    biller_id = payload.get("biller_id")
                    paid_amount = float(tx.get("amount", 0))
                    try:
                        local_amount = float(payload.get("service_amount") or paid_amount)
                    except (TypeError, ValueError):
                        local_amount = paid_amount
                    if tx.get("currency", "NGN") != "NGN" or local_amount <= 0 or not meter:
                        raise Exception("Electricity order is incomplete")
                    # Provider order comes from Net365's routing policy (VTpass first by default, Reloadly on standby; the admin
                    # can override and Net365 senses an unhealthy provider). Customers never choose or see the provider.
                    # An old in-flight order that still carries an explicit choice keeps it (never silently swapped).
                    import net365_routing as _rt
                    order_e = [pref] if pref in ("vtpass", "reloadly") else _rt.order("electricity")
                    e_result, last_err = None, ""
                    for prov_e in order_e:
                        if prov_e == "vtpass":
                            if not (disco and _np.enabled()):
                                continue
                            routed_e = _np.route_purchase(
                                reference=reference, service="electricity", disco=disco, account=meter,
                                phone=str(payload.get("phone") or ""), amount=local_amount,
                                meter_type=str(payload.get("meter_type") or "prepaid"), only="vtpass")
                            if routed_e.get("status") in ("success", "pending"):
                                _rt.record("vtpass", "electricity", True, reference)
                                e_result = {"status": "SUCCESSFUL" if routed_e["status"] == "success" else "PENDING",
                                            "transactionId": routed_e.get("provider_ref") or f"{routed_e.get('provider')}-{reference}",
                                            "provider": routed_e.get("provider"), "token": routed_e.get("token") or ""}
                                break
                            if not routed_e.get("fallback_ok"):
                                raise Exception("Provider router could not confirm the order; not retrying elsewhere: " + str(routed_e.get("message") or ""))
                            _rt.record("vtpass", "electricity", False, reference)
                            last_err = str(routed_e.get("message") or "Electricity payment failed")
                        elif prov_e == "reloadly":
                            if not biller_id:
                                continue
                            try:
                                r_res = self.platform.pay_utility_bill(biller_id=int(biller_id), subscriber_account=meter, amount=local_amount,
                                                                       reference_id=f"util-{reference}"[:36], use_local_amount=True)
                            except Exception as rl_e:
                                # pay_utility_bill already cross-checks Reloadly's own records before raising, so this is a real failure.
                                _rt.record("reloadly", "electricity", False, reference)
                                last_err = str(rl_e) or "Electricity payment failed"
                                logger.warning(f"electricity {reference}: Reloadly failed ({last_err}); trying next provider if any")
                                continue
                            r_res = r_res if isinstance(r_res, dict) else {}
                            if (r_res.get("transactionId") or r_res.get("id")) and str(r_res.get("status", "")).upper() not in ("FAILED", "ERROR"):
                                _rt.record("reloadly", "electricity", True, reference)
                                r_res["provider"] = "reloadly"
                                e_result = r_res
                                break
                            _rt.record("reloadly", "electricity", False, reference)
                            last_err = str(r_res.get("message") or r_res.get("error") or "Electricity payment failed")
                    if not e_result:
                        raise Exception(last_err or "No provider could take this electricity order")
                    e_txid = e_result.get("transactionId") or e_result.get("id")
                    if not e_txid or str(e_result.get("status", "")).upper() in ("FAILED", "ERROR"):
                        raise Exception(e_result.get("message") or e_result.get("error") or "Electricity payment failed")
                    e_token = str(e_result.get("token") or "")
                    result = {"status": "success", "transactionId": e_txid, "amount": local_amount, "currency": "NGN",
                              "provider": e_result.get("provider"), "token": e_token, "full_result": e_result}
                    try:
                        db.create_reloadly_transaction(reference=reference, user_id=user_id, transaction_type="utility", amount=local_amount,
                                                       status="processing" if str(e_result.get("status")).upper() == "PENDING" else "completed",
                                                       provider_transaction_id=e_txid, result=e_result, currency="NGN")
                    except Exception as e:
                        logger.critical(f"electricity DELIVERED for {reference} but reloadly_transactions insert failed: {e}")
                    if user_id:
                        try:
                            db.create_notification(user_id, "Electricity Payment Successful ✅",
                                                   f"₦{local_amount:,.2f} for meter {meter[-4:].rjust(len(meter), '*')}." + (f" Token: {e_token}" if e_token else ""), "success")
                        except Exception as e:
                            logger.warning(f"electricity notification failed for {reference}: {e}")
                        send_service_receipt(
                            user_id, payload, f"✅ Electricity Payment Receipt — {reference}",
                            f"Your electricity payment was successful.\n\nCompany: {payload.get('biller_name') or disco}\n"
                            f"Meter: {meter}\n"
                            + (f"Customer: {payload.get('customer_name')}\n" if payload.get("customer_name") else "")
                            + f"Amount: ₦{local_amount:,.2f}\n"
                            + (f"Token: {e_token}\n" if e_token else "Your token will follow shortly.\n") + f"Reference: {reference}",
                            "electricity", reference, paid_amount)

                # -----------------------------------------------------------------
                # 2c. INSURANCE (motor third-party). Premium comes from the provider catalogue and is re-checked here.
                #     The policy details travel encrypted in the payload; the certificate link is the delivery.
                # -----------------------------------------------------------------
                elif tx_type == "insurance":
                    import net365_providers as _np
                    product = str(payload.get("product") or "").lower()
                    plan_code = str(payload.get("variation_code") or "")
                    plan = _np.find_service_plan(product, plan_code) if (_np.enabled() and product and plan_code) else None
                    if not plan:
                        raise Exception("This cover is not available right now")
                    paid_amount = float(tx.get("amount", 0))
                    try:
                        service_amount = float(payload.get("service_amount") or paid_amount)
                    except (TypeError, ValueError):
                        service_amount = paid_amount
                    if tx.get("currency", "NGN") != "NGN" or abs(service_amount - plan["price"]) > 0.01 or plan["price"] <= 0:
                        raise Exception(f"Cover price mismatch (expected {plan['price']}, order {service_amount})")
                    try:
                        ins_details = json.loads(str(payload.get("subscriber_account") or "{}"))
                    except ValueError:
                        raise Exception("Policy details could not be read")
                    routed_i = _np.route_purchase(reference=reference, service="insurance", network=product, phone=str(payload.get("phone") or ""),
                                                  amount=plan["price"], variation_code=plan_code, extra=ins_details)
                    if routed_i.get("status") not in ("success", "pending"):
                        raise Exception(routed_i.get("message") or "Policy could not be issued")
                    pending_i = routed_i["status"] == "pending"
                    cert = str(routed_i.get("token") or "")
                    result = {"status": "success", "transactionId": routed_i.get("provider_ref") or f"{routed_i.get('provider')}-{reference}",
                              "amount": plan["price"], "currency": "NGN", "provider": routed_i.get("provider"), "plan": plan["name"],
                              "token": cert, "full_result": {k: v for k, v in routed_i.items() if k != "raw"}}
                    try:
                        db.create_reloadly_transaction(reference=reference, user_id=user_id, transaction_type="insurance", amount=paid_amount,
                                                       status="processing" if pending_i else "completed",
                                                       provider_transaction_id=result["transactionId"], result=result["full_result"], currency="NGN")
                    except Exception as e:
                        logger.critical(f"insurance ISSUED for {reference} but reloadly_transactions insert failed: {e}")
                    if user_id:
                        try:
                            db.create_notification(user_id, "Insurance Policy Issued ✅" if not pending_i else "Insurance Order Received ⏳",
                                                   (f"Your certificate: {cert}" if cert else "Your certificate will be sent to you shortly."), "success")
                        except Exception as e:
                            logger.warning(f"insurance notification failed for {reference}: {e}")
                        u_i = db.get_user(user_id) or {}
                        em_i = (payload.get("email") or u_i.get("email"))
                        if em_i:
                            try:
                                send_email_notification(
                                    em_i, f"Your Net365 insurance — {reference}",
                                    f"Thank you. Your {payload.get('biller_name') or 'motor insurance'} order was received.\n\nVehicle plate: {ins_details.get('Plate_Number', '')}\n"
                                    f"Premium: ₦{plan['price']:,.2f}\n" + (f"Certificate: {cert}\n" if cert else "Your certificate will follow by email once the insurer issues it.\n") + f"Reference: {reference}\n\n"
                                    "Keep this email. If anything looks wrong, reply or contact support@net365co.com quoting the reference.",
                                    include_promo=True,
                                    promo_context={"user_id": user_id, "reference": reference, "tx_type": "insurance", "amount": paid_amount})
                            except Exception as e:
                                logger.warning(f"insurance receipt email failed for {reference}: {e}")

                # -----------------------------------------------------------------
                # 3. UTILITY PAYMENT (manual / gateway)
                # -----------------------------------------------------------------
                elif tx_type == "utility":
                    biller_id = payload.get("biller_id")
                    subscriber_account = payload.get("subscriber_account")
                    if not biller_id or not subscriber_account:
                        raise Exception("Missing biller_id or subscriber_account in transaction payload")

                    # Amount is in local currency (NGN, etc.)
                    amount = float(tx.get("amount", 0))
                    currency = tx.get("currency", "NGN")

                    # Use the amount as is (Reloadly utility expects local amount). When a chat
                    # service fee was added, the biller only receives the bill amount.
                    local_amount = float(payload.get("service_amount") or amount)

                    # Nigerian electricity: provider router first, Reloadly only if the router is certain nothing was accepted.
                    routed_u = None
                    if currency == "NGN":
                        try:
                            import net365_providers as _np
                            _disco = _np.disco_for(payload.get("biller_name"))
                            if _np.enabled() and _disco:
                                routed_u = _np.route_purchase(
                                    reference=reference, service="electricity", disco=_disco,
                                    account=str(subscriber_account), phone=str(payload.get("phone") or ""),
                                    amount=local_amount, meter_type=str(payload.get("meter_type") or "prepaid"))
                                if routed_u.get("status") not in ("success", "pending") and not routed_u.get("fallback_ok"):
                                    raise Exception("Provider router could not confirm the order; not retrying elsewhere: "
                                                    + str(routed_u.get("message") or ""))
                        except Exception as _ue:
                            if "not retrying elsewhere" in str(_ue):
                                raise
                            logger.exception(f"Provider router error for {reference}: {_ue}")
                            routed_u = None

                    if routed_u and routed_u.get("status") in ("success", "pending"):
                        utility_result = {"status": "SUCCESSFUL" if routed_u["status"] == "success" else "PENDING",
                                          "transactionId": routed_u.get("provider_ref") or f"{routed_u.get('provider')}-{reference}",
                                          "provider": routed_u.get("provider"), "routed": True}
                        if routed_u.get("token"):
                            utility_result["token"] = routed_u["token"]
                    else:
                        # Execute Reloadly utility payment
                        unique_ref = f"util-{reference}"[:36]  # Reloadly max 36 chars
                        utility_result = self.platform.pay_utility_bill(
                            biller_id=int(biller_id),
                            subscriber_account=subscriber_account,
                            amount=local_amount,
                            reference_id=unique_ref,
                            use_local_amount=True,
                        )

                    # Check success
                    transaction_id = utility_result.get("transactionId") or utility_result.get("id")
                    status = str(utility_result.get("status", "")).upper()
                    if not transaction_id or status in ("FAILED", "ERROR"):
                        error_msg = utility_result.get("message") or utility_result.get("error") or "Utility payment failed"
                        raise Exception(error_msg)

                    # Build result
                    result = {
                        "status": "success",
                        "transactionId": transaction_id,
                        "amount": local_amount,
                        "currency": currency,
                        "provider": utility_result.get("provider", "reloadly"),
                        "full_result": utility_result,
                    }

                    # Log in reloadly_transactions
                    db.create_reloadly_transaction(
                        reference=reference,
                        user_id=user_id,
                        transaction_type="utility",
                        amount=local_amount,
                        status="processing" if utility_result.get("status") == "PENDING" else "completed",
                        provider_transaction_id=transaction_id,
                        result=utility_result,
                        currency=currency,
                    )

                    # Notify user
                    db.create_notification(
                        user_id,
                        "Utility Payment Successful ✅",
                        f"{currency} {local_amount:,.2f} paid for {subscriber_account}",
                        "success"
                    )

                    user = db.get_user(user_id) if user_id else None
                    if user and user.get("email"):
                        try:
                            send_email_notification(
                                user["email"],
                                f"✅ Utility Payment Receipt — {reference}",
                                f"Your utility payment was completed successfully.\n\nAccount: {subscriber_account}\nAmount: {currency} {local_amount:,.2f}\nReference: {reference}",
                                include_promo=True,
                                promo_context={
                                    "user_id": user_id,
                                    "reference": reference,
                                    "tx_type": "utility",
                                    "amount": local_amount,
                                },
                            )
                        except Exception as e:
                            logger.error(f"Failed to send utility email: {e}")

                # -----------------------------------------------------------------
                # 3a. DATA BUNDLE (Nigeria, via the provider router). The price is taken from the provider's own plan
                #     list, never from the request, so an edited request cannot buy a dearer plan for a cheaper price.
                # -----------------------------------------------------------------
                elif tx_type == "data":
                    import net365_providers as _np
                    network = str(payload.get("network") or "").lower()
                    plan_code = str(payload.get("variation_code") or "")
                    data_phone = str(payload.get("phone") or "")
                    plan = _np.find_plan(network, plan_code) if (_np.enabled() and network and plan_code) else None
                    if not plan:
                        raise Exception("Data plan not available right now")
                    paid_amount = float(tx.get("amount", 0))
                    currency = tx.get("currency", "NGN")
                    try:
                        service_amount = float(payload.get("service_amount") or paid_amount)
                    except (TypeError, ValueError):
                        service_amount = paid_amount
                    if currency != "NGN" or abs(service_amount - plan["price"]) > 0.01:
                        raise Exception(f"Data plan price mismatch (plan {plan['price']}, order {service_amount})")
                    routed_d = _np.route_purchase(reference=reference, service="data", network=network, phone=data_phone,
                                                  amount=plan["price"], variation_code=plan_code)
                    if routed_d.get("status") not in ("success", "pending"):
                        raise Exception(routed_d.get("message") or "Data purchase failed at provider")
                    pending_d = routed_d["status"] == "pending"
                    result = {"status": "success", "transactionId": routed_d.get("provider_ref") or f"{routed_d.get('provider')}-{reference}",
                              "amount": plan["price"], "currency": "NGN", "provider": routed_d.get("provider"),
                              "plan": plan["name"], "full_result": routed_d}
                    try:
                        db.create_reloadly_transaction(
                            reference=reference, user_id=user_id, transaction_type="data", amount=paid_amount,
                            status="processing" if pending_d else "completed",
                            provider_transaction_id=result["transactionId"], result=routed_d, currency="NGN")
                    except Exception as e:
                        logger.critical(f"Data DELIVERED for {reference} but reloadly_transactions insert failed: {e}")
                    if user_id:
                        try:
                            db.create_notification(user_id, "Data Purchase Successful ✅",
                                                   f"{plan['name']} sent to {data_phone}.", "success")
                        except Exception as e:
                            logger.warning(f"Data notification failed for {reference}: {e}")
                        send_service_receipt(
                            user_id, payload, f"✅ Data Purchase Receipt — {reference}",
                            f"Your data purchase was successful.\n\nPlan: {plan['name']}\nNumber: {data_phone}\n"
                            f"Amount: ₦{service_amount:,.2f}\n" + ("Status: processing, it will reflect shortly.\n" if pending_d else "")
                            + f"Reference: {reference}",
                            "data", reference, paid_amount)

                # -----------------------------------------------------------------
                # 3a-2. TV SUBSCRIPTION / EDUCATION PIN (via the provider router). Price comes from the provider catalogue.
                #       JAMB is sold at exactly the official price (service fee 0), enforced at checkout and re-checked here.
                # -----------------------------------------------------------------
                elif tx_type in ("tv", "education"):
                    import net365_providers as _np
                    product = str(payload.get("product") or "").lower()
                    plan_code = str(payload.get("variation_code") or "")
                    quantity = max(1, min(int(payload.get("quantity") or 1), 5))
                    sub_type = str(payload.get("subscription_type") or "")
                    plan = _np.find_service_plan(product, plan_code) if (_np.enabled() and product and plan_code) else None
                    if not plan:
                        raise Exception("This plan is not available right now")
                    paid_amount = float(tx.get("amount", 0))
                    try:
                        service_amount = float(payload.get("service_amount") or paid_amount)
                    except (TypeError, ValueError):
                        service_amount = paid_amount
                    # renewal of a DStv/GOtv decoder may carry a provider "promo" price that differs from the catalogue
                    expected = float(payload.get("renewal_amount") or 0) if sub_type == "renew" else plan["price"] * quantity
                    if tx.get("currency", "NGN") != "NGN" or abs(service_amount - expected) > 0.01 or expected <= 0:
                        raise Exception(f"Plan price mismatch (expected {expected}, order {service_amount})")
                    routed_t = _np.route_purchase(reference=reference, service=tx_type, network=product,
                                                  phone=str(payload.get("phone") or ""), amount=expected,
                                                  account=str(payload.get("subscriber_account") or ""),
                                                  variation_code=plan_code, quantity=quantity, subscription_type=sub_type)
                    if routed_t.get("status") not in ("success", "pending"):
                        raise Exception(routed_t.get("message") or "Purchase failed at provider")
                    pending_t = routed_t["status"] == "pending"
                    result = {"status": "success", "transactionId": routed_t.get("provider_ref") or f"{routed_t.get('provider')}-{reference}",
                              "amount": expected, "currency": "NGN", "provider": routed_t.get("provider"),
                              "plan": plan["name"], "token": routed_t.get("token") or "", "full_result": routed_t}
                    try:
                        db.create_reloadly_transaction(
                            reference=reference, user_id=user_id, transaction_type=tx_type, amount=paid_amount,
                            status="processing" if pending_t else "completed",
                            provider_transaction_id=result["transactionId"], result=routed_t, currency="NGN")
                    except Exception as e:
                        logger.critical(f"{tx_type} DELIVERED for {reference} but reloadly_transactions insert failed: {e}")
                    if user_id:
                        try:
                            db.create_notification(user_id, "Purchase Successful ✅", f"{plan['name']} ({payload.get('biller_name') or product}).", "success")
                        except Exception as e:
                            logger.warning(f"{tx_type} notification failed for {reference}: {e}")
                        _tv_token = str(routed_t.get("token") or "")
                        _tv_label = "Cable TV Subscription" if tx_type == "tv" else "Education PIN"
                        send_service_receipt(
                            user_id, payload, f"✅ {_tv_label} Receipt — {reference}",
                            f"Your {_tv_label.lower()} purchase was successful.\n\n{payload.get('biller_name') or product}\n"
                            + (f"Plan: {plan['name']}\n" if plan.get("name") else "")
                            + (f"Smartcard / account: {payload.get('subscriber_account')}\n" if tx_type == "tv" and payload.get("subscriber_account") else "")
                            + (f"Customer: {payload.get('customer_name')}\n" if payload.get("customer_name") else "")
                            + f"Amount: ₦{expected:,.2f}\n"
                            + (f"PIN / token: {_tv_token}\n" if _tv_token else "")
                            + ("Status: processing, it will reflect shortly.\n" if pending_t else "") + f"Reference: {reference}",
                            tx_type, reference, paid_amount)

                # -----------------------------------------------------------------
                # 3b. GIFT CARD (gateway-paid). Codes are fetched at delivery, never stored.
                # -----------------------------------------------------------------
                elif tx_type == "giftcard":
                    from net365_giftcards import fulfil_giftcard
                    result = fulfil_giftcard(reference, payload, tx)

                # -----------------------------------------------------------------
                # 3c. BUSINESS PAYMENT (user-to-business). Paystack already settles the merchant
                #     directly through the split; nothing for Net365 to deliver or hold.
                # -----------------------------------------------------------------
                elif tx_type == "merchant":
                    from net365_merchants import fulfil_merchant
                    result = fulfil_merchant(reference, payload, tx)

                # -----------------------------------------------------------------
                # 4. BULK RECHARGE (gateway-paid)
                # -----------------------------------------------------------------
                elif tx_type == "bulk_recharge":
                    job_id = payload.get("job_id")
                    if not job_id:
                        raise Exception("Missing job_id in bulk_recharge transaction payload")

                    job_conn = db.get_db_connection()
                    job_cur = job_conn.cursor()
                    try:
                        job_row = job_cur.execute(
                            "SELECT status FROM bulk_jobs WHERE id = ?", (job_id,)
                        ).fetchone()
                        job_status = job_row["status"] if job_row else None

                        if job_status == "pending_payment":
                            record_rows = job_cur.execute(
                                "SELECT phone, amount, operator_id, country_code, name, network "
                                "FROM bulk_job_records WHERE job_id = ?",
                                (job_id,),
                            ).fetchall()
                            records = [dict(r) for r in record_rows]

                            job_cur.execute(
                                "UPDATE bulk_jobs SET status = 'pending', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                                (job_id,),
                            )
                            try:
                                job_cur.execute(
                                    "UPDATE bulk_job_payments SET status = 'paid', reconciled_at = CURRENT_TIMESTAMP WHERE job_id = ?",
                                    (job_id,),
                                )
                            except Exception as _e:
                                logger.warning(f"bulk_job_payments status update skipped: {_e}")
                            job_conn.commit()

                            if records:
                                threading.Thread(
                                    target=self._process_bulk_job,
                                    args=(job_id, user_id, records),
                                    daemon=True,
                                ).start()
                            else:
                                job_cur.execute(
                                    "UPDATE bulk_jobs SET status = 'failed', error = ? WHERE id = ?",
                                    ("No records found for this job", job_id),
                                )
                                job_conn.commit()
                    finally:
                        job_conn.close()

                    result = {
                        "status": "success",
                        "job_id": job_id,
                        "message": f"Payment confirmed — bulk recharge job {job_id} started",
                    }

                    db.create_notification(
                        user_id,
                        "💳 Bulk Recharge Payment Confirmed",
                        f"Payment received — your bulk recharge job is now processing.",
                        "success"
                    )

                # -----------------------------------------------------------------
                # 5. CART (OnePay): one verified gateway payment funds several deliveries.
                #    Children are created ONLY here, after the parent payment is verified.
                # -----------------------------------------------------------------
                elif tx_type == "cart":
                    items = payload.get("items") or []
                    if not items:
                        raise Exception("Cart has no items")
                    if abs(sum(float(i.get("amount") or 0) for i in items) - float(tx.get("amount") or 0)) > 0.02:
                        raise Exception("Cart items do not add up to the amount paid")
                    child_refs = []
                    for idx, it in enumerate(items, 1):
                        child_ref = f"{reference}-{idx}"
                        if not db.get_transaction(child_ref):  # idempotent on re-run
                            db.create_pending(
                                reference=child_ref,
                                tx_type=it["type"],
                                provider="cart",
                                amount=float(it["amount"]),
                                currency="NGN",
                                payload=dict(it["payload"], parent_reference=reference),
                                user_id=user_id,
                            )
                        child_refs.append(child_ref)
                    threading.Thread(
                        target=self._run_cart_children,
                        args=(reference, user_id, child_refs),
                        daemon=True,
                    ).start()
                    result = {
                        "status": "success",
                        "children": child_refs,
                        "message": f"Payment confirmed: {len(child_refs)} deliveries started",
                    }

                else:
                    raise ValueError(f"Unknown transaction type: {tx_type}")

                # Mark the transaction as fulfilled in the main transactions table
                db.mark_fulfilled(reference, result)
                logger.info(f"Fulfilled {tx_type} for reference {reference}")
                if tx_type == "merchant":
                    try:
                        from net365_merchants import notify_merchant_paid
                        threading.Thread(target=notify_merchant_paid, args=(reference,), daemon=True).start()
                    except Exception:
                        pass
                if tx_type in ("topup", "utility", "giftcard", "merchant", "data", "tv", "education", "electricity", "insurance"):
                    try:
                        from net365_whatsapp import notify_after_fulfillment
                        threading.Thread(target=notify_after_fulfillment, args=(reference,), daemon=True).start()
                    except Exception as _ne:
                        logger.warning(f"chat notify not started: {_ne}")

                return {
                    "success": True,
                    "result": result,
                    "already_fulfilled": False,
                }

            except Exception as e:
                logger.error(f"FULFILLMENT FAILED: {e}")
                import traceback
                logger.error(traceback.format_exc())
                try:
                    db.mark_fulfillment_failed(reference, str(e))
                except:
                    pass
                if tx_type == "topup":
                    # A wrong-operator/invalid-number failure must not stay remembered as "the right network"
                    try:
                        import net365_network_memory as _nm
                        _nm.record_failure(tx.get("user_id"), locals().get("phone"), locals().get("country_code", "NG"),
                                           locals().get("operator_id"), str(e))
                    except Exception:
                        pass
                if tx_type == "utility":
                    _utility_trip(str(e))
                try:
                    if tx_type in ("topup", "utility", "giftcard", "data", "tv", "education", "electricity", "insurance"):
                        from net365_whatsapp import notify_delay
                        threading.Thread(target=notify_delay, args=(reference,), daemon=True).start()
                except Exception:
                    pass
                return {"success": False, "error": str(e)}
                
                
    # ------------------------------------------------------------------
    # CART (OnePay) helpers
    # ------------------------------------------------------------------
    _CART_TRANSIENT = ("server error", "balance", "timed out", "timeout", " 502", " 503", " 504",
                       "service unavailable", "temporarily", "connection")

    def _verify_cart_child(self, tx, payload):
        """A cart child has no gateway reference of its own. It is payable only if its parent cart
        payment was verified and fulfilled (children are only ever created after that)."""
        parent_ref = (payload or {}).get("parent_reference")
        parent = db.get_transaction(parent_ref) if parent_ref else None
        if not parent or parent.get("tx_type") != "cart" or parent.get("status") != "fulfilled":
            return {"success": False, "error": "Parent cart payment is not confirmed"}
        return {"success": True, "amount": float(tx.get("amount") or 0),
                "currency": tx.get("currency") or "NGN"}

    def _record_cart_refund_due(self, parent_ref, child_ref, user_id, amount, note):
        """Gateway-paid cart item that could not be delivered: wallets are off, so record a refund
        owed through the payment gateway (same approach as bulk_refunds_due)."""
        try:
            c = db.get_db_connection()
            try:
                c.execute("""CREATE TABLE IF NOT EXISTS cart_refunds_due (
                    reference TEXT PRIMARY KEY, parent_reference TEXT, user_id INTEGER, amount REAL,
                    currency TEXT DEFAULT 'NGN', status TEXT DEFAULT 'due', note TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
                c.execute("INSERT OR IGNORE INTO cart_refunds_due (reference, parent_reference, user_id, amount, note) "
                          "VALUES (?,?,?,?,?)", (child_ref, parent_ref, user_id, amount, str(note or "")[:300]))
                c.commit()
            finally:
                c.close()
            logger.critical(f"CART REFUND DUE: {child_ref} NGN {amount} user {user_id} - refund through the gateway "
                            f"(table cart_refunds_due)")
            return True
        except Exception as e:
            logger.critical(f"Could not record cart refund due for {child_ref}: {e}")
            return False

    def _run_cart_children(self, parent_ref, user_id, child_refs):
        """Background worker: deliver each cart item independently, retry transient provider errors,
        refund-record what cannot be delivered, then send ONE summary to the customer."""
        for _ in range(120):  # the parent is marked fulfilled just after this thread starts
            p = db.get_transaction(parent_ref)
            if p and p.get("status") == "fulfilled":
                break
            time.sleep(0.5)

        outcomes = []
        for ref in child_refs:
            res = {"success": False, "error": "not run"}
            for attempt in range(3):
                try:
                    res = self._finalize_transaction(ref) or {}
                except Exception as e:
                    logger.exception(f"cart child {ref} crashed")
                    res = {"success": False, "error": str(e)}
                if res.get("success"):
                    break
                err = str(res.get("error") or "").lower()
                if attempt < 2 and any(h in err for h in self._CART_TRANSIENT):
                    time.sleep(15 * (attempt + 1))
                    try:  # fulfillment_failed -> pending so the lock can be taken again (provider id is deterministic)
                        c = db.get_db_connection()
                        c.execute("UPDATE transactions SET status='pending' WHERE reference=? "
                                  "AND status='fulfillment_failed'", (ref,))
                        c.commit()
                        c.close()
                    except Exception:
                        pass
                    continue
                break
            child = db.get_transaction(ref) or {}
            ok = bool(res.get("success")) or child.get("status") == "fulfilled"
            if not ok:
                self._record_cart_refund_due(parent_ref, ref, user_id, float(child.get("amount") or 0),
                                             res.get("error"))
            outcomes.append((ref, float(child.get("amount") or 0), ok))

        done = sum(1 for _, _, ok in outcomes if ok)
        failed = [(r, a) for r, a, ok in outcomes if not ok]
        try:
            title = "OnePay: all items delivered" if not failed else (
                "OnePay: some items need attention" if done else "OnePay: items could not be delivered")
            body = f"{done} of {len(outcomes)} items delivered."
            if failed:
                body += (f" NGN {sum(a for _, a in failed):,.2f} for the rest will be refunded to your "
                         f"original payment method.")
            db.create_notification(user_id, title, body, "success" if not failed else "warning")
            user = db.get_user(user_id) if user_id else None
            if user and user.get("email"):
                send_email_notification(user["email"], f"Net365 OnePay summary - {parent_ref}",
                                        f"{body}\n\nOrder reference: {parent_ref}")
        except Exception as e:
            logger.warning(f"cart summary notification failed for {parent_ref}: {e}")

    def _start_pending_sweeper(self):
        _SWEEP_ATTEMPTS = {}
        """Chat-bot payments are often completed on a phone, where the gateway's browser redirect to
        this server (or its webhook) cannot reach a local/dev machine. Every minute, re-verify recent
        pending chat purchases with the gateway and fulfil the ones that were actually paid.
        _finalize_transaction is idempotent and leaves unpaid ones pending."""
        if os.getenv("PENDING_SWEEPER_ENABLED", "true").strip().lower() not in ("1", "true", "yes", "on"):
            return

        def loop():
            import time as _t
            _t.sleep(20)
            while True:
                try:
                    conn = db.get_db_connection()
                    rows = conn.execute(
                        "SELECT reference FROM transactions WHERE status = 'pending' "
                        "AND tx_type = 'topup' AND payload LIKE '%\"source\"%' "
                        "AND created_at >= datetime('now','-3 hours') "
                        "AND created_at <= datetime('now','-40 seconds') "
                        "ORDER BY created_at DESC LIMIT 15"
                    ).fetchall()
                    # Paid but not delivered because the provider (Reloadly) had a hiccup: put the
                    # transaction back to 'pending' and try again, up to 20 times. A paid customer must never
                    # be left stranded by a transient 5xx / balance / timeout error.
                    stuck = conn.execute(
                        "SELECT reference FROM transactions WHERE status = 'fulfillment_failed' "
                        "AND (tx_type IN ('utility','giftcard') OR (tx_type = 'topup' AND provider = 'cart')) "
                        "AND created_at >= datetime('now','-6 hours') "
                        "AND (fulfillment_error LIKE '%Server Error%' OR fulfillment_error LIKE '%balance%' "
                        "OR fulfillment_error LIKE '%timed out%' OR fulfillment_error LIKE '%timeout%' "
                        "OR fulfillment_error LIKE '% 502%' OR fulfillment_error LIKE '% 503%' "
                        "OR fulfillment_error LIKE '% 504%') "
                        "ORDER BY created_at DESC LIMIT 10"
                    ).fetchall()
                    retry_refs = []
                    for r in stuck:
                        if _utility_provider_down():
                            break
                        n = _SWEEP_ATTEMPTS.get(r[0], 0)
                        if n >= 20:
                            if n == 20:
                                logger.critical(f"PAID BUT UNDELIVERED after 20 retries: {r[0]} - refund or deliver manually")
                                _SWEEP_ATTEMPTS[r[0]] = 21
                            continue
                        _SWEEP_ATTEMPTS[r[0]] = n + 1
                        conn.execute("UPDATE transactions SET status='pending' WHERE reference=? "
                                     "AND status='fulfillment_failed'", (r[0],))
                        retry_refs.append((r[0],))
                    try:    # recovery engine: paid-but-failed electricity/data/TV/education/insurance orders (admin-controlled)
                        import net365_recovery as _rc
                        for _rref in _rc.sweep():
                            conn.execute("UPDATE transactions SET status='pending' WHERE reference=? "
                                         "AND status='fulfillment_failed'", (_rref,))
                            retry_refs.append((_rref,))
                    except ImportError:
                        pass
                    except Exception as _rce:
                        logger.warning(f"Recovery sweep error: {_rce}")
                    if retry_refs:
                        conn.commit()
                    rows = list(rows) + retry_refs
                    for r in rows:
                        ref = r[0]
                        try:
                            res = self._finalize_transaction(ref)
                            if res.get("success") and not res.get("already_fulfilled"):
                                logger.info(f"Sweeper fulfilled chat purchase {ref}")
                        except Exception as e:
                            logger.warning(f"Sweeper could not finalize {ref}: {e}")
                except Exception as e:
                    logger.warning(f"Pending sweeper error: {e}")
                _t.sleep(60)

        threading.Thread(target=loop, daemon=True, name="pending-sweeper").start()
        logger.info("Pending-payment sweeper started (chat purchases, every 60s)")

    def _refund_bulk_record(self, job_id, user_id, amount, currency, reference, paid_by_wallet, extra=None):
        """Refund one failed bulk record to wherever the money came from.
        Wallet-paid job -> back to the wallet. Gateway-paid job -> the customer paid by card, so the
        wallet was never debited: crediting it would hand out unfunded wallet money. Record a refund
        owed (shown in admin / logs) so it is returned through the gateway."""
        if paid_by_wallet:
            try:
                res = db.credit_wallet(
                    user_id=user_id, amount=amount, currency=currency,
                    description=f"Refund for failed bulk recharge {reference}",
                    reference=f"REFUND-{reference}",
                    metadata=dict({"original_reference": reference}, **(extra or {})),
                )
                if res and res.get("success"):
                    return res
                err = (res or {}).get("error") or "credit failed"
            except Exception as e:
                err = str(e)
            # The wallet was debited but could not be refunded: never lose track of it. Record the
            # debt so it appears in bulk_refunds_due, and shout in the log.
            logger.critical(f"BULK WALLET REFUND FAILED {reference} {currency} {amount} user {user_id}: {err}")
            extra = dict(extra or {}, error=f"wallet refund failed: {err}")
        try:
            _c = db.get_db_connection()
            try:
                _c.execute("""CREATE TABLE IF NOT EXISTS bulk_refunds_due (
                    reference TEXT PRIMARY KEY, job_id TEXT, user_id INTEGER, amount REAL,
                    currency TEXT, status TEXT DEFAULT 'due', note TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
                _c.execute(
                    "INSERT OR IGNORE INTO bulk_refunds_due (reference, job_id, user_id, amount, currency, note) VALUES (?,?,?,?,?,?)",
                    (reference, job_id, user_id, amount, currency, str((extra or {}).get("error") or "provider rejected")[:300]),
                )
            finally:
                _c.close()
            logger.critical(
                f"BULK REFUND DUE (gateway-paid): job {job_id} record {reference} {currency} {amount} "
                f"user {user_id} — refund through the payment gateway (table bulk_refunds_due)"
            )
        except Exception as e:
            logger.critical(f"Could not record bulk refund due for {reference}: {e}")
            return {"success": False, "error": str(e)}
        try:
            db.create_notification(
                user_id, "Bulk recharge: refund pending",
                f"One recharge in your bulk job could not be delivered. {currency} {amount:,.2f} will be refunded to your original payment method.",
                "warning",
            )
        except Exception as e:
            logger.warning(f"Refund-due notification failed for {reference}: {e}")
        return {"success": True, "gateway_refund_due": True}

    def _process_bulk_job(self, job_id: str, user_id: int, records: List[Dict]):
        """Background worker that fulfills each record in a bulk recharge job."""
        conn = db.get_db_connection()
        c = conn.cursor()
        try:
            _pm = c.execute("SELECT payment_method FROM bulk_jobs WHERE id = ?", (job_id,)).fetchone()
            # Only a job explicitly tagged "wallet" refunds to the wallet; untagged/unknown never does.
            paid_by_wallet = str((_pm["payment_method"] if _pm else None) or "").strip().lower() == "wallet"
        except Exception:
            # Unknown: never default to the wallet (that would credit unfunded money to a card-paid job)
            logger.warning(f"Bulk job {job_id}: could not read payment_method; defaulting to gateway refund")
            paid_by_wallet = False

        processed = 0
        successful = 0
        failed = 0

        try:
            for rec in records:
                try:
                    phone = rec["phone"]
                    amount = rec["amount"]
                    operator_id = rec["operator_id"]
                    country_code = rec["country_code"]

                    if not operator_id:
                        # Ask Reloadly's auto-detect — this is the authoritative source.
                        auto_detect_ok = False
                        try:
                            detect = self.platform.auto_detect_operator(phone, country_code)
                            if detect.get("success") and detect.get("operator"):
                                operator_id = detect["operator"].get("operatorId") or detect["operator"].get("id")
                                auto_detect_ok = bool(operator_id)
                                if operator_id:
                                    logger.info(
                                        f"Bulk: Reloadly auto-detect resolved {phone} → "
                                        f"operator {operator_id} ({detect['operator'].get('name', 'unknown')})"
                                    )
                        except Exception as e:
                            logger.warning(f"Bulk: auto-detect request failed for {phone}: {e}")

                    # In sandbox, Reloadly only accepts its own test numbers
                    # (e.g. 2348012345678 → operator 341). Real numbers and
                    # production operator IDs (49/50/51/52) will 400 forever.
                    # Skip cleanly rather than falling back to a prefix table
                    # that maps to operator IDs sandbox doesn't know about.
                    if self.credentials.environment.value == "sandbox" and not operator_id:
                        fallback = detect_operator_from_prefix(phone, country_code)
                        if country_code == "NG":
                            if fallback:
                                # Map production operator IDs to their sandbox equivalents
                                SANDBOX_OPERATOR_MAP = {
                                    49: "341",   # MTN (confirmed official sandbox ID)
                                    50: "344",   # Glo (verify this in your Reloadly sandbox dashboard)
                                    51: "342",   # Airtel (verify this)
                                    52: "343",   # 9mobile (verify this)
                                }
                                operator_id = SANDBOX_OPERATOR_MAP.get(fallback["operatorId"], "341")
                                logger.info(
                                    f"Bulk (sandbox): {phone} → {fallback['name']} "
                                    f"(production {fallback['operatorId']} → sandbox {operator_id})"
                                )
                            else:
                                operator_id = "341"
                                logger.info(f"Bulk (sandbox): using operator 341 for {phone} (prefix not recognized)")
                        else:
                            # Sandbox only supports Nigeria operators
                            logger.warning(f"Bulk (sandbox): no sandbox operator for {phone} (country {country_code}). Skipping.")
                            failed += 1
                            processed += 1
                            self._update_bulk_job(c, job_id, processed, successful, failed)
                            continue

                    # LIVE environment only: fall back to the prefix table if
                    # Reloadly couldn't be reached at all. This never runs in
                    # sandbox, because sandbox is guarded above.
                    if not operator_id and not auto_detect_ok:
                        fallback = detect_operator_from_prefix(phone, country_code)
                        if fallback:
                            operator_id = fallback["operatorId"]
                            logger.warning(
                                f"Bulk (live): Reloadly auto-detect unavailable for {phone}; "
                                f"using UNCONFIRMED prefix fallback → {fallback['name']} "
                                f"(operator {operator_id}). May be wrong if the number was ported."
                            )

                    if not operator_id:
                        logger.warning(
                            f"Bulk: could not confidently determine operator for {phone} "
                            f"(country {country_code}). Skipping rather than guessing."
                        )
                        failed += 1
                        processed += 1
                        self._update_bulk_job(c, job_id, processed, successful, failed)
                        continue

                    # LIVE environment only: fall back to prefix table if Reloadly
                    # couldn't be reached at all.
                    

                    # The wallet was already debited for the full job total up
                    # front (bulk_recharge_init / bulk_recharge_contacts), or —
                    # for gateway-paid jobs — the total was already collected
                    # by Paystack/Stripe/Flutterwave before this worker ever
                    # runs. Debiting again per-record here used to double-
                    # charge the wallet path (and would incorrectly try to
                    # debit a wallet at all for gateway-paid jobs). We only
                    # create the pending transaction record now, and refund
                    # THIS record's share below if the Reloadly call fails.
                    reference = f"BULK-{job_id[:8]}-{uuid.uuid4().hex[:8]}"
                    currency = "NGN"

                    # Create pending transaction
                    db.create_pending(
                        reference=reference,
                        tx_type="topup",
                        provider="wallet",
                        amount=amount,
                        currency=currency,
                        payload={
                            "operator_id": operator_id,
                            "phone": phone,
                            "country_code": country_code,
                            "is_bulk": True,
                            "job_id": job_id,
                        },
                        user_id=user_id,
                    )


                    # Call Reloadly
                    try:
                        formatted_phone = self.platform._format_phone_for_topup(phone, country_code)
                        usd_amount = self.platform.convert_to_usd(amount, currency)
                        result = self.platform.make_topup(
                            operator_id=str(operator_id),
                            amount=str(round(usd_amount, 2)),
                            recipient_phone={"countryCode": country_code, "number": formatted_phone},
                            use_local_amount=False,
                            custom_identifier=f"bulk-{reference}",
                            is_async=True,
                        ) or {}

                        provider_status = str(result.get("status") or "").upper()
                        tx_id = result.get("transactionId") or result.get("id")

                        if provider_status == "FAILED" or not tx_id:
                            # Refund
                            self._refund_bulk_record(job_id, user_id, amount, currency, reference, paid_by_wallet)
                            db.mark_failed(reference, result.get("message") or "Provider rejected")
                            failed += 1
                        else:
                            db.mark_fulfilled(reference, result)
                            db.create_reloadly_transaction(
                                reference=reference,
                                user_id=user_id,
                                transaction_type="airtime",
                                amount=amount,
                                status="completed",
                                provider_transaction_id=str(tx_id),
                                result=result,
                                currency=currency,
                            )
                            successful += 1

                    except Exception as e:
                        logger.error(f"Bulk record failure for {reference}: {e}")
                        self._refund_bulk_record(job_id, user_id, amount, currency, reference, paid_by_wallet, {"error": str(e)})
                        db.mark_failed(reference, str(e))
                        failed += 1

                    processed += 1
                    self._update_bulk_job(c, job_id, processed, successful, failed)

                except Exception as e:
                    logger.error(f"Bulk job unexpected error: {e}")
                    failed += 1
                    processed += 1
                    self._update_bulk_job(c, job_id, processed, successful, failed)

            # Finalize
            final_status = "completed" if failed == 0 else ("failed" if successful == 0 else "completed")
            c.execute(
                "UPDATE bulk_jobs SET status = ?, processed = ?, successful = ?, failed = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (final_status, processed, successful, failed, job_id),
            )
            conn.commit()

            db.create_notification(
                user_id,
                "📤 Bulk Recharge Completed",
                f"Bulk job finished: {successful} successful, {failed} failed.",
                "success" if failed == 0 else "warning",
            )

        except Exception as e:
            logger.exception(f"Bulk job {job_id} crashed: {e}")
            try:
                c.execute(
                    "UPDATE bulk_jobs SET status = 'failed', error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (str(e), job_id),
                )
                conn.commit()
            except Exception:
                pass
        finally:
            conn.close()


    def _update_bulk_job(self, cursor, job_id, processed, successful, failed):
        cursor.execute(
            "UPDATE bulk_jobs SET processed = ?, successful = ?, failed = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (processed, successful, failed, job_id),
        )
        cursor.connection.commit()


    def _init_bulk_gateway_checkout(
        self, provider, user_id, amount, currency, job_id, return_url, contact_count
    ):
        """Create a gateway checkout for a bulk job.

        Returns {'authorization_url': ..., 'reference': ...}.
        Reuses the existing PaymentProcessor that single-recharge payments use.
        """
        provider = provider.lower()
        user = db.get_user(user_id)
        email = (user or {}).get("email") or f"user_{user_id}@net365.com"

        # Callback that carries the bulk_job_id back to us
        callback = f"{return_url}?status=success&bulk_job_id={job_id}"

        # Pick the correct secret per provider
        if provider == "paystack":
            api_key = os.getenv("PAYSTACK_SECRET_KEY")
        elif provider == "flutterwave":
            api_key = os.getenv("FLUTTERWAVE_SECRET_KEY")
        elif provider == "stripe":
            api_key = os.getenv("STRIPE_SECRET_KEY")
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        if not api_key:
            raise RuntimeError(f"{provider} secret key not configured")

        processor = PaymentProcessor(provider, api_key)

        # Paystack's own helper already builds the callback URL internally —
        # but it appends its own `return_url` handling. Pass our callback via
        # the return_url arg so the final redirect carries bulk_job_id.
        error_detail = None
        if provider == "paystack":
            auth_url, reference, error_detail = processor.init_paystack_payment(
                email=email,
                amount=amount,
                return_url=callback,
            )
        elif provider == "flutterwave":
            auth_url, reference, error_detail = processor.init_flutterwave_payment(
                email=email,
                amount=amount,
                currency=currency,
                return_url=callback,
            )
        elif provider == "stripe":
            # NOTE: this call site was unpacking only 2 values from a method
            # that has always returned 3 (auth_url, reference, session_id) —
            # meaning bulk-recharge-via-Stripe crashed with a ValueError on
            # every attempt, success or failure, before this fix.
            auth_url, reference, error_detail = processor.init_stripe_payment(
                email=email,
                amount=amount,
                currency=currency,
                return_url=callback,
                description=f"Bulk recharge — {contact_count} contacts",
            )
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        if not auth_url:
            raise RuntimeError(
                f"{provider} did not return an authorization_url: "
                f"{error_detail or 'no detail given'}"
            )

        # Register this payment where /api/payment/verify and the
        # paystack/stripe/flutterwave webhooks actually look for it.
        # Without this, the reference only exists in bulk_job_payments,
        # which the generic verify/webhook pipeline never queries — so a
        # successful charge would leave the job stuck in 'pending_payment'
        # forever and the frontend's verify call would 404.
        db.create_pending(
            reference=reference,
            tx_type="bulk_recharge",
            provider=provider,
            amount=amount,
            currency=currency,
            payload={
                "job_id": job_id,
                "is_bulk_recharge": True,
                "contact_count": contact_count,
            },
            user_id=user_id,
        )

        return {"authorization_url": auth_url, "reference": reference}


    def _user_email(self, user_id):
        conn = db.get_db_connection()
        c = conn.cursor()
        try:
            row = c.execute(
                "SELECT email FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            return row["email"] if row else ""
        finally:
            conn.close()        
    
    def _debit_wallet(self, user_id, currency, amount, reference=None):
        """
        Debit the user's wallet for a bulk-recharge job total.

        Reuses db.debit_wallet() — the same path every other wallet debit in
        this app goes through — instead of hand-rolled SQL. The previous
        version here INSERTed into `transactions` with a `type` column that
        doesn't exist in this deployment's schema (the rest of the codebase
        uses `tx_type` via db.create_pending/db.debit_wallet), which silently
        failed every time ("table transactions has no column named type")
        and meant no ledger row was ever recorded for these debits.

        Returns (ok: bool, error_message: str | None).
        """
        try:
            result = db.debit_wallet(
                user_id=user_id,
                amount=amount,
                currency=currency,
                description="Bulk recharge (wallet)",
                reference=reference,
                metadata={"type": "bulk_recharge_total", "reference": reference},
            )
            if not result or not result.get("success"):
                return False, (result or {}).get("error") or "Wallet debit failed"
            return True, None
        except Exception as e:
            logger.exception("Wallet debit failed")
            return False, str(e)


    def _start_wallet_bulk_job(self, user_id, job_id, records, charge):
        """
        Debit the wallet for a bulk job total, tag the job with payment info,
        then kick off the background worker.

        Returns (success: bool, error_message: str | None).
        """
        # 1. Debit the wallet for the full job total
        ok, err = self._debit_wallet(
            user_id, "NGN", charge, reference=f"bulk:{job_id}"
        )
        if not ok:
            conn = db.get_db_connection()
            c = conn.cursor()
            try:
                c.execute(
                    "UPDATE bulk_jobs SET status = 'failed', error = ? WHERE id = ?",
                    (err or "Wallet debit failed", job_id),
                )
                conn.commit()
            finally:
                conn.close()
            return False, err or "Wallet debit failed"

        # 2. Tag the job with payment details so it's traceable
        conn = db.get_db_connection()
        c = conn.cursor()
        try:
            # Defensive: make sure the columns exist before writing to them
            existing_cols = {
                row[1] for row in c.execute("PRAGMA table_info(bulk_jobs)").fetchall()
            }
            for col, typ in [
                ("payment_method", "TEXT"),
                ("payment_reference", "TEXT"),
                ("total_amount", "REAL"),
                ("currency", "TEXT DEFAULT 'NGN'"),
            ]:
                if col not in existing_cols:
                    try:
                        c.execute(f"ALTER TABLE bulk_jobs ADD COLUMN {col} {typ}")
                    except sqlite3.OperationalError:
                        pass

            c.execute(
                """
                UPDATE bulk_jobs
                SET payment_method = 'wallet',
                    total_amount = ?,
                    currency = 'NGN',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (charge, job_id),
            )
            conn.commit()
        finally:
            conn.close()

        # 3. Kick off the background worker
        threading.Thread(
            target=self._process_bulk_job,
            args=(job_id, user_id, records),
            daemon=True,
        ).start()

        return True, None

    

    def setup_routes(self):
        # ============================================================
        # NET365 LIVE CHAT STORAGE
        # Shared by mobile/desktop customers and the admin console.
        # SQLite is used through the existing database connection so the
        # chat layer requires no second application or service.
        # ============================================================
        try:
            conn = db.get_db_connection()
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    visitor_id TEXT NOT NULL UNIQUE,
                    user_id INTEGER,
                    name TEXT,
                    email TEXT,
                    phone TEXT,
                    country_code TEXT,
                    status TEXT NOT NULL DEFAULT 'open',
                    assigned_admin TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_message_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id INTEGER NOT NULL,
                    sender_type TEXT NOT NULL CHECK(sender_type IN ('customer','admin','system')),
                    sender_id TEXT,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    read_at TEXT,
                    FOREIGN KEY(conversation_id) REFERENCES chat_conversations(id) ON DELETE CASCADE
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_conv_updated ON chat_conversations(updated_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_msg_conv ON chat_messages(conversation_id, id)")
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Live chat schema initialization failed (non-fatal): {e}")

        # ============ ADMIN: SUCCESS PAGE ADS ============
        @self.app.route("/api/admin/success-ads", methods=["GET"])
        @admin_required
        def admin_list_success_ads():
            limit = min(request.args.get("limit", 50, type=int), 200)
            offset = max(request.args.get("offset", 0, type=int), 0)
            ads = db.get_all_success_page_ads(limit, offset)
            return jsonify({"success": True, "ads": ads})


        @self.app.route("/api/admin/success-ads", methods=["POST"])
        @admin_required
        def admin_create_success_ad():
            data = request.json or {}
            if not data.get("name") or not data.get("headline"):
                return jsonify({"success": False, "error": "Name and headline required"}), 400
            ad_id = db.create_success_page_ad(
                slot=data.get("slot", "primary"),
                name=data["name"],
                headline=data["headline"],
                subheadline=data.get("subheadline"),
                body=data.get("body"),
                image_url=data.get("image_url"),
                logo_url=data.get("logo_url"),
                cta_text=data.get("cta_text", "Continue"),
                cta_url=data.get("cta_url"),
                cta_action=data.get("cta_action"),
                background_color=data.get("background_color", "#0b1735"),
                accent_color=data.get("accent_color", "#4f8cff"),
                text_color=data.get("text_color", "#ffffff"),
                secondary_cta_text=data.get("secondary_cta_text"),
                secondary_cta_url=data.get("secondary_cta_url"),
                advertiser_name=data.get("advertiser_name"),
                sponsored=1 if data.get("sponsored") else 0,
                active=1 if data.get("active", True) else 0,
                priority=int(data.get("priority", 0)),
                target_tx_type=data.get("target_tx_type"),
                target_country=data.get("target_country"),
                target_min_amount=data.get("target_min_amount"),
                target_max_amount=data.get("target_max_amount"),
                target_device=data.get("target_device"),
                start_date=data.get("start_date"),
                end_date=data.get("end_date"),
                max_impressions=data.get("max_impressions"),
                max_clicks=data.get("max_clicks"),
                created_by=g.current_user.get("id") if hasattr(g, "current_user") else None,
            )
            if not ad_id:
                return jsonify({"success": False, "error": "Failed to create ad"}), 500
            return jsonify({"success": True, "ad_id": ad_id})


        @self.app.route("/api/admin/success-ads/<int:ad_id>", methods=["GET"])
        @admin_required
        def admin_get_success_ad(ad_id):
            ad = db.get_success_page_ad(ad_id)
            if not ad:
                return jsonify({"success": False, "error": "Ad not found"}), 404
            ad["analytics"] = db.get_success_page_ad_analytics(ad_id)
            return jsonify({"success": True, "ad": ad})


        @self.app.route("/api/admin/success-ads/<int:ad_id>", methods=["PUT"])
        @admin_required
        def admin_update_success_ad(ad_id):
            data = request.json or {}
            if db.update_success_page_ad(ad_id, **data):
                return jsonify({"success": True})
            return jsonify({"success": False, "error": "Update failed"}), 500


        @self.app.route("/api/admin/success-ads/<int:ad_id>", methods=["DELETE"])
        @admin_required
        def admin_delete_success_ad(ad_id):
            if db.delete_success_page_ad(ad_id):
                return jsonify({"success": True})
            return jsonify({"success": False, "error": "Delete failed"}), 500
            
            
        @self.app.route("/api/success-ads/recommend", methods=["POST"])
        def recommend_success_ad():
            """Return the best success-page ad for this transaction.

            This is the mobile-friendly entry point. Mobile.html calls it after a
            payment succeeds and renders the returned ad as a moment overlay.
            """
            try:
                db.ensure_success_page_ads_schema()  # self-heal
                data = request.get_json(silent=True) or {}
                tx_type = data.get("tx_type")
                amount = data.get("amount")
                country = data.get("country")
                device_type = parse_user_agent(request.headers.get("User-Agent", ""))["device_type"]

                ad = db.select_success_page_ad(
                    tx_type=tx_type,
                    country=country,
                    amount=float(amount) if amount else None,
                    device_type=device_type or "Mobile",
                )
                if not ad:
                    return jsonify({"success": True, "ad": None})

                # Track impression server-side (fire once per request)
                try:
                    db.record_success_page_ad_event(
                        ad["id"], "impression",
                        reference=data.get("reference"),
                        user_id=data.get("user_id"),
                        device_type=device_type,
                        country=country,
                    )
                except Exception as e:
                    logger.warning(f"Impression tracking failed: {e}")

                # Translate success_page_ads shape -> the shape mobile.html's renderSmartAd() expects
                return jsonify({
                    "success": True,
                    "ad": {
                        "id": f"spa-{ad['id']}",
                        "type": "success_page_ad",
                        "sponsored": bool(ad.get("sponsored")),
                        "badge": "SPONSORED" if ad.get("sponsored") else "SMART OFFER",
                        "accent": ad.get("accent_color") or "#7C3AED",
                        "accent2": "#22D3EE",
                        "icon": "fa-sparkles",
                        "kicker": ad.get("subheadline") or "",
                        "title": ad.get("headline") or "",
                        "description": ad.get("body") or "",
                        "offer_value": "",
                        "offer_label": "",
                        "cta": ad.get("cta_text") or "Continue",
                        "landing_url": ad.get("cta_url") or "#",
                        "image_url": ad.get("image_url") or "",
                        "logo_url": ad.get("logo_url") or "",
                        "footer": ad.get("advertiser_name") or "Net365",
                        "action": ad.get("cta_action") or None,
                        "campaign_id": ad["id"],
                    },
                })
            except Exception as e:
                logger.exception(f"recommend_success_ad failed: {e}")
                return jsonify({"success": False, "error": str(e)}), 500            


        def select_success_page_ad(self, tx_type, country, amount, device_type, user_signals):
            candidates = get_active_campaigns()
            scored = []
            for c in candidates:
                score = c.priority  # base
                # Hard filters
                if c.target_country and c.target_country != country:
                    continue
                # Soft scoring — every match adds weight
                if c.target_tx_type == tx_type:
                    score += 50
                if c.target_device == device_type:
                    score += 10
                if c.target_languages and user_signals['language'] in c.target_languages:
                    score += 15
                if c.target_connection and user_signals['connection'] == c.target_connection:
                    score += 8
                if c.target_hours and user_signals['local_hour'] in c.target_hours:
                    score += 12
                if c.target_networks and user_signals['preferred_network'] in c.target_networks:
                    score += 20
                if c.exclude_service and c.exclude_service == tx_type:
                    continue
                # RFM gating
                if c.target_rfm and not matches_rfm(user_signals['rfm'], c.target_rfm):
                    continue
                scored.append((score, c))
            return max(scored, key=lambda x: x[0])[1] if scored else None
     
        @self.app.route("/api/chat/session", methods=["POST"])
        def chat_session():
            """Create/reuse a lightweight anonymous support conversation."""
            data = request.get_json(silent=True) or {}
            visitor_id = (request.cookies.get("net365_chat_visitor") or str(uuid.uuid4())).strip()
            user = get_authenticated_user()
            user_id = user.get("id") if user else None
            name = str(data.get("name") or (user.get("full_name") if user else "") or "")[:120]
            email = str(data.get("email") or (user.get("email") if user else "") or "")[:180]
            phone = str(data.get("phone") or "")[:40]
            country_code = str(data.get("country_code") or get_request_country(request) or "NG").upper()[:2]

            conn = db.get_db_connection()
            row = conn.execute("SELECT * FROM chat_conversations WHERE visitor_id = ?", (visitor_id,)).fetchone()
            if row:
                conversation_id = row["id"] if isinstance(row, sqlite3.Row) else row[0]
                conn.execute("""UPDATE chat_conversations
                    SET user_id=COALESCE(?, user_id), name=COALESCE(NULLIF(?, ''), name),
                        email=COALESCE(NULLIF(?, ''), email), phone=COALESCE(NULLIF(?, ''), phone),
                        country_code=COALESCE(NULLIF(?, ''), country_code), updated_at=CURRENT_TIMESTAMP
                    WHERE id=?""", (user_id, name, email, phone, country_code, conversation_id))
            else:
                cur = conn.execute("""INSERT INTO chat_conversations
                    (visitor_id,user_id,name,email,phone,country_code)
                    VALUES (?,?,?,?,?,?)""", (visitor_id,user_id,name,email,phone,country_code))
                conversation_id = cur.lastrowid
                conn.execute("""INSERT INTO chat_messages(conversation_id,sender_type,message)
                    VALUES (?,?,?)""", (conversation_id, "system", "Hi! 👋 Welcome to NET365 Support. An agent will join the conversation as soon as possible."))
            conn.commit()
            conn.close()

            response = jsonify({"success": True, "conversation_id": conversation_id, "visitor_id": visitor_id})
            response.set_cookie("net365_chat_visitor", visitor_id, max_age=60*60*24*90, httponly=True, samesite="Lax", secure=request.is_secure)
            return response

        @self.app.route("/api/chat/messages", methods=["GET"])
        def chat_messages():
            # A conversation ID is not an authorization credential. Require the
            # HttpOnly visitor cookie or the authenticated account that owns it.
            cookie_visitor = (request.cookies.get("net365_chat_visitor") or "").strip()
            supplied_visitor = (request.args.get("visitor_id") or "").strip()
            if supplied_visitor and cookie_visitor and not secrets.compare_digest(supplied_visitor, cookie_visitor):
                return jsonify({"success": False, "error": "Chat session mismatch"}), 403
            visitor_id = cookie_visitor
            conversation_id = request.args.get("conversation_id", type=int)
            user = get_authenticated_user()
            if not visitor_id and not user:
                return jsonify({"success": False, "error": "Chat session required"}), 401
            if not conversation_id and not visitor_id:
                return jsonify({"success": False, "error": "Chat session required"}), 400
            conn = db.get_db_connection()
            if conversation_id:
                conv = conn.execute("SELECT * FROM chat_conversations WHERE id=?", (conversation_id,)).fetchone()
            else:
                conv = conn.execute("SELECT * FROM chat_conversations WHERE visitor_id=?", (visitor_id,)).fetchone()
            if not conv:
                conn.close()
                return jsonify({"success": True, "conversation": None, "messages": []})
            cid = conv["id"] if isinstance(conv, sqlite3.Row) else conv[0]
            owner_visitor = conv["visitor_id"] if isinstance(conv, sqlite3.Row) else conv[1]
            owner_user = conv["user_id"] if isinstance(conv, sqlite3.Row) and "user_id" in conv.keys() else None
            owns = bool(visitor_id and secrets.compare_digest(str(owner_visitor or ""), visitor_id))
            owns = owns or bool(user and owner_user and str(owner_user) == str(user.get("id")))
            if not owns:
                conn.close()
                return jsonify({"success": False, "error": "Chat session mismatch"}), 403
            rows = conn.execute("SELECT id,sender_type,sender_id,message,created_at,read_at FROM chat_messages WHERE conversation_id=? ORDER BY id ASC LIMIT 500", (cid,)).fetchall()
            messages = [
                {k: r[k] for k in ("id", "sender_type", "message", "created_at", "read_at")}
                for r in rows
            ]
            # Customer reading admin messages marks them read.
            conn.execute("UPDATE chat_messages SET read_at=CURRENT_TIMESTAMP WHERE conversation_id=? AND sender_type='admin' AND read_at IS NULL", (cid,))
            conn.commit()
            conn.close()
            # Do not return visitor IDs or customer contact details to the browser.
            safe_conversation = {"id": cid, "status": conv["status"] if isinstance(conv, sqlite3.Row) else None}
            return jsonify({"success": True, "conversation": safe_conversation, "messages": messages})

        @self.app.route("/api/chat/messages", methods=["POST"])
        @rate_limit(max_requests=30, window_seconds=60)
        def chat_send_message():
            data = request.get_json(silent=True) or {}
            text = str(data.get("message") or "").strip()
            if not text:
                return jsonify({"success": False, "error": "Message is required"}), 400
            if len(text) > 4000:
                return jsonify({"success": False, "error": "Message is too long"}), 400

            cookie_visitor = (request.cookies.get("net365_chat_visitor") or "").strip()
            supplied_visitor = str(data.get("visitor_id") or "").strip()
            if supplied_visitor and cookie_visitor and not secrets.compare_digest(supplied_visitor, cookie_visitor):
                return jsonify({"success": False, "error": "Chat session mismatch"}), 403
            visitor_id = cookie_visitor
            conversation_id = data.get("conversation_id")
            if not visitor_id and not conversation_id:
                return jsonify({"success": False, "error": "Start a chat session first"}), 400

            conn = db.get_db_connection()
            if conversation_id:
                conv = conn.execute("SELECT * FROM chat_conversations WHERE id=?", (int(conversation_id),)).fetchone()
            else:
                conv = conn.execute("SELECT * FROM chat_conversations WHERE visitor_id=?", (visitor_id,)).fetchone()
            if not conv:
                conn.close()
                return jsonify({"success": False, "error": "Chat session not found"}), 404
            cid = conv["id"] if isinstance(conv, sqlite3.Row) else conv[0]
            conv_visitor = conv["visitor_id"] if isinstance(conv, sqlite3.Row) else conv[1]
            user = get_authenticated_user()
            conv_user = conv["user_id"] if isinstance(conv, sqlite3.Row) and "user_id" in conv.keys() else None
            owns_visitor = bool(visitor_id and secrets.compare_digest(str(conv_visitor or ""), visitor_id))
            owns_user = bool(user and conv_user and str(conv_user) == str(user.get("id")))
            if not (owns_visitor or owns_user):
                conn.close()
                return jsonify({"success": False, "error": "Chat session mismatch"}), 403

            cur = conn.execute("INSERT INTO chat_messages(conversation_id,sender_type,sender_id,message) VALUES (?,?,?,?)",
                               (cid, "customer", str(user.get("id")) if user else visitor_id, text))
            conn.execute("UPDATE chat_conversations SET status='open', updated_at=CURRENT_TIMESTAMP, last_message_at=CURRENT_TIMESTAMP WHERE id=?", (cid,))
            conn.commit()
            message_id = cur.lastrowid
            row = conn.execute("SELECT id,sender_type,sender_id,message,created_at,read_at FROM chat_messages WHERE id=?", (message_id,)).fetchone()
            conn.close()
            return jsonify({"success": True, "message": dict(row)})

        @self.app.route("/api/admin/chat/conversations", methods=["GET"])
        @admin_required
        def admin_chat_conversations():
            status = (request.args.get("status") or "open").strip().lower()
            if status not in ("open", "closed", "all"):
                status = "open"
            conn = db.get_db_connection()
            where = "" if status == "all" else "WHERE c.status=?"
            params = () if status == "all" else (status,)
            rows = conn.execute(f"""SELECT c.*, 
                (SELECT COUNT(*) FROM chat_messages m WHERE m.conversation_id=c.id AND m.sender_type='customer' AND m.read_at IS NULL) AS unread_count,
                (SELECT message FROM chat_messages m WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1) AS last_message
                FROM chat_conversations c {where} ORDER BY c.last_message_at DESC LIMIT 100""", params).fetchall()
            result = [dict(r) for r in rows]
            conn.close()
            return jsonify({"success": True, "conversations": result})

        @self.app.route("/api/admin/chat/conversations/<int:conversation_id>", methods=["GET"])
        @admin_required
        def admin_chat_conversation(conversation_id):
            conn = db.get_db_connection()
            conv = conn.execute("SELECT * FROM chat_conversations WHERE id=?", (conversation_id,)).fetchone()
            rows = conn.execute("SELECT id,sender_type,sender_id,message,created_at,read_at FROM chat_messages WHERE conversation_id=? ORDER BY id ASC", (conversation_id,)).fetchall()
            conn.execute("UPDATE chat_messages SET read_at=CURRENT_TIMESTAMP WHERE conversation_id=? AND sender_type='customer'", (conversation_id,))
            conn.commit()
            conn.close()
            if not conv:
                return jsonify({"success": False, "error": "Conversation not found"}), 404
            return jsonify({"success": True, "conversation": dict(conv), "messages": [dict(r) for r in rows]})

        @self.app.route("/api/admin/chat/messages", methods=["POST"])
        @admin_required
        @rate_limit(max_requests=60, window_seconds=60)
        def admin_chat_send_message():
            data = request.get_json(silent=True) or {}
            conversation_id = data.get("conversation_id")
            text = str(data.get("message") or "").strip()
            if not conversation_id or not text:
                return jsonify({"success": False, "error": "Conversation and message are required"}), 400
            if len(text) > 4000:
                return jsonify({"success": False, "error": "Message is too long"}), 400
            conn = db.get_db_connection()
            exists = conn.execute("SELECT id FROM chat_conversations WHERE id=?", (int(conversation_id),)).fetchone()
            if not exists:
                conn.close()
                return jsonify({"success": False, "error": "Conversation not found"}), 404
            cur = conn.execute("INSERT INTO chat_messages(conversation_id,sender_type,sender_id,message) VALUES (?,?,?,?)",
                               (int(conversation_id), "admin", "admin", text))
            conn.execute("UPDATE chat_conversations SET status='open', assigned_admin='admin', updated_at=CURRENT_TIMESTAMP, last_message_at=CURRENT_TIMESTAMP WHERE id=?", (int(conversation_id),))
            conn.commit()
            row = conn.execute("SELECT id,sender_type,sender_id,message,created_at,read_at FROM chat_messages WHERE id=?", (cur.lastrowid,)).fetchone()
            conn.close()
            return jsonify({"success": True, "message": dict(row)})

        @self.app.route("/api/admin/chat/conversations/<int:conversation_id>/status", methods=["POST"])
        @admin_required
        def admin_chat_status(conversation_id):
            data = request.get_json(silent=True) or {}
            status = str(data.get("status") or "open").lower()
            if status not in ("open", "closed"):
                return jsonify({"success": False, "error": "Invalid status"}), 400
            conn = db.get_db_connection()
            conn.execute("UPDATE chat_conversations SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (status, conversation_id))
            conn.commit()
            conn.close()
            return jsonify({"success": True, "status": status})

        @self.app.after_request
        def add_security_headers(response):
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = "camera=(self), microphone=(self), geolocation=(self)"
            response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
            if request.is_secure:
                # Avoid includeSubDomains until every Net365 subdomain is confirmed HTTPS-only.
                response.headers["Strict-Transport-Security"] = "max-age=15552000"
            if request.path == "/app":
                # Telegram Mini App page: Telegram Web shows it in a frame, so allow Telegram (and only Telegram) to frame it
                response.headers["Content-Security-Policy"] = "frame-ancestors 'self' https://web.telegram.org https://*.telegram.org"
            else:
                response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            # Ask Chrome/Edge for the real device model. Critical-CH makes the
            # browser retry the FIRST page load with the hint (HTTPS/localhost only);
            # without it the model only appears from the second request onwards.
            response.headers["Accept-CH"] = "Sec-CH-UA-Model"
            response.headers["Critical-CH"] = "Sec-CH-UA-Model"
            response.headers.add("Vary", "Sec-CH-UA-Model")
            return response

        @self.app.route("/")
        @self.app.route("/index.html")
        def index():
            device_type = parse_user_agent(request.headers.get("User-Agent", ""))["device_type"]
            # ?full=1 lets phone users open the full desktop platform on purpose
            use_mobile = device_type == "Mobile" and not request.args.get("full")
            template = "mobile.html" if use_mobile else "index.html"
            return render_template(
                template,
                environment=self.credentials.environment.value,
                device_type=device_type,
            )

        @self.app.route("/utilities")
        def utilities():
            device_type = parse_user_agent(request.headers.get("User-Agent", ""))["device_type"]
            return render_template(
                "utilities.html",
                environment=self.credentials.environment.value,
                device_type=device_type,
            )

        @self.app.route("/scheduler")
        def scheduler_page():
            scheduler_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "scheduler.html"
            )
            if os.path.exists(scheduler_path):
                return send_from_directory(
                    os.path.dirname(scheduler_path), "scheduler.html"
                )
            else:
                return (
                    "Scheduler page not found. Please create scheduler.html in the root directory.",
                    404,
                )

        # Scheduler assets are served ONLY from a dedicated folder (scheduler_static/) and only
        # for an allow-list of file types. The old route served the whole application directory,
        # which exposed source code, the database and environment files to anyone.
        _SCHEDULER_ASSET_EXT = {".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".webp", ".woff", ".woff2"}

        @self.app.route("/scheduler/<path:filename>")
        def scheduler_static(filename):
            ext = os.path.splitext(filename)[1].lower()
            parts = [p for p in filename.replace("\\", "/").split("/") if p]
            if (
                ext not in _SCHEDULER_ASSET_EXT
                or not parts
                or any(p.startswith(".") or p == ".." for p in parts)
            ):
                return jsonify({"success": False, "error": "Not found"}), 404
            static_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "scheduler_static"
            )
            if not os.path.isdir(static_dir):
                return jsonify({"success": False, "error": "Not found"}), 404
            return send_from_directory(static_dir, filename)

        @self.app.route("/analytics")
        def analytics_page():
            analytics_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "analytics.html"
            )
            if os.path.exists(analytics_path):
                return send_from_directory(
                    os.path.dirname(analytics_path), "analytics.html"
                )
            else:
                return (
                    "Analytics page not found. Please create analytics.html in the root directory.",
                    404,
                )
        @self.app.route("/bots")
        def bots_page():
            return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "bots.html")
        # ============ PWA (installable app) ============
        _pwa_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pwa")

        @self.app.route("/manifest.webmanifest")
        def pwa_manifest():
            resp = send_from_directory(_pwa_dir, "manifest.webmanifest",
                                       mimetype="application/manifest+json")
            resp.headers["Cache-Control"] = "no-cache"
            return resp

        @self.app.route("/sw.js")
        def pwa_service_worker():
            # Must be served from the site root so it can control every page.
            resp = send_from_directory(_pwa_dir, "sw.js", mimetype="application/javascript")
            resp.headers["Cache-Control"] = "no-cache, max-age=0"
            resp.headers["Service-Worker-Allowed"] = "/"
            return resp

        @self.app.route("/pwa.js")
        def pwa_loader():
            resp = send_from_directory(_pwa_dir, "pwa.js", mimetype="application/javascript")
            resp.headers["Cache-Control"] = "no-cache"
            return resp

        @self.app.route("/onepay.js")
        def onepay_loader():
            resp = send_from_directory(os.path.dirname(os.path.abspath(__file__)), "onepay.js",
                                       mimetype="application/javascript")
            resp.headers["Cache-Control"] = "no-cache"
            return resp

        @self.app.route("/offline.html")
        def pwa_offline():
            return send_from_directory(_pwa_dir, "offline.html")

        @self.app.route("/icons/<path:filename>")
        def pwa_icons(filename):
            resp = send_from_directory(os.path.join(_pwa_dir, "icons"), filename)
            resp.headers["Cache-Control"] = "public, max-age=604800"
            return resp

        @self.app.route("/giftcards")
        def giftcards_page():
            """Full-page Reloadly gift cards & subscriptions store."""
            base = os.path.dirname(os.path.abspath(__file__))
            if os.path.exists(os.path.join(base, "giftcards.html")):
                return send_from_directory(base, "giftcards.html")
            return "Gift cards page not found", 404

        @self.app.route("/business")
        def business_page():
            business_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "business.html"
            )
            if os.path.exists(business_path):
                return send_from_directory(
                    os.path.dirname(business_path), "business.html"
                )
            else:
                return (
                    "Business page not found. Please create business.html in the root directory.",
                    404,
                )

        # ============================================================
        # ADMIN: REFERRAL BONUS CONFIGURATION
        # ============================================================

        

        

        # ============================================================
        # ADMIN: REFERRALS MANAGEMENT
        # ============================================================

        @self.app.route("/api/admin/referrals/all", methods=["GET"])
        @admin_required
        def admin_get_all_referrals():
            """Get all referrals with pagination and filters."""
            limit = min(request.args.get("limit", 20, type=int), 100)
            offset = max(request.args.get("offset", 0, type=int), 0)
            status = request.args.get("status")
            tier = request.args.get("tier")
            date = request.args.get("date")

            result = db.get_all_referrals_admin(limit, offset, status, tier, date)
            return jsonify(result)

        @self.app.route("/api/admin/referrals/<int:referral_id>", methods=["GET"])
        @admin_required
        def admin_get_referral_detail(referral_id):
            """Get detailed referral information."""
            result = db.get_referral_detail_admin(referral_id)
            if not result:
                return jsonify({"success": False, "error": "Referral not found"}), 404
            return jsonify({"success": True, "referral": result})

        @self.app.route(
            "/api/admin/referrals/<int:referral_id>/complete", methods=["POST"]
        )
        @admin_required
        def admin_complete_referral(referral_id):
            """Manually mark a referral as completed."""
            result = db.complete_referral_admin(referral_id)
            if result:
                return jsonify({"success": True, "message": "Referral completed"})
            return jsonify({"success": False, "error": "Failed to complete referral"})

        # ============================================================
        # ADMIN: BONUS HISTORY
        # ============================================================

        @self.app.route("/api/admin/bonus/history", methods=["GET"])
        @admin_required
        def admin_get_bonus_history():
            """Get bonus history for all users."""
            limit = min(request.args.get("limit", 50, type=int), 200)
            result = db.get_bonus_history_admin(limit)
            return jsonify({"success": True, "bonuses": result})

        # ============================================================
        # ADMIN: SEASONAL PROMOTION
        # ============================================================

        @self.app.route("/api/admin/seasonal-promo", methods=["GET", "POST", "DELETE"])
        @admin_required
        def admin_seasonal_promo():
            """Manage seasonal promotions."""
            if request.method == "GET":
                result = db.get_seasonal_promo()
                return jsonify({"success": True, "promo": result})

            if request.method == "POST":
                data = request.json or {}
                result = db.save_seasonal_promo(
                    name=data.get("name"),
                    multiplier=data.get("multiplier", 1.5),
                    start_date=data.get("start_date"),
                    end_date=data.get("end_date"),
                )
                return jsonify(result)

            if request.method == "DELETE":
                result = db.cancel_seasonal_promo()
                return jsonify(result)

        
        # ============ REFERRAL ADMIN ENDPOINTS ============

        @self.app.route("/admin")
        def admin_page():
            # No @login_required here deliberately — the page itself prompts for the
            # ADMIN_SECRET and every API call it makes is gated by @admin_required.
            # Serving the empty shell to anyone is harmless; the data behind it isn't.
            admin_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "admin.html"
            )
            if os.path.exists(admin_path):
                return send_from_directory(os.path.dirname(admin_path), "admin.html")
            else:
                return (
                    "Admin page not found. Please create admin.html in the root directory.",
                    404,
                )
                # ============ STATIC PAGE ROUTES ============

        @self.app.route("/marketplace")
        def marketplace():
            marketplace_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "marketplace.html"
            )
            if os.path.exists(marketplace_path):
                return send_from_directory(
                    os.path.dirname(marketplace_path), "marketplace.html"
                )
            else:
                return (
                    "Marketplace page not found. Please create marketplace.html in the root directory.",
                    404,
                )

        @self.app.route("/services")
        def services():
            services_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "services.html"
            )
            if os.path.exists(services_path):
                return send_from_directory(
                    os.path.dirname(services_path), "services.html"
                )
            else:
                return (
                    "Services page not found. Please create services.html in the root directory.",
                    404,
                )

        # ============ REFERRAL SYSTEM API ROUTES ============

        @self.app.route("/api/referral/generate", methods=["POST"])
        @login_required
        def generate_referral_code():
            """Generate a new referral code for the current user."""
            user_id = g.current_user_id

            # Check if user already has a code
            existing = db.get_referral_code_by_user_id(user_id)
            if existing:
                return jsonify(
                    {
                        "success": True,
                        "referral_code": existing,
                        "message": "You already have a referral code",
                    }
                )

            # Generate new code
            code = db.create_referral_code(user_id)
            if code:
                return jsonify(
                    {
                        "success": True,
                        "referral_code": code,
                        "message": "Referral code generated successfully!",
                    }
                )

            return (
                jsonify(
                    {"success": False, "error": "Failed to generate referral code"}
                ),
                500,
            )

        @self.app.route("/api/referral/check", methods=["POST"])
        def check_referral_code():
            """Check if a referral code is valid."""

            data = request.get_json(silent=True) or {}

            code = data.get("code") or data.get("referral_code")

            if code:
                code = str(code).strip().upper()

            logger.info("Referral check request - code=%s", code)

            if not code:
                return (
                    jsonify(
                        {
                            "success": False,
                            "valid": False,
                            "error": "Please enter a referral code",
                            "code": "MISSING_CODE",
                        }
                    ),
                    400,
                )

            conn = db.get_db_connection()

            try:
                c = conn.cursor()

                # Exact match
                user = c.execute(
                    """
                    SELECT id, full_name, email
                    FROM users
                    WHERE UPPER(TRIM(referral_code)) = ?
                    """,
                    (code,),
                ).fetchone()

                # Try NET- prefix
                if not user and not code.startswith("NET-"):
                    user = c.execute(
                        """
                        SELECT id, full_name, email
                        FROM users
                        WHERE UPPER(TRIM(referral_code)) = ?
                        """,
                        (f"NET-{code}",),
                    ).fetchone()

                # Try without NET- prefix
                if not user and code.startswith("NET-"):
                    user = c.execute(
                        """
                        SELECT id, full_name, email
                        FROM users
                        WHERE UPPER(TRIM(referral_code)) = ?
                        """,
                        (code[4:],),
                    ).fetchone()

            finally:
                conn.close()

            if user:
                logger.info("Referral code %s is valid for user %s", code, user["id"])

                return (
                    jsonify(
                        {
                            "success": True,
                            "valid": True,
                            "message": "Referral code is valid!",
                            "referrer_name": user["full_name"],
                            "referrer_id": user["id"],
                            "referrer_email": user["email"],
                        }
                    ),
                    200,
                )

            logger.warning("Referral code %s is invalid", code)

            return (
                jsonify(
                    {
                        "success": False,
                        "valid": False,
                        "error": "Invalid referral code",
                        "code": "INVALID_CODE",
                    }
                ),
                404,
            )

        @self.app.route("/api/referral/apply", methods=["POST"])
        @login_required
        def apply_referral():
            """Apply a referral code during transaction or registration.

            Records the referrer → referred relationship as 'pending'. Actual bonus
            computation happens later, at payout time, via db.process_pending_referrals()
            or db.process_referral_reward() — NOT here. This endpoint does not check
            whether bonuses are currently enabled, because a pending referral is valid
            even if the program is temporarily paused; it simply becomes payable once
            the program resumes.
            """
            data = request.json or {}
            referral_code = data.get("referral_code", "").strip().upper()
            user_id = g.current_user_id

            logger.info(f"Referral apply attempt: user_id={user_id}, code={referral_code}")

            if not referral_code:
                return jsonify({
                    "success": False,
                    "error": "Referral code required",
                    "code": "MISSING_CODE",
                }), 400

            DEFAULT_REFERRAL_CODE = "00000"

            if referral_code == DEFAULT_REFERRAL_CODE:
                logger.info(f"User {user_id} used default referral code")
                return jsonify({
                    "success": True,
                    "message": "Default referral code applied",
                    "code": "DEFAULT_REFERRAL",
                    "referrer": None,
                    "is_default": True,
                })

            conn = db.get_db_connection()
            c = conn.cursor()

            try:
                # Don't allow users to use their own referral code
                own_code = c.execute(
                    "SELECT id FROM users WHERE id = ? AND UPPER(referral_code) = ?",
                    (user_id, referral_code),
                ).fetchone()

                if own_code:
                    logger.warning(
                        f"User {user_id} attempted to use their own referral code: {referral_code}"
                    )
                    return jsonify({
                        "success": False,
                        "error": "You cannot use your own referral code",
                        "code": "SELF_REFERRAL",
                    }), 400

                # Find the referrer by referral code
                referrer = c.execute(
                    "SELECT id, full_name, email FROM users WHERE UPPER(referral_code) = ? AND id != ?",
                    (referral_code, user_id),
                ).fetchone()

                if not referrer:
                    logger.warning(
                        f"Invalid referral code attempted: {referral_code} by user {user_id}"
                    )
                    return jsonify({
                        "success": False,
                        "error": "Invalid referral code",
                        "code": "INVALID_CODE",
                    }), 404

                # Check if user has already been referred
                existing_referral = c.execute(
                    "SELECT id, status FROM referrals WHERE referred_id = ? AND status IN ('pending', 'completed')",
                    (user_id,),
                ).fetchone()

                if existing_referral:
                    logger.info(
                        f"User {user_id} already has a referral (status: {existing_referral['status']})"
                    )
                    return jsonify({
                        "success": False,
                        "error": "You have already been referred by someone",
                        "code": "ALREADY_REFERRED",
                        "already_referred": True,
                        "status": existing_referral["status"],
                    }), 400

                # Create referral record (pending — bonus is computed later, at payout time)
                c.execute(
                    """
                    INSERT INTO referrals (referrer_id, referred_id, status, created_at)
                    VALUES (?, ?, 'pending', CURRENT_TIMESTAMP)
                    """,
                    (referrer["id"], user_id),
                )
                referral_id = c.lastrowid
                conn.commit()

                logger.info(
                    f"Referral created: id={referral_id}, referrer={referrer['id']}, referred={user_id}"
                )

                # Log the event
                log_event(
                    user_id=user_id,
                    event_type="referral_applied",
                    details={
                        "referrer_id": referrer["id"],
                        "referrer_name": referrer["full_name"],
                        "referral_code": referral_code,
                        "referral_id": referral_id,
                    },
                    status="success",
                )

                # Notify the referrer
                db.create_notification(
                    referrer["id"],
                    "👤 New Referral!",
                    "A new user has used your referral code to join Net365!",
                    "success",
                )

                # Notify the referred user
                try:
                    _bonus_live = is_referral_bonus_enabled() and bool(
                        (db.get_referral_bonus_config() or {}).get("enabled")
                    )
                except Exception:
                    _bonus_live = False
                db.create_notification(
                    user_id,
                    "🎉 Referral Code Applied!" if _bonus_live else "Referral code saved",
                    (f"You've been referred by {referrer['full_name']}. Complete your first transaction to earn rewards!"
                     if _bonus_live else
                     f"You've been referred by {referrer['full_name']}. Referral rewards are not active yet."),
                    "success",
                )

                return jsonify({
                    "success": True,
                    "message": ("Referral code applied successfully!" if _bonus_live
                                else "Referral code saved. Referral rewards are not active yet."),
                    "referrer": {
                        "id": referrer["id"],
                        "name": referrer["full_name"],
                        "email": referrer["email"],
                    },
                    "referral_id": referral_id,
                    "is_default": False,
                })

            except sqlite3.IntegrityError as e:
                conn.rollback()
                logger.error(f"Database integrity error creating referral: {e}")
                return jsonify({
                    "success": False,
                    "error": "Failed to apply referral code. Please try again.",
                    "code": "DB_ERROR",
                }), 500
            except Exception as e:
                conn.rollback()
                logger.error(f"Error creating referral: {e}")
                return jsonify({
                    "success": False,
                    "error": "An unexpected error occurred. Please try again.",
                    "code": "UNKNOWN_ERROR",
                }), 500
            finally:
                conn.close()
        
        
        
        
        
        def referral_enabled_required(func):
            """Short-circuits the request when the referral program is paused."""
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not is_referral_bonus_enabled():
                    return jsonify({
                        "success": False,
                        "valid": False,
                        "error": "Referral program is currently paused.",
                        "code": "REFERRAL_DISABLED",
                    }), 403
                return func(*args, **kwargs)
            return wrapper

        @self.app.route("/api/referral/code", methods=["GET"])
        @login_required
        def get_referral_code():
            """Get the current user's referral code."""
            user_id = g.current_user_id

            code = db.get_referral_code_by_user_id(user_id)
            if code:
                return jsonify(
                    {
                        "success": True,
                        "referral_code": code,
                        "invite_url": f"{FRONTEND_URL}/?ref={code}",
                    }
                )

            # Generate a code if none exists
            code = db.create_referral_code(user_id)
            if code:
                return jsonify(
                    {
                        "success": True,
                        "referral_code": code,
                        "invite_url": f"{FRONTEND_URL}/?ref={code}",
                    }
                )

            return (
                jsonify({"success": False, "error": "Failed to get referral code"}),
                500,
            )

        @self.app.route("/api/referral/process-reward", methods=["POST"])
        @login_required
        def process_referral_reward():
            """Process referral reward for a transaction (called after payment)."""
            data = request.json or {}
            transaction_reference = data.get("transaction_reference")
            transaction_amount = data.get("amount")
            transaction_currency = data.get("currency", "NGN")
            user_id = g.current_user_id

            if not transaction_reference or not transaction_amount:
                return (
                    jsonify({"success": False, "error": "Missing transaction details"}),
                    400,
                )

            result = db.process_referral_reward(
                user_id,
                transaction_reference,
                float(transaction_amount),
                transaction_currency,
            )

            return jsonify(result)

        # ============ ADD THESE INSIDE setup_routes() ============

        # ============ REFERRAL API ROUTES ============

        @self.app.route("/api/referral/complete", methods=["POST"])
        @login_required
        def complete_referral():
            """Complete a referral when the referred user makes their first transaction."""
            data = request.json or {}
            transaction_ref = data.get("transaction_reference")
            user_id = g.current_user_id

            conn = db.get_db_connection()
            c = conn.cursor()

            # Find pending referral for this user
            referral = c.execute(
                """
                SELECT r.*, u.referral_code as referrer_code 
                FROM referrals r
                JOIN users u ON u.id = r.referrer_id
                WHERE r.referred_id = ? AND r.status = 'pending'
                ORDER BY r.created_at DESC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()

            if not referral:
                conn.close()
                return (
                    jsonify({"success": False, "error": "No pending referral found"}),
                    404,
                )

            # Mark as completed
            c.execute(
                "UPDATE referrals SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                (referral["id"],),
            )
            conn.commit()

            # Apply referral bonuses
            promo_result = db.apply_referral_promo(user_id)
            bonus_applied = False

            if promo_result.get("success"):
                referrer_id = referral["referrer_id"]

                # Credit referrer
                referrer_bonus = promo_result.get("referrer", {})
                if referrer_bonus.get("bonus_value", 0) > 0:
                    if referrer_bonus.get("bonus_type") == "percentage":
                        # Get transaction amount and calculate percentage
                        tx = (
                            db.get_transaction(transaction_ref)
                            if transaction_ref
                            else None
                        )
                        if tx:
                            amount = float(tx.get("amount", 0))
                            bonus_amount = amount * (
                                referrer_bonus["bonus_value"] / 100
                            )
                        else:
                            bonus_amount = 0
                    else:
                        bonus_amount = float(referrer_bonus["bonus_value"])

                    if bonus_amount > 0:
                        db.credit_wallet(
                            user_id=referrer_id,
                            amount=bonus_amount,
                            description=f"Referral bonus: {user_id} completed their first transaction",
                            reference=f'REFBONUS-{referral["id"]}',
                            currency="NGN",
                        )
                        db.create_notification(
                            referrer_id,
                            "🎉 Referral Bonus!",
                            f"You earned {bonus_amount:.2f} NGN for referring a friend who completed their first transaction!",
                            "success",
                        )
                        bonus_applied = True

                # Credit referred user
                referred_bonus = promo_result.get("referred", {})
                if referred_bonus.get("bonus_value", 0) > 0:
                    if referred_bonus.get("bonus_type") == "percentage":
                        tx = (
                            db.get_transaction(transaction_ref)
                            if transaction_ref
                            else None
                        )
                        if tx:
                            amount = float(tx.get("amount", 0))
                            bonus_amount = amount * (
                                referred_bonus["bonus_value"] / 100
                            )
                        else:
                            bonus_amount = 0
                    else:
                        bonus_amount = float(referred_bonus["bonus_value"])

                    if bonus_amount > 0:
                        db.credit_wallet(
                            user_id=user_id,
                            amount=bonus_amount,
                            description=f'Welcome bonus from referral: {referral["referrer_code"]}',
                            reference=f'WELCOME-{referral["id"]}',
                            currency="NGN",
                        )
                        db.create_notification(
                            user_id,
                            "🎉 Welcome Bonus!",
                            f"You received {bonus_amount:.2f} NGN as a welcome bonus for signing up with a referral!",
                            "success",
                        )
                        bonus_applied = True

            conn.close()

            return jsonify(
                {
                    "success": True,
                    "message": "Referral completed successfully!",
                    "bonuses_applied": bonus_applied,
                }
            )

        @self.app.route("/api/referral/stats", methods=["GET"])
        @login_required
        def get_referral_stats():
            """Get referral statistics for the current user."""
            user_id = g.current_user_id
            stats = db.get_referral_stats(user_id)
            referrals = db.get_referrals(user_id)

            # Calculate total earnings from referrals
            total_earnings = 0
            conn = db.get_db_connection()
            c = conn.cursor()
            for ref in referrals:
                if ref.get("status") == "completed":
                    # Get bonus transactions
                    bonus_tx = c.execute(
                        """
                        SELECT SUM(amount) as total 
                        FROM wallet_transactions 
                        WHERE user_id = ? AND description LIKE '%Referral%'
                        """,
                        (user_id,),
                    ).fetchone()
                    if bonus_tx and bonus_tx["total"]:
                        total_earnings += float(bonus_tx["total"])
            conn.close()

            return jsonify(
                {
                    "success": True,
                    "stats": {
                        "total": stats.get("total", 0),
                        "completed": stats.get("completed", 0),
                        "pending": stats.get("pending", 0),
                        "total_earnings": total_earnings,
                    },
                    "referrals": referrals,
                }
            )

        # ============ REFERRAL SYSTEM API ROUTES ============

        @self.app.route("/api/referral/status", methods=["GET"])
        @login_required
        def get_referral_status():
            """Check if the user has an active referral."""
            user_id = g.current_user_id

            conn = db.get_db_connection()
            c = conn.cursor()
            referral = c.execute(
                """
                SELECT r.*, u.full_name as referrer_name, u.email as referrer_email
                FROM referrals r
                JOIN users u ON u.id = r.referrer_id
                WHERE r.referred_id = ? AND r.status = 'pending'
                ORDER BY r.created_at DESC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()
            conn.close()

            if referral:
                return jsonify(
                    {"success": True, "has_referral": True, "referral": dict(referral)}
                )

            return jsonify({"success": True, "has_referral": False})

        # ============ EXCHANGE RATE API ENDPOINTS ============
        @self.app.route("/api/exchange-rates", methods=["GET"])
        def get_exchange_rates():
            try:
                rates = {
                    "NGN": ExchangeRateService.get_ngn_to_usd(),
                    "USD": 1.0,
                    "GBP": ExchangeRateService.get_rate("GBP"),
                    "EUR": ExchangeRateService.get_rate("EUR"),
                    "GHS": ExchangeRateService.get_rate("GHS"),
                    "KES": ExchangeRateService.get_rate("KES"),
                    "ZAR": ExchangeRateService.get_rate("ZAR"),
                    "timestamp": datetime.now().isoformat(),
                    "last_update": (
                        ExchangeRateService._last_update.isoformat()
                        if ExchangeRateService._last_update
                        else None
                    ),
                    "source": (
                        "live" if ExchangeRateService._last_success else "fallback"
                    ),
                    "update_count": ExchangeRateService._update_count,
                }
                return jsonify(
                    {
                        "success": True,
                        "rates": rates,
                        "base_currency": "USD",
                        "update_interval": ExchangeRateService._update_interval,
                    }
                )
            except Exception as e:
                logger.error(f"Error fetching exchange rates: {e}")
                return jsonify(
                    {
                        "success": False,
                        "error": str(e),
                        "rates": {
                            "NGN": 1900.0,
                            "USD": 1.0,
                            "GBP": 1.25,
                            "EUR": 1.08,
                            "timestamp": datetime.now().isoformat(),
                            "source": "fallback",
                        },
                    }
                )

        @self.app.route("/api/exchange-rates/refresh", methods=["POST"])
        @login_required
        def refresh_exchange_rates():
            user = g.current_user
            admin_email = os.getenv("ADMIN_EMAIL", "admin@net365.com")
            if user.get("email") != admin_email:
                return (
                    jsonify({"success": False, "error": "Admin access required"}),
                    403,
                )

            try:
                success = ExchangeRateService.force_refresh()
                status = ExchangeRateService.get_status()
                return jsonify(
                    {
                        "success": success,
                        "status": status,
                        "message": (
                            "Exchange rates refreshed successfully"
                            if success
                            else "Refresh failed, using fallback rates"
                        ),
                    }
                )
            except Exception as e:
                logger.error(f"Error refreshing exchange rates: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/exchange-rates/status", methods=["GET"])
        def get_exchange_rate_status():
            try:
                status = ExchangeRateService.get_status()
                return jsonify({"success": True, "status": status})
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/payment/success")
        def payment_success():
            """Landing page after a successful gateway payment.

            Renders a full-screen, ad-supported success page so the user can
            confirm their payment, see the receipt, and view a rich advertiser
            placement — separately configured from receipt ads.
            """
            frontend_url = FRONTEND_URL
            reference = (
                request.args.get("reference")
                or request.args.get("session_id")
                or request.args.get("trxref")
            )
            try:
                if not reference:
                    return redirect(frontend_url)

                logger.info(f"Payment success callback received: reference={reference}")

                # Stripe returns cs_... — resolve to our internal reference
                stripe_session_id = None
                if reference.startswith("cs_") or reference.startswith("cs_test_"):
                    stripe_session_id = reference
                    tx = self._find_transaction_by_stripe_session(reference)
                    if tx:
                        reference = tx["reference"]
                        try:
                            payload = tx.get("payload", {})
                            if isinstance(payload, str):
                                payload = json.loads(payload) if payload else {}
                            payload["stripe_session_id"] = stripe_session_id
                            conn = db.get_db_connection()
                            c = conn.cursor()
                            c.execute(
                                "UPDATE transactions SET payload = ? WHERE reference = ?",
                                (json.dumps(payload), reference),
                            )
                            conn.commit()
                        except Exception as e:
                            logger.error(f"Failed to persist Stripe session ID: {e}")

                # Finalize the transaction (idempotent — safe to re-run)
                try:
                    result = self._finalize_transaction(reference)
                except Exception as e:
                    logger.error(f"payment_success finalize error: {e}")
                    result = {"success": False, "error": str(e)}

                # Fetch transaction for the success page template
                tx = db.get_transaction(reference) or {}
                if tx.get("payload") and isinstance(tx["payload"], str):
                    try:
                        tx["payload"] = json.loads(tx["payload"])
                    except Exception:
                        pass

                # ---- display mode: "pro" (adults, default) or "play" (kids) --------------------
                mode = request.args.get("mode") or request.cookies.get("n365_mode") or "pro"
                mode = mode if mode in ("pro", "play") else "pro"

                # ---- what was recharged: decrypt the payload and find the recipient number -------
                recipient_masked = None
                airtime_value = None
                try:
                    _p = tx.get("payload")
                    if isinstance(_p, str):
                        _p = json.loads(_p) if _p else {}
                    _p = decrypt_payload(dict(_p or {}))
                    _num = None
                    for _k in ("phone", "recipient_phone", "recipient", "phone_number", "msisdn", "number"):
                        if _p.get(_k):
                            _num = str(_p[_k])
                            break
                    if not _num:
                        _rr = tx.get("reloadly_result")
                        if isinstance(_rr, str):
                            _rr = json.loads(_rr) if _rr else {}
                        _rr = _rr or {}
                        _rp = _rr.get("recipientPhone") or (_rr.get("result") or {}).get("recipientPhone") or {}
                        _num = _rp.get("number") if isinstance(_rp, dict) else _rp
                    if _num:
                        _digits = "".join(ch for ch in str(_num) if ch.isdigit())
                        if _digits.startswith("234") and len(_digits) == 13:
                            _digits = "0" + _digits[3:]
                        if len(_digits) >= 8:
                            recipient_masked = _digits[:4] + "•" * max(3, len(_digits) - 8) + _digits[-4:]
                    if _p.get("service_amount"):
                        airtime_value = float(_p["service_amount"])
                except Exception as e:
                    logger.warning(f"Success page: could not read recipient: {e}")

                # Pick the best success-page ad for this transaction
                ad = None
                ads = {}
                device_type = None
                try:
                    device_type = parse_user_agent(request.headers.get("User-Agent", ""))["device_type"]
                    ads = db.get_receipt_ads(
                        tx_type=tx.get("tx_type"),
                        country=get_request_country(request),
                        amount=float(tx.get("amount") or 0) or None,
                        device_type=device_type,
                    )
                    if mode == "play":
                        # Play mode shows house content only: no paid/third-party ads in front of
                        # children, and no impressions are billed for ads that are not shown.
                        ads = {k: (v if v and not v.get("sponsored") else None) for k, v in (ads or {}).items()}

                    # Track an impression for whichever slots actually resolved
                    for _slot_name in ("primary", "secondary", "tertiary"):
                        _ad = ads.get(_slot_name)
                        if _ad:
                            try:
                                db.record_success_page_ad_event(
                                    _ad["id"], "impression",
                                    reference=reference,
                                    user_id=tx.get("user_id"),
                                    device_type=device_type,
                                    country=get_request_country(request),
                                )
                                try:
                                    from net365_adengine import record_event as _ae_rec
                                    _ae_rec("success", "success", _ad["id"], "impression", reference=reference,
                                            user_id=tx.get("user_id"), tx_type=tx.get("tx_type"),
                                            amount=tx.get("amount"), country=get_request_country(request),
                                            device=device_type)
                                except Exception:
                                    pass
                            except Exception as e:
                                logger.warning(f"Impression tracking failed for {_slot_name}: {e}")
                    if ad:
                        db.record_success_page_ad_event(
                            ad["id"], "impression",
                            reference=reference,
                            user_id=tx.get("user_id"),
                            device_type=device_type,
                            country=get_request_country(request),
                        )
                except Exception as e:
                    logger.warning(f"Success-page ad lookup failed: {e}")

                # Paid campaigns (if admin allows) and Boost ads fill the slots that are still free.
                try:
                    if mode != "play":
                        from net365_adcredits import fill_success_slots, viewer_city
                        _uid = tx.get("user_id")
                        ads = fill_success_slots(ads, {
                            "reference": reference, "user_id": _uid, "tx_type": tx.get("tx_type"),
                            "amount": tx.get("amount"), "city": viewer_city(_uid, get_client_ip())})
                except Exception as e:
                    logger.warning(f"Boost/paid slot fill failed: {e}")

                # ---- rewards (server-side only; never from the browser) --------------------------
                rewards = None
                headlines = []
                try:
                    import net365_rewards as _rw
                    award = _rw.award_for_transaction(tx)
                    if tx.get("user_id"):
                        rewards = _rw.summary(int(tx["user_id"]))
                        rewards["award"] = award
                    headlines = _rw.get_headlines("kids" if mode == "play" else "pro", 5)
                except Exception as e:
                    logger.warning(f"Rewards lookup failed: {e}")

                resp = make_response(render_template(
                    "payment_success.html",
                    reference=reference,
                    tx=tx,
                    ads=ads,
                    frontend_url=frontend_url,
                    result=result,
                    mode=mode,
                    rewards=rewards,
                    headlines=headlines,
                    recipient_masked=recipient_masked,
                    airtime_value=airtime_value,
                ))
                if request.args.get("mode") in ("pro", "play"):
                    resp.set_cookie("n365_mode", mode, max_age=60 * 60 * 24 * 365, samesite="Lax",
                                    secure=request.is_secure, httponly=True)
                return resp

            except Exception as e:
                logger.error(f"payment_success crashed for reference={reference}: {e}")
                import traceback
                logger.error(traceback.format_exc())
                return redirect(f"{frontend_url}/?status=success&reference={reference or ''}")


        @self.app.route("/api/success-ad/<int:ad_id>/click", methods=["POST"])
        def success_ad_click(ad_id):
            """Track a click on a success-page ad."""
            data = request.get_json(silent=True) or {}
            try:
                db.record_success_page_ad_event(
                    ad_id, data.get("event") or "click",
                    reference=data.get("reference"),
                    user_id=session.get("user_id"),
                    device_type=parse_user_agent(request.headers.get("User-Agent", ""))["device_type"],
                    country=get_request_country(request),
                )
                try:
                    if (data.get("event") or "click") == "click":
                        from net365_adengine import record_event as _ae_rec
                        _ae_rec("success", "success", ad_id, "click", reference=data.get("reference"),
                                user_id=session.get("user_id"), country=get_request_country(request),
                                device=parse_user_agent(request.headers.get("User-Agent", ""))["device_type"])
                except Exception:
                    pass
                return jsonify({"success": True})
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 500








        @self.app.route("/payment/cancel")
        def payment_cancel():
            reference = request.args.get("reference") or request.args.get("session_id")
            frontend_url = FRONTEND_URL
            return redirect(f"{frontend_url}/?status=cancelled&reference={reference}")



        @self.app.route("/payment/callback", methods=["GET"])
        def payment_callback():
            reference = (
                request.args.get("reference")
                or request.args.get("trxref")
                or request.args.get("session_id")
            )

            return_url = _safe_payment_return_url(
                request.args.get("return_url")
            )

            try:
                if not reference:
                    return redirect(
                        f"{return_url}?status=error"
                    )

                separator = "&" if "?" in return_url else "?"

                return redirect(
                    f"{return_url}"
                    f"{separator}"
                    f"status=processing"
                    f"&reference={reference}"
                )

            except Exception as e:
                logger.error(
                    f"payment_callback crashed for reference={reference}: {e}"
                )

                return redirect(
                    f"{FRONTEND_URL}/?status=error"
                )



        
        
        # ============ WEBHOOK ROUTES ============
        @self.app.route("/webhooks/paystack", methods=["POST"])
        def paystack_webhook():
            raw_body = request.get_data()
            signature = request.headers.get("x-paystack-signature", "")

            logger.info(f"Paystack webhook received, signature: {signature[:20]}...")

            if not verify_paystack_signature(raw_body, signature):
                logger.warning("Paystack webhook: Invalid signature")
                return jsonify({"error": "invalid signature"}), 401

            data = request.get_json(silent=True) or {}
            event = data.get("event")
            event_data = data.get("data", {})
            reference = event_data.get("reference")

            logger.info(f"Paystack webhook: event={event}, reference={reference}")

            if event == "charge.success" and reference:
                webhook_id = str(event_data.get("id") or reference)
                if db.has_processed_webhook(webhook_id):
                    logger.info(f"Paystack webhook {webhook_id} already processed")
                    return jsonify({"status": "already processed"}), 200

                db.record_webhook(webhook_id, reference)
                result = self._finalize_transaction(reference)
                logger.info(
                    f"Paystack webhook fulfillment result: {result.get('success')}"
                )

                if result.get("success"):
                    return jsonify({"status": "ok"}), 200
                else:
                    logger.error(
                        f"Paystack webhook fulfillment failed: {result.get('error')}"
                    )
                    return (
                        jsonify(
                            {
                                "status": "fulfillment_failed",
                                "error": result.get("error"),
                            }
                        ),
                        200,
                    )

            return jsonify({"status": "ignored"}), 200

        @self.app.route("/webhooks/flutterwave", methods=["POST"])
        def flutterwave_webhook():
            signature = request.headers.get("verif-hash", "")
            if not verify_flutterwave_signature(request.get_data(), signature):
                return jsonify({"error": "invalid signature"}), 401

            data = request.get_json(silent=True) or {}
            event_data = data.get("data", {})
            reference = event_data.get("tx_ref")
            status = event_data.get("status") or data.get("status")

            if status == "successful" and reference:
                webhook_id = str(event_data.get("id") or reference)
                if db.has_processed_webhook(webhook_id):
                    return jsonify({"status": "already processed"}), 200
                db.record_webhook(webhook_id, reference)
                result = self._finalize_transaction(reference)
                logger.info(f"Flutterwave webhook fulfillment: {result.get('success')}")
                return jsonify({"status": "ok"}), 200

            return jsonify({"status": "ignored"}), 200

        @self.app.route("/webhooks/stripe", methods=["POST"])
        def stripe_webhook():
            if not STRIPE_AVAILABLE:
                logger.error("Stripe library not available, cannot process webhook")
                return jsonify({"error": "Stripe not configured"}), 500

            # Fail closed: an unsigned webhook is never processed. Without the signing secret we
            # cannot tell Stripe from anyone else on the internet.
            webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
            if not webhook_secret:
                logger.error("Stripe webhook secret is not configured; rejecting webhook")
                return jsonify({"error": "Webhook not configured"}), 503

            payload = request.get_data()  # raw bytes — the signature is computed over the exact body
            sig_header = request.headers.get("Stripe-Signature")
            if not sig_header:
                return jsonify({"error": "Missing signature"}), 400

            _sig_error = getattr(stripe, "SignatureVerificationError", None) or getattr(
                getattr(stripe, "error", None), "SignatureVerificationError", Exception
            )
            try:
                stripe.Webhook.construct_event(payload, sig_header, webhook_secret)  # verifies signature + timestamp
                # Use the verified raw body as a plain dict. Newer stripe-python versions return an
                # Event object without dict.get(), which this handler relies on.
                event = json.loads(payload)
            except ValueError as e:
                logger.error(f"Invalid Stripe webhook payload: {e}")
                return jsonify({"error": "Invalid payload"}), 400
            except _sig_error as e:
                logger.error(f"Invalid Stripe signature: {e}")
                return jsonify({"error": "Invalid signature"}), 400

            logger.info(f"Stripe webhook received: type={event.get('type')}")

            _etype = event.get("type")
            if _etype == "checkout.session.async_payment_failed":
                logger.warning("Stripe async payment failed: %s" % (event.get("data", {}).get("object", {}).get("id")))
                return jsonify({"status": "noted"}), 200
            if _etype in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
                session_obj = event.get("data", {}).get("object", {})
                session_id = session_obj.get("id")
                if session_obj.get("payment_status") not in ("paid", "no_payment_required"):
                    # Delayed payment method (bank debit etc.): the session completed but money has not
                    # arrived. Do nothing now; Stripe sends async_payment_succeeded when it does.
                    logger.info(f"Stripe session {session_id} completed but payment_status="
                                f"{session_obj.get('payment_status')}; waiting for async_payment_succeeded")
                    return jsonify({"status": "awaiting payment"}), 200
                metadata = session_obj.get("metadata", {})
                reference = metadata.get("reference")

                logger.info(
                    f"Stripe checkout completed: session_id={session_id}, reference={reference}"
                )

                if reference:
                    webhook_id = str(session_obj.get("id") or reference)
                    if db.has_processed_webhook(webhook_id):
                        return jsonify({"status": "already processed"}), 200
                    db.record_webhook(webhook_id, reference)

                    tx = db.get_transaction(reference)
                    if tx and tx.get("payload"):
                        try:
                            payload_dict = (
                                json.loads(tx["payload"])
                                if isinstance(tx["payload"], str)
                                else tx["payload"]
                            )
                            # Never overwrite a session id we already stored when the payment was created.
                            if payload_dict.get("stripe_session_id") and payload_dict.get("stripe_session_id") != session_id:
                                logger.error(
                                    f"Stripe webhook session mismatch for {reference}: stored="
                                    f"{payload_dict.get('stripe_session_id')} event={session_id}; ignoring event"
                                )
                                return jsonify({"status": "ignored"}), 200
                            payload_dict["stripe_session_id"] = session_id
                            conn = db.get_db_connection()
                            c = conn.cursor()
                            c.execute(
                                "UPDATE transactions SET payload = ? WHERE reference = ?",
                                (json.dumps(payload_dict), reference),
                            )
                            conn.commit()
                            logger.info(
                                f"Updated transaction {reference} with Stripe session ID {session_id}"
                            )
                        except Exception as e:
                            logger.error(f"Failed to update transaction: {e}")

                    result = self._finalize_transaction(reference)
                    logger.info(f"Stripe webhook fulfillment: {result.get('success')}")
                else:
                    tx = self._find_transaction_by_stripe_session(session_id)
                    if tx:
                        reference = tx["reference"]
                        webhook_id = str(session_obj.get("id") or reference)
                        if db.has_processed_webhook(webhook_id):
                            return jsonify({"status": "already processed"}), 200
                        db.record_webhook(webhook_id, reference)
                        result = self._finalize_transaction(reference)
                        logger.info(
                            f"Stripe webhook fulfillment (by session): {result.get('success')}"
                        )

            return jsonify({"status": "success"}), 200

        # ============ PAUSE/RESUME SCHEDULE ROUTES ============
        @self.app.route(
            "/api/scheduler/schedules/<schedule_id>/pause", methods=["POST"]
        )
        @login_required
        def pause_schedule(schedule_id):
            user_id = g.current_user_id

            try:
                conn = db.get_db_connection()
                c = conn.cursor()

                schedule = c.execute(
                    "SELECT name, status FROM scheduler_schedules WHERE id = ? AND user_id = ?",
                    (schedule_id, user_id),
                ).fetchone()

                if not schedule:
                    return (
                        jsonify({"success": False, "error": "Schedule not found"}),
                        404,
                    )

                if schedule["status"] == "paused":
                    return (
                        jsonify(
                            {"success": False, "error": "Schedule is already paused"}
                        ),
                        400,
                    )

                c.execute(
                    """
                    UPDATE scheduler_schedules 
                    SET status = 'paused', updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND user_id = ?
                """,
                    (schedule_id, user_id),
                )
                conn.commit()

                log_event(
                    user_id=user_id,
                    event_type="schedule_paused",
                    details={"schedule_id": schedule_id, "name": schedule["name"]},
                    status="success",
                )

                db.create_notification(
                    user_id,
                    "⏸️ Schedule Paused",
                    f'Schedule "{schedule["name"]}" has been paused.',
                    "info",
                )

                return jsonify(
                    {
                        "success": True,
                        "message": "Schedule paused successfully",
                        "status": "paused",
                    }
                )

            except Exception as e:
                logger.error(f"Error pausing schedule: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route(
            "/api/scheduler/schedules/<schedule_id>/resume", methods=["POST"]
        )
        @login_required
        def resume_schedule(schedule_id):
            user_id = g.current_user_id

            try:
                conn = db.get_db_connection()
                c = conn.cursor()

                schedule = c.execute(
                    "SELECT name, status, frequency, day_of_month, day_of_week, month, time, event_date, timezone FROM scheduler_schedules WHERE id = ? AND user_id = ?",
                    (schedule_id, user_id),
                ).fetchone()

                if not schedule:
                    return (
                        jsonify({"success": False, "error": "Schedule not found"}),
                        404,
                    )

                if schedule["status"] != "paused":
                    return (
                        jsonify({"success": False, "error": "Schedule is not paused"}),
                        400,
                    )

                next_run = calculate_next_run(
                    schedule["frequency"],
                    schedule.get("day_of_month", 1),
                    schedule.get("time", "09:00"),
                    schedule.get("day_of_week", 0),
                    schedule.get("month", 1),
                    schedule.get("event_date"),
                    schedule.get("timezone") or "Africa/Lagos",
                )

                c.execute(
                    """
                    UPDATE scheduler_schedules 
                    SET status = 'active', next_run = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND user_id = ?
                """,
                    (next_run, schedule_id, user_id),
                )
                conn.commit()

                log_event(
                    user_id=user_id,
                    event_type="schedule_resumed",
                    details={
                        "schedule_id": schedule_id,
                        "name": schedule["name"],
                        "next_run": next_run,
                    },
                    status="success",
                )

                db.create_notification(
                    user_id,
                    "▶️ Schedule Resumed",
                    f'Schedule "{schedule["name"]}" has been resumed. Next run: {next_run}',
                    "success",
                )

                return jsonify(
                    {
                        "success": True,
                        "message": "Schedule resumed successfully",
                        "status": "active",
                        "next_run": next_run,
                    }
                )

            except Exception as e:
                logger.error(f"Error resuming schedule: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        # ============ ANALYTICS DASHBOARD ============
        # ============ ANALYTICS DASHBOARD ============
        # ============ ANALYTICS DASHBOARD ============
        @self.app.route("/api/analytics/dashboard", methods=["GET"])
        @login_required
        def analytics_dashboard():
            user_id = g.current_user_id

            try:
                conn = db.get_db_connection()
                c = conn.cursor()

                # Get all schedules for this user
                schedules = c.execute(
                    "SELECT * FROM scheduler_schedules WHERE user_id = ?", (user_id,)
                ).fetchall()

                # Get transactions
                transactions = c.execute(
                    "SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 100",
                    (user_id,),
                ).fetchall()

                # Get wallets
                wallets = c.execute(
                    "SELECT * FROM wallets WHERE user_id = ?", (user_id,)
                ).fetchall()

                # ============================================================
                # FIX: Convert sqlite3.Row to dict for all records
                # ============================================================
                schedules = [dict(s) for s in schedules]
                transactions = [dict(t) for t in transactions]
                wallets = [dict(w) for w in wallets]

                # Calculate summary stats
                total_schedules = len(schedules)
                active_schedules = len(
                    [s for s in schedules if s.get("status") == "active"]
                )
                completed_schedules = len(
                    [s for s in schedules if s.get("status") == "completed"]
                )
                paused_schedules = len(
                    [s for s in schedules if s.get("status") == "paused"]
                )
                failed_schedules = len(
                    [s for s in schedules if s.get("status") == "failed"]
                )
                pending_schedules = len(
                    [
                        s
                        for s in schedules
                        if s.get("status") == "pending" or s.get("status") == "queued"
                    ]
                )

                total_spent = 0
                monthly_spent = 0
                current_month = datetime.now().month
                current_year = datetime.now().year

                for tx in transactions:
                    amount = float(tx.get("amount", 0))
                    total_spent += amount

                    created_at = tx.get("created_at")
                    if created_at:
                        try:
                            dt = datetime.fromisoformat(
                                created_at.replace("Z", "+00:00")
                            )
                            if dt.month == current_month and dt.year == current_year:
                                monthly_spent += amount
                        except:
                            pass

                # Count by department
                dept_counts = {}
                for s in schedules:
                    dept = s.get("department") or "General"
                    dept_counts[dept] = dept_counts.get(dept, 0) + 1
                top_departments = sorted(
                    [{"name": k, "count": v} for k, v in dept_counts.items()],
                    key=lambda x: x["count"],
                    reverse=True,
                )[:10]

                # Count by operator
                operator_counts = {}
                for s in schedules:
                    op = s.get("operator_name") or s.get("operator_id") or "Unknown"
                    if op:
                        operator_counts[op] = operator_counts.get(op, 0) + 1
                top_operators = sorted(
                    [{"name": k, "count": v} for k, v in operator_counts.items()],
                    key=lambda x: x["count"],
                    reverse=True,
                )[:10]

                # Format wallets
                wallet_list = []
                for w in wallets:
                    wallet_list.append(
                        {
                            "currency": w.get("currency", "NGN"),
                            "balance": float(w.get("balance", 0)),
                        }
                    )

                # If no wallets exist, add default NGN wallet
                if not wallet_list:
                    wallet_list.append({"currency": "NGN", "balance": 0.0})

                # Format transactions
                tx_list = []
                for tx in transactions:
                    tx_list.append(
                        {
                            "id": tx.get("id"),
                            "reference": tx.get("reference"),
                            "amount": float(tx.get("amount", 0)),
                            "currency": tx.get("currency", "NGN"),
                            "status": tx.get("status", "pending"),
                            "tx_type": tx.get("tx_type", "unknown"),
                            "created_at": tx.get("created_at"),
                            "provider": tx.get("provider"),
                        }
                    )

                conn.close()

                return jsonify(
                    {
                        "success": True,
                        "data": {
                            "summary": {
                                "total_schedules": total_schedules,
                                "active_schedules": active_schedules,
                                "completed_schedules": completed_schedules,
                                "paused_schedules": paused_schedules,
                                "failed_schedules": failed_schedules,
                                "pending_schedules": pending_schedules,
                                "total_spent": total_spent,
                                "monthly_spent": monthly_spent,
                            },
                            "wallets": wallet_list,
                            "top_departments": top_departments,
                            "top_operators": top_operators,
                            "recent_transactions": tx_list[:10],
                        },
                    }
                )

            except Exception as e:
                logger.error(f"Analytics error: {e}", exc_info=True)
                return jsonify({"success": False, "error": str(e)}), 500

                # ============ SETTINGS API ============

        @self.app.route("/api/settings", methods=["GET"])
        @login_required
        def get_settings():
            """Get user settings."""
            user_id = g.current_user_id

            try:
                settings = db.get_settings(user_id)
                if not settings:
                    # Return default settings if none exist
                    return jsonify(
                        {
                            "success": True,
                            "settings": {
                                "notifications_enabled": True,
                                "email_notifications": True,
                                "sms_notifications": False,
                                "theme": "light",
                                "language": "en",
                                "currency": "NGN",
                                "sms_config": None,
                            },
                        }
                    )
                return jsonify({"success": True, "settings": settings})
            except Exception as e:
                logger.error(f"Error fetching settings: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/settings", methods=["PUT"])
        @login_required
        def update_settings():
            """Update user settings."""
            user_id = g.current_user_id
            data = request.json or {}

            try:
                # Only update allowed fields
                allowed_fields = [
                    "notifications_enabled",
                    "email_notifications",
                    "sms_notifications",
                    "theme",
                    "language",
                    "currency",
                    "sms_config",
                ]
                updates = {k: v for k, v in data.items() if k in allowed_fields}

                if not updates:
                    return (
                        jsonify(
                            {"success": False, "error": "No valid fields to update"}
                        ),
                        400,
                    )

                result = db.update_settings(user_id, **updates)

                if result:
                    return jsonify(
                        {"success": True, "message": "Settings updated successfully"}
                    )
                else:
                    return (
                        jsonify(
                            {"success": False, "error": "Failed to update settings"}
                        ),
                        500,
                    )
            except Exception as e:
                logger.error(f"Error updating settings: {e}")
                return jsonify({"success": False, "error": str(e)}), 500
                
                
    
 
        # ============ API ROUTES ============
        @self.app.route("/api/payment/verify/<reference>", methods=["GET"])
        @login_required
        def verify_payment(reference):
            user_id = g.current_user_id
            tx, error = require_owned_transaction(reference, user_id)
            if error:
                return error

            result = self._finalize_transaction(reference)

            response_data = {
                "reference": reference,
                "success": result.get("success", False),
                "status": "success" if result.get("success") else "pending",
                "already_fulfilled": result.get("already_fulfilled", False),
                "pending": bool(result.get("pending")),
            }

            if result.get("success"):
                response_data["fulfillment"] = result.get("result", {})
                wallet = db.get_wallet(user_id)
                response_data["wallet_balance"] = (
                    wallet.get("balance", 0) if wallet else 0
                )
            else:
                response_data["error"] = result.get(
                    "error", "Payment verification failed"
                )
                response_data["detail"] = result.get("detail", {})

            return jsonify(response_data)

        # ============ ONEPAY: ONE PAYMENT, MANY DELIVERIES ============
        CART_MAX_ITEMS = int(os.getenv("CART_MAX_ITEMS", "10") or 10)

        @self.app.route("/api/cart/checkout", methods=["POST"])
        @login_required
        @email_verified_required
        @rate_limit(max_requests=10, window_seconds=60)
        def cart_checkout():
            data = request.get_json(silent=True) or {}
            user_id = g.current_user_id
            raw_items = data.get("items")
            if not isinstance(raw_items, list) or not raw_items:
                return jsonify({"success": False, "error": "Your cart is empty"}), 400
            if len(raw_items) > CART_MAX_ITEMS:
                return jsonify({"success": False, "error": f"A cart can hold up to {CART_MAX_ITEMS} items"}), 400
            if str(data.get("provider") or "paystack").lower() != "paystack" or str(data.get("currency") or "NGN").upper() != "NGN":
                return jsonify({"success": False, "error": "OnePay currently supports Nigerian Naira by card or bank transfer (Paystack)."}), 400
            try:
                from net365_whatsapp import is_guest_user
                if is_guest_user(user_id):
                    return jsonify({"success": False, "error": "Create a free Net365 account to use OnePay."}), 403
            except Exception:
                pass

            payer_email = data.get("email") or g.current_user.get("email")
            min_amount = SUPPORTED_CURRENCIES["NGN"]["min_amount"]
            items, summary, has_utility = [], [], False

            for n_, raw in enumerate(raw_items, 1):
                if not isinstance(raw, dict):
                    return jsonify({"success": False, "error": f"Item {n_} is invalid"}), 400
                kind = str(raw.get("type") or "topup").lower()
                try:
                    service = round(float(raw.get("amount")), 2)  # what the recipient/biller receives
                except (TypeError, ValueError):
                    return jsonify({"success": False, "error": f"Item {n_}: invalid amount"}), 400
                if service <= 0:
                    return jsonify({"success": False, "error": f"Item {n_}: invalid amount"}), 400

                if kind == "topup":
                    operator_id, phone = raw.get("operator_id"), str(raw.get("phone") or "").strip()
                    if not operator_id or not phone:
                        return jsonify({"success": False, "error": f"Item {n_}: missing network or phone number"}), 400
                    if not self.platform._format_phone_for_topup(phone, "NG"):
                        return jsonify({"success": False, "error": f"Item {n_}: invalid Nigerian phone number"}), 400
                    fee = server_fee_for(service, "NGN")  # the SERVER owns the fee; any client total is ignored
                    total = round(service + fee, 2)
                    if total < min_amount:
                        return jsonify({"success": False, "error": f"Item {n_}: minimum is NGN {min_amount}"}), 400
                    label = f"{str(raw.get('operator_name') or 'Airtime')[:30]} airtime - {phone[-4:].rjust(len(phone), '*')}"
                    item_payload = {
                        "operator_id": str(operator_id), "phone": encrypt_pii(phone), "country_code": "NG",
                        "email": payer_email, "service_amount": service, "fee_amount": fee,
                        "operator_name": str(raw.get("operator_name") or "")[:40],
                    }
                elif kind == "utility":
                    has_utility = True
                    account = str(raw.get("subscriber_account") or "").strip()
                    try:
                        biller_id = int(raw.get("biller_id"))
                    except (TypeError, ValueError):
                        return jsonify({"success": False, "error": f"Item {n_}: invalid biller"}), 400
                    if not account:
                        return jsonify({"success": False, "error": f"Item {n_}: missing account/meter number"}), 400
                    check = UtilityBillerValidator.validate_amount(biller_id, service)
                    if not check.get("valid", True):  # never silently change what the customer is paying
                        return jsonify({"success": False, "error": f"Item {n_}: {check.get('message')}"}), 400
                    fee, total = 0.0, service
                    label = f"{str(raw.get('biller_name') or 'Bill payment')[:40]}"
                    item_payload = {
                        "biller_id": biller_id, "subscriber_account": encrypt_pii(account), "amount": service,
                        "currency": "NGN", "email": payer_email, "payment_method": "cart",
                        "service_amount": service, "fee_amount": 0.0,
                        "biller_name": str(raw.get("biller_name") or "")[:60],
                    }
                else:
                    return jsonify({"success": False, "error": f"Item {n_}: unsupported type '{kind}'"}), 400

                items.append({"type": kind, "label": label, "amount": total, "payload": item_payload})
                summary.append({"type": kind, "label": label, "service_amount": service, "fee": fee, "total": total})

            cart_total = round(sum(i["amount"] for i in items), 2)

            try:  # frozen account / PIN step-up above the configured amount (same check as single payments)
                from net365_whatsapp import chat_purchase_error
                _ce = chat_purchase_error(user_id, cart_total, "NGN")
                if _ce:
                    return jsonify(_ce[0]), _ce[1]
            except ImportError:
                pass

            # Per-transaction cap applies to each delivery; the daily cap applies to the whole cart.
            _limit_err = _purchase_limit_error(user_id, cart_total, "NGN", per_tx_amount=max(i["amount"] for i in items))
            if _limit_err:
                return jsonify({"success": False, "code": "LIMIT_EXCEEDED", "error": _limit_err}), 400
            if has_utility and _utility_provider_down():
                return jsonify({"success": False, "code": "PROVIDER_UNAVAILABLE",
                                "error": "Bill payments are temporarily unavailable. You have not been charged. "
                                         "Remove the bill items or try again in a few minutes."}), 503

            result = self.platform.create_payment(
                amount=cart_total, currency="NGN", email=payer_email,
                return_url=_safe_payment_return_url(data.get("return_url")), provider="paystack",
            )
            if not (result.get("success") and result.get("reference")):
                return jsonify(result if isinstance(result, dict) else {"success": False, "error": "Could not start payment"}), 502

            db.create_pending(
                reference=result["reference"], tx_type="cart", provider="paystack", amount=cart_total,
                currency="NGN", payload={"items": items, "email": payer_email, "item_count": len(items)},
                user_id=user_id,
            )
            log_event(user_id=user_id, event_type="cart_checkout_initiated",
                      details={"reference": result["reference"], "items": len(items), "amount": cart_total},
                      status="pending")
            return jsonify({
                "success": True, "reference": result["reference"], "amount": cart_total, "currency": "NGN",
                "authorization_url": result.get("authorization_url") or result.get("checkout_url"),
                "items": summary,
            })

        @self.app.route("/api/cart/<reference>", methods=["GET"])
        @login_required
        def cart_status(reference):
            parent = db.get_transaction(reference)
            if not parent or parent.get("tx_type") != "cart" or parent.get("user_id") != g.current_user_id:
                return jsonify({"success": False, "error": "Cart not found"}), 404
            payload = parent.get("payload") or {}
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except Exception:
                    payload = {}
            rows = []
            for idx, it in enumerate(payload.get("items") or [], 1):
                ref = f"{reference}-{idx}"
                child = db.get_transaction(ref)
                st = (child or {}).get("status")
                state = ("delivered" if st == "fulfilled"
                         else "failed" if st in ("fulfillment_failed", "failed")
                         else "processing" if child else "awaiting_payment")
                rows.append({"reference": ref, "type": it.get("type"), "label": it.get("label"),
                             "amount": it.get("amount"), "state": state})
            pstatus = parent.get("status")
            if pstatus != "fulfilled":
                overall = "failed" if pstatus in ("fulfillment_failed", "failed") else "awaiting_payment"
            else:
                states = {r["state"] for r in rows}
                overall = ("completed" if states == {"delivered"} else
                           "failed" if states <= {"failed"} else
                           "partially_completed" if "failed" in states and "delivered" in states else
                           "processing")
                if overall == "processing" and "failed" in states and not ({"processing"} & states):
                    overall = "partially_completed"
            return jsonify({"success": True, "reference": reference, "status": overall,
                            "amount": parent.get("amount"), "currency": parent.get("currency") or "NGN",
                            "items": rows,
                            "delivered": sum(1 for r in rows if r["state"] == "delivered"),
                            "failed": sum(1 for r in rows if r["state"] == "failed")})

        # ============ FIX: /api/payment/init ENDPOINT ============
        @self.app.route("/api/payment/init", methods=["POST"])
        @login_required
        @email_verified_required
        def init_payment():
            data = request.json or {}
            amount = data.get("amount")
            currency = data.get("currency", "NGN")
            provider = data.get("provider")
            user_id = g.current_user_id

            if not amount or float(amount) <= 0:
                return jsonify({"success": False, "error": "Invalid amount"}), 400

            try:  # chat purchases: frozen account, or PIN needed above the step-up amount
                from net365_whatsapp import chat_purchase_error
                _ce = chat_purchase_error(user_id, amount, currency)
                if _ce:
                    return jsonify(_ce[0]), _ce[1]
            except ImportError:
                pass

            # Chat guests (no account): airtime top-ups by gateway only, with their own lower caps.
            _guest_email = None
            _is_guest = False
            try:
                from net365_whatsapp import is_guest_user, guest_limit_error, guest_receipt_email
                _is_guest = is_guest_user(user_id)
            except Exception:
                pass
            if _is_guest:
                if data.get("type", "topup") != "topup" or str(provider or "").lower() in ("wallet", "stripe", "flutterwave") or str(currency).upper() != "NGN":
                    return jsonify({"success": False, "error": "Guests can buy Nigerian airtime by card or bank transfer. Create a free Net365 account for more."}), 403
                _gerr = guest_limit_error(user_id, amount)
                if _gerr:
                    return jsonify({"success": False, "code": "LIMIT_EXCEEDED", "error": _gerr}), 400
                _guest_email = guest_receipt_email(user_id)
                if not _guest_email:
                    return jsonify({"success": False, "code": "EMAIL_NEEDED", "error": "An email address is needed for your receipt."}), 400
            _payer_email = _guest_email or g.current_user.get("email")

            _limit_err = _purchase_limit_error(user_id, amount, currency)
            if _limit_err:
                return jsonify({"success": False, "code": "LIMIT_EXCEEDED", "error": _limit_err}), 400

            if data.get("type") != "wallet_funding":
                if not data.get("operator_id") or not data.get("phone"):
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "Missing operator or phone number",
                            }
                        ),
                        400,
                    )
                if str(data.get("country_code") or "NG").upper() == "NG":
                    try:
                        import net365_recovery as _rc
                        _mb = _rc.maintenance_block("airtime")
                        if _mb:
                            return _mb
                    except ImportError:
                        pass
                    _mm = network_mismatch_error(data.get("phone"), data.get("operator_id"), data.get("operator_name"), bool(data.get("confirm_network")))
                    if _mm:
                        return jsonify(_mm), 409

            if currency not in SUPPORTED_CURRENCIES:
                return (
                    jsonify(
                        {"success": False, "error": f"Unsupported currency: {currency}"}
                    ),
                    400,
                )

            # ------------------------------------------------------------
            # Currency must match the destination country, not whatever the
            # client happened to send. This is the actual root-cause fix:
            # previously nothing here checked country_code at all, so a
            # frontend bug (or a malicious/buggy client) could create a
            # ₦5.13 payment intent for a US topup, which would later crash
            # _finalize_transaction trying to convert that to a viable USD
            # amount. Skipped for wallet_funding, where there is no
            # "destination country" — the user is choosing their own
            # wallet currency directly.
            # ------------------------------------------------------------
            country_code = str(data.get("country_code") or "").upper() or None
            tx_type_for_validation = data.get("type", "topup")
            if country_code and tx_type_for_validation != "wallet_funding":
                expected_currency = COUNTRY_CURRENCY_MAP.get(country_code)
                if expected_currency and currency != expected_currency:
                    # NOTE: this is the hook point for the optional
                    # cross-currency-funding feature (pay a USD recharge
                    # from an NGN wallet balance at the live rate) — not
                    # implemented yet, so for now we reject cleanly rather
                    # than risk creating an unpayable/mismatched intent.
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": (
                                    f"Currency mismatch: {country_code} recharges are "
                                    f"priced in {expected_currency}, not {currency}. "
                                    f"Please switch currency or payment method."
                                ),
                            }
                        ),
                        400,
                    )

            _rb = _live_rates_block(currency)
            if _rb:
                return jsonify({"success": False, "code": "RATES_UNAVAILABLE", "error": _rb}), 503
            if float(amount) < SUPPORTED_CURRENCIES[currency]["min_amount"]:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": (
                                f"Minimum amount for {currency} is "
                                f"{SUPPORTED_CURRENCIES[currency]['min_amount']}."
                            ),
                        }
                    ),
                    400,
                )

            if provider and str(provider).lower().strip() not in ("", "wallet"):
                provider_key = str(provider).lower().strip()
                if provider_key in GATEWAY_CURRENCIES and currency not in GATEWAY_CURRENCIES[provider_key]:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"{provider_key} does not support {currency}.",
                            }
                        ),
                        400,
                    )

            if not provider:
                provider = SUPPORTED_CURRENCIES[currency]["gateway"]
            else:
                provider = str(provider).lower().strip()

            tx_type = data.get("type", "topup")

            # ================================================================
            # NET365 WALLET PAYMENT
            # ================================================================
            if provider == "wallet":
                if tx_type != "topup":
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "Net365 Wallet payment is currently available for recharge/top-up transactions.",
                            }
                        ),
                        400,
                    )

                if not data.get("operator_id") or not data.get("phone"):
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "Missing operator or phone number",
                            }
                        ),
                        400,
                    )

                try:
                    total_amount = round(float(amount), 2)
                    service_amount, _wfee = split_topup_amounts(
                        dict(data, currency=currency), total_amount, user_id=g.current_user_id
                    )
                except (TypeError, ValueError):
                    return (
                        jsonify({"success": False, "error": "Invalid payment amount"}),
                        400,
                    )

                if (
                    total_amount <= 0
                    or service_amount <= 0
                    or service_amount > total_amount
                ):
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "Invalid recharge amount or checkout total",
                            }
                        ),
                        400,
                    )

                db.ensure_wallet(user_id, currency)
                wallet = db.get_wallet(user_id, currency) or {}
                available_balance = float(wallet.get("balance") or 0)
                if available_balance + 1e-9 < total_amount:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"Insufficient {currency} wallet balance. Available: {currency} {available_balance:,.2f}. Required: {currency} {total_amount:,.2f}.",
                                "code": "INSUFFICIENT_WALLET_FUNDS",
                                "wallet_balance": available_balance,
                                "required": total_amount,
                                "currency": currency,
                            }
                        ),
                        400,
                    )

                reference = generate_reference("WAL")
                phone = str(data.get("phone")).strip()
                country_code = str(data.get("country_code") or "NG").upper()
                debit_done = False
                provider_called = False

                try:
                    pending_created = db.create_pending(
                        reference=reference,
                        tx_type="topup",
                        provider="wallet",
                        amount=total_amount,
                        currency=currency,
                        payload={
                            "operator_id": data.get("operator_id"),
                            "phone": phone,
                            "country_code": country_code,
                            "service_amount": service_amount,
                            "fee_amount": round(total_amount - service_amount, 2),
                        },
                        user_id=user_id,
                    )
                    if not pending_created:
                        logger.error(
                            f"Wallet topup {reference}: create_pending returned False — "
                            f"this transaction will NOT appear in the transactions table"
                        )

                    debit_result = db.debit_wallet(
                        user_id=user_id,
                        amount=total_amount,
                        description=f"Airtime recharge via Net365 Wallet - {phone}",
                        reference=reference,
                        metadata={
                            "type": "wallet_topup",
                            "service_amount": service_amount,
                            "fee_amount": round(total_amount - service_amount, 2),
                            "operator_id": data.get("operator_id"),
                            "phone": phone,
                            "currency": currency,
                        },
                        currency=currency,
                    )
                    if not debit_result.get("success"):
                        db.mark_failed(
                            reference,
                            debit_result.get("error", "Unable to debit wallet"),
                        )
                        return (
                            jsonify(
                                {
                                    "success": False,
                                    "error": debit_result.get(
                                        "error", "Unable to debit wallet"
                                    ),
                                }
                            ),
                            400,
                        )
                    debit_done = True

                    formatted_phone = self.platform._format_phone_for_topup(
                        phone, country_code
                    )
                    if not formatted_phone:
                        raise ValueError("Invalid phone number format")
                    # Nigerian naira recharge follows the admin's routing policy (Admin > Provider Routing > Airtime), exactly like
                    # card-paid recharge: VTpass first with Reloadly on standby, or the reverse. The second processor is only used when the
                    # first one DEFINITELY did not accept the order.
                    import net365_routing as _rt
                    _ng_naira = country_code == "NG" and currency == "NGN"
                    _reloadly_first = _ng_naira and _rt.order("airtime")[0] == "reloadly"
                    result = None
                    if _ng_naira and not _reloadly_first:
                        try:
                            result = _wallet_airtime_via_router(reference, data, phone, service_amount, _rt)
                        except Exception:
                            provider_called = True      # outcome unknown: keep the debit for review, never refund or retry elsewhere
                            raise
                        if result is not None:
                            provider_called = True
                    if result is None:
                        usd_amount = self.platform.convert_to_usd(service_amount, currency)
                        if usd_amount <= 0:
                            raise ValueError(
                                "Unable to convert recharge amount to provider currency"
                            )

                        provider_called = True
                        result = (
                            self.platform.make_topup(
                                operator_id=str(data.get("operator_id")),
                                amount=str(round(usd_amount, 2)),
                                recipient_phone={
                                    "countryCode": country_code,
                                    "number": formatted_phone,
                                },
                                use_local_amount=False,
                                custom_identifier=f"wallet-topup-{reference}",
                                recipient_email=data.get("email")
                                or g.current_user.get("email"),
                                is_async=True,
                            )
                            or {}
                        )
                        if _ng_naira:
                            _rl_ok = str(result.get("status") or "").upper() != "FAILED" and bool(result.get("transactionId") or result.get("id"))
                            _rt.record("reloadly", "airtime", _rl_ok, reference)
                            if not _rl_ok and _reloadly_first:
                                # Reloadly definitely did not take it: try the standby processor before refunding.
                                _standby = _wallet_airtime_via_router(reference, data, phone, service_amount, _rt)
                                if _standby is not None:
                                    result = _standby

                    provider_status = str(result.get("status") or "").upper()
                    transaction_id = result.get("transactionId") or result.get("id")
                    if (
                        provider_status == "FAILED"
                        or str(result.get("success")).lower() == "false"
                    ):
                        error_message = (
                            result.get("message")
                            or result.get("error")
                            or "Recharge failed at provider"
                        )
                        db.mark_failed(reference, error_message)
                        refund = db.credit_wallet(
                            user_id=user_id,
                            amount=total_amount,
                            currency=currency,
                            description=f"Refund for failed wallet recharge {reference}",
                            reference=f"REFUND-{reference}",
                            metadata={
                                "original_reference": reference,
                                "provider_result": result,
                            },
                        )
                        return (
                            jsonify(
                                {
                                    "success": False,
                                    "error": f"{error_message}. Your wallet has been refunded.",
                                    "refunded": refund.get("success", False),
                                    "reference": reference,
                                    "wallet_balance": (
                                        db.get_wallet(user_id, currency) or {}
                                    ).get("balance", 0),
                                }
                            ),
                            400,
                        )

                    if not transaction_id:
                        logger.error(
                            f"Wallet recharge {reference} returned no provider transaction ID: {result}"
                        )
                        db.mark_fulfillment_failed(
                            reference, "Provider did not return a transaction ID"
                        )
                        return (
                            jsonify(
                                {
                                    "success": False,
                                    "status": "review",
                                    "needs_review": True,
                                    "error": "Recharge was submitted but the provider did not return a transaction ID. Your wallet debit has been retained temporarily to prevent duplicate recharge.",
                                    "reference": reference,
                                    "wallet_balance": (
                                        db.get_wallet(user_id, currency) or {}
                                    ).get("balance", 0),
                                }
                            ),
                            202,
                        )

                    db.mark_fulfilled(
                        reference,
                        {
                            **result,
                            "service_amount": service_amount,
                            "fee_amount": round(total_amount - service_amount, 2),
                            "payment_method": "wallet",
                        },
                    )
                    db.create_reloadly_transaction(
                        reference=reference,
                        user_id=user_id,
                        transaction_type="airtime",
                        amount=total_amount,
                        status="completed",
                        provider_transaction_id=str(transaction_id),
                        result={
                            **result,
                            "service_amount": service_amount,
                            "fee_amount": round(total_amount - service_amount, 2),
                            "payment_method": "wallet",
                        },
                        currency=currency,
                    )
                    log_event(
                        user_id=user_id,
                        event_type="wallet_topup",
                        details={
                            "amount": total_amount,
                            "service_amount": service_amount,
                            "fee_amount": round(total_amount - service_amount, 2),
                            "currency": currency,
                            "phone": formatted_phone,
                            "operator_id": data.get("operator_id"),
                            "reference": reference,
                            "transaction_id": transaction_id,
                            "payment_method": "wallet",
                        },
                        status="success",
                    )
                    db.create_notification(
                        user_id,
                        "Airtime Recharge Successful ✅",
                        f"{currency} {service_amount:,.2f} recharge completed for {formatted_phone}. Wallet charged: {currency} {total_amount:,.2f}.",
                        "success",
                    )
                    user = db.get_user(user_id)
                    if user and user.get("email"):
                        try:
                            send_email_notification(
                                user["email"],
                                f"Net365 Airtime Recharge Receipt — {reference}",
                                f"Your airtime recharge was completed successfully.\n\nRecharge: {currency} {service_amount:,.2f}\nFee: {currency} {total_amount - service_amount:,.2f}\nWallet charged: {currency} {total_amount:,.2f}\nPhone: {formatted_phone}\nReference: {reference}",
                                include_promo=True,
                                promo_context={
                                    "user_id": user_id,
                                    "reference": reference,
                                    "tx_type": "airtime",
                                    "amount": service_amount,
                                },
                            )
                        except Exception:
                            logger.exception(
                                f"Failed to send wallet recharge receipt for {reference}"
                            )
                    wallet_after = db.get_wallet(user_id, currency) or {}
                    return jsonify(
                        {
                            "success": True,
                            "status": "completed",
                            "payment_method": "wallet",
                            "reference": reference,
                            "transactionId": str(transaction_id),
                            "amount": total_amount,
                            "service_amount": service_amount,
                            "fee": round(total_amount - service_amount, 2),
                            "currency": currency,
                            "wallet_balance": wallet_after.get("balance", 0),
                        }
                    )

                except Exception as exc:
                    logger.exception(f"Wallet recharge failed for {reference}: {exc}")
                    if debit_done and not provider_called:
                        db.mark_failed(reference, str(exc))
                        refund = db.credit_wallet(
                            user_id=user_id,
                            amount=total_amount,
                            currency=currency,
                            description=f"Refund for failed wallet recharge {reference}",
                            reference=f"REFUND-{reference}",
                            metadata={
                                "original_reference": reference,
                                "reason": str(exc),
                            },
                        )
                        return (
                            jsonify(
                                {
                                    "success": False,
                                    "error": "Recharge failed before provider submission. Wallet refunded.",
                                    "refunded": refund.get("success", False),
                                    "reference": reference,
                                }
                            ),
                            400,
                        )
                    db.mark_fulfillment_failed(reference, str(exc))
                    return (
                        jsonify(
                            {
                                "success": False,
                                "status": "review",
                                "needs_review": True,
                                "error": "The recharge provider response could not be confirmed. Your wallet debit was retained temporarily to prevent a duplicate recharge.",
                                "reference": reference,
                            }
                        ),
                        202,
                    )

            if (
                provider not in GATEWAY_CURRENCIES
                or currency not in GATEWAY_CURRENCIES[provider]
            ):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"{provider} does not support {currency}",
                        }
                    ),
                    400,
                )

            if tx_type == "wallet_funding":
                result = self.platform.create_payment(
                    amount=float(amount),
                    currency=currency,
                    email=g.current_user.get("email") or "user@example.com",
                    return_url=data.get("return_url"),
                    provider=provider,
                )
            else:
                result = self.platform.create_payment(
                    amount=float(amount),
                    currency=currency,
                    operator_id=data.get("operator_id"),
                    phone=data.get("phone"),
                    country_code=data.get("country_code", "NG"),
                    email=_payer_email,
                    return_url=data.get("return_url"),
                    provider=provider,
                )

            if result.get("success") and result.get("reference"):
                if tx_type == "wallet_funding":
                    payload = {
                        "type": "wallet_funding",
                        "user_id": user_id,
                        "email": g.current_user.get("email"),
                        "wallet_currency": currency,
                    }

                else:
                    payload = {
                        "operator_id": data.get("operator_id"),
                        "phone": data.get("phone"),
                        "country_code": data.get("country_code", "NG"),
                        "email": _payer_email,
                    }
                    if str(data.get("source") or "") in ("telegram", "whatsapp"):
                        payload["source"] = data["source"]
                        payload["operator_name"] = str(data.get("operator_name") or "")[:40]
                    if data.get("save_card") and not _is_guest:
                        payload["save_card"] = True
                    if tx_type == "topup":
                        try:
                            _svc, _fee = split_topup_amounts(data, amount, user_id=g.current_user_id)
                        except (TypeError, ValueError):
                            return jsonify({"success": False, "error": "Price changed or invalid. Please refresh the page and try again."}), 400
                        payload["service_amount"] = _svc
                        payload["fee_amount"] = _fee

                    if payload.get("phone"):
                        payload["phone"] = encrypt_pii(payload["phone"])


                # ============================================================
                # PRESERVE STRIPE SESSION ID FOR EVERY STRIPE TRANSACTION
                # ============================================================
                if (
                    result.get("provider") == "stripe"
                    and result.get("stripe_session_id")
                ):
                    payload["stripe_session_id"] = result["stripe_session_id"]

                    logger.info(
                        f"Saving Stripe session ID "
                        f"{result['stripe_session_id']} "
                        f"to {tx_type} transaction "
                        f"{result['reference']}"
                    )

                db.create_pending(
                    reference=result["reference"],
                    tx_type=tx_type,
                    provider=result.get("provider", provider or "paystack"),
                    amount=float(amount),
                    currency=result.get("currency", currency),
                    payload=payload,
                    user_id=user_id,
                )

                log_event(
                    user_id=user_id,
                    event_type="payment_initiated",
                    details={
                        "amount": amount,
                        "currency": currency,
                        "provider": provider,
                        "reference": result["reference"],
                        "type": tx_type,
                    },
                    status="pending",
                )

            return jsonify(result)

        # ============ PUBLIC / GUEST RECHARGE PAYMENT ============
        # Mobile Express can recharge without an account. The payment gateway
        # transaction is still recorded and verified server-side; fulfillment
        # is tied to the verified payment reference, not browser state.
        @self.app.route("/api/public/payment/init", methods=["POST"])
        @self.app.route("/api/public/topup/init", methods=["POST"])  # path index.html calls for guests
        @rate_limit(max_requests=20, window_seconds=60)
        def public_init_payment():
            data = request.get_json(silent=True) or {}
            try:
                amount = float(data.get("amount", 0))
            except (TypeError, ValueError):
                amount = 0
            currency = str(data.get("currency") or "NGN").upper()
            provider = str(data.get("provider") or "").lower()
            country_code = str(data.get("country_code") or "NG").upper()
            operator_id = data.get("operator_id")
            phone = str(data.get("phone") or "").strip()
            email = str(data.get("email") or "").strip()

            if amount <= 0 or not phone or not operator_id:
                return jsonify({"success": False, "error": "Phone, network and amount are required"}), 400
            if country_code == "NG":
                try:
                    import net365_recovery as _rc
                    _mb = _rc.maintenance_block("airtime")
                    if _mb:
                        return _mb
                except ImportError:
                    pass
                _mm = network_mismatch_error(phone, operator_id, data.get("operator_name"), bool(data.get("confirm_network")))
                if _mm:
                    return jsonify(_mm), 409
            if currency not in SUPPORTED_CURRENCIES:
                return jsonify({"success": False, "error": "Unsupported currency"}), 400
            expected_currency = COUNTRY_CURRENCY_MAP.get(country_code)
            if expected_currency and currency != expected_currency:
                return jsonify({"success": False, "error": f"{country_code} recharges are priced in {expected_currency}"}), 400
            if provider not in GATEWAY_CURRENCIES or provider == "wallet" or currency not in GATEWAY_CURRENCIES[provider]:
                cfg = recommended_payment(country_code)
                provider = cfg.get("provider")
                if provider not in GATEWAY_CURRENCIES or currency not in GATEWAY_CURRENCIES[provider]:
                    return jsonify({"success": False, "error": f"No supported payment gateway for {currency}"}), 400
            if amount < SUPPORTED_CURRENCIES[currency]["min_amount"]:
                return jsonify({"success": False, "error": f"Minimum amount is {SUPPORTED_CURRENCIES[currency]['min_amount']} {currency}"}), 400
            _rb = _live_rates_block(currency)
            if _rb:
                return jsonify({"success": False, "code": "RATES_UNAVAILABLE", "error": _rb}), 503
            if not email or "@" not in email:
                email = "customer@net365co.com"

            _limit_err = _purchase_limit_error(None, amount, currency)
            if _limit_err:
                return jsonify({"success": False, "code": "LIMIT_EXCEEDED", "error": _limit_err}), 400
            try:
                _svc, _fee = split_topup_amounts(data, amount)
            except (TypeError, ValueError):
                return jsonify({"success": False, "error": "Price changed or invalid. Please refresh the page and try again."}), 400

            try:
                result = self.platform.create_payment(
                    amount=amount,
                    currency=currency,
                    operator_id=operator_id,
                    phone=phone,
                    country_code=country_code,
                    email=email,
                    return_url=data.get("return_url") or f"{request.host_url.rstrip('/')}/payment/success",
                    provider=provider,
                )
                if result.get("success") and result.get("reference"):
                    payload = {
                        "operator_id": str(operator_id),
                        "phone": encrypt_pii(phone),
                        "country_code": country_code,
                        "email": email,
                        "guest_recharge": True,
                        "service_amount": _svc,
                        "fee_amount": _fee,
                    }
                    if result.get("provider") == "stripe" and result.get("stripe_session_id"):
                        payload["stripe_session_id"] = result["stripe_session_id"]
                    db.create_pending(
                        reference=result["reference"],
                        tx_type="topup",
                        provider=result.get("provider", provider),
                        amount=amount,
                        currency=result.get("currency", currency),
                        payload=payload,
                        user_id=None,
                    )
                    log_event(user_id=None, event_type="guest_payment_initiated", details={
                        "amount": amount, "currency": currency, "provider": result.get("provider", provider),
                        "reference": result["reference"], "country_code": country_code,
                    }, status="pending")
                return jsonify(result)
            except Exception as e:
                # Full details (type, message, traceback) go to the server log only. Returning exception
                # text to an anonymous caller can leak gateway, URL or configuration details.
                _ref = generate_reference("ERR")
                logger.exception(f"Guest payment initialization failed [{_ref}]: {e}")
                return jsonify({
                    "success": False,
                    "error": "We could not start your payment. Please try again, or contact support with the reference below.",
                    "reference": _ref,
                }), 502

                # ============ WALLET FUNDING ============
        @self.app.route("/api/wallet/fund", methods=["POST"])
        @login_required
        @email_verified_required
        def fund_wallet():
            data = request.json or {}
            user_id = g.current_user_id
            amount = data.get("amount")
            currency = (data.get("currency") or "NGN").upper()

            if currency not in SUPPORTED_CURRENCIES:
                return (
                    jsonify({
                        "success": False,
                        "error": f"Unsupported wallet currency: {currency}",
                    }),
                    400,
                )

            provider = SUPPORTED_CURRENCIES[currency]["gateway"]
            min_amount = SUPPORTED_CURRENCIES[currency]["min_amount"]

            email = g.current_user.get("email")

            if not user_id:
                return jsonify({"success": False, "error": "User ID required"}), 400

            if not amount or float(amount) <= 0:
                return jsonify({"success": False, "error": "Invalid amount"}), 400

            if float(amount) < min_amount:
                return (
                    jsonify({
                        "success": False,
                        "error": f"Minimum {currency} funding is {min_amount:g}",
                    }),
                    400,
                )

            user = db.get_user(user_id)
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404

            email = email or user.get("email", f"user_{user_id}@net365.com")

            db.ensure_wallet(user_id, currency)

            result = self.platform.create_payment(
                amount=float(amount),
                currency=currency,
                email=email,
                return_url=_safe_payment_return_url(data.get("return_url")),
                provider=provider,
            )

            if result.get("success") and result.get("reference"):
                payload = {
                    "type": "wallet_funding",
                    "user_id": user_id,
                    "email": email,
                    "wallet_currency": currency,
                }

                if result.get("provider") == "stripe" and result.get("stripe_session_id"):
                    payload["stripe_session_id"] = result["stripe_session_id"]

                db.create_pending(
                    reference=result["reference"],
                    tx_type="wallet_funding",
                    provider=result.get("provider", provider),
                    amount=float(amount),
                    currency=result.get("currency", currency),
                    payload=payload,
                    user_id=user_id,
                )

            return jsonify(result)

        # ============ WALLET TRANSFER ============
        @self.app.route("/api/wallet/transfer", methods=["POST"])
        @login_required
        def wallet_transfer():
            if not WALLET_TRANSFERS_ENABLED:
                return jsonify({"success": False, "code": "TRANSFERS_DISABLED",
                                "error": "Wallet transfers are not available."}), 403
            data = request.json or {}
            user_id = g.current_user_id
            to_user_id = data.get("to_user_id")
            amount = data.get("amount")
            currency = (data.get("currency") or "NGN").upper()
            description = data.get("description", "Wallet transfer")

            if not to_user_id:
                return (
                    jsonify({"success": False, "error": "Recipient user ID required"}),
                    400,
                )

            if to_user_id == user_id:
                return (
                    jsonify({"success": False, "error": "Cannot transfer to yourself"}),
                    400,
                )

            if not amount or float(amount) <= 0:
                return jsonify({"success": False, "error": "Invalid amount"}), 400

            recipient = db.get_user(to_user_id)
            if not recipient:
                return jsonify({"success": False, "error": "Recipient not found"}), 404

            db.ensure_wallet(user_id, currency)
            db.ensure_wallet(to_user_id, currency)

            sender_wallet = db.get_wallet(user_id, currency)
            if not sender_wallet or sender_wallet.get("balance", 0) < float(amount):
                return (
                    jsonify(
                        {"success": False, "error": f"Insufficient {currency} balance"}
                    ),
                    400,
                )

            reference = generate_reference("TRF")

            debit_result = db.debit_wallet(
                user_id=user_id,
                amount=float(amount),
                description=f'Transfer to {recipient.get("full_name", "User")} - {description}',
                reference=reference,
                metadata={"to_user_id": to_user_id, "type": "transfer"},
                currency=currency,
            )

            if not debit_result.get("success"):
                return (
                    jsonify({"success": False, "error": debit_result.get("error")}),
                    400,
                )

            credit_result = db.credit_wallet(
                user_id=to_user_id,
                amount=float(amount),
                description=f'Transfer from {g.current_user.get("full_name", "User")} - {description}',
                reference=reference,
                metadata={"from_user_id": user_id, "type": "transfer"},
                currency=currency,
            )

            if not credit_result.get("success"):
                db.credit_wallet(
                    user_id=user_id,
                    amount=float(amount),
                    description=f"Rollback: {reference}",
                    reference=f"ROLLBACK-{reference}",
                    metadata={"original_reference": reference, "type": "rollback"},
                    currency=currency,
                )
                return (
                    jsonify({"success": False, "error": "Failed to credit recipient"}),
                    500,
                )

            log_event(
                user_id=user_id,
                event_type="wallet_transfer_out",
                details={
                    "amount": amount,
                    "currency": currency,
                    "to_user_id": to_user_id,
                    "to_user_name": recipient.get("full_name"),
                    "reference": reference,
                    "description": description,
                },
                status="success",
            )

            log_event(
                user_id=to_user_id,
                event_type="wallet_transfer_in",
                details={
                    "amount": amount,
                    "currency": currency,
                    "from_user_id": user_id,
                    "from_user_name": g.current_user.get("full_name"),
                    "reference": reference,
                    "description": description,
                },
                status="success",
            )

            db.create_notification(
                user_id,
                "📤 Transfer Sent",
                f'{currency} {float(amount):,.2f} sent to {recipient.get("full_name")}',
                "info",
            )

            db.create_notification(
                to_user_id,
                "📥 Transfer Received",
                f'{currency} {float(amount):,.2f} received from {g.current_user.get("full_name")}',
                "success",
            )

            sender = g.current_user
            if sender.get("email"):
                send_email_notification(
                    sender["email"],
                    f"📤 Transfer Sent: {currency} {amount}",
                    f"You have sent {currency} {float(amount):,.2f} to {recipient.get('full_name')}.\n\nReference: {reference}",
                    include_promo=True,
                    promo_context={
                        "user_id": sender.get("id") or g.current_user_id,
                        "reference": reference,
                        "tx_type": "transfer",
                        "amount": float(amount),
                    },
                )

            if recipient.get("email"):
                send_email_notification(
                    recipient["email"],
                    f"📥 Transfer Received: {currency} {amount}",
                    f"You have received {currency} {float(amount):,.2f} from {sender.get('full_name')}.\n\nReference: {reference}",
                    include_promo=True,
                    promo_context={
                        "user_id": recipient.get("id"),
                        "reference": reference,
                        "tx_type": "transfer",
                        "amount": float(amount),
                    },
                )

            return jsonify(
                {
                    "success": True,
                    "reference": reference,
                    "sender_balance": debit_result.get("new_balance"),
                    "recipient_balance": credit_result.get("new_balance"),
                    "currency": currency,
                    "amount": float(amount),
                }
            )

        # ============ WALLET BALANCE ============
        @self.app.route("/api/wallet", methods=["GET"])
        @login_required
        def get_wallet():
            user_id = g.current_user_id
            currency = request.args.get("currency", "NGN").upper()
            wallet = db.get_wallet(user_id, currency)
            wallets = db.get_wallets(user_id)
            return jsonify({"success": True, "wallet": wallet, "wallets": wallets})

        # ============ PAYMENT PREFERENCES ============
        @self.app.route("/api/payment/preferences", methods=["GET"])
        def payment_preferences():
            # The page tells us which country the customer is paying FOR (phone prefix / dropdown).
            # That must win over the visitor's IP country (CF-IPCountry), otherwise a Nigerian
            # visitor recharging a UK number is always told "NGN". It is only a display
            # preference: /api/payment/init still validates country vs currency.
            _asked = (request.headers.get("X-Country-Code") or request.args.get("country") or "").strip().upper()
            _country = _asked if len(_asked) == 2 and _asked.isalpha() else get_request_country(request)
            cfg = recommended_payment(_country)
            return jsonify(
                {
                    "success": True,
                    "country": cfg["country"],
                    "currency": cfg["currency"],
                    "recommended_provider": cfg["provider"],
                    "alternatives": cfg["alternatives"],
                    "local": cfg["country"] == "NG",
                    "wallet_currencies": list(SUPPORTED_CURRENCIES.keys()),
                    "supported_currencies": SUPPORTED_CURRENCIES,
                }
            )

        # ============ DASHBOARD SUMMARY ============
        @self.app.route("/api/dashboard/summary", methods=["GET"])
        @login_required
        def dashboard_summary():
            user_id = g.current_user_id
            user = db.get_user(user_id)
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404

            wallets = db.get_wallets(user_id)
            rewards = db.get_rewards(user_id)
            transactions = db.get_transactions(user_id, 5)
            notifications = db.get_notifications(user_id, 5, unread_only=True)
            unread_count = db.get_unread_count(user_id)

            ngn_wallet = next(
                (w for w in wallets if w["currency"] == "NGN"), {"balance": 0}
            )

            return jsonify(
                {
                    "success": True,
                    "summary": {
                        "user": {
                            "id": user["id"],
                            "name": user["full_name"],
                            "email": user["email"],
                            "phone": user.get("phone"),
                            "currency": user.get("currency", "NGN"),
                        },
                        "wallet": {
                            "balance": ngn_wallet["balance"] if ngn_wallet else 0,
                            "currency": "NGN",
                            "wallets": wallets,
                        },
                        "rewards": {
                            "points": rewards["points"] if rewards else 0,
                            "level": rewards["level"] if rewards else "Bronze",
                            "cashback_value": (
                                rewards["cashback_value"] if rewards else 0
                            ),
                        },
                        "unread_notifications": unread_count,
                        "recent_transactions": transactions,
                        "recent_notifications": notifications,
                    },
                }
            )

        # ============ USER TRANSACTIONS ============
        @self.app.route("/api/user/transactions", methods=["GET"])
        @login_required
        def get_user_transactions():
            user_id = g.current_user_id
            limit = min(request.args.get("limit", 20, type=int), 100)
            offset = max(request.args.get("offset", 0, type=int), 0)

            transactions = db.get_transactions(user_id, limit, offset)
            return jsonify({"success": True, "transactions": transactions})

        # ============ CUSTOMER-SAFE TRANSACTION RECEIPT ============
        @self.app.route("/api/user/transaction/<reference>", methods=["GET"])
        @login_required
        def get_user_transaction_detail(reference):
            """Return a transaction only when it belongs to the signed-in customer.

            The older /api/transaction/<reference> route is admin-only, so the
            mobile receipt UI must use this customer-scoped endpoint instead.
            """
            user_id = g.current_user_id
            try:
                transactions = db.get_transactions(user_id, 100, 0) or []
                wanted = str(reference).strip()
                tx = next((item for item in transactions
                           if str(item.get("reference") or item.get("id") or "") == wanted), None)
                if not tx:
                    return jsonify({"success": False, "error": "Transaction not found in your account"}), 404
                return jsonify({"success": True, "transaction": tx})
            except Exception as e:
                logger.exception("Customer receipt lookup failed for user %s", user_id)
                return jsonify({"success": False, "error": "Could not load this receipt yet"}), 500

        # ============ USER EVENTS / LOGS ============
        @self.app.route("/api/events", methods=["GET"])
        @login_required
        def get_user_events_route():
            user_id = g.current_user_id
            limit = min(request.args.get("limit", 50, type=int), 200)
            offset = max(request.args.get("offset", 0, type=int), 0)
            event_type = request.args.get("type")

            events = get_user_events(user_id, limit, offset, event_type)
            return jsonify({"success": True, "events": events})

        @self.app.route("/api/events/types", methods=["GET"])
        def get_event_types():
            return jsonify(
                {
                    "success": True,
                    "types": [
                        "topup",
                        "airtime",
                        "data",
                        "gift_card",
                        "utility",
                        "wallet_funding",
                        "wallet_transfer",
                        "schedule_run",
                        "schedule_created",
                        "schedule_updated",
                        "schedule_deleted",
                        "schedule_paused",
                        "schedule_resumed",
                        "payment_initiated",
                        "payment_success",
                        "payment_failed",
                        "reward_earned",
                        "referral_completed",
                        "wallet_transfer_in",
                        "wallet_transfer_out",
                    ],
                }
            )



        # ============ USER CONTACTS ============
        @self.app.route("/api/user/contacts", methods=["GET"])
        @login_required
        def get_user_contacts():
            user_id = g.current_user_id
            limit = request.args.get("limit", type=int)
            contacts = db.get_contacts(user_id, limit=limit)
            return jsonify({"success": True, "contacts": contacts})

        @self.app.route("/api/user/contacts", methods=["POST"])
        @login_required
        def add_user_contact():
            data = request.json
            user_id = g.current_user_id
            name = data.get("name")
            phone = data.get("phone")
            network = data.get("network")

            if not all([user_id, name, phone]):
                return (
                    jsonify({"success": False, "error": "Missing required fields"}),
                    400,
                )

            result = db.add_contact(user_id, name, phone, network)
            return jsonify(result)

        @self.app.route("/api/user/contacts/import", methods=["POST"])
        @login_required
        def import_contacts():
            user_id = g.current_user_id
            data = request.get_json(silent=True) or {}
            logger.info(f"📥 Contact import request from user {user_id}")

            phone_field = data.get("phone_field", "phone")
            name_field = data.get("name_field", "name")
            raw_contacts = data.get("contacts")

            # Normalize bulk vs single contact
            if raw_contacts is None or not isinstance(raw_contacts, list):
                name = data.get("name", "").strip()
                phone = data.get("phone", "").strip()
                email = data.get("email", "").strip()

                if not phone and not email:
                    return jsonify({"success": False, "error": "Phone number or email is required"}), 400

                single_contact = {
                    name_field: name,
                    phone_field: phone,
                    "email": email
                }
                if data.get("network"):
                    single_contact["network"] = data.get("network")
                if data.get("country"):
                    single_contact["country"] = data.get("country")

                contacts = [single_contact]
            else:
                contacts = raw_contacts

            if len(contacts) > 500:
                return jsonify({"success": False, "error": "Maximum 500 contacts per import allowed."}), 400

            # Clean and normalize
            normalized_contacts = []
            for item in contacts:
                if not isinstance(item, dict):
                    continue

                p_val = str(item.get(phone_field) or item.get("phone") or "").strip()
                e_val = str(item.get("email") or "").strip()

                if p_val or e_val:
                    item[phone_field] = p_val
                    item[name_field] = str(item.get(name_field) or item.get("name") or "").strip()
                    normalized_contacts.append(item)

            if not normalized_contacts:
                return jsonify({"success": False, "error": "No valid contact entries found in payload."}), 400

            try:
                result = db.import_contacts_unique(user_id, normalized_contacts, phone_field, name_field)
                return jsonify(result), 200
            except Exception as e:
                logger.error(f"Import error for user {user_id}: {str(e)}", exc_info=True)
                return jsonify({"success": False, "error": "Database error during contact import."}), 500        

        @self.app.route("/api/bulk/status/<job_id>", methods=["GET"])
        @login_required
        def bulk_job_status(job_id):
            """Get status of a bulk job."""
            user_id = g.current_user_id
            
            conn = db.get_db_connection()
            c = conn.cursor()
            job = c.execute(
                "SELECT * FROM bulk_jobs WHERE id = ? AND user_id = ?",
                (job_id, user_id)
            ).fetchone()
            conn.close()
            
            if not job:
                return jsonify({"success": False, "error": "Job not found"}), 404
            
            job_dict = dict(job)
            if job_dict.get('error'):
                try:
                    job_dict['error'] = json.loads(job_dict['error'])
                except:
                    pass
            
            return jsonify({"success": True, "job": job_dict}) 

        @self.app.route("/api/bulk/recharge/init", methods=["POST"])
        @login_required
        @email_verified_required
        def bulk_recharge_init():
            """Gateway-aware CSV/TXT bulk upload.

            Same parsing as /api/bulk/recharge, but:
              - Accepts an extra `payment_method` form field
              - For 'wallet'   → debits wallet immediately, runs worker
              - For gateways   → creates a paused job + returns a checkout URL
            """
            user_id = g.current_user_id

            file = request.files.get("file")
            if not file or not file.filename:
                return jsonify({"success": False, "error": "No file uploaded"}), 400

            allowed = (".csv", ".txt")
            if not file.filename.lower().endswith(allowed):
                return jsonify({"success": False, "error": "Only .csv or .txt files are allowed"}), 400

            payment_method = (request.form.get("payment_method") or "wallet").lower().strip()
            if payment_method not in ("wallet", "paystack", "stripe", "flutterwave"):
                return jsonify({"success": False, "error": "Unsupported payment method"}), 400
            if payment_method == "stripe":
                # Bulk totals are NGN amounts; sending them to Stripe as USD would overcharge ~1000x.
                return jsonify({"success": False, "error": "Bulk recharge by Stripe is not available. Please use Paystack or Flutterwave."}), 400

            return_url = request.form.get("return_url") or url_for("payment_success", _external=True)

            # ── Reuse the exact same parsing as the wallet path ────────────
            try:
                raw = file.read().decode("utf-8-sig", errors="ignore")
            except Exception as e:
                return jsonify({"success": False, "error": f"Could not read file: {e}"}), 400

            lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
            if not lines:
                return jsonify({"success": False, "error": "File is empty"}), 400

            header = [c.strip().lower() for c in lines[0].split(",")]
            header_set = set(header)

            is_contact_list = (
                ("name" in header_set or "full_name" in header_set)
                and "phone" in header_set
                and "amount" not in header_set
            )

            if is_contact_list:
                # Contact-list imports never touch payment — nothing to charge.
                return self._import_contacts_with_networks(user_id, lines, header)

            start_index = 0
            if any(h in header_set for h in ("phone", "mobile", "number", "amount")):
                start_index = 1

            records = []
            errors = []
            for i, line in enumerate(lines[start_index:], start=start_index + 1):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 2:
                    errors.append(f"Line {i}: expected at least phone,amount")
                    continue

                phone_raw = parts[0]
                try:
                    amount = float(parts[1])
                except (ValueError, TypeError):
                    errors.append(f"Line {i}: invalid amount '{parts[1]}'")
                    continue

                operator_id = parts[2] if len(parts) > 2 and parts[2] else None
                country_code = (parts[3] if len(parts) > 3 and parts[3] else "NG").upper()

                clean = re.sub(r"[^0-9]", "", phone_raw)
                if country_code == "NG":
                    while clean.startswith("0"):
                        clean = clean[1:]
                    if len(clean) == 10:
                        clean = "234" + clean
                    elif len(clean) == 11:
                        clean = "234" + clean
                    if len(clean) != 13 or not clean.startswith("234"):
                        errors.append(f"Line {i}: invalid Nigerian phone '{phone_raw}'")
                        continue

                records.append({
                    "phone": clean,
                    "amount": amount,
                    "operator_id": operator_id,
                    "country_code": country_code,
                })

            if not records:
                return jsonify({
                    "success": False,
                    "error": "No valid records found in file",
                    "errors": errors[:20],
                }), 400

            if len(records) > 1000:
                return jsonify({"success": False, "error": "Maximum 1000 records per upload"}), 400

            needed = sum(r["amount"] for r in records)
            bulk_fee = server_fee_for(needed, "NGN")
            charge = round(needed + bulk_fee, 2)   # what the customer pays; records are delivered at face value

            # ── Wallet pre-flight check (only when wallet was chosen) ─────
            if payment_method == "wallet":
                wallet = db.get_wallet(user_id, "NGN") or {}
                balance = float(wallet.get("balance") or 0)
                if balance + 1e-9 < charge:
                    return jsonify({
                        "success": False,
                        "error": (
                            f"Insufficient NGN wallet balance. "
                            f"Need ~NGN {charge:,.2f}, have NGN {balance:,.2f}. "
                            f"Choose Paystack, Stripe or Flutterwave to pay by card."
                        ),
                        "wallet_balance": balance,
                        "required": charge,
                    }), 400

            # ── Create the job record ─────────────────────────────────────
            import uuid as _uuid
            job_id = str(_uuid.uuid4())
            initial_status = "pending_payment" if payment_method != "wallet" else "pending"

            conn = db.get_db_connection()
            c = conn.cursor()
            try:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS bulk_jobs (
                        id TEXT PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        total INTEGER DEFAULT 0,
                        processed INTEGER DEFAULT 0,
                        successful INTEGER DEFAULT 0,
                        failed INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'pending',
                        error TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                c.execute(
                    "INSERT INTO bulk_jobs (id, user_id, total, status) VALUES (?, ?, ?, ?)",
                    (job_id, user_id, len(records), initial_status),
                )
                c.execute("""
                    CREATE TABLE IF NOT EXISTS bulk_job_records (
                        job_id TEXT NOT NULL,
                        phone TEXT NOT NULL,
                        amount REAL NOT NULL,
                        operator_id TEXT,
                        country_code TEXT NOT NULL,
                        name TEXT,
                        network TEXT,
                        PRIMARY KEY (job_id, phone)
                    )
                """)
                c.executemany(
                    "INSERT INTO bulk_job_records "
                    "(job_id, phone, amount, operator_id, country_code, name, network) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [(job_id, r["phone"], r["amount"], r["operator_id"],
                      r["country_code"], None, None) for r in records],
                )
                conn.commit()
            finally:
                conn.close()

            # ── Wallet: debit + run now ────────────────────────────────────
            if payment_method == "wallet":
                # Debits the wallet, tags the job as wallet-paid, then starts the worker.
                ok, err = self._start_wallet_bulk_job(user_id, job_id, records, charge)
                if not ok:
                    return jsonify({"success": False, "error": err or "Wallet debit failed",
                                    "job_id": job_id}), 402

                return jsonify({
                    "success": True,
                    "requires_payment": False,
                    "job_id": job_id,
                    "total": len(records),
                    "skipped_lines": len(errors),
                    "amount": charge, "fee": bulk_fee,
                    "currency": "NGN",
                    "message": f"Bulk job started for {len(records)} records",
                })

            # ── Gateway: create checkout, keep job paused ─────────────────
            gateway_currency = "NGN"
            if payment_method == "stripe":
                gateway_currency = "USD"

            try:
                init = self._init_bulk_gateway_checkout(
                    provider=payment_method,
                    user_id=user_id,
                    amount=charge,
                    currency=gateway_currency,
                    job_id=job_id,
                    return_url=return_url,
                    contact_count=len(records),
                )
            except Exception as e:
                logger.exception(f"Bulk file gateway init failed for {job_id}")
                conn = db.get_db_connection()
                c = conn.cursor()
                c.execute("UPDATE bulk_jobs SET status = 'failed', error = ? WHERE id = ?",
                          (str(e), job_id))
                conn.commit()
                conn.close()
                return jsonify({"success": False, "error": f"Could not start {payment_method}: {e}",
                                "job_id": job_id}), 502

            if not init or not init.get("authorization_url"):
                return jsonify({"success": False, "error": "Gateway did not return a checkout URL",
                                "job_id": job_id}), 502

            conn = db.get_db_connection()
            c = conn.cursor()
            try:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS bulk_job_payments (
                        job_id TEXT PRIMARY KEY,
                        provider TEXT NOT NULL,
                        reference TEXT NOT NULL,
                        currency TEXT NOT NULL,
                        amount REAL NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                c.execute(
                    "INSERT OR REPLACE INTO bulk_job_payments "
                    "(job_id, provider, reference, currency, amount) VALUES (?, ?, ?, ?, ?)",
                    (job_id, payment_method,
                     init.get("reference") or init.get("tx_ref") or init.get("id") or job_id,
                     gateway_currency, charge),
                )
                conn.commit()
            finally:
                conn.close()

            return jsonify({
                "success": True,
                "requires_payment": True,
                "authorization_url": init["authorization_url"],
                "reference": init.get("reference") or init.get("tx_ref") or init.get("id"),
                "job_id": job_id,
                "amount": charge, "fee": bulk_fee,
                "currency": gateway_currency,
                "total": len(records),
                "provider": payment_method,
            })


        def _start_wallet_bulk_job(self, user_id, job_id, records, charge):
            """
            Debit the wallet for a bulk job total, then kick off the background worker.
            Returns (success, error_message).
            """
            # 1. Debit the wallet
            ok, err = self._debit_wallet(user_id, "NGN", charge, reference=f"bulk:{job_id}")
            if not ok:
                conn = db.get_db_connection()
                c = conn.cursor()
                c.execute(
                    "UPDATE bulk_jobs SET status = 'failed', error = ? WHERE id = ?",
                    (err or "Wallet debit failed", job_id),
                )
                conn.commit()
                conn.close()
                return False, err or "Wallet debit failed"

            # 2. Record the payment method on the job
            conn = db.get_db_connection()
            c = conn.cursor()
            c.execute(
                "UPDATE bulk_jobs SET payment_method = 'wallet', total_amount = ?, currency = 'NGN' WHERE id = ?",
                (charge, job_id),
            )
            conn.commit()
            conn.close()

            # 3. Kick off the worker
            threading.Thread(
                target=self._process_bulk_job,
                args=(job_id, user_id, records),
                daemon=True,
            ).start()

            return True, None

        @self.app.route("/api/bulk/recharge/contacts", methods=["POST"])
        @login_required
        @email_verified_required
        def bulk_recharge_contacts():
            """Bulk recharge using contacts already saved in the user's address book.

            JSON body: { contact_ids: [int, ...], amount, country_code, operator_id,
                         payment_method, return_url }
            """
            user_id = g.current_user_id
            data = request.get_json(silent=True) or {}

            # ── Validate contact_ids ─────────────────────────────────────────
            contact_ids = data.get("contact_ids") or []
            if not isinstance(contact_ids, list) or not contact_ids:
                return jsonify({"success": False, "error": "No contacts selected"}), 400
            try:
                contact_ids = {int(cid) for cid in contact_ids}
            except (TypeError, ValueError):
                return jsonify({"success": False, "error": "Invalid contact_ids"}), 400

            # ── Validate amount ──────────────────────────────────────────────
            try:
                amount = float(data.get("amount"))
            except (TypeError, ValueError):
                return jsonify({"success": False, "error": "Invalid amount"}), 400
            if amount <= 0:
                return jsonify({"success": False, "error": "Amount must be greater than 0"}), 400

            operator_id = data.get("operator_id") or None
            country_code = (data.get("country_code") or "NG").upper()

            # ── Validate payment_method ──────────────────────────────────────
            payment_method = (data.get("payment_method") or "wallet").lower().strip()
            if payment_method not in ("wallet", "paystack", "stripe", "flutterwave"):
                return jsonify({"success": False, "error": "Unsupported payment method"}), 400
            if payment_method == "stripe":
                # Bulk totals are NGN amounts; sending them to Stripe as USD would overcharge ~1000x.
                return jsonify({"success": False, "error": "Bulk recharge by Stripe is not available. Please use Paystack or Flutterwave."}), 400

            return_url = data.get("return_url") or url_for("payment_success", _external=True)

            # ── Look up selected contacts, scoped to this user ───────────────
            all_contacts = db.get_contacts(user_id) or []
            selected = [c for c in all_contacts if int(c.get("id")) in contact_ids]
            if not selected:
                return jsonify({"success": False, "error": "Selected contacts not found"}), 404

            # ── Build normalized recharge records ────────────────────────────
            records = []
            errors = []
            for c in selected:
                phone_raw = str(c.get("phone") or "")
                clean = re.sub(r"[^0-9]", "", phone_raw)

                if country_code == "NG":
                    while clean.startswith("0"):
                        clean = clean[1:]
                    if len(clean) == 10:
                        clean = "234" + clean
                    elif len(clean) == 11:
                        clean = "234" + clean
                    if len(clean) != 13 or not clean.startswith("234"):
                        errors.append(
                            f"Contact '{c.get('name') or c.get('id')}': "
                            f"invalid phone '{phone_raw}'"
                        )
                        continue

                records.append({
                    "phone": clean,
                    "amount": amount,
                    "operator_id": operator_id,
                    "country_code": country_code,
                    "name": c.get("name"),
                    "network": c.get("network"),
                })

            if not records:
                return jsonify({
                    "success": False,
                    "error": "No valid contacts to recharge",
                    "errors": errors[:20],
                }), 400

            if len(records) > 1000:
                return jsonify({
                    "success": False,
                    "error": "Maximum 1000 contacts per bulk recharge",
                }), 400

            needed = sum(r["amount"] for r in records)
            bulk_fee = server_fee_for(needed, "NGN")
            charge = round(needed + bulk_fee, 2)   # what the customer pays; records are delivered at face value

            # ── Wallet pre-flight check ──────────────────────────────────────
            if payment_method == "wallet":
                wallet = db.get_wallet(user_id, "NGN") or {}
                balance = float(wallet.get("balance") or 0)
                if balance + 1e-9 < charge:
                    return jsonify({
                        "success": False,
                        "error": (
                            f"Insufficient NGN wallet balance. "
                            f"Need ~NGN {charge:,.2f}, have NGN {balance:,.2f}. "
                            f"Choose Paystack, Stripe or Flutterwave to pay by card."
                        ),
                        "wallet_balance": balance,
                        "required": charge,
                    }), 400

            # ── Create the job + records atomically ──────────────────────────
            import uuid as _uuid
            job_id = str(_uuid.uuid4())
            initial_status = "pending_payment" if payment_method != "wallet" else "pending"

            conn = db.get_db_connection()
            c = conn.cursor()
            try:
                # Ensure bulk_jobs has all required columns (defensive migration)
                existing_cols = {
                    row[1] for row in c.execute("PRAGMA table_info(bulk_jobs)").fetchall()
                }
                if not existing_cols:
                    c.execute("""
                        CREATE TABLE IF NOT EXISTS bulk_jobs (
                            id TEXT PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            total INTEGER DEFAULT 0,
                            processed INTEGER DEFAULT 0,
                            successful INTEGER DEFAULT 0,
                            failed INTEGER DEFAULT 0,
                            status TEXT DEFAULT 'pending',
                            error TEXT,
                            payment_method TEXT,
                            payment_reference TEXT,
                            total_amount REAL,
                            currency TEXT DEFAULT 'NGN',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                else:
                    for col, typ in [
                        ("payment_method", "TEXT"),
                        ("payment_reference", "TEXT"),
                        ("total_amount", "REAL"),
                        ("currency", "TEXT DEFAULT 'NGN'"),
                    ]:
                        if col not in existing_cols:
                            try:
                                c.execute(f"ALTER TABLE bulk_jobs ADD COLUMN {col} {typ}")
                            except sqlite3.OperationalError:
                                pass

                c.execute("""
                    CREATE TABLE IF NOT EXISTS bulk_job_records (
                        job_id TEXT NOT NULL,
                        phone TEXT NOT NULL,
                        amount REAL NOT NULL,
                        operator_id TEXT,
                        country_code TEXT NOT NULL,
                        name TEXT,
                        network TEXT,
                        PRIMARY KEY (job_id, phone)
                    )
                """)

                c.execute(
                    "INSERT INTO bulk_jobs (id, user_id, total, status) VALUES (?, ?, ?, ?)",
                    (job_id, user_id, len(records), initial_status),
                )
                c.executemany(
                    "INSERT INTO bulk_job_records "
                    "(job_id, phone, amount, operator_id, country_code, name, network) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [
                        (
                            job_id,
                            r["phone"],
                            r["amount"],
                            r["operator_id"],
                            r["country_code"],
                            r["name"],
                            r["network"],
                        )
                        for r in records
                    ],
                )
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.exception(f"Failed to persist bulk job {job_id}")
                return jsonify({
                    "success": False,
                    "error": f"Could not create bulk job: {e}",
                }), 500
            finally:
                conn.close()

            # ── Wallet path: debit + run immediately ─────────────────────────
            if payment_method == "wallet":
                ok, err = self._start_wallet_bulk_job(user_id, job_id, records, charge)
                if not ok:
                    return jsonify({
                        "success": False,
                        "error": err,
                        "job_id": job_id,
                    }), 402

                return jsonify({
                    "success": True,
                    "requires_payment": False,
                    "job_id": job_id,
                    "total": len(records),
                    "skipped_lines": len(errors),
                    "amount": charge, "fee": bulk_fee,
                    "currency": "NGN",
                    "message": f"Bulk job started for {len(records)} contacts",
                })

            # ── Gateway path: create checkout, job stays pending_payment ────
            gateway_currency = "NGN"
            if payment_method == "stripe":
                gateway_currency = "USD"

            try:
                init = self._init_bulk_gateway_checkout(
                    provider=payment_method,
                    user_id=user_id,
                    amount=charge,
                    currency=gateway_currency,
                    job_id=job_id,
                    return_url=return_url,
                    contact_count=len(records),
                )
            except Exception as e:
                logger.exception(f"Bulk contacts gateway init failed for {job_id}")
                conn = db.get_db_connection()
                c = conn.cursor()
                c.execute(
                    "UPDATE bulk_jobs SET status = 'failed', error = ? WHERE id = ?",
                    (str(e), job_id),
                )
                conn.commit()
                conn.close()
                return jsonify({
                    "success": False,
                    "error": f"Could not start {payment_method}: {e}",
                    "job_id": job_id,
                }), 502

            if not init or not init.get("authorization_url"):
                return jsonify({
                    "success": False,
                    "error": "Gateway did not return a checkout URL",
                    "job_id": job_id,
                }), 502

            # ── Record the gateway payment reference ─────────────────────────
            reference = (
                init.get("reference")
                or init.get("tx_ref")
                or init.get("id")
                or job_id
            )

            conn = db.get_db_connection()
            c = conn.cursor()
            try:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS bulk_job_payments (
                        job_id TEXT PRIMARY KEY,
                        provider TEXT NOT NULL,
                        reference TEXT NOT NULL,
                        currency TEXT NOT NULL,
                        amount REAL NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                c.execute(
                    "INSERT OR REPLACE INTO bulk_job_payments "
                    "(job_id, provider, reference, currency, amount) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (job_id, payment_method, reference, gateway_currency, charge),
                )
                c.execute(
                    """
                    UPDATE bulk_jobs
                    SET payment_method = ?,
                        payment_reference = ?,
                        total_amount = ?,
                        currency = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (payment_method, reference, charge, gateway_currency, job_id),
                )
                conn.commit()
            finally:
                conn.close()

            return jsonify({
                "success": True,
                "requires_payment": True,
                "authorization_url": init["authorization_url"],
                "reference": reference,
                "job_id": job_id,
                "amount": charge, "fee": bulk_fee,
                "currency": gateway_currency,
                "total": len(records),
                "provider": payment_method,
            })

            


    
        def operator_id_for_network(network_name: str, country_code: str, operators: list):
            """Match a canonical network name to a real operator ID.

            `operators` is the list returned by get_operators_by_country().
            Match is case-insensitive and substring-based, so a stored network
            of "MTN" matches an operator named "MTN Nigeria".
            """
            if not network_name or not operators:
                return None
            needle = str(network_name).strip().lower()
            for op in operators:
                op_name = str(op.get("name") or "").strip().lower()
                if not op_name:
                    continue
                if needle == op_name or needle in op_name:
                    return str(op.get("operatorId") or op.get("id"))
            return None            

        # ============ REWARDS ============
        @self.app.route("/api/rewards", methods=["GET"])
        @login_required
        def get_rewards():
            user_id = g.current_user_id
            rewards = db.get_rewards(user_id)
            return jsonify({"success": True, "rewards": rewards})

        # ============ REFERRALS ============
        @self.app.route("/api/referral", methods=["GET"])
        @login_required
        def get_referral_link():
            user = db.get_user(g.current_user_id)
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404
            code = user.get("referral_code")
            if not code:
                return (
                    jsonify({"success": False, "error": "Referral code unavailable"}),
                    400,
                )
            base_url = os.getenv("FRONTEND_URL") or request.host_url.rstrip("/")
            return jsonify(
                {
                    "success": True,
                    "referral_code": code,
                    "invite_url": f"{base_url}/?ref={code}",
                }
            )

        # ============ NOTIFICATIONS ============
        @self.app.route("/api/notifications", methods=["GET"])
        @login_required
        def get_notifications():
            user_id = g.current_user_id
            limit = min(request.args.get("limit", 20, type=int), 100)
            unread_only = request.args.get("unread_only", "false").lower() == "true"

            notifications = db.get_notifications(user_id, limit, unread_only)
            unread_count = db.get_unread_count(user_id)
            return jsonify(
                {
                    "success": True,
                    "notifications": notifications,
                    "unread_count": unread_count,
                }
            )

        # ============ VISITOR TRACKING (ADMIN) ============
        @self.app.route("/api/admin/visitors", methods=["GET"])
        @admin_required
        def get_admin_visitors():
            limit = min(request.args.get("limit", 100, type=int), 500)
            offset = request.args.get("offset", 0, type=int)
            device_type = request.args.get("device_type")
            start_date = request.args.get("start_date")
            end_date = request.args.get("end_date")
            country = request.args.get("country")          # ← NEW

            logs = db.get_visitor_logs(
                limit=limit,
                offset=offset,
                device_type=device_type,
                start_date=start_date,
                end_date=end_date,
                country=country,                           # ← NEW
            )
            if offset == 0 and _enrich_visit_rows(logs):
                logs = db.get_visitor_logs(
                    limit=limit, offset=offset, device_type=device_type,
                    start_date=start_date, end_date=end_date, country=country,
                )
            return jsonify({"success": True, "visitors": logs, "count": len(logs)})

        # ============ ADMIN: RECEIPT PROMOS ============
        @self.app.route("/api/admin/receipt-promos", methods=["GET"])
        @admin_required
        def admin_list_receipt_promos():
            return jsonify({"success": True, "promos": db.get_all_receipt_promos()})

        @self.app.route("/api/admin/receipt-promos", methods=["POST"])
        @admin_required
        def admin_create_receipt_promo():
            data = request.json or {}
            required = ["slot_index", "title", "body"]
            missing = [f for f in required if not data.get(f) and data.get(f) != 0]
            if missing:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"Missing required field(s): {', '.join(missing)}",
                        }
                    ),
                    400,
                )
            promo = db.upsert_receipt_promo(
                promo_id=None,
                slot_index=int(data["slot_index"]),
                title=data["title"],
                body=data["body"],
                cta_text=data.get("cta_text"),
                cta_url=data.get("cta_url"),
                active=bool(data.get("active", True)),
            )
            return jsonify({"success": True, "promo": promo})

        @self.app.route("/api/admin/receipt-promos/<int:promo_id>", methods=["PUT"])
        @admin_required
        def admin_update_receipt_promo(promo_id):
            existing = next(
                (p for p in db.get_all_receipt_promos() if p["id"] == promo_id), None
            )
            if not existing:
                return jsonify({"success": False, "error": "Promo not found"}), 404
            data = request.json or {}
            promo = db.upsert_receipt_promo(
                promo_id=promo_id,
                slot_index=int(data.get("slot_index", existing["slot_index"])),
                title=data.get("title", existing["title"]),
                body=data.get("body", existing["body"]),
                cta_text=data.get("cta_text", existing.get("cta_text")),
                cta_url=data.get("cta_url", existing.get("cta_url")),
                active=bool(data.get("active", existing["active"])),
            )
            return jsonify({"success": True, "promo": promo})

        @self.app.route("/api/admin/receipt-promos/<int:promo_id>", methods=["DELETE"])
        @admin_required
        def admin_delete_receipt_promo(promo_id):
            deleted = db.delete_receipt_promo(promo_id)
            if not deleted:
                return jsonify({"success": False, "error": "Promo not found"}), 404
            return jsonify({"success": True})

        # ============ RECEIPT AD  ============
        @self.app.route("/api/receipt-ads/pricing", methods=["GET"])
        def get_receipt_ad_pricing():
            # Public — the business.html form reads this to show live pricing
            # instead of hardcoding numbers that could drift from the backend.
            return jsonify(
                {
                    "success": True,
                    "price_per_impression": db.RECEIPT_AD_PREMIUM_PRICE_PER_IMPRESSION,
                    "dominant_price_per_impression": 5.0,  # Hardcoded fallback
                    "dominant_price": db.RECEIPT_AD_DOMINANT_PRICE,
                    "dominant_impressions": db.RECEIPT_AD_DOMINANT_IMPRESSIONS,
                    "min_impressions": db.RECEIPT_AD_MIN_IMPRESSIONS,
                    "max_impressions": db.RECEIPT_AD_MAX_IMPRESSIONS,
                    "valid_tx_types": sorted(db.RECEIPT_AD_VALID_TX_TYPES),
                    "dominant_slot_occupied": db.dominant_slot_is_occupied(),
                    "currency": "NGN",
                }
            )

        # ============ PUBLIC RECEIPT (for the success page) ============
        @self.app.route("/receipt/<reference>", methods=["GET"])
        def public_receipt(reference):
            """Serve a receipt PDF immediately after payment, without requiring login.

            Safe because the reference is an unguessable gateway-issued value
            (e.g. PSK_20260101_ABC12345 / STR_... / FLW_...). Anyone who has the
            reference already has the payment details, so this endpoint exposes
            nothing beyond what the payment page itself already shows.

            Rate-limited to prevent enumeration.
            """
            if not reference:
                return jsonify({"success": False, "error": "Missing reference"}), 400

            tx = db.get_transaction(reference)
            if not tx:
                return jsonify({"success": False, "error": "Receipt not found"}), 404

            # Decrypt payload so phone / account fields render correctly
            if tx.get("payload"):
                tx["payload"] = decrypt_payload(tx["payload"])

            receipt_pdf = generate_receipt(tx)
            if not receipt_pdf:
                return jsonify({"success": False, "error": "Failed to generate receipt"}), 500

            response = make_response(receipt_pdf)
            response.headers["Content-Type"] = "application/pdf"
            response.headers["Content-Disposition"] = (
                f"attachment; filename=receipt_{reference}.pdf"
            )
            return response
        


        @self.app.route("/api/receipt-ads/campaigns", methods=["GET"])
        @login_required
        def list_my_receipt_ad_campaigns():
            campaigns = db.get_campaigns_for_advertiser(g.current_user_id)
            return jsonify({"success": True, "campaigns": campaigns})

        @self.app.route("/api/admin/referral-codes", methods=["GET"])
        @admin_required
        def list_referral_codes():
            """List all referral codes in the system."""
            conn = db.get_db_connection()
            c = conn.cursor()

            codes = c.execute("""
                SELECT id, email, full_name, referral_code, created_at 
                FROM users 
                WHERE referral_code IS NOT NULL
                ORDER BY created_at DESC
            """).fetchall()

            conn.close()

            return jsonify(
                {
                    "success": True,
                    "count": len(codes),
                    "codes": [dict(code) for code in codes],
                }
            )

        @self.app.route("/api/admin/referral-bonus/config", methods=["GET"])
        @admin_required
        def get_referral_bonus_config():
            """Get referral bonus configuration."""
            try:
                config = db.get_referral_bonus_config()
                return jsonify({"success": True, "config": config})
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/admin/referral-bonus/config", methods=["POST"])
        @admin_required
        def update_referral_bonus_config():
            """Update referral bonus configuration.

            Called by the admin panel's Bonus/Commission tab. Writes a new row to
            referral_bonus_config (the table is log-style, latest row wins). Every
            payout reads the latest row, so changes take effect on the next
            qualifying transaction — no restart required.
            """
            data = request.json or {}

            bonus_percentage = data.get("bonus_percentage")
            min_bonus = data.get("min_bonus", 50.0)
            max_bonus = data.get("max_bonus", 5000.0)

            # Normalize `enabled` so both boolean False and string "false" behave
            # as False. Without this, sending {"enabled": "false"} would coerce to
            # True via Python's default truthiness, silently ignoring the toggle.
            enabled_raw = data.get("enabled", True)
            if isinstance(enabled_raw, str):
                enabled = enabled_raw.strip().lower() in ("true", "1", "yes", "on")
            else:
                enabled = bool(enabled_raw)

            if bonus_percentage is None:
                return jsonify({
                    "success": False,
                    "error": "bonus_percentage is required",
                }), 400

            try:
                bonus_percentage = float(bonus_percentage)
                min_bonus = float(min_bonus)
                max_bonus = float(max_bonus)
            except (ValueError, TypeError):
                return jsonify({
                    "success": False,
                    "error": "Invalid numeric values",
                }), 400

            if bonus_percentage < 0 or bonus_percentage > 100:
                return jsonify({
                    "success": False,
                    "error": "Percentage must be between 0 and 100",
                }), 400

            if min_bonus < 0:
                return jsonify({
                    "success": False,
                    "error": "Minimum bonus cannot be negative",
                }), 400

            if max_bonus < min_bonus:
                return jsonify({
                    "success": False,
                    "error": "Maximum bonus must be greater than minimum bonus",
                }), 400

            result = db.update_referral_bonus_config(
                bonus_percentage=bonus_percentage,
                min_bonus=min_bonus,
                max_bonus=max_bonus,
                enabled=enabled,
                updated_by=None,
            )

            if result:
                if enabled:
                    message = f"Referral bonuses enabled at {bonus_percentage}%"
                else:
                    message = (
                        f"Referral bonuses disabled. "
                        f"Saved rate: {bonus_percentage}% "
                        f"(will apply when re-enabled)."
                    )
                return jsonify({"success": True, "message": message})

            return jsonify({"success": False, "error": "Failed to update config"}), 500

        def import_contacts_unique(user_id, contacts, phone_field='phone', name_field='name'):
            """Import multiple contacts for a user, skipping duplicates by phone/email.

            Args: user_id, contacts (list of dicts), phone_field, name_field
            Returns: {success, added, skipped, updated, errors}
            """
            conn = db.get_db_connection()          # ← was bare get_db_connection()
            c = conn.cursor()

            added = 0
            skipped = 0
            updated = 0
            errors = []

            try:
                for contact in contacts:
                    if not isinstance(contact, dict):
                        skipped += 1
                        continue

                    phone = str(contact.get(phone_field) or contact.get('phone') or '').strip()
                    email = str(contact.get('email') or '').strip().lower()
                    name = str(contact.get(name_field) or contact.get('name') or '').strip()
                    network = str(contact.get('network') or '').strip()
                    country = str(contact.get('country') or '').strip()

                    if not phone and not email:
                        skipped += 1
                        continue

                    clean_phone = re.sub(r'[^\d+]', '', phone)
                    if not clean_phone or len(clean_phone) < 5:
                        skipped += 1
                        continue

                    # Look up an existing row by phone first, then by email
                    existing = None
                    if clean_phone:
                        existing = c.execute(
                            "SELECT id FROM contacts WHERE user_id = ? AND phone = ?",
                            (user_id, clean_phone)
                        ).fetchone()
                    if not existing and email:
                        existing = c.execute(
                            "SELECT id FROM contacts WHERE user_id = ? AND email = ?",
                            (user_id, email)
                        ).fetchone()

                    if existing:
                        existing_id = existing["id"] if hasattr(existing, "keys") else existing[0]
                        c.execute(
                            """
                            UPDATE contacts
                            SET name = COALESCE(NULLIF(?, ''), name),
                                network = COALESCE(NULLIF(?, ''), network),
                                country = COALESCE(NULLIF(?, ''), country),
                                email = COALESCE(NULLIF(?, ''), email),
                                updated_at = CURRENT_TIMESTAMP
                            WHERE id = ? AND user_id = ?
                            """,
                            (name, network, country, email, existing_id, user_id)
                        )
                        updated += 1
                    else:
                        c.execute(
                            """
                            INSERT INTO contacts
                                (user_id, name, phone, email, network, country, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                            """,
                            (user_id, name or 'Contact', clean_phone, email, network, country)
                        )
                        added += 1

                conn.commit()
                return {
                    'success': True,
                    'added': added,
                    'skipped': skipped,
                    'updated': updated,
                    'errors': errors
                }

            except Exception as e:
                conn.rollback()
                logger.error(f"import_contacts_unique failed: {e}")
                return {
                    'success': False,
                    'error': str(e),
                    'added': added,
                    'skipped': skipped,
                    'updated': updated
                }
            finally:
                conn.close()
        
        
        
        
       # ============ BULK RECHARGE API ============
        # ============ BULK RECHARGE API ============
        @self.app.route("/api/bulk/recharge", methods=["POST"])
        @login_required
        @email_verified_required
        def bulk_recharge_upload():
            """Handle CSV/TXT upload — either a recharge list or a contact list.

            Two formats are supported, detected by the header row:

            1. Recharge list:  phone,amount,operator_id,country_code
            2. Contact list:   name,phone,network

            The contact-list format is what "import contacts with their
            network" uses. It creates/updates contacts, so the network is
            stored once and reused by future bulk recharges.
            """
            user_id = g.current_user_id

            file = request.files.get("file")
            if not file or not file.filename:
                return jsonify({"success": False, "error": "No file uploaded"}), 400

            allowed = (".csv", ".txt")
            if not file.filename.lower().endswith(allowed):
                return jsonify({"success": False, "error": "Only .csv or .txt files are allowed"}), 400

            try:
                raw = file.read().decode("utf-8-sig", errors="ignore")
            except Exception as e:
                return jsonify({"success": False, "error": f"Could not read file: {e}"}), 400

            lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
            if not lines:
                return jsonify({"success": False, "error": "File is empty"}), 400

            # ------------------------------------------------------------------
            # Detect the format from the first non-empty line.
            # ------------------------------------------------------------------
            header = [c.strip().lower() for c in lines[0].split(",")]
            header_set = set(header)

            is_contact_list = (
                ("name" in header_set or "full_name" in header_set)
                and "phone" in header_set
                and "amount" not in header_set
            )

            if is_contact_list:
                return self._import_contacts_with_networks(user_id, lines, header)

            # ------------------------------------------------------------------
            # Otherwise: existing "recharge list" flow (phone,amount,operator_id,country)
            # ------------------------------------------------------------------
            start_index = 0
            if any(h in header_set for h in ("phone", "mobile", "number", "amount")):
                start_index = 1

            records = []
            errors = []
            for i, line in enumerate(lines[start_index:], start=start_index + 1):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 2:
                    errors.append(f"Line {i}: expected at least phone,amount")
                    continue

                phone_raw = parts[0]
                try:
                    amount = float(parts[1])
                except (ValueError, TypeError):
                    errors.append(f"Line {i}: invalid amount '{parts[1]}'")
                    continue

                operator_id = parts[2] if len(parts) > 2 and parts[2] else None
                country_code = (parts[3] if len(parts) > 3 and parts[3] else "NG").upper()

                clean = re.sub(r"[^0-9]", "", phone_raw)
                if country_code == "NG":
                    while clean.startswith("0"):
                        clean = clean[1:]
                    if len(clean) == 10:
                        clean = "234" + clean
                    elif len(clean) == 11:
                        clean = "234" + clean
                    if len(clean) != 13 or not clean.startswith("234"):
                        errors.append(f"Line {i}: invalid Nigerian phone '{phone_raw}'")
                        continue

                records.append({
                    "phone": clean,
                    "amount": amount,
                    "operator_id": operator_id,
                    "country_code": country_code,
                })

            if not records:
                return jsonify({
                    "success": False,
                    "error": "No valid records found in file",
                    "errors": errors[:20],
                }), 400

            if len(records) > 1000:
                return jsonify({"success": False, "error": "Maximum 1000 records per upload"}), 400

            import uuid as _uuid
            job_id = str(_uuid.uuid4())
            conn = db.get_db_connection()
            c = conn.cursor()
            try:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS bulk_jobs (
                        id TEXT PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        total INTEGER DEFAULT 0,
                        processed INTEGER DEFAULT 0,
                        successful INTEGER DEFAULT 0,
                        failed INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'pending',
                        error TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                c.execute(
                    "INSERT INTO bulk_jobs (id, user_id, total, status) VALUES (?, ?, ?, 'pending')",
                    (job_id, user_id, len(records)),
                )
                conn.commit()
            finally:
                conn.close()

            threading.Thread(
                target=self._process_bulk_job,
                args=(job_id, user_id, records),
                daemon=True,
            ).start()

            return jsonify({
                "success": True,
                "job_id": job_id,
                "total": len(records),
                "skipped_lines": len(errors),
                "message": f"Bulk job created with {len(records)} records",
            })
        
        def _import_contacts_with_networks(self, user_id, lines, header):
            """Import a name,phone,network list into the contacts table.

            Normalizes each network name to its canonical form, upserts the
            contacts (creating new ones, updating existing ones with the new
            network if provided), and returns a summary.
            """
            col_index = {name: idx for idx, name in enumerate(header)}
            name_i = col_index.get("name", col_index.get("full_name", 0))
            phone_i = col_index["phone"]
            network_i = col_index.get("network")   # may be None
            email_i = col_index.get("email")
            country_i = col_index.get("country")

            if network_i is None:
                return jsonify({
                    "success": False,
                    "error": "Contact-list format requires a 'network' column. "
                             "Example header: name,phone,network",
                }), 400

            contacts = []
            errors = []

            for i, line in enumerate(lines[1:], start=2):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) <= max(name_i, phone_i, network_i):
                    errors.append(f"Line {i}: not enough columns")
                    continue

                raw_phone = parts[phone_i]
                clean_phone = re.sub(r"[^0-9+]", "", raw_phone)
                if len(clean_phone) < 8:
                    errors.append(f"Line {i}: invalid phone '{raw_phone}'")
                    continue

                network_raw = parts[network_i]
                network = normalize_network(network_raw)
                if not network:
                    errors.append(
                        f"Line {i}: unrecognized network '{network_raw}' "
                        f"(expected one of: MTN, Glo, Airtel, 9mobile)"
                    )
                    continue

                contact = {
                    "name": parts[name_i] or "Contact",
                    "phone": clean_phone,
                    "network": network,
                }
                if email_i is not None and len(parts) > email_i:
                    contact["email"] = parts[email_i].strip().lower()
                if country_i is not None and len(parts) > country_i:
                    contact["country"] = parts[country_i].strip().upper()
                contacts.append(contact)

            if not contacts:
                return jsonify({
                    "success": False,
                    "error": "No valid contacts found in file",
                    "errors": errors[:20],
                }), 400

            result = db.import_contacts_unique(
                user_id, contacts, phone_field="phone", name_field="name"
            )

            # Give the caller a clear, compact summary
            return jsonify({
                "success": result.get("success", False),
                "added": result.get("added", 0),
                "updated": result.get("updated", 0),
                "skipped": result.get("skipped", 0),
                "errors": errors[:20] + (result.get("errors") or [])[:20],
                "message": (
                    f"{result.get('added', 0)} new contacts imported, "
                    f"{result.get('updated', 0)} updated"
                ),
            })        

        @self.app.route("/api/admin/debug/referral-codes", methods=["GET"])
        @admin_required
        def debug_all_referral_codes():
            """Debug endpoint to see all referral codes."""
            conn = db.get_db_connection()
            c = conn.cursor()

            codes = c.execute("""
                SELECT id, email, full_name, referral_code, created_at 
                FROM users 
                WHERE referral_code IS NOT NULL
                ORDER BY created_at DESC
            """).fetchall()

            conn.close()

            return jsonify(
                {
                    "success": True,
                    "total": len(codes),
                    "codes": [
                        {
                            "id": code["id"],
                            "email": code["email"],
                            "full_name": code["full_name"],
                            "referral_code": code["referral_code"],
                            "created_at": code["created_at"],
                        }
                        for code in codes
                    ],
                }
            )

        @self.app.route("/api/admin/debug/referral/<code>", methods=["GET"])
        @admin_required
        def debug_referral_code(code):
            """Debug endpoint to check if a referral code exists."""
            conn = db.get_db_connection()
            c = conn.cursor()

            # Search for the code exactly as provided
            exact = c.execute(
                "SELECT id, email, full_name, referral_code FROM users WHERE referral_code = ?",
                (code,),
            ).fetchone()

            # Search case-insensitive
            case_insensitive = c.execute(
                "SELECT id, email, full_name, referral_code FROM users WHERE UPPER(referral_code) = UPPER(?)",
                (code,),
            ).fetchone()

            # Search with NET- prefix
            with_prefix = c.execute(
                "SELECT id, email, full_name, referral_code FROM users WHERE UPPER(referral_code) = UPPER(?)",
                (f"NET-{code}",),
            ).fetchone()

            conn.close()

            return jsonify(
                {
                    "success": True,
                    "search_code": code,
                    "exact_match": dict(exact) if exact else None,
                    "case_insensitive_match": (
                        dict(case_insensitive) if case_insensitive else None
                    ),
                    "with_net_prefix": dict(with_prefix) if with_prefix else None,
                }
            )

        @self.app.route("/api/admin/process-referrals", methods=["POST"])
        @admin_required
        def process_pending_referrals():
            """Process all pending referral rewards."""
            try:
                result = db.process_pending_referrals()
                return jsonify(
                    {
                        "success": True,
                        "processed": result["processed"],
                        "errors": result["errors"],
                        "message": result["message"],
                    }
                )
            except Exception as e:
                logger.error(f"Error processing referrals: {e}")
                return jsonify({"success": False, "error": str(e)}), 500
            # ============ AUTH ROUTES ============

        @self.app.route("/api/auth/register", methods=["POST"])
        @rate_limit(max_requests=5, window_seconds=300)
        def register_user():
            data = request.get_json(silent=True) or {}
            email = data.get("email")
            password = data.get("password")
            full_name = data.get("full_name")
            phone = data.get("phone")
            referral_code = data.get("referral_code", "").strip().upper()

            # Terms of Service: the sign-up must carry the customer's acceptance (net365_legal.py).
            try:
                from net365_legal import signup_terms_error
                _terms_err = signup_terms_error(data)
            except ImportError:
                _terms_err = None
            if _terms_err:
                return jsonify(_terms_err[0]), _terms_err[1]

            # DEFAULT REFERRAL CODE - allowed for all users
            DEFAULT_REFERRAL_CODE = "00000"

            if not email or not password:
                return (
                    jsonify({"success": False, "error": "Email and password required"}),
                    400,
                )

            _pw_err = validate_password_strength(password)
            if _pw_err:
                return jsonify({"success": False, "error": _pw_err}), 400

            existing = db.get_user_by_email(email)
            if existing:
                return (
                    jsonify({"success": False, "error": "Email already registered"}),
                    400,
                )

            # ============================================================
            # FIX: Handle referral code with proper connection management
            # ============================================================

            logger.info(f"Registration attempt with referral_code: {referral_code}")

            # If no referral code provided, set to None
            if not referral_code:
                referral_code = None
                logger.info(f"Registration with no referral code for {email}")

            # If it's the default code, set to None
            elif referral_code == DEFAULT_REFERRAL_CODE:
                referral_code = None
                logger.info(f"Registration with default referral code for {email}")

            # If it's a real referral code, validate it
            else:
                conn = None
                try:
                    conn = db.get_db_connection()
                    c = conn.cursor()

                    referrer = None

                    # 1. Try exact match (most common)
                    referrer = c.execute(
                        "SELECT id, full_name, email FROM users WHERE UPPER(referral_code) = UPPER(?)",
                        (referral_code,),
                    ).fetchone()
                    logger.info(
                        f"Exact match for {referral_code}: {referrer is not None}"
                    )

                    # 2. If not found, try removing any "NET-" prefix
                    if not referrer and referral_code.startswith("NET-"):
                        clean_code = referral_code[4:]
                        referrer = c.execute(
                            "SELECT id, full_name, email FROM users WHERE UPPER(referral_code) = UPPER(?)",
                            (clean_code,),
                        ).fetchone()
                        logger.info(
                            f"After removing NET- prefix: {clean_code} -> {referrer is not None}"
                        )

                    # 3. If still not found, try adding "NET-" prefix
                    if not referrer and not referral_code.startswith("NET-"):
                        referrer = c.execute(
                            "SELECT id, full_name, email FROM users WHERE UPPER(referral_code) = UPPER(?)",
                            (f"NET-{referral_code}",),
                        ).fetchone()
                        logger.info(
                            f"After adding NET- prefix: NET-{referral_code} -> {referrer is not None}"
                        )

                    # 4. Try partial match
                    if not referrer and len(referral_code) >= 4:
                        referrer = c.execute(
                            "SELECT id, full_name, email FROM users WHERE UPPER(referral_code) LIKE UPPER(?)",
                            (f"%{referral_code}%",),
                        ).fetchone()
                        logger.info(f"Partial match: {referrer is not None}")

                    if not referrer:
                        logger.warning(
                            f"❌ Invalid referral code attempted during registration: {referral_code}"
                        )
                        referral_code = None
                    else:
                        logger.info(
                            f"✅ Valid referral code {referral_code} from user {referrer['id']} ({referrer['full_name']})"
                        )
                        # Store the referrer info for later use
                        referrer_id = referrer["id"]
                        referrer_name = referrer["full_name"]

                except Exception as e:
                    logger.error(f"Error validating referral code: {e}")
                    referral_code = None
                finally:
                    if conn:
                        conn.close()

            # ============================================================
            # Create the user
            # ============================================================
            user_id = db.create_user(
                email=email,
                password=password,
                full_name=full_name,
                phone=phone,
                referral_code=referral_code,  # None for default, or actual code
            )

            if user_id:
                try:
                    from net365_legal import record_signup_acceptance
                    record_signup_acceptance(user_id, data, get_client_ip(), request.headers.get("User-Agent", ""))
                except ImportError:
                    pass
                # ============================================================
                # If it's a REAL referral code (not default), create the referral relationship
                # ============================================================
                if referral_code:
                    try:
                        conn = db.get_db_connection()
                        c = conn.cursor()

                        # Find the referrer again
                        referrer = c.execute(
                            "SELECT id FROM users WHERE UPPER(referral_code) = UPPER(?)",
                            (referral_code,),
                        ).fetchone()

                        if not referrer and referral_code.startswith("NET-"):
                            clean_code = referral_code[4:]
                            referrer = c.execute(
                                "SELECT id FROM users WHERE UPPER(referral_code) = UPPER(?)",
                                (clean_code,),
                            ).fetchone()

                        if not referrer and not referral_code.startswith("NET-"):
                            referrer = c.execute(
                                "SELECT id FROM users WHERE UPPER(referral_code) = UPPER(?)",
                                (f"NET-{referral_code}",),
                            ).fetchone()

                        if referrer and referrer["id"] != user_id:
                            # Check if referral already exists
                            existing_referral = c.execute(
                                "SELECT id FROM referrals WHERE referrer_id = ? AND referred_id = ?",
                                (referrer["id"], user_id),
                            ).fetchone()

                            if not existing_referral:
                                # Create referral record
                                c.execute(
                                    """
                                    INSERT INTO referrals (referrer_id, referred_id, status, created_at)
                                    VALUES (?, ?, 'pending', CURRENT_TIMESTAMP)
                                    """,
                                    (referrer["id"], user_id),
                                )
                                conn.commit()
                                logger.info(
                                    f"✅ Referral created: referrer={referrer['id']}, referred={user_id}"
                                )

                                # Notify the referrer
                                try:
                                    db.create_notification(
                                        referrer["id"],
                                        "👤 New Referral!",
                                        f"A new user used your referral code to join Net365!",
                                        "success",
                                    )
                                except Exception as e:
                                    logger.error(
                                        f"Failed to create referrer notification: {e}"
                                    )

                                # Notify the new user
                                try:
                                    db.create_notification(
                                        user_id,
                                        "🎉 Referral Code Applied!",
                                        f"You've been referred by someone! Complete your first transaction to earn rewards!",
                                        "success",
                                    )
                                except Exception as e:
                                    logger.error(
                                        f"Failed to create referred user notification: {e}"
                                    )

                        conn.close()

                    except Exception as e:
                        logger.error(f"Failed to create referral relationship: {e}")

                # ============================================================
                # Send verification OTP
                # ============================================================
                otp_sent = False
                try:
                    code = db.create_verification_otp(
                        email, otp_type="email", ttl_minutes=10
                    )
                    otp_sent = send_email_notification(
                        email,
                        "Verify your Net365 account",
                        f'Your verification code is <span class="amount">{code}</span>. '
                        f"It expires in 10 minutes. Enter it in the app to verify your email "
                        f"and unlock wallet funding and payments.",
                        wait_seconds=8,  # OTP flow needs a real success/fail answer, but bounded
                    )
                    if not otp_sent:
                        logger.warning(
                            f"Could not send verification email to {email} (SMTP not configured?)"
                        )
                except Exception as e:
                    logger.error(
                        f"Failed to create/send verification OTP for {email}: {e}"
                    )
                # Send welcome email from the CEO (fire-and-forget; never blocks signup)
                try:
                    send_welcome_once(user_id, email, full_name or "", "web")
                except Exception as e:
                    logger.error(f"Welcome email dispatch error for {email}: {e}")

                # ============================================================
                # Create session and return response
                # ============================================================
                session_token = db.create_session(user_id)
                response = make_response(
                    jsonify(
                        {
                            "success": True,
                            "user_id": user_id,
                            "user": sanitize_user(db.get_user(user_id)),
                            "message": "Registration successful!",
                            "verification_email_sent": otp_sent,
                            "referral_code_applied": (
                                referral_code if referral_code else None
                            ),
                            "has_referral": bool(referral_code),
                        }
                    )
                )
                return set_auth_cookie(response, session_token)

            return jsonify({"success": False, "error": "Registration failed"}), 400

        @self.app.route("/api/auth/verify-email", methods=["POST"])
        @rate_limit(max_requests=10, window_seconds=300)
        def verify_email():
            data = request.json or {}
            email = data.get("email")
            code = data.get("code")
            if not email or not code:
                return (
                    jsonify({"success": False, "error": "Email and code required"}),
                    400,
                )

            ok = db.verify_otp(email, code, otp_type="email")
            if ok:
                return jsonify(
                    {"success": True, "message": "Email verified successfully!"}
                )
            return jsonify({"success": False, "error": "Invalid or expired code"}), 400

        @self.app.route("/api/auth/resend-otp", methods=["POST"])
        @rate_limit(max_requests=3, window_seconds=300)
        def resend_otp():
            data = request.json or {}
            email = data.get("email")
            if not email:
                return jsonify({"success": False, "error": "Email required"}), 400

            user = db.get_user_by_email(email)
            if not user:
                # Don't reveal whether the email exists — respond the same either way.
                return jsonify(
                    {
                        "success": True,
                        "message": "If that email is registered, a code has been sent.",
                    }
                )
            if user.get("email_verified"):
                return (
                    jsonify({"success": False, "error": "Email already verified"}),
                    400,
                )

            try:
                code = db.create_verification_otp(
                    email, otp_type="email", ttl_minutes=10
                )
                send_email_notification(
                    email,
                    "Your Net365 verification code",
                    f'Your verification code is <span class="amount">{code}</span>. It expires in 10 minutes.',
                )
            except Exception as e:
                logger.error(f"Failed to resend verification OTP for {email}: {e}")

            return jsonify(
                {
                    "success": True,
                    "message": "If that email is registered, a code has been sent.",
                }
            )

        @self.app.route("/api/auth/change-password", methods=["POST"])
        @login_required
        def change_password():
            data = request.json or {}
            current_password = data.get("current_password")
            new_password = data.get("new_password")
            if not current_password or not new_password:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Current and new password are required",
                        }
                    ),
                    400,
                )
            if len(new_password) < 8:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "New password must be at least 8 characters",
                        }
                    ),
                    400,
                )

            result = db.change_password(
                g.current_user_id, current_password, new_password
            )
            if not result.get("success"):
                return jsonify(result), 400

            log_event(
                user_id=g.current_user_id,
                event_type="password_change",
                details={"method": "self_service"},
                status="success",
            )
            return jsonify(
                {"success": True, "message": "Password changed successfully."}
            )

        @self.app.route("/api/auth/forgot-password", methods=["POST"])
        @rate_limit(max_requests=5, window_seconds=300)
        def forgot_password():
            data = request.json or {}
            email = data.get("email")
            if not email:
                return jsonify({"success": False, "error": "Email required"}), 400

            user = db.get_user_by_email(email)
            # Same response whether or not the account exists — don't leak which emails
            # are registered.
            generic_response = jsonify(
                {
                    "success": True,
                    "message": "If that email is registered, a reset code has been sent.",
                }
            )
            if not user:
                return generic_response

            try:
                code = db.create_verification_otp(
                    email, otp_type="password_reset", ttl_minutes=15
                )
                send_email_notification(
                    email,
                    "Reset your Net365 password",
                    f'Your password reset code is <span class="amount">{code}</span>. '
                    f"It expires in 15 minutes. If you did not request this, you can safely ignore this email.",
                )
                log_event(
                    user_id=user["id"],
                    event_type="password_reset_requested",
                    details={},
                    status="success",
                )
            except Exception as e:
                logger.error(f"Failed to send password reset OTP for {email}: {e}")

            return generic_response

        @self.app.route("/api/auth/reset-password", methods=["POST"])
        @rate_limit(max_requests=10, window_seconds=300)
        def reset_password():
            data = request.json or {}
            email = data.get("email")
            code = data.get("code")
            new_password = data.get("new_password")
            if not email or not code or not new_password:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Email, code, and new password are required",
                        }
                    ),
                    400,
                )
            if len(new_password) < 8:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "New password must be at least 8 characters",
                        }
                    ),
                    400,
                )

            if not db.verify_otp(email, code, otp_type="password_reset"):
                return (
                    jsonify({"success": False, "error": "Invalid or expired code"}),
                    400,
                )

            user = db.get_user_by_email(email)
            if not user:
                return jsonify({"success": False, "error": "Account not found"}), 404

            db.set_password(user["id"], new_password)
            # A password reset is exactly the moment to invalidate every existing
            # session — if the reset was needed because of a compromised account, an
            # attacker's live session should not survive it.
            db.kill_user_sessions(user["id"])
            log_event(
                user_id=user["id"],
                event_type="password_reset_completed",
                details={},
                status="success",
            )

            return jsonify(
                {
                    "success": True,
                    "message": "Password reset successfully. Please log in with your new password.",
                }
            )

        # ============ GOOGLE SIGN-IN / SIGN-UP ============
        google_client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
        google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
        self.google_oauth = None
        if AUTH_LIB_AVAILABLE and google_client_id and google_client_secret:
            _oauth = OAuth(self.app)
            _oauth.register(
                name="google",
                client_id=google_client_id,
                client_secret=google_client_secret,
                server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
                client_kwargs={"scope": "openid email profile"},
            )
            self.google_oauth = _oauth.google
            logger.info("Google OAuth enabled")
        else:
            logger.warning(
                "Google OAuth disabled (authlib=%s, client_id=%s, secret=%s)",
                AUTH_LIB_AVAILABLE, bool(google_client_id), bool(google_client_secret),
            )

        def _google_fail(msg):
            from urllib.parse import quote
            return redirect(f"{FRONTEND_URL}/?google_error={quote(msg)}")

        @self.app.route("/api/auth/google/login", methods=["GET"])
        def google_login():
            if not self.google_oauth:
                return _google_fail("Google sign-in is not configured on this server")
            ref = (request.args.get("ref") or "").strip()
            if ref:
                session["google_ref"] = ref[:32]
            redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "").strip() or url_for(
                "google_callback", _external=True
            )
            return self.google_oauth.authorize_redirect(redirect_uri)

        @self.app.route("/api/auth/google/callback", methods=["GET"])
        def google_callback():
            if not self.google_oauth:
                return _google_fail("Google sign-in is not configured")
            if request.args.get("error"):
                return _google_fail("Google sign-in was cancelled")
            try:
                token = self.google_oauth.authorize_access_token()
                info = token.get("userinfo") or self.google_oauth.userinfo()
            except Exception as e:
                logger.error(f"Google OAuth callback failed: {e}")
                _msg = ("Google sign-in could not finish. If you started from Telegram or WhatsApp, open the link from your chat "
                        "in Chrome or Safari (not inside the chat app), then try again.")
                if session.get("chat_link_token"):
                    from net365_whatsapp import _google_page
                    return _google_page(False, _msg)
                return _google_fail(_msg)

            email = (info.get("email") or "").strip().lower()
            if not email or not info.get("email_verified", False):
                return _google_fail("Your Google email is not verified")

            try:
                user = db.get_user_by_email(email)
                if not user:
                    ref = session.pop("google_ref", None)
                    user_id = db.create_user(
                        email=email,
                        password=None,
                        full_name=info.get("name") or email.split("@")[0],
                        referral_code=ref,
                    )
                    if not user_id:
                        return _google_fail("Could not create your account")
                    user = db.get_user_by_email(email)
                    try:
                        send_welcome_once(user_id, email, (user or {}).get("full_name") or info.get("name") or "", "google")
                    except Exception as _we:
                        logger.error(f"Welcome email dispatch error for {email}: {_we}")
                session.pop("google_ref", None)

                status = user.get("account_status") or "active"
                if status in ("suspended", "blocked", "deleted"):
                    return _google_fail(f"This account has been {status}")

                # Google has verified the address. If this Net365 account already existed but was never
                # email-verified, someone else may have registered it with the victim's address and a
                # password they chose ("pre-hijacking"). Signing the real owner in through Google must
                # not hand them that account: clear the old password (they can set a new one by
                # email) and end every existing session before marking it verified.
                if not user.get("email_verified"):
                    conn = db.get_db_connection()
                    try:
                        conn.execute(
                            "UPDATE users SET password_hash = NULL, email_verified = 1, "
                            "verified_at = CURRENT_TIMESTAMP WHERE id = ?",
                            (user["id"],),
                        )
                    finally:
                        conn.close()
                    try:
                        db.kill_user_sessions(user["id"])
                    except Exception as e:
                        logger.error(f"Could not end old sessions for user {user['id']}: {e}")
                    logger.warning(
                        f"Google sign-in verified a previously unverified account (user {user['id']}); "
                        f"password cleared and sessions revoked"
                    )

                # Started from a chat (WhatsApp/Telegram)? Then this sign-in only proves the Google identity to that
                # one chat link. It must NOT open a website session in this browser.
                _chat_tok = session.pop("chat_link_token", None)
                logger.info("google callback on host %s: chat link token %s", request.host, "present" if _chat_tok else "MISSING (treated as a website sign-in)")
                if _chat_tok:
                    from net365_whatsapp import google_link_finish
                    return google_link_finish(_chat_tok, user, info)

                _go = "/"
                try:
                    from net365_identity import record_identity, profile_status, mode as _id_mode
                    record_identity(user["id"], "google", info.get("sub"))
                    # Verification is optional by default: never redirect unless the business chose to enforce it.
                    if _id_mode() == "enforce" and not profile_status(user["id"])["complete"]:
                        _go = "/complete-profile"
                except Exception as _ie:
                    logger.warning(f"identity check after Google sign-in failed: {_ie}")
                session_token = db.create_session(user["id"])
                response = make_response(redirect(f"{FRONTEND_URL}{_go}"))
                return set_auth_cookie(response, session_token)
            except Exception as e:
                logger.error(f"Google login error: {e}", exc_info=True)
                return _google_fail("Something went wrong. Please try again.")

        @self.app.route("/api/auth/login", methods=["POST"])
        @rate_limit(max_requests=5, window_seconds=300)
        def login_user():
            data = request.json
            email = data.get("email")
            password = data.get("password")

            if not email or not password:
                return (
                    jsonify({"success": False, "error": "Email and password required"}),
                    400,
                )

            user = db.authenticate_user(email, password)
            if user:
                status = user.get("account_status") or "active"
                if status in ("suspended", "blocked", "deleted"):
                    logger.warning(
                        f"Login blocked for {status} account: user_id={user['id']}"
                    )
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"This account has been {status}. Contact support if you believe this is a mistake.",
                                "error_code": f"ACCOUNT_{status.upper()}",
                            }
                        ),
                        403,
                    )
                session_token = db.create_session(user["id"])
                response = make_response(
                    jsonify(
                        {
                            "success": True,
                            "user": sanitize_user(user),
                            "message": "Login successful!",
                        }
                    )
                )
                return set_auth_cookie(response, session_token)

            return (
                jsonify({"success": False, "error": "Invalid email or password"}),
                401,
            )

        @self.app.route("/api/auth/logout", methods=["POST"])
        @login_required
        def logout_user():
            token = _get_request_token()
            if token:
                db.delete_session(token)

            response = make_response(
                jsonify({"success": True, "message": "Logged out successfully"})
            )
            response.set_cookie(
                SESSION_COOKIE_NAME,
                "",
                expires=0,
                max_age=0,
                path="/",
                httponly=True,
                secure=SESSION_COOKIE_SECURE,
                samesite=SESSION_COOKIE_SAMESITE,
                domain=SESSION_COOKIE_DOMAIN,
            )
            return response

        @self.app.route("/api/auth/me", methods=["GET"])
        @login_required
        def auth_me():
            return jsonify({"success": True, "user": sanitize_user(g.current_user)})

        @self.app.route("/api/auth/user/by-email", methods=["GET"])
        @login_required
        def get_user_by_email_route():
            email = request.args.get("email")
            if not email:
                return jsonify({"success": False, "error": "Email required"}), 400
            user = db.get_user_by_email(email)
            if user:
                return jsonify(
                    {
                        "success": True,
                        "user": {
                            "id": user.get("id"),
                            "full_name": user.get("full_name"),
                        },
                    }
                )
            return jsonify({"success": False, "error": "User not found"}), 404

        @self.app.route("/api/auth/user/by-phone", methods=["GET"])
        @login_required
        def get_user_by_phone_route():
            phone = request.args.get("phone")
            if not phone:
                return jsonify({"success": False, "error": "Phone required"}), 400
            user = db.get_user_by_phone(phone)
            if user:
                return jsonify(
                    {
                        "success": True,
                        "user": {
                            "id": user.get("id"),
                            "full_name": user.get("full_name"),
                        },
                    }
                )
            return jsonify({"success": False, "error": "User not found"}), 404

        # ============ COUNTRIES AND OPERATORS ============
        @self.app.route("/api/countries", methods=["GET"])
        def get_countries():
            try:
                return jsonify(self.platform.get_countries())
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 503

        @self.app.route("/api/operators/country/<country_code>", methods=["GET"])
        def get_operators_by_country(country_code):
            code = (country_code or "").strip().upper()
            if len(code) != 2 or not code.isalpha():
                return (
                    jsonify({"success": False, "error": "Invalid ISO country code."}),
                    400,
                )
            try:
                operators = self.platform.get_operators_for_country(code)
                return jsonify(operators)
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 503
                
                
        @self.app.route("/api/operators/auto-detect", methods=["GET"])
        def auto_detect_operator():
            phone = request.args.get("phone")
            country_code = (request.args.get("country_code") or "NG").upper()
            if not phone:
                return jsonify({"success": False, "error": "Phone number required"}), 400

            # 1. Ask Reloadly (authoritative in live mode; frequently 400s in sandbox).
            try:
                result = self.platform.auto_detect_operator(phone, country_code)
            except Exception as e:
                logger.warning(f"auto-detect route: Reloadly unreachable for {phone}: {e}")
                result = {"success": False, "error": str(e)}

            if result.get("success") and result.get("operator"):
                return jsonify(result)

            # 2. Sandbox fallback.
            #    Reloadly's sandbox rejects real numbers, so a 400 here is expected —
            #    not evidence the number is invalid. Ask Reloadly which operators
            #    actually exist for this country (a different endpoint, which DOES
            #    work with real data in sandbox) and use a real one — no hardcoded
            #    guesses, works for any country Reloadly supports, nothing to
            #    manually verify or maintain as numbers get added/ported over time.
            if self.credentials.environment == Environment.SANDBOX:
                fallback = self.platform._sandbox_operator_fallback(country_code)
                if fallback:
                    logger.info(
                        f"auto-detect: sandbox fallback for {phone} ({country_code}) "
                        f"→ operator {fallback['operatorId']} ({fallback['name']}) "
                        f"[live operator data, not a guess]"
                    )
                    return jsonify({
                        "success": True,
                        "operator": fallback,
                        "source": "sandbox_fallback",
                        "warning": (
                            "Reloadly's sandbox only recognizes its own test phone "
                            "numbers, not real ones, so exact-number detection isn't "
                            "possible here. This is a real, verified operator for the "
                            "country — not a guess — so the top-up flow can be tested "
                            "end to end. Production credentials get genuine "
                            "per-number detection automatically, no code changes needed."
                        ),
                    })

            # 3. Live fallback: prefix table (Nigeria only, currently).
            fallback = detect_operator_from_prefix(phone, country_code)
            if fallback:
                logger.info(
                    f"auto-detect: prefix fallback for {phone} ({country_code}) "
                    f"→ operator {fallback['operatorId']} ({fallback['name']})"
                )
                return jsonify({
                    "success": True,
                    "operator": fallback,
                    "source": "prefix_fallback",
                    "warning": (
                        "Network inferred from number prefix — may be wrong if the "
                        "number has been ported."
                    ),
                })

            # 4. Nothing worked. Return Reloadly's original error so the frontend
            #    can show a meaningful message instead of a generic failure.
            return jsonify(result)

        @self.app.route("/api/operators/<operator_id>", methods=["GET"])
        def get_operator_details(operator_id):
            return jsonify(self.platform.get_operator_by_id(operator_id))

        @self.app.route("/api/balance", methods=["GET"])
        @admin_required
        def get_balance():
            try:
                return jsonify(self.platform.get_balance())
            except Exception as e:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Unable to retrieve platform balance",
                            "balance": 0,
                            "currency": "USD",
                        }
                    ),
                    500,
                )

        @self.app.route("/api/admin/email-test", methods=["GET", "POST"])
        @admin_required
        def admin_email_test():
            """Sends one real test email and reports the provider's exact answer.
            Usage: GET /api/admin/email-test?to=you@example.com with header X-Admin-Secret."""
            to = (request.values.get("to") or "").strip()
            info = {
                "resend_key_set": bool(os.getenv("RESEND_API_KEY")),
                "mailgun_api_key_set": bool(os.getenv("MAILGUN_API_KEY")),
                "mailgun_domain": os.getenv("MAILGUN_DOMAIN") or None,
                "mailgun_api_base": os.getenv("MAILGUN_API_BASE", "https://api.mailgun.net"),
                "smtp_user_set": bool(os.getenv("SMTP_USER")),
                "from_email": os.getenv("FROM_EMAIL") or None,
            }
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", to):
                return jsonify({"success": False, "error": "Add ?to=<your email address>", **info}), 400
            if not _https_email_configured():
                return jsonify({"success": False, "provider": None, **info,
                                "error": "No HTTPS email provider configured. Render free services block SMTP, so set "
                                         "RESEND_API_KEY or MAILGUN_API_KEY + MAILGUN_DOMAIN on THIS service and redeploy."}), 200
            from_name = os.getenv("FROM_NAME", "Net365 Support")
            from_email = os.getenv("FROM_EMAIL") or f"support@{os.getenv('MAILGUN_DOMAIN') or 'net365co.com'}"
            _r = {}
            _send_via_https_provider(f"{from_name} <{from_email}>", to, "Net365 email test",
                                     "<p>If you can read this, Net365 email works.</p>", None, None, _r,
                                     "If you can read this, Net365 email works.", from_email)
            _dom = os.getenv("MAILGUN_DOMAIN") or ""
            hints = []
            if "sandbox" in _dom:
                hints.append("MAILGUN_DOMAIN is a sandbox domain: Mailgun delivers ONLY to recipients you authorise under Sending > Domain settings > Authorized Recipients, "
                             "and each person must click the confirmation email. This is the usual reason one Gmail address works and another does not.")
            if from_email.split("@")[-1].lower() in ("gmail.com", "googlemail.com", "yahoo.com", "outlook.com"):
                hints.append("FROM_EMAIL is a free-mail address. Gmail rejects or spams mail sent 'from Gmail' by another server (DMARC). Use an address on your own verified domain.")
            hints.append("'accepted' means the provider took the message, not that the inbox did. Check the Mailgun/Resend Logs for delivered/failed, then Gmail Spam, "
                         "and add SPF + DKIM DNS records for the sending domain.")
            return jsonify({"success": bool(_r.get("success")), "provider": "resend" if os.getenv("RESEND_API_KEY") else "mailgun_api",
                            "provider_answer": _r.get("error") or "accepted", "message_id": _r.get("id"), "hints": hints, **info})

        @self.app.route("/api/admin/chat-notify-test", methods=["GET", "POST"])
        @admin_required
        def admin_chat_notify_test():
            """Checks the Flask -> bot link that delivers success messages into the chat.
            GET /api/admin/chat-notify-test?wa=<chat id, optional> with header X-Admin-Secret."""
            import requests as _rq
            url = os.getenv("CHAT_BOT_NOTIFY_URL", "http://127.0.0.1:3001/internal/notify")
            out = {"notify_url": url, "secret_set": bool(os.getenv("WHATSAPP_BOT_SECRET")),
                   "is_default_localhost": "127.0.0.1" in url or "localhost" in url}
            if out["is_default_localhost"]:
                out["problem"] = "CHAT_BOT_NOTIFY_URL still points at localhost. On Render set it to https://<your-bot>.onrender.com/internal/notify on THIS (Flask) service."
            try:
                r = _rq.get(url.rsplit("/internal/notify", 1)[0] + "/health", timeout=75)
                out["bot_health"] = r.status_code
            except Exception as e:
                out["bot_health"] = f"unreachable: {e}"
            wa = (request.values.get("wa") or "").strip()
            if wa:
                try:
                    r = _rq.post(url, json={"wa": wa, "kind": "engage", "title": "Net365 test", "body": "Chat delivery test from the server."},
                                 headers={"X-Bot-Secret": os.getenv("WHATSAPP_BOT_SECRET", "")}, timeout=75)
                    out["notify_status"] = r.status_code
                    if r.status_code in (401, 403):
                        out["problem"] = "The bot refused the secret: WHATSAPP_BOT_SECRET must be identical on both services."
                except Exception as e:
                    out["notify_status"] = f"failed: {e}"
            return jsonify({"success": True, **out})

        @self.app.route("/api/admin/link-debug", methods=["GET"])
        @admin_required
        def admin_link_debug():
            """Which chats are linked to an email (masked ids). GET ?email=you@example.com"""
            email = (request.values.get("email") or "").strip().lower()
            u = db.get_user_by_email(email) if email else None
            if not u:
                return jsonify({"success": True, "account": False, "note": "No live account for this email: the chat 'link' step sends no code, by design."})
            rows = db.get_db_connection().execute("SELECT wa_number, is_guest, active FROM whatsapp_links WHERE user_id = ?", (u["id"],)).fetchall()
            return jsonify({"success": True, "account": True, "email_verified": bool(u.get("email_verified")),
                            "links": [{"chat": ("telegram" if str(r[0]).startswith("999") else "whatsapp"), "ending": str(r[0])[-4:],
                                       "guest": bool(r[1]), "active": bool(r[2])} for r in rows]})

        @self.app.route("/api/health", methods=["GET"])
        def health():
            return jsonify(
                {
                    "success": True,
                    "service": "net365",
                    "reloadly_environment": self.credentials.environment.value,
                    "version": "2.2.0",
                    "supported_currencies": list(SUPPORTED_CURRENCIES.keys()),
                }
            )

        @self.app.route("/api/health/dependencies", methods=["GET"])
        @admin_required
        def health_dependencies():
            status = {
                "database": db.check_database(),
                "reloadly": bool(
                    os.getenv("RELOADLY_CLIENT_ID")
                    and os.getenv("RELOADLY_CLIENT_SECRET")
                ),
                "paystack": bool(os.getenv("PAYSTACK_SECRET_KEY")),
                "stripe": bool(os.getenv("STRIPE_SECRET_KEY")) and STRIPE_AVAILABLE,
                "flutterwave": bool(os.getenv("FLUTTERWAVE_SECRET_KEY")),
                "encryption": bool(_encryption_key_valid and cipher and decrypt_pii(encrypt_pii("ok")) == "ok"),
                "exchange_rates": ExchangeRateService._last_success is not None,
            }
            healthy = all(status.values())
            return jsonify(
                {
                    "healthy": healthy,
                    "status": status,
                    "timestamp": datetime.now().isoformat(),
                }
            ), (200 if healthy else 503)

        # ============ SCHEDULER API ROUTES ============
        @self.app.route("/api/scheduler/schedules", methods=["GET"])
        @login_required
        def get_scheduler_schedules():
            user_id = g.current_user_id
            try:
                conn = db.get_db_connection()
                c = conn.cursor()

                c.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='scheduler_schedules'"
                )
                if not c.fetchone():
                    c.execute("""
                        CREATE TABLE scheduler_schedules (
                            id TEXT PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            name TEXT NOT NULL,
                            service_type TEXT NOT NULL,
                            amount REAL NOT NULL,
                            currency TEXT DEFAULT 'NGN',
                            frequency TEXT NOT NULL,
                            country_code TEXT,
                            operator_id TEXT,
                            operator_name TEXT,
                            phone TEXT,
                            recipient TEXT,
                            department TEXT,
                            recipient_type TEXT DEFAULT 'individual',
                            biller_id TEXT,
                            biller_name TEXT,
                            subscriber_account TEXT,
                            day_of_month INTEGER DEFAULT 1,
                            day_of_week INTEGER DEFAULT 0,
                            month INTEGER DEFAULT 1,
                            time TEXT DEFAULT '09:00',
                            timezone TEXT DEFAULT 'Africa/Lagos',
                            notify_days INTEGER DEFAULT 3,
                            status TEXT DEFAULT 'active',
                            priority INTEGER DEFAULT 5,
                            wallet_currency TEXT DEFAULT 'NGN',
                            next_run TIMESTAMP,
                            last_run TIMESTAMP,
                            last_error TEXT,
                            metadata TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (user_id) REFERENCES users(id)
                        )
                    """)
                    conn.commit()
                    logger.info("Created scheduler_schedules table")

                for col, dtype in [
                    ("priority", "INTEGER DEFAULT 5"),
                    ("wallet_currency", 'TEXT DEFAULT "NGN"'),
                    ("biller_id", "TEXT"),
                    ("biller_name", "TEXT"),
                    ("subscriber_account", "TEXT"),
                ]:
                    try:
                        c.execute(
                            f"ALTER TABLE scheduler_schedules ADD COLUMN {col} {dtype}"
                        )
                    except sqlite3.OperationalError:
                        pass
                conn.commit()

                c.execute(
                    """
                    SELECT * FROM scheduler_schedules 
                    WHERE user_id = ? 
                    ORDER BY priority ASC, created_at DESC
                """,
                    (user_id,),
                )
                rows = c.fetchall()
                schedules = []
                for row in rows:
                    sched = dict(row)
                    if sched.get("metadata"):
                        try:
                            sched["metadata"] = json.loads(sched["metadata"])
                        except:
                            pass
                    schedules.append(sched)
                return jsonify({"success": True, "schedules": schedules})
            except Exception as e:
                logger.error(f"Error fetching schedules: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/scheduler/schedules", methods=["POST"])
        @login_required
        @email_verified_required
        def create_scheduler_schedule():
            user_id = g.current_user_id
            data = request.json or {}

            logger.info(f"Creating schedule with data: {data}")

            service_type = data.get("service_type") or data.get("serviceType")
            recipient_type = (
                data.get("recipient_type") or data.get("recipientType") or "individual"
            )

            required = ["name", "frequency", "amount"]
            for field in required:
                if field not in data:
                    logger.error(f"Missing required field: {field}")
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"Missing required field: {field}",
                            }
                        ),
                        400,
                    )

            if not service_type:
                logger.error("Missing required field: service_type")
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Missing required field: service_type",
                        }
                    ),
                    400,
                )

            try:
                amount = float(data["amount"])
                if amount <= 0:
                    return (
                        jsonify(
                            {"success": False, "error": "Amount must be greater than 0"}
                        ),
                        400,
                    )
            except (TypeError, ValueError):
                return jsonify({"success": False, "error": "Invalid amount"}), 400

            currency = data.get("currency", "NGN").upper()
            if currency not in SUPPORTED_CURRENCIES:
                return (
                    jsonify(
                        {"success": False, "error": f"Unsupported currency: {currency}"}
                    ),
                    400,
                )

            wallet_currency = currency
            priority = data.get("priority", 5)
            if priority < 1 or priority > 10:
                priority = 5

            # The browser's next_run is computed in the viewer's LOCAL time and ignores
            # the selected timezone, so it is never trusted. Always recompute here from
            # the chosen time + timezone.
            freq_value = str(data.get("frequency") or "").lower()
            event_date_value = data.get("event_date") or (
                (data.get("startDate") or data.get("eventDate"))
                if freq_value == "once"
                else (data.get("eventDate") or data.get("startDate"))
            )
            next_run = None
            if data.get("frequency"):
                next_run = calculate_next_run(
                    data.get("frequency"),
                    data.get("day_of_month", 1),
                    data.get("time", "09:00"),
                    data.get("day_of_week", 0),
                    data.get("month", 1),
                    event_date_value,
                    data.get("timezone") or "Africa/Lagos",
                )
            logger.info(
                f"Schedule next_run computed: freq={data.get('frequency')} "
                f"time={data.get('time')} tz={data.get('timezone')} -> {next_run}"
            )

            try:
                conn = db.get_db_connection()
                c = conn.cursor()

                schedule_id = data.get("id")
                if schedule_id:
                    existing = c.execute(
                        "SELECT id FROM scheduler_schedules WHERE id = ? AND user_id = ?",
                        (schedule_id, user_id),
                    ).fetchone()
                    if existing:
                        c.execute(
                            """
                            UPDATE scheduler_schedules SET
                                name = ?, service_type = ?, amount = ?, currency = ?,
                                frequency = ?, country_code = ?, operator_id = ?, operator_name = ?,
                                phone = ?, recipient = ?, department = ?, recipient_type = ?,
                                biller_id = ?, biller_name = ?, subscriber_account = ?,
                                day_of_month = ?, day_of_week = ?, month = ?, time = ?,
                                timezone = ?, notify_days = ?, status = ?, priority = ?,
                                wallet_currency = ?, next_run = ?,
                                metadata = ?, updated_at = CURRENT_TIMESTAMP
                            WHERE id = ? AND user_id = ?
                        """,
                            (
                                data["name"],
                                service_type,
                                amount,
                                currency,
                                data["frequency"],
                                data.get("country_code"),
                                data.get("operator_id"),
                                data.get("operator_name"),
                                data.get("phone"),
                                data.get("recipient"),
                                data.get("department"),
                                recipient_type,
                                data.get("biller_id"),
                                data.get("biller_name"),
                                data.get("subscriber_account"),
                                data.get("day_of_month", 1),
                                data.get("day_of_week", 0),
                                data.get("month", 1),
                                data.get("time", "09:00"),
                                data.get("timezone", "Africa/Lagos"),
                                data.get("notify_days", 3),
                                data.get("status", "active"),
                                priority,
                                wallet_currency,
                                next_run,
                                json.dumps(data.get("metadata", {})),
                                schedule_id,
                                user_id,
                            ),
                        )
                        conn.commit()

                        log_event(
                            user_id=user_id,
                            event_type="schedule_updated",
                            details={"schedule_id": schedule_id, "name": data["name"]},
                            status="success",
                        )

                        return jsonify(
                            {
                                "success": True,
                                "schedule_id": schedule_id,
                                "message": "Schedule updated successfully",
                            }
                        )

                import uuid

                schedule_id = data.get("id") or str(uuid.uuid4())

                c.execute(
                    """
                    INSERT INTO scheduler_schedules (
                        id, user_id, name, service_type, amount, currency, frequency,
                        country_code, operator_id, operator_name, phone, recipient,
                        department, recipient_type, biller_id, biller_name, subscriber_account,
                        day_of_month, day_of_week, month,
                        time, timezone, notify_days, status, priority, wallet_currency,
                        next_run, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        schedule_id,
                        user_id,
                        data["name"],
                        service_type,
                        amount,
                        currency,
                        data["frequency"],
                        data.get("country_code"),
                        data.get("operator_id"),
                        data.get("operator_name"),
                        data.get("phone"),
                        data.get("recipient"),
                        data.get("department"),
                        recipient_type,
                        data.get("biller_id"),
                        data.get("biller_name"),
                        data.get("subscriber_account"),
                        data.get("day_of_month", 1),
                        data.get("day_of_week", 0),
                        data.get("month", 1),
                        data.get("time", "09:00"),
                        data.get("timezone", "Africa/Lagos"),
                        data.get("notify_days", 3),
                        data.get("status", "active"),
                        priority,
                        wallet_currency,
                        next_run,
                        json.dumps(data.get("metadata", {})),
                    ),
                )

                conn.commit()

                log_event(
                    user_id=user_id,
                    event_type="schedule_created",
                    details={"schedule_id": schedule_id, "name": data["name"]},
                    status="success",
                )

                return jsonify(
                    {
                        "success": True,
                        "schedule_id": schedule_id,
                        "message": "Schedule created successfully",
                    }
                )

            except Exception as e:
                logger.error(f"Error creating schedule: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/scheduler/schedules/<schedule_id>", methods=["PUT"])
        @login_required
        def update_scheduler_schedule(schedule_id):
            user_id = g.current_user_id
            data = request.json or {}

            try:
                conn = db.get_db_connection()
                c = conn.cursor()

                existing = c.execute(
                    "SELECT id FROM scheduler_schedules WHERE id = ? AND user_id = ?",
                    (schedule_id, user_id),
                ).fetchone()

                if not existing:
                    return (
                        jsonify({"success": False, "error": "Schedule not found"}),
                        404,
                    )

                current = c.execute(
                    "SELECT currency FROM scheduler_schedules WHERE id = ? AND user_id = ?",
                    (schedule_id, user_id),
                ).fetchone()
                current_currency = str(
                    (current["currency"] if current else "NGN") or "NGN"
                ).upper()
                requested_currency = str(
                    data.get("currency", current_currency) or current_currency
                ).upper()
                requested_wallet_currency = str(
                    data.get("wallet_currency", requested_currency)
                    or requested_currency
                ).upper()
                if requested_currency not in SUPPORTED_CURRENCIES:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"Unsupported currency: {requested_currency}",
                            }
                        ),
                        400,
                    )
                if requested_wallet_currency != requested_currency:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "wallet_currency must match currency. Cross-currency scheduler spending is disabled.",
                            }
                        ),
                        400,
                    )
                data["currency"] = requested_currency
                data["wallet_currency"] = requested_currency

                allowed_fields = [
                    "name",
                    "service_type",
                    "amount",
                    "currency",
                    "frequency",
                    "country_code",
                    "operator_id",
                    "operator_name",
                    "phone",
                    "recipient",
                    "department",
                    "recipient_type",
                    "day_of_month",
                    "day_of_week",
                    "month",
                    "time",
                    "timezone",
                    "notify_days",
                    "status",
                    "priority",
                    "wallet_currency",
                    "next_run",
                    "metadata",
                    "biller_id",
                    "biller_name",
                    "subscriber_account",
                ]

                updates = []
                values = []
                for field in allowed_fields:
                    if field in data:
                        updates.append(f"{field} = ?")
                        if field == "metadata":
                            values.append(json.dumps(data[field]))
                        else:
                            values.append(data[field])

                if not updates:
                    return (
                        jsonify({"success": False, "error": "No fields to update"}),
                        400,
                    )

                values.append(schedule_id)
                values.append(user_id)

                c.execute(
                    f"""
                    UPDATE scheduler_schedules 
                    SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND user_id = ?
                """,
                    values,
                )

                conn.commit()

                log_event(
                    user_id=user_id,
                    event_type="schedule_updated",
                    details={"schedule_id": schedule_id},
                    status="success",
                )

                return jsonify(
                    {"success": True, "message": "Schedule updated successfully"}
                )

            except Exception as e:
                logger.error(f"Error updating schedule: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/scheduler/schedules/<schedule_id>", methods=["DELETE"])
        @login_required
        def delete_scheduler_schedule(schedule_id):
            user_id = g.current_user_id

            try:
                conn = db.get_db_connection()
                c = conn.cursor()

                schedule = c.execute(
                    "SELECT name FROM scheduler_schedules WHERE id = ? AND user_id = ?",
                    (schedule_id, user_id),
                ).fetchone()

                c.execute(
                    "DELETE FROM scheduler_schedules WHERE id = ? AND user_id = ?",
                    (schedule_id, user_id),
                )

                if c.rowcount == 0:
                    return (
                        jsonify({"success": False, "error": "Schedule not found"}),
                        404,
                    )

                conn.commit()

                if schedule:
                    log_event(
                        user_id=user_id,
                        event_type="schedule_deleted",
                        details={"schedule_id": schedule_id, "name": schedule["name"]},
                        status="success",
                    )

                return jsonify(
                    {"success": True, "message": "Schedule deleted successfully"}
                )

            except Exception as e:
                logger.error(f"Error deleting schedule: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/scheduler/schedules/<schedule_id>/run", methods=["POST"])
        @login_required
        def run_scheduler_schedule(schedule_id):
            user_id = g.current_user_id

            try:
                conn = db.get_db_connection()
                c = conn.cursor()

                schedule = c.execute(
                    """
                    SELECT * FROM scheduler_schedules 
                    WHERE id = ? AND user_id = ?
                """,
                    (schedule_id, user_id),
                ).fetchone()

                if not schedule:
                    return (
                        jsonify({"success": False, "error": "Schedule not found"}),
                        404,
                    )

                schedule = dict(schedule)

                if schedule.get("service_type") == "airtime":
                    if (
                        not schedule.get("country_code")
                        or not schedule.get("operator_id")
                        or not schedule.get("phone")
                    ):
                        return (
                            jsonify(
                                {
                                    "success": False,
                                    "error": "Schedule is missing country, operator, or phone number. Please edit and fix.",
                                }
                            ),
                            400,
                        )

                if schedule.get("service_type") == "utility":
                    if not schedule.get("biller_id") or not schedule.get(
                        "subscriber_account"
                    ):
                        return (
                            jsonify(
                                {
                                    "success": False,
                                    "error": "Schedule is missing biller or account number. Please edit and fix.",
                                }
                            ),
                            400,
                        )

                result = _execute_schedule_fulfillment(schedule, user_id, self.platform)
                outcome = _finalize_schedule_run(schedule_id, user_id, schedule, result)

                if outcome["success"]:
                    return jsonify(
                        {
                            "success": True,
                            "message": "Schedule executed successfully",
                            "result": result,
                        }
                    )
                else:
                    return jsonify(
                        {
                            "success": False,
                            "needs_review": outcome["needs_review"],
                            "status": outcome["status"],
                            "error": result.get("error", "Execution failed"),
                        }
                    ), (409 if outcome["needs_review"] else 400)

            except Exception as e:
                logger.error(f"Error running schedule: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        # ============ UTILITIES API ROUTES ============
        @self.app.route("/api/utilities/billers", methods=["GET"])
        @safe_api_response
        def get_utility_billers():
            try:
                country = request.args.get("countryISOCode", "NG").upper()
                logger.info(f"Fetching utility billers for country: {country}")

                billers = self.platform.get_utility_billers(
                    biller_id=request.args.get("id", type=int),
                    name=request.args.get("name"),
                    biller_type=request.args.get("type"),
                    service_type=request.args.get("serviceType"),
                    country_iso_code=country,
                    page=request.args.get("page", 1, type=int),
                    size=request.args.get("size", 50, type=int),
                )

                logger.info(
                    f"Fetched {len(billers) if billers else 0} billers from Reloadly"
                )

                if billers and len(billers) > 0:
                    formatted = []
                    for idx, b in enumerate(billers):
                        if isinstance(b, dict):
                            if idx == 0:
                                logger.info(
                                    f"Raw Reloadly biller record (for field-name verification): {json.dumps(b)[:800]}"
                                )
                            biller_id = (
                                b.get("billerId") or b.get("id") or b.get("biller_id")
                            )
                            if biller_id:
                                formatted.append(
                                    {
                                        "id": biller_id,
                                        "billerId": biller_id,
                                        "name": b.get("name")
                                        or b.get("billerName")
                                        or f"Biller {biller_id}",
                                        "type": b.get("type")
                                        or b.get("billerType")
                                        or b.get("serviceType")
                                        or "UTILITY",
                                        "countryISOCode": b.get("countryISOCode")
                                        or b.get("countryCode")
                                        or country,
                                        "minAmount": b.get("minAmount")
                                        or b.get("min")
                                        or 50,
                                        "maxAmount": b.get("maxAmount")
                                        or b.get("max")
                                        or 5000,
                                        "validAmounts": b.get("validAmounts")
                                        or b.get("amounts")
                                        or [100, 200, 500, 1000, 2000, 5000],
                                        "isSandbox": self.credentials.environment.value
                                        == "sandbox",
                                        "defaultAmount": b.get("defaultAmount") or 500,
                                    }
                                )

                    if formatted:
                        logger.info(f"Returning {len(formatted)} formatted billers")
                        return jsonify(formatted)

            except Exception as e:
                logger.error(f"Error fetching utility billers: {e}")

            # Comprehensive fallback billers
            logger.info(f"Using fallback billers for country: {country}")

            all_billers = [
                {
                    "id": 49,
                    "billerId": 49,
                    "name": "📱 MTN Nigeria",
                    "type": "AIRTIME_TOPUP",
                    "countryISOCode": "NG",
                },
                {
                    "id": 50,
                    "billerId": 50,
                    "name": "📱 Glo Nigeria",
                    "type": "AIRTIME_TOPUP",
                    "countryISOCode": "NG",
                },
                {
                    "id": 51,
                    "billerId": 51,
                    "name": "📱 Airtel Nigeria",
                    "type": "AIRTIME_TOPUP",
                    "countryISOCode": "NG",
                },
                {
                    "id": 52,
                    "billerId": 52,
                    "name": "📱 9mobile Nigeria",
                    "type": "AIRTIME_TOPUP",
                    "countryISOCode": "NG",
                },
                {
                    "id": 38,
                    "billerId": 38,
                    "name": "⚡ Eko Electric",
                    "type": "ELECTRICITY_BILL_PAYMENT",
                    "countryISOCode": "NG",
                },
                {
                    "id": 39,
                    "billerId": 39,
                    "name": "⚡ Ikeja Electric",
                    "type": "ELECTRICITY_BILL_PAYMENT",
                    "countryISOCode": "NG",
                },
                {
                    "id": 40,
                    "billerId": 40,
                    "name": "⚡ Kaduna Electric",
                    "type": "ELECTRICITY_BILL_PAYMENT",
                    "countryISOCode": "NG",
                },
                {
                    "id": 41,
                    "billerId": 41,
                    "name": "⚡ Kano Electric",
                    "type": "ELECTRICITY_BILL_PAYMENT",
                    "countryISOCode": "NG",
                },
                {
                    "id": 42,
                    "billerId": 42,
                    "name": "⚡ Abuja Electric",
                    "type": "ELECTRICITY_BILL_PAYMENT",
                    "countryISOCode": "NG",
                },
                {
                    "id": 53,
                    "billerId": 53,
                    "name": "📺 DSTV",
                    "type": "CABLE_BILL_PAYMENT",
                    "countryISOCode": "NG",
                },
                {
                    "id": 54,
                    "billerId": 54,
                    "name": "📺 GOtv",
                    "type": "CABLE_BILL_PAYMENT",
                    "countryISOCode": "NG",
                },
                {
                    "id": 55,
                    "billerId": 55,
                    "name": "📺 Startimes",
                    "type": "CABLE_BILL_PAYMENT",
                    "countryISOCode": "NG",
                },
                {
                    "id": 201,
                    "billerId": 201,
                    "name": "📱 Safaricom Kenya",
                    "type": "AIRTIME_TOPUP",
                    "countryISOCode": "KE",
                },
                {
                    "id": 202,
                    "billerId": 202,
                    "name": "📱 Airtel Kenya",
                    "type": "AIRTIME_TOPUP",
                    "countryISOCode": "KE",
                },
                {
                    "id": 203,
                    "billerId": 203,
                    "name": "⚡ Kenya Power",
                    "type": "ELECTRICITY_BILL_PAYMENT",
                    "countryISOCode": "KE",
                },
                {
                    "id": 301,
                    "billerId": 301,
                    "name": "📱 MTN Ghana",
                    "type": "AIRTIME_TOPUP",
                    "countryISOCode": "GH",
                },
                {
                    "id": 302,
                    "billerId": 302,
                    "name": "📱 Vodafone Ghana",
                    "type": "AIRTIME_TOPUP",
                    "countryISOCode": "GH",
                },
                {
                    "id": 303,
                    "billerId": 303,
                    "name": "⚡ ECG Ghana",
                    "type": "ELECTRICITY_BILL_PAYMENT",
                    "countryISOCode": "GH",
                },
                {
                    "id": 401,
                    "billerId": 401,
                    "name": "📱 Vodacom SA",
                    "type": "AIRTIME_TOPUP",
                    "countryISOCode": "ZA",
                },
                {
                    "id": 402,
                    "billerId": 402,
                    "name": "📱 MTN SA",
                    "type": "AIRTIME_TOPUP",
                    "countryISOCode": "ZA",
                },
                {
                    "id": 403,
                    "billerId": 403,
                    "name": "⚡ Eskom SA",
                    "type": "ELECTRICITY_BILL_PAYMENT",
                    "countryISOCode": "ZA",
                },
                {
                    "id": 501,
                    "billerId": 501,
                    "name": "⚡ British Gas",
                    "type": "UTILITY",
                    "countryISOCode": "GB",
                },
                {
                    "id": 502,
                    "billerId": 502,
                    "name": "⚡ E.ON UK",
                    "type": "UTILITY",
                    "countryISOCode": "GB",
                },
                {
                    "id": 601,
                    "billerId": 601,
                    "name": "⚡ EDF France",
                    "type": "UTILITY",
                    "countryISOCode": "FR",
                },
                {
                    "id": 602,
                    "billerId": 602,
                    "name": "⚡ E.ON Germany",
                    "type": "UTILITY",
                    "countryISOCode": "DE",
                },
            ]

            fallback_billers = [
                b for b in all_billers if b["countryISOCode"] == country
            ]
            if not fallback_billers:
                fallback_billers = all_billers

            for b in fallback_billers:
                b["isSandbox"] = self.credentials.environment.value == "sandbox"
                b["minAmount"] = 50
                b["maxAmount"] = 5000
                b["validAmounts"] = [50, 100, 200, 500, 1000, 2000, 5000]
                b["defaultAmount"] = 500

            logger.info(f"Returning {len(fallback_billers)} fallback billers")
            return jsonify(fallback_billers)

        @self.app.route("/api/utilities/billers/<int:biller_id>", methods=["GET"])
        @safe_api_response
        def get_utility_biller(biller_id):
            try:
                return jsonify(self.platform.get_utility_biller_by_id(biller_id))
            except Exception as e:
                logger.error(f"Error fetching biller {biller_id}: {e}")
                return jsonify(
                    {
                        "id": biller_id,
                        "name": f"Biller {biller_id}",
                        "billerId": biller_id,
                    }
                )

        @self.app.route("/api/utilities/validate", methods=["POST"])
        @safe_api_response
        def validate_utility_account():
            data = request.json or {}
            biller_id = data.get("biller_id")
            subscriber_account = data.get("subscriber_account")

            try:
                result = self.platform.validate_utility_account(
                    biller_id, subscriber_account
                )
                return jsonify(result)
            except Exception as e:
                logger.error(f"Error validating utility account: {e}")
                return jsonify(
                    {
                        "valid": True,
                        "customerName": f"Customer_{subscriber_account[-4:]}",
                        "accountNumber": subscriber_account,
                        "billerId": biller_id,
                    }
                )

        # ============ VTPASS SERVICES: data, TV, education (via the provider router) ============
        _SVC_TV = {"dstv", "gotv", "startimes", "showmax"}
        _SVC_EDU = {"waec", "waec-registration", "jamb"}
        _SVC_NET = {"mtn", "airtel", "glo", "9mobile"}
        _SVC_LABEL = {"dstv": "DStv", "gotv": "GOtv", "startimes": "StarTimes", "showmax": "Showmax", "waec": "WAEC result checker",
                      "waec-registration": "WAEC registration", "jamb": "JAMB"}

        @self.app.route("/api/services/catalog", methods=["GET"])
        @safe_api_response
        def services_catalog():
            import net365_providers as _np
            product = str(request.args.get("product") or "").lower()
            if not _np.enabled() or product not in (_SVC_TV | _SVC_EDU):
                return jsonify({"success": False, "error": "Service not available"}), 404
            plans = _np.service_catalog(product)
            if not plans:
                return jsonify({"success": False, "error": "Plans are unavailable right now. Please try again shortly."}), 503
            return jsonify({"success": True, "product": product, "label": _SVC_LABEL.get(product, product), "plans": plans})

        @self.app.route("/api/services/verify", methods=["POST"])
        @login_required
        @safe_api_response
        def services_verify():
            import net365_providers as _np
            d = request.json or {}
            product = str(d.get("product") or "").lower()
            code = re.sub(r"\s", "", str(d.get("billers_code") or ""))
            if not _np.enabled() or product not in ("dstv", "gotv", "startimes", "jamb") or not re.fullmatch(r"\d{6,16}", code):
                return jsonify({"success": False, "error": "Enter a valid smartcard / profile number"}), 400
            v = _np.verify_account(product, code, str(d.get("variation_code") or ""))
            status = 200 if v.get("ok") else (503 if v.get("unavailable") else 422)
            return jsonify({"success": bool(v.get("ok")), **v}), status

        @self.app.route("/api/services/checkout", methods=["POST"])
        @login_required
        @email_verified_required
        @safe_api_response
        def services_checkout():
            """Start a gateway payment for a data bundle, a TV subscription or an education PIN. The price is taken from
            the provider's catalogue (or the verified renewal amount), never from the request."""
            import net365_providers as _np
            d = request.json or {}
            user_id = g.current_user_id
            service = str(d.get("service") or "").lower()
            product = str(d.get("product") or d.get("network") or "").lower()
            code = str(d.get("variation_code") or "")
            src = str(d.get("source") or "")
            if not _np.enabled():
                return jsonify({"success": False, "error": "This service is not available yet"}), 503
            try:
                import net365_recovery as _rc
                _mb = _rc.maintenance_block(service)
                if _mb:
                    return _mb
            except ImportError:
                pass
            if (service == "data" and product not in _SVC_NET) or (service == "tv" and product not in _SVC_TV) \
                    or (service == "education" and product not in _SVC_EDU) or service not in ("data", "tv", "education") or not code:
                return jsonify({"success": False, "error": "Invalid request"}), 400
            phone = re.sub(r"[^\d+]", "", str(d.get("phone") or ""))
            if not _np.local_number(phone):
                phone = re.sub(r"[^\d+]", "", str((db.get_user(user_id) or {}).get("phone") or ""))
            account = re.sub(r"\s", "", str(d.get("billers_code") or ""))
            if service == "data":
                plan = _np.find_plan(product, code)
                account = phone
            else:
                plan = _np.find_service_plan(product, code)
            if not plan:
                return jsonify({"success": False, "error": "That plan is no longer available. Please pick again."}), 409
            if not _np.local_number(phone):
                return jsonify({"success": False, "error": "Enter a valid Nigerian phone number"}), 400
            if service == "data":
                _mm = network_mismatch_error(phone, None, product, bool(d.get("confirm_network")))
                if _mm:
                    return jsonify(_mm), 409
            quantity, sub_type, renewal = 1, "", 0.0
            amount = float(plan["price"])
            verified_name = ""
            if service == "tv" and product in ("dstv", "gotv", "startimes"):
                if not re.fullmatch(r"\d{6,16}", account):
                    return jsonify({"success": False, "error": "Enter a valid smartcard number"}), 400
                v = _np.verify_account(product, account)
                if not v.get("ok"):
                    return jsonify({"success": False, "error": v.get("message") or "Smartcard could not be verified"}), 422
                verified_name = v.get("name", "")
                if product in ("dstv", "gotv"):
                    sub_type = "renew" if str(d.get("subscription_type")) == "renew" else "change"
                    if sub_type == "renew":
                        renewal = float(v.get("renewal_amount") or 0)
                        if renewal <= 0:
                            return jsonify({"success": False, "error": "Renewal amount unavailable. Choose a bouquet instead."}), 409
                        amount = renewal
            elif service == "tv" and product == "showmax":
                account = _np.local_number(phone)
            elif service == "education":
                if product == "jamb":
                    if not re.fullmatch(r"\d{6,16}", account):
                        return jsonify({"success": False, "error": "Enter a valid JAMB profile number"}), 400
                    v = _np.verify_account("jamb", account, code)
                    if not v.get("ok"):
                        return jsonify({"success": False, "error": v.get("message") or "Profile could not be verified"}), 422
                    verified_name = v.get("name", "")
                else:
                    try:
                        quantity = max(1, min(int(d.get("quantity") or 1), 5))
                    except (TypeError, ValueError):
                        quantity = 1
                    amount = round(amount * quantity, 2)
                    account = _np.local_number(phone)
            fee = 0.0 if product == "jamb" else (server_fee_for(amount, "NGN") if src in ("telegram", "whatsapp") else 0.0)
            charge = round(amount + fee, 2)
            try:
                from net365_whatsapp import chat_purchase_error
                _ce = chat_purchase_error(user_id, charge, "NGN")
                if _ce:
                    return jsonify(_ce[0]), _ce[1]
            except ImportError:
                _le = _purchase_limit_error(user_id, charge, "NGN")
                if _le:
                    return jsonify({"success": False, "error": _le}), 400
            user = db.get_user(user_id) or {}
            email = str(d.get("email") or "").strip() or user.get("email") or os.getenv("DEFAULT_PAYMENT_EMAIL", f"user_{user_id}@net365.com")
            result = self.platform.create_payment(amount=charge, currency="NGN", email=email,
                                                  return_url=_safe_payment_return_url(d.get("return_url")), provider="paystack")
            if not (result.get("success") and result.get("reference")):
                return jsonify(result), 502
            label = _SVC_LABEL.get(product, product.upper())
            biller = f"{label} {plan['name']}"[:60] if service != "data" else plan["name"][:60]
            payload = {"product": product, "network": product if service == "data" else "", "variation_code": code,
                       "phone": encrypt_pii(phone),
                       "subscriber_account": encrypt_pii(account),
                       "quantity": quantity, "subscription_type": sub_type, "renewal_amount": renewal,
                       "service_amount": amount, "fee_amount": fee, "biller_name": biller, "customer_name": verified_name,
                       "currency": "NGN", "email": email, "user_id": user_id, "payment_method": "paystack"}
            if src in ("telegram", "whatsapp"):
                payload["source"] = src
            db.create_pending(reference=result["reference"], tx_type=service, provider=result.get("provider", "paystack"),
                              amount=charge, currency="NGN", payload=payload, user_id=user_id)
            return jsonify({"success": True, "authorization_url": result.get("authorization_url") or result.get("checkout_url"),
                            "reference": result["reference"], "amount": charge, "service_amount": amount, "fee_amount": fee,
                            "customer_name": verified_name, "plan": plan["name"]})

        # ============ BILLS & SERVICES HUB: electricity (VTpass + Reloadly, customer can choose) and insurance ============
        # HUB_<SERVICE>=off|soon|live. Electricity is live by default; insurance stays off until you switch it on after sandbox testing.
        _HUB_DEFAULTS = {"ELECTRICITY": "live", "TV": "live", "DATA": "live", "EDUCATION": "live", "INSURANCE": "off"}

        def _hub_state(key):
            v = str(os.getenv("HUB_" + key, _HUB_DEFAULTS.get(key, "off"))).strip().lower()
            return v if v in ("off", "soon", "live") else "soon"

        _ELEC_CACHE = {}

        def _electricity_options(country="NG"):
            """Each distribution company once, with every provider that can pay it: [{key, name, options:[{provider, biller_id?, min, max}]}]."""
            import net365_providers as _np
            country = (country or "NG").upper()
            hit = _ELEC_CACHE.get(country)
            if hit and time.time() - hit[0] < 600:
                return hit[1]
            rows = {}
            try:
                billers = self.platform.get_utility_billers(biller_type="ELECTRICITY_BILL_PAYMENT", country_iso_code=country, page=1, size=100) or []
                if isinstance(billers, dict):
                    billers = billers.get("content") or []
            except Exception as e:
                logger.warning(f"electricity billers (Reloadly) unavailable: {e}")
                billers = []
            for b in billers:
                if not isinstance(b, dict):
                    continue
                bid = b.get("billerId") or b.get("id") or b.get("biller_id")
                name = str(b.get("name") or b.get("billerName") or "").strip()
                btype = str(b.get("type") or b.get("billerType") or b.get("serviceType") or "").upper()
                if not bid or not name or (btype and "ELECTRIC" not in btype):
                    continue
                key = (_np.disco_for(name) if country == "NG" else "") or f"rl-{bid}"
                e = rows.setdefault(key, {"key": key, "name": re.sub(r"^[^\w(]+", "", name).strip(), "options": []})
                e["options"].append({"provider": "reloadly", "biller_id": int(bid), "min": b.get("minAmount") or b.get("min"), "max": b.get("maxAmount") or b.get("max")})
            if country == "NG" and _np.enabled() and _np.provider_ready("vtpass"):
                for d in _np.list_discos():
                    e = rows.setdefault(d["key"], {"key": d["key"], "name": d["label"], "options": []})
                    e["name"] = d["label"]
                    e["options"].append({"provider": "vtpass", "min": 500, "max": None})
            out = sorted(rows.values(), key=lambda r: r["name"].lower())
            if out:
                _ELEC_CACHE[country] = (time.time(), out)
            return out

        def _elec_amount_bounds(opts):
            lo = max([float(o["min"]) for o in opts if o.get("min")] or [500.0]) if len(opts) > 1 else float((opts[0].get("min") or 500))
            hi = float(os.getenv("ELECTRICITY_MAX_NGN", "200000"))
            return lo, hi

        @self.app.route("/api/hub/config", methods=["GET"])
        def hub_config():
            import net365_providers as _np
            ready = _np.enabled() and _np.provider_ready("vtpass")
            st = {k.lower(): _hub_state(k) for k in _HUB_DEFAULTS}
            if not ready:                       # these four are sold through VTpass only
                for k in ("tv", "data", "education", "insurance"):
                    if st[k] == "live":
                        st[k] = "soon"
            try:                                # a service in maintenance is not offered
                import net365_recovery as _rc
                for k in list(st):
                    if st[k] == "live" and _rc.maintenance(k)[0]:
                        st[k] = "soon"
            except Exception:
                pass
            return jsonify({"success": True, "services": st, "countries": [{"code": "NG", "name": "Nigeria", "live": True}]})

        @self.app.route("/api/hub/contact", methods=["GET"])
        @login_required
        @safe_api_response
        def hub_contact():
            """The customer's own registered phone and email, so checkout can pre-fill them and only ask for confirmation."""
            import net365_providers as _np
            user = db.get_user(g.current_user_id) or {}
            raw_phone = str(user.get("phone") or "")
            try:
                from net365_identity import effective_phone as _ep
                _e = _ep(g.current_user_id)
                if _e:
                    raw_phone = _e["e164"]
            except Exception:
                pass
            try:
                phone = _np.local_number(raw_phone) or ""
            except Exception:
                phone = ""
            email = str(user.get("email") or "")
            return jsonify({"success": True, "phone": phone, "email": email})

        @self.app.route("/api/electricity/providers", methods=["GET"])
        @safe_api_response
        def electricity_providers():
            if _hub_state("ELECTRICITY") == "off":
                return jsonify({"success": False, "error": "Not available"}), 404
            country = str(request.args.get("country") or "NG").upper()[:2]
            discos = _electricity_options(country)
            # Customers only ever see the company name. Which processor pays it is Net365's business (admin routing tab).
            public = [{"key": d["key"], "name": d["name"]} for d in discos]
            if not public:
                try:
                    import net365_providers as _npd
                    logger.warning(f"electricity providers EMPTY: providers enabled={_npd.enabled()}, vtpass ready={_npd.provider_ready('vtpass')} (and the Reloadly biller list returned nothing)")
                except Exception as _de:
                    logger.warning(f"electricity providers EMPTY and the provider module failed: {_de}")
            return jsonify({"success": True, "country": country, "discos": public, "bills_open": _hub_state("ELECTRICITY") == "live"})

        def _elec_pick(country, key, pref):
            """The disco and the provider options the customer's choice allows."""
            disco = next((d for d in _electricity_options(country) if d["key"] == key), None)
            if not disco:
                return None, []
            opts = list(disco["options"])           # the customer never chooses a processor
            return disco, opts

        def _elec_detect(meter, meter_type, exclude_key=""):
            """Which distribution company does this meter belong to? Ask each company's meter check in parallel.
            Meter numbers carry no reliable company prefix, so the companies' own lookups are the only trustworthy answer."""
            import net365_providers as _np
            from concurrent.futures import ThreadPoolExecutor, as_completed
            if not (_np.enabled() and _np.provider_ready("vtpass")):
                return []
            discos = [d for d in _np.list_discos() if d["key"] != exclude_key]
            found = []

            def probe(dd):
                try:
                    v = _np.verify_meter(dd["key"], meter, meter_type)
                    if v.get("ok"):
                        return {"key": dd["key"], "name": dd["label"], "customer": v.get("name", "")}
                except Exception:
                    pass
                return None
            with ThreadPoolExecutor(max_workers=6) as ex:
                futs = [ex.submit(probe, dd) for dd in discos]
                try:
                    for f in as_completed(futs, timeout=25):
                        r = f.result()
                        if r:
                            found.append(r)
                except Exception:
                    pass
            return found

        def _wrong_disco(meter, meter_type, key, disco_name):
            """If the meter belongs to a different company than the one chosen, say which."""
            m = _elec_detect(meter, meter_type, exclude_key=key)
            if len(m) == 1:
                return {"success": False, "code": "WRONG_DISCO", "suggested": {"key": m[0]["key"], "name": m[0]["name"]},
                        "error": f"This meter number belongs to {m[0]['name']}, not {disco_name}. Please switch to {m[0]['name']} so your payment goes to the right company."}
            return None

        @self.app.route("/api/electricity/detect", methods=["POST"])
        @login_required
        @rate_limit(max_requests=10, window_seconds=60)
        @safe_api_response
        def electricity_detect():
            d = request.json or {}
            meter = re.sub(r"[\s-]", "", str(d.get("meter") or ""))
            mtype = "postpaid" if str(d.get("meter_type") or "").lower().startswith("post") else "prepaid"
            if not re.fullmatch(r"[A-Za-z0-9]{6,20}", meter):
                return jsonify({"success": False, "error": "Enter a valid meter number"}), 400
            m = _elec_detect(meter, mtype)
            if not m:
                return jsonify({"success": False, "error": "We could not match that meter to an electricity company. Check the number and meter type, or pick your company from the list."}), 404
            return jsonify({"success": True, "matches": [{"key": x["key"], "name": x["name"], "customer": x["customer"]} for x in m]})

        def _elec_verify(opts, key, meter, meter_type):
            """Check the meter with whichever allowed provider can; VTpass first because it returns the customer name reliably."""
            import net365_providers as _np
            import net365_routing as _rt
            last = {"ok": False, "message": "Could not verify this meter right now."}
            _rank = {p: i for i, p in enumerate(_rt.order("electricity"))}
            for o in sorted(opts, key=lambda x: _rank.get(x["provider"], 9)):
                if o["provider"] == "vtpass":
                    v = _np.verify_meter(key, meter, meter_type)
                else:
                    try:
                        r = self.platform.validate_utility_account(o.get("biller_id"), meter) or {}
                        okv = r.get("valid") is not False and bool(r.get("customerName") or r.get("name") or r.get("valid"))
                        v = {"ok": bool(okv), "name": str(r.get("customerName") or r.get("name") or "").strip(), "address": "",
                             "message": "" if okv else "Meter number not recognised."}
                    except Exception:
                        v = {"ok": False, "unavailable": True, "message": "Could not reach the verification service. Please try again."}
                if v.get("ok"):
                    return {**v, "checked_by": o["provider"]}   # internal only; stripped before it reaches the customer
                last = v
            return last

        @self.app.route("/api/electricity/verify", methods=["POST"])
        @login_required
        @safe_api_response
        def electricity_verify():
            d = request.json or {}
            meter = re.sub(r"[\s-]", "", str(d.get("meter") or ""))
            mtype = "postpaid" if str(d.get("meter_type") or "").lower().startswith("post") else "prepaid"
            if not re.fullmatch(r"[A-Za-z0-9]{6,20}", meter):
                return jsonify({"success": False, "error": "Enter a valid meter number"}), 400
            disco, opts = _elec_pick(str(d.get("country") or "NG").upper(), str(d.get("key") or ""), str(d.get("provider") or "auto"))
            if not disco or not opts:
                return jsonify({"success": False, "error": "That electricity company or provider is not available"}), 404
            v = _elec_verify(opts, disco["key"], meter, mtype)
            if not v.get("ok") and not v.get("unavailable"):
                _wd = _wrong_disco(meter, mtype, disco["key"], disco["name"])
                if _wd:
                    return jsonify(_wd), 422
            lo, hi = _elec_amount_bounds(opts)
            status = 200 if v.get("ok") else (503 if v.get("unavailable") else 422)
            return jsonify({"success": bool(v.get("ok")), "name": v.get("name", ""), "address": v.get("address", ""), "message": v.get("message", ""),
                            "min_amount": max(lo, float(v.get("min_amount") or 0)), "max_amount": hi}), status

        @self.app.route("/api/electricity/checkout", methods=["POST"])
        @login_required
        @email_verified_required
        @safe_api_response
        def electricity_checkout():
            """Start a gateway payment for electricity. The customer may choose VTpass or Reloadly; 'auto' lets the router pick."""
            import net365_providers as _np
            d = request.json or {}
            user_id = g.current_user_id
            if _hub_state("ELECTRICITY") != "live":
                return jsonify({"success": False, "error": "Electricity payments are not open yet"}), 503
            try:
                import net365_recovery as _rc
                _mb = _rc.maintenance_block("electricity")
                if _mb:
                    return _mb
            except ImportError:
                pass
            country = str(d.get("country") or "NG").upper()
            if country != "NG":
                return jsonify({"success": False, "error": "Only Nigeria is open for now"}), 400
            pref = "auto"                                   # processor choice is Net365's, never the customer's
            disco, opts = _elec_pick(country, str(d.get("key") or ""), pref)
            if not disco or not opts:
                return jsonify({"success": False, "error": "That electricity company or provider is not available"}), 404
            meter = re.sub(r"[\s-]", "", str(d.get("meter") or ""))
            mtype = "postpaid" if str(d.get("meter_type") or "").lower().startswith("post") else "prepaid"
            if not re.fullmatch(r"[A-Za-z0-9]{6,20}", meter):
                return jsonify({"success": False, "error": "Enter a valid meter number"}), 400
            user = db.get_user(user_id) or {}
            # Use the number typed/confirmed at checkout; if it is missing or not Nigerian (e.g. a chat id), use the registered one.
            phone = re.sub(r"[^\d+]", "", str(d.get("phone") or ""))
            if not _np.local_number(phone):
                phone = re.sub(r"[^\d+]", "", str(user.get("phone") or ""))
            if not _np.local_number(phone):
                return jsonify({"success": False, "error": "Enter a valid Nigerian phone number"}), 400
            try:
                amount = round(float(d.get("amount")), 2)
            except (TypeError, ValueError):
                return jsonify({"success": False, "error": "Enter an amount"}), 400
            lo, hi = _elec_amount_bounds(opts)
            if amount < lo or amount > hi:
                return jsonify({"success": False, "error": f"Amount must be between ₦{lo:,.0f} and ₦{hi:,.0f}"}), 400
            v = _elec_verify(opts, disco["key"], meter, mtype)          # never take money for an unchecked meter
            if not v.get("ok"):
                if not v.get("unavailable"):
                    _wd = _wrong_disco(meter, mtype, disco["key"], disco["name"])
                    if _wd:
                        return jsonify(_wd), 422
                return jsonify({"success": False, "error": v.get("message") or "Meter could not be verified"}), (503 if v.get("unavailable") else 422)
            if v.get("min_amount") and amount < float(v["min_amount"]):
                return jsonify({"success": False, "error": f"The minimum for this meter is ₦{float(v['min_amount']):,.0f}"}), 400
            src = str(d.get("source") or "")
            fee = server_fee_for(amount, "NGN") if src in ("telegram", "whatsapp") else 0.0
            charge = round(amount + fee, 2)
            try:
                from net365_whatsapp import chat_purchase_error
                _ce = chat_purchase_error(user_id, charge, "NGN")
                if _ce:
                    return jsonify(_ce[0]), _ce[1]
            except ImportError:
                _le = _purchase_limit_error(user_id, charge, "NGN")
                if _le:
                    return jsonify({"success": False, "error": _le}), 400
            email = str(d.get("email") or "").strip() or user.get("email") or os.getenv("DEFAULT_PAYMENT_EMAIL", f"user_{user_id}@net365.com")
            result = self.platform.create_payment(amount=charge, currency="NGN", email=email,
                                                  return_url=_safe_payment_return_url(d.get("return_url")), provider="paystack")
            if not (result.get("success") and result.get("reference")):
                return jsonify(result), 502
            rl = next((o for o in disco["options"] if o["provider"] == "reloadly"), None)
            payload = {"hub": True, "disco": disco["key"], "provider_pref": "auto",
                       "biller_id": (rl or {}).get("biller_id"), "meter_type": mtype, "subscriber_account": encrypt_pii(meter), "phone": encrypt_pii(phone),
                       "service_amount": amount, "fee_amount": fee, "biller_name": disco["name"][:60], "customer_name": v.get("name", ""),
                       "currency": "NGN", "email": email, "user_id": user_id, "payment_method": "paystack"}
            if src in ("telegram", "whatsapp"):
                payload["source"] = src
            db.create_pending(reference=result["reference"], tx_type="electricity", provider=result.get("provider", "paystack"),
                              amount=charge, currency="NGN", payload=payload, user_id=user_id)
            return jsonify({"success": True, "authorization_url": result.get("authorization_url") or result.get("checkout_url"),
                            "reference": result["reference"], "amount": charge, "service_amount": amount, "fee_amount": fee,
                            "customer_name": v.get("name", ""), "disco": disco["name"]})

        # ---- insurance (motor third-party first). Off until HUB_INSURANCE=live and VTpass is configured.
        _INS_PRODUCTS = {"ui-insure": "Third-party motor insurance"}

        def _insurance_details(d):
            """Validate and normalise the policy details. Returns (details, error)."""
            rules = {"Insured_Name": (r"[A-Za-z][A-Za-z .'\-]{2,59}", "Enter the owner's full name"),
                     "Plate_Number": (r"[A-Za-z0-9][A-Za-z0-9\- ]{3,11}", "Enter a valid plate number"),
                     "Chasis_Number": (r"[A-Za-z0-9]{5,25}", "Enter a valid chassis number (letters and digits only)"),
                     "vehicle_Make": (r"[A-Za-z0-9][A-Za-z0-9 .\-]{1,29}", "Enter the vehicle make"),
                     "vehicle_Model": (r"[A-Za-z0-9][A-Za-z0-9 .\-]{0,29}", "Enter the vehicle model"),
                     "vehicle_Color": (r"[A-Za-z][A-Za-z /\-]{1,29}", "Enter the vehicle colour"),
                     "engine_capacity": (r"\d{3,5}", "Enter the engine size in cc, for example 1600"),
                     "state": (r"[A-Za-z][A-Za-z .\-]{1,39}", "Enter the state"),
                     "lga": (r"[A-Za-z][A-Za-z .\-/]{1,39}", "Enter the local government area"),
                     "email": (r"[^@\s]{1,64}@[^@\s]{1,120}\.[A-Za-z]{2,}", "Enter a valid email address")}
            out = {}
            for f, (rx, msg) in rules.items():
                val = re.sub(r"\s+", " ", str(d.get(f) or "")).strip()
                if not re.fullmatch(rx, val):
                    return None, msg
                out[f] = val.upper() if f in ("Plate_Number", "Chasis_Number") else val
            yr = re.sub(r"\D", "", str(d.get("YearofMake") or ""))
            if not (len(yr) == 4 and 1980 <= int(yr) <= datetime.now().year + 1):
                return None, "Enter the year the vehicle was made, for example 2018"
            out["YearofMake"] = yr
            return out, None

        @self.app.route("/api/insurance/products", methods=["GET"])
        @safe_api_response
        def insurance_products():
            import net365_providers as _np
            if _hub_state("INSURANCE") != "live" or not (_np.enabled() and _np.provider_ready("vtpass")):
                return jsonify({"success": False, "error": "Insurance is not available yet"}), 404
            out = []
            for pid, label in _INS_PRODUCTS.items():
                plans = _np.service_catalog(pid)
                if plans:
                    out.append({"product": pid, "label": label, "plans": plans})
            if not out:
                return jsonify({"success": False, "error": "Cover options are unavailable right now. Please try again shortly."}), 503
            return jsonify({"success": True, "products": out})

        @self.app.route("/api/insurance/checkout", methods=["POST"])
        @login_required
        @email_verified_required
        @safe_api_response
        def insurance_checkout():
            """Start a gateway payment for a motor policy. The premium comes from the provider's catalogue, never the request."""
            import net365_providers as _np
            d = request.json or {}
            user_id = g.current_user_id
            if _hub_state("INSURANCE") != "live" or not (_np.enabled() and _np.provider_ready("vtpass")):
                return jsonify({"success": False, "error": "Insurance is not available yet"}), 503
            try:
                import net365_recovery as _rc
                _mb = _rc.maintenance_block("insurance")
                if _mb:
                    return _mb
            except ImportError:
                pass
            product = str(d.get("product") or "").lower()
            code = str(d.get("variation_code") or "")
            if product not in _INS_PRODUCTS or not code:
                return jsonify({"success": False, "error": "Invalid request"}), 400
            if d.get("accept") is not True:
                return jsonify({"success": False, "error": "Please confirm the policy details and accept the insurance terms"}), 400
            plan = _np.find_service_plan(product, code)
            if not plan:
                return jsonify({"success": False, "error": "That cover is no longer available. Please pick again."}), 409
            details, err = _insurance_details(d.get("details") or {})
            if err:
                return jsonify({"success": False, "error": err}), 400
            phone = re.sub(r"[^\d+]", "", str(d.get("phone") or ""))
            if not _np.local_number(phone):
                return jsonify({"success": False, "error": "Enter a valid Nigerian phone number"}), 400
            amount = float(plan["price"])
            src = str(d.get("source") or "")
            fee = server_fee_for(amount, "NGN") if src in ("telegram", "whatsapp") else 0.0
            charge = round(amount + fee, 2)
            try:
                from net365_whatsapp import chat_purchase_error
                _ce = chat_purchase_error(user_id, charge, "NGN")
                if _ce:
                    return jsonify(_ce[0]), _ce[1]
            except ImportError:
                _le = _purchase_limit_error(user_id, charge, "NGN")
                if _le:
                    return jsonify({"success": False, "error": _le}), 400
            user = db.get_user(user_id) or {}
            email = details["email"] or user.get("email") or os.getenv("DEFAULT_PAYMENT_EMAIL", f"user_{user_id}@net365.com")
            result = self.platform.create_payment(amount=charge, currency="NGN", email=email,
                                                  return_url=_safe_payment_return_url(d.get("return_url")), provider="paystack")
            if not (result.get("success") and result.get("reference")):
                return jsonify(result), 502
            payload = {"product": product, "variation_code": code, "phone": encrypt_pii(phone), "email": email,
                       "subscriber_account": encrypt_pii(json.dumps(details)),        # policy details are personal data: encrypted like the other PII
                       "service_amount": amount, "fee_amount": fee, "biller_name": f"{_INS_PRODUCTS[product]} {plan['name']}"[:60],
                       "customer_name": details["Insured_Name"], "currency": "NGN", "user_id": user_id, "payment_method": "paystack",
                       "terms_accepted": True}
            if src in ("telegram", "whatsapp"):
                payload["source"] = src
            db.create_pending(reference=result["reference"], tx_type="insurance", provider=result.get("provider", "paystack"),
                              amount=charge, currency="NGN", payload=payload, user_id=user_id)
            return jsonify({"success": True, "authorization_url": result.get("authorization_url") or result.get("checkout_url"),
                            "reference": result["reference"], "amount": charge, "service_amount": amount, "fee_amount": fee, "plan": plan["name"]})

        # ============ FIX: /api/utilities/pay ENDPOINT WITH WALLET SUPPORT ============
        @self.app.route("/api/utilities/pay", methods=["POST"])
        @login_required
        @email_verified_required
        @safe_api_response
        def pay_utility_bill():
            data = request.json or {}
            user_id = g.current_user_id
            biller_id = data.get("biller_id")
            subscriber_account = data.get("subscriber_account")
            amount = data.get("amount")
            currency = data.get("currency", "NGN")
            provider = data.get("provider")
            return_url = _safe_payment_return_url(data.get("return_url"))

            user = db.get_user(user_id)
            if not user:
                logger.error(f"User {user_id} not found for utility payment")
                return jsonify({"success": False, "error": "User not found"}), 404

            email = data.get("email") or user.get("email")
            if not email:
                email = os.getenv("DEFAULT_PAYMENT_EMAIL", f"user_{user_id}@net365.com")
                logger.warning(f"No email for user {user_id}, using fallback: {email}")

            logger.info(
                f"Utility payment: user={user_id}, email={email}, biller={biller_id}, amount={amount}, currency={currency}, provider={provider}"
            )

            try:
                from net365_whatsapp import chat_purchase_error
                _ce = chat_purchase_error(user_id, amount, currency) if amount else None
                if _ce:
                    return jsonify(_ce[0]), _ce[1]
            except ImportError:
                pass

            if not biller_id or not subscriber_account or not amount:
                return (
                    jsonify({"success": False, "error": "Missing required fields"}),
                    400,
                )

            try:
                amount = float(amount)
            except (TypeError, ValueError):
                return jsonify({"success": False, "error": "Invalid amount"}), 400

            if amount <= 0:
                return (
                    jsonify(
                        {"success": False, "error": "Amount must be greater than 0"}
                    ),
                    400,
                )

            # Validate amount against biller limits
            try:
                biller_id_int = int(biller_id)
                validation = UtilityBillerValidator.validate_amount(
                    biller_id_int, amount
                )
                if not validation["valid"]:
                    logger.warning(
                        f"Utility amount validation: {validation['message']}"
                    )
                    amount = validation["adjusted"]
            except (ValueError, TypeError):
                return (
                    jsonify(
                        {"success": False, "error": f"Invalid biller_id: {biller_id}"}
                    ),
                    400,
                )

            # ============ FIX: SUPPORT WALLET PAYMENT ============
            if provider == "wallet":
                # Pay directly from wallet
                currency_upper = currency.upper()

                # Check wallet balance
                wallet = db.get_wallet(user_id, currency_upper)
                if not wallet:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"{currency_upper} wallet not found",
                            }
                        ),
                        400,
                    )

                if float(wallet.get("balance", 0)) < amount:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"Insufficient {currency_upper} wallet balance",
                            }
                        ),
                        400,
                    )

                # Generate reference
                reference = f"UTIL-WALLET-{secrets.token_hex(12)}"

                # Debit wallet
                debit_result = db.debit_wallet(
                    user_id=user_id,
                    amount=amount,
                    description=f"Utility bill payment {subscriber_account}",
                    reference=reference,
                    metadata={
                        "biller_id": biller_id,
                        "subscriber_account": subscriber_account,
                        "type": "utility",
                        "payment_method": "wallet",
                    },
                    currency=currency_upper,
                )

                if not debit_result.get("success"):
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": debit_result.get(
                                    "error", "Failed to debit wallet"
                                ),
                            }
                        ),
                        400,
                    )

                try:
                    # Execute utility payment
                    local_amount = amount
                    if self.credentials.environment.value == "sandbox":
                        biller_limits = UtilityBillerValidator.get_biller_limits(
                            biller_id_int
                        )
                        local_amount = max(
                            biller_limits.get("min", 50),
                            min(local_amount, biller_limits.get("max", 5000)),
                        )
                        logger.info(
                            f"Sandbox: using amount {currency} {local_amount:.2f} for utility biller {biller_id}"
                        )

                    import uuid

                    unique_ref = f"wallet-util-{reference}"[:36]
                    if len(unique_ref) < 10:
                        unique_ref = f"wallet-util-{reference}-{uuid.uuid4().hex[:8]}"[
                            :36
                        ]

                    logger.info(
                        f"Executing wallet utility payment: biller={biller_id}, account={subscriber_account}, amount={local_amount} {currency}, use_local_amount=True"
                    )

                    result = self.platform.pay_utility_bill(
                        biller_id=int(biller_id),
                        subscriber_account=subscriber_account,
                        amount=local_amount,
                        reference_id=unique_ref,
                        use_local_amount=True,
                    )

                    transaction_id = result.get("transactionId") or result.get("id")
                    status = str(result.get("status", "")).upper()

                    if not transaction_id and status not in ("SUCCESS", "COMPLETED"):
                        # Refund on failure
                        db.credit_wallet(
                            user_id=user_id,
                            amount=amount,
                            currency=currency_upper,
                            description=f"Refund for failed utility payment {reference}",
                            reference=f"REFUND-{reference}",
                            metadata={
                                "original_reference": reference,
                                "reason": result.get(
                                    "message", "Utility payment failed"
                                ),
                            },
                        )
                        return (
                            jsonify(
                                {
                                    "success": False,
                                    "error": result.get(
                                        "message", "Utility payment failed"
                                    ),
                                    "refunded": True,
                                }
                            ),
                            400,
                        )

                    # ============ LOG SUCCESSFUL WALLET UTILITY TRANSACTION ============
                    db.create_reloadly_transaction(
                        reference=reference,
                        user_id=user_id,
                        transaction_type="utility",
                        amount=amount,
                        status="completed",
                        provider_transaction_id=transaction_id or f"util-{reference}",
                        result=result,
                        currency=currency_upper,
                    )

                    # Create transaction record
                    db.create_pending(
                        reference=reference,
                        tx_type="utility",
                        provider="wallet",
                        amount=amount,
                        currency=currency_upper,
                        payload={
                            "biller_id": biller_id,
                            "subscriber_account": subscriber_account,
                            "payment_method": "wallet",
                            "transaction_id": transaction_id,
                        },
                        user_id=user_id,
                    )
                    db.mark_fulfilled(
                        reference, {"wallet_payment": True, "result": result}
                    )

                    log_event(
                        user_id=user_id,
                        event_type="utility",
                        details={
                            "amount": amount,
                            "currency": currency_upper,
                            "biller_id": biller_id,
                            "account": subscriber_account,
                            "reference": reference,
                            "payment_method": "wallet",
                            "transaction_id": transaction_id,
                        },
                        status="success",
                    )

                    db.create_notification(
                        user_id,
                        "Utility Payment Successful ✅",
                        f"{currency_upper} {amount:,.2f} paid for {subscriber_account} via wallet",
                        "success",
                    )

                    user = db.get_user(user_id)
                    if user and user.get("email"):
                        send_email_notification(
                            user["email"],
                            "✅ Utility Payment Successful",
                            f"Your utility payment was completed successfully via wallet.\n\nAccount: {subscriber_account}\nAmount: {currency_upper} {amount:,.2f}\nReference: {reference}",
                            include_promo=True,
                            promo_context={
                                "user_id": user_id,
                                "reference": reference,
                                "tx_type": "utility",
                                "amount": amount,
                            },
                        )

                    wallet_after = db.get_wallet(user_id, currency_upper)

                    return jsonify(
                        {
                            "success": True,
                            "transactionId": transaction_id,
                            "reference": reference,
                            "status": "completed",
                            "payment_method": "wallet",
                            "wallet_balance": (
                                wallet_after.get("balance", 0) if wallet_after else 0
                            ),
                            "currency": currency_upper,
                        }
                    )

                except Exception as e:
                    logger.exception("Utility payment failed after wallet debit")

                    # Refund
                    db.credit_wallet(
                        user_id=user_id,
                        amount=amount,
                        currency=currency_upper,
                        description=f"Refund for failed utility payment {reference}",
                        reference=f"REFUND-{reference}",
                        metadata={"original_reference": reference, "reason": str(e)},
                    )

                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"Utility payment failed: {str(e)}",
                                "refunded": True,
                                "reference": reference,
                            }
                        ),
                        400,
                    )

            # ============ GATEWAY PAYMENT (Existing logic) ============
            if not provider:
                currency_upper = currency.upper()
                if currency_upper == "NGN":
                    provider = "paystack"
                elif currency_upper in ["USD", "GBP", "EUR"]:
                    provider = "stripe"
                else:
                    provider = "paystack"

            logger.info(f"Using provider: {provider} for currency: {currency}")

            # Chat-channel bill payments carry the same server-owned service fee as airtime.
            # The biller receives `amount`; the customer pays `amount + fee`.
            if _utility_provider_down():
                return jsonify({
                    "success": False, "code": "PROVIDER_UNAVAILABLE",
                    "error": "Bill payments are temporarily unavailable because our bill provider is having a problem. "
                             "You have not been charged. Please try again in a few minutes.",
                }), 503
            _chat_src = str(data.get("source") or "")
            _svc_fee = 0.0
            if _chat_src in ("telegram", "whatsapp") and str(currency).upper() == "NGN":
                _svc_fee = server_fee_for(amount, "NGN")
            _charge = round(amount + _svc_fee, 2)

            result = self.platform.create_payment(
                amount=_charge,
                currency=currency,
                email=email,
                return_url=return_url,
                provider=provider,
            )

            logger.info(f"Payment creation result: {result}")

            if result.get("success") and result.get("reference"):
                payload = {
                    "biller_id": biller_id,
                    "subscriber_account": subscriber_account,
                    "amount": amount,
                    "currency": currency,
                    "email": email,
                    "user_id": user_id,
                    "payment_method": provider,
                }
                if data.get("save_card"):
                    payload["save_card"] = True
                if _chat_src in ("telegram", "whatsapp"):
                    payload["source"] = _chat_src
                    payload["biller_name"] = str(data.get("biller_name") or "")[:60]
                    payload["service_amount"] = amount
                    payload["fee_amount"] = _svc_fee

                db.create_pending(
                    reference=result["reference"],
                    tx_type="utility",
                    provider=result.get("provider", provider or "paystack"),
                    amount=_charge,
                    currency=result.get("currency", currency),
                    payload=payload,
                    user_id=user_id,
                )

                log_event(
                    user_id=user_id,
                    event_type="utility",
                    details={
                        "amount": amount,
                        "currency": currency,
                        "biller_id": biller_id,
                        "account": subscriber_account,
                        "reference": result["reference"],
                        "payment_method": provider,
                        "status": "pending",
                    },
                    status="pending",
                )

                auth_url = result.get("authorization_url") or result.get("checkout_url")
                logger.info(f"Returning auth URL: {auth_url}")

                return jsonify(
                    {
                        "success": True,
                        "authorization_url": auth_url,
                        "reference": result["reference"],
                        "provider": result.get("provider", provider),
                        "payment_method": provider,
                        "amount": _charge,
                        "service_amount": amount,
                        "fee_amount": _svc_fee,
                    }
                )

            logger.error(f"Payment creation failed: {result}")
            return jsonify(result)

        @self.app.route("/api/utilities/confirm", methods=["POST"])
        @login_required
        @safe_api_response
        def confirm_utility_payment():
            data = request.json or {}
            reference = data.get("payment_reference") or data.get("reference")

            if not reference:
                return (
                    jsonify({"success": False, "error": "Missing payment reference"}),
                    400,
                )

            user_id = g.current_user_id
            tx, error = require_owned_transaction(reference, user_id)
            if error:
                return error

            result = self._finalize_transaction(reference)

            if result.get("success"):
                reloadly_result = result.get("result", {})
                return jsonify(
                    {
                        "success": True,
                        "transactionId": reloadly_result.get("transactionId")
                        or reloadly_result.get("id", "N/A"),
                        "already_fulfilled": result.get("already_fulfilled", False),
                        **reloadly_result,
                    }
                )

            return (
                jsonify(
                    {
                        "success": False,
                        "error": result.get("error", "Utility payment failed"),
                        "needs_review": result.get("needs_review", False),
                    }
                ),
                400,
            )

        @self.app.route("/api/receipt-ads/campaigns", methods=["POST"])
        @login_required
        @email_verified_required
        def create_receipt_ad_campaign():
            data = request.json or {}
            user_id = g.current_user_id
            title = (data.get("title") or "").strip()
            body = (data.get("body") or "").strip()
            cta_text = (data.get("cta_text") or "").strip() or None
            cta_url = (data.get("cta_url") or "").strip() or None
            currency = (data.get("currency") or "NGN").upper()
            campaign_tier = (data.get("campaign_tier") or "basic").strip().lower()

            target_tx_type = (data.get("target_tx_type") or "").strip().lower() or None
            target_customer_type = (
                data.get("target_customer_type") or ""
            ).strip().lower() or None
            target_hour_start = data.get("target_hour_start")
            target_hour_end = data.get("target_hour_end")
            target_min_amount = data.get("target_min_amount")
            target_max_amount = data.get("target_max_amount")

            budget = data.get("budget")
            clicks = data.get("clicks")
            impressions = data.get("impressions")

            if not title or not body:
                return (
                    jsonify({"success": False, "error": "Title and body are required"}),
                    400,
                )

            if len(title) > 80:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Title must be 80 characters or fewer",
                        }
                    ),
                    400,
                )

            if len(body) > 400:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Body must be 400 characters or fewer",
                        }
                    ),
                    400,
                )

            if cta_url and not (
                cta_url.startswith("http://") or cta_url.startswith("https://")
            ):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "CTA URL must start with http:// or https://",
                        }
                    ),
                    400,
                )

            if campaign_tier not in ("basic", "premium", "dominant", "performance"):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "campaign_tier must be 'basic', 'premium', 'dominant', or 'performance'",
                        }
                    ),
                    400,
                )

            if campaign_tier == "premium":
                if not budget or float(budget) <= 0:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "Budget is required for Premium tier",
                            }
                        ),
                        400,
                    )
                budget = float(budget)
                if (
                    budget < db.RECEIPT_AD_PREMIUM_MIN_BUDGET
                    or budget > db.RECEIPT_AD_PREMIUM_MAX_BUDGET
                ):
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": f"Premium budget must be between {db.RECEIPT_AD_PREMIUM_MIN_BUDGET:,.0f} and {db.RECEIPT_AD_PREMIUM_MAX_BUDGET:,.0f}",
                            }
                        ),
                        400,
                    )
                impressions = int(budget / db.RECEIPT_AD_PREMIUM_PRICE_PER_IMPRESSION)
                price = budget

            elif campaign_tier == "performance":
                # Blocked: this tier bills advertisers upfront for "verified clicks",
                # but click tracking is entirely unimplemented on the backend — there
                # is no /r/<click_token> redirect endpoint, nothing ever writes to the
                # receipt_ad_clicks table, and clicks_delivered never increments. That
                # means a purchased campaign can never register a click, never
                # complete, and never deliver what advertisers paid for. Taking real
                # money for this today is a real risk, so it's disabled server-side
                # until click tracking is actually built and tested end-to-end.
                #
                # The original validation/pricing logic (kept here for whoever builds
                # tracking next, rather than deleted) was:
                #   if not clicks or int(clicks) <= 0: error "clicks required"
                #   clicks = int(clicks)
                #   if clicks < RECEIPT_AD_PERFORMANCE_MIN_CLICKS or clicks > RECEIPT_AD_PERFORMANCE_MAX_CLICKS: error
                #   price = round(clicks * RECEIPT_AD_PERFORMANCE_DEFAULT_COST_PER_CLICK, 2)
                #   impressions = None
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Performance (pay-per-click) campaigns aren't available yet — click tracking is still being built. Try Basic, Premium, or Dominant instead.",
                        }
                    ),
                    400,
                )

            elif campaign_tier == "basic":
                impressions = db.RECEIPT_AD_BASIC_IMPRESSIONS
                price = db.RECEIPT_AD_BASIC_PRICE

            elif campaign_tier == "dominant":
                if db.dominant_slot_is_occupied():
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "The Dominant slot is currently occupied by another campaign (pending review or live). Try again once it completes, or choose the Basic tier.",
                            }
                        ),
                        409,
                    )
                impressions = db.RECEIPT_AD_DOMINANT_IMPRESSIONS
                price = db.RECEIPT_AD_DOMINANT_PRICE

            def _clean_hour(v):
                if v is None or v == "":
                    return None
                try:
                    h = int(v)
                    return h if 0 <= h <= 23 else None
                except (TypeError, ValueError):
                    return None

            target_hour_start = _clean_hour(target_hour_start)
            target_hour_end = _clean_hour(target_hour_end)

            def _clean_amount(v):
                if v is None or v == "":
                    return None
                try:
                    return float(v)
                except (TypeError, ValueError):
                    return None

            target_min_amount = _clean_amount(target_min_amount)
            target_max_amount = _clean_amount(target_max_amount)

            if (
                target_min_amount is not None
                and target_max_amount is not None
                and target_min_amount > target_max_amount
            ):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "target_min_amount cannot exceed target_max_amount",
                        }
                    ),
                    400,
                )

            if target_tx_type and target_tx_type not in db.RECEIPT_AD_VALID_TX_TYPES:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"target_tx_type must be one of {sorted(db.RECEIPT_AD_VALID_TX_TYPES)} or omitted",
                        }
                    ),
                    400,
                )

            if target_customer_type and target_customer_type not in (
                "new",
                "returning",
            ):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "target_customer_type must be 'new', 'returning', or omitted",
                        }
                    ),
                    400,
                )

            db.ensure_wallet(user_id, currency)
            wallet = db.get_wallet(user_id, currency)
            available = float(
                wallet.get("available_balance", wallet.get("balance", 0))
                if wallet
                else 0
            )
            price = round(price, 2)

            if available < price:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"Insufficient balance. Campaign costs {currency} {price:,.2f}, wallet has {currency} {available:,.2f}",
                        }
                    ),
                    400,
                )

            reference = generate_reference("ADCAMP")
            debit_result = db.debit_wallet(
                user_id=user_id,
                amount=price,
                currency=currency,
                reference=reference,
                description=f"Receipt ad campaign ({campaign_tier}): {title}",
                metadata={
                    "type": "receipt_ad_campaign",
                    "impressions": impressions,
                    "tier": campaign_tier,
                    "clicks": clicks if campaign_tier == "performance" else None,
                },
            )
            if not debit_result.get("success"):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": debit_result.get("error", "Payment failed"),
                        }
                    ),
                    400,
                )

            campaign = db.create_sponsored_campaign(
                advertiser_user_id=user_id,
                title=title,
                body=body,
                impressions=impressions,
                cta_text=cta_text,
                cta_url=cta_url,
                currency=currency,
                campaign_tier=campaign_tier,
                budget=budget if campaign_tier == "premium" else None,
                clicks=clicks if campaign_tier == "performance" else None,
                target_tx_type=target_tx_type,
                target_min_amount=target_min_amount,
                target_max_amount=target_max_amount,
                target_customer_type=target_customer_type,
                target_hour_start=target_hour_start,
                target_hour_end=target_hour_end,
            )

            log_event(
                user_id=user_id,
                event_type="receipt_ad_campaign_created",
                details={
                    "campaign_id": campaign.get("id"),
                    "impressions": impressions,
                    "price": price,
                    "tier": campaign_tier,
                },
                status="success",
            )

            logger.info(
                f"Receipt ad campaign #{campaign.get('id')} created by user {user_id}: "
                f"{impressions or clicks} {'impressions' if impressions else 'clicks'} for {currency} {price:,.2f}, pending review"
            )

            return jsonify(
                {
                    "success": True,
                    "campaign": campaign,
                    "message": "Campaign submitted for review. You'll be notified once it's approved and starts running.",
                }
            )

        @self.app.route(
            "/api/receipt-ads/campaigns/<int:campaign_id>/pause", methods=["POST"]
        )
        @login_required
        def pause_receipt_ad_campaign(campaign_id):
            paused = db.pause_sponsored_campaign(campaign_id, g.current_user_id)
            if not paused:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Campaign not found, not yours, or not currently active",
                        }
                    ),
                    404,
                )
            return jsonify({"success": True})

            # ============ ADMIN: VISITOR STATS ============

        @self.app.route("/api/admin/visitors/stats", methods=["GET"])
        @admin_required
        def get_admin_visitor_stats():
            """Get visitor statistics for admin dashboard."""
            try:
                stats = db.get_visitor_stats()
                return jsonify({"success": True, "stats": stats})
            except Exception as e:
                logger.error(f"Error getting visitor stats: {e}")
                return jsonify({"success": False, "error": str(e)}), 500





        # ---- moved here from dead code inside get_authenticated_user(): these routes were never registered ----
        # ============ ADMIN: ALL RECEIPT ADS ============
        @self.app.route("/api/admin/receipt-ads/all", methods=["GET"])
        @admin_required
        def admin_list_all_receipt_ads():
            """Get all receipt ads for admin."""
            limit = min(request.args.get("limit", 50, type=int), 100)
            offset = max(request.args.get("offset", 0, type=int), 0)
            campaigns = db.get_all_sponsored_campaigns(limit, offset)
            return jsonify(
                {"success": True, "campaigns": campaigns, "count": len(campaigns)}
            )

        # ============ PROMOTIONS MANAGEMENT API ============
        @self.app.route("/api/admin/promotions", methods=["GET"])
        @admin_required
        def admin_get_promotions():
            """Get all promotions with pagination."""
            limit = min(request.args.get("limit", 50, type=int), 100)
            offset = max(request.args.get("offset", 0, type=int), 0)
            promotions = db.get_all_promotions(limit, offset)
            return jsonify({"success": True, "promotions": promotions})

        @self.app.route("/api/admin/promotions", methods=["POST"])
        @admin_required
        def admin_create_promotion():
            """Create a new promotion."""
            data = request.json or {}

            required = ["name", "title", "body"]
            missing = [f for f in required if not data.get(f)]
            if missing:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"Missing required fields: {', '.join(missing)}",
                        }
                    ),
                    400,
                )

            promo_id = db.create_promotion(
                name=data.get("name"),
                title=data.get("title"),
                body=data.get("body"),
                cta_text=data.get("cta_text"),
                cta_url=data.get("cta_url"),
                promo_type=data.get("promo_type", "standard"),
                category=data.get("category", "general"),
                icon=data.get("icon", "🎁"),
                brand_color=data.get("brand_color", "#4f46e5"),
                background_color=data.get("background_color", "#f5f3ff"),
                text_color=data.get("text_color", "#1e293b"),
                active=data.get("active", True),
                priority=data.get("priority", 0),
                start_date=data.get("start_date"),
                end_date=data.get("end_date"),
                target_tx_type=data.get("target_tx_type"),
                target_min_amount=data.get("target_min_amount"),
                target_max_amount=data.get("target_max_amount"),
                target_customer_type=data.get("target_customer_type"),
                target_hour_start=data.get("target_hour_start"),
                target_hour_end=data.get("target_hour_end"),
                target_days=data.get("target_days"),
                max_impressions=data.get("max_impressions"),
                max_clicks=data.get("max_clicks"),
                metadata=data.get("metadata"),
                created_by=(
                    g.current_user.get("id") if hasattr(g, "current_user") else None
                ),
            )

            if promo_id:
                return jsonify(
                    {
                        "success": True,
                        "promotion_id": promo_id,
                        "message": "Promotion created successfully",
                    }
                )
            return (
                jsonify({"success": False, "error": "Failed to create promotion"}),
                500,
            )

        @self.app.route("/api/admin/promotions/<int:promo_id>", methods=["GET"])
        @admin_required
        def admin_get_promotion(promo_id):
            """Get a specific promotion."""
            promo = db.get_promotion(promo_id)
            if not promo:
                return jsonify({"success": False, "error": "Promotion not found"}), 404
            return jsonify({"success": True, "promotion": promo})

        @self.app.route("/api/admin/promotions/<int:promo_id>", methods=["PUT"])
        @admin_required
        def admin_update_promotion(promo_id):
            """Update a promotion."""
            data = request.json or {}
            result = db.update_promotion(promo_id, **data)
            if result:
                return jsonify(
                    {"success": True, "message": "Promotion updated successfully"}
                )
            return (
                jsonify({"success": False, "error": "Failed to update promotion"}),
                500,
            )

        @self.app.route("/api/admin/promotions/<int:promo_id>", methods=["DELETE"])
        @admin_required
        def admin_delete_promotion(promo_id):
            """Delete a promotion."""
            if db.delete_promotion(promo_id):
                return jsonify({"success": True, "message": "Promotion deleted"})
            return jsonify({"success": False, "error": "Promotion not found"}), 404

        # ============ BRAND COLORS MANAGEMENT ============
        @self.app.route("/api/admin/brand-colors", methods=["GET"])
        @admin_required
        def admin_get_brand_colors():
            """Get all brand colors."""
            brands = db.get_all_brand_colors()
            return jsonify({"success": True, "brands": brands})

        @self.app.route("/api/admin/brand-colors", methods=["POST"])
        @admin_required
        def admin_upsert_brand_colors():
            """Create or update brand colors."""
            data = request.json or {}
            required = ["advertiser_id", "advertiser_name", "primary_color"]
            missing = [f for f in required if not data.get(f)]
            if missing:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"Missing required fields: {', '.join(missing)}",
                        }
                    ),
                    400,
                )

            result = db.upsert_brand_colors(
                advertiser_id=data["advertiser_id"],
                advertiser_name=data["advertiser_name"],
                primary_color=data["primary_color"],
                secondary_color=data.get("secondary_color"),
                accent_color=data.get("accent_color"),
                text_color=data.get("text_color"),
                background_color=data.get("background_color"),
                logo_url=data.get("logo_url"),
            )

            if result:
                return jsonify({"success": True, "message": "Brand colors saved"})
            return (
                jsonify({"success": False, "error": "Failed to save brand colors"}),
                500,
            )

        @self.app.route("/api/admin/brand-colors/<advertiser_id>", methods=["DELETE"])
        @admin_required
        def admin_delete_brand_colors(advertiser_id):
            """Delete brand colors for an advertiser."""
            conn = db.get_db_connection()
            c = conn.cursor()
            try:
                c.execute(
                    "DELETE FROM brand_colors WHERE advertiser_id = ?", (advertiser_id,)
                )
                conn.commit()
                if c.rowcount > 0:
                    return jsonify({"success": True, "message": "Brand colors deleted"})
                return jsonify({"success": False, "error": "Brand not found"}), 404
            except Exception as e:
                logger.error(f"Failed to delete brand colors: {e}")
                return jsonify({"success": False, "error": str(e)}), 500
            finally:
                conn.close()

       

        # ============ ADMIN: SMS CONFIG ============
        @self.app.route("/api/admin/sms/config", methods=["GET"])
        @admin_required
        def admin_get_sms_config():
            """Get SMS provider configuration."""
            try:
                config = db.get_sms_config()
                if config:
                    masked = {}
                    for k, v in config.items():
                        if (
                            k in ["api_key", "auth_token", "account_sid", "password"]
                            and v
                        ):
                            masked[k] = (
                                v[:4] + "****" + v[-4:] if len(v) > 8 else "****"
                            )
                        else:
                            masked[k] = v
                    return jsonify({"success": True, "config": masked})
                return jsonify({"success": True, "config": None})
            except Exception as e:
                logger.error(f"Error getting SMS config: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        @self.app.route("/api/admin/sms/config", methods=["POST"])
        @admin_required
        def admin_save_sms_config():
            """Save SMS provider configuration."""
            data = request.json or {}
            provider = data.get("provider", "none")

            config = {
                "provider": provider,
                "sender_id": data.get("sender_id", "Net365"),
                "api_key": data.get("api_key", ""),
                "account_sid": data.get("account_sid", ""),
                "auth_token": data.get("auth_token", ""),
                "from_number": data.get("from_number", ""),
                "username": data.get("username", "sandbox"),
            }

            db.save_sms_config(config)
            return jsonify(
                {"success": True, "message": f"SMS provider configured: {provider}"}
            )

        @self.app.route("/api/admin/sms/config", methods=["DELETE"])
        @admin_required
        def admin_delete_sms_config():
            """Clear SMS provider configuration."""
            db.save_sms_config({"provider": "none"})
            return jsonify({"success": True, "message": "SMS configuration cleared"})

        @self.app.route("/api/admin/sms/test", methods=["POST"])
        @admin_required
        def admin_test_sms_config():
            """Test SMS configuration."""
            data = request.json or {}
            phone = data.get("phone")
            message = data.get("message", "Test SMS from Net365 Admin")

            if not phone:
                return (
                    jsonify({"success": False, "error": "Phone number is required"}),
                    400,
                )

            # Use the existing SMS provider function
            if not SMS_PROVIDER_CONFIGURED:
                return (
                    jsonify({"success": False, "error": "No SMS provider configured"}),
                    400,
                )

            result = send_sms_via_provider(
                contacts=[phone], message=message, sender_id="Net365"
            )

            if result.get("sent", 0) > 0:
                return jsonify(
                    {
                        "success": True,
                        "sent": result.get("sent"),
                        "provider": SMS_PROVIDER_NAME,
                    }
                )
            else:
                errors = result.get("errors", ["Unknown error"])
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": errors[0] if errors else "Failed to send",
                        }
                    ),
                    400,
                )

        # ============ ADMIN: TRANSACTIONS ============
        @self.app.route("/api/admin/transactions", methods=["GET"])
        @admin_required
        def admin_get_transactions():
            """Get transactions for admin with filters."""
            limit = min(request.args.get("limit", 20, type=int), 100)
            offset = max(request.args.get("offset", 0, type=int), 0)
            status = request.args.get("status")
            tx_type = request.args.get("tx_type")
            date = request.args.get("date")

            try:
                transactions, total = db.get_admin_transactions(
                    limit, offset, status, tx_type, date
                )
                return jsonify(
                    {
                        "success": True,
                        "transactions": transactions,
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                    }
                )
            except Exception as e:
                logger.error(f"Error fetching admin transactions: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

        # ============ ADMIN: TRANSACTION DETAIL ============
        @self.app.route("/api/transaction/<reference>", methods=["GET"])
        @admin_required
        def admin_get_transaction_detail(reference):
            """Get a single transaction by reference."""
            tx = db.get_transaction(reference)
            if not tx:
                return (
                    jsonify({"success": False, "error": "Transaction not found"}),
                    404,
                )
            return jsonify({"success": True, "transaction": tx})

        # ============ ADMIN: RETRY FULFILLMENT ============
        @self.app.route("/api/admin/retry-fulfillment/<reference>", methods=["POST"])
        @admin_required
        def admin_retry_fulfillment(reference):
            """Retry fulfillment for a failed transaction."""
            result = self._finalize_transaction(reference)
            return jsonify(result)

        # ============ ADMIN: BULK REFUNDS DUE ============
        @self.app.route("/api/admin/bulk-refunds-due", methods=["GET"])
        @admin_required
        def admin_bulk_refunds_due():
            status = (request.args.get("status") or "due").strip()
            conn = db.get_db_connection()
            try:
                rows = conn.execute(
                    "SELECT * FROM bulk_refunds_due WHERE status = ? ORDER BY created_at DESC LIMIT 500",
                    (status,),
                ).fetchall()
            finally:
                conn.close()
            return jsonify({"success": True, "refunds": [dict(r) for r in rows]})

        @self.app.route("/api/admin/bulk-refunds-due/<reference>/resolve", methods=["POST"])
        @admin_required
        def admin_bulk_refund_resolve(reference):
            """Mark a gateway refund as done (after you refunded in the Paystack/Flutterwave dashboard)."""
            note = str((request.get_json(silent=True) or {}).get("note") or "")[:300]
            conn = db.get_db_connection()
            try:
                cur = conn.execute(
                    "UPDATE bulk_refunds_due SET status='refunded', note=? WHERE reference=? AND status='due'",
                    (note or "refunded via gateway", reference),
                )
                changed = cur.rowcount
            finally:
                conn.close()
            if not changed:
                return jsonify({"success": False, "error": "No open refund with that reference"}), 404
            return jsonify({"success": True})

        # ============ ADMIN: RESOLVE needs_review SCHEDULE ============
        @self.app.route("/api/admin/schedules/<schedule_id>/resolve", methods=["POST"])
        @admin_required
        def admin_resolve_schedule(schedule_id):
            """Close a needs_review schedule. action = "refund" (credit the wallet `amount`, once) or
            "mark_fulfilled" (provider delivered; just close it)."""
            data = request.get_json(silent=True) or {}
            action = str(data.get("action") or "").strip().lower()
            note = str(data.get("note") or "")[:300]
            conn = db.get_db_connection()
            try:
                row = conn.execute(
                    "SELECT id, user_id, currency, status FROM scheduler_schedules WHERE id = ?",
                    (schedule_id,),
                ).fetchone()
            finally:
                conn.close()
            if not row:
                return jsonify({"success": False, "error": "Schedule not found"}), 404
            if row["status"] != "needs_review":
                return jsonify({"success": False, "error": "Schedule is not in needs_review"}), 409
            if action == "refund":
                try:
                    amount = round(float(data.get("amount")), 2)
                except (TypeError, ValueError):
                    return jsonify({"success": False, "error": "amount is required for a refund"}), 400
                if amount <= 0:
                    return jsonify({"success": False, "error": "amount must be positive"}), 400
                res = db.credit_wallet(
                    user_id=row["user_id"], amount=amount, currency=row["currency"] or "NGN",
                    description=f"Admin refund for schedule {schedule_id}",
                    reference=f"ADMINREFUND-{schedule_id}",
                    metadata={"note": note},
                )
                if not res or not res.get("success"):
                    return jsonify({"success": False, "error": (res or {}).get("error") or "Refund failed"}), 500
                new_status = "failed"
            elif action == "mark_fulfilled":
                new_status = "completed"
            else:
                return jsonify({"success": False, "error": 'action must be "refund" or "mark_fulfilled"'}), 400
            conn = db.get_db_connection()
            try:
                conn.execute(
                    "UPDATE scheduler_schedules SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'needs_review'",
                    (new_status, schedule_id),
                )
            finally:
                conn.close()
            logger.warning(f"Admin resolved schedule {schedule_id}: {action} {note}")
            return jsonify({"success": True, "status": new_status})

        @self.app.route("/api/admin/users", methods=["GET"])
        @admin_required
        def admin_search_users():
            query = (request.args.get("q") or "").strip()
            include_deleted = request.args.get("include_deleted") in ("1", "true", "yes")
            _not_deleted = "" if include_deleted else " AND COALESCE(account_status,'active') != 'deleted'"
            conn = db.get_db_connection()
            c = conn.cursor()

            if not query:
                # Return total count and empty list when no query (deleted accounts are audited separately)
                total = c.execute("SELECT COUNT(*) FROM users WHERE 1=1" + _not_deleted).fetchone()[0] or 0
                conn.close()
                return jsonify({"success": True, "users": [], "total": total})

            rows = c.execute(
                """
                SELECT id, email, phone, full_name, account_status, status_reason, status_changed_at,
                       email_verified, phone_verified, created_at
                FROM users WHERE (email LIKE ? OR phone LIKE ? OR full_name LIKE ?)""" + _not_deleted + """
                LIMIT 25
                """,
                (f"%{query}%", f"%{query}%", f"%{query}%"),
            ).fetchall()
            conn.close()
            return jsonify({"success": True, "users": [dict(r) for r in rows]})

        @self.app.route("/api/admin/receipt-ads/pending", methods=["GET"])
        @admin_required
        def admin_list_pending_receipt_ads():
            return jsonify(
                {"success": True, "campaigns": db.get_pending_sponsored_campaigns()}
            )

        @self.app.route(
            "/api/admin/receipt-ads/<int:campaign_id>/approve", methods=["POST"]
        )
        @admin_required
        def admin_approve_receipt_ad(campaign_id):
            result = db.moderate_sponsored_campaign(
                campaign_id, approve=True, reviewer=_admin_identity()
            )
            if not result:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Campaign not found or not pending review",
                        }
                    ),
                    404,
                )
            logger.warning(
                f"Admin {_admin_identity()} APPROVED receipt ad campaign #{campaign_id}"
            )
            return jsonify({"success": True, "campaign": result})

        @self.app.route(
            "/api/admin/receipt-ads/<int:campaign_id>/reject", methods=["POST"]
        )
        @admin_required
        def admin_reject_receipt_ad(campaign_id):
            data = request.json or {}
            reason = (
                data.get("reason") or ""
            ).strip() or "Did not meet content guidelines"
            refund = data.get("refund", True)

            all_pending = db.get_pending_sponsored_campaigns()
            campaign = next((c for c in all_pending if c["id"] == campaign_id), None)
            if not campaign:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Campaign not found or not pending review",
                        }
                    ),
                    404,
                )

            result = db.moderate_sponsored_campaign(
                campaign_id, approve=False, reviewer=_admin_identity(), reason=reason
            )
            if not result:
                return (
                    jsonify({"success": False, "error": "Could not reject campaign"}),
                    400,
                )

            if (
                refund
                and campaign.get("price_paid")
                and campaign.get("advertiser_user_id")
            ):
                db.credit_wallet(
                    user_id=campaign["advertiser_user_id"],
                    amount=float(campaign["price_paid"]),
                    currency=campaign.get("price_currency", "NGN"),
                    description=f"Refund: receipt ad campaign rejected ({reason})",
                    reference=generate_reference("ADREFUND"),
                    metadata={"type": "receipt_ad_refund", "campaign_id": campaign_id},
                )
                logger.warning(
                    f"Admin {_admin_identity()} REJECTED campaign #{campaign_id} and refunded "
                    f"{campaign.get('price_currency')} {campaign['price_paid']} — reason: {reason}"
                )

            return jsonify(
                {"success": True, "campaign": result, "refunded": bool(refund)}
            )

        def _admin_identity() -> str:
            # Last X-Forwarded-For entry is the one Railway's edge appended; earlier ones are forgeable.
            return (
                request.headers.get("CF-Connecting-IP")
                or request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[-1].strip()
            )

        @self.app.route(
            "/api/admin/users/<int:target_user_id>/suspend", methods=["POST"]
        )
        @admin_required
        def admin_suspend_user(target_user_id):
            data = request.json or {}
            reason = (data.get("reason") or "").strip()
            if not reason:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "A reason is required to suspend an account",
                        }
                    ),
                    400,
                )
            if not db.get_user(target_user_id):
                return jsonify({"success": False, "error": "User not found"}), 404

            db.set_account_status(target_user_id, "suspended", reason)
            log_event(
                user_id=target_user_id,
                event_type="account_suspended",
                details={"reason": reason, "admin": _admin_identity()},
                status="success",
            )
            db.create_notification(
                target_user_id,
                "⚠️ Account Suspended",
                f"Your account has been suspended. Reason: {reason}. Contact support for help.",
                "warning",
            )
            return jsonify({"success": True, "message": "Account suspended."})

        @self.app.route("/api/admin/users/<int:target_user_id>/block", methods=["POST"])
        @admin_required
        def admin_block_user(target_user_id):
            data = request.json or {}
            reason = (data.get("reason") or "").strip()
            if not reason:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "A reason is required to block an account",
                        }
                    ),
                    400,
                )
            if not db.get_user(target_user_id):
                return jsonify({"success": False, "error": "User not found"}), 404

            db.set_account_status(target_user_id, "blocked", reason)
            killed = db.kill_user_sessions(target_user_id)
            log_event(
                user_id=target_user_id,
                event_type="account_blocked",
                details={
                    "reason": reason,
                    "admin": _admin_identity(),
                    "sessions_killed": killed,
                },
                status="success",
            )
            return jsonify(
                {
                    "success": True,
                    "message": "Account blocked and all sessions terminated.",
                }
            )

        @self.app.route(
            "/api/admin/users/<int:target_user_id>/reactivate", methods=["POST"]
        )
        @admin_required
        def admin_reactivate_user(target_user_id):
            data = request.json or {}
            reason = (data.get("reason") or "Reactivated by admin").strip()
            if not db.get_user(target_user_id):
                return jsonify({"success": False, "error": "User not found"}), 404

            db.set_account_status(target_user_id, "active", reason)
            log_event(
                user_id=target_user_id,
                event_type="account_reactivated",
                details={"reason": reason, "admin": _admin_identity()},
                status="success",
            )
            db.create_notification(
                target_user_id,
                "✅ Account Reactivated",
                "Your account has been reactivated. You can now log in normally.",
                "success",
            )
            return jsonify({"success": True, "message": "Account reactivated."})

        @self.app.route(
            "/api/admin/users/<int:target_user_id>/force-logout", methods=["POST"]
        )
        @admin_required
        def admin_force_logout(target_user_id):
            if not db.get_user(target_user_id):
                return jsonify({"success": False, "error": "User not found"}), 404
            killed = db.kill_user_sessions(target_user_id)
            log_event(
                user_id=target_user_id,
                event_type="force_logout",
                details={"admin": _admin_identity(), "sessions_killed": killed},
                status="success",
            )
            return jsonify(
                {"success": True, "message": f"{killed} session(s) terminated."}
            )

        @self.app.route(
            "/api/admin/users/<int:target_user_id>/reset-password", methods=["POST"]
        )
        @admin_required
        def admin_trigger_password_reset(target_user_id):
            user = db.get_user(target_user_id)
            if not user or not user.get("email"):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "User not found or has no email on file",
                        }
                    ),
                    404,
                )

            try:
                code = db.create_verification_otp(
                    user["email"], otp_type="password_reset", ttl_minutes=15
                )
                send_email_notification(
                    user["email"],
                    "Reset your Net365 password",
                    f"An administrator has triggered a password reset for your account. "
                    f'Your reset code is <span class="amount">{code}</span>. It expires in 15 minutes. '
                    f"If you did not expect this, contact support immediately.",
                )
                log_event(
                    user_id=target_user_id,
                    event_type="admin_password_reset_triggered",
                    details={"admin": _admin_identity()},
                    status="success",
                )
                return jsonify(
                    {
                        "success": True,
                        "message": "Password reset code sent to the user's email.",
                    }
                )
            except Exception as e:
                logger.error(
                    f"Admin-triggered password reset failed for user {target_user_id}: {e}"
                )
                return (
                    jsonify({"success": False, "error": "Could not send reset email"}),
                    500,
                )

        @self.app.route(
            "/api/admin/users/<int:target_user_id>/set-password",
            methods=["POST"]
        )
        @admin_required
        def admin_set_password_directly(target_user_id):
            """
            Admin-controlled password reset.

            Important:
            - Admin can choose the new password.
            - The plaintext password is never stored.
            - db.set_password() is responsible for hashing it.
            - All existing sessions are terminated.
            - The plaintext password is never written to the audit log.
            """

            data = request.get_json(silent=True) or {}

            new_password = data.get("new_password", "")
            confirm_password = data.get("confirm_password", "")

            # ---------------------------------------------------------
            # Validate target user
            # ---------------------------------------------------------
            user = db.get_user(target_user_id)

            if not user:
                return jsonify({
                    "success": False,
                    "error": "User not found"
                }), 404

            # ---------------------------------------------------------
            # Validate password
            # ---------------------------------------------------------
            if not new_password:
                return jsonify({
                    "success": False,
                    "error": "New password is required"
                }), 400

            if len(new_password) < 8:
                return jsonify({
                    "success": False,
                    "error": "Password must be at least 8 characters"
                }), 400

            if len(new_password) > 128:
                return jsonify({
                    "success": False,
                    "error": "Password must not exceed 128 characters"
                }), 400

            # ---------------------------------------------------------
            # Confirm password
            # ---------------------------------------------------------
            if confirm_password != new_password:
                return jsonify({
                    "success": False,
                    "error": "Passwords do not match"
                }), 400

            # ---------------------------------------------------------
            # Do not allow password changes for deleted accounts
            # ---------------------------------------------------------
            account_status = (user.get("account_status") or "active").lower()

            if account_status == "deleted":
                return jsonify({
                    "success": False,
                    "error": "Cannot set a password for a deleted account"
                }), 400

            # ---------------------------------------------------------
            # Set password
            #
            # db.set_password() should hash the password before storage.
            # NEVER store new_password directly in the database.
            # ---------------------------------------------------------
            try:
                db.set_password(target_user_id, new_password)

                # -----------------------------------------------------
                # Kill every existing login session
                # -----------------------------------------------------
                killed_sessions = db.kill_user_sessions(target_user_id)

                # -----------------------------------------------------
                # Audit event
                #
                # NEVER include the actual password.
                # -----------------------------------------------------
                log_event(
                    user_id=target_user_id,
                    event_type="admin_password_set_directly",
                    details={
                        "admin": _admin_identity(),
                        "sessions_killed": killed_sessions,
                        "method": "admin_direct_password_set"
                    },
                    status="success"
                )

                logger.warning(
                    "Admin %s directly set a new password for user_id=%s; "
                    "%s session(s) terminated",
                    _admin_identity(),
                    target_user_id,
                    killed_sessions
                )

                return jsonify({
                    "success": True,
                    "message": "Password changed successfully.",
                    "sessions_killed": killed_sessions
                })

            except Exception as e:
                logger.exception(
                    "Admin password change failed for user_id=%s",
                    target_user_id
                )

                return jsonify({
                    "success": False,
                    "error": "Could not change the password"
                }), 500

        @self.app.route(
            "/api/admin/users/<int:target_user_id>/unblock", methods=["POST"]
        )
        @admin_required
        def admin_unblock_user(target_user_id):
            data = request.json or {}
            reason = (data.get("reason") or "Unblocked by admin").strip()
            if not db.get_user(target_user_id):
                return jsonify({"success": False, "error": "User not found"}), 404
            db.set_account_status(target_user_id, "active", reason)
            log_event(
                user_id=target_user_id,
                event_type="account_unblocked",
                details={"reason": reason, "admin": _admin_identity()},
                status="success",
            )
            db.create_notification(
                target_user_id,
                "✅ Account Unblocked",
                "Your account has been unblocked. You can now log in normally.",
                "success",
            )
            return jsonify({"success": True, "message": "Account unblocked."})

        @self.app.route(
            "/api/admin/users/<int:target_user_id>/unsuspend", methods=["POST"]
        )
        @admin_required
        def admin_unsuspend_user(target_user_id):
            data = request.json or {}
            reason = (data.get("reason") or "Unsuspended by admin").strip()
            if not db.get_user(target_user_id):
                return jsonify({"success": False, "error": "User not found"}), 404
            db.set_account_status(target_user_id, "active", reason)
            log_event(
                user_id=target_user_id,
                event_type="account_unsuspended",
                details={"reason": reason, "admin": _admin_identity()},
                status="success",
            )
            db.create_notification(
                target_user_id,
                "✅ Account Unsuspended",
                "Your account has been unsuspended. You can now log in normally.",
                "success",
            )
            return jsonify({"success": True, "message": "Account unsuspended."})

        @self.app.route("/api/admin/users", methods=["POST"])
        @admin_required
        def admin_create_user():
            data = request.json or {}
            email = (data.get("email") or "").strip().lower()
            password = data.get("password")
            full_name = data.get("full_name")
            phone = (data.get("phone") or "").strip() or None
            if phone:
                try:
                    from net365_accounts import normalize_phone as _np_norm
                    _e164 = _np_norm(phone)
                except Exception:
                    _e164 = None
                if not _e164:
                    return jsonify({"success": False, "error": "That phone number does not look valid. Use 0803... or +234803..."}), 400
                phone = _e164
            if not email or not password:
                return (
                    jsonify({"success": False, "error": "Email and password required"}),
                    400,
                )
            if len(password) < 8:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Password must be at least 8 characters",
                        }
                    ),
                    400,
                )
            if db.get_user_by_email(email):
                return (
                    jsonify({"success": False, "error": "Email already registered"}),
                    400,
                )

            user_id = db.create_user(email, password, full_name, phone)
            if not user_id:
                return (
                    jsonify({"success": False, "error": "Could not create account"}),
                    500,
                )

            try:
                conn = db.get_db_connection()
                c = conn.cursor()
                c.execute(
                    "UPDATE users SET email_verified=1, verification_status='verified', verified_at=CURRENT_TIMESTAMP WHERE id=?",
                    (user_id,),
                )
                conn.commit()
            except Exception as e:
                logger.warning(
                    f"Could not mark admin-created user {user_id} as verified: {e}"
                )

            log_event(
                user_id=user_id,
                event_type="account_created_by_admin",
                details={"admin": _admin_identity(), "phone_added": bool(phone)},
                status="success",
            )
            # A phone typed in by an admin is stored UNverified: it only becomes usable for transactions after the
            # customer enters the SMS code. The admin can send that code now (or later from the user's Edit dialog).
            try:
                if phone:
                    _c2 = db.get_db_connection()
                    _c2.execute("UPDATE users SET phone_verified=0 WHERE id=?", (user_id,))
                    _c2.commit()
                    _c2.close()
            except Exception as _pe:
                logger.warning(f"Could not flag phone as unverified for {user_id}: {_pe}")
            _sent = {}
            try:
                _acct = getattr(self, "_accounts", None)
                _u = db.get_user(user_id) or {}
                if _acct and data.get("send_email_verification"):
                    _sent["email"] = _acct["send_email_code"](_u)
                if _acct and data.get("send_phone_verification") and phone:
                    _sent["phone"] = _acct["send_phone_code"](_u, _admin_identity())
            except Exception as _se:
                logger.warning(f"Verification sends after admin create failed: {_se}")
            return jsonify(
                {"success": True, "user": sanitize_user(db.get_user(user_id)), "verification_sent": _sent}
            )

        @self.app.route("/api/admin/users/<int:target_user_id>", methods=["DELETE"])
        @admin_required
        def admin_delete_user(target_user_id):
            data = request.get_json(silent=True) or {}
            try:
                from net365_accounts import clean_remarks as _cr, record_user_deletion as _rud
            except Exception as _imp:
                logger.error(f"Deletion audit module missing: {_imp}")
                return jsonify({"success": False, "error": "Deletion audit is unavailable, so nothing was deleted."}), 500
            reason = _cr(data.get("remarks") or data.get("reason"))
            if not reason:
                return jsonify({"success": False, "error": "Remarks are required to delete an account (at least 5 characters)."}), 400
            user = db.get_user(target_user_id)
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404
            if (user.get("account_status") or "active") == "deleted":
                return jsonify({"success": False, "error": "This account is already deleted."}), 409

            # Audit first: if this fails, nothing is deleted.
            try:
                _rud(db, user, reason, _admin_identity())
            except Exception as _ae:
                logger.error(f"Could not write deletion audit for {target_user_id}: {_ae}", exc_info=True)
                return jsonify({"success": False, "error": "Could not record the audit entry, so nothing was deleted."}), 500
            db.set_account_status(target_user_id, "deleted", reason)
            killed = db.kill_user_sessions(target_user_id)
            log_event(
                user_id=target_user_id,
                event_type="account_deleted",
                details={
                    "reason": reason,
                    "admin": _admin_identity(),
                    "sessions_killed": killed,
                },
                status="success",
            )
            return jsonify(
                {
                    "success": True,
                    "message": "Account deleted (soft delete — history preserved for audit purposes).",
                }
            )

        @self.app.route("/api/business/sms/send", methods=["POST"])
        @login_required
        @email_verified_required
        def send_sms_campaign():
            user_id = g.current_user_id
            data = request.json or {}

            name = (data.get("name") or "").strip()
            sender = (data.get("sender") or "Net365")[:11]
            message = (data.get("message") or "").strip()
            contact_list = data.get("contactList") or ""
            schedule_raw = data.get("schedule") or None
            schedule = None

            if schedule_raw:
                try:
                    naive_dt = datetime.fromisoformat(schedule_raw)
                    schedule = (naive_dt - timedelta(hours=1)).isoformat()
                except (ValueError, TypeError):
                    return (
                        jsonify(
                            {"success": False, "error": "Invalid schedule date/time"}
                        ),
                        400,
                    )

            contacts = data.get("contacts") or []
            MAX_SMS_RECIPIENTS = int(os.getenv("MAX_SMS_RECIPIENTS", "2000"))
            if not isinstance(contacts, list) or len(contacts) > MAX_SMS_RECIPIENTS:
                return (
                    jsonify({"success": False,
                             "error": f"A campaign can have at most {MAX_SMS_RECIPIENTS} recipients"}),
                    400,
                )

            if not name or not message or not contact_list:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Name, message, and contact list are required",
                        }
                    ),
                    400,
                )

            if len(message) > 160:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Message exceeds 160 characters (would be split into multiple SMS segments — trim it or confirm you want multi-part billing)",
                        }
                    ),
                    400,
                )

            recipient_count = len(contacts) if contacts else 0
            campaign_id = db.create_sms_campaign(
                user_id=user_id,
                name=name,
                sender_id=sender,
                message=message,
                contact_list=contact_list,
                scheduled_for=schedule,
                total_recipients=recipient_count,
                provider=SMS_PROVIDER_NAME,
                contacts=contacts,
            )

            if schedule:
                return jsonify(
                    {
                        "success": True,
                        "sent": 0,
                        "campaign_id": campaign_id,
                        "message": "Campaign scheduled — it will be sent automatically at the scheduled time.",
                    }
                )

            if not SMS_PROVIDER_CONFIGURED:
                db.update_sms_campaign_result(
                    campaign_id,
                    "queued_no_provider",
                    0,
                    0,
                    {
                        "note": "No SMS provider is configured (checked TERMII_API_KEY, TWILIO_*, AFRICASTALKING_*). Campaign saved but not sent."
                    },
                )
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "No SMS provider is configured yet, so this campaign was saved but not sent. Add SMS provider credentials to actually deliver messages.",
                            "campaign_id": campaign_id,
                        }
                    ),
                    400,
                )

            result = send_sms_via_provider(contacts, message, sender)
            db.update_sms_campaign_result(
                campaign_id,
                "sent" if result["sent"] > 0 else "failed",
                result["sent"],
                result["failed"],
                result,
            )
            return jsonify(
                {
                    "success": result["sent"] > 0,
                    "sent": result["sent"],
                    "failed": result["failed"],
                    "campaign_id": campaign_id,
                }
            )

        @self.app.route("/api/business/sms/campaigns", methods=["GET"])
        @login_required
        def get_sms_campaigns():
            campaigns = db.get_sms_campaigns(g.current_user_id, limit=50)
            return jsonify({"success": True, "campaigns": campaigns})

        @self.app.route("/api/notifications/send", methods=["POST"])
        @login_required
        def send_notification_route():
            data = request.json
            user_id = data.get("user_id")
            title = data.get("title", "Notification")
            message = data.get("message", "")
            notification_type = data.get("type", "info")

            if not user_id or not message:
                return (
                    jsonify({"success": False, "error": "Missing required fields"}),
                    400,
                )

            result = db.create_notification(user_id, title, message, notification_type)

            user = db.get_user(user_id)
            if user and user.get("email"):
                send_email_notification(user["email"], title, message)

            return jsonify({"success": result})

        @self.app.route("/api/notifications/read/<notification_id>", methods=["POST"])
        @login_required
        def mark_notification_read(notification_id):
            result = db.mark_notification_read(notification_id)
            return jsonify({"success": result})

        @self.app.route("/api/utilities/transactions", methods=["GET"])
        @admin_required
        @safe_api_response
        def get_utility_transactions():
            try:
                transactions = self.platform.get_utility_transactions(
                    reference_id=request.args.get("referenceId"),
                    status=request.args.get("status"),
                    service_type=request.args.get("serviceType"),
                    biller_type=request.args.get("billerType"),
                    biller_country_code=request.args.get("billerCountryCode"),
                    start_date=request.args.get("startDate"),
                    end_date=request.args.get("endDate"),
                    page=request.args.get("page", 1, type=int),
                    size=request.args.get("size", 10, type=int),
                )
                if transactions:
                    return jsonify(transactions)
            except Exception as e:
                logger.error(f"Error fetching utility transactions: {e}")

            return jsonify([])

        @self.app.route("/api/utilities/transactions/<transaction_id>", methods=["GET"])
        @admin_required
        @safe_api_response
        def get_utility_transaction(transaction_id):
            try:
                return jsonify(
                    self.platform.get_utility_transaction_by_id(transaction_id)
                )
            except Exception as e:
                logger.error(
                    f"Error fetching utility transaction {transaction_id}: {e}"
                )
                return jsonify({"error": str(e)}), 404
                
        

        # ============ WALLET UTILITY PAYMENT - FIXED: Use local currency, NOT USD ============
        @self.app.route("/api/wallet/utility", methods=["POST"])
        @login_required
        @email_verified_required
        @safe_api_response
        def wallet_utility_payment():
            data = request.json or {}
            user_id = g.current_user_id
            biller_id = data.get("biller_id")
            subscriber_account = data.get("subscriber_account")
            amount = data.get("amount")
            currency = data.get("currency", "NGN").upper()

            if not biller_id or not subscriber_account:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Biller and account number are required",
                        }
                    ),
                    400,
                )

            try:
                amount = float(amount)
            except (TypeError, ValueError):
                return jsonify({"success": False, "error": "Invalid amount"}), 400

            if amount <= 0:
                return jsonify({"success": False, "error": "Invalid amount"}), 400

            # Validate amount against biller limits
            try:
                biller_id_int = int(biller_id)
                validation = UtilityBillerValidator.validate_amount(
                    biller_id_int, amount
                )
                if not validation["valid"]:
                    logger.warning(
                        f"Utility amount validation: {validation['message']}"
                    )
                    amount = validation["adjusted"]
            except (ValueError, TypeError):
                return (
                    jsonify(
                        {"success": False, "error": f"Invalid biller_id: {biller_id}"}
                    ),
                    400,
                )

            reference = (
                data.get("reference") or f"WALLET-UTILITY-{secrets.token_hex(12)}"
            )

            wallet = db.get_wallet(user_id, currency)
            if not wallet or float(wallet.get("balance", 0)) < amount:
                return (
                    jsonify({"success": False, "error": "Insufficient wallet balance"}),
                    400,
                )

            debit = db.debit_wallet(
                user_id=user_id,
                amount=amount,
                description=f"Utility bill payment {subscriber_account}",
                reference=reference,
                metadata={
                    "biller_id": biller_id,
                    "subscriber_account": subscriber_account,
                    "type": "utility",
                },
                currency=currency,
            )

            if not debit.get("success"):
                return jsonify(debit), 400

            try:
                local_amount = amount
                if self.credentials.environment.value == "sandbox":
                    biller_limits = UtilityBillerValidator.get_biller_limits(
                        biller_id_int
                    )
                    local_amount = max(
                        biller_limits.get("min", 50),
                        min(local_amount, biller_limits.get("max", 5000)),
                    )
                    logger.info(
                        f"Sandbox: using amount {currency} {local_amount:.2f} for utility biller {biller_id}"
                    )

                import uuid

                unique_ref = f"wallet-util-{reference}"[:36]
                if len(unique_ref) < 10:
                    unique_ref = f"wallet-util-{reference}-{uuid.uuid4().hex[:8]}"[:36]

                logger.info(
                    f"Executing wallet utility payment: biller={biller_id}, account={subscriber_account}, amount={local_amount} {currency}, use_local_amount=True"
                )

                result = self.platform.pay_utility_bill(
                    biller_id=int(biller_id),
                    subscriber_account=subscriber_account,
                    amount=local_amount,
                    reference_id=unique_ref,
                    use_local_amount=True,
                )

                transaction_id = result.get("transactionId") or result.get("id")
                status = str(result.get("status", "")).upper()

                if not transaction_id and status not in ("SUCCESS", "COMPLETED"):
                    raise Exception(result.get("message", "Utility payment failed"))

                # ============ LOG SUCCESSFUL WALLET UTILITY TRANSACTION ============
                db.create_reloadly_transaction(
                    reference=reference,
                    user_id=user_id,
                    transaction_type="utility",
                    amount=amount,
                    status="completed",
                    provider_transaction_id=transaction_id,
                    result=result,
                    currency=currency,
                )

                # Create transaction record
                db.create_pending(
                    reference=reference,
                    tx_type="utility",
                    provider="wallet",
                    amount=amount,
                    currency=currency,
                    payload={
                        "biller_id": biller_id,
                        "subscriber_account": subscriber_account,
                        "payment_method": "wallet",
                        "transaction_id": transaction_id,
                    },
                    user_id=user_id,
                )
                db.mark_fulfilled(reference, {"wallet_payment": True, "result": result})

                log_event(
                    user_id=user_id,
                    event_type="utility",
                    details={
                        "amount": amount,
                        "currency": currency,
                        "biller_id": biller_id,
                        "account": subscriber_account,
                        "reference": reference,
                        "payment_method": "wallet",
                        "transaction_id": transaction_id,
                    },
                    status="success",
                )

                db.create_notification(
                    user_id,
                    "Utility Payment Successful ✅",
                    f"{currency} {amount:,.2f} paid for {subscriber_account} via wallet",
                    "success",
                )

                user = db.get_user(user_id)
                if user and user.get("email"):
                    send_email_notification(
                        user["email"],
                        "✅ Utility Payment Successful",
                        f"Your utility payment was completed successfully via wallet.\n\nAccount: {subscriber_account}\nAmount: {currency} {amount:,.2f}\nReference: {reference}",
                        include_promo=True,
                        promo_context={
                            "user_id": user_id,
                            "reference": reference,
                            "tx_type": "utility",
                            "amount": amount,
                        },
                    )

                wallet_after = db.get_wallet(user_id, currency)

                return jsonify(
                    {
                        "success": True,
                        "transactionId": transaction_id,
                        "reference": reference,
                        "status": "completed",
                        "payment_method": "wallet",
                        "wallet_balance": (
                            wallet_after.get("balance", 0) if wallet_after else 0
                        ),
                        "currency": currency,
                    }
                )

            except Exception as e:
                logger.exception("Utility payment failed after wallet debit")

                refund = db.credit_wallet(
                    user_id=user_id,
                    amount=amount,
                    description=f"Refund for failed utility payment {reference}",
                    reference=f"REFUND-{reference}",
                    metadata={"original_reference": reference, "reason": str(e)},
                    currency=currency,
                )

                log_event(
                    user_id=user_id,
                    event_type="utility",
                    details={
                        "amount": amount,
                        "currency": currency,
                        "biller_id": biller_id,
                        "account": subscriber_account,
                        "reference": reference,
                        "error": str(e),
                    },
                    status="failed",
                )

                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Utility payment failed. Wallet refunded.",
                            "refunded": refund.get("success", False),
                            "reference": reference,
                        }
                    ),
                    400,
                )

    def run(self, debug: bool = False, port: int = 5557):
        logger.info(f"Starting web server on port {port} (debug={debug})")
        self.app.run(debug=debug, port=port, host=os.getenv("FLASK_HOST", "127.0.0.1"))

# ============================================================
# WSGI ENTRY POINT FOR GUNICORN / RAILWAY
# ============================================================
# Gunicorn is started with `gunicorn main:app`, which means it imports
# this module and looks for a variable named `app`. Our Flask instance
# actually lives at ReloadlyWebApp(...).app, so we need to:
#
#   1. Build the ReloadlyWebApp instance at import time
#   2. Expose its .app attribute under the module-level name `app`
#
# This block runs whether the module is imported by gunicorn or executed
# directly via `python main.py`. `main()` below just reuses the already-
# built instance instead of creating a second one (which would double
# DB init, background threads, etc.).
# ============================================================
_credentials = ReloadlyCredentials.from_env()

if not _credentials.client_id or not _credentials.client_secret:
    raise RuntimeError(
        "RELOADLY_CLIENT_ID and RELOADLY_CLIENT_SECRET must be set in the environment. "
        "On Railway, add them under the service's Variables tab."
    )

web_app = ReloadlyWebApp(_credentials)


def _log_storage_paths():
    """Show exactly which files hold your data. A database inside the app folder is wiped on every
    Railway redeploy unless that folder is a mounted volume."""
    try:
        main_db = os.path.abspath(getattr(db, "DATABASE", "") or "")
        logger.info(f"STORAGE: main database file = {main_db}")
        logger.info(f"STORAGE: Smart Media database = {os.path.abspath(os.getenv('NET365_DB_PATH', 'net365.db'))}")
        on_railway = bool(os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("RAILWAY_PROJECT_ID"))
        app_dir = os.path.dirname(os.path.abspath(__file__))
        if on_railway and main_db.startswith(app_dir) and not os.getenv("DATABASE_URL"):
            logger.warning(
                "LAUNCH CHECK: the main database is inside the app folder and DATABASE_URL is not set — "
                "it will be lost on redeploy unless that folder is a mounted volume. "
                "Set DATABASE_URL=/your/volume/path/reloadly.db."
            )
        # The path must exist, be writable, and (on Railway) sit on a mounted volume,
        # otherwise it is the container's throwaway disk even when DATABASE_URL is set.
        db_dir = os.path.dirname(main_db) or "."
        if not os.path.isdir(db_dir):
            logger.warning(f"LAUNCH CHECK: database folder {db_dir} does not exist — create/mount it.")
        elif not os.access(db_dir, os.W_OK):
            logger.warning(f"LAUNCH CHECK: database folder {db_dir} is not writable.")
        elif on_railway:
            p, mounted = db_dir, False
            while True:
                if os.path.ismount(p) and p not in ("/", ""):
                    mounted = True
                    break
                parent = os.path.dirname(p)
                if parent == p:
                    break
                p = parent
            if not mounted:
                logger.warning(
                    f"LAUNCH CHECK: {db_dir} is not on a mounted volume — data will be lost on "
                    "redeploy. Attach a Railway volume and point DATABASE_URL into it."
                )
    except Exception as e:
        logger.warning(f"could not report storage paths: {e}")


def _launch_readiness_warnings():
    """Log loud warnings at startup for settings that must be right before real customers use the app."""
    checks = [
        (os.getenv("ENCRYPTION_KEY"), "ENCRYPTION_KEY is not set: personal data is stored in plaintext."),
        (bool(os.getenv("STRIPE_WEBHOOK_SECRET")) if os.getenv("STRIPE_SECRET_KEY") else True,
         "STRIPE_WEBHOOK_SECRET is not set: Stripe webhooks are rejected (503) until it is."),
        (bool(os.getenv("STRIPE_SECRET_KEY")) or not os.getenv("STRIPE_PUBLISHABLE_KEY"),
         "STRIPE_PUBLISHABLE_KEY is set but STRIPE_SECRET_KEY is missing."),
        (ADMIN_SECRET and len(ADMIN_SECRET) >= 24, "ADMIN_SECRET is missing or shorter than 24 characters."),
        (SESSION_COOKIE_SECURE, "SESSION_COOKIE_SECURE is off: session cookies can travel over plain HTTP."),
        (EMAIL_VERIFICATION_REQUIRED, "EMAIL_VERIFICATION_REQUIRED is off: unverified emails can move money."),
        (os.getenv("RELOADLY_ENVIRONMENT", "sandbox").lower() != "sandbox",
         "RELOADLY_ENVIRONMENT is sandbox: no real airtime will be delivered."),
        (os.getenv("RESEND_API_KEY") or os.getenv("MAILGUN_API_KEY") or os.getenv("SMTP_PASSWORD"), "No email provider configured."),
    ]
    for ok, msg in checks:
        if not ok:
            logger.warning(f"LAUNCH CHECK: {msg}")
    logger.info(f"LAUNCH CHECK: wallet={'ON' if WALLET_ENABLED else 'OFF'}, "
                f"transfers={'ON' if WALLET_TRANSFERS_ENABLED else 'OFF'}, "
                f"limits per-tx={LIMIT_PER_TX_NGN:,.0f} daily={LIMIT_DAILY_NGN:,.0f} NGN")


_log_storage_paths()
_launch_readiness_warnings()
app = web_app.app  # <-- this is what `gunicorn main:app` binds to
# ============================================================

# ============================================================
# LATE ROUTE REGISTRATION — Company Intelligence
# ------------------------------------------------------------
# Module-level: registered after `app = web_app.app` so the
# decorators are guaranteed to run at import time, before Flask
# starts serving. Inside setup_routes() the decorator @app.route
# would raise NameError (only self.app is in scope there), which
# was silently swallowing these registrations.
# ============================================================
from flask import request as _flask_request, jsonify as _flask_jsonify


@app.route("/api/admin/companies", methods=["GET"])
@admin_required
def _admin_get_companies():
    """Aggregate visitors by organization — who's actually visiting."""
    try:
        _limit = min(_flask_request.args.get("limit", 50, type=int), 200)
        _days = min(_flask_request.args.get("days", 30, type=int), 365)
        _conn = db.get_db_connection()
        _c = _conn.cursor()
        _rows = _c.execute("""
            SELECT
                COALESCE(v.org_name, '(unresolved)') AS org_name,
                v.asn,
                v.ip_kind,
                COUNT(*)                              AS visit_count,
                COUNT(DISTINCT v.ip_address)          AS unique_ips,
                COUNT(DISTINCT v.visitor_name)        AS unique_users,
                MIN(v.visited_at)                     AS first_seen,
                MAX(v.visited_at)                     AS last_seen,
                GROUP_CONCAT(DISTINCT v.country)      AS countries
            FROM visitor_logs v
            WHERE v.visited_at >= datetime('now', ?)
            GROUP BY COALESCE(v.org_name, '(unresolved)'), v.asn, v.ip_kind
            ORDER BY visit_count DESC
            LIMIT ?
        """, (f"-{_days} days", _limit)).fetchall()
        _conn.close()
        return _flask_jsonify({
            "success": True,
            "companies": [dict(r) for r in _rows],
            "window_days": _days,
        })
    except Exception as _e:
        logger.error(f"Company intel query failed: {_e}")
        return _flask_jsonify({"success": False, "error": str(_e)}), 500


@app.route("/api/admin/companies/<path:ip>/resolve", methods=["POST"])
@admin_required
def _admin_resolve_ip(ip):
    """Force a fresh lookup for one IP."""
    _info = IPIntel.lookup(ip, force=True)
    if not _info:
        return _flask_jsonify({"success": False, "error": "Could not resolve this IP"}), 404
    return _flask_jsonify({"success": True, "intel": _info})


@app.route("/api/admin/bots/summary", methods=["GET"])
@admin_required
def _admin_bot_summary():
    """Bot vs human traffic summary."""
    try:
        _conn = db.get_db_connection()
        _c = _conn.cursor()
        _totals = _c.execute("""
            SELECT
                SUM(CASE WHEN is_bot = 1 THEN 1 ELSE 0 END) AS bot_visits,
                SUM(CASE WHEN is_bot = 0 OR is_bot IS NULL THEN 1 ELSE 0 END) AS human_visits,
                COUNT(*) AS total_visits
            FROM visitor_logs
            WHERE visited_at >= datetime('now', '-30 days')
        """).fetchone()
        _bots = _c.execute("""
            SELECT COALESCE(bot_name, 'Unknown bot') AS bot_name, COUNT(*) AS count
            FROM visitor_logs
            WHERE is_bot = 1 AND visited_at >= datetime('now', '-30 days')
            GROUP BY bot_name
            ORDER BY count DESC
            LIMIT 25
        """).fetchall()
        _conn.close()
        return _flask_jsonify({
            "success": True,
            "totals": dict(_totals) if _totals else {},
            "by_bot": [dict(b) for b in _bots],
        })
    except Exception as _e:
        return _flask_jsonify({"success": False, "error": str(_e)}), 500

@app.route("/api/admin/visitors/geo-status", methods=["GET"])
@admin_required
def _admin_geo_status():
    """How many visitor IPs still lack a country or city, and how the resolver is doing."""
    try:
        return _flask_jsonify({
            "success": True,
            "missing_ips": GeoResolver.missing_count(),
            "resolver": GeoResolver.status(),
            "org_resolver": IPIntel.status(),
        })
    except Exception as _e:
        return _flask_jsonify({"success": False, "error": str(_e)}), 500


@app.route("/api/admin/visitors/backfill-geo", methods=["POST"])
@admin_required
def _admin_backfill_geo():
    """Queue the most recent visitor IPs with no country/city for a background lookup."""
    try:
        if GeoResolver.provider() == "off":
            return _flask_jsonify({"success": False,
                                   "error": "Geo lookups are disabled (GEO_PROVIDER=off)"}), 400
        limit = _flask_request.args.get("limit", 300, type=int)
        queued = GeoResolver.backfill(limit)
        return _flask_jsonify({"success": True, "queued": queued,
                               "missing_ips": GeoResolver.missing_count(),
                               "resolver": GeoResolver.status()})
    except Exception as _e:
        logger.error(f"Geo backfill failed: {_e}")
        return _flask_jsonify({"success": False, "error": str(_e)}), 500


def main():
    print("\n" + "=" * 60)
    print("NET365 / RELOADLY PLATFORM v2.2")
    print("=" * 60)

    credentials = _credentials  # reuse, don't re-create

    print(f"\nENVIRONMENT: {credentials.environment.value.upper()} MODE")
    print(
        f"   Client ID: {credentials.client_id[:10] if credentials.client_id else 'NOT SET'}..."
    )
    print(f"   Base URL: {credentials.base_url}")
    print(f"   Auth URL: {credentials.auth_url}")

    # ============================================================
    # Diagnostic: referral bonus flag state.
    # If REFERRAL_BONUS_ENABLED reports True when you expected it
    # to be off, this print will show you exactly what the app sees
    # at runtime — both the resolved flag and the raw env value.
    # ============================================================
    print("\n=== REFERRAL BONUS FLAG ===")
    print(f"  REFERRAL_BONUS_ENABLED  = {REFERRAL_BONUS_ENABLED}")
    print(f"  raw env value           = {os.getenv('REFERRAL_BONUS_ENABLED')!r}")
    print("=== END FLAG ===\n")

    # ============================================================
    # Diagnostic: print every route Flask actually registered.
    # If a route is missing here, the frontend will get a 404 no
    # matter what the JS looks like — so this is the first thing
    # to check whenever "endpoint not found" appears in the console.
    # ============================================================
    print("\n=== REGISTERED ROUTES ===")
    for rule in sorted(web_app.app.url_map.iter_rules(), key=lambda r: str(r)):
        methods = sorted(rule.methods - {"HEAD", "OPTIONS"})
        print(f"  {methods}  {rule}")
    print("=== END ROUTES ===\n")

    # Focused check for the routes we care about most right now.
    print("=== CONTACT & BULK ROUTES ===")
    wanted = ("/api/user/contacts", "/api/bulk")
    for rule in sorted(web_app.app.url_map.iter_rules(), key=lambda r: str(r)):
        if any(w in str(rule) for w in wanted):
            methods = sorted(rule.methods - {"HEAD", "OPTIONS"})
            print(f"  {methods}  {rule}")
    print("=== END ===\n")

    # Reuse the web_app already built at module load.
    web_app.run(debug=False, port=int(os.getenv("PORT", 5557)))


if __name__ == "__main__":
    main()
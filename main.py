# ============ FIX WINDOWS CONSOLE ENCODING ============
# ============ FIX WINDOWS CONSOLE ENCODING ============
# ============ FIX UNICODE/ENCODING ISSUES ============
import sys
import io
import os
import uuid

# Force UTF-8 for all I/O
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    os.environ["PYTHONIOENCODING"] = "utf-8"

# Also set for logging
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("net365.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
# ======================================================'
# ======================================================

# ============ LOAD ENVIRONMENT VARIABLES ============
try:
    from dotenv import load_dotenv

    load_dotenv()
    print("Loaded .env file using python-dotenv")
except ImportError:
    print("python-dotenv not installed, using system environment variables")

import os

# Diagnostic: shows exactly what SMTP_HOST resolved to, wrapped in brackets so
# hidden issues (stray quotes, trailing spaces, wrong variable name entirely)
# are visible instead of silently causing a DNS lookup failure later.
_smtp_host_check = os.getenv("SMTP_HOST")
if _smtp_host_check:
    print(f"SMTP_HOST loaded as: [{_smtp_host_check}]")
else:
    print("SMTP_HOST not set — email sending will use the default (smtp.gmail.com)")
print(f"SMTP_PORT loaded as: [{os.getenv('SMTP_PORT', '587 (default)')}]")
_smtp_user_check = os.getenv("SMTP_USER")
_smtp_pass_check = os.getenv("SMTP_PASSWORD")
print(f"SMTP_USER loaded: [{'SET as ' + _smtp_user_check if _smtp_user_check else 'NOT SET'}]")
print(f"SMTP_PASSWORD loaded: [{'SET' if _smtp_pass_check else 'NOT SET'}]")
if not _smtp_user_check or not _smtp_pass_check:
    print("⚠️ WARNING: SMTP_USER/SMTP_PASSWORD missing — send_email_notification() will "
          "silently return False for every email until these are set on Railway.")
from flask import send_from_directory, render_template_string

print("=" * 60)
print("ENVIRONMENT VARIABLES CHECK")
print("=" * 60)
print(
    f"RELOADLY_CLIENT_ID: {os.getenv('RELOADLY_CLIENT_ID', 'NOT SET')[:15] if os.getenv('RELOADLY_CLIENT_ID') else 'NOT SET'}..."
)
print(
    f"RELOADLY_CLIENT_SECRET: {'SET' if os.getenv('RELOADLY_CLIENT_SECRET') else 'NOT SET'}"
)
print(f"RELOADLY_ENVIRONMENT: {os.getenv('RELOADLY_ENVIRONMENT', 'NOT SET')}")
print(f"PAYMENT_SERVICE_URL: {os.getenv('PAYMENT_SERVICE_URL', 'NOT SET')}")
print(f"PUBLIC_URL: {os.getenv('PUBLIC_URL', 'NOT SET')}")
print(f"FRONTEND_URL: {os.getenv('FRONTEND_URL', 'NOT SET')}")
print(f"EXCHANGE_RATE_INTERVAL: {os.getenv('EXCHANGE_RATE_INTERVAL', '300')} seconds")
print("=" * 60 + "\n")
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
from urllib.parse import urlsplit, urlunsplit
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

import database as db
from webhook_security import verify_paystack_signature, verify_flutterwave_signature

# ============ CHECK ENCRYPTION KEY IN PRODUCTION ============
if os.getenv("ENVIRONMENT", "").lower() == "production":
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
class ExchangeRateService:
    """Dynamic exchange rate service with automatic refresh"""

    FALLBACK_RATES = {
        # ── units per 1 USD ───────────────────────────────────────────
        "USD": 1.0,
        "NGN": 1350.0,
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
SUPPORTED_CURRENCIES = {
    # ── Local / primary ──────────────────────────────────────────────
    "NGN": {"name": "Nigerian Naira",   "symbol": "₦",   "gateway": "paystack",    "min_amount": 100,  "step": 100, "is_local": True,  "country": "NG", "decimals": 2},
    "USD": {"name": "US Dollar",        "symbol": "$",   "gateway": "stripe",      "min_amount": 1,    "step": 1,   "is_local": False, "country": "US", "decimals": 2},
    "GBP": {"name": "Pound Sterling",   "symbol": "£",   "gateway": "stripe",      "min_amount": 1,    "step": 1,   "is_local": False, "country": "GB", "decimals": 2},
    "EUR": {"name": "Euro",             "symbol": "€",   "gateway": "stripe",      "min_amount": 1,    "step": 1,   "is_local": False, "country": "EU", "decimals": 2},

    # ── Americas ─────────────────────────────────────────────────────
    "CAD": {"name": "Canadian Dollar",  "symbol": "CA$", "gateway": "stripe",      "min_amount": 1,    "step": 1,   "is_local": False, "country": "CA", "decimals": 2},
    "BRL": {"name": "Brazilian Real",   "symbol": "R$",  "gateway": "stripe",      "min_amount": 5,    "step": 1,   "is_local": False, "country": "BR", "decimals": 2},
    "MXN": {"name": "Mexican Peso",     "symbol": "MX$", "gateway": "stripe",      "min_amount": 20,   "step": 10,  "is_local": False, "country": "MX", "decimals": 2},
    "ARS": {"name": "Argentine Peso",   "symbol": "AR$", "gateway": "stripe",      "min_amount": 100,  "step": 50,  "is_local": False, "country": "AR", "decimals": 2},
    "CLP": {"name": "Chilean Peso",     "symbol": "CL$", "gateway": "stripe",      "min_amount": 500,  "step": 100, "is_local": False, "country": "CL", "decimals": 0},
    "COP": {"name": "Colombian Peso",   "symbol": "CO$", "gateway": "stripe",      "min_amount": 3000, "step": 1000,"is_local": False, "country": "CO", "decimals": 2},
    "PEN": {"name": "Peruvian Sol",     "symbol": "S/",  "gateway": "stripe",      "min_amount": 5,    "step": 1,   "is_local": False, "country": "PE", "decimals": 2},

    # ── Asia-Pacific ─────────────────────────────────────────────────
    "AUD": {"name": "Australian Dollar","symbol": "A$",  "gateway": "stripe",      "min_amount": 1,    "step": 1,   "is_local": False, "country": "AU", "decimals": 2},
    "NZD": {"name": "New Zealand Dollar","symbol": "NZ$","gateway": "stripe",      "min_amount": 1,    "step": 1,   "is_local": False, "country": "NZ", "decimals": 2},
    "JPY": {"name": "Japanese Yen",     "symbol": "¥",   "gateway": "stripe",      "min_amount": 100,  "step": 50,  "is_local": False, "country": "JP", "decimals": 0},
    "CNY": {"name": "Chinese Yuan",     "symbol": "CN¥", "gateway": "stripe",      "min_amount": 10,   "step": 5,   "is_local": False, "country": "CN", "decimals": 2},
    "HKD": {"name": "Hong Kong Dollar", "symbol": "HK$", "gateway": "stripe",      "min_amount": 10,   "step": 5,   "is_local": False, "country": "HK", "decimals": 2},
    "SGD": {"name": "Singapore Dollar", "symbol": "S$",  "gateway": "stripe",      "min_amount": 2,    "step": 1,   "is_local": False, "country": "SG", "decimals": 2},
    "MYR": {"name": "Malaysian Ringgit","symbol": "RM",  "gateway": "stripe",      "min_amount": 5,    "step": 1,   "is_local": False, "country": "MY", "decimals": 2},
    "THB": {"name": "Thai Baht",        "symbol": "฿",   "gateway": "stripe",      "min_amount": 30,   "step": 10,  "is_local": False, "country": "TH", "decimals": 2},
    "VND": {"name": "Vietnamese Dong",  "symbol": "₫",   "gateway": "stripe",      "min_amount": 20000,"step": 5000,"is_local": False, "country": "VN", "decimals": 0},
    "PHP": {"name": "Philippine Peso",  "symbol": "₱",   "gateway": "stripe",      "min_amount": 50,   "step": 10,  "is_local": False, "country": "PH", "decimals": 2},
    "IDR": {"name": "Indonesian Rupiah","symbol": "Rp",  "gateway": "stripe",      "min_amount": 15000,"step": 5000,"is_local": False, "country": "ID", "decimals": 0},
    "INR": {"name": "Indian Rupee",     "symbol": "₹",   "gateway": "stripe",      "min_amount": 50,   "step": 10,  "is_local": False, "country": "IN", "decimals": 2},
    "PKR": {"name": "Pakistani Rupee",  "symbol": "₨",   "gateway": "stripe",      "min_amount": 200,  "step": 50,  "is_local": False, "country": "PK", "decimals": 2},
    "BDT": {"name": "Bangladeshi Taka", "symbol": "৳",   "gateway": "stripe",      "min_amount": 100,  "step": 50,  "is_local": False, "country": "BD", "decimals": 2},

    # ── Middle East / North Africa ───────────────────────────────────
    "AED": {"name": "UAE Dirham",       "symbol": "د.إ", "gateway": "stripe",      "min_amount": 5,    "step": 1,   "is_local": False, "country": "AE", "decimals": 2},
    "SAR": {"name": "Saudi Riyal",      "symbol": "﷼",   "gateway": "stripe",      "min_amount": 5,    "step": 1,   "is_local": False, "country": "SA", "decimals": 2},
    "EGP": {"name": "Egyptian Pound",   "symbol": "E£",  "gateway": "stripe",      "min_amount": 30,   "step": 10,  "is_local": False, "country": "EG", "decimals": 2},
    "TRY": {"name": "Turkish Lira",     "symbol": "₺",   "gateway": "stripe",      "min_amount": 20,   "step": 10,  "is_local": False, "country": "TR", "decimals": 2},

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

GATEWAY_CURRENCIES = {
    "paystack": ["NGN"],
    "stripe": ["USD", "EUR", "GBP", "CAD", "AUD"],
    "flutterwave": ["NGN", "USD", "EUR", "GBP"],
    "wallet": ["NGN", "USD", "GBP", "EUR", "CAD", "AUD"],
}

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

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
cipher = None
if CRYPTOGRAPHY_AVAILABLE and ENCRYPTION_KEY:
    try:
        cipher = Fernet(ENCRYPTION_KEY.encode())
        print("Encryption initialized successfully")
    except Exception as e:
        print(f"WARNING: Failed to initialize encryption: {e}")


def encrypt_pii(data: str) -> str:
    if not data or not cipher:
        return data
    try:
        return cipher.encrypt(data.encode()).decode()
    except Exception:
        return data


def decrypt_pii(data: str) -> str:
    if not data or not cipher:
        return data
    try:
        return cipher.decrypt(data.encode()).decode()
    except Exception:
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
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
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
REFERRAL_BONUS_ENABLED = (
    os.getenv("REFERRAL_BONUS_ENABLED", "false").lower() == "true"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("net365.log"), logging.StreamHandler()],
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
        self, email: str, amount: float, reference: str = None, return_url: str = None
    ) -> Tuple[Optional[str], Optional[str]]:
        if not self.api_key:
            return None, None
        reference = reference or generate_reference("PSK")
        amount_kobo = int(amount * 100)
        return_url = return_url or os.getenv("PAYSTACK_RETURN_URL", DEFAULT_RETURN_URL)
        callback_url = f"{PAYMENT_SERVICE_URL}/payment/callback?return_url={return_url}&reference={reference}"
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
                    return data["data"]["authorization_url"], reference
            return None, None
        except Exception as e:
            logger.error(f"Paystack init error: {str(e)}")
            return None, None

    def init_flutterwave_payment(
        self,
        email: str,
        amount: float,
        currency: str = "NGN",
        reference: str = None,
        return_url: str = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        flutterwave_secret_key = os.getenv("FLUTTERWAVE_SECRET_KEY")
        if not flutterwave_secret_key:
            return None, None
        reference = reference or generate_reference("FLW")
        return_url = return_url or os.getenv(
            "FLUTTERWAVE_RETURN_URL", DEFAULT_RETURN_URL
        )
        callback_url = f"{PAYMENT_SERVICE_URL}/payment/callback?return_url={return_url}&reference={reference}"
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
                    return data["data"]["link"], reference
            return None, None
        except Exception as e:
            logger.error(f"Flutterwave init error: {str(e)}")
            return None, None

    def init_stripe_payment(
        self,
        email: str,
        amount: float,
        currency: str = "USD",
        reference: str = None,
        return_url: str = None,
        description: str = "Airtime Top-up",
    ) -> Tuple[Optional[str], Optional[str]]:
        if not STRIPE_AVAILABLE or not self.api_key:
            return None, None

        reference = reference or generate_reference("STR")
        return_url = return_url or os.getenv("STRIPE_RETURN_URL", DEFAULT_RETURN_URL)

        try:
                        # Stripe expects amounts in the smallest currency unit — but some
            # currencies are zero-decimal (JPY, VND, IDR, CLP, UGX, TZS, KRW,
            # ISK, HUF is 2-decimal, etc.). For those, send the raw amount.
            ZERO_DECIMAL = {
                "bif", "clp", "djf", "gnf", "jpy", "kmf", "krw", "mga",
                "pyg", "rwf", "ugx", "vnd", "vuv", "xaf", "xof", "xpf",
            }
            if currency.lower() in ZERO_DECIMAL:
                amount_cents = int(amount)
            else:
                amount_cents = int(amount * 100)

            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
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
            return session.url, reference
        except Exception as e:
            logger.error(f"Stripe init error: {str(e)}")
            return None, None

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
                f"{self.flutterwave_base_url}/transactions/{reference}/verify",
                headers=headers,
                timeout=30,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    payment_data = data.get("data", {})
                    return {
                        "success": True,
                        "status": payment_data.get("status"),
                        "amount": float(payment_data.get("amount", 0)),
                        "currency": payment_data.get("currency", "NGN"),
                        "reference": payment_data.get("tx_ref"),
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
                    payment_data = data.get("data", {})
                    return {
                        "success": True,
                        "status": payment_data.get("status"),
                        "amount": float(payment_data.get("amount", 0)) / 100,
                        "currency": payment_data.get("currency", "NGN"),
                        "reference": payment_data.get("reference"),
                        "customer": payment_data.get("customer", {}),
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

            if session.payment_status == "paid":
                return {
                    "success": True,
                    "status": "success",
                    "reference": session_id,
                    "amount": float(session.amount_total) / 100,
                    "currency": session.currency.upper(),
                    "customer": session.customer_details,
                    "metadata": session.metadata,
                }
            else:
                return {
                    "success": False,
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
            auth_url, reference = self.init_paystack_payment(
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
            return {"success": False, "error": "Failed to initialize Paystack payment"}

        elif provider == "flutterwave":
            auth_url, reference = self.init_flutterwave_payment(
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
                "error": "Failed to initialize Flutterwave payment",
            }

        elif provider == "stripe":
            if not STRIPE_AVAILABLE:
                return {"success": False, "error": "Stripe library not installed"}
            auth_url, reference = self.init_stripe_payment(
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
                    "provider": "stripe",
                    "currency": currency,
                    "amount": amount,
                }
            return {"success": False, "error": "Failed to initialize Stripe payment"}

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
            {"currency": "NGN", "provider": "paystack", "alternatives": ["stripe"]},
        ),
    }


def sanitize_user(user):
    if not user:
        return None
    clean = dict(user)
    for key in ("password_hash", "password", "session_token", "token"):
        clean.pop(key, None)
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


        # contact Imports

        # ============ CONTACT IMPORT ROUTE ============
        # ============ CONTACT IMPORT ROUTE - FIXED ============
        # ============ CONTACT IMPORT ROUTE ============
        # ============ CONTACT IMPORT ROUTE - FIXED ============
# This should be at the SAME indentation level as other @self.app.route decorators
# inside setup_routes()


                
                
                
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
        def debug_session():
            """Debug endpoint — shows what the server sees about the current session."""
            token = _get_request_token()
            result = {
                "cookie_name": SESSION_COOKIE_NAME,
                "cookie_received": bool(token),
                "cookie_prefix": token[:10] if token else None,
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
        if not EMAIL_VERIFICATION_REQUIRED:
            return func(*args, **kwargs)
        user_id = getattr(g, "current_user_id", None)
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


def get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


# Page routes to log as visits. Deliberately NOT logging /api/* — this app polls its own
# APIs every few seconds per page load, so logging every API call would flood the table
# with noise rather than meaningful visit data.
VISITOR_TRACKED_PATHS = {"/", "/scheduler", "/analytics", "/business", "/utilities"}


def log_page_visit():
    try:
        if request.path not in VISITOR_TRACKED_PATHS:
            return
        ua_info = parse_user_agent(request.headers.get("User-Agent", ""))
        user_id = None
        visitor_name = None
        try:
            user = get_authenticated_user()
            if user:
                user_id = user.get("id")
                visitor_name = user.get("full_name") or user.get("email")
        except Exception:
            pass
        db.log_visitor(
            user_id=user_id,
            visitor_name=visitor_name,
            ip_address=get_client_ip(),
            user_agent=request.headers.get("User-Agent", ""),
            device_type=ua_info["device_type"],
            os_name=ua_info["os"],
            browser=ua_info["browser"],
            path=request.path,
            referrer=request.headers.get("Referer", ""),
            session_id=request.cookies.get(SESSION_COOKIE_NAME, ""),
        )
    except Exception as e:
        logger.warning(f"Visitor logging failed (non-fatal): {e}")


def admin_required(func):
    """Gates admin-only endpoints behind ADMIN_SECRET. Denies access by default if
    ADMIN_SECRET isn't set — an unset secret should never mean 'open to everyone'."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        provided = request.headers.get("X-Admin-Secret", "") or request.args.get(
            "admin_secret", ""
        )
        if not ADMIN_SECRET or not secrets.compare_digest(provided, ADMIN_SECRET):
            return jsonify({"success": False, "error": "Unauthorized"}), 401
        return func(*args, **kwargs)

    return wrapper


def rate_limit(max_requests=10, window_seconds=60):
    requests_cache = {}

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = f"{request.remote_addr}-{func.__name__}"
            now = time.time()
            requests_cache[key] = [
                t for t in requests_cache.get(key, []) if now - t < window_seconds
            ]
            if len(requests_cache.get(key, [])) >= max_requests:
                return jsonify({"error": "Rate limit exceeded"}), 429
            requests_cache.setdefault(key, []).append(now)
            return func(*args, **kwargs)

        return wrapper

    return decorator


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


def send_welcome_email(to_email: str, first_name: str = "") -> bool:
    """Send the Net365 welcome email from the CEO. Non-fatal on failure."""
    smtp_host = os.getenv("SMTP_HOST", "smtp.mailgun.org")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("WELCOME_FROM_EMAIL", "ceo@net365co.com")
    from_name = os.getenv(
        "WELCOME_FROM_NAME", "Chijioke C. Igbokwe, Founder & CEO"
    )
    reply_to = os.getenv("WELCOME_REPLY_TO", "ceo@net365co.com")

    if not smtp_user or not smtp_password:
        logger.warning("SMTP not configured, skipping welcome email")
        return False

    safe_name = (first_name or "there").strip() or "there"
    import html as _html

    safe_name = _html.escape(safe_name)

    subject = f"Welcome to Net365, {safe_name}!"

    html_body = f"""<!DOCTYPE html>
<html><body style="font-family:Arial,sans-serif;background:#f8fafc;padding:24px;">
  <div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:12px;
              border:1px solid #e2e8f0;overflow:hidden;">
    <div style="background:linear-gradient(145deg,#E31E24 0%,#991B1B 100%);
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

    try:
        msg = MIMEMultipart("alternative")
        # Fixed: formataddr safely formats names with special characters like commas
        msg["From"] = formataddr((from_name, from_email))
        msg["To"] = to_email
        msg["Subject"] = subject
        msg["Reply-To"] = reply_to
        msg.attach(MIMEText(html_body, "html"))

        # Same fix as send_email_notification: SMTP I/O on a background thread
        # so a hung DNS/socket connect can never block the request (signup) path.
        import threading as _threading

        def _bg_send():
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
                logger.info(f"Welcome email sent to {to_email}")
            except Exception as e:
                logger.error(f"Welcome email failed for {to_email}: {e}")

        _threading.Thread(target=_bg_send, daemon=True).start()
        return True
    except Exception as e:
        logger.error(f"Welcome email failed for {to_email}: {e}")
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

    if not smtp_user or not smtp_password:
        logger.warning("SMTP credentials not configured, skipping email notification")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg["Reply-To"] = reply_to

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
                promo_html = _build_email_promo_html(promo)
            except NameError:
                logger.warning("Promo helpers not available, skipping promo block")

        safe_subject = _html.escape(str(subject))
        safe_message = _html.escape(str(message)).replace("\n", "<br>")

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
                background: linear-gradient(145deg, #E31E24 0%, #991B1B 100%);
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
                background: #fef2f2; border-left: 4px solid #E31E24;
                padding: 16px 20px; border-radius: 8px; margin: 16px 0;
            }}
            .message-box p {{ margin: 0; color: #1e293b; }}
            .button {{
                background: linear-gradient(145deg, #E31E24 0%, #991B1B 100%);
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
            .footer .link {{ color: #E31E24; text-decoration: none; font-weight: 600; }}
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

        msg.attach(MIMEText(html_body, "html"))

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
        _result: Dict = {}
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
            user_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            status TEXT DEFAULT 'success',
            details TEXT,
            reference TEXT,
            amount REAL,
            currency TEXT DEFAULT 'NGN',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
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
    from datetime import datetime, timedelta
    import calendar
    import pytz

    # Default to WAT if no timezone specified
    if not timezone_str:
        timezone_str = "Africa/Lagos"

    try:
        tz = pytz.timezone(timezone_str)
    except Exception:
        tz = pytz.timezone("Africa/Lagos")
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
                    event_dt = tz.localize(event_dt)
                else:
                    event_dt = event_dt.astimezone(tz)
                next_run = at_time(event_dt)
                if next_run <= now:
                    return None
                # Convert to UTC for storage
                return next_run.astimezone(pytz.UTC).isoformat()
            except (ValueError, TypeError):
                return None
        return None

    if freq == "daily":
        next_run = at_time(now)
        if next_run <= now:
            next_run += timedelta(days=1)
        return next_run.astimezone(pytz.UTC).isoformat()

    if freq == "weekly":
        target_day = min(max(int(day_of_week or 0), 0), 6)
        days_ahead = (target_day - now.weekday()) % 7
        next_run = at_time(now + timedelta(days=days_ahead))
        if next_run <= now:
            next_run += timedelta(days=7)
        return next_run.astimezone(pytz.UTC).isoformat()

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
        return next_run.astimezone(pytz.UTC).isoformat()

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
        return next_run.astimezone(pytz.UTC).isoformat()

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
        return next_run.astimezone(pytz.UTC).isoformat()

    if freq == "event" and event_date:
        try:
            event_dt = datetime.fromisoformat(str(event_date).replace("Z", "+00:00"))
            if event_dt.tzinfo is None:
                event_dt = tz.localize(event_dt)
            else:
                event_dt = event_dt.astimezone(tz)
            next_run = at_time(event_dt)
            if next_run <= now:
                next_run = next_run.replace(year=next_run.year + 1)
            return next_run.astimezone(pytz.UTC).isoformat()
        except (ValueError, TypeError):
            return None

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


# ============ UPDATE: Apply promotion in payment flow ============


# In your /api/payment/init endpoint, add this before creating the payment:
def init_payment(self):
    # ... existing code ...

    # Apply promotion
    promotion_result = apply_promotion_to_transaction(
        user_id=user_id,
        amount=float(amount),
        service_type=tx_type,  # 'topup', 'utility', 'airtime', etc.
        promo_code=data.get("promo_code"),
        transaction_ref=reference if "reference" in locals() else None,
    )

    if promotion_result.get("discount_amount", 0) > 0:
        # Store promotion in payload
        payload["promotion"] = {
            "id": promotion_result.get("promo_id"),
            "name": promotion_result.get("promo_name"),
            "discount_amount": promotion_result.get("discount_amount"),
            "applied_value": promotion_result.get("applied_value"),
            "discount_type": promotion_result.get("discount_type"),
            "original_amount": amount,
            "new_total": promotion_result.get("new_total"),
        }
        # Update amount for payment
        amount = promotion_result.get("new_total")

        # Log promotion usage
        log_event(
            user_id=user_id,
            event_type="promotion_applied",
            details={
                "promo_id": promotion_result.get("promo_id"),
                "promo_name": promotion_result.get("promo_name"),
                "discount_amount": promotion_result.get("discount_amount"),
                "original_amount": float(data.get("amount")),
                "new_amount": amount,
                "service_type": tx_type,
            },
            status="success",
        )

        db.create_notification(
            user_id,
            f'🎉 {promotion_result.get("promo_name") or "Promotion"} Applied!',
            f'You saved {promotion_result.get("discount_amount"):.2f} on your {tx_type} transaction!',
            "success",
        )

    # Continue with payment using the updated amount
    # ... rest of payment code ...


# ============ ADD TO app.py - Referral Token Processing ============


# ============ FIX: SCHEDULER UTILITY PAYMENT HANDLING ============
# ============ FIX: SCHEDULER TRANSACTION LOGGING ============
# Add this to app.py - replace the existing _execute_schedule_fulfillment function
# or add this missing create_pending call


def _execute_schedule_fulfillment(schedule: Dict, user_id: int, platform) -> Dict:
    import uuid

    service_type = str(schedule.get("service_type") or "airtime").lower()
    amount = float(schedule.get("amount") or 0)
    currency = str(schedule.get("currency") or "NGN").upper()
    wallet_currency = str(schedule.get("wallet_currency") or currency).upper()
    schedule_id = schedule.get("id")

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
                amount=amount,
                currency=wallet_currency,
                description=f'Refund for failed scheduled payment {schedule.get("name")}',
                reference=f"REFUND-{run_reference}",
                metadata={"original_reference": run_reference, "reason": str(exc)},
            )
            return {
                "success": False,
                "error": str(exc),
                "refunded": refund.get("success", False),
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
        db.create_notification(
            user_id,
            "✅ Schedule Executed",
            f'Schedule "{schedule.get("name")}" executed successfully.',
            "success",
        )
        return {"success": True, "status": "completed", "needs_review": False}

    review_required = bool(result.get("needs_review"))
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
    def _tick(cls):
        conn = db.get_db_connection()
        c = conn.cursor()
        now_utc_iso = datetime.utcnow().isoformat()

        due = c.execute(
            """
            SELECT id, user_id FROM scheduler_schedules
            WHERE status = 'active' AND next_run IS NOT NULL AND next_run <= ?
        """,
            (now_utc_iso,),
        ).fetchall()

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
            if os.getenv("ENVIRONMENT", "").lower() == "production":
                raise ValueError("FLASK_SECRET_KEY is required in production")
            flask_secret = "net365-development-secret-change-me"
            logger.warning("FLASK_SECRET_KEY not set; using development-only fallback")
        self.app.secret_key = flask_secret
        self.app.config["SESSION_COOKIE_HTTPONLY"] = True
        self.app.config["SESSION_COOKIE_SECURE"] = SESSION_COOKIE_SECURE
        self.app.config["SESSION_COOKIE_SAMESITE"] = SESSION_COOKIE_SAMESITE
        self.app.config["SESSION_COOKIE_DOMAIN"] = SESSION_COOKIE_DOMAIN
        self.app.config["SESSION_COOKIE_PATH"] = "/"

        db.init_db()
        self.setup_routes()
        self.app.before_request(log_page_visit)

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
        else:
            logger.info(
                "Schedule auto-runner DISABLED in this process (NET365_SCHEDULER_ENABLED is not 'true'). "
                "Schedules will only run when 'Execute Now' is clicked, or from a process that has this "
                "env var set — e.g. run scheduler_worker.py as one dedicated process in production."
            )

    def _find_transaction_by_stripe_session(self, session_id: str) -> Optional[Dict]:
        try:
            conn = db.get_db_connection()
            c = conn.cursor()
            c.execute(
                """
                SELECT * FROM transactions 
                WHERE payload LIKE ? 
                AND tx_type = 'wallet_funding'
                ORDER BY created_at DESC
                LIMIT 1
            """,
                (f"%{session_id}%",),
            )
            result = c.fetchone()
            if result:
                tx = dict(result)
                if tx.get("payload"):
                    tx["payload"] = decrypt_payload(tx["payload"])
                return tx
            return None
        except Exception as e:
            logger.error(f"Error finding Stripe transaction: {e}")
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
                    if stripe_session_id and stripe_session_id.startswith("cs_"):
                        verify_reference = stripe_session_id
                        logger.info(f"Using Stripe session ID from payload: {stripe_session_id}")
                    elif reference.startswith("cs_"):
                        verify_reference = reference
                        logger.info(f"Using Stripe session ID from reference: {reference}")
                    elif reference.startswith("STR_"):
                        stripe_session_id = payload.get("stripe_session_id")
                        if stripe_session_id:
                            verify_reference = stripe_session_id
                            logger.info(f"Found Stripe session ID in payload: {stripe_session_id}")

                try:
                    verify_result = self.platform.verify_payment(verify_reference, tx.get("provider"))
                    logger.info(f"Payment verification result: {verify_result}")
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
                        db.mark_fulfillment_failed(
                            reference,
                            f'Payment not confirmed: {verify_result.get("error")}',
                        )
                        return {
                            "success": False,
                            "error": "Payment not confirmed",
                            "detail": verify_result,
                        }

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

                                if not bonus_config.get("enabled", True):
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
                    email = payload.get("email") or (g.current_user.get("email") if hasattr(g, 'current_user') else None)

                    if not operator_id or not phone:
                        raise Exception("Missing operator_id or phone in transaction payload")

                    # Format phone number for Reloadly
                    formatted_phone = self.platform._format_phone_for_topup(phone, country_code)
                    if not formatted_phone:
                        raise Exception("Invalid phone number format")

                    # Convert amount to USD (Reloadly top‑ups are in USD)
                    amount = float(tx.get("amount", 0))
                    currency = tx.get("currency", "NGN")
                    usd_amount = self.platform.convert_to_usd(amount, currency)
                    if usd_amount <= 0:
                        raise Exception(f"Unable to convert {amount} {currency} to USD")

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

                    # Check failure
                    if topup_result.get("status") == "FAILED" or not topup_result.get("transactionId"):
                        error_msg = topup_result.get("message") or topup_result.get("error") or "Top-up failed at provider"
                        raise Exception(error_msg)

                    # Build success result
                    result = {
                        "status": "success",
                        "transactionId": topup_result.get("transactionId"),
                        "amount": usd_amount,
                        "currency": "USD",
                        "original_amount": amount,
                        "original_currency": currency,
                        "provider": "reloadly",
                        "full_result": topup_result,
                    }

                    # Log success in reloadly_transactions
                    db.create_reloadly_transaction(
                        reference=reference,
                        user_id=user_id,
                        transaction_type="airtime",
                        amount=amount,
                        status="completed",
                        provider_transaction_id=topup_result.get("transactionId"),
                        result=topup_result,
                        currency=currency,
                    )

                    # Notify user
                    db.create_notification(
                        user_id,
                        "Airtime Recharge Successful ✅",
                        f"{currency} {amount:,.2f} recharge completed for {formatted_phone}.",
                        "success"
                    )

                    user = db.get_user(user_id) if user_id else None
                    if user and user.get("email"):
                        try:
                            send_email_notification(
                                user["email"],
                                f"Net365 Airtime Recharge Receipt — {reference}",
                                f"Your airtime recharge was completed successfully.\n\nAmount: {currency} {amount:,.2f}\nPhone: {formatted_phone}\nReference: {reference}",
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

                    # Use the amount as is (Reloadly utility expects local amount)
                    local_amount = amount

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
                        "provider": "reloadly",
                        "full_result": utility_result,
                    }

                    # Log in reloadly_transactions
                    db.create_reloadly_transaction(
                        reference=reference,
                        user_id=user_id,
                        transaction_type="utility",
                        amount=local_amount,
                        status="completed",
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

                else:
                    raise ValueError(f"Unknown transaction type: {tx_type}")

                # Mark the transaction as fulfilled in the main transactions table
                db.mark_fulfilled(reference, result)
                logger.info(f"Fulfilled {tx_type} for reference {reference}")

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
                return {"success": False, "error": str(e)}
                
                
    def _process_bulk_job(self, job_id: str, user_id: int, records: List[Dict]):
        """Background worker that fulfills each record in a bulk recharge job."""
        conn = db.get_db_connection()
        c = conn.cursor()

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
                            db.credit_wallet(
                                user_id=user_id,
                                amount=amount,
                                currency=currency,
                                description=f"Refund for failed bulk recharge {reference}",
                                reference=f"REFUND-{reference}",
                                metadata={"original_reference": reference},
                            )
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
                        db.credit_wallet(
                            user_id=user_id,
                            amount=amount,
                            currency=currency,
                            description=f"Refund for failed bulk recharge {reference}",
                            reference=f"REFUND-{reference}",
                            metadata={"original_reference": reference, "error": str(e)},
                        )
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
        if provider == "paystack":
            auth_url, reference = processor.init_paystack_payment(
                email=email,
                amount=amount,
                return_url=callback,
            )
        elif provider == "flutterwave":
            auth_url, reference = processor.init_flutterwave_payment(
                email=email,
                amount=amount,
                currency=currency,
                return_url=callback,
            )
        elif provider == "stripe":
            auth_url, reference = processor.init_stripe_payment(
                email=email,
                amount=amount,
                currency=currency,
                return_url=callback,
                description=f"Bulk recharge — {contact_count} contacts",
            )
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        if not auth_url:
            raise RuntimeError(f"{provider} did not return an authorization_url")

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


    def _start_wallet_bulk_job(self, user_id, job_id, records, needed):
        """
        Debit the wallet for a bulk job total, tag the job with payment info,
        then kick off the background worker.

        Returns (success: bool, error_message: str | None).
        """
        # 1. Debit the wallet for the full job total
        ok, err = self._debit_wallet(
            user_id, "NGN", needed, reference=f"bulk:{job_id}"
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
                (needed, job_id),
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
        @self.app.after_request
        def add_security_headers(response):
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            return response

        @self.app.route("/")
        def index():
            return render_template(
                "index.html", environment=self.credentials.environment.value
            )

        @self.app.route("/utilities")
        def utilities():
            return render_template(
                "utilities.html", environment=self.credentials.environment.value
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

        @self.app.route("/scheduler/<path:filename>")
        def scheduler_static(filename):
            return send_from_directory(
                os.path.dirname(os.path.abspath(__file__)), filename
            )

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
                db.create_notification(
                    user_id,
                    "🎉 Referral Code Applied!",
                    f"You've been referred by {referrer['full_name']}. Complete your first transaction to earn rewards!",
                    "success",
                )

                return jsonify({
                    "success": True,
                    "message": "Referral code applied successfully!",
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
                if not REFERRAL_BONUS_ENABLED:
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
            # Whole body wrapped in try/except: this route MUST always redirect
            # the user's browser somewhere, never return a raw Flask 500 page.
            # Previously an exception here (DB errors, etc.) escaped uncaught and
            # the user landed on an "Internal Server Error" page instead of the
            # app, even when the underlying payment had already succeeded.
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

                stripe_session_id = None
                if reference.startswith("cs_") or reference.startswith("cs_test_"):
                    stripe_session_id = reference
                    tx = self._find_transaction_by_stripe_session(reference)
                    if tx:
                        reference = tx["reference"]
                        logger.info(
                            f"Found transaction {reference} for Stripe session {stripe_session_id}"
                        )
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
                            logger.info(
                                f"Updated transaction {reference} with Stripe session ID {stripe_session_id}"
                            )
                        except Exception as e:
                            logger.error(
                                f"Failed to update transaction with Stripe session ID: {e}"
                            )

                result = self._finalize_transaction(reference)

                if result.get("success"):
                    redirect_url = f"{frontend_url}/?status=success&reference={reference}"
                    logger.info(f"Payment success - redirecting to: {redirect_url}")
                else:
                    redirect_url = (
                        f"{frontend_url}/?status=processing&reference={reference}"
                    )
                    logger.info(f"Payment processing - redirecting to: {redirect_url}")

                return redirect(redirect_url)

            except Exception as e:
                logger.error(f"payment_success crashed for reference={reference}: {e}")
                import traceback
                logger.error(traceback.format_exc())
                # Never show the raw error page — send them back to the app.
                # The transaction itself (if it succeeded) is unaffected; this
                # only controls what the browser does next.
                fallback_ref = reference or ""
                return redirect(
                    f"{frontend_url}/?status=error&reference={fallback_ref}"
                )

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
            return_url = _safe_payment_return_url(request.args.get("return_url"))
            try:
                if not reference:
                    return redirect(f"{return_url}?status=error")
                separator = "&" if "?" in return_url else "?"
                return redirect(
                    f"{return_url}{separator}status=processing&reference={reference}"
                )
            except Exception as e:
                logger.error(f"payment_callback crashed for reference={reference}: {e}")
                return redirect(f"{FRONTEND_URL}/?status=error")





        
        
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
            if not verify_flutterwave_signature(signature):
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

            payload = request.get_data(as_text=True)
            sig_header = request.headers.get("Stripe-Signature")
            webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

            if not webhook_secret:
                logger.warning(
                    "STRIPE_WEBHOOK_SECRET not set, skipping webhook verification"
                )
                try:
                    event = json.loads(payload)
                except:
                    return jsonify({"status": "webhook secret not configured"}), 200
            else:
                try:
                    event = stripe.Webhook.construct_event(
                        payload, sig_header, webhook_secret
                    )
                except ValueError as e:
                    logger.error(f"Invalid Stripe webhook payload: {e}")
                    return jsonify({"error": "Invalid payload"}), 400
                except stripe.error.SignatureVerificationError as e:
                    logger.error(f"Invalid Stripe signature: {e}")
                    return jsonify({"error": "Invalid signature"}), 400

            logger.info(f"Stripe webhook received: type={event.get('type')}")

            if event.get("type") == "checkout.session.completed":
                session_obj = event.get("data", {}).get("object", {})
                session_id = session_obj.get("id")
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
                    "SELECT name, status, frequency, day_of_month, day_of_week, month, time, event_date FROM scheduler_schedules WHERE id = ? AND user_id = ?",
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

            if currency not in SUPPORTED_CURRENCIES:
                return (
                    jsonify(
                        {"success": False, "error": f"Unsupported currency: {currency}"}
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
                    service_amount = round(
                        float(data.get("service_amount") or total_amount), 2
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
                    email=g.current_user.get("email"),
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
                        "email": g.current_user.get("email"),
                    }
                    if payload.get("phone"):
                        payload["phone"] = encrypt_pii(payload["phone"])

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
                    jsonify(
                        {
                            "success": False,
                            "error": f"Unsupported wallet currency: {currency}",
                        }
                    ),
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
                    jsonify(
                        {
                            "success": False,
                            "error": f"Minimum {currency} funding is {min_amount:g}",
                        }
                    ),
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
            cfg = recommended_payment(get_request_country(request))
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

        # ============ RECEIPT ============
        @self.app.route("/api/receipt/<reference>", methods=["GET"])
        @login_required
        def get_receipt(reference):
            user_id = g.current_user_id
            tx, error = require_owned_transaction(reference, user_id)
            if error:
                return error

            receipt_pdf = generate_receipt(tx)
            if receipt_pdf:
                response = make_response(receipt_pdf)
                response.headers["Content-Type"] = "application/pdf"
                response.headers["Content-Disposition"] = (
                    f"attachment; filename=receipt_{reference}.pdf"
                )
                return response

            return (
                jsonify({"success": False, "error": "Failed to generate receipt"}),
                500,
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

            # ── Wallet pre-flight check (only when wallet was chosen) ─────
            if payment_method == "wallet":
                wallet = db.get_wallet(user_id, "NGN") or {}
                balance = float(wallet.get("balance") or 0)
                if balance + 1e-9 < needed:
                    return jsonify({
                        "success": False,
                        "error": (
                            f"Insufficient NGN wallet balance. "
                            f"Need ~NGN {needed:,.2f}, have NGN {balance:,.2f}. "
                            f"Choose Paystack, Stripe or Flutterwave to pay by card."
                        ),
                        "wallet_balance": balance,
                        "required": needed,
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
                ok, err = self._debit_wallet(user_id, "NGN", needed, reference=f"bulk:{job_id}")
                if not ok:
                    conn = db.get_db_connection()
                    c = conn.cursor()
                    c.execute("UPDATE bulk_jobs SET status = 'failed', error = ? WHERE id = ?",
                              (err or "Wallet debit failed", job_id))
                    conn.commit()
                    conn.close()
                    return jsonify({"success": False, "error": err or "Wallet debit failed",
                                    "job_id": job_id}), 402

                threading.Thread(
                    target=self._process_bulk_job,
                    args=(job_id, user_id, records),
                    daemon=True,
                ).start()

                return jsonify({
                    "success": True,
                    "requires_payment": False,
                    "job_id": job_id,
                    "total": len(records),
                    "skipped_lines": len(errors),
                    "amount": needed,
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
                    amount=needed,
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
                     gateway_currency, needed),
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
                "amount": needed,
                "currency": gateway_currency,
                "total": len(records),
                "provider": payment_method,
            })


        def _start_wallet_bulk_job(self, user_id, job_id, records, needed):
            """
            Debit the wallet for a bulk job total, then kick off the background worker.
            Returns (success, error_message).
            """
            # 1. Debit the wallet
            ok, err = self._debit_wallet(user_id, "NGN", needed, reference=f"bulk:{job_id}")
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
                (needed, job_id),
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

            # ── Wallet pre-flight check ──────────────────────────────────────
            if payment_method == "wallet":
                wallet = db.get_wallet(user_id, "NGN") or {}
                balance = float(wallet.get("balance") or 0)
                if balance + 1e-9 < needed:
                    return jsonify({
                        "success": False,
                        "error": (
                            f"Insufficient NGN wallet balance. "
                            f"Need ~NGN {needed:,.2f}, have NGN {balance:,.2f}. "
                            f"Choose Paystack, Stripe or Flutterwave to pay by card."
                        ),
                        "wallet_balance": balance,
                        "required": needed,
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
                ok, err = self._start_wallet_bulk_job(user_id, job_id, records, needed)
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
                    "amount": needed,
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
                    amount=needed,
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
                    (job_id, payment_method, reference, gateway_currency, needed),
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
                    (payment_method, reference, needed, gateway_currency, job_id),
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
                "amount": needed,
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
            logs = db.get_visitor_logs(
                limit=limit,
                offset=offset,
                device_type=device_type,
                start_date=start_date,
                end_date=end_date,
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
            """
            Import multiple contacts for a user, skipping duplicates by phone/email.
            
            Args:
                user_id: The user's ID
                contacts: List of dicts with phone/email/name
                phone_field: Key name for phone in each contact dict
                name_field: Key name for name in each contact dict
            
            Returns:
                dict: {success, added, skipped, updated, errors}
            """
            conn = get_db_connection()
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
                    
                    # Normalize phone - strip non-digits except leading +
                    clean_phone = re.sub(r'[^\d+]', '', phone)
                    if not clean_phone or len(clean_phone) < 5:
                        skipped += 1
                        continue
                    
                    # Check for existing contact by phone or email
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
                        # Update existing contact
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
                            (name, network, country, email,
                             existing_phones[phone]["id"], user_id)
                        )
                        updated += 1
                    else:
                        # Insert new contact
                        c.execute("""
                            INSERT INTO contacts (user_id, name, phone, email, network, country, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        """, (user_id, name or 'Contact', clean_phone, email, network, country))
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
            data = request.json
            email = data.get("email")
            password = data.get("password")
            full_name = data.get("full_name")
            phone = data.get("phone")
            referral_code = data.get("referral_code", "").strip().upper()

            # DEFAULT REFERRAL CODE - allowed for all users
            DEFAULT_REFERRAL_CODE = "00000"

            if not email or not password:
                return (
                    jsonify({"success": False, "error": "Email and password required"}),
                    400,
                )

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
                    send_welcome_email(email, full_name or "")
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
            country_code = request.args.get("country_code", "NG")
            if not phone:
                return jsonify({"success": False, "error": "Phone number required"}), 400

            try:
                result = self.platform.auto_detect_operator(phone, country_code)
            except Exception as e:
                logger.warning(f"auto-detect route: Reloadly unreachable for {phone}: {e}")
                result = {"success": False, "error": str(e)}

            if result.get("success") and result.get("operator"):
                return jsonify(result)

            # Reloadly could not identify the number. If we couldn't reach Reloadly
            # at all (network error), fall back to a prefix hint — clearly labelled.
            # If Reloadly *did* respond but returned "unknown", respect that and do
            # not guess.
            reachable = result.get("success") is False and "unreachable" not in str(result.get("error", ""))
            if not reachable:
                fallback = detect_operator_from_prefix(phone, country_code)
                if fallback:
                    return jsonify({
                        "success": True,
                        "operator": fallback,
                        "source": "prefix_fallback",
                        "warning": "Network inferred from number prefix — may be wrong if the number has been ported.",
                    })

            return jsonify(result)

        @self.app.route("/api/operators/<operator_id>", methods=["GET"])
        def get_operator_details(operator_id):
            return jsonify(self.platform.get_operator_by_id(operator_id))

        @self.app.route("/api/balance", methods=["GET"])
        def get_balance():
            try:
                return jsonify(self.platform.get_balance())
            except Exception as e:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": str(e),
                            "balance": 0,
                            "currency": "USD",
                        }
                    ),
                    500,
                )

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
                "encryption": bool(ENCRYPTION_KEY),
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

            next_run = data.get("next_run")
            if not next_run and data.get("frequency"):
                next_run = calculate_next_run(
                    data.get("frequency"),
                    data.get("day_of_month", 1),
                    data.get("time", "09:00"),
                    data.get("day_of_week", 0),
                    data.get("month", 1),
                    data.get("event_date"),
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

            result = self.platform.create_payment(
                amount=amount,
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

                db.create_pending(
                    reference=result["reference"],
                    tx_type="utility",
                    provider=result.get("provider", provider or "paystack"),
                    amount=amount,
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

                # ============ PROMOTIONS MANAGEMENT API ============

        @self.app.route("/api/admin/promotions", methods=["GET"])
        @admin_required
        def admin_get_promotions():
            """Get all promotions with pagination."""
            limit = min(request.args.get("limit", 50, type=int), 100)
            offset = max(request.args.get("offset", 0, type=int), 0)
            promotions = db.get_all_promotions(limit, offset)
            return jsonify({"success": True, "promotions": promotions})

            # ============ PROMOTIONS MANAGEMENT API ============

        @self.app.route("/api/admin/promotions", methods=["POST"])
        @admin_required
        def admin_create_promotion():
            """Create a new promotion."""
            data = request.json or {}

            # Log incoming data for debugging
            logger.info(f"Creating promotion with data: {data}")

            # Only require name, title, body - everything else is optional
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

            # Build promotion data with defaults for all fields
            try:
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
                    # New fields for percentage discounts
                    discount_type=data.get("discount_type", "fixed"),
                    discount_value=data.get("discount_value", 0),
                    max_discount=data.get("max_discount"),
                    min_purchase=data.get("min_purchase"),
                    service_types=data.get("service_types"),
                    usage_limit_per_user=data.get("usage_limit_per_user"),
                    coupon_code=data.get("coupon_code"),
                    is_referral=data.get("is_referral", False),
                    referrer_bonus_type=data.get("referrer_bonus_type", "fixed"),
                    referrer_bonus_value=data.get("referrer_bonus_value", 0),
                    referred_bonus_type=data.get("referred_bonus_type", "fixed"),
                    referred_bonus_value=data.get("referred_bonus_value", 0),
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

            except Exception as e:
                logger.error(f"Error creating promotion: {e}")
                return jsonify({"success": False, "error": str(e)}), 500

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

        @self.app.route("/api/admin/users", methods=["GET"])
        @admin_required
        def admin_search_users():
            query = (request.args.get("q") or "").strip()
            conn = db.get_db_connection()
            c = conn.cursor()

            if not query:
                # Return total count and empty list when no query
                total = c.execute("SELECT COUNT(*) FROM users").fetchone()[0] or 0
                conn.close()
                return jsonify({"success": True, "users": [], "total": total})

            rows = c.execute(
                """
                SELECT id, email, phone, full_name, account_status, status_reason, status_changed_at,
                       email_verified, phone_verified, created_at
                FROM users WHERE email LIKE ? OR phone LIKE ? OR full_name LIKE ?
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
            return (
                request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
                .split(",")[0]
                .strip()
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
            "/api/admin/users/<int:target_user_id>/set-password", methods=["POST"]
        )
        @admin_required
        def admin_set_password_directly(target_user_id):
            data = request.json or {}
            new_password = data.get("new_password")
            if not new_password or len(new_password) < 8:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "New password must be at least 8 characters",
                        }
                    ),
                    400,
                )
            if not db.get_user(target_user_id):
                return jsonify({"success": False, "error": "User not found"}), 404

            db.set_password(target_user_id, new_password)
            db.kill_user_sessions(target_user_id)
            log_event(
                user_id=target_user_id,
                event_type="admin_password_set_directly",
                details={
                    "admin": _admin_identity(),
                    "note": "Emergency direct set, no email round-trip",
                },
                status="success",
            )
            return jsonify(
                {
                    "success": True,
                    "message": "Password set. All existing sessions were terminated — the user (or you) can now log in with the new password.",
                }
            )

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
            phone = data.get("phone")
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
                details={"admin": _admin_identity()},
                status="success",
            )
            return jsonify(
                {"success": True, "user": sanitize_user(db.get_user(user_id))}
            )

        @self.app.route("/api/admin/users/<int:target_user_id>", methods=["DELETE"])
        @admin_required
        def admin_delete_user(target_user_id):
            data = request.json or {}
            reason = (data.get("reason") or "Deleted by admin").strip()
            user = db.get_user(target_user_id)
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404

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
app = web_app.app  # <-- this is what `gunicorn main:app` binds to
# ============================================================


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

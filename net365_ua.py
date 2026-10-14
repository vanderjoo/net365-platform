"""
net365_ua.py — User-Agent device/brand/model extraction for Net365.

Exposes:
    DeviceDetector(user_agent, headers=None).parse()
        .device_brand() -> str
        .device_model() -> str

    parse_device_model(ua_string, request_obj=None) -> str

Renamed from ua_extract.py because a PyPI package named `ua_extract` was
already installed in site-packages and shadowed the local file.
"""

import re


class _ParsedDevice:
    def __init__(self, brand="", model=""):
        self._brand = brand or ""
        self._model = model or ""

    def device_brand(self):
        return self._brand

    def device_model(self):
        return self._model


class DeviceDetector:
    def __init__(self, user_agent="", headers=None):
        self.user_agent = user_agent or ""
        self.headers = headers or {}

    def parse(self):
        ua = self.user_agent
        h = {k.lower(): v for k, v in self.headers.items()}

        # ---- 1. Client Hints (most accurate for modern Android Chrome) ----
        ch_model = h.get("sec-ch-ua-model", "").strip('"').strip()
        if ch_model:
            brand = self._brand_from_model(ch_model)
            return _ParsedDevice(brand, ch_model)

        # ---- 2. iPhone / iPad / iPod ----
        if re.search(r"iPhone", ua):
            return _ParsedDevice("Apple", "iPhone")
        if re.search(r"iPad", ua):
            return _ParsedDevice("Apple", "iPad")
        if re.search(r"iPod", ua):
            return _ParsedDevice("Apple", "iPod")

        # ---- 3. Android: "Android X; <model> Build/..." ----
        m = re.search(r"Android[^;]*;\s*([^;)]+?)(?:\s+Build[/\s]|\)|;)", ua)
        if m:
            model = m.group(1).strip()
            model = re.sub(r"^[a-z]{2}-[a-z]{2}[;\s]*", "", model, flags=re.I).strip()
            brand = self._brand_from_model(model)
            return _ParsedDevice(brand, model)

        # ---- 4. Desktop — no model. Return "" so caller writes NULL. ----
        return _ParsedDevice("", "")

    @staticmethod
    def _brand_from_model(model: str) -> str:
        m = model.lower()
        if m.startswith(("sm-", "gt-", "sgh-", "sch-")) or "samsung" in m:
            return "Samsung"
        if m.startswith("pixel") or "google" in m:
            return "Google"
        if m.startswith(("m2", "redmi", "mi ", "poco")) or "xiaomi" in m:
            return "Xiaomi"
        if m.startswith("cph"):
            return "Oppo"
        if m.startswith("vivo") or m.startswith("v2"):
            return "Vivo"
        if m.startswith("oneplus") or m.startswith("ne2"):
            return "OnePlus"
        if "moto" in m:
            return "Motorola"
        if "huawei" in m or m.startswith(("ane-", "lya-", "ele-", "vog-")):
            return "Huawei"
        if "nokia" in m:
            return "Nokia"
        if "infinix" in m:
            return "Infinix"
        if "tecno" in m:
            return "Tecno"
        if "itel" in m:
            return "Itel"
        return ""


def parse_device_model(ua_string, request_obj=None):
    """Return 'Brand Model' (or just one of them) from UA + client hints.

    Returns "" when nothing meaningful could be determined.
    """
    headers = {}
    if request_obj is not None:
        try:
            headers = dict(request_obj.headers)
        except Exception:
            headers = {}
    try:
        device = DeviceDetector(ua_string, headers=headers).parse()
        brand = device.device_brand() or ""
        model = device.device_model() or ""
    except Exception:
        return ""
    if brand and model:
        return f"{brand} {model}"
    return model or brand or ""

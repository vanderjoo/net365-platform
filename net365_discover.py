#!/usr/bin/env python3
"""
net365_discover.py - Discover public Microsoft 365 / Entra ID tenant info for a domain.

Uses only unauthenticated, public endpoints:
  * OpenID configuration  -> tenant ID
  * GetUserRealm          -> Managed vs Federated, brand name, federation URL
  * Autodiscover (SOAP)   -> all domains registered in the same tenant

Usage:
    python net365_discover.py contoso.com
    python net365_discover.py contoso.com fabrikam.com --json
    python net365_discover.py -f domains.txt --no-domains

Only run this against domains you own or are authorized to assess.
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

TIMEOUT = 10
UA = "net365-discover/1.0"

AUTODISCOVER_URL = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"

SOAP_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
    xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Header>
    <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
    <a:To soap:mustUnderstand="1">{url}</a:To>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
  </soap:Header>
  <soap:Body>
    <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Request>
        <Domain>{domain}</Domain>
      </Request>
    </GetFederationInformationRequestMessage>
  </soap:Body>
</soap:Envelope>"""

GUID_RE = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")


def http(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="replace")


def get_tenant_id(domain):
    url = f"https://login.microsoftonline.com/{urllib.parse.quote(domain)}/.well-known/openid-configuration"
    try:
        cfg = json.loads(http(url))
    except urllib.error.HTTPError as e:
        if e.code == 400:
            return None  # domain not in any tenant
        raise
    m = GUID_RE.search(cfg.get("token_endpoint", ""))
    return m.group(0).lower() if m else None


def get_user_realm(domain):
    url = "https://login.microsoftonline.com/getuserrealm.srf?" + urllib.parse.urlencode(
        {"login": f"user@{domain}", "json": "1"}
    )
    return json.loads(http(url))


def get_tenant_domains(domain):
    body = SOAP_TEMPLATE.format(url=AUTODISCOVER_URL, domain=domain).encode("utf-8")
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"',
    }
    xml_text = http(AUTODISCOVER_URL, data=body, headers=headers)
    root = ET.fromstring(xml_text)
    domains = sorted(
        {el.text.strip().lower() for el in root.iter() if el.tag.endswith("}Domain") and el.text}
    )
    return domains


def discover(domain, want_domains=True):
    domain = domain.strip().lower()
    result = {"domain": domain, "tenant_id": None, "name_space_type": None,
              "brand_name": None, "federation_url": None, "tenant_domains": [],
              "errors": []}
    try:
        result["tenant_id"] = get_tenant_id(domain)
    except Exception as e:
        result["errors"].append(f"openid: {e}")
    try:
        realm = get_user_realm(domain)
        result["name_space_type"] = realm.get("NameSpaceType")
        result["brand_name"] = realm.get("FederationBrandName")
        result["federation_url"] = realm.get("AuthURL")
    except Exception as e:
        result["errors"].append(f"getuserrealm: {e}")
    if want_domains:
        try:
            result["tenant_domains"] = get_tenant_domains(domain)
        except Exception as e:
            result["errors"].append(f"autodiscover: {e}")
    result["uses_m365"] = result["name_space_type"] in ("Managed", "Federated")
    return result


def print_result(r):
    print(f"== {r['domain']}")
    print(f"  Uses Microsoft 365/Entra : {'yes' if r['uses_m365'] else 'no / unknown'}")
    print(f"  Tenant ID                : {r['tenant_id'] or '-'}")
    print(f"  Namespace type           : {r['name_space_type'] or '-'}")
    print(f"  Brand name               : {r['brand_name'] or '-'}")
    if r["federation_url"]:
        print(f"  Federation URL           : {r['federation_url']}")
    if r["tenant_domains"]:
        print(f"  Tenant domains ({len(r['tenant_domains'])}):")
        for d in r["tenant_domains"]:
            print(f"    - {d}")
    for err in r["errors"]:
        print(f"  ! {err}", file=sys.stderr)
    print()


def main():
    ap = argparse.ArgumentParser(description="Discover public Microsoft 365 tenant info for domains.")
    ap.add_argument("domains", nargs="*", help="domain(s) to check")
    ap.add_argument("-f", "--file", help="file with one domain per line")
    ap.add_argument("--no-domains", action="store_true", help="skip tenant domain enumeration")
    ap.add_argument("--json", action="store_true", help="output JSON")
    args = ap.parse_args()

    domains = list(args.domains)
    if args.file:
        with open(args.file) as fh:
            domains += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not domains:
        ap.error("provide at least one domain or --file")

    results = [discover(d, want_domains=not args.no_domains) for d in domains]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print_result(r)


if __name__ == "__main__":
    main()

"""
Test VTpass from your own computer, through the real Net365 router code.

Put this file next to net365_providers.py (the same folder as app.py and your .env), then:

    pip install requests flask python-dotenv
    python test_vtpass_local.py                       # step 1+2: keys + wallet balance, buys nothing
    python test_vtpass_local.py --buy                 # step 3: a SANDBOX airtime purchase (fake money)
    python test_vtpass_local.py --buy --phone 08011111111 --network mtn --amount 100
    python test_vtpass_local.py --meter 1111111111111 --disco ikeja --amount 1000     # electricity (sandbox)

It uses a throwaway database, so your real data is never touched. It refuses to buy unless VTPASS_ENV=sandbox
(add --allow-live only if you really mean to spend real money from your VTpass wallet).
"""
import argparse
import os
import sqlite3
import sys
import tempfile
import time

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    print("(python-dotenv not installed: using only variables already set in this terminal)")

os.environ["PROVIDER_ROUTER_ENABLED"] = "true"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import net365_providers as P  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--buy", action="store_true", help="make an airtime purchase")
ap.add_argument("--phone", default="08011111111", help="VTpass sandbox test number (check their docs for the current ones)")
ap.add_argument("--network", default="mtn", choices=["mtn", "airtel", "glo", "9mobile"])
ap.add_argument("--amount", type=float, default=100)
ap.add_argument("--meter", help="electricity meter number: buys electricity instead of airtime")
ap.add_argument("--disco", default="ikeja")
ap.add_argument("--tv", choices=["dstv", "gotv", "startimes", "showmax"], help="TV subscription test (sandbox card 1212121212; showmax uses --phone)")
ap.add_argument("--edu", choices=["waec", "waec-registration", "jamb"], help="education PIN test (JAMB sandbox profile 0123456789)")
ap.add_argument("--card", default="", help="smartcard / JAMB profile number (defaults to the documented sandbox one)")
ap.add_argument("--plan", default="", help="variation code; default = first plan in the catalogue")
ap.add_argument("--renew", action="store_true", help="DStv/GOtv: renew instead of changing bouquet")
ap.add_argument("--allow-live", action="store_true")
a = ap.parse_args()

env = os.getenv("VTPASS_ENV", "sandbox").lower()
vt = P._registry()["vtpass"]
print(f"VTpass environment : {env}  ({vt.base})")
missing = [k for k in ("VTPASS_API_KEY", "VTPASS_SECRET_KEY", "VTPASS_PUBLIC_KEY") if not os.getenv(k)]
print("keys present       :", "all three" if not missing else "MISSING " + ", ".join(missing))
if missing:
    sys.exit("Fix your .env first (is it in this folder? no spaces or quotes around the values?).")

bal = vt.balance()
print("wallet balance     :", bal if bal is not None else "could not read (details below)")
if bal is None:
    try:
        import requests
        r = requests.get(vt.base + "/balance", headers=vt._get_headers(), timeout=20)
        print(f"   balance call    : HTTP {r.status_code}")
        print("   VTpass said     :", r.text[:300].replace("\n", " "))
        print("   (a 'balance' problem alone does not stop purchases: the purchase test below is the real check)")
    except Exception as e:
        print("   could not reach VTpass:", type(e).__name__, str(e)[:200])

path = tempfile.mktemp(suffix=".db")


class DB:
    def get_db_connection(self):
        c = sqlite3.connect(path)
        c.row_factory = sqlite3.Row
        return c


P._d["db"] = DB()
P._ensure_schema()
print("router sees VTpass :", [(r["provider"], "eligible" if r["eligible"] else r["why"]) for r in P.rank("airtime", a.network)][0])

if not (a.buy or a.meter or a.tv or a.edu):
    print("\nNo purchase made. Add --buy to test an airtime purchase in the sandbox.")
    sys.exit(0)

if env == "live" and not a.allow_live:
    sys.exit("VTPASS_ENV is live: refusing to buy. Set VTPASS_ENV=sandbox, or add --allow-live to spend real money.")

ref = "TEST" + str(int(time.time()))
if a.tv or a.edu:
    prod = a.tv or a.edu
    svc = "tv" if a.tv else "education"
    plans = P.service_catalog(prod)
    print(f"\n{prod}: {len(plans)} plans in the catalogue")
    for p_ in plans[:8]:
        print(f"   {p_['code']:28} {p_['price']:>10,.2f}  {p_['name']}")
    plan = next((p_ for p_ in plans if p_["code"] == a.plan), plans[0] if plans else None)
    if not plan:
        sys.exit("No plans came back. Check keys / that the product is enabled on your VTpass account (028 = not whitelisted).")
    card = a.card or ("0123456789" if prod == "jamb" else "1212121212")
    if prod in ("dstv", "gotv", "startimes", "jamb"):
        print("verify:", P.verify_account(prod, card, plan["code"]))
    print(f"Buying {prod} plan {plan['code']} (N{plan['price']:,.0f}) ...")
    r = P.route_purchase(ref, svc, network=prod, phone=a.phone, amount=plan["price"], account=card if prod != "showmax" else a.phone,
                         variation_code=plan["code"], subscription_type="renew" if a.renew else "change")
elif a.meter:
    print(f"\nBuying electricity: disco={a.disco} meter={a.meter} amount={a.amount} ...")
    r = P.route_purchase(ref, "electricity", disco=a.disco, account=a.meter, phone=a.phone, amount=a.amount)
else:
    print(f"\nBuying airtime: {a.network} {a.phone} N{a.amount:.0f} ...")
    r = P.route_purchase(ref, "airtime", network=a.network, phone=a.phone, amount=a.amount)

print("\nRESULT")
for k in ("status", "provider", "provider_ref", "code", "message", "tried", "fallback_ok"):
    print(f"  {k:13}: {r.get(k)}")
if r.get("token"):
    print("  token        :", r["token"])
print("\nWhat the status means:")
print("  success  -> VTpass delivered it")
print("  pending  -> VTpass accepted it but has not finished (normal for some sandbox test numbers)")
print("  failed   -> VTpass refused it; 'code' says why (018 = wallet empty, 027 = IP not whitelisted, 087 = bad keys,")
print("              085 = bad request id/clock, 012/010 = wrong service or plan id)")
c = DB().get_db_connection()
row = c.execute("SELECT request_id, status, code, message FROM provider_attempts WHERE reference = ?", (ref,)).fetchone()
if row:
    print("\nrecorded attempt   :", dict(row))
c.close()

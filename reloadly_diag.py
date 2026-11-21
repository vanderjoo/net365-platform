"""Run from your Net365 project folder:  python reloadly_diag.py
Checks the Reloadly accounts your app uses and prints balances. Prints no secrets."""
import os, sys
from dotenv import load_dotenv
load_dotenv()
import app as A
plat = A.web_app.platform if hasattr(A, "web_app") else None
api = plat._get_utilities_api()
env = os.getenv("RELOADLY_ENVIRONMENT", "?")
print("Environment:", env)
for label, call in (("Utilities balance", lambda: api._make_request("GET", "/accounts/balance")),
                    ("Airtime balance",   lambda: plat.get_balance())):
    try:
        print(f"{label}: {call()}")
    except Exception as e:
        resp = getattr(e, "response", None)
        print(f"{label}: FAILED -> {e}", (resp.text[:300] if resp is not None else ""))
try:
    from net365_giftcards import _api as _gc_api
    print("Gift card balance:", _gc_api().balance())
except Exception as e:
    resp = getattr(e, "response", None)
    print("Gift card balance: FAILED ->", e, (resp.text[:300] if resp is not None else ""))
print("\nIf Utilities balance FAILS the same way as /pay, the problem is in your Reloadly account"
      " (wallet / sandbox setup). Send this output to Reloadly support.")

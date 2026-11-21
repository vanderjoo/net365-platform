"""Net365 Money Intelligence: one reporting engine for the web API, Telegram/WhatsApp bots and scheduled reports.

What it does
  * Turns a customer's own completed Net365 payments into clear reports: totals, categories, comparison with the
    previous period, fees, repeat top-ups, budget progress and upcoming scheduled payments.
  * Writes short, factual insights (rule based, no guessing, no investment advice).
  * Answers plain questions ("how much did I spend on electricity last month?") from the same data.
  * Delivers scheduled reports to the customer's linked chat and/or their verified account email.

What it never does
  * Move money, touch payment routes, or read anything outside the transactions/schedules tables.
  * Add different currencies together or convert at a guessed rate.
  * Present wallet funding as earned income, or give financial/investment advice.

Scheduled delivery is exposed as run_due_reports() and a small MoneyReportRunner thread. Start it in exactly ONE
process (the one with NET365_SCHEDULER_ENABLED=true), never in every web worker.
"""
from __future__ import annotations

import calendar
import json
import logging
import re
import threading
import time
from collections import defaultdict
from datetime import date, datetime, time as dtime, timedelta, timezone

from flask import Blueprint, g, jsonify, request

log = logging.getLogger("net365.money")

try:
    from zoneinfo import ZoneInfo
    LAGOS = ZoneInfo("Africa/Lagos")
except Exception:  # pragma: no cover
    LAGOS = timezone(timedelta(hours=1))

DONE = ("fulfilled", "completed", "success", "succeeded")
INCOME_TYPES = {"wallet_funding", "deposit", "wallet_credit", "cash_in"}
TRANSFER_TYPES = {"wallet_transfer", "transfer", "p2p_transfer"}
SAVINGS_TYPES = {"savings", "savings_deposit", "goal_contribution"}
SKIP_TYPES = {"refund", "reversal"}
DATA_SCOPE = ("Completed Net365 payments only. Bank accounts and spending outside Net365 are not included. "
              "These are simple observations, not financial advice.")
MAX_RUNS_PER_DAY = 20

_ELEC = re.compile(r"ELECTRIC|POWER|DISCO|IKEDC|EKEDC|AEDC|PHED|IBEDC|KEDCO|\bJED\b|BEDC|EEDC|YEDC", re.I)
_TV = re.compile(r"CABLE|DSTV|GOTV|STARTIME|\bTV\b|SHOWMAX", re.I)

_decrypt = None
_schema_ready = False
_schema_lock = threading.Lock()


def set_decryptor(fn):
    """Payloads are stored encrypted (phone numbers). Pass the app's decrypt_payload so reports can read them."""
    global _decrypt
    _decrypt = fn


# --------------------------------------------------------------------------- small helpers
def _money(cur, amount):
    amount = float(amount or 0)
    return f"₦{amount:,.0f}" if str(cur).upper() == "NGN" else f"{str(cur).upper()} {amount:,.2f}"


def _short_day(d):
    return f"{d.day} {d.strftime('%b')}"


def _label(period, a, b):
    if period == "monthly" and a.day == 1 and (b.month, b.year) == (a.month, a.year):
        return a.strftime("%B %Y")
    if a == b:
        return _short_day(a)
    return f"{_short_day(a)} to {_short_day(b)}"


def _national(p):
    d = re.sub(r"\D", "", str(p or ""))
    if d.startswith("234"):
        d = d[3:]
    return d.lstrip("0")


def _window(period, now, start=None, end=None, completed=False):
    """(a, b, prev_a, prev_b) as Lagos calendar dates. `completed` = the last finished day/week/month."""
    today = now.date()
    if period == "custom":
        if not start or not end:
            raise ValueError("Custom reports need start and end dates (YYYY-MM-DD).")
        a, b = date.fromisoformat(str(start)), date.fromisoformat(str(end))
        if b < a:
            raise ValueError("End date must be on or after the start date.")
        if (b - a).days > 366:
            raise ValueError("A custom report cannot cover more than 366 days.")
    elif period == "daily":
        a = b = today - timedelta(days=1) if completed else today
    elif period == "weekly":
        if completed:
            a = today - timedelta(days=today.weekday() + 7)
            b = a + timedelta(days=6)
        else:
            a, b = today - timedelta(days=6), today
    elif period == "monthly":
        if completed:
            b = today.replace(day=1) - timedelta(days=1)
            a = b.replace(day=1)
        else:
            a, b = today.replace(day=1), today
    else:
        raise ValueError("period must be daily, weekly, monthly or custom")
    if period == "monthly":
        pb = a - timedelta(days=1)
        pa = pb.replace(day=1)
    else:
        n = (b - a).days + 1
        pb = a - timedelta(days=1)
        pa = pb - timedelta(days=n - 1)
    return a, b, pa, pb


def _utc_floor(d):
    return datetime.combine(d, dtime.min, LAGOS).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- schema
def _ensure_schema(conn):
    global _schema_ready
    if _schema_ready:
        return
    with _schema_lock:
        if _schema_ready:
            return
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS financial_report_preferences (
          user_id INTEGER PRIMARY KEY, period TEXT NOT NULL DEFAULT 'weekly',
          channel TEXT NOT NULL DEFAULT 'chat', email_enabled INTEGER NOT NULL DEFAULT 0,
          email TEXT, enabled INTEGER NOT NULL DEFAULT 1, updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS financial_report_runs (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
          period TEXT NOT NULL, start_date TEXT NOT NULL, end_date TEXT NOT NULL,
          currency TEXT NOT NULL, report_json TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_fin_report_runs_user ON financial_report_runs(user_id, created_at);
        CREATE TABLE IF NOT EXISTS spending_budgets (
          user_id INTEGER PRIMARY KEY, monthly_ngn REAL NOT NULL, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(financial_report_runs)").fetchall()}
        for name, ddl in (("scheduled", "INTEGER DEFAULT 0"), ("delivered", "INTEGER DEFAULT 0"), ("attempts", "INTEGER DEFAULT 0")):
            if name not in cols:
                conn.execute(f"ALTER TABLE financial_report_runs ADD COLUMN {name} {ddl}")
        try:
            conn.commit()
        except Exception:
            pass
        _schema_ready = True


def get_budget(conn, user_id):
    row = conn.execute("SELECT monthly_ngn FROM spending_budgets WHERE user_id = ?", (user_id,)).fetchone()
    return float(row[0]) if row else None


def set_budget(conn, user_id, amount):
    """amount <= 0 removes it. Returns the stored budget or None. Raises ValueError for silly values."""
    amount = float(amount or 0)
    if amount <= 0:
        conn.execute("DELETE FROM spending_budgets WHERE user_id = ?", (user_id,))
    elif 1000 <= amount <= 100000000:
        conn.execute("INSERT INTO spending_budgets (user_id, monthly_ngn) VALUES (?, ?) ON CONFLICT(user_id) "
                     "DO UPDATE SET monthly_ngn = excluded.monthly_ngn, updated_at = CURRENT_TIMESTAMP", (user_id, amount))
    else:
        raise ValueError("Budget must be between 1,000 and 100,000,000 naira.")
    try:
        conn.commit()
    except Exception:
        pass
    return get_budget(conn, user_id)


# --------------------------------------------------------------------------- data
def _category(tx_type, pl):
    t = str(tx_type or "other").lower().replace("-", "_").replace(" ", "_")
    if t in ("topup", "airtime", "data", "international_airtime", "foreign_airtime"):
        abroad = str(pl.get("country_code") or "NG").upper() != "NG" or t in ("international_airtime", "foreign_airtime")
        return "Airtime abroad" if abroad else ("Data" if t == "data" else "Airtime")
    if t in ("utility", "bill", "electricity", "power", "cable", "dstv", "gotv", "startimes"):
        name = str(pl.get("biller_name") or t)
        return "Electricity" if _ELEC.search(name) else "Cable TV" if _TV.search(name) else "Bills"
    if t == "giftcard":
        return "Gift cards"
    if t in ("merchant", "business_payment"):
        return "Business payments"
    if t == "sms":
        return "Messaging"
    return t.replace("_", " ").title() or "Other"


def _kind(tx_type):
    t = str(tx_type or "").lower()
    return "income" if t in INCOME_TYPES else "transfer" if t in TRANSFER_TYPES else "savings" if t in SAVINGS_TYPES else "spend"


def _load_rows(conn, user_id, since_utc):
    rows = conn.execute(
        "SELECT tx_type, amount, currency, created_at, payload FROM transactions WHERE user_id = ? "
        "AND lower(status) IN (%s) AND created_at >= ? ORDER BY created_at DESC LIMIT 4000" % ",".join("?" * len(DONE)),
        (user_id, *DONE, since_utc)).fetchall()
    out = []
    for r in rows:
        t = str(r["tx_type"] or "").lower()
        if t in SKIP_TYPES:
            continue
        try:
            pl = r["payload"]
            pl = json.loads(pl) if isinstance(pl, str) else (pl or {})
            if _decrypt:
                pl = _decrypt(dict(pl))
        except Exception:
            pl = {}
        try:
            day = datetime.strptime(str(r["created_at"])[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).astimezone(LAGOS).date()
        except Exception:
            continue
        try:
            fee = float(pl.get("fee_amount") or 0)
        except (TypeError, ValueError):
            fee = 0.0
        nat = _national(pl.get("phone")) if t == "topup" else ""
        out.append({"day": day, "cur": str(r["currency"] or "NGN").upper(), "amt": float(r["amount"] or 0), "kind": _kind(t),
                    "cat": _category(t, pl), "fee": fee, "nat": nat if re.match(r"^[789][01]\d{8}$", nat) else ""})
    return out


def _stats(items):
    income = sum(i["amt"] for i in items if i["kind"] == "income")
    transfers = sum(i["amt"] for i in items if i["kind"] == "transfer")
    savings = sum(i["amt"] for i in items if i["kind"] == "savings")
    spend = [i for i in items if i["kind"] == "spend"]
    expenses = sum(i["amt"] for i in spend)
    cats = defaultdict(lambda: [0.0, 0])
    for i in spend:
        cats[i["cat"]][0] += i["amt"]
        cats[i["cat"]][1] += 1
    categories = [{"name": k, "amount": round(v[0], 2), "count": v[1], "pct": round(v[0] / expenses * 100) if expenses else 0}
                  for k, v in sorted(cats.items(), key=lambda kv: -kv[1][0])]
    nums = defaultdict(lambda: [0, 0.0])
    for i in spend:
        if i["nat"]:
            nums[i["nat"]][0] += 1
            nums[i["nat"]][1] += i["amt"]
    top = None
    if nums:
        nat, (c, amt) = max(nums.items(), key=lambda kv: (kv[1][0], kv[1][1]))
        top = {"label": f"0{nat[:3]}••••{nat[-3:]}", "count": c, "amount": round(amt, 2)}
    big = max(spend, key=lambda i: i["amt"]) if spend else None
    return {"income": round(income, 2), "expenses": round(expenses, 2), "transfers": round(transfers, 2), "savings": round(savings, 2),
            "transaction_count": len(items), "spend_count": len(spend), "fees": round(sum(i["fee"] for i in spend), 2),
            "categories": categories, "top_number": top,
            "largest": {"category": big["cat"], "amount": round(big["amt"], 2), "date": big["day"].isoformat()} if big else None}


def _upcoming(conn, user_id, now, days=14):
    out = []
    try:
        rows = conn.execute("SELECT name, amount, currency, next_run FROM scheduler_schedules WHERE user_id = ? "
                            "AND lower(status) IN ('active','pending') AND next_run IS NOT NULL ORDER BY next_run LIMIT 40", (user_id,)).fetchall()
        for r in rows:
            try:
                dt = datetime.fromisoformat(str(r["next_run"]).replace("Z", "+00:00").replace(" ", "T"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                dt = dt.astimezone(LAGOS)
            except Exception:
                continue
            if now <= dt <= now + timedelta(days=days):
                out.append({"name": str(r["name"] or "Scheduled payment")[:60], "amount": float(r["amount"] or 0),
                            "currency": str(r["currency"] or "NGN").upper(), "due": dt.strftime("%Y-%m-%d %H:%M"),
                            "due_label": dt.strftime("%a ") + _short_day(dt.date())})
    except Exception:
        log.debug("upcoming schedules unavailable", exc_info=True)
    return out[:10]


def build_report(conn, user_id, period="weekly", start=None, end=None, completed=False, now=None):
    """Everything about one customer's completed payments for a period. Raises ValueError for bad periods."""
    _ensure_schema(conn)
    now = (now or datetime.now(LAGOS)).astimezone(LAGOS)
    a, b, pa, pb = _window(period, now, start, end, completed)
    month_start = now.date().replace(day=1)
    items = _load_rows(conn, user_id, _utc_floor(min(pa, month_start) - timedelta(days=1)))
    cur_items = [i for i in items if a <= i["day"] <= b]
    prev_items = [i for i in items if pa <= i["day"] <= pb]
    mtd_ngn = [i for i in items if month_start <= i["day"] <= now.date() and i["cur"] == "NGN"]
    currencies = {}
    for cur in sorted({i["cur"] for i in cur_items}) or ["NGN"]:
        s = _stats([i for i in cur_items if i["cur"] == cur])
        p = _stats([i for i in prev_items if i["cur"] == cur])
        s["previous_expenses"] = p["expenses"]
        s["change_pct"] = round((s["expenses"] - p["expenses"]) / p["expenses"] * 100) if p["expenses"] > 0 else None
        # Cash flow only means something if the customer has recognised cash-in (e.g. wallet funding).
        s["net_cash_flow"] = round(s["income"] - s["expenses"] - s["transfers"] - s["savings"], 2) if s["income"] > 0 else None
        currencies[cur] = s
    budget = None
    try:
        monthly = get_budget(conn, user_id)
    except Exception:
        monthly = None
    if monthly:
        spent = round(sum(i["amt"] for i in mtd_ngn if i["kind"] == "spend"), 2)
        dim = calendar.monthrange(now.year, now.month)[1]
        budget = {"monthly": monthly, "spent": spent, "pct": round(spent / monthly * 100), "days_left": max(0, dim - now.day),
                  "projected": round(spent / max(1, now.day) * dim, 2)}
    report = {"product": "Net365 Money Intelligence", "period": period, "start_date": a.isoformat(), "end_date": b.isoformat(),
              "label": _label(period, a, b), "completed_period": bool(completed), "generated_at": now.isoformat(),
              "data_scope": DATA_SCOPE, "currencies": currencies, "budget": budget,
              "upcoming_scheduled_payments": _upcoming(conn, user_id, now),
              "notes": ["Amounts are grouped by currency. No cross-currency totals are calculated.",
                        "Wallet funding is shown as cash-in, not earned income."]}
    report["insights"] = make_insights(report, now)
    return report


# --------------------------------------------------------------------------- insights
def make_insights(report, now=None):
    """Short factual observations, most useful first. Each is {severity, text}."""
    out = []
    b = report.get("budget")
    if b:
        if b["pct"] >= 100:
            out.append(("warning", f"You have passed your monthly budget ({_money('NGN', b['spent'])} of {_money('NGN', b['monthly'])})."))
        elif b["pct"] >= 80:
            out.append(("warning", f"You have used {b['pct']}% of your {_money('NGN', b['monthly'])} budget with {b['days_left']} days left."))
        elif b["projected"] > b["monthly"] and b["days_left"] <= 21 and b["spent"] > 0:
            out.append(("info", f"At this pace you will spend about {_money('NGN', b['projected'])} this month, above your {_money('NGN', b['monthly'])} budget."))
    soon = [u for u in report.get("upcoming_scheduled_payments", [])][:2]
    if soon:
        out.append(("info", "Coming up: " + "; ".join(f"{u['name']} ({_money(u['currency'], u['amount'])}) on {u['due_label']}" for u in soon) + "."))
    for cur, s in report["currencies"].items():
        tag = "" if cur == "NGN" else f" in {cur}"
        if not s["transaction_count"]:
            if cur == "NGN" and len(report["currencies"]) == 1:
                out.append(("info", "No completed Net365 payments in this period."))
            continue
        if s["change_pct"] is not None and abs(s["change_pct"]) >= 20 and s["previous_expenses"] >= (1000 if cur == "NGN" else 5):
            word = "up" if s["change_pct"] > 0 else "down"
            out.append(("warning" if s["change_pct"] > 0 else "info",
                        f"Spending{tag} is {word} {abs(s['change_pct'])}% on the previous period ({_money(cur, s['expenses'])} vs {_money(cur, s['previous_expenses'])})."))
        t = s["top_number"]
        if t and t["count"] >= 3:
            out.append(("info", f"You topped up {t['label']} {t['count']} times. A schedule would save you the effort: open Schedules."))
        c = s["categories"]
        if c and len(c) > 1 and c[0]["pct"] >= 50:
            out.append(("info", f"{c[0]['name']}{tag} is {c[0]['pct']}% of your spending."))
        elif c and len(c) == 1:
            out.append(("info", f"All your spending{tag} was on {c[0]['name']} ({_money(cur, c[0]['amount'])})."))
        if s["fees"] > 0:
            out.append(("info", f"Net365 fees{tag}: {_money(cur, s['fees'])} across {s['spend_count']} payments."))
        if s["net_cash_flow"] is not None and s["net_cash_flow"] < 0:
            out.append(("warning", f"Recorded outflows{tag} exceeded recognised cash-in by {_money(cur, abs(s['net_cash_flow']))}."))
    return [{"severity": sev, "text": txt} for sev, txt in out]


# --------------------------------------------------------------------------- chat / email shapes
def chat_summary(report):
    """The compact NGN-first shape the Telegram/WhatsApp bots and the Mini App draw from."""
    ngn = report["currencies"].get("NGN") or {"expenses": 0, "spend_count": 0, "fees": 0, "previous_expenses": 0, "change_pct": None, "categories": [], "top_number": None}
    other = sum(s["transaction_count"] for c, s in report["currencies"].items() if c != "NGN")
    bd = report.get("budget") or {}
    return {"label": report["label"], "month": report["label"], "period": report["period"], "start_date": report["start_date"], "end_date": report["end_date"],
            "total": ngn["expenses"], "count": ngn["spend_count"], "fees": ngn["fees"], "last_month_total": ngn["previous_expenses"],
            "change_pct": ngn["change_pct"], "by_category": [{"name": c["name"], "amount": c["amount"], "count": c["count"]} for c in ngn["categories"]],
            "top_number": ngn["top_number"], "abroad_count": other, "budget": bd.get("monthly"), "budget_pct": bd.get("pct"), "days_left": bd.get("days_left"),
            "tips": [i["text"] for i in report["insights"]][:3],
            "upcoming": [{"name": u["name"], "amount": u["amount"], "due_label": u["due_label"]} for u in report["upcoming_scheduled_payments"][:3]]}


def render_text(report):
    """Plain-text email body."""
    lines = [f"Net365 Money Intelligence: {report['period'].title()} report", f"Period: {report['label']}", ""]
    for cur, s in report["currencies"].items():
        if not s["transaction_count"]:
            continue
        lines += [f"{cur}", f"  Spent: {_money(cur, s['expenses'])} on {s['spend_count']} payments"]
        if s["change_pct"] is not None:
            lines.append(f"  Previous period: {_money(cur, s['previous_expenses'])} ({'+' if s['change_pct'] >= 0 else ''}{s['change_pct']}%)")
        if s["fees"]:
            lines.append(f"  Fees: {_money(cur, s['fees'])}")
        if s["income"]:
            lines.append(f"  Cash-in (wallet funding): {_money(cur, s['income'])}")
        for c in s["categories"][:6]:
            lines.append(f"  - {c['name']}: {_money(cur, c['amount'])} ({c['pct']}%)")
        lines.append("")
    if report.get("budget"):
        b = report["budget"]
        lines += [f"Monthly budget: {_money('NGN', b['spent'])} of {_money('NGN', b['monthly'])} used ({b['pct']}%), {b['days_left']} days left", ""]
    if report["insights"]:
        lines.append("Insights")
        lines += [f"- {i['text']}" for i in report["insights"]]
        lines.append("")
    lines += [report["data_scope"], "", "You can change or stop these reports any time: message the Net365 bot and say 'reports'."]
    return "\n".join(lines)


# --------------------------------------------------------------------------- questions
_CAT_WORDS = (("Airtime abroad", r"abroad|international|foreign|overseas"), ("Airtime", r"airtime|recharge|top ?up"),
              ("Electricity", r"electric|light|nepa|power|disco|meter"), ("Cable TV", r"\btv\b|dstv|gotv|cable|startimes"),
              ("Gift cards", r"gift"), ("Business payments", r"business|merchant"), ("Bills", r"\bbills?\b"))


def _ask_range(q, now):
    t, today = q.lower(), now.date()
    mon = today - timedelta(days=today.weekday())
    if "last month" in t:
        b = today.replace(day=1) - timedelta(days=1)
        return b.replace(day=1), b, "last month"
    if "last week" in t:
        a = mon - timedelta(days=7)
        return a, a + timedelta(days=6), "last week"
    if "this week" in t:
        return mon, today, "this week"
    if "yesterday" in t:
        y = today - timedelta(days=1)
        return y, y, "yesterday"
    if "today" in t:
        return today, today, "today"
    m = re.search(r"last (\d{1,3}) days", t)
    if m and 1 <= int(m.group(1)) <= 365:
        n = int(m.group(1))
        return today - timedelta(days=n - 1), today, f"in the last {n} days"
    return today.replace(day=1), today, "this month"


def answer_question(conn, user_id, question, now=None):
    now = (now or datetime.now(LAGOS)).astimezone(LAGOS)
    q = question.lower()
    if re.search(r"\b(invest|loan|borrow|crypto|bitcoin|stocks?|shares|forex|should i buy)\b", q):
        return "I can't give investment or credit advice. I can tell you what you have spent through Net365, your budget and your upcoming payments."
    a, b, words = _ask_range(q, now)
    rep = build_report(conn, user_id, "custom", a.isoformat(), b.isoformat(), now=now)
    cur_map = rep["currencies"]
    nothing = all(not s["transaction_count"] for s in cur_map.values())
    if re.search(r"budget|left|remaining|afford", q):
        bd = rep.get("budget")
        if not bd:
            return "You have not set a monthly budget yet. Say 'budget 30000' to set one."
        return (f"You have used {_money('NGN', bd['spent'])} of your {_money('NGN', bd['monthly'])} budget ({bd['pct']}%). "
                f"{_money('NGN', max(0, bd['monthly'] - bd['spent']))} is left with {bd['days_left']} days to go.")
    if re.search(r"upcoming|due|next bill|scheduled|coming up", q):
        up = rep["upcoming_scheduled_payments"]
        return ("Coming up: " + "; ".join(f"{u['name']} ({_money(u['currency'], u['amount'])}) on {u['due_label']}" for u in up[:5]) + ".") if up else "You have no scheduled payments in the next 14 days."
    if nothing:
        return f"I found no completed Net365 payments {words}."
    ngn = cur_map.get("NGN")
    if re.search(r"which (number|phone)|\bwho\b|top(ped)? up the most|most (often|topped)", q):
        t = ngn and ngn["top_number"]
        return f"You topped up {t['label']} the most {words}: {t['count']} times ({_money('NGN', t['amount'])})." if t else f"No airtime number stood out {words}."
    cat = next((name for name, rx in _CAT_WORDS if re.search(rx, q)), None)
    if cat:
        parts = []
        for cur, s in cur_map.items():
            hit = next((c for c in s["categories"] if c["name"] == cat), None)
            if hit:
                parts.append(f"{_money(cur, hit['amount'])} on {cat} ({hit['count']} payment{'s' if hit['count'] != 1 else ''})")
        return (f"You spent {' and '.join(parts)} {words}.") if parts else f"You had no {cat} payments {words}."
    if re.search(r"fee|charge", q):
        return " ".join(f"Net365 fees {words}: {_money(c, s['fees'])} across {s['spend_count']} payments." for c, s in cur_map.items() if s["spend_count"])
    if re.search(r"compare|more than|less than|\bvs\b|versus|increase|decrease|\bup\b|\bdown\b", q):
        if ngn and ngn["change_pct"] is not None:
            return f"{words.capitalize()} you spent {_money('NGN', ngn['expenses'])}, against {_money('NGN', ngn['previous_expenses'])} in the period before ({'+' if ngn['change_pct'] >= 0 else ''}{ngn['change_pct']}%)."
        return "There is not enough earlier data to compare with yet."
    if re.search(r"how many|count|number of", q):
        return " ".join(f"{s['spend_count']} payments in {c} {words}." for c, s in cur_map.items() if s["spend_count"])
    if re.search(r"biggest|largest|most|top|highest", q):
        out = []
        for cur, s in cur_map.items():
            if s["categories"]:
                out.append(f"{cur}: biggest category was {s['categories'][0]['name']} ({_money(cur, s['categories'][0]['amount'])}, {s['categories'][0]['pct']}%)." + (f" Largest single payment: {_money(cur, s['largest']['amount'])} on {s['largest']['category']}." if s["largest"] else ""))
        return " ".join(out)
    if re.search(r"spen[dt]|expense|total|how much|paid", q):
        out = []
        for cur, s in cur_map.items():
            if s["spend_count"]:
                top = s["categories"][0] if s["categories"] else None
                out.append(f"{words.capitalize()} you spent {_money(cur, s['expenses'])} in {cur} on {s['spend_count']} payments." + (f" Most of it went on {top['name']}." if top else ""))
        return " ".join(out)
    return "I can answer questions about what you spent, by category or period, your budget, fees, repeat numbers and upcoming scheduled payments. Try: 'How much did I spend on electricity last month?'"


# --------------------------------------------------------------------------- scheduled delivery
def _user_email(conn, user_id):
    row = conn.execute("SELECT email, email_verified FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row or not row["email"]:
        return None, False
    return row["email"], bool(row["email_verified"])


def run_due_reports(db_module, email_sender=None, chat_sender=None, now=None):
    """Send every report that is due. Safe to call repeatedly: each (customer, period, end date) is delivered once, with up to 3 tries.
    Daily = yesterday, weekly = the week that just ended (sent Mondays), monthly = last month (sent on the 1st), from 08:00 Lagos."""
    conn = db_module.get_db_connection()
    sent = 0
    try:
        _ensure_schema(conn)
        now = (now or datetime.now(LAGOS)).astimezone(LAGOS)
        if now.hour < 8:
            return 0
        for pref in conn.execute("SELECT * FROM financial_report_preferences WHERE enabled = 1").fetchall():
            p = dict(pref)
            period = p["period"]
            if not (period == "daily" or (period == "weekly" and now.weekday() == 0) or (period == "monthly" and now.day == 1)):
                continue
            try:
                report = build_report(conn, p["user_id"], period, completed=True, now=now)
                run = conn.execute("SELECT id, delivered, attempts FROM financial_report_runs WHERE user_id = ? AND period = ? "
                                   "AND end_date = ? AND scheduled = 1 LIMIT 1", (p["user_id"], period, report["end_date"])).fetchone()
                if run and (run["delivered"] or run["attempts"] >= 3):
                    continue
                channel, ok, tried = p["channel"], False, False
                empty = all(not s["spend_count"] for s in report["currencies"].values())
                if empty:
                    ok = True  # a silent period is not worth a message
                else:
                    if channel in ("chat", "both") and chat_sender:
                        tried = True
                        try:
                            ok = bool(chat_sender(p["user_id"], chat_summary(report))) or ok
                        except Exception:
                            log.exception("report chat delivery failed")
                    if channel in ("email", "both") and email_sender:
                        email, verified = _user_email(conn, p["user_id"])
                        if email and verified:
                            tried = True
                            try:
                                ok = bool(email_sender(email, f"Your Net365 {period} money report ({report['label']})", render_text(report))) or ok
                            except Exception:
                                log.exception("report email delivery failed")
                    if not tried:
                        ok = False
                blob = json.dumps(report, ensure_ascii=False)
                if run:
                    conn.execute("UPDATE financial_report_runs SET attempts = attempts + 1, delivered = ?, report_json = ? WHERE id = ?", (1 if ok else 0, blob, run["id"]))
                else:
                    conn.execute("INSERT INTO financial_report_runs (user_id, period, start_date, end_date, currency, report_json, scheduled, delivered, attempts) "
                                 "VALUES (?,?,?,?,?,?,1,?,1)", (p["user_id"], period, report["start_date"], report["end_date"], ",".join(report["currencies"]), blob, 1 if ok else 0))
                try:
                    conn.commit()
                except Exception:
                    pass
                if ok and not empty:
                    sent += 1
            except Exception:
                log.exception("scheduled report failed for user %s", p.get("user_id"))
        return sent
    finally:
        conn.close()


class MoneyReportRunner:
    """Checks for due reports every few minutes. Start in ONE process only (NET365_SCHEDULER_ENABLED=true)."""
    _thread = None

    @classmethod
    def start(cls, db_module, email_sender=None, chat_sender=None, interval=900):
        if cls._thread and cls._thread.is_alive():
            return

        def loop():
            time.sleep(60)
            while True:
                try:
                    n = run_due_reports(db_module, email_sender, chat_sender)
                    if n:
                        log.info("Money Intelligence: %s report(s) delivered", n)
                except Exception:
                    log.exception("Money Intelligence runner error")
                time.sleep(max(60, interval))

        cls._thread = threading.Thread(target=loop, name="money-report-runner", daemon=True)
        cls._thread.start()
        log.info("Money Intelligence report runner started (every %ss)", interval)


# --------------------------------------------------------------------------- web API
def init_money_intelligence(app, db_module, login_required, email_sender=None, chat_sender=None):
    bp = Blueprint("net365_money_intelligence", __name__)

    def connection():
        c = db_module.get_db_connection()
        _ensure_schema(c)
        return c

    @bp.get("/api/money-intelligence/preferences")
    @login_required
    def get_preferences():
        conn = connection()
        try:
            row = conn.execute("SELECT period, channel, email_enabled, enabled FROM financial_report_preferences WHERE user_id = ?", (g.current_user_id,)).fetchone()
            return jsonify({"success": True, "preferences": dict(row) if row else {"period": "weekly", "channel": "chat", "email_enabled": 0, "enabled": 0}})
        finally:
            conn.close()

    @bp.put("/api/money-intelligence/preferences")
    @login_required
    def put_preferences():
        data = request.get_json(silent=True) or {}
        period, channel = data.get("period", "weekly"), data.get("channel", "chat")
        if period not in ("daily", "weekly", "monthly"):
            return jsonify({"success": False, "error": "period must be daily, weekly or monthly"}), 400
        if channel not in ("chat", "email", "both"):
            return jsonify({"success": False, "error": "channel must be chat, email or both"}), 400
        conn = connection()
        try:
            email, verified = _user_email(conn, g.current_user_id)
            # Reports only ever go to the verified email on the account, never to an address typed into the request.
            if channel in ("email", "both") and not (email and verified):
                return jsonify({"success": False, "error": "Verify your account email first to receive reports by email."}), 400
            conn.execute("INSERT INTO financial_report_preferences (user_id, period, channel, email_enabled, email, enabled, updated_at) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP) "
                         "ON CONFLICT(user_id) DO UPDATE SET period=excluded.period, channel=excluded.channel, email_enabled=excluded.email_enabled, "
                         "email=excluded.email, enabled=excluded.enabled, updated_at=CURRENT_TIMESTAMP",
                         (g.current_user_id, period, channel, 1 if channel in ("email", "both") else 0, email if channel in ("email", "both") else None, 1 if data.get("enabled", True) else 0))
            try:
                conn.commit()
            except Exception:
                pass
            return jsonify({"success": True, "message": "Report preferences saved."})
        finally:
            conn.close()

    @bp.post("/api/money-intelligence/report")
    @login_required
    def generate_report():
        data = request.get_json(silent=True) or {}
        conn = connection()
        try:
            n = conn.execute("SELECT COUNT(*) FROM financial_report_runs WHERE user_id = ? AND scheduled = 0 AND created_at >= datetime('now','-1 day')", (g.current_user_id,)).fetchone()[0]
            if n >= MAX_RUNS_PER_DAY:
                return jsonify({"success": False, "error": "Report limit reached for today. Try again tomorrow."}), 429
            report = build_report(conn, g.current_user_id, data.get("period", "weekly"), data.get("start"), data.get("end"))
            cur = conn.execute("INSERT INTO financial_report_runs (user_id, period, start_date, end_date, currency, report_json, scheduled) VALUES (?,?,?,?,?,?,0)",
                               (g.current_user_id, report["period"], report["start_date"], report["end_date"], ",".join(report["currencies"]), json.dumps(report, ensure_ascii=False)))
            report["report_id"] = cur.lastrowid
            return jsonify({"success": True, "report": report})
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400
        except Exception:
            log.exception("Money Intelligence report failed")
            return jsonify({"success": False, "error": "Unable to generate report."}), 500
        finally:
            conn.close()

    @bp.get("/api/money-intelligence/reports")
    @login_required
    def report_history():
        conn = connection()
        try:
            rows = conn.execute("SELECT id, period, start_date, end_date, currency, created_at FROM financial_report_runs WHERE user_id = ? ORDER BY id DESC LIMIT 30", (g.current_user_id,)).fetchall()
            return jsonify({"success": True, "reports": [dict(r) for r in rows]})
        finally:
            conn.close()

    @bp.get("/api/money-intelligence/reports/<int:report_id>")
    @login_required
    def report_detail(report_id):
        conn = connection()
        try:
            row = conn.execute("SELECT report_json FROM financial_report_runs WHERE id = ? AND user_id = ?", (report_id, g.current_user_id)).fetchone()
            if not row:
                return jsonify({"success": False, "error": "Report not found"}), 404
            return jsonify({"success": True, "report": json.loads(row["report_json"])})
        finally:
            conn.close()

    @bp.route("/api/money-intelligence/budget", methods=["GET", "PUT"])
    @login_required
    def budget_route():
        conn = connection()
        try:
            if request.method == "PUT":
                try:
                    return jsonify({"success": True, "budget": set_budget(conn, g.current_user_id, (request.get_json(silent=True) or {}).get("amount"))})
                except (ValueError, TypeError) as e:
                    return jsonify({"success": False, "error": str(e)}), 400
            return jsonify({"success": True, "budget": get_budget(conn, g.current_user_id)})
        finally:
            conn.close()

    @bp.post("/api/money-intelligence/ask")
    @login_required
    def ask_advisor():
        question = ((request.get_json(silent=True) or {}).get("question") or "").strip()
        if not question or len(question) > 500:
            return jsonify({"success": False, "error": "Enter a question of up to 500 characters."}), 400
        conn = connection()
        try:
            return jsonify({"success": True, "answer": answer_question(conn, g.current_user_id, question), "data_scope": DATA_SCOPE})
        finally:
            conn.close()

    app.register_blueprint(bp)
    log.info("Net365 Money Intelligence routes registered")
    return bp

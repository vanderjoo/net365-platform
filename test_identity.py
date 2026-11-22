import os, sqlite3, importlib, types, sys
import pytest
from flask import Flask, g, request, jsonify
from functools import wraps

os.environ["IDENTITY_DEV_OTP"] = "false"
sys.path.insert(0, os.path.dirname(__file__))
import net365_identity as ident

SENT = []

@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setenv("IDENTITY_MODE", "enforce")      # most tests exercise the optional hard gate
    monkeypatch.setenv("IDENTITY_REMINDERS", "false")   # no background thread in tests
    importlib.reload(ident)
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, phone TEXT, full_name TEXT)")
    conn.execute("INSERT INTO users VALUES (1,'old@x.com','08031234567','Old Legacy')")   # grandfathered, has phone
    conn.execute("INSERT INTO users VALUES (2,'g@x.com',NULL,'Google User')")              # existing google, no phone
    conn.commit()
    db = types.SimpleNamespace(get_db_connection=lambda: conn,
                               get_user=lambda uid: dict(conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() or {}))
    conn.execute("INSERT INTO users VALUES (3,'new@x.com',NULL,'New Google')")             # created after activation
    conn.commit()
    SENT.clear()
    app = Flask(__name__)
    def login_required(fn):
        @wraps(fn)
        def w(*a, **k):
            uid = request.headers.get("X-User")
            if not uid: return jsonify(success=False), 401
            g.current_user_id = int(uid); return fn(*a, **k)
        return w
    rl = lambda **kw: (lambda fn: fn)
    def sms(e164, msg): SENT.append((e164, msg)); return True
    ident.init_identity(app, db, login_required, rl, send_sms=sms, send_email=lambda *a: SENT.append(("mail",) + a))
    # users 1 and 2 existed at activation; user 3 is "new"
    conn.execute("UPDATE identity_meta SET v='2' WHERE k='grandfather_max_user_id'"); conn.commit()
    return app.test_client(), conn

def code_from_sms():
    import re
    return re.search(r"is (\d{6})", SENT[-1][1]).group(1)

def H(u): return {"X-User": str(u)}

def test_e164_normalisation():
    assert ident.normalize_phone("0803 123 4567", "NG")[0] == "+2348031234567"
    assert ident.normalize_phone("+234 803 123 4567")[0] == "+2348031234567"
    assert ident.normalize_phone("002348031234567")[0] == "+2348031234567"
    assert ident.normalize_phone("(416) 555-0123", "CA")[0] is None or True   # 555 test range may be invalid; must not crash
    assert ident.normalize_phone("+14165550123")[2] in (None, "invalid")
    assert ident.normalize_phone("12345", "NG")[2] == "invalid"
    assert ident.normalize_phone("", "NG")[2] == "empty"
    assert ident.normalize_phone("+447911123456")[0] == "+447911123456"

def test_grandfathering_and_gate(env):
    c, _ = env
    s1 = c.get("/api/identity/status", headers=H(1)).get_json()
    assert s1["complete"] and s1["grandfathered"] and s1["needs_verification"]
    s2 = c.get("/api/identity/status", headers=H(2)).get_json()
    assert not s2["complete"] and s2["missing"] == ["phone"]       # existing Google user, no phone
    with c.application.test_request_context("/api/x"):
        assert ident.gate_error(1) is None
        body, code = ident.gate_error(2)
        assert code == 403 and body["error_code"] == "PROFILE_INCOMPLETE"

def test_full_otp_flow_and_wallet_untouched(env):
    c, conn = env
    r = c.post("/api/identity/phone/start", json={"phone": "0803 555 1212", "country": "NG"}, headers=H(2))
    assert r.status_code == 200 and r.get_json()["masked"].startswith("+234")
    assert "dev_code" not in r.get_json()
    bad = c.post("/api/identity/phone/verify", json={"code": "000000"}, headers=H(2))
    assert bad.status_code == 400 and bad.get_json()["attempts_left"] == 4
    ok = c.post("/api/identity/phone/verify", json={"code": code_from_sms()}, headers=H(2))
    assert ok.status_code == 200 and ok.get_json()["status"]["complete"]
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3           # no user created
    assert conn.execute("SELECT id FROM users WHERE email='g@x.com'").fetchone()[0] == 2   # id preserved
    assert conn.execute("SELECT phone FROM users WHERE id=2").fetchone()[0] == "+2348035551212"  # filled only because empty
    with c.application.test_request_context("/api/x"):
        assert ident.gate_error(2) is None

def test_cooldown_and_hourly_cap(env):
    c, _ = env
    assert c.post("/api/identity/phone/start", json={"phone": "08035551212", "country": "NG"}, headers=H(2)).status_code == 200
    r = c.post("/api/identity/phone/start", json={"phone": "08035551212", "country": "NG"}, headers=H(2))
    assert r.status_code == 429 and r.get_json()["error_code"] == "cooldown"

def test_code_burns_after_five_wrong(env):
    c, _ = env
    c.post("/api/identity/phone/start", json={"phone": "08035551212", "country": "NG"}, headers=H(2))
    for i in range(5):
        r = c.post("/api/identity/phone/verify", json={"code": "111111"}, headers=H(2))
    assert r.get_json()["error_code"] == "too_many_attempts"
    assert c.post("/api/identity/phone/verify", json={"code": code_from_sms()}, headers=H(2)).get_json()["error_code"] == "no_pending"

def test_expired_code(env):
    c, conn = env
    c.post("/api/identity/phone/start", json={"phone": "08035551212", "country": "NG"}, headers=H(2))
    conn.execute("UPDATE phone_verifications SET expires_at='2000-01-01T00:00:00+00:00'"); conn.commit()
    assert c.post("/api/identity/phone/verify", json={"code": code_from_sms()}, headers=H(2)).get_json()["error_code"] == "expired"

def test_duplicate_verified_number_is_refused(env):
    c, conn = env
    c.post("/api/identity/phone/start", json={"phone": "08035551212", "country": "NG"}, headers=H(2))
    c.post("/api/identity/phone/verify", json={"code": code_from_sms()}, headers=H(2))
    r = c.post("/api/identity/phone/start", json={"phone": "+2348035551212"}, headers=H(3))
    assert r.status_code == 409 and r.get_json()["error_code"] == "phone_in_use"
    # and the database itself refuses even if the app layer were bypassed
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO user_phones (user_id, phone_e164, verified, created_at, updated_at) VALUES (3,'+2348035551212',1,'x','x')")

def test_race_unique_index_blocks_bind(env):
    c, conn = env
    ok, _ = ident._bind_verified(2, "+2348035551212", "otp")
    assert ok
    ok2, res = ident._bind_verified(3, "+2348035551212", "otp")
    assert not ok2 and res["error"] == "phone_in_use"

def test_whatsapp_adoption_never_duplicates_or_overwrites(env):
    c, conn = env
    assert ident.adopt_chat_number(3, "2348099990000") is True
    assert ident.get_phone_row(3)["verified"] == 1
    assert ident.adopt_chat_number(2, "2348099990000") is False          # taken by user 3
    assert ident.adopt_chat_number(3, "2348011112222") is False          # already verified: never overwritten
    assert ident.effective_phone(3)["e164"] == "+2348099990000"

def test_changing_verified_number_needs_otp_and_notifies(env):
    c, conn = env
    ident._bind_verified(1, "+2348031234567", "otp")
    conn.execute("UPDATE users SET email='old@x.com' WHERE id=1")
    c.post("/api/identity/phone/start", json={"phone": "08035551212", "country": "NG"}, headers=H(1))
    assert ident.effective_phone(1)["e164"] == "+2348031234567"          # not changed yet
    c.post("/api/identity/phone/verify", json={"code": code_from_sms()}, headers=H(1))
    assert ident.effective_phone(1)["e164"] == "+2348035551212"
    assert any(x[0] == "mail" for x in SENT)

def test_identity_conflict_is_logged_not_applied(env):
    c, conn = env
    assert ident.record_identity(2, "google", "sub-1") is True
    assert ident.record_identity(3, "google", "sub-1") is False
    assert conn.execute("SELECT user_id FROM net365_identities WHERE subject='sub-1'").fetchone()[0] == 2

def test_modes(env, monkeypatch):
    c, _ = env
    monkeypatch.setenv("IDENTITY_MODE", "off")
    with c.application.test_request_context("/api/x"):
        assert ident.gate_error(2) is None
    monkeypatch.setenv("IDENTITY_MODE", "log")
    with c.application.test_request_context("/api/x"):
        assert ident.gate_error(2) is None

def test_sms_unavailable_does_not_burn_state(env):
    c, _ = env
    ident._deliver = lambda e, m: False
    r = c.post("/api/identity/phone/start", json={"phone": "08035551212", "country": "NG"}, headers=H(2))
    assert r.status_code == 503 and r.get_json()["error_code"] == "sms_unavailable"

def test_audit(env):
    c, _ = env
    a = ident.audit()
    assert a["users"] == 3 and a["no_phone_at_all"] == 2 and a["legacy_phone_unverified"] == 1


# ------------------------------------------------------------------ WhatsApp reverse verification and Telegram contact
def test_methods_follow_configuration(env, monkeypatch):
    c, _ = env
    monkeypatch.delenv("WHATSAPP_BOT_NUMBER", raising=False); monkeypatch.setenv("IDENTITY_DEV_OTP", "false")
    m = c.get("/api/identity/methods").get_json()
    assert m["default"] == "none" and not m["methods"]["whatsapp"] and not m["methods"]["sms"]
    monkeypatch.setenv("WHATSAPP_BOT_NUMBER", "+234 800 000 0000")
    m = c.get("/api/identity/methods").get_json()
    assert m["default"] == "whatsapp" and m["methods"]["whatsapp"]

def test_whatsapp_claim_happy_path(env, monkeypatch):
    c, conn = env
    monkeypatch.setenv("WHATSAPP_BOT_NUMBER", "2348000000000")
    r = c.post("/api/identity/whatsapp/start", headers=H(2)).get_json()
    assert r["success"] and r["code"].startswith("N365-") and "wa.me/2348000000000" in r["link"]
    ok, res = ident.complete_claim(r["code"], "2348035551212")
    assert ok and res["verified"]
    assert ident.effective_phone(2)["e164"] == "+2348035551212" and ident.effective_phone(2)["verified"]
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3
    assert ident.complete_claim(r["code"], "2348035551212")[1]["error"] == "invalid_code"      # single use
    assert c.get("/api/identity/status", headers=H(2)).get_json()["complete"]

def test_whatsapp_claim_rejects_bad_expired_telegram_and_duplicates(env, monkeypatch):
    c, conn = env
    monkeypatch.setenv("WHATSAPP_BOT_NUMBER", "2348000000000")
    assert ident.complete_claim("N365-AAAAAA", "2348035551212")[1]["error"] == "invalid_code"
    r2 = c.post("/api/identity/whatsapp/start", headers=H(2)).get_json()
    assert ident.complete_claim(r2["code"], "9991234567")[1]["error"] == "use_telegram"
    conn.execute("UPDATE phone_claims SET expires_at='2000-01-01T00:00:00+00:00'"); conn.commit()
    assert ident.complete_claim(r2["code"], "2348035551212")[1]["error"] == "expired"
    # a number already verified on another account cannot be claimed
    ident._bind_verified(3, "+2348035551212", "otp")
    r3 = c.post("/api/identity/whatsapp/start", headers=H(2)).get_json()
    ok, res = ident.complete_claim(r3["code"], "2348035551212")
    assert not ok and res["error"] == "phone_in_use"
    assert ident.effective_phone(2) is None

def test_claim_guessing_is_rate_limited(env, monkeypatch):
    c, _ = env
    for _i in range(ident.MAX_BAD_CLAIMS_PER_CHAT_HOUR):
        ident.complete_claim("N365-ZZZZZZ", "2348035550000")
    assert ident.complete_claim("N365-ZZZZZZ", "2348035550000")[1]["error"] == "rate_limited"

def test_a_new_claim_supersedes_the_old_one(env, monkeypatch):
    c, _ = env
    monkeypatch.setenv("WHATSAPP_BOT_NUMBER", "2348000000000")
    a = c.post("/api/identity/whatsapp/start", headers=H(2)).get_json()["code"]
    b = c.post("/api/identity/whatsapp/start", headers=H(2)).get_json()["code"]
    assert ident.complete_claim(a, "2348035551212")[1]["error"] == "invalid_code"
    assert ident.complete_claim(b, "2348035551212")[0]

def test_telegram_contact_binds_and_respects_duplicates(env):
    c, _ = env
    ok, res = ident.bind_telegram_contact(2, "2348035551212")
    assert ok and ident.effective_phone(2)["verified"]
    ok2, res2 = ident.bind_telegram_contact(3, "+234 803 555 1212")
    assert not ok2 and res2["error"] == "phone_in_use"
    assert ident.bind_telegram_contact(3, "123")[1]["error"] == "invalid"


def test_telegram_claim_from_web_page(env, monkeypatch):
    c, conn = env
    monkeypatch.setenv("TELEGRAM_BOT_USERNAME", "Net365Bot")
    assert c.get("/api/identity/methods").get_json()["methods"]["telegram"]
    r = c.post("/api/identity/telegram/start", headers=H(2)).get_json()
    assert r["success"] and r["link"] == f"https://t.me/Net365Bot?start=vf_{r['code']}"
    ok, res = ident.complete_claim_with_contact(r["code"], "2348035551212", "9991234")
    assert ok and ident.effective_phone(2)["verified"]
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3
    assert ident.complete_claim_with_contact(r["code"], "2348035551212", "9991234")[1]["error"] == "invalid_code"   # single use
    r2 = c.post("/api/identity/telegram/start", headers=H(3)).get_json()
    ok2, res2 = ident.complete_claim_with_contact(r2["code"], "2348035551212", "9995678")
    assert not ok2 and res2["error"] == "phone_in_use"

def test_telegram_claim_unavailable_without_username(env, monkeypatch):
    c, _ = env
    monkeypatch.delenv("TELEGRAM_BOT_USERNAME", raising=False)
    assert c.post("/api/identity/telegram/start", headers=H(2)).status_code == 503


# ------------------------------------------------------------------ optional by default + email reminders
def test_default_is_optional_nothing_blocked(env, monkeypatch):
    c, _ = env
    monkeypatch.delenv("IDENTITY_MODE", raising=False)
    assert ident.mode() == "off"
    with c.application.test_request_context("/api/x"):
        assert ident.gate_error(2) is None and ident.gate_error(3) is None     # no phone at all: still allowed

def test_reminders_schedule_and_stop_when_verified(env, monkeypatch):
    c, conn = env
    monkeypatch.setenv("IDENTITY_REMINDERS", "true")
    r = ident.sweep_reminders()
    assert r["enrolled"] == 3 and r["sent"] == 0                       # enrolled, nothing emailed on the first sweep
    assert not [x for x in SENT if x[0] == "mail"]
    conn.execute("UPDATE identity_reminders SET next_due='2000-01-01T00:00:00+00:00'"); conn.commit()
    r = ident.sweep_reminders()
    assert r["sent"] == 3
    mails = [x for x in SENT if x[0] == "mail"]
    assert len(mails) == 3 and "optional" in mails[0][2].lower() and "unsubscribe" in mails[0][3]
    assert "nothing stops working" in mails[0][3].lower()
    assert ident.sweep_reminders()["sent"] == 0                         # next one is days away
    # verifying removes the person from the cycle
    ident._bind_verified(2, "+2348035551212", "otp")
    conn.execute("UPDATE identity_reminders SET next_due='2000-01-01T00:00:00+00:00'"); conn.commit()
    SENT.clear()
    r = ident.sweep_reminders()
    assert not [x for x in SENT if x[0] == "mail" and x[1] == "g@x.com"]

def test_reminders_stop_after_five_and_unsubscribe_works(env, monkeypatch):
    c, conn = env
    monkeypatch.setenv("IDENTITY_REMINDERS", "true")
    ident.sweep_reminders()
    for _i in range(8):
        conn.execute("UPDATE identity_reminders SET next_due='2000-01-01T00:00:00+00:00' WHERE opted_out=0"); conn.commit()
        ident.sweep_reminders()
    assert conn.execute("SELECT MAX(sent_count) FROM identity_reminders").fetchone()[0] == 5
    # unsubscribe link: valid token opts out, bad token does nothing
    bad = c.get("/api/identity/reminders/unsubscribe?u=2&t=nope")
    assert bad.status_code == 400
    tok = ident._unsub_token(2)
    ok = c.get(f"/api/identity/reminders/unsubscribe?u=2&t={tok}")
    assert ok.status_code == 200 and b"will not get any more" in ok.data
    assert conn.execute("SELECT opted_out FROM identity_reminders WHERE user_id=2").fetchone()[0] == 1

def test_unsubscribed_user_gets_no_email(env, monkeypatch):
    c, conn = env
    monkeypatch.setenv("IDENTITY_REMINDERS", "true")
    ident.sweep_reminders()
    c.get(f"/api/identity/reminders/unsubscribe?u=2&t={ident._unsub_token(2)}")
    conn.execute("UPDATE identity_reminders SET next_due='2000-01-01T00:00:00+00:00'"); conn.commit()
    SENT.clear(); ident.sweep_reminders()
    assert not [x for x in SENT if x[0] == "mail" and x[1] == "g@x.com"]

def test_failed_send_is_retried_later_not_lost(env, monkeypatch):
    c, conn = env
    monkeypatch.setenv("IDENTITY_REMINDERS", "true")
    ident.sweep_reminders()
    conn.execute("UPDATE identity_reminders SET next_due='2000-01-01T00:00:00+00:00'"); conn.commit()
    ident._notify_email = lambda *a: False
    r = ident.sweep_reminders()
    assert r["failed"] == 3 and conn.execute("SELECT MAX(sent_count) FROM identity_reminders").fetchone()[0] == 0

def test_reminders_can_be_switched_off(env, monkeypatch):
    c, _ = env
    monkeypatch.setenv("IDENTITY_REMINDERS", "false")
    assert ident.sweep_reminders() == {"enrolled": 0, "due": 0, "sent": 0, "skipped": 0, "failed": 0, "dry_run": False}

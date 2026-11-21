"""net365_legal.py - versioned Terms of Service, proof of acceptance, and the endpoints every channel uses.

One source of truth: legal/terms_v<VERSION>.md (the document the lawyer and the business review).

  * GET  /terms, /terms/<version>        the full Terms as a readable, printable page (no login)
  * GET  /api/legal/terms/current        version, document fingerprint, link and one-screen summary
  * GET  /api/legal/status               (logged in) has this account accepted the current version?
  * POST /api/legal/accept               (logged in) record acceptance from the website or mobile app
  * POST /api/whatsapp/terms/status      (bot secret) has this chat accepted? returns the summary to show if not
  * POST /api/whatsapp/terms/accept      (bot secret) record acceptance from a WhatsApp or Telegram chat
  * GET  /api/admin/legal/acceptances    (admin) audit list of who accepted what, when and where

Proof of acceptance = who (account or chat), which version, a SHA-256 of the exact document text, channel, time, IP and
user agent. Acceptance is per version: when TERMS_VERSION changes, everyone is asked again.

Environment (all optional):
  TERMS_VERSION=1.1                  which legal/terms_v<version>.md is current
  TERMS_ENFORCE_SIGNUP=true          the register endpoint refuses accounts created without ticking the box
  TERMS_URL=https://.../terms        absolute link shown in chats (default: NET365_PUBLIC_URL + /terms)
"""
import hashlib
import html
import logging
import os
import re
import threading
from datetime import datetime, timezone

from flask import Blueprint, jsonify, make_response, request

logger = logging.getLogger(__name__)
legal_bp = Blueprint("legal", __name__)

_HERE = os.path.dirname(os.path.abspath(__file__))
_LEGAL_DIR = os.path.join(_HERE, "legal")
_ctx = {"db": None, "ready": False, "ip": lambda: request.remote_addr or "", "login": None, "admin": None, "bot": None}
_lock = threading.Lock()
_cache = {}

CHANNELS = ("web", "mobile", "telegram", "whatsapp", "google", "api")
_VER_RE = re.compile(r"^\d{1,3}\.\d{1,3}$")

# One screen for a chat. WhatsApp reply-button messages hold 1,024 characters including the link, so keep this short.
SUMMARY = (
    "*Before you start: Net365 Terms*\n\n"
    "Tap *Accept* to agree to the Net365 Terms of Service and Privacy Policy. In short:\n"
    "- Net365 is a payments and digital-services platform. Some services are delivered by third parties.\n"
    "- Net365 staff will *never* ask for your PIN, OTP or password in a chat.\n"
    "- We log activity and may automatically block suspicious access to keep your money safe.\n"
    "- Report any problem any time by replying *support*.\n\n"
    "Full Terms: {url}"
)


def current_version():
    v = os.getenv("TERMS_VERSION", "1.1").strip()
    return v if _VER_RE.match(v) else "1.1"


def _read(version):
    """(text, sha256, is_draft) for a version, cached by file modification time. None if the file does not exist."""
    if not _VER_RE.match(str(version)):
        return None
    path = os.path.join(_LEGAL_DIR, f"terms_v{version}.md")
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    hit = _cache.get(path)
    if hit and hit[0] == mtime:
        return hit[1]
    text = open(path, encoding="utf-8").read()
    val = (text, hashlib.sha256(text.encode("utf-8")).hexdigest(), "[●]" in text)
    _cache[path] = (mtime, val)
    return val


def terms_url():
    explicit = os.getenv("TERMS_URL", "").strip()
    if explicit:
        return explicit
    base = (os.getenv("NET365_PUBLIC_URL") or os.getenv("FRONTEND_URL") or "").strip().rstrip("/")
    return (base + "/terms") if base else "/terms"


def current():
    v = current_version()
    doc = _read(v)
    return {"version": v, "hash": doc[1] if doc else "", "draft": bool(doc and doc[2]), "available": bool(doc),
            "url": terms_url(), "summary": SUMMARY.format(url=terms_url())}


# ----------------------------------------------------------------------------------------------- storage
def _conn():
    return _ctx["db"].get_db_connection()


def ensure_schema():
    if _ctx["ready"]:
        return
    with _lock:
        if _ctx["ready"]:
            return
        c = _conn()
        c.execute("""CREATE TABLE IF NOT EXISTS terms_acceptances (
            id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT NOT NULL, user_id INTEGER, chat_id TEXT,
            channel TEXT NOT NULL, version TEXT NOT NULL, doc_hash TEXT NOT NULL, accepted_at TEXT NOT NULL,
            ip TEXT, user_agent TEXT, request_ref TEXT)""")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_terms_subject_version ON terms_acceptances(subject, version)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_terms_user ON terms_acceptances(user_id)")
        c.commit()
        _ctx["ready"] = True


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def has_accepted(subject, version=None):
    """subject is 'u:<user id>' for an account or 'c:<chat id>' for a chat."""
    ensure_schema()
    row = _conn().execute("SELECT 1 FROM terms_acceptances WHERE subject = ? AND version = ?",
                          (subject, version or current_version())).fetchone()
    return bool(row)


def record(subject, channel, ip="", ua="", ref="", version=None):
    """Store acceptance of the CURRENT version (idempotent). Returns True when stored or already stored."""
    ensure_schema()
    cur = current()
    version = version or cur["version"]
    if version != cur["version"] or not cur["available"]:
        return False
    channel = channel if channel in CHANNELS else "api"
    uid = int(subject[2:]) if subject.startswith("u:") and subject[2:].isdigit() else None
    cid = subject[2:] if subject.startswith("c:") else None
    c = _conn()
    c.execute("INSERT OR IGNORE INTO terms_acceptances (subject, user_id, chat_id, channel, version, doc_hash, accepted_at, ip, user_agent, request_ref) "
              "VALUES (?,?,?,?,?,?,?,?,?,?)",
              (subject, uid, cid, channel, version, cur["hash"], _now(), str(ip)[:64], str(ua)[:300], str(ref)[:80]))
    c.commit()
    return True


# ----------------------------------------------------------------------------------------------- signup helpers
def signup_terms_error(data):
    """Call at the top of the register endpoint. Returns (json body, status) to refuse, or None to continue."""
    if os.getenv("TERMS_ENFORCE_SIGNUP", "true").strip().lower() not in ("1", "true", "yes", "on"):
        return None
    cur = current()
    if not cur["available"]:
        logger.error("Terms file legal/terms_v%s.md is missing: signup is NOT blocked, fix the file", cur["version"])
        return None
    if not (data or {}).get("accept_terms"):
        return {"success": False, "error": "Please read and accept the Terms to create an account.", "error_code": "TERMS_REQUIRED",
                "terms_version": cur["version"], "terms_url": cur["url"]}, 400
    seen = str((data or {}).get("terms_version") or "")
    if seen and seen != cur["version"]:
        return {"success": False, "error": "Our Terms were just updated. Please review them and accept again.",
                "error_code": "TERMS_CHANGED", "terms_version": cur["version"], "terms_url": cur["url"]}, 409
    return None


def record_signup_acceptance(user_id, data, ip="", ua=""):
    """Call right after the account is created. Never raises."""
    try:
        if (data or {}).get("accept_terms") and user_id:
            channel = str((data or {}).get("channel") or "web").lower()
            record(f"u:{int(user_id)}", channel if channel in CHANNELS else "web", ip, ua, "signup")
    except Exception:
        logger.exception("could not record Terms acceptance for new user %s", user_id)


# ----------------------------------------------------------------------------------------------- page rendering
def _inline(t):
    t = html.escape(t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"(https?://[^\s<)]+)", r'<a href="\1" rel="noopener">\1</a>', t)
    return t


def render_markdown(md, show_review_box=False):
    out, listing, toc = [], False, []

    def close():
        nonlocal listing
        if listing:
            out.append("</ul>")
            listing = False

    skip_quote = False
    for raw in md.split("\n"):
        line = raw.rstrip()
        if line.startswith(">"):
            body = line.lstrip("> ").strip()
            if body.startswith("**FOR THE REVIEWERS") and not show_review_box:
                skip_quote = True
                continue
            if skip_quote:
                continue
            close()
            out.append(f'<blockquote>{_inline(body)}</blockquote>')
            continue
        skip_quote = False
        if not line.strip():
            close()
            continue
        if line.startswith("---"):
            close()
            out.append("<hr>")
            continue
        m = re.match(r"^(#{1,3}) (.+)$", line)
        if m:
            close()
            level, text = len(m.group(1)), m.group(2)
            sec = re.match(r"^(\d+)\. (.+)$", text)
            if sec:
                toc.append((sec.group(1), sec.group(2)))
                out.append(f'<h2 id="s{sec.group(1)}">{_inline(text)}</h2>')
            else:
                out.append(f"<h{level}>{_inline(text)}</h{level}>")
            continue
        if line.startswith("- "):
            if not listing:
                out.append("<ul>")
                listing = True
            out.append(f"<li>{_inline(line[2:])}</li>")
            continue
        close()
        out.append(f"<p>{_inline(line)}</p>")
    close()
    return "\n".join(out), toc


_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Net365 Terms and Conditions of Service v{version}</title>
<style>
:root{{--bg:#fff;--fg:#1e293b;--mut:#64748b;--line:#e2e8f0;--acc:#E53935;--card:#f8fafc}}
@media (prefers-color-scheme:dark){{:root{{--bg:#121214;--fg:#e8e8ec;--mut:#9a9aa6;--line:#2a2a30;--card:#1c1c20}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.65 -apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:780px;margin:0 auto;padding:20px 18px 80px}}
.bar{{height:4px;border-radius:2px;background:linear-gradient(90deg,#E53935,#FF6D00);margin-bottom:22px}}
h1{{font-size:26px;margin:0 0 4px}}h2{{font-size:19px;margin:34px 0 8px;padding-top:6px;border-top:1px solid var(--line)}}
p,li{{margin:8px 0}}blockquote{{margin:12px 0;padding:10px 14px;background:var(--card);border-left:3px solid var(--acc);border-radius:6px}}
.draft{{background:#fff4e5;color:#7a4a00;border:1px solid #f5c77e;padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:14px}}
nav.toc{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin:18px 0;font-size:14px;columns:2 220px}}
nav.toc a{{display:block;color:var(--fg);text-decoration:none;padding:2px 0}}nav.toc a:hover{{color:var(--acc)}}
a{{color:var(--acc)}}code{{background:var(--card);padding:1px 5px;border-radius:4px}}hr{{border:0;border-top:1px solid var(--line);margin:22px 0}}
.meta{{color:var(--mut);font-size:13px}}
@media print{{nav.toc,.noprint{{display:none}}h2{{page-break-after:avoid}}body{{font-size:12px}}}}
</style></head><body><div class="wrap"><div class="bar"></div>
{draft}<p class="meta">Version {version} &middot; Document fingerprint (SHA-256): <code>{short}</code> &middot; <a class="noprint" href="#" onclick="window.print();return false">Print or save as PDF</a></p>
<nav class="toc"><strong>Contents</strong>{toc}</nav>
{body}</div></body></html>"""


def render_page(version, review=False):
    doc = _read(version)
    if not doc:
        return None
    body, toc = render_markdown(doc[0], show_review_box=review)
    toc_html = "".join(f'<a href="#s{n}">{n}. {html.escape(t.title())}</a>' for n, t in toc)
    draft = ('<div class="draft"><strong>Draft.</strong> This version is still being reviewed and is not yet in force.</div>' if doc[2] else "")
    return _PAGE.format(version=html.escape(version), short=doc[1][:16], toc=toc_html, body=body, draft=draft)


def _html_response(markup, status=200):
    resp = make_response(markup, status)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


# ----------------------------------------------------------------------------------------------- init + routes
def init_legal(app, db_module, login_required, admin_required, bot_required, get_client_ip):
    _ctx.update(db=db_module, login=login_required, admin=admin_required, bot=bot_required, ip=get_client_ip)
    try:
        ensure_schema()
    except Exception as e:
        logger.warning("terms table not ready: %s", e)
    cur = current()
    if not cur["available"]:
        logger.error("Terms file legal/terms_v%s.md was not found next to net365_legal.py: sign-up will not show Terms.", cur["version"])
    elif cur["draft"]:
        logger.warning("Terms v%s still contains [●] placeholders: it is shown as a DRAFT until they are filled in.", cur["version"])

    @legal_bp.route("/terms", methods=["GET"])
    def terms_current_page():
        page = render_page(current_version(), review=request.args.get("review") == "1" and bool(request.headers.get("X-Admin-Secret")))
        return _html_response(page) if page else (jsonify({"success": False, "error": "Terms not available"}), 404)

    @legal_bp.route("/terms/<version>", methods=["GET"])
    def terms_version_page(version):
        page = render_page(version)
        return _html_response(page) if page else (jsonify({"success": False, "error": "Unknown version"}), 404)

    @legal_bp.route("/api/legal/terms/current", methods=["GET"])
    def terms_current_api():
        return jsonify({"success": True, **current()})

    @legal_bp.route("/api/legal/status", methods=["GET"])
    @login_required
    def legal_status():
        from flask import g
        cur = current()
        ok = has_accepted(f"u:{g.current_user_id}") if cur["available"] else True
        return jsonify({"success": True, "accepted": ok, "version": cur["version"], "url": cur["url"], "draft": cur["draft"]})

    @legal_bp.route("/api/legal/accept", methods=["POST"])
    @login_required
    def legal_accept():
        from flask import g
        d = request.get_json(silent=True) or {}
        cur = current()
        if str(d.get("version") or cur["version"]) != cur["version"]:
            return jsonify({"success": False, "error": "These Terms were updated. Please review the new version.", "error_code": "TERMS_CHANGED",
                            "version": cur["version"]}), 409
        channel = str(d.get("channel") or "web").lower()
        ok = record(f"u:{g.current_user_id}", channel if channel in ("web", "mobile", "google") else "web",
                    get_client_ip(), request.headers.get("User-Agent", ""), "gate")
        return jsonify({"success": bool(ok), "version": cur["version"]}), (200 if ok else 503)

    @legal_bp.route("/api/whatsapp/terms/status", methods=["POST"])
    @bot_required
    def bot_terms_status():
        wa = re.sub(r"\D", "", str((request.get_json(silent=True) or {}).get("wa") or ""))
        if not re.match(r"^\d{8,15}$", wa):
            return jsonify({"success": False, "error": "bad_number"}), 400
        cur = current()
        if not cur["available"]:      # a missing file must never lock every chat out
            return jsonify({"success": True, "accepted": True, "version": cur["version"], "note": "terms_file_missing"})
        ok = has_accepted(f"c:{wa}")
        out = {"success": True, "accepted": ok, "version": cur["version"], "url": cur["url"]}
        if not ok:
            out["summary"] = cur["summary"]
        return jsonify(out)

    @legal_bp.route("/api/whatsapp/terms/accept", methods=["POST"])
    @bot_required
    def bot_terms_accept():
        d = request.get_json(silent=True) or {}
        wa = re.sub(r"\D", "", str(d.get("wa") or ""))
        if not re.match(r"^\d{8,15}$", wa):
            return jsonify({"success": False, "error": "bad_number"}), 400
        cur = current()
        if str(d.get("version") or cur["version"]) != cur["version"]:
            return jsonify({"success": False, "error": "terms_changed", "version": cur["version"]}), 409
        channel = "telegram" if wa.startswith("999") else "whatsapp"
        ok = record(f"c:{wa}", channel, "", "bot", str(d.get("ref") or ""))
        return jsonify({"success": bool(ok), "version": cur["version"]}), (200 if ok else 503)

    @legal_bp.route("/api/admin/legal/acceptances", methods=["GET"])
    @admin_required
    def admin_acceptances():
        ensure_schema()
        limit = max(1, min(500, request.args.get("limit", 100, type=int)))
        rows = _conn().execute(
            "SELECT id, subject, channel, version, substr(doc_hash,1,12) AS doc_hash, accepted_at, ip, request_ref FROM terms_acceptances "
            "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        by = _conn().execute("SELECT channel, COUNT(*) FROM terms_acceptances WHERE version = ? GROUP BY channel", (current_version(),)).fetchall()
        mask = lambda s: (s[:2] + "…" + s[-3:]) if s.startswith("c:") and len(s) > 8 else s
        return jsonify({"success": True, "current": {k: v for k, v in current().items() if k != "summary"},
                        "accepted_by_channel": {r[0]: r[1] for r in by},
                        "rows": [{**dict(zip(("id", "subject", "channel", "version", "doc_hash", "accepted_at", "ip", "ref"), tuple(r))),
                                  "subject": mask(r[1])} for r in rows]})

    app.register_blueprint(legal_bp)
    logger.info("Terms module ready: v%s (%s)", cur["version"], "DRAFT" if cur["draft"] else "final")

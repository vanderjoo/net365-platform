/* NET365 Terms client: shared by the website (index.html) and the mobile app (mobile.html). No dependencies.
 *   Net365Terms.load()          -> fetches the current version (also sets window.__net365TermsVersion)
 *   Net365Terms.gate(channel)   -> call after a user is signed in. If they have not accepted the current Terms,
 *                                  shows a screen they cannot dismiss until they accept (or decline and sign out).
 * Fails open on network errors: a hiccup in this check never locks a customer out of their account. */
(function () {
  'use strict';
  var S = { info: null, loading: null, shown: false };

  function api(path, opts) {
    var o = Object.assign({ credentials: 'include', headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' } }, opts || {});
    return fetch(path, o).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, status: r.status, data: d }; });
    });
  }

  function load() {
    if (S.loading) return S.loading;
    S.loading = api('/api/legal/terms/current').then(function (r) {
      if (r.ok && r.data && r.data.success) {
        S.info = r.data;
        window.__net365TermsVersion = r.data.version;
        window.__net365TermsAvailable = !!r.data.available;
      }
      return S.info;
    }).catch(function () { return null; });
    return S.loading;
  }

  var CSS = '#n365t{position:fixed;inset:0;z-index:2147483000;background:rgba(10,10,14,.72);display:flex;align-items:center;justify-content:center;padding:16px;font-family:-apple-system,Segoe UI,Roboto,sans-serif}' +
    '#n365t .c{background:#fff;color:#1e293b;max-width:440px;width:100%;max-height:92vh;overflow:auto;border-radius:16px;padding:22px 20px;box-shadow:0 20px 60px rgba(0,0,0,.4)}' +
    '@media (prefers-color-scheme:dark){ #n365t .c{background:#1c1c20;color:#e8e8ec}#n365t .m{color:#9a9aa6}#n365t .o{border-color:#34343c}}' +
    '#n365t .b{height:4px;border-radius:2px;background:linear-gradient(90deg,#E53935,#FF6D00);margin-bottom:16px}' +
    '#n365t h2{margin:0 0 6px;font-size:20px}#n365t p,#n365t li{font-size:14px;line-height:1.55}#n365t ul{padding-left:18px;margin:8px 0 12px}' +
    '#n365t .m{color:#64748b;font-size:13px}#n365t a{color:#E53935}' +
    '#n365t label{display:flex;gap:10px;align-items:flex-start;margin:14px 0;font-size:14px;cursor:pointer}#n365t input[type=checkbox]{width:20px;height:20px;margin-top:1px;flex:none}' +
    '#n365t button{width:100%;border:0;border-radius:12px;padding:13px;font-size:15px;font-weight:700;cursor:pointer;margin-top:8px}' +
    '#n365t .go{background:linear-gradient(90deg,#E53935,#FF6D00);color:#fff}#n365t .go[disabled]{opacity:.5;cursor:not-allowed}' +
    '#n365t .o{background:transparent;border:1px solid #cbd5e1;color:inherit;font-weight:600}#n365t .e{color:#c93434;font-size:13px;margin-top:8px;display:none}';

  function show(channel) {
    if (S.shown || document.getElementById('n365t')) return;
    S.shown = true;
    if (!document.getElementById('n365t-style')) {
      var st = document.createElement('style'); st.id = 'n365t-style'; st.textContent = CSS; document.head.appendChild(st);
    }
    var d = document.createElement('div');
    d.id = 'n365t'; d.setAttribute('role', 'dialog'); d.setAttribute('aria-modal', 'true'); d.setAttribute('aria-labelledby', 'n365t-h');
    d.innerHTML = '<div class="c"><div class="b"></div><h2 id="n365t-h">Please review our Terms</h2>' +
      '<p class="m">Before you continue, please accept the Net365 Terms of Service (version ' + (S.info.version || '') + ').</p>' +
      '<ul><li>Net365 is a payments and digital-services platform. Some services are delivered by third parties.</li>' +
      '<li>Net365 staff will <b>never</b> ask for your PIN, OTP or password.</li>' +
      '<li>We log activity and may automatically block suspicious access to keep your money safe.</li>' +
      '<li>You can contact support from the app or website at any time.</li></ul>' +
      '<p><a href="/terms" target="_blank" rel="noopener">Read the full Terms and Conditions</a></p>' +
      '<label><input type="checkbox" id="n365t-ck"><span>I have read and agree to the Terms of Service and Privacy Policy.</span></label>' +
      '<button class="go" id="n365t-ok" disabled>Accept and continue</button>' +
      '<button class="o" id="n365t-no">Decline and sign out</button><div class="e" id="n365t-err" role="alert"></div></div>';
    document.body.appendChild(d);
    var ck = document.getElementById('n365t-ck'), ok = document.getElementById('n365t-ok'), no = document.getElementById('n365t-no'), er = document.getElementById('n365t-err');
    ck.addEventListener('change', function () { ok.disabled = !ck.checked; });
    ok.addEventListener('click', function () {
      ok.disabled = true; ok.textContent = 'Saving...'; er.style.display = 'none';
      api('/api/legal/accept', { method: 'POST', body: JSON.stringify({ version: S.info.version, channel: channel || 'web' }) }).then(function (r) {
        if (r.ok && r.data && r.data.success) { d.remove(); S.shown = false; return; }
        er.textContent = (r.data && r.data.error) || 'Could not save. Please try again.'; er.style.display = 'block';
        ok.disabled = !ck.checked; ok.textContent = 'Accept and continue';
        if (r.status === 409) { S.loading = null; load(); }
      }).catch(function () { er.textContent = 'No connection. Please try again.'; er.style.display = 'block'; ok.disabled = false; ok.textContent = 'Accept and continue'; });
    });
    no.addEventListener('click', function () {
      api('/api/auth/logout', { method: 'POST' }).catch(function () {}).then(function () { location.reload(); });
    });
    setTimeout(function () { try { ck.focus(); } catch (e) {} }, 50);
  }

  function gate(channel) {
    return load().then(function (info) {
      if (!info || !info.available) return;
      return api('/api/legal/status').then(function (r) {
        if (r.ok && r.data && r.data.success && r.data.accepted === false) show(channel);
      });
    }).catch(function () { /* fail open */ });
  }

  window.Net365Terms = { load: load, gate: gate };
  load();
})();

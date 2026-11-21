/* NET365 Support client: shared by the website (index.html) and the mobile app (mobile.html). No dependencies.
 *   Net365Support.open()   opens the support panel (list of reports, new report, conversation, reply, "is it fixed?")
 *   A small floating "Help" button is added automatically; call Net365Support.hideButton() if you have your own entry point.
 * Everything customer-supplied is written with textContent, never innerHTML. */
(function () {
  'use strict';
  var CH = (/mobile/i.test(location.pathname) || document.querySelector('meta[name="net365-channel"][content="mobile"]')) ? 'mobile' : 'web';
  var CATS = [['failed', 'Failed or slow transaction'], ['missing', 'Payment taken, service not received'], ['wrong', 'Wrong amount or wrong service'],
    ['login', 'Login or account problem'], ['security', 'Security concern (someone else used my account)'], ['support', 'Poor customer service'], ['other', 'Something else']];
  var ST = { OPEN: 'Open', UNDER_REVIEW: 'Under review', IN_PROGRESS: 'In progress', WAITING_CUSTOMER: 'Waiting for your reply', RESOLVED: 'Resolved', CONFIRMED: 'Closed', REOPENED: 'Reopened' };
  var root, body, btn, state = { ticket: null };

  function api(path, opts) {
    var o = Object.assign({ credentials: 'include', headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' } }, opts || {});
    return fetch(path, o).then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, status: r.status, data: d }; }); });
  }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function clear() { while (body.firstChild) body.removeChild(body.firstChild); }
  function when(s) { try { return new Date(s.replace(' ', 'T') + 'Z').toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }); } catch (e) { return s || ''; } }

  var CSS = '#n365s-b{position:fixed;right:16px;bottom:' + (CH === 'mobile' ? '88px' : '18px') + ';z-index:2147482000;border:0;border-radius:999px;padding:11px 16px;font:700 14px -apple-system,Segoe UI,Roboto,sans-serif;color:#fff;background:linear-gradient(90deg,#E53935,#FF6D00);box-shadow:0 6px 20px rgba(0,0,0,.25);cursor:pointer}' +
    '#n365s-b .d{display:inline-block;min-width:18px;height:18px;line-height:18px;border-radius:9px;background:#fff;color:#E53935;font-size:11px;margin-left:6px;text-align:center}' +
    '#n365s{position:fixed;inset:0;z-index:2147482500;background:rgba(10,10,14,.6);display:none;align-items:flex-end;justify-content:center;font-family:-apple-system,Segoe UI,Roboto,sans-serif}' +
    '#n365s.on{display:flex}@media(min-width:640px){ #n365s{align-items:center}}' +
    '#n365s .p{background:#fff;color:#1e293b;width:100%;max-width:480px;max-height:92vh;display:flex;flex-direction:column;border-radius:18px 18px 0 0;overflow:hidden}@media(min-width:640px){ #n365s .p{border-radius:18px}}' +
    '@media(prefers-color-scheme:dark){ #n365s .p{background:#1c1c20;color:#e8e8ec}#n365s .m,#n365s .t{color:#9a9aa6}#n365s .i,#n365s textarea,#n365s select{background:#26262c;color:#e8e8ec;border-color:#34343c}#n365s .row{border-color:#2c2c34}}' +
    '#n365s .h{display:flex;align-items:center;gap:8px;padding:14px 16px;border-bottom:1px solid #e2e8f0}#n365s .h b{flex:1;font-size:16px}' +
    '#n365s .x{border:0;background:none;font-size:22px;line-height:1;cursor:pointer;color:inherit}' +
    '#n365s .bd{padding:14px 16px;overflow:auto;flex:1}#n365s .m,#n365s .t{color:#64748b;font-size:12px}' +
    '#n365s .row{display:block;width:100%;text-align:left;background:none;border:0;border-bottom:1px solid #e2e8f0;padding:11px 0;cursor:pointer;color:inherit;font:inherit}' +
    '#n365s .row b{font-size:14px}#n365s .tag{font-size:11px;padding:2px 8px;border-radius:9px;background:#fff1ea;color:#c2410c;margin-left:6px}#n365s .tag.w{background:#e6f4ea;color:#166534}' +
    '#n365s textarea,#n365s select{width:100%;box-sizing:border-box;border:1px solid #cbd5e1;border-radius:10px;padding:10px;font:inherit;font-size:14px;margin:6px 0 10px;background:#fff;color:inherit}#n365s textarea{min-height:110px;resize:vertical}' +
    '#n365s .go{width:100%;border:0;border-radius:12px;padding:12px;font-size:15px;font-weight:700;color:#fff;background:linear-gradient(90deg,#E53935,#FF6D00);cursor:pointer}#n365s .go[disabled]{opacity:.5}' +
    '#n365s .sec{width:100%;border:1px solid #cbd5e1;border-radius:12px;padding:11px;font-size:14px;font-weight:600;background:none;color:inherit;cursor:pointer;margin-top:8px}' +
    '#n365s .msg{max-width:86%;margin:8px 0;padding:9px 12px;border-radius:14px;font-size:14px;line-height:1.45;white-space:pre-wrap;word-wrap:break-word;background:#f1f5f9;color:#1e293b}' +
    '#n365s .msg.me{margin-left:auto;background:#E53935;color:#fff}#n365s .e{color:#c93434;font-size:13px;margin:6px 0;display:none}#n365s .w2{font-size:12px;color:#64748b;margin:6px 0}';

  function build() {
    if (root) return;
    root = el('div'); root.id = 'n365s'; root.setAttribute('role', 'dialog'); root.setAttribute('aria-modal', 'true'); root.setAttribute('aria-label', 'Net365 support');
    var p = el('div', 'p'), h = el('div', 'h'), t = el('b', null, 'Support'), x = el('button', 'x', '×');
    x.setAttribute('aria-label', 'Close'); x.addEventListener('click', close);
    h.appendChild(t); h.appendChild(x); body = el('div', 'bd'); p.appendChild(h); p.appendChild(body); root.appendChild(p);
    root.addEventListener('click', function (e) { if (e.target === root) close(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });
    document.body.appendChild(root);
    state.title = t;
  }
  function close() { if (root) root.classList.remove('on'); }
  function title(s) { state.title.textContent = s; }
  function err(box, d, fallback) {
    var m = { too_short: 'Please give a little more detail.', too_many: 'You have opened several reports today. Our team is working on them.', slow_down: 'You are sending messages very quickly. Please wait a few minutes.', closed: 'This report is closed. Please open a new one.' };
    box.textContent = m[d && d.error] || (d && d.message) || fallback || 'Something went wrong. Please try again.'; box.style.display = 'block';
  }

  function list() {
    title('Support'); clear(); state.ticket = null;
    body.appendChild(el('p', 'm', 'Tell us about a problem or a security concern. We reply here, by email and in the chat you used.'));
    var nb = el('button', 'go', 'Report a problem'); nb.addEventListener('click', form); body.appendChild(nb);
    var box = el('div'); body.appendChild(box);
    api('/api/support/tickets').then(function (r) {
      if (r.status === 401) { box.appendChild(el('p', 'm', 'Please sign in to see your reports. You can also email support@net365co.com.')); nb.disabled = true; return; }
      var ts = (r.data && r.data.tickets) || [];
      setBadge(r.data && r.data.waiting_for_you || 0);
      if (!ts.length) { box.appendChild(el('p', 'm', 'You have no reports yet.')); return; }
      box.appendChild(el('h4', null, 'Your reports'));
      ts.forEach(function (x) {
        var b = el('button', 'row'), l = el('b', null, x.category_label + ' '), g = el('span', 'tag' + (x.status === 'RESOLVED' || x.status === 'CONFIRMED' ? ' w' : ''), ST[x.status] || x.status);
        l.appendChild(g); if (x.kind === 'incident') l.appendChild(el('span', 'tag', 'Incident'));
        b.appendChild(l); b.appendChild(el('div', 't', x.ticket_no + ' · ' + when(x.updated_at) + (x.waiting_for_you ? ' · new reply' : '')));
        b.addEventListener('click', function () { thread(x.ticket_no); }); box.appendChild(b);
      });
    }).catch(function () { box.appendChild(el('p', 'm', 'Could not load your reports. Please check your connection.')); });
  }

  function form() {
    title('Report a problem'); clear();
    var sel = el('select'); CATS.forEach(function (c) { var o = el('option', null, c[1]); o.value = c[0]; sel.appendChild(o); });
    var ta = el('textarea'); ta.placeholder = 'What happened? If it was an order, we attach your latest one automatically.'; ta.maxLength = 4000;
    var w = el('p', 'w2', 'Never send your PIN, OTP, password or full card number.'), e = el('div', 'e'), go = el('button', 'go', 'Send to support'), bk = el('button', 'sec', 'Back');
    [el('label', 'm', 'What is this about?'), sel, ta, w, e, go, bk].forEach(function (n) { body.appendChild(n); });
    bk.addEventListener('click', list);
    go.addEventListener('click', function () {
      e.style.display = 'none'; go.disabled = true; go.textContent = 'Sending...';
      api('/api/support/tickets', { method: 'POST', body: JSON.stringify({ category: sel.value, message: ta.value, channel: CH }) }).then(function (r) {
        if (r.ok && r.data && r.data.success) { thread(r.data.ticket_no, r.data.kind === 'incident'); return; }
        err(e, r.data, r.status === 401 ? 'Please sign in first.' : null); go.disabled = false; go.textContent = 'Send to support';
      }).catch(function () { err(e, null, 'No connection. Please try again.'); go.disabled = false; go.textContent = 'Send to support'; });
    });
  }

  function thread(no, justCreated) {
    title(no); clear(); state.ticket = no;
    var top = el('div'); body.appendChild(top);
    api('/api/support/tickets/' + encodeURIComponent(no)).then(function (r) {
      if (!r.ok) { top.appendChild(el('p', 'm', 'We could not open this report.')); return; }
      var t = r.data.ticket;
      top.appendChild(el('p', 'm', (t.category_label || '') + ' · ' + (ST[t.status] || t.status) + (t.reference ? ' · Order ' + t.reference : '')));
      if (justCreated) top.appendChild(el('p', 'm', t.kind === 'incident' ? 'We have flagged this as urgent and our team has been alerted.' : 'We have it. Our team will reply here, by email and in your chat.'));
      (r.data.messages || []).forEach(function (m) { var b = el('div', 'msg' + (m.sender === 'customer' ? ' me' : ''), m.body); top.appendChild(b); top.appendChild(el('div', 't', (m.sender === 'agent' ? 'Net365 Support' : 'You') + ' · ' + when(m.created_at))); });
      if (t.status === 'RESOLVED') {
        top.appendChild(el('p', null, 'Is this sorted now?'));
        var y = el('button', 'go', 'Yes, it is fixed'), n = el('button', 'sec', 'No, it is not fixed');
        y.addEventListener('click', function () { confirm(no, true); }); n.addEventListener('click', function () { confirm(no, false); });
        top.appendChild(y); top.appendChild(n);
      }
      if (t.status !== 'CONFIRMED') {
        var ta = el('textarea'); ta.placeholder = 'Write a reply...'; ta.style.minHeight = '70px'; ta.maxLength = 4000;
        var e = el('div', 'e'), go = el('button', 'go', 'Send reply');
        top.appendChild(ta); top.appendChild(e); top.appendChild(go);
        go.addEventListener('click', function () {
          e.style.display = 'none'; go.disabled = true;
          api('/api/support/tickets/' + encodeURIComponent(no) + '/reply', { method: 'POST', body: JSON.stringify({ message: ta.value, channel: CH }) }).then(function (r2) {
            if (r2.ok && r2.data && r2.data.success) thread(no); else { err(e, r2.data); go.disabled = false; }
          }).catch(function () { err(e, null, 'No connection.'); go.disabled = false; });
        });
      } else top.appendChild(el('p', 'm', 'This report is closed. Open a new one if you need more help.'));
      var bk = el('button', 'sec', 'All my reports'); bk.addEventListener('click', list); top.appendChild(bk);
      refreshBadge();
    }).catch(function () { top.appendChild(el('p', 'm', 'No connection. Please try again.')); });
  }
  function confirm(no, fixed) {
    api('/api/support/tickets/' + encodeURIComponent(no) + '/confirm', { method: 'POST', body: JSON.stringify({ fixed: fixed }) }).then(function () { thread(no); });
  }

  function setBadge(n) {
    if (!btn) return; var d = btn.querySelector('.d'); if (d) d.remove();
    if (n > 0) { var s = el('span', 'd', String(n)); btn.appendChild(s); }
  }
  function refreshBadge() { api('/api/support/tickets').then(function (r) { if (r.ok) setBadge(r.data.waiting_for_you || 0); }).catch(function () {}); }

  function open() { build(); root.classList.add('on'); list(); }
  function mountButton() {
    if (btn || document.getElementById('n365s-b')) return;
    var st = document.createElement('style'); st.textContent = CSS; document.head.appendChild(st);
    btn = el('button', null, 'Help'); btn.id = 'n365s-b'; btn.type = 'button'; btn.setAttribute('aria-label', 'Contact Net365 support');
    btn.addEventListener('click', open); document.body.appendChild(btn);
    setTimeout(refreshBadge, 2500);
  }
  window.Net365Support = { open: open, hideButton: function () { if (btn) btn.style.display = 'none'; }, refresh: refreshBadge };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mountButton); else mountButton();
})();

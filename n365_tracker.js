/* Net365 visitor tracker.
 * Loaded on public pages (the server injects the <script> tag). Does nothing until the visitor accepts.
 * Sends only: event name + small non-personal props (path, referrer, utm, network, amount).
 * Never reads or sends phone numbers, emails, names, PINs or card data.
 *
 * Manual use from your own page code:
 *   n365Track('network_detected', {network: 'MTN'});
 *   n365Track('amount_selected',  {amount: 1000});
 *   n365Track('payment_redirected', {provider: 'paystack'});
 * Or without code: add data-n365-event="amount_selected" data-n365-amount="1000" to any button.
 */
(function () {
  'use strict';
  var CONSENT = 'n365_consent';
  var ALLOWED = {
    phone_entered: 1, network_detected: 1, amount_selected: 1, payment_redirected: 1,
    signup_started: 1, signup_completed: 1, ad_seen: 1, ad_clicked: 1, referral_code_used: 1
  };

  function getCookie(n) {
    var m = document.cookie.match('(?:^|; )' + n + '=([^;]*)');
    return m ? decodeURIComponent(m[1]) : null;
  }
  function setCookie(n, v) {
    document.cookie = n + '=' + encodeURIComponent(v) + '; path=/; max-age=31536000; SameSite=Lax' +
      (location.protocol === 'https:' ? '; Secure' : '');
  }
  function sid() {
    try {
      var s = sessionStorage.getItem('n365_sid');
      if (!s) { s = 's_' + Math.random().toString(16).slice(2) + Date.now().toString(16); sessionStorage.setItem('n365_sid', s); }
      return s;
    } catch (e) { return null; }
  }
  function utm() {
    var q = new URLSearchParams(location.search), o = {};
    ['utm_source', 'utm_medium', 'utm_campaign'].forEach(function (k) { if (q.get(k)) o[k] = q.get(k).slice(0, 60); });
    return o;
  }
  function post(url, body) {
    try {
      return fetch(url, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin', keepalive: true, body: JSON.stringify(body)
      }).catch(function () {});
    } catch (e) {}
  }
  function refClass(ref) {
    if (!ref) return 'direct';
    try {
      var h = new URL(ref).hostname;
      if (h === location.hostname) return 'internal';
      if (/google|bing|duckduckgo|yahoo|yandex/.test(h)) return 'search';
      if (/facebook|instagram|twitter|x\.com|t\.co|linkedin|tiktok|whatsapp|wa\.me|telegram|t\.me|youtube/.test(h)) return 'social';
      if (/mail|gmail|outlook/.test(h)) return 'email';
      return 'referral';
    } catch (e) { return 'other'; }
  }

  function track(event, props) {
    if (getCookie(CONSENT) !== '1' || !ALLOWED[event]) return;
    post('/api/track', { event: event, props: props || {}, session_id: sid() });
  }
  window.n365Track = track;

  var sent = {};
  function once(event, props) { if (!sent[event]) { sent[event] = 1; track(event, props); } }

  function sendSignals() {
    var c = navigator.connection || {};
    var u = utm();
    post('/api/visitor/signals', {
      session_id: sid(), screen_w: screen.width, screen_h: screen.height,
      viewport_w: innerWidth, viewport_h: innerHeight,
      timezone: (Intl.DateTimeFormat().resolvedOptions() || {}).timeZone || null,
      language: navigator.language, touch: ('ontouchstart' in window) ? 1 : 0,
      connection: c.effectiveType || null, referrer_class: refClass(document.referrer),
      utm_source: u.utm_source || null, utm_medium: u.utm_medium || null, utm_campaign: u.utm_campaign || null
    });
  }

  function wire() {
    // Phone field: only the fact that a plausible number was typed, never the number.
    document.addEventListener('blur', function (e) {
      var el = e.target;
      if (el && el.tagName === 'INPUT' && (el.type === 'tel' || /phone/i.test(el.name || el.id || ''))) {
        if ((el.value || '').replace(/\D/g, '').length >= 10) once('phone_entered');
      }
    }, true);
    document.addEventListener('click', function (e) {
      var el = e.target.closest ? e.target.closest('[data-n365-event]') : null;
      if (!el) return;
      var p = {};
      if (el.dataset.n365Network) p.network = el.dataset.n365Network;
      if (el.dataset.n365Amount) p.amount = Number(el.dataset.n365Amount) || 0;
      if (el.dataset.n365Provider) p.provider = el.dataset.n365Provider;
      track(el.dataset.n365Event, p);
    }, true);
    if (!sessionStorage.getItem('n365_sig')) {
      try { sessionStorage.setItem('n365_sig', '1'); } catch (e) {}
      sendSignals();
    }
  }

  function banner() {
    var dark = window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches;
    var box = document.createElement('div');
    box.setAttribute('role', 'region');
    box.setAttribute('aria-label', 'Cookie notice');
    box.style.cssText = 'position:fixed;left:12px;right:12px;bottom:12px;z-index:2147483000;max-width:520px;margin:0 auto;' +
      'padding:14px 16px;border-radius:12px;font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;' +
      'box-shadow:0 8px 30px rgba(0,0,0,.25);border:1px solid ' + (dark ? '#334155' : '#e2e8f0') + ';' +
      'background:' + (dark ? '#1e293b' : '#ffffff') + ';color:' + (dark ? '#e2e8f0' : '#1e293b');
    box.innerHTML = '<div style="margin-bottom:10px">We use one small cookie to count visits and learn which pages and offers work, ' +
      'so we can improve Net365. We never sell your data and never record your phone number, PIN or card details.</div>' +
      '<div style="display:flex;gap:8px;justify-content:flex-end">' +
      '<button type="button" data-a="no" style="padding:8px 14px;border-radius:8px;border:1px solid ' + (dark ? '#475569' : '#cbd5e1') +
      ';background:transparent;color:inherit;font:inherit;cursor:pointer">No thanks</button>' +
      '<button type="button" data-a="yes" style="padding:8px 14px;border-radius:8px;border:0;background:#4f46e5;color:#fff;' +
      'font:inherit;font-weight:600;cursor:pointer">Accept</button></div>';
    box.addEventListener('click', function (e) {
      var a = e.target && e.target.getAttribute && e.target.getAttribute('data-a');
      if (!a) return;
      setCookie(CONSENT, a === 'yes' ? '1' : '0');
      box.remove();
      if (a === 'yes') {
        var p = utm();
        p.path = location.pathname; p.ref = document.referrer || '';
        post('/api/track', { event: 'consent_granted', props: p, session_id: sid() });
        wire();
      }
    });
    document.body.appendChild(box);
  }

  function start() {
    var c = getCookie(CONSENT);
    if (c === '1') wire();
    else if (c === null) banner();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();

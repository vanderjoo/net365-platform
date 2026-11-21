/* Net365 investor-page engagement beacon.
 * Include on any investor-facing page:  <script src="/investor_track.js" defer></script>
 * Sends: page view, active seconds, max scroll depth, clicks on [data-track] elements, downloads.
 * Respects Do-Not-Track / Global Privacy Control. No cookies are set by this script; it sends no personal data. */
(function () {
  'use strict';
  if (navigator.doNotTrack === '1' || navigator.globalPrivacyControl) return;
  var URL_ = '/api/investors/event', path = location.pathname, qs = new URLSearchParams(location.search);
  var first = {};
  ['utm_source', 'utm_medium', 'utm_campaign'].forEach(function (k) {
    var v = qs.get(k);
    try { if (v) sessionStorage.setItem('inv_' + k, v); else v = sessionStorage.getItem('inv_' + k); } catch (e) {}
    first[k] = v || '';
  });
  var ref = document.referrer || ''; try { if (ref) sessionStorage.setItem('inv_ref', ref); else ref = sessionStorage.getItem('inv_ref') || ''; } catch (e) {}

  function send(event, value, label) {
    var body = JSON.stringify({ path: path, event: event, value: value || 0, label: label || '', referrer: ref,
      utm_source: first.utm_source, utm_medium: first.utm_medium, utm_campaign: first.utm_campaign });
    try {
      if (navigator.sendBeacon && navigator.sendBeacon(URL_, new Blob([body], { type: 'application/json' }))) return;
    } catch (e) {}
    try { fetch(URL_, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body, keepalive: true }); } catch (e) {}
  }

  send('view');

  // active time: only counts while the tab is visible; flushed every 15s and when leaving
  var active = 0, last = Date.now(), sent = 0;
  function tick() { if (!document.hidden) { active += (Date.now() - last) / 1000; } last = Date.now(); }
  function flush() { tick(); var d = Math.round(active - sent); if (d > 0) { sent += d; send('time', d); } }
  setInterval(function () { tick(); if (active - sent >= 15) flush(); }, 5000);
  document.addEventListener('visibilitychange', function () { flush(); });
  window.addEventListener('pagehide', flush);

  // scroll depth in 25% steps, reported once each
  var seen = {};
  function onScroll() {
    var h = document.documentElement, max = h.scrollHeight - h.clientHeight;
    var pct = max > 0 ? Math.round(100 * (window.scrollY || h.scrollTop) / max) : 100;
    [25, 50, 75, 100].forEach(function (m) { if (pct >= m && !seen[m]) { seen[m] = 1; send('scroll', m); } });
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  setTimeout(onScroll, 1500);

  // clicks: add data-track="label" to links/buttons; data-track-type="download" for documents
  document.addEventListener('click', function (e) {
    var el = e.target.closest && e.target.closest('[data-track]');
    if (!el) return;
    send(el.getAttribute('data-track-type') === 'download' ? 'download' : 'click', 0, el.getAttribute('data-track'));
  });

  // sections: add data-section="Market" to a block to learn which parts get read
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (es) {
      es.forEach(function (en) { if (en.isIntersecting) { send('section', 0, en.target.getAttribute('data-section')); io.unobserve(en.target); } });
    }, { threshold: 0.6 });
    document.querySelectorAll('[data-section]').forEach(function (n) { io.observe(n); });
  }
  window.n365Investor = { track: send };
})();

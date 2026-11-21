/* Net365 OnePay: one payment, many deliveries.
 * Loaded by index.html and mobile.html. Talks to /api/cart/checkout and /api/cart/<reference>.
 * Public API:  OnePay.addAirtime()  OnePay.addUtility({biller_id, subscriber_account, amount, biller_name})
 *              OnePay.open()  OnePay.count()
 * The server recomputes every price and fee; nothing the browser sends as a total is trusted. */
(function () {
  'use strict';
  var KEY = 'n365_onepay_cart', MAX = 10;
  var items = [];
  try { items = JSON.parse(localStorage.getItem(KEY) || '[]') || []; } catch (e) { items = []; }

  function save() { try { localStorage.setItem(KEY, JSON.stringify(items)); } catch (e) {} render(); }
  function say(msg, kind) {
    try {
      if (typeof showToast === 'function') return showToast(msg, kind || 'info');
      if (typeof toast === 'function') return toast(msg, kind || 'info');
    } catch (e) {}
    alert(msg);
  }
  function naira(v) { return '₦' + Number(v || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') n.textContent = attrs[k];
      else if (k === 'class') n.className = attrs[k];
      else if (k.indexOf('on') === 0) n.addEventListener(k.slice(2), attrs[k]);
      else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c) n.appendChild(c); });
    return n;
  }
  function signedIn() {
    try { if (typeof currentUser !== 'undefined' && currentUser) return true; } catch (e) {}
    try { if (typeof userId !== 'undefined' && userId) return true; } catch (e) {}
    return false;
  }

  // ---------------------------------------------------------------- styles
  var css = document.createElement('style');
  css.textContent =
    '.op-fab{position:fixed;left:14px;bottom:84px;z-index:9990;background:#0f172a;color:#fff;border:0;border-radius:999px;padding:11px 16px;font:600 14px system-ui,sans-serif;box-shadow:0 6px 20px rgba(0,0,0,.28);cursor:pointer;display:none}' +
    '.op-fab.show{display:flex;gap:8px;align-items:center}.op-fab b{background:#ff6d00;border-radius:999px;padding:1px 8px;font-size:12px}' +
    '.op-add{display:block;width:100%;margin-top:10px;padding:12px;border-radius:12px;border:1.5px dashed #ff6d00;background:transparent;color:#ff6d00;font:600 14px system-ui,sans-serif;cursor:pointer}' +
    '.op-back{position:fixed;inset:0;z-index:9995;background:rgba(0,0,0,.5);display:none;align-items:flex-end;justify-content:center}' +
    '.op-back.show{display:flex}' +
    '.op-sheet{background:#fff;color:#14181f;width:100%;max-width:480px;max-height:88vh;overflow:auto;border-radius:20px 20px 0 0;padding:18px 18px 24px;font:14px/1.45 system-ui,sans-serif}' +
    '@media (min-width:600px){.op-back{align-items:center}.op-sheet{border-radius:20px}}' +
    '.op-sheet h3{margin:0 0 4px;font-size:18px}.op-sub{color:#667085;margin:0 0 12px}' +
    '.op-row{display:flex;justify-content:space-between;gap:10px;align-items:center;padding:10px 0;border-bottom:1px solid #e4e7ec}' +
    '.op-row small{display:block;color:#667085}.op-x{border:0;background:none;color:#c0262d;font-size:18px;cursor:pointer}' +
    '.op-total{display:flex;justify-content:space-between;font-weight:700;font-size:16px;padding:12px 0}' +
    '.op-btn{width:100%;border:0;border-radius:12px;padding:14px;font:700 15px system-ui,sans-serif;cursor:pointer;background:#ff6d00;color:#fff;margin-top:6px}' +
    '.op-btn.ghost{background:#eef0f3;color:#14181f}.op-btn:disabled{opacity:.55}' +
    '.op-ok{color:#14804a;font-weight:700}.op-bad{color:#c0262d;font-weight:700}.op-wait{color:#b7791f;font-weight:700}' +
    '.op-err{color:#c0262d;margin:6px 0}';
  document.head.appendChild(css);

  var fab = el('button', { class: 'op-fab', 'aria-label': 'Open OnePay cart', onclick: function () { open(); } });
  var back = el('div', { class: 'op-back', onclick: function (e) { if (e.target === back) close(); } });
  var sheet = el('div', { class: 'op-sheet', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'OnePay cart' });
  back.appendChild(sheet);

  function close() { back.classList.remove('show'); if (stage === 'status') { stage = 'cart'; render(); } }
  function open(view) { stage = view || stage; render(); back.classList.add('show'); }

  // ---------------------------------------------------------------- cart state
  var stage = 'cart';       // cart | review | status
  var quote = null;         // server-confirmed breakdown
  var busy = false, errMsg = '';

  function add(item) {
    if (items.length >= MAX) { say('A cart can hold up to ' + MAX + ' items.', 'warning'); return false; }
    items.push(item); save(); say('Added to your OnePay cart (' + items.length + ')', 'success'); return true;
  }

  function addAirtime() {
    if (!signedIn()) { say('Please sign in to use OnePay.', 'warning'); return; }
    var phone = (document.getElementById('phoneInput') || {}).value || '';
    var amount = parseFloat((document.getElementById('amountInput') || {}).value) || 0;
    var op = null; try { op = selectedOperator; } catch (e) {}
    var cc = ''; try { cc = currentCountry; } catch (e) {}
    if (cc && cc !== 'NG') { say('OnePay currently supports Nigerian airtime and bills.', 'warning'); return; }
    if (!phone.trim() || amount <= 0 || !op || !op.operatorId) { say('Choose a network, enter the phone number and amount first.', 'warning'); return; }
    add({ type: 'topup', operator_id: op.operatorId, operator_name: op.name || '', phone: phone.replace(/\s/g, ''), amount: amount });
  }
  function addUtility(o) {
    if (!signedIn()) { say('Please sign in to use OnePay.', 'warning'); return; }
    if (!o || !o.biller_id || !o.subscriber_account || !(Number(o.amount) > 0)) { say('Missing bill details.', 'warning'); return; }
    add({ type: 'utility', biller_id: o.biller_id, subscriber_account: String(o.subscriber_account), amount: Number(o.amount), biller_name: o.biller_name || '' });
  }

  function describe(it) {
    if (it.type === 'utility') return (it.biller_name || 'Bill payment') + ' · ' + it.subscriber_account;
    return (it.operator_name || 'Airtime') + ' · ' + it.phone;
  }

  // ---------------------------------------------------------------- server calls
  async function call(url, opts) {
    var r = await fetch(url, Object.assign({ credentials: 'include', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' } }, opts || {}));
    var text = await r.text(), j = {};
    try { j = JSON.parse(text); } catch (e) { /* non-JSON error page */ }
    if (!r.ok || j.success === false) {
      var m = j.error || (r.status === 401 ? 'Please sign in again.' : r.status === 429 ? 'Too many requests. Wait a moment and retry.' : 'Something went wrong (HTTP ' + r.status + ').');
      var e = new Error(m); e.status = r.status; throw e;
    }
    return j;
  }

  async function review() {
    if (busy) return; busy = true; errMsg = ''; render();
    try {
      quote = await call('/api/cart/checkout', { method: 'POST', body: JSON.stringify({
        provider: 'paystack', currency: 'NGN', return_url: location.origin + '/payment/success',
        items: items.map(function (i) { return Object.assign({}, i); }) }) });
      stage = 'review';
    } catch (e) { errMsg = e.message; }
    busy = false; render();
  }

  var pollTimer = null;
  async function track(reference) {
    stage = 'status'; open('status');
    clearTimeout(pollTimer);
    try {
      var s = await call('/api/cart/' + encodeURIComponent(reference));
      quote = s; errMsg = ''; render();
      if (s.status === 'processing' || s.status === 'awaiting_payment') pollTimer = setTimeout(function () { track(reference); }, 3000);
    } catch (e) { errMsg = e.message; render(); }
  }

  // ---------------------------------------------------------------- rendering
  function render() {
    fab.classList.toggle('show', items.length > 0 && stage !== 'status');
    fab.textContent = '';
    fab.appendChild(document.createTextNode('OnePay cart '));
    fab.appendChild(el('b', { text: String(items.length) }));
    sheet.textContent = '';
    if (stage === 'status') return renderStatus();
    if (stage === 'review' && quote) return renderReview();
    return renderCart();
  }

  function renderCart() {
    sheet.appendChild(el('h3', { text: 'Your OnePay cart' }));
    sheet.appendChild(el('p', { class: 'op-sub', text: 'Pay once. Each item is delivered separately.' }));
    if (!items.length) sheet.appendChild(el('p', { text: 'Nothing here yet. Fill in an airtime purchase and tap "Add to OnePay cart".' }));
    items.forEach(function (it, i) {
      sheet.appendChild(el('div', { class: 'op-row' }, [
        el('div', {}, [el('span', { text: describe(it) }), el('small', { text: naira(it.amount) + ' before fee' })]),
        el('button', { class: 'op-x', 'aria-label': 'Remove item', text: '×', onclick: function () { items.splice(i, 1); save(); } })
      ]));
    });
    if (errMsg) sheet.appendChild(el('div', { class: 'op-err', text: errMsg }));
    var go = el('button', { class: 'op-btn', text: busy ? 'Checking prices…' : 'Review exact total', onclick: review });
    go.disabled = busy || !items.length;
    sheet.appendChild(go);
    sheet.appendChild(el('button', { class: 'op-btn ghost', text: 'Close', onclick: close }));
  }

  function renderReview() {
    sheet.appendChild(el('h3', { text: 'Confirm and pay' }));
    sheet.appendChild(el('p', { class: 'op-sub', text: 'Prices below are confirmed by Net365.' }));
    (quote.items || []).forEach(function (it) {
      sheet.appendChild(el('div', { class: 'op-row' }, [
        el('div', {}, [el('span', { text: it.label }), el('small', { text: naira(it.service_amount) + (it.fee ? ' + ' + naira(it.fee) + ' fee' : '') })]),
        el('b', { text: naira(it.total) })
      ]));
    });
    sheet.appendChild(el('div', { class: 'op-total' }, [el('span', { text: 'One payment' }), el('span', { text: naira(quote.amount) })]));
    sheet.appendChild(el('button', { class: 'op-btn', text: 'Pay ' + naira(quote.amount), onclick: function () {
      try { sessionStorage.setItem('n365_onepay_ref', quote.reference); } catch (e) {}
      location.href = quote.authorization_url;
    } }));
    sheet.appendChild(el('button', { class: 'op-btn ghost', text: 'Back to cart', onclick: function () { stage = 'cart'; quote = null; render(); } }));
  }

  function renderStatus() {
    var q = quote || {};
    var head = { completed: 'All items delivered', partially_completed: 'Some items need attention', failed: 'Items could not be delivered',
                 processing: 'Delivering your items…', awaiting_payment: 'Confirming your payment…' }[q.status] || 'Checking your order…';
    sheet.appendChild(el('h3', { text: head }));
    if (q.amount) sheet.appendChild(el('p', { class: 'op-sub', text: 'One payment of ' + naira(q.amount) + ' · ' + q.reference }));
    (q.items || []).forEach(function (it) {
      var cls = it.state === 'delivered' ? 'op-ok' : it.state === 'failed' ? 'op-bad' : 'op-wait';
      var txt = it.state === 'delivered' ? 'Delivered' : it.state === 'failed' ? 'Failed' : 'In progress';
      sheet.appendChild(el('div', { class: 'op-row' }, [
        el('div', {}, [el('span', { text: it.label }), el('small', { text: naira(it.amount) })]),
        el('span', { class: cls, text: txt })
      ]));
    });
    if (q.failed) sheet.appendChild(el('p', { class: 'op-sub', text: 'Anything we could not deliver will be refunded to your original payment method.' }));
    if (errMsg) sheet.appendChild(el('div', { class: 'op-err', text: errMsg }));
    sheet.appendChild(el('button', { class: 'op-btn ghost', text: 'Close', onclick: function () { close(); stage = 'cart'; render(); } }));
  }

  // ---------------------------------------------------------------- boot
  function boot() {
    document.body.appendChild(fab); document.body.appendChild(back);

    // "Add to OnePay cart" under the main pay button
    var pay = document.getElementById('payBtn') || document.getElementById('payButton');
    if (pay && pay.parentNode && !document.getElementById('opAddBtn')) {
      var b = el('button', { id: 'opAddBtn', class: 'op-add', type: 'button', text: '+ Add to OnePay cart', onclick: addAirtime });
      pay.parentNode.insertBefore(b, pay.nextSibling);
    }

    // Returning from Paystack: if the reference is a cart, show per-item results.
    var qs = new URLSearchParams(location.search);
    var ref = qs.get('reference') || qs.get('trxref');
    if (ref && /^(success|successful|completed|paid|processing|pending)$/i.test(qs.get('status') || qs.get('payment_status') || '')) {
      call('/api/cart/' + encodeURIComponent(ref)).then(function (s) {
        items = []; save();                       // the cart was paid for
        track(ref);
      }).catch(function () { /* not a cart: the page's own receipt flow handles it */ });
    }
    render();
  }

  window.OnePay = { addAirtime: addAirtime, addUtility: addUtility, open: open, count: function () { return items.length; } };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();

/* NET365 Bills & Services hub: shared by the website (index.html) and the mobile app (mobile.html). No dependencies.
 *   Net365Hub.open()              opens the hub home (tiles)
 *   Net365Hub.open('electricity') opens straight into a service: electricity | tv | data | education | insurance
 * Which tiles are live comes from /api/hub/config (HUB_* settings on the server), so nothing is sold before you switch it on.
 * Prices always come from the server. Everything customer-supplied is written with textContent, never innerHTML. */
(function () {
  'use strict';
  var S = { cfg: null, root: null, body: null, title: null, backBtn: null, back: null, busy: false };
  var NAIRA = '₦';
  var SERVICES = [
    ['electricity', 'Electricity', 'Prepaid and postpaid', 'fa-bolt', '#f59e0b'],
    ['tv', 'Cable TV', 'DStv, GOtv, StarTimes, Showmax', 'fa-tv', '#ef4444'],
    ['data', 'Data', 'MTN, Airtel, Glo, 9mobile', 'fa-wifi', '#22d3ee'],
    ['education', 'Education', 'WAEC and JAMB PINs', 'fa-graduation-cap', '#6366f1'],
    ['insurance', 'Insurance', 'Motor third-party', 'fa-shield-alt', '#10b981']
  ];
  var TV = [['dstv', 'DStv'], ['gotv', 'GOtv'], ['startimes', 'StarTimes'], ['showmax', 'Showmax']];
  var NET = [['mtn', 'MTN'], ['airtel', 'Airtel'], ['glo', 'Glo'], ['9mobile', '9mobile']];
  var EDU = [['waec', 'WAEC result checker PIN'], ['waec-registration', 'WAEC registration PIN'], ['jamb', 'JAMB PIN (UTME / Direct Entry)']];
  var PNAME = { vtpass: 'VTpass', reloadly: 'Reloadly' };

  function api(path, opts) {
    var o = Object.assign({ credentials: 'include', headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' } }, opts || {});
    return fetch(path, o).then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, status: r.status, data: d }; }); });
  }
  function post(path, body) { return api(path, { method: 'POST', body: JSON.stringify(body) }); }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function clear() { while (S.body.firstChild) S.body.removeChild(S.body.firstChild); }
  function money(n) { return NAIRA + Number(n || 0).toLocaleString(undefined, { maximumFractionDigits: 2 }); }
  function add(parent) { for (var i = 1; i < arguments.length; i++) if (arguments[i]) parent.appendChild(arguments[i]); return parent; }

  var CSS = '#n365h{position:fixed;inset:0;z-index:2147482400;background:rgba(10,10,14,.6);display:none;align-items:flex-end;justify-content:center;font-family:-apple-system,Segoe UI,Roboto,sans-serif}' +
    '#n365h.on{display:flex}@media(min-width:640px){ #n365h{align-items:center}}' +
    '#n365h .p{background:#fff;color:#1e293b;width:100%;max-width:520px;height:92vh;max-height:92vh;display:flex;flex-direction:column;border-radius:18px 18px 0 0;overflow:hidden}@media(min-width:640px){ #n365h .p{height:auto;max-height:90vh;min-height:520px;border-radius:18px}}' +
    '@media(prefers-color-scheme:dark){ #n365h .p{background:#1c1c20;color:#e8e8ec}#n365h .m{color:#9a9aa6}#n365h .i,#n365h select,#n365h input{background:#26262c;color:#e8e8ec;border-color:#34343c}#n365h .row,#n365h .h{border-color:#2c2c34}#n365h .ok{background:#12301f;color:#86efac}#n365h .chip{border-color:#34343c}}' +
    '#n365h .h{display:flex;align-items:center;gap:8px;padding:12px 14px;border-bottom:1px solid #e2e8f0}#n365h .h b{flex:1;font-size:16px}' +
    '#n365h .x{border:0;background:none;font-size:22px;line-height:1;cursor:pointer;color:inherit;padding:4px 8px}' +
    '#n365h .bd{padding:14px 16px 22px;overflow:auto;flex:1}#n365h .m{color:#64748b;font-size:13px}' +
    '#n365h .grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}' +
    '#n365h .tile{display:block;text-align:left;border:1px solid #e2e8f0;border-radius:14px;padding:14px;background:none;color:inherit;cursor:pointer;font:inherit}#n365h .tile[disabled]{opacity:.55;cursor:default}' +
    '#n365h .ico{display:inline-flex;width:38px;height:38px;border-radius:11px;align-items:center;justify-content:center;color:#fff;margin-bottom:8px}' +
    '#n365h .tile b{display:block;font-size:14px}#n365h .tile small{font-size:12px;color:#64748b}' +
    '#n365h .row{display:block;width:100%;text-align:left;background:none;border:0;border-bottom:1px solid #e2e8f0;padding:12px 2px;cursor:pointer;color:inherit;font:inherit}#n365h .row b{font-size:14px}' +
    '#n365h .tag{font-size:11px;padding:2px 8px;border-radius:9px;background:#eef2ff;color:#4338ca;margin-left:6px}' +
    '#n365h label{display:block;font-size:13px;font-weight:600;margin:12px 0 4px}' +
    '#n365h input,#n365h select{width:100%;box-sizing:border-box;border:1px solid #cbd5e1;border-radius:10px;padding:11px;font:inherit;font-size:15px;background:#fff;color:inherit}' +
    '#n365h .chips{display:flex;gap:8px;flex-wrap:wrap}#n365h .chip{border:1px solid #cbd5e1;border-radius:999px;padding:8px 13px;font-size:13px;background:none;color:inherit;cursor:pointer;font-weight:600}#n365h .chip.on{background:#E53935;border-color:#E53935;color:#fff}' +
    '#n365h .go{width:100%;border:0;border-radius:12px;padding:13px;font-size:15px;font-weight:700;color:#fff;background:linear-gradient(90deg,#E53935,#FF6D00);cursor:pointer;margin-top:16px}#n365h .go[disabled]{opacity:.5;cursor:not-allowed}' +
    '#n365h .sec{width:100%;border:1px solid #cbd5e1;border-radius:12px;padding:12px;font-size:14px;font-weight:600;background:none;color:inherit;cursor:pointer;margin-top:10px}' +
    '#n365h .ok{background:#e6f4ea;color:#14532d;border-radius:12px;padding:11px 13px;font-size:14px;margin-top:12px}#n365h .e{color:#c93434;font-size:13px;margin-top:10px;display:none}' +
    '#n365h .chk{display:flex;gap:10px;align-items:flex-start;margin-top:14px;font-size:13px;font-weight:400}#n365h .chk input{width:20px;height:20px;flex:none;margin-top:1px}';

  function build() {
    if (S.root) return;
    var st = document.createElement('style'); st.textContent = CSS; document.head.appendChild(st);
    S.root = el('div'); S.root.id = 'n365h'; S.root.setAttribute('role', 'dialog'); S.root.setAttribute('aria-modal', 'true'); S.root.setAttribute('aria-label', 'Bills and services');
    var p = el('div', 'p'), h = el('div', 'h');
    S.backBtn = el('button', 'x', '‹'); S.backBtn.setAttribute('aria-label', 'Back'); S.backBtn.style.display = 'none';
    S.backBtn.addEventListener('click', function () { if (S.back) S.back(); });
    S.title = el('b', null, 'Bills & Services');
    var x = el('button', 'x', '×'); x.setAttribute('aria-label', 'Close'); x.addEventListener('click', close);
    add(h, S.backBtn, S.title, x); S.body = el('div', 'bd'); add(p, h, S.body); S.root.appendChild(p);
    S.root.addEventListener('click', function (e) { if (e.target === S.root) close(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });
    document.body.appendChild(S.root);
  }
  function close() { if (S.root) S.root.classList.remove('on'); }
  function screen(title, back) { S.title.textContent = title; clear(); S.back = back || null; S.backBtn.style.display = back ? '' : 'none'; S.body.scrollTop = 0; }
  function errBox() { return el('div', 'e'); }
  function showErr(box, msg) { box.textContent = msg || 'Something went wrong. Please try again.'; box.style.display = 'block'; }
  function field(label, input) { var w = el('div'); add(w, el('label', null, label), input); return w; }
  function textInput(type, ph, max) { var i = el('input'); i.type = type || 'text'; if (ph) i.placeholder = ph; if (max) i.maxLength = max; i.autocomplete = 'off'; return i; }
  function select(options) { var s = el('select'); options.forEach(function (o) { var op = el('option', null, o[1]); op.value = o[0]; s.appendChild(op); }); return s; }
  function needSignIn(r) {
    if (r.status !== 401) return false;
    screen('Sign in', home);
    add(S.body, el('p', null, 'Please sign in to continue.'), el('p', 'm', 'Your account keeps your receipts and lets us deliver tokens and PINs to you.'));
    var b = el('button', 'go', 'Sign in'); b.addEventListener('click', function () {
      close();
      try { if (typeof showLoginScreen === 'function') showLoginScreen(); else if (typeof fromUserMenuAuth === 'function') fromUserMenuAuth(); } catch (e) { /* page has its own sign-in */ }
    }); S.body.appendChild(b); return true;
  }
  function payNow(btn, errEl, path, body) {
    if (S.busy) return; S.busy = true; btn.disabled = true; var old = btn.textContent; btn.textContent = 'Preparing payment...'; errEl.style.display = 'none';
    post(path, body).then(function (r) {
      S.busy = false;
      if (needSignIn(r)) return;
      if (r.ok && r.data && r.data.success && r.data.authorization_url) { btn.textContent = 'Opening payment page...'; window.location.href = r.data.authorization_url; return; }
      showErr(errEl, (r.data && (r.data.error || r.data.message)) || (r.status === 403 ? 'Please verify your email first.' : null)); btn.disabled = false; btn.textContent = old;
    }).catch(function () { S.busy = false; showErr(errEl, 'No connection. Please try again.'); btn.disabled = false; btn.textContent = old; });
  }
  function userPhone() { try { return (typeof currentUser !== 'undefined' && currentUser && currentUser.phone) ? String(currentUser.phone) : ''; } catch (e) { return ''; } }

  /* ---------------------------------------------------------------- home */
  function home() {
    screen('Bills & Services', null);
    add(S.body, el('p', 'm', 'Pick what you need. You pay securely online and we deliver to your account.'));
    var g = el('div', 'grid');
    SERVICES.forEach(function (s) {
      var st = (S.cfg && S.cfg.services && S.cfg.services[s[0]]) || 'off';
      if (st === 'off') return;
      var b = el('button', 'tile'), i = el('span', 'ico'); i.style.background = s[4]; var ic = el('i', 'fas ' + s[3]); i.appendChild(ic);
      add(b, i, el('b', null, s[1]), el('small', null, st === 'live' ? s[2] : 'Coming soon'));
      if (st !== 'live') b.disabled = true; else b.addEventListener('click', function () { go(s[0]); });
      g.appendChild(b);
    });
    S.body.appendChild(g);
    add(S.body, el('p', 'm', 'Country: Nigeria. More countries are coming soon.'));
  }
  function go(svc) {
    var st = S.cfg && S.cfg.services && S.cfg.services[svc];
    if (st !== 'live') { screen('Coming soon', home); add(S.body, el('p', null, 'This service is not open yet. Please check back soon.')); return; }
    ({ electricity: elecList, tv: tvProducts, data: dataNetworks, education: eduProducts, insurance: insPlans })[svc]();
  }

  /* ---------------------------------------------------------------- electricity */
  function elecList() {
    screen('Electricity', home); add(S.body, el('p', 'm', 'Loading electricity companies...'));
    api('/api/electricity/providers?country=NG').then(function (r) {
      screen('Electricity', home);
      if (!r.ok || !r.data.success) { add(S.body, el('p', null, (r.data && r.data.error) || 'Electricity is unavailable right now. Please try again shortly.')); return; }
      var q = textInput('search', 'Search your electricity company'), box = el('div');
      add(S.body, q, box);
      function draw() {
        while (box.firstChild) box.removeChild(box.firstChild);
        var t = q.value.trim().toLowerCase();
        r.data.discos.filter(function (d) { return !t || d.name.toLowerCase().indexOf(t) >= 0; }).forEach(function (d) {
          var b = el('button', 'row'), l = el('b', null, d.name);
          d.providers.forEach(function (p) { l.appendChild(el('span', 'tag', PNAME[p] || p)); });
          b.appendChild(l); b.addEventListener('click', function () { elecForm(d); }); box.appendChild(b);
        });
        if (!box.firstChild) box.appendChild(el('p', 'm', 'No match. Try another name.'));
      }
      q.addEventListener('input', draw); draw();
    }).catch(function () { screen('Electricity', home); add(S.body, el('p', null, 'No connection. Please try again.')); });
  }
  function elecForm(d) {
    screen(d.name, elecList);
    var pref = 'auto', verified = false;
    var chips = el('div', 'chips');
    var meterType = select([['prepaid', 'Prepaid'], ['postpaid', 'Postpaid']]), meter = textInput('text', 'Meter number', 20), phone = textInput('tel', '08012345678', 15), amount = textInput('number', 'Amount in ' + NAIRA);
    amount.min = '0'; amount.inputMode = 'numeric'; phone.value = userPhone();
    var info = el('div'), err = errBox(), checkBtn = el('button', 'sec', 'Check meter'), payBtn = el('button', 'go', 'Pay'); payBtn.disabled = true;
    function reset() { verified = false; payBtn.disabled = true; while (info.firstChild) info.removeChild(info.firstChild); }
    function setPref(p) { pref = p; Array.prototype.forEach.call(chips.children, function (c) { c.classList.toggle('on', c.getAttribute('data-p') === p); }); reset(); }
    if (d.choosable) {
      add(S.body, el('label', null, 'Who should process this payment?'));
      var opts = [['auto', 'Best option (recommended)']].concat(d.providers.map(function (p) { return [p, PNAME[p] || p]; }));
      opts.forEach(function (o) { var c = el('button', 'chip', o[1]); c.type = 'button'; c.setAttribute('data-p', o[0]); c.addEventListener('click', function () { setPref(o[0]); }); chips.appendChild(c); });
      S.body.appendChild(chips); setPref('auto');
    } else add(S.body, el('p', 'm', 'Processed by ' + (PNAME[d.providers[0]] || d.providers[0]) + '.'));
    add(S.body, field('Meter type', meterType), field('Meter number', meter), field('Phone number (for your receipt)', phone), field('Amount', amount), checkBtn, info, payBtn, err);
    [meterType, meter].forEach(function (x) { x.addEventListener('input', reset); x.addEventListener('change', reset); });
    var min = 500;
    function upd() { var v = Number(amount.value); payBtn.textContent = v > 0 ? 'Pay ' + money(v) : 'Pay'; payBtn.disabled = !(verified && v >= min); }
    amount.addEventListener('input', upd);
    checkBtn.addEventListener('click', function () {
      err.style.display = 'none'; reset(); checkBtn.disabled = true; checkBtn.textContent = 'Checking...';
      post('/api/electricity/verify', { key: d.key, provider: pref, meter: meter.value, meter_type: meterType.value }).then(function (r) {
        checkBtn.disabled = false; checkBtn.textContent = 'Check meter';
        if (needSignIn(r)) return;
        if (r.ok && r.data.success) {
          verified = true; min = r.data.min_amount || 500;
          var ok = el('div', 'ok'); add(ok, el('b', null, r.data.name || 'Meter found'), r.data.address ? el('div', 'm', r.data.address) : null, el('div', 'm', 'Minimum purchase ' + money(min)));
          info.appendChild(ok); upd();
        } else showErr(err, r.data && (r.data.error || r.data.message));
      }).catch(function () { checkBtn.disabled = false; checkBtn.textContent = 'Check meter'; showErr(err, 'No connection. Please try again.'); });
    });
    payBtn.addEventListener('click', function () {
      payNow(payBtn, err, '/api/electricity/checkout', { key: d.key, provider: pref, meter: meter.value, meter_type: meterType.value, phone: phone.value, amount: Number(amount.value) });
    });
  }

  /* ---------------------------------------------------------------- plan-based services: TV, data, education */
  function productList(title, items, next) {
    screen(title, home);
    items.forEach(function (it) { var b = el('button', 'row'); b.appendChild(el('b', null, it[1])); b.addEventListener('click', function () { next(it); }); S.body.appendChild(b); });
  }
  function loadPlans(url, title, back, ready) {
    screen(title, back); add(S.body, el('p', 'm', 'Loading plans...'));
    api(url).then(function (r) {
      screen(title, back);
      var plans = r.data && r.data.plans;
      if (!r.ok || !plans || !plans.length) { add(S.body, el('p', null, (r.data && r.data.error) || 'Plans are unavailable right now. Please try again shortly.')); return; }
      ready(plans.slice().sort(function (a, b) { return a.price - b.price; }));
    }).catch(function () { screen(title, back); add(S.body, el('p', null, 'No connection. Please try again.')); });
  }
  function planRows(plans, pick) {
    plans.forEach(function (p) { var b = el('button', 'row'); add(b, el('b', null, p.name), el('div', 'm', money(p.price))); b.addEventListener('click', function () { pick(p); }); S.body.appendChild(b); });
  }

  function tvProducts() { productList('Cable TV', TV, function (it) { loadPlans('/api/services/catalog?product=' + it[0], it[1], tvProducts, function (plans) { add(S.body, el('p', 'm', 'Choose a package')); planRows(plans, function (p) { tvForm(it, p); }); }); }); }
  function tvForm(prod, plan) {
    screen(prod[1], function () { tvProducts(); });
    var card = prod[0] !== 'showmax', verified = !card, err = errBox(), info = el('div');
    var acct = textInput('text', 'Smartcard / IUC number', 16), phone = textInput('tel', '08012345678', 15); phone.value = userPhone();
    var payBtn = el('button', 'go', 'Pay ' + money(plan.price)), chk = el('button', 'sec', 'Check smartcard'); payBtn.disabled = card;
    add(S.body, el('p', null, plan.name + ' - ' + money(plan.price)));
    if (card) { add(S.body, field('Smartcard number', acct), chk, info); acct.addEventListener('input', function () { verified = false; payBtn.disabled = true; while (info.firstChild) info.removeChild(info.firstChild); }); }
    add(S.body, field('Phone number', phone), payBtn, err);
    chk.addEventListener('click', function () {
      err.style.display = 'none'; chk.disabled = true; chk.textContent = 'Checking...';
      post('/api/services/verify', { product: prod[0], billers_code: acct.value }).then(function (r) {
        chk.disabled = false; chk.textContent = 'Check smartcard'; if (needSignIn(r)) return;
        if (r.ok && r.data.success) { verified = true; payBtn.disabled = false; var ok = el('div', 'ok'); add(ok, el('b', null, r.data.name || 'Smartcard found'), r.data.bouquet ? el('div', 'm', 'Current: ' + r.data.bouquet) : null); info.appendChild(ok); }
        else showErr(err, r.data && (r.data.error || r.data.message));
      }).catch(function () { chk.disabled = false; chk.textContent = 'Check smartcard'; showErr(err, 'No connection. Please try again.'); });
    });
    payBtn.addEventListener('click', function () { if (!verified) return; payNow(payBtn, err, '/api/services/checkout', { service: 'tv', product: prod[0], variation_code: plan.code, billers_code: acct.value, phone: phone.value, subscription_type: 'change' }); });
  }

  function dataNetworks() { productList('Data', NET, function (it) { loadPlans('/api/data/plans?network=' + it[0], it[1] + ' data', dataNetworks, function (plans) { add(S.body, el('p', 'm', 'Choose a bundle')); planRows(plans, function (p) { dataForm(it, p); }); }); }); }
  function dataForm(net, plan) {
    screen(net[1] + ' data', function () { dataNetworks(); });
    var phone = textInput('tel', '08012345678', 15), err = errBox(), payBtn = el('button', 'go', 'Pay ' + money(plan.price)); phone.value = userPhone();
    add(S.body, el('p', null, plan.name + ' - ' + money(plan.price)), field('Phone number to credit', phone), payBtn, err);
    payBtn.addEventListener('click', function () { payNow(payBtn, err, '/api/services/checkout', { service: 'data', product: net[0], variation_code: plan.code, phone: phone.value }); });
  }

  function eduProducts() { productList('Education', EDU, function (it) { loadPlans('/api/services/catalog?product=' + it[0], it[1], eduProducts, function (plans) { add(S.body, el('p', 'm', 'Choose an option')); planRows(plans, function (p) { eduForm(it, p); }); }); }); }
  function eduForm(prod, plan) {
    screen(prod[1], function () { eduProducts(); });
    var jamb = prod[0] === 'jamb', verified = !jamb, err = errBox(), info = el('div');
    var profile = textInput('text', 'JAMB profile code', 16), phone = textInput('tel', '08012345678', 15), qty = select([['1', '1'], ['2', '2'], ['3', '3'], ['4', '4'], ['5', '5']]);
    phone.value = userPhone();
    var payBtn = el('button', 'go', 'Pay ' + money(plan.price)), chk = el('button', 'sec', 'Check profile'); payBtn.disabled = jamb;
    add(S.body, el('p', null, plan.name + ' - ' + money(plan.price)));
    if (jamb) { add(S.body, field('JAMB profile code', profile), chk, info); profile.addEventListener('input', function () { verified = false; payBtn.disabled = true; while (info.firstChild) info.removeChild(info.firstChild); }); }
    else { add(S.body, field('How many PINs?', qty)); qty.addEventListener('change', function () { payBtn.textContent = 'Pay ' + money(plan.price * Number(qty.value)); }); }
    add(S.body, field('Phone number (the PIN is also sent to your account)', phone), payBtn, err);
    chk.addEventListener('click', function () {
      err.style.display = 'none'; chk.disabled = true; chk.textContent = 'Checking...';
      post('/api/services/verify', { product: 'jamb', billers_code: profile.value, variation_code: plan.code }).then(function (r) {
        chk.disabled = false; chk.textContent = 'Check profile'; if (needSignIn(r)) return;
        if (r.ok && r.data.success) { verified = true; payBtn.disabled = false; var ok = el('div', 'ok'); add(ok, el('b', null, r.data.name || 'Profile found')); info.appendChild(ok); }
        else showErr(err, r.data && (r.data.error || r.data.message));
      }).catch(function () { chk.disabled = false; chk.textContent = 'Check profile'; showErr(err, 'No connection. Please try again.'); });
    });
    payBtn.addEventListener('click', function () {
      if (!verified) return;
      payNow(payBtn, err, '/api/services/checkout', { service: 'education', product: prod[0], variation_code: plan.code, billers_code: jamb ? profile.value : '', phone: phone.value, quantity: jamb ? 1 : Number(qty.value) });
    });
  }

  /* ---------------------------------------------------------------- insurance */
  function insPlans() {
    screen('Motor insurance', home); add(S.body, el('p', 'm', 'Loading cover options...'));
    api('/api/insurance/products').then(function (r) {
      screen('Motor insurance', home);
      var prod = r.ok && r.data.success && r.data.products && r.data.products[0];
      if (!prod) { add(S.body, el('p', null, (r.data && r.data.error) || 'Insurance is unavailable right now. Please try again shortly.')); return; }
      add(S.body, el('p', 'm', 'Third-party motor insurance is the legal minimum cover. Choose your vehicle type.'));
      planRows(prod.plans.slice().sort(function (a, b) { return a.price - b.price; }), function (p) { insForm(prod, p); });
    }).catch(function () { screen('Motor insurance', home); add(S.body, el('p', null, 'No connection. Please try again.')); });
  }
  function insForm(prod, plan) {
    screen('Vehicle details', insPlans);
    var F = [['Insured_Name', 'Owner\'s full name', 'text', 60], ['Plate_Number', 'Plate number', 'text', 12], ['Chasis_Number', 'Chassis number (VIN)', 'text', 25],
      ['vehicle_Make', 'Vehicle make (e.g. Toyota)', 'text', 30], ['vehicle_Model', 'Vehicle model (e.g. Corolla)', 'text', 30], ['vehicle_Color', 'Colour', 'text', 30],
      ['YearofMake', 'Year made (e.g. 2018)', 'number', 4], ['engine_capacity', 'Engine size in cc (e.g. 1600)', 'number', 5], ['state', 'State', 'text', 40],
      ['lga', 'Local government area', 'text', 40], ['email', 'Email for your certificate', 'email', 120]];
    var inputs = {}, err = errBox();
    add(S.body, el('p', null, plan.name + ' - ' + money(plan.price)), el('p', 'm', 'Enter the details exactly as they appear on the vehicle papers. They go on your policy and cannot be changed afterwards.'));
    F.forEach(function (f) { var i = textInput(f[2], '', f[3]); if (f[0] === 'email') { try { if (typeof currentUser !== 'undefined' && currentUser && currentUser.email) i.value = currentUser.email; } catch (e) { /* none */ } } inputs[f[0]] = i; S.body.appendChild(field(f[1], i)); });
    var phone = textInput('tel', '08012345678', 15); phone.value = userPhone(); S.body.appendChild(field('Phone number', phone));
    var acc = el('input'); acc.type = 'checkbox';
    var lab = el('label', 'chk'); lab.appendChild(acc);
    var sp = el('span'); add(sp, document.createTextNode('I confirm these details are correct and I accept the insurance terms in the '), (function () { var a = el('a', null, 'Terms of Service'); a.href = '/terms'; a.target = '_blank'; a.rel = 'noopener'; return a; })(), document.createTextNode('.'));
    lab.appendChild(sp); S.body.appendChild(lab);
    var payBtn = el('button', 'go', 'Pay ' + money(plan.price)); payBtn.disabled = true; add(S.body, payBtn, err);
    acc.addEventListener('change', function () { payBtn.disabled = !acc.checked; });
    payBtn.addEventListener('click', function () {
      var details = {}; Object.keys(inputs).forEach(function (k) { details[k] = inputs[k].value; });
      payNow(payBtn, err, '/api/insurance/checkout', { product: prod.product, variation_code: plan.code, details: details, phone: phone.value, accept: acc.checked });
    });
  }

  /* ---------------------------------------------------------------- entry points */
  function loadCfg() {
    if (S.cfg) return Promise.resolve(S.cfg);
    return api('/api/hub/config').then(function (r) { if (r.ok && r.data.success) S.cfg = r.data; return S.cfg; }).catch(function () { return null; });
  }
  function open(svc) {
    build(); S.root.classList.add('on'); screen('Bills & Services', null); add(S.body, el('p', 'm', 'Loading...'));
    loadCfg().then(function (cfg) {
      if (!cfg) { screen('Bills & Services', null); add(S.body, el('p', null, 'Could not load services. Please check your connection and try again.')); return; }
      if (svc) go(svc); else home();
    });
  }
  /* Elements marked data-hub="insurance" (etc.) stay hidden until that service is switched on. */
  function revealTiles() {
    loadCfg().then(function (cfg) {
      if (!cfg) return;
      Array.prototype.forEach.call(document.querySelectorAll('[data-hub]'), function (n) {
        var st = cfg.services[n.getAttribute('data-hub')];
        if (st && st !== 'off') n.style.display = '';
      });
    });
  }
  window.Net365Hub = { open: open, reveal: revealTiles };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', revealTiles); else revealTiles();
})();

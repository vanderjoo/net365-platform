/* Net365 admin dashboards: "Reports" (sales, profit, funnel) and "Visitor Intel" (visitor intelligence, conversion, alerts).
 * Self-contained: draws its own SVG charts (no Chart.js / CDN). Needs only the page's adminFetch() and two panels:
 *   <div id="tab-insights" class="tab-panel"></div>   <div id="tab-intel" class="tab-panel"></div>
 * Entry points: loadInsights(), loadIntel(). */
(function () {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';
  var R = { days: 30, data: null, funnel: null, sources: null };
  var V = { days: 30, segment: 'all', q: '', over: null, conv: null, list: null, alerts: null, open: null };

  // ------------------------------------------------------------------ styles
  var CSS = '' +
    '.ix-scope{--ix-blue:#2a78d6;--ix-orange:#eb6834;--ix-aqua:#1baf7a;--ix-violet:#6250d6;--ix-red:#c93434;--ix-amber:#b7791f;--ix-heat:42,120,214;--ix-text:#1e293b;--ix-muted:#64748b;--ix-line:#e2e8f0;--ix-surface:#ffffff}' +
    'body.dark-mode .ix-scope{--ix-blue:#3987e5;--ix-orange:#d95926;--ix-aqua:#199e70;--ix-violet:#9085e9;--ix-red:#e66a6a;--ix-amber:#e0a43a;--ix-heat:57,135,229;--ix-text:#e2e8f0;--ix-muted:#94a3b8;--ix-line:#334155;--ix-surface:#1e293b}' +
    '.ix-bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:16px}' +
    '.ix-bar h3{margin:0 auto 0 0}' +
    '.ix-bar select,.ix-bar button,.ix-bar input{padding:8px 12px;border-radius:8px;border:1px solid var(--ix-line);background:var(--ix-surface);color:var(--ix-text);font:inherit;cursor:pointer;max-width:100%}' +
    '.ix-bar input{cursor:text;min-width:180px}' +
    '.ix-h{margin:22px 0 10px;font-size:16px;color:var(--ix-text)}' +
    '.ix-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}' +
    '.ix-kpi{background:var(--ix-surface);border:1px solid var(--ix-line);border-radius:12px;padding:14px 16px}' +
    '.ix-kpi .k{font-size:12px;color:var(--ix-muted)}' +
    '.ix-kpi .v{font-size:24px;font-weight:700;margin:4px 0 2px;color:var(--ix-text);font-variant-numeric:tabular-nums}' +
    '.ix-kpi .d{font-size:12px;color:var(--ix-muted)}' +
    '.ix-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:16px;margin-bottom:16px}' +
    '.ix-card{background:var(--ix-surface);border:1px solid var(--ix-line);border-radius:12px;padding:16px;min-width:0;color:var(--ix-text)}' +
    '.ix-card h4{margin:0 0 2px;font-size:15px}' +
    '.ix-card .sub{font-size:12px;color:var(--ix-muted);margin-bottom:12px}' +
    '.ix-chart{position:relative;height:240px}.ix-chart svg{display:block;overflow:visible}' +
    '.ix-chart.tall{height:300px}' +
    '.ix-legend{display:flex;gap:14px;font-size:12px;color:var(--ix-muted);margin:-4px 0 8px}' +
    '.ix-legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px}' +
    '.ix-table{width:100%;border-collapse:collapse;font-size:13px}' +
    '.ix-table th{text-align:left;font-weight:600;color:var(--ix-muted);padding:6px 8px;border-bottom:1px solid var(--ix-line);white-space:nowrap}' +
    '.ix-table td{padding:7px 8px;border-bottom:1px solid var(--ix-line);color:var(--ix-text);font-variant-numeric:tabular-nums;vertical-align:top}' +
    '.ix-table td.n,.ix-table th.n{text-align:right}' +
    '.ix-table tr.ix-row{cursor:pointer}.ix-table tr.ix-row:hover td{background:rgba(var(--ix-heat),.07)}' +
    '.ix-meter{height:8px;border-radius:4px;background:var(--ix-line);overflow:hidden;min-width:70px}' +
    '.ix-meter i{display:block;height:100%;background:var(--ix-blue);border-radius:4px}' +
    '.ix-note{font-size:12px;color:var(--ix-muted);margin:8px 0 0}' +
    '.ix-warn{border-left:3px solid var(--ix-amber);padding:8px 12px;background:var(--ix-surface);border:1px solid var(--ix-line);border-left:3px solid var(--ix-amber);border-radius:6px;font-size:12px;color:var(--ix-muted);margin-bottom:10px}' +
    '.ix-err{border-left-color:var(--ix-red);color:var(--ix-text)}' +
    '.ix-empty{padding:28px 0;text-align:center;color:var(--ix-muted);font-size:13px}' +
    '.ix-card details{margin-top:10px;font-size:12px;color:var(--ix-muted)}.ix-card summary{cursor:pointer}' +
    '.ix-scroll{overflow-x:auto}' +
    '.ix-b{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid var(--ix-line);white-space:nowrap;color:var(--ix-text)}' +
    '.ix-b.hi{background:rgba(var(--ix-heat),.16);border-color:rgba(var(--ix-heat),.5)}' +
    '.ix-b.med{background:rgba(var(--ix-heat),.07)}' +
    '.ix-b.unc{border-color:var(--ix-amber);color:var(--ix-amber)}' +
    '.ix-b.bot{border-style:dashed;color:var(--ix-muted)}' +
    '.ix-b.sev-high{border-color:var(--ix-red);color:var(--ix-red)}' +
    '.ix-alert{display:flex;gap:10px;align-items:flex-start;padding:8px 0;border-bottom:1px solid var(--ix-line);font-size:13px}' +
    '.ix-alert:last-child{border-bottom:0}.ix-alert .t{font-weight:600}.ix-alert .m{color:var(--ix-muted);font-size:12px;margin-top:2px;word-break:break-word}' +
    '.ix-detail td{background:rgba(var(--ix-heat),.05)}' +
    '.ix-vcard{padding:6px 4px;max-width:900px}' +
    '.ix-vcard .hd{font-weight:700;letter-spacing:.3px;margin-bottom:10px}' +
    '.ix-vcard dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0 0 10px}' +
    '.ix-vcard dt{color:var(--ix-muted)}.ix-vcard dd{margin:0}' +
    '.ix-vcard ul{list-style:none;margin:4px 0 10px;padding:0;display:flex;flex-wrap:wrap;gap:4px 18px}' +
    '.ix-tip{position:fixed;z-index:99999;display:none;pointer-events:none;max-width:280px;padding:8px 10px;border-radius:8px;font-size:12px;line-height:1.45;box-shadow:0 6px 24px rgba(0,0,0,.25);background:#fff;color:#1e293b;border:1px solid #e2e8f0}' +
    'body.dark-mode .ix-tip{background:#0f172a;color:#e2e8f0;border-color:#334155}' +
    '.ix-badge{display:inline-block;min-width:18px;padding:0 6px;margin-left:6px;border-radius:999px;background:#c93434;color:#fff;font-size:11px;line-height:18px;text-align:center}';

  // ------------------------------------------------------------------ helpers
  function $(id) { return document.getElementById(id); }
  function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
  function css(name) { var el = document.querySelector('.ix-scope') || document.body; return getComputedStyle(el).getPropertyValue(name).trim(); }
  function naira(n, compact) {
    n = Number(n) || 0;
    if (compact && Math.abs(n) >= 1e6) return '₦' + (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
    if (compact && Math.abs(n) >= 1e4) return '₦' + (n / 1e3).toFixed(0) + 'k';
    return '₦' + n.toLocaleString('en-NG', { maximumFractionDigits: 0 });
  }
  function num(n) { return (Number(n) || 0).toLocaleString('en-NG'); }
  function cnum(n) { n = Number(n) || 0; return Math.abs(n) >= 10000 ? (n / 1000).toFixed(0) + 'k' : (n % 1 ? n.toFixed(1) : String(n)); }
  function pct(n) { return n == null ? '–' : n + '%'; }
  var RN = null; try { RN = new Intl.DisplayNames(['en'], { type: 'region' }); } catch (e) {}
  function cname(c) { if (!c) return '—'; try { return (RN && RN.of(c)) || c; } catch (e) { return c; } }
  function when(s) { if (!s) return ''; var m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})/); if (!m) return s; return m[3] + '/' + m[2] + ' ' + m[4]; }
  function apiError(e) {
    var m = String(e && e.message || e || 'unknown error');
    if (/unexpected token|JSON|<!doctype/i.test(m)) return 'The reports API was not found on the server (404). Upload net365_insights.py and net365_visitor_intel.py next to app.py, use the updated app.py, then redeploy.';
    if (/unauthorized/i.test(m)) return 'Not authorised. Unlock the admin panel again.';
    return m;
  }
  async function api(path) {
    try { return await adminFetch(path); } catch (e) { return { success: false, error: apiError(e) }; }
  }
  function S(tag, attrs, parent, text) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = text;
    if (parent) parent.appendChild(e);
    return e;
  }
  function inject() {
    if (document.getElementById('ix-style')) return;
    var st = document.createElement('style'); st.id = 'ix-style'; st.textContent = CSS; document.head.appendChild(st);
  }
  function card(t, s, body) { return '<div class="ix-card"><h4>' + t + '</h4><div class="sub">' + s + '</div>' + body + '</div>'; }
  function chartBox(id, tall) { return '<div class="ix-chart' + (tall ? ' tall' : '') + '" id="' + id + '"></div>'; }
  function tile(label, value, delta) {
    var d = delta === undefined ? '' : (delta == null ? 'no previous data' : (delta >= 0 ? '▲ ' : '▼ ') + Math.abs(delta) + '% vs previous period');
    return '<div class="ix-kpi"><div class="k">' + label + '</div><div class="v">' + value + '</div><div class="d">' + d + '</div></div>';
  }
  function tableOrEmpty(html, hasRows, msg) { return hasRows ? html : '<div class="ix-empty">' + esc(msg) + '</div>'; }

  // ------------------------------------------------------------------ tooltip + svg charts
  var tipEl = null;
  function tip(ev, lines) {
    if (!tipEl) { tipEl = document.createElement('div'); tipEl.className = 'ix-tip'; document.body.appendChild(tipEl); }
    tipEl.innerHTML = lines.map(function (l, i) { return i === 0 ? '<b>' + esc(l) + '</b>' : '<div>' + esc(l) + '</div>'; }).join('');
    tipEl.style.display = 'block';
    var x = ev.clientX + 14, y = ev.clientY + 14, w = tipEl.offsetWidth, h = tipEl.offsetHeight;
    if (x + w > innerWidth - 8) x = Math.max(8, ev.clientX - w - 14);
    if (y + h > innerHeight - 8) y = Math.max(8, ev.clientY - h - 14);
    tipEl.style.left = x + 'px'; tipEl.style.top = y + 'px';
  }
  function untip() { if (tipEl) tipEl.style.display = 'none'; }
  function niceMax(v) {
    if (v <= 0) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(v))), m = v / p;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10) * p;
  }
  function mount(el, draw) {
    if (!el) return;
    el._draw = draw;
    draw();
    if (!el._ro && window.ResizeObserver) {
      el._ro = new ResizeObserver(function () { if (el._w !== el.clientWidth && el.clientWidth) el._draw(); });
      el._ro.observe(el);
    }
  }
  function empty(el, msg) { el.innerHTML = '<div class="ix-empty">' + esc(msg || 'No data in this period') + '</div>'; }
  function barPath(x, y, w, h, r) {
    r = Math.max(0, Math.min(r, w / 2, h));
    return 'M' + x + ',' + (y + h) + 'L' + x + ',' + (y + r) + 'Q' + x + ',' + y + ' ' + (x + r) + ',' + y + 'L' + (x + w - r) + ',' + y +
      'Q' + (x + w) + ',' + y + ' ' + (x + w) + ',' + (y + r) + 'L' + (x + w) + ',' + (y + h) + 'Z';
  }
  function axes(svg, W, H, m, max, yfmt, grid, muted) {
    var ticks = [0, 1, 2, 3, 4];
    ticks.forEach(function (i) {
      var y = m.t + (H - m.t - m.b) * (1 - i / 4);
      S('line', { x1: m.l, x2: W - m.r, y1: y, y2: y, stroke: grid, 'stroke-width': 1 }, svg);
      S('text', { x: m.l - 6, y: y + 4, 'text-anchor': 'end', 'font-size': 11, fill: muted }, svg, yfmt(max * i / 4));
    });
  }
  function leftMargin(max, yfmt) {
    var w = 0; [0, 1, 2, 3, 4].forEach(function (i) { w = Math.max(w, String(yfmt(max * i / 4)).length); });
    return w * 6.4 + 14;
  }
  function labelsRow(svg, labels, W, H, m, band, centered) {
    var pw = W - m.l - m.r, n = labels.length, step = Math.max(1, Math.ceil(n / Math.max(1, Math.floor(pw / 46))));
    labels.forEach(function (lb, i) {
      if (i % step) return;
      S('text', { x: m.l + band * i + (centered ? band / 2 : 0), y: H - 6, 'text-anchor': 'middle', 'font-size': 11, fill: css('--ix-muted') }, svg, lb);
    });
  }
  function barChart(el, o) {
    mount(el, function () {
      el.innerHTML = '';
      var n = o.values.length, mx = Math.max.apply(null, o.values.concat([0]));
      if (!n || mx <= 0) return empty(el, o.empty);
      var W = el.clientWidth || 320, H = el.clientHeight || 240; el._w = W;
      var max = niceMax(mx), yfmt = o.yfmt || cnum, grid = css('--ix-line'), muted = css('--ix-muted'), color = o.color || css('--ix-blue');
      var m = { l: leftMargin(max, yfmt), r: 8, t: 10, b: 24 }, pw = W - m.l - m.r, ph = H - m.t - m.b, band = pw / n, bw = Math.min(30, band * 0.7);
      var svg = S('svg', { width: W, height: H, viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': o.aria || 'Bar chart' }, el);
      axes(svg, W, H, m, max, yfmt, grid, muted);
      var hov = S('rect', { y: m.t, height: ph, width: band, fill: color, 'fill-opacity': 0 }, svg);
      o.values.forEach(function (v, i) {
        var h = ph * v / max; if (v > 0 && h < 2) h = 2;
        if (v > 0) S('path', { d: barPath(m.l + band * i + (band - bw) / 2, m.t + ph - h, bw, h, 4), fill: color }, svg);
      });
      labelsRow(svg, o.labels, W, H, m, band, true);
      var hit = S('rect', { x: m.l, y: m.t, width: pw, height: ph, fill: 'transparent' }, svg);
      function at(ev) {
        var r = svg.getBoundingClientRect(), i = Math.min(n - 1, Math.max(0, Math.floor((ev.clientX - r.left - m.l) / band)));
        hov.setAttribute('x', m.l + band * i); hov.setAttribute('fill-opacity', 0.1); tip(ev, o.tip(i));
      }
      hit.addEventListener('pointermove', at); hit.addEventListener('pointerdown', at);
      hit.addEventListener('pointerleave', function () { hov.setAttribute('fill-opacity', 0); untip(); });
    });
  }
  function hbarChart(el, o) {
    mount(el, function () {
      el.innerHTML = '';
      var n = o.values.length, mx = Math.max.apply(null, o.values.concat([0]));
      if (!n || mx <= 0) { el.style.height = ''; return empty(el, o.empty); }
      var rowH = 28, H = n * rowH + 6; el.style.height = H + 'px';
      var W = el.clientWidth || 320; el._w = W;
      var vfmt = o.vfmt || num, color = o.color || css('--ix-blue'), text = css('--ix-text');
      var lab = o.labels.map(function (l) { l = String(l); return l.length > 24 ? l.slice(0, 23) + '…' : l; });
      var labW = Math.min(170, Math.max.apply(null, lab.map(function (l) { return l.length; })) * 6.4 + 10);
      var valW = Math.max.apply(null, o.values.map(function (v) { return String(vfmt(v)).length; })) * 6.8 + 12;
      var pw = Math.max(20, W - labW - valW - 6);
      var svg = S('svg', { width: W, height: H, viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': o.aria || 'Bar chart' }, el);
      o.values.forEach(function (v, i) {
        var y = 3 + i * rowH, w = v > 0 ? Math.max(2, pw * v / mx) : 0;
        var bg = S('rect', { x: 0, y: y, width: W, height: rowH, fill: color, 'fill-opacity': 0 }, svg);
        S('text', { x: labW - 8, y: y + rowH / 2 + 4, 'text-anchor': 'end', 'font-size': 12, fill: text }, svg, lab[i]);
        if (w) S('rect', { x: labW, y: y + 5, width: w, height: rowH - 10, rx: 4, fill: color }, svg);
        S('text', { x: labW + w + 6, y: y + rowH / 2 + 4, 'font-size': 12, fill: text }, svg, vfmt(v));
        var hit = S('rect', { x: 0, y: y, width: W, height: rowH, fill: 'transparent' }, svg);
        var f = function (ev) { bg.setAttribute('fill-opacity', 0.08); tip(ev, o.tip ? o.tip(i) : [o.labels[i], vfmt(v)]); };
        hit.addEventListener('pointermove', f); hit.addEventListener('pointerdown', f);
        hit.addEventListener('pointerleave', function () { bg.setAttribute('fill-opacity', 0); untip(); });
      });
    });
  }
  function lineChart(el, o) {
    mount(el, function () {
      el.innerHTML = '';
      var n = o.labels.length, mx = 0;
      o.series.forEach(function (s) { mx = Math.max(mx, Math.max.apply(null, s.values.concat([0]))); });
      if (!n || mx <= 0) return empty(el, o.empty);
      var W = el.clientWidth || 320, H = el.clientHeight || 240; el._w = W;
      var max = niceMax(mx), yfmt = o.yfmt || cnum, grid = css('--ix-line'), muted = css('--ix-muted');
      var m = { l: leftMargin(max, yfmt), r: 10, t: 10, b: 24 }, pw = W - m.l - m.r, ph = H - m.t - m.b;
      var X = function (i) { return m.l + (n > 1 ? pw * i / (n - 1) : pw / 2); }, Y = function (v) { return m.t + ph - ph * v / max; };
      var svg = S('svg', { width: W, height: H, viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': o.aria || 'Line chart' }, el);
      axes(svg, W, H, m, max, yfmt, grid, muted);
      var step = Math.max(1, Math.ceil(n / Math.max(1, Math.floor(pw / 46))));
      o.labels.forEach(function (lb, i) { if (i % step === 0) S('text', { x: X(i), y: H - 6, 'text-anchor': 'middle', 'font-size': 11, fill: muted }, svg, lb); });
      o.series.forEach(function (s) {
        S('path', { d: s.values.map(function (v, i) { return (i ? 'L' : 'M') + X(i) + ',' + Y(v); }).join(''), fill: 'none', stroke: s.color, 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }, svg);
      });
      var g = S('g', { visibility: 'hidden' }, svg), vl = S('line', { y1: m.t, y2: m.t + ph, stroke: muted, 'stroke-width': 1, 'stroke-dasharray': '3 3' }, g);
      var dots = o.series.map(function (s) { return S('circle', { r: 4.5, fill: s.color, stroke: css('--ix-surface'), 'stroke-width': 2 }, g); });
      var hit = S('rect', { x: m.l, y: m.t, width: pw, height: ph, fill: 'transparent' }, svg);
      function at(ev) {
        var r = svg.getBoundingClientRect(), i = n > 1 ? Math.round((ev.clientX - r.left - m.l) / pw * (n - 1)) : 0;
        i = Math.min(n - 1, Math.max(0, i)); g.setAttribute('visibility', 'visible');
        vl.setAttribute('x1', X(i)); vl.setAttribute('x2', X(i));
        dots.forEach(function (d, k) { d.setAttribute('cx', X(i)); d.setAttribute('cy', Y(o.series[k].values[i])); });
        tip(ev, o.tip(i));
      }
      hit.addEventListener('pointermove', at); hit.addEventListener('pointerdown', at);
      hit.addEventListener('pointerleave', function () { g.setAttribute('visibility', 'hidden'); untip(); });
    });
  }

  // ================================================================== REPORTS TAB
  function buildReports() {
    var p = $('tab-insights'); if (!p || p.dataset.built) return;
    p.dataset.built = '1'; inject(); p.classList.add('ix-scope');
    p.innerHTML =
      '<div class="panel"><div class="ix-bar"><h3><i class="fas fa-chart-line"></i> Sales, profit and funnel reports</h3>' +
      daysSelect('ixDays', 30) + '<button id="ixRefresh">Refresh</button><button id="ixCsv">Daily CSV</button></div>' +
      '<div id="ixWarn"></div><div id="ixKpis" class="ix-kpis"></div><div class="ix-grid">' +
      card('Sales per day', 'Total paid by customers (airtime + fees), Lagos time', chartBox('ixDaily') + '<details><summary>View as table</summary><div class="ix-scroll" id="ixDailyTable"></div></details>') +
      card('Fees and estimated profit per day', 'What Net365 earned each day', '<div class="ix-legend"><span><i style="background:var(--ix-aqua)"></i>Estimated profit</span><span><i style="background:var(--ix-orange)"></i>Fees</span></div>' + chartBox('ixProfit')) +
      card('When customers buy (hour of day)', 'Total sales by hour, Lagos time. Send promos just before the peaks.', chartBox('ixHour')) +
      card('Best days of the week', 'Total sales by weekday', chartBox('ixDow')) +
      card('Sales by network / biller', 'Top 12 by sales', chartBox('ixNetwork', 1)) +
      card('Sales by service type', 'Airtime, data, utilities, gift cards and so on', chartBox('ixType', 1)) +
      card('Visitor funnel', 'Visitors who accepted analytics, from first visit to delivered recharge', chartBox('ixFunnel', 1) + '<div id="ixFunnelNote" class="ix-note"></div>') +
      card('Payment gateway reliability', 'Share of finished payments that were delivered', '<div id="ixGateway"></div>') +
      card('Why recharges fail', 'Most common failure reasons', '<div id="ixFailures"></div>') +
      card('Which traffic source brings paying customers', 'First-touch source of each visitor, with what they bought', '<div class="ix-scroll" id="ixSources"></div><div id="ixSourcesNote" class="ix-note"></div>') +
      '</div>' + card('Customer retention by signup week', 'Share of each weekly group of new buyers who bought again in later weeks', '<div class="ix-scroll" id="ixCohorts"></div>') +
      '<p class="ix-note" id="ixAssume"></p></div>';
    $('ixDays').onchange = function () { R.days = +this.value; loadInsights(); };
    $('ixRefresh').onclick = function () { loadInsights(); };
    $('ixCsv').onclick = exportCsv;
    watchTheme(function () { if (R.data) renderReports(); });
  }
  function daysSelect(id, def) {
    return '<select id="' + id + '" aria-label="Date range">' + [[7, 'Last 7 days'], [14, 'Last 14 days'], [30, 'Last 30 days'], [90, 'Last 90 days'], [365, 'Last 12 months']]
      .map(function (o) { return '<option value="' + o[0] + '"' + (o[0] === def ? ' selected' : '') + '>' + o[1] + '</option>'; }).join('') + '</select>';
  }
  var themeWatchers = [];
  function watchTheme(fn) {
    themeWatchers.push(fn);
    if (!watchTheme.on) { watchTheme.on = 1; new MutationObserver(function () { themeWatchers.forEach(function (f) { try { f(); } catch (e) {} }); }).observe(document.body, { attributes: true, attributeFilter: ['class'] }); }
  }

  async function loadInsights() {
    buildReports();
    var q = '?days=' + R.days;
    $('ixWarn').innerHTML = '';
    $('ixKpis').innerHTML = '<div class="ix-empty" style="grid-column:1/-1">Loading reports…</div>';
    var res = await Promise.all([api('/api/admin/insights/overview' + q), api('/api/admin/insights/funnel' + q), api('/api/admin/insights/sources' + q)]);
    if (!res[0] || !res[0].success) {
      $('ixKpis').innerHTML = '<div class="ix-warn ix-err" style="grid-column:1/-1">Could not load reports: ' + esc(res[0] && res[0].error || 'unknown error') + '</div>';
      return;
    }
    R.data = res[0]; R.funnel = res[1]; R.sources = res[2];
    renderReports();
  }

  function renderReports() {
    var D = R.data, K = D.kpis, X = D.delta || {}, warn = [];
    if (!K.transactions && !K.failed && !K.abandoned) warn.push('No transactions were recorded in this period. Try a longer date range.');
    if (!D.assumptions || !D.assumptions.provider_margin_pct) warn.push('Profit shows fees minus payment-gateway cost only. Set <b>PROFIT_PROVIDER_MARGIN_PCT</b> (your Reloadly discount, for example 2.5) to include the discount you earn on every recharge.');
    if (D.other_currency_transactions) warn.push(num(D.other_currency_transactions) + ' successful non-NGN transactions are excluded from the naira totals.');
    $('ixWarn').innerHTML = warn.map(function (w) { return '<div class="ix-warn">' + w + '</div>'; }).join('');
    $('ixKpis').innerHTML =
      tile('Sales volume', naira(K.volume, true), X.volume) + tile('Fees earned', naira(K.fees, true), X.fees) +
      tile('Estimated profit', naira(K.profit, true), X.profit) + tile('Profit margin', K.profit_margin_pct == null ? '–' : K.profit_margin_pct + '%') +
      tile('Delivered orders', num(K.transactions), X.transactions) + tile('Success rate', pct(K.success_rate)) +
      tile('Average order', naira(K.avg_ticket), X.avg_ticket) +
      tile('Customers', num(K.customers) + ' <span style="font-size:13px;font-weight:500;color:var(--ix-muted)">(' + num(K.new_customers) + ' new)</span>', X.customers) +
      tile('Failed orders', num(K.failed)) + tile('Abandoned (unpaid)', num(K.abandoned));
    var blue = css('--ix-blue'), orange = css('--ix-orange'), aqua = css('--ix-aqua');
    var daily = D.daily || [], lb = daily.map(function (r) { return r.day.slice(5); });
    barChart($('ixDaily'), { labels: lb, values: daily.map(function (r) { return r.volume; }), yfmt: function (v) { return naira(v, true); }, aria: 'Sales per day',
      tip: function (i) { var r = daily[i]; return [r.day, 'Sales ' + naira(r.volume), 'Orders ' + r.count, 'Failed ' + r.failed]; } });
    lineChart($('ixProfit'), { labels: lb, yfmt: function (v) { return naira(v, true); }, aria: 'Fees and profit per day',
      series: [{ values: daily.map(function (r) { return r.profit; }), color: aqua }, { values: daily.map(function (r) { return r.fees; }), color: orange }],
      tip: function (i) { var r = daily[i]; return [r.day, 'Estimated profit ' + naira(r.profit), 'Fees ' + naira(r.fees)]; } });
    var hrs = D.by_hour || [];
    barChart($('ixHour'), { labels: hrs.map(function (r) { return r.hour + 'h'; }), values: hrs.map(function (r) { return r.volume; }), yfmt: function (v) { return naira(v, true); },
      tip: function (i) { return [hrs[i].hour + ':00 to ' + hrs[i].hour + ':59', 'Sales ' + naira(hrs[i].volume), 'Orders ' + hrs[i].count]; } });
    var dow = D.by_dow || [];
    barChart($('ixDow'), { labels: dow.map(function (r) { return r.day; }), values: dow.map(function (r) { return r.volume; }), yfmt: function (v) { return naira(v, true); },
      tip: function (i) { return [dow[i].day, 'Sales ' + naira(dow[i].volume), 'Orders ' + dow[i].count]; } });
    var nets = D.by_network || [], types = D.by_type || [];
    hbarChart($('ixNetwork'), { labels: nets.map(function (r) { return r.name; }), values: nets.map(function (r) { return r.volume; }), vfmt: function (v) { return naira(v, true); },
      tip: function (i) { return [nets[i].name, 'Sales ' + naira(nets[i].volume), 'Orders ' + nets[i].count, 'Profit ' + naira(nets[i].profit)]; } });
    hbarChart($('ixType'), { labels: types.map(function (r) { return r.name; }), values: types.map(function (r) { return r.volume; }), vfmt: function (v) { return naira(v, true); },
      tip: function (i) { return [types[i].name, 'Sales ' + naira(types[i].volume), 'Orders ' + types[i].count, 'Profit ' + naira(types[i].profit)]; } });
    var F = R.funnel, fn = $('ixFunnelNote');
    if (F && F.success) {
      var st = F.steps || [], ex = F.extras || {};
      hbarChart($('ixFunnel'), { labels: st.map(function (s) { return s.label; }), values: st.map(function (s) { return s.visitors; }), empty: 'No visitor data yet. It appears after visitors accept the cookie notice.',
        tip: function (i) { var s = st[i]; return [s.label, num(s.visitors) + ' visitors', pct(s.pct_of_first) + ' of all visitors', s.pct_of_prev == null ? '' : pct(s.pct_of_prev) + ' of previous step']; } });
      fn.textContent = 'Also: ' + num(ex.fulfillment_failed) + ' failed deliveries, ' + num(ex.signup_started) + ' signups started, ' + num(ex.signup_completed) + ' completed. ' + (F.note || '');
    } else { empty($('ixFunnel'), 'Funnel data unavailable.'); fn.textContent = ''; }
    var gw = D.by_gateway || [];
    $('ixGateway').innerHTML = tableOrEmpty('<table class="ix-table"><thead><tr><th>Gateway</th><th class="n">Attempts</th><th class="n">Failed</th><th>Success</th></tr></thead><tbody>' +
      gw.map(function (g) { var r = g.success_rate == null ? 0 : g.success_rate; return '<tr><td>' + esc(g.provider) + '</td><td class="n">' + num(g.attempts) + '</td><td class="n">' + num(g.failed) + '</td><td><div style="display:flex;align-items:center;gap:8px"><div class="ix-meter" style="flex:1"><i style="width:' + r + '%"></i></div><span>' + pct(g.success_rate) + '</span></div></td></tr>'; }).join('') + '</tbody></table>', gw.length, 'No finished payments in this period.');
    var fl = D.failures || [];
    $('ixFailures').innerHTML = tableOrEmpty('<table class="ix-table"><tbody>' + fl.map(function (f) { return '<tr><td>' + esc(f.reason) + '</td><td class="n">' + num(f.count) + '</td></tr>'; }).join('') + '</tbody></table>', fl.length, 'No failures in this period.');
    var S2 = R.sources;
    $('ixSources').innerHTML = (S2 && S2.success && (S2.sources || []).length) ? '<table class="ix-table"><thead><tr><th>Source</th><th class="n">Visitors</th><th class="n">Buyers</th><th class="n">Conversion</th><th class="n">Orders</th><th class="n">Sales</th></tr></thead><tbody>' +
      S2.sources.map(function (r) { return '<tr><td>' + esc(r.source) + '</td><td class="n">' + num(r.visitors) + '</td><td class="n">' + num(r.buyers) + '</td><td class="n">' + pct(r.conversion_pct) + '</td><td class="n">' + num(r.orders) + '</td><td class="n">' + naira(r.volume) + '</td></tr>'; }).join('') + '</tbody></table>'
      : '<div class="ix-empty">No attributed visitors yet. This fills in once visitors accept the cookie notice and buy.</div>';
    $('ixSourcesNote').textContent = (S2 && S2.note) || '';
    var co = D.cohorts || [], heat = css('--ix-heat') || '42,120,214';
    $('ixCohorts').innerHTML = co.length ? '<table class="ix-table"><thead><tr><th>Week starting</th><th class="n">New buyers</th><th class="n">Week 0</th><th class="n">Week 1</th><th class="n">Week 2</th><th class="n">Week 3</th><th class="n">Week 4</th></tr></thead><tbody>' +
      co.map(function (c) { return '<tr><td>' + esc(c.cohort) + '</td><td class="n">' + num(c.size) + '</td>' + c.retention.map(function (v) { return v == null ? '<td class="n" style="color:var(--ix-muted)">·</td>' : '<td class="n" style="background:rgba(' + heat + ',' + (0.12 + 0.55 * v / 100).toFixed(2) + ')">' + v + '%</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table>'
      : '<div class="ix-empty">Not enough purchase history yet.</div>';
    $('ixDailyTable').innerHTML = '<table class="ix-table"><thead><tr><th>Day</th><th class="n">Sales</th><th class="n">Orders</th><th class="n">Fees</th><th class="n">Profit</th><th class="n">Failed</th></tr></thead><tbody>' +
      daily.slice().reverse().map(function (r) { return '<tr><td>' + r.day + '</td><td class="n">' + naira(r.volume) + '</td><td class="n">' + r.count + '</td><td class="n">' + naira(r.fees) + '</td><td class="n">' + naira(r.profit) + '</td><td class="n">' + r.failed + '</td></tr>'; }).join('') + '</tbody></table>';
    $('ixAssume').textContent = (D.assumptions && D.assumptions.note) || '';
  }
  function exportCsv() {
    if (!R.data) return;
    var rows = [['day', 'sales_ngn', 'orders', 'fees_ngn', 'est_profit_ngn', 'failed']].concat((R.data.daily || []).map(function (r) { return [r.day, r.volume, r.count, r.fees, r.profit, r.failed]; }));
    var a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([rows.map(function (r) { return r.join(','); }).join('\n')], { type: 'text/csv' }));
    a.download = 'net365-daily-' + R.days + 'd.csv'; document.body.appendChild(a); a.click(); a.remove();
  }

  // ================================================================== VISITOR INTEL TAB
  var SEGMENTS = [['all', 'All visitors'], ['new', 'New'], ['returning', 'Returning'], ['high', 'High engagement'], ['corporate', 'Organisation networks'],
    ['prospect', 'Prospect signals (unconfirmed)'], ['registered', 'Registered users'], ['suspected', 'Suspected automation'], ['bots', 'Bots and crawlers']];

  function buildIntel() {
    var p = $('tab-intel'); if (!p || p.dataset.built) return;
    p.dataset.built = '1'; inject(); p.classList.add('ix-scope');
    p.innerHTML =
      '<div class="panel"><div class="ix-bar"><h3><i class="fas fa-user-secret"></i> Visitor intelligence and prospects</h3>' + daysSelect('viDays', 30) +
      '<button id="viRefresh">Refresh</button></div>' +
      '<div id="viMsg"></div>' +
      '<div class="ix-card" style="margin-bottom:16px"><h4>Alerts <span id="viAlertCount" class="ix-note"></span></h4><div class="sub">Significant visitor activity. Pushed to Telegram or a webhook if you set INTEL_ALERT_TELEGRAM_BOT_TOKEN and INTEL_ALERT_TELEGRAM_CHAT_ID (or INTEL_ALERT_WEBHOOK_URL).</div>' +
      '<div id="viAlerts"></div><div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap"><button class="ix-bar-btn" id="viSeen" style="padding:6px 12px;border-radius:8px;border:1px solid var(--ix-line);background:var(--ix-surface);color:var(--ix-text);cursor:pointer">Mark all seen</button>' +
      '<button id="viScan" style="padding:6px 12px;border-radius:8px;border:1px solid var(--ix-line);background:var(--ix-surface);color:var(--ix-text);cursor:pointer">Scan now</button></div></div>' +
      '<div id="viKpis" class="ix-kpis"></div><div id="viCoverage" class="ix-note" style="margin:-6px 0 14px"></div>' +
      '<h3 class="ix-h">Visitor-to-customer journey</h3><div class="ix-grid">' + card('Journey funnel', 'Visitors to repeat customers in this period', chartBox('viFunnel', 1)) +
      card('Acquisition metrics', 'The numbers investors ask for', '<div id="viMetrics" class="ix-kpis" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr));margin:0"></div><div id="viConvNote" class="ix-note"></div>') + '</div>' +
      '<h3 class="ix-h">Visitors</h3><div class="ix-bar"><select id="viSegment" aria-label="Segment">' + SEGMENTS.map(function (s) { return '<option value="' + s[0] + '">' + s[1] + '</option>'; }).join('') +
      '</select><input id="viSearch" type="search" placeholder="Search id, organisation, country, page…" aria-label="Search visitors"><span id="viCount" class="ix-note" style="margin:0"></span></div>' +
      '<div class="ix-card"><div class="ix-scroll" id="viTable"></div><div id="viNote" class="ix-note"></div></div>' +
      '<h3 class="ix-h">Audience</h3><div class="ix-grid">' +
      card('Visits per day', 'Real visitors, Lagos time (bots excluded)', '<div class="ix-legend"><span><i style="background:var(--ix-blue)"></i>Visits</span></div>' + chartBox('viDaily')) +
      card('Visits by hour of day', 'Lagos time', chartBox('viHour')) +
      card('Top countries', 'Visitors by country', chartBox('viCountries', 1)) + card('Top cities', 'Approximate, from the network location', chartBox('viCities', 1)) +
      card('Network types', 'Who is carrying the traffic', chartBox('viNetworks')) + card('Where visitors come from', 'First referrer of each visitor', chartBox('viRefs', 1)) +
      card('Devices', 'Device type', chartBox('viDevices')) + card('Browsers', 'Browser family', chartBox('viBrowsers', 1)) +
      card('Pages viewed', 'Page views by page', chartBox('viPages', 1)) + card('Common navigation paths', 'Most frequent page sequences', '<div class="ix-scroll" id="viFlows"></div>') +
      card('Organisations visiting', 'Resolved from the network owner. Not proof of who is browsing.', '<div class="ix-scroll" id="viOrgs"></div>') +
      card('Bots and crawlers', 'Separated from real visitors', chartBox('viBots') + '<div class="ix-note" id="viBotNames"></div>') +
      card('Screen and connection', 'From visitors who accepted analytics', '<div id="viSig"></div>') + '</div></div>';
    $('viDays').onchange = function () { V.days = +this.value; loadIntel(); };
    $('viRefresh').onclick = function () { loadIntel(); };
    $('viSegment').onchange = function () { V.segment = this.value; loadList(); };
    var t; $('viSearch').oninput = function () { var v = this.value; clearTimeout(t); t = setTimeout(function () { V.q = v; loadList(); }, 350); };
    $('viSeen').onclick = async function () { await adminFetch('/api/admin/insights/intel/alerts/seen', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); loadAlerts(); };
    $('viScan').onclick = async function () { try { await adminFetch('/api/admin/insights/intel/alerts/scan', { method: 'POST' }); } catch (e) {} loadAlerts(); };
    watchTheme(function () { if (V.over) renderAudience(); });
  }

  async function loadIntel() {
    buildIntel();
    var q = '?days=' + V.days;
    $('viMsg').innerHTML = ''; $('viKpis').innerHTML = '<div class="ix-empty" style="grid-column:1/-1">Loading visitor intelligence…</div>';
    var r = await Promise.all([api('/api/admin/insights/intel/overview' + q), api('/api/admin/insights/intel/conversion' + q)]);
    if (!r[0] || !r[0].success) {
      $('viKpis').innerHTML = '<div class="ix-warn ix-err" style="grid-column:1/-1">Could not load visitor intelligence: ' + esc(r[0] && r[0].error || 'unknown error') + '</div>';
      return;
    }
    V.over = r[0]; V.conv = r[1];
    renderSummary(); renderAudience(); renderConversion();
    loadList(); loadAlerts();
  }

  function renderSummary() {
    var S0 = V.over.summary, C = V.over.coverage;
    $('viKpis').innerHTML =
      tile('Visitors', num(S0.visitors)) + tile('New', num(S0.new)) + tile('Returning', num(S0.returning)) + tile('Registered users', num(S0.registered)) +
      tile('Organisation networks', num(S0.corporate)) + tile('High engagement', num(S0.high_engagement)) +
      tile('Prospect signals', num(S0.prospect_signals) + ' <span style="font-size:12px;font-weight:600;color:var(--ix-amber)">UNCONFIRMED</span>') +
      tile('Suspected automation', num(S0.suspected_automation)) + tile('Bots filtered out', num(S0.bot_visitors)) + tile('Avg engagement', S0.avg_engagement + '/100');
    var low = C.organization_pct < 70 || C.city_pct < 70;
    $('viCoverage').innerHTML = 'Identified for ' + C.organization_pct + '% of visitors: organisation. ' + C.city_pct + '%: city. ' + C.country_pct + '%: country.' +
      (low ? ' <b>Some lookups are still pending.</b> Open the Visitor Log tab once to trigger them, or check /api/admin/visitors/geo-status for the last error.' : '');
  }

  function renderConversion() {
    var C = V.conv;
    if (!C || !C.success) { empty($('viFunnel'), 'Conversion data unavailable.'); $('viMetrics').innerHTML = ''; $('viConvNote').textContent = C && C.error || ''; return; }
    var st = C.steps, M = C.metrics;
    hbarChart($('viFunnel'), { labels: st.map(function (s) { return s.label; }), values: st.map(function (s) { return s.count; }), vfmt: num,
      tip: function (i) { return [st[i].label, num(st[i].count)]; } });
    $('viMetrics').innerHTML =
      tile('Unique visitors', num(M.unique_visitors)) + tile('Monthly active users', num(M.monthly_active_users)) +
      tile('Visitor to registration', pct(M.visitor_to_registration_pct)) + tile('Registration to funded wallet', pct(M.registration_to_funded_pct)) +
      tile('Registration to first purchase', pct(M.registration_to_first_transaction_pct)) +
      tile('Median days to first purchase', M.median_days_to_first_transaction == null ? '–' : M.median_days_to_first_transaction) +
      tile('Repeat purchase rate', pct(M.repeat_transaction_rate_pct)) + tile('Customer acquisition cost', M.customer_acquisition_cost == null ? '–' : naira(M.customer_acquisition_cost));
    $('viConvNote').textContent = C.note + (M.marketing_spend_set ? '' : '');
  }

  async function loadList() {
    var el = $('viTable'); if (!el) return;
    el.innerHTML = '<div class="ix-empty">Loading…</div>';
    var j = await api('/api/admin/insights/intel/visitors?days=' + V.days + '&segment=' + encodeURIComponent(V.segment) + '&q=' + encodeURIComponent(V.q) + '&limit=100');
    if (!j.success) { el.innerHTML = '<div class="ix-warn ix-err">' + esc(j.error || 'Could not load visitors') + '</div>'; return; }
    V.list = j; V.open = null; renderList();
  }

  function badgeTier(t) { return '<span class="ix-b ' + (t === 'HIGH' ? 'hi' : t === 'MEDIUM' ? 'med' : '') + '">' + t + '</span>'; }
  function renderList() {
    var j = V.list, rows = j.visitors || [];
    $('viCount').textContent = num(j.total) + ' matching' + (j.total > rows.length ? ' (showing ' + rows.length + ')' : '');
    $('viNote').textContent = (j.scoring || '') + ' ' + (j.prospect_note || '');
    if (!rows.length) { $('viTable').innerHTML = '<div class="ix-empty">No visitors match this filter in the selected period.</div>'; return; }
    $('viTable').innerHTML = '<table class="ix-table"><thead><tr><th>Visitor</th><th>Status</th><th>Engagement</th><th>Organisation / network</th><th>Location</th><th>Device</th><th class="n">Pages</th><th>Stage</th><th>Signal</th></tr></thead><tbody>' +
      rows.map(function (v, i) {
        var status = v.bot ? '<span class="ix-b bot">' + esc(v.bot_class || 'Bot') + '</span>' : '<span class="ix-b ' + (v.is_new ? '' : 'med') + '">' + (v.is_new ? 'New' : 'Returning') + '</span>';
        var sig = v.investor_likelihood === 'UNCONFIRMED' ? '<span class="ix-b unc">UNCONFIRMED</span>' : (v.suspected_automation ? '<span class="ix-b bot">Possible automation</span>' : (v.corporate ? '<span class="ix-b">Org network</span>' : ''));
        return '<tr class="ix-row" data-i="' + i + '" tabindex="0"><td><b>' + esc(v.label.replace('NET365-VISITOR-', 'V-')) + '</b><div class="ix-note" style="margin:0">' + esc(when(v.last_seen)) + '</div></td><td>' + status + '</td>' +
          '<td>' + (v.bot ? '–' : '<div style="display:flex;gap:6px;align-items:center">' + v.score + ' ' + badgeTier(v.tier) + '</div>') + '</td>' +
          '<td>' + esc(v.organization) + '<div class="ix-note" style="margin:0">' + esc(v.network) + '</div></td>' +
          '<td>' + esc(cname(v.country)) + '<div class="ix-note" style="margin:0">' + esc(v.city || '') + '</div></td>' +
          '<td>' + esc(v.device || '—') + '<div class="ix-note" style="margin:0">' + esc([v.browser, v.os].filter(Boolean).join(' / ')) + '</div></td>' +
          '<td class="n">' + v.pages.length + '</td><td>' + esc(v.stage) + '</td><td>' + sig + '</td></tr>';
      }).join('') + '</tbody></table>';
    Array.prototype.forEach.call($('viTable').querySelectorAll('tr.ix-row'), function (tr) {
      var h = function () { toggleDetail(tr, +tr.dataset.i); };
      tr.addEventListener('click', h); tr.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); h(); } });
    });
  }

  function toggleDetail(tr, i) {
    var next = tr.nextElementSibling;
    if (next && next.classList.contains('ix-detail')) { next.remove(); return; }
    var v = V.list.visitors[i], d = document.createElement('tr'); d.className = 'ix-detail';
    var pages = v.pages.map(function (p) { return '<li>✓ ' + esc(p.name) + (p.count > 1 ? ' <span class="ix-note" style="margin:0">×' + p.count + '</span>' : '') + '</li>'; }).join('');
    d.innerHTML = '<td colspan="9"><div class="ix-vcard"><div class="hd">' + esc(v.headline) + '</div><dl>' +
      '<dt>Visitor ID</dt><dd>' + esc(v.label) + '</dd>' +
      '<dt>Country</dt><dd>' + esc(cname(v.country)) + (v.city ? ', ' + esc(v.city) : '') + '</dd>' +
      '<dt>Organisation</dt><dd>' + esc(v.organization) + (v.asn ? ' <span class="ix-note" style="margin:0">(' + esc(v.asn) + ')</span>' : '') + '</dd>' +
      '<dt>Network</dt><dd>' + esc(v.network) + '</dd>' +
      '<dt>Device</dt><dd>' + esc([v.device, v.device_model].filter(Boolean).join(' · ') || '—') + '</dd>' +
      '<dt>Browser / OS</dt><dd>' + esc([v.browser, v.os].filter(Boolean).join(' / ') || '—') + '</dd>' +
      '<dt>Came from</dt><dd>' + esc(v.referrer) + '</dd>' +
      '<dt>Visits</dt><dd>' + v.visits + ' (' + v.hits + ' page views, about ' + v.span_minutes + ' min on site)</dd>' +
      '<dt>First / last seen</dt><dd>' + esc(when(v.first_seen)) + ' / ' + esc(when(v.last_seen)) + ' (Lagos time)</dd></dl>' +
      '<div class="ix-note" style="margin:0">Pages explored</div><ul>' + pages + '</ul>' +
      '<dl><dt>Journey</dt><dd>' + esc(v.journey) + '</dd><dt>Classification</dt><dd>' + esc(v.classification) + '</dd>' +
      '<dt>Journey stage</dt><dd>' + esc(v.stage) + '</dd><dt>Engagement</dt><dd>' + (v.bot ? '–' : v.score + '/100 ' + badgeTier(v.tier)) + '</dd>' +
      '<dt>Investor likelihood</dt><dd>' + (v.investor_likelihood === 'UNCONFIRMED' ? '<span class="ix-b unc">UNCONFIRMED</span>' : 'No signal') +
      (v.signals && v.signals.length ? ' <span class="ix-note" style="margin:0">based on: ' + esc(v.signals.join('; ')) + '</span>' : '') + '</dd>' +
      '<dt>Recommended action</dt><dd>' + esc(v.action) + '</dd></dl></div></td>';
    tr.parentNode.insertBefore(d, tr.nextSibling);
  }

  function renderAudience() {
    var O = V.over; if (!O) return;
    var blue = css('--ix-blue'), dly = O.daily || [];
    barChart($('viDaily'), { labels: dly.map(function (r) { return r.day.slice(5); }), values: dly.map(function (r) { return r.visits; }), aria: 'Visits per day',
      tip: function (i) { var r = dly[i]; return [r.day, num(r.visits) + ' visits', num(r.visitors) + ' visitors', num(r.bots) + ' bot hits (excluded)']; } });
    var hr = O.by_hour || [];
    barChart($('viHour'), { labels: hr.map(function (r) { return r.hour + 'h'; }), values: hr.map(function (r) { return r.count; }), tip: function (i) { return [hr[i].hour + ':00 to ' + hr[i].hour + ':59', num(hr[i].count) + ' visits']; } });
    function h(id, rows, nameKey, fmt) {
      hbarChart($(id), { labels: rows.map(function (r) { return fmt ? fmt(r[nameKey]) : r[nameKey]; }), values: rows.map(function (r) { return r.count; }), vfmt: num, color: blue,
        tip: function (i) { return [fmt ? fmt(rows[i][nameKey]) : rows[i][nameKey], num(rows[i].count)]; } });
    }
    h('viCountries', O.countries || [], 'name', cname); h('viCities', O.cities || [], 'name'); h('viNetworks', O.networks || [], 'name');
    h('viRefs', O.referrers || [], 'source'); h('viDevices', O.devices || [], 'name'); h('viBrowsers', O.browsers || [], 'name'); h('viPages', O.pages || [], 'name');
    var b = (O.bots || {}).classes || []; h('viBots', b, 'name');
    $('viBotNames').textContent = ((O.bots || {}).names || []).map(function (x) { return x.name + ' (' + x.count + ')'; }).join(', ');
    var fl = O.flows || [];
    $('viFlows').innerHTML = fl.length ? '<table class="ix-table"><tbody>' + fl.map(function (f) { return '<tr><td>' + esc(f.flow) + '</td><td class="n">' + f.count + '</td></tr>'; }).join('') + '</tbody></table>' : '<div class="ix-empty">No multi-page journeys yet.</div>';
    var og = O.organizations || [];
    $('viOrgs').innerHTML = og.length ? '<table class="ix-table"><thead><tr><th>Organisation</th><th>Type</th><th class="n">Visitors</th><th class="n">Visits</th></tr></thead><tbody>' + og.map(function (o) {
      return '<tr><td>' + esc(o.organization) + (o.corporate ? ' <span class="ix-b">Org network</span>' : '') + '</td><td>' + esc(o.network) + '</td><td class="n">' + o.visitors + '</td><td class="n">' + o.visits + '</td></tr>';
    }).join('') + '</tbody></table>' : '<div class="ix-empty">No organisations identified yet.</div>';
    var sg = O.device_signals || {};
    $('viSig').innerHTML = sg.samples ? ['screens', 'connections', 'languages'].map(function (k) {
      var rows = sg[k] || [];
      return '<div class="ix-note" style="margin:6px 0 2px"><b>' + { screens: 'Screen width', connections: 'Connection', languages: 'Language' }[k] + '</b>: ' + (rows.map(function (r) { return esc(r.name) + ' (' + r.count + ')'; }).join(', ') || 'no data') + '</div>';
    }).join('') : '<div class="ix-empty">No screen data yet. It appears after visitors accept the cookie notice.</div>';
  }

  async function loadAlerts() {
    var j = await api('/api/admin/insights/intel/alerts?all=1');
    if (!$('viAlerts')) return;
    if (!j.success) { $('viAlerts').innerHTML = '<div class="ix-note">' + esc(j.error || '') + '</div>'; return; }
    $('viAlertCount').textContent = j.unseen ? '(' + j.unseen + ' new)' : '';
    $('viAlerts').innerHTML = j.alerts.length ? j.alerts.slice(0, 12).map(function (a) {
      return '<div class="ix-alert"><span class="ix-b ' + (a.severity === 'high' ? 'sev-high' : 'med') + '">' + esc(a.severity.toUpperCase()) + '</span><div><div class="t">' + esc(a.title) + (a.seen ? '' : ' <span class="ix-b hi">NEW</span>') + '</div><div class="m">' + esc(a.detail) + ' · ' + esc(when(a.created_at)) + ' UTC</div></div></div>';
    }).join('') : '<div class="ix-empty">No alerts yet. They appear when a visitor shows strong interest, returns repeatedly or comes from an organisation network.</div>';
    setBadge(j.unseen);
  }

  function setBadge(n) {
    var b = document.querySelector('.admin-tab[data-tab="intel"]'); if (!b) return;
    var s = b.querySelector('.ix-badge');
    if (!n) { if (s) s.remove(); return; }
    if (!s) { s = document.createElement('span'); s.className = 'ix-badge'; b.appendChild(s); }
    s.textContent = n > 99 ? '99+' : n;
  }
  function pollAlerts() {
    try {
      if (typeof adminSecret !== 'string' || !adminSecret) return;
      adminFetch('/api/admin/insights/intel/alerts').then(function (j) { if (j && j.success) setBadge(j.unseen); }).catch(function () {});
    } catch (e) {}
  }
  setTimeout(pollAlerts, 4000); setInterval(pollAlerts, 90000);

  window.loadInsights = loadInsights;
  window.loadIntel = loadIntel;
})();

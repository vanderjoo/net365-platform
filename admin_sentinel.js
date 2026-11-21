/* NET365 SENTINEL - Security Operations Centre tab. Self-contained (no CDN). Needs the page's adminFetch() and
 *   <div id="tab-security" class="tab-panel"></div>
 * Entry point: loadSecurity(). */
(function () {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';
  var S = { hours: 24, data: null, blocks: null, events: null, minScore: 0, ip: '', tab: 'live', timer: null };

  var CSS = '' +
    '.sx{--b:#2a78d6;--o:#eb6834;--g:#1baf7a;--r:#c93434;--a:#b7791f;--t:#1e293b;--m:#64748b;--l:#e2e8f0;--s:#fff;color:var(--t)}' +
    'body.dark-mode .sx{--b:#3987e5;--o:#d95926;--g:#199e70;--r:#e66a6a;--a:#e0a43a;--t:#e2e8f0;--m:#94a3b8;--l:#334155;--s:#1e293b}' +
    '.sx *{box-sizing:border-box}' +
    '.sx-bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:14px}.sx-bar h3{margin:0 auto 0 0}' +
    '.sx button,.sx select,.sx input{padding:8px 12px;border-radius:8px;border:1px solid var(--l);background:var(--s);color:var(--t);font:inherit;cursor:pointer;max-width:100%}' +
    '.sx input{cursor:text}.sx button.pri{background:var(--b);border-color:var(--b);color:#fff}.sx button.dng{background:var(--r);border-color:var(--r);color:#fff}' +
    '.sx button.sm{padding:3px 9px;font-size:12px}' +
    '.sx-banner{display:flex;flex-wrap:wrap;gap:12px;align-items:center;padding:12px 16px;border-radius:12px;border:1px solid var(--l);background:var(--s);margin-bottom:14px}' +
    '.sx-banner.lock{border-color:var(--r);background:rgba(201,52,52,.08)}.sx-banner .sp{flex:1;min-width:200px;font-size:13px;color:var(--m)}' +
    '.sx-mode{display:inline-flex;border:1px solid var(--l);border-radius:8px;overflow:hidden}.sx-mode button{border:0;border-radius:0;background:transparent}' +
    '.sx-mode button.on{background:var(--b);color:#fff}' +
    '.sx-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:14px}' +
    '.sx-kpi{background:var(--s);border:1px solid var(--l);border-radius:12px;padding:12px 14px}.sx-kpi .k{font-size:12px;color:var(--m)}' +
    '.sx-kpi .v{font-size:24px;font-weight:700;margin-top:2px;font-variant-numeric:tabular-nums}.sx-kpi.hot .v{color:var(--r)}' +
    '.sx-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:14px;margin-bottom:14px}' +
    '.sx-card{background:var(--s);border:1px solid var(--l);border-radius:12px;padding:16px;min-width:0}.sx-card h4{margin:0 0 2px;font-size:15px}' +
    '.sx-card .sub{font-size:12px;color:var(--m);margin-bottom:10px}' +
    '.sx-chart{position:relative;height:220px}.sx-chart svg{display:block;overflow:visible}' +
    '.sx-t{width:100%;border-collapse:collapse;font-size:13px}.sx-t th{text-align:left;color:var(--m);font-weight:600;padding:6px 8px;border-bottom:1px solid var(--l);white-space:nowrap}' +
    '.sx-t td{padding:7px 8px;border-bottom:1px solid var(--l);vertical-align:top}.sx-scroll{overflow-x:auto}' +
    '.sx-b{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid var(--l);white-space:nowrap}' +
    '.sx-b.c{border-color:var(--r);color:var(--r);background:rgba(201,52,52,.1)}.sx-b.h{border-color:var(--o);color:var(--o)}' +
    '.sx-b.s{border-color:var(--a);color:var(--a)}.sx-b.l{color:var(--m)}.sx-b.ok{border-color:var(--g);color:var(--g)}' +
    '.sx-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 12px}.sx-tabs button.on{background:var(--b);color:#fff;border-color:var(--b)}' +
    '.sx-note{font-size:12px;color:var(--m);margin:8px 0 0}.sx-empty{padding:24px 0;text-align:center;color:var(--m);font-size:13px}' +
    '.sx-warn{padding:8px 12px;border:1px solid var(--l);border-left:3px solid var(--a);border-radius:6px;font-size:12px;margin-bottom:12px;background:var(--s)}' +
    '.sx-form{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}.sx-form input{flex:1;min-width:140px}' +
    '.sx-mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;white-space:nowrap}.sx-t td,.sx-t th{white-space:nowrap}.sx-t td:nth-last-child(2),.sx-t td.wrap{white-space:normal;min-width:200px}' +
    '.sx-tip{position:fixed;z-index:99999;display:none;pointer-events:none;padding:6px 9px;border-radius:8px;font-size:12px;background:#fff;color:#1e293b;border:1px solid #e2e8f0;box-shadow:0 6px 24px rgba(0,0,0,.25)}' +
    'body.dark-mode .sx-tip{background:#0f172a;color:#e2e8f0;border-color:#334155}' +
    '.sx-badge{display:inline-block;min-width:18px;padding:0 6px;margin-left:6px;border-radius:999px;background:#c93434;color:#fff;font-size:11px;line-height:18px;text-align:center}';

  function $(id) { return document.getElementById(id); }
  function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
  function num(n) { return (Number(n) || 0).toLocaleString('en-NG'); }
  function when(s) { var m = String(s || '').match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})/); return m ? m[3] + '/' + m[2] + ' ' + m[4] : (s || ''); }
  function label(k) { return String(k || '').replace(/_/g, ' ').replace(/^./, function (c) { return c.toUpperCase(); }); }
  function inject() {
    if ($('sx-style')) return;
    var st = document.createElement('style'); st.id = 'sx-style'; st.textContent = CSS; document.head.appendChild(st);
  }
  async function api(path, opts) {
    try { return await adminFetch(path, opts); }
    catch (e) {
      var m = String(e && e.message || e);
      if (/unauthorized/i.test(m)) m = 'Not authorised. Unlock the admin panel again.';
      else if (/unexpected token|JSON|<!doctype/i.test(m)) m = 'SENTINEL API not found (404). Upload net365_sentinel.py and the new app.py, then restart.';
      return { success: false, error: m };
    }
  }
  function post(path, body) {
    return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  }
  function bandClass(score) { return score >= 80 ? 'c' : score >= 60 ? 'h' : score >= 40 ? 's' : 'l'; }
  function bandName(score) { return score >= 90 ? 'Critical' : score >= 80 ? 'Very high' : score >= 60 ? 'High' : score >= 40 ? 'Suspicious' : score >= 20 ? 'Low' : 'Normal'; }
  function badge(score) { return '<span class="sx-b ' + bandClass(score) + '">' + bandName(score) + ' · ' + (score || 0) + '</span>'; }
  function actBadge(a) {
    a = String(a || '');
    var cls = /block|restrict|lockdown/.test(a) ? 'c' : /challenge|ratelimit/.test(a) ? 'h' : /observed/.test(a) ? 's' : 'l';
    return '<span class="sx-b ' + cls + '">' + esc(a || 'monitor') + '</span>';
  }

  // ---- tiny SVG charts
  function tip() { var t = $('sx-tip'); if (!t) { t = document.createElement('div'); t.id = 'sx-tip'; t.className = 'sx-tip'; document.body.appendChild(t); } return t; }
  function sv(tag, a, p, t) { var e = document.createElementNS(NS, tag); for (var k in a) e.setAttribute(k, a[k]); if (t != null) e.textContent = t; if (p) p.appendChild(e); return e; }
  function timeline(el, rows) {
    el.innerHTML = '';
    if (!rows.length) { el.innerHTML = '<div class="sx-empty">No threat events in this period.</div>'; return; }
    var w = el.clientWidth || 600, h = el.clientHeight || 220, L = 34, B = 22, T = 8, R = 6;
    var max = Math.max.apply(null, rows.map(function (r) { return r.events || 0; })) || 1;
    var svg = sv('svg', { width: w, height: h, viewBox: '0 0 ' + w + ' ' + h }, el);
    var cs = getComputedStyle(el.closest('.sx'));
    var gap = (w - L - R) / rows.length, bw = Math.max(2, Math.min(28, gap * 0.7));
    [0, .5, 1].forEach(function (f) {
      var y = T + (h - T - B) * (1 - f);
      sv('line', { x1: L, x2: w - R, y1: y, y2: y, stroke: cs.getPropertyValue('--l'), 'stroke-width': 1 }, svg);
      sv('text', { x: L - 6, y: y + 4, 'text-anchor': 'end', 'font-size': 10, fill: cs.getPropertyValue('--m') }, svg, Math.round(max * f));
    });
    var step = Math.ceil(rows.length / 8);
    rows.forEach(function (r, i) {
      var x = L + gap * i + (gap - bw) / 2, hh = (h - T - B) * (r.events / max), hb = (h - T - B) * ((r.blocked || 0) / max);
      var rect = sv('rect', { x: x, y: h - B - hh, width: bw, height: Math.max(1, hh), rx: 2, fill: cs.getPropertyValue('--b') }, svg);
      if (hb > 0) sv('rect', { x: x, y: h - B - hb, width: bw, height: hb, rx: 2, fill: cs.getPropertyValue('--r') }, svg);
      if (i % step === 0) sv('text', { x: x + bw / 2, y: h - 6, 'text-anchor': 'middle', 'font-size': 10, fill: cs.getPropertyValue('--m') }, svg, String(r.bucket).slice(-5).replace(' ', ' '));
      rect.addEventListener('mousemove', function (e) { var t = tip(); t.style.display = 'block'; t.style.left = (e.clientX + 12) + 'px'; t.style.top = (e.clientY + 12) + 'px'; t.textContent = r.bucket + ': ' + r.events + ' events, ' + (r.blocked || 0) + ' blocked/restricted'; });
      rect.addEventListener('mouseleave', function () { tip().style.display = 'none'; });
    });
  }
  function hbars(el, rows) {
    el.innerHTML = '';
    if (!rows.length) { el.innerHTML = '<div class="sx-empty">Nothing detected.</div>'; return; }
    var max = Math.max.apply(null, rows.map(function (r) { return r.n; })) || 1;
    el.innerHTML = rows.slice(0, 10).map(function (r) {
      return '<div style="display:flex;align-items:center;gap:10px;margin:6px 0;font-size:13px"><div style="width:150px;flex:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(label(r.kind)) +
        '</div><div style="flex:1;height:10px;border-radius:5px;background:var(--l)"><i style="display:block;height:100%;width:' + Math.max(3, 100 * r.n / max) + '%;background:var(--o);border-radius:5px"></i></div><div style="width:44px;text-align:right;font-variant-numeric:tabular-nums">' + num(r.n) + '</div></div>';
    }).join('');
  }

  // ---- rendering
  function kpi(k, v, hot) { return '<div class="sx-kpi' + (hot && v ? ' hot' : '') + '"><div class="k">' + k + '</div><div class="v">' + num(v) + '</div></div>'; }

  function shell() {
    var root = $('tab-security');
    root.innerHTML = '<div class="sx" id="sx-root"><div class="sx-bar"><h3>🛡️ NET365 SENTINEL · Security Operations Centre</h3>' +
      '<select id="sx-hours"><option value="1">Last hour</option><option value="24">Last 24 hours</option><option value="168">Last 7 days</option><option value="720">Last 30 days</option></select>' +
      '<button id="sx-refresh">↻ Refresh</button><button id="sx-csv">⬇ Export CSV</button></div><div id="sx-body"><div class="sx-empty">Loading…</div></div></div>';
    $('sx-hours').value = String(S.hours);
    $('sx-hours').onchange = function () { S.hours = +this.value; loadSecurity(); };
    $('sx-refresh').onclick = function () { loadSecurity(); };
    $('sx-csv').onclick = exportCsv;
  }
  async function exportCsv() {
    try {
      var res = await fetch('/api/admin/sentinel/report.csv?days=' + Math.max(1, Math.ceil(S.hours / 24)), { credentials: 'include', headers: { 'X-Admin-Secret': adminSecret } });
      if (!res.ok) throw new Error('export failed (' + res.status + ')');
      var b = await res.blob(), a = document.createElement('a');
      a.href = URL.createObjectURL(b); a.download = 'sentinel_report.csv'; document.body.appendChild(a); a.click(); a.remove();
    } catch (e) { alert(e.message); }
  }

  function render() {
    var d = S.data, body = $('sx-body');
    if (!d || !d.success) { body.innerHTML = '<div class="sx-warn" style="border-left-color:var(--r)">' + esc((d && d.error) || 'Could not load SENTINEL.') + '</div>'; return; }
    var k = d.kpis, th = d.thresholds || {};
    var modeBtns = ['observation', 'adaptive', 'maximum'].map(function (m) { return '<button data-mode="' + m + '" class="' + (d.mode === m ? 'on' : '') + '">' + label(m) + (m === 'maximum' ? ' (recommended)' : '') + '</button>'; }).join('');
    var modeText = { observation: 'Detects and records everything, blocks nothing automatically. Not recommended unless you are testing accuracy: attacks are only reported, not stopped.',
      adaptive: 'Rate-limits and challenges suspicious traffic, restricts and blocks confirmed attacks (needs 2+ kinds of evidence). Blocks last 24 hours.',
      maximum: 'Active defence, day and night. Attackers are blocked for 12 hours (24h, then 7 days if they return) the moment real attack evidence appears, from any country or network. An account that sends attack payloads from its own session is deactivated for 12 hours and restores itself. You are emailed what was done and why.' }[d.mode] || '';
    var h = '';
    h += '<div class="sx-banner' + (d.lockdown ? ' lock' : '') + '"><div><b>Mode</b></div><div class="sx-mode">' + modeBtns + '</div><div class="sp">' + esc(modeText) +
      (d.forced_mode ? ' <b>(Locked by SENTINEL_FORCE_MODE on the server.)</b>' : '') + '</div>' +
      '<button class="' + (d.lockdown ? 'pri' : 'dng') + '" id="sx-lock">' + (d.lockdown ? '✔ End emergency lockdown' : '⛔ Emergency lockdown') + '</button></div>';
    if (d.lockdown) h += '<div class="sx-warn" style="border-left-color:var(--r)"><b>Lockdown is ON.</b> New logins, registrations and money actions are refused for everyone. Pages, payment webhooks, bots and health checks still work.</div>';
    if (!d.alerts_configured) h += '<div class="sx-warn">Critical alerts are not pushed anywhere yet. Set SENTINEL_ALERT_TELEGRAM_BOT_TOKEN + SENTINEL_ALERT_TELEGRAM_CHAT_ID (or SENTINEL_ALERT_WEBHOOK_URL) to get them on your phone.</div>';
    h += '<div class="sx-kpis">' + kpi('Requests monitored', k.requests_monitored) + kpi('Threat events', k.threat_events) + kpi('Active blocks', k.active_blocks, 1) + kpi('Accounts on hold', k.active_holds, 1) + kpi('High-risk sources', k.high_risk_sources, 1) +
      kpi('Critical / very high', k.critical, 1) + kpi('Brute-force attempts', k.brute_force, 1) + kpi('Injection attempts', k.injection_attempts, 1) + kpi('API abuse', k.api_abuse, 1) +
      kpi('Recon / scanners', k.recon) + kpi('Requests blocked', k.blocked_requests) + kpi('Challenged', k.challenged) + kpi('Rate-limited', k.rate_limited) + '</div>';
    h += '<div class="sx-grid"><div class="sx-card"><h4>Threat timeline</h4><div class="sub">Events per period <span style="color:var(--b)">■</span> and how many were blocked or restricted <span style="color:var(--r)">■</span></div><div class="sx-chart" id="sx-tl"></div></div>' +
      '<div class="sx-card"><h4>What is being attempted</h4><div class="sub">Detected attack types</div><div id="sx-kinds"></div>' +
      '<p class="sx-note">Bands: 0–19 normal · 20–39 monitor · ' + (th.ratelimit || 40) + '+ rate-limit · ' + (th.challenge || 60) + '+ challenge · ' + (th.restrict || 80) + '+ restrict · ' + (th.block || 90) + '+ block.</p></div></div>';
    h += '<div class="sx-tabs" id="sx-tabs">' + [['live', 'Live threat monitor'], ['top', 'Top sources'], ['blocks', 'Blocks & allow-list'], ['audit', 'Audit log']].map(function (t) {
      return '<button data-t="' + t[0] + '" class="' + (S.tab === t[0] ? 'on' : '') + '">' + t[1] + '</button>'; }).join('') + '</div><div class="sx-card" id="sx-pane"></div>';
    h += '<p class="sx-note">' + esc(d.workers_note || '') + ' Country or hosting provider alone never blocks anyone. Webhooks, bots and health checks are exempt. A request carrying your admin secret is never blocked.</p>';
    body.innerHTML = h;
    timeline($('sx-tl'), d.timeline || []);
    hbars($('sx-kinds'), d.by_kind || []);
    body.querySelectorAll('[data-mode]').forEach(function (b) { b.onclick = function () { setMode(b.getAttribute('data-mode')); }; });
    $('sx-lock').onclick = function () { toggleLock(!d.lockdown); };
    body.querySelectorAll('#sx-tabs button').forEach(function (b) { b.onclick = function () { S.tab = b.getAttribute('data-t'); render(); }; });
    pane();
  }

  function eventRows(list) {
    if (!list.length) return '<div class="sx-empty">No threats recorded in this period. That is a good sign.</div>';
    return '<div class="sx-scroll"><table class="sx-t"><thead><tr><th>Time</th><th>IP</th><th>Country</th><th>Network</th><th>Threat</th><th>Score</th><th>Action</th><th>Detail</th><th></th></tr></thead><tbody>' +
      list.map(function (e) {
        return '<tr><td>' + when(e.ts) + '</td><td class="sx-mono">' + esc(e.ip) + '</td><td>' + esc(e.country || '—') + '</td><td>' + esc(e.org || '—') + '</td><td>' + esc(label(e.kind)) + '</td><td>' + badge(e.score) + '</td><td>' + actBadge(e.action) + '</td>' +
          '<td style="max-width:320px">' + esc((e.path || '') + (e.detail ? ' · ' + e.detail : '')) + '</td><td>' + (e.ip ? '<button class="sm" data-block="' + esc(e.ip) + '">Block</button> <button class="sm" data-allow="' + esc(e.ip) + '">Allow</button>' : '') + '</td></tr>';
      }).join('') + '</tbody></table></div>';
  }
  function wireRowButtons(p) {
    p.querySelectorAll('[data-block]').forEach(function (b) { b.onclick = function () { blockIp(b.getAttribute('data-block')); }; });
    p.querySelectorAll('[data-allow]').forEach(function (b) { b.onclick = function () { allowIp(b.getAttribute('data-allow')); }; });
    p.querySelectorAll('[data-unblock]').forEach(function (b) { b.onclick = function () { unblock(b.getAttribute('data-unblock')); }; });
    p.querySelectorAll('[data-unallow]').forEach(function (b) { b.onclick = function () { unallow(b.getAttribute('data-unallow')); }; });
    p.querySelectorAll('[data-release]').forEach(function (b) { b.onclick = function () { releaseHold(b.getAttribute('data-release')); }; });
    p.querySelectorAll('[data-unasn]').forEach(function (b) { b.onclick = function () { unasn(b.getAttribute('data-unasn')); }; });
  }

  async function pane() {
    var p = $('sx-pane'), d = S.data;
    if (S.tab === 'live') {
      p.innerHTML = '<h4>Live threat monitor</h4><div class="sub">Newest first. IPs are shown in full because only you can see this page. Every view is audited.</div>' + eventRows(d.live || []);
    } else if (S.tab === 'top') {
      var t = d.top_sources || [];
      p.innerHTML = '<h4>Top threat sources</h4><div class="sub">Highest score in the selected period</div>' + (!t.length ? '<div class="sx-empty">No sources flagged.</div>' :
        '<div class="sx-scroll"><table class="sx-t"><thead><tr><th>IP</th><th>Country</th><th>Network</th><th>Main threat</th><th>Peak</th><th>Events</th><th>Last seen</th><th>Last action</th><th></th></tr></thead><tbody>' +
        t.map(function (r) { return '<tr><td class="sx-mono">' + esc(r.ip) + '</td><td>' + esc(r.country || '—') + '</td><td>' + esc(r.org || '—') + '</td><td>' + esc(label(r.main_kind)) + '</td><td>' + badge(r.max_score) + '</td><td>' + num(r.events) + '</td><td>' + when(r.last_seen) + '</td><td>' + actBadge(r.last_action) + '</td><td><button class="sm" data-block="' + esc(r.ip) + '">Block</button> <button class="sm" data-allow="' + esc(r.ip) + '">Allow</button></td></tr>'; }).join('') + '</tbody></table></div>');
    } else if (S.tab === 'blocks') {
      p.innerHTML = '<div class="sx-empty">Loading…</div>';
      var b = await api('/api/admin/sentinel/blocks'); S.blocks = b;
      if (!b.success) { p.innerHTML = '<div class="sx-warn">' + esc(b.error || 'failed') + '</div>'; return; }
      var h = holdsHtml(b.holds || []) + '<h4>Blocked IPs</h4><div class="sub">Manual blocks apply in every mode, including Observation.</div>' +
        '<div class="sx-form"><input id="sx-bip" placeholder="IP address"><input id="sx-bmin" placeholder="Minutes (blank = permanent)" inputmode="numeric"><input id="sx-brs" placeholder="Reason"><button class="dng" id="sx-bgo">Block</button></div>';
      h += !b.ips.length ? '<div class="sx-empty">No IPs blocked.</div>' : '<div class="sx-scroll"><table class="sx-t"><thead><tr><th>IP</th><th>Level</th><th>Reason</th><th>By</th><th>Since</th><th>Expires</th><th></th></tr></thead><tbody>' +
        b.ips.map(function (r) { return '<tr><td class="sx-mono">' + esc(r.ip) + '</td><td>' + esc(r.level) + '</td><td>' + esc(r.reason) + '</td><td>' + esc(r.created_by || r.source) + '</td><td>' + when(r.created_at) + '</td><td>' + (r.expires_at ? when(r.expires_at) : 'never') + '</td><td><button class="sm" data-unblock="' + esc(r.ip) + '">Unblock</button></td></tr>'; }).join('') + '</tbody></table></div>';
      h += '<h4 style="margin-top:20px">Blocked networks (ASN)</h4><div class="sub">Blocks a whole network. Use sparingly: it can cut off real customers on that provider.</div>' +
        '<div class="sx-form"><input id="sx-asn" placeholder="ASN, e.g. 14061"><input id="sx-asnr" placeholder="Reason"><button class="dng" id="sx-asngo">Block network</button></div>';
      h += !b.networks.length ? '<div class="sx-empty">No networks blocked.</div>' : '<div class="sx-scroll"><table class="sx-t"><tbody>' + b.networks.map(function (r) { return '<tr><td>AS' + esc(r.asn) + '</td><td>' + esc(r.reason) + '</td><td>' + when(r.created_at) + '</td><td><button class="sm" data-unasn="' + esc(r.asn) + '">Remove</button></td></tr>'; }).join('') + '</tbody></table></div>';
      h += '<h4 style="margin-top:20px">Trusted (never scored or blocked)</h4><div class="sub">Your office, monitoring, bot server. Single IP or CIDR range.</div>' +
        '<div class="sx-form"><input id="sx-aip" placeholder="IP or CIDR"><input id="sx-anote" placeholder="Note"><button class="pri" id="sx-ago">Add</button></div>';
      h += !(b.allow.length + b.env_allow.length) ? '<div class="sx-empty">Nothing on the allow-list.</div>' : '<div class="sx-scroll"><table class="sx-t"><tbody>' +
        b.allow.map(function (r) { return '<tr><td class="sx-mono">' + esc(r.value) + '</td><td>' + esc(r.note) + '</td><td>' + when(r.created_at) + '</td><td><button class="sm" data-unallow="' + esc(r.value) + '">Remove</button></td></tr>'; }).join('') +
        b.env_allow.map(function (v) { return '<tr><td class="sx-mono">' + esc(v) + '</td><td colspan="3">set in SENTINEL_ALLOW_IPS</td></tr>'; }).join('') + '</tbody></table></div>';
      h += '<p class="sx-note">Exempt from SENTINEL entirely (protected by their own signatures/secrets): ' + esc((b.exempt_prefixes || []).join('  ')) + '</p>';
      p.innerHTML = h;
      $('sx-bgo').onclick = function () { blockIp($('sx-bip').value.trim(), $('sx-bmin').value.trim(), $('sx-brs').value.trim()); };
      $('sx-asngo').onclick = blockAsn;
      $('sx-ago').onclick = function () { allowIp($('sx-aip').value.trim(), $('sx-anote').value.trim()); };
    } else {
      p.innerHTML = '<div class="sx-empty">Loading…</div>';
      var a = await api('/api/admin/sentinel/audit');
      if (!a.success) { p.innerHTML = '<div class="sx-warn">' + esc(a.error || 'failed') + '</div>'; return; }
      p.innerHTML = '<h4>Administrative audit log</h4><div class="sub">Every security action and every view of this data.</div><div class="sx-scroll"><table class="sx-t"><thead><tr><th>Time</th><th>Who</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead><tbody>' +
        a.audit.map(function (r) { return '<tr><td>' + when(r.ts) + '</td><td>' + esc(r.actor) + '</td><td>' + esc(r.action) + '</td><td class="sx-mono">' + esc(r.target) + '</td><td>' + esc(r.detail) + '</td></tr>'; }).join('') + '</tbody></table></div>' +
        '<h4 style="margin-top:18px">Alert delivery</h4>' + (!a.notifications.length ? '<div class="sx-empty">No alerts sent yet.</div>' : '<div class="sx-scroll"><table class="sx-t"><tbody>' +
        a.notifications.map(function (r) { return '<tr><td>' + when(r.ts) + '</td><td>' + esc(r.channel) + '</td><td>' + esc(r.subject) + '</td><td>' + (r.ok ? '<span class="sx-b ok">sent</span>' : '<span class="sx-b c">failed</span>') + '</td><td>' + esc(r.detail) + '</td></tr>'; }).join('') + '</tbody></table></div>');
      return;
    }
    wireRowButtons(p);
  }

  function holdsHtml(rows) {
    return '<h4>Accounts on automatic hold</h4><div class="sub">Accounts Sentinel deactivated because their own session sent attack payloads. They restore automatically; release one early if it was a false alarm.</div>' +
      (!rows.length ? '<div class="sx-empty">No accounts on hold.</div>' : '<div class="sx-scroll"><table class="sx-t"><thead><tr><th>Account</th><th>Reason</th><th>Since</th><th>Restores</th><th></th></tr></thead><tbody>' +
        rows.map(function (r) { return '<tr><td>#' + esc(r.user_id) + ' ' + esc(r.email || '') + '</td><td class="wrap">' + esc(r.reason) + '</td><td>' + when(r.created_at) + '</td><td>' + when(r.until) + ' UTC</td><td><button class="sm" data-release="' + esc(r.user_id) + '">Release now</button></td></tr>'; }).join('') + '</tbody></table></div>') +
      '<div style="height:18px"></div>';
  }
  async function releaseHold(id) {
    if (!confirm('Restore account #' + id + ' now?')) return;
    var r = await post('/api/admin/sentinel/holds/release', { user_id: id }); if (!r.success) alert(r.error || 'failed'); pane();
  }

  // ---- actions
  async function setMode(m) {
    if (m === 'adaptive' && !confirm('Adaptive mode will start rate-limiting, challenging and blocking confirmed attackers automatically. Continue?')) return;
    if (m === 'maximum' && !confirm('Maximum mode blocks attackers automatically for 12 hours and deactivates accounts that send attack payloads (they restore after 12 hours). Real customers are protected: country or hosting provider alone never blocks anyone. Continue?')) return;
    var r = await post('/api/admin/sentinel/mode', { mode: m }); if (!r.success) alert(r.error || 'failed'); loadSecurity();
  }
  async function toggleLock(on) {
    if (on && !confirm('Emergency lockdown refuses ALL new logins, registrations and money actions for every visitor. Existing payments and webhooks are unaffected. Enable?')) return;
    var r = await post('/api/admin/sentinel/lockdown', { on: on }); if (!r.success) alert(r.error || 'failed'); loadSecurity();
  }
  async function blockIp(ip, mins, reason) {
    if (!ip) return;
    if (mins === undefined) { mins = prompt('Block ' + ip + ' for how many minutes? (leave empty for permanent)', '1440'); if (mins === null) return; reason = 'blocked from Security tab'; }
    var r = await post('/api/admin/sentinel/block', { ip: ip, minutes: mins ? parseInt(mins, 10) : 0, reason: reason || 'manual block' });
    if (!r.success) alert(r.error || 'failed'); S.tab = 'blocks'; loadSecurity();
  }
  async function unblock(ip) { var r = await post('/api/admin/sentinel/unblock', { ip: ip }); if (!r.success) alert(r.error || 'failed'); pane(); }
  async function allowIp(v, note) {
    if (!v) return;
    var r = await post('/api/admin/sentinel/allow', { value: v, note: note || 'added from Security tab' }); if (!r.success) alert(r.error || 'failed'); S.tab = 'blocks'; pane();
  }
  async function unallow(v) { var r = await api('/api/admin/sentinel/allow', { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ value: v }) }); if (!r.success) alert(r.error || 'failed'); pane(); }
  async function blockAsn() {
    var a = $('sx-asn').value.trim(); if (!a) return;
    if (!confirm('Block the whole network AS' + a.replace(/\D/g, '') + '? Real customers on it will be blocked too.')) return;
    var r = await post('/api/admin/sentinel/block-network', { asn: a, reason: $('sx-asnr').value.trim() || 'manual' }); if (!r.success) alert(r.error || 'failed'); pane();
  }
  async function unasn(a) { var r = await api('/api/admin/sentinel/block-network', { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ asn: a }) }); if (!r.success) alert(r.error || 'failed'); pane(); }

  async function loadSecurity() {
    inject();
    if (!$('sx-root')) shell();
    S.data = await api('/api/admin/sentinel/overview?hours=' + S.hours);
    render();
    clearInterval(S.timer);
    S.timer = setInterval(function () {
      var panel = $('tab-security');
      if (!panel || !panel.classList.contains('active') || document.hidden || (document.activeElement && /INPUT|SELECT/.test(document.activeElement.tagName))) return;
      api('/api/admin/sentinel/overview?hours=' + S.hours).then(function (d) { if (d && d.success) { S.data = d; if (S.tab === 'live' || S.tab === 'top') render(); } });
    }, 30000);
  }
  window.loadSecurity = loadSecurity;

  // red badge on the tab when something critical happened in the last 24h
  async function badgeTick() {
    try {
      if (typeof adminSecret !== 'string' || !adminSecret) return;
      var d = await adminFetch('/api/admin/sentinel/overview?hours=24');
      var tab = document.querySelector('.admin-tab[data-tab="security"]'); if (!tab || !d || !d.success) return;
      var old = tab.querySelector('.sx-badge'); if (old) old.remove();
      var n = (d.kpis.critical || 0) + (d.kpis.active_blocks || 0) * 0;
      if (n > 0) { var s = document.createElement('span'); s.className = 'sx-badge'; s.textContent = n > 99 ? '99+' : n; tab.appendChild(s); }
    } catch (e) {}
  }
  setTimeout(badgeTick, 4000); setInterval(badgeTick, 120000);
})();

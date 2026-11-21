/* NET365 International Intelligence tab. Needs adminFetch() and <div id="tab-intl" class="tab-panel"></div>.
 * Entry point: loadIntl(). Data: /api/admin/sentinel/intelligence */
(function () {
  'use strict';
  var S = { days: 7, data: null, filter: 'all', q: '' };
  var CSS = '' +
    '.ii{--b:#2a78d6;--o:#eb6834;--g:#1baf7a;--r:#c93434;--a:#b7791f;--t:#1e293b;--m:#64748b;--l:#e2e8f0;--s:#fff;color:var(--t)}' +
    'body.dark-mode .ii{--b:#3987e5;--o:#d95926;--g:#199e70;--r:#e66a6a;--a:#e0a43a;--t:#e2e8f0;--m:#94a3b8;--l:#334155;--s:#1e293b}' +
    '.ii *{box-sizing:border-box}.ii-bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:14px}.ii-bar h3{margin:0 auto 0 0}' +
    '.ii button,.ii select,.ii input{padding:8px 12px;border-radius:8px;border:1px solid var(--l);background:var(--s);color:var(--t);font:inherit;cursor:pointer;max-width:100%}.ii input{cursor:text}' +
    '.ii-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:14px}' +
    '.ii-kpi{background:var(--s);border:1px solid var(--l);border-radius:12px;padding:12px 14px}.ii-kpi .k{font-size:12px;color:var(--m)}.ii-kpi .v{font-size:24px;font-weight:700;font-variant-numeric:tabular-nums}.ii-kpi.hot .v{color:var(--r)}' +
    '.ii-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:14px;margin-bottom:14px}' +
    '.ii-card{background:var(--s);border:1px solid var(--l);border-radius:12px;padding:16px;min-width:0}.ii-card h4{margin:0 0 2px;font-size:15px}.ii-card .sub{font-size:12px;color:var(--m);margin-bottom:10px}' +
    '.ii-t{width:100%;border-collapse:collapse;font-size:13px}.ii-t th{text-align:left;color:var(--m);font-weight:600;padding:6px 8px;border-bottom:1px solid var(--l);white-space:nowrap}' +
    '.ii-t td{padding:7px 8px;border-bottom:1px solid var(--l);vertical-align:top}.ii-t td.n,.ii-t th.n{text-align:right;font-variant-numeric:tabular-nums}.ii-scroll{overflow-x:auto}' +
    '.ii-b{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid var(--l);white-space:nowrap}' +
    '.ii-b.alert{border-color:var(--r);color:var(--r);background:rgba(201,52,52,.1)}.ii-b.monitor{border-color:var(--a);color:var(--a)}.ii-b.allow{border-color:var(--g);color:var(--g)}' +
    '.ii-mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}.ii-note{font-size:12px;color:var(--m);margin:8px 0 0}.ii-empty{padding:24px 0;text-align:center;color:var(--m);font-size:13px}' +
    '.ii-warn{padding:8px 12px;border:1px solid var(--l);border-left:3px solid var(--a);border-radius:6px;font-size:12px;margin-bottom:10px;background:var(--s)}';
  function $(id) { return document.getElementById(id); }
  function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
  function num(n) { return (Number(n) || 0).toLocaleString('en-NG'); }
  function when(s) { var m = String(s || '').match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})/); return m ? m[3] + '/' + m[2] + ' ' + m[4] : (s || ''); }
  var RN = null; try { RN = new Intl.DisplayNames(['en'], { type: 'region' }); } catch (e) {}
  function cname(c) { if (!c || c === '??') return 'Unknown'; try { return (RN && RN.of(c)) || c; } catch (e) { return c; } }
  function inject() { if ($('ii-style')) return; var s = document.createElement('style'); s.id = 'ii-style'; s.textContent = CSS; document.head.appendChild(s); }
  function badge(a, t) { return '<span class="ii-b ' + esc(a) + '">' + esc(t || a) + '</span>'; }
  async function api(p) {
    try { return await adminFetch(p); } catch (e) {
      var m = String(e && e.message || e);
      if (/unexpected token|JSON|<!doctype/i.test(m)) m = 'Intelligence API not found (404). Upload net365_intl_intel.py, register it in app.py, then redeploy.';
      return { success: false, error: m };
    }
  }
  function kpi(k, v, hot) { return '<div class="ii-kpi' + (hot && v ? ' hot' : '') + '"><div class="k">' + k + '</div><div class="v">' + num(v) + '</div></div>'; }

  function shell() {
    $('tab-intl').innerHTML = '<div class="ii"><div class="ii-bar"><h3>🌍 International Intelligence</h3>' +
      '<select id="ii-days"><option value="1">Last 24 hours</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option></select>' +
      '<button id="ii-refresh">↻ Refresh</button></div><div id="ii-body"><div class="ii-empty">Loading…</div></div></div>';
    $('ii-days').value = String(S.days);
    $('ii-days').onchange = function () { S.days = +this.value; loadIntl(); };
    $('ii-refresh').onclick = function () { loadIntl(); };
  }

  function render() {
    var d = S.data, b = $('ii-body');
    if (!d || !d.success) { b.innerHTML = '<div class="ii-warn" style="border-left-color:var(--r)">' + esc((d && d.error) || 'Could not load.') + '</div>'; return; }
    var cnt = function (k) { return (d.summary.filter(function (s) { return s.label === k; })[0] || {}).ips || 0; };
    var h = '<div class="ii-kpis">' + kpi('Distinct IPs', d.total_ips) + kpi('Outside ' + cname(d.home_country), d.international_ips) + kpi('Need attention', d.alerts, 1) +
      kpi('Verified search crawlers', cnt('verified_crawler')) + kpi('Failed crawler check', cnt('spoofed_crawler'), 1) + kpi('AI crawlers', cnt('ai_crawler')) +
      kpi('Datacenter / VPN', cnt('datacenter')) + kpi('Residential / mobile', cnt('consumer')) + '</div>';
    if (d.verification_pending) h += '<div class="ii-warn">' + d.verification_pending + ' crawler claim(s) are being verified by reverse DNS. Refresh in a minute.</div>';
    h += '<div class="ii-grid"><div class="ii-card"><h4>What the traffic is</h4><div class="sub">Distinct IP addresses per classification</div><table class="ii-t"><thead><tr><th>Classification</th><th>Action</th><th class="n">IPs</th></tr></thead><tbody>' +
      (d.summary.map(function (s) { return '<tr><td>' + esc(s.text) + '</td><td>' + badge(s.action) + '</td><td class="n">' + num(s.ips) + '</td></tr>'; }).join('') || '<tr><td colspan="3" class="ii-empty">No visitors in this period.</td></tr>') + '</tbody></table></div>' +
      '<div class="ii-card"><h4>Countries</h4><div class="sub">By requests, with how many IPs need attention</div><div class="ii-scroll"><table class="ii-t"><thead><tr><th>Country</th><th class="n">IPs</th><th class="n">Requests</th><th class="n">Bots</th><th class="n">Datacenter</th><th class="n">Attention</th></tr></thead><tbody>' +
      d.countries.slice(0, 15).map(function (c) { return '<tr><td>' + esc(cname(c.country)) + '</td><td class="n">' + num(c.ips) + '</td><td class="n">' + num(c.hits) + '</td><td class="n">' + num(c.bots) + '</td><td class="n">' + num(c.datacenter) + '</td><td class="n">' + num(c.alerts) + '</td></tr>'; }).join('') + '</tbody></table></div></div></div>';
    h += '<div class="ii-card" style="margin-bottom:14px"><h4>Organisations and networks</h4><div class="sub">Who owns the networks visitors come from. The network owner is not proof of who is browsing.</div><div class="ii-scroll"><table class="ii-t"><thead><tr><th>Organisation</th><th>ASN</th><th>Country</th><th>Type</th><th class="n">IPs</th><th class="n">Requests</th></tr></thead><tbody>' +
      d.organisations.slice(0, 20).map(function (o) { return '<tr><td>' + esc(o.org) + '</td><td class="ii-mono">' + esc(o.asn) + '</td><td>' + esc(cname(o.country)) + '</td><td>' + esc(o.network_type || '—') + '</td><td class="n">' + num(o.ips) + '</td><td class="n">' + num(o.hits) + '</td></tr>'; }).join('') + '</tbody></table></div></div>';
    h += '<div class="ii-card"><h4>Visitors</h4><div class="sub">Most important first</div><div class="ii-bar"><select id="ii-f"><option value="all">All</option><option value="alert">Need attention</option><option value="monitor">Monitor</option><option value="allow">Fine</option><option value="intl">Outside home country</option></select>' +
      '<input id="ii-q" type="search" placeholder="Search IP, organisation, country…"><span id="ii-count" class="ii-note" style="margin:0"></span></div><div class="ii-scroll" id="ii-list"></div></div>';
    h += '<p class="ii-note">' + d.notes.map(esc).join(' ') + '</p>';
    b.innerHTML = h;
    $('ii-f').value = S.filter; $('ii-q').value = S.q;
    $('ii-f').onchange = function () { S.filter = this.value; list(); };
    $('ii-q').oninput = function () { S.q = this.value; list(); };
    list();
  }

  function list() {
    var d = S.data, q = S.q.toLowerCase();
    var rows = d.visitors.filter(function (v) {
      if (S.filter === 'intl' ? !v.international : (S.filter !== 'all' && v.action !== S.filter)) return false;
      return !q || [v.ip, v.org, v.country, cname(v.country), v.city, v.label_text, v.bot_name].join(' ').toLowerCase().indexOf(q) >= 0;
    });
    $('ii-count').textContent = rows.length + ' shown';
    $('ii-list').innerHTML = rows.length ? '<table class="ii-t"><thead><tr><th>IP</th><th>Classification</th><th>Action</th><th>Organisation</th><th>Location</th><th class="n">Requests</th><th class="n">Peak/min</th><th>Why</th><th>Last seen</th></tr></thead><tbody>' +
      rows.map(function (v) {
        return '<tr><td class="ii-mono">' + esc(v.ip) + '</td><td>' + esc(v.label_text) + '</td><td>' + badge(v.action) + '</td><td>' + esc(v.org || '—') + '<div class="ii-note" style="margin:0">' + esc(v.asn || '') + ' ' + esc(v.network_type || '') + '</div></td>' +
          '<td>' + esc(cname(v.country)) + '<div class="ii-note" style="margin:0">' + esc(v.city || '') + '</div></td><td class="n">' + num(v.hits) + '</td><td class="n">' + num(v.peak_per_minute) + '</td><td style="min-width:200px">' + esc((v.reasons || []).join('; ')) + '</td><td>' + when(v.last_seen) + '</td></tr>';
      }).join('') + '</tbody></table>' : '<div class="ii-empty">Nothing matches this filter.</div>';
  }

  async function loadIntl() {
    inject();
    if (!$('ii-body')) shell();
    S.data = await api('/api/admin/sentinel/intelligence?days=' + S.days);
    render();
  }
  window.loadIntl = loadIntl;
})();
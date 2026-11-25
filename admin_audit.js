/* Net365 admin: Logs tab. Served like admin_insights.js (add <script src="/admin_audit.js"></script> in admin.html).
   Uses helpers already defined in admin.html: adminFetch, escapeHtml, formatDate, fetchAllPages, runExport, downloadCSV, todayStamp, showToast. */
(function () {
  const PAGE = 100;
  let offset = 0, total = 0;

  const filters = () => ({
    actor_type: document.getElementById('auActorType').value, category: document.getElementById('auCategory').value,
    status: document.getElementById('auStatus').value, action: document.getElementById('auAction').value.trim(),
    actor: document.getElementById('auActor').value.trim(), ip: document.getElementById('auIp').value.trim(),
    q: document.getElementById('auQ').value.trim(), start: document.getElementById('auStart').value, end: document.getElementById('auEnd').value
  });
  const qs = (limit, off) => { const p = new URLSearchParams({ limit, offset: off }); const f = filters(); Object.keys(f).forEach(k => f[k] && p.set(k, f[k])); return '/api/admin/audit?' + p.toString(); };

  function shell() {
    const sel = (id, label, opts) => `<select id="${id}" onchange="auditReload()"><option value="">${label}</option>${opts.map(o => `<option>${o}</option>`).join('')}</select>`;
    document.getElementById('tab-audit').innerHTML = `
      <div class="panel"><h3><i class="fas fa-clipboard-list"></i> Activity Logs</h3>
        <p style="color:var(--text-secondary);font-size:13px;margin-bottom:12px;">Every sign-up, login, code sent and entered, payment, admin action and chat security event. Passwords, PINs and codes are never stored.</p>
        <div id="auStats" class="metric-grid"></div>
        <div class="filters">
          ${sel('auActorType', 'All actors', ['user', 'admin', 'agent', 'chat', 'anonymous', 'system'])}
          ${sel('auCategory', 'All categories', ['auth', 'account', 'verification', 'payment', 'schedule', 'admin', 'chat', 'support', 'ads', 'system'])}
          ${sel('auStatus', 'Any outcome', ['success', 'failed', 'denied'])}
          <input id="auAction" placeholder="Action (e.g. login_failed)" onchange="auditReload()">
          <input id="auActor" placeholder="Actor email / id" onchange="auditReload()">
          <input id="auIp" placeholder="IP" onchange="auditReload()">
          <input id="auQ" placeholder="Search target / details" onchange="auditReload()">
          <input type="date" id="auStart" onchange="auditReload()"><input type="date" id="auEnd" onchange="auditReload()">
          <button class="btn btn-sm btn-primary" onclick="auditReload()"><i class="fas fa-refresh"></i> Refresh</button>
          <button class="btn btn-sm btn-success" id="auExportBtn" onclick="auditExport()"><i class="fas fa-download"></i> Export CSV</button>
          <button class="btn btn-sm" onclick="auditVerify()"><i class="fas fa-shield-halved"></i> Verify integrity</button>
        </div>
        <div style="overflow-x:auto;"><table><thead><tr><th>Time</th><th>Who</th><th>Action</th><th>Target</th><th>Outcome</th><th>IP</th><th>Details</th></tr></thead>
        <tbody id="auRows"><tr><td colspan="7"><div class="empty-state">Loading...</div></td></tr></tbody></table></div>
        <div class="pagination"><button class="btn btn-sm" onclick="auditPage(-1)">← Prev</button><span id="auLabel" style="color:var(--text-secondary);font-size:13px;"></span><button class="btn btn-sm" onclick="auditPage(1)">Next →</button></div>
      </div>`;
  }

  window.loadAudit = async function () { if (!document.getElementById('auRows')) shell(); offset = 0; await render(); loadStats(); };
  window.auditReload = function () { offset = 0; render(); };
  window.auditPage = function (d) { const n = offset + d * PAGE; if (n < 0 || n >= total) return; offset = n; render(); };

  async function render() {
    const body = document.getElementById('auRows');
    try {
      const d = await adminFetch(qs(PAGE, offset));
      if (!d.success) throw new Error(d.error || 'failed');
      total = d.total;
      const badge = s => `<span class="badge ${s === 'success' ? 'badge-success' : s === 'denied' ? 'badge-warning' : 'badge-danger'}">${escapeHtml(s)}</span>`;
      body.innerHTML = d.logs.length ? d.logs.map(r => `<tr>
        <td>${formatDate(r.ts)}</td><td>${escapeHtml(r.actor_type)}${r.actor_label ? '<br><span style="color:var(--text-secondary)">' + escapeHtml(r.actor_label) + '</span>' : ''}${r.actor_id ? ' #' + r.actor_id : ''}</td>
        <td><b>${escapeHtml(r.action)}</b><br><span style="color:var(--text-secondary)">${escapeHtml(r.category || '')}</span></td>
        <td style="white-space:normal;max-width:180px;">${escapeHtml(r.target || '')}</td><td>${badge(r.status)} ${r.http_status || ''}</td>
        <td style="font-family:monospace">${escapeHtml(r.ip || '')}</td>
        <td style="white-space:normal;max-width:260px;font-size:11px;color:var(--text-secondary)">${escapeHtml(r.details || '')}</td></tr>`).join('')
        : '<tr><td colspan="7"><div class="empty-state">No activity matches these filters.</div></td></tr>';
      document.getElementById('auLabel').textContent = total ? `Showing ${offset + 1}–${offset + d.logs.length} of ${total.toLocaleString()}` : '';
    } catch (e) { body.innerHTML = `<tr><td colspan="7"><div class="empty-state">${escapeHtml(e.message)}. Is net365_audit.py installed and init_audit called in app.py?</div></td></tr>`; }
  }

  async function loadStats() {
    try {
      const d = await adminFetch('/api/admin/audit/stats?days=7'); if (!d.success) return;
      const n = k => (d.by_status.find(x => x.status === k) || { n: 0 }).n;
      const card = (v, l) => `<div class="metric-card"><div class="value">${v}</div><div class="label">${l}</div></div>`;
      document.getElementById('auStats').innerHTML = card(n('success') + n('failed') + n('denied'), 'Events (7 days)') + card(n('failed'), 'Failed') + card(n('denied'), 'Denied')
        + card(d.failed_logins.reduce((a, x) => a + x.n, 0), 'Failed logins') + card(d.wrong_codes.reduce((a, x) => a + x.n, 0), 'Wrong codes') + card(d.admin_denied.reduce((a, x) => a + x.n, 0), 'Admin access denied');
    } catch (e) { }
  }

  window.auditExport = function () {
    return runExport('audit', 'auExportBtn', async () => {
      const rows = await fetchAllPages((l, o) => qs(l, o), 'logs', 500, EXPORT_MAX_ROWS);
      if (!rows.length) { showToast('No logs match these filters', 'warning'); return; }
      downloadCSV(`net365_audit_${todayStamp()}.csv`, ['Time (UTC)', 'Actor type', 'Actor', 'Actor id', 'Action', 'Category', 'Target', 'Outcome', 'HTTP', 'IP', 'Path', 'Details'],
        rows.map(r => [r.ts, r.actor_type, r.actor_label, r.actor_id, r.action, r.category, r.target, r.status, r.http_status, r.ip, r.path, r.details]));
      showToast(`Exported ${rows.length} log rows`, 'success');
    });
  };

  window.auditVerify = async function () {
    const d = await adminFetch('/api/admin/audit/verify');
    showToast(d.ok ? `Log is intact (${d.checked} rows checked)` : `Tampering detected at row ${d.first_bad_id}`, d.ok ? 'success' : 'error');
  };
})();

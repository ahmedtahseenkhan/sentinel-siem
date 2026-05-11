(function () {
  const SUPER_ADMIN_ONLY_PAGES = ['stack', 'data-sources', 'advanced'];
  let currentUser = null;

  const API = {
    agentsSummary: '/api/agents/summary',
    agents: '/api/agents',
    agentsHealth: '/api/agents/health',
    managerStatus: '/api/manager/status',
    indexerHealth: '/api/indexer/health',
    stackStatus: '/api/stack/status',
    dashboardOverview: '/api/dashboard/overview',
    managerTest: '/api/manager/test',
    indexerPatterns: '/api/indexer/patterns',
    indexerTest: '/api/indexer/test',
    alertsRecent: '/api/alerts/recent',
    alertsDashboard: '/api/alerts/dashboard',
    alertsList: '/api/alerts/list',
    discoverFields: '/api/discover/fields',
    discoverFieldValues: '/api/discover/field-values',
    alertsBySeverity: '/api/alerts/by-severity',
    alertsByRule: '/api/alerts/by-rule',
    alertsByAgent: '/api/alerts/by-agent',
    alertsSeverityOverTime: '/api/alerts/severity-over-time',
    alertsByTactic: '/api/alerts/by-tactic',
    alertsRuleGroups: '/api/alerts/rule-groups',
    dashboardStats: '/api/dashboard/stats',
    vulnerabilitiesSummary: '/api/vulnerabilities/summary',
    vulnerabilitiesRecent: '/api/vulnerabilities/recent',
    vulnerabilitiesList: '/api/vulnerabilities/list',
    vulnerabilitiesTrends: '/api/vulnerabilities/trends',
    vulnerabilitiesTopAgents: '/api/vulnerabilities/top-agents',
    vulnerabilitiesTopPackages: '/api/vulnerabilities/top-packages',
    vulnerabilitiesKpis: '/api/vulnerabilities/kpis',
    inventorySystemSummary: '/api/inventory/system/summary',
    inventorySystemList: '/api/inventory/system/list',
    inventoryPackagesSummary: '/api/inventory/packages/summary',
    inventoryPackagesList: '/api/inventory/packages/list',
    inventoryProcessesSummary: '/api/inventory/processes/summary',
    inventoryProcessesHistogram: '/api/inventory/processes/histogram',
    inventoryProcessesList: '/api/inventory/processes/list',
    inventoryUsersSummary: '/api/inventory/users/summary',
    inventoryUsersList: '/api/inventory/users/list',
    hipaaDashboard: '/api/hipaa/dashboard',
    hipaaControls: '/api/hipaa/controls',
    hipaaEvents: '/api/hipaa/events',
    rules: '/api/rules',
    rulesFiles: '/api/rules/files',
    decoders: '/api/decoders',
    decodersFiles: '/api/decoders/files',
    indexerManagementIndices: '/api/indexer/management/indices',
    mitreTactics: '/api/alerts/by-tactic',
    mitreMatrix: '/api/mitre/matrix',
    fimSummary: '/api/fim/summary',
    fimEvents: '/api/fim/events',
    auditSummary: '/api/audit/summary',
    auditEvents: '/api/audit/events',
    scaSummary: '/api/sca/summary',
    scaAgents: '/api/sca/agents',
    customVizList: '/api/custom/visualizations',
    customVizPreview: '/api/custom/visualizations/_inline/preview',
    customDashList: '/api/custom/dashboards',
    reportsGenerate: '/api/reports/generate',
    notificationsConfig: '/api/notifications/config',
    notificationsTest: '/api/notifications/test',
  };

  let utcClockInterval = null;
  const MONTHS = 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(' ');
  const THEME_STORAGE_KEY = 'sentinel_theme';

  function getTheme() {
    try {
      const t = localStorage.getItem(THEME_STORAGE_KEY);
      return t === 'light' || t === 'dark' ? t : 'dark';
    } catch (e) { return 'dark'; }
  }
  function setTheme(theme) {
    try { localStorage.setItem(THEME_STORAGE_KEY, theme); } catch (e) {}
  }
  function applyTheme(theme) {
    const root = document.documentElement;
    root.setAttribute('data-theme', theme);
    const btn = document.getElementById('themeToggle');
    if (btn) {
      btn.textContent = theme === 'dark' ? '🌙' : '☀️';
      btn.title = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
    }
  }
  (function initTheme() {
    const theme = getTheme();
    document.documentElement.setAttribute('data-theme', theme);
    var btn = document.getElementById('themeToggle');
    if (btn) {
      btn.textContent = theme === 'dark' ? '🌙' : '☀️';
      btn.title = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
    }
  })();

  const SIDEBAR_STORAGE_KEY = 'sentinel_sidebar_collapsed';
  function getSidebarCollapsed() {
    try {
      return localStorage.getItem(SIDEBAR_STORAGE_KEY) === '1';
    } catch (e) { return false; }
  }
  function setSidebarCollapsed(collapsed) {
    try { localStorage.setItem(SIDEBAR_STORAGE_KEY, collapsed ? '1' : '0'); } catch (e) {}
  }
  function applySidebarCollapsed(collapsed) {
    const app = document.querySelector('.app');
    if (app) app.classList.toggle('sidebar-collapsed', !!collapsed);
    const btn = document.getElementById('sidebarToggle');
    if (btn) btn.setAttribute('aria-label', collapsed ? 'Show sidebar' : 'Hide sidebar');
  }
  (function initSidebar() {
    applySidebarCollapsed(getSidebarCollapsed());
  })();

  const PAGES = {
    overview: { title: 'Overview', desc: 'Security posture and key metrics' },
    stack: { title: 'Stack Status', desc: 'Sentinel manager and indexer status' },
    'data-sources': { title: 'Data Sources', desc: 'Manager API and index patterns' },
    'index-management': { title: 'Index Management', desc: 'View and manage indexer indices' },
    agents: { title: 'Agent Health', desc: 'Agent status and connectivity' },
    'threat-hunting': { title: 'Threat Hunting', desc: 'Top threats and alert patterns' },
    alerts: { title: 'Alerts', desc: 'Recent security alerts' },
    discover: { title: 'Discover', desc: 'Alert table with search and full details' },
    rules: { title: 'Rules', desc: 'Manage rules and add new rule files' },
    decoders: { title: 'Decoders', desc: 'Manage decoders and add new decoder files' },
    vulnerabilities: { title: 'Vulnerabilities', desc: 'Vulnerability counts and findings' },
    visualizations: { title: 'Visualizations', desc: 'Charts by agent, severity, and tactic' },
    dashboard: { title: 'Dashboard', desc: 'Filtered dashboard with time range' },
    'it-hygiene': { title: 'IT Hygiene', desc: 'System, software, processes, and identity inventory' },
    advanced: { title: 'Advanced', desc: 'Scripts, wodles, and configuration' },
    compliance: { title: 'Compliance', desc: 'Compliance framework views' },
  };

  const DASHBOARD_STORAGE_KEY = 'sentinel_dashboard';
  function getDashboardSaved() {
    try {
      const s = localStorage.getItem(DASHBOARD_STORAGE_KEY);
      return s ? JSON.parse(s) : {};
    } catch (e) { return {}; }
  }
  function setDashboardSaved(obj) {
    try {
      localStorage.setItem(DASHBOARD_STORAGE_KEY, JSON.stringify(obj));
    } catch (e) {}
  }
  function getTimeRangeBounds(range) {
    const now = new Date();
    let start = new Date(now);
    if (range === '24h') start.setHours(now.getHours() - 24);
    else if (range === '7d') start.setDate(now.getDate() - 7);
    else if (range === '30d') start.setDate(now.getDate() - 30);
    else start.setDate(now.getDate() - 7);
    return {
      time_from: start.toISOString().slice(0, 19) + 'Z',
      time_to: now.toISOString().slice(0, 19) + 'Z',
      days: range === '24h' ? 1 : range === '30d' ? 30 : 7
    };
  }

  function escapeHtml(s) {
    if (s == null || s === '') return '';
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  function levelClass(level) {
    if (level == null) return '';
    const n = parseInt(level, 10);
    if (n >= 10) return 'level-high';
    if (n >= 5) return 'level-mid';
    return 'level-low';
  }

  function severityClass(s) {
    if (!s) return '';
    const v = String(s).toLowerCase();
    if (v.includes('critical')) return 'sev-critical';
    if (v.includes('high')) return 'sev-high';
    if (v.includes('medium')) return 'sev-medium';
    return 'sev-low';
  }

  async function fetchJson(url) {
    const res = await fetch(url);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || res.statusText);
    }
    return res.json();
  }

  function setNav(pageId) {
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-page') === pageId);
    });
    document.querySelectorAll('.nav-tab').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-page') === pageId);
    });
    document.querySelectorAll('.page').forEach(el => {
      el.classList.toggle('active', el.id === 'page-' + pageId);
    });
    const header = document.querySelector('.content-header');
    const meta = PAGES[pageId] || {};
    if (pageId === 'overview') {
      if (header) header.classList.add('header-overview');
      const pt = document.getElementById('pageTitle');
      const pd = document.getElementById('pageDesc');
      if (pt) pt.textContent = 'GLOBAL SECURITY OPERATIONS COMMAND';
      if (pd) pd.textContent = '';
      startUtcClock();
    } else {
      if (header) header.classList.remove('header-overview');
      const pt = document.getElementById('pageTitle');
      const pd = document.getElementById('pageDesc');
      if (pt) pt.textContent = meta.title || pageId;
      if (pd) pd.textContent = meta.desc || '';
      stopUtcClock();
    }
  }

  function startUtcClock() {
    function tick() {
      const d = new Date();
      const h = d.getUTCHours(), m = d.getUTCMinutes(), s = d.getUTCSeconds();
      const day = d.getUTCDate(), month = MONTHS[d.getUTCMonth()], year = d.getUTCFullYear();
      const el = document.getElementById('headerUtc');
      if (el) el.textContent = `${day} ${month} ${year} ${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`;
    }
    stopUtcClock();
    tick();
    utcClockInterval = setInterval(tick, 1000);
  }

  function stopUtcClock() {
    if (utcClockInterval) {
      clearInterval(utcClockInterval);
      utcClockInterval = null;
    }
  }

  function renderAgentCards(data) {
    const conn = data?.connection || {};
    const total = conn.total ?? 0;
    const active = conn.active ?? 0;
    const disconnected = conn.disconnected ?? 0;
    const never = conn.never_connected ?? 0;
    const pending = conn.pending ?? 0;
    return `
      <div class="card card-total"><div class="label">Total</div><div class="value">${total}</div></div>
      <div class="card card-active"><div class="label">Active</div><div class="value">${active}</div></div>
      <div class="card card-disconnected"><div class="label">Disconnected</div><div class="value">${disconnected}</div></div>
      <div class="card card-never"><div class="label">Never connected</div><div class="value">${never}</div></div>
      <div class="card card-pending"><div class="label">Pending</div><div class="value">${pending}</div></div>
    `;
  }

  function renderManagerStatus(data) {
    const items = data?.data?.affected_items || [];
    const pairs = [];
    items.forEach(obj => {
      if (obj && typeof obj === 'object') {
        Object.entries(obj).forEach(([name, status]) => {
          if (name && status) pairs.push({ name, status: String(status).toLowerCase() });
        });
      }
    });
    pairs.sort((a, b) => a.name.localeCompare(b.name));
    if (pairs.length === 0) return '<span class="empty-msg">No daemon data</span>';
    return pairs.map(({ name, status }) => {
      const cls = status === 'running' ? 'running' : 'stopped';
      return `<div class="daemon"><span>${escapeHtml(name)}</span><span class="${cls}">${escapeHtml(status)}</span></div>`;
    }).join('');
  }

  function renderIndexerHealth(data) {
    const status = data?.status || 'unknown';
    const cluster = data?.cluster_name || '—';
    const nodes = data?.number_of_nodes ?? '—';
    const dataNodes = data?.number_of_data_nodes ?? '—';
    const activeShards = data?.active_primary_shards ?? '—';
    const unassigned = data?.unassigned_shards ?? 0;
    const statusClass = status === 'green' ? 'running' : status === 'yellow' ? 'key' : 'stopped';
    return `
      <div class="line"><span class="key">Status</span><span class="${statusClass}">${escapeHtml(status)}</span></div>
      <div class="line"><span class="key">Cluster</span><span>${escapeHtml(cluster)}</span></div>
      <div class="line"><span class="key">Nodes</span><span>${nodes}</span></div>
      <div class="line"><span class="key">Data nodes</span><span>${dataNodes}</span></div>
      <div class="line"><span class="key">Active primary shards</span><span>${activeShards}</span></div>
      <div class="line"><span class="key">Unassigned shards</span><span>${unassigned}</span></div>
    `;
  }

  function renderStackStatus(data) {
    const manager = data?.manager || {};
    const indexer = data?.indexer || {};
    const config = data?.config || {};
    const mOk = manager.connected;
    const iOk = indexer.connected;
    const cards = [
      `<div class="card"><div class="label">Manager</div><div class="value ${mOk ? 'badge-ok' : 'badge-fail'}">${mOk ? 'Connected' : 'Disconnected'}</div></div>`,
      `<div class="card"><div class="label">Indexer</div><div class="value ${iOk ? 'badge-ok' : 'badge-fail'}">${iOk ? 'Connected' : 'Disconnected'}</div></div>`,
    ];
    const info = manager.info || {};
    const ver = info.version || '—';
    const mDetail = mOk
      ? `<div class="line"><span class="key">Version</span><span>${escapeHtml(ver)}</span></div>
         <div class="line"><span class="key">Type</span><span>${escapeHtml(info.type || '—')}</span></div>
         <div class="line"><span class="key">Path</span><span>${escapeHtml(info.path || '—')}</span></div>`
      : `<span class="error-msg">${escapeHtml(manager.error || 'Connection failed')}</span>`;
    const idxInfo = indexer.info || {};
    const iDetail = iOk
      ? `<div class="line"><span class="key">Version</span><span>${escapeHtml(idxInfo.version_number || '—')}</span></div>
         <div class="line"><span class="key">Cluster</span><span>${escapeHtml(idxInfo.cluster_name || '—')}</span></div>
         <div class="line"><span class="key">Node</span><span>${escapeHtml(idxInfo.name || '—')}</span></div>`
      : `<span class="error-msg">${escapeHtml(idxInfo.error || 'Connection failed')}</span>`;
    const cfgHtml = `
      <div class="line"><span class="key">Manager URL</span><span>${escapeHtml(config.manager_url || '—')}</span></div>
      <div class="line"><span class="key">Manager user</span><span>${escapeHtml(config.manager_user || '—')}</span></div>
      <div class="line"><span class="key">Indexer URL</span><span>${escapeHtml(config.indexer_url || '—')}</span></div>
      <div class="line"><span class="key">Indexer user</span><span>${escapeHtml(config.indexer_user || '—')}</span></div>
      <div class="line"><span class="key">Verify SSL</span><span>${config.verify_ssl ? 'Yes' : 'No'}</span></div>
    `;
    return { cards: cards.join(''), mDetail, iDetail, cfgHtml };
  }

  function renderAgentsTable(data) {
    const items = data?.data?.affected_items || [];
    if (items.length === 0) return '<tr><td colspan="6" class="empty-msg">No agents</td></tr>';
    return items.map(a => {
      const status = (a.status || '').toLowerCase().replace(' ', '_');
      const lastKeep = a.last_keep_alive ? new Date(a.last_keep_alive).toLocaleString() : '—';
      const os = [a.os?.name, a.os?.version].filter(Boolean).join(' ') || '—';
      return `<tr>
        <td>${escapeHtml(String(a.id || ''))}</td>
        <td>${escapeHtml(a.name || '—')}</td>
        <td>${escapeHtml(a.ip || '—')}</td>
        <td><span class="status-${status}">${escapeHtml(a.status || '')}</span></td>
        <td>${escapeHtml(os)}</td>
        <td>${escapeHtml(lastKeep)}</td>
      </tr>`;
    }).join('');
  }

  function severityLabel(level) {
    const n = parseInt(level, 10);
    if (n >= 12) return '🔴 CRIT';
    if (n >= 8) return '🟠 HIGH';
    if (n >= 4) return '🟡 MED';
    return '🟢 LOW';
  }

  function renderAlertsRows(alerts) {
    if (!alerts || alerts.length === 0) return '<tr><td colspan="5" class="empty-msg">No alerts</td></tr>';
    return alerts.map(a => {
      const time = a.timestamp ? new Date(a.timestamp).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
      const level = a.rule_level != null ? a.rule_level : '';
      const label = severityLabel(level);
      const desc = (a.rule_description || '—').slice(0, 50);
      const source = a.agent_name || a.agent_id || '—';
      return `<tr>
        <td class="stream-time">${escapeHtml(time)}</td>
        <td><span class="severity-pill severity-pill--${levelClass(level)}">${escapeHtml(String(level))}</span></td>
        <td>${escapeHtml(String(a.rule_id || '—'))}</td>
        <td class="stream-alert-name">${escapeHtml(desc)}</td>
        <td>${escapeHtml(source)}</td>
      </tr>`;
    }).join('');
  }

  function renderAlertsRowsLegacy(alerts) {
    if (!alerts || alerts.length === 0) return '<tr><td colspan="6" class="empty-msg">No alerts</td></tr>';
    return alerts.map(a => {
      const time = a.timestamp ? new Date(a.timestamp).toLocaleString() : '—';
      const levelCls = levelClass(a.rule_level);
      return `<tr>
        <td>${escapeHtml(time)}</td>
        <td><span class="${levelCls}">${escapeHtml(String(a.rule_level ?? '—'))}</span></td>
        <td>${escapeHtml((a.rule_description || a.rule_id || '—').slice(0, 55))}${(a.rule_description || '').length > 55 ? '…' : ''}</td>
        <td>${escapeHtml(a.agent_name || a.agent_id || '—')}</td>
        <td>${escapeHtml(a.srcip || '—')}</td>
        <td>${escapeHtml(a.dstuser || '—')}</td>
      </tr>`;
    }).join('');
  }

  function renderOverviewAlertsRows(alerts) {
    if (!alerts || alerts.length === 0) return '<tr><td colspan="5" class="empty-msg">No alerts</td></tr>';
    return alerts.slice(0, 15).map(a => {
      const time = a.timestamp ? new Date(a.timestamp).toLocaleString() : '—';
      const levelCls = levelClass(a.rule_level);
      return `<tr>
        <td>${escapeHtml(time)}</td>
        <td><span class="${levelCls}">${escapeHtml(String(a.rule_level ?? '—'))}</span></td>
        <td>${escapeHtml((a.rule_description || a.rule_id || '—').slice(0, 50))}${(a.rule_description || '').length > 50 ? '…' : ''}</td>
        <td>${escapeHtml(a.agent_name || a.agent_id || '—')}</td>
        <td>${escapeHtml(a.srcip || '—')}</td>
      </tr>`;
    }).join('');
  }

  function renderSeverityChart(buckets) {
    if (!buckets || buckets.length === 0) return '<span class="empty-msg">No data</span>';
    const max = Math.max(...buckets.map(b => b.doc_count), 1);
    const severityLabel = (key) => {
      const n = parseInt(key, 10);
      if (n >= 12) return 'Critical';
      if (n >= 8) return 'High';
      if (n >= 5) return 'Medium';
      return 'Low';
    };
    return buckets.map((b, i) => {
      const pct = (b.doc_count / max) * 100;
      const cls = levelClass(b.key);
      const label = severityLabel(b.key) + ' (' + b.key + ')';
      return `<div class="bar-item bar-item--chart bar-item--severity">
        <span class="bar-label bar-label--severity ${cls}">${escapeHtml(label)}</span>
        <div class="bar-track bar-track--rounded"><div class="bar-fill ${cls} bar-fill--rounded" style="width:${pct}%"></div></div>
        <span class="bar-count bar-count--strong">${b.doc_count.toLocaleString()}</span>
      </div>`;
    }).join('');
  }

  function renderRulesChart(buckets) {
    if (!buckets || buckets.length === 0) return '<span class="empty-msg">No data</span>';
    return `<ul class="rule-list">${buckets.map(b => `
      <li><span class="rule-desc" title="${escapeHtml(b.key)}">${escapeHtml(String(b.key).slice(0, 48))}${b.key.length > 48 ? '…' : ''}</span><span class="rule-count">${b.doc_count}</span></li>
    `).join('')}</ul>`;
  }

  function normalizeAgentLabel(name) {
    if (!name || typeof name !== 'string') return name;
    const s = name.trim().toLowerCase();
    if (s === 'wazuh.manager' || s === 'wazuh-manager' || s === 'watchtower') return 'Sentinel Manager';
    return name;
  }

  function renderByAgentChart(buckets) {
    if (!buckets || buckets.length === 0) return '<span class="empty-msg">No data</span>';
    const max = Math.max(...buckets.map(b => b.doc_count), 1);
    return buckets.map((b, i) => {
      const pct = (b.doc_count / max) * 100;
      const rawName = b.key || ('Agent ' + (b.agent_id || ''));
      const name = normalizeAgentLabel(rawName);
      const display = String(name).slice(0, 24) + (name.length > 24 ? '…' : '');
      const rank = i + 1;
      const isTop = rank <= 3;
      return `<div class="bar-item bar-item--chart ${isTop ? 'bar-item--top' : ''}" data-rank="${rank}">
        <span class="bar-rank">${rank}</span>
        <span class="bar-label bar-label--agent" title="${escapeHtml(name)}">${escapeHtml(display)}</span>
        <div class="bar-track bar-track--rounded"><div class="bar-fill bar-fill--agent" style="width:${pct}%"></div></div>
        <span class="bar-count bar-count--strong">${b.doc_count.toLocaleString()}</span>
      </div>`;
    }).join('');
  }

  function renderVulnSummary(buckets) {
    if (!buckets || buckets.length === 0) return '<span class="empty-msg">No vulnerability data</span>';
    const max = Math.max(...buckets.map(b => b.doc_count), 1);
    return buckets.map(b => {
      const pct = (b.doc_count / max) * 100;
      const cls = severityClass(b.key);
      return `<div class="bar-item">
        <span class="bar-label ${cls}">${escapeHtml(String(b.key || '—'))}</span>
        <div class="bar-track"><div class="bar-fill ${cls}" style="width:${pct}%"></div></div>
        <span class="bar-count">${b.doc_count}</span>
      </div>`;
    }).join('');
  }

  function renderVulnTable(vulns) {
    if (!vulns || vulns.length === 0) return '<tr><td colspan="7" class="empty-msg">No findings</td></tr>';
    return vulns.map(v => {
      const detected = v.detected_at ? new Date(v.detected_at).toLocaleDateString(undefined, { day: '2-digit', month: '2-digit', year: '2-digit' }) : '—';
      const pkg = [v.package_name, v.package_version].filter(Boolean).join(' @ ') || '—';
      const score = v.score_base != null ? Number(v.score_base).toFixed(1) : '—';
      const sev = (v.severity || '').toLowerCase();
      const sevPillClass = sev.includes('critical') || sev === 'high' ? 'high' : sev === 'medium' ? 'mid' : 'low';
      const status = '—'; // Placeholder: Patch available / Fixed / No patch when backend supports it
      return `<tr>
        <td class="vuln-td-date">${escapeHtml(detected)}</td>
        <td class="vuln-td-cve">${escapeHtml(v.vuln_id || '—')}</td>
        <td><span class="severity-pill severity-pill--${sevPillClass}">${escapeHtml(v.severity || '—')}</span></td>
        <td>${escapeHtml(v.agent_name || v.agent_id || '—')}</td>
        <td class="vuln-td-pkg">${escapeHtml(pkg)}</td>
        <td>${escapeHtml(score)}</td>
        <td class="vuln-td-status">${escapeHtml(status)}</td>
      </tr>`;
    }).join('');
  }

  function getVulnTimeBounds() {
    const range = document.getElementById('vulnTimeRange')?.value || '30d';
    const now = new Date();
    let start = new Date(now);
    if (range === '24h') start.setHours(now.getHours() - 24);
    else if (range === '7d') start.setDate(now.getDate() - 7);
    else start.setDate(now.getDate() - 30);
    return {
      time_from: start.toISOString().slice(0, 19) + 'Z',
      time_to: now.toISOString().slice(0, 19) + 'Z',
      days: range === '24h' ? 1 : range === '30d' ? 30 : 7,
    };
  }

  function getVulnParams() {
    const bounds = getVulnTimeBounds();
    const p = new URLSearchParams();
    p.set('time_from', bounds.time_from);
    p.set('time_to', bounds.time_to);
    const severity = document.getElementById('vulnSeverity')?.value;
    const agent = document.getElementById('vulnAgent')?.value;
    const cvssMin = document.getElementById('vulnCvssMin')?.value;
    const cvssMax = document.getElementById('vulnCvssMax')?.value;
    if (severity) p.set('severity', severity);
    if (agent) p.set('agent_name', agent);
    if (cvssMin) p.set('cvss_min', cvssMin);
    if (cvssMax) p.set('cvss_max', cvssMax);
    const search = document.getElementById('vulnSearch')?.value?.trim();
    if (search) {
      if (/CVE/i.test(search)) p.set('cve', search);
      else p.set('package', search);
    }
    return { params: p, bounds };
  }

  function drawVulnTrend(canvasId, legendId, seriesData) {
    const canvas = document.getElementById(canvasId);
    const legendEl = document.getElementById(legendId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.width;
    const h = canvas.height;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    const padding = { top: 24, right: 24, bottom: 32, left: 44 };
    const chartW = w - padding.left - padding.right;
    const chartH = h - padding.top - padding.bottom;
    const series = seriesData?.series || [];
    if (series.length === 0) {
      ctx.fillStyle = '#8b949e';
      ctx.font = '12px Outfit';
      ctx.fillText('No trend data', padding.left, padding.top + chartH / 2);
      if (legendEl) legendEl.innerHTML = '';
      return;
    }
    const severities = new Set();
    series.forEach(s => (s.buckets || []).forEach(b => severities.add(String(b.key))));
    const severityList = Array.from(severities);
    const colors = ['#f85149', '#d29922', '#3fb950', '#58a6ff', '#bc8cff'];
    let maxVal = 0;
    series.forEach(s => (s.buckets || []).forEach(b => { if (b.doc_count > maxVal) maxVal = b.doc_count; }));
    maxVal = Math.max(1, maxVal);
    const stepX = series.length > 1 ? chartW / (series.length - 1) : chartW;
    ctx.fillStyle = '#0d1117';
    ctx.fillRect(0, 0, w, h);
    ctx.strokeStyle = '#30363d';
    ctx.fillStyle = '#8b949e';
    ctx.font = '10px JetBrains Mono';
    severityList.forEach((sev, idx) => {
      const points = [];
      series.forEach((s, i) => {
        const bucket = (s.buckets || []).find(b => String(b.key) === sev);
        const count = bucket ? bucket.doc_count : 0;
        const x = padding.left + i * stepX;
        const y = padding.top + chartH - (count / maxVal) * chartH;
        points.push({ x, y, count });
      });
      if (points.length === 0) return;
      const color = colors[idx % colors.length];
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.beginPath();
      points.forEach((pt, i) => {
        if (i === 0) ctx.moveTo(pt.x, pt.y);
        else ctx.lineTo(pt.x, pt.y);
      });
      ctx.stroke();
    });
    if (legendEl) legendEl.innerHTML = severityList.map((s, i) =>
      `<span style="color:${colors[i % colors.length]}">■</span> ${escapeHtml(s)}`
    ).join(' &nbsp; ');
  }

  function drawTimeline(canvasId, timeline24h) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.width;
    const h = canvas.height;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    const padding = { top: 20, right: 20, bottom: 30, left: 40 };
    const chartW = w - padding.left - padding.right;
    const chartH = h - padding.top - padding.bottom;
    const buckets = timeline24h || [];
    const maxVal = Math.max(...buckets.map(b => b.count), 1);
    const step = buckets.length > 0 ? chartW / Math.max(buckets.length, 1) : 0;

    ctx.fillStyle = '#0d1117';
    ctx.fillRect(0, 0, w, h);
    ctx.strokeStyle = '#30363d';
    ctx.fillStyle = '#8b949e';
    ctx.font = '10px JetBrains Mono';
    ctx.fillText('0', padding.left - 20, padding.top + chartH + 4);
    ctx.fillText(String(Math.ceil(maxVal)), padding.left - 28, padding.top + 4);

    ctx.beginPath();
    ctx.strokeStyle = '#58a6ff';
    ctx.lineWidth = 2;
    buckets.forEach((b, i) => {
      const x = padding.left + i * step + step / 2;
      const y = padding.top + chartH - (b.count / maxVal) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    ctx.fillStyle = 'rgba(210, 153, 34, 0.3)';
    ctx.beginPath();
    buckets.forEach((b, i) => {
      const x = padding.left + i * step + step / 2;
      const y = padding.top + chartH - (b.count / maxVal) * chartH;
      if (i === 0) ctx.moveTo(x, padding.top + chartH);
      ctx.lineTo(x, y);
    });
    ctx.lineTo(padding.left + buckets.length * step - step / 2, padding.top + chartH);
    ctx.closePath();
    ctx.fill();
  }

  function drawAgentsSummaryDonut(canvasId, legendId, summary) {
    const canvas = document.getElementById(canvasId);
    const legendEl = document.getElementById(legendId);
    if (!canvas) return;
    const active = summary?.active ?? 0;
    const disconnected = summary?.disconnected ?? 0;
    const pending = summary?.pending ?? 0;
    const never = summary?.never_connected ?? 0;
    const segments = [
      { label: 'Active', count: active, color: '#3fb950' },
      { label: 'Disconnected', count: disconnected, color: '#f85149' },
      { label: 'Pending', count: pending, color: '#d29922' },
      { label: 'Never connected', count: never, color: '#8b949e' },
    ].filter(s => s.count > 0);
    const total = segments.reduce((s, x) => s + x.count, 0);
    if (total === 0) {
      if (legendEl) legendEl.innerHTML = '<span class="empty-msg">No agent data</span>';
      return;
    }
    const ctx = canvas.getContext('2d');
    const cx = canvas.width / 2, cy = canvas.height / 2;
    const r = Math.min(cx, cy) - 8;
    let start = -Math.PI / 2;
    segments.forEach((seg, i) => {
      const slice = (seg.count / total) * 2 * Math.PI;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, start, start + slice);
      ctx.closePath();
      ctx.fillStyle = seg.color;
      ctx.fill();
      start += slice;
    });
    ctx.beginPath();
    ctx.arc(cx, cy, r * 0.5, 0, 2 * Math.PI);
    ctx.fillStyle = '#161b22';
    ctx.fill();
    if (legendEl) legendEl.innerHTML = segments.map(s => `<span><span class="legend-dot" style="background:${s.color}"></span>${escapeHtml(s.label)} (${s.count})</span>`).join('');
  }

  function drawMitreDonut(canvasId, legendId, mitreList) {
    const canvas = document.getElementById(canvasId);
    const legendEl = document.getElementById(legendId);
    if (!canvas || !mitreList || mitreList.length === 0) {
      if (legendEl) legendEl.innerHTML = '<span class="empty-msg">No MITRE data</span>';
      return;
    }
    const total = mitreList.reduce((s, m) => s + m.count, 0);
    const colors = ['#f85149', '#d29922', '#58a6ff', '#3fb950', '#bc8cff', '#56d4dd'];
    const ctx = canvas.getContext('2d');
    const cx = canvas.width / 2, cy = canvas.height / 2;
    const r = Math.min(cx, cy) - 8;
    let start = -Math.PI / 2;
    mitreList.forEach((m, i) => {
      const slice = (m.count / total) * 2 * Math.PI;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, start, start + slice);
      ctx.closePath();
      ctx.fillStyle = colors[i % colors.length];
      ctx.fill();
      start += slice;
    });
    ctx.beginPath();
    ctx.arc(cx, cy, r * 0.5, 0, 2 * Math.PI);
    ctx.fillStyle = '#161b22';
    ctx.fill();
    legendEl.innerHTML = mitreList.map((m, i) =>
      `<span style="color:${colors[i % colors.length]}">■</span> ${escapeHtml(String(m.technique).slice(0, 25))} (${m.pct}%)`
    ).join('<br>');
  }

  function drawThreatSummaryDonut(canvasId, centerId, legendId, sev24) {
    const canvas = document.getElementById(canvasId);
    const centerEl = document.getElementById(centerId);
    const legendEl = document.getElementById(legendId);
    if (!canvas) return;
    const critical = sev24?.critical ?? 0;
    const high = sev24?.high ?? 0;
    const medium = sev24?.medium ?? 0;
    const low = sev24?.low ?? 0;
    const segments = [
      { label: 'Critical', count: critical, color: '#f85149' },
      { label: 'High', count: high, color: '#d29922' },
      { label: 'Medium', count: medium, color: '#d4a72c' },
      { label: 'Low', count: low, color: '#8b949e' },
    ].filter(s => s.count > 0);
    const total = segments.reduce((s, x) => s + x.count, 0);
    if (centerEl) centerEl.textContent = total > 0 ? String(total) : '0';
    if (total === 0) {
      if (legendEl) legendEl.innerHTML = '<span class="empty-msg">No alerts</span>';
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      return;
    }
    const ctx = canvas.getContext('2d');
    const cx = canvas.width / 2, cy = canvas.height / 2;
    const r = Math.min(cx, cy) - 8;
    let start = -Math.PI / 2;
    segments.forEach((seg) => {
      const slice = (seg.count / total) * 2 * Math.PI;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, start, start + slice);
      ctx.closePath();
      ctx.fillStyle = seg.color;
      ctx.fill();
      start += slice;
    });
    ctx.beginPath();
    ctx.arc(cx, cy, r * 0.55, 0, 2 * Math.PI);
    ctx.fillStyle = '#161b22';
    ctx.fill();
    if (legendEl) legendEl.innerHTML = segments.map(s => {
      const pct = total ? Math.round((s.count / total) * 100) : 0;
      return `<span><span class="legend-dot" style="background:${s.color}"></span>${escapeHtml(s.label)}: ${s.count.toLocaleString()} (${pct}%)</span>`;
    }).join('');
  }

  async function loadOverview() {
    const data = await fetchJson(API.dashboardOverview).catch(e => ({ error: e }));
    if (data.error) {
      const msg = escapeHtml(data.error.message);
      const kpiEvents = document.getElementById('kpiTotalEvents');
      const kpiAssets = document.getElementById('kpiMonitoredAssets');
      if (kpiEvents) kpiEvents.textContent = '—';
      if (kpiAssets) kpiAssets.textContent = '—';
      const critEl = document.getElementById('criticalCount');
      const healthEl = document.getElementById('healthPct');
      const healthLabelEl = document.getElementById('systemHealthLabel');
      if (critEl) critEl.textContent = '—';
      if (healthEl) healthEl.textContent = '—';
      if (healthLabelEl) healthLabelEl.textContent = '—';
      const so = document.getElementById('topSourcesList');
      const se = document.getElementById('topSourcesEmpty');
      if (so) so.innerHTML = '';
      if (se) { se.classList.remove('hidden'); se.querySelector('.overview-empty-text').textContent = 'Error loading data'; }
      document.getElementById('atRiskUsers').innerHTML = '';
      document.getElementById('atRiskDevices').innerHTML = '';
      document.getElementById('liveAlertStream').innerHTML = `<tr><td colspan="5" class="error-msg">${msg}</td></tr>`;
      const leg = document.getElementById('agentsSummaryDonutLegend');
      if (leg) leg.innerHTML = '<span class="error-msg">—</span>';
      return;
    }

    const totalEvents = data.timeline_total ?? data.recent_alerts_total ?? 0;
    const agentsSummary = data.agents_summary || {};
    const totalAgents = (agentsSummary.total != null && agentsSummary.total !== '') ? agentsSummary.total : (data.agent_status_list || []).length;
    const healthPct = data.system_health_pct ?? 99.8;
    const kpiEventsEl = document.getElementById('kpiTotalEvents');
    const kpiAssetsEl = document.getElementById('kpiMonitoredAssets');
    const healthLabelEl = document.getElementById('systemHealthLabel');
    if (kpiEventsEl) kpiEventsEl.textContent = typeof totalEvents === 'number' ? totalEvents.toLocaleString() : totalEvents;
    if (kpiAssetsEl) kpiAssetsEl.textContent = typeof totalAgents === 'number' ? totalAgents.toLocaleString() : (totalAgents || '—');
    document.getElementById('criticalCount').textContent = data.critical_incidents ?? 0;
    document.getElementById('healthPct').textContent = healthPct + '%';
    if (healthLabelEl) healthLabelEl.textContent = healthPct >= 95 ? 'OPERATIONAL' : healthPct >= 80 ? 'DEGRADED' : 'ISSUE';

    drawAgentsSummaryDonut('agentsSummaryDonutCanvas', 'agentsSummaryDonutLegend', agentsSummary);
    const sev24 = data.alert_severity_24h || {};
    drawThreatSummaryDonut('threatSummaryDonutCanvas', 'threatSummaryTotal', 'threatSummaryLegend', sev24);

    const sources = data.top_sources || [];
    const topSourcesListEl = document.getElementById('topSourcesList');
    const topSourcesEmptyEl = document.getElementById('topSourcesEmpty');
    if (topSourcesListEl && topSourcesEmptyEl) {
      if (sources.length > 0) {
        topSourcesEmptyEl.classList.add('hidden');
        const maxCount = Math.max(...sources.map(s => s.count), 1);
        topSourcesListEl.innerHTML = sources.slice(0, 8).map(s => {
          const pct = Math.min(100, (s.count / maxCount) * 100);
          return `<div class="source-ip-card"><span class="source-ip-addr">${escapeHtml(s.ip || '—')}</span><span class="source-ip-count">${s.count}</span><div class="source-ip-bar"><div class="source-ip-bar-fill" style="width:${pct}%"></div></div></div>`;
        }).join('');
        topSourcesListEl.classList.remove('hidden');
      } else {
        topSourcesListEl.classList.add('hidden');
        topSourcesListEl.innerHTML = '';
        topSourcesEmptyEl.classList.remove('hidden');
      }
    }

    drawTimeline('timelineCanvas', data.timeline_24h);
    const total = data.timeline_total ?? 0;
    const peak = data.timeline_peak ?? 0;
    const topSource = data.top_source_first ? (data.top_source_first.ip || data.top_source_first.source || '—') : null;
    const statsEl = document.getElementById('timelineStats');
    if (statsEl) {
      const parts = ['Total: ' + total.toLocaleString(), 'Peak: ' + peak.toLocaleString()];
      if (topSource) parts.push('Top Source: ' + escapeHtml(String(topSource).slice(0, 20)));
      statsEl.textContent = parts.join(' · ');
    }

    const agentList = data.agent_status_list || [];
    const liveAssetsBody = document.getElementById('liveAssetsBody');
    if (liveAssetsBody) {
      if (agentList.length === 0) {
        liveAssetsBody.innerHTML = '<tr><td colspan="4">No agents</td></tr>';
      } else {
        liveAssetsBody.innerHTML = agentList.map(a => {
          const status = (a.status || 'pending').toLowerCase();
          const statusLabel = status === 'active' ? 'Online' : status === 'disconnected' ? 'Offline' : status === 'pending' ? 'Pending' : 'Degraded';
          const statusCls = status === 'active' ? 'asset-status-online' : status === 'disconnected' ? 'asset-status-offline' : status === 'pending' ? 'asset-status-pending' : 'asset-status-degraded';
          let lastSeen = '—';
          if (a.last_keep_alive) {
            try {
              const t = new Date(a.last_keep_alive);
              const diff = (Date.now() - t.getTime()) / 1000;
              if (diff < 60) lastSeen = 'Just now';
              else if (diff < 3600) lastSeen = Math.floor(diff / 60) + 'm ago';
              else lastSeen = t.toLocaleString();
            } catch (e) {}
          }
          return `<tr><td>${escapeHtml(a.name || a.id || '—')}</td><td><span class="asset-status ${statusCls}"><span class="asset-status-dot"></span>${statusLabel}</span></td><td>${a.alerts ?? '—'}</td><td>${escapeHtml(lastSeen)}</td></tr>`;
        }).join('');
      }
    }

    const mttrEl = document.getElementById('responseMttr');
    if (mttrEl) mttrEl.textContent = (data.mttr_min ?? 45) + ' min';
    const mttrTrendEl = document.getElementById('responseMttrTrend');
    if (mttrTrendEl) mttrTrendEl.textContent = '▲ +12 min from avg';
    const triageEl = document.getElementById('responseTriage');
    if (triageEl) triageEl.textContent = (data.triage_rate ?? 94) + '%';
    const containmentEl = document.getElementById('responseContainment');
    const containmentPctEl = document.getElementById('responseContainmentPct');
    const containmentVal = data.containment_pct ?? 78;
    if (containmentEl) containmentEl.style.width = containmentVal + '%';
    if (containmentPctEl) containmentPctEl.textContent = containmentVal + '%';

    const users = data.at_risk_users || [];
    document.getElementById('atRiskUsers').innerHTML = users.length
      ? users.map((u, i) => `<div class="atrisk-row atrisk-row--styled"><span class="atrisk-name">${escapeHtml(String(normalizeAgentLabel(u.name)).slice(0, 18))}</span><div class="atrisk-bar-wrap atrisk-bar-wrap--rounded"><div class="atrisk-bar atrisk-bar--gradient" style="width:${Math.min(100, u.score)}%"></div></div><span class="atrisk-score atrisk-score--badge">${u.score}</span></div>`).join('')
      : '<p class="overview-empty overview-empty--inline"><span class="overview-empty-text">No user-related alerts in this period</span></p>';
    const devices = data.at_risk_devices || [];
    document.getElementById('atRiskDevices').innerHTML = devices.length
      ? devices.map(d => `<div class="atrisk-row atrisk-row--styled"><span class="atrisk-name">${escapeHtml(String(normalizeAgentLabel(d.name)).slice(0, 18))}</span><div class="atrisk-bar-wrap atrisk-bar-wrap--rounded"><div class="atrisk-bar atrisk-bar--gradient" style="width:${Math.min(100, d.score)}%"></div></div><span class="atrisk-score atrisk-score--badge">${d.score}</span></div>`).join('')
      : '<p class="overview-empty overview-empty--inline"><span class="overview-empty-text">No device alerts in this period</span></p>';

    drawMitreDonut('mitreCanvas', 'mitreLegend', data.mitre || []);

    const alerts = data.recent_alerts || [];
    const totalAlerts = data.recent_alerts_total ?? alerts.length;
    const streamBody = document.getElementById('liveAlertStream');
    if (streamBody) {
      if (alerts.length === 0) {
        streamBody.innerHTML = '<tr><td colspan="5" class="empty-msg">No alerts</td></tr>';
      } else {
        streamBody.innerHTML = alerts.map(a => {
          const time = a.timestamp ? new Date(a.timestamp).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
          const level = parseInt(a.rule_level, 10);
          const sevCls = level >= 10 ? 'high' : level >= 5 ? 'mid' : 'low';
          const sevLabel = level >= 10 ? 'Critical' : level >= 5 ? 'High' : 'Medium';
          const name = (a.rule_description || a.rule_id || 'Alert').slice(0, 48);
          const agent = a.agent_name || a.agent_id || '—';
          return `<tr>
            <td class="stream-time">${escapeHtml(time)}</td>
            <td>${escapeHtml(agent)}</td>
            <td class="stream-alert-name">${escapeHtml(name)}</td>
            <td><span class="severity-pill severity-pill--${sevCls}">${sevLabel}</span></td>
            <td><a href="#" class="stream-action-investigate" data-page="discover">[investigate]</a></td>
          </tr>`;
        }).join('');
      }
    }
    const streamFooterInfo = document.getElementById('streamFooterInfo');
    if (streamFooterInfo) streamFooterInfo.textContent = 'Showing ' + alerts.length + ' of ' + totalAlerts + ' active alerts';
  }

  async function loadDataSources() {
    const configEl = document.getElementById('managerConfigDisplay');
    const indexerConfigEl = document.getElementById('indexerConfigDisplay');
    const patternsEl = document.getElementById('indexPatternsList');
    const resultEl = document.getElementById('managerTestResult');
    const indexerResultEl = document.getElementById('indexerTestResult');
    if (resultEl) resultEl.textContent = '';
    if (indexerResultEl) indexerResultEl.textContent = '';
    const [stackData, patternsData] = await Promise.all([
      fetchJson(API.stackStatus).catch(e => ({ error: e })),
      fetchJson(API.indexerPatterns).catch(e => ({ error: e })),
    ]);
    const cfg = stackData?.config || {};
    if (configEl) {
      configEl.innerHTML = `
        <div class="line"><span class="key">Manager URL</span><span>${escapeHtml(cfg.manager_url || '—')}</span></div>
        <div class="line"><span class="key">Port</span><span>${escapeHtml((cfg.manager_url || '').match(/:(\d+)/)?.[1] || '55000')}</span></div>
        <div class="line"><span class="key">Username</span><span>${escapeHtml(cfg.manager_user || '—')}</span></div>
        <div class="line"><span class="key">Password</span><span>••••••••</span></div>
      `;
    }
    if (indexerConfigEl) {
      indexerConfigEl.innerHTML = `
        <div class="line"><span class="key">Indexer URL</span><span>${escapeHtml(cfg.indexer_url || '—')}</span></div>
        <div class="line"><span class="key">Port</span><span>${escapeHtml((cfg.indexer_url || '').match(/:(\d+)/)?.[1] || '9200')}</span></div>
        <div class="line"><span class="key">Username</span><span>${escapeHtml(cfg.indexer_user || '—')}</span></div>
        <div class="line"><span class="key">Password</span><span>••••••••</span></div>
      `;
    }
    if (patternsData.error) {
      if (patternsEl) patternsEl.innerHTML = `<span class="error-msg">${escapeHtml(patternsData.error.message)}</span>`;
    } else {
      const patterns = patternsData.patterns || [];
      if (patternsEl) {
        if (patterns.length === 0) {
          patternsEl.innerHTML = '<span class="empty-msg">No watchvault-* index patterns found.</span>';
        } else {
          patternsEl.innerHTML = patterns.map(p => {
            const primary = p.pattern === 'watchvault-alerts-*' ? ' <span class="badge-ok">(primary)</span>' : '';
            const monitoring = p.pattern === 'watchvault-monitoring-*' ? ' <span class="key">(monitoring)</span>' : '';
            const indicesList = (p.indices || []).map(i => `<span>${escapeHtml(i.name)} (${i.docs})</span>`).join('');
            return `<div class="pattern-card">
              <h4>${escapeHtml(p.pattern)}${primary}${monitoring}</h4>
              <div class="pattern-meta">Total docs: ${p.total_docs} · ${(p.indices || []).length} index(es)</div>
              <div class="pattern-indices">${indicesList || '—'}</div>
            </div>`;
          }).join('');
        }
      }
    }
  }

  async function loadStack() {
    const data = await fetchJson(API.stackStatus).catch(e => ({ error: e }));
    if (data.error) {
      document.getElementById('stackCards').innerHTML = `<div class="card card-skeleton"><span class="error-msg">${escapeHtml(data.error.message)}</span></div>`;
      document.getElementById('stackManagerDetail').innerHTML = '';
      document.getElementById('stackIndexerDetail').innerHTML = '';
      document.getElementById('stackConfig').innerHTML = '';
      return;
    }
    const r = renderStackStatus(data);
    document.getElementById('stackCards').innerHTML = r.cards;
    document.getElementById('stackManagerDetail').innerHTML = r.mDetail;
    document.getElementById('stackIndexerDetail').innerHTML = r.iDetail;
    document.getElementById('stackConfig').innerHTML = r.cfgHtml;
  }

  function formatAgentsUpdated(iso) {
    if (!iso) return '—';
    try {
      const d = new Date(iso);
      const mon = MONTHS[d.getMonth()];
      return 'Last updated: ' + d.getDate() + ' ' + mon + ' ' + d.getFullYear() + ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
    } catch (e) { return '—'; }
  }

  function renderAgentsByOs(byOs) {
    if (!byOs || byOs.length === 0) return '<p class="empty-msg">No OS data</p>';
    return byOs.map(o => {
      const total = o.total || 0;
      const active = o.active || 0;
      const disconnected = o.disconnected || 0;
      const pending = o.pending || 0;
      const pctA = total ? Math.round(100 * active / total) : 0;
      const pctD = total ? Math.round(100 * disconnected / total) : 0;
      const pctP = total ? Math.round(100 * pending / total) : 0;
      return `<div class="agents-os-card"><h4>${escapeHtml(o.os)}</h4><div class="line"><span class="key">Total</span><span>${total}</span></div><div class="line"><span class="key">🟢 Active</span><span>${active} (${pctA}%)</span></div><div class="line"><span class="key">🔴 Disconn.</span><span>${disconnected} (${pctD}%)</span></div><div class="line"><span class="key">🟡 Pending</span><span>${pending} (${pctP}%)</span></div></div>`;
    }).join('');
  }

  function renderAgentsBreakdown(agents) {
    const active = agents.filter(a => a.status === 'active');
    const disconnected = agents.filter(a => a.status === 'disconnected');
    const pending = agents.filter(a => a.status === 'pending');
    const never = agents.filter(a => a.status === 'never_connected');
    const line = (a, extra) => `<li><span class="agent-id">(${escapeHtml(String(a.id || '').padStart(3, '0'))})</span><span class="agent-detail">${escapeHtml(a.name || '—')} - ${escapeHtml(a.ip || '—')} - ${escapeHtml(a.os_label || '—')}${extra ? ' - ' + escapeHtml(extra) : ''}</span></li>`;
    return { active, disconnected, pending, never, line };
  }

  function renderAgentsBreakdownSection(list, lineFn, emptyMsg) {
    if (!list || list.length === 0) return '<p class="empty-msg">' + (emptyMsg || 'No agents') + '</p>';
    return '<ul class="agents-breakdown-list">' + list.map(a => lineFn(a)).join('') + '</ul>';
  }

  function renderAgentsTableFromHealth(agents) {
    if (!agents || agents.length === 0) return '<tr><td colspan="9" class="empty-msg">No agents found.</td></tr>';
    const badge = s => {
      const m = { active: ['agent-status-active','Connected'], disconnected: ['agent-status-disconnected','Disconnected'], pending: ['agent-status-pending','Pending'] };
      const [cls, label] = m[s] || ['agent-status-pending', s];
      return `<span class="${cls}">${label}</span>`;
    };
    return agents.map(a => {
      const alerts = (a.alert_count || 0).toLocaleString();
      const crits = a.critical_count || 0;
      const critHtml = crits > 0 ? `<span style="color:#ff4444;font-weight:700">${crits}</span>` : '<span style="color:var(--text-muted)">0</span>';
      return `<tr>
        <td>${badge(a.status)}</td>
        <td><strong>${escapeHtml(a.name || a.hostname || '—')}</strong></td>
        <td class="mono" style="font-size:11px;color:var(--text-muted)">${escapeHtml((a.id||'').slice(0,12))}…</td>
        <td>${escapeHtml(a.os_label || '—')}</td>
        <td>${escapeHtml(a.version || '—')}</td>
        <td>${alerts}</td>
        <td>${critHtml}</td>
        <td>${escapeHtml(a.last_seen_label || '—')}</td>
        <td><button type="button" class="btn-agent-view" data-agent-id="${escapeHtml(String(a.id))}" title="View agent">👁</button></td>
      </tr>`;
    }).join('');
  }

  function renderAgentCards(agents) {
    const grid = document.getElementById('agentCardsGrid');
    if (!grid) return;
    if (!agents || agents.length === 0) {
      grid.innerHTML = '<div style="color:var(--text-muted);padding:20px;text-align:center">No agents. Click <strong>Add New Agent</strong> to enroll your first system.</div>';
      return;
    }
    grid.innerHTML = agents.map(a => {
      const isActive = a.status === 'active';
      const isPending = a.status === 'pending';
      const dotClass = isActive ? 'acard-dot-active' : isPending ? 'acard-dot-pending' : 'acard-dot-disconnected';
      const statusLabel = isActive ? 'Connected' : isPending ? 'Pending' : 'Disconnected';
      const alerts = (a.alert_count || 0).toLocaleString();
      const crits = a.critical_count || 0;
      const hostname = a.hostname || a.name || a.id || '—';
      const osShort = (a.os_label || '—').replace('linux/amd64','Linux').replace('linux','Linux').replace('windows','Windows');
      return `<div class="agent-card ${isActive ? '' : 'agent-card-dim'}" data-agent-id="${escapeHtml(String(a.id))}">
        <div class="acard-header">
          <div class="acard-status-row"><span class="acard-dot ${dotClass}"></span><span class="acard-status-label">${statusLabel}</span></div>
          <button type="button" class="btn-agent-view acard-view-btn" data-agent-id="${escapeHtml(String(a.id))}" title="View details">👁</button>
        </div>
        <div class="acard-hostname">${escapeHtml(hostname)}</div>
        <div class="acard-id mono">${escapeHtml((a.id||'').slice(0,8))}…</div>
        <div class="acard-os">${escapeHtml(osShort)}</div>
        <div class="acard-metrics">
          <div class="acard-metric"><span class="acard-metric-val">${alerts}</span><span class="acard-metric-label">Alerts</span></div>
          <div class="acard-metric"><span class="acard-metric-val" style="${crits>0?'color:#ff4444':''}">${crits}</span><span class="acard-metric-label">Critical</span></div>
          <div class="acard-metric"><span class="acard-metric-val">${escapeHtml(a.version||'—')}</span><span class="acard-metric-label">Version</span></div>
        </div>
        <div class="acard-last-seen">${escapeHtml(a.last_seen_label || '—')}</div>
      </div>`;
    }).join('');
  }

  async function loadAgents() {
    const data = await fetchJson(API.agentsHealth).catch(e => ({ error: e }));
    const updatedEl = document.getElementById('agentsUpdated');
    if (data.error) {
      ['agentsKpiTotal','agentsKpiActive','agentsKpiDisconnected','agentsKpiPending'].forEach(id => {
        const el = document.getElementById(id); if (el) el.textContent = '—';
      });
      if (updatedEl) updatedEl.textContent = 'Error loading data';
      return;
    }
    const summary = data.summary || {};
    const agents = data.agents || [];
    const el = id => document.getElementById(id);
    if (el('agentsKpiTotal')) el('agentsKpiTotal').textContent = summary.total ?? '—';
    if (el('agentsKpiActive')) el('agentsKpiActive').textContent = summary.active ?? '—';
    if (el('agentsKpiDisconnected')) el('agentsKpiDisconnected').textContent = summary.disconnected ?? '—';
    if (el('agentsKpiPending')) el('agentsKpiPending').textContent = summary.pending ?? '—';
    const pct = summary.pct_active ?? 0;
    if (el('agentsHealthFill')) el('agentsHealthFill').style.width = pct + '%';
    if (el('agentsHealthPct')) el('agentsHealthPct').textContent = pct + '%';
    if (updatedEl) updatedEl.textContent = 'Updated ' + formatAgentsUpdated(data.updated_at);
    window._agentsHealthData = data;
    renderAgentCards(agents);
    const filtered = filterAgentsTable(agents);
    if (el('agentsBody')) el('agentsBody').innerHTML = renderAgentsTableFromHealth(filtered);
    if (el('agentsTableCount')) el('agentsTableCount').textContent = '(' + filtered.length + ')';
  }

  async function openAgentDetail(agentId) {
    const panel = document.getElementById('agentDetailPanel');
    const titleEl = document.getElementById('agentDetailTitle');
    const contentEl = document.getElementById('agentDetailContent');
    if (!panel || !contentEl) return;
    panel.classList.remove('hidden');
    titleEl.textContent = 'Agent ' + (agentId || '');
    contentEl.innerHTML = '<p class="empty-msg">Loading…</p>';
    const data = await fetchJson('/api/agents/' + encodeURIComponent(agentId)).catch(e => ({ error: e }));
    if (data.error) {
      contentEl.innerHTML = '<p class="error-msg">' + escapeHtml(data.error.message || 'Failed to load agent') + '</p>';
      return;
    }
    const fmt = (v) => v ? new Date(v.replace('Z', '+00:00')).toLocaleString() : '—';
    const statusDot = data.status === 'active' ? '🟢' : data.status === 'disconnected' ? '🔴' : '🟡';
    let html = '<div class="agent-detail-info">';
    html += '<div class="agent-detail-grid"><span class="key">ID</span><span>' + escapeHtml(String(data.id || '—')) + '</span>';
    html += '<span class="key">Status</span><span>' + statusDot + ' ' + escapeHtml((data.status || '—')) + '</span>';
    html += '<span class="key">IP address</span><span>' + escapeHtml(data.ip || '—') + '</span>';
    html += '<span class="key">Version</span><span>' + escapeHtml(data.version || '—') + '</span>';
    html += '<span class="key">Group</span><span>' + escapeHtml(data.group || '—') + '</span>';
    html += '<span class="key">Operating system</span><span>' + escapeHtml(data.os_label || '—') + '</span>';
    html += '<span class="key">Cluster node</span><span>' + escapeHtml(data.node_name || '—') + '</span>';
    html += '<span class="key">Registration date</span><span>' + fmt(data.date_added) + '</span>';
    html += '<span class="key">Last keep alive</span><span>' + fmt(data.last_keep_alive) + '</span>';
    html += '<span class="key">Host name</span><span>' + escapeHtml(data.hostname || '—') + '</span></div></div>';
    html += '<div class="agent-detail-widgets"><div class="panel"><h4>Events &amp; alerts</h4><p class="text-muted">View alerts for this agent on the <a href="#" class="nav-link" data-page="alerts">Alerts</a> page and filter by agent.</p></div>';
    html += '<div class="panel"><h4>Vulnerabilities</h4><p class="text-muted">See <a href="#" class="nav-link" data-page="vulnerabilities">Vulnerabilities</a> and filter by agent.</p></div>';
    html += '<div class="panel"><h4>Compliance</h4><p class="text-muted">HIPAA and other frameworks are available under <a href="#" class="nav-link" data-page="compliance">Compliance</a>.</p></div></div>';
    contentEl.innerHTML = html;
    contentEl.querySelectorAll('.nav-link').forEach(el => {
      el.addEventListener('click', (e) => { e.preventDefault(); document.getElementById('agentDetailClose').click(); setTimeout(() => goToPage(el.getAttribute('data-page')), 100); });
    });
  }

  function closeAgentDetail() {
    document.getElementById('agentDetailPanel')?.classList.add('hidden');
  }

  function filterAgentsTable(agents) {
    if (!agents) return [];
    const search = (document.getElementById('agentsSearch')?.value || '').trim().toLowerCase();
    const statusFilter = (document.getElementById('agentsFilterStatus')?.value || '').trim();
    let out = agents;
    if (statusFilter) out = out.filter(a => a.status === statusFilter);
    if (search) out = out.filter(a => (a.name || '').toLowerCase().includes(search) || (a.id || '').toString().includes(search) || (a.ip || '').toLowerCase().includes(search) || (a.os_label || '').toLowerCase().includes(search));
    return out;
  }

  async function loadThreatHunting() {
    const [byAgent, bySev, byRule] = await Promise.all([
      fetchJson(API.alertsByAgent).catch(e => ({ error: e })),
      fetchJson(API.alertsBySeverity).catch(e => ({ error: e })),
      fetchJson(API.alertsByRule).catch(e => ({ error: e })),
    ]);
    const set = (id, err, fn, data) => {
      const el = document.getElementById(id);
      if (err) el.innerHTML = `<span class="error-msg">${escapeHtml(err.message)}</span>`;
      else el.innerHTML = fn(data?.buckets || []);
    };
    set('chartByAgent', byAgent.error, renderByAgentChart, byAgent);
    set('chartSeverity', bySev.error, renderSeverityChart, bySev);
    set('chartRules', byRule.error, renderRulesChart, byRule);
  }

  const ALERTS_PAGE_SIZE = 25;
  let alertsTableOffset = 0;
  let alertsTableTotal = 0;

  function getAlertsListParams() {
    const range = document.getElementById('alertsTimeRange')?.value || '24h';
    const now = new Date();
    let start = new Date(now);
    if (range === '24h') start.setHours(now.getHours() - 24);
    else start.setDate(now.getDate() - 7);
    const time_from = start.toISOString().slice(0, 19) + 'Z';
    const time_to = now.toISOString().slice(0, 19) + 'Z';
    const min_level = document.getElementById('alertsFilterSeverity')?.value ? parseInt(document.getElementById('alertsFilterSeverity').value, 10) : undefined;
    const agent_name = document.getElementById('alertsFilterAgent')?.value || undefined;
    const rule_group = document.getElementById('alertsFilterGroup')?.value || undefined;
    return { time_from, time_to, min_level, agent_name, rule_group };
  }

  function drawAlertsTimelineStacked(canvasId, timelineBySeverity) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !timelineBySeverity || timelineBySeverity.length === 0) return;
    const ctx = canvas.getContext('2d');
    const w = 600;
    const h = 200;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    ctx.scale(dpr, dpr);
    const padding = { top: 20, right: 20, bottom: 30, left: 45 };
    const chartW = w - padding.left - padding.right;
    const chartH = h - padding.top - padding.bottom;
    const maxVal = Math.max(...timelineBySeverity.map(t => (t.critical || 0) + (t.high || 0) + (t.medium || 0) + (t.low || 0)), 1);
    const step = chartW / Math.max(timelineBySeverity.length, 1);
    const colors = { critical: '#f85149', high: '#d29922', medium: '#58a6ff', low: '#3fb950' };
    const bands = ['low', 'medium', 'high', 'critical'];
    const toY = v => padding.top + chartH - (v / maxVal) * chartH;
    const toX = i => padding.left + i * step + step / 2;
    const cum = timelineBySeverity.map(t => {
      const l = t.low || 0, m = t.medium || 0, h = t.high || 0, c = t.critical || 0;
      return { l, lm: l + m, lmh: l + m + h, total: l + m + h + c };
    });
    bands.forEach((band, bi) => {
      const keyBottom = bi === 0 ? 'zero' : (band === 'medium' ? 'l' : band === 'high' ? 'lm' : 'lmh');
      const keyTop = band === 'low' ? 'l' : band === 'medium' ? 'lm' : band === 'high' ? 'lmh' : 'total';
      ctx.fillStyle = colors[band];
      ctx.beginPath();
      for (let i = 0; i < timelineBySeverity.length; i++) {
        const bottom = keyBottom === 'zero' ? 0 : cum[i][keyBottom];
        const top = cum[i][keyTop];
        const x = toX(i);
        if (i === 0) ctx.moveTo(x, toY(bottom));
        ctx.lineTo(x, toY(top));
      }
      for (let i = timelineBySeverity.length - 1; i >= 0; i--) {
        const bottom = keyBottom === 'zero' ? 0 : cum[i][keyBottom];
        ctx.lineTo(toX(i), toY(bottom));
      }
      ctx.closePath();
      ctx.fill();
    });
    ctx.fillStyle = '#8b949e';
    ctx.font = '10px JetBrains Mono';
    ctx.fillText('0', padding.left - 8, padding.top + chartH + 4);
    ctx.fillText(String(Math.ceil(maxVal)), padding.left - 22, padding.top + 4);
  }

  async function loadAlerts() {
    const set = (id, text) => { const el = document.getElementById(id); if (el) el.textContent = text; };
    const setHtml = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
    set('alertsKpiTotal', '—');
    set('alertsKpiCritical', '—');
    set('alertsKpiHigh', '—');
    set('alertsKpiMedLow', '—');
    const d = new Date();
    const timeStr = d.getDate() + ' ' + MONTHS[d.getMonth()] + ' ' + d.getFullYear() + ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
    set('alertsHeaderTime', timeStr);

    const dash = await fetchJson(API.alertsDashboard).catch(e => ({ error: e }));
    if (dash.error) {
      set('alertsKpiTotal', '—');
      setHtml('alertsTopCategories', '<span class="error-msg">' + escapeHtml(dash.error.message) + '</span>');
      setHtml('alertsTopAgents', '');
      setHtml('alertsIncidentsBody', '<tr><td colspan="5" class="error-msg">' + escapeHtml(dash.error.message) + '</td></tr>');
      setHtml('alertsBody', '<tr><td colspan="5" class="error-msg">' + escapeHtml(dash.error.message) + '</td></tr>');
      return;
    }
    const total = dash.total_24h ?? 0;
    const sev = dash.severity_24h || {};
    const critical = sev.critical ?? 0;
    const high = sev.high ?? 0;
    const medLow = (sev.medium ?? 0) + (sev.low ?? 0);
    set('alertsKpiTotal', total.toLocaleString());
    set('alertsKpiCritical', critical.toLocaleString());
    set('alertsKpiCriticalMeta', '⚠️ —');
    set('alertsKpiHigh', high.toLocaleString());
    set('alertsKpiHighMeta', '📈 —');
    set('alertsKpiMedLow', medLow.toLocaleString());
    const timeline = dash.timeline_24h_by_severity || [];
    drawAlertsTimelineStacked('alertsTimelineCanvas', timeline);
    let peakVal = 0;
    let peakKey = '';
    timeline.forEach(t => {
      const v = (t.critical || 0) + (t.high || 0) + (t.medium || 0) + (t.low || 0);
      if (v > peakVal) { peakVal = v; peakKey = t.key || ''; }
    });
    set('alertsTimelinePeak', peakVal ? 'Peak: ' + peakVal + ' alerts at ' + (peakKey ? new Date(peakKey).toLocaleTimeString() : '') : 'Peak: —');
    const categories = dash.top_categories || [];
    const maxCat = Math.max(...categories.map(c => c.count), 1);
    setHtml('alertsTopCategories', (categories.length ? categories.map(c => {
      const pct = Math.min(100, (c.count / maxCat) * 100);
      return '<div class="bar-item"><span class="bar-label">' + escapeHtml(String(c.key).slice(0, 24)) + '</span><div class="bar-track"><div class="bar-fill level-low" style="width:' + pct + '%"></div></div><span class="bar-count">' + c.count + '</span></div>';
    }) : ['<p class="empty-msg">No data</p>']).join(''));
    const agents = dash.top_agents || [];
    const maxAg = Math.max(...agents.map(a => a.count), 1);
    setHtml('alertsTopAgents', (agents.length ? agents.map(a => {
      const pct = Math.min(100, (a.count / maxAg) * 100);
      return '<div class="bar-item"><span class="bar-label">' + escapeHtml(String(a.key).slice(0, 20)) + '</span><div class="bar-track"><div class="bar-fill level-mid" style="width:' + pct + '%"></div></div><span class="bar-count">' + a.count + '</span></div>';
    }) : ['<p class="empty-msg">No data</p>']).join(''));
    const incidents = dash.incidents || [];
    if (incidents.length === 0) setHtml('alertsIncidentsBody', '<tr><td colspan="5" class="empty-msg">No high-severity incidents</td></tr>');
    else setHtml('alertsIncidentsBody', incidents.map(a => {
      const time = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '—';
      const level = parseInt(a.rule_level, 10);
      const sevLabel = level >= 12 ? '🔴 CRIT' : '🟠 HIGH';
      const desc = (a.rule_description || '—').slice(0, 40);
      const affected = a.agent_name || a.agent_id || '—';
      return '<tr><td>' + escapeHtml(time) + '</td><td>' + sevLabel + '</td><td>' + escapeHtml(desc) + '</td><td>' + escapeHtml(affected) + '</td><td>INVESTIGATE</td></tr>';
    }).join(''));
  }

  let DISCOVER_PAGE_SIZE = 25;
  let discoverOffset = 0;
  let discoverTotal = 0;
  let discoverAlertsCache = [];
  let discoverAvailableFieldsList = [];
  let discoverSortField = 'timestamp';
  let discoverSortOrder = 'desc';
  let discoverDropdownsLoaded = false;
  let discoverAgentMap = {};  // agent_id -> hostname, built from dropdown data
  const DISCOVER_POPULAR_FIELDS = [
    'timestamp', 'rule_level', 'rule_id', 'rule_description',
    'agent_id', 'rule_groups', 'event_data.type',
    'net_remote', 'net_local', 'net_status',
    'proc_name', 'proc_pid', 'proc_cmdline', '_index',
  ];
  // Default columns — use fields that actually have data in documents
  let discoverSelectedFields = ['timestamp', 'rule_level', 'rule_id', 'rule_description', 'agent_id', 'event_data.type'];
  let discoverDslFilters = [];

  function getDiscoverParams() {
    const range = document.getElementById('discoverTimeRange')?.value || '24h';
    const now = new Date();
    const start = new Date(now);
    if (range === '7d') start.setDate(now.getDate() - 7);
    else if (range === '30d') start.setDate(now.getDate() - 30);
    else start.setHours(now.getHours() - 24);
    const time_from = start.toISOString().slice(0, 19) + 'Z';
    const time_to = now.toISOString().slice(0, 19) + 'Z';
    const min_level = document.getElementById('discoverSeverity')?.value ? parseInt(document.getElementById('discoverSeverity').value, 10) : undefined;
    const agent_id = document.getElementById('discoverAgent')?.value || undefined;
    const rule_group = document.getElementById('discoverGroup')?.value || undefined;
    const search = (document.getElementById('discoverSearch')?.value || '').trim() || undefined;
    return { range, time_from, time_to, min_level, agent_id, rule_group, search };
  }

  function getByPath(obj, path) {
    if (obj == null) return undefined;
    const aliases = {
      'rule.id': ['rule_id'],
      'rule.level': ['rule_level'],
      'rule.description': ['rule_description'],
      'rule.groups': ['rule_groups'],
      'rule_level': ['rule.level'],
      'rule_id': ['rule.id'],
      'rule_description': ['rule.description'],
      'rule_groups': ['rule.groups'],
      'agent.id': ['agent_id'],
      'agent.name': ['agent_name'],
      'agent.ip': ['agent_ip'],
      'agent_name': ['agent.name'],
      'agent_id': ['agent.id'],
      'data.srcip': ['event_data.srcip', 'srcip'],
      'data.dstuser': ['event_data.dstuser', 'dstuser'],
      'event_data.srcip': ['srcip'],
      'event_data.dstuser': ['dstuser'],
      'manager.name': ['manager'],
    };

    const tryPath = (candidate) => {
      const parts = candidate.split('.');
      let cur = obj;
      for (const p of parts) {
        cur = cur != null && typeof cur === 'object' ? cur[p] : undefined;
      }
      return cur;
    };

    const candidates = [path].concat(aliases[path] || []);
    for (const candidate of candidates) {
      const v = tryPath(candidate);
      if (v !== undefined && v !== null && v !== '') return v;
    }

    const parts = path.split('.');
    let cur = obj;
    for (const p of parts) {
      cur = cur != null && typeof cur === 'object' ? cur[p] : undefined;
    }
    return cur;
  }

  function queryFieldForExactMatch(field, type) {
    if (type === 'text') return field + '.keyword';
    return field;
  }

  function buildDiscoverDsl() {
    const params = getDiscoverParams();
    const must = [];
    if (params.time_from && params.time_to) {
      must.push({ range: { timestamp: { gte: params.time_from, lte: params.time_to } } });
    }
    // Always merge toolbar params into DSL so they are never silently dropped
    if (params.min_level != null) {
      must.push({ range: { rule_level: { gte: params.min_level } } });
    }
    if (params.agent_id) {
      must.push({ term: { 'agent_id': params.agent_id } });
    }
    if (params.rule_group) {
      must.push({ bool: { should: [
        { term: { 'rule_groups.keyword': params.rule_group } },
        { term: { 'rule_groups': params.rule_group } },
        { match: { 'rule_groups': params.rule_group } },
      ], minimum_should_match: 1 } });
    }
    if (params.search && params.search.trim()) {
      must.push({ multi_match: {
        query: params.search.trim(),
        fields: ['rule_description^3', 'rule_groups^2', 'agent_name^2', 'agent_id', 'event_data.srcip', 'event_data.dstuser'],
        type: 'best_fields', operator: 'or',
      }});
    }
    discoverDslFilters.forEach((f) => {
      let clause = null;
      const field = f.field;
      const type = f.type;
      const op = f.op;
      const val = f.value;
      const negate = !!f.negate;
      const exactField = queryFieldForExactMatch(field, type);
      if (op === 'exists') {
        clause = { exists: { field } };
      } else if (op === 'does not exist') {
        clause = { bool: { must_not: [{ exists: { field } }] } };
      } else if (op === 'is' && (val === '' || val == null)) {
        clause = { exists: { field } };
      } else if (op === 'is' && val !== '') {
        clause = { term: { [exactField]: val } };
      } else if (op === 'is not' && val !== '') {
        clause = { bool: { must_not: [{ term: { [exactField]: val } }] } };
      } else if (op === 'is one of' && val) {
        const terms = val.split(',').map((s) => s.trim()).filter(Boolean);
        if (terms.length) clause = { terms: { [exactField]: terms } };
      } else if (op === 'starts with' && val !== '') {
        clause = { prefix: { [exactField]: val } };
      } else if (op === '>' && val !== '') {
        clause = { range: { [field]: { gt: isNaN(Number(val)) ? val : Number(val) } } };
      } else if (op === '<' && val !== '') {
        clause = { range: { [field]: { lt: isNaN(Number(val)) ? val : Number(val) } } };
      } else if (op === '>=' && val !== '') {
        clause = { range: { [field]: { gte: isNaN(Number(val)) ? val : Number(val) } } };
      } else if (op === '<=' && val !== '') {
        clause = { range: { [field]: { lte: isNaN(Number(val)) ? val : Number(val) } } };
      } else if (op === 'between' && val !== '') {
        const [a, b] = val.split(',').map((s) => s.trim());
        if (a !== undefined && b !== undefined) clause = { range: { [field]: { gte: isNaN(Number(a)) ? a : Number(a), lte: isNaN(Number(b)) ? b : Number(b) } } };
      }
      if (clause) {
        if (negate) must.push({ bool: { must_not: [clause] } });
        else must.push(clause);
      }
    });
    const query = must.length > 0 ? { bool: { must } } : { match_all: {} };
    const sortClause = {};
    sortClause[discoverSortField] = { order: discoverSortOrder };
    return { query, sort: [sortClause] };
  }

  function renderDiscoverFilterPills() {
    const params = getDiscoverParams();
    const pills = [];
    discoverDslFilters.forEach((f, i) => {
      const label = f.negate ? 'NOT ' + f.field + ' ' + f.op + (f.value ? ' ' + f.value : '') : f.field + ' ' + f.op + (f.value ? ' ' + f.value : '');
      pills.push({ label: label.slice(0, 40) + (label.length > 40 ? '…' : ''), clear: () => { discoverDslFilters.splice(i, 1); renderDiscoverFilterPills(); discoverOffset = 0; loadDiscover(); } });
    });
    if (params.range && params.range !== '24h') {
      const rangeLabel = params.range === '7d' ? 'Last 7 days' : params.range === '30d' ? 'Last 30 days' : params.range;
      pills.push({ label: 'Time: ' + rangeLabel, clear: () => { const el = document.getElementById('discoverTimeRange'); if (el) el.value = '24h'; loadDiscover(); } });
    }
    if (params.min_level != null) pills.push({ label: 'Severity: ' + params.min_level + '+', clear: () => { const el = document.getElementById('discoverSeverity'); if (el) el.value = ''; loadDiscover(); } });
    if (params.agent_id) {
      const agentEl = document.getElementById('discoverAgent');
      const agentLabel = agentEl?.options[agentEl.selectedIndex]?.text || params.agent_id;
      pills.push({ label: 'Agent: ' + agentLabel, clear: () => { const el = document.getElementById('discoverAgent'); if (el) el.value = ''; loadDiscover(); } });
    }
    if (params.rule_group) pills.push({ label: 'Group: ' + params.rule_group, clear: () => { const el = document.getElementById('discoverGroup'); if (el) el.value = ''; loadDiscover(); } });
    if (params.search) pills.push({ label: 'Search: ' + params.search.slice(0, 20) + (params.search.length > 20 ? '…' : ''), clear: () => { const el = document.getElementById('discoverSearch'); if (el) el.value = ''; loadDiscover(); } });
    const el = document.getElementById('discoverFilterPills');
    if (!el) return;
    el.innerHTML = pills.length ? pills.map(p => '<span class="filter-pill">' + escapeHtml(p.label) + ' <button type="button" class="filter-pill-remove" aria-label="Remove">×</button></span>').join('') : '';
    el.querySelectorAll('.filter-pill-remove').forEach((btn, i) => { btn.addEventListener('click', () => pills[i].clear()); });
  }

  async function loadDiscoverFields() {
    const res = await fetchJson(API.discoverFields).catch(() => ({ fields: [] }));
    const list = res.fields || [];
    discoverAvailableFieldsList = list;
    renderDiscoverFieldsSidebar();
    const fieldSelect = document.getElementById('discoverFilterField');
    if (fieldSelect) {
      const current = fieldSelect.value;
      fieldSelect.innerHTML = '<option value="">Field</option>' + list.map((f) => '<option value="' + escapeHtml(f.name) + '" data-type="' + escapeHtml(f.type || 'keyword') + '">' + escapeHtml(f.name) + '</option>').join('');
      if (current && list.some((f) => f.name === current)) fieldSelect.value = current;
    }
  }

  function renderDiscoverFieldsSidebar() {
    const available = discoverAvailableFieldsList.filter((f) => !discoverSelectedFields.includes(f.name));
    const selectedList = document.getElementById('discoverSelectedFields');
    const popularList = document.getElementById('discoverPopularFields');
    const availableList = document.getElementById('discoverAvailableFields');
    if (selectedList) {
      selectedList.innerHTML = discoverSelectedFields.length ? discoverSelectedFields.map((name) => '<li><span class="field-name">' + escapeHtml(name) + '</span> <button type="button" class="field-remove" aria-label="Remove">−</button></li>').join('') : '<li class="text-muted">None selected</li>';
      selectedList.querySelectorAll('.field-remove').forEach((btn, i) => {
        btn.addEventListener('click', () => {
          discoverSelectedFields.splice(i, 1);
          renderDiscoverFieldsSidebar();
          renderDiscoverThead();
          discoverOffset = 0;
          loadDiscover();
        });
      });
    }
    if (popularList) {
      popularList.innerHTML = DISCOVER_POPULAR_FIELDS.filter((name) => !discoverSelectedFields.includes(name)).map((name) => '<li><span class="field-name">' + escapeHtml(name) + '</span> <button type="button" class="field-add" aria-label="Add">+</button></li>').join('');
      popularList.querySelectorAll('.field-add').forEach((btn, i) => {
        const name = DISCOVER_POPULAR_FIELDS.filter((n) => !discoverSelectedFields.includes(n))[i];
        if (name) btn.addEventListener('click', () => {
          if (!discoverSelectedFields.includes(name)) { discoverSelectedFields.push(name); renderDiscoverFieldsSidebar(); renderDiscoverThead(); discoverOffset = 0; loadDiscover(); }
        });
      });
    }
    if (availableList) {
      availableList.innerHTML = available.length ? available.slice(0, 80).map((f) => '<li><span class="field-name">' + escapeHtml(f.name) + '</span> <button type="button" class="field-add" aria-label="Add">+</button></li>').join('') : '<li class="text-muted">Loading… or none</li>';
      availableList.querySelectorAll('.field-add').forEach((btn, i) => {
        const f = available[i];
        if (f) btn.addEventListener('click', () => {
          if (!discoverSelectedFields.includes(f.name)) { discoverSelectedFields.push(f.name); renderDiscoverFieldsSidebar(); renderDiscoverThead(); discoverOffset = 0; loadDiscover(); }
        });
      });
    }
  }

  function renderDiscoverThead() {
    const cols = discoverSelectedFields.slice();
    const thead = document.getElementById('discoverThead');
    if (!thead) return;
    const sortable = ['timestamp', 'rule_level', 'rule_id', 'agent_name'];
    thead.innerHTML = '<tr>' + cols.map((c) => {
      const label = FIELD_LABELS[c] || c;
      const isSorted = c === discoverSortField;
      const sortIcon = isSorted ? (discoverSortOrder === 'desc' ? ' ↓' : ' ↑') : '';
      const cls = sortable.includes(c) ? ' class="sortable-th"' : '';
      return '<th' + cls + ' data-field="' + escapeHtml(c) + '">' + escapeHtml(label) + sortIcon + '</th>';
    }).join('') + '<th></th></tr>';
    thead.querySelectorAll('.sortable-th').forEach(th => {
      th.addEventListener('click', () => {
        const f = th.getAttribute('data-field');
        if (discoverSortField === f) discoverSortOrder = discoverSortOrder === 'desc' ? 'asc' : 'desc';
        else { discoverSortField = f; discoverSortOrder = 'desc'; }
        discoverOffset = 0;
        loadDiscover();
      });
    });
  }

  const FIELD_LABELS = {
    'timestamp': 'Time', 'rule_level': 'Level', 'rule.level': 'Level',
    'rule_id': 'Rule ID', 'rule.id': 'Rule ID',
    'rule_description': 'Description', 'rule.description': 'Description',
    'rule_groups': 'Groups', 'rule.groups': 'Groups',
    'agent_name': 'Agent', 'agent.name': 'Agent',
    'agent_id': 'Agent', 'agent.id': 'Agent ID',
    'agent_ip': 'Agent IP', 'agent.ip': 'Agent IP',
    'event_data.srcip': 'Source IP', 'data.srcip': 'Source IP',
    'event_data.dstuser': 'User', 'data.dstuser': 'User',
    'event_data.type': 'Event Type',
    'net_remote': 'Remote Addr', 'net_local': 'Local Addr', 'net_status': 'Conn Status',
    'proc_name': 'Process', 'proc_pid': 'PID', 'proc_cmdline': 'Cmd Line',
    '_index': 'Index', 'manager': 'Manager', 'title': 'Title',
  };

  function renderDiscoverRows(alerts) {
    const cols = discoverSelectedFields;
    const colCount = cols.length + 1;
    if (!alerts || alerts.length === 0) return '<tr><td colspan="' + colCount + '" class="empty-msg">No alerts</td></tr>';
    const levelBadge = (l) => {
      const n = Number(l);
      const cls = n >= 12 ? 'disc-lvl disc-lvl-crit' : n >= 8 ? 'disc-lvl disc-lvl-high' : n >= 4 ? 'disc-lvl disc-lvl-med' : 'disc-lvl disc-lvl-low';
      return '<span class="' + cls + '">' + n + '</span>';
    };
    const formatVal = (v, path) => {
      if (v == null || v === '') return '<span class="disc-empty">—</span>';
      if (path === 'timestamp' && (typeof v === 'string' || typeof v === 'number')) {
        const d = new Date(v);
        return '<span title="' + escapeHtml(d.toISOString()) + '">' + escapeHtml(d.toLocaleString()) + '</span>';
      }
      if (path === 'rule.level' || path === 'rule_level') return levelBadge(v);
      if (path === 'rule_groups' || path === 'rule.groups') {
        const gs = Array.isArray(v) ? v : String(v).split(',');
        return gs.map(g => '<span class="disc-group-tag">' + escapeHtml(g.trim()) + '</span>').join(' ');
      }
      if (typeof v === 'object') return '<span class="disc-json">' + escapeHtml(JSON.stringify(v).slice(0, 80)) + '</span>';
      const s = String(v);
      return escapeHtml(s.length > 120 ? s.slice(0, 120) + '…' : s);
    };
    return alerts.map((a, i) => {
      const src = a.source || {};
      const level = getByPath(src, 'rule_level') || getByPath(src, 'rule.level') || 0;
      const rowClass = 'discover-row' + (level >= 12 ? ' row-crit' : level >= 8 ? ' row-high' : '');
      const cells = cols.map((path) => {
        let v = getByPath(src, path);
        // Resolve agent_id to hostname using the agent map
        if ((path === 'agent_id' || path === 'agent.id') && v && discoverAgentMap[v]) {
          return '<td class="discover-td"><span title="' + escapeHtml(v) + '">' + escapeHtml(discoverAgentMap[v]) + '</span></td>';
        }
        return '<td class="discover-td">' + formatVal(v, path) + '</td>';
      });
      cells.push('<td class="discover-td-action"><button type="button" class="btn-disc-detail" title="Inspect event">⊕</button></td>');
      return '<tr class="' + rowClass + '" data-index="' + i + '">' + cells.join('') + '</tr>';
    }).join('');
  }

  function flattenSource(obj, prefix) {
    if (obj == null || typeof obj !== 'object') return {};
    prefix = prefix || '';
    let out = {};
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      const key = prefix ? prefix + '.' + k : k;
      if (v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Date) && typeof v.getMonth !== 'function') {
        Object.assign(out, flattenSource(v, key));
      } else if (Array.isArray(v)) {
        out[key] = v.map(x => typeof x === 'object' && x !== null && !(x instanceof Date) ? JSON.stringify(x) : x).join(', ');
      } else {
        out[key] = v;
      }
    }
    return out;
  }

  function openDiscoverDetail(alert) {
    const panel = document.getElementById('discoverDetailPanel');
    const titleEl = document.getElementById('discoverDetailTitle');
    const contentEl = document.getElementById('discoverDetailContent');
    const jsonEl = document.getElementById('discoverDetailJson');
    if (!panel || !contentEl) return;
    panel.classList.remove('hidden');
    titleEl.textContent = 'Event details · ' + (alert.timestamp ? new Date(alert.timestamp).toLocaleString() : '');
    let rows = [];
    if (alert.source && typeof alert.source === 'object') {
      const flat = flattenSource(alert.source);
      const keys = Object.keys(flat).sort();
      keys.forEach(k => {
        let v = flat[k];
        if (v == null) v = '—';
        else if (typeof v === 'string' && (v.toLowerCase() === 'wazuh.manager' || v.toLowerCase() === 'watchtower')) v = 'Sentinel Manager';
        else v = String(v);
        rows.push([k, v]);
      });
    }
    if (rows.length === 0) {
      rows = [
        ['timestamp', alert.timestamp != null ? String(alert.timestamp) : '—'],
        ['rule.id', alert.rule_id != null ? String(alert.rule_id) : '—'],
        ['rule.description', alert.rule_description || '—'],
        ['rule.level', alert.rule_level != null ? String(alert.rule_level) : '—'],
        ['rule.groups', (alert.rule_groups || []).join(', ') || '—'],
        ['agent.id', alert.agent_id || '—'],
        ['agent.name', alert.agent_name || '—'],
        ['agent.ip', alert.agent_ip || '—'],
        ['data.srcip', alert.srcip || '—'],
        ['data.dstuser', alert.dstuser || '—'],
        ['manager', (alert.manager && (alert.manager.toLowerCase() === 'wazuh.manager' || alert.manager.toLowerCase() === 'watchtower')) ? 'Sentinel Manager' : (alert.manager || '—')],
      ];
    }
    const canFilter = (val) => val !== '—' && val !== '' && val != null;
    const escAttr = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
    const rowHtml = rows.map(([k, v]) => {
      const filterable = canFilter(v);
      const actions = '<span class="detail-value-actions">' +
        '<button type="button" class="detail-action-btn detail-action-filter-for" title="Filter for value" aria-label="Filter for value" ' + (filterable ? '' : ' disabled') + ' data-action="filter-for">&#128269;+</button>' +
        '<button type="button" class="detail-action-btn detail-action-filter-out" title="Filter out value" aria-label="Filter out value" ' + (filterable ? '' : ' disabled') + ' data-action="filter-out">&#128269;−</button>' +
        '<button type="button" class="detail-action-btn detail-action-toggle-column" title="Toggle column in table" aria-label="Toggle column in table" data-action="toggle-column">&#8862;</button>' +
        '</span>';
      return '<tr data-key="' + escAttr(k) + '" data-value="' + escAttr(v) + '"><td class="key">' + escapeHtml(k) + '</td><td class="detail-value-cell">' + actions + '<span class="detail-value-text">' + escapeHtml(v) + '</span></td></tr>';
    }).join('');
    contentEl.innerHTML = '<table class="discover-detail-table"><tbody>' + rowHtml + '</tbody></table>';
    contentEl.querySelectorAll('.detail-action-btn').forEach((btn) => {
      if (btn.disabled) return;
      const tr = btn.closest('tr');
      const key = tr.getAttribute('data-key');
      const value = tr.getAttribute('data-value');
      const action = btn.getAttribute('data-action');
      btn.addEventListener('click', () => {
        const fieldType = discoverAvailableFieldsList.find((f) => f.name === key)?.type;
        if (action === 'filter-for') {
          discoverDslFilters.push({ field: key, op: 'is', value: value, type: fieldType });
          renderDiscoverFilterPills();
          discoverOffset = 0;
          loadDiscover();
          closeDiscoverDetail();
        } else if (action === 'filter-out') {
          discoverDslFilters.push({ field: key, op: 'is not', value: value, type: fieldType });
          renderDiscoverFilterPills();
          discoverOffset = 0;
          loadDiscover();
          closeDiscoverDetail();
        } else if (action === 'toggle-column') {
          const idx = discoverSelectedFields.indexOf(key);
          if (idx >= 0) discoverSelectedFields.splice(idx, 1);
          else discoverSelectedFields.push(key);
          renderDiscoverFieldsSidebar();
          renderDiscoverThead();
          discoverOffset = 0;
          loadDiscover();
        }
      });
    });
    if (jsonEl) {
      try {
        jsonEl.textContent = JSON.stringify(alert.source || {}, null, 2);
      } catch (e) {
        jsonEl.textContent = String(e);
      }
      jsonEl.classList.add('hidden');
    }
    contentEl.classList.remove('hidden');
    document.querySelectorAll('.discover-detail-tab').forEach((t) => {
      t.classList.toggle('active', t.getAttribute('data-tab') === 'table');
    });
  }

  function setDiscoverDetailTab(tab) {
    const contentEl = document.getElementById('discoverDetailContent');
    const jsonEl = document.getElementById('discoverDetailJson');
    document.querySelectorAll('.discover-detail-tab').forEach((t) => {
      t.classList.toggle('active', t.getAttribute('data-tab') === tab);
    });
    if (tab === 'json') {
      if (contentEl) contentEl.classList.add('hidden');
      if (jsonEl) jsonEl.classList.remove('hidden');
    } else {
      if (contentEl) contentEl.classList.remove('hidden');
      if (jsonEl) jsonEl.classList.add('hidden');
    }
  }

  async function initDiscoverDropdowns() {
    if (discoverDropdownsLoaded) return;
    const [agentsRes, groupsRes] = await Promise.all([
      fetchJson(API.agents + '?limit=200').catch(() => ({ agents: [] })),
      fetchJson(API.alertsRuleGroups).catch(() => []),
    ]);
    const agentSelect = document.getElementById('discoverAgent');
    if (agentSelect) {
      const agentList = (agentsRes.agents || agentsRes.data || []);
      // Build id→hostname map for column rendering
      agentList.forEach(a => {
        const id = a.id || a.agent_id || '';
        const label = a.hostname || a.name || a.agent_name || id;
        if (id) discoverAgentMap[id] = label;
      });
      agentSelect.innerHTML = '<option value="">All agents</option>' + agentList.map(a => {
        const id = a.id || a.agent_id || '';
        const label = a.hostname || a.name || a.agent_name || id;
        return '<option value="' + escapeHtml(id) + '">' + escapeHtml(label) + '</option>';
      }).join('');
    }
    const groupSelect = document.getElementById('discoverGroup');
    if (groupSelect) {
      const groups = Array.isArray(groupsRes) ? groupsRes : (groupsRes.groups || []);
      groupSelect.innerHTML = '<option value="">All groups</option>' + groups.map(g => '<option value="' + escapeHtml(g) + '">' + escapeHtml(g) + '</option>').join('');
    }
    discoverDropdownsLoaded = true;
  }

  async function loadDiscover() {
    if (discoverAvailableFieldsList.length === 0) await loadDiscoverFields();
    if (!discoverDropdownsLoaded) initDiscoverDropdowns();
    const pageSizeEl = document.getElementById('discoverPageSize');
    if (pageSizeEl) DISCOVER_PAGE_SIZE = parseInt(pageSizeEl.value, 10) || 25;
    const dsl = buildDiscoverDsl();
    const q = new URLSearchParams();
    q.set('size', DISCOVER_PAGE_SIZE);
    q.set('offset', String(discoverOffset));
    const listRes = await fetch(API.alertsList + '?' + q.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dsl }),
    }).then((r) => r.json()).catch((e) => ({ error: String(e) }));

    discoverTotal = listRes.error ? 0 : (listRes.total ?? 0);
    const listAlerts = listRes.alerts || [];
    discoverAlertsCache = listAlerts;
    renderDiscoverThead();
    const bodyEl = document.getElementById('discoverBody');
    const colCount = discoverSelectedFields.length + 1;
    if (bodyEl) {
      if (listRes.error) {
        bodyEl.innerHTML = '<tr><td colspan="' + colCount + '" class="error-msg">Query error: ' + escapeHtml(typeof listRes.error === 'string' ? listRes.error : JSON.stringify(listRes.error)) + '</td></tr>';
      } else if (listAlerts.length === 0) {
        bodyEl.innerHTML = '<tr><td colspan="' + colCount + '" class="empty-msg" style="text-align:center;padding:32px;color:var(--text-muted)">No events found for the current filters. Try widening your time range or removing filters.</td></tr>';
      } else {
        bodyEl.innerHTML = renderDiscoverRows(listAlerts);
      }
    }
    document.getElementById('discoverHits').textContent = discoverTotal.toLocaleString();
    const showFrom = listAlerts.length === 0 ? 0 : discoverOffset + 1;
    const showTo = discoverOffset + listAlerts.length;
    document.getElementById('discoverTableInfo').textContent = 'Showing ' + showFrom + (listAlerts.length > 0 ? '–' + showTo : '') + ' of ' + discoverTotal.toLocaleString();
    document.getElementById('discoverPageInfo').textContent = 'Page ' + (Math.floor(discoverOffset / DISCOVER_PAGE_SIZE) + 1) + ' of ' + (Math.ceil(discoverTotal / DISCOVER_PAGE_SIZE) || 1);
    document.getElementById('discoverPrev').disabled = discoverOffset === 0;
    document.getElementById('discoverNext').disabled = discoverOffset + DISCOVER_PAGE_SIZE >= discoverTotal;
    renderDiscoverFilterPills();
    drawDiscoverHistogram(listRes.histogram || []);
  }

  function drawDiscoverHistogram(histogram) {
    const canvas = document.getElementById('discoverHistogram');
    if (!canvas) return;
    const W = canvas.offsetWidth || canvas.width;
    canvas.width = W;
    const ctx = canvas.getContext('2d');
    const H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    const buckets = Array.isArray(histogram) ? histogram : [];
    if (buckets.length === 0) {
      ctx.fillStyle = 'rgba(51,153,255,0.06)';
      ctx.fillRect(0, 0, W, H);
      ctx.fillStyle = 'rgba(138,170,208,0.45)';
      ctx.font = '11px Outfit, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No events in selected time range', W / 2, H / 2 + 4);
      return;
    }

    const maxVal = Math.max(...buckets.map(b => b.count), 1);
    const n = buckets.length;
    const padL = 2, padR = 2, padT = 4, padB = 14;
    const chartW = W - padL - padR;
    const chartH = H - padT - padB;
    const barW = Math.max(1, chartW / n - 1);

    // Background
    ctx.fillStyle = 'rgba(51,153,255,0.04)';
    ctx.fillRect(0, 0, W, H);

    buckets.forEach((b, i) => {
      const x = padL + i * (chartW / n);
      const barH = Math.max(1, Math.round((b.count / maxVal) * chartH));
      const y = padT + chartH - barH;
      const intensity = 0.35 + (b.count / maxVal) * 0.65;
      ctx.fillStyle = `rgba(51,153,255,${intensity})`;
      ctx.fillRect(x, y, Math.max(barW, 1), barH);
    });

    // Axis labels — first and last bucket timestamp
    ctx.fillStyle = 'rgba(138,170,208,0.7)';
    ctx.font = '9px JetBrains Mono, monospace';
    if (buckets[0]?.ts) {
      ctx.textAlign = 'left';
      ctx.fillText(new Date(buckets[0].ts).toLocaleDateString(), padL + 2, H - 2);
    }
    if (buckets[buckets.length - 1]?.ts) {
      ctx.textAlign = 'right';
      ctx.fillText(new Date(buckets[buckets.length - 1].ts).toLocaleDateString(), W - padR - 2, H - 2);
    }
    // Total count label top-right
    const total = buckets.reduce((s, b) => s + b.count, 0);
    ctx.textAlign = 'right';
    ctx.fillStyle = 'rgba(51,153,255,0.8)';
    ctx.font = '10px Outfit, sans-serif';
    ctx.fillText(total.toLocaleString() + ' events', W - padR - 2, padT + 10);
  }

  function discoverExportCsv() {
    if (!discoverAlertsCache.length) return;
    const cols = discoverSelectedFields;
    const headers = cols.map(c => FIELD_LABELS[c] || c);
    const rows = discoverAlertsCache.map(a => {
      const src = a.source || {};
      return cols.map(path => {
        const v = getByPath(src, path);
        if (v == null || v === '') return '';
        if (typeof v === 'object') return JSON.stringify(v);
        return String(v).replace(/"/g, '""');
      }).map(v => '"' + v + '"').join(',');
    });
    const csv = [headers.map(h => '"' + h + '"').join(','), ...rows].join('\r\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentinel-discover-' + new Date().toISOString().slice(0, 10) + '.csv';
    a.click();
    URL.revokeObjectURL(url);
  }

  function closeDiscoverDetail() { document.getElementById('discoverDetailPanel')?.classList.add('hidden'); }

  const RULES_PAGE_SIZE = 20;
  let rulesOffset = 0;
  let rulesTotal = 0;
  let rulesCache = [];
  let rulesDetailCurrentRule = null;

  function flattenRuleForDisplay(obj, prefix) {
    if (obj == null || typeof obj !== 'object') return [];
    prefix = prefix || '';
    const rows = [];
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      const key = prefix ? prefix + '.' + k : k;
      if (v !== null && typeof v === 'object' && !Array.isArray(v) && typeof v.getMonth !== 'function') {
        rows.push(...flattenRuleForDisplay(v, key));
      } else if (Array.isArray(v)) {
        rows.push([key, v.length ? v.join(', ') : '—']);
      } else {
        rows.push([key, v == null || v === '' ? '—' : String(v)]);
      }
    }
    return rows;
  }

  function openRuleDetail(index) {
    const rule = rulesCache[index];
    if (!rule) return;
    rulesDetailCurrentRule = rule;
    const panel = document.getElementById('rulesDetailPanel');
    const titleEl = document.getElementById('rulesDetailTitle');
    const tableWrap = document.getElementById('rulesDetailTableWrap');
    const fileContentEl = document.getElementById('rulesDetailFileContent');
    if (!panel || !tableWrap) return;
    fileContentEl.classList.add('hidden');
    fileContentEl.textContent = '';
    titleEl.textContent = 'Rule details · ID ' + (rule.id != null ? rule.id : '—');
    const viewFileBtn = document.getElementById('rulesDetailViewFile');
    if (viewFileBtn) viewFileBtn.textContent = 'View rule file content';
    const rows = flattenRuleForDisplay(rule);
    if (rows.length === 0) {
      tableWrap.innerHTML = '<table class="discover-detail-table"><tbody><tr><td class="key">id</td><td>' + escapeHtml(String(rule.id != null ? rule.id : '—')) + '</td></tr><tr><td class="key">description</td><td>' + escapeHtml(rule.description || '—') + '</td></tr></tbody></table>';
    } else {
      tableWrap.innerHTML = '<table class="discover-detail-table"><tbody>' + rows.map(([k, v]) => '<tr><td class="key">' + escapeHtml(k) + '</td><td>' + escapeHtml(v) + '</td></tr>').join('') + '</tbody></table>';
    }
    panel.classList.remove('hidden');
  }

  function closeRuleDetail() {
    document.getElementById('rulesDetailPanel')?.classList.add('hidden');
    rulesDetailCurrentRule = null;
  }

  async function loadRuleFileContent() {
    const rule = rulesDetailCurrentRule;
    if (!rule) return;
    const filename = rule.filename || rule.file;
    if (!filename) {
      alert('This rule has no file associated.');
      return;
    }
    const fileContentEl = document.getElementById('rulesDetailFileContent');
    const btn = document.getElementById('rulesDetailViewFile');
    if (!fileContentEl || !btn) return;
    if (!fileContentEl.classList.contains('hidden') && fileContentEl.textContent) {
      fileContentEl.classList.add('hidden');
      fileContentEl.textContent = '';
      btn.textContent = 'View rule file content';
      return;
    }
    btn.textContent = 'Loading…';
    try {
      const q = new URLSearchParams();
      q.set('raw', 'true');
      if (rule.relative_dirname) q.set('relative_dirname', rule.relative_dirname);
      const res = await fetch(API.rulesFiles + '/' + encodeURIComponent(filename) + '?' + q.toString());
      const text = await res.text();
      if (!res.ok) {
        const err = JSON.parse(text).error || text || res.statusText;
        fileContentEl.textContent = 'Error: ' + err;
      } else {
        fileContentEl.textContent = text;
      }
      fileContentEl.classList.remove('hidden');
    } catch (e) {
      fileContentEl.textContent = 'Error: ' + (e.message || 'Request failed');
      fileContentEl.classList.remove('hidden');
    }
    btn.textContent = 'Hide rule file content';
  }

  const DECODERS_PAGE_SIZE = 20;
  let decodersOffset = 0;
  let decodersTotal = 0;
  let decodersCache = [];
  let decodersDetailCurrent = null;

  function flattenDecoderForDisplay(obj, prefix) {
    if (obj == null || typeof obj !== 'object') return [];
    prefix = prefix || '';
    const rows = [];
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      const key = prefix ? prefix + '.' + k : k;
      if (v !== null && typeof v === 'object' && !Array.isArray(v) && typeof v.getMonth !== 'function') {
        rows.push(...flattenDecoderForDisplay(v, key));
      } else if (Array.isArray(v)) {
        rows.push([key, v.length ? v.join(', ') : '—']);
      } else {
        rows.push([key, v == null || v === '' ? '—' : String(v)]);
      }
    }
    return rows;
  }

  function openDecoderDetail(index) {
    const dec = decodersCache[index];
    if (!dec) return;
    decodersDetailCurrent = dec;
    const panel = document.getElementById('decodersDetailPanel');
    const titleEl = document.getElementById('decodersDetailTitle');
    const tableWrap = document.getElementById('decodersDetailTableWrap');
    const fileContentEl = document.getElementById('decodersDetailFileContent');
    if (!panel || !tableWrap) return;
    fileContentEl.classList.add('hidden');
    fileContentEl.textContent = '';
    titleEl.textContent = 'Decoder details · ' + (dec.name || '—');
    const viewFileBtn = document.getElementById('decodersDetailViewFile');
    if (viewFileBtn) viewFileBtn.textContent = 'View decoder file content';
    const rows = flattenDecoderForDisplay(dec);
    tableWrap.innerHTML = rows.length ? '<table class="discover-detail-table"><tbody>' + rows.map(([k, v]) => '<tr><td class="key">' + escapeHtml(k) + '</td><td>' + escapeHtml(v) + '</td></tr>').join('') + '</tbody></table>' : '<table class="discover-detail-table"><tbody><tr><td class="key">name</td><td>' + escapeHtml(dec.name || '—') + '</td></tr></tbody></table>';
    panel.classList.remove('hidden');
  }

  function closeDecoderDetail() {
    document.getElementById('decodersDetailPanel')?.classList.add('hidden');
    decodersDetailCurrent = null;
  }

  async function loadDecoderFileContent() {
    const dec = decodersDetailCurrent;
    if (!dec) return;
    const filename = dec.filename || dec.file;
    if (!filename) {
      alert('This decoder has no file associated.');
      return;
    }
    const fileContentEl = document.getElementById('decodersDetailFileContent');
    const btn = document.getElementById('decodersDetailViewFile');
    if (!fileContentEl || !btn) return;
    if (!fileContentEl.classList.contains('hidden') && fileContentEl.textContent) {
      fileContentEl.classList.add('hidden');
      fileContentEl.textContent = '';
      btn.textContent = 'View decoder file content';
      return;
    }
    btn.textContent = 'Loading…';
    try {
      const q = new URLSearchParams();
      q.set('raw', 'true');
      if (dec.relative_dirname) q.set('relative_dirname', dec.relative_dirname);
      const res = await fetch(API.decodersFiles + '/' + encodeURIComponent(filename) + '?' + q.toString());
      const text = await res.text();
      if (!res.ok) {
        try { fileContentEl.textContent = 'Error: ' + (JSON.parse(text).error || text); } catch (_) { fileContentEl.textContent = 'Error: ' + text; }
      } else {
        fileContentEl.textContent = text;
      }
      fileContentEl.classList.remove('hidden');
      btn.textContent = 'Hide decoder file content';
    } catch (e) {
      fileContentEl.textContent = 'Error: ' + (e.message || 'Request failed');
      fileContentEl.classList.remove('hidden');
      btn.textContent = 'Hide decoder file content';
    }
  }

  async function loadDecoders() {
    const search = (document.getElementById('decodersSearch')?.value || '').trim() || undefined;
    const q = new URLSearchParams();
    q.set('limit', DECODERS_PAGE_SIZE);
    q.set('offset', String(decodersOffset));
    if (search) q.set('search', search);
    const res = await fetchJson(API.decoders + '?' + q.toString()).catch(e => ({ error: e }));
    const data = res.data || {};
    const items = data.affected_items || [];
    decodersCache = items;
    const total = data.total_affected_items != null ? data.total_affected_items : (res.total_affected_items != null ? res.total_affected_items : items.length);
    decodersTotal = total;
    const bodyEl = document.getElementById('decodersBody');
    if (!bodyEl) return;
    if (res.error) {
      bodyEl.innerHTML = '<tr><td colspan="6" class="error-msg">' + escapeHtml(res.error.message || res.error) + '</td></tr>';
    } else if (!items.length) {
      bodyEl.innerHTML = '<tr><td colspan="6" class="empty-msg">No decoders</td></tr>';
    } else {
      bodyEl.innerHTML = items.map((d, i) => {
        const name = d.name || '—';
        const programName = (d.details && d.details.program_name) || (d.program_name) || '—';
        const order = (d.details && d.details.order) || (Array.isArray(d.order) ? d.order.join(', ') : d.order) || '—';
        const file = d.filename || d.file || '—';
        const path = d.relative_dirname || '—';
        return '<tr class="rule-row decoder-row" data-index="' + i + '"><td>' + escapeHtml(String(name)) + '</td><td>' + escapeHtml(String(programName)) + '</td><td>' + escapeHtml(String(order)) + '</td><td>' + escapeHtml(String(file)) + '</td><td>' + escapeHtml(String(path)) + '</td><td><button type="button" class="btn-agent-view" title="View details">👁</button></td></tr>';
      }).join('');
    }
    document.getElementById('decodersTotal').textContent = decodersTotal.toLocaleString();
    document.getElementById('decodersTableInfo').textContent = 'Showing ' + (decodersOffset + 1) + '-' + Math.min(decodersOffset + items.length, decodersTotal) + ' of ' + decodersTotal.toLocaleString();
    document.getElementById('decodersPageInfo').textContent = 'Page ' + (Math.floor(decodersOffset / DECODERS_PAGE_SIZE) + 1) + ' of ' + (Math.ceil(decodersTotal / DECODERS_PAGE_SIZE) || 1);
    document.getElementById('decodersPrev').disabled = decodersOffset === 0;
    document.getElementById('decodersNext').disabled = decodersOffset + DECODERS_PAGE_SIZE >= decodersTotal;
  }

  function openDecodersModal() {
    document.getElementById('decodersModalFilename').value = '';
    document.getElementById('decodersModalContent').value = '';
    document.getElementById('decodersModal')?.classList.remove('hidden');
  }
  function closeDecodersModal() {
    document.getElementById('decodersModal')?.classList.add('hidden');
  }
  async function saveDecodersFile() {
    const filename = (document.getElementById('decodersModalFilename')?.value || '').trim();
    const content = (document.getElementById('decodersModalContent')?.value || '').trim();
    if (!filename) {
      alert('Please enter a filename (e.g. local_decoders.xml).');
      return;
    }
    if (!content) {
      alert('Please enter the XML content for the decoder file.');
      return;
    }
    if (!filename.endsWith('.xml')) filename = filename + '.xml';
    try {
      const res = await fetch(API.decodersFiles + '/' + encodeURIComponent(filename), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(data.error || data.message || res.statusText || 'Failed to save decoders file.');
        return;
      }
      closeDecodersModal();
      decodersOffset = 0;
      loadDecoders();
    } catch (e) {
      alert(e.message || 'Request failed.');
    }
  }

  async function loadIndexManagement() {
    const search = (document.getElementById('indexMgmtSearch')?.value || '').trim();
    const showAll = document.getElementById('indexMgmtDataStreams')?.checked !== false;
    const pattern = search ? (search.includes('*') ? search : search + '*') : (showAll ? '*' : 'watchvault-*');
    const q = new URLSearchParams();
    q.set('pattern', pattern);
    const res = await fetchJson(API.indexerManagementIndices + '?' + q.toString()).catch(e => ({ error: e }));
    const list = Array.isArray(res) ? res : (res.error ? [] : []);
    const bodyEl = document.getElementById('indexMgmtBody');
    if (!bodyEl) return;
    if (res.error) {
      bodyEl.innerHTML = '<tr><td colspan="9" class="error-msg">' + escapeHtml(res.error.message || res.error) + '</td></tr>';
    } else if (!list.length) {
      bodyEl.innerHTML = '<tr><td colspan="9" class="empty-msg">No indexes found</td></tr>';
    } else {
      bodyEl.innerHTML = list.map((idx) => {
        const name = idx.index || idx.index_name || '—';
        const health = (idx.health || '—').toLowerCase();
        const status = idx.status || '—';
        const storeSize = idx['store.size'] != null ? idx['store.size'] : (idx.store_size || '—');
        const priSize = idx['pri.store.size'] != null ? idx['pri.store.size'] : (idx.pri_store_size || storeSize);
        const docsCount = idx['docs.count'] != null ? idx['docs.count'] : (idx['docs.count'] ?? idx.docs_count ?? '—');
        const docsDeleted = idx['docs.deleted'] != null ? idx['docs.deleted'] : (idx.docs_deleted ?? '0');
        const pri = idx.pri != null ? idx.pri : (idx.primaries ?? '—');
        const rep = idx.rep != null ? idx.rep : (idx.replicas ?? '—');
        const healthCls = health === 'green' ? 'health-green' : health === 'yellow' ? 'health-yellow' : 'health-red';
        return '<tr><td class="index-name">' + escapeHtml(String(name)) + '</td><td><span class="' + healthCls + '">' + escapeHtml(String(health)) + '</span></td><td>' + escapeHtml(String(status)) + '</td><td>' + escapeHtml(String(storeSize)) + '</td><td>' + escapeHtml(String(priSize)) + '</td><td>' + escapeHtml(String(docsCount)) + '</td><td>' + escapeHtml(String(docsDeleted)) + '</td><td>' + escapeHtml(String(pri)) + '</td><td>' + escapeHtml(String(rep)) + '</td></tr>';
      }).join('');
    }
    document.getElementById('indexMgmtTotal').textContent = list.length.toLocaleString();
  }

  async function loadRules() {
    const search = (document.getElementById('rulesSearch')?.value || '').trim() || undefined;
    const q = new URLSearchParams();
    q.set('limit', RULES_PAGE_SIZE);
    q.set('offset', String(rulesOffset));
    if (search) q.set('search', search);
    const res = await fetchJson(API.rules + '?' + q.toString()).catch(e => ({ error: e }));
    const data = res.data || {};
    const items = data.affected_items || [];
    rulesCache = items;
    const total = data.total_affected_items != null ? data.total_affected_items : (res.total_affected_items != null ? res.total_affected_items : items.length);
    rulesTotal = total;
    const bodyEl = document.getElementById('rulesBody');
    if (!bodyEl) return;
    if (res.error) {
      bodyEl.innerHTML = '<tr><td colspan="7" class="error-msg">' + escapeHtml(res.error.message || res.error) + '</td></tr>';
    } else if (!items.length) {
      bodyEl.innerHTML = '<tr><td colspan="7" class="empty-msg">No rules</td></tr>';
    } else {
      bodyEl.innerHTML = items.map((r, i) => {
        const desc = (r.description || '—').slice(0, 80);
        const groups = Array.isArray(r.groups) ? r.groups.join(', ') : (r.groups || '—');
        const file = r.filename || r.file || '—';
        const path = r.relative_dirname || '—';
        const level = r.level != null ? r.level : '—';
        const id = r.id != null ? r.id : '—';
        return '<tr class="rule-row" data-index="' + i + '"><td>' + escapeHtml(String(id)) + '</td><td><span class="rule-desc" title="' + escapeHtml(r.description || '') + '">' + escapeHtml(desc) + (desc.length >= 80 ? '…' : '') + '</span></td><td>' + escapeHtml(groups) + '</td><td>' + escapeHtml(String(level)) + '</td><td>' + escapeHtml(String(file)) + '</td><td>' + escapeHtml(String(path)) + '</td><td><button type="button" class="btn-agent-view" title="View details">👁</button></td></tr>';
      }).join('');
    }
    document.getElementById('rulesTotal').textContent = rulesTotal.toLocaleString();
    document.getElementById('rulesTableInfo').textContent = 'Showing ' + (rulesOffset + 1) + '-' + Math.min(rulesOffset + items.length, rulesTotal) + ' of ' + rulesTotal.toLocaleString();
    document.getElementById('rulesPageInfo').textContent = 'Page ' + (Math.floor(rulesOffset / RULES_PAGE_SIZE) + 1) + ' of ' + (Math.ceil(rulesTotal / RULES_PAGE_SIZE) || 1);
    document.getElementById('rulesPrev').disabled = rulesOffset === 0;
    document.getElementById('rulesNext').disabled = rulesOffset + RULES_PAGE_SIZE >= rulesTotal;
  }

  function openRulesModal() {
    document.getElementById('rulesModalFilename').value = '';
    document.getElementById('rulesModalContent').value = '';
    document.getElementById('rulesModal')?.classList.remove('hidden');
  }
  function closeRulesModal() {
    document.getElementById('rulesModal')?.classList.add('hidden');
  }
  async function saveRulesFile() {
    const filename = (document.getElementById('rulesModalFilename')?.value || '').trim();
    const content = (document.getElementById('rulesModalContent')?.value || '').trim();
    if (!filename) {
      alert('Please enter a filename (e.g. local_rules.xml).');
      return;
    }
    if (!content) {
      alert('Please enter the XML content for the rule file.');
      return;
    }
    if (!filename.endsWith('.xml')) filename = filename + '.xml';
    try {
      const res = await fetch(API.rulesFiles + '/' + encodeURIComponent(filename), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(data.error || data.message || res.statusText || 'Failed to save rules file.');
        return;
      }
      closeRulesModal();
      rulesOffset = 0;
      loadRules();
    } catch (e) {
      alert(e.message || 'Request failed.');
    }
  }

  const HIPAA_PAGE_SIZE = 15;
  let hipaaEventsOffset = 0;
  let hipaaEventsTotal = 0;
  let hipaaControlsData = { high_level: [], requirements: [] };

  function getHipaaTimeRange() {
    const range = document.getElementById('hipaaTimeRange')?.value || '24h';
    const now = new Date();
    const start = new Date(now);
    if (range === '24h') start.setHours(now.getHours() - 24);
    else start.setDate(now.getDate() - 7);
    return { time_from: start.toISOString().slice(0, 19) + 'Z', time_to: now.toISOString().slice(0, 19) + 'Z' };
  }

  function setHipaaView(view) {
    document.querySelectorAll('.hipaa-tab').forEach(t => { t.classList.toggle('active', t.getAttribute('data-hipaa-view') === view); });
    document.querySelectorAll('.hipaa-view').forEach(v => { v.classList.toggle('hidden', v.id !== 'hipaa-' + view + '-view'); });
    if (view === 'dashboard') loadHipaaDashboard();
    else if (view === 'controls') loadHipaaControls();
    else if (view === 'events') loadHipaaEvents();
  }

  async function loadHipaaDashboard() {
    const { time_from, time_to } = getHipaaTimeRange();
    const q = 'time_from=' + encodeURIComponent(time_from) + '&time_to=' + encodeURIComponent(time_to);
    const res = await fetchJson(API.hipaaDashboard + '?' + q).catch(e => ({ error: e }));
    if (res.error) {
      document.getElementById('hipaaTotalAlerts').textContent = '—';
      document.getElementById('hipaaMaxLevel').textContent = '—';
      document.getElementById('hipaaHeatmap').innerHTML = '<span class="error-msg">' + escapeHtml(res.error.message) + '</span>';
      document.getElementById('hipaaMostCommon').innerHTML = '';
      document.getElementById('hipaaActiveAgents').innerHTML = '';
      return;
    }
    document.getElementById('hipaaTotalAlerts').textContent = (res.total_alerts ?? 0).toLocaleString();
    document.getElementById('hipaaMaxLevel').textContent = res.max_rule_level != null ? String(res.max_rule_level) : '—';
    const topReqs = res.top_requirements || [];
    const maxR = Math.max(...topReqs.map(r => r.count), 1);
    const colors = ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#a371f7', '#79c0ff', '#7ee787', '#ffa657', '#ff7b72', '#bc8cff'];
    document.getElementById('hipaaDonutLegend').innerHTML = topReqs.slice(0, 10).map((r, i) => '<span class="hipaa-legend-item" style="color:' + (colors[i % colors.length]) + '">' + escapeHtml(String(r.key || '—')) + '</span>').join('') || '<span class="empty-msg">No data</span>';
    drawDonut('hipaaDonutCanvas', topReqs.slice(0, 10).map(r => r.count), colors);
    document.getElementById('hipaaMostCommon').innerHTML = (res.top_requirements || []).slice(0, 8).map((r, i) => {
      const size = i < 3 ? 'font-size:1.1em' : '';
      return '<div class="hipaa-common-item" style="' + size + '">' + escapeHtml(String(r.key || '—')) + '</div>';
    }).join('') || '<span class="empty-msg">No data</span>';
    const byAgent = res.by_agent || [];
    document.getElementById('hipaaActiveAgents').innerHTML = byAgent.slice(0, 8).map(a => '<div class="hipaa-agent-item">' + escapeHtml(String(a.key || '—')) + ' <span class="hipaa-badge">' + a.count + '</span></div>').join('') || '<span class="empty-msg">No data</span>';
    const heatmap = res.heatmap || { agents: [], requirements: [], matrix: [] };
    if (heatmap.agents.length && heatmap.requirements.length) {
      const maxVal = Math.max(...heatmap.matrix.flat(), 1);
      const cols = heatmap.agents.length;
      let html = '<div class="hipaa-heatmap"><div class="hipaa-heatmap-grid" style="grid-template-columns:repeat(' + cols + ', 32px);">';
      heatmap.requirements.forEach((req, ri) => {
        heatmap.agents.forEach((ag, ai) => {
          const v = (heatmap.matrix[ai] && heatmap.matrix[ai][ri]) || 0;
          const pct = Math.min(100, (v / maxVal) * 100);
          html += '<div class="hipaa-heatcell" style="background:rgba(88,166,255,' + (0.2 + 0.8 * pct / 100) + ')" title="' + escapeHtml(ag.name + ' / ' + req + ': ' + v) + '">' + (v || '') + '</div>';
        });
      });
      html += '</div><div class="hipaa-heatmap-labels">Y: ' + heatmap.requirements.slice(0, 5).map(r => escapeHtml(String(r).slice(0, 14))).join(' · ') + (heatmap.requirements.length > 5 ? '…' : '') + '</div>';
      html += '<div class="hipaa-heatmap-x">' + heatmap.agents.map(a => escapeHtml(String(a.name).slice(0, 10))).join(' ') + '</div></div>';
      document.getElementById('hipaaHeatmap').innerHTML = html;
    } else document.getElementById('hipaaHeatmap').innerHTML = '<span class="empty-msg">No heatmap data</span>';
    const evolution = res.evolution || [];
    drawHipaaEvolutionChart('hipaaEvolutionCanvas', evolution);
    const byAgentChart = res.by_agent || [];
    drawHipaaByAgentChart('hipaaDistByAgentCanvas', byAgent);
  }

  function drawDonut(canvasId, values, colors) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !values || values.length === 0) return;
    const total = values.reduce((a, b) => a + b, 0);
    if (total === 0) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;
    const cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - 10;
    let start = -Math.PI / 2;
    values.forEach((v, i) => {
      const sweep = (v / total) * 2 * Math.PI;
      ctx.fillStyle = colors[i % colors.length];
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, start, start + sweep);
      ctx.closePath();
      ctx.fill();
      start += sweep;
    });
  }

  function drawHipaaEvolutionChart(canvasId, evolution) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !evolution.length) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;
    const padding = { left: 50, right: 20, top: 20, bottom: 30 };
    const chartW = w - padding.left - padding.right, chartH = h - padding.top - padding.bottom;
    const maxVal = Math.max(...evolution.map(b => (b.buckets || []).reduce((s, x) => s + x.doc_count, 0)), 1);
    const step = chartW / evolution.length;
    const reqKeys = [...new Set(evolution.flatMap(b => (b.buckets || []).map(x => x.key)))];
    const colors = ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#a371f7'];
    reqKeys.forEach((req, ri) => {
      ctx.fillStyle = colors[ri % colors.length];
      ctx.beginPath();
      let cum = 0;
      evolution.forEach((b, i) => {
        const v = (b.buckets || []).find(x => x.key === req);
        const count = v ? v.doc_count : 0;
        const y = padding.top + chartH - (cum + count) / maxVal * chartH;
        const x = padding.left + i * step + step / 2;
        if (i === 0) ctx.moveTo(x, padding.top + chartH);
        ctx.lineTo(x, y);
        cum += count;
      });
      ctx.lineTo(padding.left + (evolution.length - 1) * step + step / 2, padding.top + chartH);
      ctx.closePath();
      ctx.fill();
      cum = 0;
      evolution.forEach((b, i) => { cum += (b.buckets || []).find(x => x.key === req)?.doc_count || 0; });
    });
  }

  function drawHipaaByAgentChart(canvasId, byAgent) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !byAgent || !byAgent.length) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;
    const padding = { left: 80, right: 20, top: 20, bottom: 40 };
    const chartW = w - padding.left - padding.right, chartH = h - padding.top - padding.bottom;
    const labels = byAgent.map(a => String(a.key).slice(0, 14));
    const maxVal = Math.max(...byAgent.map(a => a.count), 1);
    const barH = chartH / labels.length;
    const colors = ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#a371f7'];
    byAgent.forEach((a, i) => {
      const pct = a.count / maxVal;
      ctx.fillStyle = colors[i % colors.length];
      ctx.fillRect(padding.left, padding.top + i * barH + 2, chartW * pct, barH - 4);
    });
    ctx.fillStyle = '#8b949e';
    ctx.font = '11px sans-serif';
    labels.forEach((l, i) => { ctx.fillText(l, 4, padding.top + (i + 0.6) * barH); });
  }

  async function loadHipaaControls() {
    const { time_from, time_to } = getHipaaTimeRange();
    const q = 'time_from=' + encodeURIComponent(time_from) + '&time_to=' + encodeURIComponent(time_to);
    const res = await fetchJson(API.hipaaControls + '?' + q).catch(e => ({ error: e }));
    hipaaControlsData = res.error ? { high_level: [], requirements: [] } : { high_level: res.high_level || [], requirements: res.requirements || [] };
    const listEl = document.getElementById('hipaaHighLevelList');
    if (listEl) listEl.innerHTML = hipaaControlsData.high_level.map(h => '<div class="hipaa-req-row">Requirement ' + escapeHtml(h.key) + ' <span class="hipaa-badge">' + h.count + '</span></div>').join('') || '<span class="empty-msg">No data</span>';
    renderHipaaRequirementsGrid();
  }

  function renderHipaaRequirementsGrid() {
    const hideZero = document.getElementById('hipaaHideZero')?.checked;
    const filter = (document.getElementById('hipaaFilterReqs')?.value || '').toLowerCase();
    let list = hipaaControlsData.requirements || [];
    if (hideZero) list = list.filter(r => (r.count || 0) > 0);
    if (filter) list = list.filter(r => String(r.key || '').toLowerCase().includes(filter));
    const gridEl = document.getElementById('hipaaRequirementsGrid');
    if (gridEl) gridEl.innerHTML = list.map(r => '<div class="hipaa-req-card"><span class="hipaa-req-title">' + escapeHtml(String(r.key).slice(0, 42)) + '</span><span class="hipaa-badge">' + r.count + '</span></div>').join('') || '<span class="empty-msg">No requirements</span>';
  }

  async function loadHipaaEvents() {
    const { time_from, time_to } = getHipaaTimeRange();
    const size = HIPAA_PAGE_SIZE;
    const q = 'size=' + size + '&offset=' + hipaaEventsOffset + '&time_from=' + encodeURIComponent(time_from) + '&time_to=' + encodeURIComponent(time_to);
    const res = await fetchJson(API.hipaaEvents + '?' + q).catch(e => ({ error: e }));
    hipaaEventsTotal = res.error ? 0 : (res.total ?? 0);
    const events = res.events || [];
    const tbody = document.getElementById('hipaaEventsBody');
    if (tbody) tbody.innerHTML = res.error ? '<tr><td colspan="6" class="error-msg">' + escapeHtml(res.error.message) + '</td></tr>' : events.map(e => '<tr><td>' + escapeHtml(e.timestamp ? new Date(e.timestamp).toLocaleString() : '—') + '</td><td>' + escapeHtml(e.agent_name || '—') + '</td><td>' + escapeHtml(e.rule_hipaa || '—') + '</td><td>' + escapeHtml((e.rule_description || '—').slice(0, 40)) + '</td><td>' + escapeHtml(String(e.rule_level ?? '—')) + '</td><td>' + escapeHtml(String(e.rule_id ?? '—')) + '</td></tr>').join('');
    document.getElementById('hipaaEventsHits').textContent = hipaaEventsTotal.toLocaleString();
    document.getElementById('hipaaEventsInfo').textContent = 'Showing ' + (hipaaEventsOffset + 1) + '-' + (hipaaEventsOffset + events.length) + ' of ' + hipaaEventsTotal.toLocaleString();
    document.getElementById('hipaaEventsPageInfo').textContent = 'Page ' + (Math.floor(hipaaEventsOffset / size) + 1) + ' of ' + (Math.ceil(hipaaEventsTotal / size) || 1);
    document.getElementById('hipaaEventsPrev').disabled = hipaaEventsOffset === 0;
    document.getElementById('hipaaEventsNext').disabled = hipaaEventsOffset + size >= hipaaEventsTotal;
    const evolution = await fetchJson(API.hipaaDashboard + '?time_from=' + encodeURIComponent(time_from) + '&time_to=' + encodeURIComponent(time_to)).catch(() => ({}));
    const evo = evolution.evolution || [];
    const maxE = Math.max(...evo.map(b => (b.buckets || []).reduce((s, x) => s + x.doc_count, 0)), 1);
    const canvas = document.getElementById('hipaaEventsTimelineCanvas');
    if (canvas && evo.length) {
      const ctx = canvas.getContext('2d');
      const w = canvas.width, h = canvas.height;
      const padding = { left: 40, right: 20, top: 20, bottom: 30 };
      const chartW = w - padding.left - padding.right, chartH = h - padding.top - padding.bottom;
      const step = chartW / evo.length;
      ctx.clearRect(0, 0, w, h);
      ctx.fillStyle = '#58a6ff';
      evo.forEach((b, i) => {
        const v = (b.buckets || []).reduce((s, x) => s + x.doc_count, 0);
        const barH = (v / maxE) * chartH;
        ctx.fillRect(padding.left + i * step + 2, padding.top + chartH - barH, step - 4, barH);
      });
    }
  }

  function loadHIPAA() {
    setHipaaView('dashboard');
  }

  let vulnCurrentPage = 0;

  async function loadVulnerabilities() {
    const { params, bounds } = getVulnParams();
    const pageSize = parseInt(document.getElementById('vulnPageSize')?.value || '25', 10);
    const offset = vulnCurrentPage * pageSize;
    params.set('size', pageSize);
    params.set('offset', offset);
    const q = params.toString();
    const days = bounds.days;

    const kpisQuery = 'time_from=' + encodeURIComponent(params.get('time_from')) + '&time_to=' + encodeURIComponent(params.get('time_to'));
    const [kpisRes, trendsRes, topAgentsRes, topPkgsRes, listRes] = await Promise.all([
      fetchJson(API.vulnerabilitiesKpis + '?' + kpisQuery).catch(e => ({ error: e })),
      fetchJson(API.vulnerabilitiesTrends + '?days=' + days).catch(e => ({ error: e })),
      fetchJson(API.vulnerabilitiesTopAgents + '?size=10&' + q).catch(e => ({ error: e })),
      fetchJson(API.vulnerabilitiesTopPackages + '?size=10&' + q).catch(e => ({ error: e })),
      fetchJson(API.vulnerabilitiesList + '?' + q).catch(e => ({ error: e })),
    ]);

    if (kpisRes.error) {
      ['vulnKpiTotal', 'vulnKpiCriticalHigh', 'vulnKpiAvgCvss', 'vulnKpiAgents', 'vulnKpiCves'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = '—';
      });
    } else {
      document.getElementById('vulnKpiTotal').textContent = kpisRes.total ?? '—';
      document.getElementById('vulnKpiCriticalHigh').textContent = kpisRes.critical_high ?? '—';
      document.getElementById('vulnKpiAvgCvss').textContent = kpisRes.avg_cvss ?? '—';
      document.getElementById('vulnKpiAgents').textContent = kpisRes.affected_agents ?? '—';
      document.getElementById('vulnKpiCves').textContent = kpisRes.unique_cves ?? '—';
    }

    if (trendsRes.error) {
      const c = document.getElementById('vulnTrendCanvas');
      if (c) { const ctx = c.getContext('2d'); ctx.fillStyle = '#0d1117'; ctx.fillRect(0, 0, c.width, c.height); }
      if (document.getElementById('vulnTrendLegend')) document.getElementById('vulnTrendLegend').innerHTML = '<span class="error-msg">' + escapeHtml(trendsRes.error.message) + '</span>';
    } else drawVulnTrend('vulnTrendCanvas', 'vulnTrendLegend', trendsRes);

    const agentsEl = document.getElementById('vulnTopAgents');
    if (topAgentsRes.error) agentsEl.innerHTML = '<span class="error-msg">' + escapeHtml(topAgentsRes.error.message) + '</span>';
    else {
      const buckets = topAgentsRes.buckets || [];
      if (document.getElementById('vulnAgent') && document.getElementById('vulnAgent').options.length <= 1) {
        document.getElementById('vulnAgent').innerHTML = '<option value="">All agents</option>' + buckets.map(b => `<option value="${escapeHtml(b.key || '')}">${escapeHtml(b.key || '—')}</option>`).join('');
      }
      const maxA = Math.max(...buckets.map(b => b.doc_count), 1);
      agentsEl.innerHTML = buckets.length === 0 ? '<span class="empty-msg">No data</span>' : buckets.map((b, i) => {
        const pct = (b.doc_count / maxA) * 100;
        const rank = i + 1;
        const isFirst = rank === 1;
        return `<div class="vuln-bar-row ${isFirst ? 'vuln-bar-row--top' : ''}" data-rank="${rank}">
          <span class="vuln-bar-rank">${rank}</span>
          <span class="vuln-bar-label" title="${escapeHtml(b.key || '—')}">${escapeHtml((b.key || '—').slice(0, 22))}${(b.key || '').length > 22 ? '…' : ''}</span>
          <div class="vuln-bar-track vuln-bar-track--rounded"><div class="vuln-bar-fill vuln-bar-fill--gradient" style="width:${pct}%"></div></div>
          <span class="vuln-bar-count">${b.doc_count.toLocaleString()}</span>
        </div>`;
      }).join('');
    }

    const pkgsEl = document.getElementById('vulnTopPackages');
    if (topPkgsRes.error) pkgsEl.innerHTML = '<span class="error-msg">' + escapeHtml(topPkgsRes.error.message) + '</span>';
    else {
      const buckets = topPkgsRes.buckets || [];
      const maxP = Math.max(...buckets.map(b => b.doc_count), 1);
      pkgsEl.innerHTML = buckets.length === 0 ? '<span class="empty-msg">No data</span>' : buckets.map((b, i) => {
        const pct = (b.doc_count / maxP) * 100;
        const rank = i + 1;
        const isFirst = rank === 1;
        return `<div class="vuln-bar-row ${isFirst ? 'vuln-bar-row--top' : ''}" data-rank="${rank}">
          <span class="vuln-bar-rank">${rank}</span>
          <span class="vuln-bar-label" title="${escapeHtml(b.key || '—')}">${escapeHtml((b.key || '—').slice(0, 26))}${(b.key || '').length > 26 ? '…' : ''}</span>
          <div class="vuln-bar-track vuln-bar-track--rounded"><div class="vuln-bar-fill vuln-bar-fill--gradient vuln-bar-fill--teal" style="width:${pct}%"></div></div>
          <span class="vuln-bar-count">${b.doc_count.toLocaleString()}</span>
        </div>`;
      }).join('');
    }

    const tbody = document.getElementById('vulnBody');
    const total = listRes.total ?? 0;
    if (listRes.error) tbody.innerHTML = '<tr><td colspan="7" class="error-msg">' + escapeHtml(listRes.error.message) + '</td></tr>';
    else tbody.innerHTML = renderVulnTable(listRes.vulnerabilities || []);

    const from = offset + 1;
    const to = Math.min(offset + pageSize, total);
    document.getElementById('vulnPaginationInfo').textContent = total === 0 ? '0 results' : `${from}-${to} of ${total}`;
    document.getElementById('vulnPrevPage').disabled = vulnCurrentPage === 0;
    document.getElementById('vulnNextPage').disabled = offset + pageSize >= total;
  }

  const vulnApply = document.getElementById('vulnApplyFilters');
  if (vulnApply) vulnApply.addEventListener('click', () => { vulnCurrentPage = 0; loadVulnerabilities(); });
  const vulnPrev = document.getElementById('vulnPrevPage');
  if (vulnPrev) vulnPrev.addEventListener('click', () => { vulnCurrentPage = Math.max(0, vulnCurrentPage - 1); loadVulnerabilities(); });
  const vulnNext = document.getElementById('vulnNextPage');
  if (vulnNext) vulnNext.addEventListener('click', () => { vulnCurrentPage++; loadVulnerabilities(); });
  const vulnPageSize = document.getElementById('vulnPageSize');
  if (vulnPageSize) vulnPageSize.addEventListener('change', () => { vulnCurrentPage = 0; loadVulnerabilities(); });

  function renderTop5AgentsBar(buckets, options) {
    const drillDown = options && options.drillDown;
    if (!buckets || buckets.length === 0) return '<span class="empty-msg">No data</span>';
    const top5 = buckets.slice(0, 5);
    const max = Math.max(...top5.map(b => b.doc_count), 1);
    return top5.map(b => {
      const pct = (b.doc_count / max) * 100;
      const name = (b.key || '—').slice(0, 20);
      const agentId = b.agent_id != null ? String(b.agent_id) : '';
      const cls = drillDown ? 'viz-hbar drill-down' : 'viz-hbar';
      const attrs = drillDown ? ` data-agent-name="${escapeHtml(b.key || '')}" data-agent-id="${escapeHtml(agentId)}"` : '';
      return `<div class="${cls}"${attrs}><span class="label">${escapeHtml(name)}</span><div class="bar-wrap"><div class="bar-fill" style="width:${pct}%"></div></div><span class="count">${b.doc_count}</span></div>`;
    }).join('');
  }

  function drawSeverityOverTime(canvasId, legendId, seriesData) {
    const canvas = document.getElementById(canvasId);
    const legendEl = document.getElementById(legendId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.width;
    const h = canvas.height;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    const padding = { top: 24, right: 24, bottom: 32, left: 44 };
    const chartW = w - padding.left - padding.right;
    const chartH = h - padding.top - padding.bottom;
    const series = seriesData?.series || [];
    if (series.length === 0) {
      ctx.fillStyle = '#8b949e';
      ctx.font = '12px Outfit';
      ctx.fillText('No data', padding.left, padding.top + chartH / 2);
      if (legendEl) legendEl.innerHTML = '';
      return;
    }
    const levels = new Set();
    series.forEach(s => (s.buckets || []).forEach(b => levels.add(String(b.key))));
    const levelList = Array.from(levels).sort((a, b) => parseInt(a, 10) - parseInt(b, 10));
    const colors = ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#bc8cff', '#56d4dd'];
    let maxVal = 0;
    series.forEach(s => (s.buckets || []).forEach(b => { if (b.doc_count > maxVal) maxVal = b.doc_count; }));
    maxVal = Math.max(1, maxVal);
    const stepX = series.length > 1 ? chartW / (series.length - 1) : chartW;
    ctx.fillStyle = '#0d1117';
    ctx.fillRect(0, 0, w, h);
    ctx.strokeStyle = '#30363d';
    ctx.fillStyle = '#8b949e';
    ctx.font = '10px JetBrains Mono';
    levelList.forEach((level, idx) => {
      const points = [];
      series.forEach((s, i) => {
        const bucket = (s.buckets || []).find(b => String(b.key) === level);
        const count = bucket ? bucket.doc_count : 0;
        const x = padding.left + i * stepX;
        const y = padding.top + chartH - (count / maxVal) * chartH;
        points.push({ x, y, count });
      });
      if (points.length === 0) return;
      const color = colors[idx % colors.length];
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(points[0].x, points[0].y);
      points.slice(1).forEach(p => ctx.lineTo(p.x, p.y));
      ctx.stroke();
    });
    if (legendEl) {
      legendEl.innerHTML = levelList.map((level, idx) => `<span style="color:${colors[idx % colors.length]}">■</span> rule.level ${escapeHtml(level)}`).join(' &nbsp; ');
    }
  }

  function drawTacticPie(canvasId, legendId, buckets) {
    const canvas = document.getElementById(canvasId);
    const legendEl = document.getElementById(legendId);
    if (!canvas || !buckets || buckets.length === 0) {
      if (legendEl) legendEl.innerHTML = '<span class="empty-msg">No tactic data</span>';
      return;
    }
    const total = buckets.reduce((s, b) => s + b.doc_count, 0);
    const colors = ['#f85149', '#d29922', '#58a6ff', '#3fb950', '#bc8cff', '#56d4dd'];
    const ctx = canvas.getContext('2d');
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    const r = Math.min(cx, cy) - 10;
    let start = -Math.PI / 2;
    buckets.forEach((b, i) => {
      const slice = (b.doc_count / total) * 2 * Math.PI;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, start, start + slice);
      ctx.closePath();
      ctx.fillStyle = colors[i % colors.length];
      ctx.fill();
      start += slice;
    });
    ctx.beginPath();
    ctx.arc(cx, cy, r * 0.5, 0, 2 * Math.PI);
    ctx.fillStyle = '#161b22';
    ctx.fill();
    legendEl.innerHTML = buckets.map((b, i) => `<span style="color:${colors[i % colors.length]}">■</span> ${escapeHtml(String(b.key).slice(0, 25))} (${b.doc_count})`).join('<br>');
  }

  async function loadVisualizations() {
    const [top5Res, severityRes, tacticRes] = await Promise.all([
      fetchJson(API.alertsByAgent + '?size=5').catch(e => ({ error: e })),
      fetchJson(API.alertsSeverityOverTime).catch(e => ({ error: e })),
      fetchJson(API.alertsByTactic).catch(e => ({ error: e })),
    ]);
    const top5El = document.getElementById('vizTop5Agents');
    if (top5Res.error) top5El.innerHTML = `<span class="error-msg">${escapeHtml(top5Res.error.message)}</span>`;
    else top5El.innerHTML = renderTop5AgentsBar(top5Res.buckets || []);

    if (severityRes.error) {
      document.getElementById('vizSeverityOverTimeLegend').innerHTML = `<span class="error-msg">${escapeHtml(severityRes.error.message)}</span>`;
    } else {
      drawSeverityOverTime('vizSeverityOverTime', 'vizSeverityOverTimeLegend', severityRes);
    }

    if (tacticRes.error) {
      document.getElementById('vizTacticLegend').innerHTML = `<span class="error-msg">${escapeHtml(tacticRes.error.message)}</span>`;
    } else {
      drawTacticPie('vizTacticPie', 'vizTacticLegend', tacticRes.buckets || []);
    }
  }

  function getDashboardParams() {
    const saved = getDashboardSaved();
    const minLevelEl = document.getElementById('dashboardMinLevel');
    const timeRangeEl = document.getElementById('dashboardTimeRange');
    const agentEl = document.getElementById('dashboardAgent');
    const ruleGroupEl = document.getElementById('dashboardRuleGroup');
    const excludeEl = document.getElementById('dashboardExcludeRules');
    if (minLevelEl) minLevelEl.value = saved.min_level !== undefined ? String(saved.min_level) : '';
    if (timeRangeEl) timeRangeEl.value = saved.timeRange || '7d';
    if (agentEl && saved.agent_name !== undefined) agentEl.value = saved.agent_name || '';
    if (ruleGroupEl && saved.rule_group !== undefined) ruleGroupEl.value = saved.rule_group || '';
    if (excludeEl && saved.exclude_rule_ids !== undefined) excludeEl.value = saved.exclude_rule_ids || '';
    const timeRange = timeRangeEl?.value || '7d';
    const bounds = getTimeRangeBounds(timeRange);
    const params = new URLSearchParams();
    if (minLevelEl?.value) params.set('min_level', minLevelEl.value);
    params.set('time_from', bounds.time_from);
    params.set('time_to', bounds.time_to);
    if (agentEl?.value) params.set('agent_name', agentEl.value);
    if (agentEl?.value && agentEl.selectedOptions[0]?.dataset?.agentId) params.set('agent_id', agentEl.selectedOptions[0].dataset.agentId);
    if (ruleGroupEl?.value) params.set('rule_group', ruleGroupEl.value);
    if (excludeEl?.value) params.set('exclude_rule_ids', excludeEl.value.trim());
    return { params, bounds, saved };
  }

  async function loadDashboard() {
    const { params, bounds, saved } = getDashboardParams();
    const q = params.toString();

    const agentEl = document.getElementById('dashboardAgent');
    const ruleGroupEl = document.getElementById('dashboardRuleGroup');
    if (agentEl && agentEl.options.length <= 1) {
      const baseParams = new URLSearchParams();
      params.forEach((v, k) => { if (k !== 'agent_name' && k !== 'agent_id' && k !== 'rule_group' && k !== 'exclude_rule_ids') baseParams.set(k, v); });
      const agentRes = await fetchJson(API.alertsByAgent + '?size=100&' + baseParams.toString()).catch(() => ({ buckets: [] }));
      const buckets = agentRes.buckets || [];
      agentEl.innerHTML = '<option value="">All agents</option>' + buckets.map(b => {
        const aid = b.agent_id != null ? String(b.agent_id) : '';
        return `<option value="${escapeHtml(b.key || '')}" data-agent-id="${escapeHtml(aid)}">${escapeHtml((b.key || '—').slice(0, 40))}</option>`;
      }).join('');
      if (saved.agent_name) agentEl.value = saved.agent_name;
    }
    if (ruleGroupEl && ruleGroupEl.options.length <= 1) {
      const rgRes = await fetchJson(API.alertsRuleGroups).catch(() => ({ rule_groups: [] }));
      const groups = rgRes.rule_groups || [];
      ruleGroupEl.innerHTML = '<option value="">All groups</option>' + groups.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
      if (saved.rule_group) ruleGroupEl.value = saved.rule_group;
    }

    const [top5Res, severityRes, tacticRes, statsRes] = await Promise.all([
      fetchJson(API.alertsByAgent + '?size=5' + (q ? '&' + q : '')).catch(e => ({ error: e })),
      fetchJson(API.alertsSeverityOverTime + '?days=' + bounds.days + (q ? '&' + q : '')).catch(e => ({ error: e })),
      fetchJson(API.alertsByTactic + (q ? '?' + q : '')).catch(e => ({ error: e })),
      fetchJson(API.dashboardStats + (q ? '?' + q : '')).catch(e => ({ error: e })),
    ]);

    const timeLabel = bounds.days === 1 ? 'Last 24 hours' : bounds.days === 30 ? 'Last 30 days' : 'Last 7 days';
    const subEl = (id, text) => { const e = document.getElementById(id); if (e) e.textContent = text; };
    subEl('dashSeveritySubtitle', timeLabel);
    subEl('dashTacticSubtitle', timeLabel);

    const top5El = document.getElementById('dashTop5Agents');
    if (top5Res.error) top5El.innerHTML = '<span class="error-msg">' + escapeHtml(top5Res.error.message) + '</span>';
    else top5El.innerHTML = renderTop5AgentsBar(top5Res.buckets || [], { drillDown: true });

    const badgeEl = document.getElementById('dashboardFilterBadge');
    const clearBtn = document.getElementById('dashboardClearFilter');
    if (saved.agent_name) {
      if (badgeEl) { badgeEl.style.display = 'inline'; badgeEl.textContent = 'Viewing: ' + saved.agent_name; }
      if (clearBtn) clearBtn.style.display = 'inline-block';
    } else {
      if (badgeEl) badgeEl.style.display = 'none';
      if (clearBtn) clearBtn.style.display = 'none';
    }

    top5El.querySelectorAll('.viz-hbar.drill-down').forEach(bar => {
      bar.onclick = () => {
        const name = bar.getAttribute('data-agent-name');
        const id = bar.getAttribute('data-agent-id');
        const agentSelect = document.getElementById('dashboardAgent');
        if (!agentSelect) return;
        const opt = Array.from(agentSelect.options).find(o => o.value === name);
        if (opt) { agentSelect.value = name; setDashboardSaved(Object.assign(getDashboardSaved(), { agent_name: name, agent_id: id || undefined })); loadDashboard(); }
      };
    });

    if (severityRes.error) document.getElementById('dashSeverityLegend').innerHTML = '<span class="error-msg">' + escapeHtml(severityRes.error.message) + '</span>';
    else drawSeverityOverTime('dashSeverityOverTime', 'dashSeverityLegend', severityRes);
    if (tacticRes.error) document.getElementById('dashTacticLegend').innerHTML = '<span class="error-msg">' + escapeHtml(tacticRes.error.message) + '</span>';
    else drawTacticPie('dashTacticPie', 'dashTacticLegend', tacticRes.buckets || []);

    const statsEl = document.getElementById('dashStats');
    if (statsRes.error) statsEl.innerHTML = '<span class="error-msg">' + escapeHtml(statsRes.error.message) + '</span>';
    else statsEl.innerHTML = `Unique source IPs: <strong>${statsRes.unique_src_ips ?? 0}</strong> · Unique agents: <strong>${statsRes.unique_agents ?? 0}</strong> · Total events: <strong>${statsRes.total_events ?? 0}</strong>`;
  }

  function loadAdvanced() {
    /* Static content only */
  }

  const HYGIENE_PAGE_SIZE = 15;
  let hygieneSystemOffset = 0;
  let hygienePackagesOffset = 0;
  let hygieneProcessesOffset = 0;
  let hygieneUsersOffset = 0;

  function getHygieneParams() {
    const cluster = document.getElementById('hygieneClusterFilter')?.value?.trim() || '';
    return { cluster_name: cluster || undefined };
  }

  function renderHygieneBarList(buckets, maxCount) {
    const m = Math.max(...(buckets.map(b => b.count)), 1);
    return buckets.map(b => {
      const pct = Math.min(100, (b.count / m) * 100);
      return `<div class="bar-item"><span class="bar-label">${escapeHtml(String(b.key).slice(0, 30))}</span><div class="bar-track"><div class="bar-fill level-low" style="width:${pct}%"></div></div><span class="bar-count">${b.count}</span></div>`;
    }).join('');
  }

  async function loadHygieneSystem() {
    const params = getHygieneParams();
    const q = new URLSearchParams();
    if (params.cluster_name) q.set('cluster_name', params.cluster_name);
    try {
      const [summary, list] = await Promise.all([
        fetchJson(API.inventorySystemSummary + (q.toString() ? '?' + q.toString() : '')).catch(e => ({ error: e })),
        fetchJson(API.inventorySystemList + '?size=' + HYGIENE_PAGE_SIZE + '&offset=' + hygieneSystemOffset + (q.toString() ? '&' + q.toString() : '')).catch(e => ({ error: e })),
      ]);
      if (summary.error) {
        document.getElementById('hygieneTopPlatforms').innerHTML = '<span class="error-msg">' + escapeHtml(summary.error.message) + '</span>';
        document.getElementById('hygieneTopOs').innerHTML = '';
        document.getElementById('hygieneTopArch').innerHTML = '';
      } else {
        document.getElementById('hygieneTopPlatforms').innerHTML = renderHygieneBarList(summary.top_platforms || [], 0);
        document.getElementById('hygieneTopOs').innerHTML = renderHygieneBarList(summary.top_os || [], 0);
        document.getElementById('hygieneTopArch').innerHTML = renderHygieneBarList(summary.top_architecture || [], 0);
      }
      const total = list.total ?? 0;
      const hits = list.hits || [];
      document.getElementById('hygieneSystemHits').textContent = total + ' hits';
      document.getElementById('hygieneSystemPageInfo').textContent = 'Page ' + (Math.floor(hygieneSystemOffset / HYGIENE_PAGE_SIZE) + 1) + ' of ' + (Math.ceil(total / HYGIENE_PAGE_SIZE) || 1);
      document.getElementById('hygieneSystemPrev').disabled = hygieneSystemOffset === 0;
      document.getElementById('hygieneSystemNext').disabled = hygieneSystemOffset + HYGIENE_PAGE_SIZE >= total;
      const tbody = document.getElementById('hygieneSystemTable');
      if (list.error) tbody.innerHTML = '<tr><td colspan="6" class="error-msg">' + escapeHtml(list.error.message) + '</td></tr>';
      else if (hits.length === 0) tbody.innerHTML = '<tr><td colspan="6" class="empty-msg">No data</td></tr>';
      else tbody.innerHTML = hits.map(r => `<tr><td>${escapeHtml(r.agent_name || '—')}</td><td>${escapeHtml(r.host_os_platform || '—')}</td><td>${escapeHtml(r.host_os_name || '—')}</td><td>${escapeHtml(r.host_os_version || '—')}</td><td>${escapeHtml(r.host_os_kernel_release || '—')}</td><td>${escapeHtml(r.host_architecture || '—')}</td></tr>`).join('');
    } catch (e) {
      document.getElementById('hygieneSystemTable').innerHTML = '<tr><td colspan="6" class="error-msg">' + escapeHtml(e.message) + '</td></tr>';
    }
  }

  async function loadHygieneSoftware() {
    const params = getHygieneParams();
    const q = new URLSearchParams();
    if (params.cluster_name) q.set('cluster_name', params.cluster_name);
    try {
      const [summary, list] = await Promise.all([
        fetchJson(API.inventoryPackagesSummary + (q.toString() ? '?' + q.toString() : '')).catch(e => ({ error: e })),
        fetchJson(API.inventoryPackagesList + '?size=' + HYGIENE_PAGE_SIZE + '&offset=' + hygienePackagesOffset + (q.toString() ? '&' + q.toString() : '')).catch(e => ({ error: e })),
      ]);
      if (summary.error) {
        document.getElementById('hygieneTopVendors').innerHTML = '<span class="error-msg">' + escapeHtml(summary.error.message) + '</span>';
        document.getElementById('hygieneUniquePackages').textContent = '—';
        document.getElementById('hygienePackageTypes').innerHTML = '';
      } else {
        document.getElementById('hygieneTopVendors').innerHTML = renderHygieneBarList(summary.top_vendors || [], 0);
        document.getElementById('hygieneUniquePackages').textContent = (summary.unique_packages ?? 0).toLocaleString();
        document.getElementById('hygienePackageTypes').innerHTML = renderHygieneBarList(summary.package_types || [], 0);
      }
      const total = list.total ?? 0;
      const hits = list.hits || [];
      document.getElementById('hygienePackagesHits').textContent = total + ' hits';
      document.getElementById('hygienePackagesPageInfo').textContent = 'Page ' + (Math.floor(hygienePackagesOffset / HYGIENE_PAGE_SIZE) + 1) + ' of ' + (Math.ceil(total / HYGIENE_PAGE_SIZE) || 1);
      document.getElementById('hygienePackagesPrev').disabled = hygienePackagesOffset === 0;
      document.getElementById('hygienePackagesNext').disabled = hygienePackagesOffset + HYGIENE_PAGE_SIZE >= total;
      const tbody = document.getElementById('hygienePackagesTable');
      if (list.error) tbody.innerHTML = '<tr><td colspan="5" class="error-msg">' + escapeHtml(list.error.message) + '</td></tr>';
      else if (hits.length === 0) tbody.innerHTML = '<tr><td colspan="5" class="empty-msg">No data</td></tr>';
      else tbody.innerHTML = hits.map(r => `<tr><td>${escapeHtml(r.agent_name || '—')}</td><td>${escapeHtml(r.package_vendor || '—')}</td><td>${escapeHtml(r.package_name || '—')}</td><td>${escapeHtml(r.package_version || '—')}</td><td>${escapeHtml(r.package_type || '—')}</td></tr>`).join('');
    } catch (e) {
      document.getElementById('hygienePackagesTable').innerHTML = '<tr><td colspan="5" class="error-msg">' + escapeHtml(e.message) + '</td></tr>';
    }
  }

  async function loadHygieneProcesses() {
    const params = getHygieneParams();
    const q = new URLSearchParams();
    if (params.cluster_name) q.set('cluster_name', params.cluster_name);
    try {
      const [summary, histogram, list] = await Promise.all([
        fetchJson(API.inventoryProcessesSummary + (q.toString() ? '?' + q.toString() : '')).catch(e => ({ error: e })),
        fetchJson(API.inventoryProcessesHistogram + (q.toString() ? '?' + q.toString() : '') + '&interval=1h').catch(e => ({ buckets: [] })),
        fetchJson(API.inventoryProcessesList + '?size=' + HYGIENE_PAGE_SIZE + '&offset=' + hygieneProcessesOffset + (q.toString() ? '&' + q.toString() : '')).catch(e => ({ error: e })),
      ]);
      if (summary.error) document.getElementById('hygieneTopProcesses').innerHTML = '<span class="error-msg">' + escapeHtml(summary.error.message) + '</span>';
      else document.getElementById('hygieneTopProcesses').innerHTML = renderHygieneBarList(summary.top_processes || [], 0);
      const buckets = histogram.buckets || [];
      const timeline = buckets.map(b => ({ key: b.key, count: b.count }));
      if (typeof drawTimeline === 'function') drawTimeline('hygieneProcessStartCanvas', timeline);
      const total = list.total ?? 0;
      const hits = list.hits || [];
      document.getElementById('hygieneProcessesHits').textContent = total + ' hits';
      document.getElementById('hygieneProcessesPageInfo').textContent = 'Page ' + (Math.floor(hygieneProcessesOffset / HYGIENE_PAGE_SIZE) + 1) + ' of ' + (Math.ceil(total / HYGIENE_PAGE_SIZE) || 1);
      document.getElementById('hygieneProcessesPrev').disabled = hygieneProcessesOffset === 0;
      document.getElementById('hygieneProcessesNext').disabled = hygieneProcessesOffset + HYGIENE_PAGE_SIZE >= total;
      const tbody = document.getElementById('hygieneProcessesTable');
      if (list.error) tbody.innerHTML = '<tr><td colspan="6" class="error-msg">' + escapeHtml(list.error.message) + '</td></tr>';
      else if (hits.length === 0) tbody.innerHTML = '<tr><td colspan="6" class="empty-msg">No data</td></tr>';
      else tbody.innerHTML = hits.map(r => {
        const start = r.process_start ? new Date(r.process_start).toLocaleString() : '—';
        return `<tr><td>${escapeHtml(r.agent_name || '—')}</td><td>${escapeHtml(r.process_name || '—')}</td><td>${start}</td><td>${escapeHtml(String(r.process_pid ?? '—'))}</td><td>${escapeHtml(String(r.process_parent_pid ?? '—'))}</td><td class="stream-alert-name">${escapeHtml((r.process_command_line || '—').slice(0, 80))}</td></tr>`;
      }).join('');
    } catch (e) {
      document.getElementById('hygieneProcessesTable').innerHTML = '<tr><td colspan="6" class="error-msg">' + escapeHtml(e.message) + '</td></tr>';
    }
  }

  async function loadHygieneIdentity() {
    const params = getHygieneParams();
    const q = new URLSearchParams();
    if (params.cluster_name) q.set('cluster_name', params.cluster_name);
    try {
      const [summary, list] = await Promise.all([
        fetchJson(API.inventoryUsersSummary + (q.toString() ? '?' + q.toString() : '')).catch(e => ({ error: e })),
        fetchJson(API.inventoryUsersList + '?size=' + HYGIENE_PAGE_SIZE + '&offset=' + hygieneUsersOffset + (q.toString() ? '&' + q.toString() : '')).catch(e => ({ error: e })),
      ]);
      if (summary.error) {
        document.getElementById('hygieneTopUsers').innerHTML = '<span class="error-msg">' + escapeHtml(summary.error.message) + '</span>';
        document.getElementById('hygieneTopGroups').innerHTML = '';
        document.getElementById('hygieneTopShells').innerHTML = '';
      } else {
        document.getElementById('hygieneTopUsers').innerHTML = renderHygieneBarList(summary.top_users || [], 0);
        document.getElementById('hygieneTopGroups').innerHTML = renderHygieneBarList(summary.top_groups || [], 0);
        document.getElementById('hygieneTopShells').innerHTML = renderHygieneBarList(summary.top_shells || [], 0);
      }
      const total = list.total ?? 0;
      const hits = list.hits || [];
      document.getElementById('hygieneUsersHits').textContent = total + ' hits';
      document.getElementById('hygieneUsersPageInfo').textContent = 'Page ' + (Math.floor(hygieneUsersOffset / HYGIENE_PAGE_SIZE) + 1) + ' of ' + (Math.ceil(total / HYGIENE_PAGE_SIZE) || 1);
      document.getElementById('hygieneUsersPrev').disabled = hygieneUsersOffset === 0;
      document.getElementById('hygieneUsersNext').disabled = hygieneUsersOffset + HYGIENE_PAGE_SIZE >= total;
      const tbody = document.getElementById('hygieneUsersTable');
      if (list.error) tbody.innerHTML = '<tr><td colspan="5" class="error-msg">' + escapeHtml(list.error.message) + '</td></tr>';
      else if (hits.length === 0) tbody.innerHTML = '<tr><td colspan="5" class="empty-msg">No data</td></tr>';
      else tbody.innerHTML = hits.map(r => `<tr><td>${escapeHtml(r.agent_name || '—')}</td><td>${escapeHtml(r.user_name || '—')}</td><td>${escapeHtml(r.user_groups || '—')}</td><td>${escapeHtml(r.user_shell || '—')}</td><td>${escapeHtml(r.user_home || '—')}</td></tr>`).join('');
    } catch (e) {
      document.getElementById('hygieneUsersTable').innerHTML = '<tr><td colspan="5" class="error-msg">' + escapeHtml(e.message) + '</td></tr>';
    }
  }

  function setHygieneSubtab(active) {
    document.querySelectorAll('.hygiene-subtab').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-hygiene') === active);
    });
    document.querySelectorAll('.hygiene-view').forEach(el => {
      el.classList.toggle('hidden', el.id !== 'hygiene-' + active);
    });
    if (active === 'system') loadHygieneSystem();
    else if (active === 'software') loadHygieneSoftware();
    else if (active === 'processes') loadHygieneProcesses();
    else if (active === 'identity') loadHygieneIdentity();
  }

  function loadITHygiene() {
    setHygieneSubtab('system');
  }

  const loaders = {
    overview: loadOverview,
    stack: loadStack,
    'data-sources': loadDataSources,
    'index-management': loadIndexManagement,
    agents: loadAgents,
    fim: loadFimPage,
    mitre: loadMitrePage,
    audit: loadAuditPage,
    sca: loadScaPage,
    'threat-hunting': loadThreatHunting,
    alerts: loadAlerts,
    discover: loadDiscover,
    rules: loadRules,
    decoders: loadDecoders,
    vulnerabilities: loadVulnerabilities,
    visualizations: loadVisualizations,
    dashboard: loadDashboard,
    'it-hygiene': loadITHygiene,
    advanced: loadAdvanced,
    compliance: loadHIPAA,
    visualize: loadVisualizePage,
    'custom-dashboards': loadCustomDashboardsPage,
    reports: loadReportsPage,
    notifications: loadNotificationsPage,
  };

  function goToPage(pageId) {
    if (currentUser && currentUser.role !== 'super_admin' && SUPER_ADMIN_ONLY_PAGES.includes(pageId)) {
      goToPage('overview');
      return;
    }
    setNav(pageId);
    const load = loaders[pageId];
    if (load) load();
    if (pageId === 'overview') {
      const refreshEl = document.getElementById('globalRefresh');
      const ms = parseInt(refreshEl?.value || '30', 10) * 1000;
      if (typeof startOverviewRefresh === 'function') startOverviewRefresh(ms);
    }
  }

  (async function initAuth() {
    try {
      const res = await fetch('/api/me');
      if (!res.ok) {
        window.location.href = '/login';
        return;
      }
      const data = await res.json();
      currentUser = { username: data.username, role: data.role, can_save_dashboard: data.can_save_dashboard !== false };
      document.querySelectorAll('.nav-item').forEach(el => {
        const page = el.getAttribute('data-page');
        if (SUPER_ADMIN_ONLY_PAGES.includes(page) && currentUser.role !== 'super_admin') {
          el.style.display = 'none';
        }
      });
      const userEl = document.getElementById('sidebarUser');
      const roleLabels = { super_admin: 'Super Admin', administrator: 'Administrator', admin: 'Admin', security_analyst: 'Security Analyst', compliance_officer: 'Compliance Officer' };
      if (userEl) userEl.textContent = currentUser.username + ' · ' + (roleLabels[currentUser.role] || currentUser.role);
      const headerUserEl = document.getElementById('headerUser');
      if (headerUserEl) headerUserEl.textContent = currentUser.username || 'admin';
      const saveBtn = document.getElementById('dashboardSave');
      if (saveBtn) saveBtn.style.display = currentUser.can_save_dashboard ? '' : 'none';
    } catch (e) {
      window.location.href = '/login';
      return;
    }
    goToPage('overview');
  })();

  document.querySelectorAll('.nav-item').forEach(el => {
    el.addEventListener('click', (e) => {
      e.preventDefault();
      goToPage(el.getAttribute('data-page'));
    });
  });

  document.querySelectorAll('.nav-tab').forEach(el => {
    el.addEventListener('click', (e) => {
      e.preventDefault();
      goToPage(el.getAttribute('data-page'));
    });
  });

  document.querySelectorAll('.quick-action-btn, .stream-footer-link, .panel-link').forEach(el => {
    el.addEventListener('click', (e) => {
      const page = el.getAttribute('data-page');
      if (page) { e.preventDefault(); goToPage(page); }
    });
  });
  document.addEventListener('click', (e) => {
    const link = e.target.closest('a[data-page]');
    if (link && link.getAttribute('data-page')) {
      e.preventDefault();
      goToPage(link.getAttribute('data-page'));
    }
  });

  let overviewRefreshInterval = null;
  function startOverviewRefresh(ms) {
    if (overviewRefreshInterval) clearInterval(overviewRefreshInterval);
    overviewRefreshInterval = null;
    if (ms > 0) overviewRefreshInterval = setInterval(() => { if (document.querySelector('.page.active')?.id === 'page-overview') loadOverview(); }, ms);
  }
  const globalRefreshEl = document.getElementById('globalRefresh');
  if (globalRefreshEl) {
    globalRefreshEl.addEventListener('change', () => {
      if (document.getElementById('streamPause')?.dataset.paused === '1') return;
      const ms = parseInt(globalRefreshEl.value, 10) * 1000;
      startOverviewRefresh(ms);
    });
  }
  const streamPauseEl = document.getElementById('streamPause');
  if (streamPauseEl) {
    streamPauseEl.addEventListener('click', () => {
      const paused = streamPauseEl.dataset.paused === '1';
      if (paused) {
        streamPauseEl.dataset.paused = '0';
        streamPauseEl.textContent = '⏸️ Pause';
        const refreshEl = document.getElementById('globalRefresh');
        startOverviewRefresh(parseInt(refreshEl?.value || '30', 10) * 1000);
      } else {
        streamPauseEl.dataset.paused = '1';
        streamPauseEl.textContent = '▶️ Resume';
        startOverviewRefresh(0);
      }
    });
  }
  const streamSoundEl = document.getElementById('streamSound');
  if (streamSoundEl) streamSoundEl.addEventListener('click', () => { streamSoundEl.textContent = streamSoundEl.textContent === '🔊' ? '🔇' : '🔊'; });

  const themeToggleEl = document.getElementById('themeToggle');
  if (themeToggleEl) {
    applyTheme(getTheme());
    themeToggleEl.addEventListener('click', () => {
      const next = getTheme() === 'dark' ? 'light' : 'dark';
      setTheme(next);
      applyTheme(next);
    });
  }

  const sidebarToggleEl = document.getElementById('sidebarToggle');
  if (sidebarToggleEl) {
    sidebarToggleEl.addEventListener('click', () => {
      const collapsed = !getSidebarCollapsed();
      setSidebarCollapsed(collapsed);
      applySidebarCollapsed(collapsed);
    });
  }

  document.querySelectorAll('.hygiene-subtab').forEach(el => {
    el.addEventListener('click', () => setHygieneSubtab(el.getAttribute('data-hygiene')));
  });
  document.getElementById('hygieneSystemPrev')?.addEventListener('click', () => { hygieneSystemOffset = Math.max(0, hygieneSystemOffset - HYGIENE_PAGE_SIZE); loadHygieneSystem(); });
  document.getElementById('hygieneSystemNext')?.addEventListener('click', () => { hygieneSystemOffset += HYGIENE_PAGE_SIZE; loadHygieneSystem(); });
  document.getElementById('hygienePackagesPrev')?.addEventListener('click', () => { hygienePackagesOffset = Math.max(0, hygienePackagesOffset - HYGIENE_PAGE_SIZE); loadHygieneSoftware(); });
  document.getElementById('hygienePackagesNext')?.addEventListener('click', () => { hygienePackagesOffset += HYGIENE_PAGE_SIZE; loadHygieneSoftware(); });
  document.getElementById('hygieneProcessesPrev')?.addEventListener('click', () => { hygieneProcessesOffset = Math.max(0, hygieneProcessesOffset - HYGIENE_PAGE_SIZE); loadHygieneProcesses(); });
  document.getElementById('hygieneProcessesNext')?.addEventListener('click', () => { hygieneProcessesOffset += HYGIENE_PAGE_SIZE; loadHygieneProcesses(); });
  document.getElementById('hygieneUsersPrev')?.addEventListener('click', () => { hygieneUsersOffset = Math.max(0, hygieneUsersOffset - HYGIENE_PAGE_SIZE); loadHygieneIdentity(); });
  document.getElementById('hygieneUsersNext')?.addEventListener('click', () => { hygieneUsersOffset += HYGIENE_PAGE_SIZE; loadHygieneIdentity(); });

  const agentsSearchEl = document.getElementById('agentsSearch');
  const agentsFilterStatusEl = document.getElementById('agentsFilterStatus');
  if (agentsSearchEl) agentsSearchEl.addEventListener('input', () => { if (window._agentsHealthData?.agents) { const filtered = filterAgentsTable(window._agentsHealthData.agents); document.getElementById('agentsBody').innerHTML = renderAgentsTableFromHealth(filtered); document.getElementById('agentsTableCount').textContent = '(' + filtered.length + ')'; } });
  if (agentsFilterStatusEl) agentsFilterStatusEl.addEventListener('change', () => { if (window._agentsHealthData?.agents) { const filtered = filterAgentsTable(window._agentsHealthData.agents); document.getElementById('agentsBody').innerHTML = renderAgentsTableFromHealth(filtered); document.getElementById('agentsTableCount').textContent = '(' + filtered.length + ')'; } });

  document.getElementById('agentsBody')?.addEventListener('click', (e) => {
    const btn = e.target.closest('.btn-agent-view');
    if (btn && btn.getAttribute('data-agent-id')) openAgentDetail(btn.getAttribute('data-agent-id'));
  });
  document.getElementById('agentDetailClose')?.addEventListener('click', closeAgentDetail);

  document.querySelector('.agents-breakdown-tablist')?.addEventListener('click', (e) => {
    const tab = e.target.closest('.agents-breakdown-tab[data-tab]');
    if (!tab) return;
    const tabId = tab.getAttribute('data-tab');
    document.querySelectorAll('.agents-breakdown-tab').forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
    tab.classList.add('active');
    tab.setAttribute('aria-selected', 'true');
    document.querySelectorAll('.agents-breakdown-panel').forEach(p => p.classList.add('hidden'));
    const panel = document.getElementById('panel-' + tabId);
    if (panel) panel.classList.remove('hidden');
  });

  document.getElementById('agentsExport')?.addEventListener('click', () => {
    const agents = window._agentsHealthData?.agents || [];
    if (!agents.length) return;
    const headers = ['id','name','status','os_label','version','alert_count','critical_count','last_seen_label'];
    const csv = [headers.join(',')].concat(agents.map(a => headers.map(h => '"' + String(a[h]||'').replace(/"/g,'""') + '"').join(','))).join('\n');
    const blob = new Blob([csv], {type:'text/csv'});
    const lnk = document.createElement('a'); lnk.href = URL.createObjectURL(blob); lnk.download = 'agents-' + new Date().toISOString().slice(0,10) + '.csv'; lnk.click(); URL.revokeObjectURL(lnk.href);
  });

  // Enroll modal logic
  let enrollOs = 'linux';
  function updateEnrollCommands() {
    const serverIp = (document.getElementById('enrollServerIp')?.value || '').trim() || '<YOUR_SERVER_IP>';
    const wrap = document.getElementById('enrollCommands');
    if (!wrap) return;
    const cmds = {
      linux: [
        `# 1. Download the WatchNode binary`,
        `curl -Lo watchnode https://YOUR_RELEASE_SERVER/watchnode-linux-amd64`,
        `chmod +x watchnode`,
        ``,
        `# 2. Create config file`,
        `mkdir -p /etc/watchnode/agent`,
        `cat > /etc/watchnode/agent/config.yaml << EOF`,
        `agent:`,
        `  name: "{{hostname}}"`,
        `manager:`,
        `  url: "${serverIp}:50051"`,
        `collectors:`,
        `  system:`,
        `    enabled: true`,
        `    interval: "30s"`,
        `  process:`,
        `    enabled: true`,
        `    interval: "30s"`,
        `EOF`,
        ``,
        `# 3. Run agent (or install as systemd service)`,
        `./watchnode --config /etc/watchnode/agent/config.yaml`,
      ],
      windows: [
        `# 1. Download WatchNode for Windows (PowerShell)`,
        `Invoke-WebRequest -Uri "https://YOUR_RELEASE_SERVER/watchnode-windows-amd64.exe" -OutFile watchnode.exe`,
        ``,
        `# 2. Create config file`,
        `New-Item -ItemType Directory -Force -Path "C:\\WatchNode"`,
        `@"`,
        `agent:`,
        `  name: "{{hostname}}"`,
        `manager:`,
        `  url: "${serverIp}:50051"`,
        `collectors:`,
        `  system:`,
        `    enabled: true`,
        `    interval: "30s"`,
        `  process:`,
        `    enabled: true`,
        `    interval: "30s"`,
        `"@ | Set-Content -Path "C:\\WatchNode\\config.yaml"`,
        ``,
        `# 3. Run agent`,
        `.\\watchnode.exe --config C:\\WatchNode\\config.yaml`,
        ``,
        `# 4. (Optional) Install as Windows service using nssm`,
        `nssm install WatchNode ".\\watchnode.exe" "--config C:\\WatchNode\\config.yaml"`,
        `nssm start WatchNode`,
      ],
      macos: [
        `# 1. Download WatchNode for macOS`,
        `curl -Lo watchnode https://YOUR_RELEASE_SERVER/watchnode-darwin-amd64`,
        `chmod +x watchnode`,
        ``,
        `# 2. Create config file`,
        `mkdir -p /etc/watchnode/agent`,
        `cat > /etc/watchnode/agent/config.yaml << EOF`,
        `agent:`,
        `  name: "{{hostname}}"`,
        `manager:`,
        `  url: "${serverIp}:50051"`,
        `collectors:`,
        `  system:`,
        `    enabled: true`,
        `    interval: "30s"`,
        `  process:`,
        `    enabled: true`,
        `    interval: "30s"`,
        `EOF`,
        ``,
        `# 3. Run agent`,
        `./watchnode --config /etc/watchnode/agent/config.yaml`,
      ],
    };
    const lines = cmds[enrollOs] || cmds.linux;
    wrap.innerHTML = `<pre class="enroll-cmd-block">${escapeHtml(lines.join('\n'))}</pre>
      <button type="button" class="global-btn" id="enrollCopyBtn" style="margin-top:8px;width:100%">📋 Copy to clipboard</button>`;
    document.getElementById('enrollCopyBtn')?.addEventListener('click', () => {
      navigator.clipboard?.writeText(lines.join('\n')).then(() => {
        const btn = document.getElementById('enrollCopyBtn');
        if (btn) { btn.textContent = '✓ Copied!'; setTimeout(() => { btn.textContent = '📋 Copy to clipboard'; }, 2000); }
      });
    });
  }

  ['agentsAddNewBtn', 'agentsAddNewBtn2'].forEach(id => {
    document.getElementById(id)?.addEventListener('click', () => {
      document.getElementById('agentEnrollModal')?.classList.remove('hidden');
      updateEnrollCommands();
    });
  });
  document.getElementById('agentEnrollClose')?.addEventListener('click', () => document.getElementById('agentEnrollModal')?.classList.add('hidden'));
  document.getElementById('agentEnrollDone')?.addEventListener('click', () => {
    document.getElementById('agentEnrollModal')?.classList.add('hidden');
    loadAgents();
  });
  document.getElementById('enrollServerIp')?.addEventListener('input', updateEnrollCommands);
  document.getElementById('enrollCommands')?.parentElement?.addEventListener('click', e => {
    const btn = e.target.closest('.enroll-os-btn');
    if (!btn) return;
    enrollOs = btn.getAttribute('data-os');
    document.querySelectorAll('.enroll-os-btn').forEach(b => b.classList.toggle('active', b === btn));
    updateEnrollCommands();
  });
  document.querySelector('.enroll-os-btns')?.addEventListener('click', e => {
    const btn = e.target.closest('.enroll-os-btn');
    if (!btn) return;
    enrollOs = btn.getAttribute('data-os');
    document.querySelectorAll('.enroll-os-btn').forEach(b => b.classList.toggle('active', b === btn));
    updateEnrollCommands();
  });

  document.getElementById('alertsOpenDiscover')?.addEventListener('click', (e) => { e.preventDefault(); goToPage('discover'); });

  document.getElementById('discoverRefresh')?.addEventListener('click', () => { discoverOffset = 0; loadDiscover(); });
  document.getElementById('discoverExportCsv')?.addEventListener('click', discoverExportCsv);
  document.getElementById('discoverPrev')?.addEventListener('click', () => { discoverOffset = Math.max(0, discoverOffset - DISCOVER_PAGE_SIZE); loadDiscover(); });
  document.getElementById('discoverNext')?.addEventListener('click', () => { discoverOffset += DISCOVER_PAGE_SIZE; loadDiscover(); });
  ['discoverTimeRange', 'discoverSeverity', 'discoverAgent', 'discoverGroup'].forEach(id => {
    document.getElementById(id)?.addEventListener('change', () => { discoverOffset = 0; loadDiscover(); });
  });
  let discoverSearchTimeout = null;
  document.getElementById('discoverSearch')?.addEventListener('input', () => {
    if (discoverSearchTimeout) clearTimeout(discoverSearchTimeout);
    discoverSearchTimeout = setTimeout(() => { discoverOffset = 0; loadDiscover(); }, 400);
  });
  document.getElementById('discoverDetailClose')?.addEventListener('click', closeDiscoverDetail);
  document.querySelectorAll('.discover-detail-tab').forEach((tab) => {
    tab.addEventListener('click', () => setDiscoverDetailTab(tab.getAttribute('data-tab')));
  });
  document.getElementById('discoverFilterAdd')?.addEventListener('click', () => {
    const fieldSelect = document.getElementById('discoverFilterField');
    const field = fieldSelect?.value;
    const op = document.getElementById('discoverFilterOp')?.value;
    const value = (document.getElementById('discoverFilterValue')?.value || '').trim();
    if (!field) return;
    const type = fieldSelect?.options[fieldSelect.selectedIndex]?.getAttribute('data-type') || undefined;
    discoverDslFilters.push({ field, op, value, type });
    document.getElementById('discoverFilterValue').value = '';
    renderDiscoverFilterPills();
    discoverOffset = 0;
    loadDiscover();
  });
  document.getElementById('discoverPageSize')?.addEventListener('change', () => { discoverOffset = 0; loadDiscover(); });

  document.getElementById('rulesAddFile')?.addEventListener('click', openRulesModal);
  document.getElementById('rulesRefresh')?.addEventListener('click', () => { rulesOffset = 0; loadRules(); });
  document.getElementById('rulesModalClose')?.addEventListener('click', closeRulesModal);
  document.getElementById('rulesModalCancel')?.addEventListener('click', closeRulesModal);
  document.getElementById('rulesModalSave')?.addEventListener('click', saveRulesFile);
  document.getElementById('rulesPrev')?.addEventListener('click', () => { rulesOffset = Math.max(0, rulesOffset - RULES_PAGE_SIZE); loadRules(); });
  document.getElementById('rulesNext')?.addEventListener('click', () => { rulesOffset += RULES_PAGE_SIZE; loadRules(); });
  let rulesSearchTimeout = null;
  document.getElementById('rulesSearch')?.addEventListener('input', () => {
    if (rulesSearchTimeout) clearTimeout(rulesSearchTimeout);
    rulesSearchTimeout = setTimeout(() => { rulesOffset = 0; loadRules(); }, 400);
  });
  document.getElementById('rulesDetailClose')?.addEventListener('click', closeRuleDetail);
  document.getElementById('rulesDetailViewFile')?.addEventListener('click', loadRuleFileContent);
  document.getElementById('rulesBody')?.addEventListener('click', (e) => {
    const row = e.target.closest('.rule-row');
    if (!row) return;
    const idx = row.getAttribute('data-index');
    if (idx != null && rulesCache[parseInt(idx, 10)] != null) openRuleDetail(parseInt(idx, 10));
  });

  document.getElementById('decodersAddFile')?.addEventListener('click', openDecodersModal);
  document.getElementById('decodersRefresh')?.addEventListener('click', () => { decodersOffset = 0; loadDecoders(); });
  document.getElementById('decodersModalClose')?.addEventListener('click', closeDecodersModal);
  document.getElementById('decodersModalCancel')?.addEventListener('click', closeDecodersModal);
  document.getElementById('decodersModalSave')?.addEventListener('click', saveDecodersFile);
  document.getElementById('decodersDetailClose')?.addEventListener('click', closeDecoderDetail);
  document.getElementById('decodersDetailViewFile')?.addEventListener('click', loadDecoderFileContent);
  document.getElementById('decodersPrev')?.addEventListener('click', () => { decodersOffset = Math.max(0, decodersOffset - DECODERS_PAGE_SIZE); loadDecoders(); });
  document.getElementById('decodersNext')?.addEventListener('click', () => { decodersOffset += DECODERS_PAGE_SIZE; loadDecoders(); });
  let decodersSearchTimeout = null;
  document.getElementById('decodersSearch')?.addEventListener('input', () => {
    if (decodersSearchTimeout) clearTimeout(decodersSearchTimeout);
    decodersSearchTimeout = setTimeout(() => { decodersOffset = 0; loadDecoders(); }, 400);
  });
  document.getElementById('decodersBody')?.addEventListener('click', (e) => {
    const row = e.target.closest('.decoder-row');
    if (!row) return;
    const idx = row.getAttribute('data-index');
    if (idx != null && decodersCache[parseInt(idx, 10)] != null) openDecoderDetail(parseInt(idx, 10));
  });

  document.getElementById('indexMgmtRefresh')?.addEventListener('click', loadIndexManagement);
  document.getElementById('indexMgmtDataStreams')?.addEventListener('change', loadIndexManagement);
  let indexMgmtSearchTimeout = null;
  document.getElementById('indexMgmtSearch')?.addEventListener('input', () => {
    if (indexMgmtSearchTimeout) clearTimeout(indexMgmtSearchTimeout);
    indexMgmtSearchTimeout = setTimeout(loadIndexManagement, 400);
  });

  document.getElementById('discoverBody')?.addEventListener('click', (e) => {
    const row = e.target.closest('.discover-row');
    if (!row) return;
    const idx = row.getAttribute('data-index');
    if (discoverAlertsCache[idx] != null) openDiscoverDetail(discoverAlertsCache[idx]);
  });

  document.querySelectorAll('.hipaa-tab').forEach(el => {
    el.addEventListener('click', () => setHipaaView(el.getAttribute('data-hipaa-view')));
  });
  document.getElementById('hipaaRefresh')?.addEventListener('click', () => {
    const view = document.querySelector('.hipaa-tab.active')?.getAttribute('data-hipaa-view') || 'dashboard';
    setHipaaView(view);
  });
  document.getElementById('hipaaTimeRange')?.addEventListener('change', () => {
    const view = document.querySelector('.hipaa-tab.active')?.getAttribute('data-hipaa-view') || 'dashboard';
    setHipaaView(view);
  });
  document.getElementById('hipaaHideZero')?.addEventListener('change', renderHipaaRequirementsGrid);
  document.getElementById('hipaaFilterReqs')?.addEventListener('input', renderHipaaRequirementsGrid);
  document.getElementById('hipaaEventsPrev')?.addEventListener('click', () => { hipaaEventsOffset = Math.max(0, hipaaEventsOffset - HIPAA_PAGE_SIZE); loadHipaaEvents(); });
  document.getElementById('hipaaEventsNext')?.addEventListener('click', () => { hipaaEventsOffset += HIPAA_PAGE_SIZE; loadHipaaEvents(); });

  document.getElementById('btnRefresh').addEventListener('click', () => {
    const active = document.querySelector('.nav-item.active');
    if (active) goToPage(active.getAttribute('data-page'));
  });

  function wireTestButton(btnId, resultId, apiUrl) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    btn.addEventListener('click', async () => {
      const resultEl = document.getElementById(resultId);
      if (resultEl) resultEl.textContent = 'Testing…';
      try {
        const res = await fetch(apiUrl);
        const data = await res.json().catch(() => ({}));
        const ok = res.ok && data.ok;
        if (resultEl) {
          resultEl.textContent = ok ? 'Connection successful.' : (data.error || res.statusText || 'Connection failed.');
          resultEl.className = 'test-result ' + (ok ? 'ok' : 'fail');
        }
      } catch (e) {
        if (resultEl) {
          resultEl.textContent = e.message || 'Request failed.';
          resultEl.className = 'test-result fail';
        }
      }
    });
  }
  wireTestButton('btnTestManager', 'managerTestResult', API.managerTest);
  wireTestButton('btnTestIndexer', 'indexerTestResult', API.indexerTest);

  const dashboardClearFilter = document.getElementById('dashboardClearFilter');
  if (dashboardClearFilter) {
    dashboardClearFilter.addEventListener('click', () => {
      const agentEl = document.getElementById('dashboardAgent');
      if (agentEl) agentEl.value = '';
      setDashboardSaved(Object.assign(getDashboardSaved(), { agent_name: undefined, agent_id: undefined }));
      loadDashboard();
    });
  }
  const dashboardApply = document.getElementById('dashboardApply');
  if (dashboardApply) {
    dashboardApply.addEventListener('click', () => {
      const minLevelEl = document.getElementById('dashboardMinLevel');
      const timeRangeEl = document.getElementById('dashboardTimeRange');
      const agentEl = document.getElementById('dashboardAgent');
      const ruleGroupEl = document.getElementById('dashboardRuleGroup');
      const excludeEl = document.getElementById('dashboardExcludeRules');
      const agentOpt = agentEl?.selectedOptions?.[0];
      setDashboardSaved({
        min_level: minLevelEl?.value ? parseInt(minLevelEl.value, 10) : undefined,
        timeRange: timeRangeEl?.value || '7d',
        agent_name: agentEl?.value || undefined,
        agent_id: agentOpt?.dataset?.agentId || undefined,
        rule_group: ruleGroupEl?.value || undefined,
        exclude_rule_ids: excludeEl?.value?.trim() || undefined,
      });
      loadDashboard();
    });
  }
  const dashboardSave = document.getElementById('dashboardSave');
  if (dashboardSave) {
    dashboardSave.addEventListener('click', () => {
      const minLevelEl = document.getElementById('dashboardMinLevel');
      const timeRangeEl = document.getElementById('dashboardTimeRange');
      const agentEl = document.getElementById('dashboardAgent');
      const ruleGroupEl = document.getElementById('dashboardRuleGroup');
      const excludeEl = document.getElementById('dashboardExcludeRules');
      const agentOpt = agentEl?.selectedOptions?.[0];
      setDashboardSaved({
        min_level: minLevelEl?.value ? parseInt(minLevelEl.value, 10) : undefined,
        timeRange: timeRangeEl?.value || '7d',
        agent_name: agentEl?.value || undefined,
        agent_id: agentOpt?.dataset?.agentId || undefined,
        rule_group: ruleGroupEl?.value || undefined,
        exclude_rule_ids: excludeEl?.value?.trim() || undefined,
      });
      const orig = dashboardSave.textContent;
      dashboardSave.textContent = 'Saved';
      setTimeout(() => { dashboardSave.textContent = orig; }, 1500);
    });
  }

  // ---------------------------------------------------------------------------
  // drawDonutChart — simple canvas donut used by MITRE, FIM, Audit, SCA pages
  // ---------------------------------------------------------------------------
  function drawDonutChart(canvas, segments, centerLabel) {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.width;
    const h = canvas.height;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const total = segments.reduce((s, sg) => s + (sg.value || 0), 0);
    if (total === 0) {
      ctx.fillStyle = '#8aaad0';
      ctx.font = '13px Outfit, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('No data', w / 2, h / 2);
      return;
    }

    const cx = w / 2;
    const cy = h / 2 - 10;
    const outerR = Math.min(w, h) * 0.38;
    const innerR = outerR * 0.6;
    let startAngle = -Math.PI / 2;

    segments.forEach(sg => {
      const slice = (sg.value / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, outerR, startAngle, startAngle + slice);
      ctx.closePath();
      ctx.fillStyle = sg.color || '#3399ff';
      ctx.fill();
      startAngle += slice;
    });

    // Hole
    ctx.beginPath();
    ctx.arc(cx, cy, innerR, 0, Math.PI * 2);
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--bg-panel') || '#0d1b2a';
    ctx.fill();

    // Center label
    ctx.fillStyle = '#e0efff';
    ctx.font = 'bold 13px Outfit, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(centerLabel || '', cx, cy);

    // Legend below
    const legendY = cy + outerR + 14;
    const itemW = w / Math.min(segments.length, 4);
    segments.forEach((sg, i) => {
      const lx = (i % 4) * itemW + itemW / 2;
      const ly = legendY + Math.floor(i / 4) * 18;
      ctx.fillStyle = sg.color || '#3399ff';
      ctx.fillRect(lx - itemW / 2 + 2, ly - 5, 10, 10);
      ctx.fillStyle = '#8aaad0';
      ctx.font = '10px Outfit, sans-serif';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      ctx.fillText(sg.label + ' (' + (sg.value || 0) + ')', lx - itemW / 2 + 16, ly);
    });
  }

  // ---------------------------------------------------------------------------
  // MITRE ATT&CK Page
  // ---------------------------------------------------------------------------
  async function loadMitrePage() {
    const [tacticsRes, techniques] = await Promise.all([
      fetchJson(API.mitreTactics + '?size=20').catch(() => ({})),
      fetchJson(API.mitreMatrix).catch(() => ({techniques: []}))
    ]);

    const tacticList = Array.isArray(tacticsRes.buckets) ? tacticsRes.buckets : (Array.isArray(tacticsRes) ? tacticsRes : []);
    const techList = Array.isArray(techniques.techniques) ? techniques.techniques : (Array.isArray(techniques) ? techniques : []);

    const normalizedTactics = tacticList.map(t => ({
      tactic: t.tactic || t.key || 'Unknown',
      count: t.count || t.doc_count || 0,
    }));
    const normalizedTechs = techList.map(t => ({
      technique_id: t.technique_id || t.key || '—',
      technique_name: t.technique_name || t.name || t.key || '—',
      count: t.count || t.doc_count || 0,
    }));

    const totalAlerts = normalizedTechs.reduce((s, t) => s + (t.count || 0), 0);
    const critCount = normalizedTechs.filter(t => (t.count || 0) >= 10).length;

    const el = id => document.getElementById(id);
    if (el('mitreTechniquesCount')) el('mitreTechniquesCount').textContent = normalizedTechs.length;
    if (el('mitreTacticsCount')) el('mitreTacticsCount').textContent = normalizedTactics.length;
    if (el('mitreTotalAlerts')) el('mitreTotalAlerts').textContent = totalAlerts.toLocaleString();
    if (el('mitreCriticalCount')) el('mitreCriticalCount').textContent = critCount;

    // Heatmap
    const matrix = el('mitreMatrix');
    if (matrix) {
      if (normalizedTechs.length === 0) {
        matrix.innerHTML = '<div style="color:var(--text-muted);padding:20px;text-align:center">No MITRE ATT&CK data available. Alerts with MITRE mappings will appear here.</div>';
      } else {
        const maxCount = Math.max(...normalizedTechs.map(t => t.count || 1), 1);
        matrix.innerHTML = '<div class="mitre-grid">' + normalizedTechs.slice(0, 60).map(t => {
          const intensity = t.count / maxCount;
          const r = Math.round(50 + intensity * 200);
          const g = Math.round(Math.max(0, 100 - intensity * 100));
          const bg = `rgba(${r}, ${g}, 0, ${0.3 + intensity * 0.7})`;
          return `<div class="mitre-cell" style="background:${bg}" title="${escapeHtml(t.technique_id)}: ${t.count} alerts">
            <span class="mitre-cell-id">${escapeHtml(t.technique_id)}</span>
            <span class="mitre-cell-count">${t.count}</span>
          </div>`;
        }).join('') + '</div>';
      }
    }

    // Tactic bar chart
    const tacticBar = el('mitreTacticsBar');
    if (tacticBar) {
      if (normalizedTactics.length === 0) {
        tacticBar.innerHTML = '<div style="color:var(--text-muted);padding:20px;text-align:center">No tactic data available.</div>';
      } else {
        const maxT = Math.max(...normalizedTactics.map(t => t.count || 0), 1);
        tacticBar.innerHTML = normalizedTactics.slice(0, 10).map(t => {
          const pct = (t.count / maxT * 100);
          return `<div class="bar-row"><span class="bar-label">${escapeHtml(t.tactic)}</span>
            <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:var(--cyber-orange, #ff9900)"></div></div>
            <span class="bar-count">${t.count}</span></div>`;
        }).join('');
      }
    }

    // Top techniques list
    const topList = el('mitreTopTechniques');
    if (topList) {
      topList.innerHTML = normalizedTechs.length ? normalizedTechs.slice(0, 10).map((t, i) => `
        <div class="mitre-list-row">
          <span class="mitre-rank">#${i + 1}</span>
          <span class="mitre-id">${escapeHtml(t.technique_id)}</span>
          <span class="mitre-name">${escapeHtml(t.technique_name)}</span>
          <span class="mitre-count cyber-val-orange">${(t.count || 0).toLocaleString()}</span>
        </div>`).join('') : '<div style="color:var(--text-muted);padding:20px">No technique data available.</div>';
    }

    // Technique donut
    const donutCanvas = el('mitreTechniqueDonut');
    if (donutCanvas && normalizedTechs.length > 0) {
      const top5 = normalizedTechs.slice(0, 5);
      const colors = ['#ff3333', '#ff9900', '#ffcc00', '#3399ff', '#33cc99'];
      drawDonutChart(donutCanvas, top5.map((t, i) => ({
        label: t.technique_id,
        value: t.count || 0,
        color: colors[i % colors.length]
      })), 'Top Techniques');
    } else if (donutCanvas) {
      const ctx = donutCanvas.getContext('2d');
      ctx.clearRect(0, 0, donutCanvas.width, donutCanvas.height);
      ctx.fillStyle = '#8aaad0';
      ctx.font = '13px Outfit, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('No MITRE data', donutCanvas.width / 2, donutCanvas.height / 2);
    }
  }

  // ---------------------------------------------------------------------------
  // File Integrity Monitoring Page
  // ---------------------------------------------------------------------------
  async function loadFimPage() {
    const [summary, events] = await Promise.all([
      fetchJson(API.fimSummary).catch(() => ({total: 0, added: 0, modified: 0, deleted: 0})),
      fetchJson(API.fimEvents + '?size=20&offset=0').catch(() => ({hits: [], total: 0}))
    ]);

    const el = id => document.getElementById(id);
    if (el('fimTotal')) el('fimTotal').textContent = (summary.total || 0).toLocaleString();
    if (el('fimAdded')) el('fimAdded').textContent = (summary.added || 0).toLocaleString();
    if (el('fimModified')) el('fimModified').textContent = (summary.modified || 0).toLocaleString();
    if (el('fimDeleted')) el('fimDeleted').textContent = (summary.deleted || 0).toLocaleString();
    if (el('fimEventsHits')) el('fimEventsHits').textContent = (events.total || 0) + ' hits';
    if (el('fimEventsInfo')) el('fimEventsInfo').textContent = `Showing ${Math.min((events.hits || []).length, 20)} of ${events.total || 0}`;

    // Action donut
    const donut = el('fimActionDonut');
    if (donut) {
      const segments = [
        {label: 'Added', value: summary.added || 0, color: '#33cc99'},
        {label: 'Modified', value: summary.modified || 0, color: '#ff9900'},
        {label: 'Deleted', value: summary.deleted || 0, color: '#ff3333'}
      ];
      if (segments.every(s => s.value === 0)) {
        const ctx = donut.getContext('2d');
        ctx.clearRect(0, 0, donut.width, donut.height);
        ctx.fillStyle = '#8aaad0';
        ctx.font = '13px Outfit, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('No FIM events yet', donut.width / 2, donut.height / 2);
      } else {
        drawDonutChart(donut, segments, 'By Action');
      }
    }

    // Events table
    const tbody = el('fimEventsBody');
    if (tbody) {
      const rows = events.hits || [];
      tbody.innerHTML = rows.length ? rows.map(r => {
        const ts = r.timestamp ? new Date(r.timestamp).toLocaleString() : '—';
        const agent = escapeHtml(r.agent_name || r.agent || '—');
        const action = escapeHtml(r.fim_action || r.action || (r.event_data && r.event_data.type) || '—');
        const path = escapeHtml(r.fim_path || r.file_path || (r.event_data && r.event_data.path) || '—');
        const fullHash = r.fim_sha256 || r.sha256 || (r.event_data && r.event_data.sha256) || '';
        const hash = escapeHtml(fullHash.substring(0, 12) + (fullHash.length > 12 ? '…' : (fullHash ? '' : '—')));
        const size = escapeHtml(String(r.fim_size || r.file_size || (r.event_data && r.event_data.size) || '—'));
        return `<tr><td>${ts}</td><td>${agent}</td><td><span class="cyber-pill">${action}</span></td><td class="mono">${path}</td><td class="mono">${hash}</td><td>${size}</td></tr>`;
      }).join('') : '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;padding:20px">No FIM events found. Enable File Integrity Monitoring in WatchNode agent config.</td></tr>';
    }

    // Wire filter/pagination
    let fimOffset = 0;
    const fimSize = 20;
    async function reloadFimEvents() {
      const agentVal = ((el('fimAgentFilter') && el('fimAgentFilter').value) || '').trim();
      const pathVal = ((el('fimPathFilter') && el('fimPathFilter').value) || '').trim();
      let url = `${API.fimEvents}?size=${fimSize}&offset=${fimOffset}`;
      if (agentVal) url += `&agent_name=${encodeURIComponent(agentVal)}`;
      if (pathVal) url += `&path=${encodeURIComponent(pathVal)}`;
      const data = await fetchJson(url).catch(() => ({hits: [], total: 0}));
      const tbody2 = el('fimEventsBody');
      if (tbody2) {
        const rows2 = data.hits || [];
        tbody2.innerHTML = rows2.length ? rows2.map(r => {
          const ts = r.timestamp ? new Date(r.timestamp).toLocaleString() : '—';
          const a2 = escapeHtml(r.agent_name || r.agent || '—');
          const act2 = escapeHtml(r.fim_action || r.action || (r.event_data && r.event_data.type) || '—');
          const p2 = escapeHtml(r.fim_path || r.file_path || (r.event_data && r.event_data.path) || '—');
          const h2 = escapeHtml((r.fim_sha256 || r.sha256 || '').substring(0, 12));
          const s2 = String(r.fim_size || r.file_size || (r.event_data && r.event_data.size) || '—');
          return `<tr><td>${ts}</td><td>${a2}</td><td><span class="cyber-pill">${act2}</span></td><td class="mono">${p2}</td><td class="mono">${h2}</td><td>${s2}</td></tr>`;
        }).join('') : '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;padding:20px">No results.</td></tr>';
      }
      if (el('fimEventsHits')) el('fimEventsHits').textContent = (data.total || 0) + ' hits';
      if (el('fimEventsInfo')) el('fimEventsInfo').textContent = `Showing ${Math.min((data.hits || []).length, fimSize)} of ${data.total || 0}`;
      if (el('fimPageInfo')) el('fimPageInfo').textContent = `Page ${Math.floor(fimOffset / fimSize) + 1}`;
    }

    el('fimApplyFilter') && el('fimApplyFilter').addEventListener('click', () => { fimOffset = 0; reloadFimEvents(); });
    el('fimPrev') && el('fimPrev').addEventListener('click', () => { if (fimOffset >= fimSize) { fimOffset -= fimSize; reloadFimEvents(); } });
    el('fimNext') && el('fimNext').addEventListener('click', () => { fimOffset += fimSize; reloadFimEvents(); });
  }

  // ---------------------------------------------------------------------------
  // Audit Trail Page
  // ---------------------------------------------------------------------------
  async function loadAuditPage() {
    const [summary, events] = await Promise.all([
      fetchJson(API.auditSummary).catch(() => ({total: 0, failed_logins: 0, successful_logins: 0, sudo_events: 0})),
      fetchJson(API.auditEvents + '?size=20&offset=0').catch(() => ({hits: [], total: 0}))
    ]);

    const el = id => document.getElementById(id);
    if (el('auditTotal')) el('auditTotal').textContent = (summary.total || 0).toLocaleString();
    if (el('auditFailed')) el('auditFailed').textContent = (summary.failed_logins || 0).toLocaleString();
    if (el('auditSuccess')) el('auditSuccess').textContent = (summary.successful_logins || 0).toLocaleString();
    if (el('auditSudo')) el('auditSudo').textContent = (summary.sudo_events || 0).toLocaleString();
    if (el('auditEventsHits')) el('auditEventsHits').textContent = (events.total || 0) + ' hits';

    // Login donut
    const donut = el('auditLoginDonut');
    if (donut) {
      const segments = [
        {label: 'Success', value: summary.successful_logins || 0, color: '#33cc99'},
        {label: 'Failed', value: summary.failed_logins || 0, color: '#ff3333'},
        {label: 'Sudo', value: summary.sudo_events || 0, color: '#ff9900'}
      ];
      if (segments.every(s => s.value === 0)) {
        const ctx = donut.getContext('2d');
        ctx.clearRect(0, 0, donut.width, donut.height);
        ctx.fillStyle = '#8aaad0';
        ctx.font = '13px Outfit, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('No auth events found', donut.width / 2, donut.height / 2);
      } else {
        drawDonutChart(donut, segments, 'Auth Events');
      }
    }

    // Events table
    const tbody = el('auditEventsBody');
    if (tbody) {
      const rows = events.hits || [];
      tbody.innerHTML = rows.length ? rows.map(r => {
        const ts = r.timestamp ? new Date(r.timestamp).toLocaleString() : '—';
        const agent = escapeHtml(r.agent_name || (r.agent && r.agent.name) || '—');
        const user = escapeHtml((r.event_data && (r.event_data.dstuser || r.event_data.user)) || r.user || '—');
        const desc = escapeHtml(r.rule_description || (r.rule && r.rule.description) || '—');
        const srcip = escapeHtml((r.event_data && r.event_data.srcip) || r.srcip || '—');
        const level = r.rule_level || (r.rule && r.rule.level) || '—';
        const ruleId = r.rule_id || (r.rule && r.rule.id) || '—';
        const lvlClass = level >= 10 ? 'cyber-pill-crit' : level >= 7 ? 'cyber-tag-red' : 'cyber-pill';
        return `<tr><td>${ts}</td><td>${agent}</td><td>${user}</td><td>${desc}</td><td>${srcip}</td><td><span class="${lvlClass}">${level}</span></td><td>${ruleId}</td></tr>`;
      }).join('') : '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:20px">No authentication events found. Auth log collection must be enabled in WatchNode.</td></tr>';
    }
    if (el('auditEventsInfo')) el('auditEventsInfo').textContent = `Showing ${Math.min((events.hits || []).length, 20)} of ${events.total || 0}`;

    let auditOffset = 0;
    const auditSize = 20;
    async function reloadAuditEvents() {
      const agentVal = ((el('auditAgentFilter') && el('auditAgentFilter').value) || '').trim();
      const timeRange = (el('auditTimeRange') && el('auditTimeRange').value) || '24h';
      const bounds = getTimeRangeBounds(timeRange);
      let url = `${API.auditEvents}?size=${auditSize}&offset=${auditOffset}`;
      if (agentVal) url += `&agent_name=${encodeURIComponent(agentVal)}`;
      if (bounds.from) url += `&time_from=${encodeURIComponent(bounds.from)}`;
      if (bounds.to) url += `&time_to=${encodeURIComponent(bounds.to)}`;
      const data = await fetchJson(url).catch(() => ({hits: [], total: 0}));
      const rows2 = data.hits || [];
      const tbody2 = el('auditEventsBody');
      if (tbody2) {
        tbody2.innerHTML = rows2.length ? rows2.map(r => {
          const ts = r.timestamp ? new Date(r.timestamp).toLocaleString() : '—';
          const a2 = escapeHtml(r.agent_name || (r.agent && r.agent.name) || '—');
          const u2 = escapeHtml((r.event_data && (r.event_data.dstuser || r.event_data.user)) || r.user || '—');
          const d2 = escapeHtml(r.rule_description || (r.rule && r.rule.description) || '—');
          const ip2 = escapeHtml((r.event_data && r.event_data.srcip) || r.srcip || '—');
          const lv2 = r.rule_level || (r.rule && r.rule.level) || '—';
          const rid2 = r.rule_id || (r.rule && r.rule.id) || '—';
          const lc2 = lv2 >= 10 ? 'cyber-pill-crit' : lv2 >= 7 ? 'cyber-tag-red' : 'cyber-pill';
          return `<tr><td>${ts}</td><td>${a2}</td><td>${u2}</td><td>${d2}</td><td>${ip2}</td><td><span class="${lc2}">${lv2}</span></td><td>${rid2}</td></tr>`;
        }).join('') : '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:20px">No results.</td></tr>';
      }
      if (el('auditEventsHits')) el('auditEventsHits').textContent = (data.total || 0) + ' hits';
      if (el('auditEventsInfo')) el('auditEventsInfo').textContent = `Showing ${rows2.length} of ${data.total || 0}`;
      if (el('auditPageInfo')) el('auditPageInfo').textContent = `Page ${Math.floor(auditOffset / auditSize) + 1}`;
    }

    el('auditApplyFilter') && el('auditApplyFilter').addEventListener('click', () => { auditOffset = 0; reloadAuditEvents(); });
    el('auditPrev') && el('auditPrev').addEventListener('click', () => { if (auditOffset >= auditSize) { auditOffset -= auditSize; reloadAuditEvents(); } });
    el('auditNext') && el('auditNext').addEventListener('click', () => { auditOffset += auditSize; reloadAuditEvents(); });
  }

  // ---------------------------------------------------------------------------
  // SCA / Policy Monitoring Page
  // ---------------------------------------------------------------------------
  async function loadScaPage() {
    const [summary, agentsRes] = await Promise.all([
      fetchJson(API.scaSummary).catch(() => ({total_checks: 0, passed: 0, failed: 0, not_applicable: 0, score_pct: 0, agents_checked: 0})),
      fetchJson(API.scaAgents + '?size=20').catch(() => ({agents: []}))
    ]);

    const el = id => document.getElementById(id);
    if (el('scaTotalChecks')) el('scaTotalChecks').textContent = (summary.total_checks || 0).toLocaleString();
    if (el('scaPassed')) el('scaPassed').textContent = (summary.passed || 0).toLocaleString();
    if (el('scaFailed')) el('scaFailed').textContent = (summary.failed || 0).toLocaleString();
    if (el('scaScore')) el('scaScore').textContent = (summary.score_pct || 0) + '%';

    // Result donut
    const donut = el('scaResultDonut');
    if (donut) {
      const segments = [
        {label: 'Passed', value: summary.passed || 0, color: '#33cc99'},
        {label: 'Failed', value: summary.failed || 0, color: '#ff3333'},
        {label: 'N/A', value: summary.not_applicable || 0, color: '#8aaad0'}
      ];
      if (segments.every(s => s.value === 0)) {
        const ctx = donut.getContext('2d');
        ctx.clearRect(0, 0, donut.width, donut.height);
        ctx.fillStyle = '#8aaad0';
        ctx.font = '13px Outfit, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('No SCA data yet', donut.width / 2, donut.height / 2);
      } else {
        drawDonutChart(donut, segments, 'Checks');
      }
    }

    // Agent bars
    const agentList = (agentsRes && (agentsRes.agents || agentsRes.hits)) || [];
    const agentBars = el('scaAgentBars');
    if (agentBars) {
      if (agentList.length === 0) {
        agentBars.innerHTML = '<div style="color:var(--text-muted);padding:20px;text-align:center">No SCA data available. Enable SCA collector in WatchNode agent configuration.</div>';
      } else {
        agentBars.innerHTML = agentList.slice(0, 10).map(a => {
          const score = a.score_pct || a.score || 0;
          const color = score >= 80 ? '#33cc99' : score >= 50 ? '#ff9900' : '#ff3333';
          return `<div class="bar-row">
            <span class="bar-label">${escapeHtml(a.agent_name || a.agent || 'Unknown')}</span>
            <div class="bar-track"><div class="bar-fill" style="width:${score}%;background:${color}"></div></div>
            <span class="bar-count">${score}%</span>
          </div>`;
        }).join('');
      }
    }

    // Agent table
    const tbody = el('scaAgentBody');
    if (tbody) {
      tbody.innerHTML = agentList.length ? agentList.map(a => {
        const score = a.score_pct || a.score || 0;
        const scoreColor = score >= 80 ? 'cyber-val-green' : score >= 50 ? 'cyber-val-orange' : 'cyber-val-red';
        return `<tr>
          <td>${escapeHtml(a.agent_name || a.agent || '—')}</td>
          <td>${escapeHtml(a.policy || 'CIS Benchmark')}</td>
          <td>${a.total_checks || 0}</td>
          <td>${a.passed || 0}</td>
          <td>${a.failed || 0}</td>
          <td>${a.not_applicable || 0}</td>
          <td><span class="${scoreColor}">${score}%</span></td>
          <td>${a.last_scan ? new Date(a.last_scan).toLocaleString() : '—'}</td>
        </tr>`;
      }).join('') : '<tr><td colspan="8" style="color:var(--text-muted);text-align:center;padding:20px">No SCA results found. Enable SCA in WatchNode agent config to see policy compliance data.</td></tr>';
    }
  }

  // =========================================================================
  // CUSTOM VISUALIZATIONS & DASHBOARDS
  // =========================================================================

  let vizBuilderMode = 'create';  // 'create' | 'edit'
  let vizBuilderCurrentId = null;
  let currentDashId = null;
  let currentDashData = null;
  let dashEditMode = false;

  // -------------- Visualization rendering functions -------------------------

  function renderWidgetContent(container, vizType, data, title) {
    if (!container) return;
    if (data.error) {
      container.innerHTML = '<div class="widget-error">⚠ ' + escapeHtml(data.error) + '</div>';
      return;
    }
    if (vizType === 'metric') renderWidgetMetric(container, data);
    else if (vizType === 'area') renderWidgetArea(container, data, title);
    else if (vizType === 'bar') renderWidgetBar(container, data);
    else if (vizType === 'pie') renderWidgetPie(container, data, title);
    else if (vizType === 'table') renderWidgetTable(container, data);
    else if (vizType === 'markdown') renderWidgetMarkdown(container, data);
    else container.innerHTML = '<div class="widget-error">Unknown type: ' + escapeHtml(vizType) + '</div>';
  }

  function renderWidgetMetric(el, data) {
    const val = data.value ?? '—';
    const formatted = typeof val === 'number' ? val.toLocaleString() : String(val);
    el.innerHTML = '<div class="widget-metric-wrap"><div class="widget-metric-val">' + escapeHtml(formatted) + '</div><div class="widget-metric-label">' + escapeHtml(data.label || '') + '</div></div>';
  }

  function renderWidgetArea(el, data, title) {
    const canvas = document.createElement('canvas');
    canvas.width = el.offsetWidth || 400;
    canvas.height = 160;
    canvas.style.width = '100%';
    canvas.style.height = '160px';
    el.innerHTML = '';
    el.appendChild(canvas);
    const ctx = canvas.getContext('2d');
    const series = data.series || [];
    if (!series.length || !series[0].data?.length) {
      ctx.fillStyle = 'rgba(138,170,208,0.4)'; ctx.font = '12px Outfit'; ctx.textAlign = 'center';
      ctx.fillText('No data', canvas.width/2, 80); return;
    }
    const colors = ['#3399ff','#ff9900','#33cc99','#ff3333','#cc33ff'];
    const allPts = series.flatMap(s => s.data);
    const maxY = Math.max(...allPts.map(p => p.count), 1);
    const W = canvas.width, H = canvas.height, padL = 30, padB = 20, padT = 10, padR = 10;
    const cW = W - padL - padR, cH = H - padT - padB;
    const xs = allPts.map(p => p.ts);
    const minX = Math.min(...xs), maxX = Math.max(...xs, minX + 1);
    const toX = ts => padL + ((ts - minX) / (maxX - minX)) * cW;
    const toY = v => padT + cH - (v / maxY) * cH;
    // Grid lines
    ctx.strokeStyle = 'rgba(255,255,255,0.06)'; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = padT + (i / 4) * cH;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    }
    series.forEach((s, si) => {
      if (!s.data?.length) return;
      const pts = s.data.filter(p => p.ts != null);
      if (!pts.length) return;
      const color = colors[si % colors.length];
      // Fill
      ctx.beginPath();
      ctx.moveTo(toX(pts[0].ts), H - padB);
      pts.forEach(p => ctx.lineTo(toX(p.ts), toY(p.count)));
      ctx.lineTo(toX(pts[pts.length-1].ts), H - padB);
      ctx.closePath();
      const r = parseInt(color.slice(1,3),16), g = parseInt(color.slice(3,5),16), b = parseInt(color.slice(5,7),16);
      ctx.fillStyle = `rgba(${r},${g},${b},0.15)`;
      ctx.fill();
      // Line
      ctx.beginPath();
      pts.forEach((p,i) => i === 0 ? ctx.moveTo(toX(p.ts), toY(p.count)) : ctx.lineTo(toX(p.ts), toY(p.count)));
      ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.stroke();
    });
    // X axis labels
    ctx.fillStyle = 'rgba(138,170,208,0.6)'; ctx.font = '9px JetBrains Mono'; ctx.textAlign = 'center';
    if (allPts[0]?.ts) ctx.fillText(new Date(allPts[0].ts).toLocaleDateString(), padL + 20, H - 4);
    if (allPts[allPts.length-1]?.ts) ctx.fillText(new Date(allPts[allPts.length-1].ts).toLocaleDateString(), W - padR - 20, H - 4);
    // Legend
    if (series.length > 1) {
      let lx = padL;
      series.forEach((s, si) => {
        ctx.fillStyle = colors[si % colors.length];
        ctx.fillRect(lx, padT, 10, 4);
        ctx.fillStyle = 'rgba(138,170,208,0.8)'; ctx.font = '9px Outfit';
        ctx.textAlign = 'left';
        ctx.fillText(s.name || '', lx + 13, padT + 6);
        lx += ctx.measureText(s.name || '').width + 28;
      });
    }
  }

  function renderWidgetBar(el, data) {
    const bars = data.bars || [];
    if (!bars.length) { el.innerHTML = '<div class="widget-empty">No data</div>'; return; }
    const max = Math.max(...bars.map(b => b.count), 1);
    el.innerHTML = '<div class="widget-bar-list">' + bars.map(b => {
      const pct = (b.count / max * 100).toFixed(1);
      return `<div class="widget-bar-row">
        <span class="widget-bar-label" title="${escapeHtml(b.label)}">${escapeHtml(b.label)}</span>
        <div class="widget-bar-track"><div class="widget-bar-fill" style="width:${pct}%"></div></div>
        <span class="widget-bar-count">${b.count.toLocaleString()}</span>
      </div>`;
    }).join('') + '</div>';
  }

  function renderWidgetPie(el, data, title) {
    const slices = data.slices || [];
    if (!slices.length) { el.innerHTML = '<div class="widget-empty">No data</div>'; return; }
    const canvas = document.createElement('canvas');
    const SIZE = Math.min(el.offsetWidth || 200, 200);
    canvas.width = SIZE; canvas.height = SIZE;
    canvas.style.maxWidth = '200px'; canvas.style.maxHeight = '200px';
    const legendEl = document.createElement('div');
    legendEl.className = 'widget-pie-legend';
    el.innerHTML = '';
    el.style.display = 'flex'; el.style.alignItems = 'center'; el.style.gap = '12px';
    el.appendChild(canvas);
    el.appendChild(legendEl);
    const ctx = canvas.getContext('2d');
    const total = slices.reduce((s, x) => s + x.value, 0);
    const colors = ['#3399ff','#ff9900','#33cc99','#ff3333','#cc33ff','#ffcc00','#00ccff','#ff6633','#99cc00','#ff99cc'];
    const cx = SIZE/2, cy = SIZE/2, r = SIZE/2 - 8, ri = r * 0.55;
    let angle = -Math.PI/2;
    slices.forEach((s, i) => {
      const sweep = (s.value / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, angle, angle + sweep);
      ctx.closePath();
      ctx.fillStyle = colors[i % colors.length];
      ctx.fill();
      ctx.strokeStyle = 'rgba(0,0,0,0.3)'; ctx.lineWidth = 1;
      ctx.stroke();
      angle += sweep;
    });
    // Inner circle (donut)
    ctx.beginPath(); ctx.arc(cx, cy, ri, 0, Math.PI*2);
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--bg-card') || '#1a2e42';
    ctx.fill();
    // Center total
    ctx.fillStyle = 'rgba(224,230,237,0.9)'; ctx.font = `bold ${Math.round(SIZE/10)}px Outfit`;
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText(total.toLocaleString(), cx, cy);
    // Legend
    legendEl.innerHTML = slices.slice(0,8).map((s, i) =>
      `<div class="wpie-leg-row"><span class="wpie-dot" style="background:${colors[i%colors.length]}"></span><span class="wpie-leg-label">${escapeHtml(s.label)}</span><span class="wpie-leg-val">${s.value.toLocaleString()}</span></div>`
    ).join('');
  }

  function renderWidgetTable(el, data) {
    const cols = data.columns || [];
    const rows = data.rows || [];
    if (!rows.length) { el.innerHTML = '<div class="widget-empty">No data</div>'; return; }
    const LABELS = {'timestamp':'Time','rule_level':'Level','rule_description':'Description','agent_id':'Agent','rule_groups':'Groups','rule_id':'Rule ID'};
    el.innerHTML = '<div class="table-wrap" style="max-height:220px;overflow-y:auto"><table class="table" style="font-size:11px"><thead><tr>' +
      cols.map(c => '<th>' + escapeHtml(LABELS[c]||c) + '</th>').join('') + '</tr></thead><tbody>' +
      rows.map(r => '<tr>' + cols.map(c => {
        let v = r[c];
        if (v == null) return '<td>—</td>';
        if (c === 'timestamp') v = new Date(v).toLocaleString();
        if (c === 'rule_level') {
          const n = Number(v);
          const cls = n>=12?'disc-lvl disc-lvl-crit':n>=8?'disc-lvl disc-lvl-high':n>=4?'disc-lvl disc-lvl-med':'disc-lvl disc-lvl-low';
          return '<td><span class="'+cls+'">'+n+'</span></td>';
        }
        const s = String(v);
        return '<td>' + escapeHtml(s.length>60?s.slice(0,60)+'…':s) + '</td>';
      }).join('') + '</tr>').join('') + '</tbody></table></div>';
  }

  function renderWidgetMarkdown(el, data) {
    // Basic markdown: headers, bold, italic, code, line breaks
    let md = escapeHtml(data.content || '');
    md = md.replace(/^### (.+)$/gm, '<h3>$1</h3>');
    md = md.replace(/^## (.+)$/gm, '<h2>$1</h2>');
    md = md.replace(/^# (.+)$/gm, '<h1>$1</h1>');
    md = md.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    md = md.replace(/\*(.+?)\*/g, '<em>$1</em>');
    md = md.replace(/`(.+?)`/g, '<code>$1</code>');
    md = md.replace(/\n/g, '<br>');
    el.innerHTML = '<div class="widget-markdown">' + md + '</div>';
  }

  // -------------- Visualize Page -------------------------------------------

  async function loadVisualizePage() {
    document.getElementById('vizBuilderPanel')?.classList.add('hidden');
    document.getElementById('vizListView')?.classList.remove('hidden');
    const res = await fetchJson(API.customVizList).catch(() => ({ visualizations: [] }));
    const vizs = res.visualizations || [];
    const grid = document.getElementById('vizList');
    const empty = document.getElementById('vizListEmpty');
    if (!grid) return;
    if (!vizs.length) {
      grid.innerHTML = '';
      empty?.classList.remove('hidden');
      return;
    }
    empty?.classList.add('hidden');
    const TYPE_ICONS = { metric:'🔢', area:'📈', bar:'📊', pie:'🥧', table:'📋', markdown:'📝' };
    grid.innerHTML = vizs.map(v => `
      <div class="viz-card" data-viz-id="${escapeHtml(v.id)}">
        <div class="viz-card-icon">${TYPE_ICONS[v.viz_type] || '📊'}</div>
        <div class="viz-card-info">
          <div class="viz-card-title">${escapeHtml(v.title)}</div>
          <div class="viz-card-meta">${escapeHtml(v.viz_type)} · ${escapeHtml(v.datasource.replace('watchvault-','').replace('-*',''))}</div>
        </div>
        <div class="viz-card-actions">
          <button type="button" class="viz-card-edit global-btn" data-viz-id="${escapeHtml(v.id)}">✏ Edit</button>
          <button type="button" class="viz-card-delete global-btn" style="color:#ff4444" data-viz-id="${escapeHtml(v.id)}">🗑</button>
        </div>
      </div>`).join('');

    grid.querySelectorAll('.viz-card-edit').forEach(btn => {
      btn.addEventListener('click', () => openVizBuilder(btn.getAttribute('data-viz-id')));
    });
    grid.querySelectorAll('.viz-card-delete').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm('Delete this visualization?')) return;
        await fetch(API.customVizList + '/' + btn.getAttribute('data-viz-id'), { method: 'DELETE' });
        loadVisualizePage();
      });
    });
  }

  function openVizBuilder(editId) {
    vizBuilderMode = editId ? 'edit' : 'create';
    vizBuilderCurrentId = editId || null;
    document.getElementById('vizListView')?.classList.add('hidden');
    document.getElementById('vizBuilderPanel')?.classList.remove('hidden');
    document.getElementById('vizBuilderTitle').textContent = editId ? 'Edit Visualization' : 'New Visualization';
    // Reset form
    if (!editId) {
      document.getElementById('vizTitle').value = '';
      setVizType('metric');
      document.getElementById('vizDatasource').value = 'watchvault-alerts-*';
      document.getElementById('vizMetricAgg').value = 'count';
      document.getElementById('vizFilterLevel').value = '';
      document.getElementById('vizFilterGroup').value = '';
      document.getElementById('vizTimeFilter').value = '24h';
      document.getElementById('vizMarkdownContent').value = '';
      document.getElementById('vizPreviewArea').innerHTML = '<div class="viz-preview-placeholder">Configure and click Preview to see your visualization.</div>';
    } else {
      // Load existing viz and populate form
      fetchJson(API.customVizList + '/' + editId).then(v => {
        if (!v || v.error) return;
        document.getElementById('vizTitle').value = v.title || '';
        document.getElementById('vizDatasource').value = v.datasource || 'watchvault-alerts-*';
        document.getElementById('vizTimeFilter').value = (v.config && v.config.time_filter) || '24h';
        setVizType(v.viz_type || 'metric');
        const cfg = v.config || {};
        if (v.viz_type === 'metric') {
          document.getElementById('vizMetricAgg').value = cfg.aggregation || 'count';
        } else if (v.viz_type === 'area') {
          document.getElementById('vizAreaInterval').value = cfg.interval || '1h';
          document.getElementById('vizAreaSplit').value = cfg.split_by || '';
        } else if (v.viz_type === 'bar') {
          document.getElementById('vizBarField').value = cfg.field || 'rule_groups';
          document.getElementById('vizBarSize').value = cfg.size || '10';
        } else if (v.viz_type === 'pie') {
          document.getElementById('vizPieField').value = cfg.field || 'rule_groups';
          document.getElementById('vizPieSize').value = cfg.size || '10';
        } else if (v.viz_type === 'table') {
          document.getElementById('vizTableSize').value = cfg.size || '10';
        } else if (v.viz_type === 'markdown') {
          document.getElementById('vizMarkdownContent').value = cfg.content || '';
        }
        document.getElementById('vizFilterLevel').value = cfg.min_level || '';
        document.getElementById('vizFilterGroup').value = cfg.rule_group || '';
      });
    }
  }

  function setVizType(type) {
    document.querySelectorAll('.viz-type-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-type') === type);
    });
    document.querySelectorAll('.viz-type-config').forEach(el => el.classList.add('hidden'));
    const configEl = document.getElementById('vizConfig' + type.charAt(0).toUpperCase() + type.slice(1));
    if (configEl) configEl.classList.remove('hidden');
    const hideDs = type === 'markdown';
    document.getElementById('vizDatasourceSection')?.classList.toggle('hidden', hideDs);
    document.getElementById('vizFiltersSection')?.classList.toggle('hidden', hideDs);
  }

  function getVizBuilderConfig() {
    const type = document.querySelector('.viz-type-btn.active')?.getAttribute('data-type') || 'metric';
    const datasource = document.getElementById('vizDatasource')?.value || 'watchvault-alerts-*';
    const timeFilter = document.getElementById('vizTimeFilter')?.value || '24h';
    const minLevel = document.getElementById('vizFilterLevel')?.value || '';
    const ruleGroup = (document.getElementById('vizFilterGroup')?.value || '').trim();
    const cfg = { time_filter: timeFilter };
    if (minLevel) cfg.min_level = parseInt(minLevel);
    if (ruleGroup) cfg.rule_group = ruleGroup;
    if (type === 'metric') {
      cfg.aggregation = document.getElementById('vizMetricAgg')?.value || 'count';
      if (cfg.aggregation !== 'count') cfg.field = document.getElementById('vizMetricField')?.value || 'rule_level';
    } else if (type === 'area') {
      cfg.interval = document.getElementById('vizAreaInterval')?.value || '1h';
      const split = document.getElementById('vizAreaSplit')?.value;
      if (split) cfg.split_by = split;
    } else if (type === 'bar') {
      cfg.field = document.getElementById('vizBarField')?.value || 'rule_groups';
      cfg.size = parseInt(document.getElementById('vizBarSize')?.value) || 10;
    } else if (type === 'pie') {
      cfg.field = document.getElementById('vizPieField')?.value || 'rule_groups';
      cfg.size = parseInt(document.getElementById('vizPieSize')?.value) || 10;
    } else if (type === 'table') {
      cfg.size = parseInt(document.getElementById('vizTableSize')?.value) || 10;
      cfg.fields = ['timestamp','rule_level','rule_description','agent_id'];
    } else if (type === 'markdown') {
      cfg.content = document.getElementById('vizMarkdownContent')?.value || '';
    }
    return { type, datasource, config: cfg };
  }

  async function runVizPreview() {
    const { type, datasource, config } = getVizBuilderConfig();
    const tf = config.time_filter || '24h';
    const previewArea = document.getElementById('vizPreviewArea');
    if (!previewArea) return;
    previewArea.innerHTML = '<div class="viz-preview-placeholder">⏳ Loading preview…</div>';
    try {
      const res = await fetch('/api/custom/visualizations/_inline/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ viz_type: type, datasource, config, time_filter: tf }),
      }).then(r => r.json());
      previewArea.innerHTML = '';
      if (res.error || (res.data && res.data.error)) {
        previewArea.innerHTML = '<div class="widget-error">⚠ ' + escapeHtml((res.error || res.data?.error) || 'Error') + '</div>';
        return;
      }
      renderWidgetContent(previewArea, res.viz_type || type, res.data || {}, document.getElementById('vizTitle')?.value || 'Preview');
    } catch (e) {
      previewArea.innerHTML = '<div class="widget-error">Request failed</div>';
    }
  }

  async function saveVisualization() {
    const title = (document.getElementById('vizTitle')?.value || '').trim();
    if (!title) { alert('Please enter a title for the visualization.'); return; }
    const { type, datasource, config } = getVizBuilderConfig();
    const payload = { title, viz_type: type, datasource, config };
    let url = API.customVizList, method = 'POST';
    if (vizBuilderMode === 'edit' && vizBuilderCurrentId) {
      url = API.customVizList + '/' + vizBuilderCurrentId;
      method = 'PUT';
    }
    try {
      const res = await fetch(url, { method, headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) }).then(r => r.json());
      if (res.error) { alert('Save failed: ' + res.error); return; }
      document.getElementById('vizBuilderPanel')?.classList.add('hidden');
      document.getElementById('vizListView')?.classList.remove('hidden');
      loadVisualizePage();
    } catch (e) {
      alert('Save failed: ' + String(e));
    }
  }

  // -------------- Custom Dashboards Page -----------------------------------

  async function loadCustomDashboardsPage() {
    document.getElementById('dashViewer')?.classList.add('hidden');
    document.getElementById('dashListView')?.classList.remove('hidden');
    const res = await fetchJson(API.customDashList).catch(() => ({ dashboards: [] }));
    const dashes = res.dashboards || [];
    const list = document.getElementById('dashList');
    const empty = document.getElementById('dashListEmpty');
    if (!list) return;
    if (!dashes.length) {
      list.innerHTML = '';
      empty?.classList.remove('hidden');
      return;
    }
    empty?.classList.add('hidden');
    list.innerHTML = dashes.map(d => `
      <div class="dash-card">
        <div class="dash-card-icon">🗂</div>
        <div class="dash-card-info">
          <div class="dash-card-title">${escapeHtml(d.title)}</div>
          <div class="dash-card-meta">${d.widgets?.length || 0} widget${(d.widgets?.length||0)!==1?'s':''} · ${escapeHtml(d.time_filter||'24h')}</div>
          <div class="dash-card-desc">${escapeHtml(d.description||'')}</div>
        </div>
        <div class="dash-card-actions">
          <button type="button" class="btn-primary dash-open-btn" data-dash-id="${escapeHtml(d.id)}">Open</button>
        </div>
      </div>`).join('');
    list.querySelectorAll('.dash-open-btn').forEach(btn => {
      btn.addEventListener('click', () => openDashboard(btn.getAttribute('data-dash-id')));
    });
  }

  async function openDashboard(dashId) {
    currentDashId = dashId;
    dashEditMode = false;
    document.getElementById('dashListView')?.classList.add('hidden');
    document.getElementById('dashViewer')?.classList.remove('hidden');
    document.getElementById('dashEditToolbar')?.classList.add('hidden');
    document.getElementById('dashEditToggle').textContent = '✏ Edit';
    const dash = await fetchJson(API.customDashList + '/' + dashId).catch(() => null);
    if (!dash || dash.error) return;
    currentDashData = dash;
    document.getElementById('dashViewerTitle').textContent = dash.title || 'Dashboard';
    document.getElementById('dashTimeFilter').value = dash.time_filter || '24h';
    await renderDashboard();
  }

  async function renderDashboard() {
    const grid = document.getElementById('dashWidgetGrid');
    if (!grid || !currentDashId) return;
    const timeFilter = document.getElementById('dashTimeFilter')?.value || '24h';
    const widgetCount = (currentDashData?.widgets || []).length;
    if (widgetCount === 0) {
      grid.innerHTML = '<div class="dash-empty-grid"><p>This dashboard has no widgets yet.</p>' +
        (dashEditMode ? '<button type="button" id="dashAddWidgetInline" class="btn-primary">+ Add Widget</button>' : '') + '</div>';
      grid.querySelector('#dashAddWidgetInline')?.addEventListener('click', openAddWidgetModal);
      return;
    }
    // Render skeleton
    grid.innerHTML = (currentDashData.widgets || []).map((w, i) =>
      `<div class="dash-widget" data-widget-idx="${i}">
        <div class="dash-widget-header">
          <span class="dash-widget-title" id="wt-${i}">Loading…</span>
          ${dashEditMode ? `<button type="button" class="dash-remove-widget global-btn" data-idx="${i}" style="color:#ff4444;font-size:11px">✕ Remove</button>` : ''}
        </div>
        <div class="dash-widget-body" id="wb-${i}"><div class="viz-preview-placeholder">⏳</div></div>
      </div>`
    ).join('');
    if (dashEditMode) {
      grid.querySelectorAll('.dash-remove-widget').forEach(btn => {
        btn.addEventListener('click', () => {
          const idx = parseInt(btn.getAttribute('data-idx'));
          currentDashData.widgets.splice(idx, 1);
          renderDashboard();
        });
      });
    }
    // Run all widget queries
    try {
      const res = await fetch(API.customDashList + '/' + currentDashId + '/run', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ time_filter: timeFilter }),
      }).then(r => r.json());
      const results = res.results || {};
      (currentDashData.widgets || []).forEach((w, i) => {
        const r = results[String(i)];
        const titleEl = document.getElementById('wt-' + i);
        const bodyEl = document.getElementById('wb-' + i);
        if (titleEl) titleEl.textContent = r?.title || w.viz_id || '—';
        if (bodyEl && r) renderWidgetContent(bodyEl, r.viz_type, r.data || {}, r.title || '');
        else if (bodyEl) bodyEl.innerHTML = '<div class="widget-empty">No data</div>';
      });
    } catch (e) {
      console.error('Dashboard run error', e);
    }
  }

  async function openAddWidgetModal() {
    const modal = document.getElementById('dashAddWidgetModal');
    if (!modal) return;
    modal.classList.remove('hidden');
    const listEl = document.getElementById('dashAddWidgetList');
    const res = await fetchJson(API.customVizList).catch(() => ({ visualizations: [] }));
    const vizs = res.visualizations || [];
    const TYPE_ICONS = { metric:'🔢', area:'📈', bar:'📊', pie:'🥧', table:'📋', markdown:'📝' };
    listEl.innerHTML = vizs.length ? vizs.map(v =>
      `<div class="dash-add-viz-item" data-viz-id="${escapeHtml(v.id)}">
        <span class="dash-add-viz-icon">${TYPE_ICONS[v.viz_type]||'📊'}</span>
        <div>
          <div class="dash-add-viz-title">${escapeHtml(v.title)}</div>
          <div class="dash-add-viz-meta">${escapeHtml(v.viz_type)} · ${escapeHtml(v.datasource.replace('watchvault-','').replace('-*',''))}</div>
        </div>
        <button type="button" class="btn-primary dash-add-viz-pick" data-viz-id="${escapeHtml(v.id)}" style="margin-left:auto;flex-shrink:0">Add</button>
      </div>`).join('') :
      '<div style="color:var(--text-muted);padding:20px;text-align:center">No saved visualizations. Create some in the Visualize page first.</div>';

    listEl.querySelectorAll('.dash-add-viz-pick').forEach(btn => {
      btn.addEventListener('click', () => {
        if (!currentDashData) return;
        currentDashData.widgets = currentDashData.widgets || [];
        currentDashData.widgets.push({ viz_id: btn.getAttribute('data-viz-id') });
        modal.classList.add('hidden');
        renderDashboard();
      });
    });

    // Search filter
    const searchEl = document.getElementById('dashAddWidgetSearch');
    if (searchEl) {
      searchEl.value = '';
      searchEl.oninput = () => {
        const q = searchEl.value.toLowerCase();
        listEl.querySelectorAll('.dash-add-viz-item').forEach(item => {
          item.style.display = item.textContent.toLowerCase().includes(q) ? '' : 'none';
        });
      };
    }
  }

  // -------------- Event wiring for Visualize page ---------------------------

  document.getElementById('vizCreateNew')?.addEventListener('click', () => openVizBuilder(null));
  document.getElementById('vizBuilderBack')?.addEventListener('click', () => {
    document.getElementById('vizBuilderPanel')?.classList.add('hidden');
    document.getElementById('vizListView')?.classList.remove('hidden');
  });
  document.getElementById('vizBuilderSave')?.addEventListener('click', saveVisualization);
  document.getElementById('vizPreviewBtn')?.addEventListener('click', runVizPreview);

  document.getElementById('vizTypeGrid')?.addEventListener('click', e => {
    const btn = e.target.closest('.viz-type-btn');
    if (!btn) return;
    setVizType(btn.getAttribute('data-type'));
  });

  // -------------- Event wiring for Dashboard page ---------------------------

  document.getElementById('dashNewBtn')?.addEventListener('click', () => {
    document.getElementById('dashNewModal')?.classList.remove('hidden');
    document.getElementById('dashNewTitle').value = '';
    document.getElementById('dashNewDesc').value = '';
  });
  document.getElementById('dashNewModalClose')?.addEventListener('click', () => document.getElementById('dashNewModal')?.classList.add('hidden'));
  document.getElementById('dashNewCancel')?.addEventListener('click', () => document.getElementById('dashNewModal')?.classList.add('hidden'));
  document.getElementById('dashNewConfirm')?.addEventListener('click', async () => {
    const title = (document.getElementById('dashNewTitle')?.value || '').trim();
    if (!title) { alert('Please enter a title.'); return; }
    const desc = document.getElementById('dashNewDesc')?.value || '';
    const res = await fetch(API.customDashList, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ title, description: desc, widgets: [], time_filter: '24h' }),
    }).then(r => r.json());
    document.getElementById('dashNewModal')?.classList.add('hidden');
    if (res.id) openDashboard(res.id);
    else loadCustomDashboardsPage();
  });

  document.getElementById('dashBackBtn')?.addEventListener('click', () => {
    currentDashId = null; currentDashData = null; dashEditMode = false;
    document.getElementById('dashViewer')?.classList.add('hidden');
    document.getElementById('dashListView')?.classList.remove('hidden');
    loadCustomDashboardsPage();
  });

  document.getElementById('dashRefreshBtn')?.addEventListener('click', () => {
    if (currentDashId) renderDashboard();
    else loadCustomDashboardsPage();
  });

  document.getElementById('dashTimeFilter')?.addEventListener('change', () => { if (currentDashId) renderDashboard(); });

  document.getElementById('dashEditToggle')?.addEventListener('click', () => {
    dashEditMode = !dashEditMode;
    document.getElementById('dashEditToolbar')?.classList.toggle('hidden', !dashEditMode);
    document.getElementById('dashEditToggle').textContent = dashEditMode ? '👁 View' : '✏ Edit';
    renderDashboard();
  });

  document.getElementById('dashAddWidgetBtn')?.addEventListener('click', openAddWidgetModal);
  document.getElementById('dashAddWidgetClose')?.addEventListener('click', () => document.getElementById('dashAddWidgetModal')?.classList.add('hidden'));

  document.getElementById('dashSaveLayoutBtn')?.addEventListener('click', async () => {
    if (!currentDashId || !currentDashData) return;
    const timeFilter = document.getElementById('dashTimeFilter')?.value || '24h';
    await fetch(API.customDashList + '/' + currentDashId, {
      method: 'PUT', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ widgets: currentDashData.widgets, time_filter: timeFilter }),
    });
    dashEditMode = false;
    document.getElementById('dashEditToolbar')?.classList.add('hidden');
    document.getElementById('dashEditToggle').textContent = '✏ Edit';
    renderDashboard();
  });

  document.getElementById('dashCancelEditBtn')?.addEventListener('click', () => {
    dashEditMode = false;
    document.getElementById('dashEditToolbar')?.classList.add('hidden');
    document.getElementById('dashEditToggle').textContent = '✏ Edit';
    renderDashboard();
  });

  document.getElementById('dashDeleteBtn')?.addEventListener('click', async () => {
    if (!currentDashId) return;
    if (!confirm('Delete this dashboard?')) return;
    await fetch(API.customDashList + '/' + currentDashId, { method: 'DELETE' });
    currentDashId = null; currentDashData = null;
    document.getElementById('dashViewer')?.classList.add('hidden');
    document.getElementById('dashListView')?.classList.remove('hidden');
    loadCustomDashboardsPage();
  });

  async function loadReportsPage() {
    const btn = document.getElementById('reportGenerateBtn');
    if (!btn) return;
    // Remove any previously attached listener by cloning the button.
    const newBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(newBtn, btn);
    newBtn.addEventListener('click', async () => {
      const timeRange = document.getElementById('reportTimeRange')?.value || '7d';
      const fmt = document.querySelector('input[name="reportFormat"]:checked')?.value || 'pdf';
      const statusEl = document.getElementById('reportStatus');
      if (statusEl) statusEl.textContent = '⏳ Generating report…';
      try {
        const resp = await fetch(API.reportsGenerate, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({time_range: timeRange, format: fmt}),
        });
        if (!resp.ok) { if (statusEl) statusEl.textContent = '✗ Generation failed.'; return; }
        const isFallback = resp.headers.get('X-Report-Format') === 'html-fallback';
        if (fmt === 'pdf' && !isFallback) {
          const blob = await resp.blob();
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url; a.download = `sentinel-report-${timeRange}.pdf`; a.click();
          URL.revokeObjectURL(url);
          if (statusEl) statusEl.textContent = '✓ PDF downloaded.';
        } else {
          const html = await resp.text();
          const win = window.open('', '_blank');
          if (win) { win.document.write(html); win.document.close(); }
          if (statusEl) statusEl.textContent = isFallback ? '⚠ WeasyPrint not installed — opened as HTML.' : '✓ Opened in new tab.';
        }
      } catch(e) {
        if (statusEl) statusEl.textContent = '✗ Error: ' + e.message;
      }
    });
  }

  async function loadNotificationsPage() {
    const cfg = await fetchJson(API.notificationsConfig).catch(() => ({}));
    const emailStatus = document.getElementById('notifEmailStatus');
    const slackStatus = document.getElementById('notifSlackStatus');
    const throttleEl  = document.getElementById('notifThrottle');
    if (emailStatus) {
      const ok = cfg.smtp_configured;
      emailStatus.style.background = ok ? 'rgba(63,185,80,0.1)' : 'rgba(248,81,73,0.1)';
      emailStatus.style.border     = ok ? '1px solid rgba(63,185,80,0.3)' : '1px solid rgba(248,81,73,0.3)';
      emailStatus.textContent = ok
        ? `✓ Email configured → ${escapeHtml(cfg.smtp_host)} → ${escapeHtml(cfg.alert_to)}`
        : '✗ Email not configured. Set SMTP_HOST and ALERT_EMAIL_TO in .env';
    }
    if (slackStatus) {
      const ok = cfg.slack_configured;
      slackStatus.style.background = ok ? 'rgba(63,185,80,0.1)' : 'rgba(248,81,73,0.1)';
      slackStatus.style.border     = ok ? '1px solid rgba(63,185,80,0.3)' : '1px solid rgba(248,81,73,0.3)';
      slackStatus.textContent = ok ? '✓ Slack webhook configured.' : '✗ Slack not configured. Set SLACK_WEBHOOK_URL in .env';
    }
    if (throttleEl) throttleEl.textContent = String(cfg.throttle_minutes || 30);

    const emailBtn = document.getElementById('notifTestEmail');
    if (emailBtn) {
      const newEmailBtn = emailBtn.cloneNode(true);
      emailBtn.parentNode.replaceChild(newEmailBtn, emailBtn);
      newEmailBtn.addEventListener('click', async () => {
        const r = document.getElementById('notifEmailTestResult');
        if (r) r.textContent = '⏳ Sending…';
        const res = await fetch(API.notificationsTest, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({channel:'email'})}).then(x=>x.json()).catch(()=>({}));
        if (r) r.textContent = res?.results?.email ? '✓ Email sent!' : '✗ Failed — check SMTP config in .env';
      });
    }
    const slackBtn = document.getElementById('notifTestSlack');
    if (slackBtn) {
      const newSlackBtn = slackBtn.cloneNode(true);
      slackBtn.parentNode.replaceChild(newSlackBtn, slackBtn);
      newSlackBtn.addEventListener('click', async () => {
        const r = document.getElementById('notifSlackTestResult');
        if (r) r.textContent = '⏳ Sending…';
        const res = await fetch(API.notificationsTest, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({channel:'slack'})}).then(x=>x.json()).catch(()=>({}));
        if (r) r.textContent = res?.results?.slack ? '✓ Slack message sent!' : '✗ Failed — check SLACK_WEBHOOK_URL in .env';
      });
    }
  }

})();

// ── Case Management ───────────────────────────────────────────────────────────

let _currentCaseId = null;

async function loadCases() {
  const status   = document.getElementById('caseFilterStatus')?.value || '';
  const priority = document.getElementById('caseFilterPriority')?.value || '';
  const params   = new URLSearchParams();
  if (status)   params.set('status', status);
  if (priority) params.set('priority', priority);

  const res = await fetch(`/api/cases?${params}`).then(r => r.json()).catch(() => ({}));
  const cases = res.data || [];

  document.getElementById('caseKpiTotal').textContent         = res.total || 0;
  document.getElementById('caseKpiOpen').textContent          = res.open || 0;
  document.getElementById('caseKpiInvestigating').textContent = res.investigating || 0;
  document.getElementById('caseKpiResolved').textContent      = res.resolved || 0;

  const tbody = document.getElementById('casesTableBody');
  if (!tbody) return;

  if (!cases.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text-muted)">No cases found. Click <strong>+ New Case</strong> to create one.</td></tr>';
    return;
  }

  const priorityColor = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#6b7280' };
  const statusColor   = { open:'#f59e0b', investigating:'#3b82f6', resolved:'#10b981', closed:'#6b7280', false_positive:'#8b5cf6' };

  tbody.innerHTML = cases.map(c => `
    <tr style="cursor:pointer" onclick="openCaseDetail(${c.id})">
      <td style="color:var(--text-muted);font-size:12px">#${c.id}</td>
      <td><strong>${escHtml(c.title)}</strong></td>
      <td><span style="background:${statusColor[c.status]||'#666'}22;color:${statusColor[c.status]||'#aaa'};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase">${c.status}</span></td>
      <td><span style="color:${priorityColor[c.priority]||'#aaa'};font-size:12px;font-weight:600;text-transform:uppercase">${c.priority}</span></td>
      <td style="font-size:12px">${c.assignee || '—'}</td>
      <td style="font-size:12px">${c.note_count || 0}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtTs(c.created_at)}</td>
      <td>
        <button onclick="event.stopPropagation();openCaseDetail(${c.id})" style="background:var(--surface-2);border:1px solid var(--border);color:var(--text-primary);padding:3px 10px;border-radius:4px;font-size:11px;cursor:pointer">View</button>
        <button onclick="event.stopPropagation();confirmDeleteCase(${c.id})" style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#ef4444;padding:3px 10px;border-radius:4px;font-size:11px;cursor:pointer;margin-left:4px">Delete</button>
      </td>
    </tr>`).join('');
}

async function openCaseDetail(id) {
  _currentCaseId = id;
  const panel = document.getElementById('caseDetailPanel');
  panel.style.display = 'block';

  const res = await fetch(`/api/cases/${id}`).then(r => r.json()).catch(() => ({}));
  const c = res.data || {};

  const priorityColor = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#6b7280' };
  const statusColor   = { open:'#f59e0b', investigating:'#3b82f6', resolved:'#10b981', closed:'#6b7280', false_positive:'#8b5cf6' };

  document.getElementById('detailCaseId').textContent    = `Case #${c.id}  ·  Created ${fmtTs(c.created_at)}`;
  document.getElementById('detailCaseTitle').textContent = c.title || '';
  document.getElementById('detailCaseDesc').textContent  = c.description || '—';
  document.getElementById('detailCaseStatus').textContent  = c.status;
  document.getElementById('detailCaseStatus').style.cssText = `background:${statusColor[c.status]||'#666'}22;color:${statusColor[c.status]||'#aaa'};padding:3px 10px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase`;
  document.getElementById('detailCasePriority').textContent = c.priority;
  document.getElementById('detailCasePriority').style.cssText = `background:${priorityColor[c.priority]||'#666'}22;color:${priorityColor[c.priority]||'#aaa'};padding:3px 10px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase`;
  document.getElementById('detailCaseAssignee').textContent = c.assignee ? `Assigned to: ${c.assignee}` : 'Unassigned';
  document.getElementById('detailStatusSelect').value = c.status;

  const tagsRow = document.getElementById('detailCaseTagsRow');
  const tagsEl  = document.getElementById('detailCaseTags');
  if (c.tags && c.tags.length) {
    tagsEl.innerHTML = c.tags.map(t => `<span style="background:var(--surface-2);border:1px solid var(--border);padding:2px 8px;border-radius:4px;font-size:11px;margin-right:4px">${escHtml(t)}</span>`).join('');
    tagsRow.style.display = 'block';
  } else {
    tagsRow.style.display = 'none';
  }

  await loadCaseNotes(id);
  await loadCaseEvidence(id);
}

function closeCaseDetail() {
  document.getElementById('caseDetailPanel').style.display = 'none';
  _currentCaseId = null;
}

async function updateCaseStatus() {
  if (!_currentCaseId) return;
  const status = document.getElementById('detailStatusSelect').value;
  await fetch(`/api/cases/${_currentCaseId}`, {
    method: 'PUT',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({status})
  });
  await openCaseDetail(_currentCaseId);
  await loadCases();
}

async function loadCaseNotes(id) {
  const res = await fetch(`/api/cases/${id}/notes`).then(r => r.json()).catch(() => ({}));
  const notes = res.data || [];
  const el = document.getElementById('detailCaseNotes');
  if (!el) return;
  if (!notes.length) {
    el.innerHTML = '<div style="font-size:12px;color:var(--text-muted);font-style:italic">No notes yet.</div>';
    return;
  }
  el.innerHTML = notes.map(n => `
    <div style="background:var(--surface-2);border:1px solid var(--border);border-radius:6px;padding:10px 12px">
      <div style="display:flex;justify-content:space-between;margin-bottom:6px">
        <span style="font-size:11px;font-weight:600;color:var(--text-primary)">${escHtml(n.author||'System')}</span>
        <span style="font-size:11px;color:var(--text-muted)">${fmtTs(n.created_at)}</span>
      </div>
      <p style="margin:0;font-size:13px;color:var(--text-secondary);white-space:pre-wrap">${escHtml(n.content)}</p>
    </div>`).join('');
}

async function submitNote() {
  if (!_currentCaseId) return;
  const content = document.getElementById('newNoteContent')?.value?.trim();
  if (!content) return;
  await fetch(`/api/cases/${_currentCaseId}/notes`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({content})
  });
  document.getElementById('newNoteContent').value = '';
  await loadCaseNotes(_currentCaseId);
  await loadCases();
}

async function loadCaseEvidence(id) {
  const res = await fetch(`/api/cases/${id}/evidence`).then(r => r.json()).catch(() => ({}));
  const evidence = res.data || [];
  const el = document.getElementById('detailCaseEvidence');
  if (!el) return;
  if (!evidence.length) {
    el.innerHTML = '<div style="font-size:12px;color:var(--text-muted);font-style:italic">No evidence attached.</div>';
    return;
  }
  el.innerHTML = evidence.map(e => `
    <div style="background:var(--surface-2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;display:flex;gap:12px;align-items:flex-start">
      <span style="font-size:10px;background:var(--surface-3);border:1px solid var(--border);padding:2px 6px;border-radius:3px;text-transform:uppercase;color:var(--text-muted);white-space:nowrap">${e.type}</span>
      <div style="flex:1">
        <div style="font-size:12px;font-weight:600;color:var(--text-primary)">${escHtml(e.title)}</div>
        <div style="font-size:12px;color:var(--text-secondary);margin-top:2px">${escHtml(e.content)}</div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:4px">Added by ${escHtml(e.added_by||'—')} · ${fmtTs(e.added_at)}</div>
      </div>
    </div>`).join('');
}

async function submitEvidence() {
  if (!_currentCaseId) return;
  const title   = document.getElementById('newEvidenceTitle')?.value?.trim();
  const type    = document.getElementById('newEvidenceType')?.value || 'log';
  const content = document.getElementById('newEvidenceContent')?.value?.trim();
  if (!title || !content) return;
  await fetch(`/api/cases/${_currentCaseId}/evidence`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({title, type, content})
  });
  document.getElementById('newEvidenceTitle').value   = '';
  document.getElementById('newEvidenceContent').value = '';
  await loadCaseEvidence(_currentCaseId);
}

function showCreateCaseModal() {
  const m = document.getElementById('createCaseModal');
  if (m) m.style.display = 'flex';
}

function hideCreateCaseModal() {
  const m = document.getElementById('createCaseModal');
  if (m) {
    m.style.display = 'none';
    ['newCaseTitle','newCaseDesc','newCaseTags','newCaseAssignee'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
  }
}

async function submitCreateCase() {
  const title    = document.getElementById('newCaseTitle')?.value?.trim();
  const desc     = document.getElementById('newCaseDesc')?.value?.trim() || '';
  const priority = document.getElementById('newCasePriority')?.value || 'medium';
  const assignee = document.getElementById('newCaseAssignee')?.value?.trim() || '';
  const tagsRaw  = document.getElementById('newCaseTags')?.value?.trim() || '';
  const tags     = tagsRaw ? tagsRaw.split(',').map(t => t.trim()).filter(Boolean) : [];
  if (!title) { alert('Title is required'); return; }
  const res = await fetch('/api/cases', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({title, description:desc, priority, assignee, tags})
  }).then(r => r.json()).catch(() => ({}));
  hideCreateCaseModal();
  await loadCases();
  if (res?.data?.id) openCaseDetail(res.data.id);
}

async function confirmDeleteCase(id) {
  if (!confirm(`Delete case #${id}? This cannot be undone.`)) return;
  await fetch(`/api/cases/${id}`, {method:'DELETE'});
  if (_currentCaseId === id) closeCaseDetail();
  await loadCases();
}

function fmtTs(ms) {
  if (!ms) return '—';
  const d = new Date(ms);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
}

function escHtml(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="cases"]').forEach(el => {
    el.addEventListener('click', () => loadCases());
  });
  document.querySelectorAll('.nav-item[data-page="reports"]').forEach(el => {
    el.addEventListener('click', () => loadSchedules());
  });
});

// ── Scheduled Reports ─────────────────────────────────────────────────────────

async function loadSchedules() {
  const res = await fetch('/api/reports/schedules').then(r => r.json()).catch(() => ({}));
  const schedules = res.data || [];
  const el = document.getElementById('schedulesList');
  if (!el) return;

  if (!schedules.length) {
    el.innerHTML = '<div style="color:var(--text-muted);font-size:13px;font-style:italic">No scheduled reports. Click <strong>+ New Schedule</strong> to create one.</div>';
    return;
  }

  el.innerHTML = schedules.map(s => `
    <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border)">
      <div>
        <div style="font-weight:600;font-size:13px">${escHtml(s.name)}</div>
        <div style="font-size:12px;color:var(--text-muted);margin-top:2px">
          ${s.report_type} · ${s.frequency} · ${s.recipients?.join(', ')||'—'}
        </div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:2px">
          Last run: ${s.last_run ? new Date(s.last_run).toLocaleString() : 'Never'}
        </div>
      </div>
      <div style="display:flex;gap:8px">
        <button onclick="triggerReportNow('${s.id}')" style="background:var(--surface-2);border:1px solid var(--border);color:var(--text-primary);padding:4px 12px;border-radius:4px;font-size:11px;cursor:pointer">▶ Run Now</button>
        <button onclick="deleteSchedule('${s.id}')" style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#ef4444;padding:4px 12px;border-radius:4px;font-size:11px;cursor:pointer">Delete</button>
      </div>
    </div>`).join('');
}

function showScheduleModal() {
  const m = document.getElementById('scheduleModal');
  if (m) m.style.display = 'flex';
}

function hideScheduleModal() {
  const m = document.getElementById('scheduleModal');
  if (m) m.style.display = 'none';
}

async function submitSchedule() {
  const name       = document.getElementById('schName')?.value?.trim();
  const report_type = document.getElementById('schType')?.value || 'overview';
  const frequency  = document.getElementById('schFreq')?.value || 'daily';
  const hour       = parseInt(document.getElementById('schHour')?.value || '8');
  const day_of_week = document.getElementById('schDow')?.value || 'fri';
  const recipientsRaw = document.getElementById('schRecipients')?.value?.trim() || '';
  const recipients = recipientsRaw.split(',').map(r => r.trim()).filter(Boolean);

  if (!name) { alert('Name is required'); return; }
  if (!recipients.length) { alert('At least one recipient email is required'); return; }

  await fetch('/api/reports/schedules', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({name, report_type, frequency, recipients, hour, day_of_week})
  });
  hideScheduleModal();
  await loadSchedules();
}

async function deleteSchedule(id) {
  if (!confirm('Delete this schedule?')) return;
  await fetch(`/api/reports/schedules/${id}`, {method: 'DELETE'});
  await loadSchedules();
}

async function triggerReportNow(id) {
  await fetch(`/api/reports/schedules/${id}/run`, {method: 'POST'});
  alert('Report triggered — check your email shortly.');
}

// ── Risk-Based Alerting ───────────────────────────────────────────────────────

async function loadRbaPage() {
  await Promise.all([loadRbaEntities(), loadRbaNotables(), loadRbaWeights()]);
}

async function loadRbaEntities() {
  const res = await fetch('/api/rba/entities?limit=100').then(r => r.json()).catch(() => ({}));
  const entities = res.data || [];
  const tbody = document.getElementById('rbaEntitiesBody');
  if (!tbody) return;

  if (!entities.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:30px;color:var(--text-muted)">No risk data yet — alerts will accumulate risk scores automatically.</td></tr>';
    return;
  }

  tbody.innerHTML = entities.map(e => {
    const pct  = Math.min(100, Math.round(e.current_score / e.threshold * 100));
    const color = pct >= 100 ? '#ef4444' : pct >= 75 ? '#f97316' : pct >= 50 ? '#f59e0b' : '#10b981';
    const bar  = `<div style="display:flex;align-items:center;gap:8px">
      <div style="flex:1;height:6px;background:var(--surface-2);border-radius:3px;min-width:80px">
        <div style="width:${pct}%;height:100%;background:${color};border-radius:3px"></div>
      </div>
      <span style="font-size:11px;color:var(--text-muted)">${pct}%</span>
    </div>`;
    return `<tr>
      <td style="font-weight:600;font-size:12px">${escHtml(e.entity_id)}</td>
      <td><span style="font-size:18px;font-weight:700;color:${color}">${e.current_score}</span></td>
      <td style="font-size:12px;color:var(--text-muted)">${e.threshold}</td>
      <td style="min-width:120px">${bar}</td>
      <td style="font-size:12px">${e.alert_count_7d || '—'}</td>
      <td style="font-size:12px;color:${e.notables_fired > 0 ? '#ef4444' : 'var(--text-muted)'}">${e.notables_fired}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtTs(e.last_event)}</td>
    </tr>`;
  }).join('');
}

async function loadRbaNotables() {
  const res = await fetch('/api/rba/notables?limit=100').then(r => r.json()).catch(() => ({}));
  const notables = res.data || [];
  const tbody = document.getElementById('rbaNotablesBody');
  if (!tbody) return;

  if (!notables.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:30px;color:var(--text-muted)">No Risk Notables yet. They fire when an entity\'s accumulated risk score exceeds its threshold.</td></tr>';
    return;
  }

  tbody.innerHTML = notables.map(n => `
    <tr>
      <td style="font-size:12px;color:var(--text-muted)">#${n.id}</td>
      <td style="font-weight:600;font-size:12px">${escHtml(n.entity_id)}</td>
      <td><span style="font-size:16px;font-weight:700;color:#ef4444">${n.risk_score}</span></td>
      <td style="font-size:12px;color:var(--text-secondary);max-width:300px">${escHtml(n.description)}</td>
      <td style="font-size:12px">${n.case_id ? `<a href="#" onclick="event.preventDefault()" style="color:var(--accent)">Case #${n.case_id}</a>` : '—'}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtTs(n.created_at)}</td>
    </tr>`).join('');
}

async function loadRbaWeights() {
  const res = await fetch('/api/rba/weights').then(r => r.json()).catch(() => ({}));
  const weights = res.data || [];
  const tbody = document.getElementById('rbaWeightsBody');
  if (!tbody) return;

  if (!weights.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--text-muted)">No custom weights. All rules use level-derived defaults.</td></tr>';
    return;
  }

  tbody.innerHTML = weights.map(w => `
    <tr>
      <td style="font-size:12px">Rule #${w.rule_id}</td>
      <td style="font-weight:600;color:var(--accent)">${w.risk_weight} pts</td>
      <td style="font-size:12px;color:var(--text-muted)">${escHtml(w.description||'—')}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtTs(w.updated_at)}</td>
    </tr>`).join('');
}

function switchRbaTab(tab) {
  ['entities','notables','weights'].forEach(t => {
    const pane = document.getElementById(`rbaPaneEntities`.replace('entities', t === 'entities' ? 'entities' : `${t[0].toUpperCase()}${t.slice(1)}`));
    // manual mapping
  });
  const panes = { entities: 'rbaPaneEntities', notables: 'rbaPaneNotables', weights: 'rbaPaneWeights' };
  const tabs  = { entities: 'rbaTabEntities',  notables: 'rbaTabNotables',  weights: 'rbaTabWeights' };
  Object.entries(panes).forEach(([key, id]) => {
    const el = document.getElementById(id);
    if (el) el.style.display = key === tab ? '' : 'none';
  });
  Object.entries(tabs).forEach(([key, id]) => {
    const el = document.getElementById(id);
    if (el) {
      el.style.borderBottomColor = key === tab ? 'var(--accent)' : 'transparent';
      el.style.color = key === tab ? 'var(--text-primary)' : 'var(--text-muted)';
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="rba"]').forEach(el => {
    el.addEventListener('click', () => { loadRbaPage(); switchRbaTab('entities'); });
  });
});

// ── UEBA ─────────────────────────────────────────────────────────────────────

async function loadUebaPage() {
  await Promise.all([loadUebaRiskScores(), loadUebaAnomalies()]);
}

async function loadUebaRiskScores() {
  const res = await fetch('/api/ueba/risk-scores?limit=50').then(r => r.json()).catch(() => ({}));
  const scores = res.data || [];
  const tbody  = document.getElementById('uebaRiskTableBody');
  if (!tbody) return;

  if (!scores.length) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:30px;color:var(--text-muted)">
      No risk data yet. Click <strong>⟳ Run Analysis</strong> to compute baselines.
    </td></tr>`;
    return;
  }

  const riskColor = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };
  tbody.innerHTML = scores.map((s, i) => {
    const rc = riskColor[s.risk_level] || '#6b7280';
    const bar = `<div style="display:inline-block;width:${s.risk_score}px;max-width:100px;height:6px;background:${rc};border-radius:3px;vertical-align:middle"></div>`;
    return `<tr onclick="loadUebaEntity('${escHtml(s.entity_id)}')" style="cursor:pointer">
      <td style="font-size:12px;color:var(--text-muted)">#${i+1}</td>
      <td style="font-weight:600;font-size:12px">${escHtml(s.entity_id)}</td>
      <td style="font-size:11px;color:var(--text-muted)">${s.entity_type}</td>
      <td>
        ${bar}
        <span style="color:${rc};font-weight:600;font-size:13px;margin-left:8px">${s.risk_score}</span>
        <span style="background:${rc}22;color:${rc};padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;margin-left:4px;text-transform:uppercase">${s.risk_level}</span>
      </td>
      <td style="font-size:12px">${s.alert_count_7d}</td>
      <td style="font-size:12px;color:${s.critical_count_7d > 0 ? '#ef4444' : 'var(--text-muted)'}">${s.critical_count_7d}</td>
      <td style="font-size:12px;color:${s.anomaly_count_7d > 0 ? '#f59e0b' : 'var(--text-muted)'}">${s.anomaly_count_7d}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtTs(s.last_alert)}</td>
      <td>
        <button onclick="event.stopPropagation();loadUebaEntity('${escHtml(s.entity_id)}')" style="background:var(--surface-2);border:1px solid var(--border);color:var(--text-primary);padding:3px 10px;border-radius:4px;font-size:11px;cursor:pointer">Detail</button>
      </td>
    </tr>`;
  }).join('');
}

async function loadUebaAnomalies() {
  const res = await fetch('/api/ueba/anomalies?limit=100').then(r => r.json()).catch(() => ({}));
  const anomalies = res.data || [];
  const tbody = document.getElementById('uebaAnomalyTableBody');
  if (!tbody) return;

  if (!anomalies.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:30px;color:var(--text-muted)">No anomalies detected yet.</td></tr>';
    return;
  }

  const sevColor = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };
  const typeLabel = { alert_spike:'⚡ Alert Spike', critical_alert_burst:'🔴 Critical Burst', off_hours:'🌙 Off-Hours' };
  tbody.innerHTML = anomalies.map(a => `
    <tr>
      <td style="font-weight:600;font-size:12px">${escHtml(a.entity_id)}</td>
      <td style="font-size:12px">${typeLabel[a.anomaly_type] || escHtml(a.anomaly_type)}</td>
      <td style="font-size:12px;color:var(--text-secondary)">${escHtml(a.description)}</td>
      <td><span style="background:${sevColor[a.severity]||'#666'}22;color:${sevColor[a.severity]||'#aaa'};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase">${a.severity}</span></td>
      <td style="font-size:12px;font-weight:600;color:${sevColor[a.severity]||'#aaa'}">${a.score}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtTs(a.detected_at)}</td>
    </tr>`).join('');
}

async function loadUebaEntity(entityId) {
  const res = await fetch(`/api/ueba/entity/${encodeURIComponent(entityId)}`).then(r => r.json()).catch(() => ({}));
  const risk = res.risk;
  const anomalies = res.anomalies || [];

  const details = risk
    ? `Risk Score: ${risk.risk_score} (${risk.risk_level.toUpperCase()}) · ` +
      `Alerts 7d: ${risk.alert_count_7d} · Critical: ${risk.critical_count_7d} · Anomalies: ${risk.anomaly_count_7d}`
    : 'No risk data computed yet';

  const anomalyList = anomalies.length
    ? anomalies.map(a => `• ${a.anomaly_type}: ${a.description} (${a.severity})`).join('\n')
    : 'No anomalies detected.';

  alert(`Entity: ${entityId}\n\n${details}\n\nAnomalies:\n${anomalyList}`);
}

function switchUebaTab(tab) {
  const isRisk = tab === 'risk';
  document.getElementById('uebaPaneRisk').style.display      = isRisk ? '' : 'none';
  document.getElementById('uebaPaneAnomalies').style.display = isRisk ? 'none' : '';
  document.getElementById('uebaTabRisk').style.borderBottomColor      = isRisk ? 'var(--accent)' : 'transparent';
  document.getElementById('uebaTabRisk').style.color                  = isRisk ? 'var(--text-primary)' : 'var(--text-muted)';
  document.getElementById('uebaTabAnomalies').style.borderBottomColor = !isRisk ? 'var(--accent)' : 'transparent';
  document.getElementById('uebaTabAnomalies').style.color             = !isRisk ? 'var(--text-primary)' : 'var(--text-muted)';
}

async function triggerUebaAnalysis() {
  const btn = event?.target;
  if (btn) btn.textContent = 'Running…';
  const res = await fetch('/api/ueba/analyze', {method:'POST'}).then(r => r.json()).catch(() => ({}));
  if (btn) btn.textContent = '⟳ Run Analysis';
  if (res?.message) {
    setTimeout(() => loadUebaPage(), 3000); // reload after 3s for results
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="ueba"]').forEach(el => {
    el.addEventListener('click', () => { loadUebaPage(); switchUebaTab('risk'); });
  });
});

// ── Identity Management ───────────────────────────────────────────────────────

let _allIdentityUsers = [];

async function loadIdentityPage() {
  const dept    = document.getElementById('idFilterDept')?.value || '';
  const enabled = document.getElementById('idFilterEnabled')?.checked ? 'true' : '';

  const params = new URLSearchParams();
  if (dept)    params.set('department', dept);
  if (enabled) params.set('enabled', 'true');
  params.set('limit', '500');

  const [usersRes, statusRes] = await Promise.all([
    fetch(`/api/identity/users?${params}`).then(r => r.json()).catch(() => ({})),
    fetch('/api/identity/status').then(r => r.json()).catch(() => ({})),
  ]);

  _allIdentityUsers = usersRes.data || [];
  const total   = usersRes.total || 0;
  const enabled_count = usersRes.enabled || 0;

  document.getElementById('idKpiTotal').textContent   = total;
  document.getElementById('idKpiEnabled').textContent = enabled_count;
  document.getElementById('idKpiDisabled').textContent = Math.max(0, total - enabled_count);
  document.getElementById('idKpiLdap').textContent    = statusRes.ldap_configured ? 'Yes' : 'No';

  // Populate department filter
  const deptEl = document.getElementById('idFilterDept');
  if (deptEl) {
    const depts = [...new Set(_allIdentityUsers.map(u => u.department).filter(Boolean))].sort();
    const currentDept = deptEl.value;
    deptEl.innerHTML = '<option value="">All Departments</option>' +
      depts.map(d => `<option value="${escHtml(d)}"${d===currentDept?' selected':''}>${escHtml(d)}</option>`).join('');
  }

  filterIdentityUsers();
}

function filterIdentityUsers() {
  const search = (document.getElementById('idSearchInput')?.value || '').toLowerCase();
  const users  = search
    ? _allIdentityUsers.filter(u =>
        (u.sam_account||'').toLowerCase().includes(search) ||
        (u.display_name||'').toLowerCase().includes(search) ||
        (u.email||'').toLowerCase().includes(search))
    : _allIdentityUsers;

  const tbody = document.getElementById('identityTableBody');
  if (!tbody) return;

  if (!users.length) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:30px;color:var(--text-muted)">${search ? 'No matching users.' : 'No users found. Configure LDAP or add manually.'}</td></tr>`;
    return;
  }

  tbody.innerHTML = users.map(u => `
    <tr>
      <td style="font-weight:600;font-size:12px">${escHtml(u.sam_account)}</td>
      <td style="font-size:13px">${escHtml(u.display_name||'—')}</td>
      <td style="font-size:12px;color:var(--text-muted)">${escHtml(u.department||'—')}</td>
      <td style="font-size:12px;color:var(--text-muted)">${escHtml(u.title||'—')}</td>
      <td style="font-size:12px">${u.email ? `<a href="mailto:${escHtml(u.email)}" style="color:var(--accent)">${escHtml(u.email)}</a>` : '—'}</td>
      <td style="font-size:11px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml((u.groups||[]).join(', '))}">
        ${(u.groups||[]).slice(0,3).map(g => `<span style="background:var(--surface-2);border:1px solid var(--border);padding:1px 5px;border-radius:3px;margin-right:3px">${escHtml(g)}</span>`).join('')}
        ${u.groups?.length > 3 ? `<span style="color:var(--text-muted)">+${u.groups.length-3}</span>` : ''}
      </td>
      <td>
        <span style="background:${u.enabled ? '#10b98122':'#6b728022'};color:${u.enabled ? '#10b981':'#6b7280'};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">${u.enabled ? 'ENABLED':'DISABLED'}</span>
      </td>
      <td style="font-size:11px;color:var(--text-muted)">${u.source}</td>
      <td>
        <button onclick="deleteIdentityUser('${escHtml(u.sam_account)}')" style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#ef4444;padding:3px 10px;border-radius:4px;font-size:11px;cursor:pointer">Delete</button>
      </td>
    </tr>`).join('');
}

async function triggerLdapSync() {
  const btn = event?.target;
  if (btn) btn.textContent = 'Syncing…';
  const res = await fetch('/api/identity/sync', {method:'POST'}).then(r => r.json()).catch(() => ({}));
  if (btn) btn.textContent = '⟳ Sync LDAP';
  if (res?.message) {
    alert(`✓ ${res.message} (${res.total} total users)`);
    await loadIdentityPage();
  } else {
    alert(`✗ ${res?.error || 'Sync failed. Check LDAP configuration.'}`);
  }
}

async function deleteIdentityUser(sam) {
  if (!confirm(`Delete user ${sam}?`)) return;
  await fetch(`/api/identity/users/${encodeURIComponent(sam)}`, {method:'DELETE'});
  await loadIdentityPage();
}

function showAddUserModal() {
  ['newUserSam','newUserDisplay','newUserEmail','newUserDept','newUserTitle','newUserGroups']
    .forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  document.getElementById('addUserModal').style.display = 'flex';
}

function hideAddUserModal() {
  document.getElementById('addUserModal').style.display = 'none';
}

async function submitAddUser() {
  const sam = document.getElementById('newUserSam')?.value?.trim();
  if (!sam) { alert('Username is required'); return; }

  const groupsRaw = document.getElementById('newUserGroups')?.value?.trim() || '';
  const groups = groupsRaw ? groupsRaw.split(',').map(g => g.trim()).filter(Boolean) : [];

  await fetch('/api/identity/users', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      sam_account:  sam,
      display_name: document.getElementById('newUserDisplay')?.value?.trim() || '',
      email:        document.getElementById('newUserEmail')?.value?.trim() || '',
      department:   document.getElementById('newUserDept')?.value?.trim() || '',
      title:        document.getElementById('newUserTitle')?.value?.trim() || '',
      groups,
    })
  });
  hideAddUserModal();
  await loadIdentityPage();
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="identity"]').forEach(el => {
    el.addEventListener('click', () => loadIdentityPage());
  });
});

// ── Detection Studio (Rule Versioning) ───────────────────────────────────────

let _rvSelectedFile = null;
let _rvVersions     = [];

async function loadRuleVersionsPage() {
  const res = await fetch('/api/rule-versions').then(r => r.json()).catch(() => ({}));
  const files = res.data || [];
  const el = document.getElementById('rvFileList');
  if (!el) return;

  if (!files.length) {
    el.innerHTML = '<div style="padding:16px;color:var(--text-muted);font-size:12px;font-style:italic">No versioned rules found.<br>WatchTower auto-imports rules on startup.</div>';
    return;
  }

  el.innerHTML = files.map(f => `
    <div class="rv-file-item" onclick="selectRvFile('${escHtml(f.rule_file)}')"
         style="padding:10px 14px;cursor:pointer;border-bottom:1px solid var(--border);transition:background 0.1s"
         onmouseover="this.style.background='var(--surface-2)'" onmouseout="this.style.background=''">
      <div style="font-size:12px;font-weight:600;color:var(--text-primary)">${escHtml(f.rule_file)}</div>
      <div style="font-size:11px;color:var(--text-muted);margin-top:2px">
        v${f.latest_version} · ${f.version_count} version${f.version_count===1?'':'s'}
        · ${escHtml(f.last_author||'system')}
      </div>
    </div>`).join('');
}

async function selectRvFile(file) {
  _rvSelectedFile = file;
  document.getElementById('rvSelectedFile').textContent = file;
  document.getElementById('rvActionBar').style.display = 'flex';
  closeRvEditor();
  closeRvDiff();

  const res = await fetch(`/api/rule-versions/history?file=${encodeURIComponent(file)}`).then(r => r.json()).catch(() => ({}));
  _rvVersions = res.data || [];

  const pane = document.getElementById('rvVersionPane');
  if (!pane) return;

  if (!_rvVersions.length) {
    pane.innerHTML = '<div style="padding:20px;color:var(--text-muted);font-size:13px">No versions found.</div>';
    return;
  }

  pane.innerHTML = `
    <table class="data-table">
      <thead><tr><th>Version</th><th>Commit Message</th><th>Author</th><th>Date</th><th>Actions</th></tr></thead>
      <tbody>
        ${_rvVersions.map((v, i) => `
          <tr>
            <td style="font-size:12px;font-weight:600">
              v${v.version}
              ${i===0 ? '<span style="background:#10b98122;color:#10b981;padding:1px 6px;border-radius:3px;font-size:10px;margin-left:4px">LATEST</span>' : ''}
            </td>
            <td style="font-size:12px">${escHtml(v.commit_msg||'—')}</td>
            <td style="font-size:12px;color:var(--text-muted)">${escHtml(v.author||'—')}</td>
            <td style="font-size:12px;color:var(--text-muted)">${fmtTs(v.created_at)}</td>
            <td>
              <button onclick="rvViewContent('${escHtml(file)}',${v.version})" style="background:var(--surface-2);border:1px solid var(--border);color:var(--text-primary);padding:3px 10px;border-radius:4px;font-size:11px;cursor:pointer">View</button>
              ${i > 0 ? `<button onclick="rvRollback('${escHtml(file)}',${v.version})" style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);color:#f59e0b;padding:3px 10px;border-radius:4px;font-size:11px;cursor:pointer;margin-left:4px">Rollback</button>` : ''}
            </td>
          </tr>`).join('')}
      </tbody>
    </table>`;

  // Populate diff version selects
  const v1 = document.getElementById('rvDiffV1');
  const v2 = document.getElementById('rvDiffV2');
  if (v1 && v2) {
    const opts = _rvVersions.map(v => `<option value="${v.version}">v${v.version} — ${escHtml(v.commit_msg||'')}</option>`).join('');
    v1.innerHTML = opts;
    v2.innerHTML = opts;
    if (_rvVersions.length >= 2) v1.selectedIndex = 1;
  }
}

async function rvViewContent(file, version) {
  const res = await fetch(`/api/rule-versions/content?file=${encodeURIComponent(file)}&version=${version}`).then(r => r.json()).catch(() => ({}));
  const content = res.data?.content || '';
  document.getElementById('rvEditorContent').value = content;
  document.getElementById('rvCommitMsg').value = '';
  document.getElementById('rvValidationMsg').textContent = '';
  showRvEditor();
}

function showRvEditor() {
  document.getElementById('rvVersionPane').style.display = 'none';
  document.getElementById('rvEditorPane').style.display  = 'flex';
  document.getElementById('rvDiffPane').style.display    = 'none';
}

function closeRvEditor() {
  document.getElementById('rvVersionPane').style.display = 'block';
  document.getElementById('rvEditorPane').style.display  = 'none';
}

function showRvDiff() {
  document.getElementById('rvVersionPane').style.display = 'none';
  document.getElementById('rvEditorPane').style.display  = 'none';
  document.getElementById('rvDiffPane').style.display    = 'flex';
}

function closeRvDiff() {
  document.getElementById('rvVersionPane').style.display = 'block';
  document.getElementById('rvDiffPane').style.display    = 'none';
}

async function rvValidate() {
  const content = document.getElementById('rvEditorContent')?.value;
  const msgEl   = document.getElementById('rvValidationMsg');
  if (!content || !msgEl) return;

  msgEl.textContent = 'Validating…';
  const res = await fetch('/api/rule-versions/validate', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({content})
  }).then(r => r.json()).catch(() => ({}));

  if (res.valid) {
    msgEl.textContent = '✓ Valid Sigma YAML';
    msgEl.style.color = '#10b981';
  } else {
    msgEl.textContent = '✗ ' + (res.errors?.[0] || 'Invalid YAML');
    msgEl.style.color = '#ef4444';
  }
}

async function rvSaveVersion() {
  if (!_rvSelectedFile) return;
  const content   = document.getElementById('rvEditorContent')?.value;
  const commitMsg = document.getElementById('rvCommitMsg')?.value?.trim() || 'Manual update';
  if (!content) return;

  const res = await fetch('/api/rule-versions', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({file: _rvSelectedFile, content, commit_msg: commitMsg})
  }).then(r => r.json()).catch(() => ({}));

  if (res?.data?.version) {
    closeRvEditor();
    await selectRvFile(_rvSelectedFile);
    await loadRuleVersionsPage();
    alert(`✓ Saved as v${res.data.version}`);
  }
}

async function rvRollback(file, version) {
  if (!confirm(`Roll back ${file} to v${version}? This creates a new version with the old content.`)) return;
  const rv = await fetch(`/api/rule-versions/content?file=${encodeURIComponent(file)}&version=${version}`)
    .then(r => r.json()).catch(() => ({}));
  const content = rv.data?.content;
  if (!content) { alert('Could not fetch version content'); return; }

  const res = await fetch('/api/rule-versions', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({file, content, commit_msg: `Rollback to v${version}`})
  }).then(r => r.json()).catch(() => ({}));

  if (res?.data?.version) {
    await selectRvFile(file);
    await loadRuleVersionsPage();
    alert(`✓ Rolled back — saved as v${res.data.version}`);
  }
}

async function rvRunDiff() {
  if (!_rvSelectedFile) return;
  const v1 = parseInt(document.getElementById('rvDiffV1')?.value);
  const v2 = parseInt(document.getElementById('rvDiffV2')?.value);
  if (v1 === v2) { alert('Select two different versions to compare'); return; }

  const res = await fetch(`/api/rule-versions/diff?file=${encodeURIComponent(_rvSelectedFile)}&v1=${v1}&v2=${v2}`)
    .then(r => r.json()).catch(() => ({}));
  const diff = res.diff || [];
  const el   = document.getElementById('rvDiffContent');
  if (!el) return;

  if (!diff.length) {
    el.innerHTML = '<div style="color:var(--text-muted)">No differences found.</div>';
    return;
  }

  el.innerHTML = diff.filter(d => d.type !== 'equal' || Math.random() < 0.05).map(d => {
    const color  = d.type === 'added' ? '#10b981' : d.type === 'removed' ? '#ef4444' : 'var(--text-muted)';
    const prefix = d.type === 'added' ? '+ ' : d.type === 'removed' ? '- ' : '  ';
    return `<div style="color:${color};white-space:pre"><span style="user-select:none;color:var(--text-muted)">${String(d.line).padStart(4)} </span>${prefix}${escHtml(d.content)}</div>`;
  }).join('');
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="rule-versions"]').forEach(el => {
    el.addEventListener('click', () => loadRuleVersionsPage());
  });
});

// ── Ticketing Integration ─────────────────────────────────────────────────────

async function loadTicketingPage() {
  await Promise.all([loadTicketConfig(), loadTickets()]);
}

async function loadTicketConfig() {
  const res = await fetch('/api/tickets/config').then(r => r.json()).catch(() => ({}));
  const el = document.getElementById('ticketConfigStatus');
  if (!el) return;

  const providerLabel = { jira: 'Jira', servicenow: 'ServiceNow', none: 'None' };
  const label = providerLabel[res.provider] || res.provider;

  if (res.provider === 'none') {
    el.innerHTML = `<span style="color:#f59e0b">⚠ No provider configured. Set TICKETING_PROVIDER in .env</span>`;
    return;
  }

  const statusColor = res.configured ? '#10b981' : '#ef4444';
  const statusText  = res.configured ? '✓ Configured' : '✗ Missing credentials';
  const details = res.provider === 'jira'
    ? `URL: ${res.url || '—'} &nbsp;·&nbsp; Email: ${res.email || '—'} &nbsp;·&nbsp; Project: ${res.project || '—'}`
    : `URL: ${res.url || '—'} &nbsp;·&nbsp; User: ${res.username || '—'} &nbsp;·&nbsp; Table: ${res.table || '—'}`;

  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px">
      <span style="font-size:20px">${res.provider === 'jira' ? '🟦' : '🟩'}</span>
      <div>
        <div style="font-weight:600;font-size:13px">${label} <span style="color:${statusColor};font-size:12px">${statusText}</span></div>
        <div style="font-size:12px;color:var(--text-muted);margin-top:2px">${details}</div>
      </div>
    </div>`;
}

async function loadTickets() {
  const res = await fetch('/api/tickets').then(r => r.json()).catch(() => ({}));
  const tickets = res.data || [];
  const tbody = document.getElementById('ticketsTableBody');
  if (!tbody) return;

  if (!tickets.length) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:30px;color:var(--text-muted)">No tickets created yet.</td></tr>';
    return;
  }

  const priorityColor = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#6b7280' };
  const providerIcon  = { jira:'🟦', servicenow:'🟩' };

  tbody.innerHTML = tickets.map(t => `
    <tr>
      <td>
        ${t.ticket_url
          ? `<a href="${escHtml(t.ticket_url)}" target="_blank" style="color:var(--accent);font-weight:600;font-size:12px">${escHtml(t.ticket_id)}</a>`
          : `<span style="font-size:12px">${escHtml(t.ticket_id)}</span>`}
      </td>
      <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px">${escHtml(t.summary)}</td>
      <td><span style="color:${priorityColor[t.priority]||'#aaa'};font-size:11px;font-weight:600;text-transform:uppercase">${t.priority}</span></td>
      <td style="font-size:12px">${providerIcon[t.provider]||''} ${t.provider}</td>
      <td style="font-size:12px;color:var(--text-muted)">${t.alert_id ? '#'+t.alert_id : '—'}</td>
      <td style="font-size:12px;color:var(--text-muted)">${t.case_id  ? '#'+t.case_id  : '—'}</td>
      <td style="font-size:12px">${escHtml(t.created_by||'—')}</td>
      <td style="font-size:12px;color:var(--text-muted)">${t.created_at ? new Date(t.created_at).toLocaleString() : '—'}</td>
      <td>
        ${t.ticket_url ? `<a href="${escHtml(t.ticket_url)}" target="_blank" style="background:var(--surface-2);border:1px solid var(--border);color:var(--text-primary);padding:3px 10px;border-radius:4px;font-size:11px;text-decoration:none">Open ↗</a>` : ''}
      </td>
    </tr>`).join('');
}

async function testTicketConnection() {
  const btn = event?.target;
  if (btn) btn.textContent = 'Testing…';
  const res = await fetch('/api/tickets/test', {method:'POST'}).then(r => r.json()).catch(() => ({}));
  if (btn) btn.textContent = 'Test Connection';
  if (res?.data?.ticket_id) {
    alert(`✓ Success! Created test ticket: ${res.data.ticket_id}\nURL: ${res.data.ticket_url}`);
    await loadTickets();
  } else {
    alert(`✗ Failed: ${res?.error || 'Unknown error. Check provider credentials.'}`);
  }
}

function showCreateTicketModal(alertId, caseId, summary) {
  document.getElementById('ticketSummary').value  = summary || '';
  document.getElementById('ticketAlertId').value  = alertId || '';
  document.getElementById('ticketCaseId').value   = caseId  || '';
  document.getElementById('ticketPriority').value = 'medium';
  document.getElementById('ticketDesc').value     = '';
  document.getElementById('ticketModalStatus').textContent = '';
  document.getElementById('createTicketModal').style.display = 'flex';
}

function hideCreateTicketModal() {
  document.getElementById('createTicketModal').style.display = 'none';
}

async function submitCreateTicket() {
  const summary  = document.getElementById('ticketSummary')?.value?.trim();
  const desc     = document.getElementById('ticketDesc')?.value?.trim() || '';
  const priority = document.getElementById('ticketPriority')?.value || 'medium';
  const alertId  = parseInt(document.getElementById('ticketAlertId')?.value) || null;
  const caseId   = parseInt(document.getElementById('ticketCaseId')?.value)  || null;

  if (!summary) { alert('Summary is required'); return; }

  const statusEl = document.getElementById('ticketModalStatus');
  if (statusEl) statusEl.textContent = 'Creating ticket…';

  const res = await fetch('/api/tickets', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({summary, description: desc, priority, alert_id: alertId, case_id: caseId})
  }).then(r => r.json()).catch(() => ({}));

  if (res?.data?.ticket_id) {
    hideCreateTicketModal();
    await loadTickets();
    alert(`✓ Ticket created: ${res.data.ticket_id}\n${res.data.ticket_url}`);
  } else {
    if (statusEl) statusEl.textContent = `Error: ${res?.error || 'Failed to create ticket'}`;
    statusEl.style.color = '#ef4444';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="ticketing"]').forEach(el => {
    el.addEventListener('click', () => loadTicketingPage());
  });
});

// ── SOAR Playbooks ────────────────────────────────────────────────────────────

const ACTION_TEMPLATES = {
  block_ip:        { label: 'Block IP',            params: { ip: '{{src_ip}}' } },
  kill_process:    { label: 'Kill Process',         params: { pid: '{{pid}}' } },
  isolate_host:    { label: 'Isolate Host',         params: { reason: '{{title}}' } },
  create_case:     { label: 'Create Case',          params: { title: 'Auto: {{title}}', priority: 'high' } },
  create_ticket:   { label: 'Create Ticket',        params: { dashboard_url: 'http://dashboard:5050', summary: 'Alert L{{level}}: {{title}}', priority: 'high' } },
  notify_slack:    { label: 'Notify Slack',         params: { webhook_url: '', message: '🚨 [{{level}}] {{title}} — Agent: {{agent_id}}' } },
  notify_email:    { label: 'Send Email',           params: { to: '', subject: '[Alert] {{title}}' } },
  add_to_watchlist:{ label: 'Add to Watchlist',    params: { value: '{{src_ip}}', list: 'blocked_ips' } },
};

let _pbActions = [];

async function loadPlaybooks() {
  const res = await fetch('/api/playbooks?all=true').then(r => r.json()).catch(() => ({}));
  const pbs = res.data || [];
  const tbody = document.getElementById('playbooksTableBody');
  if (!tbody) return;

  if (!pbs.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:30px;color:var(--text-muted)">No playbooks yet. Click <strong>+ New Playbook</strong> to create one.</td></tr>';
    return;
  }

  tbody.innerHTML = pbs.map(pb => `
    <tr>
      <td style="color:var(--text-muted);font-size:12px">#${pb.id}</td>
      <td><strong>${escHtml(pb.name)}</strong><div style="font-size:11px;color:var(--text-muted)">${escHtml(pb.description||'')}</div></td>
      <td style="font-size:12px">Level ≥ ${pb.trigger?.min_level || 'any'}</td>
      <td style="font-size:12px">${(pb.actions||[]).length} actions</td>
      <td style="font-size:12px">${pb.run_count || 0}</td>
      <td>
        <span style="background:${pb.enabled ? '#10b98122':'#6b728022'};color:${pb.enabled ? '#10b981':'#6b7280'};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">${pb.enabled ? 'ENABLED':'DISABLED'}</span>
      </td>
      <td>
        <button onclick="viewPlaybookExecutions(${pb.id})" style="background:var(--surface-2);border:1px solid var(--border);color:var(--text-primary);padding:3px 10px;border-radius:4px;font-size:11px;cursor:pointer">History</button>
        <button onclick="togglePlaybook(${pb.id}, ${!pb.enabled})" style="background:var(--surface-2);border:1px solid var(--border);color:var(--text-primary);padding:3px 10px;border-radius:4px;font-size:11px;cursor:pointer;margin-left:4px">${pb.enabled ? 'Disable':'Enable'}</button>
        <button onclick="deletePlaybook(${pb.id})" style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#ef4444;padding:3px 10px;border-radius:4px;font-size:11px;cursor:pointer;margin-left:4px">Delete</button>
      </td>
    </tr>`).join('');
}

async function loadExecutions(playbookId) {
  const url = playbookId ? `/api/playbooks/${playbookId}/executions` : '/api/playbook-executions';
  const res = await fetch(url).then(r => r.json()).catch(() => ({}));
  const execs = res.data || [];
  const tbody = document.getElementById('executionsTableBody');
  if (!tbody) return;

  const statusColor = { success:'#10b981', failed:'#ef4444', partial:'#f59e0b', running:'#3b82f6' };
  if (!execs.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:30px;color:var(--text-muted)">No executions yet.</td></tr>';
    return;
  }
  tbody.innerHTML = execs.map(ex => {
    const dur = ex.completed_at && ex.started_at ? `${((ex.completed_at - ex.started_at)/1000).toFixed(1)}s` : '—';
    return `<tr>
      <td style="font-size:12px;color:var(--text-muted)">#${ex.id}</td>
      <td style="font-size:12px">#${ex.playbook_id}</td>
      <td style="font-size:12px">Alert #${ex.alert_id}</td>
      <td style="font-size:12px">${escHtml(ex.agent_id)}</td>
      <td><span style="background:${statusColor[ex.status]||'#666'}22;color:${statusColor[ex.status]||'#aaa'};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase">${ex.status}</span></td>
      <td style="font-size:12px">${dur}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtTs(ex.started_at)}</td>
    </tr>`;
  }).join('');
}

function switchPbTab(tab) {
  const isPlaybooks = tab === 'playbooks';
  document.getElementById('pbPanePlaybooks').style.display = isPlaybooks ? '' : 'none';
  document.getElementById('pbPaneHistory').style.display   = isPlaybooks ? 'none' : '';
  document.getElementById('pbTabPlaybooks').style.borderBottomColor = isPlaybooks ? 'var(--accent)' : 'transparent';
  document.getElementById('pbTabPlaybooks').style.color = isPlaybooks ? 'var(--text-primary)' : 'var(--text-muted)';
  document.getElementById('pbTabHistory').style.borderBottomColor = !isPlaybooks ? 'var(--accent)' : 'transparent';
  document.getElementById('pbTabHistory').style.color = !isPlaybooks ? 'var(--text-primary)' : 'var(--text-muted)';
  if (tab === 'history') loadExecutions(null);
}

function viewPlaybookExecutions(id) {
  switchPbTab('history');
  loadExecutions(id);
}

async function togglePlaybook(id, enabled) {
  await fetch(`/api/playbooks/${id}`, {
    method: 'PUT',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({enabled})
  });
  await loadPlaybooks();
}

async function deletePlaybook(id) {
  if (!confirm(`Delete playbook #${id}?`)) return;
  await fetch(`/api/playbooks/${id}`, {method: 'DELETE'});
  await loadPlaybooks();
}

function showPlaybookModal() {
  _pbActions = [];
  renderPlaybookActions();
  ['pbName','pbDesc','pbRuleIds','pbRuleGroups'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const lvl = document.getElementById('pbMinLevel');
  if (lvl) lvl.value = '10';
  document.getElementById('playbookModal').style.display = 'flex';
}

function hidePlaybookModal() {
  document.getElementById('playbookModal').style.display = 'none';
}

function addPlaybookAction() {
  _pbActions.push({ type: 'block_ip', params: {...ACTION_TEMPLATES.block_ip.params}, continue_on_failure: true, timeout_seconds: 30 });
  renderPlaybookActions();
}

function renderPlaybookActions() {
  const c = document.getElementById('pbActionsContainer');
  if (!c) return;
  if (!_pbActions.length) {
    c.innerHTML = '<div style="font-size:12px;color:var(--text-muted);font-style:italic">No actions yet. Click "Add Action".</div>';
    return;
  }
  c.innerHTML = _pbActions.map((action, i) => `
    <div style="background:var(--surface-1);border:1px solid var(--border);border-radius:6px;padding:10px 12px">
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
        <span style="font-size:11px;color:var(--text-muted);min-width:28px">${i+1}.</span>
        <select onchange="pbActionTypeChange(${i}, this.value)" style="background:var(--surface-2);border:1px solid var(--border);color:var(--text-primary);padding:4px 8px;border-radius:4px;font-size:12px">
          ${Object.entries(ACTION_TEMPLATES).map(([k,v]) => `<option value="${k}"${action.type===k?' selected':''}>${v.label}</option>`).join('')}
        </select>
        <label style="font-size:11px;color:var(--text-muted);display:flex;align-items:center;gap:4px;cursor:pointer">
          <input type="checkbox" ${action.continue_on_failure?'checked':''} onchange="_pbActions[${i}].continue_on_failure=this.checked"> Continue on fail
        </label>
        <button onclick="_pbActions.splice(${i},1);renderPlaybookActions()" style="background:none;border:none;color:#ef4444;cursor:pointer;font-size:14px;margin-left:auto">✕</button>
      </div>
      <div style="display:flex;flex-direction:column;gap:6px">
        ${Object.entries(action.params||{}).map(([k,v]) => `
          <div style="display:flex;gap:8px;align-items:center">
            <span style="font-size:11px;color:var(--text-muted);min-width:80px">${k}</span>
            <input value="${escHtml(v)}" oninput="_pbActions[${i}].params['${k}']=this.value" style="flex:1;background:var(--surface-2);border:1px solid var(--border);color:var(--text-primary);padding:4px 8px;border-radius:4px;font-size:11px">
          </div>`).join('')}
      </div>
    </div>`).join('');
}

function pbActionTypeChange(i, type) {
  _pbActions[i].type = type;
  _pbActions[i].params = {...(ACTION_TEMPLATES[type]?.params || {})};
  renderPlaybookActions();
}

async function submitPlaybook() {
  const name = document.getElementById('pbName')?.value?.trim();
  if (!name) { alert('Name is required'); return; }

  const minLevel = parseInt(document.getElementById('pbMinLevel')?.value || '10');
  const ruleIdsRaw = document.getElementById('pbRuleIds')?.value?.trim() || '';
  const ruleGroupsRaw = document.getElementById('pbRuleGroups')?.value?.trim() || '';

  const rule_ids = ruleIdsRaw ? ruleIdsRaw.split(',').map(s => parseInt(s.trim())).filter(Boolean) : [];
  const rule_groups = ruleGroupsRaw ? ruleGroupsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];

  const body = {
    name,
    description: document.getElementById('pbDesc')?.value?.trim() || '',
    enabled: true,
    trigger: { min_level: minLevel, rule_ids, rule_groups, agent_ids: [] },
    actions: _pbActions,
  };

  const res = await fetch('/api/playbooks', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(body)
  }).then(r => r.json()).catch(() => ({}));

  hidePlaybookModal();
  await loadPlaybooks();
  if (res?.data?.id) alert(`Playbook #${res.data.id} created successfully.`);
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="playbooks"]').forEach(el => {
    el.addEventListener('click', () => { loadPlaybooks(); switchPbTab('playbooks'); });
  });
});

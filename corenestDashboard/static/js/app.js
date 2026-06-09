// Utility functions used by both IIFE and outer module-level code
function escapeHtml(s) {
  if (s == null || s === '') return '';
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

const GEO_CONTINENTS = [
  "M 70 110 L 130 80 L 200 70 L 260 90 L 300 130 L 290 170 L 240 200 L 200 220 L 180 250 L 200 280 L 170 290 L 130 270 L 100 240 L 80 200 L 70 160 Z",
  "M 240 290 L 280 290 L 310 320 L 320 360 L 310 400 L 290 430 L 260 450 L 240 440 L 230 410 L 230 370 L 245 340 L 250 310 Z",
  "M 460 110 L 510 100 L 540 110 L 560 130 L 545 155 L 510 165 L 480 160 L 460 140 Z",
  "M 470 180 L 530 175 L 560 200 L 575 230 L 580 270 L 565 310 L 545 340 L 525 360 L 505 370 L 490 350 L 480 320 L 470 290 L 465 250 L 465 215 Z",
  "M 560 110 L 660 95 L 740 100 L 800 120 L 850 150 L 830 190 L 790 215 L 740 230 L 700 240 L 680 220 L 650 215 L 620 210 L 590 195 L 575 170 L 565 140 Z",
  "M 660 220 L 700 240 L 720 270 L 705 285 L 690 290 L 670 280 L 660 260 Z",
  "M 720 290 L 770 295 L 800 300 L 815 310 L 800 320 L 765 315 L 735 310 L 720 305 Z",
  "M 800 360 L 870 360 L 900 380 L 905 410 L 880 425 L 830 420 L 805 405 L 795 380 Z",
  "M 360 50 L 410 50 L 420 70 L 405 90 L 380 95 L 360 80 Z",
  "M 440 100 L 455 95 L 458 110 L 446 116 L 437 110 Z",
  "M 840 145 L 855 145 L 860 165 L 850 175 L 840 170 Z",
];

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
    syslogDecoders: '/api/decoders/syslog',
    syslogDecodersTest: '/api/decoders/syslog/test',
    syslogDecodersReload: '/api/decoders/syslog/reload',
    indexerManagementIndices: '/api/indexer/management/indices',
    mitreTactics: '/api/alerts/by-tactic',
    mitreMatrix: '/api/mitre/matrix',
    fimSummary: '/api/fim/summary',
    fimEvents: '/api/fim/events',
    auditSummary: '/api/audit/summary',
    auditEvents: '/api/audit/events',
    logsSearch: '/api/logs/search',
    logsSummary: '/api/logs/summary',
    cfgAuditLog:   '/api/admin/audit-log',
    cfgAuditStats: '/api/admin/audit-log/stats',
    logFilters:    '/api/admin/filters',
    silentSources: '/api/silent-sources',
    silentThresh:  '/api/silent-sources/thresholds',
    silentRunNow:  '/api/silent-sources/run-now',
    users:         '/api/users',
    corrIncidents: '/api/correlations/incidents',
    socEngineers: '/api/soc/engineers',
    socShifts: '/api/soc/shifts',
    caseMetrics: '/api/cases/metrics',
    fpStats: '/api/cases/fp-stats',
    corrRunNow:    '/api/correlations/run-now',
    sysLogsList:   '/api/admin/system-logs/services',
    sysLogsRead:   '/api/admin/system-logs',
    retention:     '/api/admin/retention',
    retentionPurge:'/api/admin/retention/purge',
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
    'agent-detail': { title: 'Node Detail', desc: 'Full detail for a single WatchNode agent' },
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
    'compliance-hub': { title: 'Compliance Hub', desc: 'ISO 27001, NIST CSF, SOC 2, HIPAA, PCI-DSS posture' },
    cases: { title: 'Case Management', desc: 'Investigate, track, and resolve security incidents' },
    playbooks: { title: 'SOAR Playbooks', desc: 'Automated response workflows for security events' },
    ueba: { title: 'UEBA', desc: 'User and Entity Behavior Analytics — anomaly detection' },
    rba: { title: 'Risk-Based Alerting', desc: 'Entity risk scoring and notable events' },
    'geo-map': { title: 'Geo Threat Map', desc: 'Geographic visualization of threat sources' },
    'cloud-monitoring': { title: 'Cloud Monitoring', desc: 'AWS, Azure, and GCP event ingestion and status' },
    'rule-versions': { title: 'Detection Studio', desc: 'Rule versioning, diff, and validation' },
    identity: { title: 'Identity', desc: 'User identity inventory and risk tracking' },
    ticketing: { title: 'Ticketing', desc: 'Jira and ServiceNow integration for alert escalation' },
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
  // Convert a time-range token into ISO bounds.
  // Supported tokens:
  //   "15m" "1h" "3h" "24h" "7d" "30d"                 — rolling windows
  //   "custom:<fromISO>:<toISO>"                       — absolute range
  // Backwards-compat: also returns .time_from / .time_to / .days / .from / .to.
  function getTimeRangeBounds(range) {
    const now = new Date();
    let start = new Date(now);
    let days  = 1;
    if (typeof range === 'string' && range.startsWith('custom:')) {
      const parts = range.split(':');
      // ISO timestamps may themselves contain ':' so re-join everything after the
      // first two splits as the end of the second ISO string.
      // Format: "custom:<fromISO>:<toISO>"  — both ISO strings end in "Z".
      const m = range.match(/^custom:([^|]+)\|(.+)$/);
      let fromStr = null, toStr = null;
      if (m) { fromStr = m[1]; toStr = m[2]; }
      else {
        // Tolerate the older colon-joined form by finding the boundary 'Z|2'.
        // Falls back to the now ± 24h window if parsing fails.
        const idx = range.indexOf('Z:', 'custom:'.length);
        if (idx > 0) {
          fromStr = range.slice('custom:'.length, idx + 1);
          toStr   = range.slice(idx + 2);
        }
      }
      const f = fromStr ? new Date(fromStr) : null;
      const t = toStr   ? new Date(toStr)   : null;
      if (f && !isNaN(f) && t && !isNaN(t) && t > f) {
        days = Math.max(1, Math.round((t - f) / 86400000));
        return {
          time_from: f.toISOString().slice(0, 19) + 'Z',
          time_to:   t.toISOString().slice(0, 19) + 'Z',
          from:      f.toISOString().slice(0, 19) + 'Z',
          to:        t.toISOString().slice(0, 19) + 'Z',
          days,
        };
      }
      // Malformed custom range → fall through to defaults.
    }
    if (range === '15m')      start.setMinutes(now.getMinutes() - 15);
    else if (range === '1h')  start.setHours(now.getHours() - 1);
    else if (range === '3h')  start.setHours(now.getHours() - 3);
    else if (range === '24h') { start.setHours(now.getHours() - 24); days = 1; }
    else if (range === '7d')  { start.setDate(now.getDate() - 7);   days = 7; }
    else if (range === '30d') { start.setDate(now.getDate() - 30);  days = 30; }
    else                      { start.setDate(now.getDate() - 7);   days = 7; }
    const iso = d => d.toISOString().slice(0, 19) + 'Z';
    return {
      time_from: iso(start),
      time_to:   iso(now),
      from:      iso(start),
      to:        iso(now),
      days,
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
    // Drill-down pages keep their parent nav item highlighted.
    const NAV_PARENT = { 'agent-detail': 'agents' };
    const navId = NAV_PARENT[pageId] || pageId;
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-page') === navId);
    });
    document.querySelectorAll('.nav-tab').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-page') === navId);
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
      const el   = document.getElementById('headerUtc');
      const el2  = document.getElementById('tb2Clock');
      const hh = String(h).padStart(2,'0'), mm = String(m).padStart(2,'0'), ss = String(s).padStart(2,'0');
      if (el)  el.textContent  = `${day} ${month} ${year} ${hh}:${mm}`;
      if (el2) el2.textContent = `${hh}:${mm}:${ss}`;
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
    const colW = 'grid-template-columns:120px 130px 90px 120px 1fr 70px 100px';
    if (!vulns || vulns.length === 0) return `<div class="sigil-block"><div class="sigil" style="background:radial-gradient(circle,rgba(45,212,191,0.08),transparent 70%);color:var(--accent)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" width="32" height="32"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg></div><div class="sigil-text"><h4>No vulnerabilities found</h4><p>Enable vulnerability scanning on your agents to populate CVE data. Scans run on a schedule and emit CVE alerts when new advisories drop.</p></div><div style="flex:1"></div><button class="act-btn" onclick="goToPage('agents')"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M2 12h2M20 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg> Configure scanning</button></div>`;
    return vulns.map(v => {
      const detected = v.detected_at ? new Date(v.detected_at).toLocaleDateString(undefined, { day: '2-digit', month: '2-digit', year: '2-digit' }) : '—';
      const pkg = [v.package_name, v.package_version].filter(Boolean).join(' @ ') || '—';
      const score = v.score_base != null ? Number(v.score_base).toFixed(1) : '—';
      const sev = (v.severity || '').toLowerCase();
      const sevCol = sev.includes('critical') ? 'var(--crit)' : sev === 'high' ? 'var(--high)' : sev === 'medium' ? 'var(--med)' : 'var(--low)';
      const sevPillCls = sev.includes('critical') ? 'crit' : sev === 'high' ? 'high' : sev === 'medium' ? 'med' : 'low';
      return `<div class="tbl-r" style="${colW}">
        <span class="tbl-time">${escapeHtml(detected)}</span>
        <span class="tbl-mono" style="color:var(--accent)">${escapeHtml(v.vuln_id || '—')}</span>
        <span><span class="pill ${sevPillCls}">${escapeHtml(v.severity || '—')}</span></span>
        <span class="tbl-mono">${escapeHtml((v.agent_name || v.agent_id || '—').slice(0,16))}</span>
        <span class="tbl-pri">${escapeHtml(pkg.slice(0,50))}</span>
        <span style="font-family:var(--font-mono);font-weight:600;color:${sevCol}">${escapeHtml(score)}</span>
        <span class="tbl-muted">—</span>
      </div>`;
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
    const colors = ['#F25555', '#F59E0B', '#34D399', '#2DD4BF', '#bc8cff'];
    let maxVal = 0;
    series.forEach(s => (s.buckets || []).forEach(b => { if (b.doc_count > maxVal) maxVal = b.doc_count; }));
    maxVal = Math.max(1, maxVal);
    const stepX = series.length > 1 ? chartW / (series.length - 1) : chartW;
    ctx.fillStyle = '#08090b';
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

  function drawTimeline(canvasId, timeline24h, demoTrend) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const container = canvas.parentElement;
    const w = (container ? container.clientWidth : canvas.offsetWidth) || 500;
    const h = 180;
    canvas.style.width  = w + 'px';
    canvas.style.height = h + 'px';
    canvas.width  = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    ctx.scale(dpr, dpr);

    const isDark   = document.documentElement.getAttribute('data-theme') !== 'light';
    const bg       = isDark ? '#0f1115' : '#ffffff';
    const gridCol  = isDark ? 'rgba(255,255,255,0.055)' : 'rgba(0,0,0,0.07)';
    const textCol  = isDark ? '#5E6068' : '#9ca3af';
    const P        = { t:14, r:12, b:24, l:32 };
    const cW = w - P.l - P.r;
    const cH = h - P.t - P.b;

    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, w, h);

    // Normalise data: accept {crit,high,med,low}[] (demo) or {key,count}[] (real API)
    let series;
    if (demoTrend && demoTrend.length > 0 && demoTrend[0].crit !== undefined) {
      series = demoTrend;
    } else if (timeline24h && timeline24h.length > 0 && timeline24h[0].crit !== undefined) {
      series = timeline24h;
    } else if (timeline24h && timeline24h.length > 0) {
      // Old format: convert single-count to low series
      series = timeline24h.map(b => ({ crit:0, high:0, med:0, low: b.count || 0 }));
    } else {
      series = [];
    }

    const n   = series.length || 1;
    const stepX = cW / (n - 1 || 1);
    const maxVal = Math.max(...series.map(d => (d.crit||0)+(d.high||0)+(d.med||0)+(d.low||0)), 1);

    // Grid lines
    ctx.strokeStyle = gridCol;
    ctx.lineWidth   = 0.8;
    ctx.setLineDash([2, 3]);
    [0, 0.25, 0.5, 0.75, 1].forEach((p, i) => {
      const y = P.t + cH * (1 - p);
      ctx.beginPath(); ctx.moveTo(P.l, y); ctx.lineTo(P.l + cW, y); ctx.stroke();
    });
    ctx.setLineDash([]);

    // Y labels
    ctx.fillStyle = textCol;
    ctx.font = `9px 'Geist Mono','JetBrains Mono',monospace`;
    ctx.textAlign = 'right';
    [0, 0.5, 1].forEach(p => {
      ctx.fillText(Math.round(maxVal * p), P.l - 4, P.t + cH * (1 - p) + 3);
    });

    if (series.length === 0) {
      ctx.fillStyle = textCol;
      ctx.textAlign = 'center';
      ctx.font = `11px 'Geist',system-ui,sans-serif`;
      ctx.fillText('no events in the last 24 hours · system quiet', P.l + cW / 2, P.t + cH / 2 + 4);
      return;
    }

    // Stacked area — draw from bottom (low) to top (crit)
    const sevLayers = [
      { key: 'low',  color: isDark ? '#38BDF8' : '#3b82f6', opacity: 0.22, strokeOpacity: 0.9 },
      { key: 'med',  color: '#EAB308', opacity: 0.22, strokeOpacity: 0.9 },
      { key: 'high', color: '#F59E0B', opacity: 0.22, strokeOpacity: 0.9 },
      { key: 'crit', color: '#F25555', opacity: 0.22, strokeOpacity: 0.9 },
    ];

    const xAt = i => P.l + i * stepX;
    const yAt = v => P.t + cH - (v / maxVal) * cH;

    sevLayers.forEach(({ key, color, opacity, strokeOpacity }) => {
      const topVals  = series.map(d => (d.crit||0) + (d.high||0) + (d.med||0) + (d.low||0));
      const baseVals = series.map(d => {
        let base = 0;
        if (key === 'med')  base = d.low||0;
        if (key === 'high') base = (d.low||0) + (d.med||0);
        if (key === 'crit') base = (d.low||0) + (d.med||0) + (d.high||0);
        return base + (d[key]||0);
      });
      const bVals = series.map(d => {
        if (key === 'low')  return 0;
        if (key === 'med')  return d.low||0;
        if (key === 'high') return (d.low||0) + (d.med||0);
        return (d.low||0) + (d.med||0) + (d.high||0);
      });

      // Area
      ctx.beginPath();
      series.forEach((_, i) => {
        const x = xAt(i), y = yAt(baseVals[i]);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      for (let i = series.length - 1; i >= 0; i--) {
        ctx.lineTo(xAt(i), yAt(bVals[i]));
      }
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.globalAlpha = opacity;
      ctx.fill();
      ctx.globalAlpha = 1;

      // Stroke
      ctx.beginPath();
      series.forEach((_, i) => {
        const x = xAt(i), y = yAt(baseVals[i]);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = color;
      ctx.globalAlpha = strokeOpacity;
      ctx.lineWidth = 1.2;
      ctx.lineJoin = 'round';
      ctx.stroke();
      ctx.globalAlpha = 1;
    });

    // X-axis labels
    ctx.fillStyle = textCol;
    ctx.textAlign = 'center';
    ctx.font = `9px 'Geist Mono','JetBrains Mono',monospace`;
    const labels = ['00:00','04:00','08:00','12:00','16:00','20:00','now'];
    labels.forEach((lbl, li) => {
      const x = P.l + (li / (labels.length - 1)) * cW;
      ctx.fillText(lbl, x, P.t + cH + 16);
    });
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
      { label: 'Active', count: active, color: '#34D399' },
      { label: 'Disconnected', count: disconnected, color: '#F25555' },
      { label: 'Pending', count: pending, color: '#F59E0B' },
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
    ctx.fillStyle = '#0f1115';
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
    const colors = ['#F25555', '#F59E0B', '#2DD4BF', '#34D399', '#bc8cff', '#56d4dd'];
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
    ctx.fillStyle = '#0f1115';
    ctx.fill();
    legendEl.innerHTML = mitreList.map((m, i) =>
      `<span style="color:${colors[i % colors.length]}">■</span> ${escapeHtml(String(m.technique).slice(0, 25))} (${m.pct}%)`
    ).join('<br>');
  }

  function drawThreatSummaryDonut(canvasId, centerId, legendId, sev24, demoData) {
    const canvas    = document.getElementById(canvasId);
    const centerEl  = document.getElementById(centerId);
    const legendEl  = document.getElementById(legendId);
    if (!canvas) return;
    const isDark    = document.documentElement.getAttribute('data-theme') !== 'light';
    const trackCol  = isDark ? '#1a1d23' : '#e5e7eb';
    const holeBg    = isDark ? '#0f1115' : '#ffffff';
    const src       = demoData || sev24 || {};
    const segs = [
      { label:'Critical', count: src.critical ?? 0, color:'#F25555' },
      { label:'High',     count: src.high     ?? 0, color:'#F59E0B' },
      { label:'Medium',   count: src.medium   ?? 0, color:'#EAB308' },
      { label:'Low',      count: src.low      ?? 0, color:'#38BDF8' },
    ];
    const total = segs.reduce((s, x) => s + x.count, 0);
    if (centerEl) centerEl.textContent = total;

    const dpr   = window.devicePixelRatio || 1;
    const size  = 92;
    canvas.width = canvas.height = Math.round(size * dpr);
    canvas.style.width = canvas.style.height = size + 'px';
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    const cx = size / 2, cy = size / 2;
    const r  = size / 2 - 3;
    const thickness = 11;

    // Track
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, 2 * Math.PI);
    ctx.lineWidth = thickness;
    ctx.strokeStyle = trackCol;
    ctx.stroke();

    if (total === 0) {
      if (legendEl) legendEl.innerHTML = `
        <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--d-fg-3)">
          <span style="width:10px;height:10px;border-radius:50%;background:${trackCol};display:inline-block"></span>No alerts · 24h
        </div>`;
      return;
    }

    // Arcs
    let start = -Math.PI / 2;
    segs.filter(s => s.count > 0).forEach(seg => {
      const slice = (seg.count / total) * 2 * Math.PI;
      ctx.beginPath();
      ctx.arc(cx, cy, r, start, start + slice);
      ctx.lineWidth = thickness;
      ctx.strokeStyle = seg.color;
      ctx.stroke();
      start += slice;
    });

    // Hole label
    const sub = document.querySelector('#threatSummaryTotal + span') || null;

    if (legendEl) {
      legendEl.innerHTML = segs.filter(s => s.count > 0).map(s => `
        <div style="display:flex;align-items:center;justify-content:space-between;font-size:11.5px;gap:8px">
          <span style="display:flex;align-items:center;gap:6px;color:var(--d-fg-2)">
            <span style="width:10px;height:10px;border-radius:2px;background:${s.color};display:inline-block;flex-shrink:0"></span>
            ${s.label}
          </span>
          <span style="font-family:var(--d-font-mono,monospace);color:var(--d-fg);font-weight:500">${s.count}</span>
        </div>`).join('');
    }
  }

  function drawAgentsSummaryDonut(canvasId, legendId, summary) {
    const canvas   = document.getElementById(canvasId);
    if (!canvas) return;
    const isDark   = document.documentElement.getAttribute('data-theme') !== 'light';
    const trackCol = isDark ? '#1a1d23' : '#e5e7eb';
    const active       = summary?.active ?? summary?.connected ?? 0;
    const disconnected = summary?.disconnected ?? 0;
    const pending      = summary?.pending ?? 0;
    const never        = summary?.never_connected ?? 0;
    const total        = active + disconnected + pending + never;
    if (total === 0) return;

    const segs = [
      { label:'Active',       count: active,       color:'#34D399' },
      { label:'Disconnected', count: disconnected,  color:'#F25555' },
      { label:'Pending',      count: pending,       color:'#F59E0B' },
      { label:'Never',        count: never,         color:'#5E6068'  },
    ].filter(s => s.count > 0);

    const dpr  = window.devicePixelRatio || 1;
    const size = 92;
    canvas.width = canvas.height = Math.round(size * dpr);
    canvas.style.width = canvas.style.height = size + 'px';
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    const cx = size / 2, cy = size / 2, r = size / 2 - 3;
    const thickness = 11;

    ctx.beginPath(); ctx.arc(cx, cy, r, 0, 2 * Math.PI);
    ctx.lineWidth = thickness; ctx.strokeStyle = trackCol; ctx.stroke();

    let start = -Math.PI / 2;
    segs.forEach(seg => {
      const slice = (seg.count / total) * 2 * Math.PI;
      ctx.beginPath(); ctx.arc(cx, cy, r, start, start + slice);
      ctx.lineWidth = thickness; ctx.strokeStyle = seg.color; ctx.stroke();
      start += slice;
    });

    // Center overlay: show pct
    const legendEl = document.getElementById(legendId);
    const pct      = total > 0 ? Math.round((active / total) * 100) : 0;
    if (legendEl) {
      legendEl.innerHTML = `
        <div style="font-size:16px;font-weight:700;font-family:var(--d-font-mono,monospace);color:var(--d-fg,#ECEDEE);line-height:1">${pct}%</div>
        <div style="font-size:10px;color:var(--d-fg-4,#5E6068);margin-top:2px">${active}/${total} healthy</div>`;
    }

    // Side legend
    const sideEl = document.getElementById('agentsDonutSideLegend');
    if (sideEl) {
      sideEl.innerHTML = segs.map(s => `
        <div style="display:flex;align-items:center;justify-content:space-between;gap:6px">
          <span style="display:flex;align-items:center;gap:5px;font-size:11px;color:var(--d-fg-2,#B4B6BD)">
            <span style="width:8px;height:8px;border-radius:50%;background:${s.color};display:inline-block;flex-shrink:0"></span>
            ${s.label}
          </span>
          <span style="font-family:var(--d-font-mono,monospace);font-size:11px;color:var(--d-fg,#ECEDEE)">${s.count}</span>
        </div>`).join('');
    }
  }


  // ── sparkline SVG builder ─────────────────────────────────────────
  function buildSparklineSVG(data, color, w=70, h=22) {
    if (!data || !data.length) {
      return `<svg width="${w}" height="${h}"><line x1="0" y1="${h/2}" x2="${w}" y2="${h/2}" stroke="#3F4147" stroke-width="1" stroke-dasharray="2 3"/></svg>`;
    }
    const flat = data.every(v => v === data[0]);
    if (flat && data[0] === 0) {
      return `<svg width="${w}" height="${h}"><line x1="0" y1="${h/2}" x2="${w}" y2="${h/2}" stroke="#3F4147" stroke-width="1" stroke-dasharray="2 3"/></svg>`;
    }
    const min = Math.min(...data), max = Math.max(...data);
    const range = max - min || 1;
    const stepX = w / (data.length - 1 || 1);
    const pts = data.map((v, i) => [i * stepX, h - 2 - ((v - min) / range) * (h - 4)]);
    const pathD = pts.map((p, i) => (i === 0 ? `M${p[0].toFixed(1)},${p[1].toFixed(1)}` : `L${p[0].toFixed(1)},${p[1].toFixed(1)}`)).join(' ');
    const areaD = `${pathD} L${w},${h} L0,${h} Z`;
    const gid = `sg${Math.random().toString(36).slice(2,7)}`;
    return `<svg width="${w}" height="${h}" style="display:block">
      <defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="${color}" stop-opacity="0.28"/>
        <stop offset="100%" stop-color="${color}" stop-opacity="0"/>
      </linearGradient></defs>
      <path d="${areaD}" fill="url(#${gid})"/>
      <path d="${pathD}" fill="none" stroke="${color}" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
  }

  function _ov2SetKpi(ids, kpi, isDemo) {
    const { value, sub, tag, tagKind, spark, sparkColor } = kpi;
    const valEl  = document.getElementById(ids.val);
    const subEl  = document.getElementById(ids.sub);
    const tagEl  = document.getElementById(ids.tag);
    const spkEl  = document.getElementById(ids.spark);
    if (valEl)  valEl.textContent  = value;
    if (subEl)  subEl.textContent  = sub;
    if (tagEl) { tagEl.textContent = tag; tagEl.className = `ov2-kpi-tag ${tagKind||''}`; }
    if (spkEl)  spkEl.innerHTML    = buildSparklineSVG(spark, sparkColor||'#38BDF8');
    if (valEl && tagKind === 'crit') valEl.classList.add('crit'); else if (valEl) valEl.classList.remove('crit');
  }

  function _ov2RenderSourceRow(r, i, maxCount) {
    const pct = Math.min(100, (r.count / maxCount) * 100);
    const sev = r.sev || 'low';
    const barCls = sev === 'crit' ? '' : sev === 'high' ? 'high' : sev === 'med' ? 'med' : 'low';
    return `<div class="ov2-row">
      <span class="ov2-row-num">${i+1}</span>
      <div class="ov2-row-main">
        <span class="ov2-row-pri mono mono">${escapeHtml(r.ip||r.source||'—')}</span>
        <span class="ov2-row-sec">${escapeHtml(r.asn||'')}</span>
      </div>
      <div class="ov2-row-bar"><div class="ov2-row-bar-fill ${barCls}" style="width:${pct}%"></div></div>
      <span class="ov2-row-meta ${sev === 'crit' ? 'crit' : sev === 'high' ? 'high' : ''}">${(r.count||0).toLocaleString()}</span>
    </div>`;
  }

  function _ov2RenderAgentRiskRow(r, i, maxScore) {
    const pct = Math.min(100, ((r.score||r.risk_score||0) / (maxScore||1)) * 100);
    const score = r.score || r.risk_score || 0;
    const sev = score >= 80 ? 'crit' : score >= 60 ? 'high' : score >= 40 ? 'med' : 'low';
    return `<div class="ov2-row">
      <span class="ov2-row-num">${i+1}</span>
      <div class="ov2-row-main">
        <span class="ov2-row-pri mono mono">${escapeHtml(r.host||r.name||'—')}</span>
        <span class="ov2-row-sec">risk score</span>
      </div>
      <div class="ov2-row-bar"><div class="ov2-row-bar-fill ${sev === 'crit' ? '' : sev}" style="width:${pct}%"></div></div>
      <span class="ov2-row-meta ${sev === 'crit' ? 'crit' : sev === 'high' ? 'high' : ''}">${score}</span>
    </div>`;
  }

  function _ov2RenderMitre(mitreList) {
    const grid = document.getElementById('ov2MitreHeatmap');
    const leg  = document.getElementById('mitreLegend');
    if (!grid) return;
    if (!mitreList || !mitreList.length) {
      grid.innerHTML = '';
      leg.innerHTML  = `<div class="ov2-empty" style="padding:14px 0 18px">
        <div class="ov2-empty-icon info"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="9"/><path d="m16 8-6 2-2 6 6-2 2-6z"/></svg></div>
        <div class="ov2-empty-msg">No tactic coverage data</div>
        <div class="ov2-empty-sub">Rules will populate this view as detections fire</div>
      </div>`;
      return;
    }
    grid.innerHTML = mitreList.map(c =>
      `<div class="ov2-mitre-cell ${c.level||''}" title="${escapeHtml(c.tactic)} · ${c.count} detection${c.count===1?'':'s'}">${c.count||''}</div>`
    ).join('');
    const top4 = [...mitreList].filter(c => c.count > 0).sort((a,b) => b.count - a.count).slice(0,4);
    leg.innerHTML = top4.map(c =>
      `<div class="ov2-status-row" style="height:24px">
        <span class="ov2-status-name" style="font-size:11px">${escapeHtml(c.tactic)}</span>
        <span class="ov2-status-val" style="${c.count > 5 ? 'color:var(--d-crit)' : ''}">${c.count} detection${c.count===1?'':'s'}</span>
      </div>`
    ).join('');
  }

  async function loadOverview() {
    const data = await fetchJson(API.dashboardOverview).catch(e => ({ error: e }));
    if (data.error) {
      // API unavailable — render an honest empty/zero state, never demo data.
      _ov2RenderEmpty();
      _loadOvCases(); _loadOvUeba(); _loadOvRba(); _loadOvCompliance(); _loadOvCloud();
      return;
    }

    const totalEvents   = data.timeline_total ?? data.recent_alerts_total ?? 0;
    const agentsSummary = data.agents_summary || {};
    const totalAgents   = (agentsSummary.total != null && agentsSummary.total !== '') ? agentsSummary.total : (data.agent_status_list || []).length;
    const critVal       = data.critical_incidents ?? 0;

    // KPIs from real data only — counts from API, sparklines from real
    // timeline_24h. No demo/sample fallback: empty data renders zeros and a
    // flat sparkline, which is the honest state for a quiet/new deployment.
    // Use ?? not || so zero active agents is not treated as falsy.
    const agentsOnline = agentsSummary.active ?? agentsSummary.connected ?? 0;
    const agentsTotal  = agentsSummary.total ?? totalAgents ?? 0;
    const agentsPct    = agentsTotal > 0 ? Math.round((agentsOnline / agentsTotal) * 100) : 0;
    const tl24 = (data.timeline_24h || []).map(t => t.count || 0);
    const _spkEvents = tl24;
    const tl24sev = data.timeline_24h_by_severity || [];
    const _spkCrit   = tl24sev.map(t => (t.critical||0)+(t.high||0));
    const _spkAgents = agentsTotal > 0 ? tl24.map(() => agentsPct) : [];
    _ov2SetKpi({ val:'kpiTotalEvents',   sub:'kpiEventsSub',  tag:'kpiEventsTag',  spark:'kpiEventsSpark'  },
      { value: totalEvents.toLocaleString(), sub:'events · 24h window', tag:totalEvents>0?'+'+totalEvents:'IDLE', tagKind:totalEvents>1000?'up':'ok', spark: _spkEvents, sparkColor:'#38BDF8' });
    _ov2SetKpi({ val:'criticalCount',    sub:'kpiAlertsSub',  tag:'kpiAlertsTag',  spark:'kpiAlertsSpark'  },
      { value: String(critVal), sub: critVal > 0 ? critVal + ' need attention' : 'no escalations', tag: critVal > 0 ? 'ATTN' : 'CLEAR', tagKind: critVal > 0 ? 'crit' : 'ok', spark: _spkCrit, sparkColor:'#F25555' });
    _ov2SetKpi({ val:'kpiMonitoredAssets', sub:'kpiAgentsSub', tag:'kpiAgentsTag', spark:'kpiAgentsSpark' },
      { value: String(agentsOnline), sub: `of ${agentsTotal} · ${Math.max(0, agentsTotal - agentsOnline)} offline`, tag: agentsPct + '%', tagKind: agentsPct >= 95 ? 'ok' : 'crit', spark: _spkAgents, sparkColor:'#34D399' });
    const alertBadge = document.getElementById('navBadgeAlerts');
    if (alertBadge) { alertBadge.textContent = critVal > 0 ? (critVal > 99 ? '99+' : critVal) : ''; alertBadge.style.display = critVal > 0 ? '' : 'none'; }

    // Charts (real data always)
    const sev24 = data.alert_severity_24h || {};
    drawThreatSummaryDonut('threatSummaryDonutCanvas', 'threatSummaryTotal', 'threatSummaryLegend', sev24);
    drawAgentsSummaryDonut('agentsSummaryDonutCanvas', 'agentsSummaryDonutLegend', agentsSummary);
    drawTimeline('timelineCanvas', data.timeline_24h);

    const statsEl = document.getElementById('timelineStats');
    if (statsEl) {
      const t = data.timeline_total ?? 0, p = data.timeline_peak ?? 0;
      statsEl.textContent = t > 0 ? `Total ${t.toLocaleString()} · peak ${p.toLocaleString()}` : '';
    }

    // MITRE
    const mitreData = data.mitre || [];
    _ov2RenderMitre(mitreData);

    // Response metrics — real values only; show "—" when the API doesn't
    // provide them rather than inventing 18 min / 94% / 78%.
    const mttrEl = document.getElementById('responseMttr');
    const triageEl = document.getElementById('responseTriage');
    const containmentPctEl = document.getElementById('responseContainmentPct');
    const containmentEl = document.getElementById('responseContainment');
    if (mttrEl) mttrEl.textContent = data.mttr_min != null ? data.mttr_min : '—';
    if (triageEl) triageEl.textContent = data.triage_rate != null ? data.triage_rate : '—';
    const containmentVal = data.containment_pct ?? 0;
    if (containmentEl) containmentEl.style.width = containmentVal + '%';
    if (containmentPctEl) containmentPctEl.textContent = data.containment_pct != null ? containmentVal : '—';

    // Alert feed
    const alerts      = data.recent_alerts || [];
    const totalAlerts = data.recent_alerts_total ?? alerts.length;
    _ov2RenderFeed(alerts, totalAlerts);

    // Top source IPs
    const sources   = data.top_sources || [];
    const ipListEl  = document.getElementById('topSourcesList');
    const ipEmptyEl = document.getElementById('topSourcesEmpty');
    const ipData    = sources;
    if (ipListEl) {
      if (ipData.length === 0) {
        ipListEl.innerHTML = '';
        if (ipEmptyEl) ipEmptyEl.classList.remove('hidden');
      } else {
        if (ipEmptyEl) ipEmptyEl.classList.add('hidden');
        const maxC = Math.max(...ipData.map(s => s.count||1), 1);
        ipListEl.innerHTML = ipData.slice(0, 6).map((r, i) => _ov2RenderSourceRow(r, i, maxC)).join('');
        document.getElementById('ipsDot').style.background = 'var(--d-crit)';
      }
    }

    // At-risk agents
    const devices = data.at_risk_devices || [];
    const devData = devices;
    const devEl   = document.getElementById('atRiskDevices');
    if (devEl) {
      if (devData.length === 0) {
        devEl.innerHTML = `<div class="ov2-empty" style="padding:14px 0 18px">
          <div class="ov2-empty-icon info"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 9h6v6H9zM9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3"/></svg></div>
          <div class="ov2-empty-msg">No flagged endpoints</div>
          <div class="ov2-empty-sub">Risk scores under threshold across the fleet</div>
        </div>`;
      } else {
        const maxS = Math.max(...devData.map(d => d.score || d.risk_score || 0), 1);
        devEl.innerHTML = devData.slice(0, 6).map((r, i) => _ov2RenderAgentRiskRow(r, i, maxS)).join('');
        document.getElementById('riskDot').style.background = 'var(--d-high)';
      }
    }

    // Agent health host list (v2)
    const agentList = (data.agent_status_list || []);
    const hostData  = agentList.slice(0, 6).map(a => ({
      name: a.name || a.id || '—',
      state: (a.status || 'pending').toLowerCase(),
      dotCls: (a.status||'').toLowerCase() === 'active' ? 'ok' : (a.status||'').toLowerCase() === 'disconnected' ? 'crit' : 'warn',
    }));
    const liveAssets2 = document.getElementById('liveAssetsBody2');
    if (liveAssets2) {
      liveAssets2.innerHTML = hostData.map(h =>
        `<div class="ov2-host-row">
          <span class="ov2-hdot ${h.dotCls||'idle'}"></span>
          <span class="ov2-host-name">${escapeHtml(h.name)}</span>
          <span class="ov2-host-state">${escapeHtml(h.state)}</span>
        </div>`
      ).join('') || `<div class="ov2-empty-msg" style="padding:10px;font-size:11px;color:var(--d-fg-4)">No agents enrolled</div>`;
    }

    _loadOvCases(); _loadOvUeba(); _loadOvRba(); _loadOvCompliance(); _loadOvCloud();
  }

  function _ov2RenderFeed(alerts, total) {
    const emptyEl = document.getElementById('ov2FeedEmpty');
    const tableEl = document.getElementById('ov2FeedTable');
    const bodyEl  = document.getElementById('liveAlertStream');
    const statEl  = document.getElementById('streamFooterInfo');
    const dotEl   = document.getElementById('feedLiveDot');
    if (!bodyEl) return;
    if (!alerts || alerts.length === 0) {
      if (emptyEl)  emptyEl.style.display  = 'flex';
      if (tableEl)  tableEl.style.display  = 'none';
      if (statEl)   statEl.textContent = '';
      if (dotEl)    dotEl.style.background  = 'var(--d-ok)';
      return;
    }
    if (emptyEl) emptyEl.style.display = 'none';
    if (tableEl) tableEl.style.display = '';
    if (dotEl)   dotEl.style.background = 'var(--d-low)';
    if (statEl)  statEl.textContent = alerts.length + ' alerts · streaming';

    bodyEl.innerHTML = alerts.map(a => {
      const time    = a.timestamp ? new Date(a.timestamp).toLocaleTimeString(undefined, { hour:'2-digit', minute:'2-digit', second:'2-digit' }) : '—';
      const lvl     = parseInt(a.rule_level, 10);
      const sevCls  = lvl >= 13 ? 'crit' : lvl >= 10 ? 'high' : lvl >= 5 ? 'med' : 'low';
      const desc    = (a.rule_description || a.rule_id || 'Alert').slice(0, 70);
      const agent   = (a.agent_name || a.agent_id || '—').slice(0, 18);
      const tactic  = a.mitre_tactic ? `${a.mitre_tactic}` : '—';
      const sevLabel = { crit:'Critical', high:'High', med:'Medium', low:'Low' }[sevCls] || sevCls;
      return `<tr>
        <td class="ov2-feed-time">${escapeHtml(time)}</td>
        <td class="ov2-feed-agent">${escapeHtml(agent)}</td>
        <td class="ov2-feed-desc">${escapeHtml(desc)}</td>
        <td class="ov2-feed-tactic">${escapeHtml(tactic)}</td>
        <td><span class="ov2-pill ${sevCls}">${sevLabel}</span></td>
        <td class="ov2-feed-action"><a href="#" data-page="discover">Investigate →</a></td>
      </tr>`;
    }).join('');
  }

  // Honest empty/zero state used when the overview API is unavailable.
  // Never renders sample data — zeros + flat sparklines + empty lists.
  function _ov2RenderEmpty() {
    const zero = { value:'0', sub:'no data', tag:'IDLE', tagKind:'ok', spark:[], sparkColor:'#38BDF8' };
    _ov2SetKpi({ val:'kpiTotalEvents',    sub:'kpiEventsSub', tag:'kpiEventsTag', spark:'kpiEventsSpark' }, zero);
    _ov2SetKpi({ val:'criticalCount',     sub:'kpiAlertsSub', tag:'kpiAlertsTag', spark:'kpiAlertsSpark' }, { ...zero, tag:'CLEAR' });
    _ov2SetKpi({ val:'kpiMonitoredAssets',sub:'kpiAgentsSub', tag:'kpiAgentsTag', spark:'kpiAgentsSpark' }, { ...zero, tag:'0%' });
    drawTimeline('timelineCanvas', []);
    drawThreatSummaryDonut('threatSummaryDonutCanvas','threatSummaryTotal','threatSummaryLegend', {});
    drawAgentsSummaryDonut('agentsSummaryDonutCanvas','agentsSummaryDonutLegend', {});
    _ov2RenderMitre([]);
    _ov2RenderFeed([], 0);
  }

  async function _loadOvCases() {
    const el = document.getElementById('ovCasesList');
    if (!el) return;
    try {
      const res    = await fetch('/api/cases?status=open&limit=5').then(r => r.json()).catch(() => ({}));
      const cases  = res.cases || res.data || [];
      const total  = res.total || cases.length;
      const kpi    = document.getElementById('kpiOpenCases');
      const tagEl  = document.getElementById('kpiCasesTag');
      const subEl  = document.getElementById('kpiCasesSub');
      const spkEl  = document.getElementById('kpiCasesSpark');
      const badge  = document.getElementById('navBadgeCases');
      if (kpi)   kpi.textContent   = total;
      if (subEl) subEl.textContent = total === 1 ? '1 open case' : total > 0 ? total + ' open cases' : 'queue empty';
      if (tagEl) { tagEl.textContent = total > 0 ? '+' + total : 'CLEAR'; tagEl.className = `ov2-kpi-tag ${total > 0 ? 'up' : 'ok'}`; }
      if (spkEl) spkEl.innerHTML    = buildSparklineSVG([], '#2DD4BF');
      if (badge) { badge.textContent = total > 0 ? (total > 99 ? '99+' : total) : ''; badge.style.display = total > 0 ? '' : 'none'; }

      if (cases.length === 0) {
        el.innerHTML = `<div class="ov2-empty"><div class="ov2-empty-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/></svg>
        </div><div class="ov2-empty-msg">No open cases</div><div class="ov2-empty-sub">Inbox zero · nice work</div></div>`;
        const cDot = document.getElementById('casesDot');
        if (cDot) cDot.style.background = 'var(--d-ok)';
        return;
      }
      const cDot = document.getElementById('casesDot');
      if (cDot) cDot.style.background = 'var(--d-high)';
      el.innerHTML = cases.slice(0, 5).map(c => {
        const prio = (c.priority || 'medium').toLowerCase();
        const sev = prio === 'critical' ? 'crit' : prio === 'high' ? 'high' : 'med';
        const sevLabel = sev === 'crit' ? 'Crit' : sev === 'high' ? 'High' : 'Med';
        return `<div class="ov2-row">
          <div class="ov2-row-main">
            <span class="ov2-row-pri mono">${escapeHtml((c.title || 'Untitled').slice(0,46))}</span>
            <span class="ov2-row-sec">${escapeHtml(c.id||'—')} · ${escapeHtml(c.assignee || 'unassigned')}</span>
          </div>
          <span class="ov2-pill ${sev}">${sevLabel}</span>
        </div>`;
      }).join('');
    } catch(e) {
      const el2 = document.getElementById('ovCasesList');
      if (el2) el2.innerHTML = `<div class="ov2-empty-msg" style="padding:10px;font-size:11px;color:var(--d-fg-4)">Unavailable</div>`;
    }
  }

  async function _loadOvUeba() {
    const el = document.getElementById('ovUebaList');
    if (!el) return;
    try {
      const res    = await fetch('/api/ueba/risk-scores?limit=5').then(r => r.json()).catch(() => ({}));
      const scores = res.risk_scores || res.data || [];
      if (typeof _ensureEntityAgentMap === 'function') { try { await _ensureEntityAgentMap(); } catch(_) {} }
      const anomalyRes   = await fetch('/api/ueba/anomalies?limit=1').then(r => r.json()).catch(() => ({}));
      const anomalyCount = anomalyRes.total || (anomalyRes.anomalies || []).length || 0;
      const kpi   = document.getElementById('kpiUebaAnomalies');
      const tagEl = document.getElementById('kpiUebaTag');
      const subEl = document.getElementById('kpiUebaSub');
      const spkEl = document.getElementById('kpiUebaSpark');
      if (kpi)   kpi.textContent   = anomalyCount;
      if (subEl) subEl.textContent = anomalyCount > 0 ? anomalyCount + ' anomalies detected' : 'within baseline';
      if (tagEl) { tagEl.textContent = anomalyCount > 0 ? '+' + anomalyCount : 'OK'; tagEl.className = `ov2-kpi-tag ${anomalyCount > 0 ? 'up' : 'ok'}`; }
      if (spkEl) spkEl.innerHTML    = buildSparklineSVG([], '#a78bfa');

      if (scores.length === 0) {
        el.innerHTML = `<div class="ov2-empty"><div class="ov2-empty-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 0 1 12 0v1"/></svg>
        </div><div class="ov2-empty-msg">No risk-scored entities</div><div class="ov2-empty-sub">UEBA baselines still forming</div></div>`;
        return;
      }
      const uebaData = scores.slice(0, 5);
      el.innerHTML = uebaData.map(s => {
        const score  = s.risk_score || s.score || 0;
        const label  = s.label || s.entity_type || 'agent';
        const badge  = s.badge || (s.entity_id || s.id || '').slice(0, 2).toUpperCase() || '??';
        const color  = s.color || '#8A8C95';
        const metaColor = score >= 7 ? 'var(--d-crit)' : score >= 4 ? 'var(--d-high)' : 'var(--d-fg-3)';
        return `<div class="ov2-row">
          <div class="ov2-avatar" style="background:${color}">${escapeHtml(badge)}</div>
          <div class="ov2-row-main">
            <span class="ov2-row-pri mono">${escapeHtml(typeof _resolveEntity === 'function' ? _resolveEntity(s.id || s.entity_id, s.entity_type || 'agent') : (s.id || s.entity_id || '—'))}</span>
            <span class="ov2-row-sec">${escapeHtml(label)} · ${s.anomaly_count || score} anomalies</span>
          </div>
          <span style="font-size:11.5px;font-family:var(--d-font-mono);font-weight:600;color:${metaColor};flex-shrink:0;min-width:18px;text-align:right">${score}</span>
        </div>`;
      }).join('');
    } catch(e) {
      const el2 = document.getElementById('ovUebaList');
      if (el2) el2.innerHTML = `<div class="ov2-empty-msg" style="padding:10px;font-size:11px;color:var(--d-fg-4)">Unavailable</div>`;
    }
  }

  async function _loadOvRba() {
    const el = document.getElementById('ovRbaList');
    if (!el) return;
    try {
      const res      = await fetch('/api/rba/notables?limit=5').then(r => r.json()).catch(() => ({}));
      const notables = res.notables || res.data || [];
      if (typeof _ensureEntityAgentMap === 'function') { try { await _ensureEntityAgentMap(); } catch(_) {} }
      const total    = res.total || notables.length;
      const kpi   = document.getElementById('kpiRbaNotables');
      const tagEl = document.getElementById('kpiRbaTag');
      const subEl = document.getElementById('kpiRbaSub');
      const spkEl = document.getElementById('kpiRbaSpark');
      if (kpi)   kpi.textContent   = total;
      if (subEl) subEl.textContent = total > 0 ? 'risk score ≥ threshold' : 'no risk-scored events';
      if (tagEl) { tagEl.textContent = total > 0 ? '+' + total : 'OK'; tagEl.className = `ov2-kpi-tag ${total > 0 ? 'up' : 'ok'}`; }
      if (spkEl) spkEl.innerHTML    = buildSparklineSVG([], '#F59E0B');
      const rbaDot = document.getElementById('rbaDot');

      if (notables.length === 0) {
        if (rbaDot) rbaDot.style.background = 'var(--d-ok)';
        el.innerHTML = `<div class="ov2-empty"><div class="ov2-empty-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M13 2 3 14h7l-1 8 10-12h-7l1-8z"/></svg>
        </div><div class="ov2-empty-msg">No notable events</div><div class="ov2-empty-sub">Risk-based alerting is calibrated</div></div>`;
        return;
      }
      if (rbaDot) rbaDot.style.background = 'var(--d-high)';
      el.innerHTML = notables.slice(0, 5).map(n => {
        const score = n.total_risk || n.risk_score || 0;
        const scoreColor = score >= 90 ? 'var(--d-crit)' : score >= 70 ? 'var(--d-high)' : 'var(--d-fg-3)';
        return `<div class="ov2-row">
          <div class="ov2-row-main">
            <span class="ov2-row-pri mono">${escapeHtml(typeof _resolveEntity === 'function' ? _resolveEntity(n.entity_id || n.entity, n.entity_type || 'agent') : (n.entity_id || n.entity || '—').slice(0,36))}</span>
            <span class="ov2-row-sec">${n.event_count || 0} events · ${n.triggered_at ? new Date(n.triggered_at).toLocaleTimeString() : '—'}</span>
          </div>
          <span style="font-size:14px;font-family:var(--d-font-mono);font-weight:500;color:${scoreColor};flex-shrink:0">${score}</span>
        </div>`;
      }).join('');
    } catch(e) {
      const el2 = document.getElementById('ovRbaList');
      if (el2) el2.innerHTML = `<div class="ov2-empty-msg" style="padding:10px;font-size:11px;color:var(--d-fg-4)">Unavailable</div>`;
    }
  }

  async function _loadOvCompliance() {
    const el = document.getElementById('ovComplianceBars');
    if (!el) return;
    const defaults = [
      { id:'iso27001', label:'ISO 27001', pct:100 },
      { id:'nist',     label:'NIST CSF',  pct:100 },
      { id:'soc2',     label:'SOC 2',     pct:96  },
      { id:'hipaa',    label:'HIPAA',     pct:92  },
      { id:'pci',      label:'PCI-DSS',   pct:88  },
    ];
    try {
      const results = await Promise.all(defaults.map(f =>
        fetch('/api/compliance/' + f.id)
          .then(r => r.ok ? r.json() : Promise.resolve({}))
          .catch(() => ({}))
      ));
      el.innerHTML = defaults.map((f, i) => {
        const pct = results[i].compliance_pct ?? results[i].score ?? f.pct;
        const fillCls = pct >= 90 ? '' : pct >= 75 ? 'warn' : 'crit';
        return `<div class="ov2-comply-row">
          <span class="ov2-comply-label">${f.label}</span>
          <div class="ov2-comply-track"><div class="ov2-comply-fill ${fillCls}" style="width:${pct}%"></div></div>
          <span class="ov2-comply-val">${pct}%</span>
        </div>`;
      }).join('');
    } catch(e) {
      el.innerHTML = defaults.map(f =>
        `<div class="ov2-comply-row">
          <span class="ov2-comply-label">${f.label}</span>
          <div class="ov2-comply-track"><div class="ov2-comply-fill" style="width:${f.pct}%"></div></div>
          <span class="ov2-comply-val">${f.pct}%</span>
        </div>`
      ).join('');
    }
  }

  async function _loadOvCloud() {
    const el = document.getElementById('ovCloudStatus');
    if (!el) return;
    try {
      const res   = await fetch('/api/cloud/status').then(r => r.json()).catch(() => ({}));
      const aiRes = await fetch('/api/ai/status').then(r => r.json()).catch(() => ({ configured: false }));
      const providers = [
        { key:'aws',   label:'AWS CloudTrail' },
        { key:'azure', label:'Azure Monitor'  },
        { key:'gcp',   label:'GCP Logging'    },
      ];
      el.innerHTML = providers.map(p => {
        const pd  = (res.providers || {})[p.key] || {};
        const ok  = pd.configured || pd.enabled || false;
        const dot = ok ? 'ok' : 'warn';
        const val = ok ? (pd.last_sync ? new Date(pd.last_sync).toLocaleTimeString() : 'Active') : 'Not configured';
        return `<div class="ov2-status-row"><span class="ov2-sdot ${dot}"></span><span class="ov2-status-name">${p.label}</span><span class="ov2-status-val">${val}</span></div>`;
      }).join('') + `<div class="ov2-status-row"><span class="ov2-sdot ${aiRes.configured ? 'ok' : 'warn'}"></span><span class="ov2-status-name">AI Summaries</span><span class="ov2-status-val">${aiRes.configured ? 'Ready' : 'No API key'}</span></div>`;
    } catch(e) {
      const providers = ['AWS CloudTrail','Azure Monitor','GCP Logging','AI Summaries'];
      el.innerHTML = providers.map(p => `<div class="ov2-status-row"><span class="ov2-sdot warn"></span><span class="ov2-status-name">${p}</span><span class="ov2-status-val">Not configured</span></div>`).join('');
    }
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
    _stackWireBackup();
    _stackRefreshBackupList();
    _stackWirePipeline();
    _stackRefreshPipeline();
  }

  let _pipeWired = false;
  function _stackWirePipeline() {
    if (_pipeWired) return;
    const btn = document.getElementById('pipeRefresh');
    if (!btn) return;
    _pipeWired = true;
    btn.addEventListener('click', _stackRefreshPipeline);
  }

  async function _stackRefreshPipeline() {
    const el = id => document.getElementById(id);
    const data = await fetchJson('/api/pipeline/health').catch(() => null);
    if (!data) {
      if (el('pipeStatusBadge')) el('pipeStatusBadge').textContent = 'unreachable';
      if (el('pipeStatusDot')) el('pipeStatusDot').style.background = 'var(--fg-4)';
      return;
    }
    const status = data.status || 'unknown';
    const color = status === 'healthy'  ? 'var(--ok)'
                : status === 'warning'  ? 'var(--high)'
                : status === 'degraded' ? 'var(--crit)'
                : 'var(--fg-4)';
    if (el('pipeStatusBadge')) {
      el('pipeStatusBadge').textContent = status.toUpperCase();
      el('pipeStatusBadge').style.color = color;
    }
    if (el('pipeStatusDot')) el('pipeStatusDot').style.background = color;
    const f = data.forwarder || {};
    const a = data.agents || {};
    if (el('pipeDlq')) el('pipeDlq').textContent = (f.dlq_depth || 0).toLocaleString();
    if (el('pipeDropEv')) {
      el('pipeDropEv').textContent = (f.dropped_events || 0).toLocaleString();
      el('pipeDropEv').style.color = f.dropped_events > 0 ? 'var(--crit)' : '';
    }
    if (el('pipeDropAl')) {
      el('pipeDropAl').textContent = (f.dropped_alerts || 0).toLocaleString();
      el('pipeDropAl').style.color = f.dropped_alerts > 0 ? 'var(--crit)' : '';
    }
    if (el('pipeAgents')) el('pipeAgents').textContent = (a.total || 0).toLocaleString();
    if (el('pipeAgentSub')) el('pipeAgentSub').textContent = `${a.active || 0} active / ${a.disconnected || 0} disconnected`;
  }

  let _stackBackupWired = false;
  function _stackWireBackup() {
    if (_stackBackupWired) return;
    const btn = document.getElementById('backupDownloadBtn');
    if (!btn) return;
    _stackBackupWired = true;
    btn.addEventListener('click', async () => {
      const orig = btn.textContent;
      btn.disabled = true;
      btn.textContent = 'Building…';
      try {
        const res = await fetch('/api/admin/backup/download', { method: 'POST', credentials: 'same-origin' });
        if (!res.ok) {
          const t = await res.text();
          alert('Backup failed: ' + t);
          return;
        }
        const blob = await res.blob();
        const dispo = res.headers.get('Content-Disposition') || '';
        const m = dispo.match(/filename="?([^";]+)"?/);
        const fname = m ? m[1] : `sentinel-backup-${Date.now()}.tar.gz`;
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = fname;
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(a.href);
        _stackRefreshBackupList();
      } finally {
        btn.disabled = false;
        btn.textContent = orig;
      }
    });
  }

  async function _stackRefreshBackupList() {
    const target = document.getElementById('backupList');
    if (!target) return;
    const data = await fetchJson('/api/admin/backup/list').catch(() => null);
    if (!data || !data.backups || data.backups.length === 0) {
      target.innerHTML = '<div style="color:var(--fg-4);font-size:11px">No previous backups on disk.</div>';
      return;
    }
    target.innerHTML =
      '<div style="font-size:11px;color:var(--fg-4);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Recent backups</div>' +
      data.backups.slice(0, 10).map(b => {
        const ts = new Date(b.created_at_ms).toLocaleString();
        const kb = (b.size_bytes / 1024).toFixed(1) + ' KB';
        return `<div style="display:flex;justify-content:space-between;gap:8px;padding:4px 0;font-family:var(--font-mono);font-size:11px;border-bottom:1px solid var(--border)"><span>${escapeHtml(b.name)}</span><span style="color:var(--fg-4)">${ts} · ${kb}</span></div>`;
      }).join('');
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

  function _agOsLabel(raw) {
    const s = (raw || '').toLowerCase();
    if (s.includes('win')) return 'WINDOWS';
    if (s.includes('mac') || s.includes('darwin')) return 'MACOS';
    return 'LINUX';
  }
  function _agStatusMeta(s) {
    if (s === 'active') return { dot:'ok', label:'Connected' };
    if (s === 'pending') return { dot:'warn', label:'Pending' };
    return { dot:'crit', label:'Disconnected' };
  }


  function renderAgentsTableFromHealth(agents) {
    if (!agents || agents.length === 0) {
      return `<div class="adt-empty">No agents match this view.</div>`;
    }
    return agents.map(a => {
      const { dot, label } = _agStatusMeta(a.status);
      const hostname = escapeHtml(a.name || a.hostname || '—');
      const hostnameRaw = String(a.name || a.hostname || '').replace(/['"\\]/g, '');
      const fullId = String(a.id || '');
      const agId = escapeHtml(fullId.slice(0, 14)) + (fullId.length > 14 ? '…' : '');
      const os = _agOsLabel(a.os_label);
      const osIcon = _ndOsIcon(a.os_label);
      const alerts = (a.alert_count || 0);
      const crits = a.critical_count || 0;
      const ver = escapeHtml(a.version || '—');
      const lastSeen = escapeHtml(a.last_seen_label || '—');
      const rawIp = String(a.ip || '').trim();
      const hasIp = rawIp && rawIp.toLowerCase() !== 'any';
      const ipCell = hasIp
        ? `<span role="cell" class="adt-mono adt-ip">${escapeHtml(rawIp)}</span>`
        : `<span role="cell" class="adt-mono adt-ip none">—</span>`;
      return `<div class="adt-row adt-brow" role="row" data-agent-id="${escapeHtml(fullId)}" title="Open node detail">
        <span role="cell"><span class="adt-badge ${dot}"><span class="adt-dot ${dot}"></span>${label}</span></span>
        <span role="cell" class="adt-name">${hostname}</span>
        ${ipCell}
        <span role="cell" class="adt-mono" title="${escapeHtml(fullId)}">${agId}</span>
        <span role="cell" class="adt-os"><span class="adt-os-ico">${osIcon}</span>${os}</span>
        <span role="cell" class="adt-mono">${ver}</span>
        <span role="cell" class="adt-num">${alerts}</span>
        <span role="cell" class="adt-num ${crits>0?'crit':'zero'}">${crits}</span>
        <span role="cell" class="adt-time">${lastSeen}</span>
        <span role="cell" class="adt-act">
          <button type="button" class="adt-act-btn" title="Isolate host — network quarantine (keeps manager channel)" aria-label="Isolate host" onclick="event.stopPropagation();isolateAgent('${escapeHtml(fullId)}','${escapeHtml(hostnameRaw)}')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </button>
          <button type="button" class="adt-act-btn" title="Release isolation" aria-label="Release isolation" onclick="event.stopPropagation();releaseAgent('${escapeHtml(fullId)}','${escapeHtml(hostnameRaw)}')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M4 4l16 16"/></svg>
          </button>
          <button type="button" class="adt-act-btn" title="Application control (AppLocker prevention)" aria-label="Application control" onclick="event.stopPropagation();openAppControl('${escapeHtml(fullId)}','${escapeHtml(hostnameRaw)}')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </button>
          <button type="button" class="adt-act-btn" title="Collect forensic evidence" aria-label="Collect forensic evidence" onclick="event.stopPropagation();openForensics('${escapeHtml(fullId)}','${escapeHtml(hostnameRaw)}')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M9 13h6M9 17h4"/></svg>
          </button>
          <button type="button" class="adt-act-btn btn-agent-view" data-agent-id="${escapeHtml(fullId)}" title="Open node detail" aria-label="Open node detail">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
          </button>
        </span>
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
    // Update tab counts
    const active = agents.filter(a => a.status === 'active').length;
    const disconn = agents.filter(a => a.status === 'disconnected').length;
    const pending = agents.filter(a => a.status === 'pending').length;
    const setTxt = (id, v) => { const e = el(id); if (e) e.textContent = v; };
    setTxt('agTabAll', agents.length);
    setTxt('agTabConnected', active);
    setTxt('agTabDisconnected', disconn);
    setTxt('agTabPending', pending);
    const filtered = filterAgentsTable(agents);
    if (el('agentsBody')) el('agentsBody').innerHTML = renderAgentsTableFromHealth(filtered);
    if (el('agentsTableCount')) el('agentsTableCount').textContent = filtered.length;
  }

  // Currently-open node on the full detail page.
  let _agentDetailId = null;

  // Entry point from the fleet table → navigate to the full node detail page.
  function openAgentDetail(agentId) {
    _agentDetailId = agentId;
    goToPage('agent-detail');
  }

  function _ndOsIcon(osLabel) {
    const s = (osLabel || '').toLowerCase();
    if (s.includes('win')) return '🪟';
    if (s.includes('mac') || s.includes('darwin')) return '🍎';
    return '🐧';
  }
  function _ndStatusMeta(s) {
    if (s === 'active') return { dot: 'ok', label: 'Connected', sub: 'sending events' };
    if (s === 'pending') return { dot: 'warn', label: 'Pending', sub: 'awaiting first heartbeat' };
    if (s === 'never_connected') return { dot: 'warn', label: 'Never connected', sub: 'enrolled, never checked in' };
    return { dot: 'crit', label: 'Disconnected', sub: 'no recent heartbeat' };
  }
  function _ndRow(key, val, mono) {
    return '<div class="nd-row"><span class="nd-key">' + escapeHtml(key) + '</span><span class="nd-val' +
      (mono ? ' mono' : '') + '">' + (val == null || val === '' ? '—' : escapeHtml(String(val))) + '</span></div>';
  }

  async function loadAgentDetailPage() {
    const body = document.getElementById('agentDetailBody');
    if (!body) return;
    const agentId = _agentDetailId;
    if (!agentId) { body.innerHTML = '<p class="empty-msg">No agent selected.</p>'; return; }
    body.innerHTML = '<p class="empty-msg">Loading node…</p>';
    const data = await fetchJson('/api/agents/' + encodeURIComponent(agentId)).catch(e => ({ error: e }));
    if (data.error) {
      body.innerHTML = '<p class="error-msg">' + escapeHtml(data.error.message || 'Failed to load agent') + '</p>';
      return;
    }
    const fmt = (v) => { try { return v ? new Date(String(v).replace('Z', '+00:00')).toLocaleString() : '—'; } catch (e) { return '—'; } };
    const meta = _ndStatusMeta(data.status);
    const hostname = data.hostname || data.name || data.id || '—';
    const alerts = data.alert_count || 0;
    const crits = data.critical_count || 0;
    const offline = data.offline_minutes != null
      ? (data.offline_minutes < 60 ? data.offline_minutes + 'm' : Math.floor(data.offline_minutes / 60) + 'h ' + (data.offline_minutes % 60) + 'm')
      : null;
    const labels = data.labels && typeof data.labels === 'object' ? data.labels : {};
    const labelKeys = Object.keys(labels);

    // --- Hero header ---
    let html = '<div class="nd-hero">' +
      '<div class="nd-hero-icon">' + _ndOsIcon(data.os_label) + '</div>' +
      '<div class="nd-hero-main">' +
        '<div class="nd-hero-name">' + escapeHtml(hostname) + '</div>' +
        '<div class="nd-hero-id mono">' + escapeHtml(String(data.id || '—')) + '</div>' +
      '</div>' +
      '<div class="nd-hero-status ' + meta.dot + '">' +
        '<span class="ag2-sum-dot ' + meta.dot + '"></span>' +
        '<div class="nd-hero-status-txt"><span class="nd-hero-status-lbl">' + meta.label + '</span>' +
        '<span class="nd-hero-status-sub">' + escapeHtml(meta.sub) + (offline ? ' · offline ' + offline : '') + '</span></div>' +
      '</div>' +
    '</div>';

    // --- KPI strip ---
    html += '<div class="nd-kpis">' +
      '<div class="nd-kpi"><span class="nd-kpi-val">' + alerts + '</span><span class="nd-kpi-lbl">Total alerts</span></div>' +
      '<div class="nd-kpi"><span class="nd-kpi-val ' + (crits > 0 ? 'crit' : '') + '">' + crits + '</span><span class="nd-kpi-lbl">Critical</span></div>' +
      '<div class="nd-kpi"><span class="nd-kpi-val">' + escapeHtml(data.version || '—') + '</span><span class="nd-kpi-lbl">Agent version</span></div>' +
      '<div class="nd-kpi"><span class="nd-kpi-val">' + escapeHtml(data.last_seen_label || '—') + '</span><span class="nd-kpi-lbl">Last seen</span></div>' +
    '</div>';

    // --- Two info cards: Identity + System ---
    html += '<div class="nd-grid">';
    html += '<div class="nd-card"><div class="nd-card-h">Identity</div>' +
      _ndRow('Hostname', data.hostname || data.name) +
      _ndRow('Agent ID', data.id, true) +
      _ndRow('IP address', data.ip, true) +
      _ndRow('Group', data.group) +
      _ndRow('Cluster node', data.node_name) +
    '</div>';
    html += '<div class="nd-card"><div class="nd-card-h">System &amp; enrollment</div>' +
      _ndRow('Operating system', data.os_label) +
      _ndRow('Platform', data.platform || data.os_name) +
      _ndRow('Agent version', data.version) +
      _ndRow('Registered', fmt(data.date_added)) +
      _ndRow('Last keep-alive', fmt(data.last_keep_alive)) +
    '</div>';
    html += '</div>';

    // --- Labels (if any) ---
    if (labelKeys.length) {
      html += '<div class="nd-card"><div class="nd-card-h">Labels</div><div class="nd-labels">' +
        labelKeys.map(k => '<span class="nd-label-chip"><b>' + escapeHtml(k) + '</b>' + escapeHtml(String(labels[k])) + '</span>').join('') +
        '</div></div>';
    }

    // --- Quick pivots ---
    const pivots = [
      { page: 'alerts', icon: '🔔', title: 'Alerts', desc: 'Detections raised on this node' },
      { page: 'discover', icon: '🔎', title: 'Investigate events', desc: 'Pivot raw events in Discover' },
      { page: 'vulnerabilities', icon: '🛡️', title: 'Vulnerabilities', desc: 'CVEs matched on installed packages' },
      { page: 'fim', icon: '📁', title: 'File integrity', desc: 'Who changed which files (whodata)' },
      { page: 'sca', icon: '✅', title: 'Configuration (SCA)', desc: 'Security config assessment results' },
      { page: 'compliance', icon: '📋', title: 'Compliance', desc: 'HIPAA / PCI / NIST posture' },
    ];
    html += '<div class="nd-card"><div class="nd-card-h">Investigate this node</div><div class="nd-pivots">' +
      pivots.map(p => '<button type="button" class="nd-pivot" data-pivot="' + p.page + '">' +
        '<span class="nd-pivot-icon">' + p.icon + '</span>' +
        '<span class="nd-pivot-txt"><span class="nd-pivot-title">' + p.title + '</span>' +
        '<span class="nd-pivot-desc">' + p.desc + '</span></span>' +
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>' +
      '</button>').join('') +
    '</div></div>';

    body.innerHTML = html;

    // Wire pivots — every pivot opens the destination pre-filtered to THIS agent.
    // Pages with their own agent filter (vulnerabilities, FIM) get it via the
    // _pivotAgent handoff; the rest open in Discover scoped to the agent.
    body.querySelectorAll('.nd-pivot').forEach(btn => {
      btn.addEventListener('click', () => {
        const page = btn.getAttribute('data-pivot');
        const agentId = data.id;
        const agentName = data.name || data.hostname || '';
        if (page === 'alerts') {
          _pivotDiscover(agentId, { index: 'watchvault-alerts-*' });
        } else if (page === 'discover') {
          _pivotDiscover(agentId, { index: 'watchvault-events-*' });
        } else if (page === 'sca') {
          _pivotDiscover(agentId, { index: 'watchvault-events-*', query: 'event_type:sca*' });
        } else if (page === 'compliance') {
          _pivotDiscover(agentId, { index: 'watchvault-alerts-*', query: 'rule_groups:compliance' });
        } else if (page === 'vulnerabilities' || page === 'fim') {
          window._pivotAgent = { id: agentId, name: agentName };
          goToPage(page);
        } else {
          goToPage(page);
        }
      });
    });
  }

  function filterAgentsTable(agents) {
    if (!agents) return [];
    const search = (document.getElementById('agentsSearch')?.value || '').trim().toLowerCase();
    const activeTab = document.querySelector('.ag2-tab.active')?.getAttribute('data-status') || '';
    let out = agents;
    if (activeTab) out = out.filter(a => a.status === activeTab);
    if (search) out = out.filter(a =>
      (a.name || '').toLowerCase().includes(search) ||
      (a.hostname || '').toLowerCase().includes(search) ||
      (a.id || '').toString().includes(search) ||
      (a.os_label || '').toLowerCase().includes(search));
    return out;
  }


  function _renderBigbars(containerId, rows, dotId, metaId, dotColor) {
    const el = document.getElementById(containerId);
    if (!el) return;
    if (dotId) { const d = document.getElementById(dotId); if (d) d.style.background = dotColor || 'var(--crit)'; }
    if (metaId) { const m = document.getElementById(metaId); if (m) m.textContent = `${rows.length} ${containerId.includes('Agent') ? 'agents' : containerId.includes('Sev') ? 'levels' : 'rules'}`; }
    el.innerHTML = rows.map((r, i) => {
      const pct = Math.min(100, (r.count / rows[0].count) * 100);
      const num = r.sev ? `<span class="bigbar-r-num ${r.sev}">${String(r.name||'')[0] || (i+1)}</span>` : `<span class="bigbar-r-num ${r.sev||''}">${i+1}</span>`;
      return `<div class="bigbar-row">
        ${num}
        <div class="bigbar-l">
          <div class="bigbar-l-name">
            <span ${r.mono ? 'style="font-family:var(--font-mono)"' : ''}>${escapeHtml(r.name)}</span>
            ${r.meta ? `<span class="meta">${escapeHtml(r.meta)}</span>` : ''}
          </div>
          <div class="bigbar-l-bar ${r.sev||''}"><i style="width:${pct}%"></i></div>
        </div>
        <span class="bigbar-v">${r.count}</span>
      </div>`;
    }).join('');
  }

  // ── Agent id → hostname resolver (cached) ──────────────────────────────
  let _agentNameMap = null;
  async function getAgentNameMap() {
    if (_agentNameMap) return _agentNameMap;
    const map = {};
    try {
      const data = window._agentsHealthData || await fetchJson(API.agentsHealth);
      (data.agents || []).forEach(a => { if (a.id) map[a.id] = a.name || a.hostname || a.id; });
    } catch (e) { /* fall back to raw ids */ }
    _agentNameMap = map;
    return map;
  }
  function resolveAgent(idOrName, map) {
    if (idOrName && map && map[idOrName]) return map[idOrName];
    const s = String(idOrName || '');
    // Looks like a raw hex id → shorten so it doesn't dominate the row
    if (/^[0-9a-f]{16,}$/i.test(s)) return s.slice(0, 10) + '…';
    return s || '—';
  }

  // ── Severity helpers ───────────────────────────────────────────────────
  function _levelBand(l) { l = +l || 0; if (l >= 12) return 'crit'; if (l >= 8) return 'high'; if (l >= 4) return 'med'; return 'low'; }
  function _levelLabel(l) { return ({ crit: 'Critical', high: 'High', med: 'Medium', low: 'Low' })[_levelBand(l)]; }

  // ── Alerts-over-time histogram (gap-filled, stacked by severity) ────────
  function renderHuntHistogram(series, range) {
    const el = document.getElementById('thHistogram');
    if (!el) return;
    const interval = range === '7d' ? 86400000 : 3600000;
    const count = range === '7d' ? 7 : 24;
    // Bucket populated counts by their interval-aligned start
    const byStart = {};
    (series || []).forEach(s => {
      const start = Math.floor(Number(s.date) / interval) * interval;
      const segs = byStart[start] || (byStart[start] = { crit: 0, high: 0, med: 0, low: 0 });
      (s.buckets || []).forEach(b => { segs[_levelBand(b.key)] += (b.doc_count || 0); });
    });
    const nowStart = Math.floor(Date.now() / interval) * interval;
    const bins = [];
    for (let i = count - 1; i >= 0; i--) {
      const start = nowStart - i * interval;
      const segs = byStart[start] || { crit: 0, high: 0, med: 0, low: 0 };
      bins.push({ start, segs, total: segs.crit + segs.high + segs.med + segs.low });
    }
    const max = Math.max(1, ...bins.map(b => b.total));
    if (bins.every(b => b.total === 0)) {
      el.innerHTML = `<div class="th-hist-empty"><div class="chart-empty-msg">No alerts in this window</div><div class="chart-empty-sub">Detections will plot here as agents report events</div></div>`;
      return;
    }
    const H = 156;
    const fmtTime = (ms) => {
      const d = new Date(ms);
      return range === '7d'
        ? ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][d.getDay()] + ' ' + d.getDate()
        : String(d.getHours()).padStart(2, '0') + ':00';
    };
    const labelEvery = range === '7d' ? 1 : 4;
    const order = ['crit', 'high', 'med', 'low'];
    const cols = bins.map((b, i) => {
      const segHtml = order.map(k => b.segs[k] > 0
        ? `<i class="th-seg ${k}" style="height:${(b.segs[k] / max) * H}px"></i>` : '').join('');
      const tip = fmtTime(b.start) + ' — ' + b.total + ' alert' + (b.total === 1 ? '' : 's') +
        (b.total ? ` (C${b.segs.crit} H${b.segs.high} M${b.segs.med} L${b.segs.low})` : '');
      const lbl = (i % labelEvery === 0) ? fmtTime(b.start) : '';
      return `<div class="th-hcol" title="${escapeHtml(tip)}">
        <div class="th-hbar">${segHtml}</div>
        <span class="th-hx">${escapeHtml(lbl)}</span>
      </div>`;
    }).join('');
    el.innerHTML = `<div class="th-hist-bars" style="--th-h:${H}px">${cols}</div>`;
  }

  // ── Alerts explorer table ──────────────────────────────────────────────
  let _huntExplorerData = [];
  function renderHuntExplorer(alerts, nameMap) {
    const body = document.getElementById('thExplorerBody');
    const countEl = document.getElementById('thExplorerCount');
    if (!body) return;
    if (countEl) countEl.textContent = alerts.length;
    if (!alerts.length) {
      body.innerHTML = `<div class="adt-empty">No alerts match your filter.</div>`;
      return;
    }
    body.innerHTML = alerts.slice(0, 100).map(a => {
      const band = _levelBand(a.rule_level);
      const ts = a.timestamp ? new Date(a.timestamp) : null;
      const tlabel = ts ? ts.toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '—';
      const agent = escapeHtml(a.agent_name && a.agent_name.trim() ? a.agent_name : resolveAgent(a.agent_id, nameMap));
      const desc = escapeHtml(a.rule_description || '—');
      const groups = (a.rule_groups || []).slice(0, 2).map(g => `<span class="th-grp">${escapeHtml(g)}</span>`).join('');
      const rid = escapeHtml(String(a.rule_id ?? '—'));
      return `<div class="adt-row th-exp-row" role="row">
        <span role="cell" class="th-exp-time">${escapeHtml(tlabel)}</span>
        <span role="cell" class="th-exp-agent" title="${escapeHtml(String(a.agent_id||''))}">${agent}</span>
        <span role="cell" class="th-exp-rule" title="${desc}">${desc}</span>
        <span role="cell" class="th-exp-groups">${groups || '<span class="th-grp muted">—</span>'}</span>
        <span role="cell" class="adt-num"><span class="th-lvl ${band}">${escapeHtml(String(a.rule_level ?? '—'))}</span></span>
        <span role="cell" class="adt-mono">${rid}</span>
      </div>`;
    }).join('');
  }
  function filterHuntExplorer() {
    const q = (document.getElementById('thExplorerSearch')?.value || '').trim().toLowerCase();
    let rows = _huntExplorerData;
    if (q) rows = rows.filter(a =>
      (a.rule_description || '').toLowerCase().includes(q) ||
      (a.agent_name || '').toLowerCase().includes(q) ||
      (a.agent_id || '').toLowerCase().includes(q) ||
      String(a.rule_level || '').includes(q) ||
      String(a.rule_id || '').includes(q) ||
      (a.srcip || '').toLowerCase().includes(q) ||
      (a.rule_groups || []).join(' ').toLowerCase().includes(q));
    renderHuntExplorer(rows, _agentNameMap || {});
  }

  async function loadThreatHunting() {
    const range = document.getElementById('huntTimeRange')?.value || '24h';
    const days = range === '7d' ? 7 : 1;
    const interval = range === '7d' ? '1d' : '1h';
    const nameMap = await getAgentNameMap();

    const [stats, sevTime, byAgent, byRule, byTactic, bySev, listRes] = await Promise.all([
      fetchJson(API.dashboardStats || '/api/dashboard/stats').catch(() => ({})),
      fetchJson(`/api/alerts/severity-over-time?days=${days}&interval=${interval}`).catch(() => ({ series: [] })),
      fetchJson(API.alertsByAgent + '?size=8').catch(() => ({})),
      fetchJson(API.alertsByRule + '?size=8').catch(() => ({})),
      fetchJson(API.mitreTactics + '?size=8').catch(() => ({})),
      fetchJson(API.alertsBySeverity).catch(() => ({})),
      fetchJson(`${API.alertsList}?limit=200&range=${range === '7d' ? '7d' : '24h'}`).catch(() => ({ alerts: [] })),
    ]);

    // KPIs
    const sevBuckets = bySev?.buckets || [];
    const total = sevBuckets.reduce((s, b) => s + (b.count || 0), 0) || (stats.total_events || 0);
    const elevated = (listRes.alerts || []).filter(a => (+a.rule_level || 0) >= 8).length;
    const distinctRules = new Set((listRes.alerts || []).map(a => a.rule_id)).size || (byRule?.buckets || []).length;
    const setT = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
    setT('thKpiTotal', total);
    setT('huntHitsMeta', total);
    setT('thKpiHigh', elevated);
    setT('thKpiAgents', stats.unique_agents ?? (byAgent?.buckets || []).length);
    setT('thKpiRules', distinctRules);

    // Histogram
    renderHuntHistogram(sevTime?.series || [], range);

    // Breakdown panels
    const agentRows = (byAgent?.buckets || []).slice(0, 6).map(b => ({
      name: resolveAgent(b.key, nameMap), count: b.count || 0,
      sev: (b.count || 0) > 50 ? 'crit' : (b.count || 0) > 20 ? 'high' : 'med',
      mono: !nameMap[b.key],
    }));
    const ruleRows = (byRule?.buckets || []).slice(0, 6).map(b => ({
      name: (b.key || '—').slice(0, 52), count: b.count || 0,
      sev: (b.count || 0) > 50 ? 'crit' : (b.count || 0) > 10 ? 'high' : 'med',
    }));
    const tacticRows = (byTactic?.buckets || []).slice(0, 6).map(b => ({
      name: b.key || '—', count: b.count || b.doc_count || 0, sev: 'high',
    }));
    const sevRows = sevBuckets.map(b => ({
      name: b.key || '—', count: b.count || 0, sev: String(b.key || '').toLowerCase().includes('crit') ? 'crit'
        : String(b.key || '').toLowerCase().includes('high') ? 'high'
        : String(b.key || '').toLowerCase().includes('med') ? 'med' : 'low',
    }));

    _renderBigbars('chartByAgent', agentRows, null, 'huntAgentMeta', 'var(--crit)');
    _renderBigbars('chartRules', ruleRows, null, 'huntRulesMeta', 'var(--high)');
    if (tacticRows.length) {
      _renderBigbars('chartMitre', tacticRows, null, 'huntMitreMeta', 'var(--accent)');
    } else {
      const m = document.getElementById('chartMitre');
      if (m) m.innerHTML = `<div class="chart-empty"><div class="chart-empty-msg">No MITRE-tagged alerts</div><div class="chart-empty-sub">Rules with a mitre: block will populate this</div></div>`;
      setT('huntMitreMeta', '0 tactics');
    }
    _renderBigbars('chartSeverity', sevRows, null, 'huntSevMeta', 'var(--ok)');

    // Explorer
    _huntExplorerData = listRes.alerts || [];
    filterHuntExplorer();
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
    const colors = { critical: '#F25555', high: '#F59E0B', medium: '#2DD4BF', low: '#34D399' };
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

  // ── Severity chip toggle (Alerts page) ───────────────────────────
  function _wireAlertChips() {
    const chips = document.querySelectorAll('#alertsSevChips .v2-chip');
    chips.forEach(chip => {
      chip.addEventListener('click', () => {
        chip.classList.toggle('active');
      });
    });
  }

  // ── Discover field panel init ─────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    // Init field selector with defaults
    setTimeout(() => {
      if (document.getElementById('discoverSelectedFields')) {
        renderDiscoverFieldsSidebar();
      }
    }, 0);
  });



  const MITRE_TACTICS = [
    { id:'TA0043', name:'Reconnaissance',    short:'Recon'     },
    { id:'TA0042', name:'Resource Dev',      short:'Resource'  },
    { id:'TA0001', name:'Initial Access',    short:'Init Acc'  },
    { id:'TA0002', name:'Execution',         short:'Exec'      },
    { id:'TA0003', name:'Persistence',       short:'Persist'   },
    { id:'TA0004', name:'Priv. Escalation',  short:'Priv Esc'  },
    { id:'TA0005', name:'Defense Evasion',   short:'Def Evade' },
    { id:'TA0006', name:'Cred. Access',      short:'Cred Acc'  },
    { id:'TA0007', name:'Discovery',         short:'Discover'  },
    { id:'TA0008', name:'Lateral Movement',  short:'Lateral'   },
    { id:'TA0009', name:'Collection',        short:'Collect'   },
    { id:'TA0011', name:'C2',                short:'C2'        },
    { id:'TA0010', name:'Exfiltration',      short:'Exfil'     },
    { id:'TA0040', name:'Impact',            short:'Impact'    },
  ];

  // ── Sparkline helper (reuse from overview) ────────────────────────
  function _spark(data, color, w=70, h=22) {
    if (!data || !data.length || data.every(v => v === 0))
      return `<svg width="${w}" height="${h}"><line x1="0" y1="${h/2}" x2="${w}" y2="${h/2}" stroke="var(--fg-5,#3F4147)" stroke-width="1" stroke-dasharray="2 3"/></svg>`;
    const mn=Math.min(...data), mx=Math.max(...data), rng=mx-mn||1;
    const sx=w/(data.length-1||1);
    const pts=data.map((v,i)=>[i*sx,h-2-((v-mn)/rng)*(h-4)]);
    const pd=pts.map((p,i)=>(i===0?`M${p[0].toFixed(1)},${p[1].toFixed(1)}`:`L${p[0].toFixed(1)},${p[1].toFixed(1)}`)).join(' ');
    const gid='sp'+Math.random().toString(36).slice(2,7);
    return `<svg width="${w}" height="${h}" style="display:block"><defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${color}" stop-opacity="0.28"/><stop offset="100%" stop-color="${color}" stop-opacity="0"/></linearGradient></defs><path d="${pd} L${w},${h} L0,${h} Z" fill="url(#${gid})"/><path d="${pd}" fill="none" stroke="${color}" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  }

  async function loadAlerts() {
    const set = (id, text) => { const el = document.getElementById(id); if (el) el.textContent = text; };
    const setHtml = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
    set('alertsKpiTotal', '—');
    set('alertsKpiCritical', '—');
    set('alertsKpiHigh', '—');
    set('alertsKpiMedLow', '—');
    const dash = await fetchJson(API.alertsDashboard).catch(e => ({ error: e }));

    const total    = dash.error ? 0 : (dash.total_24h ?? 0);
    const sev      = dash.error ? {} : (dash.severity_24h || {});
    const critical = sev.critical ?? 0;
    const high     = sev.high ?? 0;
    const medLow   = (sev.medium ?? 0) + (sev.low ?? 0);
    // Topbar status
    const tbStatus = document.getElementById('tb2Status');
    if (tbStatus) {
      tbStatus.className = critical > 0 ? 'tb2-status crit' : 'tb2-status ok';
      tbStatus.innerHTML = `<span class="tb2-status-dot"></span> ${critical > 0 ? 'active incidents' : 'all clear'}`;
    }

    const kpis = [
      { val:'alertsKpiTotal',    tag:'alertsKpiTotalTag',  sub:'alertsKpiTotalSub', spark:'alertsKpiTotalSpark',
        value: total.toLocaleString(), sub: '+events · 24h window',
        tag: total > 0 ? '+' + total : 'IDLE', kind: total > 0 ? 'up' : 'ok',
        sp: [], color: 'var(--low)' },
      { val:'alertsKpiCritical', tag:'alertsKpiCritTag',  sub:'alertsKpiCritSub',  spark:'alertsKpiCritSpark',
        value: String(critical), sub: critical > 0 ? critical + ' need attention' : 'level 12+',
        tag: critical > 0 ? 'ATTN' : 'CLEAR', kind: critical > 0 ? 'crit' : 'ok',
        sp: [], color: 'var(--crit)', cls: critical > 0 ? 'crit' : '' },
      { val:'alertsKpiHigh',     tag:'alertsKpiHighTag',  sub:'alertsKpiHighSub',  spark:'alertsKpiHighSpark',
        value: String(high), sub: 'level 8–11',
        tag: high > 0 ? '+' + high : 'CLEAR', kind: high > 0 ? 'up' : 'ok',
        sp: [], color: 'var(--high)' },
      { val:'alertsKpiMedLow',   tag:'alertsKpiMedTag',   sub:'alertsKpiMedSub',   spark:'alertsKpiMedSpark',
        value: String(medLow), sub: 'level 1–7',
        tag: medLow > 0 ? 'OK' : 'BASELINE', kind: 'ok',
        sp: [], color: 'var(--med)' },
    ];
    kpis.forEach(k => {
      const vEl = document.getElementById(k.val); if (vEl) { vEl.textContent = k.value; if (k.cls) vEl.classList.add(k.cls); }
      const tEl = document.getElementById(k.tag); if (tEl) { tEl.textContent = k.tag; tEl.className = `kpi-tag ${k.kind}`; }
      const sEl = document.getElementById(k.sub); if (sEl) sEl.textContent = k.sub;
      const spEl= document.getElementById(k.spark); if (spEl) spEl.innerHTML = _spark(k.sp, k.color);
    });
    const metaEl = document.getElementById('alertsTotalMeta');
    if (metaEl) metaEl.textContent = total.toLocaleString();

    // Timeline
    const trendData = (dash.timeline_24h_by_severity || []).map(t => ({
      crit: t.critical||0, high: t.high||0, med: t.medium||0, low: t.low||0
    }));
    drawTimeline('alertsTimelineCanvas', trendData, trendData[0]?.crit !== undefined ? null : null);
    let peakVal = 0;
    trendData.forEach(t => { const v=(t.crit||0)+(t.high||0)+(t.med||0)+(t.low||0); if(v>peakVal) peakVal=v; });
    const peakEl = document.getElementById('alertsTimelinePeak');
    if (peakEl) peakEl.textContent = peakVal > 0 ? `Peak ${peakVal} · 19:00 UTC` : '';
    const tDot = document.getElementById('alertsTrendDot');
    if (tDot) tDot.style.background = peakVal > 0 ? 'var(--low)' : 'var(--ok)';

    // Categories
    const catData = (dash.top_categories || []).map(c => ({
      name: c.key, count: c.count, sev: (c.count > 100 ? 'high' : c.count > 50 ? 'med' : 'low')
    }));
    const catEl = document.getElementById('alertsTopCategories');
    if (catEl) {
      if (!catData.length) {
        catEl.innerHTML = `<div class="chart-empty"><div class="chart-empty-icon info"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg></div><div class="chart-empty-msg">No categories yet</div><div class="chart-empty-sub">Categories appear as rules trigger across the fleet</div></div>`;
      } else {
        const maxC = Math.max(...catData.map(c => c.count), 1);
        catEl.innerHTML = catData.slice(0,6).map((c,i) => {
          const pct = Math.min(100, (c.count/maxC)*100);
          return `<div class="row"><span class="row-num">${i+1}</span><div class="row-main"><span class="row-pri mono">${escapeHtml(String(c.name).slice(0,34))}</span><span class="row-sec">rule group</span></div><div class="row-bar ${c.sev === 'med' ? 'med' : c.sev === 'low' ? 'low' : ''}"><i style="width:${pct}%"></i></div><span class="row-meta">${c.count}</span></div>`;
        }).join('');
        const cDot = document.getElementById('alertsCatDot');
        if (cDot) cDot.style.background = 'var(--high)';
      }
    }

    // Top affected agents
    const agData = (dash.top_agents || []).map(a => ({
      host: a.key, count: a.count, sev: (a.count > 70 ? 'crit' : a.count > 40 ? 'high' : a.count > 20 ? 'med' : 'low')
    }));
    const agEl = document.getElementById('alertsTopAgents');
    if (agEl) {
      if (!agData.length) {
        agEl.innerHTML = `<div class="chart-empty"><div class="chart-empty-icon info"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 9h6v6H9z"/></svg></div><div class="chart-empty-msg">No affected endpoints</div><div class="chart-empty-sub">Endpoints will appear here when alerts fire against them</div></div>`;
      } else {
        agEl.innerHTML = agData.slice(0,6).map((a,i) => {
          const sev = a.sev || 'low';
          return `<div class="row"><span class="row-num">${i+1}</span><div class="row-main"><span class="row-pri mono" style="font-family:var(--font-mono)">${escapeHtml(String(a.host).slice(0,22))}</span><span class="row-sec">agent</span></div><span class="pill ${sev}">${sev}</span><span class="row-meta">${a.count}</span></div>`;
        }).join('');
        const aDot = document.getElementById('alertsAgentsDot');
        if (aDot) aDot.style.background = 'var(--crit)';
      }
    }

    // Active incidents — keep agent_id and rule_id for Investigate button
    const incData  = (dash.incidents || []).map(a => ({
      time: a.timestamp ? new Date(a.timestamp).toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit',second:'2-digit'}) : '—',
      sev: parseInt(a.rule_level,10) >= 12 ? 'crit' : 'high',
      title: (a.rule_description || '—').slice(0,55),
      affected: a.agent_name || a.agent_id || '—',
      agent_id: a.agent_id || '',
      rule_id: a.rule_id || '',
      status: 'in-triage',
    }));
    const incWrap  = document.getElementById('alertsIncidentsWrap');
    const incDot   = document.getElementById('alertsIncidentDot');
    const incMeta  = document.getElementById('alertsIncidentsMeta');
    if (incWrap) {
      if (!incData.length) {
        incWrap.innerHTML = `<div class="sigil-block"><div class="sigil" style="background:radial-gradient(circle,rgba(52,211,153,0.10),transparent 70%);color:#34D399"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg></div><div class="sigil-text"><h4>No active incidents</h4><p>The platform has no open high-severity incidents. Lower-severity alerts continue to be triaged automatically.</p></div><div style="flex:1"></div><button class="act-btn" onclick="goToPage('threat-hunting')"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M22 12h-4M6 12H2M12 6V2M12 22v-4"/></svg>Threat hunt</button><button class="act-btn" onclick="goToPage('discover')"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>Open Discover</button></div>`;
        if (incDot) incDot.style.background = 'var(--ok)';
        if (incMeta) incMeta.textContent = '';
      } else {
        const critCount = incData.filter(r => r.sev === 'crit').length;
        if (incDot)  { incDot.style.background = 'var(--crit)'; incDot.style.boxShadow = '0 0 6px var(--crit)'; }
        if (incMeta) incMeta.textContent = `${incData.length} open · ${critCount} critical`;
        const statusColor = s => s === 'in-triage' ? 'var(--crit)' : s === 'investigating' ? 'var(--high)' : 'var(--low)';
        incWrap.innerHTML = `<div class="tbl">
          <div class="tbl-h" style="grid-template-columns:78px 80px 1fr 130px 110px 90px">
            <span>Time</span><span>Severity</span><span>Incident</span><span>Affected</span><span>Status</span><span>Action</span>
          </div>
          ${incData.map(r => `<div class="tbl-r" style="grid-template-columns:78px 80px 1fr 130px 110px 90px">
            <span class="tbl-time">${escapeHtml(r.time)}</span>
            <span><span class="pill ${r.sev}">${r.sev}</span></span>
            <span class="tbl-pri">${escapeHtml(r.title)}</span>
            <span class="tbl-mono">${escapeHtml(r.affected)}</span>
            <span class="tbl-muted"><span style="width:6px;height:6px;border-radius:50%;background:${statusColor(r.status)};flex-shrink:0;display:inline-block"></span>${escapeHtml(r.status)}</span>
            <span><a href="#" class="tbl-link" onclick="event.preventDefault();investigateIncident('${escapeHtml(r.agent_id)}','${escapeHtml(r.rule_id)}')">Investigate →</a></span>
          </div>`).join('')}
        </div>`;
      }
    }
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
    'timestamp', 'rule_level', 'title', 'agent_name',
    'src_ip', 'dst_ip', 'username', 'process_name',
    'win_event_id', 'rule_groups', 'event_category',
    'rule_id', 'rule_description', 'agent_id',
  ];
  // Default columns shown in the table
  let discoverSelectedFields = ['timestamp', 'rule_level', 'title', 'agent_name', 'src_ip', 'username', 'process_name'];
  let discoverDslFilters = [];

  function getDiscoverParams() {
    const sel = document.getElementById('discoverTimeRange');
    // Default 7d (was 24h). Discover reads from OpenSearch via the Kafka
    // pipeline; alerts take a few seconds to index and operators usually want
    // to see "what happened recently", not just today. The Alerts page already
    // covers live 24h. A wider Discover default also avoids the "0 hits but
    // there's data 25h ago" confusion users hit on day-1.
    let range = sel?.value || '7d';
    if (range === 'custom') {
      const from = sel.getAttribute('data-custom-from');
      const to   = sel.getAttribute('data-custom-to');
      if (from && to) range = `custom:${from}|${to}`;
      else range = '7d';
    }
    const b = getTimeRangeBounds(range);
    const time_from = b.time_from;
    const time_to   = b.time_to;
    const min_level = document.getElementById('discoverSeverity')?.value ? parseInt(document.getElementById('discoverSeverity').value, 10) : undefined;
    const agent_id = document.getElementById('discoverAgent')?.value || undefined;
    const rule_group = document.getElementById('discoverGroup')?.value || undefined;
    const mitre = document.getElementById('discoverMitre')?.value || undefined;
    const compliance = document.getElementById('discoverCompliance')?.value || undefined;
    const search = (document.getElementById('discoverSearch')?.value || '').trim() || undefined;
    return { range, time_from, time_to, min_level, agent_id, rule_group, mitre, compliance, search };
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
    if (type === 'text' || type === 'txt') return field + '.keyword';
    return field;
  }

  function buildDiscoverDsl() {
    const params = getDiscoverParams();
    const must = [];
    if (params.time_from && params.time_to) {
      must.push({ range: { timestamp: { gte: params.time_from, lte: params.time_to } } });
    }
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
    // MITRE ATT&CK filter
    if (params.mitre) {
      must.push({ bool: { should: [
        { term: { 'rule_groups.keyword': params.mitre } },
        { match: { 'rule_groups': params.mitre } },
        { term: { 'mitre.id': params.mitre } },
        { term: { 'mitre.technique_id': params.mitre } },
        { term: { 'mitre.tactic': params.mitre } },
      ], minimum_should_match: 1 } });
    }
    // Compliance filter
    if (params.compliance) {
      must.push({ exists: { field: params.compliance } });
    }
    // Search: try KQL parser first, fall back to multi_match
    if (params.search && params.search.trim()) {
      const kqlClause = parseKqlQuery(params.search.trim());
      if (kqlClause) {
        must.push(kqlClause);
      } else {
        must.push({ multi_match: {
          query: params.search.trim(),
          fields: ['rule_description^3', 'title^3', 'rule_groups^2', 'agent_name^2', 'agent_id',
                   'src_ip^2', 'dst_ip', 'username^2', 'process_name^2',
                   'event_data.srcip^2', 'event_data.dstuser', 'event_data.commandline'],
          type: 'best_fields', operator: 'or',
        }});
      }
    }
    // Pinned + session filters
    const allFilters = [...discoverPinnedFilters.filter(f => !discoverDslFilters.some(df => df.field === f.field && df.value === f.value)), ...discoverDslFilters];
    allFilters.forEach((f) => {
      // IOC special filter
      if (f._ioc && f._dsl) { must.push(f._dsl); return; }
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
      } else if (op === 'matches' && val !== '') {
        clause = { wildcard: { [exactField]: { value: val, case_insensitive: true } } };
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
    // Pinned filters first
    discoverPinnedFilters.forEach((f, i) => {
      const label = (f.field || '') + ' ' + (f.op || '') + (f.value ? ' ' + f.value : '');
      pills.push({ label: label.slice(0, 40) + (label.length > 40 ? '…' : ''), pinned: true, clear: () => { discoverPinnedFilters.splice(i, 1); try { localStorage.setItem('disc_pinned_filters', JSON.stringify(discoverPinnedFilters)); } catch(e){} renderDiscoverFilterPills(); discoverOffset = 0; loadDiscover(); } });
    });
    discoverDslFilters.forEach((f, i) => {
      const label = f._ioc ? 'IOC: ' + f.value : (f.negate ? 'NOT ' + f.field + ' ' + f.op + (f.value ? ' ' + f.value : '') : (f.field || '') + ' ' + (f.op || '') + (f.value ? ' ' + f.value : ''));
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
    if (params.mitre) pills.push({ label: 'MITRE: ' + params.mitre, clear: () => { const el = document.getElementById('discoverMitre'); if (el) el.value = ''; loadDiscover(); } });
    if (params.compliance) pills.push({ label: 'Compliance: ' + params.compliance, clear: () => { const el = document.getElementById('discoverCompliance'); if (el) el.value = ''; loadDiscover(); } });
    if (params.search) pills.push({ label: 'Search: ' + params.search.slice(0, 20) + (params.search.length > 20 ? '…' : ''), clear: () => { const el = document.getElementById('discoverSearch'); if (el) el.value = ''; loadDiscover(); } });
    const el = document.getElementById('discoverFilterPills');
    if (!el) return;
    el.innerHTML = pills.length ? pills.map(p => '<span class="filter-pill' + (p.pinned ? ' pinned' : '') + '">' + escapeHtml(p.label) + ' <button type="button" class="filter-pill-remove" aria-label="Remove">×</button></span>').join('') : '';
    el.querySelectorAll('.filter-pill-remove').forEach((btn, i) => { btn.addEventListener('click', () => pills[i].clear()); });
  }

  const DISC_FIELD_TYPES = {
    'timestamp':'date',
    'rule_id':'kw', 'rule_level':'num', 'rule_description':'txt', 'rule_groups':'kw',
    'agent_id':'kw', 'agent_name':'kw', 'agent_ip':'ip',
    'title':'txt', 'event_type':'kw',
    'event_data.type':'kw', 'event_data.srcip':'ip', 'event_data.dstuser':'kw',
    'net_remote':'ip', 'net_local':'ip', 'net_status':'kw',
    'proc_name':'txt', 'proc_pid':'num', 'proc_cmdline':'txt',
    'file.hash.sha256':'kw',
  };

  const DISC_FALLBACK_FIELDS = Object.keys(DISC_FIELD_TYPES).map(n => ({ name: n, type: DISC_FIELD_TYPES[n] }));

  async function loadDiscoverFields() {
    const res = await fetchJson(API.discoverFields).catch(() => ({ fields: [] }));
    const apiList = res.fields || [];
    const list = apiList.length > 0 ? apiList : DISC_FALLBACK_FIELDS;
    discoverAvailableFieldsList = list;
    renderDiscoverFieldsSidebar();
    const fieldSelect = document.getElementById('discoverFilterField');
    if (fieldSelect) {
      const current = fieldSelect.value;
      fieldSelect.innerHTML = '<option value="">Field…</option>' + list.map((f) => '<option value="' + escapeHtml(f.name) + '" data-type="' + escapeHtml(f.type || 'keyword') + '">' + escapeHtml(f.name) + '</option>').join('');
      if (current && list.some((f) => f.name === current)) fieldSelect.value = current;
    }
  }
  const DISC_TYPE_LABELS = { kw: 'keyword', num: 'number', txt: 'text', ip: 'ip', date: 'date', bool: 'boolean', geo: 'geo' };
  function _discTypeLabel(name) {
    const apiType = (discoverAvailableFieldsList.find(f => f.name === name) || {}).type;
    const t = apiType || DISC_FIELD_TYPES[name] || 'kw';
    return DISC_TYPE_LABELS[t] || t;
  }
  function _discFieldRow(name, isSelected, draggable) {
    const typeLabel = _discTypeLabel(name);
    const act  = isSelected ? '−' : '+';
    const cls  = isSelected ? 'v2-field-row selected' : 'v2-field-row';
    const drag = draggable ? ' draggable="true"' : '';
    const handle = draggable ? '<span class="v2-field-drag" title="Drag to reorder" style="cursor:grab;color:var(--fg-4);padding:0 2px;font-size:11px">⋮⋮</span>' : '';
    return `<div class="${cls}" data-field="${escapeHtml(name)}" data-selected="${isSelected}"${drag}>
      ${handle}
      <span class="v2-field-name" style="flex:1;min-width:0;font-family:var(--font-mono);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${escapeHtml(name)}">${escapeHtml(name)}</span>
      <span class="v2-field-type" style="color:var(--fg-4);font-size:10px;margin:0 6px">${typeLabel}</span>
      <span class="v2-field-act" style="cursor:pointer;padding:0 6px;font-weight:600" title="${isSelected ? 'Remove column' : 'Add column'}">${act}</span>
    </div>`;
  }

  // Drag-to-reorder for the Selected list. Reorders by field name so it works
  // regardless of which rows the search filter is currently showing.
  function _wireSelectedDrag(container) {
    let dragName = null;
    container.querySelectorAll('.v2-field-row.selected').forEach(row => {
      row.addEventListener('dragstart', () => { dragName = row.getAttribute('data-field'); row.style.opacity = '0.4'; });
      row.addEventListener('dragend', () => { row.style.opacity = ''; });
      row.addEventListener('dragover', (e) => { e.preventDefault(); });
      row.addEventListener('drop', (e) => {
        e.preventDefault();
        const targetName = row.getAttribute('data-field');
        if (!dragName || dragName === targetName) return;
        const from = discoverSelectedFields.indexOf(dragName);
        const to = discoverSelectedFields.indexOf(targetName);
        if (from < 0 || to < 0) return;
        discoverSelectedFields.splice(from, 1);
        discoverSelectedFields.splice(to, 0, dragName);
        renderDiscoverFieldsSidebar(); renderDiscoverThead(); discoverOffset = 0; loadDiscover();
      });
    });
  }

  // Renders the column-manager modal contents. (Named "...Sidebar" for history;
  // the old left sidebar was replaced by the "Columns" modal.)
  function renderDiscoverFieldsSidebar() {
    const fieldSearchVal = (document.getElementById('discoverFieldSearch')?.value || '').toLowerCase();
    const filterBySearch = (name) => !fieldSearchVal || name.toLowerCase().includes(fieldSearchVal);
    const available = discoverAvailableFieldsList.filter((f) => !discoverSelectedFields.includes(f.name) && filterBySearch(f.name));
    const selectedEl  = document.getElementById('discoverSelectedFields');
    const popularEl   = document.getElementById('discoverPopularFields');
    const availableEl = document.getElementById('discoverAvailableFields');

    if (selectedEl) {
      const selFiltered = discoverSelectedFields.filter(filterBySearch);
      selectedEl.innerHTML = selFiltered.length
        ? selFiltered.map(n => _discFieldRow(n, true, !fieldSearchVal)).join('')
        : (discoverSelectedFields.length ? '<div class="disc-col-empty" style="padding:6px 4px;font-size:11px;color:var(--fg-4)">No match</div>' : '<div class="disc-col-empty" style="padding:6px 4px;font-size:11px;color:var(--fg-4)">None selected</div>');
      selectedEl.querySelectorAll('.v2-field-row.selected').forEach((row) => {
        row.querySelector('.v2-field-act')?.addEventListener('click', () => {
          const name = row.getAttribute('data-field');
          const idx = discoverSelectedFields.indexOf(name);
          if (idx >= 0) discoverSelectedFields.splice(idx, 1);
          renderDiscoverFieldsSidebar(); renderDiscoverThead(); discoverOffset = 0; loadDiscover();
        });
      });
      if (!fieldSearchVal) _wireSelectedDrag(selectedEl);
      const selCntEl = document.getElementById('discoverSelectedCount');
      if (selCntEl) selCntEl.textContent = discoverSelectedFields.length;
    }

    const popFiltered = DISCOVER_POPULAR_FIELDS.filter(n => !discoverSelectedFields.includes(n) && filterBySearch(n));
    if (popularEl) {
      popularEl.innerHTML = popFiltered.length ? popFiltered.map(n => _discFieldRow(n, false)).join('') : '<div class="disc-col-empty" style="padding:6px 4px;font-size:11px;color:var(--fg-4)">—</div>';
      popularEl.querySelectorAll('.v2-field-row').forEach((row) => {
        row.querySelector('.v2-field-act')?.addEventListener('click', () => {
          const name = row.getAttribute('data-field');
          if (name && !discoverSelectedFields.includes(name)) { discoverSelectedFields.push(name); renderDiscoverFieldsSidebar(); renderDiscoverThead(); discoverOffset = 0; loadDiscover(); }
        });
      });
    }

    if (availableEl) {
      const avSource = available.length ? available.slice(0, 200) : (!fieldSearchVal ? [
        {name:'agent.name'},{name:'agent.ip'},{name:'host.os'},{name:'user.name'},{name:'rule.mitre.id'},{name:'rule.mitre.tactic'},{name:'data.win.event'},{name:'data.srcip'},{name:'data.dstport'},{name:'file.hash.sha256'},
      ].filter(f => filterBySearch(f.name)) : []);
      // Group by top-level prefix so the long event_data.* list collapses visually.
      const groups = {};
      avSource.forEach(f => {
        const nm = f.name || f;
        const prefix = nm.includes('.') ? nm.split('.')[0] : '_core';
        (groups[prefix] = groups[prefix] || []).push(nm);
      });
      const groupNames = Object.keys(groups).sort((a, b) => a === '_core' ? -1 : b === '_core' ? 1 : a.localeCompare(b));
      let html = '';
      groupNames.forEach(g => {
        const label = g === '_core' ? 'Core fields' : g + '.*';
        html += `<div class="disc-col-group" style="font-size:10px;text-transform:uppercase;letter-spacing:.04em;color:var(--fg-4);padding:8px 4px 3px;border-bottom:1px solid var(--border);margin-top:4px">${escapeHtml(label)} <span style="opacity:.7">${groups[g].length}</span></div>`;
        groups[g].forEach(nm => { html += _discFieldRow(nm, false); });
      });
      availableEl.innerHTML = html || '<div class="disc-col-empty" style="padding:6px 4px;font-size:11px;color:var(--fg-4)">No matching fields</div>';
      availableEl.querySelectorAll('.v2-field-row').forEach((row) => {
        row.querySelector('.v2-field-act')?.addEventListener('click', () => {
          const name = row.getAttribute('data-field');
          if (name && !discoverSelectedFields.includes(name)) { discoverSelectedFields.push(name); renderDiscoverFieldsSidebar(); renderDiscoverThead(); discoverOffset = 0; loadDiscover(); }
        });
      });
      const cntEl = document.getElementById('discoverAvailCount');
      if (cntEl) cntEl.textContent = avSource.length;
    }
  }

  function _discoverColWidths() {
    return discoverSelectedFields.map(c => {
      if (c === 'timestamp') return '150px';
      if (c === 'rule_level') return '60px';
      if (c === 'rule_id') return '70px';
      if (c === 'rule_description' || c === 'title') return 'minmax(200px, 1fr)';
      if (c === 'rule_groups') return '140px';
      return '140px';
    }).join(' ') + ' 44px';
  }

  function renderDiscoverThead() {
    const cols = discoverSelectedFields.slice();
    const thead = document.getElementById('discoverThead');
    if (!thead) return;
    const colWidths = _discoverColWidths();
    thead.style.gridTemplateColumns = colWidths;
    const sortable = ['timestamp', 'rule_level', 'rule_id', 'agent_name'];
    thead.innerHTML = cols.map((c) => {
      const label = FIELD_LABELS[c] || c;
      const isSorted = c === discoverSortField;
      const sortIcon = isSorted ? (discoverSortOrder === 'desc' ? ' ↓' : ' ↑') : '';
      const cls = sortable.includes(c) ? ' class="sortable-th"' : '';
      return '<span' + cls + ' data-field="' + escapeHtml(c) + '"><span class="th-label" title="' + escapeHtml(label) + '">' + escapeHtml(label) + sortIcon + '</span>' +
        '<button type="button" class="th-stats" data-statsfield="' + escapeHtml(c) + '" title="Field statistics" style="background:none;border:none;color:var(--fg-4);cursor:pointer;font-size:10px;padding:0 2px;line-height:1">≡</button></span>';
    }).join('') + '<span></span>';
    thead.querySelectorAll('.th-stats').forEach(btn => {
      btn.addEventListener('click', (e) => { e.stopPropagation(); showFieldStats(btn.getAttribute('data-statsfield'), btn); });
    });
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
    // Core
    'timestamp':       'Time',
    'title':           'Alert Title',
    'rule_id':         'Rule ID',
    'rule_level':      'Severity',
    'rule_description':'Description',
    'rule_groups':     'Rule Groups',
    // Agent
    'agent_id':        'Agent ID',
    'agent_name':      'Agent',
    // Network — normalized top-level fields (new)
    'src_ip':          'Source IP',
    'dst_ip':          'Dest IP',
    'src_hostname':    'Source Host',
    // Identity & process — normalized top-level fields (new)
    'username':        'Username',
    'process_name':    'Process',
    // Windows
    'win_event_id':    'Win Event ID',
    // Event meta
    'event_type':      'Event Type',
    'event_category':  'Category',
    // Legacy aliases (kept for backwards compat)
    'event_data.type': 'Event Type',
  };

  function renderDiscoverRows(alerts) {
    const cols = discoverSelectedFields;
    const colWidths = _discoverColWidths();
    if (!alerts || alerts.length === 0) return '<div class="tbl-r" style="grid-template-columns:1fr"><span class="empty-msg">No alerts</span></div>';
    const levelBadge = (l) => {
      const n = Number(l);
      const cls = n >= 12 ? 'disc-lvl disc-lvl-crit' : n >= 8 ? 'disc-lvl disc-lvl-high' : n >= 4 ? 'disc-lvl disc-lvl-med' : 'disc-lvl disc-lvl-low';
      return '<span class="' + cls + '">' + n + '</span>';
    };
    const formatVal = (v, path) => {
      if (v == null || v === '') return '<span class="disc-empty">—</span>';
      if (path === 'timestamp' && (typeof v === 'string' || typeof v === 'number')) {
        const d = new Date(v);
        if (isNaN(d.getTime())) return escapeHtml(String(v));
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
      const rowClass = 'tbl-r discover-row' + (level >= 12 ? ' row-crit' : level >= 8 ? ' row-high' : '');
      const cells = cols.map((path) => {
        let v = getByPath(src, path);
        if ((path === 'agent_id' || path === 'agent.id') && v && discoverAgentMap[v]) {
          return '<span class="discover-td"><span title="' + escapeHtml(v) + '">' + escapeHtml(discoverAgentMap[v]) + '</span></span>';
        }
        return '<span class="discover-td">' + formatVal(v, path) + '</span>';
      });
      const tags = discoverGetTags(a);
      const tagBadges = tags.map(t => '<span class="disc-tag-badge">' + escapeHtml(t) + '</span>').join('');
      const bookmarked = discoverBookmarks.has(_alertId(a));
      cells.push('<span class="discover-td-action">' +
        '<button type="button" class="disc-bookmark-btn' + (bookmarked ? ' active' : '') + '" title="' + (bookmarked ? 'Remove bookmark' : 'Bookmark event') + '" data-index="' + i + '">★</button>' +
        (tagBadges ? '<span style="display:flex;gap:2px;flex-wrap:wrap">' + tagBadges + '</span>' : '') +
        '<button type="button" class="btn-disc-detail" title="Inspect event (click row or this button)">⊕</button>' +
        '</span>');
      return '<div class="' + rowClass + '" data-index="' + i + '" style="grid-template-columns:' + colWidths + '">' + cells.join('') + '</div>';
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

  let _discoverCurrentAlert = null;
  let _aiSummaryCache = {};

  function openDiscoverDetail(alert) {
    const panel = document.getElementById('discoverDetailPanel');
    const titleEl = document.getElementById('discoverDetailTitle');
    const contentEl = document.getElementById('discoverDetailContent');
    const jsonEl = document.getElementById('discoverDetailJson');
    if (!panel || !contentEl) return;
    _discoverCurrentAlert = alert;
    // Reset to table tab when opening a new alert
    const aiEl = document.getElementById('discoverDetailAi');
    if (aiEl) aiEl.classList.add('hidden');
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
    // Reset timeline
    const timelineEl = document.getElementById('discoverDetailTimeline');
    if (timelineEl) { timelineEl.innerHTML = ''; timelineEl.classList.add('hidden'); }
    contentEl.classList.remove('hidden');
    document.querySelectorAll('.discover-detail-tab').forEach((t) => {
      t.classList.toggle('active', t.getAttribute('data-tab') === 'table');
    });
    // Wire detail action buttons
    document.getElementById('discoverDetailCopyJson')?.addEventListener('click', () => {
      const json = JSON.stringify(alert.source || {}, null, 2);
      if (navigator.clipboard) navigator.clipboard.writeText(json).then(() => showDiscoverToast('JSON copied'));
      else { const t=document.createElement('textarea');t.value=json;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showDiscoverToast('JSON copied'); }
    }, { once: true });
    document.getElementById('discoverDetailTagBtn')?.addEventListener('click', () => discoverShowTagModal(alert), { once: true });
    document.getElementById('discoverDetailCorrelateBtn')?.addEventListener('click', () => { discoverShowCorrelation(alert); closeDiscoverDetail(); }, { once: true });
    document.getElementById('discoverDetailViewRule')?.addEventListener('click', () => {
      const ruleId = (alert.source || {}).rule_id || alert.rule_id;
      if (ruleId) { closeDiscoverDetail(); goToPage('rules'); setTimeout(() => { const el = document.getElementById('rulesSearch'); if (el) { el.value = String(ruleId); el.dispatchEvent(new Event('input')); } }, 200); }
      else showDiscoverToast('No rule ID for this event');
    }, { once: true });
  }

  function setDiscoverDetailTab(tab) {
    const contentEl = document.getElementById('discoverDetailContent');
    const jsonEl = document.getElementById('discoverDetailJson');
    const aiEl = document.getElementById('discoverDetailAi');
    const timelineEl = document.getElementById('discoverDetailTimeline');
    document.querySelectorAll('.discover-detail-tab').forEach((t) => {
      t.classList.toggle('active', t.getAttribute('data-tab') === tab);
    });
    if (contentEl) contentEl.classList.add('hidden');
    if (jsonEl) jsonEl.classList.add('hidden');
    if (aiEl) aiEl.classList.add('hidden');
    if (timelineEl) timelineEl.classList.add('hidden');
    if (tab === 'json') {
      if (jsonEl) jsonEl.classList.remove('hidden');
    } else if (tab === 'ai') {
      if (aiEl) aiEl.classList.remove('hidden');
      if (_discoverCurrentAlert) loadAiSummary(_discoverCurrentAlert);
    } else if (tab === 'timeline') {
      if (timelineEl) { timelineEl.classList.remove('hidden'); if (_discoverCurrentAlert) discoverLoadTimeline(_discoverCurrentAlert); }
    } else {
      if (contentEl) contentEl.classList.remove('hidden');
    }
  }

  async function loadAiSummary(alert) {
    const container = document.getElementById('aiSummaryContent');
    if (!container) return;

    const src = alert.source || {};
    const alertId = src.id || src._id || alert.id || '';
    if (alertId && _aiSummaryCache[alertId]) {
      renderAiSummary(container, _aiSummaryCache[alertId]);
      return;
    }

    container.innerHTML = '<p class="ai-summary-loading">Analyzing alert with Claude AI...</p>';

    const payload = {
      alert: {
        id: alertId,
        rule_id: src.rule_id || (src.rule && src.rule.id) || '',
        rule_level: src.rule_level || (src.rule && src.rule.level) || 0,
        title: src.rule_description || (src.rule && src.rule.description) || 'Security Alert',
        description: src.rule_description || (src.rule && src.rule.description) || '',
        agent_id: src.agent_id || (src.agent && src.agent.id) || '',
        timestamp: src.timestamp || alert.timestamp || '',
        event_data: src.event_data || src.data || {},
        rule_groups: src.rule_groups || (src.rule && src.rule.groups) || [],
      },
    };

    try {
      const res = await fetch('/api/ai/summarize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (alertId) _aiSummaryCache[alertId] = data;
      renderAiSummary(container, data);
    } catch (e) {
      container.innerHTML = '<p class="ai-summary-error">Failed to fetch AI summary: ' + escapeHtml(String(e)) + '</p>';
    }
  }

  function renderAiSummary(container, data) {
    if (!container) return;
    if (data.error && data.model === 'fallback') {
      // Fallback mode — still render but show note
    }
    const fpColor = data.false_positive_likelihood === 'low' ? '#2ecc71' : data.false_positive_likelihood === 'high' ? '#e74c3c' : '#f39c12';
    const modelBadge = data.cached ? ' (cached)' : '';
    const isAi = data.model && data.model !== 'fallback';

    const actions = (data.recommended_actions || []).map(a => '<li>' + escapeHtml(a) + '</li>').join('');

    container.innerHTML = `
      <div class="ai-badge">${isAi ? '🤖 Claude AI' + modelBadge : '⚙ Rule-based fallback'}</div>
      <section class="ai-section">
        <h4 class="ai-section-title">Executive Summary</h4>
        <p class="ai-text">${escapeHtml(data.executive_summary || '—')}</p>
      </section>
      <section class="ai-section">
        <h4 class="ai-section-title">Technical Analysis</h4>
        <p class="ai-text">${escapeHtml(data.technical_analysis || '—')}</p>
      </section>
      <section class="ai-section">
        <h4 class="ai-section-title">Recommended Actions</h4>
        <ol class="ai-actions">${actions || '<li>No specific actions provided.</li>'}</ol>
      </section>
      <section class="ai-section">
        <h4 class="ai-section-title">MITRE ATT&amp;CK Context</h4>
        <p class="ai-text">${escapeHtml(data.mitre_context || '—')}</p>
      </section>
      <section class="ai-section">
        <h4 class="ai-section-title">Severity Explanation</h4>
        <p class="ai-text">${escapeHtml(data.severity_explanation || '—')}</p>
      </section>
      <section class="ai-section">
        <h4 class="ai-section-title">False Positive Assessment</h4>
        <p class="ai-text">
          <span style="color:${fpColor};font-weight:600;">${escapeHtml((data.false_positive_likelihood || '—').toUpperCase())}</span>
          likelihood — ${escapeHtml(data.false_positive_reason || '—')}
        </p>
      </section>
    `;
  }

  async function initDiscoverDropdowns() {
    if (discoverDropdownsLoaded) return;
    const [agentsRes, groupsRes] = await Promise.all([
      fetchJson(API.agents + '?limit=200').catch(() => ({ agents: [] })),
      fetchJson(API.alertsRuleGroups).catch(() => []),
    ]);
    const agentSelect = document.getElementById('discoverAgent');
    if (agentSelect) {
      const _agRaw = Array.isArray(agentsRes) ? agentsRes : (agentsRes?.agents || agentsRes?.data || []);
      const agentList = Array.isArray(_agRaw) ? _agRaw : [];
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

  // Probe: same DSL but with the timestamp range replaced by "last 30 days".
  // Used by the empty-state hint to tell the operator that data exists outside
  // the chosen time window so they don't conclude "no data" when really it's
  // "no data in this 24-hour slice".
  async function probeOutsideTimeWindow(currentDsl, index) {
    try {
      const probe = JSON.parse(JSON.stringify(currentDsl));
      if (probe && probe.query && probe.query.bool && Array.isArray(probe.query.bool.must)) {
        probe.query.bool.must = probe.query.bool.must.filter(c => !(c && c.range && c.range.timestamp));
        probe.query.bool.must.unshift({ range: { timestamp: { gte: 'now-30d' } } });
        if (probe.query.bool.must.length === 1) {
          // collapsed back to time-only — keep as bool so server is happy
        }
      } else {
        probe.query = { bool: { must: [{ range: { timestamp: { gte: 'now-30d' } } }] } };
      }
      const q = new URLSearchParams({ size: '0', offset: '0' });
      const r = await fetch(API.alertsList + '?' + q.toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dsl: probe, index }),
      }).then(r => r.json()).catch(() => ({ total: 0 }));
      return r && typeof r.total === 'number' ? r.total : 0;
    } catch (e) {
      return 0;
    }
  }

  async function loadDiscover() {
    if (discoverAvailableFieldsList.length === 0) await loadDiscoverFields();
    if (!discoverDropdownsLoaded) initDiscoverDropdowns();
    const pageSizeEl = document.getElementById('discoverPageSize');
    if (pageSizeEl) DISCOVER_PAGE_SIZE = parseInt(pageSizeEl.value, 10) || 25;
    const dsl = buildDiscoverDsl();
    const selectedIndex = document.getElementById('discoverIndex')?.value || 'watchvault-alerts-*';
    const q = new URLSearchParams();
    q.set('size', DISCOVER_PAGE_SIZE);
    q.set('offset', String(discoverOffset));
    const listRes = await fetch(API.alertsList + '?' + q.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dsl, index: selectedIndex }),
    }).then((r) => r.json()).catch((e) => ({ error: String(e) }));

    discoverTotal = listRes.error ? 0 : (listRes.total ?? 0);
    const listAlerts = listRes.alerts || [];
    discoverAlertsCache = listAlerts;

    const displayAlerts = listAlerts;
    const displayTotal  = discoverTotal;

    // Update hits count
    const hitsEl = document.getElementById('discoverHits');
    const hitsLbl = document.getElementById('discoverHitsLabel');
    const volDot  = document.getElementById('discoverVolDot');
    const resDot  = document.getElementById('discoverResDot');
    if (hitsEl)  hitsEl.textContent  = displayTotal.toLocaleString();
    if (hitsLbl) hitsLbl.textContent = displayTotal > 0 ? `${displayTotal.toLocaleString()} hits · last 24 h` : 'No hits';
    if (volDot)  volDot.style.background  = displayTotal > 0 ? 'var(--low)' : 'var(--ok)';
    if (resDot)  resDot.style.background  = displayTotal > 0 ? 'var(--low)' : 'var(--fg-4)';

    // Results table
    const resWrap = document.getElementById('discoverResultsWrap');
    if (resWrap) {
      if (displayTotal === 0) {
        // Honest empty state + async probe: if data exists OUTSIDE the chosen
        // time window the operator usually just needs to widen it. Tell them
        // exactly how many they'd see at 30d so the next action is obvious.
        const hintId = 'dsHint_' + Math.random().toString(36).slice(2,8);
        resWrap.innerHTML = `<div class="sigil-block"><div class="sigil" style="background:radial-gradient(circle,rgba(255,255,255,0.04),transparent 70%);color:var(--fg-3)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg></div><div class="sigil-text"><h4>No events found</h4><p>No events match the current filters and time range. Try widening the time window or removing filters.</p><p id="${hintId}" style="margin-top:8px;color:var(--med);font-size:12px;display:none"></p></div><div style="flex:1"></div><button class="act-btn" onclick="discoverDslFilters=[];renderDiscoverFilterPills();loadDiscover()">Reset filters</button></div>`;
        probeOutsideTimeWindow(dsl, selectedIndex).then((n) => {
          if (n > 0) {
            const el = document.getElementById(hintId);
            if (!el) return;
            el.innerHTML = `${n.toLocaleString()} event${n===1?'':'s'} exist outside this window. <a href="#" style="color:var(--accent);text-decoration:underline" onclick="event.preventDefault();var t=document.getElementById('discoverTimeRange');if(t){t.value='30d';loadDiscover();}">Widen to Last 30d →</a>`;
            el.style.display = '';
          }
        });
      } else {
        resWrap.innerHTML = `<div class="tbl"><div class="tbl-h" id="discoverThead"></div><div id="discoverBody">${renderDiscoverRows(displayAlerts)}</div></div>`;
        renderDiscoverThead();
      }
    }

    const showFrom = displayAlerts.length === 0 ? 0 : discoverOffset + 1;
    const showTo   = discoverOffset + displayAlerts.length;
    const footTxt  = `Showing ${showFrom}${displayAlerts.length>0?'–'+showTo:''} of ${displayTotal.toLocaleString()}`;
    const footEl   = document.getElementById('discoverTableFooter');
    const infoEl   = document.getElementById('discoverTableInfo');
    if (footEl) footEl.textContent = footTxt;
    if (infoEl) infoEl.textContent = footTxt;
    document.getElementById('discoverPageInfo').textContent = 'Page ' + (Math.floor(discoverOffset / DISCOVER_PAGE_SIZE) + 1) + ' of ' + (Math.ceil(displayTotal / DISCOVER_PAGE_SIZE) || 1);
    document.getElementById('discoverPrev').disabled = discoverOffset === 0;
    document.getElementById('discoverNext').disabled = discoverOffset + DISCOVER_PAGE_SIZE >= displayTotal;
    renderDiscoverFilterPills();
    drawDiscoverHistogram(listRes.histogram || []);
    discoverUpdateStatsSummary(listAlerts);
    discoverSaveSession();
    discoverSetUrlState();
  }

  function drawDiscoverHistogram(histogram) {
    const canvas = document.getElementById('discoverHistogram');
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const W   = canvas.parentElement?.clientWidth || canvas.offsetWidth || 700;
    const H   = 110;
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';
    canvas.width  = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    const isDark  = document.documentElement.getAttribute('data-theme') !== 'light';
    const bg      = isDark ? '#0f1115' : '#ffffff';
    const gridCol = isDark ? 'rgba(255,255,255,0.055)' : 'rgba(0,0,0,0.07)';
    ctx.fillStyle = bg; ctx.fillRect(0, 0, W, H);

    // Use demo trend if histogram is empty
    const raw = Array.isArray(histogram) && histogram.length > 0 ? histogram : null;
    const buckets = raw || null;

    const P = {l:32,r:8,t:6,b:18};
    const cW = W-P.l-P.r, cH = H-P.t-P.b;

    if (!buckets || buckets.length === 0) {
      ctx.fillStyle = isDark ? '#5E6068' : '#9ca3af';
      ctx.textAlign = 'center'; ctx.font = `11px 'Geist',system-ui,sans-serif`;
      ctx.fillText('No events in selected time range', P.l + cW/2, P.t + cH/2 + 4);
      return;
    }

    const isStacked = buckets[0]?.crit !== undefined;
    const maxVal = isStacked
      ? Math.max(...buckets.map(b => (b.crit||0)+(b.high||0)+(b.med||0)+(b.low||0)), 1)
      : Math.max(...buckets.map(b => b.count||0), 1);
    const n    = buckets.length;
    const stepX= cW / n;
    const barW = Math.max(1, stepX - 2);

    // gridlines
    ctx.strokeStyle = gridCol; ctx.lineWidth = 0.8; ctx.setLineDash([2,3]);
    [0, 0.5, 1].forEach(p => {
      const y = P.t + cH * (1-p);
      ctx.beginPath(); ctx.moveTo(P.l,y); ctx.lineTo(P.l+cW,y); ctx.stroke();
    });
    ctx.setLineDash([]);

    // y-labels
    ctx.fillStyle = isDark ? '#5E6068' : '#9ca3af';
    ctx.textAlign = 'right'; ctx.font = `9px 'Geist Mono','JetBrains Mono',monospace`;
    [0,0.5,1].forEach(p => ctx.fillText(Math.round(maxVal*p), P.l-4, P.t+cH*(1-p)+3));

    // columns
    const sevColors = ['var(--low)','var(--med)','var(--high)','var(--crit)'];
    buckets.forEach((b, i) => {
      const x = P.l + i * stepX + 1;
      let y   = P.t + cH;
      if (isStacked) {
        [b.low||0, b.med||0, b.high||0, b.crit||0].forEach((v, si) => {
          const h = (v / maxVal) * cH;
          y -= h;
          if (h >= 0.5) {
            ctx.fillStyle = sevColors[si];
            ctx.globalAlpha = 0.85;
            ctx.beginPath();
            ctx.roundRect ? ctx.roundRect(x, y, barW, h, [1,1,0,0]) : ctx.fillRect(x, y, barW, h);
            ctx.fill();
            ctx.globalAlpha = 1;
          }
        });
      } else {
        const h = Math.max(1, (b.count||0) / maxVal * cH);
        ctx.fillStyle = 'var(--low)'; ctx.globalAlpha = 0.8;
        ctx.fillRect(x, P.t+cH-h, barW, h);
        ctx.globalAlpha = 1;
      }
    });

    // x-axis labels
    const xLabels = ['00:00','04:00','08:00','12:00','16:00','20:00','now'];
    ctx.fillStyle = isDark ? '#5E6068' : '#9ca3af';
    ctx.textAlign = 'center'; ctx.font = `9px 'Geist Mono','JetBrains Mono',monospace`;
    xLabels.forEach((lbl, li) => {
      ctx.fillText(lbl, P.l + (li/(xLabels.length-1))*cW, H-4);
    });

    // Axis labels — first and last bucket timestamp
    ctx.fillStyle = 'rgba(138,170,208,0.7)';
    ctx.font = '9px JetBrains Mono, monospace';
    if (buckets[0]?.ts) {
      ctx.textAlign = 'left';
      ctx.fillText(new Date(buckets[0].ts).toLocaleDateString(), P.l + 2, H - 2);
    }
    if (buckets[buckets.length - 1]?.ts) {
      ctx.textAlign = 'right';
      ctx.fillText(new Date(buckets[buckets.length - 1].ts).toLocaleDateString(), W - P.r - 2, H - 2);
    }
    // Total count label top-right
    const total = buckets.reduce((s, b) => s + b.count, 0);
    ctx.textAlign = 'right';
    ctx.fillStyle = 'rgba(51,153,255,0.8)';
    ctx.font = '10px Outfit, sans-serif';
    ctx.fillText(total.toLocaleString() + ' events', W - P.r - 2, P.t + 10);
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

  // ── Discover: Extended feature state ──────────────────────────────────────
  let discoverPinnedFilters = [];
  let discoverDensity = 'default';
  let discoverAutoRefreshActive = false;
  let discoverAutoRefreshTimerId = null;
  let discoverAutoRefreshSeconds = 30;
  let discoverSearchHistory = [];
  let discoverSavedSearches = [];
  let discoverTaggedEvents = {};
  let discoverBookmarks = new Set();
  let _discoverFieldStatsCache = {};

  (function _discoverBootstrap() {
    try { discoverPinnedFilters = JSON.parse(localStorage.getItem('disc_pinned_filters') || '[]'); } catch(e){}
    try { discoverDensity = localStorage.getItem('disc_density') || 'default'; } catch(e){}
    try { discoverSearchHistory = JSON.parse(localStorage.getItem('disc_search_history') || '[]'); } catch(e){}
    try { discoverSavedSearches = JSON.parse(localStorage.getItem('disc_saved_searches') || '[]'); } catch(e){}
    try { discoverTaggedEvents = JSON.parse(localStorage.getItem('disc_tags') || '{}'); } catch(e){}
    try { discoverBookmarks = new Set(JSON.parse(localStorage.getItem('disc_bookmarks') || '[]')); } catch(e){}
  })();

  // ── KQL / Lucene parser ────────────────────────────────────────────────────
  function parseKqlQuery(q) {
    if (!q || !q.trim()) return null;
    q = q.trim();
    if (!/[\w.]+\s*:/.test(q) && !/\b(AND|OR|NOT)\b/i.test(q)) return null;
    try { return _kqlParse(q); } catch(e) { return null; }
  }
  function _kqlParse(expr) {
    expr = expr.trim();
    const orParts = _kqlSplit(expr, 'OR');
    if (orParts.length > 1) {
      const s = orParts.map(p => _kqlParse(p.trim())).filter(Boolean);
      return s.length === 1 ? s[0] : { bool: { should: s, minimum_should_match: 1 } };
    }
    const andParts = _kqlSplit(expr, 'AND');
    if (andParts.length > 1) {
      const m = andParts.map(p => _kqlParse(p.trim())).filter(Boolean);
      return m.length === 1 ? m[0] : { bool: { must: m } };
    }
    if (/^NOT\s+/i.test(expr)) {
      const c = _kqlParse(expr.replace(/^NOT\s+/i, ''));
      return c ? { bool: { must_not: [c] } } : null;
    }
    if (expr.startsWith('(') && expr.endsWith(')')) return _kqlParse(expr.slice(1, -1));
    const m = expr.match(/^([\w.]+)\s*:\s*(.+)$/);
    if (m) return _kqlFieldValue(m[1], m[2].trim());
    return { multi_match: { query: expr, fields: ['rule_description^3','title^2','agent_name^2','src_ip','username'], type: 'best_fields' } };
  }
  function _kqlFieldValue(field, val) {
    const rm = val.match(/^\[(.+)\s+TO\s+(.+)\]$/i);
    if (rm) return { range: { [field]: { gte: _kqlNum(rm[1]), lte: _kqlNum(rm[2]) } } };
    if (/^".*"$/.test(val)) return { match_phrase: { [field]: val.slice(1, -1) } };
    if (val.startsWith('>=')) return { range: { [field]: { gte: _kqlNum(val.slice(2).trim()) } } };
    if (val.startsWith('<=')) return { range: { [field]: { lte: _kqlNum(val.slice(2).trim()) } } };
    if (val.startsWith('>')) return { range: { [field]: { gt: _kqlNum(val.slice(1).trim()) } } };
    if (val.startsWith('<')) return { range: { [field]: { lt: _kqlNum(val.slice(1).trim()) } } };
    if (val === '*') return { exists: { field } };
    if (val.includes('*') || val.includes('?')) return { wildcard: { [field + '.keyword']: { value: val, case_insensitive: true } } };
    if (val.includes(',')) { const terms = val.split(',').map(s=>s.trim()).filter(Boolean); if (terms.length > 1) return { terms: { [field + '.keyword']: terms } }; }
    if (/~\d?$/.test(val)) return { fuzzy: { [field]: { value: val.replace(/~\d?$/, ''), fuzziness: 1 } } };
    return { term: { [field]: val } };
  }
  function _kqlSplit(expr, op) { return expr.split(new RegExp('\\s+' + op + '\\s+', 'i')); }
  function _kqlNum(s) { const n = Number(s.trim()); return isNaN(n) ? s.trim() : n; }

  // ── Session persistence ────────────────────────────────────────────────────
  function _discoverStateToObj() {
    return {
      search: document.getElementById('discoverSearch')?.value || '',
      timeRange: document.getElementById('discoverTimeRange')?.value || '24h',
      severity: document.getElementById('discoverSeverity')?.value || '',
      agent: document.getElementById('discoverAgent')?.value || '',
      group: document.getElementById('discoverGroup')?.value || '',
      mitre: document.getElementById('discoverMitre')?.value || '',
      compliance: document.getElementById('discoverCompliance')?.value || '',
      index: document.getElementById('discoverIndex')?.value || 'watchvault-alerts-*',
      fields: [...discoverSelectedFields],
      sortField: discoverSortField,
      sortOrder: discoverSortOrder,
      filters: discoverDslFilters.filter(f => !f._ioc),
      density: discoverDensity,
    };
  }
  function _discoverApplyState(state) {
    if (!state) return;
    const set = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };
    set('discoverSearch', state.search);
    set('discoverTimeRange', state.timeRange);
    set('discoverSeverity', state.severity);
    set('discoverAgent', state.agent);
    set('discoverGroup', state.group);
    set('discoverMitre', state.mitre);
    set('discoverCompliance', state.compliance);
    set('discoverIndex', state.index);
    if (Array.isArray(state.fields) && state.fields.length) discoverSelectedFields = [...state.fields];
    if (state.sortField) discoverSortField = state.sortField;
    if (state.sortOrder) discoverSortOrder = state.sortOrder;
    if (Array.isArray(state.filters)) discoverDslFilters = [...state.filters];
    if (state.density) discoverSetDensity(state.density);
  }
  function discoverSaveSession() {
    try { localStorage.setItem('disc_session', JSON.stringify(_discoverStateToObj())); } catch(e){}
  }
  function discoverLoadSession() {
    try { const s = localStorage.getItem('disc_session'); if (s) _discoverApplyState(JSON.parse(s)); } catch(e){}
    try { const p = localStorage.getItem('disc_pinned_filters'); if (p) discoverPinnedFilters = JSON.parse(p); } catch(e){}
  }

  // ── URL state sharing ──────────────────────────────────────────────────────
  function discoverGetUrlHash() {
    try {
      const s = _discoverStateToObj();
      return '#discover:' + btoa(unescape(encodeURIComponent(JSON.stringify({ q:s.search,t:s.timeRange,sev:s.severity,ag:s.agent,gr:s.group,mt:s.mitre,co:s.compliance,idx:s.index,f:s.fields,sf:s.sortField,so:s.sortOrder,fl:s.filters }))));
    } catch(e) { return '#discover'; }
  }
  function discoverSetUrlState() {
    try { history.replaceState(null, '', window.location.pathname + window.location.search + discoverGetUrlHash()); } catch(e){}
  }
  function discoverRestoreUrlState() {
    try {
      const hash = window.location.hash;
      if (!hash.startsWith('#discover:')) return false;
      const state = JSON.parse(decodeURIComponent(escape(atob(hash.slice(10)))));
      _discoverApplyState({ search:state.q,timeRange:state.t,severity:state.sev,agent:state.ag,group:state.gr,mitre:state.mt,compliance:state.co,index:state.idx,fields:state.f,sortField:state.sf,sortOrder:state.so,filters:state.fl||[] });
      return true;
    } catch(e) { return false; }
  }
  function discoverShareUrl() {
    discoverSetUrlState();
    const url = window.location.href.split('#')[0] + discoverGetUrlHash();
    if (navigator.clipboard) navigator.clipboard.writeText(url).then(() => showDiscoverToast('Share URL copied to clipboard'));
    else { const t=document.createElement('textarea');t.value=url;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showDiscoverToast('URL copied'); }
  }

  // ── Toast ──────────────────────────────────────────────────────────────────
  function showDiscoverToast(msg) {
    const toast = document.getElementById('discoverToast');
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => toast.classList.remove('show'), 2600);
  }

  // ── Search history ─────────────────────────────────────────────────────────
  function discoverAddToHistory(q) {
    if (!q || !q.trim()) return;
    discoverSearchHistory = [q, ...discoverSearchHistory.filter(h => h !== q)].slice(0, 20);
    try { localStorage.setItem('disc_search_history', JSON.stringify(discoverSearchHistory)); } catch(e){}
  }
  function discoverShowHistory() {
    const drop = document.getElementById('discoverSearchHistoryDrop');
    if (!drop) return;
    if (drop.classList.contains('hidden')) {
      if (!discoverSearchHistory.length) {
        drop.innerHTML = '<div class="disc-drop-empty">No recent searches</div>';
      } else {
        drop.innerHTML = '<div class="disc-drop-hdr">Recent searches <button class="disc-drop-clear" id="discHistClear">Clear all</button></div>' +
          discoverSearchHistory.map(h => '<div class="disc-drop-item disc-hist-item" data-q="' + escapeHtml(h) + '"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> ' + escapeHtml(h.length > 50 ? h.slice(0,50)+'…' : h) + '</div>').join('');
      }
      drop.classList.remove('hidden');
      drop.querySelectorAll('.disc-hist-item').forEach(el => {
        el.addEventListener('click', () => {
          document.getElementById('discoverSearch').value = el.getAttribute('data-q');
          drop.classList.add('hidden');
          discoverOffset = 0; loadDiscover();
        });
      });
      document.getElementById('discHistClear')?.addEventListener('click', () => {
        discoverSearchHistory = [];
        try { localStorage.removeItem('disc_search_history'); } catch(e){}
        drop.classList.add('hidden');
      });
    } else { drop.classList.add('hidden'); }
  }

  // ── Saved searches ─────────────────────────────────────────────────────────
  function discoverSaveSearch(name) {
    if (!name || !name.trim()) return;
    const id = Date.now().toString(36);
    discoverSavedSearches.push({ id, name: name.trim(), state: _discoverStateToObj(), created: new Date().toISOString() });
    try { localStorage.setItem('disc_saved_searches', JSON.stringify(discoverSavedSearches)); } catch(e){}
    showDiscoverToast('Search saved: ' + name.trim());
    discoverRenderSavedSearches();
  }
  function discoverLoadSearch(id) {
    const s = discoverSavedSearches.find(x => x.id === id);
    if (!s) return;
    _discoverApplyState(s.state);
    discoverOffset = 0;
    renderDiscoverFieldsSidebar(); renderDiscoverFilterPills();
    loadDiscover();
    document.getElementById('discoverSavedModal')?.classList.add('hidden');
    showDiscoverToast('Loaded: ' + s.name);
  }
  function discoverDeleteSearch(id) {
    discoverSavedSearches = discoverSavedSearches.filter(x => x.id !== id);
    try { localStorage.setItem('disc_saved_searches', JSON.stringify(discoverSavedSearches)); } catch(e){}
    discoverRenderSavedSearches();
  }
  function discoverRenderSavedSearches() {
    const list = document.getElementById('discoverSavedList');
    if (!list) return;
    if (!discoverSavedSearches.length) { list.innerHTML = '<div class="disc-drop-empty">No saved searches yet</div>'; return; }
    list.innerHTML = discoverSavedSearches.map(s =>
      '<div class="disc-saved-item"><div class="disc-saved-info"><span class="disc-saved-name">' + escapeHtml(s.name) + '</span><span class="disc-saved-meta">' + new Date(s.created).toLocaleDateString() + ' · ' + (s.state.timeRange||'24h') + '</span></div>' +
      '<div class="disc-saved-actions"><button class="act-btn" data-load="' + s.id + '">Load</button><button class="act-btn" data-del="' + s.id + '">Delete</button></div></div>'
    ).join('');
    list.querySelectorAll('[data-load]').forEach(btn => btn.addEventListener('click', () => discoverLoadSearch(btn.getAttribute('data-load'))));
    list.querySelectorAll('[data-del]').forEach(btn => btn.addEventListener('click', () => discoverDeleteSearch(btn.getAttribute('data-del'))));
  }
  function discoverShowSavedModal() {
    discoverRenderSavedSearches();
    document.getElementById('discoverSavedModal')?.classList.remove('hidden');
  }

  // ── Auto-refresh / Live mode ───────────────────────────────────────────────
  function discoverToggleAutoRefresh() {
    if (discoverAutoRefreshActive) discoverStopAutoRefresh();
    else { const s = parseInt(document.getElementById('discoverAutoRefreshInterval')?.value || '30', 10); discoverStartAutoRefresh(s); }
  }
  function discoverStartAutoRefresh(secs) {
    discoverStopAutoRefresh();
    discoverAutoRefreshActive = true;
    discoverAutoRefreshSeconds = secs;
    const btn = document.getElementById('discoverAutoRefreshBtn');
    if (btn) { btn.innerHTML = '⏹ ' + secs + 's'; btn.classList.add('active'); }
    document.getElementById('discoverLiveIndicator')?.classList.remove('hidden');
    document.getElementById('discoverAutoRefreshInterval')?.classList.remove('hidden');
    loadDiscover();
    discoverAutoRefreshTimerId = setInterval(() => {
      if (document.getElementById('page-discover')?.classList.contains('active')) loadDiscover();
    }, secs * 1000);
    showDiscoverToast('Live: refreshing every ' + secs + 's');
  }
  function discoverStopAutoRefresh() {
    if (discoverAutoRefreshTimerId) clearInterval(discoverAutoRefreshTimerId);
    discoverAutoRefreshTimerId = null;
    discoverAutoRefreshActive = false;
    const btn = document.getElementById('discoverAutoRefreshBtn');
    if (btn) { btn.innerHTML = '▶ Live'; btn.classList.remove('active'); }
    document.getElementById('discoverLiveIndicator')?.classList.add('hidden');
    document.getElementById('discoverAutoRefreshInterval')?.classList.add('hidden');
  }

  // ── Inspector ─────────────────────────────────────────────────────────────
  function discoverShowInspector() {
    const modal = document.getElementById('discoverInspectorModal');
    if (!modal) return;
    const dsl = buildDiscoverDsl();
    const body = document.getElementById('discoverInspectorBody');
    if (body) body.textContent = JSON.stringify(dsl, null, 2);
    modal.classList.remove('hidden');
  }

  // ── Density ───────────────────────────────────────────────────────────────
  function discoverSetDensity(mode) {
    discoverDensity = mode;
    const wrap = document.getElementById('discoverResultsWrap');
    if (wrap) { wrap.classList.remove('disc-density-compact', 'disc-density-comfortable'); if (mode !== 'default') wrap.classList.add('disc-density-' + mode); }
    try { localStorage.setItem('disc_density', mode); } catch(e){}
  }

  // ── Field statistics popover ───────────────────────────────────────────────
  async function showFieldStats(fieldName, anchorEl) {
    const pop = document.getElementById('discoverFieldStatsPop');
    if (!pop) return;
    const rect = anchorEl.getBoundingClientRect();
    pop.style.top = (rect.bottom + window.scrollY + 6) + 'px';
    pop.style.left = Math.min(rect.left + window.scrollX, window.innerWidth - 380) + 'px';
    pop.innerHTML = '<div class="disc-fsp-title">' + escapeHtml(fieldName) + '</div><div class="disc-fsp-loading">Loading…</div>';
    pop.classList.remove('hidden');
    const closeH = (e) => { if (!pop.contains(e.target)) { pop.classList.add('hidden'); document.removeEventListener('click', closeH); } };
    setTimeout(() => document.addEventListener('click', closeH), 80);
    const cacheKey = fieldName + ':' + (document.getElementById('discoverTimeRange')?.value || '24h');
    if (_discoverFieldStatsCache[cacheKey]) { renderFieldStatsPop(pop, fieldName, _discoverFieldStatsCache[cacheKey]); return; }
    const params = getDiscoverParams();
    const url = '/api/discover/field-stats?' + new URLSearchParams({ field: fieldName, size: 15, time_from: params.time_from || '', time_to: params.time_to || '', index: document.getElementById('discoverIndex')?.value || 'watchvault-alerts-*' });
    try {
      const data = await fetch(url).then(r => r.json());
      _discoverFieldStatsCache[cacheKey] = data;
      renderFieldStatsPop(pop, fieldName, data);
    } catch(e) { pop.innerHTML = '<div class="disc-fsp-title">' + escapeHtml(fieldName) + '</div><div class="disc-fsp-error">Failed to load</div>'; }
  }
  function renderFieldStatsPop(pop, fieldName, data) {
    const values = (data.values || []).slice(0, 12);
    const total = data.total || 1;
    if (!values.length) { pop.innerHTML = '<div class="disc-fsp-title">' + escapeHtml(fieldName) + '</div><div class="disc-fsp-empty">No data in time range</div>'; return; }
    const rows = values.map(v => {
      const pct = v.pct != null ? v.pct : Math.round((v.count||0) / total * 100);
      const dv = v.value != null ? String(v.value) : '(empty)';
      const dv2 = dv.length > 28 ? dv.slice(0,28)+'…' : dv;
      return '<div class="disc-fsp-row" data-f="' + escapeHtml(fieldName) + '" data-v="' + escapeHtml(String(v.value)) + '">' +
        '<span class="disc-fsp-val" title="' + escapeHtml(dv) + '">' + escapeHtml(dv2) + '</span>' +
        '<div class="disc-fsp-bar-wrap"><div class="disc-fsp-bar" style="width:' + Math.min(pct, 100) + '%"></div></div>' +
        '<span class="disc-fsp-pct">' + pct + '%</span><span class="disc-fsp-count">' + (v.count||0).toLocaleString() + '</span>' +
        '<button class="disc-fsp-add" title="Filter for">+</button><button class="disc-fsp-exc" title="Filter out">−</button></div>';
    }).join('');
    pop.innerHTML = '<div class="disc-fsp-title">' + escapeHtml(fieldName) + ' <span class="disc-fsp-subtitle">' + total.toLocaleString() + ' docs</span></div>' + rows;
    pop.querySelectorAll('.disc-fsp-add').forEach(btn => { const row = btn.closest('.disc-fsp-row'); btn.addEventListener('click', () => { discoverDslFilters.push({ field: row.getAttribute('data-f'), op: 'is', value: row.getAttribute('data-v') }); renderDiscoverFilterPills(); discoverOffset = 0; loadDiscover(); pop.classList.add('hidden'); }); });
    pop.querySelectorAll('.disc-fsp-exc').forEach(btn => { const row = btn.closest('.disc-fsp-row'); btn.addEventListener('click', () => { discoverDslFilters.push({ field: row.getAttribute('data-f'), op: 'is not', value: row.getAttribute('data-v') }); renderDiscoverFilterPills(); discoverOffset = 0; loadDiscover(); pop.classList.add('hidden'); }); });
  }

  // ── IOC Quick Search ───────────────────────────────────────────────────────
  function discoverIOCQuickSearch(ioc) {
    if (!ioc || !ioc.trim()) return;
    const q = ioc.trim();
    const el = document.getElementById('discoverSearch');
    if (el) el.value = q;
    discoverDslFilters = discoverDslFilters.filter(f => !f._ioc);
    discoverDslFilters.push({ _ioc: true, value: q, field: '_all', op: 'ioc',
      _dsl: { multi_match: { query: q, fields: ['src_ip^3','dst_ip^3','username^2','process_name^2','event_data.srcip^3','event_data.dstip^2','event_data.parentprocessname','event_data.commandline','event_data.dstuser','rule_description','title','agent_name'], type: 'best_fields' } }
    });
    discoverOffset = 0;
    renderDiscoverFilterPills(); loadDiscover();
    document.getElementById('discoverIOCModal')?.classList.add('hidden');
    discoverAddToHistory('IOC: ' + q);
    showDiscoverToast('IOC hunting: ' + q);
  }

  // ── Correlation ────────────────────────────────────────────────────────────
  async function discoverShowCorrelation(alert) {
    const card = document.getElementById('discoverCorrelationCard');
    const content = document.getElementById('discoverCorrelationContent');
    if (!card || !content) return;
    card.style.display = '';
    content.innerHTML = '<div class="disc-drop-empty">Loading related events…</div>';
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    const src = alert.source || {};
    const corrFields = {};
    ['src_ip','username','agent_id','agent_name','process_name','win_event_id','rule_id'].forEach(f => {
      const v = getByPath(src, f) || getByPath(src, 'event_data.' + f);
      if (v && String(v) !== '—' && String(v).trim() && String(v) !== 'undefined') corrFields[f] = String(v);
    });
    if (!Object.keys(corrFields).length) { content.innerHTML = '<div class="disc-drop-empty">No correlatable fields in this event</div>'; return; }
    const params = getDiscoverParams();
    try {
      const data = await fetch('/api/discover/correlate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: corrFields, exclude_id: src._id || src.id, time_from: params.time_from, time_to: params.time_to, index: document.getElementById('discoverIndex')?.value || 'watchvault-alerts-*', size: 20 })
      }).then(r => r.json());
      const hits = (data.hits || []).map(h => { const s = h._source||{}; return { timestamp:s.timestamp, rule_level:s.rule_level||0, title:s.title||s.rule_description||'—', agent_name:s.agent_name||s.agent?.name||'—', source:s }; });
      if (!hits.length) { content.innerHTML = '<div class="disc-drop-empty">No related events found (matched on: ' + escapeHtml(Object.keys(corrFields).join(', ')) + ')</div>'; return; }
      content.innerHTML = '<div class="disc-corr-header"><span>' + (data.total||hits.length) + ' related events</span><span class="disc-corr-fields">Matched on: ' + escapeHtml(Object.keys(corrFields).join(', ')) + '</span></div>' +
        '<div class="disc-corr-list">' + hits.map(h => {
          const lvl = Number(h.rule_level||0);
          return '<div class="disc-corr-row' + (lvl>=12?' row-crit':lvl>=8?' row-high':'') + '"><span class="disc-lvl disc-lvl-' + (lvl>=12?'crit':lvl>=8?'high':lvl>=4?'med':'low') + '">' + lvl + '</span><span class="disc-corr-ts">' + (h.timestamp ? new Date(h.timestamp).toLocaleString() : '—') + '</span><span class="disc-corr-title">' + escapeHtml(h.title) + '</span><span class="disc-corr-agent">' + escapeHtml(h.agent_name) + '</span></div>';
        }).join('') + '</div>';
    } catch(e) { content.innerHTML = '<div class="disc-drop-empty">Correlation request failed</div>'; }
  }

  // ── Event tagging ─────────────────────────────────────────────────────────
  function _alertId(alert) {
    const s = alert.source||{};
    return s._id || s.id || ((s.timestamp||'') + ':' + (s.rule_id||''));
  }
  function discoverTagEvent(alert, tag) {
    const id = _alertId(alert);
    if (!id || !tag) return;
    if (!discoverTaggedEvents[id]) discoverTaggedEvents[id] = [];
    if (!discoverTaggedEvents[id].includes(tag)) discoverTaggedEvents[id].push(tag);
    try { localStorage.setItem('disc_tags', JSON.stringify(discoverTaggedEvents)); } catch(e){}
  }
  function discoverGetTags(alert) {
    return discoverTaggedEvents[_alertId(alert)] || [];
  }
  function discoverRemoveTag(alert, tag) {
    const id = _alertId(alert);
    if (!discoverTaggedEvents[id]) return;
    discoverTaggedEvents[id] = discoverTaggedEvents[id].filter(t => t !== tag);
    if (!discoverTaggedEvents[id].length) delete discoverTaggedEvents[id];
    try { localStorage.setItem('disc_tags', JSON.stringify(discoverTaggedEvents)); } catch(e){}
  }
  function discoverShowTagModal(alert) {
    const modal = document.getElementById('discoverTagModal');
    if (!modal) return;
    const input = document.getElementById('discoverTagInput');
    if (input) input.value = '';
    const suggestions = ['false-positive','reviewed','ioc','escalated','benign','investigation','true-positive','critical-asset'];
    const existing = discoverGetTags(alert);
    const sugg = document.getElementById('discoverTagSuggestions');
    if (sugg) {
      sugg.innerHTML = suggestions.map(s => '<span class="disc-tag-sugg' + (existing.includes(s)?' active':'') + '" data-tag="'+s+'">' + s + '</span>').join('');
      sugg.querySelectorAll('.disc-tag-sugg').forEach(el => {
        el.addEventListener('click', () => {
          const tag = el.getAttribute('data-tag');
          if (el.classList.contains('active')) { discoverRemoveTag(alert, tag); el.classList.remove('active'); }
          else { discoverTagEvent(alert, tag); el.classList.add('active'); }
          renderDiscoverTagCurrentList(alert);
        });
      });
    }
    renderDiscoverTagCurrentList(alert);
    modal._alert = alert;
    modal.classList.remove('hidden');
  }
  function renderDiscoverTagCurrentList(alert) {
    const tags = discoverGetTags(alert);
    const el = document.getElementById('discoverTagCurrentList');
    if (!el) return;
    el.innerHTML = tags.length ? '<div class="disc-tag-current">' + tags.map(t => '<span class="disc-tag-item">' + escapeHtml(t) + '<button data-tag="'+escapeHtml(t)+'">×</button></span>').join('') + '</div>' : '';
    el.querySelectorAll('[data-tag]').forEach(btn => {
      btn.addEventListener('click', () => { discoverRemoveTag(alert, btn.getAttribute('data-tag')); renderDiscoverTagCurrentList(alert); const s = document.querySelector('.disc-tag-sugg[data-tag="'+btn.getAttribute('data-tag')+'"]'); if (s) s.classList.remove('active'); });
    });
  }

  // ── Bookmarks ─────────────────────────────────────────────────────────────
  function discoverToggleBookmark(alert) {
    const id = _alertId(alert);
    if (discoverBookmarks.has(id)) discoverBookmarks.delete(id);
    else discoverBookmarks.add(id);
    try { localStorage.setItem('disc_bookmarks', JSON.stringify([...discoverBookmarks])); } catch(e){}
  }

  // ── Save as Threat Hunt ────────────────────────────────────────────────────
  function discoverSaveAsHunt() {
    const q = document.getElementById('discoverSearch')?.value || '';
    const name = prompt('Hunt name (will appear in Threat Hunting page):', q || 'New hunt');
    if (!name) return;
    const hunts = JSON.parse(localStorage.getItem('saved_hunts') || '[]');
    hunts.unshift({ name, query: q, filters: discoverDslFilters, created: new Date().toISOString() });
    try { localStorage.setItem('saved_hunts', JSON.stringify(hunts.slice(0, 50))); } catch(e){}
    showDiscoverToast('Saved to Threat Hunts: ' + name);
  }

  // ── Pre-filter navigation ─────────────────────────────────────────────────
  function navigateToDiscover(filters) {
    discoverDslFilters = filters || [];
    discoverOffset = 0;
    goToPage('discover');
    setTimeout(() => { renderDiscoverFilterPills(); loadDiscover(); }, 150);
  }

  // ── Keyboard shortcuts ─────────────────────────────────────────────────────
  function discoverHandleKeyboard(e) {
    const onDiscover = document.getElementById('page-discover')?.classList.contains('active');
    if (!onDiscover) return;
    if (e.key === 'Escape') {
      closeDiscoverDetail();
      ['discoverInspectorModal','discoverSavedModal','discoverShortcutsModal','discoverIOCModal','discoverTagModal'].forEach(id => document.getElementById(id)?.classList.add('hidden'));
      document.getElementById('discoverFieldStatsPop')?.classList.add('hidden');
      document.getElementById('discoverSearchHistoryDrop')?.classList.add('hidden');
      document.getElementById('discoverToolsDrop')?.classList.add('hidden');
      return;
    }
    const tag = document.activeElement?.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); discoverOffset = 0; const q = document.getElementById('discoverSearch')?.value||''; if (q) discoverAddToHistory(q); loadDiscover(); }
      return;
    }
    if (e.ctrlKey || e.metaKey) {
      switch(e.key.toLowerCase()) {
        case '/': e.preventDefault(); document.getElementById('discoverSearch')?.focus(); break;
        case 'e': e.preventDefault(); discoverExportCsv(); break;
        case 'i': e.preventDefault(); discoverShowInspector(); break;
        case 's': e.preventDefault(); discoverShowSavedModal(); break;
        case 'l': e.preventDefault(); discoverToggleAutoRefresh(); break;
        case 'k': e.preventDefault(); document.getElementById('discoverIOCModal')?.classList.remove('hidden'); document.getElementById('discoverIOCInput')?.focus(); break;
      }
      return;
    }
    switch(e.key) {
      case '?': discoverShowShortcutsModal(); break;
      case 'ArrowLeft': if (!document.getElementById('discoverPrev')?.disabled) { discoverOffset = Math.max(0, discoverOffset - DISCOVER_PAGE_SIZE); loadDiscover(); } break;
      case 'ArrowRight': if (!document.getElementById('discoverNext')?.disabled) { discoverOffset += DISCOVER_PAGE_SIZE; loadDiscover(); } break;
    }
  }
  function discoverShowShortcutsModal() { document.getElementById('discoverShortcutsModal')?.classList.remove('hidden'); }

  // ── Timeline tab ──────────────────────────────────────────────────────────
  async function discoverLoadTimeline(alert) {
    const el = document.getElementById('discoverDetailTimeline');
    if (!el) return;
    el.innerHTML = '<div class="disc-drop-empty">Loading timeline…</div>';
    const src = alert.source || {};
    const agentId = src.agent_id || src.agent?.id;
    const ts = src.timestamp || alert.timestamp;
    if (!ts) { el.innerHTML = '<div class="disc-drop-empty">No timestamp available</div>'; return; }
    const t = new Date(typeof ts === 'number' ? ts : ts);
    const from = new Date(t.getTime() - 15*60*1000).toISOString();
    const to   = new Date(t.getTime() + 15*60*1000).toISOString();
    const must = [{ range: { timestamp: { gte: from, lte: to } } }];
    if (agentId) must.push({ bool: { should: [{ term: { agent_id: agentId } }, { term: { 'agent.id': agentId } }], minimum_should_match: 1 } });
    const dsl = { query: { bool: { must } }, sort: [{ timestamp: { order: 'asc' } }] };
    try {
      const res = await fetch('/api/alerts/list?size=60&offset=0', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ dsl, index: document.getElementById('discoverIndex')?.value||'watchvault-alerts-*' }) }).then(r=>r.json());
      const hits = res.alerts || [];
      if (!hits.length) { el.innerHTML = '<div class="disc-drop-empty">No events in ±15 min window</div>'; return; }
      el.innerHTML = '<div class="disc-timeline-hdr">Events ±15 min · agent: ' + escapeHtml(src.agent_name || agentId || 'all') + ' · ' + hits.length + ' events</div><div class="disc-timeline-list">' +
        hits.map(h => {
          const s = h.source||{};
          const isCurrent = s.timestamp === ts || (src._id && s._id === src._id);
          const lvl = Number(s.rule_level||0);
          return '<div class="disc-tl-row' + (isCurrent?' current':'') + (lvl>=12?' row-crit':lvl>=8?' row-high':'') + '">' +
            (isCurrent?'<span class="disc-tl-marker">▶</span>':'<span class="disc-tl-marker-empty"></span>') +
            '<span class="disc-tl-ts">' + (h.timestamp ? new Date(h.timestamp).toLocaleTimeString() : '—') + '</span>' +
            '<span class="disc-lvl disc-lvl-' + (lvl>=12?'crit':lvl>=8?'high':lvl>=4?'med':'low') + '">' + lvl + '</span>' +
            '<span class="disc-tl-title">' + escapeHtml(h.title||s.rule_description||'—') + '</span></div>';
        }).join('') + '</div>';
    } catch(e) { el.innerHTML = '<div class="disc-drop-empty">Timeline load failed</div>'; }
  }

  // ── Quick stats summary ───────────────────────────────────────────────────
  function discoverUpdateStatsSummary(alerts) {
    const el = document.getElementById('discoverStatsSummary');
    if (!el || !alerts.length) { if (el) el.innerHTML = ''; return; }
    let crit = 0, high = 0; const agents = new Set(), rules = new Set();
    alerts.forEach(a => {
      const s = a.source||{};
      const lvl = Number(s.rule_level||0);
      if (lvl >= 12) crit++;
      else if (lvl >= 8) high++;
      const ag = s.agent_name||s.agent?.name; if (ag) agents.add(ag);
      const r = s.rule_id||s.rule?.id; if (r) rules.add(String(r));
    });
    const parts = [];
    if (crit) parts.push('<span class="disc-stat-crit">' + crit + ' critical</span>');
    if (high) parts.push('<span class="disc-stat-high">' + high + ' high</span>');
    if (agents.size) parts.push('<span class="disc-stat-info">' + agents.size + ' agent' + (agents.size>1?'s':'') + '</span>');
    if (rules.size) parts.push('<span class="disc-stat-info">' + rules.size + ' rule' + (rules.size>1?'s':'') + '</span>');
    el.innerHTML = parts.join(' · ');
  }

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
    const dcW = 'grid-template-columns:1fr 140px 80px 140px 1fr 44px';
    if (res.error) {
      bodyEl.innerHTML = `<div class="tbl-r" style="${dcW}"><span class="error-msg" style="grid-column:1/-1">${escapeHtml(res.error.message || res.error)}</span></div>`;
    } else if (!items.length) {
      bodyEl.innerHTML = `<div class="sigil-block"><div class="sigil-text"><h4>No decoders found</h4><p>Add decoder files to define log parsing rules</p></div></div>`;
    } else {
      bodyEl.innerHTML = items.map((d, i) => {
        const name = d.name || '—';
        const programName = (d.details && d.details.program_name) || (d.program_name) || '—';
        const order = (d.details && d.details.order) || (Array.isArray(d.order) ? d.order.join(', ') : d.order) || '—';
        const file = d.filename || d.file || '—';
        const path = d.relative_dirname || '—';
        return `<div class="tbl-r decoder-row" style="${dcW}" data-index="${i}"><span class="tbl-pri">${escapeHtml(String(name))}</span><span class="tbl-mono">${escapeHtml(String(programName))}</span><span class="tbl-mono">${escapeHtml(String(order))}</span><span class="tbl-mono">${escapeHtml(String(file))}</span><span class="tbl-muted">${escapeHtml(String(path))}</span><span><button type="button" class="btn-disc-detail btn-agent-view" title="View details">⋯</button></span></div>`;
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
    const idxW = 'grid-template-columns:1fr 80px 80px 90px 110px 100px 100px 80px 80px';
    if (res.error) {
      bodyEl.innerHTML = `<div class="tbl-r" style="${idxW}"><span class="error-msg" style="grid-column:1/-1">${escapeHtml(res.error.message || res.error)}</span></div>`;
    } else if (!list.length) {
      bodyEl.innerHTML = `<div class="sigil-block"><div class="sigil-text"><h4>No indexes found</h4><p>No OpenSearch indexes match the current search</p></div></div>`;
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
        const hCol = health === 'green' ? 'var(--ok)' : health === 'yellow' ? 'var(--high)' : health === 'red' ? 'var(--crit)' : 'var(--fg-4)';
        return `<div class="tbl-r" style="${idxW}"><span class="tbl-mono" style="font-size:11px">${escapeHtml(String(name))}</span><span><span style="color:${hCol};font-weight:600;font-size:11px">${escapeHtml(String(health))}</span></span><span class="tbl-mono">${escapeHtml(String(status))}</span><span class="tbl-mono">${escapeHtml(String(storeSize))}</span><span class="tbl-mono">${escapeHtml(String(priSize))}</span><span class="tbl-mono">${escapeHtml(String(docsCount))}</span><span class="tbl-mono">${escapeHtml(String(docsDeleted))}</span><span class="tbl-mono">${escapeHtml(String(pri))}</span><span class="tbl-mono">${escapeHtml(String(rep))}</span></div>`;
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
    const rlW = 'grid-template-columns:70px 1fr 140px 70px 140px 1fr 44px';
    if (res.error) {
      bodyEl.innerHTML = `<div class="tbl-r" style="${rlW}"><span class="error-msg" style="grid-column:1/-1">${escapeHtml(res.error.message || res.error)}</span></div>`;
    } else if (!items.length) {
      bodyEl.innerHTML = `<div class="sigil-block"><div class="sigil-text"><h4>No rules found</h4><p>Add rule files or adjust the search</p></div></div>`;
    } else {
      bodyEl.innerHTML = items.map((r, i) => {
        const desc = (r.description || '—').slice(0, 80);
        const groups = Array.isArray(r.groups) ? r.groups.join(', ') : (r.groups || '—');
        const file = r.filename || r.file || '—';
        const path = r.relative_dirname || '—';
        const level = r.level != null ? r.level : '—';
        const id = r.id != null ? r.id : '—';
        const lvlCol = Number(level) >= 12 ? 'var(--crit)' : Number(level) >= 8 ? 'var(--high)' : Number(level) >= 4 ? 'var(--med)' : 'var(--fg-3)';
        return `<div class="tbl-r rule-row" style="${rlW}" data-index="${i}"><span class="tbl-mono" style="color:var(--accent)">${escapeHtml(String(id))}</span><span class="tbl-pri" title="${escapeHtml(r.description||'')}">${escapeHtml(desc)}${desc.length >= 80 ? '…' : ''}</span><span class="tbl-muted" style="font-size:10px">${escapeHtml(groups)}</span><span style="font-family:var(--font-mono);font-weight:600;color:${lvlCol}">${escapeHtml(String(level))}</span><span class="tbl-mono">${escapeHtml(String(file))}</span><span class="tbl-muted">${escapeHtml(String(path))}</span><span><button type="button" class="btn-disc-detail btn-agent-view" title="View">⋯</button></span></div>`;
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
    const colors = ['#2DD4BF', '#34D399', '#F59E0B', '#F25555', '#a371f7', '#79c0ff', '#7ee787', '#ffa657', '#ff7b72', '#bc8cff'];
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
    const colors = ['#2DD4BF', '#34D399', '#F59E0B', '#F25555', '#a371f7'];
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
    const colors = ['#2DD4BF', '#34D399', '#F59E0B', '#F25555', '#a371f7'];
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
      ctx.fillStyle = '#2DD4BF';
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
    // Pivot from an agent detail page → pre-select this agent in the filter.
    if (window._pivotAgent) {
      const sel = document.getElementById('vulnAgent');
      if (sel) {
        const pa = window._pivotAgent;
        if (![...sel.options].some(o => o.value === pa.id)) {
          const o = document.createElement('option');
          o.value = pa.id; o.textContent = pa.name || pa.id; sel.appendChild(o);
        }
        sel.value = pa.id;
      }
      vulnCurrentPage = 0;
      window._pivotAgent = null;
    }
    const { params, bounds } = getVulnParams();
    const _vulnNameMap = await getAgentNameMap();
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
      if (c) { const ctx = c.getContext('2d'); ctx.fillStyle = '#08090b'; ctx.fillRect(0, 0, c.width, c.height); }
      if (document.getElementById('vulnTrendLegend')) document.getElementById('vulnTrendLegend').innerHTML = '<span class="error-msg">' + escapeHtml(trendsRes.error.message) + '</span>';
    } else drawVulnTrend('vulnTrendCanvas', 'vulnTrendLegend', trendsRes);

    const agentsEl = document.getElementById('vulnTopAgents');
    if (topAgentsRes.error) agentsEl.innerHTML = '<span class="error-msg">' + escapeHtml(topAgentsRes.error.message) + '</span>';
    else {
      const buckets = topAgentsRes.buckets || [];
      if (document.getElementById('vulnAgent') && document.getElementById('vulnAgent').options.length <= 1) {
        document.getElementById('vulnAgent').innerHTML = '<option value="">All agents</option>' + buckets.map(b => `<option value="${escapeHtml(b.key || '')}">${escapeHtml(resolveAgent(b.key, _vulnNameMap))}</option>`).join('');
      }
      const maxA = Math.max(...buckets.map(b => b.doc_count), 1);
      agentsEl.innerHTML = buckets.length === 0 ? '<span class="empty-msg">No data</span>' : buckets.map((b, i) => {
        const pct = (b.doc_count / maxA) * 100;
        const rank = i + 1;
        const isFirst = rank === 1;
        const _aname = resolveAgent(b.key, _vulnNameMap);
        return `<div class="vuln-bar-row ${isFirst ? 'vuln-bar-row--top' : ''}" data-rank="${rank}">
          <span class="vuln-bar-rank">${rank}</span>
          <span class="vuln-bar-label" title="${escapeHtml(b.key || '—')}">${escapeHtml(_aname.slice(0, 22))}${_aname.length > 22 ? '…' : ''}</span>
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
    const nameMap = options && options.nameMap;
    return top5.map(b => {
      const pct = (b.doc_count / max) * 100;
      const name = (nameMap ? resolveAgent(b.key, nameMap) : (b.key || '—')).slice(0, 24);
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
    const colors = ['#2DD4BF', '#34D399', '#F59E0B', '#F25555', '#bc8cff', '#56d4dd'];
    let maxVal = 0;
    series.forEach(s => (s.buckets || []).forEach(b => { if (b.doc_count > maxVal) maxVal = b.doc_count; }));
    maxVal = Math.max(1, maxVal);
    const stepX = series.length > 1 ? chartW / (series.length - 1) : chartW;
    ctx.fillStyle = '#08090b';
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
    const colors = ['#F25555', '#F59E0B', '#2DD4BF', '#34D399', '#bc8cff', '#56d4dd'];
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
    ctx.fillStyle = '#0f1115';
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
    const nameMap = await getAgentNameMap();

    const agentEl = document.getElementById('dashboardAgent');
    const ruleGroupEl = document.getElementById('dashboardRuleGroup');
    if (agentEl && agentEl.options.length <= 1) {
      const baseParams = new URLSearchParams();
      params.forEach((v, k) => { if (k !== 'agent_name' && k !== 'agent_id' && k !== 'rule_group' && k !== 'exclude_rule_ids') baseParams.set(k, v); });
      const agentRes = await fetchJson(API.alertsByAgent + '?size=100&' + baseParams.toString()).catch(() => ({ buckets: [] }));
      const buckets = agentRes.buckets || [];
      agentEl.innerHTML = '<option value="">All agents</option>' + buckets.map(b => {
        const aid = b.agent_id != null ? String(b.agent_id) : '';
        return `<option value="${escapeHtml(b.key || '')}" data-agent-id="${escapeHtml(aid)}">${escapeHtml(resolveAgent(b.key, nameMap).slice(0, 40))}</option>`;
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
    else top5El.innerHTML = renderTop5AgentsBar(top5Res.buckets || [], { drillDown: true, nameMap });

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
      const sysW = 'grid-template-columns:140px 120px 140px 120px 140px 100px';
      const _hyEmptyState = (msg) => `<div class="sigil-block"><div class="sigil" style="color:var(--accent)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" width="28" height="28"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9h6v6H9z"/></svg></div><div class="sigil-text"><h4>No inventory data yet</h4><p>${msg}</p></div></div>`;
      if (list.error) tbody.innerHTML = `<div class="tbl-r" style="${sysW}"><span class="error-msg" style="grid-column:1/-1">${escapeHtml(list.error.message)}</span></div>`;
      else if (hits.length === 0) tbody.innerHTML = _hyEmptyState('System inventory populates from agent check-ins. Each connected agent reports its OS, kernel, and hardware on a daily schedule.');
      else tbody.innerHTML = hits.map(r => `<div class="tbl-r" style="${sysW}"><span class="tbl-mono">${escapeHtml(r.agent_name||'—')}</span><span class="tbl-mono">${escapeHtml(r.host_os_platform||'—')}</span><span>${escapeHtml(r.host_os_name||'—')}</span><span class="tbl-mono">${escapeHtml(r.host_os_version||'—')}</span><span class="tbl-mono" style="font-size:10px">${escapeHtml(r.host_os_kernel_release||'—')}</span><span class="tbl-mono">${escapeHtml(r.host_architecture||'—')}</span></div>`).join('');
    } catch (e) {
      document.getElementById('hygieneSystemTable').innerHTML = `<div class="tbl-r"><span class="error-msg" style="grid-column:1/-1">${escapeHtml(e.message)}</span></div>`;
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
      const pkgW = 'grid-template-columns:140px 140px 1fr 120px 100px';
      if (list.error) tbody.innerHTML = `<div class="tbl-r" style="${pkgW}"><span class="error-msg" style="grid-column:1/-1">${escapeHtml(list.error.message)}</span></div>`;
      else if (hits.length === 0) tbody.innerHTML = `<div class="sigil-block"><div class="sigil-text"><h4>No package data</h4><p>Package-level vulnerability rollups will populate here</p></div></div>`;
      else tbody.innerHTML = hits.map(r => `<div class="tbl-r" style="${pkgW}"><span class="tbl-mono">${escapeHtml(r.agent_name||'—')}</span><span class="tbl-mono">${escapeHtml(r.package_vendor||'—')}</span><span class="tbl-pri">${escapeHtml(r.package_name||'—')}</span><span class="tbl-mono">${escapeHtml(r.package_version||'—')}</span><span class="tbl-muted">${escapeHtml(r.package_type||'—')}</span></div>`).join('');
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
      const procW = 'grid-template-columns:130px 130px 120px 70px 80px 1fr';
      if (list.error) tbody.innerHTML = `<div class="tbl-r" style="${procW}"><span class="error-msg" style="grid-column:1/-1">${escapeHtml(list.error.message)}</span></div>`;
      else if (hits.length === 0) tbody.innerHTML = `<div class="sigil-block"><div class="sigil-text"><h4>No process data</h4><p>Process list populates once agents report running processes</p></div></div>`;
      else tbody.innerHTML = hits.map(r => {
        const start = r.process_start ? new Date(r.process_start).toLocaleString() : '—';
        return `<div class="tbl-r" style="${procW}"><span class="tbl-mono">${escapeHtml(r.agent_name||'—')}</span><span class="tbl-pri">${escapeHtml(r.process_name||'—')}</span><span class="tbl-time">${start}</span><span class="tbl-mono">${escapeHtml(String(r.process_pid??'—'))}</span><span class="tbl-mono">${escapeHtml(String(r.process_parent_pid??'—'))}</span><span class="tbl-mono" style="font-size:10px">${escapeHtml((r.process_command_line||'—').slice(0,80))}</span></div>`;
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
      const usrW = 'grid-template-columns:140px 140px 1fr 120px 140px';
      if (list.error) tbody.innerHTML = `<div class="tbl-r" style="${usrW}"><span class="error-msg" style="grid-column:1/-1">${escapeHtml(list.error.message)}</span></div>`;
      else if (hits.length === 0) tbody.innerHTML = `<div class="sigil-block"><div class="sigil-text"><h4>No identity data</h4><p>User/identity data will populate once agents report user inventory</p></div></div>`;
      else tbody.innerHTML = hits.map(r => `<div class="tbl-r" style="${usrW}"><span class="tbl-mono">${escapeHtml(r.agent_name||'—')}</span><span class="tbl-pri">${escapeHtml(r.user_name||'—')}</span><span class="tbl-muted">${escapeHtml(r.user_groups||'—')}</span><span class="tbl-mono">${escapeHtml(r.user_shell||'—')}</span><span class="tbl-mono">${escapeHtml(r.user_home||'—')}</span></div>`).join('');
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
    'agent-detail': loadAgentDetailPage,
    fim: loadFimPage,
    mitre: loadMitrePage,
    audit: loadAuditPage,
    logs: loadLogsPage,
    'config-audit': loadConfigAuditPage,
    'system-logs': loadSystemLogsPage,
    'retention': loadRetentionPage,
    'log-filters': loadLogFiltersPage,
    'silent-sources': loadSilentSourcesPage,
    'users': loadUsersPage,
    'correlations': loadCorrelationsPage,
    'soc': loadSOCPage,
    sca: loadScaPage,
    'threat-hunting': loadThreatHunting,
    'process-tree': loadProcessTreePage,
    alerts: () => { _wireAlertChips(); loadAlerts(); },
    discover: () => {
      // Restore URL state first, then session, then apply density and load
      if (!discoverRestoreUrlState()) discoverLoadSession();
      discoverSetDensity(discoverDensity);
      renderDiscoverFieldsSidebar();
      renderDiscoverFilterPills();
      loadDiscover();
    },
    rules: loadRules,
    decoders: () => { loadDecoders(); (window.loadSyslogDecoders || function(){})(); },
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
    // Enterprise features
    cases: () => loadCases(),
    playbooks: () => loadPlaybooks(),
    ueba: () => loadUebaPage(),
    rba: () => loadRbaPage(),
    'geo-map': () => loadGeoMap(),
    'cloud-monitoring': () => loadCloudMonitoringPage(),
    'compliance-hub': () => loadComplianceHub(),
    'rule-versions': () => loadRuleVersionsPage(),
    identity: () => loadIdentityPage(),
    ticketing: () => loadTicketingPage(),
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
    // Start/stop per-page auto-refresh timers based on the active page
    if (typeof window.startAgentsRefresh === 'function') window.startAgentsRefresh();
    if (typeof window.startAlertsRefresh === 'function') window.startAlertsRefresh();
  }
  window.goToPage = goToPage;

  // investigateIncident — called from Active Incidents "Investigate →" button.
  // Pre-filters Discover by agent_id so results show immediately.
  window.investigateIncident = function(agentId, ruleId) {
    discoverDslFilters = [];
    if (agentId) {
      discoverDslFilters.push({ term: { agent_id: agentId } });
    }
    if (ruleId) {
      discoverDslFilters.push({ term: { rule_id: parseInt(ruleId, 10) } });
    }
    // Reset to alerts index and widen time range to catch the incident
    const timeEl = document.getElementById('discoverTimeRange');
    if (timeEl) timeEl.value = '24h';
    const idxEl = document.getElementById('discoverIndex');
    if (idxEl) idxEl.value = 'watchvault-alerts-*';
    discoverOffset = 0;
    goToPage('discover');
  };

  // Open Discover scoped to a single agent (optionally with a query_string and
  // a specific index). Used by the agent-detail "Investigate this node" pivots.
  function _pivotDiscover(agentId, opts) {
    opts = opts || {};
    discoverDslFilters = [];
    if (agentId) discoverDslFilters.push({ field: 'agent_id', op: 'is', value: agentId });
    const idxEl = document.getElementById('discoverIndex');
    if (idxEl && opts.index) idxEl.value = opts.index;
    const qEl = document.getElementById('discoverSearch');
    if (qEl) qEl.value = opts.query || '';
    const tEl = document.getElementById('discoverTimeRange'); if (tEl) tEl.value = '24h';
    discoverOffset = 0;
    if (typeof renderDiscoverFilterPills === 'function') renderDiscoverFilterPills();
    goToPage('discover');
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
      const roleLabels = { super_admin: 'Super Admin', administrator: 'Administrator', admin: 'Admin', security_analyst: 'Security Analyst', compliance_officer: 'Compliance Officer' };
      const roleLabel = roleLabels[currentUser.role] || currentUser.role || 'User';
      // Update visible sidebar elements
      const userNameEl = document.getElementById('sidebarUserName');
      if (userNameEl) userNameEl.textContent = currentUser.username || 'admin';
      const userSubEl = document.getElementById('sidebarUserSub');
      if (userSubEl) userSubEl.textContent = roleLabel + ' · SOC-1';
      const avatarEl = document.getElementById('sidebarAvatar');
      if (avatarEl) avatarEl.textContent = (currentUser.username || 'A').slice(0, 2).toUpperCase();
      // Hidden compat element
      const userEl = document.getElementById('sidebarUser');
      if (userEl) userEl.textContent = currentUser.username + ' · ' + roleLabel;
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

  // Only surface the "AI Summary" event-detail tab when an AI backend is
  // actually configured (ANTHROPIC_API_KEY set). Otherwise it would only ever
  // show the rule-based fallback, which reads as a broken/unfinished feature.
  (function revealAiTabIfConfigured() {
    const aiTab = document.getElementById('discoverDetailAiTab');
    if (!aiTab) return;
    fetch('/api/ai/status')
      .then(r => r.json())
      .then(d => { if (d && d.configured) aiTab.style.display = ''; })
      .catch(() => {});
  })();

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
  document.getElementById('hygieneRefreshBtn')?.addEventListener('click', () => {
    const active = document.querySelector('.hygiene-subtab.active')?.getAttribute('data-hygiene') || 'system';
    setHygieneSubtab(active);
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
  const _refilterAgents = () => {
    if (!window._agentsHealthData?.agents) return;
    const filtered = filterAgentsTable(window._agentsHealthData.agents);
    const bodyEl = document.getElementById('agentsBody');
    if (bodyEl) bodyEl.innerHTML = renderAgentsTableFromHealth(filtered);
    const countEl = document.getElementById('agentsTableCount');
    if (countEl) countEl.textContent = filtered.length;
  };
  if (agentsSearchEl) agentsSearchEl.addEventListener('input', _refilterAgents);
  document.querySelectorAll('.ag2-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.ag2-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      _refilterAgents();
    });
  });

  document.getElementById('agentsBody')?.addEventListener('click', (e) => {
    // Whole row is clickable; the chevron button works too (both carry data-agent-id).
    const target = e.target.closest('.btn-agent-view, .adt-brow');
    if (target && target.getAttribute('data-agent-id')) openAgentDetail(target.getAttribute('data-agent-id'));
  });
  document.getElementById('agentDetailBack')?.addEventListener('click', () => goToPage('agents'));

  // Threat Hunting controls
  document.getElementById('huntTimeRange')?.addEventListener('change', () => loadThreatHunting());
  document.getElementById('huntRefreshBtn')?.addEventListener('click', () => loadThreatHunting());
  document.getElementById('thExplorerSearch')?.addEventListener('input', () => filterHuntExplorer());

  // Agents auto-refresh (the dropdown was previously decorative)
  window._agentsRefreshTimer = window._agentsRefreshTimer || null;
  window.startAgentsRefresh = function () {
    if (window._agentsRefreshTimer) { clearInterval(window._agentsRefreshTimer); window._agentsRefreshTimer = null; }
    const sec = parseInt(document.getElementById('agentsRefresh')?.value || '0', 10);
    if (sec > 0) window._agentsRefreshTimer = setInterval(() => {
      if (document.querySelector('.page.active')?.id === 'page-agents') loadAgents();
    }, sec * 1000);
  };
  document.getElementById('agentsRefresh')?.addEventListener('change', window.startAgentsRefresh);

  // Alerts auto-refresh (the dropdown + "auto-refreshing" subtitle were previously decorative)
  window._alertsRefreshTimer = window._alertsRefreshTimer || null;
  window.startAlertsRefresh = function () {
    if (window._alertsRefreshTimer) { clearInterval(window._alertsRefreshTimer); window._alertsRefreshTimer = null; }
    const sec = parseInt(document.getElementById('alertsRefresh')?.value || '0', 10);
    if (sec > 0) window._alertsRefreshTimer = setInterval(() => {
      if (document.querySelector('.page.active')?.id === 'page-alerts') loadAlerts();
    }, sec * 1000);
  };
  document.getElementById('alertsRefresh')?.addEventListener('change', window.startAlertsRefresh);

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
  document.getElementById('discoverIndex')?.addEventListener('change', () => { discoverOffset = 0; discoverDslFilters = []; discoverSelectedFields = ['timestamp','rule_level','title','agent_name','src_ip','username','process_name']; renderDiscoverFilterPills(); loadDiscover(); });
  document.getElementById('discoverExportCsv')?.addEventListener('click', discoverExportCsv);
  document.getElementById('discoverPrev')?.addEventListener('click', () => { discoverOffset = Math.max(0, discoverOffset - DISCOVER_PAGE_SIZE); loadDiscover(); });
  document.getElementById('discoverNext')?.addEventListener('click', () => { discoverOffset += DISCOVER_PAGE_SIZE; loadDiscover(); });
  ['discoverTimeRange', 'discoverSeverity', 'discoverAgent', 'discoverGroup', 'discoverMitre', 'discoverCompliance'].forEach(id => {
    document.getElementById(id)?.addEventListener('change', () => { discoverOffset = 0; loadDiscover(); });
  });

  // Custom-range picker: show/hide on selection, apply on button click.
  // The picker is suppressed from reloading until Apply, so partial dates
  // don't fire half-broken queries.
  (function wireDiscoverCustomRange() {
    const sel  = document.getElementById('discoverTimeRange');
    const wrap = document.getElementById('discoverCustomRange');
    const fromEl = document.getElementById('discoverCustomFrom');
    const toEl   = document.getElementById('discoverCustomTo');
    const apply  = document.getElementById('discoverCustomApply');
    if (!sel || !wrap || !apply) return;

    function toLocalISO(date) {
      // datetime-local expects YYYY-MM-DDTHH:MM in local time, no Z.
      const off = date.getTimezoneOffset();
      const local = new Date(date.getTime() - off * 60000);
      return local.toISOString().slice(0, 16);
    }

    sel.addEventListener('change', () => {
      if (sel.value === 'custom') {
        wrap.classList.remove('hidden');
        if (!fromEl.value || !toEl.value) {
          const now = new Date();
          const past = new Date(now.getTime() - 24 * 3600 * 1000);
          fromEl.value = toLocalISO(past);
          toEl.value   = toLocalISO(now);
        }
      } else {
        wrap.classList.add('hidden');
      }
    });

    apply.addEventListener('click', () => {
      if (!fromEl.value || !toEl.value) { alert('Pick both a start and an end.'); return; }
      const fromD = new Date(fromEl.value);
      const toD   = new Date(toEl.value);
      if (toD <= fromD) { alert('"To" must be after "From".'); return; }
      // Persist as ISO Z on the select element so getDiscoverParams reads it.
      sel.setAttribute('data-custom-from', fromD.toISOString().slice(0, 19) + 'Z');
      sel.setAttribute('data-custom-to',   toD.toISOString().slice(0, 19)   + 'Z');
      sel.value = 'custom';
      discoverOffset = 0;
      loadDiscover();
    });
  })();
  let discoverSearchTimeout = null;
  document.getElementById('discoverSearch')?.addEventListener('input', () => {
    if (discoverSearchTimeout) clearTimeout(discoverSearchTimeout);
    discoverSearchTimeout = setTimeout(() => { discoverOffset = 0; loadDiscover(); }, 400);
  });
  document.getElementById('discoverSearch')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.ctrlKey && !e.metaKey) {
      clearTimeout(discoverSearchTimeout);
      discoverOffset = 0;
      const q = document.getElementById('discoverSearch')?.value || '';
      if (q) discoverAddToHistory(q);
      loadDiscover();
    }
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
    const pinned = document.getElementById('discoverFilterPin')?.checked;
    const filter = { field, op, value, type };
    if (pinned) {
      discoverPinnedFilters.push(filter);
      try { localStorage.setItem('disc_pinned_filters', JSON.stringify(discoverPinnedFilters)); } catch(e){}
    } else {
      discoverDslFilters.push(filter);
    }
    const valEl = document.getElementById('discoverFilterValue');
    if (valEl) valEl.value = '';
    const pinEl = document.getElementById('discoverFilterPin');
    if (pinEl) pinEl.checked = false;
    renderDiscoverFilterPills(); discoverOffset = 0; loadDiscover();
  });
  document.getElementById('discoverFilterValue')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('discoverFilterAdd')?.click();
  });
  document.getElementById('discoverPageSize')?.addEventListener('change', () => { discoverOffset = 0; loadDiscover(); });
  // Field search (inside the Columns modal)
  let discoverFieldSearchTimeout = null;
  document.getElementById('discoverFieldSearch')?.addEventListener('input', () => {
    clearTimeout(discoverFieldSearchTimeout);
    discoverFieldSearchTimeout = setTimeout(() => renderDiscoverFieldsSidebar(), 200);
  });
  // Columns manager modal
  const _closeColsModal = () => document.getElementById('discoverColumnsModal')?.classList.add('hidden');
  document.getElementById('discoverColumnsBtn')?.addEventListener('click', () => {
    const m = document.getElementById('discoverColumnsModal');
    if (!m) return;
    m.classList.remove('hidden');
    renderDiscoverFieldsSidebar();
    setTimeout(() => document.getElementById('discoverFieldSearch')?.focus(), 50);
  });
  document.getElementById('discoverColumnsClose')?.addEventListener('click', _closeColsModal);
  document.getElementById('discoverColumnsDone')?.addEventListener('click', _closeColsModal);
  document.getElementById('discoverColumnsModal')?.addEventListener('click', (e) => { if (e.target.id === 'discoverColumnsModal') _closeColsModal(); });
  document.getElementById('discoverColumnsReset')?.addEventListener('click', () => {
    discoverSelectedFields = ['timestamp', 'rule_level', 'title', 'agent_name', 'src_ip', 'username', 'process_name'];
    renderDiscoverFieldsSidebar(); renderDiscoverThead(); discoverOffset = 0; loadDiscover();
  });
  // Search history button
  document.getElementById('discoverSearchHistBtn')?.addEventListener('click', (e) => { e.stopPropagation(); discoverShowHistory(); });
  // Auto-refresh
  document.getElementById('discoverAutoRefreshBtn')?.addEventListener('click', discoverToggleAutoRefresh);
  document.getElementById('discoverAutoRefreshInterval')?.addEventListener('change', (e) => {
    if (discoverAutoRefreshActive) { discoverStopAutoRefresh(); discoverStartAutoRefresh(parseInt(e.target.value, 10)); }
  });
  // Tools dropdown
  document.getElementById('discoverToolsBtn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    document.getElementById('discoverToolsDrop')?.classList.toggle('hidden');
  });
  document.getElementById('discoverToolsDrop')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action = btn.getAttribute('data-action');
    document.getElementById('discoverToolsDrop')?.classList.add('hidden');
    if (action === 'save-search') discoverShowSavedModal();
    else if (action === 'load-search') discoverShowSavedModal();
    else if (action === 'share-url') discoverShareUrl();
    else if (action === 'inspector') discoverShowInspector();
    else if (action === 'density-compact') discoverSetDensity('compact');
    else if (action === 'density-default') discoverSetDensity('default');
    else if (action === 'density-comfortable') discoverSetDensity('comfortable');
    else if (action === 'ioc-hunt') { document.getElementById('discoverIOCModal')?.classList.remove('hidden'); document.getElementById('discoverIOCInput')?.focus(); }
    else if (action === 'save-hunt') discoverSaveAsHunt();
    else if (action === 'shortcuts') discoverShowShortcutsModal();
  });
  // Inspector modal
  document.getElementById('discoverInspectorClose')?.addEventListener('click', () => document.getElementById('discoverInspectorModal')?.classList.add('hidden'));
  document.getElementById('discoverInspectorClose2')?.addEventListener('click', () => document.getElementById('discoverInspectorModal')?.classList.add('hidden'));
  document.getElementById('discoverInspectorCopy')?.addEventListener('click', () => {
    const txt = document.getElementById('discoverInspectorBody')?.textContent || '';
    if (navigator.clipboard) navigator.clipboard.writeText(txt).then(() => showDiscoverToast('DSL copied'));
    else { const t=document.createElement('textarea');t.value=txt;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showDiscoverToast('DSL copied'); }
  });
  // Saved searches modal
  document.getElementById('discoverSavedClose')?.addEventListener('click', () => document.getElementById('discoverSavedModal')?.classList.add('hidden'));
  document.getElementById('discoverSaveCurrentBtn')?.addEventListener('click', () => {
    const name = document.getElementById('discoverSaveNameInput')?.value || '';
    if (name.trim()) discoverSaveSearch(name);
  });
  document.getElementById('discoverSaveNameInput')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') document.getElementById('discoverSaveCurrentBtn')?.click(); });
  // Shortcuts modal
  document.getElementById('discoverShortcutsClose')?.addEventListener('click', () => document.getElementById('discoverShortcutsModal')?.classList.add('hidden'));
  // IOC modal
  document.getElementById('discoverIOCClose')?.addEventListener('click', () => document.getElementById('discoverIOCModal')?.classList.add('hidden'));
  document.getElementById('discoverIOCSearch')?.addEventListener('click', () => discoverIOCQuickSearch(document.getElementById('discoverIOCInput')?.value || ''));
  document.getElementById('discoverIOCInput')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') document.getElementById('discoverIOCSearch')?.click(); });
  // Tag modal
  document.getElementById('discoverTagClose')?.addEventListener('click', () => document.getElementById('discoverTagModal')?.classList.add('hidden'));
  document.getElementById('discoverTagCancel')?.addEventListener('click', () => document.getElementById('discoverTagModal')?.classList.add('hidden'));
  document.getElementById('discoverTagSave')?.addEventListener('click', () => {
    const modal = document.getElementById('discoverTagModal');
    const tag = document.getElementById('discoverTagInput')?.value.trim();
    if (tag && modal?._alert) { discoverTagEvent(modal._alert, tag); renderDiscoverTagCurrentList(modal._alert); document.getElementById('discoverTagInput').value = ''; showDiscoverToast('Tag applied: ' + tag); }
    if (!tag) modal?.classList.add('hidden');
  });
  document.getElementById('discoverTagInput')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') document.getElementById('discoverTagSave')?.click(); });
  // Correlation panel close
  document.getElementById('discoverCorrelationClose')?.addEventListener('click', () => { const c = document.getElementById('discoverCorrelationCard'); if (c) c.style.display = 'none'; });
  // Close dropdowns/popover on outside click
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#discoverToolsBtn') && !e.target.closest('#discoverToolsDrop')) document.getElementById('discoverToolsDrop')?.classList.add('hidden');
    if (!e.target.closest('#discoverSearchHistBtn') && !e.target.closest('#discoverSearchHistoryDrop')) document.getElementById('discoverSearchHistoryDrop')?.classList.add('hidden');
    if (!e.target.closest('#discoverFieldStatsPop') && !e.target.classList.contains('disc-fsp-trigger')) document.getElementById('discoverFieldStatsPop')?.classList.add('hidden');
    // Modal overlays — click outside to close
    ['discoverInspectorModal','discoverSavedModal','discoverShortcutsModal','discoverIOCModal','discoverTagModal'].forEach(id => {
      const m = document.getElementById(id);
      if (m && !m.classList.contains('hidden') && e.target === m) m.classList.add('hidden');
    });
  });
  // Keyboard shortcuts global handler
  document.addEventListener('keydown', discoverHandleKeyboard);
  // Results table: row click and bookmark click
  document.getElementById('discoverResultsWrap')?.addEventListener('click', (e) => {
    const bmBtn = e.target.closest('.disc-bookmark-btn');
    if (bmBtn) {
      e.stopPropagation();
      const idx = bmBtn.getAttribute('data-index');
      const alert = discoverAlertsCache[idx];
      if (alert) { discoverToggleBookmark(alert); bmBtn.classList.toggle('active'); bmBtn.title = discoverBookmarks.has(_alertId(alert)) ? 'Remove bookmark' : 'Bookmark event'; }
      return;
    }
    const row = e.target.closest('.discover-row');
    if (!row) return;
    const idx = row.getAttribute('data-index');
    if (discoverAlertsCache[idx] != null) openDiscoverDetail(discoverAlertsCache[idx]);
  });

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
    const [tacticsRes, techniquesRes] = await Promise.all([
      fetchJson(API.mitreTactics + '?size=20').catch(() => ({})),
      fetchJson(API.mitreMatrix).catch(() => ({techniques: []}))
    ]);
    const apiTechs = Array.isArray(techniquesRes.techniques) ? techniquesRes.techniques : [];
    const apiTotal = apiTechs.reduce((s, t) => s + (t.count||0), 0);

    const tacticTotal = (id) =>
      (Array.isArray(tacticsRes.buckets) ? tacticsRes.buckets : []).find(t => (t.tactic||t.key||'') === id)?.count || 0;

    const allTechs   = apiTechs.map(t => ({ id: t.technique_id, n: t.technique_name, c: t.count, lvl: t.count >= 8 ? 'hot3' : t.count >= 5 ? 'hot2' : t.count >= 3 ? 'hot1' : 'warm' }));
    const techCount  = allTechs.filter(t => (t.c||0) > 0).length;
    const totalA     = apiTotal;
    const critTechs  = allTechs.filter(t => (t.c||0) >= 5).length;
    const tacsCovered= MITRE_TACTICS.filter(t => tacticTotal(t.id) > 0).length;

    // Update KPIs
    const setKpi = (valId, tagId, spId, val, tag, kind, sub, subId, color) => {
      const vEl = document.getElementById(valId); if (vEl) vEl.textContent = val;
      const tEl = document.getElementById(tagId);  if (tEl) { tEl.textContent = tag; tEl.className = `kpi-tag ${kind}`; }
      const sEl = document.getElementById(subId);  if (sEl) sEl.textContent = sub;
      const spEl= document.getElementById(spId);   if (spEl) spEl.innerHTML = _spark([], color);
    };
    setKpi('mitreTechniquesCount','mitreTechTag','mitreTechSpark',  techCount,  techCount>0?'+'+techCount:'IDLE', techCount>0?'up':'ok', 'unique T-IDs · 24h', 'mitreTechSub', 'var(--low)');
    setKpi('mitreTacticsCount',  'mitreTacTag',  'mitreTacSpark',   `${tacsCovered}/${MITRE_TACTICS.length}`, tacsCovered>0?'OK':'CLEAR', 'ok', 'of ATT&CK enterprise', null, 'var(--accent)');
    setKpi('mitreTotalAlerts',   'mitreTotalTag','mitreTotalSpark',  totalA, totalA>0?'+'+totalA:'CLEAR', totalA>0?'up':'ok', 'mapped to T-IDs · 24h', null, 'var(--high)');
    setKpi('mitreCriticalCount', 'mitreCritTag', 'mitreCritSpark',   critTechs, critTechs>0?'ATTN':'CLEAR', critTechs>0?'crit':'ok', 'count ≥ 5 detections', null, 'var(--crit)');
    const metaEl = document.getElementById('mitreTacticsCoveredMeta'); if (metaEl) metaEl.textContent = `${tacsCovered}/${MITRE_TACTICS.length}`;

    // ATT&CK Matrix heatmap
    const matrixWrap = document.getElementById('mitreMatrixWrap');
    const matrixDot  = document.getElementById('mitreMatrixDot');
    const matrixMeta = document.getElementById('mitreMatrixMeta');
    // Techniques that carry no recognised tactic mapping — surfaced separately
    // so their detections stay visible instead of vanishing from the matrix.
    const knownTacticIds = new Set(MITRE_TACTICS.map(t => t.id));
    const unmappedTechs = apiTechs
      .filter(a => !knownTacticIds.has(a.tactic || ''))
      .map(a => ({ id: a.technique_id, n: a.technique_name, c: a.count, lvl: a.count >= 8 ? 'hot3' : a.count >= 5 ? 'hot2' : a.count >= 3 ? 'hot1' : 'warm' }));
    const unmappedTotal = unmappedTechs.reduce((a, c) => a + (c.c || 0), 0);

    if (matrixDot) matrixDot.style.background = totalA > 0 ? 'var(--crit)' : 'var(--ok)';
    if (matrixMeta) matrixMeta.textContent = totalA > 0
      ? `${techCount} techniques · ${tacsCovered}/${MITRE_TACTICS.length} tactics` + (unmappedTotal ? ` · ${unmappedTechs.length} unmapped` : '')
      : 'Configure rules → MITRE mappings';
    if (matrixWrap) {
      if (totalA === 0) {
        matrixWrap.innerHTML = `<div class="sigil-block"><div class="sigil" style="background:radial-gradient(circle,rgba(45,212,191,0.10),transparent 70%);color:var(--accent)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="m16 8-6 2-2 6 6-2 2-6z"/></svg></div><div class="sigil-text"><h4>No MITRE ATT&amp;CK data yet</h4><p>Alerts with MITRE technique mappings will populate this matrix. Add MITRE IDs to your detection rules to see coverage here.</p></div><div style="flex:1"></div><button class="act-btn" onclick="goToPage('rule-versions')">Detection Studio</button></div>`;
      } else {
        // Banner shown when alerts exist but lack tactic data (explains 0/12)
        const banner = (tacsCovered === 0 && unmappedTotal > 0)
          ? `<div class="mitre-note"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v4h1"/></svg><span><b>${unmappedTotal} detections</b> carry a technique but no ATT&CK <b>tactic</b> — that's why tactic coverage reads 0/${MITRE_TACTICS.length}. Add a <code>tactic</code> to these rules' <code>mitre:</code> blocks to map them onto the matrix.</span></div>`
          : '';
        const cols = MITRE_TACTICS.map(t => {
          const techs = apiTechs.filter(a => (a.tactic || '') === t.id).map(a => ({ id: a.technique_id, n: a.technique_name, c: a.count, lvl: a.count >= 8 ? 'hot3' : a.count >= 5 ? 'hot2' : a.count >= 3 ? 'hot1' : 'warm' }));
          const ttl = techs.reduce((a, c) => a + (c.c || 0), 0);
          const isHot = ttl >= 5;
          return `<div class="matrix-col"><div class="matrix-col-h${isHot ? ' hot' : ''}">${escapeHtml(t.short)}<span class="count">${ttl} · ${t.id}</span></div>` +
            techs.map(tech => `<div class="matrix-cell ${tech.lvl || ''}" title="${escapeHtml(tech.id || '')} · ${escapeHtml(tech.n || '')} · ${tech.c} detections"><span class="cell-name">${escapeHtml(tech.n || tech.id || '')}</span><span class="n">${tech.c}</span></div>`).join('') +
            `</div>`;
        }).join('');
        const unmappedCol = unmappedTechs.length
          ? `<div class="matrix-col unmapped"><div class="matrix-col-h hot">Unmapped<span class="count">${unmappedTotal} · no tactic</span></div>` +
              unmappedTechs.map(tech => `<div class="matrix-cell ${tech.lvl || ''}" title="${escapeHtml(tech.id || '')} · ${escapeHtml(tech.n || '')} · ${tech.c} detections · no tactic mapping"><span class="cell-name">${escapeHtml(tech.n || tech.id || '')}</span><span class="n">${tech.c}</span></div>`).join('') +
            `</div>`
          : '';
        // Unmapped column first so populated detections are visible immediately
        // instead of being scrolled off the right behind empty tactic columns.
        matrixWrap.innerHTML = banner + `<div class="matrix-wrap"><div class="matrix">` + unmappedCol + cols + `</div></div>`;
      }
    }

    // Top 10 techniques
    const topList   = document.getElementById('mitreTopTechniques');
    const tech10Dot = document.getElementById('mitreTech10Dot');
    const topTechs  = [...allTechs].filter(t => (t.c||0) > 0).sort((a,b) => (b.c||0)-(a.c||0)).slice(0,10);
    if (tech10Dot) tech10Dot.style.background = topTechs.length ? 'var(--crit)' : 'var(--info,#94A3B8)';
    if (topList) {
      if (!topTechs.length) {
        topList.innerHTML = `<div class="chart-empty"><div class="chart-empty-icon info"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="9"/><path d="M22 12h-4M6 12H2M12 6V2M12 22v-4"/></svg></div><div class="chart-empty-msg">No technique data yet</div><div class="chart-empty-sub">Top techniques will rank here once detections fire</div></div>`;
      } else {
        topList.innerHTML = topTechs.map((t,i) =>
          `<div class="row"><span class="row-num">${i+1}</span><div class="row-main"><span class="row-pri mono">${escapeHtml(t.n||t.technique_name||'—')}</span><span class="row-sec">${escapeHtml(t.id||t.technique_id||'')}</span></div><div class="row-bar ${t.lvl==='warm'?'med':''}"><i style="width:${Math.min(100,(t.c/topTechs[0].c)*100)}%"></i></div><span class="row-meta">${t.c}</span></div>`
        ).join('');
      }
    }

    // Top tactics by volume (hbar chart)
    const tacBar    = document.getElementById('mitreTacticsBar');
    const tacVolDot = document.getElementById('mitreTacVolDot');
    const topTacs   = MITRE_TACTICS.map(t => ({...t, c: tacticTotal(t.id)})).filter(t => t.c > 0).sort((a,b) => b.c-a.c).slice(0,6);
    const tacMax    = Math.max(...topTacs.map(t => t.c), 1);
    if (tacVolDot) tacVolDot.style.background = topTacs.length ? 'var(--high)' : 'var(--info,#94A3B8)';
    if (tacBar) {
      if (!topTacs.length) {
        tacBar.innerHTML = `<div class="chart-empty" style="padding:20px 14px 24px"><div class="chart-empty-icon info"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 12a9 9 0 1 1-9-9v9h9z"/></svg></div><div class="chart-empty-msg">No tactic data yet</div><div class="chart-empty-sub">Volume per tactic will appear here as alerts arrive</div></div>`;
      } else {
        tacBar.innerHTML = topTacs.map(t =>
          `<div class="hbar-row"><span class="hbar-l">${escapeHtml(t.name)}</span><div class="hbar-bar ${t.c>=8?'':t.c>=4?'high':'med'}"><i style="width:${(t.c/tacMax)*100}%"></i></div><span class="hbar-v">${t.c}</span></div>`
        ).join('');
      }
    }

    // Kill-chain distribution
    const distWrap = document.getElementById('mitreDistWrap');
    const dist = [
      { label:'Pre-compromise',   ids:['TA0043','TA0042','TA0001'], color:'var(--low)'  },
      { label:'Execution',        ids:['TA0002','TA0003','TA0004'], color:'var(--med)'  },
      { label:'Action on target', ids:['TA0005','TA0006','TA0007','TA0008','TA0009'], color:'var(--high)' },
      { label:'Exfil & impact',   ids:['TA0011','TA0010','TA0040'], color:'var(--crit)' },
    ].map(b => ({ ...b, c: b.ids.reduce((a,id) => a+tacticTotal(id), 0) }));
    const distTotal = dist.reduce((a,b) => a+b.c, 0) || 1;
    if (distWrap) {
      if (distTotal <= 1) {
        distWrap.innerHTML = `<div class="chart-empty" style="padding:24px"><div class="chart-empty-icon info"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 3v18M6 7l-3 7c0 2 1.5 3 3 3s3-1 3-3L6 7zM18 7l-3 7c0 2 1.5 3 3 3s3-1 3-3l-3-7zM5 7h14"/></svg></div><div class="chart-empty-msg">No distribution data</div><div class="chart-empty-sub">The kill-chain breakdown will populate as detections fire</div></div>`;
      } else {
        distWrap.innerHTML = `<div class="dist">` +
          dist.map(b => `<div class="dist-item">
            <span class="label">${escapeHtml(b.label)}</span>
            <span class="v">${b.c}</span>
            <span class="pct">${Math.round((b.c/distTotal)*100)}% of detections</span>
            <div class="dist-bar"><i style="width:${(b.c/distTotal)*100}%;background:${b.color}"></i></div>
          </div>`).join('') + `</div>`;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // File Integrity Monitoring Page
  // ---------------------------------------------------------------------------
  async function loadFimPage() {
    const el = id => document.getElementById(id);
    // Pivot from an agent detail page → pre-fill the agent filter so the
    // initial events load (and the summary cards) are scoped to this node.
    if (window._pivotAgent) {
      if (el('fimAgentFilter')) el('fimAgentFilter').value = window._pivotAgent.name || '';
      window._pivotAgent = null;
    }
    const _fimAgentQ = ((el('fimAgentFilter') && el('fimAgentFilter').value) || '').trim();
    const _fimEventsUrl = API.fimEvents + '?size=20&offset=0' +
      (_fimAgentQ ? '&agent_name=' + encodeURIComponent(_fimAgentQ) : '');
    const [summary, events] = await Promise.all([
      fetchJson(API.fimSummary).catch(() => ({total: 0, added: 0, modified: 0, deleted: 0})),
      fetchJson(_fimEventsUrl).catch(() => ({hits: [], total: 0}))
    ]);
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
      const fimW = 'grid-template-columns:140px 120px 90px 1fr 160px 80px';
      tbody.innerHTML = rows.length ? rows.map(r => {
        const ts = r.timestamp ? new Date(r.timestamp).toLocaleString() : '—';
        const agent = escapeHtml(r.agent_name || r.agent || '—');
        const action = escapeHtml(r.fim_action || r.action || (r.event_data && r.event_data.type) || '—');
        const path = escapeHtml(r.fim_path || r.file_path || (r.event_data && r.event_data.path) || '—');
        const fullHash = r.fim_sha256 || r.sha256 || (r.event_data && r.event_data.sha256) || '';
        const hash = escapeHtml(fullHash.substring(0, 12) + (fullHash.length > 12 ? '…' : (fullHash ? '' : '—')));
        const size = escapeHtml(String(r.fim_size || r.file_size || (r.event_data && r.event_data.size) || '—'));
        const aCol = action === 'added' ? 'var(--ok)' : action === 'deleted' ? 'var(--crit)' : 'var(--high)';
        return `<div class="tbl-r" style="${fimW}"><span class="tbl-time">${ts}</span><span class="tbl-mono">${agent}</span><span><span class="pill" style="color:${aCol};background:${aCol}22;border:1px solid ${aCol}44">${action}</span></span><span class="tbl-mono" style="font-size:10px">${path}</span><span class="tbl-mono" style="font-size:10px">${hash}</span><span class="tbl-mono">${size}</span></div>`;
      }).join('') : `<div class="sigil-block"><div class="sigil-text"><h4>No FIM events found</h4><p>Enable File Integrity Monitoring in WatchNode agent config</p></div></div>`;
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
        const fimW2 = 'grid-template-columns:140px 120px 90px 1fr 160px 80px';
        tbody2.innerHTML = rows2.length ? rows2.map(r => {
          const ts = r.timestamp ? new Date(r.timestamp).toLocaleString() : '—';
          const a2 = escapeHtml(r.agent_name || r.agent || '—');
          const act2 = escapeHtml(r.fim_action || r.action || (r.event_data && r.event_data.type) || '—');
          const p2 = escapeHtml(r.fim_path || r.file_path || (r.event_data && r.event_data.path) || '—');
          const h2 = escapeHtml((r.fim_sha256 || r.sha256 || '').substring(0, 12));
          const s2 = String(r.fim_size || r.file_size || (r.event_data && r.event_data.size) || '—');
          const ac2 = act2 === 'added' ? 'var(--ok)' : act2 === 'deleted' ? 'var(--crit)' : 'var(--high)';
          return `<div class="tbl-r" style="${fimW2}"><span class="tbl-time">${ts}</span><span class="tbl-mono">${a2}</span><span><span class="pill" style="color:${ac2};background:${ac2}22;border:1px solid ${ac2}44">${act2}</span></span><span class="tbl-mono" style="font-size:10px">${p2}</span><span class="tbl-mono" style="font-size:10px">${h2}</span><span class="tbl-mono">${s2}</span></div>`;
        }).join('') : `<div class="sigil-block" style="padding:20px"><div class="sigil-text"><p>No results.</p></div></div>`;
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
      const audW = 'grid-template-columns:140px 120px 100px 1fr 120px 70px 80px';
      tbody.innerHTML = rows.length ? rows.map(r => {
        const ts = r.timestamp ? new Date(r.timestamp).toLocaleString() : '—';
        const agent = escapeHtml(r.agent_name || (r.agent && r.agent.name) || '—');
        const user = escapeHtml((r.event_data && (r.event_data.dstuser || r.event_data.user)) || r.user || '—');
        const desc = escapeHtml(r.rule_description || (r.rule && r.rule.description) || '—');
        const srcip = escapeHtml((r.event_data && r.event_data.srcip) || r.srcip || '—');
        const level = r.rule_level || (r.rule && r.rule.level) || '—';
        const ruleId = r.rule_id || (r.rule && r.rule.id) || '—';
        const lvlCol = level >= 10 ? 'var(--crit)' : level >= 7 ? 'var(--high)' : 'var(--fg-3)';
        return `<div class="tbl-r" style="${audW}"><span class="tbl-time">${ts}</span><span class="tbl-mono">${agent}</span><span class="tbl-mono">${user}</span><span class="tbl-pri">${desc}</span><span class="tbl-mono">${srcip}</span><span style="font-family:var(--font-mono);font-weight:600;color:${lvlCol}">${level}</span><span class="tbl-mono">${ruleId}</span></div>`;
      }).join('') : `<div class="sigil-block"><div class="sigil-text"><h4>No authentication events found</h4><p>Enable auth log collection in WatchNode config</p></div></div>`;
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
        const audW2 = 'grid-template-columns:140px 120px 100px 1fr 120px 70px 80px';
        tbody2.innerHTML = rows2.length ? rows2.map(r => {
          const ts = r.timestamp ? new Date(r.timestamp).toLocaleString() : '—';
          const a2 = escapeHtml(r.agent_name || (r.agent && r.agent.name) || '—');
          const u2 = escapeHtml((r.event_data && (r.event_data.dstuser || r.event_data.user)) || r.user || '—');
          const d2 = escapeHtml(r.rule_description || (r.rule && r.rule.description) || '—');
          const ip2 = escapeHtml((r.event_data && r.event_data.srcip) || r.srcip || '—');
          const lv2 = r.rule_level || (r.rule && r.rule.level) || '—';
          const rid2 = r.rule_id || (r.rule && r.rule.id) || '—';
          const lc2 = lv2 >= 10 ? 'var(--crit)' : lv2 >= 7 ? 'var(--high)' : 'var(--fg-3)';
          return `<div class="tbl-r" style="${audW2}"><span class="tbl-time">${ts}</span><span class="tbl-mono">${a2}</span><span class="tbl-mono">${u2}</span><span class="tbl-pri">${d2}</span><span class="tbl-mono">${ip2}</span><span style="font-family:var(--font-mono);font-weight:600;color:${lc2}">${lv2}</span><span class="tbl-mono">${rid2}</span></div>`;
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
  // Logs / Raw Events Explorer
  //
  // SOC analysts need every event, not just rule-matched alerts. This page
  // talks to /api/logs/* which queries watchvault-events-* directly.
  // ---------------------------------------------------------------------------
  let _logsOffset = 0;
  let _logsLastHits = [];

  function _logsParams() {
    const el = id => document.getElementById(id);
    const size = parseInt((el('logsPageSize') && el('logsPageSize').value) || '50', 10);
    let range = (el('logsTimeRange') && el('logsTimeRange').value) || '24h';
    if (range === 'custom') {
      const f = el('logsCustomFrom') && el('logsCustomFrom').value;
      const t = el('logsCustomTo')   && el('logsCustomTo').value;
      if (f && t) {
        const fromIso = new Date(f).toISOString().slice(0, 19) + 'Z';
        const toIso   = new Date(t).toISOString().slice(0, 19) + 'Z';
        range = `custom:${fromIso}|${toIso}`;
      } else {
        range = '24h';
      }
    }
    const bounds = getTimeRangeBounds(range);
    const p = new URLSearchParams();
    p.set('size', size);
    p.set('offset', _logsOffset);
    if (bounds.from) p.set('time_from', bounds.from);
    if (bounds.to) p.set('time_to', bounds.to);
    const q = ((el('logsQuery') && el('logsQuery').value) || '').trim();
    if (q) p.set('q', q);
    const src = (el('logsSource') && el('logsSource').value) || '';
    if (src) p.set('source', src);
    const agent = ((el('logsAgent') && el('logsAgent').value) || '').trim();
    if (agent) p.set('agent_name', agent);
    const evid = ((el('logsEventId') && el('logsEventId').value) || '').trim();
    if (evid) p.set('event_id', evid);
    return { params: p, size };
  }

  function _logsSummarize(hit) {
    // Prefer Windows event description, then channel/message, then any rule text.
    const parts = [];
    if (hit.win_event_description) parts.push(hit.win_event_description);
    if (hit.TargetUserName) parts.push('user=' + hit.TargetUserName);
    else if (hit.SubjectUserName) parts.push('user=' + hit.SubjectUserName);
    if (hit.IpAddress && hit.IpAddress !== '-') parts.push('src=' + hit.IpAddress);
    if (hit.Image) parts.push('img=' + hit.Image);
    if (parts.length) return parts.join(' · ');
    if (hit.message) return String(hit.message).slice(0, 240);
    if (hit.rule_description) return String(hit.rule_description);
    // Structured fallbacks for non-Windows events (network/process/fim/registry),
    // which have no win_event_description but carry useful fields.
    const et = String(hit.event_type || '');
    if (et.startsWith('network')) {
      const l = hit.laddr ? hit.laddr + (hit.lport ? ':' + hit.lport : '') : '';
      const r = (hit.raddr && hit.raddr !== '0.0.0.0') ? ' → ' + hit.raddr + (hit.rport ? ':' + hit.rport : '') : '';
      const st = hit.status ? ' [' + hit.status + ']' : '';
      const pn = hit.process_name ? ' (' + hit.process_name + ')' : '';
      if (l || r) return (et + ' ' + l + r + st + pn).trim();
    }
    if (et.startsWith('process')) {
      const n = hit.process_name || hit.Image || hit.name || '';
      const pid = (hit.pid != null && hit.pid !== 0) ? ' pid=' + hit.pid : '';
      if (n) return (et + ' ' + n + pid).trim();
    }
    if (et.startsWith('fim') || et.startsWith('registry')) {
      const f = hit.path || hit.file || hit.key || hit.target || '';
      if (f) return (et + ' ' + f).trim();
    }
    if (hit.raw) return String(hit.raw).slice(0, 240);
    if (et) return et;  // at minimum, show the event type rather than "(no summary)"
    return '(no summary)';
  }

  function _logsSource(hit) {
    // `event_type` is the real source discriminator (e.g. "network.connection",
    // "log.eventlog"). The bare `type` is a numeric data field, not a source.
    if (hit.event_type) return String(hit.event_type);
    if (hit.tags && hit.tags.source) return String(hit.tags.source);
    if (hit.source) return String(hit.source);
    if (hit.collector) return String(hit.collector);
    return '—';
  }

  function _logsEventId(hit) {
    return hit.win_event_id || hit.event_id || '—';
  }

  function _logsAgent(hit) {
    return hit.agent_name || (hit.agent && hit.agent.name) || hit.computer || '—';
  }

  async function reloadLogs() {
    const el = id => document.getElementById(id);
    const { params, size } = _logsParams();
    const url = API.logsSearch + '?' + params.toString();
    const data = await fetchJson(url).catch(() => ({ hits: [], total: 0 }));
    const hits = data.hits || [];
    _logsLastHits = hits;
    const total = data.total || 0;
    if (el('logsHits')) el('logsHits').textContent = total.toLocaleString() + ' hits';
    if (el('logsInfo')) el('logsInfo').textContent = `Showing ${hits.length} of ${total.toLocaleString()}`;
    if (el('logsPageInfo')) el('logsPageInfo').textContent = `Page ${Math.floor(_logsOffset / size) + 1}`;
    if (el('logsPrev')) el('logsPrev').disabled = _logsOffset === 0;
    if (el('logsNext')) el('logsNext').disabled = (_logsOffset + size) >= total;

    const tbody = el('logsBody');
    if (!tbody) return;
    const cols = 'grid-template-columns:160px 130px 110px 80px 1fr 90px';
    tbody.innerHTML = hits.length ? hits.map((h, i) => {
      const ts = h.timestamp ? new Date(h.timestamp).toLocaleString() : '—';
      const agent = escapeHtml(_logsAgent(h));
      const src = escapeHtml(_logsSource(h));
      const evid = escapeHtml(String(_logsEventId(h)));
      const summary = escapeHtml(_logsSummarize(h));
      return `<div class="tbl-r" style="${cols}">
        <span class="tbl-time">${ts}</span>
        <span class="tbl-mono">${agent}</span>
        <span class="tbl-mono">${src}</span>
        <span class="tbl-mono">${evid}</span>
        <span class="tbl-pri" title="${summary}">${summary}</span>
        <span><button type="button" class="act-btn logs-view-btn" data-idx="${i}" style="height:22px;padding:0 8px;font-size:11px">View</button></span>
      </div>`;
    }).join('') : `<div class="sigil-block"><div class="sigil-text"><h4>No events found</h4><p>Try widening the time range, removing filters, or clearing the search query.</p></div></div>`;

    // Wire detail buttons
    tbody.querySelectorAll('.logs-view-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-idx'), 10);
        _logsShowDetail(_logsLastHits[idx]);
      });
    });
  }

  function _logsShowDetail(hit) {
    const el = id => document.getElementById(id);
    const drawer = el('logsDetailDrawer');
    const body = el('logsDetailBody');
    if (!drawer || !body) return;
    body.textContent = JSON.stringify(hit, null, 2);
    drawer.classList.remove('hidden');
  }

  async function _logsRefreshSummary() {
    const el = id => document.getElementById(id);
    const bounds = getTimeRangeBounds((el('logsTimeRange') && el('logsTimeRange').value) || '24h');
    const p = new URLSearchParams();
    if (bounds.from) p.set('time_from', bounds.from);
    if (bounds.to) p.set('time_to', bounds.to);
    const data = await fetchJson(API.logsSummary + '?' + p.toString()).catch(() => null);
    if (!data) return;
    if (el('logsTotal')) el('logsTotal').textContent = (data.total || 0).toLocaleString();
    const top = (arr) => (arr && arr[0]) || null;
    const t = top(data.by_type);
    const a = top(data.by_agent);
    const e = top(data.by_event_id);
    if (el('logsTopType'))  el('logsTopType').textContent  = t ? t.key : '—';
    if (el('logsTopTypeCount')) el('logsTopTypeCount').textContent = t ? (t.count.toLocaleString() + ' events') : '—';
    if (el('logsTopAgent')) el('logsTopAgent').textContent = a ? a.key : '—';
    if (el('logsTopAgentCount')) el('logsTopAgentCount').textContent = a ? (a.count.toLocaleString() + ' events') : '—';
    if (el('logsTopEvid'))  el('logsTopEvid').textContent  = e ? e.key : '—';
    if (el('logsTopEvidCount')) el('logsTopEvidCount').textContent = e ? (e.count.toLocaleString() + ' events') : '—';
    const rng = (el('logsTimeRange') && el('logsTimeRange').value) || '24h';
    if (el('logsRangeLabel')) el('logsRangeLabel').textContent = 'last ' + rng;
  }

  let _logsWired = false;
  async function loadLogsPage() {
    _logsOffset = 0;
    await Promise.all([reloadLogs(), _logsRefreshSummary()]);

    if (_logsWired) return;
    _logsWired = true;
    const el = id => document.getElementById(id);
    const apply = () => { _logsOffset = 0; reloadLogs(); _logsRefreshSummary(); };
    el('logsApply') && el('logsApply').addEventListener('click', apply);
    el('logsReset') && el('logsReset').addEventListener('click', () => {
      ['logsQuery', 'logsAgent', 'logsEventId'].forEach(id => { if (el(id)) el(id).value = ''; });
      if (el('logsSource')) el('logsSource').value = '';
      if (el('logsTimeRange')) el('logsTimeRange').value = '24h';
      if (el('logsPageSize')) el('logsPageSize').value = '50';
      apply();
    });
    el('logsQuery') && el('logsQuery').addEventListener('keydown', e => { if (e.key === 'Enter') apply(); });
    el('logsAgent') && el('logsAgent').addEventListener('keydown', e => { if (e.key === 'Enter') apply(); });
    el('logsEventId') && el('logsEventId').addEventListener('keydown', e => { if (e.key === 'Enter') apply(); });
    el('logsTimeRange') && el('logsTimeRange').addEventListener('change', () => {
      const wrap = el('logsCustomRange');
      const sel = el('logsTimeRange');
      if (sel.value === 'custom') {
        wrap && wrap.classList.remove('hidden');
        // seed defaults if empty
        const f = el('logsCustomFrom'), t = el('logsCustomTo');
        if (f && !f.value) {
          const now = new Date();
          const past = new Date(now.getTime() - 24*3600*1000);
          const local = d => new Date(d.getTime() - d.getTimezoneOffset()*60000).toISOString().slice(0,16);
          f.value = local(past); if (t) t.value = local(now);
        }
        // do NOT auto-apply — wait for user to click Search
      } else {
        wrap && wrap.classList.add('hidden');
        apply();
      }
    });
    el('logsSource') && el('logsSource').addEventListener('change', apply);
    el('logsPageSize') && el('logsPageSize').addEventListener('change', apply);
    el('logsPrev') && el('logsPrev').addEventListener('click', () => {
      const { size } = _logsParams();
      if (_logsOffset >= size) { _logsOffset -= size; reloadLogs(); }
    });
    el('logsNext') && el('logsNext').addEventListener('click', () => {
      const { size } = _logsParams();
      _logsOffset += size; reloadLogs();
    });
    // Quick-filter chips set EventID and re-query.
    document.querySelectorAll('#page-logs .logs-chip').forEach(btn => {
      btn.addEventListener('click', () => {
        if (el('logsEventId')) el('logsEventId').value = btn.getAttribute('data-evid') || '';
        if (el('logsSource')) el('logsSource').value = 'eventlog';
        apply();
      });
    });
    el('logsDetailClose') && el('logsDetailClose').addEventListener('click', () => {
      const drawer = el('logsDetailDrawer');
      if (drawer) drawer.classList.add('hidden');
    });
  }

  // ---------------------------------------------------------------------------
  // Correlations — stateful UEBA-style incidents.
  // ---------------------------------------------------------------------------
  let _corrLast = [];

  // ── SOC Workflow (metrics + roster/schedule + FP tuning) ───────────────────
  let _socWired = false;
  async function loadSOCPage() {
    await _socLoadMetrics();
    await _socLoadEngineers();
    await _socLoadFp();
    if (_socWired) return;
    _socWired = true;
    const el = id => document.getElementById(id);
    el('socRefresh') && el('socRefresh').addEventListener('click', () => { _socLoadMetrics(); _socLoadEngineers(); _socLoadFp(); });
    el('socAddEng') && el('socAddEng').addEventListener('click', _socAddEngineer);
  }

  async function _socLoadMetrics() {
    const el = id => document.getElementById(id);
    const m = (await fetchJson(API.caseMetrics).catch(() => ({}))).data || {};
    const sev = m.open_by_severity || {};
    if (el('socMttr')) el('socMttr').textContent = (m.mttr_min != null ? m.mttr_min + 'm' : '—');
    if (el('socOpen')) el('socOpen').textContent = (m.open_total != null ? m.open_total : '—');
    if (el('socOpenSev')) el('socOpenSev').textContent = ['critical', 'high', 'medium', 'low'].map(s => `${s[0].toUpperCase()}:${sev[s] || 0}`).join('  ');
    if (el('socBreach')) el('socBreach').textContent = Math.round((m.sla_breach_rate || 0) * 100) + '%';
    if (el('socUnassigned')) el('socUnassigned').textContent = (m.open_by_assignee || {})['(unassigned)'] || 0;
  }

  async function _socLoadEngineers() {
    const body = document.getElementById('socEngBody');
    if (!body) return;
    const engs = (await fetchJson(API.socEngineers).catch(() => ({}))).data || [];
    const shifts = (await fetchJson(API.socShifts).catch(() => ({}))).data || [];
    const byEng = {};
    shifts.forEach(s => { (byEng[s.sam_account] = byEng[s.sam_account] || []).push(s); });
    const cnt = document.getElementById('socEngCount');
    if (cnt) cnt.textContent = engs.length + ' engineer' + (engs.length === 1 ? '' : 's');
    const wd = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const fmt = m => String(Math.floor(m / 60)).padStart(2, '0') + ':' + String(m % 60).padStart(2, '0');
    const cols = 'grid-template-columns:150px 1fr 80px 90px 90px 1fr 80px';
    body.innerHTML = engs.length ? engs.map(e => {
      const sh = (byEng[e.sam_account] || []).map(s => `${wd[s.weekday]} ${fmt(s.start_min)}-${fmt(s.end_min)}${s.on_call ? ' (on-call)' : ''}`).join(', ') || '<span style="color:var(--fg-4)">none</span>';
      const load = (e.open_load || 0) + '/' + e.max_load;
      return `<div class="tbl-r" style="${cols}">
        <span class="tbl-mono">${escapeHtml(e.sam_account)}</span>
        <span class="tbl-pri">${escapeHtml(e.display_name || '—')}</span>
        <span>T${e.tier}</span>
        <span class="tbl-mono">${load}</span>
        <span class="tbl-mono">${escapeHtml((e.skill_groups || []).join(', '))}</span>
        <span style="font-size:11px">${sh}</span>
        <span style="display:flex;gap:4px">
          <button type="button" class="act-btn soc-shift" data-sam="${escapeHtml(e.sam_account)}" style="height:22px;padding:0 6px;font-size:11px">+Shift</button>
          <button type="button" class="act-btn soc-del" data-sam="${escapeHtml(e.sam_account)}" style="height:22px;padding:0 6px;font-size:11px;color:var(--crit)">Del</button>
        </span>
      </div>`;
    }).join('') : '<div class="sigil-block"><div class="sigil-text"><h4>No SOC engineers</h4><p>Add engineers above to enable auto-assignment.</p></div></div>';
    body.querySelectorAll('.soc-del').forEach(b => b.addEventListener('click', async () => {
      if (!confirm(`Remove ${b.dataset.sam} from the SOC roster?`)) return;
      await fetch(`${API.socEngineers}/${encodeURIComponent(b.dataset.sam)}`, { method: 'DELETE', credentials: 'same-origin' });
      _socLoadEngineers();
    }));
    body.querySelectorAll('.soc-shift').forEach(b => b.addEventListener('click', () => _socAddShift(b.dataset.sam)));
  }

  async function _socAddEngineer() {
    const el = id => document.getElementById(id);
    const sam = (el('socNewSam').value || '').trim();
    if (!sam) { alert('sam_account is required'); return; }
    const body = {
      sam_account: sam,
      skill_groups: (el('socNewSkills').value || '').split(',').map(s => s.trim()).filter(Boolean),
      tier: parseInt(el('socNewTier').value, 10),
      max_load: parseInt(el('socNewMax').value, 10) || 25,
      active: true,
    };
    const r = await fetch(API.socEngineers, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify(body) });
    if (!r.ok) { alert('Add failed: ' + await r.text()); return; }
    el('socNewSam').value = ''; el('socNewSkills').value = '';
    _socLoadEngineers();
  }

  async function _socAddShift(sam) {
    const wd = prompt(`Add shift for ${sam}\nWeekday (0=Sun .. 6=Sat):`, '1'); if (wd === null) return;
    const sh = prompt('Start hour (UTC, 0-23):', '9'); if (sh === null) return;
    const eh = prompt('End hour (UTC, 1-24):', '17'); if (eh === null) return;
    const onCall = confirm('On-call shift?  (OK = yes, Cancel = no)');
    const body = { sam_account: sam, weekday: parseInt(wd, 10), start_min: parseInt(sh, 10) * 60, end_min: parseInt(eh, 10) * 60, on_call: onCall };
    const r = await fetch(API.socShifts, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify(body) });
    if (!r.ok) { alert('Add shift failed: ' + await r.text()); return; }
    _socLoadEngineers();
  }

  async function _socLoadFp() {
    const body = document.getElementById('socFpBody');
    if (!body) return;
    const stats = (await fetchJson(API.fpStats).catch(() => ({}))).data || [];
    body.innerHTML = stats.length ? stats.map(s => `<div class="tbl-r" style="grid-template-columns:120px 120px 1fr">
      <span class="tbl-mono">${s.rule_id}</span>
      <span class="tbl-mono">${s.fp_count}</span>
      <span style="color:var(--fg-4);font-size:11px">Disable or raise level/threshold for rule ${s.rule_id} in Rule Versions</span>
    </div>`).join('') : '<div class="sigil-block"><div class="sigil-text"><h4>No false positives yet</h4><p>Resolve a case as false-positive to populate noisy-rule stats.</p></div></div>';
  }

  function _corrSevColor(s) {
    return s === 'critical' ? 'var(--crit)'
         : s === 'high'     ? 'var(--high)'
         : s === 'medium'   ? 'var(--med)'
         : 'var(--fg-3)';
  }

  // Per-detector one-line summary for the incident row (XDR-aware).
  function _corrDetail(inc) {
    const ev = inc.evidence || {};
    switch (inc.detector) {
      case 'multi_location_logon': {
        const ips = ev.distinct_ips || [], hosts = ev.distinct_hosts || [], cc = ev.distinct_countries || [];
        return `${ips.length} IP / ${hosts.length} host${cc.length ? ` / ${cc.length} country` : ''}`;
      }
      case 'lateral_movement':
        return `→ ${ev.host_count || 0} hosts`;
      case 'data_exfiltration':
        return `${ev.endpoint_events || 0} endpoint / ${ev.cloud_events || 0} cloud egress`;
      case 'compromised_identity':
        return `signals across ${(inc.domains || []).length} domains`;
      default:
        return (inc.domains || []).join(', ') || 'correlation';
    }
  }

  async function _corrLoad() {
    const el = id => document.getElementById(id);
    const status = (el('corrStatus') || {}).value || 'open';
    const data = await fetchJson(`${API.corrIncidents}?status=${encodeURIComponent(status)}&size=200`).catch(() => ({ incidents: [], stats: {} }));
    const incs = data.incidents || [];
    _corrLast = incs;
    const stats = data.stats || {};
    if (el('corrOpen')) el('corrOpen').textContent = (stats.open_count || 0).toLocaleString();
    if (el('corrMLL'))  el('corrMLL').textContent  = ((stats.by_detector || {})['multi_location_logon'] || 0).toLocaleString();
    if (el('corrIncCount')) el('corrIncCount').textContent = incs.length + ' incident' + (incs.length === 1 ? '' : 's');
    if (el('navBadgeCorr')) {
      const n = stats.open_count || 0;
      const b = el('navBadgeCorr');
      if (n > 0) { b.textContent = n; b.style.display = ''; } else { b.style.display = 'none'; }
    }
    const body = el('corrBody');
    if (!body) return;
    const cols = 'grid-template-columns:160px 140px 1fr 90px 130px 120px 110px';
    body.innerHTML = incs.length ? incs.map((inc, i) => {
      const first = inc.first_seen_ms ? new Date(inc.first_seen_ms).toLocaleString() : '—';
      const ev = inc.evidence || {};
      const domains = (inc.domains || []);
      const caseTag = inc.case_id ? ` · <span style="color:var(--accent)">case #${inc.case_id}</span>` : '';
      const summary = `<b>${escapeHtml(inc.entity)}</b> · ${escapeHtml(_corrDetail(inc))}${caseTag}`;
      const sevCol = _corrSevColor(inc.severity);
      const domainBadges = domains.length
        ? domains.map(d => `<span style="padding:1px 6px;border-radius:8px;background:rgba(88,166,255,.15);color:var(--accent);font-size:9px;margin-right:3px">${escapeHtml(d)}</span>`).join('')
        : '<span style="color:var(--fg-4)">—</span>';
      const statusBadge = inc.status === 'resolved'
        ? '<span style="padding:2px 8px;border-radius:10px;background:rgba(51,204,153,.15);color:var(--ok);font-size:10px;font-weight:600">RESOLVED</span>'
        : '<span style="padding:2px 8px;border-radius:10px;background:rgba(255,51,51,.15);color:var(--crit);font-size:10px;font-weight:600">OPEN</span>';
      return `<div class="tbl-r" style="${cols}">
        <span class="tbl-time">${first}</span>
        <span class="tbl-mono">${escapeHtml(inc.detector)}</span>
        <span class="tbl-pri">${summary}</span>
        <span style="font-family:var(--font-mono);font-weight:600;color:${sevCol}">${escapeHtml(inc.severity)}</span>
        <span>${domainBadges}</span>
        <span>${statusBadge}</span>
        <span style="display:flex;gap:4px">
          <button type="button" class="act-btn corr-view" data-id="${inc.id}" style="height:22px;padding:0 8px;font-size:11px">View</button>
          ${inc.status === 'open' ? `<button type="button" class="act-btn corr-respond" data-id="${inc.id}" style="height:22px;padding:0 8px;font-size:11px;color:var(--high)">Respond</button>` : ''}
          ${inc.status === 'open' ? `<button type="button" class="act-btn corr-resolve" data-id="${inc.id}" style="height:22px;padding:0 8px;font-size:11px">Resolve</button>` : ''}
        </span>
      </div>`;
    }).join('') : `<div class="sigil-block"><div class="sigil-text"><h4>No ${escapeHtml(status)} correlations</h4><p>The engine runs every 2 minutes. Click <strong>▶ Run all now</strong> to force a check.</p></div></div>`;

    body.querySelectorAll('.corr-view').forEach(b => b.addEventListener('click', async () => {
      const id = b.getAttribute('data-id');
      const drawer = el('corrDetailDrawer');
      const dbody = el('corrDetailBody');
      if (!drawer || !dbody) return;
      dbody.textContent = 'Loading…';
      drawer.classList.remove('hidden');
      // Detail endpoint enriches with recommended cross-domain response actions.
      const detail = await fetchJson(`${API.corrIncidents}/${id}`).catch(() => null);
      const inc = (detail && detail.incident) || _corrLast.find(x => String(x.id) === String(id)) || {};
      dbody.textContent = JSON.stringify(inc, null, 2);
    }));

    body.querySelectorAll('.corr-respond').forEach(b => b.addEventListener('click', async () => {
      const id = b.getAttribute('data-id');
      if (!confirm(`Execute the recommended cross-domain containment for incident #${id}?\n\nThis may isolate hosts / disable accounts / block IPs via active response.`)) return;
      b.disabled = true; const o = b.textContent; b.textContent = '…';
      try {
        const res = await fetch(`${API.corrIncidents}/${id}/respond`, { method: 'POST', credentials: 'same-origin' });
        const j = await res.json().catch(() => ({}));
        if (!res.ok) { alert('Respond failed: ' + (j.error || res.status)); }
        else {
          const ok = (j.results || []).filter(r => r.ok).length;
          alert(`Response executed: ${ok}/${(j.results || []).length} action(s) succeeded.`);
        }
      } finally { b.disabled = false; b.textContent = o; await _corrLoad(); }
    }));
    body.querySelectorAll('.corr-resolve').forEach(b => b.addEventListener('click', async () => {
      const id = b.getAttribute('data-id');
      const res = await fetch(`${API.corrIncidents}/${id}/resolve`, { method: 'POST', credentials: 'same-origin' });
      if (res.ok) _corrLoad();
    }));
  }

  let _corrWired = false;
  async function loadCorrelationsPage() {
    await _corrLoad();
    if (_corrWired) return;
    _corrWired = true;
    const el = id => document.getElementById(id);
    el('corrStatus')      && el('corrStatus').addEventListener('change', _corrLoad);
    el('corrDetailClose') && el('corrDetailClose').addEventListener('click', () => {
      const d = el('corrDetailDrawer'); if (d) d.classList.add('hidden');
    });
    el('corrRunNow') && el('corrRunNow').addEventListener('click', async () => {
      const btn = el('corrRunNow'); btn.disabled = true; const o = btn.textContent; btn.textContent = 'Running…';
      try {
        await fetch(API.corrRunNow, { method: 'POST', credentials: 'same-origin' });
        await _corrLoad();
      } finally { btn.disabled = false; btn.textContent = o; }
    });
  }

  // ---------------------------------------------------------------------------
  // Users & Roles (super_admin only) — dashboard account management.
  // ---------------------------------------------------------------------------
  async function _usrLoad() {
    const el = id => document.getElementById(id);
    const data = await fetchJson(API.users).catch(() => ({ users: [], total: 0 }));
    const users = data.users || [];
    const me = data.current_user || '';
    if (el('usrCount')) el('usrCount').textContent = users.length + ' account' + (users.length === 1 ? '' : 's');
    const body = el('usrBody');
    if (!body) return;
    const cols = 'grid-template-columns:160px 140px 1fr 160px 90px 140px 160px';
    body.innerHTML = users.length ? users.map(u => {
      const last = u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'never';
      const status = u.enabled
        ? '<span style="padding:2px 8px;border-radius:10px;background:rgba(51,204,153,.15);color:var(--ok);font-size:10px;font-weight:600">ENABLED</span>'
        : '<span style="padding:2px 8px;border-radius:10px;background:rgba(140,140,140,.15);color:var(--fg-3);font-size:10px;font-weight:600">DISABLED</span>';
      const isMe = u.username === me;
      return `<div class="tbl-r" style="${cols}">
        <span class="tbl-mono">${escapeHtml(u.username)}${isMe ? ' <span style="color:var(--accent);font-size:10px">(you)</span>' : ''}</span>
        <span class="tbl-mono">${escapeHtml(u.role)}</span>
        <span class="tbl-pri">${escapeHtml(u.full_name || '—')}<span style="color:var(--fg-4);font-size:11px;margin-left:6px">${escapeHtml(u.email || '')}</span></span>
        <span class="tbl-time">${escapeHtml(last)}</span>
        <span>${status}</span>
        <span class="tbl-mono" style="font-size:11px;color:var(--fg-3)">${escapeHtml(u.created_by || '—')}</span>
        <span style="display:flex;gap:4px">
          <button type="button" class="act-btn usr-edit" data-username="${escapeHtml(u.username)}" style="height:22px;padding:0 8px;font-size:11px">Edit</button>
          <button type="button" class="act-btn usr-delete" data-username="${escapeHtml(u.username)}" ${isMe ? 'disabled' : ''} style="height:22px;padding:0 8px;font-size:11px;color:var(--crit)" title="${isMe ? 'Cannot delete your own account' : ''}">Del</button>
        </span>
      </div>`;
    }).join('') : `<div class="sigil-block"><div class="sigil-text"><h4>No users yet</h4><p>Click <strong>+ New user</strong> to add a dashboard account. Env-var accounts (<code>DASHBOARD_USERS</code>) still work as a fallback.</p></div></div>`;

    body.querySelectorAll('.usr-edit').forEach(b => b.addEventListener('click', () => {
      const u = users.find(x => x.username === b.getAttribute('data-username'));
      if (u) _usrOpenDrawer(u);
    }));
    body.querySelectorAll('.usr-delete').forEach(b => b.addEventListener('click', async () => {
      const username = b.getAttribute('data-username');
      if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
      const res = await fetch(`${API.users}/${encodeURIComponent(username)}`, { method: 'DELETE', credentials: 'same-origin' });
      if (!res.ok) { alert('Delete failed: ' + await res.text()); return; }
      _usrLoad();
    }));
  }

  function _usrOpenDrawer(u) {
    const el = id => document.getElementById(id);
    el('usrDrawer').classList.remove('hidden');
    el('usrDrawerTitle').textContent = u ? `Edit user · ${u.username}` : 'New user';
    el('usrEditMode').value = u ? 'edit' : 'create';
    el('usrUsername').value = u ? u.username : '';
    el('usrUsername').disabled = !!u;
    el('usrFullName').value = u ? u.full_name : '';
    el('usrEmail').value = u ? u.email : '';
    el('usrRole').value = u ? u.role : 'viewer';
    el('usrPassword').value = '';
    el('usrPwLabel').textContent = u ? 'Password (leave blank to keep current)' : 'Password (≥ 8 chars)';
    el('usrPwHint').style.display = u ? '' : 'none';
    el('usrEnabled').checked = u ? !!u.enabled : true;
  }

  function _usrCloseDrawer() {
    const d = document.getElementById('usrDrawer');
    if (d) d.classList.add('hidden');
  }

  async function _usrSave() {
    const el = id => document.getElementById(id);
    const mode = el('usrEditMode').value;
    const username = el('usrUsername').value.trim();
    const body = {
      full_name: el('usrFullName').value.trim(),
      email: el('usrEmail').value.trim(),
      role: el('usrRole').value,
      enabled: el('usrEnabled').checked,
    };
    const pw = el('usrPassword').value;
    if (mode === 'create') {
      if (!username) { alert('Username is required.'); return; }
      if (!pw || pw.length < 10) { alert('Password must be at least 10 characters.'); return; }
      body.username = username;
      body.password = pw;
      const res = await fetch(API.users, {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) { alert('Create failed: ' + await res.text()); return; }
    } else {
      if (pw) body.password = pw;
      const res = await fetch(`${API.users}/${encodeURIComponent(username)}`, {
        method: 'PUT', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) { alert('Update failed: ' + await res.text()); return; }
    }
    _usrCloseDrawer();
    _usrLoad();
  }

  let _usrWired = false;
  async function loadUsersPage() {
    await _usrLoad();
    if (_usrWired) return;
    _usrWired = true;
    const el = id => document.getElementById(id);
    el('usrAdd')         && el('usrAdd').addEventListener('click', () => _usrOpenDrawer(null));
    el('usrDrawerClose') && el('usrDrawerClose').addEventListener('click', _usrCloseDrawer);
    el('usrCancel')      && el('usrCancel').addEventListener('click', _usrCloseDrawer);
    el('usrSave')        && el('usrSave').addEventListener('click', _usrSave);
  }

  // ---------------------------------------------------------------------------
  // Silent Sources monitor — incidents + threshold management.
  // ---------------------------------------------------------------------------
  function _ssFmtGap(min) {
    if (min == null) return '—';
    if (min < 60) return min + 'm';
    if (min < 1440) return Math.floor(min / 60) + 'h ' + (min % 60) + 'm';
    return Math.floor(min / 1440) + 'd ' + Math.floor((min % 1440) / 60) + 'h';
  }
  function _ssSevColor(s) {
    return s === 'critical' ? 'var(--crit)'
         : s === 'high'     ? 'var(--high)'
         : s === 'medium'   ? 'var(--med)'
         : 'var(--fg-3)';
  }

  async function _ssLoadIncidents() {
    const status = (document.getElementById('ssIncStatus') || {}).value || 'open';
    const data = await fetchJson(`${API.silentSources}?status=${encodeURIComponent(status)}&size=100`).catch(() => ({ incidents: [], stats: {} }));
    const incs = data.incidents || [];
    const stats = data.stats || {};
    const el = id => document.getElementById(id);

    if (el('ssOpenCount')) el('ssOpenCount').textContent = (stats.open_count || 0).toLocaleString();
    if (el('navBadgeSilent')) {
      const n = stats.open_count || 0;
      const badge = el('navBadgeSilent');
      if (n > 0) { badge.textContent = n; badge.style.display = ''; } else { badge.style.display = 'none'; }
    }
    if (el('ssOpenSev')) {
      const bs = stats.by_severity || {};
      el('ssOpenSev').textContent = ((bs.high || 0) + (bs.critical || 0)).toLocaleString();
    }
    if (el('ssIncCount')) el('ssIncCount').textContent = incs.length + ' incident' + (incs.length === 1 ? '' : 's');

    const body = el('ssIncidentsBody');
    if (!body) return;
    const cols = 'grid-template-columns:1fr 110px 110px 110px 110px 90px';
    body.innerHTML = incs.length ? incs.map(i => {
      const lastSeen = i.last_seen_ms ? new Date(i.last_seen_ms).toLocaleString() : '—';
      const sevCol = _ssSevColor(i.severity);
      const statusBadge = i.status === 'resolved'
        ? '<span style="padding:2px 8px;border-radius:10px;background:rgba(51,204,153,.15);color:var(--ok);font-size:10px;font-weight:600">RESOLVED</span>'
        : '<span style="padding:2px 8px;border-radius:10px;background:rgba(255,51,51,.15);color:var(--crit);font-size:10px;font-weight:600">OPEN</span>';
      return `<div class="tbl-r" style="${cols}">
        <span class="tbl-pri">${escapeHtml(i.source)}</span>
        <span class="tbl-mono">${escapeHtml(i.kind || '—')}</span>
        <span style="font-family:var(--font-mono);font-weight:600;color:${sevCol}">${escapeHtml(i.severity)}</span>
        <span class="tbl-time">${lastSeen}</span>
        <span class="tbl-mono">${_ssFmtGap(i.gap_minutes)} (≥${i.threshold_min}m)</span>
        <span>${statusBadge}</span>
      </div>`;
    }).join('') : `<div class="sigil-block"><div class="sigil-text"><h4>No ${escapeHtml(status)} incidents</h4><p>Sources sending events within their threshold.</p></div></div>`;
  }

  async function _ssLoadThresholds() {
    const data = await fetchJson(API.silentThresh).catch(() => ({ thresholds: [] }));
    const ts = data.thresholds || [];
    const enabledN = ts.filter(t => t.enabled).length;
    const el = id => document.getElementById(id);
    if (el('ssThresholdCount')) el('ssThresholdCount').textContent = enabledN.toLocaleString();
    const body = el('ssThresholdsBody');
    if (!body) return;
    const cols = 'grid-template-columns:50px 1fr 100px 90px 100px 60px 1fr 130px';
    body.innerHTML = ts.length ? ts.map(t => {
      const onBadge = t.enabled
        ? '<span style="padding:2px 6px;border-radius:8px;background:rgba(51,204,153,.15);color:var(--ok);font-size:10px;font-weight:600">ON</span>'
        : '<span style="padding:2px 6px;border-radius:8px;background:rgba(140,140,140,.15);color:var(--fg-3);font-size:10px;font-weight:600">OFF</span>';
      return `<div class="tbl-r" style="${cols}">
        <span>${onBadge}</span>
        <span class="tbl-mono">${escapeHtml(t.source_pattern)}</span>
        <span class="tbl-mono">${escapeHtml(t.kind)}</span>
        <span class="tbl-mono">${t.minutes}m</span>
        <span style="font-family:var(--font-mono);font-weight:600;color:${_ssSevColor(t.severity)}">${escapeHtml(t.severity)}</span>
        <span class="tbl-mono">${t.notify ? '✓' : '—'}</span>
        <span style="color:var(--fg-3);font-size:11px" title="${escapeHtml(t.reason || '')}">${escapeHtml(t.reason || '—')}</span>
        <span style="display:flex;gap:4px">
          <button type="button" class="act-btn ss-edit" data-id="${t.id}" style="height:22px;padding:0 8px;font-size:11px">Edit</button>
          <button type="button" class="act-btn ss-delete" data-id="${t.id}" style="height:22px;padding:0 8px;font-size:11px;color:var(--crit)">Del</button>
        </span>
      </div>`;
    }).join('') : `<div class="sigil-block"><div class="sigil-text"><h4>No thresholds defined</h4><p>Click <strong>+ New threshold</strong> to set per-source silence limits. Sources without a match fall back to the default of 15 minutes.</p></div></div>`;

    body.querySelectorAll('.ss-edit').forEach(b => b.addEventListener('click', () => {
      const id = b.getAttribute('data-id');
      const t = ts.find(x => String(x.id) === id);
      if (t) _ssOpenDrawer(t);
    }));
    body.querySelectorAll('.ss-delete').forEach(b => b.addEventListener('click', async () => {
      if (!confirm('Delete this threshold?')) return;
      await fetch(`${API.silentThresh}/${b.getAttribute('data-id')}`, { method: 'DELETE', credentials: 'same-origin' });
      _ssLoadThresholds(); _ssLoadIncidents();
    }));
  }

  function _ssOpenDrawer(t) {
    const el = id => document.getElementById(id);
    el('ssDrawer').classList.remove('hidden');
    el('ssDrawerTitle').textContent = t ? 'Edit threshold' : 'New threshold';
    el('ssEditId').value = t ? t.id : '';
    el('ssPattern').value = t ? t.source_pattern : '';
    el('ssKind').value = t ? t.kind : 'agent';
    el('ssMinutes').value = t ? t.minutes : 15;
    el('ssSeverity').value = t ? t.severity : 'medium';
    el('ssReason').value = t ? t.reason || '' : '';
    el('ssEnabled').checked = t ? !!t.enabled : true;
    el('ssNotify').checked = t ? !!t.notify : true;
  }

  function _ssCloseDrawer() {
    const d = document.getElementById('ssDrawer');
    if (d) d.classList.add('hidden');
  }

  async function _ssSave() {
    const el = id => document.getElementById(id);
    const id = el('ssEditId').value;
    const body = {
      source_pattern: el('ssPattern').value.trim(),
      kind: el('ssKind').value,
      minutes: parseInt(el('ssMinutes').value, 10) || 15,
      severity: el('ssSeverity').value,
      reason: el('ssReason').value.trim(),
      enabled: el('ssEnabled').checked,
      notify: el('ssNotify').checked,
    };
    if (!body.source_pattern) { alert('Source pattern is required.'); return; }
    const method = id ? 'PUT' : 'POST';
    const url = id ? `${API.silentThresh}/${id}` : API.silentThresh;
    const res = await fetch(url, {
      method, credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      alert('Save failed: ' + await res.text());
      return;
    }
    _ssCloseDrawer();
    _ssLoadThresholds();
    _ssLoadIncidents();
  }

  let _ssWired = false;
  async function loadSilentSourcesPage() {
    await Promise.all([_ssLoadIncidents(), _ssLoadThresholds()]);
    if (_ssWired) return;
    _ssWired = true;
    const el = id => document.getElementById(id);
    el('ssAddThreshold') && el('ssAddThreshold').addEventListener('click', () => _ssOpenDrawer(null));
    el('ssDrawerClose')  && el('ssDrawerClose').addEventListener('click', _ssCloseDrawer);
    el('ssCancel')       && el('ssCancel').addEventListener('click', _ssCloseDrawer);
    el('ssSave')         && el('ssSave').addEventListener('click', _ssSave);
    el('ssIncStatus')    && el('ssIncStatus').addEventListener('change', _ssLoadIncidents);
    el('ssRunNow')       && el('ssRunNow').addEventListener('click', async () => {
      const btn = el('ssRunNow');
      btn.disabled = true; const o = btn.textContent; btn.textContent = 'Checking…';
      try {
        await fetch(API.silentRunNow, { method: 'POST', credentials: 'same-origin' });
        await Promise.all([_ssLoadIncidents(), _ssLoadThresholds()]);
      } finally { btn.disabled = false; btn.textContent = o; }
    });
  }

  // ---------------------------------------------------------------------------
  // Log Filters / Whitelist — operator-defined suppression rules applied at
  // query time to drop known-good noise from Logs + alert views.
  // ---------------------------------------------------------------------------
  async function _lfFetchRules() {
    const data = await fetchJson(API.logFilters).catch(() => ({ rules: [] }));
    return data.rules || [];
  }

  function _lfRowHtml(r) {
    const cols = 'grid-template-columns:60px 1fr 140px 90px 140px 1fr 120px 160px';
    const enabledBadge = r.enabled
      ? '<span style="display:inline-block;padding:2px 8px;border-radius:10px;background:rgba(51,204,153,.15);color:var(--ok);font-size:10px;font-weight:600">ON</span>'
      : '<span style="display:inline-block;padding:2px 8px;border-radius:10px;background:rgba(140,140,140,.15);color:var(--fg-3);font-size:10px;font-weight:600">OFF</span>';
    return `<div class="tbl-r" style="${cols}">
      <span>${enabledBadge}</span>
      <span class="tbl-pri" title="${escapeHtml(r.name)}">${escapeHtml(r.name)}</span>
      <span class="tbl-mono" title="${escapeHtml(r.match_field)}">${escapeHtml(r.match_field)}</span>
      <span class="tbl-mono">${escapeHtml(r.match_op)}</span>
      <span class="tbl-mono" title="${escapeHtml(r.match_value)}">${escapeHtml(r.match_value)}</span>
      <span style="color:var(--fg-3);font-size:11px" title="${escapeHtml(r.reason || '')}">${escapeHtml(r.reason || '—')}</span>
      <span class="tbl-mono">${escapeHtml(r.scope)}</span>
      <span style="display:flex;gap:4px">
        <button type="button" class="act-btn lf-toggle"  data-id="${r.id}" style="height:22px;padding:0 8px;font-size:11px">${r.enabled ? 'Disable' : 'Enable'}</button>
        <button type="button" class="act-btn lf-edit"    data-id="${r.id}" style="height:22px;padding:0 8px;font-size:11px">Edit</button>
        <button type="button" class="act-btn lf-delete"  data-id="${r.id}" style="height:22px;padding:0 8px;font-size:11px;color:var(--crit)">Del</button>
      </span>
    </div>`;
  }

  async function _lfRender() {
    const rules = await _lfFetchRules();
    const el = id => document.getElementById(id);
    if (el('lfCount')) el('lfCount').textContent = rules.length + ' rule' + (rules.length === 1 ? '' : 's');
    const body = el('lfBody');
    if (!body) return;
    body.innerHTML = rules.length
      ? rules.map(_lfRowHtml).join('')
      : `<div class="sigil-block"><div class="sigil-text"><h4>No filters yet</h4><p>Click <strong>+ New filter</strong> to suppress noisy known-good events.</p></div></div>`;
    body.querySelectorAll('.lf-toggle').forEach(b => b.addEventListener('click', () => _lfToggle(b.getAttribute('data-id'))));
    body.querySelectorAll('.lf-edit').forEach(b => b.addEventListener('click', () => _lfEdit(rules.find(r => String(r.id) === b.getAttribute('data-id')))));
    body.querySelectorAll('.lf-delete').forEach(b => b.addEventListener('click', () => _lfDelete(b.getAttribute('data-id'))));
  }

  function _lfOpenDrawer(rule) {
    const el = id => document.getElementById(id);
    el('lfDrawer').classList.remove('hidden');
    el('lfDrawerTitle').textContent = rule ? 'Edit filter' : 'New filter';
    el('lfEditId').value = rule ? rule.id : '';
    el('lfName').value = rule ? rule.name : '';
    el('lfScope').value = rule ? rule.scope : 'both';
    el('lfField').value = rule ? rule.match_field : '';
    el('lfOp').value = rule ? rule.match_op : 'equals';
    el('lfValue').value = rule ? rule.match_value : '';
    el('lfReason').value = rule ? rule.reason || '' : '';
    el('lfEnabled').checked = rule ? !!rule.enabled : true;
  }

  function _lfCloseDrawer() {
    const d = document.getElementById('lfDrawer');
    if (d) d.classList.add('hidden');
  }

  function _lfEdit(rule) { if (rule) _lfOpenDrawer(rule); }

  async function _lfSave() {
    const el = id => document.getElementById(id);
    const id = el('lfEditId').value;
    const body = {
      name: el('lfName').value.trim(),
      scope: el('lfScope').value,
      match_field: el('lfField').value.trim(),
      match_op: el('lfOp').value,
      match_value: el('lfValue').value.trim(),
      reason: el('lfReason').value.trim(),
      enabled: el('lfEnabled').checked,
    };
    if (!body.name || !body.match_field || !body.match_value) {
      alert('Name, field, and value are required.');
      return;
    }
    const method = id ? 'PUT' : 'POST';
    const url = id ? `${API.logFilters}/${id}` : API.logFilters;
    const res = await fetch(url, {
      method, credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const t = await res.text();
      alert('Save failed: ' + t);
      return;
    }
    _lfCloseDrawer();
    _lfRender();
  }

  async function _lfToggle(id) {
    await fetch(`${API.logFilters}/${id}/toggle`, { method: 'POST', credentials: 'same-origin' });
    _lfRender();
  }

  async function _lfDelete(id) {
    if (!confirm('Delete this filter?')) return;
    await fetch(`${API.logFilters}/${id}`, { method: 'DELETE', credentials: 'same-origin' });
    _lfRender();
  }

  let _lfWired = false;
  async function loadLogFiltersPage() {
    await _lfRender();
    if (_lfWired) return;
    _lfWired = true;
    const el = id => document.getElementById(id);
    el('lfAddBtn')      && el('lfAddBtn').addEventListener('click', () => _lfOpenDrawer(null));
    el('lfDrawerClose') && el('lfDrawerClose').addEventListener('click', _lfCloseDrawer);
    el('lfCancel')      && el('lfCancel').addEventListener('click', _lfCloseDrawer);
    el('lfSave')        && el('lfSave').addEventListener('click', _lfSave);
  }

  // ---------------------------------------------------------------------------
  // Retention — index lifecycle visibility + force purge (super_admin only).
  // ---------------------------------------------------------------------------
  function _retFmtBytes(n) {
    if (n == null || isNaN(n)) return '—';
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0, v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2) + ' ' + u[i];
  }

  async function _retLoad() {
    const el = id => document.getElementById(id);
    const data = await fetchJson(API.retention).catch(() => null);
    if (!data) {
      if (el('retIndicesBody')) el('retIndicesBody').innerHTML = '<div class="sigil-block"><div class="sigil-text"><h4>Failed to load</h4></div></div>';
      return;
    }
    if (el('retTotalIndices')) el('retTotalIndices').textContent = (data.total_indices || 0).toLocaleString();
    if (el('retTotalSize'))    el('retTotalSize').textContent    = _retFmtBytes(data.total_size_bytes || 0);
    if (el('retTotalDocs'))    el('retTotalDocs').textContent    = (data.total_docs || 0).toLocaleString();
    if (el('retConfigured'))   el('retConfigured').textContent   = data.configured_retention_days != null ? (data.configured_retention_days + 'd') : '—';

    const fams = data.families || [];
    const famBody = el('retFamiliesBody');
    if (famBody) {
      const famCols = 'grid-template-columns:160px 100px 140px 140px 130px 130px';
      famBody.innerHTML = fams.length ? fams.map(f => `<div class="tbl-r" style="${famCols}">
        <span class="tbl-mono">${escapeHtml(f.family)}</span>
        <span class="tbl-mono">${f.indices.toLocaleString()}</span>
        <span class="tbl-mono">${_retFmtBytes(f.size_bytes)}</span>
        <span class="tbl-mono">${f.docs.toLocaleString()}</span>
        <span class="tbl-mono">${f.youngest_days != null ? f.youngest_days + 'd ago' : '—'}</span>
        <span class="tbl-mono">${f.oldest_days != null ? f.oldest_days + 'd ago' : '—'}</span>
      </div>`).join('') : '<div class="sigil-block"><div class="sigil-text"><h4>No indices yet</h4></div></div>';
    }

    const items = data.indices || [];
    const filter = ((el('retFilter') && el('retFilter').value) || '').toLowerCase();
    const filtered = filter ? items.filter(i => i.name.toLowerCase().includes(filter)) : items;
    if (el('retIndicesCount')) el('retIndicesCount').textContent = filtered.length + (filter ? ' / ' + items.length : '') + ' indices';
    const body = el('retIndicesBody');
    if (body) {
      const cols = 'grid-template-columns:1fr 120px 100px 110px 110px 80px';
      const healthColor = h => h === 'red' ? 'var(--crit)' : h === 'yellow' ? 'var(--high)' : 'var(--ok)';
      body.innerHTML = filtered.length ? filtered.map(i => `<div class="tbl-r" style="${cols}">
        <span class="tbl-mono">${escapeHtml(i.name)}</span>
        <span class="tbl-mono">${escapeHtml(i.family)}</span>
        <span class="tbl-mono">${i.age_days != null ? i.age_days : '—'}</span>
        <span class="tbl-mono">${_retFmtBytes(i.size_bytes)}</span>
        <span class="tbl-mono">${i.docs.toLocaleString()}</span>
        <span style="font-family:var(--font-mono);color:${healthColor(i.health)}">${escapeHtml(i.health || '—')}</span>
      </div>`).join('') : '<div class="sigil-block"><div class="sigil-text"><h4>No indices match</h4></div></div>';
    }
  }

  async function _retPurge(dryRun) {
    const el = id => document.getElementById(id);
    const days = parseInt((el('retPurgeDays') && el('retPurgeDays').value) || '0', 10);
    if (!days || days < 1) { alert('Enter a number of days ≥ 1.'); return; }
    const famRaw = ((el('retPurgeFamilies') && el('retPurgeFamilies').value) || '').trim();
    const families = famRaw ? famRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
    if (!dryRun) {
      const confirmMsg = `Delete indices older than ${days} days` +
        (families.length ? ` in families: ${families.join(', ')}` : ' (all families)') +
        '?\n\nThis cannot be undone.';
      if (!confirm(confirmMsg)) return;
    }
    const res = await fetch(API.retentionPurge, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ older_than_days: days, families, dry_run: dryRun }),
    });
    const j = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (el('retPurgeResult')) el('retPurgeResult').textContent = 'Error: ' + (j.error || res.status);
      return;
    }
    const list = dryRun ? (j.would_delete || []) : (j.deleted || []);
    const msg = dryRun
      ? `Dry run: ${j.matched} indices would be deleted` + (list.length ? ' — ' + list.slice(0, 5).map(x => x.name).join(', ') + (list.length > 5 ? '…' : '') : '')
      : `Deleted ${(j.deleted || []).length} indices` + ((j.failed || []).length ? ` (${j.failed.length} failed)` : '');
    if (el('retPurgeResult')) el('retPurgeResult').textContent = msg;
    if (!dryRun) _retLoad();
  }

  let _retWired = false;
  async function loadRetentionPage() {
    await _retLoad();
    if (_retWired) return;
    _retWired = true;
    const el = id => document.getElementById(id);
    el('retRefresh')     && el('retRefresh').addEventListener('click', _retLoad);
    el('retFilter')      && el('retFilter').addEventListener('input', _retLoad);
    el('retPurgeDryRun') && el('retPurgeDryRun').addEventListener('click', () => _retPurge(true));
    el('retPurgeRun')    && el('retPurgeRun').addEventListener('click', () => _retPurge(false));
  }

  // ---------------------------------------------------------------------------
  // System Logs viewer (super_admin only) — pulls docker/file output for the
  // SIEM's own services so operators don't need to SSH.
  // ---------------------------------------------------------------------------
  let _sysLogsService = 'watchtower';
  let _sysLogsTimer = null;

  function _sysLogsRenderTabs(services) {
    const wrap = document.getElementById('sysLogsTabs');
    if (!wrap) return;
    wrap.innerHTML = services.map(s => {
      const active = s.name === _sysLogsService;
      return `<button type="button" class="act-btn sys-tab" data-name="${escapeHtml(s.name)}" style="height:28px;padding:0 12px;font-size:12px;${active ? 'background:var(--accent);color:#fff' : ''}">${escapeHtml(s.name)}</button>`;
    }).join('');
    wrap.querySelectorAll('.sys-tab').forEach(b => b.addEventListener('click', () => {
      _sysLogsService = b.getAttribute('data-name');
      _sysLogsRenderTabs(services);
      _sysLogsLoad();
    }));
  }

  async function _sysLogsLoad() {
    const el = id => document.getElementById(id);
    const lines = parseInt((el('sysLogsLines') || {}).value || '200', 10);
    const data = await fetchJson(`${API.sysLogsRead}?service=${encodeURIComponent(_sysLogsService)}&lines=${lines}`).catch(() => null);
    if (!data) {
      if (el('sysLogsBody')) el('sysLogsBody').textContent = '(failed to load)';
      return;
    }
    const allLines = data.lines || [];
    const grep = ((el('sysLogsGrep') || {}).value || '').toLowerCase();
    const filtered = grep ? allLines.filter(l => l.toLowerCase().includes(grep)) : allLines;
    if (el('sysLogsSource')) el('sysLogsSource').textContent = data.source || '—';
    if (el('sysLogsHits')) el('sysLogsHits').textContent = `${filtered.length}${grep ? ' / ' + allLines.length : ''} lines`;
    if (el('sysLogsStatusDot')) {
      el('sysLogsStatusDot').style.background = data.error ? 'var(--crit)' : 'var(--ok)';
    }
    const body = el('sysLogsBody');
    if (body) {
      if (data.error) {
        body.textContent = `⚠ ${data.error}\n\n${data.hint || ''}`;
        body.style.color = 'var(--high)';
      } else {
        body.textContent = filtered.join('\n');
        body.style.color = 'var(--fg-2)';
        body.scrollTop = body.scrollHeight; // auto-scroll to tail
      }
    }
  }

  let _sysLogsWired = false;
  async function loadSystemLogsPage() {
    const svcs = await fetchJson(API.sysLogsList).catch(() => ({ services: [] }));
    _sysLogsRenderTabs(svcs.services || []);
    await _sysLogsLoad();
    if (_sysLogsWired) return;
    _sysLogsWired = true;
    const el = id => document.getElementById(id);
    el('sysLogsRefresh')      && el('sysLogsRefresh').addEventListener('click', _sysLogsLoad);
    el('sysLogsLines')        && el('sysLogsLines').addEventListener('change', _sysLogsLoad);
    el('sysLogsGrep')         && el('sysLogsGrep').addEventListener('input', _sysLogsLoad);
    el('sysLogsAutoRefresh')  && el('sysLogsAutoRefresh').addEventListener('change', e => {
      if (_sysLogsTimer) { clearInterval(_sysLogsTimer); _sysLogsTimer = null; }
      if (e.target.checked) _sysLogsTimer = setInterval(_sysLogsLoad, 5000);
    });
  }

  // ---------------------------------------------------------------------------
  // Configuration Audit Log (super_admin only) — who changed what, when.
  // ---------------------------------------------------------------------------
  let _cfgAuditOffset = 0;
  let _cfgAuditLast = [];

  function _cfgAuditParams() {
    const el = id => document.getElementById(id);
    const size = 50;
    const bounds = getTimeRangeBounds((el('cfgAuditTimeRange') && el('cfgAuditTimeRange').value) || '24h');
    const p = new URLSearchParams();
    p.set('size', size);
    p.set('offset', _cfgAuditOffset);
    if (bounds.from) p.set('time_from', bounds.from);
    if (bounds.to) p.set('time_to', bounds.to);
    const user = ((el('cfgAuditUser') && el('cfgAuditUser').value) || '').trim();
    if (user) p.set('user', user);
    const target = ((el('cfgAuditTarget') && el('cfgAuditTarget').value) || '').trim();
    if (target) p.set('target_prefix', target);
    const action = (el('cfgAuditAction') && el('cfgAuditAction').value) || '';
    if (action) p.set('action', action);
    if (el('cfgAuditOnlyFailures') && el('cfgAuditOnlyFailures').checked) p.set('only_failures', '1');
    return { params: p, size };
  }

  async function _cfgAuditReload() {
    const el = id => document.getElementById(id);
    const { params, size } = _cfgAuditParams();
    const data = await fetchJson(API.cfgAuditLog + '?' + params.toString()).catch(() => ({ hits: [], total: 0 }));
    const hits = data.hits || [];
    _cfgAuditLast = hits;
    const total = data.total || 0;
    if (el('cfgAuditHits')) el('cfgAuditHits').textContent = total.toLocaleString() + ' entries';
    if (el('cfgAuditInfo')) el('cfgAuditInfo').textContent = `Showing ${hits.length} of ${total.toLocaleString()}`;
    if (el('cfgAuditPageInfo')) el('cfgAuditPageInfo').textContent = `Page ${Math.floor(_cfgAuditOffset / size) + 1}`;
    if (el('cfgAuditPrev')) el('cfgAuditPrev').disabled = _cfgAuditOffset === 0;
    if (el('cfgAuditNext')) el('cfgAuditNext').disabled = (_cfgAuditOffset + size) >= total;

    const tbody = el('cfgAuditBody');
    if (!tbody) return;
    const cols = 'grid-template-columns:160px 110px 110px 70px 1fr 80px 60px 70px';
    tbody.innerHTML = hits.length ? hits.map((r, i) => {
      const ts = r.ts_ms ? new Date(r.ts_ms).toLocaleString() : '—';
      const user = escapeHtml(r.user || '—');
      const role = escapeHtml(r.role || '—');
      const method = escapeHtml(r.method || '');
      const targetLabel = escapeHtml(r.target || r.path || '—');
      const action = escapeHtml(r.action || '');
      const status = parseInt(r.status, 10) || 0;
      const statusColor = status >= 500 ? 'var(--crit)' : status >= 400 ? 'var(--high)' : status >= 200 ? 'var(--ok)' : 'var(--fg-3)';
      return `<div class="tbl-r" style="${cols}">
        <span class="tbl-time">${ts}</span>
        <span class="tbl-mono">${user}</span>
        <span class="tbl-mono">${role}</span>
        <span class="tbl-mono">${method}</span>
        <span class="tbl-pri" title="${escapeHtml(r.path || '')}">${targetLabel}</span>
        <span class="tbl-mono">${action}</span>
        <span style="font-family:var(--font-mono);font-weight:600;color:${statusColor}">${status}</span>
        <span><button type="button" class="act-btn cfg-audit-view" data-idx="${i}" style="height:22px;padding:0 8px;font-size:11px">View</button></span>
      </div>`;
    }).join('') : `<div class="sigil-block"><div class="sigil-text"><h4>No audit entries</h4><p>Make a configuration change (rule edit, decoder save, dashboard save) and it will be recorded here.</p></div></div>`;

    tbody.querySelectorAll('.cfg-audit-view').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-idx'), 10);
        const el2 = id => document.getElementById(id);
        const drawer = el2('cfgAuditDetailDrawer');
        const body = el2('cfgAuditDetailBody');
        if (drawer && body) {
          body.textContent = JSON.stringify(_cfgAuditLast[idx], null, 2);
          drawer.classList.remove('hidden');
        }
      });
    });
  }

  async function _cfgAuditRefreshStats() {
    const el = id => document.getElementById(id);
    const data = await fetchJson(API.cfgAuditStats).catch(() => null);
    if (!data) return;
    if (el('cfgAuditTotal'))    el('cfgAuditTotal').textContent    = (data.total || 0).toLocaleString();
    if (el('cfgAuditFailures')) el('cfgAuditFailures').textContent = (data.failures || 0).toLocaleString();
    const u = (data.by_user || [])[0];
    const t = (data.by_target || [])[0];
    if (el('cfgAuditTopUser'))       el('cfgAuditTopUser').textContent       = u ? u.user : '—';
    if (el('cfgAuditTopUserCount'))  el('cfgAuditTopUserCount').textContent  = u ? (u.count + ' actions') : '—';
    if (el('cfgAuditTopTarget'))     el('cfgAuditTopTarget').textContent     = t ? t.target : '—';
    if (el('cfgAuditTopTargetCount'))el('cfgAuditTopTargetCount').textContent= t ? (t.count + ' actions') : '—';
  }

  let _cfgAuditWired = false;
  async function loadConfigAuditPage() {
    _cfgAuditOffset = 0;
    await Promise.all([_cfgAuditReload(), _cfgAuditRefreshStats()]);

    if (_cfgAuditWired) return;
    _cfgAuditWired = true;
    const el = id => document.getElementById(id);
    const apply = () => { _cfgAuditOffset = 0; _cfgAuditReload(); _cfgAuditRefreshStats(); };
    el('cfgAuditApply') && el('cfgAuditApply').addEventListener('click', apply);
    el('cfgAuditReset') && el('cfgAuditReset').addEventListener('click', () => {
      ['cfgAuditUser', 'cfgAuditTarget'].forEach(id => { if (el(id)) el(id).value = ''; });
      if (el('cfgAuditAction')) el('cfgAuditAction').value = '';
      if (el('cfgAuditTimeRange')) el('cfgAuditTimeRange').value = '24h';
      if (el('cfgAuditOnlyFailures')) el('cfgAuditOnlyFailures').checked = false;
      apply();
    });
    ['cfgAuditUser', 'cfgAuditTarget'].forEach(id => {
      el(id) && el(id).addEventListener('keydown', e => { if (e.key === 'Enter') apply(); });
    });
    el('cfgAuditAction') && el('cfgAuditAction').addEventListener('change', apply);
    el('cfgAuditTimeRange') && el('cfgAuditTimeRange').addEventListener('change', apply);
    el('cfgAuditOnlyFailures') && el('cfgAuditOnlyFailures').addEventListener('change', apply);
    el('cfgAuditPrev') && el('cfgAuditPrev').addEventListener('click', () => {
      const { size } = _cfgAuditParams();
      if (_cfgAuditOffset >= size) { _cfgAuditOffset -= size; _cfgAuditReload(); }
    });
    el('cfgAuditNext') && el('cfgAuditNext').addEventListener('click', () => {
      const { size } = _cfgAuditParams();
      _cfgAuditOffset += size; _cfgAuditReload();
    });
    el('cfgAuditDetailClose') && el('cfgAuditDetailClose').addEventListener('click', () => {
      const drawer = el('cfgAuditDetailDrawer');
      if (drawer) drawer.classList.add('hidden');
    });
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
      const scaW = 'grid-template-columns:140px 1fr 70px 70px 70px 60px 90px 140px';
      tbody.innerHTML = agentList.length ? agentList.map(a => {
        const score = a.score_pct || a.score || 0;
        const scoreCol = score >= 80 ? 'var(--ok)' : score >= 50 ? 'var(--high)' : 'var(--crit)';
        return `<div class="tbl-r" style="${scaW}">
          <span class="tbl-mono">${escapeHtml(a.agent_name || a.agent || '—')}</span>
          <span class="tbl-muted">${escapeHtml(a.policy || 'CIS Benchmark')}</span>
          <span class="tbl-mono">${a.total_checks || 0}</span>
          <span class="tbl-mono" style="color:var(--ok)">${a.passed || 0}</span>
          <span class="tbl-mono" style="color:${(a.failed||0)>0?'var(--crit)':'var(--fg-4)'}">${a.failed || 0}</span>
          <span class="tbl-mono" style="color:var(--fg-4)">${a.not_applicable || 0}</span>
          <span style="font-family:var(--font-mono);font-weight:700;color:${scoreCol}">${score}%</span>
          <span class="tbl-time">${a.last_scan ? new Date(a.last_scan).toLocaleString() : '—'}</span>
        </div>`;
      }).join('') : `<div class="sigil-block"><div class="sigil-text"><h4>No SCA results found</h4><p>Enable SCA in WatchNode agent config to see policy compliance data</p></div></div>`;
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

  // Shared SVG glyphs for visualization types (cohesive with the rest of the UI)
  const VIZ_TYPE_SVG = {
    metric: '<path d="M4 19V5M4 19h16M8 16V9M12 16v-5M16 16v-9M20 16V6"/>',
    area: '<path d="M3 20V4M3 20h18M21 20v-8l-5 2-4-6-4 4-2-1v9z"/>',
    bar: '<path d="M4 20V4M4 20h16"/><rect x="7" y="11" width="3" height="6"/><rect x="12" y="8" width="3" height="9"/><rect x="17" y="13" width="3" height="4"/>',
    pie: '<path d="M12 3a9 9 0 1 0 9 9h-9V3z"/><path d="M12 3v9h9A9 9 0 0 0 12 3z" opacity=".5"/>',
    table: '<rect x="3" y="4" width="18" height="16" rx="1.5"/><path d="M3 10h18M3 15h18M9 4v16"/>',
    markdown: '<path d="M4 7V5h16v2M9 19h6M12 5v14"/>',
  };
  function vizTypeIcon(type) {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7">${VIZ_TYPE_SVG[type] || VIZ_TYPE_SVG.bar}</svg>`;
  }

  async function loadVisualizePage() {
    document.getElementById('vizBuilderPanel')?.classList.add('hidden');
    document.getElementById('vizListView')?.classList.remove('hidden');
    document.getElementById('vizHeaderBar')?.classList.remove('hidden');
    const res = await fetchJson(API.customVizList).catch(() => ({ visualizations: [] }));
    const vizs = res.visualizations || [];
    const countEl = document.getElementById('vizCountMeta');
    if (countEl) countEl.textContent = vizs.length;
    const grid = document.getElementById('vizList');
    const empty = document.getElementById('vizListEmpty');
    if (!grid) return;
    if (!vizs.length) {
      grid.innerHTML = '';
      empty?.classList.remove('hidden');
      return;
    }
    empty?.classList.add('hidden');
    grid.innerHTML = vizs.map(v => `
      <div class="card" data-viz-id="${escapeHtml(v.id)}" style="cursor:default">
        <div class="card-h" style="gap:9px">
          <span class="viz-type-glyph">${vizTypeIcon(v.viz_type)}</span>
          <h3 class="card-h-title" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(v.title)}</h3>
        </div>
        <div class="card-body" style="padding:10px 16px 12px">
          <div style="display:flex;align-items:center;gap:8px;font-size:11px;color:var(--fg-4);margin-bottom:12px">
            <span class="viz-type-badge">${escapeHtml(v.viz_type)}</span>
            <span>${escapeHtml((v.datasource||'').replace('watchvault-','').replace('-*',''))}</span>
          </div>
          <div style="display:flex;gap:6px">
            <button type="button" class="act-btn viz-card-edit" data-viz-id="${escapeHtml(v.id)}" style="flex:1;font-size:11px">Edit</button>
            <button type="button" class="act-btn viz-card-delete" data-viz-id="${escapeHtml(v.id)}" style="color:var(--crit);font-size:11px;width:32px;padding:0">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
            </button>
          </div>
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
      <div class="card">
        <div class="card-h" style="gap:9px">
          <span class="viz-type-glyph"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg></span>
          <h3 class="card-h-title" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(d.title)}</h3>
        </div>
        <div class="card-body" style="padding:8px 16px 14px">
          <div style="font-size:11px;color:var(--fg-4);margin-bottom:4px">${d.widgets?.length || 0} widget${(d.widgets?.length||0)!==1?'s':''} · ${escapeHtml(d.time_filter||'24h')}</div>
          ${d.description ? `<div style="font-size:12px;color:var(--fg-3);margin-bottom:10px">${escapeHtml(d.description)}</div>` : '<div style="margin-bottom:10px"></div>'}
          <button type="button" class="act-btn primary dash-open-btn" style="width:100%" data-dash-id="${escapeHtml(d.id)}">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
            Open
          </button>
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
    listEl.innerHTML = vizs.length ? vizs.map(v =>
      `<div class="dash-add-viz-item" data-viz-id="${escapeHtml(v.id)}">
        <span class="viz-type-glyph">${vizTypeIcon(v.viz_type)}</span>
        <div>
          <div class="dash-add-viz-title">${escapeHtml(v.title)}</div>
          <div class="dash-add-viz-meta">${escapeHtml(v.viz_type)} · ${escapeHtml(v.datasource.replace('watchvault-','').replace('-*',''))}</div>
        </div>
        <button type="button" class="act-btn primary dash-add-viz-pick" data-viz-id="${escapeHtml(v.id)}" style="margin-left:auto;flex-shrink:0">Add</button>
      </div>`).join('') :
      '<div class="viz-empty" style="padding:30px 20px"><div class="viz-empty-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 20V10M18 20V4M6 20v-4"/></svg></div><p>No saved visualizations yet.<br>Build one in the Visualizations page first.</p></div>';

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
    tbody.innerHTML = `<div class="sigil-block"><div class="sigil-text"><h4>No cases found</h4><p>Click <strong>New Case</strong> to create your first security case</p></div></div>`;
    return;
  }

  const priorityColor = { critical:'var(--crit)', high:'var(--high)', medium:'var(--med)', low:'var(--fg-4)' };
  const statusColor   = { open:'var(--high)', investigating:'var(--accent)', resolved:'var(--ok)', closed:'var(--fg-4)', false_positive:'var(--med)' };
  const caseW = 'grid-template-columns:50px 1fr 110px 90px 120px 60px 130px 90px';

  tbody.innerHTML = cases.map(c => `
    <div class="tbl-r discover-row" style="${caseW};cursor:pointer" onclick="openCaseDetail(${c.id})">
      <span class="tbl-mono" style="color:var(--fg-4)">#${c.id}</span>
      <span class="tbl-pri">${escHtml(c.title)}${slaBadge(c)}</span>
      <span><span class="pill" style="background:${statusColor[c.status]||'var(--fg-4)'}22;color:${statusColor[c.status]||'var(--fg-3)'};border:1px solid ${statusColor[c.status]||'var(--line)'}44">${c.status}</span></span>
      <span style="color:${priorityColor[c.priority]||'var(--fg-4)'};font-weight:600;font-size:11px;text-transform:uppercase">${c.priority}</span>
      <span class="tbl-mono">${c.assignee || '—'}</span>
      <span class="tbl-mono">${c.note_count || 0}</span>
      <span class="tbl-time">${fmtTs(c.created_at)}</span>
      <span style="display:flex;gap:4px">
        <button onclick="event.stopPropagation();openCaseDetail(${c.id})" class="btn-disc-detail" title="View">⋯</button>
        <button onclick="event.stopPropagation();confirmDeleteCase(${c.id})" class="btn-disc-detail" style="color:var(--crit)" title="Delete">✕</button>
      </span>
    </div>`).join('');
}

async function openCaseDetail(id) {
  _currentCaseId = id;
  const panel = document.getElementById('caseDetailPanel');
  panel.style.display = 'block';

  const res = await fetch(`/api/cases/${id}`).then(r => r.json()).catch(() => ({}));
  const c = res.data || {};

  const priorityColor = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#6b7280' };
  const statusColor   = { open:'#f59e0b', investigating:'#3b82f6', resolved:'#10b981', closed:'#6b7280', false_positive:'#8b5cf6' };

  let idLine = `Case #${c.id}  ·  Created ${fmtTs(c.created_at)}`;
  if (c.sla_breached)              idLine += '  ·  ⚠ SLA breached';
  else if (c.due_at && c.due_at < Date.now() && c.status !== 'resolved' && c.status !== 'closed') idLine += '  ·  ⚠ Overdue';
  else if (c.due_at)              idLine += `  ·  Due ${fmtTs(c.due_at)}`;
  document.getElementById('detailCaseId').textContent    = idLine;
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
  await loadCaseHistory(id);
}

// slaBadge renders a small chip reflecting a case's SLA state for the list view.
function slaBadge(c) {
  const chip = (txt, col) => ` <span style="background:${col}22;color:${col};border:1px solid ${col}55;font-size:9px;padding:1px 5px;border-radius:4px;margin-left:6px;font-weight:600;text-transform:uppercase">${txt}</span>`;
  if (c.sla_breached) return chip('SLA breached', '#ef4444');
  if (!c.due_at || c.status === 'resolved' || c.status === 'closed') return '';
  const now = Date.now();
  if (c.due_at < now) return chip('Overdue', '#f97316');
  const mins = Math.round((c.due_at - now) / 60000);
  if (mins <= 60) return chip(`Due ${mins}m`, '#f59e0b');
  return chip(`Due ${Math.round(mins / 60)}h`, '#6b7280');
}

async function loadCaseHistory(id) {
  const el = document.getElementById('detailCaseHistory');
  if (!el) return;
  const res  = await fetch(`/api/cases/${id}/history`).then(r => r.json()).catch(() => ({}));
  const hist = res.data || [];
  if (!hist.length) {
    el.innerHTML = '<div style="font-size:12px;color:var(--text-muted);font-style:italic">No history yet.</div>';
    return;
  }
  const label = { created:'Created', status_changed:'Status', assignee_changed:'Assignee', priority_changed:'Priority', sla_breached:'SLA breached' };
  el.innerHTML = hist.map(h => {
    let detail;
    if (h.action === 'created')           detail = 'Case opened';
    else if (h.action === 'sla_breached') detail = `Escalated ${escHtml(h.old_value)} → ${escHtml(h.new_value)}`;
    else                                  detail = `${escHtml(h.old_value || '—')} → ${escHtml(h.new_value || '—')}`;
    return `<div style="display:flex;gap:10px;align-items:baseline;font-size:12px;padding:4px 0;border-bottom:1px solid var(--border)">
      <span style="color:var(--text-muted);white-space:nowrap;min-width:140px">${fmtTs(h.created_at)}</span>
      <span style="font-weight:600;color:var(--text-primary);min-width:90px">${label[h.action] || escHtml(h.action)}</span>
      <span style="color:var(--text-secondary);flex:1">${detail}</span>
      <span style="color:var(--text-muted)">${escHtml(h.actor || '')}</span>
    </div>`;
  }).join('');
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

// ── Compliance Hub ────────────────────────────────────────────────────────────

const FRAMEWORK_ICONS = {
  iso27001: '🔒', nist: '🇺🇸', soc2: '✅', hipaa: '🏥', pci: '💳'
};

async function loadComplianceHub() {
  const days = document.getElementById('complianceDays')?.value || '30';

  // Load all framework summaries in parallel.
  const frameworksRes = await fetch('/api/compliance/frameworks').then(r => r.json()).catch(() => ({}));
  const frameworks = frameworksRes.data || [];

  const scores = await Promise.all(
    frameworks.map(f =>
      fetch(`/api/compliance/${f.id}?days=${days}`).then(r => r.json()).catch(() => null)
    )
  );

  const cards = document.getElementById('complianceScoreCards');
  if (!cards) return;

  cards.innerHTML = scores.map((s, i) => {
    if (!s) return '';
    const fw   = frameworks[i];
    const icon = FRAMEWORK_ICONS[fw.id] || '📋';
    const sc   = s.score || 0;
    const col  = sc >= 90 ? '#10b981' : sc >= 70 ? '#f59e0b' : '#ef4444';
    const ring = `conic-gradient(${col} ${sc * 3.6}deg, var(--surface-2) 0deg)`;

    return `
      <div class="panel" style="cursor:pointer;border-top:3px solid ${col}" onclick="loadFrameworkDetail('${fw.id}', '${s.framework}', ${days})">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px">
          <div>
            <div style="font-size:14px;font-weight:700">${icon} ${s.framework}</div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:2px">${s.control_count||s.total_controls} controls · ${days}d</div>
          </div>
          <div style="position:relative;width:56px;height:56px">
            <div style="width:56px;height:56px;border-radius:50%;background:${ring}"></div>
            <div style="position:absolute;inset:6px;background:var(--surface-1);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:${col}">${sc}%</div>
          </div>
        </div>
        <div style="display:flex;gap:16px;font-size:12px">
          <div><span style="color:#10b981;font-weight:600">${s.compliant}</span> <span style="color:var(--text-muted)">compliant</span></div>
          <div><span style="color:#ef4444;font-weight:600">${s.non_compliant}</span> <span style="color:var(--text-muted)">issues</span></div>
          <div><span style="color:var(--text-muted)">${s.total_alerts} alerts</span></div>
        </div>
        <div style="margin-top:10px;height:4px;background:var(--surface-2);border-radius:2px">
          <div style="width:${sc}%;height:100%;background:${col};border-radius:2px;transition:width 0.5s"></div>
        </div>
        <div style="font-size:11px;color:var(--accent);margin-top:8px;text-align:right">View controls →</div>
      </div>`;
  }).join('');
}

async function loadFrameworkDetail(frameworkId, frameworkName, days) {
  const res = await fetch(`/api/compliance/${frameworkId}?days=${days}`).then(r => r.json()).catch(() => ({}));
  const controls = res.controls || [];

  document.getElementById('complianceDetailTitle').textContent = `${frameworkName} — Control Details (${days} days)`;
  document.getElementById('complianceDetailPanel').style.display = 'block';

  const tbody = document.getElementById('complianceControlsBody');
  if (!tbody) return;

  const levelColor = l => l >= 10 ? '#ef4444' : l >= 6 ? '#f97316' : l >= 3 ? '#f59e0b' : '#10b981';

  const ccW = 'grid-template-columns:120px 1fr 100px 120px 110px';
  tbody.innerHTML = controls.map(c => {
    const compliant = c.status === 'compliant';
    return `<div class="tbl-r" style="${ccW}">
      <span class="tbl-mono" style="color:var(--accent)">${escHtml(c.id)}</span>
      <span class="tbl-pri">${escHtml(c.name)}</span>
      <span><span class="pill ${compliant ? 'ok' : 'crit'}">${compliant ? '✓ OK' : '✗ ISSUE'}</span></span>
      <span class="tbl-mono" style="color:${c.alert_count > 0 ? 'var(--crit)':'var(--fg-4)'};font-weight:${c.alert_count > 0 ? '600':'400'}">${c.alert_count}</span>
      <span>
        ${c.max_level > 0
          ? `<span style="color:${levelColor(c.max_level)};font-weight:600;font-size:12px;font-family:var(--font-mono)">Level ${c.max_level}</span>`
          : '<span class="disc-empty">—</span>'}
      </span>
    </div>`;
  }).join('');

  // Scroll to detail
  document.getElementById('complianceDetailPanel').scrollIntoView({behavior: 'smooth', block: 'start'});
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="compliance-hub"]').forEach(el => {
    el.addEventListener('click', () => loadComplianceHub());
  });
});

// ── Cloud Monitoring ──────────────────────────────────────────────────────────

async function loadCloudMonitoringPage() {
  await Promise.all([loadCloudStatus(), loadCloudEvents()]);
}

async function loadCloudStatus() {
  const res = await fetch('/api/cloud/status').then(r => r.json()).catch(() => ({}));
  const providers = res.data || [];
  const el = document.getElementById('cloudProviderCards');
  if (!el) return;

  const icons  = { aws:'🟨', azure:'🟦', gcp:'🟩' };
  const labels = { aws:'AWS CloudTrail', azure:'Azure Activity Log', gcp:'GCP Cloud Logging' };
  const colors = { aws:'#f59e0b', azure:'#3b82f6', gcp:'#10b981' };

  el.innerHTML = providers.map(p => {
    const col = colors[p.provider] || '#6b7280';
    const ok  = p.configured;
    return `
      <div class="panel" style="border-left:3px solid ${col};padding:16px">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
          <div>
            <div style="font-size:13px;font-weight:600">${icons[p.provider]||'☁'} ${labels[p.provider]||p.provider}</div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:2px">
              ${p.region||p.subscription||p.project||''}
            </div>
          </div>
          <span style="background:${ok ? '#10b98122':'#6b728022'};color:${ok ? '#10b981':'#6b7280'};padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600">${ok ? 'ACTIVE':'NOT CONFIGURED'}</span>
        </div>
        <div style="font-size:12px;color:var(--text-muted)">
          Last sync: ${p.last_sync ? new Date(p.last_sync).toLocaleString() : 'Never'}<br>
          Events indexed: ${p.events_indexed || 0}
        </div>
        ${ok ? `<button onclick="syncCloud('${p.provider}')" style="margin-top:10px;background:${col}22;border:1px solid ${col}44;color:${col};padding:4px 12px;border-radius:4px;font-size:11px;cursor:pointer;width:100%">⟳ Sync Now</button>` : ''}
      </div>`;
  }).join('');
}

async function syncCloud(provider) {
  const btn = event?.target;
  if (btn) btn.textContent = 'Syncing…';
  const res = await fetch(`/api/cloud/sync/${provider}`, {method:'POST'}).then(r => r.json()).catch(() => ({}));
  if (btn) btn.textContent = '⟳ Sync Now';
  if (res?.events_indexed !== undefined) {
    alert(`✓ ${provider.toUpperCase()} sync complete — ${res.events_indexed} events indexed`);
    await loadCloudStatus();
    await loadCloudEvents();
  } else {
    alert(`✗ Sync failed: ${res?.error || 'Check cloud credentials'}`);
  }
}

async function loadCloudEvents() {
  const provider = document.getElementById('cloudProviderFilter')?.value || '';
  const hours    = document.getElementById('cloudHoursFilter')?.value   || '24';
  const params   = new URLSearchParams({limit: 100, hours});
  if (provider) params.set('provider', provider);

  const res = await fetch(`/api/cloud/events?${params}`).then(r => r.json()).catch(() => ({}));
  const events = res.data || [];
  const tbody  = document.getElementById('cloudEventsBody');
  if (!tbody) return;

  const ceW = 'grid-template-columns:140px 90px 1fr 140px 1fr 90px';
  if (!events.length) {
    tbody.innerHTML = `<div class="sigil-block"><div class="sigil-text"><h4>No cloud events found</h4><p>Configure cloud credentials and click Refresh to pull events</p></div></div>`;
    return;
  }

  const providerColor = { aws:'var(--high)', azure:'var(--accent)', gcp:'var(--ok)' };
  tbody.innerHTML = events.map(e => {
    const prov = (e.cloud_provider || '').toLowerCase();
    const pc   = providerColor[prov] || 'var(--fg-4)';
    const sev  = e.severity || e.level || '';
    const caller = e.caller || e.username || '—';
    const resource = e.resource_name || e.resource_id || e.operation_name || '—';
    return `<div class="tbl-r" style="${ceW}">
      <span class="tbl-time">${fmtTs(e.timestamp)}</span>
      <span><span class="pill" style="color:${pc};background:${pc}22;border:1px solid ${pc}44">${prov||'cloud'}</span></span>
      <span class="tbl-pri">${escHtml(e.event_type||e.event_name||'—')}</span>
      <span class="tbl-mono">${escHtml(caller)}</span>
      <span class="tbl-muted" title="${escHtml(resource)}">${escHtml(resource.slice(0,50))}</span>
      <span class="tbl-muted">${escHtml(sev)}</span>
    </div>`;
  }).join('');
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="cloud-monitoring"]').forEach(el => {
    el.addEventListener('click', () => loadCloudMonitoringPage());
  });
});

// ── Geo Threat Map ────────────────────────────────────────────────────────────

let _geoMap     = null;
let _geoMarkers = [];

function initGeoMap() {
  if (_geoMap) {
    // Already initialised — just force a size recalculation in case the
    // container was hidden when the map was first rendered.
    setTimeout(() => _geoMap.invalidateSize(), 50);
    return;
  }
  const container = document.getElementById('threatMap');
  if (!container) return;
  try {
    _geoMap = L.map('threatMap', {
      center: [20, 0],
      zoom: 2,
      minZoom: 1,
      maxZoom: 8,
      zoomControl: true,
    });

    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    if (isDark) {
      // Dark CartoDB tiles
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://carto.com">CARTO</a>',
        subdomains: 'abcd', maxZoom: 19,
      }).addTo(_geoMap);
    } else {
      // Light OpenStreetMap tiles (no CARTO CSP needed)
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://openstreetmap.org/copyright">OpenStreetMap</a>',
        maxZoom: 19,
      }).addTo(_geoMap);
    }

    // Fix tile rendering after initial hidden-container render
    setTimeout(() => _geoMap.invalidateSize(), 100);
  } catch (e) {
    console.warn('Leaflet not available:', e);
  }
}

async function loadGeoMap() {
  initGeoMap();

  const hours = document.getElementById('geoTimeRange')?.value || '168';
  const statusEl = document.getElementById('geoStatusMsg');
  if (statusEl) statusEl.textContent = 'Fetching geo data (may take a moment for new IPs)…';

  const res = await fetch(`/api/geo/map-data?hours=${hours}&limit=100`)
    .then(r => r.json())
    .catch(() => ({}));

  const points    = res.points    || [];
  const countries = res.countries || [];

  if (statusEl) {
    statusEl.textContent = points.length
      ? `${points.length} unique IPs geo-located from recent alerts.`
      : 'No geo data yet. Alerts with source IPs will appear here.';
  }

  // Clear old markers.
  _geoMarkers.forEach(m => m.remove());
  _geoMarkers = [];

  if (_geoMap && points.length) {
    const maxCount = Math.max(...points.map(p => p.alert_count), 1);

    points.forEach(p => {
      if (!p.lat || !p.lng) return;

      // Circle radius scales with alert count (log scale).
      const radius   = Math.max(4, Math.log(p.alert_count + 1) * 6);
      const severity = p.max_level >= 10 ? '#ef4444'
                     : p.max_level >= 6  ? '#f97316'
                     : p.max_level >= 3  ? '#f59e0b'
                     :                     '#3b82f6';

      const circle = L.circleMarker([p.lat, p.lng], {
        radius,
        fillColor:   severity,
        color:       severity,
        weight:      1,
        opacity:     0.9,
        fillOpacity: 0.5,
      });

      circle.bindPopup(`
        <div style="font-family:monospace;min-width:180px">
          <strong>${p.ip}</strong><br>
          <span style="color:#666">${p.city ? p.city + ', ' : ''}${p.country}</span><br>
          <span style="color:#666">ISP: ${p.isp || '—'}</span><br>
          <hr style="margin:6px 0;border:none;border-top:1px solid #eee">
          Alerts: <strong style="color:${severity}">${p.alert_count}</strong><br>
          Max level: ${p.max_level}
        </div>
      `);

      circle.addTo(_geoMap);
      _geoMarkers.push(circle);
    });
  }

  // ── New V2 country list ───────────────────────────────────────────
  const countryWrap = document.getElementById('geoCountryList');
  const hasGeoData  = (countries.length > 0 || points.length > 0);
  const countryData = countries.slice(0,7).map(c => ({
    flag: '', name: c.country || '—', count: c.count||0, share: 1, sev: (c.count||0)>300?'crit':(c.count||0)>100?'high':'med'
  }));

  const mapDot     = document.getElementById('geoMapDot');
  const vecMeta    = document.getElementById('geoVectorsMeta');
  const cntMeta    = document.getElementById('geoCountriesMeta');
  const ipsMeta    = document.getElementById('geoIpsMeta');
  const ipsDot     = document.getElementById('geoIpsDot');
  const legend     = document.getElementById('geoLegend');
  const emptyOverlay = document.getElementById('geoEmptyOverlay');

  if (mapDot) mapDot.style.background = hasGeoData ? 'var(--crit)' : 'var(--ok)';
  if (mapDot) mapDot.style.boxShadow  = hasGeoData ? '0 0 6px var(--crit)' : '';
  if (vecMeta) vecMeta.textContent  = hasGeoData ? `${points.length} active vectors` : 'No traffic detected';
  if (cntMeta) cntMeta.textContent  = countryData.length;
  if (ipsMeta) ipsMeta.textContent  = hasGeoData ? `${points.length} ranked · last 7d` : '';
  if (ipsDot)  ipsDot.style.background = hasGeoData ? 'var(--crit)' : 'var(--ok)';
  if (legend)  legend.style.display    = hasGeoData ? 'flex' : 'none';
  if (emptyOverlay) emptyOverlay.style.display = hasGeoData ? 'none' : 'grid';

  // Draw SVG map
  const contGroup   = document.getElementById('geoContGroup');
  const attackGroup = document.getElementById('geoAttackGroup');
  if (contGroup) {
    contGroup.innerHTML = GEO_CONTINENTS.map(d => `<path d="${d}" class="v2-cont"/>`).join('');
  }
  if (attackGroup) {
    const origins = points.map(p => ({ x: p.x||0, y: p.y||0, s: p.sev||'low' }));
    const target  = [180, 220];
    let html = '';
    if (origins.length) {
      html += `<circle cx="${target[0]}" cy="${target[1]}" r="32" fill="url(#v2tgtGlow)"/>`;
      html += `<circle cx="${target[0]}" cy="${target[1]}" r="5" fill="var(--accent)" stroke="#04201d" stroke-width="1.5"/>`;
      origins.forEach(o => {
        const mx = (o.x + target[0]) / 2, my = Math.min(o.y, target[1]) - 70;
        const cls = `v2-geo-arc${o.s !== 'crit' ? ' ' + o.s : ''}`;
        html += `<path class="${cls}" d="M ${o.x} ${o.y} Q ${mx} ${my} ${target[0]} ${target[1]}"/>`;
        const col = o.s==='crit'?'var(--crit)':o.s==='high'?'var(--high)':o.s==='med'?'var(--med)':'var(--low)';
        const r = o.s==='crit'?6:o.s==='high'?5:4;
        html += `<circle cx="${o.x}" cy="${o.y}" r="${r+4}" fill="${col}" fill-opacity="0.15" class="v2-geo-pulse-r"/>`;
        html += `<circle cx="${o.x}" cy="${o.y}" r="${r}" fill="${col}" style="filter:drop-shadow(0 0 6px ${col})"/>`;
      });
    }
    attackGroup.innerHTML = html;
  }

  // Country list
  if (countryWrap) {
    const maxC = Math.max(...countryData.map(c => c.count), 1);
    countryWrap.innerHTML = !countryData.length
      ? `<div class="chart-empty" style="padding:20px"><div class="chart-empty-icon info"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg></div><div class="chart-empty-msg">No attacker geo data</div></div>`
      : countryData.map(c => `
          <div class="country-row">
            <span class="country-flag">${c.flag||'🌐'}</span>
            <div style="display:flex;flex-direction:column;gap:4px;min-width:0">
              <span class="v2-country-name">${escapeHtml(c.name)}</span>
              <div class="country-bar ${c.sev==='med'?'med':c.sev==='high'?'high':''}"><i style="width:${Math.round((c.share||c.count/maxC)*100)}%"></i></div>
            </div>
            <span class="pill ${c.sev}" style="height:16px;padding:0 5px;font-size:9px">${c.sev}</span>
            <span class="country-count">${(c.count||0).toLocaleString()}</span>
          </div>`).join('');
  }

  // Source IPs table
  const ipsWrap = document.getElementById('geoIpWrap');
  const ipData  = points.slice(0,10).map(p => ({
    ip: p.ip, country: p.country_code||'—', city: p.city||'—', isp: p.isp||'—',
    alerts: p.alert_count||0, max: p.max_level||0, last: p.last_seen ? new Date(p.last_seen).toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit',second:'2-digit'}) : '—'
  }));
  if (ipsWrap) {
    if (!ipData.length) {
      ipsWrap.innerHTML = `<div class="sigil-block"><div class="sigil" style="background:radial-gradient(circle,rgba(52,211,153,.10),transparent 70%);color:#34D399"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg></div><div class="sigil-text"><h4>No geo data yet</h4><p>Alerts with source IPs will populate this table.</p></div></div>`;
    } else {
      ipsWrap.innerHTML = `<div class="tbl">
        <div class="tbl-h" style="grid-template-columns:150px 60px 110px 1fr 80px 70px 100px">
          <span>IP Address</span><span>Country</span><span>City</span><span>ISP / ASN</span><span>Alerts</span><span>Max level</span><span>Last seen</span>
        </div>
        ${ipData.map(r => `<div class="tbl-r" style="grid-template-columns:150px 60px 110px 1fr 80px 70px 100px">
          <span class="tbl-mono">${escapeHtml(r.ip)}</span>
          <span class="tbl-mono">${escapeHtml(r.country)}</span>
          <span class="tbl-pri" style="font-size:11.5px">${escapeHtml(r.city)}</span>
          <span class="tbl-mono" style="color:var(--fg-3)">${escapeHtml(r.isp)}</span>
          <span class="tbl-mono" style="color:var(--fg-2)">${(r.alerts||0).toLocaleString()}</span>
          <span><span class="pill ${r.max>=12?'crit':r.max>=8?'high':'med'}">${r.max}</span></span>
          <span class="tbl-time">${escapeHtml(r.last)}</span>
        </div>`).join('')}
      </div>`;
    }
  }
  // Keep legacy compat
  const countryEl = document.getElementById('geoCountryList');
  if (countryEl && !countryEl.querySelector('.country-row') && !countryEl.querySelector('.chart-empty')) {
    countryEl.innerHTML = '<div style="color:var(--fg-4);font-size:12px">—</div>';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="geo-map"]').forEach(el => {
    el.addEventListener('click', () => {
      // Small delay to let the page section become visible before Leaflet renders.
      setTimeout(loadGeoMap, 100);
    });
  });
});

// ── Risk-Based Alerting ───────────────────────────────────────────────────────

// Shared agent id→hostname cache for UEBA/RBA pages
let _entityAgentMap = {};
async function _ensureEntityAgentMap() {
  if (Object.keys(_entityAgentMap).length > 0) return;
  try {
    const res = await fetch('/api/agents?limit=500').then(r => r.json()).catch(() => ({}));
    // /api/agents returns the Wazuh-style envelope {data:{affected_items:[...]}}.
    // The old code grabbed res.data (the OBJECT) and called .forEach on it, which
    // threw and left the map empty — so every entity fell back to raw hex. Dig
    // into affected_items, and stay tolerant of the bare-array / {data:[]} shapes.
    const d = res && res.data;
    const list = Array.isArray(res)              ? res
      : Array.isArray(res.agents)                ? res.agents
      : (d && Array.isArray(d.affected_items))   ? d.affected_items
      : Array.isArray(d)                         ? d
      : Array.isArray(res.affected_items)        ? res.affected_items
      : [];
    list.forEach(a => {
      const id = a.id || a.agent_id || '';
      if (id) _entityAgentMap[id] = a.hostname || a.name || a.agent_name || id;
    });
  } catch(e) {}
}
function _resolveEntity(entityId, entityType) {
  if (!entityId) return '—';
  // For agent-type entities try to resolve UUID → hostname
  if (!entityType || entityType === 'agent') {
    const hostname = _entityAgentMap[entityId];
    if (hostname && hostname !== entityId) return hostname;
  }
  // Truncate long UUIDs
  if (entityId.length > 20 && /^[a-f0-9-]+$/i.test(entityId)) {
    return entityId.slice(0, 8) + '…';
  }
  return entityId;
}

async function loadRbaPage() {
  await _ensureEntityAgentMap();
  await Promise.all([loadRbaEntities(), loadRbaNotables(), loadRbaWeights()]);
  _renderRbaV2();
}

// Purge "ghost" entities — agent IDs no longer registered (old/re-installed
// nodes) that can never resolve to a hostname. Server keeps live agents and
// syslog sources and clears the rest, then we refresh the board.
async function purgeStaleEntities() {
  const btn = document.getElementById('rbaPurgeBtn');
  if (!confirm('Clear risk scores for stale/ghost entities?\n\nThis removes RBA + UEBA history for agent IDs that are no longer registered (old or re-installed nodes that show as raw hex). Live agents and syslog sources are kept.')) return;
  const orig = btn ? btn.innerHTML : '';
  if (btn) { btn.disabled = true; btn.innerHTML = 'Clearing…'; }
  try {
    const res = await fetch('/api/rba/entities/purge-stale', { method: 'POST' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      alert('Could not clear stale entities: ' + (data.error || res.status));
    } else if ((data.deleted || 0) === 0) {
      alert('No stale entities found — the board already shows only live machines.');
    } else {
      alert('Cleared ' + data.deleted + ' stale entit' + (data.deleted === 1 ? 'y' : 'ies') + '. The board now shows only your live machines.');
    }
  } catch (e) {
    alert('Could not clear stale entities: ' + e);
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = orig; }
    // Rebuild the agent→hostname cache and reload the board.
    _entityAgentMap = {};
    await loadRbaPage();
  }
}

function switchRbaTab(tabKey) {
  ['entities','notables','weights'].forEach(k => {
    const pEl = document.getElementById(`rbaPaneEntities`.replace('entities', k === 'entities' ? 'entities' : k[0].toUpperCase()+k.slice(1)));
    const tEl = document.getElementById(`rbaTabEntities`.replace('entities', k === 'entities' ? 'entities' : k[0].toUpperCase()+k.slice(1)));
    const panes = { entities:'rbaPaneEntities', notables:'rbaPaneNotables', weights:'rbaPaneWeights' };
    const tabs  = { entities:'rbaTabEntities',  notables:'rbaTabNotables',  weights:'rbaTabWeights' };
    const pane = document.getElementById(panes[k]); if (pane) pane.style.display = k === tabKey ? '' : 'none';
    const tab  = document.getElementById(tabs[k]);  if (tab)  tab.classList.toggle('active', k === tabKey);
  });
}

// Map a raw accumulated RBA risk score to a readable 0–100 index. The raw score
// is an uncapped point sum (per-alert weights, 24h rolling) that can reach the
// millions under heavy load. Half-saturation at the entity threshold: 0 = no
// risk, 50 = at the notable-firing threshold, asymptotes to 100 for large
// pile-ups — so big scores stay distinguishable instead of all pinning at 100.
function _riskIndex(score, threshold) {
  score = Number(score) || 0;
  threshold = Number(threshold) || 100;
  if (score <= 0) return 0;
  return Math.round(100 * score / (score + threshold));
}

function _renderRbaV2() {
  // Fetch cached data or use demo
  const res = window._rbaEntitiesCache || {};
  const entities   = res.entities  || [];
  const notables   = res.notables  || [];
  const weights    = res.weights   || [];

  // KPIs
  const highest = entities.reduce((a,e)=>Math.max(a,e.score||e.current_score||0),0);
  const notableCount = notables.length;
  const _sk = (id,val,tag,kind,sub,subId,tagId) => {
    const vEl=document.getElementById(id); if(vEl) vEl.textContent=val;
    const tEl=document.getElementById(tagId); if(tEl){tEl.textContent=tag;tEl.className=`kpi-tag ${kind}`;}
    const sEl=document.getElementById(subId); if(sEl) sEl.textContent=sub;
  };
  _sk('rbaKpiEntities', String(entities.length), entities.length>0?'+'+entities.length:'OK', entities.length>0?'up':'ok', 'auto-discovered', 'rbaKpiEntitiesSub', 'rbaKpiEntitiesTag');
  _sk('rbaKpiNotables', String(notableCount), notableCount>0?'ATTN':'CLEAR', notableCount>0?'crit':'ok', 'over threshold (100)', 'rbaKpiNotablesSub', 'rbaKpiNotablesTag');
  const highestIdx = _riskIndex(highest, 100);
  _sk('rbaKpiHighest',  String(highestIdx), highest>0?(highestIdx>=70?'HIGH':'OK'):'OK', highest>0?(highestIdx>=70?'up':'ok'):'ok', highest>0?('raw '+Number(highest).toLocaleString()):'below threshold', 'rbaKpiHighestSub', 'rbaKpiHighestTag');
  const metaEl=document.getElementById('rbaEntitiesMeta'); if(metaEl) metaEl.textContent=entities.length;
  // Tab counts
  const ec=document.getElementById('rbaTabEntitiesCount'); if(ec) ec.textContent=entities.length;
  const nc=document.getElementById('rbaTabNotablesCount'); if(nc) nc.textContent=notableCount;
  const wc=document.getElementById('rbaTabWeightsCount'); if(wc) wc.textContent=weights.length;

  // Entities pane
  const ePane = document.getElementById('rbaPaneEntities');
  if (ePane) {
    ePane.innerHTML = `<div class="tbl">
      <div class="tbl-h" style="grid-template-columns:28px 1fr 90px 70px 1fr 70px 80px 120px">
        <span></span><span>Entity</span><span>Risk score</span><span>Threshold</span><span>Progress</span><span>Alerts</span><span>Notables</span><span>Last event</span>
      </div>
      ${entities.map(e => {
        const s     = e.score || e.current_score || 0;
        const thr   = e.threshold || 100;
        const idx   = _riskIndex(s, thr);
        const pct   = idx;
        const tone  = s>=thr?'hot':s>=thr*.7?'warm':'';
        const sCol  = s>=thr?'var(--crit)':s>=thr*.7?'var(--high)':'var(--ok)';
        const sBg   = s>=thr?'var(--crit-soft,rgba(242,85,85,.12))':s>=thr*.7?'var(--high-soft,rgba(245,158,11,.12))':'var(--ok-soft,rgba(52,211,153,.12))';
        const badge = e.badge ? `<span class="entbadge" style="background:${e.color||'#555'}">${escapeHtml(e.badge)}</span>` : `<span class="entbadge idle">·</span>`;
        return `<div class="tbl-r" style="grid-template-columns:28px 1fr 90px 70px 1fr 70px 80px 120px">
          <span>${badge}</span>
          <span class="tbl-pri" title="${escapeHtml(e.id||e.entity_id||'')}" style="${e.mono?'font-family:var(--font-mono);font-size:11px':'font-size:12px'}">${escapeHtml(typeof _resolveEntity==='function' ? _resolveEntity(e.id||e.entity_id, e.entity_type||'agent') : (e.id||e.entity_id||'—'))}</span>
          <span><span title="raw score: ${Number(s).toLocaleString()}" style="font-family:var(--font-mono);font-size:13px;font-weight:500;color:${sCol};padding:2px 8px;border-radius:4px;background:${sBg}">${idx}</span></span>
          <span class="tbl-mono" style="color:var(--fg-4)">${thr}</span>
          <span style="display:flex;align-items:center;gap:8px">
            <span class="risk-prog ${tone}"><i style="width:${pct}%"></i></span>
            <span style="font-family:var(--font-mono);font-size:10.5px;color:var(--fg-3);min-width:32px;text-align:right">${pct}%</span>
          </span>
          <span class="tbl-mono">${e.alerts||e.alert_count_7d||'—'}</span>
          <span class="tbl-mono" style="color:${(e.notables||e.notables_fired||0)>0?'var(--crit)':'var(--fg-4)'}">${e.notables||e.notables_fired||0}</span>
          <span class="tbl-time">${e.last||e.last_event||'—'}</span>
        </div>`;
      }).join('')}
    </div>`;
  }

  // Notables pane
  const nPane = document.getElementById('rbaPaneNotables');
  if (nPane) {
    if (!notables.length) {
      nPane.innerHTML = `<div class="chart-empty"><div class="chart-empty-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M13 2 3 14h7l-1 8 10-12h-7l1-8z"/></svg></div><div class="chart-empty-msg">No active risk notables</div><div class="chart-empty-sub">Notables fire only when an entity's risk score crosses the threshold (default 100)</div></div>`;
    } else {
      nPane.innerHTML = `<div class="tbl">
        <div class="tbl-h" style="grid-template-columns:110px 1fr 70px 90px 1fr 90px">
          <span>Notable ID</span><span>Entity</span><span>Score</span><span>Severity</span><span>Summary</span><span>Triggered</span>
        </div>
        ${notables.map(n => `<div class="tbl-r" style="grid-template-columns:110px 1fr 70px 90px 1fr 90px">
          <span class="tbl-mono">${escapeHtml(n.id||'—')}</span>
          <span class="tbl-pri" title="${escapeHtml(n.entity||n.entity_id||'')}">${escapeHtml(typeof _resolveEntity==='function' ? _resolveEntity(n.entity||n.entity_id, n.entity_type||'agent') : (n.entity||n.entity_id||'—'))}</span>
          <span title="raw score: ${Number(n.score||n.risk_score||0).toLocaleString()}" style="font-family:var(--font-mono);color:var(--crit);font-weight:500">${_riskIndex(n.score||n.risk_score||0, 100)}</span>
          <span><span class="pill ${n.sev||'crit'}">${n.sev||'crit'}</span></span>
          <span class="tbl-muted">${escapeHtml(n.summary||n.description||'—')}</span>
          <span class="tbl-time">${escapeHtml(n.triggered||n.created_at||'—')}</span>
        </div>`).join('')}
      </div>`;
    }
  }

  // Weights pane — editable: add a per-rule weight, edit existing ones
  const wPane = document.getElementById('rbaPaneWeights');
  if (wPane) {
    const addForm = `<div class="rba-weight-add">
      <span class="rba-weight-add-lbl">Add / override a rule weight</span>
      <input type="number" id="rbaNewWeightRule" class="fld" placeholder="Rule ID" min="1" style="width:110px">
      <input type="number" id="rbaNewWeightVal" class="fld" placeholder="Weight (pts)" min="0" style="width:120px">
      <button type="button" class="act-btn primary" onclick="addRbaWeight()">Add weight</button>
    </div>`;
    if (!weights.length) {
      wPane.innerHTML = addForm + `<div class="chart-empty" style="padding:28px"><div class="chart-empty-icon ok"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 3v18M6 7l-3 7c0 2 1.5 3 3 3s3-1 3-3L6 7zM18 7l-3 7c0 2 1.5 3 3 3s3-1 3-3l-3-7zM5 7h14"/></svg></div><div class="chart-empty-msg">No custom rule weights</div><div class="chart-empty-sub">All rules currently use level-derived default weights. Add an override above to make a specific rule contribute more (or less) risk.</div></div>`;
    } else {
      wPane.innerHTML = addForm + `<div class="tbl">
        <div class="tbl-h" style="grid-template-columns:90px 1fr 110px 150px">
          <span>Rule ID</span><span>Rule</span><span>Weight (pts)</span><span></span>
        </div>
        ${weights.map(w => `<div class="tbl-r" style="grid-template-columns:90px 1fr 110px 150px">
          <span class="tbl-mono" style="color:var(--accent)">#${escapeHtml(String(w.rule_id ?? '—'))}</span>
          <span class="tbl-pri">${escapeHtml(w.rule||'—')}</span>
          <span><input type="number" class="fld rba-w-input" data-rule-id="${escapeHtml(String(w.rule_id))}" value="${escapeHtml(String(w.weight||0))}" min="1" style="width:80px;height:26px"></span>
          <span style="display:flex;gap:6px">
            <button type="button" class="act-btn rba-w-save" data-rule-id="${escapeHtml(String(w.rule_id))}" onclick="saveRbaWeightFromRow(${w.rule_id})">Save</button>
            <button type="button" class="act-btn rba-w-del" title="Remove this override" data-rule-id="${escapeHtml(String(w.rule_id))}" onclick="deleteRbaWeight(${w.rule_id})" style="color:var(--crit);width:30px;padding:0">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
            </button>
          </span>
        </div>`).join('')}
      </div>`;
    }
  }
}

// ── RBA: rule weight + entity threshold configuration (live PUT endpoints) ──
async function addRbaWeight() {
  const ruleEl = document.getElementById('rbaNewWeightRule');
  const valEl  = document.getElementById('rbaNewWeightVal');
  const ruleId = parseInt(ruleEl?.value, 10);
  const weight = parseInt(valEl?.value, 10);
  if (!Number.isInteger(ruleId) || ruleId <= 0) { alert('Enter a valid numeric Rule ID.'); return; }
  if (!Number.isInteger(weight) || weight < 0) { alert('Enter a valid weight (0 or more).'); return; }
  await _putRbaWeight(ruleId, weight);
  await loadRbaWeights(); _renderRbaV2();
}
async function saveRbaWeightFromRow(ruleId) {
  const input = document.querySelector(`.rba-w-input[data-rule-id="${ruleId}"]`);
  const weight = parseInt(input?.value, 10);
  if (!Number.isInteger(weight) || weight < 0) { alert('Enter a valid weight (0 or more).'); return; }
  const btn = document.querySelector(`.rba-w-save[data-rule-id="${ruleId}"]`);
  if (btn) { btn.textContent = 'Saving…'; btn.disabled = true; }
  await _putRbaWeight(ruleId, weight);
  if (btn) { btn.textContent = 'Saved ✓'; setTimeout(() => { btn.textContent = 'Save'; btn.disabled = false; }, 1400); }
}
async function _putRbaWeight(ruleId, weight) {
  try {
    const r = await fetch(`/api/rba/weights/${ruleId}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ risk_weight: weight, weight }),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
  } catch (e) { alert('Failed to save weight: ' + e.message); }
}
async function deleteRbaWeight(ruleId) {
  if (!confirm(`Remove the risk-weight override for rule #${ruleId}? It will revert to the level-derived default.`)) return;
  try {
    const r = await fetch(`/api/rba/weights/${ruleId}`, { method: 'DELETE' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
  } catch (e) { alert('Failed to remove weight: ' + e.message); return; }
  await loadRbaWeights(); _renderRbaV2();
}

function openRbaThresholds() {
  const modal = document.getElementById('rbaThresholdModal');
  const list  = document.getElementById('rbaThresholdList');
  if (!modal || !list) return;
  const entities = (window._rbaEntitiesCache || {}).entities || [];
  if (!entities.length) {
    list.innerHTML = `<div style="color:var(--fg-4);font-size:13px;padding:20px;text-align:center">No entities are being tracked yet. Thresholds become configurable once entities accumulate risk.</div>`;
  } else {
    list.innerHTML = entities.map(e => {
      const id = e.id || e.entity_id || '';
      const thr = e.threshold || 100;
      const name = (typeof _resolveEntity === 'function') ? _resolveEntity(id, e.type || e.entity_type || 'agent') : id;
      return `<div class="rba-thr-row">
        <span class="rba-thr-name" title="${escapeHtml(id)}">${escapeHtml(name)}</span>
        <input type="number" class="fld rba-thr-input" data-entity-id="${escapeHtml(id)}" value="${escapeHtml(String(thr))}" min="1" style="width:100px;height:28px">
        <button type="button" class="act-btn rba-thr-save" data-entity-id="${escapeHtml(id)}" onclick="saveRbaThreshold('${escapeHtml(id)}')">Save</button>
      </div>`;
    }).join('');
  }
  modal.classList.remove('hidden');
}
function closeRbaThresholds() { document.getElementById('rbaThresholdModal')?.classList.add('hidden'); }
async function saveRbaThreshold(entityId) {
  const input = document.querySelector(`.rba-thr-input[data-entity-id="${entityId}"]`);
  const threshold = parseInt(input?.value, 10);
  if (!Number.isInteger(threshold) || threshold < 1) { alert('Enter a valid threshold (1 or more).'); return; }
  const btn = document.querySelector(`.rba-thr-save[data-entity-id="${entityId}"]`);
  if (btn) { btn.textContent = 'Saving…'; btn.disabled = true; }
  try {
    const r = await fetch(`/api/rba/entities/${encodeURIComponent(entityId)}/threshold`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threshold }),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    if (btn) { btn.textContent = 'Saved ✓'; }
    // reflect locally so the entities table shows the new threshold on next render
    const ent = ((window._rbaEntitiesCache||{}).entities||[]).find(x => (x.id||x.entity_id) === entityId);
    if (ent) ent.threshold = threshold;
  } catch (e) {
    if (btn) { btn.textContent = 'Save'; btn.disabled = false; }
    alert('Failed to save threshold: ' + e.message); return;
  }
  setTimeout(() => { if (btn) { btn.textContent = 'Save'; btn.disabled = false; } }, 1400);
}

async function loadRbaEntities() {
  const res = await fetch('/api/rba/entities?limit=100').then(r => r.json()).catch(() => ({}));
  const entities = res.data || [];
  window._rbaEntitiesCache = window._rbaEntitiesCache || {};
  window._rbaEntitiesCache.entities = entities.length > 0 ? entities.map(e => ({
    id: e.entity_id, badge: (e.entity_id||'').slice(0,2).toUpperCase(), color: '#8A8C95',
    score: e.current_score, threshold: e.threshold, alerts: e.alert_count_7d,
    notables: e.notables_fired, last: fmtTs(e.last_event)
  })) : null;

  const tbody = document.getElementById('rbaEntitiesBody');
  if (!tbody) return;
  if (!entities.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:32px;color:var(--text-muted)">No risk data yet — alerts will accumulate risk scores automatically.</td></tr>';
    return;
  }

  tbody.innerHTML = entities.map(e => {
    const ratio = (e.current_score || 0) / (e.threshold || 100);
    const pct   = _riskIndex(e.current_score, e.threshold);
    const level = ratio >= 1 ? 'danger' : ratio >= .75 ? 'high' : ratio >= .5 ? 'medium' : 'ok';
    const badgeClass = ratio >= 1 ? 'critical' : ratio >= .75 ? 'high' : ratio >= .5 ? 'medium' : 'low';
    const bar   = `<div class="risk-bar-wrap">
      <div class="risk-bar-track"><div class="risk-bar-fill risk-bar-fill--${level}" style="width:${pct}%"></div></div>
      <span class="risk-bar-pct">${pct}%</span>
    </div>`;
    const rbaDisplayName = _resolveEntity(e.entity_id, e.entity_type);
    const notablesCls = e.notables_fired > 0 ? 'style="color:#ef4444;font-weight:600"' : 'style="color:var(--text-muted)"';
    return `<tr title="${escHtml(e.entity_id)}">
      <td style="font-weight:600;font-size:12px;font-family:var(--font-mono)">${escHtml(rbaDisplayName)}</td>
      <td><span class="risk-badge risk-badge--${badgeClass}" title="raw score: ${Number(e.current_score||0).toLocaleString()}">${_riskIndex(e.current_score, e.threshold)}</span></td>
      <td style="font-size:12px;color:var(--text-muted);font-family:var(--font-mono)">${e.threshold}</td>
      <td style="min-width:130px">${bar}</td>
      <td style="font-size:12px">${e.alert_count_7d || '—'}</td>
      <td ${notablesCls} style="font-size:12px">${e.notables_fired}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtTs(e.last_event)}</td>
    </tr>`;
  }).join('');
}

async function loadRbaNotables() {
  const res = await fetch('/api/rba/notables?limit=100').then(r => r.json()).catch(() => ({}));
  const notables = res.data || [];
  window._rbaEntitiesCache = window._rbaEntitiesCache || {};
  window._rbaEntitiesCache.notables = notables.length > 0 ? notables.map(n => ({
    id: n.id ? `RBA-${n.id}` : '—', entity: n.entity_id, score: n.risk_score,
    sev: (n.risk_score||0) >= 100 ? 'crit' : 'high',
    summary: n.description||'Crossed threshold',
    triggered: fmtTs(n.created_at)
  })) : null;

  const tbody = document.getElementById('rbaNotablesBody');
  if (!tbody) return;

  // KPI: notable count
  const kpiNot = document.getElementById('rbaKpiNotables');
  if (kpiNot) kpiNot.textContent = notables.length || '0';

  if (!notables.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--text-muted)">No Risk Notables yet — they fire when accumulated risk score exceeds threshold.</td></tr>';
    return;
  }

  tbody.innerHTML = notables.map(n => `
    <tr title="${escHtml(n.entity_id)}">
      <td style="font-size:12px;color:var(--text-muted);font-family:var(--font-mono)">#${n.id}</td>
      <td style="font-weight:600;font-size:12px;font-family:var(--font-mono)">${escHtml(_resolveEntity(n.entity_id, n.entity_type))}</td>
      <td><span class="risk-badge risk-badge--critical" title="raw score: ${Number(n.risk_score||0).toLocaleString()}">${_riskIndex(n.risk_score||0, 100)}</span></td>
      <td style="font-size:12px;color:var(--text-muted);max-width:300px">${escHtml(n.description)}</td>
      <td style="font-size:12px">${n.case_id ? `<a href="#" onclick="event.preventDefault()" style="color:var(--accent)">Case #${n.case_id}</a>` : '<span style="color:var(--text-muted)">—</span>'}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtTs(n.created_at)}</td>
    </tr>`).join('');
}

async function loadRbaWeights() {
  const res = await fetch('/api/rba/weights').then(r => r.json()).catch(() => ({}));
  const weights = res.data || [];
  window._rbaEntitiesCache = window._rbaEntitiesCache || {};
  window._rbaEntitiesCache.weights = (weights.length > 0 ? weights.map(w => ({
    rule_id: w.rule_id, rule: w.description || `Rule #${w.rule_id}`, weight: w.risk_weight||0, updated: w.updated_at
  })) : []);
  const tbody = document.getElementById('rbaWeightsBody');
  if (!tbody) return;

  if (!weights.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--text-muted)">No custom weights. All rules use level-derived defaults.</td></tr>';
    return;
  }

  tbody.innerHTML = weights.map(w => `
    <tr>
      <td style="font-size:12px;font-family:var(--font-mono);color:var(--text-muted)">Rule #${w.rule_id}</td>
      <td><span class="risk-badge risk-badge--low" style="font-size:13px">${w.risk_weight} pts</span></td>
      <td style="font-size:12px;color:var(--text-muted)">${escHtml(w.description||'—')}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtTs(w.updated_at)}</td>
    </tr>`).join('');
}

function switchRbaTab(tab) {
  const panes = { entities: 'rbaPaneEntities', notables: 'rbaPaneNotables', weights: 'rbaPaneWeights' };
  const tabs  = { entities: 'rbaTabEntities',  notables: 'rbaTabNotables',  weights: 'rbaTabWeights' };
  Object.entries(panes).forEach(([key, id]) => {
    const el = document.getElementById(id);
    if (el) el.style.display = key === tab ? '' : 'none';
  });
  Object.entries(tabs).forEach(([key, id]) => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('active', key === tab);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="rba"]').forEach(el => {
    el.addEventListener('click', () => { loadRbaPage(); switchRbaTab('entities'); });
  });
});

// ── UEBA ─────────────────────────────────────────────────────────────────────

function switchUebaV2Tab(tabKey) {
  const panes = { leaderboard:'uebaPaneRisk', anomalies:'uebaPaneAnomalies', baselines:'uebaPaneBaselines' };
  const tabs  = { leaderboard:'uebaTabRisk',  anomalies:'uebaTabAnomalies',  baselines:'uebaTabBaselines'  };
  Object.entries(panes).forEach(([k,id]) => { const el=document.getElementById(id); if(el) el.style.display=k===tabKey?'':'none'; });
  Object.entries(tabs).forEach(([k,id])  => { const el=document.getElementById(id); if(el) el.classList.toggle('active',k===tabKey); });
}

async function loadUebaPage() {
  await _ensureEntityAgentMap();
  await Promise.all([loadUebaRiskScores(), loadUebaAnomalies()]);
  _renderUebaV2();
}

function _renderUebaV2() {
  const scoresRes = window._uebaScoresCache || [];
  const anomRes   = window._uebaAnomaliesCache || [];
  const entities  = scoresRes;
  const anomalies = anomRes;

  // KPIs
  const highRisk = entities.filter(e => (e.score||e.risk_score||0) >= 70).length;
  const setK = (vid,val,tid,tag,kind,sid,sub) => {
    const v=document.getElementById(vid); if(v) v.textContent=val;
    const t=document.getElementById(tid); if(t){t.textContent=tag;t.className=`kpi-tag ${kind}`;}
    const s=document.getElementById(sid); if(s) s.textContent=sub;
  };
  setK('uebaKpiMonitored', String(entities.length), 'uebaKpiMonTag', entities.length>0?'+'+entities.length:'OK', entities.length>0?'up':'ok', 'uebaEntitiesMeta', 'identities · hosts · service accts');
  setK('kpiUebaAnomalies', String(anomalies.length), 'uebaKpiAnomTag', anomalies.length>0?'+'+anomalies.length:'CLEAR', anomalies.length>0?'up':'ok', 'uebaKpiAnomSub', anomalies.length>0?anomalies.length+' anomalies detected':'no anomalies');
  setK('uebaKpiHighRisk', String(highRisk), 'uebaKpiHRTag', highRisk>0?'ATTN':'CLEAR', highRisk>0?'crit':'ok', null, 'risk score ≥ 70');
  // Baselines profiled = entities that have produced activity (a real, derived metric)
  const profiled = entities.filter(e => (e.alerts||e.alert_count_7d||0) > 0).length;
  const basePct = entities.length ? Math.round(100*profiled/entities.length) : 0;
  setK('uebaKpiBaselines', basePct+'%', 'uebaKpiBaseTag', entities.length ? 'OK' : 'IDLE', entities.length ? 'ok' : 'ok', 'uebaKpiBaseSub', `${profiled}/${entities.length} entities with activity`);
  const metaEl=document.getElementById('uebaEntitiesMeta'); if(metaEl) metaEl.textContent=entities.length;
  // Tab counts
  const rc=document.getElementById('uebaTabRiskCount'); if(rc) rc.textContent=entities.length;
  const ac=document.getElementById('uebaTabAnomCount'); if(ac) ac.textContent=anomalies.length;
  const bc=document.getElementById('uebaTabBaseCount'); if(bc) bc.textContent=entities.length;

  // Leaderboard pane
  const rPane = document.getElementById('uebaPaneRisk');
  if (rPane) {
    rPane.innerHTML = `<div class="tbl">
      <div class="tbl-h" style="grid-template-columns:40px 24px 1fr 100px 90px 70px 90px 110px 70px">
        <span>#</span><span></span><span>Entity</span><span>Type</span><span>Risk score</span><span>Alerts 7d</span><span>Critical</span><span>Last alert</span><span></span>
      </div>
      ${entities.map(e => {
        const s = e.score||e.risk_score||0;
        const sCol = s>=70?'var(--crit)':s>=40?'var(--high)':s>=10?'var(--med)':'var(--ok)';
        const badge = e.color ? `<span class="entbadge" style="background:${e.color}">${escapeHtml(e.badge||'?')}</span>` : `<span class="entbadge idle">·</span>`;
        return `<div class="tbl-r" style="grid-template-columns:40px 24px 1fr 100px 90px 70px 90px 110px 70px">
          <span class="row-num">${e.rank||''}</span>
          <span>${badge}</span>
          <span class="tbl-pri" style="font-size:12px">${escapeHtml(_resolveEntity(e.id||e.entity_id||'', e.type||e.entity_type||'agent'))}</span>
          <span class="tbl-mono" style="color:var(--fg-3)">${escapeHtml(e.type||e.entity_type||'—')}</span>
          <span style="font-family:var(--font-mono);font-size:13px;font-weight:500;color:${sCol}">${s}</span>
          <span class="tbl-mono">${e.alerts||e.alert_count_7d||0}</span>
          <span class="tbl-mono" style="color:${(e.crit||e.critical_count_7d||0)>0?'var(--crit)':'var(--fg-4)'}">${e.crit||e.critical_count_7d||0}</span>
          <span class="tbl-time">${escapeHtml(e.last||fmtTs(e.last_alert)||'—')}</span>
          <span><a href="#" class="tbl-link" onclick="event.preventDefault();loadUebaEntity('${escapeHtml(e.id||e.entity_id||'')}')">Detail →</a></span>
        </div>`;
      }).join('')}
    </div>`;
  }

  // Anomaly types pane
  const aPane = document.getElementById('uebaPaneAnomalies');
  if (aPane) {
    if (!anomalies.length) {
      aPane.innerHTML = `<div class="chart-empty"><div class="chart-empty-icon info"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 12a9 9 0 1 1-9-9c4.5 0 7 3 7 7s-2.5 5-5 5-3-1.5-3-3"/></svg></div><div class="chart-empty-msg">No anomalies detected</div><div class="chart-empty-sub">Anomaly types will appear here as the platform builds baselines</div></div>`;
    } else {
      aPane.innerHTML = `<div class="rows">${anomalies.map((a,i) => `
        <div class="row">
          <span class="row-num">${i+1}</span>
          <div class="row-main"><span class="row-pri mono">${escapeHtml(a.name||a.anomaly_type||'—')}</span><span class="row-sec">anomaly model</span></div>
          <span class="pill ${a.sev||a.severity||'med'}">${a.sev||a.severity||'med'}</span>
          <span class="row-meta">${a.count||a.score||0}</span>
        </div>`).join('')}</div>`;
    }
  }

  // Baselines pane — honest, derived from real entity activity (no fabricated numbers)
  const bPane = document.getElementById('uebaPaneBaselines');
  if (bPane) {
    if (!entities.length) {
      bPane.innerHTML = `<div class="chart-empty" style="padding:24px"><div class="chart-empty-icon info"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 3v18h18"/><path d="M7 14l4-4 3 3 5-6"/></svg></div><div class="chart-empty-msg">No baselines yet</div><div class="chart-empty-sub">Run analysis to build behavioural baselines as entities accumulate activity</div></div>`;
    } else {
      bPane.innerHTML = `<div class="tbl">
        <div class="tbl-h" style="grid-template-columns:24px 1fr 110px 100px 90px 130px">
          <span></span><span>Entity</span><span>Type</span><span>Status</span><span>Alerts 7d</span><span>Last activity</span>
        </div>
        ${entities.map(e => {
          const act = e.alerts||e.alert_count_7d||0;
          const established = act > 0;
          const badge = e.color ? `<span class="entbadge" style="background:${e.color}">${escapeHtml(e.badge||'?')}</span>` : `<span class="entbadge idle">·</span>`;
          return `<div class="tbl-r" style="grid-template-columns:24px 1fr 110px 100px 90px 130px">
            <span>${badge}</span>
            <span class="tbl-pri" style="font-size:12px">${escapeHtml(_resolveEntity(e.id||e.entity_id||'', e.type||e.entity_type||'agent'))}</span>
            <span class="tbl-mono" style="color:var(--fg-3)">${escapeHtml(e.type||e.entity_type||'—')}</span>
            <span><span class="pill ${established?'ok':'med'}" style="font-size:10px">${established?'Established':'Learning'}</span></span>
            <span class="tbl-mono">${act}</span>
            <span class="tbl-time">${escapeHtml(e.last||fmtTs(e.last_alert)||'—')}</span>
          </div>`;
        }).join('')}
      </div>`;
    }
  }
}

async function loadUebaRiskScores() {
  const res = await fetch('/api/ueba/risk-scores?limit=50').then(r => r.json()).catch(() => ({}));
  const scores = res.data || [];
  window._uebaScoresCache = scores.map(s => ({
    rank: 0, id: s.entity_id, type: s.entity_type, score: s.risk_score,
    alerts: s.alert_count_7d, crit: s.critical_count_7d, anom: s.anomaly_count_7d,
    last: fmtTs(s.last_alert), badge: (s.entity_id||'').slice(0,2).toUpperCase(), color: null,
  })).map((e,i) => ({ ...e, rank: i+1 }));

  const tbody  = document.getElementById('uebaRiskTableBody');
  if (!tbody) return;

  if (!scores.length) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:30px;color:var(--text-muted)">
      No risk data yet. Click <strong>⟳ Run Analysis</strong> to compute baselines.
    </td></tr>`;
    return;
  }

  tbody.innerHTML = scores.map((s, i) => {
    const rl  = (s.risk_level || 'low').toLowerCase();
    const rank = i < 3 ? `<span class="rank-badge rank-badge--${i+1}">${i+1}</span>` : `<span class="rank-badge">${i+1}</span>`;
    const displayName = _resolveEntity(s.entity_id, s.entity_type);
    const critStyle = s.critical_count_7d > 0 ? 'color:#ef4444;font-weight:600' : 'color:var(--text-muted)';
    const anomStyle = s.anomaly_count_7d  > 0 ? 'color:#f59e0b;font-weight:600' : 'color:var(--text-muted)';
    return `<tr onclick="loadUebaEntity('${escHtml(s.entity_id)}')" style="cursor:pointer" title="${escHtml(s.entity_id)}">
      <td>${rank}</td>
      <td style="font-weight:600;font-size:12px;font-family:var(--font-mono)">${escHtml(displayName)}</td>
      <td><span class="type-tag">${escHtml(s.entity_type)}</span></td>
      <td>
        <div style="display:flex;align-items:center;gap:8px">
          <span class="risk-badge risk-badge--${rl}">${s.risk_score}</span>
          <span class="sev-pill sev-pill--${rl}">${rl}</span>
        </div>
      </td>
      <td style="font-size:12px">${s.alert_count_7d}</td>
      <td style="font-size:12px;${critStyle}">${s.critical_count_7d}</td>
      <td style="font-size:12px;${anomStyle}">${s.anomaly_count_7d}</td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtTs(s.last_alert)}</td>
      <td>
        <button onclick="event.stopPropagation();loadUebaEntity('${escHtml(s.entity_id)}')" class="act-btn">Detail</button>
      </td>
    </tr>`;
  }).join('');
}

async function loadUebaAnomalies() {
  const res = await fetch('/api/ueba/anomalies?limit=100').then(r => r.json()).catch(() => ({}));
  const anomalies = res.data || [];
  window._uebaAnomaliesCache = anomalies.map(a => ({
    name: a.anomaly_type, count: a.score||0, sev: (a.severity||'med').toLowerCase()
  }));
  const tbody = document.getElementById('uebaAnomalyTableBody');
  if (!tbody) return;

  if (!anomalies.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:30px;color:var(--text-muted)">No anomalies detected yet.</td></tr>';
    return;
  }

  const typeLabel = { alert_spike: 'Alert Spike', critical_alert_burst: 'Critical Burst', off_hours: 'Off-Hours' };
  tbody.innerHTML = anomalies.map(a => {
    const sev = (a.severity || 'low').toLowerCase();
    return `<tr>
      <td style="font-weight:600;font-size:12px;font-family:var(--font-mono)">${escHtml(a.entity_id)}</td>
      <td style="font-size:12px"><span class="type-tag">${typeLabel[a.anomaly_type] || escHtml(a.anomaly_type)}</span></td>
      <td style="font-size:12px;color:var(--text-muted);max-width:280px">${escHtml(a.description)}</td>
      <td><span class="sev-pill sev-pill--${sev}">${sev}</span></td>
      <td style="font-size:12px;font-weight:600"><span class="risk-badge risk-badge--${sev}" style="font-size:12px;min-width:32px">${a.score}</span></td>
      <td style="font-size:12px;color:var(--text-muted)">${fmtTs(a.detected_at)}</td>
    </tr>`;
  }).join('');
}

async function loadUebaEntity(entityId) {
  const modal = document.getElementById('uebaEntityModal');
  if (!modal) return;
  modal.classList.add('open');

  document.getElementById('uebaModalEntityId').textContent = entityId;
  document.getElementById('uebaModalScore').textContent    = '…';
  document.getElementById('uebaModalAlerts').textContent   = '…';
  document.getElementById('uebaModalCritical').textContent = '…';
  document.getElementById('uebaModalAnomalies').innerHTML  = '<div style="color:var(--text-muted);font-size:13px;padding:8px 0">Loading…</div>';

  const res = await fetch(`/api/ueba/entity/${encodeURIComponent(entityId)}`).then(r => r.json()).catch(() => ({}));
  const risk      = res.risk;
  const anomalies = res.anomalies || [];

  if (risk) {
    const rl = (risk.risk_level || 'low').toLowerCase();
    document.getElementById('uebaModalScore').textContent    = risk.risk_score;
    document.getElementById('uebaModalScore').className      = 'entity-modal-kpi-val';
    document.getElementById('uebaModalScore').style.color    = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' }[rl] || 'var(--text)';
    document.getElementById('uebaModalAlerts').textContent   = risk.alert_count_7d;
    document.getElementById('uebaModalCritical').textContent = risk.critical_count_7d;
  } else {
    document.getElementById('uebaModalScore').textContent  = '—';
    document.getElementById('uebaModalAlerts').textContent = '—';
    document.getElementById('uebaModalCritical').textContent = '—';
  }

  const typeLabel = { alert_spike:'Alert Spike', critical_alert_burst:'Critical Burst', off_hours:'Off-Hours' };
  document.getElementById('uebaModalAnomalies').innerHTML = anomalies.length
    ? anomalies.map(a => {
        const sev = (a.severity||'low').toLowerCase();
        return `<div class="entity-anomaly-item sev-${sev}">
          <div class="entity-anomaly-type">${typeLabel[a.anomaly_type] || escHtml(a.anomaly_type)}</div>
          <div class="entity-anomaly-desc">${escHtml(a.description)}</div>
        </div>`;
      }).join('')
    : '<div style="color:var(--text-muted);font-size:13px;padding:8px 0">No anomalies detected.</div>';
}

function closeUebaEntityModal() {
  const modal = document.getElementById('uebaEntityModal');
  if (modal) modal.classList.remove('open');
}

function switchUebaTab(tab) {
  const isRisk = tab === 'risk';
  document.getElementById('uebaPaneRisk').style.display      = isRisk ? '' : 'none';
  document.getElementById('uebaPaneAnomalies').style.display = isRisk ? 'none' : '';
  document.getElementById('uebaTabRisk').classList.toggle('tab-btn--active',      isRisk);
  document.getElementById('uebaTabAnomalies').classList.toggle('tab-btn--active', !isRisk);
}

async function triggerUebaAnalysis() {
  const btn  = document.getElementById('uebaRunBtn');
  const span = btn?.querySelector('span');
  if (span) span.textContent = 'Running…';
  if (btn) btn.disabled = true;
  const res = await fetch('/api/ueba/analyze', {method:'POST'}).then(r => r.json()).catch(() => ({}));
  if (span) span.textContent = 'Run Analysis';
  if (btn) btn.disabled = false;
  if (res?.message) {
    setTimeout(() => loadUebaPage(), 3000);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="ueba"]').forEach(el => {
    el.addEventListener('click', () => { loadUebaPage(); switchUebaTab('risk'); });
  });
  // Close UEBA entity modal on backdrop click
  const uebaModal = document.getElementById('uebaEntityModal');
  if (uebaModal) {
    uebaModal.addEventListener('click', e => { if (e.target === uebaModal) closeUebaEntityModal(); });
  }
  // Close on Escape
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeUebaEntityModal();
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

  const idW = 'grid-template-columns:130px 140px 120px 120px 1fr 120px 90px 90px 44px';
  if (!users.length) {
    tbody.innerHTML = `<div class="sigil-block"><div class="sigil-text"><h4>${search ? 'No matching users' : 'No users found'}</h4><p>${search ? 'Try a different search term' : 'Configure LDAP or add users manually'}</p></div></div>`;
    return;
  }

  tbody.innerHTML = users.map(u => `
    <div class="tbl-r" style="${idW}">
      <span class="tbl-pri">${escHtml(u.sam_account)}</span>
      <span class="tbl-mono">${escHtml(u.display_name||'—')}</span>
      <span class="tbl-muted">${escHtml(u.department||'—')}</span>
      <span class="tbl-muted">${escHtml(u.title||'—')}</span>
      <span>${u.email ? `<a href="mailto:${escHtml(u.email)}" class="tbl-link">${escHtml(u.email)}</a>` : '<span class="disc-empty">—</span>'}</span>
      <span style="font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml((u.groups||[]).join(', '))}">
        ${(u.groups||[]).slice(0,2).map(g => `<span class="disc-group-tag">${escHtml(g)}</span>`).join(' ')}${u.groups?.length > 2 ? `<span class="tbl-muted"> +${u.groups.length-2}</span>` : ''}
      </span>
      <span><span class="pill ${u.enabled ? 'ok' : ''}" style="${u.enabled ? '' : 'color:var(--fg-4)'}">${u.enabled ? 'ON':'OFF'}</span></span>
      <span class="tbl-muted">${u.source}</span>
      <span><button onclick="deleteIdentityUser('${escHtml(u.sam_account)}')" class="btn-disc-detail" style="color:var(--crit)" title="Delete">✕</button></span>
    </div>`).join('');
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
let _rvAllFiles     = [];

function _renderRvFileList(files) {
  const el = document.getElementById('rvFileList');
  if (!el) return;
  if (!files.length) {
    el.innerHTML = '<div style="padding:16px;color:var(--text-muted);font-size:12px;font-style:italic">No rules match the filter.</div>';
    return;
  }
  el.innerHTML = files.map(f => {
    const isActive = _rvSelectedFile === f.rule_file;
    return `<div class="studio-file-item${isActive ? ' active' : ''}" onclick="selectRvFile('${escHtml(f.rule_file)}')">
      <div class="studio-file-name">${escHtml(f.rule_file)}</div>
      <div class="studio-file-meta">v${f.latest_version} &middot; ${f.version_count} version${f.version_count===1?'':'s'} &middot; ${escHtml(f.last_author||'system')}</div>
    </div>`;
  }).join('');
}

async function loadRuleVersionsPage() {
  const res   = await fetch('/api/rule-versions').then(r => r.json()).catch(() => ({}));
  const files = res.data || [];
  _rvAllFiles = files;

  const countEl = document.getElementById('rvFileCount');
  if (countEl) countEl.textContent = files.length ? `${files.length} files` : '';

  const el = document.getElementById('rvFileList');
  if (!el) return;

  if (!files.length) {
    el.innerHTML = '<div style="padding:16px;color:var(--text-muted);font-size:12px;font-style:italic">No versioned rules found.<br>WatchTower auto-imports rules on startup.</div>';
    return;
  }
  _renderRvFileList(files);
}

function filterRvFiles() {
  const q = (document.getElementById('rvSearchInput')?.value || '').toLowerCase().trim();
  const filtered = q ? _rvAllFiles.filter(f => f.rule_file.toLowerCase().includes(q)) : _rvAllFiles;
  _renderRvFileList(filtered);
}

async function selectRvFile(file) {
  _rvSelectedFile = file;
  const label = document.getElementById('rvSelectedFile');
  if (label) { label.textContent = file; label.classList.add('has-file'); }
  document.getElementById('rvActionBar').style.display = 'flex';
  // highlight active file in sidebar
  document.querySelectorAll('.studio-file-item').forEach(el => {
    el.classList.toggle('active', el.querySelector('.studio-file-name')?.textContent === file);
  });
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
            <td>
              <span class="version-badge">v${v.version}${i===0 ? ' <span class="latest-chip">LATEST</span>' : ''}</span>
            </td>
            <td style="font-size:12px;color:var(--text-muted)">${escHtml(v.commit_msg||'—')}</td>
            <td style="font-size:12px;color:var(--text-muted)">${escHtml(v.author||'—')}</td>
            <td style="font-size:12px;color:var(--text-muted)">${fmtTs(v.created_at)}</td>
            <td style="display:flex;gap:5px;align-items:center">
              <button onclick="rvViewContent('${escHtml(file)}',${v.version})" class="act-btn">View</button>
              ${i > 0 ? `<button onclick="rvRollback('${escHtml(file)}',${v.version})" class="act-btn" style="color:#f59e0b;border-color:rgba(245,158,11,0.3)">Rollback</button>` : ''}
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

  const tktW = 'grid-template-columns:110px 1fr 90px 100px 80px 80px 120px 130px 60px';
  if (!tickets.length) {
    tbody.innerHTML = `<div class="sigil-block"><div class="sigil-text"><h4>No tickets created yet</h4><p>Create tickets from alerts or cases to track them in Jira or ServiceNow</p></div></div>`;
    return;
  }

  const priorityColor = { critical:'var(--crit)', high:'var(--high)', medium:'var(--med)', low:'var(--fg-4)' };

  tbody.innerHTML = tickets.map(t => `
    <div class="tbl-r" style="${tktW}">
      <span>${t.ticket_url
        ? `<a href="${escHtml(t.ticket_url)}" target="_blank" style="color:var(--accent);font-weight:600;font-size:11px;font-family:var(--font-mono)">${escHtml(t.ticket_id)}</a>`
        : `<span class="tbl-mono">${escHtml(t.ticket_id)}</span>`}</span>
      <span class="tbl-pri">${escHtml(t.summary)}</span>
      <span style="color:${priorityColor[t.priority]||'var(--fg-4)'};font-weight:600;font-size:11px;text-transform:uppercase">${t.priority}</span>
      <span class="tbl-mono">${t.provider}</span>
      <span class="tbl-muted">${t.alert_id ? '#'+t.alert_id : '—'}</span>
      <span class="tbl-muted">${t.case_id  ? '#'+t.case_id  : '—'}</span>
      <span class="tbl-mono">${escHtml(t.created_by||'—')}</span>
      <span class="tbl-time">${t.created_at ? new Date(t.created_at).toLocaleString() : '—'}</span>
      <span>${t.ticket_url ? `<a href="${escHtml(t.ticket_url)}" target="_blank" class="tbl-link">Open ↗</a>` : ''}</span>
    </div>`).join('');
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
  quarantine_file: { label: 'Quarantine File',      params: { path: '{{file_path}}' } },
  force_logoff:    { label: 'Force Logoff',          params: { username: '{{username}}' } },
  create_case:     { label: 'Create Case',          params: { title: 'Auto: {{title}}', priority: 'high' } },
  create_ticket:   { label: 'Create Ticket',        params: { dashboard_url: 'http://dashboard:5050', summary: 'Alert L{{level}}: {{title}}', priority: 'high' } },
  notify_slack:    { label: 'Notify Slack',         params: { webhook_url: '', message: '🚨 [{{level}}] {{title}} — Agent: {{agent_id}}' } },
  notify_email:    { label: 'Send Email',           params: { to: '', subject: '[Alert] {{title}}' } },
  add_to_watchlist:{ label: 'Add to Watchlist',    params: { value: '{{src_ip}}', list: 'blocked_ips' } },
};

let _pbActions = [];

// Forensic evidence collection.
let _fxAgent = null, _fxHost = null;
function openForensics(agentId, hostname) {
  _fxAgent = agentId; _fxHost = hostname || agentId;
  const t = document.getElementById('fxTarget');
  if (t) t.textContent = _fxHost;
  const m = document.getElementById('forensicsModal');
  if (m) m.style.display = 'flex';
  _loadArtifacts();
}
function closeForensics() {
  const m = document.getElementById('forensicsModal');
  if (m) m.style.display = 'none';
}
async function collectEvidence() {
  if (!_fxAgent) return;
  if (!confirm(`Collect a forensic snapshot from ${_fxHost}?\n\nGathers process list, network connections, autoruns, scheduled tasks, and recent logs — zips them and uploads to the manager.`)) return;
  try {
    const r = await fetch('/api/active-response/collect', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_id: _fxAgent })
    });
    const d = await r.json().catch(() => ({}));
    alert(r.ok && d.ok ? `Collection requested from ${_fxHost}. The bundle appears below once uploaded — Refresh in ~30s.` : `Could not request collection: ${d.error || r.status}`);
  } catch (e) { alert('Could not request collection: ' + e); }
}
async function _loadArtifacts() {
  const c = document.getElementById('fxList');
  if (!c || !_fxAgent) return;
  c.innerHTML = '<div style="color:var(--text-muted);font-size:12px">Loading…</div>';
  try {
    const res = await fetch(`/api/artifacts?agent_id=${encodeURIComponent(_fxAgent)}&limit=50`).then(r => r.json());
    const items = (res && res.data) || [];
    if (!items.length) { c.innerHTML = '<div style="color:var(--text-muted);font-size:12px">No artifacts yet — click "Collect new evidence".</div>'; return; }
    c.innerHTML = items.map(a => {
      const kb = Math.max(1, Math.round((a.size_bytes || 0) / 1024));
      const when = a.created_at ? new Date(a.created_at).toLocaleString() : '';
      return `<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px">
        <span style="font-family:var(--font-mono);font-size:11.5px">${escapeHtml(a.filename || ('#' + a.id))}<span style="color:var(--text-muted)"> · ${kb} KB · ${escapeHtml(when)}</span></span>
        <a href="/api/artifacts/${encodeURIComponent(a.id)}/download" class="act-btn" style="text-decoration:none">Download</a>
      </div>`;
    }).join('');
  } catch (e) { c.innerHTML = '<div style="color:var(--crit);font-size:12px">Error loading artifacts.</div>'; }
}

// Host isolation — quarantine a compromised endpoint (keeps the manager channel
// so it can be released remotely). Auto-releases after the agent's block TTL.
async function isolateAgent(agentId, hostname) {
  const who = hostname || agentId;
  if (!confirm(`Isolate ${who}?\n\nThis network-quarantines the host — all traffic is blocked except the WatchTower channel. It auto-releases after the configured TTL, or use the Release button.`)) return;
  try {
    const r = await fetch('/api/active-response/isolate', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_id: agentId })
    });
    const d = await r.json().catch(() => ({}));
    alert(r.ok && d.ok ? `Isolation command sent to ${who}.` : `Could not isolate ${who}: ${d.error || r.status}`);
  } catch (e) { alert('Could not isolate: ' + e); }
}

async function releaseAgent(agentId, hostname) {
  const who = hostname || agentId;
  if (!confirm(`Release isolation on ${who}?`)) return;
  try {
    const r = await fetch('/api/active-response/isolate', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_id: agentId, release: true })
    });
    const d = await r.json().catch(() => ({}));
    alert(r.ok && d.ok ? `Release command sent to ${who}.` : `Could not release ${who}: ${d.error || r.status}`);
  } catch (e) { alert('Could not release: ' + e); }
}

// Application control (Windows AppLocker) — pre-execution prevention.
let _appCtlAgent = null, _appCtlHost = null;
function openAppControl(agentId, hostname) {
  _appCtlAgent = agentId; _appCtlHost = hostname || agentId;
  const t = document.getElementById('appControlTarget');
  if (t) t.textContent = _appCtlHost;
  const m = document.getElementById('appControlModal');
  if (m) m.style.display = 'flex';
}
function closeAppControl() {
  const m = document.getElementById('appControlModal');
  if (m) m.style.display = 'none';
}
async function applyAppControl(mode) {
  if (!_appCtlAgent) return;
  const who = _appCtlHost;
  const warn = mode === 'enforce'
    ? `ENFORCE application control on ${who}?\n\nWindows will BLOCK any executable or script run from user-writable folders (Downloads, %TEMP%, %APPDATA%). Always test in Audit first. Enforcement needs Windows Enterprise/Education/Server.`
    : mode === 'clear'
    ? `Clear application control on ${who}? This removes the AppLocker policy.`
    : `Apply AUDIT application control on ${who}?\n\nLog-only — nothing is blocked. Review the AppLocker events it generates, then switch to Enforce.`;
  if (!confirm(warn)) return;
  try {
    const r = await fetch('/api/active-response/app-control', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_id: _appCtlAgent, mode })
    });
    const d = await r.json().catch(() => ({}));
    alert(r.ok && d.ok ? `Application control (${mode}) sent to ${who}.` : `Could not apply app-control: ${d.error || r.status}`);
  } catch (e) { alert('Could not apply app-control: ' + e); }
  closeAppControl();
}

// ── Process Tree ────────────────────────────────────────────────────────────
let _ptHostsLoaded = false;
let _ptNodes = [];
async function _ptEnsureHosts() {
  const sel = document.getElementById('ptHost');
  if (!sel || _ptHostsLoaded) return;
  await _ensureEntityAgentMap();
  try {
    const res = await fetch('/api/agents?limit=500').then(r => r.json()).catch(() => ({}));
    const d = res && res.data;
    const list = Array.isArray(res) ? res
      : Array.isArray(res.agents) ? res.agents
      : (d && Array.isArray(d.affected_items)) ? d.affected_items
      : Array.isArray(d) ? d : [];
    sel.innerHTML = list.map(a => {
      const id = a.id || a.agent_id || '';
      const name = a.hostname || a.name || id;
      return `<option value="${escapeHtml(id)}">${escapeHtml(name)}</option>`;
    }).join('') || '<option value="">No agents</option>';
    // Attach change/filter listeners once.
    sel.addEventListener('change', loadProcessTreePage);
    document.getElementById('ptWindow')?.addEventListener('change', loadProcessTreePage);
    document.getElementById('ptSearch')?.addEventListener('input', () => _ptRender(_ptNodes));
    _ptHostsLoaded = true;
  } catch (e) {}
}

async function loadProcessTreePage() {
  await _ptEnsureHosts();
  const agentId = document.getElementById('ptHost')?.value || '';
  const hours = document.getElementById('ptWindow')?.value || '24';
  const meta = document.getElementById('ptMeta');
  const tree = document.getElementById('ptTree');
  if (!agentId) { if (tree) tree.innerHTML = ''; if (meta) meta.textContent = 'No host selected.'; return; }
  if (meta) meta.textContent = 'Loading…';
  let data;
  try {
    data = await fetch(`/api/process-tree?agent_id=${encodeURIComponent(agentId)}&hours=${encodeURIComponent(hours)}`).then(r => r.json());
  } catch (e) { if (meta) meta.textContent = 'Error loading process tree.'; return; }
  _ptNodes = (data && data.nodes) || [];
  if (!_ptNodes.length) {
    if (tree) tree.innerHTML = '';
    if (meta) meta.textContent = 'No process-creation events for this host in the window. (Events are emitted as new processes start — they accumulate on a busy host.)';
    return;
  }
  const who = (typeof _resolveEntity === 'function') ? _resolveEntity(agentId, 'agent') : agentId;
  if (meta) meta.textContent = `${_ptNodes.length} process events · ${who}`;
  _ptRender(_ptNodes);
}

function _ptRender(nodes) {
  const tree = document.getElementById('ptTree');
  if (!tree) return;
  const filter = (document.getElementById('ptSearch')?.value || '').toLowerCase();
  const byPid = {};
  nodes.forEach(n => { if (n.pid != null) byPid[n.pid] = n; });
  const children = {};
  nodes.forEach(n => { (children[n.ppid] = children[n.ppid] || []).push(n); });
  // Roots: ppid not present as a pid (or 0/null).
  const rootSeen = new Set(), roots = [];
  nodes.forEach(n => {
    if ((!(n.ppid in byPid) || n.ppid === 0 || n.ppid == null) && !rootSeen.has(n.pid)) {
      rootSeen.add(n.pid); roots.push(n);
    }
  });
  const suspicious = /powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|\bnet1?\.exe|wmic|bitsadmin|certutil/i;
  const seen = new Set(), lines = [];
  function walk(node, depth) {
    const key = node.pid + ':' + node.timestamp;
    if (depth > 40 || seen.has(key)) return;
    seen.add(key);
    const name = node.name || '?';
    const cmd = (node.cmdline || '').slice(0, 140);
    const sus = suspicious.test(name) || suspicious.test(cmd);
    if (!filter || (name + ' ' + cmd).toLowerCase().includes(filter)) {
      const indent = '&nbsp;'.repeat(depth * 4);
      const branch = depth > 0 ? '└─ ' : '';
      lines.push(`<div style="white-space:nowrap">${indent}<span style="color:var(--text-muted)">${branch}</span>` +
        `<span style="color:${sus ? '#f25555' : 'var(--accent)'};font-weight:600">${escapeHtml(name)}</span>` +
        `<span style="color:var(--text-muted)"> [${escapeHtml(String(node.pid))}]</span>` +
        (node.user ? `<span style="color:var(--text-muted)"> · ${escapeHtml(node.user)}</span>` : '') +
        (cmd ? `<span style="color:var(--fg-3)"> · ${escapeHtml(cmd)}</span>` : '') + `</div>`);
    }
    (children[node.pid] || []).filter(k => k.pid !== node.pid).forEach(k => walk(k, depth + 1));
  }
  roots.forEach(r => walk(r, 0));
  tree.innerHTML = lines.join('') || '<div style="color:var(--text-muted)">No processes match the filter.</div>';
}

async function loadPlaybooks() {
  const res = await fetch('/api/playbooks?all=true').then(r => r.json()).catch(() => ({}));
  const pbs = res.data || [];
  const tbody = document.getElementById('playbooksTableBody');
  if (!tbody) return;

  const pbW = 'grid-template-columns:50px 1fr 120px 80px 70px 90px 80px';
  if (!pbs.length) {
    tbody.innerHTML = `<div class="sigil-block"><div class="sigil-text"><h4>No playbooks yet</h4><p>Click <strong>New Playbook</strong> to create automated response workflows</p></div></div>`;
    return;
  }

  tbody.innerHTML = pbs.map(pb => `
    <div class="tbl-r" style="${pbW}">
      <span class="tbl-mono" style="color:var(--fg-4)">#${pb.id}</span>
      <span><span class="tbl-pri">${escHtml(pb.name)}${pb.dry_run ? ' <span class="pill" style="font-size:9px;padding:1px 5px;background:rgba(245,158,11,.15);color:#f59e0b" title="Dry-run: actions are logged but not executed">DRY RUN</span>' : ''}</span><span class="tbl-muted" style="font-size:10px;display:block">${escHtml(pb.description||'')}</span></span>
      <span class="tbl-mono">Level ≥ ${pb.trigger?.min_level || 'any'}</span>
      <span class="tbl-mono">${(pb.actions||[]).length} actions</span>
      <span class="tbl-mono">${pb.run_count || 0}</span>
      <span><span class="pill ${pb.enabled ? 'ok' : ''}" style="${pb.enabled ? '' : 'color:var(--fg-4)'}">${pb.enabled ? 'ENABLED':'DISABLED'}</span></span>
      <span style="display:flex;gap:4px">
        <button onclick="viewPlaybookExecutions(${pb.id})" class="btn-disc-detail" title="History">⋮</button>
        <button onclick="togglePlaybook(${pb.id}, ${!pb.enabled})" class="btn-disc-detail" title="${pb.enabled ? 'Disable':'Enable'}">${pb.enabled ? '⏸':'▶'}</button>
        <button onclick="deletePlaybook(${pb.id})" class="btn-disc-detail" style="color:var(--crit)" title="Delete">✕</button>
      </span>
    </div>`).join('');
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
  const exW = 'grid-template-columns:100px 1fr 80px 120px 100px 90px 140px';
  tbody.innerHTML = execs.map(ex => {
    const dur = ex.completed_at && ex.started_at ? `${((ex.completed_at - ex.started_at)/1000).toFixed(1)}s` : '—';
    const sCol = ex.status === 'success' ? 'var(--ok)' : ex.status === 'failed' ? 'var(--crit)' : 'var(--low)';
    return `<div class="tbl-r" style="${exW}">
      <span class="tbl-mono" style="color:var(--fg-4)">#${ex.id}</span>
      <span class="tbl-mono">#${ex.playbook_id}</span>
      <span class="tbl-mono">Alert #${ex.alert_id}</span>
      <span class="tbl-mono">${escHtml(ex.agent_id)}</span>
      <span><span class="pill" style="color:${sCol};background:${sCol}22;border:1px solid ${sCol}44">${ex.status}</span></span>
      <span class="tbl-mono">${dur}</span>
      <span class="tbl-time">${fmtTs(ex.started_at)}</span>
    </div>`;
  }).join('');
}

function switchPbTab(tab) {
  const isPlaybooks = tab === 'playbooks';
  document.getElementById('pbPanePlaybooks').style.display = isPlaybooks ? '' : 'none';
  document.getElementById('pbPaneHistory').style.display   = isPlaybooks ? 'none' : '';
  document.getElementById('pbTabPlaybooks')?.classList.toggle('active', isPlaybooks);
  document.getElementById('pbTabHistory')?.classList.toggle('active', !isPlaybooks);
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
  const dr = document.getElementById('pbDryRun');
  if (dr) dr.checked = false;
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

  const dryRun = document.getElementById('pbDryRun')?.checked || false;
  const body = {
    name,
    description: document.getElementById('pbDesc')?.value?.trim() || '',
    enabled: true,
    dry_run: dryRun,
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
  if (res?.data?.id) alert(`Playbook #${res.data.id} created successfully.` + (dryRun ? '\n\nDry-run mode is ON — matching alerts will log the actions but not execute them. Turn it off (edit the playbook) when you\'re ready to arm it.' : ''));
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page="playbooks"]').forEach(el => {
    el.addEventListener('click', () => { loadPlaybooks(); switchPbTab('playbooks'); });
  });
});

// ── Syslog Decoder Management ─────────────────────────────────────────────────

(function() {
  'use strict';

  // URL constants — defined locally so this IIFE doesn't depend on the outer API map.
  var SD_URL        = '/api/decoders/syslog';
  var SD_URL_TEST   = '/api/decoders/syslog/test';
  var SD_URL_RELOAD = '/api/decoders/syslog/reload';

  let _sdAll = [];   // full list from server
  let _sdFiltered = [];  // after search/filter

  // ── helpers ──────────────────────────────────────────────────────────────
  function _esc(s) { return escapeHtml(String(s == null ? '' : s)); }

  function _groupColor(name) {
    if (!name) return 'var(--fg-4)';
    const palette = ['var(--accent)', 'var(--ok)', 'var(--med)', 'var(--low)', 'var(--high)'];
    let h = 0;
    for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) & 0xffffffff;
    return palette[Math.abs(h) % palette.length];
  }

  // ── render table ─────────────────────────────────────────────────────────
  function _renderTable() {
    const search = (document.getElementById('sdSearch')?.value || '').toLowerCase();
    const typeFilter = document.getElementById('sdFilterType')?.value || '';
    _sdFiltered = _sdAll.filter(d => {
      const name = (d.name || '').toLowerCase();
      const group = (d.group || d.parent || '').toLowerCase();
      if (search && !name.includes(search) && !group.includes(search)) return false;
      if (typeFilter === 'builtin' && !d.built_in) return false;
      if (typeFilter === 'custom' && d.built_in) return false;
      return true;
    });

    // Always update stats regardless of filter — stats reflect the full loaded set.
    const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    setEl('sdStatTotal',   _sdAll.length);
    setEl('sdStatBuiltin', _sdAll.filter(d => d.built_in).length);
    setEl('sdStatCustom',  _sdAll.filter(d => !d.built_in).length);
    setEl('sdStatGroups',  new Set(_sdAll.map(d => d.group || d.parent || '').filter(Boolean)).size);

    const col = 'grid-template-columns:1fr 110px 120px 160px 90px 100px';
    const body = document.getElementById('sdTableBody');
    if (!body) return;

    if (!_sdFiltered.length) {
      body.innerHTML = '<div class="sigil-block"><div class="sigil-text"><h4>No decoders found</h4><p>Try adjusting your search or add a custom decoder.</p></div></div>';
      return;
    }

    body.innerHTML = _sdFiltered.map((d, i) => {
      const name    = d.name || '—';
      const group   = d.group || (d.parent ? '' : 'root');
      const parent  = d.parent || '—';
      const program = d.program || '—';
      const isBuiltin = !!d.built_in;
      const typeBadge = isBuiltin
        ? '<span style="background:rgba(99,179,237,0.15);color:#63b3ed;border:1px solid rgba(99,179,237,0.3);border-radius:4px;font-size:10px;padding:1px 7px;font-weight:600">Built-in</span>'
        : '<span style="background:rgba(72,187,120,0.15);color:#48bb78;border:1px solid rgba(72,187,120,0.3);border-radius:4px;font-size:10px;padding:1px 7px;font-weight:600">Custom</span>';
      const groupColor = _groupColor(group);
      const groupPill = group
        ? `<span style="background:${groupColor};opacity:0.85;color:#fff;border-radius:10px;font-size:10px;padding:1px 8px;font-weight:600;white-space:nowrap">${_esc(group)}</span>`
        : '<span style="color:var(--fg-4)">—</span>';
      const deleteBtnHtml = isBuiltin
        ? '<button type="button" disabled title="Built-in decoders cannot be deleted" style="opacity:0.3;cursor:not-allowed;background:var(--surface-2);border:1px solid var(--border);color:var(--text-muted);padding:3px 8px;border-radius:4px;font-size:11px">Delete</button>'
        : `<button type="button" class="sd-delete-btn" data-name="${_esc(name)}" style="background:rgba(245,101,101,0.1);border:1px solid rgba(245,101,101,0.3);color:#f56565;padding:3px 8px;border-radius:4px;font-size:11px;cursor:pointer">Delete</button>`;
      return `<div class="tbl-r" style="${col}">
        <span class="tbl-pri">${_esc(name)}</span>
        <span>${groupPill}</span>
        <span class="tbl-mono" style="font-size:11px">${_esc(parent)}</span>
        <span class="tbl-mono" style="font-size:11px">${_esc(program)}</span>
        <span>${typeBadge}</span>
        <span style="display:flex;gap:5px;align-items:center">
          <button type="button" class="sd-view-btn btn-disc-detail btn-agent-view" data-index="${i}" title="View details">&#8943;</button>
          ${deleteBtnHtml}
        </span>
      </div>`;
    }).join('');

  }

  // ── load from server ──────────────────────────────────────────────────────
  async function loadSyslogDecoders() {
    const body = document.getElementById('sdTableBody');
    if (body) body.innerHTML = '<div class="tbl-r"><span style="color:var(--fg-3);grid-column:1/-1;padding:12px">Loading…</span></div>';
    try {
      const res = await fetch(SD_URL);
      const data = await res.json().catch(() => ({}));
      _sdAll = Array.isArray(data.data) ? data.data : [];
    } catch (_) {
      _sdAll = [];
    }
    _renderTable();
  }
  window.loadSyslogDecoders = loadSyslogDecoders;

  // ── add decoder modal ─────────────────────────────────────────────────────
  function _openAddModal() {
    ['sdFormName','sdFormDesc','sdFormParent','sdFormProgram','sdFormPrematch','sdFormRegex','sdFormStaticFields'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    const m = document.getElementById('sdAddModal');
    if (m) { m.style.display = 'flex'; }
  }
  function _closeAddModal() {
    const m = document.getElementById('sdAddModal');
    if (m) m.style.display = 'none';
  }

  async function _submitAddDecoder() {
    const name = (document.getElementById('sdFormName')?.value || '').trim();
    if (!name) { alert('Name is required.'); return; }
    const desc      = (document.getElementById('sdFormDesc')?.value || '').trim();
    const parent    = (document.getElementById('sdFormParent')?.value || '').trim();
    const program   = (document.getElementById('sdFormProgram')?.value || '').trim();
    const prematch  = (document.getElementById('sdFormPrematch')?.value || '').trim();
    const regex     = (document.getElementById('sdFormRegex')?.value || '').trim();
    const sfRaw     = (document.getElementById('sdFormStaticFields')?.value || '').trim();
    const static_fields = {};
    sfRaw.split('\n').forEach(line => {
      const eq = line.indexOf('=');
      if (eq > 0) {
        const k = line.slice(0, eq).trim();
        const v = line.slice(eq + 1).trim();
        if (k) static_fields[k] = v;
      }
    });
    const body = { name, description: desc, parent, program, prematch, regex, static_fields, built_in: false };
    try {
      const res = await fetch(SD_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(data.error || data.message || 'Failed to create decoder.');
        return;
      }
      _closeAddModal();
      await loadSyslogDecoders();
    } catch (e) {
      alert(e.message || 'Request failed.');
    }
  }

  // ── delete decoder ────────────────────────────────────────────────────────
  async function _deleteDecoder(name) {
    if (!name) return;
    if (!confirm(`Delete decoder "${name}"? This cannot be undone.`)) return;
    try {
      const res = await fetch(SD_URL + '/' + encodeURIComponent(name), { method: 'DELETE' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(data.error || data.message || 'Failed to delete decoder.');
        return;
      }
      await loadSyslogDecoders();
    } catch (e) {
      alert(e.message || 'Request failed.');
    }
  }

  // ── view decoder modal ────────────────────────────────────────────────────
  function _openViewModal(index) {
    const d = _sdFiltered[index];
    if (!d) return;
    const titleEl = document.getElementById('sdViewModalTitle');
    const bodyEl  = document.getElementById('sdViewModalBody');
    if (titleEl) titleEl.textContent = 'Decoder: ' + (d.name || '—');
    if (bodyEl) {
      const rows = [
        ['Name',         d.name        || '—'],
        ['Description',  d.description || '—'],
        ['Parent',       d.parent      || '—'],
        ['Program',      d.program     || '—'],
        ['Prematch',     d.prematch    || '—'],
        ['Regex',        d.regex       || '—'],
        ['Type',         d.built_in ? 'Built-in' : 'Custom'],
      ];
      const sf = d.static_fields || {};
      const sfKeys = Object.keys(sf);
      if (sfKeys.length) {
        rows.push(['Static Fields', sfKeys.map(k => `${k}=${sf[k]}`).join(', ')]);
      }
      bodyEl.innerHTML = '<table class="discover-detail-table"><tbody>'
        + rows.map(([k, v]) => `<tr><td class="key">${_esc(k)}</td><td>${_esc(v)}</td></tr>`).join('')
        + '</tbody></table>';
    }
    const m = document.getElementById('sdViewModal');
    if (m) m.style.display = 'flex';
  }
  function _closeViewModal() {
    const m = document.getElementById('sdViewModal');
    if (m) m.style.display = 'none';
  }

  // ── test decoder ──────────────────────────────────────────────────────────
  async function _testDecoder() {
    const appName = (document.getElementById('sdTestAppName')?.value || '').trim();
    const message = (document.getElementById('sdTestMessage')?.value || '').trim();
    if (!appName || !message) {
      alert('Please fill in both App Name and Message fields.');
      return;
    }
    const resultEl = document.getElementById('sdTestResult');
    const innerEl  = document.getElementById('sdTestResultInner');
    if (resultEl) resultEl.style.display = 'block';
    if (innerEl)  innerEl.innerHTML = '<span style="color:var(--fg-3)">Testing…</span>';
    try {
      const res = await fetch(SD_URL_TEST, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ app_name: appName, message }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (innerEl) innerEl.innerHTML = `<span style="color:var(--crit)">Error: ${_esc(data.error || res.statusText)}</span>`;
        return;
      }
      const result = data.data || data;
      const matched = result.matched === true;
      let html = '';
      if (matched) {
        html += `<div style="margin-bottom:10px"><span style="color:var(--ok);font-weight:600">&#10003; Matched</span>`;
        if (result.decoder_name) html += ` &mdash; decoder: <span style="font-weight:600">${_esc(result.decoder_name)}</span>`;
        html += '</div>';
        const fields = result.fields || {};
        const fkeys = Object.keys(fields);
        if (fkeys.length) {
          html += '<table class="discover-detail-table"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>'
            + fkeys.map(k => `<tr><td class="key">${_esc(k)}</td><td>${_esc(fields[k])}</td></tr>`).join('')
            + '</tbody></table>';
        } else {
          html += '<span style="color:var(--fg-3);font-size:12px">No named fields extracted.</span>';
        }
      } else {
        html = '<span style="color:var(--crit);font-weight:600">&#10007; No decoder matched</span>';
      }
      if (innerEl) innerEl.innerHTML = html;
    } catch (e) {
      if (innerEl) innerEl.innerHTML = `<span style="color:var(--crit)">Error: ${_esc(e.message || 'Request failed')}</span>`;
    }
  }

  // ── reload decoders ───────────────────────────────────────────────────────
  async function _reloadDecoders() {
    const btn = document.getElementById('sdReloadBtn');
    if (btn) btn.textContent = 'Reloading…';
    try {
      const res = await fetch(SD_URL_RELOAD, { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(data.error || data.message || 'Reload failed.');
      } else {
        await loadSyslogDecoders();
      }
    } catch (e) {
      alert(e.message || 'Request failed.');
    } finally {
      if (btn) {
        btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 12a9 9 0 0 1 15-6.7L21 8M21 3v5h-5M21 12a9 9 0 0 1-15 6.7L3 16M3 21v-5h5"/></svg> Reload';
      }
    }
  }

  // ── wire events ───────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('sdAddBtn')?.addEventListener('click', _openAddModal);
    document.getElementById('sdAddModalClose')?.addEventListener('click', _closeAddModal);
    document.getElementById('sdAddModalCancel')?.addEventListener('click', _closeAddModal);
    document.getElementById('sdAddModalSubmit')?.addEventListener('click', _submitAddDecoder);
    document.getElementById('sdViewModalClose')?.addEventListener('click', _closeViewModal);
    document.getElementById('sdReloadBtn')?.addEventListener('click', _reloadDecoders);
    document.getElementById('sdTestBtn')?.addEventListener('click', _testDecoder);

    let _sdSearchTimer = null;
    document.getElementById('sdSearch')?.addEventListener('input', () => {
      clearTimeout(_sdSearchTimer);
      _sdSearchTimer = setTimeout(_renderTable, 300);
    });
    document.getElementById('sdFilterType')?.addEventListener('change', _renderTable);

    document.getElementById('sdTableBody')?.addEventListener('click', (e) => {
      const viewBtn = e.target.closest('.sd-view-btn');
      if (viewBtn) {
        const idx = parseInt(viewBtn.getAttribute('data-index'), 10);
        _openViewModal(idx);
        return;
      }
      const delBtn = e.target.closest('.sd-delete-btn');
      if (delBtn) {
        _deleteDecoder(delBtn.getAttribute('data-name'));
      }
    });

    // close modals on backdrop click
    document.getElementById('sdAddModal')?.addEventListener('click', (e) => {
      if (e.target === e.currentTarget) _closeAddModal();
    });
    document.getElementById('sdViewModal')?.addEventListener('click', (e) => {
      if (e.target === e.currentTarget) _closeViewModal();
    });

    // load when navigating to the decoders page
    document.querySelectorAll('.nav-item[data-page="decoders"]').forEach(el => {
      el.addEventListener('click', () => { loadSyslogDecoders(); });
    });
  });
})();

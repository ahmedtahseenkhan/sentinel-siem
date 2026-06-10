# CoreNest SIEM Dashboard

A professional SIEM dashboard that connects to your **WatchTower** (Manager) and **WatchVault** (Indexer, backed by OpenSearch) and provides a single pane of glass for threat hunting, agent health, alerts, and vulnerabilities.

## Phase 1: Foundation and Environment Setup

The dashboard supports Phase 1 explicitly:

1. **1.1 Verify the stack** — Use **Stack Status** in the sidebar to confirm Manager and Indexer connection, versions, and endpoints (WatchTower default 9400, WatchVault default 9500, OpenSearch default 9200).
2. **1.2 Credentials** — Set `WATCHTOWER_API_KEY`, `WATCHVAULT_API_KEY`, and `OPENSEARCH_USER`/`OPENSEARCH_PASSWORD` in `.env`. Stack Status shows configured URLs (no secrets).
3. **1.3 Plan your dashboard** — Use **Overview** (threat/compliance/agent health at a glance), **Threat Hunting** (top threats, agent-level alerts, rule level), **Agent Health** (agent status), **Vulnerabilities** (counts and severity), and **Alerts** (recent alerts with level, agent, etc.).

## Phase 2: Connecting to Data Sources

Configure everything in `.env` and use the **Data Sources** page to test and verify connections.

1. **2.1 Manager API** — View WatchTower URL and port (9400). Use **Test connection** to verify. Configure via `WATCHTOWER_URL` / `WATCHTOWER_API_KEY` in `.env`; restart the app after changes.
2. **2.2 Indexer API** — View WatchVault URL and port (9500), plus the OpenSearch URL (9200) used for direct index queries. Use **Test connection** to verify. Index patterns are listed with doc counts on the same page.

## Phase 3: Custom Visualizations

The **Visualizations** page provides core visualizations over the alert index:

1. **Top 5 Alerts by Agent** — Horizontal bar chart; metric Count; bucket Terms on agent.
2. **Alert Severity Over Time** — Line chart; metric Count; X-axis Date Histogram on timestamp; split series by rule level.
3. **Rule Tactic Breakdown** — Pie chart; metric Count; bucket Terms on MITRE tactic.

Aggregations used: metric = Count; buckets = Terms (agent, rule level, MITRE tactic) and Date Histogram (timestamp). Each visualization has a clear, descriptive name.

## Phase 4: Assembling and Configuring the Dashboard

The **Dashboard** page is the assembled view (no separate "Create new dashboard" step):

- **4.1–4.2** — The dashboard shows the Phase 3 visualizations (Top 5 Alerts by Agent, Alert Severity Over Time, Rule Tactic Breakdown) in one place.
- **4.3** — Panels are arranged in a grid; layout is fixed (no drag/resize in this version).
- **4.4** — **Dashboard-level filters**: use **Min rule level** (e.g. ≥ 10) and **Time range** (Last 24h, 7d, 30d). Click **Apply** to refresh data with the filters. Click **Save dashboard** to persist the current filter and time range to the browser (localStorage); they are restored on next visit.

API support: `min_level`, `time_from`, and `time_to` query parameters are applied to the alert aggregation APIs so all panels respect the same filter and time range.

## Phase 5: Advanced Customization and Integration

The **Advanced** page documents optional steps:

- **5.1** — Integrate non-alert data: ingest custom telemetry through the agent/collector pipeline so it lands in the events index, then build visualizations for the new data in this dashboard.
- **5.2** — Connection settings and timeouts are configured in `.env` and `config.py`.

## Phase 6: Dashboard Refinement and User Management

- **6.1 Optimize visualizations** — Default time range (e.g. Last 7 days), optional permanent filter via **Exclude rule IDs** (comma-separated) to exclude known false positives. **Unique counts** panel: unique source IPs, unique agents, total events (cardinality aggregations). Chart subtitles show the selected time range.
- **6.2 Dashboard controls** — **Filter by agent** and **Filter by rule group** dropdowns; all dashboard panels update when you Apply. **Drill-down**: click a bar in "Top 5 Alerts by Agent" to filter the dashboard by that agent; use **Clear filter** to reset. Filters can be saved with **Save dashboard** (for roles that have permission).
- **6.3 User access control** — Four roles with different permissions:

| Role | Description |
|------|-------------|
| **Super Admin** | Full access: config pages (Stack Status, Data Sources, Advanced) and all operational pages; can save dashboard. |
| **Administrator** | All operational pages; can save dashboard; no config pages. |
| **Security Analyst** | All operational pages; **read-only** dashboard (cannot save filters). |
| **Compliance Officer** | Same as Security Analyst (read-only dashboards). |

Configure users via `.env`: either the four vars (`DASHBOARD_SUPER_ADMIN_*`, `DASHBOARD_ADMIN_*`) or `DASHBOARD_USERS=user:password:role,...` with roles `super_admin`, `administrator`, `security_analyst`, `compliance_officer`. Set `SECRET_KEY` in production.

## Phase 7: Expanding Data Sources and Integrations

- **7.1 IT Hygiene / Asset Management** — System, software, processes, and identity inventory is built from `syscollector.*` events in the events index. Use **Asset Management** to browse it and **Data Sources** to inspect index patterns.
- **7.2 Custom data** — Identify new sources, ingest them through the agent/collector pipeline, then build visualizations over the new data. The **Advanced** page summarizes the workflow.

See **docs/PHASES_7_8_9.md** for full guidance.

## Phase 8: Maintenance, Monitoring, and Troubleshooting

- **8.1 Maintenance** — Keep WatchTower, WatchVault, and the dashboard on compatible versions; schedule upgrades.
- **8.2 Monitoring** — Check service status (WatchTower, WatchVault, OpenSearch), logs, and connectivity. Use **Stack Status** and **Data Sources** in this app to test connections.
- **8.3 Troubleshooting** — Data delays (e.g. syscollector scan interval), missing data (agent restart / scan-on-start), and direct index queries for deep troubleshooting.

Details in **docs/PHASES_7_8_9.md** and in the app under **Advanced → Phase 8**.

## Phase 9: Advanced Customization and Automation

- **9.1 Branding** — Edit `templates/` and `static/css/style.css` to match your organization.
- **9.2 Reporting** — Scheduled PDF reports and email are supported (weasyprint + APScheduler + SMTP). See the **Reports** page.
- **9.3 Alerts from searches** — Email/Slack alerting on thresholds is configured via the SMTP and `SLACK_WEBHOOK_URL` settings in `.env`.

See **docs/PHASES_7_8_9.md** and **Advanced → Phase 9** in the app.

## Dashboard login

The app requires sign-in. Roles and credentials are configured in `.env` (see Phase 6.3 and `.env.example`).

## Features and menus

- **Overview** — Security posture, scorecards, timeline, at-risk entities, MITRE, live alert stream
- **Stack Status** — Phase 1 checklist; Manager/Indexer connection, versions, IPs/ports; configured endpoints from `.env`
- **Data Sources** — Phase 2: Manager/Indexer config + test, index patterns with doc counts
- **Agent Health** — Agent summary and full agents table (ID, name, IP, status, OS, last keep-alive)
- **Threat Hunting** — Alerts by agent, alerts by severity (rule level), top rules
- **Alerts** — Recent alerts with time, level, rule, agent, source IP, user
- **Vulnerabilities** — Counts by severity, recent findings (CVE, severity, agent, package)
- **Asset Management** — System, software, processes, and identity inventory across the fleet
- **Visualizations** — Phase 3: Top 5 Alerts by Agent (bar), Alert Severity Over Time (line), Rule Tactic Breakdown (pie)
- **Dashboard** — Phase 4/6: Min rule level, time range, filter by agent, filter by rule group, exclude rule IDs; unique counts panel; drill-down from Top Agents bar; Save (for permitted roles)
- **Advanced** — Configuration reference; Phase 7 (data sources & custom data), Phase 8 (operations & troubleshooting), Phase 9 (branding, reporting, alerting). See also **docs/PHASES_7_8_9.md**.
- **Compliance** — Per-framework compliance views

## Requirements

- Python 3.9+
- WatchTower (Manager) REST API — default port 9400
- WatchVault (Indexer) REST API — default port 9500
- OpenSearch — default port 9200

## Setup

1. **Clone or copy this project** into a folder (e.g. `corenestDashboard`).

2. **Create a virtual environment and install dependencies:**

   ```bash
   cd corenestDashboard
   python3 -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure the connection to WatchTower / WatchVault / OpenSearch:**

   Copy `.env.example` to `.env` and adjust if your services are not on `localhost`:

   ```bash
   cp .env.example .env
   ```

   If the stack runs in Docker on the same host, publish the ports and use:
   - `WATCHTOWER_URL=http://localhost:9400`
   - `WATCHVAULT_URL=http://localhost:9500`
   - `OPENSEARCH_URL=http://localhost:9200` (use `https://` only if TLS is enabled on the indexer)

   If the dashboard runs inside the same Docker network, use the service names (e.g. `http://watchtower:9400`, `http://watchvault:9500`, `http://opensearch:9200`).

   Set `WATCHTOWER_API_KEY` and `WATCHVAULT_API_KEY` to the API keys issued by those services, and `OPENSEARCH_USER`/`OPENSEARCH_PASSWORD` for direct index queries (default `admin`/`admin`).

4. **Run the dashboard:**

   ```bash
   python app.py
   ```

   The app listens on `http://0.0.0.0:5050` by default. Open **http://localhost:5050** in your browser. Set `PORT` to use another port.

## Configuration (environment variables)

| Variable | Description | Default |
|----------|-------------|---------|
| `WATCHTOWER_URL` | WatchTower (Manager) REST API base URL | `http://localhost:9400` |
| `WATCHTOWER_API_KEY` | WatchTower API key (Bearer) | _(empty)_ |
| `WATCHVAULT_URL` | WatchVault (Indexer) REST API base URL | `http://localhost:9500` |
| `WATCHVAULT_API_KEY` | WatchVault API key (Bearer) | _(empty)_ |
| `OPENSEARCH_URL` | OpenSearch base URL (direct index queries) | `http://localhost:9200` |
| `OPENSEARCH_USER` | OpenSearch user | `admin` |
| `OPENSEARCH_PASSWORD` | OpenSearch password | `admin` |
| `INDEX_PREFIX` | Index prefix used by WatchVault (`<prefix>-<type>-<date>`) | `watchvault` |
| `VERIFY_SSL` | Verify HTTPS certificates | `false` |
| `REQUEST_TIMEOUT` | API request timeout in seconds | `15` |

## Docker note

If WatchTower/WatchVault/OpenSearch run in Docker with ports published to the host, run this dashboard on the host pointing at `http://localhost:9400`, `http://localhost:9500`, and `http://localhost:9200`. Use `VERIFY_SSL=false` for self-signed certs. If you see **`SSL: UNEXPECTED_EOF_WHILE_READING`** on port 9200, the indexer is serving **HTTP** — switch to `http://` in `OPENSEARCH_URL`.

## Troubleshooting: 401 / connection errors

If the dashboard cannot reach a service:

1. **WatchTower / WatchVault (Manager / Indexer)** — these use **Bearer API-key** auth. Confirm `WATCHTOWER_API_KEY` / `WATCHVAULT_API_KEY` match the keys issued by each service, and that the URLs/ports are reachable from where the dashboard runs.
2. **OpenSearch** — uses HTTP Basic auth. Confirm `OPENSEARCH_USER` / `OPENSEARCH_PASSWORD` are correct (default `admin`/`admin` in dev). A `SSL: UNEXPECTED_EOF_WHILE_READING` error means you used `https://` against a plain-HTTP indexer — switch to `http://`.

After changing `.env`, **restart** the CoreNest Dashboard so it picks up the new settings.

## License

Use and modify as needed for your environment.

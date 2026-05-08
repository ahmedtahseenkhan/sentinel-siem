# Sentinel Core SIEM Dashboard

A professional SIEM dashboard that connects to your **Wazuh Manager** and **Wazuh Indexer** (Docker or standalone) and provides a single pane of glass for threat hunting, agent health, alerts, and vulnerabilities.

## Phase 1: Foundation and Environment Setup

The dashboard supports Phase 1 explicitly:

1. **1.1 Verify Wazuh stack** — Use **Stack Status** in the sidebar to confirm manager and indexer connection, versions, and endpoints (Manager API default 55000, Indexer default 9200).
2. **1.2 Credentials** — Set `SENTINEL_MANAGER_USER`/`SENTINEL_MANAGER_PASSWORD` and `SENTINEL_INDEXER_USER`/`SENTINEL_INDEXER_PASSWORD` in `.env`. Stack Status shows configured URLs and users (no passwords).
3. **1.3 Plan your dashboard** — Use **Overview** (threat/compliance/agent health at a glance), **Threat Hunting** (top threats, agent-level alerts, rule.level), **Agent Health** (agent status), **Vulnerabilities** (counts and data.vulnerability.severity), and **Alerts** (recent alerts with rule.level, agent.id, etc.).

## Phase 2: Connecting to Data Sources (no Wazuh Dashboard required)

This app replaces the need for the official Wazuh Dashboard (Kibana) for connection and index verification. Configure everything in `.env` and use the **Data Sources** page to test and verify.

1. **2.1 Manager API** — View Manager URL, port (55000), username (password masked). Use **Test connection** to verify. Configure via `SENTINEL_MANAGER_*` in `.env`; restart the app after changes.
2. **2.2 Indexer API** — View Indexer URL, port (9200), username (password masked). Use **Test connection** to verify. Configure via `SENTINEL_INDEXER_*` in `.env`. Index patterns (`wazuh-alerts-*`, `wazuh-monitoring-*`, etc.) are listed with doc counts on the same page.

## Phase 3: Custom Visualizations (no Wazuh Dashboard required)

The **Visualizations** page provides the core visualizations that would otherwise be built in the Wazuh Dashboard “Explore > Visualize” flow:

1. **Top 5 Alerts by Agent** — Horizontal bar chart; data source `wazuh-alerts-*`; metric Count; bucket Terms on `agent.name`.
2. **Alert Severity Over Time** — Line chart; data source `wazuh-alerts-*`; metric Count; X-axis Date Histogram on `timestamp`; split series by `rule.level`.
3. **Rule Tactic Breakdown** — Pie chart; data source `wazuh-alerts-*`; metric Count; bucket Terms on `rule.mitre.tactic`.

Aggregations used: metric = Count; buckets = Terms (`agent.name`, `rule.level`, `rule.mitre.tactic`) and Date Histogram (`timestamp`). Each visualization has a clear, descriptive name.

## Phase 4: Assembling and Configuring the Dashboard

The **Dashboard** page is the assembled view (no separate "Create new dashboard" step):

- **4.1–4.2** — The dashboard shows the Phase 3 visualizations (Top 5 Alerts by Agent, Alert Severity Over Time, Rule Tactic Breakdown) in one place.
- **4.3** — Panels are arranged in a grid; layout is fixed (no drag/resize in this version).
- **4.4** — **Dashboard-level filters**: use **Min rule.level** (e.g. ≥ 10) and **Time range** (Last 24h, 7d, 30d). Click **Apply** to refresh data with the filters. Click **Save dashboard** to persist the current filter and time range to the browser (localStorage); they are restored on next visit.

API support: `min_level`, `time_from`, and `time_to` query parameters are applied to the alert aggregation APIs so all panels respect the same filter and time range.

## Phase 5: Advanced Customization and Integration

The **Advanced** page documents optional steps:

- **5.1** — Integrate non-alert data: develop a script, configure a Wodle in `ossec.conf`, add a custom rule in `local_rules.xml`, then build visualizations for the new data in this dashboard.
- **5.2** — This app does not use the official Wazuh Dashboard's `wazuh.yml`. Connection and timeouts are configured in `.env` and `config.py`.

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

- **7.1 IT Hygiene** — The official Wazuh IT Hygiene dashboard (and newer Browser Extensions / Services tabs) uses state/inventory indices. Use **Data Sources** in this app to see index patterns; the same indices can back custom views.
- **7.2 Custom data** — Identify new sources, use the **command wodle** and **custom rules** to ingest data into the indexer, then create index patterns and visualizations. The **Advanced** page summarizes the workflow.

See **docs/PHASES_7_8_9.md** for full guidance.

## Phase 8: Maintenance, Monitoring, and Troubleshooting

- **8.1 Maintenance** — Version compatibility (manager, indexer, dashboard); schedule upgrades; keep cluster nodes on the same version.
- **8.2 Monitoring** — Check service status (`wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard`), logs, and connectivity. Use **Stack Status** and **Data Sources** in this app to test connections.
- **8.3 Troubleshooting** — Data delays (e.g. syscollector interval), missing data (agent restart, `scan_on_start`), and direct index queries for deep troubleshooting.

Details in **docs/PHASES_7_8_9.md** and in the app under **Advanced → Phase 8**.

## Phase 9: Advanced Customization and Automation

- **9.1 Branding** — Official dashboard: `opensearch_dashboards.yml`. This app: edit `templates/` and `static/css/style.css`.
- **9.2 Reporting** — Scheduled PDF reports and email: use the official Wazuh Dashboard reporting feature.
- **9.3 Alerts from searches** — Saved searches and alerting (email, Slack): use the official Wazuh Dashboard or external monitoring.

See **docs/PHASES_7_8_9.md** and **Advanced → Phase 9** in the app.

## Dashboard login

The app requires sign-in. Roles and credentials are configured in `.env` (see Phase 6.3 and `.env.example`).

## Features and menus

- **Overview** — Security posture, scorecards, timeline, at-risk entities, MITRE, live alert stream
- **Stack Status** — Phase 1 checklist; Manager/Indexer connection, versions, IPs/ports; configured endpoints from `.env`
- **Data Sources** — Phase 2: Manager API config + test, index patterns (wazuh-alerts-*, wazuh-monitoring-*, etc.)
- **Agent Health** — Agent summary and full agents table (ID, name, IP, status, OS, last keep-alive)
- **Threat Hunting** — Alerts by agent, alerts by severity (rule.level), top rules
- **Alerts** — Recent alerts with time, level, rule, agent, source IP, user
- **Vulnerabilities** — Counts by severity, recent findings (CVE, severity, agent, package)
- **Visualizations** — Phase 3: Top 5 Alerts by Agent (bar), Alert Severity Over Time (line), Rule Tactic Breakdown (pie)
- **Dashboard** — Phase 4/6: Min rule.level, time range, filter by agent, filter by rule group, exclude rule IDs; unique counts panel; drill-down from Top Agents bar; Save (for permitted roles)
- **Advanced** — Configuration reference; Phase 7 (data sources & custom data), Phase 8 (operations & troubleshooting), Phase 9 (branding, reporting, alerting). See also **docs/PHASES_7_8_9.md**.
- **Compliance** — Placeholder for compliance framework views

## Requirements

- Python 3.9+
- Wazuh Manager API (port 55000)
- Wazuh Indexer API (port 9200)

## Setup

1. **Clone or copy this project** into a folder (e.g. `sentinelCoreDashboard`).

2. **Create a virtual environment and install dependencies:**

   ```bash
   cd sentinelCoreDashboard
   python3 -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure connection to Sentinel Manager / Indexer (optional):**

   Copy `.env.example` to `.env` and adjust if your Manager/Indexer are not on `localhost`:

   ```bash
   cp .env.example .env
   ```

   If your stack runs in Docker on the same host, you may need to use:
   - `SENTINEL_MANAGER_URL=https://localhost:55000` (with port 55000 mapped from the manager container)
   - `SENTINEL_INDEXER_URL=http://localhost:9200` (most indexers expose **plain HTTP** on 9200; use `https://` only if TLS is enabled)

   If the dashboard runs inside the same Docker network as the stack, use the service names:
   - `SENTINEL_MANAGER_URL=https://sentinelcore-manager:55000`
   - `SENTINEL_INDEXER_URL=http://sentinelcore-indexer:9200` (or `https://` if your stack enables indexer TLS)

   Default credentials are often `wazuh`/`wazuh` for the manager and `admin`/`admin` for the indexer; set `SENTINEL_MANAGER_USER`, `SENTINEL_MANAGER_PASSWORD`, `SENTINEL_INDEXER_USER`, `SENTINEL_INDEXER_PASSWORD` in `.env` to match your setup.

4. **Run the dashboard:**

   ```bash
   python app.py
   ```

   The app listens on `http://0.0.0.0:5050` by default. Open **http://localhost:5050** in your browser. Set `PORT` to use another port.

## Configuration (environment variables)

| Variable | Description | Default |
|----------|-------------|---------|
| `SENTINEL_MANAGER_URL` | Manager API base URL | `https://localhost:55000` |
| `SENTINEL_MANAGER_USER` | Manager API user | `wazuh` |
| `SENTINEL_MANAGER_PASSWORD` | Manager API password | `wazuh` |
| `SENTINEL_INDEXER_URL` | Indexer API base URL | `http://localhost:9200` |
| `SENTINEL_INDEXER_USER` | Indexer API user | `admin` |
| `SENTINEL_INDEXER_PASSWORD` | Indexer API password | `admin` |
| `VERIFY_SSL` | Verify HTTPS certificates | `false` |
| `REQUEST_TIMEOUT` | API request timeout in seconds (Manager and Indexer) | `15` |

## Docker note

If Manager and Indexer are in Docker with ports 55000 and 9200 published to the host, run this dashboard on the host with `SENTINEL_MANAGER_URL=https://localhost:55000` and `SENTINEL_INDEXER_URL=http://localhost:9200` unless your indexer uses HTTPS on 9200. Use `VERIFY_SSL=false` for self-signed Manager certs. If you see **`SSL: UNEXPECTED_EOF_WHILE_READING`** on port 9200, the indexer is almost certainly **HTTP** — switch to `http://` in `SENTINEL_INDEXER_URL`.

## Troubleshooting: 401 Unauthorized (Manager API)

If you see **401 Unauthorized** when the dashboard calls the Wazuh Manager API, the Manager is rejecting the username or password in your `.env`.

### Use the same credentials as your Sentinel / Wazuh stack

1. **Wazuh installed with Docker**
   - Open the **docker-compose** or **.env** used to start your stack (e.g. `wazuh-docker/single-node/.env` or the manager service env).
   - Find the variables that set the **API** user/password. They are often named:
     - `API_USERNAME` and `API_PASSWORD`, or
     - `WAZUH_API_USERNAME` / `WAZUH_API_PASSWORD`, or similar.
   - Copy that **exact** username and password into this dashboard’s `.env`:
     - `SENTINEL_MANAGER_USER=<that_username>`
     - `SENTINEL_MANAGER_PASSWORD=<that_password>`
   - If you never set them, the Wazuh Docker image may have created a default; check the Wazuh Docker docs or the container’s env for the API user. Some images use `wazuh-wui` as the API user with a generated password.

2. **Wazuh installed with the installation script**
   - The API password is usually in:  
     `wazuh-install-files/wazuh-passwords.txt`  
   - Use the username (often `wazuh`) and the password from that file for `SENTINEL_MANAGER_USER` and `SENTINEL_MANAGER_PASSWORD` in `.env`.

3. **You can log in to the Wazuh Dashboard (Kibana)**
   - Use the **same** username and password you use to log in to the Wazuh web UI as `SENTINEL_MANAGER_USER` and `SENTINEL_MANAGER_PASSWORD` in this dashboard’s `.env`.

After changing `.env`, **restart** the Sentinel Core Dashboard so it picks up the new credentials.

## License

Use and modify as needed for your environment.

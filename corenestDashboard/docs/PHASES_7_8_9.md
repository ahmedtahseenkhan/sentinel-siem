# Phases 7, 8, and 9: Data Sources, Maintenance, and Advanced Customization

This document summarizes guidance for expanding data sources, maintaining the stack, and advanced customization for the **CoreNest** dashboard and the WatchTower / WatchVault backend.

---

## Phase 7: Expanding Data Sources and Integrations

### 7.1 Leverage Pre-built Views

- **Asset Management (IT Hygiene)**: The built-in Asset Management page gives a consolidated view of system data (OS, software, processes, identity) across endpoints. See [IT_HYGIENE_IMPLEMENTATION.md](IT_HYGIENE_IMPLEMENTATION.md) for how it is built and how to add Services / Hardware / Ports tabs.
- **In this app**: The **Data Sources** page lists index patterns with doc counts. Inventory lives in the events index keyed by `event_type` (e.g. `syscollector.os`, `syscollector.packages`, `process.new`); you can query the same index for custom panels.

### 7.2 Ingest and Visualize Custom Data

1. **Identify new data sources**: Consider custom application logs, threat-intelligence feeds, or other data valuable for visualization.
2. **Collect it on the endpoint**: Use an existing WatchNode collector (file tail, osquery, syscollector) or add a new one so the data is shipped to WatchTower.
3. **Detect / shape it**: Add native YAML detection rules in `WatchTower/rules/` to turn raw events into alerts; WatchVault indexes both events and alerts into OpenSearch.
4. **Index patterns**: Once custom data is indexed, it appears on the **Data Sources** page after it receives data.
5. **Visualizations**: Build visualizations from the new data (add API routes in `app.py` / `watchtower_client.py` and panels in `static/js/app.js` that query the new index or `event_type`).

---

## Phase 8: Maintenance, Monitoring, and Troubleshooting

### 8.1 Establish a Maintenance Routine

- **Version compatibility**: Keep WatchTower, WatchVault, and the dashboard on compatible versions; review release notes before upgrading.
- **Regular upgrades**: Schedule upgrades to get new features, performance improvements, and bug fixes.

### 8.2 Proactive Monitoring of the Stack

- **Service status**: Verify that WatchTower, WatchVault, and OpenSearch are healthy (e.g. `docker compose -f docker-compose.local.yaml ps`, or the container/service manager you deploy with).
- **Logs**: Check component logs for errors (WatchTower / WatchVault container logs; OpenSearch logs).
- **Connectivity**: Ensure the dashboard can reach WatchTower (9400), WatchVault (9500), and OpenSearch (9200). Use **Stack Status** and **Data Sources** in this app to test connections.

### 8.3 Troubleshoot Common Data Issues

- **Data delays**: Inventory data (e.g. installed software) is collected by the agent's syscollector on an interval. Changes may take up to that interval to appear.
- **Missing data**: To force an inventory update, restart the agent if scan-on-start is enabled.
- **A view is empty but others have data**: Each Asset Management view is pinned to one `event_type`. If Software/Processes show data but System does not, the agent isn't emitting `syscollector.os` — a collector gap, not a UI bug.
- **Direct index inspection**: For deep troubleshooting, query the indexer directly, e.g. `GET /{INDEX_PREFIX}-events-*/_search?pretty` with a `term` on `event_type` for raw inventory data.

---

## Phase 9: Advanced Customization and Automation

### 9.1 Customize Look and Feel (Branding)

- **This dashboard (CoreNest)**: Branding is done by editing the app's templates and static assets (`templates/`, `static/css/style.css`, `static/js/app.js`). No separate branding config file.

### 9.2 Automate Reporting

- **This dashboard**: Scheduled PDF reports are built in — weasyprint + APScheduler render and email reports on a schedule, configured via the **Reports** page and the SMTP settings in `.env`. Reports can include your branded logo and key metrics.

### 9.3 Alerts from Searches

- **This dashboard**: Threshold/notification alerting is delivered over SMTP (email) and `SLACK_WEBHOOK_URL` (Slack), throttled via `ALERT_THROTTLE_MINUTES`. Configure recipients and channels in `.env`.

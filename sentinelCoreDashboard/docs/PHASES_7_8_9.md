# Phases 7, 8, and 9: Data Sources, Maintenance, and Advanced Customization

This document summarizes guidance for expanding data sources, maintaining the Wazuh stack, and advanced customization. The **Sentinel Core** dashboard supports many of these concepts; some items refer to the official Wazuh Dashboard.

---

## Phase 7: Expanding Data Sources and Integrations

### 7.1 Leverage Pre-built Dashboards

- **IT Hygiene Dashboard** (official Wazuh Dashboard): On recent Wazuh versions, the out-of-the-box IT Hygiene dashboard provides a consolidated view of system data (OS, software, processes, network) across endpoints without extra configuration. Use it as inspiration or incorporate its data into custom views.
- **New data tabs**: Newer IT Hygiene modules include **Browser Extensions** and **Services** tabs for deeper endpoint visibility.
- **In this app**: The **Data Sources** page lists index patterns. Inventory and state indices (e.g. `wazuh-states-inventory-*`, `wazuh-states-vulnerabilities-*`) are used by the official dashboard for IT Hygiene. You can query the same indices via the indexer for custom panels.

### 7.2 Ingest and Visualize Custom Data

1. **Identify new data sources**: Consider custom application logs, threat intelligence feeds, or other data valuable for visualization.
2. **Custom scripts (Wodles)**: Use Wazuh’s **command wodle** to run scripts on the manager or agents (e.g. daily software inventory, listening ports). Add a `<wodle name="command">` block in `ossec.conf`.
3. **Custom rules**: Write rules in `/var/ossec/etc/rules/local_rules.xml` to format script output into alerts so they are sent to the indexer.
4. **Index patterns**: Once custom data is indexed, create or use the corresponding index pattern. The **Data Sources** page in this app shows existing `wazuh-*` patterns; new indices will appear there after they receive data.
5. **Visualizations**: Build visualizations from the new index (e.g. add API routes and panels in this dashboard that query the new index pattern).

---

## Phase 8: Maintenance, Monitoring, and Troubleshooting

### 8.1 Establish a Maintenance Routine

- **Version compatibility**: Before upgrading any Wazuh component, check official release notes and upgrade guides. Manager, indexer, and dashboard versions should be compatible; cluster nodes should generally run the same version.
- **Regular upgrades**: Schedule upgrades to get new features, performance improvements, and bug fixes.

### 8.2 Proactive Monitoring of the Wazuh Stack

- **Service status**: Regularly verify that **wazuh-dashboard**, **wazuh-indexer**, and **wazuh-manager** are active (e.g. `systemctl status wazuh-manager`, `systemctl status wazuh-indexer`).
- **Logs**: Check component logs for errors:
  - Dashboard: `journalctl -u wazuh-dashboard | grep -i -E "error|warn"`
  - Manager: `/var/ossec/logs/ossec.log`
- **Connectivity**: Ensure the dashboard can reach the indexer and manager API. Use **Stack Status** and **Data Sources** in this app to test Manager and Indexer connections.

### 8.3 Troubleshoot Common Data Issues

- **Data delays**: Inventory data (e.g. installed software) is collected by the agent’s syscollector on an interval (e.g. every 1 hour). Changes may take up to that interval to appear.
- **Missing data**: To force an inventory update, restart the agent (`sudo systemctl restart wazuh-agent`) if `scan_on_start` is enabled.
- **Direct index inspection**: For deep troubleshooting, query indices directly (e.g. Wazuh Dashboard Dev Tools or indexer API). Example: `GET /wazuh-states-inventory-packages-*/_search?pretty` for raw package data.

---

## Phase 9: Advanced Customization and Automation

### 9.1 Customize Look and Feel (Branding)

- **Official Wazuh Dashboard** (from 4.12.0): Customize loading logo, main logo, and PDF report logo via `/etc/wazuh-dashboard/opensearch_dashboards.yml` and `opensearchDashboards.branding` settings.
- **This dashboard (Sentinel Core)**: Branding is done by editing the app’s templates and static assets (`templates/`, `static/css/style.css`, `static/js/app.js`). No separate branding config file.

### 9.2 Automate Reporting

- **Official Wazuh Dashboard**: Use the built-in reporting feature to schedule PDF reports from dashboards and email them (e.g. daily or weekly).
- **This dashboard**: Focus is on live dashboards. For automated PDF reports, use the official Wazuh Dashboard reporting feature; reports can include your branded logo and key metrics.

### 9.3 Alerts from Dashboard Searches

- **Official Wazuh Dashboard**: Create a saved search in Discover (e.g. `rule.level > 15 AND agent.os.platform: "windows"`), then create an alert based on that search. Notifications (email, Slack, etc.) can fire when new documents match the criteria.
- **This dashboard**: Does not currently provide saved-search alerting. Use the official Wazuh Dashboard or external monitoring (e.g. alerting on indexer or manager) for proactive notifications based on search criteria.

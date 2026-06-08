# IT Hygiene Feature – Implementation Guide

This document describes how the IT Hygiene–style views (System, Software, Processes, Identity) were implemented so you can extend or replicate the pattern.

## Can we do it? Yes.

The reference UIs (Wazuh IT Hygiene: Dashboard, System, Software, Processes, Identity) are all implementable with the current stack:

- **Backend:** Flask + Wazuh Indexer (Elasticsearch-compatible)
- **Frontend:** HTML + CSS + vanilla JS
- **Data:** Wazuh inventory indices populated by Syscollector

## Data sources (Wazuh indexer indices)

| View       | Index pattern                           | Main fields |
|-----------|------------------------------------------|-------------|
| System    | `wazuh-states-inventory-system-*`       | agent.name, host.os.platform, host.os.name, host.os.version, host.os.kernel.release, host.architecture |
| Software  | `wazuh-states-inventory-packages-*`      | agent.name, package.vendor, package.name, package.version, package.type |
| Processes | `wazuh-states-inventory-processes-*`     | agent.name, process.name, process.start, process.pid, process.parent.pid, process.command_line |
| Identity  | `wazuh-states-inventory-users-*`        | agent.name, user.name, user.groups, user.shell, user.home |

Other available patterns (for future tabs):  
`wazuh-states-inventory-hardware-*`, `wazuh-states-inventory-ports-*`, `wazuh-states-inventory-services-*`, `wazuh-states-inventory-groups-*`, `wazuh-states-inventory-browser-extensions-*`.

## Implementation overview

### 1. Backend (`wazuh_client.py`)

- **Summary APIs:** Aggregations (terms/cardinality) for “Top 5” and counts:
  - `get_inventory_system_summary()` → top_platforms, top_os, top_architecture
  - `get_inventory_packages_summary()` → top_vendors, package_types, unique_packages
  - `get_inventory_processes_summary()` → top_processes
  - `get_inventory_processes_start_histogram()` → date_histogram on `process.start`
  - `get_inventory_users_summary()` → top_users, top_groups, top_shells

- **List APIs:** Paginated search with optional filters (e.g. cluster_name, platform, vendor, process_name, user_name):
  - `get_inventory_system_list()`, `get_inventory_packages_list()`, `get_inventory_processes_list()`, `get_inventory_users_list()`

- **Filtering:** All accept optional `cluster_name` (and view-specific filters) and build an Elasticsearch `bool.must` query.

### 2. Flask routes (`app.py`)

- `/api/inventory/system/summary` and `/api/inventory/system/list`
- `/api/inventory/packages/summary` and `/api/inventory/packages/list`
- `/api/inventory/processes/summary`, `/api/inventory/processes/histogram`, `/api/inventory/processes/list`
- `/api/inventory/users/summary` and `/api/inventory/users/list`

Query parameters: `size`, `offset`, `cluster_name`, and view-specific filters (e.g. `platform`, `name`, `architecture` for system; `vendor`, `package_name`, `package_type` for packages; etc.).

### 3. Frontend

- **Page:** “IT Hygiene” in sidebar and top nav; one page with four sub-tabs (System, Software, Processes, Identity).
- **Sub-tabs:** Buttons with `data-hygiene="system|software|processes|identity"`; clicking calls `setHygieneSubtab(active)` which shows the corresponding `.hygiene-view` and loads that view’s data.
- **Global filter:** Optional “wazuh.cluster.name” text input; value is sent as `cluster_name` to all inventory APIs.
- **Per view:**
  - **Summary:** Top 5 (and similar) rendered with `renderHygieneBarList()` (bar items with count).
  - **Table:** Rows from the list API; columns match the index fields (e.g. agent.name, host.os.*, package.*, process.*, user.*).
  - **Pagination:** Prev/Next with `HYGIENE_PAGE_SIZE` (15); offset state per view (`hygieneSystemOffset`, etc.).
- **Processes:** “Processes start time” uses the same `drawTimeline()` as the overview, fed by the histogram API.

### 4. CSS (`static/css/style.css`)

- `.hygiene-subnav`, `.hygiene-subtab`, `.hygiene-filters`, `.hygiene-view`, `.hygiene-chart-list`, `.hygiene-table-footer`, `.hygiene-pagination` for layout and styling consistent with the rest of the dashboard.

## How to extend

- **More filters:** Add dropdowns or inputs (e.g. Platform, Name, Architecture for System); in JS build `URLSearchParams` and pass to the existing list/summary APIs; in backend add the corresponding `wazuh_client` parameters and `bool.must` clauses.
- **Export:** Add an “Export” button that requests the same list API with a larger `size` (or a new export endpoint) and triggers a CSV/download in the browser.
- **Sort:** List APIs already accept `sort_field` and `sort_order`; add column-header controls that set these and reload the list.
- **Network / Services / Hardware:** Add new sub-tabs and new backend functions that query `wazuh-states-inventory-ports-*`, `wazuh-states-inventory-services-*`, `wazuh-states-inventory-hardware-*` in the same pattern (summary aggs + paginated list).
- **Rows per page:** Add a dropdown that sets `HYGIENE_PAGE_SIZE` and resets offset before calling the list loader.

## Prerequisites

- Wazuh agents must have Syscollector enabled so that inventory data is sent to the manager and indexed into the `wazuh-states-inventory-*` indices.
- If an index pattern returns no data, the UI will show “No data” or empty charts; verify indices in Data Sources and that the indexer has the expected mapping (e.g. `process.start` as date for the process start histogram).

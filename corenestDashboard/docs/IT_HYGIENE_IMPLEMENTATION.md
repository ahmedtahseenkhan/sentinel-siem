# Asset Management (IT Hygiene) – Implementation Guide

This document describes how the Asset Management views (System, Software, Processes, Identity) are implemented so you can extend or replicate the pattern.

## Architecture

- **Backend:** Flask + WatchVault/OpenSearch (Elasticsearch-compatible query API)
- **Frontend:** HTML + CSS + vanilla JS
- **Data:** Endpoint inventory emitted by the agent's syscollector and process collectors, indexed into the events index.

## Data source

All inventory views query the **events index** — `EVENTS_INDEX = "{INDEX_PREFIX}-events-*"` (default `watchvault-events-*`) — and filter by `event_type`. Fields are **flat** (text type → use `.keyword` for aggregations).

| View       | `event_type`            | Main flat fields |
|-----------|--------------------------|------------------|
| System    | `syscollector.os`        | platform, os_name, arch, agent_id, hostname |
| Software  | `syscollector.packages`  | name, version, arch, vendor, format |
| Processes | `process.new`            | name, pid, ppid, cmdline, create_time |
| Identity  | `syscollector.users`     | username, shell, type |

Other event types available for future tabs: `syscollector.hardware`, `syscollector.services`, `syscollector.ports`.

> **Note:** Processes use the `process.new` event stream (live process starts), not a `syscollector.processes` snapshot. This is why the Processes tab can show data while a snapshot-only view would not.

## Implementation overview

### 1. Backend (`watchtower_client.py`)

- **Summary APIs:** Aggregations (terms/cardinality) for "Top 5" and counts:
  - `get_inventory_system_summary()` → top_platforms, top_os, top_architecture
  - `get_inventory_packages_summary()` → top_vendors, package_formats, unique_packages
  - `get_inventory_processes_summary()` → top_processes
  - `get_inventory_processes_start_histogram()` → date_histogram on `timestamp`
  - `get_inventory_users_summary()` → top_users, top_shells, top_types

- **List APIs:** Paginated search with optional filters (e.g. cluster_name, platform, vendor, process_name, user_name):
  - `get_inventory_system_list()`, `get_inventory_packages_list()`, `get_inventory_processes_list()`, `get_inventory_users_list()`

- **Filtering:** All accept optional `cluster_name` (and view-specific filters) and build a `bool.must` query, always pinned to the appropriate `event_type` term.

### 2. Flask routes (`app.py`)

- `/api/inventory/system/summary` and `/api/inventory/system/list`
- `/api/inventory/packages/summary` and `/api/inventory/packages/list`
- `/api/inventory/processes/summary`, `/api/inventory/processes/histogram`, `/api/inventory/processes/list`
- `/api/inventory/users/summary` and `/api/inventory/users/list`

Query parameters: `size`, `offset`, `cluster_name`, and view-specific filters (e.g. `platform`, `name`, `architecture` for system; `vendor`, `package_name`, `package_type` for packages; etc.).

### 3. Frontend (`static/js/app.js`)

- **Page:** "Asset Management" in sidebar and top nav; one page with four sub-tabs (System, Software, Processes, Identity).
- **KPI strip:** `loadHygieneKpis()` populates the Systems/Packages/Processes/Identities cards and the header meta from the four endpoints, independent of the active sub-tab.
- **Sub-tabs:** Buttons with `data-hygiene="system|software|processes|identity"`; clicking calls `setHygieneSubtab(active)` which shows the corresponding `.hygiene-view` and loads that view's data.
- **Global filter:** Optional cluster-name text input; value is sent as `cluster_name` to all inventory APIs.
- **Per view:**
  - **Summary:** Top 5 (and similar) rendered with `renderHygieneBarList()` (bar items with count).
  - **Table:** Rows from the list API; columns match the flat fields (e.g. agent_name, platform/os_name, package name/vendor/version, process name/pid/cmdline, username/shell).
  - **Pagination:** Prev/Next with `HYGIENE_PAGE_SIZE` (15); offset state per view (`hygieneSystemOffset`, etc.).
- **Processes:** "Processes start time" uses the same `drawTimeline()` as the overview, fed by the histogram API.

### 4. CSS (`static/css/style.css`)

- `.hygiene-subtab`, `.hygiene-view`, and the shared `.kpi`, `.card`, `.tbl` classes for layout consistent with the rest of the dashboard.

## How to extend

- **More filters:** Add dropdowns or inputs (e.g. Platform, Name, Architecture for System); in JS build `URLSearchParams` and pass to the existing list/summary APIs; in backend add the corresponding `watchtower_client` parameters and `bool.must` clauses.
- **Export:** Add an "Export" button that requests the same list API with a larger `size` (or a new export endpoint) and triggers a CSV/download in the browser.
- **Sort:** List APIs accept `sort_field` and `sort_order`; add column-header controls that set these and reload the list.
- **Services / Hardware / Ports:** Add new sub-tabs and new backend functions that filter `event_type = syscollector.services|hardware|ports` in the same pattern (summary aggs + paginated list).
- **Rows per page:** Add a dropdown that sets `HYGIENE_PAGE_SIZE` and resets offset before calling the list loader.

## Prerequisites

- The agent's syscollector and process collectors must be enabled so inventory events (`syscollector.os`, `syscollector.packages`, `process.new`, `syscollector.users`) flow to the manager and are indexed into the events index.
- If a view is empty, the corresponding `event_type` has no documents. Verify in Data Sources (or `GET /{INDEX_PREFIX}-events-*/_search` filtered by `event_type`) that the events exist. A common case: packages/processes report but `syscollector.os` does not — that's a collector gap, not a UI bug.

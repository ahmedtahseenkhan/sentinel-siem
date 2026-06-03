# Sentinel SIEM Project Overview

## 1. At a Glance
**Project:** Sentinel SIEM - An end-to-end security monitoring, threat detection, and compliance platform.
**Stack:** Go, Python (Flask), OpenSearch, SQLite, Docker, gRPC, Sigma rules
**Platform:** Endpoint Agent (Windows/Linux) + Backend Server (Web App + REST/gRPC APIs)
**Status:** Active deployment / Production-ready

## 2. Commands
**Server / Backend Start:** `docker compose -f docker-compose.local.yaml up -d`
**Server / Backend Stop:** `docker compose -f docker-compose.local.yaml down`
> ⚠️ The running dev/single-host stack is defined by **`docker-compose.local.yaml`** (single-node OpenSearch on `opensearch:9200`, single WatchTower reachable directly on `watchtower:9400`, no HAProxy). Always target this file locally. `docker-compose.full.yaml` is the **multi-node production topology** (3-node OpenSearch cluster `opensearch-node1/2/3`, HAProxy, dual WatchTower) — do NOT run `full.yaml` against a `local.yaml` deployment; the service names/volumes differ and it will clobber the stack. Other variants: `docker-compose.ha.yaml`, `docker-compose.esxi.yaml`, `docker-compose.test-nodes.yaml`.
**WatchNode Agent Build (Windows):** `cd WatchNode/cmd/agent && GOOS=windows GOARCH=amd64 go build -o watchnode.exe`
**WatchNode Agent Build (Linux):** `cd WatchNode/cmd/agent && GOOS=linux GOARCH=amd64 go build -o watchnode-linux`
**Agent Bulk Deployment:** `.\deploy-to-all-machines.ps1 -ServerIP <IP> -CsvFile machines.csv`
**Agent Status Check:** `curl http://localhost:9400/api/v1/agents`

**Tests (WatchTower):** `cd WatchTower && go test -race ./...`
**Tests (WatchNode):** `cd WatchNode && go test -race ./...`
**Per-role rule pipeline smoke:** `cd WatchTower && go test -race -v -run TestRolePipeline ./internal/engine/`
**Engine perf benchmark:** `cd WatchTower && go test -run X -bench BenchmarkSustainedEPS -benchtime 1x ./internal/engine/`
**CI:** runs automatically on push via `.github/workflows/ci.yml`

## 3. Architecture
- `/WatchNode` → Go-based endpoint agent (collectors for FIM, osquery, registry, SCA, etc.)
- `/WatchTower` → Go-based manager (Sigma rules engine, SQLite state management, active response, gRPC API)
- `/WatchVault` → Go-based indexer (OpenSearch routing, data pipeline)
- `/sentinelCoreDashboard` → Python/Flask web dashboard application
- `/WatchTower/rules` → Sigma YAML detection rules directory
- `docker-compose.local.yaml` → **The running local/single-host stack** (single-node OpenSearch, single WatchTower, Kafka, Postgres, WatchVault, 2 WatchNodes, dashboard). Use this one locally.
- `docker-compose.full.yaml` → Multi-node production topology (3-node OpenSearch + OpenSearch Dashboards + HAProxy + dual WatchTower). Not for local use.

## 4. Key Patterns
- **Communication:** Strict use of gRPC between the Agent (WatchNode) → Manager (WatchTower) → Indexer (WatchVault).
- **Data Storage:** SQLite is used in WatchTower for agent state and quick alert lookups. OpenSearch is used via WatchVault for heavy event indexing and historical aggregation.
- **Rule Engine:** Native Wazuh-style YAML schema (NOT Sigma — Sigma support exists in `sigma/` as a secondary engine). Rules use `field: {equals: X}` or the legacy `{value: X}` (both honoured by the compiler since the Week-3 loader fix). 3,000+ rules across 90 files in [WatchTower/rules/](WatchTower/rules/). Both `rules:`-wrapped and bare-list YAML files load.
- **Web Dashboard:** Connects to both WatchTower APIs (for agent/alert summaries) and OpenSearch (for deep discovery, aggregations, and metrics like MITRE ATT&CK or compliance).
- **Alert enrichment:** `EnricherHook` interface on the engine, called between dedup and store so attached context (VirusTotal reputation, etc.) lands in the persisted alert. See [WatchTower/internal/enrich/](WatchTower/internal/enrich/).
- **Whodata:** FIM events are tagged with the user that touched the file. Linux via the audit collector tailing `/var/log/audit/audit.log`; Windows via 4663/4656 from the Security event log. Lookup cache in [WatchNode/internal/whodata/](WatchNode/internal/whodata/).

## 5. Code Style
- **Language:** Go (Backend services), Python (Dashboard).
- **Structure:** Standard Go project layout (`cmd/`, `internal/`, `pkg/`).
- **Error handling:** Standard Go error returns, properly wrapped with context for logging.
- **Dashboard:** Flask app uses server-side rendering with Jinja2 templates, keeping REST API endpoints prefixed with `/api/`.

## 6. Known Issues / Warnings
- Agent communication to the Manager requires port `50051 (TCP)` to be open on the firewall.
- The web dashboard runs on port `5050 (TCP)` by default.
- WatchVault depends heavily on OpenSearch; it requires OpenSearch to be healthy before starting up properly.
- Ensure the correct server IP is configured in the agent's `agent.yaml` before executing the bulk deployment scripts.
- **Postfix rule batch (3900) is coarse** — `TestRolePipeline_Postfix` produces 0 alerts on the canonical fixture; tighten field-match patterns when needed per customer.
- **Apache rule batch (3300) requires `source: apache` tag** — if the agent ships events without it, traversal/XSS rules won't fire. Either set the tag in the agent config or loosen the rule.
- **AD rule batch is broad** — a single 4625 event currently fires ~12 rules. This is real signal across batches 1000/2300/3000/6700-6900 (logon, escalation, MITRE) but operators may want to dedup-by-event in the dashboard.

## 6a. Audit-first development pattern
This codebase has had 14 bugs in code that initially looked "shipped". Before building any new capability, **read the existing code first** — it has paid off 9 of 14 times. Specifically:
- `Active Response`, `Vulnerability Detection`, `Cloud connectors`, `TI integration`, `Rootcheck` all had scaffolding that needed bug fixes rather than new code
- `FIM whodata` was genuinely absent — only true greenfield item

When the comparison table says "❌", verify by reading the code, not by trusting the label.

## 7. Current Task / Recent Decisions
**Recent Decisions (chronological — see [CHANGELOG.md](CHANGELOG.md) for the full diff):**
- Adopted a microservices architecture separating the Manager (WatchTower) and Indexer (WatchVault) to allow independent scaling.
- Integrated OpenSearch as the primary backend for log, alert, and event storage instead of a traditional relational DB.
- Standardized on a Wazuh-style native YAML rule schema for threat detection. Sigma kept as a secondary engine. Native rules total ~3,000 across 90 files.
- Automated client deployment via PowerShell and `nssm` for Windows services to quickly onboard large fleets (e.g., 60 machines).
- **3-week hardening sprint** closed every actionable item from an 8-week capability plan: per-role rule-pipeline test harness, VirusTotal enrichment, MISP feed, O365/Workspace/Defender ingestion, FIM whodata, OS-aware vuln matching, real AWS SigV4. 14 bugs in pre-existing scaffolding fixed, including 2 critical (rule compiler ignoring `value:` syntax, rule loader rejecting bare-array files — ~800 rules silently absent). Engine verified at 850k EPS sustained on Apple M5.
- **EDR build-out sprint** added the detection+response core of an EDR: enabled active-response on agents (PR #29, was `enabled:false` → all commands denied), real **host isolation** (#30), **ransomware canary** (#31), and **in-memory YARA** (#32). Constraints to remember: agent is `CGO_ENABLED=0` static + runs in `distroless:nonroot` in dev → active-response/memory features can't be exercised in the dev container and must be validated on a real endpoint (Windows SYSTEM / Linux root). Kernel-inline prevention, PPL tamper protection, and ransomware rollback are deliberately out of scope (need a signed kernel driver / MS vendor program).

## 7a. Per-role setup guides
[docs/per-role/](docs/per-role/) — one operator-facing markdown per server role (AD, IIS, MSSQL, Apache, Postfix, sshd). Each is cross-referenced to its `TestRolePipeline_*` test in [WatchTower/internal/engine/per_role_test.go](WatchTower/internal/engine/per_role_test.go) so docs stay accurate as rules evolve.

---

## 8. Detailed Project Summary
Sentinel SIEM (Security Information and Event Management) is a comprehensive, end-to-end security monitoring and threat detection platform. It is designed to collect, analyze, and store security events from endpoint machines (with a strong focus on Windows environments), evaluate them against security rules, and present actionable insights through a centralized web dashboard.

The project mirrors enterprise-grade security solutions (like Wazuh or Elastic Security) by providing agent-based telemetry collection, a centralized rule engine, an indexing layer, and a custom visualization interface.

### Core Architecture & Components
The platform is built using a modern, microservices-oriented architecture divided into four main pillars:

#### A. WatchNode (The Agent)
*   **Language:** Go
*   **Purpose:** A lightweight, high-performance agent installed on endpoint machines.
*   **Key Features:**
    *   **Collectors:** Integrates multiple data collectors including File Integrity Monitoring (FIM), system logs, registry monitoring, process & network tracking, and Docker events.
    *   **Security Configuration Assessment (SCA):** Evaluates local system configurations against defined security policies.
    *   **Osquery Integration:** Capable of running scheduled queries to extract granular OS state information.
    *   **Communication:** Streams telemetry data securely to the manager via gRPC.

#### B. WatchTower (The Manager)
*   **Language:** Go
*   **Purpose:** The central intelligence hub that processes all incoming telemetry from WatchNode agents.
*   **Key Features:**
    *   **Rules Engine:** Evaluates incoming events against detection rules. It natively supports parsing and executing community **Sigma rules**.
    *   **Threat Intelligence & Vulnerability Scanning:** Matches system inventory against known vulnerabilities (CVEs) and threat intel feeds.
    *   **Active Response:** Orchestrates automated responses to detected threats.
    *   **State Management:** Uses a local SQLite database to maintain the state of agents, groups, and recent alerts.

#### C. WatchVault (The Indexer)
*   **Language:** Go
*   **Purpose:** The data pipeline and indexing bridge.
*   **Key Features:**
    *   Receives processed events and alerts from WatchTower via gRPC.
    *   Buffers, transforms, and routes data into **OpenSearch**.
    *   Manages OpenSearch indices (e.g., rotating indices based on time/size like `watchvault-alerts-*`).

#### D. Sentinel Core Dashboard (The UI)
*   **Language:** Python (Flask)
*   **Purpose:** The central user interface for Security Operations Center (SOC) analysts and IT admins.
*   **Key Features:**
    *   Provides an overview of risk scores, system health, and critical incidents.
    *   Displays MITRE ATT&CK mappings, top threat sources, and at-risk devices/users.
    *   Monitors agent health and connection status.
    *   Tracks compliance metrics (e.g., HIPAA).
    *   Interacts with WatchTower and WatchVault APIs to fetch real-time and historical data.

#### E. Infrastructure & Deployment
*   **Server Stack:** Deployed via `docker-compose.full.yaml` bringing up OpenSearch, OpenSearch Dashboards, WatchTower, and WatchVault on a central Ubuntu server.
*   **Client Deployment:** Includes automated PowerShell scripts (`deploy-to-all-machines.ps1`) and batch files designed to deploy WatchNode across fleets of machines (e.g., a target of 60 Windows machines).
*   **Documentation:** Extensive implementation and deployment guides (`START_HERE.md`, `IMPLEMENTATION_GUIDE.md`, etc.) outlining team roles, capacity planning, and firewall configurations.

## 9. Capability matrix (vs. Wazuh)

| Capability | Status | Notes |
|---|---|---|
| Generic OS signals (logon, process, network, FIM, registry) | ✅ | Plus 14 collector bug fixes from the hardening sprint |
| Pre-built detection rules | ✅ 3,000+ | Native YAML, organized by tactic / source / framework |
| MITRE ATT&CK rule mapping | ✅ | Explicit per-rule `mitre:` block with tactic + technique IDs |
| Compliance frameworks (PCI/HIPAA/GDPR/NIST/SOC2/CIS) | ✅ | 290 rules tagged by `groups: [compliance, <framework>, <control>]`; dashboard queries via `term: rule.groups = <framework>` |
| Active Response (auto-block IP, kill PID, disable user, restart svc) | ✅ | Agent honors firewall-drop/kill-process/disable-account/restart-service with safelist (IPs+users), TTL auto-unblock, idempotent dedup. Gated by `active_response.enabled` — now ON in the shipped agent configs (PR #29) |
| EDR: host isolation (network quarantine) | ✅ | `isolate-host`/`unisolate-host` (PR #30): blocks all traffic except the manager IP; refuses if the manager is unresolvable (no self-lockout); auto-releases after the block TTL. Dashboard Isolate/Release buttons + playbook action. **Validate on a real endpoint — not exercisable in the distroless/nonroot dev container.** |
| EDR: ransomware canary detection | ✅ | `ransomware_canary` collector (PR #31) plants decoy files, emits critical `ransomware.canary` (rule 19570, MITRE T1486) on tamper; attach an isolate playbook for auto-containment |
| EDR: in-memory YARA scanning | ⚠️ | `yara_memory` collector (PR #32) scans process memory via the `yara` binary (no CGO), emits `yara.match` (rule 19860, MITRE T1620). Wired + **shipped disabled** — needs the `yara` binary on the endpoint (Linux pkg / bundled `yara64.exe`) |
| EDR: kernel-inline prevention · PPL tamper protection · ransomware rollback · on-sensor exploit prevention | ❌ | Out of scope — require a signed kernel driver / Microsoft anti-malware vendor program. Position the product as **SIEM/XDR with EDR-grade detection + response**, NOT a CrowdStrike-class pre-execution prevention EDR |
| Vulnerability Detection | ✅ | NVD JSON feed + 6h cache + dpkg/rpm-aware version comparator + vendor disambiguation + version-range start + OS-aware matching |
| FIM whodata (who changed the file) | ✅ | Linux: auditd; Windows: 4663/4656 from Security event log; FIM emit enriched with `user`, `process_name`, `audit_uid` |
| Cloud connectors | ✅ | AWS GuardDuty + CloudTrail (real SigV4, S3 polling), Azure Activity, GCP Audit (works off-GCE via JWT), O365 Mgmt API, Google Workspace Admin Reports, Microsoft Defender Graph Security |
| Threat-intel integration | ✅ | 7 sources: AbuseIPDB, OTX, plaintext, Feodo Tracker, MalwareBazaar, URLhaus, MISP. CDB Manager is race-safe with field-normalization and CIDR support |
| VirusTotal alert enrichment | ✅ | Rate-limited + TTL-cached, attaches to `Alert.Enrichment["virustotal"]` |
| Container/Docker collection | ✅ | |
| In-product dashboards | ✅ | Flask + Chart.js; per-framework compliance endpoints |
| Config audit log | ✅ | |
| Silent-source monitoring | ✅ | |
| Scheduled PDF reports | ✅ | weasyprint + APScheduler + SMTP delivery |
| Per-role test harness | ✅ | `TestRolePipeline_*` for AD/IIS/MSSQL/Apache/Postfix/sshd/Compliance |
| Per-role setup docs | ✅ | [docs/per-role/](docs/per-role/) |
| Performance | ✅ | 850,000 EPS sustained on M5 with full 3k rule set loaded |
| Pre-built decoders for app logs (Apache, IIS, MSSQL, sshd, sudo, ...) | ⚠️ | Generic file tail works; per-app field extraction added on demand per customer (we did NOT import Wazuh's XML decoders — dropped to avoid GPL maintenance) |
| End-to-end agent↔manager smoke test against real OpenSearch | ❌ | Rule pipeline is covered by `TestRolePipeline_*`; the wire format + persistence layer is not. Listed as future work in [docs/per-role/README.md](docs/per-role/README.md). |

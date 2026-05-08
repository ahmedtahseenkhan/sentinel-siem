# Sentinel SIEM Project Overview

## 1. At a Glance
**Project:** Sentinel SIEM - An end-to-end security monitoring, threat detection, and compliance platform.
**Stack:** Go, Python (Flask), OpenSearch, SQLite, Docker, gRPC, Sigma rules
**Platform:** Endpoint Agent (Windows/Linux) + Backend Server (Web App + REST/gRPC APIs)
**Status:** Active deployment / Production-ready

## 2. Commands
**Server / Backend Start:** `docker-compose -f docker-compose.full.yaml up -d`
**Server / Backend Stop:** `docker-compose -f docker-compose.full.yaml down`
**WatchNode Agent Build (Windows):** `cd WatchNode/cmd/agent && GOOS=windows GOARCH=amd64 go build -o watchnode.exe`
**Agent Bulk Deployment:** `.\deploy-to-all-machines.ps1 -ServerIP <IP> -CsvFile machines.csv`
**Agent Status Check:** `curl http://localhost:9400/api/v1/agents`

## 3. Architecture
- `/WatchNode` → Go-based endpoint agent (collectors for FIM, osquery, registry, SCA, etc.)
- `/WatchTower` → Go-based manager (Sigma rules engine, SQLite state management, active response, gRPC API)
- `/WatchVault` → Go-based indexer (OpenSearch routing, data pipeline)
- `/sentinelCoreDashboard` → Python/Flask web dashboard application
- `/WatchTower/rules` → Sigma YAML detection rules directory
- `docker-compose.full.yaml` → Orchestrates OpenSearch, OpenSearch Dashboards, WatchTower, and WatchVault.

## 4. Key Patterns
- **Communication:** Strict use of gRPC between the Agent (WatchNode) → Manager (WatchTower) → Indexer (WatchVault).
- **Data Storage:** SQLite is used in WatchTower for agent state and quick alert lookups. OpenSearch is used via WatchVault for heavy event indexing and historical aggregation.
- **Rule Engine:** The Go-based rules engine natively parses and executes community Sigma YAML rules directly into executable matches.
- **Web Dashboard:** Connects to both WatchTower APIs (for agent/alert summaries) and OpenSearch (for deep discovery, aggregations, and metrics like MITRE ATT&CK or HIPAA).

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

## 7. Current Task / Recent Decisions
**Recent Decisions:**
- Adopted a microservices architecture separating the Manager (WatchTower) and Indexer (WatchVault) to allow independent scaling.
- Integrated OpenSearch as the primary backend for log, alert, and event storage instead of a traditional relational DB.
- Standardized on Sigma rules for threat detection to instantly leverage community-driven threat intelligence.
- Automated client deployment via PowerShell and `nssm` for Windows services to quickly onboard large fleets (e.g., 60 machines).

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

## 9. What Has Been Achieved
Based on the codebase analysis, the following capabilities have been successfully implemented:

1.  **Agent Telemetry:** Built a robust Go-based agent capable of pulling deep OS-level metrics, logs, registry changes, and FIM data, making use of tools like osquery.
2.  **Advanced Threat Detection:** Implemented a complex rules engine in Go that parses Sigma YAML rules directly, converting them into executable matches without requiring external conversion tools.
3.  **Vulnerability & Compliance Tracking:** Added SCA evaluators and vulnerability fetchers to constantly assess the security posture of endpoints.
4.  **Scalable Data Pipeline:** Established a high-throughput gRPC pipeline between the Agent, Manager, and Indexer, ultimately storing data in OpenSearch for fast retrieval.
5.  **Polished Web Interface:** Developed a Flask-based web application featuring a modern UI layout. It includes sophisticated data aggregation (using OpenSearch queries) to display timelines, severity breakdowns, and compliance stats.
6.  **Production-Ready Automation:** Created deployment scripts and detailed documentation allowing a team (Project Manager, Linux Admin, Windows Admin, SecOps) to take the project from zero to a fully monitored 60-machine deployment in a matter of weeks.

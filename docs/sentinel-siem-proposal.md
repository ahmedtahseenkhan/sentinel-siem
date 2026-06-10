---
title: "Sentinel SIEM — Service & Capability Proposal"
author: "Security Operations Division"
date: "June 2026"
geometry: "margin=2.5cm"
fontsize: 11pt
linestretch: 1.4
colorlinks: true
---

---

# Sentinel SIEM
## Security Information & Event Management Platform
### Technical Capability & Service Proposal

---

**Prepared for:** \[Client Name\]  
**Prepared by:** \[Your Name / Company\]  
**Document date:** June 2026  
**Document version:** 1.0  

---

\newpage

# 1. Executive Summary

Sentinel SIEM is a fully self-contained, enterprise-grade Security Information and Event Management platform purpose-built to give your organisation continuous visibility into threats across endpoints, servers, cloud environments, and SaaS applications.

The platform delivers:

- **Real-time threat detection** across 3,000+ pre-built detection rules covering every major attack tactic
- **MITRE ATT&CK-aligned coverage** with explicit tactic and technique mappings on every rule
- **Automated Active Response** — isolate hosts, block IPs, kill processes, and disable accounts within seconds of detection
- **Built-in compliance reporting** for PCI DSS, HIPAA, GDPR, NIST 800-53, SOC 2, and CIS Controls
- **Deep cloud coverage** across AWS, Azure, GCP, Microsoft 365, Google Workspace, and Microsoft Defender
- **Vulnerability management** with NVD-backed CVE matching and OS-aware scope enforcement
- **Threat intelligence enrichment** from 7 live feeds including MISP, AbuseIPDB, AlienVault OTX, and VirusTotal

The platform is delivered as a managed, containerised service — no on-premises hardware procurement required. You get enterprise-level security operations centre (SOC) capability at a fraction of the cost of traditional SIEM vendors.

---

\newpage

# 2. Platform Architecture

Sentinel SIEM is built on a modern microservices architecture with four core components that work together seamlessly.

## 2.1 WatchNode — Endpoint Agent

A lightweight Go binary deployed silently to each endpoint (Windows and Linux). It operates as a persistent system service and streams telemetry securely to the central manager over an encrypted gRPC channel.

**Collected telemetry types:**

| Collector | What It Captures |
|---|---|
| File Integrity Monitoring (FIM) | Creation, modification, and deletion of files and directories — with the identity of who made the change (whodata) |
| Windows Event Log | Security, System, Application, and PowerShell operational logs |
| Process monitoring | Process start/stop, parent-child relationships, command lines |
| Network connections | Inbound/outbound connections, listening ports, protocol details |
| Registry monitoring | Key and value creation, modification, and deletion (Windows) |
| Security Configuration Assessment | Baseline hardening audit against CIS benchmarks |
| Osquery integration | Scheduled ad-hoc queries against OS state |
| Docker / container events | Container lifecycle and runtime behaviour |
| System inventory | Installed software, running services, OS version, hardware profile |

## 2.2 WatchTower — Central Manager

The intelligence hub. Receives telemetry from all agents, evaluates it against 3,000+ detection rules in real time, manages agent state, orchestrates active responses, and exposes the REST and gRPC APIs consumed by the dashboard and downstream systems.

## 2.3 WatchVault — Indexer & Data Pipeline

Routes all processed events and alerts into OpenSearch for long-term retention, historical querying, and aggregation. Manages index rotation and retention policies.

## 2.4 CoreNest Dashboard

A web-based SOC analyst interface providing real-time visualisations, alert triage, agent health, compliance dashboards, and MITRE ATT&CK heat maps.

---

\newpage

# 3. Detection & Threat Intelligence

## 3.1 Detection Rule Library — 3,000+ Rules Across 91 Files

The rule library is the core of the platform's detection capability. Rules are organised by tactic, data source, compliance framework, threat actor group, and technology stack.

### Coverage by Category

| Category | Rule Files | Examples |
|---|---|---|
| **Endpoint — Windows** | 15+ files | Authentication events, PowerShell attacks, WMI abuse, Scheduled Task persistence, Sysmon deep-dive |
| **Endpoint — Linux** | 6+ files | Audit syscalls, privilege escalation, cron persistence, SSH brute force |
| **Active Directory** | 2 files | Kerberoasting, Pass-the-Hash, DCSync, golden ticket, privilege escalation |
| **Web Applications** | 3 files | SQLi, XSS, path traversal, RFI, web shells, advanced injection |
| **Cloud — AWS** | 1 file | CloudTrail anomalies, GuardDuty findings, S3 exposure, IAM abuse |
| **Cloud — Azure** | 1 file | Azure Activity log, Azure AD events, suspicious sign-ins |
| **Cloud — GCP** | 1 file | GCP audit log, service account abuse, compute anomalies |
| **Microsoft 365** | 3 files | Exchange audit, SharePoint access, Teams exfiltration, MAPI/EWS abuse |
| **Network / Firewall** | 4 files | Cisco ASA, Palo Alto, Fortinet FortiGate, F5 BIG-IP, Snort/Suricata IDS |
| **Database** | 4 files | MSSQL, MySQL, PostgreSQL, Bind DNS audit |
| **Mail Server** | 2 files | Postfix, Exim, Exchange |
| **Container / Kubernetes** | 4 files | Docker escape, Kubernetes RBAC abuse, Helm supply chain, runtime anomalies |
| **Threat Intel matching** | 1 file | IP/domain/hash matching against live threat feeds |
| **Malware / Ransomware** | 3 files | Known ransomware TTPs, encryption behaviour, exfiltration staging |
| **Lateral Movement** | 1 file | SMB, WMI, PsExec, RDP pivoting |
| **MITRE ATT&CK** | 7 dedicated files | Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery & Lateral Movement |
| **Compliance** | 6 files | PCI DSS, HIPAA, GDPR, NIST 800-53, SOC 2, CIS Controls |
| **APT / Nation-State** | 6 files | Russia (APT28/29), China (APT40/41), North Korea (Lazarus), Iran (APT33/34), cross-actor TTPs |
| **eCrime** | 2 files | Ransomware-as-a-Service groups, financial crime syndicates |
| **Specialty / Emerging** | 7 files | Mobile/MDM, IoT/Edge, OT/ICS/SCADA, 5G gateways, email security, DLP, identity governance, data warehouse & AI |

## 3.2 MITRE ATT&CK Mapping

Every detection rule carries an explicit `mitre:` block with tactic and technique identifiers (e.g., `TA0001 / T1078`). The dashboard renders this as a live ATT&CK heat map showing which techniques have been observed across your environment in the selected time window.

## 3.3 Threat Intelligence Integration

Sentinel SIEM pulls from **7 live threat intelligence sources** and applies them in real time against inbound events:

| Source | What It Provides |
|---|---|
| AbuseIPDB | Crowd-sourced malicious IP database |
| AlienVault OTX | Indicators of compromise: IPs, domains, hashes, URLs |
| Feodo Tracker | Botnet C2 server IP block list |
| MalwareBazaar | Malware file hash database |
| URLhaus | Malicious URL database |
| MISP | Your own or a shared threat intelligence platform (custom feed) |
| Plaintext custom lists | Bring-your-own IOC lists in plain IP/hash/domain format |

Feeds are stored in a race-safe in-memory CDB with CIDR range support. A failed feed fetch never overwrites the last known-good list.

## 3.4 VirusTotal Alert Enrichment

When the engine raises an alert involving a file hash, IP address, or URL, it automatically submits the indicator to VirusTotal and attaches the verdict to the alert before it is stored and forwarded. Free-tier safe (4 requests/minute token bucket, 1-hour TTL cache).

---

\newpage

# 4. Active Response (Automated Remediation)

Sentinel SIEM does not just alert — it acts. The Active Response engine allows pre-configured playbooks to execute automatically when a rule fires, with full operator controls and safeguards.

## 4.1 Built-in Response Actions

| Action | Platforms | Effect |
|---|---|---|
| Block IP | Linux / Windows | Adds the source IP to the host firewall deny list |
| Kill Process | Linux / Windows | Terminates the identified malicious process by PID |
| Isolate Host | Linux / Windows | Drops all network connectivity except to the SIEM manager |
| Disable User Account | Linux / Windows | Locks the compromised account immediately |
| Custom script | Any | Execute any operator-defined remediation script |

## 4.2 Safeguards

- **Safelist** — define IP ranges and user accounts that can never be blocked or disabled, preventing accidental lockout of administrators and monitoring systems
- **TTL auto-unblock** — every block carries a configurable expiry; the host is automatically restored when the TTL expires without operator intervention
- **Idempotent deduplication** — a rule firing repeatedly on the same host does not trigger the same action multiple times within the TTL window
- **Dry-run mode** — simulate the full response chain and log what *would* have been executed without making any real changes; ideal for testing playbooks before live deployment
- **Audit trail** — every response action is logged with timestamp, triggering rule ID, agent ID, and action taken

---

\newpage

# 5. Compliance Reporting

Sentinel SIEM provides out-of-the-box compliance dashboards and API endpoints for six major regulatory and standards frameworks.

| Framework | Standard / Regulation |
|---|---|
| **PCI DSS** | Payment Card Industry Data Security Standard |
| **HIPAA** | Health Insurance Portability and Accountability Act |
| **GDPR** | General Data Protection Regulation |
| **NIST 800-53** | National Institute of Standards and Technology Security Controls |
| **SOC 2** | Service Organization Controls (Trust Services Criteria) |
| **CIS Controls** | Center for Internet Security Critical Security Controls (v8) |

Each framework dashboard shows:

- Total events tagged to this framework in the selected period
- Alert breakdown by severity (critical / high / medium / low)
- Top triggered controls and the raw events behind them
- Trend line over the last 30 days
- Export to PDF for auditor submission

290+ detection rules are pre-tagged to one or more compliance frameworks, so the moment a relevant event is detected it appears automatically in the appropriate compliance dashboard.

### Scheduled PDF Compliance Reports

Reports can be generated on a schedule (daily, weekly, monthly) and delivered by email to your compliance team or auditors. Reports include the dashboard summary, alert tables, and a signed time-stamp.

---

\newpage

# 6. Cloud & SaaS Coverage

Sentinel SIEM ingests security data from all major cloud platforms natively. No third-party connectors or additional licensing is required.

## 6.1 Cloud Infrastructure

| Platform | Data Source | What Is Monitored |
|---|---|---|
| **AWS** | CloudTrail + GuardDuty | API calls, IAM changes, S3 policy changes, GuardDuty findings, root account use |
| **Azure** | Azure Activity Log | Resource CRUD operations, RBAC changes, policy violations, suspicious sign-ins |
| **GCP** | GCP Audit Log | Admin activity, data access, system events — works off-GCE with a service account JWT |

## 6.2 SaaS Productivity Platforms

| Platform | Data Source | What Is Monitored |
|---|---|---|
| **Microsoft 365** | O365 Management Activity API | Exchange, SharePoint, Azure AD, Teams, and General audit logs |
| **Google Workspace** | Admin Reports API | Admin console, login activity, Drive access, token grants |
| **Microsoft Defender** | Graph Security API | Unified alerts from Defender for Endpoint, Office 365, Cloud Apps, Identity, and Sentinel |

All cloud collectors use native authenticated APIs with cursor-based polling to ensure no event is missed across restarts.

---

\newpage

# 7. Vulnerability Management

Sentinel SIEM includes a built-in vulnerability detection engine that correlates your endpoint software inventory against the NIST National Vulnerability Database (NVD).

## 7.1 How It Works

1. WatchNode collects the full software inventory from every endpoint on every check-in cycle
2. WatchTower matches installed package names and versions against the NVD CVE feed (refreshed every 6 hours)
3. Matches are filtered by operating system to eliminate false positives (e.g., a Linux OpenSSL CVE will not fire on a Windows host)
4. Confirmed CVE hits are raised as alerts with CVSS score, CVE ID, affected version range, and the specific package name

## 7.2 Key Capabilities

- **OS-aware scope** — vendor + CPE-based OS disambiguation prevents cross-platform false positives
- **Version-range matching** — handles open-ended ranges ("all versions before X.Y.Z")
- **dpkg and rpm aware** — understands Debian and Red Hat package naming conventions
- **6-hour feed refresh** — newly published CVEs surface within hours
- **Dashboard view** — per-agent and per-CVE drill-down in the web interface

---

\newpage

# 8. File Integrity Monitoring (FIM) with Whodata

Sentinel SIEM FIM tracks changes to files and directories in real time and — critically — records the **identity of the user or process** that made the change (whodata).

## 8.1 What Is Captured

| Field | Description |
|---|---|
| Path | Full path of the file or directory changed |
| Change type | Created / Modified / Deleted |
| Hash (before/after) | SHA-256 of file content before and after the change |
| User | The OS user account that performed the change |
| Process | The process name and PID that performed the change |
| Audit UID | The original login UID (Linux), preserved across `su` or `sudo` |
| Timestamp | Precise time of the change |

## 8.2 Platform Implementation

- **Linux**: Uses the kernel audit subsystem (`auditd`). Audit rules are installed automatically for all monitored paths when `fim.whodata: true` is set in the agent configuration
- **Windows**: Reads Security event log events 4663 (object access) and 4656 (handle close) and correlates them with FIM events

FIM rules are pre-loaded in the rule library with alerting for changes to sensitive system paths (e.g., `/etc/passwd`, Windows SAM hive, system32) and any path the operator designates.

---

\newpage

# 9. Security Configuration Assessment (SCA)

WatchNode performs automated security configuration audits on every endpoint it monitors, evaluating the local configuration against defined policy benchmarks.

- Checks are run on every agent check-in and after configuration changes
- Findings are categorised as Pass / Fail / Not Applicable
- CIS benchmark policies are pre-loaded for Windows Server and Linux
- Custom policy files can be deployed to target any operator-defined configuration requirement
- Results appear in the dashboard per-agent and in aggregate

---

\newpage

# 10. Agent Fleet Management

## 10.1 Deployment

| Deployment Method | Platform | Notes |
|---|---|---|
| Automated PowerShell script (`deploy-to-all-machines.ps1`) | Windows | Reads a CSV of target machines, deploys the agent, installs as a Windows Service via NSSM |
| Batch install script | Windows | Single-machine silent install |
| Shell script | Linux | Installs and registers the systemd service |
| Manual binary deploy | Windows / Linux | Place binary, configure `agent.yaml`, start service |

## 10.2 Fleet Visibility

From the dashboard and API you can see, per agent:

- Online / offline / stale status with last-seen timestamp
- Agent version and operating system
- Current IP address and hostname
- Event and alert throughput (events per minute)
- Active response actions currently in effect on this host
- Open alerts associated with this host

## 10.3 Bulk Operations

- Push configuration updates to all agents or a group simultaneously
- Re-deploy to failed agents automatically via the `remediate-offline-agents.ps1` script
- Group agents by role (e.g., "domain controllers", "web servers") and apply different rule sets or response policies per group

---

\newpage

# 11. SOC Dashboard

The CoreNest Dashboard is the primary interface for your security operations team. It is a web application accessible from any browser, requiring no software installation.

## 11.1 Dashboard Sections

| Section | What It Shows |
|---|---|
| **Overview** | Risk score trend, active alert count by severity, agent health, recent critical events |
| **Alerts** | Searchable, filterable alert list with full event detail, enrichment data, and response history |
| **MITRE ATT&CK** | Heat map of tactics and techniques observed in the environment |
| **Agents** | Fleet health, per-agent status and telemetry rates |
| **Compliance** | Per-framework dashboard: PCI DSS, HIPAA, GDPR, NIST 800-53, SOC 2, CIS |
| **Vulnerability Management** | Per-host CVE findings with CVSS scores |
| **Threat Intelligence** | Feed health, matched IOC events |
| **Cloud** | Ingestion status for each connected cloud / SaaS source |
| **Reports** | Scheduled and on-demand PDF report management |
| **Active Response** | Current blocks, isolations, and response history |

## 11.2 Search & Investigation

The platform exposes the full power of the OpenSearch query engine through the dashboard. Analysts can:

- Free-text search across all events and alerts
- Filter by time range, severity, rule ID, agent, data source, or any event field
- Build saved queries for recurring investigations
- Pivot from an alert directly to all raw events from the same agent in the same time window
- View MITRE tactic attribution on every alert

---

\newpage

# 12. Data Retention & Storage

| Data Type | Storage Backend | Retention |
|---|---|---|
| Raw events | OpenSearch | Configurable (default: 90 days) |
| Alerts | OpenSearch + SQLite | OpenSearch: configurable; SQLite: recent window for fast lookup |
| Agent state | SQLite | Persistent |
| Compliance reports (PDF) | Local filesystem | Configurable |
| Threat intel feeds | In-memory CDB | Refreshed on schedule; last-good preserved across restarts |

Index rotation and retention policies are managed automatically by WatchVault. Disk usage grows linearly with event volume and can be sized to your specific environment and retention requirement.

---

\newpage

# 13. Performance

| Metric | Value |
|---|---|
| Sustained events per second (EPS) | **850,000 EPS** through the full 3,000+ rule pipeline |
| Rule evaluation latency | Sub-millisecond per event |
| Agent check-in interval | Configurable (default: 60 seconds) |
| Threat intel feed refresh | Configurable per source (default: 1 hour) |
| Vulnerability feed refresh | Every 6 hours |
| Dashboard page load | < 2 seconds on a standard deployment |

Performance benchmarks were measured on a single host (Apple M5 class hardware). A production deployment sized for your environment will be scoped during onboarding.

---

\newpage

# 14. Deployment & Infrastructure

## 14.1 Server Requirements (Minimum — Single Tenant)

| Component | Specification |
|---|---|
| CPU | 4 cores (8 recommended) |
| RAM | 16 GB (32 GB recommended for > 50 agents) |
| Disk | 500 GB SSD (scale with event volume and retention) |
| OS | Ubuntu 22.04 LTS or RHEL 8/9 |
| Network | Static IP, port 50051 (TCP) inbound for agent gRPC, port 5050 (TCP) for dashboard |

## 14.2 Deployment Model

The entire server stack is containerised with Docker Compose. Deployment to a new client environment typically takes **under 2 hours** from a fresh Ubuntu server. The stack includes:

- OpenSearch (single-node or 3-node cluster for HA)
- WatchTower (manager)
- WatchVault (indexer)
- CoreNest Dashboard (web UI)
- Kafka (event bus between components)
- Postgres (operational database)

A high-availability topology with HAProxy and a 3-node OpenSearch cluster is available for environments requiring no single point of failure.

## 14.3 Network Requirements

| Port | Protocol | Purpose |
|---|---|---|
| 50051 | TCP | Agent-to-manager gRPC (WatchNode → WatchTower) |
| 5050 | TCP | Dashboard web UI (HTTPS in production) |
| 9200 | TCP | OpenSearch (internal, not exposed externally) |
| 9092 | TCP | Kafka (internal) |

---

\newpage

# 15. Services Included

## 15.1 Platform Deployment

- Server environment setup and Docker stack deployment
- TLS certificate configuration for encrypted agent communication
- Initial rule set load and tuning for your environment
- Dashboard configuration and user account setup

## 15.2 Agent Deployment

- Bulk automated deployment to Windows endpoints via PowerShell
- Linux agent deployment via shell script
- Agent configuration (`agent.yaml`) pre-populated with your server IP and monitoring paths
- Verification that all agents check in and are reporting

## 15.3 Integration & Onboarding

- Cloud connector configuration (AWS, Azure, GCP, M365, Google Workspace, Defender)
- Threat intelligence feed setup and validation
- Compliance framework alignment — confirming relevant rules are active for your regulatory requirements
- Custom FIM path configuration for your critical file locations
- Custom rule development for environment-specific detection requirements (included up to agreed scope)

## 15.4 Ongoing Support

- Rule library updates as new threats and techniques emerge
- Dashboard and platform version updates
- Threat intelligence feed health monitoring
- Scheduled compliance report delivery
- Incident investigation assistance on request

---

\newpage

# 16. What Sets Sentinel SIEM Apart

| Capability | Sentinel SIEM | Typical Open-Source SIEM | Cloud-Hosted Commercial SIEM |
|---|---|---|---|
| Pre-built detection rules | 3,000+ | Minimal | Vendor-limited |
| MITRE ATT&CK mapping | Every rule | Partial | Partial |
| Compliance frameworks | 6 built-in | Manual | Extra licence |
| Active Response (SOAR) | Native | Plugin / add-on | Extra licence |
| FIM with whodata | Native | Basic FIM only | Limited |
| Cloud connectors (6 platforms) | Native | Separate tools | Native but costly |
| Threat intel (7 feeds + MISP) | Native | Manual config | Extra licence |
| Vulnerability management | Native | Separate tool | Extra licence |
| VirusTotal enrichment | Native | Manual | Extra licence |
| APT / nation-state rules | 6 actor groups | None | Threat intel add-on |
| On-premises / self-hosted | Yes | Yes | No |
| Per-tenant deployment | Yes (single-tenant) | Varies | Multi-tenant by default |
| Performance | 850k EPS | Low–moderate | Vendor-managed |

---

\newpage

# 17. Engagement Scope

The following table summarises the services delivered as part of a standard engagement. Scope adjustments are agreed per client.

| Service Item | Included | Notes |
|---|---|---|
| Server deployment and configuration | Yes | Containerised, single or HA topology |
| Agent deployment (up to agreed fleet size) | Yes | Windows + Linux |
| Cloud connector setup (up to agreed platforms) | Yes | AWS / Azure / GCP / M365 / Workspace / Defender |
| Compliance framework alignment | Yes | All 6 frameworks |
| Custom FIM path configuration | Yes | |
| Threat intel feed setup | Yes | All 7 sources + MISP if applicable |
| VirusTotal enrichment configuration | Yes | Client API key required |
| Active response playbook configuration | Yes | Up to agreed number of playbooks |
| SOC dashboard user accounts | Yes | Unlimited |
| Scheduled compliance PDF reports | Yes | Daily / weekly / monthly |
| Custom rule development | Yes | Up to agreed scope |
| Knowledge transfer and handover documentation | Yes | |
| Ongoing platform updates | Yes | Monthly cadence |
| Ongoing rule library updates | Yes | |
| Incident investigation support | Yes | Per-incident, reasonable efforts basis |

---

\newpage

# 18. Next Steps

To proceed with a Sentinel SIEM deployment for your organisation:

1. **Scoping call** — We confirm the number of endpoints, cloud platforms, compliance frameworks, and any specific detection requirements
2. **Environment questionnaire** — You complete a short form covering OS versions, network topology, and access credentials for cloud connectors
3. **Proposal and agreement** — We provide a final scoped proposal and service agreement
4. **Deployment** — Server stack is deployed, agents are rolled out, and all integrations are validated end-to-end
5. **Handover** — Dashboard walkthrough, user training, and documentation delivered

**Typical time from signed agreement to live monitoring: 3–5 business days** for a standard environment.

---

*For questions regarding this proposal, please contact:*  
**Ahmed Tahseen Khan**  
ahmed.tahseen.khan@gmail.com

---

*This document contains proprietary information. It is intended solely for the named recipient and should not be distributed without prior written consent.*

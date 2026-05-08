# WatchTower

**Security Manager for the Watch Platform**

WatchTower is the central management and analysis server of the Watch security platform. It receives telemetry from distributed WatchNode agents over gRPC, runs events through a configurable pipeline of decoders and detection rules, generates alerts, and forwards enriched data to WatchVault for long-term indexing and search.

## Architecture

```
┌────────────┐         gRPC (50051)         ┌─────────────┐       gRPC (50052)       ┌────────────┐
│  WatchNode │ ────────────────────────────▶ │  WatchTower │ ──────────────────────▶  │ WatchVault │
│  (agents)  │  events, heartbeats, sysinfo  │  (manager)  │  alerts, events, FIM    │  (indexer)  │
└────────────┘                               └──────┬──────┘                          └─────┬──────┘
                                                    │ REST API (9400)                       │
                                               dashboards, SIEM                        OpenSearch
                                               integrations                            (storage)
```

WatchNode agents collect file integrity, process, network, system metrics, and log data from endpoints. WatchTower receives that telemetry, decodes raw messages into structured fields, evaluates detection rules, triggers active responses when thresholds are met, and batches everything to WatchVault for indexing into OpenSearch.

## Features

- **Agent Management** — Register, monitor, and group WatchNode agents; track heartbeats and connection state.
- **Rule Engine** — YAML-based detection rules with regex, equality, and substring field matching across multiple event types.
- **Decoders** — Regex-based field extraction pipelines that normalize raw syslog, JSON, and FIM events into structured data.
- **CDB Lists** — Constant database lookups (key-value flat files) for allowlists, blocklists, and enrichment during rule evaluation.
- **Active Response** — Automated countermeasures (process kill, firewall drop) triggered by high-severity rule matches and pushed back to agents.
- **Vulnerability Scanning** — Optional CVE feed integration for matching installed packages against known vulnerabilities.
- **Event Forwarding** — Batched gRPC streaming of events and alerts to WatchVault with configurable flush intervals.
- **REST API** — Full management API for agents, groups, rules, decoders, CDB lists, alerts, active response, and system status.
- **State Store** — Embedded SQLite database for persisting agent state, alerts, and registration data.

## Quick Start

### Build from Source

```bash
go build -o watchtower ./cmd/watchtower
```

### Run Locally

```bash
# Use the example config
cp configs/watchtower.yaml.example configs/watchtower.yaml

# Start WatchTower
./watchtower -config configs/watchtower.yaml
```

### Run with Docker

```bash
docker build -t watchtower .
docker run -p 50051:50051 -p 9400:9400 watchtower
```

### Run with Docker Compose

```bash
docker compose up -d
```

### Full Stack (with WatchVault + OpenSearch)

From the parent `Go/` directory:

```bash
docker compose -f docker-compose.full.yaml up -d
```

## Configuration

WatchTower loads configuration from YAML files. Search order:

1. Path passed via `-config` flag
2. `/etc/watchtower/config.yaml`
3. `~/.watchtower/config.yaml`
4. `./config.yaml`

### Reference

| Section | Key | Default | Description |
|---|---|---|---|
| `server.grpc` | `listen_address` | `:50051` | gRPC server bind address for agent connections |
| `server.grpc.tls` | `cert`, `key`, `ca` | `""` | TLS certificate paths for mutual TLS |
| `server.api` | `listen_address` | `:9400` | REST API bind address |
| `server.api.auth` | `api_key` | `""` | Bearer token for API authentication (empty = no auth) |
| `engine` | `rules_dir` | `/etc/watchtower/rules` | Directory containing YAML rule files |
| `engine` | `decoders_dir` | `/etc/watchtower/decoders` | Directory containing YAML decoder files |
| `engine` | `cdb_dir` | `/etc/watchtower/cdb` | Directory containing CDB list files |
| `engine` | `workers` | `4` | Number of parallel event processing workers |
| `vulnerability` | `enabled` | `false` | Enable CVE vulnerability scanning |
| `vulnerability` | `db_path` | `/var/lib/watchtower/vuln.db` | Path to vulnerability database |
| `vulnerability` | `update_interval` | `6h` | How often to refresh the CVE feed |
| `forwarder.watchvault` | `address` | `localhost:50052` | WatchVault gRPC address |
| `forwarder.watchvault` | `batch_size` | `500` | Events per bulk forward batch |
| `forwarder.watchvault` | `flush_interval` | `5s` | Maximum time before flushing a partial batch |
| `store` | `path` | `/var/lib/watchtower/state.db` | SQLite state database path |
| `logging` | `level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `logging` | `output` | `stdout` | Log output: `stdout` or a file path |

### Environment Variable Overrides

| Variable | Config Path |
|---|---|
| `WATCHTOWER_GRPC_LISTEN` | `server.grpc.listen_address` |
| `WATCHTOWER_API_LISTEN` | `server.api.listen_address` |
| `WATCHTOWER_API_KEY` | `server.api.auth.api_key` |
| `WATCHTOWER_STORE_PATH` | `store.path` |
| `WATCHTOWER_LOG_LEVEL` | `logging.level` |
| `WATCHTOWER_ENGINE_WORKERS` | `engine.workers` |

## API Endpoints

All endpoints are under `/api/v1` and require `Authorization: Bearer <api_key>` when an API key is configured.

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check (no auth required) |
| `GET` | `/api/v1/status` | Manager status and uptime |
| `GET` | `/api/v1/stats` | Aggregate statistics |
| `GET` | `/api/v1/agents` | List all registered agents |
| `GET` | `/api/v1/agents/{id}` | Get agent details |
| `DELETE` | `/api/v1/agents/{id}` | Remove an agent |
| `PUT` | `/api/v1/agents/{id}/group` | Assign agent to a group |
| `GET` | `/api/v1/groups` | List agent groups |
| `POST` | `/api/v1/groups` | Create a new group |
| `GET` | `/api/v1/groups/{id}` | Get group details |
| `DELETE` | `/api/v1/groups/{id}` | Delete a group |
| `GET` | `/api/v1/alerts` | List alerts |
| `POST` | `/api/v1/active-response` | Trigger an active response command |
| `GET` | `/api/v1/rules` | List loaded detection rules |
| `GET` | `/api/v1/rules/{id}` | Get a specific rule |
| `POST` | `/api/v1/rules` | Add a new rule at runtime |
| `GET` | `/api/v1/decoders` | List loaded decoders |
| `POST` | `/api/v1/decoders` | Add a new decoder at runtime |
| `GET` | `/api/v1/cdb-lists` | List CDB lists |
| `GET` | `/api/v1/cdb-lists/{name}` | Get a CDB list by name |
| `POST` | `/api/v1/cdb-lists` | Upload a new CDB list |

## Rule Format

Rules are defined in YAML files inside the rules directory. Each file contains a top-level `rules` array.

### Structure

```yaml
rules:
  - id: 5503            # Unique numeric ID
    level: 10           # Severity: 0 (lowest) to 15 (critical)
    description: "Critical system binary modified"
    groups:             # Tags for categorization and filtering
      - "fim"
      - "system_integrity"
      - "high_severity"
    match:
      type: "fim.modified"          # Event type to match
      fields:                       # Field-level conditions (all must match)
        path:
          regex: "^/(etc|bin|sbin|usr/bin|usr/sbin)/"
    cdb_lookup:                     # Optional CDB enrichment
      list: "audit-keys"
      field: "path"
    alert:
      title: "FIM: Critical system path modified"
    active_response:                # Optional automated response
      action: "kill-process"
      field: "pid"
    enabled: true
```

### Field Match Operators

| Operator | Description | Example |
|---|---|---|
| `regex` | Matches field value against a Go regular expression | `regex: "^root$"` |
| `equals` | Exact string equality | `equals: "ESTABLISHED"` |
| `contains` | Substring match | `contains: "error"` |

### Examples

**Detect reverse shell tools:**

```yaml
- id: 5601
  level: 12
  description: "Reverse shell tool spawned"
  groups: ["process", "attack", "reverse_shell", "critical"]
  match:
    type: "process.new"
    fields:
      name:
        regex: "^(nc|ncat|netcat|socat)$"
  alert:
    title: "Process: Reverse shell tool detected"
  active_response:
    action: "kill-process"
    field: "pid"
  enabled: true
```

**Detect SSH brute force:**

```yaml
- id: 5801
  level: 10
  description: "Multiple SSH authentication failures"
  groups: ["syslog", "authentication", "brute_force", "high_severity"]
  match:
    type: "log"
    fields:
      source:
        equals: "sshd"
      message:
        regex: "(message repeated|Failed password.*\\(([5-9]|[1-9][0-9]+) time)"
  alert:
    title: "Auth: SSH brute force attempt"
  active_response:
    action: "firewall-drop"
    field: "srcip"
  enabled: true
```

## Decoder Format

Decoders extract structured fields from raw event messages using regex capture groups.

### Structure

```yaml
decoders:
  - name: "syslog-header"
    description: "Extract syslog fields from RFC 3164 messages"
    match:
      type: "log"                   # Only process events of this type
      tags:                         # Optional tag-based filtering
        format: "syslog"
    extract:
      - field: "hostname"          # Target field name
        regex: "<pattern with (capture group)>"
      - field: "program"
        regex: "<another pattern>"
```

### Example

```yaml
decoders:
  - name: "syslog-kernel"
    description: "Extract kernel log messages"
    match:
      type: "log"
      tags:
        source: "kernel"
    extract:
      - field: "timestamp"
        regex: "^\\[\\s*(\\d+\\.\\d+)\\]"
      - field: "subsystem"
        regex: "^\\[\\s*\\d+\\.\\d+\\]\\s+(\\S+?):"
      - field: "message"
        regex: "^\\[\\s*\\d+\\.\\d+\\]\\s+(.+)$"
```

## Built-in Rules

WatchTower ships with detection rules covering five categories:

| File | IDs | Category | Rules |
|---|---|---|---|
| `0100-fim_rules.yaml` | 5500–5507 | File Integrity Monitoring | File created/modified/deleted, critical path changes, credential file tampering, SSH config changes, cron modifications, sudoers changes |
| `0200-process_rules.yaml` | 5600–5606 | Process Monitoring | New processes, reverse shell tools, crypto miners, reconnaissance tools, package managers, container tools, compilers/debuggers |
| `0300-network_rules.yaml` | 5700–5704 | Network Connections | New connections, suspicious ports (C2), high-port anomalies, IRC channels, Tor connections |
| `0400-syslog_rules.yaml` | 5800–5805 | Authentication & Logs | SSH failures, brute force detection, successful logins, root login, sudo commands, account changes |
| `0500-system_rules.yaml` | 5900–5903 | System Resources | High CPU (>90%), high memory (>90%), critical disk (>95%), runaway processes (>80% CPU) |

## License

Proprietary. All rights reserved.

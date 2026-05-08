# WatchVault

**Security Indexer for the Watch Platform**

WatchVault is the indexing and search backend of the Watch security platform. It receives security events, alerts, and telemetry from WatchTower over gRPC, transforms and routes them through a high-throughput pipeline, and bulk-indexes everything into OpenSearch for long-term storage, search, and visualization through OpenSearch Dashboards.

## Architecture

```
                          gRPC (50052)
┌─────────────┐  events, alerts, FIM  ┌────────────┐  bulk API   ┌────────────┐
│  WatchTower │ ─────────────────────▶│ WatchVault │ ──────────▶ │ OpenSearch │
│  (manager)  │                       │  (indexer)  │             │  (storage)  │
└─────────────┘                       └──────┬──────┘             └──────┬──────┘
                                             │ REST API (9500)          │
                                        search queries           ┌──────┴──────┐
                                        index management         │  Dashboards │
                                                                 │   (5601)    │
                                                                 └─────────────┘
```

WatchVault sits between WatchTower and OpenSearch. Incoming events are buffered, transformed into OpenSearch documents, routed to type-specific indices (events, alerts, FIM, system, vulnerability), and flushed in bulk batches. A REST API exposes search, index management, and cluster health endpoints.

## Features

- **Event Indexing** — High-throughput bulk indexing pipeline with configurable workers, buffer sizes, and flush intervals.
- **Intelligent Routing** — Events are automatically routed to the correct index based on event type (FIM, system metrics, vulnerabilities, alerts, general events).
- **Search API** — Query indexed data through a REST API that translates requests into OpenSearch queries.
- **Index Lifecycle Management** — Automated hot → warm → delete lifecycle with configurable rollover and retention policies.
- **Index Templates** — Pre-defined OpenSearch index templates with optimized mappings for each data type.
- **Cluster Health Monitoring** — Real-time OpenSearch cluster status exposed through the API.
- **Role-Based Access** — API key authentication with role-based authorization.
- **gRPC Ingestion** — Receives events and alerts from WatchTower via streaming gRPC for low-latency, high-throughput delivery.

## Quick Start

### Build from Source

```bash
go build -o watchvault ./cmd/watchvault
```

### Run Locally

WatchVault requires a running OpenSearch instance.

```bash
# Start OpenSearch (single-node, security disabled for development)
docker run -d --name opensearch \
  -e "discovery.type=single-node" \
  -e "DISABLE_SECURITY_PLUGIN=true" \
  -p 9200:9200 \
  opensearchproject/opensearch:2.12.0

# Copy and edit the config
cp configs/watchvault.yaml.example configs/watchvault.yaml

# Start WatchVault
./watchvault -config configs/watchvault.yaml
```

### Run with Docker Compose

This brings up WatchVault, OpenSearch, and OpenSearch Dashboards together:

```bash
docker compose up -d
```

Services will be available at:

| Service | URL |
|---|---|
| WatchVault gRPC | `localhost:50052` |
| WatchVault API | `http://localhost:9500` |
| OpenSearch | `http://localhost:9200` |
| OpenSearch Dashboards | `http://localhost:5601` |

### Full Stack (with WatchTower + WatchNode)

From the parent `Go/` directory:

```bash
docker compose -f docker-compose.full.yaml up -d
```

## Configuration

WatchVault loads configuration from YAML files. Search order:

1. Path passed via `-config` flag
2. `/etc/watchvault/config.yaml`
3. `~/.watchvault/config.yaml`
4. `./config.yaml`

### Reference

| Section | Key | Default | Description |
|---|---|---|---|
| `server.grpc` | `listen_address` | `0.0.0.0:50052` | gRPC server bind address |
| `server.grpc.tls` | `cert`, `key`, `ca` | `""` | TLS certificate paths |
| `server.api` | `listen_address` | `0.0.0.0:9500` | REST API bind address |
| `server.api.auth` | `api_key` | `""` | Bearer token for API authentication |
| `opensearch` | `addresses` | `["https://localhost:9200"]` | OpenSearch node URLs |
| `opensearch` | `username` | `admin` | OpenSearch username |
| `opensearch` | `password` | `admin` | OpenSearch password |
| `opensearch` | `insecure_skip_verify` | `false` | Skip TLS certificate verification |
| `opensearch` | `ca_cert` | `""` | Custom CA certificate path |
| `pipeline` | `workers` | `4` | Number of parallel pipeline workers |
| `pipeline` | `buffer_size` | `10000` | In-memory event buffer capacity |
| `pipeline` | `flush_interval` | `5s` | Maximum time before flushing a partial bulk batch |
| `pipeline` | `bulk_size` | `500` | Documents per bulk request |
| `indices` | `prefix` | `watchvault` | Index name prefix |
| `indices` | `rollover` | `daily` | Index rollover frequency |
| `indices` | `retention_days` | `90` | Days before indices are deleted |
| `indices` | `shards` | `1` | Primary shards per index |
| `indices` | `replicas` | `1` | Replica shards per index |
| `logging` | `level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `logging` | `output` | `""` | Log output: empty for stdout, or a file path |

### Environment Variable Overrides

| Variable | Config Path |
|---|---|
| `WATCHVAULT_GRPC_LISTEN` | `server.grpc.listen_address` |
| `WATCHVAULT_API_LISTEN` | `server.api.listen_address` |
| `WATCHVAULT_API_KEY` | `server.api.auth.api_key` |
| `WATCHVAULT_OPENSEARCH_URL` | `opensearch.addresses[0]` |
| `WATCHVAULT_OPENSEARCH_USER` | `opensearch.username` |
| `WATCHVAULT_OPENSEARCH_PASS` | `opensearch.password` |
| `WATCHVAULT_LOG_LEVEL` | `logging.level` |

## API Endpoints

All endpoints under `/api/v1` require `Authorization: Bearer <api_key>` when an API key is configured.

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check (no auth required) |
| `POST` | `/api/v1/search` | Search indexed events and alerts |
| `GET` | `/api/v1/indices` | List all WatchVault indices |
| `GET` | `/api/v1/indices/{name}/stats` | Get stats for a specific index |
| `GET` | `/api/v1/stats` | Pipeline and indexing statistics |
| `GET` | `/api/v1/cluster/health` | OpenSearch cluster health status |

### Search Example

```bash
curl -X POST http://localhost:9500/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{
    "index": "watchvault-alerts-*",
    "query": {
      "match": { "rule_groups": "brute_force" }
    },
    "size": 20,
    "sort": [{"timestamp": "desc"}]
  }'
```

## Index Types

WatchVault maintains five index types, each with optimized OpenSearch mappings. Indices follow the naming pattern `{prefix}-{type}-{date}` (e.g. `watchvault-alerts-2025.01.15`).

### Events (`watchvault-events-*`)

General-purpose index for all events that don't match a specialized type.

| Field | Type | Description |
|---|---|---|
| `timestamp` | `date` | Event timestamp (epoch milliseconds) |
| `event_type` | `keyword` | Event type identifier |
| `agent_id` | `keyword` | Source agent ID |
| `agent_name` | `keyword` | Source agent name |
| `message` | `text` | Raw event message (full-text searchable) |
| `fields` | `object` | Dynamic event-specific fields |
| `tags` | `keyword` | Event tags |
| `decoded` | `object` | Fields extracted by WatchTower decoders |

### Alerts (`watchvault-alerts-*`)

Alerts generated by WatchTower rule matches.

| Field | Type | Description |
|---|---|---|
| `timestamp` | `date` | Alert timestamp |
| `rule_id` | `integer` | Triggering rule ID |
| `rule_level` | `integer` | Rule severity level (0–15) |
| `rule_description` | `text` | Rule description (keyword sub-field) |
| `rule_groups` | `keyword` | Rule group tags |
| `agent_id` | `keyword` | Source agent |
| `title` | `text` | Alert title (keyword sub-field) |
| `event_type` | `keyword` | Original event type |
| `event_data` | `object` | Full triggering event data |

### FIM (`watchvault-fim-*`)

File integrity monitoring events.

| Field | Type | Description |
|---|---|---|
| `timestamp` | `date` | Event timestamp |
| `event_type` | `keyword` | `fim.added`, `fim.modified`, or `fim.deleted` |
| `agent_id` | `keyword` | Source agent |
| `path` | `keyword` | Full file path (text sub-field for search) |
| `sha256` | `keyword` | Current file hash |
| `previous_hash` | `keyword` | Previous file hash |
| `directory` | `keyword` | Parent directory |
| `filename` | `keyword` | File name |
| `action` | `keyword` | Action performed |

### System (`watchvault-system-*`)

System resource metrics from agents.

| Field | Type | Description |
|---|---|---|
| `timestamp` | `date` | Metric timestamp |
| `agent_id` | `keyword` | Source agent |
| `metric_type` | `keyword` | `cpu`, `memory`, `disk`, `network`, `process`, `load` |
| `cpu_percent` | `float` | CPU usage percentage |
| `memory_percent` | `float` | Memory usage percentage |
| `disk_percent` | `float` | Disk usage percentage |
| `process_name` | `keyword` | Process name |
| `pid` | `integer` | Process ID |
| `bytes_sent` / `bytes_recv` | `long` | Network I/O counters |
| `load_1m` / `load_5m` / `load_15m` | `float` | System load averages |

### Vulnerability (`watchvault-vulnerability-*`)

Vulnerability scan results.

| Field | Type | Description |
|---|---|---|
| `timestamp` | `date` | Scan timestamp |
| `agent_id` | `keyword` | Source agent |
| `package_name` | `keyword` | Affected package |
| `package_version` | `keyword` | Installed version |
| `cve_id` | `keyword` | CVE identifier |
| `severity` | `keyword` | `low`, `medium`, `high`, `critical` |
| `description` | `text` | Vulnerability description |
| `cvss_score` | `float` | CVSS score |
| `fixed_version` | `keyword` | Version that contains the fix |

## Index Lifecycle Management

WatchVault applies an automated lifecycle policy to all indices:

| State | Duration | Actions |
|---|---|---|
| **Hot** | 0–7 days | Active writes; rollover at 1 day age or 10M documents |
| **Warm** | 7–90 days | Replicas reduced to 0; force-merged to 1 segment for storage efficiency |
| **Delete** | >90 days | Index automatically deleted |

The retention period is configurable via `indices.retention_days`. Rollover frequency is controlled by `indices.rollover` (supports `daily` and `monthly`).

## License

Proprietary. All rights reserved.

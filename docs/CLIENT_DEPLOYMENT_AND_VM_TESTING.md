# Stage 2 — VM Lab Test & Client Deployment

This guide covers deploying Sentinel SIEM to a **real multi-machine environment**: one
Linux box runs the server stack, Windows/Linux endpoints run the WatchNode agent and
report in over the network.

It is written against your **test VM lab**, but the steps are identical for a **client
install** — only the IPs and machine count change. Validate here first; promote to the
client once the lab is green.

> **Run Stage 1 first** — [TESTING_ON_MACBOOK.md](TESTING_ON_MACBOOK.md). Don't deploy a
> build to the lab that hasn't passed the local smoke test.

---

## The lab topology

| VM (from ESXi) | Role in Sentinel | Notes |
|---|---|---|
| **Ubuntu LTS** | **Server** — runs the whole Docker stack (WatchTower, WatchVault, OpenSearch, Kafka, Postgres, dashboard) | The single "SIEM server". Note its IP — call it `SERVER_IP` below. |
| **DC01** (Win Server 2022) | WatchNode agent (Domain Controller — high-value: 4624/4625/4768 logon + AD events) | Best signal source; enroll first. |
| **Windows**, **Windows2** (Win10) | WatchNode agents (workstation telemetry) | Standard endpoint coverage. |
| **Pfsense** | Optional syslog source | Point pfSense syslog at `SERVER_IP:5140` (WatchTower syslog listener). |

Pick **one** machine to be the server. In the lab that's **Ubuntu LTS**. Everything else
is an agent.

---

## PART A — Server setup (Ubuntu LTS VM)

### A1. Requirements
- Ubuntu 20.04+ , **≥ 4 GB RAM**, ≥ 30 GB disk.
- Docker Engine + Docker Compose v2.
- A **static IP** the agents can reach. Find it: `ip -4 addr show | grep inet`.

Install Docker if needed:
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker
```

### A2. Copy the project to the server
Copy the repo (or at minimum `WatchTower/`, `WatchVault/`, `sentinelCoreDashboard/`, and
the compose file) to the Ubuntu VM, e.g. via `scp`/`rsync`/git.

### A3. Choose the right compose file
- **Single server (the lab, and most clients): `docker-compose.local.yaml`** — one
  OpenSearch node, one WatchTower. This is the supported single-host stack.
- Multi-node, HA client: `docker-compose.full.yaml` (3-node OpenSearch + HAProxy + dual
  WatchTower). Only use this when the client actually needs it.

For the lab:
```bash
cd /path/to/Go
docker compose -f docker-compose.local.yaml up -d --build
docker compose -f docker-compose.local.yaml ps   # wait for healthy
```

### A4. Open the firewall on the server
Agents connect to gRPC `50051`; you'll also want the dashboard and (optionally) syslog:
```bash
sudo ufw allow 50051/tcp   # agent -> manager (gRPC)   REQUIRED
sudo ufw allow 5050/tcp    # dashboard (browser)
sudo ufw allow 5140/tcp    # syslog ingest (pfSense etc.) — optional
# 9200 (OpenSearch) / 9400 (WatchTower REST) — keep internal unless you need them remotely
```

### A5. Verify the server
```bash
curl -s http://localhost:9200/_cluster/health
curl -s -H "X-API-Key: sentinel-dev-api-key" http://localhost:9400/api/v1/agents
```
Then browse to **`http://SERVER_IP:5050`** → log in `admin` / `admin`.

> **Production hardening note:** the local stack ships with dev credentials
> (`admin/admin`, API key `sentinel-dev-api-key`, enroll token
> `sentinel-enroll-secret-2024`). **Change these before a real client deployment** — see
> [Hardening for clients](#part-d--hardening-before-a-client-goes-live).

---

## PART B — Deploy the Windows agents (DC01, Windows, Windows2)

### B1. Build the Windows agent binary
On your Mac (or any machine with Go 1.21+):
```bash
cd WatchNode/cmd/agent
GOOS=windows GOARCH=amd64 go build -o watchnode.exe .
```
Output: `watchnode.exe` (~16 MB). For Linux endpoints use `GOOS=linux GOARCH=amd64`.

### B2. Write the agent config
Create `agent.yaml` (one per machine, or reuse with `{{hostname}}` for the name). This is
the **current** schema — note `enroll_token` lives under `manager:` and **must match**
the server's `WATCHTOWER_GRPC_ENROLL_TOKEN`:

```yaml
agent:
  name: "{{hostname}}"          # auto-uses the Windows computer name
  labels:
    environment: lab            # use "production" at a client
    team: security
manager:
  url: "SERVER_IP:50051"        # <-- Ubuntu LTS VM IP
  enroll_token: "sentinel-enroll-secret-2024"   # MUST match the server token
  reconnect:
    max_attempts: 0
    initial_backoff: "2s"
    max_backoff: "60s"
collectors:
  system:   { enabled: true, interval: "30s" }
  process:  { enabled: true, interval: "30s" }
  network:  { enabled: true, interval: "120s" }
  logs:
    enabled: true
    sources:
      - { type: eventlog, channels: ["Security", "System", "Application"], tags: [windows] }
  syscollector:
    enabled: true
    interval: "1h"
```

> **DC01 specifically:** keep `logs.eventlog` with the **Security** channel enabled — that's
> where 4624/4625/4768/4769 and AD events come from, which the AD rule batches key off.

### B3. Install on each Windows machine

Copy `watchnode.exe` + `agent.yaml` to the machine (e.g. `C:\Sentinel\WatchNode\`), then,
from an **Administrator** PowerShell/cmd, pick one method:

**Method 1 — native Windows service (recommended).** The binary installs/removes itself
via the Service Control Manager:
```bat
cd C:\Sentinel\WatchNode
watchnode.exe --install --config C:\Sentinel\WatchNode\agent.yaml
sc start SentinelWatchNode
```
Remove later with `watchnode.exe --uninstall`.

**Method 2 — run in the foreground (quick test / first connect).**
```bat
cd C:\Sentinel\WatchNode
watchnode.exe --config agent.yaml
```
You'll see it connect to the manager and start collectors. `Ctrl+C` to stop.

> **Flag note:** the agent uses **`--config`** (the older `install-watchnode.bat` passes
> `-c`, which this binary does not register — use `--config`).

**Method 3 — nssm** (only if you prefer nssm over the native service):
```bat
nssm install SentinelWatchNode "C:\Sentinel\WatchNode\watchnode.exe" "--config C:\Sentinel\WatchNode\agent.yaml"
nssm start SentinelWatchNode
```

### B4. Open the *outbound* firewall on the endpoint (usually allowed by default)
```bat
netsh advfirewall firewall add rule name="SentinelWatchNode" dir=out action=allow protocol=tcp remoteport=50051 program="C:\Sentinel\WatchNode\watchnode.exe"
```

### B5. Bulk deployment (many endpoints / a real client fleet)
For a fleet, use the repo's PowerShell pusher with a CSV of machine names:
```powershell
.\deploy-to-all-machines.ps1 -ServerIP SERVER_IP -CsvFile machines.csv
```
> Before bulk-deploying to a client, edit the config block inside
> `deploy-to-all-machines.ps1` to **add `enroll_token` under `manager:`** — the script's
> built-in template predates the enroll-token requirement, so agents it deploys will be
> rejected by a server that enforces the token until you add it.

---

## PART C — Verify the end-to-end pipeline

1. **Server sees the agents:**
   ```bash
   curl -s -H "X-API-Key: sentinel-dev-api-key" http://SERVER_IP:9400/api/v1/agents | python3 -m json.tool
   ```
   DC01, Windows, Windows2 should appear with recent last-seen times.

2. **Dashboard:** `http://SERVER_IP:5050` → **Agents** shows all endpoints "active";
   **Discover** shows events flowing.

3. **Generate a real detection** — on DC01 or a Win10 box, trigger a failed logon
   (e.g. `runas /user:bogus cmd` with a wrong password a few times). Within a minute it
   should land as a **4625** event and fire AD logon-failure rules — check the dashboard
   **Alerts/Discover**.

4. **Confirm indexing:**
   ```bash
   curl -s http://SERVER_IP:9200/_cat/indices?v | grep watchvault
   ```

If all four pass in the lab, you're ready to repeat against the client.

---

## PART D — Hardening before a client goes live

The local stack uses dev defaults. For a client, change these (in the compose
environment on the server, then restart the stack):

| Setting | Dev default | Change to |
|---|---|---|
| Dashboard admin login | `admin` / `admin` | strong per-client password |
| Dashboard super-admin | `superadmin` / `superadmin` | strong password |
| `WATCHTOWER_API_KEY` / `WATCHVAULT_API_KEY` | `sentinel-dev-api-key` | unique random key |
| `WATCHTOWER_GRPC_ENROLL_TOKEN` | `sentinel-enroll-secret-2024` | unique per-client token (and update every agent `agent.yaml`) |
| Postgres password | `watchtower_dev_pass` | strong password |

Also recommended for clients: enable **mTLS** between agents and the manager (populate
`manager.tls.{cert,key,ca}` in the agent config and the matching server certs in
`certs/`), set container CPU/memory limits, and put OpenSearch on a data disk with
snapshots.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Agent: "connection refused" | Wrong `SERVER_IP`, or server firewall not allowing `50051/tcp`. `Test-NetConnection SERVER_IP -Port 50051` from the endpoint. |
| Agent connects then drops, never appears | `enroll_token` missing or doesn't match `WATCHTOWER_GRPC_ENROLL_TOKEN`. |
| Agent listed but no Windows events | Security event log channel not enabled in `agent.yaml`, or agent not running as Administrator/Service. |
| No data on Discover at all | OpenSearch unhealthy — `docker compose -f docker-compose.local.yaml logs opensearch`. |
| `/api/v1/agents` 401 | Missing `X-API-Key` header. |
| pfSense logs not arriving | pfSense remote syslog must target `SERVER_IP:5140`, and `5140/tcp` open on the server. |

---

### Quick reference
- **Server up:** `docker compose -f docker-compose.local.yaml up -d --build`
- **Server down:** `docker compose -f docker-compose.local.yaml down`
- **Agents API:** `curl -H "X-API-Key: <key>" http://SERVER_IP:9400/api/v1/agents`
- **Dashboard:** `http://SERVER_IP:5050`
- **Build Windows agent:** `cd WatchNode/cmd/agent && GOOS=windows GOARCH=amd64 go build -o watchnode.exe .`
- **Install as service:** `watchnode.exe --install --config agent.yaml`

## WatchNode Agent (client)

Cross-platform security telemetry agent written in Go (Linux/Windows/macOS).

## WatchNode Manager (server)

Central gRPC manager that accepts agent registration, heartbeats, and streaming telemetry over mTLS.

### What it does (current)

- System metrics: CPU, memory, disk, network I/O, uptime, host info
- Process monitoring: new processes (pid/ppid/cmdline)
- File integrity monitoring: fsnotify-based change detection + periodic scan (SHA256)
- Log collection: file tailing with rotation re-open and basic multiline; journald/eventlog stubs
- Secure transport: gRPC with mTLS, bi-directional stream, batching, heartbeat, reconnect backoff
- Service install:
  - Linux: systemd unit (`watchnode.service`)
  - macOS: launchd plist (`com.watchnode.agent.plist`)
  - Windows: installer script guidance (service install via `sc.exe`/NSSM)

### Build

```bash
go build -o watchnode ./cmd/agent
go build -o watchnode-manager ./cmd/manager
```

### Local end-to-end (manager + agent) with mTLS

Generate local test certs:

```bash
./scripts/gen-certs.sh
```

Run the manager:

```bash
./watchnode-manager --config configs/manager.yaml.example
```

Run the agent (in another terminal):

```bash
./watchnode --config configs/agent.yaml.example
```

### Run on Linux with Docker (host monitoring)

This runs **manager + agent** with mTLS. The agent is configured to see the **host** (not just the container):

- `pid: host` (host process list)
- `network_mode: host` (host network connections)
- bind mounts for `/etc`, `/usr/bin`, `/var/log` into `/host/...`

Steps:

```bash
./scripts/gen-certs.sh
docker compose up --build
```

Note: for host monitoring the `agent` container is run as `root` in `docker-compose.yml` so it can write its state to the mounted volume at `/var/lib/watchnode`.

Configs used:

- `configs/manager.docker.yaml`
- `configs/agent.docker.yaml`

If you want **container-only** monitoring, comment out `pid: "host"` and `network_mode: "host"` in `docker-compose.yml` and update the paths in `configs/agent.docker.yaml` to non-`/host/...` paths.

### Config

Copy `configs/agent.yaml.example` to `/etc/watchnode/agent/config.yaml` and edit:

```bash
sudo mkdir -p /etc/watchnode/agent
sudo cp configs/agent.yaml.example /etc/watchnode/agent/config.yaml
```

### Environment overrides (agent)

- `WATCHNODE_AGENT_ID`
- `WATCHNODE_MANAGER_URL`
- `WATCHNODE_MANAGER_CA`, `WATCHNODE_MANAGER_CERT`, `WATCHNODE_MANAGER_KEY`

### Run (foreground)

```bash
./watchnode --config /etc/watchnode/agent/config.yaml
```

### Install as a service

Linux:

```bash
./scripts/install-linux.sh
sudo systemctl start watchnode
```

macOS:

```bash
./scripts/install-macos.sh
```

Windows (PowerShell as Admin):

```powershell
.\scripts\install-windows.ps1
```

### Regenerate protobuf code

If you edit `pkg/proto/agent.proto`:

```bash
./scripts/genproto.sh --docker
```

### Go module

`github.com/watchnode/watchnode`

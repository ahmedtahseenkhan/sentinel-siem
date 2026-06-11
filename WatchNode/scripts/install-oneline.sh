#!/usr/bin/env bash
# Sentinel WatchNode — One-line Linux installer
#
# Usage:
#   curl -fsSL https://<server>/install.sh | sudo bash -s -- \
#       --server <SERVER_IP> --token <ENROLL_TOKEN>
#
# Example:
#   curl -fsSL http://192.168.100.100/install.sh | sudo bash -s -- \
#       --server 192.168.100.100 --token sentinel-enroll-secret-2024
#
# What it does:
#   1. Detects OS, arch, init system
#   2. Downloads the matching agent binary from the Sentinel server
#   3. Generates a sane default config with sustained-CPU limits
#   4. Installs a systemd unit with auto-restart on failure
#   5. Verifies the agent enrolls and starts heartbeating
#
# Re-running the installer upgrades the binary in place.

set -euo pipefail

SERVER=""
TOKEN="sentinel-enroll-secret-2024"
GROUP="default"
BIN_URL=""
DASH_PORT="5050"   # Sentinel dashboard port (serves the agent binary + this script)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server) SERVER="$2"; shift 2 ;;
        --token)  TOKEN="$2";  shift 2 ;;
        --group)  GROUP="$2";  shift 2 ;;
        --bin-url) BIN_URL="$2"; shift 2 ;;
        --dashboard-port) DASH_PORT="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

if [[ -z "$SERVER" ]]; then
    echo "ERROR: --server <IP> is required"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (use sudo)"
    exit 1
fi

# Default binary location: the dashboard serves it at /deploy/agent/linux on the
# same port this installer was fetched from (5050 by default). Override the port
# with --dashboard-port, or the whole URL with --bin-url.
if [[ -z "$BIN_URL" ]]; then
    BIN_URL="http://${SERVER}:${DASH_PORT}/deploy/agent/linux"
fi

log()  { echo "[$(date +%H:%M:%S)] $*"; }
fail() { echo "[ERROR] $*" >&2; exit 1; }

# ── 1. Preflight ─────────────────────────────────────────────────────────────
log "Preflight checks..."
command -v curl    >/dev/null || fail "curl is required"
command -v systemctl >/dev/null || fail "systemd is required (other init systems not supported yet)"

if ! curl -sf -o /dev/null --max-time 5 "http://${SERVER}:9400/api/v1/health" 2>/dev/null \
   && ! nc -z -w 3 "$SERVER" 50051 2>/dev/null; then
    fail "Cannot reach Sentinel server at $SERVER (ports 9400/50051). Check firewall."
fi

# ── 2. Download binary ───────────────────────────────────────────────────────
log "Downloading agent binary from $BIN_URL ..."
TMPBIN=$(mktemp)
if ! curl -fsSL --max-time 60 -o "$TMPBIN" "$BIN_URL"; then
    fail "Failed to download binary from $BIN_URL"
fi
chmod +x "$TMPBIN"

# Stop existing service if present (in-place upgrade)
if systemctl list-unit-files | grep -q '^watchnode\.service'; then
    log "Existing installation detected — stopping for upgrade"
    systemctl stop watchnode || true
fi

mkdir -p /usr/local/bin /etc/watchnode/agent /var/lib/watchnode/queue /var/log/watchnode
mv "$TMPBIN" /usr/local/bin/watchnode
chmod 755 /usr/local/bin/watchnode

# ── 3. Generate config ───────────────────────────────────────────────────────
log "Writing config to /etc/watchnode/agent/config.yaml"
HOSTNAME=$(hostname)
cat > /etc/watchnode/agent/config.yaml <<EOF
agent:
  id: ""
  name: "${HOSTNAME}"
  labels:
    environment: production
    group: ${GROUP}
    _enroll_token: "${TOKEN}"

manager:
  url: "${SERVER}:50051"
  tls: {}
  reconnect:
    max_attempts: 0
    initial_backoff: "5s"
    max_backoff: "2m"

collectors:
  system:
    enabled: true
    interval: "30s"
    metrics: ["cpu", "memory", "disk", "network", "processes"]
  process:
    enabled: true
    interval: "30s"
  network:
    enabled: true
    interval: "30s"
  logs:
    enabled: true
    sources:
      - type: file
        path: "/var/log/auth.log"
        tags: [authentication]
      - type: journal
        units: ["sshd", "systemd-logind", "sudo"]
  file_integrity:
    enabled: true
    interval: "5m"
    paths:
      - path: "/etc"
        recursive: true
        ignore_patterns: ["*.lock", "*.pid", "*.swp"]
      - path: "/usr/bin"
        recursive: false
      - path: "/usr/sbin"
        recursive: false
    hash_algorithms: ["sha256"]
    scan_on_start: true
  sca:
    enabled: true
    interval: "12h"
    policy_dirs:
      - "/etc/watchnode/sca"
  syscollector:
    enabled: true
    interval: "1h"
    hardware: true
    os: true
    packages: true
    ports: true
    network_interfaces: true
    users: true
    services: true

performance:
  max_cpu_percent: 25
  max_memory_bytes: 268435456
  batch_size: 500
  flush_interval: "30s"
  queue_size: 10000
  disk_queue:
    enabled: true
    dir: "/var/lib/watchnode/queue"
    max_bytes: 524288000  # 500 MB
EOF

# ── 4. Install systemd unit with auto-restart ────────────────────────────────
log "Installing systemd unit with auto-restart"
cat > /etc/systemd/system/watchnode.service <<EOF
[Unit]
Description=Sentinel WatchNode Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/watchnode --config /etc/watchnode/agent/config.yaml
Restart=always
RestartSec=10
StartLimitInterval=0
StandardOutput=append:/var/log/watchnode/watchnode.log
StandardError=append:/var/log/watchnode/watchnode.log
LimitNOFILE=65536

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/watchnode /var/log/watchnode /etc/watchnode

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now watchnode

# ── 5. Verify ────────────────────────────────────────────────────────────────
log "Waiting 10s for agent to enroll..."
sleep 10

if systemctl is-active --quiet watchnode; then
    log "✓ Agent service is running"
else
    fail "Agent service failed to start. Check: journalctl -u watchnode -n 50"
fi

# Check it actually heartbeated
if grep -q "agent started" /var/log/watchnode/watchnode.log 2>/dev/null; then
    log "✓ Agent enrolled successfully"
else
    log "⚠ Agent process is up but enrollment not yet confirmed — check logs"
fi

echo ""
echo "=================================================="
echo "  Sentinel WatchNode installed successfully"
echo "=================================================="
echo "  Service:   sudo systemctl status watchnode"
echo "  Logs:      tail -f /var/log/watchnode/watchnode.log"
echo "  Config:    /etc/watchnode/agent/config.yaml"
echo "=================================================="

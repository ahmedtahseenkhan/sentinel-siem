#!/usr/bin/env bash
# Install WatchNode Agent on macOS (launchd).
set -e
AGENT_BINARY="${AGENT_BINARY:-/usr/local/bin/watchnode}"
CONFIG_PATH="${CONFIG_PATH:-/etc/watchnode/agent/config.yaml}"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${BINARY:-$INSTALL_DIR/watchnode}"

if [[ ! -f "$BINARY" ]]; then
  echo "Binary not found: $BINARY. Build with: go build -o watchnode ./cmd/agent"
  exit 1
fi

sudo mkdir -p /etc/watchnode/agent
sudo cp "$BINARY" "$AGENT_BINARY"
sudo chmod 755 "$AGENT_BINARY"
if [[ -f "$INSTALL_DIR/configs/agent.yaml.example" ]]; then
  if [[ ! -f "$CONFIG_PATH" ]]; then
    sudo cp "$INSTALL_DIR/configs/agent.yaml.example" "$CONFIG_PATH"
    echo "Created $CONFIG_PATH from example. Edit it before starting."
  fi
fi
sudo "$AGENT_BINARY" --config "$CONFIG_PATH" --install
echo "Installed. Load with: sudo launchctl load /Library/LaunchDaemons/com.watchnode.agent.plist"
echo "Unload: sudo launchctl unload /Library/LaunchDaemons/com.watchnode.agent.plist"

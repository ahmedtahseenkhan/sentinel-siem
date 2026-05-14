#!/bin/bash
# Deploy Sentinel SIEM to ESXi Ubuntu VM (192.168.100.100)
# Usage: bash deploy-esxi.sh [user@host]
set -e

TARGET=${1:-"user@192.168.100.100"}
REMOTE_DIR="/opt/sentinel"

echo "▶ Deploying Sentinel SIEM to $TARGET:$REMOTE_DIR"

# 1. Sync source (exclude dev-only artefacts)
echo "  Syncing source files..."
rsync -az --progress \
  --exclude='.git' \
  --exclude='**/__pycache__' \
  --exclude='**/venv*' \
  --exclude='**/node_modules' \
  --exclude='*.zip' \
  --exclude='design_handoff_siem_overview/' \
  --exclude='docker-compose.local.yaml' \
  ./ "$TARGET:$REMOTE_DIR/"

# 2. Copy the ESXi compose file as the main compose file
ssh "$TARGET" "cp $REMOTE_DIR/docker-compose.esxi.yaml $REMOTE_DIR/docker-compose.yaml"

# 3. Ensure sysctl is set for OpenSearch
echo "  Setting vm.max_map_count for OpenSearch..."
ssh "$TARGET" "sudo sysctl -w vm.max_map_count=262144 && echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf > /dev/null"

# 4. Create .env if it doesn't exist
ssh "$TARGET" "test -f $REMOTE_DIR/.env && echo '  .env already exists — skipping' || (cat > $REMOTE_DIR/.env <<'EOF'
POSTGRES_PASSWORD=SentinelDB_Prod_2024!
WATCHTOWER_API_KEY=SentinelWT_Prod_2024!
ENROLL_TOKEN=sentinel-prod-enroll-2024
DASHBOARD_SECRET_KEY=SentinelDash_Prod_SecretKey_ChangeMe!
ADMIN_USER=superadmin
ADMIN_PASSWORD=SentinelAdmin_2024!
EOF
echo '  Created default .env — CHANGE PASSWORDS before going live!')"

# 5. Build and start
echo "  Building images and starting services..."
ssh "$TARGET" "cd $REMOTE_DIR && docker compose build --parallel && docker compose up -d"

# 6. Wait for health
echo "  Waiting for services to be healthy..."
sleep 20
ssh "$TARGET" "cd $REMOTE_DIR && docker compose ps"

echo ""
echo "✓ Deployment complete!"
echo "  Dashboard: http://192.168.100.100:5050"
echo "  Manager API: http://192.168.100.100:9400"
echo "  OpenSearch: http://192.168.100.100:9200"
echo "  Agent gRPC port: 50051"
echo ""
echo "  Default login: superadmin / SentinelAdmin_2024!"
echo "  ⚠  Change all passwords in $REMOTE_DIR/.env before client use"

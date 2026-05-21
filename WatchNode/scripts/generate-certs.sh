#!/bin/bash
# Usage: ./generate-certs.sh <SERVER_IP>
# Example: ./generate-certs.sh 192.168.100.100
set -e

SERVER_IP="${1:-192.168.100.100}"
OUTDIR="$(dirname "$0")/certs"
mkdir -p "$OUTDIR"

echo "[1/4] Generating CA..."
openssl genrsa -out "$OUTDIR/ca.key" 4096 2>/dev/null
openssl req -new -x509 -days=3650 -key "$OUTDIR/ca.key" \
  -subj "/CN=WatchNode Local CA" \
  -out "$OUTDIR/ca.crt"

echo "[2/4] Generating server cert (CN=manager.local, IP=$SERVER_IP)..."
openssl genrsa -out "$OUTDIR/server.key" 2048 2>/dev/null
openssl req -new -key "$OUTDIR/server.key" \
  -subj "/CN=manager.local" \
  -out "$OUTDIR/server.csr"
cat > /tmp/server_ext.cnf << EXTEOF
[v3_req]
subjectAltName = DNS:manager.local, DNS:localhost, IP:127.0.0.1, IP:$SERVER_IP
EXTEOF
openssl x509 -req -days=825 \
  -in "$OUTDIR/server.csr" \
  -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
  -extfile /tmp/server_ext.cnf -extensions v3_req \
  -out "$OUTDIR/server.crt"

echo "[3/4] Generating client (agent) cert..."
openssl genrsa -out "$OUTDIR/client.key" 2048 2>/dev/null
openssl req -new -key "$OUTDIR/client.key" \
  -subj "/CN=agent.local" \
  -out "$OUTDIR/client.csr"
openssl x509 -req -days=825 \
  -in "$OUTDIR/client.csr" \
  -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
  -out "$OUTDIR/client.crt"

echo "[4/4] Copying agent certs to SentinelAgent bundle..."
AGENT_CERTS="$(dirname "$0")/../SentinelAgent/certs"
mkdir -p "$AGENT_CERTS"
cp "$OUTDIR/ca.crt"     "$AGENT_CERTS/ca.crt"
cp "$OUTDIR/client.crt" "$AGENT_CERTS/watchnode.crt"
cp "$OUTDIR/client.key" "$AGENT_CERTS/watchnode.key"

echo ""
echo "Done. Next steps:"
echo "  1. Copy these to the server's certs/ directory:"
echo "     $OUTDIR/ca.crt        → /home/ahsan/sentinel-siem/certs/ca.crt"
echo "     $OUTDIR/server.crt    → /home/ahsan/sentinel-siem/certs/watchtower.crt"
echo "     $OUTDIR/server.key    → /home/ahsan/sentinel-siem/certs/watchtower.key"
echo "  2. Restart WatchTower:  docker compose -f docker-compose.full.yaml restart watchtower watchtower-2"
echo "  3. Redeploy agent with the updated SentinelAgent bundle (which now has the new certs)"

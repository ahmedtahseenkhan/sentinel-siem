#!/usr/bin/env bash
# Generate a local CA plus server/client certs for mTLS testing.
#
# Outputs to: scripts/certs/
# - ca.crt / ca.key
# - server.crt / server.key
# - client.crt / client.key
#
# NOTE: This is for local/dev. For production, use your PKI and rotate certs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/scripts/certs"
mkdir -p "$OUT"

CA_KEY="$OUT/ca.key"
CA_CRT="$OUT/ca.crt"
SERVER_KEY="$OUT/server.key"
SERVER_CSR="$OUT/server.csr"
SERVER_CRT="$OUT/server.crt"
CLIENT_KEY="$OUT/client.key"
CLIENT_CSR="$OUT/client.csr"
CLIENT_CRT="$OUT/client.crt"

if [[ -f "$CA_KEY" || -f "$CA_CRT" ]]; then
  echo "CA already exists in $OUT. Remove ca.* to regenerate."
fi

openssl genrsa -out "$CA_KEY" 4096
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
  -subj "/CN=WatchNode Local CA" -out "$CA_CRT"

openssl genrsa -out "$SERVER_KEY" 2048
SAN_CFG="$(mktemp)"
cat > "$SAN_CFG" <<'EOF'
[req]
distinguished_name=req_distinguished_name
req_extensions=v3_req
prompt=no

[req_distinguished_name]
CN=manager.local

[v3_req]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=manager.local
DNS.2=localhost
IP.1=127.0.0.1
EOF

openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -config "$SAN_CFG"
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_CRT" -days 825 -sha256 -extensions v3_req -extfile "$SAN_CFG"
rm -f "$SAN_CFG"

openssl genrsa -out "$CLIENT_KEY" 2048
openssl req -new -key "$CLIENT_KEY" -subj "/CN=agent.local" -out "$CLIENT_CSR"
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CLIENT_CRT" -days 825 -sha256

rm -f "$SERVER_CSR" "$CLIENT_CSR"

echo "Wrote certs to $OUT"


#!/usr/bin/env bash
# Generate mTLS certificates for all Sentinel SIEM internal services.
#
# Run this ONCE on the server before starting docker-compose:
#   bash scripts/gen-mtls-certs.sh
#
# Outputs to: certs/
#   ca.crt / ca.key           — root CA (keep key secret)
#   watchtower.crt / .key     — WatchTower gRPC server cert
#   watchvault.crt  / .key    — WatchVault gRPC server cert
#   watchnode.crt  / .key     — WatchNode client cert (agent identity)
#
# For production: replace with certs from your PKI and rotate every 1 year.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/certs"
mkdir -p "$OUT"

DAYS_CA=3650    # 10 years for CA
DAYS_CERT=825   # ~2.5 years for leaf certs

echo "==> Generating mTLS certificates in $OUT"

# ── CA ────────────────────────────────────────────────────────────────────────
echo "--> CA"
openssl genrsa -out "$OUT/ca.key" 4096
openssl req -x509 -new -nodes \
  -key "$OUT/ca.key" \
  -sha256 -days "$DAYS_CA" \
  -subj "/O=Sentinel SIEM/CN=Sentinel Internal CA" \
  -out "$OUT/ca.crt"

sign_cert() {
  local name="$1"
  local subj="$2"
  local san_cfg="$3"

  openssl genrsa -out "$OUT/${name}.key" 2048

  local csr
  csr="$(mktemp)"
  openssl req -new \
    -key "$OUT/${name}.key" \
    -subj "$subj" \
    -out "$csr" \
    -config "$san_cfg" 2>/dev/null || \
  openssl req -new \
    -key "$OUT/${name}.key" \
    -subj "$subj" \
    -out "$csr"

  openssl x509 -req \
    -in "$csr" \
    -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
    -out "$OUT/${name}.crt" \
    -days "$DAYS_CERT" -sha256 \
    -extfile "$san_cfg" -extensions v3_req 2>/dev/null || \
  openssl x509 -req \
    -in "$csr" \
    -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
    -out "$OUT/${name}.crt" \
    -days "$DAYS_CERT" -sha256

  rm -f "$csr"
}

# ── WatchTower server cert ────────────────────────────────────────────────────
echo "--> WatchTower"
WT_CFG="$(mktemp)"
cat > "$WT_CFG" <<'EOF'
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no

[req_dn]
O  = Sentinel SIEM
CN = watchtower

[v3_req]
basicConstraints     = CA:FALSE
keyUsage             = digitalSignature, keyEncipherment
extendedKeyUsage     = serverAuth
subjectAltName       = @alt_names

[alt_names]
DNS.1 = watchtower
DNS.2 = localhost
DNS.3 = watchtower-1
DNS.4 = watchtower-2
IP.1  = 127.0.0.1
EOF
sign_cert "watchtower" "/O=Sentinel SIEM/CN=watchtower" "$WT_CFG"
rm -f "$WT_CFG"

# ── WatchVault server cert ────────────────────────────────────────────────────
echo "--> WatchVault"
WV_CFG="$(mktemp)"
cat > "$WV_CFG" <<'EOF'
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no

[req_dn]
O  = Sentinel SIEM
CN = watchvault

[v3_req]
basicConstraints     = CA:FALSE
keyUsage             = digitalSignature, keyEncipherment
extendedKeyUsage     = serverAuth
subjectAltName       = @alt_names

[alt_names]
DNS.1 = watchvault
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF
sign_cert "watchvault" "/O=Sentinel SIEM/CN=watchvault" "$WV_CFG"
rm -f "$WV_CFG"

# ── WatchNode client cert (agent identity) ────────────────────────────────────
echo "--> WatchNode (agent client cert)"
WN_CFG="$(mktemp)"
cat > "$WN_CFG" <<'EOF'
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no

[req_dn]
O  = Sentinel SIEM
CN = watchnode

[v3_req]
basicConstraints   = CA:FALSE
keyUsage           = digitalSignature, keyEncipherment
extendedKeyUsage   = clientAuth
EOF
sign_cert "watchnode" "/O=Sentinel SIEM/CN=watchnode" "$WN_CFG"
rm -f "$WN_CFG"

# ── Set permissions ───────────────────────────────────────────────────────────
chmod 600 "$OUT"/*.key
chmod 644 "$OUT"/*.crt

echo ""
echo "==> Done! Certs written to $OUT/"
echo ""
echo "    ca.crt         — share with all services (trust anchor)"
echo "    watchtower.*   — WatchTower gRPC server identity"
echo "    watchvault.*   — WatchVault gRPC server identity"
echo "    watchnode.*    — Agent client identity"
echo ""
echo "    Run: docker compose -f docker-compose.full.yaml up -d --build"

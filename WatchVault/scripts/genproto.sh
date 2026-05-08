#!/usr/bin/env sh
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if ! command -v protoc >/dev/null 2>&1; then
  echo "protoc is required" >&2
  exit 1
fi
if ! command -v protoc-gen-go >/dev/null 2>&1; then
  echo "install: go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.33.0" >&2
  exit 1
fi
if ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
  echo "install: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0" >&2
  exit 1
fi
protoc --go_out=. --go_opt=module=github.com/watchvault/watchvault \
  --go-grpc_out=. --go-grpc_opt=module=github.com/watchvault/watchvault \
  pkg/proto/indexer.proto
echo "generated pkg/proto/indexer.pb.go and indexer_grpc.pb.go"

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
protoc --go_out=. --go_opt=module=github.com/watchtower/watchtower \
  --go-grpc_out=. --go-grpc_opt=module=github.com/watchtower/watchtower \
  pkg/proto/agent.proto pkg/proto/indexer.proto
echo "generated pkg/proto/*.pb.go"

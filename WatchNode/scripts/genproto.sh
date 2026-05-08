#!/usr/bin/env bash
# Generate Go code from agent.proto.
# Option 1: Run with Go and protoc on PATH:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
#   ./scripts/genproto.sh
# Option 2: Use Docker (no local install):
#   ./scripts/genproto.sh --docker
set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
USE_DOCKER=false
[[ "${1:-}" == "--docker" ]] && USE_DOCKER=true

if "$USE_DOCKER"; then
  docker run --rm -v "$ROOT":/work -w /work golang:1.23 bash -c '
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.33.0
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.4.0
    apt-get update -qq && apt-get install -qq -y protobuf-compiler
    export PATH=$GOPATH/bin:$PATH
    protoc --proto_path=/work/pkg/proto --go_out=/work --go_opt=module=github.com/watchnode/watchnode \
      --go-grpc_out=/work --go-grpc_opt=module=github.com/watchnode/watchnode \
      /work/pkg/proto/agent.proto
  '
else
  export PATH="$(go env GOPATH)/bin:$PATH"
  protoc --proto_path="$ROOT/pkg/proto" \
    --go_out="$ROOT" --go_opt=module=github.com/watchnode/watchnode \
    --go-grpc_out="$ROOT" --go-grpc_opt=module=github.com/watchnode/watchnode \
    "$ROOT/pkg/proto/agent.proto"
fi
echo "Generated pkg/proto/agent.pb.go and pkg/proto/agent_grpc.pb.go"

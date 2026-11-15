#!/usr/bin/env bash
#
# Regenerate the Flutter client's Dart gRPC stubs for the service provider contract
# (transport/src/main/protobuf/provider.proto — the same file the JVM compiles) into
# clients/flutter/lib/generated/. The output is committed, so neither CI nor a contributor needs the
# plugin unless the contract changes; run this script after changing provider.proto and commit
# the result.
#
# Requires protoc and the pinned Dart plugin:
#   dart pub global activate protoc_plugin 25.1.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN="${PROTOC_GEN_DART:-$HOME/.pub-cache/bin/protoc-gen-dart}"
[ -x "$PLUGIN" ] || { echo "protoc-gen-dart not found; run: dart pub global activate protoc_plugin 25.1.0" >&2; exit 127; }
OUT="$ROOT/clients/flutter/lib/generated"
mkdir -p "$OUT"
protoc --plugin=protoc-gen-dart="$PLUGIN" \
  --dart_out=grpc:"$OUT" \
  -I "$ROOT/transport/src/main/protobuf" \
  "$ROOT/transport/src/main/protobuf/provider.proto"
echo "generated: $(ls "$OUT")"

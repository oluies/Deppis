#!/usr/bin/env bash
# gRPC-web transport smoke (T032c): stage the JVM ObliviousStore server, then bring up
# server + Envoy + a gRPC-web client that asserts a real browser-style round-trip through Envoy
#   client --(gRPC-web, HTTP/1.1)--> Envoy --(gRPC, HTTP/2)--> Scala ObliviousStore  (and back).
#
# Uses Apple's `container` (native arm64 VMs on Apple Silicon — no QEMU). Wires the two hops by
# container IP on a shared network, so it needs NO `sudo container system dns create` (apple/container
# name resolution requires an admin-created DNS domain; IPs avoid that). The committed
# deploy/envoy/envoy.yaml stays DNS-based (production style); this script substitutes the server's IP
# into a runtime copy. Requires JDK 26 + sbt to stage the server.
set -euo pipefail
cd "$(dirname "$0")"
NET=deppis-grpcweb

ipof() { container inspect "$1" 2>/dev/null | python3 -c \
  "import json,sys; d=json.load(sys.stdin)[0]; n=d.get('networks') or d.get('status',{}).get('networks') or []; print(n[0]['ipv4Address'].split('/')[0] if n else '')"; }

cleanup() { container rm -f messenger-server envoy >/dev/null 2>&1 || true; container network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "[run] staging the JVM ObliviousStore server (sbt transport/stageServer) ..."
export JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home -v 26 2>/dev/null || true)}"
( cd ../.. && sbt -batch transport/stageServer )
LIB="$(find ../../target -type d -path '*transport/grpc-web-server/lib' | head -1)"
[ -n "$LIB" ] || { echo "[run] staged lib not found" >&2; exit 1; }
rm -rf server-lib && mkdir server-lib && cp "$LIB"/*.jar server-lib/
echo "[run] staged $(ls server-lib | wc -l | tr -d ' ') jars"

echo "[run] building server image ..."
container build -t messenger-server -f Dockerfile.server . >/dev/null

container network create "$NET" >/dev/null 2>&1 || true
echo "[run] starting messenger-server (h2c gRPC ObliviousStore :9090) ..."
container run -d --name messenger-server --network "$NET" messenger-server:latest >/dev/null
sleep 3
SRV_IP="$(ipof messenger-server)"; [ -n "$SRV_IP" ] || { echo "[run] no server IP" >&2; exit 1; }

echo "[run] starting Envoy (gRPC-web :8080 -> $SRV_IP:9090) ..."
sed "s/address: messenger-server,/address: $SRV_IP,/" ../envoy/envoy.yaml > /tmp/deppis-envoy.runtime.yaml
container run -d --name envoy --network "$NET" -p 8080:8080 \
  -v "/tmp/deppis-envoy.runtime.yaml:/etc/envoy/envoy.yaml" \
  envoyproxy/envoy:v1.31.2 -c /etc/envoy/envoy.yaml --log-level warning >/dev/null
sleep 6
ENVOY_IP="$(ipof envoy)"; [ -n "$ENVOY_IP" ] || { echo "[run] no envoy IP" >&2; exit 1; }

echo "[run] gRPC-web client → Envoy round-trip ..."
container run --rm --network "$NET" -v "$(pwd)/client.js:/app/client.js" -w /app \
  -e ENVOY="http://$ENVOY_IP:8080" node:22-bookworm-slim node /app/client.js
echo "[run] OK — gRPC-web → Envoy → gRPC round-trip verified."

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
#
#   ./run.sh            the raw gRPC-web round-trip above.
#   ./run.sh --browser  ALSO the live browser run (design/offline-delegation.md §3): the Flutter web
#                       app's self-test build in headless Chromium — two provider-routed devices in one
#                       real page, each with its own Scala.js engine + ProviderSession + Dart gRPC-web
#                       client, through Envoy to the provider (GrpcWebBackendServer). Both online, then
#                       the offline case: Bob away, Alice queues and goes away too, Bob returns and gets
#                       it from Alice's bundle. Verdict = the page title. Needs flutter, npm (esbuild,
#                       for the engine bundle) and Chromium/Chrome (CHROME=… to choose).
set -euo pipefail
cd "$(dirname "$0")"
NET=deppis-grpcweb
MODE="${1:-}"
[ -z "$MODE" ] || [ "$MODE" = "--browser" ] || { echo "usage: $0 [--browser]" >&2; exit 2; }
# The live run uses fast rounds; the provider and the self-test build MUST get the same values.
INTERVAL_MS=2000
CUTOFF_MS=1200
PAGE_PORT=8090
DEBUG_PORT=9333
HTTP_PID=""
CHROME_PID=""
# A UNIQUE tag per run. apple/container keeps a previous image under the same name:tag when one is
# rebuilt, and `container run name:latest` then resolves to the OLD one — which silently ran a
# months-old server (old jars, no provider) in the first live run of this harness.
IMAGE="messenger-server:run-$(date +%s)"

ipof() { container inspect "$1" 2>/dev/null | python3 -c \
  "import json,sys; d=json.load(sys.stdin)[0]; n=d.get('networks') or d.get('status',{}).get('networks') or []; print(n[0]['ipv4Address'].split('/')[0] if n else '')"; }

cleanup() {
  [ -z "$CHROME_PID" ] || kill "$CHROME_PID" >/dev/null 2>&1 || true
  [ -z "$HTTP_PID" ] || kill "$HTTP_PID" >/dev/null 2>&1 || true
  container rm -f messenger-server envoy >/dev/null 2>&1 || true
  container network rm "$NET" >/dev/null 2>&1 || true
  container image rm "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "[run] staging the JVM ObliviousStore server (sbt transport/stageServer) ..."
export JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home -v 26 2>/dev/null || true)}"
# Throwaway action cache, same reason as the CI staging step (.github/workflows/ci.yml): sbt 2
# caches task results machine-wide, stageServer returns Unit, and its real output is the staged
# lib/ on disk. On a warm cache sbt replays the Unit, stages nothing and still exits 0 — the
# `find` below would then pick up a STALE lib/ from an earlier run, or none at all.
( cd ../.. && sbt -batch "set Global / localCacheDirectory := file(\"$(mktemp -d)\"); transport/stageServer" )
LIB="$(find ../../target -type d -path '*transport/grpc-web-server/lib' | head -1)"
[ -n "$LIB" ] || { echo "[run] staged lib not found" >&2; exit 1; }
rm -rf server-lib && mkdir server-lib && cp "$LIB"/*.jar server-lib/
echo "[run] staged $(ls server-lib | wc -l | tr -d ' ') jars"

echo "[run] building server image ..."
container build -t "$IMAGE" -f Dockerfile.server . >/dev/null

container network create "$NET" >/dev/null 2>&1 || true
echo "[run] starting messenger-server (h2c gRPC ObliviousStore :9090) ..."
# `${SCHED[@]+...}` below: an empty array under `set -u` is "unbound" on bash < 4.4 (macOS /bin/bash 3.2).
SCHED=()
[ "$MODE" != "--browser" ] || SCHED=(-e "ROUND_INTERVAL_MS=$INTERVAL_MS" -e "ROUND_CUTOFF_MS=$CUTOFF_MS")
container run -d --name messenger-server --network "$NET" ${SCHED[@]+"${SCHED[@]}"} "$IMAGE" >/dev/null
# Wait until the server announces itself — and, for the browser run, that it is the build that
# serves the provider (an old image would serve only the store and the run would time out later).
want="ObliviousStore"
[ "$MODE" != "--browser" ] || want="ProviderService"
for _ in $(seq 1 30); do
  container logs messenger-server 2>&1 | grep -q "$want" && break
  sleep 1
done
container logs messenger-server 2>&1 | grep -q "$want" \
  || { echo "[run] the server never reported '$want':" >&2; container logs messenger-server 2>&1 | tail -5 >&2; exit 1; }
SRV_IP="$(ipof messenger-server)"; [ -n "$SRV_IP" ] || { echo "[run] no server IP" >&2; exit 1; }

echo "[run] starting Envoy (gRPC-web :8080 -> $SRV_IP:9090) ..."
sed "s/address: messenger-server,/address: $SRV_IP,/" ../envoy/envoy.yaml > /tmp/deppis-envoy.runtime.yaml
# Fail loudly if the endpoint form in envoy.yaml ever changes and the substitution silently no-ops
# (otherwise Envoy would start with an unresolvable upstream and the client would just retry-exhaust).
grep -q "address: $SRV_IP," /tmp/deppis-envoy.runtime.yaml \
  || { echo "[run] envoy upstream address substitution failed (envoy.yaml endpoint format changed?)" >&2; exit 1; }
if [ "$MODE" = "--browser" ]; then
  # The browser page is served from http://localhost:$PAGE_PORT — allow THAT origin in the runtime copy
  # only; the committed envoy.yaml stays restricted to the real app origin.
  python3 - "$PAGE_PORT" /tmp/deppis-envoy.runtime.yaml <<'PY'
import sys
port, path = sys.argv[1], sys.argv[2]
s = open(path).read()
line = '                            - exact: "https://mm.example"\n'
if s.count(line) != 1:
    sys.exit("[run] envoy CORS origin substitution failed (envoy.yaml cors format changed?)")
s = s.replace(line, line + line.replace("https://mm.example", f"http://localhost:{port}"))
open(path, "w").write(s)
PY
fi
container run -d --name envoy --network "$NET" -p 8080:8080 \
  -v "/tmp/deppis-envoy.runtime.yaml:/etc/envoy/envoy.yaml" \
  envoyproxy/envoy:v1.38.3 -c /etc/envoy/envoy.yaml --log-level warning >/dev/null
sleep 6
ENVOY_IP="$(ipof envoy)"; [ -n "$ENVOY_IP" ] || { echo "[run] no envoy IP" >&2; exit 1; }

echo "[run] gRPC-web client → Envoy round-trip ..."
container run --rm --network "$NET" -v "$(pwd)/client.js:/app/client.js" -w /app \
  -e ENVOY="http://$ENVOY_IP:8080" node:22-bookworm-slim node /app/client.js
echo "[run] OK — gRPC-web → Envoy → gRPC round-trip verified."

[ "$MODE" = "--browser" ] || exit 0

echo "[run] building the engine bundle and the self-test web app ..."
( cd ../.. && scripts/build-web-bundle.sh )
( cd ../../clients/flutter && flutter build web --no-tree-shake-icons \
    --dart-define=PROVIDER_URL=http://localhost:8080 --dart-define=ROUTING_SELFTEST=true \
    --dart-define=ROUND_INTERVAL_MS=$INTERVAL_MS --dart-define=ROUND_CUTOFF_MS=$CUTOFF_MS )

echo "[run] serving it on http://localhost:$PAGE_PORT and opening it in headless Chromium ..."
python3 -m http.server "$PAGE_PORT" --bind 127.0.0.1 --directory ../../clients/flutter/build/web \
  >/dev/null 2>&1 &
HTTP_PID=$!
# The first candidate that actually RUNS: a `chromium` on PATH can be a shim whose app is not
# installed (Homebrew's is), which exits at once and leaves the poll below waiting for nothing.
CHROME="${CHROME:-}"
if [ -z "$CHROME" ]; then
  for c in "$(command -v chromium || true)" "$(command -v google-chrome || true)" \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "/Applications/Chromium.app/Contents/MacOS/Chromium"; do
    [ -n "$c" ] && "$c" --version >/dev/null 2>&1 && { CHROME="$c"; break; }
  done
fi
[ -n "$CHROME" ] || { echo "[run] no working Chromium/Chrome found (set CHROME=…)" >&2; exit 1; }
echo "[run] browser: $("$CHROME" --version)"
"$CHROME" --headless=new --remote-debugging-port="$DEBUG_PORT" --user-data-dir="$(mktemp -d)" \
  --no-first-run --no-default-browser-check "http://localhost:$PAGE_PORT/" >/dev/null 2>&1 &
CHROME_PID=$!

# The self-test writes its verdict into the page title; Chromium's debugging endpoint lists it.
title=""
deadline=$((SECONDS + 300))
while [ $SECONDS -lt $deadline ]; do
  title="$(curl -s "http://127.0.0.1:$DEBUG_PORT/json" | python3 -c \
    'import json,sys; t=[p["title"] for p in json.load(sys.stdin) if p.get("type")=="page"]; print(t[0] if t else "")' \
    2>/dev/null || true)"
  case "$title" in ROUTING-SELFTEST-*) break ;; esac
  sleep 2
done
echo "[run] browser verdict: ${title:-<none within 300 s>}"
if [ "$title" != "ROUTING-SELFTEST-OK" ]; then
  echo "[run] server log tail:" >&2
  container logs messenger-server 2>&1 | tail -20 >&2
  exit 1
fi
echo "[run] OK — two browser devices delivered through the provider, including from a bundle while offline."

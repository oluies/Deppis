#!/usr/bin/env bash
# Live NATIVE run of provider routing (design/offline-delegation.md §3) on the iOS simulator: the
# Flutter app's self-test build, two provider-routed devices sharing one flutter_js (JavaScriptCore)
# runtime, each with its own Scala.js engine + ProviderSession, reaching the provider
# (GrpcWebBackendServer, run directly on this Mac) over plain HTTP/2 gRPC — no Envoy natively. The
# same scenario as the browser run (deploy/grpc-web/run.sh --browser): both online, then Bob away,
# Alice queues and goes away too, Bob returns and gets it from Alice's bundle.
#
# The simulator shares the Mac's network, so the app reaches the server on 127.0.0.1. Verdict = the
# app's `ROUTING-SELFTEST-VERDICT …` log line.
#
# Needs: a full Xcode with an iOS simulator runtime, CocoaPods, Flutter >= 3.50, JDK 27 + sbt (to stage the
# server), npm (esbuild, for the engine bundle). SIM=… picks the simulator (default: iPhone 17).
# Labeled DEV, NO METADATA PRIVACY like everything provider-routed until Phase 4.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"
SIM="${SIM:-iPhone 17}"
PORT="${PORT:-9190}"
INTERVAL_MS=2000
CUTOFF_MS=1200
BUNDLE_ID=com.example.metadataMessenger
WORK="$(mktemp -d)"
SERVER_PID=""
CONSOLE_PID=""

cleanup() {
  [ -z "$CONSOLE_PID" ] || kill "$CONSOLE_PID" >/dev/null 2>&1 || true
  [ -z "$SERVER_PID" ] || kill "$SERVER_PID" >/dev/null 2>&1 || true
  xcrun simctl terminate "$UDID" "$BUNDLE_ID" >/dev/null 2>&1 || true
}
UDID=""
trap cleanup EXIT

export JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home -v 27 2>/dev/null || true)}"
echo "[sim] staging the JVM server (sbt transport/stageServer) ..."
# Throwaway action cache: on a warm sbt 2 cache stageServer replays Unit and stages nothing
# (see deploy/grpc-web/run.sh).
sbt -batch "set Global / localCacheDirectory := file(\"$(mktemp -d)\"); transport/stageServer" >/dev/null
LIB="$(find target -type d -path '*transport/grpc-web-server/lib' | head -1)"
[ -n "$LIB" ] || { echo "[sim] staged lib not found" >&2; exit 1; }

echo "[sim] starting the provider on 127.0.0.1:$PORT (rounds $INTERVAL_MS ms, cutoff $CUTOFF_MS ms) ..."
PORT="$PORT" ROUND_INTERVAL_MS="$INTERVAL_MS" ROUND_CUTOFF_MS="$CUTOFF_MS" \
  "$JAVA_HOME/bin/java" --enable-native-access=ALL-UNNAMED -cp "$LIB/*" \
  transport.round.GrpcWebBackendServer >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 30); do grep -q ProviderService "$WORK/server.log" && break; sleep 1; done
grep -q ProviderService "$WORK/server.log" \
  || { echo "[sim] the server never reported ProviderService:" >&2; tail -20 "$WORK/server.log" >&2; exit 1; }

echo "[sim] rebuilding the native engine bundle ..."
protocol-core-js/build-jsc-bundle.sh >/dev/null

UDID="$(xcrun simctl list devices available -j | python3 -c '
import json, sys
name = sys.argv[1]
for rt, devs in json.load(sys.stdin)["devices"].items():
    if "iOS" in rt:
        for d in devs:
            if d["name"] == name:
                print(d["udid"]); sys.exit()
' "$SIM")"
[ -n "$UDID" ] || { echo "[sim] no available simulator named '$SIM' (SIM=…)" >&2; exit 1; }
echo "[sim] simulator: $SIM ($UDID)"
xcrun simctl boot "$UDID" >/dev/null 2>&1 || true
xcrun simctl bootstatus "$UDID" -b >/dev/null

echo "[sim] building, installing and launching the self-test app (flutter run) ..."
# `flutter run -d <udid>` builds for that one simulator and launches the app with its console
# attached. (`flutter build ios --simulator` also works on Flutter >= 3.50; older versions fail
# under Xcode 27, whose lipo rejects their `-verify_arch arm64 x86_64` check.)
( cd clients/flutter && exec flutter run -d "$UDID" --debug \
    --dart-define=PROVIDER_URL="http://127.0.0.1:$PORT" --dart-define=ROUTING_SELFTEST=true \
    --dart-define=ROUND_INTERVAL_MS=$INTERVAL_MS --dart-define=ROUND_CUTOFF_MS=$CUTOFF_MS ) \
  </dev/null >"$WORK/app.log" 2>&1 &
CONSOLE_PID=$!

verdict=""
deadline=$((SECONDS + 600)) # includes the first Xcode build
while [ $SECONDS -lt $deadline ]; do
  verdict="$(grep -ao 'ROUTING-SELFTEST-VERDICT .*' "$WORK/app.log" | head -1 | tr -d '\r' || true)"
  [ -n "$verdict" ] && break
  kill -0 "$CONSOLE_PID" 2>/dev/null || break
  sleep 2
done
echo "[sim] app log (selftest lines):"
grep -a '\[selftest\]\|ScalaJsEngine\|provider' "$WORK/app.log" | tr -d '\r' | sed 's/^/    /' | tail -30 || true
echo "[sim] verdict: ${verdict:-<none>}"
[ -n "$verdict" ] || { echo "[sim] flutter run log tail:" >&2; tail -25 "$WORK/app.log" | tr -d '\r' >&2; }
if [ "$verdict" != "ROUTING-SELFTEST-VERDICT ROUTING-SELFTEST-OK" ]; then
  echo "[sim] server log tail:" >&2
  tail -20 "$WORK/server.log" >&2
  exit 1
fi
echo "[sim] OK — two native devices delivered through the provider, including from a bundle while offline."

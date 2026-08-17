#!/usr/bin/env bash
# Verify that envoy-pq-tls.yaml actually negotiates RFC 10024 hybrid key agreement — and actually
# refuses a classical-only client.
#
# Why this exists: every load-bearing claim about that config (X25519MLKEM768 is a valid ecdh_curves
# value for the pinned image, the negotiated group really is the hybrid one, a classical client fails
# closed) otherwise rests on a one-time manual run transcribed into a comment. An image bump, a
# downgrade, or a field rename would break the browser hop silently while the gRPC-web smoke test
# stayed green. The JVM side has PqTlsSpec/PqTlsInteropSpec; this is the equivalent for the hop that
# actually protects users.
#
# Opt-in, not part of the smoke harness: it needs a container runtime and an OpenSSL >= 3.5 (RFC
# 10024 support), and it mints an EPHEMERAL self-signed cert into a temp dir. That is deliberate and
# does not conflict with the deployment config shipping no certs — a throwaway cert is fine for
# asserting key agreement, which is what this checks. It asserts nothing about PKI.
#
#   ./deploy/envoy/verify-pq-tls.sh
set -euo pipefail

CONFIG="$(cd "$(dirname "$0")" && pwd)/envoy-pq-tls.yaml"
GROUP="X25519MLKEM768"
PORT="${PORT:-18443}"
NAME="deppis-pq-tls-verify"

# Pin read from the config itself, so this can never verify a different image than the one deployed.
IMAGE="$(sed -n 's/^# Pinned image.*: *\(envoyproxy\/envoy:[^ ]*\)/\1/p' "$CONFIG" | head -1)"
[ -n "$IMAGE" ] || { echo "could not read the pinned image out of $CONFIG" >&2; exit 1; }

# OpenSSL >= 3.5 knows the hybrid group; older ones (Ubuntu 24.04 ships 3.0.x) do not.
OPENSSL=""
for c in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl openssl; do
  if command -v "$c" >/dev/null 2>&1 && "$c" list -tls-groups 2>/dev/null | grep -q "$GROUP"; then
    OPENSSL="$c"; break
  fi
done
[ -n "$OPENSSL" ] || { echo "SKIP: no openssl advertising $GROUP (needs OpenSSL >= 3.5)" >&2; exit 0; }

RUNTIME=""
for r in docker podman; do command -v "$r" >/dev/null 2>&1 && { RUNTIME="$r"; break; }; done
[ -n "$RUNTIME" ] || { echo "SKIP: no docker/podman available" >&2; exit 0; }

TMP="$(mktemp -d)"
cleanup() { "$RUNTIME" rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT

mkdir -p "$TMP/certs"
"$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$TMP/certs/key.pem" -out "$TMP/certs/cert.pem" -days 1 -nodes \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1

echo "[verify] $IMAGE, config $(basename "$CONFIG"), port $PORT"

# Start Envoy with the given extra flags. Kept as a function because the premise of the triage
# instruction — that plain `warning` does NOT carry the signal — needs a second run to pin.
start_envoy() {
  "$RUNTIME" rm -f "$NAME" >/dev/null 2>&1 || true
  # NOT --rm: on a boot failure the container must survive long enough to read its logs, which is
  # the whole point of the diagnostic below. The EXIT trap removes it either way.
  "$RUNTIME" run -d --name "$NAME" -p "$PORT:8443" \
    -v "$CONFIG:/etc/envoy/envoy.yaml:ro" -v "$TMP/certs:/etc/envoy/certs:ro" \
    "$IMAGE" -c /etc/envoy/envoy.yaml "$@" >/dev/null
  for _ in $(seq 1 30); do
    "$OPENSSL" s_client -connect "localhost:$PORT" -groups "$GROUP" -tls1_3 </dev/null >/dev/null 2>&1 && return 0
    sleep 1
  done
  # Distinguish "Envoy never started" from "Envoy started but would not negotiate". Without this the
  # readiness loop just times out and the next assertion blames ecdh_curves or the image pin — and
  # the likeliest cause is actually a rejected flag (Envoy exits at boot on an unknown component id,
  # so --component-log-level is exactly the argument whose breakage would be misattributed).
  if [ "$("$RUNTIME" inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]; then
    echo "FAIL: Envoy did not start with: $*"
    "$RUNTIME" logs "$NAME" 2>&1 | tail -20
    exit 1
  fi
  return 0
}

start_envoy --log-level warning --component-log-level connection:debug

pq="$("$OPENSSL" s_client -connect "localhost:$PORT" -groups "$GROUP" -tls1_3 -alpn h2 </dev/null 2>&1 || true)"
grep -q "Negotiated TLS1.3 group: $GROUP" <<<"$pq" \
  || { echo "FAIL: hybrid client did not negotiate $GROUP"; echo "$pq" | tail -20; exit 1; }
grep -q "ALPN protocol: h2" <<<"$pq" \
  || { echo "FAIL: ALPN h2 not negotiated (gRPC-web needs it)"; echo "$pq" | tail -20; exit 1; }
echo "[verify] hybrid client  -> Negotiated TLS1.3 group: $GROUP, ALPN h2"

# Hybrid-only means no fallback: a classical-only client must be refused, not quietly downgraded.
# Asserted on the exact wording rather than a loose "alert", because the config comments cite
# "handshake failure" specifically as the reproduced negative — a broader grep would let a passing
# run stand behind wording that was never observed.
cls="$("$OPENSSL" s_client -connect "localhost:$PORT" -groups x25519 -tls1_3 </dev/null 2>&1 || true)"
grep -qi "handshake failure" <<<"$cls" \
  || { echo "FAIL: classical-only client was NOT refused with a handshake failure"; echo "$cls" | tail -20; exit 1; }
echo "[verify] classical-only -> refused (handshake failure)"

# The operator-facing triage signal documented in envoy-pq-tls.yaml. Asserted here for the same
# reason as everything else in this script: otherwise an Envoy bump that renames or drops the string
# leaves the triage instruction silently wrong while this check stays green.
#
# POLLED, not read once: s_client returns as soon as it gets the fatal alert, which is the same
# moment Envoy logs the line — which then still has to cross Envoy's stderr and the runtime's log
# pipe before `logs` can see it. A single read races that and would flake on a working config.
found=""
for _ in $(seq 1 10); do
  logs="$("$RUNTIME" logs "$NAME" 2>&1 || true)"
  if grep -q "NO_SHARED_GROUP" <<<"$logs"; then found=1; break; fi
  sleep 1
done
[ -n "$found" ] \
  || { echo "FAIL: expected NO_SHARED_GROUP in Envoy's connection log after the refused handshake"; echo "$logs" | tail -20; exit 1; }
echo "[verify] operator signal -> NO_SHARED_GROUP present with connection:debug"

# Pin the PREMISE of the triage instruction: at plain `warning` the signal is NOT there, which is why
# the docs tell an operator to raise anything at all. Without this, a future Envoy that logged the
# line at warning would leave the instruction (restart, drop live connections, have the client retry)
# recommending cost for nothing, and every existing assertion would still pass.
start_envoy --log-level warning
"$OPENSSL" s_client -connect "localhost:$PORT" -groups x25519 -tls1_3 </dev/null >/dev/null 2>&1 || true
sleep 3
quiet="$("$RUNTIME" logs "$NAME" 2>&1 || true)"
grep -q "NO_SHARED_GROUP" <<<"$quiet" \
  && { echo "FAIL: NO_SHARED_GROUP appears at plain --log-level warning; the docs' premise that the level must be raised is stale"; exit 1; }
echo "[verify] premise        -> absent at plain warning (so raising the level is required)"

echo "[verify] OK: $(basename "$CONFIG") negotiates $GROUP, refuses classical-only clients, and reports NO_SHARED_GROUP only with connection:debug."

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
"$RUNTIME" run --rm -d --name "$NAME" -p "$PORT:8443" \
  -v "$CONFIG:/etc/envoy/envoy.yaml:ro" -v "$TMP/certs:/etc/envoy/certs:ro" \
  "$IMAGE" -c /etc/envoy/envoy.yaml --log-level warning >/dev/null

for _ in $(seq 1 30); do
  "$OPENSSL" s_client -connect "localhost:$PORT" -groups "$GROUP" -tls1_3 </dev/null >/dev/null 2>&1 && break
  sleep 1
done

pq="$("$OPENSSL" s_client -connect "localhost:$PORT" -groups "$GROUP" -tls1_3 -alpn h2 </dev/null 2>&1 || true)"
grep -q "Negotiated TLS1.3 group: $GROUP" <<<"$pq" \
  || { echo "FAIL: hybrid client did not negotiate $GROUP"; echo "$pq" | tail -20; exit 1; }
grep -q "ALPN protocol: h2" <<<"$pq" \
  || { echo "FAIL: ALPN h2 not negotiated (gRPC-web needs it)"; echo "$pq" | tail -20; exit 1; }
echo "[verify] hybrid client  -> Negotiated TLS1.3 group: $GROUP, ALPN h2"

# Hybrid-only means no fallback: a classical-only client must be refused, not quietly downgraded.
cls="$("$OPENSSL" s_client -connect "localhost:$PORT" -groups x25519 -tls1_3 </dev/null 2>&1 || true)"
grep -qi "handshake failure\|alert" <<<"$cls" \
  || { echo "FAIL: classical-only client was NOT refused — the no-fallback posture is broken"; echo "$cls" | tail -20; exit 1; }
echo "[verify] classical-only -> refused (handshake failure)"

echo "[verify] OK: $(basename "$CONFIG") negotiates $GROUP and refuses classical-only clients."

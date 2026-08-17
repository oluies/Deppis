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

# --- helpers -----------------------------------------------------------------------------------

# Container state as three outcomes, not two: 0 running, 1 definitely stopped, 2 could not tell.
# `inspect` itself can fail transiently (daemon hiccup, name not yet resolvable straight after
# `run -d`), and collapsing that into "not running" would report "Envoy did not start" — the most
# misleading message available — for a container that is perfectly healthy.
envoy_state() {
  local out rc
  # 2>/dev/null, NOT 2>&1: `out` is only ever pattern-matched, never printed, so merging stderr
  # buys nothing and can only corrupt the parse — a deprecation notice or podman warning would make
  # this "WARN...\ntrue", fall through to *, and report "could not tell" for a healthy container.
  # The exit status alone already separates "inspect failed" from "inspect answered".
  out="$("$RUNTIME" inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)"; rc=$?
  [ $rc -ne 0 ] && return 2
  case "$out" in
    true)  return 0 ;;
    false) return 1 ;;
    *)     return 2 ;;
  esac
}

# Container logs, with the runtime's exit status preserved. Envoy logs to stderr so 2>&1 is
# required, which means a runtime error ("No such container: ...") would otherwise be captured as if
# it were log content — and satisfy any non-empty check written to detect exactly that failure.
# Callers must consult the status, not just the text.
read_logs() {
  "$RUNTIME" logs "$NAME" 2>&1
}

start_envoy() {
  "$RUNTIME" rm -f "$NAME" >/dev/null 2>&1 || true
  # NOT --rm: on a boot failure the container must survive long enough to read its logs, which is
  # the whole point of the diagnostic below. The EXIT trap removes it either way.
  "$RUNTIME" run -d --name "$NAME" -p "$PORT:8443" \
    -v "$CONFIG:/etc/envoy/envoy.yaml:ro" -v "$TMP/certs:/etc/envoy/certs:ro" \
    "$IMAGE" -c /etc/envoy/envoy.yaml "$@" >/dev/null
  local st
  for _ in $(seq 1 30); do
    # Checked every iteration, not only after the loop: Envoy exits at boot on a rejected flag — an
    # unknown --component-log-level id, say — within about a second, and that is exactly the case
    # this diagnostic exists for. Only a definite "stopped" fails; "could not tell" keeps waiting.
    # `|| st=$?` and not `envoy_state; st=$?`: under `set -e` the bare call aborts the script the
    # moment it returns non-zero, which silently swallowed this very diagnostic.
    st=0; envoy_state || st=$?
    if [ $st -eq 1 ]; then
      echo "FAIL: Envoy did not start with: $*"
      read_logs | tail -20
      exit 1
    fi
    "$OPENSSL" s_client -connect "localhost:$PORT" -groups "$GROUP" -tls1_3 </dev/null >/dev/null 2>&1 && return 0
    sleep 1
  done
  # Timed out. Returning 0 here would let every later assertion "pass" against a listener that never
  # completed a single handshake — but the verdict must match what was actually established, so
  # re-check the state rather than asserting running-ness the rc=2 path never verified.
  st=0; envoy_state || st=$?
  case $st in
    0) echo "FAIL: Envoy is running but never completed a handshake with: $*" ;;
    1) echo "FAIL: Envoy did not start with: $*" ;;
    *) echo "FAIL: could not determine the container's state (inspect kept failing) with: $*" ;;
  esac
  read_logs | tail -20
  exit 1
}

# A classical-only client must be refused, and refused at key agreement. Asserted on the exact
# wording rather than a loose "alert": the config comments cite "handshake failure" as the
# reproduced negative, and a broader grep would let a run stand behind wording never observed.
assert_classical_refused() {
  local out
  out="$("$OPENSSL" s_client -connect "localhost:$PORT" -groups x25519 -tls1_3 </dev/null 2>&1 || true)"
  grep -qi "handshake failure" <<<"$out" \
    || { echo "FAIL: $1: classical-only client was not refused with a handshake failure"; echo "$out" | tail -20; exit 1; }
}

# Poll the container log for a pattern. 0 = found, 1 = not found within the window. Sets LOGS and
# LOGS_RC for the caller. Sleeps BEFORE each capture so the final second of the window is sampled
# (capture-first would waste the trailing sleep and never look at t=window).
poll_logs_for() {
  local pat="$1" iters="$2"
  for _ in $(seq 1 "$iters"); do
    sleep 1
    # Same `set -e` hazard: a failing command substitution in a bare assignment kills the script.
    if LOGS="$(read_logs)"; then LOGS_RC=0; else LOGS_RC=$?; fi
    grep -q "$pat" <<<"$LOGS" && return 0
  done
  return 1
}

# --- assertions --------------------------------------------------------------------------------

start_envoy --log-level warning --component-log-level connection:debug

pq="$("$OPENSSL" s_client -connect "localhost:$PORT" -groups "$GROUP" -tls1_3 -alpn h2 </dev/null 2>&1 || true)"
grep -q "Negotiated TLS1.3 group: $GROUP" <<<"$pq" \
  || { echo "FAIL: hybrid client did not negotiate $GROUP"; echo "$pq" | tail -20; exit 1; }
grep -q "ALPN protocol: h2" <<<"$pq" \
  || { echo "FAIL: ALPN h2 not negotiated (gRPC-web needs it)"; echo "$pq" | tail -20; exit 1; }
echo "[verify] hybrid client  -> Negotiated TLS1.3 group: $GROUP, ALPN h2"

assert_classical_refused "connection:debug run"
echo "[verify] classical-only -> refused (handshake failure)"

# The operator-facing triage signal documented in envoy-pq-tls.yaml, asserted here so an Envoy bump
# that renames or drops the string fails this check rather than silently leaving the triage
# instruction wrong. Polled: s_client returns the instant it gets the fatal alert, which is when
# Envoy logs the line — and that line still has to cross Envoy's stderr and the runtime's log pipe.
poll_logs_for "NO_SHARED_GROUP" 10 || {
  # Same distinction the plain-warning run makes below: an unreadable log is not evidence that the
  # operator signal is missing, and reporting it as such sends the reader after an Envoy change that
  # never happened.
  [ "${LOGS_RC:-1}" -eq 0 ] \
    || { echo "FAIL: could not read the connection:debug container's logs (rc=${LOGS_RC:-?})"; echo "$LOGS" | tail -5; exit 1; }
  echo "FAIL: expected NO_SHARED_GROUP in Envoy's connection log after the refused handshake"
  echo "$LOGS" | tail -20
  exit 1
}
echo "[verify] operator signal -> NO_SHARED_GROUP present with connection:debug"

# Pin the PREMISE of the triage instruction: at plain `warning` the signal is NOT there, which is why
# the docs tell an operator to restart at all. Without this, a future Envoy that logged the line by
# default would leave that instruction — restart, drop live connections, have the client retry —
# recommending real cost for nothing, while every assertion above still passed.
start_envoy --log-level warning
assert_classical_refused "plain-warning run"   # a refusal must actually happen, or absence proves nothing
if poll_logs_for "NO_SHARED_GROUP" 10; then
  echo "FAIL: NO_SHARED_GROUP appears at plain --log-level warning; the docs' premise that the level must be raised is stale"
  grep -n "NO_SHARED_GROUP" <<<"$LOGS" | tail -5
  exit 1
fi
# Separate "quiet by design" from "logs unreadable": the runtime's own error text would satisfy a
# bare non-empty check, so the read must have SUCCEEDED and produced output. Envoy emits at least
# its downstream-connection-limit warning at this level.
{ [ "${LOGS_RC:-1}" -eq 0 ] && [ -n "$LOGS" ]; } \
  || { echo "FAIL: could not read the plain-warning container's logs (rc=${LOGS_RC:-?}) — absence is indistinguishable from unreadable"; echo "$LOGS" | tail -5; exit 1; }
echo "[verify] premise        -> absent at plain warning (so raising the level is required)"

echo "[verify] OK: $(basename "$CONFIG") negotiates $GROUP, refuses classical-only clients, and reports NO_SHARED_GROUP only with connection:debug."

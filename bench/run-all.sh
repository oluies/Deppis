#!/usr/bin/env bash
# Runs the whole benchmark: the Rust sidecar over gRPC/HTTP2, and the Scala sidecar — the same
# sources linked two ways — over gRPC/HTTP1.1 on the JVM and on Scala Native.
#
# Read bench/README.md before quoting any number from this. In particular the Rust and Scala runs
# do NOT share a transport, for reasons that are a property of the ecosystem rather than a choice.
set -euo pipefail
cd "$(dirname "$0")/.."

# 5 by default, because that is where all three targets can be compared at the SAME concurrency:
# `io.gatling:gatling-grpc` is trial-licensed and silently records nothing above 5 virtual users
# (see ObsdGrpcSimulation). Raising this still benchmarks the two Scala targets against each other
# — which is the JVM-vs-Native comparison — but drops the Rust run, so the script says so.
USERS="${BENCH_USERS:-5}"
DURATION="${BENCH_DURATION_S:-30}"
CAPACITY="${BENCH_CAPACITY:-4096}"
BATCH="${BENCH_BATCH:-1}"
# Repetitions per target, median reported. A single run is not a measurement on a workstation:
# an unrelated app at 30% CPU moved `obsd` — which no code change touched — by 42% between two
# batches. The Rust run also acts as a CONTROL: every batch measures it in the same conditions as
# the Scala ones, so the ratio to it survives machine noise that the absolute rps does not.
REPS="${BENCH_REPS:-3}"
export BENCH_USERS BENCH_DURATION_S BENCH_CAPACITY BENCH_BATCH
BENCH_USERS="$USERS" BENCH_DURATION_S="$DURATION" BENCH_BATCH="$BATCH"

RESULTS="bench/target/results"
mkdir -p "$RESULTS"
: > "$RESULTS/summary.txt"
# Recorded because it is the single most useful thing for judging whether a run is comparable.
echo "load average at start: $(uptime)" | tee "$RESULTS/environment.txt"

say() { printf '\n=== %s ===\n' "$*"; }

# --- build every target up front, so a build failure never masquerades as a slow server ----------
if [ "$USERS" -gt 5 ]; then
  say "NOTE users=$USERS exceeds gatling-grpc's trial cap of 5 — SKIPPING the Rust gRPC run."
  say "     The JVM-vs-Native comparison below is still valid; the Rust column will be absent."
  SKIP_GRPC=1
else
  SKIP_GRPC=0
fi

say "building targets (capacity=$CAPACITY users=$USERS duration=${DURATION}s batch=$BATCH)"
cargo build --release --bin obsd --manifest-path oblivious-sidecar/Cargo.toml
sbt -batch -no-colors ";sidecarScala/writeClasspath ;sidecarScalaNative/nativeLink ;bench/compile"

CP_FILE="$(find target -name 'sidecar-scala.classpath' | head -1)"
NATIVE_BIN="$(find target -name 'sidecar-scala-native' -type f -perm +111 | head -1)"
[ -n "$CP_FILE" ] || { echo "no JVM classpath file; did sidecarScala/writeClasspath run?" >&2; exit 1; }
[ -n "$NATIVE_BIN" ] || { echo "no Scala Native binary; did nativeLink run?" >&2; exit 1; }

SERVER_PID=""
stop_server() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  SERVER_PID=""
}
trap stop_server EXIT

# Wait for the port to ACCEPT. "the process is still alive" is not evidence a server came up — it
# is equally satisfied by one that died after binding nothing, which would then be measured as a
# run of zero successful requests rather than reported as a failure.
wait_for_port() {
  local port="$1" tries=0
  until nc -z 127.0.0.1 "$port" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -gt 100 ] && { echo "nothing listening on $port after 20s" >&2; return 1; }
    sleep 0.2
  done
}

# Gatling prints throughput as e.g. "15,346.45"; strip the thousands separators for arithmetic.
extract_rps() {
  grep -E "mean throughput" "$1" | tail -1 | grep -oE "[0-9][0-9,]*\.[0-9]+" | tr -d ',' | tail -1
}

median() {
  printf '%s\n' "$@" | sort -n | awk '{v[NR]=$1} END {print (NR%2) ? v[(NR+1)/2] : (v[NR/2]+v[NR/2+1])/2}'
}

run_sim() {
  local label="$1" sim="$2" port_var="$3" port="$4"
  say "$label ($REPS reps, median reported)"
  wait_for_port "$port"
  local samples=() rep rps
  for rep in $(seq 1 "$REPS"); do
    env "$port_var=$port" BENCH_USERS="$USERS" BENCH_DURATION_S="$DURATION" BENCH_BATCH="$BATCH" \
      sbt -batch -no-colors "bench/runMain bench.Run $sim" > "$RESULTS/$label.rep$rep.log" 2>&1 || true
    rps="$(extract_rps "$RESULTS/$label.rep$rep.log")"
    if [ -z "$rps" ]; then
      echo "  rep $rep: NO RESULT — see $RESULTS/$label.rep$rep.log" >&2
      # An empty run is exactly what the gatling-grpc licence cap produces; never average it away.
      return 1
    fi
    echo "  rep $rep: $rps rps"
    samples+=("$rps")
  done
  local med
  med="$(median "${samples[@]}")"
  echo "  MEDIAN: $med rps"
  echo "$label $med" >> "$RESULTS/summary.txt"
}

# --- 1. the Rust sidecar, the real production path -----------------------------------------------
if [ "$SKIP_GRPC" -eq 0 ]; then
  OBSD_ADDR=127.0.0.1:50051 OBSD_CAPACITY="$CAPACITY" \
    ./oblivious-sidecar/target/release/obsd > "$RESULTS/obsd.server.log" 2>&1 &
  SERVER_PID=$!
  run_sim "rust-obsd-grpc-h2" bench.ObsdGrpcSimulation BENCH_GRPC_PORT 50051
  stop_server
fi

# --- 2. the same Scala sources on the JVM --------------------------------------------------------
SIDECAR_ADDR=127.0.0.1:50061 SIDECAR_CAPACITY="$CAPACITY" \
  java -cp "$(cat "$CP_FILE")" sidecar.Main > "$RESULTS/jvm.server.log" 2>&1 &
SERVER_PID=$!
run_sim "scala-jvm-grpc-h1" bench.ScalaSidecarSimulation BENCH_HTTP_PORT 50061
stop_server

# --- 3. and linked by Scala Native ---------------------------------------------------------------
SIDECAR_ADDR=127.0.0.1:50062 SIDECAR_CAPACITY="$CAPACITY" \
  "$NATIVE_BIN" > "$RESULTS/native.server.log" 2>&1 &
SERVER_PID=$!
run_sim "scala-native-grpc-h1" bench.ScalaSidecarSimulation BENCH_HTTP_PORT 50062
stop_server

say "summary (median of $REPS reps, $USERS users x ${DURATION}s, capacity $CAPACITY)"
awk '{ printf "  %-24s %12.1f rps", $1, $2
       if ($1 ~ /^rust-/) { base = $2; printf "   (control)\n" }
       else if (base > 0) { printf "   %.2fx the Rust control\n", $2 / base }
       else { printf "\n" } }' "$RESULTS/summary.txt"
echo "load average at end:   $(uptime)" | tee -a "$RESULTS/environment.txt"
say "done — per-run logs in $RESULTS, full Gatling reports in bench/target/gatling"

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
# or beyond 5 minutes (see ObsdGrpcSimulation). Exceeding either still benchmarks the two Scala
# targets against each other — the JVM-vs-Native comparison — but drops the Rust run, so we say so.
USERS="${BENCH_USERS:-5}"
DURATION="${BENCH_DURATION_S:-30}"
CAPACITY="${BENCH_CAPACITY:-4096}"
BATCH="${BENCH_BATCH:-1}"
# Repetitions per target, median reported. A single run is not a measurement on a workstation:
# an unrelated app at 30% CPU moved `obsd` — which no code change touched — by 42% between two
# batches. The Rust run also acts as a CONTROL: every batch measures it in the same conditions as
# the Scala ones, so the ratio to it survives machine noise that the absolute rps does not.
REPS="${BENCH_REPS:-3}"

RESULTS="bench/target/results"
mkdir -p "$RESULTS"
: > "$RESULTS/summary.txt"
# Recorded because it is the single most useful thing for judging whether a run is comparable.
echo "load average at start: $(uptime)" | tee "$RESULTS/environment.txt"

say() { printf '\n=== %s ===\n' "$*"; }

FAILED=""

# gatling-grpc's trial licence caps BOTH dimensions, and exceeding either makes the run record
# nothing while exiting non-zero. Guarding duration here as well as users means the operator is
# told which target is being dropped and why, instead of the Rust run failing mid-batch.
SKIP_GRPC=0
if [ "$USERS" -gt 5 ]; then
  say "NOTE users=$USERS exceeds gatling-grpc's trial cap of 5 — SKIPPING the Rust gRPC run."
  say "     The JVM-vs-Native comparison below is still valid; the Rust column will be absent."
  SKIP_GRPC=1
fi
if [ "$DURATION" -gt 300 ]; then
  say "NOTE duration=${DURATION}s exceeds gatling-grpc's trial cap of 5 minutes — SKIPPING the Rust run."
  SKIP_GRPC=1
fi

# --- build every target up front, so a build failure never masquerades as a slow server ----------
say "building targets (capacity=$CAPACITY users=$USERS duration=${DURATION}s batch=$BATCH reps=$REPS)"
cargo build --release --bin obsd --manifest-path oblivious-sidecar/Cargo.toml
sbt -batch -no-colors ";sidecarScala/writeClasspath ;sidecarScalaNative/nativeLink ;bench/compile"

CP_FILE="$(find target -name 'sidecar-scala.classpath' | head -1)"
# `-perm -u+x`, not `-perm +111`: the latter is a fatal error on GNU findutils ("invalid mode"),
# which would leave NATIVE_BIN empty and report "did nativeLink run?" after a full build.
NATIVE_BIN="$(find target -name 'sidecar-scala-native' -type f -perm -u+x | head -1)"
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
#
# bash's /dev/tcp rather than `nc -z`: netcat is absent on many hosts and the OpenBSD and nmap
# variants disagree about `-z`, so this was a second silent portability failure.
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

wait_for_port() {
  local port="$1" tries=0
  until port_open "$port"; do
    tries=$((tries + 1))
    [ "$tries" -gt 100 ] && { echo "nothing listening on $port after 20s" >&2; return 1; }
    sleep 0.2
  done
}

# Gatling's console table is `label | Total | OK | KO`, so pull a named COLUMN rather than "the last
# number on the line". The old heuristic (`grep -oE ... | tail -1`) silently reported the KO
# throughput as soon as anything failed: with KO=0 that cell is the `-` no-data marker so the last
# number happened to be OK, but on a line like `| 1,234.50 | 1,000.10 | 234.40` it returns 234.40.
# Field 3 is OK, field 4 is KO.
extract_col() { # file, row-regex, field
  awk -F'|' -v re="$2" -v f="$3" \
    '$0 ~ re { gsub(/[ ,]/, "", $f); v=$f } END { if (v != "" && v != "-") print v }' "$1"
}

median() {
  printf '%s\n' "$@" | sort -n | awk '{v[NR]=$1} END {print (NR%2) ? v[(NR+1)/2] : (v[NR/2]+v[NR/2+1])/2}'
}

# One rep. Echoes OK/KO counts so a degraded run is visible on the console, and fails the rep on
# any KO at all — Gatling exits 0 on a 100%-KO run, so its exit code alone is not a gate. (The
# simulations also declare `assertions(global.failedRequests.count.is(0))`, which makes Gatling's
# own status meaningful; this check is the belt to that braces, and reports the counts either way.)
one_rep() { # label, sim, port_var, port, rep -> prints rps on stdout, diagnostics on stderr
  local label="$1" sim="$2" port_var="$3" port="$4" rep="$5"
  local log="$RESULTS/$label.rep$rep.log" status=0

  wait_for_port "$port" || { echo "    server not listening before rep $rep" >&2; return 1; }

  env "$port_var=$port" BENCH_USERS="$USERS" BENCH_DURATION_S="$DURATION" BENCH_BATCH="$BATCH" \
    sbt -batch -no-colors "bench/runMain bench.Run $sim" > "$log" 2>&1 || status=$?

  local ok ko rps
  ok="$(extract_col "$log" "request count" 3)"
  ko="$(extract_col "$log" "request count" 4)"
  rps="$(extract_col "$log" "mean throughput" 3)"

  if [ "$status" -ne 0 ]; then
    echo "    sbt/Gatling exited $status — see $log" >&2
    return 1
  fi
  if [ -z "$rps" ] || [ -z "$ok" ]; then
    # Exactly what the gatling-grpc licence cap produces: a run that records nothing.
    echo "    no result recorded — see $log" >&2
    return 1
  fi
  if [ -n "$ko" ] && [ "$ko" != "0" ]; then
    echo "    ${ko} FAILED requests (OK=${ok}) — not a usable measurement, see $log" >&2
    return 1
  fi
  echo "$rps ${ok:-?}"
}

run_sim() {
  local label="$1" sim="$2" port_var="$3" port="$4"
  say "$label (1 discarded warm-up + $REPS reps, median reported)"

  # A discarded warm-up rep. The server is started once per target and reused, so without this the
  # JVM's first rep measures a cold, un-JITted server and the median bakes that ordering bias in
  # rather than removing it — visibly so: an earlier batch ran 4,543 -> 5,495 -> 5,619, monotonic.
  local warm
  if warm="$(one_rep "$label" "$sim" "$port_var" "$port" 0)"; then
    echo "  warm-up (discarded): ${warm%% *} rps"
  else
    echo "  warm-up rep FAILED" >&2
    return 1
  fi

  local samples=() rep out
  for rep in $(seq 1 "$REPS"); do
    if out="$(one_rep "$label" "$sim" "$port_var" "$port" "$rep")"; then
      echo "  rep $rep: ${out%% *} rps (${out##* } requests, 0 failed)"
      samples+=("${out%% *}")
    else
      echo "  rep $rep: NO RESULT" >&2
      return 1
    fi
  done

  [ "${#samples[@]}" -gt 0 ] || return 1
  local med
  med="$(median "${samples[@]}")"
  echo "  MEDIAN: $med rps"
  echo "$label $med" >> "$RESULTS/summary.txt"
}

# `|| FAILED=...` rather than a bare call: `run_sim` returning non-zero is a top-level simple
# command, so under `set -e` it would kill the whole batch — including the two targets that have
# nothing to do with the failure, and the summary and environment footer at the end. One target
# failing must not cost the others their measurement.
attempt() { # label, sim, port_var, port
  run_sim "$@" || FAILED="$FAILED $1"
}

# --- 1. the Rust sidecar, the real production path -----------------------------------------------
if [ "$SKIP_GRPC" -eq 0 ]; then
  OBSD_ADDR=127.0.0.1:50051 OBSD_CAPACITY="$CAPACITY" \
    ./oblivious-sidecar/target/release/obsd > "$RESULTS/obsd.server.log" 2>&1 &
  SERVER_PID=$!
  attempt "rust-obsd-grpc-h2" bench.ObsdGrpcSimulation BENCH_GRPC_PORT 50051
  stop_server
fi

# --- 2. the same Scala sources on the JVM --------------------------------------------------------
SIDECAR_ADDR=127.0.0.1:50061 SIDECAR_CAPACITY="$CAPACITY" \
  java -cp "$(cat "$CP_FILE")" sidecar.Main > "$RESULTS/jvm.server.log" 2>&1 &
SERVER_PID=$!
attempt "scala-jvm-grpc-h1" bench.ScalaSidecarSimulation BENCH_HTTP_PORT 50061
stop_server

# --- 3. and linked by Scala Native ---------------------------------------------------------------
SIDECAR_ADDR=127.0.0.1:50062 SIDECAR_CAPACITY="$CAPACITY" \
  "$NATIVE_BIN" > "$RESULTS/native.server.log" 2>&1 &
SERVER_PID=$!
attempt "scala-native-grpc-h1" bench.ScalaSidecarSimulation BENCH_HTTP_PORT 50062
stop_server

say "summary (median of $REPS reps, $USERS users x ${DURATION}s, capacity $CAPACITY)"
awk '{ printf "  %-24s %12.1f rps", $1, $2
       if ($1 ~ /^rust-/) { base = $2; printf "   (control)\n" }
       else if (base > 0) { printf "   %.2fx the Rust control\n", $2 / base }
       else { printf "\n" } }' "$RESULTS/summary.txt"
echo "load average at end:   $(uptime)" | tee -a "$RESULTS/environment.txt"

if [ -n "$FAILED" ]; then
  say "INCOMPLETE — no usable measurement for:$FAILED (see $RESULTS/*.log)"
  exit 1
fi
say "done — per-run logs in $RESULTS, full Gatling reports in bench/target/gatling"

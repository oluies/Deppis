#!/usr/bin/env bash
#
# Deppis headless prototype launcher.
#
# Builds the Rust `obsd` oblivious sidecar, then runs the two-party metadata-private
# delivery demo (`transport.DeppisDemo`) through it: two engines pair out of band and
# a message is delivered through the real sidecar with uniform per-round cover traffic.
#
# THIS IS A DEV BUILD — NO METADATA PRIVACY (Constitution IV). The dev store/notify
# provide no access-pattern privacy and the run is unattested; the demo prints the
# `DEV, NO METADATA PRIVACY` label throughout.
#
# Usage: scripts/run-demo.sh
# Requires: cargo (Rust), sbt (JDK 21+ for the Foreign Function & Memory API).

set -euo pipefail

# Repo root = parent of this script's directory (works from any CWD).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' not found on PATH — please install it." >&2; exit 127; }; }
need cargo
need sbt

echo "==> Building obsd (Rust oblivious sidecar) …"
cargo build --bin obsd --manifest-path oblivious-sidecar/Cargo.toml

# DeppisDemo can find obsd on a relative path, but be explicit so the script works
# regardless of the forked JVM's working directory.
export OBSD_BIN="$ROOT/oblivious-sidecar/target/debug/obsd"
[ -x "$OBSD_BIN" ] || { echo "error: obsd binary not found at $OBSD_BIN" >&2; exit 1; }

echo "==> Running DeppisDemo (spawns obsd, pairs two engines, delivers a message) …"
echo
# `exec` so the demo's exit code (0 = delivered) becomes the script's exit code.
exec sbt -batch "transport/runMain transport.DeppisDemo"

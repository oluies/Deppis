#!/usr/bin/env bash
# Reproducible enclave build + measurement (T057, Constitution X) — Docker + Gramine SGX-sim.
#
# Builds the obsd sidecar deterministically and measures it under Gramine, producing the enclave
# MRENCLAVE. The Dockerfile asserts reproducibility INTERNALLY (it builds obsd twice in an identical
# path and fails the build unless the two binaries are byte-identical, and likewise re-signs and
# compares MRENCLAVE), so a successful `docker build` already proves a deterministic measurement.
# This script runs that build and prints the measurement; pass `--twice` to additionally rebuild the
# whole image from scratch and diff the exported measurement across two independent invocations.
#
# Requires Docker only — NO SGX hardware. `gramine-sgx-sign` computes MRENCLAVE on any machine; only
# *running* the enclave needs SGX. On an arm64 host the amd64 image runs under emulation (slower);
# on a native x86 CI runner it is fast. The signed measurement is DEV until produced on real SGX with
# a PCK-endorsed key and published to the transparency log (steps 3-4 in README.md) — see the label
# rule (Constitution IV): this build does not by itself entitle any deployment to claim privacy.
set -euo pipefail
cd "$(dirname "$0")"

PLATFORM="${PLATFORM:-linux/amd64}"
build() { # $1 = output dir
  docker build --platform "$PLATFORM" --no-cache --progress=plain \
    --output "type=local,dest=$1" -f Dockerfile ../.. >"$1.log" 2>&1
}

echo "[reproduce] building enclave measurement (platform=$PLATFORM) ..."
build out
M1="$(cat out/mrenclave.hex)"
echo "[reproduce] MRENCLAVE = $M1"

if [[ "${1:-}" == "--twice" ]]; then
  echo "[reproduce] second independent from-scratch build for cross-invocation determinism ..."
  build out2
  M2="$(cat out2/mrenclave.hex)"
  echo "[reproduce] build #2 MRENCLAVE = $M2"
  if [[ "$M1" == "$M2" ]]; then
    echo "[reproduce] CROSS-BUILD REPRODUCIBLE ✓ ($M1)"
  else
    echo "[reproduce] MISMATCH ✗ ($M1 != $M2)" >&2
    exit 1
  fi
fi

echo "[reproduce] done. Record this measurement in the transparency log (ReferenceLog) as the"
echo "[reproduce] reference value the attestation verifier appraises quotes against."

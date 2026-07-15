#!/usr/bin/env bash
# Regenerate the committed attack graphs in graphs/ from the models beside this script.
#
# WHY THIS EXISTS: graphs/*.svg are GENERATED artifacts committed for reviewers who should not have to
# install Tamarin to see what the falsified lemmas actually mean. Committed images can drift silently
# from the models they claim to depict — that is exactly the "the doc asserts something the code does
# not do" failure this analysis has been bitten by repeatedly. So: never hand-edit graphs/*.svg, and
# re-run this whenever a model changes. `--check` fails if the committed SVGs are stale.
#
# Requires: tamarin-prover + graphviz `dot` (the Homebrew tamarin tap installs both).
#   brew install tamarin-prover/tap/tamarin-prover
#
# Usage:
#   ./render-attack-graphs.sh            # regenerate graphs/*.svg in place
#   ./render-attack-graphs.sh --check    # exit 1 if the committed SVGs are stale (CI-friendly)
set -euo pipefail

cd "$(dirname "$0")"
OUT=graphs
mkdir -p "$OUT"

# Each entry: <model>|<lemma>|<output-basename>
# ONLY falsified lemmas produce a trace — Tamarin emits a graph for the counterexample it found.
# A *verified* all-traces lemma has no trace to draw, which is why the fold model itself has no image:
# its result is the ABSENCE of an attack, and absence has no picture. That asymmetry is the point.
TARGETS=(
  "ratchet-pq-epoch-nofold.spthy|pq_post_compromise_security|nofold-attack"
  "ratchet-pq-epoch-hijack.spthy|pq_post_compromise_security|hijack-attack"
)

check=0
[ "${1:-}" = "--check" ] && check=1
status=0

for t in "${TARGETS[@]}"; do
  model="${t%%|*}"; rest="${t#*|}"; lemma="${rest%%|*}"; base="${rest##*|}"
  tmp="$(mktemp -d)"
  # --prove=<lemma> restricts proving to the one lemma; --output-dot serializes the found trace.
  tamarin-prover "$model" --prove="$lemma" --output-dot="$tmp/t.dot" >"$tmp/log" 2>&1

  if ! grep -q "falsified" "$tmp/log"; then
    echo "ERROR: $model :: $lemma did NOT falsify — there is no attack trace to render." >&2
    echo "       If this lemma now VERIFIES, the model changed meaning; fix this script and the" >&2
    echo "       README rather than shipping a stale picture of an attack that no longer exists." >&2
    rm -rf "$tmp"; exit 1
  fi
  [ -s "$tmp/t.dot" ] || { echo "ERROR: no dot emitted for $model :: $lemma" >&2; rm -rf "$tmp"; exit 1; }

  dot -Tsvg "$tmp/t.dot" -o "$tmp/t.svg"

  if [ "$check" = 1 ]; then
    if ! diff -q "$tmp/t.svg" "$OUT/$base.svg" >/dev/null 2>&1; then
      echo "STALE: $OUT/$base.svg does not match a fresh render of $model :: $lemma" >&2
      status=1
    else
      echo "ok: $OUT/$base.svg"
    fi
  else
    mv "$tmp/t.svg" "$OUT/$base.svg"
    steps="$(grep -oE 'falsified - found trace \([0-9]+ steps\)' "$tmp/log" | head -1)"
    echo "wrote $OUT/$base.svg   ($model :: $lemma — $steps)"
  fi
  rm -rf "$tmp"
done

exit "$status"

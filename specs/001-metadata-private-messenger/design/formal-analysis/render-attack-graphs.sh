#!/usr/bin/env bash
# Regenerate the committed attack graphs in graphs/ from the models beside this script.
#
# WHY THIS EXISTS: graphs/*.svg are GENERATED artifacts committed for reviewers who should not have to
# install Tamarin to see what the falsified lemmas actually mean. Committed images can drift silently
# from the models they claim to depict — that is exactly the "the doc asserts something the code does
# not do" failure this analysis has been bitten by repeatedly. So: never hand-edit graphs/*.svg, and
# re-run this whenever a model changes.
#
# Requires: tamarin-prover + graphviz `dot` (the Homebrew tamarin tap installs both).
#   brew install tamarin-prover/tap/tamarin-prover
#
# Usage:
#   ./render-attack-graphs.sh            # regenerate graphs/*.svg in place
#   ./render-attack-graphs.sh --check    # exit 1 if the committed SVGs are stale
#
# NOTE on --check: `dot` layout is NOT guaranteed byte-stable across graphviz versions, so a bump can
# report STALE with no model change. It is a drift alarm for humans — do NOT wire it into CI as a gate
# (the README says the same; keep the two consistent).
set -euo pipefail

cd "$(dirname "$0")"
OUT=graphs
mkdir -p "$OUT"

command -v tamarin-prover >/dev/null 2>&1 || { echo "ERROR: tamarin-prover not on PATH (brew install tamarin-prover/tap/tamarin-prover)" >&2; exit 1; }
command -v dot            >/dev/null 2>&1 || { echo "ERROR: graphviz 'dot' not on PATH" >&2; exit 1; }

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

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for t in "${TARGETS[@]}"; do
  model="${t%%|*}"; rest="${t#*|}"; lemma="${rest%%|*}"; base="${rest##*|}"
  rm -f "$tmp/t.dot" "$tmp/t.svg" "$tmp/log"

  # Guard the invocation explicitly: under `set -e` a bare call would abort HERE with the log trapped
  # in a temp file and none of the diagnostics below ever printed — the opposite of "fails loudly".
  if ! tamarin-prover "$model" --prove="$lemma" --output-dot="$tmp/t.dot" >"$tmp/log" 2>&1; then
    echo "ERROR: prover failed on $model :: $lemma — output follows:" >&2
    cat "$tmp/log" >&2
    exit 1
  fi

  # Anchor to THIS lemma. A bare `grep -q falsified` would match a falsification anywhere in the log
  # (another lemma, or the word echoed in theory text) and pass while `$lemma` itself verified — the
  # exact silent drift this guard exists to catch.
  if ! grep -qE "^[[:space:]]*${lemma}[[:space:]]*\(.*\):[[:space:]]*falsified" "$tmp/log"; then
    echo "ERROR: $model :: $lemma did NOT falsify — there is no attack trace to render." >&2
    echo "       If this lemma now VERIFIES, the model changed meaning; fix this script and the" >&2
    echo "       README rather than shipping a stale picture of an attack that no longer exists." >&2
    echo "       Prover summary:" >&2
    grep -E "verified|falsified" "$tmp/log" >&2 || true
    exit 1
  fi
  [ -s "$tmp/t.dot" ] || { echo "ERROR: no dot emitted for $model :: $lemma" >&2; exit 1; }

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
    # `|| true`: this is a cosmetic progress line. Without it, a future tamarin rephrasing the summary
    # would make grep match nothing, return 1, and abort under `set -o pipefail` AFTER an SVG was
    # already moved into place — a half-regenerated graphs/ for a message that does not matter.
    steps="$(grep -oE 'falsified - found trace \([0-9]+ steps\)' "$tmp/log" | head -1 || true)"
    echo "wrote $OUT/$base.svg   ($model :: $lemma — ${steps:-falsified})"
  fi
done

exit "$status"

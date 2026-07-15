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
  #
  # Two DIFFERENT failures live here and must not be conflated: "the summary says this lemma
  # verified" (the model changed meaning) vs. "no recognisable summary line for this lemma at all"
  # (Tamarin rephrased its output). Reporting the second as the first would hand the reader a
  # confident, WRONG diagnosis — telling them a security property flipped when only a format did.
  # That is the same defect guarded against at the prover invocation above.
  summary="$(grep -E "^[[:space:]]*${lemma}[[:space:]]*\(" "$tmp/log" || true)"
  if [ -z "$summary" ]; then
    echo "ERROR: no summary line found for $lemma in $model — Tamarin's output format may have" >&2
    echo "       changed. This is NOT necessarily a security result; do not touch the README on" >&2
    echo "       the strength of this message. Update this script's parser. Full output:" >&2
    cat "$tmp/log" >&2
    exit 1
  fi
  if ! printf '%s\n' "$summary" | grep -qE ":[[:space:]]*falsified"; then
    echo "ERROR: $model :: $lemma did NOT falsify — there is no attack trace to render." >&2
    echo "       If this lemma now VERIFIES, the model changed meaning; fix this script and the" >&2
    echo "       README rather than shipping a stale picture of an attack that no longer exists." >&2
    echo "       Summary line: $summary" >&2
    exit 1
  fi
  [ -s "$tmp/t.dot" ] || { echo "ERROR: no dot emitted for $model :: $lemma" >&2; exit 1; }

  # CONFRONT THE README WITH THE ARTIFACT. The §5.2.1 table hardcodes a step count per graph; the
  # prover just told us the real one. Without this the images are drift-checked and the PROSE is not:
  # a model edit changes the trace, --check says STALE, the reader regenerates, and the sentence
  # beside the picture silently becomes false — the exact failure this whole section exists to
  # prevent. Cheap to check, so check it rather than trusting a human to remember.
  real_steps="$(printf '%s\n' "$summary" | grep -oE '\(([0-9]+) steps\)' | grep -oE '[0-9]+' | head -1 || true)"
  doc_steps="$(grep -F "graphs/$base.svg" README.md | grep -oE 'falsified, [0-9]+ steps' | grep -oE '[0-9]+' | head -1 || true)"
  # A check that silently does nothing when it cannot parse is worse than no check: it reads as
  # enforcement in review while enforcing nothing. If either side won't parse, say so and fail.
  if [ -z "$real_steps" ] || [ -z "$doc_steps" ]; then
    echo "ERROR: step-count check could not run for $base (prover='${real_steps:-?}'," >&2
    echo "       README='${doc_steps:-?}'). This is a PARSER problem, not a security result —" >&2
    echo "       fix the parsing rather than assuming the claim still holds." >&2
    exit 1
  fi
  if [ "$real_steps" != "$doc_steps" ]; then
    echo "STALE PROSE: README §5.2.1 says '$doc_steps steps' for $base, prover says '$real_steps'." >&2
    echo "             Regenerating the SVG will NOT fix the sentence next to it. Update both." >&2
    status=1
  fi

  dot -Tsvg "$tmp/t.dot" -o "$tmp/t.svg"

  # The hijack row makes SPECIFIC structural claims about its trace, because a vaguer sentence was
  # what got the previous revision wrong (it said the adversary "supplies its own KEM public key";
  # the trace shows it does not). Specific claims are only safe if they are checked — otherwise they
  # rot the moment the model moves. These greps ARE the claims:
  #   * the attacker encapsulates under the HONEST epoch key            -> aenc(ss, pk(~ek)) present
  #   * it never supplies a key of its own                              -> exactly one ~ek name
  # Assert on the .dot, NOT the rendered .svg: graphviz emits labels as <text> runs, may split a long
  # label across elements, and escapes XML metacharacters — so a substring match against SVG bytes can
  # fail while the trace is unchanged, yielding a confident "the attack's SHAPE changed". The .dot is
  # the upstream, stabler surface. Whitespace-tolerant for the same reason.
  # ($tmp/t.dot is guaranteed present and non-empty by the `-s` guard above, which exits loudly —
  # so a missing/renamed artifact cannot reach these greps and be mis-reported as a shape change.)
  if [ "$base" = "hijack-attack" ]; then
    # The closing `\)` is load-bearing: an unanchored `pk(~ek` prefix also matches `pk(~ek.1)` /
    # `pk(~ek.2)` — an epoch key the ADVERSARY supplied — and would report "encapsulates under the
    # HONEST key" for a trace that does the opposite, which is the exact claim this grep encodes. It
    # would also match `pk(~ekey)`, the false-positive class the sibling `\b` exists to stop.
    if ! grep -qE 'aenc\(ss,[[:space:]]*pk\(~ek\)' "$tmp/t.dot"; then
      echo "STALE PROSE: README claims the hijack trace shows aenc(ss, pk(~ek)) — not found in the" >&2
      echo "             fresh render. The attack's SHAPE changed; rewrite the sentence, not just" >&2
      echo "             the picture." >&2
      status=1
    fi
    # Tamarin disambiguates repeated fresh names with a DOT suffix (~ek, ~ek.1) — NOT a bare digit.
    # An earlier version of this guard used '~ek[0-9]*', which matches only the '~ek' prefix of
    # '~ek.1', so `sort -u` collapsed the two into one and it reported "1 distinct" in precisely the
    # two-key case it exists to detect: a no-op against its own threat model. The \b also stops an
    # unrelated name like ~ekey from counting.
    eks="$(grep -oE '~ek(\.[0-9]+)?\b' "$tmp/t.dot" | sort -u | wc -l | tr -d ' ')"
    if [ "$eks" != "1" ]; then
      echo "STALE PROSE: README claims 'no second ~ek exists in the trace' (i.e. the adversary uses" >&2
      echo "             no key of its own), but the fresh render has $eks distinct ~ek names." >&2
      status=1
    fi
  fi

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

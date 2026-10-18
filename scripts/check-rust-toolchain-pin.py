#!/usr/bin/env python3
"""Fail unless rust-toolchain.toml and every CI workflow pin the same Rust version.

The Rust toolchain is a build input, so Constitution XI applies to it. It is pinned in two places
that rustup and GitHub Actions read independently:

  * rust-toolchain.toml  -> [toolchain] channel, which governs every local `cargo` call and both
                            CI jobs that shell out to cargo
  * .github/workflows/*  -> `dtolnay/rust-toolchain@<ver>`, which is what CI installs (that action
                            ignores rust-toolchain.toml entirely — toolchain choice comes from the
                            @rev or an explicit `with: toolchain:` input, nothing else)

Nothing makes them agree on its own. If they drift, CI installs one compiler and then rustup
silently downloads and uses another on the first cargo call: slow, confusing, and it defeats the
pin, because the version the workflow advertises is no longer the version that built anything.

A THIRD pin exists and is deliberately OUT OF SCOPE here: deploy/enclave/Dockerfile builds obsd
`FROM rust:<ver>-bookworm`, recorded in deploy/enclave/measurement.txt. That compiler is bound to
the enclave measurement — bumping it changes MRENCLAVE — so it moves on the attestation's schedule,
not CI's, and must NOT be dragged along by a CI toolchain bump. It is reported for visibility and
never enforced. No CI job builds that image, so sidecar code CI accepts under the workflow
toolchain can still fail the reproducible enclave build; that gap is real and not this gate's job.

It also asserts rust-toolchain.toml sits at the repo root. rustup resolves that file by walking up
from the current directory, not from --manifest-path, and CI's integration job runs cargo from the
root with `--manifest-path oblivious-sidecar/Cargo.toml`. Moved down next to the crate the file
would be silently ignored there, so "tidying" it into oblivious-sidecar/ is a real regression.

Stdlib only, on purpose: a hygiene gate that fails because PyYAML is absent from a runner would be
worse than the drift it checks for. The step scan below is indentation-aware rather than a full
YAML parse, which is enough to find an action's `uses:` and its `with: toolchain:` sibling.

Usage: check-rust-toolchain-pin.py [repo-root]   (default: cwd)
"""

import re
import sys
import tomllib
from pathlib import Path

WORKFLOW_DIR = Path(".github/workflows")
TOOLCHAIN_FILE = Path("rust-toolchain.toml")
ENCLAVE_DOCKERFILE = Path("deploy/enclave/Dockerfile")

ACTION = "dtolnay/rust-toolchain"
# The leading `- ` is OPTIONAL: `uses:` is only the step's first key in the unnamed form. The
# common `- name: Install Rust` / `uses: ...` shape has no dash on the uses line, and requiring
# one let a floating @stable install hide in a named step while the gate reported OK.
# The quotes are optional too: `uses: "dtolnay/rust-toolchain@stable"` is legal YAML and used to
# make the whole step invisible.
USES_RE = re.compile(
    rf"""^(?P<indent>\s*)(?:-\s*)?uses:\s*["']?{re.escape(ACTION)}@(?P<ref>[^\s"']+)"""
)
TOOLCHAIN_INPUT_RE = re.compile(r"^(?P<indent>\s*)toolchain:\s*(?P<val>[^\s#]+)")
# `with: { toolchain: stable }` — a flow mapping, which the line-anchored pattern above misses.
TOOLCHAIN_FLOW_RE = re.compile(r"[{,]\s*toolchain:\s*(?P<val>[^\s,}#]+)")
# Any mention at all, for the fail-closed backstop below.
MENTION_RE = re.compile(re.escape(ACTION))
ENCLAVE_FROM_RE = re.compile(r"^FROM\s+rust:(?P<ver>[0-9][^\s-]*)", re.MULTILINE)
# A pin is an exact version; a channel name is what we are trying to keep out.
SEMVER_RE = re.compile(r"^\d+\.\d+(\.\d+)?$")


def fail(msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


def key_indent(line: str) -> int:
    """Column of the step's first KEY, skipping a list dash so `- uses:` and `uses:` agree."""
    stripped = line.lstrip()
    lead = len(line) - len(stripped)
    return lead + 2 if stripped.startswith("- ") else lead


def raw_indent(line: str) -> int:
    """Column of the first non-space character, dash included."""
    return len(line) - len(line.lstrip())


def skippable(line: str) -> bool:
    """Blank or comment — carries no structure, so a step walk must step OVER it."""
    stripped = line.lstrip()
    return not stripped or stripped.startswith("#")


def step_bounds(lines: list[str], i: int, step_col: int) -> tuple[int, int]:
    """The [start, end) line range of the step whose `uses:` key sits at `step_col` on line i.

    The boundary test is RAW indent, not key_indent: a sibling list item's dash sits at
    step_col - 2, so raw indent catches it while key_indent (which adds 2 for `- `) reports an
    equal column and walks straight into the next step. That bug attributed a later step's
    `toolchain:` input to this one. Blank and comment lines are stepped over rather than treated
    as a boundary — a comment at the dash column used to end the walk early and hide an override.

    Scans BOTH directions, because `with:`/`toolchain:` may be written above the `uses:` key.
    """
    start = i
    while start > 0:
        prev = lines[start - 1]
        if skippable(prev):
            start -= 1
            continue
        if raw_indent(prev) < step_col:
            break
        start -= 1
    end = i + 1
    while end < len(lines):
        nxt = lines[end]
        if skippable(nxt):
            end += 1
            continue
        if raw_indent(nxt) < step_col:
            break
        end += 1
    return start, end


def toolchain_override(lines: list[str], span: tuple[int, int], step_col: int) -> str | None:
    """The step's `toolchain:` input, block or flow form, if it has one."""
    for line in lines[span[0] : span[1]]:
        if skippable(line):
            continue
        if (t := TOOLCHAIN_INPUT_RE.match(line)) and len(t.group("indent")) > step_col:
            return t.group("val").strip("\"'")
        if (f := TOOLCHAIN_FLOW_RE.search(line)) and raw_indent(line) >= step_col:
            return f.group("val").strip("\"'")
    return None


def installs(path: Path) -> list[tuple[str, str | None, int]]:
    """Every `dtolnay/rust-toolchain` step in one workflow: (ref, toolchain-input, line no)."""
    lines = path.read_text().splitlines()
    found = []
    for i, line in enumerate(lines):
        if not (m := USES_RE.match(line)):
            continue
        step_col = key_indent(line)
        override = toolchain_override(lines, step_bounds(lines, i, step_col), step_col)
        found.append((m.group("ref"), override, i + 1))
    return found


def unparsed_mentions(path: Path, matched_lines: set[int]) -> list[int]:
    """Lines naming the action that the structured scan did NOT claim.

    FAIL CLOSED. Both earlier rounds of this gate shipped the same shape of bug: a YAML form the
    matcher did not anticipate PASSED silently, which is strictly worse than a false alarm. Any
    unrecognised mention is now an error, so the failure mode of a parsing gap is noise rather
    than a floating toolchain nobody notices.
    """
    out = []
    for i, line in enumerate(path.read_text().splitlines(), start=1):
        if skippable(line) or i in matched_lines:
            continue
        if MENTION_RE.search(line):
            out.append(i)
    return out


def main() -> None:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()

    toolchain_path = root / TOOLCHAIN_FILE
    if not toolchain_path.is_file():
        fail(
            f"{TOOLCHAIN_FILE} must exist at the repo root (rustup resolves it from the current "
            "directory, not from --manifest-path, so CI's integration job would miss it elsewhere)"
        )

    with toolchain_path.open("rb") as fh:
        pinned = tomllib.load(fh).get("toolchain", {}).get("channel")
    if not pinned:
        fail(f"{TOOLCHAIN_FILE} must set [toolchain] channel")
    if not SEMVER_RE.match(pinned):
        fail(
            f"{TOOLCHAIN_FILE} channel is {pinned!r}, not an exact version. A floating channel is "
            "not a pin: stable rolling forward enabled a new clippy lint and reddened every open "
            "PR at once (#159)."
        )

    wf_dir = root / WORKFLOW_DIR
    if not wf_dir.is_dir():
        fail(f"{WORKFLOW_DIR} not found")

    # EVERY workflow, not just ci.yml: a Rust install added to any other one escaped the old check.
    steps: list[tuple[Path, str, str | None, int]] = []
    unparsed: list[str] = []
    for wf in sorted(p for p in wf_dir.iterdir() if p.suffix in (".yml", ".yaml")):
        rel = WORKFLOW_DIR / wf.name
        got = installs(wf)
        steps.extend((rel, ref, override, ln) for ref, override, ln in got)
        unparsed += [f"{rel}:{ln}" for ln in unparsed_mentions(wf, {ln for _, _, ln in got})]

    if not steps:
        fail(f"no {ACTION} step found under {WORKFLOW_DIR} — expected the pinned action")

    if unparsed:
        fail(
            f"{ACTION} named in a form this check cannot read, so its version cannot be verified: "
            + ", ".join(unparsed)
            + ". Write it as `uses: "
            + f"{ACTION}@<version>` (quotes optional), or teach this script the new shape."
        )

    problems = []
    for rel, ref, override, ln in steps:
        where = f"{rel}:{ln}"
        if not SEMVER_RE.match(ref):
            problems.append(f"{where} uses floating ref @{ref}; pin it to @{pinned}")
        elif ref != pinned:
            problems.append(f"{where} installs {ref} but {TOOLCHAIN_FILE} pins {pinned}")
        # An explicit `toolchain:` input OVERRIDES the @rev at runtime, so a pinned ref with a
        # floating input is a pin in appearance only.
        if override is not None and override != pinned:
            problems.append(
                f"{where} passes `toolchain: {override}`, which overrides the @{ref} ref at "
                f"runtime; it must equal {pinned} or be removed"
            )

    if problems:
        fail(
            "Rust toolchain pin drift. Bump every place in the same commit:\n  - "
            + "\n  - ".join(problems)
        )

    note = ""
    enclave = root / ENCLAVE_DOCKERFILE
    if enclave.is_file() and (m := ENCLAVE_FROM_RE.search(enclave.read_text())):
        note = (
            f"; {ENCLAVE_DOCKERFILE} independently pins rust:{m.group('ver')} for the enclave "
            "measurement (not enforced here — bumping it changes MRENCLAVE)"
        )

    print(
        f"rust-toolchain pin OK: {pinned} in {TOOLCHAIN_FILE} and all {len(steps)} "
        f"workflow install step(s){note}"
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Fail unless rust-toolchain.toml and the CI workflow pin the same Rust version.

The Rust toolchain is a build input, so Constitution XI applies to it. It is pinned in two places
that rustup and GitHub Actions read independently:

  * rust-toolchain.toml  -> [toolchain] channel, which governs every local `cargo` call and both
                            CI jobs that shell out to cargo
  * .github/workflows/ci.yml -> `dtolnay/rust-toolchain@<ver>`, which is what CI actually installs
                            (that action ignores rust-toolchain.toml entirely — toolchain choice
                            comes from the @rev or an explicit input, nothing else)

Nothing makes them agree on its own. If they drift, CI installs one compiler and then rustup
silently downloads and uses another on the first cargo call: slow, confusing, and it defeats the
pin, because the version the workflow advertises is no longer the version that built anything.
This check makes the rule mechanical so a one-sided bump fails fast and loudly.

It also asserts rust-toolchain.toml sits at the repo root. rustup resolves that file by walking up
from the current directory, not from --manifest-path, and CI's integration job runs cargo from the
root with `--manifest-path oblivious-sidecar/Cargo.toml`. Moved down next to the crate the file
would be silently ignored there, so "tidying" it into oblivious-sidecar/ is a real regression.

Usage: check-rust-toolchain-pin.py [repo-root]   (default: cwd)
"""

import re
import sys
import tomllib
from pathlib import Path

WORKFLOW = Path(".github/workflows/ci.yml")
TOOLCHAIN_FILE = Path("rust-toolchain.toml")
ACTION_RE = re.compile(r"^\s*-\s*uses:\s*dtolnay/rust-toolchain@(?P<ver>\S+)", re.MULTILINE)
# A pin is an exact version; a channel name is what we are trying to keep out.
SEMVER_RE = re.compile(r"^\d+\.\d+(\.\d+)?$")


def fail(msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


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

    workflow_path = root / WORKFLOW
    if not workflow_path.is_file():
        fail(f"{WORKFLOW} not found")

    refs = ACTION_RE.findall(workflow_path.read_text())
    if not refs:
        fail(f"{WORKFLOW} installs no dtolnay/rust-toolchain — expected the pinned action")

    versions = refs
    floating = sorted({v for v in versions if not SEMVER_RE.match(v)})
    if floating:
        fail(
            f"{WORKFLOW} uses floating Rust toolchain ref(s) {', '.join(floating)}; pin to "
            f"dtolnay/rust-toolchain@{pinned} to match {TOOLCHAIN_FILE}"
        )

    mismatched = sorted({v for v in versions if v != pinned})
    if mismatched:
        fail(
            f"Rust toolchain pin drift: {TOOLCHAIN_FILE} pins {pinned} but {WORKFLOW} installs "
            f"{', '.join(mismatched)}. Bump both in the same commit."
        )

    print(f"rust-toolchain pin OK: {pinned} in {TOOLCHAIN_FILE} and all {len(versions)} CI install step(s)")


if __name__ == "__main__":
    main()

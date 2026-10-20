#!/usr/bin/env python3
"""Regression tests for check-rust-toolchain-pin.py.

WHY THIS FILE EXISTS. The gate's YAML step scan has now regressed three times, each round
fixing the previous round's blind spot and opening a new one:

  * #160 shipped a regex requiring `uses:` to be a step's first token, so a floating install in a
    named step was invisible (roborev 1998).
  * #170 replaced it with a hand-rolled walk that compared the WRONG indent, so it ran into the
    following step, and treated a comment as a boundary, so one comment line hid an override
    (roborev 2040).
  * The fix for that added a backward walk which crossed into the PRECEDING step — the same
    over-attribution bug mirrored (roborev 2041).

Every round was reported as "verified against fixtures", and every round's fixtures were built ad
hoc and thrown away, so round N+1 could not catch round N's regression. That is the actual defect
this file fixes. Each case below is a shape some round got wrong; none may be deleted without a
reason better than "it passes now".

stdlib `unittest` and subprocess only — the script under test is deliberately stdlib-only so a
hygiene gate cannot fail on a missing module, and its tests inherit that constraint.

Run: python3 scripts/test_check_rust_toolchain_pin.py
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-rust-toolchain-pin.py"
PIN = "1.99.0"
TOML = f'[toolchain]\nchannel = "{PIN}"\ncomponents = ["rustfmt", "clippy"]\nprofile = "minimal"\n'


class GateCase(unittest.TestCase):
    """Builds a throwaway repo root and runs the real script against it."""

    def run_gate(self, workflows: dict[str, str], toml: str | None = TOML, extra: dict = {}):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github" / "workflows").mkdir(parents=True)
            if toml is not None:
                (root / "rust-toolchain.toml").write_text(toml)
            for name, body in workflows.items():
                (root / ".github" / "workflows" / name).write_text(body)
            for rel, body in extra.items():
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(body)
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(root)], capture_output=True, text=True
            )
            return proc.returncode, proc.stdout + proc.stderr

    def assertRejected(self, workflows, because: str, **kw):
        code, out = self.run_gate(workflows, **kw)
        self.assertEqual(code, 1, f"expected rejection ({because}); got pass:\n{out}")
        return out

    def assertAccepted(self, workflows, because: str, **kw):
        code, out = self.run_gate(workflows, **kw)
        self.assertEqual(code, 0, f"expected pass ({because}); got rejection:\n{out}")
        return out


PINNED_STEP = f"""jobs:
  rust:
    steps:
      - uses: dtolnay/rust-toolchain@{PIN}
"""


class TestDriftRegressions(GateCase):
    """The original six. Nothing below may start passing."""

    def test_floating_action_ref(self):
        self.assertRejected(
            {"ci.yml": "jobs:\n  r:\n    steps:\n      - uses: dtolnay/rust-toolchain@stable\n"},
            "a floating @stable ref is not a pin",
        )

    def test_version_mismatch(self):
        self.assertRejected(
            {"ci.yml": "jobs:\n  r:\n    steps:\n      - uses: dtolnay/rust-toolchain@1.98.0\n"},
            "ci installs a different version than the toml pins",
        )

    def test_missing_toolchain_file(self):
        self.assertRejected({"ci.yml": PINNED_STEP}, "rust-toolchain.toml absent", toml=None)

    def test_floating_channel(self):
        self.assertRejected(
            {"ci.yml": PINNED_STEP}, "channel is a moving target", toml='[toolchain]\nchannel = "stable"\n'
        )

    def test_no_install_step_at_all(self):
        self.assertRejected({"ci.yml": "jobs:\n  r:\n    steps:\n      - run: cargo build\n"},
                            "no toolchain install to verify")


class TestBypassesFound1998(GateCase):
    """Shapes that passed the #160 regex."""

    def test_named_step_hides_floating_install(self):
        """Asserts the REASON, not just the exit code.

        Mutation-tested: reverting USES_RE to require the leading dash (the #160 defect) still
        exits 1, because the fail-closed backstop catches the unclaimed mention. An exit-code-only
        assertion therefore could NOT tell correct parsing from falling back to the backstop, and
        would have passed on the very bug it exists to pin. The message must show the step was
        parsed and its ref judged floating.
        """
        out = self.assertRejected(
            {
                "ci.yml": PINNED_STEP
                + """  sneaky:
    steps:
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
"""
            },
            "a named step's floating install must not hide behind a pinned one",
        )
        self.assertIn("floating ref @stable", out)
        self.assertNotIn("cannot read", out)

    def test_toolchain_input_overrides_pinned_ref(self):
        out = self.assertRejected(
            {
                "ci.yml": f"""jobs:
  r:
    steps:
      - uses: dtolnay/rust-toolchain@{PIN}
        with:
          toolchain: stable
"""
            },
            "the with: input wins at runtime, so a pinned ref alone is not enough",
        )
        self.assertIn("toolchain: stable", out)

    def test_install_in_another_workflow(self):
        self.assertRejected(
            {"ci.yml": PINNED_STEP, "other.yml": "jobs:\n  n:\n    steps:\n      - uses: dtolnay/rust-toolchain@nightly\n"},
            "every workflow is scanned, not only ci.yml",
        )


class TestBypassesFound2040(GateCase):
    """Shapes that passed the #170 walk."""

    def test_comment_inside_step_must_not_hide_override(self):
        self.assertRejected(
            {
                "ci.yml": f"""jobs:
  r:
    steps:
      - uses: dtolnay/rust-toolchain@{PIN}
      # a comment at the dash column
        with:
          toolchain: nightly
"""
            },
            "one comment line must not end the step walk",
        )

    def test_quoted_uses_alongside_pinned_step(self):
        out = self.assertRejected(
            {
                "ci.yml": PINNED_STEP
                + """  sneaky:
    steps:
      - uses: "dtolnay/rust-toolchain@stable"
"""
            },
            "a quoted scalar must not make the step invisible",
        )
        # Again the reason, not just the code: without the optional quote in USES_RE this is
        # rejected by the backstop instead of being read as a floating ref.
        self.assertIn("floating ref @stable", out)
        self.assertNotIn("cannot read", out)

    def test_flow_mapping_input(self):
        self.assertRejected(
            {"ci.yml": f'jobs:\n  r:\n    steps:\n      - uses: dtolnay/rust-toolchain@{PIN}\n        with: {{ toolchain: stable }}\n'},
            "a flow-mapping with: must be read too",
        )

    def test_with_block_above_uses_key(self):
        self.assertRejected(
            {
                "ci.yml": f"""jobs:
  r:
    steps:
      - with:
          toolchain: nightly
        uses: dtolnay/rust-toolchain@{PIN}
"""
            },
            "an input written above uses: still applies",
        )


class TestOverAttribution(GateCase):
    """A neighbouring step's `toolchain:` belongs to IT. Both orders, because each direction of
    the walk broke separately (2040 forward, 2041 backward)."""

    OTHER = """      - name: Some other toolchain action
        uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: nightly
"""
    MINE = f"      - uses: dtolnay/rust-toolchain@{PIN}\n"

    def test_other_step_after_pinned(self):
        self.assertAccepted(
            {"ci.yml": "jobs:\n  r:\n    steps:\n" + self.MINE + self.OTHER},
            "the nightly belongs to the following step, not ours",
        )

    def test_other_step_before_pinned(self):
        self.assertAccepted(
            {"ci.yml": "jobs:\n  r:\n    steps:\n" + self.OTHER + self.MINE},
            "the nightly belongs to the preceding step, not ours",
        )


class TestFailClosed(GateCase):
    """An unreadable reference must be loud, never silently fine."""

    def test_multiline_uses_is_rejected_and_named(self):
        out = self.assertRejected(
            {
                "ci.yml": PINNED_STEP
                + """  weird:
    steps:
      - uses:
          dtolnay/rust-toolchain@nightly
"""
            },
            "a form the scan cannot claim must fail closed",
        )
        self.assertIn("cannot read", out)

    def test_unreadable_only_names_the_line_not_absence(self):
        """Ordering: the diagnostic must point at the line, not claim no step exists."""
        out = self.assertRejected(
            {"ci.yml": "jobs:\n  r:\n    steps:\n      - uses:\n          dtolnay/rust-toolchain@nightly\n"},
            "unreadable reference",
        )
        self.assertIn("cannot read", out)
        self.assertNotIn("no dtolnay/rust-toolchain step found", out)

    def test_trailing_comment_mention_is_inert(self):
        self.assertAccepted(
            {
                "ci.yml": PINNED_STEP
                + """      - uses: Swatinem/rust-cache@v2  # must follow dtolnay/rust-toolchain
"""
            },
            "a mention inside a trailing comment is not a reference",
        )


class TestHappyPath(GateCase):
    def test_pinned_single_step(self):
        out = self.assertAccepted({"ci.yml": PINNED_STEP}, "a correctly pinned repo")
        self.assertIn("pin OK", out)

    def test_quoted_pinned_ref_is_accepted(self):
        self.assertAccepted(
            {"ci.yml": f'jobs:\n  r:\n    steps:\n      - uses: "dtolnay/rust-toolchain@{PIN}"\n'},
            "quoting a correctly pinned ref is legal",
        )

    def test_matching_toolchain_input_is_allowed(self):
        self.assertAccepted(
            {"ci.yml": f"jobs:\n  r:\n    steps:\n      - uses: dtolnay/rust-toolchain@{PIN}\n        with:\n          toolchain: {PIN}\n"},
            "an input equal to the pin is not drift",
        )

    def test_enclave_pin_is_reported_but_not_enforced(self):
        out = self.assertAccepted(
            {"ci.yml": PINNED_STEP},
            "the enclave image pins its own measurement-bound compiler",
            extra={"deploy/enclave/Dockerfile": "FROM rust:1.88.0-bookworm AS rbuild\n"},
        )
        self.assertIn("1.88.0", out)
        self.assertIn("MRENCLAVE", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)

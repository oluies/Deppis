#!/usr/bin/env python3
"""Regression tests for check-scalapb-grpc-pin.py.

Kept, not thrown away. The toolchain-pin gate next door regressed three times because each round's
fixtures were built ad hoc and discarded, so round N+1 could not catch round N (roborev 1998, 2040,
2041). Every case below is a behaviour the gate claims; the FIRST one is the property that makes
this gate worth having at all — a Steward `grpcJava` bump must PASS, because a gate that reddened
every grpc bump would be pure cost.

`problems()` and `grpc_pins()` are pure, so none of this touches the network: the POM is a fixture
and the V.scala values are a dict. stdlib unittest only, matching the scripts under test.

Run: python3 scripts/test_check_scalapb_grpc_pin.py
"""

import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "chk", Path(__file__).resolve().parent / "check-scalapb-grpc-pin.py"
)
chk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(chk)


def pom(grpc: str | None = "1.62.2", *, stub: str | None = None, proto: str | None = None) -> str:
    """A minimal scalapb-runtime-grpc POM declaring the given io.grpc versions."""
    deps = []
    for artifact, v in (("grpc-stub", stub or grpc), ("grpc-protobuf", proto or grpc)):
        if v is not None:
            deps.append(
                f"<dependency><groupId>io.grpc</groupId>"
                f"<artifactId>{artifact}</artifactId><version>{v}</version></dependency>"
            )
    # A non-io.grpc dependency, so the groupId filter is actually exercised.
    deps.append(
        "<dependency><groupId>com.thesamet.scalapb</groupId>"
        "<artifactId>scalapb-runtime_3</artifactId><version>0.11.21</version></dependency>"
    )
    return (
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies>'
        + "".join(deps)
        + "</dependencies></project>"
    )


def vals(scalapb="0.11.21", baseline="1.62.2", grpc="1.85.1") -> dict[str, str]:
    out = {"scalapb": scalapb}
    if baseline is not None:
        out["grpcJavaBaseline"] = baseline
    if grpc is not None:
        out["grpcJava"] = grpc
    return out


class TestAcceptsIntendedState(unittest.TestCase):
    """The gate must stay quiet for the things that are supposed to happen."""

    def test_forward_eviction_passes(self):
        """THE point of this gate's design: grpcJava far ahead of the baseline is fine."""
        self.assertEqual(chk.problems(vals(grpc="1.85.1"), chk.grpc_pins(pom("1.62.2"))), [])

    def test_a_steward_grpc_bump_passes(self):
        """A Steward bump moves only grpcJava. It must NOT redden the build."""
        before = chk.problems(vals(grpc="1.85.1"), chk.grpc_pins(pom("1.62.2")))
        after = chk.problems(vals(grpc="1.86.0"), chk.grpc_pins(pom("1.62.2")))
        self.assertEqual((before, after), ([], []))

    def test_exact_equality_passes(self):
        """grpcJava == baseline is legal (that was the state at #31)."""
        self.assertEqual(chk.problems(vals(grpc="1.62.2"), chk.grpc_pins(pom("1.62.2"))), [])


class TestCatchesDrift(unittest.TestCase):
    def test_scalapb_moved_its_grpc_target(self):
        """The signal this gate exists for: a scalapb bump changes the declared grpc-java."""
        found = chk.problems(vals(baseline="1.62.2"), chk.grpc_pins(pom("1.70.0")))
        self.assertEqual(len(found), 1, found)
        self.assertIn("grpcJavaBaseline = 1.62.2", found[0])
        self.assertIn("declares grpc-java 1.70.0", found[0])
        self.assertIn("same", found[0].lower())  # "in the SAME commit"

    def test_grpcjava_below_baseline_is_a_downgrade(self):
        found = chk.problems(vals(baseline="1.62.2", grpc="1.60.0"), chk.grpc_pins(pom("1.62.2")))
        self.assertTrue(any("downgrade" in p for p in found), found)

    def test_both_problems_reported_together(self):
        """One run reports every reason, not just the first."""
        found = chk.problems(vals(baseline="1.50.0", grpc="1.55.0"), chk.grpc_pins(pom("1.62.2")))
        self.assertEqual(len(found), 2, found)


class TestCatchesMalformedInputs(unittest.TestCase):
    def test_missing_baseline(self):
        found = chk.problems(vals(baseline=None), chk.grpc_pins(pom("1.62.2")))
        self.assertTrue(any("grpcJavaBaseline not found" in p for p in found), found)

    def test_missing_grpcjava(self):
        found = chk.problems(vals(grpc=None), chk.grpc_pins(pom("1.62.2")))
        self.assertTrue(any("V.grpcJava not found" in p for p in found), found)

    def test_pom_declares_no_grpc(self):
        """A POM-shape change must be loud, not silently treated as agreement."""
        found = chk.problems(vals(), chk.grpc_pins(pom(None)))
        self.assertTrue(any("does not declare" in p for p in found), found)

    def test_pom_declares_a_mixed_set(self):
        found = chk.problems(vals(), chk.grpc_pins(pom(stub="1.62.2", proto="1.70.0")))
        self.assertTrue(any("MIXED" in p for p in found), found)

    def test_non_numeric_version_is_reported_not_crashed(self):
        found = chk.problems(vals(grpc="1.85.1-SNAPSHOT"), chk.grpc_pins(pom("1.62.2")))
        self.assertTrue(any("cannot compare" in p for p in found), found)


class TestHelpers(unittest.TestCase):
    def test_grpc_pins_filters_by_groupid(self):
        pins = chk.grpc_pins(pom("1.62.2"))
        self.assertEqual(pins, {"grpc-stub": "1.62.2", "grpc-protobuf": "1.62.2"})

    def test_version_ordering(self):
        pv = chk.parse_version
        self.assertLess(pv("1.62.2"), pv("1.85.1"))
        self.assertLess(pv("1.9.0"), pv("1.10.0"))  # not string ordering
        self.assertEqual(pv("1.62.2"), pv("1.62.2"))

    def test_scala_vals_reads_the_real_file(self):
        v = chk.scala_vals(Path("project/V.scala").read_text())
        for key in ("scalapb", "grpcJava", "grpcJavaBaseline"):
            self.assertIn(key, v)


if __name__ == "__main__":
    unittest.main(verbosity=2)

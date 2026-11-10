#!/usr/bin/env python3
"""Fail unless V.grpcJavaBaseline still equals the grpc-java that scalapb-runtime-grpc declares.

`transport` puts grpc-netty-shaded/grpc-inprocess at V.grpcJava on the same classpath as
scalapb-runtime-grpc at V.scalapb. That artifact was COMPILED against a specific grpc-java, and
the newer pin evicts forward over it. Nothing made the two agree: V.grpcJava started equal to the
declared version (#31 pinned 1.62.2) and Scala Steward then moved it independently several times,
because Steward tracks the `io.grpc` artifacts and knows nothing about what ScalaPB declares. The
comment in V.scala that described the relationship became false by that drift, twice.

WHAT THIS GATE DOES AND DELIBERATELY DOES NOT DO.

It does NOT require V.grpcJava == the declared version. The forward eviction is intended and works;
demanding equality would fail today and force a revert nobody wants. A gate that goes red on every
Steward grpc bump would also be pure cost — that trade is worth it for the BouncyCastle keys
(scripts/check-bc-bom.py, where a mixed set is genuinely unsupported) and is not worth it here.

Instead V.scala declares `grpcJavaBaseline` = the grpc-java that scalapb-runtime-grpc is built
against, and this check verifies that declaration against the published POM. So:

  * a Steward bump of `grpcJava`  -> PASSES. Moving further ahead is allowed and expected.
  * a Steward bump of `scalapb` that CHANGES its declared grpc-java -> RED. That is the moment a
    human must re-confirm the eviction is still safe and move the baseline in the same commit.
  * `grpcJava` dropping BELOW the baseline -> RED. That is not an eviction, it is a downgrade:
    scalapb-runtime-grpc would be running against an older grpc-java than it was compiled with.

What it cannot do, and no version check can: catch scalapb-runtime-grpc using a grpc-java API that
a later 1.x changed or that was @ExperimentalApi. That failure is a runtime NoSuchMethodError, and
only `transport`'s suite and the cross-process integration job exercise it. This gate narrows the
silent-drift window; it does not close the compatibility question.

Stdlib only, matching scripts/check-bc-bom.py — a hygiene gate that fails on a missing module
would be worse than the drift it checks for.

Usage: check-scalapb-grpc-pin.py [path/to/V.scala]   (default: project/V.scala)
"""

import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

DEFAULT_V_SCALA = Path("project/V.scala")
POM_URL = (
    "https://repo1.maven.org/maven2/com/thesamet/scalapb/scalapb-runtime-grpc_3/"
    "{v}/scalapb-runtime-grpc_3-{v}.pom"
)
# The io.grpc artifacts scalapb-runtime-grpc compiles against. Both must agree with each other;
# a split would mean ScalaPB itself is carrying a mixed set and the baseline is ill-defined.
GRPC_ARTIFACTS = ("grpc-stub", "grpc-protobuf")

VAL = re.compile(r'^\s*val\s+(\w+)\s*=\s*"([^"]+)"', re.MULTILINE)
VERSION = re.compile(r"^\d+(\.\d+)*$")


def scala_vals(text: str) -> dict[str, str]:
    """Every `val name = "string"` in V.scala."""
    return dict(VAL.findall(text))


def grpc_pins(pom_xml: str) -> dict[str, str]:
    """artifactId -> version for every io.grpc dependency the POM declares. Namespace-agnostic."""

    def local(el: ET.Element) -> str:
        return el.tag.rsplit("}", 1)[-1]

    def field(dep: ET.Element, name: str) -> str | None:
        return next((c.text.strip() for c in dep if local(c) == name and c.text), None)

    out = {}
    for dep in ET.fromstring(pom_xml).iter():
        if local(dep) != "dependency":
            continue
        if field(dep, "groupId") != "io.grpc":
            continue
        if (artifact := field(dep, "artifactId")) and (version := field(dep, "version")):
            out[artifact] = version
    return out


def parse_version(v: str) -> tuple[int, ...]:
    """Dotted-integer version as a comparable tuple. Raises ValueError on anything else."""
    if not VERSION.match(v):
        raise ValueError(f"not a dotted-integer version: {v!r}")
    return tuple(int(part) for part in v.split("."))


def problems(vals: dict[str, str], pins: dict[str, str]) -> list[str]:
    """Every reason to fail, so one run reports them all rather than the first."""
    found: list[str] = []

    baseline = vals.get("grpcJavaBaseline")
    current = vals.get("grpcJava")
    if not baseline:
        found.append(
            "V.grpcJavaBaseline not found in V.scala; it must declare the grpc-java that "
            "scalapb-runtime-grpc is built against, so this check has something to verify"
        )
    if not current:
        found.append("V.grpcJava not found in V.scala")

    declared = {a: pins.get(a) for a in GRPC_ARTIFACTS}
    missing = [a for a, v in declared.items() if not v]
    if missing:
        found.append(
            f"scalapb-runtime-grpc does not declare {', '.join(missing)} — its POM shape changed, "
            "so the baseline cannot be derived; inspect the POM and update this check"
        )
        return found
    if len(set(declared.values())) != 1:
        found.append(
            "scalapb-runtime-grpc declares a MIXED grpc-java set ("
            + ", ".join(f"{a}={v}" for a, v in declared.items())
            + "); the baseline is ill-defined until that is understood"
        )
        return found

    actual = next(iter(declared.values()))
    if not baseline or not current:
        return found

    if baseline != actual:
        found.append(
            f"V.grpcJavaBaseline = {baseline}, but scalapb-runtime-grpc {vals.get('scalapb')} "
            f"declares grpc-java {actual}. ScalaPB moved its target: re-confirm that running "
            f"grpc-java {current} over it is still safe (run transport's suite and the "
            f"cross-process integration job), then set grpcJavaBaseline = {actual} in the SAME "
            "commit as the scalapb bump"
        )

    try:
        if parse_version(current) < parse_version(actual):
            found.append(
                f"V.grpcJava = {current} is BELOW the {actual} that scalapb-runtime-grpc is built "
                "against. That is a downgrade, not a forward eviction: scalapb-runtime-grpc would "
                "run against an older grpc-java than it was compiled with"
            )
    except ValueError as e:
        found.append(f"cannot compare grpc-java versions: {e}")

    return found


def fetch(url: str, attempts: int = 5) -> str:
    """GET with retries on transient failures. A 4xx is final: that scalapb version does not exist."""
    for n in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                return r.read().decode()
        except urllib.error.HTTPError as e:
            if e.code < 500 or n == attempts:
                raise
        except OSError:  # URLError, timeouts, resets: worth another try
            if n == attempts:
                raise
        time.sleep(5 * n)
    raise AssertionError("unreachable: the last attempt either returns or raises")


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_V_SCALA
    vals = scala_vals(path.read_text())
    scalapb = vals.get("scalapb")
    if not scalapb:
        print(f"::error::V.scalapb not found in {path}; cannot tell which POM to read")
        return 1
    try:
        pins = grpc_pins(fetch(POM_URL.format(v=scalapb)))
    except urllib.error.HTTPError as e:
        print(
            f"::error::scalapb-runtime-grpc_3 {scalapb} could not be fetched (HTTP {e.code}) — "
            "does that version exist?"
        )
        return 1
    found = problems(vals, pins)
    for p in found:
        print(f"::error::{p}")
    if not found:
        print(
            f"scalapb/grpc-java pin OK: scalapb-runtime-grpc {scalapb} is built against grpc-java "
            f"{vals['grpcJavaBaseline']} (V.grpcJavaBaseline agrees); V.grpcJava = "
            f"{vals['grpcJava']} evicts forward over it"
        )
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""Fail unless project/V.scala's four BouncyCastle versions equal what BouncyCastle's own BOM pins.

V.scala keeps one version key per BouncyCastle artifact, because BouncyCastle versions them
independently (see the comment there). Separate keys can drift into a combination no BouncyCastle
BOM sanctions — Scala Steward bumping bcprov alone, say — and CI's TLS tests only catch drift that
breaks at runtime. This check makes the rule mechanical: V.bcBom names the
org.bouncycastle:bc-jdk18on-bom version the four keys claim to match, and any disagreement fails.

When it fires on a Steward PR, that is the point, not a nuisance: find the BOM that sanctions the
proposed set, then set V.bcBom and all four keys to match it in that same PR.

Usage: check-bc-bom.py [path/to/V.scala]   (default: project/V.scala)
"""

import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

DEFAULT_V_SCALA = Path("project/V.scala")
BOM_URL = "https://repo1.maven.org/maven2/org/bouncycastle/bc-jdk18on-bom/{v}/bc-jdk18on-bom-{v}.pom"

# V.scala key -> the Maven artifactId the BOM pins for it.
ARTIFACTS = {
    "bcprov": "bcprov-jdk18on",
    "bcpkix": "bcpkix-jdk18on",
    "bctls": "bctls-jdk18on",
    "bcutil": "bcutil-jdk18on",
}

VAL = re.compile(r'^\s*val\s+(\w+)\s*=\s*"([^"]+)"', re.MULTILINE)


def scala_vals(text: str) -> dict[str, str]:
    """Every `val name = "string"` in V.scala."""
    return dict(VAL.findall(text))


def bom_pins(pom_xml: str) -> dict[str, str]:
    """artifactId -> version for every dependency the BOM pins. Namespace-agnostic."""

    def local(el: ET.Element) -> str:
        return el.tag.rsplit("}", 1)[-1]

    def field(dep: ET.Element, name: str) -> str | None:
        return next((c.text.strip() for c in dep if local(c) == name and c.text), None)

    return {
        artifact: version
        for dep in ET.fromstring(pom_xml).iter()
        if local(dep) == "dependency"
        if (artifact := field(dep, "artifactId")) and (version := field(dep, "version"))
    }


def problems(ours: dict[str, str], pins: dict[str, str]) -> list[str]:
    """One message per key whose V.scala value is missing, unpinned, or disagrees with the BOM."""

    def check(key: str, artifact: str) -> str | None:
        match ours.get(key), pins.get(artifact):
            case None, _:
                return f"V.{key} not found in V.scala"
            case _, None:
                return f"{artifact} is not pinned by the BOM"
            case mine, bom if mine == bom:
                return None
            case mine, bom:
                return f"V.{key} = {mine}, but the BOM pins {artifact} at {bom}"

    return [p for key, artifact in ARTIFACTS.items() if (p := check(key, artifact))]


def fetch(url: str, attempts: int = 5) -> str:
    """GET with retries on transient failures. A 4xx is final: the BOM version does not exist."""
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
    bom = vals.get("bcBom")
    if not bom:
        print(f"::error::V.bcBom not found in {path}; cannot tell which BOM the keys claim to match")
        return 1
    try:
        pins = bom_pins(fetch(BOM_URL.format(v=bom)))
    except urllib.error.HTTPError as e:
        print(f"::error::bc-jdk18on-bom {bom} could not be fetched (HTTP {e.code}) — does it exist?")
        return 1
    found = problems(vals, pins)
    for p in found:
        print(f"::error::{p} (bc-jdk18on-bom {bom})")
    if not found:
        pinned = ", ".join(f"{k}={vals[k]}" for k in ARTIFACTS)
        print(f"BouncyCastle versions match bc-jdk18on-bom {bom}: {pinned}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

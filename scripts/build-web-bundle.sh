#!/usr/bin/env bash
# Build the real Scala.js protocol-core engine into a minified browser bundle for the Flutter web
# client (clients/flutter/web/protocol-engine.js). See clients/flutter/README.md.
#
# The bundle is a GENERATED artifact (not checked in). web/index.html already loads it; if it is
# absent the app degrades to the labeled DevEngine, so this is a deployment build step, not a test.
#
# Usage: scripts/build-web-bundle.sh
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="clients/flutter/web/protocol-engine.js"

echo "==> 1/2 linking the Scala.js engine (fullLinkJS) …"
sbt -batch -no-colors "protocolCoreJS/fullLinkJS" >/dev/null

# sbt 2.0 centralizes build outputs under target/out/<platform>/scala-<version>/… (this script used
# to point at the sbt 1.x `protocol-core-js/target/…` layout, which had silently stopped resolving).
# The Scala version is part of the path, so resolve it by glob — a `scalaVersion` bump must not need
# a matching edit here. Insist on exactly one match so an ambiguous tree fails loudly.
shopt -s nullglob
BUNDLES=(target/out/sjs1/scala-*/protocol-core-js/protocol-core-js-opt/main.js)
if [ ${#BUNDLES[@]} -ne 1 ]; then
  echo "expected exactly 1 link output, found ${#BUNDLES[@]}: ${BUNDLES[*]:-<none>}" >&2
  if [ ${#BUNDLES[@]} -eq 0 ]; then
    echo "(the link step produced nothing under target/out/sjs1/ — check that fullLinkJS above" >&2
    echo "   actually succeeded, and that you are running from the repo root)" >&2
  else
    # NOT `sbt clean`: verified that it removes only the CURRENT scalaVersion's output and leaves a
    # tree from a previous one in place, so it cannot resolve this ambiguity. Delete the stale dir.
    echo "(a leftover tree from an older scalaVersion — 'sbt clean' will NOT remove it:" >&2
    echo "   rm -rf target/out/sjs1/scala-<old-version>)" >&2
  fi
  exit 1
fi
OPT="${BUNDLES[0]}"
echo "    link output: $OPT"

echo "==> 2/2 bundling + minifying for the browser (pinned esbuild) …"
ESB="node_modules/.bin/esbuild"
[ -x "$ESB" ] || { echo "    installing pinned esbuild (package.json devDependencies) …"; npm install >/dev/null; }
"$ESB" "$OPT" \
  --bundle --minify --global-name=__mm --format=iife \
  --outfile="$OUT"

raw=$(wc -c < "$OUT")
gz=$(gzip -c "$OUT" | wc -c)
# brotli is what a CDN actually serves, and the README quotes it — report it here so those figures
# stay reproducible from this script alone. Optional: not every machine has the binary.
if command -v brotli >/dev/null 2>&1; then
  br=", $(brotli -c "$OUT" | wc -c | tr -d ' ') bytes brotli"
else
  br=""
fi
echo "==> built $OUT  (${raw} bytes raw, ${gz} bytes gzip${br})"
echo "    add the script tags to web/index.html if not present, then: (cd clients/flutter && flutter build web)"

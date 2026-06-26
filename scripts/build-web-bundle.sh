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

OPT="protocol-core-js/target/scala-3.3.4/protocol-core-js-opt/main.js"
OUT="clients/flutter/web/protocol-engine.js"

echo "==> 1/2 linking the Scala.js engine (fullLinkJS) …"
sbt -batch -no-colors "protocolCoreJS/fullLinkJS" >/dev/null
[ -f "$OPT" ] || { echo "link output not found: $OPT" >&2; exit 1; }

echo "==> 2/2 bundling + minifying for the browser (pinned esbuild) …"
ESB="node_modules/.bin/esbuild"
[ -x "$ESB" ] || { echo "    installing pinned esbuild (package.json devDependencies) …"; npm install >/dev/null; }
"$ESB" "$OPT" \
  --bundle --minify --global-name=__mm --format=iife \
  --outfile="$OUT"

raw=$(wc -c < "$OUT")
gz=$(gzip -c "$OUT" | wc -c)
echo "==> built $OUT  (${raw} bytes raw, ${gz} bytes gzip)"
echo "    add the script tags to web/index.html if not present, then: (cd clients/flutter && flutter build web)"

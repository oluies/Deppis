#!/usr/bin/env bash
# Build a SELF-CONTAINED engine bundle for non-browser JS engines (Apple JavaScriptCore via
# `flutter_js` on iOS) — the native counterpart to the web bundle (T019 → native iOS, Gate 4).
#
# The Scala.js link emits a CommonJS module that `require`s @noble/hashes; a browser bundler resolves
# those bare specifiers on web. JavaScriptCore has no module loader, so here esbuild inlines everything
# into one IIFE that assigns `globalThis.ProtocolEngine` (the same `@JSExportTopLevel` class the web
# path binds). The result is loaded once into the JS runtime and driven through the engine-api JSON
# boundary exactly like the web `ScalaJsEngine`.
#
# The host runtime MUST provide `globalThis.crypto.getRandomValues` backed by a real OS CSPRNG (noble's
# entropy source). The Flutter iOS engine factory injects that from Dart's `Random.secure()`; this
# script's companion test (`e2e/engine-jsc.cjs`) injects Node webcrypto to prove the bundle is
# otherwise self-contained.
set -euo pipefail
cd "$(dirname "$0")/.."

export JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home -v 26 2>/dev/null || true)}"
echo "[bundle] linking Scala.js (fullLinkJS) ..."
sbt -batch protocolCoreJS/fullLinkJS >/dev/null
MAIN="$(find target -path '*protocol-core-js/protocol-core-js-opt/main.js' | head -1)"
[ -n "$MAIN" ] || { echo "[bundle] linked main.js not found" >&2; exit 1; }

OUT=protocol-core-js/dist
mkdir -p "$OUT"
# Entry wrapper: lift the Scala.js CJS export onto globalThis (what the host references after eval).
cat > "$OUT/.entry.js" <<EOF
const m = require("$(cd "$(dirname "$MAIN")" && pwd)/$(basename "$MAIN")");
globalThis.ProtocolEngine = m.ProtocolEngine;
EOF
echo "[bundle] bundling self-contained IIFE (esbuild) ..."
npx --no-install esbuild "$OUT/.entry.js" --bundle --format=iife --platform=browser \
  --legal-comments=none --outfile="$OUT/engine.bundle.js"
rm -f "$OUT/.entry.js"
echo "[bundle] wrote $OUT/engine.bundle.js ($(wc -c < "$OUT/engine.bundle.js") bytes)"
echo "[bundle] verifying it runs standalone ..."
node protocol-core-js/e2e/engine-jsc.cjs "$OUT/engine.bundle.js"

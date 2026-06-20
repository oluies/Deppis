# Metadata Messenger — Flutter client

Presentation layer for the metadata-private messenger. The UI holds **display
state only**; all cryptography and protocol state live in the engine
(`protocol-core`), reached through the narrow, versioned bridge in
`lib/engine/protocol_engine.dart` (see `specs/.../contracts/engine-api.md`,
Constitution VII).

## Status

- **`ProtocolEngine`** — the bridge interface (commands + events) the UI talks to.
- **`ScalaJsEngine`** — adapter over the **real** Scala.js `protocol-core` engine
  (T019), driving it through the versioned JSON boundary (`engine-api.md`). The
  engine `handle` is injected, so the adapter is fully unit-tested with a fake
  handle; on web the handle is the linked bundle's `ProtocolEngine.handle`.
- **`DevEngine`** — an in-memory, UI-development stand-in. It performs **no
  cryptography** and re-derives **no** protocol logic (Constitution VII). It
  always reports `metadataPrivate == false` and the UI shows
  **`DEV, NO METADATA PRIVACY`** prominently (FR-016, Constitution IV).
- **`createEngine()`** (`engine_factory.dart`) picks at compile time: the
  Scala.js engine on web (when its bundle is loaded), the `DevEngine` everywhere
  else and in `flutter test`.

## Wiring the real engine for web

The Scala.js bundle uses ES/CommonJS modules and imports the vetted
`@noble/hashes`, so a browser build needs a bundler to expose the
`ProtocolEngine` class as a global. Once `globalThis.ProtocolEngine` exists,
`createEngine()` uses it automatically; otherwise it falls back to `DevEngine`.

```sh
# 1. link the engine bundle
sbt 'protocolCoreJS/fullLinkJS'
# 2. bundle it for the browser, exposing ProtocolEngine on the global scope, e.g.:
npx esbuild protocol-core-js/target/scala-3.3.4/protocol-core-js-opt/main.js \
  --bundle --global-name=__mm --format=iife \
  --outfile=clients/flutter/web/protocol-engine.js
#    then in web/index.html, before main.dart.js:
#    <script src="protocol-engine.js"></script>
#    <script>window.ProtocolEngine = __mm.ProtocolEngine;</script>
```

(The bundling is a deployment build step — not part of `flutter test`/CI, which
exercise the adapter via the fake handle and the engine via the Node e2e.)

## Screens

- **Home** — privacy banner + multi-conversation buddy list (T036).
- **Add buddy** — shared-secret handshake → safety-number comparison →
  confirm/reject (T026).
- **Conversation** — decrypted history + send (T032 engine command wiring).

## Develop

```sh
flutter pub get
flutter analyze    # CI gate (T005)
flutter test       # widget + engine-bridge tests
flutter run -d chrome
```

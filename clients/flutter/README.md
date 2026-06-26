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
# 1. link the engine bundle (Scala.js full optimization)
sbt 'protocolCoreJS/fullLinkJS'
# 2. bundle + MINIFY it for the browser, exposing ProtocolEngine on the global scope:
npx esbuild protocol-core-js/target/scala-3.3.4/protocol-core-js-opt/main.js \
  --bundle --minify --global-name=__mm --format=iife \
  --outfile=clients/flutter/web/protocol-engine.js
```

`web/index.html` already loads it (synchronously, before `flutter_bootstrap.js`):
```html
<script src="protocol-engine.js"></script>
<script>window.ProtocolEngine = __mm.ProtocolEngine;</script>
```
If the bundle is absent (e.g. a fresh checkout, or CI's bundle-less build), the
script 404s, `globalThis.ProtocolEngine` is undefined, and `createEngine()`
degrades gracefully to the labeled `DevEngine` — so committing the script tags is
safe even though the generated bundle is not checked in.

**Size.** The engine is a full E2E crypto stack (Scala.js runtime + the ratchet +
the vetted `@noble` primitives), so expect a few hundred KB raw — but the
over-the-wire size is what matters and it compresses well. With `--minify`:
~370 KB raw → **~100 KB gzip / ~80 KB brotli**. Serve compressed (any CDN/nginx
does this); don't optimize against the raw number. (Without `--minify` it is
~646 KB raw / ~118 KB gzip — minify is a free ~43% raw / ~15% gzip win.)

(The bundling is a deployment build step — not part of `flutter test`/CI, which
exercise the adapter via the fake handle and the engine via the Node e2e.)

### Enabling real delivery (notify-before-retrieval) on web

By default `new ProtocolEngine()` is **local-only** (no delivery). To make the
"mail waiting" indicator (FR-004) and incoming messages fire on web, construct it
with a host **transport** + this client's notify label:
`new ProtocolEngine(transport, label)`.

The engine calls the transport **synchronously** during `tick`, but browser
network I/O (gRPC-web / connect-web) is async — so the host uses a *staging*
model per round:

1. (async) fetch this round's notify digest + any retrievable frames → buffer them;
2. call `engine.tick(roundId)` — the transport reads the buffer synchronously:
   `mailWaiting`/`retrieve` return staged answers; `submit` records frames to send;
3. (async) flush the buffered `submit`s to the server.

The `JsTransport` shape (`submit(token, frame) -> bool`, `mailWaiting(round, label)
-> bool`, `retrieve(token) -> Uint8Array|null`) is proven by `JsRoundTransportSpec`
under Node. The actual gRPC-web client + Envoy/connect proxy that backs it against
a running server is the remaining deployment piece (T032c).

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

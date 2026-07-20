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

Use the script — it does both steps, resolves the link output safely, and reports the size:

```sh
scripts/build-web-bundle.sh
```

Equivalent by hand, if you want the steps (pinned esbuild from package.json — run
`npm install` once):

```sh
# 1. link the engine bundle (Scala.js full optimization)
sbt 'protocolCoreJS/fullLinkJS'
# 2. bundle + MINIFY it for the browser. sbt 2.0 puts link output under
#    target/out/sjs1/scala-<version>/…, so let the shell resolve the version rather than typing it —
#    it changes whenever build.sbt's scalaVersion does.
npx esbuild target/out/sjs1/scala-*/protocol-core-js/protocol-core-js-opt/main.js \
  --bundle --minify --global-name=__mm --format=iife \
  --outfile=clients/flutter/web/protocol-engine.js
```

Unlike the script, that glob is **unguarded**: it assumes a clean tree. If a previous
`scalaVersion` left a second `target/out/sjs1/scala-*` directory behind, esbuild gets two entry
points and one `--outfile` and fails on *that* instead of on the real cause — delete the stale
directory (`rm -rf target/out/sjs1/scala-<old-version>`; `sbt clean` will not, it only touches the
current version's output).

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
the vetted `@noble` primitives, now including the post-quantum ones), so expect
well over half a MB raw — but the over-the-wire size is what matters and it
compresses well. Measured on Scala 3.3.8 — `build-web-bundle.sh` reports raw,
gzip and brotli, so these stay reproducible without extra tooling:

| | raw | gzip | brotli |
|---|---|---|---|
| `--minify` | 580 KB | **164 KB** | **130 KB** |
| without | 1.62 MB | 250 KB | 179 KB |

Minify is a free ~65% raw / ~34% gzip win. Serve compressed (any CDN/nginx does
this); don't optimize against the raw number.

> These figures replace an earlier set (~370 KB raw / ~100 KB gzip) that was
> ~60% low. They predated the post-quantum additions, and `build-web-bundle.sh`
> had been unable to resolve its input since the sbt 2.0 layout change, so
> nothing re-measured them. Re-measure when the crypto surface changes.

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

## Native (iOS / Android) — running the REAL engine via `flutter_js`

On web the real engine is the Scala.js bundle reached through browser JS interop
(`engine_factory_web.dart`). On **native** platforms there is no browser JS
runtime, so today `engine_factory_io.dart` falls back to the labeled `DevEngine`
stub. The intended path to the real engine on native is **`flutter_js`**: load
the **same** `web/protocol-engine.js` bundle into the embedded JS engine
(JavaScriptCore on iOS, QuickJS on Android) and back `ScalaJsEngine` with a
synchronous `runtime.evaluate('ProtocolEngine…')` handle. No native crypto, no
second engine — the vetted `@noble` crypto runs inside the JS runtime.

**The one crux — RNG polyfill (validated).** The engine's randomness is
`@JSGlobal("crypto")` → `crypto.getRandomValues` (`random.Rand`). JavaScriptCore
has **no `crypto` global**, so `new ProtocolEngine()` throws
`ReferenceError: crypto is not defined` at construction (it mints a per-session
cover key). The fix is a **one-function polyfill** injected before loading the
bundle, backed by Dart's secure random across the bridge:

```js
globalThis.crypto = { getRandomValues: (a) => { /* fill a from a Dart-bridged CSPRNG */ return a; } };
```

This is now a **committed, runnable proof**: `protocol-core-js/build-jsc-bundle.sh`
links the engine and esbuild-bundles it into a self-contained
`globalThis.ProtocolEngine` (the JavaScriptCore-loadable form — the web bundle
exposes an internal `__mm` global instead), then runs
`protocol-core-js/e2e/engine-jsc.cjs`, which loads it in a **bare** JS context
(no Node, no browser — only the injected `crypto.getRandomValues`) and asserts
both halves: **without** `crypto`, `new ProtocolEngine()` throws at construction
(the polyfill is required); **with only** `getRandomValues`, the full
privacy-status + add-buddy (X25519 keygen + KDF) flow runs. Everything else (the
ratchet, the JSON boundary, `@noble`) runs unmodified.

**This is now wired and built (iOS).** `engine_factory_io.dart` loads
`assets/protocol-engine.bundle.js` into a `flutter_js` runtime, injects
`crypto.getRandomValues` from a `Random.secure()`-seeded pool, and constructs the
same `ScalaJsEngine` the web client uses. `createEngine()` is `async` (native
loads the bundle from an asset); on any failure — or on the Dart VM under
`flutter test` — it falls back to the labeled `DevEngine`. Verified on the iOS
simulator: the app logs `Native ScalaJsEngine initialized (flutter_js) — real
protocol-core engine.` (i.e. the real engine, not the stub). `flutter analyze` +
`flutter test` (30) stay green; `flutter build ios --simulator` succeeds.

**RNG (OS entropy, on-demand refill).** `getRandomValues` is served from an
8 KB seed pool of OS entropy (`Random.secure()`) that **tops up synchronously**:
when it runs low, `assets/rng-pool.js` calls a flutter_js `sendMessage` channel
whose Dart handler returns fresh `Random.secure()` bytes — and on JavaScriptCore
`sendMessage` returns the (non-Future) handler result synchronously
(`jscore_runtime._sendMessage`), which fits `getRandomValues`'s synchronous
contract. So the pool is effectively **unbounded**; every byte is OS CSPRNG (no
PRNG anywhere). `ENTROPY_POOL_EXHAUSTED` (surfaced as the `ENTROPY_EXHAUSTED`
engine error) now only fires if the channel itself fails to deliver — e.g. a
runtime without a synchronous bridge. Validated on the iOS simulator by seeding a
4-byte pool: `new ProtocolEngine()` still constructs, which is only possible if
the refill bridge delivered entropy synchronously during construction.

**Prerequisites.** Building native needs a **full Xcode** + **CocoaPods** + the
iOS platform/simulator (`xcodebuild -downloadPlatform iOS`), plus
`flutter create --platforms=ios .`. Build the asset first with
`protocol-core-js/build-jsc-bundle.sh`. `flutter_js` is a native plugin, so it is
imported ONLY by `engine_factory_io.dart` (web + `flutter test` never load it).
Android is the same shape (QuickJS) but its `ios/`-equivalent scaffold + SDK are
not set up here.

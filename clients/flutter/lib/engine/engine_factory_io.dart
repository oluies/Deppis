import 'dart:convert';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_js/flutter_js.dart';

import 'dev_engine.dart';
import 'protocol_engine.dart';
import 'scalajs_engine.dart';

/// Native platforms (iOS/Android): run the REAL Scala.js `protocol-core` engine inside an embedded JS
/// runtime via `flutter_js` (JavaScriptCore on iOS, QuickJS on Android) — the same engine the web
/// client runs, just hosted without a browser. No native crypto and no second engine: the vetted
/// `@noble` primitives run unchanged inside the JS runtime.
///
/// Two things the host must provide that a bare JS engine lacks:
///   1. The bundle (`assets/protocol-engine.bundle.js`, built by `protocol-core-js/build-jsc-bundle.sh`)
///      assigns `globalThis.ProtocolEngine`; we `new` it once and bridge `handle(json)`.
///   2. `crypto.getRandomValues` — the engine's only entropy source (`@noble`). JavaScriptCore has no
///      `crypto` global, so we inject one backed by **`Random.secure()`** (the OS CSPRNG). See the RNG
///      note on [_installSecureRandom].
///
/// On ANY failure (asset missing, runtime unavailable on the Dart VM under `flutter test`, malformed
/// bundle) this degrades to the clearly-labeled [DevEngine] — the engine never silently runs without
/// its real backing, and the reason is logged.
Future<ProtocolEngine> createPlatformEngine() async {
  try {
    final bundle = await rootBundle.loadString(
      'assets/protocol-engine.bundle.js',
    );
    final rt = getJavascriptRuntime();
    await _installSecureRandom(
      rt,
    ); // BEFORE the bundle: construction needs crypto.getRandomValues
    rt.evaluate(bundle); // defines globalThis.ProtocolEngine
    rt.evaluate('globalThis.__engine = new ProtocolEngine();');
    // The engine-api boundary: a synchronous String(request)->String(response) call, exactly the
    // contract ScalaJsEngine speaks. `evaluate` is synchronous in flutter_js.
    String handle(String request) {
      final res = rt.evaluate('__engine.handle(${jsonEncode(request)})');
      if (res.isError) {
        // A JS RUNTIME fault (e.g. the entropy pool exhausting, or any internal engine fault) — NOT an
        // engine-api error envelope. Surface it AS that envelope so ScalaJsEngine handles it like any
        // engine error (typed EngineException + EngineError event) instead of choking on jsonDecode of
        // raw JS error text. The code is content-independent (Constitution II); the UI never renders it.
        final code = res.stringResult.contains('ENTROPY_POOL_EXHAUSTED')
            ? 'ENTROPY_EXHAUSTED'
            : 'ENGINE_RUNTIME';
        return jsonEncode({
          'error': {'code': code, 'message': code},
        });
      }
      return res.stringResult;
    }

    debugPrint(
      'Native ScalaJsEngine initialized (flutter_js) — real protocol-core engine.',
    );
    return ScalaJsEngine(handle);
  } catch (e) {
    debugPrint(
      'Native ScalaJsEngine init failed ($e); using DevEngine (no metadata privacy).',
    );
    return DevEngine();
  }
}

/// Inject `crypto.getRandomValues` backed by the OS CSPRNG, with **on-demand refill**.
///
/// Every byte comes from [Random.secure] (the platform CSPRNG — `SecRandomCopyBytes` on iOS) — there
/// is no PRNG anywhere (Constitution I/II). A small seed pool covers the first construction without a
/// round-trip; thereafter `getRandomValues` tops the pool up **synchronously** through a flutter_js
/// `sendMessage` channel: on JavaScriptCore, `sendMessage` returns the Dart handler's (non-Future)
/// String result synchronously (`jscore_runtime._sendMessage`), so the bridge fits `getRandomValues`'s
/// synchronous contract. The pool is therefore effectively unbounded — no `ENTROPY_POOL_EXHAUSTED` in
/// normal operation (that error only fires if the channel ever fails to deliver, e.g. on a runtime
/// without a synchronous bridge).
///
/// The decoder + serve/refill/exhaust logic live in `assets/rng-pool.js` (single source of truth,
/// tested by `protocol-core-js/e2e/rng-pool.cjs`); here we generate the OS bytes and register the
/// channel that delivers more.
Future<void> _installSecureRandom(JavascriptRuntime rt) async {
  final rng = Random.secure();
  Uint8List osBytes(int n) {
    final b = Uint8List(n);
    for (var i = 0; i < n; i++) {
      b[i] = rng.nextInt(256);
    }
    return b;
  }

  // The synchronous refill channel: JS `sendMessage('deppisEntropy', JSON.stringify(n))` -> this
  // handler -> base64 of n fresh OS-CSPRNG bytes, returned synchronously to JS (JSC).
  rt.onMessage('deppisEntropy', (dynamic args) {
    final n = (args is num) ? args.toInt() : int.parse(args.toString());
    return base64Encode(osBytes(n.clamp(1, 1 << 20)));
  });

  const seedBytes =
      8 * 1024; // covers the first construction before any refill round-trip
  final installer = await rootBundle.loadString('assets/rng-pool.js');
  rt.evaluate(installer); // defines globalThis.__installSecureRandomPool
  rt.evaluate(
    '__installSecureRandomPool(${jsonEncode(base64Encode(osBytes(seedBytes)))}, '
    'function (n) { return sendMessage("deppisEntropy", JSON.stringify(n)); });',
  );
}

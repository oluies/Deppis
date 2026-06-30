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
    final bundle = await rootBundle.loadString('assets/protocol-engine.bundle.js');
    final rt = getJavascriptRuntime();
    _installSecureRandom(rt);
    rt.evaluate(bundle); // defines globalThis.ProtocolEngine
    rt.evaluate('globalThis.__engine = new ProtocolEngine();');
    // The engine-api boundary: a synchronous String(request)->String(response) call, exactly the
    // contract ScalaJsEngine speaks. `evaluate` is synchronous in flutter_js.
    String handle(String request) {
      final res = rt.evaluate('__engine.handle(${jsonEncode(request)})');
      return res.stringResult;
    }

    debugPrint('Native ScalaJsEngine initialized (flutter_js) — real protocol-core engine.');
    return ScalaJsEngine(handle);
  } catch (e) {
    debugPrint('Native ScalaJsEngine init failed ($e); using DevEngine (no metadata privacy).');
    return DevEngine();
  }
}

/// Inject `crypto.getRandomValues` backed by the OS CSPRNG.
///
/// RNG approach (and its honest bound): JavaScriptCore exposes no synchronous path back to Dart, so
/// rather than a (possibly async) per-call bridge we **pre-seed a pool** of bytes from
/// [Random.secure] (the platform CSPRNG — `SecRandomCopyBytes` on iOS) and serve `getRandomValues`
/// from it. Every byte is OS entropy (no weakened/seeded PRNG — Constitution I/II); the only limit is
/// the pool *size* — exhausting it throws rather than returning low-quality bytes. The pool is sized
/// for a long session; a production build would refill it from a synchronous native bridge.
void _installSecureRandom(JavascriptRuntime rt) {
  const poolBytes = 256 * 1024; // ~thousands of keygens/nonces per session
  final rng = Random.secure();
  final pool = Uint8List(poolBytes);
  for (var i = 0; i < poolBytes; i++) {
    pool[i] = rng.nextInt(256);
  }
  // Pass the pool as base64 + a tiny pure-JS decoder (atob is absent in JSC/QuickJS).
  final b64 = base64Encode(pool);
  rt.evaluate('''
(function () {
  var B64 = "$b64";
  var T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var lut = {}; for (var i = 0; i < T.length; i++) lut[T.charAt(i)] = i;
  var clean = B64.replace(/=+\$/, "");
  var pool = new Uint8Array((clean.length * 6) >> 3);
  var acc = 0, bits = 0, o = 0;
  for (var j = 0; j < clean.length; j++) {
    acc = (acc << 6) | lut[clean.charAt(j)]; bits += 6;
    if (bits >= 8) { bits -= 8; pool[o++] = (acc >> bits) & 0xff; }
  }
  var off = 0;
  globalThis.crypto = {
    getRandomValues: function (arr) {
      var n = arr.length;
      if (off + n > pool.length) throw new Error("entropy pool exhausted");
      for (var k = 0; k < n; k++) arr[k] = pool[off + k];
      off += n;
      return arr;
    }
  };
})();
''');
}

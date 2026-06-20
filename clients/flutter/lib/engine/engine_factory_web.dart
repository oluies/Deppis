import 'dart:js_interop';
import 'dart:js_interop_unsafe';

import 'package:flutter/foundation.dart';

import 'dev_engine.dart';
import 'protocol_engine.dart';
import 'scalajs_engine.dart';

/// JS interop binding to the linked Scala.js bundle's `@JSExportTopLevel("ProtocolEngine")` class.
/// `new ProtocolEngine()` constructs one engine instance; `handle(json)` is the versioned JSON
/// boundary (engine-api.md). No key material crosses this boundary.
@JS('ProtocolEngine')
extension type _JsProtocolEngine._(JSObject _) implements JSObject {
  external _JsProtocolEngine();
  external String handle(String input);
}

/// On web, use the real Scala.js engine if the bundle is loaded (the `web/index.html` script tag),
/// otherwise fall back to the labeled [DevEngine] so the app still runs in a bundle-less build.
///
/// Construction is guarded: an incompatible or malformed bundle (which would throw on the first
/// `handle` call in the [ScalaJsEngine] constructor) degrades to the clearly-labeled [DevEngine]
/// rather than crashing the app at startup — the bundle-presence check alone is not enough.
ProtocolEngine createPlatformEngine() {
  if (!globalContext.has('ProtocolEngine')) {
    debugPrint('ProtocolEngine bundle not loaded; using DevEngine (no metadata privacy).');
    return DevEngine();
  }
  try {
    final js = _JsProtocolEngine();
    return ScalaJsEngine((input) => js.handle(input));
  } catch (e) {
    // Make the silent fallback observable: an incompatible/malformed bundle drops us to the
    // labeled DevEngine, and the REASON is logged so the field can tell which engine is running.
    debugPrint('ScalaJsEngine construction failed ($e); falling back to DevEngine (no metadata privacy).');
    return DevEngine();
  }
}

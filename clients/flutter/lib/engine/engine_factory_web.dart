import 'dart:js_interop';
import 'dart:js_interop_unsafe';

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
ProtocolEngine createPlatformEngine() {
  if (!globalContext.has('ProtocolEngine')) {
    return DevEngine();
  }
  final js = _JsProtocolEngine();
  return ScalaJsEngine((input) => js.handle(input));
}

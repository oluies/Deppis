import 'protocol_engine.dart';
// Picks the platform implementation at compile time: the Scala.js bundle binding on web, the
// in-memory DevEngine everywhere else (and in `flutter test`, which runs on the Dart VM).
import 'engine_factory_io.dart'
    if (dart.library.js_interop) 'engine_factory_web.dart';

/// Construct the protocol engine for the current platform. On web this is the real Scala.js
/// `protocol-core` engine (T019) loaded from the linked bundle; if the bundle isn't present, or on
/// any non-web platform, it falls back to the clearly-labeled [DevEngine] (no metadata privacy).
ProtocolEngine createEngine() => createPlatformEngine();

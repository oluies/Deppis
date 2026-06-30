import 'protocol_engine.dart';
// Picks the platform implementation at compile time: the Scala.js bundle binding on web, the
// in-memory DevEngine everywhere else (and in `flutter test`, which runs on the Dart VM).
import 'engine_factory_io.dart'
    if (dart.library.js_interop) 'engine_factory_web.dart';

/// Construct the protocol engine for the current platform. On web this is the real Scala.js
/// `protocol-core` engine (T019) loaded from the linked bundle; on iOS/Android it is the same engine
/// hosted in a `flutter_js` runtime (loaded from the bundled asset). On any failure — or on the Dart
/// VM under `flutter test` — it falls back to the clearly-labeled [DevEngine] (no metadata privacy).
///
/// Async because native platforms load the engine bundle from an asset (web resolves synchronously,
/// so its implementation simply returns an already-completed future).
Future<ProtocolEngine> createEngine() => createPlatformEngine();

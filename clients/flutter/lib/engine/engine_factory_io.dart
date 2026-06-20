import 'dev_engine.dart';
import 'protocol_engine.dart';

/// Non-web platforms (and `flutter test` on the Dart VM): there is no JS runtime to host the
/// Scala.js bundle, so use the in-memory [DevEngine]. It is clearly labeled `DEV, NO METADATA
/// PRIVACY` and performs no cryptography (Constitution VII/IV).
ProtocolEngine createPlatformEngine() => DevEngine();

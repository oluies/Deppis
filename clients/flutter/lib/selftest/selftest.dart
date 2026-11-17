// The live routing self-test (deploy/grpc-web `run.sh --browser`, deploy/native/run-ios-sim.sh).
// A build without `--dart-define=ROUTING_SELFTEST=true` never calls it.
export 'selftest_io.dart' if (dart.library.js_interop) 'selftest_web.dart';

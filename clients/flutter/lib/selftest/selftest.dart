// The live browser self-test (deploy/grpc-web `run.sh --browser`). Web only; a
// build without `--dart-define=ROUTING_SELFTEST=true` never calls it.
export 'selftest_stub.dart' if (dart.library.js_interop) 'selftest_web.dart';

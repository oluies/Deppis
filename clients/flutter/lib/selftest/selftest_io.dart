import 'package:flutter/foundation.dart';

import '../engine/engine_factory_io.dart';
import 'selftest_scenario.dart';

/// The iOS simulator self-test (`deploy/native/run-ios-sim.sh`): both devices share one
/// flutter_js runtime (see `assets/provider-bridge.js`) and reach the provider over HTTP/2 gRPC.
/// The verdict is a log line, which the harness reads from `flutter run`'s output.
Future<void> runRoutingSelfTest() => runRoutingScenario(
  devices: (provider, tuning, tick) =>
      nativeRoutedSetups(provider, count: 2, tuning: tuning, tick: tick),
  report: (title) => debugPrint('ROUTING-SELFTEST-VERDICT $title'),
);

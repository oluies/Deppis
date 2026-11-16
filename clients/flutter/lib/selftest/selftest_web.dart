import 'dart:js_interop';
import 'dart:js_interop_unsafe';

import '../provider/routing_web.dart';
import 'selftest_scenario.dart';

/// The browser self-test (`deploy/grpc-web/run.sh --browser`): each device is its own Scala.js
/// engine + ProviderSession + gRPC-web client. The verdict is the page title, which the harness
/// reads over the DevTools protocol.
Future<void> runRoutingSelfTest() => runRoutingScenario(
  devices: (provider, tuning, tick) async => [
    for (var i = 0; i < 2; i++)
      routedSetup(provider, tuning: tuning, tick: tick),
  ],
  report: (title) =>
      (globalContext['document'] as JSObject)['title'] = title.toJS,
);

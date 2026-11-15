import 'dart:typed_data';

import '../provider/provider_routing.dart';
import 'protocol_engine.dart';

/// What the platform factory hands the app: the engine, and — when the app was
/// built with a provider (`--dart-define=PROVIDER_URL=https://host:port`) and
/// the bundle supports it — the [ProviderRouting] that drives it and this
/// device's notify label, which the user gives each buddy at pairing.
class EngineSetup {
  const EngineSetup(this.engine, {this.routing, this.notifyLabel});

  final ProtocolEngine engine;
  final ProviderRouting? routing;
  final Uint8List? notifyLabel;
}

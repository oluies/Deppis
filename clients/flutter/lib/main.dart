import 'dart:typed_data';

import 'package:flutter/material.dart';

import 'engine/engine_factory.dart';
import 'engine/protocol_engine.dart';
import 'provider/provider_routing.dart';
import 'state/app_state.dart';
import 'ui/home_screen.dart';

Future<void> main() async {
  // Platform-selected engine: the real Scala.js `protocol-core` engine (T019) on web (bundle via a
  // script tag) and on iOS/Android (bundle loaded into a flutter_js runtime), the labeled DevEngine
  // otherwise. The UI talks only to [ProtocolEngine]. Async because native loads the bundle asset.
  // On web, an app built with `--dart-define=PROVIDER_URL=…` is provider-routed
  // (design/offline-delegation.md §3) and the setup carries the routing that drives it.
  WidgetsFlutterBinding.ensureInitialized();
  final setup = await createEngine();
  runApp(MetadataMessengerApp(
    engine: setup.engine,
    routing: setup.routing,
    notifyLabel: setup.notifyLabel,
  ));
}

class MetadataMessengerApp extends StatefulWidget {
  const MetadataMessengerApp({
    super.key,
    required this.engine,
    this.routing,
    this.notifyLabel,
  });

  final ProtocolEngine engine;

  /// Present when the engine is provider-routed.
  final ProviderRouting? routing;

  /// This device's notify label, given to each buddy at pairing (routed only).
  final Uint8List? notifyLabel;

  @override
  State<MetadataMessengerApp> createState() => _MetadataMessengerAppState();
}

class _MetadataMessengerAppState extends State<MetadataMessengerApp> {
  late final AppState _state =
      AppState(widget.engine, notifyLabel: widget.notifyLabel);
  AppLifecycleListener? _lifecycle;

  @override
  void initState() {
    super.initState();
    final routing = widget.routing;
    if (routing != null) {
      // In the foreground the session is stepped; hidden or backgrounded it simply stops and the
      // provider runs the standing bundle — an abrupt disconnect is the normal case, not an error.
      routing.start();
      _lifecycle =
          AppLifecycleListener(onHide: routing.pause, onShow: routing.resume);
    }
  }

  @override
  void dispose() {
    _lifecycle?.dispose();
    widget.routing?.dispose();
    _state.dispose();
    widget.engine.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Metadata Messenger',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: HomeScreen(state: _state),
    );
  }
}

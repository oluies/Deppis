import 'package:flutter/material.dart';

import 'engine/engine_factory.dart';
import 'engine/protocol_engine.dart';
import 'state/app_state.dart';
import 'ui/home_screen.dart';

Future<void> main() async {
  // Platform-selected engine: the real Scala.js `protocol-core` engine (T019) on web (bundle via a
  // script tag) and on iOS/Android (bundle loaded into a flutter_js runtime), the labeled DevEngine
  // otherwise. The UI talks only to [ProtocolEngine]. Async because native loads the bundle asset.
  WidgetsFlutterBinding.ensureInitialized();
  runApp(MetadataMessengerApp(engine: await createEngine()));
}

class MetadataMessengerApp extends StatefulWidget {
  const MetadataMessengerApp({super.key, required this.engine});

  final ProtocolEngine engine;

  @override
  State<MetadataMessengerApp> createState() => _MetadataMessengerAppState();
}

class _MetadataMessengerAppState extends State<MetadataMessengerApp> {
  late final AppState _state = AppState(widget.engine);

  @override
  void dispose() {
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

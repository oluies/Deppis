import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grpc/grpc.dart';
import 'package:metadata_messenger/generated/provider.pbgrpc.dart';
import 'package:metadata_messenger/provider/provider_client.dart';
import 'package:metadata_messenger/provider/routing_native.dart';
import 'package:metadata_messenger/provider/routing_tuning.dart';

import 'support/fake_provider_service.dart';

/// [JsHost] over a Node child process running `support/js_host.cjs`: the real native bundle and the
/// real `provider-bridge.js`, with V8 standing in for JavaScriptCore / QuickJS.
class NodeJsHost implements JsHost {
  NodeJsHost._(this._p);

  static Future<NodeJsHost> start(void Function(Object?) onMessage) async {
    final p = await Process.start('node', [
      'test/support/js_host.cjs',
      'assets/protocol-engine.bundle.js',
      'assets/provider-bridge.js',
    ]);
    final host = NodeJsHost._(p);
    final ready = Completer<bool>();
    p.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
      final m = jsonDecode(line) as Map<String, dynamic>;
      if (m.containsKey('ready')) {
        ready.complete(m['ready'] as bool);
      } else if (m['channel'] == providerBridgeChannel) {
        onMessage(m['message']);
      } else if (m.containsKey('error')) {
        host.errors.add(m['error'] as String);
      }
    });
    p.stderr.transform(utf8.decoder).listen(host.errors.add);
    expect(await ready.future, isTrue, reason: 'the bundle exports ProviderSession');
    return host;
  }

  final Process _p;
  final errors = <String>[];

  @override
  bool run(String code) {
    _p.stdin.writeln(jsonEncode(code));
    return true; // evaluated asynchronously; a fault is reported on stdout as an error
  }

  void kill() => _p.kill();
}

const tuning = RoutingTuning(
  intervalMillis: 2000,
  cutoffMillis: 1200,
  refreshEveryRounds: 2,
  horizonRounds: 4,
  openGraceMillis: 100,
  closeGraceMillis: 100,
  submitMarginMillis: 200,
);

Future<bool> nodeAvailable() async {
  try {
    return (await Process.run('node', ['--version'])).exitCode == 0;
  } catch (_) {
    return false;
  }
}

void main() async {
  final hasNode = await nodeAvailable();

  late FakeProviderService service;
  late Server server;
  late ClientChannel channel;
  late NodeJsHost host;
  late NativeRoutedSession session;
  final label = Uint8List.fromList(List<int>.generate(16, (i) => 0x40 + i));
  const user = 'native-alice';

  setUp(() async {
    service = FakeProviderService();
    server = Server.create(services: [service]);
    await server.serve(address: InternetAddress.loopbackIPv4, port: 0);
    channel = ClientChannel(
      'localhost',
      port: server.port!,
      options: const ChannelOptions(credentials: ChannelCredentials.insecure()),
    );
    final client = ProviderClient(ProviderServiceClient(channel));
    late NativeRoutedSession s;
    host = await NodeJsHost.start((m) => s.onMessage(m));
    s = NativeRoutedSession.create(host, client, user: user, label: label, tuning: tuning);
    session = s;
  });

  tearDown(() async {
    host.kill();
    await channel.shutdown();
    await server.shutdown();
  });

  test(
    'the bundle\'s ProviderSession reaches the provider through the bridge: '
    'register, bundle, live set, receipt, away',
    () async {
      // Round 5 is in progress at 10.5 s (2 s rounds), so the first bundle starts at round 6.
      await session.startAt(10500);
      expect(service.sessions.keys, [user], reason: 'registered with its label');
      final bundle = service.bundles[user]!;
      expect(bundle.length, tuning.horizonRounds);
      expect(bundle.first.roundId, Int64(6));
      expect(bundle.first.writeToken.length, 32, reason: 'bytes survive the base64 hop');
      expect(bundle.first.frame, isNotEmpty);

      // Round 6 opens at 12 s; its cutoff is at 13.2 s. Inside the submit window the device
      // fetches the digest and hands its live set in.
      service.openRound = Int64(6);
      await session.step(12300);
      expect(service.live[user]?.roundId, Int64(6), reason: 'live set handed in for round 6');

      // After the cutoff (+ grace) it collects round 6's receipt.
      service.receipts['$user/6'] = Receipt(
        roundId: Int64(6),
        ranLive: true,
        writeAccepted: true,
        retrieved: Uint8List(0),
        retrievedPresent: false,
      );
      await session.step(13400);
      expect(service.receipts.containsKey('$user/6'), isFalse, reason: 'receipt collected');

      // Back from an absence: everything the provider kept is dropped and counted.
      for (final r in [9, 10]) {
        service.receipts['$user/$r'] = Receipt(roundId: Int64(r), ranLive: false);
      }
      expect(await session.collectAway(), 2);
      expect(host.errors, isEmpty);
    },
    skip: hasNode ? false : 'needs node on PATH to host the JS bundle',
    timeout: const Timeout(Duration(seconds: 60)),
  );

  test('a session call whose evaluation faults fails at once instead of hanging', () async {
    final client = ProviderClient(ProviderServiceClient(channel));
    final s = NativeRoutedSession.create(_FaultyHost(), client, user: 'u', label: label);
    await expectLater(s.step(0), throwsStateError);
  }, skip: hasNode ? false : 'needs node on PATH to host the JS bundle');

  test('malformed or unknown messages are dropped, never thrown', () {
    session.onMessage('not json');
    session.onMessage(42);
    session.onMessage({'t': 'done', 'id': 999, 'ok': true});
  }, skip: hasNode ? false : 'needs node on PATH to host the JS bundle');
}

class _FaultyHost implements JsHost {
  @override
  bool run(String code) => false;
}

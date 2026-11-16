import 'dart:io';
import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grpc/grpc.dart';
import 'package:metadata_messenger/generated/provider.pbgrpc.dart';
import 'package:metadata_messenger/provider/provider_client.dart';

import 'support/fake_provider_service.dart';

RoundOps ops(int round, int seed) => RoundOps(
  roundId: Int64(round),
  writeToken: List<int>.generate(32, (i) => (i + seed) & 0xff),
  frame: List<int>.generate(256, (i) => (i * 3 + seed) & 0xff),
  signal: Signal(label: List<int>.filled(32, seed), bit: seed % 512),
  fallbackSignal: Signal(
    label: List<int>.filled(32, seed + 1),
    bit: (seed + 1) % 512,
  ),
  readToken: List<int>.generate(32, (i) => (i ^ seed) & 0xff),
);

void main() {
  late FakeProviderService service;
  late Server server;
  late ClientChannel channel;
  late ProviderClient client;
  final label = Uint8List.fromList('alice-label'.codeUnits);

  setUp(() async {
    service = FakeProviderService();
    server = Server.create(services: [service]);
    await server.serve(address: InternetAddress.loopbackIPv4, port: 0);
    channel = ClientChannel(
      '127.0.0.1',
      port: server.port!,
      options: const ChannelOptions(credentials: ChannelCredentials.insecure()),
    );
    client = ProviderClient(ProviderServiceClient(channel));
  });

  tearDown(() async {
    await channel.shutdown();
    await server.shutdown();
  });

  test(
    'register keeps the session and presents it on every later call',
    () async {
      expect(await client.register('alice', label), isTrue);
      expect(
        await client.register('alice', label),
        isFalse,
        reason: 'a name registers once',
      );
      expect(
        await client.uploadBundle('alice', Int64(10), [ops(10, 1), ops(11, 2)]),
        isTrue,
        reason: 'the stored session authorised the upload',
      );
      expect(service.bundles['alice']!.length, 2);
    },
  );

  test('round operations and receipts cross the wire byte for byte', () async {
    await client.register('alice', label);
    service.openRound = Int64(5);
    service.digest = Uint8List.fromList(List<int>.generate(64, (i) => i));
    expect(await client.getDigest('alice', Int64(5)), service.digest);
    expect(
      await client.getDigest('alice', Int64(6)),
      isNull,
      reason: 'that round is not open',
    );

    final sent = ops(5, 9);
    expect(await client.submitLive('alice', sent), isTrue);
    expect(
      await client.submitLive('alice', sent),
      isFalse,
      reason: 'one live set per round',
    );
    expect(
      service.live['alice'],
      sent,
      reason: 'the provider received exactly what was sent',
    );

    final r = Receipt(
      roundId: Int64(5),
      ranLive: true,
      writeAccepted: true,
      retrievedPresent: true,
      retrieved: List<int>.filled(256, 7),
      digest: service.digest,
    );
    service.receipts['alice/5'] = r;
    expect(await client.collectReceipt('alice', Int64(5)), r);
    expect(
      await client.collectReceipt('alice', Int64(5)),
      isNull,
      reason: 'taken once',
    );
    service.receipts['alice/6'] = r..roundId = Int64(6);
    service.receipts['alice/7'] = Receipt(roundId: Int64(7));
    expect(await client.collectAll('alice'), 2);
  });

  test(
    'a user this client never registered is answered locally, with no RPC',
    () async {
      // bob is registered with the provider — but by someone else, so this client has no session.
      await ProviderClient(
        ProviderServiceClient(channel),
      ).register('bob', label);
      expect(await client.uploadBundle('bob', Int64(1), [ops(1, 1)]), isFalse);
      expect(await client.getDigest('bob', Int64(0)), isNull);
      expect(await client.submitLive('bob', ops(0, 1)), isFalse);
      expect(service.bundles.containsKey('bob'), isFalse);
    },
  );

  test(
    'a failed RPC degrades to the safe answer — nothing throws into a round',
    () async {
      await client.register('alice', label);
      await server.shutdown(); // the provider goes away mid-session
      expect(await client.getDigest('alice', Int64(0)), isNull);
      expect(await client.submitLive('alice', ops(0, 1)), isFalse);
      expect(await client.collectReceipt('alice', Int64(0)), isNull);
      expect(await client.collectAll('alice'), 0);
      expect(
        await client.uploadBundle('alice', Int64(1), [ops(1, 1)]),
        isFalse,
      );
      expect(await client.register('carol', label), isFalse);
    },
  );
}

import 'dart:io';
import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grpc/grpc.dart';
import 'package:metadata_messenger/generated/provider.pbgrpc.dart';
import 'package:metadata_messenger/provider/provider_client.dart';

/// A stand-in provider behind a REAL in-process gRPC server (Dart VM), implementing just enough of
/// `ProviderService` to check the client: sessions are enforced exactly like the JVM front (a name
/// registers once; every other call needs its session), and bytes are kept verbatim.
class FakeProviderService extends ProviderServiceBase {
  final sessions = <String, List<int>>{};
  final bundles = <String, List<RoundOps>>{};
  final live = <String, RoundOps>{};
  final receipts = <String, Receipt>{};
  Uint8List digest = Uint8List(64);
  var openRound = Int64(0);

  bool _authorised(String user, List<int> session) {
    final s = sessions[user];
    if (s == null || s.length != session.length) {
      return false;
    }
    for (var i = 0; i < s.length; i++) {
      if (s[i] != session[i]) {
        return false;
      }
    }
    return true;
  }

  @override
  Future<RegisterResponse> register(
    ServiceCall call,
    RegisterRequest request,
  ) async {
    if (sessions.containsKey(request.user)) {
      return RegisterResponse(ok: false, error: 'user already registered');
    }
    final s = List<int>.generate(
      32,
      (i) => (i * 7 + request.user.length) & 0xff,
    );
    sessions[request.user] = s;
    return RegisterResponse(ok: true, session: s);
  }

  @override
  Future<UploadBundleResponse> uploadBundle(
    ServiceCall call,
    UploadBundleRequest request,
  ) async {
    if (!_authorised(request.user, request.session)) {
      return UploadBundleResponse(ok: false);
    }
    bundles[request.user] = request.slots.toList();
    return UploadBundleResponse(ok: true);
  }

  @override
  Future<GetDigestResponse> getDigest(
    ServiceCall call,
    GetDigestRequest request,
  ) async {
    final ok =
        _authorised(request.user, request.session) &&
        request.roundId == openRound;
    return ok
        ? GetDigestResponse(ok: true, digest: digest)
        : GetDigestResponse(ok: false);
  }

  @override
  Future<SubmitLiveResponse> submitLive(
    ServiceCall call,
    SubmitLiveRequest request,
  ) async {
    final ok =
        _authorised(request.user, request.session) &&
        request.ops.roundId == openRound &&
        !live.containsKey(request.user);
    if (ok) {
      live[request.user] = request.ops;
    }
    return SubmitLiveResponse(accepted: ok);
  }

  @override
  Future<CollectReceiptResponse> collectReceipt(
    ServiceCall call,
    CollectReceiptRequest request,
  ) async {
    if (!_authorised(request.user, request.session)) {
      return CollectReceiptResponse(found: false);
    }
    final r = receipts.remove('${request.user}/${request.roundId}');
    return r == null
        ? CollectReceiptResponse(found: false)
        : CollectReceiptResponse(found: true, receipt: r);
  }

  @override
  Future<CollectAllResponse> collectAll(
    ServiceCall call,
    CollectAllRequest request,
  ) async {
    if (!_authorised(request.user, request.session)) {
      return CollectAllResponse();
    }
    final mine = receipts.keys
        .where((k) => k.startsWith('${request.user}/'))
        .toList();
    final out = [for (final k in mine) receipts.remove(k)!];
    return CollectAllResponse(receipts: out);
  }
}

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

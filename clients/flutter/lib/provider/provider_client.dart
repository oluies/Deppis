import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:grpc/grpc_or_grpcweb.dart';

import '../generated/provider.pbgrpc.dart';

/// The Flutter client's route to its untrusted service provider (contract
/// `provider.proto`; `design/offline-delegation.md` §3) — the calls behind the
/// engine's `ProviderSession`.
///
/// Over [GrpcOrGrpcWebClientChannel] this is gRPC-web in a browser (to Envoy)
/// and HTTP/2 natively; tests hand it a stub over any channel. It moves opaque
/// bytes only: it never sees plaintext or keys.
///
/// SESSIONS: `Register` returns a secret every later call must present; this
/// client keeps it per user and adds it itself. A call for a user it has not
/// registered is answered locally, without an RPC.
///
/// FAILURES degrade to the safe answer for each call, exactly like the JVM
/// `GrpcProviderClient` and the Scala.js `JsProviderPort`: a refused live set
/// (the provider runs the bundle slot instead), no digest (the round reads as
/// idle), no receipt, zero receipts. Nothing throws into a round.
///
/// Labeled `DEV, NO METADATA PRIVACY` like everything provider-routed until
/// Phase 4 seals what the provider relays.
class ProviderClient {
  ProviderClient(this._stub);

  /// Connect to a provider at [host]:[port] — gRPC-web on web, HTTP/2 natively.
  factory ProviderClient.connect({
    required String host,
    required int port,
    required bool secure,
  }) => ProviderClient(
    ProviderServiceClient(
      GrpcOrGrpcWebClientChannel.toSingleEndpoint(
        host: host,
        port: port,
        transportSecure: secure,
      ),
    ),
  );

  final ProviderServiceClient _stub;
  final _sessions = <String, List<int>>{};

  /// Register [user] with its notify [clientLabel]; keeps the session secret.
  Future<bool> register(String user, Uint8List clientLabel) async {
    try {
      final r = await _stub.register(
        RegisterRequest(user: user, clientLabel: clientLabel),
      );
      if (r.ok) _sessions[user] = r.session;
      return r.ok;
    } catch (_) {
      return false;
    }
  }

  /// Replace [user]'s standing bundle with [slots], one per round from [fromRound].
  Future<bool> uploadBundle(
    String user,
    Int64 fromRound,
    List<RoundOps> slots,
  ) => _withSession(user, false, (s) async {
    final r = await _stub.uploadBundle(
      UploadBundleRequest(
        user: user,
        session: s,
        fromRound: fromRound,
        slots: slots,
      ),
    );
    return r.ok;
  });

  /// The phase-A digest for [user] in [roundId], or null.
  Future<Uint8List?> getDigest(String user, Int64 roundId) =>
      _withSession<Uint8List?>(user, null, (s) async {
        final r = await _stub.getDigest(
          GetDigestRequest(user: user, session: s, roundId: roundId),
        );
        return r.ok ? Uint8List.fromList(r.digest) : null;
      });

  /// Hand in [user]'s live operations for the open round; false = refused.
  Future<bool> submitLive(String user, RoundOps ops) =>
      _withSession(user, false, (s) async {
        final r = await _stub.submitLive(
          SubmitLiveRequest(user: user, session: s, ops: ops),
        );
        return r.accepted;
      });

  /// The kept receipt for [user]'s round [roundId], or null.
  Future<Receipt?> collectReceipt(String user, Int64 roundId) =>
      _withSession<Receipt?>(user, null, (s) async {
        final r = await _stub.collectReceipt(
          CollectReceiptRequest(user: user, session: s, roundId: roundId),
        );
        return r.found ? r.receipt : null;
      });

  /// Drop everything kept for [user] while it was away; returns how many receipts.
  Future<int> collectAll(String user) => _withSession(user, 0, (s) async {
    final r = await _stub.collectAll(CollectAllRequest(user: user, session: s));
    return r.receipts.length;
  });

  Future<T> _withSession<T>(
    String user,
    T fallback,
    Future<T> Function(List<int>) call,
  ) async {
    final s = _sessions[user];
    if (s == null) return fallback;
    try {
      return await call(s);
    } catch (_) {
      return fallback;
    }
  }
}

import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:grpc/grpc.dart';
import 'package:metadata_messenger/generated/provider.pbgrpc.dart';

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

// This is a generated file - do not edit.
//
// Generated from provider.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports

import 'dart:async' as $async;
import 'dart:core' as $core;

import 'package:grpc/service_api.dart' as $grpc;
import 'package:protobuf/protobuf.dart' as $pb;

import 'provider.pb.dart' as $0;

export 'provider.pb.dart';

/// The untrusted service provider's DEVICE-FACING contract (design/offline-delegation.md §3, T038).
///
/// A device never talks to the backend (store, notify) itself: every round it fetches its phase-A
/// digest here, hands in its live operations before the cutoff, and collects the receipt; while it
/// is away the provider runs its standing bundle instead. The provider holds no keys and makes no
/// decisions — it never interprets a token, frame, signal, digest or read result.
///
/// LABELING (Constitution IV): DEV, NO METADATA PRIVACY. Until Phase 4 (§4.2, §4.3, §4.6) the write,
/// read and signal travel in the clear here, and digests and read responses come back in the clear,
/// so a provider serving both ends of a conversation can link them. No build may claim metadata
/// privacy over this contract before then.
///
/// SESSIONS: `Register` returns a random session secret that every other call must present. It stops
/// one client acting in another user's name (submitting its live sets, replacing its bundle) — an
/// integrity / denial-of-service concern, not a privacy one. A user name can be registered once.
@$pb.GrpcServiceName('metadatamessenger.provider.v1.ProviderService')
class ProviderServiceClient extends $grpc.Client {
  /// The hostname for this service.
  static const $core.String defaultHost = '';

  /// OAuth scopes needed for the client.
  static const $core.List<$core.String> oauthScopes = [
    '',
  ];

  ProviderServiceClient(super.channel, {super.options, super.interceptors});

  $grpc.ResponseFuture<$0.RegisterResponse> register(
    $0.RegisterRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$register, request, options: options);
  }

  $grpc.ResponseFuture<$0.UploadBundleResponse> uploadBundle(
    $0.UploadBundleRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$uploadBundle, request, options: options);
  }

  $grpc.ResponseFuture<$0.GetDigestResponse> getDigest(
    $0.GetDigestRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$getDigest, request, options: options);
  }

  $grpc.ResponseFuture<$0.SubmitLiveResponse> submitLive(
    $0.SubmitLiveRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$submitLive, request, options: options);
  }

  $grpc.ResponseFuture<$0.CollectReceiptResponse> collectReceipt(
    $0.CollectReceiptRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$collectReceipt, request, options: options);
  }

  $grpc.ResponseFuture<$0.CollectAllResponse> collectAll(
    $0.CollectAllRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$collectAll, request, options: options);
  }

  // method descriptors

  static final _$register =
      $grpc.ClientMethod<$0.RegisterRequest, $0.RegisterResponse>(
          '/metadatamessenger.provider.v1.ProviderService/Register',
          ($0.RegisterRequest value) => value.writeToBuffer(),
          $0.RegisterResponse.fromBuffer);
  static final _$uploadBundle =
      $grpc.ClientMethod<$0.UploadBundleRequest, $0.UploadBundleResponse>(
          '/metadatamessenger.provider.v1.ProviderService/UploadBundle',
          ($0.UploadBundleRequest value) => value.writeToBuffer(),
          $0.UploadBundleResponse.fromBuffer);
  static final _$getDigest =
      $grpc.ClientMethod<$0.GetDigestRequest, $0.GetDigestResponse>(
          '/metadatamessenger.provider.v1.ProviderService/GetDigest',
          ($0.GetDigestRequest value) => value.writeToBuffer(),
          $0.GetDigestResponse.fromBuffer);
  static final _$submitLive =
      $grpc.ClientMethod<$0.SubmitLiveRequest, $0.SubmitLiveResponse>(
          '/metadatamessenger.provider.v1.ProviderService/SubmitLive',
          ($0.SubmitLiveRequest value) => value.writeToBuffer(),
          $0.SubmitLiveResponse.fromBuffer);
  static final _$collectReceipt =
      $grpc.ClientMethod<$0.CollectReceiptRequest, $0.CollectReceiptResponse>(
          '/metadatamessenger.provider.v1.ProviderService/CollectReceipt',
          ($0.CollectReceiptRequest value) => value.writeToBuffer(),
          $0.CollectReceiptResponse.fromBuffer);
  static final _$collectAll =
      $grpc.ClientMethod<$0.CollectAllRequest, $0.CollectAllResponse>(
          '/metadatamessenger.provider.v1.ProviderService/CollectAll',
          ($0.CollectAllRequest value) => value.writeToBuffer(),
          $0.CollectAllResponse.fromBuffer);
}

@$pb.GrpcServiceName('metadatamessenger.provider.v1.ProviderService')
abstract class ProviderServiceBase extends $grpc.Service {
  $core.String get $name => 'metadatamessenger.provider.v1.ProviderService';

  ProviderServiceBase() {
    $addMethod($grpc.ServiceMethod<$0.RegisterRequest, $0.RegisterResponse>(
        'Register',
        register_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.RegisterRequest.fromBuffer(value),
        ($0.RegisterResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.UploadBundleRequest, $0.UploadBundleResponse>(
            'UploadBundle',
            uploadBundle_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.UploadBundleRequest.fromBuffer(value),
            ($0.UploadBundleResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.GetDigestRequest, $0.GetDigestResponse>(
        'GetDigest',
        getDigest_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.GetDigestRequest.fromBuffer(value),
        ($0.GetDigestResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.SubmitLiveRequest, $0.SubmitLiveResponse>(
        'SubmitLive',
        submitLive_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.SubmitLiveRequest.fromBuffer(value),
        ($0.SubmitLiveResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.CollectReceiptRequest,
            $0.CollectReceiptResponse>(
        'CollectReceipt',
        collectReceipt_Pre,
        false,
        false,
        ($core.List<$core.int> value) =>
            $0.CollectReceiptRequest.fromBuffer(value),
        ($0.CollectReceiptResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.CollectAllRequest, $0.CollectAllResponse>(
        'CollectAll',
        collectAll_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.CollectAllRequest.fromBuffer(value),
        ($0.CollectAllResponse value) => value.writeToBuffer()));
  }

  $async.Future<$0.RegisterResponse> register_Pre($grpc.ServiceCall $call,
      $async.Future<$0.RegisterRequest> $request) async {
    return register($call, await $request);
  }

  $async.Future<$0.RegisterResponse> register(
      $grpc.ServiceCall call, $0.RegisterRequest request);

  $async.Future<$0.UploadBundleResponse> uploadBundle_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.UploadBundleRequest> $request) async {
    return uploadBundle($call, await $request);
  }

  $async.Future<$0.UploadBundleResponse> uploadBundle(
      $grpc.ServiceCall call, $0.UploadBundleRequest request);

  $async.Future<$0.GetDigestResponse> getDigest_Pre($grpc.ServiceCall $call,
      $async.Future<$0.GetDigestRequest> $request) async {
    return getDigest($call, await $request);
  }

  $async.Future<$0.GetDigestResponse> getDigest(
      $grpc.ServiceCall call, $0.GetDigestRequest request);

  $async.Future<$0.SubmitLiveResponse> submitLive_Pre($grpc.ServiceCall $call,
      $async.Future<$0.SubmitLiveRequest> $request) async {
    return submitLive($call, await $request);
  }

  $async.Future<$0.SubmitLiveResponse> submitLive(
      $grpc.ServiceCall call, $0.SubmitLiveRequest request);

  $async.Future<$0.CollectReceiptResponse> collectReceipt_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.CollectReceiptRequest> $request) async {
    return collectReceipt($call, await $request);
  }

  $async.Future<$0.CollectReceiptResponse> collectReceipt(
      $grpc.ServiceCall call, $0.CollectReceiptRequest request);

  $async.Future<$0.CollectAllResponse> collectAll_Pre($grpc.ServiceCall $call,
      $async.Future<$0.CollectAllRequest> $request) async {
    return collectAll($call, await $request);
  }

  $async.Future<$0.CollectAllResponse> collectAll(
      $grpc.ServiceCall call, $0.CollectAllRequest request);
}

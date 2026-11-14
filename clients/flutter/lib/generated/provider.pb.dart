// This is a generated file - do not edit.
//
// Generated from provider.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports

import 'dart:core' as $core;

import 'package:fixnum/fixnum.dart' as $fixnum;
import 'package:protobuf/protobuf.dart' as $pb;

export 'package:protobuf/protobuf.dart' show GeneratedMessageGenericExtensions;

/// A notify signal: the fixed-width label tag and the round-rotated bit.
class Signal extends $pb.GeneratedMessage {
  factory Signal({
    $core.List<$core.int>? label,
    $core.int? bit,
  }) {
    final result = Signal._();
    if (label != null) result.label = label;
    if (bit != null) result.bit = bit;
    return result;
  }

  Signal._();

  factory Signal.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      Signal()..mergeFromBuffer(data, registry);
  factory Signal.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      Signal()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'Signal',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: Signal.$_createMessage)
    ..a<$core.List<$core.int>>(
        1, _omitFieldNames ? '' : 'label', $pb.PbFieldType.OY)
    ..aI(2, _omitFieldNames ? '' : 'bit', fieldType: $pb.PbFieldType.OU3)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  Signal clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  Signal copyWith(void Function(Signal) updates) =>
      super.copyWith((message) => updates(message as Signal)) as Signal;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use Signal() / Signal.new instead')
  static Signal create() => Signal._();
  static $pb.GeneratedMessage $_createMessage() => Signal._();
  @$core.override
  Signal createEmptyInstance() => Signal._();
  @$core.pragma('dart2js:noInline')
  static Signal getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<Signal>(Signal.$_createMessage);
  static Signal? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<$core.int> get label => $_getN(0);
  @$pb.TagNumber(1)
  set label($core.List<$core.int> value) => $_setBytes(0, value);
  @$pb.TagNumber(1)
  $core.bool hasLabel() => $_has(0);
  @$pb.TagNumber(1)
  void clearLabel() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.int get bit => $_getIZ(1);
  @$pb.TagNumber(2)
  set bit($core.int value) => $_setUnsignedInt32(1, value);
  @$pb.TagNumber(2)
  $core.bool hasBit() => $_has(1);
  @$pb.TagNumber(2)
  void clearBit() => $_clearField(2);
}

/// One round's operations for one device (engine.RoundOps): exactly one write, one signal (the real
/// one if the write is accepted, else the decoy fallback) and one read. Fixed size per field.
class RoundOps extends $pb.GeneratedMessage {
  factory RoundOps({
    $fixnum.Int64? roundId,
    $core.List<$core.int>? writeToken,
    $core.List<$core.int>? frame,
    Signal? signal,
    Signal? fallbackSignal,
    $core.List<$core.int>? readToken,
  }) {
    final result = RoundOps._();
    if (roundId != null) result.roundId = roundId;
    if (writeToken != null) result.writeToken = writeToken;
    if (frame != null) result.frame = frame;
    if (signal != null) result.signal = signal;
    if (fallbackSignal != null) result.fallbackSignal = fallbackSignal;
    if (readToken != null) result.readToken = readToken;
    return result;
  }

  RoundOps._();

  factory RoundOps.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RoundOps()..mergeFromBuffer(data, registry);
  factory RoundOps.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RoundOps()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RoundOps',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: RoundOps.$_createMessage)
    ..aInt64(1, _omitFieldNames ? '' : 'roundId')
    ..a<$core.List<$core.int>>(
        2, _omitFieldNames ? '' : 'writeToken', $pb.PbFieldType.OY)
    ..a<$core.List<$core.int>>(
        3, _omitFieldNames ? '' : 'frame', $pb.PbFieldType.OY)
    ..aOM<Signal>(4, _omitFieldNames ? '' : 'signal',
        subBuilder: Signal.$_createMessage)
    ..aOM<Signal>(5, _omitFieldNames ? '' : 'fallbackSignal',
        subBuilder: Signal.$_createMessage)
    ..a<$core.List<$core.int>>(
        6, _omitFieldNames ? '' : 'readToken', $pb.PbFieldType.OY)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RoundOps clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RoundOps copyWith(void Function(RoundOps) updates) =>
      super.copyWith((message) => updates(message as RoundOps)) as RoundOps;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use RoundOps() / RoundOps.new instead')
  static RoundOps create() => RoundOps._();
  static $pb.GeneratedMessage $_createMessage() => RoundOps._();
  @$core.override
  RoundOps createEmptyInstance() => RoundOps._();
  @$core.pragma('dart2js:noInline')
  static RoundOps getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RoundOps>(RoundOps.$_createMessage);
  static RoundOps? _defaultInstance;

  @$pb.TagNumber(1)
  $fixnum.Int64 get roundId => $_getI64(0);
  @$pb.TagNumber(1)
  set roundId($fixnum.Int64 value) => $_setInt64(0, value);
  @$pb.TagNumber(1)
  $core.bool hasRoundId() => $_has(0);
  @$pb.TagNumber(1)
  void clearRoundId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.int> get writeToken => $_getN(1);
  @$pb.TagNumber(2)
  set writeToken($core.List<$core.int> value) => $_setBytes(1, value);
  @$pb.TagNumber(2)
  $core.bool hasWriteToken() => $_has(1);
  @$pb.TagNumber(2)
  void clearWriteToken() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.List<$core.int> get frame => $_getN(2);
  @$pb.TagNumber(3)
  set frame($core.List<$core.int> value) => $_setBytes(2, value);
  @$pb.TagNumber(3)
  $core.bool hasFrame() => $_has(2);
  @$pb.TagNumber(3)
  void clearFrame() => $_clearField(3);

  @$pb.TagNumber(4)
  Signal get signal => $_getN(3);
  @$pb.TagNumber(4)
  set signal(Signal value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasSignal() => $_has(3);
  @$pb.TagNumber(4)
  void clearSignal() => $_clearField(4);
  @$pb.TagNumber(4)
  Signal ensureSignal() => $_ensure(3);

  @$pb.TagNumber(5)
  Signal get fallbackSignal => $_getN(4);
  @$pb.TagNumber(5)
  set fallbackSignal(Signal value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasFallbackSignal() => $_has(4);
  @$pb.TagNumber(5)
  void clearFallbackSignal() => $_clearField(5);
  @$pb.TagNumber(5)
  Signal ensureFallbackSignal() => $_ensure(4);

  @$pb.TagNumber(6)
  $core.List<$core.int> get readToken => $_getN(5);
  @$pb.TagNumber(6)
  set readToken($core.List<$core.int> value) => $_setBytes(5, value);
  @$pb.TagNumber(6)
  $core.bool hasReadToken() => $_has(5);
  @$pb.TagNumber(6)
  void clearReadToken() => $_clearField(6);
}

/// What ran for a round, with that round's phase-A digest.
class Receipt extends $pb.GeneratedMessage {
  factory Receipt({
    $fixnum.Int64? roundId,
    $core.bool? ranLive,
    $core.bool? writeAccepted,
    $core.bool? retrievedPresent,
    $core.List<$core.int>? retrieved,
    $core.List<$core.int>? digest,
  }) {
    final result = Receipt._();
    if (roundId != null) result.roundId = roundId;
    if (ranLive != null) result.ranLive = ranLive;
    if (writeAccepted != null) result.writeAccepted = writeAccepted;
    if (retrievedPresent != null) result.retrievedPresent = retrievedPresent;
    if (retrieved != null) result.retrieved = retrieved;
    if (digest != null) result.digest = digest;
    return result;
  }

  Receipt._();

  factory Receipt.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      Receipt()..mergeFromBuffer(data, registry);
  factory Receipt.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      Receipt()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'Receipt',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: Receipt.$_createMessage)
    ..aInt64(1, _omitFieldNames ? '' : 'roundId')
    ..aOB(2, _omitFieldNames ? '' : 'ranLive')
    ..aOB(3, _omitFieldNames ? '' : 'writeAccepted')
    ..aOB(4, _omitFieldNames ? '' : 'retrievedPresent')
    ..a<$core.List<$core.int>>(
        5, _omitFieldNames ? '' : 'retrieved', $pb.PbFieldType.OY)
    ..a<$core.List<$core.int>>(
        6, _omitFieldNames ? '' : 'digest', $pb.PbFieldType.OY)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  Receipt clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  Receipt copyWith(void Function(Receipt) updates) =>
      super.copyWith((message) => updates(message as Receipt)) as Receipt;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use Receipt() / Receipt.new instead')
  static Receipt create() => Receipt._();
  static $pb.GeneratedMessage $_createMessage() => Receipt._();
  @$core.override
  Receipt createEmptyInstance() => Receipt._();
  @$core.pragma('dart2js:noInline')
  static Receipt getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<Receipt>(Receipt.$_createMessage);
  static Receipt? _defaultInstance;

  @$pb.TagNumber(1)
  $fixnum.Int64 get roundId => $_getI64(0);
  @$pb.TagNumber(1)
  set roundId($fixnum.Int64 value) => $_setInt64(0, value);
  @$pb.TagNumber(1)
  $core.bool hasRoundId() => $_has(0);
  @$pb.TagNumber(1)
  void clearRoundId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.bool get ranLive => $_getBF(1);
  @$pb.TagNumber(2)
  set ranLive($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(2)
  $core.bool hasRanLive() => $_has(1);
  @$pb.TagNumber(2)
  void clearRanLive() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.bool get writeAccepted => $_getBF(2);
  @$pb.TagNumber(3)
  set writeAccepted($core.bool value) => $_setBool(2, value);
  @$pb.TagNumber(3)
  $core.bool hasWriteAccepted() => $_has(2);
  @$pb.TagNumber(3)
  void clearWriteAccepted() => $_clearField(3);

  /// The read returned a frame. (Not `has_retrieved`: generated Dart gives every field a
  /// `hasX()` accessor, so that name collides with `retrieved`'s and gets mangled.)
  @$pb.TagNumber(4)
  $core.bool get retrievedPresent => $_getBF(3);
  @$pb.TagNumber(4)
  set retrievedPresent($core.bool value) => $_setBool(3, value);
  @$pb.TagNumber(4)
  $core.bool hasRetrievedPresent() => $_has(3);
  @$pb.TagNumber(4)
  void clearRetrievedPresent() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.List<$core.int> get retrieved => $_getN(4);
  @$pb.TagNumber(5)
  set retrieved($core.List<$core.int> value) => $_setBytes(4, value);
  @$pb.TagNumber(5)
  $core.bool hasRetrieved() => $_has(4);
  @$pb.TagNumber(5)
  void clearRetrieved() => $_clearField(5);

  @$pb.TagNumber(6)
  $core.List<$core.int> get digest => $_getN(5);
  @$pb.TagNumber(6)
  set digest($core.List<$core.int> value) => $_setBytes(5, value);
  @$pb.TagNumber(6)
  $core.bool hasDigest() => $_has(5);
  @$pb.TagNumber(6)
  void clearDigest() => $_clearField(6);
}

class RegisterRequest extends $pb.GeneratedMessage {
  factory RegisterRequest({
    $core.String? user,
    $core.List<$core.int>? clientLabel,
  }) {
    final result = RegisterRequest._();
    if (user != null) result.user = user;
    if (clientLabel != null) result.clientLabel = clientLabel;
    return result;
  }

  RegisterRequest._();

  factory RegisterRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RegisterRequest()..mergeFromBuffer(data, registry);
  factory RegisterRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RegisterRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RegisterRequest',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: RegisterRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'user')
    ..a<$core.List<$core.int>>(
        2, _omitFieldNames ? '' : 'clientLabel', $pb.PbFieldType.OY)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RegisterRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RegisterRequest copyWith(void Function(RegisterRequest) updates) =>
      super.copyWith((message) => updates(message as RegisterRequest))
          as RegisterRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use RegisterRequest() / RegisterRequest.new instead')
  static RegisterRequest create() => RegisterRequest._();
  static $pb.GeneratedMessage $_createMessage() => RegisterRequest._();
  @$core.override
  RegisterRequest createEmptyInstance() => RegisterRequest._();
  @$core.pragma('dart2js:noInline')
  static RegisterRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<RegisterRequest>(
          RegisterRequest.$_createMessage);
  static RegisterRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get user => $_getSZ(0);
  @$pb.TagNumber(1)
  set user($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasUser() => $_has(0);
  @$pb.TagNumber(1)
  void clearUser() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.int> get clientLabel => $_getN(1);
  @$pb.TagNumber(2)
  set clientLabel($core.List<$core.int> value) => $_setBytes(1, value);
  @$pb.TagNumber(2)
  $core.bool hasClientLabel() => $_has(1);
  @$pb.TagNumber(2)
  void clearClientLabel() => $_clearField(2);
}

class RegisterResponse extends $pb.GeneratedMessage {
  factory RegisterResponse({
    $core.bool? ok,
    $core.List<$core.int>? session,
    $core.String? error,
  }) {
    final result = RegisterResponse._();
    if (ok != null) result.ok = ok;
    if (session != null) result.session = session;
    if (error != null) result.error = error;
    return result;
  }

  RegisterResponse._();

  factory RegisterResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RegisterResponse()..mergeFromBuffer(data, registry);
  factory RegisterResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RegisterResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RegisterResponse',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: RegisterResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'ok')
    ..a<$core.List<$core.int>>(
        2, _omitFieldNames ? '' : 'session', $pb.PbFieldType.OY)
    ..aOS(3, _omitFieldNames ? '' : 'error')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RegisterResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RegisterResponse copyWith(void Function(RegisterResponse) updates) =>
      super.copyWith((message) => updates(message as RegisterResponse))
          as RegisterResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use RegisterResponse() / RegisterResponse.new instead')
  static RegisterResponse create() => RegisterResponse._();
  static $pb.GeneratedMessage $_createMessage() => RegisterResponse._();
  @$core.override
  RegisterResponse createEmptyInstance() => RegisterResponse._();
  @$core.pragma('dart2js:noInline')
  static RegisterResponse getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<RegisterResponse>(
          RegisterResponse.$_createMessage);
  static RegisterResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get ok => $_getBF(0);
  @$pb.TagNumber(1)
  set ok($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasOk() => $_has(0);
  @$pb.TagNumber(1)
  void clearOk() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.int> get session => $_getN(1);
  @$pb.TagNumber(2)
  set session($core.List<$core.int> value) => $_setBytes(1, value);
  @$pb.TagNumber(2)
  $core.bool hasSession() => $_has(1);
  @$pb.TagNumber(2)
  void clearSession() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get error => $_getSZ(2);
  @$pb.TagNumber(3)
  set error($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasError() => $_has(2);
  @$pb.TagNumber(3)
  void clearError() => $_clearField(3);
}

class UploadBundleRequest extends $pb.GeneratedMessage {
  factory UploadBundleRequest({
    $core.String? user,
    $core.List<$core.int>? session,
    $fixnum.Int64? fromRound,
    $core.Iterable<RoundOps>? slots,
  }) {
    final result = UploadBundleRequest._();
    if (user != null) result.user = user;
    if (session != null) result.session = session;
    if (fromRound != null) result.fromRound = fromRound;
    if (slots != null) result.slots.addAll(slots);
    return result;
  }

  UploadBundleRequest._();

  factory UploadBundleRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UploadBundleRequest()..mergeFromBuffer(data, registry);
  factory UploadBundleRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UploadBundleRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UploadBundleRequest',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: UploadBundleRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'user')
    ..a<$core.List<$core.int>>(
        2, _omitFieldNames ? '' : 'session', $pb.PbFieldType.OY)
    ..aInt64(3, _omitFieldNames ? '' : 'fromRound')
    ..pPM<RoundOps>(4, _omitFieldNames ? '' : 'slots',
        subBuilder: RoundOps.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UploadBundleRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UploadBundleRequest copyWith(void Function(UploadBundleRequest) updates) =>
      super.copyWith((message) => updates(message as UploadBundleRequest))
          as UploadBundleRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core
      .Deprecated('Use UploadBundleRequest() / UploadBundleRequest.new instead')
  static UploadBundleRequest create() => UploadBundleRequest._();
  static $pb.GeneratedMessage $_createMessage() => UploadBundleRequest._();
  @$core.override
  UploadBundleRequest createEmptyInstance() => UploadBundleRequest._();
  @$core.pragma('dart2js:noInline')
  static UploadBundleRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UploadBundleRequest>(
          UploadBundleRequest.$_createMessage);
  static UploadBundleRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get user => $_getSZ(0);
  @$pb.TagNumber(1)
  set user($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasUser() => $_has(0);
  @$pb.TagNumber(1)
  void clearUser() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.int> get session => $_getN(1);
  @$pb.TagNumber(2)
  set session($core.List<$core.int> value) => $_setBytes(1, value);
  @$pb.TagNumber(2)
  $core.bool hasSession() => $_has(1);
  @$pb.TagNumber(2)
  void clearSession() => $_clearField(2);

  @$pb.TagNumber(3)
  $fixnum.Int64 get fromRound => $_getI64(2);
  @$pb.TagNumber(3)
  set fromRound($fixnum.Int64 value) => $_setInt64(2, value);
  @$pb.TagNumber(3)
  $core.bool hasFromRound() => $_has(2);
  @$pb.TagNumber(3)
  void clearFromRound() => $_clearField(3);

  @$pb.TagNumber(4)
  $pb.PbList<RoundOps> get slots => $_getList(3);
}

class UploadBundleResponse extends $pb.GeneratedMessage {
  factory UploadBundleResponse({
    $core.bool? ok,
    $core.String? error,
  }) {
    final result = UploadBundleResponse._();
    if (ok != null) result.ok = ok;
    if (error != null) result.error = error;
    return result;
  }

  UploadBundleResponse._();

  factory UploadBundleResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UploadBundleResponse()..mergeFromBuffer(data, registry);
  factory UploadBundleResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UploadBundleResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UploadBundleResponse',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: UploadBundleResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'ok')
    ..aOS(2, _omitFieldNames ? '' : 'error')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UploadBundleResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UploadBundleResponse copyWith(void Function(UploadBundleResponse) updates) =>
      super.copyWith((message) => updates(message as UploadBundleResponse))
          as UploadBundleResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use UploadBundleResponse() / UploadBundleResponse.new instead')
  static UploadBundleResponse create() => UploadBundleResponse._();
  static $pb.GeneratedMessage $_createMessage() => UploadBundleResponse._();
  @$core.override
  UploadBundleResponse createEmptyInstance() => UploadBundleResponse._();
  @$core.pragma('dart2js:noInline')
  static UploadBundleResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UploadBundleResponse>(
          UploadBundleResponse.$_createMessage);
  static UploadBundleResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get ok => $_getBF(0);
  @$pb.TagNumber(1)
  set ok($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasOk() => $_has(0);
  @$pb.TagNumber(1)
  void clearOk() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get error => $_getSZ(1);
  @$pb.TagNumber(2)
  set error($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasError() => $_has(1);
  @$pb.TagNumber(2)
  void clearError() => $_clearField(2);
}

class GetDigestRequest extends $pb.GeneratedMessage {
  factory GetDigestRequest({
    $core.String? user,
    $core.List<$core.int>? session,
    $fixnum.Int64? roundId,
  }) {
    final result = GetDigestRequest._();
    if (user != null) result.user = user;
    if (session != null) result.session = session;
    if (roundId != null) result.roundId = roundId;
    return result;
  }

  GetDigestRequest._();

  factory GetDigestRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetDigestRequest()..mergeFromBuffer(data, registry);
  factory GetDigestRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetDigestRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetDigestRequest',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: GetDigestRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'user')
    ..a<$core.List<$core.int>>(
        2, _omitFieldNames ? '' : 'session', $pb.PbFieldType.OY)
    ..aInt64(3, _omitFieldNames ? '' : 'roundId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetDigestRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetDigestRequest copyWith(void Function(GetDigestRequest) updates) =>
      super.copyWith((message) => updates(message as GetDigestRequest))
          as GetDigestRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use GetDigestRequest() / GetDigestRequest.new instead')
  static GetDigestRequest create() => GetDigestRequest._();
  static $pb.GeneratedMessage $_createMessage() => GetDigestRequest._();
  @$core.override
  GetDigestRequest createEmptyInstance() => GetDigestRequest._();
  @$core.pragma('dart2js:noInline')
  static GetDigestRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetDigestRequest>(
          GetDigestRequest.$_createMessage);
  static GetDigestRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get user => $_getSZ(0);
  @$pb.TagNumber(1)
  set user($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasUser() => $_has(0);
  @$pb.TagNumber(1)
  void clearUser() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.int> get session => $_getN(1);
  @$pb.TagNumber(2)
  set session($core.List<$core.int> value) => $_setBytes(1, value);
  @$pb.TagNumber(2)
  $core.bool hasSession() => $_has(1);
  @$pb.TagNumber(2)
  void clearSession() => $_clearField(2);

  @$pb.TagNumber(3)
  $fixnum.Int64 get roundId => $_getI64(2);
  @$pb.TagNumber(3)
  set roundId($fixnum.Int64 value) => $_setInt64(2, value);
  @$pb.TagNumber(3)
  $core.bool hasRoundId() => $_has(2);
  @$pb.TagNumber(3)
  void clearRoundId() => $_clearField(3);
}

class GetDigestResponse extends $pb.GeneratedMessage {
  factory GetDigestResponse({
    $core.bool? ok,
    $core.List<$core.int>? digest,
  }) {
    final result = GetDigestResponse._();
    if (ok != null) result.ok = ok;
    if (digest != null) result.digest = digest;
    return result;
  }

  GetDigestResponse._();

  factory GetDigestResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetDigestResponse()..mergeFromBuffer(data, registry);
  factory GetDigestResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetDigestResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetDigestResponse',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: GetDigestResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'ok')
    ..a<$core.List<$core.int>>(
        2, _omitFieldNames ? '' : 'digest', $pb.PbFieldType.OY)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetDigestResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetDigestResponse copyWith(void Function(GetDigestResponse) updates) =>
      super.copyWith((message) => updates(message as GetDigestResponse))
          as GetDigestResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use GetDigestResponse() / GetDigestResponse.new instead')
  static GetDigestResponse create() => GetDigestResponse._();
  static $pb.GeneratedMessage $_createMessage() => GetDigestResponse._();
  @$core.override
  GetDigestResponse createEmptyInstance() => GetDigestResponse._();
  @$core.pragma('dart2js:noInline')
  static GetDigestResponse getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetDigestResponse>(
          GetDigestResponse.$_createMessage);
  static GetDigestResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get ok => $_getBF(0);
  @$pb.TagNumber(1)
  set ok($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasOk() => $_has(0);
  @$pb.TagNumber(1)
  void clearOk() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.int> get digest => $_getN(1);
  @$pb.TagNumber(2)
  set digest($core.List<$core.int> value) => $_setBytes(1, value);
  @$pb.TagNumber(2)
  $core.bool hasDigest() => $_has(1);
  @$pb.TagNumber(2)
  void clearDigest() => $_clearField(2);
}

class SubmitLiveRequest extends $pb.GeneratedMessage {
  factory SubmitLiveRequest({
    $core.String? user,
    $core.List<$core.int>? session,
    RoundOps? ops,
  }) {
    final result = SubmitLiveRequest._();
    if (user != null) result.user = user;
    if (session != null) result.session = session;
    if (ops != null) result.ops = ops;
    return result;
  }

  SubmitLiveRequest._();

  factory SubmitLiveRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      SubmitLiveRequest()..mergeFromBuffer(data, registry);
  factory SubmitLiveRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      SubmitLiveRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SubmitLiveRequest',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: SubmitLiveRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'user')
    ..a<$core.List<$core.int>>(
        2, _omitFieldNames ? '' : 'session', $pb.PbFieldType.OY)
    ..aOM<RoundOps>(3, _omitFieldNames ? '' : 'ops',
        subBuilder: RoundOps.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SubmitLiveRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SubmitLiveRequest copyWith(void Function(SubmitLiveRequest) updates) =>
      super.copyWith((message) => updates(message as SubmitLiveRequest))
          as SubmitLiveRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use SubmitLiveRequest() / SubmitLiveRequest.new instead')
  static SubmitLiveRequest create() => SubmitLiveRequest._();
  static $pb.GeneratedMessage $_createMessage() => SubmitLiveRequest._();
  @$core.override
  SubmitLiveRequest createEmptyInstance() => SubmitLiveRequest._();
  @$core.pragma('dart2js:noInline')
  static SubmitLiveRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<SubmitLiveRequest>(
          SubmitLiveRequest.$_createMessage);
  static SubmitLiveRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get user => $_getSZ(0);
  @$pb.TagNumber(1)
  set user($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasUser() => $_has(0);
  @$pb.TagNumber(1)
  void clearUser() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.int> get session => $_getN(1);
  @$pb.TagNumber(2)
  set session($core.List<$core.int> value) => $_setBytes(1, value);
  @$pb.TagNumber(2)
  $core.bool hasSession() => $_has(1);
  @$pb.TagNumber(2)
  void clearSession() => $_clearField(2);

  @$pb.TagNumber(3)
  RoundOps get ops => $_getN(2);
  @$pb.TagNumber(3)
  set ops(RoundOps value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasOps() => $_has(2);
  @$pb.TagNumber(3)
  void clearOps() => $_clearField(3);
  @$pb.TagNumber(3)
  RoundOps ensureOps() => $_ensure(2);
}

class SubmitLiveResponse extends $pb.GeneratedMessage {
  factory SubmitLiveResponse({
    $core.bool? accepted,
  }) {
    final result = SubmitLiveResponse._();
    if (accepted != null) result.accepted = accepted;
    return result;
  }

  SubmitLiveResponse._();

  factory SubmitLiveResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      SubmitLiveResponse()..mergeFromBuffer(data, registry);
  factory SubmitLiveResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      SubmitLiveResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SubmitLiveResponse',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: SubmitLiveResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'accepted')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SubmitLiveResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SubmitLiveResponse copyWith(void Function(SubmitLiveResponse) updates) =>
      super.copyWith((message) => updates(message as SubmitLiveResponse))
          as SubmitLiveResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use SubmitLiveResponse() / SubmitLiveResponse.new instead')
  static SubmitLiveResponse create() => SubmitLiveResponse._();
  static $pb.GeneratedMessage $_createMessage() => SubmitLiveResponse._();
  @$core.override
  SubmitLiveResponse createEmptyInstance() => SubmitLiveResponse._();
  @$core.pragma('dart2js:noInline')
  static SubmitLiveResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SubmitLiveResponse>(
          SubmitLiveResponse.$_createMessage);
  static SubmitLiveResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get accepted => $_getBF(0);
  @$pb.TagNumber(1)
  set accepted($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasAccepted() => $_has(0);
  @$pb.TagNumber(1)
  void clearAccepted() => $_clearField(1);
}

class CollectReceiptRequest extends $pb.GeneratedMessage {
  factory CollectReceiptRequest({
    $core.String? user,
    $core.List<$core.int>? session,
    $fixnum.Int64? roundId,
  }) {
    final result = CollectReceiptRequest._();
    if (user != null) result.user = user;
    if (session != null) result.session = session;
    if (roundId != null) result.roundId = roundId;
    return result;
  }

  CollectReceiptRequest._();

  factory CollectReceiptRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CollectReceiptRequest()..mergeFromBuffer(data, registry);
  factory CollectReceiptRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CollectReceiptRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CollectReceiptRequest',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: CollectReceiptRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'user')
    ..a<$core.List<$core.int>>(
        2, _omitFieldNames ? '' : 'session', $pb.PbFieldType.OY)
    ..aInt64(3, _omitFieldNames ? '' : 'roundId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CollectReceiptRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CollectReceiptRequest copyWith(
          void Function(CollectReceiptRequest) updates) =>
      super.copyWith((message) => updates(message as CollectReceiptRequest))
          as CollectReceiptRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CollectReceiptRequest() / CollectReceiptRequest.new instead')
  static CollectReceiptRequest create() => CollectReceiptRequest._();
  static $pb.GeneratedMessage $_createMessage() => CollectReceiptRequest._();
  @$core.override
  CollectReceiptRequest createEmptyInstance() => CollectReceiptRequest._();
  @$core.pragma('dart2js:noInline')
  static CollectReceiptRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CollectReceiptRequest>(
          CollectReceiptRequest.$_createMessage);
  static CollectReceiptRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get user => $_getSZ(0);
  @$pb.TagNumber(1)
  set user($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasUser() => $_has(0);
  @$pb.TagNumber(1)
  void clearUser() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.int> get session => $_getN(1);
  @$pb.TagNumber(2)
  set session($core.List<$core.int> value) => $_setBytes(1, value);
  @$pb.TagNumber(2)
  $core.bool hasSession() => $_has(1);
  @$pb.TagNumber(2)
  void clearSession() => $_clearField(2);

  @$pb.TagNumber(3)
  $fixnum.Int64 get roundId => $_getI64(2);
  @$pb.TagNumber(3)
  set roundId($fixnum.Int64 value) => $_setInt64(2, value);
  @$pb.TagNumber(3)
  $core.bool hasRoundId() => $_has(2);
  @$pb.TagNumber(3)
  void clearRoundId() => $_clearField(3);
}

class CollectReceiptResponse extends $pb.GeneratedMessage {
  factory CollectReceiptResponse({
    $core.bool? found,
    Receipt? receipt,
  }) {
    final result = CollectReceiptResponse._();
    if (found != null) result.found = found;
    if (receipt != null) result.receipt = receipt;
    return result;
  }

  CollectReceiptResponse._();

  factory CollectReceiptResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CollectReceiptResponse()..mergeFromBuffer(data, registry);
  factory CollectReceiptResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CollectReceiptResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CollectReceiptResponse',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: CollectReceiptResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'found')
    ..aOM<Receipt>(2, _omitFieldNames ? '' : 'receipt',
        subBuilder: Receipt.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CollectReceiptResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CollectReceiptResponse copyWith(
          void Function(CollectReceiptResponse) updates) =>
      super.copyWith((message) => updates(message as CollectReceiptResponse))
          as CollectReceiptResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CollectReceiptResponse() / CollectReceiptResponse.new instead')
  static CollectReceiptResponse create() => CollectReceiptResponse._();
  static $pb.GeneratedMessage $_createMessage() => CollectReceiptResponse._();
  @$core.override
  CollectReceiptResponse createEmptyInstance() => CollectReceiptResponse._();
  @$core.pragma('dart2js:noInline')
  static CollectReceiptResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CollectReceiptResponse>(
          CollectReceiptResponse.$_createMessage);
  static CollectReceiptResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get found => $_getBF(0);
  @$pb.TagNumber(1)
  set found($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasFound() => $_has(0);
  @$pb.TagNumber(1)
  void clearFound() => $_clearField(1);

  @$pb.TagNumber(2)
  Receipt get receipt => $_getN(1);
  @$pb.TagNumber(2)
  set receipt(Receipt value) => $_setField(2, value);
  @$pb.TagNumber(2)
  $core.bool hasReceipt() => $_has(1);
  @$pb.TagNumber(2)
  void clearReceipt() => $_clearField(2);
  @$pb.TagNumber(2)
  Receipt ensureReceipt() => $_ensure(1);
}

class CollectAllRequest extends $pb.GeneratedMessage {
  factory CollectAllRequest({
    $core.String? user,
    $core.List<$core.int>? session,
  }) {
    final result = CollectAllRequest._();
    if (user != null) result.user = user;
    if (session != null) result.session = session;
    return result;
  }

  CollectAllRequest._();

  factory CollectAllRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CollectAllRequest()..mergeFromBuffer(data, registry);
  factory CollectAllRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CollectAllRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CollectAllRequest',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: CollectAllRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'user')
    ..a<$core.List<$core.int>>(
        2, _omitFieldNames ? '' : 'session', $pb.PbFieldType.OY)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CollectAllRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CollectAllRequest copyWith(void Function(CollectAllRequest) updates) =>
      super.copyWith((message) => updates(message as CollectAllRequest))
          as CollectAllRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use CollectAllRequest() / CollectAllRequest.new instead')
  static CollectAllRequest create() => CollectAllRequest._();
  static $pb.GeneratedMessage $_createMessage() => CollectAllRequest._();
  @$core.override
  CollectAllRequest createEmptyInstance() => CollectAllRequest._();
  @$core.pragma('dart2js:noInline')
  static CollectAllRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<CollectAllRequest>(
          CollectAllRequest.$_createMessage);
  static CollectAllRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get user => $_getSZ(0);
  @$pb.TagNumber(1)
  set user($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasUser() => $_has(0);
  @$pb.TagNumber(1)
  void clearUser() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.int> get session => $_getN(1);
  @$pb.TagNumber(2)
  set session($core.List<$core.int> value) => $_setBytes(1, value);
  @$pb.TagNumber(2)
  $core.bool hasSession() => $_has(1);
  @$pb.TagNumber(2)
  void clearSession() => $_clearField(2);
}

class CollectAllResponse extends $pb.GeneratedMessage {
  factory CollectAllResponse({
    $core.Iterable<Receipt>? receipts,
  }) {
    final result = CollectAllResponse._();
    if (receipts != null) result.receipts.addAll(receipts);
    return result;
  }

  CollectAllResponse._();

  factory CollectAllResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CollectAllResponse()..mergeFromBuffer(data, registry);
  factory CollectAllResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CollectAllResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CollectAllResponse',
      package: const $pb.PackageName(
          _omitMessageNames ? '' : 'metadatamessenger.provider.v1'),
      createEmptyInstance: CollectAllResponse.$_createMessage)
    ..pPM<Receipt>(1, _omitFieldNames ? '' : 'receipts',
        subBuilder: Receipt.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CollectAllResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CollectAllResponse copyWith(void Function(CollectAllResponse) updates) =>
      super.copyWith((message) => updates(message as CollectAllResponse))
          as CollectAllResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use CollectAllResponse() / CollectAllResponse.new instead')
  static CollectAllResponse create() => CollectAllResponse._();
  static $pb.GeneratedMessage $_createMessage() => CollectAllResponse._();
  @$core.override
  CollectAllResponse createEmptyInstance() => CollectAllResponse._();
  @$core.pragma('dart2js:noInline')
  static CollectAllResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CollectAllResponse>(
          CollectAllResponse.$_createMessage);
  static CollectAllResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<Receipt> get receipts => $_getList(0);
}

const $core.bool _omitFieldNames =
    $core.bool.fromEnvironment('protobuf.omit_field_names');
const $core.bool _omitMessageNames =
    $core.bool.fromEnvironment('protobuf.omit_message_names');

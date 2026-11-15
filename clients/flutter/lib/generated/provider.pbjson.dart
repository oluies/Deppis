// This is a generated file - do not edit.
//
// Generated from provider.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports
// ignore_for_file: unused_import

import 'dart:convert' as $convert;
import 'dart:core' as $core;
import 'dart:typed_data' as $typed_data;

@$core.Deprecated('Use signalDescriptor instead')
const Signal$json = {
  '1': 'Signal',
  '2': [
    {'1': 'label', '3': 1, '4': 1, '5': 12, '10': 'label'},
    {'1': 'bit', '3': 2, '4': 1, '5': 13, '10': 'bit'},
  ],
};

/// Descriptor for `Signal`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List signalDescriptor = $convert.base64Decode(
    'CgZTaWduYWwSFAoFbGFiZWwYASABKAxSBWxhYmVsEhAKA2JpdBgCIAEoDVIDYml0');

@$core.Deprecated('Use roundOpsDescriptor instead')
const RoundOps$json = {
  '1': 'RoundOps',
  '2': [
    {'1': 'round_id', '3': 1, '4': 1, '5': 3, '10': 'roundId'},
    {'1': 'write_token', '3': 2, '4': 1, '5': 12, '10': 'writeToken'},
    {'1': 'frame', '3': 3, '4': 1, '5': 12, '10': 'frame'},
    {
      '1': 'signal',
      '3': 4,
      '4': 1,
      '5': 11,
      '6': '.metadatamessenger.provider.v1.Signal',
      '10': 'signal'
    },
    {
      '1': 'fallback_signal',
      '3': 5,
      '4': 1,
      '5': 11,
      '6': '.metadatamessenger.provider.v1.Signal',
      '10': 'fallbackSignal'
    },
    {'1': 'read_token', '3': 6, '4': 1, '5': 12, '10': 'readToken'},
  ],
};

/// Descriptor for `RoundOps`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List roundOpsDescriptor = $convert.base64Decode(
    'CghSb3VuZE9wcxIZCghyb3VuZF9pZBgBIAEoA1IHcm91bmRJZBIfCgt3cml0ZV90b2tlbhgCIA'
    'EoDFIKd3JpdGVUb2tlbhIUCgVmcmFtZRgDIAEoDFIFZnJhbWUSPQoGc2lnbmFsGAQgASgLMiUu'
    'bWV0YWRhdGFtZXNzZW5nZXIucHJvdmlkZXIudjEuU2lnbmFsUgZzaWduYWwSTgoPZmFsbGJhY2'
    'tfc2lnbmFsGAUgASgLMiUubWV0YWRhdGFtZXNzZW5nZXIucHJvdmlkZXIudjEuU2lnbmFsUg5m'
    'YWxsYmFja1NpZ25hbBIdCgpyZWFkX3Rva2VuGAYgASgMUglyZWFkVG9rZW4=');

@$core.Deprecated('Use receiptDescriptor instead')
const Receipt$json = {
  '1': 'Receipt',
  '2': [
    {'1': 'round_id', '3': 1, '4': 1, '5': 3, '10': 'roundId'},
    {'1': 'ran_live', '3': 2, '4': 1, '5': 8, '10': 'ranLive'},
    {'1': 'write_accepted', '3': 3, '4': 1, '5': 8, '10': 'writeAccepted'},
    {
      '1': 'retrieved_present',
      '3': 4,
      '4': 1,
      '5': 8,
      '10': 'retrievedPresent'
    },
    {'1': 'retrieved', '3': 5, '4': 1, '5': 12, '10': 'retrieved'},
    {'1': 'digest', '3': 6, '4': 1, '5': 12, '10': 'digest'},
  ],
};

/// Descriptor for `Receipt`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List receiptDescriptor = $convert.base64Decode(
    'CgdSZWNlaXB0EhkKCHJvdW5kX2lkGAEgASgDUgdyb3VuZElkEhkKCHJhbl9saXZlGAIgASgIUg'
    'dyYW5MaXZlEiUKDndyaXRlX2FjY2VwdGVkGAMgASgIUg13cml0ZUFjY2VwdGVkEisKEXJldHJp'
    'ZXZlZF9wcmVzZW50GAQgASgIUhByZXRyaWV2ZWRQcmVzZW50EhwKCXJldHJpZXZlZBgFIAEoDF'
    'IJcmV0cmlldmVkEhYKBmRpZ2VzdBgGIAEoDFIGZGlnZXN0');

@$core.Deprecated('Use registerRequestDescriptor instead')
const RegisterRequest$json = {
  '1': 'RegisterRequest',
  '2': [
    {'1': 'user', '3': 1, '4': 1, '5': 9, '10': 'user'},
    {'1': 'client_label', '3': 2, '4': 1, '5': 12, '10': 'clientLabel'},
  ],
};

/// Descriptor for `RegisterRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List registerRequestDescriptor = $convert.base64Decode(
    'Cg9SZWdpc3RlclJlcXVlc3QSEgoEdXNlchgBIAEoCVIEdXNlchIhCgxjbGllbnRfbGFiZWwYAi'
    'ABKAxSC2NsaWVudExhYmVs');

@$core.Deprecated('Use registerResponseDescriptor instead')
const RegisterResponse$json = {
  '1': 'RegisterResponse',
  '2': [
    {'1': 'ok', '3': 1, '4': 1, '5': 8, '10': 'ok'},
    {'1': 'session', '3': 2, '4': 1, '5': 12, '10': 'session'},
    {'1': 'error', '3': 3, '4': 1, '5': 9, '10': 'error'},
  ],
};

/// Descriptor for `RegisterResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List registerResponseDescriptor = $convert.base64Decode(
    'ChBSZWdpc3RlclJlc3BvbnNlEg4KAm9rGAEgASgIUgJvaxIYCgdzZXNzaW9uGAIgASgMUgdzZX'
    'NzaW9uEhQKBWVycm9yGAMgASgJUgVlcnJvcg==');

@$core.Deprecated('Use uploadBundleRequestDescriptor instead')
const UploadBundleRequest$json = {
  '1': 'UploadBundleRequest',
  '2': [
    {'1': 'user', '3': 1, '4': 1, '5': 9, '10': 'user'},
    {'1': 'session', '3': 2, '4': 1, '5': 12, '10': 'session'},
    {'1': 'from_round', '3': 3, '4': 1, '5': 3, '10': 'fromRound'},
    {
      '1': 'slots',
      '3': 4,
      '4': 3,
      '5': 11,
      '6': '.metadatamessenger.provider.v1.RoundOps',
      '10': 'slots'
    },
  ],
};

/// Descriptor for `UploadBundleRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List uploadBundleRequestDescriptor = $convert.base64Decode(
    'ChNVcGxvYWRCdW5kbGVSZXF1ZXN0EhIKBHVzZXIYASABKAlSBHVzZXISGAoHc2Vzc2lvbhgCIA'
    'EoDFIHc2Vzc2lvbhIdCgpmcm9tX3JvdW5kGAMgASgDUglmcm9tUm91bmQSPQoFc2xvdHMYBCAD'
    'KAsyJy5tZXRhZGF0YW1lc3Nlbmdlci5wcm92aWRlci52MS5Sb3VuZE9wc1IFc2xvdHM=');

@$core.Deprecated('Use uploadBundleResponseDescriptor instead')
const UploadBundleResponse$json = {
  '1': 'UploadBundleResponse',
  '2': [
    {'1': 'ok', '3': 1, '4': 1, '5': 8, '10': 'ok'},
    {'1': 'error', '3': 2, '4': 1, '5': 9, '10': 'error'},
  ],
};

/// Descriptor for `UploadBundleResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List uploadBundleResponseDescriptor = $convert.base64Decode(
    'ChRVcGxvYWRCdW5kbGVSZXNwb25zZRIOCgJvaxgBIAEoCFICb2sSFAoFZXJyb3IYAiABKAlSBW'
    'Vycm9y');

@$core.Deprecated('Use getDigestRequestDescriptor instead')
const GetDigestRequest$json = {
  '1': 'GetDigestRequest',
  '2': [
    {'1': 'user', '3': 1, '4': 1, '5': 9, '10': 'user'},
    {'1': 'session', '3': 2, '4': 1, '5': 12, '10': 'session'},
    {'1': 'round_id', '3': 3, '4': 1, '5': 3, '10': 'roundId'},
  ],
};

/// Descriptor for `GetDigestRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getDigestRequestDescriptor = $convert.base64Decode(
    'ChBHZXREaWdlc3RSZXF1ZXN0EhIKBHVzZXIYASABKAlSBHVzZXISGAoHc2Vzc2lvbhgCIAEoDF'
    'IHc2Vzc2lvbhIZCghyb3VuZF9pZBgDIAEoA1IHcm91bmRJZA==');

@$core.Deprecated('Use getDigestResponseDescriptor instead')
const GetDigestResponse$json = {
  '1': 'GetDigestResponse',
  '2': [
    {'1': 'ok', '3': 1, '4': 1, '5': 8, '10': 'ok'},
    {'1': 'digest', '3': 2, '4': 1, '5': 12, '10': 'digest'},
  ],
};

/// Descriptor for `GetDigestResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getDigestResponseDescriptor = $convert.base64Decode(
    'ChFHZXREaWdlc3RSZXNwb25zZRIOCgJvaxgBIAEoCFICb2sSFgoGZGlnZXN0GAIgASgMUgZkaW'
    'dlc3Q=');

@$core.Deprecated('Use submitLiveRequestDescriptor instead')
const SubmitLiveRequest$json = {
  '1': 'SubmitLiveRequest',
  '2': [
    {'1': 'user', '3': 1, '4': 1, '5': 9, '10': 'user'},
    {'1': 'session', '3': 2, '4': 1, '5': 12, '10': 'session'},
    {
      '1': 'ops',
      '3': 3,
      '4': 1,
      '5': 11,
      '6': '.metadatamessenger.provider.v1.RoundOps',
      '10': 'ops'
    },
  ],
};

/// Descriptor for `SubmitLiveRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List submitLiveRequestDescriptor = $convert.base64Decode(
    'ChFTdWJtaXRMaXZlUmVxdWVzdBISCgR1c2VyGAEgASgJUgR1c2VyEhgKB3Nlc3Npb24YAiABKA'
    'xSB3Nlc3Npb24SOQoDb3BzGAMgASgLMicubWV0YWRhdGFtZXNzZW5nZXIucHJvdmlkZXIudjEu'
    'Um91bmRPcHNSA29wcw==');

@$core.Deprecated('Use submitLiveResponseDescriptor instead')
const SubmitLiveResponse$json = {
  '1': 'SubmitLiveResponse',
  '2': [
    {'1': 'accepted', '3': 1, '4': 1, '5': 8, '10': 'accepted'},
  ],
};

/// Descriptor for `SubmitLiveResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List submitLiveResponseDescriptor =
    $convert.base64Decode(
        'ChJTdWJtaXRMaXZlUmVzcG9uc2USGgoIYWNjZXB0ZWQYASABKAhSCGFjY2VwdGVk');

@$core.Deprecated('Use collectReceiptRequestDescriptor instead')
const CollectReceiptRequest$json = {
  '1': 'CollectReceiptRequest',
  '2': [
    {'1': 'user', '3': 1, '4': 1, '5': 9, '10': 'user'},
    {'1': 'session', '3': 2, '4': 1, '5': 12, '10': 'session'},
    {'1': 'round_id', '3': 3, '4': 1, '5': 3, '10': 'roundId'},
  ],
};

/// Descriptor for `CollectReceiptRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List collectReceiptRequestDescriptor = $convert.base64Decode(
    'ChVDb2xsZWN0UmVjZWlwdFJlcXVlc3QSEgoEdXNlchgBIAEoCVIEdXNlchIYCgdzZXNzaW9uGA'
    'IgASgMUgdzZXNzaW9uEhkKCHJvdW5kX2lkGAMgASgDUgdyb3VuZElk');

@$core.Deprecated('Use collectReceiptResponseDescriptor instead')
const CollectReceiptResponse$json = {
  '1': 'CollectReceiptResponse',
  '2': [
    {'1': 'found', '3': 1, '4': 1, '5': 8, '10': 'found'},
    {
      '1': 'receipt',
      '3': 2,
      '4': 1,
      '5': 11,
      '6': '.metadatamessenger.provider.v1.Receipt',
      '10': 'receipt'
    },
  ],
};

/// Descriptor for `CollectReceiptResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List collectReceiptResponseDescriptor = $convert.base64Decode(
    'ChZDb2xsZWN0UmVjZWlwdFJlc3BvbnNlEhQKBWZvdW5kGAEgASgIUgVmb3VuZBJACgdyZWNlaX'
    'B0GAIgASgLMiYubWV0YWRhdGFtZXNzZW5nZXIucHJvdmlkZXIudjEuUmVjZWlwdFIHcmVjZWlw'
    'dA==');

@$core.Deprecated('Use collectAllRequestDescriptor instead')
const CollectAllRequest$json = {
  '1': 'CollectAllRequest',
  '2': [
    {'1': 'user', '3': 1, '4': 1, '5': 9, '10': 'user'},
    {'1': 'session', '3': 2, '4': 1, '5': 12, '10': 'session'},
  ],
};

/// Descriptor for `CollectAllRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List collectAllRequestDescriptor = $convert.base64Decode(
    'ChFDb2xsZWN0QWxsUmVxdWVzdBISCgR1c2VyGAEgASgJUgR1c2VyEhgKB3Nlc3Npb24YAiABKA'
    'xSB3Nlc3Npb24=');

@$core.Deprecated('Use collectAllResponseDescriptor instead')
const CollectAllResponse$json = {
  '1': 'CollectAllResponse',
  '2': [
    {
      '1': 'receipts',
      '3': 1,
      '4': 3,
      '5': 11,
      '6': '.metadatamessenger.provider.v1.Receipt',
      '10': 'receipts'
    },
  ],
};

/// Descriptor for `CollectAllResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List collectAllResponseDescriptor = $convert.base64Decode(
    'ChJDb2xsZWN0QWxsUmVzcG9uc2USQgoIcmVjZWlwdHMYASADKAsyJi5tZXRhZGF0YW1lc3Nlbm'
    'dlci5wcm92aWRlci52MS5SZWNlaXB0UghyZWNlaXB0cw==');

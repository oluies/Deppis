import 'dart:async';

import 'protocol_engine.dart';

/// In-memory, UI-development stand-in for the real Scala.js `protocol-core`
/// engine.
///
/// **This is NOT the protocol.** Constitution VII makes `protocol-core` the
/// single source of truth and forbids re-deriving its crypto/handshake logic in
/// another language. Accordingly this stand-in:
///   * performs NO cryptography and NO real handshake;
///   * produces a **placeholder** safety number (see
///     [_devPlaceholderSafetyNumber]) that is explicitly non-cryptographic —
///     the real numeric safety number is computed inside the engine;
///   * always reports `metadataPrivate == false` with the
///     [devNoPrivacyLabel], because a dev/stub backend gives no privacy
///     (FR-016, Constitution IV).
///
/// It exists only so the UI flows (add-buddy → safety-number → confirm,
/// multi-conversation messaging) can be built and widget-tested before the
/// engine binding lands (T019).
class DevEngine implements ProtocolEngine {
  DevEngine() {
    // Emit the privacy status once so late subscribers can also read it via
    // [privacyStatus].
    scheduleMicrotask(() => _emit(PrivacyStatusChanged(privacyStatus)));
  }

  final _controller = StreamController<EngineEvent>.broadcast();
  final _pending = <String, String>{}; // pairId -> placeholder safety number
  int _seq = 0;

  void _emit(EngineEvent e) {
    if (!_controller.isClosed) _controller.add(e);
  }

  @override
  String get apiVersion => engineApiVersion;

  @override
  PrivacyStatus get privacyStatus => const PrivacyStatus(
        backend: 'dev',
        metadataPrivate: false,
        label: devNoPrivacyLabel,
      );

  @override
  Stream<EngineEvent> get events => _controller.stream;

  @override
  Future<AddBuddyResult> addBuddy({
    required String sharedSecret,
    required BuddyRole role,
  }) async {
    if (sharedSecret.trim().isEmpty) {
      // Constant message — never varies on the secret value (Constitution II).
      _emit(const EngineError('invalid_arg', 'shared secret required'));
      throw ArgumentError('shared secret required');
    }
    final pairId = 'pair-${_seq++}';
    final safety = _devPlaceholderSafetyNumber(sharedSecret);
    _pending[pairId] = safety;
    return AddBuddyResult(pairId: pairId, safetyNumber: safety);
  }

  @override
  Future<void> confirmBuddy({
    required String pairId,
    required bool matched,
  }) async {
    final safety = _pending.remove(pairId);
    if (safety == null) {
      _emit(const EngineError('unknown_pair', 'no such pairing'));
      return;
    }
    if (matched) _emit(BuddyConfirmed(pairId, safety));
    // On mismatch the pairing is simply dropped; no buddy is established.
  }

  @override
  Future<void> removeBuddy({required String pairId}) async {
    _pending.remove(pairId);
    // Real removal (FR-018) happens in the engine; nothing to leak here.
  }

  @override
  Future<void> sendMessage({
    required String pairId,
    required String plaintext,
  }) async {
    // The dev stand-in just echoes the message back as "received" on the next
    // microtask so the conversation UI can be exercised end to end.
    _emit(MessageReceived(pairId, plaintext, DateTime.now()));
  }

  @override
  Future<void> tick({required int roundId}) async {
    // "Some buddy has mail" — which buddy is intentionally not revealed.
    _emit(Notified(roundId));
  }

  @override
  Future<void> dispose() async {
    await _controller.close();
  }

  /// A **non-cryptographic** placeholder so the UI can render a stable, grouped
  /// safety number while developing. The real safety number is derived inside
  /// `protocol-core` (Constitution VII) — do not treat this as security.
  static String _devPlaceholderSafetyNumber(String secret) {
    var h = 0;
    for (final c in secret.codeUnits) {
      h = (h * 31 + c) & 0x7fffffff;
    }
    // Pad each repeat to 5 digits so 6 repeats always yield >= 30 characters,
    // regardless of how small `h` is for short secrets.
    final digits = (h.toString().padLeft(5, '0') * 6).substring(0, 30);
    final groups = <String>[];
    for (var i = 0; i < 30; i += 5) {
      groups.add(digits.substring(i, i + 5));
    }
    return groups.join(' ');
  }
}

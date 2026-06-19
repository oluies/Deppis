/// Engine bridge — the narrow, versioned API between the Flutter UI and the
/// Scala.js-compiled `protocol-core` engine.
///
/// Per `contracts/engine-api.md` (D14, Constitution VII):
///   * Dart holds **presentation state only**. All crypto and protocol state
///     live inside the engine.
///   * The engine NEVER returns key material or raw tokens to Dart.
///   * `apiVersion` is mandatory and the engine refuses on mismatch.
///   * When `privacyStatus.metadataPrivate == false`, the UI MUST display
///     `DEV, NO METADATA PRIVACY` prominently (FR-016, Constitution IV).
///
/// This file defines the interface + value types only. The concrete
/// implementations are:
///   * [DevEngine] — an in-memory UI-development stand-in (current).
///   * a future Scala.js engine binding (T019) — the real protocol/crypto.
library;

/// API version this client speaks. The engine refuses calls on mismatch.
const String engineApiVersion = '1';

/// The label the UI must show prominently while metadata privacy is OFF.
const String devNoPrivacyLabel = 'DEV, NO METADATA PRIVACY';

/// Add-friend handshake role (mirrors protocol-core `Handshake`).
enum BuddyRole { initiator, responder }

/// Drives the mandatory build/privacy label (engine → Dart `privacyStatus`).
class PrivacyStatus {
  const PrivacyStatus({
    required this.backend,
    required this.metadataPrivate,
    required this.label,
  });

  final String backend;
  final bool metadataPrivate;
  final String label;
}

/// Result of an `addBuddy` command: a pairing handle plus the human-comparable
/// safety number. The safety number is computed inside the engine — Dart only
/// displays it for out-of-band comparison.
class AddBuddyResult {
  const AddBuddyResult({required this.pairId, required this.safetyNumber});

  final String pairId;
  final String safetyNumber;
}

/// Presentation model for a buddy/conversation. Carries no key material.
class Buddy {
  const Buddy({
    required this.pairId,
    required this.displayName,
    required this.confirmed,
    this.safetyNumber,
  });

  final String pairId;
  final String displayName;
  final bool confirmed;
  final String? safetyNumber;

  Buddy copyWith({bool? confirmed, String? safetyNumber}) => Buddy(
        pairId: pairId,
        displayName: displayName,
        confirmed: confirmed ?? this.confirmed,
        safetyNumber: safetyNumber ?? this.safetyNumber,
      );
}

/// Presentation model for a decrypted message line.
class Message {
  const Message({
    required this.pairId,
    required this.plaintext,
    required this.mine,
    required this.at,
  });

  final String pairId;
  final String plaintext;
  final bool mine;
  final DateTime at;
}

/// Engine → Dart events (see `engine-api.md`). Sealed so the UI handles every
/// case explicitly.
sealed class EngineEvent {
  const EngineEvent();
}

class BuddyConfirmed extends EngineEvent {
  const BuddyConfirmed(this.pairId, this.safetyNumber);
  final String pairId;
  final String safetyNumber;
}

class MessageReceived extends EngineEvent {
  const MessageReceived(this.pairId, this.plaintext, this.receivedAt);
  final String pairId;
  final String plaintext;
  final DateTime receivedAt;
}

/// "Some buddy has mail" — which buddy is deliberately NOT exposed (FR-004).
class Notified extends EngineEvent {
  const Notified(this.roundId);
  final int roundId;
}

class PrivacyStatusChanged extends EngineEvent {
  const PrivacyStatusChanged(this.status);
  final PrivacyStatus status;
}

/// Error surfaced to the UI. MUST NOT vary on secret values (Constitution II).
class EngineError extends EngineEvent {
  const EngineError(this.code, this.message);
  final String code;
  final String message;
}

/// The protocol engine seen by the UI. The real implementation is the Scala.js
/// `protocol-core`; [DevEngine] is the in-memory stand-in.
abstract interface class ProtocolEngine {
  String get apiVersion;
  PrivacyStatus get privacyStatus;
  Stream<EngineEvent> get events;

  Future<AddBuddyResult> addBuddy({
    required String sharedSecret,
    required BuddyRole role,
  });
  Future<void> confirmBuddy({required String pairId, required bool matched});
  Future<void> removeBuddy({required String pairId});
  Future<void> sendMessage({required String pairId, required String plaintext});
  Future<void> tick({required int roundId});

  Future<void> dispose();
}

import 'package:flutter_test/flutter_test.dart';
import 'package:metadata_messenger/engine/dev_engine.dart';
import 'package:metadata_messenger/engine/protocol_engine.dart';

void main() {
  group('DevEngine', () {
    test('reports no metadata privacy with the mandatory label', () {
      final e = DevEngine();
      expect(e.privacyStatus.metadataPrivate, isFalse);
      expect(e.privacyStatus.label, devNoPrivacyLabel);
      expect(e.apiVersion, engineApiVersion);
    });

    test('addBuddy returns a pairing handle and a grouped safety number', () async {
      final e = DevEngine();
      final r = await e.addBuddy(sharedSecret: 'hunter2', role: BuddyRole.initiator);
      expect(r.pairId, isNotEmpty);
      // 6 groups of 5 digits.
      expect(r.safetyNumber.split(' ').length, 6);
      expect(r.safetyNumber.replaceAll(' ', '').length, 30);
    });

    test('safety number is deterministic for the same secret', () async {
      final e = DevEngine();
      final a = await e.addBuddy(sharedSecret: 'same', role: BuddyRole.initiator);
      final b = await e.addBuddy(sharedSecret: 'same', role: BuddyRole.initiator);
      expect(a.safetyNumber, b.safetyNumber);
      expect(a.pairId, isNot(b.pairId)); // distinct pairings
    });

    test('empty secret is rejected without leaking detail', () async {
      final e = DevEngine();
      expect(
        () => e.addBuddy(sharedSecret: '   ', role: BuddyRole.responder),
        throwsArgumentError,
      );
    });

    test('confirmBuddy(matched) emits buddyConfirmed', () async {
      final e = DevEngine();
      final r = await e.addBuddy(sharedSecret: 's', role: BuddyRole.initiator);
      final ev = e.events.firstWhere((x) => x is BuddyConfirmed);
      await e.confirmBuddy(pairId: r.pairId, matched: true);
      final confirmed = await ev as BuddyConfirmed;
      expect(confirmed.pairId, r.pairId);
      expect(confirmed.safetyNumber, r.safetyNumber);
    });

    test('confirmBuddy(rejected) establishes no buddy', () async {
      final e = DevEngine();
      final r = await e.addBuddy(sharedSecret: 's', role: BuddyRole.initiator);
      var sawConfirm = false;
      final sub = e.events.listen((x) {
        if (x is BuddyConfirmed) sawConfirm = true;
      });
      await e.confirmBuddy(pairId: r.pairId, matched: false);
      await Future<void>.delayed(Duration.zero);
      await sub.cancel();
      expect(sawConfirm, isFalse);
    });

    test('tick emits a notified event without naming a buddy', () async {
      final e = DevEngine();
      final ev = e.events.firstWhere((x) => x is Notified);
      await e.tick(roundId: 42);
      final n = await ev as Notified;
      expect(n.roundId, 42);
    });
  });
}

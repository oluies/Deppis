import 'dart:async';
import 'dart:js_interop';
import 'dart:js_interop_unsafe';

import 'package:flutter/material.dart';

import '../engine/protocol_engine.dart';
import '../provider/routing_tuning.dart';
import '../provider/routing_web.dart';

/// The LIVE BROWSER self-test (`deploy/grpc-web/run.sh --browser`): two
/// provider-routed devices in one real page — each with its own Scala.js engine,
/// `ProviderSession` and Dart gRPC-web client — talking through Envoy to the
/// provider and its store. It runs `design/offline-delegation.md`'s case:
///   1. both online: Alice → Bob is delivered;
///   2. Bob goes away, Alice queues a message and goes away too, Bob returns and
///      receives it from Alice's standing bundle while she is still away.
/// The verdict is the page title (`ROUTING-SELFTEST-OK` or
/// `ROUTING-SELFTEST-FAIL: …`), which the harness reads; progress is logged to
/// the console and shown on the page.
Future<void> runRoutingSelfTest() async {
  final log = ValueNotifier<List<String>>(const []);
  void say(String line) {
    debugPrint('[selftest] $line');
    log.value = [...log.value, line];
  }

  void verdict(String title) {
    (globalContext['document'] as JSObject)['title'] = title.toJS;
    say(title);
  }

  runApp(
    MaterialApp(
      home: Scaffold(
        body: ValueListenableBuilder(
          valueListenable: log,
          builder: (_, lines, _) =>
              ListView(children: [for (final l in lines) Text(l)]),
        ),
      ),
    ),
  );

  const url = String.fromEnvironment('PROVIDER_URL');
  const interval = int.fromEnvironment('ROUND_INTERVAL_MS', defaultValue: 2000);
  const cutoff = int.fromEnvironment('ROUND_CUTOFF_MS', defaultValue: 1200);
  final tuning = RoutingTuning(
    intervalMillis: interval,
    cutoffMillis: cutoff,
    refreshEveryRounds: 3,
    horizonRounds: 60,
    openGraceMillis: 100,
    closeGraceMillis: 100,
    submitMarginMillis: 200,
  );
  Duration rounds(int n) => Duration(milliseconds: interval * n);

  try {
    if (url.isEmpty) throw StateError('built without PROVIDER_URL');
    say('provider $url; rounds $interval ms, cutoff $cutoff ms');
    const tick = Duration(milliseconds: 100);
    final alice = routedSetup(Uri.parse(url), tuning: tuning, tick: tick);
    final bob = routedSetup(Uri.parse(url), tuning: tuning, tick: tick);

    final toBob = <String>[];
    bob.engine.events.listen((e) {
      if (e is MessageReceived) {
        toBob.add(e.plaintext);
        say('bob received "${e.plaintext}"');
      }
    });

    // Pairing, out of band: the same secret, opposite roles, each side's notify label.
    const secret = 'live-browser-selftest';
    final a = await alice.engine.addBuddy(
      sharedSecret: secret,
      role: BuddyRole.initiator,
      peerNotifyLabel: bob.notifyLabel,
    );
    final b = await bob.engine.addBuddy(
      sharedSecret: secret,
      role: BuddyRole.responder,
      peerNotifyLabel: alice.notifyLabel,
    );
    if (a.safetyNumber != b.safetyNumber) {
      throw StateError('safety numbers differ');
    }
    await alice.engine.confirmBuddy(pairId: a.pairId, matched: true);
    await bob.engine.confirmBuddy(pairId: b.pairId, matched: true);
    say('paired; safety number ${a.safetyNumber}');

    await alice.routing!.start();
    await bob.routing!.start();
    say('both registered with the provider and stepping');

    // 1) Both online.
    await alice.engine.sendMessage(
      pairId: a.pairId,
      plaintext: 'm1: hello from alice',
    );
    if (!await _waitFor(
      () => toBob.contains('m1: hello from alice'),
      rounds(15),
    )) {
      throw StateError('phase 1: m1 not delivered with both online');
    }

    // 2) Bob goes away; Alice queues m2, refreshes her bundle, and goes away too.
    bob.routing!.pause();
    say('bob went offline');
    await alice.engine.sendMessage(
      pairId: a.pairId,
      plaintext: 'm2: sent while you were away',
    );
    await Future<void>.delayed(rounds(tuning.refreshEveryRounds + 3));
    alice.routing!.pause();
    say('alice went offline too — both run from their bundles now');
    await Future<void>.delayed(rounds(3));
    if (toBob.length != 1) {
      throw StateError('phase 2: bob received while offline: $toBob');
    }
    await bob.routing!.resume();
    say('bob came back (alice is still away)');
    if (!await _waitFor(
      () => toBob.contains('m2: sent while you were away'),
      rounds(15),
    )) {
      throw StateError("phase 2: m2 not delivered from alice's bundle");
    }

    alice.routing!.dispose();
    bob.routing!.dispose();
    verdict('ROUTING-SELFTEST-OK');
  } catch (e) {
    verdict('ROUTING-SELFTEST-FAIL: $e');
  }
}

Future<bool> _waitFor(bool Function() done, Duration timeout) async {
  final end = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(end)) {
    if (done()) return true;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  return done();
}

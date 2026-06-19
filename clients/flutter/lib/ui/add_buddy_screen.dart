import 'package:flutter/material.dart';

import '../engine/protocol_engine.dart';
import '../state/app_state.dart';

/// Add-friend flow (T026): enter a shared secret + role, run the engine
/// handshake, then display the **safety number** for out-of-band comparison and
/// let the user confirm or reject the pairing.
///
/// The safety number comes from the engine; Dart never derives it.
class AddBuddyScreen extends StatefulWidget {
  const AddBuddyScreen({super.key, required this.state});

  final AppState state;

  @override
  State<AddBuddyScreen> createState() => _AddBuddyScreenState();
}

class _AddBuddyScreenState extends State<AddBuddyScreen> {
  final _name = TextEditingController();
  final _secret = TextEditingController();
  BuddyRole _role = BuddyRole.initiator;
  AddBuddyResult? _pending;
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _name.dispose();
    _secret.dispose();
    super.dispose();
  }

  Future<void> _runHandshake() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r = await widget.state.engine
          .addBuddy(sharedSecret: _secret.text, role: _role);
      setState(() => _pending = r);
    } catch (_) {
      // Engine errors never carry secret-dependent detail (Constitution II).
      setState(() => _error = 'Could not start handshake.');
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _confirm(bool matched) async {
    final p = _pending!;
    await widget.state.confirmPairing(
      pairId: p.pairId,
      displayName: _name.text.trim().isEmpty ? p.pairId : _name.text.trim(),
      safetyNumber: p.safetyNumber,
      matched: matched,
    );
    if (mounted) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Add buddy')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: _pending == null ? _entryForm() : _safetyNumberView(_pending!),
      ),
    );
  }

  Widget _entryForm() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        TextField(
          controller: _name,
          decoration: const InputDecoration(
            labelText: 'Display name (local only)',
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          key: const Key('secretField'),
          controller: _secret,
          obscureText: true,
          decoration: const InputDecoration(
            labelText: 'Shared secret (exchanged out of band)',
          ),
        ),
        const SizedBox(height: 12),
        SegmentedButton<BuddyRole>(
          segments: const [
            ButtonSegment(value: BuddyRole.initiator, label: Text('Initiator')),
            ButtonSegment(value: BuddyRole.responder, label: Text('Responder')),
          ],
          selected: {_role},
          onSelectionChanged: (s) => setState(() => _role = s.first),
        ),
        const SizedBox(height: 20),
        if (_error != null)
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: Text(_error!, style: const TextStyle(color: Colors.red)),
          ),
        FilledButton(
          key: const Key('startHandshake'),
          onPressed: _busy ? null : _runHandshake,
          child: _busy
              ? const SizedBox(
                  height: 18, width: 18, child: CircularProgressIndicator())
              : const Text('Start handshake'),
        ),
      ],
    );
  }

  Widget _safetyNumberView(AddBuddyResult r) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text(
          'Compare this safety number with your buddy over a trusted channel. '
          'Confirm only if both sides see the same digits.',
        ),
        const SizedBox(height: 20),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: SelectableText(
              r.safetyNumber,
              key: const Key('safetyNumber'),
              textAlign: TextAlign.center,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 20,
                letterSpacing: 1.5,
              ),
            ),
          ),
        ),
        const SizedBox(height: 24),
        Row(
          children: [
            Expanded(
              child: OutlinedButton(
                onPressed: () => _confirm(false),
                child: const Text("Doesn't match"),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: FilledButton(
                key: const Key('confirmMatch'),
                onPressed: () => _confirm(true),
                child: const Text('Matches — confirm'),
              ),
            ),
          ],
        ),
      ],
    );
  }
}

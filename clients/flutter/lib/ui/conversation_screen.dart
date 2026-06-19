import 'package:flutter/material.dart';

import '../engine/protocol_engine.dart';
import '../state/app_state.dart';

/// Per-buddy conversation view (T032 engine command wiring): renders the
/// decrypted message history and sends via `engine.sendMessage`.
class ConversationScreen extends StatefulWidget {
  const ConversationScreen({
    super.key,
    required this.state,
    required this.buddy,
  });

  final AppState state;
  final Buddy buddy;

  @override
  State<ConversationScreen> createState() => _ConversationScreenState();
}

class _ConversationScreenState extends State<ConversationScreen> {
  final _input = TextEditingController();

  @override
  void dispose() {
    _input.dispose();
    super.dispose();
  }

  Future<void> _send() async {
    final text = _input.text;
    _input.clear();
    await widget.state.send(widget.buddy.pairId, text);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.buddy.displayName)),
      body: Column(
        children: [
          Expanded(
            child: ListenableBuilder(
              listenable: widget.state,
              builder: (context, _) {
                final msgs = widget.state.messagesFor(widget.buddy.pairId);
                if (msgs.isEmpty) {
                  return const Center(child: Text('No messages yet'));
                }
                return ListView.builder(
                  padding: const EdgeInsets.all(12),
                  itemCount: msgs.length,
                  itemBuilder: (context, i) {
                    final m = msgs[i];
                    return Align(
                      alignment:
                          m.mine ? Alignment.centerRight : Alignment.centerLeft,
                      child: Container(
                        margin: const EdgeInsets.symmetric(vertical: 4),
                        padding: const EdgeInsets.symmetric(
                            horizontal: 12, vertical: 8),
                        decoration: BoxDecoration(
                          color: m.mine
                              ? Theme.of(context).colorScheme.primaryContainer
                              : Theme.of(context).colorScheme.surfaceContainerHighest,
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Text(m.plaintext),
                      ),
                    );
                  },
                );
              },
            ),
          ),
          SafeArea(
            top: false,
            child: Padding(
              padding: const EdgeInsets.all(8),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      key: const Key('messageInput'),
                      controller: _input,
                      decoration: const InputDecoration(
                        hintText: 'Message',
                        border: OutlineInputBorder(),
                      ),
                      onSubmitted: (_) => _send(),
                    ),
                  ),
                  IconButton(
                    key: const Key('sendButton'),
                    icon: const Icon(Icons.send),
                    onPressed: _send,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

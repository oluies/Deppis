# Metadata Messenger — Flutter client

Presentation layer for the metadata-private messenger. The UI holds **display
state only**; all cryptography and protocol state live in the engine
(`protocol-core`), reached through the narrow, versioned bridge in
`lib/engine/protocol_engine.dart` (see `specs/.../contracts/engine-api.md`,
Constitution VII).

## Status

- **`ProtocolEngine`** — the bridge interface (commands + events) the UI talks to.
- **`DevEngine`** — an in-memory, UI-development stand-in. It performs **no
  cryptography** and re-derives **no** protocol logic (Constitution VII). It
  always reports `metadataPrivate == false` and the UI shows
  **`DEV, NO METADATA PRIVACY`** prominently (FR-016, Constitution IV).
- The real engine is the Scala.js-compiled `protocol-core` (T019); it swaps in
  behind `ProtocolEngine` with no UI changes.

## Screens

- **Home** — privacy banner + multi-conversation buddy list (T036).
- **Add buddy** — shared-secret handshake → safety-number comparison →
  confirm/reject (T026).
- **Conversation** — decrypted history + send (T032 engine command wiring).

## Develop

```sh
flutter pub get
flutter analyze    # CI gate (T005)
flutter test       # widget + engine-bridge tests
flutter run -d chrome
```

# Deppis

A **metadata-private messenger** — a Signal-style chat system designed to hide not just message
*content* but communication *metadata* (who talks to whom, and when). It combines end-to-end
encryption (double ratchet) with cover traffic and an **oblivious store-and-notify** backend, so a
network observer — or the relay operator — cannot tell an active conversation from an idle client.

> ### ⚠️ Privacy status of this repository's builds
> Until the Phase C PingPong enclave store and its attestation flow are in place, **every build is
> `DEV, NO METADATA PRIVACY`** and is labeled so in code, logs, and UI (Constitution IV). The dev
> store/notify provide no access-pattern privacy. **Do not deploy a dev build as private.**

## Run the prototype

The headless prototype shows the whole path working end to end: two independent engines pair out of
band and are routed through an untrusted **service provider** ([`design/offline-delegation.md`](specs/001-metadata-private-messenger/design/offline-delegation.md)),
which alone talks to the **real Rust `obsd` sidecar**. The devices reach the provider over TLS 1.3.

```bash
scripts/run-demo.sh
```

The script builds `obsd` and runs the demo. Expected output (abbreviated):

```
== Deppis metadata-private messenger — headless demo (provider-routed) ==
provider: label="DEV, NO METADATA PRIVACY" metadataPrivate=false
devices ↔ provider: TLS 1.3 on port <port>;  provider ↔ obsd: gRPC
[alice] paired with bob — safetyNumber 92349 49678 63182 72023 82353 36590
[bob  ] paired with alice — safetyNumber 92349 49678 63182 72023 82353 36590
✓ safety numbers match → out-of-band verification succeeds
[round]   1: alice=live   bob=live    → backend saw 2 writes
[bob  ] goes offline — no warning; his standing bundle keeps his rounds going
[alice] queued: "see you at dusk" (bob is offline)
[round]   4: alice=live   bob=bundle  → backend saw 2 writes
[alice] goes offline too — now BOTH run from bundles; the backend still sees 2 writes
[round]  11: alice=bundle bob=bundle  → backend saw 2 writes
[bob  ] comes back online (alice is still away)
[bob  ] round 16: received "see you at dusk" — from alice's bundle, while she was offline
✓ delivered with BOTH ends offline at different times: "see you at dusk"
```

Every round the provider runs exactly one write and one read per user — the device's own live
operations when it is online, its precomputed standing bundle when it is not — so the backend sees
the same traffic whether a device is active, idle or offline (FR-012). The provider itself still
sees everything in the clear until the design's Phase 4 sealing lands, hence the DEV label.

**Requirements:** `cargo` (Rust) and `sbt` with **JDK 22+** (the crypto layer uses the finalized
Foreign Function & Memory API — JEP 454, GA in JDK 22 — to call libsodium). The demo prints the
`DEV, NO METADATA PRIVACY` label.

## Components

| Component | Tech | Role |
|---|---|---|
| `protocol-core` | Scala 3 (JVM + Scala.js) | Single source of truth: handshake, notification codec, retrieval-token PRF, schedule, framing, the client **engine**, and `engine.DoubleRatchet` — the **content** double ratchet |
| `crypto` | Scala 3 JVM + FFM | Wrappers over libsodium, with KATs; plus the audited `org.signal:libsignal-client` ratchet as the JVM **cross-check reference** (not the content path) |
| `server` | JVM Scala | PING/PONG/provider/attestation fronts; dev store + notify; DCAP attestation + OpenBao key release |
| `oblivious-sidecar` | Rust | Oblivious primitives + PONG store + sealed-notification aggregation (`obsd` — the real privacy core) |
| `transport` | Scala + gRPC (ScalaPB) | gRPC contracts, the client engine's `RoundTransport` over the sidecar, the service provider's TLS front + device client; the `DeppisDemo` launcher |
| `anonymity` | Scala | `AnonymityLayer` + Groove mixnet stub |
| `clients/flutter` | Flutter/Dart | Presentation only; drives the Scala.js engine |

## Build & test (dev backend — NO metadata privacy)

```bash
sbt protocolCore/test crypto/test transport/test server/test   # JVM: property tests + KATs + E2E
sbt protocolCoreJS/test                                        # Scala.js engine under Node
cargo test --manifest-path oblivious-sidecar/Cargo.toml        # Rust oblivious sidecar + invariants
```

The cross-process integration tests (`transport/test`) build and drive the real `obsd` sidecar; they
self-cancel if the `obsd` binary is absent.

## Try the library CLIs (no UI — Constitution V)

JSON in (stdin) → JSON out (stdout). Run them through sbt:

```bash
echo '{"sharedSecret":"b3V0LW9mLWJhbmQ="}' | sbt -batch "protocolCore/runMain cli.Pcore handshake-init"
echo '{"senderId":"A","receiverId":"B","counter":1}' | sbt -batch "protocolCore/runMain cli.Pcore retrieval-token"
echo '{}' | sbt -batch "crypto/runMain crypto.Mcrypto kat"     # {"pass":true,"vectors":2,...}
sbt -batch "protocolCore/runMain cli.Pstatus show"             # shows the dev privacy label
```

## Architecture & spec

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the components, the messaging scenarios (pairing,
send, notify-before-retrieval, cover traffic), the encryption layers, and the attestation flow —
with diagrams.

The full specification, plan, and task breakdown live under
[`specs/001-metadata-private-messenger/`](specs/001-metadata-private-messenger/) — start with
[`quickstart.md`](specs/001-metadata-private-messenger/quickstart.md) and `plan.md`. Non-negotiable
constraints are in [`.specify/memory/constitution.md`](.specify/memory/constitution.md): no
hand-rolled crypto, the `DEV, NO METADATA PRIVACY` labeling rule, and attestation-not-identity on
PING/PONG.

# Quickstart: Metadata-Private Messenger

> **Privacy status of this repository's builds**: until the Phase C PingPong enclave store and
> its attestation flow are in place, every build is **`DEV, NO METADATA PRIVACY`** and is
> labeled so in code, logs, and UI (Constitution IV). Do not deploy a dev build as private.

## Components

| Component | Tech | Role |
|---|---|---|
| `protocol-core` | Scala 3 (JVM + Scala.js) | Single source of truth: handshake, notification codec, retrieval-token PRF, schedule, framing |
| `crypto` | Scala 3 JVM + FFI | Wrappers over libsodium / liboqs / ratchet / OPRF + KATs |
| `server` | JVM Scala on **Pekko/Akka** | Async batched rounds; PING/PONG/provider/attestation fronts over gRPC/TLS 1.3 |
| `oblivious-sidecar` | Rust | Oblivious primitives + PONG store + sealed-notif aggregation (the real privacy core) |
| `anonymity` | Scala | `AnonymityLayer` + Groove mixnet stub (single shuffler, no DP) |
| `clients/flutter` | Flutter/Dart | Presentation only, drives the Scala.js engine |

## Build & test (dev backend — NO metadata privacy)

```bash
# protocol-core + crypto (JVM) with property tests and KATs
sbt protocolCoreJVM/test cryptoJVM/test       # ScalaCheck + FIPS/library known-answer tests

# protocol-core (Scala.js) engine bundle for the Flutter client
sbt protocolCoreJS/fullLinkJS

# oblivious sidecar (Rust) + its constant-time / oblivious-invariant self-tests
cargo test --manifest-path oblivious-sidecar/Cargo.toml
obsx selftest                                  # {constantTime:true, obliviousInvariants:true}

# server (Pekko) + gRPC integration tests (engine <-> server <-> sidecar)
sbt server/test
```

## Try the CLIs (no UI required — Constitution V)

```bash
echo '{"sharedSecret":"<oob-secret>"}'                       | pcore handshake-init
echo '{"sharedSecret":"<oob-secret>","pqRequired":true}'     | pcore handshake-init  # PQ-intent bound
echo '{"senderId":"A","receiverId":"B","counter":1}'      | pcore retrieval-token
echo '{"suite":"ml-kem-768"}'                              | mcrypto kat   # {pass:true,...}
echo '{}'                                                  | pstatus show  # shows the dev label
```

## End-to-end smoke (maps to acceptance scenarios)

1. **Add buddy** (US1/FR-001): two engines run `addBuddy`, compare `safetyNumber` out of band,
   `confirmBuddy{matched:true}` on both → both list a Confirmed buddy.
2. **Notify-without-who** (US2/FR-004): A `sendMessage` to B; B's engine emits `notified{roundId}`
   with no buddy identity; the notification server's logs do not reveal the sender.
3. **Concurrent, never blocked** (US3/FR-006): three buddies send in one round; B retrieves all
   three; replies proceed independently.
4. **Offline catch-up** (US4): B offline; A sends; B returns and retrieves.
5. **Cover traffic** (US6/FR-012): capture an active trace and an idle trace; the
   indistinguishability test reports no better-than-chance discrimination.
6. **Labeling** (FR-016): the Flutter UI shows `DEV, NO METADATA PRIVACY`; `pstatus show`
   reports `metadataPrivate:false`.

## Promoting to the real (Phase C) backend

```bash
# Switch ObliviousStore to the enclave target; client refuses the enclave key until attestation
export STORE_BACKEND=enclave-target
attest verify < attestation-result.json        # {accepted:true,enclaveKey:...} or refuse
```

Only when `attest verify` accepts (fresh nonce + measurement present in the transparency log)
does the client submit its sealed notification token and does any build report
`metadataPrivate:true`. See `research.md` (D2/D11) for the recorded trust assumptions.

# Architecture

Deppis is a **metadata-private messenger**: it hides not just message *content* but communication
*metadata* — who talks to whom, and when. This document explains the components, the messaging
scenarios, and the encryption layers, with diagrams.

> **Privacy status of dev builds.** Until the Phase C enclave store + attestation flow are live,
> every build is `DEV, NO METADATA PRIVACY` and is labeled so in code, logs, and UI (Constitution
> IV). The dev store/notify provide no access-pattern privacy. The diagrams below show the *intended*
> oblivious path; the dev backend implements the same wire protocol **without** the oblivious
> guarantees.

---

## 1. Components

`protocol-core` is the single source of truth (Constitution VII): one set of `shared/` Scala 3
sources cross-compiled to the **JVM** (servers/tests) and **Scala.js** (the client engine the Flutter
app drives). The real oblivious privacy core is the Rust **`obsd`** sidecar.

```mermaid
flowchart TB
    subgraph client["Client (per device)"]
        flutter["Flutter UI<br/><i>presentation only</i>"]
        engine["protocol-core engine<br/>(Scala.js)<br/>handshake · framing · schedule<br/>retrieval-token PRF · notify digest"]
        flutter -->|"platform channel<br/>(JSON, apiVersion)"| engine
    end

    subgraph crypto["crypto (JVM, libsodium FFM)"]
        aead["AEAD ChaCha20-Poly1305<br/>+ Blake2b KDF"]
        ratchet["libsignal double ratchet<br/><i>vetted; content E2E</i>"]
    end

    subgraph transport["transport (gRPC / TLS 1.3, ScalaPB)"]
        grt["GrpcRoundTransport"]
        store_front["EnclaveObliviousStore<br/>(PONG client)"]
        notify_front["EnclaveNotificationClient<br/>(PING client)"]
        grt --> store_front
        grt --> notify_front
    end

    subgraph sidecar["oblivious-sidecar · obsd (Rust)"]
        pong["PONG — Oblivious Store<br/>write/read by retrieval token<br/><i>single-use, oblivious access</i>"]
        ping["PING — Notification aggregation<br/>signal / fetchDigest<br/><i>sealed one-hot bits</i>"]
    end

    subgraph attest["Attestation & key release"]
        dcap["DCAP/SGX quote verify<br/>(AttestationGate)"]
        bao["OpenBao<br/>attested key release"]
    end

    engine -. uses .-> aead
    engine --> grt
    store_front -->|gRPC| pong
    notify_front -->|gRPC| ping
    dcap --> bao
    bao -.->|"enclave key<br/>(only if attested)"| sidecar

    classDef dev fill:#fff3cd,stroke:#d39e00;
    class pong,ping dev;
```

The two server roles come from the Signal-inspired **PING/PONG** split: **PONG** is the oblivious
store (where frames live, addressed by an unlinkable retrieval token); **PING** is the notification
service (tells a client "you have mail this round" without revealing the sender). `obsd` implements
both over gRPC.

---

## 2. Buddy lifecycle

Buddies are added once, out of band, and mutually authenticated by a safety-number comparison
(US1). A build enforces a **512-buddy cap** (FR-015/FR-018).

```mermaid
stateDiagram-v2
    [*] --> Pending: addBuddy(sharedSecret, role)
    Pending --> Confirmed: confirmBuddy(matched = true)
    Pending --> [*]: confirmBuddy(matched = false) — rejected
    Confirmed --> Removed: removeBuddy(pairId)
    Removed --> [*]
    note right of Confirmed
        Safety numbers are compared out of band before confirming.
        Only a Confirmed buddy can send/receive. A 512-buddy cap is enforced.
    end note
```

---

## 3. Pairing — out-of-band handshake (US1, FR-001)

Two parties exchange a shared secret out of band (QR / safety number). Each derives the **same**
`pairId`, `safetyNumber`, and per-pair key (`pairKey`) independently via keyed HMAC — no key material
crosses the wire. A tampered secret yields a different safety number and is rejected.

```mermaid
sequenceDiagram
    autonumber
    actor A as Alice (Initiator)
    actor B as Bob (Responder)
    Note over A,B: shared secret exchanged OUT OF BAND (QR, etc.)
    A->>A: Handshake.init(secret)<br/>→ pairId, safetyNumber, pairKey
    B->>B: Handshake.init(secret)<br/>→ pairId, safetyNumber, pairKey
    Note over A,B: compare safety numbers in person / over a trusted channel
    A-->>B: "my safety number is 92349 49678 …"
    B->>B: matches? confirmBuddy(matched = true)
    A->>A: matches? confirmBuddy(matched = true)
    Note over A,B: both list a Confirmed buddy sharing pairKey<br/>(mismatch ⇒ rejected, no session)
```

`pairKey` is the root from which every later secret for this conversation is derived (AEAD frame
keys and retrieval tokens) — see §7.

---

## 4. Sending a message (a round)

The engine runs in **rounds**. Each `tick(roundId)` makes exactly one send decision and one receive
decision (§6). On a send, the queued plaintext is framed to a fixed **256 bytes**, encrypted with
ChaCha20-Poly1305, and written to the oblivious store under a one-time **retrieval token**. A
PONG-side front then seals and signals the receiver's one-hot **notify bit**.

```mermaid
sequenceDiagram
    autonumber
    participant AE as Alice engine
    participant PF as PING front<br/>(notify aggregator)
    participant ST as PONG store (obsd)
    participant NT as PING notify (obsd)

    Note over AE: sendMessage(pairId, "see you at dusk") → queued
    AE->>AE: tick(r): pad to 228B inner, then<br/>wire = nonce(12) ‖ AEAD(key, inner) = 256B<br/>key = HMAC(pairKey,"aead/Initiator/Responder/0")
    AE->>AE: token = PRF(pairKey, Initiator, Responder, counter=0)
    AE->>ST: write(token, wire)
    Note over AE,ST: the store learns neither sender nor receiver
    AE->>PF: (real frame this round)
    PF->>NT: signal(r, seal(notifyKey, roundId ‖ bit ‖ Bob-label))
    Note over ST,NT: store + notify see only opaque bytes and one set bit
```

The store never learns who wrote or for whom — only an opaque token → opaque frame mapping it
serves **once**. The retrieval token is derived from `pairKey` under a domain (`"aead/"` vs the token
domain) kept **separate** from the AEAD key, so the public token can never reveal the secret key.

---

## 5. Receiving — notify before retrieval (US2/US3, FR-004)

On each `tick`, the engine first fetches the round's **notify digest** (512 one-hot bits). It reads
the store **only** for buddies whose bit is set — so it never issues a recurring read for an idle
buddy (FR-014). A retrieved frame is AEAD-decrypted and unpadded; `notified` is always emitted
*before* `messageReceived`.

```mermaid
sequenceDiagram
    autonumber
    participant BE as Bob engine
    participant NT as PING notify (obsd)
    participant ST as PONG store (obsd)
    participant UI as Bob UI

    BE->>NT: fetchDigest(r, Bob-label)
    NT-->>BE: digest (512 bits, carrier = all-zero if no mail)
    BE->>BE: for each Confirmed buddy:<br/>NotifyDigest.isSet(digest, bit(pairKey)) ?
    alt bit set for this buddy
        BE-->>UI: emit Notified(r)
        BE->>BE: token = PRF(pairKey, Initiator, Responder, recvCounter)
        BE->>ST: read(token)
        ST-->>BE: wire (256B), then single-use delete
        BE->>BE: AEAD.open(key, nonce, ct) → inner → unpad
        BE-->>UI: emit MessageReceived(pairId, "see you at dusk")
    else no bit set
        BE->>ST: read(cover token)
        Note over BE: uniform traffic (see §6) — nothing delivered this round
    end
```

A wrong or replayed token retrieves nothing (single-use, no residual retention). Fairness rotation
across simultaneously-signaled buddies prevents starvation (FR-006).

---

## 6. Cover traffic — look identical whether chatting or idle (US6, FR-012)

The metadata-privacy guarantee rests on **uniformity**: in *every* round, each client performs
**exactly one store write and one store read**, whether or not it has real traffic. A real frame and
a carrier frame are byte-indistinguishable (random-looking, same size, encrypted).

```mermaid
flowchart LR
    tick(["tick(roundId)"]) --> q{queued<br/>message?}
    q -->|yes| real["write REAL frame:<br/>AEAD(aeadKey, padded plaintext)<br/>under PRF(pairKey,…,counter++)"]
    q -->|no| carrier["write CARRIER frame:<br/>AEAD(random key, zero-padding)<br/>under PRF(coverKey,'cover',counter++)"]
    real --> readdec
    carrier --> readdec
    readdec{notify bit<br/>set?} -->|yes| rread["read buddy token<br/>→ decrypt → deliver"]
    readdec -->|no| cread["read CARRIER token<br/>PRF(coverKey,'cover-read',counter++)"]

    classDef u fill:#e7f5ff,stroke:#1c7ed6;
    class real,carrier,rread,cread u;
```

An observer of the store/notify traffic sees one write + one read of identical shape per client per
round, and cannot tell an active conversation from an idle client.

> **Honest caveat (current state).** The PING aggregation front that turns "a real frame was stored"
> into "signal the receiver's bit" is not yet a standalone process — the demo/tests play that role
> (see `transport/DeppisDemo`). The production PING/PONG front must decouple signal volume from
> real-message presence so the *notify* channel is uniform too.

---

## 7. Encryption layers & key hierarchy

Everything for a conversation descends from the out-of-band `pairKey`. Domain-separated HMAC keeps
the **public** retrieval token cryptographically independent from the **secret** AEAD key.

```mermaid
flowchart TB
    secret["shared secret — out of band"] -->|"Handshake.init / HMAC"| pk["pairKey — per buddy pair"]
    pk -->|"HMAC(pairKey, aead/from/to/counter)"| ak["AEAD frame key<br/>ChaCha20-Poly1305, 32B"]
    pk -->|"PRF(pairKey, sender, receiver, counter)"| tok["retrieval token<br/>public, non-recurrent"]
    pk -->|"PRF(pairKey, notify-bit) mod 512"| bit["notify bit — one-hot, 0..511"]

    content["plaintext message"] -->|"double ratchet (libsignal)"| ct["ratchet ciphertext<br/>forward secrecy / PCS"]
    ct -.->|"roadmap: ratchet output is the inner payload"| inner["inner = pad(payload, 228B)"]
    content -.->|"current: plaintext framed directly"| inner
    inner -->|"AEAD.seal(ak, nonce, inner)"| wire["wire frame — 256B"]

    nkey["server notify key<br/>real: enclave attested pubkey"] -->|"AEAD-seal(roundId, bit, label)"| ntok["sealed notify token"]
```

**Layer summary**

| Layer | Primitive | Key | Purpose |
|---|---|---|---|
| Pairing / X3DH | keyed HMAC (Blake2b/HMAC-SHA256) | shared secret | derive `pairId`, `safetyNumber`, `pairKey` |
| Content E2E | libsignal **double ratchet** | per-session ratchet | forward secrecy & post-compromise security *(vetted component; integration into the frame path is a tracked roadmap item — the engine currently frames plaintext directly)* |
| Frame encryption | **ChaCha20-Poly1305** (IETF) | `HMAC(pairKey,"aead/{from}/{to}/{counter}")` | confidential, authenticated, per-message frame |
| Addressing | keyed-HMAC **PRF** | `pairKey` (separate domain) | unlinkable, **non-recurrent** retrieval token |
| Notification | AEAD-sealed one-hot token | server notify key | "mail this round" with no sender identity |
| Cover traffic | random per-session `coverKey` | ephemeral | carrier frames indistinguishable from real |

No hand-rolled primitives (Constitution I): AEAD/Blake2b come from libsodium (JVM) / `@noble`
(JS), the ratchet from `org.signal:libsignal-client`.

### Wire frame layout (256 bytes, fixed — FR-015a)

```mermaid
flowchart LR
    n["nonce<br/>12 B"] --- c["AEAD ciphertext of inner — 228 B<br/>inner = len(2) ‖ payload ‖ zero-pad"] --- t["Poly1305 tag<br/>16 B"]
```

`256 = 12 (nonce) + 228 (inner plaintext) + 16 (tag)`; `inner`'s 2-byte length prefix caps the
payload at 226 bytes. Every frame — real or carrier — is exactly this shape.

---

## 8. Attestation & key provisioning (Phase C, Constitution IX)

A backend may claim metadata privacy **only** when a hardware-backed remote attestation passes and
the sealed PONG/notify key is released to the verified enclave. Attestation proves the enclave, it is
**not** an identity (attestation-not-identity): a freshness nonce is bound into the signed quote, and
the enclave key is only ever used post-attestation.

```mermaid
sequenceDiagram
    autonumber
    participant EN as Enclave (obsd, SGX)
    participant GA as AttestationGate (verifier)
    participant BAO as OpenBao (sealed store)
    participant PS as BuildPrivacyStatus

    EN->>GA: DCAP quote (mrEnclave ‖ mrSigner ‖ enclaveKey ‖ nonce, ECDSA-P256 sig)
    GA->>GA: verify signature + appraise measurement vs reference set,<br/>check freshness nonce
    alt passed AND verifier is hardware-backed
        GA->>BAO: release request (token from attested auth)
        BAO-->>EN: sealed PONG/notify key (transit-wrapped to enclave pubkey)
        GA-->>PS: ProvisionedEnclave(attested = true)
        PS-->>PS: label = "METADATA PRIVATE"
    else failed OR dev/software verifier
        GA-->>PS: attested = false
        PS-->>PS: label = "DEV, NO METADATA PRIVACY"
    end
```

The pieces that need real hardware/ops (SGX TEE + Intel collateral, OpenBao Shamir unseal, the
attestation-gated auth method, transit wrap) are gated and documented; the CI-tested code verifies
ECDSA-P256 quotes against synthetic quotes and exercises the OpenBao KV-v2 client against a mock
server.

---

## Where this lives in the tree

| Concern | Code |
|---|---|
| Engine, handshake, framing, token PRF, schedule, notify digest | `protocol-core/shared/src/main/scala/{engine,handshake,frame,token,schedule}` |
| AEAD / KDF (libsodium FFM), double ratchet | `crypto/src/main/scala/{crypto,ratchet}` |
| gRPC fronts + round transport + the runnable demo | `transport/src/main/scala/transport` |
| Oblivious store + sealed-notify aggregation | `oblivious-sidecar/src` (`obsd`) |
| Dev store/notify + DCAP + OpenBao | `server/{pong,ping}/…`, `server/src/main/scala/attestation` |
| Privacy labeling (FR-016) | `protocol-core/shared/src/main/scala/privacy` |

See [`README.md`](README.md) to run the prototype and
[`specs/001-metadata-private-messenger/`](specs/001-metadata-private-messenger/) for the full spec,
plan, and the non-negotiable [constitution](.specify/memory/constitution.md).

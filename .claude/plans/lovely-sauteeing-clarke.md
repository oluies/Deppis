# Plan: T020 Pekko/TLS server skeleton + attestation integration (T058)

## Context

Two high-value, non-parallelizable follow-ups the user asked for. Research confirmed the foundations
already exist; both are about wiring the missing seam, not green-field work:

- **T020** — the three gRPC services (`RoundServiceImpl`, `StoreServiceImpl`, `NotificationServiceImpl`
  in `transport/`) are implemented and tested **in-process only** (`InProcessServerBuilder`). There is
  **no Pekko dependency, no `server/src/main/scala/round/`, and no TLS/networked bind** anywhere. The
  gap is a real networked, TLS-1.3 server with a Pekko orchestration actor.
- **Attestation (T058)** — the whole attestation core is done and CI-tested: `DcapAttestationVerifier`
  (real ECDSA-P256, `hardwareBacked=true`), `SoftwareAttestationVerifier` (`hardwareBacked=false`),
  `AttestationGate.provision → ProvisionedEnclave(attested = verifier.hardwareBacked && passed)`, and
  the enclave fronts already take `attested: Boolean` → `Privacy.BuildPrivacyStatus(EnclaveTarget,
  attested)`. The only missing wire is **`attested` is hardcoded `false` at every front call site** —
  nothing runs the gate and flows its result into the fronts so `metadataPrivate` can become `true`.

Delivered as **two sequential PRs**, each with the roborev loop. Gated parts (real SGX quote
production, Intel PCK/TCB collateral, Veraison/RATS external verifier, live OpenBao) are documented,
never faked — same discipline as the DCAP/OpenBao PRs.

---

## PR A — T020: Pekko/Akka server skeleton + gRPC/TLS 1.3

**Approach (recommended):** `pekko-actor-typed` for orchestration + the **already-present**
`grpc-netty-shaded` for the TLS network bind (it bundles netty's TLS + `SelfSignedCertificate`). Avoid
the heavier full `pekko-grpc` codegen — the ScalaPB services already exist and just need a networked,
TLS-secured host.

Files (new, in the `server` module — which already has the per-role source dirs):
- `project/V.scala` + `build.sbt` — pin `org.apache.pekko %% pekko-actor-typed` (latest stable, Scala 3
  `_3` build); add to the `server` module deps. `server` already depends on `transport`'s services via
  `protocolCore`/`crypto`? No — the gRPC service impls live in `transport`. **Decision:** put the
  round server in `transport/src/main/scala/transport/round/` (transport already has the services +
  grpc-netty-shaded), and add `pekko-actor-typed` to `transport`. This avoids a `server → transport`
  dep inversion. (tasks.md says `server/.../round/`; note the deviation in the PR — the services it
  must bind live in `transport`.)
- `round/RoundOrchestrator.scala` — a **Pekko typed actor**: owns the dev backend (`DevObliviousStore`
  + `DevNotificationServer`), maintains a monotonic round clock (`AdvanceRound`/`CurrentRound`
  messages), and is the lifecycle supervisor + the natural seam for future per-round batching. Genuine
  orchestration skeleton, not actor-for-its-own-sake.
- `round/TlsRoundServer.scala` — builds `NettyServerBuilder.forPort(0)` with a TLS 1.3 `SslContext`
  (`GrpcSslContexts` + a dev `SelfSignedCertificate`, `.protocols("TLSv1.3")`), registers
  `RoundServiceGrpc.bindService(new RoundServiceImpl(store), …)` (+ store/notify), `start()`/`stop()`
  under the actor system. A `clientChannel(cert)` helper builds a `NettyChannelBuilder` trusting the
  self-signed cert. Honest label: self-signed = DEV; real deploy uses real certs / SPIRE (T060).

Test (new):
- `round/TlsRoundServerSpec.scala` — start the server on an ephemeral port over **real TLS 1.3**,
  connect a TLS client trusting the dev cert, do a `RoundService` `sendFrame`/`retrieve` round-trip on
  the wire (proves the networked TLS path, distinct from the existing in-process tests). Assert a
  plaintext client is rejected. Plus a small `RoundOrchestrator` actor test (round advances; backend
  wired). Use `pekko-actor-testkit-typed` (Test scope).

**Verification:** `sbt "transport/test"` (the new specs pass on JDK 26); `scalafmt --test`. The existing
in-process service tests and the obsd E2E/demo stay green.

---

## PR B — Attestation integration (T058) + `attest verify` CLI

**Approach:** add the provisioning seam that runs the gate and flows the real `attested` into the
fronts, proving `metadataPrivate:true` on a passing **hardware-backed** attestation and the dev label
otherwise — all with the existing synthetic-quote machinery (CI-safe, no hardware).

Files (new):
- `transport/src/main/scala/transport/AttestedProvisioning.scala` — `provision(verifier, quote, nonce,
  refs, storeStub, notifyStub): Either[String, AttestedFronts]` that calls `AttestationGate.provision`
  (reuse `server/.../attestation/KeyProvisioning.scala`) and constructs `EnclaveObliviousStore`/
  `EnclaveNotificationClient` with `attested = provisioned.attested` (the seam that is hardcoded `false`
  today). Returns the enclave public key + the attested fronts; on `Left`, no fronts are built (no key
  release). This is the T058 wire.
- `attest verify` CLI — extend the existing CLI pattern (`cli.Pcore`/`crypto.Mcrypto` style: pure
  `run(...): Either[String, ujson.Value]` core + thin `main`). Lives where the attestation types are
  (`server` module): `server/attestation/src/main/scala/attestation/AttestCli.scala`. Given a verifier
  choice (dcap/software) + quote fields, runs provision and emits `{attested, metadataPrivate, label,
  enclaveKey?}`. Reuses `Privacy.BuildPrivacyStatus`.

Tests (new):
- `transport/src/test/scala/transport/AttestedProvisioningSpec.scala` — with a `DcapAttestationVerifier`
  (hardware-backed) + a correctly-signed synthetic quote (reuse `DcapSpec`'s vector/keygen helpers) →
  fronts report `metadataPrivate == true` / `METADATA PRIVATE`; with `SoftwareAttestationVerifier` (or a
  bad quote) → `false` / `DEV, NO METADATA PRIVACY`. Pins the **labeling rule** end-to-end through the
  attestation gate (Constitution IV/IX).
- `server/attestation/src/test/scala/attestation/AttestCliSpec.scala` — the CLI `run` core on both paths.

**Honestly gated (documented in code + PR, NOT implemented):** real SGX quote generation, Intel
PCK-chain/TCB collateral, the external **Veraison/RATS** verifier service and the `attestation.proto`
gRPC relying-party front (T055/T056 remainder), and live OpenBao Shamir-unseal + transit-wrap. The
appraisal + ECDSA verification core they build on is already real and CI-tested.

**Verification:** `sbt "transport/test" "server/test"`; `scalafmt --test`. Confirm `metadataPrivate`
flips to `true` only on hardware-backed + passing.

---

## Cross-cutting

- Branches `feat/t020-tls-server` and `feat/attestation-integration`; one PR each, roborev loop, merge
  when CI green + roborev clean. JDK 26 locally (`export JAVA_HOME=$(/usr/libexec/java_home -v 26)`),
  scalafmt enforced.
- Constitution: no hand-rolled crypto; the `DEV, NO METADATA PRIVACY` label holds for dev/self-signed/
  software-verifier; attestation-not-identity; errors don't vary on secrets.
- Sequence: PR A (T020) first, then PR B (attestation) — independent, but this order matches the ask.

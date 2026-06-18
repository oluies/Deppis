<!--
SYNC IMPACT REPORT
==================
Version change: (template, unversioned) → 1.0.0
Bump rationale: Initial ratification of the project constitution (MAJOR baseline).

Modified principles: N/A (initial adoption)
Added sections:
  Core Principles I–XI (replacing the 5 template placeholder principles)
  - I.   No Hand-Rolled Cryptography
  - II.  Constant-Time Discipline
  - III. Metadata Disclosure Per Feature
  - IV.  Honesty About Guarantees (Labeling Rule)
  - V.   Library-First & CLI-First
  - VI.  Test-Driven (Property Tests + Known-Answer Tests)
  - VII. Single Source of Truth for Protocol Logic
  - VIII. Pluggable Trust Backends
  - IX.  Attestation, Not Identity
  - X.   Reproducible Builds & Transparency Log
  - XI.  Pinned Dependencies & No Committed Secrets
  Section: Security & Cryptography Constraints
  Section: Development Workflow & Quality Gates
  Section: Governance

Removed sections: None (template placeholders superseded)

Templates requiring updates:
  ✅ .specify/memory/constitution.md (this file)
  ✅ .specify/templates/plan-template.md (Constitution Check gates populated)
  ⚠ .specify/templates/spec-template.md (pending: add "Metadata Protected / Metadata Leaked" + labeling fields when /speckit-specify runs)
  ⚠ .specify/templates/tasks-template.md (pending: ensure KAT/property-test + labeling task categories at /speckit-tasks time)

Follow-up TODOs: None. RATIFICATION_DATE set to today (initial adoption).
-->

# Metadata-Messenger Constitution

A text messenger whose primary goal is hiding communication metadata — who talks to whom,
and when — not only message content. These principles are non-negotiable. They bind every
feature, every commit, and every reviewer. Where a principle uses MUST / MUST NOT, a
violation blocks merge; where it uses SHOULD, a deviation requires written justification in
the Complexity Tracking table of the relevant plan.

## Core Principles

### I. No Hand-Rolled Cryptography

Cryptographic primitives MUST NOT be implemented by hand. Use vetted libraries only:
libsodium / NaCl for AEAD and hashing; BoringSSL or liboqs for ML-KEM (FIPS 203) and
ML-DSA (FIPS 204); an audited OPRF library for the epoch PRF. Any code that touches a
secret MUST either call into such a library, or carry both (a) a written constant-time
argument and (b) a passing known-answer test. ML-KEM and ML-DSA MUST come from a
recognized library and never from local code. Rationale: the most expensive and dangerous
bugs in a privacy system are in primitives; we adopt corecrypto's discipline of trusting
verified, audited implementations rather than re-deriving them.

### II. Constant-Time Discipline

All secret-dependent code MUST be constant-time, following corecrypto's rules: no
secret-dependent branches, no secret-dependent memory indexing or table lookups, and no
comparison of secrets with non-constant-time equality. Logging and error messages MUST NOT
vary on secret values. Code MUST document where Data-Independent Timing (DIT) assumptions
are relied on and MUST guard against compiler transformations that could reintroduce a
timing signal. Rationale: a timing side channel leaks the very metadata this project
exists to hide.

### III. Metadata Disclosure Per Feature

Every feature MUST name, in its spec, exactly what metadata it protects and what it leaks.
A feature that does not yet provide a referenced paper's guarantee (PingPong, Groove) MUST
say so in plain words. Rationale: a privacy claim that is not written down and bounded is a
privacy claim that will silently regress.

### IV. Honesty About Guarantees (Labeling Rule) — NON-NEGOTIABLE

A build without the real oblivious store (PONG / enclave) or the real mixnet (Groove) does
NOT provide metadata privacy and MUST be labeled `DEV, NO METADATA PRIVACY` in code, in
logs, and in the UI. No dev build, stub backend, or single-shuffler path may present itself
as private — anywhere. No metadata-privacy property may be advertised until the real Phase
C backend and its attestation are in place and the trust assumptions are written down.
Rationale: a messenger that lies about its guarantees is worse than one that makes none,
because users act on the claim.

### V. Library-First & CLI-First

Each capability MUST be a standalone library with a CLI that reads text or JSON on
stdin/args and writes JSON on stdout, testable without the UI. Errors go to stderr.
Rationale: protocol and crypto logic must be exercisable and reviewable in isolation,
independent of any device or UI runtime.

### VI. Test-Driven (Property Tests + Known-Answer Tests) — NON-NEGOTIABLE

Tests are written before implementation (Red-Green-Refactor). Protocol state machines and
oblivious primitives MUST have property-based tests. ML-KEM, ML-DSA, and the AEAD MUST have
known-answer tests taken from the FIPS and library test vectors. Every crypto path MUST
ship its KATs in the same change that introduces it. Rationale: correctness of state
machines and primitives cannot be eyeballed; vectors and properties are the only durable
evidence.

### VII. Single Source of Truth for Protocol Logic

The add-friend handshake, notification encode/decode, retrieval-token derivation, the
client schedule, and message framing MUST live in one Scala module (`protocol-core`) that
cross-compiles to the JVM and to Scala.js. Clients MUST NOT re-derive this logic in another
language. Rationale: divergent reimplementations of protocol logic are how clients and
servers silently disagree and leak.

### VIII. Pluggable Trust Backends

The message store and the anonymity layer MUST each sit behind an interface with a dev
implementation and a target implementation, switchable by config. Rationale: the UX can be
built and tested over a dev backend, while the real privacy backend is developed and
swapped in without rewriting callers — and the labeling rule (IV) makes the active backend
unambiguous.

### IX. Attestation, Not Identity — NON-NEGOTIABLE

On the PING and PONG path, trust MUST derive from a verified attestation result over the
enclave, appraised against transparency-logged reference values with a freshness nonce, and
NEVER from service identity. A SPIFFE SVID, a mesh certificate, or any "which service is
this" credential MUST NOT be accepted as a substitute for enclave attestation. An enclave
public key MUST NOT be accepted before attestation. Where both exist, an enclave-workload
SVID is issued only after a passing attestation result, so the two agree rather than one
standing in for the other. Rationale: attestation answers "is this genuine enclave running
reviewed code X"; identity answers "which process is this" — only the former protects the
privacy guarantee.

### X. Reproducible Builds & Transparency Log

The enclave MUST be built reproducibly and its measurement published to an append-only
transparency log as RATS reference values (CoRIM). Clients MUST accept only measurements
present in that log, and the appraisal policy MUST pin those values. Rationale: a quote
proves the running measurement, not that the measurement is honest reviewed code; the
transparency log closes that gap, and without it trust merely moves to whoever controls the
allowlist.

### XI. Pinned Dependencies & No Committed Secrets

Dependencies MUST be pinned. Builds MUST be reproducible. Secrets MUST NOT be committed.
Rationale: supply-chain integrity and reproducibility are preconditions for every claim
above; a floating dependency or a leaked key voids them.

## Security & Cryptography Constraints

- **Content cryptography**: a vetted AEAD + KDF stack (ChaCha20-Poly1305, Blake2b) and a
  Signal-style double ratchet for forward secrecy on content. Wrap an audited ratchet; do
  not write one from scratch. The keyed PRF for retrieval tokens uses Blake2b or HMAC.
- **Post-quantum**: ML-KEM (FIPS 203) for key establishment and ML-DSA (FIPS 204) for
  signatures and key-transparency records, via liboqs / BoringSSL / corecrypto bindings.
  Key agreement runs as a hybrid of X25519 and ML-KEM, so a break in either alone is not
  fatal.
- **Forward secrecy across epochs**: per-buddy and multi-device keys evolve once per epoch
  via a verifiable OPRF against the servers. Keys MUST NOT outlive their epoch; evolved keys
  MUST be erased; no path may roll an old key forward past the allowed window.
- **Oblivious-access invariants**: in the store and notification code, every access pattern
  MUST depend only on public batch sizes, never on data content. Retrieval tokens are
  non-recurrent — a token MUST NOT be reused for two different messages.
- **Cover traffic**: client send and fetch timing and volume MUST NOT depend on whether a
  real message exists.
- **Notification token direction**: the sealed notification token is generated by the
  receiver and given to the sender at add-friend time, so a sender can only flip its own bit
  and cannot flood or impersonate. This direction MUST be preserved.
- **Threat-model honesty**: each phase's README states the trust assumptions and the leaked
  metadata. Residual assumptions (uncompromised enclave; rollback, power, and
  transient-execution attacks out of scope unless mitigated; single TEE vendor unless
  heterogeneous TEEs are added; a trusted verifier and reference-value log) MUST be recorded.

## Development Workflow & Quality Gates

- **Phasing**: privacy claims are gated by phase. Phase A (content-encrypted messenger,
  buddy handshake, client schedule, cover traffic, dev store, no-privacy label). Phase B
  (PING notification subsystem over the dev store; concurrent-conversation UX). Phase C
  (real oblivious store / mixnet sidecar, attestation flow, written trust assumptions;
  SPIRE mesh identity may land alongside). Phase D (post-quantum hybrid, epoch forward
  secrecy, multi-device delegation, threshold enclave key).
- **Dependency order**: `protocol-core` before server before clients; the dev store before
  the native sidecar.
- **Review**: every commit is reviewed (roborev `security` + `architecture`) against the
  rules in `.roborev.toml`. Commit in small units so review runs against fresh context.
- **Pre-implementation gate**: `/speckit-analyze` MUST pass — every constitution violation
  or coverage gap it reports MUST be fixed, especially the labeling rule (IV) and the
  crypto-library rule (I) — before `/speckit-implement`.
- **Crypto-task gate**: SHOULD run a threat-model / crypto-misuse checklist
  (`/speckit-checklist`) before implementing each crypto task.

## Governance

This constitution supersedes all other development practices for this project. All plans,
specs, tasks, reviews, and PRs MUST verify compliance with it; any reviewer MUST block a
change that violates a MUST principle. Complexity or deviation from a SHOULD MUST be
justified in the Complexity Tracking table of the governing plan, with the simpler
alternative and why it was rejected.

Amendments require: a written proposal describing the change and its rationale, approval,
and a migration note for any artifact (templates, specs, code) the change affects. Versioning
of this constitution follows semantic versioning: MAJOR for backward-incompatible
governance or principle removals/redefinitions, MINOR for a new principle or materially
expanded guidance, PATCH for clarifications and non-semantic refinements. On every
amendment, propagate changes to `.specify/templates/plan-template.md`,
`.specify/templates/spec-template.md`, and `.specify/templates/tasks-template.md`, and
record a Sync Impact Report at the top of this file.

**Version**: 1.0.0 | **Ratified**: 2026-06-18 | **Last Amended**: 2026-06-18

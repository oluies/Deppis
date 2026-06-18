# Implementation Plan: [FEATURE]

**Branch**: `[###-feature-name]` | **Date**: [DATE] | **Spec**: [link]

**Input**: Feature specification from `/specs/[###-feature-name]/spec.md`

**Note**: This template is filled in by the `/speckit-plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

[Extract from feature spec: primary requirement + technical approach from research]

## Technical Context

<!--
  ACTION REQUIRED: Replace the content in this section with the technical details
  for the project. The structure here is presented in advisory capacity to guide
  the iteration process.
-->

**Language/Version**: [e.g., Python 3.11, Swift 5.9, Rust 1.75 or NEEDS CLARIFICATION]

**Primary Dependencies**: [e.g., FastAPI, UIKit, LLVM or NEEDS CLARIFICATION]

**Storage**: [if applicable, e.g., PostgreSQL, CoreData, files or N/A]

**Testing**: [e.g., pytest, XCTest, cargo test or NEEDS CLARIFICATION]

**Target Platform**: [e.g., Linux server, iOS 15+, WASM or NEEDS CLARIFICATION]

**Project Type**: [e.g., library/cli/web-service/mobile-app/compiler/desktop-app or NEEDS CLARIFICATION]

**Performance Goals**: [domain-specific, e.g., 1000 req/s, 10k lines/sec, 60 fps or NEEDS CLARIFICATION]

**Constraints**: [domain-specific, e.g., <200ms p95, <100MB memory, offline-capable or NEEDS CLARIFICATION]

**Scale/Scope**: [domain-specific, e.g., 10k users, 1M LOC, 50 screens or NEEDS CLARIFICATION]

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Gates derived from the constitution (`.specify/memory/constitution.md`, v1.0.0). Each item
is PASS / FAIL / N/A with a one-line justification. A FAIL on a NON-NEGOTIABLE gate blocks
the plan; any other FAIL requires an entry in Complexity Tracking.

- [ ] **I. No hand-rolled crypto**: every AEAD / KEM / signature / hash / PRF used is named
  and sourced from a vetted library (libsodium, BoringSSL/liboqs, audited OPRF/ratchet). Any
  secret-touching code without a library call carries a constant-time argument + KAT.
- [ ] **II. Constant-time discipline**: no secret-dependent branch, index, or non-CT compare;
  DIT assumptions documented.
- [ ] **III. Metadata disclosure**: the plan states exactly what metadata each feature
  protects and what it leaks; gaps vs. PingPong/Groove guarantees are stated plainly.
- [ ] **IV. Labeling rule (NON-NEGOTIABLE)**: any dev-store / stub / single-shuffler path
  surfaces `DEV, NO METADATA PRIVACY` in code, logs, and UI; no privacy is advertised before
  Phase C + attestation are real.
- [ ] **V. Library-first & CLI-first**: each capability is a standalone library with a
  JSON/text stdin→stdout CLI, testable without the UI.
- [ ] **VI. Test-driven (NON-NEGOTIABLE)**: property tests for protocol state machines and
  oblivious primitives; FIPS/library KATs for ML-KEM, ML-DSA, AEAD, shipped with each crypto
  path.
- [ ] **VII. Single source of truth**: handshake, notification codec, retrieval-token
  derivation, schedule, and framing live only in `protocol-core`; no client re-derivation.
- [ ] **VIII. Pluggable trust backends**: store and anonymity layer sit behind interfaces
  with dev + target implementations switchable by config.
- [ ] **IX. Attestation, not identity (NON-NEGOTIABLE)**: PING/PONG trust derives only from a
  verified attestation result (freshness nonce, reference-value appraisal); no SVID / mesh
  cert substitutes; enclave key never accepted before attestation.
- [ ] **X. Reproducible builds & transparency log**: enclave measurement is reproducible and
  pinned to an append-only CoRIM reference-value log; clients accept only logged measurements.
- [ ] **XI. Pinned deps & no secrets**: dependencies pinned, builds reproducible, no secrets
  committed.
- [ ] **Security constraints**: oblivious access depends only on public batch sizes; tokens
  non-recurrent; cover traffic independent of real-message presence; epoch keys erased and
  non-roll-forward; receiver-generated notification tokens.

## Project Structure

### Documentation (this feature)

```text
specs/[###-feature]/
├── plan.md              # This file (/speckit-plan command output)
├── research.md          # Phase 0 output (/speckit-plan command)
├── data-model.md        # Phase 1 output (/speckit-plan command)
├── quickstart.md        # Phase 1 output (/speckit-plan command)
├── contracts/           # Phase 1 output (/speckit-plan command)
└── tasks.md             # Phase 2 output (/speckit-tasks command - NOT created by /speckit-plan)
```

### Source Code (repository root)
<!--
  ACTION REQUIRED: Replace the placeholder tree below with the concrete layout
  for this feature. Delete unused options and expand the chosen structure with
  real paths (e.g., apps/admin, packages/something). The delivered plan must
  not include Option labels.
-->

```text
# [REMOVE IF UNUSED] Option 1: Single project (DEFAULT)
src/
├── models/
├── services/
├── cli/
└── lib/

tests/
├── contract/
├── integration/
└── unit/

# [REMOVE IF UNUSED] Option 2: Web application (when "frontend" + "backend" detected)
backend/
├── src/
│   ├── models/
│   ├── services/
│   └── api/
└── tests/

frontend/
├── src/
│   ├── components/
│   ├── pages/
│   └── services/
└── tests/

# [REMOVE IF UNUSED] Option 3: Mobile + API (when "iOS/Android" detected)
api/
└── [same as backend above]

ios/ or android/
└── [platform-specific structure: feature modules, UI flows, platform tests]
```

**Structure Decision**: [Document the selected structure and reference the real
directories captured above]

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |

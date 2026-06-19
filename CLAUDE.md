<!-- SPECKIT START -->
For additional context about technologies to be used, project structure,
shell commands, and other important information, read the current plan:
`specs/001-metadata-private-messenger/plan.md`

Active feature: **Metadata-Private Messenger** (`specs/001-metadata-private-messenger/`).
Constitution: `.specify/memory/constitution.md` (v1.0.0) — non-negotiable; honor the labeling
rule (no dev build claims privacy), no hand-rolled crypto, attestation-not-identity on PING/PONG.
Stack: Scala 3 `protocol-core` (JVM + Scala.js) as single source of truth; JVM servers on
Pekko/Akka over gRPC/TLS; Rust oblivious sidecar (PONG/PING); Flutter client (presentation only).
First real backend: PingPong enclave; real metadata privacy is in MVP scope (gated on Phase C).
<!-- SPECKIT END -->

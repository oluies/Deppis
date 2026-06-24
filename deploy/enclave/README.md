# Reproducible enclave build + transparency log (T057)

This is the trust root for the metadata-privacy claim (Constitution IX/X). The chain is:

```
reproducible enclave build  ──►  deterministic measurement (mrEnclave / mrSigner)
        │                                   │
        │ (toolchain/hardware-gated)        │ append + publish
        ▼                                   ▼
   the binary that runs            append-only TRANSPARENCY LOG  ──►  pinned checkpoint root
   inside the SGX enclave          (attestation.ReferenceLog over            │
                                    attestation.TransparencyLog, RFC 6962)   │ relying party pins
                                                                             ▼
   attestation verifier appraises the quote's measurement against the logged reference set,
   accepting the enclave key ONLY if the measurement is logged + inclusion-proven (T056/T058).
```

So a deployment may claim `METADATA PRIVATE` only for code whose measurement is **publicly, append-only
logged** — the operator cannot quietly trust un-reviewed code, and history cannot be rewritten.

## What is implemented and tested (software)

The **publish-and-prove** half — `server/.../attestation/`:

- `TransparencyLog` — RFC 6962 Merkle log over JCA SHA-256 (domain-separated `0x00`/`0x01` hashing):
  Merkle root, **inclusion proofs** ("measurement X is logged under root R") and **consistency proofs**
  ("the size-`n` log is an append-only extension of the size-`m` log"). Prover + verifier, the verifier
  reconstructing roots from proofs alone. `TransparencyLogSpec` round-trips every tree size 1..16 and
  every position and rejects every forgery (tampered leaf/proof/root/index, rewritten history).
- `ReferenceLog` — the append-only log of `Measurement`s; derives the verifier's `ReferenceValues` ONLY
  from logged entries, and `ReferenceLogTrust.trusts(...)` accepts a measurement only with an inclusion
  proof to the **pinned** root. `ReferenceLogSpec`: logged ⇒ trusted, unlogged ⇒ not, wrong root ⇒ not.

Run: `sbt "server/testOnly attestation.TransparencyLogSpec attestation.ReferenceLogSpec"`.

## What is toolchain/hardware-gated (NOT exercisable here)

Producing the measurement that gets logged — the **reproducible build** itself — needs the SGX SDK and,
to verify the result, SGX hardware. It is documented here, not run in CI:

1. **Deterministic build.** Pin the toolchain (compiler, SGX SDK, linker) by digest; build inside a
   pinned container; set `SOURCE_DATE_EPOCH`, strip non-deterministic timestamps/paths
   (`-ffile-prefix-map`), disable parallel-link nondeterminism, and produce `enclave.signed.so`.
   Two independent builds of the same source MUST yield byte-identical output (verify by diffing the
   `mrEnclave` from `sgx_sign dump`).
2. **Extract the measurement.** `sgx_sign dump -enclave enclave.signed.so -dumpfile m.txt` →
   `mrEnclave` (the SHA-256 measurement of code+data pages) and `mrSigner` (the signer key hash).
3. **Publish.** Append `Measurement(mrEnclave, mrSigner)` to the `ReferenceLog`, publish the new root as
   a signed **checkpoint** to the public append-only log (e.g. a Sigstore/Rekor- or Trillian-backed
   transparency service), and record the consistency proof from the previous checkpoint.
4. **Pin.** Relying parties (clients) pin a checkpoint root out of band; thereafter a measurement is
   trusted only via an inclusion proof to a pinned root — the mechanism `ReferenceLogTrust.trusts`
   implements and tests. NOTE: wiring this pinned-root inclusion check INTO the attestation appraisal
   path (so the verifier consults a pinned root rather than the full live log) is part of the
   still-open T056/T058 live-attestation integration; today the verifier appraises against the
   logged reference set without the pinned-root gate.

Until steps 1–4 run on real hardware with a real SGX toolchain, no build advertises privacy: the label
stays `DEV, NO METADATA PRIVACY` (Constitution IV). This directory + the tested log mechanism are the
honest, reviewable scaffolding that a real attested deployment slots into.

## CoRIM note

In production the reference values are carried as CoRIM (Concise Reference Integrity Manifest, CBOR)
records rather than the raw length-prefixed `Measurement` encoding used here; the transparency-log
mechanism (leaves, inclusion/consistency proofs, pinned checkpoints) is identical regardless of the
leaf encoding. A CBOR/CoRIM codec is a vetted-library concern, deliberately out of scope of this slice.

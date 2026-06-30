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

Run: `sbt "server/testOnly attestation.TransparencyLogSpec attestation.ReferenceLogSpec attestation.ReproducibleMeasurementSpec"`
(the last drives the **real** reproducible `MRENCLAVE` from `deploy/enclave/` through this trust chain).

## Reproducible build + measurement — Docker + Gramine SGX-sim (DONE, no hardware)

The reproducible-build → deterministic-measurement half of the chain is now exercisable **with Docker
alone, no SGX hardware** (`gramine-sgx-sign` computes `MRENCLAVE` on any machine; only *running* the
enclave needs SGX). Files in this directory:

- `Dockerfile` — two stages, each with an internal reproducibility gate that **fails the build** unless
  the result is deterministic:
  1. **Reproducible obsd.** Builds the `obsd` sidecar as a fully **static (musl) PIE** with pinned
     toolchain (`rust:1.88.0-bookworm`, digest-pinnable), `--locked` deps, `SOURCE_DATE_EPOCH`,
     `-C codegen-units=1` (kills parallel-codegen ordering nondeterminism), `-C debuginfo=0`, and
     `--remap-path-prefix`. It builds **twice** in an identical path and aborts unless the two stripped
     binaries are byte-identical.
  2. **Reproducible measurement.** Generates the Gramine manifest (`obsd.manifest.template`) for that
     binary and signs it **twice**, aborting unless both signings yield the same `MRENCLAVE`. Static
     linking makes the application TCB exactly one trusted file, so `MRENCLAVE` is a clean function of
     `(obsd bytes ‖ manifest ‖ pinned Gramine loader)`.
- `obsd.manifest.template` — the Gramine manifest (entrypoint `/obsd`, single trusted file).
- `reproduce.sh` — host runner: `./reproduce.sh` prints the measurement; `./reproduce.sh --twice` does a
  second from-scratch image build and diffs the exported `MRENCLAVE` for cross-invocation determinism.
- `measurement.txt` — the recorded reproducible values from a reference run (the obsd sha256 + the
  `MRENCLAVE`). `attestation.ReproducibleMeasurementSpec` pins this `MRENCLAVE` and drives it through the
  `ReferenceLog` publish → inclusion-proof → pinned-root trust chain end to end.

Run: `docker build -f deploy/enclave/Dockerfile -o type=local,dest=out .` (or `./reproduce.sh`). On an
arm64 host the amd64 image runs under emulation (slower); on a native x86 CI runner it is fast.

## What is still hardware/collateral-gated

1. **A genuine SGX-signed enclave.** The build above signs with a **throwaway dev key**, not a
   PCK-endorsed platform key, so `MRSIGNER` is a dev value and `hardwareBacked = false`. A real
   `enclave.signed.so` measured + quoted by genuine SGX hardware (and verifying the quote) needs SGX.
   `MRENCLAVE` is key-independent and reproducible here; full `(mrEnclave, mrSigner)` reproducibility
   additionally requires pinning the signing key — the operator's PCK-endorsed signer in production.
2. **Publish.** Append `Measurement(mrEnclave, mrSigner)` to the `ReferenceLog`, publish the new root as
   a signed **checkpoint** to a public append-only log (e.g. a Sigstore/Rekor- or Trillian-backed
   transparency service), and record the consistency proof from the previous checkpoint.
3. **Pin.** Relying parties pin a checkpoint root out of band; thereafter a measurement is trusted only
   via an inclusion proof to that pinned root — the mechanism `ReferenceLogTrust.trusts` implements and
   `ReproducibleMeasurementSpec` exercises with the real produced `MRENCLAVE`. Wiring this pinned-root
   inclusion check INTO the attestation appraisal path (so the verifier consults a pinned root rather
   than the full live log) is part of the still-open T056/T058 live-attestation integration.

Until a measurement is produced on real SGX with a PCK-endorsed key AND published to the public log, no
build advertises privacy: the label stays `DEV, NO METADATA PRIVACY` (Constitution IV). This directory
+ the tested log mechanism are the honest, reviewable scaffolding a real attested deployment slots into.

## CoRIM note

In production the reference values are carried as CoRIM (Concise Reference Integrity Manifest, CBOR)
records rather than the raw length-prefixed `Measurement` encoding used here; the transparency-log
mechanism (leaves, inclusion/consistency proofs, pinned checkpoints) is identical regardless of the
leaf encoding. A CBOR/CoRIM codec is a vetted-library concern, deliberately out of scope of this slice.

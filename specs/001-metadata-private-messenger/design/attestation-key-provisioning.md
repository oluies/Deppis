# Design: Attestation-Gated Key Provisioning (OpenBao + Shamir)

**Status**: design (verifier + gate implemented in `server/.../attestation/`; DCAP signature
verification and the live OpenBao deployment are TEE-/ops-gated)
**Governs**: Constitution **IX** (Attestation, Not Identity), **X** (Reproducible Builds &
Transparency Log), **XI** (Pinned Deps & No Committed Secrets); research **D11** (key custody),
**D16** (round-bound sealed tokens).

## Problem

The PONG/notify path uses a long-term symmetric key (`OBSD_NOTIFY_KEY` today) that seals retrieval
tokens (round-bound, D16) and is opened inside the oblivious sidecar. Two questions must be
answered without trusting the orchestrator, the mesh, or "which service is this":

1. **Custody** — where does that key live at rest, and who can unseal it?
2. **Release** — how does the key reach a *genuine* enclave running *reviewed* code, and nothing
   else?

Constitution IX is categorical: trust derives from a **verified attestation result**, appraised
against **transparency-logged reference values** with a **freshness nonce**, and **never** from a
SPIFFE SVID or mesh certificate. An enclave public key MUST NOT be accepted before attestation.

## Components

| Component | Role |
|---|---|
| **OpenBao** | Sealed secret store holding the root/transit key. Its storage barrier is encrypted; the unseal key is **never** stored with it. |
| **Shamir's Secret Sharing** | The OpenBao unseal key is split into *N* shares with threshold *M*. Boot requires *M* operators (or auto-unseal HSM) — no single party holds the barrier key (Constitution XI: no committed secrets). |
| **OpenBao Transit / wrapping** | Releases the PONG/notify key **wrapped to the enclave's attested ephemeral public key**, so it is never in plaintext outside the enclave. |
| **Attestation verifier** (`server/.../attestation/`) | Appraises the enclave's DCAP quote: freshness nonce, signature, measurement vs reference set; releases the bound key only on pass. |
| **Transparency log** (Constitution X) | Publishes the reviewed reference measurements (`mrEnclave`/`mrSigner`) the verifier appraises against. |

## Flow

```
                 ┌──────── fresh nonce  (per attempt, never reused) ────────┐
                 ▼                                                          │
  Enclave (SGX) ── DCAP quote {measurement, ephemeral pubkey, nonce}sig ──► Verifier (Scala)
  oblivious-sidecar                                                          │  appraise:
                 ▲                                                           │   1. nonce == expected   (replay)
                 │                                                           │   2. quote signature     (DCAP, TEE-gated)
                 │                                                           │   3. measurement ∈ ref set (transparency log)
                 │                                                           │   4. ephemeral pubkey present
                 │                                                           ▼
                 │                                                      AttestationGate.provision
                 │                                                           │ Passed + hardwareBacked
                 │                                                           ▼
                 │                                          OpenBao: unwrap notify key, re-wrap
                 └──────────── key wrapped to enclave pubkey ◄───────────────  to attested pubkey
```

Only after a **Passed, hardware-backed** result does OpenBao release the key — and even then only
**wrapped to the attested ephemeral public key**, so plaintext key material never exists outside
the enclave (Constitution IX: "no enclave public key before attestation"; the converse — no key to
the holder of an unattested public key — also holds).

## Code mapping

The security-critical appraisal + gate are implemented and unit-tested today:

- `Quote{measurement, enclavePublicKey, nonce, signature}` — evidence; the signed body binds the
  ephemeral key and the freshness nonce (SGX report-data), defeating replay and key substitution.
- `ReferenceValues{allowedMrEnclave, allowedMrSigner}` — the transparency-logged reference set.
- `AttestationVerifier.verify` — fixed-order checks, fixed public failure reasons (Constitution II),
  constant-time nonce compare (Constitution III).
- `AttestationGate.provision` → `ProvisionedEnclave{enclavePublicKey, attested}`. `attested` is the
  exact boolean the enclave-target fronts (`EnclaveNotificationClient`, `EnclaveObliviousStore`)
  feed to `Privacy.BuildPrivacyStatus`. A backend is `attested` **only** when a *hardware-backed*
  verifier vouched for a passing quote.
- `SoftwareAttestationVerifier` — dev: runs the real appraisal but **does not** verify the DCAP
  signature; `hardwareBacked = false`, so a dev build keeps `DEV, NO METADATA PRIVACY` even when
  the appraisal passes (Constitution IV). `DcapAttestationVerifier` is the production hook
  (`hardwareBacked = true`), left abstract until a TEE is available.

## What is real vs. gated

- **Real & tested now**: freshness-nonce binding/replay rejection, measurement appraisal against
  reference values, key release on pass, and the privacy-gating rule (dev never claims privacy).
- **TEE-gated**: DCAP quote-signature verification (PCK chain, TCB/QE-identity appraisal) — needs
  SGX hardware + Intel collateral. Implement in `DcapAttestationVerifier.signatureValid`.
- **Ops-gated**: live OpenBao with Shamir unseal (or HSM auto-unseal) and a Transit wrap path; the
  transparency log that publishes reviewed reference measurements (Constitution X).

## Threat model notes

- **Replay** — a captured quote is bound to a one-time `nonce`; a fresh nonce per attempt makes
  replay fail at check 1.
- **Key substitution** — the ephemeral pubkey is inside the signed quote body; an attacker cannot
  swap in their own key without invalidating the signature (check 2).
- **Fake/old code** — only measurements in the transparency-logged reference set pass (check 3);
  TCB rollback is rejected by DCAP TCB appraisal once `signatureValid` is implemented.
- **Identity spoofing** — irrelevant by construction: the verifier never consults service identity
  (Constitution IX). An SVID may be *issued* to the workload only **after** a passing result, so
  identity follows attestation rather than substituting for it.
- **Custody compromise** — the barrier key is never stored with OpenBao; unseal needs *M-of-N*
  Shamir shares, so a single stolen disk or operator does not yield the key (Constitution XI).
```

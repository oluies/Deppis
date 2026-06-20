# Design: DCAP / SGX Attestation — what is built vs. TEE-gated

**Status**: cryptographic core built + CI-tested (synthetic quotes); the Intel quote-binary parse +
PKI/TCB appraisal is **TEE-/collateral-gated** (needs SGX hardware + Intel PCS). Constitution **IX**
(attestation, not identity); relates to [attestation-key-provisioning.md](./attestation-key-provisioning.md).

## What a DCAP quote proves

An Intel SGX **ECDSA DCAP quote (v3)** asserts: "enclave with measurement `mrEnclave`/`mrSigner`,
running on a genuine, up-to-date SGX platform, produced this report-data" — where the report-data
binds the enclave's ephemeral key and the verifier's freshness nonce. Trust chains:

```
quote body (measurement ‖ report-data)
   └─ ECDSA-P256 signed by  ── platform Attestation Key (AK)
                                  └─ endorsed by ── PCK leaf cert
                                                      └─ PCK chain ── Intel SGX Root CA
   + TCB appraisal: TCBInfo + QEIdentity (Intel PCS) say the platform/QE are at an acceptable TCB level
```

## Built + CI-tested (`server/.../attestation/Dcap.scala`)

The **load-bearing cryptographic step** — verify the quote signature over the binding:

- `Dcap.quoteBody(quote)` — the deterministic, length-prefixed encoding the AK signs
  (`mrEnclave ‖ mrSigner ‖ enclaveKey ‖ nonce`). Changing any field changes the body (tested), so
  the signature binds exactly the measurement, the key, and the nonce — defeating replay and key
  substitution.
- `Dcap.ecdsaVerify` — `SHA256withECDSA` over an X.509 EC public key (JCA, vetted — Constitution I).
- `DcapAttestationVerifier(attestationKeyDer)` — `hardwareBacked = true`, so a passing appraisal
  yields `attested = true` through the existing `AttestationGate`; composes with the
  `AppraisingVerifier` nonce/measurement/key checks (signature verified first).
- `DcapSpec` proves it with **synthetic** quotes: a real P-256 keypair signs `quoteBody`; correct
  signature passes (and the gate releases the key), while a wrong key, a tampered measurement, a
  swapped enclave key, or a garbage key are all rejected — never thrown.

## TEE-/collateral-gated (the remainder)

These need an SGX TEE producing real quotes and the Intel Provisioning Certification Service (PCS)
collateral, so they are not in CI:

1. **Quote-binary parse** — parse the SGX quote v3 layout (header ‖ ISV-enclave report 384B ‖
   signature section: AK signature, AK public, QE report + signature, QE auth data, PCK cert chain)
   into the fields `Dcap.quoteBody` expects, and extract the AK from the signature section rather
   than receiving it as a constructor input.
2. **PCK chain verification** — verify the AK's endorsement: QE-report-signature by the PCK leaf,
   PCK chain up to the **Intel SGX Root CA** (pinned), with CRL checks.
3. **TCB appraisal** — fetch TCBInfo + QEIdentity from the Intel PCS (or a cache), check the
   platform CPUSVN/PCESVN and QE ISVSVN against an acceptable TCB level, and apply a written policy
   for `OutOfDate`/`ConfigurationNeeded`/advisory states with a freshness window (Constitution X — the
   accepted TCB level + reference measurements are transparency-logged).
4. **Attested key provisioning** — only after 1–3 pass does OpenBao release the notify/store key,
   wrapped to the attested enclave key (see attestation-key-provisioning.md).

## Honest labeling

Until 1–4 are in place on real hardware, the production verifier is not wired to a live quote
source, so builds use `SoftwareAttestationVerifier` (`hardwareBacked = false`) and report
`DEV, NO METADATA PRIVACY` (Constitution IV) — the cryptographic verifier existing in code does NOT
make a dev build private; only a passing **hardware-backed** quote does.

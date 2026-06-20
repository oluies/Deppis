# Design Note: Hardware Acceleration of Server-Side Crypto & Oblivious Ops (GPU / FPGA)

**Status**: exploratory / research (NOT MVP, NOT scheduled). A place to capture the path and —
crucially — the gates any such work must clear, so "for fun" never becomes "for production"
without the same discipline as the rest of the system.
**Governs / bound by**: Constitution **I** (no hand-rolled crypto), **III** (constant-time),
**IX** (attestation, not identity), **X** (reproducible builds & transparency log), **XI** (pinned
deps); research **D11** (key custody), **D16** (round-bound tokens). Relates to
[attestation-key-provisioning.md](./attestation-key-provisioning.md).

## Why this is even tempting here

Most "accelerate crypto on a GPU" ideas die on the first gate: **GPUs are not constant-time**
(warp divergence, memory-coalescing timing, cache effects), and data-dependent timing on key/plaintext
is a side channel (Constitution III). This codebase is an unusual exception for *part* of its
workload, because the PONG/PING hot path is built on **data-oblivious primitives with fixed,
data-independent control flow**:

- `oblivious-sidecar/src/primitives.rs` — a **bitonic sort network** (`bitonic_sort` /
  `bitonic_merge` / `oblivious_sort_items`): the sequence of compare-exchanges is fixed by `n`
  alone, never by the data. Swaps go through `cond_swap` / `ct_select_u64` (branchless, constant
  time). `oblivious_compact` is likewise a fixed routing network.
- `store.rs` — the oblivious store is a **full linear scan** (touches every slot regardless of the
  query), single-use, zeroizing.
- `notify.rs` — oblivious PING aggregation over a fixed-size digest.

A fixed compare-exchange network is *exactly* the shape that maps well to SIMD/SIMT and to spatial
hardware — and it is fixed-control-flow for the **same reason** it is constant-time. So for the
oblivious-sort / compaction / full-scan operations specifically, "fast" and "side-channel-safe" do
not pull in opposite directions the way they do for, say, a branchy bignum modexp.

## Candidate operations (server side only)

| Operation | Where | HW fit | Notes |
|---|---|---|---|
| Bitonic oblivious sort | `primitives.rs` | **GPU & FPGA** | Fixed O(n log²n) network; the canonical GPU-sort + classic systolic FPGA sorter. |
| Oblivious compaction | `primitives.rs` | GPU & FPGA | Fixed routing network. |
| Oblivious store full-scan | `store.rs` | **FPGA** | Streaming linear scan + constant-time select; a natural fit for a pipelined FPGA datapath / HBM bandwidth. |
| AEAD (ChaCha20-Poly1305) batch | sidecar seal/open | GPU (batch) / **FPGA** | Per-record independent → embarrassingly parallel; FPGA AEAD cores are well-trodden, vetted IP. |
| PING digest aggregation | `notify.rs` | GPU | Fixed-size reduction. |

Client-side ratchet / handshake crypto stays on the CPU (it is not the bottleneck and not the
attack surface this note is about).

## Two paths

### A. GPU offload (CUDA / OpenCL / SPIR-V)
- **From Scala/JVM**: TornadoVM (JVM → OpenCL/PTX/SPIR-V), Lift (Scala → high-perf OpenCL), or
  JCuda/JOCL bindings. From the **Rust** sidecar: `cust`/`cudarc` (CUDA) or `wgpu`/`ash` (Vulkan
  compute) — closer to where the obliv primitives already live.
- **Good for**: batch AEAD, the bitonic network at large `n`, the digest reduction.
- **The hard part — side channels**: even with a fixed network, a naïve kernel can leak via
  **data-dependent memory access** (coalescing/bank conflicts) or **divergent branches** in
  `cond_swap`. The kernel MUST be written branchless with **fixed access patterns** (every thread
  touches the same addresses each step), mirroring the CPU `ct_select` discipline. This is
  auditable but it is real work, and GPU constant-time is **not** the default.

### B. Custom FPGA / ASIC (Chisel or SpinalHDL → Verilog/VHDL)
- **Scala is the headline host language for this**: **Chisel** (emits Verilog) and **SpinalHDL**
  (emits VHDL *and* Verilog) are Scala-embedded hardware-construction languages. You write a
  parameterized generator in Scala; the output is synthesizable RTL. So "Scala emitting VHDL for
  crypto" is literally a supported workflow.
- **Good for**: a pipelined oblivious-store scan engine, a systolic bitonic sorter, and AEAD
  offload — all as constant-latency datapaths (constant-time by construction when the pipeline has
  no data-dependent stalls).
- **The hard part — physical side channels**: RTL can be constant-*time* yet still leak via
  **power/EM** (DPA/DEMA). Hardware crypto must additionally consider masking/hiding countermeasures
  — out of scope to design here, but it MUST be named so it is not silently skipped.

## Non-negotiable gates (any path, before it touches a real deployment)

1. **No hand-rolled crypto (Constitution I).** A Chisel AES core or a CUDA ChaCha kernel *is*
   hand-rolled crypto. Use **vetted, ideally formally-verified IP** (e.g. cores verified with
   Cryptol/SAW, fiat-crypto-style proofs) — not a fresh implementation. The **oblivious-sort /
   compaction** logic is not a cryptographic primitive (no secret keys), so a custom
   implementation is acceptable there *provided* it is proven data-oblivious; the **AEAD** is a
   primitive and must be vetted IP.
2. **Constant-time / data-oblivious (Constitution III).** Fixed control flow AND fixed memory-access
   pattern, branchless selects. For GPU: no divergence, no data-dependent addressing. For FPGA:
   constant-latency pipeline; consider power/EM masking. Validated, not assumed.
3. **Attestation, not identity (Constitution IX).** An accelerator is part of the trusted enclave
   boundary. Either it sits **inside** the TEE, or it is itself **attested** and bound into the
   same quote (its measurement appraised against transparency-logged reference values) before any
   key is released to it (see [attestation-key-provisioning.md](./attestation-key-provisioning.md)).
   A GPU/FPGA reachable over PCIe is otherwise an unattested third party — exactly the "which device
   is this" trap IX forbids. **No key crosses to an unattested accelerator.**
4. **KATs per path (Test-Driven, NON-NEGOTIABLE).** Every target re-runs the known-answer vectors
   (AEAD vs RFC 8439, the oblivious-sort output vs the CPU reference) **on that hardware**, plus a
   differential test: GPU/FPGA output ≡ the Rust CPU path, byte for byte — the same discipline as
   the existing Node-HMAC-≡-JCA-HMAC cross-platform KAT.
5. **Reproducible builds & transparency (Constitution X/XI).** Pinned toolchains (CUDA/LLVM/SPIR-V
   versions; the FPGA synthesis flow + bitstream hash) and the accelerator's measurement published
   to the transparency log, so what is attested is what was reviewed.
6. **Labeling (Constitution IV).** A build using an **unattested** accelerator path reports
   `metadataPrivate=false` / `DEV, NO METADATA PRIVACY`, identical to any other unattested backend.

## Suggested staged path (cheapest signal first)

1. **CPU baseline + differential-test harness** — make the Rust oblivious-sort / AEAD callable
   behind a trait so any accelerator is a drop-in with the CPU path as the always-on oracle.
2. **GPU bitonic sort (Vulkan/wgpu from Rust)** — the highest fun-to-risk ratio: no key material
   (pure oblivious sort), so gate (1)/(3) are light; prove the fixed-access-pattern kernel matches
   the CPU output and benchmark vs `n`.
3. **FPGA AEAD offload (SpinalHDL → VHDL)** — uses **vetted** ChaCha20-Poly1305 IP, behind the
   attestation gate; constant-latency datapath; KAT on-device.
4. **FPGA oblivious-store scan engine** — the most "custom hardware for fun" piece; constant-time
   streaming scan with `ct_select`, attested and measured.

## Honest recommendation

Technically very feasible, and genuinely a good fit for *this* workload because the oblivious
primitives are already fixed-control-flow. Start with **GPU oblivious-sort** (no keys → fewest
gates) for the fun/benchmark, and treat **FPGA AEAD via vetted IP** as the only "real crypto in
hardware" candidate. Do **not** emit a fresh AEAD/MAC core in Chisel for production — that trips
Constitution I. Everything stays gated by **attested + vetted + constant-time + differential-KAT'd**.

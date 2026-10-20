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
   ✅ **Prototyped** — `oblivious-sidecar/src/portable_sort.rs`: `bitonic_schedule(n)` emits the
   data-independent compare-exchange network as parallel-dispatchable stages, `oblivious_sort_portable`
   executes it, and a proptest differential KAT asserts it ≡ the recursive CPU oracle byte for byte
   (plus stage-disjointness + schedule-data-independence checks). Runs in CI without a GPU.
2. **GPU bitonic sort (Vulkan/wgpu from Rust)** — the highest fun-to-risk ratio: no key material
   (pure oblivious sort), so gate (1)/(3) are light. The schedule from step 1 is exactly the kernel
   input; a real backend is a drop-in that must pass the same differential KAT. Prove the
   fixed-access-pattern kernel matches the CPU output and benchmark vs `n`.
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

## Basing the RTL on a CUTE-style tensor engine (Brokkr) — what transfers, what does not

[Brokkr](https://oluies.github.io/brokkr/) asks whether a CUTE-style Chisel tensor engine can
accelerate quantum simulation. It is a sibling project worth mining, with one caveat up front:
**Brokkr implements no cryptographic primitives.** Its workload is state-vector and density-matrix
simulation (Grover, brickwork, Kraus channels). There is no crypto datapath there to copy.

### Do NOT base the datapath on CUTE

CUTE is a **multiply-accumulate** engine: dense complex MAC arrays, a 2^k-wide product tree, an
operand-staging fabric. Our hot path has **no multiplication at all**:

| Our operation | Arithmetic | CUTE's expensive unit |
|---|---|---|
| Oblivious store scan (`store.rs`) | compare 32 B token, conditional-select 256 B frame, per slot | unused |
| Bitonic sort (`primitives.rs`) | compare-exchange | unused |
| Oblivious compaction | fixed routing, no arithmetic | unused |
| PING digest aggregation (`notify.rs`) | OR-reduction over a fixed-size digest | unused |

Brokkr's own analysis notes that routing diagonal/monomial blocks through dense hardware wastes
~8.5× area per block. Our case is the limit of that argument: routing a compare/select workload
through a complex MAC array wastes **the entire multiplier array**, which is the part that costs
(~20,000 cells/MAC in Brokkr's estimate). A scan/sort engine is a comparator tree, a mux network
and a wide streaming datapath. **Start the datapath from scratch.**

### DO lift Brokkr's surrounding machinery

The datapath is the cheap part to write and the least reusable. What is expensive, and directly
reusable:

1. **Banked SRAM + XOR bank mapping.** Brokkr measures extended-Hamming XOR-combined address bits
   reaching 18.2 of 32 banks against 1.1 for naive low-bit banking — a 16× bandwidth gain. The
   oblivious **store scan** is sequential and barely needs this, but the **bitonic network's**
   compare-exchange pairs are strided by a power of two per stage, which is precisely the
   collide-everything-in-one-bank pattern that mapping fixes.
2. **The Benes permutation network.** Brokkr's monomial path already has one, verified on arbitrary
   permutations. **Oblivious compaction is a fixed routing network** — this is the single most
   directly transferable block in the project.
3. **The difftest harness.** Brokkr difftests RTL against Scotty, its golden software model, with a
   stated fixed-point error budget. Gate 4 above demands exactly that discipline, and we already
   have the oracle: `portable_sort.rs`'s proptest asserts the portable schedule ≡ the recursive CPU
   reference byte for byte. Our comparison is **exact**, not an error budget — integer compare/select
   has no rounding — so the harness gets simpler, not harder.
4. **The descriptor-queue host interface.** Brokkr's `TaskController` + form-tagged operator
   descriptors is the right offload shape for "here is a batch of slots, scan them".

### Build-system reality: do not drag Chisel into this build

Brokkr is **Chisel 6.7.0 on Scala 2.13.15** (dual-built Mill + sbt). This repo is **Scala 3.9.0 on
sbt 2.0.10**. A Chisel subproject here would need its own `scalaVersion := "2.13.x"` — legal
per-project, but it introduces a second Scala version into a build that pins every dependency
(Constitution XI) and whose plugin set is sbt-2-specific. No Chisel source can be shared with
`protocol-core` or the sidecar regardless, because the language versions differ.

**Recommendation: keep the Chisel work in Brokkr (or its own repo) and let this repo consume only
the artifact** — the bitstream plus a thin host shim behind the trait in the staged path above.
Deppis then depends on a *measurement*, not on a 2.13 toolchain, which is also what gates 3 and 5
want (attested, measured, reproducible, transparency-logged).

## The four-way sidecar comparison

`bench/` already compares three implementations of the same store against one load profile, with
the Rust path as the in-batch control: `obsd` (Rust/tonic), `sidecar-scala` on the JVM, and the same
Scala sources linked by Scala Native. A **Chisel/FPGA leg is a natural fourth** and the harness
needs no new methodology — `run-all.sh` already starts a server per target, discards a warm-up rep,
reports the median of repetitions and the ratio to the control.

Three constraints on making that comparison honest:

- **Measure the SCAN, not per-frame RPC throughput.** Frames are 256 bytes. ChaCha20-Poly1305 on
  256 B is well under a microsecond on a CPU, while a PCIe round trip is one to a few microseconds,
  so a per-frame offload is a *slowdown* by construction. The scan is the opposite shape: at
  capacity 4096 each call touches 4096 × (32 + 256 + 1) B ≈ **1.2 MB** of branchless byte work, and
  `bench/README.md` records that throughput is dominated by that scan rather than the network front.
  `BENCH_CAPACITY` is therefore the independent variable that matters, and the existing capacity
  sweep is the right table to extend — it already shows a 16× capacity cut buying the JVM only 1.7×
  but Scala Native 10.5×, i.e. it separates transport-bound from scan-bound targets, which is
  exactly what an accelerator leg needs to demonstrate.
- **Report FPGA+host, and say so.** The accelerator leg's number includes the host shim and the bus
  crossing. That is the honest figure for a deployment, but it is not comparable to a CPU figure as
  "the hardware is N× faster" — state both the end-to-end rate and the on-device scan rate.
- **Scope parity.** `sidecar-scala` implements the **store only** (the notify path needs
  libsodium-backed sealed tokens, which has not been ported). A fourth leg should match that scope
  or the table stops being like-for-like.

## Roadmap placement: when to run this spike

**Not before Phase C, and the hardware part belongs in Phase D or later.** Two reasons, one of them
decisive:

1. **Gate 3 is the binding constraint, and it IS Phase C.** No key may cross to an unattested
   accelerator; the accelerator must sit inside the TEE or be attested into the same quote. The
   attestation flow — Veraison verifier, CoRIM transparency-logged reference values, client-side
   appraisal — *is* Phase C. Before Phase C exists there is nothing to bind an accelerator into, so
   an FPGA path built earlier would have to be rebuilt against the real attestation boundary anyway.
2. **Phase C is the MVP release gate.** Per the phasing section of `plan.md`, the first shippable
   build is Phase C, not before. Non-MVP work competing for attention with the release gate delays
   the release, and this note's status line already says NOT MVP, NOT scheduled. That stays true.

What **can** land early, cheaply, and is worth doing on its own merits — because it is software, has
no constitutional gates and no hardware:

- **The trait seam** (step 1 of the staged path). Today the sidecar has no trait: `grep` finds only
  gRPC service impls, and `portable_sort` exposes free functions. The CPU oracle exists; the
  injection point does not. An `ObliviousOps`-shaped trait with the current functions as the
  always-on CPU implementation costs little and makes every later backend a drop-in.
- **Promoting the differential proptest to a conformance suite** any backend must pass.
- **A fourth target slot in `run-all.sh`**, so the comparison table has somewhere to put a leg.

Suggested placement, then:

| Work | Phase | Why there |
|---|---|---|
| Trait seam + conformance suite + 4th bench slot | alongside **Phase B** | Pure software, no gates, useful immediately, de-risks everything after |
| GPU bitonic sort (wgpu/Vulkan from Rust) | **Phase D** or any post-MVP slack | No key material → gates 1 and 3 are light; highest signal per unit effort |
| FPGA oblivious-scan / sort engine (Chisel, scratch datapath) | **Phase D or later**, after C's attestation flow is real | Needs the attestation boundary to exist; the "custom hardware" piece |
| FPGA AEAD | **only** with vetted IP, never as fresh RTL | Constitution I — see gate 1 |

The cheapest useful signal, if the goal is the four-way comparison rather than a deployment, is the
trait seam plus the GPU leg: it exercises the whole comparison harness end to end with no keys, no
attestation and no synthesis flow, and tells you whether the scan actually accelerates before any
RTL is written.

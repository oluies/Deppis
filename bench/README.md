# Benchmarking the oblivious sidecar

Two questions, kept separate on purpose:

1. **How fast is the sidecar we actually ship?** Gatling drives the real Rust `obsd` over real
   gRPC — `ObsdGrpcSimulation`.
2. **Would a Scala Native + cats-effect implementation be competitive?** The same `.proto`, the
   same store semantics, the same load profile, linked for the JVM and for Scala Native from ONE
   source tree — `sidecar-scala` + `ScalaSidecarSimulation`.

Run everything with `./bench/run-all.sh`. Gatling's HTML reports land in `bench/target/gatling`.

## Results

macOS arm64 (Apple silicon, 18 cores), JDK 26, 5 virtual users, 30 s, capacity 4096, batch 1,
**median of 3 reps**. Each virtual user writes a 256-byte frame and reads it straight back.

| target | stack | median rps | vs control | spread across reps |
|---|---|---:|---:|---|
| `obsd` | Rust, tonic, gRPC/HTTP2, `--release` | **8,643** | control | 7,102–10,191 (±20%) |
| `sidecar-scala` (JVM) | http4s-grpc + Ember, gRPC/HTTP1.1 | **5,495** | 0.64× | 4,543–5,619 |
| `sidecar-scala` (Native) | same source, SN 0.5.12 `releaseFast` | **484** | 0.06× | 481–485 (±0.5%) |

**Do not quote the absolute numbers.** On a workstation they are not reproducible to more than one
significant figure: an unrelated desktop app at 30% CPU moved the `obsd` figure by 42% between two
batches with no code change at all. That is why the Rust run is a **control** measured in the same
batch as the Scala ones, why every figure is a median of repetitions, and why `run-all.sh` records
the load average at both ends of the run. The ratio to the control is the number that survives.

The spread column is itself informative: `obsd` is noisy because it is fast enough that the load
generator and the machine dominate, while Native is steady to ±0.5% because it *is* the bottleneck.

Two caveats on that column specifically. These figures come from a batch run BEFORE the harness
discarded a warm-up rep, so the JVM row's 4,543 → 5,495 → 5,619 is monotonically increasing and is
at least as well explained by JIT warm-up as by machine noise — the server is started once per
target and reused across reps. `run-all.sh` now runs and discards one warm-up rep per target, so
later batches do not carry that bias, but the numbers above still do. Separately, `during(duration)`
can cut a virtual user between its `WriteBatch` and the paired `ReadBatch`, so each rep can leave up
to `users × batch` slots occupied in a store that is not reset between reps; at capacity 4096 with
5 users that is negligible, but it would not be at small capacities.

### Where the Native gap actually comes from

First, which layer. Measured by varying capacity, which is what sets the size of the oblivious scan:

| capacity | JVM | Native | Native / JVM |
|---:|---:|---:|---:|
| 256 (scan cheap) | 6,732 | 4,903 | **0.73×** |
| 4096 (scan dominant) | 3,899 | 465 | **0.12×** |

A 16× cut in capacity buys the JVM only **1.7×** — it is bounded by HTTP and framework overhead
there — but buys Scala Native **10.5×**, near-linear. Dropping from 5 virtual users to 1 costs
Native only 16% (465 → 390 rps), so it is not waiting on locks or fibers either; it saturates with
roughly one request in flight. **Native's framework overhead is competitive** (within 1.4× of the
JVM once the scan is small); the gap is the scan.

**These capacity figures are a different batch from the headline table above, and are single runs
rather than medians** — 3,899 and 465 rps here versus 5,495 and 484 there for what is otherwise the
same configuration. Given the ±20-40% batch-to-batch movement this document insists on, only the
*within-row* ratios are meaningful; do not read the absolute numbers across the two tables.

Second, what about the scan. `sidecar.Main bench` and `storebench` run the loop with no transport
at all (see "The core microbenchmark" below). At capacity 4096, µs per write+read round — these are
single runs, but the effect sizes are 10-25×, far above the run-to-run variance:

| implementation | µs/round | vs Rust | vs JVM |
|---|---:|---:|---:|
| Rust, `--release` | **150.9** | 1.0× | 0.61× |
| Scala JVM | **248.8** | 1.65× | 1.0× |
| Scala Native, `releaseFast` | **3,872.5** | 25.7× | 15.6× |
| Scala Native, raw pointers (no bounds checks) | **2,845.9** | 18.9× | 11.4× |
| Scala Native, `releaseFull` | 3,416.8 | 22.6× | 13.7× |
| Scala Native, `releaseFull` + raw pointers | 2,776.4 | 18.4× | 11.2× |

All four implementations print **checksum 314794**, which is how we know they are doing identical
work rather than one of them being quietly optimised away or subtly different.

**The bounds-check hypothesis is not supported as an explanation.** Scala Native does bounds-check
arrays — verified directly: an out-of-range read on an index opaque to the optimiser still throws
`ArrayIndexOutOfBoundsException` under `releaseFast`. But removing those checks entirely, by
scanning the *same* store object's *same* arrays through raw `Ptr[Byte]`, buys only **1.36×**.
`releaseFull` buys a further ~13%. Together they close about 1.4× of a 25× gap; Scala Native is
still **18× slower than Rust and 11× slower than the JVM with every bounds check gone.**

So bounds checks are a real but minor cost, and the remaining ~18× is Scala Native's code
generation for this loop itself. The most likely candidate — untested, so treat it as a hypothesis
and not a result — is auto-vectorisation: the inner loops are byte-wise conditional selects over
32- and 256-byte runs, exactly the shape LLVM vectorises for Rust and HotSpot handles well, and the
mask arithmetic here round-trips through `Int` with `.toByte` truncation on every element, which may
be what blocks it. Confirming that needs a look at the emitted assembly, which this benchmark does
not do.

The practical read: **Scala Native is a poor fit for this particular workload** — a long, tight,
branchless byte scan — while being perfectly competitive on the server plumbing around it. That is
a narrower and more useful conclusion than "Scala Native is slow".

### The core microbenchmark

`sbt "sidecarScala/writeClasspath"` then `java -cp $(cat …/sidecar-scala.classpath) sidecar.Main bench`,
`./sidecar-scala-native bench`, and `cargo run --release --bin storebench`. All take optional
capacities as arguments (default `256 1024 4096`).

Hand-rolled rather than criterion or JMH, deliberately: neither exists across all three targets, so
per-language harnesses would fold three different measurement methodologies into the comparison.
All three use the identical shape — a fixed token pool built outside the timed region, a warmup
phase, a timed phase over a fixed op count, and a checksum consumed at the end (without which the
optimiser is entitled to delete the scan and report a spectacular 0 ns/op). Per-round cost is tens
to thousands of microseconds, so loop overhead is irrelevant.

### The runtime really is multithreaded

Checked rather than assumed, because the answer changes how the numbers should be read:
cats-effect **3.7.1** is the newest published for `native0.5_3` and is what resolves; the 3.7.x line
is the one that added Scala Native 0.5 support with the work-stealing pool cross-built for LLVM and
kqueue/epoll polling. Under load the Native binary shows **29 threads and ~395% CPU** on an 18-core
box. So the Native figure is not a single-core artifact.

## Three things that would have made these numbers a lie

**Scala Native's defaults.** The first run measured 561 rps — not because Scala Native is slow, but
because the default link is a *debug* build and, worse, auto-detects whether to support threads.
It saw no `Thread` use during initial class loading and linked a **single-threaded** binary
("Multithreading support will be disabled to improve performance"), so a cats-effect server was
pinned to one core while the JVM used all of them. Building `releaseFast` with multithreading and
the parallel `commix` GC took it to 2,410 rps — **4.3× from link flags alone**. `build.sbt` pins
these explicitly and says why.

**gatling-grpc's trial licence.** `io.gatling:gatling-grpc` is first-party but licence-capped:
above 5 virtual users or 5 minutes it prints a warning, shuts the run down, and exits non-zero
having recorded **nothing** — which looks exactly like a server that refused every connection. It
cost one confusing empty run to notice. `ObsdGrpcSimulation` now `require`s the cap up front so
that failure can't be mistaken for a result, and `run-all.sh` refuses to pretend, skipping the Rust
run and saying so if you raise the user count. Lifting the cap needs Gatling Enterprise or the
Apache-2.0 `com.github.phisgr:gatling-grpc`.

**Checking only the status code — or only the response size.** http4s-grpc answers a *failed* call
with HTTP 200 and an empty body, putting the error in a `grpc-status` trailer that Gatling's HTTP
client does not surface, so `status.is(200)` alone would give a flawless report for a server
rejecting everything. Worse, a read MISS is the same size as a hit — `sealed_result` is 257 bytes
either way, by design — so a length check does not catch a run that never hit at all, which is what
an overflowing store or a capacity misconfiguration produces. Both simulations now assert the found
tag is 1, and both declare `assertions(global.failedRequests.count.is(0))`, because Gatling exits 0
even on a 100%-KO run.

**A runner that read throughput from the wrong column.** Gatling's console table is
`label | Total | OK | KO`, and the extraction took "the last number on the line". With zero failures
the KO cell is a `-` marker, so that happened to land on OK — but the moment anything failed, the KO
cell held a number and the harness silently recorded KO throughput as the result. It now pulls a
named column, echoes OK/KO counts per rep, keeps sbt's exit status instead of `|| true`, re-checks
the port before every rep, fails a rep on any KO, and continues to the remaining targets instead of
letting `set -e` abort the whole batch (which also cost the summary and the environment footer).

## Why the Rust and Scala runs don't share a transport

They can't, and the reason is structural rather than a shortcut.

`fs2-grpc` wraps grpc-java, so it is JVM-only and no use for the Native half. `http4s-grpc` is a
pure-Scala gRPC implementation and does cross-publish for Native — it is the right choice, and it
is what `sidecar-scala` uses. But it runs on http4s Ember, and **Ember speaks HTTP/1.1**: measured
here on both the 0.23 and the 1.0.0-M lines, it rejects the HTTP/2 connection preface outright.
Meanwhile grpc-java — which Gatling's gRPC module is built on — is HTTP/2 only. So Gatling's gRPC
client physically cannot connect to the Scala server, and tonic will not accept HTTP/1.1.

gRPC's *framing* doesn't need HTTP/2, so `ScalaSidecarSimulation` drives the same methods over
HTTP/1.1 by hand: `POST /<service>/<Method>`, `content-type: application/grpc+proto`, body =
5-byte length prefix ‖ protobuf. The server replies with the same content type and a `grpc-status`
trailer, exactly as it would to a real gRPC client.

What that costs: **JVM vs Native is a controlled comparison** (one variable, the runtime).
**Rust vs Scala is not** — HTTP/2 + grpc-netty versus HTTP/1.1 + Gatling's HTTP client. Removing
that confound needs either an HTTP/1.1 front on the Rust side or HTTP/2 in Ember; until then the
Rust column is indicative.

## What is being measured

`ObliviousStore` scans **every** slot on every operation, doing the same conditional-assignment
work per slot regardless of where — or whether — the token matches. At capacity 4096 that is
4096 × (32 + 256 + 1) bytes ≈ **1.2 MB of branchless byte work per single-entry call**. Throughput
is dominated by that scan, not by the network front, which is why capacity is the interesting
independent variable (`BENCH_CAPACITY`) and `BENCH_BATCH` multiplies per-call cost linearly.

## `sidecar-scala` is not a deployment target

It carries **no privacy claim**, and unlike `obsd` it could not carry one as written. The Rust
store uses the `subtle` crate, whose compiler barriers are what make constant-time a property the
toolchain must preserve. Neither the JVM nor Scala Native offers an equivalent, so the port's
conditional assignments are hand-written integer arithmetic and nothing stops HotSpot or LLVM from
reintroducing a branch. It does the same *amount* of work — which is what a throughput benchmark
needs — and establishes nothing about timing leaks. `ObliviousStoreSuite` pins behavioural parity
with the Rust unit tests on both platforms, because a benchmark of a divergent implementation
measures nothing.

The Rust sidecar remains the only implementation the metadata-privacy argument rests on.

## Knobs

| variable | default | meaning |
|---|---|---|
| `BENCH_USERS` | 5 | virtual users (>5 skips the Rust run — trial licence) |
| `BENCH_DURATION_S` | 30 | run length per target |
| `BENCH_CAPACITY` | 4096 | store slots; the dominant cost driver |
| `BENCH_BATCH` | 1 | entries per RPC |
| `BENCH_REPS` | 3 | repetitions per target; the median is reported |

Individually: `sbt "bench/runMain bench.Run bench.ObsdGrpcSimulation"`.

## Not done yet

- **Attributing the remaining ~18× Native gap.** The microbenchmark rules out bounds checks,
  locks, fibers, the runtime and the transport, but does not identify what IS responsible.
  Inspecting the emitted assembly for the inner loops — specifically whether Rust and HotSpot
  vectorise them and Scala Native does not — is the next step.
- **The notify half.** `NotificationService` needs libsodium-backed sealed tokens; porting that to
  Scala Native is a separate lift, so `sidecar-scala` implements the store only. Gatling can still
  drive `obsd`'s notify path.
- **Capacity sweeps.** Everything above is a single point at 4096.

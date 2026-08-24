# Benchmarking the oblivious sidecar

Two questions, kept separate on purpose:

1. **How fast is the sidecar we actually ship?** Gatling drives the real Rust `obsd` over real
   gRPC — `ObsdGrpcSimulation`.
2. **Would a Scala Native + cats-effect implementation be competitive?** The same `.proto`, the
   same store semantics, the same load profile, linked for the JVM and for Scala Native from ONE
   source tree — `sidecar-scala` + `ScalaSidecarSimulation`.

Run everything with `./bench/run-all.sh`. Gatling's HTML reports land in `bench/target/gatling`.

## Results

macOS arm64 (Apple silicon), JDK 26, 5 virtual users, 30 s, capacity 4096, batch size 1.
Each virtual user writes a 256-byte frame and reads it straight back, so both RPCs are exercised
and the store never saturates.

| target | stack | throughput (rps) | mean | p99 | failures |
|---|---|---:|---:|---:|---:|
| `obsd` | Rust, tonic, gRPC/HTTP2, `--release` | **15,346** | 0 ms | 1 ms | 0 |
| `sidecar-scala` (JVM) | Scala 3, http4s-grpc + Ember, gRPC/HTTP1.1 | **10,840** | 0 ms | 1 ms | 0 |
| `sidecar-scala` (Native) | same source, Scala Native 0.5.12 `releaseFast` | **2,410** | 2 ms | 3 ms | 0 |

Read the caveats below before quoting any of this. The honest one-line summary is: **the JVM build
reaches about 70% of the Rust sidecar's throughput, and the Scala Native build about 16% — but the
Rust column is not measured over the same transport, so treat it as indicative, not a like-for-like
verdict.** The JVM-vs-Native gap of ~4.5× IS like-for-like: identical source, identical transport,
identical driver.

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

**Checking only the status code.** http4s-grpc answers a *failed* call with HTTP 200 and an empty
body, putting the error in a `grpc-status` trailer that Gatling's HTTP client does not surface. A
simulation asserting `status.is(200)` would give a flawless report for a server rejecting every
request. `ScalaSidecarSimulation` also requires a non-empty response body.

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

Individually: `sbt "bench/runMain bench.Run bench.ObsdGrpcSimulation"`.

## Not done yet

- **A core-level microbenchmark** (criterion vs a Scala harness) measuring the oblivious scan with
  no transport at all. That is the one comparison that would be fully controlled across all three
  runtimes, and it would isolate how much of the Rust lead is the store versus the server.
- **The notify half.** `NotificationService` needs libsodium-backed sealed tokens; porting that to
  Scala Native is a separate lift, so `sidecar-scala` implements the store only. Gatling can still
  drive `obsd`'s notify path.
- **Capacity sweeps.** Everything above is a single point at 4096.

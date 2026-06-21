# Contributing to Deppis

Thanks for helping build a **metadata-private messenger**. This guide is the practical
path from a fresh clone to a green build and an open PR. For *what* the system is and *how*
it works, read [`README.md`](README.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md) first —
this file does not repeat them.

> ### ⚠️ Privacy status of dev builds
> Until the Phase C PingPong enclave store and its attestation flow are in place, **every
> build is `DEV, NO METADATA PRIVACY`** and is labeled so in code, logs, and UI
> (Constitution IV). The dev store/notify provide no access-pattern privacy. **Never label,
> ship, or describe a dev build as private.** See the non-negotiables below.

## Non-negotiables (read before you write code)

These come from [`.specify/memory/constitution.md`](.specify/memory/constitution.md) (v1.0.0)
and are not up for debate in a PR:

- **No hand-rolled crypto (Constitution I).** AEAD / Blake2b / KDF come from libsodium (JVM,
  via the Foreign Function & Memory API) or `@noble/hashes` (Scala.js); the double ratchet is
  `org.signal:libsignal-client`. Do not reimplement a primitive, ever.
- **The `DEV, NO METADATA PRIVACY` labeling rule (Constitution IV).** A build may claim
  metadata privacy *only* after a real hardware attestation passes. The CI labeling gate
  fails the build if a dev build reports anything else — see the JVM CI job.
- **Attestation-not-identity on PING/PONG (Constitution IX).** Attestation proves the enclave
  measurement (with a freshness nonce bound into the quote); it is never used as an identity.

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| **JDK** | **22 or newer** (CI uses **24**) | The `crypto` layer calls libsodium through the finalized Foreign Function & Memory API (JEP 454, GA in JDK 22). Older JDKs lack the final FFM API. |
| **sbt** | **2.0** | Build tool (pinned in `project/build.properties`). |
| **Rust + cargo** | stable | Builds the `obsd` oblivious sidecar and runs its tests. |
| **libsodium** | system package | Loaded at runtime by the `crypto` module via FFM (`libsodium-dev` on Debian/Ubuntu; `brew install libsodium` on macOS). |
| **Node** | 22 | Runs the Scala.js engine tests under Node, and provides the vetted `@noble/hashes` JS crypto dep (`npm ci`). |
| **Flutter** | 3.44.2 (stable) | Builds and tests the client in `clients/flutter` (presentation only). |
| **protoc** | system package | `protobuf-compiler`, needed by the Rust sidecar's `tonic-build` and the gRPC integration test. |

The Scala-side gRPC contracts are compiled by ScalaPB inside sbt (no separate protoc needed
for the JVM modules); `protoc` is only required for the Rust sidecar build.

## Module map and how to test each one

The modules are defined in [`build.sbt`](build.sbt). `protocol-core` is the single source of
truth (Constitution VII): one set of `shared/` Scala 3 sources cross-compiled to the JVM and
to Scala.js.

| sbt module | Path | Test command |
|---|---|---|
| `protocolCore` | `protocol-core/` (shared + `jvm/`) | `sbt "protocolCore/test"` |
| `protocolCoreJS` | `protocol-core-js/` (shared + `js/`, runs under Node) | `npm ci && sbt "protocolCoreJS/test"` |
| `crypto` | `crypto/` (libsodium FFM + libsignal ratchet) | `sbt "crypto/test"` |
| `anonymity` | `anonymity/` | `sbt "anonymity/test"` |
| `server` | `server/` (`pong`/`ping`/`provider`/`attestation`) | `sbt "server/test"` |
| `transport` | `transport/` (gRPC fronts + `DeppisDemo`) | `sbt "transport/test"` |

### Run all the JVM modules at once

`build.sbt` defines a **`testJvm`** command alias (next to the `root` aggregate) that runs the JVM
modules in one `;`-chained sbt session — CI uses it so the modules share a single cold start. The
Scala.js module is excluded (its tests run in the `scalajs` CI job under Node):

```bash
sbt -batch testJvm
# equivalent to: sbt -batch ';protocolCore/test ;crypto/test ;anonymity/test ;server/test ;transport/test'
```

`crypto`, `server`, and `transport` tests **fork** the JVM with
`--enable-native-access=ALL-UNNAMED` (set automatically by `build.sbt`) because they touch
libsodium through FFM — so make sure libsodium is installed.

### Scala.js engine tests

```bash
npm ci                      # installs the pinned @noble/hashes (vetted JS crypto)
sbt "protocolCoreJS/test"   # runs the engine under Node, cross-checked against the JVM JCA
```

### Rust oblivious sidecar (`obsd`)

```bash
cargo test --manifest-path oblivious-sidecar/Cargo.toml
```

### Cross-process integration (Scala client ↔ real `obsd`)

`transport/test` includes a cross-process test that builds and drives the real `obsd` binary;
it self-cancels if the binary is absent. To run it against a freshly built sidecar:

```bash
cargo build --bin obsd --manifest-path oblivious-sidecar/Cargo.toml
OBSD_BIN="$(pwd)/oblivious-sidecar/target/debug/obsd" \
  sbt -batch "transport/testOnly transport.SidecarIntegrationSpec"
```

### Flutter client

```bash
cd clients/flutter
flutter pub get
flutter analyze && flutter test
```

## Run the prototype

The headless demo pairs two engines out of band and delivers a message metadata-privately
through the **real Rust `obsd` sidecar**. It builds `obsd` for you:

```bash
scripts/run-demo.sh
```

It prints the `DEV, NO METADATA PRIVACY` label throughout. See
[`README.md`](README.md#run-the-prototype) for the expected output and what each line means.

## Formatting and linting (CI-enforced)

Run all three before you push — CI gates on each.

**Scala — scalafmt** (config: [`.scalafmt.conf`](.scalafmt.conf), pinned to 3.8.3):

```bash
scalafmt .          # format the whole tree in place
scalafmt --test     # check only; fails if anything is unformatted (this is the CI gate)
```

Install a matching `scalafmt` via Coursier: `cs install scalafmt:3.8.3`. Generated code
(`target/`, `src_managed/`) is excluded in the config.

**Rust — rustfmt + clippy** (run in `oblivious-sidecar/`, matching CI):

```bash
cargo fmt --all                         # format
cargo fmt --all --check                 # check (CI gate)
cargo clippy --all-targets -- -D warnings   # lint; warnings are errors in CI
```

**Flutter — analyzer:**

```bash
cd clients/flutter && flutter analyze
```

## Pull request and review workflow

1. **Branch** off `main` for your change.
2. **Format and lint** locally (`scalafmt --test`, `cargo fmt --check`, `cargo clippy`,
   `flutter analyze`) so you don't burn a CI round on style.
3. **Run the tests** for the modules you touched (see the table above). If you changed wire
   formats or the sidecar, run the cross-process integration test too.
4. **Open the PR** with `gh pr create`, a descriptive title, and a body that says what changed
   and why. Reference the relevant FR / spec ids from
   [`specs/001-metadata-private-messenger/`](specs/001-metadata-private-messenger/) where they
   apply.
5. **CI must be green.** The pipeline ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))
   runs: JVM tests **+ the labeling gate**, scalafmt, Rust fmt/clippy/test, the cross-process
   integration test, the Scala.js cross-build + link, the Flutter analyze/test, and a hygiene
   job (pinned-deps + secret scan).
6. **Honor the non-negotiables above** — a reviewer will reject any PR that hand-rolls a
   primitive, mislabels a dev build, or treats attestation as identity.

## Honest caveat: two pinned deps are pre-release

For reproducible builds we pin every dependency (Constitution XI, `project/V.scala` and
`project/plugins.sbt`). Two of them are currently **pre-release** and are tracked to swap for
a GA release later:

- **`sbt-protoc` `1.1.0-RC1`** — the only `_sbt2_3` artifact available for sbt 2.0. ScalaPB
  codegen runs in a sandboxed classloader to dodge a `protoc-bridge` version clash (see the
  comments in `project/plugins.sbt` and `build.sbt`). Revisit once ScalaPB ships a
  `protoc-bridge_3` compiler plugin and sbt-protoc GAs for sbt 2.
- **ScalaTest `3.3.0-alpha.2`** (with `scalatestplus` `3.3.0.0-alpha.2`) — the alpha that
  works under the sbt 2.0 Scala 3 toolchain. Swap to GA when it lands.

If a build breaks around proto codegen or the test framework, these pins are the usual
suspects.

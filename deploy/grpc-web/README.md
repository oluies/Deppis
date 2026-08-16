# gRPC-web transport — browser ⇄ Envoy ⇄ Scala (T032c)

A browser cannot speak HTTP/2 gRPC, so the Flutter/web `ProtocolEngine`'s gRPC-web host transport talks
**gRPC-web (HTTP/1.1)** to **Envoy**, which translates it to **gRPC (HTTP/2)** and forwards to the Scala
`ObliviousStore` service. This directory is the runnable proof of that hop.

```
 grpcweb-client ──gRPC-web/HTTP1.1──▶ Envoy :8080 ──gRPC/HTTP2──▶ messenger-server :9090
   (raw frame)        (grpc_web filter ⇄ http2 upstream)            (Scala ObliviousStore, h2c)
```

## Run it

```sh
./run.sh
```

Expected tail: `GRPC-WEB-ROUNDTRIP-OK: WriteBatch(round_id=42) echoed through Envoy; grpc-status ok`.

`run.sh` stages the JVM server (`sbt transport/stageServer`), builds the server image, starts
server + Envoy, and runs a gRPC-web client that POSTs a `WriteBatch(round_id=42)` and asserts the
echoed `round_id` + `grpc-status: 0` come back through Envoy. It cleans up on exit.

## What proves what

- **`GrpcWebBackendServer`** (`transport/.../round/`) binds the `ObliviousStore` gRPC service over plain
  **h2c** — the Envoy upstream (TLS terminates at/above Envoy in this topology).
- **`deploy/envoy/envoy.yaml`** — the committed, production-style Envoy config: `grpc_web` + `cors`
  filters on an `:8080` listener, HTTP/2 upstream cluster `scala_grpc`. `run.sh` substitutes the
  server's address into a runtime copy (see "Networking" below). Terminates **no** TLS.
- **`deploy/envoy/envoy-pq-tls.yaml`** — the **TLS-terminating** front, with post-quantum key
  agreement per RFC 10024 (`ecdh_curves: [X25519MLKEM768]`, TLS 1.3 only) on `:8443`.

  This is where post-quantum protection actually reaches users: `transport`'s `TlsRoundServer`
  (hybrid-only, see `transport.round.PqTls`) has no external clients, so **browser → Envoy is the
  only TLS hop a real user traverses**.

  It is **hybrid-only**, matching `PqTls`: no classical group is offered, so there is nothing to
  downgrade to — and, deliberately, **a browser without ML-KEM-768 cannot load the app**. That is a
  failed handshake, not a soft degradation.

  **That cost is accepted.** Deppis is a new service with no installed base, so there is no legacy
  client population to strand. If such a client ever has to be supported, the answer is an **adapter
  in front** rather than relaxing this listener — a classical group added here applies silently to
  every user, and a downgrade path is much harder to remove than to avoid taking.

  Verified against real clients before enabling. The listener offers *only* the hybrid group, so
  reaching key agreement at all proves the client supports it — which is what each row records, and
  is a weaker claim than "the connection succeeded":

  | client | result |
  | --- | --- |
  | Chrome 151 | handshake completes — reaches Envoy's HTTP layer |
  | Safari, macOS 27 | **key agreement** completes — a cert warning. Not the full handshake: Safari evaluates the certificate inside the handshake and aborts before sending `Finished`. It still proves the group, because the group is settled in ClientHello/ServerHello *before the certificate is sent*. A failed handshake instead gives Safari's generic "can't establish a secure connection" page — observed against a *plaintext* listener, which is a different failure surfacing the same message rather than a reproduced group mismatch; the group-mismatch negative is covered by the classical-only check in `verify-pq-tls.sh`. |

  Published support agrees: Chrome default since 131, Firefox/Edge default-on, Apple system-wide in
  iOS 26 / macOS Tahoe 26. The residual risk is not modern browsers but (a) clients predating those
  versions and (b) TLS-inspecting corporate middleboxes, where the *proxy's* stack must support
  ML-KEM-768 — undetectable from outside such a network.

  Certs are not generated: mount operator/CA-issued ones at `/etc/envoy/certs/`.

  The image pin is load-bearing rather than hygiene. Verified against real containers:

  | image | result |
  | --- | --- |
  | `envoyproxy/envoy:v1.31.2` | refuses to start — `Failed to initialize ECDH curves X25519MLKEM768` |
  | `envoyproxy/envoy:v1.38.3` | `Negotiated TLS1.3 group: X25519MLKEM768`, ALPN `h2`; a classical-only client gets `handshake failure` |
- **`client.js`** — a dependency-free gRPC-web client (hand-framed `application/grpc-web+proto`): it
  exercises the real wire format (5-byte framing, trailers) rather than a generated stub, so a
  regression in Envoy's translation or the service contract fails the smoke.

## Runtime / tooling

- **Apple `container`** (native arm64 VMs on Apple Silicon — no QEMU). `run.sh` uses `container`
  primitives directly.
- **Networking.** apple/container resolves container names only under an **admin-created DNS domain**
  (`sudo container system dns create …`). To avoid requiring sudo, `run.sh` wires the two hops by
  **container IP** on a shared network and substitutes the server IP into the Envoy config at runtime.
  `compose.yaml` is the declarative equivalent (service-name DNS) for `docker compose` or an
  apple/container setup that has a DNS domain configured.
- **Pinned:** `envoyproxy/envoy:v1.38.3`, `eclipse-temurin:26-jre`, `node:22-bookworm-slim`
  (Constitution XI). The server is staged as a plain `lib/` of jars (`sbt transport/stageServer`)
  because sbt-native-packager has no sbt-2 build yet.

## DEV posture (Constitution IV)

The backend is the dev in-memory `ObliviousStore` — **NO metadata privacy** (the server logs that
label on startup). This harness validates the transport wiring only; it confers no privacy.

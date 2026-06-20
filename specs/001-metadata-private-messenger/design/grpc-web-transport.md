# Design / Deployment: Browser ↔ Server gRPC-web Transport (T032c)

**Status**: deployment design + Envoy config (NOT CI-tested — needs a running server + proxy). The
engine side (`JsTransport` contract) and the JVM side (`GrpcRoundTransport` against real `obsd`) are
both proven in CI; this is the network glue that backs `JsTransport` in a browser.
**Relates to**: T032b (the `JsTransport` host-staging contract), T020 (the gRPC server), the
`contracts/*.proto` services.

## The path

```
Flutter web (browser tab)
  └─ ProtocolEngine  (Scala.js bundle: engine.Engine over a JsTransport)
       └─ gRPC-web host transport  (implements JsTransport; this document)
            └─ HTTP/1.1 gRPC-web ──► Envoy ──► HTTP/2 gRPC ──► Scala server (RoundService etc.)
                                                                   └─ obsd (oblivious sidecar)
```

A browser cannot speak raw gRPC (it needs HTTP/2 trailers it can't set), so **Envoy** translates
gRPC-web ⇄ gRPC. The Scala server and `obsd` are unchanged — they already serve the
`ObliviousStore` and `NotificationService` the JVM `GrpcRoundTransport` uses.

## The hard part: a synchronous engine over async network

`engine.Engine.tick` calls the transport **synchronously** (`fetchDigest`/`submit`/`retrieve` all
return immediately). Browser gRPC-web is **async** (Promises). Worse, the read token the engine
passes to `retrieve` is computed *inside* `tick` from the digest, so the host cannot simply
pre-fetch it. Two supported resolutions:

### Option A — engine in a Web Worker, sync-over-async via SharedArrayBuffer (recommended)

Run the Scala.js engine in a **Web Worker**. The worker's `JsTransport` is synchronous: each call
writes a request into a `SharedArrayBuffer` and **blocks** on `Atomics.wait`. The **main thread**
observes the request, performs the async gRPC-web call via Envoy, writes the response back, and
`Atomics.notify`s the worker. This is the standard "sync API over async I/O" shim (Emscripten,
WASI). The engine stays unchanged; `tick` runs to completion on the worker.

- Requires the page be **cross-origin isolated** (`COOP: same-origin` + `COEP: require-corp`) for
  `SharedArrayBuffer`. (Documented; a deployment header requirement.)
- One round = at most three blocking calls (fetchDigest, submit, retrieve) — bounded.

### Option B — split `tick` into plan/apply (no worker, needs an engine API addition)

Add a two-phase round API: `planRound(roundId) → { readToken, writeToken, writeFrame }` (sync,
derives the tokens), the host does the async gRPC-web I/O, then `applyRound(digest, readResult) →
events` (sync, processes). The host orchestrates the await between. Cleaner for async backends but
is a new engine surface; tracked as a follow-up if Option A's isolation requirement is undesirable.

## JsTransport ⇄ gRPC mapping

The host transport implements the `JsTransport` contract (T032b) by calling the proxied services:

| `JsTransport` | gRPC call | Request → response |
|---|---|---|
| `submit(token, frame)` | `ObliviousStore.WriteBatch` | one `WriteEntry{write_token, frame}` (256B) → `true` iff accepted |
| `fetchDigest(round, label)` | `NotificationService.FetchDigest` | `{round_id, client_label}` → `digest` bytes |
| `retrieve(token)` | `ObliviousStore.ReadBatch` | one `ReadEntry{retrieval_token}` → `sealed_result`; `null` on miss |

Every round issues exactly one of each regardless of real-message presence (the engine's cover
traffic, FR-012), so the gRPC-web call pattern an observer sees is itself uniform.

### Reference host transport (TypeScript, over connect-web)

```ts
// Runs on the MAIN thread; the worker's synchronous JsTransport relays to this via the SAB shim.
import { createPromiseClient } from "@connectrpc/connect";
import { createGrpcWebTransport } from "@connectrpc/connect-web";
import { ObliviousStore } from "./gen/store_connect";
import { NotificationService } from "./gen/notify_connect";

const t = createGrpcWebTransport({ baseUrl: "https://mm.example/grpc" }); // → Envoy
const store  = createPromiseClient(ObliviousStore, t);
const notify = createPromiseClient(NotificationService, t);

export const hostTransport = {
  async submit(token: Uint8Array, frame: Uint8Array): Promise<boolean> {
    await store.writeBatch({ roundId, batchSize: 1, entries: [{ writeToken: token, frame }] });
    return true; // WriteBatch is all-or-nothing per the contract
  },
  async fetchDigest(roundId: bigint, clientLabel: Uint8Array): Promise<Uint8Array> {
    return (await notify.fetchDigest({ roundId, clientLabel })).digest;
  },
  async retrieve(token: Uint8Array): Promise<Uint8Array | null> {
    const r = await store.readBatch({ roundId, batchSize: 1, entries: [{ retrievalToken: token }] });
    return foundTag(r.results[0].sealedResult) ? frameOf(r.results[0].sealedResult) : null;
  },
};
```

The synchronous `JsTransport` the engine sees is a thin SAB/Atomics relay onto these async calls.

## Envoy

`deploy/envoy/envoy.yaml` (in this repo) terminates gRPC-web from the browser and forwards gRPC to
the Scala server, with the `envoy.filters.http.grpc_web` filter and CORS for the app origin. TLS is
terminated at Envoy (or upstream). The server cluster points at the Scala gRPC port.

## Security notes (do not regress)

- The transport moves **opaque bytes** only — it never sees plaintext or keys (the engine encrypts
  every frame, T042; tokens are derived in `protocol-core`).
- The labeling rule still holds: until the backend is **attested** (Constitution IX), the engine
  reports `DEV, NO METADATA PRIVACY`. Reaching a server over gRPC-web does NOT by itself make the
  build metadata-private — that requires the attested enclave path.
- CORS is restricted to the app origin; the digest/read/write batch sizes are public and uniform
  by construction (cover traffic), so the gRPC-web traffic shape leaks nothing.

## What is NOT covered here (CI)

A full browser → Envoy → server → obsd round-trip needs all four running, so it is not part of CI
(which proves the engine, the `JsTransport` bridge under Node, and `GrpcRoundTransport` against real
`obsd` separately). A docker-compose smoke harness wiring them together is the natural follow-up.

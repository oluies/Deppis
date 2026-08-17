//! obsd — the oblivious-sidecar gRPC server: serves the PONG `ObliviousStore` and, by default, the
//! PING `NotificationService` over gRPC. DEV build: provides NO metadata privacy outside the SGX
//! enclave (Constitution IV); uses a dev notification key.
//!
//! # `OBSD_SERVICES` — why you would turn the notify half OFF
//!
//! `both` (default) keeps the historical single-process behaviour that the demo and the existing
//! integration tests rely on. `store` serves the PONG store ONLY, which is what a deployment running
//! the notify front as its own process (`pingd`) must use.
//!
//! The reason is a trust boundary, not tidiness. PING/PONG's unlinkability argument assumes the
//! party that sees *which token was written* is not the party that sees *whose bit was set*. One
//! process holding both can join them — "a write landed at round r" ∧ "label L's bit was set at
//! round r" re-identifies the receiver of every real frame — and no amount of obliviousness inside
//! either service repairs a leak that lives in the join. See `pingd.rs` for the full note, including
//! why two processes are necessary but NOT sufficient (they must also end up in distinct attested
//! trust domains, which is the rest of Phase C and is not delivered yet).

use oblivious_sidecar::env::{hex_key_osvar, serve_notify_osvar, KeyVar};
use oblivious_sidecar::grpc::pb::oblivious_store_server::ObliviousStoreServer;
use oblivious_sidecar::grpc::StoreService;
use oblivious_sidecar::grpc_notify::pb::notification_service_server::NotificationServiceServer;
use oblivious_sidecar::grpc_notify::NotificationServer;
use oblivious_sidecar::store::ObliviousStore;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("OBSD_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50051".to_string())
        .parse()?;
    let capacity = std::env::var("OBSD_CAPACITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4096usize);
    // Resolve the ROLE first. The notify key is only read inside the notify branch below, so the
    // split deployment (`OBSD_SERVICES=store`) — the shape this binary exists to support — neither
    // warns about a dev key it will never construct nor dies on a malformed key it will never touch.
    // A dev-key warning that fires in the CORRECT deployment is a warning operators learn to ignore.
    //
    // Parsed in the library so the fail-closed branch is unit-testable (`env::serve_notify_osvar`);
    // it was previously inlined here and therefore had no test on either side. `var_os`, not `var`:
    // `var(..).ok()` maps a set-but-non-UTF-8 value to `None`, which would take the `Ok(true)`
    // default and re-co-host the notify front instead of failing closed.
    let serve_notify_flag = match serve_notify_osvar(std::env::var_os("OBSD_SERVICES").as_deref()) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("obsd: {msg}");
            std::process::exit(2);
        }
    };

    let store = Arc::new(Mutex::new(ObliviousStore::with_capacity(capacity)));
    let builder = tonic::transport::Server::builder()
        .add_service(ObliviousStoreServer::new(StoreService::new(store)));

    if serve_notify_flag {
        // Fail closed on a malformed key for the same reason an unknown OBSD_SERVICES fails closed —
        // see `env::hex_key_var`. Silently substituting the published dev key is the worse outcome.
        let notify_key = match hex_key_osvar(std::env::var_os("OBSD_NOTIFY_KEY").as_deref()) {
            KeyVar::Parsed(k) => k,
            KeyVar::Unset => {
                eprintln!("obsd: OBSD_NOTIFY_KEY unset — using the DEV key (not secret, dev only)");
                [0x01u8; 32]
            }
            KeyVar::Malformed => {
                eprintln!(
                    "obsd: OBSD_NOTIFY_KEY is set but is not 64 hex chars — refusing to start"
                );
                std::process::exit(2);
            }
        };
        eprintln!(
            "obsd: serving ObliviousStore (capacity {capacity}) + NotificationService on {addr} — DEV, NO METADATA PRIVACY"
        );
        eprintln!(
            "obsd: NOTE both PING and PONG are in ONE process — a deployment should split them (OBSD_SERVICES=store + pingd)"
        );
        builder
            .add_service(NotificationServiceServer::new(NotificationServer::new(
                notify_key,
            )))
            .serve(addr)
            .await?;
    } else {
        eprintln!(
            "obsd: serving ObliviousStore ONLY (capacity {capacity}) on {addr} — DEV, NO METADATA PRIVACY"
        );
        eprintln!("obsd: run the notify front separately (pingd)");
        builder.serve(addr).await?;
    }
    Ok(())
}

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

use oblivious_sidecar::grpc::pb::oblivious_store_server::ObliviousStoreServer;
use oblivious_sidecar::grpc::StoreService;
use oblivious_sidecar::grpc_notify::pb::notification_service_server::NotificationServiceServer;
use oblivious_sidecar::grpc_notify::NotificationServer;
use oblivious_sidecar::store::ObliviousStore;
use std::sync::{Arc, Mutex};

/// Parse a 64-hex-char env var into a 32-byte key.
fn hex_key(var: &str) -> Option<[u8; 32]> {
    let s = std::env::var(var).ok()?;
    if s.len() != 64 || !s.is_ascii() {
        return None; // is_ascii ensures 1 byte per char, so the slicing below can't split a char
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("OBSD_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50051".to_string())
        .parse()?;
    let capacity = std::env::var("OBSD_CAPACITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4096usize);
    let notify_key = hex_key("OBSD_NOTIFY_KEY").unwrap_or([0x01u8; 32]);
    // Unknown values FAIL rather than silently defaulting to `both`: a typo in a deployment unit
    // (`OBSD_SERVICES=stor`) would otherwise re-co-host the notify front and quietly reinstate the
    // very correlation the split exists to remove — a privacy regression that starts up clean.
    let services = std::env::var("OBSD_SERVICES").unwrap_or_else(|_| "both".to_string());
    let serve_notify = match services.as_str() {
        "both" => true,
        "store" => false,
        other => {
            eprintln!("obsd: OBSD_SERVICES must be `both` or `store`, got `{other}`");
            std::process::exit(2);
        }
    };

    let store = Arc::new(Mutex::new(ObliviousStore::with_capacity(capacity)));
    let builder = tonic::transport::Server::builder()
        .add_service(ObliviousStoreServer::new(StoreService::new(store)));

    if serve_notify {
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

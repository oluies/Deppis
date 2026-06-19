//! obsd — the oblivious-sidecar gRPC server: serves the PONG `ObliviousStore` and the PING
//! `NotificationService` over gRPC. DEV build: provides NO metadata privacy outside the SGX
//! enclave (Constitution IV); uses a dev notification key.

use oblivious_sidecar::grpc::pb::oblivious_store_server::ObliviousStoreServer;
use oblivious_sidecar::grpc::StoreService;
use oblivious_sidecar::grpc_notify::pb::notification_service_server::NotificationServiceServer;
use oblivious_sidecar::grpc_notify::NotificationServer;
use oblivious_sidecar::store::ObliviousStore;
use std::sync::{Arc, Mutex};

/// Parse a 64-hex-char env var into a 32-byte key.
fn hex_key(var: &str) -> Option<[u8; 32]> {
    let s = std::env::var(var).ok()?;
    if s.len() != 64 {
        return None;
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

    let store = Arc::new(Mutex::new(ObliviousStore::with_capacity(capacity)));
    eprintln!(
        "obsd: serving ObliviousStore (capacity {capacity}) + NotificationService on {addr} — DEV, NO METADATA PRIVACY"
    );

    tonic::transport::Server::builder()
        .add_service(ObliviousStoreServer::new(StoreService::new(store)))
        .add_service(NotificationServiceServer::new(NotificationServer::new(
            notify_key,
        )))
        .serve(addr)
        .await?;
    Ok(())
}

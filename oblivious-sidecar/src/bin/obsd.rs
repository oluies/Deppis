//! obsd — the oblivious-sidecar gRPC server: serves the PONG `ObliviousStore` over `store.proto`.
//! DEV build: provides NO metadata privacy outside the SGX enclave (Constitution IV).

use oblivious_sidecar::grpc::pb::oblivious_store_server::ObliviousStoreServer;
use oblivious_sidecar::grpc::StoreService;
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

    let store = Arc::new(Mutex::new(ObliviousStore::with_capacity(capacity)));
    eprintln!(
        "obsd: serving ObliviousStore (capacity {capacity}) on {addr} — DEV, NO METADATA PRIVACY"
    );

    tonic::transport::Server::builder()
        .add_service(ObliviousStoreServer::new(StoreService::new(store)))
        .serve(addr)
        .await?;
    Ok(())
}

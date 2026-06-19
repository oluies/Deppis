//! gRPC sidecar services over the oblivious primitives (the real native PONG/PING sidecar the
//! Scala server calls; the privacy claim still requires running inside the SGX enclave).

use crate::store::{ObliviousStore, FRAME_LEN, TOKEN_LEN};
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

/// Generated types for `store.proto` (`metadatamessenger.store.v1`).
pub mod pb {
    tonic::include_proto!("metadatamessenger.store.v1");
}

use pb::oblivious_store_server::ObliviousStore as ObliviousStoreSvc;
use pb::{ReadBatchRequest, ReadBatchResponse, ReadResult, WriteBatchRequest, WriteBatchResponse};

/// Copy up to `N` bytes from `src` into a fixed array (zero-padded / truncated).
fn fixed<const N: usize>(src: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = src.len().min(N);
    out[..n].copy_from_slice(&src[..n]);
    out
}

/// gRPC front for the oblivious PONG store. Holds the store behind a `Mutex` (writes/reads mutate
/// the slot table). Every read returns a fixed-size `sealed_result = frame ‖ found-tag`, so
/// hit-vs-miss is not observable in transit (it lives in the sealed blob).
pub struct StoreService {
    store: Arc<Mutex<ObliviousStore>>,
}

impl StoreService {
    pub fn new(store: Arc<Mutex<ObliviousStore>>) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl ObliviousStoreSvc for StoreService {
    async fn write_batch(
        &self,
        req: Request<WriteBatchRequest>,
    ) -> Result<Response<WriteBatchResponse>, Status> {
        let req = req.into_inner();
        let mut store = self
            .store
            .lock()
            .map_err(|_| Status::internal("store unavailable"))?;
        for e in &req.entries {
            let token: [u8; TOKEN_LEN] = fixed(&e.write_token);
            let frame: [u8; FRAME_LEN] = fixed(&e.frame);
            // A full store silently drops (dev); the store enforces non-recurrence.
            let _ = store.write(&token, &frame);
        }
        Ok(Response::new(WriteBatchResponse {
            round_id: req.round_id,
        }))
    }

    async fn read_batch(
        &self,
        req: Request<ReadBatchRequest>,
    ) -> Result<Response<ReadBatchResponse>, Status> {
        let req = req.into_inner();
        let mut store = self
            .store
            .lock()
            .map_err(|_| Status::internal("store unavailable"))?;
        let results = req
            .entries
            .iter()
            .map(|e| {
                let token: [u8; TOKEN_LEN] = fixed(&e.retrieval_token);
                let (frame, found) = store.read_sealed(&token);
                // sealed_result = frame (256B) ‖ found tag (1B): uniform 257-byte length.
                let mut sealed = Vec::with_capacity(FRAME_LEN + 1);
                sealed.extend_from_slice(&frame);
                sealed.push(u8::from(found));
                ReadResult {
                    sealed_result: sealed,
                }
            })
            .collect();
        Ok(Response::new(ReadBatchResponse {
            round_id: req.round_id,
            results,
        }))
    }
}

//! gRPC sidecar services over the oblivious primitives (the real native PONG/PING sidecar the
//! Scala server calls; the privacy claim still requires running inside the SGX enclave).

// tonic::Status is large by design; returning it in Result is the standard gRPC signature, so
// boxing every error would only add noise.
#![allow(clippy::result_large_err)]

use crate::store::{ObliviousStore, FRAME_LEN, TOKEN_LEN};
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

/// Generated types for `store.proto` (`metadatamessenger.store.v1`).
pub mod pb {
    tonic::include_proto!("metadatamessenger.store.v1");
}

use pb::oblivious_store_server::ObliviousStore as ObliviousStoreSvc;
use pb::{ReadBatchRequest, ReadBatchResponse, ReadResult, WriteBatchRequest, WriteBatchResponse};

/// Require `src` to be exactly `N` bytes (a public-size check — content-independent, so it does
/// not weaken the oblivious invariant). Rejects malformed/short fields rather than reshaping them.
fn exact<const N: usize>(src: &[u8], field: &str) -> Result<[u8; N], Status> {
    if src.len() != N {
        return Err(Status::invalid_argument(format!(
            "{field} must be {N} bytes, got {}",
            src.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(src);
    Ok(out)
}

/// The declared `batch_size` (public) must match the number of entries actually sent.
fn check_batch(declared: u32, actual: usize) -> Result<(), Status> {
    if declared as usize != actual {
        return Err(Status::invalid_argument(format!(
            "batch_size {declared} does not match {actual} entries"
        )));
    }
    Ok(())
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
        check_batch(req.batch_size, req.entries.len())?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| Status::internal("store unavailable"))?;
        for e in &req.entries {
            let token = exact::<TOKEN_LEN>(&e.write_token, "write_token")?;
            let frame = exact::<FRAME_LEN>(&e.frame, "frame")?;
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
        check_batch(req.batch_size, req.entries.len())?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| Status::internal("store unavailable"))?;
        let mut results = Vec::with_capacity(req.entries.len());
        for e in &req.entries {
            let token = exact::<TOKEN_LEN>(&e.retrieval_token, "retrieval_token")?;
            let (frame, found) = store.read_sealed(&token);
            // sealed_result = frame (256B) ‖ found tag (1B): uniform 257-byte length. NOTE: this
            // DEV impl returns CLEARTEXT (frame+tag), so hit/miss is distinguishable by content to
            // the store host — acceptable only under the DEV/NO-METADATA-PRIVACY label. Only the
            // enclave-target impl produces a genuinely sealed, content-uniform blob.
            let mut sealed = Vec::with_capacity(FRAME_LEN + 1);
            sealed.extend_from_slice(&frame);
            sealed.push(u8::from(found));
            results.push(ReadResult {
                sealed_result: sealed,
            });
        }
        Ok(Response::new(ReadBatchResponse {
            round_id: req.round_id,
            results,
        }))
    }
}

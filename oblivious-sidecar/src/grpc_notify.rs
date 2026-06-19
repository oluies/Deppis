//! gRPC PING notification service: opens receiver-sealed tokens (AEAD) and aggregates them
//! obliviously per round. The sidecar is the enclave in deployment; this DEV build provides NO
//! metadata privacy (Constitution IV) and uses a dev server key.

// tonic::Status is large by design; returning it in Result is the standard gRPC signature.
#![allow(clippy::result_large_err)]

use crate::notify::{oblivious_aggregate, Signal, DIGEST_BYTES, MAX_BIT};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use std::collections::HashMap;
use std::sync::Mutex;
use tonic::{Request, Response, Status};

/// Generated types for `notify.proto` (`metadatamessenger.notify.v1`).
pub mod pb {
    tonic::include_proto!("metadatamessenger.notify.v1");
}

use pb::notification_service_server::NotificationService as NotificationSvcTrait;
use pb::{FetchDigestRequest, FetchDigestResponse, SignalRequest, SignalResponse};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const RETENTION_ROUNDS: u64 = 16;

/// FNV-1a hash of the (public) aggregation label to a u64 key for the oblivious aggregator. Labels
/// are public tags, not secrets, so a non-cryptographic hash is appropriate; 64 bits has no
/// practical collision for the buddy-scale label space.
fn label_key(label: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in label {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

struct State {
    rounds: HashMap<u64, Vec<Signal>>,
    max_round: u64,
}

/// PING notification server. Holds the server key (to open sealed tokens) and per-round decoded
/// signals; aggregation is recomputed obliviously on fetch. Map growth is bounded by a sliding
/// retention window.
pub struct NotificationServer {
    cipher: ChaCha20Poly1305,
    state: Mutex<State>,
}

impl NotificationServer {
    pub fn new(server_key: [u8; 32]) -> Self {
        NotificationServer {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&server_key)),
            state: Mutex::new(State {
                rounds: HashMap::new(),
                max_round: 0,
            }),
        }
    }
}

#[tonic::async_trait]
impl NotificationSvcTrait for NotificationServer {
    async fn signal(
        &self,
        req: Request<SignalRequest>,
    ) -> Result<Response<SignalResponse>, Status> {
        let req = req.into_inner();
        // Open the sealed token; a forged/tampered/short token is silently dropped (uniform
        // response — token validity is never leaked to the submitter, FR-003). AEAD authentication
        // is what stops flooding/impersonation: only a correctly-sealed token decodes.
        if req.sealed_token.len() >= NONCE_LEN + TAG_LEN {
            let (nonce, ct) = req.sealed_token.split_at(NONCE_LEN);
            if let Ok(pt) = self.cipher.decrypt(Nonce::from_slice(nonce), ct) {
                if pt.len() >= 2 {
                    let bit = ((pt[0] as u16) << 8) | (pt[1] as u16);
                    if bit < MAX_BIT {
                        let label = label_key(&pt[2..]);
                        let mut st = self
                            .state
                            .lock()
                            .map_err(|_| Status::internal("unavailable"))?;
                        if req.round_id > st.max_round {
                            st.max_round = req.round_id;
                            let min = st.max_round.saturating_sub(RETENTION_ROUNDS);
                            st.rounds.retain(|&r, _| r >= min);
                        }
                        st.rounds
                            .entry(req.round_id)
                            .or_default()
                            .push(Signal { label, bit });
                    }
                }
            }
        }
        Ok(Response::new(SignalResponse {
            round_id: req.round_id,
        }))
    }

    async fn fetch_digest(
        &self,
        req: Request<FetchDigestRequest>,
    ) -> Result<Response<FetchDigestResponse>, Status> {
        let req = req.into_inner();
        let client = label_key(&req.client_label);
        let st = self
            .state
            .lock()
            .map_err(|_| Status::internal("unavailable"))?;
        let digest = match st.rounds.get(&req.round_id) {
            // oblivious aggregation: scans every signal for the client identically (carrier on none)
            Some(signals) => oblivious_aggregate(signals, &[client]).remove(0),
            None => [0u8; DIGEST_BYTES],
        };
        Ok(Response::new(FetchDigestResponse {
            round_id: req.round_id,
            digest: digest.to_vec(),
        }))
    }
}

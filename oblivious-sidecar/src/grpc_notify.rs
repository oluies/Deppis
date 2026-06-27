//! gRPC PING notification service: opens receiver-sealed tokens (AEAD) and aggregates them
//! obliviously per round. The sidecar is the enclave in deployment; this DEV build provides NO
//! metadata privacy (Constitution IV) and uses a dev server key.

// tonic::Status is large by design; returning it in Result is the standard gRPC signature.
#![allow(clippy::result_large_err)]

use crate::notify::{oblivious_aggregate, Signal, DIGEST_BYTES, MAX_BIT};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use tonic::{Request, Response, Status};

/// Generated types for `notify.proto` (`metadatamessenger.notify.v1`).
pub mod pb {
    // tonic 0.14 codegen emits doc comments that trip clippy::doc_lazy_continuation (generated code).
    #![allow(clippy::doc_lazy_continuation)]
    tonic::include_proto!("metadatamessenger.notify.v1");
}

use pb::notification_service_server::NotificationService as NotificationSvcTrait;
use pb::{FetchDigestRequest, FetchDigestResponse, SignalRequest, SignalResponse};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Bounded retention: keep the most-recently-INSERTED rounds, evicted in insertion order (NOT by
/// round_id arithmetic, which would let a large round_id wipe legitimate rounds). A memory backstop.
const MAX_ROUNDS: usize = 1024;
/// Per-round signal cap: bounds memory/CPU against same-round token replay (round binding stops
/// cross-round replay; a token replayed within its own round just re-ORs the same bit).
const MAX_SIGNALS_PER_ROUND: usize = 8192;

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
    order: VecDeque<u64>, // round-id insertion order, for bounded eviction
}

/// PING notification server. Holds the server key (to open sealed tokens) and per-round decoded
/// signals; aggregation is recomputed obliviously on fetch.
///
/// The `round_id` is BOUND into the sealed plaintext ([round][bit][label]) and validated on signal,
/// so a captured token cannot be replayed into a different round — this closes the round-eviction
/// replay DoS. Insertion-order round eviction + a per-round signal cap remain as memory/CPU
/// backstops (e.g. against same-round replay, which is idempotent OR'ing).
pub struct NotificationServer {
    cipher: ChaCha20Poly1305,
    state: Mutex<State>,
    max_rounds: usize,
    max_signals_per_round: usize,
}

impl NotificationServer {
    pub fn new(server_key: [u8; 32]) -> Self {
        Self::with_limits(server_key, MAX_ROUNDS, MAX_SIGNALS_PER_ROUND)
    }

    /// Construct with explicit bounds (used by tests to exercise eviction/cap cheaply).
    pub fn with_limits(
        server_key: [u8; 32],
        max_rounds: usize,
        max_signals_per_round: usize,
    ) -> Self {
        NotificationServer {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&server_key)),
            state: Mutex::new(State {
                rounds: HashMap::new(),
                order: VecDeque::new(),
            }),
            max_rounds,
            max_signals_per_round,
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
        // Open the sealed token; a forged/tampered/short token, or one whose bound round != this
        // signal's round, is silently dropped (uniform response — validity is never leaked, FR-003).
        // AEAD stops forgery (can't craft another buddy's bit); the bound round stops cross-round
        // replay; the per-round cap bounds same-round replay.
        if req.sealed_token.len() >= NONCE_LEN + TAG_LEN {
            let (nonce, ct) = req.sealed_token.split_at(NONCE_LEN);
            if let Ok(pt) = self.cipher.decrypt(Nonce::from_slice(nonce), ct) {
                // plaintext = [round(8 BE)][bit(2 BE)][label]
                if pt.len() >= 10 {
                    let round = u64::from_be_bytes(pt[0..8].try_into().unwrap());
                    let bit = ((pt[8] as u16) << 8) | (pt[9] as u16);
                    // round binding: a token sealed for a DIFFERENT round cannot be replayed here.
                    if round == req.round_id && bit < MAX_BIT {
                        let label = label_key(&pt[10..]);
                        let mut st = self
                            .state
                            .lock()
                            .map_err(|_| Status::internal("unavailable"))?;
                        if let Some(sigs) = st.rounds.get_mut(&req.round_id) {
                            // existing round: cap signals per round (replay/flood bound)
                            if sigs.len() < self.max_signals_per_round {
                                sigs.push(Signal { label, bit });
                            }
                        } else {
                            // new round: insert and evict the oldest-inserted round if over the cap
                            st.rounds.insert(req.round_id, vec![Signal { label, bit }]);
                            st.order.push_back(req.round_id);
                            if st.order.len() > self.max_rounds {
                                if let Some(old) = st.order.pop_front() {
                                    st.rounds.remove(&old);
                                }
                            }
                        }
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

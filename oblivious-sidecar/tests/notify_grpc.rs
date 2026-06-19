use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use oblivious_sidecar::grpc_notify::pb::notification_service_server::NotificationService as _;
use oblivious_sidecar::grpc_notify::pb::{FetchDigestRequest, SignalRequest};
use oblivious_sidecar::grpc_notify::NotificationServer;
use oblivious_sidecar::notify::{DIGEST_BYTES, MAX_BIT};
use tonic::Request;

const KEY: [u8; 32] = [9u8; 32];

/// Seal a token the way the Scala receiver does: nonce(12) ‖ ChaCha20-Poly1305(key, serialize),
/// where serialize = [8-byte big-endian round][2-byte big-endian bit][label]. (Interop + the round
/// binding that prevents cross-round replay.)
fn seal(round: u64, bit: u16, label: &[u8], nonce_seed: u8) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&KEY));
    let nonce = [nonce_seed; 12];
    let mut pt = round.to_be_bytes().to_vec();
    pt.push((bit >> 8) as u8);
    pt.push((bit & 0xff) as u8);
    pt.extend_from_slice(label);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), pt.as_ref())
        .unwrap();
    let mut sealed = nonce.to_vec();
    sealed.extend(ct);
    sealed
}

fn bit_set(digest: &[u8], b: u16) -> bool {
    (digest[(b >> 3) as usize] >> (b & 7)) & 1 == 1
}

async fn fetch(svc: &NotificationServer, round: u64, label: &[u8]) -> Vec<u8> {
    svc.fetch_digest(Request::new(FetchDigestRequest {
        round_id: round,
        client_label: label.to_vec(),
    }))
    .await
    .unwrap()
    .into_inner()
    .digest
}

async fn signal(svc: &NotificationServer, round: u64, sealed_token: Vec<u8>) {
    svc.signal(Request::new(SignalRequest {
        round_id: round,
        sealed_token,
    }))
    .await
    .unwrap();
}

#[tokio::test]
async fn signal_then_fetch_reports_the_bit() {
    let svc = NotificationServer::new(KEY);
    signal(&svc, 1, seal(1, 5, b"alice", 1)).await;
    let d = fetch(&svc, 1, b"alice").await;
    assert_eq!(d.len(), DIGEST_BYTES);
    assert!(bit_set(&d, 5));
}

#[tokio::test]
async fn two_buddies_one_label_or_into_the_digest() {
    let svc = NotificationServer::new(KEY);
    signal(&svc, 1, seal(1, 3, b"alice", 1)).await;
    signal(&svc, 1, seal(1, 9, b"alice", 2)).await;
    let d = fetch(&svc, 1, b"alice").await;
    assert!(bit_set(&d, 3) && bit_set(&d, 9));
}

#[tokio::test]
async fn forged_token_sets_no_bit_with_uniform_response() {
    let svc = NotificationServer::new(KEY);
    let resp = svc
        .signal(Request::new(SignalRequest {
            round_id: 2,
            sealed_token: vec![0u8; 40],
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.round_id, 2); // uniform success, no validity leaked
    assert!(fetch(&svc, 2, b"alice").await.iter().all(|&b| b == 0)); // carrier
}

#[tokio::test]
async fn a_token_bound_to_one_round_is_rejected_in_another() {
    let svc = NotificationServer::new(KEY);
    let tok = seal(1, 3, b"alice", 1); // bound to round 1
    signal(&svc, 2, tok.clone()).await; // replay to round 2
    assert!(fetch(&svc, 2, b"alice").await.iter().all(|&b| b == 0)); // dropped (round mismatch)
    signal(&svc, 1, tok).await; // valid in its own round
    assert!(bit_set(&fetch(&svc, 1, b"alice").await, 3));
}

#[tokio::test]
async fn a_huge_round_id_does_not_wipe_existing_rounds() {
    let svc = NotificationServer::new(KEY);
    signal(&svc, 1, seal(1, 3, b"alice", 1)).await;
    signal(&svc, u64::MAX, seal(u64::MAX, 7, b"alice", 2)).await;
    assert!(bit_set(&fetch(&svc, 1, b"alice").await, 3)); // round 1 NOT wiped
    assert!(bit_set(&fetch(&svc, u64::MAX, b"alice").await, 7)); // high-bit round-bound token accepted
}

#[tokio::test]
async fn out_of_range_bit_is_dropped_not_panicked() {
    let svc = NotificationServer::new(KEY);
    signal(&svc, 1, seal(1, MAX_BIT, b"alice", 1)).await; // bit == MAX_BIT (512) out of range
    assert!(fetch(&svc, 1, b"alice").await.iter().all(|&b| b == 0));
}

#[tokio::test]
async fn fifo_eviction_drops_the_oldest_round() {
    let svc = NotificationServer::with_limits(KEY, 2, 100); // keep only 2 rounds
    for r in 1..=3u64 {
        signal(&svc, r, seal(r, 3, b"alice", r as u8)).await;
    }
    assert!(fetch(&svc, 1, b"alice").await.iter().all(|&b| b == 0)); // oldest evicted
    assert!(bit_set(&fetch(&svc, 2, b"alice").await, 3));
    assert!(bit_set(&fetch(&svc, 3, b"alice").await, 3));
}

#[tokio::test]
async fn per_round_cap_drops_excess_signals() {
    let svc = NotificationServer::with_limits(KEY, 100, 2); // cap 2 signals per round
    signal(&svc, 1, seal(1, 3, b"alice", 1)).await;
    signal(&svc, 1, seal(1, 5, b"alice", 2)).await;
    signal(&svc, 1, seal(1, 7, b"alice", 3)).await;
    let d = fetch(&svc, 1, b"alice").await;
    assert!(bit_set(&d, 3) && bit_set(&d, 5) && !bit_set(&d, 7)); // 3rd signal dropped by the cap
}

#[tokio::test]
async fn rounds_are_isolated() {
    let svc = NotificationServer::new(KEY);
    signal(&svc, 1, seal(1, 3, b"alice", 7)).await;
    assert!(fetch(&svc, 2, b"alice").await.iter().all(|&b| b == 0)); // round 2 empty
    assert!(bit_set(&fetch(&svc, 1, b"alice").await, 3)); // round 1 retained
}

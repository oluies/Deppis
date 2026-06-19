use oblivious_sidecar::grpc::pb::oblivious_store_server::ObliviousStore as _;
use oblivious_sidecar::grpc::pb::{ReadBatchRequest, ReadEntry, WriteBatchRequest, WriteEntry};
use oblivious_sidecar::grpc::StoreService;
use oblivious_sidecar::store::{ObliviousStore, FRAME_LEN, TOKEN_LEN};
use std::sync::{Arc, Mutex};
use tonic::Request;

fn svc(capacity: usize) -> StoreService {
    StoreService::new(Arc::new(Mutex::new(ObliviousStore::with_capacity(
        capacity,
    ))))
}

#[tokio::test]
async fn write_then_read_carries_found_tag_and_is_single_use() {
    let s = svc(8);
    let tok = vec![7u8; TOKEN_LEN];
    let frame = vec![42u8; FRAME_LEN];

    s.write_batch(Request::new(WriteBatchRequest {
        round_id: 1,
        batch_size: 1,
        entries: vec![WriteEntry {
            write_token: tok.clone(),
            frame: frame.clone(),
        }],
    }))
    .await
    .unwrap();

    // batch read: one hit (tok) + one miss (other token)
    let resp = s
        .read_batch(Request::new(ReadBatchRequest {
            round_id: 1,
            batch_size: 2,
            entries: vec![
                ReadEntry {
                    retrieval_token: tok.clone(),
                },
                ReadEntry {
                    retrieval_token: vec![9u8; TOKEN_LEN],
                },
            ],
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.results.len(), 2);

    // hit: sealed_result = frame ‖ 1, uniform 257 bytes
    let hit = &resp.results[0].sealed_result;
    assert_eq!(hit.len(), FRAME_LEN + 1);
    assert_eq!(&hit[..FRAME_LEN], &frame[..]);
    assert_eq!(hit[FRAME_LEN], 1);

    // miss: carrier ‖ 0, same length (hit/miss not observable from length)
    let miss = &resp.results[1].sealed_result;
    assert_eq!(miss.len(), FRAME_LEN + 1);
    assert!(miss[..FRAME_LEN].iter().all(|&b| b == 0));
    assert_eq!(miss[FRAME_LEN], 0);

    // single-use: re-reading tok now misses (found tag = 0)
    let resp2 = s
        .read_batch(Request::new(ReadBatchRequest {
            round_id: 1,
            batch_size: 1,
            entries: vec![ReadEntry {
                retrieval_token: tok,
            }],
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp2.results[0].sealed_result[FRAME_LEN], 0);
}

#[tokio::test]
async fn rejects_wrong_token_length() {
    let s = svc(4);
    let r = s
        .read_batch(Request::new(ReadBatchRequest {
            round_id: 0,
            batch_size: 1,
            entries: vec![ReadEntry {
                retrieval_token: vec![1u8; 8], // not TOKEN_LEN
            }],
        }))
        .await;
    assert_eq!(r.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn rejects_batch_size_mismatch() {
    let s = svc(4);
    let r = s
        .write_batch(Request::new(WriteBatchRequest {
            round_id: 0,
            batch_size: 5, // declares 5 but sends 0 entries
            entries: vec![],
        }))
        .await;
    assert_eq!(r.unwrap_err().code(), tonic::Code::InvalidArgument);
}

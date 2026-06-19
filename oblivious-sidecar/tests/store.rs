use oblivious_sidecar::store::{ObliviousStore, FRAME_LEN, TOKEN_LEN};
use proptest::prelude::*;

fn tok(b: u8) -> [u8; TOKEN_LEN] {
    [b; TOKEN_LEN]
}
fn frame(b: u8) -> [u8; FRAME_LEN] {
    [b; FRAME_LEN]
}
const CARRIER: [u8; FRAME_LEN] = [0u8; FRAME_LEN];

#[test]
fn write_then_read_returns_frame_once() {
    let mut s = ObliviousStore::with_capacity(8);
    assert!(s.write(&tok(1), &frame(7)));
    assert_eq!(s.read(&tok(1)), frame(7)); // hit
    assert_eq!(s.read(&tok(1)), CARRIER); // single-use -> carrier (FR-014)
}

#[test]
fn miss_returns_carrier_zeros() {
    let mut s = ObliviousStore::with_capacity(4);
    assert_eq!(s.read(&tok(9)), CARRIER);
}

#[test]
fn distinct_tokens_do_not_interfere() {
    let mut s = ObliviousStore::with_capacity(8);
    assert!(s.write(&tok(1), &frame(10)));
    assert!(s.write(&tok(2), &frame(20)));
    assert_eq!(s.read(&tok(2)), frame(20));
    assert_eq!(s.read(&tok(1)), frame(10));
}

#[test]
fn write_fails_when_full() {
    let mut s = ObliviousStore::with_capacity(2);
    assert!(s.write(&tok(1), &frame(1)));
    assert!(s.write(&tok(2), &frame(2)));
    assert!(!s.write(&tok(3), &frame(3))); // full
}

proptest! {
    /// Distinct tokens written then read back in arbitrary order each return their own frame; a
    /// re-read returns the carrier (single-use).
    #[test]
    fn writes_then_reads_in_any_order(ids in proptest::collection::hash_set(1u8..=200, 1..40)) {
        let ids: Vec<u8> = ids.into_iter().collect();
        let mut s = ObliviousStore::with_capacity(64);
        for &id in &ids {
            prop_assert!(s.write(&tok(id), &frame(id)));
        }
        let mut order = ids.clone();
        order.reverse();
        for &id in &order {
            prop_assert_eq!(s.read(&tok(id)), frame(id));
            prop_assert_eq!(s.read(&tok(id)), CARRIER); // consumed
        }
    }
}

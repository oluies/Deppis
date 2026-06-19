use oblivious_sidecar::primitives::{ct_select_u64, oblivious_compact, oblivious_sort, Record};
use proptest::prelude::*;
use subtle::Choice;

proptest! {
    /// ct_select_u64 picks the correct branch for each choice bit.
    #[test]
    fn ct_select_picks_correct_branch(a in any::<u64>(), b in any::<u64>()) {
        prop_assert_eq!(ct_select_u64(Choice::from(1), a, b), a);
        prop_assert_eq!(ct_select_u64(Choice::from(0), a, b), b);
    }

    /// Compaction preserves each record's real key (does not clobber it).
    #[test]
    fn oblivious_compact_preserves_keys(keep in proptest::collection::vec(any::<bool>(), 1..32)) {
        let n = keep.len();
        let mut records: Vec<Record> = (0..n).map(|i| Record::new(1000 + i as u64, vec![i as u8; 2])).collect();
        oblivious_compact(&mut records, &keep);
        // every surviving record still has a key in the original 1000.. range (not a synthetic one)
        for r in &records {
            prop_assert!((1000..1000 + n as u64).contains(&r.key));
            prop_assert_eq!(r.key, 1000 + r.payload[0] as u64); // key matches its payload's index
        }
    }
    /// The oblivious (bitonic) sort produces the same ordering as a reference sort.
    #[test]
    fn oblivious_sort_matches_reference(mut keys in proptest::collection::vec(0u64..1_000_000, 0..64)) {
        let mut records: Vec<Record> =
            keys.iter().enumerate().map(|(i, &k)| Record::new(k, vec![i as u8; 4])).collect();
        oblivious_sort(&mut records);
        keys.sort();
        let got: Vec<u64> = records.iter().map(|r| r.key).collect();
        prop_assert_eq!(got, keys);
    }

    /// Payloads travel with their keys through the sort (swaps move whole records).
    #[test]
    fn oblivious_sort_preserves_payloads(keys in proptest::collection::vec(0u64..1000, 1..32)) {
        let mut uniq = keys.clone();
        uniq.sort();
        uniq.dedup();
        let mut records: Vec<Record> =
            uniq.iter().map(|&k| Record::new(k, vec![(k & 0xff) as u8; 4])).collect();
        oblivious_sort(&mut records);
        for r in &records {
            prop_assert_eq!(r.payload.clone(), vec![(r.key & 0xff) as u8; 4]);
        }
    }

    /// Compaction moves kept records to the front in their original relative order.
    #[test]
    fn oblivious_compact_moves_keeps_front_stably(keep in proptest::collection::vec(any::<bool>(), 0..48)) {
        let n = keep.len();
        let mut records: Vec<Record> = (0..n).map(|i| Record::new(0, vec![i as u8; 2])).collect();
        let expected: Vec<u8> = (0..n).filter(|&i| keep[i]).map(|i| i as u8).collect();
        oblivious_compact(&mut records, &keep);
        let kept = keep.iter().filter(|&&k| k).count();
        let got: Vec<u8> = records.iter().take(kept).map(|r| r.payload[0]).collect();
        prop_assert_eq!(got, expected);
    }
}

/// A batch with mismatched payload lengths must panic at the entry point (not silently corrupt) —
/// the explicit point of the runtime `assert!` (vs. a release-stripped `debug_assert!`).
#[test]
#[should_panic(expected = "must share a payload length")]
fn oblivious_sort_panics_on_ragged_payloads() {
    let mut records = vec![Record::new(1, vec![0u8; 4]), Record::new(2, vec![0u8; 2])];
    oblivious_sort(&mut records);
}

#[test]
#[should_panic(expected = "must share a payload length")]
fn oblivious_compact_panics_on_ragged_payloads() {
    let mut records = vec![Record::new(1, vec![0u8; 4]), Record::new(2, vec![0u8; 2])];
    oblivious_compact(&mut records, &[true, false]);
}

use oblivious_sidecar::primitives::{oblivious_compact, oblivious_sort, Record};
use proptest::prelude::*;

proptest! {
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

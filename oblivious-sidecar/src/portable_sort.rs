//! Portable / data-parallel ("GPU-style") oblivious sort — prototype.
//!
//! Per the hardware-acceleration design note (`specs/.../design/hardware-crypto-acceleration.md`):
//! the bitonic network is a FIXED sequence of compare-exchanges determined by the public length
//! `n` ALONE. That single property is what makes it both constant-time AND GPU-mappable:
//!
//!   * The host computes the network topology once, from `n`, reading no data → a fixed access
//!     pattern (no data-dependent addressing, the GPU side-channel trap the design note flags).
//!   * The network factors into ordered STAGES; within a stage every compare-exchange touches a
//!     disjoint index pair, so a device runs a whole stage in ONE parallel dispatch (the SIMT
//!     mapping). [[bitonic_schedule]] emits exactly that, and [[disjoint_within_stages]] proves it.
//!
//! This module is the portable prototype: it produces the schedule a real SPIR-V/CUDA/wgpu kernel
//! would consume, and executes it on the CPU. CI has no GPU, so correctness is established the way
//! the design note's gate #4 requires — a **differential test proving byte-identical output to the
//! recursive CPU oracle** ([[crate::primitives::oblivious_sort]]) over random inputs. A real GPU
//! backend is a drop-in that consumes the same schedule and must pass the same differential KAT.

// Reuse the SAME constant-time compare-exchange + item type as the CPU oracle, so the obliviousness
// / constant-time properties cannot drift between the two paths — only the schedule differs here.
use crate::primitives::{compare_exchange, Item, Record};

/// One oblivious compare-exchange of positions `i < j` in a fixed direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompareExchange {
    pub i: usize,
    pub j: usize,
    pub ascending: bool,
}

/// A stage: compare-exchanges on pairwise-disjoint indices → one parallel device dispatch.
pub type Stage = Vec<CompareExchange>;

/// Build the bitonic sorting network for `padded` (a power of two) as ordered stages — from the
/// length ALONE; this function reads no element data. Standard iterative bitonic: `log²(padded)`
/// stages, each `padded/2` disjoint compare-exchanges.
pub fn bitonic_schedule(padded: usize) -> Vec<Stage> {
    assert!(
        padded.is_power_of_two(),
        "bitonic network needs a power-of-two length"
    );
    let mut stages = Vec::new();
    let mut k = 2;
    while k <= padded {
        let mut j = k / 2;
        while j >= 1 {
            let mut stage = Vec::with_capacity(padded / 2);
            for i in 0..padded {
                let l = i ^ j;
                if l > i {
                    // Ascending sub-network where bit `k` of `i` is clear, descending otherwise:
                    // the iterative bitonic recipe that yields a fully ascending result.
                    stage.push(CompareExchange {
                        i,
                        j: l,
                        ascending: (i & k) == 0,
                    });
                }
            }
            stages.push(stage);
            j >>= 1;
        }
        k <<= 1;
    }
    stages
}

/// Execute one stage via the SHARED `primitives::compare_exchange`. A real device runs these
/// concurrently (the pairs are disjoint — see [[disjoint_within_stages]]); here we apply them in
/// sequence, which is equivalent precisely because they do not overlap.
fn run_stage(items: &mut [Item], stage: &Stage) {
    for ce in stage {
        compare_exchange(items, ce.i, ce.j, ce.ascending);
    }
}

/// Data-oblivious ascending sort by `record.key`, driven by the precomputed bitonic schedule (the
/// GPU-style path). Same contract as [[crate::primitives::oblivious_sort]]: real keys `< u64::MAX`,
/// uniform payload length.
pub fn oblivious_sort_portable(records: &mut Vec<Record>) {
    let n = records.len();
    if n <= 1 {
        return;
    }
    let payload_len = records[0].payload.len();
    assert!(
        records.iter().all(|r| r.payload.len() == payload_len),
        "all records in a batch must share a payload length"
    );
    let padded = n.next_power_of_two();
    let mut items: Vec<Item> = records.drain(..).map(|r| (r.key, r)).collect();
    while items.len() < padded {
        items.push((u64::MAX, Record::new(u64::MAX, vec![0u8; payload_len])));
    }
    for stage in bitonic_schedule(padded) {
        run_stage(&mut items, &stage);
    }
    items.truncate(n);
    *records = items.into_iter().map(|(_, r)| r).collect();
}

/// True iff every stage's compare-exchanges touch pairwise-disjoint indices — the property that
/// lets a device run a whole stage in one dispatch (and that makes the access pattern fixed).
pub fn disjoint_within_stages(stages: &[Stage]) -> bool {
    use std::collections::HashSet;
    stages.iter().all(|stage| {
        let mut seen = HashSet::new();
        stage
            .iter()
            .all(|ce| seen.insert(ce.i) && seen.insert(ce.j))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::oblivious_sort;
    use proptest::prelude::*;

    // Distinct payloads per element (index in byte 1) so duplicate-key records remain distinguishable.
    fn records(keys: &[u64]) -> Vec<Record> {
        keys.iter()
            .enumerate()
            .map(|(idx, &k)| Record::new(k, vec![(k & 0xff) as u8, idx as u8]))
            .collect()
    }

    fn key_sorted(rs: &[Record]) -> bool {
        rs.windows(2).all(|w| w[0].key <= w[1].key)
    }

    fn canonical(rs: &[Record]) -> Vec<(u64, Vec<u8>)> {
        let mut v: Vec<(u64, Vec<u8>)> = rs.iter().map(|r| (r.key, r.payload.clone())).collect();
        v.sort();
        v
    }

    #[test]
    fn schedule_is_data_independent_and_well_formed() {
        // Generated from length alone → identical regardless of any data; stages are disjoint.
        let a = bitonic_schedule(8);
        let b = bitonic_schedule(8);
        assert_eq!(a, b, "schedule depends only on n");
        assert!(
            disjoint_within_stages(&a),
            "each stage must be parallel-dispatchable"
        );
        // log2(8)=3 → 3*(3+1)/2 = 6 stages, each 4 compare-exchanges.
        assert_eq!(a.len(), 6);
        assert!(a.iter().all(|s| s.len() == 4));
        // Larger boundary stays disjoint/well-formed too.
        assert!(disjoint_within_stages(&bitonic_schedule(128)));
    }

    proptest! {
        // Differential KAT: with DISTINCT keys the sorted order is unique, so the schedule path ≡
        // the recursive CPU oracle byte for byte. Inputs are SHUFFLED (not a pre-sorted subsequence)
        // and range up to a padded width of 128 to exercise larger networks.
        #[test]
        fn portable_matches_cpu_oracle_distinct(
            perm in (1usize..100usize).prop_flat_map(|n|
                Just((0u64..n as u64).collect::<Vec<_>>()).prop_shuffle())
        ) {
            let mut a = records(&perm);
            let mut b = records(&perm);
            oblivious_sort(&mut a);
            oblivious_sort_portable(&mut b);
            prop_assert_eq!(a, b);
        }

        // With DUPLICATE keys, two different bitonic networks need not agree on the relative order of
        // equal keys (a sorting network isn't stable), and the store only requires sorted-by-key. So
        // the meaningful invariant is: the portable path is itself a valid oblivious sort — key-sorted
        // output AND the same multiset of records as the oracle. (Compaction avoids this entirely by
        // using unique synthetic keys.)
        #[test]
        fn portable_is_a_valid_sort_with_duplicate_keys(keys in prop::collection::vec(0u64..6, 0..40)) {
            let mut oracle = records(&keys);
            let mut portable = records(&keys);
            oblivious_sort(&mut oracle);
            oblivious_sort_portable(&mut portable);
            prop_assert!(key_sorted(&portable), "portable output must be key-sorted");
            prop_assert_eq!(canonical(&oracle), canonical(&portable), "same multiset of records");
        }
    }

    #[test]
    fn portable_sorts_small_cases() {
        let mut r = records(&[5, 1, 9, 3]);
        oblivious_sort_portable(&mut r);
        let keys: Vec<u64> = r.iter().map(|x| x.key).collect();
        assert_eq!(keys, vec![1, 3, 5, 9]);
    }
}

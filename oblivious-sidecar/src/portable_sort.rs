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

use crate::primitives::Record;
use subtle::{Choice, ConditionallySelectable, ConstantTimeGreater};

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

/// A sort-key + record pair (mirrors `primitives::Item`, kept local to the prototype).
type Item = (u64, Record);

fn ct_swap_item(cond: Choice, a: &mut Item, b: &mut Item) {
    u64::conditional_swap(&mut a.0, &mut b.0, cond);
    u64::conditional_swap(&mut a.1.key, &mut b.1.key, cond);
    for (x, y) in a.1.payload.iter_mut().zip(b.1.payload.iter_mut()) {
        u8::conditional_swap(x, y, cond);
    }
}

fn apply(items: &mut [Item], ce: CompareExchange) {
    let CompareExchange { i, j, ascending } = ce;
    let gt = items[i].0.ct_gt(&items[j].0);
    let lt = items[j].0.ct_gt(&items[i].0);
    let do_swap = Choice::conditional_select(&lt, &gt, Choice::from(ascending as u8));
    let (left, right) = items.split_at_mut(j);
    ct_swap_item(do_swap, &mut left[i], &mut right[0]);
}

/// Execute one stage. A real device runs these concurrently (the pairs are disjoint — see
/// [[disjoint_within_stages]]); here we apply them in sequence, which is equivalent precisely
/// because they do not overlap.
fn run_stage(items: &mut [Item], stage: &Stage) {
    for &ce in stage {
        apply(items, ce);
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

    fn records(keys: &[u64]) -> Vec<Record> {
        keys.iter()
            .map(|&k| Record::new(k, vec![(k & 0xff) as u8, 0xab]))
            .collect()
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
    }

    proptest! {
        // Differential KAT: the GPU-style schedule path ≡ the recursive CPU oracle, byte for byte.
        // Distinct keys (a permutation) so the unique sorted order is unambiguous.
        #[test]
        fn portable_matches_cpu_oracle(perm in proptest::sample::subsequence((0u64..64).collect::<Vec<_>>(), 0..40)) {
            let mut a = records(&perm);
            let mut b = records(&perm);
            oblivious_sort(&mut a);
            oblivious_sort_portable(&mut b);
            prop_assert_eq!(a, b);
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

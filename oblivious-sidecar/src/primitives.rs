//! Constant-time oblivious primitives.

use subtle::{Choice, ConditionallySelectable, ConstantTimeGreater};

/// A fixed-shape record: a `u64` sort key plus an equal-length payload. All records in a batch
/// MUST share a payload length so swaps are constant-time over a public size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub key: u64,
    pub payload: Vec<u8>,
}

impl Record {
    pub fn new(key: u64, payload: Vec<u8>) -> Self {
        Record { key, payload }
    }
}

/// Constant-time select: `a` if `cond` else `b` (no data-dependent branch).
#[inline]
pub fn ct_select_u64(cond: Choice, a: u64, b: u64) -> u64 {
    u64::conditional_select(&b, &a, cond)
}

/// Conditionally swap two records in constant time (key + every payload byte).
fn ct_swap_record(cond: Choice, a: &mut Record, b: &mut Record) {
    debug_assert_eq!(a.payload.len(), b.payload.len(), "records must share payload length");
    u64::conditional_swap(&mut a.key, &mut b.key, cond);
    for (x, y) in a.payload.iter_mut().zip(b.payload.iter_mut()) {
        u8::conditional_swap(x, y, cond);
    }
}

/// Oblivious compare-exchange of positions `i < j` for a given direction. The decision to swap is
/// computed in constant time from the keys; the swap itself is constant-time.
fn compare_exchange(a: &mut [Record], i: usize, j: usize, ascending: bool) {
    debug_assert!(i < j);
    let gt = a[i].key.ct_gt(&a[j].key); // a[i] > a[j]
    let lt = a[j].key.ct_gt(&a[i].key); // a[i] < a[j]
    let do_swap = Choice::conditional_select(&lt, &gt, Choice::from(ascending as u8));
    let (left, right) = a.split_at_mut(j);
    ct_swap_record(do_swap, &mut left[i], &mut right[0]);
}

fn bitonic_merge(a: &mut [Record], lo: usize, n: usize, ascending: bool) {
    if n > 1 {
        let m = n / 2;
        for i in lo..lo + m {
            compare_exchange(a, i, i + m, ascending);
        }
        bitonic_merge(a, lo, m, ascending);
        bitonic_merge(a, lo + m, m, ascending);
    }
}

fn bitonic_sort(a: &mut [Record], lo: usize, n: usize, ascending: bool) {
    if n > 1 {
        let m = n / 2;
        bitonic_sort(a, lo, m, true);
        bitonic_sort(a, lo + m, m, false);
        bitonic_merge(a, lo, n, ascending);
    }
}

/// Data-oblivious ascending sort by `key`. The comparison network depends only on the (public)
/// length. Records are padded to the next power of two with sentinel max-key records, sorted, then
/// truncated back to the original count (truncation is by public size, so it leaks nothing).
///
/// Requires every real key to be `< u64::MAX` (reserved for padding sentinels).
pub fn oblivious_sort(records: &mut Vec<Record>) {
    let n = records.len();
    if n <= 1 {
        return;
    }
    let payload_len = records[0].payload.len();
    let padded = n.next_power_of_two();
    while records.len() < padded {
        records.push(Record::new(u64::MAX, vec![0u8; payload_len]));
    }
    bitonic_sort(records, 0, padded, true);
    records.truncate(n);
}

/// Oblivious compaction: stably move records whose `keep` flag is true to the front, preserving
/// their original relative order; dropped records follow. Implemented by re-keying each record to
/// `(!keep, original_index)` and running the oblivious sort — so the access pattern depends only on
/// the public length, not on which records are kept. The first `keep.iter().filter(..).count()`
/// records are the kept ones (count is public).
pub fn oblivious_compact(records: &mut Vec<Record>, keep: &[bool]) {
    assert_eq!(records.len(), keep.len(), "keep mask must match record count");
    for (i, r) in records.iter_mut().enumerate() {
        // keeps (0) sort before drops (1); index tiebreak preserves relative order. The bool->u64
        // cast is branch-free.
        r.key = ((!keep[i] as u64) << 40) | (i as u64);
    }
    oblivious_sort(records);
}

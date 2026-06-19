//! Constant-time oblivious primitives.

use subtle::{Choice, ConditionallySelectable, ConstantTimeGreater};

/// A fixed-shape record: a `u64` key plus an equal-length payload. All records in a batch MUST
/// share a payload length so swaps are constant-time over a public size (checked at entry).
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

/// A `(sort_key, record)` pair. The network sorts by `sort_key`, which lets compaction sort by a
/// synthetic key WITHOUT disturbing `record.key` (the record's real key travels untouched).
type Item = (u64, Record);

/// Conditionally swap two items in constant time (sort key, record key, every payload byte).
fn ct_swap_item(cond: Choice, a: &mut Item, b: &mut Item) {
    u64::conditional_swap(&mut a.0, &mut b.0, cond);
    u64::conditional_swap(&mut a.1.key, &mut b.1.key, cond);
    for (x, y) in a.1.payload.iter_mut().zip(b.1.payload.iter_mut()) {
        u8::conditional_swap(x, y, cond);
    }
}

/// Oblivious compare-exchange of positions `i < j` for a given direction, decided in constant time.
fn compare_exchange(a: &mut [Item], i: usize, j: usize, ascending: bool) {
    debug_assert!(i < j);
    let gt = a[i].0.ct_gt(&a[j].0); // a[i] > a[j]
    let lt = a[j].0.ct_gt(&a[i].0); // a[i] < a[j]
    let do_swap = Choice::conditional_select(&lt, &gt, Choice::from(ascending as u8));
    let (left, right) = a.split_at_mut(j);
    ct_swap_item(do_swap, &mut left[i], &mut right[0]);
}

fn bitonic_merge(a: &mut [Item], lo: usize, n: usize, ascending: bool) {
    if n > 1 {
        let m = n / 2;
        for i in lo..lo + m {
            compare_exchange(a, i, i + m, ascending);
        }
        bitonic_merge(a, lo, m, ascending);
        bitonic_merge(a, lo + m, m, ascending);
    }
}

fn bitonic_sort(a: &mut [Item], lo: usize, n: usize, ascending: bool) {
    if n > 1 {
        let m = n / 2;
        bitonic_sort(a, lo, m, true);
        bitonic_sort(a, lo + m, m, false);
        bitonic_merge(a, lo, n, ascending);
    }
}

/// Assert all records share a payload length and return it (constant-time swaps need a public size).
fn uniform_payload_len(records: &[Record]) -> usize {
    let len = records[0].payload.len();
    assert!(
        records.iter().all(|r| r.payload.len() == len),
        "all records in a batch must share a payload length"
    );
    len
}

/// Sort `items` (pairs of sort-key + record) by sort-key, obliviously: pad to the next power of two
/// with max-key sentinels, run the fixed bitonic network, truncate back to `n` (a public size).
fn oblivious_sort_items(items: &mut Vec<Item>, n: usize, payload_len: usize) {
    let padded = n.next_power_of_two();
    while items.len() < padded {
        items.push((u64::MAX, Record::new(u64::MAX, vec![0u8; payload_len])));
    }
    bitonic_sort(items, 0, padded, true);
    items.truncate(n);
}

/// Data-oblivious ascending sort by `record.key`. Requires every real key `< u64::MAX` (reserved
/// for padding sentinels) and a uniform payload length across the batch.
pub fn oblivious_sort(records: &mut Vec<Record>) {
    let n = records.len();
    if n <= 1 {
        return;
    }
    let payload_len = uniform_payload_len(records);
    let mut items: Vec<Item> = records.drain(..).map(|r| (r.key, r)).collect();
    oblivious_sort_items(&mut items, n, payload_len);
    *records = items.into_iter().map(|(_, r)| r).collect();
}

/// Oblivious compaction: stably move records whose `keep` flag is true to the front, preserving
/// their original relative order; dropped records follow. The first `keep.iter().filter(..).count()`
/// records are the kept ones (count is public). `record.key` is PRESERVED — compaction sorts by a
/// synthetic `(!keep, original_index)` key carried alongside each record, never overwriting it.
pub fn oblivious_compact(records: &mut Vec<Record>, keep: &[bool]) {
    assert_eq!(records.len(), keep.len(), "keep mask must match record count");
    let n = records.len();
    if n == 0 {
        return;
    }
    let payload_len = uniform_payload_len(records);
    // keeps (0) sort before drops (1); index tiebreak preserves relative order. bool->u64 is branch-free.
    let mut items: Vec<Item> = records
        .drain(..)
        .enumerate()
        .map(|(i, r)| (((!keep[i] as u64) << 40) | i as u64, r))
        .collect();
    oblivious_sort_items(&mut items, n, payload_len);
    *records = items.into_iter().map(|(_, r)| r).collect();
}

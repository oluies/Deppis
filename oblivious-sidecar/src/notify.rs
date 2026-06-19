//! Oblivious PING notification aggregation (T053, D8/FR-004).

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

pub const DIGEST_BYTES: usize = 64; // 512 one-hot buddy bits (FR-015)
pub const MAX_BIT: u16 = (DIGEST_BYTES * 8) as u16;

/// A decoded signal: a buddy's one-hot `bit` to set under an aggregation `label`. `bit` MUST be
/// `< MAX_BIT`; `oblivious_aggregate` enforces this at the trust boundary.
#[derive(Clone, Copy)]
pub struct Signal {
    pub label: u64,
    pub bit: u16,
}

// Test-only instrumentation: counts per-byte visits in `ct_set_bit`, so a unit test can assert the
// scan is data-independent (every digest byte visited for every (client, signal) regardless of
// label match). Only present in `cfg(test)` builds.
#[cfg(test)]
thread_local! {
    static BYTE_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Constant-time set of `bit` in `digest` when `cond`. Scans ALL digest bytes and conditionally
/// sets the target byte, so the byte touched is not revealed by a data-dependent index.
fn ct_set_bit(digest: &mut [u8; DIGEST_BYTES], bit: u16, cond: Choice) {
    let byte_idx = (bit >> 3) as u16;
    let mask = 1u8 << (bit & 7);
    for i in 0..DIGEST_BYTES {
        let is_target = (i as u16).ct_eq(&byte_idx);
        let set = cond & is_target;
        let with_bit = digest[i] | mask;
        digest[i].conditional_assign(&with_bit, set);
        #[cfg(test)]
        BYTE_VISITS.with(|c| c.set(c.get() + 1));
    }
}

/// Oblivious aggregation: for each client label, OR the one-hot bit of every signal whose label
/// matches. EVERY signal is scanned for EVERY client identically, so the access pattern depends
/// only on the public batch/client counts — never on which signal belongs to which client. One
/// `DIGEST_BYTES` digest is emitted per client (an all-zero carrier when the client has no waiting
/// mail), so the per-client output is uniform and reveals only "some buddy has mail", never which.
///
/// Panics if any signal carries `bit >= MAX_BIT` — a malformed-protocol error caught loudly at the
/// boundary rather than silently dropping the notification (bit positions are public, not secret).
pub fn oblivious_aggregate(signals: &[Signal], client_labels: &[u64]) -> Vec<[u8; DIGEST_BYTES]> {
    assert!(
        signals.iter().all(|s| s.bit < MAX_BIT),
        "signal bit must be < {MAX_BIT}"
    );
    client_labels
        .iter()
        .map(|&client| {
            let mut digest = [0u8; DIGEST_BYTES];
            for sig in signals {
                let matches = sig.label.ct_eq(&client);
                ct_set_bit(&mut digest, sig.bit, matches);
            }
            digest
        })
        .collect()
}

/// Read one bit out of a digest (helper for callers/tests).
pub fn get_bit(digest: &[u8; DIGEST_BYTES], bit: u16) -> bool {
    (digest[(bit >> 3) as usize] >> (bit & 7)) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregation_visits_every_byte_regardless_of_match() {
        let sigs = vec![Signal { label: 1, bit: 0 }, Signal { label: 1, bit: 1 }];

        BYTE_VISITS.with(|c| c.set(0));
        let _ = oblivious_aggregate(&sigs, &[1, 2, 3]); // all-/partly-matching
        let matching = BYTE_VISITS.with(|c| c.get());

        BYTE_VISITS.with(|c| c.set(0));
        let _ = oblivious_aggregate(&sigs, &[7, 8, 9]); // none matching
        let non_matching = BYTE_VISITS.with(|c| c.get());

        let expected = sigs.len() * 3 * DIGEST_BYTES;
        assert_eq!(matching, expected);
        assert_eq!(non_matching, expected); // scan is independent of label matches
    }
}

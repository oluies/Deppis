use oblivious_sidecar::notify::{get_bit, oblivious_aggregate, Signal, DIGEST_BYTES, MAX_BIT};
use proptest::prelude::*;
use std::collections::HashMap;

const CARRIER: [u8; DIGEST_BYTES] = [0u8; DIGEST_BYTES];

#[test]
fn aggregates_bits_per_client_label() {
    let signals = vec![
        Signal { label: 10, bit: 3 },
        Signal { label: 10, bit: 9 },
        Signal { label: 20, bit: 1 },
    ];
    let out = oblivious_aggregate(&signals, &[10, 20, 30]);
    assert!(get_bit(&out[0], 3) && get_bit(&out[0], 9)); // client 10
    assert!(get_bit(&out[1], 1)); // client 20
    assert_eq!(out[2], CARRIER); // client 30: no mail -> carrier
}

#[test]
fn client_with_no_signals_gets_carrier() {
    let out = oblivious_aggregate(&[], &[1, 2]);
    assert_eq!(out, vec![CARRIER, CARRIER]);
}

#[test]
#[should_panic(expected = "signal bit must be")]
fn out_of_range_bit_panics_not_silently_drops() {
    oblivious_aggregate(
        &[Signal {
            label: 1,
            bit: MAX_BIT,
        }],
        &[1],
    );
}

proptest! {
    /// The oblivious aggregation matches a plain reference: each client's digest is the OR of the
    /// one-hot bits of signals carrying its label.
    #[test]
    fn matches_reference(
        sigs in proptest::collection::vec((0u64..5, 0u16..MAX_BIT), 0..40),
        clients in proptest::collection::vec(0u64..5, 1..6),
    ) {
        let signals: Vec<Signal> = sigs.iter().map(|&(label, bit)| Signal { label, bit }).collect();
        let out = oblivious_aggregate(&signals, &clients);

        // reference: label -> set of bits
        let mut reference: HashMap<u64, Vec<u16>> = HashMap::new();
        for &(label, bit) in &sigs {
            reference.entry(label).or_default().push(bit);
        }
        for (ci, &client) in clients.iter().enumerate() {
            let want = reference.get(&client).cloned().unwrap_or_default();
            for bit in 0..MAX_BIT {
                prop_assert_eq!(get_bit(&out[ci], bit), want.contains(&bit));
            }
        }
    }
}

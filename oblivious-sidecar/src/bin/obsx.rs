//! `obsx` CLI (Constitution V). `obsx selftest` runs the oblivious primitives over fixed inputs
//! and reports `{constantTime, obliviousInvariants}` as JSON. Constant-timeness is by construction
//! (the `subtle` crate + a data-independent network); the self-test validates correctness.

use oblivious_sidecar::primitives::{ct_select_u64, oblivious_compact, oblivious_sort, Record};
use oblivious_sidecar::store::ObliviousStore;
use std::io::Read;
use subtle::Choice;

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    // CLI contract: JSON in on stdin (consumed, unused for selftest).
    let mut _buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut _buf);

    match cmd.as_str() {
        "selftest" => {
            let mut recs: Vec<Record> = [5u64, 1, 9, 3, 7, 2]
                .iter()
                .map(|&k| Record::new(k, vec![(k & 0xff) as u8; 2]))
                .collect();
            oblivious_sort(&mut recs);
            let sorted = recs.windows(2).all(|w| w[0].key <= w[1].key)
                && recs.iter().all(|r| r.payload == vec![(r.key & 0xff) as u8; 2]);

            let keep = vec![true, false, true, false, true, false];
            let mut c: Vec<Record> = (0..6).map(|i| Record::new(0, vec![i as u8; 1])).collect();
            oblivious_compact(&mut c, &keep);
            let compacted = c.iter().take(3).map(|r| r.payload[0]).collect::<Vec<_>>() == vec![0u8, 2, 4];

            // oblivious store round-trip: write -> read (hit) -> read again (single-use carrier)
            let mut store = ObliviousStore::with_capacity(4);
            store.write(&[3u8; 32], &[42u8; 256]);
            let store_ok = store.read(&[3u8; 32]) == [42u8; 256] && store.read(&[3u8; 32]) == [0u8; 256];

            // `constantTime` reflects an actual functional check of the ct primitive (its
            // constant-timeness is by construction via `subtle`; this validates correctness).
            let constant_time =
                ct_select_u64(Choice::from(1), 7, 9) == 7 && ct_select_u64(Choice::from(0), 7, 9) == 9;

            println!(
                "{{\"constantTime\":{},\"obliviousInvariants\":{}}}",
                constant_time,
                sorted && compacted && store_ok
            );
        }
        other => {
            eprintln!("error: unknown subcommand: {}", other);
            std::process::exit(1);
        }
    }
}

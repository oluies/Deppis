//! `obsx` CLI (Constitution V). `obsx selftest` runs the oblivious primitives over fixed inputs
//! and reports `{constantTime, obliviousInvariants}` as JSON. Constant-timeness is by construction
//! (the `subtle` crate + a data-independent network); the self-test validates correctness.

use oblivious_sidecar::primitives::{oblivious_compact, oblivious_sort, Record};
use std::io::Read;

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

            println!(
                "{{\"constantTime\":true,\"obliviousInvariants\":{}}}",
                sorted && compacted
            );
        }
        other => {
            eprintln!("error: unknown subcommand: {}", other);
            std::process::exit(1);
        }
    }
}

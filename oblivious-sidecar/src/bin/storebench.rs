//! Transport-free microbenchmark of the oblivious scan — the Rust half of the three-way comparison
//! in `bench/README.md`. Build with `--release`; a debug build measures nothing useful.
//!
//! Deliberately hand-rolled rather than criterion, and matched line-for-line with the Scala
//! harness (`sidecar-scala/.../ScanBench.scala`): same fixed token pool built outside the timed
//! region, same warmup, same op count, same checksum consumed at the end. criterion and JMH do not
//! both exist across Rust, the JVM and Scala Native, so using each language's native harness would
//! fold three different measurement methodologies into the numbers being compared. Per-round cost
//! here is microseconds, so loop overhead is irrelevant.
//!
//! The checksum is load-bearing: without consuming the result, the optimiser may delete the scan
//! outright, and 0 ns/op looks like a spectacular win rather than a deleted benchmark.

use oblivious_sidecar::store::{ObliviousStore, FRAME_LEN, TOKEN_LEN};
use std::time::Instant;

const POOL: usize = 64;

fn token_pool() -> Vec<[u8; TOKEN_LEN]> {
    (0..POOL)
        .map(|i| {
            let mut t = [0u8; TOKEN_LEN];
            let mut x = (i as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            for slot in t.iter_mut() {
                x ^= x >> 30;
                x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
                x ^= x >> 27;
                *slot = (x >> 24) as u8;
            }
            t
        })
        .collect()
}

fn measure(capacity: usize, ops: usize, warmup: usize) -> (f64, u64) {
    let mut store = ObliviousStore::with_capacity(capacity);
    let pool = token_pool();
    let frame: [u8; FRAME_LEN] = std::array::from_fn(|i| (i & 0xff) as u8);
    let mut checksum: u64 = 0;

    let rounds = |store: &mut ObliviousStore, n: usize, checksum: &mut u64| {
        for i in 0..n {
            let t = &pool[i % POOL];
            let _ = store.write(t, &frame);
            let (out, found) = store.read_sealed(t);
            if found {
                *checksum += 1;
            }
            *checksum += out[i % FRAME_LEN] as u64;
        }
    };

    rounds(&mut store, warmup, &mut checksum);
    let t0 = Instant::now();
    rounds(&mut store, ops, &mut checksum);
    let elapsed = t0.elapsed();
    (elapsed.as_nanos() as f64 / ops as f64, checksum)
}

fn main() {
    let capacities: Vec<usize> = {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            vec![256, 1024, 4096]
        } else {
            args.iter().map(|a| a.parse().expect("capacity")).collect()
        }
    };
    let (ops, warmup) = (2000usize, 500usize);
    println!("# oblivious scan microbenchmark — ops={ops} warmup={warmup} pool={POOL}");
    for c in capacities {
        let (ns, ck) = measure(c, ops, warmup);
        println!(
            "{:<24} capacity={:<6} {:>10.2} us/round  checksum={}",
            "rust",
            c,
            ns / 1000.0,
            ck
        );
    }
}

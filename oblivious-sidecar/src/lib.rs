//! Oblivious-sidecar primitives (T050/T051).
//!
//! Data-oblivious building blocks for the PONG store and PING aggregation: a constant-time
//! select/swap, a data-oblivious sort (a fixed bitonic network — the comparison sequence depends
//! only on the public length, never on the data), and an oblivious compaction built on it.
//!
//! Constant-time selection/swap is delegated to the vetted `subtle` crate (Constitution I — no
//! hand-rolled constant-time code). NOTE: these primitives make the *access pattern* independent
//! of data, but the metadata-privacy *claim* still requires running inside the SGX enclave; this
//! crate is the dev/testable component the Scala server calls, labeled accordingly.

pub mod grpc;
pub mod grpc_notify;
pub mod notify;
pub mod portable_sort;
pub mod primitives;
pub mod store;

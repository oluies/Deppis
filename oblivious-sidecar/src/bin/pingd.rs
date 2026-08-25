//! pingd — the PING notification front as its OWN process, serving ONLY `NotificationService`.
//!
//! # Why a separate binary (Phase C, ARCHITECTURE.md §6)
//!
//! `obsd` has always been able to serve both roles, and in a dev build it still does. But the
//! PING/PONG split is a **trust-domain** split, not a module split: the whole unlinkability argument
//! assumes the party that sees *which token was written* is not the party that sees *whose bit was
//! set*. Co-hosting them hands one process both halves, and correlating "a write landed at round r"
//! with "label L's bit was set at round r" re-identifies the receiver of every real frame — exactly
//! the inference the cover-traffic design exists to prevent. No amount of obliviousness inside each
//! service repairs that, because the leak is in the join, not in either side.
//!
//! So the production topology is two processes, and `pingd` is the notify half. `obsd` keeps its
//! notify service for the dev demo and the existing integration tests, but can now be told to serve
//! the store only (`OBSD_SERVICES=store`), which is what a deployment that runs `pingd` should do.
//!
//! # What this does NOT achieve on its own (Constitution IV)
//!
//! Separate processes are NECESSARY but not SUFFICIENT. Two processes on one host, under one
//! operator, with one set of logs, can still be joined trivially — by the operator, by an attacker
//! who lands on the box, or by anything that sees both sockets. The separation only becomes a real
//! boundary once the two run in distinct trust domains with distinct attested identities, which is
//! the rest of Phase C (SGX enclave, DCAP appraisal, attested key release) and is NOT delivered here.
//!
//! This build therefore remains `DEV, NO METADATA PRIVACY`, and running `pingd` does not change any
//! label. It removes one structural obstacle to Phase C; it does not deliver Phase C.

use oblivious_sidecar::env::{hex_key_osvar, KeyVar};
use oblivious_sidecar::grpc_notify::pb::notification_service_server::NotificationServiceServer;
use oblivious_sidecar::grpc_notify::NotificationServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // PINGD_ADDR, not OBSD_ADDR: the two processes bind different sockets, and sharing one env var
    // would silently collide when both are started from the same shell or unit file.
    let addr = std::env::var("PINGD_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50052".to_string())
        .parse()?;
    // FAIL on a malformed key rather than falling back to the dev key. A one-character typo would
    // otherwise start a notify front on the key published in this source — ACKing every signal
    // (`signal` returns a uniform response for tokens it cannot open), delivering no bits, and
    // letting anyone forge a bit for any label. Same fail-closed rule as `OBSD_SERVICES`.
    let notify_key = match hex_key_osvar(std::env::var_os("PINGD_NOTIFY_KEY").as_deref()) {
        KeyVar::Parsed(k) => k,
        KeyVar::Unset => {
            eprintln!("pingd: PINGD_NOTIFY_KEY unset — using the DEV key (not secret, dev only)");
            [0x01u8; 32]
        }
        KeyVar::Malformed => {
            eprintln!("pingd: PINGD_NOTIFY_KEY is set but is not 64 hex chars — refusing to start");
            std::process::exit(2);
        }
    };

    eprintln!("pingd: serving NotificationService ONLY on {addr} — DEV, NO METADATA PRIVACY");
    eprintln!("pingd: run the store in a SEPARATE process (obsd with OBSD_SERVICES=store)");

    tonic::transport::Server::builder()
        .add_service(NotificationServiceServer::new(NotificationServer::new(
            notify_key,
        )))
        .serve(addr)
        .await?;
    Ok(())
}

//! pokerbot library crate.
//!
//! The `pokerbot` binary (`main.rs`) is a thin CLI over these modules; exposing
//! them as a library lets the integration test-suite (`tests/verify.rs`) drive
//! the real self-play + transcript verifier through the same public APIs the
//! binary uses. All game/relay/escrow logic lives here; `main.rs` only parses
//! args and prints reports.

pub mod crypto;
// Live-paid-path plumbing (memo/command building). Used by the `play-staked` driver.
pub mod deposit;
pub mod dkg;
pub mod dkgtest;
pub mod game;
pub mod identity;
pub mod payout;
pub mod playstaked;
pub mod probe;
pub mod relay;
pub mod session;
pub mod settle;
pub mod srv;
// the transcript replay-verifier ("the jury") + its serde container.
pub mod transcript;

/// Random nick: literal 'p' + 8 hex chars (identity hidden until E2EE). Lives in
/// the crate root so the escrow-bridge drivers (`dkgtest`, `probe`, `playstaked`)
/// can share it via `crate::random_nick`.
pub fn random_nick() -> String {
    use rand::RngCore;
    let mut b = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut b);
    format!("p{}", hex::encode(b))
}

//! # zync-core
//!
//! Zcash light client primitives: note scanning, FlyClient verification of
//! the chain against proof of work, and the small helpers wallets share.
//!
//! ## Trust model
//!
//! 1. **Chain.** [`flyclient`] checks a server's chain against Zcash's own
//!    proof of work through the ZIP-221 history tree that every header commits
//!    to, down to a compiled anchor block. The committing tip must also be one
//!    independent nodes report (cross-verification).
//! 2. **Notes and spends.** Found by scanning every block on the client:
//!    trial decryption with cmx recomputation for notes, nullifier matching
//!    for spends. Nothing about the wallet's notes is sent to the server.
//! 3. **Cross-verification.** Tip hashes compared across independent
//!    lightwalletd endpoints, >2/3 agreement required.
//!
//! ## Modules
//!
//! - [`flyclient`]: FlyClient verification over the ZIP-221 history tree
//! - [`scanner`]: orchard note trial decryption (native + WASM parallel)
//! - [`sync`]: cross-verification tally, memo ciphertext extraction
//! - [`client`]: gRPC clients for zidecar and lightwalletd (feature-gated)
//!
//! ## Platform support
//!
//! Default features (`client`, `parallel`) build a native library with gRPC
//! clients and rayon-based parallel scanning. For WASM, disable defaults and
//! enable `wasm` or `wasm-parallel`:
//!
//! ```toml
//! zync-core = { version = "0.7", default-features = false, features = ["wasm-parallel"] }
//! ```
//!
//! WASM parallel scanning requires `SharedArrayBuffer` (COOP/COEP headers)
//! and builds with:
//! ```sh
//! RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' \
//!   cargo build --target wasm32-unknown-unknown
//! ```

#![allow(dead_code)]

pub use zync_flyclient::consensus;
pub mod endpoints;
pub mod error;
pub use zync_flyclient as flyclient;
pub mod scanner;
pub mod sync;

#[cfg(feature = "wasm")]
pub mod wasm_api;

#[cfg(feature = "client")]
pub mod client;

pub use error::{Result, ZyncError};
pub use scanner::{BatchScanner, DecryptedNote, ScanAction, Scanner};

// re-export orchard key types for downstream consumers
pub use orchard::keys::{FullViewingKey as OrchardFvk, IncomingViewingKey, Scope, SpendingKey};

#[cfg(feature = "client")]
pub use client::{LightwalletdClient, ZidecarClient};










// Activation heights and anchor hashes live with the FlyClient verifier,
// which anchors on them; re-exported so existing paths keep working.
pub use zync_flyclient::{
    ACTIVATION_HASH_MAINNET, IRONWOOD_ACTIVATION_HASH_MAINNET, IRONWOOD_ACTIVATION_HEIGHT,
    IRONWOOD_ACTIVATION_HEIGHT_TESTNET, ORCHARD_ACTIVATION_HEIGHT,
    ORCHARD_ACTIVATION_HEIGHT_TESTNET,
};

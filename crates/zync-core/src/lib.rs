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

pub mod endpoints;
pub mod error;
pub mod flyclient;
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










/// orchard activation height (mainnet)
pub const ORCHARD_ACTIVATION_HEIGHT: u32 = 1_687_104;

/// orchard activation height (testnet)
pub const ORCHARD_ACTIVATION_HEIGHT_TESTNET: u32 = 1_842_420;

/// ironwood pool activation height (NU6.3, mainnet). Ironwood reuses orchard
/// addresses and note encryption; from this height v6 transactions may carry
/// ironwood bundles and orchard receivers can be paid ironwood notes.
pub const IRONWOOD_ACTIVATION_HEIGHT: u32 = 3_428_143;

/// ironwood pool activation height (testnet)
pub const IRONWOOD_ACTIVATION_HEIGHT_TESTNET: u32 = 4_134_000;

/// orchard activation block hash (mainnet). Despite earlier wording this is
/// display order (big-endian, as explorers print it); reverse it to compare
/// with a SHA-256d output.
pub const ACTIVATION_HASH_MAINNET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0xd7, 0x23, 0x15, 0x6d, 0x9b, 0x65, 0xff, 0xcf, 0x49, 0x84, 0xda,
    0x7a, 0x19, 0x67, 0x5e, 0xd7, 0xe2, 0xf0, 0x6d, 0x9e, 0x5d, 0x51, 0x88, 0xaf, 0x08, 0x7b, 0xf8,
];

/// ironwood (NU6.3) activation block hash (mainnet), display order like
/// [`ACTIVATION_HASH_MAINNET`]. Anchors FlyClient proofs that start at NU6.3.
pub const IRONWOOD_ACTIVATION_HASH_MAINNET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x8b, 0x54, 0xbb, 0xde, 0x4e, 0x89, 0x96, 0x37, 0x34, 0x17,
    0xa6, 0xb3, 0x3e, 0xe2, 0xbd, 0x98, 0x4b, 0xcf, 0x02, 0x88, 0x2e, 0x5d, 0x81, 0x28, 0xd7, 0x61,
];

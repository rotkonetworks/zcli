//! # zync-core
//!
//! Trust-minimized Zcash light client primitives. Remaining trust assumptions:
//! the hardcoded activation block hash, the cryptographic proof systems
//! (ligerito, NOMT, Halo 2), and your key material.
//!
//! ## Trust model
//!
//! A zync-powered light client verifies every claim the server makes:
//!
//! 1. **Header chain.** [ligerito](https://crates.io/crates/ligerito) polynomial
//!    commitment proofs over block headers. The prover encodes headers into a trace
//!    polynomial and commits to the evaluation; the verifier checks the commitment
//!    in O(log n) without seeing any headers. Public outputs (block hashes,
//!    state roots, commitments) are transcript-bound but NOT evaluation-proven —
//!    the ligerito proximity test does not constrain which values the polynomial
//!    contains. Soundness relies on the honest-prover assumption; cross-verification
//!    (item 4) detects a malicious prover. Proven roots anchor subsequent steps.
//!
//! 2. **State proofs.** NOMT sparse merkle proofs for note commitments and
//!    nullifiers. Each proof binds to the tree root proven by the header chain.
//!    Commitment proofs verify that received notes exist in the global tree.
//!    Nullifier proofs verify spent/unspent status without trusting the server.
//!
//! 3. **Actions integrity.** A running Blake2b commitment chain over per-block
//!    orchard action merkle roots. Verified against the header-proven value to
//!    detect block action tampering (inserted, removed, or reordered actions).
//!
//! 4. **Cross-verification.** BFT majority consensus against independent
//!    lightwalletd nodes. Tip and activation block hashes are compared with
//!    >2/3 agreement required. Prevents single-server eclipse attacks.
//!
//! 5. **Trial decryption.** Orchard note scanning with cmx recomputation.
//!    After decryption, the note commitment is recomputed from the decrypted
//!    fields and compared against the server-provided cmx. A malicious server
//!    cannot craft ciphertexts that decrypt to fake notes with arbitrary values.
//!
//! ## Modules
//!
//! - [`verifier`]: ligerito header chain proof verification (epoch + tip, parallel)
//! - [`nomt`]: NOMT sparse merkle proof verification (commitments + nullifiers)
//! - [`actions`]: actions merkle root computation and running commitment chain
//! - [`scanner`]: orchard note trial decryption (native + WASM parallel)
//! - [`sync`]: sync verification primitives (proof validation, cross-verify, memo extraction)
//! - [`prover`]: ligerito proof generation from header chain traces
//! - [`trace`]: header chain trace encoding (headers to polynomial)
//! - [`client`]: gRPC clients for zidecar and lightwalletd (feature-gated)
//!
//! ## Platform support
//!
//! Default features (`client`, `parallel`) build a native library with gRPC
//! clients and rayon-based parallel scanning. For WASM, disable defaults and
//! enable `wasm` or `wasm-parallel`:
//!
//! ```toml
//! zync-core = { version = "0.4", default-features = false, features = ["wasm-parallel"] }
//! ```
//!
//! WASM parallel scanning requires `SharedArrayBuffer` (COOP/COEP headers)
//! and builds with:
//! ```sh
//! RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' \
//!   cargo build --target wasm32-unknown-unknown
//! ```
//!
//! ## Minimal sync loop
//!
//! ```ignore
//! use zync_core::{sync, verifier, Scanner, OrchardFvk};
//!
//! // 1. fetch header proof from zidecar
//! let (proof_bytes, _, _) = client.get_header_proof().await?;
//!
//! // 2. verify and extract proven NOMT roots
//! let proven = sync::verify_header_proof(&proof_bytes, tip, true)?;
//!
//! // 3. scan compact blocks for owned notes
//! let scanner = Scanner::from_fvk(&fvk);
//! let notes = scanner.scan(&actions);
//!
//! // 4. verify commitment proofs for received notes
//! sync::verify_commitment_proofs(&proofs, &cmxs, &proven, &server_root)?;
//!
//! // 5. verify nullifier proofs for unspent notes
//! let spent = sync::verify_nullifier_proofs(&nf_proofs, &nullifiers, &proven, &nf_root)?;
//!
//! // 6. verify actions commitment chain
//! sync::verify_actions_commitment(&running, &proven.actions_commitment, true)?;
//! ```

#![allow(dead_code)]

pub mod actions;
pub mod auth;
pub mod endpoints;
pub mod error;
pub mod nomt;
pub mod prover;
pub mod scanner;
pub mod sync;
pub mod trace;
pub mod verifier;

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

use ligerito::{ProverConfig, VerifierConfig};
use ligerito_binary_fields::{BinaryElem128, BinaryElem32};
use std::marker::PhantomData;

/// blocks per epoch (~21 hours at 75s/block)
pub const EPOCH_SIZE: u32 = 1024;

/// max orchard actions per block
pub const MAX_ACTIONS_PER_BLOCK: usize = 512;

/// fields encoded per action in trace polynomial
pub const FIELDS_PER_ACTION: usize = 8;

/// fields encoded per block header in trace polynomial
pub const FIELDS_PER_HEADER: usize = 32;

/// sentinel row size appended after all headers in trace
pub const TIP_SENTINEL_SIZE: usize = 24;

/// polynomial size exponent for tip proofs (2^20 config, max ~32K headers)
pub const TIP_TRACE_LOG_SIZE: usize = 20;

/// polynomial size exponent for epoch proofs (2^26 config)
pub const EPOCH_PROOF_TRACE_LOG_SIZE: usize = 26;

/// security parameter (bits)
pub const SECURITY_BITS: usize = 100;

/// orchard activation height (mainnet)
pub const ORCHARD_ACTIVATION_HEIGHT: u32 = 1_687_104;

/// orchard activation height (testnet)
pub const ORCHARD_ACTIVATION_HEIGHT_TESTNET: u32 = 1_842_420;

/// orchard activation block hash (mainnet, LE internal order)
pub const ACTIVATION_HASH_MAINNET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0xd7, 0x23, 0x15, 0x6d, 0x9b, 0x65, 0xff, 0xcf, 0x49, 0x84, 0xda,
    0x7a, 0x19, 0x67, 0x5e, 0xd7, 0xe2, 0xf0, 0x6d, 0x9e, 0x5d, 0x51, 0x88, 0xaf, 0x08, 0x7b, 0xf8,
];

/// domain separator for wallet state commitment
pub const DOMAIN_WALLET_STATE: &[u8] = b"ZYNC_wallet_state_v1";

/// domain separator for epoch proof hash
pub const DOMAIN_EPOCH_PROOF: &[u8] = b"ZYNC_epoch_proof_v1";

/// domain separator for ivk commitment
pub const DOMAIN_IVK_COMMIT: &[u8] = b"ZYNC_ivk_commit_v1";

/// genesis epoch hash (all zeros)
pub const GENESIS_EPOCH_HASH: [u8; 32] = [0u8; 32];

/// empty sparse merkle tree root
pub const EMPTY_SMT_ROOT: [u8; 32] = [0u8; 32];

/// ligerito prover config for tip proofs (2^20)
pub fn tip_prover_config() -> ProverConfig<BinaryElem32, BinaryElem128> {
    ligerito::hardcoded_config_20(PhantomData::<BinaryElem32>, PhantomData::<BinaryElem128>)
}

/// ligerito prover config for epoch proofs (2^26)
pub fn epoch_proof_prover_config() -> ProverConfig<BinaryElem32, BinaryElem128> {
    ligerito::hardcoded_config_26(PhantomData::<BinaryElem32>, PhantomData::<BinaryElem128>)
}

/// select the appropriate prover config for a given trace size
pub fn prover_config_for_size(
    trace_len: usize,
) -> (ProverConfig<BinaryElem32, BinaryElem128>, usize) {
    let log_size = if trace_len == 0 {
        12
    } else {
        (trace_len as f64).log2().ceil() as u32
    };

    let (config_log, config) = if log_size <= 12 {
        (
            12,
            ligerito::hardcoded_config_12(
                PhantomData::<BinaryElem32>,
                PhantomData::<BinaryElem128>,
            ),
        )
    } else if log_size <= 16 {
        (
            16,
            ligerito::hardcoded_config_16(
                PhantomData::<BinaryElem32>,
                PhantomData::<BinaryElem128>,
            ),
        )
    } else if log_size <= 20 {
        (
            20,
            ligerito::hardcoded_config_20(
                PhantomData::<BinaryElem32>,
                PhantomData::<BinaryElem128>,
            ),
        )
    } else if log_size <= 24 {
        (
            24,
            ligerito::hardcoded_config_24(
                PhantomData::<BinaryElem32>,
                PhantomData::<BinaryElem128>,
            ),
        )
    } else if log_size <= 26 {
        (
            26,
            ligerito::hardcoded_config_26(
                PhantomData::<BinaryElem32>,
                PhantomData::<BinaryElem128>,
            ),
        )
    } else if log_size <= 28 {
        (
            28,
            ligerito::hardcoded_config_28(
                PhantomData::<BinaryElem32>,
                PhantomData::<BinaryElem128>,
            ),
        )
    } else {
        (
            30,
            ligerito::hardcoded_config_30(
                PhantomData::<BinaryElem32>,
                PhantomData::<BinaryElem128>,
            ),
        )
    };

    (config, 1 << config_log)
}

/// select the appropriate verifier config for a given log size
pub fn verifier_config_for_log_size(log_size: u32) -> VerifierConfig {
    if log_size <= 12 {
        ligerito::hardcoded_config_12_verifier()
    } else if log_size <= 16 {
        ligerito::hardcoded_config_16_verifier()
    } else if log_size <= 20 {
        ligerito::hardcoded_config_20_verifier()
    } else if log_size <= 24 {
        ligerito::hardcoded_config_24_verifier()
    } else if log_size <= 26 {
        ligerito::hardcoded_config_26_verifier()
    } else if log_size <= 28 {
        ligerito::hardcoded_config_28_verifier()
    } else {
        ligerito::hardcoded_config_30_verifier()
    }
}

/// helper: calculate epoch number from block height
pub fn epoch_for_height(height: u32) -> u32 {
    height / EPOCH_SIZE
}

/// helper: get start height of epoch
pub fn epoch_start(epoch: u32) -> u32 {
    epoch * EPOCH_SIZE
}

/// helper: get end height of epoch (inclusive)
pub fn epoch_end(epoch: u32) -> u32 {
    epoch_start(epoch + 1) - 1
}

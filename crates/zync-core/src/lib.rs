//! ZYNC Core - Zcash light client primitives
//!
//! Shared library for zcash light client verification and scanning:
//! - Ligerito header chain verification
//! - NOMT state proof verification
//! - Orchard note trial decryption
//! - gRPC client for zidecar/lightwalletd

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

pub mod error;
pub mod verifier;
pub mod scanner;

#[cfg(feature = "client")]
pub mod client;

pub use error::{ZyncError, Result};
pub use scanner::{Scanner, BatchScanner, ScanAction, DecryptedNote};

// re-export orchard key types for downstream consumers
pub use orchard::keys::{FullViewingKey as OrchardFvk, IncomingViewingKey, Scope, SpendingKey};

#[cfg(feature = "client")]
pub use client::{ZidecarClient, LightwalletdClient};

use ligerito::{ProverConfig, VerifierConfig};
use ligerito_binary_fields::{BinaryElem32, BinaryElem128};
use std::marker::PhantomData;

/// blocks per epoch (~21 hours at 75s/block)
pub const EPOCH_SIZE: u32 = 1024;

/// max orchard actions per block
pub const MAX_ACTIONS_PER_BLOCK: usize = 512;

/// fields encoded per action in trace polynomial
pub const FIELDS_PER_ACTION: usize = 8;

/// polynomial size exponent for tip proofs (2^20 config, max ~32K headers)
pub const TIP_TRACE_LOG_SIZE: usize = 20;

/// polynomial size exponent for epoch proofs (2^26 config)
pub const GIGAPROOF_TRACE_LOG_SIZE: usize = 26;

/// security parameter (bits)
pub const SECURITY_BITS: usize = 100;

/// orchard activation height (mainnet)
pub const ORCHARD_ACTIVATION_HEIGHT: u32 = 1_687_104;

/// orchard activation height (testnet)
pub const ORCHARD_ACTIVATION_HEIGHT_TESTNET: u32 = 1_842_420;

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
    ligerito::hardcoded_config_20(
        PhantomData::<BinaryElem32>,
        PhantomData::<BinaryElem128>,
    )
}

/// ligerito prover config for epoch proofs (2^26)
pub fn gigaproof_prover_config() -> ProverConfig<BinaryElem32, BinaryElem128> {
    ligerito::hardcoded_config_26(
        PhantomData::<BinaryElem32>,
        PhantomData::<BinaryElem128>,
    )
}

/// select the appropriate prover config for a given trace size
pub fn prover_config_for_size(trace_len: usize) -> (ProverConfig<BinaryElem32, BinaryElem128>, usize) {
    let log_size = if trace_len == 0 { 12 } else { (trace_len as f64).log2().ceil() as u32 };

    let (config_log, config) = if log_size <= 12 {
        (12, ligerito::hardcoded_config_12(PhantomData::<BinaryElem32>, PhantomData::<BinaryElem128>))
    } else if log_size <= 16 {
        (16, ligerito::hardcoded_config_16(PhantomData::<BinaryElem32>, PhantomData::<BinaryElem128>))
    } else if log_size <= 20 {
        (20, ligerito::hardcoded_config_20(PhantomData::<BinaryElem32>, PhantomData::<BinaryElem128>))
    } else if log_size <= 24 {
        (24, ligerito::hardcoded_config_24(PhantomData::<BinaryElem32>, PhantomData::<BinaryElem128>))
    } else if log_size <= 26 {
        (26, ligerito::hardcoded_config_26(PhantomData::<BinaryElem32>, PhantomData::<BinaryElem128>))
    } else if log_size <= 28 {
        (28, ligerito::hardcoded_config_28(PhantomData::<BinaryElem32>, PhantomData::<BinaryElem128>))
    } else {
        (30, ligerito::hardcoded_config_30(PhantomData::<BinaryElem32>, PhantomData::<BinaryElem128>))
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

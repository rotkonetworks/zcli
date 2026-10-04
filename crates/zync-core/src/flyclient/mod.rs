//! FlyClient verification over the ZIP-221 chain history tree.
//!
//! Every block header since Heartwood commits to a Merkle mountain range (MMR)
//! over all earlier blocks of its network-upgrade epoch (ZIP-221). Each MMR
//! node carries the subtree's cumulative work, its first/last note commitment
//! tree roots and its shielded transaction counts. Because the commitment sits
//! in a proof-of-work header, a client that checks a handful of headers and
//! MMR paths learns, with high probability, that a server's chain is the one
//! miners built — without downloading every header and without trusting a
//! prover-chosen value.
//!
//! What this module checks, per epoch (newest first):
//!
//! 1. the committing header (the tip, or an older epoch's last block) has a
//!    valid Equihash solution and meets its own target;
//! 2. the bagged MMR peaks hash to the root that header commits to — directly
//!    (`hashLightClientRoot`, Heartwood/Canopy) or through
//!    `hashBlockCommitments` (NU5 onward, ZIP-244);
//! 3. every sampled leaf sits on an authenticated path to a peak, its block
//!    header has valid PoW, and the header matches the leaf (hash, time, nBits,
//!    work);
//! 4. the samples cover work points drawn by Fiat-Shamir from the committed
//!    root, so the server cannot choose which blocks answer;
//! 5. epochs link through `hashPrevBlock` down to a hardcoded anchor block.
//!
//! What it does NOT give you: nullifiers are not in the history tree, so
//! spent-status still comes from NOMT proofs. Difficulty adjustment between
//! sampled blocks is not re-derived (ZIP-221 calls FlyClient's guarantee under
//! Zcash's per-block difficulty adjustment heuristic).
//!
//! The same module carries the server-side store ([`store::HistoryStore`]) so
//! zidecar and the verifier share one MMR shape and one sampling rule.

pub mod epochs;
pub mod header;
pub mod node;
pub mod proof;
pub mod sampling;
pub mod store;
pub mod verify;

pub use epochs::{Epoch, Network};
pub use header::BlockHeader;
pub use node::{HistoryNode, NodeVersion};
pub use proof::{EpochProof, FlyClientProof, LeafProof};
pub use sampling::FlyParams;
pub use verify::{
    auth_data_root, block_commitments, verify_flyclient, Anchor, VerifiedChain, VerifiedEpoch,
};

/// FlyClient verification errors. Every variant is a rejection: the proof is
/// either malformed or does not match the chain the header commits to.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FlyError {
    #[error("malformed header: {0}")]
    Header(&'static str),
    #[error("invalid equihash solution at height {0}")]
    Equihash(u32),
    #[error("header at height {0} does not meet its target")]
    Target(u32),
    #[error("malformed history node: {0}")]
    Node(&'static str),
    #[error("history tree mismatch: {0}")]
    Tree(&'static str),
    #[error("epoch mismatch: {0}")]
    Epoch(&'static str),
    #[error("leaf {index}: {reason}")]
    Leaf { index: u32, reason: &'static str },
    #[error("sample point {0} is not covered by any leaf in the proof")]
    Uncovered(u32),
    #[error("required leaf {0} is missing from the proof")]
    Missing(u32),
    #[error("epoch link broken: {0}")]
    Link(&'static str),
    #[error("anchor mismatch: {0}")]
    Anchor(&'static str),
}

pub type FlyResult<T> = core::result::Result<T, FlyError>;

#[cfg(test)]
mod tests;

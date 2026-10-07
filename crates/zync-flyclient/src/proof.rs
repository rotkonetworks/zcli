//! FlyClient proof format, and assembling one from a [`HistoryStore`].

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::epochs::Epoch;
use super::header::BlockHeader;
use super::sampling::{required_leaves, sample_count, sample_points, seed, FlyParams};
use super::store::HistoryStore;
use super::{FlyError, FlyResult};

/// One opened leaf: the block's header, its history node, and the siblings
/// from the leaf up to its peak.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafProof {
    pub index: u64,
    pub header: Vec<u8>,
    pub leaf: Vec<u8>,
    pub path: Vec<Vec<u8>>,
}

/// One epoch's tree as committed by `commit_header`, the block at
/// `activation + n_leaves`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochProof {
    pub activation: u32,
    pub branch_id: u32,
    pub n_leaves: u64,
    pub commit_header: Vec<u8>,
    /// ZIP-244 auth data root of the committing block; needed from NU5 on to
    /// open `hashBlockCommitments`.
    pub auth_data_root: Option<[u8; 32]>,
    pub peaks: Vec<Vec<u8>>,
    pub leaves: Vec<LeafProof>,
}

/// Epochs newest first. The first epoch's committing header is the tip; each
/// later one ends right before the previous one's activation block; the last
/// one starts at the anchor.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlyClientProof {
    pub epochs: Vec<EpochProof>,
}

/// Leaf indices an epoch proof must open: the required ones plus the leaf
/// under every Fiat-Shamir sample point. `n` is the size of the tree the
/// committing block (height `activation + n`) commits to; the store may hold
/// more. The server calls this, fetches those headers, then calls
/// [`assemble_epoch`].
pub fn plan_epoch(
    store: &HistoryStore,
    n: u64,
    epoch: &Epoch,
    commit_hash: &[u8; 32],
    params: &FlyParams,
) -> FlyResult<BTreeSet<u64>> {
    let root = store.root_at(n)?;
    let (k, m) = sample_count(params, n);
    let s = seed(epoch.branch_id, epoch.activation, n, &root.hash(), commit_hash);
    let mut set = required_leaves(params, n);
    for p in sample_points(&s, k, m, root.work()) {
        set.insert(store.leaf_at_work_at(n, p)?);
    }
    Ok(set)
}

/// Build the epoch proof. `header` returns the raw header of the block at a
/// given leaf index (height `activation + index`).
#[allow(clippy::too_many_arguments)]
pub fn assemble_epoch(
    store: &HistoryStore,
    n: u64,
    epoch: &Epoch,
    commit_header: Vec<u8>,
    auth_data_root: Option<[u8; 32]>,
    leaves: &BTreeSet<u64>,
    mut header: impl FnMut(u64) -> Option<Vec<u8>>,
) -> FlyResult<EpochProof> {
    BlockHeader::parse(&commit_header)?;
    let peaks = store.peak_nodes_at(n)?.into_iter().map(|p| p.to_bytes()).collect();
    let leaves = leaves
        .iter()
        .map(|&i| {
            Ok(LeafProof {
                index: i,
                header: header(i).ok_or(FlyError::Missing(i as u32))?,
                leaf: store
                    .leaf(i)
                    .filter(|_| i < n)
                    .ok_or(FlyError::Tree("leaf outside the tree"))?
                    .to_bytes(),
                path: store.path_at(n, i)?.into_iter().map(|n| n.to_bytes()).collect(),
            })
        })
        .collect::<FlyResult<Vec<_>>>()?;
    Ok(EpochProof {
        activation: epoch.activation,
        branch_id: epoch.branch_id,
        n_leaves: n,
        commit_header,
        auth_data_root,
        peaks,
        leaves,
    })
}

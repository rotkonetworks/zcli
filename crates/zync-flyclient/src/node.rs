//! ZIP-221 history tree nodes across the three node formats.
//!
//! Serialization, combining and hashing are `zcash_history`'s. This wrapper
//! adds what a verifier needs on top: one type over V1/V2/V3, and combining
//! that rejects hostile input instead of panicking (`zcash_history` asserts
//! equal branch ids and adds work and transaction counts unchecked).

use primitive_types::U256;
use zcash_history::{NodeData, NodeDataV2, NodeDataV3, Version, V1, V2, V3};

use super::{FlyError, FlyResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeVersion {
    V1,
    V2,
    V3,
}

#[derive(Clone, Debug)]
pub enum HistoryNode {
    V1(NodeData),
    V2(NodeDataV2),
    V3(NodeDataV3),
}

impl HistoryNode {
    pub fn from_bytes(version: NodeVersion, branch_id: u32, bytes: &[u8]) -> FlyResult<Self> {
        let err = |_| FlyError::Node("could not parse node data");
        let node = match version {
            NodeVersion::V1 => HistoryNode::V1(V1::from_bytes(branch_id, bytes).map_err(err)?),
            NodeVersion::V2 => HistoryNode::V2(V2::from_bytes(branch_id, bytes).map_err(err)?),
            NodeVersion::V3 => HistoryNode::V3(V3::from_bytes(branch_id, bytes).map_err(err)?),
        };
        // trailing bytes would let two encodings stand for one node
        if node.to_bytes().len() != bytes.len() {
            return Err(FlyError::Node("trailing bytes after node data"));
        }
        Ok(node)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            HistoryNode::V1(d) => V1::to_bytes(d),
            HistoryNode::V2(d) => V2::to_bytes(d),
            HistoryNode::V3(d) => V3::to_bytes(d),
        }
    }

    pub fn version(&self) -> NodeVersion {
        match self {
            HistoryNode::V1(_) => NodeVersion::V1,
            HistoryNode::V2(_) => NodeVersion::V2,
            HistoryNode::V3(_) => NodeVersion::V3,
        }
    }

    /// The V1 fields every version carries.
    pub fn v1(&self) -> &NodeData {
        match self {
            HistoryNode::V1(d) => d,
            HistoryNode::V2(d) => &d.v1,
            HistoryNode::V3(d) => &d.v2.v1,
        }
    }

    pub fn branch_id(&self) -> u32 {
        self.v1().consensus_branch_id
    }

    pub fn start_height(&self) -> u64 {
        self.v1().start_height
    }

    pub fn end_height(&self) -> u64 {
        self.v1().end_height
    }

    pub fn work(&self) -> U256 {
        self.v1().subtree_total_work
    }

    pub fn sapling_tx(&self) -> u64 {
        self.v1().sapling_tx
    }

    pub fn orchard_tx(&self) -> Option<u64> {
        match self {
            HistoryNode::V1(_) => None,
            HistoryNode::V2(d) => Some(d.orchard_tx),
            HistoryNode::V3(d) => Some(d.v2.orchard_tx),
        }
    }

    pub fn ironwood_tx(&self) -> Option<u64> {
        match self {
            HistoryNode::V3(d) => Some(d.ironwood_tx),
            _ => None,
        }
    }

    /// Orchard note commitment tree root after the last block of this node.
    pub fn end_orchard_root(&self) -> Option<[u8; 32]> {
        match self {
            HistoryNode::V1(_) => None,
            HistoryNode::V2(d) => Some(d.end_orchard_root),
            HistoryNode::V3(d) => Some(d.v2.end_orchard_root),
        }
    }

    /// Ironwood note commitment tree root after the last block of this node.
    pub fn end_ironwood_root(&self) -> Option<[u8; 32]> {
        match self {
            HistoryNode::V3(d) => Some(d.end_ironwood_root),
            _ => None,
        }
    }

    /// Number of blocks this node covers.
    pub fn leaf_count(&self) -> u64 {
        self.end_height().saturating_sub(self.start_height()) + 1
    }

    /// `hashChainHistoryRoot` when this node is the bagged root.
    pub fn hash(&self) -> [u8; 32] {
        match self {
            HistoryNode::V1(d) => V1::hash(d),
            HistoryNode::V2(d) => V2::hash(d),
            HistoryNode::V3(d) => V3::hash(d),
        }
    }

    /// Parent of two adjacent nodes. Rejects mismatched versions or branch
    /// ids, non-adjacent height ranges, and sums that would overflow, all of
    /// which `zcash_history` would otherwise panic on or silently accept.
    pub fn combine(left: &HistoryNode, right: &HistoryNode) -> FlyResult<HistoryNode> {
        if left.branch_id() != right.branch_id() {
            return Err(FlyError::Node("children have different branch ids"));
        }
        if left.start_height() > left.end_height() || right.start_height() > right.end_height() {
            return Err(FlyError::Node("node height range is inverted"));
        }
        if left.end_height().checked_add(1) != Some(right.start_height()) {
            return Err(FlyError::Node("children are not adjacent"));
        }
        if left.work().checked_add(right.work()).is_none() {
            return Err(FlyError::Node("work overflows"));
        }
        let fits = |a: Option<u64>, b: Option<u64>| match (a, b) {
            (Some(a), Some(b)) => a.checked_add(b).is_some(),
            _ => true,
        };
        if !fits(Some(left.sapling_tx()), Some(right.sapling_tx()))
            || !fits(left.orchard_tx(), right.orchard_tx())
            || !fits(left.ironwood_tx(), right.ironwood_tx())
        {
            return Err(FlyError::Node("transaction count overflows"));
        }
        Ok(match (left, right) {
            (HistoryNode::V1(l), HistoryNode::V1(r)) => HistoryNode::V1(V1::combine(l, r)),
            (HistoryNode::V2(l), HistoryNode::V2(r)) => HistoryNode::V2(V2::combine(l, r)),
            (HistoryNode::V3(l), HistoryNode::V3(r)) => HistoryNode::V3(V3::combine(l, r)),
            _ => return Err(FlyError::Node("children have different versions")),
        })
    }
}

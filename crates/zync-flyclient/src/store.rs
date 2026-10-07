//! MMR shape helpers shared by prover and verifier, and an in-memory store of
//! one epoch's history tree for the server side.
//!
//! A ZIP-221 tree over `n` leaves is a list of perfect binary trees ("peaks"),
//! largest first, one per set bit of `n`, bagged left to right into a root.
//! Every aligned block of `2^h` leaves that lies inside `[0, n)` is a node of
//! one of those peaks, so the store keeps the tree as levels:
//! `levels[h][i]` covers leaves `[i * 2^h, (i + 1) * 2^h)`.

use primitive_types::U256;

use super::node::HistoryNode;
use super::{FlyError, FlyResult};

/// A peak of the mountain range: its height and its first leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peak {
    pub height: u32,
    pub first_leaf: u64,
}

impl Peak {
    pub fn leaves(&self) -> u64 {
        1u64 << self.height
    }

    pub fn contains(&self, leaf: u64) -> bool {
        leaf >= self.first_leaf && leaf < self.first_leaf + self.leaves()
    }
}

/// Peaks of a tree with `n` leaves, left to right.
pub fn peaks(n: u64) -> Vec<Peak> {
    let mut out = Vec::new();
    let mut first = 0u64;
    for h in (0..64).rev() {
        if n & (1u64 << h) != 0 {
            out.push(Peak { height: h, first_leaf: first });
            first += 1u64 << h;
        }
    }
    out
}

/// Bag peaks left to right: `root = peaks[0]`, then `root = parent(root, p)`.
pub fn bag(peaks: &[HistoryNode]) -> FlyResult<HistoryNode> {
    let (first, rest) = peaks
        .split_first()
        .ok_or(FlyError::Tree("a tree needs at least one peak"))?;
    let mut root = first.clone();
    for p in rest {
        root = HistoryNode::combine(&root, p)?;
    }
    Ok(root)
}

/// Fold a node up its authentication path. `index` is the node's position
/// within its level; bit `i` of it says whether the node is the right child at
/// step `i`. Returns the peak the path ends in and the work of every leaf
/// strictly to the left of the starting node inside that peak.
pub fn fold_path(
    node: &HistoryNode,
    mut index: u64,
    path: &[HistoryNode],
) -> FlyResult<(HistoryNode, U256)> {
    let mut current = node.clone();
    let mut left_work = U256::zero();
    for sibling in path {
        current = if index & 1 == 1 {
            left_work = left_work
                .checked_add(sibling.work())
                .ok_or(FlyError::Node("work overflows"))?;
            HistoryNode::combine(sibling, &current)?
        } else {
            HistoryNode::combine(&current, sibling)?
        };
        index >>= 1;
    }
    Ok((current, left_work))
}

/// One epoch's history tree, kept whole so proofs can be cut for any leaf.
#[derive(Default)]
pub struct HistoryStore {
    levels: Vec<Vec<HistoryNode>>,
}

impl HistoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves (blocks) in the tree.
    pub fn len(&self) -> u64 {
        self.levels.first().map_or(0, |l| l.len() as u64)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn leaf(&self, index: u64) -> Option<&HistoryNode> {
        self.levels.first()?.get(index as usize)
    }

    /// Append the next block's leaf and every parent it completes.
    pub fn push(&mut self, leaf: HistoryNode) -> FlyResult<()> {
        if let Some(last) = self.levels.first().and_then(|l| l.last()) {
            if last.end_height().checked_add(1) != Some(leaf.start_height()) {
                return Err(FlyError::Tree("leaf does not follow the previous block"));
            }
        }
        let mut node = leaf;
        let mut h = 0;
        loop {
            if self.levels.len() == h {
                self.levels.push(Vec::new());
            }
            self.levels[h].push(node);
            let level = &self.levels[h];
            if !level.len().is_multiple_of(2) {
                return Ok(());
            }
            node = HistoryNode::combine(&level[level.len() - 2], &level[level.len() - 1])?;
            h += 1;
        }
    }

    /// Drop leaves past `n` (a reorg), with every node that covered them.
    pub fn truncate(&mut self, n: u64) {
        for (h, level) in self.levels.iter_mut().enumerate() {
            level.truncate((n >> h) as usize);
        }
        while self.levels.last().is_some_and(|l| l.is_empty()) {
            self.levels.pop();
        }
    }

    fn node(&self, height: u32, index: u64) -> FlyResult<&HistoryNode> {
        self.levels
            .get(height as usize)
            .and_then(|l| l.get(index as usize))
            .ok_or(FlyError::Tree("node outside the tree"))
    }

    // Every method below has an `_at(n)` form that answers for the tree of
    // the first `n` leaves. Each aligned subtree of that prefix is also a node
    // of the full store, so no copy is needed: the block at height
    // `activation + n` commits to exactly this prefix.

    fn check_prefix(&self, n: u64) -> FlyResult<()> {
        if n == 0 || n > self.len() {
            return Err(FlyError::Tree("prefix outside the tree"));
        }
        Ok(())
    }

    /// Peak nodes, left to right.
    pub fn peak_nodes(&self) -> FlyResult<Vec<&HistoryNode>> {
        self.peak_nodes_at(self.len())
    }

    pub fn peak_nodes_at(&self, n: u64) -> FlyResult<Vec<&HistoryNode>> {
        self.check_prefix(n)?;
        peaks(n)
            .iter()
            .map(|p| self.node(p.height, p.first_leaf >> p.height))
            .collect()
    }

    /// The bagged root node; its [`HistoryNode::hash`] is the value the next
    /// block commits to.
    pub fn root(&self) -> FlyResult<HistoryNode> {
        self.root_at(self.len())
    }

    pub fn root_at(&self, n: u64) -> FlyResult<HistoryNode> {
        let peaks: Vec<HistoryNode> = self.peak_nodes_at(n)?.into_iter().cloned().collect();
        bag(&peaks)
    }

    /// Siblings from a leaf up to (not including) its peak.
    pub fn path(&self, leaf: u64) -> FlyResult<Vec<&HistoryNode>> {
        self.path_at(self.len(), leaf)
    }

    pub fn path_at(&self, n: u64, leaf: u64) -> FlyResult<Vec<&HistoryNode>> {
        self.check_prefix(n)?;
        let peak = peaks(n)
            .into_iter()
            .find(|p| p.contains(leaf))
            .ok_or(FlyError::Tree("leaf outside the tree"))?;
        (0..peak.height)
            .map(|h| self.node(h, (leaf >> h) ^ 1))
            .collect()
    }

    /// The leaf whose cumulative-work interval contains `point`, an offset in
    /// `[0, total work)`. Descends by the work recorded in each node, which is
    /// exactly the rule the verifier checks.
    pub fn leaf_at_work(&self, point: U256) -> FlyResult<u64> {
        self.leaf_at_work_at(self.len(), point)
    }

    pub fn leaf_at_work_at(&self, n: u64, point: U256) -> FlyResult<u64> {
        self.check_prefix(n)?;
        let mut before = U256::zero();
        for p in peaks(n) {
            let peak = self.node(p.height, p.first_leaf >> p.height)?;
            if point >= before + peak.work() {
                before += peak.work();
                continue;
            }
            let mut index = p.first_leaf >> p.height;
            for h in (0..p.height).rev() {
                let left = self.node(h, index * 2)?;
                if point < before + left.work() {
                    index *= 2;
                } else {
                    before += left.work();
                    index = index * 2 + 1;
                }
            }
            return Ok(index);
        }
        Err(FlyError::Tree("work point beyond the tree"))
    }
}

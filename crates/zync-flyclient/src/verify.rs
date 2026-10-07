//! Verifying a [`FlyClientProof`] down to an anchor block.

use primitive_types::U256;

use super::epochs::{Epoch, Network, Schedule};
use super::header::{bits_work, BlockHeader};
use super::node::HistoryNode;
use super::proof::{Burial, EpochProof, FlyClientProof};
use super::sampling::{required_leaves, sample_count, sample_points, seed, FlyParams};
use super::store::{bag, fold_path, peaks};
use super::{FlyError, FlyResult};

/// The block the proof must bottom out in: an epoch's activation block whose
/// hash is compiled into the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub height: u32,
    /// Internal byte order (as SHA-256d outputs it, not as explorers print it).
    pub hash: [u8; 32],
}

impl Anchor {
    /// The NU5 (Orchard) activation block on mainnet, the anchor zync already
    /// trusts. `ACTIVATION_HASH_MAINNET` is stored in display order.
    pub fn nu5_mainnet() -> Self {
        let mut hash = crate::ACTIVATION_HASH_MAINNET;
        hash.reverse();
        Anchor {
            height: crate::ORCHARD_ACTIVATION_HEIGHT,
            hash,
        }
    }

    /// The NU6.3 (Ironwood) activation block on mainnet. A server only has to
    /// index the current epoch to serve proofs against it.
    pub fn nu6_3_mainnet() -> Self {
        let mut hash = crate::IRONWOOD_ACTIVATION_HASH_MAINNET;
        hash.reverse();
        Anchor {
            height: crate::IRONWOOD_ACTIVATION_HEIGHT,
            hash,
        }
    }
}

/// What a verified epoch tells you.
#[derive(Clone, Debug)]
pub struct VerifiedEpoch {
    pub epoch: Epoch,
    /// Height of the block whose header commits to this tree.
    pub commit_height: u32,
    pub commit_hash: [u8; 32],
    /// The bagged root: cumulative work, final note commitment tree roots and
    /// shielded transaction counts for `activation..commit_height`.
    pub root: HistoryNode,
    pub root_hash: [u8; 32],
    /// `(height, nBits)` of every header checked for this epoch: the
    /// committing header and every opened leaf.
    pub checked_bits: Vec<(u32, u32)>,
}

#[derive(Clone, Debug)]
pub struct VerifiedChain {
    pub tip_height: u32,
    pub tip_hash: [u8; 32],
    /// The tip header's timestamp.
    pub tip_time: u32,
    /// Work from the anchor through the tip, for comparing servers.
    pub total_work: U256,
    /// Newest first, as in the proof.
    pub epochs: Vec<VerifiedEpoch>,
}

impl VerifiedChain {
    /// The tip epoch's root: tree roots and counts as of the block before the tip.
    pub fn tip_root(&self) -> &HistoryNode {
        &self.epochs[0].root
    }
}

/// Verify a FlyClient proof. On success every epoch from the anchor's to the
/// tip's is bound to proof-of-work headers, and each epoch's sampled blocks
/// passed the checks in the [module docs](super).
pub fn verify_flyclient(
    proof: &FlyClientProof,
    network: Network,
    params: &FlyParams,
    anchor: &Anchor,
) -> FlyResult<VerifiedChain> {
    verify_inner(proof, network, params, anchor, true)
}

/// Structure-only verification for synthetic trees, whose headers cannot
/// carry valid Equihash solutions. Never use outside tests.
#[cfg(test)]
pub(crate) fn verify_flyclient_without_pow(
    proof: &FlyClientProof,
    network: Network,
    params: &FlyParams,
    anchor: &Anchor,
) -> FlyResult<VerifiedChain> {
    verify_inner(proof, network, params, anchor, false)
}

fn header_at(raw: &[u8], height: u32, network: Network, pow: bool) -> FlyResult<BlockHeader> {
    if pow {
        BlockHeader::parse_and_verify(raw, height, network)
    } else {
        BlockHeader::parse(raw)
    }
}

fn verify_inner(
    proof: &FlyClientProof,
    network: Network,
    params: &FlyParams,
    anchor: &Anchor,
    pow: bool,
) -> FlyResult<VerifiedChain> {
    if proof.epochs.is_empty() {
        return Err(FlyError::Epoch("proof has no epochs"));
    }
    let mut verified: Vec<VerifiedEpoch> = Vec::with_capacity(proof.epochs.len());
    // (prev_hash of the newer epoch's activation block, newer epoch's activation)
    let mut link: Option<([u8; 32], u32)> = None;
    let mut total_work = U256::zero();
    let mut tip_time = 0;

    for ep in &proof.epochs {
        let (v, first_prev) = verify_epoch(ep, network, params, pow)?;
        if let Some((prev_hash, newer_activation)) = link {
            if v.commit_height.checked_add(1) != Some(newer_activation) {
                return Err(FlyError::Link(
                    "epoch does not end right before the next one",
                ));
            }
            if v.commit_hash != prev_hash {
                return Err(FlyError::Link(
                    "activation block's parent is not this epoch's last block",
                ));
            }
        } else {
            // the newest epoch's committing header is the tip; count its own work
            let tip = BlockHeader::parse(&ep.commit_header)?;
            tip_time = tip.time;
            total_work = bits_work(tip.bits).ok_or(FlyError::Target(v.commit_height))?;
        }
        total_work = total_work
            .checked_add(v.root.work())
            .ok_or(FlyError::Node("work overflows"))?;
        link = Some((first_prev, v.epoch.activation));
        verified.push(v);
    }

    let oldest = verified.last().expect("non-empty");
    if oldest.epoch.activation != anchor.height {
        return Err(FlyError::Anchor(
            "oldest epoch does not start at the anchor",
        ));
    }
    let first_leaf = proof
        .epochs
        .last()
        .expect("non-empty")
        .leaves
        .iter()
        .find(|l| l.index == 0);
    let first = first_leaf.ok_or(FlyError::Missing(0))?;
    if BlockHeader::parse(&first.header)?.hash != anchor.hash {
        return Err(FlyError::Anchor(
            "anchor epoch's first block is not the anchor block",
        ));
    }

    let newest = &verified[0];
    Ok(VerifiedChain {
        tip_height: newest.commit_height,
        tip_hash: newest.commit_hash,
        tip_time,
        total_work,
        epochs: verified,
    })
}

/// The epoch an epoch proof claims. An upgrade this build knows must match its
/// compiled activation and branch id. An upgrade newer than every one this
/// build knows (NU7, ...) is taken from the proof: the branch id personalizes
/// every history-tree hash and the header commits to the result, so a wrong
/// id or boundary cannot verify, and the epochs must still link to the anchor.
fn epoch_for(ep: &EpochProof, network: Network) -> FlyResult<Epoch> {
    let known = Schedule::compiled(network);
    if let Some(e) = known.activated_at(ep.activation) {
        if ep.branch_id != e.branch_id {
            return Err(FlyError::Epoch("branch id does not match the epoch"));
        }
        return Ok(e);
    }
    if known
        .newest_activation()
        .is_some_and(|newest| ep.activation <= newest)
    {
        return Err(FlyError::Epoch("no history epoch activates at this height"));
    }
    if known.epochs().iter().any(|e| e.branch_id == ep.branch_id) {
        return Err(FlyError::Epoch(
            "a known upgrade's branch id at a new height",
        ));
    }
    let e = Epoch::new(ep.activation, ep.branch_id, None);
    if Schedule::from_upgrades([(ep.activation, ep.branch_id)])
        .epochs()
        .is_empty()
    {
        return Err(FlyError::Epoch(
            "a pre-Heartwood branch id has no history tree",
        ));
    }
    Ok(e)
}

/// Verify one epoch. Returns it and the `hashPrevBlock` of its activation
/// block, which must be the previous epoch's committing block.
fn verify_epoch(
    ep: &EpochProof,
    network: Network,
    params: &FlyParams,
    pow: bool,
) -> FlyResult<(VerifiedEpoch, [u8; 32])> {
    let epoch = epoch_for(ep, network)?;
    if ep.n_leaves == 0 {
        return Err(FlyError::Epoch("an epoch proof needs at least one leaf"));
    }
    let commit_height = u64::from(ep.activation)
        .checked_add(ep.n_leaves)
        .and_then(|h| u32::try_from(h).ok())
        .ok_or(FlyError::Epoch("committing height overflows"))?;
    if !epoch.contains(commit_height) {
        return Err(FlyError::Epoch("committing block is outside the epoch"));
    }

    // 1. the committing header carries real work
    let commit = header_at(&ep.commit_header, commit_height, network, pow)?;

    // 2. the peaks bag into the root that header commits to
    let (peak_nodes, root, root_hash) = open_tree(
        &epoch,
        ep.n_leaves,
        &ep.peaks,
        ep.auth_data_root,
        &commit.commitments,
    )?;
    let shape = peaks(ep.n_leaves);
    let mut checked_bits = vec![(commit_height, commit.bits)];

    // a hostile server could pad the proof to burn Equihash checks
    let (_, max_samples) = sample_count(params, ep.n_leaves);
    if ep.leaves.len() > required_leaves(params, ep.n_leaves).len() + max_samples as usize {
        return Err(FlyError::Epoch(
            "proof opens more leaves than sampling can ask for",
        ));
    }

    // 3. each opened leaf is authentic and its block has real work
    let mut intervals: Vec<(U256, U256, u64)> = Vec::with_capacity(ep.leaves.len());
    let mut seen = std::collections::BTreeSet::new();
    let mut first_prev = None;
    let mut last_hash = None;
    for lp in &ep.leaves {
        let i = lp.index;
        let bad = |reason| FlyError::Leaf {
            index: i as u32,
            reason,
        };
        if i >= ep.n_leaves {
            return Err(bad("index beyond the tree"));
        }
        if !seen.insert(i) {
            return Err(bad("opened twice"));
        }
        let height = ep.activation + i as u32;
        let leaf = HistoryNode::from_bytes(epoch.version, epoch.branch_id, &lp.leaf)?;
        let v1 = leaf.v1();
        if v1.start_height != u64::from(height) || v1.end_height != u64::from(height) {
            return Err(bad("leaf is not this block"));
        }
        let header = header_at(&lp.header, height, network, pow)?;
        checked_bits.push((height, header.bits));
        if v1.subtree_commitment != header.hash {
            return Err(bad("leaf commits to a different block"));
        }
        if v1.start_time != header.time || v1.end_time != header.time {
            return Err(bad("leaf time differs from the header"));
        }
        if v1.start_target != header.bits || v1.end_target != header.bits {
            return Err(bad("leaf target differs from the header"));
        }
        if Some(v1.subtree_total_work) != bits_work(header.bits) {
            return Err(bad("leaf work differs from the header's target"));
        }

        let (pi, peak) = shape
            .iter()
            .enumerate()
            .find(|(_, p)| p.contains(i))
            .ok_or(bad("leaf in no peak"))?;
        if lp.path.len() != peak.height as usize {
            return Err(bad("path length does not match the peak"));
        }
        let path = lp
            .path
            .iter()
            .map(|b| HistoryNode::from_bytes(epoch.version, epoch.branch_id, b))
            .collect::<FlyResult<Vec<_>>>()?;
        let (top, left_in_peak) = fold_path(&leaf, i, &path)?;
        if top.to_bytes() != ep.peaks[pi] {
            return Err(bad("path does not lead to its peak"));
        }
        let mut before = left_in_peak;
        for n in &peak_nodes[..pi] {
            before = before.checked_add(n.work()).ok_or(bad("work overflows"))?;
        }
        let end = before
            .checked_add(leaf.work())
            .ok_or(bad("work overflows"))?;
        intervals.push((before, end, i));

        if i == 0 {
            first_prev = Some(header.prev_hash);
        }
        if i == ep.n_leaves - 1 {
            last_hash = Some(header.hash);
        }
    }

    // 4. the server opened what Fiat-Shamir and the tail rule demand
    let required = required_leaves(params, ep.n_leaves);
    for i in &required {
        if !seen.contains(i) {
            return Err(FlyError::Missing(*i as u32));
        }
    }
    let (k, m) = sample_count(params, ep.n_leaves);
    let s = seed(
        epoch.branch_id,
        ep.activation,
        ep.n_leaves,
        &root_hash,
        &commit.hash,
    );
    intervals.sort();
    for (j, p) in sample_points(&s, k, m, root.work()).into_iter().enumerate() {
        let at = intervals.partition_point(|(start, _, _)| *start <= p);
        let covered = at > 0 && p < intervals[at - 1].1;
        if !covered {
            return Err(FlyError::Uncovered(j as u32));
        }
    }

    // 5. the committing header extends the tree's last block
    if last_hash != Some(commit.prev_hash) {
        return Err(FlyError::Link(
            "committing header's parent is not the tree's last leaf",
        ));
    }

    Ok((
        VerifiedEpoch {
            epoch,
            commit_height,
            commit_hash: commit.hash,
            root,
            root_hash,
            checked_bits,
        },
        first_prev.ok_or(FlyError::Missing(0))?,
    ))
}

/// Parse the peaks of an `n`-leaf tree of `epoch`, check each covers its
/// leaves, bag them, and check a header's `commitments` field opens to the
/// root. Returns the peaks, the root and its hash.
fn open_tree(
    epoch: &Epoch,
    n: u64,
    peak_bytes: &[Vec<u8>],
    auth_data_root: Option<[u8; 32]>,
    commitments: &[u8; 32],
) -> FlyResult<(Vec<HistoryNode>, HistoryNode, [u8; 32])> {
    let shape = peaks(n);
    if shape.len() != peak_bytes.len() {
        return Err(FlyError::Tree("wrong number of peaks for the tree size"));
    }
    let peak_nodes = peak_bytes
        .iter()
        .map(|b| HistoryNode::from_bytes(epoch.version, epoch.branch_id, b))
        .collect::<FlyResult<Vec<_>>>()?;
    for (p, node) in shape.iter().zip(&peak_nodes) {
        let start = u64::from(epoch.activation) + p.first_leaf;
        if node.start_height() != start || node.end_height() != start + p.leaves() - 1 {
            return Err(FlyError::Tree("peak does not cover its leaves"));
        }
    }
    let root = bag(&peak_nodes)?;
    let root_hash = root.hash();
    let committed = if epoch.commits_root_directly() {
        root_hash
    } else {
        let adr =
            auth_data_root.ok_or(FlyError::Tree("auth data root missing for an NU5+ epoch"))?;
        block_commitments(&root_hash, &adr)
    };
    if committed != *commitments {
        return Err(FlyError::Tree("header does not commit to these peaks"));
    }
    Ok((peak_nodes, root, root_hash))
}

/// Tree roots that a buried block commits to.
#[derive(Clone, Debug)]
pub struct BuriedRoots {
    /// The roots hold as of this height (the buried block's parent).
    pub height: u32,
    /// The bagged `activation..height` node: its end Orchard and Ironwood
    /// roots are the note commitment tree roots after block `height`.
    pub root: HistoryNode,
}

/// Open a [`Burial`] against a proof that [`verify_flyclient`] (or
/// [`crate::verify_wallet`]) already accepted. The buried block must be an
/// opened leaf of the newest epoch, so its header is already bound to the
/// tip; this checks that header commits to the burial's peaks.
pub fn verify_burial(
    proof: &FlyClientProof,
    chain: &VerifiedChain,
    burial: &Burial,
) -> FlyResult<BuriedRoots> {
    let (ep, epoch) = match (proof.epochs.first(), chain.epochs.first()) {
        (Some(ep), Some(v)) => (ep, &v.epoch),
        _ => return Err(FlyError::Epoch("proof has no epochs")),
    };
    if burial.index == 0 || burial.index >= ep.n_leaves {
        return Err(FlyError::Tree("buried block is outside the tip epoch"));
    }
    let leaf = ep
        .leaves
        .iter()
        .find(|l| l.index == burial.index)
        .ok_or(FlyError::Missing(burial.index as u32))?;
    let header = BlockHeader::parse(&leaf.header)?;
    let (_, root, _) = open_tree(
        epoch,
        burial.index,
        &burial.peaks,
        burial.auth_data_root,
        &header.commitments,
    )?;
    Ok(BuriedRoots {
        height: epoch.activation + burial.index as u32 - 1,
        root,
    })
}

/// ZIP-244 `hashBlockCommitments`.
pub fn block_commitments(history_root: &[u8; 32], auth_data_root: &[u8; 32]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZcashBlockCommit")
        .to_state()
        .update(history_root)
        .update(auth_data_root)
        .update(&[0u8; 32])
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// ZIP-244 `hashAuthDataRoot`: a BLAKE2b-256 (`ZcashAuthDatHash`) Merkle tree
/// over the block's transaction auth digests in internal byte order, padded
/// with zero leaves to a power of two. Pre-v5 transactions use `[0xff; 32]`.
pub fn auth_data_root(digests: &[[u8; 32]]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = digests.to_vec();
    let size = level.len().max(1).next_power_of_two();
    level.resize(size, [0u8; 32]);
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let h = blake2b_simd::Params::new()
                    .hash_length(32)
                    .personal(b"ZcashAuthDatHash")
                    .to_state()
                    .update(&pair[0])
                    .update(&pair[1])
                    .finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(h.as_bytes());
                out
            })
            .collect();
    }
    level[0]
}

//! ZIP-221 history trees for FlyClient proofs.
//!
//! Zidecar rebuilds every history-tree epoch from its anchor upward, one leaf
//! per block, and serves FlyClient proofs over them. Before a block's leaf is
//! added, the block's own header is checked against the tree built so far:
//! its `hashBlockCommitments` (or, for Heartwood/Canopy, `hashLightClientRoot`)
//! must open to our root and the block's auth data root. Consensus put that
//! value in a proof-of-work header, so a match means our tree is the chain's,
//! byte for byte. On a mismatch the index stops and refuses to serve: a wrong
//! tree would hand clients proofs that fail, or worse, that pass for the
//! wrong reasons.
//!
//! Leaf fields come from three zebrad calls per block:
//! - `getblockheader <hash> false`: hash, time and nBits straight from the
//!   header bytes;
//! - `getblock <height> 2`: shielded transaction counts, auth digests, and
//!   the final Sapling root (printed byte-reversed);
//! - `z_gettreestate`: Orchard and Ironwood frontiers. Zebra stores the
//!   Ironwood tree as an Orchard note commitment tree, so one parser serves
//!   both.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt, TryStreamExt};
use orchard::tree::MerkleHashOrchard;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};
use zcash_history::{NodeData, NodeDataV2, NodeDataV3};
use zync_core::flyclient::epochs::{Epoch, Network, Schedule};
use zync_core::flyclient::header::{bits_work, BlockHeader};
use zync_core::flyclient::node::{HistoryNode, NodeVersion};
use zync_core::flyclient::proof::{assemble_epoch, plan_epoch, EpochProof, FlyClientProof};
use zync_core::flyclient::sampling::FlyParams;
use zync_core::flyclient::store::HistoryStore;
use zync_core::flyclient::{auth_data_root, block_commitments, verify_flyclient, Anchor};

use crate::error::{Result, ZidecarError};
use crate::orchard_tree::{parse_frontier_tree_root, parse_orchard_tree_root};
use crate::storage::Storage;
use crate::zebrad::{BlockVerbose, ZebradClient};

/// Blocks fetched concurrently while catching up.
const FETCH_CONCURRENCY: usize = 16;
/// Deepest reorg the index rolls back on its own.
const MAX_REORG: u32 = 100;
/// Proof-building parameters a client may ask for are bounded so one request
/// cannot make the server open the whole chain.
const MAX_LAMBDA: u32 = 80;
const MAX_TAIL: u32 = 64;

fn hex32_reversed(s: &str) -> Result<[u8; 32]> {
    let mut b: [u8; 32] = hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ZidecarError::Validation(format!("not a 32-byte hex value: {s}")))?;
    b.reverse();
    Ok(b)
}

/// What one block contributes to its epoch's tree.
struct BlockLeaf {
    height: u32,
    header: BlockHeader,
    leaf: HistoryNode,
    auth_data_root: [u8; 32],
}

/// Shielded transaction counts as zebra's history tree counts them: a
/// transaction counts for a pool when it carries that pool's bundle.
fn pool_counts(block: &BlockVerbose) -> (u64, u64, u64) {
    let mut sapling = 0;
    let mut orchard = 0;
    let mut ironwood = 0;
    for tx in &block.tx {
        let spends = tx.sapling_spends.as_ref().is_some_and(|v| !v.is_empty());
        let outputs = tx.sapling_outputs.as_ref().is_some_and(|v| !v.is_empty());
        if spends || outputs {
            sapling += 1;
        }
        if tx.orchard.as_ref().is_some_and(|o| !o.actions.is_empty()) {
            orchard += 1;
        }
        if tx.ironwood.as_ref().is_some_and(|o| !o.actions.is_empty()) {
            ironwood += 1;
        }
    }
    (sapling, orchard, ironwood)
}

fn block_auth_data_root(block: &BlockVerbose) -> Result<[u8; 32]> {
    let digests = block
        .tx
        .iter()
        .map(|tx| match &tx.authdigest {
            Some(d) => hex32_reversed(d),
            None => Ok([0xffu8; 32]), // pre-v5 placeholder (ZIP-244)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(auth_data_root(&digests))
}

async fn fetch_header(zebrad: &ZebradClient, height: u32) -> Result<Vec<u8>> {
    let hash = zebrad.get_block_hash(height).await?;
    let raw = zebrad.get_block_header_raw(&hash).await?;
    let parsed = BlockHeader::parse(&raw)
        .map_err(|e| ZidecarError::Validation(format!("header {height}: {e}")))?;
    if parsed.hash != hex32_reversed(&hash)? {
        return Err(ZidecarError::Validation(format!(
            "header {height} does not hash to the block hash zebrad reported"
        )));
    }
    Ok(raw)
}

async fn fetch_leaf(zebrad: &ZebradClient, epoch: &Epoch, height: u32) -> Result<BlockLeaf> {
    let raw = fetch_header(zebrad, height).await?;
    let header = BlockHeader::parse(&raw)
        .map_err(|e| ZidecarError::Validation(format!("header {height}: {e}")))?;
    let block = zebrad.get_block_verbose_at(height).await?;
    let (sapling_tx, orchard_tx, ironwood_tx) = pool_counts(&block);
    let sapling_root = hex32_reversed(block.finalsaplingroot.as_deref().ok_or_else(|| {
        ZidecarError::Validation(format!("block {height}: no finalsaplingroot"))
    })?)?;
    let work = bits_work(header.bits)
        .ok_or_else(|| ZidecarError::Validation(format!("block {height}: invalid nBits")))?;
    let v1 = NodeData {
        consensus_branch_id: epoch.branch_id,
        subtree_commitment: header.hash,
        start_time: header.time,
        end_time: header.time,
        start_target: header.bits,
        end_target: header.bits,
        start_sapling_root: sapling_root,
        end_sapling_root: sapling_root,
        subtree_total_work: work,
        start_height: height as u64,
        end_height: height as u64,
        sapling_tx,
    };
    let leaf = match epoch.version {
        NodeVersion::V1 => HistoryNode::V1(v1),
        NodeVersion::V2 | NodeVersion::V3 => {
            let ts = zebrad.get_tree_state(&height.to_string()).await?;
            let orchard_root = parse_orchard_tree_root(&ts.orchard.commitments.final_state);
            let v2 = NodeDataV2 {
                v1,
                start_orchard_root: orchard_root,
                end_orchard_root: orchard_root,
                orchard_tx,
            };
            if epoch.version == NodeVersion::V2 {
                HistoryNode::V2(v2)
            } else {
                let frontier = ts
                    .ironwood
                    .as_ref()
                    .map(|t| t.commitments.final_state.as_str())
                    .unwrap_or("");
                let ironwood_root = parse_frontier_tree_root::<MerkleHashOrchard>(frontier);
                HistoryNode::V3(NodeDataV3 {
                    v2,
                    start_ironwood_root: ironwood_root,
                    end_ironwood_root: ironwood_root,
                    ironwood_tx,
                })
            }
        }
    };
    Ok(BlockLeaf {
        height,
        header,
        leaf,
        auth_data_root: block_auth_data_root(&block)?,
    })
}

/// The value a block in `epoch` must carry for a history root.
fn expected_commitment(epoch: &Epoch, root_hash: &[u8; 32], adr: &[u8; 32]) -> [u8; 32] {
    if epoch.commits_root_directly() {
        *root_hash
    } else {
        block_commitments(root_hash, adr)
    }
}

#[derive(Default)]
struct State {
    /// activation height -> that epoch's tree
    stores: BTreeMap<u32, HistoryStore>,
    /// Last block whose leaf is in a store.
    indexed_to: Option<u32>,
    /// Set when a header disagrees with our tree. Nothing is served until a
    /// rollback clears it.
    fault: Option<String>,
}

impl State {
    fn store_for(&mut self, epoch: &Epoch) -> &mut HistoryStore {
        self.stores.entry(epoch.activation).or_default()
    }

    fn leaf_hash(&self, schedule: &Schedule, height: u32) -> Option<[u8; 32]> {
        let e = schedule.at(height)?;
        let leaf = self
            .stores
            .get(&e.activation)?
            .leaf((height - e.activation) as u64)?;
        Some(leaf.v1().subtree_commitment)
    }

    fn truncate_to(&mut self, schedule: &Schedule, last_kept: u32) {
        for (activation, store) in self.stores.iter_mut() {
            let keep = if last_kept < *activation {
                0
            } else {
                (last_kept - activation + 1) as u64
            };
            if store.len() > keep {
                store.truncate(keep);
            }
        }
        self.stores.retain(|_, s| !s.is_empty());
        self.indexed_to = schedule.at(last_kept).map(|_| last_kept);
    }
}

pub struct HistoryIndex {
    network: Network,
    anchor: Anchor,
    /// Upgrade schedule, refreshed from zebrad on every pass so upgrades this
    /// build does not know (NU7, ...) are followed as soon as the node knows
    /// them. Starts from the compiled one.
    schedule: std::sync::RwLock<Schedule>,
    state: RwLock<State>,
    /// Proofs for closed epochs never change; key (activation, lambda, tail).
    closed: Mutex<HashMap<(u32, u32, u32), EpochProof>>,
    /// The tip epoch's proof for the current tip; key (tip hash, lambda, tail).
    tip: Mutex<Option<([u8; 32], u32, u32, EpochProof)>>,
}

impl HistoryIndex {
    pub fn new(network: Network, anchor: Anchor) -> Result<Self> {
        let compiled = Schedule::compiled(network);
        if compiled.activated_at(anchor.height).is_none() {
            return Err(ZidecarError::Validation(format!(
                "FlyClient anchor {} is not a history-tree activation height",
                anchor.height
            )));
        }
        Ok(Self {
            network,
            anchor,
            schedule: std::sync::RwLock::new(compiled),
            state: RwLock::new(State::default()),
            closed: Mutex::new(HashMap::new()),
            tip: Mutex::new(None),
        })
    }

    pub fn anchor(&self) -> Anchor {
        self.anchor
    }

    fn schedule(&self) -> Schedule {
        self.schedule.read().expect("schedule lock").clone()
    }

    /// Take the node's upgrade list when it reports one. A node that knows
    /// fewer upgrades than this build (an old zebrad) keeps the compiled list.
    fn refresh_schedule(&self, upgrades: Vec<(u32, u32)>) {
        let from_node = Schedule::from_upgrades(upgrades);
        let compiled = Schedule::compiled(self.network);
        let pick = if from_node.epochs().len() >= compiled.epochs().len() {
            from_node
        } else {
            compiled
        };
        let mut s = self.schedule.write().expect("schedule lock");
        if *s != pick {
            if let Some(e) = pick.epochs().last() {
                info!(
                    "history: upgrade schedule has {} epochs, newest branch {:08x} at {}",
                    pick.epochs().len(),
                    e.branch_id,
                    e.activation
                );
            }
            *s = pick;
        }
    }

    /// Reload stored leaves into memory. Stops at the first gap.
    async fn load(&self, storage: &Storage) -> Result<()> {
        let schedule = self.schedule();
        let mut st = self.state.write().await;
        let mut height = self.anchor.height;
        while let Some(bytes) = storage.get_history_leaf(height)? {
            let Some(epoch) = schedule.at(height) else {
                break;
            };
            let node = HistoryNode::from_bytes(epoch.version, epoch.branch_id, &bytes)
                .map_err(|e| ZidecarError::Storage(format!("history leaf {height}: {e}")))?;
            if let Err(e) = st.store_for(&epoch).push(node) {
                warn!("history: stored leaf {height} does not extend the tree ({e}); reindexing from there");
                storage.delete_history_from(height)?;
                break;
            }
            st.indexed_to = Some(height);
            height += 1;
        }
        if let Some(h) = st.indexed_to {
            info!("history: loaded leaves {}..={}", self.anchor.height, h);
        }
        Ok(())
    }

    /// Index blocks until the tip, then follow it.
    pub async fn run(
        self: Arc<Self>,
        zebrad: ZebradClient,
        storage: Arc<Storage>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        info!(
            "history: FlyClient index from anchor {}",
            self.anchor.height
        );
        if let Err(e) = self.load(&storage).await {
            error!("history: could not load stored leaves: {e}");
        }
        loop {
            let wait = match self.step(&zebrad, &storage).await {
                Ok(true) => Duration::from_secs(10),
                Ok(false) => Duration::ZERO,
                Err(e) => {
                    warn!("history: {e}");
                    Duration::from_secs(30)
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => {
                    info!("history: shutdown received");
                    return;
                }
            }
        }
    }

    /// Index one batch. Returns `true` when caught up with the tip.
    async fn step(&self, zebrad: &ZebradClient, storage: &Storage) -> Result<bool> {
        let info = zebrad.get_blockchain_info().await?;
        self.refresh_schedule(info.upgrade_schedule());
        let schedule = self.schedule();
        let tip = info.blocks;
        let next = {
            let st = self.state.read().await;
            st.indexed_to.map_or(self.anchor.height, |h| h + 1)
        };
        if next > tip {
            return Ok(true);
        }
        let end = tip.min(next + 999);
        let leaves: Vec<BlockLeaf> = stream::iter(next..=end)
            .map(|h| {
                let schedule = &schedule;
                async move {
                    let epoch = schedule.at(h).ok_or_else(|| {
                        ZidecarError::Validation(format!("height {h} has no history epoch"))
                    })?;
                    fetch_leaf(zebrad, &epoch, h).await
                }
            })
            .buffered(FETCH_CONCURRENCY)
            .try_collect()
            .await?;

        let mut st = self.state.write().await;
        for b in leaves {
            // a reorg shows up as a parent we do not have
            if let Some(prev) = b
                .height
                .checked_sub(1)
                .and_then(|p| st.leaf_hash(&schedule, p))
            {
                if prev != b.header.prev_hash {
                    drop(st);
                    self.rollback(zebrad, storage, b.height - 1).await?;
                    return Ok(false);
                }
            }
            let epoch = schedule.at(b.height).expect("checked when fetched");
            self.check_commitment(&st, &schedule, &epoch, &b)?;
            st.store_for(&epoch)
                .push(b.leaf.clone())
                .map_err(|e| ZidecarError::Validation(format!("history leaf {}: {e}", b.height)))?;
            storage.store_history_leaf(b.height, &b.leaf.to_bytes(), &b.auth_data_root)?;
            st.indexed_to = Some(b.height);
            st.fault = None;
        }
        Ok(end == tip)
    }

    /// Fail-closed self-check: the block's header must commit to the tree we
    /// built from the blocks before it.
    fn check_commitment(
        &self,
        st: &State,
        schedule: &Schedule,
        epoch: &Epoch,
        b: &BlockLeaf,
    ) -> Result<()> {
        let expected = if b.height == epoch.activation {
            // An activation block commits to the previous epoch's complete
            // tree, under its own epoch's rule. Heartwood's commits to nothing.
            let prev = schedule.before(epoch);
            match prev.and_then(|p| st.stores.get(&p.activation).map(|s| (p, s))) {
                Some((p, store)) if store.len() == (epoch.activation - p.activation) as u64 => {
                    let root = store
                        .root()
                        .map_err(|e| ZidecarError::Validation(e.to_string()))?;
                    Some(expected_commitment(epoch, &root.hash(), &b.auth_data_root))
                }
                // below the anchor: nothing of ours to compare with
                _ => None,
            }
        } else {
            let n = (b.height - epoch.activation) as u64;
            let store = st.stores.get(&epoch.activation);
            let root = store
                .filter(|s| s.len() == n)
                .ok_or_else(|| {
                    ZidecarError::Validation(format!(
                        "history: block {} arrived without its epoch's earlier leaves",
                        b.height
                    ))
                })?
                .root()
                .map_err(|e| ZidecarError::Validation(e.to_string()))?;
            Some(expected_commitment(epoch, &root.hash(), &b.auth_data_root))
        };
        if let Some(expected) = expected {
            if expected != b.header.commitments {
                let msg = format!(
                    "block {} commits to {} but our history tree gives {}; refusing to serve",
                    b.height,
                    hex::encode(b.header.commitments),
                    hex::encode(expected)
                );
                error!("history: {msg}");
                return Err(ZidecarError::Validation(msg));
            }
        }
        Ok(())
    }

    /// Walk back from `from` to the last block zebrad still agrees with and
    /// drop everything above it.
    async fn rollback(&self, zebrad: &ZebradClient, storage: &Storage, from: u32) -> Result<()> {
        let mut h = from;
        loop {
            if from - h > MAX_REORG || h < self.anchor.height {
                let msg = format!("reorg below {h} is deeper than {MAX_REORG} blocks");
                self.state.write().await.fault = Some(msg.clone());
                return Err(ZidecarError::Validation(msg));
            }
            let ours = self.state.read().await.leaf_hash(&self.schedule(), h);
            let theirs = hex32_reversed(&zebrad.get_block_hash(h).await?)?;
            if ours == Some(theirs) {
                break;
            }
            h -= 1;
        }
        warn!("history: reorg, rolling back to {h}");
        storage.delete_history_from(h + 1)?;
        let mut st = self.state.write().await;
        st.truncate_to(&self.schedule(), h);
        *self.tip.lock().await = None;
        Ok(())
    }

    /// Build a FlyClient proof from the anchor to the latest indexed block.
    pub async fn proof(
        &self,
        zebrad: &ZebradClient,
        storage: &Storage,
        params: FlyParams,
    ) -> Result<FlyClientProof> {
        let params = FlyParams {
            lambda: params.lambda.clamp(1, MAX_LAMBDA),
            tail: params.tail.clamp(1, MAX_TAIL),
        };
        let (tip, fault) = {
            let st = self.state.read().await;
            (st.indexed_to, st.fault.clone())
        };
        if let Some(f) = fault {
            return Err(ZidecarError::Validation(format!(
                "history index is faulted: {f}"
            )));
        }
        let mut commit =
            tip.ok_or_else(|| ZidecarError::Validation("history index is empty".into()))?;
        // an activation block's own tree is empty; let its parent commit instead
        let schedule = self.schedule();
        if schedule.at(commit).map(|e| e.activation) == Some(commit) {
            commit -= 1;
        }

        // (epoch, committing height), newest first, down to the anchor
        let mut plan = Vec::new();
        let mut c = commit;
        loop {
            let e = schedule.at(c).ok_or_else(|| {
                ZidecarError::Validation(format!("height {c} has no history epoch"))
            })?;
            if c <= e.activation {
                return Err(ZidecarError::Validation(
                    "history index has not reached the anchor epoch's second block".into(),
                ));
            }
            plan.push((e, c));
            if e.activation <= self.anchor.height {
                break;
            }
            c = e.activation - 1;
        }

        let mut epochs_out = Vec::with_capacity(plan.len());
        for (i, (epoch, c)) in plan.iter().enumerate() {
            let closed = i > 0;
            if closed {
                if let Some(p) =
                    self.closed
                        .lock()
                        .await
                        .get(&(epoch.activation, params.lambda, params.tail))
                {
                    epochs_out.push(p.clone());
                    continue;
                }
            }
            let commit_header = fetch_header(zebrad, *c).await?;
            let commit_hash = BlockHeader::parse(&commit_header)
                .map_err(|e| ZidecarError::Validation(e.to_string()))?
                .hash;
            if !closed {
                if let Some((h, l, t, p)) = self.tip.lock().await.as_ref() {
                    if *h == commit_hash && *l == params.lambda && *t == params.tail {
                        epochs_out.push(p.clone());
                        continue;
                    }
                }
            }
            let ep = self
                .epoch_proof(
                    zebrad,
                    storage,
                    epoch,
                    *c,
                    commit_header,
                    &commit_hash,
                    &params,
                )
                .await?;
            if closed {
                self.closed
                    .lock()
                    .await
                    .insert((epoch.activation, params.lambda, params.tail), ep.clone());
            } else {
                *self.tip.lock().await =
                    Some((commit_hash, params.lambda, params.tail, ep.clone()));
            }
            epochs_out.push(ep);
        }

        let proof = FlyClientProof { epochs: epochs_out };
        // serve nothing we would not accept ourselves (a reorg mid-build, a
        // stale cache entry, a bug)
        let network = self.network;
        let anchor = self.anchor;
        let checked = proof.clone();
        tokio::task::spawn_blocking(move || verify_flyclient(&checked, network, &params, &anchor))
            .await
            .map_err(|e| ZidecarError::Validation(format!("proof self-check panicked: {e}")))?
            .map_err(|e| {
                ZidecarError::Validation(format!(
                    "built a FlyClient proof that does not verify: {e}"
                ))
            })?;
        Ok(proof)
    }

    #[allow(clippy::too_many_arguments)]
    async fn epoch_proof(
        &self,
        zebrad: &ZebradClient,
        storage: &Storage,
        epoch: &Epoch,
        commit_height: u32,
        commit_header: Vec<u8>,
        commit_hash: &[u8; 32],
        params: &FlyParams,
    ) -> Result<EpochProof> {
        let n = (commit_height - epoch.activation) as u64;
        let indices = {
            let st = self.state.read().await;
            let store = st
                .stores
                .get(&epoch.activation)
                .ok_or_else(|| ZidecarError::Validation("epoch not indexed".into()))?;
            plan_epoch(store, n, epoch, commit_hash, params)
                .map_err(|e| ZidecarError::Validation(e.to_string()))?
        };
        let headers: HashMap<u64, Vec<u8>> = stream::iter(indices.iter().copied())
            .map(|i| async move {
                fetch_header(zebrad, epoch.activation + i as u32)
                    .await
                    .map(|h| (i, h))
            })
            .buffer_unordered(FETCH_CONCURRENCY)
            .try_collect()
            .await?;
        let adr = if epoch.commits_root_directly() {
            None
        } else {
            Some(storage.get_auth_data_root(commit_height)?.ok_or_else(|| {
                ZidecarError::Validation(format!("no auth data root stored for {commit_height}"))
            })?)
        };
        let st = self.state.read().await;
        let store = st
            .stores
            .get(&epoch.activation)
            .ok_or_else(|| ZidecarError::Validation("epoch not indexed".into()))?;
        assemble_epoch(store, n, epoch, commit_header, adr, &indices, |i| {
            headers.get(&i).cloned()
        })
        .map_err(|e| ZidecarError::Validation(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zebrad::{OrchardAction, OrchardData, RawTransaction, SaplingOutput};

    fn tx(
        sapling_out: bool,
        orchard: usize,
        ironwood: usize,
        digest: Option<&str>,
    ) -> RawTransaction {
        let action = OrchardAction {
            cv: String::new(),
            nullifier: String::new(),
            rk: String::new(),
            cmx: String::new(),
            ephemeral_key: String::new(),
            enc_ciphertext: String::new(),
            out_ciphertext: String::new(),
        };
        RawTransaction {
            txid: String::new(),
            version: 5,
            hex: String::new(),
            height: None,
            sapling_spends: Some(vec![]),
            sapling_outputs: Some(if sapling_out {
                vec![SaplingOutput {
                    cv: String::new(),
                    cmu: String::new(),
                    ephemeral_key: String::new(),
                    enc_ciphertext: String::new(),
                    out_ciphertext: String::new(),
                    zkproof: String::new(),
                }]
            } else {
                vec![]
            }),
            orchard: Some(OrchardData {
                actions: vec![action.clone(); orchard],
            }),
            ironwood: Some(OrchardData {
                actions: vec![action; ironwood],
            }),
            authdigest: digest.map(str::to_string),
        }
    }

    #[test]
    fn the_schedule_follows_what_zebrad_reports() {
        // getblockchaininfo's shape: upgrades keyed by big-endian branch id
        let json = r#"{
            "chain": "main", "blocks": 3500000, "bestblockhash": "00", "difficulty": 1.0,
            "upgrades": {
                "5ba81b19": {"name": "Overwinter", "activationheight": 347500, "status": "active"},
                "f5b9230b": {"name": "Heartwood", "activationheight": 903000, "status": "active"},
                "e9ff75a6": {"name": "Canopy", "activationheight": 1046400, "status": "active"},
                "c2d6d0b4": {"name": "NU5", "activationheight": 1687104, "status": "active"},
                "c8e71055": {"name": "NU6", "activationheight": 2726400, "status": "active"},
                "4dec4df0": {"name": "NU6.1", "activationheight": 3146400, "status": "active"},
                "5437f330": {"name": "NU6.2", "activationheight": 3364600, "status": "active"},
                "37a5165b": {"name": "NU6.3", "activationheight": 3428143, "status": "active"},
                "deadbeef": {"name": "NU7", "activationheight": 3600000, "status": "pending"}
            }
        }"#;
        let info: crate::zebrad::BlockchainInfo = serde_json::from_str(json).unwrap();
        let s = Schedule::from_upgrades(info.upgrade_schedule());
        assert_eq!(s.epochs().first().unwrap().activation, 903_000);
        assert_eq!(s.at(1_700_000).unwrap().branch_id, 0xc2d6_d0b4);
        assert_eq!(s.at(3_500_000).unwrap().end, Some(3_600_000));
        let nu7 = s.at(3_600_001).unwrap();
        assert_eq!(nu7.branch_id, 0xdead_beef);
        assert!(!nu7.commits_root_directly());

        // an index on mainnet takes it, since it knows at least as much
        let index = HistoryIndex::new(
            Network::Mainnet,
            zync_core::flyclient::Anchor::nu6_3_mainnet(),
        )
        .unwrap();
        index.refresh_schedule(info.upgrade_schedule());
        assert_eq!(
            index.schedule().at(3_600_001).unwrap().branch_id,
            0xdead_beef
        );
        // and keeps the compiled list when a node reports nothing
        let index = HistoryIndex::new(
            Network::Mainnet,
            zync_core::flyclient::Anchor::nu6_3_mainnet(),
        )
        .unwrap();
        index.refresh_schedule(vec![]);
        assert_eq!(index.schedule(), Schedule::compiled(Network::Mainnet));
    }

    #[test]
    fn pool_counts_count_transactions_with_a_bundle() {
        let block = BlockVerbose {
            hash: String::new(),
            height: 1,
            tx: vec![
                tx(false, 0, 0, None),
                tx(true, 2, 0, None),
                tx(false, 0, 3, None),
                tx(true, 1, 1, None),
            ],
            finalsaplingroot: None,
        };
        assert_eq!(pool_counts(&block), (2, 2, 2));
    }

    #[test]
    fn auth_data_root_uses_internal_order_and_the_v4_placeholder() {
        let d = "11".repeat(31) + "22";
        let block = BlockVerbose {
            hash: String::new(),
            height: 1,
            tx: vec![tx(false, 0, 0, None), tx(false, 0, 0, Some(&d))],
            finalsaplingroot: None,
        };
        let mut internal = [0x11u8; 32];
        internal[0] = 0x22;
        assert_eq!(
            block_auth_data_root(&block).unwrap(),
            auth_data_root(&[[0xffu8; 32], internal])
        );
    }
}

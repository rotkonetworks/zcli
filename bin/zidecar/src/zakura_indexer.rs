//! Optional adoption of Zakura's node `Indexer` gRPC (`zebra.indexer.rpc`).
//!
//! When `--zakura-indexer-url` is set, this spawns a background subscriber that
//! keeps two shared cells warm from the node's push streams:
//!
//! - **tip**: `ChainTipChange` -> `(height, display-order hash hex)`
//! - **mempool**: `MempoolChange` -> a live txid set, updated by add/remove deltas
//!
//! Readers ([`IndexerWatcher::tip`] / [`IndexerWatcher::mempool_txids`]) return
//! `Some(..)` only while the corresponding stream is live and seeded; on stream
//! end or error the cell is marked stale and returns `None`, so every read site
//! falls back to the JSON-RPC path. This is the safety property: unset flag, a
//! dead stream, or a failed seed all degrade to today's exact behavior.
//!
//! Byte order: both `BlockHashAndHeight.hash` and `MempoolChangeMessage.tx_hash`
//! are produced by Zebra via `bytes_in_display_order()`, so `hex::encode` yields
//! the display-order hex that `getrawtransaction` / `bestblockhash` already use.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;
use tokio_stream::StreamExt;
use tracing::{info, warn};

use crate::zakura_indexer_proto::{
    indexer_client::IndexerClient, mempool_change_message::ChangeType, Empty, MempoolChangeMessage,
};
use crate::zebrad::ZebradClient;

/// The set of mempool txids, kept in sync with the node by `MempoolChange`
/// deltas. `live` gates reads: it is only true after a successful seed and
/// while the stream is up. A stale set returns `None` from `snapshot`, sending
/// the caller back to `get_raw_mempool`.
#[derive(Default)]
pub struct MempoolSet {
    txids: HashSet<String>,
    live: bool,
}

impl MempoolSet {
    /// Replace the set with the node's current mempool contents and mark it
    /// live. `MempoolChange` does not replay existing entries on subscribe, so
    /// without this seed the set would start empty and under-report - a
    /// behavior regression versus the pull path.
    fn seed(&mut self, txids: impl IntoIterator<Item = String>) {
        self.txids = txids.into_iter().collect();
        self.live = true;
    }

    /// Apply one `MempoolChangeMessage`: `ADDED` inserts the txid, `INVALIDATED`
    /// and `MINED` both remove it (the tx has left the mempool either way).
    /// Duplicate insert and remove-of-missing are no-ops, so races between the
    /// seed and buffered deltas are benign.
    pub fn apply(&mut self, m: MempoolChangeMessage) {
        let txid = hex::encode(&m.tx_hash);
        match ChangeType::try_from(m.change_type) {
            Ok(ChangeType::Added) => {
                self.txids.insert(txid);
            }
            Ok(ChangeType::Invalidated) | Ok(ChangeType::Mined) => {
                self.txids.remove(&txid);
            }
            Err(_) => {
                // Unknown enum discriminant from a newer node: ignore rather
                // than guess. The set stays consistent; a missed delta at worst
                // costs one stale entry until the next matching change.
                warn!("indexer mempool: unknown change_type {}", m.change_type);
            }
        }
    }

    /// Current txids, or `None` if the set is not live (caller falls back).
    fn snapshot(&self) -> Option<Vec<String>> {
        if self.live {
            Some(self.txids.iter().cloned().collect())
        } else {
            None
        }
    }

    /// Mark stale: readers fall back to JSON-RPC until the next successful seed.
    fn mark_stale(&mut self) {
        self.live = false;
        self.txids.clear();
    }
}

/// Background subscriber to a Zakura node `Indexer`. Cheap to clone (both cells
/// are `Arc`), so the same watcher is threaded into every read-site owner.
#[derive(Clone)]
pub struct IndexerWatcher {
    tip: Arc<RwLock<Option<(u32, String)>>>,
    mempool: Arc<RwLock<MempoolSet>>,
}

impl IndexerWatcher {
    /// Connect to the node's `Indexer` service, subscribe to the tip + mempool
    /// streams, seed the mempool set, and spawn a task per stream to keep the
    /// cells warm. Returns after both subscriptions are established; the seed is
    /// best-effort (a failed seed leaves the mempool cell stale, i.e. readers
    /// fall back, but the tip cell still works).
    pub async fn spawn(url: String, zebrad: ZebradClient) -> Result<Self> {
        let mut client = IndexerClient::connect(url.clone()).await?;
        let watcher = Self {
            tip: Arc::new(RwLock::new(None)),
            mempool: Arc::new(RwLock::new(MempoolSet::default())),
        };

        // Establish BOTH subscriptions before spawning either task: if the
        // mempool subscribe fails, `spawn` returns Err and the caller sets the
        // watcher to None - we must not have left a tip task running against a
        // watcher nobody reads. The mempool stream is subscribed before the
        // seed so no change is missed in the gap between seeding and the first
        // delta (a duplicate insert / remove-of-missing is a no-op).
        let mut tip_stream = client.chain_tip_change(Empty {}).await?.into_inner();
        let mut mempool_stream = client.mempool_change(Empty {}).await?.into_inner();

        // Seed the mempool set from JSON-RPC (the stream carries deltas only,
        // it does not replay existing contents on subscribe). Best-effort: a
        // failed seed leaves the mempool cell stale (readers fall back) while
        // the tip cell still works.
        match zebrad.get_raw_mempool().await {
            Ok(txids) => {
                let n = txids.len();
                watcher.mempool.write().await.seed(txids);
                info!("indexer mempool: seeded with {n} txids");
            }
            Err(e) => {
                warn!("indexer mempool seed failed: {e}; mempool reads fall back to JSON-RPC");
            }
        }

        // Tip task: overwrite the cell on each push; clear it when the stream
        // ends so readers fall back. There is no reconnect loop - a dead stream
        // means permanent JSON-RPC fallback until the process restarts.
        {
            let tip = watcher.tip.clone();
            tokio::spawn(async move {
                while let Some(item) = tip_stream.next().await {
                    match item {
                        Ok(h) => {
                            *tip.write().await = Some((h.height, hex::encode(&h.hash)));
                        }
                        Err(e) => {
                            warn!("indexer tip stream error: {e}");
                            break;
                        }
                    }
                }
                warn!("indexer tip stream ended; tip reads fall back to JSON-RPC");
                *tip.write().await = None;
            });
        }

        // Mempool task: apply add/remove deltas; mark stale on stream end.
        {
            let mempool = watcher.mempool.clone();
            tokio::spawn(async move {
                while let Some(item) = mempool_stream.next().await {
                    match item {
                        Ok(m) => mempool.write().await.apply(m),
                        Err(e) => {
                            warn!("indexer mempool stream error: {e}");
                            break;
                        }
                    }
                }
                warn!("indexer mempool stream ended; mempool reads fall back to JSON-RPC");
                mempool.write().await.mark_stale();
            });
        }

        Ok(watcher)
    }

    /// Latest tip `(height, display-order hash hex)`, or `None` if the tip
    /// stream is not live (caller reads `get_blockchain_info`).
    pub async fn tip(&self) -> Option<(u32, String)> {
        self.tip.read().await.clone()
    }

    /// Current mempool txids (display-order hex), or `None` if the mempool set
    /// is not live (caller reads `get_raw_mempool`).
    pub async fn mempool_txids(&self) -> Option<Vec<String>> {
        self.mempool.read().await.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(kind: ChangeType, txid_byte: u8) -> MempoolChangeMessage {
        MempoolChangeMessage {
            change_type: kind as i32,
            tx_hash: vec![txid_byte; 32],
            auth_digest: vec![],
        }
    }

    #[test]
    fn apply_models_add_and_remove_deltas() {
        let mut set = MempoolSet::default();
        // not live until seeded
        assert!(set.snapshot().is_none());

        set.seed(Vec::<String>::new());
        assert_eq!(set.snapshot().unwrap().len(), 0);

        // ADDED inserts
        set.apply(msg(ChangeType::Added, 0xaa));
        let snap = set.snapshot().unwrap();
        assert_eq!(snap, vec![hex::encode([0xaa; 32])]);

        // MINED removes
        set.apply(msg(ChangeType::Mined, 0xaa));
        assert_eq!(set.snapshot().unwrap().len(), 0);

        // INVALIDATED removes
        set.apply(msg(ChangeType::Added, 0xbb));
        set.apply(msg(ChangeType::Invalidated, 0xbb));
        assert_eq!(set.snapshot().unwrap().len(), 0);

        // remove-of-missing is a no-op (does not panic, stays empty)
        set.apply(msg(ChangeType::Mined, 0xcc));
        assert_eq!(set.snapshot().unwrap().len(), 0);

        // duplicate insert is a no-op
        set.apply(msg(ChangeType::Added, 0xdd));
        set.apply(msg(ChangeType::Added, 0xdd));
        assert_eq!(set.snapshot().unwrap().len(), 1);
    }

    #[test]
    fn mark_stale_forces_fallback() {
        let mut set = MempoolSet::default();
        set.seed(vec![hex::encode([0x01; 32])]);
        assert!(set.snapshot().is_some());
        set.mark_stale();
        assert!(set.snapshot().is_none());
    }
}

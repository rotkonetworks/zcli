//! background sync worker — keeps wallet synced and monitors mempool

use crate::SharedState;
use tracing::{info, warn};
use zecli::client::ZidecarClient;
use zecli::wallet::Wallet;

/// Ceiling on the retry delay after failed syncs. A wallet whose stored actions
/// commitment cannot be verified fails after a full rescan every time; without a
/// ceiling the daemon turns that into a continuous loop.
const MAX_BACKOFF_SECS: u64 = 600;

pub struct Syncer {
    pub fvk: orchard::keys::FullViewingKey,
    pub endpoint: String,
    pub verify_endpoints: String,
    pub mainnet: bool,
    pub wallet_path: String,
    pub state: SharedState,
    pub sync_interval: u64,
    pub mempool_interval: u64,
}

impl Syncer {
    pub async fn run(&self) {
        info!("starting initial sync...");
        // Initial sync BEFORE the mempool task: it is usually the long catch-up,
        // and every mempool tick during it would only contend for the wallet
        // lock it holds, against a wallet that isn't caught up anyway.
        let first_ok = self.do_sync().await;

        let state = self.state.clone();
        let endpoint = self.endpoint.clone();
        let wallet_path = self.wallet_path.clone();
        let interval = self.mempool_interval;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
                scan_mempool(&endpoint, &wallet_path, &state).await;
            }
        });

        // A failed sync costs a full rescan of everything from the stored height,
        // which on a dense chain is minutes: retrying on the fixed interval hammers
        // the server and holds the wallet lock almost continuously, which is how a
        // wallet that cannot verify its saved actions commitment (a server that
        // changed proof base, or a height/commitment pair knocked out of sync) ends
        // up never syncing at all. Back off instead, and keep the first failure's
        // message - it is the one that names the repair.
        let base = self.sync_interval.max(1);
        let mut failures: u32 = if first_ok { 0 } else { 1 };

        loop {
            let delay = retry_delay(base, failures);
            if failures > 0 {
                warn!(
                    "sync failed {} time(s) without completing; retrying in {}s",
                    failures, delay
                );
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;

            if self.do_sync().await {
                failures = 0;
            } else {
                failures += 1;
            }
        }
    }

    /// One sync pass. Returns whether it completed - a failure is worth a delay,
    /// not just a log line.
    async fn do_sync(&self) -> bool {
        {
            self.state.write().await.syncing = true;
        }

        let result = zecli::ops::sync::sync_with_fvk(
            &self.fvk,
            &self.endpoint,
            &self.verify_endpoints,
            self.mainnet,
            true,
            None,
            None,
        )
        .await;

        let ok = match result {
            Ok(found) => {
                if found > 0 {
                    info!("sync: {} new notes", found);
                }
                true
            }
            Err(e) => {
                warn!("sync failed: {}", e);
                false
            }
        };

        if let Ok(wallet) = Wallet::open(&self.wallet_path) {
            let height = wallet.sync_height().unwrap_or(0);
            let mut s = self.state.write().await;
            s.synced_to = height;
            s.syncing = false;
        }

        if let Ok(client) = ZidecarClient::connect(&self.endpoint).await {
            if let Ok((tip, _)) = client.get_tip().await {
                self.state.write().await.chain_tip = tip;
            }
        }

        ok
    }
}

async fn scan_mempool(endpoint: &str, wallet_path: &str, state: &SharedState) {
    let client = match ZidecarClient::connect(endpoint).await {
        Ok(c) => c,
        Err(_) => return,
    };

    let blocks = match client.get_mempool_stream().await {
        Ok(b) => b,
        Err(_) => return,
    };

    let total_actions: usize = blocks.iter().map(|b| b.actions.len()).sum();

    let wallet = match Wallet::open(wallet_path) {
        Ok(w) => w,
        Err(_) => return,
    };

    let wallet_nfs: Vec<[u8; 32]> = wallet
        .shielded_balance()
        .map(|(_, notes)| notes.iter().map(|n| n.nullifier).collect())
        .unwrap_or_default();

    let mut events = Vec::new();
    for block in &blocks {
        for action in &block.actions {
            if wallet_nfs.contains(&action.nullifier) {
                events.push(crate::proto::PendingEvent {
                    kind: crate::proto::pending_event::Kind::Spend as i32,
                    value_zat: 0,
                    txid: block.hash.clone(),
                    nullifier: action.nullifier.to_vec(),
                });
            }
        }
    }

    let mut s = state.write().await;
    s.mempool_txs_seen = blocks.len() as u32;
    s.mempool_actions_scanned = total_actions as u32;
    s.pending_events = events;
}

/// Delay before the next sync attempt: the configured interval while healthy,
/// doubling per consecutive failure up to [`MAX_BACKOFF_SECS`]. A wallet that
/// cannot verify its stored actions commitment fails *after* a full rescan every
/// time, so without the cap the daemon retries back to back and holds the wallet
/// lock almost continuously.
fn retry_delay(base: u64, failures: u32) -> u64 {
    if failures == 0 {
        return base;
    }
    base.saturating_mul(1u64 << failures.min(5))
        .min(MAX_BACKOFF_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_doubles_per_failure_then_caps() {
        assert_eq!(retry_delay(30, 0), 30);
        assert_eq!(retry_delay(30, 1), 60);
        assert_eq!(retry_delay(30, 2), 120);
        assert_eq!(retry_delay(30, 3), 240);
        assert_eq!(retry_delay(30, 4), 480);
        // 30 << 5 = 960, above the ceiling
        assert_eq!(retry_delay(30, 5), MAX_BACKOFF_SECS);
        assert_eq!(retry_delay(30, u32::MAX), MAX_BACKOFF_SECS);
    }
}

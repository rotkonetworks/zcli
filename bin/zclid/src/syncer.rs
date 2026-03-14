//! background sync worker — keeps wallet synced and monitors mempool

use crate::SharedState;
use tracing::{info, warn};
use zecli::client::ZidecarClient;
use zecli::wallet::Wallet;

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
        self.do_sync().await;

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

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(self.sync_interval)).await;
            self.do_sync().await;
        }
    }

    async fn do_sync(&self) {
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

        match result {
            Ok(found) => {
                if found > 0 {
                    info!("sync: {} new notes", found);
                }
            }
            Err(e) => warn!("sync failed: {}", e),
        }

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

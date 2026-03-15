//! lightwalletd CompactTxStreamer compatibility layer
//!
//! Implements the standard lightwalletd gRPC interface so that any wallet
//! supporting lightwalletd (Zashi, Nighthawk, etc.) can point directly at
//! zidecar without a separate lightwalletd instance.

use crate::lightwalletd::{
    compact_tx_streamer_server::CompactTxStreamer, BlockId, BlockRange, ChainMetadata, ChainSpec,
    CompactBlock, CompactOrchardAction, CompactTx, Empty, GetAddressUtxosArg, GetAddressUtxosReply,
    GetAddressUtxosReplyList, GetSubtreeRootsArg, LightdInfo, RawTransaction, SendResponse,
    SubtreeRoot, TreeState, TxFilter,
};
use crate::{compact::CompactBlock as InternalBlock, storage::Storage, zebrad::ZebradClient};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, warn};

pub struct LwdService {
    zebrad: ZebradClient,
    storage: Arc<Storage>,
    testnet: bool,
}

impl LwdService {
    pub fn new(zebrad: ZebradClient, storage: Arc<Storage>, testnet: bool) -> Self {
        Self {
            zebrad,
            storage,
            testnet,
        }
    }

    fn chain_name(&self) -> &'static str {
        if self.testnet {
            "testnet"
        } else {
            "mainnet"
        }
    }
}

/// Convert internal compact block to lightwalletd wire format.
/// Groups actions by txid into CompactTx entries.
fn to_lwd_block(
    block: &InternalBlock,
    prev_hash: Vec<u8>,
    time: u32,
    sapling_tree_size: u32,
    orchard_tree_size: u32,
) -> CompactBlock {
    use std::collections::HashMap;

    let mut tx_map: HashMap<Vec<u8>, Vec<CompactOrchardAction>> = HashMap::new();
    let mut tx_order: Vec<Vec<u8>> = Vec::new();

    for action in &block.actions {
        if !tx_map.contains_key(&action.txid) {
            tx_order.push(action.txid.clone());
            tx_map.insert(action.txid.clone(), Vec::new());
        }
        tx_map
            .get_mut(&action.txid)
            .unwrap()
            .push(CompactOrchardAction {
                nullifier: action.nullifier.clone(),
                cmx: action.cmx.clone(),
                ephemeral_key: action.ephemeral_key.clone(),
                ciphertext: action.ciphertext.clone(),
            });
    }

    let vtx: Vec<CompactTx> = tx_order
        .into_iter()
        .enumerate()
        .map(|(i, txid)| CompactTx {
            index: i as u64,
            hash: txid.clone(),
            fee: 0,
            spends: vec![],
            outputs: vec![],
            actions: tx_map.remove(&txid).unwrap_or_default(),
        })
        .collect();

    CompactBlock {
        proto_version: 1,
        height: block.height as u64,
        hash: block.hash.clone(),
        prev_hash,
        time,
        header: vec![],
        vtx,
        chain_metadata: Some(ChainMetadata {
            sapling_commitment_tree_size: sapling_tree_size,
            orchard_commitment_tree_size: orchard_tree_size,
        }),
    }
}

/// Fetch commitment tree sizes at a given height from zebrad.
async fn tree_sizes_at(zebrad: &ZebradClient, height: u32) -> (u32, u32) {
    match zebrad.get_tree_state(&height.to_string()).await {
        Ok(ts) => (
            ts.sapling.commitments.final_state_size.unwrap_or(0),
            ts.orchard.commitments.final_state_size.unwrap_or(0),
        ),
        Err(_) => (0, 0),
    }
}

/// Fetch prev_hash bytes for a given height (returns zeros for genesis).
async fn prev_hash_for(zebrad: &ZebradClient, height: u32) -> Vec<u8> {
    if height == 0 {
        return vec![0u8; 32];
    }
    zebrad
        .get_block_hash(height - 1)
        .await
        .ok()
        .and_then(|h| hex::decode(&h).ok())
        .unwrap_or_else(|| vec![0u8; 32])
}

#[tonic::async_trait]
impl CompactTxStreamer for LwdService {
    type GetBlockRangeStream = ReceiverStream<Result<CompactBlock, Status>>;
    type GetAddressUtxosStreamStream = ReceiverStream<Result<GetAddressUtxosReply, Status>>;
    type GetSubtreeRootsStream = ReceiverStream<Result<SubtreeRoot, Status>>;

    async fn get_latest_block(&self, _: Request<ChainSpec>) -> Result<Response<BlockId>, Status> {
        let info = self
            .zebrad
            .get_blockchain_info()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(BlockId {
            height: info.blocks as u64,
            hash: hex::decode(&info.bestblockhash).unwrap_or_default(),
        }))
    }

    async fn get_block(&self, req: Request<BlockId>) -> Result<Response<CompactBlock>, Status> {
        let id = req.into_inner();
        let height = id.height as u32;

        let hash_str = self
            .zebrad
            .get_block_hash(height)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let block_meta = self
            .zebrad
            .get_block(&hash_str, 1)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let block = InternalBlock::from_zebrad(&self.zebrad, height)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let prev_hash = prev_hash_for(&self.zebrad, height).await;
        let (sapling_size, orchard_size) = tree_sizes_at(&self.zebrad, height).await;

        Ok(Response::new(to_lwd_block(
            &block,
            prev_hash,
            block_meta.time as u32,
            sapling_size,
            orchard_size,
        )))
    }

    async fn get_block_range(
        &self,
        req: Request<BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        let range = req.into_inner();
        let start = range.start.map(|b| b.height as u32).unwrap_or(0);
        let end = range.end.map(|b| b.height as u32).unwrap_or(start);

        let (tx, rx) = mpsc::channel(32);
        let zebrad = self.zebrad.clone();

        tokio::spawn(async move {
            for height in start..=end {
                let hash_str = match zebrad.get_block_hash(height).await {
                    Ok(h) => h,
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        break;
                    }
                };
                let block_meta = match zebrad.get_block(&hash_str, 1).await {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        break;
                    }
                };
                let block = match InternalBlock::from_zebrad(&zebrad, height).await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("lwd range height {}: {}", height, e);
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        break;
                    }
                };
                let prev_hash = prev_hash_for(&zebrad, height).await;
                let (sapling_size, orchard_size) = tree_sizes_at(&zebrad, height).await;
                if tx
                    .send(Ok(to_lwd_block(
                        &block,
                        prev_hash,
                        block_meta.time as u32,
                        sapling_size,
                        orchard_size,
                    )))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_transaction(
        &self,
        req: Request<TxFilter>,
    ) -> Result<Response<RawTransaction>, Status> {
        let filter = req.into_inner();
        let txid_hex = hex::encode(&filter.hash);

        let tx = self
            .zebrad
            .get_raw_transaction(&txid_hex)
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

        let data = hex::decode(&tx.hex).map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RawTransaction {
            data,
            height: tx.height.unwrap_or(0) as u64,
        }))
    }

    async fn send_transaction(
        &self,
        req: Request<RawTransaction>,
    ) -> Result<Response<SendResponse>, Status> {
        let raw = req.into_inner();
        let hex_tx = hex::encode(&raw.data);

        match self.zebrad.send_raw_transaction(&hex_tx).await {
            Ok(txid) => Ok(Response::new(SendResponse {
                error_code: 0,
                error_message: txid,
            })),
            Err(e) => Ok(Response::new(SendResponse {
                error_code: -1,
                error_message: e.to_string(),
            })),
        }
    }

    async fn get_tree_state(&self, req: Request<BlockId>) -> Result<Response<TreeState>, Status> {
        let id = req.into_inner();
        let key = if !id.hash.is_empty() {
            hex::encode(&id.hash)
        } else {
            id.height.to_string()
        };

        let ts = self
            .zebrad
            .get_tree_state(&key)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(TreeState {
            network: self.chain_name().to_string(),
            height: ts.height as u64,
            hash: ts.hash,
            time: ts.time as u32,
            sapling_tree: ts.sapling.commitments.final_state,
            orchard_tree: ts.orchard.commitments.final_state,
        }))
    }

    async fn get_address_utxos(
        &self,
        req: Request<GetAddressUtxosArg>,
    ) -> Result<Response<GetAddressUtxosReplyList>, Status> {
        let arg = req.into_inner();
        let mut utxos = Vec::new();

        let results = self
            .zebrad
            .get_address_utxos(&arg.addresses)
            .await
            .unwrap_or_default();

        for u in results {
            utxos.push(GetAddressUtxosReply {
                address: u.address,
                txid: hex::decode(&u.txid).unwrap_or_default(),
                index: u.output_index as i32,
                script: hex::decode(&u.script).unwrap_or_default(),
                value_zat: u.satoshis as i64,
                height: u.height as u64,
            });
        }

        Ok(Response::new(GetAddressUtxosReplyList {
            address_utxos: utxos,
        }))
    }

    async fn get_address_utxos_stream(
        &self,
        req: Request<GetAddressUtxosArg>,
    ) -> Result<Response<Self::GetAddressUtxosStreamStream>, Status> {
        let list = self.get_address_utxos(req).await?.into_inner();
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(async move {
            for u in list.address_utxos {
                if tx.send(Ok(u)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_subtree_roots(
        &self,
        req: Request<GetSubtreeRootsArg>,
    ) -> Result<Response<Self::GetSubtreeRootsStream>, Status> {
        let arg = req.into_inner();
        let pool = match arg.shielded_protocol() {
            crate::lightwalletd::ShieldedProtocol::Sapling => "sapling",
            crate::lightwalletd::ShieldedProtocol::Orchard => "orchard",
        };

        let limit = if arg.max_entries > 0 {
            Some(arg.max_entries)
        } else {
            None
        };

        let response = self
            .zebrad
            .get_subtrees_by_index(pool, arg.start_index, limit)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(async move {
            for subtree in response.subtrees {
                let root_hash = hex::decode(&subtree.root).unwrap_or_default();
                let root = SubtreeRoot {
                    root_hash,
                    completing_block_hash: vec![],
                    completing_block_height: subtree.end_height as u64,
                };
                if tx.send(Ok(root)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_lightd_info(&self, _: Request<Empty>) -> Result<Response<LightdInfo>, Status> {
        let info = self
            .zebrad
            .get_blockchain_info()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let sapling_height: u64 = if self.testnet { 280000 } else { 419200 };

        Ok(Response::new(LightdInfo {
            version: "0.4.18".to_string(),
            vendor: "zidecar/rotkonetworks".to_string(),
            taddr_support: true,
            chain_name: self.chain_name().to_string(),
            sapling_activation_height: sapling_height,
            consensus_branch_id: info
                .consensus
                .as_ref()
                .map(|c| c.chaintip.clone())
                .unwrap_or_default(),
            block_height: info.blocks as u64,
            git_commit: format!("v{}-{}", env!("CARGO_PKG_VERSION"), env!("GIT_HASH")),
            branch: "main".to_string(),
            build_date: String::new(),
            build_user: "zidecar".to_string(),
            estimated_height: info.blocks as u64,
            zcashd_build: String::new(),
            zcashd_subversion: String::new(),
        }))
    }
}

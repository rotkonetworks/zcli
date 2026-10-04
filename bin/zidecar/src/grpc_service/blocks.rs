//! block-related gRPC handlers

use super::{MempoolCache, ZidecarService};
use crate::{
    compact::CompactBlock as InternalCompactBlock,
    error::{Result, ZidecarError},
    zebrad::ZebradClient,
    zidecar::{
        BlockId, BlockRange, BlockTransactions,
        CompactAction as ProtoCompactAction, CompactBlock as ProtoCompactBlock, Empty,
        RawTransaction, SendResponse, TransparentAddressFilter, TreeState, TxFilter, TxidList,
        Utxo, UtxoList,
    },
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

impl ZidecarService {
    pub(crate) async fn handle_get_compact_blocks(
        &self,
        request: Request<BlockRange>,
    ) -> std::result::Result<
        Response<ReceiverStream<std::result::Result<ProtoCompactBlock, Status>>>,
        Status,
    > {
        let range = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(128);

        let zebrad = self.zebrad.clone();
        let start = range.start_height;
        let end = range.end_height;

        tokio::spawn(async move {
            for height in start..=end {
                match InternalCompactBlock::from_zebrad(&zebrad, height).await {
                    Ok(block) => {
                        let proto_block = ProtoCompactBlock {
                            height: block.height,
                            hash: block.hash,
                            actions: to_proto_actions(block.actions),
                            ironwood_actions: to_proto_actions(block.ironwood_actions),
                        };

                        if tx.send(Ok(proto_block)).await.is_err() {
                            warn!("client disconnected during stream");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("failed to fetch block {}: {}", height, e);
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        break;
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    pub(crate) async fn handle_get_tip(
        &self,
        _request: Request<Empty>,
    ) -> std::result::Result<Response<BlockId>, Status> {
        match self.zebrad.get_blockchain_info().await {
            Ok(info) => {
                let hash = hex::decode(&info.bestblockhash)
                    .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(BlockId {
                    height: info.blocks,
                    hash,
                }))
            }
            Err(e) => {
                error!("failed to get tip: {}", e);
                Err(Status::internal(e.to_string()))
            }
        }
    }

    pub(crate) async fn handle_subscribe_blocks(
        &self,
        _request: Request<Empty>,
    ) -> std::result::Result<Response<ReceiverStream<std::result::Result<BlockId, Status>>>, Status>
    {
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        let zebrad = self.zebrad.clone();

        tokio::spawn(async move {
            let mut last_height = 0;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

                match zebrad.get_blockchain_info().await {
                    Ok(info) => {
                        if info.blocks > last_height {
                            last_height = info.blocks;
                            let hash = match hex::decode(&info.bestblockhash) {
                                Ok(h) => h,
                                Err(e) => {
                                    error!("invalid hash: {}", e);
                                    continue;
                                }
                            };
                            if tx
                                .send(Ok(BlockId {
                                    height: info.blocks,
                                    hash,
                                }))
                                .await
                                .is_err()
                            {
                                info!("client disconnected from subscription");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("failed to poll blockchain: {}", e);
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    pub(crate) async fn handle_get_transaction(
        &self,
        request: Request<TxFilter>,
    ) -> std::result::Result<Response<RawTransaction>, Status> {
        let filter = request.into_inner();
        let txid = hex::encode(&filter.hash);

        match self.zebrad.get_raw_transaction(&txid).await {
            Ok(tx) => {
                let data = hex::decode(&tx.hex)
                    .map_err(|e| Status::internal(format!("invalid tx hex: {}", e)))?;
                Ok(Response::new(RawTransaction {
                    data,
                    height: tx.height.unwrap_or(0),
                }))
            }
            Err(e) => {
                error!("get_transaction failed: {}", e);
                Err(Status::not_found(e.to_string()))
            }
        }
    }

    pub(crate) async fn handle_send_transaction(
        &self,
        request: Request<RawTransaction>,
    ) -> std::result::Result<Response<SendResponse>, Status> {
        let raw_tx = request.into_inner();
        let tx_hex = hex::encode(&raw_tx.data);

        match self.zebrad.send_raw_transaction(&tx_hex).await {
            Ok(txid) => {
                info!("transaction sent: {}", txid);
                Ok(Response::new(SendResponse {
                    txid,
                    error_code: 0,
                    error_message: String::new(),
                }))
            }
            Err(e) => {
                error!("send_transaction failed: {}", e);
                Ok(Response::new(SendResponse {
                    txid: String::new(),
                    error_code: -1,
                    error_message: e.to_string(),
                }))
            }
        }
    }

    pub(crate) async fn handle_get_block_transactions(
        &self,
        request: Request<BlockId>,
    ) -> std::result::Result<Response<BlockTransactions>, Status> {
        let block_id = request.into_inner();
        let height = block_id.height;

        let block_hash = match self.zebrad.get_block_hash(height).await {
            Ok(hash) => hash,
            Err(e) => {
                error!("failed to get block hash at {}: {}", height, e);
                return Err(Status::not_found(e.to_string()));
            }
        };

        let block = match self.zebrad.get_block(&block_hash, 1).await {
            Ok(b) => b,
            Err(e) => {
                error!("failed to get block {}: {}", block_hash, e);
                return Err(Status::internal(e.to_string()));
            }
        };

        let mut txs = Vec::new();
        for txid in &block.tx {
            match self.zebrad.get_raw_transaction(txid).await {
                Ok(tx) => {
                    let data = hex::decode(&tx.hex).unwrap_or_default();
                    txs.push(RawTransaction { data, height });
                }
                Err(e) => {
                    warn!("failed to get tx {}: {}", txid, e);
                }
            }
        }

        let hash = hex::decode(&block_hash).unwrap_or_default();
        Ok(Response::new(BlockTransactions { height, hash, txs }))
    }

    pub(crate) async fn handle_get_tree_state(
        &self,
        request: Request<BlockId>,
    ) -> std::result::Result<Response<TreeState>, Status> {
        let block_id = request.into_inner();
        let height_str = block_id.height.to_string();

        match self.zebrad.get_tree_state(&height_str).await {
            Ok(state) => {
                let hash = hex::decode(&state.hash)
                    .map_err(|e| Status::internal(format!("invalid hash: {}", e)))?;
                Ok(Response::new(TreeState {
                    height: state.height,
                    hash,
                    time: state.time,
                    sapling_tree: state.sapling.commitments.final_state,
                    orchard_tree: state.orchard.commitments.final_state,
                    ironwood_tree: state
                        .ironwood
                        .map(|t| t.commitments.final_state)
                        .unwrap_or_default(),
                }))
            }
            Err(e) => {
                error!("get_tree_state failed: {}", e);
                Err(Status::internal(e.to_string()))
            }
        }
    }

    pub(crate) async fn handle_get_address_utxos(
        &self,
        request: Request<TransparentAddressFilter>,
    ) -> std::result::Result<Response<UtxoList>, Status> {
        let filter = request.into_inner();

        match self.zebrad.get_address_utxos(&filter.addresses).await {
            Ok(utxos) => {
                let proto_utxos: Vec<Utxo> = utxos
                    .into_iter()
                    .map(|u| Utxo {
                        address: u.address,
                        txid: hex::decode(&u.txid).unwrap_or_default(),
                        output_index: u.output_index,
                        script: hex::decode(&u.script).unwrap_or_default(),
                        value_zat: u.satoshis,
                        height: u.height,
                    })
                    .collect();
                Ok(Response::new(UtxoList { utxos: proto_utxos }))
            }
            Err(e) => {
                error!("get_address_utxos failed: {}", e);
                Err(Status::internal(e.to_string()))
            }
        }
    }

    pub(crate) async fn handle_get_taddress_txids(
        &self,
        request: Request<TransparentAddressFilter>,
    ) -> std::result::Result<Response<TxidList>, Status> {
        let filter = request.into_inner();

        let end_height = match self.zebrad.get_blockchain_info().await {
            Ok(info) => info.blocks,
            Err(e) => {
                error!("failed to get blockchain info: {}", e);
                return Err(Status::internal(e.to_string()));
            }
        };

        let start_height = if filter.start_height > 0 {
            filter.start_height
        } else {
            1
        };

        match self
            .zebrad
            .get_address_txids(&filter.addresses, start_height, end_height)
            .await
        {
            Ok(txids) => {
                let proto_txids: Vec<Vec<u8>> = txids
                    .into_iter()
                    .filter_map(|txid| hex::decode(&txid).ok())
                    .collect();
                Ok(Response::new(TxidList { txids: proto_txids }))
            }
            Err(e) => {
                error!("get_taddress_txids failed: {}", e);
                Err(Status::internal(e.to_string()))
            }
        }
    }

    pub(crate) async fn handle_get_mempool_stream(
        &self,
        _request: Request<Empty>,
    ) -> std::result::Result<
        Response<ReceiverStream<std::result::Result<ProtoCompactBlock, Status>>>,
        Status,
    > {
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        let zebrad = self.zebrad.clone();
        let cache = self.mempool_cache.clone();
        let ttl = self.mempool_cache_ttl;

        tokio::spawn(async move {
            let blocks = match fetch_or_cached_mempool(&zebrad, &cache, ttl).await {
                Ok(b) => b,
                Err(e) => {
                    error!("mempool fetch failed: {}", e);
                    let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                    return;
                }
            };

            for block in blocks {
                let proto = ProtoCompactBlock {
                    height: 0,
                    hash: block.hash,
                    actions: to_proto_actions(block.actions),
                    ironwood_actions: to_proto_actions(block.ironwood_actions),
                };
                if tx.send(Ok(proto)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// fetch mempool, using cache if ttl > 0 and cache is fresh
async fn fetch_or_cached_mempool(
    zebrad: &ZebradClient,
    cache: &Arc<RwLock<Option<MempoolCache>>>,
    ttl: Duration,
) -> Result<Vec<InternalCompactBlock>> {
    // ttl == 0 means caching disabled
    if ttl.is_zero() {
        return InternalCompactBlock::from_mempool(zebrad).await;
    }

    // check cache freshness
    {
        let cached = cache.read().await;
        if let Some(ref c) = *cached {
            if c.fetched_at.elapsed() < ttl {
                return Ok(c.blocks.clone());
            }
        }
    }

    // cache miss or stale — fetch fresh
    let blocks = InternalCompactBlock::from_mempool(zebrad).await?;
    {
        let mut cached = cache.write().await;
        *cached = Some(MempoolCache {
            blocks: blocks.clone(),
            fetched_at: Instant::now(),
        });
    }
    Ok(blocks)
}

/// Convert internal compact actions to proto form (Orchard or Ironwood —
/// both pools share the same action shape).
fn to_proto_actions(actions: Vec<crate::compact::CompactAction>) -> Vec<ProtoCompactAction> {
    actions
        .into_iter()
        .map(|a| ProtoCompactAction {
            cmx: a.cmx,
            ephemeral_key: a.ephemeral_key,
            ciphertext: a.ciphertext,
            nullifier: a.nullifier,
            txid: a.txid,
        })
        .collect()
}

//! block-related gRPC handlers

use super::ZidecarService;
use crate::{
    compact::CompactBlock as InternalCompactBlock,
    error::{Result, ZidecarError},
    zidecar::{
        BlockHeader as ProtoBlockHeader, BlockId, BlockRange, BlockTransactions,
        CompactAction as ProtoCompactAction, CompactBlock as ProtoCompactBlock, Empty,
        RawTransaction, SendResponse, TransparentAddressFilter, TreeState, TxFilter, TxidList,
        Utxo, UtxoList, VerifiedBlock,
    },
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

impl ZidecarService {
    pub(crate) async fn handle_get_compact_blocks(
        &self,
        request: Request<BlockRange>,
    ) -> std::result::Result<Response<ReceiverStream<std::result::Result<ProtoCompactBlock, Status>>>, Status>
    {
        let range = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(128);

        let zebrad = self.zebrad.clone();
        let storage = self.storage.clone();
        let start = range.start_height;
        let end = range.end_height;

        tokio::spawn(async move {
            for height in start..=end {
                match InternalCompactBlock::from_zebrad(&zebrad, height).await {
                    Ok(block) => {
                        let actions_tuples: Vec<([u8; 32], [u8; 32], [u8; 32])> = block
                            .actions
                            .iter()
                            .filter_map(|a| {
                                if a.cmx.len() == 32
                                    && a.nullifier.len() == 32
                                    && a.ephemeral_key.len() == 32
                                {
                                    let mut cmx = [0u8; 32];
                                    let mut nf = [0u8; 32];
                                    let mut epk = [0u8; 32];
                                    cmx.copy_from_slice(&a.cmx);
                                    nf.copy_from_slice(&a.nullifier);
                                    epk.copy_from_slice(&a.ephemeral_key);
                                    Some((cmx, nf, epk))
                                } else {
                                    None
                                }
                            })
                            .collect();

                        let actions_root =
                            zync_core::actions::compute_actions_root(&actions_tuples);

                        if let Err(e) = storage.store_actions_root(height, actions_root) {
                            warn!("failed to store actions_root for height {}: {}", height, e);
                        }

                        let proto_block = ProtoCompactBlock {
                            height: block.height,
                            hash: block.hash,
                            actions: block
                                .actions
                                .into_iter()
                                .map(|a| ProtoCompactAction {
                                    cmx: a.cmx,
                                    ephemeral_key: a.ephemeral_key,
                                    ciphertext: a.ciphertext,
                                    nullifier: a.nullifier,
                                    txid: a.txid,
                                })
                                .collect(),
                            actions_root: actions_root.to_vec(),
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

    pub(crate) async fn handle_get_verified_blocks(
        &self,
        request: Request<BlockRange>,
    ) -> std::result::Result<Response<ReceiverStream<std::result::Result<VerifiedBlock, Status>>>, Status>
    {
        let range = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(128);

        let zebrad = self.zebrad.clone();
        let storage = self.storage.clone();
        let start = range.start_height;
        let end = range.end_height;

        tokio::spawn(async move {
            for height in start..=end {
                match InternalCompactBlock::from_zebrad(&zebrad, height).await {
                    Ok(block) => {
                        let actions_root = compute_actions_root(&block.actions);

                        let (tree_root_after, nullifier_root_after) = storage
                            .get_state_roots(height)
                            .unwrap_or(None)
                            .unwrap_or(([0u8; 32], [0u8; 32]));

                        let verified_block = VerifiedBlock {
                            height: block.height,
                            hash: block.hash,
                            actions: block
                                .actions
                                .into_iter()
                                .map(|a| ProtoCompactAction {
                                    cmx: a.cmx,
                                    ephemeral_key: a.ephemeral_key,
                                    ciphertext: a.ciphertext,
                                    nullifier: a.nullifier,
                                    txid: a.txid,
                                })
                                .collect(),
                            actions_root: actions_root.to_vec(),
                            merkle_path: vec![],
                            tree_root_after: tree_root_after.to_vec(),
                            nullifier_root_after: nullifier_root_after.to_vec(),
                        };

                        if tx.send(Ok(verified_block)).await.is_err() {
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

    pub(crate) async fn fetch_headers(
        &self,
        from_height: u32,
        to_height: u32,
    ) -> Result<Vec<ProtoBlockHeader>> {
        let mut headers = Vec::new();
        for height in from_height..=to_height {
            let hash = self.zebrad.get_block_hash(height).await?;
            let header = self.zebrad.get_block_header(&hash).await?;
            headers.push(ProtoBlockHeader {
                height: header.height,
                hash: hex::decode(&header.hash)
                    .map_err(|e| ZidecarError::Serialization(e.to_string()))?,
                prev_hash: hex::decode(&header.prev_hash)
                    .map_err(|e| ZidecarError::Serialization(e.to_string()))?,
                timestamp: header.timestamp,
                merkle_root: hex::decode(&header.merkle_root)
                    .map_err(|e| ZidecarError::Serialization(e.to_string()))?,
            });
        }
        Ok(headers)
    }
}

fn compute_actions_root(actions: &[crate::compact::CompactAction]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    if actions.is_empty() {
        return [0u8; 32];
    }

    let mut hasher = Sha256::new();
    hasher.update(b"ZIDECAR_ACTIONS_ROOT");
    for action in actions {
        hasher.update(&action.cmx);
        hasher.update(&action.nullifier);
    }
    hasher.finalize().into()
}

//! lightwalletd CompactTxStreamer compatibility layer
//!
//! Implements the standard lightwalletd gRPC interface so that any wallet
//! supporting lightwalletd (Zashi, Nighthawk, etc.) can point directly at
//! zidecar without a separate lightwalletd instance.

use crate::lightwalletd::{
    compact_tx_streamer_server::CompactTxStreamer, Address, AddressList, Balance, BlockId,
    BlockRange, ChainMetadata, ChainSpec, CompactBlock, CompactOrchardAction, CompactSaplingOutput,
    CompactSaplingSpend, CompactTx, Duration as LwdDuration, Empty, GetAddressUtxosArg,
    GetAddressUtxosReply, GetAddressUtxosReplyList, GetMempoolTxRequest, GetSubtreeRootsArg,
    LightdInfo, PingResponse, PoolType, RawTransaction, SendResponse, SubtreeRoot,
    TransparentAddressBlockFilter, TreeState, TxFilter,
};
use crate::{compact::CompactBlock as InternalBlock, storage::Storage, zebrad::ZebradClient};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
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
/// Groups sapling spends, sapling outputs, and orchard actions per txid.
fn to_lwd_block(
    block: &InternalBlock,
    prev_hash: Vec<u8>,
    time: u32,
    sapling_tree_size: u32,
    orchard_tree_size: u32,
) -> CompactBlock {
    use std::collections::HashMap;

    #[derive(Default)]
    struct TxBucket {
        spends: Vec<CompactSaplingSpend>,
        outputs: Vec<CompactSaplingOutput>,
        actions: Vec<CompactOrchardAction>,
    }

    let mut buckets: HashMap<Vec<u8>, TxBucket> = HashMap::new();
    let mut tx_order: Vec<Vec<u8>> = Vec::new();

    for s in &block.sapling_spends {
        buckets
            .entry(s.txid.clone())
            .or_insert_with(|| {
                tx_order.push(s.txid.clone());
                TxBucket::default()
            })
            .spends
            .push(CompactSaplingSpend {
                nf: s.nullifier.clone(),
            });
    }
    for o in &block.sapling_outputs {
        buckets
            .entry(o.txid.clone())
            .or_insert_with(|| {
                tx_order.push(o.txid.clone());
                TxBucket::default()
            })
            .outputs
            .push(CompactSaplingOutput {
                cmu: o.cmu.clone(),
                ephemeral_key: o.ephemeral_key.clone(),
                ciphertext: o.ciphertext.clone(),
            });
    }
    for action in &block.actions {
        buckets
            .entry(action.txid.clone())
            .or_insert_with(|| {
                tx_order.push(action.txid.clone());
                TxBucket::default()
            })
            .actions
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
        .map(|(i, txid)| {
            let bucket = buckets.remove(&txid).unwrap_or_default();
            CompactTx {
                index: i as u64,
                hash: txid,
                fee: 0,
                spends: bucket.spends,
                outputs: bucket.outputs,
                actions: bucket.actions,
            }
        })
        .collect();

    CompactBlock {
        proto_version: 1,
        height: block.height as u64,
        hash: block.hash.clone(),
        prev_hash,
        time,
        header: block.header_bytes.clone(),
        vtx,
        chain_metadata: Some(ChainMetadata {
            sapling_commitment_tree_size: sapling_tree_size,
            orchard_commitment_tree_size: orchard_tree_size,
        }),
    }
}

/// Build a full lightwalletd CompactBlock at a given height; shared by the
/// regular and nullifier-only handlers.
async fn build_compact_block_for(
    zebrad: &ZebradClient,
    height: u32,
) -> Result<CompactBlock, Status> {
    let hash_str = zebrad.get_block_hash(height).await?;
    let block_meta = zebrad.get_block(&hash_str, 1).await?;
    let internal = InternalBlock::from_zebrad(zebrad, height).await?;
    let prev_hash = prev_hash_for(zebrad, height).await;
    let (sapling_size, orchard_size) = tree_sizes_at(zebrad, height).await;
    Ok(to_lwd_block(
        &internal,
        prev_hash,
        block_meta.time as u32,
        sapling_size,
        orchard_size,
    ))
}

/// Strip everything except spend nullifiers from a CompactBlock — wire form
/// expected by GetBlockNullifiers / GetBlockRangeNullifiers callers.
fn strip_to_nullifiers(mut block: CompactBlock) -> CompactBlock {
    for tx in &mut block.vtx {
        tx.outputs.clear();
        for action in &mut tx.actions {
            action.cmx.clear();
            action.ephemeral_key.clear();
            action.ciphertext.clear();
        }
    }
    block
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
    type GetTaddressTxidsStream = ReceiverStream<Result<RawTransaction, Status>>;
    type GetTaddressTransactionsStream = ReceiverStream<Result<RawTransaction, Status>>;
    type GetMempoolStreamStream = ReceiverStream<Result<RawTransaction, Status>>;
    type GetMempoolTxStream = ReceiverStream<Result<CompactTx, Status>>;
    type GetBlockRangeNullifiersStream = ReceiverStream<Result<CompactBlock, Status>>;

    async fn get_latest_block(&self, _: Request<ChainSpec>) -> Result<Response<BlockId>, Status> {
        let info = self.zebrad.get_blockchain_info().await?;
        Ok(Response::new(BlockId {
            height: info.blocks as u64,
            hash: hex::decode(&info.bestblockhash).unwrap_or_default(),
        }))
    }

    async fn get_block(&self, req: Request<BlockId>) -> Result<Response<CompactBlock>, Status> {
        let id = req.into_inner();
        let height = id.height as u32;

        let hash_str = self.zebrad.get_block_hash(height).await?;
        let block_meta = self.zebrad.get_block(&hash_str, 1).await?;

        let block = InternalBlock::from_zebrad(&self.zebrad, height).await?;

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

        let ts = self.zebrad.get_tree_state(&key).await?;

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
            .await?;

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
        let info = self.zebrad.get_blockchain_info().await?;

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

    async fn get_taddress_txids(
        &self,
        req: Request<TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTxidsStream>, Status> {
        let (filter, start, end) = parse_taddress_filter(req.into_inner())?;
        let (tx, rx) = mpsc::channel(32);
        let zebrad = self.zebrad.clone();
        tokio::spawn(async move {
            stream_address_raw_txns(zebrad, vec![filter.address], start, end, tx).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_taddress_balance(
        &self,
        req: Request<AddressList>,
    ) -> Result<Response<Balance>, Status> {
        let addresses = req.into_inner().addresses;
        let bal = self.zebrad.get_address_balance(&addresses).await?;
        Ok(Response::new(Balance {
            value_zat: bal.balance,
        }))
    }

    async fn get_taddress_balance_stream(
        &self,
        req: Request<Streaming<Address>>,
    ) -> Result<Response<Balance>, Status> {
        let mut inbound = req.into_inner();
        let mut addresses: Vec<String> = Vec::new();
        while let Some(item) = inbound.next().await {
            let a = item.map_err(|e| Status::internal(e.to_string()))?;
            addresses.push(a.address);
        }
        let bal = self.zebrad.get_address_balance(&addresses).await?;
        Ok(Response::new(Balance {
            value_zat: bal.balance,
        }))
    }

    async fn get_mempool_stream(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<Self::GetMempoolStreamStream>, Status> {
        let initial = self.zebrad.get_blockchain_info().await?;
        let stay_hash = initial.bestblockhash;

        let (tx, rx) = mpsc::channel(32);
        let zebrad = self.zebrad.clone();

        tokio::spawn(async move {
            let mut seen: HashSet<String> = HashSet::new();
            loop {
                // Tip moved — end the stream so the client refreshes.
                match zebrad.get_blockchain_info().await {
                    Ok(i) if i.bestblockhash != stay_hash => return,
                    Ok(_) => {}
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        return;
                    }
                }

                let txids = match zebrad.get_raw_mempool().await {
                    Ok(t) => t,
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        return;
                    }
                };
                for txid in txids {
                    if !seen.insert(txid.clone()) {
                        continue;
                    }
                    // Tx may have evicted between getrawmempool and the fetch.
                    let raw = match zebrad.get_raw_transaction(&txid).await {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    // Skip anything that got mined since the snapshot.
                    if raw.height.unwrap_or(0) != 0 {
                        continue;
                    }
                    let data = match hex::decode(&raw.hex) {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                    let msg = RawTransaction { data, height: 0 };
                    if tx.send(Ok(msg)).await.is_err() {
                        return;
                    }
                }

                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_latest_tree_state(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<TreeState>, Status> {
        let info = self.zebrad.get_blockchain_info().await?;
        let ts = self.zebrad.get_tree_state(&info.blocks.to_string()).await?;
        Ok(Response::new(TreeState {
            network: self.chain_name().to_string(),
            height: ts.height as u64,
            hash: ts.hash,
            time: ts.time as u32,
            sapling_tree: ts.sapling.commitments.final_state,
            orchard_tree: ts.orchard.commitments.final_state,
        }))
    }

    async fn ping(&self, req: Request<LwdDuration>) -> Result<Response<PingResponse>, Status> {
        let dur = req.into_inner();
        let micros: u64 = dur.interval_us.try_into().unwrap_or(0);
        tokio::time::sleep(Duration::from_micros(micros)).await;
        Ok(Response::new(PingResponse { entry: 1, exit: 1 }))
    }

    async fn get_taddress_transactions(
        &self,
        req: Request<TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTransactionsStream>, Status> {
        let (filter, start, end) = parse_taddress_filter(req.into_inner())?;
        let (tx, rx) = mpsc::channel(32);
        let zebrad = self.zebrad.clone();
        tokio::spawn(async move {
            stream_address_raw_txns(zebrad, vec![filter.address], start, end, tx).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_mempool_tx(
        &self,
        req: Request<GetMempoolTxRequest>,
    ) -> Result<Response<Self::GetMempoolTxStream>, Status> {
        let request = req.into_inner();

        for sfx in &request.exclude_txid_suffixes {
            if sfx.len() > 32 {
                return Err(Status::invalid_argument(
                    "exclude txid suffix larger than 32 bytes",
                ));
            }
        }
        let mut pool_types = request.pool_types;
        if pool_types.iter().any(|&p| p == PoolType::Invalid as i32) {
            return Err(Status::invalid_argument("invalid pool type"));
        }
        // canonical lwd default: shielded-only.
        if pool_types.is_empty() {
            pool_types = vec![PoolType::Sapling as i32, PoolType::Orchard as i32];
        }
        let want_sapling = pool_types.contains(&(PoolType::Sapling as i32));
        let want_orchard = pool_types.contains(&(PoolType::Orchard as i32));

        let exclude = request.exclude_txid_suffixes;
        let (tx, rx) = mpsc::channel(32);
        let zebrad = self.zebrad.clone();

        tokio::spawn(async move {
            let txids = match zebrad.get_raw_mempool().await {
                Ok(t) => t,
                Err(e) => {
                    let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                    return;
                }
            };

            for (index, txid_str) in txids.into_iter().enumerate() {
                let Ok(txid_bytes) = hex::decode(&txid_str) else {
                    continue;
                };
                if exclude.iter().any(|sfx| {
                    txid_bytes.len() >= sfx.len()
                        && txid_bytes[txid_bytes.len() - sfx.len()..] == sfx[..]
                }) {
                    continue;
                }
                let raw = match zebrad.get_raw_transaction(&txid_str).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if raw.height.unwrap_or(0) != 0 {
                    continue;
                }

                let mut actions = Vec::new();
                let mut spends = Vec::new();
                let mut outputs = Vec::new();

                if want_orchard {
                    if let Some(orch) = &raw.orchard {
                        for a in &orch.actions {
                            let (Ok(nf), Ok(cmx), Ok(ek), Ok(ct)) = (
                                hex::decode(&a.nullifier),
                                hex::decode(&a.cmx),
                                hex::decode(&a.ephemeral_key),
                                hex::decode(&a.enc_ciphertext),
                            ) else {
                                continue;
                            };
                            actions.push(CompactOrchardAction {
                                nullifier: nf,
                                cmx,
                                ephemeral_key: ek,
                                ciphertext: ct.into_iter().take(52).collect(),
                            });
                        }
                    }
                }
                if want_sapling {
                    if let Some(ss) = &raw.sapling_spends {
                        for s in ss {
                            if let Ok(nf) = hex::decode(&s.nullifier) {
                                spends.push(CompactSaplingSpend { nf });
                            }
                        }
                    }
                    if let Some(so) = &raw.sapling_outputs {
                        for o in so {
                            let (Ok(cmu), Ok(ek), Ok(ct)) = (
                                hex::decode(&o.cmu),
                                hex::decode(&o.ephemeral_key),
                                hex::decode(&o.enc_ciphertext),
                            ) else {
                                continue;
                            };
                            outputs.push(CompactSaplingOutput {
                                cmu,
                                ephemeral_key: ek,
                                ciphertext: ct.into_iter().take(52).collect(),
                            });
                        }
                    }
                }

                // Skip txs that match no requested pool — keeps the stream
                // shielded-relevant (canonical lwd does the same).
                if actions.is_empty() && spends.is_empty() && outputs.is_empty() {
                    continue;
                }

                let msg = CompactTx {
                    index: index as u64,
                    hash: txid_bytes,
                    fee: 0,
                    spends,
                    outputs,
                    actions,
                };
                if tx.send(Ok(msg)).await.is_err() {
                    return;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_block_nullifiers(
        &self,
        req: Request<BlockId>,
    ) -> Result<Response<CompactBlock>, Status> {
        let id = req.into_inner();
        let block = build_compact_block_for(&self.zebrad, id.height as u32).await?;
        Ok(Response::new(strip_to_nullifiers(block)))
    }

    async fn get_block_range_nullifiers(
        &self,
        req: Request<BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeNullifiersStream>, Status> {
        let range = req.into_inner();
        let start = range.start.map(|b| b.height as u32).unwrap_or(0);
        let end = range.end.map(|b| b.height as u32).unwrap_or(start);
        let (tx, rx) = mpsc::channel(32);
        let zebrad = self.zebrad.clone();
        tokio::spawn(async move {
            for height in start..=end {
                match build_compact_block_for(&zebrad, height).await {
                    Ok(block) => {
                        if tx.send(Ok(strip_to_nullifiers(block))).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

fn parse_taddress_filter(
    filter: TransparentAddressBlockFilter,
) -> Result<(TransparentAddressBlockFilter, u32, u32), Status> {
    let range = filter
        .range
        .clone()
        .ok_or_else(|| Status::invalid_argument("block range is required"))?;
    let start = range.start.map(|b| b.height as u32).unwrap_or(0);
    let end = range.end.map(|b| b.height as u32).unwrap_or(start);
    Ok((filter, start, end))
}

async fn stream_address_raw_txns(
    zebrad: ZebradClient,
    addresses: Vec<String>,
    start: u32,
    end: u32,
    tx: mpsc::Sender<Result<RawTransaction, Status>>,
) {
    let txids = match zebrad.get_address_txids(&addresses, start, end).await {
        Ok(t) => t,
        Err(e) => {
            let _ = tx.send(Err(Status::internal(e.to_string()))).await;
            return;
        }
    };
    for txid in txids {
        let raw = match zebrad.get_raw_transaction(&txid).await {
            Ok(r) => r,
            Err(e) => {
                let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                return;
            }
        };
        let data = match hex::decode(&raw.hex) {
            Ok(b) => b,
            Err(e) => {
                let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                return;
            }
        };
        let msg = RawTransaction {
            data,
            height: raw.height.unwrap_or(0) as u64,
        };
        if tx.send(Ok(msg)).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compact::{
        CompactAction, CompactBlock as InternalBlock, CompactSaplingOutputItem,
        CompactSaplingSpendItem,
    };

    fn make_internal(
        actions: Vec<CompactAction>,
        spends: Vec<CompactSaplingSpendItem>,
        outputs: Vec<CompactSaplingOutputItem>,
    ) -> InternalBlock {
        InternalBlock {
            height: 100,
            hash: vec![0x11; 32],
            header_bytes: vec![0x22; 1487],
            actions,
            sapling_spends: spends,
            sapling_outputs: outputs,
        }
    }

    /// All three pools across two distinct txids — each ends up in its own
    /// CompactTx with the right pool populated and the right index.
    #[test]
    fn test_to_lwd_block_groups_per_txid() {
        let txid_a = vec![0xaa; 32];
        let txid_b = vec![0xbb; 32];

        let block = make_internal(
            vec![CompactAction {
                cmx: vec![0x01; 32],
                ephemeral_key: vec![0x02; 32],
                ciphertext: vec![0x03; 52],
                nullifier: vec![0x04; 32],
                txid: txid_a.clone(),
            }],
            vec![CompactSaplingSpendItem {
                txid: txid_b.clone(),
                nullifier: vec![0x05; 32],
            }],
            vec![
                CompactSaplingOutputItem {
                    txid: txid_a.clone(),
                    cmu: vec![0x06; 32],
                    ephemeral_key: vec![0x07; 32],
                    ciphertext: vec![0x08; 52],
                },
                CompactSaplingOutputItem {
                    txid: txid_b.clone(),
                    cmu: vec![0x09; 32],
                    ephemeral_key: vec![0x0a; 32],
                    ciphertext: vec![0x0b; 52],
                },
            ],
        );

        let prev = vec![0x12; 32];
        let out = to_lwd_block(&block, prev.clone(), 1234, 100, 200);

        assert_eq!(out.height, 100);
        assert_eq!(out.hash, vec![0x11; 32]);
        assert_eq!(out.prev_hash, prev);
        assert_eq!(out.time, 1234);
        assert_eq!(out.header, vec![0x22; 1487]);
        let cm = out.chain_metadata.expect("chain_metadata populated");
        assert_eq!(cm.sapling_commitment_tree_size, 100);
        assert_eq!(cm.orchard_commitment_tree_size, 200);

        // Two distinct txids → two CompactTx entries.
        assert_eq!(out.vtx.len(), 2);

        // Order = first-seen across (spends, outputs, actions) iteration:
        // spend loop touches txid_b first; output loop touches txid_a as new;
        // action loop sees txid_a (already in).
        assert_eq!(out.vtx[0].hash, txid_b);
        assert_eq!(out.vtx[1].hash, txid_a);
        assert_eq!(out.vtx[0].index, 0);
        assert_eq!(out.vtx[1].index, 1);

        // tx_b: 1 spend, 1 output, 0 actions.
        assert_eq!(out.vtx[0].spends.len(), 1);
        assert_eq!(out.vtx[0].spends[0].nf, vec![0x05; 32]);
        assert_eq!(out.vtx[0].outputs.len(), 1);
        assert_eq!(out.vtx[0].outputs[0].cmu, vec![0x09; 32]);
        assert!(out.vtx[0].actions.is_empty());

        // tx_a: 0 spends, 1 output, 1 action.
        assert!(out.vtx[1].spends.is_empty());
        assert_eq!(out.vtx[1].outputs.len(), 1);
        assert_eq!(out.vtx[1].outputs[0].cmu, vec![0x06; 32]);
        assert_eq!(out.vtx[1].actions.len(), 1);
        assert_eq!(out.vtx[1].actions[0].nullifier, vec![0x04; 32]);
    }

    /// Empty internal block → empty vtx + zero metadata, header still passed through.
    #[test]
    fn test_to_lwd_block_empty_block() {
        let block = make_internal(vec![], vec![], vec![]);
        let out = to_lwd_block(&block, vec![0x12; 32], 1234, 0, 0);
        assert!(out.vtx.is_empty());
        assert_eq!(out.header, vec![0x22; 1487]);
    }

    /// Multiple actions in the same tx end up grouped into one CompactTx
    /// with N actions, not N CompactTx entries.
    #[test]
    fn test_to_lwd_block_multi_action_single_tx() {
        let txid = vec![0xaa; 32];
        let block = make_internal(
            vec![
                CompactAction {
                    cmx: vec![0x01; 32],
                    ephemeral_key: vec![0x02; 32],
                    ciphertext: vec![0x03; 52],
                    nullifier: vec![0x04; 32],
                    txid: txid.clone(),
                },
                CompactAction {
                    cmx: vec![0x11; 32],
                    ephemeral_key: vec![0x12; 32],
                    ciphertext: vec![0x13; 52],
                    nullifier: vec![0x14; 32],
                    txid: txid.clone(),
                },
            ],
            vec![],
            vec![],
        );
        let out = to_lwd_block(&block, vec![0u8; 32], 0, 0, 0);
        assert_eq!(out.vtx.len(), 1);
        assert_eq!(out.vtx[0].actions.len(), 2);
    }

    /// strip_to_nullifiers must zero everything except the nullifier on
    /// orchard actions, drop sapling outputs entirely, and leave spend
    /// nullifiers untouched.
    #[test]
    fn test_strip_to_nullifiers_keeps_only_nullifiers() {
        let block = CompactBlock {
            proto_version: 1,
            height: 100,
            hash: vec![0x11; 32],
            prev_hash: vec![0x12; 32],
            time: 1234,
            header: vec![0x22; 1487],
            vtx: vec![CompactTx {
                index: 0,
                hash: vec![0xaa; 32],
                fee: 0,
                spends: vec![CompactSaplingSpend { nf: vec![0x05; 32] }],
                outputs: vec![CompactSaplingOutput {
                    cmu: vec![0x06; 32],
                    ephemeral_key: vec![0x07; 32],
                    ciphertext: vec![0x08; 52],
                }],
                actions: vec![CompactOrchardAction {
                    nullifier: vec![0x04; 32],
                    cmx: vec![0x01; 32],
                    ephemeral_key: vec![0x02; 32],
                    ciphertext: vec![0x03; 52],
                }],
            }],
            chain_metadata: None,
        };

        let stripped = strip_to_nullifiers(block);
        let tx = &stripped.vtx[0];

        // Outputs dropped, spend nullifier preserved.
        assert!(tx.outputs.is_empty());
        assert_eq!(tx.spends.len(), 1);
        assert_eq!(tx.spends[0].nf, vec![0x05; 32]);

        // Orchard action: nullifier kept, every other field zeroed out.
        assert_eq!(tx.actions.len(), 1);
        assert_eq!(tx.actions[0].nullifier, vec![0x04; 32]);
        assert!(tx.actions[0].cmx.is_empty());
        assert!(tx.actions[0].ephemeral_key.is_empty());
        assert!(tx.actions[0].ciphertext.is_empty());

        // Block-level metadata untouched by the strip.
        assert_eq!(stripped.height, 100);
        assert_eq!(stripped.header, vec![0x22; 1487]);
    }

    /// parse_taddress_filter rejects missing range and parses heights correctly.
    #[test]
    fn test_parse_taddress_filter_requires_range() {
        let filter = TransparentAddressBlockFilter {
            address: "t1abc".to_string(),
            range: None,
        };
        assert!(parse_taddress_filter(filter).is_err());

        let filter = TransparentAddressBlockFilter {
            address: "t1abc".to_string(),
            range: Some(BlockRange {
                start: Some(BlockId {
                    height: 100,
                    hash: vec![],
                }),
                end: Some(BlockId {
                    height: 200,
                    hash: vec![],
                }),
            }),
        };
        let (f, start, end) = parse_taddress_filter(filter).unwrap();
        assert_eq!(f.address, "t1abc");
        assert_eq!(start, 100);
        assert_eq!(end, 200);
    }
}

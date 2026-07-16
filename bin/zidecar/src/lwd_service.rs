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
use crate::{compact::CompactBlock as InternalBlock, zebrad::ZebradClient};
use std::collections::HashSet;
use std::time::Duration;

/// Maximum number of blocks a single GetBlockRange / GetBlockRangeNullifiers /
/// GetTaddressTxids / GetTaddressTransactions request can span. Without this
/// ceiling a malicious client requesting `start=0,end=u32::MAX` queues
/// billions of upstream RPCs on a single connection — the gRPC concurrency
/// limit doesn't catch it because the spawned handler task is detached from
/// the connection slot once the initial `Response<Stream>` returns.
const MAX_BLOCK_RANGE_DELTA: u32 = 10_000;

/// Maximum entries in the `GetMempoolStream` per-stream seen-txid set. Mempool
/// turnover at the current chain tip is tiny in practice (low hundreds), so
/// this only matters when the chain stalls or a client holds the stream open
/// across many tip changes. End the stream when hit; the client reconnects.
const MAX_SEEN_TXIDS_PER_STREAM: usize = 50_000;

/// Maximum number of `excludeTxidSuffixes` a single `GetMempoolTx` request may
/// carry. Per-suffix length is already capped at 32 bytes (matching canonical
/// lwd); this caps the count to keep the O(N·M) suffix-match loop bounded.
const MAX_EXCLUDE_SUFFIXES: usize = 256;

/// Uniform refusal message for requests that would need Ironwood (NU6.3)
/// pool data before support lands. Clients get a clear Unimplemented error
/// instead of silently-empty (i.e. wrong) results.
const IRONWOOD_UNSUPPORTED_MSG: &str = "ironwood pool not yet supported";
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, warn};

pub struct LwdService {
    zebrad: ZebradClient,
    testnet: bool,
}

impl LwdService {
    pub fn new(zebrad: ZebradClient, testnet: bool) -> Self {
        Self { zebrad, testnet }
    }

    /// Network identifier used in LightdInfo + TreeState. Must match the
    /// strings the Zcash SDK compares against (`"main"`/`"test"`); the longer
    /// `"mainnet"`/`"testnet"` forms get rejected as an unknown network.
    fn chain_name(&self) -> &'static str {
        if self.testnet {
            "test"
        } else {
            "main"
        }
    }
}

/// Reverse a byte slice. Used to flip between Zebra's display-order (BE) hex
/// representation and lightwalletd's protocol-order (LE) wire bytes. Every
/// txid, block hash, sapling cmu/ephemeral-key, and sapling spend nullifier
/// crosses this boundary; orchard fields are already in protocol order
/// because Zebra doesn't pre-reverse them.
fn rev_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v.reverse();
    v
}

/// Same as `rev_bytes` but takes ownership of the Vec to avoid one allocation.
fn rev_into(mut v: Vec<u8>) -> Vec<u8> {
    v.reverse();
    v
}

/// Run `$fut` to completion, or bail out of the enclosing async block with
/// `return` if the receiver attached to `$tx` (an `mpsc::Sender`) is dropped
/// first. Used to make streaming handlers observe client cancellation
/// between upstream Zebra RPCs instead of completing one more full
/// round-trip per loop iteration before the next `tx.send` detects the drop.
macro_rules! select_or_cancel {
    ($tx:expr, $fut:expr) => {{
        tokio::select! {
            biased;
            _ = $tx.closed() => return,
            res = $fut => res,
        }
    }};
}

/// Convert internal compact block to lightwalletd wire format.
///
/// Three pool-specific input vectors are grouped per-txid into a single
/// CompactTx per tx; the resulting CompactTx.index is the canonical
/// position-in-block of the containing tx (carried through the per-item
/// `block_tx_index`), NOT the position-in-shielded-only-set.
///
/// All txid/hash/cmu/ephemeral-key/sapling-nullifier byte fields are
/// reversed on the way out — Zebra emits these in display order (BE) and
/// the lightwalletd proto requires protocol order (LE). Orchard fields
/// pass through unchanged (Zebra doesn't pre-reverse them).
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
        block_tx_index: u32,
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
                TxBucket {
                    block_tx_index: s.block_tx_index,
                    ..TxBucket::default()
                }
            })
            .spends
            .push(CompactSaplingSpend {
                nf: rev_bytes(&s.nullifier),
            });
    }
    for o in &block.sapling_outputs {
        buckets
            .entry(o.txid.clone())
            .or_insert_with(|| {
                tx_order.push(o.txid.clone());
                TxBucket {
                    block_tx_index: o.block_tx_index,
                    ..TxBucket::default()
                }
            })
            .outputs
            .push(CompactSaplingOutput {
                cmu: rev_bytes(&o.cmu),
                ephemeral_key: rev_bytes(&o.ephemeral_key),
                ciphertext: o.ciphertext.clone(),
            });
    }
    for action in &block.actions {
        buckets
            .entry(action.txid.clone())
            .or_insert_with(|| {
                tx_order.push(action.txid.clone());
                TxBucket {
                    block_tx_index: action.block_tx_index,
                    ..TxBucket::default()
                }
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
        .map(|txid| {
            let bucket = buckets.remove(&txid).unwrap_or_default();
            CompactTx {
                index: bucket.block_tx_index as u64,
                hash: rev_into(txid),
                fee: 0,
                spends: bucket.spends,
                outputs: bucket.outputs,
                actions: bucket.actions,
                // NU6.3 groundwork: no ironwood data is served yet.
                ironwood_actions: vec![],
            }
        })
        .collect();

    CompactBlock {
        proto_version: 1,
        height: block.height as u64,
        hash: rev_bytes(&block.hash),
        prev_hash: rev_into(prev_hash),
        time,
        // Canonical compact_formats.proto:27-30 says this field "should always
        // be unset (empty)". InternalBlock still carries the parsed bytes so
        // future internal uses (chain validation, eventual full-header wire
        // option) have them; we just don't ship them by default.
        header: Vec::new(),
        vtx,
        chain_metadata: Some(ChainMetadata {
            sapling_commitment_tree_size: sapling_tree_size,
            orchard_commitment_tree_size: orchard_tree_size,
            // NU6.3 groundwork: stays 0 until ironwood support lands.
            ironwood_commitment_tree_size: 0,
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
/// Matches canonical lightwalletd's `frontend/service.go` behavior: drop
/// outputs, zero out non-nullifier fields on each Orchard action, and clear
/// `chain_metadata` (the nullifier path explicitly suppresses tree sizes).
fn strip_to_nullifiers(mut block: CompactBlock) -> CompactBlock {
    for tx in &mut block.vtx {
        tx.outputs.clear();
        for action in &mut tx.actions {
            action.cmx.clear();
            action.ephemeral_key.clear();
            action.ciphertext.clear();
        }
        // Same treatment for ironwood actions (always empty until NU6.3
        // support lands, but keep the strip future-proof).
        for action in &mut tx.ironwood_actions {
            action.cmx.clear();
            action.ephemeral_key.clear();
            action.ciphertext.clear();
        }
    }
    // Match Zaino: keep the ChainMetadata message present but zero its tree
    // sizes (canonical lwd's nullifier path also returns zeros). Proto3
    // defaults make `None` and `Some({0, 0})` wire-equivalent for clients
    // that use generated stubs, but mirroring Zaino keeps the message shape
    // identical across implementations.
    block.chain_metadata = Some(ChainMetadata {
        sapling_commitment_tree_size: 0,
        orchard_commitment_tree_size: 0,
        ironwood_commitment_tree_size: 0,
    });
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
            hash: rev_into(hex::decode(&info.bestblockhash).unwrap_or_default()),
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
        let (start, end) = parse_block_range(range.start, range.end)?;

        let (tx, rx) = mpsc::channel(32);
        let zebrad = self.zebrad.clone();

        tokio::spawn(async move {
            for height in start..=end {
                let hash_str = match select_or_cancel!(tx, zebrad.get_block_hash(height)) {
                    Ok(h) => h,
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        return;
                    }
                };
                let block_meta = match select_or_cancel!(tx, zebrad.get_block(&hash_str, 1)) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        return;
                    }
                };
                let block =
                    match select_or_cancel!(tx, InternalBlock::from_zebrad(&zebrad, height)) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("lwd range height {}: {}", height, e);
                            let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                            return;
                        }
                    };
                let prev_hash = select_or_cancel!(tx, prev_hash_for(&zebrad, height));
                let (sapling_size, orchard_size) =
                    select_or_cancel!(tx, tree_sizes_at(&zebrad, height));
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
                    return;
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
        // Client sends txid in protocol order (LE); Zebra's getrawtransaction
        // expects display order (BE).
        let txid_hex = hex::encode(rev_bytes(&filter.hash));

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
            // Client sends block hash in protocol order; Zebra expects display order.
            hex::encode(rev_bytes(&id.hash))
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
            // NU6.3 groundwork: empty until ironwood support lands.
            ironwood_tree: String::new(),
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
                txid: rev_into(hex::decode(&u.txid).unwrap_or_default()),
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
            // Refusal path: better a clear error than garbage data while the
            // ironwood (NU6.3) tree is not tracked yet.
            crate::lightwalletd::ShieldedProtocol::Ironwood => {
                return Err(Status::unimplemented(IRONWOOD_UNSUPPORTED_MSG));
            }
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
                match select_or_cancel!(tx, zebrad.get_blockchain_info()) {
                    Ok(i) if i.bestblockhash != stay_hash => return,
                    Ok(_) => {}
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        return;
                    }
                }

                // Bounded seen-set: under normal mempool churn this won't
                // get hit, but a stalled chain or a long-held stream from
                // a hostile client could grow it unboundedly otherwise.
                if seen.len() >= MAX_SEEN_TXIDS_PER_STREAM {
                    debug!(
                        "mempool stream: seen set hit cap {}, ending stream",
                        MAX_SEEN_TXIDS_PER_STREAM
                    );
                    return;
                }

                let txids = match select_or_cancel!(tx, zebrad.get_raw_mempool()) {
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
                    let raw = match select_or_cancel!(tx, zebrad.get_raw_transaction(&txid)) {
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
            // NU6.3 groundwork: empty until ironwood support lands.
            ironwood_tree: String::new(),
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

        if request.exclude_txid_suffixes.len() > MAX_EXCLUDE_SUFFIXES {
            return Err(Status::invalid_argument(format!(
                "too many exclude txid suffixes ({}; max {})",
                request.exclude_txid_suffixes.len(),
                MAX_EXCLUDE_SUFFIXES
            )));
        }
        for sfx in &request.exclude_txid_suffixes {
            if sfx.is_empty() {
                // An empty suffix matches the tail of every txid, which would
                // silently filter the entire stream — reject explicitly.
                return Err(Status::invalid_argument(
                    "empty exclude txid suffix matches every transaction",
                ));
            }
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
        // Refusal path: an IRONWOOD selection would silently yield nothing
        // (no ironwood data is tracked yet) - reject it clearly instead.
        if pool_types.iter().any(|&p| p == PoolType::Ironwood as i32) {
            return Err(Status::unimplemented(IRONWOOD_UNSUPPORTED_MSG));
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
            let txids = match select_or_cancel!(tx, zebrad.get_raw_mempool()) {
                Ok(t) => t,
                Err(e) => {
                    let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                    return;
                }
            };

            for (index, txid_str) in txids.into_iter().enumerate() {
                // Zebra's txids are display-order hex. Reverse once to the
                // protocol-order bytes used for both exclude-suffix matching
                // and the eventual CompactTx.hash field.
                let Ok(txid_bytes) = hex::decode(&txid_str).map(rev_into) else {
                    continue;
                };
                if exclude.iter().any(|sfx| {
                    txid_bytes.len() >= sfx.len()
                        && txid_bytes[txid_bytes.len() - sfx.len()..] == sfx[..]
                }) {
                    continue;
                }
                let raw = match select_or_cancel!(tx, zebrad.get_raw_transaction(&txid_str)) {
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
                                spends.push(CompactSaplingSpend { nf: rev_into(nf) });
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
                                cmu: rev_into(cmu),
                                ephemeral_key: rev_into(ek),
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
                    // IRONWOOD pool selection is refused above; nothing to
                    // serve here until NU6.3 support lands.
                    ironwood_actions: vec![],
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
        let (start, end) = parse_block_range(range.start, range.end)?;
        let (tx, rx) = mpsc::channel(32);
        let zebrad = self.zebrad.clone();
        tokio::spawn(async move {
            for height in start..=end {
                match select_or_cancel!(tx, build_compact_block_for(&zebrad, height)) {
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
    let (start, end) = parse_block_range(range.start, range.end)?;
    Ok((filter, start, end))
}

/// Validate + extract `(start, end)` heights from a BlockRange. Rejects
/// `start > end` and ranges wider than `MAX_BLOCK_RANGE_DELTA`. Used by every
/// range-accepting handler so the bound is uniform.
fn parse_block_range(
    start_opt: Option<BlockId>,
    end_opt: Option<BlockId>,
) -> Result<(u32, u32), Status> {
    let start = start_opt.map(|b| b.height as u32).unwrap_or(0);
    let end = end_opt.map(|b| b.height as u32).unwrap_or(start);
    if start > end {
        return Err(Status::invalid_argument(format!(
            "block range start ({}) > end ({})",
            start, end
        )));
    }
    let span = end.saturating_sub(start);
    if span > MAX_BLOCK_RANGE_DELTA {
        return Err(Status::resource_exhausted(format!(
            "block range too large: {} blocks (max {})",
            span, MAX_BLOCK_RANGE_DELTA
        )));
    }
    Ok((start, end))
}

async fn stream_address_raw_txns(
    zebrad: ZebradClient,
    addresses: Vec<String>,
    start: u32,
    end: u32,
    tx: mpsc::Sender<Result<RawTransaction, Status>>,
) {
    let txids = match select_or_cancel!(tx, zebrad.get_address_txids(&addresses, start, end)) {
        Ok(t) => t,
        Err(e) => {
            let _ = tx.send(Err(Status::internal(e.to_string()))).await;
            return;
        }
    };
    for txid in txids {
        let raw = match select_or_cancel!(tx, zebrad.get_raw_transaction(&txid)) {
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
    /// CompactTx with the right pool populated and the CompactTx.index
    /// reflecting the original block-tx position from the source items.
    #[test]
    fn test_to_lwd_block_groups_per_txid() {
        let txid_a = vec![0xaa; 32]; // symmetric — reversal is invisible here
        let txid_b = vec![0xbb; 32];

        let block = make_internal(
            vec![CompactAction {
                cmx: vec![0x01; 32],
                ephemeral_key: vec![0x02; 32],
                ciphertext: vec![0x03; 52],
                nullifier: vec![0x04; 32],
                txid: txid_a.clone(),
                block_tx_index: 5, // tx_a is the 6th tx in the source block
            }],
            vec![CompactSaplingSpendItem {
                txid: txid_b.clone(),
                nullifier: vec![0x05; 32],
                block_tx_index: 2, // tx_b is the 3rd tx in the source block
            }],
            vec![
                CompactSaplingOutputItem {
                    txid: txid_a.clone(),
                    cmu: vec![0x06; 32],
                    ephemeral_key: vec![0x07; 32],
                    ciphertext: vec![0x08; 52],
                    block_tx_index: 5,
                },
                CompactSaplingOutputItem {
                    txid: txid_b.clone(),
                    cmu: vec![0x09; 32],
                    ephemeral_key: vec![0x0a; 32],
                    ciphertext: vec![0x0b; 52],
                    block_tx_index: 2,
                },
            ],
        );

        let prev = vec![0x12; 32];
        let out = to_lwd_block(&block, prev.clone(), 1234, 100, 200);

        assert_eq!(out.height, 100);
        assert_eq!(out.hash, vec![0x11; 32]); // symmetric → reversed equals self
        assert_eq!(out.prev_hash, prev);
        assert_eq!(out.time, 1234);
        // CompactBlock.header is intentionally empty per canonical lwd proto.
        assert!(out.header.is_empty());
        let cm = out.chain_metadata.expect("chain_metadata populated");
        assert_eq!(cm.sapling_commitment_tree_size, 100);
        assert_eq!(cm.orchard_commitment_tree_size, 200);

        // Two distinct txids → two CompactTx entries.
        assert_eq!(out.vtx.len(), 2);

        // Iteration order = first-seen across (spends, outputs, actions):
        // spend loop touches tx_b first, output loop touches tx_a as new.
        assert_eq!(out.vtx[0].hash, txid_b);
        assert_eq!(out.vtx[1].hash, txid_a);
        // CompactTx.index is the source block-tx position, NOT vtx slot.
        assert_eq!(out.vtx[0].index, 2);
        assert_eq!(out.vtx[1].index, 5);

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

    /// `to_lwd_block` must reverse the byte order of every txid, block hash,
    /// sapling-spend nullifier, sapling-output cmu, and sapling-output
    /// ephemeral-key on the way out. Orchard fields pass through.
    /// This test uses asymmetric byte patterns where the reversed form is
    /// distinguishable from the original.
    #[test]
    fn test_to_lwd_block_reverses_wire_bytes() {
        // 32-byte pattern 0x01..0x20; reversed is 0x20..0x01
        let asym32: Vec<u8> = (1u8..=32).collect();
        let asym32_rev: Vec<u8> = asym32.iter().rev().copied().collect();

        let block = make_internal(
            vec![CompactAction {
                cmx: asym32.clone(),
                ephemeral_key: asym32.clone(),
                ciphertext: vec![0x03; 52],
                nullifier: asym32.clone(),
                txid: asym32.clone(),
                block_tx_index: 0,
            }],
            vec![CompactSaplingSpendItem {
                txid: asym32.clone(),
                nullifier: asym32.clone(),
                block_tx_index: 0,
            }],
            vec![CompactSaplingOutputItem {
                txid: asym32.clone(),
                cmu: asym32.clone(),
                ephemeral_key: asym32.clone(),
                ciphertext: vec![0x08; 52],
                block_tx_index: 0,
            }],
        );
        // Use an asymmetric InternalBlock.hash + prev_hash so we can verify
        // those reverse too.
        let block_with_asym_hash = InternalBlock {
            hash: asym32.clone(),
            ..block
        };
        let prev_hash_asym = asym32.clone();

        let out = to_lwd_block(&block_with_asym_hash, prev_hash_asym, 0, 0, 0);

        // CompactBlock.hash and prev_hash reversed.
        assert_eq!(out.hash, asym32_rev);
        assert_eq!(out.prev_hash, asym32_rev);

        // The single emitted CompactTx — its hash should be the reversed txid.
        assert_eq!(out.vtx.len(), 1);
        assert_eq!(out.vtx[0].hash, asym32_rev);

        // Sapling spend nullifier reversed.
        assert_eq!(out.vtx[0].spends[0].nf, asym32_rev);
        // Sapling output cmu + ephemeral_key reversed; ciphertext passes through.
        assert_eq!(out.vtx[0].outputs[0].cmu, asym32_rev);
        assert_eq!(out.vtx[0].outputs[0].ephemeral_key, asym32_rev);
        assert_eq!(out.vtx[0].outputs[0].ciphertext, vec![0x08; 52]);

        // Orchard action fields pass through unchanged.
        let act = &out.vtx[0].actions[0];
        assert_eq!(act.cmx, asym32);
        assert_eq!(act.ephemeral_key, asym32);
        assert_eq!(act.nullifier, asym32);
    }

    /// Empty internal block → empty vtx + zero metadata, header still passed through.
    #[test]
    fn test_to_lwd_block_empty_block() {
        let block = make_internal(vec![], vec![], vec![]);
        let out = to_lwd_block(&block, vec![0x12; 32], 1234, 0, 0);
        assert!(out.vtx.is_empty());
        // CompactBlock.header is intentionally empty per canonical lwd proto.
        assert!(out.header.is_empty());
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
                    block_tx_index: 0,
                },
                CompactAction {
                    cmx: vec![0x11; 32],
                    ephemeral_key: vec![0x12; 32],
                    ciphertext: vec![0x13; 52],
                    nullifier: vec![0x14; 32],
                    txid: txid.clone(),
                    block_tx_index: 0,
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
                ironwood_actions: vec![CompactOrchardAction {
                    nullifier: vec![0x24; 32],
                    cmx: vec![0x21; 32],
                    ephemeral_key: vec![0x22; 32],
                    ciphertext: vec![0x23; 52],
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

        // Ironwood action gets the same treatment (future-proofing: no
        // ironwood data is ever populated yet).
        assert_eq!(tx.ironwood_actions.len(), 1);
        assert_eq!(tx.ironwood_actions[0].nullifier, vec![0x24; 32]);
        assert!(tx.ironwood_actions[0].cmx.is_empty());
        assert!(tx.ironwood_actions[0].ephemeral_key.is_empty());
        assert!(tx.ironwood_actions[0].ciphertext.is_empty());

        // Block-level metadata untouched by the strip.
        assert_eq!(stripped.height, 100);
        assert_eq!(stripped.header, vec![0x22; 1487]);
    }

    /// parse_block_range: accepts valid ranges, rejects start>end, rejects
    /// spans wider than MAX_BLOCK_RANGE_DELTA. The cap is the only thing
    /// stopping a `start=0,end=u32::MAX` request from queueing billions of
    /// upstream Zebra RPCs.
    #[test]
    fn test_parse_block_range_bounds() {
        // Happy path.
        let (s, e) = parse_block_range(
            Some(BlockId {
                height: 100,
                hash: vec![],
            }),
            Some(BlockId {
                height: 200,
                hash: vec![],
            }),
        )
        .unwrap();
        assert_eq!((s, e), (100, 200));

        // At the limit — should pass.
        let (s, e) = parse_block_range(
            Some(BlockId {
                height: 0,
                hash: vec![],
            }),
            Some(BlockId {
                height: MAX_BLOCK_RANGE_DELTA as u64,
                hash: vec![],
            }),
        )
        .unwrap();
        assert_eq!((s, e), (0, MAX_BLOCK_RANGE_DELTA));

        // One over the limit — rejected.
        let err = parse_block_range(
            Some(BlockId {
                height: 0,
                hash: vec![],
            }),
            Some(BlockId {
                height: (MAX_BLOCK_RANGE_DELTA + 1) as u64,
                hash: vec![],
            }),
        )
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        // start > end — rejected.
        let err = parse_block_range(
            Some(BlockId {
                height: 200,
                hash: vec![],
            }),
            Some(BlockId {
                height: 100,
                hash: vec![],
            }),
        )
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
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

    /// Ironwood (NU6.3) refusal path: GetSubtreeRoots for the ironwood pool
    /// must fail with a clear Unimplemented error before any upstream call
    /// is made, not return garbage or an empty stream.
    #[tokio::test]
    async fn get_subtree_roots_refuses_ironwood() {
        use crate::lightwalletd::{GetSubtreeRootsArg, ShieldedProtocol};
        let svc = LwdService::new(ZebradClient::new("http://127.0.0.1:1"), false);
        let err = svc
            .get_subtree_roots(Request::new(GetSubtreeRootsArg {
                start_index: 0,
                shielded_protocol: ShieldedProtocol::Ironwood as i32,
                max_entries: 0,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        assert_eq!(err.message(), IRONWOOD_UNSUPPORTED_MSG);
    }

    /// Ironwood (NU6.3) refusal path: a GetMempoolTx selecting the IRONWOOD
    /// pool must fail with a clear Unimplemented error before any upstream
    /// call is made (an accepted request would silently stream nothing).
    #[tokio::test]
    async fn get_mempool_tx_refuses_ironwood_pool_type() {
        let svc = LwdService::new(ZebradClient::new("http://127.0.0.1:1"), false);
        let err = svc
            .get_mempool_tx(Request::new(GetMempoolTxRequest {
                exclude_txid_suffixes: vec![],
                pool_types: vec![PoolType::Sapling as i32, PoolType::Ironwood as i32],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        assert_eq!(err.message(), IRONWOOD_UNSUPPORTED_MSG);
    }

    /// Current orchard/sapling paths are untouched by the ironwood
    /// groundwork: a default (shielded) GetMempoolTx request passes
    /// validation and only fails later at the unreachable zebrad.
    #[tokio::test]
    async fn get_mempool_tx_default_pools_still_accepted() {
        let svc = LwdService::new(ZebradClient::new("http://127.0.0.1:1"), false);
        let resp = svc
            .get_mempool_tx(Request::new(GetMempoolTxRequest {
                exclude_txid_suffixes: vec![],
                pool_types: vec![],
            }))
            .await;
        assert!(resp.is_ok(), "default pool selection must not be refused");
    }

    /// Build an empty-body grpc-web POST to GetLightdInfo, run it through the
    /// tonic-web-wrapped CompactTxStreamer service (optionally applying the
    /// middleware shim first, mirroring the MapRequestLayer order in main.rs)
    /// and return `(grpc-status, grpc-message + body text)`.
    ///
    /// The LwdService points at a never-listening endpoint (port 1), so a
    /// request that actually reaches the handler fails with connection
    /// refused -> ZebradTransport -> Status::unavailable (14). A request
    /// rejected by the codec never runs the handler and comes back 13 with
    /// "Missing request message" instead - that distinction is the whole
    /// point of these tests.
    async fn empty_body_get_lightd_info_status(apply_shim: bool) -> (String, String) {
        use crate::lightwalletd::compact_tx_streamer_server::CompactTxStreamerServer;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let svc = tonic_web::enable(CompactTxStreamerServer::new(LwdService::new(
            ZebradClient::new("http://127.0.0.1:1"),
            false,
        )));

        let mut req = http::Request::builder()
            .method("POST")
            .uri("/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo")
            .header("content-type", "application/grpc-web")
            .header("content-length", "0")
            .body(tonic::body::empty_body())
            .unwrap();
        if apply_shim {
            req = crate::middleware::empty_grpc_web_body_shim(req);
        }

        let resp = svc.oneshot(req).await.expect("service call");

        // grpc-status arrives either as a response header (trailers-only
        // response) or inside a trailer frame at the end of the body.
        let header_status = resp
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let header_message = resp
            .headers()
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_default();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let body_text = String::from_utf8_lossy(&body).into_owned();
        let status = header_status.unwrap_or_else(|| {
            body_text
                .split("grpc-status:")
                .nth(1)
                .map(|rest| {
                    rest.trim_start()
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect()
                })
                .unwrap_or_default()
        });
        // grpc-message values are percent-encoded on the wire; decode the
        // one escape that matters for matching the message text.
        let message = format!("{header_message} {body_text}").replace("%20", " ");
        (status, message)
    }

    /// With the shim applied (as main.rs wires it, before tonic-web decodes
    /// frames), an empty-body grpc-web GetLightdInfo probe must reach the
    /// handler: the rewritten body decodes to a default `Empty` message and
    /// the handler's zebrad call fails with Unavailable (14). Wallets probing
    /// GetLightdInfo this way is why the shim exists (Go lightwalletd is
    /// lenient about the missing frame; zafu's backend auto-detection broke
    /// when zidecar was not).
    #[tokio::test]
    async fn empty_body_grpc_web_get_lightd_info_reaches_handler_via_shim() {
        let (status, message) = empty_body_get_lightd_info_status(true).await;
        assert!(
            !message.contains("Missing request message"),
            "empty grpc-web body was rejected by the codec before the handler ran"
        );
        assert_eq!(
            status, "14",
            "expected Unavailable from the handler's zebrad call, got grpc-status {status} \
             (message: {message:?})"
        );
    }

    /// Canary: bare tonic-web (no shim) still rejects zero-frame unary
    /// requests with grpc-status 13 "Missing request message" - true through
    /// tonic 0.12.3 (and still present in 0.13/0.14 `src/server/grpc.rs`).
    ///
    /// When a future tonic bump makes this test FAIL, empty bodies are
    /// accepted natively: delete `middleware::empty_grpc_web_body_shim`, its
    /// MapRequestLayer wiring in main.rs, and this canary, keeping only the
    /// via-shim test above (rewritten without the shim).
    #[tokio::test]
    async fn empty_body_grpc_web_without_shim_rejected_by_tonic() {
        let (status, message) = empty_body_get_lightd_info_status(false).await;
        assert_eq!(
            status, "13",
            "tonic now accepts empty-body unary requests natively \
             (message: {message:?}) - the grpc-web body shim can be removed"
        );
        assert!(
            message.contains("Missing request message"),
            "unexpected rejection message: {message:?}"
        );
    }
}

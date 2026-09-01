//! gRPC service implementation

mod blocks;
mod flyclient;
mod sync;

use crate::{
    storage::Storage,
    zebrad::ZebradClient,
    zidecar::{
        zidecar_server::Zidecar, BlockId, BlockRange, BlockTransactions,
        CompactBlock as ProtoCompactBlock, Empty, FlyClientProofRequest, FlyClientProofResponse,
        LicenseRequest, LicenseResponse, ProRing, RawTransaction, SendResponse, SignAnchorRequest,
        SignAnchorResponse, SyncStatus, TransparentAddressFilter, TreeState, TxFilter, TxidList,
        UtxoList,
    },
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::compact::CompactBlock as InternalCompactBlock;
use crate::ring_vrf::RingVrfManager;

/// cached mempool scan result
pub(crate) struct MempoolCache {
    pub(crate) blocks: Vec<InternalCompactBlock>,
    pub(crate) fetched_at: Instant,
}

pub struct ZidecarService {
    pub(crate) zebrad: ZebradClient,
    pub(crate) storage: Arc<Storage>,
    pub(crate) mempool_cache: Arc<RwLock<Option<MempoolCache>>>,
    pub(crate) mempool_cache_ttl: Duration,
    /// Optional Zakura indexer: when live, its warm mempool txid set is
    /// authoritative and bypasses `get_raw_mempool` + the TTL cache.
    pub(crate) indexer: Option<crate::zakura_indexer::IndexerWatcher>,
    pub(crate) ring_vrf: Arc<RingVrfManager>,
    /// FlyClient history index; `None` unless started with --flyclient.
    pub(crate) history: Option<Arc<crate::history::HistoryIndex>>,
}

impl ZidecarService {
    pub fn new(
        zebrad: ZebradClient,
        storage: Arc<Storage>,
        mempool_cache_ttl: Duration,
        history: Option<Arc<crate::history::HistoryIndex>>,
        indexer: Option<crate::zakura_indexer::IndexerWatcher>,
    ) -> Self {
        let license_url =
            std::env::var("ZCLI_LICENSE_URL").unwrap_or_else(|_| "http://127.0.0.1:3334".into());
        Self {
            zebrad,
            storage,
            mempool_cache: Arc::new(RwLock::new(None)),
            mempool_cache_ttl,
            indexer,
            ring_vrf: Arc::new(RingVrfManager::new(license_url)),
            history,
        }
    }
}

impl ZidecarService {
    /// check if a request has a valid ring VRF proof (pro tier).
    /// returns true for pro, false for free. never fails - free tier is default.
    pub(crate) async fn is_pro_request<T>(&self, request: &Request<T>) -> bool {
        let meta = request.metadata();
        let proof = match meta.get("x-zafu-ring-proof") {
            Some(v) => v.to_str().unwrap_or(""),
            None => return false,
        };
        let context = match meta.get("x-zafu-ring-context") {
            Some(v) => v.to_str().unwrap_or(""),
            None => return false,
        };
        if proof.is_empty() || context.is_empty() {
            return false;
        }
        self.ring_vrf.verify_proof(proof, context).await
    }
}

#[tonic::async_trait]
impl Zidecar for ZidecarService {
    // === proofs ===


    async fn get_fly_client_proof(
        &self,
        request: Request<FlyClientProofRequest>,
    ) -> std::result::Result<Response<FlyClientProofResponse>, Status> {
        self.handle_get_flyclient_proof(request).await
    }


    // === blocks ===

    type GetCompactBlocksStream = ReceiverStream<std::result::Result<ProtoCompactBlock, Status>>;

    async fn get_compact_blocks(
        &self,
        request: Request<BlockRange>,
    ) -> std::result::Result<Response<Self::GetCompactBlocksStream>, Status> {
        self.handle_get_compact_blocks(request).await
    }


    async fn get_tip(
        &self,
        request: Request<Empty>,
    ) -> std::result::Result<Response<BlockId>, Status> {
        self.handle_get_tip(request).await
    }

    type SubscribeBlocksStream = ReceiverStream<std::result::Result<BlockId, Status>>;

    async fn subscribe_blocks(
        &self,
        request: Request<Empty>,
    ) -> std::result::Result<Response<Self::SubscribeBlocksStream>, Status> {
        self.handle_subscribe_blocks(request).await
    }

    async fn get_transaction(
        &self,
        request: Request<TxFilter>,
    ) -> std::result::Result<Response<RawTransaction>, Status> {
        self.handle_get_transaction(request).await
    }

    async fn send_transaction(
        &self,
        request: Request<RawTransaction>,
    ) -> std::result::Result<Response<SendResponse>, Status> {
        self.handle_send_transaction(request).await
    }

    async fn get_block_transactions(
        &self,
        request: Request<BlockId>,
    ) -> std::result::Result<Response<BlockTransactions>, Status> {
        self.handle_get_block_transactions(request).await
    }

    async fn get_tree_state(
        &self,
        request: Request<BlockId>,
    ) -> std::result::Result<Response<TreeState>, Status> {
        self.handle_get_tree_state(request).await
    }

    async fn get_address_utxos(
        &self,
        request: Request<TransparentAddressFilter>,
    ) -> std::result::Result<Response<UtxoList>, Status> {
        self.handle_get_address_utxos(request).await
    }

    async fn get_taddress_txids(
        &self,
        request: Request<TransparentAddressFilter>,
    ) -> std::result::Result<Response<TxidList>, Status> {
        self.handle_get_taddress_txids(request).await
    }

    // === mempool ===

    type GetMempoolStreamStream = ReceiverStream<std::result::Result<ProtoCompactBlock, Status>>;

    async fn get_mempool_stream(
        &self,
        request: Request<Empty>,
    ) -> std::result::Result<Response<Self::GetMempoolStreamStream>, Status> {
        self.handle_get_mempool_stream(request).await
    }

    // === sync ===

    async fn get_sync_status(
        &self,
        request: Request<Empty>,
    ) -> std::result::Result<Response<SyncStatus>, Status> {
        self.handle_get_sync_status(request).await
    }




    async fn get_license(
        &self,
        request: Request<LicenseRequest>,
    ) -> std::result::Result<Response<LicenseResponse>, Status> {
        let req = request.into_inner();

        // proxy to license-server HTTP endpoint
        let license_url =
            std::env::var("ZCLI_LICENSE_URL").unwrap_or_else(|_| "http://127.0.0.1:3334".into());

        let url = format!("{}/license/{}", license_url, req.zid_pubkey);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| Status::internal(format!("http client: {e}")))?;

        match client.get(&url).send().await {
            Ok(resp) => {
                #[derive(serde::Deserialize)]
                struct LicResp {
                    zid: String,
                    plan: String,
                    expires: u64,
                    #[serde(default)]
                    signature: String,
                    #[serde(default)]
                    valid: bool,
                    #[serde(default)]
                    pending_zat: u64,
                    #[serde(default)]
                    pending_confs: u32,
                    #[serde(default)]
                    required_confs: u32,
                }

                let body: LicResp = resp
                    .json()
                    .await
                    .map_err(|e| Status::internal(format!("parse license response: {e}")))?;

                let sig_bytes = hex::decode(&body.signature).unwrap_or_default();

                Ok(Response::new(LicenseResponse {
                    zid: body.zid,
                    plan: body.plan,
                    expires: body.expires,
                    signature: sig_bytes,
                    valid: body.valid,
                    pending_zat: body.pending_zat,
                    pending_confs: body.pending_confs,
                    required_confs: body.required_confs,
                }))
            }
            Err(e) => {
                // license-server unavailable — return free plan (graceful degradation)
                tracing::warn!("license-server unreachable: {}", e);
                Ok(Response::new(LicenseResponse {
                    zid: req.zid_pubkey,
                    plan: "free".into(),
                    expires: 0,
                    signature: vec![],
                    valid: false,
                    pending_zat: 0,
                    pending_confs: 0,
                    required_confs: 0,
                }))
            }
        }
    }

    async fn get_pro_ring(
        &self,
        _request: Request<Empty>,
    ) -> std::result::Result<Response<ProRing>, Status> {
        match self.ring_vrf.get_ring().await {
            Some(ring) => Ok(Response::new(ProRing {
                ring_keys: ring.ring_keys.clone(),
                commitment: ring.commitment.clone(),
                epoch: ring.epoch.clone(),
                context: ring.context.clone(),
                ring_size: ring.ring_keys.len() as u32,
            })),
            None => Ok(Response::new(ProRing {
                ring_keys: vec![],
                commitment: vec![],
                epoch: String::new(),
                context: String::new(),
                ring_size: 0,
            })),
        }
    }

    async fn sign_anchor(
        &self,
        request: Request<SignAnchorRequest>,
    ) -> std::result::Result<Response<SignAnchorResponse>, Status> {
        let req = request.into_inner();

        // read signing key from environment
        let key_hex = match std::env::var("ZCLI_SIGNING_KEY") {
            Ok(k) if !k.is_empty() => k,
            _ => {
                return Ok(Response::new(SignAnchorResponse {
                    signature: vec![],
                    verifier_key: vec![],
                    available: false,
                }));
            }
        };

        let key_hex = key_hex.strip_prefix("0x").unwrap_or(&key_hex);
        let seed: [u8; 32] = hex::decode(key_hex)
            .map_err(|e| Status::internal(format!("bad signing key: {e}")))?
            .try_into()
            .map_err(|_| Status::internal("signing key must be 32 bytes"))?;

        let signing_key = ed25519_consensus::SigningKey::from(seed);
        let vk = signing_key.verification_key();

        // compute attestation digest
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"zcash-anchor-v1");
        hasher.update(vk.as_ref());
        hasher.update(&req.anchor);
        hasher.update(&req.height.to_le_bytes());
        hasher.update(&[u8::from(req.mainnet)]);
        let digest: [u8; 32] = hasher.finalize().into();

        let signature = signing_key.sign(&digest);

        Ok(Response::new(SignAnchorResponse {
            signature: signature.to_bytes().to_vec(),
            verifier_key: vk.as_ref().to_vec(),
            available: true,
        }))
    }
}

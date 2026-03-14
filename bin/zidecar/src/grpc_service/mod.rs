//! gRPC service implementation

mod blocks;
mod nomt;
mod proofs;
mod sync;

use crate::{
    epoch::EpochManager,
    storage::Storage,
    zebrad::ZebradClient,
    zidecar::{
        zidecar_server::Zidecar,
        BlockId,
        BlockRange,
        BlockTransactions,
        CommitmentProof,
        CommitmentQuery,
        CompactBlock as ProtoCompactBlock,
        Empty,
        EpochBoundary as ProtoEpochBoundary,
        EpochBoundaryList,
        EpochRangeRequest,
        EpochRequest,
        FrostCheckpoint as ProtoFrostCheckpoint,
        GetCommitmentProofsRequest,
        GetCommitmentProofsResponse,
        GetNullifierProofsRequest,
        GetNullifierProofsResponse,
        HeaderProof,
        NullifierProof,
        NullifierQuery,
        ProofRequest,
        RawTransaction,
        SendResponse,
        SyncStatus,
        TransparentAddressFilter,
        TreeState,
        TrustlessStateProof,
        TxFilter,
        TxidList,
        UtxoList,
        VerifiedBlock,
    },
};
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

pub struct ZidecarService {
    pub(crate) zebrad: ZebradClient,
    pub(crate) storage: Arc<Storage>,
    pub(crate) epoch_manager: Arc<EpochManager>,
    pub(crate) start_height: u32,
}

impl ZidecarService {
    pub fn new(
        zebrad: ZebradClient,
        storage: Arc<Storage>,
        epoch_manager: Arc<EpochManager>,
        start_height: u32,
    ) -> Self {
        Self {
            zebrad,
            storage,
            epoch_manager,
            start_height,
        }
    }
}

#[tonic::async_trait]
impl Zidecar for ZidecarService {
    // === proofs ===

    async fn get_header_proof(
        &self,
        request: Request<ProofRequest>,
    ) -> std::result::Result<Response<HeaderProof>, Status> {
        self.handle_get_header_proof(request).await
    }

    async fn get_trustless_state_proof(
        &self,
        request: Request<ProofRequest>,
    ) -> std::result::Result<Response<TrustlessStateProof>, Status> {
        self.handle_get_trustless_state_proof(request).await
    }

    // === blocks ===

    type GetCompactBlocksStream = ReceiverStream<std::result::Result<ProtoCompactBlock, Status>>;

    async fn get_compact_blocks(
        &self,
        request: Request<BlockRange>,
    ) -> std::result::Result<Response<Self::GetCompactBlocksStream>, Status> {
        self.handle_get_compact_blocks(request).await
    }

    type GetVerifiedBlocksStream = ReceiverStream<std::result::Result<VerifiedBlock, Status>>;

    async fn get_verified_blocks(
        &self,
        request: Request<BlockRange>,
    ) -> std::result::Result<Response<Self::GetVerifiedBlocksStream>, Status> {
        self.handle_get_verified_blocks(request).await
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

    // === nomt ===

    async fn get_commitment_proof(
        &self,
        request: Request<CommitmentQuery>,
    ) -> std::result::Result<Response<CommitmentProof>, Status> {
        self.handle_get_commitment_proof(request).await
    }

    async fn get_nullifier_proof(
        &self,
        request: Request<NullifierQuery>,
    ) -> std::result::Result<Response<NullifierProof>, Status> {
        self.handle_get_nullifier_proof(request).await
    }

    async fn get_commitment_proofs(
        &self,
        request: Request<GetCommitmentProofsRequest>,
    ) -> std::result::Result<Response<GetCommitmentProofsResponse>, Status> {
        self.handle_get_commitment_proofs(request).await
    }

    async fn get_nullifier_proofs(
        &self,
        request: Request<GetNullifierProofsRequest>,
    ) -> std::result::Result<Response<GetNullifierProofsResponse>, Status> {
        self.handle_get_nullifier_proofs(request).await
    }

    // === sync ===

    async fn get_sync_status(
        &self,
        request: Request<Empty>,
    ) -> std::result::Result<Response<SyncStatus>, Status> {
        self.handle_get_sync_status(request).await
    }

    async fn get_checkpoint(
        &self,
        request: Request<EpochRequest>,
    ) -> std::result::Result<Response<ProtoFrostCheckpoint>, Status> {
        self.handle_get_checkpoint(request).await
    }

    async fn get_epoch_boundary(
        &self,
        request: Request<EpochRequest>,
    ) -> std::result::Result<Response<ProtoEpochBoundary>, Status> {
        self.handle_get_epoch_boundary(request).await
    }

    async fn get_epoch_boundaries(
        &self,
        request: Request<EpochRangeRequest>,
    ) -> std::result::Result<Response<EpochBoundaryList>, Status> {
        self.handle_get_epoch_boundaries(request).await
    }
}

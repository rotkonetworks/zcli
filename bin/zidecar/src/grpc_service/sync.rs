//! sync status and epoch boundary handlers

use super::ZidecarService;
use crate::zidecar::{
    sync_status::EpochProofStatus, Empty, EpochBoundary as ProtoEpochBoundary, EpochBoundaryList,
    EpochRangeRequest, EpochRequest, FrostCheckpoint, SyncStatus,
};
use tonic::{Request, Response, Status};
use tracing::{error, warn};

impl ZidecarService {
    pub(crate) async fn handle_get_sync_status(
        &self,
        _request: Request<Empty>,
    ) -> std::result::Result<Response<SyncStatus>, Status> {
        let blockchain_info = match self.zebrad.get_blockchain_info().await {
            Ok(info) => info,
            Err(e) => {
                error!("failed to get blockchain info: {}", e);
                return Err(Status::internal(e.to_string()));
            }
        };

        let current_height = blockchain_info.blocks;
        let current_epoch = current_height / zync_core::EPOCH_SIZE;
        let blocks_in_epoch = current_height % zync_core::EPOCH_SIZE;

        let complete_epochs = if blocks_in_epoch == 0 && current_height > 0 {
            current_epoch
        } else {
            current_epoch.saturating_sub(1)
        };

        let (epoch_proof_status, last_epoch_proof_height) =
            match self.epoch_manager.is_epoch_proof_ready().await {
                Ok(true) => {
                    let last_height = self
                        .epoch_manager
                        .last_complete_epoch_height()
                        .await
                        .unwrap_or(0);
                    (EpochProofStatus::Ready as i32, last_height)
                }
                Ok(false) => {
                    if complete_epochs == 0 {
                        (EpochProofStatus::WaitingForEpoch as i32, 0)
                    } else {
                        (EpochProofStatus::Generating as i32, 0)
                    }
                }
                Err(e) => {
                    warn!("failed to check epoch proof status: {}", e);
                    (EpochProofStatus::WaitingForEpoch as i32, 0)
                }
            };

        let blocks_until_ready = if complete_epochs == 0 {
            zync_core::EPOCH_SIZE - blocks_in_epoch
        } else {
            0
        };

        Ok(Response::new(SyncStatus {
            current_height,
            current_epoch,
            blocks_in_epoch,
            complete_epochs,
            epoch_proof_status,
            blocks_until_ready,
            last_epoch_proof_height,
        }))
    }

    pub(crate) async fn handle_get_checkpoint(
        &self,
        _request: Request<EpochRequest>,
    ) -> std::result::Result<Response<FrostCheckpoint>, Status> {
        Err(Status::unimplemented(
            "FROST checkpoints removed, use get_header_proof",
        ))
    }

    pub(crate) async fn handle_get_epoch_boundary(
        &self,
        request: Request<EpochRequest>,
    ) -> std::result::Result<Response<ProtoEpochBoundary>, Status> {
        let req = request.into_inner();

        let epoch = if req.epoch_index == 0 {
            let info = self
                .zebrad
                .get_blockchain_info()
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            let current_epoch = info.blocks / zync_core::EPOCH_SIZE;
            if info.blocks % zync_core::EPOCH_SIZE == 0 {
                current_epoch
            } else {
                current_epoch.saturating_sub(1)
            }
        } else {
            req.epoch_index as u32
        };

        let boundary = self
            .storage
            .get_epoch_boundary(epoch)
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("epoch {} boundary not found", epoch)))?;

        Ok(Response::new(ProtoEpochBoundary {
            epoch: boundary.epoch,
            first_height: boundary.first_height,
            first_hash: boundary.first_hash.to_vec(),
            first_prev_hash: boundary.first_prev_hash.to_vec(),
            last_height: boundary.last_height,
            last_hash: boundary.last_hash.to_vec(),
        }))
    }

    pub(crate) async fn handle_get_epoch_boundaries(
        &self,
        request: Request<EpochRangeRequest>,
    ) -> std::result::Result<Response<EpochBoundaryList>, Status> {
        let req = request.into_inner();

        let to_epoch = if req.to_epoch == 0 {
            let info = self
                .zebrad
                .get_blockchain_info()
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            let current_epoch = info.blocks / zync_core::EPOCH_SIZE;
            if info.blocks % zync_core::EPOCH_SIZE == 0 {
                current_epoch
            } else {
                current_epoch.saturating_sub(1)
            }
        } else {
            req.to_epoch
        };

        let mut boundaries = Vec::new();
        for epoch in req.from_epoch..=to_epoch {
            if let Ok(Some(boundary)) = self.storage.get_epoch_boundary(epoch) {
                boundaries.push(ProtoEpochBoundary {
                    epoch: boundary.epoch,
                    first_height: boundary.first_height,
                    first_hash: boundary.first_hash.to_vec(),
                    first_prev_hash: boundary.first_prev_hash.to_vec(),
                    last_height: boundary.last_height,
                    last_hash: boundary.last_hash.to_vec(),
                });
            }
        }

        Ok(Response::new(EpochBoundaryList { boundaries }))
    }
}

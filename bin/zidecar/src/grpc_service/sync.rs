//! sync status handler

use super::ZidecarService;
use crate::zidecar::{Empty, SyncStatus};
use tonic::{Request, Response, Status};
use tracing::error;

impl ZidecarService {
    pub(crate) async fn handle_get_sync_status(
        &self,
        _request: Request<Empty>,
    ) -> std::result::Result<Response<SyncStatus>, Status> {
        let current_height = match self.zebrad.get_blockchain_info().await {
            Ok(info) => info.blocks,
            Err(e) => {
                error!("failed to get blockchain info: {}", e);
                return Err(Status::internal(e.to_string()));
            }
        };
        Ok(Response::new(SyncStatus { current_height }))
    }
}

//! GetFlyClientProof: FlyClient proofs over the ZIP-221 history tree.

use super::ZidecarService;
use crate::zidecar::{FlyBurial, FlyClientProofRequest, FlyClientProofResponse, FlyEpoch, FlyLeaf};
use tonic::{Request, Response, Status};
use tracing::warn;
use zync_core::flyclient::sampling::FlyParams;

impl ZidecarService {
    pub(crate) async fn handle_get_flyclient_proof(
        &self,
        request: Request<FlyClientProofRequest>,
    ) -> std::result::Result<Response<FlyClientProofResponse>, Status> {
        let history = self.history.as_ref().ok_or_else(|| {
            Status::unimplemented("FlyClient proofs are not enabled on this server")
        })?;
        let req = request.into_inner();
        let defaults = FlyParams::default();
        let params = FlyParams {
            lambda: if req.lambda == 0 {
                defaults.lambda
            } else {
                req.lambda
            },
            tail: if req.tail == 0 {
                defaults.tail
            } else {
                req.tail
            },
        };
        let (proof, burial) = history
            .proof(&self.zebrad, &self.storage, params, req.burial)
            .await
            .map_err(|e| {
                warn!("flyclient proof: {e}");
                Status::unavailable(e.to_string())
            })?;
        let epochs = proof
            .epochs
            .into_iter()
            .map(|e| FlyEpoch {
                activation: e.activation,
                branch_id: e.branch_id,
                n_leaves: e.n_leaves,
                commit_header: e.commit_header,
                auth_data_root: e.auth_data_root.map(|a| a.to_vec()).unwrap_or_default(),
                peaks: e.peaks,
                leaves: e
                    .leaves
                    .into_iter()
                    .map(|l| FlyLeaf {
                        index: l.index,
                        header: l.header,
                        leaf: l.leaf,
                        path: l.path,
                    })
                    .collect(),
            })
            .collect();
        Ok(Response::new(FlyClientProofResponse {
            epochs,
            anchor_height: history.anchor().height,
            burial: burial.map(|b| FlyBurial {
                index: b.index,
                auth_data_root: b.auth_data_root.map(|a| a.to_vec()).unwrap_or_default(),
                peaks: b.peaks,
            }),
        }))
    }
}

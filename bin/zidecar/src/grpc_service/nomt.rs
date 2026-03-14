//! NOMT commitment and nullifier proof handlers

use super::ZidecarService;
use crate::zidecar::{
    CommitmentProof, CommitmentQuery, GetCommitmentProofsRequest, GetCommitmentProofsResponse,
    GetNullifierProofsRequest, GetNullifierProofsResponse, NullifierProof, NullifierQuery,
};
use tonic::{Request, Response, Status};

impl ZidecarService {
    pub(crate) async fn handle_get_commitment_proof(
        &self,
        request: Request<CommitmentQuery>,
    ) -> std::result::Result<Response<CommitmentProof>, Status> {
        let query = request.into_inner();

        if query.cmx.len() != 32 {
            return Err(Status::invalid_argument("cmx must be 32 bytes"));
        }

        let mut cmx = [0u8; 32];
        cmx.copy_from_slice(&query.cmx);

        let proof = self
            .storage
            .generate_commitment_proof(&cmx)
            .map_err(|e| Status::internal(e.to_string()))?;

        let height = query.at_height.max(
            self.storage
                .get_latest_state_height()
                .map_err(|e| Status::internal(e.to_string()))?
                .unwrap_or(0),
        );

        let position = self
            .storage
            .get_commitment_position(&cmx)
            .map_err(|e| Status::internal(e.to_string()))?
            .unwrap_or(0);

        Ok(Response::new(CommitmentProof {
            cmx: cmx.to_vec(),
            position,
            tree_root: proof.root.to_vec(),
            height,
            proof_path: proof.path.iter().map(|p| p.to_vec()).collect(),
            proof_indices: proof.indices,
            exists: proof.exists,
            path_proof_raw: proof.path_proof_raw,
            value_hash: proof.value_hash.to_vec(),
        }))
    }

    pub(crate) async fn handle_get_nullifier_proof(
        &self,
        request: Request<NullifierQuery>,
    ) -> std::result::Result<Response<NullifierProof>, Status> {
        let query = request.into_inner();

        if query.nullifier.len() != 32 {
            return Err(Status::invalid_argument("nullifier must be 32 bytes"));
        }

        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&query.nullifier);

        let proof = self
            .storage
            .generate_nullifier_proof(&nullifier)
            .map_err(|e| Status::internal(e.to_string()))?;

        let height = query.at_height.max(
            self.storage
                .get_latest_state_height()
                .map_err(|e| Status::internal(e.to_string()))?
                .unwrap_or(0),
        );

        Ok(Response::new(NullifierProof {
            nullifier: nullifier.to_vec(),
            nullifier_root: proof.root.to_vec(),
            height,
            proof_path: proof.path.iter().map(|p| p.to_vec()).collect(),
            proof_indices: proof.indices,
            is_spent: proof.exists,
            path_proof_raw: proof.path_proof_raw,
            value_hash: proof.value_hash.to_vec(),
        }))
    }

    pub(crate) async fn handle_get_commitment_proofs(
        &self,
        request: Request<GetCommitmentProofsRequest>,
    ) -> std::result::Result<Response<GetCommitmentProofsResponse>, Status> {
        let req = request.into_inner();
        let mut proofs = Vec::with_capacity(req.cmxs.len());
        let mut tree_root = Vec::new();

        for cmx_bytes in &req.cmxs {
            let query = CommitmentQuery {
                cmx: cmx_bytes.clone(),
                at_height: req.height,
            };
            let resp = self
                .handle_get_commitment_proof(Request::new(query))
                .await?
                .into_inner();

            if tree_root.is_empty() {
                tree_root = resp.tree_root.clone();
            }
            proofs.push(resp);
        }

        Ok(Response::new(GetCommitmentProofsResponse {
            proofs,
            tree_root,
        }))
    }

    pub(crate) async fn handle_get_nullifier_proofs(
        &self,
        request: Request<GetNullifierProofsRequest>,
    ) -> std::result::Result<Response<GetNullifierProofsResponse>, Status> {
        let req = request.into_inner();
        let mut proofs = Vec::with_capacity(req.nullifiers.len());
        let mut nullifier_root = Vec::new();

        for nf_bytes in &req.nullifiers {
            let query = NullifierQuery {
                nullifier: nf_bytes.clone(),
                at_height: req.height,
            };
            let resp = self
                .handle_get_nullifier_proof(Request::new(query))
                .await?
                .into_inner();

            if nullifier_root.is_empty() {
                nullifier_root = resp.nullifier_root.clone();
            }
            proofs.push(resp);
        }

        Ok(Response::new(GetNullifierProofsResponse {
            proofs,
            nullifier_root,
        }))
    }
}

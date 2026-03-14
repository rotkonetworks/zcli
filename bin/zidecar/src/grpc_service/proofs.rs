//! proof-related gRPC handlers

use super::ZidecarService;
use crate::{
    prover::HeaderChainProof,
    zidecar::{
        HeaderProof, ProofPublicOutputs as ProtoPublicOutputs, ProofRequest, TrustlessStateProof,
    },
};
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

impl ZidecarService {
    pub(crate) async fn handle_get_header_proof(
        &self,
        _request: Request<ProofRequest>,
    ) -> std::result::Result<Response<HeaderProof>, Status> {
        let (epoch_proof, tip_proof) = match self.epoch_manager.get_proofs().await {
            Ok(p) => p,
            Err(_) => {
                warn!("header proof requested but epoch proof not ready");
                return Err(Status::unavailable(
                    "epoch proof generating, retry after sync completes",
                ));
            }
        };

        // deserialize public outputs from epoch proof
        let (epoch_outputs, _, _) = HeaderChainProof::deserialize_full(&epoch_proof)
            .map_err(|e| Status::internal(format!("failed to deserialize epoch proof: {}", e)))?;

        // deserialize public outputs from tip proof (if present)
        let tip_outputs = if !tip_proof.is_empty() {
            let (outputs, _, _) = HeaderChainProof::deserialize_full(&tip_proof)
                .map_err(|e| {
                    Status::internal(format!("failed to deserialize tip proof: {}", e))
                })?;
            Some(outputs)
        } else {
            None
        };

        // verify continuity: tip proof's start_prev_hash == epoch proof's tip_hash
        let continuity_verified = if let Some(ref tip) = tip_outputs {
            let is_continuous = tip.start_prev_hash == epoch_outputs.tip_hash;
            if is_continuous {
                info!(
                    "continuity verified: epoch tip {} -> tip start prev {}",
                    hex::encode(&epoch_outputs.tip_hash[..8]),
                    hex::encode(&tip.start_prev_hash[..8])
                );
            } else {
                error!(
                    "continuity FAILED: epoch tip {} != tip start prev {}",
                    hex::encode(&epoch_outputs.tip_hash[..8]),
                    hex::encode(&tip.start_prev_hash[..8])
                );
            }
            is_continuous
        } else {
            true
        };

        // get current tip
        let tip_info = self
            .zebrad
            .get_blockchain_info()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let tip_hash =
            hex::decode(&tip_info.bestblockhash).map_err(|e| Status::internal(e.to_string()))?;

        // proof contains verified data, no header fetching needed
        let headers = Vec::new();

        // combine full proofs: [epoch_full_size: u32][epoch_full][tip_full]
        let mut combined_proof = Vec::with_capacity(4 + epoch_proof.len() + tip_proof.len());
        combined_proof.extend_from_slice(&(epoch_proof.len() as u32).to_le_bytes());
        combined_proof.extend_from_slice(&epoch_proof);
        combined_proof.extend_from_slice(&tip_proof);

        info!(
            "serving proof: {} KB epoch + {} KB tip = {} KB total (continuity={})",
            epoch_proof.len() / 1024,
            tip_proof.len() / 1024,
            combined_proof.len() / 1024,
            continuity_verified
        );

        let epoch_proto = public_outputs_to_proto(&epoch_outputs);
        let tip_proto = tip_outputs.as_ref().map(public_outputs_to_proto);
        let nullifier_root = self.storage.get_nullifier_root().to_vec();

        Ok(Response::new(HeaderProof {
            ligerito_proof: combined_proof,
            from_height: self.start_height,
            to_height: tip_info.blocks,
            tip_hash,
            headers,
            epoch_proof_outputs: Some(epoch_proto),
            tip_proof_outputs: tip_proto,
            continuity_verified,
            nullifier_root,
        }))
    }

    pub(crate) async fn handle_get_trustless_state_proof(
        &self,
        _request: Request<ProofRequest>,
    ) -> std::result::Result<Response<TrustlessStateProof>, Status> {
        let (epoch_proof, _tip_proof) = match self.epoch_manager.get_proofs().await {
            Ok(p) => p,
            Err(_) => {
                warn!("trustless state proof requested but epoch proof not ready");
                return Err(Status::unavailable(
                    "epoch proof generating, retry after sync completes",
                ));
            }
        };

        let tip_info = self
            .zebrad
            .get_blockchain_info()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let current_hash =
            hex::decode(&tip_info.bestblockhash).map_err(|e| Status::internal(e.to_string()))?;

        let (tree_root, nullifier_root) = self
            .storage
            .get_state_roots(tip_info.blocks)
            .map_err(|e| Status::internal(e.to_string()))?
            .unwrap_or(([0u8; 32], [0u8; 32]));

        let num_actions = self
            .storage
            .get_action_count()
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(TrustlessStateProof {
            checkpoint: None,
            state_transition_proof: epoch_proof,
            current_height: tip_info.blocks,
            current_hash,
            tree_root: tree_root.to_vec(),
            nullifier_root: nullifier_root.to_vec(),
            num_actions,
            proof_log_size: 20,
        }))
    }
}

fn public_outputs_to_proto(outputs: &crate::prover::ProofPublicOutputs) -> ProtoPublicOutputs {
    ProtoPublicOutputs {
        start_height: outputs.start_height,
        end_height: outputs.end_height,
        start_hash: outputs.start_hash.to_vec(),
        start_prev_hash: outputs.start_prev_hash.to_vec(),
        tip_hash: outputs.tip_hash.to_vec(),
        tip_prev_hash: outputs.tip_prev_hash.to_vec(),
        cumulative_difficulty: outputs.cumulative_difficulty,
        final_commitment: outputs.final_commitment.to_vec(),
        final_state_commitment: outputs.final_state_commitment.to_vec(),
        num_headers: outputs.num_headers,
    }
}

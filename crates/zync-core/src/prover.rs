//! Ligerito proof generation for header chain traces.
//!
//! Uses SHA256 Fiat-Shamir transcript for browser WASM verification compatibility.
//! The transcript choice is load-bearing: verifier MUST use the same transcript.
//!
//! ## Proof format
//!
//! ```text
//! [public_outputs_len: u32 LE]
//! [public_outputs: bincode-serialized ProofPublicOutputs]
//! [log_size: u8]
//! [ligerito_proof: bincode-serialized FinalizedLigeritoProof]
//! ```
//!
//! Public outputs are bound to the Fiat-Shamir transcript before proving,
//! so swapping outputs after proof generation invalidates the proof.
//! However, the Ligerito proximity test does NOT constrain the public
//! outputs to match the polynomial — an honest prover is assumed.
//!
//! ## Public outputs
//!
//! Extracted from fixed positions in the committed trace polynomial by
//! the (honest) prover. Transcript-bound, not evaluation-proven.
//!
//! - `start_hash`, `tip_hash`: first and last block hashes
//! - `start_prev_hash`, `tip_prev_hash`: chain continuity linkage
//! - `cumulative_difficulty`: total chain work
//! - `final_commitment`: running header hash chain
//! - `final_state_commitment`: running state root chain
//! - `tip_tree_root`, `tip_nullifier_root`: NOMT roots at tip
//! - `final_actions_commitment`: running actions commitment chain

use ligerito::transcript::{FiatShamir, Transcript};
use ligerito::{data_structures::FinalizedLigeritoProof, prove_with_transcript, ProverConfig};
use ligerito_binary_fields::{BinaryElem128, BinaryElem32, BinaryFieldElement};
use serde::{Deserialize, Serialize};

use crate::error::ZyncError;
use crate::trace::{HeaderChainTrace, FIELDS_PER_HEADER, TIP_SENTINEL_SIZE};

/// Public outputs claimed by the prover.
///
/// These values are extracted from the committed trace at fixed offsets
/// and bound to the Fiat-Shamir transcript before proving, so they cannot
/// be swapped after proof generation. However, the Ligerito proof itself
/// does NOT constrain these values — a malicious prover can claim arbitrary
/// outputs for any valid polynomial commitment.
///
/// # Security model
///
/// Under the honest-prover assumption (zidecar), the values are correct
/// because the prover honestly extracts them from the trace. The cross-
/// verification layer (BFT majority against independent lightwalletd nodes)
/// detects a malicious prover claiming forged outputs.
///
/// For sound proof composition, evaluation opening proofs binding these
/// values to specific polynomial positions are required (not yet implemented).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofPublicOutputs {
    pub start_height: u32,
    pub end_height: u32,
    /// First block hash (known checkpoint).
    pub start_hash: [u8; 32],
    /// prev_hash of first block. Links to previous proof's tip_hash.
    pub start_prev_hash: [u8; 32],
    /// Last block hash. Verify against external checkpoint.
    pub tip_hash: [u8; 32],
    pub tip_prev_hash: [u8; 32],
    pub cumulative_difficulty: u64,
    /// Running header hash chain result.
    pub final_commitment: [u8; 32],
    /// Running state root chain result.
    pub final_state_commitment: [u8; 32],
    pub num_headers: u32,
    /// Orchard commitment tree root at tip.
    pub tip_tree_root: [u8; 32],
    /// Nullifier root (NOMT) at tip.
    pub tip_nullifier_root: [u8; 32],
    /// Running actions commitment chain result.
    pub final_actions_commitment: [u8; 32],
}

/// Header chain proof with public outputs and serialized ligerito proof.
pub struct HeaderChainProof {
    pub proof_bytes: Vec<u8>,
    pub public_outputs: ProofPublicOutputs,
    pub trace_log_size: u32,
}

impl HeaderChainProof {
    /// Generate a proof from a trace with explicit config.
    ///
    /// Uses SHA256 transcript for browser WASM verification.
    /// Binds public outputs to Fiat-Shamir transcript before proving.
    ///
    /// Note: the transcript binding prevents post-hoc output tampering
    /// but does NOT prove the outputs match the polynomial. See
    /// [`ProofPublicOutputs`] for the full security model.
    pub fn prove(
        config: &ProverConfig<BinaryElem32, BinaryElem128>,
        trace: &HeaderChainTrace,
    ) -> Result<Self, ZyncError> {
        let public_outputs = Self::extract_public_outputs(trace)?;

        let mut transcript = FiatShamir::new_sha256(0);

        // Bind public outputs to Fiat-Shamir transcript BEFORE proving.
        let public_bytes = bincode::serialize(&public_outputs)
            .map_err(|e| ZyncError::Serialization(format!("bincode public outputs: {}", e)))?;
        transcript.absorb_bytes(b"public_outputs", &public_bytes);

        let proof = prove_with_transcript(config, &trace.trace, transcript)
            .map_err(|e| ZyncError::Ligerito(format!("{:?}", e)))?;

        let trace_log_size = (trace.trace.len() as f64).log2().ceil() as u32;
        let proof_bytes = Self::serialize_proof_with_config(&proof, trace_log_size as u8)?;

        Ok(Self {
            proof_bytes,
            public_outputs,
            trace_log_size,
        })
    }

    /// Generate proof with auto-selected config based on trace size.
    /// Pads trace to required power-of-2 size if needed.
    pub fn prove_auto(trace: &mut HeaderChainTrace) -> Result<Self, ZyncError> {
        let (config, required_size) = crate::prover_config_for_size(trace.trace.len());

        if trace.trace.len() < required_size {
            trace.trace.resize(required_size, BinaryElem32::zero());
        }

        Self::prove(&config, trace)
    }

    /// Extract public outputs from the committed trace.
    ///
    /// Reads values from fixed positions in the trace polynomial.
    /// These values are honest extractions — not proven by the Ligerito
    /// proximity test. See [`ProofPublicOutputs`] security model.
    fn extract_public_outputs(trace: &HeaderChainTrace) -> Result<ProofPublicOutputs, ZyncError> {
        if trace.num_headers == 0 {
            return Err(ZyncError::InvalidData("empty trace".into()));
        }

        let extract_hash = |base_offset: usize, field_start: usize| -> [u8; 32] {
            let mut hash = [0u8; 32];
            for j in 0..8 {
                let field_val = trace.trace[base_offset + field_start + j].poly().value();
                hash[j * 4..(j + 1) * 4].copy_from_slice(&field_val.to_le_bytes());
            }
            hash
        };

        let first_offset = 0;
        let start_hash = extract_hash(first_offset, 1);
        let start_prev_hash = extract_hash(first_offset, 9);

        let last_offset = (trace.num_headers - 1) * FIELDS_PER_HEADER;
        let tip_hash = extract_hash(last_offset, 1);
        let tip_prev_hash = extract_hash(last_offset, 9);

        let sentinel_offset = trace.num_headers * FIELDS_PER_HEADER;
        let tip_tree_root = extract_hash(sentinel_offset, 0);
        let tip_nullifier_root = extract_hash(sentinel_offset, 8);
        let final_actions_commitment = extract_hash(sentinel_offset, 16);

        Ok(ProofPublicOutputs {
            start_height: trace.start_height,
            end_height: trace.end_height,
            start_hash,
            start_prev_hash,
            tip_hash,
            tip_prev_hash,
            cumulative_difficulty: trace.cumulative_difficulty,
            final_commitment: trace.final_commitment,
            final_state_commitment: trace.final_state_commitment,
            num_headers: trace.num_headers as u32,
            tip_tree_root,
            tip_nullifier_root,
            final_actions_commitment,
        })
    }

    /// Serialize the full proof (public outputs + ligerito proof).
    pub fn serialize_full(&self) -> Result<Vec<u8>, ZyncError> {
        let public_bytes = bincode::serialize(&self.public_outputs)
            .map_err(|e| ZyncError::Serialization(format!("bincode: {}", e)))?;

        let mut result = Vec::with_capacity(4 + public_bytes.len() + self.proof_bytes.len());
        result.extend_from_slice(&(public_bytes.len() as u32).to_le_bytes());
        result.extend(public_bytes);
        result.extend(&self.proof_bytes);
        Ok(result)
    }

    /// Deserialize full proof. Returns (public_outputs, proof_bytes, log_size).
    pub fn deserialize_full(
        bytes: &[u8],
    ) -> Result<(ProofPublicOutputs, Vec<u8>, u8), ZyncError> {
        if bytes.len() < 5 {
            return Err(ZyncError::Serialization("proof too short".into()));
        }

        let public_len =
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + public_len + 1 {
            return Err(ZyncError::Serialization("proof truncated".into()));
        }

        let public_outputs: ProofPublicOutputs =
            bincode::deserialize(&bytes[4..4 + public_len])
                .map_err(|e| ZyncError::Serialization(format!("bincode: {}", e)))?;

        let proof_bytes = bytes[4 + public_len..].to_vec();
        let log_size = if !proof_bytes.is_empty() {
            proof_bytes[0]
        } else {
            0
        };

        Ok((public_outputs, proof_bytes, log_size))
    }

    /// Serialize ligerito proof with config size prefix.
    fn serialize_proof_with_config(
        proof: &FinalizedLigeritoProof<BinaryElem32, BinaryElem128>,
        log_size: u8,
    ) -> Result<Vec<u8>, ZyncError> {
        let proof_bytes = bincode::serialize(proof)
            .map_err(|e| ZyncError::Serialization(format!("bincode: {}", e)))?;

        let mut result = Vec::with_capacity(1 + proof_bytes.len());
        result.push(log_size);
        result.extend(proof_bytes);
        Ok(result)
    }

    /// Deserialize ligerito proof with config prefix.
    pub fn deserialize_proof_with_config(
        bytes: &[u8],
    ) -> Result<(FinalizedLigeritoProof<BinaryElem32, BinaryElem128>, u8), ZyncError> {
        if bytes.is_empty() {
            return Err(ZyncError::Serialization("empty proof bytes".into()));
        }
        let log_size = bytes[0];
        let proof = bincode::deserialize(&bytes[1..])
            .map_err(|e| ZyncError::Serialization(format!("bincode: {}", e)))?;
        Ok((proof, log_size))
    }
}

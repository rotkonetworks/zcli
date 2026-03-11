//! ligerito proof verification with continuity checking
//!
//! wire format (combined proof):
//!   [epoch_full_size: u32][epoch_full][tip_full]
//! where each full proof is:
//!   [public_outputs_len: u32][public_outputs (bincode)][log_size: u8][ligerito_proof (bincode)]

use crate::{verifier_config_for_log_size, FIELDS_PER_HEADER, TIP_SENTINEL_SIZE};
use anyhow::Result;
use ligerito::{
    transcript::{FiatShamir, Transcript},
    verify_with_transcript, FinalizedLigeritoProof,
};
use ligerito_binary_fields::{BinaryElem128, BinaryElem32};
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use std::thread;

/// public outputs embedded in each proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofPublicOutputs {
    pub start_height: u32,
    pub end_height: u32,
    pub start_hash: [u8; 32],
    pub start_prev_hash: [u8; 32],
    pub tip_hash: [u8; 32],
    pub tip_prev_hash: [u8; 32],
    pub cumulative_difficulty: u64,
    pub final_commitment: [u8; 32],
    pub final_state_commitment: [u8; 32],
    pub num_headers: u32,
    /// Tree root (orchard commitment tree) at proof's end height
    pub tip_tree_root: [u8; 32],
    /// Nullifier root (nomt) at proof's end height
    pub tip_nullifier_root: [u8; 32],
    /// Final actions commitment (running chain, zeros until populated)
    pub final_actions_commitment: [u8; 32],
}

/// result of proof verification
#[derive(Clone, Debug)]
pub struct VerifyResult {
    pub epoch_proof_valid: bool,
    pub tip_valid: bool,
    pub continuous: bool,
    pub epoch_outputs: ProofPublicOutputs,
    pub tip_outputs: Option<ProofPublicOutputs>,
}

/// split a full proof into (public_outputs, raw_proof_bytes)
fn split_full_proof(full: &[u8]) -> Result<(ProofPublicOutputs, Vec<u8>)> {
    if full.len() < 4 {
        anyhow::bail!("proof too short");
    }
    let public_len = u32::from_le_bytes([full[0], full[1], full[2], full[3]]) as usize;
    if full.len() < 4 + public_len + 1 {
        anyhow::bail!("proof truncated");
    }
    let outputs: ProofPublicOutputs = bincode::deserialize(&full[4..4 + public_len])
        .map_err(|e| anyhow::anyhow!("deserialize public outputs: {}", e))?;
    let raw = full[4 + public_len..].to_vec();
    Ok((outputs, raw))
}

/// deserialize raw proof: [log_size: u8][proof_bytes...]
fn deserialize_proof(
    bytes: &[u8],
) -> Result<(FinalizedLigeritoProof<BinaryElem32, BinaryElem128>, u8)> {
    if bytes.is_empty() {
        anyhow::bail!("empty proof bytes");
    }
    let log_size = bytes[0];
    let proof = bincode::deserialize(&bytes[1..])
        .map_err(|e| anyhow::anyhow!("failed to deserialize proof: {}", e))?;
    Ok((proof, log_size))
}

/// verify a single raw proof (sha256 transcript to match prover)
/// public outputs are bound to the Fiat-Shamir transcript before verification,
/// so swapping outputs after proving invalidates the proof.
fn verify_single(proof_bytes: &[u8], public_outputs: &ProofPublicOutputs) -> Result<bool> {
    let (proof, log_size) = deserialize_proof(proof_bytes)?;

    // validate log_size against num_headers to prevent config downgrade attacks
    let expected_trace_elements =
        (public_outputs.num_headers as usize) * FIELDS_PER_HEADER + TIP_SENTINEL_SIZE;
    let expected_padded = expected_trace_elements.next_power_of_two();
    let expected_log_size = expected_padded.trailing_zeros() as u8;
    if log_size != expected_log_size {
        anyhow::bail!(
            "log_size mismatch: proof claims {} but num_headers={} requires {}",
            log_size,
            public_outputs.num_headers,
            expected_log_size,
        );
    }

    let config = verifier_config_for_log_size(log_size as u32);
    let mut transcript = FiatShamir::new_sha256(0);

    // bind public outputs to transcript (must match prover)
    let public_bytes = bincode::serialize(public_outputs)
        .map_err(|e| anyhow::anyhow!("serialize public outputs: {}", e))?;
    transcript.absorb_bytes(b"public_outputs", &public_bytes);

    verify_with_transcript(&config, &proof, transcript)
        .map_err(|e| anyhow::anyhow!("verification error: {}", e))
}

/// verify combined epoch proof + tip proof with continuity checking
///
/// format: [epoch_full_size: u32][epoch_full][tip_full]
/// each full proof: [public_outputs_len: u32][public_outputs][log_size: u8][proof]
///
/// checks:
/// 1. both proofs verify cryptographically
/// 2. tip_proof.start_prev_hash == epoch proof.tip_hash (chain continuity)
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_proofs(combined_proof: &[u8]) -> Result<(bool, bool)> {
    let result = verify_proofs_full(combined_proof)?;
    Ok((
        result.epoch_proof_valid,
        result.tip_valid && result.continuous,
    ))
}

/// full verification with detailed result
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_proofs_full(combined_proof: &[u8]) -> Result<VerifyResult> {
    if combined_proof.len() < 4 {
        anyhow::bail!("proof too small");
    }

    let epoch_full_size = u32::from_le_bytes([
        combined_proof[0],
        combined_proof[1],
        combined_proof[2],
        combined_proof[3],
    ]) as usize;

    if combined_proof.len() < 4 + epoch_full_size {
        anyhow::bail!("invalid proof format");
    }

    let epoch_full = &combined_proof[4..4 + epoch_full_size];
    let tip_full = &combined_proof[4 + epoch_full_size..];

    // parse public outputs from both proofs
    let (epoch_outputs, epoch_raw) = split_full_proof(epoch_full)?;
    let (tip_outputs, tip_raw) = if !tip_full.is_empty() {
        let (o, r) = split_full_proof(tip_full)?;
        (Some(o), r)
    } else {
        (None, vec![])
    };

    // verify both proofs in parallel (public outputs bound to transcript)
    let epoch_raw_clone = epoch_raw;
    let epoch_outputs_clone = epoch_outputs.clone();
    let tip_raw_clone = tip_raw;
    let tip_outputs_clone = tip_outputs.clone();
    let epoch_handle =
        thread::spawn(move || verify_single(&epoch_raw_clone, &epoch_outputs_clone));
    let tip_handle = if !tip_raw_clone.is_empty() {
        let tip_out = tip_outputs_clone.unwrap();
        Some(thread::spawn(move || {
            verify_single(&tip_raw_clone, &tip_out)
        }))
    } else {
        None
    };

    let epoch_proof_valid = epoch_handle
        .join()
        .map_err(|_| anyhow::anyhow!("epoch proof thread panicked"))??;
    let tip_valid = match tip_handle {
        Some(h) => h
            .join()
            .map_err(|_| anyhow::anyhow!("tip thread panicked"))??,
        None => true,
    };

    // check continuity: tip starts where epoch proof ends
    let continuous = match &tip_outputs {
        Some(tip) => tip.start_prev_hash == epoch_outputs.tip_hash,
        None => true, // no tip = epoch proof covers everything
    };

    Ok(VerifyResult {
        epoch_proof_valid,
        tip_valid,
        continuous,
        epoch_outputs,
        tip_outputs,
    })
}

/// wasm variant
#[cfg(target_arch = "wasm32")]
pub fn verify_proofs(combined_proof: &[u8]) -> Result<(bool, bool)> {
    let result = verify_proofs_full(combined_proof)?;
    Ok((
        result.epoch_proof_valid,
        result.tip_valid && result.continuous,
    ))
}

#[cfg(target_arch = "wasm32")]
pub fn verify_proofs_full(combined_proof: &[u8]) -> Result<VerifyResult> {
    if combined_proof.len() < 4 {
        anyhow::bail!("proof too small");
    }

    let epoch_full_size = u32::from_le_bytes([
        combined_proof[0],
        combined_proof[1],
        combined_proof[2],
        combined_proof[3],
    ]) as usize;

    if combined_proof.len() < 4 + epoch_full_size {
        anyhow::bail!("invalid proof format");
    }

    let epoch_full = &combined_proof[4..4 + epoch_full_size];
    let tip_full = &combined_proof[4 + epoch_full_size..];

    let (epoch_outputs, epoch_raw) = split_full_proof(epoch_full)?;
    let (tip_outputs, tip_raw) = if !tip_full.is_empty() {
        let (o, r) = split_full_proof(tip_full)?;
        (Some(o), r)
    } else {
        (None, vec![])
    };

    let epoch_proof_valid = verify_single(&epoch_raw, &epoch_outputs)?;
    let tip_valid = if !tip_raw.is_empty() {
        verify_single(&tip_raw, tip_outputs.as_ref().unwrap())?
    } else {
        true
    };

    let continuous = match &tip_outputs {
        Some(tip) => tip.start_prev_hash == epoch_outputs.tip_hash,
        None => true,
    };

    Ok(VerifyResult {
        epoch_proof_valid,
        tip_valid,
        continuous,
        epoch_outputs,
        tip_outputs,
    })
}

/// verify just tip proof (for incremental sync)
/// tip_proof is a full proof: [public_outputs_len][public_outputs][log_size][proof]
pub fn verify_tip(tip_proof: &[u8]) -> Result<bool> {
    let (outputs, raw) = split_full_proof(tip_proof)?;
    verify_single(&raw, &outputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_proof_fails() {
        let result = verify_proofs(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_too_small_proof_fails() {
        let result = verify_proofs(&[1, 2, 3]);
        assert!(result.is_err());
    }
}

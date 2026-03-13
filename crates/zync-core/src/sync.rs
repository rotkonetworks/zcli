//! Sync verification primitives for Zcash light clients.
//!
//! Pure verification logic with no IO, no wallet state, and no network calls.
//! Every function takes data in and returns a verdict. This is the core of the
//! trust model: the server provides claims, these functions verify them against
//! cryptographic proofs anchored to the hardcoded activation block hash.
//!
//! ## Verification flow
//!
//! ```text
//! header proof bytes ─→ verify_header_proof() ─→ ProvenRoots
//!                                                    │
//!                  ┌─────────────────────────────────┼──────────────────────┐
//!                  │                                 │                      │
//!                  ▼                                 ▼                      ▼
//!   verify_commitment_proofs()        verify_nullifier_proofs()   verify_actions_commitment()
//!   (received notes exist)            (spent/unspent status)      (block action integrity)
//! ```
//!
//! All verification functions return `Result<T, ZyncError>`. An `Err` means the
//! server is lying or compromised. The caller MUST abort the sync and not persist
//! any data from this session.
//!
//! ## Memo extraction
//!
//! [`extract_enc_ciphertext`] parses raw V5 transaction bytes to find the 580-byte
//! encrypted ciphertext for a specific action. Memo decryption itself requires
//! orchard key types (version-sensitive), so callers handle `try_note_decryption`
//! directly using their own orchard dependency.

use crate::error::ZyncError;
use crate::verifier;
use crate::{actions, ACTIVATION_HASH_MAINNET, EPOCH_SIZE};

use zcash_note_encryption::ENC_CIPHERTEXT_SIZE;

/// Proven NOMT roots extracted from the ligerito header proof.
/// These are the roots that NOMT merkle proofs must verify against.
#[derive(Clone, Debug, Default)]
pub struct ProvenRoots {
    pub tree_root: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub actions_commitment: [u8; 32],
}

/// Result of cross-verifying a block hash against multiple endpoints.
#[derive(Debug)]
pub struct CrossVerifyTally {
    pub agree: u32,
    pub disagree: u32,
}

impl CrossVerifyTally {
    /// Check BFT majority (>2/3 of responding nodes agree).
    pub fn has_majority(&self) -> bool {
        let total = self.agree + self.disagree;
        if total == 0 {
            return false;
        }
        let threshold = (total * 2).div_ceil(3);
        self.agree >= threshold
    }

    pub fn total(&self) -> u32 {
        self.agree + self.disagree
    }
}

/// Compare two block hashes, accounting for LE/BE byte order differences
/// between native gRPC lightwalletd (BE display order) and zidecar (LE internal).
pub fn hashes_match(a: &[u8], b: &[u8]) -> bool {
    if a.is_empty() || b.is_empty() {
        return true; // can't compare empty hashes
    }
    if a == b {
        return true;
    }
    let mut b_rev = b.to_vec();
    b_rev.reverse();
    a == b_rev.as_slice()
}

/// Validate a header proof and extract proven NOMT roots.
///
/// Returns `ProvenRoots` on success, or error if the proof is invalid,
/// discontinuous, or too stale relative to tip.
pub fn verify_header_proof(
    proof_bytes: &[u8],
    tip: u32,
    mainnet: bool,
) -> Result<ProvenRoots, ZyncError> {
    let result = verifier::verify_proofs_full(proof_bytes)
        .map_err(|e| ZyncError::InvalidProof(format!("header proof: {}", e)))?;

    if !result.epoch_proof_valid {
        return Err(ZyncError::InvalidProof("epoch proof invalid".into()));
    }
    if !result.tip_valid {
        return Err(ZyncError::InvalidProof("tip proof invalid".into()));
    }
    if !result.continuous {
        return Err(ZyncError::InvalidProof("proof chain discontinuous".into()));
    }

    // verify epoch proof anchors to hardcoded activation block hash
    if mainnet && result.epoch_outputs.start_hash != ACTIVATION_HASH_MAINNET {
        return Err(ZyncError::InvalidProof(format!(
            "epoch proof start_hash doesn't match activation anchor: got {}",
            hex::encode(&result.epoch_outputs.start_hash[..8]),
        )));
    }

    // extract proven roots from the most recent proof (tip > epoch proof)
    let outputs = result
        .tip_outputs
        .as_ref()
        .unwrap_or(&result.epoch_outputs);

    // reject if proof is more than 1 epoch behind tip
    if outputs.end_height + EPOCH_SIZE < tip {
        return Err(ZyncError::InvalidProof(format!(
            "header proof too stale: covers to {} but tip is {} (>{} blocks behind)",
            outputs.end_height, tip, EPOCH_SIZE,
        )));
    }

    Ok(ProvenRoots {
        tree_root: outputs.tip_tree_root,
        nullifier_root: outputs.tip_nullifier_root,
        actions_commitment: outputs.final_actions_commitment,
    })
}

/// Verify the running actions commitment chain against the proven value.
///
/// Returns the validated commitment, or an error if the chain doesn't match.
/// For legacy wallets (pre-0.5.1), returns the proven commitment directly.
pub fn verify_actions_commitment(
    running: &[u8; 32],
    proven: &[u8; 32],
    has_saved_commitment: bool,
) -> Result<[u8; 32], ZyncError> {
    if !has_saved_commitment {
        // legacy wallet: no saved actions commitment from pre-0.5.1 sync.
        // trust the proven value and save it for future chaining.
        Ok(*proven)
    } else if running != proven {
        Err(ZyncError::StateMismatch(format!(
            "actions commitment mismatch: server tampered with block actions (computed={} proven={})",
            hex::encode(&running[..8]),
            hex::encode(&proven[..8]),
        )))
    } else {
        Ok(*running)
    }
}

/// Commitment proof from a server, ready for verification.
pub struct CommitmentProofData {
    pub cmx: [u8; 32],
    pub tree_root: [u8; 32],
    pub path_proof_raw: Vec<u8>,
    pub value_hash: [u8; 32],
}

impl CommitmentProofData {
    pub fn verify(&self) -> Result<bool, crate::nomt::NomtVerifyError> {
        crate::nomt::verify_commitment_proof(
            &self.cmx,
            self.tree_root,
            &self.path_proof_raw,
            self.value_hash,
        )
    }
}

/// Nullifier proof from a server, ready for verification.
pub struct NullifierProofData {
    pub nullifier: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub is_spent: bool,
    pub path_proof_raw: Vec<u8>,
    pub value_hash: [u8; 32],
}

impl NullifierProofData {
    pub fn verify(&self) -> Result<bool, crate::nomt::NomtVerifyError> {
        crate::nomt::verify_nullifier_proof(
            &self.nullifier,
            self.nullifier_root,
            self.is_spent,
            &self.path_proof_raw,
            self.value_hash,
        )
    }
}

/// Verify a batch of commitment proofs against proven roots.
///
/// Checks: root binding, proof count, cmx membership, cryptographic validity.
pub fn verify_commitment_proofs(
    proofs: &[CommitmentProofData],
    requested_cmxs: &[[u8; 32]],
    proven: &ProvenRoots,
    server_root: &[u8; 32],
) -> Result<(), ZyncError> {
    // bind server-returned root to ligerito-proven root
    if server_root != &proven.tree_root {
        return Err(ZyncError::VerificationFailed(format!(
            "commitment tree root mismatch: server={} proven={}",
            hex::encode(server_root),
            hex::encode(proven.tree_root),
        )));
    }

    // verify proof count matches requested count
    if proofs.len() != requested_cmxs.len() {
        return Err(ZyncError::VerificationFailed(format!(
            "commitment proof count mismatch: requested {} but got {}",
            requested_cmxs.len(),
            proofs.len(),
        )));
    }

    // verify each returned proof's cmx matches one we requested
    let cmx_set: std::collections::HashSet<[u8; 32]> = requested_cmxs.iter().copied().collect();
    for proof in proofs {
        if !cmx_set.contains(&proof.cmx) {
            return Err(ZyncError::VerificationFailed(format!(
                "server returned commitment proof for unrequested cmx {}",
                hex::encode(proof.cmx),
            )));
        }

        // verify merkle path walks to the claimed root
        match proof.verify() {
            Ok(true) => {}
            Ok(false) => {
                return Err(ZyncError::VerificationFailed(format!(
                    "commitment proof invalid for cmx {}",
                    hex::encode(proof.cmx),
                )))
            }
            Err(e) => {
                return Err(ZyncError::VerificationFailed(format!(
                    "commitment proof verification error: {}",
                    e,
                )))
            }
        }

        // verify proof root matches the proven root
        if proof.tree_root != proven.tree_root {
            return Err(ZyncError::VerificationFailed(format!(
                "commitment proof root mismatch for cmx {}",
                hex::encode(proof.cmx),
            )));
        }
    }

    Ok(())
}

/// Verify a batch of nullifier proofs against proven roots.
///
/// Returns list of nullifiers proven spent on-chain.
pub fn verify_nullifier_proofs(
    proofs: &[NullifierProofData],
    requested_nullifiers: &[[u8; 32]],
    proven: &ProvenRoots,
    server_root: &[u8; 32],
) -> Result<Vec<[u8; 32]>, ZyncError> {
    // bind server-returned root to ligerito-proven root
    if server_root != &proven.nullifier_root {
        return Err(ZyncError::VerificationFailed(format!(
            "nullifier root mismatch: server={} proven={}",
            hex::encode(server_root),
            hex::encode(proven.nullifier_root),
        )));
    }

    if proofs.len() != requested_nullifiers.len() {
        return Err(ZyncError::VerificationFailed(format!(
            "nullifier proof count mismatch: requested {} but got {}",
            requested_nullifiers.len(),
            proofs.len(),
        )));
    }

    let nf_set: std::collections::HashSet<[u8; 32]> =
        requested_nullifiers.iter().copied().collect();
    let mut spent = Vec::new();

    for proof in proofs {
        if !nf_set.contains(&proof.nullifier) {
            return Err(ZyncError::VerificationFailed(format!(
                "server returned nullifier proof for unrequested nullifier {}",
                hex::encode(proof.nullifier),
            )));
        }

        match proof.verify() {
            Ok(true) => {
                if proof.is_spent {
                    spent.push(proof.nullifier);
                }
            }
            Ok(false) => {
                return Err(ZyncError::VerificationFailed(format!(
                    "nullifier proof invalid for {}",
                    hex::encode(proof.nullifier),
                )))
            }
            Err(e) => {
                return Err(ZyncError::VerificationFailed(format!(
                    "nullifier proof verification error: {}",
                    e,
                )))
            }
        }

        if proof.nullifier_root != proven.nullifier_root {
            return Err(ZyncError::VerificationFailed(format!(
                "nullifier proof root mismatch for {}: server={} proven={}",
                hex::encode(proof.nullifier),
                hex::encode(proof.nullifier_root),
                hex::encode(proven.nullifier_root),
            )));
        }
    }

    Ok(spent)
}

/// Extract the 580-byte enc_ciphertext for an action matching cmx+epk from raw tx bytes.
///
/// V5 orchard action layout: cv(32) + nf(32) + rk(32) + cmx(32) + epk(32) + enc(580) + out(80) = 820 bytes
/// enc_ciphertext immediately follows epk within each action.
pub fn extract_enc_ciphertext(
    raw_tx: &[u8],
    cmx: &[u8; 32],
    epk: &[u8; 32],
) -> Option<[u8; ENC_CIPHERTEXT_SIZE]> {
    for i in 0..raw_tx.len().saturating_sub(64 + ENC_CIPHERTEXT_SIZE) {
        if &raw_tx[i..i + 32] == cmx && &raw_tx[i + 32..i + 64] == epk {
            let start = i + 64;
            let end = start + ENC_CIPHERTEXT_SIZE;
            if end <= raw_tx.len() {
                let mut enc = [0u8; ENC_CIPHERTEXT_SIZE];
                enc.copy_from_slice(&raw_tx[start..end]);
                return Some(enc);
            }
        }
    }
    None
}

/// Compute running actions commitment for a sequence of blocks.
#[allow(clippy::type_complexity)]
pub fn chain_actions_commitment(
    initial: &[u8; 32],
    blocks: &[(u32, Vec<([u8; 32], [u8; 32], [u8; 32])>)],
) -> [u8; 32] {
    let mut running = *initial;
    for (height, block_actions) in blocks {
        let actions_root = actions::compute_actions_root(block_actions);
        running = actions::update_actions_commitment(&running, &actions_root, *height);
    }
    running
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashes_match_same() {
        let h = [1u8; 32];
        assert!(hashes_match(&h, &h));
    }

    #[test]
    fn test_hashes_match_reversed() {
        let a: Vec<u8> = (0..32).collect();
        let b: Vec<u8> = (0..32).rev().collect();
        assert!(hashes_match(&a, &b));
    }

    #[test]
    fn test_hashes_match_empty() {
        assert!(hashes_match(&[], &[1u8; 32]));
        assert!(hashes_match(&[1u8; 32], &[]));
    }

    #[test]
    fn test_hashes_no_match() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(!hashes_match(&a, &b));
    }

    #[test]
    fn test_cross_verify_tally_majority() {
        let tally = CrossVerifyTally {
            agree: 3,
            disagree: 1,
        };
        assert!(tally.has_majority()); // 3/4 > 2/3

        let tally = CrossVerifyTally {
            agree: 1,
            disagree: 2,
        };
        assert!(!tally.has_majority()); // 1/3 < 2/3
    }

    #[test]
    fn test_cross_verify_tally_empty() {
        let tally = CrossVerifyTally {
            agree: 0,
            disagree: 0,
        };
        assert!(!tally.has_majority());
    }

    #[test]
    fn test_actions_commitment_legacy() {
        let proven = [42u8; 32];
        let result = verify_actions_commitment(&[0u8; 32], &proven, false).unwrap();
        assert_eq!(result, proven);
    }

    #[test]
    fn test_actions_commitment_match() {
        let commitment = [42u8; 32];
        let result = verify_actions_commitment(&commitment, &commitment, true).unwrap();
        assert_eq!(result, commitment);
    }

    #[test]
    fn test_actions_commitment_mismatch() {
        let running = [1u8; 32];
        let proven = [2u8; 32];
        assert!(verify_actions_commitment(&running, &proven, true).is_err());
    }

    #[test]
    fn test_extract_enc_ciphertext_not_found() {
        let raw = vec![0u8; 100];
        let cmx = [1u8; 32];
        let epk = [2u8; 32];
        assert!(extract_enc_ciphertext(&raw, &cmx, &epk).is_none());
    }

    #[test]
    fn test_chain_actions_commitment_empty() {
        let initial = [0u8; 32];
        let result = chain_actions_commitment(&initial, &[]);
        assert_eq!(result, initial);
    }
}

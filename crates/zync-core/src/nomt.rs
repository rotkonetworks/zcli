//! NOMT proof verification primitives shared between zcli and zidecar.
//!
//! Domain-separated key derivation and merkle proof verification using nomt-core.
//! Both client (zcli) and server (zidecar) MUST use these same functions to ensure
//! key derivation is consistent.

use bitvec::prelude::*;
use nomt_core::hasher::Blake3Hasher;
use nomt_core::proof::PathProof;
use nomt_core::trie::LeafData;
use sha2::{Digest, Sha256};

// re-export for consumers
pub use nomt_core::hasher::Blake3Hasher as Hasher;
pub use nomt_core::proof::PathProof as NomtPathProof;
pub use nomt_core::trie::LeafData as NomtLeafData;

/// Domain-separated key for nullifier lookups in the NOMT tree.
pub fn key_for_nullifier(nullifier: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zidecar:nullifier:");
    hasher.update(nullifier);
    hasher.finalize().into()
}

/// Domain-separated key for note/commitment lookups in the NOMT tree.
pub fn key_for_note(cmx: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zidecar:note:");
    hasher.update(cmx);
    hasher.finalize().into()
}

/// Error from NOMT proof verification.
#[derive(Debug, thiserror::Error)]
pub enum NomtVerifyError {
    #[error("no path proof data (old server?)")]
    MissingProof,
    #[error("deserialize path proof: {0}")]
    Deserialize(String),
    #[error("path proof verification failed: {0}")]
    PathVerify(String),
    #[error("key out of scope of proof")]
    OutOfScope,
}

/// Verify a commitment (note existence) proof against a tree root.
///
/// Returns `Ok(true)` if the note exists with the expected value,
/// `Ok(false)` if the proof is valid but the value doesn't match,
/// `Err` if the proof is cryptographically invalid.
pub fn verify_commitment_proof(
    cmx: &[u8; 32],
    tree_root: [u8; 32],
    path_proof_raw: &[u8],
    value_hash: [u8; 32],
) -> Result<bool, NomtVerifyError> {
    if path_proof_raw.is_empty() {
        return Err(NomtVerifyError::MissingProof);
    }

    let path_proof: PathProof = bincode::deserialize(path_proof_raw)
        .map_err(|e| NomtVerifyError::Deserialize(e.to_string()))?;

    let key = key_for_note(cmx);

    let verified = path_proof
        .verify::<Blake3Hasher>(key.view_bits::<Msb0>(), tree_root)
        .map_err(|e| NomtVerifyError::PathVerify(format!("{:?}", e)))?;

    let expected_leaf = LeafData {
        key_path: key,
        value_hash,
    };
    match verified.confirm_value(&expected_leaf) {
        Ok(v) => Ok(v),
        Err(_) => Err(NomtVerifyError::OutOfScope),
    }
}

/// Verify a nullifier proof against a nullifier root.
///
/// If `is_spent` is true, verifies the nullifier EXISTS in the tree.
/// If `is_spent` is false, verifies the nullifier does NOT exist.
///
/// Returns `Ok(true)` if the proof matches the claimed spent status,
/// `Ok(false)` if the proof contradicts the claim (server lied),
/// `Err` if the proof is cryptographically invalid.
pub fn verify_nullifier_proof(
    nullifier: &[u8; 32],
    nullifier_root: [u8; 32],
    is_spent: bool,
    path_proof_raw: &[u8],
    value_hash: [u8; 32],
) -> Result<bool, NomtVerifyError> {
    if path_proof_raw.is_empty() {
        return Err(NomtVerifyError::MissingProof);
    }

    let path_proof: PathProof = bincode::deserialize(path_proof_raw)
        .map_err(|e| NomtVerifyError::Deserialize(e.to_string()))?;

    let key = key_for_nullifier(nullifier);

    let verified = path_proof
        .verify::<Blake3Hasher>(key.view_bits::<Msb0>(), nullifier_root)
        .map_err(|e| NomtVerifyError::PathVerify(format!("{:?}", e)))?;

    if is_spent {
        let expected_leaf = LeafData {
            key_path: key,
            value_hash,
        };
        match verified.confirm_value(&expected_leaf) {
            Ok(v) => Ok(v),
            Err(_) => Err(NomtVerifyError::OutOfScope),
        }
    } else {
        match verified.confirm_nonexistence(&key) {
            Ok(v) => Ok(v),
            Err(_) => Err(NomtVerifyError::OutOfScope),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_derivation_deterministic() {
        let nf = [0xab; 32];
        let k1 = key_for_nullifier(&nf);
        let k2 = key_for_nullifier(&nf);
        assert_eq!(k1, k2);
    }

    #[test]
    fn key_derivation_domain_separation() {
        let data = [0x42; 32];
        let nf_key = key_for_nullifier(&data);
        let note_key = key_for_note(&data);
        assert_ne!(
            nf_key, note_key,
            "different domains must produce different keys"
        );
    }

    #[test]
    fn empty_proof_rejected() {
        let cmx = [1u8; 32];
        let root = [0u8; 32];
        let err = verify_commitment_proof(&cmx, root, &[], [0u8; 32]);
        assert!(matches!(err, Err(NomtVerifyError::MissingProof)));
    }

    #[test]
    fn garbage_proof_rejected() {
        let cmx = [1u8; 32];
        let root = [0u8; 32];
        let err = verify_commitment_proof(&cmx, root, &[0xff; 64], [0u8; 32]);
        assert!(matches!(err, Err(NomtVerifyError::Deserialize(_))));
    }
}

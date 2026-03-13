//! Header chain trace encoding for ligerito polynomial commitment proofs.
//!
//! Encodes block headers into a trace polynomial that ligerito can prove over.
//! The trace layout binds block hashes, prev_hash linkage, difficulty progression,
//! state roots at epoch boundaries, and a sentinel row with tip NOMT roots.
//!
//! ## Trace layout (32 fields per header)
//!
//! ```text
//! Field  0:      height
//! Fields 1-8:    block_hash (32 bytes = 8 × 4-byte LE fields)
//! Fields 9-16:   prev_hash  (32 bytes = 8 × 4-byte LE fields)
//! Field  17:     nBits (compact difficulty target)
//! Field  18:     cumulative_difficulty (lower 32 bits)
//! Field  19:     running header commitment (Blake2b-512 chain, lower 4 bytes)
//! Fields 20-23:  sapling_root (16 bytes, epoch boundaries only)
//! Fields 24-27:  orchard_root (16 bytes, epoch boundaries only)
//! Fields 28-29:  nullifier_root (8 bytes, epoch boundaries only)
//! Field  30:     state_commitment (Blake2b-512 chain, lower 4 bytes)
//! Field  31:     reserved
//! ```
//!
//! After all headers, a sentinel row of 24 fields:
//! ```text
//! Fields 0-7:   tip_tree_root (32 bytes)
//! Fields 8-15:  tip_nullifier_root (32 bytes)
//! Fields 16-23: final_actions_commitment (32 bytes)
//! ```
//!
//! Public outputs are extracted from fixed trace positions by the prover
//! and bound to the Fiat-Shamir transcript. The Ligerito proximity test
//! does NOT constrain these values — soundness relies on the honest-prover
//! assumption plus cross-verification against independent nodes.

use blake2::{Blake2b512, Digest};
use ligerito_binary_fields::{BinaryElem32, BinaryFieldElement};

use crate::error::ZyncError;

/// Fields encoded per block header in the trace polynomial.
pub const FIELDS_PER_HEADER: usize = 32;

/// Sentinel row appended after all headers.
/// Contains tip_tree_root, tip_nullifier_root, final_actions_commitment.
pub const TIP_SENTINEL_SIZE: usize = 24;

/// State roots at an epoch boundary.
#[derive(Clone, Debug, Default)]
pub struct EpochStateRoots {
    pub epoch: u32,
    pub height: u32,
    /// Sapling note commitment tree root (hex-encoded from zebrad).
    pub sapling_root: String,
    /// Orchard note commitment tree root (hex-encoded from zebrad).
    pub orchard_root: String,
    /// Nullifier set root from NOMT (raw 32 bytes).
    pub nullifier_root: [u8; 32],
}

/// Header data for trace encoding.
/// Minimal fields needed. No full block data, just what goes into the trace.
#[derive(Clone, Debug)]
pub struct TraceHeader {
    pub height: u32,
    /// Block hash as hex string (LE internal order).
    pub hash: String,
    /// Previous block hash as hex string.
    pub prev_hash: String,
    /// nBits difficulty target as hex string (e.g. "1d00ffff").
    pub bits: String,
}

/// Header chain trace for ligerito proving.
///
/// Contains the encoded trace polynomial and metadata extracted during encoding.
/// Construct via [`encode_trace`], then pass to the prover.
pub struct HeaderChainTrace {
    /// Trace polynomial (padded to next power of 2).
    pub trace: Vec<BinaryElem32>,
    /// Number of headers encoded.
    pub num_headers: usize,
    pub start_height: u32,
    pub end_height: u32,
    /// Initial running commitment (zeros for epoch proof, previous proof's
    /// final commitment for tip proof).
    pub initial_commitment: [u8; 32],
    /// Final running commitment (stored in field 19 of last header).
    pub final_commitment: [u8; 32],
    pub initial_state_commitment: [u8; 32],
    pub final_state_commitment: [u8; 32],
    /// Cumulative difficulty (total chain work) at end of trace.
    pub cumulative_difficulty: u64,
    /// Orchard commitment tree root at tip height.
    pub tip_tree_root: [u8; 32],
    /// Nullifier root (NOMT) at tip height.
    pub tip_nullifier_root: [u8; 32],
}

/// Encode headers into a trace polynomial for ligerito proving.
///
/// Returns a `HeaderChainTrace` with the trace padded to the next power of 2.
/// The sentinel row is appended after all headers with tip roots and actions commitment.
pub fn encode_trace(
    headers: &[TraceHeader],
    state_roots: &[EpochStateRoots],
    initial_commitment: [u8; 32],
    initial_state_commitment: [u8; 32],
    tip_tree_root: [u8; 32],
    tip_nullifier_root: [u8; 32],
    final_actions_commitment: [u8; 32],
) -> Result<HeaderChainTrace, ZyncError> {
    if headers.is_empty() {
        return Err(ZyncError::InvalidData("empty headers".into()));
    }

    let num_elements = headers.len() * FIELDS_PER_HEADER + TIP_SENTINEL_SIZE;
    let trace_size = num_elements.next_power_of_two();
    let mut trace = vec![BinaryElem32::zero(); trace_size];

    let mut running_commitment = initial_commitment;
    let mut state_commitment = initial_state_commitment;
    let mut cumulative_difficulty: u64 = 0;

    let state_root_map: std::collections::HashMap<u32, &EpochStateRoots> =
        state_roots.iter().map(|r| (r.height, r)).collect();

    for (i, header) in headers.iter().enumerate() {
        let offset = i * FIELDS_PER_HEADER;

        let block_hash = hex_to_bytes(&header.hash)?;
        let prev_hash = if header.prev_hash.is_empty() {
            if header.height != 0 {
                return Err(ZyncError::InvalidData(format!(
                    "block {} has empty prev_hash (only genesis allowed)",
                    header.height
                )));
            }
            vec![0u8; 32]
        } else {
            hex_to_bytes(&header.prev_hash)?
        };

        let nbits = if header.bits.is_empty() {
            0u32
        } else {
            u32::from_str_radix(&header.bits, 16).unwrap_or(0)
        };

        let block_difficulty = nbits_to_difficulty(nbits);
        cumulative_difficulty = cumulative_difficulty.saturating_add(block_difficulty);

        // Field 0: height
        trace[offset] = BinaryElem32::from(header.height);

        // Fields 1-8: block_hash
        for j in 0..8 {
            trace[offset + 1 + j] = bytes_to_field(&block_hash[j * 4..(j + 1) * 4]);
        }

        // Fields 9-16: prev_hash
        for j in 0..8 {
            trace[offset + 9 + j] = bytes_to_field(&prev_hash[j * 4..(j + 1) * 4]);
        }

        // Field 17: nBits
        trace[offset + 17] = BinaryElem32::from(nbits);

        // Field 18: cumulative difficulty (lower 32 bits)
        trace[offset + 18] = BinaryElem32::from(cumulative_difficulty as u32);

        // Field 19: running commitment
        running_commitment =
            update_running_commitment(&running_commitment, &block_hash, &prev_hash, header.height);
        trace[offset + 19] = bytes_to_field(&running_commitment[0..4]);

        // Fields 20-31: state roots at epoch boundaries
        if let Some(roots) = state_root_map.get(&header.height) {
            let sapling = if roots.sapling_root.is_empty() {
                vec![0u8; 32]
            } else {
                hex_to_bytes(&roots.sapling_root)?
            };
            let orchard = if roots.orchard_root.is_empty() {
                vec![0u8; 32]
            } else {
                hex_to_bytes(&roots.orchard_root)?
            };

            for j in 0..4 {
                trace[offset + 20 + j] = bytes_to_field(&sapling[j * 4..(j + 1) * 4]);
            }
            for j in 0..4 {
                trace[offset + 24 + j] = bytes_to_field(&orchard[j * 4..(j + 1) * 4]);
            }

            let nf_root = &roots.nullifier_root;
            trace[offset + 28] = bytes_to_field(&nf_root[0..4]);
            trace[offset + 29] = bytes_to_field(&nf_root[4..8]);

            state_commitment = update_state_commitment(
                &state_commitment,
                &sapling,
                &orchard,
                nf_root,
                header.height,
            );
            trace[offset + 30] = bytes_to_field(&state_commitment[0..4]);
        } else {
            trace[offset + 30] = bytes_to_field(&state_commitment[0..4]);
        }
    }

    // Sentinel row
    let sentinel_offset = headers.len() * FIELDS_PER_HEADER;
    for j in 0..8 {
        trace[sentinel_offset + j] = bytes_to_field(&tip_tree_root[j * 4..(j + 1) * 4]);
    }
    for j in 0..8 {
        trace[sentinel_offset + 8 + j] =
            bytes_to_field(&tip_nullifier_root[j * 4..(j + 1) * 4]);
    }
    for j in 0..8 {
        trace[sentinel_offset + 16 + j] =
            bytes_to_field(&final_actions_commitment[j * 4..(j + 1) * 4]);
    }

    Ok(HeaderChainTrace {
        trace,
        num_headers: headers.len(),
        start_height: headers[0].height,
        end_height: headers.last().unwrap().height,
        initial_commitment,
        final_commitment: running_commitment,
        initial_state_commitment,
        final_state_commitment: state_commitment,
        cumulative_difficulty,
        tip_tree_root,
        tip_nullifier_root,
    })
}

/// Convert 4 bytes (LE) to a BinaryElem32 trace field.
pub fn bytes_to_field(bytes: &[u8]) -> BinaryElem32 {
    assert_eq!(bytes.len(), 4);
    let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    BinaryElem32::from(value)
}

/// Hex string to bytes.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, ZyncError> {
    hex::decode(hex).map_err(|e| ZyncError::InvalidData(e.to_string()))
}

/// Running header commitment chain (Blake2b-512, truncated to 32 bytes).
///
/// `commitment_i = Blake2b512("ZIDECAR_header_commitment" || prev || block_hash || prev_hash || height_le)`
pub fn update_running_commitment(
    prev_commitment: &[u8; 32],
    block_hash: &[u8],
    prev_hash: &[u8],
    height: u32,
) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(b"ZIDECAR_header_commitment");
    hasher.update(prev_commitment);
    hasher.update(block_hash);
    hasher.update(prev_hash);
    hasher.update(height.to_le_bytes());

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);
    result
}

/// Running state commitment chain (Blake2b-512, truncated to 32 bytes).
///
/// Chains sapling root, orchard root, nullifier root at each epoch boundary.
pub fn update_state_commitment(
    prev_commitment: &[u8; 32],
    sapling_root: &[u8],
    orchard_root: &[u8],
    nullifier_root: &[u8],
    height: u32,
) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(b"ZIDECAR_state_commitment");
    hasher.update(prev_commitment);
    hasher.update(sapling_root);
    hasher.update(orchard_root);
    hasher.update(nullifier_root);
    hasher.update(height.to_le_bytes());

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);
    result
}

/// Derive tree root hash from zebrad's hex-encoded final state string.
pub fn parse_tree_root_bytes(final_state: &str) -> [u8; 32] {
    use sha2::{Digest as Sha2Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ZIDECAR_TREE_ROOT");
    hasher.update(final_state.as_bytes());
    hasher.finalize().into()
}

/// Convert nBits (compact difficulty target) to difficulty value.
///
/// nBits format: `0xAABBCCDD` where AA is exponent, BBCCDD is mantissa.
/// Returns a relative difficulty measure suitable for cumulative chain work.
pub fn nbits_to_difficulty(nbits: u32) -> u64 {
    if nbits == 0 {
        return 0;
    }
    let exponent = (nbits >> 24) as u64;
    let mantissa = (nbits & 0x00FFFFFF) as u64;
    if mantissa == 0 {
        return 0;
    }
    let shift = exponent.saturating_sub(3);
    if shift < 32 {
        let base_diff = (1u64 << 32) / mantissa;
        base_diff >> (shift * 8).min(63)
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_field() {
        let bytes = [0x01, 0x02, 0x03, 0x04];
        let field = bytes_to_field(&bytes);
        assert_eq!(field.poly().value(), 0x04030201); // little endian
    }

    #[test]
    fn test_hex_to_bytes() {
        let bytes = hex_to_bytes("deadbeef").unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_running_commitment_deterministic() {
        let prev = [0u8; 32];
        let block = [1u8; 32];
        let prev_hash = [2u8; 32];

        let c1 = update_running_commitment(&prev, &block, &prev_hash, 100);
        let c2 = update_running_commitment(&prev, &block, &prev_hash, 100);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_nbits_to_difficulty() {
        assert_eq!(nbits_to_difficulty(0), 0);
        // low exponent (shift < 8 bytes) gives non-zero difficulty
        let d = nbits_to_difficulty(0x0400ffff);
        assert!(d > 0);
        // different mantissa gives different difficulty
        let d2 = nbits_to_difficulty(0x04007fff);
        assert_ne!(d, d2);
    }

    #[test]
    fn test_encode_single_header() {
        let headers = vec![TraceHeader {
            height: 100,
            hash: "00".repeat(32),
            prev_hash: "00".repeat(32),
            bits: "1d00ffff".into(),
        }];
        let trace = encode_trace(
            &headers,
            &[],
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
        )
        .unwrap();
        assert_eq!(trace.num_headers, 1);
        assert_eq!(trace.start_height, 100);
        assert_eq!(trace.end_height, 100);
        // trace should be padded to power of 2
        assert!(trace.trace.len().is_power_of_two());
        assert!(trace.trace.len() >= FIELDS_PER_HEADER + TIP_SENTINEL_SIZE);
    }
}

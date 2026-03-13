//! WASM API for zync-core verification primitives.
//!
//! Exposes sync verification, actions commitment, NOMT proofs, and constants
//! to JavaScript via wasm-bindgen. All 32-byte values use hex encoding.
//! Proof data uses raw bytes (Uint8Array).

use wasm_bindgen::prelude::*;

use crate::actions;
use crate::nomt;
use crate::sync;

// ── constants ──

/// Orchard activation height
#[wasm_bindgen]
pub fn activation_height(mainnet: bool) -> u32 {
    if mainnet {
        crate::ORCHARD_ACTIVATION_HEIGHT
    } else {
        crate::ORCHARD_ACTIVATION_HEIGHT_TESTNET
    }
}

/// Blocks per epoch
#[wasm_bindgen]
pub fn epoch_size() -> u32 {
    crate::EPOCH_SIZE
}

/// Cross-verification endpoints as JSON array
#[wasm_bindgen]
pub fn crossverify_endpoints(mainnet: bool) -> String {
    let endpoints = if mainnet {
        crate::endpoints::CROSSVERIFY_MAINNET
    } else {
        crate::endpoints::CROSSVERIFY_TESTNET
    };
    // simple JSON array of strings
    let mut json = String::from("[");
    for (i, ep) in endpoints.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push('"');
        json.push_str(ep);
        json.push('"');
    }
    json.push(']');
    json
}

// ── header proof verification ──

/// Verify a header proof and extract proven NOMT roots.
///
/// Returns JSON: `{ "tree_root": "hex", "nullifier_root": "hex", "actions_commitment": "hex" }`
/// Throws on invalid proof.
#[wasm_bindgen]
pub fn verify_header_proof(proof_bytes: &[u8], tip: u32, mainnet: bool) -> Result<String, JsError> {
    let proven = sync::verify_header_proof(proof_bytes, tip, mainnet)
        .map_err(|e| JsError::new(&format!("{}", e)))?;

    Ok(format!(
        r#"{{"tree_root":"{}","nullifier_root":"{}","actions_commitment":"{}"}}"#,
        hex::encode(proven.tree_root),
        hex::encode(proven.nullifier_root),
        hex::encode(proven.actions_commitment),
    ))
}

// ── commitment proof verification ──

/// Verify a single NOMT commitment proof (note exists in tree).
#[wasm_bindgen]
pub fn verify_commitment_proof(
    cmx_hex: &str,
    tree_root_hex: &str,
    path_proof: &[u8],
    value_hash_hex: &str,
) -> Result<bool, JsError> {
    let cmx = parse_hex32(cmx_hex)?;
    let tree_root = parse_hex32(tree_root_hex)?;
    let value_hash = parse_hex32(value_hash_hex)?;

    nomt::verify_commitment_proof(&cmx, tree_root, path_proof, value_hash)
        .map_err(|e| JsError::new(&format!("commitment proof: {}", e)))
}

/// Verify a single NOMT nullifier proof (spent/unspent).
#[wasm_bindgen]
pub fn verify_nullifier_proof(
    nullifier_hex: &str,
    nullifier_root_hex: &str,
    is_spent: bool,
    path_proof: &[u8],
    value_hash_hex: &str,
) -> Result<bool, JsError> {
    let nullifier = parse_hex32(nullifier_hex)?;
    let nullifier_root = parse_hex32(nullifier_root_hex)?;
    let value_hash = parse_hex32(value_hash_hex)?;

    nomt::verify_nullifier_proof(&nullifier, nullifier_root, is_spent, path_proof, value_hash)
        .map_err(|e| JsError::new(&format!("nullifier proof: {}", e)))
}

// ── actions commitment chain ──

/// Compute merkle root for a block's actions.
///
/// Input: binary packed actions `[count_u32_le] [cmx(32) | nullifier(32) | epk(32)] * count`
/// Returns: hex-encoded 32-byte root
#[wasm_bindgen]
pub fn compute_actions_root(actions_binary: &[u8]) -> Result<String, JsError> {
    if actions_binary.len() < 4 {
        return Ok(hex::encode([0u8; 32]));
    }

    let count = u32::from_le_bytes(
        actions_binary[..4].try_into().map_err(|_| JsError::new("invalid length"))?,
    ) as usize;

    let data = &actions_binary[4..];
    if data.len() < count * 96 {
        return Err(JsError::new(&format!(
            "expected {} actions ({}B) but got {}B",
            count, count * 96, data.len()
        )));
    }

    let mut action_tuples = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * 96;
        let mut cmx = [0u8; 32];
        let mut nf = [0u8; 32];
        let mut epk = [0u8; 32];
        cmx.copy_from_slice(&data[off..off + 32]);
        nf.copy_from_slice(&data[off + 32..off + 64]);
        epk.copy_from_slice(&data[off + 64..off + 96]);
        action_tuples.push((cmx, nf, epk));
    }

    let root = actions::compute_actions_root(&action_tuples);
    Ok(hex::encode(root))
}

/// Update running actions commitment chain.
///
/// Returns hex-encoded 32-byte commitment.
#[wasm_bindgen]
pub fn update_actions_commitment(
    prev_hex: &str,
    actions_root_hex: &str,
    height: u32,
) -> Result<String, JsError> {
    let prev = parse_hex32(prev_hex)?;
    let actions_root = parse_hex32(actions_root_hex)?;
    let result = actions::update_actions_commitment(&prev, &actions_root, height);
    Ok(hex::encode(result))
}

/// Verify actions commitment chain matches proven value.
///
/// Throws on mismatch (server tampered with block actions).
#[wasm_bindgen]
pub fn verify_actions_commitment(
    running_hex: &str,
    proven_hex: &str,
    has_saved_commitment: bool,
) -> Result<String, JsError> {
    let running = parse_hex32(running_hex)?;
    let proven = parse_hex32(proven_hex)?;
    let result = sync::verify_actions_commitment(&running, &proven, has_saved_commitment)
        .map_err(|e| JsError::new(&format!("{}", e)))?;
    Ok(hex::encode(result))
}

// ── utilities ──

/// Compare two block hashes accounting for LE/BE byte order differences.
#[wasm_bindgen]
pub fn hashes_match(a_hex: &str, b_hex: &str) -> bool {
    let a = hex::decode(a_hex).unwrap_or_default();
    let b = hex::decode(b_hex).unwrap_or_default();
    sync::hashes_match(&a, &b)
}

/// Extract enc_ciphertext from raw V5 transaction bytes for a specific action.
///
/// Returns hex-encoded 580-byte ciphertext, or empty string if not found.
#[wasm_bindgen]
pub fn extract_enc_ciphertext(
    raw_tx: &[u8],
    cmx_hex: &str,
    epk_hex: &str,
) -> Result<String, JsError> {
    let cmx = parse_hex32(cmx_hex)?;
    let epk = parse_hex32(epk_hex)?;
    match sync::extract_enc_ciphertext(raw_tx, &cmx, &epk) {
        Some(enc) => Ok(hex::encode(enc)),
        None => Ok(String::new()),
    }
}

// ── helpers ──

fn parse_hex32(hex_str: &str) -> Result<[u8; 32], JsError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| JsError::new(&format!("invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(JsError::new(&format!("expected 32 bytes, got {}", bytes.len())));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

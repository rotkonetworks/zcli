//! WASM API for zync-core verification primitives.
//!
//! Exposes constants and sync helpers to JavaScript via wasm-bindgen.
//! All 32-byte values use hex encoding.

use wasm_bindgen::prelude::*;

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
    let bytes = hex::decode(hex_str).map_err(|e| JsError::new(&format!("invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

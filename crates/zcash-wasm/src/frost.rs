// frost.rs — WASM bindings for frost-spend orchestrate module
//
// exposes DKG, signing, and spend authorization to browser (zafu/zigner-web).
// all inputs/outputs are hex strings — transport-agnostic, JSON-serializable.

use wasm_bindgen::prelude::*;

// ── DKG ──

/// trusted dealer: generate key packages for all participants
#[wasm_bindgen]
pub fn frost_dealer_keygen(min_signers: u16, max_signers: u16) -> Result<String, JsError> {
    let result = frost_spend::orchestrate::dealer_keygen(min_signers, max_signers)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "packages": result.packages,
        "public_key_package": result.public_key_package_hex,
    })).map_err(|e| JsError::new(&e.to_string()))
}

/// DKG round 1: generate ephemeral identity + signed commitment
#[wasm_bindgen]
pub fn frost_dkg_part1(max_signers: u16, min_signers: u16) -> Result<String, JsError> {
    let result = frost_spend::orchestrate::dkg_part1(max_signers, min_signers)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "secret": result.secret_hex,
        "broadcast": result.broadcast_hex,
    })).map_err(|e| JsError::new(&e.to_string()))
}

/// DKG round 2: process signed round1 broadcasts, produce per-peer packages
#[wasm_bindgen]
pub fn frost_dkg_part2(secret_hex: &str, peer_broadcasts_json: &str) -> Result<String, JsError> {
    let broadcasts: Vec<String> = serde_json::from_str(peer_broadcasts_json)
        .map_err(|e| JsError::new(&format!("bad broadcasts JSON: {}", e)))?;
    let result = frost_spend::orchestrate::dkg_part2(secret_hex, &broadcasts)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "secret": result.secret_hex,
        "peer_packages": result.peer_packages,
    })).map_err(|e| JsError::new(&e.to_string()))
}

/// DKG round 3: finalize — returns key package + public key package
#[wasm_bindgen]
pub fn frost_dkg_part3(
    secret_hex: &str,
    round1_broadcasts_json: &str,
    round2_packages_json: &str,
) -> Result<String, JsError> {
    let r1: Vec<String> = serde_json::from_str(round1_broadcasts_json)
        .map_err(|e| JsError::new(&format!("bad round1 JSON: {}", e)))?;
    let r2: Vec<String> = serde_json::from_str(round2_packages_json)
        .map_err(|e| JsError::new(&format!("bad round2 JSON: {}", e)))?;
    let result = frost_spend::orchestrate::dkg_part3(secret_hex, &r1, &r2)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "key_package": result.key_package_hex,
        "public_key_package": result.public_key_package_hex,
        "ephemeral_seed": result.ephemeral_seed_hex,
    })).map_err(|e| JsError::new(&e.to_string()))
}

// ── generic signing ──

/// signing round 1: generate nonces + signed commitments
#[wasm_bindgen]
pub fn frost_sign_round1(ephemeral_seed_hex: &str, key_package_hex: &str) -> Result<String, JsError> {
    let seed = parse_seed(ephemeral_seed_hex)?;
    let (nonces, commitments) = frost_spend::orchestrate::sign_round1(&seed, key_package_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "nonces": nonces,
        "commitments": commitments,
    })).map_err(|e| JsError::new(&e.to_string()))
}

/// coordinator: generate signed randomizer
#[wasm_bindgen]
pub fn frost_generate_randomizer(
    ephemeral_seed_hex: &str,
    message_hex: &str,
    commitments_json: &str,
) -> Result<String, JsError> {
    let seed = parse_seed(ephemeral_seed_hex)?;
    let msg = hex::decode(message_hex)
        .map_err(|e| JsError::new(&format!("bad message hex: {}", e)))?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    frost_spend::orchestrate::generate_randomizer(&seed, &msg, &commitments)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// signing round 2: produce signed signature share
#[wasm_bindgen]
pub fn frost_sign_round2(
    ephemeral_seed_hex: &str,
    key_package_hex: &str,
    nonces_hex: &str,
    message_hex: &str,
    commitments_json: &str,
    randomizer_hex: &str,
) -> Result<String, JsError> {
    let seed = parse_seed(ephemeral_seed_hex)?;
    let msg = hex::decode(message_hex)
        .map_err(|e| JsError::new(&format!("bad message hex: {}", e)))?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    frost_spend::orchestrate::sign_round2(
        &seed, key_package_hex, nonces_hex, &msg, &commitments, randomizer_hex,
    ).map_err(|e| JsError::new(&e.to_string()))
}

/// coordinator: aggregate signed shares into final signature
#[wasm_bindgen]
pub fn frost_aggregate_shares(
    public_key_package_hex: &str,
    message_hex: &str,
    commitments_json: &str,
    shares_json: &str,
    randomizer_hex: &str,
) -> Result<String, JsError> {
    let msg = hex::decode(message_hex)
        .map_err(|e| JsError::new(&format!("bad message hex: {}", e)))?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    let shares: Vec<String> = serde_json::from_str(shares_json)
        .map_err(|e| JsError::new(&format!("bad shares JSON: {}", e)))?;
    frost_spend::orchestrate::aggregate_shares(
        public_key_package_hex, &msg, &commitments, &shares, randomizer_hex,
    ).map_err(|e| JsError::new(&e.to_string()))
}

// ── spend authorization (sighash + alpha bound) ──

/// derive the multisig wallet's Orchard address (raw 43-byte address, hex-encoded)
#[wasm_bindgen]
pub fn frost_derive_address_raw(
    public_key_package_hex: &str,
    diversifier_index: u32,
) -> Result<String, JsError> {
    let raw = frost_spend::orchestrate::derive_address_raw(public_key_package_hex, diversifier_index)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(hex::encode(raw))
}

/// sighash-bound round 2: produce FROST share for one Orchard action
#[wasm_bindgen]
pub fn frost_spend_sign_round2(
    key_package_hex: &str,
    nonces_hex: &str,
    sighash_hex: &str,
    alpha_hex: &str,
    commitments_json: &str,
) -> Result<String, JsError> {
    let sighash = parse_32(sighash_hex, "sighash")?;
    let alpha = parse_32(alpha_hex, "alpha")?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    frost_spend::orchestrate::spend_sign_round2(
        key_package_hex, nonces_hex, &sighash, &alpha, &commitments,
    ).map_err(|e| JsError::new(&e.to_string()))
}

/// authenticated variant: wraps share in SignedMessage for relay transport
#[wasm_bindgen]
pub fn frost_spend_sign_round2_signed(
    ephemeral_seed_hex: &str,
    key_package_hex: &str,
    nonces_hex: &str,
    sighash_hex: &str,
    alpha_hex: &str,
    commitments_json: &str,
) -> Result<String, JsError> {
    let seed = parse_seed(ephemeral_seed_hex)?;
    let sighash = parse_32(sighash_hex, "sighash")?;
    let alpha = parse_32(alpha_hex, "alpha")?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    frost_spend::orchestrate::spend_sign_round2_signed(
        &seed, key_package_hex, nonces_hex, &sighash, &alpha, &commitments,
    ).map_err(|e| JsError::new(&e.to_string()))
}

/// coordinator: aggregate shares into Orchard SpendAuth signature (64 bytes hex)
#[wasm_bindgen]
pub fn frost_spend_aggregate(
    public_key_package_hex: &str,
    sighash_hex: &str,
    alpha_hex: &str,
    commitments_json: &str,
    shares_json: &str,
) -> Result<String, JsError> {
    let sighash = parse_32(sighash_hex, "sighash")?;
    let alpha = parse_32(alpha_hex, "alpha")?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    let shares: Vec<String> = serde_json::from_str(shares_json)
        .map_err(|e| JsError::new(&format!("bad shares JSON: {}", e)))?;
    frost_spend::orchestrate::spend_aggregate(
        public_key_package_hex, &sighash, &alpha, &commitments, &shares,
    ).map_err(|e| JsError::new(&e.to_string()))
}

// ── helpers ──

fn parse_seed(hex_str: &str) -> Result<[u8; 32], JsError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| JsError::new(&format!("bad seed hex: {}", e)))?;
    bytes.try_into()
        .map_err(|_| JsError::new("seed must be 32 bytes"))
}

fn parse_32(hex_str: &str, name: &str) -> Result<[u8; 32], JsError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| JsError::new(&format!("bad {} hex: {}", name, e)))?;
    bytes.try_into()
        .map_err(|_| JsError::new(&format!("{} must be 32 bytes", name)))
}

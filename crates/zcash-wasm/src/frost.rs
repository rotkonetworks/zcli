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

/// derive the multisig wallet's Orchard address (raw 43-byte address, hex-encoded).
/// non-deterministic — internally generates a random nk/rivk. only safe when a
/// single party derives-and-broadcasts. interactive DKG should use
/// `frost_derive_address_from_sk` instead.
#[wasm_bindgen]
pub fn frost_derive_address_raw(
    public_key_package_hex: &str,
    diversifier_index: u32,
) -> Result<String, JsError> {
    let raw = frost_spend::orchestrate::derive_address_raw(public_key_package_hex, diversifier_index)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(hex::encode(raw))
}

/// derive the multisig wallet's Orchard address (raw 43-byte address, hex-encoded)
/// from the group public key package and a caller-supplied `sk`. deterministic —
/// every participant computing this with the same inputs lands on byte-identical
/// output. pair with `frost_derive_ufvk(pkg, sk, mainnet)` so the stored address
/// and stored UFVK share a single source of truth for nk/rivk.
#[wasm_bindgen]
pub fn frost_derive_address_from_sk(
    public_key_package_hex: &str,
    sk_hex: &str,
    diversifier_index: u32,
) -> Result<String, JsError> {
    let sk_bytes = parse_32(sk_hex, "address sk")?;
    let raw = frost_spend::orchestrate::derive_address_from_sk(
        public_key_package_hex, sk_bytes, diversifier_index,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(hex::encode(raw))
}

/// host-only: sample a random 32-byte SpendingKey for nk/rivk derivation.
/// retries until the sampled bytes land in the Pallas scalar range.
/// returns hex-encoded 32-byte `sk` that the host broadcasts to peers in R1.
#[wasm_bindgen]
pub fn frost_sample_fvk_sk() -> String {
    use rand_core::{OsRng, RngCore};
    let mut rng = OsRng;
    // SpendingKey::from_bytes validates the scalar range; retry on the
    // vanishingly rare out-of-range case. we don't care which sk we land
    // on, only that all peers use the same one (which is why the host
    // broadcasts it rather than each peer generating their own).
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let maybe_sk: Option<orchard::keys::SpendingKey> =
            Option::from(orchard::keys::SpendingKey::from_bytes(bytes));
        if maybe_sk.is_some() {
            return hex::encode(bytes);
        }
    }
}

/// derive the Orchard-only UFVK string (`uview1…` / `uviewtest1…`) from a
/// caller-supplied 32-byte SpendingKey and a FROST public key package.
/// every participant, given the same `sk_hex` + `public_key_package_hex`,
/// lands on byte-identical output.
#[wasm_bindgen]
pub fn frost_derive_ufvk(
    public_key_package_hex: &str,
    sk_hex: &str,
    mainnet: bool,
) -> Result<String, JsError> {
    use zcash_address::unified::{Encoding, Fvk, Ufvk};
    use zcash_protocol::consensus::NetworkType;

    let sk_bytes = parse_32(sk_hex, "fvk sk")?;

    let pubkeys: frost_spend::frost_keys::PublicKeyPackage =
        frost_spend::orchestrate::from_hex(public_key_package_hex)
            .map_err(|e| JsError::new(&e.to_string()))?;

    let fvk = frost_spend::keys::derive_fvk_from_sk(sk_bytes, &pubkeys)
        .ok_or_else(|| JsError::new("failed to derive FVK from group key + sk"))?;

    // zcash_keys uses orchard-0.11 (registry) while frost-spend uses the ZF
    // orchard fork. both share the 96-byte FVK wire format, so we cross the
    // type boundary by going through bytes + zcash_address::unified::Ufvk
    // (byte-tagged items), bypassing zcash_keys::UnifiedFullViewingKey.
    let ufvk = Ufvk::try_from_items(vec![Fvk::Orchard(fvk.to_bytes())])
        .map_err(|e| JsError::new(&format!("build UFVK: {e}")))?;

    let network = if mainnet { NetworkType::Main } else { NetworkType::Test };
    Ok(ufvk.encode(&network))
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

// ── anchor attestation (domain-separated from spend auth) ──
//
// Signing uses the existing orchestrate::sign_round1/sign_round2/aggregate_shares
// with attestation_digest() as the message. No special signing API needed.
//
// The attestation data is 96 bytes: signature(64) || randomizer(32).

/// Compute the attestation digest for an anchor.
/// Returns hex-encoded 32-byte SHA-256 digest.
#[wasm_bindgen]
pub fn frost_attestation_digest(
    public_key_package_hex: &str,
    anchor_hex: &str,
    anchor_height: u32,
    mainnet: bool,
) -> Result<String, JsError> {
    let vk = frost_spend::attestation::extract_group_vk(public_key_package_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let anchor = parse_32(anchor_hex, "anchor")?;
    let digest = frost_spend::attestation::attestation_digest(&vk, &anchor, anchor_height, mainnet);
    Ok(hex::encode(digest))
}

/// Verify an attestation (96 bytes: sig || randomizer).
#[wasm_bindgen]
pub fn frost_attestation_verify(
    attestation_hex: &str,
    public_key_package_hex: &str,
    anchor_hex: &str,
    anchor_height: u32,
    mainnet: bool,
) -> Result<bool, JsError> {
    let anchor = parse_32(anchor_hex, "anchor")?;
    let attestation: [u8; 96] = hex::decode(attestation_hex)
        .map_err(|e| JsError::new(&format!("bad attestation hex: {e}")))?
        .try_into()
        .map_err(|_| JsError::new("attestation must be 96 bytes (sig 64 + randomizer 32)"))?;

    frost_spend::attestation::verify_from_bytes(
        &attestation, public_key_package_hex, &anchor, anchor_height, mainnet,
    )
    .map_err(|e| JsError::new(&e.to_string()))
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

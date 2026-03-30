//! ring-vrf-wasm: Bandersnatch Ring VRF prover for zafu pro.
//!
//! proves "I belong to the set of pro subscribers" without revealing which one.
//! context-specific aliases prevent cross-session linkability.
//!
//! prover only -- verifier runs on zidecar (native Rust).

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::suites::bandersnatch::{self as suite, *};
use wasm_bindgen::prelude::*;

type Suite = suite::BandersnatchSha512Ell2;

// SRS embedded at compile time (~590 KB)
const SRS_BYTES: &[u8] = include_bytes!("../data/bls12-381-srs-2-11-uncompressed-zcash.bin");

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// derive a Bandersnatch public key from a ZID seed (32 bytes).
/// returns 32-byte hex-encoded compressed point.
///
/// the extension registers this pubkey with zidecar so it gets
/// included in the pro ring.
#[wasm_bindgen]
pub fn derive_ring_pubkey(zid_seed: &[u8]) -> Result<String, JsValue> {
    let ring_seed = domain_separate_seed(zid_seed)?;
    let secret = ark_vrf::Secret::<Suite>::from_seed(&ring_seed);
    let public = secret.public();

    let mut buf = Vec::new();
    public
        .0
        .serialize_compressed(&mut buf)
        .map_err(|e| JsValue::from_str(&format!("serialize: {e}")))?;

    Ok(hex::encode(buf))
}

/// generate a ring VRF proof.
///
/// - `zid_seed`: 32-byte ZID private seed
/// - `ring_keys_hex`: comma-separated hex-encoded 32-byte Bandersnatch pubkeys
/// - `my_index`: this user's position in the ring
/// - `context`: epoch context string (e.g. "zafu-pro-2026-03-30")
///
/// returns hex-encoded proof (32-byte VRF output + ~752-byte ring proof).
/// the VRF output serves as a per-epoch unlinkable alias.
#[wasm_bindgen]
pub fn ring_vrf_prove(
    zid_seed: &[u8],
    ring_keys_hex: &str,
    my_index: u32,
    context: &str,
) -> Result<String, JsValue> {
    let ring_seed = domain_separate_seed(zid_seed)?;
    let secret = ark_vrf::Secret::<Suite>::from_seed(&ring_seed);

    // parse ring keys
    let ring_keys: Vec<[u8; 32]> = ring_keys_hex
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|h| {
            let bytes = hex::decode(h.trim())
                .map_err(|e| JsValue::from_str(&format!("hex decode: {e}")))?;
            let mut key = [0u8; 32];
            let len = bytes.len().min(32);
            key[..len].copy_from_slice(&bytes[..len]);
            Ok(key)
        })
        .collect::<Result<Vec<_>, JsValue>>()?;

    if ring_keys.is_empty() {
        return Err(JsValue::from_str("empty ring"));
    }
    let idx = my_index as usize;
    if idx >= ring_keys.len() {
        return Err(JsValue::from_str("index out of range"));
    }

    // build ring params from embedded SRS
    let pcs = PcsParams::deserialize_uncompressed_unchecked(&mut &SRS_BYTES[..])
        .map_err(|e| JsValue::from_str(&format!("SRS deserialize: {e}")))?;
    let params = RingProofParams::from_pcs_params(ring_keys.len(), pcs)
        .map_err(|e| JsValue::from_str(&format!("ring params: {e:?}")))?;

    // deserialize all public keys to affine points
    let points: Vec<AffinePoint> = ring_keys
        .iter()
        .map(|key_bytes| {
            AffinePoint::deserialize_compressed(&key_bytes[..])
                .unwrap_or(RingProofParams::padding_point())
        })
        .collect();

    // create prover bound to our position
    let prover_key = params.prover_key(&points);
    let prover = params.prover(prover_key, idx);

    // VRF input from context string
    let input = ark_vrf::Input::<Suite>::new(context.as_bytes())
        .ok_or_else(|| JsValue::from_str("invalid VRF input"))?;

    let output = secret.output(input);

    // generate the ring proof
    use ark_vrf::ring::Prover as _;
    let proof = secret.prove(input, output, &[], &prover);

    // serialize: [32-byte output | ring proof]
    let mut result = Vec::new();
    output
        .0
        .serialize_compressed(&mut result)
        .map_err(|e| JsValue::from_str(&format!("output serialize: {e}")))?;
    proof
        .serialize_compressed(&mut result)
        .map_err(|e| JsValue::from_str(&format!("proof serialize: {e}")))?;

    Ok(hex::encode(result))
}

/// domain-separate the ZID seed for ring VRF key derivation.
/// ensures the Bandersnatch key is independent of other ZID-derived keys.
fn domain_separate_seed(zid_seed: &[u8]) -> Result<[u8; 32], JsValue> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    if zid_seed.len() < 16 {
        return Err(JsValue::from_str("seed too short"));
    }

    let hk = Hkdf::<Sha256>::new(None, zid_seed);
    let mut out = [0u8; 32];
    hk.expand(b"zafu-ring-vrf-v1", &mut out)
        .map_err(|_| JsValue::from_str("HKDF failed"))?;
    Ok(out)
}

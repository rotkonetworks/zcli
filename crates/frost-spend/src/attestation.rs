// attestation.rs — anchor attestation via pre-hashed message + existing RedPallas FROST
//
// Domain separation: the attestation data is pre-hashed with SHA-256 before
// signing. The 32-byte digest is signed using the existing reddsa FROST
// infrastructure — same code path as spend auth. A valid attestation digest
// can never collide with a sighash because they use different hash functions.
//
// The CBOR carries 96 bytes: signature(64) + randomizer(32). The verifier
// reconstructs rk from vk + randomizer*G and verifies using reddsa.
//
// ZERO custom crypto. All signing uses orchestrate::sign_round1/sign_round2/
// aggregate_shares. All verification uses reddsa.

use sha2::{Digest, Sha256};

use crate::orchestrate::{from_hex, Error};

// ============================================================================
// Message construction
// ============================================================================

/// Compute the attestation digest: SHA-256 of domain-separated attestation data.
///
/// This 32-byte digest is what gets signed by the FROST group using the
/// existing RedPallas signing path (via orchestrate).
///
/// digest = SHA-256("zcash-anchor-v1" || vk(32) || anchor(32) || height(4,LE) || mainnet(1))
pub fn attestation_digest(
    group_verifying_key: &[u8; 32],
    anchor: &[u8; 32],
    height: u32,
    mainnet: bool,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zcash-anchor-v1");
    hasher.update(group_verifying_key);
    hasher.update(anchor);
    hasher.update(height.to_le_bytes());
    hasher.update([u8::from(mainnet)]);
    hasher.finalize().into()
}

// ============================================================================
// Verification (uses reddsa — same library that produced the signature)
// ============================================================================

/// Verify an attestation from raw bytes using reddsa.
///
/// attestation_data: [signature(64) || randomizer(32)] = 96 bytes.
/// group_verifying_key: 32-byte compressed Pallas point (from PublicKeyPackage).
///
/// Returns Ok(true) if valid, Ok(false) if invalid, Err on parse/deserialization failure.
pub fn verify_from_bytes(
    attestation_data: &[u8; 96],
    public_key_package_hex: &str,
    anchor: &[u8; 32],
    height: u32,
    mainnet: bool,
) -> Result<bool, Error> {
    use crate::{frost, RandomizedParams, Randomizer};

    let vk_bytes = extract_group_vk(public_key_package_hex)?;

    // Deserialize signature using frost-core's ciphersuite method
    let sig = <frost::PallasBlake2b512 as frost::Ciphersuite>::deserialize_signature(
        &attestation_data[..64],
    )
    .map_err(|e| Error::Serialize(format!("deserialize signature: {e}")))?;

    // Deserialize randomizer
    let randomizer = Randomizer::deserialize(&attestation_data[64..96])
        .map_err(|e| Error::Serialize(format!("deserialize randomizer: {e}")))?;

    // Get the verifying key from the public key package
    let pubkeys: crate::frost_keys::PublicKeyPackage = from_hex(public_key_package_hex)?;

    // Compute randomized verifying key: rk = vk + randomizer * G
    let params = RandomizedParams::from_randomizer(pubkeys.verifying_key(), randomizer);

    // Compute digest
    let digest = attestation_digest(&vk_bytes, anchor, height, mainnet);

    // Verify using reddsa's own verification
    match params.randomized_verifying_key().verify(&digest, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Extract the 32-byte group verifying key from a hex-encoded PublicKeyPackage.
pub fn extract_group_vk(public_key_package_hex: &str) -> Result<[u8; 32], Error> {
    let pubkeys: crate::frost_keys::PublicKeyPackage = from_hex(public_key_package_hex)?;
    let vk_vec = pubkeys
        .verifying_key()
        .serialize()
        .map_err(|_| Error::Serialize("serialize verifying key".into()))?;
    vk_vec
        .try_into()
        .map_err(|_| Error::Serialize("verifying key is not 32 bytes".into()))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_digest_deterministic() {
        let vk = [1u8; 32];
        let anchor = [2u8; 32];
        let d1 = attestation_digest(&vk, &anchor, 1000, true);
        let d2 = attestation_digest(&vk, &anchor, 1000, true);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_attestation_digest_domain_separation() {
        let vk = [1u8; 32];
        let anchor = [2u8; 32];
        let d1 = attestation_digest(&vk, &anchor, 1000, true);
        let d2 = attestation_digest(&vk, &anchor, 1001, true);
        assert_ne!(d1, d2);
        let d3 = attestation_digest(&vk, &anchor, 1000, false);
        assert_ne!(d1, d3);
        let d4 = attestation_digest(&[3u8; 32], &anchor, 1000, true);
        assert_ne!(d1, d4);
    }

    #[test]
    fn test_roundtrip_sign_verify() {
        // dealer keygen: 2-of-2
        let keygen = crate::orchestrate::dealer_keygen(2, 2).unwrap();
        let vk = extract_group_vk(&keygen.public_key_package_hex).unwrap();
        let anchor = [0xab; 32];
        let height = 3_000_000u32;
        let mainnet = true;

        let digest = attestation_digest(&vk, &anchor, height, mainnet);

        // unwrap dealer packages
        fn unwrap_pkg(pkg_hex: &str) -> ([u8; 32], String) {
            let signed: crate::message::SignedMessage = from_hex(pkg_hex).unwrap();
            let bundle: serde_json::Value = serde_json::from_slice(&signed.payload).unwrap();
            let seed = hex::decode(bundle["ephemeral_seed"].as_str().unwrap()).unwrap();
            (seed.try_into().unwrap(), bundle["key_package"].as_str().unwrap().to_string())
        }

        let (seed0, kp0) = unwrap_pkg(&keygen.packages[0]);
        let (seed1, kp1) = unwrap_pkg(&keygen.packages[1]);

        // round 1
        let (nonces0, commit0) = crate::orchestrate::sign_round1(&seed0, &kp0).unwrap();
        let (nonces1, commit1) = crate::orchestrate::sign_round1(&seed1, &kp1).unwrap();
        let commits = vec![commit0.clone(), commit1.clone()];

        // coordinator generates randomizer
        let randomizer_hex =
            crate::orchestrate::generate_randomizer(&[0x42; 32], &digest, &commits).unwrap();

        // round 2
        let share0 = crate::orchestrate::sign_round2(
            &seed0, &kp0, &nonces0, &digest, &commits, &randomizer_hex,
        ).unwrap();
        let share1 = crate::orchestrate::sign_round2(
            &seed1, &kp1, &nonces1, &digest, &commits, &randomizer_hex,
        ).unwrap();

        // aggregate
        let sig_hex = crate::orchestrate::aggregate_shares(
            &keygen.public_key_package_hex, &digest, &commits, &[share0, share1], &randomizer_hex,
        ).unwrap();

        // extract raw bytes: randomizer
        let signed_rand: crate::message::SignedMessage = from_hex(&randomizer_hex).unwrap();
        let (_, rand_payload) = signed_rand.verify().unwrap();
        let rand_to_hex: String = serde_json::from_slice(rand_payload).unwrap();
        let randomizer: crate::Randomizer = from_hex(&rand_to_hex).unwrap();
        let rand_json = serde_json::to_vec(&randomizer).unwrap();
        let rand_hex_str: String = serde_json::from_slice(&rand_json).unwrap();
        let rand_raw = hex::decode(&rand_hex_str).unwrap();

        // extract raw bytes: signature
        let sig: reddsa::frost::redpallas::Signature = from_hex(&sig_hex).unwrap();
        let sig_raw = sig.serialize().unwrap();

        // build attestation: sig(64) || randomizer(32)
        assert_eq!(sig_raw.len(), 64);
        assert_eq!(rand_raw.len(), 32);
        let mut attestation = [0u8; 96];
        attestation[..64].copy_from_slice(&sig_raw);
        attestation[64..96].copy_from_slice(&rand_raw);

        // verify
        let result = verify_from_bytes(
            &attestation, &keygen.public_key_package_hex, &anchor, height, mainnet,
        ).unwrap();
        assert!(result, "attestation should verify");

        // tampered anchor should fail
        let bad = verify_from_bytes(
            &attestation, &keygen.public_key_package_hex, &[0xcd; 32], height, mainnet,
        ).unwrap();
        assert!(!bad, "tampered anchor should fail");
    }
}

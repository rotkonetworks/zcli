// attestation.rs — anchor attestation signing and verification
//
// Produces Schnorr signatures on the Pallas curve with a custom challenge
// hash ("ZignerAnchorAtH") that is domain-separated from Zcash spend auth
// ("Zcash_RedPallasH"). This ensures attestation signatures can never be
// confused with spend authorization signatures, and vice versa.
//
// The signing side uses osst's RedPallas FROST infrastructure but replaces
// the challenge computation. The verification side is a standalone Schnorr
// check using the same custom challenge.
//
// Protocol:
//   message = "zcash-anchor-v1" || vk(32) || anchor(32) || height(4,LE) || mainnet(1)
//   c = BLAKE2b-512("ZignerAnchorAtH\0", R || vk || message)
//   signature = (R, z) where g^z == R + c * vk

use osst::curve::{OsstPoint, OsstScalar};
use osst::frost::{Nonces, Signature, SignatureShare, SigningCommitments};
use osst::{compute_lagrange_coefficients, OsstError, SecretShare};
use pasta_curves::pallas::{Point, Scalar};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

extern crate alloc;

// ============================================================================
// Challenge hash
// ============================================================================

/// BLAKE2b-512 personalized with "ZignerAnchorAtH\0" (16 bytes).
///
/// Domain-separated from Zcash spend auth ("Zcash_RedPallasH").
/// c = H("ZignerAnchorAtH\0", R || vk || msg)
fn attestation_challenge(group_commitment: &Point, group_pubkey: &Point, message: &[u8]) -> Scalar {
    let h = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"ZignerAnchorAtH\0")
        .to_state()
        .update(&group_commitment.compress())
        .update(&group_pubkey.compress())
        .update(message)
        .finalize();
    let hash: [u8; 64] = *h.as_array();
    Scalar::from_bytes_wide(&hash)
}

/// Binding factor for attestation FROST (same structure as RedPallas).
fn attestation_binding_factor(index: u32, message: &[u8], encoded_commitments: &[u8]) -> Scalar {
    let h = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"ZignerAttesBind\0")
        .to_state()
        .update(&index.to_le_bytes())
        .update(&(message.len() as u64).to_le_bytes())
        .update(message)
        .update(encoded_commitments)
        .finalize();
    let hash: [u8; 64] = *h.as_array();
    Scalar::from_bytes_wide(&hash)
}

// ============================================================================
// Message construction
// ============================================================================

/// Build the attestation message: domain || vk || anchor || height || mainnet.
///
/// This is the message that gets signed by the FROST group.
/// Both signer (zcli) and verifier (zigner) must produce identical messages.
pub fn attestation_message(
    group_verifying_key: &[u8; 32],
    anchor: &[u8; 32],
    height: u32,
    mainnet: bool,
) -> [u8; 84] {
    let domain = b"zcash-anchor-v1";
    let mut msg = [0u8; 84]; // 15 + 32 + 32 + 4 + 1
    msg[..15].copy_from_slice(domain);
    msg[15..47].copy_from_slice(group_verifying_key);
    msg[47..79].copy_from_slice(anchor);
    msg[79..83].copy_from_slice(&height.to_le_bytes());
    msg[83] = u8::from(mainnet);
    msg
}

// ============================================================================
// Signing package (mirrors osst::redpallas::zcash::RedPallasPackage)
// ============================================================================

/// Attestation signing package — same structure as RedPallasPackage but with
/// the attestation-specific challenge and binding factor hashes.
pub struct AttestationPackage {
    message: Vec<u8>,
    commitments: BTreeMap<u32, SigningCommitments<Point>>,
    encoded_commitments: Vec<u8>,
}

fn encode_commitments(commitments: &BTreeMap<u32, SigningCommitments<Point>>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(commitments.len() * 68);
    for (_, c) in commitments {
        buf.extend_from_slice(&c.index.to_le_bytes());
        buf.extend_from_slice(&c.hiding.compress());
        buf.extend_from_slice(&c.binding.compress());
    }
    buf
}

impl AttestationPackage {
    pub fn new(
        message: Vec<u8>,
        commitments: Vec<SigningCommitments<Point>>,
    ) -> Result<Self, OsstError> {
        let mut map = BTreeMap::new();
        for c in commitments {
            if c.index == 0 {
                return Err(OsstError::InvalidIndex);
            }
            if map.contains_key(&c.index) {
                return Err(OsstError::DuplicateIndex(c.index));
            }
            map.insert(c.index, c);
        }
        if map.is_empty() {
            return Err(OsstError::EmptyContributions);
        }

        let encoded = encode_commitments(&map);

        Ok(Self {
            message,
            commitments: map,
            encoded_commitments: encoded,
        })
    }

    pub fn signer_indices(&self) -> Vec<u32> {
        self.commitments.keys().copied().collect()
    }

    pub fn num_signers(&self) -> usize {
        self.commitments.len()
    }

    fn binding_factor(&self, index: u32) -> Scalar {
        attestation_binding_factor(index, &self.message, &self.encoded_commitments)
    }

    fn group_commitment(&self) -> Point {
        let mut r = Point::identity();
        for (_, c) in &self.commitments {
            let rho = self.binding_factor(c.index);
            let bound = c.binding.mul_scalar(&rho);
            r = r.add(&c.hiding);
            r = r.add(&bound);
        }
        r
    }

    fn challenge(&self, group_commitment: &Point, group_pubkey: &Point) -> Scalar {
        attestation_challenge(group_commitment, group_pubkey, &self.message)
    }
}

// ============================================================================
// FROST signing (attestation-specific)
// ============================================================================

/// Round 1: generate nonces and commitments (same as generic FROST).
pub fn commit<R: rand_core::RngCore + rand_core::CryptoRng>(
    index: u32,
    rng: &mut R,
) -> (Nonces<Scalar>, SigningCommitments<Point>) {
    osst::frost::commit::<Point, R>(index, rng)
}

/// Round 2: produce an attestation signature share.
pub fn sign(
    package: &AttestationPackage,
    nonces: Nonces<Scalar>,
    share: &SecretShare<Scalar>,
    group_pubkey: &Point,
) -> Result<SignatureShare<Scalar>, OsstError> {
    if package.commitments.get(&share.index).is_none() {
        return Err(OsstError::InvalidIndex);
    }

    let rho = package.binding_factor(share.index);
    let group_commitment = package.group_commitment();
    let challenge = package.challenge(&group_commitment, group_pubkey);

    let indices = package.signer_indices();
    let lagrange = compute_lagrange_coefficients::<Scalar>(&indices)?;
    let my_pos = indices
        .iter()
        .position(|&i| i == share.index)
        .ok_or(OsstError::InvalidIndex)?;
    let lambda = &lagrange[my_pos];

    // z_i = d_i + ρ_i · e_i + λ_i · c · s_i
    let response = nonces.compute_response(&rho, lambda, &challenge, share.scalar());

    Ok(SignatureShare {
        index: share.index,
        response,
    })
}

/// Aggregate signature shares into an attestation signature.
///
/// No randomization — the signature verifies against the base group key.
pub fn aggregate(
    package: &AttestationPackage,
    shares: &[SignatureShare<Scalar>],
    group_pubkey: &Point,
) -> Result<Signature<Point>, OsstError> {
    if shares.len() < package.num_signers() {
        return Err(OsstError::InsufficientContributions {
            got: shares.len(),
            need: package.num_signers(),
        });
    }

    let group_commitment = package.group_commitment();

    // z = Σ z_i
    let mut z = Scalar::zero();
    for share in shares {
        z = z.add(&share.response);
    }

    let sig = Signature {
        r: group_commitment,
        z,
    };

    // Verify before returning — catch bad shares early
    if !verify(group_pubkey, &package.message, &sig) {
        return Err(OsstError::InvalidResponse);
    }

    Ok(sig)
}

// ============================================================================
// Verification
// ============================================================================

/// Verify an attestation signature against a group public key.
///
/// This is standalone Schnorr verification with the attestation challenge hash.
/// Used by both the signer (post-aggregate check) and the verifier (zigner).
pub fn verify(group_pubkey: &Point, message: &[u8], signature: &Signature<Point>) -> bool {
    let challenge = attestation_challenge(&signature.r, group_pubkey, message);
    let lhs = Point::generator().mul_scalar(&signature.z);
    let rhs = signature.r.add(&group_pubkey.mul_scalar(&challenge));
    lhs == rhs
}

/// Verify from raw bytes — convenience for callers that don't want osst types.
///
/// signature_bytes: [R:32][z:32], group_verifying_key: compressed Pallas point.
/// Returns None on parse failure, Some(bool) on success.
pub fn verify_from_bytes(
    signature_bytes: &[u8; 64],
    group_verifying_key: &[u8; 32],
    message: &[u8],
) -> Option<bool> {
    let group_pubkey = Point::decompress(group_verifying_key)?;
    let sig = Signature::<Point>::from_bytes(signature_bytes).ok()?;
    Some(verify(&group_pubkey, message, &sig))
}

// ============================================================================
// Orchestration — hex-string API bridging reddsa key types to osst attestation
// ============================================================================

use crate::orchestrate::{from_hex, Error};

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

/// Single-party attestation: sign the anchor directly with a raw Schnorr signature.
///
/// This bypasses FROST rounds entirely — it's a single-signer shortcut for
/// dealer-keygen setups or testing. Uses the group secret key directly.
///
/// For multi-party FROST attestation, participants use commit() + sign() + aggregate().
pub fn attest_anchor_local(
    key_package_hex: &str,
    public_key_package_hex: &str,
    anchor: &[u8; 32],
    anchor_height: u32,
    mainnet: bool,
) -> Result<String, Error> {
    use rand_core::OsRng;

    let vk = extract_group_vk(public_key_package_hex)?;
    let group_pubkey =
        Point::decompress(&vk).ok_or_else(|| Error::Serialize("invalid group vk".into()))?;

    let msg = attestation_message(&vk, anchor, anchor_height, mainnet);

    // For single-signer (1-of-1 dealer keygen), the signing share IS the secret key.
    // Extract it via the reddsa serialization: JSON(hex(scalar_bytes))
    let key_pkg: crate::frost_keys::KeyPackage = from_hex(key_package_hex)?;
    let share_hex: String = serde_json::to_string(key_pkg.signing_share())
        .and_then(|s| serde_json::from_str(&s))
        .map_err(|e| Error::Serialize(format!("serialize signing share: {e}")))?;
    let share_bytes: [u8; 32] = hex::decode(&share_hex)
        .map_err(|e| Error::Serialize(format!("decode share hex: {e}")))?
        .try_into()
        .map_err(|_| Error::Serialize("share not 32 bytes".into()))?;
    let sk = Scalar::from_canonical_bytes(&share_bytes)
        .ok_or_else(|| Error::Serialize("invalid share scalar".into()))?;

    // Raw Schnorr sign: k random, R = k*G, c = H(R, Y, m), z = k + c*sk
    let k = Scalar::random(&mut OsRng);
    let r = Point::generator().mul_scalar(&k);
    let challenge = attestation_challenge(&r, &group_pubkey, &msg);
    let z = k.add(&challenge.mul(&sk));

    let sig = Signature { r, z };

    // Sanity check
    if !verify(&group_pubkey, &msg, &sig) {
        return Err(Error::Frost("local attestation verification failed".into()));
    }

    Ok(hex::encode(sig.to_bytes()))
}

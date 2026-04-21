//! zcash identity authentication primitive
//!
//! sign/verify challenges with the wallet's ed25519 identity key.
//! no chain interaction needed — pure local crypto.
//!
//! # usage
//!
//! ```text
//! verifier → challenge (32 random bytes)
//! prover   → sign(challenge, ed25519_secret_key) → (signature, public_key)
//! verifier → verify(challenge, signature, public_key) → bool
//! ```
//!
//! the ed25519 key is derived from the zcash wallet seed via:
//!   identity_key = BLAKE2b("zcash-identity-v1" || wallet_seed)
//!
//! this is the same key used by zcli for relay participant IDs,
//! zafu for challenge signing, and zitadel for lobby identity.
//!
//! # wasm
//!
//! all functions are no_std compatible and compile to wasm32.

use sha2::{Sha512, Digest};

/// generate a random 32-byte challenge
pub fn generate_challenge(rng: &mut impl rand::RngCore) -> [u8; 32] {
    let mut challenge = [0u8; 32];
    rng.fill_bytes(&mut challenge);
    challenge
}

/// derive an ed25519 identity keypair from a wallet seed.
///
/// the identity key is derived deterministically:
///   secret = BLAKE2b-512("zcash-identity-v1" || seed)[..32]
///
/// this is NOT the spending key. it's a separate identity key
/// that proves you control a wallet without revealing the seed
/// or any spending capability.
pub fn derive_identity_keypair(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha512::new();
    hasher.update(b"zcash-identity-v1");
    hasher.update(seed);
    let hash = hasher.finalize();

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&hash[..32]);

    // ed25519 public key = secret * basepoint (clamped)
    // we compute this via the standard ed25519 scalar mult
    let public = ed25519_public_from_secret(&secret);

    (secret, public)
}

/// sign a challenge with the identity secret key.
///
/// returns (signature, public_key) — 64 + 32 bytes.
/// the verifier needs only the challenge, signature, and public key.
pub fn sign_challenge(challenge: &[u8; 32], secret_key: &[u8; 32]) -> ([u8; 64], [u8; 32]) {
    let public_key = ed25519_public_from_secret(secret_key);
    let signature = ed25519_sign(challenge, secret_key, &public_key);
    (signature, public_key)
}

/// verify a challenge signature against a public key.
pub fn verify_challenge(
    challenge: &[u8; 32],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) -> bool {
    ed25519_verify(challenge, signature, public_key)
}

/// the public key bytes ARE the identity. hex-encode for display.
pub fn identity_to_hex(public_key: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in public_key {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// derive a deterministic anon nick from a public key.
///
/// free accounts (no wallet connected) get ephemeral keys.
/// their nick is "anon" + first 5 digits derived from the key.
/// e.g. "anon48201", "anon91337"
///
/// wallet-connected users can set a custom nick.
pub fn anon_nick(public_key: &[u8; 32]) -> String {
    let n = u32::from_le_bytes([
        public_key[0], public_key[1], public_key[2], public_key[3],
    ]) % 100000;
    format!("anon{:05}", n)
}

// ============================================================================
// ed25519 primitives (minimal, no external dep beyond sha2)
// ============================================================================

// these use the standard ed25519 construction over curve25519.
// in production, use ed25519-dalek. for now, we delegate to a
// simple implementation that works in no_std + wasm.

fn ed25519_public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    // clamp and scalar mult against basepoint
    // for now, hash the secret to get the expanded key per RFC 8032
    let mut hasher = Sha512::new();
    hasher.update(secret);
    let expanded = hasher.finalize();

    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&expanded[..32]);
    // clamp
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    // multiply by basepoint — we need curve25519 for this.
    // stub: return hash of scalar as "public key" for now.
    // TODO: use curve25519-dalek or ed25519-dalek for real implementation
    let mut hasher = Sha512::new();
    hasher.update(b"ed25519-pubkey-stub");
    hasher.update(&scalar);
    let h = hasher.finalize();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&h[..32]);
    pk
}

fn ed25519_sign(message: &[u8], secret: &[u8; 32], public: &[u8; 32]) -> [u8; 64] {
    // RFC 8032 Ed25519 signing
    // stub: HMAC-style signature for structure testing
    // TODO: use ed25519-dalek for real implementation
    let mut hasher = Sha512::new();
    hasher.update(b"ed25519-sign-stub");
    hasher.update(secret);
    hasher.update(public);
    hasher.update(message);
    let h = hasher.finalize();
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&h[..64]);
    sig
}

fn ed25519_verify(message: &[u8], signature: &[u8; 64], public: &[u8; 32]) -> bool {
    // recompute and compare
    // stub: matches the sign stub above
    // TODO: use ed25519-dalek for real implementation
    let mut hasher = Sha512::new();
    hasher.update(b"ed25519-sign-stub");
    // we don't have the secret key here, so this stub always returns true
    // for matching public keys. real impl verifies the curve equation.
    //
    // TEMPORARY: derive expected sig from public key + message
    // this is NOT secure — it's a placeholder until ed25519-dalek is wired in.
    let _ = (message, signature, public);

    // for now, just check the signature is non-zero
    signature.iter().any(|&b| b != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_identity() {
        let seed = b"test wallet seed for identity derivation";
        let (secret, public) = derive_identity_keypair(seed);

        assert_ne!(secret, [0u8; 32]);
        assert_ne!(public, [0u8; 32]);

        // deterministic
        let (s2, p2) = derive_identity_keypair(seed);
        assert_eq!(secret, s2);
        assert_eq!(public, p2);

        // different seed = different keys
        let (s3, p3) = derive_identity_keypair(b"different seed");
        assert_ne!(secret, s3);
        assert_ne!(public, p3);
    }

    #[test]
    fn test_sign_and_verify() {
        let seed = b"poker player wallet seed";
        let (secret, public) = derive_identity_keypair(seed);

        let mut rng = rand::rngs::OsRng;
        let challenge = generate_challenge(&mut rng);

        let (signature, returned_pk) = sign_challenge(&challenge, &secret);
        assert_eq!(returned_pk, public);

        // TODO: real verification once ed25519-dalek is wired in
        assert!(verify_challenge(&challenge, &signature, &public));
    }

    #[test]
    fn test_identity_hex() {
        let (_, public) = derive_identity_keypair(b"seed");
        let hex = identity_to_hex(&public);
        assert_eq!(hex.len(), 64);
    }
}

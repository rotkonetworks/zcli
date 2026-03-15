// frost.rs — FROST threshold multisig for Orchard spend authorization
//
// all crypto from audited libraries:
//   - reddsa (FROST(Pallas, BLAKE2b-512) ciphersuite)
//   - frost-core 2.2.0 (DKG, signing, aggregation)
//   - frost-rerandomized 2.2.0 (rerandomized signatures)
//   - ed25519-consensus 2 (message authentication, same crate zebra uses)
//
// every FROST message is signed with the participant's ed25519 identity key.
// FROST identifiers are derived from ed25519 public keys (Penumbra pattern).
// no separate "participant index" — identity IS the key.

use ed25519_consensus::{SigningKey, VerificationKey, Signature};
use serde::{Serialize, Deserialize};

pub use reddsa::frost::redpallas::{
    self,
    keys::{self, dkg, KeyPackage, PublicKeyPackage, SecretShare},
    round1, round2,
    aggregate, Identifier, SigningPackage,
    RandomizedParams, Randomizer,
};

use crate::error::Error;

// ── signed message envelope ──
//
// every FROST round message is wrapped in this envelope.
// the ed25519 signature covers the payload bytes, preventing
// MITM even if the transport is compromised.

#[derive(Serialize, Deserialize)]
pub struct SignedMessage {
    /// ed25519 public key of the sender
    pub pk: Vec<u8>,
    /// ed25519 signature over payload
    pub sig: Vec<u8>,
    /// the actual FROST message (json bytes)
    pub payload: Vec<u8>,
}

impl SignedMessage {
    /// create a signed message
    pub fn sign(sk: &SigningKey, payload: &[u8]) -> Self {
        let sig = sk.sign(payload);
        Self {
            pk: sk.verification_key().to_bytes().to_vec(),
            sig: sig.to_bytes().to_vec(),
            payload: payload.to_vec(),
        }
    }

    /// verify signature and return (verification_key, payload)
    pub fn verify(&self) -> Result<(VerificationKey, &[u8]), Error> {
        let pk_bytes: [u8; 32] = self.pk.as_slice().try_into()
            .map_err(|_| Error::Other("invalid ed25519 pubkey length".into()))?;
        let sig_bytes: [u8; 64] = self.sig.as_slice().try_into()
            .map_err(|_| Error::Other("invalid ed25519 signature length".into()))?;
        let vk = VerificationKey::try_from(pk_bytes)
            .map_err(|e| Error::Other(format!("invalid ed25519 pubkey: {}", e)))?;
        let sig = Signature::from(sig_bytes);
        vk.verify(&sig, &self.payload)
            .map_err(|_| Error::Other("ed25519 signature verification failed".into()))?;
        Ok((vk, &self.payload))
    }
}

/// derive a FROST identifier from an ed25519 verification key (Penumbra pattern)
pub fn identifier_from_vk(vk: &VerificationKey) -> Result<Identifier, Error> {
    Identifier::derive(vk.as_bytes().as_slice())
        .map_err(|e| Error::Other(format!("derive frost identifier: {}", e)))
}

/// load ed25519 signing key from raw 32-byte seed
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from(*seed)
}

// ── serialization ──

pub fn to_hex<T: Serialize>(val: &T) -> Result<String, Error> {
    let json = serde_json::to_vec(val)
        .map_err(|e| Error::Other(format!("serialize: {}", e)))?;
    Ok(hex::encode(json))
}

pub fn from_hex<T: serde::de::DeserializeOwned>(hex_str: &str) -> Result<T, Error> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| Error::Other(format!("bad hex: {}", e)))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::Other(format!("deserialize: {}", e)))
}

/// serialize a SignedMessage to hex
pub fn signed_to_hex(msg: &SignedMessage) -> Result<String, Error> {
    to_hex(msg)
}

/// deserialize and verify a SignedMessage from hex
pub fn signed_from_hex(hex_str: &str) -> Result<SignedMessage, Error> {
    from_hex(hex_str)
}

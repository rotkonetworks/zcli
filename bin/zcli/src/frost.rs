// frost.rs — FROST threshold multisig for Orchard spend authorization
//
// all crypto from audited libraries:
//   - reddsa (FROST(Pallas, BLAKE2b-512) ciphersuite)
//   - frost-core 2.2.0 (DKG, signing, aggregation)
//   - frost-rerandomized 2.2.0 (rerandomized signatures)
//   - ed25519-consensus 2 (message authentication, same crate zebra uses)
//
// privacy model:
//   - each DKG or signing session uses a fresh ephemeral ed25519 keypair
//   - FROST identifiers derive from ephemeral pubkeys, not long-lived identity
//   - long-lived SSH key only authenticates QUIC transport (TLS layer)
//   - sessions are unlinkable: no persistent identity in FROST messages
//
// this means an observer who compromises one session's ephemeral key
// learns nothing about other sessions. even other participants can't
// link your signing activity across sessions without the QUIC layer.

use ed25519_consensus::{SigningKey, VerificationKey, Signature};
use rand_core::OsRng;
use serde::{Serialize, Deserialize};

pub use reddsa::frost::redpallas::{
    self,
    keys::{self, dkg, KeyPackage, PublicKeyPackage, SecretShare},
    round1, round2,
    aggregate, Identifier, SigningPackage,
    RandomizedParams, Randomizer,
};

use crate::error::Error;

// ── ephemeral session identity ──
//
// generated fresh for each DKG or signing session.
// the ed25519 seed is stored in the session secret state
// and discarded when the session completes.

/// generate a fresh ephemeral ed25519 identity for a session
pub fn ephemeral_identity() -> SigningKey {
    SigningKey::new(OsRng)
}

// ── signed message envelope ──
//
// every FROST round message is wrapped in this envelope.
// the ed25519 key is ephemeral (per-session), so the pubkey
// in the envelope does not reveal long-lived identity.

#[derive(Serialize, Deserialize)]
pub struct SignedMessage {
    /// ephemeral ed25519 public key (per-session, not long-lived)
    pub pk: Vec<u8>,
    /// ed25519 signature over payload
    pub sig: Vec<u8>,
    /// the actual FROST message (json bytes)
    pub payload: Vec<u8>,
}

impl SignedMessage {
    pub fn sign(sk: &SigningKey, payload: &[u8]) -> Self {
        let sig = sk.sign(payload);
        Self {
            pk: sk.verification_key().to_bytes().to_vec(),
            sig: sig.to_bytes().to_vec(),
            payload: payload.to_vec(),
        }
    }

    /// verify signature and return (ephemeral verification_key, payload)
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

/// derive FROST identifier from ephemeral ed25519 verification key
pub fn identifier_from_vk(vk: &VerificationKey) -> Result<Identifier, Error> {
    Identifier::derive(vk.as_bytes().as_slice())
        .map_err(|e| Error::Other(format!("derive frost identifier: {}", e)))
}

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

// frost.rs — FROST threshold multisig for Orchard spend authorization
//
// all crypto from the zcash foundation's audited libraries:
//   - reddsa (RedPallas FROST ciphersuite, DKG, signing rounds)
//   - frost-rerandomized 2.2 (rerandomized FROST for unlinkable sigs)
//   - frost-core (DKG, aggregation, cheater detection)
//
// we only write glue: hex serialization for CLI transport.

pub use reddsa::frost::redpallas::{
    self,
    keys::{self, dkg, KeyPackage, PublicKeyPackage, SecretShare},
    round1, round2,
    aggregate, Identifier, Signature, SigningPackage,
    RandomizedParams, Randomizer,
};

use crate::error::Error;

/// serialize any serde-able FROST type to hex-encoded json
pub fn to_hex<T: serde::Serialize>(val: &T) -> Result<String, Error> {
    let json = serde_json::to_vec(val)
        .map_err(|e| Error::Other(format!("serialize: {}", e)))?;
    Ok(hex::encode(json))
}

/// deserialize any serde-able FROST type from hex-encoded json
pub fn from_hex<T: serde::de::DeserializeOwned>(hex_str: &str) -> Result<T, Error> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| Error::Other(format!("bad hex: {}", e)))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::Other(format!("deserialize: {}", e)))
}

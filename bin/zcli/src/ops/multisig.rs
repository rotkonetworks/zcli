// ops/multisig.rs — thin CLI wrapper over frost_spend::orchestrate
//
// all protocol logic lives in the frost-spend crate (shared with zafu).
// this module only adapts error types for zcli's Error.

use crate::error::Error;
use frost_spend::orchestrate;

// re-export result types
pub use orchestrate::{
    DealerResult, Dkg1Result, Dkg2Result, Dkg3Result,
};

// ── dealer ──

pub fn dealer_keygen(min_signers: u16, max_signers: u16) -> Result<DealerResult, Error> {
    orchestrate::dealer_keygen(min_signers, max_signers)
        .map_err(|e| Error::Other(e.to_string()))
}

// ── DKG ──

pub fn dkg_part1(max_signers: u16, min_signers: u16) -> Result<Dkg1Result, Error> {
    orchestrate::dkg_part1(max_signers, min_signers)
        .map_err(|e| Error::Other(e.to_string()))
}

pub fn dkg_part2(secret_hex: &str, peer_broadcasts_hex: &[String]) -> Result<Dkg2Result, Error> {
    orchestrate::dkg_part2(secret_hex, peer_broadcasts_hex)
        .map_err(|e| Error::Other(e.to_string()))
}

pub fn dkg_part3(
    secret_hex: &str,
    round1_broadcasts_hex: &[String],
    round2_packages_hex: &[String],
) -> Result<Dkg3Result, Error> {
    orchestrate::dkg_part3(secret_hex, round1_broadcasts_hex, round2_packages_hex)
        .map_err(|e| Error::Other(e.to_string()))
}

// ── generic signing ──

pub fn sign_round1(
    ephemeral_seed: &[u8; 32],
    key_package_hex: &str,
) -> Result<(String, String), Error> {
    orchestrate::sign_round1(ephemeral_seed, key_package_hex)
        .map_err(|e| Error::Other(e.to_string()))
}

pub fn generate_randomizer(
    ephemeral_seed: &[u8; 32],
    message: &[u8],
    signed_commitments_hex: &[String],
) -> Result<String, Error> {
    orchestrate::generate_randomizer(ephemeral_seed, message, signed_commitments_hex)
        .map_err(|e| Error::Other(e.to_string()))
}

pub fn sign_round2(
    ephemeral_seed: &[u8; 32],
    key_package_hex: &str,
    nonces_hex: &str,
    message: &[u8],
    signed_commitments_hex: &[String],
    signed_randomizer_hex: &str,
) -> Result<String, Error> {
    orchestrate::sign_round2(
        ephemeral_seed, key_package_hex, nonces_hex,
        message, signed_commitments_hex, signed_randomizer_hex,
    ).map_err(|e| Error::Other(e.to_string()))
}

pub fn aggregate_shares(
    public_key_package_hex: &str,
    message: &[u8],
    signed_commitments_hex: &[String],
    signed_shares_hex: &[String],
    signed_randomizer_hex: &str,
) -> Result<String, Error> {
    orchestrate::aggregate_shares(
        public_key_package_hex, message,
        signed_commitments_hex, signed_shares_hex, signed_randomizer_hex,
    ).map_err(|e| Error::Other(e.to_string()))
}

// ── spend authorization ──

pub fn derive_address(
    public_key_package_hex: &str,
    diversifier_index: u32,
) -> Result<String, Error> {
    let raw = orchestrate::derive_address_raw(public_key_package_hex, diversifier_index)
        .map_err(|e| Error::Other(e.to_string()))?;
    use zcash_address::unified::Encoding;
    let items = vec![zcash_address::unified::Receiver::Orchard(raw)];
    let ua = zcash_address::unified::Address::try_from_items(items)
        .map_err(|e| Error::Other(format!("UA construction: {}", e)))?;
    #[allow(deprecated)]
    let network = zcash_address::Network::Main;
    Ok(ua.encode(&network))
}

pub fn spend_sign_round2(
    key_package_hex: &str,
    nonces_hex: &str,
    sighash: &[u8; 32],
    alpha: &[u8; 32],
    signed_commitments_hex: &[String],
) -> Result<String, Error> {
    orchestrate::spend_sign_round2(
        key_package_hex, nonces_hex, sighash, alpha, signed_commitments_hex,
    ).map_err(|e| Error::Other(e.to_string()))
}

pub fn spend_aggregate(
    public_key_package_hex: &str,
    sighash: &[u8; 32],
    alpha: &[u8; 32],
    signed_commitments_hex: &[String],
    shares_hex: &[String],
) -> Result<String, Error> {
    orchestrate::spend_aggregate(
        public_key_package_hex, sighash, alpha, signed_commitments_hex, shares_hex,
    ).map_err(|e| Error::Other(e.to_string()))
}

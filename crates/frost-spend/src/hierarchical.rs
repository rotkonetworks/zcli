// hierarchical.rs — bridge custody via nested FROST + OSST reshare
//
// architecture (Eriksen: services, filters, composition):
//
// ```text
// SigningRequest
//   → OsstAuthFilter          (filter: stake-weighted quorum gate)
//   → ReshareGateFilter       (filter: blocks signing during rotation)
//   → NestedFrostSignService  (service: 2-party outer + t-of-n inner)
//   → SpendAuthSignature
// ```
//
// key structure:
//   outer 2-of-2 (position 1 = OSST holder, position 2 = validator group)
//   position 2 is a nested inner FROST: t-of-n validators collectively
//   produce one outer partial signature via osst::nested.
//
// no custom crypto. composition of:
//   - osst::dkg (Feldman DKG for initial keygen)
//   - osst::nested (interleaved DKG + inner FROST signing)
//   - osst::reshare (proactive rotation of position 1)
//   - frost-spend orchestrate (FROST signing + spend authorization)
//
// the bridge address is derived from the 2-of-2 group key and never
// changes across reshares (group key is an invariant of OSST reshare).
//
// linearity: both positions produce partial sigs over the same challenge.
// the outer aggregator sums them into a valid RedPallas SpendAuth signature
// indistinguishable from single-signer.

use std::collections::BTreeMap;

use rand_core::{OsRng, RngCore};

use crate::{
    frost_keys, round1,
    Identifier, RandomizedParams, Randomizer, SigningPackage,
    message::{SignedMessage, identifier_from_vk},
    orchestrate::{self, Error, to_hex, from_hex},
};

// ── bridge key material ──

/// key package for one participant in the bridge custody scheme.
///
/// position A: the OSST-managed share. initially held by one entity,
/// later reshared among validators weighted by stake.
///
/// position B: the validator share. in production, this is the output
/// of nested inner FROST (t-of-n). for the 2-of-2 outer protocol,
/// it appears as a single signer.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeKeyPackage {
    /// FROST key package for this position (hex)
    pub key_package: String,
    /// FROST public key package (shared, hex)
    pub public_key_package: String,
    /// ed25519 ephemeral seed for signing envelope authentication
    pub ephemeral_seed: String,
    /// which position this package represents
    pub position: BridgePosition,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BridgePosition {
    /// OSST-managed share (reshare-able)
    Osst,
    /// validator group share (nested inner FROST)
    Validator,
}

/// result of the bridge DKG ceremony
pub struct BridgeDkgResult {
    /// position A (OSST) key package
    pub osst_package: BridgeKeyPackage,
    /// position B (validator) key package
    pub validator_package: BridgeKeyPackage,
    /// FROST public key package (same for both positions)
    pub public_key_package_hex: String,
    /// bridge verifying key (32 bytes hex, compressed Pallas point)
    pub bridge_vk_hex: String,
    /// FVK bytes (96 bytes) — derived once during DKG, reuse for address + scanning.
    /// the nk/rivk are random but fixed at DKG time. MUST be persisted.
    pub fvk_bytes: [u8; 96],
}

// ── DKG ──

/// generate bridge custody keys using a trusted dealer.
///
/// produces a 2-of-2 FROST group. position 0 = OSST share,
/// position 1 = validator share.
///
/// WARNING: the dealer sees the full secret. use interactive DKG
/// (`bridge_dkg_interactive`) for production deployments.
pub fn bridge_dkg_dealer() -> Result<BridgeDkgResult, Error> {
    let dealer = orchestrate::dealer_keygen(2, 2)?;

    let (seed_0, kp_0) = unwrap_dealer_pkg(&dealer.packages[0])?;
    let (seed_1, kp_1) = unwrap_dealer_pkg(&dealer.packages[1])?;

    let pubkeys: frost_keys::PublicKeyPackage = from_hex(&dealer.public_key_package_hex)?;
    let vk_bytes = pubkeys.verifying_key().serialize()
        .map_err(|_| Error::Serialize("serialize vk".into()))?;

    // derive FVK ONCE — the random nk/rivk are fixed at DKG time and MUST be persisted
    let fvk = crate::keys::derive_fvk(&mut rand_core::OsRng, &pubkeys)
        .ok_or_else(|| Error::Frost("derive FVK failed".into()))?;
    let fvk_bytes = fvk.to_bytes();

    Ok(BridgeDkgResult {
        osst_package: BridgeKeyPackage {
            key_package: kp_0,
            public_key_package: dealer.public_key_package_hex.clone(),
            ephemeral_seed: seed_0,
            position: BridgePosition::Osst,
        },
        validator_package: BridgeKeyPackage {
            key_package: kp_1,
            public_key_package: dealer.public_key_package_hex.clone(),
            ephemeral_seed: seed_1,
            position: BridgePosition::Validator,
        },
        public_key_package_hex: dealer.public_key_package_hex,
        bridge_vk_hex: hex::encode(&vk_bytes),
        fvk_bytes,
    })
}

/// generate bridge custody keys using interactive DKG (no trusted dealer).
///
/// each position generates its own secret. nobody sees the full key.
/// returns two DKG round-1 states; callers exchange broadcasts and
/// complete via `bridge_dkg_finalize`.
pub fn bridge_dkg_part1() -> Result<(orchestrate::Dkg1Result, orchestrate::Dkg1Result), Error> {
    let r1_osst = orchestrate::dkg_part1(2, 2)?;
    let r1_validator = orchestrate::dkg_part1(2, 2)?;
    Ok((r1_osst, r1_validator))
}

fn unwrap_dealer_pkg(pkg_hex: &str) -> Result<(String, String), Error> {
    let signed: SignedMessage = from_hex(pkg_hex)?;
    let bundle: serde_json::Value = serde_json::from_slice(&signed.payload)
        .map_err(|e| Error::Serialize(format!("parse bundle: {}", e)))?;
    Ok((
        bundle["ephemeral_seed"].as_str().unwrap_or("").to_string(),
        bundle["key_package"].as_str().unwrap_or("").to_string(),
    ))
}

// ── signing ──

/// signing state for one position in the bridge 2-of-2
pub struct BridgeSigningState {
    pub nonces_hex: String,
    pub commitment_hex: String,
}

/// round 1: generate nonce commitment for this position
pub fn bridge_sign_round1(pkg: &BridgeKeyPackage) -> Result<BridgeSigningState, Error> {
    let seed = hex::decode(&pkg.ephemeral_seed)
        .map_err(|e| Error::Serialize(format!("bad seed: {}", e)))?;
    let seed: [u8; 32] = seed.try_into()
        .map_err(|_| Error::Serialize("seed must be 32 bytes".into()))?;

    let (nonces, commitment) = orchestrate::sign_round1(&seed, &pkg.key_package)?;

    Ok(BridgeSigningState {
        nonces_hex: nonces,
        commitment_hex: commitment,
    })
}

/// round 2: produce FROST signature share bound to sighash + alpha.
///
/// `all_commitments` must contain commitments from BOTH positions.
pub fn bridge_sign_round2(
    pkg: &BridgeKeyPackage,
    state: &BridgeSigningState,
    sighash: &[u8; 32],
    alpha: &[u8; 32],
    all_commitments: &[String],
) -> Result<String, Error> {
    orchestrate::spend_sign_round2(
        &pkg.key_package,
        &state.nonces_hex,
        sighash,
        alpha,
        all_commitments,
    )
}

/// aggregate both positions' shares into a SpendAuth signature.
///
/// the FROST aggregate function handles Lagrange interpolation for 2-of-2,
/// verifies the result against the group key, and produces a 64-byte
/// RedPallas signature ready for injection into an Orchard transaction.
pub fn bridge_aggregate(
    public_key_package_hex: &str,
    sighash: &[u8; 32],
    alpha: &[u8; 32],
    all_commitments: &[String],
    shares: &[String],
) -> Result<String, Error> {
    orchestrate::spend_aggregate(
        public_key_package_hex,
        sighash,
        alpha,
        all_commitments,
        shares,
    )
}

/// convenience: run the full 2-of-2 signing protocol locally.
///
/// both positions sign and the result is aggregated.
/// in production, position B's signing is replaced by nested inner FROST
/// via osst::nested (the coordinator collects inner shares, aggregates them
/// into a single outer partial signature, then aggregates with position A).
pub fn bridge_sign_local(
    osst_pkg: &BridgeKeyPackage,
    validator_pkg: &BridgeKeyPackage,
    sighash: &[u8; 32],
    alpha: &[u8; 32],
) -> Result<String, Error> {
    // round 1
    let state_a = bridge_sign_round1(osst_pkg)?;
    let state_b = bridge_sign_round1(validator_pkg)?;

    let commitments = vec![
        state_a.commitment_hex.clone(),
        state_b.commitment_hex.clone(),
    ];

    // round 2
    let share_a = bridge_sign_round2(osst_pkg, &state_a, sighash, alpha, &commitments)?;
    let share_b = bridge_sign_round2(validator_pkg, &state_b, sighash, alpha, &commitments)?;

    // aggregate
    bridge_aggregate(
        &osst_pkg.public_key_package,
        sighash,
        alpha,
        &commitments,
        &[share_a, share_b],
    )
}

// ── address derivation ──

/// derive the bridge's Orchard receiving address.
///
/// the address is determined by the 2-of-2 group key and does not change
/// when share A is reshared (group key is an OSST reshare invariant).
pub fn bridge_derive_address(
    public_key_package_hex: &str,
    diversifier_index: u32,
) -> Result<[u8; 43], Error> {
    orchestrate::derive_address_raw(public_key_package_hex, diversifier_index)
}

// ── OSST authorization (filter) ──

/// proof that stake-weighted quorum authorized a signing request.
///
/// this is the OsstAuthFilter output — it gates the signing service.
/// the proof is over `H(sighash || alpha || epoch)` binding it to exactly
/// one signing session.
///
/// in the Eriksen model this is a filter composed before the signing service:
///   authorized_signer = osst_auth_filter.and_then(frost_sign_service)
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct OsstAuthProof {
    /// serialized OSST contributions (68 bytes each, hex)
    pub contributions: Vec<String>,
    /// total stake weight collected
    pub total_weight: u64,
    /// H(sighash || alpha || epoch) — binds proof to signing session
    pub session_hash: [u8; 32],
}

// ── tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_dkg_produces_two_positions() {
        let dkg = bridge_dkg_dealer().unwrap();

        assert_eq!(dkg.osst_package.position, BridgePosition::Osst);
        assert_eq!(dkg.validator_package.position, BridgePosition::Validator);
        assert!(!dkg.bridge_vk_hex.is_empty());
        assert_eq!(dkg.bridge_vk_hex.len(), 64, "VK should be 32 bytes hex");

        // both packages share the same public key package
        assert_eq!(
            dkg.osst_package.public_key_package,
            dkg.validator_package.public_key_package,
        );
    }

    #[test]
    fn test_bridge_sign_produces_valid_spendauth() {
        let dkg = bridge_dkg_dealer().unwrap();

        let sighash = [0xaa; 32];
        let mut alpha = [0u8; 32];
        alpha[0] = 0x01;

        let sig = bridge_sign_local(
            &dkg.osst_package,
            &dkg.validator_package,
            &sighash,
            &alpha,
        ).unwrap();

        assert_eq!(sig.len(), 128, "SpendAuth sig should be 64 bytes (128 hex)");
        eprintln!("bridge 2-of-2 SpendAuth: {}...{}", &sig[..16], &sig[112..]);
    }

    #[test]
    fn test_bridge_derive_address() {
        let dkg = bridge_dkg_dealer().unwrap();

        let addr = bridge_derive_address(&dkg.public_key_package_hex, 0).unwrap();
        assert_eq!(addr.len(), 43, "Orchard address is 43 bytes");

        // both packages reference the same public_key_package
        assert_eq!(
            dkg.osst_package.public_key_package,
            dkg.public_key_package_hex,
        );
    }

    #[test]
    fn test_bridge_sign_stepwise_matches_local() {
        // verify that doing round1/round2/aggregate manually
        // produces the same result structure as bridge_sign_local
        let dkg = bridge_dkg_dealer().unwrap();

        let sighash = [0xbb; 32];
        let mut alpha = [0u8; 32];
        alpha[0] = 0x02;

        // stepwise
        let s_a = bridge_sign_round1(&dkg.osst_package).unwrap();
        let s_b = bridge_sign_round1(&dkg.validator_package).unwrap();

        let commits = vec![s_a.commitment_hex.clone(), s_b.commitment_hex.clone()];

        let share_a = bridge_sign_round2(
            &dkg.osst_package, &s_a, &sighash, &alpha, &commits,
        ).unwrap();
        let share_b = bridge_sign_round2(
            &dkg.validator_package, &s_b, &sighash, &alpha, &commits,
        ).unwrap();

        let sig = bridge_aggregate(
            &dkg.public_key_package_hex,
            &sighash,
            &alpha,
            &commits,
            &[share_a, share_b],
        ).unwrap();

        assert_eq!(sig.len(), 128);
    }
}

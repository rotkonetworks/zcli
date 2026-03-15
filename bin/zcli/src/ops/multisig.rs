// ops/multisig.rs — CLI commands for FROST multisig operations
//
// uses reddsa's FROST(Pallas, BLAKE2b-512) with rerandomization.
// no custom crypto — all operations delegate to the zcash foundation's
// audited frost-core / frost-rerandomized / reddsa crates.

use std::collections::BTreeMap;

use rand_core::OsRng;

use crate::error::Error;
use crate::frost::{self, dkg, keys, round1, round2, Identifier, RandomizedParams};

/// output of trusted dealer key generation
pub struct DealerResult {
    pub shares: Vec<(u16, String)>,
    pub public_key_package_hex: String,
}

/// output of DKG part1
pub struct Dkg1Result {
    pub secret_package_hex: String,
    pub broadcast_package_hex: String,
    pub identifier: u16,
}

/// output of DKG part2
pub struct Dkg2Result {
    pub secret_package_hex: String,
    pub peer_packages: Vec<(u16, String)>,
}

/// output of DKG part3
pub struct Dkg3Result {
    pub key_package_hex: String,
    pub public_key_package_hex: String,
}

/// generate key shares using a trusted dealer
pub fn dealer_keygen(min_signers: u16, max_signers: u16) -> Result<DealerResult, Error> {
    let (shares, pubkeys) = keys::generate_with_dealer(
        max_signers, min_signers, keys::IdentifierList::Default, OsRng,
    ).map_err(|e| Error::Other(format!("dealer keygen: {}", e)))?;

    let public_key_package_hex = frost::to_hex(&pubkeys)?;

    let mut share_list = Vec::new();
    for (id, share) in &shares {
        let key_pkg: keys::KeyPackage = share.clone().try_into()
            .map_err(|e: frost::redpallas::Error| Error::Other(format!("share verify: {}", e)))?;
        let idx = identifier_to_u16(id)?;
        share_list.push((idx, frost::to_hex(&key_pkg)?));
    }
    share_list.sort_by_key(|(idx, _)| *idx);

    Ok(DealerResult { shares: share_list, public_key_package_hex })
}

/// DKG round 1: generate and broadcast commitment
pub fn dkg_part1(index: u16, max_signers: u16, min_signers: u16) -> Result<Dkg1Result, Error> {
    let id = Identifier::try_from(index)
        .map_err(|e| Error::Other(format!("bad identifier: {}", e)))?;

    let (secret, package) = dkg::part1(id, max_signers, min_signers, OsRng)
        .map_err(|e| Error::Other(format!("dkg part1: {}", e)))?;

    Ok(Dkg1Result {
        secret_package_hex: frost::to_hex(&secret)?,
        broadcast_package_hex: frost::to_hex(&package)?,
        identifier: index,
    })
}

/// DKG round 2: process peer round1 packages
pub fn dkg_part2(secret_hex: &str, round1_packages_hex: &[(u16, String)]) -> Result<Dkg2Result, Error> {
    let secret: dkg::round1::SecretPackage = frost::from_hex(secret_hex)?;

    let mut round1_pkgs = BTreeMap::new();
    for (idx, hex_str) in round1_packages_hex {
        let id = Identifier::try_from(*idx)
            .map_err(|e| Error::Other(format!("bad identifier: {}", e)))?;
        let pkg: dkg::round1::Package = frost::from_hex(hex_str)?;
        round1_pkgs.insert(id, pkg);
    }

    let (secret2, round2_pkgs) = dkg::part2(secret, &round1_pkgs)
        .map_err(|e| Error::Other(format!("dkg part2: {}", e)))?;

    let peer_packages: Vec<(u16, String)> = round2_pkgs.iter()
        .map(|(id, pkg)| Ok((identifier_to_u16(id)?, frost::to_hex(pkg)?)))
        .collect::<Result<_, Error>>()?;

    Ok(Dkg2Result {
        secret_package_hex: frost::to_hex(&secret2)?,
        peer_packages,
    })
}

/// DKG round 3: finalize key generation
pub fn dkg_part3(
    secret_hex: &str,
    round1_packages_hex: &[(u16, String)],
    round2_packages_hex: &[(u16, String)],
) -> Result<Dkg3Result, Error> {
    let secret: dkg::round2::SecretPackage = frost::from_hex(secret_hex)?;

    let mut round1_pkgs = BTreeMap::new();
    for (idx, hex_str) in round1_packages_hex {
        let id = Identifier::try_from(*idx)
            .map_err(|e| Error::Other(format!("bad identifier: {}", e)))?;
        round1_pkgs.insert(id, frost::from_hex(hex_str)?);
    }

    let mut round2_pkgs = BTreeMap::new();
    for (idx, hex_str) in round2_packages_hex {
        let id = Identifier::try_from(*idx)
            .map_err(|e| Error::Other(format!("bad identifier: {}", e)))?;
        round2_pkgs.insert(id, frost::from_hex(hex_str)?);
    }

    let (key_pkg, pub_pkg) = dkg::part3(&secret, &round1_pkgs, &round2_pkgs)
        .map_err(|e| Error::Other(format!("dkg part3: {}", e)))?;

    Ok(Dkg3Result {
        key_package_hex: frost::to_hex(&key_pkg)?,
        public_key_package_hex: frost::to_hex(&pub_pkg)?,
    })
}

/// signing round 1: generate nonces + commitments
pub fn sign_round1(key_package_hex: &str) -> Result<(String, String), Error> {
    let key_pkg: keys::KeyPackage = frost::from_hex(key_package_hex)?;
    let (nonces, commitments) = round1::commit(key_pkg.signing_share(), &mut OsRng);
    Ok((frost::to_hex(&nonces)?, frost::to_hex(&commitments)?))
}

/// generate a randomizer for a signing session (coordinator does this once, shares with all signers)
pub fn generate_randomizer(
    _public_key_package_hex: &str,
    message: &[u8],
    all_commitments: &[(u16, String)],
) -> Result<String, Error> {
    let signing_package = build_signing_package(message, all_commitments)?;
    let randomizer = frost::Randomizer::new(OsRng, &signing_package)
        .map_err(|e| Error::Other(format!("randomizer: {}", e)))?;
    frost::to_hex(&randomizer)
}

/// signing round 2: produce signature share using coordinator's randomizer
pub fn sign_round2(
    key_package_hex: &str,
    nonces_hex: &str,
    message: &[u8],
    all_commitments: &[(u16, String)],
    randomizer_hex: &str,
) -> Result<String, Error> {
    let key_pkg: keys::KeyPackage = frost::from_hex(key_package_hex)?;
    let nonces: round1::SigningNonces = frost::from_hex(nonces_hex)?;
    let randomizer: frost::Randomizer = frost::from_hex(randomizer_hex)?;
    let signing_package = build_signing_package(message, all_commitments)?;

    let share = round2::sign(
        &signing_package,
        &nonces,
        &key_pkg,
        randomizer,
    ).map_err(|e| Error::Other(format!("sign round2: {}", e)))?;

    frost::to_hex(&share)
}

/// aggregate signature shares into a final rerandomized signature (coordinator)
pub fn aggregate_shares(
    public_key_package_hex: &str,
    message: &[u8],
    all_commitments: &[(u16, String)],
    all_shares: &[(u16, String)],
    randomizer_hex: &str,
) -> Result<String, Error> {
    let pubkeys: keys::PublicKeyPackage = frost::from_hex(public_key_package_hex)?;
    let randomizer: frost::Randomizer = frost::from_hex(randomizer_hex)?;
    let signing_package = build_signing_package(message, all_commitments)?;

    let randomized_params = RandomizedParams::from_randomizer(
        pubkeys.verifying_key(), randomizer,
    );

    let mut share_map = BTreeMap::new();
    for (idx, hex_str) in all_shares {
        let id = Identifier::try_from(*idx)
            .map_err(|e| Error::Other(format!("bad identifier {}: {}", idx, e)))?;
        share_map.insert(id, frost::from_hex(hex_str)?);
    }

    let signature = frost::aggregate(
        &signing_package, &share_map, &pubkeys, &randomized_params,
    ).map_err(|e| Error::Other(format!("aggregate: {}", e)))?;

    frost::to_hex(&signature)
}

fn build_signing_package(
    message: &[u8],
    all_commitments: &[(u16, String)],
) -> Result<frost::SigningPackage, Error> {
    let mut commitment_map = BTreeMap::new();
    for (idx, hex_str) in all_commitments {
        let id = Identifier::try_from(*idx)
            .map_err(|e| Error::Other(format!("bad identifier {}: {}", idx, e)))?;
        commitment_map.insert(id, frost::from_hex(hex_str)?);
    }
    Ok(frost::SigningPackage::new(commitment_map, message))
}

fn identifier_to_u16(id: &Identifier) -> Result<u16, Error> {
    let bytes = id.serialize();
    if bytes.len() < 2 {
        return Err(Error::Other("identifier too short".into()));
    }
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

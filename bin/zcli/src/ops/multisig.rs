// ops/multisig.rs — FROST multisig with ephemeral ed25519 identities
//
// privacy: each session generates a fresh ed25519 keypair.
// FROST identifiers derive from ephemeral pubkeys.
// long-lived SSH key only authenticates QUIC transport.
// sessions are unlinkable across signing rounds.

use std::collections::BTreeMap;

use rand_core::OsRng;

use crate::error::Error;
use crate::frost::{
    self, dkg, keys, round1, round2,
    Identifier, RandomizedParams, SignedMessage,
};

// ── dealer (trusted, generates everything) ──

pub struct DealerResult {
    pub packages: Vec<String>,
    pub public_key_package_hex: String,
}

/// trusted dealer: generates ephemeral identities + FROST shares for each participant.
/// each package is signed by the dealer's ephemeral key.
pub fn dealer_keygen(min_signers: u16, max_signers: u16) -> Result<DealerResult, Error> {
    let dealer_sk = frost::ephemeral_identity();

    let mut participants: Vec<(ed25519_consensus::SigningKey, Identifier)> = Vec::new();
    for _ in 0..max_signers {
        let sk = frost::ephemeral_identity();
        let id = frost::identifier_from_vk(&sk.verification_key())?;
        participants.push((sk, id));
    }

    let identifiers: Vec<Identifier> = participants.iter().map(|(_, id)| *id).collect();
    let (shares, pubkeys) = keys::generate_with_dealer(
        max_signers, min_signers,
        keys::IdentifierList::Custom(&identifiers),
        OsRng,
    ).map_err(|e| Error::Other(format!("dealer keygen: {}", e)))?;

    let public_key_package_hex = frost::to_hex(&pubkeys)?;

    let mut packages = Vec::new();
    for (sk, id) in &participants {
        let share = shares.get(id)
            .ok_or_else(|| Error::Other("missing share".into()))?;
        let key_pkg: keys::KeyPackage = share.clone().try_into()
            .map_err(|e: frost::redpallas::Error| Error::Other(format!("share verify: {}", e)))?;

        let bundle = serde_json::json!({
            "ephemeral_seed": hex::encode(sk.as_bytes()),
            "key_package": frost::to_hex(&key_pkg)?,
            "public_key_package": &public_key_package_hex,
        });
        let bundle_bytes = serde_json::to_vec(&bundle)
            .map_err(|e| Error::Other(format!("serialize: {}", e)))?;

        let signed = SignedMessage::sign(&dealer_sk, &bundle_bytes);
        packages.push(frost::to_hex(&signed)?);
    }

    Ok(DealerResult { packages, public_key_package_hex })
}

// ── DKG (interactive, no trusted dealer) ──

pub struct Dkg1Result {
    pub secret_hex: String,
    pub broadcast_hex: String,
}

/// DKG round 1: generate ephemeral identity + commitment
pub fn dkg_part1(max_signers: u16, min_signers: u16) -> Result<Dkg1Result, Error> {
    let sk = frost::ephemeral_identity();
    let vk = sk.verification_key();
    let id = frost::identifier_from_vk(&vk)?;

    let (secret, package) = dkg::part1(id, max_signers, min_signers, OsRng)
        .map_err(|e| Error::Other(format!("dkg part1: {}", e)))?;

    let payload = serde_json::to_vec(&frost::to_hex(&package)?)
        .map_err(|e| Error::Other(format!("serialize: {}", e)))?;
    let signed = SignedMessage::sign(&sk, &payload);

    let secret_state = serde_json::json!({
        "ephemeral_seed": hex::encode(sk.as_bytes()),
        "frost_secret": frost::to_hex(&secret)?,
    });

    Ok(Dkg1Result {
        secret_hex: frost::to_hex(&secret_state)?,
        broadcast_hex: frost::to_hex(&signed)?,
    })
}

pub struct Dkg2Result {
    pub secret_hex: String,
    pub peer_packages: Vec<String>,
}

/// DKG round 2: process signed broadcasts, produce signed per-peer packages
pub fn dkg_part2(secret_hex: &str, peer_broadcasts_hex: &[String]) -> Result<Dkg2Result, Error> {
    let secret_state: serde_json::Value = frost::from_hex(secret_hex)?;
    let sk = load_ephemeral_sk(&secret_state)?;
    let frost_secret: dkg::round1::SecretPackage = frost::from_hex(
        secret_state["frost_secret"].as_str()
            .ok_or_else(|| Error::Other("missing frost_secret".into()))?
    )?;

    let mut round1_pkgs = BTreeMap::new();
    for hex_str in peer_broadcasts_hex {
        let signed: SignedMessage = frost::from_hex(hex_str)?;
        let (vk, payload) = signed.verify()?;
        let pkg_hex: String = serde_json::from_slice(payload)
            .map_err(|e| Error::Other(format!("parse: {}", e)))?;
        round1_pkgs.insert(frost::identifier_from_vk(&vk)?, frost::from_hex(&pkg_hex)?);
    }

    let (secret2, round2_pkgs) = dkg::part2(frost_secret, &round1_pkgs)
        .map_err(|e| Error::Other(format!("dkg part2: {}", e)))?;

    let mut peer_packages = Vec::new();
    for (id, pkg) in &round2_pkgs {
        let payload = serde_json::to_vec(&serde_json::json!({
            "recipient": frost::to_hex(id)?,
            "package": frost::to_hex(pkg)?,
        })).map_err(|e| Error::Other(format!("serialize: {}", e)))?;
        peer_packages.push(frost::to_hex(&SignedMessage::sign(&sk, &payload))?);
    }

    let secret2_state = serde_json::json!({
        "ephemeral_seed": hex::encode(sk.as_bytes()),
        "frost_secret": frost::to_hex(&secret2)?,
    });

    Ok(Dkg2Result {
        secret_hex: frost::to_hex(&secret2_state)?,
        peer_packages,
    })
}

pub struct Dkg3Result {
    pub key_package_hex: String,
    pub public_key_package_hex: String,
    pub ephemeral_seed_hex: String,
}

/// DKG round 3: finalize. returns key package + ephemeral seed for signing.
pub fn dkg_part3(
    secret_hex: &str,
    round1_broadcasts_hex: &[String],
    round2_packages_hex: &[String],
) -> Result<Dkg3Result, Error> {
    let secret_state: serde_json::Value = frost::from_hex(secret_hex)?;
    let sk = load_ephemeral_sk(&secret_state)?;
    let frost_secret: dkg::round2::SecretPackage = frost::from_hex(
        secret_state["frost_secret"].as_str()
            .ok_or_else(|| Error::Other("missing frost_secret".into()))?
    )?;

    let mut round1_pkgs = BTreeMap::new();
    for hex_str in round1_broadcasts_hex {
        let signed: SignedMessage = frost::from_hex(hex_str)?;
        let (vk, payload) = signed.verify()?;
        let pkg_hex: String = serde_json::from_slice(payload)
            .map_err(|e| Error::Other(format!("parse: {}", e)))?;
        round1_pkgs.insert(frost::identifier_from_vk(&vk)?, frost::from_hex(&pkg_hex)?);
    }

    let mut round2_pkgs = BTreeMap::new();
    for hex_str in round2_packages_hex {
        let signed: SignedMessage = frost::from_hex(hex_str)?;
        let (vk, payload) = signed.verify()?;
        let inner: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|e| Error::Other(format!("parse: {}", e)))?;
        let pkg = frost::from_hex(
            inner["package"].as_str()
                .ok_or_else(|| Error::Other("missing package".into()))?
        )?;
        round2_pkgs.insert(frost::identifier_from_vk(&vk)?, pkg);
    }

    let (key_pkg, pub_pkg) = dkg::part3(&frost_secret, &round1_pkgs, &round2_pkgs)
        .map_err(|e| Error::Other(format!("dkg part3: {}", e)))?;

    Ok(Dkg3Result {
        key_package_hex: frost::to_hex(&key_pkg)?,
        public_key_package_hex: frost::to_hex(&pub_pkg)?,
        ephemeral_seed_hex: hex::encode(sk.as_bytes()),
    })
}

// ── signing ──

/// signing round 1: generate nonces + signed commitments using ephemeral key
pub fn sign_round1(
    ephemeral_seed: &[u8; 32],
    key_package_hex: &str,
) -> Result<(String, String), Error> {
    let sk = frost::signing_key_from_seed(ephemeral_seed);
    let key_pkg: keys::KeyPackage = frost::from_hex(key_package_hex)?;
    let (nonces, commitments) = round1::commit(key_pkg.signing_share(), &mut OsRng);

    let payload = serde_json::to_vec(&frost::to_hex(&commitments)?)
        .map_err(|e| Error::Other(format!("serialize: {}", e)))?;
    let signed = SignedMessage::sign(&sk, &payload);

    Ok((frost::to_hex(&nonces)?, frost::to_hex(&signed)?))
}

/// coordinator: generate signed randomizer using ephemeral key
pub fn generate_randomizer(
    ephemeral_seed: &[u8; 32],
    message: &[u8],
    signed_commitments_hex: &[String],
) -> Result<String, Error> {
    let sk = frost::signing_key_from_seed(ephemeral_seed);
    let signing_package = build_signing_package_from_signed(message, signed_commitments_hex)?;
    let randomizer = frost::Randomizer::new(OsRng, &signing_package)
        .map_err(|e| Error::Other(format!("randomizer: {}", e)))?;

    let payload = serde_json::to_vec(&frost::to_hex(&randomizer)?)
        .map_err(|e| Error::Other(format!("serialize: {}", e)))?;
    frost::to_hex(&SignedMessage::sign(&sk, &payload))
}

/// signing round 2: produce signed signature share
pub fn sign_round2(
    ephemeral_seed: &[u8; 32],
    key_package_hex: &str,
    nonces_hex: &str,
    message: &[u8],
    signed_commitments_hex: &[String],
    signed_randomizer_hex: &str,
) -> Result<String, Error> {
    let sk = frost::signing_key_from_seed(ephemeral_seed);
    let key_pkg: keys::KeyPackage = frost::from_hex(key_package_hex)?;
    let nonces: round1::SigningNonces = frost::from_hex(nonces_hex)?;

    let signed_rand: SignedMessage = frost::from_hex(signed_randomizer_hex)?;
    let (_, rand_payload) = signed_rand.verify()?;
    let randomizer: frost::Randomizer = frost::from_hex(
        &serde_json::from_slice::<String>(rand_payload)
            .map_err(|e| Error::Other(format!("parse randomizer: {}", e)))?
    )?;

    let signing_package = build_signing_package_from_signed(message, signed_commitments_hex)?;

    let share = round2::sign(&signing_package, &nonces, &key_pkg, randomizer)
        .map_err(|e| Error::Other(format!("sign round2: {}", e)))?;

    let payload = serde_json::to_vec(&frost::to_hex(&share)?)
        .map_err(|e| Error::Other(format!("serialize: {}", e)))?;
    frost::to_hex(&SignedMessage::sign(&sk, &payload))
}

/// coordinator: aggregate signed shares into final signature
pub fn aggregate_shares(
    public_key_package_hex: &str,
    message: &[u8],
    signed_commitments_hex: &[String],
    signed_shares_hex: &[String],
    signed_randomizer_hex: &str,
) -> Result<String, Error> {
    let pubkeys: keys::PublicKeyPackage = frost::from_hex(public_key_package_hex)?;

    let signed_rand: SignedMessage = frost::from_hex(signed_randomizer_hex)?;
    let (_, rand_payload) = signed_rand.verify()?;
    let randomizer: frost::Randomizer = frost::from_hex(
        &serde_json::from_slice::<String>(rand_payload)
            .map_err(|e| Error::Other(format!("parse randomizer: {}", e)))?
    )?;

    let signing_package = build_signing_package_from_signed(message, signed_commitments_hex)?;
    let randomized_params = RandomizedParams::from_randomizer(
        pubkeys.verifying_key(), randomizer,
    );

    let mut share_map = BTreeMap::new();
    for hex_str in signed_shares_hex {
        let signed: SignedMessage = frost::from_hex(hex_str)?;
        let (vk, payload) = signed.verify()?;
        let share = frost::from_hex(
            &serde_json::from_slice::<String>(payload)
                .map_err(|e| Error::Other(format!("parse share: {}", e)))?
        )?;
        share_map.insert(frost::identifier_from_vk(&vk)?, share);
    }

    let signature = frost::aggregate(
        &signing_package, &share_map, &pubkeys, &randomized_params,
    ).map_err(|e| Error::Other(format!("aggregate: {}", e)))?;

    frost::to_hex(&signature)
}

// ── helpers ──

fn load_ephemeral_sk(state: &serde_json::Value) -> Result<ed25519_consensus::SigningKey, Error> {
    let seed_hex = state["ephemeral_seed"].as_str()
        .ok_or_else(|| Error::Other("missing ephemeral_seed".into()))?;
    let seed = hex::decode(seed_hex)
        .map_err(|e| Error::Other(format!("bad seed: {}", e)))?;
    let seed: [u8; 32] = seed.try_into()
        .map_err(|_| Error::Other("seed must be 32 bytes".into()))?;
    Ok(frost::signing_key_from_seed(&seed))
}

fn build_signing_package_from_signed(
    message: &[u8],
    signed_commitments_hex: &[String],
) -> Result<frost::SigningPackage, Error> {
    let mut commitment_map = BTreeMap::new();
    for hex_str in signed_commitments_hex {
        let signed: SignedMessage = frost::from_hex(hex_str)?;
        let (vk, payload) = signed.verify()?;
        let commit = frost::from_hex(
            &serde_json::from_slice::<String>(payload)
                .map_err(|e| Error::Other(format!("parse commitment: {}", e)))?
        )?;
        commitment_map.insert(frost::identifier_from_vk(&vk)?, commit);
    }
    Ok(frost::SigningPackage::new(commitment_map, message))
}

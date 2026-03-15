// ops/multisig.rs — FROST multisig with ed25519-authenticated messages
//
// every round message is signed with the participant's ed25519 key.
// FROST identifiers are derived from ed25519 pubkeys (no numeric indices).
// all crypto: reddsa (ZF), frost-core (ZF), ed25519-consensus (Zebra).

use std::collections::BTreeMap;

use ed25519_consensus::SigningKey;
use rand_core::OsRng;

use crate::error::Error;
use crate::frost::{
    self, dkg, keys, round1, round2,
    Identifier, RandomizedParams, SignedMessage,
};

// ── DKG ──

pub struct DealerResult {
    /// signed key packages, one per participant (each signed by the dealer)
    pub packages: Vec<String>,
    pub public_key_package_hex: String,
}

/// trusted dealer keygen: generates ed25519 identity + FROST share for each participant
pub fn dealer_keygen(min_signers: u16, max_signers: u16) -> Result<DealerResult, Error> {
    let dealer_sk = SigningKey::new(OsRng);

    // generate identity keys for each participant
    let mut id_keys: Vec<(SigningKey, Identifier)> = Vec::new();
    for _ in 0..max_signers {
        let sk = SigningKey::new(OsRng);
        let vk = sk.verification_key();
        let id = frost::identifier_from_vk(&vk)?;
        id_keys.push((sk, id));
    }

    let identifiers: Vec<Identifier> = id_keys.iter().map(|(_, id)| *id).collect();
    let (shares, pubkeys) = keys::generate_with_dealer(
        max_signers, min_signers,
        keys::IdentifierList::Custom(&identifiers),
        OsRng,
    ).map_err(|e| Error::Other(format!("dealer keygen: {}", e)))?;

    let public_key_package_hex = frost::to_hex(&pubkeys)?;

    let mut packages = Vec::new();
    for (sk, id) in &id_keys {
        let share = shares.get(id)
            .ok_or_else(|| Error::Other("missing share for identifier".into()))?;
        let key_pkg: keys::KeyPackage = share.clone().try_into()
            .map_err(|e: frost::redpallas::Error| Error::Other(format!("share verify: {}", e)))?;

        // bundle: identity key seed + FROST key package + public key package
        let bundle = serde_json::json!({
            "identity_seed": hex::encode(sk.as_bytes()),
            "key_package": frost::to_hex(&key_pkg)?,
            "public_key_package": &public_key_package_hex,
        });
        let bundle_bytes = serde_json::to_vec(&bundle)
            .map_err(|e| Error::Other(format!("serialize bundle: {}", e)))?;

        // dealer signs the bundle so recipients can verify provenance
        let signed = SignedMessage::sign(&dealer_sk, &bundle_bytes);
        packages.push(frost::to_hex(&signed)?);
    }

    Ok(DealerResult { packages, public_key_package_hex })
}

// ── DKG (interactive, no trusted dealer) ──

pub struct Dkg1Result {
    /// secret state to keep for round 2 (hex)
    pub secret_hex: String,
    /// signed broadcast message (hex) — send to all participants
    pub broadcast_hex: String,
}

/// DKG round 1: generate commitment. uses SSH key as identity.
pub fn dkg_part1(
    identity_seed: &[u8; 32],
    max_signers: u16,
    min_signers: u16,
) -> Result<Dkg1Result, Error> {
    let sk = frost::signing_key_from_seed(identity_seed);
    let vk = sk.verification_key();
    let id = frost::identifier_from_vk(&vk)?;

    let (secret, package) = dkg::part1(id, max_signers, min_signers, OsRng)
        .map_err(|e| Error::Other(format!("dkg part1: {}", e)))?;

    // sign the broadcast package
    let payload = serde_json::to_vec(&frost::to_hex(&package)?)
        .map_err(|e| Error::Other(format!("serialize: {}", e)))?;
    let signed = SignedMessage::sign(&sk, &payload);

    // secret state includes identity seed for subsequent rounds
    let secret_state = serde_json::json!({
        "identity_seed": hex::encode(identity_seed),
        "frost_secret": frost::to_hex(&secret)?,
    });

    Ok(Dkg1Result {
        secret_hex: frost::to_hex(&secret_state)?,
        broadcast_hex: frost::to_hex(&signed)?,
    })
}

pub struct Dkg2Result {
    pub secret_hex: String,
    /// signed per-peer packages (hex), one per other participant
    pub peer_packages: Vec<String>,
}

/// DKG round 2: process peer round1 broadcasts, produce per-peer packages
pub fn dkg_part2(
    secret_hex: &str,
    peer_broadcasts_hex: &[String],
) -> Result<Dkg2Result, Error> {
    let secret_state: serde_json::Value = frost::from_hex(secret_hex)?;
    let identity_seed = hex::decode(
        secret_state["identity_seed"].as_str()
            .ok_or_else(|| Error::Other("missing identity_seed".into()))?
    ).map_err(|e| Error::Other(format!("bad seed hex: {}", e)))?;
    let identity_seed: [u8; 32] = identity_seed.try_into()
        .map_err(|_| Error::Other("identity seed must be 32 bytes".into()))?;
    let sk = frost::signing_key_from_seed(&identity_seed);

    let frost_secret_hex = secret_state["frost_secret"].as_str()
        .ok_or_else(|| Error::Other("missing frost_secret".into()))?;
    let frost_secret: dkg::round1::SecretPackage = frost::from_hex(frost_secret_hex)?;

    // verify and parse peer broadcasts
    let mut round1_pkgs = BTreeMap::new();
    for hex_str in peer_broadcasts_hex {
        let signed: SignedMessage = frost::from_hex(hex_str)?;
        let (vk, payload) = signed.verify()?;
        let pkg_hex: String = serde_json::from_slice(payload)
            .map_err(|e| Error::Other(format!("parse payload: {}", e)))?;
        let pkg: dkg::round1::Package = frost::from_hex(&pkg_hex)?;
        let id = frost::identifier_from_vk(&vk)?;
        round1_pkgs.insert(id, pkg);
    }

    let (secret2, round2_pkgs) = dkg::part2(frost_secret, &round1_pkgs)
        .map_err(|e| Error::Other(format!("dkg part2: {}", e)))?;

    // sign each per-peer package
    let mut peer_packages = Vec::new();
    for (id, pkg) in &round2_pkgs {
        let payload = serde_json::to_vec(&serde_json::json!({
            "recipient": frost::to_hex(id)?,
            "package": frost::to_hex(pkg)?,
        })).map_err(|e| Error::Other(format!("serialize: {}", e)))?;
        let signed = SignedMessage::sign(&sk, &payload);
        peer_packages.push(frost::to_hex(&signed)?);
    }

    let secret2_state = serde_json::json!({
        "identity_seed": hex::encode(identity_seed),
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
    pub identity_pubkey: String,
}

/// DKG round 3: finalize
pub fn dkg_part3(
    secret_hex: &str,
    round1_broadcasts_hex: &[String],
    round2_packages_hex: &[String],
) -> Result<Dkg3Result, Error> {
    let secret_state: serde_json::Value = frost::from_hex(secret_hex)?;
    let identity_seed = hex::decode(
        secret_state["identity_seed"].as_str()
            .ok_or_else(|| Error::Other("missing identity_seed".into()))?
    ).map_err(|e| Error::Other(format!("bad seed hex: {}", e)))?;
    let identity_seed: [u8; 32] = identity_seed.try_into()
        .map_err(|_| Error::Other("identity seed must be 32 bytes".into()))?;
    let sk = frost::signing_key_from_seed(&identity_seed);

    let frost_secret_hex = secret_state["frost_secret"].as_str()
        .ok_or_else(|| Error::Other("missing frost_secret".into()))?;
    let frost_secret: dkg::round2::SecretPackage = frost::from_hex(frost_secret_hex)?;

    // verify and parse round1 broadcasts
    let mut round1_pkgs = BTreeMap::new();
    for hex_str in round1_broadcasts_hex {
        let signed: SignedMessage = frost::from_hex(hex_str)?;
        let (vk, payload) = signed.verify()?;
        let pkg_hex: String = serde_json::from_slice(payload)
            .map_err(|e| Error::Other(format!("parse payload: {}", e)))?;
        round1_pkgs.insert(frost::identifier_from_vk(&vk)?, frost::from_hex(&pkg_hex)?);
    }

    // verify and parse round2 packages addressed to us
    let my_vk = sk.verification_key();
    let mut round2_pkgs = BTreeMap::new();
    for hex_str in round2_packages_hex {
        let signed: SignedMessage = frost::from_hex(hex_str)?;
        let (vk, payload) = signed.verify()?;
        let inner: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|e| Error::Other(format!("parse payload: {}", e)))?;
        let pkg: dkg::round2::Package = frost::from_hex(
            inner["package"].as_str()
                .ok_or_else(|| Error::Other("missing package field".into()))?
        )?;
        round2_pkgs.insert(frost::identifier_from_vk(&vk)?, pkg);
    }

    let (key_pkg, pub_pkg) = dkg::part3(&frost_secret, &round1_pkgs, &round2_pkgs)
        .map_err(|e| Error::Other(format!("dkg part3: {}", e)))?;

    Ok(Dkg3Result {
        key_package_hex: frost::to_hex(&key_pkg)?,
        public_key_package_hex: frost::to_hex(&pub_pkg)?,
        identity_pubkey: hex::encode(my_vk.to_bytes()),
    })
}

// ── signing ──

/// signing round 1: generate nonces + commitments, signed with identity key
pub fn sign_round1(
    identity_seed: &[u8; 32],
    key_package_hex: &str,
) -> Result<(String, String), Error> {
    let sk = frost::signing_key_from_seed(identity_seed);
    let key_pkg: keys::KeyPackage = frost::from_hex(key_package_hex)?;
    let (nonces, commitments) = round1::commit(key_pkg.signing_share(), &mut OsRng);

    // sign the commitments
    let payload = serde_json::to_vec(&frost::to_hex(&commitments)?)
        .map_err(|e| Error::Other(format!("serialize: {}", e)))?;
    let signed = SignedMessage::sign(&sk, &payload);

    Ok((frost::to_hex(&nonces)?, frost::to_hex(&signed)?))
}

/// generate randomizer (coordinator). signed with coordinator's identity.
pub fn generate_randomizer(
    identity_seed: &[u8; 32],
    message: &[u8],
    signed_commitments_hex: &[String],
) -> Result<String, Error> {
    let sk = frost::signing_key_from_seed(identity_seed);
    let signing_package = build_signing_package_from_signed(message, signed_commitments_hex)?;
    let randomizer = frost::Randomizer::new(OsRng, &signing_package)
        .map_err(|e| Error::Other(format!("randomizer: {}", e)))?;

    // sign the randomizer so signers can verify it came from coordinator
    let payload = serde_json::to_vec(&frost::to_hex(&randomizer)?)
        .map_err(|e| Error::Other(format!("serialize: {}", e)))?;
    let signed = SignedMessage::sign(&sk, &payload);
    frost::to_hex(&signed)
}

/// signing round 2: produce signature share
pub fn sign_round2(
    identity_seed: &[u8; 32],
    key_package_hex: &str,
    nonces_hex: &str,
    message: &[u8],
    signed_commitments_hex: &[String],
    signed_randomizer_hex: &str,
) -> Result<String, Error> {
    let sk = frost::signing_key_from_seed(identity_seed);
    let key_pkg: keys::KeyPackage = frost::from_hex(key_package_hex)?;
    let nonces: round1::SigningNonces = frost::from_hex(nonces_hex)?;

    // verify and extract randomizer
    let signed_rand: SignedMessage = frost::from_hex(signed_randomizer_hex)?;
    let (_coordinator_vk, rand_payload) = signed_rand.verify()?;
    let rand_hex: String = serde_json::from_slice(rand_payload)
        .map_err(|e| Error::Other(format!("parse randomizer: {}", e)))?;
    let randomizer: frost::Randomizer = frost::from_hex(&rand_hex)?;

    let signing_package = build_signing_package_from_signed(message, signed_commitments_hex)?;

    let share = round2::sign(&signing_package, &nonces, &key_pkg, randomizer)
        .map_err(|e| Error::Other(format!("sign round2: {}", e)))?;

    // sign our share
    let payload = serde_json::to_vec(&frost::to_hex(&share)?)
        .map_err(|e| Error::Other(format!("serialize: {}", e)))?;
    let signed = SignedMessage::sign(&sk, &payload);
    frost::to_hex(&signed)
}

/// aggregate shares into final signature (coordinator)
pub fn aggregate_shares(
    public_key_package_hex: &str,
    message: &[u8],
    signed_commitments_hex: &[String],
    signed_shares_hex: &[String],
    signed_randomizer_hex: &str,
) -> Result<String, Error> {
    let pubkeys: keys::PublicKeyPackage = frost::from_hex(public_key_package_hex)?;

    // verify and extract randomizer
    let signed_rand: SignedMessage = frost::from_hex(signed_randomizer_hex)?;
    let (_, rand_payload) = signed_rand.verify()?;
    let rand_hex: String = serde_json::from_slice(rand_payload)
        .map_err(|e| Error::Other(format!("parse randomizer: {}", e)))?;
    let randomizer: frost::Randomizer = frost::from_hex(&rand_hex)?;

    let signing_package = build_signing_package_from_signed(message, signed_commitments_hex)?;

    let randomized_params = RandomizedParams::from_randomizer(
        pubkeys.verifying_key(), randomizer,
    );

    // verify and extract shares
    let mut share_map = BTreeMap::new();
    for hex_str in signed_shares_hex {
        let signed: SignedMessage = frost::from_hex(hex_str)?;
        let (vk, payload) = signed.verify()?;
        let share_hex: String = serde_json::from_slice(payload)
            .map_err(|e| Error::Other(format!("parse share: {}", e)))?;
        let share: round2::SignatureShare = frost::from_hex(&share_hex)?;
        let id = frost::identifier_from_vk(&vk)?;
        share_map.insert(id, share);
    }

    let signature = frost::aggregate(
        &signing_package, &share_map, &pubkeys, &randomized_params,
    ).map_err(|e| Error::Other(format!("aggregate: {}", e)))?;

    frost::to_hex(&signature)
}

// ── helpers ──

fn build_signing_package_from_signed(
    message: &[u8],
    signed_commitments_hex: &[String],
) -> Result<frost::SigningPackage, Error> {
    let mut commitment_map = BTreeMap::new();
    for hex_str in signed_commitments_hex {
        let signed: SignedMessage = frost::from_hex(hex_str)?;
        let (vk, payload) = signed.verify()?;
        let commit_hex: String = serde_json::from_slice(payload)
            .map_err(|e| Error::Other(format!("parse commitment: {}", e)))?;
        let commit: round1::SigningCommitments = frost::from_hex(&commit_hex)?;
        let id = frost::identifier_from_vk(&vk)?;
        commitment_map.insert(id, commit);
    }
    Ok(frost::SigningPackage::new(commitment_map, message))
}

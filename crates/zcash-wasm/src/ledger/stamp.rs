//! Stamps the account derivations the Ledger Zcash app needs onto a PCZT.
//!
//! zafu's PCZT builders do not record ZIP-32 / BIP-32 derivations, but the
//! Ledger serializer requires one on every wallet-controlled shielded spend and
//! exactly one on every transparent input (the device re-derives the signing
//! key from it). This fills them in for a single Ledger account.
//!
//! - Every shielded spend (Orchard and Ironwood) that is not a true dummy gets
//!   `Zip32Derivation(fp, [32', 133', account'])`. That includes the zero-value
//!   spends orchard pairs with change when cross-address transfers are
//!   disabled: the account key authorizes them too.
//! - Every transparent input gets exactly one
//!   `Bip32Derivation(pubkey, fp, [44', 133', account', scope, address_index])`
//!   from the host-supplied path, after checking the pubkey really is the one
//!   the input's P2PKH script pays.
//!
//! An existing identical derivation is left alone and an existing different
//! one is refused, so stamping is idempotent: a PCZT that needs no change is
//! returned byte-for-byte.

use std::collections::BTreeMap;

use pczt::roles::{
    updater::Updater,
    verifier::{OrchardError, TransparentError, Verifier},
};
use sha2::{Digest, Sha256};
use zcash_script::script::Evaluable;
use zcash_transparent as transparent;

use super::protocol;

const HARDENED: u32 = 0x8000_0000;
const ZCASH_COIN_TYPE: u32 = 133;

/// Where the host derived one transparent input's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransparentPath {
    pub input_index: u32,
    /// 0 external, 1 internal (change), 2 ZIP-320 ephemeral.
    pub scope: u32,
    pub address_index: u32,
    /// Compressed secp256k1 pubkey at that path. The PCZT does not carry it,
    /// and it keys the BIP-32 derivation map.
    pub pubkey: [u8; 33],
}

#[derive(Debug)]
struct ShieldedSpend {
    is_dummy: bool,
    derivation: Option<([u8; 32], Vec<u32>)>,
}

#[derive(Debug)]
struct TransparentInputView {
    script_pubkey: Vec<u8>,
    derivations: BTreeMap<[u8; 33], ([u8; 32], Vec<u32>)>,
}

pub(crate) fn stamp_derivations(
    pczt_bytes: &[u8],
    seed_fingerprint: &[u8; 32],
    account_index: u32,
    transparent_paths: &[TransparentPath],
) -> Result<Vec<u8>, String> {
    if account_index >= HARDENED {
        return Err(protocol("Ledger account index must be below 2^31"));
    }
    let pczt =
        pczt::Pczt::parse(pczt_bytes).map_err(|e| protocol(format!("PCZT parse failed: {e:?}")))?;
    let (inputs, orchard, ironwood) = read_pczt(pczt.clone())?;

    let shielded_path = vec![
        HARDENED | 32,
        HARDENED | ZCASH_COIN_TYPE,
        HARDENED | account_index,
    ];
    let orchard_stamps = shielded_stamps("Orchard", &orchard, seed_fingerprint, &shielded_path)?;
    let ironwood_stamps = shielded_stamps("Ironwood", &ironwood, seed_fingerprint, &shielded_path)?;
    let transparent_stamps =
        transparent_stamps(&inputs, seed_fingerprint, account_index, transparent_paths)?;

    if orchard_stamps.is_empty() && ironwood_stamps.is_empty() && transparent_stamps.is_empty() {
        return Ok(pczt_bytes.to_vec());
    }

    let zip32 = || {
        orchard::pczt::Zip32Derivation::parse(*seed_fingerprint, shielded_path.clone())
            .map_err(|e| protocol(format!("ZIP-32 derivation is invalid: {e:?}")))
    };
    // Parse once up front so the updater closures below cannot fail on it.
    zip32()?;

    let mut updater = Updater::new(pczt);
    if !transparent_stamps.is_empty() {
        let stamps = transparent_stamps
            .into_iter()
            .map(|(index, pubkey, path)| {
                transparent::pczt::Bip32Derivation::parse(*seed_fingerprint, path)
                    .map(|derivation| (index, pubkey, derivation))
                    .map_err(|e| protocol(format!("BIP-32 derivation is invalid: {e:?}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        updater = updater
            .update_transparent_with(|mut bundle| {
                for (index, pubkey, derivation) in stamps {
                    bundle.update_input_with(index, |mut input| {
                        input.set_bip32_derivation(pubkey, derivation);
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .map_err(|e| protocol(format!("Stamp transparent derivations: {e:?}")))?;
    }
    if !orchard_stamps.is_empty() {
        updater = updater
            .update_orchard_with(|mut bundle| {
                for index in orchard_stamps {
                    bundle.update_action_with(index, |mut action| {
                        action.set_spend_zip32_derivation(zip32().expect("validated above"));
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .map_err(|e| protocol(format!("Stamp Orchard derivations: {e:?}")))?;
    }
    if !ironwood_stamps.is_empty() {
        updater = updater
            .update_ironwood_with(|mut bundle| {
                for index in ironwood_stamps {
                    bundle.update_action_with(index, |mut action| {
                        action.set_spend_zip32_derivation(zip32().expect("validated above"));
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .map_err(|e| protocol(format!("Stamp Ironwood derivations: {e:?}")))?;
    }
    updater
        .finish()
        .serialize()
        .map_err(|e| protocol(format!("Serialize stamped PCZT: {e:?}")))
}

/// `(input index, pubkey, BIP-32 path)` still to be stamped.
type TransparentStamp = (usize, [u8; 33], Vec<u32>);

type PcztView = (
    Vec<TransparentInputView>,
    Vec<ShieldedSpend>,
    Vec<ShieldedSpend>,
);

fn read_pczt(pczt: pczt::Pczt) -> Result<PcztView, String> {
    let is_v6 = *pczt.global().tx_version() >= 6;
    let mut inputs = Vec::new();
    let mut orchard = Vec::new();
    let mut ironwood = Vec::new();

    let verifier = Verifier::new(pczt)
        .with_transparent::<String, _>(|bundle| {
            inputs = bundle
                .inputs()
                .iter()
                .map(|input| TransparentInputView {
                    script_pubkey: input.script_pubkey().to_bytes(),
                    derivations: input
                        .bip32_derivation()
                        .iter()
                        .map(|(pubkey, derivation)| {
                            (
                                *pubkey,
                                (
                                    *derivation.seed_fingerprint(),
                                    derivation
                                        .derivation_path()
                                        .iter()
                                        .copied()
                                        .map(u32::from)
                                        .collect(),
                                ),
                            )
                        })
                        .collect(),
                })
                .collect();
            Ok(())
        })
        .map_err(|e| match e {
            TransparentError::Custom(message) => protocol(message),
            other => protocol(format!("Transparent bundle is invalid: {other:?}")),
        })?;
    let read_bundle = |bundle: &orchard::pczt::Bundle| {
        bundle
            .actions()
            .iter()
            .map(|action| ShieldedSpend {
                is_dummy: action.spend().dummy_sk().is_some(),
                derivation: action.spend().zip32_derivation().as_ref().map(|d| {
                    (
                        *d.seed_fingerprint(),
                        d.derivation_path().iter().map(|c| c.index()).collect(),
                    )
                }),
            })
            .collect::<Vec<_>>()
    };
    let orchard_error = |pool: &str, e: OrchardError<String>| match e {
        OrchardError::Custom(message) => protocol(message),
        other => protocol(format!("{pool} bundle is invalid: {other:?}")),
    };
    let verifier = verifier
        .with_orchard::<String, _>(|bundle| {
            orchard = read_bundle(bundle);
            Ok(())
        })
        .map_err(|e| orchard_error("Orchard", e))?;
    if is_v6 {
        verifier
            .with_ironwood::<String, _>(|bundle| {
                ironwood = read_bundle(bundle);
                Ok(())
            })
            .map_err(|e| orchard_error("Ironwood", e))?;
    }
    Ok((inputs, orchard, ironwood))
}

/// Action indices that need the account derivation stamped.
fn shielded_stamps(
    pool: &str,
    spends: &[ShieldedSpend],
    seed_fingerprint: &[u8; 32],
    path: &[u32],
) -> Result<Vec<usize>, String> {
    let mut stamps = Vec::new();
    for (index, spend) in spends.iter().enumerate() {
        if spend.is_dummy {
            continue;
        }
        match &spend.derivation {
            None => stamps.push(index),
            Some((fp, existing)) if fp == seed_fingerprint && existing == path => {}
            Some(_) => {
                return Err(protocol(format!(
                    "refusing to overwrite the different ZIP-32 derivation on {pool} action {index}"
                )))
            }
        }
    }
    Ok(stamps)
}

/// `(input index, pubkey, path)` for every input that needs its derivation.
fn transparent_stamps(
    inputs: &[TransparentInputView],
    seed_fingerprint: &[u8; 32],
    account_index: u32,
    paths: &[TransparentPath],
) -> Result<Vec<TransparentStamp>, String> {
    let mut by_input = BTreeMap::new();
    for entry in paths {
        let index = entry.input_index as usize;
        if index >= inputs.len() {
            return Err(protocol(format!(
                "transparent path for input {index}, but the PCZT has {} input(s)",
                inputs.len()
            )));
        }
        if by_input.insert(index, entry).is_some() {
            return Err(protocol(format!(
                "duplicate transparent path for input {index}"
            )));
        }
    }

    let mut stamps = Vec::new();
    for (index, input) in inputs.iter().enumerate() {
        let entry = by_input
            .get(&index)
            .ok_or_else(|| protocol(format!("missing transparent path for input {index}")))?;
        if entry.scope > 2 {
            return Err(protocol(format!(
                "transparent path for input {index} has scope {}; expected 0, 1 or 2",
                entry.scope
            )));
        }
        if entry.address_index >= HARDENED {
            return Err(protocol(format!(
                "transparent path for input {index} has a hardened address index"
            )));
        }
        secp256k1::PublicKey::from_slice(&entry.pubkey).map_err(|_| {
            protocol(format!(
                "transparent path for input {index} has an invalid secp256k1 pubkey"
            ))
        })?;
        if input.script_pubkey != p2pkh_script(&entry.pubkey) {
            return Err(protocol(format!(
                "transparent input {index} is not a P2PKH output paying the supplied pubkey"
            )));
        }

        let path = vec![
            HARDENED | 44,
            HARDENED | ZCASH_COIN_TYPE,
            HARDENED | account_index,
            entry.scope,
            entry.address_index,
        ];
        let wanted = (*seed_fingerprint, path.clone());
        match input.derivations.len() {
            0 => stamps.push((index, entry.pubkey, path)),
            1 if input.derivations.get(&entry.pubkey) == Some(&wanted) => {}
            _ => {
                return Err(protocol(format!(
                    "refusing to overwrite the different BIP-32 derivation on transparent input {index}"
                )))
            }
        }
    }
    Ok(stamps)
}

fn p2pkh_script(pubkey: &[u8; 33]) -> Vec<u8> {
    use ripemd::Ripemd160;
    let hash = Ripemd160::digest(Sha256::digest(pubkey));
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&hash);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

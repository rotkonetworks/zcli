// Portions adapted from vizor-wallet (chainapsis/vizor-wallet, Apache-2.0), modified.
// See crates/zcash-wasm/LICENSE-APACHE-vizor.
//
//! End-to-end protocol tests: build a real PCZT, plan the APDU exchange,
//! answer it the way a Ledger would (signatures made locally with the same
//! keys), and finalize.

use super::*;
use orchard::{
    builder::{Builder as OrchardBuilder, BundleType},
    bundle::BundleVersion,
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Note,
};
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, updater::Updater, verifier::Verifier,
};
use transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztParts, PcztResult},
    fees::zip317,
    TxVersion,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters},
    value::Zatoshis,
};

const SPEND_VALUE: u64 = 100_000;
/// ZIP-302 "no memo".
const NO_MEMO: [u8; 512] = {
    let mut memo = [0; 512];
    memo[0] = 0xf6;
    memo
};

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct PreNu6_3TestNetwork;

impl Parameters for PreNu6_3TestNetwork {
    fn network_type(&self) -> NetworkType {
        NetworkType::Test
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Nu6_3 => None,
            _ => Some(BlockHeight::from_u32(1)),
        }
    }
}

fn secp_key() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
    let sk = secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
    let pk = sk.public_key(&secp256k1::Secp256k1::new());
    (sk, pk)
}

/// A transparent-only PCZT with `inputs` P2PKH inputs and `outputs` outputs,
/// each input carrying exactly one BIP-32 derivation (as zafu must stamp).
fn transparent_pczt_n(inputs: usize, outputs: usize) -> Vec<u8> {
    let (_, pubkey) = secp_key();
    let pubkey_bytes = pubkey.serialize();
    let address = TransparentAddress::from_pubkey(&pubkey);

    let mut builder = Builder::new(
        PreNu6_3TestNetwork,
        100.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    for index in 0..inputs {
        builder
            .add_transparent_p2pkh_input(
                pubkey,
                OutPoint::new([1; 32], index as u32),
                TxOut::new(Zatoshis::const_from_u64(1_000_000), address.script().into()),
            )
            .unwrap();
    }
    // Balance exactly under ZIP-317 so the builder needs no change output.
    let fee = 5_000 * inputs.max(outputs).max(2) as u64;
    let total = inputs as u64 * 1_000_000 - fee;
    for index in 0..outputs {
        let value = if index == 0 {
            total - (outputs as u64 - 1) * 10_000
        } else {
            10_000
        };
        builder
            .add_transparent_output(&address, Zatoshis::const_from_u64(value))
            .unwrap();
    }
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(crate::OsRng10, &zip317::FeeRule::standard())
        .unwrap();
    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io()
        .unwrap();

    let derivation = || {
        transparent::pczt::Bip32Derivation::parse(
            [0x22; 32],
            vec![0x8000_002c, 0x8000_0001, 0x8000_0000, 0, 0],
        )
        .unwrap()
    };
    Updater::new(pczt)
        .update_transparent_with(|mut bundle| {
            for index in 0..inputs {
                bundle.update_input_with(index, |mut input| {
                    input.set_bip32_derivation(pubkey_bytes, derivation());
                    Ok(())
                })?;
            }
            Ok(())
        })
        .unwrap()
        .finish()
        .serialize()
        .unwrap()
}

fn transparent_pczt() -> Vec<u8> {
    transparent_pczt_n(1, 1)
}

fn spending_key(byte: u8) -> SpendingKey {
    SpendingKey::from_bytes([byte; 32]).unwrap()
}

fn derivation() -> orchard::pczt::Zip32Derivation {
    orchard::pczt::Zip32Derivation::parse([0x22; 32], vec![0x8000_0020, 0x8000_0085, 0x8000_0000])
        .unwrap()
}

/// One shielded bundle of `version`: optionally one real spend of
/// [`SPEND_VALUE`] (stamped with its ZIP-32 derivation), plus `outputs`.
fn shielded_bundle(
    version: BundleVersion,
    sk: &SpendingKey,
    spend: bool,
    outputs: &[u64],
) -> orchard::pczt::Bundle {
    let fvk = FullViewingKey::from(sk);
    let rho = Rho::from_bytes(&[1; 32]).into_option().unwrap();
    let rseed = (0u8..=255)
        .find_map(|byte| RandomSeed::from_bytes([byte; 32], &rho).into_option())
        .unwrap();
    let note = Note::from_parts(
        fvk.address_at(0u32, Scope::External),
        NoteValue::from_raw(SPEND_VALUE),
        rho,
        rseed,
        version.note_version(),
    )
    .into_option()
    .unwrap();
    let path = MerklePath::from_parts(0, [MerkleHashOrchard::from_bytes(&[0; 32]).unwrap(); 32]);
    let mut builder = OrchardBuilder::new(
        BundleType::UNPADDED,
        version,
        version.default_flags(),
        path.root(note.commitment().into()),
    )
    .unwrap();
    if spend {
        builder.add_spend(fvk.clone(), note, path).unwrap();
    }
    for value in outputs {
        if version.default_flags().cross_address_enabled() {
            builder
                .add_output(
                    Some(fvk.to_ovk(Scope::External)),
                    fvk.address_at(1u32, Scope::External),
                    NoteValue::from_raw(*value),
                    NO_MEMO,
                )
                .unwrap();
        } else {
            builder
                .add_change_output(
                    fvk.clone(),
                    Some(fvk.to_ovk(Scope::External)),
                    fvk.address_at(1u32, Scope::External),
                    NoteValue::from_raw(*value),
                    [0; 512],
                )
                .unwrap();
        }
    }
    let (mut bundle, metadata) = builder.build_for_pczt(crate::OsRng10).unwrap();
    if spend {
        bundle
            .update_with(|mut bundle| {
                bundle.update_action_with(metadata.spend_action_index(0).unwrap(), |mut action| {
                    action.set_spend_zip32_derivation(derivation());
                    Ok(())
                })
            })
            .unwrap();
    }
    bundle
}

fn shielded_pczt(
    branch: BranchId,
    orchard: Option<orchard::pczt::Bundle>,
    ironwood: Option<orchard::pczt::Bundle>,
) -> Vec<u8> {
    let pczt = Creator::build_from_parts(PcztParts {
        params: MainNetwork,
        version: TxVersion::suggested_for_branch(branch),
        consensus_branch_id: branch,
        lock_time: 0,
        expiry_height: BlockHeight::from_u32(0),
        transparent: None,
        sapling: None,
        orchard,
        ironwood,
    })
    .unwrap();
    IoFinalizer::new(pczt)
        .finalize_io()
        .unwrap()
        .serialize()
        .unwrap()
}

fn orchard_send_pczt(outputs: &[u64]) -> Vec<u8> {
    let sk = spending_key(0x43);
    shielded_pczt(
        BranchId::Nu6_2,
        Some(shielded_bundle(
            BundleVersion::orchard_v2(),
            &sk,
            true,
            outputs,
        )),
        None,
    )
}

fn ironwood_send_pczt() -> Vec<u8> {
    let sk = spending_key(0x43);
    shielded_pczt(
        BranchId::Nu6_3,
        None,
        Some(shielded_bundle(
            BundleVersion::ironwood_v3(),
            &sk,
            true,
            &[90_000],
        )),
    )
}

/// What a Ledger holding `sk` (and the transparent key) would answer to
/// `plan`: empty payloads for PCZT packets, then signatures.
fn device_responses(pczt_bytes: &[u8], plan: &[ApduCommand], sk: &SpendingKey) -> Vec<Vec<u8>> {
    let ask = SpendAuthorizingKey::from(sk);
    let pczt = pczt::Pczt::parse(pczt_bytes).unwrap();
    let mut signer = Signer::new(pczt.clone()).unwrap();
    for command in plan {
        match command.ins {
            0x57 => signer.sign_orchard(command.p2 as usize, &ask).unwrap(),
            0x59 => signer.sign_ironwood(command.p2 as usize, &ask).unwrap(),
            _ => {}
        }
    }
    let signed = signer.finish();
    let shielded = pczt::roles::signer::extract_orchard_spend_auth_signatures(&signed);
    let transparent_sighash = |index: usize| {
        Signer::new(pczt.clone())
            .unwrap()
            .transparent_sighash(index)
            .unwrap()
    };

    plan.iter()
        .map(|command| match command.ins {
            0x55 => {
                let (sk, _) = secp_key();
                let secp = secp256k1::Secp256k1::new();
                let message =
                    secp256k1::Message::from_digest(transparent_sighash(command.p2 as usize));
                let mut der = secp.sign_ecdsa(&message, &sk).serialize_der().to_vec();
                der[0] |= 1; // Ledger's Y-parity metadata bit
                der.push(0x01);
                der
            }
            0x57 | 0x59 => {
                let pool = if command.ins == 0x57 {
                    ValuePool::Orchard
                } else {
                    ValuePool::Ironwood
                };
                shielded
                    .iter()
                    .find(|sig| {
                        sig.value_pool() == pool && sig.action_index() == command.p2 as usize
                    })
                    .unwrap()
                    .signature()
                    .to_vec()
            }
            _ => Vec::new(),
        })
        .collect()
}

fn shielded_sig_count(pczt_bytes: &[u8]) -> usize {
    let pczt = pczt::Pczt::parse(pczt_bytes).unwrap();
    pczt.orchard()
        .actions()
        .iter()
        .chain(pczt.ironwood().actions())
        .filter(|action| action.spend().spend_auth_sig().is_some())
        .count()
}

// ---------------------------------------------------------------------------
// round trips
// ---------------------------------------------------------------------------

#[test]
fn transparent_round_trip_applies_and_validates_the_signature() {
    let pczt_bytes = transparent_pczt();
    let plan = pczt_signing_plan(&pczt_bytes, false).unwrap();
    assert_eq!(plan.first().map(|c| c.ins), Some(0x52));
    assert_eq!(plan.last().map(|c| (c.ins, c.p2)), Some((0x55, 0)));
    assert!(plan[..plan.len() - 1]
        .iter()
        .all(|command| matches!(command.ins, 0x52 | 0x53 | 0x54 | 0x56)));

    let responses = device_responses(&pczt_bytes, &plan, &spending_key(1));
    let signed = finalize_pczt_signing(&pczt_bytes, &responses).unwrap();

    let (_, pubkey) = secp_key();
    let mut stored = None;
    Verifier::new(pczt::Pczt::parse(&signed).unwrap())
        .with_transparent::<String, _>(|bundle| {
            stored = bundle.inputs()[0]
                .partial_signatures()
                .get(&pubkey.serialize())
                .cloned();
            Ok(())
        })
        .unwrap();
    assert_eq!(
        stored.expect("transparent signature is stored").last(),
        Some(&1)
    );
}

#[test]
fn orchard_round_trip_applies_every_spend_authorization() {
    let sk = spending_key(0x43);
    let pczt_bytes = orchard_send_pczt(&[90_000]);
    let plan = pczt_signing_plan(&pczt_bytes, false).unwrap();
    let requests: Vec<_> = plan.iter().filter(|c| c.ins == 0x57).collect();
    assert_eq!(requests.len(), 1);
    assert!(
        plan.iter().all(|c| c.ins != 0x58),
        "v5 has no Ironwood command"
    );

    let before = shielded_sig_count(&pczt_bytes);
    let signed =
        finalize_pczt_signing(&pczt_bytes, &device_responses(&pczt_bytes, &plan, &sk)).unwrap();
    assert_eq!(shielded_sig_count(&signed), before + 1);
}

#[test]
fn ironwood_round_trip_applies_every_spend_authorization() {
    let sk = spending_key(0x43);
    let pczt_bytes = ironwood_send_pczt();
    let plan = pczt_signing_plan(&pczt_bytes, true).unwrap();
    let ins: Vec<u8> = plan.iter().map(|c| c.ins).collect();
    assert!(ins.contains(&0x58), "v6 streams the Ironwood bundle");
    assert_eq!(ins.iter().filter(|i| **i == 0x59).count(), 1);
    // The final PCZT packet (the one that triggers review) carries p2 = 1.
    let last_packet = plan.iter().rposition(|c| c.ins == 0x58).unwrap();
    assert_eq!(plan[last_packet].p2, 1);

    let before = shielded_sig_count(&pczt_bytes);
    let signed =
        finalize_pczt_signing(&pczt_bytes, &device_responses(&pczt_bytes, &plan, &sk)).unwrap();
    assert_eq!(shielded_sig_count(&signed), before + 1);
}

#[test]
fn a_signature_from_another_key_is_a_signature_mismatch() {
    let pczt_bytes = ironwood_send_pczt();
    // Same shape, but spent by another key: a different Ledger's answers.
    let other_sk = spending_key(0x44);
    let other = shielded_pczt(
        BranchId::Nu6_3,
        None,
        Some(shielded_bundle(
            BundleVersion::ironwood_v3(),
            &other_sk,
            true,
            &[90_000],
        )),
    );
    let other_plan = pczt_signing_plan(&other, true).unwrap();
    let responses = device_responses(&other, &other_plan, &other_sk);
    assert_eq!(
        responses.len(),
        pczt_signing_plan(&pczt_bytes, true).unwrap().len()
    );
    let error = finalize_pczt_signing(&pczt_bytes, &responses).unwrap_err();
    assert!(
        error.starts_with("protocol_error: ledger_signature_mismatch: "),
        "{error}"
    );
}

#[test]
fn a_corrupted_shielded_signature_is_rejected() {
    let sk = spending_key(0x43);
    let pczt_bytes = orchard_send_pczt(&[90_000]);
    let plan = pczt_signing_plan(&pczt_bytes, true).unwrap();
    let mut responses = device_responses(&pczt_bytes, &plan, &sk);
    responses.last_mut().unwrap()[40] ^= 0x01;
    let error = finalize_pczt_signing(&pczt_bytes, &responses).unwrap_err();
    assert!(error.starts_with("protocol_error: "), "{error}");
}

#[test]
fn a_corrupted_transparent_signature_is_a_signature_mismatch() {
    let pczt_bytes = transparent_pczt();
    let plan = pczt_signing_plan(&pczt_bytes, true).unwrap();
    let mut responses = device_responses(&pczt_bytes, &plan, &spending_key(1));
    // Flip a byte inside the r value of the DER signature (keeps DER valid).
    responses.last_mut().unwrap()[10] ^= 0x01;
    let error = finalize_pczt_signing(&pczt_bytes, &responses).unwrap_err();
    assert!(
        error.starts_with("protocol_error: ledger_signature_mismatch: "),
        "{error}"
    );
}

#[test]
fn orchard_v3_change_pairs_are_signed_by_the_device_too() {
    // Post-NU6.3 Orchard disables cross-address transfers, so orchard pairs the
    // change output with a zero-value spend the WALLET controls. The IO
    // Finalizer cannot sign it; the Ledger must, or the tx never completes.
    let sk = spending_key(0x43);
    let pczt_bytes = shielded_pczt(
        BranchId::Nu6_3,
        Some(shielded_bundle(
            BundleVersion::orchard_v3(),
            &sk,
            true,
            &[90_000],
        )),
        None,
    );
    let plan = pczt_signing_plan(&pczt_bytes, true).unwrap();
    assert_eq!(plan.iter().filter(|c| c.ins == 0x57).count(), 2);
    let signed =
        finalize_pczt_signing(&pczt_bytes, &device_responses(&pczt_bytes, &plan, &sk)).unwrap();
    let pczt = pczt::Pczt::parse(&signed).unwrap();
    assert!(pczt
        .orchard()
        .actions()
        .iter()
        .all(|action| action.spend().spend_auth_sig().is_some()));
}

#[test]
fn response_shape_is_validated() {
    let sk = spending_key(0x43);
    let pczt_bytes = orchard_send_pczt(&[90_000]);
    let plan = pczt_signing_plan(&pczt_bytes, true).unwrap();
    let good = device_responses(&pczt_bytes, &plan, &sk);

    let mut short = good.clone();
    short.pop();
    assert!(finalize_pczt_signing(&pczt_bytes, &short)
        .unwrap_err()
        .contains("response(s); expected"));

    let mut long = good.clone();
    long.push(Vec::new());
    assert!(finalize_pczt_signing(&pczt_bytes, &long)
        .unwrap_err()
        .contains("response(s); expected"));

    let mut chatty = good.clone();
    chatty[0] = vec![1];
    assert!(finalize_pczt_signing(&pczt_bytes, &chatty)
        .unwrap_err()
        .contains("unexpected response data"));

    let mut truncated = good.clone();
    truncated.last_mut().unwrap().pop();
    assert!(finalize_pczt_signing(&pczt_bytes, &truncated)
        .unwrap_err()
        .contains("expected 64"));

    let mut zero = good;
    *zero.last_mut().unwrap() = vec![0; 64];
    assert!(finalize_pczt_signing(&pczt_bytes, &zero)
        .unwrap_err()
        .contains("all-zero"));
}

#[test]
fn transparent_response_shape_is_validated() {
    let pczt_bytes = transparent_pczt();
    let plan = pczt_signing_plan(&pczt_bytes, true).unwrap();
    let good = device_responses(&pczt_bytes, &plan, &spending_key(1));

    let mut wrong_sighash = good.clone();
    *wrong_sighash.last_mut().unwrap().last_mut().unwrap() = 0x02;
    assert!(finalize_pczt_signing(&pczt_bytes, &wrong_sighash)
        .unwrap_err()
        .contains("used sighash type"));

    let mut bad_tag = good.clone();
    bad_tag.last_mut().unwrap()[0] = 0x31 ^ 0x10;
    assert!(finalize_pczt_signing(&pczt_bytes, &bad_tag)
        .unwrap_err()
        .contains("DER sequence tag"));

    let mut bad_len = good;
    *bad_len.last_mut().unwrap() = vec![0x30; 5];
    assert!(finalize_pczt_signing(&pczt_bytes, &bad_len)
        .unwrap_err()
        .contains("expected DER plus sighash type"));
}

#[test]
fn decodes_ordered_transparent_orchard_and_ironwood_responses() {
    let command = |ins, p2, data| ApduCommand {
        cla: ZCASH_CLA,
        ins,
        p1: 0,
        p2,
        data,
    };
    let commands = vec![
        command(0x52, 0, vec![1]),
        command(0x55, 0, vec![]),
        command(0x57, 2, vec![]),
        command(0x59, 3, vec![]),
    ];
    let requests = vec![
        SignatureRequest::Transparent { input_index: 0 },
        SignatureRequest::Shielded {
            pool: ValuePool::Orchard,
            action_index: 2,
            instruction: 0x57,
        },
        SignatureRequest::Shielded {
            pool: ValuePool::Ironwood,
            action_index: 3,
            instruction: 0x59,
        },
    ];
    let der = vec![0x30, 0x06, 0x02, 0x01, 1, 0x02, 0x01, 1, 1];
    let (transparent, shielded) = decode_signing_responses(
        &commands,
        &requests,
        &[vec![], der, vec![0x11; 64], vec![0x22; 64]],
    )
    .unwrap();

    assert_eq!(transparent.len(), 1);
    assert_eq!(transparent[0].sighash_type, 1);
    assert_eq!(shielded.len(), 2);
    assert_eq!(shielded[0].value_pool(), ValuePool::Orchard);
    assert_eq!(shielded[0].action_index(), 2);
    assert_eq!(shielded[1].value_pool(), ValuePool::Ironwood);
    assert_eq!(shielded[1].action_index(), 3);
}

// ---------------------------------------------------------------------------
// limits and release gate
// ---------------------------------------------------------------------------

#[test]
fn transparent_input_limit_is_enforced_before_the_device() {
    assert!(validate_pczt(&transparent_pczt_n(MAX_TRANSPARENT_INPUTS, 1)).is_ok());
    let over = transparent_pczt_n(MAX_TRANSPARENT_INPUTS + 1, 1);
    for error in [
        validate_pczt(&over).unwrap_err(),
        pczt_signing_plan(&over, true).unwrap_err(),
    ] {
        assert!(error.starts_with("unsupported_transaction: "), "{error}");
        assert!(error.contains("at most 32 transparent inputs"), "{error}");
    }
}

#[test]
fn transparent_output_limit_is_enforced_before_the_device() {
    assert!(validate_pczt(&transparent_pczt_n(1, MAX_TRANSPARENT_OUTPUTS)).is_ok());
    let error = validate_pczt(&transparent_pczt_n(1, MAX_TRANSPARENT_OUTPUTS + 1)).unwrap_err();
    assert!(error.starts_with("unsupported_transaction: "), "{error}");
    assert!(error.contains("at most 10 transparent outputs"), "{error}");
}

#[test]
fn shielded_action_limit_is_enforced_per_pool() {
    assert!(validate_pczt(&orchard_send_pczt(&[1_000; MAX_SHIELDED_ACTIONS])).is_ok());
    let error = validate_pczt(&orchard_send_pczt(&[1_000; MAX_SHIELDED_ACTIONS + 1])).unwrap_err();
    assert!(error.starts_with("unsupported_transaction: "), "{error}");
    assert!(error.contains("at most 32 shielded actions"), "{error}");
}

#[test]
fn legacy_orchard_into_ironwood_is_refused() {
    let sk = spending_key(0x43);
    let legacy = shielded_pczt(
        BranchId::Nu6_3,
        Some(shielded_bundle(BundleVersion::orchard_v3(), &sk, true, &[])),
        Some(shielded_bundle(
            BundleVersion::ironwood_v3(),
            &sk,
            false,
            &[90_000],
        )),
    );
    for error in [
        validate_pczt(&legacy).unwrap_err(),
        pczt_signing_plan(&legacy, true).unwrap_err(),
    ] {
        assert!(
            error.starts_with(
                "unsupported_transaction: ledger_legacy_orchard_recovery_unsupported: "
            ),
            "{error}"
        );
    }
    // Ironwood-only sends are unaffected.
    assert!(validate_pczt(&ironwood_send_pczt()).is_ok());
}

#[test]
fn release_gate_blocks_only_legacy_orchard_to_ironwood_recovery() {
    assert!(require_legacy_orchard_recovery_support(true, true)
        .unwrap_err()
        .contains("ledger_legacy_orchard_recovery_unsupported"));
    assert_eq!(require_legacy_orchard_recovery_support(true, false), Ok(()));
    assert_eq!(require_legacy_orchard_recovery_support(false, true), Ok(()));
    assert_eq!(
        require_legacy_orchard_recovery_support(false, false),
        Ok(())
    );
}

#[test]
fn a_pczt_that_was_not_io_finalized_is_refused_before_the_device() {
    let sk = spending_key(0x43);
    // Two outputs + one spend -> one dummy spend the IO Finalizer would sign.
    let pczt = Creator::build_from_parts(PcztParts {
        params: MainNetwork,
        version: TxVersion::suggested_for_branch(BranchId::Nu6_2),
        consensus_branch_id: BranchId::Nu6_2,
        lock_time: 0,
        expiry_height: BlockHeight::from_u32(0),
        transparent: None,
        sapling: None,
        orchard: Some(shielded_bundle(
            BundleVersion::orchard_v2(),
            &sk,
            true,
            &[40_000, 50_000],
        )),
        ironwood: None,
    })
    .unwrap()
    .serialize()
    .unwrap();
    let error = pczt_signing_plan(&pczt, true).unwrap_err();
    assert!(error.starts_with("unsupported_transaction: "), "{error}");
    assert!(error.contains("IO-finalized"), "{error}");
}

#[test]
fn memo_hash_gate_reports_app_too_old() {
    let pczt = orchard_send_pczt(&[90_000]);
    // A no-memo (0xF6) output does not need the memo-hash path.
    assert!(pczt_signing_plan(&pczt, false).is_ok());
    assert_eq!(
        plan_error(LEDGER_MEMO_HASH_UNSUPPORTED.to_string()),
        format!("app_too_old: {LEDGER_MEMO_HASH_UNSUPPORTED}")
    );
}

#[test]
fn garbage_is_an_unsupported_transaction_not_a_panic() {
    assert!(validate_pczt(b"PCZT")
        .unwrap_err()
        .starts_with("unsupported_transaction: "));
    assert!(finalize_pczt_signing(b"", &[])
        .unwrap_err()
        .starts_with("unsupported_transaction: "));
}

// ---------------------------------------------------------------------------
// UFVK
// ---------------------------------------------------------------------------

fn mainnet_ufvk() -> String {
    zcash_keys::keys::UnifiedSpendingKey::from_seed(
        &MainNetwork,
        &[0x5a; 32],
        zip32::AccountId::ZERO,
    )
    .unwrap()
    .to_unified_full_viewing_key()
    .encode(&MainNetwork)
}

fn ufvk_chunks(ufvk: &str, chunk: usize) -> Vec<Vec<u8>> {
    let mut bytes = (ufvk.len() as u16).to_be_bytes().to_vec();
    bytes.extend_from_slice(ufvk.as_bytes());
    bytes.chunks(chunk).map(<[u8]>::to_vec).collect()
}

#[test]
fn ufvk_export_round_trips_through_plan_remaining_and_parse() {
    let plan = ufvk_plan(0).unwrap();
    assert_eq!(plan.len(), 2);
    assert_eq!((plan[0].ins, plan[0].p1), (0x50, 0x00));
    assert_eq!((plan[1].ins, plan[1].p1), (0x50, 0x80));

    let ufvk = mainnet_ufvk();
    let all = ufvk_chunks(&ufvk, 64);
    assert!(
        all.len() > 2,
        "a real UFVK needs more than one continuation"
    );
    // Host loop: send first, then continuation while bytes are owed.
    let mut received = vec![all[0].clone()];
    while apdu::ufvk_remaining_bytes(&received).unwrap() > 0 {
        received.push(all[received.len()].clone());
    }
    assert_eq!(received.len(), all.len());

    let export = parse_ufvk(&received, "main", 0).unwrap();
    assert_eq!(export.ufvk, ufvk);
    assert_eq!(export.account_index, 0);
    assert_eq!(export.seed_fingerprint, account_fingerprint(&ufvk, 0));
}

#[test]
fn ufvk_is_checked_against_the_requested_network() {
    let chunks = ufvk_chunks(&mainnet_ufvk(), 250);
    let error = parse_ufvk(&chunks, "test", 0).unwrap_err();
    assert!(
        error.starts_with("protocol_error: Failed to parse Ledger UFVK"),
        "{error}"
    );
    assert!(parse_ufvk(&chunks, "regtest", 0)
        .unwrap_err()
        .starts_with("protocol_error: "));
    assert!(parse_ufvk(&ufvk_chunks("uview1notakey", 250), "main", 0)
        .unwrap_err()
        .starts_with("protocol_error: "));
}

#[test]
fn account_fingerprint_is_stable_and_account_scoped() {
    let first = account_fingerprint("uview-test", 0);
    assert_eq!(first, account_fingerprint("uview-test", 0));
    assert_ne!(first, account_fingerprint("uview-test", 1));
    assert_ne!(first, account_fingerprint("uview-other", 0));
}

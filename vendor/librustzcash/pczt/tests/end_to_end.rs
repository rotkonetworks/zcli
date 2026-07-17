use std::sync::OnceLock;

use ::transparent::{
    address::{Script, TransparentAddress},
    bundle as transparent,
    keys::{AccountPrivKey, IncomingViewingKey, NonHardenedChildIndex},
    sighash::SighashType,
    zip48,
};
use orchard::tree::MerkleHashOrchard;
use pczt::{
    Pczt,
    roles::{
        combiner::Combiner, creator::Creator, io_finalizer::IoFinalizer, prover::Prover,
        signer::Signer, spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor,
        updater::Updater,
    },
};
use rand_core::OsRng;
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_note_encryption::try_note_decryption;
#[cfg(zcash_unstable = "nu6.3")]
use zcash_primitives::transaction::{TxVersion, builder::PcztParts};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, PcztResult},
    fees::zip317,
    sighash::SignableInput,
    sighash_v5::v5_signature_hash,
    txid::TxIdDigester,
};
use zcash_proofs::prover::LocalTxProver;
#[cfg(zcash_unstable = "nu6.3")]
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters};
use zcash_protocol::{
    consensus::MainNetwork,
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};
use zcash_script::script::{self, Evaluable};

static ORCHARD_PROVING_KEY: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();
#[cfg(zcash_unstable = "nu6.3")]
static IRONWOOD_PROVING_KEY: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();

fn orchard_proving_key() -> &'static orchard::circuit::ProvingKey {
    ORCHARD_PROVING_KEY.get_or_init(|| {
        orchard::circuit::ProvingKey::build(
            orchard::BundleProtocol::OrchardPreNu6_3.circuit_version(),
        )
    })
}

#[cfg(zcash_unstable = "nu6.3")]
fn ironwood_proving_key() -> &'static orchard::circuit::ProvingKey {
    IRONWOOD_PROVING_KEY.get_or_init(|| {
        orchard::circuit::ProvingKey::build(
            orchard::BundleProtocol::IronwoodPostNu6_3.circuit_version(),
        )
    })
}

fn check_round_trip(pczt: &Pczt) {
    let encoded = pczt.serialize();
    assert_eq!(encoded, Pczt::parse(&encoded).unwrap().serialize());
}

#[cfg(zcash_unstable = "nu6.3")]
#[derive(Clone, Copy, Debug)]
struct Nu6_3Network;

#[cfg(zcash_unstable = "nu6.3")]
impl Parameters for Nu6_3Network {
    fn network_type(&self) -> NetworkType {
        NetworkType::Test
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Nu6_3 => Some(BlockHeight::from_u32(10)),
            _ => MainNetwork.activation_height(nu),
        }
    }
}

#[cfg(zcash_unstable = "nu6.3")]
fn nu6_3_network() -> Nu6_3Network {
    Nu6_3Network
}

#[cfg(zcash_unstable = "nu6.3")]
#[test]
fn creator_accepts_v6_pczt_parts() {
    assert!(
        Creator::build_from_parts(PcztParts {
            params: nu6_3_network(),
            version: TxVersion::V6,
            consensus_branch_id: BranchId::Nu6_3,
            lock_time: 0,
            expiry_height: 0u32.into(),
            transparent: None,
            sapling: None,
            orchard: None,
            ironwood: None,
        })
        .is_some()
    );
}

#[cfg(zcash_unstable = "nu6.3")]
#[test]
fn creator_accepts_v5_pczt_parts_without_ironwood_bundle() {
    assert!(
        Creator::build_from_parts(PcztParts {
            params: nu6_3_network(),
            version: TxVersion::V5,
            consensus_branch_id: BranchId::Nu5,
            lock_time: 0,
            expiry_height: 0u32.into(),
            transparent: None,
            sapling: None,
            orchard: None,
            ironwood: None,
        })
        .is_some()
    );
}

#[cfg(zcash_unstable = "nu6.3")]
#[test]
fn creator_rejects_v5_pczt_parts_with_ironwood_bundle() {
    let mut parts = nu6_3_pczt_parts_with_orchard_style_outputs(true);
    assert!(
        parts
            .ironwood
            .as_ref()
            .is_some_and(|bundle| !bundle.actions().is_empty())
    );

    parts.version = TxVersion::V5;
    parts.consensus_branch_id = BranchId::Nu5;

    assert!(Creator::build_from_parts(parts).is_none());
}

#[cfg(zcash_unstable = "nu6.3")]
fn nu6_3_pczt_parts_with_orchard_style_outputs(ironwood: bool) -> PcztParts<Nu6_3Network> {
    let params = nu6_3_network();

    let transparent_account_sk =
        AccountPrivKey::from_seed(&params, &[1; 32], zip32::AccountId::ZERO).unwrap();
    let (transparent_addr, address_index) = transparent_account_sk
        .to_account_pubkey()
        .derive_external_ivk()
        .unwrap()
        .default_address();
    let transparent_sk = transparent_account_sk
        .derive_external_secret_key(address_index)
        .unwrap();
    let secp = secp256k1::Secp256k1::signing_only();
    let transparent_pubkey = transparent_sk.public_key(&secp);

    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);
    let internal_ovk = orchard_fvk.to_ovk(zip32::Scope::Internal);
    let internal_recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal);

    let coin = transparent::TxOut::new(
        Zatoshis::const_from_u64(1_000_000),
        transparent_addr.script().into(),
    );

    let mut builder = Builder::new(
        params,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
        },
    );
    builder
        .add_transparent_p2pkh_input(transparent_pubkey, transparent::OutPoint::fake(), coin)
        .unwrap();

    if ironwood {
        builder
            .add_ironwood_output::<zip317::FeeRule>(
                Some(orchard_ovk),
                recipient,
                Zatoshis::const_from_u64(100_000),
                MemoBytes::empty(),
            )
            .unwrap();
        builder
            .add_ironwood_change_output::<zip317::FeeRule>(
                orchard_fvk.clone(),
                Some(internal_ovk),
                internal_recipient,
                Zatoshis::const_from_u64(885_000),
                MemoBytes::empty(),
            )
            .unwrap();
    } else {
        builder
            .add_orchard_change_output::<zip317::FeeRule>(
                orchard_fvk.clone(),
                Some(orchard_ovk),
                recipient,
                Zatoshis::const_from_u64(100_000),
                MemoBytes::empty(),
            )
            .unwrap();
        builder
            .add_orchard_change_output::<zip317::FeeRule>(
                orchard_fvk.clone(),
                Some(internal_ovk),
                internal_recipient,
                Zatoshis::const_from_u64(885_000),
                MemoBytes::empty(),
            )
            .unwrap();
    }

    builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap()
        .pczt_parts
}

#[cfg(zcash_unstable = "nu6.3")]
#[test]
fn creator_rejects_ironwood_bundle_as_orchard_parts() {
    let mut parts = nu6_3_pczt_parts_with_orchard_style_outputs(true);
    parts.orchard = parts.ironwood.take();

    assert!(Creator::build_from_parts(parts).is_none());
}

#[cfg(zcash_unstable = "nu6.3")]
#[test]
fn creator_rejects_orchard_bundle_as_ironwood_parts() {
    let mut parts = nu6_3_pczt_parts_with_orchard_style_outputs(false);
    parts.ironwood = parts.orchard.take();

    assert!(Creator::build_from_parts(parts).is_none());
}

#[test]
fn transparent_to_orchard() {
    let params = MainNetwork;
    let rng = OsRng;

    // Create a transparent account to send funds from.
    let transparent_account_sk =
        AccountPrivKey::from_seed(&params, &[1; 32], zip32::AccountId::ZERO).unwrap();
    let (transparent_addr, address_index) = transparent_account_sk
        .to_account_pubkey()
        .derive_external_ivk()
        .unwrap()
        .default_address();
    let transparent_sk = transparent_account_sk
        .derive_external_secret_key(address_index)
        .unwrap();
    let secp = secp256k1::Secp256k1::signing_only();
    let transparent_pubkey = transparent_sk.public_key(&secp);
    let p2pkh_addr = TransparentAddress::from_pubkey(&transparent_pubkey);

    // Create an Orchard account to receive funds.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already have a transparent coin.
    let utxo = transparent::OutPoint::fake();
    let coin = transparent::TxOut::new(
        Zatoshis::const_from_u64(1_000_000),
        transparent_addr.script().into(),
    );

    // Create the transaction's I/O.
    let mut builder = Builder::new(
        params,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood_anchor: None,
        },
    );
    builder
        .add_transparent_p2pkh_input(transparent_pubkey, utxo, coin.clone())
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_fvk.to_ovk(zip32::Scope::Internal)),
            orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal),
            Zatoshis::const_from_u64(885_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(rng, &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_round_trip(&pczt);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    check_round_trip(&pczt);

    // Create proofs.
    let pczt = Prover::new(pczt)
        .create_orchard_proof(orchard_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt);

    // Apply signatures.
    let mut signer = Signer::new(pczt).unwrap();
    signer.sign_transparent(0, &transparent_sk).unwrap();
    let pczt = signer.finish();
    check_round_trip(&pczt);

    // Finalize spends.
    let pczt = SpendFinalizer::new(pczt).finalize_spends().unwrap();
    check_round_trip(&pczt);

    // Grab the transaction's effects here, as it's easier.
    let tx_effects = pczt.clone().into_effects().unwrap();

    // We should now be able to extract the fully authorized transaction.
    let tx = TransactionExtractor::new(pczt).extract().unwrap();
    let tx_digests = tx.digest(TxIdDigester);

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);

    // Validate the transaction.
    let bundle = tx.transparent_bundle().unwrap();
    assert_eq!(bundle.vin.len(), 1);
    let txin = bundle.vin.first().unwrap();
    let sighasher = |script_code: &script::Code, hash_type: &zcash_script::signature::HashType| {
        Some(
            v5_signature_hash(
                &tx_effects,
                &SignableInput::Transparent(
                    ::transparent::sighash::SignableInput::from_parts(
                        bundle,
                        match (hash_type.signed_outputs(), hash_type.anyone_can_pay()) {
                            (zcash_script::signature::SignedOutputs::All, false) => {
                                SighashType::ALL
                            }
                            (zcash_script::signature::SignedOutputs::All, true) => {
                                SighashType::ALL_ANYONECANPAY
                            }
                            (zcash_script::signature::SignedOutputs::Single, false) => {
                                SighashType::SINGLE
                            }
                            (zcash_script::signature::SignedOutputs::Single, true) => {
                                SighashType::SINGLE_ANYONECANPAY
                            }
                            (zcash_script::signature::SignedOutputs::None, false) => {
                                SighashType::NONE
                            }
                            (zcash_script::signature::SignedOutputs::None, true) => {
                                SighashType::NONE_ANYONECANPAY
                            }
                        },
                        0,
                        &Script(script_code.clone()),
                        coin.script_pubkey(),
                        coin.value(),
                    )
                    .unwrap(),
                ),
                &tx_digests,
            )
            .as_ref()
            .try_into()
            .unwrap(),
        )
    };
    let checker = zcash_script::interpreter::CallbackTransactionSignatureChecker {
        sighash: &sighasher,
        lock_time: tx.lock_time().into(),
        is_final: txin.sequence() == 0xFFFFFFFF,
    };
    assert_eq!(
        script::Raw::from_raw_parts(
            txin.script_sig().0.to_bytes(),
            p2pkh_addr.script().to_bytes()
        )
        .eval(zcash_script::interpreter::Flags::all(), &checker),
        Ok(true)
    );
}

#[test]
fn transparent_p2sh_multisig_to_orchard() {
    let params = MainNetwork;
    let rng = OsRng;

    // Construct a 2-of-3 ZIP 48 P2SH account.
    let account_sk =
        |i| zip48::AccountPrivKey::from_seed(&params, &[i; 32], zip32::AccountId::ZERO).unwrap();
    let account_sks = [account_sk(1), account_sk(2), account_sk(3)];
    let key_info = account_sks
        .iter()
        .map(|sk| sk.to_account_pubkey())
        .collect();
    let fvk = zip48::FullViewingKey::standard(2, key_info).unwrap();

    // Derive its first external address, and corresponding spending keys.
    let (p2sh_addr, redeem_script) =
        fvk.derive_address(zip32::Scope::External, NonHardenedChildIndex::ZERO);
    let transparent_sks = account_sks
        .map(|sk| sk.derive_signing_key(zip32::Scope::External, NonHardenedChildIndex::ZERO));

    // Create an Orchard account to receive funds.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already have a transparent coin.
    let utxo = transparent::OutPoint::fake();
    let coin = transparent::TxOut::new(
        Zatoshis::const_from_u64(1_000_000),
        p2sh_addr.script().into(),
    );

    // The transaction builder can't assume that the P2SH address receiving the coin was
    // generated from a redeem script that didn't contain bad opcodes.
    let redeem_script = redeem_script.weaken();

    // Create the transaction's I/O.
    let mut builder = Builder::new(
        params,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood_anchor: None,
        },
    );
    builder
        .add_transparent_p2sh_input(redeem_script, utxo, coin.clone())
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_fvk.to_ovk(zip32::Scope::Internal)),
            orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal),
            Zatoshis::const_from_u64(880_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(rng, &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_round_trip(&pczt);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    check_round_trip(&pczt);

    // Create proofs.
    let pczt = Prover::new(pczt)
        .create_orchard_proof(orchard_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt);

    // If we only sign with one of the signers, we can't finalize spends.
    {
        let mut signer = Signer::new(pczt.clone()).unwrap();
        signer.sign_transparent(0, &transparent_sks[0]).unwrap();
        assert!(matches!(
            SpendFinalizer::new(signer.finish()).finalize_spends(),
            Err(pczt::roles::spend_finalizer::Error::TransparentFinalize(
                ::transparent::pczt::SpendFinalizerError::MissingSignature
            ))
        ));
    }

    // Sign the input with all three signers.
    let mut signer = Signer::new(pczt).unwrap();
    for sk in &transparent_sks {
        signer.sign_transparent(0, sk).unwrap();
    }
    let pczt = signer.finish();
    check_round_trip(&pczt);

    // Finalize spends. This will pick 2 of the signatures to use in the P2SH scriptSig.
    let pczt = SpendFinalizer::new(pczt).finalize_spends().unwrap();
    check_round_trip(&pczt);

    // Grab the transaction's effects here, as it's easier.
    let tx_effects = pczt.clone().into_effects().unwrap();

    // We should now be able to extract the fully authorized transaction.
    let tx = TransactionExtractor::new(pczt).extract().unwrap();
    let tx_digests = tx.digest(TxIdDigester);

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);

    // Validate the transaction.
    let bundle = tx.transparent_bundle().unwrap();
    assert_eq!(bundle.vin.len(), 1);
    let txin = bundle.vin.first().unwrap();
    let sighasher = |script_code: &script::Code, hash_type: &zcash_script::signature::HashType| {
        Some(
            v5_signature_hash(
                &tx_effects,
                &SignableInput::Transparent(
                    ::transparent::sighash::SignableInput::from_parts(
                        bundle,
                        match (hash_type.signed_outputs(), hash_type.anyone_can_pay()) {
                            (zcash_script::signature::SignedOutputs::All, false) => {
                                SighashType::ALL
                            }
                            (zcash_script::signature::SignedOutputs::All, true) => {
                                SighashType::ALL_ANYONECANPAY
                            }
                            (zcash_script::signature::SignedOutputs::Single, false) => {
                                SighashType::SINGLE
                            }
                            (zcash_script::signature::SignedOutputs::Single, true) => {
                                SighashType::SINGLE_ANYONECANPAY
                            }
                            (zcash_script::signature::SignedOutputs::None, false) => {
                                SighashType::NONE
                            }
                            (zcash_script::signature::SignedOutputs::None, true) => {
                                SighashType::NONE_ANYONECANPAY
                            }
                        },
                        0,
                        &Script(script_code.clone()),
                        coin.script_pubkey(),
                        coin.value(),
                    )
                    .unwrap(),
                ),
                &tx_digests,
            )
            .as_ref()
            .try_into()
            .unwrap(),
        )
    };
    let checker = zcash_script::interpreter::CallbackTransactionSignatureChecker {
        sighash: &sighasher,
        lock_time: tx.lock_time().into(),
        is_final: txin.sequence() == 0xFFFFFFFF,
    };
    assert_eq!(
        script::Raw::from_raw_parts(
            txin.script_sig().0.to_bytes(),
            p2sh_addr.script().to_bytes()
        )
        .eval(zcash_script::interpreter::Flags::all(), &checker),
        Ok(true)
    );
}

#[test]
fn sapling_to_orchard() {
    let mut rng = OsRng;

    // Create a Sapling account to send funds from.
    let sapling_extsk = sapling::zip32::ExtendedSpendingKey::master(&[1; 32]);
    let sapling_dfvk = sapling_extsk.to_diversifiable_full_viewing_key();
    let sapling_internal_dfvk = sapling_extsk
        .derive_internal()
        .to_diversifiable_full_viewing_key();
    let sapling_recipient = sapling_dfvk.default_address().1;

    // Create an Orchard account to receive funds.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already received a note.
    let value = sapling::value::NoteValue::from_raw(1_000_000);
    let note = {
        let mut sapling_builder = sapling::builder::Builder::new(
            sapling::note_encryption::Zip212Enforcement::On,
            sapling::builder::BundleType::DEFAULT,
            sapling::Anchor::empty_tree(),
        );
        sapling_builder
            .add_output(
                None,
                sapling_recipient,
                value,
                Memo::Empty.encode().into_bytes(),
            )
            .unwrap();
        let (bundle, meta) = sapling_builder
            .build::<LocalTxProver, LocalTxProver, _, i64>(&[], &mut rng)
            .unwrap()
            .unwrap();
        let output = bundle
            .shielded_outputs()
            .get(meta.output_index(0).unwrap())
            .unwrap();
        let domain = sapling::note_encryption::SaplingDomain::new(
            sapling::note_encryption::Zip212Enforcement::On,
        );
        let (note, _, _) =
            try_note_decryption(&domain, &sapling_dfvk.to_external_ivk().prepare(), output)
                .unwrap();
        note
    };

    // Use the tree with a single leaf.
    let (anchor, merkle_path) = {
        let cmu = note.cmu();
        let leaf = sapling::Node::from_cmu(&cmu);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<sapling::Node, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path)
    };

    // Build the Orchard bundle we'll be using.
    let mut builder = Builder::new(
        MainNetwork,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: Some(anchor),
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood_anchor: None,
        },
    );
    builder
        .add_sapling_spend::<zip317::FeeRule>(sapling_dfvk.fvk().clone(), note, merkle_path)
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(sapling_dfvk.to_ovk(zip32::Scope::External).0.into()),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_sapling_output::<zip317::FeeRule>(
            Some(sapling_dfvk.to_ovk(zip32::Scope::Internal)),
            sapling_internal_dfvk.find_address(0u32.into()).unwrap().1,
            Zatoshis::const_from_u64(880_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        sapling_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_round_trip(&pczt);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    check_round_trip(&pczt);

    // Update the Sapling bundle with its proof generation key.
    let index = sapling_meta.spend_index(0).unwrap();
    let pczt = Updater::new(pczt)
        .update_sapling_with(|mut updater| {
            updater.update_spend_with(index, |mut spend_updater| {
                spend_updater.set_proof_generation_key(sapling_extsk.expsk.proof_generation_key())
            })
        })
        .unwrap()
        .finish();

    // To test the Combiner, we will create the Sapling proofs, Sapling signatures, and
    // Orchard proof "in parallel".

    // Create Sapling proofs.
    let sapling_prover = LocalTxProver::bundled();
    let pczt_with_sapling_proofs = Prover::new(pczt.clone())
        .create_sapling_proofs(&sapling_prover, &sapling_prover)
        .unwrap()
        .finish();
    check_round_trip(&pczt_with_sapling_proofs);

    // Create Orchard proof.
    let pczt_with_orchard_proof = Prover::new(pczt.clone())
        .create_orchard_proof(orchard_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt_with_orchard_proof);

    // Pass the PCZT to be signed through a serialization cycle to ensure we don't lose
    // any information. This emulates passing it to another device.
    let pczt = Pczt::parse(&pczt.serialize()).unwrap();

    // Apply signatures.
    let mut signer = Signer::new(pczt).unwrap();
    signer
        .sign_sapling(index, &sapling_extsk.expsk.ask)
        .unwrap();
    let pczt_with_sapling_signatures = signer.finish();
    check_round_trip(&pczt_with_sapling_signatures);

    // Emulate passing the signed PCZT back to the first device.
    let pczt_with_sapling_signatures =
        Pczt::parse(&pczt_with_sapling_signatures.serialize()).unwrap();

    // Combine the three PCZTs into one.
    let pczt = Combiner::new(vec![
        pczt_with_sapling_proofs,
        pczt_with_orchard_proof,
        pczt_with_sapling_signatures,
    ])
    .combine()
    .unwrap();
    check_round_trip(&pczt);

    // We should now be able to extract the fully authorized transaction.
    let (spend_vk, output_vk) = sapling_prover.verifying_keys();
    let tx = TransactionExtractor::new(pczt)
        .with_sapling(&spend_vk, &output_vk)
        .extract()
        .unwrap();

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

#[test]
fn orchard_to_orchard() {
    let mut rng = OsRng;

    // Create an Orchard account to receive funds.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_ask = orchard::keys::SpendAuthorizingKey::from(&orchard_sk);
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already received a note.
    let value = orchard::value::NoteValue::from_raw(1_000_000);
    let note = {
        let mut orchard_builder = orchard::builder::Builder::new(
            orchard::BundleProtocol::OrchardPreNu6_3,
            orchard::builder::BundleType::DEFAULT,
            orchard::Anchor::empty_tree(),
        );
        orchard_builder
            .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
            .unwrap();
        let (bundle, meta) = orchard_builder.build::<i64>(&mut rng).unwrap().unwrap();
        let action = bundle
            .actions()
            .get(meta.output_action_index(0).unwrap())
            .unwrap();
        let domain = orchard::note_encryption::OrchardDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &orchard_ivk.prepare(), action).unwrap();
        note
    };

    // Use the tree with a single leaf.
    let (anchor, merkle_path) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path.into())
    };

    // Build the Orchard bundle we'll be using.
    let mut builder = Builder::new(
        MainNetwork,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood_anchor: None,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_fvk.to_ovk(zip32::Scope::Internal)),
            orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal),
            Zatoshis::const_from_u64(890_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        orchard_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_round_trip(&pczt);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    check_round_trip(&pczt);

    // Create proofs.
    let pczt = Prover::new(pczt)
        .create_orchard_proof(orchard_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt);

    // Apply signatures.
    let index = orchard_meta.spend_action_index(0).unwrap();
    let mut signer = Signer::new(pczt).unwrap();
    signer.sign_orchard(index, &orchard_ask).unwrap();
    let pczt = signer.finish();
    check_round_trip(&pczt);

    // We should now be able to extract the fully authorized transaction.
    let tx = TransactionExtractor::new(pczt).extract().unwrap();

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

#[cfg(zcash_unstable = "nu6.3")]
#[test]
fn v6_orchard_anchor_can_be_updated_after_signing() {
    use pczt::roles::updater::OrchardSpendWitness;

    let mut rng = OsRng;

    // Create an Orchard account to receive funds.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_ask = orchard::keys::SpendAuthorizingKey::from(&orchard_sk);
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already received an Orchard note.
    let value = orchard::value::NoteValue::from_raw(1_000_000);
    let note = {
        let mut orchard_builder = orchard::builder::Builder::new(
            orchard::BundleProtocol::OrchardPreNu6_3,
            orchard::builder::BundleType::DEFAULT,
            orchard::Anchor::empty_tree(),
        );
        orchard_builder
            .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
            .unwrap();
        let (bundle, meta) = orchard_builder.build::<i64>(&mut rng).unwrap().unwrap();
        let action = bundle
            .actions()
            .get(meta.output_action_index(0).unwrap())
            .unwrap();
        let domain = orchard::note_encryption::OrchardDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &orchard_ivk.prepare(), action).unwrap();
        note
    };

    // Use the tree with a single leaf.
    let (anchor, merkle_path): (orchard::Anchor, orchard::tree::MerklePath) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path.into())
    };

    // Build a v6 transaction that spends Orchard and outputs to Ironwood.
    let dummy = dummy_orchard_merkle_path();
    let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
    let dummy_anchor = dummy.root(cmx);
    assert_eq!(merkle_path.root(cmx), anchor);
    let mut builder = Builder::new(
        nu6_3_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(dummy_anchor),
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, dummy)
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(980_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        orchard_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    let base_pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_round_trip(&base_pczt);

    let pczt = IoFinalizer::new(base_pczt).finalize_io().unwrap();
    check_round_trip(&pczt);

    let index = orchard_meta.spend_action_index(0).unwrap();
    let mut signer = Signer::new(pczt.clone()).unwrap();
    let shielded_sighash_before = signer.shielded_sighash();
    signer.sign_orchard(index, &orchard_ask).unwrap();
    let signed_pczt = signer.finish();
    check_round_trip(&signed_pczt);

    let updated_base = Updater::new(pczt)
        .set_v6_orchard_anchor(anchor)
        .unwrap()
        .set_orchard_spend_witnesses([OrchardSpendWitness::from_merkle_path(
            index,
            merkle_path.clone(),
        )])
        .unwrap()
        .finish();
    check_round_trip(&updated_base);

    let updated_signed = Updater::new(signed_pczt)
        .set_v6_orchard_anchor(anchor)
        .unwrap()
        .set_orchard_spend_witnesses([OrchardSpendWitness::from_merkle_path(index, merkle_path)])
        .unwrap()
        .finish();
    check_round_trip(&updated_signed);

    assert_eq!(*updated_signed.orchard().anchor(), anchor.to_bytes());
    assert_eq!(
        Signer::new(updated_signed.clone())
            .unwrap()
            .shielded_sighash(),
        shielded_sighash_before
    );

    let pczt_with_proofs = Prover::new(updated_base)
        .create_orchard_proof(ironwood_proving_key())
        .unwrap()
        .create_ironwood_proof(ironwood_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt_with_proofs);
    assert_eq!(
        Signer::new(pczt_with_proofs.clone())
            .unwrap()
            .shielded_sighash(),
        shielded_sighash_before
    );

    let pczt = Combiner::new(vec![pczt_with_proofs, updated_signed])
        .combine()
        .unwrap();
    check_round_trip(&pczt);

    let pczt = SpendFinalizer::new(pczt).finalize_spends().unwrap();
    check_round_trip(&pczt);

    let tx = TransactionExtractor::new(pczt).extract().unwrap();
    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

#[cfg(zcash_unstable = "nu6.3")]
fn dummy_orchard_merkle_path() -> orchard::tree::MerklePath {
    let zero = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&[0; 32]))
        .expect("zero Orchard Merkle hash is valid");
    orchard::tree::MerklePath::from_parts(0, [zero; 32])
}

#[cfg(zcash_unstable = "nu6.3")]
#[test]
fn ironwood_to_ironwood() {
    let mut rng = OsRng;

    // Create an Orchard account to receive funds.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_ask = orchard::keys::SpendAuthorizingKey::from(&orchard_sk);
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already received an Ironwood note.
    let value = orchard::value::NoteValue::from_raw(1_000_000);
    let note = {
        let mut orchard_builder = orchard::builder::Builder::new(
            orchard::BundleProtocol::IronwoodPostNu6_3,
            orchard::builder::BundleType::DEFAULT,
            orchard::Anchor::empty_tree(),
        );
        orchard_builder
            .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
            .unwrap();
        let (bundle, meta) = orchard_builder.build::<i64>(&mut rng).unwrap().unwrap();
        let action = bundle
            .actions()
            .get(meta.output_action_index(0).unwrap())
            .unwrap();
        let domain = orchard::note_encryption::OrchardDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &orchard_ivk.prepare(), action).unwrap();
        assert_eq!(note.version(), orchard::note::NoteVersion::V3);
        note
    };

    // Use the Ironwood tree with a single leaf.
    let (anchor, merkle_path) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path.into())
    };

    // Build the Ironwood bundle we'll be using.
    let mut builder = Builder::new(
        nu6_3_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
        },
    );
    builder
        .add_ironwood_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(990_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        ironwood_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_round_trip(&pczt);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    check_round_trip(&pczt);

    // Create proofs.
    let pczt = Prover::new(pczt)
        .create_ironwood_proof(ironwood_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt);

    // Apply signatures.
    let index = ironwood_meta.spend_action_index(0).unwrap();
    let mut signer = Signer::new(pczt).unwrap();
    signer.sign_ironwood(index, &orchard_ask).unwrap();
    let pczt = signer.finish();
    check_round_trip(&pczt);

    // We should now be able to extract the fully authorized transaction.
    let tx = TransactionExtractor::new(pczt).extract().unwrap();

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
    assert!(tx.orchard_bundle().is_none());
    assert!(tx.ironwood_bundle().is_some());
}

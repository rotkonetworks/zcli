//! HOT-WALLET turnstile migration end-to-end (native): derive keys from a
//! DETERMINISTIC seed phrase, build a V6 PCZT that spends a synthetic orchard
//! note into the wallet's own ironwood address, LOCAL-sign the orchard spend
//! with the seed-derived spend authorizing key, extract, and assert we got a
//! broadcastable TxVersion::V6 transaction whose orchard spend-auth + binding
//! signatures VERIFY, that binds the real NU6.3 consensus branch id, and whose
//! value balance is exactly `input - fee == migrated ironwood value`.
//!
//! Sibling of `turnstile_v6.rs` (the cold/redacted flow). Exercises the
//! money-path signing function `build_signed_turnstile_migration_core`.
//!
//! Run with:
//!   cargo test --release --test signed_turnstile_v6
//! Run with --release: it
//! builds the post-NU6.3 Halo 2 proving key and proves two bundles.


use zafu_wasm::build_signed_turnstile_migration_core;

use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{Authorization, Transaction, TransactionData, TxVersion};
use zcash_protocol::consensus::{
    BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters,
};
use zcash_protocol::memo::MemoBytes;

/// A transaction authorization view whose TRANSPARENT part is `EffectsOnly`
/// (carries the input amounts/scripts a sighash needs) while the shielded parts
/// stay fully `Authorized`. We use it to recompute the ZIP-244 shielded sighash
/// from the extracted, fully-signed transaction: `signature_hash` requires
/// `TransparentAuth: TransparentAuthorizingContext`, which the extracted tx's
/// `transparent::Authorized` does NOT implement (it lacks prevout amounts). For
/// this orchard->ironwood migration the transparent bundle is `None`, so the
/// `EffectsOnly` view is exact (empty inputs) and the shielded digests are
/// identical to what the extractor signed under.
#[derive(Debug)]
struct ShieldedSighashAuth;

impl Authorization for ShieldedSighashAuth {
    type TransparentAuth = zcash_transparent::bundle::EffectsOnly;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

/// Test network with NU6.3 active from height 10 (same shape as the
/// `Nu63TestNet` fixture in `turnstile_v6.rs` and the fork's end_to_end.rs).
#[derive(Clone, Copy, Debug)]
struct Nu63TestNet;

impl Parameters for Nu63TestNet {
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

/// Real NU6.3 / Ironwood consensus branch id (from the live zebra). The patched
/// fork binds this at any NU6.3-active height; the fail-closed guard requires
/// the caller to pass it explicitly.
const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;

#[test]
fn signed_turnstile_orchard_to_ironwood_verifies() {
    // -- wallet keys derived from a DETERMINISTIC seed phrase, exactly the way
    //    `build_signed_turnstile_migration` derives them internally:
    //    SpendingKey::from_zip32_seed(seed, coin_type, account). We use the
    //    TEST coin type (1) to match Nu63TestNet's network_type == Test. This is
    //    identical to UnifiedSpendingKey::from_seed(TestNetwork,..).orchard().
    const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon about";
    const ACCOUNT: u32 = 0;
    const COIN_TYPE_TEST: u32 = 1;

    let mnemonic = bip39::Mnemonic::parse(SEED).expect("valid test mnemonic");
    let seed = mnemonic.to_seed("");
    let account_id = zip32::AccountId::try_from(ACCOUNT).unwrap();
    let sk =
        orchard::keys::SpendingKey::from_zip32_seed(&seed, COIN_TYPE_TEST, account_id).unwrap();
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let ask = orchard::keys::SpendAuthorizingKey::from(&sk);

    // -- a spendable orchard note (legacy pool, V2 plaintext) OWNED by the
    //    derived fvk, with a dummy single-leaf witness (same fixture shape as
    //    turnstile_v6.rs). Because the note is addressed to this fvk's own
    //    external address, verify_nullifier(Some(fvk)) accepts it and the
    //    seed-derived ask produces a valid spend-auth signature. --
    let note_value = 1_000_000u64;
    let fee = 10_000u64;
    let migrated = note_value - fee;

    let rho = orchard::note::Rho::from_bytes(&[1u8; 32]).unwrap();
    let rseed = (0u8..=255)
        .find_map(|b| Option::from(orchard::note::RandomSeed::from_bytes([b; 32], &rho)))
        .expect("test rseed");
    let note: orchard::Note = Option::from(orchard::Note::from_parts(
        fvk.address_at(0u32, orchard::keys::Scope::External),
        orchard::value::NoteValue::from_raw(note_value),
        rho,
        rseed,
        orchard::note::NoteVersion::V2,
    ))
    .expect("test note");

    let zero = Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&[0u8; 32]))
        .expect("zero merkle hash");
    let witness = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
    let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
    let orchard_anchor = witness.root(cmx);

    // Sanity: the patched params bind the REAL branch id at an NU6.3-active
    // height (not the 0xffff_ffff placeholder). Target height must be past every
    // inherited MainNetwork activation (the orchard builder needs NU5 active).
    let target_height = 10_000_000u32;
    assert_eq!(
        u32::from(BranchId::for_height(
            &Nu63TestNet,
            BlockHeight::from_u32(target_height)
        )),
        NU6_3_BRANCH_ID,
        "turnstile must bind the real NU6.3 branch id 0x37a5165b"
    );

    // === (1) build + local-sign the turnstile migration ===
    let tx_bytes = build_signed_turnstile_migration_core(
        Nu63TestNet,
        &fvk,
        &ask,
        vec![(note, witness)],
        fee,
        orchard_anchor,
        target_height,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("build + sign turnstile migration");

    // FAIL-CLOSED guard is inherited from the shared build core: a mismatched
    // branch id and the placeholder must both be REFUSED even on the hot path.
    {
        let note2: orchard::Note = Option::from(orchard::Note::from_parts(
            fvk.address_at(0u32, orchard::keys::Scope::External),
            orchard::value::NoteValue::from_raw(note_value),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        ))
        .unwrap();
        let w2 = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
        let err = build_signed_turnstile_migration_core(
            Nu63TestNet,
            &fvk,
            &ask,
            vec![(note2, w2)],
            fee,
            orchard_anchor,
            target_height,
            0xdead_beef,
            MemoBytes::empty(),
        )
        .expect_err("must refuse a mismatched branch id");
        assert!(err.contains("branch id"), "unexpected error: {err}");

        let note3: orchard::Note = Option::from(orchard::Note::from_parts(
            fvk.address_at(0u32, orchard::keys::Scope::External),
            orchard::value::NoteValue::from_raw(note_value),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        ))
        .unwrap();
        let w3 = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
        let err = build_signed_turnstile_migration_core(
            Nu63TestNet,
            &fvk,
            &ask,
            vec![(note3, w3)],
            fee,
            orchard_anchor,
            target_height,
            0xffff_ffff,
            MemoBytes::empty(),
        )
        .expect_err("must refuse the placeholder branch id");
        assert!(err.contains("placeholder"), "unexpected error: {err}");
    }

    // === (2) parse the resulting tx ===
    let tx = Transaction::read(&tx_bytes[..], BranchId::Nu6_3).expect("tx parses");

    // === (3) assertions ===

    // (3a) parses as a valid V6 transaction with the orchard spend(s) + ironwood
    // output bundle.
    assert_eq!(tx.version(), TxVersion::V6, "must be a V6 transaction");
    let orchard_bundle = tx.orchard_bundle().expect("orchard spend bundle present");
    let ironwood_bundle = tx
        .ironwood_bundle()
        .expect("ironwood output bundle present");
    assert!(
        !orchard_bundle.actions().is_empty(),
        "orchard bundle has at least one action (the migrated spend)"
    );
    assert!(
        !ironwood_bundle.actions().is_empty(),
        "ironwood bundle has at least one action (the migrated output)"
    );

    // (3b) the bound consensus branch id == 0x37a5165b. Transaction::read was
    // told Nu6_3 as a decoding hint; assert the value the tx actually carries.
    assert_eq!(
        u32::from(tx.consensus_branch_id()),
        NU6_3_BRANCH_ID,
        "signed tx must bind the real NU6.3 consensus branch id 0x37a5165b"
    );

    // (3c) the orchard spend-auth signatures + binding signature VERIFY, and the
    // ironwood proof + binding signature VERIFY. Recompute the ZIP-244 shielded
    // sighash from the extracted tx exactly as the TransactionExtractor does
    // (TxIdDigester -> signature_hash over SignableInput::Shielded), then run
    // orchard's own BatchValidator over each bundle. add_bundle checks the proof
    // AND every action's spend-auth signature AND the binding signature against
    // the sighash; validate() returns false on ANY failure. This is an
    // INDEPENDENT re-verification (the extractor already verified internally, or
    // extraction would have errored above).
    // The extracted migration tx has NO transparent bundle. Rebuild a
    // TransactionData whose transparent auth is EffectsOnly (empty inputs) so
    // signature_hash's TransparentAuthorizingContext bound is satisfied; the
    // orchard + ironwood bundles are carried through unchanged (cloned). This
    // reproduces the exact ZIP-244 shielded sighash the extractor bound.
    assert!(
        tx.transparent_bundle().is_none(),
        "migration tx must have no transparent bundle"
    );
    let sighash_tx: TransactionData<ShieldedSighashAuth> = TransactionData::from_parts_v6(
        tx.consensus_branch_id(),
        tx.lock_time(),
        tx.expiry_height(),
        None, // transparent (EffectsOnly, empty)
        None, // sapling
        Some(orchard_bundle.clone()),
        Some(ironwood_bundle.clone()),
    );
    let txid_parts = sighash_tx.digest(TxIdDigester);
    let sighash = *signature_hash(&sighash_tx, &SignableInput::Shielded, &txid_parts).as_ref();

    {
        use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
        // V6 orchard bundle uses the post-NU6.3 circuit; the ironwood bundle uses
        // the ironwood post-NU6.3 circuit.
        let orchard_vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
        let mut v = orchard::bundle::BatchValidator::new(&orchard_vk);
        assert!(
            v.add_bundle(orchard_bundle, sighash).is_ok(),
            "orchard bundle rejected by validator (bad proof or spend-auth sig)"
        );
        assert!(
            v.validate(rand_core::OsRng),
            "orchard spend-auth + binding signatures + proof FAILED to verify"
        );

        let ironwood_vk =
            VerifyingKey::build(orchard::bundle::BundleVersion::ironwood_v3().circuit_version());
        let mut vi = orchard::bundle::BatchValidator::new(&ironwood_vk);
        assert!(
            vi.add_bundle(ironwood_bundle, sighash).is_ok(),
            "ironwood bundle rejected by validator (bad proof or binding sig)"
        );
        assert!(
            vi.validate(rand_core::OsRng),
            "ironwood binding signature + proof FAILED to verify"
        );
    }

    // (3d) value balance is correct: input - fee == migrated ironwood value.
    //
    // Orchard value_balance is (value spent - value output) = value LEAVING the
    // orchard pool. Here the orchard bundle spends the full note and its outputs
    // are zero-value dummies, so its value_balance == +note_value. The ironwood
    // bundle has no real spend and outputs the migrated value, so its
    // value_balance == -migrated (value ENTERING the ironwood pool). The two
    // must sum to the fee, i.e. orchard_vb + ironwood_vb == fee, which restates
    // input - fee == migrated. We assert both the split identity and the
    // migrated-value identity directly.
    let orchard_vb: i64 = (*orchard_bundle.value_balance()).into();
    let ironwood_vb: i64 = (*ironwood_bundle.value_balance()).into();

    assert_eq!(
        orchard_vb, note_value as i64,
        "orchard value balance must equal the full spent input (dummy outputs are zero-value)"
    );
    assert_eq!(
        ironwood_vb,
        -(migrated as i64),
        "ironwood value balance must equal the negated migrated value"
    );
    assert_eq!(
        orchard_vb + ironwood_vb,
        fee as i64,
        "orchard + ironwood value balances must sum to the fee"
    );
    // The headline money-path identity, stated exactly as the task requires:
    // input - fee == migrated ironwood value.
    assert_eq!(
        (note_value as i64) - (fee as i64),
        -ironwood_vb,
        "input - fee must equal the migrated ironwood value"
    );
    assert_eq!(-ironwood_vb, migrated as i64);
}

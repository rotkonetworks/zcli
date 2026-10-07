//! A z->t move's txid is known before it is signed.
//!
//! zafu's one-round zigner swap builds the move (ironwood -> the swap's own
//! t-address, V6) and, before anything is signed, the deposit that spends the
//! move's transparent output at (move txid, vout). That only works if the txid
//! of the unsigned, io-finalized PCZT is the txid of the transaction that is
//! finally broadcast. ZIP 244 says it is: the txid commits to effecting data
//! only. For a transaction with no transparent inputs the shielded sighash is
//! that same digest (`transparent_sig_digest` falls back to the txid's
//! transparent digest when `vin` is empty), so `Signer::shielded_sighash()`
//! (what `frost_inspect_pczt_outputs` reports as `computed_sighash_hex`) is the
//! txid in wire order.
//!
//! This proves it on the real builder and the real extractor: sign the same
//! unsigned PCZT twice (fresh signature randomness each time), extract both,
//! and assert both txids equal the one read before signing.
//!
//! With `MOVE_FIXTURE_DIR` set it also writes the PCZTs zafu's batch test
//! replays (mainnet keys of the zigner test seed, the swap at t-index 57).
//!
//! Run:  cargo test --release --test move_txid_before_signing -- --nocapture

use zafu_wasm::{
    build_ironwood_send_pczt_proven, inspect_pczt_outputs_core, redact_pczt_for_signer,
    sign_pczt_spends, IronwoodPcztWithFrost, IronwoodRecipient, LEGACY_PCZT_EXPIRY_DELTA,
};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork};
use zcash_protocol::memo::MemoBytes;
use zcash_transparent::{
    address::TransparentAddress,
    keys::{NonHardenedChildIndex, TransparentKeyScope},
};

const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon about";
const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;
const TARGET: u32 = 3_500_000;
/// the swap's own t-branch index (zafu's transparent-deposit-zigner test)
const SWAP_INDEX: u32 = 57;
const NOTE: u64 = 1_000_000;
/// the deposit's 400_000 plus its 25_000 fee, the address being empty
const SHORT: u64 = 425_000;
const FEE: u64 = 15_000;

fn note_of(fvk: &orchard::keys::FullViewingKey, value: u64) -> orchard::Note {
    let rho = orchard::note::Rho::from_bytes(&[1u8; 32]).unwrap();
    let rseed = (0u8..=255)
        .find_map(|b| Option::from(orchard::note::RandomSeed::from_bytes([b; 32], &rho)))
        .expect("test rseed");
    Option::from(orchard::Note::from_parts(
        fvk.address_at(0u32, orchard::keys::Scope::External),
        orchard::value::NoteValue::from_raw(value),
        rho,
        rseed,
        orchard::note::NoteVersion::V3,
    ))
    .expect("test note")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn move_txid_is_known_before_signing() {
    let mnemonic = bip39::Mnemonic::parse(SEED).unwrap();
    let usk =
        UnifiedSpendingKey::from_seed(&MainNetwork, &mnemonic.to_seed(""), zip32::AccountId::ZERO)
            .unwrap();
    let ufvk = usk.to_unified_full_viewing_key().encode(&MainNetwork);
    let sk = orchard::keys::SpendingKey::from_bytes(*usk.orchard().to_bytes()).unwrap();
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let ask = orchard::keys::SpendAuthorizingKey::from(&sk);
    let swap_t = TransparentAddress::from_pubkey(
        &usk.transparent()
            .to_account_pubkey()
            .derive_address_pubkey(
                TransparentKeyScope::EXTERNAL,
                NonHardenedChildIndex::from_index(SWAP_INDEX).unwrap(),
            )
            .unwrap(),
    );
    assert_eq!(
        u32::from(BranchId::for_height(
            &MainNetwork,
            BlockHeight::from_u32(TARGET)
        )),
        NU6_3_BRANCH_ID
    );

    let note = note_of(&fvk, NOTE);
    let zero = Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&[0u8; 32])).unwrap();
    let witness = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
    let anchor = witness.root(note.commitment().into());

    let IronwoodPcztWithFrost { pczt, .. } = build_ironwood_send_pczt_proven(
        MainNetwork,
        &fvk,
        vec![(note, witness)],
        IronwoodRecipient::Transparent(swap_t),
        SHORT,
        FEE,
        anchor,
        TARGET,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
        LEGACY_PCZT_EXPIRY_DELTA,
    )
    .expect("build + prove the move");
    let unsigned = pczt.clone().serialize().expect("serialize");

    // before any signature: the shielded sighash, as zafu reads it
    let inspected = inspect_pczt_outputs_core(&unsigned, &ufvk).expect("inspect");
    let sighash = inspected["computed_sighash_hex"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(inspected["tx_version"], 6, "a post-NU6.3 move is V6");
    assert_eq!(inspected["transparent_input_count"], 0);
    let outs = inspected["transparent_outputs"].as_array().unwrap();
    assert_eq!(outs.len(), 1, "the move pays one transparent output");
    assert_eq!(outs[0]["value_zat"], SHORT);
    assert_eq!(
        outs[0]["script_pubkey_hex"].as_str().unwrap(),
        hex(&zcash_transparent::address::Script::from(swap_t.script())
            .0
             .0)
    );

    // signed twice, each with fresh randomness: the authorizing data differs,
    // the txid does not, and it is the digest read before signing
    let mut sigs = Vec::new();
    for _ in 0..2 {
        // signs the real spend, then extracts (proof and every signature verified)
        let tx_bytes = sign_pczt_spends(&unsigned, &fvk, &ask).expect("sign + extract");
        let tx = Transaction::read(&tx_bytes[..], BranchId::Nu6_3).expect("parse tx");
        assert_eq!(
            hex(tx.txid().as_ref()),
            sighash,
            "txid == pre-signing sighash"
        );
        sigs.push(tx_bytes);
    }
    assert_ne!(
        sigs[0], sigs[1],
        "two signings, two sets of authorizing bytes"
    );

    if let Ok(dir) = std::env::var("MOVE_FIXTURE_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        let device = redact_pczt_for_signer(pczt)
            .serialize()
            .expect("serialize device copy");
        std::fs::write(format!("{dir}/move_retained.hex"), hex(&unsigned)).unwrap();
        std::fs::write(format!("{dir}/move_device.hex"), hex(&device)).unwrap();
        std::fs::write(format!("{dir}/move_sighash.hex"), &sighash).unwrap();
        std::fs::write(format!("{dir}/ufvk.txt"), &ufvk).unwrap();
        eprintln!("wrote move fixtures to {dir}");
    }
}

//! Dump REAL ironwood-SEND PCZTs across adversarial shapes, as hex fixtures the
//! zigner `pczt_signing` module-wasm harness replays. The money path that had no
//! native coverage (`pczt_compact_redaction.rs` is all `#[ignore]`).
//!
//! For each shape we dump THREE artifacts:
//!   *_retained.hex - the proven UNREDACTED pczt the wallet keeps (merge target)
//!   *_full.hex     - redact_pczt_for_signer  (tx_type 0x03, vizor single-send)
//!   *_compact.hex  - redact_pczt_compact     (tx_type 0x05, batch optimization)
//!
//! Shapes (isislovecruft "break it"):
//!   single       - one note, empty memo, shielded recipient (the easy case)
//!   memo         - one note, NON-EMPTY memo. Compact hardcodes an empty memo
//!                  ([0u8;512], lib.rs:5518/5548), so the device re-encrypts the
//!                  WRONG ciphertext and signs a sighash that will not match the
//!                  retained tx. This fixture is built to expose that.
//!   zt           - z->t withdrawal (transparent recipient, no orchard bundle)
//!   multinote    - two ironwood notes spent against one shared 2-leaf anchor
//!
//! Run:  cargo test --release --test dump_ironwood_send_fixtures -- --nocapture

mod common;

use zafu_wasm::{
    build_ironwood_send_pczt_proven, redact_pczt_compact, redact_pczt_for_signer,
    IronwoodPcztWithFrost, IronwoodRecipient,
};
use zcash_protocol::consensus::{
    BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters,
};
use zcash_protocol::memo::MemoBytes;

const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;
const COIN_TYPE_TEST: u32 = 1;
const OUT_DIR: &str = "/steam/rotko/zigner/rust/pczt_signing/tests/fixtures";

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

fn keys_from_seed(seed_phrase: &str, account: u32) -> orchard::keys::FullViewingKey {
    let mnemonic = bip39::Mnemonic::parse(seed_phrase).expect("valid test mnemonic");
    let seed = mnemonic.to_seed("");
    let account_id = zip32::AccountId::try_from(account).unwrap();
    let sk = orchard::keys::SpendingKey::from_zip32_seed(&seed, COIN_TYPE_TEST, account_id).unwrap();
    orchard::keys::FullViewingKey::from(&sk)
}

fn note_of(
    fvk: &orchard::keys::FullViewingKey,
    value: u64,
    rho_seed: u8,
) -> orchard::Note {
    let rho = orchard::note::Rho::from_bytes(&[rho_seed; 32]).unwrap();
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

/// One note + single-leaf witness/anchor.
fn single_note(
    fvk: &orchard::keys::FullViewingKey,
    value: u64,
) -> (
    Vec<(orchard::Note, orchard::tree::MerklePath)>,
    orchard::tree::Anchor,
) {
    let note = note_of(fvk, value, 1u8);
    let zero =
        Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&[0u8; 32])).expect("zero hash");
    let witness = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
    let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
    let anchor = witness.root(cmx);
    (vec![(note, witness)], anchor)
}

/// Two notes as leaves 0 and 1 of one shared tree, both proving to one anchor.
fn two_notes(
    fvk: &orchard::keys::FullViewingKey,
    v0: u64,
    v1: u64,
) -> (
    Vec<(orchard::Note, orchard::tree::MerklePath)>,
    orchard::tree::Anchor,
) {
    let n0 = note_of(fvk, v0, 1u8);
    let n1 = note_of(fvk, v1, 2u8);
    let cmxs: Vec<orchard::note::ExtractedNoteCommitment> =
        vec![n0.commitment().into(), n1.commitment().into()];
    let p0 = common::two_leaf_merkle_path(&cmxs, 0);
    let p1 = common::two_leaf_merkle_path(&cmxs, 1);
    let anchor = p0.root(cmxs[0]);
    assert_eq!(
        anchor.to_bytes(),
        p1.root(cmxs[1]).to_bytes(),
        "both notes must share one anchor"
    );
    (vec![(n0, p0), (n1, p1)], anchor)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn dump(
    name: &str,
    recipient: IronwoodRecipient,
    prepared: Vec<(orchard::Note, orchard::tree::MerklePath)>,
    anchor: orchard::tree::Anchor,
    amount: u64,
    fee: u64,
    memo: MemoBytes,
) {
    let fvk = keys_from_seed(SEED, 0);
    let target_height = 10_000_000u32;
    let IronwoodPcztWithFrost { pczt, .. } = build_ironwood_send_pczt_proven(
        Nu63TestNet,
        &fvk,
        prepared,
        recipient,
        amount,
        fee,
        anchor,
        target_height,
        NU6_3_BRANCH_ID,
        memo,
    )
    .unwrap_or_else(|e| panic!("[{name}] build+prove: {e}"));

    let retained_hex = to_hex(&pczt.clone().serialize().expect("serialize retained"));
    let full_hex = to_hex(
        &redact_pczt_for_signer(pczt)
            .serialize()
            .expect("serialize full"),
    );
    let compact_hex = redact_pczt_compact(&full_hex).expect("compact-redact");

    std::fs::create_dir_all(OUT_DIR).expect("mk fixtures dir");
    std::fs::write(format!("{OUT_DIR}/ironwood_{name}_retained.hex"), &retained_hex).unwrap();
    std::fs::write(format!("{OUT_DIR}/ironwood_{name}_full.hex"), &full_hex).unwrap();
    std::fs::write(format!("{OUT_DIR}/ironwood_{name}_compact.hex"), &compact_hex).unwrap();
    eprintln!(
        "[{name}] retained={}B full={}B compact={}B",
        retained_hex.len() / 2,
        full_hex.len() / 2,
        compact_hex.len() / 2,
    );
}

const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon about";
const RECIP_SEED: &str = "legal winner thank year wave sausage worth useful legal \
                          winner thank yellow";

#[test]
fn dump_ironwood_send_fixtures() {
    assert_eq!(
        u32::from(BranchId::for_height(
            &Nu63TestNet,
            BlockHeight::from_u32(10_000_000)
        )),
        NU6_3_BRANCH_ID,
    );
    let recip = keys_from_seed(RECIP_SEED, 0).address_at(0u32, orchard::keys::Scope::External);
    let shielded = IronwoodRecipient::Shielded(recip);

    // single: one note, empty memo (the tested-easy shape)
    let (p, a) = single_note(&keys_from_seed(SEED, 0), 1_000_000);
    dump("single", shielded, p, a, 600_000, 10_000, MemoBytes::empty());

    // memo: NON-EMPTY memo - the compact empty-memo hardcode should mis-sign
    let (p, a) = single_note(&keys_from_seed(SEED, 0), 1_000_000);
    let memo = MemoBytes::from_bytes(b"break the compact path - isislovecruft").expect("memo");
    dump("memo", shielded, p, a, 600_000, 10_000, memo);

    // zt: transparent recipient (z->t withdrawal, no orchard bundle)
    let taddr = zcash_transparent::address::TransparentAddress::PublicKeyHash([0x42u8; 20]);
    let (p, a) = single_note(&keys_from_seed(SEED, 0), 1_000_000);
    dump(
        "zt",
        IronwoodRecipient::Transparent(taddr),
        p,
        a,
        600_000,
        10_000,
        MemoBytes::empty(),
    );

    // multinote: two notes, shared anchor
    let (p, a) = two_notes(&keys_from_seed(SEED, 0), 700_000, 700_000);
    dump("multinote", shielded, p, a, 1_000_000, 10_000, MemoBytes::empty());
}

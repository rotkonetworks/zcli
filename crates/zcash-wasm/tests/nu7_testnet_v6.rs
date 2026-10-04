//! NU7 on the public testnet: build and sign a turnstile migration with the
//! crate's `TestNetwork` at a post-NU7 height and check the result is a V6
//! transaction bound to the NU7 branch id. This is the path zcli and zafu take
//! on testnet, so it catches the Common 2.0 params missing the NU7 height.
//!
//! Run with:
//!   cargo test --release --test nu7_testnet_v6

use zafu_wasm::build_signed_turnstile_migration_core;
use zafu_wasm::consensus::{TestNetwork, TESTNET_NU7_ACTIVATION_HEIGHT};

use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_protocol::memo::MemoBytes;

const NU7_BRANCH_ID: u32 = 0x7719_0ad9;

#[test]
fn testnet_nu7_builds_v6_bound_to_nu7() {
    let target_height = TESTNET_NU7_ACTIVATION_HEIGHT + 1_000;
    assert_eq!(
        BranchId::for_height(&TestNetwork, BlockHeight::from_u32(target_height)),
        BranchId::Nu7
    );

    let seed = bip39::Mnemonic::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about",
    )
    .unwrap()
    .to_seed("");
    let account = zip32::AccountId::try_from(0).unwrap();
    let sk = orchard::keys::SpendingKey::from_zip32_seed(&seed, 1, account).unwrap();
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let ask = orchard::keys::SpendAuthorizingKey::from(&sk);

    let rho = orchard::note::Rho::from_bytes(&[1u8; 32]).unwrap();
    let rseed = (0u8..=255)
        .find_map(|b| Option::from(orchard::note::RandomSeed::from_bytes([b; 32], &rho)))
        .unwrap();
    let note: orchard::Note = Option::from(orchard::Note::from_parts(
        fvk.address_at(0u32, orchard::keys::Scope::External),
        orchard::value::NoteValue::from_raw(1_000_000),
        rho,
        rseed,
        orchard::note::NoteVersion::V2,
    ))
    .unwrap();
    let zero = Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&[0u8; 32])).unwrap();
    let witness = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
    let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
    let anchor = witness.root(cmx);

    let tx_bytes = build_signed_turnstile_migration_core(
        TestNetwork,
        &fvk,
        &ask,
        vec![(note, witness)],
        10_000,
        anchor,
        target_height,
        NU7_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("build + sign at an NU7 height");

    let tx = Transaction::read(&tx_bytes[..], BranchId::Nu7).expect("tx parses");
    assert_eq!(tx.version(), TxVersion::V6);
    assert_eq!(u32::from(tx.consensus_branch_id()), NU7_BRANCH_ID);
}

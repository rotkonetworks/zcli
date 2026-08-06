//! IRONWOOD SHIELDING end-to-end (native): spend transparent P2PKH UTXOs into a
//! single ironwood output in one V6 transaction, prove on the post-NU6.3
//! ironwood circuit, sign every transparent input with the secp256k1 key,
//! finalize the spends and extract a broadcastable V6 transaction.
//!
//! This is the money path that replaces `build_shielding_transaction` (orchard),
//! whose outputs are consensus-disabled from NU6.3. Sibling of
//! `signed_ironwood_send_v6.rs` (which SPENDS ironwood); this one only OUTPUTS
//! ironwood and has no shielded spends at all.
//!
//! Only meaningful when built the way the forks require:
//!   RUSTFLAGS='--cfg zcash_unstable="nu6.3"' cargo test --release --test shielding_ironwood_v6
//! Without the cfg this file compiles to nothing. Run with --release: it builds
//! the post-NU6.3 Halo 2 proving key and proves the ironwood bundle.


use zafu_wasm::{build_shielding_transaction_ironwood_core, zip317_shielding_fee, NU6_3_BRANCH_ID};

use orchard::keys::Scope;
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::{
    BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters,
};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::bundle::{OutPoint, TxOut};

/// Test network with NU6.3 active from height 10 (same fixture as the sibling
/// signed_ironwood_send_v6.rs and the fork's end_to_end.rs).
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

const TARGET_HEIGHT: u32 = 100;

fn test_key() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
    let secp = secp256k1::Secp256k1::signing_only();
    let sk = secp256k1::SecretKey::from_slice(&[7u8; 32]).expect("valid test secret key");
    let pk = sk.public_key(&secp);
    (sk, pk)
}

/// A P2PKH coin locked to `pk`, worth `value` zat.
fn coin(pk: &secp256k1::PublicKey, value: u64, txid_byte: u8, vout: u32) -> (OutPoint, TxOut) {
    let script = TransparentAddress::from_pubkey(pk).script().into();
    (
        OutPoint::new([txid_byte; 32], vout),
        TxOut::new(Zatoshis::const_from_u64(value), script),
    )
}

fn recipient() -> orchard::Address {
    let sk = orchard::keys::SpendingKey::from_bytes([3u8; 32]).unwrap();
    orchard::keys::FullViewingKey::from(&sk).address_at(0u32, Scope::External)
}

/// ZIP-317: 5_000 zat per logical action, summed across bundles, with each
/// non-empty shielded bundle padded to 2 actions. A shielding tx has n
/// transparent inputs, no transparent outputs, no orchard bundle and one padded
/// (2-action) ironwood bundle => 5_000 * (ceil(148n/150) + 2).
///
/// `ceil(148n/150)` equals n only up to n = 74; it is NOT the input count.
#[test]
fn zip317_shielding_fee_matches_the_padded_action_count() {
    assert_eq!(zip317_shielding_fee(1), 15_000);
    // The regression this constant exists for: 2 inputs is 4 logical actions =
    // 20_000 zat, NOT 10_000. Under-fee'ing here is what zebra rejects with
    // "Unpaid actions is higher than the limit".
    assert_eq!(zip317_shielding_fee(2), 20_000);
    assert_eq!(zip317_shielding_fee(3), 25_000);
    assert_eq!(zip317_shielding_fee(10), 60_000);
    // The transparent byte total crosses a 150-byte boundary at n = 75:
    // 148*75 == 11_100 == 74*150, so 74 transparent actions, not 75.
    assert_eq!(zip317_shielding_fee(75), 380_000);
}

#[test]
fn shields_transparent_utxos_into_one_ironwood_output() {
    let (sk, pk) = test_key();
    let inputs = vec![coin(&pk, 200_000, 0xa1, 0), coin(&pk, 50_000, 0xa2, 1)];
    let total_in: u64 = 250_000;
    let fee = zip317_shielding_fee(inputs.len());
    assert_eq!(fee, 20_000);

    let tx_bytes = build_shielding_transaction_ironwood_core(
        Nu63TestNet,
        &sk,
        &inputs,
        recipient(),
        fee,
        TARGET_HEIGHT,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("ironwood shielding build must succeed");

    let tx = Transaction::read(&tx_bytes[..], BranchId::Nu6_3).expect("tx parses");
    assert_eq!(tx.version(), TxVersion::V6, "must be a V6 transaction");
    assert_eq!(
        u32::from(tx.consensus_branch_id()),
        NU6_3_BRANCH_ID,
        "must bind the real NU6.3 consensus branch id"
    );

    // Transparent side: both inputs present, no transparent change output, and
    // every script_sig ends with our compressed pubkey push.
    let transparent = tx.transparent_bundle().expect("transparent bundle present");
    assert_eq!(transparent.vin.len(), 2, "expected 2 transparent inputs");
    assert_eq!(transparent.vout.len(), 0, "expected no transparent outputs");
    for vin in &transparent.vin {
        let script = format!("{:?}", vin.script_sig());
        assert!(
            script.contains(&hex::encode(pk.serialize())),
            "script_sig must push the signing pubkey; got {script}"
        );
    }

    // Shielded side: an ironwood bundle only - NO orchard bundle (a shielding tx
    // has neither orchard spends nor orchard outputs, which is why the builder
    // passes orchard_anchor: None).
    assert!(
        tx.orchard_bundle().is_none(),
        "ironwood shielding must not create an orchard bundle"
    );
    let ironwood = tx.ironwood_bundle().expect("ironwood bundle present");
    assert_eq!(
        ironwood.actions().len(),
        2,
        "output-only ironwood bundle is padded to exactly 2 actions"
    );

    // Value conservation: everything except the fee moves into the ironwood
    // pool, so the ironwood value balance (value LEAVING the pool) is negative
    // and equals -(total_in - fee).
    let ironwood_vb: i64 = (*ironwood.value_balance()).into();
    assert_eq!(
        ironwood_vb,
        -((total_in - fee) as i64),
        "ironwood value balance must equal -(inputs - fee)"
    );

    // ZIP-317 sanity on the tx as actually built: 2 transparent inputs + 2
    // padded ironwood actions = 4 logical actions = 20_000 zat.
    let logical = transparent.vin.len() + ironwood.actions().len();
    assert_eq!(5_000 * logical as u64, fee);
}

#[test]
fn refuses_an_underpaid_fee() {
    let (sk, pk) = test_key();
    let inputs = vec![coin(&pk, 200_000, 0xb1, 0), coin(&pk, 50_000, 0xb2, 1)];
    // The historical bug: 10_000 where 20_000 is required.
    let err = build_shielding_transaction_ironwood_core(
        Nu63TestNet,
        &sk,
        &inputs,
        recipient(),
        10_000,
        TARGET_HEIGHT,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect_err("must refuse a fee below the ZIP-317 conventional fee");
    assert!(
        err.contains("ZIP-317") && err.contains("20000"),
        "unexpected under-fee error: {err}"
    );
}

#[test]
fn refuses_a_mismatched_or_placeholder_branch_id() {
    let (sk, pk) = test_key();
    let inputs = vec![coin(&pk, 200_000, 0xc1, 0)];
    let fee = zip317_shielding_fee(1);

    let err = build_shielding_transaction_ironwood_core(
        Nu63TestNet,
        &sk,
        &inputs,
        recipient(),
        fee,
        TARGET_HEIGHT,
        0xdead_beef,
        MemoBytes::empty(),
    )
    .expect_err("must refuse a mismatched branch id");
    assert!(
        err.contains("branch id") || err.contains("mismatch"),
        "unexpected error for mismatched branch id: {err}"
    );

    let err = build_shielding_transaction_ironwood_core(
        Nu63TestNet,
        &sk,
        &inputs,
        recipient(),
        fee,
        TARGET_HEIGHT,
        0xffff_ffff,
        MemoBytes::empty(),
    )
    .expect_err("must refuse the placeholder branch id");
    assert!(
        err.contains("placeholder"),
        "unexpected error for placeholder branch id: {err}"
    );
}

#[test]
fn refuses_a_pre_nu6_3_target_height() {
    let (sk, pk) = test_key();
    let inputs = vec![coin(&pk, 200_000, 0xd1, 0)];
    // Height 5 is before this fixture's NU6.3 activation (10), so the tx would
    // bind a pre-NU6.3 branch and the ironwood bundle would be invalid.
    let err = build_shielding_transaction_ironwood_core(
        Nu63TestNet,
        &sk,
        &inputs,
        recipient(),
        zip317_shielding_fee(1),
        5,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect_err("must refuse to build before NU6.3 activation");
    assert!(
        err.contains("NU6.3 not active"),
        "unexpected pre-activation error: {err}"
    );
}

#[test]
fn refuses_a_utxo_not_locked_to_the_signing_key() {
    let (sk, _pk) = test_key();
    let other = secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
    let other_pk = other.public_key(&secp256k1::Secp256k1::signing_only());
    let inputs = vec![coin(&other_pk, 200_000, 0xe1, 0)];
    let err = build_shielding_transaction_ironwood_core(
        Nu63TestNet,
        &sk,
        &inputs,
        recipient(),
        zip317_shielding_fee(1),
        TARGET_HEIGHT,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect_err("must refuse a UTXO locked to a different key");
    assert!(
        err.contains("P2PKH output locked"),
        "unexpected foreign-utxo error: {err}"
    );
}

#[test]
fn refuses_when_inputs_do_not_cover_the_fee() {
    let (sk, pk) = test_key();
    let inputs = vec![coin(&pk, 10_000, 0xf1, 0)];
    let err = build_shielding_transaction_ironwood_core(
        Nu63TestNet,
        &sk,
        &inputs,
        recipient(),
        zip317_shielding_fee(1),
        TARGET_HEIGHT,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect_err("must refuse when the inputs cannot cover the fee");
    assert!(
        err.contains("insufficient funds"),
        "unexpected insufficient-funds error: {err}"
    );
}

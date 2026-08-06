//! REAL-VALIDATOR end-to-end for the two ironwood money paths, against a local
//! zebrad Regtest chain with NU6.3 (Ironwood) active from block 1.
//!
//! Everything else in this repo proves the ironwood paths *locally*
//! (build → prove → sign → extract → re-verify). This file is the only place
//! where a consensus node gets a vote: each transaction is submitted with
//! `sendrawtransaction`, mined, and read back out of the block with
//! `getblock <height> 2`.
//!
//! Paths covered:
//!   1. t→z: a transparent P2PKH coinbase UTXO into one ironwood output, via
//!      `build_shielding_transaction_ironwood_core`
//!   2. z→t: that ironwood note back out to a transparent address with ironwood
//!      change, via `build_signed_ironwood_send_core`
//!
//! This test is `#[ignore]`d because it needs a node. To run it:
//!
//!   # 1. build a zebrad that knows about NU6.3 (any recent ZF main; v6.2.3+)
//!   git clone --depth 1 https://github.com/ZcashFoundation/zebra
//!   cargo build --release -p zebrad --manifest-path zebra/Cargo.toml
//!
//!   # 2. start the regtest chain (config lives in this repo)
//!   zebra/target/release/zebrad \
//!       --config deploy/regtest/zebrad-regtest.toml start &
//!
//!   # 3. run this test (--release is needed to prove; do NOT set RUSTFLAGS -
//!   #    NU6.3 is ungated upstream, and a command-line RUSTFLAGS REPLACES the
//!   #    rustflags array in .cargo/config.toml wholesale)
//!   cargo test --release -p zafu-wasm --test regtest_ironwood_e2e \
//!       -- --ignored --nocapture
//!
//! Or just `deploy/regtest/run-ironwood-e2e.sh`, which does all three.
//!
//! `ZEBRAD_RPC` overrides the RPC endpoint (default `http://127.0.0.1:28232`).
//!
//! It talks JSON-RPC over `curl` rather than pulling an HTTP client into this
//! crate's dependency graph; the crate ships to wasm and does not want one.

mod common;

use common::{
    encode_p2pkh, ironwood_pool_zat, ironwood_tree_size, mine, node_conventional_fee,
    p2pkh_script_hex, rpc, rpc_ok, tip_height, transparent_key, two_leaf_merkle_path, wallet_keys,
    COINBASE_MATURITY, MARGINAL_FEE,
};

use serde_json::json;

use orchard::keys::Scope;
use zafu_wasm::{
    build_shielding_transaction_ironwood_core, build_signed_ironwood_send_core,
    zip317_shielding_fee, IronwoodRecipient, NU6_3_BRANCH_ID,
};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::bundle::{OutPoint, TxOut};

// ---------------------------------------------------------------------------
// consensus params matching deploy/regtest/zebrad-regtest.toml
// ---------------------------------------------------------------------------

/// Regtest with every network upgrade, including NU6.3, live from height 1 -
/// exactly what `[network.testnet_parameters.activation_heights]` in
/// `deploy/regtest/zebrad-regtest.toml` configures the node with.
#[derive(Clone, Copy, Debug)]
struct RegtestNu63;

impl Parameters for RegtestNu63 {
    fn network_type(&self) -> NetworkType {
        NetworkType::Regtest
    }
    fn activation_height(&self, _nu: NetworkUpgrade) -> Option<BlockHeight> {
        Some(BlockHeight::from_u32(1))
    }
}

// ---------------------------------------------------------------------------
// the test
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs a local zebrad regtest node; see the module docs"]
fn regtest_shields_into_ironwood_then_withdraws_to_transparent() {
    // ---- 0. the node must actually be an NU6.3 regtest chain ---------------
    let info = rpc_ok("getblockchaininfo", json!([]));
    let upgrades = &info["upgrades"];
    let nu63 = upgrades
        .get(format!("{NU6_3_BRANCH_ID:08x}"))
        .unwrap_or_else(|| {
            panic!(
                "node does not know the NU6.3 branch id {NU6_3_BRANCH_ID:08x}; upgrades: {upgrades}"
            )
        });
    assert_eq!(
        nu63["activationheight"].as_u64(),
        Some(1),
        "NU6.3 must activate at height 1 on this chain"
    );
    assert!(
        info["valuePools"]
            .as_array()
            .expect("valuePools")
            .iter()
            .any(|p| p["id"] == "ironwood"),
        "node reports no ironwood value pool"
    );

    // ---- 1. mine to a transparent address we hold the key for --------------
    let (t_sk, t_pk) = transparent_key(7);
    let miner_addr = encode_p2pkh(&t_pk);
    println!("regtest miner address: {miner_addr}");

    let start = tip_height();
    if start < COINBASE_MATURITY + 5 {
        mine(COINBASE_MATURITY + 5 - start, &miner_addr);
    }
    let tip = tip_height();
    assert!(
        tip >= COINBASE_MATURITY + 5,
        "mining did not advance the tip"
    );

    // NU6.3 is live from block 1, so every block on this chain is post-Ironwood.
    let block1 = rpc_ok("getblock", json!(["1", 2]));
    assert_eq!(
        ironwood_tree_size(&block1),
        0,
        "a transparent-coinbase regtest chain must leave the ironwood tree empty"
    );

    // ---- 2. pick a mature coinbase UTXO ------------------------------------
    let coinbase = &block1["tx"][0];
    let txid_hex = coinbase["txid"]
        .as_str()
        .expect("coinbase txid")
        .to_string();
    let vout0 = &coinbase["vout"][0];
    let value_zat = vout0["valueZat"]
        .as_u64()
        .or_else(|| vout0["value"].as_f64().map(|z| (z * 1e8).round() as u64))
        .expect("coinbase output value");
    let node_script_hex = vout0["scriptPubKey"]["hex"]
        .as_str()
        .expect("scriptPubKey hex")
        .to_string();

    // The script we will sign against must be byte-identical to the one the
    // node recorded, or the signature binds the wrong scriptCode.
    assert_eq!(
        p2pkh_script_hex(&t_pk),
        node_script_hex,
        "the node's coinbase scriptPubKey is not the P2PKH script for our key"
    );
    let our_script: zcash_transparent::address::Script =
        TransparentAddress::from_pubkey(&t_pk).script().into();

    let mut txid_le = hex::decode(&txid_hex).expect("hex txid");
    txid_le.reverse(); // RPC prints txids big-endian; OutPoint wants internal order
    let outpoint = OutPoint::new(txid_le.try_into().expect("32-byte txid"), 0);
    let utxo = TxOut::new(
        Zatoshis::from_u64(value_zat).expect("valid coinbase value"),
        our_script,
    );
    println!("spending coinbase {txid_hex}:0 worth {value_zat} zat");

    // ---- 3. t→z: shield the coinbase into the ironwood pool -----------------
    let (fvk, ask) = wallet_keys(
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about",
    );
    let recipient = fvk.address_at(0u32, Scope::External);

    let shield_fee = zip317_shielding_fee(1);
    assert_eq!(shield_fee, 15_000, "1 input + 2 padded ironwood actions");

    let target_height = tip_height() + 1;
    let shield_bytes = build_shielding_transaction_ironwood_core(
        RegtestNu63,
        &t_sk,
        &[(outpoint, utxo)],
        recipient,
        shield_fee,
        target_height,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("ironwood shielding build must succeed");

    let shield_txid = rpc("sendrawtransaction", json!([hex::encode(&shield_bytes)]))
        .unwrap_or_else(|e| panic!("NODE REJECTED the t→z ironwood shielding tx: {e}"));
    let shield_txid = shield_txid.as_str().expect("txid string").to_string();
    println!("t→z shielding accepted into the mempool: {shield_txid}");

    mine(1, &miner_addr);
    let shield_height = tip_height();
    let block = rpc_ok("getblock", json!([shield_height.to_string(), 2]));
    let mined = block["tx"]
        .as_array()
        .expect("block tx array")
        .iter()
        .find(|t| t["txid"] == shield_txid.as_str())
        .unwrap_or_else(|| {
            panic!("the shielding tx was accepted but not mined into {shield_height}")
        });

    assert_eq!(
        mined["version"].as_u64(),
        Some(6),
        "must be mined as a V6 tx"
    );
    let iw = &mined["ironwood"];
    assert!(!iw.is_null(), "mined tx has no ironwood bundle: {mined}");
    assert_eq!(
        iw["actions"].as_array().map(|a| a.len()),
        Some(2),
        "output-only ironwood bundle is padded to 2 actions"
    );
    let node_value_balance = iw["valueBalanceZat"].as_i64().expect("valueBalanceZat");
    assert_eq!(
        node_value_balance,
        -((value_zat - shield_fee) as i64),
        "node's ironwood value balance must equal -(input - fee)"
    );
    assert!(
        mined["orchard"].is_null()
            || mined["orchard"]["actions"]
                .as_array()
                .is_none_or(|a| a.is_empty()),
        "an ironwood shielding tx must not carry orchard actions"
    );
    assert_eq!(
        ironwood_tree_size(&block),
        2,
        "the ironwood commitment tree must have grown by exactly the 2 padded actions"
    );
    assert_eq!(
        ironwood_pool_zat(&block),
        (value_zat - shield_fee) as i64,
        "the node's ironwood value pool must now hold the shielded value"
    );

    // The fee the node actually charged, straight out of consensus arithmetic:
    // transparent in - transparent out + (value entering the shielded pool).
    let node_fee = (value_zat as i64) + node_value_balance;
    assert_eq!(
        node_fee, shield_fee as i64,
        "node-accepted fee disagrees with zip317_shielding_fee"
    );
    // And the ZIP-317 arithmetic the node used to decide it was paid enough:
    // max(ceil(148/150), 0) transparent + 2 ironwood = 3 logical actions.
    assert_eq!(
        shield_fee,
        MARGINAL_FEE * 3,
        "ZIP-317 logical actions for this shape"
    );
    assert_eq!(
        node_conventional_fee(mined),
        shield_fee,
        "ZIP-317 conventional fee recomputed from the MINED tx disagrees with \
         zip317_shielding_fee"
    );
    println!("t→z MINED at {shield_height}, node-accepted fee {node_fee} zat");

    // ---- 4. recover the note we just created -------------------------------
    let tx = Transaction::read(&shield_bytes[..], BranchId::Nu6_3).expect("our own tx parses");
    assert_eq!(tx.version(), TxVersion::V6);
    let bundle = tx.ironwood_bundle().expect("ironwood bundle");
    let cmxs: Vec<_> = bundle.actions().iter().map(|a| *a.cmx()).collect();

    let ivk = orchard::keys::PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let (position, note) = bundle
        .actions()
        .iter()
        .enumerate()
        .find_map(|(i, action)| {
            let domain = orchard::note_encryption::IronwoodDomain::for_action(action);
            zcash_note_encryption::try_note_decryption(&domain, &ivk, action)
                .map(|(note, _addr, _memo): (orchard::Note, _, [u8; 512])| (i as u32, note))
        })
        .expect("our ironwood output must decrypt with our own ivk");
    let note_value = note.value().inner();
    assert_eq!(
        note_value,
        value_zat - shield_fee,
        "the decrypted ironwood note must hold the whole shielded amount"
    );
    println!("decrypted our ironwood note: {note_value} zat at tree position {position}");

    // ---- 5. z→t: spend that note back out to a transparent address ---------
    let path = two_leaf_merkle_path(&cmxs, position);
    let anchor = path.root(cmxs[position as usize]);

    let (_withdraw_sk, withdraw_pk) = transparent_key(9);
    let withdraw_to = TransparentAddress::from_pubkey(&withdraw_pk);

    // ZIP-317 for this shape: max(0 tx_in, 1 tx_out) transparent
    // + max(1 ironwood spend, 1 ironwood change output) padded to 2
    // = 3 logical actions.
    let send_fee = MARGINAL_FEE * 3;
    let amount = note_value / 2;

    let target_height = tip_height() + 1;
    let send_bytes = build_signed_ironwood_send_core(
        RegtestNu63,
        &fvk,
        &ask,
        vec![(note, path)],
        IronwoodRecipient::Transparent(withdraw_to),
        amount,
        send_fee,
        anchor,
        target_height,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("ironwood send build must succeed");

    let send_txid = rpc("sendrawtransaction", json!([hex::encode(&send_bytes)]))
        .unwrap_or_else(|e| panic!("NODE REJECTED the z→t ironwood withdrawal: {e}"));
    let send_txid = send_txid.as_str().expect("txid string").to_string();
    println!("z→t withdrawal accepted into the mempool: {send_txid}");

    mine(1, &miner_addr);
    let send_height = tip_height();
    let block = rpc_ok("getblock", json!([send_height.to_string(), 2]));
    let mined = block["tx"]
        .as_array()
        .expect("block tx array")
        .iter()
        .find(|t| t["txid"] == send_txid.as_str())
        .unwrap_or_else(|| panic!("the withdrawal was accepted but not mined into {send_height}"));

    assert_eq!(mined["version"].as_u64(), Some(6));
    let iw = &mined["ironwood"];
    assert!(
        !iw.is_null(),
        "mined withdrawal has no ironwood bundle: {mined}"
    );
    assert_eq!(
        iw["actions"].as_array().map(|a| a.len()),
        Some(2),
        "1 spend + 1 change output pads to a 2-action ironwood bundle"
    );
    let send_value_balance = iw["valueBalanceZat"].as_i64().expect("valueBalanceZat");
    assert_eq!(
        send_value_balance,
        (amount + send_fee) as i64,
        "value LEAVING the ironwood pool must be amount + fee"
    );

    // The transparent output really landed on the withdrawal address.
    let vouts = mined["vout"].as_array().expect("vout array");
    assert_eq!(vouts.len(), 1, "one transparent withdrawal output");
    let paid_zat = vouts[0]["valueZat"]
        .as_u64()
        .or_else(|| vouts[0]["value"].as_f64().map(|z| (z * 1e8).round() as u64))
        .expect("withdrawal output value");
    assert_eq!(
        paid_zat, amount,
        "the exchange-facing output must carry `amount`"
    );

    let node_fee = send_value_balance - (amount as i64);
    assert_eq!(
        node_fee, send_fee as i64,
        "node-accepted fee disagrees with our ironwood-send fee arithmetic"
    );
    assert_eq!(
        node_conventional_fee(mined),
        send_fee,
        "ZIP-317 conventional fee recomputed from the MINED withdrawal disagrees \
         with the fee we paid"
    );
    assert_eq!(
        ironwood_tree_size(&block),
        4,
        "the withdrawal's 2 padded actions must also be committed to the ironwood tree"
    );
    assert_eq!(
        ironwood_pool_zat(&block),
        (note_value - amount - send_fee) as i64,
        "the ironwood pool must be left holding exactly the change note"
    );
    println!("z→t MINED at {send_height}, node-accepted fee {node_fee} zat");

    // The nullifier is now spent: replaying the same transaction must fail.
    let replay = rpc("sendrawtransaction", json!([hex::encode(&send_bytes)]));
    assert!(
        replay.is_err(),
        "the node re-accepted an already-mined ironwood spend"
    );
    println!("double-spend correctly refused: {}", replay.unwrap_err());
}

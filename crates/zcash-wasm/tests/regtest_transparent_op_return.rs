//! REAL-VALIDATOR end-to-end for the THORChain deposit shape: a t->t
//! transaction [vault, OP_RETURN(memo), change] built unsigned by
//! `build_unsigned_transparent_core`, signed as the worker signs it, submitted
//! to a zebrad Regtest chain (NU6.3 live from block 1), mined, and read back
//! with `getblock <h> 2`.
//!
//! Coinbase can only be spent into a shielded pool, so the test first shields
//! a coinbase into ironwood and withdraws it z->t to the depositing key.
//!
//! Same node setup as `regtest_ironwood_e2e.rs`:
//!   zebrad --config deploy/regtest/zebrad-regtest.toml start &
//!   cargo test --release -p zafu-wasm --test regtest_transparent_op_return \
//!       -- --ignored --nocapture

mod common;

use common::{
    encode_p2pkh, mine, node_conventional_fee, p2pkh_script_hex, pool_cmxs_through,
    replayed_merkle_path, rpc, rpc_ok, tip_height, transparent_key, wallet_keys, ShieldedPool,
    COINBASE_MATURITY, MARGINAL_FEE,
};

use serde_json::{json, Value};

use orchard::keys::Scope;
use zafu_wasm::{
    build_shielding_transaction_ironwood_core, build_signed_ironwood_send_core,
    build_unsigned_transparent_core, complete_shielding_pczt_bytes, sign_transparent_sighash,
    zip317_shielding_fee, IronwoodRecipient, NU6_3_BRANCH_ID,
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::bundle::{OutPoint, TxOut};

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

const MEMO: &[u8] = b"=:ETH.USDC:0xf3e03d4905725065Cc2E342Fc56BD1769A29E322:0/1/0:zafu:50";

fn value_zat(vout: &Value) -> u64 {
    vout["valueZat"]
        .as_u64()
        .or_else(|| vout["value"].as_f64().map(|z| (z * 1e8).round() as u64))
        .expect("output value")
}

fn send_and_mine(tx: &[u8], what: &str, miner: &str) -> Value {
    let txid = rpc("sendrawtransaction", json!([hex::encode(tx)]))
        .unwrap_or_else(|e| panic!("NODE REJECTED the {what}: {e}"));
    let txid = txid.as_str().expect("txid string").to_string();
    mine(1, miner);
    let block = rpc_ok("getblock", json!([tip_height().to_string(), 2]));
    block["tx"]
        .as_array()
        .expect("block tx array")
        .iter()
        .find(|t| t["txid"] == txid.as_str())
        .unwrap_or_else(|| panic!("the {what} was accepted but not mined"))
        .clone()
}

#[test]
#[ignore = "needs a local zebrad regtest node; see the module docs"]
fn regtest_thorchain_deposit_with_op_return() {
    let (t_sk, t_pk) = transparent_key(7);
    let miner = encode_p2pkh(&t_pk);
    let start = tip_height();
    if start < COINBASE_MATURITY + 5 {
        mine(COINBASE_MATURITY + 5 - start, &miner);
    }

    // ---- coinbase -> ironwood ----------------------------------------------
    // use the newest mature coinbase so a shared chain doesn't double-spend
    // what `regtest_ironwood_e2e` already used
    let cb_height = tip_height() - COINBASE_MATURITY;
    let cb_block = rpc_ok("getblock", json!([cb_height.to_string(), 2]));
    let cb = &cb_block["tx"][0];
    assert_eq!(
        cb["vout"][0]["scriptPubKey"]["hex"].as_str().unwrap(),
        p2pkh_script_hex(&t_pk)
    );
    let cb_value = value_zat(&cb["vout"][0]);
    let mut txid_le = hex::decode(cb["txid"].as_str().unwrap()).unwrap();
    txid_le.reverse();
    let cb_coin = (
        OutPoint::new(txid_le.try_into().unwrap(), 0),
        TxOut::new(
            Zatoshis::from_u64(cb_value).unwrap(),
            TransparentAddress::from_pubkey(&t_pk).script().into(),
        ),
    );

    let (fvk, ask) = wallet_keys(
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about",
    );
    let shield_fee = zip317_shielding_fee(1);
    let shield = build_shielding_transaction_ironwood_core(
        RegtestNu63,
        &t_sk,
        &[cb_coin],
        fvk.address_at(77u32, Scope::External),
        shield_fee,
        tip_height() + 1,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("shield builds");
    send_and_mine(&shield, "t->z shielding", &miner);

    // ---- ironwood -> depositor t-addr --------------------------------------
    let tx = Transaction::read(&shield[..], BranchId::Nu6_3).unwrap();
    let bundle = tx.ironwood_bundle().expect("ironwood bundle");
    let ivk = orchard::keys::PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let (note, cmx) = bundle
        .actions()
        .iter()
        .find_map(|a| {
            let domain = orchard::note_encryption::IronwoodDomain::for_action(a);
            zcash_note_encryption::try_note_decryption(&domain, &ivk, a)
                .map(|(n, _, _): (orchard::Note, _, [u8; 512])| (n, *a.cmx()))
        })
        .expect("our note decrypts");
    let anchor_height = tip_height();
    let cmxs = pool_cmxs_through(anchor_height, ShieldedPool::Ironwood);
    let position = cmxs.iter().position(|c| *c == cmx).expect("note in tree") as u64;
    let (anchor, path) = replayed_merkle_path(&cmxs, position);

    let (dep_sk, dep_pk) = transparent_key(11);
    let withdraw_amount = note.value().inner() / 2;
    let withdraw_fee = MARGINAL_FEE * 3;
    let withdraw = build_signed_ironwood_send_core(
        RegtestNu63,
        &fvk,
        &ask,
        vec![(note, path)],
        IronwoodRecipient::Transparent(TransparentAddress::from_pubkey(&dep_pk)),
        withdraw_amount,
        withdraw_fee,
        anchor,
        tip_height() + 1,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("withdraw builds");
    let mined = send_and_mine(&withdraw, "z->t withdrawal", &miner);
    let mut w_txid = hex::decode(mined["txid"].as_str().unwrap()).unwrap();
    w_txid.reverse();
    let dep_coin = (
        OutPoint::new(w_txid.try_into().unwrap(), 0),
        TxOut::new(
            Zatoshis::from_u64(withdraw_amount).unwrap(),
            TransparentAddress::from_pubkey(&dep_pk).script().into(),
        ),
    );

    // ---- the deposit: t->t [vault, OP_RETURN, change] ----------------------
    let (_, vault_pk) = transparent_key(13);
    let vault = TransparentAddress::from_pubkey(&vault_pk);
    let deposit_amount = withdraw_amount / 3;
    let unsigned = build_unsigned_transparent_core(
        RegtestNu63,
        &dep_pk,
        &[dep_coin],
        vault,
        deposit_amount,
        MEMO,
        tip_height() + 1,
        NU6_3_BRANCH_ID,
    )
    .expect("deposit builds");
    let sigs: Vec<Vec<u8>> = unsigned
        .sighashes
        .iter()
        .map(|h| sign_transparent_sighash(&dep_sk, *h))
        .collect();
    let deposit = complete_shielding_pczt_bytes(&unsigned.pczt_bytes, &sigs).expect("signs");
    let (fee, change) = (unsigned.plan.fee, unsigned.plan.change);
    println!("deposit tx hex: {}", hex::encode(&deposit));
    let mined = send_and_mine(&deposit, "t->t OP_RETURN deposit", &miner);
    println!("deposit mined: {} (v{})", mined["txid"], mined["version"]);
    assert_eq!(
        mined["version"].as_u64(),
        Some(5),
        "transparent-only deposits are V5"
    );

    let vout = mined["vout"].as_array().expect("vout");
    assert_eq!(vout.len(), 3, "[vault, OP_RETURN, change]: {mined}");
    assert_eq!(value_zat(&vout[0]), deposit_amount);
    assert_eq!(
        vout[0]["scriptPubKey"]["hex"].as_str().unwrap(),
        p2pkh_script_hex(&vault_pk)
    );
    assert_eq!(value_zat(&vout[1]), 0);
    let mut want = vec![0x6a, MEMO.len() as u8];
    want.extend_from_slice(MEMO);
    assert_eq!(
        vout[1]["scriptPubKey"]["hex"].as_str().unwrap(),
        hex::encode(want)
    );
    assert_eq!(value_zat(&vout[2]), change);
    assert_eq!(
        vout[2]["scriptPubKey"]["hex"].as_str().unwrap(),
        p2pkh_script_hex(&dep_pk)
    );

    assert_eq!(withdraw_amount - deposit_amount - change, fee);
    assert_eq!(
        node_conventional_fee(&mined),
        fee,
        "fee must be exactly ZIP-317"
    );
    println!("deposit fee {fee} zat, change {change} zat");
}

//! Fund a poker-escrow SEAT address with a real ironwood deposit on a local regtest chain.
//!
//! This is the Layer-4 funding helper for the local ironwood sim: it shields a matured coinbase
//! UTXO into a single ironwood output paid to the escrow's seat unified address (`ESCROW_SEAT_UA`),
//! submits it with `sendrawtransaction`, and mines it. The running poker-escrow (scanning the same
//! zidecar/zebrad) then detects + credits the deposit.
//!
//!   ESCROW_SEAT_UA=uregtest1...  ZEBRAD_RPC=http://127.0.0.1:18232 \
//!     cargo test --release -p zafu-wasm --test fund_escrow_deposit -- --ignored --nocapture

mod common;

use common::{
    encode_p2pkh, mine, p2pkh_script_hex, rpc, rpc_ok, tip_height, transparent_key,
    COINBASE_MATURITY,
};
use serde_json::json;

use zafu_wasm::{build_shielding_transaction_ironwood_core, zip317_shielding_fee, NU6_3_BRANCH_ID};
use zcash_address::unified::{Address as UnifiedAddress, Container, Encoding, Receiver};
use zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters};
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

#[test]
#[ignore = "needs a local zebrad regtest node + a running escrow; see module docs"]
fn fund_escrow_seat_ironwood() {
    // ---- 0. chain must be NU6.3 regtest ------------------------------------
    let info = rpc_ok("getblockchaininfo", json!([]));
    let upgrades = &info["upgrades"];
    assert!(
        upgrades
            .get(format!("{NU6_3_BRANCH_ID:08x}"))
            .and_then(|u| u["activationheight"].as_u64())
            == Some(1),
        "chain is not an NU6.3-from-height-1 regtest node: {upgrades}"
    );

    // ---- 1. the escrow seat we're funding ----------------------------------
    let seat_ua = std::env::var("ESCROW_SEAT_UA").expect("set ESCROW_SEAT_UA to the seat address");
    let (_net, ua) = UnifiedAddress::decode(&seat_ua).expect("decode escrow seat UA");
    let raw: [u8; 43] = ua
        .items()
        .into_iter()
        .find_map(|r| match r {
            Receiver::Orchard(b) => Some(b),
            _ => None,
        })
        .expect("escrow seat UA has no orchard receiver");
    let recipient = orchard::Address::from_raw_address_bytes(&raw)
        .expect("escrow seat is a valid orchard addr");
    println!("funding escrow seat {}", &seat_ua[..40]);

    // ---- 2. mine a coinbase WE control, to maturity ------------------------
    let (t_sk, t_pk) = transparent_key(7);
    let miner_addr = encode_p2pkh(&t_pk);
    let first = tip_height() + 1; // first block whose coinbase pays our key
    mine(COINBASE_MATURITY + 2, &miner_addr);
    assert!(
        tip_height() >= first + COINBASE_MATURITY,
        "coinbase at {first} is not matured"
    );

    // ---- 3. pick that matured coinbase UTXO --------------------------------
    let block = rpc_ok("getblock", json!([first.to_string(), 2]));
    let (outpoint, utxo, value_zat) = coinbase_utxo(&block, &t_pk);

    // ---- 4. shield it into ONE ironwood output paid to the escrow seat ------
    let shield_fee = zip317_shielding_fee(1);
    let target_height = tip_height() + 1;
    let bytes = build_shielding_transaction_ironwood_core(
        RegtestNu63,
        &t_sk,
        &[(outpoint, utxo)],
        recipient,
        shield_fee,
        target_height,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("ironwood shielding build to escrow seat");

    let txid = rpc("sendrawtransaction", json!([hex::encode(&bytes)]))
        .unwrap_or_else(|e| panic!("node REJECTED the deposit tx: {e}"));
    let txid = txid.as_str().expect("txid").to_string();
    let deposit = value_zat - shield_fee;
    println!("DEPOSIT SENT: {deposit} zat -> escrow seat, txid {txid}");

    // 0-conf test: leave the deposit in the mempool so the escrow's mempool watcher can spot it
    // BEFORE any block confirms it (fast-UX path). Set SKIP_MINE=1 to exercise that.
    if std::env::var("SKIP_MINE").is_ok() {
        println!(
            "DEPOSIT LEFT IN MEMPOOL (SKIP_MINE) — escrow mempool watcher should flag it pending"
        );
        return;
    }

    mine(1, &miner_addr);
    let h = tip_height();
    let mined = rpc_ok("getblock", json!([h.to_string(), 2]));
    let found = mined["tx"]
        .as_array()
        .expect("tx array")
        .iter()
        .any(|t| t["txid"] == txid.as_str());
    assert!(found, "deposit tx was accepted but not mined into {h}");
    println!("DEPOSIT MINED at height {h}. escrow poller should now credit {deposit} zat.");
}

/// The vout-0 coinbase UTXO of `block`, checked to be payable to `t_pk`.
fn coinbase_utxo(block: &serde_json::Value, t_pk: &secp256k1::PublicKey) -> (OutPoint, TxOut, u64) {
    let coinbase = &block["tx"][0];
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
        .expect("scriptPubKey hex");
    assert_eq!(
        p2pkh_script_hex(t_pk),
        node_script_hex,
        "coinbase scriptPubKey is not our key's P2PKH"
    );
    let our_script: zcash_transparent::address::Script =
        TransparentAddress::from_pubkey(t_pk).script().into();
    let mut txid_le = hex::decode(&txid_hex).expect("hex txid");
    txid_le.reverse();
    let outpoint = OutPoint::new(txid_le.try_into().expect("32-byte txid"), 0);
    let utxo = TxOut::new(
        Zatoshis::from_u64(value_zat).expect("valid coinbase value"),
        our_script,
    );
    (outpoint, utxo, value_zat)
}

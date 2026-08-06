//! REAL-VALIDATOR end-to-end for the TURNSTILE path: a legacy ORCHARD note
//! migrated into the IRONWOOD pool, submitted to a local zebrad Regtest chain,
//! mined, and read back out of the block.
//!
//! This is the last ironwood money path that had no consensus node's vote, and
//! it is the one most exposed to the note-version split: upstream `orchard`
//! separates the note-encryption domains by note version and ENFORCES them
//! (`OrchardDomain` accepts only V2 plaintexts, lead byte `0x02`;
//! `IronwoodDomain` only V3, lead byte `0x03`). A turnstile migration spends a
//! V2 note and creates a V3 note in ONE transaction, so it is precisely where a
//! version-handling mistake hides. This file therefore not only submits the
//! migration, it decrypts the resulting ironwood note back out of the mined
//! bundle and asserts its value and its SCOPE.
//!
//! # Why this needs its own chain
//!
//! `deploy/regtest/zebrad-regtest.toml` activates NU6.3 at height 1, and a
//! turnstile test cannot be built on it: post-NU6.3, orchard OUTPUTS are
//! consensus-disabled, so there is no way to create the orchard note the
//! migration has to spend. (Orchard SPENDS remain enabled - that is exactly
//! what the turnstile is.) `deploy/regtest/zebrad-regtest-turnstile.toml`
//! therefore defers NU6.3 to height 200, which leaves a legal window for a
//! t→orchard shielding transaction below it. It also defers NU6.2 to 150,
//! because the Orchard Action circuit changed at NU6.2 and this repo's legacy
//! orchard shielding builder emits `BundleVersion::orchard_insecure_v1()`,
//! which only verifies under zebra's pre-NU6.2 key.
//!
//! # Shape of the test
//!
//!   1. mine past coinbase maturity, spend a mature transparent coinbase UTXO
//!      into an ORCHARD note (pre-NU6.3, NU6.1 branch id `0x4dec4df0`) and
//!      assert it really is an orchard note: it decrypts under `OrchardDomain`,
//!      NOT under `IronwoodDomain`, and the block's ORCHARD tree grew. Without
//!      that check a silently-ironwood note would make the whole test vacuous.
//!   2. mine past the NU6.3 activation height
//!   3. run the turnstile migration: spend that orchard note, create an
//!      ironwood note, `sendrawtransaction`, mine, `getblock <height> 2`
//!   4. assert on the MINED transaction: V6, both bundles present, the value
//!      balances point in opposite directions and differ by exactly the fee,
//!      and the ZIP-317 conventional fee recomputed from the mined bytes agrees
//!      with what the builder charged
//!   5. decrypt the ironwood output with our own ivk and assert it is CHANGE:
//!      it decrypts under the INTERNAL ivk and NOT the external one. A wallet
//!      that gets this wrong renders a migration as a large incoming payment.
//!   6. replay the migration and require the node to refuse it
//!
//! This test is `#[ignore]`d because it needs a node. To run it:
//!
//!   deploy/regtest/run-turnstile-e2e.sh
//!
//! or by hand:
//!
//!   # 1. a zebrad that knows about NU6.3 (any recent ZF main; v6.2.3+)
//!   zebra/target/release/zebrad \
//!       --config deploy/regtest/zebrad-regtest-turnstile.toml start &
//!
//!   # 2. run it. --release is needed to prove; do NOT set RUSTFLAGS - NU6.3 is
//!   #    ungated upstream, and a command-line RUSTFLAGS REPLACES the rustflags
//!   #    array in .cargo/config.toml wholesale.
//!   ZEBRAD_RPC=http://127.0.0.1:28242 \
//!     cargo test --release -p zafu-wasm --test regtest_turnstile_e2e \
//!     -- --ignored --nocapture
//!
//! `ZEBRAD_RPC` overrides the RPC endpoint (default `http://127.0.0.1:28242`,
//! deliberately NOT the 28232 the everything-at-height-1 harness uses, so the
//! two chains cannot be confused for one another).

mod common;

use common::{
    encode_p2pkh, ironwood_pool_zat, ironwood_tree_size, mine, node_conventional_fee,
    orchard_pool_zat, orchard_tree_size, p2pkh_script_hex, rpc, rpc_ok, set_default_rpc,
    tip_height, transparent_key, two_leaf_merkle_path, wallet_keys, COINBASE_MATURITY,
    MARGINAL_FEE,
};

use serde_json::json;

use orchard::keys::Scope;
use orchard::note_encryption::{IronwoodDomain, OrchardDomain};
use zafu_wasm::{
    build_shielding_transaction, build_signed_turnstile_migration_core, shielding_pool_for_height,
    zip317_shielding_fee, NU6_3_BRANCH_ID,
};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters};
use zcash_protocol::memo::MemoBytes;

// ---------------------------------------------------------------------------
// the chain this test expects
// ---------------------------------------------------------------------------

/// Default RPC endpoint of `deploy/regtest/zebrad-regtest-turnstile.toml`.
const TURNSTILE_RPC: &str = "http://127.0.0.1:28242";

/// NU6.3 activation height on that chain. Comfortably above the 100-block
/// coinbase maturity, so a coinbase can mature AND be shielded into orchard
/// before Ironwood turns orchard outputs off.
const NU6_3_HEIGHT: u32 = 200;

/// NU6.2 activation height on that chain; see the module docs for why it is not
/// 1 (the orchard circuit era has to match the legacy shielding builder).
const NU6_2_HEIGHT: u32 = 150;

/// Consensus branch id of NU6.1, the era the shielding transaction is mined in.
const NU6_1_BRANCH_ID: u32 = 0x4dec_4df0;

/// Regtest consensus params matching
/// `deploy/regtest/zebrad-regtest-turnstile.toml`: everything up to NU6.1 live
/// from block 1, NU6.2 at 150, NU6.3 at 200.
///
/// The deferred NU6.3 is the whole point - `BranchId::for_height` must resolve
/// to NU6.1 in the shielding window and to NU6.3 for the migration, exactly as
/// the node does.
#[derive(Clone, Copy, Debug)]
struct RegtestDeferredNu63;

impl Parameters for RegtestDeferredNu63 {
    fn network_type(&self) -> NetworkType {
        NetworkType::Regtest
    }
    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        Some(BlockHeight::from_u32(match nu {
            NetworkUpgrade::Nu6_3 => NU6_3_HEIGHT,
            NetworkUpgrade::Nu6_2 => NU6_2_HEIGHT,
            _ => 1,
        }))
    }
}

/// The wallet seed. Same phrase the other end-to-end tests use.
const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon about";

/// Encode an orchard address as a unified address string, which is what the
/// legacy `build_shielding_transaction` takes as its recipient. `mainnet=false`
/// there decodes with `TestNetwork`, so encode for testnet.
fn unified_address_for(addr: &orchard::Address) -> String {
    use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
    let ua = UnifiedAddress::try_from_items(vec![Receiver::Orchard(addr.to_raw_address_bytes())])
        .expect("a single orchard receiver is a valid unified address");
    ua.encode(&NetworkType::Test)
}

// ---------------------------------------------------------------------------
// the test
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs a local zebrad regtest node with a DEFERRED NU6.3; see the module docs"]
fn regtest_migrates_an_orchard_note_through_the_turnstile_into_ironwood() {
    set_default_rpc(TURNSTILE_RPC);

    // ---- 0. the node must be the DEFERRED-NU6.3 regtest chain --------------
    // Getting this wrong is the failure mode that matters: run against the
    // everything-at-height-1 chain and step 1 cannot even build.
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
        Some(NU6_3_HEIGHT as u64),
        "this test needs NU6.3 DEFERRED to height {NU6_3_HEIGHT} (config \
         deploy/regtest/zebrad-regtest-turnstile.toml), not the \
         everything-at-height-1 chain on port 28232"
    );
    let nu61 = upgrades
        .get(format!("{NU6_1_BRANCH_ID:08x}"))
        .expect("node must know the NU6.1 branch id");
    assert_eq!(
        nu61["activationheight"].as_u64(),
        Some(1),
        "the pre-NU6.3 shielding window must be NU6.1 (the orchard circuit era \
         the legacy shielding builder targets)"
    );
    assert!(
        info["valuePools"]
            .as_array()
            .expect("valuePools")
            .iter()
            .any(|p| p["id"] == "ironwood"),
        "node reports no ironwood value pool"
    );

    // Our own params must agree with the node's, branch id for branch id.
    assert_eq!(
        u32::from(BranchId::for_height(
            &RegtestDeferredNu63,
            BlockHeight::from_u32(NU6_3_HEIGHT - 1)
        )),
        0x5437_f330,
        "the block before NU6.3 must be NU6.2 under our params too"
    );
    assert_eq!(
        u32::from(BranchId::for_height(
            &RegtestDeferredNu63,
            BlockHeight::from_u32(NU6_3_HEIGHT)
        )),
        NU6_3_BRANCH_ID,
        "our params must bind NU6.3 from the node's activation height"
    );

    // ---- 1. mine to a transparent address we hold the key for --------------
    let (t_sk, t_pk) = transparent_key(11);
    let miner_addr = encode_p2pkh(&t_pk);
    println!("regtest miner address: {miner_addr}");

    let start = tip_height();
    assert!(
        start < NU6_3_HEIGHT,
        "this chain must be FRESH: it is already at height {start}, past the \
         NU6.3 activation at {NU6_3_HEIGHT}, so no orchard output can be created"
    );
    if start < COINBASE_MATURITY + 5 {
        mine(COINBASE_MATURITY + 5 - start, &miner_addr);
    }
    let tip = tip_height();
    assert!(
        (COINBASE_MATURITY + 5..NU6_3_HEIGHT).contains(&tip),
        "the tip must be mature but still pre-NU6.3; it is {tip}"
    );

    // ---- 2. pick a mature coinbase UTXO ------------------------------------
    let block1 = rpc_ok("getblock", json!(["1", 2]));
    assert_eq!(
        orchard_tree_size(&block1),
        0,
        "a transparent-coinbase regtest chain must leave the orchard tree empty"
    );
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
    assert_eq!(
        p2pkh_script_hex(&t_pk),
        node_script_hex,
        "the node's coinbase scriptPubKey is not the P2PKH script for our key"
    );
    println!("spending coinbase {txid_hex}:0 worth {value_zat} zat");

    // ---- 3. t→orchard: create the legacy note the turnstile will migrate ---
    let (fvk, ask) = wallet_keys(SEED);
    // The shielding recipient is the wallet's EXTERNAL orchard address: this is
    // ordinary incoming money, the thing a user would actually be holding when
    // Ironwood strands it.
    let orchard_recipient = fvk.address_at(0u32, Scope::External);

    let shield_target_height = tip_height() + 1;
    // Sanity on the pool selector the wallet uses. Note that it is driven by the
    // compiled-in MAINNET/TESTNET activation constants, not by this chain's, so
    // on regtest heights it always answers "orchard"; the assertion below is
    // therefore about the pre-activation answer only, which is the one this step
    // relies on.
    assert_eq!(
        shielding_pool_for_height(shield_target_height, false),
        "orchard",
        "below NU6.3 the shielding pool must be orchard"
    );

    let shield_fee = zip317_shielding_fee(1);
    assert_eq!(
        shield_fee, 15_000,
        "1 transparent input (148 bytes → 1 action) + 2 padded orchard actions"
    );
    let shielded_value = value_zat - shield_fee;

    let utxos_json = json!([{
        "txid": txid_hex,
        "vout": 0,
        "value": value_zat,
        "script": node_script_hex,
    }])
    .to_string();

    let shield_hex = build_shielding_transaction(
        &utxos_json,
        &hex::encode(t_sk.secret_bytes()),
        &unified_address_for(&orchard_recipient),
        shielded_value,
        shield_fee,
        shield_target_height,
        false, // regtest decodes addresses as testnet
        Some(format!("{NU6_1_BRANCH_ID:08x}")),
    )
    .expect("legacy orchard shielding build must succeed pre-NU6.3");
    let shield_bytes = hex::decode(&shield_hex).expect("builder returns hex");

    let shield_txid = rpc("sendrawtransaction", json!([shield_hex]))
        .unwrap_or_else(|e| panic!("NODE REJECTED the t→orchard shielding tx: {e}"));
    let shield_txid = shield_txid.as_str().expect("txid string").to_string();
    println!("t→orchard shielding accepted into the mempool: {shield_txid}");

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
        Some(5),
        "the legacy orchard shielding tx is a V5 transaction"
    );
    let orch = &mined["orchard"];
    assert!(!orch.is_null(), "mined tx has no orchard bundle: {mined}");
    assert_eq!(
        orch["actions"].as_array().map(|a| a.len()),
        Some(2),
        "output-only orchard bundle is padded to 2 actions"
    );
    assert!(
        mined["ironwood"].is_null()
            || mined["ironwood"]["actions"]
                .as_array()
                .is_none_or(|a| a.is_empty()),
        "a pre-NU6.3 shielding tx must carry no ironwood actions"
    );
    // THIS is what makes the migration below non-vacuous: the value landed in
    // the ORCHARD pool and grew the ORCHARD tree, not the ironwood ones.
    assert_eq!(
        orchard_tree_size(&block),
        2,
        "the orchard commitment tree must have grown by exactly the 2 padded actions"
    );
    assert_eq!(
        ironwood_tree_size(&block),
        0,
        "the ironwood tree must still be empty after an orchard shielding"
    );
    assert_eq!(
        orchard_pool_zat(&block),
        shielded_value as i64,
        "the node's orchard value pool must now hold the shielded value"
    );
    assert_eq!(
        ironwood_pool_zat(&block),
        0,
        "the ironwood pool must still be empty"
    );
    assert_eq!(
        node_conventional_fee(mined),
        shield_fee,
        "ZIP-317 conventional fee recomputed from the MINED shielding tx \
         disagrees with zip317_shielding_fee"
    );
    println!("t→orchard MINED at {shield_height}, {shielded_value} zat into the orchard pool");

    // ---- 4. recover the ORCHARD note, and prove it IS an orchard note ------
    let tx = Transaction::read(&shield_bytes[..], BranchId::Nu6_1).expect("our own tx parses");
    assert_eq!(tx.version(), TxVersion::V5);
    let bundle = tx.orchard_bundle().expect("orchard bundle");
    let cmxs: Vec<orchard::note::ExtractedNoteCommitment> =
        bundle.actions().iter().map(|a| *a.cmx()).collect();

    let ext_ivk = orchard::keys::PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let (position, orchard_note) = bundle
        .actions()
        .iter()
        .enumerate()
        .find_map(|(i, action)| {
            let domain = OrchardDomain::for_action(action);
            zcash_note_encryption::try_note_decryption(&domain, &ext_ivk, action)
                .map(|(note, _addr, _memo): (orchard::Note, _, [u8; 512])| (i as u32, note))
        })
        .expect("our orchard output must decrypt under OrchardDomain with our external ivk");
    assert_eq!(
        orchard_note.value().inner(),
        shielded_value,
        "the decrypted orchard note must hold the whole shielded amount"
    );
    assert_eq!(
        orchard_note.version(),
        orchard::note::NoteVersion::V2,
        "a legacy orchard note is a V2 note (plaintext lead byte 0x02)"
    );
    // The version split is ENFORCED upstream, so the same action must NOT
    // decrypt under the ironwood domain. If this ever passes, the domains have
    // been merged again and the whole premise of this test is gone.
    assert!(
        bundle.actions().iter().all(|action| {
            let domain = IronwoodDomain::for_action(action);
            zcash_note_encryption::try_note_decryption(&domain, &ext_ivk, action)
                .map(|(n, _a, _m): (orchard::Note, _, [u8; 512])| n)
                .is_none()
        }),
        "an ORCHARD (V2) note decrypted under IronwoodDomain: the note-version \
         domains are no longer enforced"
    );
    println!(
        "decrypted our ORCHARD note: {shielded_value} zat at orchard tree position {position}"
    );

    // ---- 5. cross the turnstile: mine past NU6.3, then migrate -------------
    let now = tip_height();
    assert!(now < NU6_3_HEIGHT);
    mine(NU6_3_HEIGHT + 2 - now, &miner_addr);
    let tip = tip_height();
    assert!(
        tip >= NU6_3_HEIGHT,
        "failed to mine past the NU6.3 activation height"
    );
    // Nothing else touched the orchard tree in between, so the anchor from the
    // shielding block is still the tree's root.
    let tip_block = rpc_ok("getblock", json!([tip.to_string(), 2]));
    assert_eq!(
        orchard_tree_size(&tip_block),
        2,
        "nothing but our shielding tx may have touched the orchard tree"
    );

    let path = two_leaf_merkle_path(&cmxs, position);
    let orchard_anchor = path.root(cmxs[position as usize]);

    // ZIP-317 for a migration: 0 transparent, orchard 1 real spend padded to 2
    // actions, ironwood 1 real output padded to 2 actions. Logical actions SUM
    // ACROSS bundles, so 2 + 2 = 4 and the fee is 5000 * 4. That is exactly what
    // mainnet block 3,436,797 paid (orchard +385000, ironwood -365000).
    let migration_fee = MARGINAL_FEE * 4;
    assert_eq!(migration_fee, 20_000);
    let migrated = shielded_value - migration_fee;

    let target_height = tip_height() + 1;
    assert_eq!(
        u32::from(BranchId::for_height(
            &RegtestDeferredNu63,
            BlockHeight::from_u32(target_height)
        )),
        NU6_3_BRANCH_ID,
        "the migration must be built for an NU6.3-active height"
    );

    let migration_bytes = build_signed_turnstile_migration_core(
        RegtestDeferredNu63,
        &fvk,
        &ask,
        vec![(orchard_note, path)],
        migration_fee,
        orchard_anchor,
        target_height,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("turnstile migration build must succeed");

    let migration_txid = rpc("sendrawtransaction", json!([hex::encode(&migration_bytes)]))
        .unwrap_or_else(|e| panic!("NODE REJECTED the orchard→ironwood turnstile migration: {e}"));
    let migration_txid = migration_txid.as_str().expect("txid string").to_string();
    println!("turnstile migration accepted into the mempool: {migration_txid}");

    mine(1, &miner_addr);
    let migration_height = tip_height();
    let block = rpc_ok("getblock", json!([migration_height.to_string(), 2]));
    let mined = block["tx"]
        .as_array()
        .expect("block tx array")
        .iter()
        .find(|t| t["txid"] == migration_txid.as_str())
        .unwrap_or_else(|| {
            panic!("the migration was accepted but not mined into {migration_height}")
        });

    // ---- 6. assert on the MINED migration ----------------------------------
    assert_eq!(
        mined["version"].as_u64(),
        Some(6),
        "a turnstile migration must be mined as a V6 tx"
    );

    // BOTH bundles, in one transaction: this is the only shape that spans the
    // two pools, and the only one that can hide a note-version mistake.
    let orch = &mined["orchard"];
    let iw = &mined["ironwood"];
    assert!(
        !orch.is_null(),
        "mined migration has no orchard bundle (the spend): {mined}"
    );
    assert!(
        !iw.is_null(),
        "mined migration has no ironwood bundle (the output): {mined}"
    );
    assert_eq!(
        orch["actions"].as_array().map(|a| a.len()),
        Some(2),
        "1 real orchard spend pads to a 2-action bundle"
    );
    assert_eq!(
        iw["actions"].as_array().map(|a| a.len()),
        Some(2),
        "1 real ironwood output pads to a 2-action bundle"
    );

    let orchard_vb = orch["valueBalanceZat"].as_i64().expect("valueBalanceZat");
    let ironwood_vb = iw["valueBalanceZat"].as_i64().expect("valueBalanceZat");
    assert!(
        orchard_vb > 0,
        "orchard valueBalance must be POSITIVE (value LEAVING orchard); got {orchard_vb}"
    );
    assert!(
        ironwood_vb < 0,
        "ironwood valueBalance must be NEGATIVE (value ENTERING ironwood); got {ironwood_vb}"
    );
    assert_eq!(
        orchard_vb, shielded_value as i64,
        "the whole orchard note must leave the orchard pool"
    );
    assert_eq!(
        ironwood_vb,
        -(migrated as i64),
        "the ironwood pool must receive input - fee"
    );

    // The fee the node actually charged, straight out of consensus arithmetic.
    // There is no transparent bundle, so the difference of the two shielded
    // value balances IS the fee.
    assert!(
        mined["vin"].as_array().is_none_or(|a| a.is_empty())
            && mined["vout"].as_array().is_none_or(|a| a.is_empty()),
        "a turnstile migration has no transparent inputs or outputs"
    );
    let node_fee = orchard_vb + ironwood_vb;
    assert_eq!(
        node_fee, migration_fee as i64,
        "node-accepted fee (orchard {orchard_vb} + ironwood {ironwood_vb}) disagrees \
         with the fee the builder charged"
    );
    assert_eq!(
        node_conventional_fee(mined),
        migration_fee,
        "ZIP-317 conventional fee recomputed from the MINED migration disagrees \
         with the fee the builder charged"
    );

    // The two pools moved by exactly the right amounts.
    assert_eq!(
        orchard_pool_zat(&block),
        0,
        "the orchard pool must be drained by the migration"
    );
    assert_eq!(
        ironwood_pool_zat(&block),
        migrated as i64,
        "the ironwood pool must now hold the migrated value"
    );
    assert_eq!(
        orchard_tree_size(&block),
        4,
        "the migration's 2 padded orchard actions are committed to the orchard tree"
    );
    assert_eq!(
        ironwood_tree_size(&block),
        2,
        "the migration's 2 padded ironwood actions are committed to the ironwood tree"
    );
    println!(
        "turnstile MINED at {migration_height}: orchard {orchard_vb:+} / \
         ironwood {ironwood_vb:+}, node-accepted fee {node_fee} zat"
    );

    // ---- 7. the resulting IRONWOOD note decrypts with our own ivk ----------
    //
    // This is the assertion that would have caught the note-version regression:
    // a scanner that only ever tries `OrchardDomain` reads zero balance for the
    // whole ironwood pool, and 288 unit tests plus clean clippy said nothing.
    let migration_tx =
        Transaction::read(&migration_bytes[..], BranchId::Nu6_3).expect("our own tx parses");
    assert_eq!(migration_tx.version(), TxVersion::V6);
    assert_eq!(
        u32::from(migration_tx.consensus_branch_id()),
        NU6_3_BRANCH_ID
    );
    let iw_bundle = migration_tx
        .ironwood_bundle()
        .expect("ironwood bundle in our own bytes");
    assert!(
        migration_tx.orchard_bundle().is_some(),
        "our own bytes must also carry the orchard spend bundle"
    );

    let int_ivk = orchard::keys::PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::Internal));
    let decrypt_with = |ivk: &orchard::keys::PreparedIncomingViewingKey| {
        iw_bundle.actions().iter().find_map(|action| {
            let domain = IronwoodDomain::for_action(action);
            zcash_note_encryption::try_note_decryption(&domain, ivk, action).map(
                |(note, addr, _memo): (orchard::Note, orchard::Address, [u8; 512])| (note, addr),
            )
        })
    };

    let (ironwood_note, ironwood_addr) = decrypt_with(&int_ivk).expect(
        "the migrated ironwood output must decrypt under IronwoodDomain with our INTERNAL ivk",
    );
    assert_eq!(
        ironwood_note.value().inner(),
        migrated,
        "the decrypted ironwood note must hold input - fee"
    );
    assert_eq!(
        ironwood_note.version(),
        orchard::note::NoteVersion::V3,
        "an ironwood note is a V3 note (plaintext lead byte 0x03)"
    );

    // ---- 8. the migration output is CHANGE, not incoming income ------------
    //
    // It pays the wallet's own address at Scope::Internal. `mainnet_consensus_
    // fixtures::turnstile_self_output_is_internal_scope_hence_change` pins the
    // invariant in the abstract; this pins it on a transaction a validator
    // actually accepted. A wallet that reads this note under the EXTERNAL ivk
    // renders a migration of the user's own funds as a large incoming payment.
    assert_eq!(
        ironwood_addr.to_raw_address_bytes(),
        fvk.address_at(0u32, Scope::Internal).to_raw_address_bytes(),
        "the migration must pay the wallet's INTERNAL (change) address"
    );
    assert!(
        decrypt_with(&ext_ivk).is_none(),
        "the migrated ironwood output decrypted under the EXTERNAL ivk: a \
         wallet would render this migration as incoming income"
    );
    println!(
        "decrypted the migrated IRONWOOD note: {migrated} zat, internal scope (change), not income"
    );

    // ---- 9. the orchard nullifier really was consumed ----------------------
    let replay = rpc("sendrawtransaction", json!([hex::encode(&migration_bytes)]));
    assert!(
        replay.is_err(),
        "the node re-accepted an already-mined turnstile migration: the orchard \
         nullifier was not consumed"
    );
    println!(
        "migration replay correctly refused: {}",
        replay.unwrap_err()
    );
}

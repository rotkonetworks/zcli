//! The THORChain deposit: an unsigned t->t [vault, OP_RETURN(memo), change]
//! built from public data, signed the way the zcash worker signs it
//! (`SpendKeys.sign_shielding` = per-sighash ECDSA + the verifying PCZT
//! completion), at the ZIP-317 fee.
//!
//!   cargo test -p zafu-wasm --release --test transparent_op_return

use zafu_wasm::{
    build_unsigned_transparent_core, complete_shielding_pczt_bytes, null_data_tx_out_size,
    plan_transparent_spend, sign_transparent_sighash, zip317_transparent_fee, SpendKeys,
    TransparentPlan, UnsignedTransparent, NU6_3_BRANCH_ID, P2PKH_TX_OUT_SIZE,
};

use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{Authorization, Transaction, TransactionData, TxVersion};
use zcash_protocol::consensus::{
    BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters,
};
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::{Script, TransparentAddress};
use zcash_transparent::bundle::{MapAuth, OutPoint, TxOut};
use zcash_transparent::sighash::{SighashType, TransparentAuthorizingContext};

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

const TARGET: u32 = 100;
/// a real THORChain swap memo shape, 67 bytes
const MEMO: &[u8] = b"=:ETH.USDC:0xf3e03d4905725065Cc2E342Fc56BD1769A29E322:0/1/0:zafu:50";

fn key() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
    let sk = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
    (sk, sk.public_key(&secp256k1::Secp256k1::signing_only()))
}

fn coin(pk: &secp256k1::PublicKey, value: u64, txid_byte: u8) -> (OutPoint, TxOut) {
    (
        OutPoint::new([txid_byte; 32], 0),
        TxOut::new(
            Zatoshis::const_from_u64(value),
            TransparentAddress::from_pubkey(pk).script().into(),
        ),
    )
}

fn vault() -> TransparentAddress {
    TransparentAddress::PublicKeyHash([0x42; 20])
}

fn build(
    coins: &[(OutPoint, TxOut)],
    amount: u64,
    memo: &[u8],
) -> Result<UnsignedTransparent, String> {
    build_unsigned_transparent_core(
        Nu63TestNet,
        &key().1,
        coins,
        vault(),
        amount,
        memo,
        TARGET,
        NU6_3_BRANCH_ID,
    )
}

/// What the worker does with `SpendKeys.sign_shielding`: sign each sighash the
/// builder returned, then let the completion verify and extract.
fn sign(u: &UnsignedTransparent, sk: &secp256k1::SecretKey) -> Result<Transaction, String> {
    let sigs: Vec<Vec<u8>> = u
        .sighashes
        .iter()
        .map(|h| sign_transparent_sighash(sk, *h))
        .collect();
    let tx = complete_shielding_pczt_bytes(&u.pczt_bytes, &sigs)?;
    Ok(Transaction::read(&tx[..], BranchId::Nu6_3).expect("signed tx parses"))
}

#[derive(Debug)]
struct Prevouts(Vec<TxOut>);
impl zcash_transparent::bundle::Authorization for Prevouts {
    type ScriptSig = ();
}
impl TransparentAuthorizingContext for Prevouts {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.0.iter().map(|c| c.value()).collect()
    }
    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.0.iter().map(|c| c.script_pubkey().clone()).collect()
    }
}
struct WithPrevouts(Vec<TxOut>);
impl MapAuth<zcash_transparent::bundle::Authorized, Prevouts> for WithPrevouts {
    fn map_script_sig(&self, _: Script) {}
    fn map_authorization(&self, _: zcash_transparent::bundle::Authorized) -> Prevouts {
        Prevouts(self.0.clone())
    }
}
#[derive(Debug)]
struct SighashAuth;
impl Authorization for SighashAuth {
    type TransparentAuth = Prevouts;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

/// Recompute every input's ZIP-244 sighash from the signed tx and its prevouts,
/// independently of the PCZT, and check each scriptSig's ECDSA against it.
fn verify_transparent(tx: &Transaction, prevouts: &[TxOut]) {
    let bundle = tx.transparent_bundle().expect("transparent bundle").clone();
    let script_sigs: Vec<Vec<u8>> = bundle
        .vin
        .iter()
        .map(|i| i.script_sig().0 .0.clone())
        .collect();
    let data: TransactionData<SighashAuth> = TransactionData::from_parts(
        tx.version(),
        tx.consensus_branch_id(),
        tx.lock_time(),
        tx.expiry_height(),
        Some(bundle.map_authorization(WithPrevouts(prevouts.to_vec()))),
        None,
        None,
        None,
    );
    let txid_parts = data.digest(TxIdDigester);
    let tb = data.transparent_bundle().unwrap();
    let secp = secp256k1::Secp256k1::verification_only();
    for (i, (sig_script, prev)) in script_sigs.iter().zip(prevouts).enumerate() {
        // <len> <DER || 0x01> <33> <pubkey>
        let sig_len = sig_script[0] as usize;
        let der = &sig_script[1..sig_len];
        assert_eq!(sig_script[sig_len], 0x01, "input {i}: SIGHASH_ALL");
        assert_eq!(sig_script[sig_len + 1], 33);
        let pubkey = secp256k1::PublicKey::from_slice(&sig_script[sig_len + 2..]).unwrap();
        assert_eq!(
            prev.recipient_address(),
            Some(TransparentAddress::from_pubkey(&pubkey)),
            "input {i}: scriptSig pubkey owns the prevout"
        );
        let input = zcash_transparent::sighash::SignableInput::from_parts(
            tb,
            SighashType::ALL,
            i,
            prev.script_pubkey(),
            prev.script_pubkey(),
            prev.value(),
        )
        .unwrap();
        let sighash = signature_hash(&data, &SignableInput::Transparent(input), &txid_parts);
        secp.verify_ecdsa(
            &secp256k1::Message::from_digest(*sighash.as_ref()),
            &secp256k1::ecdsa::Signature::from_der(der).unwrap(),
            &pubkey,
        )
        .unwrap_or_else(|e| panic!("input {i}: signature does not verify: {e}"));
    }
}

fn op_return(data: &[u8]) -> Vec<u8> {
    let mut s = vec![0x6a];
    if data.len() > 75 {
        s.push(0x4c); // OP_PUSHDATA1
    }
    s.push(data.len() as u8);
    s.extend_from_slice(data);
    s
}

#[test]
fn zip317_fee_counts_the_op_return_bytes() {
    assert_eq!(null_data_tx_out_size(MEMO.len()), 8 + 1 + 1 + 1 + 67);
    assert_eq!(null_data_tx_out_size(80), 8 + 1 + 1 + 2 + 80);
    // [p2pkh, op_return(67), p2pkh] = 34 + 78 + 34 = 146 bytes -> 5 actions
    let outs = [
        P2PKH_TX_OUT_SIZE,
        null_data_tx_out_size(MEMO.len()),
        P2PKH_TX_OUT_SIZE,
    ];
    assert_eq!(zip317_transparent_fee(1, &outs), 25_000);
    assert_eq!(zip317_transparent_fee(5, &outs), 25_000);
    // inputs dominate once ceil(148n / 150) > 5
    assert_eq!(zip317_transparent_fee(7, &outs), 35_000);
    // a plain t->t with change is the 2-action floor
    assert_eq!(zip317_transparent_fee(1, &[P2PKH_TX_OUT_SIZE; 2]), 10_000);
}

#[test]
fn deposit_is_vault_then_memo_then_change_and_every_signature_verifies() {
    let (sk, pk) = key();
    let coins = [coin(&pk, 600_000, 1), coin(&pk, 400_000, 2)];
    let u = build(&coins, 700_000, MEMO).expect("builds");
    assert_eq!(
        u.plan,
        TransparentPlan {
            inputs: 2,
            total_in: 1_000_000,
            fee: 25_000,
            change: 275_000,
            short: 0
        }
    );
    assert_eq!(u.sighashes.len(), 2);

    let tx = sign(&u, &sk).expect("signs");
    assert_eq!(tx.version(), TxVersion::V5);
    assert_eq!(u32::from(tx.consensus_branch_id()), NU6_3_BRANCH_ID);
    assert!(tx.sapling_bundle().is_none() && tx.orchard_bundle().is_none());

    let t = tx.transparent_bundle().unwrap();
    assert_eq!(t.vout.len(), 3);
    assert_eq!(t.vout[0].value().into_u64(), 700_000);
    assert_eq!(t.vout[0].recipient_address(), Some(vault()));
    assert_eq!(t.vout[1].value().into_u64(), 0);
    assert_eq!(t.vout[1].script_pubkey().0 .0, op_return(MEMO));
    // change goes back to the address that funded vin[0]: THORChain's refund target
    let funding = TransparentAddress::from_pubkey(&pk);
    assert_eq!(t.vout[2].value().into_u64(), 275_000);
    assert_eq!(t.vout[2].recipient_address(), Some(funding));
    // largest coin first, so vin[0] is the 600k coin
    assert_eq!(t.vin[0].prevout(), &coins[0].0);
    let ins: u64 = 1_000_000;
    let outs: u64 = t.vout.iter().map(|o| o.value().into_u64()).sum();
    assert_eq!(ins - outs, 25_000, "fee is exactly the ZIP-317 fee");

    verify_transparent(&tx, &[coins[0].1.clone(), coins[1].1.clone()]);
}

#[test]
fn an_80_byte_memo_uses_pushdata1_and_fits() {
    let (sk, pk) = key();
    let memo = [b'm'; 80];
    let u = build(&[coin(&pk, 1_000_000, 1)], 300_000, &memo).expect("builds");
    let tx = sign(&u, &sk).unwrap();
    let script = &tx.transparent_bundle().unwrap().vout[1]
        .script_pubkey()
        .0
         .0;
    assert_eq!(&script[..3], &[0x6a, 0x4c, 0x50]);
    assert_eq!(script, &op_return(&memo));
}

#[test]
fn a_memo_over_80_bytes_is_refused() {
    let (_, pk) = key();
    let err = build(&[coin(&pk, 1_000_000, 1)], 300_000, &[b'x'; 81]).unwrap_err();
    assert!(err.contains("relay limit"), "{err}");
    assert!(plan_transparent_spend(&[1_000_000], 300_000, 81).is_err());
}

#[test]
fn dust_change_goes_to_the_fee() {
    let (sk, pk) = key();
    // 1_000 zat over amount + fee: no change output, the remainder is fee
    let u = build(&[coin(&pk, 326_000, 1)], 300_000, MEMO).expect("builds");
    assert_eq!((u.plan.fee, u.plan.change), (26_000, 0));
    let tx = sign(&u, &sk).unwrap();
    let t = tx.transparent_bundle().unwrap();
    assert_eq!(t.vout.len(), 2);
    assert_eq!(t.vout[1].script_pubkey().0 .0, op_return(MEMO));
}

#[test]
fn short_says_how_much_to_bring_and_then_it_builds() {
    let (sk, pk) = key();
    let plan = plan_transparent_spend(&[100_000], 300_000, MEMO.len()).unwrap();
    assert_eq!(plan.inputs, 0);
    // 2 inputs + [p2pkh, op_return, p2pkh] is still 5 actions
    assert_eq!(plan.short, 300_000 + 25_000 - 100_000);
    assert!(build(&[coin(&pk, 100_000, 1)], 300_000, MEMO)
        .unwrap_err()
        .contains("insufficient"));
    // one coin of exactly `short` covers it
    let u = build(
        &[coin(&pk, 100_000, 1), coin(&pk, plan.short, 2)],
        300_000,
        MEMO,
    )
    .unwrap();
    assert_eq!(u.plan.short, 0);
    sign(&u, &sk).unwrap();
}

#[test]
fn refuses_foreign_coins_wrong_branch_and_foreign_signatures() {
    let (_, pk) = key();
    let other_sk = secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
    let other_pk = other_sk.public_key(&secp256k1::Secp256k1::signing_only());
    let err = build(
        &[coin(&pk, 500_000, 1), coin(&other_pk, 500_000, 2)],
        1_000,
        MEMO,
    )
    .unwrap_err();
    assert!(err.contains("one address only"), "{err}");

    let wrong_branch = build_unsigned_transparent_core(
        Nu63TestNet,
        &pk,
        &[coin(&pk, 500_000, 1)],
        vault(),
        1_000,
        MEMO,
        TARGET,
        0xc8e7_1055,
    );
    assert!(wrong_branch.unwrap_err().contains("branch id"));

    // the completion checks each signature against the carrier's own sighash
    let u = build(&[coin(&pk, 500_000, 1)], 100_000, MEMO).unwrap();
    assert!(sign(&u, &other_sk).unwrap_err().contains("rejected"));
}

/// The worker's own path: the pubkey from `SpendKeys`, the unsigned build, then
/// `SpendKeys.sign_shielding` on the PCZT and its sighashes.
#[test]
fn spend_keys_pubkey_builds_a_deposit_the_worker_can_sign() {
    let seed = bip39::Mnemonic::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about",
    )
    .unwrap()
    .to_seed("");
    let keys = SpendKeys::from_seed_bytes(seed, 0, false).unwrap();
    let pk_hex = keys.transparent_pubkey(0).unwrap();
    let pk = secp256k1::PublicKey::from_slice(&hex::decode(pk_hex).unwrap()).unwrap();
    let u = build_unsigned_transparent_core(
        Nu63TestNet,
        &pk,
        &[coin(&pk, 900_000, 3)],
        vault(),
        500_000,
        MEMO,
        TARGET,
        NU6_3_BRANCH_ID,
    )
    .unwrap();
    assert_eq!(u.plan.change, 900_000 - 500_000 - 25_000);
    let sighashes: Vec<String> = u.sighashes.iter().map(hex::encode).collect();
    let signed = keys
        .sign_shielding(
            0,
            &hex::encode(&u.pczt_bytes),
            &serde_json::to_string(&sighashes).unwrap(),
        )
        .unwrap_or_else(|_| panic!("SpendKeys refused its own deposit"));
    let tx = Transaction::read(&hex::decode(signed).unwrap()[..], BranchId::Nu6_3).unwrap();
    verify_transparent(&tx, &[coin(&pk, 900_000, 3).1]);
}

/// Mainnet NU7: no crate table has its height, so the deposit binds the branch
/// the node reports. A V5 deposit stays valid under NU7 (ZIP 2003: version 5
/// or 6), and its sighash commits to the NU7 branch id.
#[test]
fn mainnet_deposit_builds_on_the_nu7_branch_the_node_reports() {
    use zafu_wasm::node_params::{NodeParams, NU7_BRANCH_ID};
    let (sk, pk) = key();
    let target = 3_500_000;
    let params = NodeParams::new(MainNetwork, NU7_BRANCH_ID, target);
    let u = build_unsigned_transparent_core(
        params,
        &pk,
        &[coin(&pk, 500_000, 1)],
        vault(),
        100_000,
        MEMO,
        target,
        NU7_BRANCH_ID,
    )
    .expect("builds on NU7");
    let tx = sign(&u, &sk).expect("signs");
    assert_eq!(tx.version(), TxVersion::V5);
    assert_eq!(tx.consensus_branch_id(), BranchId::Nu7);

    // and a node still on NU6.3 keeps the NU6.3 binding
    let nu63 = NodeParams::new(MainNetwork, NU6_3_BRANCH_ID, target);
    let u = build_unsigned_transparent_core(
        nu63,
        &pk,
        &[coin(&pk, 500_000, 1)],
        vault(),
        100_000,
        MEMO,
        target,
        NU6_3_BRANCH_ID,
    )
    .expect("builds on NU6.3");
    assert_eq!(
        sign(&u, &sk).unwrap().consensus_branch_id(),
        BranchId::Nu6_3
    );
}

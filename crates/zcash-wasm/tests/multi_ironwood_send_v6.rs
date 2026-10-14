//! IRONWOOD SEND TO SEVERAL RECIPIENTS (native): one V6 transaction spends a
//! REAL V3 ironwood note and pays every requested output - shielded ones with
//! their own memo, a transparent one as a real transparent output - plus one
//! change output back to the wallet. Proves on the post-NU6.3 circuit, signs
//! locally, extracts (which re-verifies the proof and every signature), then
//! decrypts each ironwood output with its recipient's viewing key and checks
//! value, recipient and memo, the change, the value balance and the branch id.
//!
//! Run with:
//!   cargo test --release --test multi_ironwood_send_v6
//! (--release: it builds the post-NU6.3 Halo 2 proving key and proves.)

use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey};
use zafu_wasm::{
    build_ironwood_send_pczt_proven_multi, build_signed_ironwood_send_multi_core,
    IronwoodRecipient, IronwoodSendOutput,
};
use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{Authorization, Transaction, TransactionData, TxVersion};
use zcash_protocol::consensus::{
    BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters,
};
use zcash_protocol::memo::MemoBytes;

#[derive(Debug)]
struct ShieldedSighashAuth;

impl Authorization for ShieldedSighashAuth {
    type TransparentAuth = zcash_transparent::bundle::EffectsOnly;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

/// NU6.3 active from height 10 (the fixture of signed_ironwood_send_v6.rs).
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

const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;
const TARGET: u32 = 10_000_000;
const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon about";
const MARGINAL_FEE: u64 = 5_000;

fn keys_from_seed(seed_phrase: &str, account: u32) -> (FullViewingKey, SpendAuthorizingKey) {
    let mnemonic = bip39::Mnemonic::parse(seed_phrase).expect("valid test mnemonic");
    let seed = mnemonic.to_seed("");
    let account_id = zip32::AccountId::try_from(account).unwrap();
    let sk = orchard::keys::SpendingKey::from_zip32_seed(&seed, 1, account_id).unwrap();
    (FullViewingKey::from(&sk), SpendAuthorizingKey::from(&sk))
}

/// A V3 note owned by `fvk`, a single-leaf witness and the anchor it yields.
fn owned_note_with_witness(
    fvk: &FullViewingKey,
    value: u64,
    rho_seed: u8,
) -> (
    orchard::Note,
    orchard::tree::MerklePath,
    orchard::tree::Anchor,
) {
    let rho = orchard::note::Rho::from_bytes(&[rho_seed; 32]).unwrap();
    let rseed = (0u8..=255)
        .find_map(|b| Option::from(orchard::note::RandomSeed::from_bytes([b; 32], &rho)))
        .expect("test rseed");
    let note: orchard::Note = Option::from(orchard::Note::from_parts(
        fvk.address_at(0u32, Scope::External),
        orchard::value::NoteValue::from_raw(value),
        rho,
        rseed,
        orchard::note::NoteVersion::V3,
    ))
    .expect("test note");
    let zero = Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&[0u8; 32])).unwrap();
    let witness = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
    let anchor = witness.root(note.commitment().into());
    (note, witness, anchor)
}

/// ZIP-317 for an ironwood send, as zafu's worker prices it.
fn zip317_fee(spends: usize, z_outputs: usize, t_outputs: usize, change: bool) -> u64 {
    let ironwood_actions = spends.max(z_outputs + usize::from(change)).max(2);
    MARGINAL_FEE * (ironwood_actions + t_outputs).max(2) as u64
}

fn memo(text: &str) -> MemoBytes {
    MemoBytes::from_bytes(text.as_bytes()).expect("test memo")
}

/// Every ironwood output `ivk` can decrypt: (value, recipient, memo).
fn decrypt_all(
    bundle: &orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>,
    fvk: &FullViewingKey,
    scope: Scope,
) -> Vec<(u64, orchard::Address, [u8; 512])> {
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(scope));
    bundle
        .actions()
        .iter()
        .filter_map(|action| {
            let domain = orchard::note_encryption::IronwoodDomain::for_action(action);
            zcash_note_encryption::try_note_decryption(&domain, &ivk, action).map(
                |(note, addr, memo): (orchard::Note, orchard::Address, [u8; 512])| {
                    (note.value().inner(), addr, memo)
                },
            )
        })
        .collect()
}

fn recipient_keys(seed: &str) -> FullViewingKey {
    keys_from_seed(seed, 0).0
}

#[test]
fn ironwood_send_pays_two_shielded_and_one_transparent_recipient_in_one_tx() {
    let (fvk, ask) = keys_from_seed(SEED, 0);
    let alice = recipient_keys(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    );
    let bob = recipient_keys(
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    );
    let alice_addr = alice.address_at(0u32, Scope::External);
    let bob_addr = bob.address_at(0u32, Scope::External);
    let taddr = zcash_transparent::address::TransparentAddress::PublicKeyHash([0x42u8; 20]);

    let note_value = 2_000_000u64;
    let (a_amt, b_amt, t_amt) = (300_000u64, 450_000u64, 250_000u64);
    // 1 spend, 2 shielded outputs + change = 3 ironwood actions, + 1 transparent
    let fee = zip317_fee(1, 2, 1, true);
    assert_eq!(fee, 20_000);
    let change = note_value - a_amt - b_amt - t_amt - fee;

    let (note, witness, anchor) = owned_note_with_witness(&fvk, note_value, 7);
    let tx_bytes = build_signed_ironwood_send_multi_core(
        Nu63TestNet,
        &fvk,
        &ask,
        vec![(note, witness)],
        vec![
            IronwoodSendOutput {
                recipient: IronwoodRecipient::Shielded(alice_addr),
                amount: a_amt,
                memo: memo("seat A deposit"),
            },
            IronwoodSendOutput {
                recipient: IronwoodRecipient::Transparent(taddr),
                amount: t_amt,
                memo: MemoBytes::empty(),
            },
            IronwoodSendOutput {
                recipient: IronwoodRecipient::Shielded(bob_addr),
                amount: b_amt,
                memo: memo("rake"),
            },
        ],
        fee,
        anchor,
        TARGET,
        NU6_3_BRANCH_ID,
    )
    .expect("build + sign a three-recipient ironwood send");

    let tx = Transaction::read(&tx_bytes[..], BranchId::Nu6_3).expect("tx parses");
    assert_eq!(tx.version(), TxVersion::V6);
    assert_eq!(u32::from(tx.consensus_branch_id()), NU6_3_BRANCH_ID);
    assert!(
        tx.orchard_bundle().is_none(),
        "no orchard bundle post-NU6.3"
    );

    let bundle = tx.ironwood_bundle().expect("ironwood bundle");
    // the logical actions the fee was priced for: max(1 spend, 2 + change, 2)
    assert_eq!(bundle.actions().len(), 3);

    // each shielded recipient gets exactly its own output, with its own memo
    let to_alice = decrypt_all(bundle, &alice, Scope::External);
    assert_eq!(to_alice.len(), 1, "exactly one output to alice");
    assert_eq!(to_alice[0].0, a_amt);
    assert_eq!(to_alice[0].1, alice_addr);
    assert_eq!(&to_alice[0].2[..], memo("seat A deposit").as_array());

    let to_bob = decrypt_all(bundle, &bob, Scope::External);
    assert_eq!(to_bob.len(), 1, "exactly one output to bob");
    assert_eq!(to_bob[0].0, b_amt);
    assert_eq!(to_bob[0].1, bob_addr);
    assert_eq!(&to_bob[0].2[..], memo("rake").as_array());

    // change returns to the wallet's internal address, with no memo
    let back = decrypt_all(bundle, &fvk, Scope::Internal);
    assert_eq!(back.len(), 1, "exactly one change output");
    assert_eq!(back[0].0, change);
    assert_eq!(back[0].1, fvk.address_at(0u32, Scope::Internal));
    assert_eq!(&back[0].2[..], MemoBytes::empty().as_array());
    assert!(
        decrypt_all(bundle, &fvk, Scope::External).is_empty(),
        "nothing paid to the sender's external address"
    );

    // the transparent payment is a real transparent output
    let tb = tx.transparent_bundle().expect("transparent bundle");
    assert!(tb.vin.is_empty());
    assert_eq!(tb.vout.len(), 1);
    assert_eq!(u64::from(tb.vout[0].value()), t_amt);
    assert_eq!(
        *tb.vout[0].script_pubkey(),
        zcash_transparent::address::Script::from(taddr.script())
    );

    // value: the pool loses the transparent payment plus the fee
    let vb: i64 = (*bundle.value_balance()).into();
    assert_eq!(vb, (t_amt + fee) as i64);
    assert_eq!(note_value, a_amt + b_amt + t_amt + change + fee);
}

#[test]
fn ironwood_send_pays_three_shielded_recipients_and_verifies() {
    let (fvk, ask) = keys_from_seed(SEED, 0);
    let recips: Vec<FullViewingKey> = (1..=3).map(|acct| keys_from_seed(SEED, acct).0).collect();
    let amounts = [100_000u64, 200_000, 300_000];
    let memos = ["one", "", "three"];

    let note_value = 1_000_000u64;
    // 1 spend, 3 outputs + change = 4 actions
    let fee = zip317_fee(1, 3, 0, true);
    assert_eq!(fee, 20_000);
    let change = note_value - amounts.iter().sum::<u64>() - fee;

    let (note, witness, anchor) = owned_note_with_witness(&fvk, note_value, 8);
    let outputs = recips
        .iter()
        .zip(amounts)
        .zip(memos)
        .map(|((r, amount), m)| IronwoodSendOutput {
            recipient: IronwoodRecipient::Shielded(r.address_at(0u32, Scope::External)),
            amount,
            memo: if m.is_empty() {
                MemoBytes::empty()
            } else {
                memo(m)
            },
        })
        .collect();
    let tx_bytes = build_signed_ironwood_send_multi_core(
        Nu63TestNet,
        &fvk,
        &ask,
        vec![(note, witness)],
        outputs,
        fee,
        anchor,
        TARGET,
        NU6_3_BRANCH_ID,
    )
    .expect("build + sign a three-output ironwood send");

    let tx = Transaction::read(&tx_bytes[..], BranchId::Nu6_3).expect("tx parses");
    assert_eq!(tx.version(), TxVersion::V6);
    assert_eq!(u32::from(tx.consensus_branch_id()), NU6_3_BRANCH_ID);
    assert!(tx.transparent_bundle().is_none());
    let bundle = tx.ironwood_bundle().expect("ironwood bundle");
    assert_eq!(bundle.actions().len(), 4);

    for (i, r) in recips.iter().enumerate() {
        let got = decrypt_all(bundle, r, Scope::External);
        assert_eq!(got.len(), 1, "recipient {i}: one output");
        assert_eq!(got[0].0, amounts[i], "recipient {i}: value");
        assert_eq!(got[0].1, r.address_at(0u32, Scope::External));
        let want = if memos[i].is_empty() {
            MemoBytes::empty()
        } else {
            memo(memos[i])
        };
        assert_eq!(&got[0].2[..], want.as_array(), "recipient {i}: memo");
    }
    let back = decrypt_all(bundle, &fvk, Scope::Internal);
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].0, change);

    let vb: i64 = (*bundle.value_balance()).into();
    assert_eq!(vb, fee as i64, "a shielded-only send leaves only the fee");

    // independent check of the proof, spend-auth and binding signatures
    let sighash_tx: TransactionData<ShieldedSighashAuth> = TransactionData::from_parts_v6(
        tx.consensus_branch_id(),
        tx.lock_time(),
        tx.expiry_height(),
        None,
        None,
        None,
        Some(bundle.clone()),
    );
    let txid_parts = sighash_tx.digest(TxIdDigester);
    let sighash = *signature_hash(&sighash_tx, &SignableInput::Shielded, &txid_parts).as_ref();
    let vk = orchard::circuit::VerifyingKey::build(
        orchard::bundle::BundleVersion::ironwood_v3().circuit_version(),
    );
    let mut v = orchard::bundle::BatchValidator::new(&vk);
    assert!(v.add_bundle(bundle, sighash).is_ok());
    assert!(
        v.validate(zafu_wasm::OsRng10),
        "proof and signatures verify"
    );
}

/// The refusals happen before any proving: a memo for a transparent output
/// (named by index), no outputs at all, and outputs the inputs cannot cover.
#[test]
fn ironwood_multi_send_refusals() {
    let (fvk, _) = keys_from_seed(SEED, 0);
    let shielded = IronwoodRecipient::Shielded(
        recipient_keys(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .address_at(0u32, Scope::External),
    );
    let transparent = IronwoodRecipient::Transparent(
        zcash_transparent::address::TransparentAddress::PublicKeyHash([0x42u8; 20]),
    );
    let build = |outputs: Vec<IronwoodSendOutput>| {
        let (note, witness, anchor) = owned_note_with_witness(&fvk, 1_000_000, 9);
        build_ironwood_send_pczt_proven_multi(
            Nu63TestNet,
            &fvk,
            vec![(note, witness)],
            outputs,
            20_000,
            anchor,
            TARGET,
            NU6_3_BRANCH_ID,
            40,
        )
        .err()
        .expect("must be refused")
    };

    let err = build(vec![
        IronwoodSendOutput {
            recipient: shielded,
            amount: 1,
            memo: memo("fine"),
        },
        IronwoodSendOutput {
            recipient: transparent,
            amount: 1,
            memo: memo("nowhere to put this"),
        },
    ]);
    assert!(err.contains("output 1") && err.contains("memo"), "{err}");

    assert!(build(vec![]).contains("at least one output"));

    let err = build(vec![
        IronwoodSendOutput {
            recipient: shielded,
            amount: 600_000,
            memo: MemoBytes::empty(),
        },
        IronwoodSendOutput {
            recipient: transparent,
            amount: 390_000,
            memo: MemoBytes::empty(),
        },
    ]);
    assert!(err.contains("insufficient funds"), "{err}");
    assert!(
        !err.contains("600000") && !err.contains("390000"),
        "value-free: {err}"
    );
}

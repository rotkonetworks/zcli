//! Compact PCZT redaction: the Zigner tx_type 0x05 path, natively.
//!
//! Builds a real proven ironwood send (with a non-ASCII memo), compacts it
//! with `redact_pczt_compact`, then plays the device: the compact PCZT must
//! parse, resolve to the same shielded sighash as the full one, and the
//! signatures made over it must merge into the full PCZT through
//! `apply_signature_contributions_inner` and extract to a tx whose spend-auth
//! signatures verify. No hardware involved; the device's side is the same
//! pczt crate parsing and resolving the compact fields.
//!
//! Run with --release (it builds the post-NU6.3 proving key):
//!   cargo test -p zafu-wasm --release --test pczt_compact_redaction

use orchard::keys::Scope;
use zafu_wasm::{
    apply_signature_contributions_inner, build_ironwood_send_pczt_proven,
    extract_signed_tx_from_pczt_bytes, redact_pczt_compact, IronwoodPcztWithFrost,
    IronwoodRecipient, OsRng10, SpendKeys, LEGACY_PCZT_EXPIRY_DELTA, NU6_3_BRANCH_ID,
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters};
use zcash_protocol::memo::MemoBytes;

/// NU6.3 from height 10, as in the signed_* tests.
#[derive(Clone, Copy, Debug)]
struct Nu63TestNet;

impl Parameters for Nu63TestNet {
    fn network_type(&self) -> NetworkType {
        NetworkType::Test
    }
    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Nu6_3 => Some(BlockHeight::from_u32(10)),
            // stays NU6.3: mainnet schedules NU7 at 3,543,405 since Common 4.0
            NetworkUpgrade::Nu7 => None,
            _ => MainNetwork.activation_height(nu),
        }
    }
}

const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon about";
const RECIP_SEED: &str = "legal winner thank year wave sausage worth useful legal \
                          winner thank yellow";
const TARGET: u32 = 10_000_000;

fn keys(
    phrase: &str,
) -> (
    orchard::keys::FullViewingKey,
    orchard::keys::SpendAuthorizingKey,
) {
    let seed = bip39::Mnemonic::parse(phrase).unwrap().to_seed("");
    SpendKeys::from_seed_bytes(seed, 0, false)
        .unwrap()
        .orchard_keys()
        .unwrap()
}

/// A V3 ironwood note owned by `fvk`, with a single-leaf witness and its anchor.
fn owned_note(
    fvk: &orchard::keys::FullViewingKey,
    value: u64,
) -> (
    orchard::Note,
    orchard::tree::MerklePath,
    orchard::tree::Anchor,
) {
    let rho = orchard::note::Rho::from_bytes(&[1u8; 32]).unwrap();
    let rseed = (0u8..=255)
        .find_map(|b| Option::from(orchard::note::RandomSeed::from_bytes([b; 32], &rho)))
        .unwrap();
    let note: orchard::Note = Option::from(orchard::Note::from_parts(
        fvk.address_at(0u32, Scope::External),
        orchard::value::NoteValue::from_raw(value),
        rho,
        rseed,
        orchard::note::NoteVersion::V3,
    ))
    .unwrap();
    let zero = Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&[0u8; 32])).unwrap();
    let witness = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
    let anchor = witness.root(note.commitment().into());
    (note, witness, anchor)
}

/// The unsigned, proven ironwood send zafu hands to Zigner, plus its alphas.
fn proven_send() -> (
    IronwoodPcztWithFrost,
    orchard::keys::SpendAuthorizingKey,
) {
    let (fvk, ask) = keys(SEED);
    let (recip_fvk, _) = keys(RECIP_SEED);
    let recipient = IronwoodRecipient::Shielded(recip_fvk.address_at(0u32, Scope::External));
    let (note, witness, anchor) = owned_note(&fvk, 1_000_000);
    let memo = MemoBytes::from_bytes("compact 匿 memo, ünïcödé".as_bytes()).unwrap();
    let built = build_ironwood_send_pczt_proven(
        Nu63TestNet,
        &fvk,
        vec![(note, witness)],
        recipient,
        600_000,
        10_000,
        anchor,
        TARGET,
        NU6_3_BRANCH_ID,
        memo,
        LEGACY_PCZT_EXPIRY_DELTA,
    )
    .expect("build proven ironwood send");
    (built, ask)
}

fn shielded_sighash(bytes: &[u8]) -> [u8; 32] {
    let pczt = pczt::Pczt::parse(bytes).expect("pczt parses");
    pczt::roles::signer::Signer::new(pczt)
        .expect("signer init")
        .shielded_sighash()
}

#[test]
fn compact_send_signs_on_the_device_side_and_merges_back() {
    let (built, ask) = proven_send();
    assert!(!built.spend_indices.is_empty(), "the send spends a real note");
    let full = built.pczt.serialize().expect("serialize full pczt");
    let full_hex = hex::encode(&full);

    let compact_hex = redact_pczt_compact(&full_hex).expect("compact redaction");
    let compact = hex::decode(&compact_hex).unwrap();
    assert!(
        compact.len() < full.len(),
        "compact pczt must be smaller: {} vs {} bytes",
        compact.len(),
        full.len()
    );

    // Device side: the compact PCZT resolves to the exact sighash the wallet
    // will later extract under. Any lossy field would change it.
    let sighash = shielded_sighash(&compact);
    assert_eq!(
        sighash,
        shielded_sighash(&full),
        "compact redaction must not change the shielded sighash"
    );

    // The device signs each real spend with ask randomized by its alpha.
    let contributions: Vec<serde_json::Value> = built
        .spend_indices
        .iter()
        .zip(&built.alphas)
        .map(|(idx, alpha_hex)| {
            let alpha: [u8; 32] = hex::decode(alpha_hex).unwrap().try_into().unwrap();
            let alpha = orchard::primitives::redpallas::SpendAuthRandomizer::from_bytes(alpha)
                .into_option()
                .expect("canonical alpha");
            let sig = ask.randomize(&alpha).sign(OsRng10, &sighash);
            serde_json::json!({
                "pool": "ironwood",
                "action_index": idx,
                "signature_hex": hex::encode(<[u8; 64]>::from(&sig)),
            })
        })
        .collect();
    let contributions = serde_json::Value::from(contributions).to_string();

    // Wallet side: merge into the retained full PCZT and extract.
    let signed_hex = apply_signature_contributions_inner(&full_hex, &contributions)
        .expect("signatures from the compact pczt merge into the full one");
    let tx_bytes =
        extract_signed_tx_from_pczt_bytes(&hex::decode(signed_hex).unwrap()).expect("extract");
    let tx = Transaction::read(&tx_bytes[..], BranchId::Nu6_3).expect("tx parses");
    let bundle = tx.ironwood_bundle().expect("ironwood bundle");
    for action in bundle.actions() {
        action
            .rk()
            .verify(&sighash, action.authorization())
            .expect("every spend-auth signature verifies against the sighash");
    }
}

#[test]
fn compact_merge_refuses_malformed_contributions() {
    let (built, _) = proven_send();
    let full_hex = hex::encode(built.pczt.serialize().unwrap());
    let idx = built.spend_indices[0];
    let sig = "00".repeat(64);
    for (bad, want) in [
        (
            serde_json::json!([{"pool": "sapling", "action_index": idx, "signature_hex": sig}]),
            "unknown pool",
        ),
        (
            serde_json::json!([{"pool": "ironwood", "action_index": idx, "signature_hex": "zz"}]),
            "invalid signature hex",
        ),
        (
            serde_json::json!([{"pool": "ironwood", "action_index": idx, "signature_hex": "00".repeat(63)}]),
            "64 bytes",
        ),
        (serde_json::json!([{"pool": "ironwood", "signature_hex": sig}]), "action_index"),
    ] {
        let err = apply_signature_contributions_inner(&full_hex, &bad.to_string())
            .expect_err("malformed contribution must be refused");
        assert!(err.contains(want), "{want:?} not in {err:?}");
    }
    assert!(apply_signature_contributions_inner(&full_hex, "not json")
        .unwrap_err()
        .contains("JSON"));
}

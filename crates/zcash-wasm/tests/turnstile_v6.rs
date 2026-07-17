//! Turnstile migration end-to-end (native): build a V6 PCZT that spends an
//! orchard note into the wallet's own ironwood address, redact it, sign the
//! orchard spend, extract, and assert we got a broadcastable TxVersion::V6
//! transaction with an ironwood bundle.
//!
//! Mirrors the pinned librustzcash pczt/tests/end_to_end.rs ironwood tests
//! and the zigner spike v6_ironwood.rs producer side.
//!
//! Only meaningful when built the way the forks require:
//!   RUSTFLAGS='--cfg zcash_unstable="nu6.3"' cargo test --release --test turnstile_v6
//! Without the cfg this file compiles to nothing. Run with --release: it
//! builds the post-NU6.3 Halo 2 proving key and proves two bundles.

#![cfg(zcash_unstable = "nu6.3")]

use zafu_wasm::build_turnstile_migration_pczt_core;
use zafu_wasm::extract_signed_tx_from_pczt_bytes;

use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::{
    BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters,
};
use zcash_protocol::memo::MemoBytes;

/// Test network with NU6.3 active from height 10 (same shape as the
/// `Nu6_3Network` fixture in the fork's end_to_end.rs).
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

#[test]
fn turnstile_orchard_to_ironwood_builds_signs_extracts() {
    // -- wallet keys: sk-derived so we also hold the spend authorizing key --
    let sk = orchard::keys::SpendingKey::from_bytes([7u8; 32]).unwrap();
    let ask = orchard::keys::SpendAuthorizingKey::from(&sk);
    let fvk = orchard::keys::FullViewingKey::from(&sk);

    // -- a spendable orchard note (legacy pool, V2 plaintext) with a dummy
    //    single-leaf witness, exactly like the zigner spike fixture --
    let note_value = 1_000_000u64;
    let fee = 10_000u64;
    let rho = orchard::note::Rho::from_bytes(&[1u8; 32]).unwrap();
    let rseed = (0u8..=255)
        .find_map(|b| Option::from(orchard::note::RandomSeed::from_bytes([b; 32], &rho)))
        .expect("test rseed");
    let note: orchard::Note = Option::from(orchard::Note::from_parts(
        fvk.address_at(0u32, orchard::keys::Scope::External),
        orchard::value::NoteValue::from_raw(note_value),
        rho,
        rseed,
        orchard::note::NoteVersion::V2,
    ))
    .expect("test note");

    let zero = Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&[0u8; 32]))
        .expect("zero merkle hash");
    let witness = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
    let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
    let orchard_anchor = witness.root(cmx);

    // -- producer: build + prove + redact --
    let built = build_turnstile_migration_pczt_core(
        Nu63TestNet,
        &fvk,
        vec![(note, witness)],
        fee,
        orchard_anchor,
        100,
        MemoBytes::empty(),
    )
    .expect("build turnstile migration PCZT");

    let migrated = note_value - fee;

    // The summary is recomputed from the redacted bytes: ironwood output(s)
    // must carry the full migrated value to the wallet's own address.
    assert!(built.summary.orchard_actions >= 1, "{:?}", built.summary);
    assert!(built.summary.ironwood_actions >= 1, "{:?}", built.summary);
    assert_eq!(built.summary.fee_zat, Some(fee));
    let own_ironwood_recipient = hex::encode(
        fvk.address_at(0u32, orchard::keys::Scope::Internal)
            .to_raw_address_bytes(),
    );
    let ironwood_total: u64 = built
        .summary
        .outputs
        .iter()
        .filter(|(label, _)| *label == format!("ironwood:{}", own_ironwood_recipient))
        .map(|(_, v)| v)
        .sum();
    assert_eq!(
        ironwood_total, migrated,
        "migrated value visible on the wallet's own ironwood address: {:?}",
        built.summary
    );
    assert_eq!(
        built.action_count,
        built.summary.orchard_actions + built.summary.ironwood_actions
    );

    // -- redacted PCZT round-trips and is V6 --
    let pczt = pczt::Pczt::parse(&built.pczt_bytes).expect("redacted PCZT parses");
    assert_eq!(
        *pczt.global().tx_version(),
        zcash_protocol::constants::V6_TX_VERSION
    );
    // -- signer side: sign the real orchard spend (dummy/padding spends were
    //    already signed by IoFinalizer; sign_orchard fails on those, which is
    //    fine - at least one real spend must succeed) --
    let n_orchard = pczt.orchard().actions().len();
    let mut signer = pczt::roles::signer::Signer::new(pczt).expect("signer accepts PCZT");
    let mut signed_actions = 0usize;
    for i in 0..n_orchard {
        if signer.sign_orchard(i, &ask).is_ok() {
            signed_actions += 1;
        }
    }
    assert!(signed_actions >= 1, "no orchard action accepted our ask");
    let signed = signer.finish();

    // -- extractor: same code path zafu's hot wallet uses --
    let tx_bytes =
        extract_signed_tx_from_pczt_bytes(&signed.serialize()).expect("extract signed tx");

    let tx = Transaction::read(&tx_bytes[..], BranchId::Nu6_3).expect("tx parses");
    assert_eq!(tx.version(), TxVersion::V6);
    assert!(tx.orchard_bundle().is_some(), "orchard spend bundle present");
    assert!(
        tx.ironwood_bundle().is_some(),
        "ironwood output bundle present"
    );
}

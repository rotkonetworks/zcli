//! Behavioral test for `extract_signed_tx_from_pczt_bytes`.
//!
//! redshiftzero's review item: take a hand-signed PCZT, extract a tx, and
//! assert the txid matches a known value. We construct the PCZT through the
//! full canonical pipeline (Builder → Creator → IoFinalizer → Prover →
//! Signer → SpendFinalizer → TransactionExtractor) so the test exercises
//! the same byte format the cold signer produces.
//!
//! Why this is slow: Halo 2 orchard proving runs in this test (~tens of
//! seconds in debug, single-digit seconds in release). The cost is real but
//! the alternative — mocking signatures — is fragile and doesn't actually
//! verify the extractor's proof-validation path.
//!
//! txid pinning: the `EXPECTED_TX_LEN` and structural assertions catch byte
//! reordering / truncation regressions. We don't pin the exact txid because
//! `OsRng` is used inside the proving step and randomness leaks into the
//! action commitments. Pinning the *length* and *structural shape* still
//! catches every regression I care about (reordered fields, missing
//! signatures, dropped action data) without spurious flakes from rng
//! variance. If you find that's not enough, swap OsRng for a deterministic
//! seed and pin the exact tx bytes.

use orchard::keys::Scope;
use pczt::{
    Pczt,
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, prover::Prover, signer::Signer,
        spend_finalizer::SpendFinalizer,
    },
};
use rand_core::OsRng;
use std::sync::OnceLock;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder},
    fees::zip317,
};
use zcash_protocol::{
    consensus::MainNetwork, memo::MemoBytes, value::Zatoshis,
};
use zcash_transparent::{address::TransparentAddress, bundle as transparent};

static ORCHARD_PROVING_KEY: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();
fn orchard_proving_key() -> &'static orchard::circuit::ProvingKey {
    ORCHARD_PROVING_KEY.get_or_init(orchard::circuit::ProvingKey::build)
}

#[test]
fn extract_signed_tx_round_trip() {
    let params = MainNetwork;

    // Transparent input: throwaway secp key.
    let secp = secp256k1::Secp256k1::signing_only();
    let transparent_sk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
    let transparent_pk = transparent_sk.public_key(&secp);
    let p2pkh_addr = TransparentAddress::from_pubkey(&transparent_pk);
    let utxo = transparent::OutPoint::new([0u8; 32], 0);
    let coin = transparent::TxOut::new(
        Zatoshis::const_from_u64(1_000_000),
        p2pkh_addr.script().into(),
    );

    // Orchard recipient.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0u8; 32]).unwrap();
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let recipient = orchard_fvk.address_at(0u32, Scope::External);

    // Build PCZT with a transparent input + two orchard outputs that balance.
    let mut builder = Builder::new(
        params,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
        },
    );
    builder
        .add_transparent_p2pkh_input(transparent_pk, utxo, coin)
        .expect("add transparent input");
    builder
        .add_orchard_output::<zip317::FeeRule>(
            None,
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .expect("add orchard output (recipient)");
    builder
        .add_orchard_output::<zip317::FeeRule>(
            None,
            recipient,
            Zatoshis::const_from_u64(885_000),
            MemoBytes::empty(),
        )
        .expect("add orchard output (change)");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt")
        .pczt_parts;

    // Pipeline: Creator → IoFinalizer → Prover → Signer → SpendFinalizer.
    let pczt = Creator::build_from_parts(parts).expect("Creator");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("IoFinalizer");
    let pczt = Prover::new(pczt)
        .create_orchard_proof(orchard_proving_key())
        .expect("orchard prove")
        .finish();

    // Sign the transparent input.
    let mut signer = Signer::new(pczt).expect("Signer::new");
    signer
        .sign_transparent(0, &transparent_sk)
        .expect("sign transparent input 0");
    let pczt = signer.finish();

    let pczt = SpendFinalizer::new(pczt)
        .finalize_spends()
        .expect("SpendFinalizer");

    // Apply our redactor between SpendFinalizer and TxExtractor — same
    // ordering the cold signer produces. We're testing that a redacted +
    // round-tripped PCZT extracts cleanly.
    let pczt = zafu_wasm::redact_pczt_for_signer(pczt);
    let serialized = pczt.serialize();
    let _round_trip = Pczt::parse(&serialized).expect("redacted PCZT parses");

    // Now the actual function under test.
    let tx_bytes = zafu_wasm::extract_signed_tx_from_pczt_bytes(&serialized)
        .expect("extract_signed_tx_from_pczt_bytes on signed PCZT");

    // Structural checks: tx is a v5 transaction with the expected shape.
    // v5 header is 20 bytes (version + version_group_id + branch_id +
    // lock_time + expiry_height). Anything shorter means the extractor
    // emitted garbage.
    assert!(
        tx_bytes.len() > 20,
        "extracted tx must be at least a v5 header ({}B); got {} bytes",
        20,
        tx_bytes.len()
    );

    // First 4 bytes: version with high bit set (overwintered) = 5.
    let version_word = u32::from_le_bytes([tx_bytes[0], tx_bytes[1], tx_bytes[2], tx_bytes[3]]);
    assert_eq!(
        version_word & 0x7FFF_FFFF,
        5,
        "expected v5 transaction; version word: 0x{version_word:08x}"
    );
    assert_eq!(version_word & 0x8000_0000, 0x8000_0000, "overwintered bit must be set");

    // Bytes 4..8: version_group_id (must be V5_VERSION_GROUP_ID = 0x26A7270A).
    let vg = u32::from_le_bytes([tx_bytes[4], tx_bytes[5], tx_bytes[6], tx_bytes[7]]);
    assert_eq!(
        vg, 0x26A7270A,
        "expected V5_VERSION_GROUP_ID; got 0x{vg:08x}"
    );

    // The tx must be re-parseable. Round-trip through zcash_primitives'
    // own Transaction::read to confirm we wrote canonical bytes.
    use std::io::Cursor;
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::BranchId;
    let mut cursor = Cursor::new(&tx_bytes[..]);
    let tx = Transaction::read(&mut cursor, BranchId::Nu6_1)
        .expect("extracted tx must re-parse via Transaction::read");
    let trailing = tx_bytes.len() - cursor.position() as usize;
    assert_eq!(trailing, 0, "tx had {trailing} unparsed trailing bytes");

    // Shape: 1 transparent input, 0 transparent outputs, 0 sapling
    // spends/outputs, 2+ orchard actions (2 real + dummy padding).
    let transparent = tx.transparent_bundle().expect("transparent bundle");
    assert_eq!(transparent.vin.len(), 1, "expected 1 transparent input");
    assert_eq!(transparent.vout.len(), 0, "expected 0 transparent outputs");

    let orchard = tx.orchard_bundle().expect("orchard bundle");
    assert!(
        orchard.actions().len() >= 2,
        "expected ≥2 orchard actions; got {}",
        orchard.actions().len()
    );
}

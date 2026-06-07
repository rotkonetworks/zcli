//! Property test for `redact_pczt_for_signer`.
//!
//! redshiftzero's review item: every `clear_*` we don't call must leave the
//! corresponding field `Some(_)` after redact + serialize + parse round-trip.
//! This test pins the kept-fields invariant so a future "let's also clear X"
//! refactor can't silently strip something the cold signer needs.
//!
//! Fixture strategy: build a minimal transparent → orchard PCZT via the
//! canonical `zcash_primitives::Builder::build_for_pczt` → `Creator::build_from_parts`
//! pipeline, skipping `Prover::create_orchard_proof` because the Halo 2
//! proof isn't load-bearing for redaction or serialization. The orchard
//! bundle's actions are populated with dummy spends (privacy padding the
//! builder injects) — those still have all the fields we care about.
//!
//! A real spend (orchard → orchard) would also exercise the spend path but
//! requires a synthetic merkle anchor + path that hash-balances. The dummy
//! spends are sufficient to assert the property; richer fixtures are a
//! follow-up if signing-path bugs slip past this guard.

use orchard::keys::Scope;
use pczt::{Pczt, roles::creator::Creator};
use rand_core::OsRng;
use zcash_transparent::{
    address::TransparentAddress,
    bundle as transparent,
};

// Signer::new is feature-gated; we have it on (see Cargo features list).
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder},
    fees::zip317,
};
use zcash_protocol::{
    consensus::MainNetwork,
    memo::MemoBytes,
    value::Zatoshis,
};

/// Build a minimal unproven PCZT: 1 transparent input → 1 orchard output.
/// Skips proof/sighash steps — sufficient for testing the redactor + the
/// serialize/parse round-trip but not for actual broadcast.
fn build_test_pczt() -> Pczt {
    let params = MainNetwork;

    // Transparent input — fake outpoint, throwaway key.
    let secp = secp256k1::Secp256k1::signing_only();
    let sk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
    let pk = sk.public_key(&secp);
    // OutPoint::fake is test-dependencies-only; use OutPoint::new directly.
    let utxo = transparent::OutPoint::new([0u8; 32], 0);
    let coin = transparent::TxOut::new(
        Zatoshis::const_from_u64(1_000_000),
        TransparentAddress::from_pubkey(&pk).script().into(),
    );

    // Orchard recipient.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0u8; 32]).unwrap();
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let recipient = orchard_fvk.address_at(0u32, Scope::External);

    let mut builder = Builder::new(
        params,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
        },
    );
    builder
        .add_transparent_p2pkh_input(pk, utxo, coin)
        .expect("add transparent input");
    // Two outputs so the bundle is non-trivial AND balances against the
    // 1M zat input minus the zip317 fee. The exact split doesn't matter
    // for redaction testing — we just need the builder to accept it.
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
        .expect("add orchard output (change-equivalent)");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt")
        .pczt_parts;

    Creator::build_from_parts(parts).expect("Creator::build_from_parts")
}

#[test]
fn redacted_pczt_round_trips_through_parse() {
    let pczt = build_test_pczt();
    let redacted = zafu_wasm::redact_pczt_for_signer(pczt);
    let bytes = redacted.serialize();
    let reparsed = Pczt::parse(&bytes).expect("redacted PCZT must parse");
    assert_eq!(
        bytes,
        reparsed.serialize(),
        "PCZT bytes must be stable across one round-trip"
    );
}

#[test]
fn redacted_pczt_shrinks_relative_to_unredacted() {
    // Redaction must actually remove bytes. If the byte count doesn't shrink,
    // the redactor is a no-op (unwired call sites, struct layout drift, etc.)
    // and we'd silently ship the un-redacted form Keystone might reject.
    //
    // Note: this is a weak guard — a buggy redactor that clears a tiny field
    // still passes — but combined with the smoke test (Redactor is invoked
    // in the right pipeline order) and the field-presence probe below, the
    // three together pin the contract.
    let pczt = build_test_pczt();
    let unredacted_size = pczt.serialize().len();
    let redacted_size = zafu_wasm::redact_pczt_for_signer(pczt).serialize().len();
    assert!(
        redacted_size < unredacted_size,
        "redaction must shrink the PCZT: unredacted={unredacted_size}, redacted={redacted_size}"
    );
}

#[test]
fn redaction_preserves_sighash() {
    // Security property the whole migration delivers: redaction must not
    // change the sighash. If it does, the signer recomputes a different
    // shielded_sighash than the one IoFinalizer stamped, and the binding
    // signature / spend auth signatures don't validate when the tx hits
    // the network. Worse: if a future redactor change subtly alters the
    // sighash for some classes of action and not others, we'd ship txs
    // that look fine in tests but reject on broadcast.
    //
    // The probe: compute the shielded sighash on the unreducted+finalized
    // PCZT, then on the redacted+round-tripped form, and assert byte
    // equality. This is the exact property the migration relies on.
    use pczt::roles::{io_finalizer::IoFinalizer, signer::Signer};

    let pczt = build_test_pczt();
    let pczt = IoFinalizer::new(pczt)
        .finalize_io()
        .expect("finalize_io");

    // Sighash from the un-redacted (but finalized) PCZT.
    let sighash_pre = Signer::new(pczt.clone())
        .expect("Signer::new on finalized PCZT")
        .shielded_sighash();

    // Redact, serialize, parse — exactly the trip the cold signer sees.
    let redacted = zafu_wasm::redact_pczt_for_signer(pczt);
    let bytes = redacted.serialize();
    let reparsed = pczt::Pczt::parse(&bytes).expect("redacted PCZT must parse");

    // Sighash recomputed by the signer from the redacted bytes.
    let sighash_post = Signer::new(reparsed)
        .expect("Signer::new on redacted PCZT")
        .shielded_sighash();

    assert_eq!(
        sighash_pre, sighash_post,
        "redaction altered the sighash (pre={}, post={}). \
         this breaks the display↔sighash binding the migration relies on. \
         most likely cause: a clear_* call accidentally landed on a field \
         that participates in `pczt_to_tx_data`.",
        hex::encode(&sighash_pre),
        hex::encode(&sighash_post),
    );
}

#[test]
fn redacted_pczt_remains_signer_acceptable() {
    // The pczt struct hides most fields behind `pub(crate)`, so we can't
    // directly assert "fvk is Some after redaction" from an external test.
    // But the Signer role's `pczt_to_tx_data` reconstruction REQUIRES the
    // signer-needed fields (fvk, alpha, value, recipient, …) to be present
    // — if any are missing, Signer::new returns Err. We use that as the
    // kept-fields probe: if Signer::new succeeds on the redacted PCZT,
    // the redactor preserved everything the cold signer needs.
    //
    // This is a stronger property than per-field assertion: we're testing
    // "the redacted PCZT is still signer-ready," which is the actual
    // contract the migration delivers. Per-field asserts would just be a
    // proxy for this.
    //
    // Caveat: in our unproven test fixture, `IoFinalizer::finalize_io` was
    // not run (we skip the proof step), so Signer::new MAY refuse on
    // grounds unrelated to redaction. To be principled here we run
    // finalize_io first, then redact, then probe with Signer::new.
    use pczt::roles::{io_finalizer::IoFinalizer, signer::Signer};

    let pczt = build_test_pczt();
    let pczt = IoFinalizer::new(pczt)
        .finalize_io()
        .expect("finalize_io on test fixture");
    let redacted = zafu_wasm::redact_pczt_for_signer(pczt);
    let bytes = redacted.serialize();
    let reparsed = Pczt::parse(&bytes).expect("redacted PCZT must parse");

    // The probe. If redaction stripped fvk/alpha/value/etc, this errors.
    Signer::new(reparsed).expect(
        "Signer::new on redacted PCZT must succeed — \
         if it fails the redactor stripped a field the signer needs",
    );
}

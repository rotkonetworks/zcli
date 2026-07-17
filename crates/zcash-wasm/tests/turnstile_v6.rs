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
    // Target height must be past every inherited MainNetwork activation (the
    // orchard builder needs NU5 active); 10_000_000 matches the fork's
    // end_to_end.rs fixture.
    // Real NU6.3 / Ironwood consensus branch id (from the live zebra). The
    // patched fork binds this at any NU6.3-active height; the fail-closed guard
    // requires the caller to pass it explicitly.
    const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;

    // Sanity: the patched params bind the REAL branch id at an NU6.3-active
    // height (not the 0xffff_ffff placeholder).
    assert_eq!(
        u32::from(BranchId::for_height(
            &Nu63TestNet,
            BlockHeight::from_u32(10_000_000)
        )),
        NU6_3_BRANCH_ID,
        "turnstile must bind the real NU6.3 branch id 0x37a5165b"
    );

    let built = build_turnstile_migration_pczt_core(
        Nu63TestNet,
        &fvk,
        vec![(note, witness)],
        fee,
        orchard_anchor,
        10_000_000,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("build turnstile migration PCZT");

    // Fail-closed guard: a mismatched expected branch id must be REFUSED, and
    // the placeholder must be refused outright. Rebuild with fresh inputs since
    // the note/witness were moved into the successful build above.
    {
        let note2: orchard::Note = Option::from(orchard::Note::from_parts(
            fvk.address_at(0u32, orchard::keys::Scope::External),
            orchard::value::NoteValue::from_raw(note_value),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        ))
        .expect("test note 2");
        let witness2 = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
        let err = match build_turnstile_migration_pczt_core(
            Nu63TestNet,
            &fvk,
            vec![(note2, witness2)],
            fee,
            orchard_anchor,
            10_000_000,
            0xdead_beef, // wrong branch id
            MemoBytes::empty(),
        ) {
            Ok(_) => panic!("must refuse a mismatched branch id"),
            Err(e) => e,
        };
        assert!(err.contains("branch id"), "unexpected error: {err}");

        let note3: orchard::Note = Option::from(orchard::Note::from_parts(
            fvk.address_at(0u32, orchard::keys::Scope::External),
            orchard::value::NoteValue::from_raw(note_value),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        ))
        .expect("test note 3");
        let witness3 = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
        let err = match build_turnstile_migration_pczt_core(
            Nu63TestNet,
            &fvk,
            vec![(note3, witness3)],
            fee,
            orchard_anchor,
            10_000_000,
            0xffff_ffff, // placeholder
            MemoBytes::empty(),
        ) {
            Ok(_) => panic!("must refuse the placeholder branch id"),
            Err(e) => e,
        };
        assert!(err.contains("placeholder"), "unexpected error: {err}");
    }

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

    // -- REDACTION-ABSENCE (R3): the spent-note plaintext MUST NOT survive into
    //    the redacted-for-signer payload. The pczt Spend fields
    //    (recipient/value/rho/rseed/fvk) are pub(crate) (no public accessor), so
    //    we assert at the byte level: the known secret byte-strings must be
    //    absent from the serialized redacted PCZT.
    //
    //    We assert on the spent note's 32-byte rho: it is a spend-note secret,
    //    the redactor clears `spend.rho`, and the fabricated outputs use fresh
    //    rho values, so its absence uniquely proves the spend was redacted.
    //    (The spend's recipient/rseed ALSO appear in the fabricated dummy ORCHARD
    //    OUTPUT paired with the spend - an output-side leak out of scope for the
    //    R3 spend-redaction fix - so byte-testing those would false-negative on
    //    the output copy.)
    //
    //    R3 viewing-key leak fix: the spend `fvk` (the wallet's 96-byte orchard
    //    FullViewingKey) MUST now be absent too - it links every note the
    //    account can receive, so it may not cross the QR to the signer. We
    //    assert the raw fvk bytes are absent from the redacted PCZT. This is
    //    safe because the coordinated signer reconstructs the fvk from the seed
    //    and supplies it to `verify_nullifier(Some(fvk))`; the signing loop
    //    below mirrors that path (low-level Signer role + reconstructed fvk).
    //
    //    A control assertion confirms the ironwood OUTPUT recipient (needed for
    //    device confirmation) DOES survive, so the redaction is not over-broad.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }
    let spent_rho = rho.to_bytes();
    let spent_fvk = fvk.to_bytes();
    let ironwood_dest = fvk
        .address_at(0u32, orchard::keys::Scope::Internal)
        .to_raw_address_bytes();
    assert!(
        !contains(&built.pczt_bytes, &spent_rho),
        "redacted PCZT still leaks the spent note's rho"
    );
    assert!(
        !contains(&built.pczt_bytes, &spent_fvk),
        "redacted PCZT still leaks the spend viewing key (fvk)"
    );
    assert!(
        contains(&built.pczt_bytes, &ironwood_dest),
        "redaction dropped the ironwood output recipient needed for confirmation"
    );

    // -- MONEY-PATH OUTPUT-SIDE LEAK (this fix): the orchard bundle's DUMMY
    //    outputs are fabricated to the SPENT note's own receiver - i.e. the
    //    wallet's own EXTERNAL diversified orchard address (see zcash/orchard
    //    qleak `OutputInfo::fabricated_for_spend`). That 43-byte
    //    `output.recipient` used to survive redaction and link the wallet's
    //    address over the untrusted QR. `redact_turnstile_dummy_outputs` now
    //    clears it. Assert (a): the wallet's own external address is ABSENT from
    //    the redacted bytes.
    //
    //    This address is DISTINCT from the ironwood destination
    //    (Scope::Internal) asserted present above, so the two checks together
    //    prove the redaction is precise: it drops the dummy orchard recipient
    //    while keeping the real ironwood recipient the device must confirm.
    let own_external_orchard = fvk
        .address_at(0u32, orchard::keys::Scope::External)
        .to_raw_address_bytes();
    // Precondition: the two addresses really are different byte strings, else
    // the absence assertion would be trivially contradicted by the presence one.
    assert_ne!(
        own_external_orchard.as_slice(),
        ironwood_dest.as_slice(),
        "test fixture invalid: external and internal addresses collide"
    );
    assert!(
        !contains(&built.pczt_bytes, &own_external_orchard),
        "MONEY-PATH LEAK: redacted PCZT still contains the wallet's own external \
         orchard address (the dummy-output recipient)"
    );

    // -- redacted PCZT round-trips and is V6 --
    let pczt = pczt::Pczt::parse(&built.pczt_bytes).expect("redacted PCZT parses");
    assert_eq!(
        *pczt.global().tx_version(),
        zcash_protocol::constants::V6_TX_VERSION
    );
    // -- signer side: sign the real orchard spend the way the coordinated
    //    zigner signer does. Because the redactor now strips the spend `fvk`,
    //    the high-level `Signer::sign_orchard` (which hardcodes
    //    `verify_nullifier(None)` and rejects a missing fvk) can no longer be
    //    used. Instead we reconstruct the fvk from the seed we hold and drive
    //    the low-level Signer role, supplying the fvk to
    //    `verify_nullifier(Some(fvk))` and signing each action directly.
    //    (dummy/padding spends were already signed by IoFinalizer; those error
    //    with a Wrong/Missing mismatch and are skipped - at least one real
    //    spend must land.)
    use rand_core::OsRng;
    let shielded_sighash = pczt::roles::signer::Signer::new(pczt.clone())
        .expect("signer accepts PCZT")
        .shielded_sighash();
    let signed_actions = std::cell::Cell::new(0usize);
    let low = pczt::roles::low_level_signer::Signer::new(pczt);
    let low = low
        .sign_orchard_with(
            |_pczt, bundle, _tx_modifiable| -> Result<(), pczt::orchard::BundleParseError> {
                for action in bundle.actions_mut().iter_mut() {
                    match action.spend().verify_nullifier(Some(&fvk)) {
                        Ok(())
                        | Err(
                            orchard::pczt::VerifyError::MissingRecipient
                            | orchard::pczt::VerifyError::MissingValue
                            | orchard::pczt::VerifyError::MissingRho
                            | orchard::pczt::VerifyError::MissingRandomSeed,
                        ) => {}
                        Err(_) => continue,
                    }
                    if action.sign(shielded_sighash, &ask, OsRng).is_ok() {
                        signed_actions.set(signed_actions.get() + 1);
                    }
                }
                Ok(())
            },
        )
        .expect("low-level orchard signing");
    assert!(
        signed_actions.get() >= 1,
        "no orchard action accepted our ask with the reconstructed fvk"
    );
    let signed = low.finish();

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

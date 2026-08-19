//! Discriminating experiment for the compact-merge `MissingFullViewingKey`.
//!
//! Runs zafu's ACTUAL merge entry point (`apply_signature_contributions`, the
//! wasm export the extension calls) against the retained fixture with a DUMMY
//! signature. The dummy can't pass signature verification - but signature
//! verification runs AFTER the optional `verify_nullifier` consistency check.
//! So the error type localizes where the FVK is lost:
//!   - `MissingFullViewingKey`  -> reproduced offline: the retained pczt's
//!     ironwood spend has no FVK at MERGE time (serialize omits it, a post-prove
//!     role clears it, or `Pczt::parse` drops it via the signing-parse path).
//!   - a signature-verify failure -> the fvk survived; the on-device pczt just
//!     differs from this fixture (different builder params) - separate issue.
//!
//! Run:  cargo test --release --test fvk_repro -- --nocapture

use zafu_wasm::{apply_signature_contributions_inner, redact_pczt_for_signer};

const RETAINED: &str =
    "/steam/rotko/zigner/rust/pczt_signing/tests/fixtures/ironwood_single_retained.hex";

#[test]
fn compact_merge_dummy_sig_localizes_fvk_loss() {
    let hex = std::fs::read_to_string(RETAINED)
        .expect("retained fixture present (generate via dump_ironwood_send_fixtures)");
    let hex = hex.trim();

    let dummy_sig = "0".repeat(128); // 64-byte zero sig
    let contributions = format!(
        r#"[{{"pool":"ironwood","action_index":0,"signature_hex":"{dummy_sig}"}}]"#
    );

    // (1) UNREDACTED retained (what _proven produces): fvk present -> the merge
    // gets PAST verify_nullifier and only fails on the dummy signature.
    match apply_signature_contributions_inner(hex, &contributions) {
        Ok(_) => println!("[unredacted] RESULT: Ok (unexpected for a dummy sig)"),
        Err(msg) => println!("[unredacted] RESULT ERROR: {msg}"),
    }

    // (2) REDACTED-for-signer retained (what build_ironwood_send_pczt actually
    // returns, and what zafu retains today): fvk stripped -> verify_nullifier
    // should fail with MissingFullViewingKey BEFORE the signature is even checked.
    // This is the user's on-device error, reproduced natively.
    let redacted_bytes = redact_pczt_for_signer_hex(hex);
    match apply_signature_contributions_inner(&redacted_bytes, &contributions) {
        Ok(_) => println!("[redacted] RESULT: Ok (unexpected)"),
        Err(msg) => println!("[redacted] RESULT ERROR: {msg}"),
    }
}

/// Parse hex -> redact_pczt_for_signer -> re-serialize -> hex.
fn redact_pczt_for_signer_hex(pczt_hex: &str) -> String {
    use pczt::Pczt;
    let bytes: Vec<u8> = (0..pczt_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&pczt_hex[i..i + 2], 16).unwrap())
        .collect();
    let pczt = Pczt::parse(&bytes).expect("parse retained");
    let redacted = redact_pczt_for_signer(pczt);
    redacted
        .serialize()
        .expect("serialize redacted")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

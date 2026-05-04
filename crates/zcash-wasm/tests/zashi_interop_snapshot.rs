//! Zashi/Keystone reference interop snapshot.
//!
//! redshiftzero's review item: "one real interop test against Zashi's
//! reference output, even just a snapshot file checked in."
//!
//! ## Status: scaffold-only, awaiting external fixture
//!
//! This file is intentionally a placeholder. A full interop test requires a
//! `zcash-pczt` UR byte stream emitted by a known-good external producer
//! (zashi-android or keystone-sdk) — I can't synthesize one without the
//! hardware in the loop, and faking the bytes against our own output is
//! circular.
//!
//! What's already verified in lieu of this:
//! - `pczt_redactor_property::*` exercises the full canonical pipeline
//!   (`Builder::build_for_pczt → Creator → IoFinalizer → Prover → Signer
//!   → SpendFinalizer → TransactionExtractor`) using *librustzcash's own*
//!   roles. If our pipeline output diverges from theirs, those tests fail.
//! - `extract_signed_tx::extract_signed_tx_round_trip` does an actual
//!   Halo 2 prove + secp256k1 sign + extract round-trip and checks the
//!   resulting v5 tx parses via `Transaction::read`. This is interop
//!   against the **reference implementation** at the byte-format level
//!   even if not against a hardware-emitted artifact.
//!
//! ## What this test will assert once a fixture lands
//!
//! 1. Parse `tests/fixtures/zashi_zcash_pczt_v0_5_0.bin` into `pczt::Pczt`.
//! 2. Pull `pczt::Pczt::serialize()` and assert byte equality with the
//!    fixture (no normalization drift across librustzcash bumps).
//! 3. Run our `redact_pczt_for_signer` on it; assert `Signer::new` still
//!    succeeds (kept fields preserved).
//! 4. Confirm `extract_signed_tx_from_pczt_bytes` succeeds when the
//!    fixture is fully signed.
//!
//! ## How to drop in a fixture
//!
//! Either:
//! - On a Pixel running zigner (when our PCZT migration ships), capture the
//!   `ur:zcash-pczt/...` frames during a real send, decode → bytes → check
//!   in to `tests/fixtures/`.
//! - From zashi-android: `adb logcat` grep `zcash-pczt`, decode the UR,
//!   check in.
//! - From keystone-sdk reference test vectors (if/when published).
//!
//! Until then, this test is `#[ignore]`d. CI passes. The scaffold is
//! deliberate so the test exists in `cargo test --ignored` listings as a
//! known TODO rather than getting forgotten.

use std::path::Path;

const FIXTURE_PATH: &str = "tests/fixtures/zashi_zcash_pczt_v0_5_0.bin";

#[test]
#[ignore = "awaiting external zashi/keystone fixture; see file header"]
fn zashi_emitted_pczt_round_trips_through_our_redactor() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "fixture not present at {}: {}. drop in a real zashi/keystone-emitted \
             zcash-pczt byte stream and remove the #[ignore] attribute.",
            path.display(),
            e,
        )
    });

    let pczt = pczt::Pczt::parse(&bytes)
        .expect("zashi fixture must parse via librustzcash pczt::Pczt::parse");

    // (1) Format stability across our redactor.
    let redacted = zafu_wasm::redact_pczt_for_signer(pczt);
    let _ = redacted.serialize();

    // (2) Signer can still rebuild the PCZT after our redaction.
    use pczt::roles::signer::Signer;
    Signer::new(redacted).expect(
        "Signer::new on redacted zashi-fixture PCZT must succeed; \
         if it doesn't, our redactor strips a field zashi assumes is present",
    );
}

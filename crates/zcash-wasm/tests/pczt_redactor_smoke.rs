//! Source-shape test for the PCZT redactor wiring in `build_unsigned_pczt`.
//!
//! Why grep over a real-bytes integration test:
//!   - `build_unsigned_pczt` is a `#[wasm_bindgen]` export. Standing it up in
//!     a regular cargo test requires faking the whole prove pipeline (Halo 2
//!     proving key, FVK derivation, real notes with valid rseed/rho, witness
//!     building, …). The fixture cost is enormous for what's effectively a
//!     "did the author wire the role into the pipeline" check.
//!   - The contract we care about is: the Redactor role from the librustzcash
//!     pczt crate runs after `Prover::create_orchard_proof` /
//!     `IoFinalizer::finalize_io` and before `pczt.serialize()`. That's a
//!     code-shape assertion, not a behavioural one.
//!   - Once the redactor is wired, behavioural correctness is delegated to
//!     librustzcash's own redactor tests — we don't re-test their crate.
//!
//! If this test ever gets in the way of a deeper refactor, replace it with a
//! real fixture-based test that builds a minimal PCZT through Creator +
//! IoFinalizer with a synthesized note and asserts redacted fields are None.
//! Until that's worth the carry, grep is good enough.

use std::fs;

const SRC: &str = include_str!("../src/lib.rs");

#[test]
fn build_unsigned_pczt_calls_the_redactor_role() {
    // Sanity that the source we baked in via include_str! matches the live
    // file (catches stale incremental builds while iterating).
    let live = fs::read_to_string("src/lib.rs").expect("read live lib.rs");
    assert_eq!(SRC.len(), live.len(), "include_str! lib.rs is stale; rebuild");

    let pczt_fn = SRC
        .find("pub fn build_unsigned_pczt")
        .expect("build_unsigned_pczt not found");
    let body = &SRC[pczt_fn..];
    // Find the closing `}` of the function. We approximate by walking until
    // the next top-level `pub fn` or `///` doc comment for the next item.
    let end = body
        .find("\npub fn ")
        .or_else(|| body.find("\n/// "))
        .unwrap_or(body.len());
    let body = &body[..end];

    assert!(
        body.contains("redact_pczt_for_signer"),
        "build_unsigned_pczt must call redact_pczt_for_signer between finalize_io \
         and serialize. Without it, Keystone-class signers may reject the PCZT \
         (their RAM budget assumes redacted form)."
    );

    // Order check: redaction must happen AFTER io_finalizer.finalize_io and
    // BEFORE pczt.serialize. Reasoning: finalize_io stamps the canonical
    // sighash into action authorizations; redaction strips fields the
    // signer doesn't need; serialize freezes the bytes that go over the QR.
    let finalize = body.find("finalize_io").expect("io finalizer must run");
    let redact = body.find("redact_pczt_for_signer").expect("checked above");
    let serialize = body.find(".serialize()").expect(".serialize() not found");
    assert!(
        finalize < redact && redact < serialize,
        "expected order: finalize_io → redact_pczt_for_signer → serialize. \
         Got finalize@{finalize}, redact@{redact}, serialize@{serialize}"
    );

    // And the helper itself must use the librustzcash Redactor role.
    assert!(
        SRC.contains("pczt::roles::redactor::Redactor::new"),
        "redact_pczt_for_signer must invoke pczt::roles::redactor::Redactor"
    );
}

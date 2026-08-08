//! Tests for compact PCZT redaction functionality.
//!
//! Verifies that:
//! - `redact_pczt_compact` shrinks PCZTs while preserving required fields
//! - Round-trip parsing succeeds after compaction
//! - Size estimates are accurate
//!
//! Most tests are placeholders pending a fixture-based test that builds
//! a minimal PCZT through the full pipeline (build_unsigned_pczt with
//! real notes + proofs).

#[test]
#[ignore]
fn compact_redaction_shrinks_pczt() {
    // Build a minimal PCZT to test with. We'll use a real PCZT fixture.
    // This test is pending a fixture-based test that builds an unsigned PCZT
    // via build_unsigned_pczt with real notes + proofs.
    //
    // In a real scenario, we would:
    // 1. Build an unsigned PCZT via build_unsigned_pczt
    // 2. Call redact_pczt_compact on it
    // 3. Verify the compact version is smaller
}

#[test]
#[ignore]
fn compact_redaction_preserves_output_fields() {
    // Verifies that compact redaction keeps:
    // - output.recipient
    // - output.value
    // - output.rseed
    //
    // These fields are required for the signer to recompute cmx and enc_ciphertext.
    //
    // This is tested indirectly: if redaction didn't preserve these fields,
    // round-trip parsing would fail (the signer couldn't recompute the cmx).
    // Pending fixture-based test.
}

#[test]
#[ignore]
fn compact_redaction_round_trip() {
    // Test that a PCZT can be:
    // 1. Parsed normally
    // 2. Compacted via redact_pczt_compact
    // 3. Re-parsed successfully
    //
    // This ensures the compacted PCZT is still valid Postcard/V2 PCZT format.
    // Pending fixture-based test.
}

#[test]
#[ignore]
fn estimate_compact_savings_accuracy() {
    // Verifies that estimate_compact_savings returns correct sizes.
    // Specifically:
    // - full_bytes matches the input PCZT serialized length
    // - compact_bytes matches the output from redact_pczt_compact
    // - compact_bytes < full_bytes
    // Pending fixture-based test.
}

#[test]
#[ignore]
fn apply_signature_contributions_parsing() {
    // Verifies that apply_signature_contributions correctly parses
    // the contributions JSON and creates a valid Signer.
    //
    // Test cases:
    // - Valid orchard signature
    // - Valid ironwood signature
    // - Invalid pool name (rejected)
    // - Malformed JSON (rejected)
    // - Invalid hex signature (rejected)
    // Pending fixture-based test with actual signatures and PCZT.
}

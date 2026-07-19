//! FROST payout co-sign — SKELETON + design, deliberately NOT implemented offline.
//!
//! The payout is the SECOND co-sign of the paid path: after `/settle` records the
//! co-signed outcome (see `settle.rs`), the escrow builds a PCZT paying the settled
//! plan and opens a 2-of-3 FROST relay room. The priority seat drives the co-sign;
//! the other seat joins. This needs a LIVE escrow + a real PCZT to exercise, so it
//! cannot be unit-tested offline and is left as a documented interface. The offline
//! money-safety proof this crate delivers is the SETTLEMENT co-sign (settle.rs);
//! the payout co-sign is guarded by the same identity keys but proven on the live
//! stack.
//!
//! ── Live drive path (wired up later) ──────────────────────────────────────────
//!   1. Bot receives `srv` `ServerMsg::PayoutSigningRequest { relay_room, plan,
//!      priority_seat, fallback_secs_remaining }`.
//!   2. Bot joins the FROST relay room via `bin/zcli/src/frost_relay.rs`
//!      (`RelayTransport` / `FrostRelayClient`: `create_room` / `join_room`).
//!   3. **C3 blind-signer safety check (THIS module's job):** BEFORE contributing
//!      any FROST signature share, the bot MUST decode the PCZT it is being asked to
//!      sign and confirm every spendable output pays EXACTLY the settled `plan`'s
//!      {address, amount_zat}. A blind signer that skips this can be tricked into
//!      co-signing a PCZT that pays an attacker — the on-chain analogue of the very
//!      fork bug settle.rs guards. See `verify_pczt_recipients`.
//!   4. Only if (3) passes: run the co-sign via the escrow's driver
//!      `poker-escrow::payout_signing::join_sign_pczt`, which internally calls
//!      `frost-spend::orchestrate::sign_round1` (round-1 nonce/commitment) then
//!      `frost-spend::orchestrate::spend_sign_round2_signed` (round-2 signed share)
//!      per action. The priority seat instead SENDS `SIGN` first (the escrow's
//!      `sign_pczt` entry) and both aggregate.
//!   5. Escrow aggregates + broadcasts → `ServerMsg::PayoutComplete { txid }` (or
//!      `PayoutFailed { reason }`).

use anyhow::Result;

use crate::srv::PayoutLine;

/// The secrets a seat needs to FROST-sign a payout, recovered from its multisig
/// vault (DKG output). Modelled here for the interface; populated on the live path.
#[derive(Debug, Clone)]
pub struct PayoutSignerContext {
    /// FROST relay room to join (from `PayoutSigningRequest.relay_room`).
    pub relay_room: String,
    /// hex-encoded `PublicKeyPackage` for this escrow (from DKG, stored in the vault).
    pub public_key_package_hex: String,
    /// hex-encoded per-seat FROST `KeyPackage` (secret share).
    pub key_package_hex: String,
    /// hex ephemeral signing seed for the round nonces.
    pub ephemeral_seed_hex: String,
    /// the settled payout plan this seat agreed to — the ground truth the PCZT
    /// recipients are checked against in `verify_pczt_recipients`.
    pub expected_plan: Vec<PayoutLine>,
}

/// **C3 blind-signer safety check.** Decode `pczt_hex` and confirm every output
/// pays exactly the settled `expected_plan` (address + zatoshi amount), with no
/// extra outputs. Returns `Ok(())` only when the PCZT is safe to FROST-sign.
///
/// INTENDED LOGIC (implemented on the live path against a real PCZT decoder):
///   1. Decode the PCZT (`pczt` crate / the escrow's `tx_build` decoder) into its
///      Orchard action outputs, recovering each output's recipient UA + value.
///   2. Build a multiset of `(address, amount_zat)` from `expected_plan`.
///   3. Require the PCZT's spendable outputs to equal that multiset EXACTLY —
///      every planned line present with the right amount, and NO unplanned
///      recipient (an extra output to an attacker fails closed). Change back to the
///      escrow UA (if any) and the reserved tx fee are accounted for separately, so
///      they don't count as unplanned recipients.
///   4. Any decode failure, missing line, wrong amount, or surplus output ⇒ `Err`.
///
/// It is `unimplemented!()` here (guarded so it is never reached offline) precisely
/// so a caller cannot accidentally treat an un-checked PCZT as verified: calling it
/// without the live decoder PANICS rather than returning a false `Ok`.
pub fn verify_pczt_recipients(_pczt_hex: &str, _expected_plan: &[PayoutLine]) -> Result<()> {
    unimplemented!(
        "C3 blind-signer check: decode the PCZT and confirm every output pays the \
         settled plan's address+amount BEFORE FROST-signing. Live-path only — needs \
         a real PCZT + escrow; see module docs. NEVER FROST-sign without this passing."
    )
}

/// Drive this seat's half of the FROST payout co-sign. STUB: the live implementation
/// (1) joins the FROST relay room, (2) waits for the escrow's `SIGN` (learns the PCZT
/// + sighash), (3) runs `verify_pczt_recipients` and ABORTS on failure, (4) delegates
/// to `poker-escrow::payout_signing::join_sign_pczt` (→ `frost-spend::orchestrate`
/// `sign_round1` / `spend_sign_round2_signed`). Not exercised offline.
pub async fn cosign_payout(_ctx: &PayoutSignerContext) -> Result<()> {
    unimplemented!(
        "FROST payout co-sign — live escrow + PCZT required. Flow: join frost_relay \
         room → verify_pczt_recipients(plan) → payout_signing::join_sign_pczt. See \
         module docs; guarded so it is never called offline."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // We do NOT execute the stubs (they intentionally panic); we only assert the
    // types wire together, so the interface is real and compiles.
    #[test]
    fn context_and_plan_types_wire_up() {
        let ctx = PayoutSignerContext {
            relay_room: "fr42".into(),
            public_key_package_hex: "aa".into(),
            key_package_hex: "bb".into(),
            ephemeral_seed_hex: "cc".into(),
            expected_plan: vec![PayoutLine { seat: 0, address: "u1w".into(), amount_zat: 190_000 }],
        };
        assert_eq!(ctx.relay_room, "fr42");
        assert_eq!(ctx.expected_plan.len(), 1);
        assert_eq!(ctx.expected_plan[0].amount_zat, 190_000);
    }
}

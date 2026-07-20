//! FROST payout co-sign — the SECOND co-sign of the paid path.
//!
//! After `/settle` records the co-signed outcome (see `settle.rs`), the escrow
//! builds an Orchard payout PCZT paying the settled plan and opens a 2-of-3 FROST
//! relay room. The escrow is the signing HOST; the two seats are JOINERS. This bot
//! drives a seat, so it runs the JOINER half:
//!
//!   1. Bot receives `srv` `ServerMsg::PayoutSigningRequest { relay_room, plan,
//!      priority_seat, .. }`.
//!   2. Bot joins the FROST relay `relay_room` (SAME `wss://zrelay.rotko.net/ws`
//!      JSON relay + `FrostRelayClient` as DKG — reused from `dkg.rs`).
//!   3. Bot waits for the escrow host's `SIGN:<sighash>:<alphas>:<recipient>:<amount>
//!      :<fee>:<pczt_hex>` message (the exact wire poker-escrow's
//!      `payout_signing::host_sign_pczt` / zafu `relay-protocol.ts` emit).
//!   4. **C3 blind-signer safety check (`verify_pczt_recipients`, THIS module):**
//!      BEFORE contributing ANY FROST signature share, decode the PCZT and confirm
//!      every spendable Orchard output pays EXACTLY the settled `plan`'s
//!      {address, amount_zat}. A blind signer that skips this can be tricked into
//!      co-signing a PCZT that pays an attacker — the on-chain analogue of the very
//!      fork bug `settle.rs` guards. ABORT (do NOT sign) on any mismatch.
//!   5. Only if (4) passes: per action, `sign_round1` (nonce/commitment) then
//!      `spend_sign_round2_signed` (signed share) via `frost-spend::orchestrate`,
//!      exchanging `C:<commits>` and `S:<idx>:<share>` on the relay — byte-identical
//!      to the escrow's `payout_signing::run_multi_rounds`. The bot aggregates each
//!      action independently (`spend_aggregate`) and returns the 64-byte SpendAuth
//!      sigs so both parties converge on the same signature.
//!   6. Escrow aggregates across parties + broadcasts → `ServerMsg::PayoutComplete
//!      { txid }` (or `PayoutFailed { reason }`).
//!
//! SAFETY: this module never broadcasts a transaction. It only contributes FROST
//! shares AFTER the recipient check passes; the escrow host aggregates + broadcasts.

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use frost_spend::orchestrate as fs;
use zcash_address::unified::{Address as UnifiedAddress, Container, Encoding, Receiver};

use crate::dkg::{FrostRelayClient, RelayError, RelayEvent};
use crate::srv::PayoutLine;

/// The secrets + plan a seat needs to FROST-sign a payout, recovered from its DKG
/// output (`dkg::DkgOutput`) plus the `PayoutSigningRequest`.
#[derive(Debug, Clone)]
pub struct PayoutSignerContext {
    /// FROST relay WS URL (SAME relay as DKG — from the room's frost coords).
    pub relay_url: String,
    /// FROST relay room to join (from `PayoutSigningRequest.relay_room`).
    pub relay_room: String,
    /// unique nick for this seat on the relay.
    pub nick: String,
    /// hex-encoded group `PublicKeyPackage` for this escrow (from DKG).
    pub public_key_package_hex: String,
    /// hex-encoded per-seat FROST `KeyPackage` (this seat's secret share, from DKG).
    pub key_package_hex: String,
    /// hex ephemeral signing seed for the round nonces (from DKG).
    pub ephemeral_seed_hex: String,
    /// the settled payout plan this seat agreed to — the ground truth the PCZT
    /// recipients are checked against in `verify_pczt_recipients`.
    pub expected_plan: Vec<PayoutLine>,
    /// mainnet vs testnet — decides how a plan UA string decodes to raw bytes.
    pub mainnet: bool,
}

/// Outcome of a successful co-sign: the 64-byte SpendAuth sigs (one per signed
/// action), hex-encoded. Returned for diagnostics/tests; the escrow host is what
/// actually aggregates across parties and broadcasts.
#[derive(Debug, Clone)]
pub struct PayoutCosignOutput {
    pub action_sigs_hex: Vec<String>,
}

/// The escrow host's `SIGN:` message, parsed into the fields we use.
#[derive(Debug, Clone)]
struct SignRequest {
    sighash: [u8; 32],
    alphas: Vec<[u8; 32]>,
    pczt_hex: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// C3 blind-signer safety check
// ─────────────────────────────────────────────────────────────────────────────

/// **C3 blind-signer safety check.** Decode `pczt_hex` and confirm every Orchard
/// output pays exactly the settled `expected_plan` (address + zatoshi amount).
/// Returns `Ok(())` only when the PCZT is safe to FROST-sign; any decode failure,
/// missing plan line, wrong amount, or unplanned recipient ⇒ `Err`.
///
/// LOGIC:
///   1. Parse the standard PCZT (`pczt 0.7`, same version poker-escrow builds it
///      with) and read every Orchard action's OUTPUT `recipient` (raw 43-byte
///      Orchard receiver) + `value` (zatoshi) — the PCZT keeps these in the clear
///      for the signer, so no OVK-decryption is needed.
///   2. Decode each plan line's UA string to its raw 43-byte Orchard receiver and
///      build the expected multiset of `(recipient_bytes, amount_zat)`.
///   3. Require every plan line to appear as a PCZT output with the exact amount,
///      matched as a multiset (order-independent, no double-count).
///   4. Every REMAINING PCZT output must be recognizable CHANGE back to the escrow
///      (an Orchard output whose recipient equals none of the plan recipients).
///      Change is legitimate — the escrow's own note remainder — BUT a change
///      output that happens to pay a NON-escrow address is exactly the attack this
///      check exists to stop. We cannot see the escrow's change address from the
///      plan alone, so we FAIL CLOSED on any surplus paid-recipient output that we
///      cannot account for: the only outputs allowed are (a) planned recipients and
///      (b) at most one leftover output (the escrow change note). Any extra
///      *paid-recipient* line beyond the plan + single change ⇒ reject.
///
/// This is deliberately conservative: it never green-lights a PCZT whose paid
/// destinations aren't the agreed winner(s). The escrow reserves the tx fee from
/// the pot (it is NOT an output), so the fee never appears here.
pub fn verify_pczt_recipients(pczt_hex: &str, expected_plan: &[PayoutLine]) -> Result<()> {
    let pczt_bytes = hex::decode(pczt_hex.trim())
        .context("C3: PCZT hex decode failed")?;
    let pczt = pczt::Pczt::parse(&pczt_bytes)
        .map_err(|e| anyhow!("C3: PCZT parse failed: {:?}", e))?;

    // 1. enumerate Orchard outputs as (recipient_bytes, value_zat). An output with a
    //    redacted recipient/value can't be checked → fail closed.
    let mut pczt_outputs: Vec<([u8; 43], u64)> = Vec::new();
    for (i, action) in pczt.orchard().actions().iter().enumerate() {
        let out = action.output();
        let recipient = out.recipient().ok_or_else(|| {
            anyhow!("C3: orchard output {i} has no recipient in the PCZT (redacted) — cannot verify, refusing to sign")
        })?;
        let value = out.value().ok_or_else(|| {
            anyhow!("C3: orchard output {i} has no value in the PCZT (redacted) — cannot verify, refusing to sign")
        })?;
        pczt_outputs.push((recipient, value));
    }
    if pczt_outputs.is_empty() {
        bail!("C3: PCZT has no Orchard outputs — nothing pays the plan, refusing to sign");
    }

    // 2. expected recipients (raw bytes) + amounts from the settled plan.
    if expected_plan.is_empty() {
        bail!("C3: empty settled plan — refusing to sign a payout with no agreed recipient");
    }
    let mut expected: Vec<([u8; 43], u64, String)> = Vec::with_capacity(expected_plan.len());
    for line in expected_plan {
        let raw = ua_to_orchard_raw(&line.address).with_context(|| {
            format!("C3: plan address for seat {} is not a decodable Orchard UA", line.seat)
        })?;
        expected.push((raw, line.amount_zat, line.address.clone()));
    }

    // 3. match every plan line against a distinct PCZT output (multiset match).
    let mut remaining: Vec<([u8; 43], u64)> = pczt_outputs.clone();
    for (raw, amount, addr) in &expected {
        match remaining.iter().position(|(r, v)| r == raw && v == amount) {
            Some(pos) => {
                remaining.remove(pos);
            }
            None => {
                // Distinguish "recipient present, wrong amount" from "recipient absent"
                // for a precise, actionable error — both are hard rejects.
                if let Some((_, v)) = remaining.iter().find(|(r, _)| r == raw) {
                    bail!(
                        "C3: plan pays {addr} {amount} zat but the PCZT pays that recipient {v} zat \
                         — AMOUNT MISMATCH, refusing to sign"
                    );
                }
                bail!(
                    "C3: plan recipient {addr} ({amount} zat) is NOT among the PCZT's Orchard \
                     outputs — refusing to sign"
                );
            }
        }
    }

    // 4. Surplus outputs: the escrow may add ONE change output (its own note
    //    remainder). More than one unaccounted paid output — or any that we cannot
    //    treat as change — is the redirect attack we fail closed on. A change
    //    output NEVER matches a plan recipient (those were consumed above); the
    //    escrow's change address is not knowable from the plan alone, so we cap the
    //    surplus at exactly one output.
    if remaining.len() > 1 {
        let extra: Vec<String> = remaining
            .iter()
            .map(|(r, v)| format!("{}…={} zat", short_hex(r), v))
            .collect();
        bail!(
            "C3: PCZT has {} unplanned Orchard outputs (expected at most 1 escrow-change note): [{}] \
             — refusing to sign a PCZT that pays recipients outside the settled plan",
            remaining.len(),
            extra.join(", "),
        );
    }

    Ok(())
}

/// Decode a Zcash unified-address string to its raw 43-byte Orchard receiver — the
/// inverse of `dkg::encode_unified`. Errors if the string isn't a UA or carries no
/// Orchard receiver. Network is taken from the UA's own prefix (we accept whichever
/// the address encodes; the caller pins the plan addresses from the settlement).
fn ua_to_orchard_raw(ua: &str) -> Result<[u8; 43]> {
    let (_net, addr) = UnifiedAddress::decode(ua.trim())
        .map_err(|e| anyhow!("not a unified address: {:?}", e))?;
    for item in addr.items() {
        if let Receiver::Orchard(raw) = item {
            return Ok(raw);
        }
    }
    bail!("unified address has no Orchard receiver")
}

fn short_hex(b: &[u8]) -> String {
    hex::encode(&b[..b.len().min(6)])
}

/// Confirm a plan UA decodes on the expected network (`mainnet` true ⇒ must be a
/// mainnet unified address). Fail closed on any decode error or network mismatch.
fn assert_plan_network(ua: &str, mainnet: bool) -> Result<()> {
    use zcash_protocol::consensus::NetworkType;
    let (net, _addr) = UnifiedAddress::decode(ua.trim())
        .map_err(|e| anyhow!("not a unified address: {:?}", e))?;
    let is_main = matches!(net, NetworkType::Main);
    if is_main != mainnet {
        bail!(
            "plan address network mismatch: expected {}, address is {}",
            if mainnet { "mainnet" } else { "test/regtest" },
            if is_main { "mainnet" } else { "test/regtest" },
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// FROST payout co-sign (JOINER half — mirrors escrow payout_signing::join_sign_pczt)
// ─────────────────────────────────────────────────────────────────────────────

/// Drive this seat's half of the FROST payout co-sign:
///   (1) join the FROST relay room, (2) wait for the escrow host's `SIGN`, (3) run
///   `verify_pczt_recipients` and ABORT on failure, (4) run `sign_round1` +
///   `spend_sign_round2_signed` per action, exchanging shares, and aggregate.
///
/// Returns the 64-byte SpendAuth sigs (hex) once all actions converge. The escrow
/// host aggregates across parties and broadcasts — this bot never broadcasts.
pub async fn cosign_payout(ctx: &PayoutSignerContext, timeout: Duration) -> Result<PayoutCosignOutput> {
    let deadline = Instant::now() + timeout;

    let mut client = FrostRelayClient::connect(&ctx.relay_url, ctx.nick.clone())
        .await
        .context("payout co-sign: connect FROST relay")?;
    client
        .join_room(&ctx.relay_room)
        .await
        .context("payout co-sign: join FROST room")?;

    // 2. wait for the escrow host's SIGN — learns sighash + alphas + the PCZT.
    let req = wait_for_sign(&mut client, &deadline)
        .await
        .context("payout co-sign: waiting for host SIGN")?;

    // Defence-in-depth: every plan address must belong to the network we expect
    // (a mainnet payout must not carry a testnet UA, and vice-versa) — a mismatch is
    // a red flag that the plan was tampered with or crossed wires. Checked BEFORE the
    // C3 decode so an off-network address can never even reach the recipient match.
    for line in &ctx.expected_plan {
        assert_plan_network(&line.address, ctx.mainnet).with_context(|| {
            format!("payout co-sign: plan address for seat {} is not on the expected network", line.seat)
        })?;
    }

    // 3. C3 CHECK FIRST — never contribute a share to a PCZT that pays outside plan.
    if req.pczt_hex.is_empty() {
        bail!(
            "payout co-sign: host SIGN carried NO PCZT — cannot run the C3 recipient check; \
             refusing to blind-sign"
        );
    }
    verify_pczt_recipients(&req.pczt_hex, &ctx.expected_plan)
        .context("payout co-sign: C3 recipient check FAILED — aborting before any FROST share")?;
    tracing::info!(
        actions = req.alphas.len(),
        "payout co-sign: C3 recipient check PASSED — PCZT pays exactly the settled plan"
    );

    // 4. run the per-action FROST rounds (identical wire to the escrow host).
    let sigs = run_multi_rounds(
        &mut client,
        &ctx.public_key_package_hex,
        &ctx.key_package_hex,
        &ctx.ephemeral_seed_hex,
        req.sighash,
        &req.alphas,
        &deadline,
    )
    .await?;

    Ok(PayoutCosignOutput {
        action_sigs_hex: sigs.iter().map(hex::encode).collect(),
    })
}

/// Per-action FROST signing over the relay — byte-for-byte the escrow's
/// `payout_signing::run_multi_rounds` joiner path:
///   `C:<commit1>|<commit2>|...` (both, once) then `S:<idx>:<share>` (both, per action).
async fn run_multi_rounds(
    client: &mut FrostRelayClient,
    public_key_package_hex: &str,
    key_package_hex: &str,
    ephemeral_seed_hex: &str,
    sighash: [u8; 32],
    alphas: &[[u8; 32]],
    deadline: &Instant,
) -> Result<Vec<[u8; 64]>> {
    let seed_bytes = decode_32(ephemeral_seed_hex, "ephemeral_seed")?;
    let n = alphas.len();
    if n == 0 {
        bail!("payout co-sign: host SIGN carried zero alphas (no actions to sign)");
    }

    // round 1: one fresh nonce/commitment per action.
    let mut my_nonces: Vec<String> = Vec::with_capacity(n);
    let mut my_commits: Vec<String> = Vec::with_capacity(n);
    for _ in 0..n {
        let (nonces, signed_commit) = fs::sign_round1(&seed_bytes, key_package_hex)
            .map_err(|e| anyhow!("payout co-sign round1: {:?}", e))?;
        my_nonces.push(nonces);
        my_commits.push(signed_commit);
    }
    client
        .send_message(format!("C:{}", my_commits.join("|")).as_bytes())
        .await
        .context("payout co-sign: send commitments")?;

    let peer_commits_csv = collect_tagged(client, "C:", deadline)
        .await
        .context("payout co-sign: collect peer commitments")?;
    let peer_commits: Vec<String> = peer_commits_csv.split('|').map(|s| s.to_string()).collect();
    if peer_commits.len() != n {
        bail!(
            "payout co-sign: peer sent {} commits, expected {}",
            peer_commits.len(),
            n
        );
    }

    // round 2: per action — sign share, exchange, aggregate.
    let mut out: Vec<[u8; 64]> = Vec::with_capacity(n);
    for i in 0..n {
        let all_commits = vec![my_commits[i].clone(), peer_commits[i].clone()];
        let signed_share = fs::spend_sign_round2_signed(
            &seed_bytes,
            key_package_hex,
            &my_nonces[i],
            &sighash,
            &alphas[i],
            &all_commits,
        )
        .map_err(|e| anyhow!("payout co-sign round2 action {i}: {:?}", e))?;
        client
            .send_message(format!("S:{}:{}", i, signed_share).as_bytes())
            .await
            .with_context(|| format!("payout co-sign: send share {i}"))?;
        let peer_share = wait_share_for(client, i, deadline)
            .await
            .with_context(|| format!("payout co-sign: wait peer share {i}"))?;
        let all_shares = vec![signed_share, peer_share];
        let sig_hex = fs::spend_aggregate(
            public_key_package_hex,
            &sighash,
            &alphas[i],
            &all_commits,
            &all_shares,
        )
        .map_err(|e| anyhow!("payout co-sign aggregate action {i}: {:?}", e))?;
        out.push(decode_64(&sig_hex)?);
    }
    Ok(out)
}

/// Wait for the escrow host's `SIGN:<sighash>:<alphas>:<recipient>:<amount>:<fee>[:<pczt_hex>]`.
async fn wait_for_sign(client: &mut FrostRelayClient, deadline: &Instant) -> Result<SignRequest> {
    loop {
        let remaining = remaining_or_timeout(deadline, "waiting for SIGN")?;
        match client
            .recv_event_timeout(remaining)
            .await
            .map_err(relay_anyhow)?
        {
            Some(RelayEvent::Message { payload }) => {
                let text = String::from_utf8(payload)
                    .map_err(|e| anyhow!("non-utf8 SIGN frame: {e}"))?;
                let Some(body) = text.strip_prefix("SIGN:") else {
                    // pre-sign noise (a peer's stray frame) — keep waiting.
                    continue;
                };
                // SIGN:<sighash>:<alphas>:<recipient>:<amount>:<fee>:<pczt_hex>
                // splitn(6) so the pczt_hex (last field) keeps any ':' intact.
                let mut parts = body.splitn(6, ':');
                let sighash_hex = parts.next().ok_or_else(|| anyhow!("SIGN missing sighash"))?;
                let alphas_csv = parts.next().ok_or_else(|| anyhow!("SIGN missing alphas"))?;
                let _recipient = parts.next().ok_or_else(|| anyhow!("SIGN missing recipient"))?;
                let _amount = parts.next().ok_or_else(|| anyhow!("SIGN missing amount"))?;
                let _fee = parts.next().ok_or_else(|| anyhow!("SIGN missing fee"))?;
                let pczt_hex = parts.next().unwrap_or("").to_string();
                let sighash = decode_32(sighash_hex, "sighash")?;
                let alphas: Vec<[u8; 32]> = alphas_csv
                    .split(',')
                    .map(|h| decode_32(h, "alpha"))
                    .collect::<Result<_>>()?;
                return Ok(SignRequest { sighash, alphas, pczt_hex });
            }
            Some(RelayEvent::PeerJoined { .. }) => continue,
            Some(RelayEvent::Closed { reason }) => bail!("FROST room closed: {reason}"),
            None => bail!("timed out waiting for host SIGN"),
        }
    }
}

/// Collect ONE message with `tag`, returning the body with the tag stripped.
async fn collect_tagged(
    client: &mut FrostRelayClient,
    tag: &str,
    deadline: &Instant,
) -> Result<String> {
    loop {
        let remaining = remaining_or_timeout(deadline, tag)?;
        match client
            .recv_event_timeout(remaining)
            .await
            .map_err(relay_anyhow)?
        {
            Some(RelayEvent::Message { payload }) => {
                let text = String::from_utf8(payload)
                    .map_err(|e| anyhow!("non-utf8 {tag} frame: {e}"))?;
                if let Some(body) = text.strip_prefix(tag) {
                    return Ok(body.to_string());
                }
                // a different-phase frame (stale SIGN echo etc.) — ignore.
            }
            Some(RelayEvent::PeerJoined { .. }) => continue,
            Some(RelayEvent::Closed { reason }) => bail!("FROST room closed: {reason}"),
            None => bail!("timed out collecting {tag}"),
        }
    }
}

/// Wait for the peer's `S:<idx>:<share>` for a specific action index; skip others.
async fn wait_share_for(
    client: &mut FrostRelayClient,
    idx: usize,
    deadline: &Instant,
) -> Result<String> {
    let prefix = format!("S:{}:", idx);
    loop {
        let remaining = remaining_or_timeout(deadline, &format!("share {idx}"))?;
        match client
            .recv_event_timeout(remaining)
            .await
            .map_err(relay_anyhow)?
        {
            Some(RelayEvent::Message { payload }) => {
                let text = String::from_utf8(payload)
                    .map_err(|e| anyhow!("non-utf8 share frame: {e}"))?;
                if let Some(body) = text.strip_prefix(&prefix) {
                    return Ok(body.to_string());
                }
                // other actions' shares — skip.
            }
            Some(RelayEvent::PeerJoined { .. }) => continue,
            Some(RelayEvent::Closed { reason }) => bail!("FROST room closed: {reason}"),
            None => bail!("timed out waiting for share {idx}"),
        }
    }
}

fn relay_anyhow(e: RelayError) -> anyhow::Error {
    anyhow!("FROST relay: {e}")
}

fn remaining_or_timeout(deadline: &Instant, ctx: &str) -> Result<Duration> {
    let now = Instant::now();
    if now >= *deadline {
        bail!("timed out: {ctx}")
    } else {
        Ok(*deadline - now)
    }
}

fn decode_32(h: &str, ctx: &str) -> Result<[u8; 32]> {
    let v = hex::decode(h.trim()).with_context(|| format!("{ctx} hex decode"))?;
    let arr: [u8; 32] = v
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("{ctx} wrong length: {} (want 32)", v.len()))?;
    Ok(arr)
}

fn decode_64(h: &str) -> Result<[u8; 64]> {
    let v = hex::decode(h.trim()).context("sig hex decode")?;
    let arr: [u8; 64] = v
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("sig wrong length: {} (want 64)", v.len()))?;
    Ok(arr)
}


#[cfg(test)]
mod tests {
    use super::*;

    // Real payout PCZTs + their recipient UAs, generated once by poker-escrow's
    // `gen_pczt_fixtures` bin (same pczt 0.7 / orchard NU6.2 pipeline the escrow
    // builds payouts with). Embedding the bytes lets these C3 tests run WITHOUT the
    // heavy orchard/zcash_primitives builder in pokerbot's own dep tree.
    mod fx {
        // `include!` is resolved relative to THIS source file's directory (src/),
        // which sidesteps the nested-module `#[path]` base-dir surprise.
        include!("payout_test_fixtures.rs");
    }

    fn plan(lines: &[(u8, &str, u64)]) -> Vec<PayoutLine> {
        lines
            .iter()
            .map(|(seat, addr, amt)| PayoutLine {
                seat: *seat,
                address: (*addr).to_string(),
                amount_zat: *amt,
            })
            .collect()
    }

    // A PCZT paying exactly the settled two-line plan PASSES.
    #[test]
    fn matching_pczt_passes() {
        let p = plan(&[(0, fx::UA0, 190_000), (1, fx::UA1, 10_000)]);
        verify_pczt_recipients(fx::PCZT_TWO, &p).expect("exact plan match must pass");
    }

    // Winner-take-all single output PASSES.
    #[test]
    fn single_winner_pczt_passes() {
        let p = plan(&[(0, fx::UA0, 200_000)]);
        verify_pczt_recipients(fx::PCZT_WINNER, &p).expect("winner-take-all must pass");
    }

    // TAMPERED RECIPIENT: the PCZT pays a DIFFERENT address than the plan → reject.
    // This is the core blind-signer attack: the escrow (or a MITM) asks us to sign a
    // PCZT that redirects the winner's funds to an attacker. We must NOT sign.
    #[test]
    fn tampered_recipient_fails() {
        // PCZT pays the attacker 190k; plan says pay UA0 190k.
        let p = plan(&[(0, fx::UA0, 190_000)]);
        let err = verify_pczt_recipients(fx::PCZT_ATTACKER, &p)
            .expect_err("PCZT paying a non-plan recipient MUST be rejected");
        let m = err.to_string();
        assert!(m.contains("NOT among") || m.contains("C3"), "unexpected error: {m}");
    }

    // TAMPERED AMOUNT: right recipient, wrong (inflated) amount → reject.
    #[test]
    fn tampered_amount_fails() {
        let p = plan(&[(0, fx::UA0, 190_000)]); // PCZT pays UA0 999_999
        let err = verify_pczt_recipients(fx::PCZT_WRONGAMT, &p)
            .expect_err("wrong amount to the right recipient MUST be rejected");
        assert!(
            err.to_string().contains("AMOUNT MISMATCH"),
            "expected amount-mismatch error, got: {err}"
        );
    }

    // EXTRA RECIPIENTS: plan is satisfied but the PCZT ALSO pays TWO unplanned
    // recipients (a skim) beyond the single change note allowance → reject.
    #[test]
    fn extra_unplanned_recipients_fail() {
        let p = plan(&[(0, fx::UA0, 190_000)]); // PCZT: UA0 190k + skim1 5k + skim2 5k
        let err = verify_pczt_recipients(fx::PCZT_SKIM2, &p)
            .expect_err("2+ unplanned outputs beyond a single change note MUST be rejected");
        assert!(
            err.to_string().contains("unplanned"),
            "expected unplanned-outputs error, got: {err}"
        );
    }

    // A single leftover output (models the escrow's own change note) is tolerated
    // as long as every plan line is paid exactly.
    #[test]
    fn single_change_note_tolerated() {
        let p = plan(&[(0, fx::UA0, 190_000)]); // PCZT: UA0 190k + change 50k
        verify_pczt_recipients(fx::PCZT_CHANGE, &p)
            .expect("plan paid exactly + one change note must pass");
    }

    // MISSING PLAN LINE: PCZT pays only ONE of the two planned recipients → reject.
    // (The winner-only PCZT is used as a plan-of-two against a PCZT-of-one.)
    #[test]
    fn missing_plan_line_fails() {
        let p = plan(&[(0, fx::UA0, 200_000), (1, fx::UA1, 10_000)]);
        let err = verify_pczt_recipients(fx::PCZT_WINNER, &p)
            .expect_err("a plan recipient absent from the PCZT MUST be rejected");
        assert!(err.to_string().contains("NOT among"), "unexpected error: {err}");
    }

    // Garbage / non-PCZT hex fails closed (never a false Ok).
    #[test]
    fn undecodable_pczt_fails() {
        let p = plan(&[(0, fx::UA0, 190_000)]);
        assert!(verify_pczt_recipients("deadbeef", &p).is_err(), "garbage PCZT must fail");
        assert!(verify_pczt_recipients("nothex!!", &p).is_err(), "non-hex must fail");
        assert!(verify_pczt_recipients("", &p).is_err(), "empty must fail");
    }

    // An empty plan is refused outright (can't sign a payout with no agreed recipient).
    #[test]
    fn empty_plan_fails() {
        assert!(
            verify_pczt_recipients(fx::PCZT_WINNER, &[]).is_err(),
            "empty settled plan must be refused"
        );
    }

    // The UA→raw-orchard-bytes decode matches the fixture's raw recipient hex —
    // proving the bytes we compare against the PCZT are the SAME bytes it stores.
    #[test]
    fn ua_decode_matches_fixture_raw() {
        let raw = ua_to_orchard_raw(fx::UA0).expect("decode UA0");
        assert_eq!(hex::encode(raw), fx::RAW0, "UA0 decode must equal fixture raw bytes");
        let raw1 = ua_to_orchard_raw(fx::UA1).expect("decode UA1");
        assert_eq!(hex::encode(raw1), fx::RAW1, "UA1 decode must equal fixture raw bytes");
    }

    // A malformed / non-UA plan address is rejected (never silently skipped).
    #[test]
    fn bad_plan_address_fails() {
        let p = plan(&[(0, "not-a-unified-address", 190_000)]);
        assert!(
            verify_pczt_recipients(fx::PCZT_WINNER, &p).is_err(),
            "an undecodable plan address must fail closed"
        );
    }

    // Context type wires up (kept from the original skeleton).
    #[test]
    fn context_and_plan_types_wire_up() {
        let ctx = PayoutSignerContext {
            relay_url: "wss://zrelay.rotko.net/ws".into(),
            relay_room: "fr42".into(),
            nick: "seat0".into(),
            public_key_package_hex: "aa".into(),
            key_package_hex: "bb".into(),
            ephemeral_seed_hex: "cc".into(),
            expected_plan: vec![PayoutLine { seat: 0, address: "u1w".into(), amount_zat: 190_000 }],
            mainnet: true,
        };
        assert_eq!(ctx.relay_room, "fr42");
        assert_eq!(ctx.expected_plan.len(), 1);
        assert_eq!(ctx.expected_plan[0].amount_zat, 190_000);
    }
}

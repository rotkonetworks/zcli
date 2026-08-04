//! integration tests for the transcript replay-verifier (the "jury").
//!
//! Proves the verifier is not vacuous: a happy transcript verifies valid with
//! the true winner matching the engine, and each tamper is caught with the
//! RIGHT violation. Also round-trips a real self-play hand through verify().
//!
//! Fixtures are REAL: `self_play` drives the actual `poker_pvm` engine and each
//! action carries a genuine ed25519 signature from that seat's session key.
//! Tamper tests mutate that real transcript, so a caught violation means the
//! jury rejected an authentic-looking-but-corrupted log, not a strawman.
//!
//! NOTE on claims: the production settlement `claim.log_hash` is the OUTCOME
//! hash — `settle::log_hash(room, a_stack, b_stack, a_addr, b_addr)` — NOT a
//! hash of the action entries. The jury cross-checks the replayed stacks and
//! the outcome-hash internal consistency; these tests assert both.

use pokerbot::game::{demo_deal, self_play, IdentityMode, Policy, SelfPlayResult};
use pokerbot::identity::SessionIdentity;
use pokerbot::settle;
use pokerbot::transcript::{verify, Deal, RulesSpec, Transcript, TranscriptEntry};

fn rules() -> RulesSpec {
    RulesSpec {
        buyin: 1000,
        sb: 5,
        bb: 10,
    }
}

/// a happy zafu transcript with a truthful claim (goes to showdown, seat 0 = AA wins).
fn happy() -> SelfPlayResult {
    self_play(
        "test-room",
        rules(),
        demo_deal(),
        IdentityMode::Zafu,
        [Policy::CallDown, Policy::CallDown],
        true,
    )
}

/// an anon transcript (no delegation) — seat 0 folds at the first action so
/// seat 1 wins by fold.
fn anon_fold() -> SelfPlayResult {
    self_play(
        "anon-room",
        rules(),
        demo_deal(),
        IdentityMode::Anon,
        [Policy::FoldAt(1), Policy::CallDown],
        false,
    )
}

fn first_violation(t: &Transcript) -> String {
    verify(t).first_violation.unwrap_or_else(|| "<none>".into())
}

/// recompute a truthful OUTCOME-hash claim over a transcript's own room + claim
/// fields, so a claim stays internally consistent after we mutate unrelated bits.
fn refresh_claim_loghash(t: &mut Transcript) {
    if let Some(c) = t.claim.as_mut() {
        c.log_hash = settle::log_hash(&t.room, c.a_stack, c.b_stack, &c.a_addr, &c.b_addr);
    }
}

// ---------------------------------------------------------------------------
// happy paths
// ---------------------------------------------------------------------------

#[test]
fn happy_transcript_verifies_and_winner_matches_engine() {
    let res = happy();
    let report = verify(&res.transcript);
    assert!(report.valid, "happy transcript must verify: {:?}", report.first_violation);
    assert_eq!(
        report.true_winner,
        Some(res.engine_winner),
        "jury winner must match engine winner"
    );
    assert_eq!(report.final_stacks, res.engine_stacks);
    assert_eq!(res.engine_winner, 0, "seat 0 holds AA and should win");
    // chips are conserved: buyins in == stacks out.
    assert_eq!(report.final_stacks[0] + report.final_stacks[1], 2000);
    assert!(report.first_violation.is_none());
}

#[test]
fn anon_fold_hand_winner_is_the_non_folder() {
    let res = anon_fold();
    let report = verify(&res.transcript);
    assert!(report.valid, "anon fold transcript must verify: {:?}", report.first_violation);
    assert_eq!(report.true_winner, Some(1), "seat 1 wins when seat 0 folds");
    assert_eq!(report.true_winner, Some(res.engine_winner));
}

#[test]
fn transcript_json_round_trips_through_serde() {
    let res = happy();
    let json = serde_json::to_string(&res.transcript).unwrap();
    let back: Transcript = serde_json::from_str(&json).unwrap();
    let report = verify(&back);
    assert!(report.valid, "deserialized transcript must still verify");
    assert_eq!(report.true_winner, Some(res.engine_winner));
}

// ---------------------------------------------------------------------------
// tamper: signature (flip an amount)
// ---------------------------------------------------------------------------

#[test]
fn tamper_flip_amount_fails_signature() {
    let mut res = happy();
    // find a bet/call and bump its amount — the recorded sig no longer covers it.
    let idx = res
        .transcript
        .entries
        .iter()
        .position(|e| e.action == "call" || e.action == "bet")
        .unwrap_or(0);
    res.transcript.entries[idx].amount += 1;
    let v = first_violation(&res.transcript);
    assert!(v.starts_with("signatures:"), "expected signature violation, got: {v}");
    assert!(!verify(&res.transcript).valid);
}

// ---------------------------------------------------------------------------
// tamper: sequence (drop an entry / reorder)
// ---------------------------------------------------------------------------

#[test]
fn tamper_drop_entry_fails_sequence() {
    let mut res = happy();
    // drop the 2nd entry — remaining seqs now have a gap (1,3,4,...).
    res.transcript.entries.remove(1);
    let v = first_violation(&res.transcript);
    assert!(v.starts_with("sequence:"), "expected sequence violation, got: {v}");
}

#[test]
fn tamper_reorder_entries_fails_sequence() {
    let mut res = happy();
    res.transcript.entries.swap(0, 1);
    let v = first_violation(&res.transcript);
    assert!(v.starts_with("sequence:"), "expected sequence violation, got: {v}");
}

// ---------------------------------------------------------------------------
// tamper: forge an action by the wrong seat (session_pub mismatch)
// ---------------------------------------------------------------------------

#[test]
fn tamper_forge_wrong_seat_fails_signature_check() {
    let mut res = happy();
    // seat 0's entry, but stamped with seat 1's registered session key. even a
    // valid signature by seat 1 can't authorize an action attributed to seat 0.
    let seat1_pub = res.transcript.players[1].session_pub.clone();
    let victim = res
        .transcript
        .entries
        .iter()
        .position(|e| e.seat == 0)
        .unwrap();
    res.transcript.entries[victim].session_pub = seat1_pub;
    let v = first_violation(&res.transcript);
    assert!(
        v.contains("does not match seat") && v.starts_with("signatures:"),
        "expected forged-actor (session_pub mismatch) violation, got: {v}"
    );
}

// ---------------------------------------------------------------------------
// tamper: inject an illegal action (replay fails)
// ---------------------------------------------------------------------------

#[test]
fn tamper_illegal_action_fails_replay() {
    let res = happy();
    // We can't recover the client's private key from the transcript, so we build
    // a transcript with a single re-signed ILLEGAL action using known identities:
    // seat 0 (SB) preflop is facing the big blind, so CHECK is illegal — the
    // engine rejects it on replay. signatures + sequence pass, isolating the
    // failure to the replay step.
    let seat0 = SessionIdentity::anon(0);
    let seat1 = SessionIdentity::anon(1);
    let mut t = res.transcript.clone();
    t.players[0].session_pub = seat0.session_pub_hex();
    t.players[0].zafu_pub = None;
    t.players[0].delegation = None;
    t.players[0].pinned_id = Some(seat0.pinned_id_hex());
    t.players[1].session_pub = seat1.session_pub_hex();
    t.players[1].zafu_pub = None;
    t.players[1].delegation = None;
    t.players[1].pinned_id = Some(seat1.pinned_id_hex());
    t.claim = None;
    t.transcript_hash = None;
    // one signed, sequence-correct, but ILLEGAL action: seat 0 checks facing BB.
    let sig = seat0.sign_action("check", 0, 1);
    t.entries = vec![TranscriptEntry {
        seq: 1,
        seat: 0,
        action: "check".into(),
        amount: 0,
        sig,
        session_pub: seat0.session_pub_hex(),
        relay_ts: 1000,
        local_ts: 0,
    }];
    let report = verify(&t);
    let v = report.first_violation.clone().unwrap_or_default();
    assert!(v.starts_with("replay:"), "expected replay violation, got: {v}");
    assert!(v.contains("illegal action"), "detail should name the illegal action: {v}");
    assert!(!report.valid);
}

// ---------------------------------------------------------------------------
// tamper: acting out of turn (replay catches it via acting_seat)
// ---------------------------------------------------------------------------

#[test]
fn tamper_act_out_of_turn_fails_replay() {
    // build a valid 2-action prefix, then re-sign so seat 0 acts twice in a row.
    let seat0 = SessionIdentity::anon(0);
    let seat1 = SessionIdentity::anon(1);
    let mut t = happy().transcript;
    t.players[0].session_pub = seat0.session_pub_hex();
    t.players[0].zafu_pub = None;
    t.players[0].delegation = None;
    t.players[0].pinned_id = Some(seat0.pinned_id_hex());
    t.players[1].session_pub = seat1.session_pub_hex();
    t.players[1].zafu_pub = None;
    t.players[1].delegation = None;
    t.players[1].pinned_id = Some(seat1.pinned_id_hex());
    t.claim = None;
    t.transcript_hash = None;
    // seq1: seat0 calls (legal). seq2: seat0 AGAIN (should be seat1's turn).
    let e1 = TranscriptEntry {
        seq: 1,
        seat: 0,
        action: "call".into(),
        amount: 0,
        sig: seat0.sign_action("call", 0, 1),
        session_pub: seat0.session_pub_hex(),
        relay_ts: 1000,
        local_ts: 0,
    };
    let e2 = TranscriptEntry {
        seq: 2,
        seat: 0,
        action: "check".into(),
        amount: 0,
        sig: seat0.sign_action("check", 0, 2),
        session_pub: seat0.session_pub_hex(),
        relay_ts: 2000,
        local_ts: 0,
    };
    t.entries = vec![e1, e2];
    let v = first_violation(&t);
    assert!(v.starts_with("replay:"), "expected replay violation, got: {v}");
    assert!(v.contains("out of turn"), "detail should say out of turn: {v}");
}

// ---------------------------------------------------------------------------
// tamper: lie in the claim (stacks / log_hash)
// ---------------------------------------------------------------------------

#[test]
fn tamper_claim_wrong_stacks_fails_cross_check() {
    let mut res = happy();
    let claim = res.transcript.claim.as_mut().unwrap();
    // operator claims seat 1 (the loser) actually won. Keep the log_hash
    // internally consistent with the lied stacks so the FIRST violation is the
    // stacks mismatch against the replayed truth (not a self-inconsistent hash).
    claim.a_stack = 990;
    claim.b_stack = 1010;
    refresh_claim_loghash(&mut res.transcript);
    let report = verify(&res.transcript);
    let v = report.first_violation.clone().unwrap_or_default();
    assert!(v.starts_with("claim-stacks:"), "expected claim-stacks violation, got: {v}");
    assert!(v.contains("LIE"), "should be flagged as a lie: {v}");
    assert!(!report.valid);
    // the jury still reports the TRUE winner regardless of the lie.
    assert_eq!(report.true_winner, Some(0));
}

#[test]
fn tamper_claim_wrong_loghash_fails_cross_check() {
    let mut res = happy();
    let claim = res.transcript.claim.as_mut().unwrap();
    claim.log_hash = "deadbeef".repeat(8); // 64 hex chars, wrong
    let report = verify(&res.transcript);
    let v = report.first_violation.clone().unwrap_or_default();
    assert!(v.starts_with("claim-loghash:"), "expected claim-loghash violation, got: {v}");
    assert!(!report.valid);
}

#[test]
fn honest_claim_loghash_is_the_outcome_hash() {
    // the claim the client emits carries the OUTCOME hash (settle::log_hash over
    // the final stacks + payout addrs), NOT a hash of the action entries.
    let res = happy();
    let claim = res.transcript.claim.clone().unwrap();
    let recomputed = settle::log_hash(
        &res.transcript.room,
        claim.a_stack,
        claim.b_stack,
        &claim.a_addr,
        &claim.b_addr,
    );
    assert_eq!(claim.log_hash, recomputed, "claim.log_hash must be the outcome hash");
}

// ---------------------------------------------------------------------------
// tamper: delegation signed by the wrong zafu key
// ---------------------------------------------------------------------------

#[test]
fn tamper_wrong_zafu_delegation_fails() {
    let mut res = happy();
    // replace seat 0's zafu pubkey with a different key that never signed the
    // delegation — the delegation signature no longer verifies under it.
    let impostor = SessionIdentity::zafu(0, "test-room");
    res.transcript.players[0].zafu_pub = impostor.zafu_pub_hex();
    // pinned_id follows the (impostor) zafu key so the pinned-id check passes and
    // the failure is isolated to the delegation signature itself.
    res.transcript.players[0].pinned_id = Some(impostor.zafu_pub_hex().unwrap());
    let v = first_violation(&res.transcript);
    assert!(v.starts_with("delegation[seat 0]:"), "expected delegation violation, got: {v}");
}

#[test]
fn tamper_pinned_id_mismatch_fails() {
    let mut res = happy();
    // the on-chain deposit id doesn't match the seat's authorizing zafu key.
    res.transcript.players[1].pinned_id = Some("11".repeat(32));
    let v = first_violation(&res.transcript);
    assert!(v.starts_with("pinned-id[seat 1]:"), "expected pinned-id violation, got: {v}");
}

// ---------------------------------------------------------------------------
// timing
// ---------------------------------------------------------------------------

#[test]
fn timeout_gap_is_flagged_but_not_fatal() {
    let mut res = happy();
    // blow past the agreed timeout on one action's relay gap.
    res.transcript.timeout_ms = 500;
    // widen the gap before entry index 2 (keep the rest monotonic).
    assert!(res.transcript.entries.len() > 2, "need at least 3 entries");
    res.transcript.entries[2].relay_ts += 10_000;
    for e in res.transcript.entries.iter_mut().skip(3) {
        e.relay_ts += 10_000;
    }
    // relay_ts is not part of the OUTCOME hash, so the claim stays truthful; but
    // the recorded action-log digest DID cover relay_ts — refresh it so the only
    // signal is the (non-fatal) timeout note.
    res.transcript.transcript_hash =
        Some(pokerbot::transcript::transcript_hash(&res.transcript.entries));
    let report = verify(&res.transcript);
    // timeouts are non-fatal: overall still valid.
    assert!(report.valid, "timeout must not invalidate: {:?}", report.first_violation);
    let note = report
        .checks
        .iter()
        .find(|c| c.name == "timing-timeout")
        .unwrap();
    assert!(note.detail.contains("TIMEOUT"), "timeout should be noted: {}", note.detail);
}

#[test]
fn non_monotonic_relay_ts_fails() {
    let mut res = happy();
    assert!(res.transcript.entries.len() > 1, "need at least 2 entries");
    res.transcript.entries[1].relay_ts = 0; // goes backwards from entry 0
    // refresh the action-log digest so the FIRST violation is the monotonic clock.
    res.transcript.transcript_hash =
        Some(pokerbot::transcript::transcript_hash(&res.transcript.entries));
    let v = first_violation(&res.transcript);
    assert!(v.starts_with("timing-monotonic:"), "expected monotonic violation, got: {v}");
}

// ---------------------------------------------------------------------------
// the demo Deal helper is a valid card set
// ---------------------------------------------------------------------------

#[test]
fn demo_deal_is_a_valid_card_set() {
    let d: Deal = demo_deal();
    let mut seen = std::collections::HashSet::new();
    for c in d.hole.iter().flatten().chain(d.community.iter()) {
        assert!(*c < 52, "card {c} out of range");
        assert!(seen.insert(*c), "duplicate card {c} in demo deal");
    }
}

// ---------------------------------------------------------------------------
// round-trip through the CLI: `selfplay --stake --emit-transcript` → load →
// verify() valid + true_winner matches.
// ---------------------------------------------------------------------------

#[test]
fn cli_emit_transcript_round_trips_through_verify() {
    // build the transcript exactly as the `--emit-transcript` CLI path does
    // (staked demo hand, zafu, truthful claim), write it to a temp file, read it
    // back, and adjudicate.
    let res = self_play(
        "selfplay-seed-1",
        rules(),
        demo_deal(),
        IdentityMode::Zafu,
        [Policy::CallDown, Policy::CallDown],
        true, // staked → truthful settlement claim attached
    );
    let dir = std::env::temp_dir().join(format!("pokerbot-tx-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("tx.json");
    std::fs::write(&path, serde_json::to_string_pretty(&res.transcript).unwrap()).unwrap();

    // read it back from disk and adjudicate — the on-disk round-trip the CLI does.
    let raw = std::fs::read_to_string(&path).unwrap();
    let back: Transcript = serde_json::from_str(&raw).unwrap();
    let report = verify(&back);
    assert!(report.valid, "emitted transcript must verify VALID: {:?}", report.first_violation);
    assert_eq!(
        report.true_winner,
        Some(res.engine_winner),
        "jury winner must match the engine's true winner"
    );
    assert_eq!(report.true_winner, Some(0), "seat 0 (AA) is the true winner");
    let _ = std::fs::remove_file(&path);
}

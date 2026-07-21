//! transcript replay-verifier — the "jury".
//!
//! Given a signed action log (the transcript a real match emits) this module
//! adjudicates, with math alone, who actually won a hand and what the true
//! final stacks were. No money, no network, no chain: pure crypto + the
//! deterministic `poker_pvm` engine. A dispute is settled by replay, not by an
//! operator's PIN ruling.
//!
//! The checks mirror the jury steps documented in the browser client's
//! `transcript-filter.ts`:
//!   1. delegation      — zafu → session chain of trust (+ on-chain id binding)
//!   2. per-action sig   — session key signed exactly this action
//!   3. sequence         — seq = 1,2,3,… and each actor acted in turn
//!   4. timing           — relay clock monotonic; per-action timeout
//!   5. replay           — every action is legal in the engine → true winner
//!   6. claim cross-check — a claimed settlement matches the replayed truth
//!
//! Tier 1 (this module) takes the revealed deck (`deal`) AS GIVEN. It does NOT
//! yet prove the shuffle was fair — that is the Tier-2 follow-on (zk-shuffle /
//! Chaum–Pedersen proofs). See the module tail note.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{action_from_name, action_message, delegation_message, verify_hex};
use crate::settle::{self, Claim};

use poker_pvm::{GameState, Rules, SignedAction};

// ---------------------------------------------------------------------------
// serde container — the on-disk / on-wire transcript
// ---------------------------------------------------------------------------

/// one signed action, byte-compatible with transcript-filter.ts::TranscriptEntry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TranscriptEntry {
    pub seq: u32,
    pub seat: u8,
    /// lowercase action name: fold/check/call/bet/raise/allin
    pub action: String,
    pub amount: u64,
    /// hex ed25519 signature over "{seat}|{action}|{amount}|{seq}"
    pub sig: String,
    #[serde(rename = "sessionPub")]
    pub session_pub: String,
    /// relay-assigned timestamp (neutral clock). In offline self-play this is a
    /// synthetic monotonic counter — real relayTs only exists over the network.
    #[serde(rename = "relayTs")]
    pub relay_ts: u64,
    /// recorder-local timestamp (untrusted). 0 in offline self-play.
    #[serde(rename = "localTs", default)]
    pub local_ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesSpec {
    pub buyin: u64,
    pub sb: u64,
    pub bb: u64,
}

impl RulesSpec {
    pub fn to_engine(&self) -> Rules {
        Rules {
            buyin: self.buyin as u32,
            small_blind: self.sb as u32,
            big_blind: self.bb as u32,
            turn_timeout_blocks: 0,
            rake_bps: 0,
            rake_cap: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Player {
    pub seat: u8,
    #[serde(rename = "sessionPub")]
    pub session_pub: String,
    #[serde(rename = "zafuPub", default, skip_serializing_if = "Option::is_none")]
    pub zafu_pub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<String>,
    /// the `;id:` ed25519 hex from the on-chain deposit memo, if adjudicating a
    /// real match. binds the transcript to the seat that actually deposited.
    #[serde(rename = "pinnedId", default, skip_serializing_if = "Option::is_none")]
    pub pinned_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deal {
    /// revealed hole cards per seat (card idx 0..51). Tier 1 takes as given.
    pub hole: [[u8; 2]; 2],
    pub community: [u8; 5],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transcript {
    pub room: String,
    /// agreed per-action timeout in ms (0 = don't check timing gaps).
    #[serde(rename = "timeoutMs", default)]
    pub timeout_ms: u64,
    pub rules: RulesSpec,
    pub players: [Player; 2],
    pub deal: Deal,
    pub entries: Vec<TranscriptEntry>,
    /// the settlement being disputed, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<Claim>,
    /// OPTIONAL SHA-256 of the canonical action-log entries (an integrity digest
    /// over the exact action stream). This is a SEPARATE artifact from the
    /// settlement binding: the settlement `claim.log_hash` is the OUTCOME hash
    /// (`settle::log_hash` over final stacks/addrs), whereas this records the
    /// action-log itself. Recorded/checked only if present.
    #[serde(rename = "transcriptHash", default, skip_serializing_if = "Option::is_none")]
    pub transcript_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    /// true iff every hard check passed (timing timeouts are noted, not fatal).
    pub valid: bool,
    /// the adjudicated winner seat (None only if replay never completed).
    pub true_winner: Option<u8>,
    /// the true final stacks after replay [seat0, seat1].
    pub final_stacks: [u64; 2],
    /// every check run, in order: (name, pass, human detail).
    pub checks: Vec<CheckResult>,
    /// the first hard violation encountered, if any.
    pub first_violation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub pass: bool,
    pub detail: String,
}

/// internal accumulator so each check records itself and the first hard failure
/// short-circuits cleanly.
struct Report {
    checks: Vec<CheckResult>,
    first_violation: Option<String>,
}

impl Report {
    fn new() -> Self {
        Self {
            checks: Vec::new(),
            first_violation: None,
        }
    }

    /// record a check outcome. a failing check sets the first violation.
    fn record(&mut self, name: &str, pass: bool, detail: impl Into<String>) {
        let detail = detail.into();
        if !pass && self.first_violation.is_none() {
            self.first_violation = Some(format!("{}: {}", name, detail));
        }
        self.checks.push(CheckResult {
            name: name.into(),
            pass,
            detail,
        });
    }
}

// ---------------------------------------------------------------------------
// the jury
// ---------------------------------------------------------------------------

/// adjudicate a transcript. runs every check, returns a structured report with
/// the TRUE winner + final stacks and the first violation (if any).
pub fn verify(t: &Transcript) -> VerifyReport {
    let mut r = Report::new();

    // ---- 1. delegation (+ pinned-id binding) --------------------------------
    check_delegation(t, &mut r);

    // ---- 2. per-action signatures -------------------------------------------
    check_signatures(t, &mut r);

    // ---- 3. sequence + acting-in-turn ---------------------------------------
    // needs the engine to know whose turn it is; folded into replay below via a
    // dry acting-seat trace. we first do the cheap monotonic-seq check here.
    check_sequence_numbers(t, &mut r);

    // ---- 4. timing ----------------------------------------------------------
    check_timing(t, &mut r);

    // ---- 5. replay (also enforces acting-in-turn) ---------------------------
    let replay = replay_hand(t, &mut r);

    // ---- 6. claim cross-check ----------------------------------------------
    if let Some(claim) = &t.claim {
        check_claim(t, claim, &replay, &mut r);
    }

    // ---- optional: action-log integrity digest ------------------------------
    if let Some(th) = &t.transcript_hash {
        let real = transcript_hash(&t.entries);
        let ok = eq_hex(th, &real);
        r.record(
            "transcript-hash",
            ok,
            if ok {
                "recorded transcript_hash matches the action log".to_string()
            } else {
                format!(
                    "recorded transcript_hash {}… != actual {}…",
                    short(th),
                    short(&real)
                )
            },
        );
    }

    let valid = r.first_violation.is_none();
    VerifyReport {
        valid,
        true_winner: replay.winner,
        final_stacks: replay.final_stacks,
        checks: r.checks,
        first_violation: r.first_violation,
    }
}

// --- check 1 ---------------------------------------------------------------

fn check_delegation(t: &Transcript, r: &mut Report) {
    for p in &t.players {
        // zafu mode: a zafu key must have delegated to this session key.
        match (&p.zafu_pub, &p.delegation) {
            (Some(zpub), Some(del)) => {
                let msg = delegation_message(&p.session_pub, &t.room);
                let ok = verify_hex(zpub, &msg, del);
                r.record(
                    &format!("delegation[seat {}]", p.seat),
                    ok,
                    if ok {
                        format!("zafu {}… → session {}…", short(zpub), short(&p.session_pub))
                    } else {
                        "zafu delegation signature invalid".into()
                    },
                );
                // pinned-id binding: the on-chain id must equal the zafu key
                // (the authorizing identity in zafu mode).
                if let Some(pid) = &p.pinned_id {
                    let bound = eq_hex(pid, zpub);
                    r.record(
                        &format!("pinned-id[seat {}]", p.seat),
                        bound,
                        if bound {
                            "on-chain id == zafu key".into()
                        } else {
                            format!("pinned id {}… != zafu key {}…", short(pid), short(zpub))
                        },
                    );
                }
            }
            (None, None) => {
                // anon mode: session key IS the identity. nothing to delegate.
                r.record(
                    &format!("delegation[seat {}]", p.seat),
                    true,
                    "anon mode (session key is the identity)",
                );
                if let Some(pid) = &p.pinned_id {
                    let bound = eq_hex(pid, &p.session_pub);
                    r.record(
                        &format!("pinned-id[seat {}]", p.seat),
                        bound,
                        if bound {
                            "on-chain id == session key".into()
                        } else {
                            format!(
                                "pinned id {}… != session key {}…",
                                short(pid),
                                short(&p.session_pub)
                            )
                        },
                    );
                }
            }
            _ => {
                // exactly one of zafu_pub / delegation present — malformed.
                r.record(
                    &format!("delegation[seat {}]", p.seat),
                    false,
                    "zafu_pub and delegation must both be present or both absent",
                );
            }
        }
    }
}

// --- check 2 ---------------------------------------------------------------

fn check_signatures(t: &Transcript, r: &mut Report) {
    let mut all_ok = true;
    let mut detail = format!("{} action signatures valid", t.entries.len());
    for e in &t.entries {
        // an actor may only sign as the session key registered for their seat.
        let seat = e.seat as usize;
        if seat >= t.players.len() {
            all_ok = false;
            detail = format!("entry seq {} has out-of-range seat {}", e.seq, e.seat);
            break;
        }
        if !eq_hex(&e.session_pub, &t.players[seat].session_pub) {
            all_ok = false;
            detail = format!(
                "entry seq {}: session_pub does not match seat {}'s registered key (forged actor)",
                e.seq, e.seat
            );
            break;
        }
        let msg = action_message(e.seat, &e.action, e.amount, e.seq);
        if !verify_hex(&e.session_pub, &msg, &e.sig) {
            all_ok = false;
            detail = format!(
                "entry seq {}: signature invalid over \"{}|{}|{}|{}\" (tampered action)",
                e.seq, e.seat, e.action, e.amount, e.seq
            );
            break;
        }
    }
    r.record("signatures", all_ok, detail);
}

// --- check 3 ---------------------------------------------------------------

fn check_sequence_numbers(t: &Transcript, r: &mut Report) {
    let mut ok = true;
    let mut detail = format!("seq strictly 1..={}", t.entries.len());
    for (i, e) in t.entries.iter().enumerate() {
        let expected = (i as u32) + 1;
        if e.seq != expected {
            ok = false;
            detail = format!(
                "entry #{}: seq = {}, expected {} (gap/dup/reorder)",
                i, e.seq, expected
            );
            break;
        }
    }
    r.record("sequence", ok, detail);
}

// --- check 4 ---------------------------------------------------------------

fn check_timing(t: &Transcript, r: &mut Report) {
    // monotonic relay clock (hard).
    let mut mono_ok = true;
    let mut mono_detail = "relay_ts non-decreasing".to_string();
    for w in t.entries.windows(2) {
        if w[1].relay_ts < w[0].relay_ts {
            mono_ok = false;
            mono_detail = format!(
                "relay_ts went backwards at seq {} ({} < {})",
                w[1].seq, w[1].relay_ts, w[0].relay_ts
            );
            break;
        }
    }
    r.record("timing-monotonic", mono_ok, mono_detail);

    // per-action timeout (soft: reported, does not invalidate — a timed-out
    // actor's turn is adjudicable, see transcript-filter.ts §3).
    if t.timeout_ms > 0 {
        let mut timeouts = Vec::new();
        for w in t.entries.windows(2) {
            let gap = w[1].relay_ts.saturating_sub(w[0].relay_ts);
            if gap > t.timeout_ms {
                timeouts.push(format!("seq {} (+{}ms)", w[1].seq, gap));
            }
        }
        // record as a passing (non-fatal) note either way.
        let detail = if timeouts.is_empty() {
            format!("no action exceeded {}ms", t.timeout_ms)
        } else {
            format!("TIMEOUTS (non-fatal, adjudicable): {}", timeouts.join(", "))
        };
        r.checks.push(CheckResult {
            name: "timing-timeout".into(),
            pass: true,
            detail,
        });
    }
}

// --- check 5 ---------------------------------------------------------------

struct Replay {
    winner: Option<u8>,
    final_stacks: [u64; 2],
}

fn replay_hand(t: &Transcript, r: &mut Report) -> Replay {
    let mut gs = GameState::new(t.rules.to_engine(), 2);
    gs.deal(&t.deal.hole, t.deal.community);

    let mut ok = true;
    let mut detail = format!("all {} actions legal", t.entries.len());
    let mut fold_winner: Option<u8> = None;
    let mut reached_showdown = false;

    for e in &t.entries {
        // acting-in-turn (part of check 3, enforced against live engine state).
        if e.seat != gs.acting_seat {
            ok = false;
            detail = format!(
                "entry seq {}: seat {} acted out of turn (engine expects seat {})",
                e.seq, e.seat, gs.acting_seat
            );
            break;
        }
        let Some(action) = action_from_name(&e.action) else {
            ok = false;
            detail = format!("entry seq {}: unknown action \"{}\"", e.seq, e.action);
            break;
        };
        let sa = SignedAction {
            seat: e.seat,
            action,
            amount: e.amount as u32,
            seq: e.seq,
            sig: [0u8; 64], // replay does not re-check sigs (check 2 did)
        };
        match gs.apply(&sa) {
            Ok(res) => {
                if res.hand_over && res.winner != 255 {
                    // ended by fold: engine credited the pot to res.winner.
                    fold_winner = Some(res.winner);
                }
                if matches!(gs.phase, poker_pvm::Phase::Showdown) {
                    reached_showdown = true;
                }
            }
            Err(why) => {
                ok = false;
                detail = format!(
                    "entry seq {}: illegal action {} ({}) — actor cheated or transcript invalid",
                    e.seq, e.action, why
                );
                break;
            }
        }
    }
    r.record("replay", ok, detail);

    // determine winner + true final stacks.
    let winner = if !ok {
        None
    } else if let Some(w) = fold_winner {
        Some(w)
    } else if reached_showdown {
        // showdown() distributes the pot into stacks and returns the headline seat.
        Some(gs.showdown())
    } else {
        // transcript ended mid-hand (incomplete). no adjudicated winner, but the
        // stacks so far are still reportable. flag as a soft note.
        r.checks.push(CheckResult {
            name: "completeness".into(),
            pass: true,
            detail: "transcript ended before showdown/fold (hand incomplete)".into(),
        });
        None
    };

    Replay {
        winner,
        final_stacks: [gs.stacks[0] as u64, gs.stacks[1] as u64],
    }
}

// --- check 6 ---------------------------------------------------------------

/// Cross-check a settlement `Claim` against the replayed truth.
///
/// The production settlement `claim.log_hash` is the OUTCOME hash — the
/// `settle::log_hash(code, a_stack, b_stack, a_addr, b_addr)` SHA-256 of the
/// canonical `"zk.poker/log/v1:…"` string — NOT a hash of the action entries.
/// So we:
///   (a) assert the REPLAYED final stacks equal `claim.a_stack`/`b_stack`
///       (the primary, engine-truth check), and
///   (b) recompute `settle::log_hash(room, claim.a_stack, claim.b_stack,
///       claim.a_addr, claim.b_addr)` and require it to equal `claim.log_hash`
///       (the claim's internal consistency — a peer can't smuggle a mismatched
///       outcome hash past its own fields). `code` is the transcript `room`.
fn check_claim(t: &Transcript, claim: &Claim, replay: &Replay, r: &mut Report) {
    let stacks_ok =
        claim.a_stack == replay.final_stacks[0] && claim.b_stack == replay.final_stacks[1];
    let stacks_detail = if stacks_ok {
        format!(
            "claimed stacks [{}, {}] == replayed truth",
            claim.a_stack, claim.b_stack
        )
    } else {
        format!(
            "LIE: claimed stacks [{}, {}] but replay says [{}, {}]",
            claim.a_stack, claim.b_stack, replay.final_stacks[0], replay.final_stacks[1]
        )
    };
    r.record("claim-stacks", stacks_ok, stacks_detail);

    // (b) the OUTCOME hash must be internally consistent with the claim's own
    //     stacks + addrs under the production settle::log_hash format.
    let expected = settle::log_hash(
        &t.room,
        claim.a_stack,
        claim.b_stack,
        &claim.a_addr,
        &claim.b_addr,
    );
    let hash_ok = eq_hex(&claim.log_hash, &expected);
    let hash_detail = if hash_ok {
        "claimed log_hash == settle::log_hash over the claim's own outcome fields".into()
    } else {
        format!(
            "LIE: claimed log_hash {}… but outcome hashes to {}…",
            short(&claim.log_hash),
            short(&expected)
        )
    };
    r.record("claim-loghash", hash_ok, hash_detail);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// SHA-256 (hex) over the canonical serialization of the action entries. This is
/// the OPTIONAL action-log integrity digest recorded in `Transcript::transcript_hash`
/// — NOT the settlement binding (that is `settle::log_hash`, the outcome hash).
///
/// The entries serialize into the exact key order the browser client's
/// `transcript-filter.ts::record` produces: seq, seat, action, amount, sig,
/// sessionPub, relayTs, localTs. `serde_json` preserves struct field order, so
/// `LogEntryForHash` controls the hashed byte stream.
pub fn transcript_hash(entries: &[TranscriptEntry]) -> String {
    let for_hash: Vec<LogEntryForHash> = entries.iter().map(LogEntryForHash::from).collect();
    let json = serde_json::to_string(&for_hash).expect("transcript entries serialize");
    hex::encode(Sha256::digest(json.as_bytes()))
}

/// A view of a transcript entry whose serde field order matches the JS object
/// key order in transcript-filter.ts (localTs last).
#[derive(Serialize)]
struct LogEntryForHash {
    seq: u32,
    seat: u8,
    action: String,
    amount: u64,
    sig: String,
    #[serde(rename = "sessionPub")]
    session_pub: String,
    #[serde(rename = "relayTs")]
    relay_ts: u64,
    #[serde(rename = "localTs")]
    local_ts: u64,
}

impl From<&TranscriptEntry> for LogEntryForHash {
    fn from(e: &TranscriptEntry) -> Self {
        Self {
            seq: e.seq,
            seat: e.seat,
            action: e.action.clone(),
            amount: e.amount,
            sig: e.sig.clone(),
            session_pub: e.session_pub.clone(),
            relay_ts: e.relay_ts,
            local_ts: e.local_ts,
        }
    }
}

/// case-insensitive hex equality (an on-chain id and a session key may differ
/// only in case). compares decoded bytes when both decode, else raw ascii-lower.
fn eq_hex(a: &str, b: &str) -> bool {
    match (hex::decode(a), hex::decode(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a.eq_ignore_ascii_case(b),
    }
}

fn short(s: &str) -> &str {
    &s[..s.len().min(10)]
}

// ---------------------------------------------------------------------------
// TIER-1 SCOPE NOTE — what this does NOT yet prove
// ---------------------------------------------------------------------------
// verify() takes `t.deal` (the hole + community cards) AS GIVEN. It proves the
// BETTING was honest — signatures, turn order, legal actions, and the true
// winner given those cards — and that any settlement claim matches. It does NOT
// prove the DECK was fair: that the hole cards were dealt by an unbiased,
// unpeeked shuffle. A colluding dealer who fixes the cards would still produce a
// transcript that verifies "valid" here. Closing that gap is Tier 2: bind
// `deal` to zk-shuffle / Chaum–Pedersen shuffle proofs + ElGamal card masking
// so the revealed cards are provably the committed, fairly-shuffled deck. Until
// then, "valid" means "the money followed the rules for the cards shown", not
// "the cards were fair".

#[cfg(test)]
mod tests {
    // the full verifier test-suite (happy path + tamper cases + round-trip)
    // lives in tests/verify.rs so it can build a real transcript via game.rs.
    #[test]
    fn eq_hex_is_case_insensitive() {
        assert!(super::eq_hex("AABB", "aabb"));
        assert!(!super::eq_hex("aabb", "aacc"));
    }

    #[test]
    fn transcript_hash_is_order_sensitive() {
        use super::TranscriptEntry;
        let entry = |seq: u32| TranscriptEntry {
            seq,
            seat: (seq % 2) as u8,
            action: "call".into(),
            amount: 10,
            sig: "aa".repeat(64),
            session_pub: "bb".repeat(32),
            relay_ts: seq as u64 * 100,
            local_ts: 0,
        };
        let a = vec![entry(1), entry(2), entry(3)];
        let mut b = a.clone();
        b.swap(0, 2);
        assert_eq!(super::transcript_hash(&a), super::transcript_hash(&a));
        assert_ne!(
            super::transcript_hash(&a),
            super::transcript_hash(&b),
            "reordering must change the digest"
        );
    }
}

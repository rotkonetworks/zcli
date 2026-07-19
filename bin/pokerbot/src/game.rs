//! Heads-up game driver: runs a local `poker_pvm::GameState` per seat, plays a
//! seeded reproducible bot policy, exchanges encrypted action/deal/showdown
//! messages with the peer, and records the outcome of every hand.
//!
//! Both seats run identical code. The HOST (seat 0) is the dealer: it shuffles
//! the deck with the seeded RNG each hand and sends the guest its hole cards.
//! Every action either side takes is validated by BOTH engines independently —
//! that is the whole point: if a legal action our engine accepted is REJECTED
//! by the peer's engine (or the two engines disagree on a winner), we have
//! found a real desync bug and we abort loudly with the exact state.

use anyhow::{anyhow, bail, Result};
use poker_pvm::{Action, GameState, Phase, Rules, SeatState, SignedAction};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde_json::json;
use tracing::{debug, trace};

use crate::identity::Identity;
use crate::session::{GameMsg, Peer};
use crate::settle::{self, Settlement};

/// One hand's agreed result, compared across the two seats' vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandResult {
    pub hand_number: u32,
    /// winning seat, 255 = chop/split (showdown returned a tie headline seat is
    /// still a concrete seat; we only ever store a real seat here — see below).
    pub winner: u8,
    pub stacks: [u32; 2],
}

/// Aggregate stats for the run summary.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub hands: u32,
    pub showdowns: u32,
    pub folds: u32,
    pub rebuys: u32,
}

/// A `SignedAction` payload we transmit (chips added + engine seq).
struct ActionChoice {
    action: Action,
    amount: u32,
}

/// Map an `Action` to the wire string used in `action` game messages.
fn action_str(a: Action) -> &'static str {
    match a {
        Action::Fold => "fold",
        Action::Check => "check",
        Action::Call => "call",
        Action::Bet => "bet",
        Action::Raise => "raise",
        Action::AllIn => "allin",
    }
}

fn parse_action(s: &str) -> Option<Action> {
    Some(match s {
        "fold" => Action::Fold,
        "check" => Action::Check,
        "call" => Action::Call,
        "bet" => Action::Bet,
        "raise" => Action::Raise,
        "allin" => Action::AllIn,
        _ => return None,
    })
}

/// The bot policy + hand-playing loop for a single seat.
pub struct Player {
    pub me: u8,
    engine: GameState,
    rng: ChaCha8Rng,
    rules: Rules,
    /// deck RNG (host only) — seeded identically to the run so hands reproduce.
    deck_rng: ChaCha8Rng,
    pub results: Vec<HandResult>,
    pub stats: Stats,
}

impl Player {
    pub fn new(me: u8, rules: Rules, seed: u64) -> Self {
        // Policy RNG differs per seat (so the two bots play differently) but is
        // fully determined by the run seed. The deck RNG is seat-INDEPENDENT so
        // both engines could in principle agree on cards; in practice only the
        // host deals, but keeping it seed-derived makes the whole run replayable.
        let rng = ChaCha8Rng::seed_from_u64(seed ^ (0x9E37_79B9_7F4A_7C15u64.wrapping_mul(me as u64 + 1)));
        let deck_rng = ChaCha8Rng::seed_from_u64(seed ^ 0xD1B5_4A32_D192_ED03);
        Self {
            me,
            engine: GameState::new(rules, 2),
            rng,
            rules,
            deck_rng,
            results: Vec::new(),
            stats: Stats::default(),
        }
    }

    /// Shuffle a fresh 52-card deck with the seeded deck RNG (host only).
    fn shuffle_deck(&mut self) -> [u8; 52] {
        let mut deck: [u8; 52] = std::array::from_fn(|i| i as u8);
        // Fisher–Yates with the deck RNG.
        for i in (1..52).rev() {
            let j = self.deck_rng.gen_range(0..=i);
            deck.swap(i, j);
        }
        deck
    }

    /// Current legal, engine-accepted action for `me`, chosen with the policy.
    /// Guarantees the returned action applies Ok to our engine.
    fn choose_action(&mut self) -> ActionChoice {
        let e = &self.engine;
        let me = self.me as usize;
        let stack = e.stacks[me];
        let my_bet = e.bets[me];
        let n = e.num_players as usize;
        let max_bet = (0..n)
            .filter(|&i| matches!(e.seat_state[i], SeatState::Active | SeatState::AllIn))
            .map(|i| e.bets[i])
            .max()
            .unwrap_or(0);
        let to_call = max_bet.saturating_sub(my_bet);
        let min_raise_delta = if max_bet == 0 { self.rules.big_blind } else { to_call + e.last_raise_size };

        // Build the legal candidate set with policy weights (renormalized over
        // whatever is actually legal here).
        // weight buckets: fold, check/call (passive), bet/raise (aggr), allin.
        let mut candidates: Vec<(ActionChoice, u32)> = Vec::new();

        // Fold is always legal (even when free to check — the engine allows it).
        candidates.push((ActionChoice { action: Action::Fold, amount: 0 }, 5));

        if to_call == 0 {
            // Check is legal.
            candidates.push((ActionChoice { action: Action::Check, amount: 0 }, 55));
            // Bet: amount in [bb.min(stack) ..= stack], must strictly exceed 0.
            if stack > 0 {
                let lo = self.rules.big_blind.min(stack).max(1);
                let amount = self.rand_amount(lo, stack);
                candidates.push((ActionChoice { action: Action::Bet, amount }, 30));
            }
        } else {
            // Call (amount ignored by engine, but we send to_call for clarity).
            let call_amt = to_call.min(stack);
            candidates.push((ActionChoice { action: Action::Call, amount: call_amt }, 55));
            // Raise: only if we can raise by at least the min delta and it isn't
            // just an all-in shove (that's the AllIn bucket).
            if stack > min_raise_delta {
                let lo = min_raise_delta.min(stack).max(1);
                // keep raise below the full stack so it stays a real raise, not
                // an all-in (all-in has its own bucket + relaxed min-raise rule).
                let hi = stack.saturating_sub(1).max(lo);
                let amount = self.rand_amount(lo, hi);
                candidates.push((ActionChoice { action: Action::Raise, amount }, 30));
            }
        }

        // All-in is always available if we have chips.
        if stack > 0 {
            candidates.push((ActionChoice { action: Action::AllIn, amount: stack }, 10));
        }

        // Weighted pick, then verify against a clone of the engine; on reject,
        // fall through to the always-legal safe action.
        let choice = self.weighted_pick(candidates);
        if self.dry_run_ok(&choice) {
            return choice;
        }
        self.safe_action(to_call, stack)
    }

    /// Pick a random chip amount in [lo, hi], biased toward the minimum so hands
    /// tend to progress to showdowns rather than everyone shoving.
    fn rand_amount(&mut self, lo: u32, hi: u32) -> u32 {
        if hi <= lo {
            return lo;
        }
        // 60% of the time take the minimum legal size; otherwise a random step.
        if self.rng.gen_bool(0.6) {
            lo
        } else {
            self.rng.gen_range(lo..=hi)
        }
    }

    /// Weighted choice over the candidate set (weights need not sum to 100).
    fn weighted_pick(&mut self, mut candidates: Vec<(ActionChoice, u32)>) -> ActionChoice {
        let total: u32 = candidates.iter().map(|(_, w)| *w).sum();
        debug_assert!(total > 0, "no legal candidates");
        let mut r = self.rng.gen_range(0..total);
        let idx = candidates
            .iter()
            .position(|(_, w)| {
                if r < *w {
                    true
                } else {
                    r -= *w;
                    false
                }
            })
            .unwrap_or(0);
        candidates.swap_remove(idx).0
    }

    /// Does this action apply Ok on a clone of our engine (i.e. is it truly
    /// legal at this exact seq)? Never mutates the real engine.
    fn dry_run_ok(&self, choice: &ActionChoice) -> bool {
        let mut probe = self.engine.clone();
        let seq = probe.action_count + 1;
        probe
            .apply(&SignedAction {
                seat: self.me,
                action: choice.action,
                amount: choice.amount,
                seq,
                sig: [0u8; 64],
            })
            .is_ok()
    }

    /// The always-legal fallback: check if nothing to call, else call, else
    /// all-in. Guaranteed to apply Ok.
    fn safe_action(&self, to_call: u32, stack: u32) -> ActionChoice {
        if to_call == 0 {
            ActionChoice { action: Action::Check, amount: 0 }
        } else if stack >= to_call {
            ActionChoice { action: Action::Call, amount: to_call }
        } else {
            ActionChoice { action: Action::AllIn, amount: stack }
        }
    }

    /// Whether the hand has reached a showdown that needs hand evaluation.
    /// (river complete / all-in runout: phase == Showdown with ≥2 unfolded.)
    fn needs_showdown(&self) -> bool {
        self.engine.phase == Phase::Showdown
            && (0..self.engine.num_players as usize)
                .filter(|&i| !matches!(self.engine.seat_state[i], SeatState::Folded | SeatState::Empty))
                .count()
                >= 2
    }

    /// Apply an action to our engine and return the result. A `hand_over` with
    /// `winner != 255` means the hand was decided immediately (a fold).
    fn apply_local(&mut self, seat: u8, action: Action, amount: u32, seq: u32) -> Result<poker_pvm::ActionResult> {
        self.engine
            .apply(&SignedAction { seat, action, amount, seq, sig: [0u8; 64] })
            .map_err(|e| anyhow!("engine.apply rejected seat={seat} {:?} amt={amount} seq={seq}: {e}", action))
    }
}

/// Play `hands` hands over `peer`. Both sides call this with the same args.
/// Returns the per-hand results (compared by the caller).
pub async fn play(player: &mut Player, peer: &mut Peer, hands: u32) -> Result<()> {
    // announce + minimal rules negotiation, so a browser could interop.
    negotiate(player, peer).await?;

    let host = player.me == 0;
    let mut hand = 0u32;
    while hand < hands {
        hand += 1;

        // --- re-buy if a stack can't post the big blind -------------------
        if player.engine.stacks[0] < player.rules.big_blind
            || player.engine.stacks[1] < player.rules.big_blind
        {
            player.engine.stacks[0] = player.rules.buyin;
            player.engine.stacks[1] = player.rules.buyin;
            player.stats.rebuys += 1;
            debug!(seat = player.me, "rebuy: both stacks reset to buyin");
        }

        // --- deal ---------------------------------------------------------
        if host {
            deal_as_host(player, peer).await?;
        } else {
            deal_as_guest(player, peer).await?;
        }

        // --- betting loop -------------------------------------------------
        let result = play_hand(player, peer).await?;
        player.stats.hands += 1;
        debug!(seat = player.me, hand = result.hand_number, winner = result.winner,
               s0 = result.stacks[0], s1 = result.stacks[1], "hand recorded");
        player.results.push(result);
    }

    Ok(())
}

/// Minimal negotiate: both announce `seated`; host proposes rules, guest accepts.
async fn negotiate(player: &mut Player, peer: &mut Peer) -> Result<()> {
    let host = player.me == 0;
    // Announce our session identity pubkey (if any) so the peer can pin it and later
    // verify our settlement co-sign. `sessionPub` matches the browser `seated` field.
    let mut seated_d = json!({ "name": peer.nick, "mode": "anon" });
    if let Some(pk) = peer.session_pub.clone() {
        seated_d["sessionPub"] = json!(pk);
    }
    peer.send_game(&GameMsg::new("seated", seated_d)).await?;

    if host {
        peer.send_game(&GameMsg::new(
            "propose_rules",
            json!({
                "buyin": player.rules.buyin,
                "smallBlind": player.rules.small_blind,
                "bigBlind": player.rules.big_blind,
                "turnTimeout": player.rules.turn_timeout_blocks,
            }),
        ))
        .await?;
    }

    // Drain until we've seen the peer's `seated` and (host) the guest's accept
    // or (guest) the host's propose. Keep it forgiving: we only require the
    // peer's `seated` before dealing so both sides are past the ceremony.
    let mut peer_seated = false;
    let mut rules_done = host; // host finishes after guest accepts; guest after propose+accept-send
    while !(peer_seated && rules_done) {
        let m = peer.recv_game().await?;
        match m.t.as_str() {
            "seated" => {
                // Record the peer's announced session identity pubkey (if present) so
                // we can verify their settlement co-sign at game end.
                if let Some(pk) = m.d.get("sessionPub").and_then(|v| v.as_str()) {
                    peer.record_peer_session_pub(pk.to_string());
                }
                peer_seated = true;
            }
            "propose_rules" => {
                if !host {
                    peer.send_game(&GameMsg::new("accept_rules", json!({}))).await?;
                    rules_done = true;
                }
            }
            "accept_rules" => {
                if host {
                    rules_done = true;
                }
            }
            other => trace!(t = other, "negotiate: ignoring"),
        }
    }
    Ok(())
}

/// Host deals: shuffle, set local engine, tell guest its hole cards.
async fn deal_as_host(player: &mut Player, peer: &mut Peer) -> Result<()> {
    let deck = player.shuffle_deck();
    let host_hole = [deck[0], deck[1]];
    let guest_hole = [deck[2], deck[3]];
    let community = [deck[4], deck[5], deck[6], deck[7], deck[8]];

    player.engine.deal(&[host_hole, guest_hole], community);
    let stacks = [player.engine.stacks[0], player.engine.stacks[1]];

    peer.send_game(&GameMsg::new(
        "deal",
        json!({
            "cards": [guest_hole[0], guest_hole[1]],
            "community": community,
            "stacks": stacks,
        }),
    ))
    .await?;
    Ok(())
}

/// Guest waits for the host's `deal` and sets up its engine. Seat-0 (host)
/// hole cards are a placeholder until the showdown reveal.
async fn deal_as_guest(player: &mut Player, peer: &mut Peer) -> Result<()> {
    loop {
        let m = peer.recv_game().await?;
        if m.t == "deal" {
            let cards = m.d.get("cards").and_then(|v| v.as_array()).ok_or_else(|| anyhow!("deal missing cards"))?;
            let comm = m.d.get("community").and_then(|v| v.as_array()).ok_or_else(|| anyhow!("deal missing community"))?;
            let my0 = cards[0].as_u64().unwrap() as u8;
            let my1 = cards[1].as_u64().unwrap() as u8;
            let mut community = [0u8; 5];
            for (i, c) in comm.iter().enumerate().take(5) {
                community[i] = c.as_u64().unwrap() as u8;
            }
            // seat 0 (host) cards unknown until showdown → placeholder.
            player.engine.deal(&[[255, 255], [my0, my1]], community);
            return Ok(());
        }
        trace!(t = %m.t, "guest: ignoring pre-deal msg");
    }
}

/// Play out one hand's betting, resolve showdown/fold, return the result.
/// Both engines are driven in lockstep; any peer action our engine rejects is a
/// desync bug and aborts the run.
async fn play_hand(player: &mut Player, peer: &mut Peer) -> Result<HandResult> {
    let me = player.me;
    let other = 1 - me;

    // outcome, filled once the hand is decided.
    let mut decided_winner: Option<u8> = None;
    // hole cards each side needs for a showdown reveal.
    let my_hole = [player.engine.cards[me as usize][0], player.engine.cards[me as usize][1]];
    let mut peer_hole: Option<[u8; 2]> = None;
    let mut my_showdown_sent = false;

    loop {
        // 1) if the hand is decided by fold, we're done.
        if let Some(w) = decided_winner {
            player.stats.folds += 1;
            return Ok(finish_fold(player, w));
        }

        // 2) if a showdown is needed, run the reveal ceremony and evaluate.
        if player.needs_showdown() {
            return run_showdown(player, peer, me, other, my_hole, &mut peer_hole, &mut my_showdown_sent).await;
        }

        // 3) otherwise: act or receive.
        if player.engine.acting_seat == me {
            let choice = player.choose_action();
            let seq = player.engine.action_count + 1;
            let res = player.apply_local(me, choice.action, choice.amount, seq)?;
            peer.send_game(&GameMsg::new(
                "action",
                json!({ "action": action_str(choice.action), "amount": choice.amount, "seq": seq }),
            ))
            .await?;
            if res.hand_over && res.winner != 255 {
                decided_winner = Some(res.winner);
            }
        } else {
            // receive the peer's next game message.
            let m = peer.recv_game().await?;
            match m.t.as_str() {
                "action" => {
                    let a_str = m.d.get("action").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("action missing"))?;
                    let action = parse_action(a_str).ok_or_else(|| anyhow!("bad action {a_str}"))?;
                    let amount = m.d.get("amount").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let seq = m.d.get("seq").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let res = match player.apply_local(other, action, amount, seq) {
                        Ok(r) => r,
                        Err(e) => {
                            // DESYNC: peer sent an action our engine rejects.
                            bail!(
                                "ENGINE DESYNC (seat {me}): peer's legal action was REJECTED by our engine.\n  \
                                 hand={} peer_seat={other} action={a_str} amount={amount} seq={seq}\n  \
                                 our engine: phase={:?} acting_seat={} action_count={} bets={:?} stacks={:?} last_raise_size={}\n  \
                                 error: {e}",
                                player.engine.hand_number, player.engine.phase, player.engine.acting_seat,
                                player.engine.action_count, &player.engine.bets[..2], &player.engine.stacks[..2],
                                player.engine.last_raise_size,
                            );
                        }
                    };
                    if res.hand_over && res.winner != 255 {
                        decided_winner = Some(res.winner);
                    }
                }
                "showdown" => {
                    // peer revealed early (its action reached showdown first);
                    // stash the cards for the ceremony below.
                    peer_hole = Some(read_hole(&m)?);
                }
                other_t => trace!(t = other_t, "play_hand: ignoring"),
            }
        }
    }
}

/// Record a fold outcome (winner already computed identically by both engines).
fn finish_fold(player: &Player, winner: u8) -> HandResult {
    HandResult {
        hand_number: player.engine.hand_number,
        winner,
        stacks: [player.engine.stacks[0], player.engine.stacks[1]],
    }
}

/// Run the showdown reveal + evaluation. Sends our hole cards once, waits for
/// the peer's, sets `engine.cards[other]`, calls `engine.showdown()`.
async fn run_showdown(
    player: &mut Player,
    peer: &mut Peer,
    me: u8,
    other: u8,
    my_hole: [u8; 2],
    peer_hole: &mut Option<[u8; 2]>,
    my_showdown_sent: &mut bool,
) -> Result<HandResult> {
    player.stats.showdowns += 1;

    if !*my_showdown_sent {
        peer.send_game(&GameMsg::new("showdown", json!({ "cards": [my_hole[0], my_hole[1]] }))).await?;
        *my_showdown_sent = true;
    }

    // wait for the peer's hole cards (may already be buffered).
    while peer_hole.is_none() {
        let m = peer.recv_game().await?;
        match m.t.as_str() {
            "showdown" => *peer_hole = Some(read_hole(&m)?),
            "action" => {
                // A late action can only arrive if the peer still owed one
                // before reaching showdown; but both engines reached Showdown
                // together, so this would be out-of-protocol. Surface it.
                bail!("unexpected `action` from peer during showdown ceremony (seat {me})");
            }
            other_t => trace!(t = other_t, "showdown: ignoring"),
        }
    }

    let ph = peer_hole.unwrap();
    player.engine.cards[other as usize] = ph;

    let winner = player.engine.showdown();
    Ok(HandResult {
        hand_number: player.engine.hand_number,
        winner,
        stacks: [player.engine.stacks[0], player.engine.stacks[1]],
    })
}

/// Deterministic dummy per-seat payout address for the OFFLINE staked simulation.
/// (No real wallet/escrow offline; both seats derive the identical seat-indexed
/// addresses so the co-signed settlement message is byte-identical on both sides.)
pub fn demo_payout_addr(seat: u8) -> String {
    format!("utest1seat{seat}demo")
}

/// The result of the staked-sim settlement co-sign, checked by the harness.
#[derive(Debug, Clone)]
pub struct SettleOutcome {
    /// this seat's final seat-indexed stacks [s0, s1] at settlement.
    pub stacks: [u64; 2],
    /// this seat's own settlement (built + signed here).
    pub mine: Settlement,
    /// the peer's settlement (received over the E2EE channel).
    pub theirs: Settlement,
    /// did the peer's co-sign verify under its pinned identity pubkey?
    pub peer_verified: bool,
}

/// Run the offline staked-sim settlement co-sign over the E2EE peer channel.
///
/// At the END of a staked run each seat independently: takes its OWN engine's final
/// seat-indexed stacks [s0, s1], picks the deterministic demo payout addrs, builds +
/// signs its settlement (`settle::build_and_sign`), sends it as `{"t":"settle","d":..}`,
/// receives the peer's, and verifies it under the peer's pinned `sessionPub`. This is
/// the offline proof that the two engines produce IDENTICAL, mutually-verifiable
/// co-signs — the exact thing whose ABSENCE caused the refund bug.
pub async fn settle_cosign(
    player: &mut Player,
    peer: &mut Peer,
    identity: &Identity,
    code: &str,
) -> Result<SettleOutcome> {
    // Final seat-indexed stacks from OUR engine (seat 0 = A, seat 1 = B).
    let stacks = [player.engine.stacks[0] as u64, player.engine.stacks[1] as u64];
    let a_addr = demo_payout_addr(0);
    let b_addr = demo_payout_addr(1);

    // Build + sign our half.
    let mine = settle::build_and_sign(identity, code, stacks[0], stacks[1], &a_addr, &b_addr);

    // Send it to the peer over the E2EE channel.
    peer.send_game(&GameMsg::new(
        "settle",
        json!({
            "a_stack": mine.a_stack,
            "b_stack": mine.b_stack,
            "a_addr": mine.a_addr,
            "b_addr": mine.b_addr,
            "log_hash": mine.log_hash,
            "sig": mine.sig,
        }),
    ))
    .await?;

    // Receive the peer's settlement (skip any late game noise).
    let theirs = loop {
        let m = peer.recv_game().await?;
        if m.t == "settle" {
            break parse_settlement(&m)?;
        }
        trace!(t = %m.t, "settle_cosign: ignoring pre-settle msg");
    };

    // Verify the peer's co-sign under its pinned identity pubkey.
    let peer_pub = peer
        .peer_session_pub
        .clone()
        .ok_or_else(|| anyhow!("peer never announced a sessionPub — cannot verify settlement"))?;
    let peer_verified = settle::verify(&peer_pub, code, &theirs);

    Ok(SettleOutcome { stacks, mine, theirs, peer_verified })
}

/// Parse a `settle` game message into a `Settlement`.
fn parse_settlement(m: &GameMsg) -> Result<Settlement> {
    let d = &m.d;
    let get_u64 = |k: &str| d.get(k).and_then(|v| v.as_u64()).ok_or_else(|| anyhow!("settle missing {k}"));
    let get_str = |k: &str| d.get(k).and_then(|v| v.as_str()).map(|s| s.to_string()).ok_or_else(|| anyhow!("settle missing {k}"));
    Ok(Settlement {
        a_stack: get_u64("a_stack")?,
        b_stack: get_u64("b_stack")?,
        a_addr: get_str("a_addr")?,
        b_addr: get_str("b_addr")?,
        log_hash: get_str("log_hash")?,
        sig: get_str("sig")?,
    })
}

/// Read a `showdown` message's hole cards.
fn read_hole(m: &GameMsg) -> Result<[u8; 2]> {
    let cards = m.d.get("cards").and_then(|v| v.as_array()).ok_or_else(|| anyhow!("showdown missing cards"))?;
    if cards.len() < 2 {
        bail!("showdown cards too short");
    }
    Ok([cards[0].as_u64().unwrap() as u8, cards[1].as_u64().unwrap() as u8])
}

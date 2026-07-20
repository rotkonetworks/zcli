//! `play-staked` — the FULL paid-match driver, end to end, with a hard `--live`
//! gate (default false = dry-run) and per-phase latency instrumentation.
//!
//! Pipeline (both seats, concurrent):
//!   GET /new?buyin=..            → mint a staked room (read-only)
//!   two /p2p seats               → E2EE handshake
//!   srv Join                     → escrow seats us
//!   RoomInfo{frost coords}       → real FROST 2-of-3 DKG (money-free key-gen)
//!   ── DEPOSIT GATE ──
//!     dry-run  : STOP. Print the settled plan + the EXACT `zcli tx send` argv +
//!                memo the operator WOULD run to fund each seat, and the phase
//!                timings so far. NOTHING is deposited.
//!     --live   : build the deposit command to DepositStatus.seat_addresses[seat]
//!                with memo `zk.poker/v1/payout:<payout_ua>;id:<ed25519_hex>`. Per
//!                the fleet rule the AGENT DOES NOT BROADCAST TXS — the operator
//!                runs the printed command; the bot then waits for DepositStatus.ready.
//!   play (existing game loop) → settle co-sign (existing) → PayoutSigningRequest →
//!   cosign_payout (verify PCZT recipients, then FROST-sign) → PayoutComplete.
//!
//! SAFETY: dry-run performs NO transaction. It DKGs for real (keys only), reaches
//! the deposit gate, and stops. The `--live` deposit/play/settle/payout legs require
//! a real funded + settled escrow room (real notes/PCZT) and a supervised operator
//! run; the FROST payout co-sign itself is fully implemented (`payout::cosign_payout`,
//! incl. the C3 recipient check) but can only be EXERCISED against a live settled
//! room, so beyond the gate the driver is structured + logged, never money-moving.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use tokio::sync::Barrier;
use tracing::{info, warn};
use zcash_protocol::consensus::NetworkType;

use crate::deposit;
use crate::dkg::{self, DkgOutput};
use crate::identity::Identity;
use crate::payout::{self, PayoutSignerContext};
use crate::relay::{RelayFrame, Transport, WsTransport};
use crate::session::Peer;
use crate::srv::{ClientMsg, PayoutLine, ServerMsg};

/// Every phase boundary we time, in order. `new` (t0) is implicit (the run start).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Phase {
    /// room minted + seat seated + FROST coords in hand (pre-DKG).
    Seated,
    /// real FROST DKG finished — escrow UA derived.
    DkgDone,
    /// reached the deposit gate (dry-run stops here; live builds the deposit cmd).
    DepositGate,
    /// escrow reported both deposits confirmed + ready (live only).
    DepositConfirmed,
    /// first hand started (live only).
    FirstHand,
    /// settlement co-sign exchanged + verified (live only).
    Settle,
    /// FROST payout co-sign finished (shares emitted) (live only).
    PayoutBroadcast,
    /// escrow reported PayoutComplete{txid} (live only).
    PayoutConfirmed,
}

/// Records `t0` and each phase's wall-clock offset from `t0`.
#[derive(Debug, Clone)]
struct PhaseTimer {
    t0: Instant,
    marks: Vec<(Phase, Duration)>,
}

impl PhaseTimer {
    fn start() -> Self {
        Self { t0: Instant::now(), marks: Vec::new() }
    }
    fn mark(&mut self, p: Phase) {
        let dt = self.t0.elapsed();
        self.marks.push((p, dt));
        info!(phase = ?p, at_ms = dt.as_millis(), "phase reached");
    }
    fn get(&self, p: Phase) -> Option<Duration> {
        self.marks.iter().find(|(x, _)| *x == p).map(|(_, d)| *d)
    }
}

/// FROST coords lifted out of a `RoomInfo` frame.
struct FrostCoords {
    relay_url: String,
    room_code: String,
    staked: bool,
}

/// One seat's end-to-end result for the summary.
struct SeatResult {
    seat: u8,
    timer: PhaseTimer,
    dkg: Option<DkgOutput>,
    /// escrow UA the relay surfaced (RoomInfo.escrow / DepositStatus.escrow_address).
    surfaced_escrow: Option<String>,
    /// this seat's on-chain deposit address (DepositStatus.seat_addresses[seat]).
    seat_deposit_addr: Option<String>,
    /// the exact `zcli tx send` argv the operator WOULD run to fund this seat.
    deposit_cmd: Option<Vec<String>>,
    /// the memo bound into that deposit.
    deposit_memo: Option<String>,
    /// required deposit (zat) from the escrow.
    required_deposit: u64,
    /// live-only: did we observe DepositStatus.ready?
    deposit_confirmed: bool,
    /// live-only: PayoutComplete txid, if reached.
    payout_txid: Option<String>,
    error: Option<String>,
}

impl SeatResult {
    fn new(seat: u8, timer: PhaseTimer) -> Self {
        Self {
            seat,
            timer,
            dkg: None,
            surfaced_escrow: None,
            seat_deposit_addr: None,
            deposit_cmd: None,
            deposit_memo: None,
            required_deposit: 0,
            deposit_confirmed: false,
            payout_txid: None,
            error: None,
        }
    }
}

/// Mint a staked room via the relay HTTP `/new` (303 location header; redirects NOT
/// followed). Read-only room mint — identical to `dkgtest::mint_room`.
async fn mint_room(relay_http: &str, buyin: u64) -> Result<String> {
    let url = format!("{}/new?buyin={}&rake_bps=0", relay_http.trim_end_matches('/'), buyin);
    info!(%url, "GET (read-only room mint; redirects disabled)");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build reqwest client")?;
    let resp = client.get(&url).send().await.with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let code = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches('/').trim().to_string())
        .ok_or_else(|| anyhow!("no `location` header on /new (status {status})"))?;
    if code.is_empty() {
        return Err(anyhow!("empty room code from location header (status {status})"));
    }
    info!(status = %status, room = %code, "minted staked room");
    Ok(code)
}

/// Pump `peer` until a `RoomInfo` carrying non-null frost coords arrives.
async fn await_frost_coords(peer: &mut Peer, seat: u8, deadline: Instant) -> Result<FrostCoords> {
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let _ = tokio::time::timeout(remaining.min(Duration::from_secs(2)), peer.pump_once()).await;
        while let Some(sm) = peer.try_recv_srv() {
            if let ServerMsg::RoomInfo { staked, frost_relay_url, frost_room_code, .. } = &sm {
                if let (Some(url), Some(code)) = (frost_relay_url.clone(), frost_room_code.clone()) {
                    return Ok(FrostCoords { relay_url: url, room_code: code, staked: *staked });
                }
            }
        }
    }
    Err(anyhow!("seat {seat}: no RoomInfo with frost coords within window"))
}

/// After DKG, watch for the escrow to surface (a) the escrow UA and (b) THIS seat's
/// deposit address in a DepositStatus/RoomInfo. Fills `res`. Returns when we have a
/// seat deposit address (⇒ the deposit gate) or the deadline passes.
async fn await_deposit_gate(peer: &mut Peer, res: &mut SeatResult, deadline: Instant) {
    let seat = res.seat as usize;
    while Instant::now() < deadline {
        if res.seat_deposit_addr.is_some() {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let _ = tokio::time::timeout(remaining.min(Duration::from_secs(2)), peer.pump_once()).await;
        while let Some(sm) = peer.try_recv_srv() {
            match &sm {
                ServerMsg::RoomInfo { seat_addresses, .. } => {
                    // (escrow, required_deposit) via the shared deposit helper.
                    if let Some((esc, req)) = deposit::parse_room_info(&sm) {
                        if !esc.is_empty() && res.surfaced_escrow.is_none() {
                            res.surfaced_escrow = Some(esc);
                        }
                        if req > 0 {
                            res.required_deposit = req;
                        }
                    }
                    if let Some(Some(a)) = seat_addresses.get(seat) {
                        res.seat_deposit_addr = Some(a.clone());
                    }
                }
                ServerMsg::DepositStatus {
                    escrow_address, seat_addresses, required, ..
                } => {
                    if !escrow_address.is_empty() && res.surfaced_escrow.is_none() {
                        res.surfaced_escrow = Some(escrow_address.clone());
                    }
                    if *required > 0 {
                        res.required_deposit = *required;
                    }
                    if let Some(Some(a)) = seat_addresses.get(seat) {
                        res.seat_deposit_addr = Some(a.clone());
                    }
                }
                _ => {}
            }
        }
    }
}

/// Run one seat: handshake → Join → DKG → deposit gate. `live` decides whether we
/// stop at the gate (dry-run) or proceed to build the deposit cmd + wait for ready.
#[allow(clippy::too_many_arguments)]
async fn run_seat(
    transport: Transport,
    room: String,
    seat: u8,
    identity: Identity,
    network: NetworkType,
    dkg_timeout: Duration,
    buyin: u64,
    zcli_bin: String,
    live: bool,
    seated_barrier: Arc<Barrier>,
    overall_deadline: Instant,
) -> SeatResult {
    let mut res = SeatResult::new(seat, PhaseTimer::start());

    let nick = crate::random_nick();
    let mut peer = Peer::new(transport, nick);
    peer.set_session_pub(identity.pubkey_hex());

    // 1. join the poker room (creator = seat0, joiner = seat1).
    if let Err(e) = peer.join_room(false, Some(room.clone())).await {
        res.error = Some(format!("join_room: {e}"));
        return res;
    }

    // 2. bounded E2EE handshake so the table progresses like a real one.
    match tokio::time::timeout(Duration::from_secs(15), peer.key_exchange()).await {
        Ok(Ok(())) => info!(seat, "E2EE ready"),
        Ok(Err(e)) => warn!(seat, error = %e, "key_exchange errored; continuing"),
        Err(_) => warn!(seat, "key_exchange timed out; continuing"),
    }

    // 3. announce identity + our PERSONAL payout address via srv Join (escrow seats
    //    us). The payout UA the escrow should pay us at is bound into the deposit memo.
    let payout_ua = crate::game::demo_payout_addr(seat);
    if let Err(e) = peer
        .send_srv(ClientMsg::Join {
            name: format!("stakedbot-seat-{seat}"),
            pubkey: Some(identity.pubkey_hex()),
            zcash_address: Some(payout_ua.clone()),
        })
        .await
    {
        res.error = Some(format!("srv Join: {e}"));
        return res;
    }

    // 4. wait for RoomInfo carrying the FROST coords.
    let coords = match await_frost_coords(&mut peer, seat, overall_deadline).await {
        Ok(c) => c,
        Err(e) => {
            res.error = Some(e.to_string());
            return res;
        }
    };
    if !coords.staked {
        res.error = Some("RoomInfo.staked == false (not a staked/DKG room)".into());
        return res;
    }
    res.timer.mark(Phase::Seated);

    // rendezvous so both seats start the DKG together (escrow host sees all 3 promptly).
    let _ = tokio::time::timeout(
        overall_deadline.saturating_duration_since(Instant::now()),
        seated_barrier.wait(),
    )
    .await;

    // 5. run the REAL FROST DKG on the FROST relay as a joiner (money-free key-gen).
    info!(seat, relay = %coords.relay_url, frost_room = %coords.room_code, "starting FROST DKG (joiner)");
    let dkg_nick = format!("stakedbot-seat-{seat}-{}", crate::random_nick());
    let dkg = dkg::run_dkg_joiner(&coords.relay_url, &coords.room_code, dkg_nick, network, dkg_timeout).await;
    let out = match dkg {
        Ok(o) => {
            info!(seat, ua = %o.orchard_ua, net = ?o.network, "DKG complete — escrow UA derived");
            o
        }
        Err(e) => {
            res.error = Some(format!("DKG failed: {e}"));
            return res;
        }
    };
    res.dkg = Some(out.clone());
    res.timer.mark(Phase::DkgDone);

    // 6. report DkgComplete so the escrow can surface the UA + seat deposit addresses.
    if let Err(e) = peer
        .send_srv(ClientMsg::DkgComplete {
            escrow_ua: out.orchard_ua.clone(),
            orchard_fvk: out.orchard_fvk_hex.clone(),
        })
        .await
    {
        res.error = Some(format!("send DkgComplete: {e}"));
        return res;
    }

    // 7. wait for the escrow to surface this seat's deposit address = the deposit gate.
    await_deposit_gate(&mut peer, &mut res, overall_deadline).await;

    // Build the deposit command (BUILD ONLY — never executed here). Target address is
    // the escrow's per-seat deposit UA (DepositStatus.seat_addresses[seat]); if the
    // escrow hasn't surfaced a per-seat address, fall back to the escrow UA the DKG
    // derived (a single shared deposit UA), still money-free (we only print the cmd).
    let deposit_target = res
        .seat_deposit_addr
        .clone()
        .or_else(|| res.surfaced_escrow.clone())
        .unwrap_or_else(|| out.orchard_ua.clone());
    let required = if res.required_deposit > 0 { res.required_deposit } else { buyin };
    let memo = deposit::deposit_memo(&payout_ua, &identity.pubkey_hex());
    let cmd = deposit::deposit_command(&zcli_bin, &deposit_target, required, &memo);
    res.deposit_memo = Some(memo.clone());
    res.deposit_cmd = Some(cmd);
    res.required_deposit = required;
    res.timer.mark(Phase::DepositGate);

    if !live {
        // DRY-RUN: stop at the gate. NOTHING is deposited.
        info!(seat, "dry-run: reached deposit gate — STOP (no ZEC moved)");
        let _ = peer.transport.send(&RelayFrame::Part).await;
        return res;
    }

    // ── LIVE PATH (supervised; the AGENT DOES NOT BROADCAST TXS) ──────────────
    // The deposit itself is operator-run (see MEMORY: agent-does-NOT-broadcast-txs):
    // we print the exact command and WAIT for the escrow to confirm the operator's
    // deposit. We never call `zcli send` ourselves.
    warn!(
        seat,
        "--live: the deposit + payout broadcast are OPERATOR-run. The bot prints the \
         deposit command and CONTRIBUTES the FROST payout share (with the C3 recipient \
         check), but does not spend ZEC or broadcast. Requires a supervised real run."
    );
    println!(
        "\n[LIVE seat {seat}] operator: run this to fund the seat, then the bot continues:\n  {}\n",
        shell_join(res.deposit_cmd.as_ref().unwrap())
    );

    // wait for the escrow to report BOTH deposits confirmed + ready.
    if wait_deposit_ready(&mut peer, seat, overall_deadline).await {
        res.deposit_confirmed = true;
        res.timer.mark(Phase::DepositConfirmed);
    } else {
        res.error = Some("deposit never confirmed within window (operator did not fund?)".into());
        let _ = peer.transport.send(&RelayFrame::Part).await;
        return res;
    }

    // play → settle → payout co-sign. These need a real funded+settled room; run the
    // existing loops and, on PayoutSigningRequest, drive the FROST payout co-sign.
    if let Err(e) = run_live_match(&mut peer, &mut res, seat, &identity, &room, &out, network).await {
        res.error = Some(format!("live match: {e}"));
    }

    let _ = peer.transport.send(&RelayFrame::Part).await;
    res
}

/// Wait for `DepositStatus.ready` (both seats' confirmed deposits meet `required`).
async fn wait_deposit_ready(peer: &mut Peer, seat: u8, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let _ = tokio::time::timeout(remaining.min(Duration::from_secs(2)), peer.pump_once()).await;
        while let Some(sm) = peer.try_recv_srv() {
            if deposit::gate_ready(&sm) {
                info!(seat, "escrow reports deposits READY");
                return true;
            }
        }
    }
    false
}

/// The live match: play the hands, settle-cosign, then drive the FROST payout
/// co-sign on `PayoutSigningRequest`. Needs a REAL funded+settled room.
async fn run_live_match(
    peer: &mut Peer,
    res: &mut SeatResult,
    seat: u8,
    identity: &Identity,
    room: &str,
    dkg: &DkgOutput,
    network: NetworkType,
) -> Result<()> {
    use crate::game::{self, Player};
    use poker_pvm::Rules;

    // play the existing game loop.
    let rules = Rules { buyin: 1000, small_blind: 5, big_blind: 10, turn_timeout_blocks: 30, rake_bps: 0, rake_cap: 0 };
    let mut player = Player::new(seat, rules, 1);
    res.timer.mark(Phase::FirstHand);
    game::play(&mut player, peer, 1).await.context("play")?;

    // settle co-sign (existing).
    let _settle = game::settle_cosign(&mut player, peer, identity, room).await.context("settle")?;
    res.timer.mark(Phase::Settle);

    // wait for the escrow's PayoutSigningRequest, then FROST-co-sign the payout.
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let _ = tokio::time::timeout(Duration::from_secs(2), peer.pump_once()).await;
        while let Some(sm) = peer.try_recv_srv() {
            match sm {
                ServerMsg::PayoutSigningRequest { relay_room, plan, priority_seat, .. } => {
                    info!(seat, priority_seat, actions = plan.len(), "PayoutSigningRequest — co-signing");
                    cosign(peer, res, seat, identity, room, dkg, network, relay_room, plan).await?;
                    res.timer.mark(Phase::PayoutBroadcast);
                }
                ServerMsg::PayoutComplete { txid } => {
                    info!(seat, %txid, "PayoutComplete");
                    res.payout_txid = Some(txid);
                    res.timer.mark(Phase::PayoutConfirmed);
                    return Ok(());
                }
                ServerMsg::PayoutFailed { reason } => {
                    return Err(anyhow!("escrow reported PayoutFailed: {reason}"));
                }
                _ => {}
            }
        }
    }
    Err(anyhow!("no PayoutComplete within window"))
}

/// Drive the FROST payout co-sign (JOINER half): the C3 recipient check + FROST
/// signing via `payout::cosign_payout`. The escrow host aggregates + broadcasts.
#[allow(clippy::too_many_arguments)]
async fn cosign(
    _peer: &mut Peer,
    _res: &mut SeatResult,
    seat: u8,
    _identity: &Identity,
    _room: &str,
    dkg: &DkgOutput,
    network: NetworkType,
    relay_room: String,
    plan: Vec<PayoutLine>,
) -> Result<()> {
    let ctx = PayoutSignerContext {
        // the payout co-sign runs on the SAME FROST relay as the DKG; the escrow puts
        // the relay coords in the room, and the joiner reuses them (the relay_room is
        // the fresh signing room from the PayoutSigningRequest).
        relay_url: dkg_relay_url_hint(),
        relay_room,
        nick: format!("stakedbot-seat-{seat}-payout-{}", crate::random_nick()),
        public_key_package_hex: dkg.public_key_package_hex.clone(),
        key_package_hex: dkg.key_package_hex.clone(),
        ephemeral_seed_hex: dkg.ephemeral_seed_hex.clone(),
        expected_plan: plan,
        mainnet: matches!(network, NetworkType::Main),
    };
    let out = payout::cosign_payout(&ctx, Duration::from_secs(90))
        .await
        .context("cosign_payout")?;
    info!(seat, sigs = out.action_sigs_hex.len(), "payout co-sign emitted shares (C3 check passed)");
    Ok(())
}

/// The FROST relay URL used for the payout co-sign. The escrow hosts payout signing
/// on the same relay as the DKG; the production relay is the shared JSON relay.
fn dkg_relay_url_hint() -> String {
    std::env::var("POKERBOT_FROST_RELAY")
        .unwrap_or_else(|_| "wss://zrelay.rotko.net/ws".to_string())
}

fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| if a.contains(' ') || a.contains(';') { format!("'{a}'") } else { a.clone() })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Entry point for `play-staked`.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    relay_http: String,
    relay_ws: String,
    buyin: u64,
    network: String,
    zcli_bin: String,
    dkg_secs: u64,
    gate_secs: u64,
    live: bool,
) -> Result<()> {
    let net = dkg::network_from_str(&network);
    println!("── pokerbot play-staked ({}) ──────────────────────────", if live { "LIVE" } else { "DRY-RUN" });
    println!("relay-http:  {relay_http}");
    println!("relay-ws:    {relay_ws}");
    println!("buyin:       {buyin} zat");
    println!("network:     {network} ({net:?})");
    println!("zcli-bin:    {zcli_bin}");
    println!("mode:        {}", if live { "LIVE (--live: deposit+payout are operator-run; supervised)" } else { "DRY-RUN (stops at deposit gate; NO money moves)" });
    println!("dkg-timeout: {dkg_secs}s   gate-window: {gate_secs}s\n");

    if live {
        warn!(
            "--live set: the driver reaches the deposit gate and prints the operator deposit \
             command; per the fleet rule the AGENT DOES NOT BROADCAST TXS. Deposit + payout \
             broadcast are operator-run and require a supervised real run."
        );
    }

    // 1. mint the staked room (read-only GET).
    let room = mint_room(&relay_http, buyin).await?;

    // 2. two seats over /p2p, concurrent.
    let overall_deadline = Instant::now() + Duration::from_secs(dkg_secs + gate_secs + 60);
    let dkg_timeout = Duration::from_secs(dkg_secs);

    let host_ws = Transport::Ws(WsTransport::connect(&relay_ws).await.context("seat 0 ws connect")?);
    let guest_ws = Transport::Ws(WsTransport::connect(&relay_ws).await.context("seat 1 ws connect")?);
    let host_id = Identity::for_selfplay(0x57A, 0);
    let guest_id = Identity::for_selfplay(0x57A, 1);

    let barrier = Arc::new(Barrier::new(2));
    let (b0, b1) = (barrier.clone(), barrier.clone());
    let (r0, r1) = (room.clone(), room.clone());
    let (z0, z1) = (zcli_bin.clone(), zcli_bin.clone());

    let host = tokio::spawn(async move {
        run_seat(host_ws, r0, 0, host_id, net, dkg_timeout, buyin, z0, live, b0, overall_deadline).await
    });
    tokio::time::sleep(Duration::from_millis(500)).await; // seat 0 lands first.
    let guest = tokio::spawn(async move {
        run_seat(guest_ws, r1, 1, guest_id, net, dkg_timeout, buyin, z1, live, b1, overall_deadline).await
    });

    let (host_res, guest_res) = tokio::join!(host, guest);
    let host = host_res.map_err(|e| anyhow!("seat 0 task panicked: {e}"))?;
    let guest = guest_res.map_err(|e| anyhow!("seat 1 task panicked: {e}"))?;

    let ok = print_summary(&room, &host, &guest, live);
    if ok {
        Ok(())
    } else {
        Err(anyhow!("play-staked did not fully complete — see summary above"))
    }
}

/// Print the proof summary + the latency table. Returns true iff both seats reached
/// the deposit gate (dry-run) / the payout confirmation (live).
fn print_summary(room: &str, host: &SeatResult, guest: &SeatResult, live: bool) -> bool {
    println!("\n══ play-staked SUMMARY (room {room}) ═══════════════════════");

    for r in [host, guest] {
        print!("seat {}: ", r.seat);
        match (&r.dkg, &r.error) {
            (Some(d), None) => println!("DKG OK — ua={}", d.orchard_ua),
            (Some(d), Some(e)) => println!("DKG OK — ua={} — but errored later: {e}", d.orchard_ua),
            (None, Some(e)) => println!("FAILED before DKG — {e}"),
            (None, None) => println!("incomplete (no DKG, no error)"),
        }
    }

    let both_agree = match (&host.dkg, &guest.dkg) {
        (Some(h), Some(g)) => {
            let agree = h.orchard_ua == g.orchard_ua && h.orchard_fvk_hex == g.orchard_fvk_hex;
            println!("\nboth seats derived the SAME escrow UA?  {}", if agree { "YES ✓" } else { "NO ✗" });
            agree
        }
        _ => {
            println!("\nboth seats derived the SAME escrow UA?  N/A (a seat has no DKG result)");
            false
        }
    };
    if let Some(d) = host.dkg.as_ref().or(guest.dkg.as_ref()) {
        println!("DERIVED ESCROW UA:   {}", d.orchard_ua);
    }

    // ── the deposit gate: what WOULD be sent (dry-run) ──
    println!("\n── DEPOSIT GATE (the exact `zcli tx send` the operator WOULD run) ──");
    for r in [host, guest] {
        println!("seat {}:", r.seat);
        println!("  required deposit: {} zat", r.required_deposit);
        println!("  deposit target:   {}", r.seat_deposit_addr.as_deref()
            .or(r.surfaced_escrow.as_deref()).unwrap_or("(escrow UA fallback)"));
        match &r.deposit_cmd {
            Some(cmd) => println!("  command:          {}", shell_join(cmd)),
            None => println!("  command:          (not reached — {})",
                r.error.as_deref().unwrap_or("gate not reached")),
        }
        if let Some(m) = &r.deposit_memo {
            println!("  memo:             {m}");
        }
    }
    if !live {
        println!("\nDRY-RUN: NOTHING was deposited. NO `zcli tx send` was executed. NO on-chain tx.");
    }

    // ── latency table ──
    println!("\n── PHASE LATENCY (ms from run start; per seat) ──");
    println!("  {:<26} {:>10} {:>10}", "phase", "seat0", "seat1");
    let rows = [
        ("new → seated", Phase::Seated),
        ("new → DKG done", Phase::DkgDone),
        ("new → deposit gate", Phase::DepositGate),
        ("new → deposit confirmed", Phase::DepositConfirmed),
        ("new → first hand", Phase::FirstHand),
        ("new → settle", Phase::Settle),
        ("new → payout broadcast", Phase::PayoutBroadcast),
        ("new → payout confirmed", Phase::PayoutConfirmed),
    ];
    for (label, p) in rows {
        println!(
            "  {:<26} {:>10} {:>10}",
            label,
            fmt_ms(host.timer.get(p)),
            fmt_ms(guest.timer.get(p)),
        );
    }

    if live {
        println!(
            "\nLIVE payout txids: seat0={} seat1={}",
            host.payout_txid.as_deref().unwrap_or("(not reached)"),
            guest.payout_txid.as_deref().unwrap_or("(not reached)"),
        );
    }
    println!("══════════════════════════════════════════════════════════");

    let gate_reached = host.deposit_cmd.is_some() && guest.deposit_cmd.is_some();
    if !live {
        both_agree && gate_reached
    } else {
        host.payout_txid.is_some() && guest.payout_txid.is_some()
    }
}

fn fmt_ms(d: Option<Duration>) -> String {
    match d {
        Some(d) => format!("{}", d.as_millis()),
        None => "—".into(),
    }
}

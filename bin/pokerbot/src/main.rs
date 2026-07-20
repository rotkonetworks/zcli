//! pokerbot — headless heads-up poker bot that drives the production
//! `poker-pvm` engine over the real zkbtc.org E2EE relay.
//!
//! `selfplay` is the regression harness: in ONE process it spawns two seats
//! that create/join a free-play relay room, complete the E2EE handshake, and
//! play N hands. Both seats keep an independent `poker_pvm::GameState`; after
//! the run the two per-hand result vectors are compared element-by-element.
//! Any disagreement (winner or stacks) — or any action one engine accepted but
//! the other rejected — is a real engine/protocol desync and exits non-zero.
//!
//! `play` runs a single seat for interop against a browser or another machine.

mod crypto;
// Live-paid-path plumbing (memo/command building). Used by the `play-staked` driver.
mod deposit;
mod dkg;
mod dkgtest;
mod game;
mod identity;
mod payout;
mod playstaked;
mod probe;
mod relay;
mod session;
mod settle;
mod srv;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use poker_pvm::Rules;
use tokio::sync::oneshot;
use tracing::info;

use game::{HandResult, Player, SettleOutcome, Stats};
use identity::Identity;
use relay::{Transport, WsTransport};
use session::Peer;

const DEFAULT_RELAY: &str = "wss://zkbtc.org/ws";

#[derive(Parser)]
#[command(name = "pokerbot", about = "headless heads-up poker bot over the zkbtc.org E2EE relay")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Two bots play N hands over one relay in-process; assert both engines agree.
    Selfplay {
        #[arg(long, default_value = DEFAULT_RELAY)]
        relay: String,
        #[arg(long, default_value_t = 100)]
        hands: u32,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value_t = 1000)]
        buyin: u32,
        #[arg(long, default_value_t = 5)]
        sb: u32,
        #[arg(long, default_value_t = 10)]
        bb: u32,
        /// buy-in in zatoshi. 0 = free-play (default; unchanged behaviour). >0 runs
        /// the SAME engine loop as a STAKED SIMULATION: after the hands, both seats
        /// build + sign + exchange + verify a settlement co-sign (offline; no escrow).
        #[arg(long, default_value_t = 0)]
        stake: u64,
        /// run both seats over an IN-PROCESS channel instead of the network relay.
        /// Deterministic + offline (no `--relay` needed); the co-sign assertion is
        /// identical. Handy where the relay is unreachable/slow from CI.
        #[arg(long)]
        local: bool,
    },
    /// Single seat, for interop against a browser or another machine.
    Play {
        #[arg(long, conflicts_with = "join")]
        create: bool,
        #[arg(long)]
        join: Option<String>,
        #[arg(long, default_value = DEFAULT_RELAY)]
        relay: String,
        #[arg(long, default_value_t = 100)]
        hands: u32,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value_t = 1000)]
        buyin: u32,
        #[arg(long, default_value_t = 5)]
        sb: u32,
        #[arg(long, default_value_t = 10)]
        bb: u32,
        #[arg(long, default_value = "pokerbot")]
        name: String,
        /// path to this seat's persistent Ed25519 identity seed (32 raw bytes);
        /// generated + persisted on first use. Announced as `sessionPub` in `seated`.
        #[arg(long, default_value = "pokerbot-identity.key")]
        identity: String,
    },
    /// READ-ONLY diagnostic: mint a staked room, connect two seats, and log the
    /// escrow-bridge (`srv`) frames the relay sends (RoomInfo/DepositStatus). Moves
    /// NO money — no deposit, no settlement, no on-chain tx. Answers whether staked
    /// rooms run FROST-DKG (frost coords present) or trusted-dealer (coords null).
    ProbeStaked {
        /// HTTP(S) base for the room-mint `/new` GET.
        #[arg(long, default_value = "https://zkbtc.org")]
        relay_http: String,
        /// WebSocket relay URL the seats connect to. Defaults to `/p2p` (the
        /// ESCROW-AWARE poker-server relay that emits the staked `srv` RoomInfo /
        /// DepositStatus bridge). NOTE: `/ws` in prod is a separate escrow-UNAWARE
        /// blind relay and will reject a join for an HTTP-minted room — use `/p2p`.
        #[arg(long, default_value = "wss://zkbtc.org/p2p")]
        relay_ws: String,
        /// buy-in in zatoshi, passed to `/new?buyin=..` (nothing is deposited).
        #[arg(long, default_value_t = 10_000)]
        buyin: u64,
        /// how many seconds to observe the srv channel before parting + exiting.
        #[arg(long, default_value_t = 60)]
        secs: u64,
    },
    /// Drive the REAL FROST 2-of-3 DKG for a staked room and PROVE the escrow UA
    /// is produced. Mints a room, seats two bots over `/p2p`, runs the ceremony on
    /// the FROST relay, reports `DkgComplete`, and watches for the relay to surface
    /// the agreed escrow UA. Generates keys only — NO deposit, settlement, or
    /// on-chain tx; no ZEC moves.
    DkgTest {
        /// HTTP(S) base for the room-mint `/new` GET.
        #[arg(long, default_value = "https://zkbtc.org")]
        relay_http: String,
        /// WebSocket relay the seats connect to (escrow-aware `/p2p`).
        #[arg(long, default_value = "wss://zkbtc.org/p2p")]
        relay_ws: String,
        /// buy-in in zatoshi, passed to `/new?buyin=..` (nothing is deposited).
        #[arg(long, default_value_t = 10_000)]
        buyin: u64,
        /// Zcash network for UA/UFVK encoding. A prod staked room that moves real
        /// ZEC runs `main`; the FVK echo is the source of truth and the driver
        /// auto-reconciles if the escrow ran the other network.
        #[arg(long, default_value = "main")]
        network: String,
        /// max seconds to wait for the DKG ceremony to complete.
        #[arg(long, default_value_t = 120)]
        dkg_secs: u64,
        /// seconds to watch for the relay to surface the escrow UA after DkgComplete.
        #[arg(long, default_value_t = 30)]
        watch_secs: u64,
    },
    /// The FULL paid-match driver: mint a staked room, seat two bots, run the REAL
    /// FROST DKG, reach the DEPOSIT GATE, then (dry-run, DEFAULT) STOP and print the
    /// exact `zcli tx send` deposit command + memo the operator WOULD run, plus a
    /// per-phase latency table — moving NO money. With `--live` it also drives the
    /// deposit (operator-run), play, settle co-sign, and FROST payout co-sign
    /// (incl. the C3 recipient check); that path needs a supervised real run.
    PlayStaked {
        /// HTTP(S) base for the room-mint `/new` GET.
        #[arg(long, default_value = "https://zkbtc.org")]
        relay_http: String,
        /// WebSocket relay the seats connect to (escrow-aware `/p2p`).
        #[arg(long, default_value = "wss://zkbtc.org/p2p")]
        relay_ws: String,
        /// buy-in in zatoshi, passed to `/new?buyin=..`. In dry-run nothing is deposited.
        #[arg(long, default_value_t = 10_000)]
        buyin: u64,
        /// Zcash network for UA/UFVK encoding + the payout co-sign. Prod staked rooms
        /// that move real ZEC run `main`; the DKG FVK echo is the source of truth.
        #[arg(long, default_value = "main")]
        network: String,
        /// path to the `zcli` binary the operator's wallet would use for the deposit.
        /// Only ever BUILT into the printed command — never executed by the bot.
        #[arg(long, default_value = "zcli")]
        zcli_bin: String,
        /// max seconds to wait for the FROST DKG ceremony.
        #[arg(long, default_value_t = 120)]
        dkg_secs: u64,
        /// seconds to wait at/after the deposit gate (surface deposit addrs; live wait).
        #[arg(long, default_value_t = 60)]
        gate_secs: u64,
        /// HARD gate (default OFF). Without it the driver is a pure dry-run that stops
        /// at the deposit gate — no `zcli tx send`, no on-chain tx, no FROST payout
        /// broadcast. `--live` enables the operator-run deposit + the full play/settle/
        /// payout co-sign path (supervised real run only).
        #[arg(long, default_value_t = false)]
        live: bool,
    },
}

fn rules(buyin: u32, sb: u32, bb: u32) -> Rules {
    Rules { buyin, small_blind: sb, big_blind: bb, turn_timeout_blocks: 30, rake_bps: 0, rake_cap: 0 }
}

/// Random nick: literal 'p' + 8 hex chars (identity hidden until E2EE).
fn random_nick() -> String {
    use rand::RngCore;
    let mut b = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut b);
    format!("p{}", hex::encode(b))
}

/// Run one seat end-to-end: handshake, then play `hands` hands.
async fn run_seat(
    transport: Transport,
    create: bool,
    room: Option<String>,
    rules: Rules,
    seed: u64,
    me: u8,
    hands: u32,
    nick: String,
    identity: Option<Identity>,
) -> Result<(Vec<HandResult>, Stats, String)> {
    let mut peer = Peer::new(transport, nick);
    if let Some(id) = &identity {
        peer.set_session_pub(id.pubkey_hex());
    }
    let room_code = peer.handshake(create, room).await?;
    let mut player = Player::new(me, rules, seed);
    game::play(&mut player, &mut peer, hands).await?;
    Ok((player.results, player.stats, room_code))
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 no longer auto-selects a crypto provider; install the ring
    // provider (already compiled in via tokio-tungstenite) before any TLS use.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Selfplay { relay, hands, seed, buyin, sb, bb, stake, local } => {
            // Build the two seats' transports: in-process channel (--local) or two
            // websocket connections to the relay. The rest of the run is identical.
            let (host_t, guest_t) = if local {
                let (a, b) = relay::ChannelTransport::pair("selfplay");
                (Transport::Channel(a), Transport::Channel(b))
            } else {
                info!(relay = %relay, "connecting two seats to relay");
                (
                    Transport::Ws(WsTransport::connect(&relay).await?),
                    Transport::Ws(WsTransport::connect(&relay).await?),
                )
            };
            let code = selfplay(host_t, guest_t, hands, seed, rules(buyin, sb, bb), stake).await?;
            std::process::exit(code);
        }
        Cmd::Play { create, join, relay, hands, seed, buyin, sb, bb, name, identity } => {
            if !create && join.is_none() {
                return Err(anyhow!("play needs either --create or --join <code>"));
            }
            info!(relay = %relay, "connecting");
            let id = Identity::load_or_create(std::path::Path::new(&identity))?;
            info!(session_pub = %id.pubkey_hex(), identity_file = %identity, "session identity loaded");
            let transport = Transport::Ws(WsTransport::connect(&relay).await?);
            let me = if create { 0 } else { 1 };
            let (results, stats, room) =
                run_seat(transport, create, join, rules(buyin, sb, bb), seed, me, hands, name, Some(id)).await?;
            if create {
                info!(room = %room, "room code (share with the other seat)");
            }
            print_single(&results, &stats, &room);
            Ok(())
        }
        Cmd::ProbeStaked { relay_http, relay_ws, buyin, secs } => {
            probe::run(relay_http, relay_ws, buyin, secs).await
        }
        Cmd::DkgTest { relay_http, relay_ws, buyin, network, dkg_secs, watch_secs } => {
            dkgtest::run(relay_http, relay_ws, buyin, network, dkg_secs, watch_secs).await
        }
        Cmd::PlayStaked { relay_http, relay_ws, buyin, network, zcli_bin, dkg_secs, gate_secs, live } => {
            playstaked::run(relay_http, relay_ws, buyin, network, zcli_bin, dkg_secs, gate_secs, live).await
        }
    }
}

/// The regression harness: two seats over the same relay, compared at the end.
/// Returns the process exit code (0 = full agreement). When `stake > 0` the run is a
/// STAKED SIMULATION: after the hands both seats build + exchange + verify a
/// settlement co-sign, and the harness asserts they never forked into inconsistent
/// co-signs — the exact failure that caused the original refund bug.
async fn selfplay(
    host_t: Transport,
    guest_t: Transport,
    hands: u32,
    seed: u64,
    rules: Rules,
    stake: u64,
) -> Result<i32> {
    let staked = stake > 0;
    info!(hands, seed, stake, staked, "selfplay: two seats");

    // Host creates the room and ships the code to the guest via a oneshot.
    let (code_tx, code_rx) = oneshot::channel::<String>();

    let host = tokio::spawn(async move {
        let nick = random_nick();
        let mut peer = Peer::new(host_t, nick.clone());
        // Seat 0's persistent identity, derived from the run seed (reproducible).
        let identity = Identity::for_selfplay(seed, 0);
        peer.set_session_pub(identity.pubkey_hex());
        // Join the room FIRST and hand the code to the guest BEFORE blocking on
        // key exchange — the host's keyex can't complete until the guest joins,
        // and the guest can't join without this code.
        let room = peer.join_room(true, None).await?;
        code_tx.send(room.clone()).map_err(|_| anyhow!("guest task dropped"))?;
        peer.key_exchange().await?;
        let mut player = Player::new(0, rules, seed);
        game::play(&mut player, &mut peer, hands).await?;
        let settle = if staked {
            Some(game::settle_cosign(&mut player, &mut peer, &identity, &room).await?)
        } else {
            None
        };
        Ok::<_, anyhow::Error>((player.results, player.stats, room, settle))
    });

    let guest = tokio::spawn(async move {
        let room = code_rx.await.map_err(|_| anyhow!("host task never produced a room code"))?;
        let nick = random_nick();
        let mut peer = Peer::new(guest_t, nick);
        let identity = Identity::for_selfplay(seed, 1);
        peer.set_session_pub(identity.pubkey_hex());
        peer.join_room(false, Some(room.clone())).await?;
        peer.key_exchange().await?;
        let mut player = Player::new(1, rules, seed);
        game::play(&mut player, &mut peer, hands).await?;
        let settle = if staked {
            Some(game::settle_cosign(&mut player, &mut peer, &identity, &room).await?)
        } else {
            None
        };
        Ok::<_, anyhow::Error>((player.results, player.stats, settle))
    });

    let (host_res, guest_res) = tokio::join!(host, guest);
    let (host_results, host_stats, room, host_settle) = host_res.map_err(|e| anyhow!("host task panicked: {e}"))??;
    let (guest_results, guest_stats, guest_settle) = guest_res.map_err(|e| anyhow!("guest task panicked: {e}"))??;

    let mut code = compare_and_report(&room, &host_results, &host_stats, &guest_results, &guest_stats);

    if staked {
        // The offline money-safety proof: both seats must have produced identical,
        // mutually-verifiable settlement co-signs.
        let settle_code = report_settlement(
            &room,
            host_settle.as_ref().expect("staked host must settle"),
            guest_settle.as_ref().expect("staked guest must settle"),
        );
        if settle_code != 0 {
            code = settle_code;
        }
    }

    Ok(code)
}

/// Assert + report the staked-sim settlement invariant. Returns 0 iff:
///   (a) both seats' final seat-indexed stacks [s0,s1] are identical,
///   (b) both computed the IDENTICAL log_hash and settlement_message inputs, and
///   (c) each seat's sig verifies under the peer's pinned identity pubkey.
/// Any failure is the "engines forked → no matching co-signed outcome" bug and
/// yields a non-zero exit code.
fn report_settlement(room: &str, host: &SettleOutcome, guest: &SettleOutcome) -> i32 {
    println!("── pokerbot staked-sim settlement ────────────────────────");
    println!("final stacks: host {:?} / guest {:?}", host.stacks, guest.stacks);

    // (a) both engines' final seat-indexed stacks identical.
    if host.stacks != guest.stacks {
        println!("SETTLEMENT MISMATCH: final stacks differ (engines forked) — {:?} vs {:?}",
            host.stacks, guest.stacks);
        return 3;
    }

    // (b) both derived the identical log_hash (⇒ identical settlement_message inputs).
    //     Each seat's OWN settlement is over [s0,s1]; the peer's copy (received) must
    //     carry the same log_hash. Cross-check all four.
    let lh = &host.mine.log_hash;
    if host.theirs.log_hash != *lh || guest.mine.log_hash != *lh || guest.theirs.log_hash != *lh {
        println!("SETTLEMENT MISMATCH: log_hash differs across seats");
        println!("  host.mine={} host.theirs={}", host.mine.log_hash, host.theirs.log_hash);
        println!("  guest.mine={} guest.theirs={}", guest.mine.log_hash, guest.theirs.log_hash);
        return 3;
    }

    // (c) each seat verified the peer's co-sign under its pinned identity pubkey.
    if !host.peer_verified {
        println!("SETTLEMENT VERIFY FAILED: host could not verify guest's co-sign");
        return 3;
    }
    if !guest.peer_verified {
        println!("SETTLEMENT VERIFY FAILED: guest could not verify host's co-sign");
        return 3;
    }

    println!("log_hash:    {lh}");
    println!("payout plan: seat0={} seat1={}", host.mine.a_addr, host.mine.b_addr);
    println!("settlement:  co-signs MATCH + both verify ✓  (room {room})");
    0
}

/// Compare the two seats' per-hand vectors and print the summary.
fn compare_and_report(
    room: &str,
    a: &[HandResult],
    a_stats: &Stats,
    b: &[HandResult],
    b_stats: &Stats,
) -> i32 {
    println!("── pokerbot selfplay summary ─────────────────────────────");
    println!("room:        {room}");
    println!("hands:       {} (host) / {} (guest)", a.len(), b.len());
    println!("showdowns:   {} (host) / {} (guest)", a_stats.showdowns, b_stats.showdowns);
    println!("folds:       {} (host) / {} (guest)", a_stats.folds, b_stats.folds);
    println!("rebuys:      {} (host) / {} (guest)", a_stats.rebuys, b_stats.rebuys);

    if a.len() != b.len() {
        println!("MISMATCH: hand counts differ ({} vs {})", a.len(), b.len());
        return 1;
    }

    for (i, (ha, hb)) in a.iter().zip(b.iter()).enumerate() {
        if ha != hb {
            println!("MISMATCH at hand index {i}:");
            println!("  host : hand={} winner={} stacks={:?}", ha.hand_number, ha.winner, ha.stacks);
            println!("  guest: hand={} winner={} stacks={:?}", hb.hand_number, hb.winner, hb.stacks);
            return 1;
        }
    }

    println!("ALL AGREED ✓  ({} hands, both engines identical)", a.len());
    0
}

fn print_single(results: &[HandResult], stats: &Stats, room: &str) {
    println!("── pokerbot single-seat summary ──────────────────────────");
    println!("room:      {room}");
    println!("hands:     {}", results.len());
    println!("showdowns: {}", stats.showdowns);
    println!("folds:     {}", stats.folds);
    println!("rebuys:    {}", stats.rebuys);
    if let Some(last) = results.last() {
        println!("final:     hand={} winner={} stacks={:?}", last.hand_number, last.winner, last.stacks);
    }
}

// ============================================================================
// Offline regression test: run the FULL two-seat loop over an in-process
// channel (no websocket), proving the engine-driving + bot + sync logic agrees
// over many hands even when the relay is unreachable from CI.
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{ChannelTransport, Transport};

    async fn run_channel_selfplay(hands: u32, seed: u64) -> (Vec<HandResult>, Vec<HandResult>) {
        let rules = rules(1000, 5, 10);
        let (a, b) = ChannelTransport::pair("test");

        let host = tokio::spawn(async move {
            let (r, _s, _room) = run_seat(
                Transport::Channel(a), true, None, rules, seed, 0, hands, "host".into(), None,
            )
            .await
            .expect("host seat failed");
            r
        });
        let guest = tokio::spawn(async move {
            let (r, _s, _room) = run_seat(
                Transport::Channel(b), false, Some("test".into()), rules, seed, 1, hands, "guest".into(), None,
            )
            .await
            .expect("guest seat failed");
            r
        });
        let (ha, hb) = tokio::join!(host, guest);
        (ha.unwrap(), hb.unwrap())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_seats_agree_over_500_hands() {
        let (a, b) = run_channel_selfplay(500, 1).await;
        assert_eq!(a.len(), 500, "host played 500 hands");
        assert_eq!(a, b, "both engines must agree on every hand");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_seats_agree_seed_2_and_3() {
        for seed in [2u64, 3] {
            let (a, b) = run_channel_selfplay(300, seed).await;
            assert_eq!(a, b, "seed {seed}: engines must agree");
        }
    }

    /// Full STAKED-SIM run over the in-process channel: play `hands`, then have each
    /// seat build + exchange + verify its settlement co-sign, and return both
    /// outcomes. This is the offline proof of the money invariant — no network.
    async fn run_channel_staked(hands: u32, seed: u64) -> (SettleOutcome, SettleOutcome) {
        let rules = rules(1000, 5, 10);
        let (a, b) = ChannelTransport::pair("stakedtest");
        // Mirror production `selfplay`: the host hands its ACTUAL room code to the
        // guest so BOTH seats sign the settlement over the identical `code`.
        let (code_tx, code_rx) = tokio::sync::oneshot::channel::<String>();

        let host = tokio::spawn(async move {
            let mut peer = Peer::new(Transport::Channel(a), "host".into());
            let identity = Identity::for_selfplay(seed, 0);
            peer.set_session_pub(identity.pubkey_hex());
            let room = peer.join_room(true, None).await.expect("host join");
            code_tx.send(room.clone()).expect("send room code");
            peer.key_exchange().await.expect("host keyex");
            let mut player = Player::new(0, rules, seed);
            game::play(&mut player, &mut peer, hands).await.expect("host play");
            game::settle_cosign(&mut player, &mut peer, &identity, &room).await.expect("host settle")
        });
        let guest = tokio::spawn(async move {
            let room = code_rx.await.expect("recv room code");
            let mut peer = Peer::new(Transport::Channel(b), "guest".into());
            let identity = Identity::for_selfplay(seed, 1);
            peer.set_session_pub(identity.pubkey_hex());
            peer.join_room(false, Some(room.clone())).await.expect("guest join");
            peer.key_exchange().await.expect("guest keyex");
            let mut player = Player::new(1, rules, seed);
            game::play(&mut player, &mut peer, hands).await.expect("guest play");
            game::settle_cosign(&mut player, &mut peer, &identity, &room).await.expect("guest settle")
        });
        let (h, g) = tokio::join!(host, guest);
        (h.unwrap(), g.unwrap())
    }

    // THE money invariant, offline: over many hands + several seeds, both seats
    // produce IDENTICAL final stacks, the IDENTICAL log_hash, and each seat verifies
    // the peer's co-sign under the peer's pinned identity pubkey. This is exactly the
    // guarantee whose ABSENCE caused the refund bug (engines forked → no matching
    // co-signed outcome → escrow refunded instead of paying the winner).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn staked_sim_cosigns_match_and_verify() {
        for seed in [1u64, 2, 3, 7] {
            let (host, guest) = run_channel_staked(200, seed).await;
            // (a) both engines' final seat-indexed stacks identical.
            assert_eq!(host.stacks, guest.stacks, "seed {seed}: final stacks must match");
            // (b) identical log_hash across all four settlement copies.
            assert_eq!(host.mine.log_hash, guest.mine.log_hash, "seed {seed}: log_hash must match");
            assert_eq!(host.mine.log_hash, host.theirs.log_hash, "seed {seed}: host's view consistent");
            assert_eq!(guest.mine.log_hash, guest.theirs.log_hash, "seed {seed}: guest's view consistent");
            // (c) each seat verified the peer's co-sign.
            assert!(host.peer_verified, "seed {seed}: host must verify guest co-sign");
            assert!(guest.peer_verified, "seed {seed}: guest must verify host co-sign");
            // and the report helper agrees (exit 0).
            assert_eq!(report_settlement("stakedtest", &host, &guest), 0, "seed {seed}: report ok");
        }
    }

    // A forked/tampered settlement (as if an engine forked or a peer lied about
    // stacks) must NOT verify — the report helper returns non-zero. Guards that the
    // invariant is real, not vacuous.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn staked_sim_detects_forked_stacks() {
        let (host, mut guest) = run_channel_staked(50, 5).await;
        // simulate the guest's engine having forked to a different outcome.
        guest.stacks[0] = guest.stacks[0].wrapping_add(1);
        assert_ne!(report_settlement("stakedtest", &host, &guest), 0,
            "forked final stacks must fail the settlement assertion");
    }
}

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
mod game;
mod relay;
mod session;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use poker_pvm::Rules;
use tokio::sync::oneshot;
use tracing::info;

use game::{HandResult, Player, Stats};
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
) -> Result<(Vec<HandResult>, Stats, String)> {
    let mut peer = Peer::new(transport, nick);
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
        Cmd::Selfplay { relay, hands, seed, buyin, sb, bb } => {
            let code = selfplay(&relay, hands, seed, rules(buyin, sb, bb)).await?;
            std::process::exit(code);
        }
        Cmd::Play { create, join, relay, hands, seed, buyin, sb, bb, name } => {
            if !create && join.is_none() {
                return Err(anyhow!("play needs either --create or --join <code>"));
            }
            info!(relay = %relay, "connecting");
            let transport = Transport::Ws(WsTransport::connect(&relay).await?);
            let me = if create { 0 } else { 1 };
            let (results, stats, room) =
                run_seat(transport, create, join, rules(buyin, sb, bb), seed, me, hands, name).await?;
            if create {
                info!(room = %room, "room code (share with the other seat)");
            }
            print_single(&results, &stats, &room);
            Ok(())
        }
    }
}

/// The regression harness: two seats over the same relay, compared at the end.
/// Returns the process exit code (0 = full agreement).
async fn selfplay(relay: &str, hands: u32, seed: u64, rules: Rules) -> Result<i32> {
    info!(relay, hands, seed, "selfplay: connecting two seats");

    // Two independent websocket connections to the same relay.
    let host_ws = Transport::Ws(WsTransport::connect(relay).await?);
    let guest_ws = Transport::Ws(WsTransport::connect(relay).await?);

    // Host creates the room and ships the code to the guest via a oneshot.
    let (code_tx, code_rx) = oneshot::channel::<String>();

    let host = tokio::spawn(async move {
        let nick = random_nick();
        let mut peer = Peer::new(host_ws, nick.clone());
        // Join the room FIRST and hand the code to the guest BEFORE blocking on
        // key exchange — the host's keyex can't complete until the guest joins,
        // and the guest can't join without this code.
        let room = peer.join_room(true, None).await?;
        code_tx.send(room.clone()).map_err(|_| anyhow!("guest task dropped"))?;
        peer.key_exchange().await?;
        let mut player = Player::new(0, rules, seed);
        game::play(&mut player, &mut peer, hands).await?;
        Ok::<_, anyhow::Error>((player.results, player.stats, room))
    });

    let guest = tokio::spawn(async move {
        let room = code_rx.await.map_err(|_| anyhow!("host task never produced a room code"))?;
        let nick = random_nick();
        let mut peer = Peer::new(guest_ws, nick);
        peer.join_room(false, Some(room)).await?;
        peer.key_exchange().await?;
        let mut player = Player::new(1, rules, seed);
        game::play(&mut player, &mut peer, hands).await?;
        Ok::<_, anyhow::Error>((player.results, player.stats))
    });

    let (host_res, guest_res) = tokio::join!(host, guest);
    let (host_results, host_stats, room) = host_res.map_err(|e| anyhow!("host task panicked: {e}"))??;
    let (guest_results, guest_stats) = guest_res.map_err(|e| anyhow!("guest task panicked: {e}"))??;

    Ok(compare_and_report(&room, &host_results, &host_stats, &guest_results, &guest_stats))
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
                Transport::Channel(a), true, None, rules, seed, 0, hands, "host".into(),
            )
            .await
            .expect("host seat failed");
            r
        });
        let guest = tokio::spawn(async move {
            let (r, _s, _room) = run_seat(
                Transport::Channel(b), false, Some("test".into()), rules, seed, 1, hands, "guest".into(),
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
}

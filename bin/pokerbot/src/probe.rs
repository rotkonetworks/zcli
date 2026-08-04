//! `probe-staked` — a READ-ONLY diagnostic that observes the real staked-room
//! escrow handshake on the production relay.
//!
//! It answers ONE question: when a staked room is created on zkbtc.org, does the
//! escrow run in FROST-DKG mode (RoomInfo carries `frost_relay_url`/`frost_room_code`)
//! or trusted-dealer mode (those are null and `escrow` is a pre-derived UA)?
//!
//! SAFETY: this NEVER moves money. It does exactly three network things:
//!   1. a plain HTTPS GET to `{relay-http}/new?buyin=..&rake_bps=0` — the room mint,
//!      which 303-redirects with the room code in the `location` header. Redirect
//!      following is DISABLED; we only read that header.
//!   2. two websocket seats join the room and complete the E2EE `_keyex` handshake
//!      (seat 0 creator + seat 1 joiner, so the room progresses to a real table).
//!   3. each seat sends ONE `srv` `ClientMsg::Join{ name, pubkey, zcash_address:None }`
//!      so the escrow has the seat identity. That is a plain control frame — NOT a
//!      deposit, settlement, or any on-chain command.
//!
//! Then it logs every inbound `srv` ServerMsg verbatim for `--secs`, prints a
//! summary, sends `part`, and closes. No `ReportDeposit`, no `Settlement`, no
//! `zcli send`, no deposit/payout endpoint is ever called.

use anyhow::{anyhow, Context, Result};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::identity::Identity;
use crate::relay::{RelayFrame, Transport, WsTransport};
use crate::session::Peer;
use crate::srv::{ClientMsg, ServerMsg};

/// Mint a staked room via the relay's HTTP `/new` endpoint and return the room
/// code parsed from the 303 `location` header. Read-only: redirects are NOT
/// followed, so no page is loaded and nothing is submitted.
async fn mint_room(relay_http: &str, buyin: u64) -> Result<String> {
    let url = format!("{}/new?buyin={}&rake_bps=0", relay_http.trim_end_matches('/'), buyin);
    info!(%url, "GET (read-only room mint; redirects disabled)");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build reqwest client")?;
    let resp = client.get(&url).send().await.with_context(|| format!("GET {url}"))?;
    let status = resp.status();

    // The room code is in the `location` header of the 3xx redirect, e.g.
    // `location: /84-deck-rank`. We parse it; we do NOT follow it.
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let code = match location {
        Some(loc) => loc.trim_start_matches('/').trim().to_string(),
        None => {
            return Err(anyhow!(
                "no `location` header on /new response (status {status}); cannot extract room code"
            ));
        }
    };
    if code.is_empty() {
        return Err(anyhow!("empty room code from location header (status {status})"));
    }
    info!(status = %status, room = %code, "minted staked room (from location header)");
    Ok(code)
}

/// What one seat observed on the srv channel, returned to the summary printer.
struct SeatObs {
    first_room_info: Option<serde_json::Value>,
    frames: Vec<serde_json::Value>,
    deposit_statuses: Vec<serde_json::Value>,
}

/// Run one observer seat: join the room, complete keyex, announce identity via a
/// single `srv` Join, then log every inbound srv frame for `deadline`.
async fn observe_seat(
    transport: Transport,
    create: bool,
    room: String,
    seat: u8,
    identity: Identity,
    deadline: Instant,
) -> Result<SeatObs> {
    let nick = crate::random_nick();
    let mut peer = Peer::new(transport, nick);
    peer.set_session_pub(identity.pubkey_hex());

    // room membership (creator = seat 0, joiner = seat 1). On a staked room the
    // escrow bridge pushes RoomInfo IMMEDIATELY on join — before any keyex — so the
    // frame is already queued in the srv inbox by the time we observe.
    peer.join_room(create, if create { None } else { Some(room.clone()) }).await
        .with_context(|| format!("seat {seat}: join_room"))?;
    info!(seat, "joined; running E2EE handshake (bounded)");

    // Best-effort E2EE handshake so the room "progresses" like a real table. It is
    // NOT fatal if it doesn't complete inside the window (the peer seat may be slow,
    // or a solo observation still wants the srv frames): srv frames are demuxed into
    // the inbox during the attempt regardless, and we observe them below.
    match tokio::time::timeout(Duration::from_secs(15), peer.key_exchange()).await {
        Ok(Ok(())) => info!(seat, "E2EE ready"),
        Ok(Err(e)) => warn!(seat, error = %e, "key_exchange errored; continuing to observe srv"),
        Err(_) => warn!(seat, "key_exchange timed out; continuing to observe srv"),
    }
    info!(seat, "announcing identity via srv Join (no money)");

    // Announce the seat to the escrow. Plain control frame — NOT a deposit.
    peer.send_srv(ClientMsg::Join {
        name: format!("probe-seat-{seat}"),
        pubkey: Some(identity.pubkey_hex()),
        zcash_address: None,
    })
    .await
    .with_context(|| format!("seat {seat}: send srv Join"))?;

    let mut obs = SeatObs { first_room_info: None, frames: Vec::new(), deposit_statuses: Vec::new() };

    // Observe loop: pump the relay (which demuxes srv frames into the inbox), then
    // drain + log every srv frame verbatim until the deadline.
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        // Pump at most one frame, bounded so a quiet room can't block past the deadline.
        let pump = tokio::time::timeout(remaining.min(Duration::from_secs(2)), peer.pump_once()).await;
        match pump {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                warn!(seat, error = %e, "relay pump error; stopping this seat's observation");
                break;
            }
            Err(_) => { /* timeout: no frame this tick; loop and re-check deadline */ }
        }

        // Drain everything the demux queued and log it verbatim.
        while let Some(sm) = peer.try_recv_srv() {
            let raw = serde_json::to_value(&sm).unwrap_or(serde_json::Value::Null);
            println!(
                "── srv[seat {seat}] {} ──\n{}",
                variant_name(&sm),
                serde_json::to_string_pretty(&raw).unwrap_or_else(|_| "<unserializable>".into())
            );
            match &sm {
                ServerMsg::RoomInfo { .. } => {
                    if obs.first_room_info.is_none() {
                        obs.first_room_info = Some(raw.clone());
                    }
                }
                ServerMsg::DepositStatus { .. } => obs.deposit_statuses.push(raw.clone()),
                _ => {}
            }
            obs.frames.push(raw);
        }
    }

    // Leave cleanly. `part` only removes us from the relay room; it commits nothing.
    let _ = peer.transport.send(&RelayFrame::Part).await;
    info!(seat, frames = obs.frames.len(), "seat observation complete; sent part");
    Ok(obs)
}

/// Short human tag for a ServerMsg, for the per-frame log header.
fn variant_name(m: &ServerMsg) -> &'static str {
    match m {
        ServerMsg::RoomInfo { .. } => "RoomInfo",
        ServerMsg::DepositStatus { .. } => "DepositStatus",
        ServerMsg::PayoutSigningRequest { .. } => "PayoutSigningRequest",
        ServerMsg::PayoutComplete { .. } => "PayoutComplete",
        ServerMsg::PayoutFailed { .. } => "PayoutFailed",
        ServerMsg::GameOver { .. } => "GameOver",
        ServerMsg::Error { .. } => "Error",
        ServerMsg::Other => "Other(unmodelled)",
    }
}

/// Entry point for the `probe-staked` subcommand.
pub async fn run(relay_http: String, relay_ws: String, buyin: u64, secs: u64) -> Result<()> {
    println!("── pokerbot probe-staked (READ-ONLY; no money moves) ─────");
    println!("relay-http: {relay_http}");
    println!("relay-ws:   {relay_ws}");
    println!("buyin:      {buyin} zat   observe: {secs}s\n");

    // 1. mint the room over HTTP (read-only GET; redirect not followed).
    let room = mint_room(&relay_http, buyin).await?;

    // 2. connect two websocket seats and observe for `secs`.
    let deadline = Instant::now() + Duration::from_secs(secs);
    let host_ws = Transport::Ws(Box::new(WsTransport::connect(&relay_ws).await.context("seat 0 ws connect")?));
    let guest_ws = Transport::Ws(Box::new(WsTransport::connect(&relay_ws).await.context("seat 1 ws connect")?));

    // Distinct, throwaway identities for the two observer seats.
    let host_id = Identity::for_selfplay(0xC0FFEE, 0);
    let guest_id = Identity::for_selfplay(0xC0FFEE, 1);

    // The HTTP `/new` mint already created the escrow-aware room; BOTH seats simply
    // JOIN that exact code (seat = relay join order, so the first joiner is seat 0).
    // We do NOT send a relay `create` — that would mint a DIFFERENT code and miss the
    // escrow bridge, which keys the staked-room lookup on the join code.
    //
    // Both seats run CONCURRENTLY from the start: seat 0's key_exchange blocks until
    // seat 1 joins and sends its `_keyex`, so gating seat 1 on seat 0 finishing would
    // deadlock. A short stagger lets seat 0 land first (seat 0), then seat 1 joins.
    let host_room = room.clone();
    let guest_room = room.clone();

    let host = tokio::spawn(async move {
        observe_seat(host_ws, /*create=*/ false, host_room, 0, host_id, deadline).await
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let guest = tokio::spawn(async move {
        observe_seat(guest_ws, /*create=*/ false, guest_room, 1, guest_id, deadline).await
    });

    let (host_res, guest_res) = tokio::join!(host, guest);
    let host_obs = host_res.map_err(|e| anyhow!("seat 0 task panicked: {e}"))??;
    let guest_obs = guest_res.map_err(|e| anyhow!("seat 1 task panicked: {e}"))??;

    // 3. summary.
    print_summary(&room, &host_obs, &guest_obs);
    Ok(())
}

/// Print the diagnostic summary — the answers to the key questions.
fn print_summary(room: &str, host: &SeatObs, guest: &SeatObs) {
    println!("\n══ probe-staked SUMMARY (room {room}) ════════════════════");

    // Prefer the host's RoomInfo; fall back to the guest's.
    let room_info = host.first_room_info.as_ref().or(guest.first_room_info.as_ref());

    match room_info {
        None => {
            println!("RoomInfo:            NONE OBSERVED on either seat");
            println!("  ⇒ the staked-room handshake did not deliver a RoomInfo within the window.");
        }
        Some(ri) => {
            let get = |k: &str| ri.get(k).cloned().unwrap_or(serde_json::Value::Null);
            let staked = get("staked");
            let escrow = get("escrow");
            let frost_url = get("frost_relay_url");
            let frost_code = get("frost_room_code");
            let null = serde_json::Value::Null;
            let dkg = frost_url != null || frost_code != null;

            println!("RoomInfo.staked:     {staked}");
            println!("RoomInfo.escrow:     {escrow}");
            println!("frost_relay_url:     {frost_url}");
            println!("frost_room_code:     {frost_code}");
            println!(
                "  ⇒ MODE: {}",
                if dkg {
                    "FROST-DKG (frost coords present)"
                } else {
                    "TRUSTED-DEALER (frost coords null)"
                }
            );
            println!("required_deposit:    {}", get("required_deposit"));
            println!("buyin_zat:           {}", get("buyin_zat"));
            println!("fee_per_seat:        {}", get("fee_per_seat"));
            println!("jury_nodes:          {}", get("jury_nodes"));
            println!("jury_threshold:      {}", get("jury_threshold"));
            println!("seat_addresses:      {}", get("seat_addresses"));
        }
    }

    let total_deposit = host.deposit_statuses.len() + guest.deposit_statuses.len();
    println!("\nDepositStatus frames: {} (seat0={}, seat1={})",
        total_deposit, host.deposit_statuses.len(), guest.deposit_statuses.len());
    for (i, ds) in host.deposit_statuses.iter().chain(guest.deposit_statuses.iter()).enumerate() {
        if let Some(sa) = ds.get("seat_addresses") {
            println!("  DepositStatus[{i}].seat_addresses: {sa}");
        }
    }

    println!("\nsrv frames observed: seat0={} seat1={}", host.frames.len(), guest.frames.len());

    println!("\n── first RoomInfo (raw JSON) ─────────────────────────────");
    match room_info {
        Some(ri) => println!("{}", serde_json::to_string_pretty(ri).unwrap_or_else(|_| ri.to_string())),
        None => println!("(none)"),
    }
    println!("══════════════════════════════════════════════════════════");
    println!("NO on-chain tx, NO deposit, NO settlement was sent. Read-only.");
}

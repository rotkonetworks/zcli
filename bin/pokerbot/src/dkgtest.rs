//! `dkg-test` — drive the REAL FROST 2-of-3 DKG ceremony for a production staked
//! poker room and PROVE it by observing the escrow Unified Address get produced.
//!
//! Flow (per the confirmed prod handshake — see `probe.rs`):
//!   1. HTTPS GET `{relay-http}/new?buyin=..&rake_bps=0` → room code (303 location;
//!      redirect NOT followed). Read-only room mint.
//!   2. Two websocket seats JOIN that code over `/p2p` (the escrow-aware relay).
//!      Seat 0 = first joiner, seat 1 = second. Each completes the E2EE `_keyex`
//!      and sends ONE `srv` `ClientMsg::Join` so the escrow seats it (the
//!      `DkgComplete` handler requires a seated player).
//!   3. Each seat waits for `RoomInfo{ staked, frost_relay_url, frost_room_code }`.
//!   4. Each seat connects to `frost_relay_url`, joins `frost_room_code`, and runs
//!      the real `frost-spend` DKG as a JOINER (escrow is the host). Both derive the
//!      escrow UA + Orchard FVK, cross-checked by the on-relay FVK echo.
//!   5. Each seat sends `srv` `ClientMsg::DkgComplete{ escrow_ua, orchard_fvk }`.
//!   6. Both seats watch for the relay to SURFACE the agreed UA: an updated
//!      `RoomInfo.escrow` (non-empty) and/or `DepositStatus.seat_addresses`.
//!
//! SAFETY: this ends at "escrow UA produced." It NEVER deposits, settles, pays out,
//! or broadcasts any Zcash transaction. DKG is key generation only — no ZEC moves.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use tokio::sync::Barrier;
use tracing::{info, warn};
use zcash_protocol::consensus::NetworkType;

use crate::dkg::{self, DkgOutput};
use crate::identity::Identity;
use crate::relay::{RelayFrame, Transport, WsTransport};
use crate::session::Peer;
use crate::srv::{ClientMsg, ServerMsg};

/// Mint a staked room via the relay's HTTP `/new` endpoint and return the room code
/// parsed from the 303 `location` header. Read-only: redirects are NOT followed.
async fn mint_room(relay_http: &str, buyin: u64) -> Result<String> {
    let url = format!(
        "{}/new?buyin={}&rake_bps=0",
        relay_http.trim_end_matches('/'),
        buyin
    );
    info!(%url, "GET (read-only room mint; redirects disabled)");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build reqwest client")?;
    let resp = client.get(&url).send().await.with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let code = match location {
        Some(loc) => loc.trim_start_matches('/').trim().to_string(),
        None => return Err(anyhow!("no `location` header on /new (status {status})")),
    };
    if code.is_empty() {
        return Err(anyhow!("empty room code from location header (status {status})"));
    }
    info!(status = %status, room = %code, "minted staked room");
    Ok(code)
}

/// FROST coords lifted out of a `RoomInfo` frame.
struct FrostCoords {
    relay_url: String,
    room_code: String,
    staked: bool,
}

/// The result each seat reports back to the summary.
struct SeatResult {
    seat: u8,
    dkg: Option<DkgOutput>,
    dkg_wall: Option<Duration>,
    dkg_complete_sent: bool,
    /// escrow UA surfaced by the relay AFTER our DkgComplete (RoomInfo.escrow non-empty).
    surfaced_escrow: Option<String>,
    /// seat deposit addresses surfaced by the relay (RoomInfo/DepositStatus).
    surfaced_seat_addrs: Vec<Option<String>>,
    error: Option<String>,
}

/// Pump `peer` until a `RoomInfo` with non-null frost coords arrives (or deadline).
/// Returns the coords. Any other srv frame is drained (and ignored) meanwhile.
async fn await_frost_coords(peer: &mut Peer, seat: u8, deadline: Instant) -> Result<FrostCoords> {
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let _ = tokio::time::timeout(remaining.min(Duration::from_secs(2)), peer.pump_once()).await;
        while let Some(sm) = peer.try_recv_srv() {
            if let ServerMsg::RoomInfo {
                escrow,
                staked,
                frost_relay_url,
                frost_room_code,
                ..
            } = &sm
            {
                info!(
                    seat, staked, escrow = %escrow,
                    frost_relay_url = ?frost_relay_url, frost_room_code = ?frost_room_code,
                    "RoomInfo observed",
                );
                if let (Some(url), Some(code)) = (frost_relay_url.clone(), frost_room_code.clone()) {
                    return Ok(FrostCoords { relay_url: url, room_code: code, staked: *staked });
                }
            }
        }
    }
    Err(anyhow!("seat {seat}: no RoomInfo with frost coords within window"))
}

/// After sending DkgComplete, watch for the relay to surface the agreed escrow UA
/// (RoomInfo.escrow non-empty) and any seat deposit addresses. Fills `res`.
async fn watch_for_surfaced_ua(peer: &mut Peer, res: &mut SeatResult, deadline: Instant) {
    while Instant::now() < deadline {
        // stop early once we've seen a non-empty escrow surface.
        if res.surfaced_escrow.is_some() {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let _ = tokio::time::timeout(remaining.min(Duration::from_secs(2)), peer.pump_once()).await;
        while let Some(sm) = peer.try_recv_srv() {
            match &sm {
                ServerMsg::RoomInfo { escrow, seat_addresses, .. } => {
                    if !escrow.is_empty() && res.surfaced_escrow.is_none() {
                        info!(seat = res.seat, escrow = %escrow, "relay surfaced escrow UA (RoomInfo)");
                        res.surfaced_escrow = Some(escrow.clone());
                    }
                    if !seat_addresses.is_empty() {
                        res.surfaced_seat_addrs = seat_addresses.clone();
                    }
                }
                ServerMsg::DepositStatus { escrow_address, seat_addresses, .. } => {
                    if !escrow_address.is_empty() && res.surfaced_escrow.is_none() {
                        info!(seat = res.seat, escrow = %escrow_address, "relay surfaced escrow (DepositStatus)");
                        res.surfaced_escrow = Some(escrow_address.clone());
                    }
                    if !seat_addresses.is_empty() {
                        res.surfaced_seat_addrs = seat_addresses.clone();
                    }
                }
                _ => {}
            }
        }
    }
}

/// Run one seat end-to-end through the DKG.
#[allow(clippy::too_many_arguments)]
async fn run_seat(
    transport: Transport,
    room: String,
    seat: u8,
    identity: Identity,
    network: NetworkType,
    dkg_timeout: Duration,
    seated_barrier: Arc<Barrier>,
    overall_deadline: Instant,
) -> SeatResult {
    let mut res = SeatResult {
        seat,
        dkg: None,
        dkg_wall: None,
        dkg_complete_sent: false,
        surfaced_escrow: None,
        surfaced_seat_addrs: Vec::new(),
        error: None,
    };

    let nick = crate::random_nick();
    let mut peer = Peer::new(transport, nick);
    peer.set_session_pub(identity.pubkey_hex());

    // 1. join the poker room (creator=seat0, joiner=seat1).
    if let Err(e) = peer.join_room(false, Some(room.clone())).await {
        res.error = Some(format!("join_room: {e}"));
        return res;
    }
    info!(seat, "joined poker room; running E2EE handshake (bounded)");

    // 2. best-effort E2EE handshake so the table progresses like a real one.
    match tokio::time::timeout(Duration::from_secs(15), peer.key_exchange()).await {
        Ok(Ok(())) => info!(seat, "E2EE ready"),
        Ok(Err(e)) => warn!(seat, error = %e, "key_exchange errored; continuing"),
        Err(_) => warn!(seat, "key_exchange timed out; continuing"),
    }

    // 3. announce identity via srv Join so the escrow SEATS us (DkgComplete needs a seat).
    if let Err(e) = peer
        .send_srv(ClientMsg::Join {
            name: format!("dkgbot-seat-{seat}"),
            pubkey: Some(identity.pubkey_hex()),
            zcash_address: None,
        })
        .await
    {
        res.error = Some(format!("srv Join: {e}"));
        return res;
    }
    info!(seat, "announced seat via srv Join");

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

    // Rendezvous: both seats must have their coords + be seated before EITHER starts
    // the FROST DKG, so the escrow host sees all 3 parties promptly.
    let _ = tokio::time::timeout(
        overall_deadline.saturating_duration_since(Instant::now()),
        seated_barrier.wait(),
    )
    .await;

    // 5. run the REAL DKG on the FROST relay as a joiner.
    info!(
        seat,
        relay = %coords.relay_url, frost_room = %coords.room_code,
        "starting FROST DKG (joiner)"
    );
    let dkg_nick = format!("dkgbot-seat-{seat}-{}", crate::random_nick());
    let t0 = Instant::now();
    let dkg = dkg::run_dkg_joiner(
        &coords.relay_url,
        &coords.room_code,
        dkg_nick,
        network,
        dkg_timeout,
    )
    .await;
    let wall = t0.elapsed();
    res.dkg_wall = Some(wall);

    let out = match dkg {
        Ok(o) => {
            info!(
                seat, wall_ms = wall.as_millis(),
                ua = %o.orchard_ua, net = ?o.network,
                "DKG complete — escrow UA derived",
            );
            o
        }
        Err(e) => {
            res.error = Some(format!("DKG failed after {:?}: {e}", wall));
            return res;
        }
    };
    res.dkg = Some(out.clone());

    // 6. report our DkgComplete to the escrow/relay.
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
    res.dkg_complete_sent = true;
    info!(seat, "sent srv DkgComplete");

    // 7. watch for the relay to surface the agreed UA / seat addresses.
    watch_for_surfaced_ua(&mut peer, &mut res, overall_deadline).await;

    // leave cleanly — `part` commits nothing.
    let _ = peer.transport.send(&RelayFrame::Part).await;
    res
}

/// Entry point for `dkg-test`.
pub async fn run(
    relay_http: String,
    relay_ws: String,
    buyin: u64,
    network: String,
    dkg_secs: u64,
    watch_secs: u64,
) -> Result<()> {
    let net = dkg::network_from_str(&network);
    println!("── pokerbot dkg-test (real FROST DKG; NO money moves) ─────");
    println!("relay-http:  {relay_http}");
    println!("relay-ws:    {relay_ws}");
    println!("buyin:       {buyin} zat");
    println!("network:     {network} ({net:?})");
    println!("dkg-timeout: {dkg_secs}s   watch: {watch_secs}s\n");

    // 1. mint the room (read-only GET).
    let room = mint_room(&relay_http, buyin).await?;

    // 2. two seats over /p2p, run concurrently.
    let overall_deadline = Instant::now() + Duration::from_secs(dkg_secs + watch_secs + 30);
    let dkg_timeout = Duration::from_secs(dkg_secs);

    let host_ws = Transport::Ws(
        WsTransport::connect(&relay_ws).await.context("seat 0 ws connect")?,
    );
    let guest_ws = Transport::Ws(
        WsTransport::connect(&relay_ws).await.context("seat 1 ws connect")?,
    );

    let host_id = Identity::for_selfplay(0xDC6, 0);
    let guest_id = Identity::for_selfplay(0xDC6, 1);

    // both seats gate on this barrier after seating, so the FROST DKG starts together.
    let barrier = Arc::new(Barrier::new(2));

    let host_room = room.clone();
    let guest_room = room.clone();
    let b0 = barrier.clone();
    let b1 = barrier.clone();

    let host = tokio::spawn(async move {
        run_seat(host_ws, host_room, 0, host_id, net, dkg_timeout, b0, overall_deadline).await
    });
    // small stagger so seat 0 lands first (join order = seat index).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let guest = tokio::spawn(async move {
        run_seat(guest_ws, guest_room, 1, guest_id, net, dkg_timeout, b1, overall_deadline).await
    });

    let (host_res, guest_res) = tokio::join!(host, guest);
    let host = host_res.map_err(|e| anyhow!("seat 0 task panicked: {e}"))?;
    let guest = guest_res.map_err(|e| anyhow!("seat 1 task panicked: {e}"))?;

    let ok = print_summary(&room, &host, &guest);
    if ok {
        Ok(())
    } else {
        Err(anyhow!("dkg-test did not fully complete — see summary above"))
    }
}

/// Print the proof summary. Returns true iff both seats derived the SAME UA.
fn print_summary(room: &str, host: &SeatResult, guest: &SeatResult) -> bool {
    println!("\n══ dkg-test SUMMARY (room {room}) ═══════════════════════════");

    for r in [host, guest] {
        print!("seat {}: ", r.seat);
        match (&r.dkg, &r.error) {
            (Some(d), _) => println!(
                "DKG OK in {} — ua={} net={:?}",
                fmt_dur(r.dkg_wall),
                d.orchard_ua,
                d.network,
            ),
            (None, Some(e)) => println!("DKG FAILED ({}) — {e}", fmt_dur(r.dkg_wall)),
            (None, None) => println!("no DKG result and no error (incomplete)"),
        }
    }

    let both_agree = match (&host.dkg, &guest.dkg) {
        (Some(h), Some(g)) => {
            let agree = h.orchard_ua == g.orchard_ua && h.orchard_fvk_hex == g.orchard_fvk_hex;
            println!(
                "\nboth seats derived the SAME escrow UA?  {}",
                if agree { "YES ✓" } else { "NO ✗ (UA/FVK differ — real divergence)" }
            );
            if !agree {
                println!("  seat0 ua: {}", h.orchard_ua);
                println!("  seat1 ua: {}", g.orchard_ua);
                println!("  seat0 fvk…{}", tail(&h.orchard_fvk_hex));
                println!("  seat1 fvk…{}", tail(&g.orchard_fvk_hex));
            }
            agree
        }
        _ => {
            println!("\nboth seats derived the SAME escrow UA?  N/A (a seat has no DKG result)");
            false
        }
    };

    if let Some(d) = host.dkg.as_ref().or(guest.dkg.as_ref()) {
        println!("\nDERIVED ESCROW UA:   {}", d.orchard_ua);
        println!("DERIVED ORCHARD FVK: …{} (96 bytes)", tail(&d.orchard_fvk_hex));
        println!("DERIVED UFVK:        {}", d.orchard_ufvk);
    }

    println!(
        "\nDkgComplete sent:    seat0={} seat1={}",
        host.dkg_complete_sent, guest.dkg_complete_sent
    );

    let surfaced = host.surfaced_escrow.as_ref().or(guest.surfaced_escrow.as_ref());
    match surfaced {
        Some(ua) => {
            println!("relay SURFACED escrow UA (RoomInfo.escrow/DepositStatus): {ua}");
            if let Some(d) = host.dkg.as_ref().or(guest.dkg.as_ref()) {
                println!(
                    "  matches our DERIVED UA?  {}",
                    if *ua == d.orchard_ua { "YES ✓" } else { "NO ✗" }
                );
            }
        }
        None => println!(
            "relay did NOT surface a non-empty escrow UA within {}s watch window",
            "(watch)",
        ),
    }

    let seat_addrs = if !host.surfaced_seat_addrs.is_empty() {
        &host.surfaced_seat_addrs
    } else {
        &guest.surfaced_seat_addrs
    };
    if seat_addrs.iter().any(|a| a.is_some()) {
        println!("relay SURFACED seat deposit addresses:");
        for (i, a) in seat_addrs.iter().enumerate() {
            println!("  seat {i}: {}", a.as_deref().unwrap_or("(none)"));
        }
    } else {
        println!("relay surfaced NO seat deposit addresses within the window");
    }

    println!(
        "\nphase timing (DKG wall-clock):  seat0={}  seat1={}",
        fmt_dur(host.dkg_wall),
        fmt_dur(guest.dkg_wall),
    );
    println!("══════════════════════════════════════════════════════════");
    println!("NO deposit, NO settlement, NO on-chain tx was sent. DKG (key-gen) only.");

    both_agree
}

fn fmt_dur(d: Option<Duration>) -> String {
    match d {
        Some(d) => format!("{}ms", d.as_millis()),
        None => "n/a".into(),
    }
}

fn tail(s: &str) -> &str {
    &s[s.len().saturating_sub(12)..]
}

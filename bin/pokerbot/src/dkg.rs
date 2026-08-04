//! Real FROST 2-of-3 DKG for a staked poker room — the ceremony that produces the
//! escrow Unified Address. This is a faithful port of the escrow's own DKG client
//! (`poker-escrow/src/frost_relay.rs` + `frost_dkg.rs` + `orchard_ua.rs`) so the two
//! bot seats speak the EXACT same wire protocol as a browser (zafu) player.
//!
//! ── DKG parties (2-of-3) ─────────────────────────────────────────────────────
//!   * ESCROW  — the DKG *host*. It provisions the FROST relay room (via the escrow
//!     service's HTTP `/room` path), joins first, samples the shared fvk-seed `sk`,
//!     and broadcasts it inside its round-1 message. `is_host=true` on the escrow.
//!   * SEAT A / SEAT B — the two players. Both are DKG *joiners* (`is_host=false`);
//!     they learn the host's `sk` from its R1. THIS bot drives seats A + B.
//!   FROST identifiers are NOT positional — each party derives its own identifier
//!   from an ephemeral ed25519 verifying key (`identifier_from_vk`), so there is no
//!   fixed seat→index map inside DKG; the relay just needs all 3 present.
//!
//! ── Wire protocol on the FROST relay (`wss://zrelay.rotko.net/ws`) ────────────
//!   JSON text frames, blind broadcast to the room (`create`/`join`/`msg`/`part`):
//!     host R1:    "R1:T:N:SK:<fvk_sk_hex>:<part1_broadcast_hex>"
//!     joiner R1:  "R1:<part1_broadcast_hex>"
//!     R2:         "R2:<peer_package_hex>"       (each party emits N-1 = 2)
//!     FVK echo:   "FVK:<orchard_ufvk_string>"   (all 3 must agree)
//!   Ordering: wait until room has N=3 → send R1 → collect N-1 peer R1s → part2 →
//!   send 2×R2 → collect (N-1)^2 = 4 R2s → part3 → derive UA/UFVK at diversifier 0 →
//!   send FVK echo → collect N-1 peer FVKs → assert all equal → done.
//!
//! SAFETY: DKG generates keys only. Nothing here builds, signs, or broadcasts a
//! Zcash transaction; no ZEC moves.

use std::time::{Duration, Instant};

use ff::PrimeField;
use frost_spend::orchestrate as fs;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, protocol::Message},
    MaybeTlsStream, WebSocketStream,
};
use zcash_address::unified::{Address as UnifiedAddress, Encoding, Fvk, Receiver, Ufvk};
use zcash_protocol::consensus::NetworkType;

// ─────────────────────────────────────────────────────────────────────────────
// FROST relay WS client (port of poker-escrow/src/frost_relay.rs)
// ─────────────────────────────────────────────────────────────────────────────

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Serialize)]
#[serde(tag = "t")]
enum RelayClientMsg<'a> {
    // NOTE: the bot only ever JOINs the FROST room — the escrow service is the DKG
    // host and CREATEs it. No `create` variant here by design.
    #[serde(rename = "join")]
    Join { room: &'a str, nick: &'a str },
    #[serde(rename = "msg")]
    Msg { text: &'a str },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "t")]
enum RelayServerMsg {
    #[serde(rename = "created")]
    Created {
        #[allow(dead_code)]
        room: String,
    },
    #[serde(rename = "joined")]
    Joined { nick: String, count: u32 },
    #[serde(rename = "msg")]
    Msg { nick: String, text: String },
    #[serde(rename = "system")]
    System { text: String },
    #[serde(rename = "error")]
    Error { msg: String },
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone)]
pub(crate) enum RelayEvent {
    PeerJoined { count: u32 },
    Message { payload: Vec<u8> },
    Closed { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("ws closed")]
    Closed,
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("io: {0}")]
    Io(String),
}

/// FROST relay WS client shared by the DKG joiner (this module) and the payout
/// co-signer (`payout.rs`). Same wire the escrow's `frost_relay.rs` speaks; the bot
/// only ever JOINs rooms (the escrow service creates them).
pub(crate) struct FrostRelayClient {
    ws: Ws,
    nick: String,
}

impl FrostRelayClient {
    pub(crate) async fn connect(url: &str, nick: String) -> Result<Self, RelayError> {
        let req = url
            .into_client_request()
            .map_err(|e| RelayError::Connect(e.to_string()))?;
        let (ws, _resp) = connect_async(req)
            .await
            .map_err(|e| RelayError::Connect(e.to_string()))?;
        Ok(Self { ws, nick })
    }

    /// Join an existing FROST room by code. Returns the participant count after us.
    pub(crate) async fn join_room(&mut self, room: &str) -> Result<u32, RelayError> {
        let nick = self.nick.clone();
        self.send_json(&RelayClientMsg::Join { room, nick: &nick }).await?;
        loop {
            match self.read_next().await? {
                RelayServerMsg::Joined { nick: joiner, count } if joiner == nick => return Ok(count),
                RelayServerMsg::Error { msg } => return Err(RelayError::Protocol(msg)),
                _ => continue,
            }
        }
    }

    pub(crate) async fn send_message(&mut self, payload: &[u8]) -> Result<(), RelayError> {
        let text = std::str::from_utf8(payload)
            .map_err(|e| RelayError::Protocol(format!("payload not UTF-8: {}", e)))?;
        self.send_json(&RelayClientMsg::Msg { text }).await
    }

    async fn recv_event(&mut self) -> Result<RelayEvent, RelayError> {
        loop {
            match self.read_next().await? {
                RelayServerMsg::Joined { nick, count } if nick != self.nick => {
                    return Ok(RelayEvent::PeerJoined { count });
                }
                RelayServerMsg::Msg { nick, text } if nick != self.nick => {
                    return Ok(RelayEvent::Message { payload: text.into_bytes() });
                }
                RelayServerMsg::System { text } if text.contains("joined") => {
                    let count = parse_system_join_count(&text);
                    return Ok(RelayEvent::PeerJoined { count });
                }
                RelayServerMsg::System { text }
                    if text.contains("left")
                        || text.contains("disconnected")
                        || text.contains("closed") =>
                {
                    return Ok(RelayEvent::Closed { reason: text });
                }
                RelayServerMsg::Error { msg } => return Err(RelayError::Protocol(msg)),
                _ => continue,
            }
        }
    }

    pub(crate) async fn recv_event_timeout(
        &mut self,
        deadline: Duration,
    ) -> Result<Option<RelayEvent>, RelayError> {
        match tokio::time::timeout(deadline, self.recv_event()).await {
            Ok(r) => r.map(Some),
            Err(_) => Ok(None),
        }
    }

    async fn send_json<T: Serialize>(&mut self, msg: &T) -> Result<(), RelayError> {
        let body = serde_json::to_string(msg).map_err(|e| RelayError::Protocol(e.to_string()))?;
        self.ws
            .send(Message::Text(body.into()))
            .await
            .map_err(|e| RelayError::Io(e.to_string()))?;
        Ok(())
    }

    async fn read_next(&mut self) -> Result<RelayServerMsg, RelayError> {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Text(text))) => {
                    let parsed: RelayServerMsg = serde_json::from_str(&text)
                        .map_err(|e| RelayError::Protocol(format!("bad json: {}", e)))?;
                    return Ok(parsed);
                }
                Some(Ok(Message::Ping(p))) => {
                    let _ = self.ws.send(Message::Pong(p)).await;
                    continue;
                }
                Some(Ok(Message::Close(_))) | None => return Err(RelayError::Closed),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(RelayError::Io(e.to_string())),
            }
        }
    }
}

/// "<nick> joined (N)" → N. Tolerant: 0 on parse failure.
fn parse_system_join_count(text: &str) -> u32 {
    text.rsplit_once('(')
        .and_then(|(_, tail)| tail.split_once(')'))
        .and_then(|(n, _)| n.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchard UA / UFVK encoding (port of poker-escrow/src/orchard_ua.rs)
// ─────────────────────────────────────────────────────────────────────────────

fn encode_unified(raw: [u8; 43], network: NetworkType) -> Result<String, String> {
    let receiver = Receiver::Orchard(raw);
    let ua = UnifiedAddress::try_from_items(vec![receiver])
        .map_err(|e| format!("UA assembly failed: {}", e))?;
    Ok(ua.encode(&network))
}

/// raw 96-byte Orchard FVK from the DKG group pubkey + host-broadcast sk.
fn fvk_bytes_from_sk(public_key_package_hex: &str, sk_bytes: [u8; 32]) -> Result<[u8; 96], String> {
    let pubkeys: frost_spend::frost_keys::PublicKeyPackage =
        fs::from_hex(public_key_package_hex).map_err(|e| format!("pkg parse: {:?}", e))?;
    let fvk = frost_spend::keys::derive_fvk_from_sk(sk_bytes, &pubkeys)
        .ok_or_else(|| "derive_fvk_from_sk returned None".to_string())?;
    Ok(fvk.to_bytes())
}

fn encode_ufvk_from_sk(
    public_key_package_hex: &str,
    sk_bytes: [u8; 32],
    network: NetworkType,
) -> Result<String, String> {
    let bytes = fvk_bytes_from_sk(public_key_package_hex, sk_bytes)?;
    let ufvk = Ufvk::try_from_items(vec![Fvk::Orchard(bytes)])
        .map_err(|e| format!("UFVK assembly failed: {}", e))?;
    Ok(ufvk.encode(&network))
}

// ─────────────────────────────────────────────────────────────────────────────
// DKG state machine (port of poker-escrow/src/frost_dkg.rs, joiner path)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DkgOutput {
    /// the shared FROST group public key package (all 3 parties agree). Needed by
    /// the payout co-sign (`payout::cosign_payout`) to aggregate/verify shares.
    pub public_key_package_hex: String,
    /// THIS seat's private FROST key package (its 1-of-N share). Threaded into the
    /// payout co-sign so the bot can contribute its round-1/round-2 shares. SECRET.
    pub key_package_hex: String,
    /// THIS seat's ephemeral signing seed from `dkg_part3` — mints the fresh nonces
    /// each FROST signing round needs. Threaded into the payout co-sign. SECRET.
    pub ephemeral_seed_hex: String,
    /// the agreed escrow Unified Address (diversifier index 0).
    pub orchard_ua: String,
    /// the agreed Unified FVK string (echoed + cross-checked by all parties).
    pub orchard_ufvk: String,
    /// raw 96-byte FVK hex — what `DkgComplete.orchard_fvk` carries.
    pub orchard_fvk_hex: String,
    /// the network we successfully agreed on (may differ from the flag if the
    /// escrow ran a different network and we re-derived to match its FVK echo).
    pub network: NetworkType,
}

#[derive(Debug, thiserror::Error)]
pub enum DkgError {
    #[error("relay: {0}")]
    Relay(#[from] RelayError),
    #[error("frost-spend: {0}")]
    Frost(String),
    #[error("ua: {0}")]
    Ua(String),
    #[error("timed out: {0}")]
    Timeout(String),
    #[error("room closed: {0}")]
    Closed(String),
    #[error("protocol: {0}")]
    Protocol(String),
}

const DKG_THRESHOLD: u16 = 2;
const DKG_TOTAL: u16 = 3;

/// Connect to the FROST relay, join `frost_room_code`, and run the 2-of-3 DKG as a
/// JOINER (the escrow is the host). Returns the agreed escrow UA + FVK once the FVK
/// echo matches across all parties. `nick` should be unique per seat.
///
/// `network` is the network to derive/echo on; if the escrow echoes a UFVK on the
/// OTHER network we re-derive to match it and report that in the output — the FVK
/// echo (network-tagged) is the source of truth.
pub async fn run_dkg_joiner(
    relay_url: &str,
    frost_room_code: &str,
    nick: String,
    network: NetworkType,
    timeout: Duration,
) -> Result<DkgOutput, DkgError> {
    let deadline = Instant::now() + timeout;

    let mut client = FrostRelayClient::connect(relay_url, nick).await?;
    let count = client.join_room(frost_room_code).await?;

    // wait until all 3 parties (escrow host + 2 seats) are present.
    wait_for_full_room(&mut client, DKG_TOTAL as u32, count, &deadline).await?;

    // round 1 — joiner sends bare broadcast; escrow (host) sends the SK-bearing R1.
    let r1 =
        fs::dkg_part1(DKG_TOTAL, DKG_THRESHOLD).map_err(|e| DkgError::Frost(format!("part1: {:?}", e)))?;
    client
        .send_message(format!("R1:{}", r1.broadcast_hex).as_bytes())
        .await?;

    let (r1_peers, learned_sk) = collect_r1(&mut client, (DKG_TOTAL - 1) as usize, &deadline).await?;
    let sk_hex = learned_sk.ok_or_else(|| DkgError::Protocol("no host SK seen in R1".into()))?;

    // round 2
    let r2 = fs::dkg_part2(&r1.secret_hex, &r1_peers)
        .map_err(|e| DkgError::Frost(format!("part2: {:?}", e)))?;
    for pkg in &r2.peer_packages {
        client.send_message(format!("R2:{}", pkg).as_bytes()).await?;
    }
    let expected_r2 = ((DKG_TOTAL - 1) as usize).pow(2);
    let r2_peers = collect_tagged(&mut client, "R2:", expected_r2, &deadline).await?;

    // round 3 — the group public key package
    let r3 = fs::dkg_part3(&r2.secret_hex, &r1_peers, &r2_peers)
        .map_err(|e| DkgError::Frost(format!("part3: {:?}", e)))?;

    let sk_bytes = decode_sk(&sk_hex)?;

    // derive UA + UFVK on the flagged network.
    let addr_bytes = fs::derive_address_from_sk(&r3.public_key_package_hex, sk_bytes, 0)
        .map_err(|e| DkgError::Frost(format!("derive_address_from_sk: {:?}", e)))?;
    let fvk_bytes = fvk_bytes_from_sk(&r3.public_key_package_hex, sk_bytes).map_err(DkgError::Ua)?;
    let ua = encode_unified(addr_bytes, network).map_err(DkgError::Ua)?;
    let ufvk = encode_ufvk_from_sk(&r3.public_key_package_hex, sk_bytes, network).map_err(DkgError::Ua)?;

    // FVK echo — every party sends its UFVK; all must agree (source of truth).
    client.send_message(format!("FVK:{}", ufvk).as_bytes()).await?;
    let peer_fvks = collect_tagged(&mut client, "FVK:", (DKG_TOTAL - 1) as usize, &deadline).await?;

    // If a peer echoed a UFVK on the OTHER network (escrow ran mainnet vs testnet),
    // re-derive on that network so we converge on the escrow's canonical string
    // rather than reporting a spurious mismatch. The FVK bytes are network-agnostic;
    // only the encoding prefix differs.
    let (final_network, final_ua, final_ufvk) = reconcile_network(
        network,
        &ufvk,
        &ua,
        &peer_fvks,
        &r3.public_key_package_hex,
        sk_bytes,
        addr_bytes,
    )?;

    Ok(DkgOutput {
        public_key_package_hex: r3.public_key_package_hex,
        key_package_hex: r3.key_package_hex,
        ephemeral_seed_hex: r3.ephemeral_seed_hex,
        orchard_ua: final_ua,
        orchard_ufvk: final_ufvk,
        orchard_fvk_hex: hex::encode(fvk_bytes),
        network: final_network,
    })
}

/// If every peer FVK equals ours, done. Otherwise try re-deriving on the OTHER
/// network and check whether THAT matches — if so, the escrow simply ran a
/// different network and we adopt its encoding. Any remaining mismatch is a real
/// DKG divergence (different group key) and is a hard error.
#[allow(clippy::too_many_arguments)]
fn reconcile_network(
    network: NetworkType,
    ours_ufvk: &str,
    ours_ua: &str,
    peer_fvks: &[String],
    public_key_package_hex: &str,
    sk_bytes: [u8; 32],
    addr_bytes: [u8; 43],
) -> Result<(NetworkType, String, String), DkgError> {
    if peer_fvks.iter().all(|p| p == ours_ufvk) {
        return Ok((network, ours_ua.to_string(), ours_ufvk.to_string()));
    }

    let other = match network {
        NetworkType::Main => NetworkType::Test,
        _ => NetworkType::Main,
    };
    let other_ufvk = encode_ufvk_from_sk(public_key_package_hex, sk_bytes, other).map_err(DkgError::Ua)?;
    if peer_fvks.iter().all(|p| p == &other_ufvk) {
        let other_ua = encode_unified(addr_bytes, other).map_err(DkgError::Ua)?;
        tracing::warn!(
            "FVK network reconciled: escrow runs {:?}, not {:?}; adopting escrow's UA",
            other, network,
        );
        return Ok((other, other_ua, other_ufvk));
    }

    // genuine mismatch — the group verifying key or sk differs. Report the tails.
    let peer = peer_fvks
        .iter()
        .find(|p| *p != ours_ufvk && *p != &other_ufvk)
        .cloned()
        .unwrap_or_else(|| peer_fvks.first().cloned().unwrap_or_default());
    let our_tail = &ours_ufvk[ours_ufvk.len().saturating_sub(10)..];
    let their_tail = &peer[peer.len().saturating_sub(10)..];
    Err(DkgError::Protocol(format!(
        "FVK mismatch (not a network difference): ours ends …{}, peer ends …{}",
        our_tail, their_tail,
    )))
}

fn decode_sk(hex_string: &str) -> Result<[u8; 32], DkgError> {
    let bytes = hex::decode(hex_string.trim())
        .map_err(|e| DkgError::Frost(format!("sk hex decode: {}", e)))?;
    if bytes.len() != 32 {
        return Err(DkgError::Frost(format!("sk wrong length: {}", bytes.len())));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

async fn wait_for_full_room(
    client: &mut FrostRelayClient,
    total: u32,
    initial_count: u32,
    deadline: &Instant,
) -> Result<(), DkgError> {
    if initial_count >= total {
        return Ok(());
    }
    loop {
        let remaining = remaining_or_timeout(deadline, "waiting for peers")?;
        match client.recv_event_timeout(remaining).await? {
            Some(RelayEvent::PeerJoined { count }) if count >= total => return Ok(()),
            Some(RelayEvent::PeerJoined { .. }) => continue,
            Some(RelayEvent::Message { .. }) => continue, // pre-DKG noise
            Some(RelayEvent::Closed { reason }) => return Err(DkgError::Closed(reason)),
            None => return Err(DkgError::Timeout("waiting for peers".into())),
        }
    }
}

/// returns (peer broadcasts, host-supplied sk if any). Joiners never emit an SK,
/// so exactly one peer R1 (the escrow host's) carries it.
async fn collect_r1(
    client: &mut FrostRelayClient,
    n: usize,
    deadline: &Instant,
) -> Result<(Vec<String>, Option<String>), DkgError> {
    let mut broadcasts = Vec::with_capacity(n);
    let mut sk: Option<String> = None;
    while broadcasts.len() < n {
        let label = || format!("R1 collected {}/{}", broadcasts.len(), n);
        let remaining = remaining_or_timeout(deadline, &label())?;
        match client.recv_event_timeout(remaining).await? {
            Some(RelayEvent::Message { payload }) => {
                let text = String::from_utf8(payload)
                    .map_err(|e| DkgError::Frost(format!("non-utf8 dkg payload: {}", e)))?;
                // ignore anything that isn't an R1 frame (stray R2/FVK on a busy room)
                if !text.starts_with("R1:") {
                    continue;
                }
                let (broadcast, host_sk) = parse_r1(&text)?;
                if let Some(s) = host_sk {
                    sk = Some(s);
                }
                broadcasts.push(broadcast);
            }
            Some(RelayEvent::PeerJoined { .. }) => continue,
            Some(RelayEvent::Closed { reason }) => return Err(DkgError::Closed(reason)),
            None => return Err(DkgError::Timeout(label())),
        }
    }
    Ok((broadcasts, sk))
}

fn parse_r1(text: &str) -> Result<(String, Option<String>), DkgError> {
    let body = text
        .strip_prefix("R1:")
        .ok_or_else(|| DkgError::Protocol(format!("expected R1: tag, got: {}", short(text))))?;
    if let Some((sk, broadcast)) = parse_host_prefix(body) {
        return Ok((broadcast, Some(sk)));
    }
    Ok((body.to_string(), None))
}

/// peel the host-only "T:N:SK:<sk>:<broadcast>" header; None on a joiner R1.
fn parse_host_prefix(body: &str) -> Option<(String, String)> {
    if !body.chars().next()?.is_ascii_digit() {
        return None;
    }
    let (_t, rest) = body.split_once(':')?;
    let (_n, rest) = rest.split_once(':')?;
    let rest = rest.strip_prefix("SK:")?;
    let (sk_hex, broadcast) = rest.split_once(':')?;
    if sk_hex.len() != 64 || !sk_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some((sk_hex.to_string(), broadcast.to_string()))
}

/// collect n messages with the given tag, returning bodies with tag stripped.
/// Frames with a different (already-consumed) tag are skipped, so a party that
/// races ahead can't wedge us.
async fn collect_tagged(
    client: &mut FrostRelayClient,
    tag: &str,
    n: usize,
    deadline: &Instant,
) -> Result<Vec<String>, DkgError> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let label = || format!("{} collected {}/{}", tag, out.len(), n);
        let remaining = remaining_or_timeout(deadline, &label())?;
        match client.recv_event_timeout(remaining).await? {
            Some(RelayEvent::Message { payload }) => {
                let text = String::from_utf8(payload)
                    .map_err(|e| DkgError::Frost(format!("non-utf8 dkg payload: {}", e)))?;
                match text.strip_prefix(tag) {
                    Some(body) => out.push(body.to_string()),
                    None => continue, // a different-phase frame; ignore
                }
            }
            Some(RelayEvent::PeerJoined { .. }) => continue,
            Some(RelayEvent::Closed { reason }) => return Err(DkgError::Closed(reason)),
            None => return Err(DkgError::Timeout(label())),
        }
    }
    Ok(out)
}

fn remaining_or_timeout(deadline: &Instant, ctx: &str) -> Result<Duration, DkgError> {
    let now = Instant::now();
    if now >= *deadline {
        Err(DkgError::Timeout(ctx.to_string()))
    } else {
        Ok(*deadline - now)
    }
}

fn short(s: &str) -> String {
    let take = s.len().min(32);
    s[..take].to_string()
}

/// Sample 32 bytes inside the Pallas scalar field. Only the HOST needs this; a
/// joiner never generates the sk. Kept here for a `--host` self-test path and to
/// mirror the escrow exactly.
#[allow(dead_code)]
pub fn sample_valid_sk_hex() -> String {
    let mut rng = rand::thread_rng();
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let scalar = pasta_curves::pallas::Scalar::from_repr(bytes);
        if bool::from(scalar.is_some()) {
            return hex::encode(bytes);
        }
    }
}

/// Map the CLI `--network` string to a NetworkType (mirrors escrow `network_from_str`).
pub fn network_from_str(s: &str) -> NetworkType {
    match s {
        "main" | "mainnet" => NetworkType::Main,
        "regtest" => NetworkType::Regtest,
        _ => NetworkType::Test,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_r1_host_and_joiner() {
        let sk_hex = "0".repeat(64);
        let host = format!("R1:2:3:SK:{}:abcdef", sk_hex);
        let (b, s) = parse_r1(&host).unwrap();
        assert_eq!(b, "abcdef");
        assert_eq!(s.as_deref(), Some(sk_hex.as_str()));

        let joiner = "R1:abcdef".to_string();
        let (b, s) = parse_r1(&joiner).unwrap();
        assert_eq!(b, "abcdef");
        assert_eq!(s, None);

        assert!(parse_r1("R2:abcdef").is_err());
    }

    #[test]
    fn system_join_count_parse() {
        assert_eq!(parse_system_join_count("abcd… joined (3)"), 3);
        assert_eq!(parse_system_join_count("garbage"), 0);
    }

    #[test]
    fn network_str_map() {
        assert!(matches!(network_from_str("main"), NetworkType::Main));
        assert!(matches!(network_from_str("mainnet"), NetworkType::Main));
        assert!(matches!(network_from_str("test"), NetworkType::Test));
        assert!(matches!(network_from_str("regtest"), NetworkType::Regtest));
    }

    // Full LOCAL DKG (host + 2 joiners over frost-spend, no relay) proving the
    // joiner derivation converges on the SAME UA/UFVK the host would — the exact
    // agreement the on-relay FVK-echo asserts. Uses the shared lib directly.
    #[test]
    fn joiner_derivation_agrees_across_all_three() {
        // three interactive DKG parties (mirrors frost-spend's own test).
        let a = fs::dkg_part1(3, 2).unwrap();
        let b = fs::dkg_part1(3, 2).unwrap();
        let c = fs::dkg_part1(3, 2).unwrap();

        let bc_a = vec![b.broadcast_hex.clone(), c.broadcast_hex.clone()];
        let bc_b = vec![a.broadcast_hex.clone(), c.broadcast_hex.clone()];
        let bc_c = vec![a.broadcast_hex.clone(), b.broadcast_hex.clone()];

        let r2a = fs::dkg_part2(&a.secret_hex, &bc_a).unwrap();
        let r2b = fs::dkg_part2(&b.secret_hex, &bc_b).unwrap();
        let r2c = fs::dkg_part2(&c.secret_hex, &bc_c).unwrap();

        let all_r2: Vec<String> = r2a
            .peer_packages
            .iter()
            .chain(r2b.peer_packages.iter())
            .chain(r2c.peer_packages.iter())
            .cloned()
            .collect();

        let r3a = fs::dkg_part3(&r2a.secret_hex, &bc_a, &all_r2).unwrap();
        let r3b = fs::dkg_part3(&r2b.secret_hex, &bc_b, &all_r2).unwrap();
        let r3c = fs::dkg_part3(&r2c.secret_hex, &bc_c, &all_r2).unwrap();

        // all agree on the group pubkey package.
        assert_eq!(r3a.public_key_package_hex, r3b.public_key_package_hex);
        assert_eq!(r3b.public_key_package_hex, r3c.public_key_package_hex);

        // host samples the shared sk; every party derives the SAME UA/UFVK from it.
        let sk_hex = sample_valid_sk_hex();
        let sk = decode_sk(&sk_hex).unwrap();
        let net = NetworkType::Test;

        let ua_a = {
            let raw = fs::derive_address_from_sk(&r3a.public_key_package_hex, sk, 0).unwrap();
            encode_unified(raw, net).unwrap()
        };
        let ua_b = {
            let raw = fs::derive_address_from_sk(&r3b.public_key_package_hex, sk, 0).unwrap();
            encode_unified(raw, net).unwrap()
        };
        let ua_c = {
            let raw = fs::derive_address_from_sk(&r3c.public_key_package_hex, sk, 0).unwrap();
            encode_unified(raw, net).unwrap()
        };
        assert_eq!(ua_a, ua_b, "seat A vs seat B escrow UA");
        assert_eq!(ua_b, ua_c, "seat B vs escrow(host) UA");
        assert!(ua_a.starts_with("utest1"), "testnet UA prefix, got {}", ua_a);

        let uf_a = encode_ufvk_from_sk(&r3a.public_key_package_hex, sk, net).unwrap();
        let uf_b = encode_ufvk_from_sk(&r3b.public_key_package_hex, sk, net).unwrap();
        assert_eq!(uf_a, uf_b, "UFVK echo must agree across parties");
        assert!(uf_a.starts_with("uviewtest1"));
    }
}

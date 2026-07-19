//! Envelope + handshake glue that sits between the raw relay transport and the
//! game logic. Owns the E2EE session and turns opaque `msg` frames into typed,
//! decrypted game messages (and back).
//!
//! Inner "WireMessage" shape: `{"t":"<type>","d":<payload>}`.
//! Two inner kinds cross the wire:
//!   - `_keyex` : PLAINTEXT pubkey exchange, `{"t":"_keyex","d":{"pk":"<b64>"}}`
//!   - `_enc`   : an ENCRYPTED game message, `{"t":"_enc","d":{"p":"<iv.ct>"}}`
//!
//! `send_raw(inner)` = `msg{ text: json_string(inner) }` — note `text` holds the
//! STRINGIFIED inner object, not a nested JSON object.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::VecDeque;
use tracing::{debug, trace};

use crate::crypto::Session;
use crate::relay::{RelayFrame, Transport};
use crate::srv::{self, ClientMsg, ServerMsg};

/// A decrypted inner game message: `{"t":..,"d":..}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameMsg {
    pub t: String,
    #[serde(default)]
    pub d: Value,
}

impl GameMsg {
    pub fn new(t: &str, d: Value) -> Self {
        Self { t: t.to_string(), d }
    }
}

/// Owns the transport + crypto session and drives the `_keyex` handshake, then
/// carries encrypted game messages.
pub struct Peer {
    pub transport: Transport,
    pub crypto: Session,
    /// our seat (0 = creator/host, 1 = joiner/guest), set after `joined`.
    pub seat: u8,
    /// whether we've already emitted our own `_keyex` (idempotent guard).
    keyex_sent: bool,
    pub nick: String,
    /// OUR session identity pubkey (64 hex) — announced in `seated` as `sessionPub`,
    /// pinned in the deposit memo, and used to sign settlement. `None` = anon/free.
    pub session_pub: Option<String>,
    /// the PEER's announced `sessionPub` (recorded from their `seated`), used to
    /// verify their settlement co-sign later. `None` until they announce it.
    pub peer_session_pub: Option<String>,
    /// inbound top-level `{"t":"srv","msg":..}` server frames, demuxed here so the
    /// game/paid loop can drain them without racing the E2EE peer channel.
    srv_inbox: VecDeque<ServerMsg>,
}

impl Peer {
    pub fn new(transport: Transport, nick: String) -> Self {
        Self {
            transport,
            crypto: Session::new(),
            seat: 0,
            keyex_sent: false,
            nick,
            session_pub: None,
            peer_session_pub: None,
            srv_inbox: VecDeque::new(),
        }
    }

    /// Set OUR session identity pubkey (announced as `sessionPub` in `seated`).
    pub fn set_session_pub(&mut self, pubkey_hex: String) {
        self.session_pub = Some(pubkey_hex);
    }

    /// Record the peer's announced `sessionPub` (from their `seated` handshake).
    pub fn record_peer_session_pub(&mut self, pubkey_hex: String) {
        self.peer_session_pub = Some(pubkey_hex);
    }

    /// Send a top-level `{"t":"srv","msg":<ClientMsg>}` relay frame. This is NOT
    /// E2EE-encrypted and NOT wrapped in a peer `msg` — the relay/escrow reads it
    /// directly (staked tables only). Mirrors the browser `transport.sendServer`.
    /// Live-paid-path plumbing: wired into the driver alongside the escrow infra.
    #[allow(dead_code)]
    pub async fn send_srv(&mut self, msg: ClientMsg) -> Result<()> {
        let frame = serde_json::json!({ "t": "srv", "msg": msg });
        let text = serde_json::to_string(&frame)?;
        trace!(seat = self.seat, "send_srv");
        self.transport.send(&RelayFrame::Raw { text }).await
    }

    /// Pop the next demuxed server frame if one has arrived, else `None` (non-blocking).
    /// Live-paid-path plumbing: drained by the driver alongside the escrow infra.
    #[allow(dead_code)]
    pub fn try_recv_srv(&mut self) -> Option<ServerMsg> {
        self.srv_inbox.pop_front()
    }

    /// Wrap an inner WireMessage into a relay `msg` frame (stringified `text`)
    /// and send it. Used for both plaintext `_keyex` and `_enc` envelopes.
    async fn send_raw(&mut self, inner: &Value) -> Result<()> {
        let text = serde_json::to_string(inner)?;
        self.transport.send(&RelayFrame::Msg { text, nick: String::new(), ts: 0 }).await
    }

    /// Send our ephemeral pubkey as a plaintext `_keyex`. Idempotent: at most
    /// once per side.
    async fn send_keyex(&mut self) -> Result<()> {
        if self.keyex_sent {
            return Ok(());
        }
        let inner = serde_json::json!({
            "t": "_keyex",
            "d": { "pk": self.crypto.public_b64() },
        });
        self.send_raw(&inner).await?;
        self.keyex_sent = true;
        debug!(seat = self.seat, "sent _keyex");
        Ok(())
    }

    /// Send an encrypted game message: encrypt the inner `{"t","d"}` string and
    /// wrap it as `_enc{ d:{ p:"iv.ct" }}`.
    pub async fn send_game(&mut self, msg: &GameMsg) -> Result<()> {
        let plaintext = serde_json::to_string(msg)?;
        let p = self.crypto.encrypt(&plaintext)?;
        let inner = serde_json::json!({ "t": "_enc", "d": { "p": p } });
        trace!(seat = self.seat, t = %msg.t, "send_game");
        self.send_raw(&inner).await
    }

    /// Establish the room + E2EE channel.
    ///
    /// `create == true`  → host: send `create`, wait for `created`, then `join`
    ///                     the fresh code (the relay does NOT seat the creator
    ///                     on `create` alone — it must join like everyone else,
    ///                     landing on seat 0 as the first joiner).
    /// `create == false` → guest: `join` the given `room` code (seat 1).
    ///
    /// After `joined`, runs the `_keyex` handshake until the shared AES key is
    /// derived. Returns the room code. Equivalent to `join_room` then
    /// `key_exchange`; the selfplay orchestrator calls those two separately so
    /// the host can hand the room code to the guest BEFORE blocking on keyex
    /// (otherwise host and guest deadlock — the host can't finish keyex until
    /// the guest joins, but the guest can't join without the code).
    pub async fn handshake(&mut self, create: bool, room: Option<String>) -> Result<String> {
        let code = self.join_room(create, room).await?;
        self.key_exchange().await?;
        Ok(code)
    }

    /// Establish room membership and learn our seat. Returns the room code.
    pub async fn join_room(&mut self, create: bool, room: Option<String>) -> Result<String> {
        // --- room membership -------------------------------------------------
        let room_code: String = if create {
            self.transport
                .send(&RelayFrame::Create { nick: self.nick.clone() })
                .await?;
            let code = loop {
                match self.transport.recv().await? {
                    RelayFrame::Created { room } => break room,
                    RelayFrame::Error { msg } => return Err(anyhow!("relay error on create: {msg}")),
                    other => trace!(?other, "ignoring pre-created frame"),
                }
            };
            debug!(room = %code, "room created");
            // creator now joins its own room to actually take seat 0.
            self.transport
                .send(&RelayFrame::Join { room: code.clone(), nick: self.nick.clone() })
                .await?;
            code
        } else {
            let code = room.ok_or_else(|| anyhow!("guest handshake needs a room code"))?;
            self.transport
                .send(&RelayFrame::Join { room: code.clone(), nick: self.nick.clone() })
                .await?;
            code
        };

        // --- wait for our own `joined` (learns our seat) ---------------------
        // Seat = the relay-provided value if present, else derived from our role:
        // the creator joins first (seat 0), the guest joins second (seat 1). The
        // production relay currently omits `seat`, so the role-derived value is
        // authoritative in practice.
        let role_seat = if create { 0 } else { 1 };
        loop {
            match self.transport.recv().await? {
                RelayFrame::Joined { seat, count, .. } => {
                    self.seat = seat.unwrap_or(role_seat);
                    debug!(seat = self.seat, count, room = %room_code, "joined");
                    break;
                }
                RelayFrame::Error { msg } => return Err(anyhow!("relay error on join: {msg}")),
                other => trace!(?other, "ignoring pre-joined frame"),
            }
        }

        Ok(room_code)
    }

    /// Run the `_keyex` handshake until the shared AES key is derived. Must be
    /// called after `join_room`.
    pub async fn key_exchange(&mut self) -> Result<()> {
        // Reliable order: the joiner (seat 1, guaranteed to have a peer present)
        // sends its `_keyex` immediately; the host (seat 0) sends its own only
        // in RESPONSE to the peer's `_keyex`, so it never lands "undelivered".
        // Both derive the key on receiving the peer's pubkey.
        if self.seat == 1 {
            self.send_keyex().await?;
        }

        while !self.crypto.ready() {
            match self.next_relay_inner().await? {
                Inner::Keyex { pk } => {
                    // host: respond with our keyex if we haven't yet.
                    self.send_keyex().await?;
                    self.crypto.derive(&pk).context("derive shared key from peer _keyex")?;
                    debug!(seat = self.seat, "shared key derived — E2EE ready");
                }
                Inner::Enc { .. } => {
                    // A game frame before our key is ready would be a protocol
                    // ordering bug for our own bots (both sides gate game msgs on
                    // E2EE). Surface it rather than silently dropping.
                    return Err(anyhow!("received _enc before key exchange completed"));
                }
                Inner::Undelivered => { /* peer not present yet; keep waiting */ }
                Inner::Ignore => {}
            }
        }

        Ok(())
    }

    /// Receive the next DECRYPTED game message. Transparently answers any late
    /// `_keyex` (idempotent) and skips relay control noise.
    pub async fn recv_game(&mut self) -> Result<GameMsg> {
        loop {
            match self.next_relay_inner().await? {
                Inner::Enc { p } => {
                    let plaintext = self.crypto.decrypt(&p).context("decrypt _enc payload")?;
                    let msg: GameMsg = serde_json::from_str(&plaintext)
                        .with_context(|| format!("parse decrypted game msg: {plaintext}"))?;
                    // ignore transport-reliability control frames the browser may
                    // emit (`_ack`), but our own bots never send them.
                    if msg.t == "_ack" {
                        continue;
                    }
                    trace!(seat = self.seat, t = %msg.t, "recv_game");
                    return Ok(msg);
                }
                Inner::Keyex { pk } => {
                    // a re-sent keyex (peer reconnect); re-derive, stay ready.
                    self.send_keyex().await?;
                    let _ = self.crypto.derive(&pk);
                }
                Inner::Undelivered => { /* transient; keep reading */ }
                Inner::Ignore => {}
            }
        }
    }

    /// Read the next relay frame and classify its inner content.
    async fn next_relay_inner(&mut self) -> Result<Inner> {
        loop {
            match self.transport.recv().await? {
                RelayFrame::Msg { text, nick, .. } => {
                    // Self-echo guard: the PRODUCTION relay forwards our own `msg`
                    // frames BACK to us (it does not skip the sender's channel),
                    // stamping our nick. Drop those — a frame we sent is never a
                    // peer message. Our nicks are random 8-hex, so this never
                    // eats a real peer frame. (An empty nick, e.g. the in-process
                    // ChannelTransport which already skips the sender, is kept.)
                    if !nick.is_empty() && nick == self.nick {
                        trace!("dropping self-echoed msg frame");
                        continue;
                    }
                    let inner: Value = serde_json::from_str(&text)
                        .with_context(|| format!("parse inner msg text: {text}"))?;
                    let t = inner.get("t").and_then(|v| v.as_str()).unwrap_or("");
                    match t {
                        "_keyex" => {
                            let pk = inner
                                .pointer("/d/pk")
                                .and_then(|v| v.as_str())
                                .ok_or_else(|| anyhow!("_keyex missing d.pk"))?
                                .to_string();
                            return Ok(Inner::Keyex { pk });
                        }
                        "_enc" => {
                            let p = inner
                                .pointer("/d/p")
                                .and_then(|v| v.as_str())
                                .ok_or_else(|| anyhow!("_enc missing d.p"))?
                                .to_string();
                            return Ok(Inner::Enc { p });
                        }
                        other => {
                            trace!(t = other, "ignoring unknown inner frame");
                            return Ok(Inner::Ignore);
                        }
                    }
                }
                RelayFrame::Srv { msg } => {
                    // Top-level server/escrow bridge frame. Type it and queue it for
                    // the paid-path driver to drain via `try_recv_srv`; it never
                    // disturbs the E2EE peer channel.
                    let sm = srv::parse_server_msg(&msg);
                    trace!(seat = self.seat, "queued srv ServerMsg");
                    self.srv_inbox.push_back(sm);
                    return Ok(Inner::Ignore);
                }
                RelayFrame::Undelivered { reason } => {
                    trace!(reason = %reason, "relay: undelivered");
                    return Ok(Inner::Undelivered);
                }
                RelayFrame::System { .. } | RelayFrame::Joined { .. } | RelayFrame::Other => {
                    return Ok(Inner::Ignore);
                }
                RelayFrame::Error { msg } => return Err(anyhow!("relay error: {msg}")),
                other => {
                    trace!(?other, "ignoring relay frame");
                    return Ok(Inner::Ignore);
                }
            }
        }
    }
}

/// Classified inner content of a relay `msg` (or a control frame).
enum Inner {
    Keyex { pk: String },
    Enc { p: String },
    Undelivered,
    Ignore,
}

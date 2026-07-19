//! Relay client — a thin async transport over the zkbtc.org blind relay.
//!
//! The relay speaks plain JSON text frames (see `poker-server/src/main.rs`
//! `handle_relay_socket`). Top-level frames the relay understands:
//!   send `{"t":"create","nick":..}`  -> recv `{"t":"created","room":<code>}`
//!   send `{"t":"join","room":..,"nick":..}` -> recv `{"t":"joined","room":..,"count":N,"seat":S}`
//!   send `{"t":"msg","text":<opaque>}` -> forwarded to the OTHER peer as
//!         `{"t":"msg","text":..,"nick":..,"ts":<ms>}`; sender gets
//!         `{"t":"undelivered","reason":"no_peer"|"peer_gone"}` if nobody heard it.
//!   send `{"t":"part"}` -> leave.
//!
//! IMPORTANT (verified against the live relay): the `create` handler only mints
//! the room and returns `created` — it does NOT seat the creator. BOTH peers
//! must then send `join`; seat = join order, so the creator (joining first) is
//! seat 0 and the joiner is seat 1. This mirrors the browser transport, which
//! re-joins on `created`.
//!
//! All peer-to-peer content (`_keyex`, `_enc`) travels INSIDE the `text` field
//! of a `msg` frame as a stringified inner JSON object.

use anyhow::{anyhow, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

/// A top-level relay frame, in either direction. We only model the fields we
/// use; unknown fields are ignored on decode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum RelayFrame {
    #[serde(rename = "create")]
    Create { nick: String },
    #[serde(rename = "created")]
    Created { room: String },
    #[serde(rename = "join")]
    Join { room: String, nick: String },
    #[serde(rename = "joined")]
    Joined {
        room: String,
        #[serde(default)]
        count: u32,
        /// Some deployed relays omit `seat` (older build) — derive it from our
        /// own create/join role in that case.
        #[serde(default)]
        seat: Option<u8>,
    },
    #[serde(rename = "msg")]
    Msg {
        text: String,
        #[serde(default)]
        nick: String,
        #[serde(default)]
        ts: u64,
    },
    #[serde(rename = "undelivered")]
    Undelivered {
        #[serde(default)]
        reason: String,
    },
    #[serde(rename = "system")]
    System {
        #[serde(default)]
        text: String,
    },
    #[serde(rename = "error")]
    Error {
        #[serde(default)]
        msg: String,
    },
    #[serde(rename = "part")]
    Part,
    /// catch-all so an unmodelled server frame (e.g. `srv`) doesn't kill the loop.
    #[serde(other)]
    Other,
}

/// Transport abstraction so the play logic can run over a real websocket OR an
/// in-process channel pair (used by the offline regression test). An enum
/// rather than a boxed trait keeps it allocation-free and dependency-free.
///
/// The `Channel` variant is only constructed by the `#[cfg(test)]` offline
/// proof, so a plain (non-test) build sees it as unused — allow that.
pub enum Transport {
    Ws(WsTransport),
    #[cfg_attr(not(test), allow(dead_code))]
    Channel(ChannelTransport),
}

impl Transport {
    pub async fn send(&mut self, frame: &RelayFrame) -> Result<()> {
        match self {
            Transport::Ws(t) => t.send(frame).await,
            Transport::Channel(t) => t.send(frame).await,
        }
    }

    pub async fn recv(&mut self) -> Result<RelayFrame> {
        match self {
            Transport::Ws(t) => t.recv().await,
            Transport::Channel(t) => t.recv().await,
        }
    }
}

/// Real websocket transport to the relay.
pub struct WsTransport {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl WsTransport {
    pub async fn connect(url: &str) -> Result<Self> {
        let (ws, _resp) = connect_async(url)
            .await
            .with_context(|| format!("ws connect to {url}"))?;
        Ok(Self { ws })
    }

    async fn send(&mut self, frame: &RelayFrame) -> Result<()> {
        let json = serde_json::to_string(frame)?;
        self.ws.send(Message::Text(json)).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<RelayFrame> {
        loop {
            let msg = self
                .ws
                .next()
                .await
                .ok_or_else(|| anyhow!("relay closed the connection"))??;
            match msg {
                Message::Text(t) => {
                    return serde_json::from_str::<RelayFrame>(&t)
                        .with_context(|| format!("decode relay frame: {t}"));
                }
                Message::Binary(_) => continue,
                Message::Ping(p) => {
                    self.ws.send(Message::Pong(p)).await.ok();
                    continue;
                }
                Message::Pong(_) => continue,
                Message::Close(_) => return Err(anyhow!("relay closed the connection")),
                Message::Frame(_) => continue,
            }
        }
    }
}

/// In-process transport that faithfully emulates the relay's blind-forward
/// semantics for exactly two peers, used by the offline `#[cfg(test)]` proof.
/// It forwards `msg` frames to the OTHER peer (re-stamping `nick`), answers
/// `create`/`join` locally, and never inspects the opaque `text`.
#[cfg_attr(not(test), allow(dead_code))]
pub struct ChannelTransport {
    nick: String,
    seat: u8,
    to_peer: mpsc::UnboundedSender<RelayFrame>,
    from_peer: mpsc::UnboundedReceiver<RelayFrame>,
    /// buffered control replies (created/joined) we owe ourselves.
    self_inbox: std::collections::VecDeque<RelayFrame>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ChannelTransport {
    /// Build a wired pair `(seat0, seat1)` sharing a synthetic room.
    pub fn pair(room: &str) -> (ChannelTransport, ChannelTransport) {
        let (a_tx, a_rx) = mpsc::unbounded_channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        let a = ChannelTransport {
            nick: String::new(),
            seat: 0,
            to_peer: b_tx,
            from_peer: a_rx,
            self_inbox: Default::default(),
        };
        let b = ChannelTransport {
            nick: String::new(),
            seat: 1,
            to_peer: a_tx,
            from_peer: b_rx,
            self_inbox: Default::default(),
        };
        let _ = room; // room code is cosmetic in-process
        (a, b)
    }

    async fn send(&mut self, frame: &RelayFrame) -> Result<()> {
        match frame {
            RelayFrame::Create { nick } => {
                self.nick = nick.clone();
                self.self_inbox
                    .push_back(RelayFrame::Created { room: "local".into() });
            }
            RelayFrame::Join { room, nick } => {
                self.nick = nick.clone();
                // seat is fixed by construction (0 or 1); count is best-effort.
                self.self_inbox.push_back(RelayFrame::Joined {
                    room: room.clone(),
                    count: (self.seat + 1) as u32,
                    seat: Some(self.seat),
                });
            }
            RelayFrame::Msg { text, .. } => {
                // forward to the other peer, stamping our nick like the relay.
                let _ = self.to_peer.send(RelayFrame::Msg {
                    text: text.clone(),
                    nick: self.nick.clone(),
                    ts: 0,
                });
            }
            RelayFrame::Part => {}
            _ => {}
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<RelayFrame> {
        if let Some(f) = self.self_inbox.pop_front() {
            return Ok(f);
        }
        self.from_peer
            .recv()
            .await
            .ok_or_else(|| anyhow!("channel peer gone"))
    }
}

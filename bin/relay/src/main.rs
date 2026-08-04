//! relay: dumb message relay following "Your Server as a Function"
//!
//! the relay is a Service[Req, Rep] = Req => Future[Rep].
//! rooms are the state. messages are opaque bytes.
//! filters handle cross-cutting concerns (rate limiting, logging, cors).
//! the relay does not parse, validate, or understand payloads.
//!
//! # architecture (Eriksen, 2013)
//!
//! ```text
//! Future   - tokio futures, composable async operations
//! Service  - Relay gRPC service: CreateRoom, JoinRoom, SendMessage
//! Filter   - tower middleware: tracing, cors, rate limiting
//! ```
//!
//! the relay is replaceable. any implementation of the proto works.
//! clients don't care if the relay is this binary, zidecar, or
//! something else. the proto is the interface.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use tokio::sync::{broadcast, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};
use tracing::info;

mod proto {
    tonic::include_proto!("relay.v1");
}
mod ws;

use proto::relay_server::{Relay, RelayServer};
use proto::*;

// ============================================================================
// Room state
// ============================================================================

const MAX_ROOMS: usize = 10_000;
/// Per-room storage budget. The relay is in-memory only, so this caps
/// per-room memory regardless of message count or size variance. When
/// a new message would push a room over budget, the oldest stored
/// messages are dropped one at a time until it fits.
///
/// 1 MiB is large enough for thousands of typical chat messages or
/// hundreds of FROST DKG / signing messages, and small enough that
/// MAX_ROOMS * MAX_ROOM_BYTES = ~10 GB worst case (which is fine for
/// a process with no persistence).
const MAX_ROOM_BYTES: usize = 1024 * 1024;
/// Approximate constant overhead per StoredMessage on top of the
/// payload bytes - accounts for sender_id, sequence, timestamp_ms and
/// Vec heap overhead. Used for computing the storage budget without
/// having to introspect heap allocations.
const MESSAGE_OVERHEAD_BYTES: usize = 80;
#[allow(dead_code)] // referenced by config for room expiry; not yet wired
const DEFAULT_TTL: Duration = Duration::from_secs(3600);

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone)]
pub(crate) struct StoredMessage {
    sender_id: Vec<u8>,
    payload: Vec<u8>,
    sequence: u64,
    timestamp_ms: u64,
}

#[derive(Clone)]
struct Participant {
    id: Vec<u8>,
}

#[derive(Clone)]
pub(crate) enum RoomBroadcast {
    Joined {
        participant_id: Vec<u8>,
        count: u32,
        max_participants: u32,
    },
    Left {
        participant_id: Vec<u8>,
        count: u32,
    },
    Message(StoredMessage),
    Closed(String),
    /// Forwarded zid-auth-v1 identity claim. Relay does not verify -
    /// clients do, under the zid-auth-v1 protocol. Carrying every
    /// field as Option so the relay does not enforce a particular
    /// announce schema; future protocol versions add fields without
    /// requiring a relay rebuild.
    Announce {
        v: Option<String>,
        server: Option<String>,
        pubkey: String,
        nick: Option<String>,
        ts: Option<u64>,
        sig: Option<String>,
    },
}

struct Room {
    code: String,
    max_participants: u32,
    /// TTL the room was created with; `None` = persistent. Expiry is
    /// sliding: every accepted message pushes `expires_at` out by `ttl`,
    /// so an active session (a >1h poker game, an ongoing FROST ceremony)
    /// is never killed mid-protocol by the wall clock.
    ttl: Option<Duration>,
    expires_at: RwLock<Option<Instant>>,
    participants: RwLock<Vec<Participant>>,
    messages: RwLock<Vec<StoredMessage>>,
    next_sequence: AtomicU64,
    tx: broadcast::Sender<RoomBroadcast>,
}

// ============================================================================
// Room manager
// ============================================================================

// ============================================================================
// Metrics (prometheus text exposition, no external deps)
// ============================================================================

#[derive(Default)]
pub(crate) struct Metrics {
    pub rooms_created: AtomicU64,
    pub joins: AtomicU64,
    pub leaves: AtomicU64,
    pub messages: AtomicU64,
    pub message_bytes: AtomicU64,
    pub rooms_expired: AtomicU64,
    pub grpc_streams_active: AtomicU64,
    pub ws_connections_active: AtomicU64,
    pub lagged_events: AtomicU64,
}

impl Metrics {
    fn c(&self, a: &AtomicU64) -> u64 {
        a.load(Ordering::Relaxed)
    }
}

pub(crate) struct RoomManager {
    rooms: RwLock<HashMap<String, Arc<Room>>>,
    pub(crate) metrics: Metrics,
}

impl RoomManager {
    fn new() -> Self {
        Self {
            rooms: RwLock::new(HashMap::new()),
            metrics: Metrics::default(),
        }
    }

    /// Render prometheus text-format metrics: monotonic counters plus
    /// point-in-time gauges computed from live room state.
    pub(crate) async fn render_metrics(&self) -> String {
        let rooms = self.rooms.read().await;
        let rooms_active = rooms.len();
        let mut participants_active = 0usize;
        let mut stored_messages = 0usize;
        for r in rooms.values() {
            participants_active += r.participants.read().await.len();
            stored_messages += r.messages.read().await.len();
        }
        drop(rooms);

        let m = &self.metrics;
        format!(
            "# HELP relay_rooms_active current number of rooms\n\
             # TYPE relay_rooms_active gauge\n\
             relay_rooms_active {rooms_active}\n\
             # HELP relay_participants_active participants across all rooms\n\
             # TYPE relay_participants_active gauge\n\
             relay_participants_active {participants_active}\n\
             # HELP relay_stored_messages messages held in room buffers\n\
             # TYPE relay_stored_messages gauge\n\
             relay_stored_messages {stored_messages}\n\
             # HELP relay_grpc_streams_active open JoinRoom gRPC streams\n\
             # TYPE relay_grpc_streams_active gauge\n\
             relay_grpc_streams_active {grpc}\n\
             # HELP relay_ws_connections_active open websocket connections\n\
             # TYPE relay_ws_connections_active gauge\n\
             relay_ws_connections_active {ws}\n\
             # HELP relay_rooms_created_total rooms created since start\n\
             # TYPE relay_rooms_created_total counter\n\
             relay_rooms_created_total {created}\n\
             # HELP relay_joins_total successful room joins\n\
             # TYPE relay_joins_total counter\n\
             relay_joins_total {joins}\n\
             # HELP relay_leaves_total participants removed from rooms\n\
             # TYPE relay_leaves_total counter\n\
             relay_leaves_total {leaves}\n\
             # HELP relay_messages_total messages relayed\n\
             # TYPE relay_messages_total counter\n\
             relay_messages_total {messages}\n\
             # HELP relay_message_bytes_total payload bytes relayed\n\
             # TYPE relay_message_bytes_total counter\n\
             relay_message_bytes_total {bytes}\n\
             # HELP relay_rooms_expired_total rooms swept by TTL cleanup\n\
             # TYPE relay_rooms_expired_total counter\n\
             relay_rooms_expired_total {expired}\n\
             # HELP relay_lagged_events_total broadcast events dropped on slow subscribers\n\
             # TYPE relay_lagged_events_total counter\n\
             relay_lagged_events_total {lagged}\n",
            rooms_active = rooms_active,
            participants_active = participants_active,
            stored_messages = stored_messages,
            grpc = m.c(&m.grpc_streams_active),
            ws = m.c(&m.ws_connections_active),
            created = m.c(&m.rooms_created),
            joins = m.c(&m.joins),
            leaves = m.c(&m.leaves),
            messages = m.c(&m.messages),
            bytes = m.c(&m.message_bytes),
            expired = m.c(&m.rooms_expired),
            lagged = m.c(&m.lagged_events),
        )
    }

    pub(crate) async fn create_room(
        &self,
        max_participants: u32,
        ttl_seconds: u32,
    ) -> Result<(String, u64), &'static str> {
        self.create_room_with_code(None, max_participants, ttl_seconds)
            .await
    }

    pub(crate) async fn create_room_with_code(
        &self,
        fixed_code: Option<String>,
        max_participants: u32,
        ttl_seconds: u32,
    ) -> Result<(String, u64), &'static str> {
        // Codes are looked up lowercased in get_room — normalize at creation
        // too, or a mixed-case fixed code becomes permanently unjoinable.
        let fixed_code = fixed_code.map(|c| c.to_lowercase());

        // Hold the write lock across the existence check AND the insert:
        // with a read-check/drop/write-insert sequence, two concurrent
        // creates could pick the same code and the second would silently
        // overwrite a live room, orphaning its participants.
        let mut rooms = self.rooms.write().await;
        if rooms.len() >= MAX_ROOMS {
            return Err("too many active rooms");
        }
        // if fixed code already exists, return it
        if let Some(ref c) = fixed_code {
            if rooms.contains_key(c) {
                return Ok((c.clone(), 0));
            }
        }

        let ttl = if ttl_seconds > 0 {
            Some(Duration::from_secs(ttl_seconds as u64))
        } else {
            None // persistent
        };

        let code = match fixed_code {
            Some(c) => c,
            None => {
                // regenerate on collision instead of clobbering a live room
                let mut attempts = 0;
                loop {
                    let c = generate_room_code();
                    if !rooms.contains_key(&c) {
                        break c;
                    }
                    attempts += 1;
                    if attempts > 16 {
                        return Err("room code space exhausted");
                    }
                }
            }
        };
        let expires_at = ttl.map(|t| Instant::now() + t);
        let expires_unix = ttl
            .map(|t| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + t.as_secs()
            })
            .unwrap_or(0);

        let (tx, _) = broadcast::channel(1024);
        let room = Arc::new(Room {
            code: code.clone(),
            max_participants: if max_participants == 0 {
                100
            } else {
                max_participants
            },
            ttl,
            expires_at: RwLock::new(expires_at),
            participants: RwLock::new(Vec::new()),
            messages: RwLock::new(Vec::new()),
            next_sequence: AtomicU64::new(0),
            tx,
        });

        rooms.insert(code.clone(), room);
        self.metrics.rooms_created.fetch_add(1, Ordering::Relaxed);
        Ok((code, expires_unix))
    }

    pub(crate) async fn get_room(&self, code: &str) -> Option<Arc<Room>> {
        let code = code.to_lowercase();
        let rooms = self.rooms.read().await;
        let room = rooms.get(&code)?;
        if let Some(exp) = *room.expires_at.read().await {
            if exp < Instant::now() {
                return None;
            }
        }
        Some(room.clone())
    }

    async fn join_room(
        &self,
        code: &str,
        participant_id: Vec<u8>,
    ) -> Result<Arc<Room>, &'static str> {
        let room = self
            .get_room(code)
            .await
            .ok_or("room not found or expired")?;

        let mut participants = room.participants.write().await;
        if participants.iter().any(|p| p.id == participant_id) {
            // Rejoin (reconnect with the same participant id): still
            // broadcast Joined so peers blocked on "waiting for player"
            // wake up — without this, a host waiting on the Joined event
            // never learns their opponent came back.
            let count = participants.len() as u32;
            drop(participants);
            let _ = room.tx.send(RoomBroadcast::Joined {
                participant_id,
                count,
                max_participants: room.max_participants,
            });
            return Ok(room);
        }
        if participants.len() >= room.max_participants as usize {
            return Err("room is full");
        }
        participants.push(Participant {
            id: participant_id.clone(),
        });
        let count = participants.len() as u32;
        drop(participants);
        self.metrics.joins.fetch_add(1, Ordering::Relaxed);

        let _ = room.tx.send(RoomBroadcast::Joined {
            participant_id,
            count,
            max_participants: room.max_participants,
        });

        Ok(room)
    }

    pub(crate) async fn leave_room(
        &self,
        code: &str,
        participant_id: Vec<u8>,
    ) -> Result<(), &'static str> {
        // get_room may return None if the room has expired or been GC'd
        // between the join and the leave. that's a normal case for a
        // disconnect path - just no-op rather than erroring.
        let Some(room) = self.get_room(code).await else {
            return Ok(());
        };
        let mut participants = room.participants.write().await;
        if let Some(pos) = participants.iter().position(|p| p.id == participant_id) {
            participants.remove(pos);
            let count = participants.len() as u32;
            drop(participants);
            self.metrics.leaves.fetch_add(1, Ordering::Relaxed);
            let _ = room.tx.send(RoomBroadcast::Left {
                participant_id,
                count,
            });
        }
        Ok(())
    }

    async fn send_message(
        &self,
        code: &str,
        sender_id: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<u64, &'static str> {
        let room = self
            .get_room(code)
            .await
            .ok_or("room not found or expired")?;

        let participants = room.participants.read().await;
        if !participants.iter().any(|p| p.id == sender_id) {
            return Err("sender not in room");
        }
        drop(participants);

        let mut messages = room.messages.write().await;

        // byte-budgeted eviction: drop oldest messages until the new
        // one fits within MAX_ROOM_BYTES. computed on demand because
        // sends are not in a hot loop.
        let msg_cost = |m: &StoredMessage| m.payload.len() + MESSAGE_OVERHEAD_BYTES;
        let new_cost = payload.len() + MESSAGE_OVERHEAD_BYTES;
        let mut total: usize = messages.iter().map(msg_cost).sum();
        while total + new_cost > MAX_ROOM_BYTES && !messages.is_empty() {
            let dropped = messages.remove(0);
            total -= msg_cost(&dropped);
        }

        let seq = room.next_sequence.fetch_add(1, Ordering::Relaxed);
        let msg = StoredMessage {
            sender_id,
            payload,
            sequence: seq,
            timestamp_ms: now_ms(),
        };
        messages.push(msg.clone());
        drop(messages);
        self.metrics.messages.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .message_bytes
            .fetch_add(msg.payload.len() as u64, Ordering::Relaxed);

        // sliding expiry: activity keeps the room alive for another ttl
        if let Some(t) = room.ttl {
            *room.expires_at.write().await = Some(Instant::now() + t);
        }

        let _ = room.tx.send(RoomBroadcast::Message(msg));
        Ok(seq)
    }

    pub(crate) async fn cleanup(&self) {
        let mut rooms = self.rooms.write().await;
        let now = Instant::now();
        let mut expired: Vec<String> = Vec::new();
        for (k, r) in rooms.iter() {
            if r.expires_at.read().await.is_some_and(|e| e < now) {
                expired.push(k.clone());
            }
        }
        for code in &expired {
            if let Some(room) = rooms.remove(code) {
                let _ = room.tx.send(RoomBroadcast::Closed("expired".into()));
            }
        }
        if !expired.is_empty() {
            self.metrics
                .rooms_expired
                .fetch_add(expired.len() as u64, Ordering::Relaxed);
            info!("cleaned up {} expired rooms", expired.len());
        }
    }
}

// ============================================================================
// Room code generation
// ============================================================================

const WORDS: &[&str] = &[
    "ace", "bet", "bid", "box", "cap", "cut", "dab", "den", "dip", "dot", "dry", "dub", "dug",
    "elm", "fan", "fig", "fin", "fit", "fix", "fog", "fun", "gap", "gem", "gin", "gum", "gut",
    "hex", "hip", "hit", "hog", "hot", "hub", "hue", "hum", "ice", "imp", "ink", "inn", "ion",
    "ivy", "jab", "jam", "jar", "jaw", "jet", "jig", "jog", "joy", "jug", "keg", "key", "kid",
    "kit", "lab", "lap", "law", "log", "lot", "low", "lux", "map", "mat", "max", "mix", "mob",
    "mod", "mop", "mud", "mug", "nap", "net", "nip", "nod", "nor", "not", "now", "nut", "oak",
    "oar", "odd", "opt", "orb", "ore", "owl", "own", "pad", "pan", "paw", "peg", "pen", "pet",
    "pie", "pig", "pin", "pit", "pod", "pop", "pot", "pug", "put", "rag", "ram", "ran", "rap",
    "raw", "ray", "red", "ref", "rib", "rid", "rig", "rim", "rip", "rob", "rod", "rot", "row",
    "rug", "rum", "run", "rut", "rye", "sap", "saw", "set", "sew", "shy", "sin", "sip", "sit",
    "six", "ski", "sky", "sly", "sob", "sod", "son", "sow", "spy", "sub", "sue", "sum", "sun",
    "sup", "tab", "tag", "tan", "tap", "tar", "tax", "ten", "the", "tie", "tin", "tip", "toe",
    "ton", "too", "top", "tow", "try", "tub", "tug", "two", "urn", "van", "vat", "vet", "via",
    "vim", "vow", "wag", "war", "was", "wax", "way", "web", "wed", "wet", "who", "wig", "win",
    "wit", "woe", "wok", "won", "wry", "yak", "yam", "yap", "yaw", "yep", "yet", "yew", "yin",
    "zip", "zoo",
];

fn generate_room_code() -> String {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    let w: Vec<&str> = WORDS.choose_multiple(&mut rng, 3).copied().collect();
    format!("{}-{}-{}", w[0], w[1], w[2])
}

// ============================================================================
// gRPC Service: Relay
// ============================================================================

struct RelayService {
    manager: Arc<RoomManager>,
}

impl RelayService {
    fn new(manager: Arc<RoomManager>) -> Self {
        Self { manager }
    }
}

/// Removes the participant from the room when the JoinRoom response stream
/// is dropped (client disconnect, cancelled RPC, connection reset). Without
/// this, gRPC disconnects never free room slots: a room fills up with ghost
/// participants until "room is full" bricks it for everyone.
struct LeaveOnDrop {
    manager: Arc<RoomManager>,
    code: String,
    participant_id: Vec<u8>,
}

impl Drop for LeaveOnDrop {
    fn drop(&mut self) {
        self.manager
            .metrics
            .grpc_streams_active
            .fetch_sub(1, Ordering::Relaxed);
        let manager = self.manager.clone();
        let code = std::mem::take(&mut self.code);
        let id = std::mem::take(&mut self.participant_id);
        // Drop is sync; the cleanup is async. The stream is always dropped
        // on a tokio worker, but guard with try_current so an off-runtime
        // drop degrades to a leak instead of a panic.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = manager.leave_room(&code, id).await;
            });
        }
    }
}

#[tonic::async_trait]
impl Relay for RelayService {
    async fn create_room(
        &self,
        request: Request<CreateRoomRequest>,
    ) -> Result<Response<CreateRoomResponse>, Status> {
        let req = request.into_inner();
        let (code, expires_at) = self
            .manager
            .create_room(req.max_participants, req.ttl_seconds)
            .await
            .map_err(Status::resource_exhausted)?;

        info!(
            "room created: {} (max={}, ttl={}s)",
            code, req.max_participants, req.ttl_seconds
        );

        Ok(Response::new(CreateRoomResponse {
            room_code: code,
            expires_at,
        }))
    }

    type JoinRoomStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<RoomEvent, Status>> + Send>>;

    async fn join_room(
        &self,
        request: Request<JoinRoomRequest>,
    ) -> Result<Response<Self::JoinRoomStream>, Status> {
        let req = request.into_inner();
        let room = self
            .manager
            .join_room(&req.room_code, req.participant_id.clone())
            .await
            .map_err(Status::not_found)?;

        info!(
            "joined: {} ({}...)",
            room.code,
            hex::encode(&req.participant_id[..4.min(req.participant_id.len())])
        );

        let existing_participants = room.participants.read().await.clone();
        let existing_messages = room.messages.read().await.clone();
        let rx = room.tx.subscribe();
        let max = room.max_participants;
        self.manager
            .metrics
            .grpc_streams_active
            .fetch_add(1, Ordering::Relaxed);
        let leave_guard = LeaveOnDrop {
            manager: self.manager.clone(),
            code: req.room_code.clone(),
            participant_id: req.participant_id.clone(),
        };
        let manager_for_stream = self.manager.clone();

        let stream = async_stream::stream! {
            // owned by the stream: dropping the stream leaves the room
            let _leave_guard = leave_guard;
            // replay existing participants
            for (i, p) in existing_participants.iter().enumerate() {
                yield Ok(RoomEvent {
                    event: Some(room_event::Event::Joined(ParticipantJoined {
                        participant_id: p.id.clone(),
                        participant_count: (i + 1) as u32,
                        max_participants: max,
                    })),
                });
            }

            // replay stored messages
            for msg in &existing_messages {
                yield Ok(RoomEvent {
                    event: Some(room_event::Event::Message(RelayedMessage {
                        sender_id: msg.sender_id.clone(),
                        payload: msg.payload.clone(),
                        sequence: msg.sequence,
                        timestamp_ms: msg.timestamp_ms,
                    })),
                });
            }

            // live events
            let mut stream = BroadcastStream::new(rx);
            use tokio_stream::StreamExt;
            while let Some(result) = stream.next().await {
                match result {
                    Ok(RoomBroadcast::Joined { participant_id, count, max_participants }) => {
                        yield Ok(RoomEvent {
                            event: Some(room_event::Event::Joined(ParticipantJoined {
                                participant_id,
                                participant_count: count,
                                max_participants,
                            })),
                        });
                    }
                    Ok(RoomBroadcast::Left { participant_id, count }) => {
                        yield Ok(RoomEvent {
                            event: Some(room_event::Event::Left(ParticipantLeft {
                                participant_id,
                                participant_count: count,
                            })),
                        });
                    }
                    Ok(RoomBroadcast::Message(msg)) => {
                        yield Ok(RoomEvent {
                            event: Some(room_event::Event::Message(RelayedMessage {
                                sender_id: msg.sender_id,
                                payload: msg.payload,
                                sequence: msg.sequence,
                                timestamp_ms: msg.timestamp_ms,
                            })),
                        });
                    }
                    Ok(RoomBroadcast::Announce { .. }) => {
                        // gRPC subscribers do not currently receive
                        // zid-auth-v1 announces - they're a chat-layer
                        // (websocket) concern. proto extension is left
                        // for a future iteration if a gRPC client
                        // needs them.
                    }
                    Ok(RoomBroadcast::Closed(reason)) => {
                        yield Ok(RoomEvent {
                            event: Some(room_event::Event::Closed(RoomClosed { reason })),
                        });
                        break;
                    }
                    Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                        // Subscriber fell behind the broadcast buffer. This
                        // is message loss, not room closure — closing here
                        // turned transient lag into a fatal disconnect.
                        // Skip ahead; messages remain in room storage, and
                        // a client that detects a sequence gap can rejoin
                        // to replay them.
                        tracing::warn!("subscriber lagged, skipped {} events", n);
                        manager_for_stream.metrics.lagged_events.fetch_add(n, Ordering::Relaxed);
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    async fn send_message(
        &self,
        request: Request<SendMessageRequest>,
    ) -> Result<Response<SendMessageResponse>, Status> {
        let req = request.into_inner();
        let seq = self
            .manager
            .send_message(&req.room_code, req.sender_id, req.payload)
            .await
            .map_err(Status::failed_precondition)?;

        Ok(Response::new(SendMessageResponse { sequence: seq }))
    }
}

// ============================================================================
// Main: filters andThen service
// ============================================================================

#[derive(Parser)]
#[command(
    name = "relay",
    about = "dumb relay. rooms, participants, opaque bytes."
)]
struct Args {
    /// gRPC listen address
    #[arg(long, default_value = "0.0.0.0:50052", env = "RELAY_LISTEN")]
    listen: std::net::SocketAddr,
    /// WebSocket listen address (for browser clients)
    #[arg(long, default_value = "0.0.0.0:50053", env = "RELAY_WS_LISTEN")]
    ws_listen: std::net::SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "relay=info".into()),
        )
        .init();

    let args = Args::parse();

    // shared room manager
    let manager = Arc::new(RoomManager::new());

    // background cleanup
    let manager_bg = manager.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            manager_bg.cleanup().await;
        }
    });

    info!("relay gRPC on {}", args.listen);
    info!("relay WS   on {}", args.ws_listen);
    info!("policy: opaque bytes, no parsing, no validation");

    // gRPC server
    let grpc_manager = manager.clone();
    let grpc_task = tokio::spawn(async move {
        let service = RelayService::new(grpc_manager);
        let relay_server = RelayServer::new(service);
        tonic::transport::Server::builder()
            .accept_http1(true)
            // h2 keepalives so long-lived JoinRoom streams survive idle
            // periods through proxies, and dead peers are detected instead
            // of holding room slots until the next write fails.
            .http2_keepalive_interval(Some(Duration::from_secs(30)))
            .http2_keepalive_timeout(Some(Duration::from_secs(20)))
            .layer(tower_http::trace::TraceLayer::new_for_grpc())
            .add_service(tonic_web::enable(relay_server))
            .serve(args.listen)
            .await
            .expect("gRPC server failed");
    });

    // WebSocket server
    let ws_manager = manager.clone();
    let ws_task = tokio::spawn(async move {
        let app = ws::ws_router(ws_manager);
        let listener = tokio::net::TcpListener::bind(args.ws_listen)
            .await
            .expect("WS bind failed");
        axum::serve(listener, app).await.expect("WS server failed");
    });

    tokio::select! {
        _ = grpc_task => {}
        _ = ws_task => {}
    }

    Ok(())
}

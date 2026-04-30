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
const MAX_MESSAGES_PER_ROOM: usize = 10_000;
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
}

struct Room {
    code: String,
    max_participants: u32,
    expires_at: Option<Instant>,
    participants: RwLock<Vec<Participant>>,
    messages: RwLock<Vec<StoredMessage>>,
    next_sequence: AtomicU64,
    tx: broadcast::Sender<RoomBroadcast>,
}

// ============================================================================
// Room manager
// ============================================================================

pub(crate) struct RoomManager {
    rooms: RwLock<HashMap<String, Arc<Room>>>,
}

impl RoomManager {
    fn new() -> Self {
        Self {
            rooms: RwLock::new(HashMap::new()),
        }
    }

    pub(crate) async fn create_room(
        &self,
        max_participants: u32,
        ttl_seconds: u32,
    ) -> Result<(String, u64), &'static str> {
        self.create_room_with_code(None, max_participants, ttl_seconds).await
    }

    pub(crate) async fn create_room_with_code(
        &self,
        fixed_code: Option<String>,
        max_participants: u32,
        ttl_seconds: u32,
    ) -> Result<(String, u64), &'static str> {
        let rooms = self.rooms.read().await;
        if rooms.len() >= MAX_ROOMS {
            return Err("too many active rooms");
        }
        // if fixed code already exists, return it
        if let Some(ref c) = fixed_code {
            if rooms.contains_key(c) {
                return Ok((c.clone(), 0));
            }
        }
        drop(rooms);

        let ttl = if ttl_seconds > 0 {
            Some(Duration::from_secs(ttl_seconds as u64))
        } else {
            None // persistent
        };

        let code = fixed_code.unwrap_or_else(generate_room_code);
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

        let (tx, _) = broadcast::channel(256);
        let room = Arc::new(Room {
            code: code.clone(),
            max_participants: if max_participants == 0 {
                100
            } else {
                max_participants
            },
            expires_at,
            participants: RwLock::new(Vec::new()),
            messages: RwLock::new(Vec::new()),
            next_sequence: AtomicU64::new(0),
            tx,
        });

        self.rooms.write().await.insert(code.clone(), room);
        Ok((code, expires_unix))
    }

    pub(crate) async fn get_room(&self, code: &str) -> Option<Arc<Room>> {
        let code = code.to_lowercase();
        let rooms = self.rooms.read().await;
        let room = rooms.get(&code)?;
        if let Some(exp) = room.expires_at {
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
            return Ok(room.clone());
        }
        if participants.len() >= room.max_participants as usize {
            return Err("room is full");
        }
        participants.push(Participant {
            id: participant_id.clone(),
        });
        let count = participants.len() as u32;
        drop(participants);

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
        if messages.len() >= MAX_MESSAGES_PER_ROOM {
            let drain_count = MAX_MESSAGES_PER_ROOM / 10;
            messages.drain(..drain_count);
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

        let _ = room.tx.send(RoomBroadcast::Message(msg));
        Ok(seq)
    }

    pub(crate) async fn cleanup(&self) {
        let mut rooms = self.rooms.write().await;
        let now = Instant::now();
        let expired: Vec<String> = rooms
            .iter()
            .filter(|(_, r)| r.expires_at.is_some_and(|e| e < now))
            .map(|(k, _)| k.clone())
            .collect();
        for code in &expired {
            if let Some(room) = rooms.remove(code) {
                let _ = room.tx.send(RoomBroadcast::Closed("expired".into()));
            }
        }
        if !expired.is_empty() {
            info!("cleaned up {} expired rooms", expired.len());
        }
    }
}

// ============================================================================
// Room code generation
// ============================================================================

const WORDS: &[&str] = &[
    "ace", "bet", "bid", "box", "cap", "cut", "dab", "den", "dip",
    "dot", "dry", "dub", "dug", "elm", "fan", "fig", "fin", "fit",
    "fix", "fog", "fun", "gap", "gem", "gin", "gum", "gut", "hex",
    "hip", "hit", "hog", "hot", "hub", "hue", "hum", "ice", "imp",
    "ink", "inn", "ion", "ivy", "jab", "jam", "jar", "jaw", "jet",
    "jig", "jog", "joy", "jug", "keg", "key", "kid", "kit", "lab",
    "lap", "law", "log", "lot", "low", "lux", "map", "mat", "max",
    "mix", "mob", "mod", "mop", "mud", "mug", "nap", "net", "nip",
    "nod", "nor", "not", "now", "nut", "oak", "oar", "odd", "opt",
    "orb", "ore", "owl", "own", "pad", "pan", "paw", "peg", "pen",
    "pet", "pie", "pig", "pin", "pit", "pod", "pop", "pot", "pug",
    "put", "rag", "ram", "ran", "rap", "raw", "ray", "red", "ref",
    "rib", "rid", "rig", "rim", "rip", "rob", "rod", "rot", "row",
    "rug", "rum", "run", "rut", "rye", "sap", "saw", "set", "sew",
    "shy", "sin", "sip", "sit", "six", "ski", "sky", "sly", "sob",
    "sod", "son", "sow", "spy", "sub", "sue", "sum", "sun", "sup",
    "tab", "tag", "tan", "tap", "tar", "tax", "ten", "the", "tie",
    "tin", "tip", "toe", "ton", "too", "top", "tow", "try", "tub",
    "tug", "two", "urn", "van", "vat", "vet", "via", "vim", "vow",
    "wag", "war", "was", "wax", "way", "web", "wed", "wet", "who",
    "wig", "win", "wit", "woe", "wok", "won", "wry", "yak", "yam",
    "yap", "yaw", "yep", "yet", "yew", "yin", "zip", "zoo",
];

fn generate_room_code() -> String {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    let w: Vec<&str> = WORDS
        .choose_multiple(&mut rng, 3)
        .copied()
        .collect();
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

        info!("room created: {} (max={}, ttl={}s)",
            code, req.max_participants, req.ttl_seconds);

        Ok(Response::new(CreateRoomResponse {
            room_code: code,
            expires_at,
        }))
    }

    type JoinRoomStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<RoomEvent, Status>> + Send>,
    >;

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

        info!("joined: {} ({}...)", room.code,
            hex::encode(&req.participant_id[..4.min(req.participant_id.len())]));

        let existing_participants = room.participants.read().await.clone();
        let existing_messages = room.messages.read().await.clone();
        let rx = room.tx.subscribe();
        let max = room.max_participants;

        let stream = async_stream::stream! {
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
                    Ok(RoomBroadcast::Closed(reason)) => {
                        yield Ok(RoomEvent {
                            event: Some(room_event::Event::Closed(RoomClosed { reason })),
                        });
                        break;
                    }
                    Err(_) => {
                        yield Ok(RoomEvent {
                            event: Some(room_event::Event::Closed(RoomClosed {
                                reason: "room closed".into(),
                            })),
                        });
                        break;
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
#[command(name = "relay", about = "dumb relay. rooms, participants, opaque bytes.")]
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
        axum::serve(listener, app)
            .await
            .expect("WS server failed");
    });

    tokio::select! {
        _ = grpc_task => {}
        _ = ws_task => {}
    }

    Ok(())
}

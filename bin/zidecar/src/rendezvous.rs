//! rendezvous — human-friendly room codes in front of frostd sessions.
//!
//! frostd fixes a session's participants at creation and addresses the
//! session by a server-minted uuid. Correct, and miserable to use: everyone
//! must swap relay public keys out of band, then the coordinator must get a
//! uuid to everyone, before anything can start. The old zafu relay had a
//! three-word room code — one short string to share — and that is the UX
//! this restores, without restoring its hole (code = admission).
//!
//! The rendezvous is DISCOVERY ONLY. It never admits anyone to anything:
//!
//!   1. the coordinator picks a human code and everyone derives
//!      room = SHA-256(code) client-side — the server never sees the code
//!   2. participants publish their relay public keys into the room
//!   3. the coordinator polls, sees the keys arrive, and EXPLICITLY
//!      APPROVES the set before creating the real frostd session with it
//!   4. the coordinator announces the frostd session uuid into the room;
//!      joiners poll it out and proceed on plain frostd
//!
//! Someone who guesses the code can offer a pubkey and read the others —
//! metadata frostd's own login already shows a listener — but cannot join a
//! ceremony unless a human coordinator approves an unexpected key, and
//! cannot redirect the room: announcing takes the creator token minted when
//! the room was first published into.
//!
//! State is in-memory and expires; there is nothing to persist. Upstream's
//! nine frostd endpoints are untouched — this router is merged alongside.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

/// Rooms live this long after creation. A ceremony's discovery phase is
/// minutes; an hour of slack covers time-zone fumbling without letting
/// abandoned rooms accumulate meaningfully.
const ROOM_TTL: Duration = Duration::from_secs(60 * 60);
/// Ceiling on concurrent rooms — a memory bound, far above legitimate use.
const MAX_ROOMS: usize = 1024;
/// FROST tops out far below this; it bounds a hostile publisher, not a user.
const MAX_ENTRIES: usize = 16;
/// Relay pubkeys are 32-byte points, hex-encoded.
const PUBKEY_HEX_LEN: usize = 64;
/// Free-form label a participant attaches to their key ("alice's laptop").
const MAX_NOTE_LEN: usize = 256;
/// frostd session ids are uuids; anything longer is not one.
const MAX_SESSION_ID_LEN: usize = 64;
/// Global request budget per second. Discovery traffic is a handful of
/// publishes and ~1 Hz polling per participant; this is two orders above
/// that, and low enough to make scanning the code space a joke.
const MAX_REQUESTS_PER_SEC: u32 = 100;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct Entry {
    /// hex relay public key — what frostd will list at session creation
    pubkey: String,
    /// participant-chosen label, opaque to the server
    #[serde(default)]
    note: String,
}

struct Room {
    created: Instant,
    /// minted for whoever publishes first; announcing requires it
    creator_token: String,
    entries: Vec<Entry>,
    /// set by announce: the frostd session uuid joiners proceed with
    session_id: Option<String>,
}

struct Limiter {
    window: Instant,
    count: u32,
}

pub struct RendezvousState {
    rooms: Mutex<HashMap<String, Room>>,
    limiter: Mutex<Limiter>,
}

impl RendezvousState {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            rooms: Mutex::new(HashMap::new()),
            limiter: Mutex::new(Limiter {
                window: Instant::now(),
                count: 0,
            }),
        })
    }

    fn over_budget(&self) -> bool {
        let mut l = self.limiter.lock().expect("limiter lock");
        let now = Instant::now();
        if now.duration_since(l.window) >= Duration::from_secs(1) {
            l.window = now;
            l.count = 0;
        }
        l.count += 1;
        l.count > MAX_REQUESTS_PER_SEC
    }
}

pub fn router(state: std::sync::Arc<RendezvousState>) -> Router {
    Router::new()
        .route("/rendezvous/publish", post(publish))
        .route("/rendezvous/poll", post(poll))
        .route("/rendezvous/announce", post(announce))
        .with_state(state)
}

type Rejection = (StatusCode, Json<serde_json::Value>);

fn bad(code: StatusCode, msg: &str) -> Rejection {
    (code, Json(serde_json::json!({ "error": msg })))
}

/// A room id is the client-side SHA-256 of the human code: exactly 64 hex.
/// Enforced so the map cannot be grown with arbitrary-length keys.
fn checked_room_id(room: &str) -> Result<String, Rejection> {
    if room.len() != 64 || !room.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad(StatusCode::BAD_REQUEST, "room must be 64 hex chars"));
    }
    Ok(room.to_ascii_lowercase())
}

fn gc(rooms: &mut HashMap<String, Room>) {
    let now = Instant::now();
    rooms.retain(|_, r| now.duration_since(r.created) < ROOM_TTL);
}

#[derive(Deserialize)]
struct PublishReq {
    room: String,
    pubkey: String,
    #[serde(default)]
    note: String,
}

#[derive(Serialize)]
struct PublishResp {
    /// present only when this publish created the room — the coordinator
    /// keeps it and presents it to announce
    #[serde(skip_serializing_if = "Option::is_none")]
    creator_token: Option<String>,
}

async fn publish(
    State(state): State<std::sync::Arc<RendezvousState>>,
    Json(req): Json<PublishReq>,
) -> Result<Json<PublishResp>, Rejection> {
    if state.over_budget() {
        return Err(bad(StatusCode::TOO_MANY_REQUESTS, "rendezvous is busy"));
    }
    let room_id = checked_room_id(&req.room)?;
    if req.pubkey.len() != PUBKEY_HEX_LEN || !req.pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad(StatusCode::BAD_REQUEST, "pubkey must be 64 hex chars"));
    }
    if req.note.len() > MAX_NOTE_LEN {
        return Err(bad(StatusCode::BAD_REQUEST, "note too long"));
    }
    let entry = Entry {
        pubkey: req.pubkey.to_ascii_lowercase(),
        note: req.note,
    };

    let mut rooms = state.rooms.lock().expect("rooms lock");
    gc(&mut rooms);

    if let Some(room) = rooms.get_mut(&room_id) {
        // re-publishing the same key refreshes its note rather than piling up
        if let Some(existing) = room.entries.iter_mut().find(|e| e.pubkey == entry.pubkey) {
            existing.note = entry.note;
        } else {
            if room.entries.len() >= MAX_ENTRIES {
                return Err(bad(StatusCode::CONFLICT, "room is full"));
            }
            room.entries.push(entry);
        }
        return Ok(Json(PublishResp {
            creator_token: None,
        }));
    }

    if rooms.len() >= MAX_ROOMS {
        return Err(bad(StatusCode::TOO_MANY_REQUESTS, "too many rooms"));
    }
    // token from the OS rng; it gates announce, nothing more
    let token: [u8; 16] = rand::random();
    let creator_token = hex::encode(token);
    rooms.insert(
        room_id,
        Room {
            created: Instant::now(),
            creator_token: creator_token.clone(),
            entries: vec![entry],
            session_id: None,
        },
    );
    Ok(Json(PublishResp {
        creator_token: Some(creator_token),
    }))
}

#[derive(Deserialize)]
struct PollReq {
    room: String,
}

#[derive(Serialize)]
struct PollResp {
    entries: Vec<Entry>,
    session_id: Option<String>,
}

async fn poll(
    State(state): State<std::sync::Arc<RendezvousState>>,
    Json(req): Json<PollReq>,
) -> Result<Json<PollResp>, Rejection> {
    if state.over_budget() {
        return Err(bad(StatusCode::TOO_MANY_REQUESTS, "rendezvous is busy"));
    }
    let room_id = checked_room_id(&req.room)?;
    let mut rooms = state.rooms.lock().expect("rooms lock");
    gc(&mut rooms);
    // an unknown room polls as empty, same as one nobody has published into
    let (entries, session_id) = rooms
        .get(&room_id)
        .map(|r| (r.entries.clone(), r.session_id.clone()))
        .unwrap_or_default();
    Ok(Json(PollResp {
        entries,
        session_id,
    }))
}

#[derive(Deserialize)]
struct AnnounceReq {
    room: String,
    creator_token: String,
    session_id: String,
}

async fn announce(
    State(state): State<std::sync::Arc<RendezvousState>>,
    Json(req): Json<AnnounceReq>,
) -> Result<Json<serde_json::Value>, Rejection> {
    if state.over_budget() {
        return Err(bad(StatusCode::TOO_MANY_REQUESTS, "rendezvous is busy"));
    }
    let room_id = checked_room_id(&req.room)?;
    if req.session_id.is_empty() || req.session_id.len() > MAX_SESSION_ID_LEN {
        return Err(bad(StatusCode::BAD_REQUEST, "bad session id"));
    }
    let mut rooms = state.rooms.lock().expect("rooms lock");
    gc(&mut rooms);
    let room = rooms
        .get_mut(&room_id)
        .ok_or_else(|| bad(StatusCode::NOT_FOUND, "no such room"))?;
    // constant-time comparison is not needed: the token is single-use-ish,
    // 128-bit, and expires with the room — but it costs nothing either
    if !subtle_eq(room.creator_token.as_bytes(), req.creator_token.as_bytes()) {
        return Err(bad(StatusCode::FORBIDDEN, "not the room creator"));
    }
    room.session_id = Some(req.session_id);
    Ok(Json(serde_json::json!({})))
}

/// Length-then-bytes comparison without early exit on content.
fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

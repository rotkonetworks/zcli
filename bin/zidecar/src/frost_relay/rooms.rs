// room state management for FROST relay.
// rooms are ephemeral, in-memory, auto-expiring.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, RwLock};

use super::wordlist;

const MAX_ROOMS: usize = 1000;
const MAX_MESSAGES_PER_ROOM: usize = 256;
const DEFAULT_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct StoredMessage {
    pub sender_id: Vec<u8>,
    pub payload: Vec<u8>,
    pub sequence: u64,
}

#[derive(Clone)]
pub enum RoomBroadcast {
    Joined {
        participant_id: Vec<u8>,
        count: u32,
        max_signers: u32,
    },
    Message(StoredMessage),
    Closed(String),
}

pub struct Room {
    pub code: String,
    pub max_signers: u32,
    pub threshold: u32,
    pub expires_at: Instant,
    pub participants: RwLock<Vec<Vec<u8>>>,
    pub messages: RwLock<Vec<StoredMessage>>,
    pub next_sequence: AtomicU64,
    pub tx: broadcast::Sender<RoomBroadcast>,
}

pub struct RoomManager {
    rooms: RwLock<HashMap<String, Arc<Room>>>,
}

impl RoomManager {
    pub fn new() -> Self {
        Self {
            rooms: RwLock::new(HashMap::new()),
        }
    }

    pub async fn create_room(
        &self,
        threshold: u32,
        max_signers: u32,
        ttl_seconds: u32,
    ) -> Result<(String, u64), &'static str> {
        let rooms = self.rooms.read().await;
        if rooms.len() >= MAX_ROOMS {
            return Err("too many active rooms");
        }
        drop(rooms);

        let ttl = if ttl_seconds > 0 {
            Duration::from_secs(ttl_seconds as u64)
        } else {
            DEFAULT_TTL
        };

        // generate unique code (retry on collision)
        let mut code;
        loop {
            code = wordlist::generate_room_code();
            let rooms = self.rooms.read().await;
            if !rooms.contains_key(&code) {
                break;
            }
        }

        let expires_at = Instant::now() + ttl;
        let expires_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + ttl.as_secs();

        let (tx, _) = broadcast::channel(64);
        let room = Arc::new(Room {
            code: code.clone(),
            max_signers,
            threshold,
            expires_at,
            participants: RwLock::new(Vec::new()),
            messages: RwLock::new(Vec::new()),
            next_sequence: AtomicU64::new(0),
            tx,
        });

        self.rooms.write().await.insert(code.clone(), room);
        Ok((code, expires_unix))
    }

    pub async fn get_room(&self, code: &str) -> Option<Arc<Room>> {
        let code = code.to_lowercase();
        let rooms = self.rooms.read().await;
        let room = rooms.get(&code)?;
        if room.expires_at < Instant::now() {
            return None;
        }
        Some(room.clone())
    }

    pub async fn join_room(
        &self,
        code: &str,
        participant_id: Vec<u8>,
    ) -> Result<Arc<Room>, &'static str> {
        let room = self.get_room(code).await.ok_or("room not found or expired")?;

        let mut participants = room.participants.write().await;
        if participants.iter().any(|p| p == &participant_id) {
            // already joined, allow reconnect
            return Ok(room.clone());
        }
        if participants.len() >= room.max_signers as usize {
            return Err("room is full");
        }
        participants.push(participant_id.clone());
        let count = participants.len() as u32;
        drop(participants);

        // broadcast join event (ignore send errors — no subscribers yet is fine)
        let _ = room.tx.send(RoomBroadcast::Joined {
            participant_id,
            count,
            max_signers: room.max_signers,
        });

        Ok(room)
    }

    pub async fn send_message(
        &self,
        code: &str,
        sender_id: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<u64, &'static str> {
        let room = self.get_room(code).await.ok_or("room not found or expired")?;

        // verify sender is a participant
        let participants = room.participants.read().await;
        if !participants.iter().any(|p| p == &sender_id) {
            return Err("sender not in room");
        }
        drop(participants);

        let mut messages = room.messages.write().await;
        if messages.len() >= MAX_MESSAGES_PER_ROOM {
            return Err("room message limit reached");
        }
        let seq = room.next_sequence.fetch_add(1, Ordering::Relaxed);
        let msg = StoredMessage {
            sender_id: sender_id.clone(),
            payload: payload.clone(),
            sequence: seq,
        };
        messages.push(msg.clone());
        drop(messages);

        let _ = room.tx.send(RoomBroadcast::Message(msg));
        Ok(seq)
    }

    /// remove expired rooms. call periodically from a background task.
    pub async fn cleanup(&self) {
        let mut rooms = self.rooms.write().await;
        let now = Instant::now();
        let expired: Vec<String> = rooms
            .iter()
            .filter(|(_, r)| r.expires_at < now)
            .map(|(k, _)| k.clone())
            .collect();
        for code in &expired {
            if let Some(room) = rooms.remove(code) {
                let _ = room.tx.send(RoomBroadcast::Closed("expired".into()));
            }
        }
        if !expired.is_empty() {
            tracing::info!("frost relay: cleaned up {} expired rooms", expired.len());
        }
    }
}

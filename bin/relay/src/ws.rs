//! websocket bridge for browser clients
//!
//! JSON protocol over WebSocket, bridging to the same room system as gRPC.
//!
//! messages:
//!   client → server:
//!     {"t":"join","room":"code","nick":"anon12345"}
//!     {"t":"msg","text":"hello"}
//!     {"t":"create","nick":"anon12345"}
//!     {"t":"part"}
//!
//!   server → client:
//!     {"t":"joined","room":"code","nick":"anon12345","count":2}
//!     {"t":"msg","nick":"alice","text":"hello","seq":5,"ts":1234567890}
//!     {"t":"created","room":"abc-def-ghi"}
//!     {"t":"left","nick":"bob","count":1}
//!     {"t":"error","msg":"room not found"}

use std::sync::Arc;
use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{RoomManager, RoomBroadcast};

/// Don't replay messages older than this when a client joins. Avoids
/// dragging stale ciphertext from earlier client/key versions into the
/// scrollback of new joiners.
const HISTORY_REPLAY_TTL_MS: u64 = 24 * 60 * 60 * 1000;

fn now_ms_local() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Deserialize)]
#[serde(tag = "t")]
enum ClientMsg {
    #[serde(rename = "create")]
    Create { nick: String, room: Option<String> },
    #[serde(rename = "join")]
    Join { room: String, nick: String },
    #[serde(rename = "msg")]
    Msg { text: String },
    #[serde(rename = "part")]
    Part,
}

#[derive(Serialize, Clone)]
#[serde(tag = "t")]
enum ServerMsg {
    #[serde(rename = "created")]
    Created { room: String },
    #[serde(rename = "joined")]
    Joined { room: String, nick: String, count: u32 },
    #[serde(rename = "left")]
    Left { nick: String, count: u32 },
    #[serde(rename = "msg")]
    Msg { nick: String, text: String, seq: u64, ts: u64 },
    #[serde(rename = "error")]
    Error { msg: String },
    #[serde(rename = "system")]
    System { text: String },
}

pub fn ws_router(manager: Arc<RoomManager>) -> Router {
    Router::new()
        .route("/ws", get(ws_handler))
        .with_state(manager)
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(manager): State<Arc<RoomManager>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, manager))
}

async fn handle_socket(socket: WebSocket, manager: Arc<RoomManager>) {
    let (mut tx, mut rx) = socket.split();

    let mut current_room: Option<String> = None;
    let mut current_nick = String::from("anon");
    let mut participant_id: Vec<u8> = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut participant_id);

    // channel for sending messages back to the client
    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<ServerMsg>();

    // spawn writer task
    let write_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if let Ok(json) = serde_json::to_string(&msg) {
                if tx.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
        }
    });

    // read loop
    while let Some(Ok(msg)) = rx.next().await {
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Close(_) => break,
            _ => continue,
        };

        let client_msg: ClientMsg = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(_) => {
                let _ = out_tx.send(ServerMsg::Error { msg: "invalid json".into() });
                continue;
            }
        };

        match client_msg {
            ClientMsg::Create { nick, room } => {
                current_nick = nick;
                match manager.create_room_with_code(room, 100, 0).await {
                    Ok((code, _)) => {
                        info!("ws: room created {} by {}", code, current_nick);
                        let _ = out_tx.send(ServerMsg::Created { room: code });
                    }
                    Err(e) => { let _ = out_tx.send(ServerMsg::Error { msg: e.into() }); }
                }
            }

            ClientMsg::Join { room, nick } => {
                current_nick = nick.clone();
                match manager.join_room(&room, participant_id.clone()).await {
                    Ok(r) => {
                        let count = r.participants.read().await.len() as u32;
                        info!("ws: {} joined {} ({})", nick, room, count);

                        // send existing messages, filtered by TTL so stale
                        // ciphertext from prior client/key versions doesn't
                        // pollute new joiners' scrollback. messages stay in
                        // the room (other clients can still see them) but
                        // aren't replayed to fresh joiners after the cutoff.
                        let cutoff_ms = now_ms_local().saturating_sub(HISTORY_REPLAY_TTL_MS);
                        let existing = r.messages.read().await.clone();
                        for m in existing.iter().filter(|m| m.timestamp_ms >= cutoff_ms) {
                            let payload = String::from_utf8_lossy(&m.payload);
                            let (msg_nick, msg_text) = match payload.find('\0') {
                                Some(pos) => (payload[..pos].to_string(), payload[pos+1..].to_string()),
                                None => ("???".to_string(), payload.to_string()),
                            };
                            let _ = out_tx.send(ServerMsg::Msg {
                                nick: msg_nick,
                                text: msg_text,
                                seq: m.sequence,
                                ts: m.timestamp_ms,
                            });
                        }

                        let _ = out_tx.send(ServerMsg::Joined { room: room.clone(), nick, count });
                        current_room = Some(room.clone());

                        // subscribe to live events
                        let live_rx = r.tx.subscribe();
                        let out_tx2 = out_tx.clone();
                        tokio::spawn(async move {
                            let mut stream = tokio_stream::wrappers::BroadcastStream::new(live_rx);
                            while let Some(Ok(event)) = stream.next().await {
                                match event {
                                    RoomBroadcast::Message(m) => {
                                        // payload format: "nick\0text"
                                        let payload = String::from_utf8_lossy(&m.payload);
                                        let (msg_nick, msg_text) = match payload.find('\0') {
                                            Some(pos) => (payload[..pos].to_string(), payload[pos+1..].to_string()),
                                            None => ("???".to_string(), payload.to_string()),
                                        };
                                        let _ = out_tx2.send(ServerMsg::Msg {
                                            nick: msg_nick,
                                            text: msg_text,
                                            seq: m.sequence,
                                            ts: m.timestamp_ms,
                                        });
                                    }
                                    RoomBroadcast::Joined { participant_id, count, .. } => {
                                        let _ = out_tx2.send(ServerMsg::System {
                                            text: format!("{}... joined ({})", hex::encode(&participant_id[..4]), count),
                                        });
                                    }
                                    RoomBroadcast::Left { participant_id, count } => {
                                        let _ = out_tx2.send(ServerMsg::Left {
                                            nick: format!("{}...", hex::encode(&participant_id[..4])),
                                            count,
                                        });
                                    }
                                    RoomBroadcast::Closed(reason) => {
                                        let _ = out_tx2.send(ServerMsg::System { text: format!("room closed: {}", reason) });
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => { let _ = out_tx.send(ServerMsg::Error { msg: e.into() }); }
                }
            }

            ClientMsg::Msg { text } => {
                if let Some(ref room) = current_room {
                    // pack nick + text as "nick\0text" in payload, use participant_id as sender
                    let payload = format!("{}\0{}", current_nick, text);
                    match manager.send_message(room, participant_id.clone(), payload.into_bytes()).await {
                        Ok(_) => {} // message will come back via broadcast
                        Err(e) => { let _ = out_tx.send(ServerMsg::Error { msg: e.into() }); }
                    }
                } else {
                    let _ = out_tx.send(ServerMsg::Error { msg: "not in a room. use /j <room>".into() });
                }
            }

            ClientMsg::Part => {
                if let Some(ref room) = current_room {
                    let _ = manager.leave_room(room, participant_id.clone()).await;
                }
                current_room = None;
                let _ = out_tx.send(ServerMsg::System { text: "left channel".into() });
            }
        }
    }

    // socket closed - clean up the participant from the room so the
    // user count actually decrements. without this, every reconnect
    // appears as a fresh user and the count grows monotonically.
    if let Some(ref room) = current_room {
        let _ = manager.leave_room(room, participant_id).await;
    }

    write_task.abort();
}

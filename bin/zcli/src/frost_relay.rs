// frost_relay.rs — native gRPC-web client for zidecar's frost relay
//
// implements FrostTransport trait for relay-based FROST coordination.
// same grpc-web wire format as client.rs (reqwest + manual framing).
//
// transport 1 of 3: relay (zidecar grpc), quic (p2p), memos (tx chain)

use std::pin::Pin;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prost::Message;
use rand_core::RngCore;
use reqwest::Client;

use frost_spend::transport::{
    FrostTransport, RoundMessage, TransportError, TransportResult,
};

// ── protobuf messages (inline, matching frost_relay.proto) ──

#[derive(Clone, PartialEq, Message)]
pub struct CreateRoomRequest {
    #[prost(uint32, tag = "1")]
    pub threshold: u32,
    #[prost(uint32, tag = "2")]
    pub max_signers: u32,
    #[prost(uint32, tag = "3")]
    pub ttl_seconds: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct CreateRoomResponse {
    #[prost(string, tag = "1")]
    pub room_code: String,
    #[prost(uint64, tag = "2")]
    pub expires_at: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct JoinRoomRequest {
    #[prost(string, tag = "1")]
    pub room_code: String,
    #[prost(bytes = "vec", tag = "2")]
    pub participant_id: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SendMessageRequest {
    #[prost(string, tag = "1")]
    pub room_code: String,
    #[prost(bytes = "vec", tag = "2")]
    pub sender_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub payload: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SendMessageResponse {
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
}

// RoomEvent uses oneof — we decode manually
#[derive(Clone, PartialEq, Message)]
pub struct ParticipantJoined {
    #[prost(bytes = "vec", tag = "1")]
    pub participant_id: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub participant_count: u32,
    #[prost(uint32, tag = "3")]
    pub max_signers: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct RelayedMessage {
    #[prost(bytes = "vec", tag = "1")]
    pub sender_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub payload: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub sequence: u64,
}

// ── relay transport ──

pub struct RelayTransport {
    base_url: String,
    http: Client,
    room_code: String,
    participant_id: Vec<u8>,
    /// messages received from the stream, shared with the poller
    received: Arc<Mutex<Vec<RoundMessage>>>,
}

impl RelayTransport {
    /// create a new relay room and return the transport + room code
    pub async fn create_room(
        base_url: &str,
        threshold: u32,
        max_signers: u32,
        ttl_seconds: u32,
    ) -> TransportResult<(Self, String)> {
        let http = Client::new();
        let resp: CreateRoomResponse = grpc_unary(
            &http, base_url,
            "frost_relay.v1.FrostRelay/CreateRoom",
            &CreateRoomRequest { threshold, max_signers, ttl_seconds },
        ).await?;

        let mut participant_id = vec![0u8; 32];
        rand_core::OsRng.fill_bytes(&mut participant_id);

        let transport = Self {
            base_url: base_url.to_string(),
            http,
            room_code: resp.room_code.clone(),
            participant_id,
            received: Arc::new(Mutex::new(Vec::new())),
        };

        Ok((transport, resp.room_code))
    }

    /// join an existing room
    pub async fn join_room(base_url: &str, room_code: &str) -> TransportResult<Self> {
        let http = Client::new();
        let mut participant_id = vec![0u8; 32];
        rand_core::OsRng.fill_bytes(&mut participant_id);

        let transport = Self {
            base_url: base_url.to_string(),
            http,
            room_code: room_code.to_string(),
            participant_id,
            received: Arc::new(Mutex::new(Vec::new())),
        };

        Ok(transport)
    }

    pub fn room_code(&self) -> &str {
        &self.room_code
    }

    /// start the JoinRoom stream in background, collecting messages
    pub fn start_listening(&self) -> TransportResult<()> {
        let base_url = self.base_url.clone();
        let http = self.http.clone();
        let room_code = self.room_code.clone();
        let participant_id = self.participant_id.clone();
        let received = Arc::clone(&self.received);

        tokio::spawn(async move {
            let _ = listen_stream(&http, &base_url, &room_code, &participant_id, &received).await;
        });

        Ok(())
    }
}

impl FrostTransport for RelayTransport {
    fn broadcast(
        &self,
        _round: u8,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = TransportResult<()>> + Send + '_>> {
        let data = data.to_vec();
        Box::pin(async move {
            let _resp: SendMessageResponse = grpc_unary(
                &self.http, &self.base_url,
                "frost_relay.v1.FrostRelay/SendMessage",
                &SendMessageRequest {
                    room_code: self.room_code.clone(),
                    sender_id: self.participant_id.clone(),
                    payload: data,
                },
            ).await?;
            Ok(())
        })
    }

    fn collect(
        &self,
        _round: u8,
        expected: usize,
    ) -> Pin<Box<dyn Future<Output = TransportResult<Vec<RoundMessage>>> + Send + '_>> {
        let received = Arc::clone(&self.received);
        Box::pin(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
            loop {
                {
                    let msgs = received.lock().unwrap();
                    if msgs.len() >= expected {
                        let result = msgs.clone();
                        drop(msgs);
                        // clear for next round
                        received.lock().unwrap().clear();
                        return Ok(result);
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(TransportError::Timeout);
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
    }
}

// ── grpc-web helpers ──

async fn grpc_unary<Req: Message, Resp: Message + Default>(
    http: &Client,
    base_url: &str,
    method: &str,
    req: &Req,
) -> TransportResult<Resp> {
    let url = format!("{}/{}", base_url, method);
    let payload = req.encode_to_vec();
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0x00);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);

    let resp = http
        .post(&url)
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .body(frame)
        .send()
        .await
        .map_err(|e| TransportError::Io(format!("{}: {}", method, e)))?;

    if !resp.status().is_success() {
        return Err(TransportError::Io(format!("{}: HTTP {}", method, resp.status())));
    }

    let bytes = resp.bytes().await
        .map_err(|e| TransportError::Io(format!("{}: read: {}", method, e)))?;

    if bytes.len() < 5 {
        return Err(TransportError::Io(format!("{}: empty response", method)));
    }

    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    Resp::decode(&bytes[5..5 + len])
        .map_err(|e| TransportError::Io(format!("{}: decode: {}", method, e)))
}

/// listen to JoinRoom server-stream, pushing RelayedMessages into shared vec
async fn listen_stream(
    http: &Client,
    base_url: &str,
    room_code: &str,
    participant_id: &[u8],
    received: &Arc<Mutex<Vec<RoundMessage>>>,
) -> TransportResult<()> {
    let url = format!("{}/frost_relay.v1.FrostRelay/JoinRoom", base_url);
    let req = JoinRoomRequest {
        room_code: room_code.to_string(),
        participant_id: participant_id.to_vec(),
    };
    let payload = req.encode_to_vec();
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0x00);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);

    let resp = http
        .post(&url)
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .timeout(Duration::from_secs(600))
        .body(frame)
        .send()
        .await
        .map_err(|e| TransportError::Io(format!("JoinRoom: {}", e)))?;

    if !resp.status().is_success() {
        return Err(TransportError::Io(format!("JoinRoom: HTTP {}", resp.status())));
    }

    let bytes = resp.bytes().await
        .map_err(|e| TransportError::Io(format!("JoinRoom stream: {}", e)))?;

    // parse all frames from the response body
    let mut offset = 0;
    while offset + 5 <= bytes.len() {
        let flags = bytes[offset];
        let len = u32::from_be_bytes([
            bytes[offset + 1], bytes[offset + 2],
            bytes[offset + 3], bytes[offset + 4],
        ]) as usize;
        offset += 5;

        if offset + len > bytes.len() { break; }

        if flags & 0x80 != 0 {
            // trailer frame — stream done
            break;
        }

        let frame_data = &bytes[offset..offset + len];
        offset += len;

        // RoomEvent oneof: field 2 = RelayedMessage
        if let Ok(msg) = RelayedMessage::decode(frame_data) {
            if !msg.payload.is_empty() {
                received.lock().unwrap().push(RoundMessage {
                    sender: msg.sender_id,
                    payload: msg.payload,
                });
            }
        }
    }

    Ok(())
}

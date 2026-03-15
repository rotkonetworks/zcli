// frost_relay — dumb relay for FROST multisig signing sessions.
// forwards opaque signed blobs between room participants.
// does not parse or validate FROST protocol messages.

pub mod rooms;
pub mod wordlist;

use std::sync::Arc;

use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};
use tracing::info;

use crate::frost_relay_proto::frost_relay_server::FrostRelay;
use crate::frost_relay_proto::*;
use rooms::{RoomBroadcast, RoomManager};

pub struct FrostRelayService {
    manager: Arc<RoomManager>,
}

impl FrostRelayService {
    pub fn new() -> Self {
        let manager = Arc::new(RoomManager::new());

        // spawn cleanup task
        let manager_bg = manager.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                manager_bg.cleanup().await;
            }
        });

        Self { manager }
    }
}

#[tonic::async_trait]
impl FrostRelay for FrostRelayService {
    async fn create_room(
        &self,
        request: Request<CreateRoomRequest>,
    ) -> Result<Response<CreateRoomResponse>, Status> {
        let req = request.into_inner();
        let threshold = req.threshold.max(1);
        let max_signers = req.max_signers.max(threshold);

        let (code, expires_at) = self
            .manager
            .create_room(threshold, max_signers, req.ttl_seconds)
            .await
            .map_err(|e| Status::resource_exhausted(e))?;

        info!("frost relay: created room {} ({}-of-{})", code, threshold, max_signers);

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
            .map_err(|e| Status::not_found(e))?;

        info!(
            "frost relay: participant joined room {} (id: {}...)",
            room.code,
            hex::encode(&req.participant_id[..4.min(req.participant_id.len())])
        );

        // replay existing messages first, then subscribe to live broadcast
        let existing_messages = room.messages.read().await.clone();
        let existing_participants = room.participants.read().await.clone();
        let rx = room.tx.subscribe();
        let max_signers = room.max_signers;

        let stream = async_stream::stream! {
            // replay join events for already-present participants
            for (i, pid) in existing_participants.iter().enumerate() {
                yield Ok(RoomEvent {
                    event: Some(room_event::Event::Joined(ParticipantJoined {
                        participant_id: pid.clone(),
                        participant_count: (i + 1) as u32,
                        max_signers,
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
                    })),
                });
            }

            // subscribe to live events
            let mut stream = BroadcastStream::new(rx);
            use tokio_stream::StreamExt;
            while let Some(result) = stream.next().await {
                match result {
                    Ok(RoomBroadcast::Joined { participant_id, count, max_signers }) => {
                        yield Ok(RoomEvent {
                            event: Some(room_event::Event::Joined(ParticipantJoined {
                                participant_id,
                                participant_count: count,
                                max_signers,
                            })),
                        });
                    }
                    Ok(RoomBroadcast::Message(msg)) => {
                        yield Ok(RoomEvent {
                            event: Some(room_event::Event::Message(RelayedMessage {
                                sender_id: msg.sender_id,
                                payload: msg.payload,
                                sequence: msg.sequence,
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
                        // broadcast channel closed (room expired/dropped)
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
            .map_err(|e| Status::failed_precondition(e))?;

        Ok(Response::new(SendMessageResponse { sequence: seq }))
    }
}

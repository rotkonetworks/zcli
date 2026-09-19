// The rendezvous rides the frostd listener and is discovery only: a room
// code (hashed client-side) collects relay pubkeys, the coordinator approves
// and announces the real frostd session uuid, joiners poll it out. These
// tests walk that round-trip and the refusals that keep it discovery-only.

use std::net::SocketAddr;

use zidecar::rendezvous;

async fn spawn() -> SocketAddr {
    // merged exactly as main.rs serves it, so the mount is what's tested
    let state = frostd::AppState::new().await.expect("frostd state");
    let app = frostd::router(state).merge(rendezvous::router(rendezvous::RendezvousState::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

async fn post(addr: SocketAddr, path: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    let res = reqwest::Client::new()
        .post(format!("http://{addr}/rendezvous/{path}"))
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = res.status().as_u16();
    let body = res.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

fn room_id(code: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(code.as_bytes()))
}

fn pubkey(byte: u8) -> String {
    hex::encode([byte; 32])
}

#[tokio::test]
async fn discovery_round_trip() {
    let addr = spawn().await;
    let room = room_id("orbit-velvet-lantern-cove");

    // coordinator publishes first and gets the creator token
    let (s, body) = post(
        addr,
        "publish",
        serde_json::json!({"room": room, "pubkey": pubkey(1), "note": "coordinator"}),
    )
    .await;
    assert_eq!(s, 200);
    let token = body["creator_token"].as_str().expect("creator token").to_string();

    // a joiner publishes into the same room — no token for them
    let (s, body) = post(
        addr,
        "publish",
        serde_json::json!({"room": room, "pubkey": pubkey(2), "note": "alice"}),
    )
    .await;
    assert_eq!(s, 200);
    assert!(body.get("creator_token").is_none());

    // the coordinator polls and sees both keys
    let (s, body) = post(addr, "poll", serde_json::json!({"room": room})).await;
    assert_eq!(s, 200);
    let entries = body["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(body["session_id"], serde_json::Value::Null);

    // coordinator approves, creates the frostd session out of band, announces
    let (s, _) = post(
        addr,
        "announce",
        serde_json::json!({"room": room, "creator_token": token,
                           "session_id": "5b7a1c1e-0000-4000-8000-000000000000"}),
    )
    .await;
    assert_eq!(s, 200);

    // the joiner polls the session id out
    let (_, body) = post(addr, "poll", serde_json::json!({"room": room})).await;
    assert_eq!(
        body["session_id"].as_str(),
        Some("5b7a1c1e-0000-4000-8000-000000000000")
    );
}

#[tokio::test]
async fn announce_needs_the_creator_token() {
    let addr = spawn().await;
    let room = room_id("brine-copper-atlas");
    let (_, body) = post(
        addr,
        "publish",
        serde_json::json!({"room": room, "pubkey": pubkey(3)}),
    )
    .await;
    assert!(body["creator_token"].is_string());

    // someone who guessed the code cannot redirect the room
    let (s, _) = post(
        addr,
        "announce",
        serde_json::json!({"room": room, "creator_token": hex::encode([9u8; 16]),
                           "session_id": "evil"}),
    )
    .await;
    assert_eq!(s, 403);

    let (_, body) = post(addr, "poll", serde_json::json!({"room": room})).await;
    assert_eq!(body["session_id"], serde_json::Value::Null);
}

#[tokio::test]
async fn republish_updates_rather_than_duplicates() {
    let addr = spawn().await;
    let room = room_id("cedar-mosaic-thimble");
    for note in ["first", "second"] {
        let (s, _) = post(
            addr,
            "publish",
            serde_json::json!({"room": room, "pubkey": pubkey(4), "note": note}),
        )
        .await;
        assert_eq!(s, 200);
    }
    let (_, body) = post(addr, "poll", serde_json::json!({"room": room})).await;
    let entries = body["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["note"], "second");
}

#[tokio::test]
async fn malformed_inputs_are_refused() {
    let addr = spawn().await;
    // room must be 64 hex
    let (s, _) = post(
        addr,
        "publish",
        serde_json::json!({"room": "not-a-hash", "pubkey": pubkey(5)}),
    )
    .await;
    assert_eq!(s, 400);
    // pubkey must be 64 hex
    let (s, _) = post(
        addr,
        "publish",
        serde_json::json!({"room": room_id("x"), "pubkey": "zz"}),
    )
    .await;
    assert_eq!(s, 400);
    // unknown room polls as empty, not as an error (no existence oracle beyond content)
    let (s, body) = post(addr, "poll", serde_json::json!({"room": room_id("never-used")})).await;
    assert_eq!(s, 200);
    assert_eq!(body["entries"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn frostd_endpoints_still_answer_next_to_the_rendezvous() {
    let addr = spawn().await;
    let res = reqwest::Client::new()
        .post(format!("http://{addr}/challenge"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("request");
    assert!(res.status().is_success());
}

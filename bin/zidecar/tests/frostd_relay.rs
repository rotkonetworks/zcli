// The frostd relay zidecar serves is upstream's, mounted unmodified. These
// tests check the mounting, not the protocol — ZF tests the protocol.
//
// Worth having anyway: the failure mode of a version-mismatched axum is a
// compile error, but the failure mode of mounting the router wrongly is a
// server that accepts connections and 404s everything, which looks fine from
// the outside until a ceremony fails.

use std::net::SocketAddr;

async fn spawn_frostd() -> SocketAddr {
    let state = frostd::AppState::new().await.expect("frostd state");
    let app = frostd::router(state);
    // port 0 - let the OS pick, so concurrent test runs do not collide
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// The endpoint every session starts with. If this answers, the router is
/// mounted and reachable.
#[tokio::test]
async fn challenge_endpoint_answers() {
    let addr = spawn_frostd().await;
    let res = reqwest::Client::new()
        .post(format!("http://{addr}/challenge"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("request");

    assert!(res.status().is_success(), "status was {}", res.status());
    let body: serde_json::Value = res.json().await.expect("json");
    assert!(
        body.get("challenge").is_some(),
        "no challenge in response: {body}"
    );
}

/// Every documented endpoint must be routed. A router mounted with a missing
/// or misspelled path 404s only that one call, which surfaces as a ceremony
/// stalling rather than as anything obviously wrong.
#[tokio::test]
async fn all_nine_endpoints_are_routed() {
    let addr = spawn_frostd().await;
    let client = reqwest::Client::new();

    for path in [
        "challenge",
        "login",
        "logout",
        "create_new_session",
        "list_sessions",
        "get_session_info",
        "send",
        "receive",
        "close_session",
    ] {
        let res = client
            .post(format!("http://{addr}/{path}"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        // Unauthenticated or malformed calls are expected to be rejected —
        // what must NOT happen is 404, which would mean the route is absent.
        assert_ne!(
            res.status(),
            reqwest::StatusCode::NOT_FOUND,
            "{path} is not routed"
        );
    }
}

/// A path we never mounted must 404 — otherwise the assertion above proves
/// nothing.
#[tokio::test]
async fn an_unmounted_path_is_not_found() {
    let addr = spawn_frostd().await;
    let res = reqwest::Client::new()
        .post(format!("http://{addr}/definitely_not_an_endpoint"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
}

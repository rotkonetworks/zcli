//! frostd-relay — standalone frostd + rendezvous, for relay-only hosts.
//!
//! relay.zafu.pro runs no chain node, so full zidecar (which refuses to start
//! without a reachable zebrad) is the wrong shape there. This serves exactly
//! what zidecar's `--frostd-listen` serves — upstream frostd's nine endpoints
//! plus our `/rendezvous/*` room-code discovery — and nothing else.
//!
//! Same posture as upstream frostd: in-memory, nothing persisted, no TLS of
//! its own (terminate in front, bind loopback).

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2744".into())
        .parse()?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "refusing to serve {addr} without TLS - bind loopback and terminate TLS in front"
        )
        .into());
    }

    let state = frostd::AppState::new().await?;
    let app = frostd::router(state)
        .merge(zidecar::rendezvous::router(zidecar::rendezvous::RendezvousState::new()));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("frostd-relay: serving frostd + rendezvous on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

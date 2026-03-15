//! integration tests against a live zebrad via SSH tunnel
//!
//! requires: ssh -f -N -L 8232:192.168.77.201:8232 bkk07
//! run with: cargo test -p zidecar --test zebrad_integration -- --ignored

use zidecar::error::ZidecarError;
use zidecar::zebrad::ZebradClient;

fn zebrad_url() -> String {
    std::env::var("ZEBRAD_RPC").unwrap_or_else(|_| "http://127.0.0.1:8232".into())
}

async fn require_zebrad() -> ZebradClient {
    let client = ZebradClient::new(&zebrad_url());
    match client.get_blockchain_info().await {
        Ok(info) => {
            assert_eq!(info.chain, "main");
            assert!(info.blocks > 3_000_000, "chain too short: {}", info.blocks);
            client
        }
        Err(e) => panic!(
            "zebrad not reachable at {} — start SSH tunnel: {}",
            zebrad_url(),
            e
        ),
    }
}

// === tower service layer tests ===

#[tokio::test]
#[ignore]
async fn test_get_blockchain_info() {
    let client = require_zebrad().await;
    let info = client.get_blockchain_info().await.unwrap();
    assert_eq!(info.chain, "main");
    assert!(info.blocks > 0);
    assert!(!info.bestblockhash.is_empty());
}

#[tokio::test]
#[ignore]
async fn test_get_block_hash_genesis() {
    let client = require_zebrad().await;
    let hash = client.get_block_hash(0).await.unwrap();
    assert_eq!(
        hash,
        "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"
    );
}

#[tokio::test]
#[ignore]
async fn test_get_block() {
    let client = require_zebrad().await;
    let hash = client.get_block_hash(1).await.unwrap();
    let block = client.get_block(&hash, 1).await.unwrap();
    assert_eq!(block.height, 1);
    assert!(!block.tx.is_empty());
}

#[tokio::test]
#[ignore]
async fn test_get_block_header() {
    let client = require_zebrad().await;
    let hash = client.get_block_hash(100_000).await.unwrap();
    let header = client.get_block_header(&hash).await.unwrap();
    assert_eq!(header.height, 100_000);
    assert!(!header.hash.is_empty());
    assert!(!header.prev_hash.is_empty());
    assert!(!header.bits.is_empty());
}

#[tokio::test]
#[ignore]
async fn test_get_tree_state() {
    let client = require_zebrad().await;
    let state = client.get_tree_state("1687104").await.unwrap();
    assert_eq!(state.height, 1687104);
    assert!(!state.orchard.commitments.final_state.is_empty());
    assert!(!state.sapling.commitments.final_state.is_empty());
}

#[tokio::test]
#[ignore]
async fn test_get_subtrees() {
    let client = require_zebrad().await;
    let resp = client
        .get_subtrees_by_index("orchard", 0, Some(5))
        .await
        .unwrap();
    assert_eq!(resp.pool, "orchard");
    assert!(!resp.subtrees.is_empty());
    assert!(resp.subtrees.len() <= 5);
    for subtree in &resp.subtrees {
        assert!(!subtree.root.is_empty());
        assert!(subtree.end_height > 0);
    }
}

#[tokio::test]
#[ignore]
async fn test_concurrent_requests() {
    let client = require_zebrad().await;
    let mut handles = Vec::new();
    for i in 0u32..16 {
        let c = client.clone();
        handles.push(tokio::spawn(async move {
            let height = 1_000_000 + i * 1000;
            c.get_block_hash(height).await
        }));
    }
    let mut ok = 0;
    for h in handles {
        if h.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 16, "all 16 concurrent requests should succeed");
}

#[tokio::test]
#[ignore]
async fn test_timeout_fast_response() {
    let client = require_zebrad().await;
    let start = std::time::Instant::now();
    client.get_blockchain_info().await.unwrap();
    let elapsed = start.elapsed();
    assert!(elapsed.as_secs() < 10, "simple RPC took {:?}", elapsed);
}

// === error classification tests (no zebrad needed) ===

#[tokio::test]
async fn test_transient_error_timeout() {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(1))
        .build()
        .unwrap();
    let err = client
        .post("http://192.0.2.1:9999")
        .send()
        .await
        .unwrap_err();
    let ze = ZidecarError::ZebradTransport(err);
    assert!(ze.is_transient(), "timeout/connect should be transient");
}

#[tokio::test]
async fn test_rpc_error_not_transient() {
    let ze = ZidecarError::ZebradRpc("RPC error -8: Block not found".into());
    assert!(!ze.is_transient());
}

#[tokio::test]
async fn test_storage_error_not_transient() {
    let ze = ZidecarError::Storage("disk full".into());
    assert!(!ze.is_transient());
}

#[tokio::test]
async fn test_network_error_transient() {
    let ze = ZidecarError::Network("connection reset".into());
    assert!(ze.is_transient());
}

//! integration tests for zcli's grpc-web client against live zidecar
//!
//! tests against production endpoint (zcash.rotko.net) to verify
//! wire compatibility after server refactoring.
//!
//! run with: cargo test -p zcli --test client_integration -- --ignored

#[cfg(feature = "cli")]
mod tests {
    use zecli::client::ZidecarClient;

    fn endpoint() -> String {
        std::env::var("ZCLI_ENDPOINT")
            .unwrap_or_else(|_| "https://zcash.rotko.net".into())
    }

    async fn require_client() -> ZidecarClient {
        match ZidecarClient::connect(&endpoint()).await {
            Ok(c) => c,
            Err(e) => panic!("cannot connect to {}: {}", endpoint(), e),
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_tip() {
        let client = require_client().await;
        let (height, hash) = client.get_tip().await.unwrap();
        assert!(height > 3_000_000, "tip too low: {}", height);
        assert_eq!(hash.len(), 32, "tip hash should be 32 bytes");
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_compact_blocks() {
        let client = require_client().await;
        // fetch 10 blocks near orchard activation
        let blocks = client.get_compact_blocks(1_687_104, 1_687_113).await.unwrap();
        assert_eq!(blocks.len(), 10);
        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(block.height, 1_687_104 + i as u32);
            assert!(!block.hash.is_empty());
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_tree_state() {
        let client = require_client().await;
        let (tree, height) = client.get_tree_state(1_687_104).await.unwrap();
        assert_eq!(height, 1_687_104);
        assert!(!tree.is_empty());
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_header_proof() {
        let client = require_client().await;
        let (proof, from, to) = client.get_header_proof().await.unwrap();
        assert!(!proof.is_empty(), "proof should not be empty");
        assert!(from > 0, "from_height should be set");
        assert!(to > from, "to_height should be > from_height");
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_address_utxos() {
        let client = require_client().await;
        // known funded transparent address (zcash foundation)
        let utxos = client
            .get_address_utxos(vec![
                "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs".to_string(),
            ])
            .await
            .unwrap();
        // may or may not have utxos, but should not error
        for u in &utxos {
            assert!(!u.address.is_empty());
            assert!(u.height > 0);
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_transaction() {
        let client = require_client().await;
        // known transaction (first orchard tx in block 1687105)
        // just test that the RPC works, not the specific txid
        let (tip, _) = client.get_tip().await.unwrap();
        // get a recent block to find a txid
        let blocks = client.get_compact_blocks(tip - 5, tip - 5).await.unwrap();
        if !blocks.is_empty() && !blocks[0].actions.is_empty() {
            let txid = &blocks[0].actions[0].txid;
            if !txid.is_empty() {
                let tx_data = client.get_transaction(txid).await.unwrap();
                assert!(!tx_data.is_empty(), "transaction data should not be empty");
            }
        }
    }
}

//! on-chain bridge custody test: fund → sync → FROST sign → broadcast
//!
//! run with: cargo test -p zecli --test bridge_onchain -- --ignored --nocapture
//! requires: live zidecar + id_claude wallet with balance

#[cfg(feature = "cli")]
mod tests {
    use frost_spend::hierarchical::bridge_dkg_dealer;

    fn endpoint() -> String {
        std::env::var("ZCLI_ENDPOINT").unwrap_or_else(|_| "https://zcash.rotko.net".into())
    }

    #[tokio::test]
    #[ignore]
    async fn test_bridge_onchain_spend() {
        eprintln!("\n=== BRIDGE ON-CHAIN E2E TEST ===\n");

        // ── step 1: DKG ──
        eprintln!("step 1: 2-of-2 dealer DKG...");
        let dkg = bridge_dkg_dealer().expect("DKG failed");
        eprintln!("  bridge VK: {}", &dkg.bridge_vk_hex);

        // ── step 2: derive bridge address from the DKG's FVK ──
        eprintln!("step 2: derive bridge address...");
        let fvk = orchard::keys::FullViewingKey::from_bytes(&dkg.fvk_bytes).unwrap();
        let bridge_orchard_addr = fvk.address_at(0u64, orchard::keys::Scope::External);
        let bridge_addr = zecli::address::encode_unified_address(&bridge_orchard_addr, true)
            .expect("encode address");
        eprintln!("  bridge: {}", bridge_addr);

        // ── step 3: fund bridge ──
        eprintln!("step 3: funding bridge (0.00020 ZEC from id_claude)...");
        let key_path = format!("{}/.ssh/id_claude", std::env::var("HOME").unwrap());
        let seed = zecli::key::load_ssh_seed(&key_path).unwrap();

        zecli::ops::send::send(
            &seed, "0.00020", &bridge_addr,
            Some("bridge e2e onchain test"),
            &endpoint(), true, false,
        ).await.expect("send to bridge failed");
        eprintln!("  funded! waiting for confirmation...");

        // ── step 4: sync bridge wallet with FVK ──
        eprintln!("step 4: wait for confirmation + sync bridge wallet...");
        // reuse the SAME FVK from DKG (already parsed in step 2)

        zecli::wallet::set_watch_mode(true);
        // skip actions commitment verification for fresh bridge wallet
        std::env::set_var("ZCLI_NO_VERIFY", "1");

        let client = zecli::client::ZidecarClient::connect(&endpoint()).await.unwrap();
        let (pre_tip, _) = client.get_tip().await.unwrap();
        // scan from 1 block before funding tx so we catch it
        let scan_from = pre_tip.saturating_sub(1);

        // get the correct orchard position at scan_from
        let (tree_hex, _) = client.get_tree_state(scan_from).await.unwrap();
        let tree_bytes = hex::decode(&tree_hex).unwrap();
        let position_at_scan = zecli::witness::frontier_tree_size(&tree_bytes).unwrap();
        eprintln!("  scan_from={} position={}", scan_from, position_at_scan);

        // wait for 3 blocks
        eprintln!("  waiting for 3 blocks...");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let (now_tip, _) = client.get_tip().await.unwrap();
            eprintln!("  tip: {} (need > {})", now_tip, pre_tip + 2);
            if now_tip > pre_tip + 2 {
                break;
            }
        }

        eprintln!("  syncing from {} with position {}...", scan_from, position_at_scan);
        let found = zecli::ops::sync::sync_with_fvk(
            &fvk, &endpoint(), "", true, false,
            Some(scan_from), Some(position_at_scan),
        ).await.expect("bridge sync failed");
        eprintln!("  found {} notes", found);
        assert!(found > 0, "no notes found — tx may not have confirmed yet");

        // ── step 5: FROST spend ──
        eprintln!("step 5: bridge spend via 2-of-2 FROST...");

        // send back to claude's address (0.00001 ZEC)
        let claude_fvk = {
            let sk = orchard::keys::SpendingKey::from_zip32_seed(
                seed.as_bytes(), 133, zip32::AccountId::ZERO,
            ).unwrap();
            orchard::keys::FullViewingKey::from(&sk)
        };
        let claude_addr = claude_fvk.address_at(0u64, orchard::keys::Scope::External);
        let claude_addr_str = zecli::address::encode_unified_address(&claude_addr, true)
            .expect("encode claude addr");

        let txid = zecli::ops::bridge::bridge_spend(
            &dkg.osst_package,
            &dkg.validator_package,
            &dkg.fvk_bytes,
            "0.00001",
            &claude_addr_str,
            Some("bridge e2e return"),
            &endpoint(),
            true,
        ).await.expect("bridge spend failed");

        eprintln!("\n=== BRIDGE ON-CHAIN E2E: SUCCESS ===");
        eprintln!("  txid: {}", txid);

        // restore default wallet mode
        zecli::wallet::set_watch_mode(false);
    }
}

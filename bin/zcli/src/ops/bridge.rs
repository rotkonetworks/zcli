// bridge.rs — bridge custody spend using nested FROST
//
// reuses the PCZT (unsigned tx) path from airgap, but replaces
// zigner/single-key signing with 2-of-2 FROST.
// position B can be local (test) or via narsild (production).

use orchard::keys::FullViewingKey;

use crate::client::ZidecarClient;
use crate::error::Error;
use crate::ops::send::{compute_fee, select_notes};
use crate::pczt;
use crate::tx;
use crate::wallet::Wallet;
use crate::witness;

use frost_spend::hierarchical::{
    BridgeKeyPackage,
    bridge_sign_round1, bridge_sign_round2, bridge_aggregate,
};

/// spend from the bridge custody wallet using local 2-of-2 FROST signing.
///
/// both positions sign in-process. for production, position B would be
/// routed through narsild for nested inner FROST among validators.
///
/// takes fvk_bytes (96 bytes) to avoid orchard crate version conflicts.
#[allow(clippy::too_many_arguments)]
pub async fn bridge_spend(
    osst_pkg: &BridgeKeyPackage,
    validator_pkg: &BridgeKeyPackage,
    fvk_bytes: &[u8; 96],
    amount_str: &str,
    recipient: &str,
    memo: Option<&str>,
    endpoint: &str,
    mainnet: bool,
) -> Result<String, Error> {
    let fvk = FullViewingKey::from_bytes(fvk_bytes)
        .ok_or_else(|| Error::Other("invalid FVK bytes".into()))?;
    let amount_zat = crate::ops::send::parse_amount(amount_str)?;
    let recipient_addr = tx::parse_orchard_address(recipient, mainnet)?;

    // select notes from the bridge wallet
    let selected = {
        let wallet = Wallet::open(&Wallet::default_path())?;
        let (balance, notes) = wallet.shielded_balance()?;
        let est_fee = compute_fee(1, 1, 0, true);
        let needed = amount_zat + est_fee;
        if balance < needed {
            return Err(Error::InsufficientFunds {
                have: balance,
                need: needed,
            });
        }
        select_notes(&notes, needed)?
    };

    let total_in: u64 = selected.iter().map(|n| n.value).sum();
    let has_change = total_in > amount_zat + compute_fee(selected.len(), 1, 0, true);
    let fee = compute_fee(selected.len(), 1, 0, has_change);
    if total_in < amount_zat + fee {
        return Err(Error::InsufficientFunds {
            have: total_in,
            need: amount_zat + fee,
        });
    }
    let change = total_in - amount_zat - fee;

    eprintln!(
        "bridge spend: {:.8} ZEC → {}... ({} notes, fee {:.8} ZEC)",
        amount_zat as f64 / 1e8,
        &recipient[..20.min(recipient.len())],
        selected.len(),
        fee as f64 / 1e8,
    );

    // reconstruct orchard notes
    let orchard_notes: Vec<orchard::Note> = selected
        .iter()
        .map(|n| n.reconstruct_note())
        .collect::<Result<_, _>>()?;

    // build merkle witnesses
    let client = ZidecarClient::connect(endpoint).await?;
    let (tip, _) = client.get_tip().await?;

    eprintln!("building merkle witnesses...");
    let (cached_frontier, sync_height) = witness::load_frontier_from_wallet();
    let (anchor, paths) = witness::build_witnesses(&client, &selected, tip, mainnet, false, cached_frontier, sync_height).await?;

    let spends: Vec<(orchard::Note, orchard::tree::MerklePath)> =
        orchard_notes.into_iter().zip(paths).collect();

    let mut memo_bytes = [0u8; 512];
    if let Some(text) = memo {
        let bytes = text.as_bytes();
        let len = bytes.len().min(512);
        memo_bytes[..len].copy_from_slice(&bytes[..len]);
    }

    eprintln!("building PCZT (halo 2 proving)...");

    let fvk_bytes = fvk.to_bytes();
    let anchor_height = tip;

    let pczt_state = tokio::task::spawn_blocking(move || {
        let (_, state) = pczt::build_pczt_and_qr(
            &fvk_bytes,
            &spends,
            &[(recipient_addr, amount_zat, memo_bytes)],
            &[],
            change,
            anchor,
            anchor_height,
            mainnet,
        )?;
        Ok::<_, Error>(state)
    })
    .await
    .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    eprintln!(
        "sighash: {} ({} action(s))",
        hex::encode(pczt_state.sighash),
        pczt_state.alphas.len(),
    );

    // ── FROST signing ──
    eprintln!("FROST signing (2-of-2)...");

    let mut orchard_sigs: Vec<[u8; 64]> = Vec::new();

    for (action_idx, alpha) in pczt_state.alphas.iter().enumerate() {
        // round 1: both positions commit
        let state_a = bridge_sign_round1(osst_pkg)
            .map_err(|e| Error::Other(format!("round1 A: {}", e)))?;
        let state_b = bridge_sign_round1(validator_pkg)
            .map_err(|e| Error::Other(format!("round1 B: {}", e)))?;

        let commitments = vec![
            state_a.commitment_hex.clone(),
            state_b.commitment_hex.clone(),
        ];

        // round 2: both positions sign with sighash + alpha
        let share_a = bridge_sign_round2(
            osst_pkg, &state_a, &pczt_state.sighash, alpha, &commitments,
        ).map_err(|e| Error::Other(format!("round2 A: {}", e)))?;

        let share_b = bridge_sign_round2(
            validator_pkg, &state_b, &pczt_state.sighash, alpha, &commitments,
        ).map_err(|e| Error::Other(format!("round2 B: {}", e)))?;

        // aggregate
        let sig_hex = bridge_aggregate(
            &osst_pkg.public_key_package,
            &pczt_state.sighash,
            alpha,
            &commitments,
            &[share_a, share_b],
        ).map_err(|e| Error::Other(format!("aggregate: {}", e)))?;

        let sig_bytes = hex::decode(&sig_hex)
            .map_err(|e| Error::Other(format!("sig hex: {}", e)))?;
        let sig: [u8; 64] = sig_bytes.try_into()
            .map_err(|_| Error::Other("sig not 64 bytes".into()))?;

        orchard_sigs.push(sig);
        eprintln!("  action {}: signed ✓", action_idx);
    }

    // ── complete and broadcast ──
    eprintln!("finalizing transaction...");

    let tx_bytes = tokio::task::spawn_blocking(move || {
        pczt::complete_pczt_tx(pczt_state, &orchard_sigs)
    })
    .await
    .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    let result = client.send_transaction(tx_bytes).await?;

    if result.is_success() {
        let txid = hex::encode(&result.txid);
        eprintln!("broadcast success!");
        println!("txid: {}", txid);
        Ok(txid)
    } else {
        Err(Error::Transaction(format!(
            "broadcast failed ({}): {}",
            result.error_code, result.error_message
        )))
    }
}

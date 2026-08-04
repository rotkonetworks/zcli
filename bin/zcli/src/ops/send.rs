use crate::client::ZidecarClient;
use crate::error::Error;
use crate::key::WalletSeed;
use crate::tx;
use crate::wallet::Wallet;
use crate::witness;

const MARGINAL_FEE: u64 = 5_000;
const GRACE_ACTIONS: usize = 2;
const MIN_ORCHARD_ACTIONS: usize = 2;

/// ZIP-317 fee computation
pub fn compute_fee(
    n_spends: usize,
    n_z_outputs: usize,
    n_t_outputs: usize,
    has_change: bool,
) -> u64 {
    let n_orchard_outputs = n_z_outputs + if has_change { 1 } else { 0 };
    let n_orchard_actions = n_spends.max(n_orchard_outputs).max(MIN_ORCHARD_ACTIONS);
    let n_t_logical = n_t_outputs; // no transparent inputs in orchard spends
    let logical_actions = n_orchard_actions + n_t_logical;
    MARGINAL_FEE * logical_actions.max(GRACE_ACTIONS) as u64
}

pub async fn send(
    seed: &WalletSeed,
    amount_str: &str,
    recipient: &str,
    memo: Option<&str>,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    let amount_zat = parse_amount(amount_str)?;

    // determine recipient type
    if recipient.starts_with("t1") || recipient.starts_with("tm") {
        send_to_transparent(seed, amount_zat, recipient, endpoint, mainnet, json).await
    } else if recipient.starts_with("u1") || recipient.starts_with("utest1") {
        send_to_shielded(seed, amount_zat, recipient, memo, endpoint, mainnet, json).await
    } else {
        Err(Error::Address(format!(
            "unrecognized address format: {}",
            recipient
        )))
    }
}

/// z→t: spend shielded notes to a transparent address
async fn send_to_transparent(
    seed: &WalletSeed,
    amount: u64,
    recipient: &str,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    let (selected, cached_frontier, sync_height) = {
        let wallet = Wallet::open(&Wallet::default_path())?;
        let (balance, notes) = wallet.shielded_balance()?;

        // estimate fee (may adjust after note selection)
        let est_fee = compute_fee(1, 0, 1, true);
        let needed = amount + est_fee;
        if balance < needed {
            return Err(Error::InsufficientFunds {
                have: balance,
                need: needed,
            });
        }

        let frontier = wallet.tree_frontier().ok().flatten();
        let sh = wallet.sync_height().unwrap_or(0);

        // select notes (largest first until we cover amount + fee)
        (select_notes(&notes, needed)?, frontier, sh)
    }; // drop wallet before later re-open

    // compute exact fee based on selected notes
    let total_in: u64 = selected.iter().map(|n| n.value).sum();
    let has_change = total_in > amount + compute_fee(selected.len(), 0, 1, true);
    let fee = compute_fee(selected.len(), 0, 1, has_change);
    if total_in < amount + fee {
        return Err(Error::InsufficientFunds {
            have: total_in,
            need: amount + fee,
        });
    }

    if !json {
        eprintln!(
            "spending {:.8} ZEC → {} ({} notes, fee {:.8} ZEC)",
            amount as f64 / 1e8,
            recipient,
            selected.len(),
            fee as f64 / 1e8
        );
    }

    // reconstruct orchard notes
    let orchard_notes: Vec<orchard::Note> = selected
        .iter()
        .map(|n| n.reconstruct_note())
        .collect::<Result<_, _>>()?;

    // build merkle witnesses
    let client = ZidecarClient::connect(endpoint).await?;
    let (tip, _) = client.get_tip().await?;

    if !json {
        eprintln!("building merkle witnesses (replaying chain)...");
    }
    let (anchor, paths) = witness::build_witnesses(
        &client,
        &selected,
        tip,
        mainnet,
        json,
        cached_frontier.clone(),
        sync_height,
    )
    .await?;

    // build spends vec
    let spends: Vec<(orchard::Note, orchard::tree::MerklePath)> =
        orchard_notes.into_iter().zip(paths).collect();

    let t_outputs = vec![(recipient.to_string(), amount)];

    if !json {
        eprintln!("building transaction (halo 2 proving)...");
    }

    // run proving in spawn_blocking (halo2 uses rayon internally)
    let seed_bytes = *seed.as_bytes();
    let anchor_height = tip;
    // consensus branch id from the LIVE chain (auto-tracks network upgrades)
    let branch_id = client.resolve_branch_id().await;
    let tx_bytes = tokio::task::spawn_blocking(move || {
        let seed = crate::key::WalletSeed::from_bytes(seed_bytes);
        tx::build_orchard_spend_tx(
            &seed,
            &spends,
            &t_outputs,
            &[],
            fee,
            anchor,
            anchor_height,
            branch_id,
            mainnet,
        )
    })
    .await
    .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    // broadcast
    let result = client.send_transaction(tx_bytes).await?;

    if result.is_success() {
        let w = Wallet::open(&Wallet::default_path())?;
        let _ = w.insert_sent_tx(&crate::wallet::SentTx {
            txid: result.txid.clone(),
            amount,
            fee,
            recipient: recipient.to_string(),
            tx_type: "z\u{2192}t".into(),
            block_height: 0,
            memo: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        });
    }

    if json {
        println!(
            "{}",
            serde_json::json!({
                "txid": result.txid,
                "amount_zat": amount,
                "fee_zat": fee,
                "recipient": recipient,
                "type": "z→t",
                "success": result.is_success(),
                "error": result.error_message,
            })
        );
    } else if result.is_success() {
        println!("txid: {}", result.txid);
    } else {
        return Err(Error::Transaction(format!(
            "broadcast failed ({}): {}",
            result.error_code, result.error_message
        )));
    }

    Ok(())
}

/// z→z: spend shielded notes to a shielded address
async fn send_to_shielded(
    seed: &WalletSeed,
    amount: u64,
    recipient: &str,
    memo: Option<&str>,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    // parse recipient
    let recipient_addr = tx::parse_orchard_address(recipient, mainnet)?;

    let (selected, cached_frontier, sync_height) = {
        let wallet = Wallet::open(&Wallet::default_path())?;
        let (balance, notes) = wallet.shielded_balance()?;

        let est_fee = compute_fee(1, 1, 0, true);
        let needed = amount + est_fee;
        if balance < needed {
            return Err(Error::InsufficientFunds {
                have: balance,
                need: needed,
            });
        }

        let frontier = wallet.tree_frontier().ok().flatten();
        let sh = wallet.sync_height().unwrap_or(0);
        (select_notes(&notes, needed)?, frontier, sh)
    }; // drop wallet before later re-open

    let total_in: u64 = selected.iter().map(|n| n.value).sum();
    let has_change = total_in > amount + compute_fee(selected.len(), 1, 0, true);
    let fee = compute_fee(selected.len(), 1, 0, has_change);
    if total_in < amount + fee {
        return Err(Error::InsufficientFunds {
            have: total_in,
            need: amount + fee,
        });
    }

    if !json {
        let addr_preview = if recipient.len() > 20 {
            &recipient[..20]
        } else {
            recipient
        };
        eprintln!(
            "spending {:.8} ZEC → {}... ({} notes, fee {:.8} ZEC)",
            amount as f64 / 1e8,
            addr_preview,
            selected.len(),
            fee as f64 / 1e8
        );
    }

    // reconstruct orchard notes
    let orchard_notes: Vec<orchard::Note> = selected
        .iter()
        .map(|n| n.reconstruct_note())
        .collect::<Result<_, _>>()?;

    // build merkle witnesses
    let client = ZidecarClient::connect(endpoint).await?;
    let (tip, _) = client.get_tip().await?;

    if !json {
        eprintln!("building merkle witnesses (replaying chain)...");
    }
    let (anchor, paths) = witness::build_witnesses(
        &client,
        &selected,
        tip,
        mainnet,
        json,
        cached_frontier.clone(),
        sync_height,
    )
    .await?;

    let spends: Vec<(orchard::Note, orchard::tree::MerklePath)> =
        orchard_notes.into_iter().zip(paths).collect();

    // build memo (512 bytes, text padded with zeros)
    let mut memo_bytes = [0u8; 512];
    if let Some(text) = memo {
        let bytes = text.as_bytes();
        let len = bytes.len().min(512);
        memo_bytes[..len].copy_from_slice(&bytes[..len]);
    }

    let z_outputs = vec![(recipient_addr, amount, memo_bytes)];

    if !json {
        eprintln!("building transaction (halo 2 proving)...");
    }

    let seed_bytes = *seed.as_bytes();
    let anchor_height = tip;
    // consensus branch id from the LIVE chain (auto-tracks network upgrades)
    let branch_id = client.resolve_branch_id().await;
    let tx_bytes = tokio::task::spawn_blocking(move || {
        let seed = crate::key::WalletSeed::from_bytes(seed_bytes);
        tx::build_orchard_spend_tx(
            &seed,
            &spends,
            &[],
            &z_outputs,
            fee,
            anchor,
            anchor_height,
            branch_id,
            mainnet,
        )
    })
    .await
    .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    // broadcast
    let result = client.send_transaction(tx_bytes).await?;

    if result.is_success() {
        let wallet = Wallet::open(&Wallet::default_path())?;
        let _ = wallet.insert_sent_tx(&crate::wallet::SentTx {
            txid: result.txid.clone(),
            amount,
            fee,
            recipient: recipient.to_string(),
            tx_type: "z\u{2192}z".into(),
            block_height: 0,
            memo: memo.map(String::from),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        });
    }

    if json {
        println!(
            "{}",
            serde_json::json!({
                "txid": result.txid,
                "amount_zat": amount,
                "fee_zat": fee,
                "recipient": recipient,
                "type": "z→z",
                "success": result.is_success(),
                "error": result.error_message,
            })
        );
    } else if result.is_success() {
        println!("txid: {}", result.txid);
    } else {
        return Err(Error::Transaction(format!(
            "broadcast failed ({}): {}",
            result.error_code, result.error_message
        )));
    }

    Ok(())
}

/// select notes covering target amount (largest first)
pub(crate) fn select_notes(
    notes: &[crate::wallet::WalletNote],
    target: u64,
) -> Result<Vec<crate::wallet::WalletNote>, Error> {
    // ironwood notes need a v6 transaction to spend; until the wallet can
    // build those, only orchard notes are spendable. They still show in the
    // balance, so surface the gap explicitly when funds fall short.
    let ironwood_zat: u64 = notes
        .iter()
        .filter(|n| n.pool == crate::wallet::Pool::Ironwood)
        .map(|n| n.value)
        .sum();
    let mut sorted: Vec<_> = notes
        .iter()
        .filter(|n| n.pool == crate::wallet::Pool::Orchard)
        .cloned()
        .collect();
    // sort by value descending, then by position descending (prefer recent notes
    // to minimize merkle witness replay distance from stale checkpoints)
    sorted.sort_by(|a, b| b.value.cmp(&a.value).then(b.position.cmp(&a.position)));

    let mut selected = Vec::new();
    let mut total = 0u64;
    for note in sorted {
        total += note.value;
        selected.push(note);
        if total >= target {
            return Ok(selected);
        }
    }

    if ironwood_zat > 0 {
        eprintln!(
            "note: {:.8} ZEC held in ironwood notes is not yet spendable \
             (needs v6 transaction support)",
            ironwood_zat as f64 / 100_000_000.0
        );
    }
    Err(Error::InsufficientFunds {
        have: total,
        need: target,
    })
}

pub fn parse_amount(s: &str) -> Result<u64, Error> {
    // accept both ZEC (decimal) and zatoshi (integer)
    if s.contains('.') {
        let zec: f64 = s
            .parse()
            .map_err(|_| Error::Transaction(format!("invalid amount: {}", s)))?;
        if zec < 0.0 {
            return Err(Error::Transaction("amount must be positive".into()));
        }
        Ok((zec * 1e8).round() as u64)
    } else {
        let zat: u64 = s
            .parse()
            .map_err(|_| Error::Transaction(format!("invalid amount: {}", s)))?;
        Ok(zat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_zec_amount() {
        assert_eq!(parse_amount("0.001").unwrap(), 100_000);
        assert_eq!(parse_amount("1.0").unwrap(), 100_000_000);
        assert_eq!(parse_amount("0.00000001").unwrap(), 1);
    }

    #[test]
    fn parse_zatoshi_amount() {
        assert_eq!(parse_amount("100000").unwrap(), 100_000);
        assert_eq!(parse_amount("1").unwrap(), 1);
    }

    fn note(value: u64, pool: crate::wallet::Pool) -> crate::wallet::WalletNote {
        crate::wallet::WalletNote {
            value,
            nullifier: [0u8; 32],
            cmx: [0u8; 32],
            block_height: 0,
            is_change: false,
            recipient: vec![],
            rho: [0u8; 32],
            rseed: [0u8; 32],
            position: 0,
            txid: vec![],
            memo: None,
            pool,
        }
    }

    /// ironwood notes are never selected for spending (no v6 builder yet),
    /// even when they would cover the target.
    #[test]
    fn select_notes_skips_ironwood() {
        use crate::wallet::Pool;
        let notes = vec![note(50_000, Pool::Orchard), note(1_000_000, Pool::Ironwood)];

        // orchard alone covers a small target
        let sel = select_notes(&notes, 40_000).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].pool, Pool::Orchard);

        // ironwood value must not count toward spendable funds
        let err = select_notes(&notes, 500_000).unwrap_err();
        match err {
            Error::InsufficientFunds { have, need } => {
                assert_eq!(have, 50_000);
                assert_eq!(need, 500_000);
            }
            other => panic!("expected InsufficientFunds, got {:?}", other),
        }
    }

    /// notes stored before ironwood support (no `pool` field in JSON)
    /// deserialize as orchard and stay spendable.
    #[test]
    fn wallet_note_pool_default_is_orchard() {
        let zeros = vec![0u8; 32];
        let legacy_json = serde_json::json!({
            "value": 123u64,
            "nullifier": zeros,
            "cmx": zeros,
            "block_height": 1u32,
            "is_change": false,
            "recipient": [],
            "rho": zeros,
            "rseed": zeros,
            "position": 7u64,
        });
        let note: crate::wallet::WalletNote = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(note.pool, crate::wallet::Pool::Orchard);
        assert!(select_notes(&[note], 100).is_ok());
    }
}

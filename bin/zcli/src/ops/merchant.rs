use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use crate::address;
use crate::client::ZidecarClient;
use crate::error::Error;
use crate::key::WalletSeed;
use crate::tx;
use crate::wallet::{PaymentRequest, SentTx, Wallet};
use crate::witness;

const MERCHANT_INDEX_BASE: u64 = 1_000_000;
const MARGINAL_FEE: u64 = 5_000;

/// create a new payment request with a unique diversified address
/// deposit=true: permanent deposit address (exchange-style, accumulates deposits)
/// deposit=false: one-time invoice (webshop-style, matches once)
pub fn create_request(
    seed: &WalletSeed,
    amount_zat: u64,
    label: Option<&str>,
    deposit: bool,
    mainnet: bool,
) -> Result<PaymentRequest, Error> {
    let wallet = Wallet::open(&Wallet::default_path())?;
    let id = wallet.next_request_id()?;
    let div_index = MERCHANT_INDEX_BASE + id;

    let (addr, ua_str) = address::orchard_address_at(seed, div_index, mainnet)?;
    let recipient = addr.to_raw_address_bytes().to_vec();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let req = PaymentRequest {
        id,
        diversifier_index: div_index,
        recipient,
        address: ua_str,
        amount_zat,
        label: label.map(String::from),
        created_at: now,
        status: "pending".into(),
        deposit,
        deposits: Vec::new(),
        matched_nullifier: None,
        received_zat: None,
        forward_txid: None,
    };

    wallet.insert_payment_request(&req)?;
    Ok(req)
}

/// scan wallet notes for payments matching pending requests
/// tip = current sync height, min_confirmations = required depth
/// returns number of newly matched payments
pub fn match_payments(tip: u32, min_confirmations: u32) -> Result<usize, Error> {
    let wallet = Wallet::open(&Wallet::default_path())?;
    let pending = wallet.list_payment_requests(Some("pending"))?;
    if pending.is_empty() {
        return Ok(0);
    }

    // build recipient → request id map
    let mut recipient_map: HashMap<Vec<u8>, u64> = HashMap::new();
    for req in &pending {
        recipient_map.insert(req.recipient.clone(), req.id);
    }

    let notes = wallet.all_received_notes()?;
    let mut matched = 0usize;

    for note in &notes {
        if wallet.is_spent(&note.nullifier)? {
            continue;
        }

        // confirmation depth filter
        if tip < note.block_height || (tip - note.block_height) < min_confirmations {
            continue;
        }

        let req_id = match recipient_map.get(&note.recipient) {
            Some(&id) => id,
            None => continue,
        };

        let mut req = wallet.get_payment_request(req_id)?;
        if req.status != "pending" {
            continue;
        }

        let nf_vec = note.nullifier.to_vec();

        if req.deposit {
            // deposit mode: accumulate, stay pending, skip already-seen nullifiers
            if req.deposits.iter().any(|d| d.nullifier == nf_vec) {
                continue;
            }
            req.deposits.push(crate::wallet::Deposit {
                nullifier: nf_vec,
                amount_zat: note.value,
                block_height: note.block_height,
                forward_txid: None,
            });
            req.received_zat = Some(
                req.received_zat.unwrap_or(0) + note.value,
            );
            wallet.update_payment_request(&req)?;
            matched += 1;
        } else {
            // invoice mode: one match, then done
            if req.amount_zat > 0 && note.value < req.amount_zat {
                continue;
            }
            req.status = "paid".into();
            req.matched_nullifier = Some(nf_vec);
            req.received_zat = Some(note.value);
            wallet.update_payment_request(&req)?;
            matched += 1;
            recipient_map.remove(&note.recipient);
        }
    }

    Ok(matched)
}

/// forward all forwardable notes to the cold storage address
/// handles both invoice mode ("paid" requests) and deposit mode (pending with unforwarded deposits)
/// returns (forwarded_count, failed_count)
pub async fn forward_payments(
    seed: &WalletSeed,
    forward_addr: &str,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(usize, usize), Error> {
    let wallet = Wallet::open(&Wallet::default_path())?;
    let mut forwarded = 0usize;
    let mut failed = 0usize;

    // invoice mode: forward "paid" and "forward_failed" requests (single note each)
    let mut forwardable = wallet.list_payment_requests(Some("paid"))?;
    forwardable.extend(wallet.list_payment_requests(Some("forward_failed"))?);
    for req in forwardable {
        let nf_bytes = match &req.matched_nullifier {
            Some(nf) if nf.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(nf);
                arr
            }
            _ => {
                failed += 1;
                continue;
            }
        };

        let note = match wallet.get_note(&nf_bytes) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("request {}: cannot load note: {}", req.id, e);
                failed += 1;
                continue;
            }
        };

        match forward_single_note(seed, &note, forward_addr, endpoint, mainnet, json).await {
            Ok((txid, amount, fee, is_transparent)) => {
                record_sent_tx(&wallet, &txid, amount, fee, forward_addr, is_transparent);
                let mut req = wallet.get_payment_request(req.id)?;
                req.status = "forwarded".into();
                req.forward_txid = Some(txid);
                wallet.update_payment_request(&req)?;
                forwarded += 1;
            }
            Err(e) => {
                eprintln!("request {}: forward failed: {}", req.id, e);
                let mut req = wallet.get_payment_request(req.id)?;
                req.status = "forward_failed".into();
                wallet.update_payment_request(&req)?;
                failed += 1;
            }
        }
    }

    // deposit mode: forward unforwarded deposits (request stays pending)
    let pending = wallet.list_payment_requests(Some("pending"))?;
    for req in pending {
        if !req.deposit || req.deposits.is_empty() {
            continue;
        }

        let mut updated = false;
        let mut req = wallet.get_payment_request(req.id)?;

        for i in 0..req.deposits.len() {
            if req.deposits[i].forward_txid.is_some() {
                continue; // already forwarded
            }

            let nf = &req.deposits[i].nullifier;
            if nf.len() != 32 {
                continue;
            }
            let mut nf_arr = [0u8; 32];
            nf_arr.copy_from_slice(nf);

            let note = match wallet.get_note(&nf_arr) {
                Ok(n) => n,
                Err(_) => continue,
            };

            match forward_single_note(seed, &note, forward_addr, endpoint, mainnet, json).await {
                Ok((txid, amount, fee, is_transparent)) => {
                    record_sent_tx(&wallet, &txid, amount, fee, forward_addr, is_transparent);
                    req.deposits[i].forward_txid = Some(txid);
                    updated = true;
                    forwarded += 1;
                }
                Err(e) => {
                    eprintln!("request {} deposit: forward failed: {}", req.id, e);
                    failed += 1;
                }
            }
        }

        if updated {
            wallet.update_payment_request(&req)?;
        }
    }

    Ok((forwarded, failed))
}

/// process pending/failed withdrawals (FIFO by id)
/// returns (completed, failed, insufficient)
pub async fn process_withdrawals(
    seed: &WalletSeed,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(usize, usize, usize), Error> {
    let wallet = Wallet::open(&Wallet::default_path())?;
    let mut pending = wallet.list_withdrawal_requests(Some("pending"))?;
    pending.extend(wallet.list_withdrawal_requests(Some("failed"))?);
    pending.extend(wallet.list_withdrawal_requests(Some("insufficient"))?);
    pending.sort_by_key(|r| r.id);

    let mut completed = 0usize;
    let mut failed = 0usize;
    let mut insufficient = 0usize;

    for wr in pending {
        let (balance, notes) = wallet.shielded_balance()?;

        let is_transparent = wr.address.starts_with("t1") || wr.address.starts_with("tm");

        // estimate fee for note selection
        let est_fee = if is_transparent {
            super::send::compute_fee(1, 0, 1, true)
        } else {
            super::send::compute_fee(1, 1, 0, true)
        };

        let needed = wr.amount_zat + est_fee;
        if balance < needed {
            let mut wr = wallet.get_withdrawal_request(wr.id)?;
            wr.status = "insufficient".into();
            wr.error = Some(format!("need {} zat, have {}", needed, balance));
            wallet.update_withdrawal_request(&wr)?;
            insufficient += 1;
            continue;
        }

        let selected = match super::send::select_notes(&notes, needed) {
            Ok(s) => s,
            Err(_) => {
                let mut wr = wallet.get_withdrawal_request(wr.id)?;
                wr.status = "insufficient".into();
                wr.error = Some("note selection failed".into());
                wallet.update_withdrawal_request(&wr)?;
                insufficient += 1;
                continue;
            }
        };

        let total_in: u64 = selected.iter().map(|n| n.value).sum();
        let has_change = if is_transparent {
            total_in > wr.amount_zat + super::send::compute_fee(selected.len(), 0, 1, true)
        } else {
            total_in > wr.amount_zat + super::send::compute_fee(selected.len(), 1, 0, true)
        };
        let fee = if is_transparent {
            super::send::compute_fee(selected.len(), 0, 1, has_change)
        } else {
            super::send::compute_fee(selected.len(), 1, 0, has_change)
        };

        if total_in < wr.amount_zat + fee {
            let mut wr = wallet.get_withdrawal_request(wr.id)?;
            wr.status = "insufficient".into();
            wr.error = Some(format!("need {} zat with fee, have {}", wr.amount_zat + fee, total_in));
            wallet.update_withdrawal_request(&wr)?;
            insufficient += 1;
            continue;
        }

        if !json {
            eprintln!(
                "withdrawal #{}: {:.8} ZEC → {}...",
                wr.id,
                wr.amount_zat as f64 / 1e8,
                if wr.address.len() > 20 { &wr.address[..20] } else { &wr.address }
            );
        }

        // reconstruct orchard notes
        let orchard_notes: Vec<orchard::Note> = match selected
            .iter()
            .map(|n| n.reconstruct_note())
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(ns) => ns,
            Err(e) => {
                let mut wr = wallet.get_withdrawal_request(wr.id)?;
                wr.status = "failed".into();
                wr.error = Some(format!("reconstruct note: {}", e));
                wallet.update_withdrawal_request(&wr)?;
                failed += 1;
                continue;
            }
        };

        let client = match crate::client::ZidecarClient::connect(endpoint).await {
            Ok(c) => c,
            Err(e) => {
                let mut wr = wallet.get_withdrawal_request(wr.id)?;
                wr.status = "failed".into();
                wr.error = Some(format!("connect: {}", e));
                wallet.update_withdrawal_request(&wr)?;
                failed += 1;
                continue;
            }
        };

        let (tip, _) = match client.get_tip().await {
            Ok(t) => t,
            Err(e) => {
                let mut wr = wallet.get_withdrawal_request(wr.id)?;
                wr.status = "failed".into();
                wr.error = Some(format!("get_tip: {}", e));
                wallet.update_withdrawal_request(&wr)?;
                failed += 1;
                continue;
            }
        };

        let (anchor, paths) =
            match witness::build_witnesses(&client, &selected, tip, mainnet, json).await {
                Ok(ap) => ap,
                Err(e) => {
                    let mut wr = wallet.get_withdrawal_request(wr.id)?;
                    wr.status = "failed".into();
                    wr.error = Some(format!("witness: {}", e));
                    wallet.update_withdrawal_request(&wr)?;
                    failed += 1;
                    continue;
                }
            };

        let spends: Vec<(orchard::Note, orchard::tree::MerklePath)> =
            orchard_notes.into_iter().zip(paths.into_iter()).collect();

        let seed_bytes = *seed.as_bytes();
        let anchor_height = tip;
        let addr = wr.address.clone();
        let amount = wr.amount_zat;

        let tx_result = if is_transparent {
            let t_outputs = vec![(addr.clone(), amount)];
            tokio::task::spawn_blocking(move || {
                let seed = WalletSeed::from_bytes(seed_bytes);
                tx::build_orchard_spend_tx(
                    &seed, &spends, &t_outputs, &[], fee, anchor, anchor_height, mainnet,
                )
            })
            .await
            .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))
            .and_then(|r| r)
        } else {
            let recipient_addr = match tx::parse_orchard_address(&addr, mainnet) {
                Ok(a) => a,
                Err(e) => {
                    let mut wr = wallet.get_withdrawal_request(wr.id)?;
                    wr.status = "failed".into();
                    wr.error = Some(format!("parse address: {}", e));
                    wallet.update_withdrawal_request(&wr)?;
                    failed += 1;
                    continue;
                }
            };
            let memo = [0u8; 512];
            let z_outputs = vec![(recipient_addr, amount, memo)];
            tokio::task::spawn_blocking(move || {
                let seed = WalletSeed::from_bytes(seed_bytes);
                tx::build_orchard_spend_tx(
                    &seed, &spends, &[], &z_outputs, fee, anchor, anchor_height, mainnet,
                )
            })
            .await
            .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))
            .and_then(|r| r)
        };

        let tx_bytes = match tx_result {
            Ok(b) => b,
            Err(e) => {
                let mut wr = wallet.get_withdrawal_request(wr.id)?;
                wr.status = "failed".into();
                wr.error = Some(format!("build tx: {}", e));
                wallet.update_withdrawal_request(&wr)?;
                failed += 1;
                continue;
            }
        };

        match client.send_transaction(tx_bytes).await {
            Ok(result) if result.is_success() => {
                // mark input notes as spent to prevent double-spend within this cycle
                for note in &selected {
                    let _ = wallet.mark_spent(&note.nullifier);
                }
                record_sent_tx(&wallet, &result.txid, amount, fee, &addr, is_transparent);
                let mut wr = wallet.get_withdrawal_request(wr.id)?;
                wr.status = "completed".into();
                wr.txid = Some(result.txid);
                wr.fee_zat = Some(fee);
                wr.error = None;
                wallet.update_withdrawal_request(&wr)?;
                completed += 1;
            }
            Ok(result) => {
                let mut wr = wallet.get_withdrawal_request(wr.id)?;
                wr.status = "failed".into();
                wr.error = Some(format!("broadcast ({}): {}", result.error_code, result.error_message));
                wallet.update_withdrawal_request(&wr)?;
                failed += 1;
            }
            Err(e) => {
                let mut wr = wallet.get_withdrawal_request(wr.id)?;
                wr.status = "failed".into();
                wr.error = Some(format!("send: {}", e));
                wallet.update_withdrawal_request(&wr)?;
                failed += 1;
            }
        }
    }

    Ok((completed, failed, insufficient))
}

/// forward a single note to the given address
async fn forward_single_note(
    seed: &WalletSeed,
    note: &crate::wallet::WalletNote,
    forward_addr: &str,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(String, u64, u64, bool), Error> {
    // 2 orchard actions (1 spend + 1 output, padded to min 2) = 10,000 zat fee
    let fee = MARGINAL_FEE * 2;
    if note.value <= fee {
        return Err(Error::Transaction(format!(
            "note value {} zat <= fee {} zat, skipping",
            note.value, fee
        )));
    }

    let send_amount = note.value - fee;
    let orchard_note = note.reconstruct_note()?;

    let client = ZidecarClient::connect(endpoint).await?;
    let (tip, _) = client.get_tip().await?;

    if !json {
        eprintln!(
            "forwarding {:.8} ZEC to {}...",
            send_amount as f64 / 1e8,
            if forward_addr.len() > 20 {
                &forward_addr[..20]
            } else {
                forward_addr
            }
        );
    }

    let (anchor, paths) =
        witness::build_witnesses(&client, &[note.clone()], tip, mainnet, json).await?;

    let spends = vec![(orchard_note, paths.into_iter().next().unwrap())];

    // determine if forwarding to transparent or shielded
    let is_transparent =
        forward_addr.starts_with("t1") || forward_addr.starts_with("tm");

    let seed_bytes = *seed.as_bytes();
    let anchor_height = tip;
    let fwd = forward_addr.to_string();

    let tx_bytes = if is_transparent {
        let t_outputs = vec![(fwd, send_amount)];
        tokio::task::spawn_blocking(move || {
            let seed = WalletSeed::from_bytes(seed_bytes);
            tx::build_orchard_spend_tx(
                &seed,
                &spends,
                &t_outputs,
                &[],
                fee,
                anchor,
                anchor_height,
                mainnet,
            )
        })
        .await
        .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??
    } else {
        let recipient_addr = tx::parse_orchard_address(&fwd, mainnet)?;
        let memo = [0u8; 512];
        let z_outputs = vec![(recipient_addr, send_amount, memo)];
        tokio::task::spawn_blocking(move || {
            let seed = WalletSeed::from_bytes(seed_bytes);
            tx::build_orchard_spend_tx(
                &seed,
                &spends,
                &[],
                &z_outputs,
                fee,
                anchor,
                anchor_height,
                mainnet,
            )
        })
        .await
        .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??
    };

    let result = client.send_transaction(tx_bytes).await?;

    if result.is_success() {
        Ok((result.txid, send_amount, fee, is_transparent))
    } else {
        Err(Error::Transaction(format!(
            "broadcast failed ({}): {}",
            result.error_code, result.error_message
        )))
    }
}

fn record_sent_tx(wallet: &Wallet, txid: &str, amount: u64, fee: u64, recipient: &str, is_transparent: bool) {
    let _ = wallet.insert_sent_tx(&SentTx {
        txid: txid.to_string(),
        amount,
        fee,
        recipient: recipient.to_string(),
        tx_type: if is_transparent { "z\u{2192}t".into() } else { "z\u{2192}z".into() },
        block_height: 0,
        memo: None,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    });
}

/// resolve forward address: flag > env (via clap) > wallet db
pub fn resolve_forward_address(flag: Option<&str>) -> Result<Option<String>, Error> {
    if let Some(addr) = flag {
        if !addr.is_empty() {
            return Ok(Some(addr.to_string()));
        }
    }
    let wallet = Wallet::open(&Wallet::default_path())?;
    wallet.get_forward_address()
}

/// atomically write data to path (write to tmp, fsync, rename)
pub fn atomic_write(path: &str, data: &[u8]) -> Result<(), Error> {
    let tmp = format!("{}.tmp", path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| Error::Other(format!("open {}: {}", tmp, e)))?;
    f.write_all(data)
        .map_err(|e| Error::Other(format!("write {}: {}", tmp, e)))?;
    f.sync_all()
        .map_err(|e| Error::Other(format!("fsync {}: {}", tmp, e)))?;
    drop(f);
    std::fs::rename(&tmp, path)
        .map_err(|e| Error::Other(format!("rename {} -> {}: {}", tmp, path, e)))?;
    Ok(())
}

/// serialize all payment + withdrawal requests to JSON (for --dir file push)
pub fn requests_json() -> String {
    let wallet = match Wallet::open(&Wallet::default_path()) {
        Ok(w) => w,
        Err(_) => return r#"{"payments":[],"withdrawals":[]}"#.into(),
    };
    let reqs = wallet.list_payment_requests(None).unwrap_or_default();
    // NOTE: addresses intentionally omitted from state dump.
    // the frontend already knows the address from the create call.
    // broadcasting all diversified addresses together in one file
    // makes wallet linkability trivial for anyone who reads the file.
    let payments: Vec<_> = reqs
        .iter()
        .map(|r| {
            let mut obj = serde_json::json!({
                "id": r.id,
                "amount_zat": r.amount_zat,
                "label": r.label,
                "status": r.status,
                "deposit": r.deposit,
                "created_at": r.created_at,
                "received_zat": r.received_zat,
            });
            if r.deposit && !r.deposits.is_empty() {
                obj["deposits"] = serde_json::json!(r.deposits.iter().map(|d| {
                    serde_json::json!({
                        "amount_zat": d.amount_zat,
                        "block_height": d.block_height,
                        "forwarded": d.forward_txid.is_some(),
                    })
                }).collect::<Vec<_>>());
                obj["deposit_count"] = r.deposits.len().into();
            }
            obj
        })
        .collect();

    let wrs = wallet.list_withdrawal_requests(None).unwrap_or_default();
    // address intentionally omitted (same privacy rationale)
    let withdrawals: Vec<_> = wrs
        .iter()
        .map(|w| {
            serde_json::json!({
                "id": w.id,
                "amount_zat": w.amount_zat,
                "status": w.status,
                "label": w.label,
                "created_at": w.created_at,
                "txid": w.txid,
                "fee_zat": w.fee_zat,
            })
        })
        .collect();

    serde_json::to_string(&serde_json::json!({
        "payments": payments,
        "withdrawals": withdrawals,
    }))
    .unwrap_or_else(|_| r#"{"payments":[],"withdrawals":[]}"#.into())
}

/// POST payment state to webhook URL with HMAC-SHA256 signature
/// signature header: X-Signature: t=<unix_ts>,v1=<hex_hmac>
/// signed message: "<timestamp>.<body>" (same as Stripe's scheme)
pub async fn post_webhook(url: &str, secret: &str, body: &str) -> Result<(), Error> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let signed_payload = format!("{}.{}", timestamp, body);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| Error::Other(format!("hmac init: {}", e)))?;
    mac.update(signed_payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    let header_val = format!("t={},v1={}", timestamp, sig);

    let client = reqwest::Client::new();
    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Signature", &header_val)
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| Error::Network(format!("webhook POST: {}", e)))?;

    if !resp.status().is_success() {
        return Err(Error::Network(format!(
            "webhook returned {}",
            resp.status()
        )));
    }

    Ok(())
}

/// parse amount string to zatoshi using integer arithmetic (no float precision issues)
pub fn parse_amount(s: &str) -> Result<u64, Error> {
    if let Some(dot_pos) = s.find('.') {
        let int_part: u64 = if dot_pos == 0 {
            0
        } else {
            s[..dot_pos]
                .parse()
                .map_err(|_| Error::Transaction(format!("invalid amount: {}", s)))?
        };
        let frac_str = &s[dot_pos + 1..];
        if frac_str.is_empty() {
            return Err(Error::Transaction(format!("invalid amount: {}", s)));
        }
        if frac_str.len() > 8 {
            return Err(Error::Transaction(format!(
                "too many decimal places (max 8): {}",
                s
            )));
        }
        // pad fractional part to 8 digits and parse as zatoshi
        let padded = format!("{:0<8}", frac_str);
        let frac_part: u64 = padded
            .parse()
            .map_err(|_| Error::Transaction(format!("invalid amount: {}", s)))?;
        Ok(int_part * 100_000_000 + frac_part)
    } else {
        s.parse()
            .map_err(|_| Error::Transaction(format!("invalid amount: {}", s)))
    }
}

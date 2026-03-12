// airgap signing via zigner QR protocol
//
// flow:
// 1. build PCZT bundle (with ZK proof) on hot machine
// 2. display QR: sighash + alphas for zigner to scan
// 3. zigner signs on cold device, displays response QR
// 4. user pastes response hex into zcli
// 5. apply external signatures, finalize, broadcast

use orchard::keys::{FullViewingKey, SpendingKey};

use crate::client::ZidecarClient;
use crate::error::Error;
use crate::key::WalletSeed;
use crate::ops::send::{compute_fee, select_notes};
use crate::pczt;
use crate::tx;
use crate::wallet::Wallet;
use crate::witness;

// re-export for external callers
pub use crate::pczt::parse_fvk_export;

/// display QR code on terminal using unicode half-blocks
fn display_qr(data: &[u8]) {
    use qrcode::QrCode;
    let code = match QrCode::new(hex::encode(data).as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("qr encode failed: {}", e);
            return;
        }
    };
    let width = code.width();
    let modules = code.into_colors();

    let dark = |r: usize, c: usize| -> bool {
        if r < width && c < width {
            modules[r * width + c] == qrcode::Color::Dark
        } else {
            false
        }
    };

    let quiet = 1;
    let total = width + quiet * 2;
    for row in (0..total).step_by(2) {
        for col in 0..total {
            let r0 = row.wrapping_sub(quiet);
            let c0 = col.wrapping_sub(quiet);
            let r1 = r0.wrapping_add(1);
            let top = dark(r0, c0);
            let bot = dark(r1, c0);
            match (top, bot) {
                (true, true) => print!("\u{2588}"),
                (true, false) => print!("\u{2580}"),
                (false, true) => print!("\u{2584}"),
                (false, false) => print!(" "),
            }
        }
        println!();
    }
    println!();
}

/// read response: try webcam QR scan, fall back to hex paste
fn read_response() -> Result<Vec<u8>, Error> {
    #[cfg(target_os = "linux")]
    {
        let cam_device = std::env::var("ZCLI_CAM").unwrap_or_else(|_| "/dev/video0".into());
        if std::path::Path::new(&cam_device).exists() {
            eprintln!("hold zigner QR up to camera ({})...", cam_device);
            eprintln!("(press Ctrl+C to cancel, or set ZCLI_CAM=none to skip)");
            if cam_device != "none" {
                match crate::cam::scan_qr(&cam_device, 60) {
                    Ok(data) => {
                        eprintln!("\rQR decoded ({} bytes)                    ", data.len());
                        return Ok(data);
                    }
                    Err(e) => {
                        eprintln!("\rcamera scan failed: {}                    ", e);
                        eprintln!("falling back to manual input...");
                    }
                }
            }
        }
    }

    read_response_manual()
}

/// manual response input: hex string or file path
fn read_response_manual() -> Result<Vec<u8>, Error> {
    use std::io::{self, BufRead};

    eprintln!("enter zigner response (hex or file path):");
    let stdin = io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .ok_or_else(|| Error::Other("no input".into()))?
        .map_err(|e| Error::Other(format!("read stdin: {}", e)))?;

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(Error::Other("empty response".into()));
    }

    if trimmed.starts_with('/') || trimmed.starts_with('.') || trimmed.starts_with('~') {
        let path = if let Some(rest) = trimmed.strip_prefix("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                format!("{}/{}", home.to_string_lossy(), rest)
            } else {
                trimmed.to_string()
            }
        } else {
            trimmed.to_string()
        };
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| Error::Other(format!("read {}: {}", path, e)))?;
        hex::decode(contents.trim())
            .map_err(|e| Error::Other(format!("invalid hex in file: {}", e)))
    } else {
        hex::decode(trimmed).map_err(|e| Error::Other(format!("invalid hex: {}", e)))
    }
}

/// send airgap with seed (hot wallet has spending key)
#[allow(clippy::too_many_arguments)]
pub async fn send_airgap(
    seed: &WalletSeed,
    amount_str: &str,
    recipient: &str,
    memo: Option<&str>,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    let coin_type = if mainnet { 133 } else { 1 };
    let sk = SpendingKey::from_zip32_seed(seed.as_bytes(), coin_type, zip32::AccountId::ZERO)
        .map_err(|_| Error::Transaction("failed to derive spending key".into()))?;
    let fvk = FullViewingKey::from(&sk);
    send_airgap_with_fvk(&fvk, amount_str, recipient, memo, endpoint, mainnet, json).await
}

/// send airgap with FVK only (watch-only wallet, signing delegated to zigner)
#[allow(clippy::too_many_arguments)]
pub async fn send_airgap_with_fvk(
    fvk: &FullViewingKey,
    amount_str: &str,
    recipient: &str,
    memo: Option<&str>,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    if recipient.starts_with("t1") || recipient.starts_with("tm") {
        return send_airgap_to_transparent_fvk(fvk, amount_str, recipient, endpoint, mainnet, json)
            .await;
    }
    if !(recipient.starts_with("u1") || recipient.starts_with("utest1")) {
        return Err(Error::Address(format!(
            "unrecognized address format: {}",
            recipient
        )));
    }

    send_airgap_shielded_fvk(fvk, amount_str, recipient, memo, endpoint, mainnet, json).await
}

/// z→z airgap send (FVK-based)
async fn send_airgap_shielded_fvk(
    fvk: &FullViewingKey,
    amount_str: &str,
    recipient: &str,
    memo: Option<&str>,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    let amount_zat = crate::ops::send::parse_amount(amount_str)?;
    let recipient_addr = tx::parse_orchard_address(recipient, mainnet)?;

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

    if !json {
        eprintln!(
            "airgap: {:.8} ZEC → {}... ({} notes, fee {:.8} ZEC)",
            amount_zat as f64 / 1e8,
            &recipient[..20.min(recipient.len())],
            selected.len(),
            fee as f64 / 1e8
        );
    }

    let orchard_notes: Vec<orchard::Note> = selected
        .iter()
        .map(|n| n.reconstruct_note())
        .collect::<Result<_, _>>()?;

    let client = ZidecarClient::connect(endpoint).await?;
    let (tip, _) = client.get_tip().await?;

    if !json {
        eprintln!("building merkle witnesses...");
    }
    let (anchor, paths) = witness::build_witnesses(&client, &selected, tip, mainnet, json).await?;

    let spends: Vec<(orchard::Note, orchard::tree::MerklePath)> =
        orchard_notes.into_iter().zip(paths).collect();

    let mut memo_bytes = [0u8; 512];
    if let Some(text) = memo {
        let bytes = text.as_bytes();
        let len = bytes.len().min(512);
        memo_bytes[..len].copy_from_slice(&bytes[..len]);
    }

    if !json {
        eprintln!("building PCZT bundle (halo 2 proving)...");
    }

    let fvk_bytes = fvk.to_bytes();
    let anchor_height = tip;
    let recipient_str = recipient.to_string();

    let (qr_data, pczt_state) = tokio::task::spawn_blocking(move || {
        pczt::build_pczt_and_qr(
            &fvk_bytes,
            &spends,
            &[(recipient_addr, amount_zat, memo_bytes)],
            &[],
            change,
            anchor,
            anchor_height,
            mainnet,
        )
    })
    .await
    .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "action": "sign_request",
                "qr_hex": hex::encode(&qr_data),
                "sighash": hex::encode(pczt_state.sighash),
                "actions": pczt_state.alphas.len(),
            })
        );
    } else {
        eprintln!("scan this QR with zigner:");
        display_qr(&qr_data);
        eprintln!("sighash: {}", hex::encode(pczt_state.sighash));
        eprintln!("{} action(s) require signing", pczt_state.alphas.len());
    }

    let response_bytes = if json {
        use std::io::{self, Read};
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| Error::Other(format!("read stdin: {}", e)))?;
        hex::decode(buf.trim()).map_err(|e| Error::Other(format!("invalid hex: {}", e)))?
    } else {
        read_response()?
    };

    let (orchard_sigs, resp_sighash) = pczt::parse_sign_response(&response_bytes)?;

    if resp_sighash != pczt_state.sighash {
        return Err(Error::Transaction("response sighash does not match".into()));
    }

    if orchard_sigs.len() != pczt_state.alphas.len() {
        return Err(Error::Transaction(format!(
            "expected {} orchard signatures, got {}",
            pczt_state.alphas.len(),
            orchard_sigs.len()
        )));
    }

    if !json {
        eprintln!("applying signatures and finalizing...");
    }

    let tx_bytes =
        tokio::task::spawn_blocking(move || pczt::complete_pczt_tx(pczt_state, &orchard_sigs))
            .await
            .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    let result = client.send_transaction(tx_bytes).await?;

    if result.is_success() {
        let w = Wallet::open(&Wallet::default_path())?;
        let _ = w.insert_sent_tx(&crate::wallet::SentTx {
            txid: result.txid.clone(),
            amount: amount_zat,
            fee,
            recipient: recipient_str.clone(),
            tx_type: "z\u{2192}z (airgap)".into(),
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
                "amount_zat": amount_zat,
                "fee_zat": fee,
                "recipient": recipient_str,
                "type": "z→z (airgap)",
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

/// z→t airgap send (FVK-based)
async fn send_airgap_to_transparent_fvk(
    fvk: &FullViewingKey,
    amount_str: &str,
    recipient: &str,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    let amount_zat = crate::ops::send::parse_amount(amount_str)?;

    let selected = {
        let wallet = Wallet::open(&Wallet::default_path())?;
        let (balance, notes) = wallet.shielded_balance()?;
        let est_fee = compute_fee(1, 0, 1, true);
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
    let has_change = total_in > amount_zat + compute_fee(selected.len(), 0, 1, true);
    let fee = compute_fee(selected.len(), 0, 1, has_change);
    if total_in < amount_zat + fee {
        return Err(Error::InsufficientFunds {
            have: total_in,
            need: amount_zat + fee,
        });
    }
    let change = total_in - amount_zat - fee;

    if !json {
        eprintln!(
            "airgap: {:.8} ZEC → {} ({} notes, fee {:.8} ZEC)",
            amount_zat as f64 / 1e8,
            recipient,
            selected.len(),
            fee as f64 / 1e8
        );
    }

    let orchard_notes: Vec<orchard::Note> = selected
        .iter()
        .map(|n| n.reconstruct_note())
        .collect::<Result<_, _>>()?;

    let client = ZidecarClient::connect(endpoint).await?;
    let (tip, _) = client.get_tip().await?;

    if !json {
        eprintln!("building merkle witnesses...");
    }
    let (anchor, paths) = witness::build_witnesses(&client, &selected, tip, mainnet, json).await?;

    let spends: Vec<(orchard::Note, orchard::tree::MerklePath)> =
        orchard_notes.into_iter().zip(paths).collect();

    if !json {
        eprintln!("building PCZT bundle (halo 2 proving)...");
    }

    let fvk_bytes = fvk.to_bytes();
    let t_recipient = recipient.to_string();
    let recipient_str = recipient.to_string();

    let (qr_data, pczt_state) = tokio::task::spawn_blocking(move || {
        pczt::build_pczt_and_qr(
            &fvk_bytes,
            &spends,
            &[],
            &[(t_recipient, amount_zat)],
            change,
            anchor,
            tip,
            mainnet,
        )
    })
    .await
    .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "action": "sign_request",
                "qr_hex": hex::encode(&qr_data),
                "sighash": hex::encode(pczt_state.sighash),
                "actions": pczt_state.alphas.len(),
            })
        );
    } else {
        eprintln!("scan this QR with zigner:");
        display_qr(&qr_data);
        eprintln!("sighash: {}", hex::encode(pczt_state.sighash));
        eprintln!("{} action(s) require signing", pczt_state.alphas.len());
    }

    let response_bytes = if json {
        use std::io::{self, Read};
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| Error::Other(format!("read stdin: {}", e)))?;
        hex::decode(buf.trim()).map_err(|e| Error::Other(format!("invalid hex: {}", e)))?
    } else {
        read_response()?
    };

    let (orchard_sigs, resp_sighash) = pczt::parse_sign_response(&response_bytes)?;

    if resp_sighash != pczt_state.sighash {
        return Err(Error::Transaction("response sighash does not match".into()));
    }

    if orchard_sigs.len() != pczt_state.alphas.len() {
        return Err(Error::Transaction(format!(
            "expected {} orchard signatures, got {}",
            pczt_state.alphas.len(),
            orchard_sigs.len()
        )));
    }

    if !json {
        eprintln!("applying signatures and finalizing...");
    }

    let tx_bytes =
        tokio::task::spawn_blocking(move || pczt::complete_pczt_tx(pczt_state, &orchard_sigs))
            .await
            .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    let result = client.send_transaction(tx_bytes).await?;

    if result.is_success() {
        let w = Wallet::open(&Wallet::default_path())?;
        let _ = w.insert_sent_tx(&crate::wallet::SentTx {
            txid: result.txid.clone(),
            amount: amount_zat,
            fee,
            recipient: recipient_str.clone(),
            tx_type: "z\u{2192}t (airgap)".into(),
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
                "amount_zat": amount_zat,
                "fee_zat": fee,
                "recipient": recipient_str,
                "type": "z→t (airgap)",
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

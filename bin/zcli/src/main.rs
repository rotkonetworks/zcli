mod cli;

use std::sync::{Arc, Mutex};

use clap::Parser;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[cfg(target_os = "linux")]
use zecli::cam;
use zecli::{address, client, frost_qr, key, notes_export, ops, quic, wallet, witness};

use cli::{Cli, Command, InitAction, MerchantAction, MultisigAction, ServiceAction, SignerAction, TxAction, ViewAction};
use zecli::error::Error;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let code = match run(&cli).await {
        Ok(()) => 0,
        Err(e) => {
            let code = e.exit_code();
            if cli.json {
                let msg = serde_json::json!({ "error": e.to_string() });
                eprintln!("{}", msg);
            } else {
                eprintln!("error: {}", e);
            }
            code
        }
    };
    std::process::exit(code);
}

async fn run(cli: &Cli) -> Result<(), Error> {
    let mainnet = cli.is_mainnet();
    wallet::set_watch_mode(cli.watch);

    match &cli.command {
        Command::View { action } => {
            // Auto-sync if wallet has never been synced
            ensure_synced(cli, mainnet).await?;
            match action {
            ViewAction::Balance => cmd_balance(cli, mainnet).await,
            ViewAction::Address { transparent, ephemeral } => {
                if *transparent {
                    cmd_address(cli, mainnet, false, true)
                } else {
                    cmd_receive(cli, mainnet, *ephemeral)
                }
            }
            ViewAction::Notes => cmd_notes(cli),
            ViewAction::History => cmd_history(cli),
            ViewAction::Export => {
                if cli.watch {
                    return Err(Error::Other(
                        "watch-only wallet: export requires spending key".into(),
                    ));
                }
                let seed = load_seed(cli)?;
                ops::export::export(&seed, mainnet, cli.json)
            }
        }},
        Command::Transaction { action } => match action {
            TxAction::Send { amount, recipient, memo, airgap } => {
                if cli.watch {
                    let fvk = load_fvk(cli, mainnet)?;
                    ops::airgap::send_airgap_with_fvk(
                        &fvk, amount, recipient, memo.as_deref(),
                        &cli.endpoint, mainnet, cli.json,
                    ).await
                } else if *airgap {
                    let seed = load_seed(cli)?;
                    ops::airgap::send_airgap(
                        &seed, amount, recipient, memo.as_deref(),
                        &cli.endpoint, mainnet, cli.json,
                    ).await
                } else {
                    let seed = load_seed(cli)?;
                    ops::send::send(
                        &seed, amount, recipient, memo.as_deref(),
                        &cli.endpoint, mainnet, cli.json,
                    ).await
                }
            }
            TxAction::Shield { fee } => {
                if cli.watch {
                    return Err(Error::Other(
                        "watch-only wallet: shielding requires spending key".into(),
                    ));
                }
                let seed = load_seed(cli)?;
                ops::shield::shield(&seed, &cli.endpoint, *fee, mainnet, cli.json).await
            }
        },
        Command::Signer { action } => match action {
            SignerAction::ExportNotes { interval, fragment_size, attestation, transport, zt_frame_size, zt_redundancy } => {
                cmd_export_notes(cli, mainnet, *interval, *fragment_size, attestation.as_deref(), transport, *zt_frame_size, *zt_redundancy).await
            }
            SignerAction::Scan { device, timeout } => cmd_scan(cli, device, *timeout),
            SignerAction::Verify => cmd_verify(cli, mainnet).await,
        },
        Command::Init { action } => match action {
            InitAction::Create { words } => cmd_init_create(cli, *words),
            InitAction::ImportFvk { hex } => cmd_import_fvk(cli, mainnet, hex.as_deref()),
            InitAction::Sync { from, position, full, no_verify } => {
                if *full {
                    if !cli.json {
                        eprintln!("full rescan from orchard activation...");
                    }
                }
                if *no_verify {
                    std::env::set_var("ZCLI_NO_VERIFY", "1");
                }
                cmd_sync(cli, mainnet, *from, *position).await
            }
        },
        Command::Service { action } => match action {
            ServiceAction::Merchant { action } => cmd_merchant(cli, mainnet, action).await,
            ServiceAction::Board { port, interval, dir } => {
                let seed = load_seed(cli)?;
                cmd_board(cli, &seed, mainnet, *port, *interval, dir.as_deref()).await
            }
            ServiceAction::TreeInfo { height } => cmd_tree_info(cli, *height).await,
        },
        Command::Multisig { action } => cmd_multisig(cli, action),
    }
}

fn cmd_address(
    cli: &Cli,
    mainnet: bool,
    show_orchard: bool,
    show_transparent: bool,
) -> Result<(), Error> {
    let (show_o, show_t) = if !show_orchard && !show_transparent {
        (true, true)
    } else {
        (show_orchard, show_transparent)
    };

    let mut result = serde_json::Map::new();

    if show_t {
        if cli.watch {
            if cli.json {
                result.insert(
                    "transparent".into(),
                    serde_json::Value::String("(watch-only: no transparent key)".into()),
                );
            } else {
                eprintln!("(watch-only wallet: transparent address unavailable)");
            }
        } else {
            let seed = load_seed(cli)?;
            let taddr = address::transparent_address(&seed, mainnet)?;
            if cli.json {
                result.insert("transparent".into(), serde_json::Value::String(taddr));
            } else {
                println!("{}", taddr);
            }
        }
    }

    if show_o {
        let uaddr = if cli.watch {
            let fvk = load_fvk(cli, mainnet)?;
            address::orchard_address_from_fvk(&fvk, mainnet)?
        } else {
            let seed = load_seed(cli)?;
            address::orchard_address(&seed, mainnet)?
        };
        if cli.json {
            result.insert("orchard".into(), serde_json::Value::String(uaddr));
        } else {
            println!("{}", uaddr);
        }
    }

    if cli.json {
        println!("{}", serde_json::Value::Object(result));
    }

    Ok(())
}

fn cmd_receive(cli: &Cli, mainnet: bool, ephemeral: bool) -> Result<(), Error> {
    let uaddr = if cli.watch {
        let fvk = load_fvk(cli, mainnet)?;
        address::orchard_address_from_fvk(&fvk, mainnet)?
    } else {
        let seed = load_seed(cli)?;
        address::orchard_address(&seed, mainnet)?
    };

    if cli.json {
        println!("{}", serde_json::json!({ "address": uaddr }));
        return Ok(());
    }

    if ephemeral {
        println!("{}", uaddr);
        return Ok(());
    }

    // render unified address as terminal QR using unicode half-blocks
    use qrcode::QrCode;
    let code =
        QrCode::new(uaddr.as_bytes()).map_err(|e| Error::Other(format!("qr encode: {}", e)))?;
    let width = code.width();
    let modules = code.into_colors();

    let dark = |r: usize, c: usize| -> bool {
        if r < width && c < width {
            modules[r * width + c] == qrcode::Color::Dark
        } else {
            false
        }
    };

    // quiet zone + half-block rendering (2 rows per line using ▀▄█ )
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
                (true, true) => print!("\u{2588}"),  // █
                (true, false) => print!("\u{2580}"), // ▀
                (false, true) => print!("\u{2584}"), // ▄
                (false, false) => print!(" "),
            }
        }
        println!();
    }

    println!();
    println!("{}", uaddr);

    Ok(())
}

async fn cmd_balance(cli: &Cli, mainnet: bool) -> Result<(), Error> {
    let bal = if cli.watch {
        // watch-only: shielded balance only (from local wallet db)
        let wallet = wallet::Wallet::open(&wallet::Wallet::default_path())?;
        let (shielded, _) = wallet.shielded_balance()?;
        ops::balance::Balance {
            transparent: 0,
            shielded,
            total: shielded,
        }
    } else {
        let seed = load_seed(cli)?;
        ops::balance::get_balance(&seed, &cli.endpoint, mainnet).await?
    };

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "transparent": bal.transparent,
                "shielded": bal.shielded,
                "total": bal.total,
                "transparent_zec": format!("{:.8}", bal.transparent as f64 / 1e8),
                "shielded_zec": format!("{:.8}", bal.shielded as f64 / 1e8),
                "total_zec": format!("{:.8}", bal.total as f64 / 1e8),
            })
        );
    } else {
        let t = bal.transparent as f64 / 1e8;
        let s = bal.shielded as f64 / 1e8;
        let total = bal.total as f64 / 1e8;
        println!("transparent: {:.8} ZEC", t);
        println!("shielded:    {:.8} ZEC", s);
        println!("total:       {:.8} ZEC", total);
    }

    Ok(())
}

/// Auto-sync if wallet has never been synced. For view commands.
async fn ensure_synced(cli: &Cli, mainnet: bool) -> Result<(), Error> {
    let wallet = wallet::Wallet::open(&wallet::Wallet::default_path())?;
    let height = wallet.sync_height()?;
    let birth = wallet.birth_height()?;
    let has_notes = wallet.shielded_balance().map(|(b, _)| b > 0).unwrap_or(false);
    drop(wallet);

    if height > 0 || has_notes {
        // Already synced or has notes from board — nothing to do
        return Ok(());
    }

    // Never synced, no notes — first use
    if birth == 0 {
        if cli.json {
            // Non-interactive: default to new wallet (birth = current tip)
            if let Ok(c) = client::ZidecarClient::connect(&cli.endpoint).await {
                if let Ok((tip, _)) = c.get_tip().await {
                    let w = wallet::Wallet::open(&wallet::Wallet::default_path())?;
                    let _ = w.set_birth_height(tip);
                    drop(w);
                }
            }
        } else {
            // Interactive: ask user
            eprint!("first use — is this a new wallet? [Y/n] ");
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
            let is_new = input.trim().is_empty() || input.trim().to_lowercase().starts_with('y');

            if is_new {
                if let Ok(c) = client::ZidecarClient::connect(&cli.endpoint).await {
                    if let Ok((tip, _)) = c.get_tip().await {
                        let w = wallet::Wallet::open(&wallet::Wallet::default_path())?;
                        let _ = w.set_birth_height(tip);
                        drop(w);
                        eprintln!("birth height set to {} (current tip)", tip);
                    }
                }
            } else {
                eprintln!("restoring wallet — will scan from orchard activation (this takes a while)");
            }
        }
    }

    if !cli.json {
        eprintln!("syncing...");
    }
    cmd_sync(cli, mainnet, None, None).await?;
    Ok(())
}

async fn cmd_sync(
    cli: &Cli,
    mainnet: bool,
    from: Option<u32>,
    position: Option<u64>,
) -> Result<(), Error> {
    let found = if cli.watch {
        let fvk = load_fvk(cli, mainnet)?;
        ops::sync::sync_with_fvk(
            &fvk,
            &cli.endpoint,
            &cli.verify_endpoints,
            mainnet,
            cli.json,
            from,
            position,
        )
        .await?
    } else {
        match load_seed(cli) {
            Ok(seed) => {
                // auto-store FVK in watch wallet for future non-interactive syncs
                ensure_fvk_cached(&seed, mainnet);
                ops::sync::sync(
                    &seed,
                    &cli.endpoint,
                    &cli.verify_endpoints,
                    mainnet,
                    cli.json,
                    from,
                    position,
                )
                .await?
            }
            Err(e) if e.is_key_error() => {
                // SSH key failed (encrypted, wrong type, etc) — try watch wallet FVK
                match load_fvk(cli, mainnet) {
                    Ok(fvk) => {
                        eprintln!("SSH key unavailable ({}), using watch-only FVK", e);
                        ops::sync::sync_with_fvk(
                            &fvk,
                            &cli.endpoint,
                            &cli.verify_endpoints,
                            mainnet,
                            cli.json,
                            from,
                            position,
                        )
                        .await?
                    }
                    Err(_) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }
    };

    if cli.json {
        println!("{}", serde_json::json!({ "notes_found": found }));
    }

    Ok(())
}

async fn cmd_verify(cli: &Cli, mainnet: bool) -> Result<(), Error> {
    let zidecar = client::ZidecarClient::connect(&cli.endpoint).await?;
    let (tip, tip_hash) = zidecar.get_tip().await?;

    let activation = if mainnet {
        zync_core::ORCHARD_ACTIVATION_HEIGHT
    } else {
        zync_core::ORCHARD_ACTIVATION_HEIGHT_TESTNET
    };
    let network = if mainnet { "mainnet" } else { "testnet" };

    if !cli.json {
        eprintln!("zcli verify - trustless verification chain");
        eprintln!("network:  {}", network);
        eprintln!("endpoint: {}", cli.endpoint);
        eprintln!("tip:      {} ({})", tip, hex::encode(&tip_hash[..8]));
        eprintln!();
    }

    // step 1: trust anchor
    if !cli.json {
        eprintln!("1. trust anchor");
        eprintln!(
            "   hardcoded orchard activation hash at height {}",
            activation
        );
    }
    if mainnet {
        let blocks = zidecar.get_compact_blocks(activation, activation).await?;
        if blocks.is_empty() || blocks[0].hash != zync_core::ACTIVATION_HASH_MAINNET {
            return Err(Error::Other(
                "activation block hash mismatch — server not on canonical chain".into(),
            ));
        }
        if !cli.json {
            eprintln!("   server returned: {}", hex::encode(&blocks[0].hash[..8]));
            eprintln!(
                "   expected:        {}",
                hex::encode(&zync_core::ACTIVATION_HASH_MAINNET[..8])
            );
            eprintln!("   PASS");
        }
    }

    // step 2: cross-verification
    let endpoints: Vec<&str> = cli
        .verify_endpoints
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if !cli.json {
        eprintln!();
        eprintln!(
            "2. cross-verification ({} independent node{})",
            endpoints.len(),
            if endpoints.len() == 1 { "" } else { "s" }
        );
    }
    if !endpoints.is_empty() {
        let mut agree = 0u32;
        let mut disagree = 0u32;
        for &ep in &endpoints {
            let lwd = match client::LightwalletdClient::connect(ep).await {
                Ok(c) => c,
                Err(e) => {
                    if !cli.json {
                        eprintln!("   {} - connect failed: {}", ep, e);
                    }
                    continue;
                }
            };
            match lwd.get_block(tip as u64).await {
                Ok((_, hash, _)) => {
                    let mut hash_rev = hash.clone();
                    hash_rev.reverse();
                    if hash == tip_hash || hash_rev == tip_hash {
                        agree += 1;
                        if !cli.json {
                            eprintln!("   {} - tip matches", ep);
                        }
                    } else {
                        disagree += 1;
                        if !cli.json {
                            eprintln!("   {} - MISMATCH", ep);
                        }
                    }
                }
                Err(e) => {
                    if !cli.json {
                        eprintln!("   {} - unreachable: {}", ep, e);
                    }
                }
            }
        }
        let total = agree + disagree;
        if total == 0 {
            return Err(Error::Other(
                "cross-verification failed: no nodes responded".into(),
            ));
        }
        let threshold = (total * 2).div_ceil(3);
        if agree < threshold {
            return Err(Error::Other(format!(
                "cross-verification failed: {}/{} nodes disagree on tip",
                disagree, total,
            )));
        }
        if !cli.json {
            eprintln!("   consensus: {}/{} agree (threshold: >2/3)", agree, total);
            eprintln!("   PASS");
        }
    } else if !cli.json {
        eprintln!("   skipped (no --verify-endpoints configured)");
    }

    // step 3: header chain proof
    if !cli.json {
        eprintln!();
        eprintln!("3. header chain proof (ligerito)");
    }
    let (proof_bytes, proof_from, proof_to) = zidecar.get_header_proof().await?;

    let result = zync_core::verifier::verify_proofs_full(&proof_bytes)
        .map_err(|e| Error::Other(format!("proof verification failed: {}", e)))?;

    if !result.epoch_proof_valid {
        return Err(Error::Other("epoch proof cryptographically INVALID".into()));
    }
    if !result.tip_valid {
        return Err(Error::Other("tip proof cryptographically INVALID".into()));
    }
    if !result.continuous {
        return Err(Error::Other(
            "proof chain DISCONTINUOUS — gap between epoch proof and tip".into(),
        ));
    }

    // verify epoch proof anchors to hardcoded activation hash
    if mainnet && result.epoch_outputs.start_hash != zync_core::ACTIVATION_HASH_MAINNET {
        return Err(Error::Other(
            "epoch proof start_hash doesn't match activation anchor".into(),
        ));
    }

    let epoch = &result.epoch_outputs;
    let blocks_proven = proof_to - proof_from;
    if !cli.json {
        eprintln!(
            "   epoch proof: {} -> {} ({} headers, {} KB)",
            epoch.start_height,
            epoch.end_height,
            epoch.num_headers,
            proof_bytes.len() / 1024,
        );
        eprintln!("   epoch proof anchored to activation hash: PASS");
        eprintln!("   epoch proof cryptographic verification:  PASS");
        if let Some(ref tip_out) = result.tip_outputs {
            eprintln!(
                "   tip proof: {} -> {} ({} headers)",
                tip_out.start_height, tip_out.end_height, tip_out.num_headers
            );
            eprintln!("   tip proof cryptographic verification:  PASS");
        }
        eprintln!("   chain continuity (tip chains to epoch proof): PASS");
        eprintln!("   total blocks proven: {}", blocks_proven);
    }

    // step 4: proven state roots
    let outputs = result.tip_outputs.as_ref().unwrap_or(&result.epoch_outputs);
    let staleness = tip.saturating_sub(outputs.end_height);
    if staleness > zync_core::EPOCH_SIZE {
        return Err(Error::Other(format!(
            "proof too stale: {} blocks behind tip (>1 epoch)",
            staleness
        )));
    }
    if !cli.json {
        eprintln!();
        eprintln!("4. cryptographically proven state roots");
        eprintln!("   (extracted from ligerito polynomial trace sentinel row)");
        eprintln!(
            "   tree_root:          {}",
            hex::encode(outputs.tip_tree_root)
        );
        eprintln!(
            "   nullifier_root:     {}",
            hex::encode(outputs.tip_nullifier_root)
        );
        eprintln!(
            "   actions_commitment: {}",
            hex::encode(outputs.final_actions_commitment)
        );
        eprintln!("   proof freshness: {} blocks behind tip", staleness);
    }

    if !cli.json {
        eprintln!();
        eprintln!("all checks passed");
    }

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "network": network,
                "tip": tip,
                "tip_hash": hex::encode(&tip_hash),
                "proof_from": proof_from,
                "proof_to": proof_to,
                "blocks_proven": blocks_proven,
                "epoch_proof_valid": result.epoch_proof_valid,
                "tip_valid": result.tip_valid,
                "continuous": result.continuous,
                "tree_root": hex::encode(outputs.tip_tree_root),
                "nullifier_root": hex::encode(outputs.tip_nullifier_root),
                "actions_commitment": hex::encode(outputs.final_actions_commitment),
                "staleness_blocks": staleness,
                "cross_verified": !endpoints.is_empty(),
            })
        );
    }

    Ok(())
}

async fn cmd_tree_info(cli: &Cli, height: u32) -> Result<(), Error> {
    let client = client::ZidecarClient::connect(&cli.endpoint).await?;
    let (tree_hex, actual_height) = client.get_tree_state(height).await?;

    // parse frontier to get tree size
    // lightwalletd orchard tree format: hex-encoded binary frontier
    let tree_bytes =
        hex::decode(&tree_hex).map_err(|e| Error::Other(format!("invalid tree hex: {}", e)))?;
    // frontier encoding: depth-first serialization of the frontier
    // the number of leaves = tree size, derivable from the frontier structure
    // quick parse: count the 01-prefixed nodes in the frontier
    let tree_size = parse_frontier_size(&tree_bytes)?;

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "height": actual_height,
                "orchard_tree_size": tree_size,
                "tree_hex_len": tree_hex.len(),
            })
        );
    } else {
        eprintln!("height: {}", actual_height);
        eprintln!("orchard tree size (leaves): {}", tree_size);
        eprintln!("tree hex length: {} chars", tree_hex.len());
    }
    Ok(())
}

/// parse the size (number of leaves) from a zcashd frontier encoding
fn parse_frontier_size(data: &[u8]) -> Result<u64, Error> {
    witness::frontier_tree_size(data)
}

fn cmd_notes(cli: &Cli) -> Result<(), Error> {
    let wallet = wallet::Wallet::open(&wallet::Wallet::default_path())?;
    let notes = wallet.all_received_notes()?;

    if cli.json {
        let json: Vec<_> = notes
            .iter()
            .map(|n| {
                let spent = wallet.is_spent(&n.nullifier).unwrap_or(false);
                let mut obj = serde_json::json!({
                    "zat": n.value,
                    "zec": format!("{:.8}", n.value as f64 / 1e8),
                    "height": n.block_height,
                    "cmx": hex::encode(&n.cmx[..8]),
                    "nullifier": hex::encode(n.nullifier),
                    "spent": spent,
                });
                if !n.txid.is_empty() {
                    obj["txid"] = hex::encode(&n.txid).into();
                }
                if let Some(ref memo) = n.memo {
                    obj["memo"] = serde_json::Value::String(memo.clone());
                }
                obj
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string(&json).unwrap_or_else(|_| "[]".into())
        );
    } else {
        if notes.is_empty() {
            println!("no received notes");
            return Ok(());
        }
        println!("{:<10} {:>14} {:>7} memo", "height", "ZEC", "spent");
        for n in &notes {
            let spent = wallet.is_spent(&n.nullifier).unwrap_or(false);
            let memo = n.memo.as_deref().unwrap_or("");
            println!(
                "{:<10} {:>14.8} {:>7} {}",
                n.block_height,
                n.value as f64 / 1e8,
                if spent { "yes" } else { "" },
                memo,
            );
        }
    }

    Ok(())
}

/// unified history entry for sorting recv + sent together
struct HistoryEntry {
    height: u32,
    timestamp: u64,
    direction: &'static str,
    amount: u64,
    memo: Option<String>,
    txid: String,
    // sent-only fields
    fee: Option<u64>,
    recipient: Option<String>,
    tx_type: Option<String>,
    // recv-only
    spent: Option<bool>,
}

impl HistoryEntry {
    /// sort key: height first (descending), then timestamp for unconfirmed
    fn sort_key(&self) -> (std::cmp::Reverse<u32>, std::cmp::Reverse<u64>) {
        (
            std::cmp::Reverse(self.height),
            std::cmp::Reverse(self.timestamp),
        )
    }
}

fn cmd_history(cli: &Cli) -> Result<(), Error> {
    let wallet = wallet::Wallet::open(&wallet::Wallet::default_path())?;

    let mut entries: Vec<HistoryEntry> = Vec::new();

    // received notes
    for n in wallet.all_received_notes()? {
        let spent = wallet.is_spent(&n.nullifier).unwrap_or(false);
        entries.push(HistoryEntry {
            height: n.block_height,
            timestamp: 0,
            direction: "recv",
            amount: n.value,
            memo: n.memo.clone(),
            txid: if n.txid.is_empty() {
                String::new()
            } else {
                hex::encode(&n.txid)
            },
            fee: None,
            recipient: None,
            tx_type: None,
            spent: Some(spent),
        });
    }

    // sent transactions
    for tx in wallet.all_sent_txs()? {
        entries.push(HistoryEntry {
            height: tx.block_height,
            timestamp: tx.timestamp,
            direction: "sent",
            amount: tx.amount,
            memo: tx.memo.clone(),
            txid: tx.txid.clone(),
            fee: Some(tx.fee),
            recipient: Some(tx.recipient.clone()),
            tx_type: Some(tx.tx_type.clone()),
            spent: None,
        });
    }

    entries.sort_by_key(|e| e.sort_key());

    if cli.json {
        let json: Vec<_> = entries
            .iter()
            .map(|e| {
                let mut obj = serde_json::json!({
                    "direction": e.direction,
                    "zat": e.amount,
                    "zec": format!("{:.8}", e.amount as f64 / 1e8),
                    "height": e.height,
                    "txid": e.txid,
                });
                if let Some(fee) = e.fee {
                    obj["fee_zat"] = fee.into();
                }
                if let Some(ref r) = e.recipient {
                    obj["recipient"] = r.clone().into();
                }
                if let Some(ref t) = e.tx_type {
                    obj["type"] = t.clone().into();
                }
                if let Some(spent) = e.spent {
                    obj["spent"] = spent.into();
                }
                if let Some(ref m) = e.memo {
                    obj["memo"] = m.clone().into();
                }
                if e.timestamp > 0 {
                    obj["timestamp"] = e.timestamp.into();
                }
                obj
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string(&json).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }

    if entries.is_empty() {
        println!("no transaction history");
        return Ok(());
    }

    println!(
        "{:<6} {:<10} {:>14} {:>8} info",
        "dir", "height", "ZEC", "txid"
    );
    for e in &entries {
        let txid_short = if e.txid.len() >= 8 {
            &e.txid[..8]
        } else {
            &e.txid
        };
        let info = match e.direction {
            "recv" => e.memo.as_deref().unwrap_or("").to_string(),
            "sent" => e.tx_type.as_deref().unwrap_or("").to_string(),
            _ => String::new(),
        };
        println!(
            "{:<6} {:<10} {:>14.8} {:>8} {}",
            e.direction,
            if e.height > 0 {
                e.height.to_string()
            } else {
                "pending".into()
            },
            e.amount as f64 / 1e8,
            txid_short,
            info,
        );
    }

    Ok(())
}

fn notes_json() -> String {
    let wallet = match wallet::Wallet::open(&wallet::Wallet::default_path()) {
        Ok(w) => w,
        Err(_) => return "[]".into(),
    };
    let notes = match wallet.all_received_notes() {
        Ok(n) => n,
        Err(_) => return "[]".into(),
    };
    let json: Vec<_> = notes
        .iter()
        .map(|n| {
            let spent = wallet.is_spent(&n.nullifier).unwrap_or(false);
            let mut obj = serde_json::json!({
                "zat": n.value,
                "zec": format!("{:.8}", n.value as f64 / 1e8),
                "height": n.block_height,
                "spent": spent,
            });
            if !n.txid.is_empty() {
                obj["txid"] = hex::encode(&n.txid).into();
            }
            if let Some(ref memo) = n.memo {
                obj["memo"] = serde_json::Value::String(memo.clone());
            }
            obj
        })
        .collect();
    serde_json::to_string(&json).unwrap_or_else(|_| "[]".into())
}

async fn cmd_board(
    cli: &Cli,
    seed: &key::WalletSeed,
    mainnet: bool,
    port: u16,
    interval: u64,
    dir: Option<&str>,
) -> Result<(), Error> {
    let state: Arc<Mutex<String>> = Arc::new(Mutex::new(notes_json()));

    // initial sync
    eprintln!("board: initial sync...");
    let _ = ops::sync::sync(
        seed,
        &cli.endpoint,
        &cli.verify_endpoints,
        mainnet,
        true,
        None,
        None,
    )
    .await;
    *state.lock().unwrap() = notes_json();
    if let Some(d) = dir {
        let _ = std::fs::write(
            format!("{}/memos.json", d),
            state.lock().unwrap().as_bytes(),
        );
    }
    eprintln!("board: serving on :{}", port);

    // sync loop
    let sync_state = Arc::clone(&state);
    let endpoint = cli.endpoint.clone();
    let verify_endpoints = cli.verify_endpoints.clone();
    let seed_bytes: [u8; 64] = *seed.as_bytes();
    let dir_owned = dir.map(String::from);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            let seed = key::WalletSeed::from_bytes(seed_bytes);
            match ops::sync::sync(
                &seed,
                &endpoint,
                &verify_endpoints,
                mainnet,
                true,
                None,
                None,
            )
            .await
            {
                Ok(found) => {
                    let json = notes_json();
                    if let Some(ref d) = dir_owned {
                        let _ = std::fs::write(format!("{}/memos.json", d), json.as_bytes());
                    }
                    *sync_state.lock().unwrap() = json;
                    eprintln!("board: synced, {} new notes", found);
                }
                Err(e) => eprintln!("board: sync error: {}", e),
            }
        }
    });

    // http server
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .map_err(|e| Error::Other(format!("bind :{}: {}", port, e)))?;

    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| Error::Other(format!("accept: {}", e)))?;
        let json = state.lock().unwrap().clone();
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Cache-Control: no-cache\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            json.len(),
            json,
        );
        let _ = stream.write_all(response.as_bytes()).await;
    }
}

async fn cmd_merchant(cli: &Cli, mainnet: bool, action: &MerchantAction) -> Result<(), Error> {
    match action {
        MerchantAction::Create {
            amount,
            memo,
            deposit,
        } => {
            let seed = load_seed(cli)?;
            let amount_zat = ops::merchant::parse_amount(amount)?;
            let req = ops::merchant::create_request(
                &seed,
                amount_zat,
                memo.as_deref(),
                *deposit,
                mainnet,
            )?;

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": req.id,
                        "address": req.address,
                        "amount_zat": req.amount_zat,
                        "amount_zec": format!("{:.8}", req.amount_zat as f64 / 1e8),
                        "label": req.label,
                        "deposit": req.deposit,
                        "status": req.status,
                    })
                );
            } else {
                // QR code
                use qrcode::QrCode;
                if let Ok(code) = QrCode::new(req.address.as_bytes()) {
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

                println!("request: #{}", req.id);
                println!("address: {}", req.address);
                if req.amount_zat > 0 {
                    println!("amount:  {:.8} ZEC", req.amount_zat as f64 / 1e8);
                } else {
                    println!("amount:  any");
                }
                if req.deposit {
                    println!("mode:    deposit (permanent, accumulates)");
                }
                if let Some(ref label) = req.label {
                    println!("label:   {}", label);
                }
            }
            Ok(())
        }

        MerchantAction::List { status } => {
            let wallet = wallet::Wallet::open(&wallet::Wallet::default_path())?;
            let reqs = wallet.list_payment_requests(status.as_deref())?;

            if cli.json {
                let json: Vec<_> = reqs
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "id": r.id,
                            "address": r.address,
                            "amount_zat": r.amount_zat,
                            "amount_zec": format!("{:.8}", r.amount_zat as f64 / 1e8),
                            "label": r.label,
                            "status": r.status,
                            "received_zat": r.received_zat,
                            "forward_txid": r.forward_txid,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string(&json).unwrap_or_else(|_| "[]".into())
                );
            } else {
                if reqs.is_empty() {
                    println!("no payment requests");
                    return Ok(());
                }
                println!(
                    "{:<4} {:>14} {:<12} {:<24} label",
                    "id", "ZEC", "status", "address"
                );
                for r in &reqs {
                    let addr_short = if r.address.len() > 20 {
                        &r.address[..20]
                    } else {
                        &r.address
                    };
                    let amt = if r.amount_zat > 0 {
                        format!("{:.8}", r.amount_zat as f64 / 1e8)
                    } else {
                        "any".into()
                    };
                    println!(
                        "{:<4} {:>14} {:<12} {:<24} {}",
                        r.id,
                        amt,
                        r.status,
                        format!("{}...", addr_short),
                        r.label.as_deref().unwrap_or(""),
                    );
                }
            }
            Ok(())
        }

        MerchantAction::Check {
            forward,
            confirmations,
            webhook_url,
            webhook_secret,
        } => {
            let seed = load_seed(cli)?;

            // sync first
            if !cli.json {
                eprintln!("syncing...");
            }
            let _ = ops::sync::sync(
                &seed,
                &cli.endpoint,
                &cli.verify_endpoints,
                mainnet,
                cli.json,
                None,
                None,
            )
            .await;

            // match payments (with confirmation depth)
            let tip = wallet::Wallet::open(&wallet::Wallet::default_path())?.sync_height()?;
            let matched = ops::merchant::match_payments(tip, *confirmations)?;
            if !cli.json && matched > 0 {
                eprintln!("{} payment(s) matched", matched);
            }

            // process withdrawals
            let (w_ok, w_fail, w_insuf) =
                ops::merchant::process_withdrawals(&seed, &cli.endpoint, mainnet, cli.json)
                    .await
                    .unwrap_or((0, 0, 0));

            // forward if address available
            let fwd_addr = ops::merchant::resolve_forward_address(forward.as_deref())?;
            let (forwarded, fwd_failed) = if let Some(ref addr) = fwd_addr {
                ops::merchant::forward_payments(&seed, addr, &cli.endpoint, mainnet, cli.json)
                    .await?
            } else {
                (0, 0)
            };

            // webhook: POST full state
            if let (Some(url), Some(secret)) = (webhook_url.as_deref(), webhook_secret.as_deref()) {
                let body = ops::merchant::requests_json();
                if let Err(e) = ops::merchant::post_webhook(url, secret, &body).await {
                    eprintln!("webhook failed: {}", e);
                }
            }

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "matched": matched,
                        "forwarded": forwarded,
                        "forward_failed": fwd_failed,
                        "forward_address": fwd_addr,
                        "withdrawals_completed": w_ok,
                        "withdrawals_failed": w_fail,
                        "withdrawals_insufficient": w_insuf,
                    })
                );
            } else {
                println!(
                    "matched: {}, forwarded: {}, failed: {}, withdrawals: {}/{}/{}",
                    matched, forwarded, fwd_failed, w_ok, w_fail, w_insuf
                );
            }
            Ok(())
        }

        MerchantAction::Watch {
            forward,
            confirmations,
            interval,
            dir,
            webhook_url,
            webhook_secret,
            quic,
            peer_key,
        } => {
            let seed = load_seed(cli)?;
            let interval = *interval;
            let confirmations = *confirmations;

            // QUIC link to exchange API
            let mut quic_link = if let Some(ref addr) = quic {
                let peer_hex = peer_key
                    .as_deref()
                    .ok_or_else(|| Error::Other("--peer-key required when using --quic".into()))?;
                let peer_pk = quic::parse_peer_key(peer_hex)?;
                let (seed32, pub32) = key::load_ssh_ed25519_keypair(&cli.identity_path())?;
                let (cert, qkey) = quic::generate_cert(&seed32, &pub32)?;
                let config = quic::client_config(cert, qkey, &peer_pk)?;
                let link = quic::QuicLink::connect(addr, config).await?;

                // spawn CE stream handler
                let conn = link.connection().clone();
                let seed_copy = key::WalletSeed::from_bytes(*seed.as_bytes());
                tokio::spawn(async move {
                    quic::QuicLink::handle_incoming(conn, seed_copy, mainnet).await;
                });

                if !cli.json {
                    eprintln!("quic: connected to {}", addr);
                }
                Some(link)
            } else {
                None
            };

            loop {
                // sync
                if !cli.json {
                    eprintln!("syncing...");
                }
                let _ = ops::sync::sync(
                    &seed,
                    &cli.endpoint,
                    &cli.verify_endpoints,
                    mainnet,
                    cli.json,
                    None,
                    None,
                )
                .await;

                // match (with confirmation depth)
                let tip = wallet::Wallet::open(&wallet::Wallet::default_path())?.sync_height()?;
                let matched = ops::merchant::match_payments(tip, confirmations)?;

                // withdraw
                let (w_ok, w_fail, w_insuf) =
                    ops::merchant::process_withdrawals(&seed, &cli.endpoint, mainnet, cli.json)
                        .await
                        .unwrap_or((0, 0, 0));

                // forward
                let fwd_addr = ops::merchant::resolve_forward_address(forward.as_deref())?;
                let (forwarded, fwd_failed) = if let Some(ref addr) = fwd_addr {
                    ops::merchant::forward_payments(&seed, addr, &cli.endpoint, mainnet, cli.json)
                        .await
                        .unwrap_or((0, 0))
                } else {
                    (0, 0)
                };

                let state_json = ops::merchant::requests_json();

                // local: atomic file push (same-machine)
                if let Some(ref d) = dir {
                    if let Err(e) = ops::merchant::atomic_write(
                        &format!("{}/requests.json", d),
                        state_json.as_bytes(),
                    ) {
                        eprintln!("warning: failed to write requests.json: {}", e);
                    }
                }

                // remote: outbound webhook (HMAC-SHA256 signed)
                if let (Some(url), Some(secret)) =
                    (webhook_url.as_deref(), webhook_secret.as_deref())
                {
                    if let Err(e) = ops::merchant::post_webhook(url, secret, &state_json).await {
                        eprintln!("webhook failed: {}", e);
                    }
                }

                // QUIC: push state to exchange API
                if let Some(ref mut link) = quic_link {
                    if let Err(e) = link.push_state(&state_json).await {
                        eprintln!("quic push failed: {}", e);
                    }
                }

                if !cli.json {
                    eprintln!(
                        "matched: {}, fwd: {}/{}, withdraw: {}/{}/{} — sleeping {}s",
                        matched, forwarded, fwd_failed, w_ok, w_fail, w_insuf, interval
                    );
                }

                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        }

        MerchantAction::Withdraw {
            amount,
            address,
            memo,
        } => {
            // validate address format
            if !(address.starts_with("t1")
                || address.starts_with("tm")
                || address.starts_with("u1")
                || address.starts_with("utest1"))
            {
                return Err(Error::Address(format!(
                    "unrecognized address format: {}",
                    address
                )));
            }

            let amount_zat = ops::merchant::parse_amount(amount)?;
            let min_amount = 10_000; // MARGINAL_FEE * 2
            if amount_zat <= min_amount {
                return Err(Error::Transaction(format!(
                    "withdrawal amount must be > {} zat (got {})",
                    min_amount, amount_zat
                )));
            }

            let w = wallet::Wallet::open(&wallet::Wallet::default_path())?;
            let id = w.next_withdrawal_id()?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let wr = wallet::WithdrawalRequest {
                id,
                address: address.clone(),
                amount_zat,
                label: memo.clone(),
                created_at: now,
                status: "pending".into(),
                txid: None,
                fee_zat: None,
                error: None,
            };
            w.insert_withdrawal_request(&wr)?;

            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": wr.id,
                        "amount_zat": wr.amount_zat,
                        "amount_zec": format!("{:.8}", wr.amount_zat as f64 / 1e8),
                        "address": wr.address,
                        "label": wr.label,
                        "status": wr.status,
                    })
                );
            } else {
                println!(
                    "withdrawal #{} queued: {:.8} ZEC → {}",
                    wr.id,
                    wr.amount_zat as f64 / 1e8,
                    address
                );
                if let Some(ref label) = wr.label {
                    println!("label: {}", label);
                }
            }
            Ok(())
        }

        MerchantAction::WithdrawList { status } => {
            let w = wallet::Wallet::open(&wallet::Wallet::default_path())?;
            let reqs = w.list_withdrawal_requests(status.as_deref())?;

            if cli.json {
                let json: Vec<_> = reqs
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "id": r.id,
                            "amount_zat": r.amount_zat,
                            "amount_zec": format!("{:.8}", r.amount_zat as f64 / 1e8),
                            "address": r.address,
                            "label": r.label,
                            "status": r.status,
                            "txid": r.txid,
                            "fee_zat": r.fee_zat,
                            "error": r.error,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string(&json).unwrap_or_else(|_| "[]".into())
                );
            } else {
                if reqs.is_empty() {
                    println!("no withdrawal requests");
                    return Ok(());
                }
                println!(
                    "{:<4} {:>14} {:<12} {:>10} label",
                    "id", "ZEC", "status", "txid"
                );
                for r in &reqs {
                    let txid_short = r
                        .txid
                        .as_deref()
                        .map(|t| if t.len() > 8 { &t[..8] } else { t })
                        .unwrap_or("");
                    println!(
                        "{:<4} {:>14.8} {:<12} {:>10} {}",
                        r.id,
                        r.amount_zat as f64 / 1e8,
                        r.status,
                        txid_short,
                        r.label.as_deref().unwrap_or(""),
                    );
                }
            }
            Ok(())
        }

        MerchantAction::SetForward { address } => {
            let wallet = wallet::Wallet::open(&wallet::Wallet::default_path())?;
            if let Some(addr) = address {
                // validate address format before storing
                if !(addr.starts_with("t1")
                    || addr.starts_with("tm")
                    || addr.starts_with("u1")
                    || addr.starts_with("utest1"))
                {
                    return Err(Error::Address(format!(
                        "unrecognized address format: {}",
                        addr
                    )));
                }
                wallet.set_forward_address(addr)?;
                if cli.json {
                    println!("{}", serde_json::json!({ "forward_address": addr }));
                } else {
                    println!("forward address set: {}", addr);
                }
            } else {
                let current = wallet.get_forward_address()?;
                if cli.json {
                    println!("{}", serde_json::json!({ "forward_address": current }));
                } else {
                    match current {
                        Some(addr) => println!("forward address: {}", addr),
                        None => println!("no forward address set"),
                    }
                }
            }
            Ok(())
        }
    }
}

fn cmd_scan(cli: &Cli, device: &str, timeout: u64) -> Result<(), Error> {
    #[cfg(not(target_os = "linux"))]
    {
        return Err(Error::Other("webcam scanning requires linux".into()));
    }

    #[cfg(target_os = "linux")]
    {
        if !cli.json {
            eprintln!("scanning QR from {}... ({}s timeout)", device, timeout);
        }
        let data = cam::scan_qr(device, timeout)?;

        // try to interpret the data
        let hex_str = hex::encode(&data);

        if cli.json {
            // try utf-8 interpretation
            let text = String::from_utf8_lossy(&data);
            println!(
                "{}",
                serde_json::json!({
                    "hex": hex_str,
                    "bytes": data.len(),
                    "text": text,
                })
            );
        } else {
            eprintln!("decoded {} bytes", data.len());

            // detect zigner protocol types
            if data.len() >= 3 && data[0] == 0x53 && data[1] == 0x04 {
                match data[2] {
                    0x01 => eprintln!("type: zigner FVK export"),
                    0x02 => eprintln!("type: zigner sign request"),
                    0x03 => eprintln!("type: zigner signature response"),
                    _ => eprintln!("type: zigner unknown (0x{:02x})", data[2]),
                }
            }

            // show hex
            println!("{}", hex_str);

            // also try to show as text if it looks like UTF-8
            if let Ok(text) = std::str::from_utf8(&data) {
                if text.chars().all(|c| !c.is_control() || c == '\n') {
                    eprintln!("text: {}", text);
                }
            }
        }
        Ok(())
    }
}

/// load FVK from the watch wallet (~/.zcli/watch)
fn load_fvk(_cli: &Cli, _mainnet: bool) -> Result<orchard::keys::FullViewingKey, Error> {
    let watch = wallet::Wallet::open(&wallet::Wallet::watch_path())?;
    let fvk_bytes = watch
        .get_fvk_bytes()?
        .ok_or_else(|| Error::Other("no FVK imported — run `zcli import-fvk` first".into()))?;
    address::fvk_from_bytes(&fvk_bytes)
}

fn cmd_import_fvk(cli: &Cli, mainnet: bool, hex_input: Option<&str>) -> Result<(), Error> {
    let data = if let Some(hex_str) = hex_input {
        hex::decode(hex_str.trim()).map_err(|e| Error::Other(format!("invalid hex: {}", e)))?
    } else {
        // try webcam scan or manual input
        #[cfg(target_os = "linux")]
        {
            let cam_device = std::env::var("ZCLI_CAM").unwrap_or_else(|_| "/dev/video0".into());
            if cam_device != "none" && std::path::Path::new(&cam_device).exists() {
                eprintln!("show zigner FVK export QR to camera ({})...", cam_device);
                match cam::scan_qr(&cam_device, 60) {
                    Ok(d) => {
                        eprintln!("QR decoded ({} bytes)", d.len());
                        d
                    }
                    Err(e) => {
                        eprintln!("camera scan failed: {}", e);
                        eprintln!("enter FVK export hex:");
                        read_hex_line()?
                    }
                }
            } else {
                eprintln!("enter FVK export hex:");
                read_hex_line()?
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("enter FVK export hex:");
            read_hex_line()?
        }
    };

    let (fvk_bytes, is_mainnet, account, label) = ops::airgap::parse_fvk_export(&data)?;

    // validate the FVK parses correctly
    let fvk = address::fvk_from_bytes(&fvk_bytes)?;
    let uaddr = address::orchard_address_from_fvk(&fvk, is_mainnet)?;

    if is_mainnet != mainnet {
        eprintln!(
            "warning: FVK is for {} but cli is set to {}",
            if is_mainnet { "mainnet" } else { "testnet" },
            if mainnet { "mainnet" } else { "testnet" },
        );
    }

    // store in watch wallet (separate from SSH key wallet)
    let watch = wallet::Wallet::open(&wallet::Wallet::watch_path())?;
    watch.store_fvk(&fvk_bytes)?;

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "mode": "watch-only",
                "account": account,
                "label": label,
                "mainnet": is_mainnet,
                "address": uaddr,
                "fvk_hex": hex::encode(fvk_bytes),
            })
        );
    } else {
        eprintln!("imported FVK (watch-only wallet)");
        if !label.is_empty() {
            eprintln!("label:   {}", label);
        }
        eprintln!("account: {}", account);
        eprintln!(
            "network: {}",
            if is_mainnet { "mainnet" } else { "testnet" }
        );
        println!("{}", uaddr);
    }

    Ok(())
}

fn read_hex_line() -> Result<Vec<u8>, Error> {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .ok_or_else(|| Error::Other("no input".into()))?
        .map_err(|e| Error::Other(format!("read stdin: {}", e)))?;
    hex::decode(line.trim()).map_err(|e| Error::Other(format!("invalid hex: {}", e)))
}

/// derive FVK from seed and store in watch wallet if not already cached
fn ensure_fvk_cached(seed: &key::WalletSeed, mainnet: bool) {
    let coin_type = if mainnet { 133 } else { 1 };
    let sk = match orchard::keys::SpendingKey::from_zip32_seed(
        seed.as_bytes(),
        coin_type,
        zip32::AccountId::ZERO,
    ) {
        Ok(sk) => sk,
        Err(_) => return,
    };
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let fvk_bytes = fvk.to_bytes();
    let watch = match wallet::Wallet::open(&wallet::Wallet::watch_path()) {
        Ok(w) => w,
        Err(_) => return,
    };
    // only write if not already stored
    if watch.get_fvk_bytes().ok().flatten().is_none() && watch.store_fvk(&fvk_bytes).is_ok() {
        watch.flush();
        eprintln!("cached FVK in watch wallet for future non-interactive syncs");
    }
}

fn cmd_init_create(cli: &Cli, words: usize) -> Result<(), Error> {
    let age_path = cli::Cli::expand_tilde("~/.config/zcli/mnemonic.age");
    if std::path::Path::new(&age_path).exists() {
        return Err(Error::Other(format!(
            "mnemonic already exists at {}. Delete it first to create a new wallet.",
            age_path
        )));
    }

    // Generate mnemonic
    let word_count = if words == 12 { 12 } else { 24 };
    let mnemonic = if word_count == 12 {
        bip39::Mnemonic::generate(12).expect("valid").to_string()
    } else {
        key::generate_mnemonic()
    };

    if cli.json {
        println!("{}", serde_json::json!({ "mnemonic": mnemonic }));
    } else {
        eprintln!("\n  ╔══════════════════════════════════════════════════════════╗");
        eprintln!("  ║  WRITE DOWN THESE WORDS. THEY ARE YOUR WALLET.          ║");
        eprintln!("  ║  Anyone with these words can spend your funds.           ║");
        eprintln!("  ╚══════════════════════════════════════════════════════════╝\n");
        for (i, word) in mnemonic.split_whitespace().enumerate() {
            eprint!("  {:>2}. {:<12}", i + 1, word);
            if (i + 1) % 4 == 0 { eprintln!(); }
        }
        eprintln!();
    }

    // Encrypt with age using the SSH key
    let identity_path = cli.identity_path();
    let config_dir = cli::Cli::expand_tilde("~/.config/zcli");
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| Error::Other(format!("create config dir: {}", e)))?;

    // Get the public key from the SSH key for age encryption
    let pubkey_output = std::process::Command::new("ssh-keygen")
        .args(["-y", "-f", &identity_path])
        .output()
        .map_err(|e| Error::Other(format!("ssh-keygen: {}", e)))?;
    if !pubkey_output.status.success() {
        return Err(Error::Other("failed to extract public key from SSH key".into()));
    }
    let pubkey = String::from_utf8_lossy(&pubkey_output.stdout).trim().to_string();

    // Encrypt with age
    let mut child = std::process::Command::new("age")
        .args(["-r", &pubkey, "-o", &age_path])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Error::Other(format!("age not found: {}", e)))?;

    use std::io::Write;
    child.stdin.take().unwrap().write_all(mnemonic.as_bytes())
        .map_err(|e| Error::Other(format!("write to age: {}", e)))?;

    let status = child.wait()
        .map_err(|e| Error::Other(format!("age wait: {}", e)))?;
    if !status.success() {
        return Err(Error::Other("age encryption failed".into()));
    }

    if !cli.json {
        eprintln!("mnemonic encrypted and saved to {}", age_path);
        eprintln!("decryptable with: age -d -i {} {}", identity_path, age_path);
    }

    Ok(())
}

fn load_seed(cli: &Cli) -> Result<key::WalletSeed, Error> {
    use cli::MnemonicSource;
    match cli.mnemonic_source() {
        Some(MnemonicSource::Plaintext(ref phrase)) => key::load_mnemonic_seed(phrase),
        Some(MnemonicSource::AgeFile(ref path)) => {
            let phrase = key::decrypt_age_file(path, &cli.identity_path())?;
            key::load_mnemonic_seed(&phrase)
        }
        None => key::load_ssh_seed(&cli.identity_path()),
    }
}

fn parse_ephemeral_seed(hex_str: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| Error::Other(format!("bad ephemeral seed hex: {}", e)))?;
    bytes.try_into()
        .map_err(|_| Error::Other("ephemeral seed must be 32 bytes".into()))
}

fn parse_32_bytes(hex_str: &str, name: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| Error::Other(format!("bad {} hex: {}", name, e)))?;
    bytes.try_into()
        .map_err(|_| Error::Other(format!("{} must be 32 bytes", name)))
}

async fn cmd_export_notes(
    cli: &Cli,
    mainnet: bool,
    interval_ms: u64,
    fragment_size: usize,
    attestation_hex: Option<&str>,
    transport: &str,
    zt_frame_size: usize,
    zt_redundancy: u8,
) -> Result<(), Error> {
    let wallet_obj = wallet::Wallet::open(&wallet::Wallet::default_path())?;
    let (balance, notes) = wallet_obj.shielded_balance()?;

    if notes.is_empty() {
        return Err(Error::Other("no unspent notes to export".into()));
    }

    if !cli.json {
        eprintln!(
            "{} unspent notes, {:.8} ZEC",
            notes.len(),
            balance as f64 / 1e8
        );
        eprintln!("connecting to {}...", cli.endpoint);
    }

    let client_obj = client::ZidecarClient::connect(&cli.endpoint).await?;
    let (tip, _) = client_obj.get_tip().await?;

    if !cli.json {
        eprintln!("building merkle witnesses (anchor height {})...", tip);
    }

    let (anchor, paths) =
        witness::build_witnesses(&client_obj, &notes, tip, mainnet, cli.json).await?;

    let attestation: Option<[u8; 96]> = match attestation_hex {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str)
                .map_err(|e| Error::Other(format!("bad attestation hex: {e}")))?;
            let arr: [u8; 96] = bytes.try_into().map_err(|v: Vec<u8>| {
                Error::Other(format!(
                    "attestation must be 96 bytes (sig 64 + randomizer 32), got {}",
                    v.len()
                ))
            })?;
            Some(arr)
        }
        None => None,
    };
    let cbor = notes_export::encode_notes_cbor(
        &anchor,
        tip,
        mainnet,
        &notes,
        &paths,
        attestation.as_ref(),
    );

    if !cli.json {
        eprintln!(
            "encoded {} notes into {} bytes CBOR",
            notes.len(),
            cbor.len()
        );
    }

    let (parts, transport_label) = match transport {
        "zt" => {
            let (frames, _session_id) =
                zoda_vss::transport::Encoder::encode_auto(&cbor, zt_frame_size, zt_redundancy);
            let n = frames.len();
            let strings: Vec<String> = frames
                .iter()
                .map(|f| format!("zt:zcash-notes/{}", hex::encode(f.to_bytes())))
                .collect();
            if !cli.json && !frames.is_empty() {
                let frame_bytes = frames[0].to_bytes().len();
                eprintln!("~{} bytes/frame, ~{} hex chars/QR", frame_bytes, frame_bytes * 2 + 15);
            }
            (strings, format!("zt {n} frames"))
        }
        _ => {
            let ur = notes_export::generate_ur_parts(&cbor, fragment_size)?;
            (ur, "ur".to_string())
        }
    };

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "transport": transport,
                "cbor_hex": hex::encode(&cbor),
                "cbor_bytes": cbor.len(),
                "notes": notes.len(),
                "balance_zat": balance,
                "anchor_height": tip,
                "anchor": hex::encode(anchor.to_bytes()),
                "attested": attestation.is_some(),
                "parts": parts,
                "frame_count": parts.len(),
            })
        );
        return Ok(());
    }

    eprintln!(
        "{} frames ({}), showing at {}ms interval (ctrl+c to stop)",
        parts.len(),
        transport_label,
        interval_ms
    );
    eprintln!();

    let status = format!(
        "{:.8} ZEC  {} notes  anchor {}  [{}]",
        balance as f64 / 1e8,
        notes.len(),
        tip,
        transport_label,
    );

    notes_export::display_animated_qr(&parts, interval_ms, &status)
}

fn cmd_multisig(cli: &Cli, action: &MultisigAction) -> Result<(), Error> {
    match action {
        MultisigAction::Dealer { min_signers, max_signers } => {
            let result = ops::multisig::dealer_keygen(*min_signers, *max_signers)?;
            if cli.json {
                println!("{}", serde_json::json!({
                    "packages": result.packages,
                    "public_key_package": result.public_key_package_hex,
                }));
            } else {
                eprintln!("generated {}-of-{} key packages:", min_signers, max_signers);
                for (i, pkg) in result.packages.iter().enumerate() {
                    eprintln!("  participant {}: {}...", i + 1, &pkg[..40]);
                }
                eprintln!("public key package: {}", result.public_key_package_hex);
            }
            Ok(())
        }
        MultisigAction::DkgPart1 { max_signers, min_signers, qr, label } => {
            if *qr {
                // Display QR for zigner to initiate DKG
                let json = frost_qr::dkg_init_qr(
                    *max_signers, *min_signers,
                    label, cli.is_mainnet(),
                );
                eprintln!("scan this QR with zigner to start {}-of-{} DKG:", min_signers, max_signers);
                frost_qr::display_text_qr(&json);
                eprintln!("after zigner completes round 1, scan its broadcast QR with:");
                eprintln!("  zcli multisig dkg-part2 ...");
                return Ok(());
            }
            let result = ops::multisig::dkg_part1(*max_signers, *min_signers)?;
            if cli.json {
                println!("{}", serde_json::json!({
                    "secret": result.secret_hex,
                    "broadcast": result.broadcast_hex,
                }));
            } else {
                eprintln!("DKG round 1 complete");
                eprintln!("secret (keep safe): {}", result.secret_hex);
                eprintln!("broadcast to all:   {}", result.broadcast_hex);
            }
            Ok(())
        }
        MultisigAction::DkgPart2 { secret, packages, qr } => {
            if *qr {
                let json = frost_qr::dkg_round2_qr(packages);
                eprintln!("scan this QR with zigner for DKG round 2:");
                frost_qr::display_text_qr(&json);
                return Ok(());
            }
            let result = ops::multisig::dkg_part2(secret, packages)?;
            if cli.json {
                println!("{}", serde_json::json!({
                    "secret": result.secret_hex,
                    "peer_packages": result.peer_packages,
                }));
            } else {
                eprintln!("DKG round 2 complete");
                eprintln!("secret (keep safe): {}", result.secret_hex);
                for (i, pkg) in result.peer_packages.iter().enumerate() {
                    eprintln!("  peer package {}: {}...", i, &pkg[..40.min(pkg.len())]);
                }
            }
            Ok(())
        }
        MultisigAction::DkgPart3 { secret, round1_packages, round2_packages, qr } => {
            if *qr {
                let json = frost_qr::dkg_round3_qr(round1_packages, round2_packages);
                eprintln!("scan this QR with zigner for DKG round 3:");
                frost_qr::display_text_qr(&json);
                return Ok(());
            }
            let result = ops::multisig::dkg_part3(secret, round1_packages, round2_packages)?;
            if cli.json {
                println!("{}", serde_json::json!({
                    "key_package": result.key_package_hex,
                    "public_key_package": result.public_key_package_hex,
                    "ephemeral_seed": result.ephemeral_seed_hex,
                }));
            } else {
                eprintln!("DKG complete!");
                eprintln!("ephemeral seed (for signing): {}", result.ephemeral_seed_hex);
                eprintln!("key package (SECRET): {}", result.key_package_hex);
                eprintln!("public key package: {}", result.public_key_package_hex);
            }
            Ok(())
        }
        MultisigAction::SignRound1 { ephemeral_seed, key_package } => {
            let seed = parse_ephemeral_seed(ephemeral_seed)?;
            let (nonces_hex, signed_commitments_hex) = ops::multisig::sign_round1(&seed, key_package)?;
            if cli.json {
                println!("{}", serde_json::json!({
                    "nonces": nonces_hex,
                    "commitments": signed_commitments_hex,
                }));
            } else {
                eprintln!("signing round 1 complete");
                eprintln!("nonces (keep safe): {}", nonces_hex);
                eprintln!("broadcast commitments: {}", signed_commitments_hex);
            }
            Ok(())
        }
        MultisigAction::Randomize { ephemeral_seed, message, commitments } => {
            let seed = parse_ephemeral_seed(ephemeral_seed)?;
            let msg_bytes = hex::decode(message)
                .map_err(|e| Error::Other(format!("bad message hex: {}", e)))?;
            let signed_randomizer = ops::multisig::generate_randomizer(
                &seed, &msg_bytes, commitments,
            )?;
            if cli.json {
                println!("{}", serde_json::json!({"randomizer": signed_randomizer}));
            } else {
                eprintln!("signed randomizer: {}", signed_randomizer);
            }
            Ok(())
        }
        MultisigAction::SignRound2 { ephemeral_seed, key_package, nonces, message, randomizer, commitments } => {
            let seed = parse_ephemeral_seed(ephemeral_seed)?;
            let msg_bytes = hex::decode(message)
                .map_err(|e| Error::Other(format!("bad message hex: {}", e)))?;
            let signed_share = ops::multisig::sign_round2(
                &seed, key_package, nonces, &msg_bytes, commitments, randomizer,
            )?;
            if cli.json {
                println!("{}", serde_json::json!({"signature_share": signed_share}));
            } else {
                eprintln!("signed signature share: {}", signed_share);
            }
            Ok(())
        }
        MultisigAction::Aggregate { public_key_package, message, randomizer, commitments, shares } => {
            let msg_bytes = hex::decode(message)
                .map_err(|e| Error::Other(format!("bad message hex: {}", e)))?;
            let sig_hex = ops::multisig::aggregate_shares(
                public_key_package, &msg_bytes, commitments, shares, randomizer,
            )?;
            if cli.json {
                println!("{}", serde_json::json!({"signature": sig_hex}));
            } else {
                eprintln!("aggregated signature: {}", sig_hex);
            }
            Ok(())
        }
        MultisigAction::DeriveAddress { public_key_package, index } => {
            let address = ops::multisig::derive_address(public_key_package, *index)?;
            if cli.json {
                println!("{}", serde_json::json!({"address": address}));
            } else {
                println!("{}", address);
            }
            Ok(())
        }
        MultisigAction::SpendSign { key_package, nonces, sighash, alpha, commitments } => {
            let sighash = parse_32_bytes(sighash, "sighash")?;
            let alpha = parse_32_bytes(alpha, "alpha")?;
            let share_hex = ops::multisig::spend_sign_round2(
                key_package, nonces, &sighash, &alpha, commitments,
            )?;
            if cli.json {
                println!("{}", serde_json::json!({"signature_share": share_hex}));
            } else {
                eprintln!("spend signature share: {}", share_hex);
            }
            Ok(())
        }
        MultisigAction::SpendAggregate { public_key_package, sighash, alpha, commitments, shares } => {
            let sighash = parse_32_bytes(sighash, "sighash")?;
            let alpha = parse_32_bytes(alpha, "alpha")?;
            let sig_hex = ops::multisig::spend_aggregate(
                public_key_package, &sighash, &alpha, commitments, shares,
            )?;
            if cli.json {
                println!("{}", serde_json::json!({"spend_auth_signature": sig_hex}));
            } else {
                eprintln!("Orchard SpendAuth signature: {}", sig_hex);
            }
            Ok(())
        }
    }
}

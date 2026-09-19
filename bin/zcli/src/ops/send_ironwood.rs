//! `zcli tx send` past NU6.3 — spending IRONWOOD notes.
//!
//! # Why this module exists
//!
//! At NU6.3 orchard OUTPUTS are consensus-disabled, so [`crate::ops::send`]
//! (which pins the pre-NU6.2 orchard bundle protocol) refuses to run past
//! activation. [`crate::ops::migrate`] gets value THROUGH the one-way turnstile
//! into the ironwood pool — and then stopped. Value that had crossed was
//! unspendable from the CLI: `select_notes` skips ironwood notes outright
//! ("needs v6 transaction support"), so the turnstile led into a dead end.
//!
//! This module is the other side of the turnstile.
//!
//! # Where the money path lives
//!
//! Not here. It is [`zafu_wasm::build_signed_ironwood_send_core`], the same
//! builder the browser wallet uses, generic over `zcash_protocol::consensus::
//! Parameters` so native callers can drive it. It runs Creator -> IoFinalizer
//! -> Prover (ironwood circuit) -> low-level Signer -> TransactionExtractor,
//! and the extractor re-verifies the proof and every spend-auth + binding
//! signature before handing back bytes. It carries the same FAIL-CLOSED
//! branch-id guard as the migration.
//!
//! This module does wallet-side work only: note selection, ZIP-317 fee
//! arithmetic, merkle witness construction, and broadcast — deliberately the
//! same shape as `ops::migrate`, because the two differ only in which pool is
//! spent and where the value goes.

use crate::client::ZidecarClient;
use crate::error::Error;
use crate::key::WalletSeed;
use crate::ops::send::compute_fee;
use crate::wallet::{Pool, SentTx, Wallet, WalletNote};
use crate::witness;

use zafu_wasm::IronwoodRecipient;

/// Real NU6.3 / Ironwood consensus branch id. Mirrors the constants in `tx.rs`
/// and `ops::migrate` (both private there) and the one the shared builder's
/// guard enforces.
///
/// Public because [`crate::ops::send`] routes on it: past NU6.3 a send is an
/// ironwood spend, and the orchard builders are unreachable by consensus.
pub const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;

/// Select ironwood notes covering `target`, largest first.
///
/// The sibling of [`crate::ops::send::select_notes`], which selects ORCHARD
/// notes and explicitly skips ironwood ones. The ordering rationale is the same:
/// value descending, then position descending, because recent notes minimise
/// merkle witness replay distance from a stale checkpoint.
///
/// On shortfall the error names the orchard balance if there is one — a wallet
/// mid-turnstile has value it can see but not spend from here, and the fix
/// (`zcli tx migrate`) is not guessable from "insufficient funds".
fn select_ironwood_notes(notes: &[WalletNote], target: u64) -> Result<Vec<WalletNote>, Error> {
    let orchard_zat: u64 = notes
        .iter()
        .filter(|n| n.pool == Pool::Orchard)
        .map(|n| n.value)
        .sum();

    let mut sorted: Vec<_> = notes
        .iter()
        .filter(|n| n.pool == Pool::Ironwood)
        .cloned()
        .collect();
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

    if orchard_zat > 0 {
        eprintln!(
            "note: {:.8} ZEC is still held in ORCHARD notes. Orchard outputs are \
             consensus-disabled at NU6.3, so that value cannot be spent directly — \
             run `zcli tx migrate` to move it through the turnstile into ironwood \
             first.",
            orchard_zat as f64 / 1e8
        );
    }
    Err(Error::InsufficientFunds {
        have: total,
        need: target,
    })
}

/// Outcome of an ironwood send build, before broadcast.
struct BuiltSend {
    tx_bytes: Vec<u8>,
    fee: u64,
    amount: u64,
    recipient: String,
    note_count: usize,
    change: u64,
}

#[allow(clippy::too_many_arguments)]
pub async fn send_ironwood(
    seed: &WalletSeed,
    amount: u64,
    recipient: &str,
    memo: Option<&str>,
    endpoint: &str,
    fee_override: Option<u64>,
    dry_run: bool,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    // Parse BEFORE note selection and witness building: a bad address must not
    // cost the user a chain replay to discover.
    let parsed = zafu_wasm::parse_ironwood_recipient(recipient, mainnet).map_err(Error::Address)?;

    // A memo has nowhere to live on a transparent output. Dropping it silently
    // would let the user believe a payment reference was delivered when it was
    // not, so refuse instead. (The shared builder also refuses; this is the
    // early, named version.)
    let transparent = matches!(parsed, IronwoodRecipient::Transparent(_));
    if transparent && memo.is_some_and(|m| !m.is_empty()) {
        return Err(Error::Transaction(
            "a memo cannot be attached to a transparent recipient: transparent \
             outputs have no memo field. Drop --memo, or send to a shielded \
             (u1…) address."
                .into(),
        ));
    }

    // ZIP-317 counts a shielded and a transparent output differently, so the
    // recipient type feeds the fee arithmetic.
    let (n_z_outputs, n_t_outputs) = if transparent { (0, 1) } else { (1, 0) };

    let (selected, cached_frontier, sync_height) = {
        let wallet = Wallet::open(&Wallet::default_path())?;
        let (_balance, notes) = wallet.shielded_balance()?;
        let frontier = wallet.tree_frontier(Pool::Ironwood).ok().flatten();
        let sh = wallet.sync_height().unwrap_or(0);

        // Fee depends on the note count and the note count depends on the fee.
        // Same fixpoint the orchard send path uses: price one spend, select
        // against that, then re-price against what was actually selected.
        let est_fee = compute_fee(1, n_z_outputs, n_t_outputs, true);
        let selected = select_ironwood_notes(&notes, amount + est_fee)?;
        (selected, frontier, sh)
    }; // drop the wallet handle before the (slow) build re-opens it

    let total_in: u64 = selected.iter().map(|n| n.value).sum();
    let has_change = total_in > amount + compute_fee(selected.len(), n_z_outputs, n_t_outputs, true);
    let fee = fee_override
        .unwrap_or_else(|| compute_fee(selected.len(), n_z_outputs, n_t_outputs, has_change));
    if total_in < amount + fee {
        return Err(Error::InsufficientFunds {
            have: total_in,
            need: amount + fee,
        });
    }
    let change = total_in - amount - fee;

    if !json {
        let preview = recipient.chars().take(20).collect::<String>();
        eprintln!(
            "spending {:.8} ZEC → {}... ({} ironwood note(s), fee {:.8} ZEC, \
             change {:.8} ZEC)",
            amount as f64 / 1e8,
            preview,
            selected.len(),
            fee as f64 / 1e8,
            change as f64 / 1e8,
        );
    }

    let client = ZidecarClient::connect(endpoint).await?;
    let (tip, _) = client.get_tip().await?;

    // FAIL CLOSED on the branch id BEFORE spending minutes on Halo 2 proving.
    // The shared builder re-checks this, but an ironwood spend is only a valid
    // shape once NU6.3 is actually active, so refuse early and by name.
    let branch_id = client.resolve_branch_id().await?;
    if branch_id != NU6_3_BRANCH_ID {
        return Err(Error::Transaction(format!(
            "refusing to build an ironwood send: the node reports consensus branch \
             id {:#010x}, but an ironwood spend is a V6 (NU6.3) transaction and is \
             only valid under {:#010x}. NU6.3 is not active on the chain this node \
             follows.",
            branch_id, NU6_3_BRANCH_ID
        )));
    }

    if !json {
        eprintln!("building merkle witnesses (replaying chain)...");
    }
    let (anchor, paths) = witness::build_witnesses(
        &client,
        &selected,
        tip,
        Pool::Ironwood,
        json,
        cached_frontier,
        sync_height,
    )
    .await?;

    let notes: Vec<orchard::Note> = selected
        .iter()
        .map(|n| n.reconstruct_note())
        .collect::<Result<_, _>>()?;
    let prepared: Vec<(orchard::Note, orchard::tree::MerklePath)> =
        notes.into_iter().zip(paths).collect();

    if !json {
        eprintln!("building + proving transaction (halo 2, ironwood bundle)...");
    }

    // Proving is CPU-bound and rayon-parallel; keep it off the async runtime.
    let seed_bytes = *seed.as_bytes();
    let memo_owned = memo.map(str::to_string);
    let note_count = selected.len();
    let recipient_owned = recipient.to_string();
    let tx_bytes = tokio::task::spawn_blocking(move || {
        let seed = WalletSeed::from_bytes(seed_bytes);
        build_signed_send(
            &seed,
            prepared,
            &recipient_owned,
            amount,
            fee,
            anchor,
            tip,
            branch_id,
            memo_owned.as_deref(),
            mainnet,
        )
    })
    .await
    .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    let built = BuiltSend {
        tx_bytes,
        fee,
        amount,
        recipient: recipient.to_string(),
        note_count,
        change,
    };

    if dry_run {
        report_dry_run(&built, json);
        return Ok(());
    }

    broadcast(&client, built, transparent, json).await
}

/// Derive the spending key from the seed and drive the shared builder.
///
/// Mirrors `ops::migrate::build_signed_migration` — same ZIP-32 derivation, same
/// ZIP-302 memo handling, same duplicated-arm shape because `mainnet` picks the
/// consensus params TYPE rather than a value.
#[allow(clippy::too_many_arguments)]
fn build_signed_send(
    seed: &WalletSeed,
    prepared: Vec<(orchard::Note, orchard::tree::MerklePath)>,
    recipient: &str,
    amount: u64,
    fee: u64,
    anchor: orchard::tree::Anchor,
    target_height: u32,
    branch_id: u32,
    memo: Option<&str>,
    mainnet: bool,
) -> Result<Vec<u8>, Error> {
    use zcash_protocol::consensus::{MainNetwork, TestNetwork};
    use zcash_protocol::memo::MemoBytes;

    let coin_type = if mainnet { 133 } else { 1 };
    let sk = orchard::keys::SpendingKey::from_zip32_seed(
        seed.as_bytes(),
        coin_type,
        zip32::AccountId::ZERO,
    )
    .map_err(|_| Error::Transaction("failed to derive spending key".into()))?;
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let ask = orchard::keys::SpendAuthorizingKey::from(&sk);

    let parsed = zafu_wasm::parse_ironwood_recipient(recipient, mainnet).map_err(Error::Address)?;

    // ZIP-302: absent memo is the 0xF6 marker (MemoBytes::empty()), never zeros.
    let memo = match memo.filter(|t| !t.is_empty()) {
        Some(text) => MemoBytes::from_bytes(text.as_bytes()).map_err(|_| {
            Error::Transaction(format!(
                "memo is {} bytes; the ZIP-302 limit is 512",
                text.len()
            ))
        })?,
        None => MemoBytes::empty(),
    };

    let res = if mainnet {
        zafu_wasm::build_signed_ironwood_send_core(
            MainNetwork,
            &fvk,
            &ask,
            prepared,
            parsed,
            amount,
            fee,
            anchor,
            target_height,
            branch_id,
            memo,
        )
    } else {
        zafu_wasm::build_signed_ironwood_send_core(
            TestNetwork,
            &fvk,
            &ask,
            prepared,
            parsed,
            amount,
            fee,
            anchor,
            target_height,
            branch_id,
            memo,
        )
    };
    res.map_err(Error::Transaction)
}

fn report_dry_run(built: &BuiltSend, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "dry_run": true,
                "tx_size_bytes": built.tx_bytes.len(),
                "fee_zat": built.fee,
                "amount_zat": built.amount,
                "change_zat": built.change,
                "recipient": built.recipient,
                "ironwood_notes_spent": built.note_count,
                "tx_hex": hex::encode(&built.tx_bytes),
            })
        );
    } else {
        println!("dry run — transaction built and proven, NOT broadcast");
        println!("  tx size:   {} bytes", built.tx_bytes.len());
        println!(
            "  amount:    {} zat ({:.8} ZEC)",
            built.amount,
            built.amount as f64 / 1e8
        );
        println!(
            "  fee:       {} zat ({:.8} ZEC)",
            built.fee,
            built.fee as f64 / 1e8
        );
        println!(
            "  change:    {} zat ({:.8} ZEC)",
            built.change,
            built.change as f64 / 1e8
        );
        println!("  recipient: {}", built.recipient);
        println!("  spends:    {} ironwood note(s)", built.note_count);
        println!("re-run without --dry-run to broadcast");
    }
}

async fn broadcast(
    client: &ZidecarClient,
    built: BuiltSend,
    transparent: bool,
    json: bool,
) -> Result<(), Error> {
    let result = client.send_transaction(built.tx_bytes).await?;

    if result.is_success() {
        let wallet = Wallet::open(&Wallet::default_path())?;
        let _ = wallet.insert_sent_tx(&SentTx {
            txid: result.txid.clone(),
            amount: built.amount,
            fee: built.fee,
            recipient: built.recipient.clone(),
            tx_type: if transparent { "z→t" } else { "z→z" }.into(),
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
                "success": result.is_success(),
                "error_code": result.error_code,
                "error_message": result.error_message,
            })
        );
    } else if result.is_success() {
        println!("txid: {}", result.txid);
    }

    if !result.is_success() {
        return Err(Error::Transaction(format!(
            "broadcast rejected ({}): {}",
            result.error_code, result.error_message
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(value: u64, pool: Pool, position: u64) -> WalletNote {
        WalletNote {
            value,
            nullifier: [0u8; 32],
            cmx: [0u8; 32],
            block_height: 0,
            is_change: false,
            recipient: vec![],
            rho: [0u8; 32],
            rseed: [0u8; 32],
            position,
            txid: vec![],
            memo: None,
            pool,
        }
    }

    /// The mirror image of `ops::send::select_notes_skips_ironwood`: this path
    /// spends ironwood and must never reach for an orchard note, which at NU6.3
    /// cannot produce an output.
    #[test]
    fn select_skips_orchard() {
        let notes = vec![
            note(1_000_000, Pool::Orchard, 1),
            note(300_000, Pool::Ironwood, 2),
        ];
        let selected = select_ironwood_notes(&notes, 200_000).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].pool, Pool::Ironwood);

        // orchard value must not count toward spendable funds
        let err = select_ironwood_notes(&notes, 500_000).unwrap_err();
        match err {
            Error::InsufficientFunds { have, .. } => assert_eq!(have, 300_000),
            other => panic!("expected InsufficientFunds, got {:?}", other),
        }
    }

    #[test]
    fn select_takes_largest_first() {
        let notes = vec![
            note(10_000, Pool::Ironwood, 1),
            note(500_000, Pool::Ironwood, 2),
            note(20_000, Pool::Ironwood, 3),
        ];
        let selected = select_ironwood_notes(&notes, 400_000).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 500_000);
    }

    /// The shape this command will actually run first: one note in, one shielded
    /// recipient, change back to self. Two logical actions, 10,000 zat — the
    /// same fee the `signed_ironwood_send_v6` fixture pins.
    #[test]
    fn fee_matches_single_note_shielded_send_fixture() {
        assert_eq!(compute_fee(1, 1, 0, true), 10_000);
    }

    /// ZIP-317 sums the transparent output alongside the padded shielded
    /// bundle, so z→t costs one action more than z→z at the same note count.
    #[test]
    fn transparent_recipient_costs_one_more_action() {
        assert_eq!(compute_fee(1, 0, 1, true), 15_000);
        assert!(compute_fee(1, 0, 1, true) > compute_fee(1, 1, 0, true));
    }
}

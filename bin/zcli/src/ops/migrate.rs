//! `zcli tx migrate` — the NU6.3 one-way turnstile: spend orchard notes and
//! output their value (minus fee) to the wallet's OWN ironwood address.
//!
//! # Why this command exists
//!
//! At NU6.3 the turnstile is one-way: orchard OUTPUTS are consensus-disabled,
//! but orchard SPENDS remain valid. `zcli tx send` pins the pre-NU6.2 orchard
//! bundle protocol and therefore refuses to run at all past activation (see
//! `tx::guard_pre_nu6_2_orchard_builder_allowed`). A wallet whose whole balance
//! sits in orchard notes consequently has no way to move value from the CLI.
//! This command is that way: a single V6 transaction with an orchard spend
//! bundle and an ironwood output bundle, self-addressed.
//!
//! # Where the money path lives
//!
//! The builder is NOT reimplemented here. It is
//! [`zafu_wasm::build_signed_turnstile_migration_core`], the same code the
//! browser wallet uses, which is generic over `zcash_protocol::consensus::
//! Parameters` specifically so native callers like this one can drive it. It
//! runs Creator -> IoFinalizer -> Prover (orchard + ironwood, post-NU6.3
//! circuit) -> low-level Signer -> TransactionExtractor, and the extractor
//! re-verifies both proofs and every spend-auth + binding signature before
//! handing back bytes. It also carries the FAIL-CLOSED branch-id guard.
//!
//! This module only does wallet-side work: note selection, ZIP-317 fee
//! arithmetic, merkle witness construction, and broadcast.

use crate::client::ZidecarClient;
use crate::error::Error;
use crate::key::WalletSeed;
use crate::wallet::{Pool, Wallet};
use crate::witness;

/// ZIP-317 marginal fee, in zatoshis per logical action.
const MARGINAL_FEE: u64 = 5_000;

/// ZIP-317 grace / minimum action count for a non-empty shielded bundle. Each
/// shielded bundle in the transaction is padded up to this many actions.
const MIN_SHIELDED_ACTIONS: usize = 2;

/// Real NU6.3 / Ironwood consensus branch id. Mirrors the constant in `tx.rs`
/// (private there) and the one the shared builder's guard enforces.
const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;

/// ZIP-317 fee for a turnstile migration of `n_orchard_notes` notes.
///
/// The migration is a single transaction with TWO non-empty shielded bundles,
/// and ZIP-317 sums logical actions ACROSS bundles:
///
/// * the ORCHARD bundle spends `n` notes and creates only zero-value dummy
///   outputs, so it has `max(n, 2)` actions after padding;
/// * the IRONWOOD bundle has one real output and no real spend, so it pads to
///   exactly 2 actions.
///
/// Hence `5000 * (max(n, 2) + 2)`.
///
/// Cross-checked against the migration mined on mainnet in block 3,436,797
/// (tx `e0932c3f91d1a14f…`): 2 orchard actions + 2 ironwood actions, fee
/// 20,000 zat, confirmed by that transaction's value balances (orchard
/// +385,000, ironwood -365,000). See the unit tests below.
pub fn compute_migration_fee(n_orchard_notes: usize) -> u64 {
    let orchard_actions = n_orchard_notes.max(MIN_SHIELDED_ACTIONS);
    let ironwood_actions = MIN_SHIELDED_ACTIONS;
    MARGINAL_FEE * (orchard_actions + ironwood_actions) as u64
}

/// Select the orchard notes to migrate, largest first.
///
/// Unlike [`crate::ops::send::select_notes`] there is no target amount: a
/// migration moves the WHOLE orchard balance. `max_notes` bounds the batch so
/// a first live run can be done with a single note (proving time and fee both
/// scale with the count).
fn select_migration_notes(
    notes: &[crate::wallet::WalletNote],
    max_notes: Option<usize>,
) -> Vec<crate::wallet::WalletNote> {
    let mut sorted: Vec<_> = notes
        .iter()
        .filter(|n| n.pool == Pool::Orchard)
        .cloned()
        .collect();
    // Value descending, then position descending — same ordering rationale as
    // the send path: recent notes minimise merkle witness replay distance.
    sorted.sort_by(|a, b| b.value.cmp(&a.value).then(b.position.cmp(&a.position)));
    if let Some(k) = max_notes {
        sorted.truncate(k);
    }
    sorted
}

/// Outcome of a migration build, before broadcast.
struct BuiltMigration {
    tx_bytes: Vec<u8>,
    fee: u64,
    migrated: u64,
    destination: String,
    note_count: usize,
}

#[allow(clippy::too_many_arguments)]
pub async fn migrate(
    seed: &WalletSeed,
    endpoint: &str,
    fee_override: Option<u64>,
    memo: Option<&str>,
    max_notes: Option<usize>,
    dry_run: bool,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    let (selected, cached_frontier, sync_height) = {
        let wallet = Wallet::open(&Wallet::default_path())?;
        let (_balance, notes) = wallet.shielded_balance()?;
        let frontier = wallet
            .tree_frontier(crate::wallet::Pool::Orchard)
            .ok()
            .flatten();
        let sh = wallet.sync_height().unwrap_or(0);
        (select_migration_notes(&notes, max_notes), frontier, sh)
    }; // drop the wallet handle before the (slow) build re-opens it

    if selected.is_empty() {
        return Err(Error::Transaction(
            "no orchard notes to migrate: the turnstile spends orchard notes, and \
             this wallet holds none (run `zcli sync`, or check `zcli view notes`)"
                .into(),
        ));
    }

    let total_in: u64 = selected.iter().map(|n| n.value).sum();
    let fee = fee_override.unwrap_or_else(|| compute_migration_fee(selected.len()));
    if total_in <= fee {
        return Err(Error::InsufficientFunds {
            have: total_in,
            need: fee + 1,
        });
    }
    let migrated = total_in - fee;

    // The destination is the wallet's OWN ironwood address: internal scope,
    // diversifier 0 — exactly what the shared builder derives from the fvk.
    // Derived here only so the operator can SEE it before broadcast.
    let fvk = crate::address::full_viewing_key(seed, mainnet)?;
    let destination = crate::address::encode_unified_address(
        &fvk.address_at(0u32, orchard::keys::Scope::Internal),
        mainnet,
    )?;

    if !json {
        eprintln!(
            "turnstile migration: {} orchard note(s), {:.8} ZEC in, fee {:.8} ZEC, \
             {:.8} ZEC → own ironwood address",
            selected.len(),
            total_in as f64 / 1e8,
            fee as f64 / 1e8,
            migrated as f64 / 1e8,
        );
    }

    let client = ZidecarClient::connect(endpoint).await?;
    let (tip, _) = client.get_tip().await?;

    // FAIL CLOSED on the branch id BEFORE spending minutes on Halo 2 proving.
    // The shared builder re-checks this (it refuses the 0xffff_ffff placeholder
    // and any mismatch against what the params would bind), but a V6 turnstile
    // is only a valid shape once NU6.3 is actually active, so refuse early and
    // with a message that names the problem.
    let branch_id = client.resolve_branch_id().await?;
    if branch_id != NU6_3_BRANCH_ID {
        return Err(Error::Transaction(format!(
            "refusing to build a turnstile migration: the node reports consensus \
             branch id {:#010x}, but the migration is a V6 (NU6.3 / ironwood) \
             transaction and is only valid under {:#010x}. NU6.3 is not active on \
             the chain this node follows.",
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
        crate::wallet::Pool::Orchard,
        json,
        cached_frontier,
        sync_height,
    )
    .await?;

    let orchard_notes: Vec<orchard::Note> = selected
        .iter()
        .map(|n| n.reconstruct_note())
        .collect::<Result<_, _>>()?;
    let prepared: Vec<(orchard::Note, orchard::tree::MerklePath)> =
        orchard_notes.into_iter().zip(paths).collect();

    if !json {
        eprintln!("building + proving transaction (halo 2, orchard + ironwood bundles)...");
    }

    // Proving is CPU-bound and rayon-parallel; keep it off the async runtime.
    let seed_bytes = *seed.as_bytes();
    let memo_owned = memo.map(str::to_string);
    let note_count = selected.len();
    let tx_bytes = tokio::task::spawn_blocking(move || {
        let seed = WalletSeed::from_bytes(seed_bytes);
        build_signed_migration(
            &seed,
            prepared,
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

    let built = BuiltMigration {
        tx_bytes,
        fee,
        migrated,
        destination,
        note_count,
    };

    if dry_run {
        report_dry_run(&built, json);
        return Ok(());
    }

    broadcast(&client, built, json).await
}

fn report_dry_run(built: &BuiltMigration, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "dry_run": true,
                "tx_size_bytes": built.tx_bytes.len(),
                "fee_zat": built.fee,
                "migrated_zat": built.migrated,
                "destination": built.destination,
                "orchard_notes_spent": built.note_count,
                "tx_hex": hex::encode(&built.tx_bytes),
            })
        );
    } else {
        println!("dry run — transaction built and proven, NOT broadcast");
        println!("  tx size:     {} bytes", built.tx_bytes.len());
        println!(
            "  fee:         {} zat ({:.8} ZEC)",
            built.fee,
            built.fee as f64 / 1e8
        );
        println!(
            "  migrated:    {} zat ({:.8} ZEC)",
            built.migrated,
            built.migrated as f64 / 1e8
        );
        println!("  destination: {} (own ironwood, internal)", built.destination);
        println!("  spends:      {} orchard note(s)", built.note_count);
        println!("re-run without --dry-run to broadcast");
    }
}

async fn broadcast(
    client: &ZidecarClient,
    built: BuiltMigration,
    json: bool,
) -> Result<(), Error> {
    let result = client.send_transaction(built.tx_bytes).await?;

    if result.is_success() {
        let wallet = Wallet::open(&Wallet::default_path())?;
        let _ = wallet.insert_sent_tx(&crate::wallet::SentTx {
            txid: result.txid.clone(),
            amount: built.migrated,
            fee: built.fee,
            recipient: built.destination.clone(),
            tx_type: "turnstile".into(),
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
                "amount_zat": built.migrated,
                "fee_zat": built.fee,
                "recipient": built.destination,
                "type": "turnstile",
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

/// Derive the spend keys and hand off to the shared zafu money-path builder.
#[allow(clippy::too_many_arguments)]
fn build_signed_migration(
    seed: &WalletSeed,
    prepared: Vec<(orchard::Note, orchard::tree::MerklePath)>,
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

    // `mainnet` picks the consensus params TYPE, so the call is duplicated
    // rather than parameterised; only one arm ever runs, so the moves are fine.
    let res = if mainnet {
        zafu_wasm::build_signed_turnstile_migration_core(
            MainNetwork,
            &fvk,
            &ask,
            prepared,
            fee,
            anchor,
            target_height,
            branch_id,
            memo,
        )
    } else {
        zafu_wasm::build_signed_turnstile_migration_core(
            TestNetwork,
            &fvk,
            &ask,
            prepared,
            fee,
            anchor,
            target_height,
            branch_id,
            memo,
        )
    };
    res.map_err(Error::Transaction)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned to the migration mined on mainnet in block 3,436,797
    /// (tx e0932c3f91d1a14f…): a 2-orchard-action + 2-ironwood-action turnstile
    /// paying 20,000 zat, evidenced by its value balances (orchard +385,000,
    /// ironwood -365,000 => fee 20,000).
    #[test]
    fn fee_matches_mined_mainnet_migration() {
        const MINED_ORCHARD_VALUE_BALANCE: i64 = 385_000;
        const MINED_IRONWOOD_VALUE_BALANCE: i64 = -365_000;
        let mined_fee = (MINED_ORCHARD_VALUE_BALANCE + MINED_IRONWOOD_VALUE_BALANCE) as u64;
        assert_eq!(mined_fee, 20_000);

        // That transaction's orchard bundle carried 2 actions, which is what
        // ZIP-317 padding produces for either 1 or 2 real spends.
        assert_eq!(compute_migration_fee(1), mined_fee);
        assert_eq!(compute_migration_fee(2), mined_fee);
    }

    /// 5000 * (max(n,2) + 2), summed across both shielded bundles.
    #[test]
    fn fee_scales_with_orchard_notes() {
        assert_eq!(compute_migration_fee(0), 20_000); // padded to 2 + 2
        assert_eq!(compute_migration_fee(1), 20_000);
        assert_eq!(compute_migration_fee(2), 20_000);
        assert_eq!(compute_migration_fee(3), 25_000);
        assert_eq!(compute_migration_fee(10), 60_000);
        for n in 0..64usize {
            assert_eq!(
                compute_migration_fee(n),
                5_000 * (n.max(2) as u64 + 2),
                "fee formula diverged at n = {n}"
            );
        }
    }

    fn note(value: u64, position: u64, pool: Pool) -> crate::wallet::WalletNote {
        crate::wallet::WalletNote {
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

    /// The turnstile spends ORCHARD notes only — ironwood notes are already
    /// through the turnstile and would need an ironwood spend path.
    #[test]
    fn migration_selects_only_orchard_notes() {
        let notes = vec![
            note(500_000, 1, Pool::Orchard),
            note(900_000, 2, Pool::Ironwood),
            note(100_000, 3, Pool::Orchard),
        ];
        let sel = select_migration_notes(&notes, None);
        assert_eq!(sel.len(), 2);
        assert!(sel.iter().all(|n| n.pool == Pool::Orchard));
        // largest first
        assert_eq!(sel[0].value, 500_000);
        assert_eq!(sel[1].value, 100_000);
    }

    #[test]
    fn migration_respects_max_notes() {
        let notes = vec![
            note(100, 1, Pool::Orchard),
            note(300, 2, Pool::Orchard),
            note(200, 3, Pool::Orchard),
        ];
        let sel = select_migration_notes(&notes, Some(2));
        assert_eq!(sel.len(), 2);
        assert_eq!(sel[0].value, 300);
        assert_eq!(sel[1].value, 200);
        assert_eq!(select_migration_notes(&notes, None).len(), 3);
        assert!(select_migration_notes(&[], None).is_empty());
    }
}

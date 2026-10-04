use indicatif::{ProgressBar, ProgressStyle};
use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey};
use orchard::note_encryption::{
    DomainVersion, IronwoodDomain, NoteEncryptionDomain, OrchardDomain,
};
use zcash_note_encryption::{
    try_compact_note_decryption, EphemeralKeyBytes, ShieldedOutput, COMPACT_NOTE_SIZE,
};

use crate::client::{LightwalletdClient, ZidecarClient};
use crate::error::Error;
use crate::key::WalletSeed;
use crate::wallet::{Wallet, WalletNote};

const BATCH_SIZE_MIN: u32 = 500;
/// Floor when a batch keeps timing out. The sapling-sandblast region (~1.72M)
/// has blocks of 500 KB with zero orchard actions; zidecar must fetch each
/// full block from zebrad to learn that, so 500 such blocks take longer than
/// the request timeout. Shrinking further makes progress instead of failing.
const BATCH_SIZE_FLOOR: u32 = 50;
/// A batch that took at least this long to serve is shrunk, whatever it held.
/// Half the 300 s stream timeout: one more doubling of a batch this slow would
/// time out.
const BATCH_SLOW_SECS: u64 = 60;
/// A batch must be served faster than this before the size may grow.
const BATCH_QUICK_SECS: u64 = 20;
const BATCH_SIZE_MAX: u32 = 2_000; // reduced from 5k — zidecar chokes on dense blocks
const BATCH_ACTIONS_TARGET: usize = 20_000; // reduced from 50k

/// Progress is measured in work units, not blocks. A block-count bar sits
/// still for minutes on dense ranges and then sprints through empty ones,
/// so its ETA is noise. One unit per shielded output (orchard action,
/// ironwood action, sapling output) plus `WORK_PER_BLOCK` per block: the
/// output terms track trial-decryption and wire cost, the block term keeps
/// the bar moving through ranges the server is slow to serve for other
/// reasons (the sapling-sandblast blocks are 500 KB with zero orchard
/// actions). The constant is a heuristic; nothing depends on its exact value.
const WORK_PER_BLOCK: u64 = 2;
/// Sapling outputs are not in the compact stream zidecar serves, so their
/// progress is interpolated between tree sizes sampled at this many
/// bucket boundaries (one `GetTreeState` each, up front).
const WORK_BUCKETS: u32 = 32;
/// Below this many blocks the bucket sampling is not worth the round-trips;
/// endpoints only.
const WORK_BUCKET_MIN_BLOCKS: u32 = 4_000;

/// Output-weighted progress model for one scan range.
///
/// Orchard and ironwood progress is exact: the scan keeps the global tree
/// position of every action it has processed, and the tree size at the tip
/// is the target. Sapling progress is interpolated from tree sizes sampled at
/// bucket boundaries. Standard lightwalletd exposes the same tree states, so
/// this needs no server extension.
struct WorkModel {
    start: u32,
    tip: u32,
    orchard_start: u64,
    ironwood_start: u64,
    /// `(height, sapling tree size at height)` ascending; first is `start - 1`
    /// (or 0 when `start` is 0), last is `tip`.
    sapling_samples: Vec<(u32, u64)>,
    total: u64,
}

impl WorkModel {
    /// Sample tree states for `start..=tip`. `orchard_start` / `ironwood_start`
    /// are the tree sizes at `start - 1`, which the scan already holds as its
    /// seeded position counters.
    async fn build(
        client: &ZidecarClient,
        start: u32,
        tip: u32,
        orchard_start: u64,
        ironwood_start: u64,
    ) -> Result<Self, Error> {
        let blocks = tip - start + 1;
        let buckets = if blocks >= WORK_BUCKET_MIN_BLOCKS {
            WORK_BUCKETS
        } else {
            1
        };
        let base = start.saturating_sub(1);
        let mut heights: Vec<u32> = (0..buckets)
            .map(|i| base + (blocks as u64 * i as u64 / buckets as u64) as u32)
            .collect();
        heights.push(tip);
        heights.dedup();

        let mut sapling_samples = Vec::with_capacity(heights.len());
        let mut tip_state = None;
        for h in heights {
            let st = client.get_tree_states(h).await?;
            let sapling = hex::decode(&st.sapling_tree)
                .map_err(|e| Error::Other(format!("invalid sapling tree hex: {e}")))?;
            sapling_samples.push((h, crate::witness::frontier_leaf_count(&sapling)?));
            if h == tip {
                tip_state = Some(st);
            }
        }
        let tip_state = tip_state.ok_or_else(|| Error::Other("no tip tree state".into()))?;
        let size = |hex_tree: &str| -> Result<u64, Error> {
            let bytes = hex::decode(hex_tree)
                .map_err(|e| Error::Other(format!("invalid tree hex: {e}")))?;
            crate::witness::frontier_leaf_count(&bytes)
        };
        let orchard_tip = size(&tip_state.orchard_tree)?;
        let ironwood_tip = size(&tip_state.ironwood_tree)?;
        let sapling_total = Self::sapling_span(&sapling_samples);

        let total = orchard_tip.saturating_sub(orchard_start)
            + ironwood_tip.saturating_sub(ironwood_start)
            + sapling_total
            + WORK_PER_BLOCK * blocks as u64;
        Ok(Self {
            start,
            tip,
            orchard_start,
            ironwood_start,
            sapling_samples,
            total,
        })
    }

    fn sapling_span(samples: &[(u32, u64)]) -> u64 {
        let first = samples.first().map(|(_, s)| *s).unwrap_or(0);
        let last = samples.last().map(|(_, s)| *s).unwrap_or(0);
        last.saturating_sub(first)
    }

    /// Sapling outputs from `start` through `height` inclusive, interpolated
    /// linearly inside the bucket that contains `height`.
    fn sapling_done(&self, height: u32) -> u64 {
        let base = self.sapling_samples.first().map(|(_, s)| *s).unwrap_or(0);
        let mut prev = self.sapling_samples[0];
        for &(h, size) in &self.sapling_samples[1..] {
            if height >= h {
                prev = (h, size);
                continue;
            }
            let span = (h - prev.0) as u64;
            let into = (height - prev.0) as u64;
            let delta = size.saturating_sub(prev.1);
            return prev.1.saturating_sub(base) + delta * into / span;
        }
        prev.1.saturating_sub(base)
    }

    /// Work units completed once every block through `last_done` (inclusive)
    /// has been scanned and the position counters have advanced past it.
    fn done(&self, last_done: u32, orchard_pos: u64, ironwood_pos: u64) -> u64 {
        let blocks = (last_done + 1).saturating_sub(self.start) as u64;
        let units = orchard_pos
            .saturating_sub(self.orchard_start)
            .saturating_add(ironwood_pos.saturating_sub(self.ironwood_start))
            .saturating_add(self.sapling_done(last_done))
            .saturating_add(WORK_PER_BLOCK * blocks);
        units.min(self.total)
    }

    fn describe(&self) -> String {
        let blocks = (self.tip - self.start + 1) as u64;
        let outputs = self.total - WORK_PER_BLOCK * blocks;
        format!(
            "{} shielded outputs to scan ({} sapling) over {} blocks",
            outputs,
            Self::sapling_span(&self.sapling_samples),
            blocks
        )
    }
}

use zync_core::{
    ACTIVATION_HASH_MAINNET, ORCHARD_ACTIVATION_HEIGHT as ORCHARD_ACTIVATION_MAINNET,
    ORCHARD_ACTIVATION_HEIGHT_TESTNET as ORCHARD_ACTIVATION_TESTNET,
};

struct CompactShieldedOutput {
    epk: [u8; 32],
    cmx: [u8; 32],
    ciphertext: [u8; 52],
}

// Generic over the note-plaintext version: upstream orchard splits the
// note-encryption domain by note version and enforces the plaintext lead byte,
// so a single concrete domain can no longer decrypt both pools. See
// `try_compact_decrypt_any_version`.
impl<V: DomainVersion> ShieldedOutput<NoteEncryptionDomain<V>, COMPACT_NOTE_SIZE>
    for CompactShieldedOutput
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.epk)
    }
    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx
    }
    fn enc_ciphertext(&self) -> &[u8; COMPACT_NOTE_SIZE] {
        &self.ciphertext
    }
}

/// Trial-decrypt a compact output against BOTH note-plaintext versions.
///
/// `OrchardDomain` accepts only V2 note plaintexts (lead byte 0x02) and
/// `IronwoodDomain` only V3 (0x03); upstream orchard returns `None` on a
/// mismatch. A compact action off the wire carries no pool label, so both
/// domains must be tried or every ironwood note is invisible.
fn try_compact_decrypt_any_version(
    compact: &orchard::note_encryption::CompactAction,
    ivk: &PreparedIncomingViewingKey,
    output: &CompactShieldedOutput,
) -> Option<(orchard::Note, orchard::Address)> {
    try_compact_note_decryption(&OrchardDomain::for_compact_action(compact), ivk, output).or_else(
        || try_compact_note_decryption(&IronwoodDomain::for_compact_action(compact), ivk, output),
    )
}

/// sync using a FullViewingKey directly (for watch-only wallets)
pub async fn sync_with_fvk(
    fvk: &FullViewingKey,
    endpoint: &str,
    verify_endpoints: &str,
    mainnet: bool,
    json: bool,
    from: Option<u32>,
    from_position: Option<u64>,
) -> Result<u32, Error> {
    sync_inner(
        fvk,
        endpoint,
        verify_endpoints,
        mainnet,
        json,
        from,
        from_position,
    )
    .await
}

pub async fn sync(
    seed: &WalletSeed,
    endpoint: &str,
    verify_endpoints: &str,
    mainnet: bool,
    json: bool,
    from: Option<u32>,
    from_position: Option<u64>,
) -> Result<u32, Error> {
    let coin_type = if mainnet { 133 } else { 1 };

    // derive viewing keys
    let sk = SpendingKey::from_zip32_seed(seed.as_bytes(), coin_type, zip32::AccountId::ZERO)
        .map_err(|_| Error::Wallet("failed to derive spending key".into()))?;
    let fvk = FullViewingKey::from(&sk);
    sync_inner(
        &fvk,
        endpoint,
        verify_endpoints,
        mainnet,
        json,
        from,
        from_position,
    )
    .await
}

async fn sync_inner(
    fvk: &FullViewingKey,
    endpoint: &str,
    verify_endpoints: &str,
    mainnet: bool,
    json: bool,
    from: Option<u32>,
    from_position: Option<u64>,
) -> Result<u32, Error> {
    let activation = if mainnet {
        ORCHARD_ACTIVATION_MAINNET
    } else {
        ORCHARD_ACTIVATION_TESTNET
    };

    let ivk_ext = fvk.to_ivk(Scope::External).prepare();
    let ivk_int = fvk.to_ivk(Scope::Internal).prepare();

    let client = ZidecarClient::connect(endpoint).await?;
    let wallet = Wallet::open(&Wallet::default_path())?;

    let stored_height = wallet.sync_height()?;

    let start = if let Some(h) = from {
        // --from H means "tree state is known at H", so scan from H+1
        // (the tree state at H already includes block H's actions)
        (h + 1).max(activation)
    } else {
        // sync_height is the last fully processed block, so scan from +1
        if stored_height > 0 {
            (stored_height + 1).max(activation)
        } else {
            // Never synced — use birth height if set, else activation
            let bh = wallet.birth_height()?;
            if bh > activation {
                bh
            } else {
                activation
            }
        }
    };

    let (tip, tip_hash) = client.get_tip().await?;

    // verify activation block hash against hardcoded anchor
    if mainnet {
        let blocks = client.get_compact_blocks(activation, activation).await?;
        if !blocks.is_empty()
            && !blocks[0].hash.is_empty()
            && blocks[0].hash != ACTIVATION_HASH_MAINNET
        {
            return Err(Error::Other(format!(
                "activation block hash mismatch: got {} expected {}",
                hex::encode(&blocks[0].hash),
                hex::encode(ACTIVATION_HASH_MAINNET),
            )));
        }
    }

    // cross-verify tip against independent lightwalletd node(s)
    let endpoints: Vec<&str> = verify_endpoints
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if !endpoints.is_empty() {
        cross_verify(&client, &endpoints, tip, &tip_hash, activation).await?;
    }

    eprintln!("tip={} start={}", tip, start);

    if start >= tip {
        if !json {
            eprintln!("wallet up to date at height {}", tip);
        }
        return Ok(0);
    }

    if !json {
        eprintln!(
            "scanning blocks from {} to {} ({} blocks)",
            start,
            tip,
            tip - start + 1
        );
    }

    let want_bar = !json && is_terminal::is_terminal(std::io::stderr());

    let mut found_total = 0u32;
    let mut current = start;
    let mut batch_size = BATCH_SIZE_MIN; // adaptive: grows for sparse blocks, shrinks for dense
                                         // global position counter - tracks every orchard action from activation
    let mut position_counter = if let Some(pos) = from_position {
        wallet.set_orchard_position(pos)?;
        pos
    } else {
        // A scan from activation rebuilds the tree from empty, so a stored
        // position (from an earlier sync to a later height) would offset every
        // note it finds. Only `start > activation` resumes a stored tree.
        let stored = if start > activation {
            wallet.orchard_position()?
        } else {
            0
        };
        if stored == 0 && start > activation {
            // first sync from birthday — fetch tree state to get correct global position
            let (tree_hex, _) = client.get_tree_state(start - 1).await?;
            let tree_bytes = hex::decode(&tree_hex)
                .map_err(|e| Error::Other(format!("invalid tree hex: {}", e)))?;
            let pos = crate::witness::frontier_tree_size(&tree_bytes)?;
            if !json {
                eprintln!(
                    "initial position from tree state at height {}: {}",
                    start - 1,
                    pos
                );
            }
            wallet.set_orchard_position(pos)?;
            pos
        } else {
            stored
        }
    };

    // global ironwood position counter — separate tree from orchard.
    // 0 until NU6.3 activation; on first sync past activation, seed from the
    // ironwood tree size at start-1 (empty frontier hex → 0).
    let mut ironwood_position = {
        // same reasoning as the orchard counter: from activation, start empty
        let stored = if start > activation {
            wallet.ironwood_position()?
        } else {
            0
        };
        if stored == 0 {
            // Ask the chain rather than gating on an activation height. The
            // previous `start > IRONWOOD_ACTIVATION_HEIGHT` gate was wrong on
            // every non-mainnet chain — regtest activates near height 0, so a
            // 3.4M (or even testnet 4.1M) threshold is never crossed, the
            // position stayed 0 while the scan began mid-chain, and every note
            // got an offset position whose witness failed against the anchor
            // (AnchorMismatch at broadcast). The tree state answers the real
            // question directly: an empty/absent ironwood tree yields 0, which
            // is exactly the right seed pre-activation, so no constant is
            // needed and the bug class disappears.
            match client
                .get_ironwood_tree_state(start.saturating_sub(1))
                .await
            {
                Ok((tree_hex, _)) if !tree_hex.is_empty() => {
                    let tree_bytes = hex::decode(&tree_hex)
                        .map_err(|e| Error::Other(format!("invalid ironwood tree hex: {}", e)))?;
                    let pos = crate::witness::frontier_tree_size(&tree_bytes)?;
                    if !json && pos > 0 {
                        eprintln!("initial ironwood position from tree state: {}", pos);
                    }
                    wallet.set_ironwood_position(pos)?;
                    pos
                }
                // Empty tree (pre-activation) → 0 is correct. A failed query is
                // also 0, but warn: post-activation that would produce offset
                // positions, which surface as a failed build rather than silently.
                Ok(_) => 0,
                Err(e) => {
                    if !json {
                        eprintln!(
                            "warning: ironwood tree state unavailable ({e}); seeding position 0"
                        );
                    }
                    0
                }
            }
        } else {
            stored
        }
    };

    // Output-weighted progress. Falls back to a plain block bar if the tree
    // states cannot be fetched: a progress bar must never fail a sync.
    let total_blocks = (tip - start + 1) as u64;
    let work = if want_bar {
        match WorkModel::build(&client, start, tip, position_counter, ironwood_position).await {
            Ok(w) => {
                eprintln!("{}", w.describe());
                Some(w)
            }
            Err(e) => {
                eprintln!("warning: tree states unavailable for progress ({e}); counting blocks");
                None
            }
        }
    } else {
        None
    };
    let pb = if want_bar {
        let len = work.as_ref().map(|w| w.total).unwrap_or(total_blocks);
        let pb = ProgressBar::new(len.max(1));
        let template = if work.is_some() {
            "[{elapsed}] {bar:40.cyan/blue} {percent:>3}% {msg} ETA: {eta}"
        } else {
            "[{elapsed}] {bar:40.cyan/blue} {pos:>7}/{len:7} blocks {per_sec} ETA: {eta}"
        };
        pb.set_style(
            ProgressStyle::default_bar()
                .template(template)
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    // collect new notes that need memo fetching
    type MemoEntry = ([u8; 32], Vec<u8>, [u8; 32], [u8; 32], [u8; 32]);
    let mut needs_memo: Vec<MemoEntry> = Vec::new();

    // collect notes in memory first; only persist after proof verification
    let mut pending_notes: Vec<WalletNote> = Vec::new();
    // collect nullifiers seen in actions to mark spent after verification
    let mut seen_nullifiers: Vec<[u8; 32]> = Vec::new();
    // The server must stream every height from `start` to the tip. A block
    // missing from the stream would hide whatever it contains (a payment, a
    // spend) while every block received is internally consistent, so track the
    // first gap and refuse to store a sync point past it.
    let mut first_height_gap: Option<(u32, u32)> = None;
    // The scan begins AT `start` (`current = start` below), not after it — the
    // block at `start` is the first one streamed.
    let mut expected_height = start;
    // Highest block actually scanned. Must equal `tip` before the sync point
    // is stored at `tip`.
    let mut last_folded_height: Option<u32> = None;

    while current <= tip {
        let end = (current + batch_size - 1).min(tip);
        let fetch_started = std::time::Instant::now();
        let blocks = match retry_compact_blocks(&client, current, end).await {
            Ok(b) => b,
            Err(_) if batch_size > BATCH_SIZE_FLOOR => {
                // batch too large (or too slow to serve) — halve and retry
                batch_size = (batch_size / 2).max(BATCH_SIZE_FLOOR);
                eprintln!("  reducing batch size to {}", batch_size);
                continue;
            }
            Err(e) => return Err(e),
        };

        let action_count: usize = blocks
            .iter()
            .map(|b| b.actions.len() + b.ironwood_actions.len())
            .sum();
        if action_count > 0 {
            eprintln!(
                "  batch {}..{}: {} blocks, {} shielded actions",
                current,
                end,
                blocks.len(),
                action_count
            );
        }

        // adaptive batch sizing: grow for sparse blocks, shrink for dense,
        // capped to 2x per step to avoid overshooting.
        //
        // Sizing by action count alone misjudges ranges that are SLOW rather
        // than dense: the sapling-sandblast blocks carry zero orchard actions
        // but take the server ~0.2 s each, so "sparse" doubled the batch,
        // the doubled batch timed out twice, and each 500 blocks cost three
        // attempts (~12 min). Serve time is the signal that matters for the
        // timeout, so it takes precedence: a slow batch shrinks, and only a
        // quick one may grow.
        let fetch_secs = fetch_started.elapsed().as_secs();
        if fetch_secs >= BATCH_SLOW_SECS {
            batch_size = (batch_size / 2).max(BATCH_SIZE_FLOOR);
        } else if fetch_secs >= BATCH_QUICK_SECS {
            // hold
        } else if action_count == 0 {
            batch_size = (batch_size * 2).min(BATCH_SIZE_MAX);
        } else if action_count > BATCH_ACTIONS_TARGET {
            batch_size = (batch_size / 2).max(BATCH_SIZE_MIN);
        } else {
            batch_size = (batch_size * 2).clamp(BATCH_SIZE_MIN, BATCH_SIZE_MAX);
        }

        for block in &blocks {
            for action in &block.actions {
                if action.ciphertext.len() < 52 {
                    position_counter += 1;
                    continue;
                }

                let mut ct = [0u8; 52];
                ct.copy_from_slice(&action.ciphertext[..52]);

                let output = CompactShieldedOutput {
                    epk: action.ephemeral_key,
                    cmx: action.cmx,
                    ciphertext: ct,
                };

                // try external then internal scope
                let result = try_decrypt(fvk, &ivk_ext, &ivk_int, &action.nullifier, &output);

                if let Some(decrypted) = result {
                    let wallet_note = WalletNote {
                        value: decrypted.value,
                        nullifier: decrypted.nullifier,
                        cmx: action.cmx,
                        block_height: block.height,
                        is_change: decrypted.is_change,
                        recipient: decrypted.recipient,
                        rho: decrypted.rho,
                        rseed: decrypted.rseed,
                        position: position_counter,
                        txid: action.txid.clone(),
                        memo: None,
                        pool: crate::wallet::Pool::Orchard,
                    };
                    pending_notes.push(wallet_note);
                    found_total += 1;

                    if !action.txid.is_empty() && !decrypted.is_change {
                        needs_memo.push((
                            decrypted.nullifier,
                            action.txid.clone(),
                            action.cmx,
                            action.ephemeral_key,
                            action.nullifier,
                        ));
                    }
                }

                // collect nullifiers for marking spent after verification
                seen_nullifiers.push(action.nullifier);

                position_counter += 1;
            }

            // ironwood actions (NU6.3+): same trial decryption — the pool
            // reuses orchard note encryption and addresses — but positions
            // count leaves of the separate ironwood tree, and memo retrieval
            // is skipped (it needs v6 raw-tx parsing the wallet doesn't have
            // yet). Notes are tagged Pool::Ironwood and excluded from spend
            // selection until v6 transaction building lands.
            for action in &block.ironwood_actions {
                if action.ciphertext.len() < 52 {
                    ironwood_position += 1;
                    continue;
                }

                let mut ct = [0u8; 52];
                ct.copy_from_slice(&action.ciphertext[..52]);

                let output = CompactShieldedOutput {
                    epk: action.ephemeral_key,
                    cmx: action.cmx,
                    ciphertext: ct,
                };

                let result = try_decrypt(fvk, &ivk_ext, &ivk_int, &action.nullifier, &output);

                if let Some(decrypted) = result {
                    pending_notes.push(WalletNote {
                        value: decrypted.value,
                        nullifier: decrypted.nullifier,
                        cmx: action.cmx,
                        block_height: block.height,
                        is_change: decrypted.is_change,
                        recipient: decrypted.recipient,
                        rho: decrypted.rho,
                        rseed: decrypted.rseed,
                        position: ironwood_position,
                        txid: action.txid.clone(),
                        memo: None,
                        pool: crate::wallet::Pool::Ironwood,
                    });
                    found_total += 1;
                }

                seen_nullifiers.push(action.nullifier);

                ironwood_position += 1;
            }

            // every height in order, no gaps
            if block.height != expected_height && first_height_gap.is_none() {
                first_height_gap = Some((expected_height, block.height));
            }
            expected_height = block.height + 1;
            last_folded_height = Some(block.height);

        }

        current = end + 1;

        if let Some(ref pb) = pb {
            match work {
                Some(ref w) => {
                    pb.set_position(w.done(end, position_counter, ironwood_position));
                    pb.set_message(format!("height {}/{}", end, tip));
                }
                None => pb.set_position((current - start) as u64),
            }
        }
    }

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    // The sync point about to be stored must describe the blocks actually
    // scanned. A run whose last batch came back short scans up to some height
    // below `tip` and would store it AS `tip`, silently skipping the rest.
    if last_folded_height != Some(tip) {
        return Err(Error::Other(format!(
            "scan reached block {} but the tip is {}: refusing to store a sync \
             point past the blocks actually scanned",
            last_folded_height
                .map(|h| h.to_string())
                .unwrap_or_else(|| "none".to_string()),
            tip
        )));
    }

    if let Some((expected, got)) = first_height_gap {
        return Err(Error::Other(format!(
            "the server skipped blocks: expected block {} but it sent {}. Nothing \
             was stored; retry, or sync from another server.",
            expected, got
        )));
    }

    // every block arrived; persist notes to wallet
    for note in &pending_notes {
        wallet.insert_note(note)?;
    }
    for nf in &seen_nullifiers {
        wallet.mark_spent(nf).ok();
    }
    wallet.commit_sync_point(tip, position_counter, ironwood_position)?;

    // cache tree frontier at sync height for fast witness building (no binary search).
    // BOTH pools: the two trees are separate, and a witness for an ironwood note
    // replayed from the orchard frontier would produce a wrong anchor.
    match client.get_tree_state(tip).await {
        Ok((tree_hex, _)) => {
            if let Err(e) = wallet.set_tree_frontier(crate::wallet::Pool::Orchard, &tree_hex, tip) {
                eprintln!("warning: failed to cache orchard tree frontier: {}", e);
            }
        }
        Err(e) => eprintln!("warning: failed to fetch tree state for caching: {}", e),
    }
    match client.get_ironwood_tree_state(tip).await {
        // An empty ironwood frontier means the pool is not active yet (or the
        // server predates it). Caching "" would look like a size-0 tree at this
        // height and mis-place every later position, so store nothing.
        Ok((tree_hex, _)) if !tree_hex.is_empty() => {
            if let Err(e) = wallet.set_tree_frontier(crate::wallet::Pool::Ironwood, &tree_hex, tip)
            {
                eprintln!("warning: failed to cache ironwood tree frontier: {}", e);
            }
        }
        Ok(_) => {}
        Err(e) => eprintln!(
            "warning: failed to fetch ironwood tree state for caching: {}",
            e
        ),
    }

    // Spends are found above: every action's nullifier in every scanned block
    // is matched against our notes (seen_nullifiers). Nothing about our notes
    // is sent to the server; the NOMT nullifier and commitment proof rounds
    // that used to run here sent our unspent nullifiers in the clear and
    // answered nothing the scan does not.

    // fetch memos for newly found notes
    if !needs_memo.is_empty() {
        eprintln!("fetching memos for {} notes...", needs_memo.len());
        for (nullifier, txid, cmx, epk, action_nf) in &needs_memo {
            match fetch_memo(&client, fvk, &ivk_ext, txid, cmx, epk, action_nf).await {
                Ok(Some(memo)) => {
                    // update note in wallet with memo
                    if let Ok(mut note) = wallet.get_note(nullifier) {
                        note.memo = Some(memo);
                        wallet.insert_note(&note).ok();
                    }
                }
                Ok(None) => {}
                Err(e) => eprintln!("  memo fetch failed: {}", e),
            }
        }
    }

    // scan mempool for pending activity (full scan for privacy)
    let mempool_found = scan_mempool(&client, fvk, &ivk_ext, &ivk_int, &wallet, json).await;

    if !json {
        eprintln!(
            "synced to {} - {} new notes found (position {})",
            tip, found_total, position_counter
        );
        if mempool_found > 0 {
            eprintln!(
                "  {} pending mempool transaction(s) detected",
                mempool_found
            );
        }
    }

    Ok(found_total)
}

struct DecryptedNote {
    value: u64,
    nullifier: [u8; 32],
    is_change: bool,
    recipient: Vec<u8>,
    rho: [u8; 32],
    rseed: [u8; 32],
}

/// try trial decryption with both external and internal IVKs
/// extracts full note data needed for spending
fn try_decrypt(
    fvk: &FullViewingKey,
    ivk_ext: &PreparedIncomingViewingKey,
    ivk_int: &PreparedIncomingViewingKey,
    action_nf: &[u8; 32],
    output: &CompactShieldedOutput,
) -> Option<DecryptedNote> {
    let nf = orchard::note::Nullifier::from_bytes(action_nf);
    if nf.is_none().into() {
        return None;
    }
    let nf = nf.unwrap();

    let cmx = orchard::note::ExtractedNoteCommitment::from_bytes(&output.cmx);
    if cmx.is_none().into() {
        return None;
    }
    let cmx = cmx.unwrap();

    let compact = orchard::note_encryption::CompactAction::from_parts(
        nf,
        cmx,
        EphemeralKeyBytes(output.epk),
        output.ciphertext,
    );
    // try external scope
    if let Some((note, _)) = try_compact_decrypt_any_version(&compact, ivk_ext, output) {
        // Verify the note commitment matches what the server sent.
        // A malicious server could craft ciphertexts that decrypt to fake notes
        // with arbitrary values. Recomputing cmx from the decrypted note fields
        // and comparing against the server-provided cmx detects this.
        let recomputed = orchard::note::ExtractedNoteCommitment::from(note.commitment());
        if recomputed.to_bytes() != output.cmx {
            eprintln!("WARNING: cmx mismatch after decryption — server sent fake note, skipping");
            return None;
        }
        return Some(extract_note_data(fvk, &note, false));
    }

    // try internal scope (change/shielding)
    if let Some((note, _)) = try_compact_decrypt_any_version(&compact, ivk_int, output) {
        let recomputed = orchard::note::ExtractedNoteCommitment::from(note.commitment());
        if recomputed.to_bytes() != output.cmx {
            eprintln!("WARNING: cmx mismatch after decryption — server sent fake note, skipping");
            return None;
        }
        return Some(extract_note_data(fvk, &note, true));
    }

    None
}

use zync_core::sync::hashes_match;

/// cross-verify tip and activation block against independent lightwalletd nodes.
/// requires BFT majority (>2/3 of reachable nodes) to agree with zidecar.
/// hard-fails on hash mismatch, soft-fails only when no nodes reachable.
async fn cross_verify(
    zidecar: &ZidecarClient,
    endpoints: &[&str],
    tip: u32,
    tip_hash: &[u8],
    activation: u32,
) -> Result<(), Error> {
    eprintln!(
        "cross-verifying against {} lightwalletd node(s)...",
        endpoints.len()
    );

    // fetch activation block hash from zidecar once
    let zid_act = match zidecar.get_compact_blocks(activation, activation).await {
        Ok(blocks) if !blocks.is_empty() => blocks[0].hash.clone(),
        _ => vec![],
    };

    let mut tip_agree = 0u32;
    let mut tip_disagree = 0u32;
    let mut act_agree = 0u32;
    let mut act_disagree = 0u32;

    for &ep in endpoints {
        let lwd = match LightwalletdClient::connect(ep).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  {}: connect failed: {}", ep, e);
                continue;
            }
        };

        // check tip block hash
        match lwd.get_block(tip as u64).await {
            Ok((_, lwd_hash, _)) => {
                if hashes_match(tip_hash, &lwd_hash) {
                    tip_agree += 1;
                } else {
                    eprintln!(
                        "  {}: tip MISMATCH at {}: zidecar={} lwd={}",
                        ep,
                        tip,
                        hex::encode(tip_hash),
                        hex::encode(&lwd_hash)
                    );
                    tip_disagree += 1;
                }
            }
            Err(e) => {
                eprintln!("  {}: get_block({}): {}", ep, tip, e);
            }
        }

        // check activation block hash
        match lwd.get_block(activation as u64).await {
            Ok((_, lwd_hash, _)) => {
                if hashes_match(&zid_act, &lwd_hash) {
                    act_agree += 1;
                } else {
                    eprintln!(
                        "  {}: activation MISMATCH at {}: zidecar={} lwd={}",
                        ep,
                        activation,
                        hex::encode(&zid_act),
                        hex::encode(&lwd_hash)
                    );
                    act_disagree += 1;
                }
            }
            Err(e) => {
                eprintln!("  {}: get_block({}): {}", ep, activation, e);
            }
        }
    }

    let tip_total = tip_agree + tip_disagree;
    let act_total = act_agree + act_disagree;

    if tip_total == 0 && act_total == 0 {
        return Err(Error::Other(
            "cross-verification failed: no verify nodes responded".into(),
        ));
    }

    // BFT majority: need >2/3 of responding nodes to agree
    if tip_total > 0 {
        let threshold = (tip_total * 2).div_ceil(3);
        if tip_agree < threshold {
            return Err(Error::Other(format!(
                "tip hash rejected: {}/{} nodes disagree at height {}",
                tip_disagree, tip_total, tip,
            )));
        }
    }

    if act_total > 0 {
        let threshold = (act_total * 2).div_ceil(3);
        if act_agree < threshold {
            return Err(Error::Other(format!(
                "activation block rejected: {}/{} nodes disagree at height {}",
                act_disagree, act_total, activation,
            )));
        }
    }

    eprintln!(
        "cross-check ok: tip={} ({}/{}) activation={} ({}/{})",
        tip, tip_agree, tip_total, activation, act_agree, act_total,
    );
    Ok(())
}

/// Coverage check for one compact-block response.
///
/// A SHORT response is a failure, not a success with fewer blocks: the scan
/// takes every block it receives and then continues from `end + 1`, so a
/// stream that stops early scans a prefix while the height it stores claims
/// the requested tip. Nothing downstream can tell — the gap check only
/// compares a block against its neighbour, and a missing tail has no
/// neighbour. Returns the received span for the error message.
fn response_covers(
    blocks: &[crate::client::CompactBlock],
    start: u32,
    end: u32,
) -> Result<(), String> {
    let got = match (blocks.first(), blocks.last()) {
        (Some(f), Some(l)) => (f.height, l.height),
        _ => return Err("no blocks".to_string()),
    };
    if got.0 == start && got.1 == end {
        Ok(())
    } else {
        Err(format!("{}..{}", got.0, got.1))
    }
}

/// retry compact block fetch with backoff (grpc-web streams are flaky)
async fn retry_compact_blocks(
    client: &ZidecarClient,
    start: u32,
    end: u32,
) -> Result<Vec<crate::client::CompactBlock>, Error> {
    let mut attempts = 0;
    loop {
        match client.get_compact_blocks(start, end).await {
            Ok(blocks) => match response_covers(&blocks, start, end) {
                Ok(()) => return Ok(blocks),
                Err(got) => {
                    attempts += 1;
                    if attempts >= 3 {
                        return Err(Error::Other(format!(
                            "server returned blocks {} for the requested range {}..{} — \
                             refusing to fold a partial range",
                            got, start, end
                        )));
                    }
                    eprintln!(
                        "  retry {}/3 for {}..{}: short response, got {}",
                        attempts, start, end, got
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(500 * attempts)).await;
                }
            },
            Err(e) => {
                attempts += 1;
                if attempts >= 3 {
                    return Err(e);
                }
                eprintln!("  retry {}/3 for {}..{}: {}", attempts, start, end, e);
                tokio::time::sleep(std::time::Duration::from_millis(500 * attempts)).await;
            }
        }
    }
}

/// fetch full transaction and decrypt memo for a specific action
async fn fetch_memo(
    client: &ZidecarClient,
    _fvk: &FullViewingKey,
    ivk: &PreparedIncomingViewingKey,
    txid: &[u8],
    cmx: &[u8; 32],
    epk: &[u8; 32],
    action_nf: &[u8; 32],
) -> Result<Option<String>, Error> {
    use zcash_note_encryption::{try_note_decryption, ENC_CIPHERTEXT_SIZE};

    let raw_tx = client.get_transaction(txid).await?;
    let Some(enc) = zync_core::sync::extract_enc_ciphertext(&raw_tx, cmx, epk) else {
        return Ok(None);
    };

    let nf = orchard::note::Nullifier::from_bytes(action_nf);
    if nf.is_none().into() {
        return Ok(None);
    }
    let nf = nf.unwrap();

    let cmx_parsed = orchard::note::ExtractedNoteCommitment::from_bytes(cmx);
    if cmx_parsed.is_none().into() {
        return Ok(None);
    }
    let cmx_parsed = cmx_parsed.unwrap();

    let mut compact_ct = [0u8; 52];
    compact_ct.copy_from_slice(&enc[..52]);
    let compact = orchard::note_encryption::CompactAction::from_parts(
        nf,
        cmx_parsed,
        EphemeralKeyBytes(*epk),
        compact_ct,
    );
    struct FullOutput {
        epk: [u8; 32],
        cmx: [u8; 32],
        enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    }
    impl<V: DomainVersion> ShieldedOutput<NoteEncryptionDomain<V>, ENC_CIPHERTEXT_SIZE> for FullOutput {
        fn ephemeral_key(&self) -> EphemeralKeyBytes {
            EphemeralKeyBytes(self.epk)
        }
        fn cmstar_bytes(&self) -> [u8; 32] {
            self.cmx
        }
        fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
            &self.enc_ciphertext
        }
    }

    let output = FullOutput {
        epk: *epk,
        cmx: *cmx,
        enc_ciphertext: enc,
    };
    // Both note-version domains, same reason as `try_compact_decrypt_any_version`.
    let memo = try_note_decryption(&OrchardDomain::for_compact_action(&compact), ivk, &output)
        .or_else(|| {
            try_note_decryption(&IronwoodDomain::for_compact_action(&compact), ivk, &output)
        });
    if let Some((_, _, memo)) = memo {
        let end = memo
            .iter()
            .rposition(|&b| b != 0)
            .map(|i| i + 1)
            .unwrap_or(0);
        if end > 0 {
            return Ok(Some(String::from_utf8_lossy(&memo[..end]).to_string()));
        }
    }
    Ok(None)
}

/// scan full mempool for privacy — trial decrypt all actions + check nullifiers.
/// always scans everything so the server can't distinguish which tx triggered interest.
/// returns number of relevant transactions found (incoming or spend-pending).
async fn scan_mempool(
    client: &ZidecarClient,
    fvk: &FullViewingKey,
    ivk_ext: &PreparedIncomingViewingKey,
    ivk_int: &PreparedIncomingViewingKey,
    wallet: &Wallet,
    json: bool,
) -> u32 {
    let blocks = match client.get_mempool_stream().await {
        Ok(b) => b,
        Err(e) => {
            if !json {
                eprintln!("mempool scan skipped: {}", e);
            }
            return 0;
        }
    };

    let total_actions: usize = blocks
        .iter()
        .map(|b| b.actions.len() + b.ironwood_actions.len())
        .sum();
    if total_actions == 0 {
        return 0;
    }

    if !json {
        eprintln!(
            "scanning mempool: {} txs, {} shielded actions",
            blocks.len(),
            total_actions
        );
    }

    // collect wallet nullifiers for spend detection
    let wallet_nullifiers: Vec<[u8; 32]> = wallet
        .shielded_balance()
        .map(|(_, notes)| notes.iter().map(|n| n.nullifier).collect())
        .unwrap_or_default();

    let mut found = 0u32;

    for block in &blocks {
        let txid_hex = hex::encode(&block.hash);

        // orchard + ironwood actions decrypt identically; mempool display
        // doesn't need positions so one chained pass covers both pools
        for action in block.actions.iter().chain(block.ironwood_actions.iter()) {
            // check if any wallet nullifier is being spent in mempool
            if wallet_nullifiers.contains(&action.nullifier) {
                if !json {
                    eprintln!(
                        "  PENDING SPEND: nullifier {}.. in mempool tx {}...",
                        hex::encode(&action.nullifier[..8]),
                        &txid_hex[..16],
                    );
                }
                found += 1;
            }

            // trial decrypt for incoming payments
            if action.ciphertext.len() >= 52 {
                let mut ct = [0u8; 52];
                ct.copy_from_slice(&action.ciphertext[..52]);
                let output = CompactShieldedOutput {
                    epk: action.ephemeral_key,
                    cmx: action.cmx,
                    ciphertext: ct,
                };
                if let Some(decrypted) =
                    try_decrypt(fvk, ivk_ext, ivk_int, &action.nullifier, &output)
                {
                    let zec = decrypted.value as f64 / 1e8;
                    let kind = if decrypted.is_change {
                        "change"
                    } else {
                        "incoming"
                    };
                    if !json {
                        eprintln!(
                            "  PENDING {}: {:.8} ZEC in mempool tx {}...",
                            kind.to_uppercase(),
                            zec,
                            &txid_hex[..16],
                        );
                    }
                    found += 1;
                }
            }
        }
    }

    found
}

/// extract all fields from a decrypted note for wallet storage
fn extract_note_data(fvk: &FullViewingKey, note: &orchard::Note, is_change: bool) -> DecryptedNote {
    let note_nf = note.nullifier(fvk);
    DecryptedNote {
        value: note.value().inner(),
        nullifier: note_nf.to_bytes(),
        is_change,
        recipient: note.recipient().to_raw_address_bytes().to_vec(),
        rho: note.rho().to_bytes(),
        rseed: *note.rseed().as_bytes(),
    }
}

#[cfg(test)]
mod work_model_tests {
    use super::*;

    fn model() -> WorkModel {
        // 1000 blocks from 101..=1100; sapling sizes sampled at 100, 600, 1100:
        // 400 outputs in the first half, 100 in the second.
        WorkModel {
            start: 101,
            tip: 1100,
            orchard_start: 50,
            ironwood_start: 0,
            sapling_samples: vec![(100, 1_000), (600, 1_400), (1_100, 1_500)],
            total: 200 + 0 + 500 + WORK_PER_BLOCK * 1000,
        }
    }

    #[test]
    fn sapling_interpolates_within_bucket_and_is_exact_at_boundaries() {
        let m = model();
        assert_eq!(m.sapling_done(100), 0);
        assert_eq!(m.sapling_done(350), 200);
        assert_eq!(m.sapling_done(600), 400);
        assert_eq!(m.sapling_done(850), 450);
        assert_eq!(m.sapling_done(1_100), 500);
        // past the last sample: clamp
        assert_eq!(m.sapling_done(5_000), 500);
    }

    #[test]
    fn done_reaches_total_at_tip_and_never_exceeds_it() {
        let m = model();
        assert_eq!(m.done(1_100, 250, 0), m.total);
        // over-advanced counters (e.g. tip moved) still clamp to the bar length
        assert_eq!(m.done(1_100, 900, 7), m.total);
        // nothing scanned yet
        assert_eq!(m.done(100, 50, 0), 0);
        // halfway: 500 blocks, 100 orchard, 400 sapling
        assert_eq!(m.done(600, 150, 0), 100 + 400 + WORK_PER_BLOCK * 500);
    }

    /// Live: build the model over the sapling-sandblast region against the
    /// public zidecar. Run with `cargo test -p zecli --lib -- --ignored live_`.
    #[tokio::test]
    #[ignore]
    async fn live_work_model_over_sandblast_region() {
        let endpoint =
            std::env::var("ZCLI_ENDPOINT").unwrap_or_else(|_| "https://zcash.rotko.net".into());
        let client = ZidecarClient::connect(&endpoint).await.unwrap();
        let start = 1_700_000u32;
        let tip = 1_780_000u32;
        let seed = client
            .get_tree_states(start.saturating_sub(1))
            .await
            .unwrap();
        let size = |h: &str| crate::witness::frontier_leaf_count(&hex::decode(h).unwrap()).unwrap();
        let (o0, i0) = (size(&seed.orchard_tree), size(&seed.ironwood_tree));
        let m = WorkModel::build(&client, start, tip, o0, i0).await.unwrap();
        eprintln!("{}", m.describe());
        for &(h, s) in &m.sapling_samples {
            eprintln!("  sapling size @{h} = {s}");
        }
        let blocks = (tip - start + 1) as u64;
        assert!(
            m.total > WORK_PER_BLOCK * blocks,
            "no shielded outputs counted"
        );
        assert!(
            WorkModel::sapling_span(&m.sapling_samples) > 0,
            "sapling sandblast region must contribute sapling outputs"
        );
        assert_eq!(m.done(tip, u64::MAX, u64::MAX), m.total);
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    fn blk(height: u32) -> crate::client::CompactBlock {
        crate::client::CompactBlock {
            height,
            hash: vec![height as u8; 32],
            actions: Vec::new(),
            ironwood_actions: Vec::new(),
        }
    }

    #[test]
    fn response_covers_demands_the_whole_requested_range() {
        let full: Vec<_> = (10..=12).map(blk).collect();
        assert!(response_covers(&full, 10, 12).is_ok());

        let short_tail: Vec<_> = (10..=11).map(blk).collect();
        assert_eq!(
            response_covers(&short_tail, 10, 12),
            Err("10..11".to_string())
        );

        let short_head: Vec<_> = (11..=12).map(blk).collect();
        assert_eq!(
            response_covers(&short_head, 10, 12),
            Err("11..12".to_string())
        );

        assert_eq!(response_covers(&[], 10, 12), Err("no blocks".to_string()));
    }
}

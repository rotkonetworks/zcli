// merkle witness construction for shielded spends
//
// uses GetTreeState RPC to restore a commitment tree checkpoint near the
// earliest note, then replays only the delta to anchor_height.  this avoids
// replaying the full 99M+ commitment history from orchard activation.
//
// POOL AWARENESS. Orchard and ironwood (NU6.3) share the tree TYPES — the same
// `MerkleHashOrchard` nodes, the same `Anchor` and `MerklePath` — but they are
// two separate trees with separate leaf numbering, separate roots, and separate
// tree-state RPCs. A witness built by replaying orchard actions into the orchard
// frontier is meaningless for an ironwood note: the node rejects it as
// `UnknownIronwoodAnchor`, and nothing in the type system would have complained.
//
// Every entry point here therefore takes an explicit `Pool`. There is no
// default and no boolean: `build_witnesses` will not compile without one, and it
// re-checks at runtime that every note it was handed actually belongs to that
// pool.

use incrementalmerkletree::frontier::CommitmentTree;
use indicatif::{ProgressBar, ProgressStyle};
use orchard::tree::{Anchor, MerkleHashOrchard, MerklePath};
use zafu_wasm::witness::WitnessReplay;

use crate::client::{CompactAction, CompactBlock, ZidecarClient};
use crate::error::Error;
use crate::wallet::{Pool, Wallet, WalletNote};

/// The action list whose commitments go into `pool`'s tree.
///
/// The two lists are the same Rust type and are both trial-decrypted with the
/// same keys, so this is the one place where getting them the wrong way round
/// is possible — and the only place, because nothing else in this module
/// touches `block.actions` directly.
pub fn actions_for_pool(block: &CompactBlock, pool: Pool) -> &[CompactAction] {
    match pool {
        Pool::Orchard => &block.actions,
        Pool::Ironwood => &block.ironwood_actions,
    }
}

/// Tree-state frontier for `pool` at `height`, hex-encoded.
///
/// An IRONWOOD frontier may legitimately be empty: pre-NU6.3 the tree does not
/// exist yet, and the first ironwood note ever mined is preceded by an empty
/// tree. A server that predates ironwood support returns the same empty string,
/// which is why callers must not treat "empty" as "verified empty" at the
/// anchor height — see `build_witnesses`.
async fn tree_state_for_pool(
    client: &ZidecarClient,
    pool: Pool,
    height: u32,
) -> Result<String, Error> {
    let (hex, _) = match pool {
        Pool::Orchard => client.get_tree_state(height).await?,
        Pool::Ironwood => client.get_ironwood_tree_state(height).await?,
    };
    Ok(hex)
}

fn pool_name(pool: Pool) -> &'static str {
    pool.name()
}

/// load the cached frontier for `pool` from the wallet, for witness building
pub fn load_frontier_from_wallet(pool: Pool) -> (Option<(String, u32)>, u32) {
    match Wallet::open(&Wallet::default_path()) {
        Ok(w) => {
            let frontier = w.tree_frontier(pool).ok().flatten();
            let sh = w.sync_height().unwrap_or(0);
            (frontier, sh)
        }
        Err(_) => (None, 0),
    }
}

/// retry compact block fetch with backoff
async fn retry_compact_blocks(
    client: &ZidecarClient,
    start: u32,
    end: u32,
) -> Result<Vec<CompactBlock>, Error> {
    let mut attempts = 0;
    loop {
        match client.get_compact_blocks(start, end).await {
            Ok(blocks) => return Ok(blocks),
            Err(e) => {
                attempts += 1;
                if attempts >= 5 {
                    return Err(e);
                }
                tokio::time::sleep(std::time::Duration::from_millis(500 * attempts)).await;
            }
        }
    }
}

const BATCH_SIZE: u32 = 1000;

/// deserialize a lightwalletd/zcashd orchard frontier into a CommitmentTree.
///
/// wire format (zcash_primitives CommitmentTree serialization):
///   [Option<Hash>] left
///   [Option<Hash>] right
///   [CompactSize]  parent_count
///   [Option<Hash>] * parent_count
///
/// Option encoding: 0x00 = None, 0x01 = Some followed by 32 bytes.
/// CompactSize: 0x00-0xfc = 1 byte, 0xfd = u16 LE, 0xfe = u32 LE, 0xff = u64 LE.
fn deserialize_tree(data: &[u8]) -> Result<CommitmentTree<MerkleHashOrchard, 32>, Error> {
    if data.is_empty() {
        return Ok(CommitmentTree::empty());
    }

    let mut pos = 0;

    let read_option = |pos: &mut usize| -> Result<Option<MerkleHashOrchard>, Error> {
        if *pos >= data.len() {
            return Err(Error::Other("frontier truncated reading option tag".into()));
        }
        if data[*pos] == 0x01 {
            if *pos + 33 > data.len() {
                return Err(Error::Other("frontier truncated reading hash".into()));
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[*pos + 1..*pos + 33]);
            *pos += 33;
            Option::from(MerkleHashOrchard::from_bytes(&bytes))
                .map(Some)
                .ok_or_else(|| Error::Other("invalid frontier hash".into()))
        } else {
            *pos += 1;
            Ok(None)
        }
    };

    let left = read_option(&mut pos)?;
    let right = read_option(&mut pos)?;

    // read CompactSize parent count
    if pos >= data.len() {
        return CommitmentTree::from_parts(left, right, vec![])
            .map_err(|_| Error::Other("invalid frontier structure (no parents)".into()));
    }
    let parent_count = read_compact_size(data, &mut pos)?;

    let mut parents = Vec::with_capacity(parent_count as usize);
    for _ in 0..parent_count {
        parents.push(read_option(&mut pos)?);
    }

    let n_parents = parents.len();
    let has_left = left.is_some();
    let has_right = right.is_some();
    CommitmentTree::from_parts(left, right, parents).map_err(|_| {
        Error::Other(format!(
            "invalid frontier structure (left={} right={} parents={})",
            has_left, has_right, n_parents,
        ))
    })
}

fn read_compact_size(data: &[u8], pos: &mut usize) -> Result<u64, Error> {
    if *pos >= data.len() {
        return Err(Error::Other("compact size: truncated".into()));
    }
    let first = data[*pos];
    *pos += 1;
    match first {
        0x00..=0xfc => Ok(first as u64),
        0xfd => {
            if *pos + 2 > data.len() {
                return Err(Error::Other("compact size: truncated u16".into()));
            }
            let v = u16::from_le_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Ok(v as u64)
        }
        0xfe => {
            if *pos + 4 > data.len() {
                return Err(Error::Other("compact size: truncated u32".into()));
            }
            let v =
                u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
            *pos += 4;
            Ok(v as u64)
        }
        0xff => {
            if *pos + 8 > data.len() {
                return Err(Error::Other("compact size: truncated u64".into()));
            }
            let v = u64::from_le_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
                data[*pos + 4],
                data[*pos + 5],
                data[*pos + 6],
                data[*pos + 7],
            ]);
            *pos += 8;
            Ok(v)
        }
    }
}

/// compute the tree size from frontier - parse to a CommitmentTree and use .size()
pub fn frontier_tree_size(data: &[u8]) -> Result<u64, Error> {
    let tree = deserialize_tree(data)?;
    Ok(tree.size() as u64)
}

/// A note's own pool tag must agree with the tree we are about to walk.
///
/// Positions are per-tree, so replaying an ironwood note against the orchard
/// tree does not fail loudly on its own — it produces a path to the wrong root,
/// which the node rejects (or, if the two trees happen to agree, something
/// worse). Refuse before doing any work.
pub fn check_notes_pool(notes: &[WalletNote], pool: Pool) -> Result<(), Error> {
    if let Some(bad) = notes.iter().find(|n| n.pool != pool) {
        return Err(Error::Other(format!(
            "witness pool mismatch: asked to build {} witnesses, but a note at \
             position {} (height {}) belongs to the {} pool. The two pools have \
             separate commitment trees; a path from the wrong tree yields a \
             wrong anchor.",
            pool_name(pool),
            bad.position,
            bad.block_height,
            pool_name(bad.pool),
        )));
    }
    Ok(())
}

/// Is a cached frontier usable as the seed for witnesses over `notes`?
///
/// A cached frontier is only usable if EVERY note we need a witness for sits at
/// or after it. The replay walks FORWARD from the frontier, so a note whose
/// position is already inside it can never be reached — the loop runs to the
/// anchor and then reports "position not found".
///
/// That is not a corrupt wallet, it is an ordering bug: sync advances the cached
/// frontier past notes received earlier, and from then on the wallet cannot
/// spend any of them. Detecting it here is what lets the caller fall back to a
/// tree state from before the earliest note instead of failing the spend.
pub fn cached_frontier_usable(hex: &str, notes: &[WalletNote]) -> bool {
    // An EMPTY frontier is not evidence of an empty tree. Pre-NU6.3, and on a
    // server that predates ironwood, the ironwood tree state is the empty
    // string; trusting it would seed a size-0 tree at a height where the real
    // tree is not empty, and every position from there on would be wrong. Treat
    // it as a cache miss and go fetch a frontier we can place.
    if hex.is_empty() {
        return false;
    }
    match hex::decode(hex)
        .ok()
        .and_then(|b| deserialize_tree(&b).ok())
    {
        Some(tree) => notes.iter().all(|n| n.position >= tree.size() as u64),
        // undecodable frontier: treat as unusable rather than trusting it
        None => false,
    }
}

/// build merkle witnesses for a set of notes, all of which must belong to `pool`.
///
/// `pool` selects the commitment tree end to end: which tree-state RPC seeds the
/// frontier, which per-block action list is replayed, and which network root the
/// resulting anchor is checked against. It is a required argument precisely so
/// that a caller cannot inherit orchard behaviour by omission — and the notes
/// are re-checked against it below, so a mismatched `pool` is an error rather
/// than a silently wrong anchor.
///
/// `cached_frontier` must be the cache for the SAME pool (see
/// `Wallet::tree_frontier`); a frontier from the other tree deserializes
/// perfectly well and would be undetectable here, so it is fetched per-pool at
/// the call site via `load_frontier_from_wallet(pool)`.
///
/// uses the cached tree frontier from sync to avoid the binary search
/// (which leaks note position via RPC access pattern). only replays
/// the gap between cached frontier and anchor_height.
///
/// if no cached frontier, falls back to fetching tree state at sync_height
/// (single RPC, no position leak).
pub async fn build_witnesses(
    client: &ZidecarClient,
    notes: &[WalletNote],
    anchor_height: u32,
    pool: Pool,
    json: bool,
    cached_frontier: Option<(String, u32)>,
    sync_height: u32,
) -> Result<(Anchor, Vec<MerklePath>), Error> {
    check_notes_pool(notes, pool)?;

    // resolve frontier: cached > fetch at sync_height (single RPC, no position leak)
    let earliest_note_height = notes.iter().map(|n| n.block_height).min();
    let usable_cache = cached_frontier.filter(|(hex, _)| cached_frontier_usable(hex, notes));

    let (frontier_hex, frontier_height) = if let Some((hex, h)) = usable_cache {
        if !json {
            eprintln!(
                "using cached {} tree frontier at height {}",
                pool_name(pool),
                h
            );
        }
        (hex, h)
    } else if let Some(h) = earliest_note_height.filter(|h| *h > 1) {
        // one RPC at a height strictly before the earliest note, so the
        // frontier is guaranteed to sit at or below every note position
        let fetch_at = h - 1;
        if !json {
            eprintln!(
                "cached frontier is newer than the notes being spent (or absent); \
                 fetching {} tree state at height {} instead",
                pool_name(pool),
                fetch_at
            );
        }
        (tree_state_for_pool(client, pool, fetch_at).await?, fetch_at)
    } else if sync_height > 0 && sync_height <= anchor_height {
        if !json {
            eprintln!(
                "no cached frontier, fetching {} tree state at sync height {}",
                pool_name(pool),
                sync_height
            );
        }
        (
            tree_state_for_pool(client, pool, sync_height).await?,
            sync_height,
        )
    } else {
        return Err(Error::Other(
            "wallet must be synced before spending - no tree frontier available".into(),
        ));
    };

    // An empty seed frontier is CORRECT when the tree really is empty at that
    // height — the first ironwood note ever mined is preceded by an empty
    // ironwood tree, and the replay below starts it at position 0. It is only
    // dangerous if the tree is NOT actually empty there, and that case is caught
    // at the anchor: the root check below cannot pass against a tree the server
    // will not tell us about.
    if frontier_hex.is_empty() && !json {
        eprintln!(
            "{} tree is empty at height {}; starting the replay from an empty tree",
            pool_name(pool),
            frontier_height
        );
    }

    let frontier_bytes = hex::decode(&frontier_hex)
        .map_err(|e| Error::Other(format!("invalid frontier hex: {}", e)))?;
    let positions: Vec<u64> = notes.iter().map(|n| n.position).collect();
    let mut replay = WitnessReplay::from_frontier_bytes(&frontier_bytes, &positions)
        .map_err(|e| Error::Other(format!("invalid {} frontier: {}", pool_name(pool), e)))?;

    if !json {
        eprintln!(
            "{} frontier: height={} size={} gap={} blocks",
            pool_name(pool),
            frontier_height,
            replay.next_position(),
            anchor_height.saturating_sub(frontier_height)
        );
    }

    // start replay from frontier_height + 1 since the tree state
    // at frontier_height already includes that block's actions
    let replay_start = frontier_height + 1;
    let replay_blocks = if anchor_height >= replay_start {
        anchor_height - replay_start + 1
    } else {
        0
    };
    let pb = if !json && is_terminal::is_terminal(std::io::stderr()) {
        let pb = ProgressBar::new(replay_blocks as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "[{elapsed}] {bar:50.green/blue} {pos:>7}/{len:7} {per_sec} building witnesses",
                )
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    if !json {
        eprintln!("replaying {} blocks for merkle witnesses...", replay_blocks);
    }

    let mut current = replay_start;

    while current <= anchor_height {
        let end = (current + BATCH_SIZE - 1).min(anchor_height);
        let blocks = retry_compact_blocks(client, current, end).await?;

        for block in &blocks {
            // the ONLY action list this pool's tree commits to
            for action in actions_for_pool(block, pool) {
                replay.append_cmx_bytes(&action.cmx).map_err(Error::Other)?;
            }
        }

        current = end + 1;
        if let Some(ref pb) = pb {
            pb.set_position((current - replay_start) as u64);
        }
    }

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    // extract paths and verify consistency
    let anchor_root = replay.root();
    let anchor = Anchor::from(anchor_root);

    // verify our tree root matches the network's tree state at anchor_height —
    // for THIS pool's tree. This is the check that turns a cross-tree replay
    // into a loud error instead of a rejected transaction.
    let anchor_tree_hex = tree_state_for_pool(client, pool, anchor_height).await?;
    if anchor_tree_hex.is_empty() && replay.next_position() > 0 {
        // We replayed leaves into this tree, so it is not empty — but the server
        // will not give us a frontier to check them against. That is a server
        // that predates ironwood (or a chain where the pool is not active), not
        // an empty tree. Refuse rather than ship an unverified anchor.
        return Err(Error::Other(format!(
            "no {} tree state at height {}: the server returned an empty frontier \
             while our replay holds {} commitment(s). Either {} is not active on \
             this chain or the server predates {} support; refusing to build a \
             witness whose anchor cannot be checked against the network.",
            pool_name(pool),
            anchor_height,
            replay.next_position(),
            pool_name(pool),
            pool_name(pool),
        )));
    }
    let anchor_tree_bytes = hex::decode(&anchor_tree_hex)
        .map_err(|e| Error::Other(format!("invalid anchor tree hex: {}", e)))?;
    let anchor_tree = deserialize_tree(&anchor_tree_bytes)?;
    let network_root = anchor_tree.root();
    if anchor_root != network_root {
        return Err(Error::Other(format!(
            "{} tree root mismatch at height {} (ours={}, network={})",
            pool_name(pool),
            anchor_height,
            hex::encode(anchor_root.to_bytes()),
            hex::encode(network_root.to_bytes()),
        )));
    }

    let paths = replay.into_paths().map_err(|e| {
        Error::Other(format!(
            "{} ({} pool, frontier at height {})",
            e,
            pool_name(pool),
            frontier_height
        ))
    })?;

    if !json {
        eprintln!(
            "witnesses built - {} anchor: {}",
            pool_name(pool),
            hex::encode(anchor.to_bytes())
        );
    }

    Ok((anchor, paths))
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::frontier::CommitmentTree;
    use incrementalmerkletree::witness::IncrementalWitness;
    use incrementalmerkletree::{Hashable, Level, Position};
    use orchard::tree::MerkleHashOrchard;

    fn test_hash(i: u8) -> MerkleHashOrchard {
        // create a deterministic test hash
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        bytes[31] = i;
        Option::from(MerkleHashOrchard::from_bytes(&bytes)).unwrap()
    }

    // ── pool separation ──
    //
    // These tests exist because the orchard and ironwood trees use the SAME
    // types. Nothing downstream of a wrong-tree replay is type-checked: the
    // anchor is an `Anchor`, the path is a `MerklePath`, and the mistake only
    // surfaces as a consensus rejection. So the fixtures below make the two
    // trees demonstrably different (different leaves AND different leaf counts)
    // and then assert that a path built for one pool does not verify against
    // the other pool's root.

    const ORCHARD_TAG: u8 = 0x11;
    const IRONWOOD_TAG: u8 = 0x22;

    /// A canonical Pallas base element, distinct per (pool tag, index).
    fn cmx(pool_tag: u8, i: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = i;
        b[1] = pool_tag;
        b[2] = 0x5a;
        b
    }

    fn leaf(cmx_bytes: &[u8; 32]) -> orchard::note::ExtractedNoteCommitment {
        let c = orchard::note::ExtractedNoteCommitment::from_bytes(cmx_bytes);
        assert!(
            bool::from(c.is_some()),
            "test cmx must be a valid commitment"
        );
        c.unwrap()
    }

    fn compact_block(height: u32, orchard: &[[u8; 32]], ironwood: &[[u8; 32]]) -> CompactBlock {
        let mk = |cmx: &[u8; 32]| CompactAction {
            cmx: *cmx,
            ephemeral_key: [0u8; 32],
            ciphertext: vec![],
            nullifier: [0u8; 32],
            txid: vec![],
        };
        CompactBlock {
            height,
            hash: vec![],
            actions: orchard.iter().map(mk).collect(),
            actions_root: [0u8; 32],
            ironwood_actions: ironwood.iter().map(mk).collect(),
        }
    }

    fn wallet_note(pool: Pool, position: u64, block_height: u32) -> WalletNote {
        WalletNote {
            value: 1,
            nullifier: [0u8; 32],
            cmx: [0u8; 32],
            block_height,
            is_change: false,
            recipient: vec![0u8; 43],
            rho: [0u8; 32],
            rseed: [0u8; 32],
            position,
            txid: vec![],
            memo: None,
            pool,
        }
    }

    /// Two blocks whose orchard and ironwood action lists differ in BOTH
    /// contents and length, so the two trees cannot coincide.
    fn divergent_blocks() -> Vec<CompactBlock> {
        vec![
            compact_block(
                10,
                &[
                    cmx(ORCHARD_TAG, 0),
                    cmx(ORCHARD_TAG, 1),
                    cmx(ORCHARD_TAG, 2),
                ],
                &[cmx(IRONWOOD_TAG, 0), cmx(IRONWOOD_TAG, 1)],
            ),
            compact_block(
                11,
                &[cmx(ORCHARD_TAG, 3), cmx(ORCHARD_TAG, 4)],
                &[
                    cmx(IRONWOOD_TAG, 2),
                    cmx(IRONWOOD_TAG, 3),
                    cmx(IRONWOOD_TAG, 4),
                ],
            ),
        ]
    }

    /// Replay a pool's action stream from an empty tree, exactly as
    /// `build_witnesses` does, and return (root, paths).
    fn replay(blocks: &[CompactBlock], pool: Pool, positions: &[u64]) -> (Anchor, Vec<MerklePath>) {
        let mut r = WitnessReplay::from_frontier_bytes(&[], positions).unwrap();
        for b in blocks {
            for a in actions_for_pool(b, pool) {
                r.append_cmx_bytes(&a.cmx).unwrap();
            }
        }
        let anchor = r.anchor();
        (anchor, r.into_paths().unwrap())
    }

    #[test]
    fn actions_for_pool_selects_the_matching_list() {
        let b = &divergent_blocks()[0];
        assert_eq!(actions_for_pool(b, Pool::Orchard).len(), 3);
        assert_eq!(actions_for_pool(b, Pool::Ironwood).len(), 2);
        assert_eq!(
            actions_for_pool(b, Pool::Orchard)[0].cmx,
            cmx(ORCHARD_TAG, 0)
        );
        assert_eq!(
            actions_for_pool(b, Pool::Ironwood)[0].cmx,
            cmx(IRONWOOD_TAG, 0)
        );
    }

    #[test]
    fn ironwood_witness_does_not_verify_against_the_orchard_tree() {
        let blocks = divergent_blocks();

        // the note we want to spend: ironwood leaf 2 (first action of block 11)
        let iw_position = 2u64;
        let iw_leaf = leaf(&cmx(IRONWOOD_TAG, 2));

        let (iw_root, iw_paths) = replay(&blocks, Pool::Ironwood, &[iw_position]);
        let (orchard_root, orchard_paths) = replay(&blocks, Pool::Orchard, &[iw_position]);

        // the fixture must actually distinguish the two trees, or the assertions
        // below would pass for the wrong reason
        assert_ne!(
            iw_root, orchard_root,
            "fixture is useless unless the two trees differ"
        );

        // the ironwood path roots to the ironwood anchor
        assert_eq!(
            iw_paths[0].root(iw_leaf),
            iw_root,
            "ironwood path must root to the ironwood tree"
        );

        // ...and NOT to the orchard anchor. This is the failure the old
        // orchard-only builder produced for every ironwood note: a well-formed
        // path against a tree the note is not in.
        assert_ne!(
            iw_paths[0].root(iw_leaf),
            orchard_root,
            "ironwood path must not root to the orchard tree"
        );

        // the reverse mistake: replaying the ORCHARD action list for an
        // ironwood note's position yields a path that does not root to the
        // ironwood anchor with the ironwood leaf
        assert_ne!(
            orchard_paths[0].root(iw_leaf),
            iw_root,
            "a path built from the orchard action stream must not validate an \
             ironwood note"
        );
    }

    #[test]
    fn pool_replays_have_independent_positions() {
        let blocks = divergent_blocks();
        // 5 orchard actions vs 5 ironwood actions in total, but interleaved
        // differently per block: position 3 is orchard leaf 3 / ironwood leaf 3,
        // which are different commitments.
        let (iw_root, iw_paths) = replay(&blocks, Pool::Ironwood, &[3]);
        let (_o_root, o_paths) = replay(&blocks, Pool::Orchard, &[3]);
        assert_eq!(iw_paths[0].root(leaf(&cmx(IRONWOOD_TAG, 3))), iw_root);
        assert_ne!(
            o_paths[0].auth_path(),
            iw_paths[0].auth_path(),
            "the same leaf index in the two trees must have different siblings"
        );
    }

    #[test]
    fn note_from_the_other_pool_is_rejected() {
        let iw = vec![wallet_note(Pool::Ironwood, 7, 100)];
        let err = check_notes_pool(&iw, Pool::Orchard)
            .unwrap_err()
            .to_string();
        assert!(err.contains("pool mismatch"), "unexpected error: {err}");
        assert!(
            err.contains("ironwood"),
            "error must name the note's pool: {err}"
        );

        let orchard = vec![wallet_note(Pool::Orchard, 7, 100)];
        assert!(check_notes_pool(&orchard, Pool::Ironwood).is_err());

        // matching pools are fine, in both directions
        check_notes_pool(&iw, Pool::Ironwood).unwrap();
        check_notes_pool(&orchard, Pool::Orchard).unwrap();
    }

    #[test]
    fn empty_frontier_is_never_treated_as_a_usable_cache() {
        // The ironwood tree state is "" pre-activation AND from a server that
        // predates ironwood. Accepting it as a size-0 frontier at a height where
        // the tree is NOT empty would offset every position that follows.
        let notes = vec![wallet_note(Pool::Ironwood, 4_000, 900_000)];
        assert!(!cached_frontier_usable("", &notes));
        assert!(!cached_frontier_usable("zzzz", &notes), "undecodable hex");
    }

    #[test]
    fn cached_frontier_newer_than_the_notes_is_rejected() {
        // regression guard: sync advancing the cached frontier past a note used
        // to make that note permanently unspendable ("position not found").
        let mut tree: CommitmentTree<MerkleHashOrchard, 32> = CommitmentTree::empty();
        for i in 0..10u8 {
            tree.append(test_hash(i + 1)).unwrap();
        }
        let hex = hex::encode(zafu_wasm::witness::serialize_tree(&tree));
        assert_eq!(frontier_tree_size(&hex::decode(&hex).unwrap()).unwrap(), 10);

        // note INSIDE the frontier: unusable, caller must refetch
        let inside = vec![wallet_note(Pool::Ironwood, 3, 100)];
        assert!(!cached_frontier_usable(&hex, &inside));

        // note at/after the frontier: usable
        let after = vec![wallet_note(Pool::Ironwood, 10, 100)];
        assert!(cached_frontier_usable(&hex, &after));

        // one note inside is enough to reject the whole batch
        let mixed = vec![
            wallet_note(Pool::Ironwood, 10, 100),
            wallet_note(Pool::Ironwood, 9, 100),
        ];
        assert!(!cached_frontier_usable(&hex, &mixed));
    }

    #[test]
    fn witness_from_scratch() {
        // build tree from scratch, witness a leaf, verify path
        let mut tree: CommitmentTree<MerkleHashOrchard, 32> = CommitmentTree::empty();
        for i in 0..5 {
            tree.append(test_hash(i)).unwrap();
        }
        // witness position 4 (the last leaf)
        let mut witness = IncrementalWitness::from_tree(tree.clone()).unwrap();
        assert_eq!(witness.witnessed_position(), Position::from(4));

        // append more leaves
        for i in 5..20 {
            let h = test_hash(i);
            tree.append(h.clone()).unwrap();
            witness.append(h).unwrap();
        }

        // check roots match
        let tree_root = tree.root();
        let witness_root = witness.root();
        assert_eq!(
            tree_root, witness_root,
            "witness root should match tree root"
        );

        // extract path and verify
        let path = witness.path().unwrap();
        let leaf = test_hash(4);
        let mut cur = leaf;
        let pos = u64::from(path.position());
        for (level, sibling) in path.path_elems().iter().enumerate() {
            let (l, r) = if (pos >> level) & 1 == 0 {
                (cur, *sibling)
            } else {
                (*sibling, cur)
            };
            cur = MerkleHashOrchard::combine(Level::from(level as u8), &l, &r);
        }
        assert_eq!(
            cur, tree_root,
            "path root should match tree root (from scratch)"
        );
    }

    #[test]
    fn witness_from_checkpoint() {
        // build a tree with enough leaves to have multiple parent levels
        let mut tree1: CommitmentTree<MerkleHashOrchard, 32> = CommitmentTree::empty();
        for i in 0u32..100 {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            let h: MerkleHashOrchard = Option::from(MerkleHashOrchard::from_bytes(&bytes)).unwrap();
            tree1.append(h).unwrap();
        }

        // serialize and reconstruct (simulating checkpoint)
        let left = tree1.left().clone();
        let right = tree1.right().clone();
        let parents = tree1.parents().clone();
        let mut tree2 =
            CommitmentTree::<MerkleHashOrchard, 32>::from_parts(left, right, parents).unwrap();
        assert_eq!(tree1.root(), tree2.root());

        // append more, then witness
        for i in 100u32..120 {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            let h: MerkleHashOrchard = Option::from(MerkleHashOrchard::from_bytes(&bytes)).unwrap();
            tree1.append(h.clone()).unwrap();
            tree2.append(h).unwrap();
        }
        assert_eq!(tree1.root(), tree2.root());

        let mut witness1 = IncrementalWitness::from_tree(tree1.clone()).unwrap();
        let mut witness2 = IncrementalWitness::from_tree(tree2.clone()).unwrap();

        // append 500 more leaves
        for i in 120u32..620 {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            let h: MerkleHashOrchard = Option::from(MerkleHashOrchard::from_bytes(&bytes)).unwrap();
            tree1.append(h.clone()).unwrap();
            tree2.append(h.clone()).unwrap();
            witness1.append(h.clone()).unwrap();
            witness2.append(h).unwrap();
        }

        assert_eq!(tree1.root(), tree2.root(), "tree roots differ");
        assert_eq!(witness1.root(), witness2.root(), "witness roots differ");
        assert_eq!(tree1.root(), witness1.root(), "tree1 vs witness1 root");

        let path1 = witness1.path().unwrap();
        let path2 = witness2.path().unwrap();

        // verify using imt's own root method
        let mut leaf_bytes = [0u8; 32];
        leaf_bytes[0..4].copy_from_slice(&119u32.to_le_bytes());
        let leaf = Option::from(MerkleHashOrchard::from_bytes(&leaf_bytes)).unwrap();

        let root1 = path1.root(leaf);
        let root2 = path2.root(leaf);
        assert_eq!(root1, tree1.root(), "path1 root mismatch");
        assert_eq!(root2, tree2.root(), "path2 root mismatch");
    }

    #[test]
    fn witness_from_padded_checkpoint() {
        // test with a tree that has EXTRA trailing None parents
        // (simulating deserialization from a 31-parent frontier)
        let mut tree1: CommitmentTree<MerkleHashOrchard, 32> = CommitmentTree::empty();
        for i in 0u32..50 {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            let h: MerkleHashOrchard = Option::from(MerkleHashOrchard::from_bytes(&bytes)).unwrap();
            tree1.append(h).unwrap();
        }

        // tree1 has parents with ~6 entries. pad to 31 with Nones.
        let left = tree1.left().clone();
        let right = tree1.right().clone();
        let mut parents = tree1.parents().clone();
        let original_parents_len = parents.len();
        // pad to 31 parents (like the network frontier)
        while parents.len() < 31 {
            parents.push(None);
        }

        let tree2 = CommitmentTree::<MerkleHashOrchard, 32>::from_parts(
            left.clone(),
            right.clone(),
            parents,
        )
        .unwrap();

        // also make tree3 with no padding
        let tree3 = CommitmentTree::<MerkleHashOrchard, 32>::from_parts(
            left,
            right,
            tree1.parents().clone(),
        )
        .unwrap();

        eprintln!(
            "tree1 parents: {}, tree2 (padded): 31, tree3 (original): {}",
            tree1.parents().len(),
            tree3.parents().len()
        );
        assert_eq!(tree1.root(), tree2.root(), "padded tree root should match");
        assert_eq!(
            tree1.root(),
            tree3.root(),
            "original tree root should match"
        );

        // append and witness from padded tree
        let mut tree1c = tree1.clone();
        let mut tree2c = tree2.clone();
        for i in 50u32..60 {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            let h: MerkleHashOrchard = Option::from(MerkleHashOrchard::from_bytes(&bytes)).unwrap();
            tree1c.append(h.clone()).unwrap();
            tree2c.append(h).unwrap();
        }

        let mut w1 = IncrementalWitness::from_tree(tree1c.clone()).unwrap();
        let mut w2 = IncrementalWitness::from_tree(tree2c.clone()).unwrap();

        for i in 60u32..200 {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            let h: MerkleHashOrchard = Option::from(MerkleHashOrchard::from_bytes(&bytes)).unwrap();
            tree1c.append(h.clone()).unwrap();
            tree2c.append(h.clone()).unwrap();
            w1.append(h.clone()).unwrap();
            w2.append(h).unwrap();
        }

        assert_eq!(tree1c.root(), w1.root(), "w1 root");
        assert_eq!(tree2c.root(), w2.root(), "w2 root");
        assert_eq!(tree1c.root(), tree2c.root(), "tree roots");

        let p1 = w1.path().unwrap();
        let p2 = w2.path().unwrap();

        let mut leaf_bytes = [0u8; 32];
        leaf_bytes[0..4].copy_from_slice(&59u32.to_le_bytes());
        let leaf = Option::from(MerkleHashOrchard::from_bytes(&leaf_bytes)).unwrap();

        let r1 = p1.root(leaf);
        let r2 = p2.root(leaf);

        eprintln!("w1 root: {}", hex::encode(w1.root().to_bytes()));
        eprintln!("p1 root: {}", hex::encode(r1.to_bytes()));
        eprintln!("p2 root: {}", hex::encode(r2.to_bytes()));
        eprintln!(
            "w1 filled: {}, w2 filled: {}",
            w1.filled().len(),
            w2.filled().len()
        );
        eprintln!("original parents: {}", original_parents_len);

        assert_eq!(r1, tree1c.root(), "p1 root mismatch (unpadded)");
        assert_eq!(
            r2,
            tree2c.root(),
            "p2 root mismatch (PADDED - this is the real test)"
        );
    }
}

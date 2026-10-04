//! NoteTree (ShardTree) witnesses must equal the witnesses of a full replay
//! from the empty tree (`WitnessReplay`, the code every send used until now).
//!
//! Run with --release: each case hashes a few hundred thousand leaves.

use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::Hashable;
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::{MerkleHashOrchard, MerklePath};
use rand::rngs::StdRng;
use rand::SeedableRng;
use zafu_wasm::note_tree::{NoteTreeCore, SHARD_HEIGHT};
use zafu_wasm::witness::{serialize_tree, serialize_witness, WitnessReplay};

const SHARD: u64 = 1 << SHARD_HEIGHT;

/// random valid cmxs, grouped into blocks of 0..=6 leaves from height 1000
struct Chain {
    cmxs: Vec<[u8; 32]>,
    /// (height, first leaf, leaf count)
    blocks: Vec<(u32, u64, u64)>,
}

fn chain(n: u64, seed: u64) -> Chain {
    let mut rng = StdRng::seed_from_u64(seed);
    // below 2^254, so always a canonical pallas base element
    let cmxs: Vec<[u8; 32]> = (0..n)
        .map(|_| {
            let mut b: [u8; 32] = rand::Rng::gen(&mut rng);
            b[31] &= 0x3f;
            b
        })
        .collect();
    let mut blocks = Vec::new();
    let (mut pos, mut height) = (0u64, 1000u32);
    while pos < n {
        let k = (rand::Rng::gen_range(&mut rng, 0..=6u64)).min(n - pos);
        blocks.push((height, pos, k));
        pos += k;
        height += 1;
    }
    Chain { cmxs, blocks }
}

fn hash(cmx: &[u8; 32]) -> MerkleHashOrchard {
    MerkleHashOrchard::from_cmx(&ExtractedNoteCommitment::from_bytes(cmx).unwrap())
}

impl Chain {
    /// encoded blocks after the one that brings the tree to size `from` (0:
    /// from the start) up to the one that brings it to `to`
    fn encode(&self, from: u64, to: u64) -> Vec<u8> {
        let lo = if from == 0 {
            0
        } else {
            self.height_at_size(from) + 1
        };
        let hi = self.height_at_size(to);
        let mut out = Vec::new();
        for &(h, first, k) in &self.blocks {
            if h < lo || h > hi {
                continue;
            }
            out.extend_from_slice(&h.to_le_bytes());
            out.extend_from_slice(&(k as u32).to_le_bytes());
            for c in &self.cmxs[first as usize..(first + k) as usize] {
                out.extend_from_slice(c);
            }
        }
        out
    }

    /// the block that ends exactly at leaf count `size` (the last such, so
    /// trailing empty blocks are included)
    fn height_at_size(&self, size: u64) -> u32 {
        self.blocks
            .iter()
            .filter(|b| b.1 + b.2 == size)
            .map(|b| b.0)
            .max()
            .unwrap()
    }

    /// a leaf count at a block boundary at or after `near`
    fn boundary(&self, near: u64) -> u64 {
        self.blocks
            .iter()
            .map(|b| b.1 + b.2)
            .find(|&s| s >= near)
            .unwrap()
    }

    fn frontier(&self, size: u64) -> Vec<u8> {
        let mut t = CommitmentTree::<MerkleHashOrchard, 32>::empty();
        for c in &self.cmxs[..size as usize] {
            t.append(hash(c)).unwrap();
        }
        serialize_tree(&t)
    }

    fn shard_root(&self, index: u64) -> [u8; 32] {
        let mut t = CommitmentTree::<MerkleHashOrchard, 16>::empty();
        for c in &self.cmxs[(index * SHARD) as usize..((index + 1) * SHARD) as usize] {
            t.append(hash(c)).unwrap();
        }
        t.root().to_bytes()
    }

    /// full replay from the empty tree to `size`: (root, paths per position)
    fn replay(&self, size: u64, positions: &[u64]) -> ([u8; 32], Vec<MerklePath>) {
        let mut r = WitnessReplay::new(CommitmentTree::empty(), positions);
        for c in &self.cmxs[..size as usize] {
            r.append_cmx_bytes(c).unwrap();
        }
        let root = r.root().to_bytes();
        (root, r.into_paths().unwrap())
    }
}

fn assert_same(tree: &NoteTreeCore, position: u64, height: u32, root: [u8; 32], path: &MerklePath) {
    let w = tree.witness(position, height).unwrap();
    assert_eq!(w.position, position);
    assert_eq!(w.root_hex, hex::encode(root), "root at {height}");
    let want: Vec<String> = path
        .auth_path()
        .iter()
        .map(|h| hex::encode(h.to_bytes()))
        .collect();
    let got: Vec<String> = w.path.iter().map(|p| p.hash.clone()).collect();
    assert_eq!(got, want, "path for {position} at {height}");
}

#[test]
fn roots_plus_partial_batches_match_full_replay() {
    let n = 2 * SHARD + 5_000;
    let c = chain(n, 1);
    // birthday inside shard 1: shard 0 is known only by its subtree root
    let birthday = c.boundary(SHARD + 20_000);
    let mid = c.boundary(2 * SHARD - 300); // batch 1 ends just before the shard 2 boundary
    let p_a = birthday + 10_000; // shard 1
    let p_b = 2 * SHARD + 100; // shard 2, reached by the batch that straddles the boundary
    let end_h = c.height_at_size(n);

    let mut tree = NoteTreeCore::new(100);
    tree.insert_frontier(&c.frontier(birthday), c.height_at_size(birthday))
        .unwrap();
    // shard 0 is behind the tree: taken. shard 1 holds the tip: not taken yet.
    let roots: Vec<u8> = [c.shard_root(0), c.shard_root(1)].concat();
    assert_eq!(tree.insert_subtree_roots(0, &roots).unwrap(), 1);

    tree.append_blocks(
        birthday,
        &c.encode(birthday, mid),
        &[p_a as u32],
        end_h - 50,
    )
    .unwrap();
    assert_eq!(tree.next_position(), Some(mid));
    tree.append_blocks(mid, &c.encode(mid, n), &[p_b as u32], end_h - 50)
        .unwrap();
    assert_eq!(tree.next_position(), Some(n));
    assert_eq!(tree.latest_checkpoint(), Some(end_h));
    assert!(tree.is_marked(p_a) && tree.is_marked(p_b) && !tree.is_marked(p_a + 1));

    let (root, paths) = c.replay(n, &[p_a, p_b]);
    assert_same(&tree, p_a, end_h, root, &paths[0]);
    assert_same(&tree, p_b, end_h, root, &paths[1]);

    // an older retained checkpoint (blocks in the last 50 heights are all checkpointed)
    let older = c.boundary(n - 120);
    let older_h = c.height_at_size(older);
    assert!(older_h >= end_h - 50);
    let (root_o, paths_o) = c.replay(older, &[p_a, p_b]);
    assert_same(&tree, p_a, older_h, root_o, &paths_o[0]);
    assert_same(&tree, p_b, older_h, root_o, &paths_o[1]);

    // shard 1 is now behind the tree: its server root is checked against our own hashes
    assert_eq!(tree.insert_subtree_roots(1, &c.shard_root(1)).unwrap(), 1);
    assert!(tree.insert_subtree_roots(1, &c.shard_root(0)).is_err());
    // a note before the birthday cannot be witnessed (and must not pretend to be)
    assert!(!tree.is_marked(100));
    assert!(tree.witness(100, end_h).is_err());
}

#[test]
fn legacy_witness_migrates_without_replay() {
    let n = 2 * SHARD + 3_000;
    let c = chain(n, 2);
    let p_old = 4_321; // a note deep in shard 0
    let p_new = SHARD + 777; // a note in shard 1, also already witnessed
    let seed_size = c.boundary(SHARD + 50_000); // where the stored witnesses stand
    let seed_h = c.height_at_size(seed_size);
    let end_h = c.height_at_size(n);

    // the per-note witnesses the wallet has stored today
    let mut r = WitnessReplay::new(CommitmentTree::empty(), &[p_old, p_new]);
    for x in &c.cmxs[..seed_size as usize] {
        r.append_cmx_bytes(x).unwrap();
    }
    let legacy = [
        serialize_witness(r.witness(0).unwrap()),
        serialize_witness(r.witness(1).unwrap()),
    ];

    let mut tree = NoteTreeCore::new(100);
    tree.insert_frontier(&c.frontier(seed_size), seed_h)
        .unwrap();
    tree.insert_witness(&legacy[0], seed_h).unwrap();
    tree.insert_witness(&legacy[1], seed_h).unwrap();
    assert!(tree.is_marked(p_old) && tree.is_marked(p_new));
    // shard 0 is complete inside the old witness: its server root must agree
    assert_eq!(tree.insert_subtree_roots(0, &c.shard_root(0)).unwrap(), 1);

    // a witness at another tree size is refused
    let mut r2 = WitnessReplay::new(CommitmentTree::empty(), &[p_old]);
    for x in &c.cmxs[..(seed_size - 1) as usize] {
        r2.append_cmx_bytes(x).unwrap();
    }
    assert!(tree
        .insert_witness(&serialize_witness(r2.witness(0).unwrap()), seed_h)
        .is_err());

    let (root_s, paths_s) = c.replay(seed_size, &[p_old, p_new]);
    assert_same(&tree, p_old, seed_h, root_s, &paths_s[0]);
    assert_same(&tree, p_new, seed_h, root_s, &paths_s[1]);

    tree.append_blocks(seed_size, &c.encode(seed_size, n), &[], end_h)
        .unwrap();
    let (root, paths) = c.replay(n, &[p_old, p_new]);
    assert_same(&tree, p_old, end_h, root, &paths[0]);
    assert_same(&tree, p_new, end_h, root, &paths[1]);
}

/// rows as the worker keeps them: index -> bytes, plus cap and checkpoints
#[derive(Default)]
struct Rows {
    shards: std::collections::BTreeMap<u64, Vec<u8>>,
    cap: Option<Vec<u8>>,
    checkpoints: Option<Vec<u8>>,
}

impl Rows {
    fn apply(&mut self, tree: &mut NoteTreeCore) {
        let ch = tree.take_changes();
        if ch.rewrite {
            self.shards.clear();
        }
        self.shards.extend(ch.shards);
        if ch.cap.is_some() {
            self.cap = ch.cap;
        }
        if ch.checkpoints.is_some() {
            self.checkpoints = ch.checkpoints;
        }
    }

    fn load(&self) -> NoteTreeCore {
        let mut t = NoteTreeCore::new(100);
        for (i, b) in &self.shards {
            t.load_shard(*i, b).unwrap();
        }
        if let Some(cap) = &self.cap {
            t.load_cap(cap).unwrap();
        }
        if let Some(ck) = &self.checkpoints {
            t.load_checkpoints(ck).unwrap();
        }
        t
    }
}

#[test]
fn persisted_rows_reload_and_truncate() {
    let n = SHARD + 30_000;
    let c = chain(n, 3);
    let birthday = c.boundary(SHARD - 10_000);
    let a = c.boundary(SHARD + 10_000);
    let p = birthday + 5;
    let end_h = c.height_at_size(n);

    let mut tree = NoteTreeCore::new(100);
    let mut rows = Rows::default();
    tree.insert_frontier(&c.frontier(birthday), c.height_at_size(birthday))
        .unwrap();
    tree.append_blocks(birthday, &c.encode(birthday, a), &[p as u32], end_h - 80)
        .unwrap();
    rows.apply(&mut tree);
    // second batch: only the changed shard rows are written
    tree.append_blocks(a, &c.encode(a, n), &[], end_h - 80)
        .unwrap();
    let ch_shards = {
        let before = rows.shards.clone();
        rows.apply(&mut tree);
        rows.shards
            .iter()
            .filter(|(i, b)| before.get(i) != Some(b))
            .count()
    };
    assert_eq!(ch_shards, 1, "only the tip shard changed");

    let reloaded = rows.load();
    assert_eq!(reloaded.latest_checkpoint(), Some(end_h));
    assert_eq!(reloaded.next_position(), Some(n));
    let (root, paths) = c.replay(n, &[p]);
    assert_same(&reloaded, p, end_h, root, &paths[0]);
    assert_eq!(reloaded.oldest_checkpoint(), tree.oldest_checkpoint());

    // a reorg back to a retained checkpoint, then the same blocks again
    let back = c.boundary(n - 100);
    let back_h = c.height_at_size(back);
    let mut t2 = rows.load();
    assert!(t2.truncate(back_h).unwrap());
    assert_eq!(t2.next_position(), Some(back));
    assert_eq!(t2.root_at(back_h).unwrap(), Some(c.replay(back, &[]).0));
    let mut rows2 = Rows {
        shards: rows.shards.clone(),
        cap: rows.cap.clone(),
        checkpoints: rows.checkpoints.clone(),
    };
    rows2.apply(&mut t2);
    let mut t3 = rows2.load();
    t3.append_blocks(back, &c.encode(back, n), &[], end_h - 80)
        .unwrap();
    assert_same(&t3, p, end_h, root, &paths[0]);
    // a height that is not a retained checkpoint cannot be truncated to
    assert!(!t3
        .truncate(c.height_at_size(c.boundary(birthday + 1_000)))
        .unwrap());

    // malformed rows are refused, not half-loaded
    assert!(NoteTreeCore::new(100).load_shard(0, &[1, 9]).is_err());
    assert!(NoteTreeCore::new(100).load_checkpoints(&[1, 0, 0]).is_err());
}

#[test]
fn checkpoints_empty_blocks_and_guards() {
    let c = chain(3_000, 4);
    let mut tree = NoteTreeCore::new(10);
    // empty tree seed: GetTreeState of a pool before its first note
    tree.insert_frontier(&[], 999).unwrap();
    assert_eq!(tree.next_position(), Some(0));
    assert_eq!(
        tree.root_at(999).unwrap(),
        Some(MerkleHashOrchard::empty_root(32.into()).to_bytes())
    );
    // a batch of nothing but empty blocks still ends in a checkpoint
    let empty: Vec<u8> = [1000u32, 1001]
        .iter()
        .flat_map(|h| [h.to_le_bytes(), 0u32.to_le_bytes()].concat())
        .collect();
    let c2 = Chain {
        cmxs: c.cmxs.clone(),
        blocks: c.blocks.iter().map(|b| (b.0 + 2, b.1, b.2)).collect(),
    };
    tree.append_blocks(0, &empty, &[], 0).unwrap();
    assert_eq!(tree.latest_checkpoint(), Some(1001));
    // gap, overlap and stale heights are refused
    assert!(tree.append_blocks(5, &c2.encode(0, 3_000), &[], 0).is_err());
    let stale = [1001u32.to_le_bytes(), 0u32.to_le_bytes()].concat();
    assert!(tree.append_blocks(0, &stale, &[], 0).is_err());
    // the whole chain in one batch, checkpointing every block: only 10 kept
    let end = c2.height_at_size(3_000);
    tree.append_blocks(0, &c2.encode(0, 3_000), &[7], 0)
        .unwrap();
    assert_eq!(tree.latest_checkpoint(), Some(end));
    assert_eq!(tree.oldest_checkpoint(), Some(end - 9));
    let (root, paths) = c2.replay(3_000, &[7]);
    assert_same(&tree, 7, end, root, &paths[0]);
}

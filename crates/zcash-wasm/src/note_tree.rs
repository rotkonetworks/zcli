// Note commitment tree kept as a ShardTree, so a spend reads its witness from
// local state at a retained checkpoint instead of replaying blocks.
//
// One type serves orchard and ironwood: both trees hash with
// `MerkleHashOrchard` (sinsemilla), depth 32, shards of height 16. The worker
// keeps one `NoteTree` per pool per wallet and persists what changed after each
// batch (`take_changes`), since a ShardStore is synchronous and IndexedDB is not.
//
// Shard serialization (`write_shard` / `read_shard`) is the v1 format of
// zcash_client_backend's serialization/shardtree.rs (MIT OR Apache-2.0):
// preorder walk, 0x02 parent + optional annotation, 0x01 leaf + hash + flags,
// 0x00 nil.

use std::collections::{BTreeSet, HashSet};
use std::convert::Infallible;
use std::sync::Arc;

use incrementalmerkletree::{Address, Hashable, Level, Marking, Position, Retention};
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::{MerkleHashOrchard, MerklePath};
use shardtree::store::memory::MemoryShardStore;
use shardtree::store::{Checkpoint, ShardStore, TreeState};
use shardtree::{
    LocatedPrunableTree, LocatedTree, Node, PrunableTree, RetentionFlags, ShardTree, Tree,
};

use crate::witness::{deserialize_tree, deserialize_witness, PathElement, WitnessPathResult};

pub const TREE_DEPTH: u8 = 32;
pub const SHARD_HEIGHT: u8 = 16;

type H = MerkleHashOrchard;
type Tree32 = ShardTree<TrackedStore, TREE_DEPTH, SHARD_HEIGHT>;

/// A MemoryShardStore that remembers what changed since the last `take_changes`.
pub struct TrackedStore {
    inner: MemoryShardStore<H, u32>,
    dirty_shards: BTreeSet<u64>,
    cap_dirty: bool,
    checkpoints_dirty: bool,
    /// shards were truncated: every stored shard row must be rewritten
    rewrite: bool,
}

impl TrackedStore {
    fn new() -> Self {
        Self {
            inner: MemoryShardStore::empty(),
            dirty_shards: BTreeSet::new(),
            cap_dirty: false,
            checkpoints_dirty: false,
            rewrite: false,
        }
    }
}

impl ShardStore for TrackedStore {
    type H = H;
    type CheckpointId = u32;
    type Error = Infallible;

    fn get_shard(&self, a: Address) -> Result<Option<LocatedPrunableTree<H>>, Infallible> {
        self.inner.get_shard(a)
    }
    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<H>>, Infallible> {
        self.inner.last_shard()
    }
    fn put_shard(&mut self, subtree: LocatedPrunableTree<H>) -> Result<(), Infallible> {
        self.dirty_shards.insert(subtree.root_addr().index());
        self.inner.put_shard(subtree)
    }
    fn get_shard_roots(&self) -> Result<Vec<Address>, Infallible> {
        self.inner.get_shard_roots()
    }
    fn truncate_shards(&mut self, shard_index: u64) -> Result<(), Infallible> {
        self.rewrite = true;
        self.inner.truncate_shards(shard_index)
    }
    fn get_cap(&self) -> Result<PrunableTree<H>, Infallible> {
        self.inner.get_cap()
    }
    fn put_cap(&mut self, cap: PrunableTree<H>) -> Result<(), Infallible> {
        self.cap_dirty = true;
        self.inner.put_cap(cap)
    }
    fn min_checkpoint_id(&self) -> Result<Option<u32>, Infallible> {
        self.inner.min_checkpoint_id()
    }
    fn max_checkpoint_id(&self) -> Result<Option<u32>, Infallible> {
        self.inner.max_checkpoint_id()
    }
    fn add_checkpoint(&mut self, id: u32, c: Checkpoint) -> Result<(), Infallible> {
        self.checkpoints_dirty = true;
        self.inner.add_checkpoint(id, c)
    }
    fn checkpoint_count(&self) -> Result<usize, Infallible> {
        self.inner.checkpoint_count()
    }
    fn get_checkpoint_at_depth(&self, d: usize) -> Result<Option<(u32, Checkpoint)>, Infallible> {
        self.inner.get_checkpoint_at_depth(d)
    }
    fn get_checkpoint(&self, id: &u32) -> Result<Option<Checkpoint>, Infallible> {
        self.inner.get_checkpoint(id)
    }
    fn with_checkpoints<F>(&mut self, limit: usize, callback: F) -> Result<(), Infallible>
    where
        F: FnMut(&u32, &Checkpoint) -> Result<(), Infallible>,
    {
        self.inner.with_checkpoints(limit, callback)
    }
    fn for_each_checkpoint<F>(&self, limit: usize, callback: F) -> Result<(), Infallible>
    where
        F: FnMut(&u32, &Checkpoint) -> Result<(), Infallible>,
    {
        self.inner.for_each_checkpoint(limit, callback)
    }
    fn update_checkpoint_with<F>(&mut self, id: &u32, update: F) -> Result<bool, Infallible>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Infallible>,
    {
        self.checkpoints_dirty = true;
        self.inner.update_checkpoint_with(id, update)
    }
    fn remove_checkpoint(&mut self, id: &u32) -> Result<(), Infallible> {
        self.checkpoints_dirty = true;
        self.inner.remove_checkpoint(id)
    }
    fn add_retained_checkpoint(&mut self, id: u32) -> Result<(), Infallible> {
        self.inner.add_retained_checkpoint(id)
    }
    fn remove_retained_checkpoint(&mut self, id: &u32) -> Result<(), Infallible> {
        self.inner.remove_retained_checkpoint(id)
    }
    fn retained_checkpoints(&self) -> Result<BTreeSet<u32>, Infallible> {
        self.inner.retained_checkpoints()
    }
    fn truncate_checkpoints_retaining(&mut self, id: &u32) -> Result<(), Infallible> {
        self.checkpoints_dirty = true;
        self.inner.truncate_checkpoints_retaining(id)
    }
}

/// What changed since the last `take_changes`, ready to be written as rows.
pub struct Changes {
    /// shards were truncated: delete every stored shard row, then write `shards`
    pub rewrite: bool,
    pub shards: Vec<(u64, Vec<u8>)>,
    pub cap: Option<Vec<u8>>,
    pub checkpoints: Option<Vec<u8>>,
}

// ── shard serialization (zcash_client_backend v1 format) ──

const SER_V1: u8 = 1;
const NIL_TAG: u8 = 0;
const LEAF_TAG: u8 = 1;
const PARENT_TAG: u8 = 2;

pub fn write_shard(out: &mut Vec<u8>, tree: &PrunableTree<H>) {
    fn go(out: &mut Vec<u8>, tree: &PrunableTree<H>) {
        match &**tree {
            Node::Parent { ann, left, right } => {
                out.push(PARENT_TAG);
                match ann {
                    Some(h) => {
                        out.push(1);
                        out.extend_from_slice(&h.to_bytes());
                    }
                    None => out.push(0),
                }
                go(out, left);
                go(out, right);
            }
            Node::Leaf { value: (h, flags) } => {
                out.push(LEAF_TAG);
                out.extend_from_slice(&h.to_bytes());
                out.push(flags.bits());
            }
            Node::Nil => out.push(NIL_TAG),
        }
    }
    out.push(SER_V1);
    go(out, tree);
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8, String> {
        let b = *self.data.get(self.pos).ok_or("note tree bytes truncated")?;
        self.pos += 1;
        Ok(b)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.data.len() {
            return Err("note tree bytes truncated".into());
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn hash(&mut self) -> Result<H, String> {
        let b: [u8; 32] = self.take(32)?.try_into().unwrap();
        Option::from(H::from_bytes(&b)).ok_or_else(|| "invalid node hash".to_string())
    }
}

pub fn read_shard(data: &[u8]) -> Result<PrunableTree<H>, String> {
    // depth-bounded, so a hostile row cannot recurse without limit
    fn go(r: &mut Reader, depth: u8) -> Result<PrunableTree<H>, String> {
        if depth > TREE_DEPTH {
            return Err("shard deeper than the tree".into());
        }
        match r.u8()? {
            PARENT_TAG => {
                let ann = match r.u8()? {
                    0 => None,
                    1 => Some(Arc::new(r.hash()?)),
                    t => return Err(format!("bad annotation tag {t}")),
                };
                let left = go(r, depth + 1)?;
                let right = go(r, depth + 1)?;
                Ok(Tree::parent(ann, left, right))
            }
            LEAF_TAG => {
                let h = r.hash()?;
                let bits = r.u8()?;
                let flags = RetentionFlags::from_bits(bits)
                    .ok_or_else(|| format!("bad retention flags {bits}"))?;
                Ok(Tree::leaf((h, flags)))
            }
            NIL_TAG => Ok(Tree::empty()),
            t => Err(format!("bad node tag {t}")),
        }
    }
    let mut r = Reader { data, pos: 0 };
    match r.u8()? {
        SER_V1 => {
            let t = go(&mut r, 0)?;
            if r.pos != data.len() {
                return Err("trailing bytes after shard".into());
            }
            Ok(t)
        }
        v => Err(format!("shard serialization version {v} not recognized")),
    }
}

/// `[u32 n] n x ([u32 id][u8 0=empty|1=at][u64 pos if at][u32 m] m x [u64 removed mark])`
fn write_checkpoints(store: &TrackedStore) -> Vec<u8> {
    let mut entries: Vec<(u32, Checkpoint)> = Vec::new();
    store
        .for_each_checkpoint(usize::MAX, |id, c| {
            entries.push((*id, c.clone()));
            Ok(())
        })
        .unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (id, c) in entries {
        out.extend_from_slice(&id.to_le_bytes());
        match c.tree_state() {
            TreeState::Empty => out.push(0),
            TreeState::AtPosition(p) => {
                out.push(1);
                out.extend_from_slice(&u64::from(p).to_le_bytes());
            }
        }
        let marks = c.marks_removed();
        out.extend_from_slice(&(marks.len() as u32).to_le_bytes());
        for m in marks {
            out.extend_from_slice(&u64::from(*m).to_le_bytes());
        }
    }
    out
}

fn read_checkpoints(data: &[u8]) -> Result<Vec<(u32, Checkpoint)>, String> {
    let mut r = Reader { data, pos: 0 };
    let n = r.u32()?;
    let mut out = Vec::with_capacity(n.min(1024) as usize);
    for _ in 0..n {
        let id = r.u32()?;
        let state = match r.u8()? {
            0 => TreeState::Empty,
            1 => TreeState::AtPosition(Position::from(r.u64()?)),
            t => return Err(format!("bad checkpoint tag {t}")),
        };
        let m = r.u32()?;
        let mut marks = BTreeSet::new();
        for _ in 0..m {
            marks.insert(Position::from(r.u64()?));
        }
        out.push((id, Checkpoint::from_parts(state, marks)));
    }
    if r.pos != data.len() {
        return Err("trailing bytes after checkpoints".into());
    }
    Ok(out)
}

fn leaf_hash(cmx: &[u8]) -> H {
    // same convention as witness.rs: an unparseable cmx is the empty leaf
    let arr: [u8; 32] = match cmx.try_into() {
        Ok(a) => a,
        Err(_) => return H::empty_leaf(),
    };
    Option::from(ExtractedNoteCommitment::from_bytes(&arr))
        .map(|c| H::from_cmx(&c))
        .unwrap_or_else(H::empty_leaf)
}

fn err<E: std::fmt::Debug>(what: &str) -> impl FnOnce(E) -> String + '_ {
    move |e| format!("{what}: {e:?}")
}

/// One pool's note commitment tree.
pub struct NoteTreeCore {
    tree: Tree32,
}

impl NoteTreeCore {
    pub fn new(max_checkpoints: usize) -> Self {
        Self {
            tree: ShardTree::new(TrackedStore::new(), max_checkpoints),
        }
    }

    // ── loading persisted rows (does not mark anything dirty) ──

    pub fn load_shard(&mut self, index: u64, bytes: &[u8]) -> Result<(), String> {
        let root = read_shard(bytes)?;
        let addr = Address::from_parts(Level::from(SHARD_HEIGHT), index);
        let shard = LocatedTree::from_parts(addr, root)
            .map_err(|a| format!("shard {index} does not fit at {a:?}"))?;
        self.tree.store_mut().inner.put_shard(shard).unwrap();
        Ok(())
    }

    pub fn load_cap(&mut self, bytes: &[u8]) -> Result<(), String> {
        let cap = read_shard(bytes)?;
        self.tree.store_mut().inner.put_cap(cap).unwrap();
        Ok(())
    }

    pub fn load_checkpoints(&mut self, bytes: &[u8]) -> Result<(), String> {
        for (id, c) in read_checkpoints(bytes)? {
            self.tree.store_mut().inner.add_checkpoint(id, c).unwrap();
        }
        Ok(())
    }

    // ── state ──

    /// Height of the newest checkpoint, if any.
    pub fn latest_checkpoint(&self) -> Option<u32> {
        self.tree.store().max_checkpoint_id().unwrap()
    }

    /// Oldest retained checkpoint, if any.
    pub fn oldest_checkpoint(&self) -> Option<u32> {
        self.tree.store().min_checkpoint_id().unwrap()
    }

    /// Tree size at a checkpoint (the next leaf position).
    pub fn size_at(&self, height: u32) -> Option<u64> {
        self.tree
            .store()
            .get_checkpoint(&height)
            .unwrap()
            .map(|c| c.position().map_or(0, |p| u64::from(p) + 1))
    }

    /// Tree size at the newest checkpoint: where the next batch must start.
    pub fn next_position(&self) -> Option<u64> {
        self.latest_checkpoint().and_then(|h| self.size_at(h))
    }

    pub fn is_marked(&self, position: u64) -> bool {
        matches!(
            self.tree.get_marked_leaf(Position::from(position)),
            Ok(Some(_))
        )
    }

    pub fn root_at(&self, height: u32) -> Result<Option<[u8; 32]>, String> {
        Ok(self
            .tree
            .root_at_checkpoint_id(&height)
            .map_err(err("root"))?
            .map(|h| h.to_bytes()))
    }

    // ── seeding ──

    /// Seed from a zcashd-format frontier (what GetTreeState and the worker's
    /// running frontier carry), checkpointed at `height`. Only on a tree with no
    /// checkpoint at or after `height`.
    pub fn insert_frontier(&mut self, frontier: &[u8], height: u32) -> Result<(), String> {
        if self.latest_checkpoint().is_some_and(|h| h >= height) {
            return Err(format!(
                "frontier at {height} is not past the newest checkpoint"
            ));
        }
        let tree = deserialize_tree(frontier)?;
        self.tree
            .insert_frontier(
                tree.to_frontier(),
                Retention::Checkpoint {
                    id: height,
                    marking: Marking::Reference,
                },
            )
            .map_err(err("insert frontier"))
    }

    /// Migrate a legacy per-note IncrementalWitness. The witness must be at the
    /// tree size of the checkpoint at `height` (insert that frontier first).
    pub fn insert_witness(&mut self, witness: &[u8], height: u32) -> Result<(), String> {
        let w = deserialize_witness(witness)?;
        let size = self
            .size_at(height)
            .ok_or_else(|| format!("no checkpoint at {height}"))?;
        let witness_size = u64::from(w.tip_position()) + 1;
        if witness_size != size {
            return Err(format!(
                "witness is at tree size {witness_size}, checkpoint {height} at {size}"
            ));
        }
        self.tree
            .insert_witness_nodes(w, height)
            .map_err(err("insert witness"))
    }

    /// Add complete-shard roots from GetSubtreeRoots, `roots` = n x 32 bytes for
    /// shard indices `start_index..`. Only shards wholly behind the newest
    /// checkpoint are taken (a root ahead of the scan would sit to the right of
    /// the tree's tip). A shard whose root we can already compute from our own
    /// leaves is compared, not inserted. Returns how many roots were consumed,
    /// so the caller resumes from `start_index + n`.
    pub fn insert_subtree_roots(&mut self, start_index: u64, roots: &[u8]) -> Result<u64, String> {
        if !roots.len().is_multiple_of(32) {
            return Err("subtree roots must be 32-byte hashes".into());
        }
        let next = self.next_position().ok_or("tree has no checkpoint yet")?;
        let mut taken = 0u64;
        for (i, chunk) in roots.chunks(32).enumerate() {
            let index = start_index + i as u64;
            let addr = Address::from_parts(Level::from(SHARD_HEIGHT), index);
            if u64::from(addr.position_range_end()) > next {
                break;
            }
            let b: [u8; 32] = chunk.try_into().unwrap();
            let root: H = Option::from(H::from_bytes(&b))
                .ok_or_else(|| format!("subtree root {index} is not a field element"))?;
            match self.tree.root(addr, addr.position_range_end()) {
                Ok(ours) if ours == root => {}
                Ok(_) => {
                    return Err(format!(
                        "subtree root {index} does not match the leaves we scanned"
                    ))
                }
                // not computable from what we hold (before the wallet's birthday)
                Err(_) => self
                    .tree
                    .insert(addr, root)
                    .map_err(err("insert subtree root"))?,
            }
            taken += 1;
        }
        Ok(taken)
    }

    // ── scanning ──

    /// Append one batch of blocks. `blocks` = repeated
    /// `[u32 height LE][u32 n LE][n x 32-byte cmx]`, in chain order, starting at
    /// the tree size of the newest checkpoint (`start_position` must equal it).
    /// Leaves at `marked` positions (our notes) are kept witnessable. Every block
    /// at or above `checkpoint_from` ends in a checkpoint, and so does the last
    /// block of the batch.
    pub fn append_blocks(
        &mut self,
        start_position: u64,
        blocks: &[u8],
        marked: &[u32],
        checkpoint_from: u32,
    ) -> Result<(), String> {
        let next = self.next_position().ok_or("tree has no checkpoint yet")?;
        if next != start_position {
            return Err(format!(
                "batch starts at {start_position} but the tree ends at {next}"
            ));
        }
        let mut last_height = self.latest_checkpoint().unwrap();

        // parse up front so a malformed batch changes nothing
        let mut parsed: Vec<(u32, &[u8])> = Vec::new();
        let mut r = Reader {
            data: blocks,
            pos: 0,
        };
        while r.pos < blocks.len() {
            let height = r.u32()?;
            let n = r.u32()? as usize;
            let cmxs = r.take(n.checked_mul(32).ok_or("block too large")?)?;
            if height <= last_height {
                return Err(format!("block {height} is not past {last_height}"));
            }
            last_height = height;
            parsed.push((height, cmxs));
        }
        let marked: HashSet<u64> = marked.iter().map(|&p| p as u64).collect();

        let mut pos = start_position;
        let mut run_start = start_position;
        let mut leaves: Vec<(H, Retention<u32>)> = Vec::new();
        let last = parsed.len().saturating_sub(1);
        for (bi, (height, cmxs)) in parsed.iter().enumerate() {
            let checkpoint = *height >= checkpoint_from || bi == last;
            let n = cmxs.len() / 32;
            if n == 0 {
                if checkpoint {
                    self.flush(run_start, &mut leaves)?;
                    run_start = pos;
                    if !self.tree.checkpoint(*height).map_err(err("checkpoint"))? {
                        return Err(format!("checkpoint {height} out of order"));
                    }
                }
                continue;
            }
            for (i, cmx) in cmxs.chunks(32).enumerate() {
                let is_marked = marked.contains(&pos);
                let retention = if checkpoint && i == n - 1 {
                    Retention::Checkpoint {
                        id: *height,
                        marking: if is_marked {
                            Marking::Marked
                        } else {
                            Marking::None
                        },
                    }
                } else if is_marked {
                    Retention::Marked
                } else {
                    Retention::Ephemeral
                };
                leaves.push((leaf_hash(cmx), retention));
                pos += 1;
            }
        }
        self.flush(run_start, &mut leaves)
    }

    fn flush(&mut self, start: u64, leaves: &mut Vec<(H, Retention<u32>)>) -> Result<(), String> {
        if leaves.is_empty() {
            return Ok(());
        }
        self.tree
            .batch_insert(Position::from(start), leaves.drain(..))
            .map_err(err("append"))?;
        Ok(())
    }

    /// Roll back to the checkpoint at `height`. False if it is not retained (the
    /// caller then drops the tree).
    pub fn truncate(&mut self, height: u32) -> Result<bool, String> {
        self.tree
            .truncate_to_checkpoint(&height)
            .map_err(err("truncate"))
    }

    // ── spending ──

    /// Merkle path for the leaf at `position` as of the checkpoint at `height`,
    /// in the shape `witness_extract_path` returns.
    pub fn witness(&self, position: u64, height: u32) -> Result<WitnessPathResult, String> {
        let root = self
            .root_at(height)?
            .ok_or_else(|| format!("no checkpoint at {height}"))?;
        let path = self
            .tree
            .witness_at_checkpoint_id(Position::from(position), &height)
            .map_err(err("witness"))?
            .ok_or_else(|| format!("no checkpoint at {height}"))?;
        let path = MerklePath::from(path);
        Ok(WitnessPathResult {
            position: u64::from(path.position()),
            root_hex: hex::encode(root),
            path: path
                .auth_path()
                .iter()
                .map(|h| PathElement {
                    hash: hex::encode(h.to_bytes()),
                })
                .collect(),
        })
    }

    // ── persistence ──

    /// Everything that changed since the last call, serialized.
    pub fn take_changes(&mut self) -> Changes {
        let store = self.tree.store_mut();
        let rewrite = std::mem::take(&mut store.rewrite);
        let indices: Vec<u64> = if rewrite {
            store
                .get_shard_roots()
                .unwrap()
                .into_iter()
                .map(|a| a.index())
                .collect()
        } else {
            std::mem::take(&mut store.dirty_shards)
                .into_iter()
                .collect()
        };
        store.dirty_shards.clear();
        let mut shards = Vec::with_capacity(indices.len());
        for index in indices {
            let addr = Address::from_parts(Level::from(SHARD_HEIGHT), index);
            if let Some(s) = store.get_shard(addr).unwrap() {
                let mut out = Vec::new();
                write_shard(&mut out, s.root());
                shards.push((index, out));
            }
        }
        let cap = (std::mem::take(&mut store.cap_dirty) || rewrite).then(|| {
            let mut out = Vec::new();
            write_shard(&mut out, &store.get_cap().unwrap());
            out
        });
        let checkpoints = (std::mem::take(&mut store.checkpoints_dirty) || rewrite)
            .then(|| write_checkpoints(store));
        Changes {
            rewrite,
            shards,
            cap,
            checkpoints,
        }
    }
}

// ── wasm surface ──

use wasm_bindgen::prelude::*;

/// One pool's note commitment tree (orchard or ironwood: same hash, same
/// shape). See `NoteTreeCore` for each method's contract.
#[wasm_bindgen]
pub struct NoteTree {
    core: NoteTreeCore,
}

fn js_err(e: String) -> JsError {
    JsError::new(&e)
}

#[wasm_bindgen]
impl NoteTree {
    #[wasm_bindgen(constructor)]
    pub fn new(max_checkpoints: u32) -> NoteTree {
        NoteTree {
            core: NoteTreeCore::new(max_checkpoints as usize),
        }
    }

    pub fn load_shard(&mut self, index: u32, bytes: &[u8]) -> Result<(), JsError> {
        self.core.load_shard(index as u64, bytes).map_err(js_err)
    }

    pub fn load_cap(&mut self, bytes: &[u8]) -> Result<(), JsError> {
        self.core.load_cap(bytes).map_err(js_err)
    }

    pub fn load_checkpoints(&mut self, bytes: &[u8]) -> Result<(), JsError> {
        self.core.load_checkpoints(bytes).map_err(js_err)
    }

    pub fn latest_checkpoint(&self) -> Option<u32> {
        self.core.latest_checkpoint()
    }

    pub fn oldest_checkpoint(&self) -> Option<u32> {
        self.core.oldest_checkpoint()
    }

    /// tree size at the newest checkpoint, or undefined before seeding
    pub fn next_position(&self) -> Option<f64> {
        self.core.next_position().map(|p| p as f64)
    }

    pub fn is_marked(&self, position: f64) -> bool {
        self.core.is_marked(position as u64)
    }

    /// hex root at the checkpoint, or undefined if it is not retained
    pub fn root_at(&self, height: u32) -> Result<Option<String>, JsError> {
        Ok(self.core.root_at(height).map_err(js_err)?.map(hex::encode))
    }

    pub fn insert_frontier(&mut self, frontier_hex: &str, height: u32) -> Result<(), JsError> {
        let bytes = hex::decode(frontier_hex).map_err(|e| JsError::new(&e.to_string()))?;
        self.core.insert_frontier(&bytes, height).map_err(js_err)
    }

    pub fn insert_witness(&mut self, witness_hex: &str, height: u32) -> Result<(), JsError> {
        let bytes = hex::decode(witness_hex).map_err(|e| JsError::new(&e.to_string()))?;
        self.core.insert_witness(&bytes, height).map_err(js_err)
    }

    /// returns how many roots were taken (resume from start_index + n)
    pub fn insert_subtree_roots(&mut self, start_index: u32, roots: &[u8]) -> Result<u32, JsError> {
        self.core
            .insert_subtree_roots(start_index as u64, roots)
            .map(|n| n as u32)
            .map_err(js_err)
    }

    pub fn append_blocks(
        &mut self,
        start_position: f64,
        blocks: &[u8],
        marked: &[u32],
        checkpoint_from: u32,
    ) -> Result<(), JsError> {
        self.core
            .append_blocks(start_position as u64, blocks, marked, checkpoint_from)
            .map_err(js_err)
    }

    pub fn truncate(&mut self, height: u32) -> Result<bool, JsError> {
        self.core.truncate(height).map_err(js_err)
    }

    /// JSON `{position, root_hex, path: [{hash}]}`, as `witness_extract_path`
    pub fn witness(&self, position: f64, height: u32) -> Result<String, JsError> {
        let w = self.core.witness(position as u64, height).map_err(js_err)?;
        serde_json::to_string(&w).map_err(|e| JsError::new(&e.to_string()))
    }

    /// `{rewrite, shards: [[index, Uint8Array]], cap?: Uint8Array, checkpoints?: Uint8Array}`
    pub fn take_changes(&mut self) -> Result<JsValue, JsError> {
        let c = self.core.take_changes();
        let out = js_sys::Object::new();
        let set = |k: &str, v: &JsValue| js_sys::Reflect::set(&out, &k.into(), v).map(|_| ());
        let shards = js_sys::Array::new();
        for (index, bytes) in c.shards {
            let pair = js_sys::Array::new();
            pair.push(&JsValue::from(index as f64));
            pair.push(&js_sys::Uint8Array::from(bytes.as_slice()));
            shards.push(&pair);
        }
        let fail = |_| JsError::new("take_changes: cannot build result");
        set("rewrite", &JsValue::from(c.rewrite)).map_err(fail)?;
        set("shards", &shards).map_err(fail)?;
        if let Some(cap) = c.cap {
            set("cap", &js_sys::Uint8Array::from(cap.as_slice())).map_err(fail)?;
        }
        if let Some(ck) = c.checkpoints {
            set("checkpoints", &js_sys::Uint8Array::from(ck.as_slice())).map_err(fail)?;
        }
        Ok(out.into())
    }
}

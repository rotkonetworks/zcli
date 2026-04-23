// merkle witness construction for orchard spends (ported from zcli/src/witness.rs)
//
// uses tree state checkpoints to avoid replaying from orchard activation.
// the JS worker fetches blocks and tree states, passes raw data here.

use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::witness::IncrementalWitness;
use incrementalmerkletree::Hashable;
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::{Anchor, MerkleHashOrchard, MerklePath};
use std::collections::HashMap;

/// Deserialize a lightwalletd/zcashd orchard frontier into a CommitmentTree.
///
/// Wire format (zcash_primitives CommitmentTree serialization):
///   [Option<Hash>] left
///   [Option<Hash>] right
///   [CompactSize]  parent_count
///   [Option<Hash>] * parent_count
///
/// Option encoding: 0x00 = None, 0x01 = Some followed by 32 bytes.
pub fn deserialize_tree(data: &[u8]) -> Result<CommitmentTree<MerkleHashOrchard, 32>, String> {
    if data.is_empty() {
        return Ok(CommitmentTree::empty());
    }

    let mut pos = 0;

    let read_option = |pos: &mut usize| -> Result<Option<MerkleHashOrchard>, String> {
        if *pos >= data.len() {
            return Err("frontier truncated reading option tag".into());
        }
        if data[*pos] == 0x01 {
            if *pos + 33 > data.len() {
                return Err("frontier truncated reading hash".into());
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[*pos + 1..*pos + 33]);
            *pos += 33;
            Option::from(MerkleHashOrchard::from_bytes(&bytes))
                .map(Some)
                .ok_or_else(|| "invalid frontier hash".to_string())
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
            .map_err(|_| "invalid frontier structure (no parents)".to_string());
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
        format!(
            "invalid frontier structure (left={} right={} parents={})",
            has_left, has_right, n_parents,
        )
    })
}

fn read_compact_size(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    if *pos >= data.len() {
        return Err("compact size: truncated".into());
    }
    let first = data[*pos];
    *pos += 1;
    match first {
        0x00..=0xfc => Ok(first as u64),
        0xfd => {
            if *pos + 2 > data.len() {
                return Err("compact size: truncated u16".into());
            }
            let v = u16::from_le_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Ok(v as u64)
        }
        0xfe => {
            if *pos + 4 > data.len() {
                return Err("compact size: truncated u32".into());
            }
            let v =
                u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
            *pos += 4;
            Ok(v as u64)
        }
        0xff => {
            if *pos + 8 > data.len() {
                return Err("compact size: truncated u64".into());
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

/// Compute the tree size from frontier data.
pub fn compute_frontier_tree_size(data: &[u8]) -> Result<u64, String> {
    let tree = deserialize_tree(data)?;
    Ok(tree.size() as u64)
}

/// Compute the tree root from frontier data.
pub fn compute_tree_root(data: &[u8]) -> Result<[u8; 32], String> {
    let tree = deserialize_tree(data)?;
    Ok(tree.root().to_bytes())
}

// ── serialization helpers ──

fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn write_option_hash(out: &mut Vec<u8>, h: &Option<MerkleHashOrchard>) {
    match h {
        Some(node) => {
            out.push(0x01);
            out.extend_from_slice(&node.to_bytes());
        }
        None => out.push(0x00),
    }
}

/// Serialize a CommitmentTree in the same wire format `deserialize_tree` expects
/// (zcashd legacy encoding).
pub fn serialize_tree(tree: &CommitmentTree<MerkleHashOrchard, 32>) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 32 * 32);
    write_option_hash(&mut out, tree.left());
    write_option_hash(&mut out, tree.right());
    let parents = tree.parents();
    write_compact_size(&mut out, parents.len() as u64);
    for p in parents {
        write_option_hash(&mut out, p);
    }
    out
}

/// Serialize an IncrementalWitness as tree || Vector<filled> || Option<cursor>.
/// Mirrors zcash_primitives::merkle_tree::write_incremental_witness.
pub fn serialize_witness(w: &IncrementalWitness<MerkleHashOrchard, 32>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&serialize_tree(w.tree()));

    let filled = w.filled();
    write_compact_size(&mut out, filled.len() as u64);
    for h in filled {
        out.extend_from_slice(&h.to_bytes());
    }

    match w.cursor() {
        Some(c) => {
            out.push(0x01);
            out.extend_from_slice(&serialize_tree(c));
        }
        None => out.push(0x00),
    }
    out
}

fn read_option_hash_cursor(data: &[u8], pos: &mut usize) -> Result<Option<MerkleHashOrchard>, String> {
    if *pos >= data.len() {
        return Err("witness truncated reading option tag".into());
    }
    if data[*pos] == 0x01 {
        if *pos + 33 > data.len() {
            return Err("witness truncated reading hash".into());
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data[*pos + 1..*pos + 33]);
        *pos += 33;
        Option::from(MerkleHashOrchard::from_bytes(&bytes))
            .map(Some)
            .ok_or_else(|| "invalid witness hash".to_string())
    } else {
        *pos += 1;
        Ok(None)
    }
}

fn read_tree_at(data: &[u8], pos: &mut usize) -> Result<CommitmentTree<MerkleHashOrchard, 32>, String> {
    let left = read_option_hash_cursor(data, pos)?;
    let right = read_option_hash_cursor(data, pos)?;
    let n_parents = read_compact_size(data, pos)?;
    let mut parents = Vec::with_capacity(n_parents as usize);
    for _ in 0..n_parents {
        parents.push(read_option_hash_cursor(data, pos)?);
    }
    CommitmentTree::from_parts(left, right, parents).map_err(|_| "invalid tree parts".to_string())
}

/// Deserialize an IncrementalWitness previously produced by `serialize_witness`.
pub fn deserialize_witness(
    data: &[u8],
) -> Result<IncrementalWitness<MerkleHashOrchard, 32>, String> {
    let mut pos = 0;
    let tree = read_tree_at(data, &mut pos)?;

    let n_filled = read_compact_size(data, &mut pos)?;
    let mut filled = Vec::with_capacity(n_filled as usize);
    for _ in 0..n_filled {
        if pos + 32 > data.len() {
            return Err("witness truncated reading filled hash".into());
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        filled.push(
            Option::from(MerkleHashOrchard::from_bytes(&b))
                .ok_or_else(|| "invalid filled hash".to_string())?,
        );
    }

    if pos >= data.len() {
        return Err("witness truncated reading cursor tag".into());
    }
    let cursor = if data[pos] == 0x01 {
        pos += 1;
        Some(read_tree_at(data, &mut pos)?)
    } else {
        None
    };

    IncrementalWitness::from_parts(tree, filled, cursor)
        .ok_or_else(|| "invalid witness parts".to_string())
}

/// A compact block action - just the cmx commitment.
#[derive(serde::Deserialize)]
pub struct CompactAction {
    pub cmx_hex: String,
}

/// A compact block with height and actions.
#[derive(serde::Deserialize)]
pub struct CompactBlockData {
    pub height: u32,
    pub actions: Vec<CompactAction>,
}

/// Result of merkle path computation.
#[derive(serde::Serialize)]
pub struct MerklePathResult {
    pub anchor_hex: String,
    pub paths: Vec<SerializedMerklePath>,
}

/// A serialized merkle path (32 siblings of 32 bytes each).
#[derive(serde::Serialize)]
pub struct SerializedMerklePath {
    pub position: u64,
    pub path: Vec<PathElement>,
}

#[derive(serde::Serialize)]
pub struct PathElement {
    pub hash: String,
}

/// Build merkle paths for specified note positions.
///
/// Takes a tree state checkpoint, compact blocks to replay, and note positions.
/// Returns the anchor and merkle paths for each note position.
pub fn build_merkle_paths_inner(
    tree_state_hex: &str,
    compact_blocks: &[CompactBlockData],
    note_positions: &[u64],
    _anchor_height: u32,
) -> Result<MerklePathResult, String> {
    // deserialize checkpoint tree
    let tree_bytes =
        hex::decode(tree_state_hex).map_err(|e| format!("invalid tree state hex: {}", e))?;
    let mut tree = deserialize_tree(&tree_bytes)?;

    let mut position_counter = tree.size() as u64;

    // build position -> index map
    let mut position_map: HashMap<u64, usize> = HashMap::new();
    for (i, &pos) in note_positions.iter().enumerate() {
        position_map.insert(pos, i);
    }

    let mut witnesses: Vec<Option<IncrementalWitness<MerkleHashOrchard, 32>>> =
        vec![None; note_positions.len()];

    // replay blocks
    for block in compact_blocks {
        for action in &block.actions {
            let cmx_bytes = hex::decode(&action.cmx_hex)
                .map_err(|e| format!("invalid cmx hex at height {}: {}", block.height, e))?;

            let hash = if cmx_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&cmx_bytes);
                let cmx = ExtractedNoteCommitment::from_bytes(&arr);
                if bool::from(cmx.is_some()) {
                    MerkleHashOrchard::from_cmx(&cmx.unwrap())
                } else {
                    MerkleHashOrchard::empty_leaf()
                }
            } else {
                MerkleHashOrchard::empty_leaf()
            };

            tree.append(hash)
                .map_err(|_| "merkle tree full".to_string())?;

            // snapshot witness at note positions
            if let Some(&idx) = position_map.get(&position_counter) {
                witnesses[idx] = IncrementalWitness::from_tree(tree.clone());
            }

            // update existing witnesses with new leaf
            for w in witnesses.iter_mut().flatten() {
                if w.witnessed_position() < incrementalmerkletree::Position::from(position_counter)
                {
                    w.append(hash)
                        .map_err(|_| "witness tree full".to_string())?;
                }
            }

            position_counter += 1;
        }
    }

    // extract anchor and paths
    let anchor_root = tree.root();
    let anchor = Anchor::from(anchor_root);

    let mut paths = Vec::with_capacity(note_positions.len());
    for (i, w) in witnesses.into_iter().enumerate() {
        let witness = w.ok_or_else(|| {
            format!(
                "note at position {} not found in tree replay",
                note_positions[i],
            )
        })?;

        let imt_path = witness.path().ok_or_else(|| {
            format!(
                "failed to compute merkle path for note at position {}",
                note_positions[i],
            )
        })?;

        let merkle_path = MerklePath::from(imt_path);
        let auth_path = merkle_path.auth_path();
        let position = u64::from(merkle_path.position());

        let path_elements: Vec<PathElement> = auth_path
            .iter()
            .map(|h| PathElement {
                hash: hex::encode(h.to_bytes()),
            })
            .collect();

        paths.push(SerializedMerklePath {
            position,
            path: path_elements,
        });
    }

    Ok(MerklePathResult {
        anchor_hex: hex::encode(anchor.to_bytes()),
        paths,
    })
}

// ── per-note witness persistence ──

/// Input witness identified by a caller-chosen opaque id (usually the note id).
#[derive(serde::Deserialize)]
pub struct ExistingWitnessInput {
    pub id: String,
    pub witness_hex: String,
}

/// A new note to seed during the block range. The note's cmx must appear at
/// `position` within the blocks supplied (or equal `frontier_tree_size`).
#[derive(serde::Deserialize)]
pub struct NewNoteInput {
    pub id: String,
    pub position: u64,
}

#[derive(serde::Serialize)]
pub struct UpdatedWitnessOutput {
    pub id: String,
    pub position: u64,
    pub witness_hex: String,
}

/// Result of an incremental witness update covering a range of blocks.
#[derive(serde::Serialize)]
pub struct WitnessUpdateResult {
    pub end_frontier_hex: String,
    pub anchor_hex: String,
    pub witnesses: Vec<UpdatedWitnessOutput>,
    pub seeded_ids: Vec<String>,
    pub end_position: u64,
}

/// Apply a range of compact blocks to a running tree and to every tracked
/// witness, optionally seeding new witnesses at given positions mid-range.
///
/// Input state:
///   * `start_frontier_hex` - tree state BEFORE the first block
///   * `compact_blocks`     - blocks in order (empty list is a no-op)
///   * `existing`           - witnesses to advance (all will receive every cmx)
///   * `new_notes`          - ids/positions to seed; each position must land
///                             somewhere in the block range (or == starting size)
///
/// Output: updated witnesses (existing + newly seeded), the new frontier, and
/// the anchor matching all witnesses.
pub fn witness_sync_update_inner(
    start_frontier_hex: &str,
    compact_blocks: &[CompactBlockData],
    existing: &[ExistingWitnessInput],
    new_notes: &[NewNoteInput],
) -> Result<WitnessUpdateResult, String> {
    let tree_bytes =
        hex::decode(start_frontier_hex).map_err(|e| format!("invalid start frontier hex: {}", e))?;
    let mut tree = deserialize_tree(&tree_bytes)?;

    let mut existing_witnesses: Vec<(String, IncrementalWitness<MerkleHashOrchard, 32>)> =
        Vec::with_capacity(existing.len());
    for e in existing {
        let bytes = hex::decode(&e.witness_hex)
            .map_err(|err| format!("invalid witness hex for {}: {}", e.id, err))?;
        let w = deserialize_witness(&bytes)
            .map_err(|err| format!("cannot deserialize witness {}: {}", e.id, err))?;
        existing_witnesses.push((e.id.clone(), w));
    }

    let mut seed_map: HashMap<u64, &NewNoteInput> = HashMap::new();
    for n in new_notes {
        if seed_map.insert(n.position, n).is_some() {
            return Err(format!("duplicate seed position {}", n.position));
        }
    }

    let mut seeded: Vec<(String, u64, IncrementalWitness<MerkleHashOrchard, 32>)> = Vec::new();
    let mut seeded_ids_in_order: Vec<String> = Vec::new();
    let mut position_counter = tree.size() as u64;

    for block in compact_blocks {
        for action in &block.actions {
            let cmx_bytes = hex::decode(&action.cmx_hex)
                .map_err(|e| format!("invalid cmx hex at height {}: {}", block.height, e))?;

            let hash = if cmx_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&cmx_bytes);
                let cmx = ExtractedNoteCommitment::from_bytes(&arr);
                if bool::from(cmx.is_some()) {
                    MerkleHashOrchard::from_cmx(&cmx.unwrap())
                } else {
                    MerkleHashOrchard::empty_leaf()
                }
            } else {
                MerkleHashOrchard::empty_leaf()
            };

            tree.append(hash)
                .map_err(|_| "merkle tree full during sync update".to_string())?;

            if let Some(note) = seed_map.get(&position_counter) {
                let w = IncrementalWitness::from_tree(tree.clone())
                    .ok_or_else(|| format!("cannot seed witness for {}", note.id))?;
                seeded.push((note.id.clone(), position_counter, w));
                seeded_ids_in_order.push(note.id.clone());
            }

            let target_pos = incrementalmerkletree::Position::from(position_counter);
            for (_id, w) in existing_witnesses.iter_mut() {
                if w.witnessed_position() < target_pos {
                    w.append(hash)
                        .map_err(|_| "witness tree full during sync update".to_string())?;
                }
            }
            for (_id, _pos, w) in seeded.iter_mut() {
                if w.witnessed_position() < target_pos {
                    w.append(hash)
                        .map_err(|_| "witness tree full during sync update".to_string())?;
                }
            }

            position_counter += 1;
        }
    }

    let anchor = tree.root().to_bytes();
    let end_frontier_hex = hex::encode(serialize_tree(&tree));

    // existing witnesses first (so callers can associate by stable id order),
    // then seeded ones.
    let mut witnesses_out: Vec<UpdatedWitnessOutput> =
        Vec::with_capacity(existing_witnesses.len() + seeded.len());
    for (id, w) in existing_witnesses {
        let pos: u64 = u64::from(w.witnessed_position());
        witnesses_out.push(UpdatedWitnessOutput {
            id,
            position: pos,
            witness_hex: hex::encode(serialize_witness(&w)),
        });
    }
    for (id, pos, w) in seeded {
        witnesses_out.push(UpdatedWitnessOutput {
            id,
            position: pos,
            witness_hex: hex::encode(serialize_witness(&w)),
        });
    }

    Ok(WitnessUpdateResult {
        end_frontier_hex,
        anchor_hex: hex::encode(anchor),
        witnesses: witnesses_out,
        seeded_ids: seeded_ids_in_order,
        end_position: position_counter,
    })
}

/// Result of extracting a merkle path from a stored witness.
#[derive(serde::Serialize)]
pub struct WitnessPathResult {
    pub position: u64,
    pub root_hex: String,
    pub path: Vec<PathElement>,
}

/// Extract the merkle path and current root from a serialized witness.
///
/// The caller must cross-check `root_hex` against the anchor the spend will
/// use (e.g. `tree_root_hex(orchardTree @ anchorHeight)`).
pub fn witness_extract_path_inner(witness_hex: &str) -> Result<WitnessPathResult, String> {
    let bytes = hex::decode(witness_hex).map_err(|e| format!("invalid witness hex: {}", e))?;
    let witness = deserialize_witness(&bytes)?;

    let root = witness.root().to_bytes();

    let imt_path = witness
        .path()
        .ok_or_else(|| "witness empty, cannot produce path".to_string())?;
    let merkle_path = MerklePath::from(imt_path);
    let auth_path = merkle_path.auth_path();
    let position = u64::from(merkle_path.position());

    let path: Vec<PathElement> = auth_path
        .iter()
        .map(|h| PathElement {
            hash: hex::encode(h.to_bytes()),
        })
        .collect();

    Ok(WitnessPathResult {
        position,
        root_hex: hex::encode(root),
        path,
    })
}

/// Like `build_merkle_paths_inner`, but also returns serialized witness state
/// so the caller can cache witnesses and keep them current via
/// `witness_sync_update_inner` rather than re-replaying the range next time.
#[derive(serde::Serialize)]
pub struct MerklePathsWithWitnesses {
    pub anchor_hex: String,
    pub end_frontier_hex: String,
    pub entries: Vec<WitnessedNote>,
}

#[derive(serde::Serialize)]
pub struct WitnessedNote {
    pub position: u64,
    pub witness_hex: String,
    pub path: Vec<PathElement>,
}

pub fn build_witnesses_and_paths_inner(
    tree_state_hex: &str,
    compact_blocks: &[CompactBlockData],
    note_positions: &[u64],
) -> Result<MerklePathsWithWitnesses, String> {
    let tree_bytes =
        hex::decode(tree_state_hex).map_err(|e| format!("invalid tree state hex: {}", e))?;
    let mut tree = deserialize_tree(&tree_bytes)?;
    let mut position_counter = tree.size() as u64;

    let mut position_map: HashMap<u64, usize> = HashMap::new();
    for (i, &pos) in note_positions.iter().enumerate() {
        position_map.insert(pos, i);
    }

    let mut witnesses: Vec<Option<IncrementalWitness<MerkleHashOrchard, 32>>> =
        vec![None; note_positions.len()];

    for block in compact_blocks {
        for action in &block.actions {
            let cmx_bytes = hex::decode(&action.cmx_hex)
                .map_err(|e| format!("invalid cmx hex at height {}: {}", block.height, e))?;

            let hash = if cmx_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&cmx_bytes);
                let cmx = ExtractedNoteCommitment::from_bytes(&arr);
                if bool::from(cmx.is_some()) {
                    MerkleHashOrchard::from_cmx(&cmx.unwrap())
                } else {
                    MerkleHashOrchard::empty_leaf()
                }
            } else {
                MerkleHashOrchard::empty_leaf()
            };

            tree.append(hash)
                .map_err(|_| "merkle tree full".to_string())?;

            if let Some(&idx) = position_map.get(&position_counter) {
                witnesses[idx] = IncrementalWitness::from_tree(tree.clone());
            }

            let target_pos = incrementalmerkletree::Position::from(position_counter);
            for w in witnesses.iter_mut().flatten() {
                if w.witnessed_position() < target_pos {
                    w.append(hash)
                        .map_err(|_| "witness tree full".to_string())?;
                }
            }

            position_counter += 1;
        }
    }

    let anchor = tree.root();
    let end_frontier_hex = hex::encode(serialize_tree(&tree));

    let mut entries = Vec::with_capacity(note_positions.len());
    for (i, w) in witnesses.into_iter().enumerate() {
        let witness = w.ok_or_else(|| {
            format!(
                "note at position {} not found in tree replay",
                note_positions[i],
            )
        })?;

        let imt_path = witness
            .path()
            .ok_or_else(|| format!("failed to compute path at position {}", note_positions[i]))?;
        let merkle_path = MerklePath::from(imt_path);
        let auth_path = merkle_path.auth_path();
        let position = u64::from(merkle_path.position());
        let path: Vec<PathElement> = auth_path
            .iter()
            .map(|h| PathElement {
                hash: hex::encode(h.to_bytes()),
            })
            .collect();

        let witness_hex = hex::encode(serialize_witness(&witness));
        entries.push(WitnessedNote {
            position,
            witness_hex,
            path,
        });
    }

    Ok(MerklePathsWithWitnesses {
        anchor_hex: hex::encode(Anchor::from(anchor).to_bytes()),
        end_frontier_hex,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn random_cmx(rng: &mut StdRng) -> String {
        // generate a hash that lands in the field (retry if not)
        loop {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            let cmx = ExtractedNoteCommitment::from_bytes(&b);
            if bool::from(cmx.is_some()) {
                return hex::encode(b);
            }
        }
    }

    fn make_blocks(rng: &mut StdRng, heights: &[u32], actions_per_block: usize) -> Vec<CompactBlockData> {
        heights
            .iter()
            .map(|&h| CompactBlockData {
                height: h,
                actions: (0..actions_per_block)
                    .map(|_| CompactAction {
                        cmx_hex: random_cmx(rng),
                    })
                    .collect(),
            })
            .collect()
    }

    #[test]
    fn tree_roundtrip() {
        let mut rng = StdRng::seed_from_u64(1);
        let blocks = make_blocks(&mut rng, &[100, 101, 102], 4);
        let empty = CommitmentTree::<MerkleHashOrchard, 32>::empty();
        let frontier = hex::encode(serialize_tree(&empty));

        let result = build_witnesses_and_paths_inner(&frontier, &blocks, &[0, 5, 11]).unwrap();

        // Round-tripping the end frontier must preserve size and root.
        let end_bytes = hex::decode(&result.end_frontier_hex).unwrap();
        let end_tree = deserialize_tree(&end_bytes).unwrap();
        assert_eq!(end_tree.size(), 3 * 4);
        assert_eq!(hex::encode(end_tree.root().to_bytes()), result.anchor_hex);
    }

    #[test]
    fn witness_path_matches_oneshot() {
        // build witnesses one-shot, then verify extracting a path from the
        // serialized witness produces the same path.
        let mut rng = StdRng::seed_from_u64(2);
        let blocks = make_blocks(&mut rng, &[1000, 1001, 1002, 1003], 3);
        let empty = CommitmentTree::<MerkleHashOrchard, 32>::empty();
        let frontier = hex::encode(serialize_tree(&empty));

        let positions = vec![2u64, 7u64];
        let full = build_witnesses_and_paths_inner(&frontier, &blocks, &positions).unwrap();

        for (pos_expected, entry) in positions.iter().zip(full.entries.iter()) {
            assert_eq!(entry.position, *pos_expected);
            let extracted = witness_extract_path_inner(&entry.witness_hex).unwrap();
            assert_eq!(extracted.position, *pos_expected);
            assert_eq!(extracted.root_hex, full.anchor_hex);
            assert_eq!(extracted.path.len(), entry.path.len());
            for (a, b) in extracted.path.iter().zip(entry.path.iter()) {
                assert_eq!(a.hash, b.hash);
            }
        }
    }

    #[test]
    fn incremental_matches_oneshot() {
        // Split the block range in half; advance witnesses incrementally
        // across the split and compare against one-shot.
        let mut rng = StdRng::seed_from_u64(3);
        let all_blocks = make_blocks(&mut rng, &[5000, 5001, 5002, 5003, 5004, 5005], 5);
        let empty = CommitmentTree::<MerkleHashOrchard, 32>::empty();
        let start_frontier = hex::encode(serialize_tree(&empty));

        let positions = vec![3u64, 8u64, 19u64];
        let oneshot = build_witnesses_and_paths_inner(&start_frontier, &all_blocks, &positions).unwrap();

        let (first_half, second_half) = all_blocks.split_at(3);

        // Step 1: seed witnesses in first half (positions 3 and 8 land there).
        let new_notes_first: Vec<NewNoteInput> = positions
            .iter()
            .filter(|&&p| p < (first_half.len() * 5) as u64)
            .map(|&p| NewNoteInput {
                id: format!("n{}", p),
                position: p,
            })
            .collect();

        let step1 = witness_sync_update_inner(&start_frontier, first_half, &[], &new_notes_first).unwrap();

        // Step 2: seed remaining witnesses (position 19) + advance existing ones
        // through second_half.
        let existing: Vec<ExistingWitnessInput> = step1
            .witnesses
            .iter()
            .map(|w| ExistingWitnessInput {
                id: w.id.clone(),
                witness_hex: w.witness_hex.clone(),
            })
            .collect();

        let already: Vec<u64> = step1.witnesses.iter().map(|w| w.position).collect();
        let new_notes_second: Vec<NewNoteInput> = positions
            .iter()
            .filter(|p| !already.contains(p))
            .map(|&p| NewNoteInput {
                id: format!("n{}", p),
                position: p,
            })
            .collect();

        let step2 = witness_sync_update_inner(
            &step1.end_frontier_hex,
            second_half,
            &existing,
            &new_notes_second,
        )
        .unwrap();

        assert_eq!(step2.anchor_hex, oneshot.anchor_hex);
        assert_eq!(step2.end_frontier_hex, oneshot.end_frontier_hex);

        // each witness path should match.
        for pos in &positions {
            let our = step2
                .witnesses
                .iter()
                .find(|w| w.position == *pos)
                .unwrap_or_else(|| panic!("witness for position {} missing", pos));
            let expected = oneshot
                .entries
                .iter()
                .find(|e| e.position == *pos)
                .unwrap();

            let extracted = witness_extract_path_inner(&our.witness_hex).unwrap();
            assert_eq!(extracted.position, *pos);
            assert_eq!(extracted.root_hex, oneshot.anchor_hex);
            assert_eq!(extracted.path.len(), expected.path.len());
            for (a, b) in extracted.path.iter().zip(expected.path.iter()) {
                assert_eq!(a.hash, b.hash, "path diverges at position {}", pos);
            }
        }
    }
}

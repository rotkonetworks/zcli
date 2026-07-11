//! Orchard tree root computation from zebrad's `final_state` frontier hex.
//!
//! `z_gettreestate` returns the orchard commitment tree as a hex-encoded
//! `Frontier` — the canonical Zcash representation. To compute the actual
//! orchard tree root (the "anchor" consumers trust), we deserialize that
//! frontier into a `CommitmentTree<MerkleHashOrchard, 32>` and call `.root()`.

use incrementalmerkletree::frontier::CommitmentTree;
use orchard::tree::MerkleHashOrchard;

/// Parse zebrad's hex-encoded orchard frontier and return the canonical
/// 32-byte tree root. For empty / pre-orchard heights, returns the empty
/// tree root.
pub fn parse_orchard_tree_root(final_state_hex: &str) -> [u8; 32] {
    if final_state_hex.is_empty() {
        return CommitmentTree::<MerkleHashOrchard, 32>::empty()
            .root()
            .to_bytes();
    }
    let bytes = match hex::decode(final_state_hex) {
        Ok(b) => b,
        Err(_) => return [0u8; 32],
    };
    match deserialize_tree(&bytes) {
        Ok(tree) => tree.root().to_bytes(),
        Err(_) => [0u8; 32],
    }
}

/// Deserialize zebrad's bincode-style frontier encoding.
///
/// Format (matches `bin/zcli/src/witness.rs:deserialize_tree`):
///   [Option<Hash>] left
///   [Option<Hash>] right
///   [CompactSize]  parent_count
///   [Option<Hash>] * parent_count
///
/// Option encoding: 0x00 = None, 0x01 = Some followed by 32 bytes.
/// CompactSize: 0x00-0xfc = 1 byte, 0xfd = u16 LE, 0xfe = u32 LE, 0xff = u64 LE.
fn deserialize_tree(data: &[u8]) -> Result<CommitmentTree<MerkleHashOrchard, 32>, &'static str> {
    if data.is_empty() {
        return Ok(CommitmentTree::empty());
    }

    let mut pos = 0;
    let left = read_option(data, &mut pos)?;
    let right = read_option(data, &mut pos)?;

    if pos >= data.len() {
        return CommitmentTree::from_parts(left, right, vec![])
            .map_err(|_| "invalid frontier structure (no parents)");
    }
    let parent_count = read_compact_size(data, &mut pos)?;

    let mut parents = Vec::with_capacity(parent_count as usize);
    for _ in 0..parent_count {
        parents.push(read_option(data, &mut pos)?);
    }

    CommitmentTree::from_parts(left, right, parents)
        .map_err(|_| "invalid frontier structure")
}

fn read_option(data: &[u8], pos: &mut usize) -> Result<Option<MerkleHashOrchard>, &'static str> {
    if *pos >= data.len() {
        return Err("frontier truncated reading option tag");
    }
    if data[*pos] == 0x01 {
        if *pos + 33 > data.len() {
            return Err("frontier truncated reading hash");
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data[*pos + 1..*pos + 33]);
        *pos += 33;
        Option::from(MerkleHashOrchard::from_bytes(&bytes))
            .map(Some)
            .ok_or("invalid frontier hash")
    } else {
        *pos += 1;
        Ok(None)
    }
}

fn read_compact_size(data: &[u8], pos: &mut usize) -> Result<u64, &'static str> {
    if *pos >= data.len() {
        return Err("compact size: truncated");
    }
    let first = data[*pos];
    *pos += 1;
    match first {
        0x00..=0xfc => Ok(first as u64),
        0xfd => {
            if *pos + 2 > data.len() {
                return Err("compact size: truncated u16");
            }
            let v = u16::from_le_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Ok(v as u64)
        }
        0xfe => {
            if *pos + 4 > data.len() {
                return Err("compact size: truncated u32");
            }
            let v = u32::from_le_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
            ]);
            *pos += 4;
            Ok(v as u64)
        }
        0xff => {
            if *pos + 8 > data.len() {
                return Err("compact size: truncated u64");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_frontier_returns_empty_tree_root() {
        let root = parse_orchard_tree_root("");
        let expected = CommitmentTree::<MerkleHashOrchard, 32>::empty()
            .root()
            .to_bytes();
        assert_eq!(root, expected);
    }

    #[test]
    fn invalid_hex_returns_zero_root() {
        assert_eq!(parse_orchard_tree_root("not-hex"), [0u8; 32]);
    }
}

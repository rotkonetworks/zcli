//! Shielded-pool commitment tree root computation from zebrad's
//! `final_state` frontier hex.
//!
//! `z_gettreestate` returns each pool's commitment tree as a hex-encoded
//! `Frontier` - the canonical Zcash representation. To compute the actual
//! tree root (the "anchor" consumers trust), we deserialize that frontier
//! into a `CommitmentTree<H, 32>` and call `.root()`.
//!
//! The byte-level frontier format is identical across pools (orchard today,
//! ironwood/NU6.3 as a second tree once its hash type is available), so the
//! parsing below is generic over the node hash type via [`FrontierHash`].

use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::Hashable;
use orchard::tree::MerkleHashOrchard;

/// Shielded pools whose commitment tree state zidecar may be asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldedPool {
    Orchard,
    /// NU6.3 pool. Same frontier wire format as orchard, but a second,
    /// independent tree with its own hash type. Not yet supported.
    Ironwood,
}

/// Node hash type readable from zebrad's frontier encoding. Every pool uses
/// the same frontier byte format; only the 32-byte node hash type (and the
/// empty-subtree constants baked into `root()`) differs per pool.
pub trait FrontierHash: Hashable + Clone {
    /// Parse a node hash from its canonical 32-byte encoding.
    fn from_frontier_bytes(bytes: &[u8; 32]) -> Option<Self>;
    /// Canonical 32-byte encoding of a node hash.
    fn to_frontier_bytes(&self) -> [u8; 32];
}

impl FrontierHash for MerkleHashOrchard {
    fn from_frontier_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Option::from(MerkleHashOrchard::from_bytes(bytes))
    }
    fn to_frontier_bytes(&self) -> [u8; 32] {
        self.to_bytes()
    }
}

/// Parse zebrad's hex-encoded orchard frontier and return the canonical
/// 32-byte tree root. For empty / pre-orchard heights, returns the empty
/// tree root.
pub fn parse_orchard_tree_root(final_state_hex: &str) -> [u8; 32] {
    parse_frontier_tree_root::<MerkleHashOrchard>(final_state_hex)
}

/// Pool-dispatching variant of the frontier parse. The orchard arm is the
/// exact code path `parse_orchard_tree_root` uses; the ironwood arm is a
/// refusal until the ironwood node hash type is available (the pool's
/// personalization / empty-leaf constants are not published in a crate we
/// can depend on yet), so callers surface a clear error instead of garbage.
pub fn parse_pool_tree_root(
    pool: ShieldedPool,
    final_state_hex: &str,
) -> Result<[u8; 32], &'static str> {
    match pool {
        ShieldedPool::Orchard => Ok(parse_orchard_tree_root(final_state_hex)),
        // When ironwood's hash type lands, this becomes
        // `Ok(parse_frontier_tree_root::<MerkleHashIronwood>(final_state_hex))`
        // and the refusal disappears.
        ShieldedPool::Ironwood => Err("ironwood pool not yet supported"),
    }
}

/// Parse a hex-encoded frontier for any pool hash type and return the
/// canonical 32-byte tree root. Empty input yields the empty tree root;
/// malformed input yields all-zeroes (preserving the long-standing orchard
/// behavior callers rely on).
pub fn parse_frontier_tree_root<H: FrontierHash>(final_state_hex: &str) -> [u8; 32] {
    if final_state_hex.is_empty() {
        return CommitmentTree::<H, 32>::empty().root().to_frontier_bytes();
    }
    let bytes = match hex::decode(final_state_hex) {
        Ok(b) => b,
        Err(_) => return [0u8; 32],
    };
    match deserialize_tree::<H>(&bytes) {
        Ok(tree) => tree.root().to_frontier_bytes(),
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
fn deserialize_tree<H: FrontierHash>(data: &[u8]) -> Result<CommitmentTree<H, 32>, &'static str> {
    if data.is_empty() {
        return Ok(CommitmentTree::empty());
    }

    let mut pos = 0;
    let left = read_option::<H>(data, &mut pos)?;
    let right = read_option::<H>(data, &mut pos)?;

    if pos >= data.len() {
        return CommitmentTree::from_parts(left, right, vec![])
            .map_err(|_| "invalid frontier structure (no parents)");
    }
    let parent_count = read_compact_size(data, &mut pos)?;

    let mut parents = Vec::with_capacity(parent_count as usize);
    for _ in 0..parent_count {
        parents.push(read_option::<H>(data, &mut pos)?);
    }

    CommitmentTree::from_parts(left, right, parents).map_err(|_| "invalid frontier structure")
}

fn read_option<H: FrontierHash>(data: &[u8], pos: &mut usize) -> Result<Option<H>, &'static str> {
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
        H::from_frontier_bytes(&bytes)
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
            let v =
                u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
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

    /// The pool-generic entry point must be byte-identical to the orchard
    /// wrapper for the orchard arm.
    #[test]
    fn pool_dispatch_orchard_matches_orchard_parser() {
        for hex in ["", "not-hex", "0000fd"] {
            assert_eq!(
                parse_pool_tree_root(ShieldedPool::Orchard, hex).unwrap(),
                parse_orchard_tree_root(hex)
            );
        }
    }

    /// Ironwood refusal path: a clear error, never a garbage root.
    #[test]
    fn pool_dispatch_ironwood_is_refused() {
        assert_eq!(
            parse_pool_tree_root(ShieldedPool::Ironwood, ""),
            Err("ironwood pool not yet supported")
        );
    }

    /// The generic parser instantiated with the orchard hash reproduces the
    /// legacy function on a structurally valid one-leaf frontier: left leaf
    /// present (0x01 tag + 32 bytes of a valid Pallas base encoding, zero is
    /// valid), right absent, zero parents.
    #[test]
    fn generic_parse_matches_legacy_on_valid_frontier() {
        let mut frontier = vec![0x01u8];
        frontier.extend_from_slice(&[0u8; 32]); // left leaf = 0 (valid base)
        frontier.push(0x00); // right = None
        frontier.push(0x00); // parent_count = 0
        let hex = hex::encode(&frontier);
        let via_generic = parse_frontier_tree_root::<MerkleHashOrchard>(&hex);
        let via_legacy = parse_orchard_tree_root(&hex);
        assert_eq!(via_generic, via_legacy);
        // and it is a real root, not the malformed-input zero sentinel
        assert_ne!(via_generic, [0u8; 32]);
    }
}

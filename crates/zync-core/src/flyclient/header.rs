//! Zcash block header parsing and proof-of-work checks.
//!
//! A mainnet header is 1487 bytes: 140 bytes of fields, a CompactSize 1344,
//! and the Equihash (200, 9) solution. The block hash is SHA-256d over all of
//! it; the Equihash input is the first 108 bytes, with the 32-byte nonce
//! passed separately.

use primitive_types::U256;
use sha2::{Digest, Sha256};

use super::epochs::Network;
use super::{FlyError, FlyResult};

pub const HEADER_LEN: usize = 1487;
pub const SOLUTION_LEN: usize = 1344;
const EQUIHASH_N: u32 = 200;
const EQUIHASH_K: u32 = 9;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    /// Previous block hash, internal byte order.
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    /// `hashLightClientRoot` (Heartwood, Canopy) or `hashBlockCommitments` (NU5 on).
    pub commitments: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: [u8; 32],
    /// SHA-256d of the whole header, internal byte order.
    pub hash: [u8; 32],
}

fn arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    a
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    arr32(&Sha256::digest(Sha256::digest(data)))
}

impl BlockHeader {
    /// Parse a serialized header. Only the canonical Equihash (200, 9) layout
    /// is accepted, so the raw bytes are exactly [`HEADER_LEN`] long.
    pub fn parse(raw: &[u8]) -> FlyResult<Self> {
        if raw.len() != HEADER_LEN {
            return Err(FlyError::Header("header is not 1487 bytes"));
        }
        // CompactSize(1344) = 0xfd 0x40 0x05
        if raw[140..143] != [0xfd, 0x40, 0x05] {
            return Err(FlyError::Header("solution length is not 1344"));
        }
        Ok(BlockHeader {
            version: le32(&raw[0..4]),
            prev_hash: arr32(&raw[4..36]),
            merkle_root: arr32(&raw[36..68]),
            commitments: arr32(&raw[68..100]),
            time: le32(&raw[100..104]),
            bits: le32(&raw[104..108]),
            nonce: arr32(&raw[108..140]),
            hash: sha256d(raw),
        })
    }

    /// Parse and check proof of work: a valid Equihash solution, a well-formed
    /// target no easier than the network's limit, and a hash at or below it.
    pub fn parse_and_verify(raw: &[u8], height: u32, network: Network) -> FlyResult<Self> {
        let header = Self::parse(raw)?;
        equihash::is_valid_solution(
            EQUIHASH_N,
            EQUIHASH_K,
            &raw[..108],
            &raw[108..140],
            &raw[143..],
        )
        .map_err(|_| FlyError::Equihash(height))?;
        let target = compact_to_target(header.bits).ok_or(FlyError::Target(height))?;
        if target > pow_limit(network) {
            return Err(FlyError::Target(height));
        }
        // the hash is a little-endian 256-bit integer
        if U256::from_little_endian(&header.hash) > target {
            return Err(FlyError::Target(height));
        }
        Ok(header)
    }
}

/// Decode a compact `nBits` target. Returns `None` for the encodings zcashd
/// treats as invalid: negative, zero, or overflowing 256 bits.
pub fn compact_to_target(bits: u32) -> Option<U256> {
    // arith_uint256::SetCompact
    let size = bits >> 24;
    let word = bits & 0x007f_ffff;
    let negative = word != 0 && bits & 0x0080_0000 != 0;
    let overflow =
        word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
    if negative || overflow {
        return None;
    }
    let target = if size <= 3 {
        U256::from(word >> (8 * (3 - size)))
    } else {
        U256::from(word) << (8 * (size - 3) as usize)
    };
    if target.is_zero() {
        return None;
    }
    Some(target)
}

/// Work represented by a target: 2^256 / (target + 1), computed as
/// `(!target / (target + 1)) + 1` so it stays inside 256 bits.
pub fn target_work(target: U256) -> U256 {
    match target.checked_add(U256::one()) {
        Some(t1) => (!target / t1) + U256::one(),
        None => U256::one(), // target = 2^256 - 1
    }
}

/// Work for a compact `nBits`, as the history tree records it.
pub fn bits_work(bits: u32) -> Option<U256> {
    compact_to_target(bits).map(target_work)
}

/// zcashd `consensus.powLimit`.
pub fn pow_limit(network: Network) -> U256 {
    let mut be = [0xffu8; 32];
    match network {
        // 0007ffff...ff
        Network::Mainnet => {
            be[0] = 0x00;
            be[1] = 0x07;
        }
        // 07ffff...ff
        Network::Testnet => {
            be[0] = 0x07;
        }
    }
    U256::from_big_endian(&be)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_round_trip_examples() {
        // 0x1d00ffff: Bitcoin's genesis target
        let t = compact_to_target(0x1d00_ffff).unwrap();
        assert_eq!(t, U256::from(0xffffu64) << (8 * (0x1d - 3)));
        assert!(compact_to_target(0x0180_0000).is_none()); // negative
        assert!(compact_to_target(0).is_none());
        assert!(compact_to_target(0xff12_3456).is_none()); // overflow
    }

    #[test]
    fn work_of_max_target_is_one() {
        assert_eq!(target_work(U256::MAX), U256::one());
        assert_eq!(target_work(U256::MAX >> 1), U256::from(2));
    }
}

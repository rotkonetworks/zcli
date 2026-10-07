//! Floors that make a FlyClient proof safe to take from a single server.
//!
//! [`verify_flyclient`] sums whatever work the proof's headers claim and only
//! checks each header's target against the network's proof-of-work limit. A
//! chain of pow-limit blocks (Equihash solutions at the easiest target, about
//! 2^27.8 times cheaper per block than mainnet today) passes it, so a client
//! that asks one server cannot tell a forged chain from the real one; zcli
//! compares several servers instead. A wallet that talks to one server needs
//! the proof to carry real work on its own. Against a compiled [`Checkpoint`]:
//!
//! - **work floor:** the chain's work since the anchor is at least the
//!   checkpoint's, plus a quarter of the checkpoint's recent work per block
//!   for every block past it;
//! - **difficulty floor:** every checked header past the checkpoint (the tip
//!   and every opened leaf) carries at least a quarter of that per-block
//!   work, i.e. its target is at most 4x easier. Older headers are left to
//!   the work floor: mainnet difficulty roughly doubled between NU6.3
//!   activation and the first checkpoint, and a raised checkpoint must not
//!   refuse the real chain's older blocks;
//! - **freshness:** the tip's timestamp is at most 90 minutes behind (or two
//!   hours ahead of) the caller's clock;
//! - **no rollback:** the tip is at least the height the caller has already
//!   seen.
//!
//! Forging past these costs the real chain's work from the anchor to the
//! checkpoint, then at least a quarter of mainnet's per-block work for every
//! block after it.
//!
//! The floors trade liveness for safety: if mainnet hashrate stayed more than
//! 4x below the checkpoint's, honest proofs would be refused until the
//! checkpoint is lowered. Raise the checkpoint each release (see
//! [`Checkpoint::mainnet`]).

use primitive_types::U256;

use super::epochs::Network;
use super::header::bits_work;
use super::proof::FlyClientProof;
use super::sampling::FlyParams;
use super::verify::{verify_flyclient, Anchor, VerifiedChain};
use super::{FlyError, FlyResult};

/// Blocks past the checkpoint must carry at least 1/FLOOR_DIVISOR of its
/// per-block work, each (difficulty floor) and on average (work floor).
pub const FLOOR_DIVISOR: u64 = 4;
/// The tip may be this much older than the caller's clock.
pub const MAX_TIP_AGE_SECS: u64 = 90 * 60;
/// The tip may be this much newer than the caller's clock (consensus allows
/// block times up to two hours ahead).
pub const MAX_TIP_LEAD_SECS: u64 = 2 * 60 * 60;

/// A block of the real chain, compiled into the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub anchor: Anchor,
    pub height: u32,
    /// Work of blocks `anchor.height..=height`, as [`VerifiedChain::total_work`]
    /// counts it.
    pub work: U256,
    /// Average work per block over the blocks just before `height`: the
    /// difficulty the floors measure against. An average, because a single
    /// block's nBits moves by close to 2x from block to block.
    pub block_work: U256,
}

impl Checkpoint {
    /// Mainnet, anchored at NU6.3 activation (3,428,143). Height 3,508,014 is
    /// the last block of the first four peaks (2^16 + 2^13 + 2^12 + 2^11 =
    /// 79,872 leaves) of the NU6.3 history tree; `work` is the sum of those
    /// peaks' work and `block_work` the fourth peak's work over its 2,048
    /// blocks. Read from two live proofs that passed [`verify_flyclient`]
    /// (tips 3,509,023 and 3,509,049, 2026-10-07), so every value is
    /// committed to by proof-of-work headers.
    ///
    /// To raise it each release: save a `FlyClientProofResponse` from any
    /// zidecar as protobuf bytes and run `FLY_PROOF=/abs/proof.pb
    /// FLY_LAMBDA=40 FLY_TAIL=16 cargo test -p zync-flyclient --release
    /// --test live -- --ignored derive_checkpoint --nocapture`. It verifies
    /// the proof, prints the deepest peak boundary at least 1,000 blocks
    /// below the tip with its `work` and `block_work`, and how far the opened
    /// headers' work spreads around `block_work`.
    pub fn mainnet() -> Self {
        Checkpoint {
            anchor: Anchor::nu6_3_mainnet(),
            height: 3_508_014,
            work: U256::from(0x022d_0efd_dc84_daa5u64),
            block_work: U256::from(BLOCK_WORK_MAINNET),
        }
    }

    /// The compiled checkpoint for `network`, if there is one.
    pub fn compiled(network: Network) -> Option<Self> {
        match network {
            Network::Mainnet => Some(Self::mainnet()),
            // testnet's minimum-difficulty rule allows pow-limit blocks
            Network::Testnet => None,
        }
    }

    fn floor(&self) -> U256 {
        self.block_work / U256::from(FLOOR_DIVISOR)
    }
}

/// 2.27e12; the opened headers past the checkpoint carried 0.72x to 1.36x of it.
const BLOCK_WORK_MAINNET: u64 = 0x0211_a388_7f88;

/// Check a verified chain against a checkpoint, the caller's clock and the
/// lowest tip it will accept. `chain` must come from a proof anchored at
/// `checkpoint.anchor`.
pub fn check_floors(
    chain: &VerifiedChain,
    checkpoint: &Checkpoint,
    now_secs: u64,
    min_height: u32,
) -> FlyResult<()> {
    if chain.tip_height < min_height {
        return Err(FlyError::Stale("tip is below a height already seen"));
    }
    let tip_time = u64::from(chain.tip_time);
    if tip_time.saturating_add(MAX_TIP_AGE_SECS) < now_secs {
        return Err(FlyError::Stale("tip is older than 90 minutes"));
    }
    if tip_time > now_secs.saturating_add(MAX_TIP_LEAD_SECS) {
        return Err(FlyError::Stale("tip is more than two hours ahead"));
    }
    if chain.tip_height < checkpoint.height {
        return Err(FlyError::Floor("tip is below the checkpoint"));
    }
    let floor = checkpoint.floor();
    let too_easy = chain
        .epochs
        .iter()
        .flat_map(|e| &e.checked_bits)
        .filter(|(height, _)| *height > checkpoint.height)
        .any(|(_, bits)| bits_work(*bits).is_none_or(|w| w < floor));
    if too_easy {
        return Err(FlyError::Floor(
            "a block past the checkpoint is far easier than it",
        ));
    }
    let past = U256::from(chain.tip_height - checkpoint.height);
    let required = floor.saturating_mul(past).saturating_add(checkpoint.work);
    if chain.total_work < required {
        return Err(FlyError::Floor("chain work is below the floor"));
    }
    Ok(())
}

/// Verify a proof the way a single-server wallet must: [`verify_flyclient`]
/// from the checkpoint's anchor, then [`check_floors`].
pub fn verify_wallet(
    proof: &FlyClientProof,
    network: Network,
    params: &FlyParams,
    checkpoint: &Checkpoint,
    now_secs: u64,
    min_height: u32,
) -> FlyResult<VerifiedChain> {
    let chain = verify_flyclient(proof, network, params, &checkpoint.anchor)?;
    check_floors(&chain, checkpoint, now_secs, min_height)?;
    Ok(chain)
}

//! Which blocks a FlyClient proof must open.
//!
//! FlyClient samples blocks by cumulative work with density
//! `g(x) = 1 / ((x - 1) ln δ)` on `[0, 1 - δ]`, i.e. `x = 1 - δ^u` for uniform
//! `u`, so samples crowd toward the tip where a forking adversary must
//! diverge. The last `tail` blocks are opened outright, and `δ = 2^-k` is the
//! smallest power of two at or below `tail / n`.
//!
//! Everything here is integer arithmetic. Prover and verifier must arrive at
//! the same points bit for bit, and floating-point `powf` is not guaranteed
//! to agree between a native server and a wasm client.

use std::collections::BTreeSet;

use blake2b_simd::Params;
use primitive_types::{U256, U512};

/// `2^(-2^-j)` for `j = 1..=32`, as Q64 fractions (floor of value × 2^64).
const HALF_POWERS: [u64; 32] = [
    0xb504f333f9de6484,
    0xd744fccad69d6af4,
    0xeac0c6e7dd24392e,
    0xf5257d152486cc2c,
    0xfa83b2db722a033a,
    0xfd3e0c0cf486c174,
    0xfe9e115c7b8f884b,
    0xff4ecb59511ec8a5,
    0xffa756521c8daed1,
    0xffd3a751c0f7e10b,
    0xffe9d2b2f7db2755,
    0xfff4e91bff1b8c3d,
    0xfffa747ea0040664,
    0xfffd3a3b7814eb53,
    0xfffe9d1cc60ddab1,
    0xffff4e8e25879bfa,
    0xffffa7470363f451,
    0xffffd3a37dda0313,
    0xffffe9d1bdf703ae,
    0xfffff4e8debe025e,
    0xfffffa746f4fa150,
    0xfffffd3a37a3f8b0,
    0xfffffe9d1bd1065a,
    0xffffff4e8de845ad,
    0xffffffa746f41376,
    0xffffffd3a37a05e3,
    0xffffffe9d1bd01fb,
    0xfffffff4e8de80c0,
    0xfffffffa746f4050,
    0xfffffffd3a37a024,
    0xfffffffe9d1bd011,
    0xffffffff4e8de808,
];

/// FlyClient parameters. Both sides must use the same values; they are part
/// of the protocol, not a tuning knob for one side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlyParams {
    /// Security parameter: an adversary with less than half the honest work
    /// passes with probability at most about `2^-lambda`.
    pub lambda: u32,
    /// Blocks at the end of each epoch opened without sampling.
    pub tail: u32,
}

impl Default for FlyParams {
    fn default() -> Self {
        FlyParams { lambda: 40, tail: 16 }
    }
}

/// `k` such that `δ = 2^-k ≤ tail / n`, and the number of samples `m`.
///
/// With the adversary bounded at `c = 1/2` of honest work, FlyClient needs
/// `m ≥ λ / log2(1 / (1 - 1/k))` samples. Since `log2(k / (k - 1)) ≥ 1/(k ln 2)`,
/// `m = ⌈λ · k · ln 2⌉` is enough and needs no logarithms; ln 2 is rounded up
/// to 0.694.
pub fn sample_count(params: &FlyParams, n_leaves: u64) -> (u32, u32) {
    let tail = params.tail.max(1) as u64;
    if n_leaves <= tail {
        return (0, 0);
    }
    let mut k = 0u32;
    while (tail << k) < n_leaves {
        k += 1;
    }
    let m = (params.lambda as u64 * k as u64 * 694).div_ceil(1000) as u32;
    (k, m)
}

/// Fiat-Shamir seed. Everything the server could vary is in it: the epoch,
/// its size, the committed root and the committing block. Changing any of
/// these means mining a new block.
pub fn seed(
    branch_id: u32,
    activation: u32,
    n_leaves: u64,
    root_hash: &[u8; 32],
    commit_hash: &[u8; 32],
) -> [u8; 32] {
    let h = Params::new()
        .hash_length(32)
        .personal(b"ZyncFlyClient_v1")
        .to_state()
        .update(&branch_id.to_le_bytes())
        .update(&activation.to_le_bytes())
        .update(&n_leaves.to_le_bytes())
        .update(root_hash)
        .update(commit_hash)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// `2^-(k·u)` as a Q64 fraction, for `u` a Q64 fraction in `[0, 1)`.
fn pow2_neg(k: u32, u: u64) -> u128 {
    let t = k as u128 * u as u128; // Q64
    let whole = (t >> 64) as u32;
    let frac = t as u64;
    let mut m: u128 = 1u128 << 64;
    for (j, c) in HALF_POWERS.iter().enumerate() {
        if frac & (1u64 << (63 - j)) != 0 {
            m = (m * *c as u128) >> 64;
        }
    }
    if whole >= 128 {
        0
    } else {
        m >> whole
    }
}

/// Sample points as work offsets in `[0, total_work)`.
pub fn sample_points(seed: &[u8; 32], k: u32, m: u32, total_work: U256) -> Vec<U256> {
    if total_work.is_zero() {
        return Vec::new();
    }
    (0..m)
        .map(|i| {
            let h = Params::new()
                .hash_length(32)
                .personal(b"ZyncFlySample_v1")
                .to_state()
                .update(seed)
                .update(&i.to_le_bytes())
                .finalize();
            let mut u = [0u8; 8];
            u.copy_from_slice(&h.as_bytes()[..8]);
            let r = pow2_neg(k, u64::from_le_bytes(u)); // ∈ (δ, 1]
            // distance from the tip = total_work · r
            let back: U512 = total_work.full_mul(U256::from(r)) >> 64;
            let back = U256::try_from(back).unwrap_or(total_work);
            total_work
                .saturating_sub(back)
                .min(total_work - U256::one())
        })
        .collect()
}

/// Leaves every proof opens regardless of sampling: the first (it links to
/// the previous epoch or the anchor) and the last `tail` (the last one links
/// to the committing header).
pub fn required_leaves(params: &FlyParams, n_leaves: u64) -> BTreeSet<u64> {
    let mut set = BTreeSet::new();
    if n_leaves == 0 {
        return set;
    }
    set.insert(0);
    let tail = (params.tail.max(1) as u64).min(n_leaves);
    set.extend(n_leaves - tail..n_leaves);
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pow2_neg_matches_float_closely() {
        for &(k, u) in &[(1u32, 0u64), (10, 1 << 63), (13, 0x1234_5678_9abc_def0), (20, u64::MAX)] {
            let got = pow2_neg(k, u) as f64 / 2f64.powi(64);
            let want = 2f64.powf(-(k as f64) * (u as f64 / 2f64.powi(64)));
            assert!((got - want).abs() < 1e-9, "k={k} u={u:x}: {got} vs {want}");
        }
        assert_eq!(pow2_neg(5, 0), 1u128 << 64);
    }

    #[test]
    fn points_stay_in_range_and_lean_to_the_tip() {
        let w = U256::from(1_000_000u64);
        let pts = sample_points(&[7u8; 32], 12, 400, w);
        assert_eq!(pts.len(), 400);
        assert!(pts.iter().all(|p| *p < w));
        let late = pts.iter().filter(|p| **p >= w / 2).count();
        assert!(late > 300, "only {late} of 400 in the second half");
    }

    #[test]
    fn sample_count_grows_with_log_n() {
        let p = FlyParams::default();
        assert_eq!(sample_count(&p, 10), (0, 0));
        let (k1, m1) = sample_count(&p, 100_000);
        let (k2, m2) = sample_count(&p, 1_000_000);
        assert!(k2 > k1 && m2 > m1);
        assert_eq!(k1, 13);
    }
}

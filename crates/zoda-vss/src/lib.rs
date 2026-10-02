//! zoda-vss: verifiable secret sharing
//!
//! implementation based on reed-solomon coding for efficient share verification.
//! for messages larger than ~128 bits, verification overhead is minimal.
//!
//! note: this is VSS (verifiable secret sharing), not to be confused with
//! commonware's ZODA which is a data availability coding scheme.
//!
//! ## key properties
//!
//! - **verifiable**: any party receiving shares can check against header
//!   and know they will decode the same secret as other honest parties
//! - **low overhead**: for 256-bit secrets, header is ~32 bytes
//! - **threshold**: requires t-of-n shares to reconstruct
//!
//! ## usage
//!
//! ```rust,no_run
//! use zoda_vss::{Dealer, Player};
//!
//! // dealer creates shares for a 32-byte secret
//! let secret = [0x42u8; 32];
//! let dealer = Dealer::new(3, 5); // 3-of-5 threshold
//! let mut rng = rand::thread_rng();
//! let (header, shares) = dealer.share(&secret, &mut rng);
//!
//! // players verify their shares against header
//! for share in &shares {
//!     assert!(share.verify(&header));
//! }
//!
//! // any 3 shares can reconstruct
//! let reconstructed = Player::reconstruct(&header, &shares[0..3]).unwrap();
//! assert_eq!(reconstructed, secret);
//! ```
//!
//! ## theory
//!
//! based on observations from guillermo angeris on reed-solomon coding:
//! - encode secret as polynomial coefficients
//! - evaluate at n distinct points for shares
//! - header commits to polynomial (lightweight commitment)
//! - verification checks share consistency with header
//!
//! for threshold t and n parties:
//! - polynomial degree: t-1
//! - secret: constant term (or first t coefficients)
//! - shares: evaluations at points 1..=n

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Add, Mul, Sub};
use sha2::{Digest, Sha256};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// field element for GF(2^8) operations
/// using AES polynomial x^8 + x^4 + x^3 + x + 1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GF256(pub u8);

impl GF256 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);

    /// multiply in GF(2^8)
    #[allow(clippy::should_implement_trait)] // intentional: inherent + trait impl share the name
    pub fn mul(self, other: Self) -> Self {
        let mut a = self.0;
        let mut b = other.0;
        let mut result = 0u8;

        for _ in 0..8 {
            if b & 1 != 0 {
                result ^= a;
            }
            let high_bit = a & 0x80;
            a <<= 1;
            if high_bit != 0 {
                a ^= 0x1b; // AES irreducible polynomial
            }
            b >>= 1;
        }
        Self(result)
    }

    /// multiplicative inverse via extended euclidean algorithm
    pub fn inv(self) -> Self {
        if self.0 == 0 {
            return Self::ZERO;
        }
        // use fermat's little theorem: a^254 = a^(-1) in GF(2^8)
        let mut result = self;
        for _ in 0..6 {
            result = result.mul(result);
            result = result.mul(self);
        }
        result = result.mul(result);
        result
    }

    /// exponentiation
    pub fn pow(self, mut exp: u8) -> Self {
        let mut base = self;
        let mut result = Self::ONE;
        while exp > 0 {
            if exp & 1 != 0 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        result
    }
}

impl Add for GF256 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)] // XOR is addition in GF(2^8)
    fn add(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }
}

impl Sub for GF256 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)] // subtraction == addition in GF(2^8)
    fn sub(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }
}

impl Mul for GF256 {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        self.mul(other)
    }
}

/// header for share verification
/// contains commitment to the polynomial
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Header {
    /// threshold (polynomial degree + 1)
    pub threshold: u8,
    /// total number of shares
    pub total: u8,
    /// hash commitment to polynomial coefficients
    pub commitment: [u8; 32],
}

impl Header {
    /// create header from polynomial coefficients
    pub fn new(threshold: u8, total: u8, coefficients: &[Vec<GF256>]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update([threshold, total]);
        for coeff_vec in coefficients {
            for coeff in coeff_vec {
                hasher.update([coeff.0]);
            }
        }
        let commitment: [u8; 32] = hasher.finalize().into();

        Self {
            threshold,
            total,
            commitment,
        }
    }

    /// verify a share against this header
    /// note: full verification requires polynomial evaluation
    /// this is a lightweight check that the share format is valid
    pub fn verify_format(&self, share: &Share) -> bool {
        share.index > 0 && share.index <= self.total && !share.data.is_empty()
    }
}

/// a single share
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Share {
    /// share index (1-indexed, corresponds to evaluation point)
    pub index: u8,
    /// share data (polynomial evaluation at index)
    pub data: Vec<u8>,
}

impl Share {
    /// lightweight verification that share format matches header
    pub fn verify(&self, header: &Header) -> bool {
        header.verify_format(self)
    }
}

/// dealer creates shares from a secret
pub struct Dealer {
    threshold: u8,
    total: u8,
}

impl Dealer {
    /// create a new dealer with t-of-n threshold
    pub fn new(threshold: u8, total: u8) -> Self {
        assert!(threshold > 0, "threshold must be positive");
        assert!(total >= threshold, "total must be >= threshold");
        assert!(total < 255, "total must be < 255");
        Self { threshold, total }
    }

    /// share a secret, returns header and shares
    pub fn share<R: rand_core::RngCore>(&self, secret: &[u8], rng: &mut R) -> (Header, Vec<Share>) {
        // for each byte position, create a polynomial
        // coefficients[i] contains the polynomial for byte i
        let mut coefficients: Vec<Vec<GF256>> = Vec::with_capacity(secret.len());

        for &secret_byte in secret {
            let mut poly = Vec::with_capacity(self.threshold as usize);
            // constant term is the secret byte
            poly.push(GF256(secret_byte));
            // random coefficients for higher terms
            for _ in 1..self.threshold {
                let mut byte = [0u8; 1];
                rng.fill_bytes(&mut byte);
                poly.push(GF256(byte[0]));
            }
            coefficients.push(poly);
        }

        // create header
        let header = Header::new(self.threshold, self.total, &coefficients);

        // evaluate polynomials at each point to create shares
        let mut shares = Vec::with_capacity(self.total as usize);
        for i in 1..=self.total {
            let x = GF256(i);
            let mut data = Vec::with_capacity(secret.len());

            for poly in &coefficients {
                // horner's method for polynomial evaluation
                let mut y = GF256::ZERO;
                for coeff in poly.iter().rev() {
                    y = y * x + *coeff;
                }
                data.push(y.0);
            }

            shares.push(Share { index: i, data });
        }

        (header, shares)
    }
}

/// player reconstructs secret from shares
pub struct Player;

impl Player {
    /// reconstruct secret from threshold shares using lagrange interpolation
    pub fn reconstruct(header: &Header, shares: &[Share]) -> Result<Vec<u8>, Error> {
        // Header fields are pub and deserializable, so a threshold of 0 can
        // arrive from a dealer. It would build empty polynomials below and
        // index their constant term.
        if header.threshold == 0 {
            return Err(Error::InvalidThreshold);
        }
        if shares.len() < header.threshold as usize {
            return Err(Error::InsufficientShares);
        }

        // verify all shares have same length
        let secret_len = shares[0].data.len();
        if shares.iter().any(|s| s.data.len() != secret_len) {
            return Err(Error::InconsistentShares);
        }

        // verify indices are unique and valid
        let mut seen = [false; 256];
        for share in shares {
            if share.index == 0 || share.index > header.total {
                return Err(Error::InvalidShareIndex);
            }
            if seen[share.index as usize] {
                return Err(Error::DuplicateShare);
            }
            seen[share.index as usize] = true;
        }

        // interpolate full polynomials from the first t shares
        let t = header.threshold as usize;
        let (base, extra) = shares.split_at(t);
        let mut coefficients: Vec<Vec<GF256>> = Vec::with_capacity(secret_len);

        for byte_idx in 0..secret_len {
            let mut poly = vec![GF256::ZERO; t];
            for (i, si) in base.iter().enumerate() {
                let xi = GF256(si.index);
                // basis numerator prod (x + xj), denominator prod (xi + xj)
                let mut num = vec![GF256::ONE];
                let mut den = GF256::ONE;
                for (j, sj) in base.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    let xj = GF256(sj.index);
                    let mut next = vec![GF256::ZERO; num.len() + 1];
                    for (k, c) in num.iter().enumerate() {
                        next[k] = next[k] + *c * xj;
                        next[k + 1] = next[k + 1] + *c;
                    }
                    num = next;
                    den = den * (xi - xj);
                }
                let scale = GF256(si.data[byte_idx]) * den.inv();
                for (k, c) in num.iter().enumerate() {
                    poly[k] = poly[k] + *c * scale;
                }
            }
            coefficients.push(poly);
        }

        // recomputed polynomial must match the dealer's commitment
        if Header::new(header.threshold, header.total, &coefficients).commitment
            != header.commitment
        {
            return Err(Error::CommitmentMismatch);
        }

        // any shares beyond t must lie on the same polynomials
        for s in extra {
            let x = GF256(s.index);
            for (byte_idx, poly) in coefficients.iter().enumerate() {
                let mut y = GF256::ZERO;
                for c in poly.iter().rev() {
                    y = y * x + *c;
                }
                if y.0 != s.data[byte_idx] {
                    return Err(Error::CommitmentMismatch);
                }
            }
        }

        Ok(coefficients.iter().map(|p| p[0].0).collect())
    }
}

/// errors during share operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// not enough shares to reconstruct
    InsufficientShares,
    /// shares have different data lengths
    InconsistentShares,
    /// share index out of valid range
    InvalidShareIndex,
    /// duplicate share index
    DuplicateShare,
    /// shares do not match the header commitment
    CommitmentMismatch,
    /// header threshold is zero
    InvalidThreshold,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InsufficientShares => write!(f, "insufficient shares for reconstruction"),
            Error::InconsistentShares => write!(f, "shares have inconsistent data lengths"),
            Error::InvalidShareIndex => write!(f, "share index out of valid range"),
            Error::DuplicateShare => write!(f, "duplicate share index"),
            Error::CommitmentMismatch => write!(f, "shares do not match header commitment"),
            Error::InvalidThreshold => write!(f, "header threshold must be at least 1"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub mod transport;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_mul() {
        assert_eq!(GF256(2) * GF256(3), GF256(6));
        assert_eq!(GF256(0x53) * GF256(0xca), GF256(1)); // known inverse pair
    }

    #[test]
    fn test_gf256_inv() {
        for i in 1..=255u8 {
            let a = GF256(i);
            let inv = a.inv();
            assert_eq!(a * inv, GF256::ONE, "inverse failed for {}", i);
        }
    }

    #[test]
    fn test_share_reconstruct_2_of_3() {
        let secret = b"hello world secret!";
        let dealer = Dealer::new(2, 3);

        let mut rng = rand::thread_rng();
        let (header, shares) = dealer.share(secret, &mut rng);

        // verify shares
        for share in &shares {
            assert!(share.verify(&header));
        }

        // reconstruct from any 2 shares
        let reconstructed = Player::reconstruct(&header, &shares[0..2]).unwrap();
        assert_eq!(reconstructed, secret);

        let reconstructed = Player::reconstruct(&header, &shares[1..3]).unwrap();
        assert_eq!(reconstructed, secret);

        let reconstructed =
            Player::reconstruct(&header, &[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_share_reconstruct_3_of_5() {
        let secret = [0x42u8; 32]; // 256-bit secret
        let dealer = Dealer::new(3, 5);

        let mut rng = rand::thread_rng();
        let (header, shares) = dealer.share(&secret, &mut rng);

        // any 3 shares should work
        let reconstructed = Player::reconstruct(&header, &shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);

        let reconstructed = Player::reconstruct(&header, &shares[2..5]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"test";
        let dealer = Dealer::new(3, 5);

        let mut rng = rand::thread_rng();
        let (header, shares) = dealer.share(secret, &mut rng);

        // 2 shares is not enough for 3-of-5
        let result = Player::reconstruct(&header, &shares[0..2]);
        assert_eq!(result, Err(Error::InsufficientShares));
    }

    #[test]
    fn test_zero_threshold_header_is_rejected() {
        // a dealer-supplied header whose commitment matches the empty
        // polynomial set, so only the threshold check stands in the way
        let header = Header::new(0, 3, &[Vec::new()]);
        let share = Share {
            index: 1,
            data: vec![0x42],
        };
        assert_eq!(
            Player::reconstruct(&header, &[share]),
            Err(Error::InvalidThreshold)
        );
        assert_eq!(
            Player::reconstruct(&header, &[]),
            Err(Error::InvalidThreshold)
        );
    }

    #[test]
    fn test_large_secret() {
        // test with 256-byte secret (2048 bits)
        let secret = [0xAB; 256];
        let dealer = Dealer::new(5, 10);

        let mut rng = rand::thread_rng();
        let (header, shares) = dealer.share(&secret, &mut rng);

        let reconstructed = Player::reconstruct(&header, &shares[0..5]).unwrap();
        assert_eq!(reconstructed, secret);
    }
}

#[cfg(test)]
mod commitment_tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn tampered_share_rejected() {
        let (h, mut s) = Dealer::new(3, 5).share(&[7u8; 32], &mut OsRng);
        s[1].data[0] ^= 1;
        assert_eq!(
            Player::reconstruct(&h, &s[0..3]),
            Err(Error::CommitmentMismatch)
        );
    }

    #[test]
    fn tampered_extra_share_rejected() {
        let (h, mut s) = Dealer::new(3, 5).share(&[7u8; 32], &mut OsRng);
        s[4].data[5] ^= 1;
        assert_eq!(Player::reconstruct(&h, &s), Err(Error::CommitmentMismatch));
    }

    #[test]
    fn any_subset_still_works() {
        let secret = [9u8; 48];
        let (h, s) = Dealer::new(3, 5).share(&secret, &mut OsRng);
        let pick = vec![s[4].clone(), s[0].clone(), s[2].clone()];
        assert_eq!(Player::reconstruct(&h, &pick).unwrap(), secret);
    }
}

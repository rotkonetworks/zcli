//! Sync helpers for Zcash light clients: the cross-verification tally and
//! memo ciphertext extraction. Pure functions, no IO.
//!
//! [`extract_enc_ciphertext`] parses raw V5 transaction bytes to find the 580-byte
//! encrypted ciphertext for a specific action. Memo decryption itself requires
//! orchard key types (version-sensitive), so callers handle `try_note_decryption`
//! directly using their own orchard dependency.

use zcash_note_encryption::ENC_CIPHERTEXT_SIZE;

/// Result of cross-verifying a block hash against multiple endpoints.
#[derive(Debug)]
pub struct CrossVerifyTally {
    pub agree: u32,
    pub disagree: u32,
}

impl CrossVerifyTally {
    /// Check BFT majority (>2/3 of responding nodes agree).
    pub fn has_majority(&self) -> bool {
        let total = self.agree + self.disagree;
        if total == 0 {
            return false;
        }
        let threshold = (total * 2).div_ceil(3);
        self.agree >= threshold
    }

    pub fn total(&self) -> u32 {
        self.agree + self.disagree
    }
}

/// Compare two block hashes, accounting for LE/BE byte order differences
/// between native gRPC lightwalletd (BE display order) and zidecar (LE internal).
pub fn hashes_match(a: &[u8], b: &[u8]) -> bool {
    if a.is_empty() || b.is_empty() {
        return true; // can't compare empty hashes
    }
    if a == b {
        return true;
    }
    let mut b_rev = b.to_vec();
    b_rev.reverse();
    a == b_rev.as_slice()
}

/// Extract the 580-byte enc_ciphertext for an action matching cmx+epk from raw tx bytes.
///
/// V5 orchard action layout: cv(32) + nf(32) + rk(32) + cmx(32) + epk(32) + enc(580) + out(80) = 820 bytes
/// enc_ciphertext immediately follows epk within each action.
pub fn extract_enc_ciphertext(
    raw_tx: &[u8],
    cmx: &[u8; 32],
    epk: &[u8; 32],
) -> Option<[u8; ENC_CIPHERTEXT_SIZE]> {
    for i in 0..raw_tx.len().saturating_sub(64 + ENC_CIPHERTEXT_SIZE) {
        if &raw_tx[i..i + 32] == cmx && &raw_tx[i + 32..i + 64] == epk {
            let start = i + 64;
            let end = start + ENC_CIPHERTEXT_SIZE;
            if end <= raw_tx.len() {
                let mut enc = [0u8; ENC_CIPHERTEXT_SIZE];
                enc.copy_from_slice(&raw_tx[start..end]);
                return Some(enc);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashes_match_same() {
        let h = [1u8; 32];
        assert!(hashes_match(&h, &h));
    }

    #[test]
    fn test_hashes_match_reversed() {
        let a: Vec<u8> = (0..32).collect();
        let b: Vec<u8> = (0..32).rev().collect();
        assert!(hashes_match(&a, &b));
    }

    #[test]
    fn test_hashes_match_empty() {
        assert!(hashes_match(&[], &[1u8; 32]));
        assert!(hashes_match(&[1u8; 32], &[]));
    }

    #[test]
    fn test_hashes_no_match() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(!hashes_match(&a, &b));
    }

    #[test]
    fn test_cross_verify_tally_majority() {
        let tally = CrossVerifyTally {
            agree: 3,
            disagree: 1,
        };
        assert!(tally.has_majority()); // 3/4 > 2/3

        let tally = CrossVerifyTally {
            agree: 1,
            disagree: 2,
        };
        assert!(!tally.has_majority()); // 1/3 < 2/3
    }

    #[test]
    fn test_cross_verify_tally_empty() {
        let tally = CrossVerifyTally {
            agree: 0,
            disagree: 0,
        };
        assert!(!tally.has_majority());
    }

    #[test]
    fn test_extract_enc_ciphertext_not_found() {
        let raw = vec![0u8; 100];
        let cmx = [1u8; 32];
        let epk = [2u8; 32];
        assert!(extract_enc_ciphertext(&raw, &cmx, &epk).is_none());
    }
}

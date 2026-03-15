//! Actions merkle root computation and running commitment chain.
//!
//! Shared between client and server to ensure identical computation.
//! The actions root binds compact block actions to the ligerito-proven header chain.

use sha2::{Digest, Sha256};

/// Compute merkle root over a block's orchard actions.
///
/// Each leaf is `SHA256(cmx || nullifier || ephemeral_key)`.
/// Tree is a standard binary SHA256 merkle tree with zero-padding to next power of 2.
/// Empty block (no actions) returns all-zeros root.
pub fn compute_actions_root(actions: &[([u8; 32], [u8; 32], [u8; 32])]) -> [u8; 32] {
    if actions.is_empty() {
        return [0u8; 32];
    }

    // compute leaf hashes
    let mut leaves: Vec<[u8; 32]> = actions
        .iter()
        .map(|(cmx, nullifier, epk)| {
            let mut hasher = Sha256::new();
            hasher.update(cmx);
            hasher.update(nullifier);
            hasher.update(epk);
            hasher.finalize().into()
        })
        .collect();

    // pad to next power of 2
    let target_len = leaves.len().next_power_of_two();
    leaves.resize(target_len, [0u8; 32]);

    // build binary merkle tree bottom-up
    let mut level = leaves;
    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(pair[0]);
            hasher.update(pair[1]);
            next_level.push(hasher.finalize().into());
        }
        level = next_level;
    }

    level[0]
}

/// Update the running actions commitment chain.
///
/// `chain_i = BLAKE2b-256("ZYNC_actions_v1" || chain_{i-1} || actions_root_i || height_i)`
///
/// This mirrors the existing `update_state_commitment` pattern in header_chain.rs.
pub fn update_actions_commitment(
    prev: &[u8; 32],
    actions_root: &[u8; 32],
    height: u32,
) -> [u8; 32] {
    use blake2::digest::typenum::U32;
    use blake2::Blake2b;

    let mut hasher = <Blake2b<U32>>::new();
    hasher.update(b"ZYNC_actions_v1");
    hasher.update(prev);
    hasher.update(actions_root);
    hasher.update(height.to_le_bytes());

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_actions_root() {
        let root = compute_actions_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn test_single_action_root() {
        let cmx = [1u8; 32];
        let nullifier = [2u8; 32];
        let epk = [3u8; 32];

        let root = compute_actions_root(&[(cmx, nullifier, epk)]);

        // single leaf: root should be the leaf hash itself (padded to 2, then
        // root = SHA256(leaf || zero))
        let mut hasher = Sha256::new();
        hasher.update(cmx);
        hasher.update(nullifier);
        hasher.update(epk);
        let leaf: [u8; 32] = hasher.finalize().into();

        // with padding to power of 2 (size 1 -> 1, which is already power of 2)
        // actually 1 is 2^0, so next_power_of_two(1) = 1, meaning no padding needed
        // and the loop stops immediately since level.len() == 1
        assert_eq!(root, leaf);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_actions_root_deterministic() {
        let actions = vec![
            ([10u8; 32], [20u8; 32], [30u8; 32]),
            ([40u8; 32], [50u8; 32], [60u8; 32]),
            ([70u8; 32], [80u8; 32], [90u8; 32]),
        ];

        let root1 = compute_actions_root(&actions);
        let root2 = compute_actions_root(&actions);
        assert_eq!(root1, root2);
        assert_ne!(root1, [0u8; 32]);
    }

    #[test]
    fn test_actions_commitment_chain() {
        let prev = [0u8; 32];
        let root_a = [1u8; 32];
        let root_b = [2u8; 32];

        // different actions roots produce different commitments
        let c1 = update_actions_commitment(&prev, &root_a, 100);
        let c2 = update_actions_commitment(&prev, &root_b, 100);
        assert_ne!(c1, c2);

        // different heights produce different commitments
        let c3 = update_actions_commitment(&prev, &root_a, 101);
        assert_ne!(c1, c3);

        // different prev produce different commitments
        let c4 = update_actions_commitment(&[0xffu8; 32], &root_a, 100);
        assert_ne!(c1, c4);

        // deterministic
        let c5 = update_actions_commitment(&prev, &root_a, 100);
        assert_eq!(c1, c5);
    }

    #[test]
    fn test_two_actions_root() {
        let a1 = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let a2 = ([4u8; 32], [5u8; 32], [6u8; 32]);

        let root = compute_actions_root(&[a1, a2]);

        // manually compute: 2 leaves, already power of 2
        let mut h1 = Sha256::new();
        h1.update(a1.0);
        h1.update(a1.1);
        h1.update(a1.2);
        let leaf1: [u8; 32] = h1.finalize().into();

        let mut h2 = Sha256::new();
        h2.update(a2.0);
        h2.update(a2.1);
        h2.update(a2.2);
        let leaf2: [u8; 32] = h2.finalize().into();

        let mut h3 = Sha256::new();
        h3.update(leaf1);
        h3.update(leaf2);
        let expected: [u8; 32] = h3.finalize().into();

        assert_eq!(root, expected);
    }

    #[test]
    fn test_three_actions_padded() {
        // 3 actions -> padded to 4 leaves
        let a1 = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let a2 = ([4u8; 32], [5u8; 32], [6u8; 32]);
        let a3 = ([7u8; 32], [8u8; 32], [9u8; 32]);

        let root = compute_actions_root(&[a1, a2, a3]);
        assert_ne!(root, [0u8; 32]);

        // order matters
        let root_reordered = compute_actions_root(&[a2, a1, a3]);
        assert_ne!(root, root_reordered);
    }
}

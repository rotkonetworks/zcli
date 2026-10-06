//! Consensus parameters that follow the chain the node reports.
//!
//! zakura's transaction builder picks the consensus branch from
//! `BranchId::for_height(params, target_height)`. The crate's built-in tables
//! cannot be the authority for NU7: zakura 2.0.0 has no testnet NU7 height,
//! mainnet's is not set until 2026-10-20, and Valar's NU7 staging chains use
//! their own activation tables. The node knows which branch it is on, and the
//! wallet already reads it (GetLightdInfo) and passes it as the expected
//! branch id - so NU7 is treated as active at `target_height` exactly when the
//! node says so, and everything else comes from the base parameters.
//!
//! Only NU7 is moved. Every other report leaves the base table alone, so the
//! builders' own fail-closed guards (placeholder id, no Ironwood pool, bound
//! branch != the node's) keep refusing exactly as before.

use zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters};

/// NU6.3 "Ironwood" (active on mainnet since height 3,428,143).
pub const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;
/// NU7 (ZIP 259).
pub const NU7_BRANCH_ID: u32 = 0x7719_0ad9;

/// Default expiry delta (blocks) before NU7 (ZIP 203), and from NU7 on
/// (ZIP 218 raises it to 120 alongside the move to 25-second blocks).
pub const EXPIRY_DELTA_PRE_NU7: u32 = 40;
pub const EXPIRY_DELTA_NU7: u32 = 120;

/// Default expiry delta (blocks) for a transaction built on `branch_id`.
pub fn default_expiry_delta(branch_id: u32) -> u32 {
    if branch_id == NU7_BRANCH_ID {
        EXPIRY_DELTA_NU7
    } else {
        EXPIRY_DELTA_PRE_NU7
    }
}

/// Expiry height for a transaction built at `target_height` on `branch_id`.
pub fn expiry_height(branch_id: u32, target_height: u32) -> BlockHeight {
    BlockHeight::from(target_height.saturating_add(default_expiry_delta(branch_id)))
}

#[derive(Clone, Copy, Debug)]
pub struct NodeParams<P> {
    base: P,
    nu7: Option<BlockHeight>,
}

impl<P: Parameters> NodeParams<P> {
    /// Parameters for building at `target_height` on the chain whose branch
    /// the node reports as `node_branch_id`. When the node reports NU7, NU7
    /// counts as active from the base table's height or `target_height`,
    /// whichever is lower. A node on NU6.3 while the table already has NU7
    /// active still binds NU7, and the builders' mismatch guard refuses.
    pub fn new(base: P, node_branch_id: u32, target_height: u32) -> Self {
        let base_nu7 = base.activation_height(NetworkUpgrade::Nu7);
        let nu7 = if node_branch_id == NU7_BRANCH_ID {
            let target = BlockHeight::from(target_height);
            Some(base_nu7.map_or(target, |h| h.min(target)))
        } else {
            base_nu7
        };
        Self { base, nu7 }
    }
}

impl<P: Parameters> Parameters for NodeParams<P> {
    fn network_type(&self) -> NetworkType {
        self.base.network_type()
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Nu7 => self.nu7,
            other => self.base.activation_height(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::{BranchId, MainNetwork, TestNetwork};

    fn branch<P: Parameters>(p: &P, h: u32) -> u32 {
        BranchId::for_height(p, BlockHeight::from(h)).into()
    }

    #[test]
    fn node_reporting_nu7_makes_the_builder_bind_nu7() {
        // staging-chain height, below public testnet's NU7 activation
        let p = NodeParams::new(TestNetwork, NU7_BRANCH_ID, 4_430_000);
        assert_eq!(branch(&p, 4_430_000), NU7_BRANCH_ID);
        let p = NodeParams::new(MainNetwork, NU7_BRANCH_ID, 3_600_000);
        assert_eq!(branch(&p, 3_600_000), NU7_BRANCH_ID);
    }

    #[test]
    fn node_reporting_nu6_3_keeps_nu6_3() {
        let p = NodeParams::new(MainNetwork, NU6_3_BRANCH_ID, 3_500_000);
        assert_eq!(branch(&p, 3_500_000), NU6_3_BRANCH_ID);
    }

    #[test]
    fn other_reports_leave_the_table_alone() {
        // NodeParams only ever moves NU7; the builders' guards refuse these
        // by comparing the bound branch with the node's.
        for id in [0xc8e7_1055, 0xdead_beef, 0xffff_ffff] {
            let p = NodeParams::new(MainNetwork, id, 3_500_000);
            assert_eq!(branch(&p, 3_500_000), NU6_3_BRANCH_ID);
        }
    }

    #[test]
    fn node_on_nu6_3_past_the_tables_nu7_still_binds_nu7() {
        // The table wins, so the bound branch (NU7) differs from the node's
        // (NU6.3) and the builders' mismatch guard refuses.
        let h = crate::consensus::TESTNET_NU7_ACTIVATION_HEIGHT;
        let p = NodeParams::new(crate::consensus::TestNetwork, NU6_3_BRANCH_ID, h + 10);
        assert_eq!(branch(&p, h + 10), NU7_BRANCH_ID);
    }

    #[test]
    fn expiry_delta_follows_the_branch() {
        assert_eq!(u32::from(expiry_height(NU7_BRANCH_ID, 100)), 220);
        assert_eq!(u32::from(expiry_height(NU6_3_BRANCH_ID, 100)), 140);
        assert_eq!(default_expiry_delta(NU7_BRANCH_ID), EXPIRY_DELTA_NU7);
        assert_eq!(
            EXPIRY_DELTA_PRE_NU7,
            crate::LEGACY_PCZT_EXPIRY_DELTA,
            "pre-NU7 default is the legacy delta"
        );
    }
}

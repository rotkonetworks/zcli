//! Testnet consensus parameters with the NU7 activation height.
//!
//! We stay on Zakura Common 2.0 because the voting crates pin it exactly, and
//! 2.0's `TEST_NETWORK` has no NU7 height (2.2 added it). This drop-in
//! `TestNetwork` delegates to Common's and fills in NU7. Delete it once the
//! workspace moves to Common >= 2.2.

use zcash_protocol::consensus::{self, BlockHeight, NetworkType, NetworkUpgrade, Parameters};

/// NU7 on the public testnet (branch 0x77190ad9).
pub const TESTNET_NU7_ACTIVATION_HEIGHT: u32 = 4_465_026;

/// Zcash testnet, with NU7 scheduled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TestNetwork;

impl Parameters for TestNetwork {
    fn network_type(&self) -> NetworkType {
        NetworkType::Test
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Nu7 => Some(BlockHeight::from_u32(TESTNET_NU7_ACTIVATION_HEIGHT)),
            _ => consensus::TestNetwork.activation_height(nu),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::BranchId;

    #[test]
    fn nu7_on_testnet() {
        let h = BlockHeight::from_u32(TESTNET_NU7_ACTIVATION_HEIGHT);
        assert_eq!(BranchId::for_height(&TestNetwork, h - 1), BranchId::Nu6_3);
        assert_eq!(BranchId::for_height(&TestNetwork, h), BranchId::Nu7);
        assert_eq!(u32::from(BranchId::Nu7), 0x77190ad9);
    }
}

//! Network-upgrade epochs that carry a ZIP-221 history tree.
//!
//! The history tree restarts at every network upgrade: block `n` commits to an
//! MMR over blocks `activation..n-1` of its own epoch, and the activation block
//! itself commits to the previous epoch's complete tree. The node format grows
//! with the shielded pools: V1 (Heartwood, Canopy), V2 adds Orchard (NU5 to
//! NU6.2), V3 adds Ironwood (NU6.3).
//!
//! Upgrades are not hardcoded. A [`Schedule`] is built either from the
//! upgrades `zcash_protocol` knows ([`Schedule::compiled`]) or from any list
//! of `(activation height, branch id)` pairs, such as zebrad's
//! `getblockchaininfo` ([`Schedule::from_upgrades`]). An upgrade this code has
//! never heard of (NU7, ...) gets the newest node format and the NU5-style
//! header binding; if it changes the node format, parsing fails and proofs
//! are rejected until the code learns it, never accepted wrongly.

use zcash_protocol::consensus::{BranchId, MainNetwork, NetworkUpgrade, Parameters, TestNetwork};

use super::node::NodeVersion;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

/// Branch ids before Heartwood (Sprout, Overwinter, Sapling, Blossom): no
/// history tree.
const PRE_HISTORY_BRANCHES: [u32; 4] = [0x0000_0000, 0x5ba8_1b19, 0x76b8_09bb, 0x2bb4_0e60];
const HEARTWOOD: u32 = 0xf5b9_230b;
const CANOPY: u32 = 0xe9ff_75a6;

/// Node format for an epoch's branch id. Heartwood and Canopy use V1; NU5
/// through NU6.2 use V2; NU6.3 and anything newer use V3, the latest format
/// `zcash_history` knows.
pub fn version_for_branch(branch_id: u32) -> NodeVersion {
    match BranchId::try_from(branch_id) {
        Ok(BranchId::Heartwood | BranchId::Canopy) => NodeVersion::V1,
        Ok(BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2) => NodeVersion::V2,
        _ => NodeVersion::V3,
    }
}

/// One history-tree epoch: `[activation, end)` where `end` is the next
/// upgrade's activation height (or `None` for the newest epoch known).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Epoch {
    pub branch_id: u32,
    pub activation: u32,
    pub end: Option<u32>,
    pub version: NodeVersion,
}

impl Epoch {
    pub fn new(activation: u32, branch_id: u32, end: Option<u32>) -> Self {
        Epoch {
            branch_id,
            activation,
            end,
            version: version_for_branch(branch_id),
        }
    }

    /// Heartwood and Canopy headers carry the history root itself in
    /// `hashLightClientRoot`; from NU5 the root is hashed into
    /// `hashBlockCommitments` together with the auth data root (ZIP-244).
    pub fn commits_root_directly(&self) -> bool {
        self.branch_id == HEARTWOOD || self.branch_id == CANOPY
    }

    pub fn contains(&self, height: u32) -> bool {
        height >= self.activation && self.end.is_none_or(|e| height < e)
    }
}

/// History-tree epochs, oldest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    epochs: Vec<Epoch>,
}

impl Schedule {
    /// Epochs from `(activation height, branch id)` pairs in any order, e.g.
    /// every upgrade a node reports. Pre-Heartwood upgrades are dropped;
    /// so are upgrades whose activation is unknown (pass only scheduled ones).
    pub fn from_upgrades(upgrades: impl IntoIterator<Item = (u32, u32)>) -> Self {
        let mut list: Vec<(u32, u32)> = upgrades
            .into_iter()
            .filter(|(_, b)| !PRE_HISTORY_BRANCHES.contains(b))
            .collect();
        list.sort_unstable();
        list.dedup_by_key(|(h, _)| *h);
        let epochs = list
            .iter()
            .enumerate()
            .map(|(i, (h, b))| Epoch::new(*h, *b, list.get(i + 1).map(|(next, _)| *next)))
            .collect();
        Schedule { epochs }
    }

    /// The upgrades `zcash_protocol` knows for `network`, with their branch ids.
    pub fn compiled(network: Network) -> Self {
        let nus = [
            NetworkUpgrade::Heartwood,
            NetworkUpgrade::Canopy,
            NetworkUpgrade::Nu5,
            NetworkUpgrade::Nu6,
            NetworkUpgrade::Nu6_1,
            NetworkUpgrade::Nu6_2,
            NetworkUpgrade::Nu6_3,
        ];
        Self::from_upgrades(nus.iter().filter_map(|nu| {
            let h = match network {
                Network::Mainnet => MainNetwork.activation_height(*nu),
                Network::Testnet => TestNetwork.activation_height(*nu),
            }?;
            Some((u32::from(h), u32::from(nu.branch_id())))
        }))
    }

    pub fn epochs(&self) -> &[Epoch] {
        &self.epochs
    }

    /// The epoch containing `height`, if that height has a history tree.
    pub fn at(&self, height: u32) -> Option<Epoch> {
        self.epochs.iter().copied().find(|e| e.contains(height))
    }

    /// The epoch that activated at exactly `activation`.
    pub fn activated_at(&self, activation: u32) -> Option<Epoch> {
        self.epochs
            .iter()
            .copied()
            .find(|e| e.activation == activation)
    }

    /// The epoch right before `epoch`.
    pub fn before(&self, epoch: &Epoch) -> Option<Epoch> {
        self.epochs
            .iter()
            .copied()
            .find(|e| e.end == Some(epoch.activation))
    }

    /// Activation of the newest epoch in the schedule.
    pub fn newest_activation(&self) -> Option<u32> {
        self.epochs.last().map(|e| e.activation)
    }
}

/// All history-tree epochs `zcash_protocol` knows for `network`, oldest first.
pub fn epochs(network: Network) -> Vec<Epoch> {
    Schedule::compiled(network).epochs
}

/// The epoch containing `height` in the compiled schedule.
pub fn epoch_at(network: Network, height: u32) -> Option<Epoch> {
    Schedule::compiled(network).at(height)
}

/// The epoch that activated at exactly `activation` in the compiled schedule.
pub fn epoch_activated_at(network: Network, activation: u32) -> Option<Epoch> {
    Schedule::compiled(network).activated_at(activation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_epochs_are_contiguous_and_versioned() {
        let es = epochs(Network::Mainnet);
        assert_eq!(es.first().unwrap().branch_id, HEARTWOOD);
        for w in es.windows(2) {
            assert_eq!(w[0].end, Some(w[1].activation));
        }
        let nu5 = epoch_at(Network::Mainnet, crate::ORCHARD_ACTIVATION_HEIGHT).unwrap();
        assert_eq!(nu5.branch_id, 0xc2d6_d0b4);
        assert_eq!(nu5.activation, crate::ORCHARD_ACTIVATION_HEIGHT);
        assert_eq!(nu5.version, NodeVersion::V2);
        assert!(!nu5.commits_root_directly());
        let nu63 = epoch_at(Network::Mainnet, crate::IRONWOOD_ACTIVATION_HEIGHT).unwrap();
        assert_eq!(nu63.version, NodeVersion::V3);
        assert_eq!(nu63.branch_id, 0x37a5_165b);
        assert!(epoch_at(Network::Mainnet, 900_000).is_none());
        assert!(es[0].commits_root_directly() && es[1].commits_root_directly());
    }

    #[test]
    fn a_node_reported_schedule_takes_upgrades_this_code_does_not_know() {
        // what zebrad reports, shuffled, with pre-Heartwood upgrades and a
        // future upgrade this crate has no name for
        let future = 0xdead_beef;
        let mut list: Vec<(u32, u32)> = epochs(Network::Mainnet)
            .iter()
            .map(|e| (e.activation, e.branch_id))
            .collect();
        list.push((347_500, 0x5ba8_1b19)); // overwinter
        list.push((4_000_000, future));
        list.reverse();
        let s = Schedule::from_upgrades(list);
        let last = *s.epochs().last().unwrap();
        assert_eq!(last.branch_id, future);
        assert_eq!(last.version, NodeVersion::V3);
        assert!(!last.commits_root_directly());
        let nu63 = s.activated_at(crate::IRONWOOD_ACTIVATION_HEIGHT).unwrap();
        assert_eq!(nu63.end, Some(4_000_000));
        assert_eq!(s.before(&last), Some(nu63));
        assert_eq!(s.epochs().first().unwrap().branch_id, HEARTWOOD);
    }
}

//! Network-upgrade epochs that carry a ZIP-221 history tree.
//!
//! The history tree restarts at every network upgrade: block `n` commits to an
//! MMR over blocks `activation..n-1` of its own epoch, and the activation block
//! itself commits to an empty tree. The node format grows with the shielded
//! pools: V1 (Heartwood, Canopy), V2 adds Orchard (NU5 to NU6.2), V3 adds
//! Ironwood (NU6.3).

use zcash_protocol::consensus::{BranchId, MainNetwork, NetworkUpgrade, Parameters, TestNetwork};

use super::node::NodeVersion;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

/// Upgrades that carry a history tree, oldest first.
const HISTORY_UPGRADES: [NetworkUpgrade; 7] = [
    NetworkUpgrade::Heartwood,
    NetworkUpgrade::Canopy,
    NetworkUpgrade::Nu5,
    NetworkUpgrade::Nu6,
    NetworkUpgrade::Nu6_1,
    NetworkUpgrade::Nu6_2,
    NetworkUpgrade::Nu6_3,
];

/// One history-tree epoch: `[activation, end)` where `end` is the next
/// upgrade's activation height (or `None` for the current epoch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Epoch {
    pub upgrade: NetworkUpgrade,
    pub branch_id: u32,
    pub activation: u32,
    pub end: Option<u32>,
    pub version: NodeVersion,
}

impl Epoch {
    /// Heartwood and Canopy headers carry the history root itself in
    /// `hashLightClientRoot`; from NU5 the root is hashed into
    /// `hashBlockCommitments` together with the auth data root (ZIP-244).
    pub fn commits_root_directly(&self) -> bool {
        self.version == NodeVersion::V1
    }

    pub fn contains(&self, height: u32) -> bool {
        height >= self.activation && self.end.is_none_or(|e| height < e)
    }
}

fn activation(network: Network, nu: NetworkUpgrade) -> Option<u32> {
    match network {
        Network::Mainnet => MainNetwork.activation_height(nu),
        Network::Testnet => TestNetwork.activation_height(nu),
    }
    .map(u32::from)
}

fn version_for(nu: NetworkUpgrade) -> NodeVersion {
    match nu {
        NetworkUpgrade::Heartwood | NetworkUpgrade::Canopy => NodeVersion::V1,
        NetworkUpgrade::Nu6_3 => NodeVersion::V3,
        _ => NodeVersion::V2,
    }
}

/// All history-tree epochs of `network`, oldest first.
pub fn epochs(network: Network) -> Vec<Epoch> {
    let active: Vec<(NetworkUpgrade, u32)> = HISTORY_UPGRADES
        .iter()
        .filter_map(|nu| activation(network, *nu).map(|h| (*nu, h)))
        .collect();
    active
        .iter()
        .enumerate()
        .map(|(i, (nu, h))| Epoch {
            upgrade: *nu,
            branch_id: u32::from(BranchId::for_height(
                &match network {
                    Network::Mainnet => ParamsRef::Main,
                    Network::Testnet => ParamsRef::Test,
                },
                (*h).into(),
            )),
            activation: *h,
            end: active.get(i + 1).map(|(_, next)| *next),
            version: version_for(*nu),
        })
        .collect()
}

/// The epoch containing `height`, if that height has a history tree.
pub fn epoch_at(network: Network, height: u32) -> Option<Epoch> {
    epochs(network).into_iter().find(|e| e.contains(height))
}

/// The epoch that activated at exactly `activation`.
pub fn epoch_activated_at(network: Network, activation: u32) -> Option<Epoch> {
    epochs(network).into_iter().find(|e| e.activation == activation)
}

/// `BranchId::for_height` wants a `Parameters` value; the two network
/// parameter types are distinct, so dispatch through a small enum.
#[derive(Clone, Copy)]
enum ParamsRef {
    Main,
    Test,
}

impl Parameters for ParamsRef {
    fn network_type(&self) -> zcash_protocol::consensus::NetworkType {
        match self {
            ParamsRef::Main => MainNetwork.network_type(),
            ParamsRef::Test => TestNetwork.network_type(),
        }
    }

    fn activation_height(
        &self,
        nu: NetworkUpgrade,
    ) -> Option<zcash_protocol::consensus::BlockHeight> {
        match self {
            ParamsRef::Main => MainNetwork.activation_height(nu),
            ParamsRef::Test => TestNetwork.activation_height(nu),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_epochs_are_contiguous_and_versioned() {
        let es = epochs(Network::Mainnet);
        assert_eq!(es.first().unwrap().upgrade, NetworkUpgrade::Heartwood);
        for w in es.windows(2) {
            assert_eq!(w[0].end, Some(w[1].activation));
        }
        let nu5 = epoch_at(Network::Mainnet, crate::ORCHARD_ACTIVATION_HEIGHT).unwrap();
        assert_eq!(nu5.upgrade, NetworkUpgrade::Nu5);
        assert_eq!(nu5.activation, crate::ORCHARD_ACTIVATION_HEIGHT);
        assert_eq!(nu5.version, NodeVersion::V2);
        let nu63 = epoch_at(Network::Mainnet, crate::IRONWOOD_ACTIVATION_HEIGHT).unwrap();
        assert_eq!(nu63.version, NodeVersion::V3);
        assert_eq!(nu63.branch_id, 0x37a5_165b);
        assert!(epoch_at(Network::Mainnet, 900_000).is_none());
    }
}

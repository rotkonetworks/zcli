//! The Creator role (single entity).
//!
//!  - Creates the base PCZT with no information about spends or outputs.

use alloc::collections::BTreeMap;

use crate::{
    Pczt,
    common::{
        FLAG_SHIELDED_MODIFIABLE, FLAG_TRANSPARENT_INPUTS_MODIFIABLE,
        FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE,
    },
};

use zcash_protocol::constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID};
#[cfg(zcash_unstable = "nu6.3")]
use zcash_protocol::constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID};

/// Initial flags allowing any modification.
const INITIAL_TX_MODIFIABLE: u8 = FLAG_TRANSPARENT_INPUTS_MODIFIABLE
    | FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE
    | FLAG_SHIELDED_MODIFIABLE;

const LEGACY_ORCHARD_SPENDS_AND_OUTPUTS_ENABLED: u8 = 0b0000_0011;
#[cfg(zcash_unstable = "nu6.3")]
const NU6_3_ORCHARD_CROSS_ADDRESS_DISABLED: u8 = 0b0000_0011;

pub struct Creator {
    tx_version: u32,
    version_group_id: u32,
    consensus_branch_id: u32,
    fallback_lock_time: Option<u32>,
    expiry_height: u32,
    coin_type: u32,
    orchard_flags: u8,
    sapling_anchor: [u8; 32],
    orchard_anchor: [u8; 32],
}

impl Creator {
    pub fn new(
        consensus_branch_id: u32,
        expiry_height: u32,
        coin_type: u32,
        sapling_anchor: [u8; 32],
        orchard_anchor: [u8; 32],
    ) -> Self {
        Self {
            // Default to v5 transaction format.
            tx_version: V5_TX_VERSION,
            version_group_id: V5_VERSION_GROUP_ID,
            consensus_branch_id,
            fallback_lock_time: None,
            expiry_height,
            coin_type,
            orchard_flags: LEGACY_ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
            sapling_anchor,
            orchard_anchor,
        }
    }

    /// Creates a base PCZT using the v6 transaction format.
    ///
    /// Use this constructor when Ironwood metadata is needed. [`Creator::new`]
    /// always creates a version 5 PCZT.
    #[cfg(zcash_unstable = "nu6.3")]
    pub fn new_v6(
        consensus_branch_id: u32,
        expiry_height: u32,
        coin_type: u32,
        sapling_anchor: [u8; 32],
        orchard_anchor: [u8; 32],
        ironwood_anchor: [u8; 32],
    ) -> V6Creator {
        V6Creator {
            consensus_branch_id,
            fallback_lock_time: None,
            expiry_height,
            coin_type,
            sapling_anchor,
            orchard_anchor,
            orchard_flags: NU6_3_ORCHARD_CROSS_ADDRESS_DISABLED,
            ironwood_flags: crate::IRONWOOD_SPENDS_AND_OUTPUTS_ENABLED,
            ironwood_anchor,
        }
    }

    pub fn with_fallback_lock_time(mut self, fallback: u32) -> Self {
        self.fallback_lock_time = Some(fallback);
        self
    }

    #[cfg(feature = "orchard")]
    pub fn with_orchard_flags(mut self, orchard_flags: orchard::bundle::Flags) -> Self {
        self.orchard_flags = orchard_flags
            .to_byte(orchard::bundle::BundleFormat::PreNu6_3)
            .expect("Orchard flags must be encodable in the pre-NU6.3 format");
        self
    }

    pub fn build(self) -> Pczt {
        Pczt {
            global: crate::common::Global {
                tx_version: self.tx_version,
                version_group_id: self.version_group_id,
                consensus_branch_id: self.consensus_branch_id,
                fallback_lock_time: self.fallback_lock_time,
                expiry_height: self.expiry_height,
                coin_type: self.coin_type,
                tx_modifiable: INITIAL_TX_MODIFIABLE,
                proprietary: BTreeMap::new(),
            },
            transparent: crate::transparent::Bundle {
                inputs: vec![],
                outputs: vec![],
            },
            sapling: crate::sapling::Bundle {
                spends: vec![],
                outputs: vec![],
                value_sum: 0,
                anchor: self.sapling_anchor,
                bsk: None,
            },
            orchard: crate::orchard::Bundle {
                actions: vec![],
                flags: self.orchard_flags,
                value_sum: (0, true),
                anchor: self.orchard_anchor,
                zkproof: None,
                bsk: None,
            },
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood: crate::empty_ironwood_bundle(),
        }
    }
}

#[cfg(zcash_unstable = "nu6.3")]
/// Builder returned by [`Creator::new_v6`] for version 6 PCZTs.
///
/// This type keeps version 6 and Ironwood-specific configuration separate from
/// [`Creator`], which always produces version 5 PCZTs.
pub struct V6Creator {
    consensus_branch_id: u32,
    fallback_lock_time: Option<u32>,
    expiry_height: u32,
    coin_type: u32,
    sapling_anchor: [u8; 32],
    orchard_anchor: [u8; 32],
    orchard_flags: u8,
    ironwood_flags: u8,
    ironwood_anchor: [u8; 32],
}

#[cfg(zcash_unstable = "nu6.3")]
impl V6Creator {
    pub fn with_fallback_lock_time(mut self, fallback: u32) -> Self {
        self.fallback_lock_time = Some(fallback);
        self
    }

    #[cfg(feature = "orchard")]
    pub fn with_orchard_flags(mut self, orchard_flags: orchard::bundle::Flags) -> Self {
        self.orchard_flags = orchard_flags
            .to_byte(orchard::bundle::BundleFormat::Nu6_3)
            .expect("Orchard flags must be encodable in the NU6.3 format");
        self
    }

    #[cfg(feature = "orchard")]
    pub fn with_ironwood_flags(mut self, ironwood_flags: orchard::bundle::Flags) -> Self {
        self.ironwood_flags = ironwood_flags
            .to_byte(orchard::bundle::BundleFormat::Nu6_3)
            .expect("Ironwood flags must be encodable in the NU6.3 format");
        self
    }

    pub fn with_ironwood_anchor(mut self, ironwood_anchor: [u8; 32]) -> Self {
        self.ironwood_anchor = ironwood_anchor;
        self
    }

    pub fn build(self) -> Pczt {
        Pczt {
            global: crate::common::Global {
                tx_version: V6_TX_VERSION,
                version_group_id: V6_VERSION_GROUP_ID,
                consensus_branch_id: self.consensus_branch_id,
                fallback_lock_time: self.fallback_lock_time,
                expiry_height: self.expiry_height,
                coin_type: self.coin_type,
                tx_modifiable: INITIAL_TX_MODIFIABLE,
                proprietary: BTreeMap::new(),
            },
            transparent: crate::transparent::Bundle {
                inputs: vec![],
                outputs: vec![],
            },
            sapling: crate::sapling::Bundle {
                spends: vec![],
                outputs: vec![],
                value_sum: 0,
                anchor: self.sapling_anchor,
                bsk: None,
            },
            orchard: crate::orchard::Bundle {
                actions: vec![],
                flags: self.orchard_flags,
                value_sum: (0, true),
                anchor: self.orchard_anchor,
                zkproof: None,
                bsk: None,
            },
            ironwood: crate::orchard::Bundle {
                actions: vec![],
                flags: self.ironwood_flags,
                value_sum: (0, true),
                anchor: self.ironwood_anchor,
                zkproof: None,
                bsk: None,
            },
        }
    }
}

impl Creator {
    /// Builds a PCZT from the output of a [`Builder`].
    ///
    /// Returns `None` if the `TxVersion` is incompatible with PCZTs, or if
    /// Orchard-shaped bundles use note plaintext versions that are invalid for
    /// their pools, or if Ironwood bundle data is present for a transaction
    /// version that does not support Ironwood.
    ///
    /// [`Builder`]: zcash_primitives::transaction::builder::Builder
    #[cfg(feature = "zcp-builder")]
    pub fn build_from_parts<P: zcash_protocol::consensus::Parameters>(
        parts: zcash_primitives::transaction::builder::PcztParts<P>,
    ) -> Option<Pczt> {
        use ::transparent::sighash::{SIGHASH_ANYONECANPAY, SIGHASH_SINGLE};
        use zcash_protocol::{consensus::NetworkConstants, constants::V4_TX_VERSION};

        use crate::common::FLAG_HAS_SIGHASH_SINGLE;

        let tx_version = match parts.version {
            zcash_primitives::transaction::TxVersion::Sprout(_)
            | zcash_primitives::transaction::TxVersion::V3 => None,
            zcash_primitives::transaction::TxVersion::V4 => Some(V4_TX_VERSION),
            zcash_primitives::transaction::TxVersion::V5 => Some(V5_TX_VERSION),
            #[cfg(zcash_unstable = "nu6.3")]
            zcash_primitives::transaction::TxVersion::V6 => Some(V6_TX_VERSION),
            #[cfg(zcash_unstable = "zfuture")]
            zcash_primitives::transaction::TxVersion::ZFuture => None,
        }?;
        if !parts.version.valid_in_branch(parts.consensus_branch_id) {
            return None;
        }
        #[cfg(zcash_unstable = "nu6.3")]
        if !parts.version.has_ironwood() && parts.ironwood.is_some() {
            return None;
        }

        // Spends and outputs not modifiable.
        let mut tx_modifiable = 0b0000_0000;
        // Check if any input is using `SIGHASH_SINGLE` (with or without `ANYONECANPAY`).
        if parts.transparent.as_ref().is_some_and(|bundle| {
            bundle.inputs().iter().any(|input| {
                (input.sighash_type().encode() & !SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE
            })
        }) {
            tx_modifiable |= FLAG_HAS_SIGHASH_SINGLE;
        }

        let orchard_bundle_format = {
            #[cfg(zcash_unstable = "nu6.3")]
            {
                if parts.version == zcash_primitives::transaction::TxVersion::V6 {
                    orchard::bundle::BundleFormat::Nu6_3
                } else {
                    orchard::bundle::BundleFormat::PreNu6_3
                }
            }

            #[cfg(not(zcash_unstable = "nu6.3"))]
            {
                orchard::bundle::BundleFormat::PreNu6_3
            }
        };
        #[cfg(zcash_unstable = "nu6.3")]
        let default_orchard_flags = match orchard_bundle_format {
            orchard::bundle::BundleFormat::PreNu6_3 => LEGACY_ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
            _ => NU6_3_ORCHARD_CROSS_ADDRESS_DISABLED,
        };
        #[cfg(not(zcash_unstable = "nu6.3"))]
        let default_orchard_flags = LEGACY_ORCHARD_SPENDS_AND_OUTPUTS_ENABLED;
        let orchard = parts
            .orchard
            .map(|bundle| crate::orchard::Bundle::serialize_from(bundle, orchard_bundle_format))
            .unwrap_or_else(|| crate::orchard::Bundle {
                actions: vec![],
                flags: default_orchard_flags,
                value_sum: (0, true),
                anchor: orchard::Anchor::empty_tree().to_bytes(),
                zkproof: None,
                bsk: None,
            });
        orchard.validate_orchard_note_plaintext_versions().ok()?;

        #[cfg(zcash_unstable = "nu6.3")]
        let ironwood = if parts.version.has_ironwood() {
            parts
                .ironwood
                .map(|bundle| {
                    crate::orchard::Bundle::serialize_from(
                        bundle,
                        orchard::bundle::BundleFormat::Nu6_3,
                    )
                })
                .unwrap_or_else(crate::empty_ironwood_bundle)
        } else {
            if parts
                .ironwood
                .as_ref()
                .is_some_and(|bundle| !bundle.actions().is_empty())
            {
                return None;
            }
            crate::empty_ironwood_bundle()
        };
        #[cfg(zcash_unstable = "nu6.3")]
        ironwood.validate_ironwood_note_plaintext_versions().ok()?;

        Some(Pczt {
            global: crate::common::Global {
                tx_version,
                version_group_id: parts.version.version_group_id(),
                consensus_branch_id: parts.consensus_branch_id.into(),
                fallback_lock_time: Some(parts.lock_time),
                expiry_height: parts.expiry_height.into(),
                coin_type: parts.params.network_type().coin_type(),
                tx_modifiable,
                proprietary: BTreeMap::new(),
            },
            transparent: parts
                .transparent
                .map(crate::transparent::Bundle::serialize_from)
                .unwrap_or_else(|| crate::transparent::Bundle {
                    inputs: vec![],
                    outputs: vec![],
                }),
            sapling: parts
                .sapling
                .map(crate::sapling::Bundle::serialize_from)
                .unwrap_or_else(|| crate::sapling::Bundle {
                    spends: vec![],
                    outputs: vec![],
                    value_sum: 0,
                    anchor: sapling::Anchor::empty_tree().to_bytes(),
                    bsk: None,
                }),
            orchard,
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(zcash_unstable = "nu6.3")]
    use super::*;
    #[cfg(zcash_unstable = "nu6.3")]
    use zcash_protocol::consensus::BranchId;

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn new_keeps_legacy_v5_format_on_nu6_3_branch() {
        let pczt = Creator::new(BranchId::Nu6_3.into(), 10_000_000, 133, [0; 32], [0; 32]).build();
        let fallback = crate::empty_ironwood_bundle();

        assert_eq!(pczt.global.tx_version, V5_TX_VERSION);
        assert_eq!(pczt.global.version_group_id, V5_VERSION_GROUP_ID);
        assert!(pczt.ironwood.actions.is_empty());
        assert_eq!(pczt.ironwood.flags, fallback.flags);
        assert_eq!(pczt.ironwood.value_sum, fallback.value_sum);
        assert_eq!(pczt.ironwood.anchor, fallback.anchor);
        assert_eq!(pczt.ironwood.zkproof, fallback.zkproof);
        assert_eq!(pczt.ironwood.bsk, fallback.bsk);
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn new_v6_selects_v6() {
        let pczt = Creator::new_v6(
            BranchId::Nu6_3.into(),
            10_000_000,
            133,
            [0; 32],
            [0; 32],
            [1; 32],
        )
        .build();

        assert_eq!(pczt.global.tx_version, V6_TX_VERSION);
        assert_eq!(pczt.global.version_group_id, V6_VERSION_GROUP_ID);
        assert_eq!(pczt.orchard.flags, NU6_3_ORCHARD_CROSS_ADDRESS_DISABLED);
        assert_eq!(pczt.ironwood.anchor, [1; 32]);
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn explicit_orchard_flags_use_selected_format() {
        let pczt = Creator::new(BranchId::Nu6_3.into(), 10_000_000, 133, [0; 32], [0; 32])
            .with_orchard_flags(orchard::bundle::Flags::ENABLED)
            .build();

        assert_eq!(pczt.global.tx_version, V5_TX_VERSION);
        assert_eq!(pczt.orchard.flags, 0b0000_0011);

        let pczt = Creator::new_v6(
            BranchId::Nu6_3.into(),
            10_000_000,
            133,
            [0; 32],
            [0; 32],
            [1; 32],
        )
        .with_orchard_flags(orchard::bundle::Flags::ENABLED)
        .build();

        assert_eq!(pczt.global.tx_version, V6_TX_VERSION);
        assert_eq!(pczt.orchard.flags, 0b0000_0111);

        let pczt = Creator::new_v6(
            BranchId::Nu6_3.into(),
            10_000_000,
            133,
            [0; 32],
            [0; 32],
            [1; 32],
        )
        .with_orchard_flags(orchard::bundle::Flags::CROSS_ADDRESS_DISABLED)
        .build();

        assert_eq!(pczt.global.tx_version, V6_TX_VERSION);
        assert_eq!(pczt.orchard.flags, 0b0000_0011);
    }

    #[cfg(all(zcash_unstable = "nu6.3", feature = "zcp-builder"))]
    #[test]
    fn build_from_parts_uses_empty_ironwood_bundle() {
        let pczt = Creator::build_from_parts(zcash_primitives::transaction::builder::PcztParts {
            params: zcash_protocol::consensus::Network::TestNetwork,
            version: zcash_primitives::transaction::TxVersion::V6,
            consensus_branch_id: BranchId::Nu6_3,
            lock_time: 0,
            expiry_height: 0u32.into(),
            transparent: None,
            sapling: None,
            orchard: None,
            ironwood: None,
        })
        .unwrap();
        let fallback = crate::empty_ironwood_bundle();

        assert!(pczt.ironwood.actions.is_empty());
        assert_eq!(pczt.ironwood.flags, fallback.flags);
        assert_eq!(pczt.ironwood.value_sum, fallback.value_sum);
        assert_eq!(pczt.ironwood.anchor, fallback.anchor);
        assert_eq!(pczt.ironwood.zkproof, fallback.zkproof);
        assert_eq!(pczt.ironwood.bsk, fallback.bsk);
    }

    #[cfg(all(zcash_unstable = "nu6.3", feature = "zcp-builder"))]
    #[test]
    fn build_from_parts_rejects_version_invalid_for_branch() {
        assert!(
            Creator::build_from_parts(zcash_primitives::transaction::builder::PcztParts {
                params: zcash_protocol::consensus::Network::TestNetwork,
                version: zcash_primitives::transaction::TxVersion::V6,
                consensus_branch_id: BranchId::Nu5,
                lock_time: 0,
                expiry_height: 0u32.into(),
                transparent: None,
                sapling: None,
                orchard: None,
                ironwood: None,
            })
            .is_none()
        );
    }

    #[cfg(all(zcash_unstable = "nu6.3", feature = "zcp-builder"))]
    #[test]
    fn build_from_parts_rejects_metadata_only_ironwood_for_v5() {
        let mut ironwood = crate::empty_ironwood_bundle();
        ironwood.anchor = [1; 32];

        assert!(
            Creator::build_from_parts(zcash_primitives::transaction::builder::PcztParts {
                params: zcash_protocol::consensus::Network::TestNetwork,
                version: zcash_primitives::transaction::TxVersion::V5,
                consensus_branch_id: BranchId::Nu5,
                lock_time: 0,
                expiry_height: 0u32.into(),
                transparent: None,
                sapling: None,
                orchard: None,
                ironwood: Some(ironwood.into_parsed_ironwood().unwrap()),
            })
            .is_none()
        );
    }
}

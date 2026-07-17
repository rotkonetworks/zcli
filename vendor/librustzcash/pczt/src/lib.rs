//! The Partially Created Zcash Transaction (PCZT) format.
//!
//! This format enables splitting up the logical steps of creating a Zcash transaction
//! across distinct entities. The entity roles roughly match those specified in
//! [BIP 174: Partially Signed Bitcoin Transaction Format] and [BIP 370: PSBT Version 2],
//! with additional Zcash-specific roles.
//!
//! [BIP 174: Partially Signed Bitcoin Transaction Format]: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
//! [BIP 370: PSBT Version 2]: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki
//!
#![cfg_attr(feature = "std", doc = "## Feature flags")]
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]

#[macro_use]
extern crate alloc;

use alloc::vec::Vec;

use getset::Getters;
use serde::Deserialize;

#[cfg(all(
    any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"),
    zcash_unstable = "nu6.3"
))]
use zcash_protocol::constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID};
#[cfg(all(
    any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"),
    any(zcash_unstable = "nu7", zcash_unstable = "zfuture"),
    feature = "zip-233",
))]
use zcash_protocol::value::Zatoshis;
#[cfg(any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"))]
use {
    common::{Global, determine_lock_time},
    zcash_primitives::transaction::{Authorization, TransactionData, TxVersion},
    zcash_protocol::consensus::BranchId,
    zcash_protocol::constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID},
};

#[cfg(all(
    any(feature = "io-finalizer", feature = "signer"),
    zcash_unstable = "nu6.3"
))]
use zcash_primitives::transaction::sighash_v6::v6_signature_hash;
#[cfg(any(feature = "io-finalizer", feature = "signer"))]
use {
    blake2b_simd::Hash as Blake2bHash,
    zcash_primitives::transaction::{
        TxDigests, sighash::SignableInput, sighash_v5::v5_signature_hash,
    },
};

pub mod roles;

pub mod common;
pub mod orchard;
pub mod sapling;
pub mod transparent;

const MAGIC_BYTES: &[u8] = b"PCZT";
const PCZT_VERSION_1: u32 = 1;
const PCZT_VERSION_2: u32 = 2;

#[cfg(feature = "orchard")]
pub(crate) fn orchard_bundle_format(_global: &common::Global) -> ::orchard::bundle::BundleFormat {
    #[cfg(zcash_unstable = "nu6.3")]
    {
        if _global.tx_version == zcash_protocol::constants::V6_TX_VERSION
            && _global.version_group_id == zcash_protocol::constants::V6_VERSION_GROUP_ID
        {
            ::orchard::bundle::BundleFormat::Nu6_3
        } else {
            ::orchard::bundle::BundleFormat::PreNu6_3
        }
    }

    #[cfg(not(zcash_unstable = "nu6.3"))]
    {
        ::orchard::bundle::BundleFormat::PreNu6_3
    }
}

fn postcard_from_exact<'de, T>(bytes: &'de [u8]) -> Result<T, postcard::Error>
where
    T: Deserialize<'de>,
{
    let (value, remainder) = postcard::take_from_bytes(bytes)?;
    if remainder.is_empty() {
        Ok(value)
    } else {
        Err(postcard::Error::DeserializeBadEncoding)
    }
}

/// A partially-created Zcash transaction.
#[derive(Clone, Debug, Getters)]
pub struct Pczt {
    /// Global fields that are relevant to the transaction as a whole.
    #[getset(get = "pub")]
    global: common::Global,

    //
    // Protocol-specific fields.
    //
    // Unlike the `TransactionData` type in `zcash_primitives`, these are not optional.
    // This is because a PCZT does not always contain a semantically-valid transaction,
    // and there may be phases where we need to store protocol-specific metadata before
    // it has been determined whether there are protocol-specific inputs or outputs.
    //
    #[getset(get = "pub")]
    transparent: transparent::Bundle,
    #[getset(get = "pub")]
    sapling: sapling::Bundle,
    /// Orchard bundle fields.
    #[getset(get = "pub")]
    orchard: orchard::Bundle,
    /// Ironwood bundle fields, represented as Orchard-shaped actions.
    #[cfg(zcash_unstable = "nu6.3")]
    #[getset(get = "pub")]
    ironwood: orchard::Bundle,
}

/// Errors that can occur while serializing a PCZT using the legacy v1 encoding.
#[derive(Debug)]
#[non_exhaustive]
pub enum LegacyV1SerializeError {
    /// The legacy v1 encoding is only supported for transaction version 5.
    UnsupportedTxVersion {
        /// The transaction version in the PCZT.
        tx_version: u32,
        /// The transaction version group ID in the PCZT.
        version_group_id: u32,
    },
    /// The Orchard bundle flags cannot be represented by the legacy v1 encoding.
    OrchardFlags {
        /// The Orchard bundle flags in the PCZT.
        flags: u8,
    },
    /// The PCZT contains Orchard-shaped notes that cannot be represented as Orchard v2 notes.
    NotePlaintextVersion(orchard::NotePlaintextVersionError),
    /// The PCZT contains Ironwood bundle data, which the v1 encoding cannot represent.
    #[cfg(zcash_unstable = "nu6.3")]
    IronwoodBundlePresent,
}

impl core::fmt::Display for LegacyV1SerializeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LegacyV1SerializeError::UnsupportedTxVersion {
                tx_version,
                version_group_id,
            } => write!(
                f,
                "legacy PCZT v1 serialization only supports transaction v5, got version {tx_version} with version group ID {version_group_id:#x}"
            ),
            LegacyV1SerializeError::OrchardFlags { flags } => write!(
                f,
                "legacy PCZT v1 serialization cannot represent Orchard bundle flags {flags:#x}"
            ),
            LegacyV1SerializeError::NotePlaintextVersion(e) => write!(f, "{e:?}"),
            #[cfg(zcash_unstable = "nu6.3")]
            LegacyV1SerializeError::IronwoodBundlePresent => {
                write!(
                    f,
                    "legacy PCZT v1 serialization cannot represent Ironwood bundle data"
                )
            }
        }
    }
}

impl From<orchard::NotePlaintextVersionError> for LegacyV1SerializeError {
    fn from(e: orchard::NotePlaintextVersionError) -> Self {
        LegacyV1SerializeError::NotePlaintextVersion(e)
    }
}

#[cfg(zcash_unstable = "nu6.3")]
pub(crate) const EMPTY_IRONWOOD_ANCHOR: [u8; 32] = [0; 32];
#[cfg(zcash_unstable = "nu6.3")]
pub(crate) const IRONWOOD_SPENDS_AND_OUTPUTS_ENABLED: u8 = 0b0000_0111;

#[cfg(zcash_unstable = "nu6.3")]
pub(crate) fn empty_ironwood_bundle() -> orchard::Bundle {
    orchard::Bundle {
        actions: vec![],
        flags: IRONWOOD_SPENDS_AND_OUTPUTS_ENABLED,
        value_sum: (0, true),
        anchor: EMPTY_IRONWOOD_ANCHOR,
        zkproof: None,
        bsk: None,
    }
}

mod v1 {
    use alloc::{collections::BTreeMap, string::String, vec::Vec};

    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    use crate::{common, orchard, sapling, transparent};

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(super) struct Pczt {
        pub(super) global: common::Global,
        pub(super) transparent: transparent::Bundle,
        pub(super) sapling: sapling::Bundle,
        pub(super) orchard: Bundle,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(super) struct Bundle {
        pub(super) actions: Vec<Action>,
        pub(super) flags: u8,
        pub(super) value_sum: (u64, bool),
        pub(super) anchor: [u8; 32],
        pub(super) zkproof: Option<Vec<u8>>,
        pub(super) bsk: Option<[u8; 32]>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(super) struct Action {
        pub(super) cv_net: [u8; 32],
        pub(super) spend: Spend,
        pub(super) output: Output,
        pub(super) rcv: Option<[u8; 32]>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(super) struct Spend {
        pub(super) nullifier: [u8; 32],
        pub(super) rk: [u8; 32],
        #[serde_as(as = "Option<[_; 64]>")]
        pub(super) spend_auth_sig: Option<[u8; 64]>,
        #[serde_as(as = "Option<[_; 43]>")]
        pub(super) recipient: Option<[u8; 43]>,
        pub(super) value: Option<u64>,
        pub(super) rho: Option<[u8; 32]>,
        pub(super) rseed: Option<[u8; 32]>,
        #[serde_as(as = "Option<[_; 96]>")]
        pub(super) fvk: Option<[u8; 96]>,
        pub(super) witness: Option<(u32, [[u8; 32]; 32])>,
        pub(super) alpha: Option<[u8; 32]>,
        pub(super) zip32_derivation: Option<common::Zip32Derivation>,
        pub(super) dummy_sk: Option<[u8; 32]>,
        pub(super) proprietary: BTreeMap<String, Vec<u8>>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(super) struct Output {
        pub(super) cmx: [u8; 32],
        pub(super) ephemeral_key: [u8; 32],
        pub(super) enc_ciphertext: Vec<u8>,
        pub(super) out_ciphertext: Vec<u8>,
        #[serde_as(as = "Option<[_; 43]>")]
        pub(super) recipient: Option<[u8; 43]>,
        pub(super) value: Option<u64>,
        pub(super) rseed: Option<[u8; 32]>,
        pub(super) ock: Option<[u8; 32]>,
        pub(super) zip32_derivation: Option<common::Zip32Derivation>,
        pub(super) user_address: Option<String>,
        pub(super) proprietary: BTreeMap<String, Vec<u8>>,
    }

    impl From<Pczt> for crate::Pczt {
        fn from(pczt: Pczt) -> Self {
            Self {
                global: pczt.global,
                transparent: pczt.transparent,
                sapling: pczt.sapling,
                orchard: pczt.orchard.into(),
                #[cfg(zcash_unstable = "nu6.3")]
                ironwood: crate::empty_ironwood_bundle(),
            }
        }
    }

    impl From<Bundle> for orchard::Bundle {
        fn from(bundle: Bundle) -> Self {
            Self {
                actions: bundle.actions.into_iter().map(Into::into).collect(),
                flags: bundle.flags,
                value_sum: bundle.value_sum,
                anchor: bundle.anchor,
                zkproof: bundle.zkproof,
                bsk: bundle.bsk,
            }
        }
    }

    impl From<Action> for orchard::Action {
        fn from(action: Action) -> Self {
            Self {
                cv_net: action.cv_net,
                spend: action.spend.into(),
                output: action.output.into(),
                rcv: action.rcv,
            }
        }
    }

    impl From<Spend> for orchard::Spend {
        fn from(spend: Spend) -> Self {
            Self {
                nullifier: spend.nullifier,
                rk: spend.rk,
                spend_auth_sig: spend.spend_auth_sig,
                recipient: spend.recipient,
                value: spend.value,
                rho: spend.rho,
                rseed: spend.rseed,
                note_version: orchard::NotePlaintextVersion::V2,
                fvk: spend.fvk,
                witness: spend.witness,
                alpha: spend.alpha,
                zip32_derivation: spend.zip32_derivation,
                dummy_sk: spend.dummy_sk,
                proprietary: spend.proprietary,
            }
        }
    }

    impl From<Output> for orchard::Output {
        fn from(output: Output) -> Self {
            Self {
                cmx: output.cmx,
                note_version: orchard::NotePlaintextVersion::V2,
                ephemeral_key: output.ephemeral_key,
                enc_ciphertext: output.enc_ciphertext,
                out_ciphertext: output.out_ciphertext,
                recipient: output.recipient,
                value: output.value,
                rseed: output.rseed,
                ock: output.ock,
                zip32_derivation: output.zip32_derivation,
                user_address: output.user_address,
                proprietary: output.proprietary,
            }
        }
    }
}

mod v2 {
    use alloc::{collections::BTreeMap, string::String, vec::Vec};

    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    use crate::{common, orchard, sapling, transparent};

    // Postcard encodes struct fields positionally, without field names. Keep
    // each encoding version's wire structs separate from the live domain types.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(super) struct Pczt {
        pub(super) global: common::Global,
        pub(super) transparent: transparent::Bundle,
        pub(super) sapling: sapling::Bundle,
        pub(super) orchard: Bundle,
        #[cfg(zcash_unstable = "nu6.3")]
        pub(super) ironwood: Bundle,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(super) struct Bundle {
        pub(super) actions: Vec<Action>,
        pub(super) flags: u8,
        pub(super) value_sum: (u64, bool),
        pub(super) anchor: [u8; 32],
        pub(super) zkproof: Option<Vec<u8>>,
        pub(super) bsk: Option<[u8; 32]>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(super) struct Action {
        pub(super) cv_net: [u8; 32],
        pub(super) spend: Spend,
        pub(super) output: Output,
        pub(super) rcv: Option<[u8; 32]>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(super) struct Spend {
        pub(super) nullifier: [u8; 32],
        pub(super) rk: [u8; 32],
        #[serde_as(as = "Option<[_; 64]>")]
        pub(super) spend_auth_sig: Option<[u8; 64]>,
        #[serde_as(as = "Option<[_; 43]>")]
        pub(super) recipient: Option<[u8; 43]>,
        pub(super) value: Option<u64>,
        pub(super) rho: Option<[u8; 32]>,
        pub(super) rseed: Option<[u8; 32]>,
        pub(super) note_version: orchard::NotePlaintextVersion,
        #[serde_as(as = "Option<[_; 96]>")]
        pub(super) fvk: Option<[u8; 96]>,
        pub(super) witness: Option<(u32, [[u8; 32]; 32])>,
        pub(super) alpha: Option<[u8; 32]>,
        pub(super) zip32_derivation: Option<common::Zip32Derivation>,
        pub(super) dummy_sk: Option<[u8; 32]>,
        pub(super) proprietary: BTreeMap<String, Vec<u8>>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(super) struct Output {
        pub(super) cmx: [u8; 32],
        pub(super) note_version: orchard::NotePlaintextVersion,
        pub(super) ephemeral_key: [u8; 32],
        pub(super) enc_ciphertext: Vec<u8>,
        pub(super) out_ciphertext: Vec<u8>,
        #[serde_as(as = "Option<[_; 43]>")]
        pub(super) recipient: Option<[u8; 43]>,
        pub(super) value: Option<u64>,
        pub(super) rseed: Option<[u8; 32]>,
        pub(super) ock: Option<[u8; 32]>,
        pub(super) zip32_derivation: Option<common::Zip32Derivation>,
        pub(super) user_address: Option<String>,
        pub(super) proprietary: BTreeMap<String, Vec<u8>>,
    }

    impl From<Pczt> for crate::Pczt {
        fn from(pczt: Pczt) -> Self {
            Self {
                global: pczt.global,
                transparent: pczt.transparent,
                sapling: pczt.sapling,
                orchard: pczt.orchard.into(),
                #[cfg(zcash_unstable = "nu6.3")]
                ironwood: pczt.ironwood.into(),
            }
        }
    }

    impl From<&crate::Pczt> for Pczt {
        fn from(pczt: &crate::Pczt) -> Self {
            Self {
                global: pczt.global.clone(),
                transparent: pczt.transparent.clone(),
                sapling: pczt.sapling.clone(),
                orchard: (&pczt.orchard).into(),
                #[cfg(zcash_unstable = "nu6.3")]
                ironwood: (&pczt.ironwood).into(),
            }
        }
    }

    impl From<Bundle> for orchard::Bundle {
        fn from(bundle: Bundle) -> Self {
            Self {
                actions: bundle.actions.into_iter().map(Into::into).collect(),
                flags: bundle.flags,
                value_sum: bundle.value_sum,
                anchor: bundle.anchor,
                zkproof: bundle.zkproof,
                bsk: bundle.bsk,
            }
        }
    }

    impl From<&orchard::Bundle> for Bundle {
        fn from(bundle: &orchard::Bundle) -> Self {
            Self {
                actions: bundle.actions.iter().map(Into::into).collect(),
                flags: bundle.flags,
                value_sum: bundle.value_sum,
                anchor: bundle.anchor,
                zkproof: bundle.zkproof.clone(),
                bsk: bundle.bsk,
            }
        }
    }

    impl From<Action> for orchard::Action {
        fn from(action: Action) -> Self {
            Self {
                cv_net: action.cv_net,
                spend: action.spend.into(),
                output: action.output.into(),
                rcv: action.rcv,
            }
        }
    }

    impl From<&orchard::Action> for Action {
        fn from(action: &orchard::Action) -> Self {
            Self {
                cv_net: action.cv_net,
                spend: (&action.spend).into(),
                output: (&action.output).into(),
                rcv: action.rcv,
            }
        }
    }

    impl From<Spend> for orchard::Spend {
        fn from(spend: Spend) -> Self {
            Self {
                nullifier: spend.nullifier,
                rk: spend.rk,
                spend_auth_sig: spend.spend_auth_sig,
                recipient: spend.recipient,
                value: spend.value,
                rho: spend.rho,
                rseed: spend.rseed,
                note_version: spend.note_version,
                fvk: spend.fvk,
                witness: spend.witness,
                alpha: spend.alpha,
                zip32_derivation: spend.zip32_derivation,
                dummy_sk: spend.dummy_sk,
                proprietary: spend.proprietary,
            }
        }
    }

    impl From<&orchard::Spend> for Spend {
        fn from(spend: &orchard::Spend) -> Self {
            Self {
                nullifier: spend.nullifier,
                rk: spend.rk,
                spend_auth_sig: spend.spend_auth_sig,
                recipient: spend.recipient,
                value: spend.value,
                rho: spend.rho,
                rseed: spend.rseed,
                note_version: spend.note_version,
                fvk: spend.fvk,
                witness: spend.witness,
                alpha: spend.alpha,
                zip32_derivation: spend.zip32_derivation.clone(),
                dummy_sk: spend.dummy_sk,
                proprietary: spend.proprietary.clone(),
            }
        }
    }

    impl From<Output> for orchard::Output {
        fn from(output: Output) -> Self {
            Self {
                cmx: output.cmx,
                note_version: output.note_version,
                ephemeral_key: output.ephemeral_key,
                enc_ciphertext: output.enc_ciphertext,
                out_ciphertext: output.out_ciphertext,
                recipient: output.recipient,
                value: output.value,
                rseed: output.rseed,
                ock: output.ock,
                zip32_derivation: output.zip32_derivation,
                user_address: output.user_address,
                proprietary: output.proprietary,
            }
        }
    }

    impl From<&orchard::Output> for Output {
        fn from(output: &orchard::Output) -> Self {
            Self {
                cmx: output.cmx,
                note_version: output.note_version,
                ephemeral_key: output.ephemeral_key,
                enc_ciphertext: output.enc_ciphertext.clone(),
                out_ciphertext: output.out_ciphertext.clone(),
                recipient: output.recipient,
                value: output.value,
                rseed: output.rseed,
                ock: output.ock,
                zip32_derivation: output.zip32_derivation.clone(),
                user_address: output.user_address.clone(),
                proprietary: output.proprietary.clone(),
            }
        }
    }
}

impl Pczt {
    /// Parses a PCZT from its encoding.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 8 {
            return Err(ParseError::TooShort);
        }
        if &bytes[..4] != MAGIC_BYTES {
            return Err(ParseError::NotPczt);
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let pczt: Self = match version {
            PCZT_VERSION_1 => postcard_from_exact::<v1::Pczt>(&bytes[8..])
                .map(Into::into)
                .map_err(ParseError::Invalid),
            PCZT_VERSION_2 => postcard_from_exact::<v2::Pczt>(&bytes[8..])
                .map(Into::into)
                .map_err(ParseError::Invalid),
            _ => Err(ParseError::UnknownVersion(version)),
        }?;

        pczt.orchard
            .validate_orchard_note_plaintext_versions()
            .map_err(ParseError::NotePlaintextVersion)?;
        #[cfg(zcash_unstable = "nu6.3")]
        pczt.ironwood
            .validate_ironwood_note_plaintext_versions()
            .map_err(ParseError::NotePlaintextVersion)?;

        Ok(pczt)
    }

    /// Serializes this PCZT.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(MAGIC_BYTES);
        bytes.extend_from_slice(&PCZT_VERSION_2.to_le_bytes());
        postcard::to_extend(&v2::Pczt::from(self), bytes).expect("can serialize into memory")
    }

    /// Serializes this PCZT using the original version 1 encoding.
    ///
    /// The v1 encoding cannot represent transaction version 6, Ironwood bundle
    /// data, or Orchard-shaped note plaintext versions other than v2. Use
    /// [`Pczt::serialize`] for normal output.
    pub fn serialize_legacy_v1(&self) -> Result<Vec<u8>, LegacyV1SerializeError> {
        if self.global.tx_version != zcash_protocol::constants::V5_TX_VERSION
            || self.global.version_group_id != zcash_protocol::constants::V5_VERSION_GROUP_ID
        {
            return Err(LegacyV1SerializeError::UnsupportedTxVersion {
                tx_version: self.global.tx_version,
                version_group_id: self.global.version_group_id,
            });
        }

        self.orchard.validate_orchard_note_plaintext_versions()?;
        if self.orchard.flags & !0b0000_0011 != 0 {
            return Err(LegacyV1SerializeError::OrchardFlags {
                flags: self.orchard.flags,
            });
        }

        #[cfg(zcash_unstable = "nu6.3")]
        if !self.ironwood.actions.is_empty()
            || self.ironwood.flags != IRONWOOD_SPENDS_AND_OUTPUTS_ENABLED
            || self.ironwood.value_sum != (0, true)
            || self.ironwood.anchor != EMPTY_IRONWOOD_ANCHOR
            || self.ironwood.zkproof.is_some()
            || self.ironwood.bsk.is_some()
        {
            return Err(LegacyV1SerializeError::IronwoodBundlePresent);
        }

        let legacy = v1::Pczt {
            global: self.global.clone(),
            transparent: self.transparent.clone(),
            sapling: self.sapling.clone(),
            orchard: v1::Bundle {
                actions: self
                    .orchard
                    .actions
                    .iter()
                    .cloned()
                    .map(|action| v1::Action {
                        cv_net: action.cv_net,
                        spend: v1::Spend {
                            nullifier: action.spend.nullifier,
                            rk: action.spend.rk,
                            spend_auth_sig: action.spend.spend_auth_sig,
                            recipient: action.spend.recipient,
                            value: action.spend.value,
                            rho: action.spend.rho,
                            rseed: action.spend.rseed,
                            fvk: action.spend.fvk,
                            witness: action.spend.witness,
                            alpha: action.spend.alpha,
                            zip32_derivation: action.spend.zip32_derivation,
                            dummy_sk: action.spend.dummy_sk,
                            proprietary: action.spend.proprietary,
                        },
                        output: v1::Output {
                            cmx: action.output.cmx,
                            ephemeral_key: action.output.ephemeral_key,
                            enc_ciphertext: action.output.enc_ciphertext,
                            out_ciphertext: action.output.out_ciphertext,
                            recipient: action.output.recipient,
                            value: action.output.value,
                            rseed: action.output.rseed,
                            ock: action.output.ock,
                            zip32_derivation: action.output.zip32_derivation,
                            user_address: action.output.user_address,
                            proprietary: action.output.proprietary,
                        },
                        rcv: action.rcv,
                    })
                    .collect(),
                flags: self.orchard.flags,
                value_sum: self.orchard.value_sum,
                anchor: self.orchard.anchor,
                zkproof: self.orchard.zkproof.clone(),
                bsk: self.orchard.bsk,
            },
        };

        let mut bytes = vec![];
        bytes.extend_from_slice(MAGIC_BYTES);
        bytes.extend_from_slice(&PCZT_VERSION_1.to_le_bytes());
        Ok(postcard::to_extend(&legacy, bytes).expect("can serialize into memory"))
    }

    /// Parses this PCZT's bundles and constructs a `TransactionData` using caller-provided
    /// bundle extraction closures.
    ///
    /// This handles bundle parsing, version validation, consensus branch ID parsing,
    /// lock time computation, and final assembly, delegating bundle extraction to the
    /// caller via closures that receive references to the parsed bundles.
    #[cfg(any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"))]
    pub(crate) fn extract_tx_data<A, E>(
        self,
        extract_transparent: impl FnOnce(
            &::transparent::pczt::Bundle,
        ) -> Result<
            Option<::transparent::bundle::Bundle<A::TransparentAuth>>,
            E,
        >,
        extract_sapling: impl FnOnce(
            &::sapling::pczt::Bundle,
        ) -> Result<
            Option<::sapling::Bundle<A::SaplingAuth, zcash_protocol::value::ZatBalance>>,
            E,
        >,
        extract_orchard: impl FnOnce(
            &::orchard::pczt::Bundle,
        ) -> Result<
            Option<::orchard::Bundle<A::OrchardAuth, zcash_protocol::value::ZatBalance>>,
            E,
        >,
        #[cfg(zcash_unstable = "nu6.3")] extract_ironwood: impl FnOnce(
            &::orchard::pczt::Bundle,
        ) -> Result<
            Option<::orchard::Bundle<A::OrchardAuth, zcash_protocol::value::ZatBalance>>,
            E,
        >,
    ) -> Result<ParsedPczt<A>, E>
    where
        A: Authorization,
        E: From<ExtractError>,
    {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood,
        } = self;

        let version = match (global.tx_version, global.version_group_id) {
            (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(TxVersion::V5),
            #[cfg(zcash_unstable = "nu6.3")]
            (V6_TX_VERSION, V6_VERSION_GROUP_ID) => Ok(TxVersion::V6),
            (version, version_group_id) => Err(ExtractError::UnsupportedTxVersion {
                version,
                version_group_id,
            }),
        }?;

        let consensus_branch_id = BranchId::try_from(global.consensus_branch_id)
            .map_err(|_| ExtractError::UnknownConsensusBranchId)?;
        if !version.valid_in_branch(consensus_branch_id) {
            return Err(ExtractError::VersionInvalidForConsensusBranch {
                version,
                consensus_branch_id,
            }
            .into());
        }

        #[cfg(zcash_unstable = "nu6.3")]
        let ironwood = if version.has_ironwood() {
            ironwood
                .into_parsed_ironwood()
                .map_err(ExtractError::IronwoodParse)?
        } else {
            if !ironwood.actions.is_empty() {
                return Err(ExtractError::IronwoodRequiresV6.into());
            }

            crate::empty_ironwood_bundle()
                .into_parsed_ironwood()
                .map_err(ExtractError::IronwoodParse)?
        };

        #[cfg(feature = "orchard")]
        let orchard_bundle_format = crate::orchard_bundle_format(&global);

        let transparent = transparent
            .into_parsed()
            .map_err(ExtractError::TransparentParse)?;
        let sapling = sapling.into_parsed().map_err(ExtractError::SaplingParse)?;
        let orchard = orchard
            .into_parsed_orchard(orchard_bundle_format)
            .map_err(ExtractError::OrchardParse)?;

        let lock_time = determine_lock_time(&global, transparent.inputs())
            .ok_or(ExtractError::IncompatibleLockTimes)?;

        let transparent_bundle = extract_transparent(&transparent)?;
        let sapling_bundle = extract_sapling(&sapling)?;
        let orchard_bundle = extract_orchard(&orchard)?;
        #[cfg(zcash_unstable = "nu6.3")]
        let ironwood_bundle = if version.has_ironwood() {
            extract_ironwood(&ironwood)?
        } else {
            None
        };

        #[cfg(not(zcash_unstable = "nu6.3"))]
        let tx_data = TransactionData::from_parts(
            version,
            consensus_branch_id,
            lock_time,
            global.expiry_height.into(),
            #[cfg(all(
                any(zcash_unstable = "nu7", zcash_unstable = "zfuture"),
                feature = "zip-233"
            ))]
            Zatoshis::ZERO,
            transparent_bundle,
            None,
            sapling_bundle,
            orchard_bundle,
        );

        #[cfg(zcash_unstable = "nu6.3")]
        let tx_data = match version {
            TxVersion::V5 => TransactionData::from_parts(
                version,
                consensus_branch_id,
                lock_time,
                global.expiry_height.into(),
                #[cfg(all(
                    any(zcash_unstable = "nu7", zcash_unstable = "zfuture"),
                    feature = "zip-233"
                ))]
                Zatoshis::ZERO,
                transparent_bundle,
                None,
                sapling_bundle,
                orchard_bundle,
            ),
            TxVersion::V6 => TransactionData::from_parts_v6(
                consensus_branch_id,
                lock_time,
                global.expiry_height.into(),
                transparent_bundle,
                sapling_bundle,
                orchard_bundle,
                ironwood_bundle,
            ),
            _ => unreachable!("PCZT extraction only accepts v5 and v6"),
        };

        Ok(ParsedPczt {
            global,
            transparent,
            sapling,
            orchard,
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood,
            tx_data,
        })
    }

    /// Gets the effects of this transaction.
    #[cfg(any(feature = "io-finalizer", feature = "signer"))]
    pub fn into_effects(self) -> Result<TransactionData<EffectsOnly>, ExtractError> {
        self.extract_tx_data(
            |t| {
                t.extract_effects()
                    .map_err(ExtractError::TransparentExtract)
            },
            |s| s.extract_effects().map_err(ExtractError::SaplingExtract),
            |o| o.extract_effects().map_err(ExtractError::OrchardExtract),
            #[cfg(zcash_unstable = "nu6.3")]
            |i| i.extract_effects().map_err(ExtractError::IronwoodExtract),
        )
        .map(|parsed| parsed.tx_data)
    }
}

/// The result of parsing a PCZT and constructing its `TransactionData`.
#[cfg(any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"))]
#[cfg_attr(
    not(any(feature = "io-finalizer", feature = "signer")),
    allow(dead_code)
)]
pub(crate) struct ParsedPczt<A: Authorization> {
    pub(crate) global: Global,
    pub(crate) transparent: ::transparent::pczt::Bundle,
    pub(crate) sapling: ::sapling::pczt::Bundle,
    pub(crate) orchard: ::orchard::pczt::Bundle,
    #[cfg(zcash_unstable = "nu6.3")]
    pub(crate) ironwood: ::orchard::pczt::Bundle,
    pub(crate) tx_data: TransactionData<A>,
}

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
pub struct EffectsOnly;

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
impl Authorization for EffectsOnly {
    type TransparentAuth = ::transparent::bundle::EffectsOnly;
    type SaplingAuth = ::sapling::bundle::EffectsOnly;
    type OrchardAuth = ::orchard::bundle::EffectsOnly;
    #[cfg(zcash_unstable = "zfuture")]
    type TzeAuth = core::convert::Infallible;
}

/// Helper to produce the correct sighash for a PCZT.
///
/// This is intended for use exclusively in the context of callbacks to
/// `extract_tx_data`, which performs the PCZT transaction version check.
#[cfg(any(feature = "io-finalizer", feature = "signer"))]
pub(crate) fn sighash(
    tx_data: &TransactionData<EffectsOnly>,
    signable_input: &SignableInput,
    txid_parts: &TxDigests<Blake2bHash>,
) -> [u8; 32] {
    match tx_data.version() {
        TxVersion::V5 => v5_signature_hash(tx_data, signable_input, txid_parts),
        #[cfg(zcash_unstable = "nu6.3")]
        TxVersion::V6 => v6_signature_hash(tx_data, signable_input, txid_parts),
        _ => unreachable!("PCZT extraction only accepts v5 and v6"),
    }
    .as_ref()
    .try_into()
    .expect("correct length")
}

/// Errors that can occur while parsing PCZT bundles and extracting transaction data.
#[cfg(any(feature = "io-finalizer", feature = "signer", feature = "tx-extractor"))]
#[derive(Debug)]
#[non_exhaustive]
pub enum ExtractError {
    /// The PCZT's transparent inputs have incompatible lock time requirements.
    IncompatibleLockTimes,
    /// The PCZT contains an Ironwood bundle but does not specify transaction version 6.
    #[cfg(zcash_unstable = "nu6.3")]
    IronwoodRequiresV6,
    /// An error occurred extracting the Ironwood protocol bundle from the Ironwood PCZT bundle.
    #[cfg(zcash_unstable = "nu6.3")]
    IronwoodExtract(::orchard::pczt::TxExtractorError),
    /// An error occurred parsing the Ironwood PCZT bundle from the PCZT data.
    #[cfg(zcash_unstable = "nu6.3")]
    IronwoodParse(crate::orchard::BundleParseError),
    /// An error occurred extracting the Orchard protocol bundle from the Orchard PCZT bundle.
    OrchardExtract(::orchard::pczt::TxExtractorError),
    /// An error occurred parsing the Orchard PCZT bundle from the PCZT data.
    OrchardParse(crate::orchard::BundleParseError),
    /// An error occurred extracting the Sapling protocol bundle from the Sapling PCZT bundle.
    SaplingExtract(::sapling::pczt::TxExtractorError),
    /// An error occurred parsing the Sapling PCZT bundle from the PCZT data.
    SaplingParse(::sapling::pczt::ParseError),
    /// An error occurred extracting the transparent protocol bundle from the transparent PCZT bundle.
    TransparentExtract(::transparent::pczt::TxExtractorError),
    /// An error occurred parsing the transparent PCZT bundle from the PCZT data.
    TransparentParse(::transparent::pczt::ParseError),
    /// The consensus branch ID requested by the PCZT does not correspond to a known network upgrade.
    UnknownConsensusBranchId,
    /// The transaction version is not valid for the specified consensus branch ID.
    VersionInvalidForConsensusBranch {
        version: TxVersion,
        consensus_branch_id: BranchId,
    },
    /// The PCZT specifies an unsupported transaction version.
    UnsupportedTxVersion { version: u32, version_group_id: u32 },
}

/// Errors that can occur while parsing a PCZT.
#[derive(Debug)]
pub enum ParseError {
    /// The bytes do not contain a PCZT.
    NotPczt,
    /// The PCZT encoding was invalid.
    Invalid(postcard::Error),
    /// The PCZT uses a note plaintext version that is not valid for its pool.
    NotePlaintextVersion(orchard::NotePlaintextVersionError),
    /// The bytes are too short to contain a PCZT.
    TooShort,
    /// The PCZT has an unknown version.
    UnknownVersion(u32),
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    use zcash_protocol::constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID};
    use zcash_protocol::{
        consensus::BranchId,
        constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID},
    };

    use super::*;

    #[cfg(feature = "orchard")]
    fn pczt_with_one_orchard_action() -> Pczt {
        Pczt {
            global: common::Global {
                tx_version: V5_TX_VERSION,
                version_group_id: V5_VERSION_GROUP_ID,
                consensus_branch_id: u32::from(BranchId::Nu5),
                fallback_lock_time: None,
                expiry_height: 0,
                coin_type: 1,
                tx_modifiable: 0,
                proprietary: BTreeMap::new(),
            },
            transparent: transparent::Bundle {
                inputs: vec![],
                outputs: vec![],
            },
            sapling: sapling::Bundle {
                spends: vec![],
                outputs: vec![],
                value_sum: 0,
                anchor: [0; 32],
                bsk: None,
            },
            orchard: orchard::Bundle {
                actions: vec![orchard::Action {
                    cv_net: [1; 32],
                    spend: orchard::Spend {
                        nullifier: [2; 32],
                        rk: [3; 32],
                        spend_auth_sig: None,
                        recipient: None,
                        value: Some(1000),
                        rho: Some([4; 32]),
                        rseed: Some([5; 32]),
                        note_version: orchard::NotePlaintextVersion::V2,
                        fvk: None,
                        witness: None,
                        alpha: None,
                        zip32_derivation: None,
                        dummy_sk: None,
                        proprietary: BTreeMap::new(),
                    },
                    output: orchard::Output {
                        cmx: [6; 32],
                        note_version: orchard::NotePlaintextVersion::V2,
                        ephemeral_key: [7; 32],
                        enc_ciphertext: vec![8; 580],
                        out_ciphertext: vec![9; 80],
                        recipient: None,
                        value: Some(1000),
                        rseed: Some([10; 32]),
                        ock: None,
                        zip32_derivation: None,
                        user_address: None,
                        proprietary: BTreeMap::new(),
                    },
                    rcv: None,
                }],
                flags: 0,
                value_sum: (0, false),
                anchor: [0; 32],
                zkproof: None,
                bsk: None,
            },
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood: empty_ironwood_bundle(),
        }
    }

    #[cfg(feature = "orchard")]
    fn orchard_witness(action_index: usize, position: u32) -> roles::updater::OrchardSpendWitness {
        roles::updater::OrchardSpendWitness::parse(action_index, position, [[0; 32]; 32]).unwrap()
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn set_orchard_style_note_version(
        bundle: &mut orchard::Bundle,
        version: orchard::NotePlaintextVersion,
    ) {
        for action in bundle.actions.iter_mut() {
            action.spend.note_version = version;
            action.output.note_version = version;
        }
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn pczt_with_one_v6_orchard_action() -> Pczt {
        let mut pczt = pczt_with_one_orchard_action();
        pczt.global.tx_version = V6_TX_VERSION;
        pczt.global.version_group_id = V6_VERSION_GROUP_ID;
        pczt.global.consensus_branch_id = u32::from(BranchId::Nu6_3);
        pczt
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn pczt_with_one_v5_ironwood_action() -> Pczt {
        let mut pczt = pczt_with_one_v6_orchard_action();
        pczt.ironwood = pczt.orchard.clone();
        set_orchard_style_note_version(&mut pczt.ironwood, orchard::NotePlaintextVersion::V3);
        pczt.global.tx_version = V5_TX_VERSION;
        pczt.global.version_group_id = V5_VERSION_GROUP_ID;
        pczt.global.consensus_branch_id = u32::from(BranchId::Nu5);
        pczt
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn pczt_with_one_v6_pre_nu6_3_ironwood_action() -> Pczt {
        let mut pczt = pczt_with_one_v6_orchard_action();
        pczt.ironwood = pczt.orchard.clone();
        set_orchard_style_note_version(&mut pczt.ironwood, orchard::NotePlaintextVersion::V3);
        pczt.global.consensus_branch_id = u32::from(BranchId::Nu5);
        pczt
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn assert_v6_consensus_branch_parse_error(
        err: crate::orchard::BundleParseError,
        expected: common::V6ConsensusBranchError,
    ) {
        assert!(matches!(
            err,
            crate::orchard::BundleParseError::V6ConsensusBranch(e) if e == expected
        ));
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    fn valid_anchor(byte: u8) -> ::orchard::Anchor {
        let mut bytes = [0; 32];
        bytes[0] = byte;
        ::orchard::Anchor::from_bytes(bytes).into_option().unwrap()
    }

    fn encoded_v1_pczt() -> Vec<u8> {
        let legacy = v1::Pczt {
            global: common::Global {
                tx_version: V5_TX_VERSION,
                version_group_id: V5_VERSION_GROUP_ID,
                consensus_branch_id: u32::from(BranchId::Nu5),
                fallback_lock_time: None,
                expiry_height: 0,
                coin_type: 1,
                tx_modifiable: 0,
                proprietary: BTreeMap::new(),
            },
            transparent: transparent::Bundle {
                inputs: vec![],
                outputs: vec![],
            },
            sapling: sapling::Bundle {
                spends: vec![],
                outputs: vec![],
                value_sum: 0,
                anchor: [0; 32],
                bsk: None,
            },
            orchard: v1::Bundle {
                actions: vec![v1::Action {
                    cv_net: [1; 32],
                    spend: v1::Spend {
                        nullifier: [2; 32],
                        rk: [3; 32],
                        spend_auth_sig: None,
                        recipient: None,
                        value: Some(1000),
                        rho: Some([4; 32]),
                        rseed: Some([5; 32]),
                        fvk: None,
                        witness: None,
                        alpha: None,
                        zip32_derivation: None,
                        dummy_sk: None,
                        proprietary: BTreeMap::new(),
                    },
                    output: v1::Output {
                        cmx: [6; 32],
                        ephemeral_key: [7; 32],
                        enc_ciphertext: vec![8; 580],
                        out_ciphertext: vec![9; 80],
                        recipient: None,
                        value: Some(1000),
                        rseed: Some([10; 32]),
                        ock: None,
                        zip32_derivation: None,
                        user_address: None,
                        proprietary: BTreeMap::new(),
                    },
                    rcv: None,
                }],
                flags: 0,
                value_sum: (0, false),
                anchor: [0; 32],
                zkproof: None,
                bsk: None,
            },
        };

        let mut encoded = vec![];
        encoded.extend_from_slice(MAGIC_BYTES);
        encoded.extend_from_slice(&PCZT_VERSION_1.to_le_bytes());
        postcard::to_extend(&legacy, encoded).unwrap()
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn v5_orchard_bundle_uses_pre_nu6_3_flags() {
        let mut pczt = pczt_with_one_orchard_action();
        pczt.orchard.actions.clear();
        pczt.orchard.flags = 0b0000_0011;
        pczt.orchard.value_sum = (0, true);
        pczt.orchard.anchor = ::orchard::Anchor::empty_tree().to_bytes();

        let bundle_format = orchard_bundle_format(&pczt.global);
        assert_eq!(bundle_format, ::orchard::bundle::BundleFormat::PreNu6_3);

        let parsed = pczt
            .orchard
            .clone()
            .into_parsed_orchard(bundle_format)
            .unwrap();
        assert_eq!(parsed.flags().to_byte(bundle_format), Some(0b0000_0011));

        let serialized = orchard::Bundle::serialize_from(parsed, bundle_format);
        assert_eq!(serialized.flags, 0b0000_0011);
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn serialize_legacy_v1_round_trips_to_current_pczt() {
        let pczt = pczt_with_one_orchard_action();
        let encoded = pczt.serialize_legacy_v1().unwrap();

        assert_eq!(&encoded[..4], MAGIC_BYTES);
        assert_eq!(
            u32::from_le_bytes(encoded[4..8].try_into().unwrap()),
            PCZT_VERSION_1
        );

        let reparsed = Pczt::parse(&encoded).unwrap();
        assert_eq!(reparsed.orchard.actions.len(), 1);
        assert_eq!(
            reparsed.orchard.actions[0].spend.note_version,
            orchard::NotePlaintextVersion::V2
        );
        assert_eq!(
            reparsed.orchard.actions[0].output.note_version,
            orchard::NotePlaintextVersion::V2
        );
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn serialize_legacy_v1_preserves_orchard_flags_for_old_v5_verifiers() {
        let mut pczt = pczt_with_one_orchard_action();
        pczt.orchard.flags = 0b0000_0011;

        let encoded = pczt.serialize_legacy_v1().unwrap();
        let reparsed = Pczt::parse(&encoded).unwrap();

        assert_eq!(reparsed.orchard.flags, 0b0000_0011);
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn serialize_legacy_v1_rejects_non_legacy_orchard_flags() {
        let mut pczt = pczt_with_one_orchard_action();
        pczt.orchard.flags = 0b0000_0111;

        assert!(matches!(
            pczt.serialize_legacy_v1(),
            Err(LegacyV1SerializeError::OrchardFlags { flags: 0b0000_0111 })
        ));
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn serialize_legacy_v1_rejects_v3_orchard_note_plaintext_version() {
        let mut pczt = pczt_with_one_orchard_action();
        pczt.orchard.actions[0].spend.note_version = orchard::NotePlaintextVersion::V3;

        assert!(matches!(
            pczt.serialize_legacy_v1(),
            Err(LegacyV1SerializeError::NotePlaintextVersion(
                orchard::NotePlaintextVersionError::OrchardSpend {
                    action_index: 0,
                    version: orchard::NotePlaintextVersion::V3
                }
            ))
        ));
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn serialize_legacy_v1_rejects_ironwood_bundle_data() {
        let mut pczt = pczt_with_one_orchard_action();
        pczt.ironwood = pczt.orchard.clone();
        set_orchard_style_note_version(&mut pczt.ironwood, orchard::NotePlaintextVersion::V3);

        assert!(matches!(
            pczt.serialize_legacy_v1(),
            Err(LegacyV1SerializeError::IronwoodBundlePresent)
        ));
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn orchard_bundle_rejects_v3_spend_note_plaintext_version() {
        let mut bundle = pczt_with_one_orchard_action().orchard;
        bundle.actions[0].spend.note_version = orchard::NotePlaintextVersion::V3;

        assert!(matches!(
            bundle.validate_orchard_note_plaintext_versions(),
            Err(orchard::NotePlaintextVersionError::OrchardSpend {
                action_index: 0,
                version: orchard::NotePlaintextVersion::V3
            })
        ));
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn orchard_bundle_rejects_v3_output_note_plaintext_version() {
        let mut bundle = pczt_with_one_orchard_action().orchard;
        bundle.actions[0].output.note_version = orchard::NotePlaintextVersion::V3;

        assert!(matches!(
            bundle.validate_orchard_note_plaintext_versions(),
            Err(orchard::NotePlaintextVersionError::OrchardOutput {
                action_index: 0,
                version: orchard::NotePlaintextVersion::V3
            })
        ));
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn ironwood_bundle_rejects_v2_spend_note_plaintext_version() {
        let mut bundle = pczt_with_one_orchard_action().orchard;
        bundle.actions[0].output.note_version = orchard::NotePlaintextVersion::V3;

        assert!(matches!(
            bundle.validate_ironwood_note_plaintext_versions(),
            Err(orchard::NotePlaintextVersionError::IronwoodSpend {
                action_index: 0,
                version: orchard::NotePlaintextVersion::V2
            })
        ));
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn ironwood_bundle_rejects_v2_output_note_plaintext_version() {
        let mut bundle = pczt_with_one_orchard_action().orchard;
        bundle.actions[0].spend.note_version = orchard::NotePlaintextVersion::V3;

        assert!(matches!(
            bundle.validate_ironwood_note_plaintext_versions(),
            Err(orchard::NotePlaintextVersionError::IronwoodOutput {
                action_index: 0,
                version: orchard::NotePlaintextVersion::V2
            })
        ));
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn parse_rejects_v3_orchard_note_plaintext_version() {
        let mut pczt = pczt_with_one_orchard_action();
        pczt.orchard.actions[0].spend.note_version = orchard::NotePlaintextVersion::V3;

        assert!(matches!(
            Pczt::parse(&pczt.serialize()),
            Err(ParseError::NotePlaintextVersion(
                orchard::NotePlaintextVersionError::OrchardSpend {
                    action_index: 0,
                    version: orchard::NotePlaintextVersion::V3
                }
            ))
        ));
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn parse_rejects_v2_ironwood_note_plaintext_version() {
        let mut pczt = pczt_with_one_v6_orchard_action();
        pczt.ironwood = pczt.orchard.clone();

        assert!(matches!(
            Pczt::parse(&pczt.serialize()),
            Err(ParseError::NotePlaintextVersion(
                orchard::NotePlaintextVersionError::IronwoodSpend {
                    action_index: 0,
                    version: orchard::NotePlaintextVersion::V2
                }
            ))
        ));
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn updater_sets_orchard_witness() {
        use roles::updater::Updater;

        let updated = Updater::new(pczt_with_one_orchard_action())
            .set_orchard_spend_witnesses([orchard_witness(0, 7)])
            .unwrap()
            .finish();

        assert_eq!(
            updated.orchard().actions()[0].spend().witness,
            Some((7, [[0; 32]; 32]))
        );
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn updater_rejects_missing_orchard_witness_action() {
        use roles::updater::{OrchardSpendWitnessError, Updater};

        let result = Updater::new(pczt_with_one_orchard_action())
            .set_orchard_spend_witnesses([orchard_witness(1, 7)]);

        assert!(matches!(
            result,
            Err(OrchardSpendWitnessError::InvalidActionIndex(1))
        ));
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn updater_rejects_invalid_orchard_witness() {
        use roles::updater::{OrchardSpendWitness, OrchardSpendWitnessError};

        let result = OrchardSpendWitness::parse(0, 7, [[0xff; 32]; 32]);

        assert!(matches!(
            result,
            Err(OrchardSpendWitnessError::InvalidWitness)
        ));
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn updater_rejects_orchard_witness_after_proof() {
        use roles::updater::{OrchardSpendWitnessError, Updater};

        let mut pczt = pczt_with_one_orchard_action();
        pczt.orchard.zkproof = Some(vec![0; 192]);

        let result = Updater::new(pczt).set_orchard_spend_witnesses([orchard_witness(0, 7)]);

        assert!(matches!(
            result,
            Err(OrchardSpendWitnessError::ProofAlreadyPresent)
        ));
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn updater_sets_v6_orchard_anchor() {
        use roles::updater::Updater;

        let anchor = valid_anchor(1);
        let updated = Updater::new(pczt_with_one_v6_orchard_action())
            .set_v6_orchard_anchor(anchor)
            .unwrap()
            .finish();

        assert_eq!(*updated.orchard().anchor(), anchor.to_bytes());
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn updater_rejects_v5_orchard_anchor_update() {
        use roles::updater::{OrchardSpendWitnessError, Updater};

        let result =
            Updater::new(pczt_with_one_orchard_action()).set_v6_orchard_anchor(valid_anchor(1));

        assert!(matches!(result, Err(OrchardSpendWitnessError::RequiresV6)));
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn updater_rejects_v6_orchard_anchor_update_for_pre_nu6_3_branch() {
        use roles::updater::{OrchardSpendWitnessError, Updater};

        let mut pczt = pczt_with_one_v6_orchard_action();
        pczt.global.consensus_branch_id = u32::from(BranchId::Nu5);
        let result = Updater::new(pczt).set_v6_orchard_anchor(valid_anchor(1));

        assert!(matches!(
            result,
            Err(OrchardSpendWitnessError::V6ConsensusBranch(
                common::V6ConsensusBranchError::VersionInvalidForConsensusBranch {
                    consensus_branch_id: BranchId::Nu5
                }
            ))
        ));
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn extraction_rejects_v5_pczt_with_ironwood_actions() {
        let mut pczt = pczt_with_one_v6_orchard_action();
        pczt.ironwood = pczt.orchard.clone();
        set_orchard_style_note_version(&mut pczt.ironwood, orchard::NotePlaintextVersion::V3);
        pczt.global.tx_version = V5_TX_VERSION;
        pczt.global.version_group_id = V5_VERSION_GROUP_ID;
        pczt.global.consensus_branch_id = u32::from(BranchId::Nu5);

        assert!(matches!(
            pczt.into_effects(),
            Err(ExtractError::IronwoodRequiresV6)
        ));
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn extraction_rejects_v6_pczt_with_pre_nu6_3_branch_id() {
        let mut pczt = pczt_with_one_v6_orchard_action();
        pczt.global.consensus_branch_id = u32::from(BranchId::Nu5);

        assert!(matches!(
            pczt.into_effects(),
            Err(ExtractError::VersionInvalidForConsensusBranch {
                version: zcash_primitives::transaction::TxVersion::V6,
                consensus_branch_id: BranchId::Nu5,
            })
        ));
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn direct_ironwood_roles_reject_v5_pczt_before_callbacks() {
        use roles::{low_level_signer, updater::Updater, verifier::Verifier};

        let pczt = pczt_with_one_v5_ironwood_action();

        let mut update_called = false;
        let update_result = Updater::new(pczt.clone()).update_ironwood_with(|_| {
            update_called = true;
            Ok(())
        });
        match update_result {
            Err(roles::updater::OrchardError::Parser(e)) => assert_v6_consensus_branch_parse_error(
                e,
                common::V6ConsensusBranchError::RequiresV6,
            ),
            Err(_) => panic!("expected v6/NU6.3 parse error"),
            Ok(_) => panic!("expected v6/NU6.3 parse error"),
        }
        assert!(!update_called);

        let mut verify_called = false;
        let verify_result = Verifier::new(pczt.clone()).with_ironwood(|_| {
            verify_called = true;
            Ok::<(), roles::verifier::OrchardError<()>>(())
        });
        match verify_result {
            Err(roles::verifier::OrchardError::Parse(e)) => assert_v6_consensus_branch_parse_error(
                e,
                common::V6ConsensusBranchError::RequiresV6,
            ),
            Err(_) => panic!("expected v6/NU6.3 parse error"),
            Ok(_) => panic!("expected v6/NU6.3 parse error"),
        }
        assert!(!verify_called);

        let mut sign_called = false;
        let sign_result = low_level_signer::Signer::new(pczt).sign_ironwood_with(
            |_, _, _| -> Result<(), crate::orchard::BundleParseError> {
                sign_called = true;
                Ok(())
            },
        );
        match sign_result {
            Err(e) => assert_v6_consensus_branch_parse_error(
                e,
                common::V6ConsensusBranchError::RequiresV6,
            ),
            Ok(_) => panic!("expected v6/NU6.3 parse error"),
        }
        assert!(!sign_called);
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn prover_rejects_v5_ironwood_proof() {
        use roles::prover::Prover;

        let pk = ::orchard::circuit::ProvingKey::build(
            ::orchard::BundleProtocol::IronwoodPostNu6_3.circuit_version(),
        );
        let result = Prover::new(pczt_with_one_v5_ironwood_action()).create_ironwood_proof(&pk);

        match result {
            Err(roles::prover::OrchardError::Parser(e)) => assert_v6_consensus_branch_parse_error(
                e,
                common::V6ConsensusBranchError::RequiresV6,
            ),
            Err(_) => panic!("expected v6/NU6.3 parse error"),
            Ok(_) => panic!("expected v6/NU6.3 parse error"),
        }
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn direct_ironwood_roles_reject_v6_pczt_for_pre_nu6_3_branch() {
        use roles::{prover::Prover, updater::Updater, verifier::Verifier};

        let pczt = pczt_with_one_v6_pre_nu6_3_ironwood_action();
        let expected = common::V6ConsensusBranchError::VersionInvalidForConsensusBranch {
            consensus_branch_id: BranchId::Nu5,
        };

        assert!(!Prover::new(pczt.clone()).requires_ironwood_proof());

        let update_result = Updater::new(pczt.clone()).update_ironwood_with(|_| Ok(()));
        match update_result {
            Err(roles::updater::OrchardError::Parser(e)) => {
                assert_v6_consensus_branch_parse_error(e, expected)
            }
            Err(_) => panic!("expected v6/NU6.3 parse error"),
            Ok(_) => panic!("expected v6/NU6.3 parse error"),
        }

        let verify_result = Verifier::new(pczt.clone())
            .with_ironwood(|_| Ok::<(), roles::verifier::OrchardError<()>>(()));
        match verify_result {
            Err(roles::verifier::OrchardError::Parse(e)) => {
                assert_v6_consensus_branch_parse_error(e, expected)
            }
            Err(_) => panic!("expected v6/NU6.3 parse error"),
            Ok(_) => panic!("expected v6/NU6.3 parse error"),
        }

        let pk = ::orchard::circuit::ProvingKey::build(
            ::orchard::BundleProtocol::IronwoodPostNu6_3.circuit_version(),
        );
        let proof_result = Prover::new(pczt.clone()).create_ironwood_proof(&pk);
        match proof_result {
            Err(roles::prover::OrchardError::Parser(e)) => {
                assert_v6_consensus_branch_parse_error(e, expected)
            }
            Err(_) => panic!("expected v6/NU6.3 parse error"),
            Ok(_) => panic!("expected v6/NU6.3 parse error"),
        }

        let witness_result =
            Updater::new(pczt.clone()).set_ironwood_spend_witnesses([orchard_witness(0, 9)]);
        assert!(matches!(
            witness_result,
            Err(roles::updater::OrchardSpendWitnessError::V6ConsensusBranch(e)) if e == expected
        ));

        let anchor_result = Updater::new(pczt).set_v6_ironwood_anchor(valid_anchor(2));
        assert!(matches!(
            anchor_result,
            Err(roles::updater::OrchardSpendWitnessError::V6ConsensusBranch(e)) if e == expected
        ));
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn updater_sets_ironwood_anchor_and_witness() {
        use roles::updater::Updater;

        let mut pczt = pczt_with_one_v6_orchard_action();
        pczt.ironwood = pczt.orchard.clone();
        set_orchard_style_note_version(&mut pczt.ironwood, orchard::NotePlaintextVersion::V3);

        let anchor = valid_anchor(2);
        let updated = Updater::new(pczt)
            .set_v6_ironwood_anchor(anchor)
            .unwrap()
            .set_ironwood_spend_witnesses([orchard_witness(0, 9)])
            .unwrap()
            .finish();

        assert_eq!(*updated.ironwood().anchor(), anchor.to_bytes());
        assert_eq!(
            updated.ironwood().actions()[0].spend().witness,
            Some((9, [[0; 32]; 32]))
        );
    }

    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    #[test]
    fn updater_rejects_v2_ironwood_witness() {
        use roles::updater::{OrchardSpendWitnessError, Updater};

        let mut pczt = pczt_with_one_v6_orchard_action();
        pczt.ironwood = pczt.orchard.clone();

        let result = Updater::new(pczt).set_ironwood_spend_witnesses([orchard_witness(0, 9)]);

        assert!(matches!(
            result,
            Err(OrchardSpendWitnessError::NotePlaintextVersion(
                orchard::NotePlaintextVersionError::IronwoodSpend {
                    action_index: 0,
                    version: orchard::NotePlaintextVersion::V2
                }
            ))
        ));
    }

    #[test]
    fn parse_v1_defaults_orchard_note_versions() {
        let encoded = encoded_v1_pczt();
        let parsed = Pczt::parse(&encoded).unwrap();
        let action = &parsed.orchard().actions()[0];
        assert_eq!(
            *action.spend().note_version(),
            orchard::NotePlaintextVersion::V2
        );
        assert_eq!(
            *action.output().note_version(),
            orchard::NotePlaintextVersion::V2
        );

        #[cfg(zcash_unstable = "nu6.3")]
        {
            let fallback = crate::empty_ironwood_bundle();
            assert!(parsed.ironwood.actions.is_empty());
            assert!(fallback.actions.is_empty());
            assert_eq!(parsed.ironwood.flags, fallback.flags);
            assert_eq!(parsed.ironwood.value_sum, fallback.value_sum);
            assert_eq!(parsed.ironwood.anchor, fallback.anchor);
            assert_eq!(parsed.ironwood.zkproof, fallback.zkproof);
            assert_eq!(parsed.ironwood.bsk, fallback.bsk);
        }

        assert_eq!(
            u32::from_le_bytes(parsed.serialize()[4..8].try_into().unwrap()),
            PCZT_VERSION_2
        );
    }

    #[test]
    fn parse_v1_rejects_trailing_bytes() {
        let mut encoded = encoded_v1_pczt();
        encoded.push(0);

        assert!(matches!(
            Pczt::parse(&encoded),
            Err(ParseError::Invalid(postcard::Error::DeserializeBadEncoding))
        ));
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn parse_v2_rejects_trailing_bytes() {
        let mut encoded = pczt_with_one_orchard_action().serialize();
        encoded.push(0);

        assert!(matches!(Pczt::parse(&encoded), Err(ParseError::Invalid(_))));
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn parse_preserves_empty_ironwood_metadata_for_v5() {
        let mut pczt =
            roles::creator::Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [0; 32], [0; 32])
                .build();
        pczt.ironwood.anchor = [1; 32];

        let encoded = pczt.serialize();
        let parsed = Pczt::parse(&encoded).unwrap();
        assert!(parsed.ironwood.actions.is_empty());
        assert_eq!(parsed.ironwood.anchor, [1; 32]);
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn serialize_v6_with_empty_actions_preserves_ironwood_metadata() {
        let anchor = [1; 32];
        let pczt = roles::creator::Creator::new_v6(
            BranchId::Nu6_3.into(),
            10_000_000,
            133,
            [0; 32],
            [0; 32],
            anchor,
        )
        .build();

        let parsed = Pczt::parse(&pczt.serialize()).unwrap();

        assert!(parsed.ironwood.actions.is_empty());
        assert_eq!(*parsed.ironwood().anchor(), anchor);
    }
}

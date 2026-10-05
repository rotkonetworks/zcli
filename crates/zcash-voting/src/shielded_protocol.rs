use orchard::bundle::BundleVersion;
use orchard::note::NoteVersion;
#[cfg(feature = "native")]
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::consensus::{BranchId, OrchardProtocolRevision};

use crate::types::VotingError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VotingShieldedProtocol {
    Ironwood,
}

impl VotingShieldedProtocol {
    /// The voting protocol for notes created under `branch_id`.
    ///
    /// Gated on the Orchard protocol revision the branch selects, not on the
    /// exact branch: every upgrade from NU6.3 on (NU7 included) keeps the
    /// Ironwood pool and its V3 notes. Branches without one fail closed.
    pub(crate) fn for_branch_id(branch_id: BranchId) -> Result<Self, VotingError> {
        if branch_id.orchard_protocol_revision() == Some(OrchardProtocolRevision::V3) {
            return Ok(Self::Ironwood);
        }

        Err(VotingError::InvalidInput {
            message: format!(
                "zcash voting needs Ironwood (V3) notes, which exist from NU6.3 on; \
                 consensus branch {branch_id:?} has no Ironwood pool"
            ),
        })
    }

    #[cfg(feature = "native")]
    pub(crate) fn for_height<P: Parameters>(
        params: &P,
        height: BlockHeight,
    ) -> Result<Self, VotingError> {
        Self::for_branch_id(BranchId::for_height(params, height))
    }

    pub(crate) fn bundle_version(self) -> BundleVersion {
        match self {
            Self::Ironwood => BundleVersion::ironwood_v3(),
        }
    }

    pub(crate) fn note_version(self) -> NoteVersion {
        match self {
            Self::Ironwood => NoteVersion::V3,
        }
    }

    #[cfg(feature = "native")]
    pub(crate) fn pool(self) -> &'static str {
        match self {
            Self::Ironwood => "ironwood",
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Ironwood => "Ironwood",
        }
    }
}

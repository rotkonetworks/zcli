//! HOT vote-casting free functions (delegation-independent crypto seam).
//!
//! The app-owned voting **hotkey** signs a vote commitment and builds the
//! helper-share payloads. This path uses **no cold key, no network, and no PIR**,
//! and it never opens a wallet / voting SQLite DB. Every input that a native
//! build would read from persisted round/delegation state is passed in by the
//! host instead — see [`CastVoteInputs`].
//!
//! IMPORTANT (delegation-phase provenance): all of `address_index`,
//! `total_note_value`, `gov_comm_rand`, `voting_round_id`, `ea_pk`,
//! `proposal_authority`, and the [`VanWitness`] fields are produced/persisted by
//! the **delegation** phase (they mirror `queries::load_zkp2_inputs` on native).
//! A first vote is impossible without prior delegation state; this module does
//! not, and must not, synthesize any of them.
//!
//! * `gov_comm_rand` — 32-byte VAN blinding factor generated when the delegation
//!   PCZT was built.
//! * `voting_round_id` — 32-byte round id (hex-decoded) from the round params.
//! * `ea_pk` — 32-byte compressed election-authority public key from round config.
//! * `address_index` / `total_note_value` — diversifier index and summed value of
//!   the delegated note bundle.
//! * `proposal_authority` — per-bundle authority bitmask; each already-submitted
//!   vote clears its bit (see [`next_proposal_authority`]). For a bundle with no
//!   submitted votes this is `voting_circuits::MAX_PROPOSAL_AUTHORITY`, the
//!   constant the delegation circuit commits to.
//! * `van_auth_path` / `van_position` / `anchor_height` — the VAN Merkle witness
//!   in the vote-commitment tree, snapshotted after the delegation TX confirmed.

use crate::types::{
    Network, ProgressReporter, SharePayload, VoteCommitmentBundle, VotingError, WireEncryptedShare,
};
use crate::vote::{SignedVoteCommitment, VanWitness, VoteRecoveryBundle};
use crate::wire::DraftVote;

/// Casting inputs. Every field is host-supplied delegation-phase state; see the
/// module docs for provenance. None of these may be defaulted/zeroed.
#[allow(clippy::struct_excessive_bools)]
pub struct CastVoteInputs<'a> {
    /// Voting hotkey seed bytes (ZIP-32 seed for the app-owned voting account).
    pub hotkey_seed: &'a [u8],
    /// Zcash network used to derive the hotkey spending key.
    pub network: Network,
    /// Diversifier index used for the hotkey address during delegation.
    pub address_index: u32,
    /// Sum of the delegated note values (from the delegation bundle).
    pub total_note_value: u64,
    /// 32-byte VAN blinding factor (delegation phase).
    pub gov_comm_rand: &'a [u8],
    /// 32-byte voting round id (hex-decoded).
    pub voting_round_id: &'a [u8],
    /// 32-byte compressed election-authority public key.
    pub ea_pk: &'a [u8],
    /// Per-bundle proposal-authority bitmask (delegation/round submission state).
    pub proposal_authority: u64,
    /// Delegation bundle index this vote belongs to (recovery-bundle key).
    pub bundle_index: u32,
    /// VAN Merkle witness (auth path / position / anchor height).
    pub witness: &'a VanWitness,
}

/// Result of a HOT vote cast: the signed commitment plus the helper-share
/// payloads. The host persists these for crash recovery and submits them to the
/// vote chain / helper servers. This function performs no I/O.
pub struct CastVoteResult {
    pub signed_commitment: SignedVoteCommitment,
    pub share_payloads: Vec<SharePayload>,
}

struct NoopProgress;

impl ProgressReporter for NoopProgress {
    fn on_progress(&self, _progress: f64) {}
}

/// Build ZKP #2, sign the cast-vote, and build helper-share payloads for one
/// proposal — the DB-free equivalent of `vote::commit` + `VoteRecoveryBundle`
/// assembly. Mirrors `storage::VotingDb::build_vote_commitment` but takes the
/// zkp2 inputs as arguments instead of reading them from a `VotingDb`.
pub fn cast_vote_hot(
    inputs: &CastVoteInputs<'_>,
    draft: &DraftVote,
) -> Result<CastVoteResult, VotingError> {
    crate::vote::validate_draft_vote(draft)?;

    let auth_path = inputs.witness.auth_path_fixed()?;

    // ZKP #2: real Halo2 vote proof + ElGamal share encryption (no DB).
    let bundle: VoteCommitmentBundle = crate::zkp2::build_vote_commitment(
        inputs.hotkey_seed,
        inputs.network,
        inputs.address_index,
        inputs.total_note_value,
        inputs.gov_comm_rand,
        inputs.voting_round_id,
        inputs.ea_pk,
        draft.proposal_id,
        draft.choice,
        draft.num_options,
        &auth_path,
        inputs.witness.position,
        inputs.witness.anchor_height,
        inputs.proposal_authority,
        draft.single_share,
        &NoopProgress,
    )?;

    let wire_shares: Vec<WireEncryptedShare> = bundle
        .enc_shares
        .iter()
        .map(WireEncryptedShare::from)
        .collect();

    // Helper-share payloads (public reveal-share material).
    let share_payloads = crate::vote_commitment::build_share_payloads(
        &wire_shares,
        &bundle,
        draft.choice,
        draft.num_options,
        draft.vc_tree_position,
        draft.single_share,
    )?;

    // Sign the canonical cast-vote sighash with the randomized voting key.
    let signature = crate::vote_commitment::sign_cast_vote(
        inputs.hotkey_seed,
        inputs.network,
        &bundle.vote_round_id,
        &bundle.r_vpk_bytes,
        &bundle.van_nullifier,
        &bundle.vote_authority_note_new,
        &bundle.vote_commitment,
        bundle.proposal_id,
        bundle.anchor_height,
        &bundle.alpha_v,
    )?;
    let vote_auth_sig: [u8; 64] =
        signature
            .vote_auth_sig
            .try_into()
            .map_err(|v: Vec<u8>| VotingError::Internal {
                message: format!("vote_auth_sig must be 64 bytes, got {}", v.len()),
            })?;

    // Reuse the exact recovery-bundle assembly `vote::commit` persists, so the
    // wire commitment and crash-recovery JSON stay byte-identical to native.
    let recovery =
        VoteRecoveryBundle::from_parts(inputs.bundle_index, draft, bundle, vote_auth_sig)?;
    let commitment_bundle_json = crate::vote::serialize_recovery(&recovery)?;

    let signed_commitment = SignedVoteCommitment {
        proposal_id: recovery.proposal_id,
        choice: recovery.vote_decision,
        vote_round_id: recovery.vote_round_id.clone(),
        van_nullifier: recovery.van_nullifier,
        vote_authority_note_new: recovery.vote_authority_note_new,
        vote_commitment: recovery.vote_commitment,
        proof: recovery.proof.clone(),
        encrypted_shares: wire_shares,
        share_payloads: share_payloads.clone(),
        anchor_height: recovery.anchor_height,
        shares_hash: recovery.shares_hash,
        share_comms: recovery.share_comms.clone(),
        r_vpk: recovery.r_vpk,
        vote_auth_sig: recovery.vote_auth_sig,
        commitment_bundle_json,
    };

    Ok(CastVoteResult {
        signed_commitment,
        share_payloads,
    })
}

/// Proposal-authority bitmask after one vote on `proposal_id` in a bundle.
///
/// A fresh delegation grants [`voting_circuits::MAX_PROPOSAL_AUTHORITY`] (bit 0
/// reserved, bits 1..=50 usable). Each cast clears its proposal's bit, and the
/// vote proof for the next cast in the same bundle must start from the cleared
/// mask. The mask is 51 bits wide, so hosts must not do this arithmetic in
/// JavaScript (bitwise operators there are 32-bit).
pub fn next_proposal_authority(authority: u64, proposal_id: u32) -> Result<u64, VotingError> {
    crate::types::validate_proposal_id(proposal_id)?;
    if authority > voting_circuits::MAX_PROPOSAL_AUTHORITY {
        return Err(VotingError::InvalidInput {
            message: format!(
                "proposal_authority {authority} exceeds the circuit maximum {}",
                voting_circuits::MAX_PROPOSAL_AUTHORITY
            ),
        });
    }
    let bit = 1u64 << proposal_id;
    if authority & bit == 0 {
        return Err(VotingError::InvalidInput {
            message: format!("proposal {proposal_id} was already voted in this bundle"),
        });
    }
    Ok(authority & !bit)
}

/// Helper-share payloads for a vote that is already on chain.
///
/// The helper needs the vote commitment's leaf position in the vote-commitment
/// tree, which is only known once the cast-vote transaction is included. This
/// rebuilds the payloads from the recovery bundle `cast_vote_hot` returned, so
/// the shares match the submitted commitment (re-running the proof would draw
/// fresh share randomness and a different `shares_hash`).
pub fn share_payloads_from_recovery(
    recovery_json: &str,
    vc_tree_position: u64,
) -> Result<Vec<SharePayload>, VotingError> {
    let recovery = crate::vote::parse_recovery(recovery_json)?;
    let enc_shares: Vec<WireEncryptedShare> = recovery
        .encrypted_shares
        .iter()
        .map(WireEncryptedShare::from)
        .collect();
    // Only the share-facing fields are read by `build_share_payloads`.
    let commitment = VoteCommitmentBundle {
        van_nullifier: recovery.van_nullifier.to_vec(),
        vote_authority_note_new: recovery.vote_authority_note_new.to_vec(),
        vote_commitment: recovery.vote_commitment.to_vec(),
        proposal_id: recovery.proposal_id,
        proof: Vec::new(),
        enc_shares: Vec::new(),
        anchor_height: recovery.anchor_height,
        vote_round_id: recovery.vote_round_id.clone(),
        shares_hash: recovery.shares_hash.to_vec(),
        share_blinds: recovery.share_blinds.iter().map(|b| b.to_vec()).collect(),
        share_comms: recovery.share_comms.iter().map(|c| c.to_vec()).collect(),
        r_vpk_bytes: recovery.r_vpk.to_vec(),
        alpha_v: Vec::new(),
    };
    crate::vote_commitment::build_share_payloads(
        &enc_shares,
        &commitment,
        recovery.vote_decision,
        recovery.num_options,
        vc_tree_position,
        recovery.single_share,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use voting_circuits::MAX_PROPOSAL_AUTHORITY;

    #[test]
    fn fresh_authority_covers_fifty_proposals() {
        assert_eq!(MAX_PROPOSAL_AUTHORITY, (1u64 << 51) - 1);
        for id in crate::types::MIN_PROPOSAL_ID..=crate::types::MAX_PROPOSAL_ID {
            let next = next_proposal_authority(MAX_PROPOSAL_AUTHORITY, id).unwrap();
            assert_eq!(next, MAX_PROPOSAL_AUTHORITY & !(1u64 << id));
        }
    }

    #[test]
    fn authority_chain_clears_one_bit_per_vote() {
        let after_17 = next_proposal_authority(MAX_PROPOSAL_AUTHORITY, 17).unwrap();
        let after_37 = next_proposal_authority(after_17, 37).unwrap();
        assert_eq!(
            after_37,
            MAX_PROPOSAL_AUTHORITY & !(1u64 << 17) & !(1u64 << 37)
        );
        assert!(
            next_proposal_authority(after_37, 17).is_err(),
            "double vote"
        );
    }

    #[test]
    fn authority_rejects_out_of_range_inputs() {
        assert!(next_proposal_authority(MAX_PROPOSAL_AUTHORITY, 0).is_err());
        assert!(next_proposal_authority(MAX_PROPOSAL_AUTHORITY, 51).is_err());
        assert!(next_proposal_authority(MAX_PROPOSAL_AUTHORITY + 1, 1).is_err());
    }
}

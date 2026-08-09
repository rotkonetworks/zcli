//! Delegation slice free functions (compiled in both `native` and `wasm-slim`).
//!
//! Delegation is the PREREQUISITE for casting: it spends the voter's real notes
//! into a governance action (authorized by the air-gapped COLD key) and records
//! the per-bundle state (`van_comm_rand`, `total_note_value`, `address_index`,
//! `proposal_authority`, `bundle_index`) that [`crate::wasm_casting`] later
//! consumes.
//!
//! These wrap the pure crypto that native drives through `impl VotingDb`
//! (`build_governance_pczt`, `build_and_prove_delegation`) as DB-free free fns.
//! The host (zafu TS) does all network I/O — lightwalletd for the anchor tree
//! state / branch id, and PIR for the nullifier IMT non-membership proofs — and
//! injects the results as bytes. Nothing here opens a socket.
//!
//! Ordering constraint (why this is two phases, not one): the ZKP #1 circuit
//! also rules out the *padded* dummy-note nullifiers, and those are only known
//! AFTER the governance PCZT is built (they are derived from freshly-sampled
//! padding secrets). So the host must build the PCZT first
//! ([`build_delegation_pczt`]), read back the real + dummy nullifiers, fetch
//! their IMT proofs over PIR, then prove ([`prove_delegation`]). A single call
//! that both builds the PCZT and proves is impossible without inventing the
//! dummy IMT proofs.

use ff::PrimeField;
use pasta_curves::pallas;
use voting_circuits::delegation::{ImtProofData, PaddedNoteData, PrecomputedRandomness, IMT_DEPTH};

use crate::types::{
    DelegationProgressReporter, GovernancePczt, Network, NoteInfo, VotingError, VotingRoundParams,
    WitnessData,
};

/// Product of the delegation PCZT build. `governance` carries every field the
/// proof and submission wire need (see [`GovernancePczt`]); `redacted_pczt` is
/// the cold-signer payload (witness + wallet-proprietary metadata stripped).
pub struct DelegationPcztArtifact {
    pub governance: GovernancePczt,
    /// Redacted PCZT bytes for the air-gapped signer (QR / hardware transport).
    pub redacted_pczt: Vec<u8>,
    /// Human-readable memo embedded in the governance output.
    pub display_memo: String,
    /// Summed value of the delegated notes (delegated weight, zatoshi).
    pub total_note_value: u64,
}

/// Build the governance delegation PCZT for one bundle (no DB, no network).
///
/// Samples the padded-note secrets fresh (browser RNG on wasm via getrandom/js),
/// builds the Orchard governance action, and redacts a signer copy. The returned
/// `governance.van_comm_rand` is the freshly-generated VAN blinding factor that
/// MUST be threaded into casting as `gov_comm_rand` — this is the single value
/// the two slices share, so return it (never regenerate it).
///
/// * `notes` — the delegated notes (1..=BUNDLE_NOTE_SLOTS), with real cmx /
///   nullifier / value / position / diversifier / rho / rseed / scope / ufvk.
/// * `params` — round params: `vote_round_id` (hex), `snapshot_height`, `ea_pk`,
///   `nc_root`, `nullifier_imt_root` (all validated).
/// * `fvk_bytes` — 96-byte Orchard FVK of the voter's account (ak||nk||rivk).
/// * `hotkey_raw_address` — 43-byte raw Orchard address of the voting hotkey
///   (the governance output target; from `generate_voting_hotkey`).
/// * `consensus_branch_id` — branch id active at `snapshot_height` (host resolves
///   via lightwalletd).
/// * `coin_type`, `seed_fingerprint`, `account_index` — ZIP-32 identity of the
///   voter's account, so the cold signer can derive the spending key.
#[allow(clippy::too_many_arguments)]
pub fn build_delegation_pczt(
    notes: &[NoteInfo],
    params: &VotingRoundParams,
    network: Network,
    fvk_bytes: &[u8],
    hotkey_raw_address: &[u8],
    consensus_branch_id: u32,
    seed_fingerprint: &[u8; 32],
    account_index: u32,
    round_name: &str,
) -> Result<DelegationPcztArtifact, VotingError> {
    use zcash_protocol::consensus::{NetworkConstants, Parameters};
    // Derive the SLIP-44 coin type the PCZT builder expects for this network,
    // so it always matches `build_governance_pczt`'s internal check.
    let coin_type = Parameters::network_type(&network).coin_type();
    let padded = crate::action::sample_padded_note_secrets(notes.len())?;
    let governance = crate::action::build_governance_pczt(
        notes,
        params,
        network,
        fvk_bytes,
        hotkey_raw_address,
        consensus_branch_id,
        coin_type,
        seed_fingerprint,
        account_index,
        round_name,
        &padded,
    )?;
    let redacted_pczt = crate::delegate::redact_delegation_pczt_for_signer(&governance.pczt_bytes)?;
    let total_note_value = notes
        .iter()
        .try_fold(0u64, |acc, n| acc.checked_add(n.value))
        .ok_or_else(|| VotingError::InvalidInput {
            message: "total note value overflows u64".to_string(),
        })?;
    let display_memo = crate::delegate::display_memo(round_name, total_note_value);
    Ok(DelegationPcztArtifact {
        governance,
        redacted_pczt,
        display_memo,
        total_note_value,
    })
}

/// A host-injected IMT non-membership proof (bytes; the crate parses to field
/// elements). The host fetches these over PIR — never in the crate. `nullifier`
/// identifies which nullifier this proof rules out (real note or padded dummy).
pub struct InjectedImtProof {
    /// 32-byte nullifier this proof authenticates (LE pallas::Base).
    pub nullifier: [u8; 32],
    /// 32-byte IMT root (LE).
    pub root: [u8; 32],
    /// Three sorted boundaries `[nf_lo, nf_mid, nf_hi]` (each 32-byte LE).
    pub nf_bounds: [[u8; 32]; 3],
    /// Leaf position in the IMT.
    pub leaf_pos: u32,
    /// `IMT_DEPTH` (29) sibling hashes along the Merkle path (each 32-byte LE).
    pub path: Vec<[u8; 32]>,
}

fn base_le(bytes: &[u8; 32], label: &str) -> Result<pallas::Base, VotingError> {
    Option::from(pallas::Base::from_repr(*bytes)).ok_or_else(|| VotingError::InvalidInput {
        message: format!("{label} is not a canonical Pallas base field element"),
    })
}

fn to_circuit_imt_proof(p: &InjectedImtProof) -> Result<ImtProofData, VotingError> {
    let root = base_le(&p.root, "imt_proof.root")?;
    let nf_bounds = [
        base_le(&p.nf_bounds[0], "imt_proof.nf_lo")?,
        base_le(&p.nf_bounds[1], "imt_proof.nf_mid")?,
        base_le(&p.nf_bounds[2], "imt_proof.nf_hi")?,
    ];
    let siblings = p
        .path
        .iter()
        .enumerate()
        .map(|(i, s)| base_le(s, &format!("imt_proof.path[{i}]")))
        .collect::<Result<Vec<_>, _>>()?;
    let path: [pallas::Base; IMT_DEPTH] =
        siblings
            .try_into()
            .map_err(|v: Vec<pallas::Base>| VotingError::InvalidInput {
                message: format!("imt_proof.path must have {IMT_DEPTH} siblings, got {}", v.len()),
            })?;
    Ok(ImtProofData {
        root,
        nf_bounds,
        leaf_pos: p.leaf_pos,
        path,
    })
}

fn precomputed_randomness(
    notes_len: usize,
    padded_note_secrets: &[(Vec<u8>, Vec<u8>)],
    rseed_signed: &[u8],
    rseed_output: &[u8],
) -> Result<PrecomputedRandomness, VotingError> {
    let padded_notes = padded_note_secrets
        .iter()
        .enumerate()
        .map(|(i, (rho, rseed))| {
            let rho: [u8; 32] = rho.as_slice().try_into().map_err(|_| VotingError::Internal {
                message: format!("padded_note_secrets[{i}].rho must be 32 bytes"),
            })?;
            let rseed: [u8; 32] =
                rseed
                    .as_slice()
                    .try_into()
                    .map_err(|_| VotingError::Internal {
                        message: format!("padded_note_secrets[{i}].rseed must be 32 bytes"),
                    })?;
            Ok(PaddedNoteData { rho, rseed })
        })
        .collect::<Result<Vec<_>, VotingError>>()?;
    let _ = notes_len;
    let rseed_signed: [u8; 32] = rseed_signed.try_into().map_err(|_| VotingError::Internal {
        message: "rseed_signed must be 32 bytes".to_string(),
    })?;
    let rseed_output: [u8; 32] = rseed_output.try_into().map_err(|_| VotingError::Internal {
        message: "rseed_output must be 32 bytes".to_string(),
    })?;
    Ok(PrecomputedRandomness {
        padded_notes,
        rseed_signed,
        rseed_output,
    })
}

struct NoopDelegationProgress;

impl DelegationProgressReporter for NoopDelegationProgress {
    fn on_progress(&self, _progress: crate::delegate::DelegationProgress) {}
}

/// Generate the ZKP #1 delegation proof (no DB, no network, no PIR client).
///
/// The padding secrets / rseeds come from the [`build_delegation_pczt`] output
/// (thread them back verbatim so the reconstructed dummy nullifiers match the
/// PCZT). `real_imt_proofs` are in note order; `dummy_imt_proofs` cover the
/// padded-note nullifiers reported by the PCZT build. On wasm the halo2 proof
/// runs inline (wasm-bindgen-rayon supplies parallelism).
#[allow(clippy::too_many_arguments)]
pub fn prove_delegation(
    notes: &[NoteInfo],
    hotkey_raw_address: &[u8],
    alpha: &[u8],
    van_comm_rand: &[u8],
    vote_round_id: &[u8],
    padded_note_secrets: &[(Vec<u8>, Vec<u8>)],
    rseed_signed: &[u8],
    rseed_output: &[u8],
    merkle_witnesses: &[WitnessData],
    real_imt_proofs: &[InjectedImtProof],
    dummy_imt_proofs: &[InjectedImtProof],
    network: Network,
) -> Result<crate::types::DelegationProofResult, VotingError> {
    let precomp = precomputed_randomness(
        notes.len(),
        padded_note_secrets,
        rseed_signed,
        rseed_output,
    )?;
    let imt_real = real_imt_proofs
        .iter()
        .map(to_circuit_imt_proof)
        .collect::<Result<Vec<_>, _>>()?;
    let extra = dummy_imt_proofs
        .iter()
        .map(|p| Ok::<_, VotingError>((p.nullifier, to_circuit_imt_proof(p)?)))
        .collect::<Result<Vec<_>, _>>()?;

    crate::zkp1::build_and_prove_delegation(
        notes,
        hotkey_raw_address,
        alpha,
        van_comm_rand,
        vote_round_id,
        merkle_witnesses,
        &imt_real,
        &extra,
        network,
        &NoopDelegationProgress,
        Some(&precomp),
    )
}

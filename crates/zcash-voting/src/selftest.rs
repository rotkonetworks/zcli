//! Self-contained delegation-proof self-test.
//!
//! Builds the same synthetic wallet notes / Merkle tree / IMT non-membership
//! proofs as `zkp1::tests::test_real_delegation_proof` (native, `--ignored`)
//! and runs a REAL K=14 halo2 delegation proof via
//! [`crate::zkp1::build_and_prove_delegation`]. No external inputs required -
//! this exists so a wasm host (voting-wasm) can call a zero-argument export
//! to measure whether K=14 proving completes inside wasm32 and how long it
//! takes, without needing a PIR server, lightwalletd, or a real wallet.
//!
//! Deliberately NOT gated behind `#[cfg(test)]`: it must be reachable from
//! the `voting-wasm` cdylib, which links this crate as a normal dependency
//! (not via `cargo test`).

use ff::{Field, PrimeField};
use incrementalmerkletree::{Hashable, Level};
use orchard::{
    keys::Scope,
    note::{ExtractedNoteCommitment, NoteVersion, Rho},
    tree::MerkleHashOrchard,
    value::NoteValue,
    NOTE_COMMITMENT_TREE_DEPTH as TEST_TREE_DEPTH,
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use voting_circuits::delegation::{ImtProofData, ImtProvider, SpacedLeafImtProvider};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::MAIN_NETWORK;
use zip32::AccountId;

use crate::governance::BUNDLE_NOTE_SLOTS;
use crate::types::{DelegationProgressReporter, DelegationProofResult, Network, NoteInfo, VotingError, WitnessData};

struct NoopReporter;
impl DelegationProgressReporter for NoopReporter {
    fn on_progress(&self, _progress: crate::delegate::DelegationProgress) {}
}

/// Run the self-contained real K=14 delegation proof and return the result
/// plus the count of proof-progress callbacks fired (sanity signal only).
pub fn run_selftest_delegation_proof() -> Result<DelegationProofResult, VotingError> {
    // 1. Deterministic test keys (matches zkp1::tests::test_real_delegation_proof).
    let seed = [0x42u8; 32];
    let account = AccountId::try_from(0u32).map_err(|_| VotingError::Internal {
        message: "invalid account id".to_string(),
    })?;
    let usk = UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &seed, account).map_err(|e| {
        VotingError::Internal {
            message: format!("usk from_seed failed: {e}"),
        }
    })?;
    let ufvk = usk.to_unified_full_viewing_key();
    let ufvk_str = ufvk.encode(&MAIN_NETWORK);
    let fvk = ufvk.orchard().ok_or_else(|| VotingError::Internal {
        message: "ufvk missing orchard component".to_string(),
    })?.clone();

    // 2. Hotkey (output note recipient).
    let hotkey_seed = [0x43u8; 32];
    let hotkey_usk = UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &hotkey_seed, account).map_err(
        |e| VotingError::Internal {
            message: format!("hotkey usk from_seed failed: {e}"),
        },
    )?;
    let hotkey_fvk = hotkey_usk
        .to_unified_full_viewing_key()
        .orchard()
        .ok_or_else(|| VotingError::Internal {
            message: "hotkey ufvk missing orchard component".to_string(),
        })?
        .clone();
    let hotkey_addr = hotkey_fvk.address_at(0u32, Scope::External);
    let hotkey_raw_address = hotkey_addr.to_raw_address_bytes().to_vec();

    // 3. Fill all note slots so no padding or IMT server is needed.
    let mut rng = crate::OsRng10;
    let note_values = vec![
        (crate::governance::BALLOT_DIVISOR / BUNDLE_NOTE_SLOTS as u64) + 1;
        BUNDLE_NOTE_SLOTS
    ];
    let address = fvk.address_at(0u32, Scope::External);

    let mut notes = Vec::new();
    for &v in &note_values {
        let (_, _, dummy_parent) = orchard::Note::dummy(&mut rng, None, NoteVersion::V3);
        let note = orchard::Note::new(
            address,
            NoteValue::from_raw(v),
            Rho::from_nf_old(dummy_parent.nullifier(&fvk)),
            NoteVersion::V3,
            &mut rng,
        );
        notes.push(note);
    }

    // 4. Build Merkle tree (5 leaves in a 32-level tree).
    let empty_leaf = MerkleHashOrchard::empty_leaf();
    let mut leaves = [empty_leaf; 8];
    for (i, note) in notes.iter().enumerate() {
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        leaves[i] = MerkleHashOrchard::from_cmx(&cmx);
    }

    let l1_0 = MerkleHashOrchard::combine(Level::from(0), &leaves[0], &leaves[1]);
    let l1_1 = MerkleHashOrchard::combine(Level::from(0), &leaves[2], &leaves[3]);
    let l1_2 = MerkleHashOrchard::combine(Level::from(0), &leaves[4], &leaves[5]);
    let l1_3 = MerkleHashOrchard::combine(Level::from(0), &leaves[6], &leaves[7]);
    let l2_0 = MerkleHashOrchard::combine(Level::from(1), &l1_0, &l1_1);
    let l2_1 = MerkleHashOrchard::combine(Level::from(1), &l1_2, &l1_3);
    let l3_0 = MerkleHashOrchard::combine(Level::from(2), &l2_0, &l2_1);

    let mut current = l3_0;
    for level in 3..TEST_TREE_DEPTH {
        let sibling = MerkleHashOrchard::empty_root(Level::from(level as u8));
        current = MerkleHashOrchard::combine(Level::from(level as u8), &current, &sibling);
    }
    let nc_root_bytes = current.to_bytes().to_vec();

    let l1 = [l1_0, l1_1, l1_2, l1_3];
    let l2 = [l2_0, l2_1];
    let mut merkle_witnesses = Vec::new();
    for (i, note) in notes.iter().enumerate() {
        let mut auth_path_hashes = [MerkleHashOrchard::empty_leaf(); TEST_TREE_DEPTH];
        auth_path_hashes[0] = leaves[i ^ 1];
        auth_path_hashes[1] = l1[(i >> 1) ^ 1];
        auth_path_hashes[2] = l2[(i >> 2) ^ 1];
        for level in 3..TEST_TREE_DEPTH {
            auth_path_hashes[level] = MerkleHashOrchard::empty_root(Level::from(level as u8));
        }

        let cmx = ExtractedNoteCommitment::from(note.commitment());
        merkle_witnesses.push(WitnessData {
            note_commitment: MerkleHashOrchard::from_cmx(&cmx).to_bytes().to_vec(),
            position: i as u64,
            root: nc_root_bytes.clone(),
            auth_path: auth_path_hashes
                .iter()
                .map(|h| h.to_bytes().to_vec())
                .collect(),
        });
    }

    // 5. Build IMT non-membership proofs.
    let imt = SpacedLeafImtProvider::new();
    let imt_proofs: Vec<ImtProofData> = notes
        .iter()
        .map(|note| {
            let nf_bytes = note.nullifier(&fvk).to_bytes();
            let nf_base: pallas::Base = pallas::Base::from_repr(nf_bytes).unwrap();
            imt.non_membership_proof(nf_base).map_err(|e| VotingError::Internal {
                message: format!("imt non_membership_proof failed: {e}"),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // 6. Serialize notes into NoteInfo.
    let full_notes: Vec<NoteInfo> = notes
        .iter()
        .enumerate()
        .map(|(i, note)| {
            let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
            NoteInfo {
                commitment: cmx.to_bytes().to_vec(),
                diversifier: note.recipient().diversifier().as_array().to_vec(),
                value: note_values[i],
                rho: note.rho().to_bytes().to_vec(),
                rseed: note.rseed().as_bytes().to_vec(),
                nullifier: note.nullifier(&fvk).to_bytes().to_vec(),
                position: i as u64,
                scope: 0,
                ufvk_str: ufvk_str.clone(),
            }
        })
        .collect();

    // 7. Generate random parameters.
    let alpha = pallas::Scalar::random(&mut rng);
    let van_comm_rand = pallas::Base::random(&mut rng);
    let vote_round_id = pallas::Base::random(&mut rng);

    let reporter = NoopReporter;

    crate::zkp1::build_and_prove_delegation(
        &full_notes,
        &hotkey_raw_address,
        &alpha.to_repr(),
        &van_comm_rand.to_repr(),
        &vote_round_id.to_repr(),
        &merkle_witnesses,
        &imt_proofs,
        &[],
        Network::Mainnet,
        &reporter,
        None,
    )
}

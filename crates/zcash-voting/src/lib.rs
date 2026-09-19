//! Client-side APIs for Zcash shielded voting.
//!
//! Wallet SDKs should import [`prelude`] and follow the lifecycle:
//! create a round, bind eligible notes into bundles, precompute witness/PIR
//! data, build a delegation PCZT, prove delegation, sync the vote commitment
//! tree, cast votes with `vote::commit`, confirm chain submissions through
//! `confirmation`, then recover helper-share payloads through `share`. New
//! integrations should use `round`, `precompute`, `delegate`, `vote`,
//! `confirmation`, `share`, and `session` rather than writing storage rows
//! directly.

/// rand_core 0.10 RNG adapter for the Zakura Common 1.0 stack.
///
/// Zakura's ff 0.14 / orchard 1.0 / voting-circuits 0.11 bound their RNG call
/// sites on rand_core 0.10's `Rng` (a pure-trait crate). This zero-sized adapter
/// bridges rand 0.8's `OsRng` (which works on both native and wasm-with-`js`) to
/// rand_core 0.10's `TryRng`/`TryCryptoRng`, promoted to `Rng`/`CryptoRng` by
/// the crate's blanket impls. Used at the `pallas::Base::random`,
/// `orchard::Note::dummy`, `rsk.sign`, and `build_for_pczt` sites.
#[derive(Clone, Copy, Default)]
pub(crate) struct OsRng10;

impl rand_core_10::TryRng for OsRng10 {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        use rand::RngCore;
        Ok(rand::rngs::OsRng.next_u32())
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        use rand::RngCore;
        Ok(rand::rngs::OsRng.next_u64())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(dst);
        Ok(())
    }
}
impl rand_core_10::TryCryptoRng for OsRng10 {}

// Modules kept under both `native` and `wasm-slim`. The wasm-slim casting slice
// needs the pure crypto core; native-only items inside these modules (anything
// taking `WalletDb`/`VotingDb`, rusqlite, tokio, or network transport) are
// `#[cfg(feature = "native")]`-gated within the module itself.
pub mod action;
pub mod config;
pub mod delegate;
pub mod error;
pub mod governance;
pub mod hotkey;
pub mod lwd;
pub mod note_bundling;
pub mod phases;
pub mod round;
pub mod share_policy;
mod shielded_protocol;
pub mod types;
pub mod vote;
pub mod vote_commitment;
pub mod wire;
pub mod zkp1;
pub mod zkp2;

// Casting-slice free functions (HOT vote casting: hotkey signs commitments +
// builds shares; no cold key, no network, no PIR). Available in both builds.
pub mod wasm_casting;

// Delegation-slice free functions (cold-signed governance PCZT + ZKP #1 proof;
// host injects lightwalletd/PIR bytes, no network in the crate). Both builds.
pub mod wasm_delegation;

// Self-contained delegation-proof self-test: builds synthetic wallet notes and
// runs a real K=14 halo2 proof with no external inputs. Used by voting-wasm's
// `selftest_prove_delegation` export to measure whether K=14 proving completes
// inside wasm32 (see BUILD_PROVENANCE.md). Not gated behind `#[cfg(test)]`
// because it must link into the voting-wasm cdylib as a normal dependency.
pub mod selftest;

// Native-only orchestration: SQLite persistence, lightwalletd/PIR network
// transport, wallet-db-driven round/session/delegation flows, witness/precompute,
// share recovery, and the resume/confirmation state machines.
#[cfg(feature = "native")]
pub mod confirmation;
#[cfg(feature = "native")]
mod http_transport;
#[cfg(feature = "native")]
pub mod pir;
#[cfg(feature = "native")]
pub mod pir_snapshot;
#[cfg(feature = "native")]
pub mod precompute;
#[cfg(feature = "native")]
pub mod prelude;
#[cfg(feature = "native")]
pub mod recovery;
#[cfg(feature = "native")]
pub mod selection;
#[cfg(feature = "native")]
pub mod session;
#[cfg(feature = "native")]
pub mod share;
#[cfg(feature = "native")]
pub mod storage;
#[cfg(feature = "native")]
pub mod transport;
#[cfg(feature = "native")]
pub mod tree_sync;
#[cfg(feature = "native")]
pub mod witness;
// Behavioral wire conversions depend on native recovery/session/delegate types;
// the casting slice builds its wire DTOs directly in `wasm_casting`.
#[cfg(feature = "native")]
mod wire_codec;

#[cfg(feature = "native")]
pub use http_transport::HyperTransport;
#[cfg(feature = "native")]
pub use pir_client::{
    ImtProofData, PirClient, PirClientBlocking, Transport, TransportFuture, TransportResponse,
};

pub use governance::{BALLOT_DIVISOR, BUNDLE_NOTE_SLOTS};
pub use note_bundling::{
    minimum_voting_eligibility_for_notes, validate_minimum_voting_eligibility_for_notes,
    BundlePolicy, MinimumVotingEligibility, MINIMUM_VOTING_NOTE_COUNT,
    MINIMUM_VOTING_WEIGHT_ZATOSHI,
};
// Native only: these take `&SelectedNotes` (lightwalletd `TreeState` field).
#[cfg(feature = "native")]
pub use note_bundling::{voting_power, voting_power_with_policy};
pub use round::validate_bundle_index;
#[cfg(feature = "native")]
pub use selection::{
    gather_delegation_wallet_inputs, select_notes_with_wallet_db, select_snapshot_notes,
    DelegationWalletInputs, GatherDelegationWalletParams,
};
pub use types::{
    validate_proposal_id, validate_round_params, validate_vote_decision, validate_vote_options,
    CastVoteSignature, DelegationAction, DelegationPirPrecomputeResult, DelegationProgressBridge,
    DelegationProgressReporter, DelegationProofResult, DelegationSubmissionData, EncryptedShare,
    GovernancePczt, Network, NoopProgressReporter, NoteInfo, NoteRef, ProgressReporter,
    ShareDelegationRecord, SharePayload, VoteCommitStageBridge,
    VoteCommitStageReporter, VoteCommitmentBundle, VotingError, VotingHotkey, VotingRoundParams,
    WireEncryptedShare, WitnessData, MAX_PROPOSAL_ID, MAX_VOTE_OPTIONS, MIN_PROPOSAL_ID,
    MIN_VOTE_OPTIONS,
};
// Native-only: carries a lightwalletd `TreeState` protobuf field.
#[cfg(feature = "native")]
pub use types::SelectedNotes;

/// Warm process-lifetime proving-key caches used by on-device voting proofs.
///
/// This is intentionally best-effort at the cache layer: callers should invoke
/// it from a background task before the first proof is needed.
#[cfg(not(target_arch = "wasm32"))]
pub fn warm_proving_caches() {
    const KEYGEN_STACK_BYTES: usize = 64 * 1024 * 1024;

    let handles = [
        std::thread::Builder::new()
            .name("voting-delegation-cache-warmup".to_string())
            .stack_size(KEYGEN_STACK_BYTES)
            .spawn(|| {
                let _ = voting_circuits::delegation::warm_delegation_keys();
            })
            .expect("spawn delegation proving cache warm-up thread"),
        std::thread::Builder::new()
            .name("voting-vote-proof-cache-warmup".to_string())
            .stack_size(KEYGEN_STACK_BYTES)
            .spawn(|| {
                let _ = voting_circuits::vote_proof::warm_vote_proof_keys();
            })
            .expect("spawn vote proof cache warm-up thread"),
    ];

    for handle in handles {
        handle
            .join()
            .expect("proving cache warm-up thread panicked");
    }
}

/// Warm process-lifetime proving-key caches (wasm build).
///
/// wasm32 has no `std::thread`; wasm-bindgen-rayon supplies halo2's parallelism,
/// so the warm-up runs inline on the calling worker.
#[cfg(target_arch = "wasm32")]
pub fn warm_proving_caches() {
    let _ = voting_circuits::delegation::warm_delegation_keys();
    let _ = voting_circuits::vote_proof::warm_vote_proof_keys();
}

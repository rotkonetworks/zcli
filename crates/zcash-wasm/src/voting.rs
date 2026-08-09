//! HOT vote-casting wasm bindings (shielded voting, casting slice only).
//!
//! These wrap `zcash_voting`'s wasm-slim casting seam: the app-owned voting
//! **hotkey** builds the ZKP #2 vote commitment, signs the cast-vote, and builds
//! the helper-share payloads. No cold key, no network, no PIR, no DB.
//!
//! Provenance of the delegation-phase inputs (host must supply — this layer
//! never synthesizes them): `ea_pk` + `vote_round_id` come from the round params
//! the vote chain publishes; `address_index`, `total_note_value`,
//! `gov_comm_rand`, `proposal_authority`, and `bundle_index` are per-bundle state
//! persisted during the **delegation** phase (mirrors native
//! `queries::load_zkp2_inputs`); the VAN witness (`auth_path`/`position`/
//! `anchor_height`) is snapshotted after the delegation TX confirmed. A first
//! vote is impossible without this prior delegation state.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use zcash_voting::types::Network;
use zcash_voting::vote::VanWitness;
use zcash_voting::wasm_casting::{cast_vote_hot, CastVoteInputs, CastVoteResult};
use zcash_voting::wire::{DraftVote, VoteCommitmentWire, VoteShareWire};

fn parse_network(network: &str) -> Result<Network, JsError> {
    match network.trim().to_ascii_lowercase().as_str() {
        "main" | "mainnet" => Ok(Network::Mainnet),
        "test" | "testnet" => Ok(Network::Testnet),
        "regtest" | "reg" => Ok(Network::Regtest),
        other => Err(JsError::new(&format!("unknown network: {other}"))),
    }
}

fn hexd(s: &str, label: &str) -> Result<Vec<u8>, JsError> {
    hex::decode(s.trim()).map_err(|e| JsError::new(&format!("invalid {label} hex: {e}")))
}

fn b64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

/// Round parameters the vote chain publishes. `ea_pk` is the 32-byte compressed
/// election-authority pubkey; `vote_round_id` is the round id hex string.
#[derive(Deserialize)]
struct RoundParamsArg {
    vote_round_id: String,
    /// 32-byte compressed election-authority public key (hex).
    ea_pk_hex: String,
}

/// Per-bundle delegation-phase state. Every field is host-persisted from the
/// delegation phase; none may be defaulted or zeroed for a real vote.
#[derive(Deserialize)]
struct DelegationStateArg {
    /// Diversifier index used for the hotkey address during delegation.
    address_index: u32,
    /// Sum of the delegated note values.
    total_note_value: u64,
    /// 32-byte VAN blinding factor (hex).
    gov_comm_rand_hex: String,
    /// Per-bundle proposal-authority bitmask (delegation/round submission state).
    proposal_authority: u64,
    /// Delegation bundle index this vote belongs to.
    bundle_index: u32,
}

/// VAN Merkle witness, wire-friendly (hex siblings).
#[derive(Deserialize)]
struct VanWitnessArg {
    /// 24 sibling hashes (each 32-byte hex) for the VAN path.
    auth_path_hex: Vec<String>,
    position: u32,
    anchor_height: u32,
}

impl VanWitnessArg {
    fn into_witness(self) -> Result<VanWitness, JsError> {
        let path: Result<Vec<Vec<u8>>, JsError> = self
            .auth_path_hex
            .iter()
            .map(|h| hexd(h, "van_auth_path sibling"))
            .collect();
        VanWitness::from_wire(&path?, self.position, self.anchor_height)
            .map_err(|e| JsError::new(&format!("invalid van witness: {e}")))
    }
}

/// Generate a fresh app-owned voting hotkey.
///
/// Returns `{ hotkey_secret_hex, hotkey_pubkey_hex }` where `hotkey_secret_hex`
/// is the 64-byte stored secret (persist in secure storage) and
/// `hotkey_pubkey_hex` is the 43-byte raw Orchard address that the delegation
/// PCZT targets as the hotkey output (the hotkey's public identity).
#[wasm_bindgen]
pub fn generate_voting_hotkey(network: &str) -> Result<String, JsError> {
    let net = parse_network(network)?;
    let hotkey = zcash_voting::hotkey::generate_random_voting_hotkey(net)
        .map_err(|e| JsError::new(&format!("hotkey generation failed: {e}")))?;
    let out = serde_json::json!({
        "hotkey_secret_hex": hex::encode(hotkey.stored_secret()),
        "hotkey_pubkey_hex": hex::encode(hotkey.raw_orchard_address()),
    });
    Ok(out.to_string())
}

/// Shared driver: run ZKP #2 + sign + build share payloads for one vote.
#[allow(clippy::too_many_arguments)]
fn run_cast(
    hotkey_secret_hex: &str,
    round_params_json: &str,
    delegation_state_json: &str,
    van_witness_json: &str,
    vote_json: &str,
    network: &str,
) -> Result<(CastVoteResult, DraftVote), JsError> {
    let net = parse_network(network)?;
    let hotkey_seed = hexd(hotkey_secret_hex, "hotkey_secret")?;
    let round: RoundParamsArg = serde_json::from_str(round_params_json)
        .map_err(|e| JsError::new(&format!("round_params_json: {e}")))?;
    let deleg: DelegationStateArg = serde_json::from_str(delegation_state_json)
        .map_err(|e| JsError::new(&format!("delegation_state_json: {e}")))?;
    let witness_arg: VanWitnessArg = serde_json::from_str(van_witness_json)
        .map_err(|e| JsError::new(&format!("van_witness_json: {e}")))?;
    let draft: DraftVote = serde_json::from_str(vote_json)
        .map_err(|e| JsError::new(&format!("vote_json: {e}")))?;

    let voting_round_id = hexd(&round.vote_round_id, "vote_round_id")?;
    let ea_pk = hexd(&round.ea_pk_hex, "ea_pk")?;
    let gov_comm_rand = hexd(&deleg.gov_comm_rand_hex, "gov_comm_rand")?;
    let witness = witness_arg.into_witness()?;

    let inputs = CastVoteInputs {
        hotkey_seed: &hotkey_seed,
        network: net,
        address_index: deleg.address_index,
        total_note_value: deleg.total_note_value,
        gov_comm_rand: &gov_comm_rand,
        voting_round_id: &voting_round_id,
        ea_pk: &ea_pk,
        proposal_authority: deleg.proposal_authority,
        bundle_index: deleg.bundle_index,
        witness: &witness,
    };

    let result =
        cast_vote_hot(&inputs, &draft).map_err(|e| JsError::new(&format!("cast vote failed: {e}")))?;
    Ok((result, draft))
}

/// Build the `POST /cast-vote` body ([`VoteCommitmentWire`]) for one HOT vote.
///
/// Binary fields are base64 STANDARD; `vote_round_id` is hex-decoded then
/// base64-encoded (matching `wire_codec`). Runs the ZKP #2 proof.
#[wasm_bindgen]
pub fn build_vote_commitment_wire(
    hotkey_secret_hex: &str,
    round_params_json: &str,
    delegation_state_json: &str,
    van_witness_json: &str,
    vote_json: &str,
    network: &str,
) -> Result<String, JsError> {
    let (result, _) = run_cast(
        hotkey_secret_hex,
        round_params_json,
        delegation_state_json,
        van_witness_json,
        vote_json,
        network,
    )?;
    let wire = commitment_wire(&result)?;
    serde_json::to_string(&wire).map_err(|e| JsError::new(&format!("serialize wire: {e}")))
}

/// Build the helper-server share payloads (`[VoteShareWire]`) for one HOT vote.
///
/// `submit_at` is the unix-seconds submission time stamped into each share.
/// Runs the ZKP #2 proof.
#[wasm_bindgen]
pub fn build_vote_shares_wire(
    hotkey_secret_hex: &str,
    round_params_json: &str,
    delegation_state_json: &str,
    van_witness_json: &str,
    vote_json: &str,
    network: &str,
    submit_at: u64,
) -> Result<String, JsError> {
    let (result, _) = run_cast(
        hotkey_secret_hex,
        round_params_json,
        delegation_state_json,
        van_witness_json,
        vote_json,
        network,
    )?;
    let shares = share_wires(&result, submit_at)?;
    serde_json::to_string(&shares).map_err(|e| JsError::new(&format!("serialize shares: {e}")))
}

/// Build BOTH the commitment wire and share wires from a SINGLE proof run.
///
/// Prefer this over calling the two builders separately: ZKP #2 is expensive and
/// each of `build_vote_commitment_wire` / `build_vote_shares_wire` runs it once.
/// Returns `SignedVoteCommitmentView`-shaped JSON
/// `{ proposal_id, wire, shares, commitment_bundle_json }`.
#[wasm_bindgen]
pub fn cast_vote_hot_wire(
    hotkey_secret_hex: &str,
    round_params_json: &str,
    delegation_state_json: &str,
    van_witness_json: &str,
    vote_json: &str,
    network: &str,
    submit_at: u64,
) -> Result<String, JsError> {
    let (result, _) = run_cast(
        hotkey_secret_hex,
        round_params_json,
        delegation_state_json,
        van_witness_json,
        vote_json,
        network,
    )?;
    let wire = commitment_wire(&result)?;
    let shares = share_wires(&result, submit_at)?;
    let out = serde_json::json!({
        "proposal_id": result.signed_commitment.proposal_id,
        "wire": wire,
        "shares": shares,
        "commitment_bundle_json": result.signed_commitment.commitment_bundle_json,
    });
    Ok(out.to_string())
}

/// Mirror of `wire_codec::TryFrom<&SignedVoteCommitment> for VoteCommitmentWire`.
fn commitment_wire(result: &CastVoteResult) -> Result<VoteCommitmentWire, JsError> {
    let c = &result.signed_commitment;
    let vote_round_id = hex::decode(c.vote_round_id.trim())
        .map_err(|e| JsError::new(&format!("vote_round_id hex: {e}")))?;
    Ok(VoteCommitmentWire {
        van_nullifier: b64(&c.van_nullifier),
        vote_authority_note_new: b64(&c.vote_authority_note_new),
        vote_commitment: b64(&c.vote_commitment),
        proposal_id: c.proposal_id,
        proof: b64(&c.proof),
        vote_round_id: b64(&vote_round_id),
        anchor_height: c.anchor_height,
        r_vpk: b64(&c.r_vpk),
        vote_auth_sig: b64(&c.vote_auth_sig),
    })
}

/// Mirror of `wire_codec::VoteShareWire::from_payload` over the payload set.
fn share_wires(result: &CastVoteResult, submit_at: u64) -> Result<Vec<VoteShareWire>, JsError> {
    result
        .share_payloads
        .iter()
        .map(|p| {
            Ok(VoteShareWire {
                shares_hash: b64(&p.shares_hash),
                proposal_id: p.proposal_id,
                vote_decision: p.vote_decision,
                encrypted_share: p.enc_share.clone(),
                share_index: p.enc_share.share_index,
                vc_tree_position: p.tree_position,
                all_encrypted_shares: p.all_enc_shares.clone(),
                share_comms: p.share_comms.iter().map(|c| b64(c)).collect(),
                primary_blind: b64(&p.primary_blind),
                submit_at,
            })
        })
        .collect()
}

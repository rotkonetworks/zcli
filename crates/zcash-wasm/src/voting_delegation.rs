//! Delegation slice wasm bindings (cold-signed governance PCZT + ZKP #1).
//!
//! Delegation is the PREREQUISITE and cold/air-gapped half of shielded voting.
//! Two phases, because the ZKP #1 circuit also rules out the padded dummy-note
//! nullifiers and those only exist AFTER the PCZT is built:
//!
//!   1. `build_delegation_pczt` — build the governance PCZT (spend of the voter's
//!      real notes -> hotkey output). Returns the REDACTED PCZT for the cold
//!      signer (zafu "zigner" over animated QR), its sighash/rk/action_index, the
//!      real + dummy nullifiers the host must fetch IMT proofs for, an opaque
//!      `delegation_context_json` to round-trip, and the `delegation_state_json`
//!      that `cast_vote_hot_wire` consumes byte-for-byte.
//!   2. `finalize_delegation` — after the host fetches the IMT proofs (PIR, in TS)
//!      and the cold signer returns a 64-byte spend-auth sig + 32-byte sighash:
//!      run ZKP #1 and assemble the `POST /delegate-vote` submission wire.
//!
//! No network, no PIR client, no DB in the crate — the host injects all
//! lightwalletd (anchor tree state, branch id) and PIR (IMT proofs) bytes.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use zcash_voting::types::{Network, NoteInfo, VotingRoundParams, WitnessData};
use zcash_voting::wasm_delegation::{
    build_delegation_pczt as crate_build_delegation_pczt, prove_delegation, InjectedImtProof,
};

fn parse_network(s: &str) -> Result<Network, JsError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "main" | "mainnet" => Ok(Network::Mainnet),
        "test" | "testnet" => Ok(Network::Testnet),
        "regtest" | "reg" => Ok(Network::Regtest),
        other => Err(JsError::new(&format!("unknown network: {other}"))),
    }
}

fn network_str(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

fn hx(s: &str, label: &str) -> Result<Vec<u8>, JsError> {
    hex::decode(s.trim()).map_err(|e| JsError::new(&format!("invalid {label} hex: {e}")))
}

fn arr32(s: &str, label: &str) -> Result<[u8; 32], JsError> {
    hx(s, label)?
        .try_into()
        .map_err(|_| JsError::new(&format!("{label} must be 32 bytes")))
}

fn b64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

// ---- host-facing JSON DTOs -------------------------------------------------

/// One delegated note. All byte fields are hex (LE where field-element valued).
#[derive(Serialize, Deserialize, Clone)]
struct NoteInfoDto {
    commitment_hex: String,
    nullifier_hex: String,
    value: u64,
    position: u64,
    diversifier_hex: String,
    rho_hex: String,
    rseed_hex: String,
    scope: u32,
    ufvk_str: String,
}

impl NoteInfoDto {
    fn to_note(&self) -> Result<NoteInfo, JsError> {
        Ok(NoteInfo {
            commitment: hx(&self.commitment_hex, "note.commitment")?,
            nullifier: hx(&self.nullifier_hex, "note.nullifier")?,
            value: self.value,
            position: self.position,
            diversifier: hx(&self.diversifier_hex, "note.diversifier")?,
            rho: hx(&self.rho_hex, "note.rho")?,
            rseed: hx(&self.rseed_hex, "note.rseed")?,
            scope: self.scope,
            ufvk_str: self.ufvk_str.clone(),
        })
    }
}

/// Round params sourced from the vote chain / anchor snapshot (hex bytes).
#[derive(Deserialize)]
struct RoundParamsDto {
    /// 64-char hex round id (canonical LE pallas::Base).
    vote_round_id: String,
    snapshot_height: u64,
    /// 32-byte compressed election-authority pubkey.
    ea_pk_hex: String,
    /// 32-byte note-commitment tree root at the snapshot.
    nc_root_hex: String,
    /// 32-byte nullifier IMT root at the snapshot.
    nullifier_imt_root_hex: String,
}

impl RoundParamsDto {
    fn to_params(&self) -> Result<VotingRoundParams, JsError> {
        Ok(VotingRoundParams {
            vote_round_id: self.vote_round_id.trim().to_string(),
            snapshot_height: self.snapshot_height,
            ea_pk: hx(&self.ea_pk_hex, "ea_pk")?,
            nc_root: hx(&self.nc_root_hex, "nc_root")?,
            nullifier_imt_root: hx(&self.nullifier_imt_root_hex, "nullifier_imt_root")?,
        })
    }
}

/// Merkle inclusion witness for one note (host builds by replaying compact
/// blocks; see zafu-wasm `build_witnesses`).
#[derive(Deserialize)]
struct WitnessDto {
    note_commitment_hex: String,
    position: u64,
    root_hex: String,
    /// Auth-path siblings (each 32-byte hex), leaf-to-root.
    auth_path_hex: Vec<String>,
}

impl WitnessDto {
    fn to_witness(&self) -> Result<WitnessData, JsError> {
        Ok(WitnessData {
            note_commitment: hx(&self.note_commitment_hex, "witness.note_commitment")?,
            position: self.position,
            root: hx(&self.root_hex, "witness.root")?,
            auth_path: self
                .auth_path_hex
                .iter()
                .map(|h| hx(h, "witness.auth_path"))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

/// A host-fetched (PIR) IMT non-membership proof for one nullifier.
#[derive(Deserialize)]
struct ImtProofDto {
    /// 32-byte nullifier this proves (LE); the key that maps proofs to notes.
    nullifier_hex: String,
    root_hex: String,
    /// Exactly 3 boundaries `[nf_lo, nf_mid, nf_hi]` (32-byte hex each).
    nf_bounds_hex: Vec<String>,
    leaf_pos: u32,
    /// Exactly 29 sibling hashes (32-byte hex each).
    path_hex: Vec<String>,
}

impl ImtProofDto {
    fn to_injected(&self) -> Result<InjectedImtProof, JsError> {
        if self.nf_bounds_hex.len() != 3 {
            return Err(JsError::new("imt_proof.nf_bounds must have 3 entries"));
        }
        let nf_bounds = [
            arr32(&self.nf_bounds_hex[0], "imt_proof.nf_bounds[0]")?,
            arr32(&self.nf_bounds_hex[1], "imt_proof.nf_bounds[1]")?,
            arr32(&self.nf_bounds_hex[2], "imt_proof.nf_bounds[2]")?,
        ];
        let path = self
            .path_hex
            .iter()
            .map(|h| arr32(h, "imt_proof.path"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(InjectedImtProof {
            nullifier: arr32(&self.nullifier_hex, "imt_proof.nullifier")?,
            root: arr32(&self.root_hex, "imt_proof.root")?,
            nf_bounds,
            leaf_pos: self.leaf_pos,
            path,
        })
    }
}

/// Opaque context round-tripped from `build_delegation_pczt` into
/// `finalize_delegation`. The host must NOT edit it; it carries the proof inputs
/// (notes, alpha, van_comm_rand, padding secrets) and the PCZT-derived wire
/// fields (rk, nf_signed, cmx_new, van, gov_nullifiers, sighash).
#[derive(Serialize, Deserialize)]
struct DelegationContext {
    network: String,
    notes: Vec<NoteInfoDto>,
    hotkey_raw_address_hex: String,
    alpha_hex: String,
    van_comm_rand_hex: String,
    /// 64-char round-id hex.
    vote_round_id_hex: String,
    padded_note_secrets: Vec<[String; 2]>,
    rseed_signed_hex: String,
    rseed_output_hex: String,
    dummy_nullifiers_hex: Vec<String>,
    // PCZT-derived submission-wire fields.
    rk_hex: String,
    nf_signed_hex: String,
    cmx_new_hex: String,
    van_hex: String,
    gov_nullifiers_hex: Vec<String>,
    pczt_sighash_hex: String,
    action_index: usize,
}

// ---- export 1: build the delegation PCZT -----------------------------------

/// Build the governance delegation PCZT for one bundle (phase 1 of 2).
///
/// Args:
/// * `fvk_hex` — 96-byte Orchard FVK of the voter's account.
/// * `seed_fingerprint_hex` — 32-byte ZIP-32 seed fingerprint.
/// * `account_index` — ZIP-32 account index.
/// * `hotkey_pubkey_hex` — 43-byte hotkey raw Orchard address (from
///   `generate_voting_hotkey`); the governance output target.
/// * `notes_json` — `[NoteInfoDto]` (the delegated notes).
/// * `round_params_json` — `RoundParamsDto`.
/// * `consensus_branch_id` — branch id at the snapshot height (host resolves via
///   lightwalletd).
/// * `round_name` — display memo text.
/// * `network` — "mainnet" | "testnet" | "regtest".
/// * `bundle_index` — delegation bundle index (echoed into `delegation_state`).
///
/// Returns `{ redacted_pczt_hex, pczt_sighash_hex, rk_hex, action_index,
/// delegated_weight, display_memo, real_note_nullifiers_hex, dummy_note_
/// nullifiers_hex, delegation_context_json, delegation_state_json }`.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_delegation_pczt(
    fvk_hex: &str,
    seed_fingerprint_hex: &str,
    account_index: u32,
    hotkey_pubkey_hex: &str,
    notes_json: &str,
    round_params_json: &str,
    consensus_branch_id: u32,
    round_name: &str,
    network: &str,
    bundle_index: u32,
) -> Result<String, JsError> {
    let net = parse_network(network)?;
    let fvk = hx(fvk_hex, "fvk")?;
    let seed_fingerprint = arr32(seed_fingerprint_hex, "seed_fingerprint")?;
    let hotkey_raw_address = hx(hotkey_pubkey_hex, "hotkey_pubkey")?;
    let note_dtos: Vec<NoteInfoDto> =
        serde_json::from_str(notes_json).map_err(|e| JsError::new(&format!("notes_json: {e}")))?;
    let notes = note_dtos
        .iter()
        .map(NoteInfoDto::to_note)
        .collect::<Result<Vec<_>, _>>()?;
    let round: RoundParamsDto = serde_json::from_str(round_params_json)
        .map_err(|e| JsError::new(&format!("round_params_json: {e}")))?;
    let params = round.to_params()?;

    let artifact = crate_build_delegation_pczt(
        &notes,
        &params,
        net,
        &fvk,
        &hotkey_raw_address,
        consensus_branch_id,
        &seed_fingerprint,
        account_index,
        round_name,
    )
    .map_err(|e| JsError::new(&format!("build delegation pczt failed: {e}")))?;
    let g = &artifact.governance;

    let real_nullifiers_hex: Vec<String> =
        notes.iter().map(|n| hex::encode(&n.nullifier)).collect();
    let dummy_nullifiers_hex: Vec<String> =
        g.dummy_nullifiers.iter().map(hex::encode).collect();
    let gov_nullifiers_hex: Vec<String> = g.gov_nullifiers.iter().map(hex::encode).collect();
    let padded_note_secrets: Vec<[String; 2]> = g
        .padded_note_secrets
        .iter()
        .map(|(rho, rseed)| [hex::encode(rho), hex::encode(rseed)])
        .collect();

    // address_index: the voting hotkey's Orchard address index (constant 0 for
    // hotkeys minted by `generate_voting_hotkey`). This is what zkp2 casting
    // reads back as `address_index`.
    let address_index = zcash_voting::hotkey::VOTING_HOTKEY_ADDRESS_INDEX;

    // delegation_state MUST match casting's DelegationStateArg byte-for-byte.
    let delegation_state = serde_json::json!({
        "address_index": address_index,
        "total_note_value": artifact.total_note_value,
        "gov_comm_rand_hex": hex::encode(&g.van_comm_rand),
        // Initial per-bundle authority: all 16 bits set (bit 0 is the dead
        // sentinel). The host clears bit `proposal_id` for each vote it later
        // submits in this bundle before the next cast.
        "proposal_authority": 65535u64,
        "bundle_index": bundle_index,
    });

    let context = DelegationContext {
        network: network_str(net).to_string(),
        notes: note_dtos,
        hotkey_raw_address_hex: hex::encode(&hotkey_raw_address),
        alpha_hex: hex::encode(&g.alpha),
        van_comm_rand_hex: hex::encode(&g.van_comm_rand),
        vote_round_id_hex: params.vote_round_id.clone(),
        padded_note_secrets,
        rseed_signed_hex: hex::encode(&g.rseed_signed),
        rseed_output_hex: hex::encode(&g.rseed_output),
        dummy_nullifiers_hex: dummy_nullifiers_hex.clone(),
        rk_hex: hex::encode(&g.rk),
        nf_signed_hex: hex::encode(&g.nf_signed),
        cmx_new_hex: hex::encode(&g.cmx_new),
        van_hex: hex::encode(&g.van),
        gov_nullifiers_hex,
        pczt_sighash_hex: hex::encode(&g.pczt_sighash),
        action_index: g.action_index,
    };
    let context_json = serde_json::to_string(&context)
        .map_err(|e| JsError::new(&format!("serialize context: {e}")))?;

    let out = serde_json::json!({
        "redacted_pczt_hex": hex::encode(&artifact.redacted_pczt),
        "pczt_sighash_hex": hex::encode(&g.pczt_sighash),
        "rk_hex": hex::encode(&g.rk),
        "action_index": g.action_index,
        "delegated_weight": artifact.total_note_value,
        "display_memo": artifact.display_memo,
        "real_note_nullifiers_hex": real_nullifiers_hex,
        "dummy_note_nullifiers_hex": dummy_nullifiers_hex,
        "delegation_context_json": context_json,
        "delegation_state_json": delegation_state.to_string(),
    });
    Ok(out.to_string())
}

// ---- export 2: prove + assemble submission wire ----------------------------

/// Finalize delegation (phase 2 of 2): run ZKP #1 with host-injected IMT proofs
/// and attach the cold signer's spend-auth signature into the submission wire.
///
/// Args:
/// * `delegation_context_json` — the opaque blob from `build_delegation_pczt`.
/// * `merkle_witnesses_json` — `[WitnessDto]`, one per note, in note order.
/// * `imt_proofs_json` — `[ImtProofDto]` covering BOTH the real note nullifiers
///   and the `dummy_note_nullifiers_hex` reported by phase 1 (keyed by nullifier).
/// * `spend_auth_sig_hex` — 64-byte SpendAuth signature from the cold signer.
/// * `sighash_hex` — 32-byte sighash the signer signed (must equal the PCZT sighash).
///
/// Returns `{ delegation_submission_wire_json }` — the `POST /delegate-vote` body.
#[wasm_bindgen]
pub fn finalize_delegation(
    delegation_context_json: &str,
    merkle_witnesses_json: &str,
    imt_proofs_json: &str,
    spend_auth_sig_hex: &str,
    sighash_hex: &str,
) -> Result<String, JsError> {
    let ctx: DelegationContext = serde_json::from_str(delegation_context_json)
        .map_err(|e| JsError::new(&format!("delegation_context_json: {e}")))?;
    let net = parse_network(&ctx.network)?;

    let sighash = arr32(sighash_hex, "sighash")?;
    let pczt_sighash = arr32(&ctx.pczt_sighash_hex, "context.pczt_sighash")?;
    if sighash != pczt_sighash {
        return Err(JsError::new(
            "sighash does not match the PCZT sighash from build_delegation_pczt",
        ));
    }
    let spend_auth_sig = hx(spend_auth_sig_hex, "spend_auth_sig")?;
    if spend_auth_sig.len() != 64 {
        return Err(JsError::new("spend_auth_sig must be 64 bytes"));
    }

    let notes = ctx
        .notes
        .iter()
        .map(NoteInfoDto::to_note)
        .collect::<Result<Vec<_>, _>>()?;
    let hotkey_raw_address = hx(&ctx.hotkey_raw_address_hex, "hotkey_raw_address")?;
    let alpha = hx(&ctx.alpha_hex, "alpha")?;
    let van_comm_rand = hx(&ctx.van_comm_rand_hex, "van_comm_rand")?;
    let vote_round_id = hx(&ctx.vote_round_id_hex, "vote_round_id")?;
    let rseed_signed = hx(&ctx.rseed_signed_hex, "rseed_signed")?;
    let rseed_output = hx(&ctx.rseed_output_hex, "rseed_output")?;
    let padded_note_secrets = ctx
        .padded_note_secrets
        .iter()
        .map(|[rho, rseed]| Ok((hx(rho, "padded.rho")?, hx(rseed, "padded.rseed")?)))
        .collect::<Result<Vec<(Vec<u8>, Vec<u8>)>, JsError>>()?;

    // Index injected IMT proofs by nullifier hex.
    let witness_dtos: Vec<WitnessDto> = serde_json::from_str(merkle_witnesses_json)
        .map_err(|e| JsError::new(&format!("merkle_witnesses_json: {e}")))?;
    let witnesses = witness_dtos
        .iter()
        .map(WitnessDto::to_witness)
        .collect::<Result<Vec<_>, _>>()?;

    let imt_dtos: Vec<ImtProofDto> = serde_json::from_str(imt_proofs_json)
        .map_err(|e| JsError::new(&format!("imt_proofs_json: {e}")))?;
    let mut imt_by_nf = std::collections::HashMap::new();
    for dto in &imt_dtos {
        imt_by_nf.insert(dto.nullifier_hex.trim().to_ascii_lowercase(), dto);
    }
    let lookup = |nf_hex: &str, kind: &str| -> Result<InjectedImtProof, JsError> {
        imt_by_nf
            .get(&nf_hex.trim().to_ascii_lowercase())
            .ok_or_else(|| JsError::new(&format!("missing {kind} IMT proof for nullifier {nf_hex}")))?
            .to_injected()
    };

    // Real proofs in note order; dummy proofs per the phase-1 dummy nullifiers.
    let real_imt_proofs = notes
        .iter()
        .map(|n| lookup(&hex::encode(&n.nullifier), "real-note"))
        .collect::<Result<Vec<_>, _>>()?;
    let dummy_imt_proofs = ctx
        .dummy_nullifiers_hex
        .iter()
        .map(|nf| lookup(nf, "padded-note"))
        .collect::<Result<Vec<_>, _>>()?;

    let proof = prove_delegation(
        &notes,
        &hotkey_raw_address,
        &alpha,
        &van_comm_rand,
        &vote_round_id,
        &padded_note_secrets,
        &rseed_signed,
        &rseed_output,
        &witnesses,
        &real_imt_proofs,
        &dummy_imt_proofs,
        net,
    )
    .map_err(|e| JsError::new(&format!("delegation proof failed: {e}")))?;

    // Defensive: the proof's public nf_signed / cmx_new must equal the PCZT's.
    if hex::encode(&proof.nf_signed) != ctx.nf_signed_hex.trim().to_ascii_lowercase()
        && hex::encode(&proof.nf_signed) != ctx.nf_signed_hex
    {
        return Err(JsError::new(
            "ZKP nf_signed does not match PCZT nf_signed (input mismatch)",
        ));
    }
    if hex::encode(&proof.cmx_new) != ctx.cmx_new_hex.trim().to_ascii_lowercase()
        && hex::encode(&proof.cmx_new) != ctx.cmx_new_hex
    {
        return Err(JsError::new(
            "ZKP cmx_new does not match PCZT cmx_new (input mismatch)",
        ));
    }

    // Assemble DelegationSubmissionWire (mirror of wire_codec, base64 STANDARD;
    // vote_round_id is hex-decoded then base64).
    let vote_round_id_b64 = b64(&hx(&ctx.vote_round_id_hex, "vote_round_id")?);
    let gov_nullifiers_b64: Vec<String> = ctx
        .gov_nullifiers_hex
        .iter()
        .map(|h| Ok(b64(&hx(h, "gov_nullifier")?)))
        .collect::<Result<Vec<String>, JsError>>()?;

    let wire = serde_json::json!({
        "rk": b64(&hx(&ctx.rk_hex, "rk")?),
        "spend_auth_sig": b64(&spend_auth_sig),
        "sighash": b64(&sighash),
        "signed_note_nullifier": b64(&hx(&ctx.nf_signed_hex, "nf_signed")?),
        "cmx_new": b64(&hx(&ctx.cmx_new_hex, "cmx_new")?),
        "van_cmx": b64(&hx(&ctx.van_hex, "van")?),
        "gov_nullifiers": gov_nullifiers_b64,
        "proof": b64(&proof.proof),
        "vote_round_id": vote_round_id_b64,
    });

    let out = serde_json::json!({ "delegation_submission_wire_json": wire.to_string() });
    Ok(out.to_string())
}

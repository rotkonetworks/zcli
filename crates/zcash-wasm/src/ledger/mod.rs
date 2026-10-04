// Portions adapted from vizor-wallet (chainapsis/vizor-wallet, Apache-2.0), modified.
// See crates/zcash-wasm/LICENSE-APACHE-vizor.
//
//! Ledger Zcash app (3.9.x, Orchard + Ironwood) PROTOCOL layer.
//!
//! Pure functions only: build the exact APDU commands for an operation, and
//! parse and validate what the device answered. No I/O, no storage, no
//! account lookup. The host (zafu) owns the transport (WebHID), status words,
//! app-version checks and "is this PCZT for the selected account" policy.
//!
//! Every error message starts with one of the `LedgerFailure` kinds of zafu's
//! `apps/extension/src/ledger/zcash-app/contract.ts`, followed by ": ":
//!
//! - `unsupported_transaction:` the PCZT is over the app's limits, spends
//!   legacy Orchard into Ironwood, or has a shape the app cannot sign.
//! - `app_too_old:` the PCZT needs a newer app (memo-hash rendering).
//! - `protocol_error:` a device response is malformed, missing, or its
//!   signature does not verify. A signature that verifies against a DIFFERENT
//!   key carries a second tag: `protocol_error: ledger_signature_mismatch: `.
//!
//! Device responses are PAYLOADS with the status word stripped (the contract's
//! `LedgerZcashDevice.exchange` does that).

pub(crate) mod apdu;
mod parse;
mod serializer;
mod stamp;

use std::collections::HashSet;

use orchard::ValuePool;
use pczt::roles::signer::{Signer, SpendAuthSignature};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use zcash_transparent as transparent;

use self::{
    apdu::{ApduCommand, ZCASH_CLA},
    parse::{parse_pczt, LEDGER_MEMO_HASH_UNSUPPORTED},
    serializer::{packet_p1, packet_p2, serialize_pczt},
};

// Ledger Zcash app 3.9.3 limits. Shielded action limits apply per pool.
pub(crate) const MAX_TRANSPARENT_INPUTS: usize = 32;
pub(crate) const MAX_TRANSPARENT_OUTPUTS: usize = 10;
pub(crate) const MAX_SHIELDED_ACTIONS: usize = 32;

const UNSUPPORTED: &str = "unsupported_transaction: ";
const APP_TOO_OLD: &str = "app_too_old: ";
const PROTOCOL_ERROR: &str = "protocol_error: ";
const SIGNATURE_MISMATCH: &str = "protocol_error: ledger_signature_mismatch: ";
const LEGACY_ORCHARD_RECOVERY_UNSUPPORTED: &str =
    "unsupported_transaction: ledger_legacy_orchard_recovery_unsupported: The current Ledger Zcash app cannot sign a transaction that spends legacy Orchard funds into Ironwood.";
/// Domain separator for the synthetic account fingerprint. The Ledger GET_VK
/// APDU does not expose the ZIP-32 seed fingerprint, so (like vizor) a
/// domain-separated hash of the approved UFVK stands in as non-secret account
/// metadata. The host must stamp this same value into every
/// `Zip32Derivation` / `Bip32Derivation` of a Ledger account's PCZTs.
const ACCOUNT_FINGERPRINT_DOMAIN: &[u8] = b"zafu-ledger-account-fingerprint-v1\0";

fn unsupported(message: impl std::fmt::Display) -> String {
    format!("{UNSUPPORTED}{message}")
}

fn protocol(message: impl std::fmt::Display) -> String {
    format!("{PROTOCOL_ERROR}{message}")
}

/// Classifies a plan-time (pre-device) error from parse/serialize.
fn plan_error(message: String) -> String {
    if message == LEDGER_MEMO_HASH_UNSUPPORTED {
        format!("{APP_TOO_OLD}{message}")
    } else if message.starts_with(UNSUPPORTED) {
        message
    } else {
        unsupported(message)
    }
}

// ---------------------------------------------------------------------------
// UFVK export
// ---------------------------------------------------------------------------

/// Account material the user approved on the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccountExport {
    pub ufvk: String,
    pub seed_fingerprint: [u8; 32],
    pub account_index: u32,
}

pub(crate) fn ufvk_plan(account_index: u32) -> Result<Vec<ApduCommand>, String> {
    let (first, continuation) = apdu::ufvk_commands(account_index).map_err(unsupported)?;
    Ok(vec![first, continuation])
}

pub(crate) fn parse_ufvk(
    responses: &[Vec<u8>],
    network: &str,
    account_index: u32,
) -> Result<AccountExport, String> {
    let ufvk = apdu::decode_ufvk_chunks(responses).map_err(protocol)?;
    let decoded = match network.trim() {
        "main" => zcash_keys::keys::UnifiedFullViewingKey::decode(
            &zcash_protocol::consensus::MainNetwork,
            &ufvk,
        ),
        "test" => zcash_keys::keys::UnifiedFullViewingKey::decode(
            &crate::consensus::TestNetwork,
            &ufvk,
        ),
        other => return Err(protocol(format!("unknown network {other:?}"))),
    };
    decoded.map_err(|error| protocol(format!("Failed to parse Ledger UFVK: {error}")))?;
    Ok(AccountExport {
        seed_fingerprint: account_fingerprint(&ufvk, account_index),
        ufvk,
        account_index,
    })
}

fn account_fingerprint(ufvk: &str, account_index: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACCOUNT_FINGERPRINT_DOMAIN);
    hasher.update(account_index.to_be_bytes());
    hasher.update(ufvk.as_bytes());
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// PCZT validation and signing plan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TransparentInputSignature {
    signature: Vec<u8>,
    sighash_type: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureRequest {
    Transparent {
        input_index: usize,
    },
    Shielded {
        pool: ValuePool,
        action_index: usize,
        instruction: u8,
    },
}

/// Rejects, before anything reaches the device, a PCZT the Ledger Zcash app
/// cannot sign: over the per-transaction limits, spending legacy Orchard into
/// Ironwood, or any shape the compact PCZT APDUs cannot express.
pub(crate) fn validate_pczt(pczt_bytes: &[u8]) -> Result<(), String> {
    let parsed = parse_pczt(pczt_bytes).map_err(plan_error)?;
    // Capacity and packet-size checks live in the serializer; run it with the
    // memo-hash capability assumed so only the app-independent limits apply.
    serialize_pczt(&parsed, true).map_err(plan_error)?;
    validate_release_support(&parsed)
}

/// Blocks the known Ledger Zcash app Orchard-to-Ironwood signing defect
/// (vizor LEGACY_ORCHARD_RECOVERY_UNSUPPORTED) without changing the PCZT.
fn validate_release_support(parsed: &parse::ParsedPczt) -> Result<(), String> {
    let has_orchard_spend = parsed
        .orchard_bundle
        .as_ref()
        .is_some_and(|bundle| bundle.actions.iter().any(|action| action.spend_value != 0));
    let has_ironwood_output = parsed
        .ironwood_bundle
        .as_ref()
        .is_some_and(|bundle| bundle.actions.iter().any(|action| action.action.value != 0));
    require_legacy_orchard_recovery_support(has_orchard_spend, has_ironwood_output)
}

fn require_legacy_orchard_recovery_support(
    has_orchard_spend: bool,
    has_ironwood_output: bool,
) -> Result<(), String> {
    if has_orchard_spend && has_ironwood_output {
        Err(LEGACY_ORCHARD_RECOVERY_UNSUPPORTED.into())
    } else {
        Ok(())
    }
}

/// The complete ordered APDU exchange for a fully signed PCZT (vizor
/// `build_pczt_full_signing_plan`): PCZT packets, then one signature request per
/// transparent input, then one per real Orchard spend, then one per real
/// Ironwood spend. Also enforces [`validate_pczt`], so a host that skips it
/// still cannot send an unsupported PCZT to the device.
pub(crate) fn pczt_signing_plan(
    pczt_bytes: &[u8],
    memo_hash_supported: bool,
) -> Result<Vec<ApduCommand>, String> {
    validate_pczt(pczt_bytes)?;
    build_signing_plan(pczt_bytes, memo_hash_supported).map(|(commands, _)| commands)
}

/// Validates the device responses for [`pczt_signing_plan`], verifies and
/// applies every signature, and returns the signed PCZT.
///
/// `pczt_bytes` must be the same IO-finalized PCZT the plan was built from.
pub(crate) fn finalize_pczt_signing(
    pczt_bytes: &[u8],
    responses: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    validate_pczt(pczt_bytes)?;
    let parsed = parse_pczt(pczt_bytes).map_err(plan_error)?;
    // The plan is rebuilt with the memo-hash capability assumed: the memo gate
    // only decides whether a plan may be SENT, and it already was.
    let (commands, requests) = build_signing_plan(pczt_bytes, true)?;
    let (transparent, shielded) = decode_signing_responses(&commands, &requests, responses)?;
    apply_signatures(pczt_bytes, &parsed, &transparent, &shielded)
}

fn build_signing_plan(
    pczt_bytes: &[u8],
    memo_hash_supported: bool,
) -> Result<(Vec<ApduCommand>, Vec<SignatureRequest>), String> {
    let parsed = parse_pczt(pczt_bytes).map_err(plan_error)?;
    let serialized = serialize_pczt(&parsed, memo_hash_supported).map_err(plan_error)?;
    let mut commands = Vec::new();
    for command in serialized {
        let total = command.packets.len();
        if total == 0 {
            return Err(unsupported("Ledger PCZT command has no packets"));
        }
        for (index, data) in command.packets.into_iter().enumerate() {
            commands.push(ApduCommand {
                cla: ZCASH_CLA,
                ins: command.instruction,
                p1: packet_p1(index, total),
                p2: packet_p2(index, total, command.finishes_pczt),
                data,
            });
        }
    }

    let mut requests: Vec<SignatureRequest> = (0..parsed.transparent_inputs.len())
        .map(|input_index| SignatureRequest::Transparent { input_index })
        .collect();
    let orchard_actions = parsed
        .orchard_bundle
        .iter()
        .flat_map(|bundle| bundle.actions.iter())
        .map(|action| (ValuePool::Orchard, 0x57, action));
    let ironwood_actions = parsed
        .ironwood_bundle
        .iter()
        .flat_map(|bundle| bundle.actions.iter())
        .map(|action| (ValuePool::Ironwood, 0x59, &action.action));
    let mut pool_index = (ValuePool::Orchard, 0usize);
    for (pool, instruction, action) in orchard_actions.chain(ironwood_actions) {
        if pool != pool_index.0 {
            pool_index = (pool, 0);
        }
        let action_index = pool_index.1;
        pool_index.1 += 1;
        require_signable(pool, action_index, action)?;
        if action.needs_signature {
            requests.push(SignatureRequest::Shielded {
                pool,
                action_index,
                instruction,
            });
        }
    }
    if requests.is_empty() {
        return Err(unsupported(
            "PCZT has no unsigned transparent, Orchard, or Ironwood spends for Ledger to sign",
        ));
    }

    for request in &requests {
        let (ins, p2) = match request {
            SignatureRequest::Transparent { input_index } => (0x55, *input_index),
            SignatureRequest::Shielded {
                action_index,
                instruction,
                ..
            } => (*instruction, *action_index),
        };
        commands.push(ApduCommand {
            cla: ZCASH_CLA,
            ins,
            p1: 0,
            p2: u8::try_from(p2)
                .map_err(|_| unsupported("Ledger signing index exceeds the APDU range"))?,
            data: Vec::new(),
        });
    }
    Ok((commands, requests))
}

/// The Ledger signs every shielded spend that has no authorization yet: real
/// spends and the zero-value spends the wallet controls. True dummies (random
/// keys) must already be signed by the IO Finalizer; the device would sign them
/// with the account key and produce an invalid transaction. Checked up front so
/// a PCZT that was not IO-finalized fails before the device review rather than
/// after the user approved it.
fn require_signable(
    pool: ValuePool,
    action_index: usize,
    action: &parse::ShieldedAction,
) -> Result<(), String> {
    if action.needs_signature && action.is_dummy {
        return Err(unsupported(format!(
            "{pool:?} action {action_index} is an unsigned dummy spend; pass the IO-finalized PCZT"
        )));
    }
    if !action.needs_signature && action.spend_value != 0 {
        return Err(unsupported(format!(
            "{pool:?} action {action_index} spends a real note that is already authorized"
        )));
    }
    Ok(())
}

fn unsigned_shielded_action_locations(pczt: &pczt::Pczt) -> HashSet<(ValuePool, usize)> {
    let pool_actions = |pool: ValuePool, bundle: &pczt::orchard::Bundle| {
        bundle
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| action.spend().spend_auth_sig().is_none())
            .map(move |(index, _)| (pool, index))
            .collect::<Vec<_>>()
    };
    pool_actions(ValuePool::Orchard, pczt.orchard())
        .into_iter()
        .chain(pool_actions(ValuePool::Ironwood, pczt.ironwood()))
        .collect()
}

// ---------------------------------------------------------------------------
// Response decoding and signature application
// ---------------------------------------------------------------------------

fn decode_signing_responses(
    commands: &[ApduCommand],
    requests: &[SignatureRequest],
    responses: &[Vec<u8>],
) -> Result<(Vec<TransparentInputSignature>, Vec<SpendAuthSignature>), String> {
    if responses.len() != commands.len() {
        return Err(protocol(format!(
            "Ledger returned {} APDU response(s); expected {}",
            responses.len(),
            commands.len()
        )));
    }
    let packet_count = commands.len() - requests.len();
    for (index, payload) in responses[..packet_count].iter().enumerate() {
        if !payload.is_empty() {
            return Err(protocol(format!(
                "Ledger PCZT APDU {} returned unexpected response data",
                index + 1
            )));
        }
    }

    let mut transparent = Vec::new();
    let mut shielded = Vec::new();
    for (request, payload) in requests.iter().zip(&responses[packet_count..]) {
        match request {
            SignatureRequest::Transparent { input_index } => {
                transparent.push(decode_transparent_signature(payload).map_err(|error| {
                    protocol(format!(
                        "Ledger transparent signature {input_index} is invalid: {error}"
                    ))
                })?)
            }
            SignatureRequest::Shielded {
                pool, action_index, ..
            } => {
                let signature: [u8; 64] = payload.as_slice().try_into().map_err(|_| {
                    protocol(format!(
                        "Ledger returned a {}-byte spend authorization signature; expected 64",
                        payload.len()
                    ))
                })?;
                if signature.iter().all(|byte| *byte == 0) {
                    return Err(protocol(
                        "Ledger returned an all-zero spend authorization signature",
                    ));
                }
                shielded.push(SpendAuthSignature::from_parts(
                    *pool,
                    *action_index,
                    signature,
                ));
            }
        }
    }
    Ok((transparent, shielded))
}

fn decode_transparent_signature(response: &[u8]) -> Result<TransparentInputSignature, String> {
    if !(9..=73).contains(&response.len()) {
        return Err(format!(
            "returned {} bytes; expected DER plus sighash type",
            response.len()
        ));
    }
    let (signature, sighash_type) = response.split_at(response.len() - 1);
    if signature[0] & 0xfe != 0x30 {
        return Err("invalid DER sequence tag".into());
    }
    if signature[1] as usize + 2 != signature.len() {
        return Err("invalid DER length".into());
    }
    Ok(TransparentInputSignature {
        signature: signature.to_vec(),
        sighash_type: sighash_type[0],
    })
}

/// Only a signature that fails verification means the device signed with
/// another key; the rest are malformed responses or PCZT construction bugs.
fn is_signature_verification_failure(error: &pczt::roles::signer::Error) -> bool {
    use pczt::roles::signer::Error;
    matches!(
        error,
        Error::TransparentSign(transparent::pczt::SignerError::InvalidExternalSignature)
            | Error::OrchardSign(orchard::pczt::SignerError::InvalidExternalSignature)
            | Error::IronwoodSign(orchard::pczt::SignerError::InvalidExternalSignature)
    )
}

fn signer_error(message: String, error: &pczt::roles::signer::Error) -> String {
    if is_signature_verification_failure(error) {
        format!("{SIGNATURE_MISMATCH}{message}")
    } else {
        protocol(message)
    }
}

fn apply_signatures(
    pczt_bytes: &[u8],
    parsed: &parse::ParsedPczt,
    transparent_signatures: &[TransparentInputSignature],
    shielded_signatures: &[SpendAuthSignature],
) -> Result<Vec<u8>, String> {
    if transparent_signatures.len() != parsed.transparent_inputs.len() {
        return Err(protocol(format!(
            "Ledger returned {} transparent signature(s); expected {}",
            transparent_signatures.len(),
            parsed.transparent_inputs.len()
        )));
    }

    let pczt = pczt::Pczt::parse(pczt_bytes)
        .map_err(|e| protocol(format!("Parse PCZT for Ledger signatures: {e:?}")))?;

    // Exactly one signature per unsigned shielded action, none twice.
    let required = unsigned_shielded_action_locations(&pczt);
    let mut provided = HashSet::new();
    for signature in shielded_signatures {
        let location = (signature.value_pool(), signature.action_index());
        if !provided.insert(location) {
            return Err(protocol(format!(
                "Duplicate Ledger signature for pool {:?} action {}",
                location.0, location.1
            )));
        }
        if !required.contains(&location) {
            return Err(protocol(format!(
                "Unexpected Ledger signature for pool {:?} action {}; the action is absent or already authorized",
                location.0, location.1
            )));
        }
    }
    if provided.len() != required.len() {
        return Err(protocol(format!(
            "Missing {} required spend-authorization signature(s)",
            required.len() - provided.len()
        )));
    }

    // The upstream transparent Signer locates the validating pubkey for a P2PKH
    // input through its hash160 preimage map. The parser already required
    // exactly one BIP-32 pubkey per input, so provide that same public data.
    let mut updater = pczt::roles::updater::Updater::new(pczt);
    if !parsed.transparent_inputs.is_empty() {
        updater = updater
            .update_transparent_with(|mut bundle| {
                for (index, input) in parsed.transparent_inputs.iter().enumerate() {
                    bundle.update_input_with(index, |mut input_updater| {
                        input_updater.set_hash160_preimage(input.derivation.pubkey.to_vec());
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .map_err(|e| {
                protocol(format!(
                    "Prepare transparent PCZT signature validation: {e:?}"
                ))
            })?;
    }

    let mut signer = Signer::new(updater.finish())
        .map_err(|e| protocol(format!("Create Ledger PCZT signer: {e:?}")))?;

    for (input_index, (input, ledger_signature)) in parsed
        .transparent_inputs
        .iter()
        .zip(transparent_signatures)
        .enumerate()
    {
        if ledger_signature.sighash_type != input.sighash_type {
            return Err(protocol(format!(
                "Ledger transparent signature {input_index} used sighash type {:#04x}; expected {:#04x}",
                ledger_signature.sighash_type, input.sighash_type
            )));
        }

        let mut der = ledger_signature.signature.clone();
        // Ledger stores the derived public key's Y parity in the low bit of the
        // usual 0x30 DER sequence tag. It is metadata, not part of the signature.
        der[0] &= 0xfe;
        let signature = secp256k1::ecdsa::Signature::from_der(&der).map_err(|e| {
            protocol(format!(
                "Parse Ledger transparent signature {input_index} as DER: {e}"
            ))
        })?;

        signer
            .append_transparent_signature(input_index, signature)
            .map_err(|e| {
                signer_error(
                    format!("Validate Ledger transparent signature {input_index}: {e:?}"),
                    &e,
                )
            })?;
    }

    for signature in shielded_signatures {
        signer
            .apply_orchard_spend_auth_signature(signature)
            .map_err(|e| {
                signer_error(
                    format!(
                        "Apply Ledger {:?} signature at action {}: {e:?}",
                        signature.value_pool(),
                        signature.action_index()
                    ),
                    &e,
                )
            })?;
    }

    signer
        .finish()
        .serialize()
        .map_err(|e| protocol(format!("Serialize Ledger-signed PCZT: {e:?}")))
}

// ---------------------------------------------------------------------------
// wasm boundary
// ---------------------------------------------------------------------------

fn js_err(message: String) -> JsError {
    JsError::new(&message)
}

fn commands_to_js(commands: &[ApduCommand]) -> Result<JsValue, JsError> {
    let array = js_sys::Array::new();
    for command in commands {
        let object = js_sys::Object::new();
        let set = |key: &str, value: JsValue| {
            js_sys::Reflect::set(&object, &JsValue::from_str(key), &value)
                .map(|_| ())
                .map_err(|_| JsError::new("protocol_error: could not build APDU object"))
        };
        set("cla", JsValue::from(command.cla))?;
        set("ins", JsValue::from(command.ins))?;
        set("p1", JsValue::from(command.p1))?;
        set("p2", JsValue::from(command.p2))?;
        set(
            "data",
            js_sys::Uint8Array::from(command.data.as_slice()).into(),
        )?;
        array.push(&object);
    }
    Ok(array.into())
}

fn responses_from_js(responses: &js_sys::Array) -> Result<Vec<Vec<u8>>, JsError> {
    responses
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .dyn_into::<js_sys::Uint8Array>()
                .map(|bytes| bytes.to_vec())
                .map_err(|_| {
                    JsError::new(&format!(
                        "protocol_error: Ledger response {index} is not a Uint8Array"
                    ))
                })
        })
        .collect()
}

/// APDUs that export the UFVK for `account_index`: `[first, continuation]`.
/// Send `first`, then repeat `continuation` while
/// [`ledger_ufvk_remaining_bytes`] reports bytes still owed.
#[wasm_bindgen]
pub fn ledger_ufvk_plan(account_index: u32) -> Result<JsValue, JsError> {
    commands_to_js(&ufvk_plan(account_index).map_err(js_err)?)
}

/// UFVK bytes the device still owes after `responses` (status words
/// stripped). `0` means stop sending continuations and call
/// [`ledger_parse_ufvk`].
#[wasm_bindgen]
pub fn ledger_ufvk_remaining_bytes(responses: js_sys::Array) -> Result<u32, JsError> {
    let responses = responses_from_js(&responses)?;
    let remaining = apdu::ufvk_remaining_bytes(&responses)
        .map_err(protocol)
        .map_err(js_err)?;
    Ok(remaining as u32)
}

/// Reassembles and validates the UFVK export. Returns
/// `{ ufvk: string, seedFingerprint: Uint8Array(32), accountIndex: number }`.
#[wasm_bindgen]
pub fn ledger_parse_ufvk(
    responses: js_sys::Array,
    network: &str,
    account_index: u32,
) -> Result<JsValue, JsError> {
    let responses = responses_from_js(&responses)?;
    let export = parse_ufvk(&responses, network, account_index).map_err(js_err)?;
    let object = js_sys::Object::new();
    let set = |key: &str, value: JsValue| {
        js_sys::Reflect::set(&object, &JsValue::from_str(key), &value)
            .map(|_| ())
            .map_err(|_| JsError::new("protocol_error: could not build account object"))
    };
    set("ufvk", JsValue::from_str(&export.ufvk))?;
    set(
        "seedFingerprint",
        js_sys::Uint8Array::from(export.seed_fingerprint.as_slice()).into(),
    )?;
    set("accountIndex", JsValue::from(export.account_index))?;
    Ok(object.into())
}

/// Throws `unsupported_transaction: ...` when the Ledger Zcash app cannot sign
/// this PCZT (limits: 32 transparent inputs, 10 transparent outputs, 32 actions
/// per shielded pool; legacy Orchard into Ironwood; unsupported shapes).
#[wasm_bindgen]
pub fn ledger_validate_pczt(pczt: &[u8]) -> Result<(), JsError> {
    validate_pczt(pczt).map_err(js_err)
}

/// The full ordered APDU exchange that has the device review the PCZT once
/// and sign every transparent input and real Orchard / Ironwood spend.
/// `memo_hash_supported` comes from the app version (3.9.4+).
#[wasm_bindgen]
pub fn ledger_pczt_signing_plan(
    pczt: &[u8],
    memo_hash_supported: bool,
) -> Result<JsValue, JsError> {
    commands_to_js(&pczt_signing_plan(pczt, memo_hash_supported).map_err(js_err)?)
}

/// Validates one response per plan command (status words stripped), verifies
/// every signature, and returns the signed PCZT bytes.
#[wasm_bindgen]
pub fn ledger_finalize_pczt_signing(
    pczt: &[u8],
    responses: js_sys::Array,
) -> Result<Vec<u8>, JsError> {
    let responses = responses_from_js(&responses)?;
    finalize_pczt_signing(pczt, &responses).map_err(js_err)
}

/// Stamps the Ledger account's derivations onto a zafu-built PCZT so the
/// signing plan can serialize it. `transparent_paths` is an array of
/// `{ input_index, scope, address_index, pubkey: Uint8Array(33) }`, one per
/// transparent input. Idempotent; refuses to overwrite a different derivation.
#[wasm_bindgen]
pub fn ledger_stamp_derivations(
    pczt: &[u8],
    seed_fingerprint: &[u8],
    account_index: u32,
    transparent_paths: JsValue,
) -> Result<Vec<u8>, JsError> {
    let seed_fingerprint: [u8; 32] = seed_fingerprint
        .try_into()
        .map_err(|_| JsError::new("protocol_error: seed fingerprint must be 32 bytes"))?;
    let paths = transparent_paths_from_js(&transparent_paths)?;
    stamp::stamp_derivations(pczt, &seed_fingerprint, account_index, &paths).map_err(js_err)
}

fn transparent_paths_from_js(value: &JsValue) -> Result<Vec<stamp::TransparentPath>, JsError> {
    if value.is_undefined() || value.is_null() {
        return Ok(Vec::new());
    }
    let array = value
        .dyn_ref::<js_sys::Array>()
        .ok_or_else(|| JsError::new("protocol_error: transparent_paths must be an array"))?;
    array
        .iter()
        .enumerate()
        .map(|(n, entry)| {
            let field = |key: &str| {
                js_sys::Reflect::get(&entry, &JsValue::from_str(key)).map_err(|_| {
                    JsError::new(&format!(
                        "protocol_error: transparent_paths[{n}] is not an object"
                    ))
                })
            };
            let number = |key: &str| -> Result<u32, JsError> {
                let value = field(key)?.as_f64().ok_or_else(|| {
                    JsError::new(&format!(
                        "protocol_error: transparent_paths[{n}].{key} must be a number"
                    ))
                })?;
                if value.fract() != 0.0 || !(0.0..=u32::MAX as f64).contains(&value) {
                    return Err(JsError::new(&format!(
                        "protocol_error: transparent_paths[{n}].{key} must be a u32"
                    )));
                }
                Ok(value as u32)
            };
            let pubkey: [u8; 33] = field("pubkey")?
                .dyn_into::<js_sys::Uint8Array>()
                .map(|bytes| bytes.to_vec())
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    JsError::new(&format!(
                        "protocol_error: transparent_paths[{n}].pubkey must be a 33-byte Uint8Array"
                    ))
                })?;
            Ok(stamp::TransparentPath {
                input_index: number("input_index")?,
                scope: number("scope")?,
                address_index: number("address_index")?,
                pubkey,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod speculos_tests;

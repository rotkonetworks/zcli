//! WASM bindings for Zafu Zcash wallet
//!
//! Provides parallel trial decryption for browser-based Zcash wallets.
//! Uses rayon + web workers for multi-threaded scanning with SIMD acceleration.
//!
//! Build with:
//! ```bash
//! RUSTFLAGS='-C target-feature=+simd128' wasm-pack build --target web --out-dir ../bin/zidecar/www/pkg
//! ```

mod frost;
/// HOT shielded-voting vote-casting bindings (casting slice only).
mod voting;
/// Shielded-voting delegation bindings (cold-signed PCZT + ZKP #1).
mod voting_delegation;
/// PIR bindings: fetch IMT non-membership proofs via a JS `fetch` callback.
/// wasm-only: it backs pir-client's async Transport with a `!Send` JS handle,
/// which only satisfies the (Send-relaxed) wasm Transport contract.
#[cfg(target_arch = "wasm32")]
mod voting_pir;
/// Commitment-tree replay and witness serialization.
///
/// Public because it is the SINGLE implementation of "walk a commitment tree
/// forward and witness these positions", shared by the wasm worker, zcli's
/// pool-aware witness builder, and the regtest end-to-end tests. Duplicating it
/// per pool is how you end up with a witness against the wrong tree.
pub mod witness;

use blake2::{Blake2b512, Digest};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// Real Orchard key derivation and note decryption
use orchard::keys::{IncomingViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey};
use orchard::note_encryption::{
    DomainVersion, IronwoodDomain, NoteEncryptionDomain, OrchardDomain,
};
use zcash_note_encryption::{
    try_compact_note_decryption, EphemeralKeyBytes, ShieldedOutput, COMPACT_NOTE_SIZE,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(feature = "parallel")]
pub use wasm_bindgen_rayon::init_thread_pool;

// JS console.log binding for WASM debug output
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = warn)]
    #[allow(dead_code)]
    fn console_warn(s: &str);
}

/// NU6.2 consensus branch id. Kept as a NAMED CONSTANT for tests and for
/// recognising historical transactions ONLY — it is deliberately *not* a
/// fallback for transaction construction. Defaulting to it silently produced
/// txs whose ZIP-244 sighash bound the wrong branch after NU6.3 activated; see
/// [`resolve_branch_id`], which fails closed instead.
pub const NU6_2_BRANCH_ID: u32 = 0x5437F330;

/// Parse the consensus branch id as returned by lightwalletd/zidecar
/// `GetLightdInfo.consensusBranchId` — a lowercase (per spec) hex string such as
/// `"5437f330"` (NU6.2) or `"37a5165b"` (NU6.3), with no `0x` prefix. Tolerates
/// an optional `0x`/`0X` prefix and surrounding whitespace. Returns `None` on
/// malformed or empty input so the caller can fall back safely.
fn parse_branch_id(s: &str) -> Option<u32> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.is_empty() {
        return None;
    }
    u32::from_str_radix(t, 16).ok()
}

/// Resolve the consensus branch id to bind into a transaction, given the
/// optional hex string a `#[wasm_bindgen]` builder received from JS.
///
/// The value is expected to be `LightdInfo.consensusBranchId` (a hex string like
/// `"5437f330"`), passed through verbatim so the browser never has to convert it.
///
/// FAIL-CLOSED: there is no fallback. Silently defaulting to the compiled-in
/// NU6.2 value produced a transaction whose ZIP-244 sighash binds the WRONG
/// branch id once NU6.3 activated — the wallet paid for a Halo 2 proof, the
/// node rejected the broadcast with "incorrect consensus branch id", and the
/// only trace was a `console.warn` nobody reads. A wallet that cannot learn the
/// live branch id must refuse to build, not guess. Callers on a *non*
/// transaction-constructing path (nothing binds the value) should not use this.
fn resolve_branch_id(branch_id_hex: Option<&str>) -> Result<u32, String> {
    branch_id_hex.and_then(parse_branch_id).ok_or_else(|| {
        format!(
            "no usable consensus branch id (got {:?}): refusing to build a \
             transaction that would bind a guessed branch id. Pass \
             LightdInfo.consensusBranchId from the endpoint verbatim (e.g. \
             \"37a5165b\" for NU6.3); an empty string means the GetLightdInfo \
             call failed and the send must be retried, not defaulted.",
            branch_id_hex
        )
    })
}

/// FAIL-CLOSED gate for the legacy ORCHARD *spend* builders (the z→z / z→t
/// paths that build a V5 orchard bundle with `BundleProtocol::OrchardPreNu6_2`).
///
/// Orchard→orchard spends are consensus-disabled by the NU6.3 one-way
/// turnstile. Building one at/after activation burns two minutes of Halo 2
/// proving and is then rejected by the node, so refuse before proving. Checked
/// on the live branch id, which is the only NU6.3 signal these builders receive
/// (they take no target height).
fn guard_orchard_spend_allowed(branch_id: u32) -> Result<(), String> {
    if branch_id == NU6_3_BRANCH_ID {
        return Err(format!(
            "orchard spends are disabled at NU6.3 (live consensus branch id \
             {:#010x}): an orchard bundle built now is rejected by the network. \
             Spend from the ironwood pool instead (build_signed_ironwood_send / \
             build_ironwood_send_pczt); orchard funds must first cross the \
             one-way turnstile (build_signed_turnstile_migration).",
            branch_id
        ));
    }
    Ok(())
}

/// Native fallback: wasm-bindgen imports panic when called off-wasm, and the
/// proving-key paths (exercised by cargo tests) log through this.
#[cfg(not(target_arch = "wasm32"))]
fn log(s: &str) {
    eprintln!("{}", s);
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
fn console_warn(s: &str) {
    eprintln!("{}", s);
}

/// Cached Halo 2 proving keys, one per circuit version. Building is
/// expensive (~seconds), built once per version and shared across all rayon
/// threads via OnceLock.
///
/// The NU6.3 fork parameterizes `ProvingKey::build` by circuit version:
/// - `InsecurePreNu6_2`: the historical NU5..NU6.1 circuit. Required for
///   proving against chains whose consensus branch predates NU6.2 (the fixed
///   circuit has a different verifying key, so its proofs would not verify
///   there). This is what today's mainnet V5 paths use.
/// - `FixedPostNu6_2`: the NU6.2 fixed circuit.
/// - `PostNu6_3`: the NU6.3 circuit with the `disableCrossAddress` public
///   input. Used for BOTH the orchard and ironwood bundles of a V6 tx.
static PROVING_KEY_PRE_NU6_2: std::sync::OnceLock<orchard::circuit::ProvingKey> =
    std::sync::OnceLock::new();
static PROVING_KEY_POST_NU6_2: std::sync::OnceLock<orchard::circuit::ProvingKey> =
    std::sync::OnceLock::new();
static PROVING_KEY_POST_NU6_3: std::sync::OnceLock<orchard::circuit::ProvingKey> =
    std::sync::OnceLock::new();

fn proving_key_cell(
    cv: orchard::circuit::OrchardCircuitVersion,
) -> &'static std::sync::OnceLock<orchard::circuit::ProvingKey> {
    use orchard::circuit::OrchardCircuitVersion as Cv;
    match cv {
        Cv::InsecurePreNu6_2 => &PROVING_KEY_PRE_NU6_2,
        Cv::FixedPostNu6_2 => &PROVING_KEY_POST_NU6_2,
        Cv::PostNu6_3 => &PROVING_KEY_POST_NU6_3,
    }
}

fn with_proving_key_for<R>(
    cv: orchard::circuit::OrchardCircuitVersion,
    f: impl FnOnce(&orchard::circuit::ProvingKey) -> R,
) -> R {
    let pk = proving_key_cell(cv).get_or_init(|| {
        log(&format!(
            "[zafu-wasm] building Halo 2 proving key for {:?} (one-time)",
            cv
        ));
        orchard::circuit::ProvingKey::build(cv)
    });
    f(pk)
}

/// Legacy helper for the hand-rolled V5 paths, which hardcode the NU6.1
/// consensus branch (0x4DEC4DF0) and therefore MUST prove with the
/// historical circuit to match the verifying key deployed on those branches.
fn with_proving_key<R>(f: impl FnOnce(&orchard::circuit::ProvingKey) -> R) -> R {
    with_proving_key_for(orchard::circuit::OrchardCircuitVersion::InsecurePreNu6_2, f)
}

/// Map a consensus branch to the orchard bundle protocol the
/// zcash_primitives Builder selects for it. Mirrors the (private)
/// `orchard_protocol_for_branch` in the fork's builder.rs — keep in sync.
fn orchard_protocol_for_branch(
    branch: zcash_protocol::consensus::BranchId,
) -> orchard::bundle::BundleVersion {
    use zcash_protocol::consensus::BranchId;
    match branch {
        BranchId::Nu6_3 => orchard::bundle::BundleVersion::orchard_v3(),
        BranchId::Nu6_2 => orchard::bundle::BundleVersion::orchard_v2(),
        _ => orchard::bundle::BundleVersion::orchard_insecure_v1(),
    }
}

/// Initialize panic hook for better error messages
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Wallet keys derived from seed phrase
#[wasm_bindgen]
pub struct WalletKeys {
    /// Full Viewing Key (needed to compute nullifiers for received notes)
    fvk: orchard::keys::FullViewingKey,
    /// Real Orchard Incoming Viewing Key for EXTERNAL scope (prepared for efficient batched decryption)
    prepared_ivk_external: PreparedIncomingViewingKey,
    /// Real Orchard Incoming Viewing Key for INTERNAL scope (change addresses)
    prepared_ivk_internal: PreparedIncomingViewingKey,
    /// Address identifier for display
    address_id: [u8; 32],
}

#[wasm_bindgen]
impl WalletKeys {
    /// Derive wallet keys from a 24-word BIP39 seed phrase
    #[wasm_bindgen(constructor)]
    pub fn from_seed_phrase(seed_phrase: &str) -> Result<WalletKeys, JsError> {
        let mnemonic = bip39::Mnemonic::parse(seed_phrase)
            .map_err(|e| JsError::new(&format!("Invalid seed phrase: {}", e)))?;

        // Get 64-byte seed from mnemonic (no passphrase)
        let seed = mnemonic.to_seed("");

        // Use real Orchard key derivation - get FVK and BOTH External and Internal IVKs
        let (fvk, ivk_external, ivk_internal) = derive_orchard_keys(&seed)
            .map_err(|e| JsError::new(&format!("Key derivation failed: {}", e)))?;

        // Create address identifier from External IVK (for display only)
        let address_id = {
            let mut hasher = Blake2b512::new();
            hasher.update(b"ZafuWalletID");
            // Hash the default address to get an identifier
            let default_addr = ivk_external.address_at(0u64);
            hasher.update(default_addr.to_raw_address_bytes());
            let hash = hasher.finalize();
            let mut id = [0u8; 32];
            id.copy_from_slice(&hash[..32]);
            id
        };

        // Prepare IVKs for efficient batched decryption
        let prepared_ivk_external = ivk_external.prepare();
        let prepared_ivk_internal = ivk_internal.prepare();

        Ok(WalletKeys {
            fvk,
            prepared_ivk_external,
            prepared_ivk_internal,
            address_id,
        })
    }

    /// Get the wallet's receiving address (identifier)
    #[wasm_bindgen]
    pub fn get_address(&self) -> String {
        hex_encode(&self.address_id)
    }

    /// Scan a batch of compact actions in PARALLEL and return found notes
    /// This is the main entry point for high-performance scanning
    ///
    /// Binary format: [count: u32][action1][action2]...
    /// Each action: [nullifier: 32][cmx: 32][epk: 32][ciphertext: 52] = 148 bytes
    #[wasm_bindgen]
    pub fn scan_actions_parallel(&self, actions_bytes: &[u8]) -> Result<JsValue, JsError> {
        scan_compact_actions_with_keys(
            &self.fvk,
            &self.prepared_ivk_external,
            &self.prepared_ivk_internal,
            actions_bytes,
            Pool::Orchard,
        )
    }

    /// Scan a batch of IRONWOOD compact actions in PARALLEL (NU6.3+ pool).
    ///
    /// Same binary format and key material as `scan_actions_parallel` — the
    /// ironwood pool shares orchard's key tree and note encryption; only the
    /// bundle (and note plaintext version, V3) differ. The caller feeds the
    /// actions from the tx's ironwood bundle here so returned notes carry
    /// `pool: "ironwood"`.
    #[wasm_bindgen]
    pub fn scan_actions_ironwood_parallel(&self, actions_bytes: &[u8]) -> Result<JsValue, JsError> {
        scan_compact_actions_with_keys(
            &self.fvk,
            &self.prepared_ivk_external,
            &self.prepared_ivk_internal,
            actions_bytes,
            Pool::Ironwood,
        )
    }

    /// Scan actions from JSON (legacy compatibility, slower)
    #[wasm_bindgen]
    pub fn scan_actions(&self, actions_json: JsValue) -> Result<JsValue, JsError> {
        let actions: Vec<CompactActionJs> = serde_wasm_bindgen::from_value(actions_json)
            .map_err(|e| JsError::new(&format!("Invalid actions JSON: {}", e)))?;

        #[cfg(feature = "parallel")]
        let found: Vec<FoundNote> = actions
            .par_iter()
            .enumerate()
            .filter_map(|(idx, action)| {
                self.try_decrypt_action_json(action).map(|value| FoundNote {
                    index: idx as u32,
                    value,
                    nullifier: action.nullifier.clone(),
                    cmx: action.cmx.clone(),
                    is_change: false, // JSON path doesn't distinguish scope yet
                    rseed: None,
                    rho: None,
                    recipient: None,
                    pool: Pool::default(),
                    note_version: FoundNote::default_note_version(),
                })
            })
            .collect();

        #[cfg(not(feature = "parallel"))]
        let found: Vec<FoundNote> = actions
            .iter()
            .enumerate()
            .filter_map(|(idx, action)| {
                self.try_decrypt_action_json(action).map(|value| FoundNote {
                    index: idx as u32,
                    value,
                    nullifier: action.nullifier.clone(),
                    cmx: action.cmx.clone(),
                    is_change: false, // JSON path doesn't distinguish scope yet
                    rseed: None,
                    rho: None,
                    recipient: None,
                    pool: Pool::default(),
                    note_version: FoundNote::default_note_version(),
                })
            })
            .collect();

        serde_wasm_bindgen::to_value(&found)
            .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
    }

    /// Calculate balance from found notes minus spent nullifiers
    #[wasm_bindgen]
    pub fn calculate_balance(
        &self,
        notes_json: JsValue,
        spent_nullifiers_json: JsValue,
    ) -> Result<u64, JsError> {
        let notes: Vec<FoundNote> = serde_wasm_bindgen::from_value(notes_json)
            .map_err(|e| JsError::new(&format!("Invalid notes: {}", e)))?;
        let spent: Vec<String> = serde_wasm_bindgen::from_value(spent_nullifiers_json)
            .map_err(|e| JsError::new(&format!("Invalid nullifiers: {}", e)))?;

        let balance: u64 = notes
            .iter()
            .filter(|n| !spent.contains(&n.nullifier))
            .map(|n| n.value)
            .sum();

        Ok(balance)
    }

    /// Try to decrypt a JSON-format action
    /// Tries BOTH external and internal scope IVKs
    fn try_decrypt_action_json(&self, action: &CompactActionJs) -> Option<u64> {
        let epk_bytes: [u8; 32] = hex_decode(&action.ephemeral_key)?.try_into().ok()?;
        let cmx_bytes: [u8; 32] = hex_decode(&action.cmx)?.try_into().ok()?;
        let nullifier_bytes: [u8; 32] = hex_decode(&action.nullifier)?.try_into().ok()?;
        let ciphertext_vec = hex_decode(&action.ciphertext)?;
        if ciphertext_vec.len() < 52 {
            return None;
        }
        let mut ciphertext = [0u8; 52];
        ciphertext.copy_from_slice(&ciphertext_vec[..52]);

        // Parse the nullifier and cmx
        let nullifier = orchard::note::Nullifier::from_bytes(&nullifier_bytes);
        if nullifier.is_none().into() {
            return None;
        }
        let nullifier = nullifier.unwrap();

        let cmx = orchard::note::ExtractedNoteCommitment::from_bytes(&cmx_bytes);
        if cmx.is_none().into() {
            return None;
        }
        let cmx = cmx.unwrap();

        // Create compact action for domain construction
        let compact_action = orchard::note_encryption::CompactAction::from_parts(
            nullifier,
            cmx,
            EphemeralKeyBytes(epk_bytes),
            ciphertext,
        );

        // Create our shielded output wrapper
        let output = CompactShieldedOutput {
            epk: epk_bytes,
            cmx: cmx_bytes,
            ciphertext,
        };

        // Try compact note decryption with EXTERNAL scope IVK first
        if let Some(result) =
            try_compact_decrypt_any_version(&compact_action, &self.prepared_ivk_external, &output)
        {
            return Some(result.0.value().inner());
        }

        // If external failed, try INTERNAL scope IVK (for change/shielding outputs)
        if let Some(result) =
            try_compact_decrypt_any_version(&compact_action, &self.prepared_ivk_internal, &output)
        {
            return Some(result.0.value().inner());
        }

        None
    }
}

/// Compact shielded output for use with zcash_note_encryption
struct CompactShieldedOutput {
    epk: [u8; 32],
    cmx: [u8; 32],
    ciphertext: [u8; 52],
}

// Generic over the note-plaintext version so the same wrapper can be trial
// decrypted against `OrchardDomain` (V2) and `IronwoodDomain` (V3). See
// `try_compact_decrypt_any_version` for why both must be tried.
impl<V: DomainVersion> ShieldedOutput<NoteEncryptionDomain<V>, COMPACT_NOTE_SIZE>
    for CompactShieldedOutput
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.epk)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx
    }

    fn enc_ciphertext(&self) -> &[u8; COMPACT_NOTE_SIZE] {
        &self.ciphertext
    }
}

/// Trial-decrypt a compact output against BOTH note-plaintext versions.
///
/// Upstream orchard splits the note-encryption domain by note version and
/// *enforces* it: `OrchardDomain` accepts only V2 plaintexts (lead byte
/// 0x02) and `IronwoodDomain` only V3 (0x03); a mismatched lead byte makes
/// `try_*_note_decryption` return `None`. (The fork this crate used to build
/// against had a single permissive domain, which is why one domain used to
/// be enough.)
///
/// A compact action arriving off the wire carries no pool label of its own —
/// the pool is a property of which bundle it came from, which the binary
/// batch format does not preserve. So both domains must be tried. The extra
/// cost is one AEAD open on a 52-byte ciphertext, negligible next to the
/// Diffie-Hellman that already happened.
/// Which shielded pool a note lives in.
///
/// This lives HERE, in the lowest crate, on purpose. It used to live in
/// `zecli::wallet`, which depends on this crate — so the scanner below could
/// not reach it and dispatched on a `&str` instead, with a silent
/// `_ => try both domains` fallback. A typo in that string was a 2x slowdown
/// nothing would report. A type cannot be typo'd.
///
/// Ironwood reuses orchard addresses and note encryption, so notes decrypt
/// identically — but they sit in a separate commitment tree, need a v6
/// transaction to spend, and use a different note-encryption domain.
///
/// The serde representation is deliberately unchanged from the definition it
/// replaces (`rename_all = "lowercase"` → `"orchard"` / `"ironwood"`), so
/// persisted wallet notes and the JS-facing scan results keep the exact same
/// shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Pool {
    #[default]
    Orchard,
    Ironwood,
}

impl Pool {
    pub fn name(self) -> &'static str {
        match self {
            Pool::Orchard => "orchard",
            Pool::Ironwood => "ironwood",
        }
    }
}

impl From<Pool> for DomainChoice {
    /// The domain follows from the pool. Deriving it here is the point: the
    /// two can no longer disagree, and there is no third "unrecognized" state
    /// to fall back from.
    fn from(pool: Pool) -> Self {
        match pool {
            Pool::Orchard => DomainChoice::Orchard,
            Pool::Ironwood => DomainChoice::Ironwood,
        }
    }
}

/// Which note-version domain(s) to trial-decrypt an action against.
///
/// Trial decryption is the dominant cost of a scan, so this is a hot-path
/// decision, not a stylistic one. Upstream orchard enforces the plaintext lead
/// byte per domain (`OrchardDomain` = V2/0x02, `IronwoodDomain` = V3/0x03), so
/// an action must be tried against the right one — but trying BOTH when the
/// pool is already known doubles the work for every action that does not
/// belong to us, which is nearly all of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DomainChoice {
    /// The pool is known because the action came out of a specific bundle
    /// (zidecar returns orchard and ironwood actions in separate lists, and
    /// the scan entry points are already per-pool). Use only that domain.
    Orchard,
    Ironwood,
    /// The pool is genuinely unknown for this action — try both. Correct, but
    /// twice the work; do not use it where the caller knows the bundle.
    Either,
}

fn try_compact_decrypt_in(
    compact_action: &orchard::note_encryption::CompactAction,
    ivk: &PreparedIncomingViewingKey,
    output: &CompactShieldedOutput,
    choice: DomainChoice,
) -> Option<(orchard::Note, orchard::Address)> {
    let orchard = || {
        try_compact_note_decryption(
            &OrchardDomain::for_compact_action(compact_action),
            ivk,
            output,
        )
    };
    let ironwood = || {
        try_compact_note_decryption(
            &IronwoodDomain::for_compact_action(compact_action),
            ivk,
            output,
        )
    };
    match choice {
        DomainChoice::Orchard => orchard(),
        DomainChoice::Ironwood => ironwood(),
        DomainChoice::Either => orchard().or_else(ironwood),
    }
}

/// Try both domains. Use only where the pool is genuinely unknown; prefer
/// [`try_compact_decrypt_in`] with a known pool on any scan hot path.
fn try_compact_decrypt_any_version(
    compact_action: &orchard::note_encryption::CompactAction,
    ivk: &PreparedIncomingViewingKey,
    output: &CompactShieldedOutput,
) -> Option<(orchard::Note, orchard::Address)> {
    try_compact_decrypt_in(compact_action, ivk, output, DomainChoice::Either)
}

/// Binary compact action for efficient transfer (148 bytes each)
#[derive(Clone)]
struct CompactActionBinary {
    nullifier: [u8; 32],
    cmx: [u8; 32],
    epk: [u8; 32],
    ciphertext: [u8; 52],
}

/// Parse compact actions from binary format
fn parse_compact_actions(data: &[u8]) -> Result<Vec<CompactActionBinary>, JsError> {
    if data.len() < 4 {
        return Err(JsError::new("Data too short"));
    }

    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let action_size = 32 + 32 + 32 + 52; // 148 bytes

    if data.len() < 4 + count * action_size {
        return Err(JsError::new(&format!(
            "Data too short: expected {} bytes for {} actions, got {}",
            4 + count * action_size,
            count,
            data.len()
        )));
    }

    let mut actions = Vec::with_capacity(count);
    let mut offset = 4;

    for _ in 0..count {
        let mut nullifier = [0u8; 32];
        let mut cmx = [0u8; 32];
        let mut epk = [0u8; 32];
        let mut ciphertext = [0u8; 52];

        nullifier.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        cmx.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        epk.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        ciphertext.copy_from_slice(&data[offset..offset + 52]);
        offset += 52;

        actions.push(CompactActionBinary {
            nullifier,
            cmx,
            epk,
            ciphertext,
        });
    }

    Ok(actions)
}

/// The decrypted fields of a compact action, shared by every scan entry
/// point (WalletKeys / WatchOnlyWallet, orchard / ironwood).
struct DecryptedParts {
    value: u64,
    nullifier: [u8; 32],
    rseed: [u8; 32],
    rho: [u8; 32],
    recipient: [u8; 43],
    is_change: bool,
    note_version: u8,
}

/// Trial-decrypt one compact action with both scope IVKs.
///
/// Each scope is tried against BOTH note-version domains — `OrchardDomain`
/// (V2) and `IronwoodDomain` (V3) — because upstream orchard enforces the
/// plaintext lead byte per domain and a wire compact action does not say
/// which pool it came from. See `try_compact_decrypt_any_version`.
///
/// `note_version` is read back off whichever note actually decrypted, and
/// the nullifier is derived from that same note (`Note::nullifier` binds
/// rho/psi/cmx, all of which already reflect the note's version), so both
/// stay consistent with the domain that succeeded. The pool label is
/// applied by the caller.
fn try_decrypt_compact_action(
    fvk: &orchard::keys::FullViewingKey,
    ivk_external: &PreparedIncomingViewingKey,
    ivk_internal: &PreparedIncomingViewingKey,
    action: &CompactActionBinary,
    choice: DomainChoice,
) -> Option<DecryptedParts> {
    let nullifier = orchard::note::Nullifier::from_bytes(&action.nullifier);
    if nullifier.is_none().into() {
        return None;
    }
    let nullifier = nullifier.unwrap();

    let cmx = orchard::note::ExtractedNoteCommitment::from_bytes(&action.cmx);
    if cmx.is_none().into() {
        return None;
    }
    let cmx = cmx.unwrap();

    let compact_action = orchard::note_encryption::CompactAction::from_parts(
        nullifier,
        cmx,
        EphemeralKeyBytes(action.epk),
        action.ciphertext,
    );

    let output = CompactShieldedOutput {
        epk: action.epk,
        cmx: action.cmx,
        ciphertext: action.ciphertext,
    };

    let build = |note: orchard::Note, addr: orchard::Address, is_change: bool| DecryptedParts {
        value: note.value().inner(),
        nullifier: note.nullifier(fvk).to_bytes(),
        rseed: *note.rseed().as_bytes(),
        rho: note.rho().to_bytes(),
        recipient: addr.to_raw_address_bytes(),
        is_change,
        note_version: match note.version() {
            orchard::note::NoteVersion::V2 => 2,
            orchard::note::NoteVersion::V3 => 3,
        },
    };

    // External scope first (incoming payments), then internal (change).
    // Each scope is tried against both note-version domains before moving on,
    // so a V3 note never falls through to the internal scope and gets
    // misclassified as change.
    if let Some((note, addr)) =
        try_compact_decrypt_in(&compact_action, ivk_external, &output, choice)
    {
        return Some(build(note, addr, false));
    }
    if let Some((note, addr)) =
        try_compact_decrypt_in(&compact_action, ivk_internal, &output, choice)
    {
        return Some(build(note, addr, true));
    }
    None
}

/// Scan a binary batch of compact actions and return decrypted notes tagged
/// with `pool`. Shared implementation behind the orchard and ironwood scan
/// exports on both wallet types.
fn scan_compact_actions_with_keys(
    fvk: &orchard::keys::FullViewingKey,
    ivk_external: &PreparedIncomingViewingKey,
    ivk_internal: &PreparedIncomingViewingKey,
    actions_bytes: &[u8],
    pool: Pool,
) -> Result<JsValue, JsError> {
    let actions = parse_compact_actions(actions_bytes)?;

    // The caller already knows the pool: zidecar returns orchard and ironwood
    // actions in SEPARATE lists and the scan exports are per-pool. Decrypting
    // against only that pool's domain halves the trial-decryption work for
    // every action that is not ours - which, over a multi-hundred-thousand
    // block sync, is essentially all of them.
    let choice = DomainChoice::from(pool);

    let to_found = |(idx, action): (usize, &CompactActionBinary)| {
        try_decrypt_compact_action(fvk, ivk_external, ivk_internal, action, choice).map(|d| {
            FoundNote {
                index: idx as u32,
                value: d.value,
                nullifier: hex_encode(&d.nullifier),
                cmx: hex_encode(&action.cmx),
                is_change: d.is_change,
                rseed: Some(hex_encode(&d.rseed)),
                rho: Some(hex_encode(&d.rho)),
                recipient: Some(hex_encode(&d.recipient)),
                pool,
                note_version: d.note_version,
            }
        })
    };

    #[cfg(feature = "parallel")]
    let found: Vec<FoundNote> = actions
        .par_iter()
        .enumerate()
        .filter_map(to_found)
        .collect();
    #[cfg(not(feature = "parallel"))]
    let found: Vec<FoundNote> = actions.iter().enumerate().filter_map(to_found).collect();

    serde_wasm_bindgen::to_value(&found)
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

/// Compact action from JavaScript (JSON format)
#[derive(Debug, Deserialize)]
struct CompactActionJs {
    nullifier: String,
    cmx: String,
    ephemeral_key: String,
    ciphertext: String,
}

/// Found note to return to JavaScript
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FoundNote {
    pub index: u32,
    pub value: u64,
    pub nullifier: String,
    pub cmx: String,
    /// true if decrypted with internal scope IVK (change/shielding output)
    #[serde(default)]
    pub is_change: bool,
    /// rseed bytes for note reconstruction (hex, 32 bytes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rseed: Option<String>,
    /// rho bytes for note reconstruction (hex, 32 bytes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rho: Option<String>,
    /// recipient address bytes for note reconstruction (hex, 43 bytes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// Which shielded pool the action was scanned from: "orchard" | "ironwood".
    /// Set by the scan entry point (the pool is a property of which bundle in
    /// the tx the action lives in, not of the ciphertext itself).
    #[serde(default)]
    pub pool: Pool,
    /// Note plaintext version from the decrypted lead byte
    /// (2 = orchard V2, 3 = ironwood V3 quantum-recoverable). Needed to
    /// reconstruct the exact note (and its commitment) at spend time.
    #[serde(default = "FoundNote::default_note_version")]
    pub note_version: u8,
}

impl FoundNote {
    fn default_note_version() -> u8 {
        2
    }
}

/// Batch scan result with stats
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub found_notes: Vec<FoundNote>,
    pub actions_scanned: u32,
    pub scan_time_ms: f64,
}

/// Derive real Orchard keys (FVK, External IVK, Internal IVK) from seed using proper ZIP-32 derivation
fn derive_orchard_keys(
    seed: &[u8],
) -> Result<
    (
        orchard::keys::FullViewingKey,
        IncomingViewingKey,
        IncomingViewingKey,
    ),
    String,
> {
    // Seed must be 64 bytes (from BIP39)
    if seed.len() != 64 {
        return Err(format!("Invalid seed length: {} (expected 64)", seed.len()));
    }

    // Derive spending key using ZIP-32 for mainnet (coin_type=133), account 0
    let sk = SpendingKey::from_zip32_seed(seed, 133, zip32::AccountId::ZERO)
        .map_err(|_| "Failed to derive spending key from seed")?;

    // Get Full Viewing Key from Spending Key
    let fvk = orchard::keys::FullViewingKey::from(&sk);

    // Get Incoming Viewing Keys for BOTH scopes
    // External = receiving addresses (what you share with others)
    // Internal = change/shielding addresses (used by wallet internally)
    let ivk_external = fvk.to_ivk(Scope::External);
    let ivk_internal = fvk.to_ivk(Scope::Internal);

    Ok((fvk, ivk_external, ivk_internal))
}

/// Generate a new 24-word seed phrase
#[wasm_bindgen]
pub fn generate_seed_phrase() -> Result<String, JsError> {
    let mnemonic = bip39::Mnemonic::generate(24)
        .map_err(|e| JsError::new(&format!("Failed to generate mnemonic: {}", e)))?;
    Ok(mnemonic.to_string())
}

/// Validate a seed phrase
#[wasm_bindgen]
pub fn validate_seed_phrase(seed_phrase: &str) -> bool {
    bip39::Mnemonic::parse(seed_phrase).is_ok()
}

/// Get library version
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get number of threads available (0 if single-threaded)
#[wasm_bindgen]
pub fn num_threads() -> usize {
    #[cfg(feature = "parallel")]
    {
        rayon::current_num_threads()
    }
    #[cfg(not(feature = "parallel"))]
    {
        1
    }
}

// Hex helpers
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// The ZIP-302 "no memo" memo: first byte `0xF6`, remaining 511 bytes zero.
///
/// This is what `MemoBytes::empty()` encodes, and what every other Zcash wallet
/// (zcashd, zecwallet, Zashi, ywallet) puts in an output the user left without
/// a memo. It is NOT the same as 512 zero bytes: `0x00…` decodes as a
/// zero-length *text* memo, which is a distinguishable minority encoding. A
/// recipient (or anyone with the OVK, or a future memo-bundle observer) can
/// therefore tell "made by zafu" from "made by anything else" on every single
/// no-memo output. Emitting the canonical marker removes that fingerprint.
pub const ZIP302_NO_MEMO: [u8; 512] = {
    let mut m = [0u8; 512];
    m[0] = 0xF6;
    m
};

/// Decode an optional hex-encoded memo into a 512-byte array.
///
/// Zcash memos are exactly 512 bytes (ZIP-302). If `hex` is None or empty,
/// returns [`ZIP302_NO_MEMO`] — the canonical `0xF6` no-memo encoding, which is
/// what the rest of the ecosystem emits — NOT 512 zero bytes. If provided, the
/// hex string is decoded and right-padded with zeros to fill 512 bytes.
///
/// This is the only place memo bytes enter the transaction builder.
/// The caller is responsible for the memo content — this function is
/// encoding-agnostic (works for UTF-8 text, zafu structured memos, or
/// any other 512-byte payload).
fn decode_memo_hex(hex: Option<&str>) -> Result<[u8; 512], JsError> {
    let Some(h) = hex.filter(|h| !h.is_empty()) else {
        return Ok(ZIP302_NO_MEMO);
    };
    let mut memo = [0u8; 512];
    let bytes = hex_decode(h).ok_or_else(|| JsError::new("memo_hex: invalid hex encoding"))?;
    if bytes.len() > 512 {
        return Err(JsError::new(&format!(
            "memo_hex: {} bytes exceeds 512-byte limit",
            bytes.len()
        )));
    }
    memo[..bytes.len()].copy_from_slice(&bytes);
    Ok(memo)
}

// ============================================================================
// Cold Signing Support
// ============================================================================

/// QR code type constants for Zcash cold signing
pub const QR_TYPE_ZCASH_FVK_EXPORT: u8 = 0x01;
pub const QR_TYPE_ZCASH_SIGN_REQUEST: u8 = 0x02;
pub const QR_TYPE_ZCASH_SIGNATURES: u8 = 0x03;

/// Watch-only wallet - holds only viewing keys, no spending capability
/// This is used by online wallets (Prax/Zafu) to track balances
/// and build unsigned transactions for cold signing.
#[wasm_bindgen]
pub struct WatchOnlyWallet {
    /// Full Viewing Key (for balance tracking and nullifier computation)
    fvk: orchard::keys::FullViewingKey,
    /// Prepared IVK for efficient scanning (External scope)
    prepared_ivk_external: PreparedIncomingViewingKey,
    /// Prepared IVK for efficient scanning (Internal scope - change)
    prepared_ivk_internal: PreparedIncomingViewingKey,
    /// Account index (for derivation path context)
    account_index: u32,
    /// Network: true = mainnet, false = testnet
    mainnet: bool,
}

#[wasm_bindgen]
impl WatchOnlyWallet {
    /// Import a watch-only wallet from FVK bytes (96 bytes)
    #[wasm_bindgen(constructor)]
    pub fn from_fvk_bytes(
        fvk_bytes: &[u8],
        account_index: u32,
        mainnet: bool,
    ) -> Result<WatchOnlyWallet, JsError> {
        if fvk_bytes.len() != 96 {
            return Err(JsError::new(&format!(
                "Invalid FVK length: {} (expected 96)",
                fvk_bytes.len()
            )));
        }

        let fvk_array: [u8; 96] = fvk_bytes.try_into().unwrap();
        let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk_array);

        if fvk.is_none() {
            return Err(JsError::new("Invalid FVK bytes"));
        }
        let fvk = fvk.unwrap();

        let ivk_external = fvk.to_ivk(Scope::External);
        let ivk_internal = fvk.to_ivk(Scope::Internal);

        Ok(WatchOnlyWallet {
            fvk,
            prepared_ivk_external: ivk_external.prepare(),
            prepared_ivk_internal: ivk_internal.prepare(),
            account_index,
            mainnet,
        })
    }

    /// Import from a UFVK string (uview1.../uviewtest1...)
    #[wasm_bindgen]
    pub fn from_ufvk(ufvk_str: &str) -> Result<WatchOnlyWallet, JsError> {
        use zcash_keys::keys::UnifiedFullViewingKey;
        use zcash_protocol::consensus::{MainNetwork, TestNetwork};

        let mainnet = ufvk_str.starts_with("uview1") && !ufvk_str.starts_with("uviewtest");

        let ufvk = if mainnet {
            UnifiedFullViewingKey::decode(&MainNetwork, ufvk_str)
        } else {
            UnifiedFullViewingKey::decode(&TestNetwork, ufvk_str)
        }
        .map_err(|e| JsError::new(&format!("invalid UFVK: {}", e)))?;

        let orchard_fvk = ufvk
            .orchard()
            .ok_or_else(|| JsError::new("UFVK has no orchard component"))?;

        // extract raw 96-byte FVK
        let fvk_bytes = orchard_fvk.to_bytes();
        let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk_bytes);
        if fvk.is_none() {
            return Err(JsError::new("invalid orchard FVK in UFVK"));
        }
        let fvk = fvk.unwrap();

        let ivk_external = fvk.to_ivk(Scope::External);
        let ivk_internal = fvk.to_ivk(Scope::Internal);

        Ok(WatchOnlyWallet {
            fvk,
            prepared_ivk_external: ivk_external.prepare(),
            prepared_ivk_internal: ivk_internal.prepare(),
            account_index: 0,
            mainnet,
        })
    }

    /// Import from hex-encoded QR data
    #[wasm_bindgen]
    pub fn from_qr_hex(qr_hex: &str) -> Result<WatchOnlyWallet, JsError> {
        let data = hex_decode(qr_hex).ok_or_else(|| JsError::new("Invalid hex string"))?;

        // Validate prelude: [0x53][0x04][0x01]
        if data.len() < 9 {
            return Err(JsError::new("QR data too short"));
        }
        if data[0] != 0x53 || data[1] != 0x04 || data[2] != QR_TYPE_ZCASH_FVK_EXPORT {
            return Err(JsError::new("Invalid QR prelude for Zcash FVK export"));
        }

        let mut offset = 3;

        // flags
        let flags = data[offset];
        offset += 1;
        let mainnet = flags & 0x01 != 0;
        let has_orchard = flags & 0x02 != 0;

        if !has_orchard {
            return Err(JsError::new("QR data missing Orchard FVK"));
        }

        // account index
        let account_index = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // skip label
        let label_len = data[offset] as usize;
        offset += 1 + label_len;

        // orchard fvk
        if offset + 96 > data.len() {
            return Err(JsError::new("Orchard FVK truncated"));
        }
        let fvk_bytes = &data[offset..offset + 96];

        Self::from_fvk_bytes(fvk_bytes, account_index, mainnet)
    }

    /// Get account index
    #[wasm_bindgen]
    pub fn get_account_index(&self) -> u32 {
        self.account_index
    }

    /// Is mainnet
    #[wasm_bindgen]
    pub fn is_mainnet(&self) -> bool {
        self.mainnet
    }

    /// Get default receiving address (diversifier index 0)
    #[wasm_bindgen]
    pub fn get_address(&self) -> String {
        let addr = self.fvk.to_ivk(Scope::External).address_at(0u64);
        encode_orchard_address(&addr, self.mainnet)
    }

    /// Get address at specific diversifier index
    #[wasm_bindgen]
    pub fn get_address_at(&self, diversifier_index: u32) -> String {
        let addr = self
            .fvk
            .to_ivk(Scope::External)
            .address_at(diversifier_index as u64);
        encode_orchard_address(&addr, self.mainnet)
    }

    /// Export FVK as hex bytes (for backup)
    #[wasm_bindgen]
    pub fn export_fvk_hex(&self) -> String {
        hex_encode(&self.fvk.to_bytes())
    }

    /// Scan compact actions (same interface as WalletKeys)
    #[wasm_bindgen]
    pub fn scan_actions_parallel(&self, actions_bytes: &[u8]) -> Result<JsValue, JsError> {
        scan_compact_actions_with_keys(
            &self.fvk,
            &self.prepared_ivk_external,
            &self.prepared_ivk_internal,
            actions_bytes,
            Pool::Orchard,
        )
    }

    /// Scan a batch of IRONWOOD compact actions (NU6.3+ pool).
    ///
    /// Same binary format and key material as `scan_actions_parallel` — the
    /// ironwood pool shares orchard's key tree and note encryption. Feed the
    /// actions from a tx's ironwood bundle here so returned notes carry
    /// `pool: "ironwood"`.
    #[wasm_bindgen]
    pub fn scan_actions_ironwood_parallel(&self, actions_bytes: &[u8]) -> Result<JsValue, JsError> {
        scan_compact_actions_with_keys(
            &self.fvk,
            &self.prepared_ivk_external,
            &self.prepared_ivk_internal,
            actions_bytes,
            Pool::Ironwood,
        )
    }
}

/// Extend WalletKeys with FVK export for cold signing setup
#[wasm_bindgen]
impl WalletKeys {
    /// Export Full Viewing Key as hex-encoded QR data
    /// This is used to create a watch-only wallet on an online device
    #[wasm_bindgen]
    pub fn export_fvk_qr_hex(
        &self,
        account_index: u32,
        label: Option<String>,
        mainnet: bool,
    ) -> String {
        let mut output = Vec::new();

        // Prelude: [0x53][0x04][0x01] - Substrate compat, Zcash, FVK export
        output.push(0x53);
        output.push(0x04);
        output.push(QR_TYPE_ZCASH_FVK_EXPORT);

        // Flags: mainnet, has_orchard, no_transparent
        let mut flags = 0u8;
        if mainnet {
            flags |= 0x01;
        }
        flags |= 0x02; // has orchard
        output.push(flags);

        // Account index
        output.extend_from_slice(&account_index.to_le_bytes());

        // Label
        match &label {
            Some(l) => {
                let bytes = l.as_bytes();
                output.push(bytes.len().min(255) as u8);
                output.extend_from_slice(&bytes[..bytes.len().min(255)]);
            }
            None => output.push(0),
        }

        // Orchard FVK (96 bytes)
        output.extend_from_slice(&self.fvk.to_bytes());

        hex_encode(&output)
    }

    /// Get the Orchard FVK bytes (96 bytes) as hex
    #[wasm_bindgen]
    pub fn get_fvk_hex(&self) -> String {
        hex_encode(&self.fvk.to_bytes())
    }

    /// Get the default receiving address as a Zcash unified address string
    #[wasm_bindgen]
    pub fn get_receiving_address(&self, mainnet: bool) -> String {
        let addr = self.fvk.to_ivk(Scope::External).address_at(0u64);
        encode_orchard_address(&addr, mainnet)
    }

    /// Get receiving address at specific diversifier index
    #[wasm_bindgen]
    pub fn get_receiving_address_at(&self, diversifier_index: u32, mainnet: bool) -> String {
        let addr = self
            .fvk
            .to_ivk(Scope::External)
            .address_at(diversifier_index as u64);
        encode_orchard_address(&addr, mainnet)
    }
}

/// Encode an Orchard address as a human-readable string
/// Note: This is the raw Orchard address, not a full Unified Address
fn encode_orchard_address(addr: &orchard::Address, mainnet: bool) -> String {
    // For simplicity, return hex-encoded raw address bytes
    // A proper implementation would use Unified Address encoding (ZIP-316)
    let raw = addr.to_raw_address_bytes();
    let prefix = if mainnet {
        "u1orchard:"
    } else {
        "utest1orchard:"
    };
    format!("{}{}", prefix, hex_encode(&raw))
}

// ============================================================================
// PCZT (Partially Constructed Zcash Transaction) for Cold Signing
// ============================================================================

/// A spendable note for transaction building
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendableNoteInfo {
    /// The note's nullifier (hex)
    pub nullifier: String,
    /// The note's commitment (cmx, hex)
    pub cmx: String,
    /// The note's value in zatoshis
    pub value: u64,
    /// Position in the commitment tree
    pub position: u64,
    /// The merkle path (hex-encoded) — optional, paths come via separate param
    #[serde(default)]
    pub merkle_path: String,
}

/// Transaction request to build
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    /// Recipient address (Orchard)
    pub recipient: String,
    /// Amount in zatoshis
    pub amount: u64,
    /// Optional memo (512 bytes max, hex-encoded)
    pub memo: Option<String>,
}

/// PCZT sign request - what gets sent to cold wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcztSignRequest {
    /// Account index for key derivation
    pub account_index: u32,
    /// The transaction sighash (32 bytes, hex)
    pub sighash: String,
    /// Orchard actions that need signing
    pub orchard_actions: Vec<OrchardActionInfo>,
    /// Human-readable transaction summary for display
    pub summary: String,
}

/// Info about an Orchard action that needs signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchardActionInfo {
    /// The randomizer (alpha) for this action (32 bytes, hex)
    pub alpha: String,
}

/// Create a PCZT sign request from transaction parameters
/// This is called by the online wallet to create the data that will be
/// transferred to the cold wallet via QR code.
#[wasm_bindgen]
pub fn create_sign_request(
    account_index: u32,
    sighash_hex: &str,
    alphas_json: JsValue,
    summary: &str,
) -> Result<String, JsError> {
    let alphas: Vec<String> = serde_wasm_bindgen::from_value(alphas_json)
        .map_err(|e| JsError::new(&format!("Invalid alphas: {}", e)))?;

    let request = PcztSignRequest {
        account_index,
        sighash: sighash_hex.to_string(),
        orchard_actions: alphas
            .into_iter()
            .map(|a| OrchardActionInfo { alpha: a })
            .collect(),
        summary: summary.to_string(),
    };

    // Encode as QR payload
    let mut output = Vec::new();

    // Prelude: [0x53][0x04][0x02] - Substrate compat, Zcash, Sign request
    output.push(0x53);
    output.push(0x04);
    output.push(QR_TYPE_ZCASH_SIGN_REQUEST);

    // Account index
    output.extend_from_slice(&account_index.to_le_bytes());

    // Sighash (32 bytes)
    let sighash_bytes =
        hex_decode(sighash_hex).ok_or_else(|| JsError::new("Invalid sighash hex"))?;
    if sighash_bytes.len() != 32 {
        return Err(JsError::new("Sighash must be 32 bytes"));
    }
    output.extend_from_slice(&sighash_bytes);

    // Action count
    output.extend_from_slice(&(request.orchard_actions.len() as u16).to_le_bytes());

    // Each action's alpha
    for action in &request.orchard_actions {
        let alpha_bytes =
            hex_decode(&action.alpha).ok_or_else(|| JsError::new("Invalid alpha hex"))?;
        if alpha_bytes.len() != 32 {
            return Err(JsError::new("Alpha must be 32 bytes"));
        }
        output.extend_from_slice(&alpha_bytes);
    }

    // Summary (length-prefixed string)
    let summary_bytes = summary.as_bytes();
    output.extend_from_slice(&(summary_bytes.len() as u16).to_le_bytes());
    output.extend_from_slice(summary_bytes);

    Ok(hex_encode(&output))
}

/// Parse signatures from cold wallet QR response
/// Returns JSON with sighash and orchard_sigs array
#[wasm_bindgen]
pub fn parse_signature_response(qr_hex: &str) -> Result<JsValue, JsError> {
    let data = hex_decode(qr_hex).ok_or_else(|| JsError::new("Invalid hex string"))?;

    // Validate prelude
    if data.len() < 36 {
        return Err(JsError::new("Response too short"));
    }
    if data[0] != 0x53 || data[1] != 0x04 || data[2] != QR_TYPE_ZCASH_SIGNATURES {
        return Err(JsError::new("Invalid QR prelude for Zcash signatures"));
    }

    let mut offset = 3;

    // Sighash (32 bytes)
    let sighash = hex_encode(&data[offset..offset + 32]);
    offset += 32;

    // Transparent sig count (skip for now - we focus on Orchard)
    let t_count = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;

    // Skip transparent sigs
    for _ in 0..t_count {
        let sig_len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2 + sig_len;
    }

    // Orchard sig count
    if offset + 2 > data.len() {
        return Err(JsError::new("Orchard count truncated"));
    }
    let o_count = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;

    // Orchard signatures
    let mut orchard_sigs = Vec::with_capacity(o_count);
    for _ in 0..o_count {
        if offset + 64 > data.len() {
            return Err(JsError::new("Orchard signature truncated"));
        }
        orchard_sigs.push(hex_encode(&data[offset..offset + 64]));
        offset += 64;
    }

    #[derive(Serialize)]
    struct SignatureResponse {
        sighash: String,
        orchard_sigs: Vec<String>,
    }

    let response = SignatureResponse {
        sighash,
        orchard_sigs,
    };

    serde_wasm_bindgen::to_value(&response)
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ============================================================================
// Full Note Decryption with Memos
// ============================================================================

/// Found note with memo from full decryption
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FoundNoteWithMemo {
    pub index: u32,
    pub value: u64,
    pub nullifier: String,
    pub cmx: String,
    /// The decrypted memo (512 bytes, may be text or binary)
    pub memo: String,
    /// Whether the memo appears to be text (UTF-8)
    pub memo_is_text: bool,
    /// Whether this is an outgoing note (decrypted via OVK)
    pub is_outgoing: bool,
    /// Raw memo bytes (512 bytes, hex-encoded) for binary/structured memos
    pub memo_bytes: String,
}

/// Full action data for decryption (includes full 580-byte ciphertext)
#[derive(Debug, Clone)]
struct FullOrchardAction {
    nullifier: [u8; 32],
    cmx: [u8; 32],
    epk: [u8; 32],
    enc_ciphertext: [u8; 580], // full ciphertext including memo
    #[allow(dead_code)]
    out_ciphertext: [u8; 80], // for outgoing note decryption
}

/// Full shielded output for use with zcash_note_encryption
struct FullShieldedOutput {
    epk: [u8; 32],
    cmx: [u8; 32],
    enc_ciphertext: [u8; 580],
}

/// NOTE_PLAINTEXT_SIZE for Orchard (580 bytes enc_ciphertext)
const ORCHARD_NOTE_PLAINTEXT_SIZE: usize = 580;

// Generic over the note-plaintext version — see `CompactShieldedOutput`.
impl<V: DomainVersion>
    zcash_note_encryption::ShieldedOutput<NoteEncryptionDomain<V>, ORCHARD_NOTE_PLAINTEXT_SIZE>
    for FullShieldedOutput
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.epk)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx
    }

    fn enc_ciphertext(&self) -> &[u8; ORCHARD_NOTE_PLAINTEXT_SIZE] {
        &self.enc_ciphertext
    }
}

/// Full-ciphertext counterpart of [`try_compact_decrypt_any_version`]: trial
/// decrypt (note, address, memo) against both the V2 and V3 domains.
fn try_full_decrypt_any_version(
    compact_action: &orchard::note_encryption::CompactAction,
    ivk: &PreparedIncomingViewingKey,
    output: &FullShieldedOutput,
) -> Option<(orchard::Note, orchard::Address, [u8; 512])> {
    zcash_note_encryption::try_note_decryption(
        &OrchardDomain::for_compact_action(compact_action),
        ivk,
        output,
    )
    .or_else(|| {
        zcash_note_encryption::try_note_decryption(
            &IronwoodDomain::for_compact_action(compact_action),
            ivk,
            output,
        )
    })
}

/// Parse full Orchard actions from raw transaction bytes
/// Uses zcash_primitives for proper v5 transaction parsing
fn parse_orchard_actions_from_tx(tx_bytes: &[u8]) -> Result<Vec<FullOrchardAction>, String> {
    use std::io::Cursor;
    // zcash_primitives 0.26 moved consensus types into zcash_protocol;
    // BranchId is re-exported there for callers like us.
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::BranchId;

    // Parse transaction using zcash_primitives
    let mut cursor = Cursor::new(tx_bytes);
    let tx = Transaction::read(&mut cursor, BranchId::Nu5)
        .map_err(|e| format!("Failed to parse transaction: {:?}", e))?;

    // Get Orchard bundle if present
    let orchard_bundle = match tx.orchard_bundle() {
        Some(bundle) => bundle,
        None => return Ok(vec![]), // No Orchard actions in this tx
    };

    // Extract actions with full ciphertext
    let mut actions = Vec::new();

    for action in orchard_bundle.actions() {
        // Get action components
        let nullifier_bytes = action.nullifier().to_bytes();
        let cmx_bytes = action.cmx().to_bytes();
        let epk_bytes = action.encrypted_note().epk_bytes;

        // Get full encrypted ciphertext (580 bytes)
        let enc_ciphertext = action.encrypted_note().enc_ciphertext;

        // Get out_ciphertext for potential outgoing decryption
        let out_ciphertext = action.encrypted_note().out_ciphertext;

        actions.push(FullOrchardAction {
            nullifier: nullifier_bytes,
            cmx: cmx_bytes,
            epk: epk_bytes,
            enc_ciphertext,
            out_ciphertext,
        });
    }

    Ok(actions)
}

#[wasm_bindgen]
impl WalletKeys {
    /// Decrypt full notes with memos from a raw transaction
    ///
    /// Takes the raw transaction bytes (from zidecar's get_transaction)
    /// and returns any notes that belong to this wallet, including memos.
    #[wasm_bindgen]
    pub fn decrypt_transaction_memos(&self, tx_bytes: &[u8]) -> Result<JsValue, JsError> {
        let actions = parse_orchard_actions_from_tx(tx_bytes)
            .map_err(|e| JsError::new(&format!("Failed to parse transaction: {}", e)))?;

        let mut found: Vec<FoundNoteWithMemo> = Vec::new();

        for (idx, action) in actions.iter().enumerate() {
            // Parse nullifier and cmx using CtOption
            let nullifier_opt = orchard::note::Nullifier::from_bytes(&action.nullifier);
            if !bool::from(nullifier_opt.is_some()) {
                continue;
            }
            let nullifier = nullifier_opt.unwrap();

            let cmx_opt = orchard::note::ExtractedNoteCommitment::from_bytes(&action.cmx);
            if !bool::from(cmx_opt.is_some()) {
                continue;
            }
            let cmx = cmx_opt.unwrap();

            // Create domain for full action
            let compact_action = orchard::note_encryption::CompactAction::from_parts(
                nullifier,
                cmx,
                EphemeralKeyBytes(action.epk),
                action.enc_ciphertext[..52].try_into().unwrap(),
            );

            // Create full shielded output
            let output = FullShieldedOutput {
                epk: action.epk,
                cmx: action.cmx,
                enc_ciphertext: action.enc_ciphertext,
            };

            // Try external scope first (incoming)
            if let Some((note, _addr, memo)) =
                try_full_decrypt_any_version(&compact_action, &self.prepared_ivk_external, &output)
            {
                let note_nf = note.nullifier(&self.fvk);
                let (memo_str, is_text) = parse_memo_bytes(&memo);

                found.push(FoundNoteWithMemo {
                    index: idx as u32,
                    value: note.value().inner(),
                    nullifier: hex_encode(&note_nf.to_bytes()),
                    cmx: hex_encode(&action.cmx),
                    memo: memo_str,
                    memo_is_text: is_text,
                    is_outgoing: false,
                    memo_bytes: hex_encode(&memo),
                });
                continue;
            }

            // Try internal scope (change / outgoing)
            if let Some((note, _addr, memo)) =
                try_full_decrypt_any_version(&compact_action, &self.prepared_ivk_internal, &output)
            {
                let note_nf = note.nullifier(&self.fvk);
                let (memo_str, is_text) = parse_memo_bytes(&memo);

                found.push(FoundNoteWithMemo {
                    index: idx as u32,
                    value: note.value().inner(),
                    nullifier: hex_encode(&note_nf.to_bytes()),
                    cmx: hex_encode(&action.cmx),
                    memo: memo_str,
                    memo_is_text: is_text,
                    is_outgoing: true,
                    memo_bytes: hex_encode(&memo),
                });
            }
        }

        serde_wasm_bindgen::to_value(&found)
            .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
    }
}

#[wasm_bindgen]
impl WatchOnlyWallet {
    /// Decrypt full notes with memos from a raw transaction (watch-only version)
    #[wasm_bindgen]
    pub fn decrypt_transaction_memos(&self, tx_bytes: &[u8]) -> Result<JsValue, JsError> {
        let actions = parse_orchard_actions_from_tx(tx_bytes)
            .map_err(|e| JsError::new(&format!("Failed to parse transaction: {}", e)))?;

        let mut found: Vec<FoundNoteWithMemo> = Vec::new();

        for (idx, action) in actions.iter().enumerate() {
            // Parse nullifier and cmx using CtOption
            let nullifier_opt = orchard::note::Nullifier::from_bytes(&action.nullifier);
            if !bool::from(nullifier_opt.is_some()) {
                continue;
            }
            let nullifier = nullifier_opt.unwrap();

            let cmx_opt = orchard::note::ExtractedNoteCommitment::from_bytes(&action.cmx);
            if !bool::from(cmx_opt.is_some()) {
                continue;
            }
            let cmx = cmx_opt.unwrap();

            let compact_action = orchard::note_encryption::CompactAction::from_parts(
                nullifier,
                cmx,
                EphemeralKeyBytes(action.epk),
                action.enc_ciphertext[..52].try_into().unwrap(),
            );

            let output = FullShieldedOutput {
                epk: action.epk,
                cmx: action.cmx,
                enc_ciphertext: action.enc_ciphertext,
            };

            // Try external scope (incoming)
            if let Some((note, _addr, memo)) =
                try_full_decrypt_any_version(&compact_action, &self.prepared_ivk_external, &output)
            {
                let note_nf = note.nullifier(&self.fvk);
                let (memo_str, is_text) = parse_memo_bytes(&memo);

                found.push(FoundNoteWithMemo {
                    index: idx as u32,
                    value: note.value().inner(),
                    nullifier: hex_encode(&note_nf.to_bytes()),
                    cmx: hex_encode(&action.cmx),
                    memo: memo_str,
                    memo_is_text: is_text,
                    is_outgoing: false,
                    memo_bytes: hex_encode(&memo),
                });
                continue;
            }

            // Try internal scope (outgoing)
            if let Some((note, _addr, memo)) =
                try_full_decrypt_any_version(&compact_action, &self.prepared_ivk_internal, &output)
            {
                let note_nf = note.nullifier(&self.fvk);
                let (memo_str, is_text) = parse_memo_bytes(&memo);

                found.push(FoundNoteWithMemo {
                    index: idx as u32,
                    value: note.value().inner(),
                    nullifier: hex_encode(&note_nf.to_bytes()),
                    cmx: hex_encode(&action.cmx),
                    memo: memo_str,
                    memo_is_text: is_text,
                    is_outgoing: true,
                    memo_bytes: hex_encode(&memo),
                });
            }
        }

        serde_wasm_bindgen::to_value(&found)
            .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
    }
}

/// Parse memo bytes into a string
/// Returns (memo_string, is_text)
fn parse_memo_bytes(memo: &[u8; 512]) -> (String, bool) {
    // Check if memo is empty (all zeros or starts with 0xF4 no-memo)
    if memo[0] == 0xF4 || memo.iter().all(|&b| b == 0) {
        return (String::new(), true);
    }

    // 0xF6 with remaining all-zeros = no memo (ZIP-302)
    // 0xF6 with non-zero remaining = reserved ("from the future")
    if memo[0] == 0xF6 {
        if memo[1..].iter().all(|&b| b == 0) {
            return (String::new(), true); // no memo
        }
        return (String::new(), false); // reserved binary
    }

    // 0xFF = arbitrary data (ZIP-302). Zafu uses 0xFF 0x5A as magic.
    // Return empty string; callers inspect memo_bytes for structured data.
    if memo[0] == 0xFF {
        return (String::new(), false);
    }

    // Check if it's a text memo (starts with 0xF5 followed by UTF-8)
    if memo[0] == 0xF5 {
        // Find the end of the text (first null byte or end of memo)
        let text_bytes: Vec<u8> = memo[1..].iter().take_while(|&&b| b != 0).copied().collect();

        if let Ok(text) = String::from_utf8(text_bytes) {
            return (text, true);
        }
    }

    // Try to parse as raw UTF-8 (some wallets don't use the 0xF5 prefix)
    let text_bytes: Vec<u8> = memo.iter().take_while(|&&b| b != 0).copied().collect();

    if let Ok(text) = String::from_utf8(text_bytes.clone()) {
        // Check if it looks like text (mostly printable ASCII + common UTF-8)
        let printable_ratio = text_bytes
            .iter()
            .filter(|&&b| (32..=126).contains(&b) || b >= 0xC0)
            .count() as f32
            / text_bytes.len().max(1) as f32;

        if printable_ratio > 0.8 {
            return (text, true);
        }
    }

    // Return as hex if it's binary data
    (hex_encode(memo), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a note of `version` through the *production* compact-scan
    /// path (`try_decrypt_compact_action`) and return what the scanner saw.
    ///
    /// Regression harness for the note-version domain split. Upstream orchard
    /// gives `OrchardDomain` and `IronwoodDomain` different, *enforced* note
    /// plaintext lead bytes (0x02 / 0x03); the fork this crate used to build
    /// against had a single permissive domain. A scanner that constructs only
    /// `OrchardDomain` therefore fails every ironwood note silently — no
    /// error, just an empty wallet. The whole test suite passed while that was
    /// live, because nothing exercised a V3 note without a node.
    fn scan_roundtrip_for_version(
        version: orchard::note::NoteVersion,
        scope: Scope,
    ) -> Option<DecryptedParts> {
        scan_roundtrip_with_choice(version, scope, DomainChoice::Either)
    }

    fn scan_roundtrip_with_choice(
        version: orchard::note::NoteVersion,
        scope: Scope,
        choice: DomainChoice,
    ) -> Option<DecryptedParts> {
        use orchard::note::{Nullifier, RandomSeed, Rho};
        use orchard::value::NoteValue;
        use rand::{rngs::OsRng, RngCore};
        use zcash_note_encryption::Domain;

        let mut rng = OsRng;
        let sk = SpendingKey::from_zip32_seed(&[7u8; 32], 133, zip32::AccountId::ZERO).unwrap();
        let fvk = orchard::keys::FullViewingKey::from(&sk);
        let ivk_external = fvk.to_ivk(Scope::External).prepare();
        let ivk_internal = fvk.to_ivk(Scope::Internal).prepare();

        let recipient = fvk.address_at(0u32, scope);
        // rho of a new note is the revealed nullifier of the note being spent,
        // which is exactly what the wire compact action carries.
        let (nf_old, rho): (Nullifier, Rho) = loop {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            b[31] &= 0x3f; // keep it inside the pallas base field
            let (Some(nf), Some(rho)) = (
                Option::<Nullifier>::from(Nullifier::from_bytes(&b)),
                Option::<Rho>::from(Rho::from_bytes(&b)),
            ) else {
                continue;
            };
            break (nf, rho);
        };
        let note = loop {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(seed, &rho)) else {
                continue;
            };
            if let Some(n) = Option::<orchard::Note>::from(orchard::Note::from_parts(
                recipient,
                NoteValue::from_raw(624_985_000),
                rho,
                rseed,
                version,
            )) {
                break n;
            }
        };
        let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());

        // Encrypt with the domain that matches the note version, exactly as a
        // real bundle builder would.
        let (epk_bytes, enc) = match version {
            orchard::note::NoteVersion::V2 => {
                let e =
                    orchard::note_encryption::OrchardNoteEncryption::new(None, note, [0u8; 512]);
                (
                    OrchardDomain::epk_bytes(e.epk()).0,
                    e.encrypt_note_plaintext(),
                )
            }
            orchard::note::NoteVersion::V3 => {
                let e =
                    orchard::note_encryption::IronwoodNoteEncryption::new(None, note, [0u8; 512]);
                (
                    IronwoodDomain::epk_bytes(e.epk()).0,
                    e.encrypt_note_plaintext(),
                )
            }
        };

        let mut ciphertext = [0u8; 52];
        ciphertext.copy_from_slice(&enc[..52]);
        let action = CompactActionBinary {
            nullifier: nf_old.to_bytes(),
            cmx: cmx.to_bytes(),
            epk: epk_bytes,
            ciphertext,
        };

        try_decrypt_compact_action(&fvk, &ivk_external, &ivk_internal, &action, choice)
    }

    /// An ironwood (V3) note must decrypt on the production scan path. This is
    /// the case that regressed on the move to upstream orchard 0.15.5: zafu
    /// went blind to the entire live pool.
    #[test]
    fn scanner_decrypts_ironwood_v3_note() {
        let d = scan_roundtrip_for_version(orchard::note::NoteVersion::V3, Scope::External)
            .expect("ironwood (V3) note must decrypt via try_decrypt_compact_action");
        assert_eq!(d.value, 624_985_000);
        assert_eq!(d.note_version, 3, "note_version must come from the note");
        assert!(!d.is_change, "external scope must not be flagged as change");
    }

    /// The pool-aware fast path must genuinely NARROW the search, not merely
    /// relabel it.
    ///
    /// `scan_compact_actions_with_keys` picks a single domain from the pool it
    /// is already given, because zidecar returns orchard and ironwood actions
    /// in separate lists and the scan exports are per-pool. That halves trial
    /// decryption on the hot path — but only if the choice is actually honoured.
    /// If a refactor ever quietly widened it back to trying both, the scan
    /// would still be CORRECT and every other test here would still pass, so
    /// the regression would show up only as a wallet that syncs at half speed.
    ///
    /// So this asserts the negative: the wrong domain must FAIL to decrypt.
    #[test]
    fn pool_aware_choice_actually_narrows_the_domain() {
        use orchard::note::NoteVersion;

        // Right domain: decrypts.
        assert!(
            scan_roundtrip_with_choice(NoteVersion::V3, Scope::External, DomainChoice::Ironwood)
                .is_some(),
            "a V3 note must decrypt under the ironwood domain"
        );
        assert!(
            scan_roundtrip_with_choice(NoteVersion::V2, Scope::External, DomainChoice::Orchard)
                .is_some(),
            "a V2 note must decrypt under the orchard domain"
        );

        // Wrong domain: must NOT decrypt. This is what proves the narrowing is
        // real — upstream enforces the plaintext lead byte per domain, so a
        // `None` here is the enforcement working, not a broken fixture.
        assert!(
            scan_roundtrip_with_choice(NoteVersion::V3, Scope::External, DomainChoice::Orchard)
                .is_none(),
            "a V3 note must NOT decrypt under the orchard domain; if it does, \
             the choice is being ignored and the scan is doing double work"
        );
        assert!(
            scan_roundtrip_with_choice(NoteVersion::V2, Scope::External, DomainChoice::Ironwood)
                .is_none(),
            "a V2 note must NOT decrypt under the ironwood domain"
        );

        // And Either still finds both, so callers without pool knowledge are
        // unaffected by the fast path existing.
        assert!(
            scan_roundtrip_with_choice(NoteVersion::V2, Scope::External, DomainChoice::Either)
                .is_some()
                && scan_roundtrip_with_choice(
                    NoteVersion::V3,
                    Scope::External,
                    DomainChoice::Either
                )
                .is_some(),
            "Either must still accept both pools"
        );
    }

    /// The orchard (V2) path must keep working — trying both domains must not
    /// regress the pool that already worked.
    #[test]
    fn scanner_decrypts_orchard_v2_note() {
        let d = scan_roundtrip_for_version(orchard::note::NoteVersion::V2, Scope::External)
            .expect("orchard (V2) note must decrypt via try_decrypt_compact_action");
        assert_eq!(d.value, 624_985_000);
        assert_eq!(d.note_version, 2);
        assert!(!d.is_change);
    }

    /// Scope semantics must survive the two-domain trial: a V3 note sent to
    /// the *internal* address is change, and must be flagged as such rather
    /// than surfacing as incoming income. (Same invariant the mainnet
    /// turnstile fixture pins at the transaction level.)
    #[test]
    fn scanner_flags_internal_scope_ironwood_note_as_change() {
        let d = scan_roundtrip_for_version(orchard::note::NoteVersion::V3, Scope::Internal)
            .expect("internal-scope ironwood note must decrypt");
        assert_eq!(d.note_version, 3);
        assert!(d.is_change, "internal scope must be flagged as change");
    }

    #[test]
    fn test_seed_validation() {
        assert!(validate_seed_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"));
        assert!(!validate_seed_phrase("invalid seed phrase"));
    }

    /// The shielding pool gate uses plain constants so it is a compile-time
    /// value on the wasm hot path. Assert they stay in sync with upstream
    /// `zcash_protocol`'s real activation heights and branch id.
    #[test]
    fn nu6_3_activation_matches_upstream() {
        use zcash_protocol::consensus::{
            BranchId, MainNetwork, NetworkUpgrade, Parameters, TestNetwork,
        };
        assert_eq!(
            MainNetwork
                .activation_height(NetworkUpgrade::Nu6_3)
                .map(u32::from),
            Some(NU6_3_ACTIVATION_HEIGHT_MAINNET)
        );
        assert_eq!(
            TestNetwork
                .activation_height(NetworkUpgrade::Nu6_3)
                .map(u32::from),
            Some(NU6_3_ACTIVATION_HEIGHT_TESTNET)
        );
        assert_eq!(u32::from(BranchId::Nu6_3), NU6_3_BRANCH_ID);
    }

    /// Orchard shielding must be unreachable at/after NU6.3 - by height AND by
    /// consensus branch id - and reachable before it.
    #[test]
    fn orchard_shielding_is_gated_at_nu6_3() {
        // mainnet, one block before activation: allowed (with a pre-NU6.3 id).
        assert!(guard_orchard_shielding_allowed(
            NU6_3_ACTIVATION_HEIGHT_MAINNET - 1,
            true,
            Some("5437f330")
        )
        .is_ok());
        // exactly at activation: refused.
        assert!(guard_orchard_shielding_allowed(
            NU6_3_ACTIVATION_HEIGHT_MAINNET,
            true,
            Some("5437f330")
        )
        .is_err());
        // after activation: refused.
        assert!(guard_orchard_shielding_allowed(
            NU6_3_ACTIVATION_HEIGHT_MAINNET + 10_000,
            true,
            None
        )
        .is_err());
        // pre-activation height but the chain reports the NU6.3 branch id (a
        // stale/wrong height must not open the door): refused.
        assert!(guard_orchard_shielding_allowed(1_000_000, true, Some("37a5165b")).is_err());
        // testnet: same boundary, at the real upstream activation height
        // (4_134_000). Before it orchard shielding is still allowed; at and
        // after it, refused.
        assert!(
            guard_orchard_shielding_allowed(NU6_3_ACTIVATION_HEIGHT_TESTNET - 1, false, None)
                .is_ok()
        );
        assert!(
            guard_orchard_shielding_allowed(NU6_3_ACTIVATION_HEIGHT_TESTNET, false, None).is_err()
        );
        assert!(guard_orchard_shielding_allowed(
            NU6_3_ACTIVATION_HEIGHT_TESTNET + 10_000,
            false,
            None
        )
        .is_err());
    }

    #[test]
    fn shielding_pool_resolves_from_height() {
        assert_eq!(
            shielding_pool_for_height(NU6_3_ACTIVATION_HEIGHT_MAINNET - 1, true),
            "orchard"
        );
        assert_eq!(
            shielding_pool_for_height(NU6_3_ACTIVATION_HEIGHT_MAINNET, true),
            "ironwood"
        );
        assert_eq!(shielding_pool_for_height(3_500_000, true), "ironwood");
        assert_eq!(
            shielding_pool_for_height(NU6_3_ACTIVATION_HEIGHT_TESTNET - 1, false),
            "orchard"
        );
        assert_eq!(
            shielding_pool_for_height(NU6_3_ACTIVATION_HEIGHT_TESTNET, false),
            "ironwood"
        );
    }

    #[test]
    fn zip317_shielding_fee_sums_across_bundles() {
        // n transparent inputs + one padded 2-action ironwood bundle.
        assert_eq!(zip317_shielding_fee(1), 15_000);
        assert_eq!(zip317_shielding_fee(2), 20_000);
        assert_eq!(zip317_shielding_fee(5), 35_000);
        // never below the ZIP-317 grace floor
        assert_eq!(zip317_shielding_fee(0), 10_000);
    }

    /// The transparent side is ceil(148n/150), which stops equalling `n` at
    /// n = 75 (148*75 == 11_100 == 74*150 exactly). Treating it as `n` overpaid
    /// one marginal fee per ~75 inputs and fingerprinted the wallet.
    #[test]
    fn zip317_transparent_actions_is_ceil_148n_over_150() {
        assert_eq!(zip317_transparent_actions(0), 0);
        // below the crossover the naive count happens to be right
        for n in 1..=74usize {
            assert_eq!(zip317_transparent_actions(n), n as u64, "n = {}", n);
        }
        // exact multiple of 150 bytes: 74 actions, not 75
        assert_eq!(zip317_transparent_actions(75), 74);
        assert_eq!(zip317_transparent_actions(76), 75);
        assert_eq!(zip317_transparent_actions(150), 148);
        // ... and the fee follows: 76 logical actions, not 77
        assert_eq!(zip317_shielding_fee(75), 380_000);
        assert_eq!(zip317_shielding_fee(74), 380_000);
        // strictly monotonic non-decreasing, never above the naive estimate
        for n in 0..300usize {
            let a = zip317_transparent_actions(n);
            assert!(a <= n as u64, "n = {}", n);
            assert!(a >= zip317_transparent_actions(n.saturating_sub(1)));
        }
    }

    #[test]
    fn test_parse_branch_id() {
        // NU6.2 / NU6.3, lowercase (the on-wire form from GetLightdInfo)
        assert_eq!(parse_branch_id("5437f330"), Some(0x5437F330));
        assert_eq!(parse_branch_id("37a5165b"), Some(0x37A5165B));
        // uppercase tolerated
        assert_eq!(parse_branch_id("5437F330"), Some(0x5437F330));
        // 0x / 0X prefix + surrounding whitespace tolerated
        assert_eq!(parse_branch_id("0x37a5165b"), Some(0x37A5165B));
        assert_eq!(parse_branch_id("0X37A5165B"), Some(0x37A5165B));
        assert_eq!(parse_branch_id("  37a5165b\n"), Some(0x37A5165B));
        // malformed / empty -> None so the caller can fall back
        assert_eq!(parse_branch_id(""), None);
        assert_eq!(parse_branch_id("   "), None);
        assert_eq!(parse_branch_id("0x"), None);
        assert_eq!(parse_branch_id("zzzz"), None);
        // out of u32 range -> None (does not silently truncate)
        assert_eq!(parse_branch_id("137a5165b"), None);
    }

    #[test]
    fn test_resolve_branch_id_valid() {
        assert_eq!(
            resolve_branch_id(Some("37a5165b")).unwrap(),
            0x37A5165B,
            "NU6.3 hex string must resolve to the NU6.3 branch id"
        );
        assert_eq!(resolve_branch_id(Some("0x5437f330")).unwrap(), 0x5437F330);
    }

    /// FAIL-CLOSED: a missing/empty/garbage branch id must be an ERROR, never a
    /// silent fallback to the compiled-in NU6.2 value. `fetchBranchIdHex` in the
    /// extension returns `""` whenever the GetLightdInfo RPC fails, so the
    /// empty-string case is the one that actually reaches production.
    #[test]
    fn test_resolve_branch_id_fails_closed() {
        assert!(resolve_branch_id(None).is_err());
        assert!(resolve_branch_id(Some("")).is_err());
        assert!(resolve_branch_id(Some("   ")).is_err());
        assert!(resolve_branch_id(Some("not-hex")).is_err());
        // out of u32 range: must not silently truncate into a valid-looking id
        assert!(resolve_branch_id(Some("137a5165b")).is_err());
    }

    /// Orchard spends are consensus-disabled once the live branch id is NU6.3.
    #[test]
    fn test_guard_orchard_spend_allowed() {
        assert!(guard_orchard_spend_allowed(0x5437_F330).is_ok());
        assert!(guard_orchard_spend_allowed(NU6_3_BRANCH_ID).is_err());
    }

    #[test]
    fn test_key_derivation() {
        // Standard 24-word test mnemonic
        let keys = WalletKeys::from_seed_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        ).unwrap();

        // Address ID is 32 bytes = 64 hex chars
        let address = keys.get_address();
        assert_eq!(address.len(), 64);

        // Verify it's not all zeros (key derivation worked)
        assert!(!address.chars().all(|c| c == '0'));
    }

    #[test]
    fn test_binary_action_parsing() {
        // Create test data: 1 action
        let mut data = vec![1, 0, 0, 0]; // count = 1
        data.extend_from_slice(&[0u8; 32]); // nullifier
        data.extend_from_slice(&[1u8; 32]); // cmx
        data.extend_from_slice(&[2u8; 32]); // epk
        data.extend_from_slice(&[3u8; 52]); // ciphertext

        let actions = parse_compact_actions(&data).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].nullifier, [0u8; 32]);
        assert_eq!(actions[0].cmx, [1u8; 32]);
    }

    #[test]
    fn test_fvk_export_roundtrip() {
        // Create wallet from seed
        let keys = WalletKeys::from_seed_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        ).unwrap();

        // Export FVK as QR hex
        let qr_hex = keys.export_fvk_qr_hex(0, Some("Test Wallet".to_string()), true);

        // Verify prelude
        let qr_bytes = hex_decode(&qr_hex).unwrap();
        assert_eq!(qr_bytes[0], 0x53); // substrate compat
        assert_eq!(qr_bytes[1], 0x04); // zcash
        assert_eq!(qr_bytes[2], QR_TYPE_ZCASH_FVK_EXPORT);

        // Import as watch-only wallet
        let watch = WatchOnlyWallet::from_qr_hex(&qr_hex).unwrap();

        // Verify same FVK
        assert_eq!(watch.export_fvk_hex(), keys.get_fvk_hex());
        assert_eq!(watch.get_account_index(), 0);
        assert!(watch.is_mainnet());
    }

    #[test]
    fn test_watch_only_from_fvk_bytes() {
        // Create wallet and get FVK
        let keys = WalletKeys::from_seed_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        ).unwrap();

        let fvk_hex = keys.get_fvk_hex();
        let fvk_bytes = hex_decode(&fvk_hex).unwrap();

        // Create watch-only wallet from FVK bytes
        let watch = WatchOnlyWallet::from_fvk_bytes(&fvk_bytes, 0, true).unwrap();

        // Verify addresses match
        assert_eq!(watch.get_address(), keys.get_receiving_address(true));
    }

    #[test]
    fn test_address_generation() {
        let keys = WalletKeys::from_seed_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        ).unwrap();

        let addr0 = keys.get_receiving_address(true);
        let addr1 = keys.get_receiving_address_at(1, true);

        // Addresses should be different
        assert_ne!(addr0, addr1);

        // Mainnet vs testnet prefix
        let addr_mainnet = keys.get_receiving_address(true);
        let addr_testnet = keys.get_receiving_address(false);
        assert!(addr_mainnet.starts_with("u1orchard:"));
        assert!(addr_testnet.starts_with("utest1orchard:"));
    }

    /// base58check encode (zcash transparent address)
    fn base58check_encode(version: &[u8], payload: &[u8]) -> String {
        use sha2::Digest as _;
        let mut data = Vec::with_capacity(version.len() + payload.len() + 4);
        data.extend_from_slice(version);
        data.extend_from_slice(payload);
        let checksum = sha2::Sha256::digest(sha2::Sha256::digest(&data));
        data.extend_from_slice(&checksum[..4]);

        // base58 encode
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut num = vec![0u8; data.len()];
        num.copy_from_slice(&data);
        let mut out = Vec::new();
        while !num.iter().all(|&b| b == 0) {
            let mut rem = 0u32;
            for byte in num.iter_mut() {
                let acc = (rem << 8) | (*byte as u32);
                *byte = (acc / 58) as u8;
                rem = acc % 58;
            }
            out.push(ALPHABET[rem as usize]);
        }
        for &b in data.iter() {
            if b == 0 {
                out.push(b'1');
            } else {
                break;
            }
        }
        out.reverse();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn test_transparent_privkey_derivation() {
        let seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = bip39::Mnemonic::parse(seed).unwrap();
        let seed_bytes = mnemonic.to_seed("");

        // BIP32 derivation: m/44'/133'/0'/0/0
        let master = bip32_master_key(&seed_bytes);
        let child = bip32_derive_child(&master, 44, true).unwrap();
        let child = bip32_derive_child(&child, 133, true).unwrap();
        let child = bip32_derive_child(&child, 0, true).unwrap();
        let child = bip32_derive_child(&child, 0, false).unwrap();
        let child = bip32_derive_child(&child, 0, false).unwrap();

        // verify we can construct a signing key and derive address
        let signing_key = k256::ecdsa::SigningKey::from_slice(&child.key).unwrap();
        let pubkey = signing_key.verifying_key().to_encoded_point(true);
        assert_eq!(pubkey.as_bytes().len(), 33);

        // derive t-addr: base58check(version_prefix || hash160(compressed_pubkey))
        let pkh = hash160(pubkey.as_bytes());
        // zcash mainnet t-addr prefix: 0x1cb8
        let taddr = base58check_encode(&[0x1c, 0xb8], &pkh);
        println!("t-addr (m/44'/133'/0'/0/0): {}", taddr);
        assert!(taddr.starts_with("t1"));
    }

    #[test]
    fn test_orchard_builder_shielding() {
        use orchard::builder::{Builder, BundleType};
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};
        use orchard::tree::Anchor;
        use orchard::value::NoteValue;
        use rand::rngs::OsRng;
        use zcash_protocol::value::ZatBalance;

        // derive orchard key from test seed
        let seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = bip39::Mnemonic::parse(seed).unwrap();
        let seed_bytes = mnemonic.to_seed("");

        let sk = SpendingKey::from_zip32_seed(
            &seed_bytes,
            133,
            zip32::AccountId::try_from(0u32).unwrap(),
        )
        .unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u64, Scope::External);

        // build an output-only bundle
        let bundle_type = BundleType::Transactional {
            bundle_required: true,
            pad_to_minimum: None,
        };
        let mut builder = Builder::new(
            bundle_type,
            orchard::bundle::BundleVersion::orchard_insecure_v1(),
            orchard::bundle::Flags::SPENDS_DISABLED,
            Anchor::empty_tree(),
        )
        .expect("flags are representable under this bundle version");

        builder
            .add_output(None, recipient, NoteValue::from_raw(50_000), [0u8; 512])
            .expect("add_output should succeed");

        let mut rng = OsRng;
        let (unauthorized, _meta) = builder
            .build::<ZatBalance>(&mut rng)
            .expect("build should succeed")
            .expect("should produce a bundle");

        println!("bundle built: {} actions", unauthorized.actions().len());
        // orchard pads to minimum 2 actions
        assert!(
            unauthorized.actions().len() >= 2,
            "expected >=2 actions (padding)"
        );

        // prove (expensive but should work natively)
        let proven = with_proving_key(|pk| unauthorized.create_proof(pk, &mut rng))
            .expect("proving should succeed");

        println!("proof generated");

        // apply signatures (no spend auth keys for output-only)
        let sighash = [0u8; 32]; // dummy sighash for test
        let authorized = proven
            .apply_signatures(&mut rng, sighash, &[])
            .expect("signatures should succeed");

        println!("authorized bundle: {} actions", authorized.actions().len());

        // serialize
        let mut out = Vec::new();
        serialize_orchard_bundle(&authorized, &mut out).expect("serialization");
        println!("serialized orchard bundle: {} bytes", out.len());
        assert!(out.len() > 100);
    }
}

// ============================================================================
// Transaction Building for Cold Signing (Real v5 Transaction Bytes)
// ============================================================================

/// Build an unsigned transaction and return the data needed for cold signing.
/// Uses the PCZT (Partially Constructed Zcash Transaction) flow from the orchard
/// crate to produce real v5 transaction bytes with Halo 2 proofs.
///
/// Returns JSON with:
/// - sighash: the transaction sighash (hex, 32 bytes)
/// - alphas: array of alpha randomizers for real spend actions only (hex, 32 bytes each)
/// - unsigned_tx: the serialized v5 transaction with dummy spend auth sigs (hex)
/// - spend_indices: array of action indices that need external signatures
/// - summary: human-readable transaction summary
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn build_unsigned_transaction(
    ufvk_str: &str,
    notes_json: JsValue,
    recipient: &str,
    amount: u64,
    fee: u64,
    anchor_hex: &str,
    merkle_paths_json: JsValue,
    _account_index: u32,
    mainnet: bool,
    memo_hex: Option<String>,
    // Live consensus branch id from GetLightdInfo.consensusBranchId, e.g.
    // "5437f330" (NU6.2) or "37a5165b" (NU6.3). Pass verbatim. REQUIRED: a
    // missing/unparseable value is a hard error, never a silent default.
    branch_id_hex: Option<String>,
) -> Result<JsValue, JsError> {
    use group::ff::PrimeField;
    use orchard::builder::{Builder, BundleType};
    use orchard::note::{RandomSeed, Rho};
    use orchard::tree::{Anchor, MerkleHashOrchard, MerklePath as OrchardMerklePath};
    use orchard::value::NoteValue;
    use rand::rngs::OsRng;
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_protocol::consensus::{MainNetwork, TestNetwork};
    use zcash_protocol::value::ZatBalance;

    // FAIL-CLOSED, BEFORE any proving: the ZIP-244 sighash below binds this
    // branch id, so resolve it (no fallback) and refuse outright once NU6.3 has
    // disabled orchard spends. Doing it here rather than at the sighash keeps
    // the user from paying ~2 minutes of Halo 2 proving for a tx the network
    // will reject.
    let branch_id: u32 =
        resolve_branch_id(branch_id_hex.as_deref()).map_err(|e| JsError::new(&e))?;
    guard_orchard_spend_allowed(branch_id).map_err(|e| JsError::new(&e))?;

    // --- derive FVK from UFVK ---
    let ufvk = if mainnet {
        UnifiedFullViewingKey::decode(&MainNetwork, ufvk_str)
    } else {
        UnifiedFullViewingKey::decode(&TestNetwork, ufvk_str)
    }
    .map_err(|e| JsError::new(&format!("invalid UFVK: {}", e)))?;

    let orchard_fvk_old = ufvk
        .orchard()
        .ok_or_else(|| JsError::new("UFVK has no orchard component"))?;

    // Reconstruct as our orchard 0.12 FVK via raw bytes
    let fvk = {
        let raw = orchard_fvk_old.to_bytes();
        orchard::keys::FullViewingKey::from_bytes(&raw)
            .ok_or_else(|| JsError::new("failed to reconstruct orchard FVK from UFVK bytes"))?
    };

    // derive change address (internal scope, diversifier 0)
    let change_addr = fvk.to_ivk(Scope::Internal).address_at(0u64);

    // --- parse recipient (orchard or transparent) ---
    let is_transparent = recipient.starts_with("t1") || recipient.starts_with("tm");
    let recipient_addr = if is_transparent {
        None
    } else {
        Some(
            parse_orchard_address(recipient, mainnet)
                .map_err(|e| JsError::new(&format!("invalid recipient: {}", e)))?,
        )
    };
    let t_output_script = if is_transparent {
        Some(
            decode_t_address_script(recipient, mainnet)
                .map_err(|e| JsError::new(&format!("invalid transparent address: {}", e)))?,
        )
    } else {
        None
    };

    // --- parse anchor ---
    let anchor_bytes = hex_decode(anchor_hex).ok_or_else(|| JsError::new("invalid anchor hex"))?;
    if anchor_bytes.len() != 32 {
        return Err(JsError::new("anchor must be 32 bytes"));
    }
    let mut anchor_arr = [0u8; 32];
    anchor_arr.copy_from_slice(&anchor_bytes);
    let anchor = Option::from(Anchor::from_bytes(anchor_arr))
        .ok_or_else(|| JsError::new("invalid anchor"))?;

    // --- parse notes and merkle paths ---
    let notes: Vec<SpendableNote> = serde_wasm_bindgen::from_value(notes_json)
        .map_err(|e| JsError::new(&format!("invalid notes: {}", e)))?;
    let merkle_paths: Vec<MerklePathInfo> = serde_wasm_bindgen::from_value(merkle_paths_json)
        .map_err(|e| JsError::new(&format!("invalid merkle paths: {}", e)))?;

    if notes.len() != merkle_paths.len() {
        return Err(JsError::new("notes and merkle paths count mismatch"));
    }

    // --- calculate totals ---
    let total_input: u64 = notes.iter().map(|n| n.value).sum();
    if total_input < amount + fee {
        return Err(JsError::new(&format!(
            "insufficient funds: {} < {} + {}",
            total_input, amount, fee
        )));
    }
    let change = total_input - amount - fee;
    let num_spends = notes.len();

    // --- build orchard bundle using PCZT path ---
    // NU6.1-branch V5 tx: legacy orchard pool, pre-NU6.2 (historical) circuit.
    let bundle_type = BundleType::Transactional {
        bundle_required: true,
        pad_to_minimum: None,
    };
    let mut builder = Builder::new(
        bundle_type,
        orchard::bundle::BundleVersion::orchard_insecure_v1(),
        orchard::bundle::Flags::ENABLED,
        anchor,
    )
    .expect("flags are representable under this bundle version");

    // add spends (same note reconstruction as build_signed_spend_transaction)
    for (i, note_info) in notes.iter().enumerate() {
        let rho_bytes = hex_decode(&note_info.rho_hex)
            .ok_or_else(|| JsError::new(&format!("invalid rho hex for note {}", i)))?;
        if rho_bytes.len() != 32 {
            return Err(JsError::new(&format!(
                "rho must be 32 bytes for note {}",
                i
            )));
        }
        let mut rho_arr = [0u8; 32];
        rho_arr.copy_from_slice(&rho_bytes);
        let rho = Option::from(Rho::from_bytes(&rho_arr))
            .ok_or_else(|| JsError::new(&format!("invalid rho for note {}", i)))?;

        let rseed_bytes = hex_decode(&note_info.rseed_hex)
            .ok_or_else(|| JsError::new(&format!("invalid rseed hex for note {}", i)))?;
        if rseed_bytes.len() != 32 {
            return Err(JsError::new(&format!(
                "rseed must be 32 bytes for note {}",
                i
            )));
        }
        let mut rseed_arr = [0u8; 32];
        rseed_arr.copy_from_slice(&rseed_bytes);
        let rseed = Option::from(RandomSeed::from_bytes(rseed_arr, &rho))
            .ok_or_else(|| JsError::new(&format!("invalid rseed for note {}", i)))?;

        let note_value = NoteValue::from_raw(note_info.value);

        let note: orchard::Note = if !note_info.recipient_hex.is_empty() {
            let addr_bytes = hex_decode(&note_info.recipient_hex)
                .ok_or_else(|| JsError::new(&format!("invalid recipient hex for note {}", i)))?;
            let addr_arr: [u8; 43] = addr_bytes
                .try_into()
                .map_err(|_| JsError::new(&format!("recipient must be 43 bytes for note {}", i)))?;
            let addr = Option::from(orchard::Address::from_raw_address_bytes(&addr_arr))
                .ok_or_else(|| JsError::new(&format!("invalid orchard address for note {}", i)))?;
            Option::from(orchard::Note::from_parts(
                addr,
                note_value,
                rho,
                rseed,
                orchard::note::NoteVersion::V2,
            ))
            .ok_or_else(|| {
                JsError::new(&format!(
                    "failed to reconstruct note {} from stored address",
                    i
                ))
            })?
        } else {
            let ext_addr = fvk.to_ivk(Scope::External).address_at(0u64);
            let int_addr = fvk.to_ivk(Scope::Internal).address_at(0u64);
            Option::from(orchard::Note::from_parts(
                ext_addr,
                note_value,
                rho,
                rseed,
                orchard::note::NoteVersion::V2,
            ))
            .or_else(|| {
                Option::from(orchard::Note::from_parts(
                    int_addr,
                    note_value,
                    rho,
                    rseed,
                    orchard::note::NoteVersion::V2,
                ))
            })
            .ok_or_else(|| {
                JsError::new(&format!(
                    "failed to reconstruct note {} — rseed/rho/value mismatch",
                    i
                ))
            })?
        };

        // verify cmx
        let expected_cmx = hex_decode(&note_info.cmx)
            .ok_or_else(|| JsError::new(&format!("invalid cmx hex for note {}", i)))?;
        let reconstructed_cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
        if hex_encode(&reconstructed_cmx.to_bytes()) != hex_encode(&expected_cmx) {
            return Err(JsError::new(&format!(
                "cmx mismatch for note {}: reconstructed={} expected={}",
                i,
                hex_encode(&reconstructed_cmx.to_bytes()),
                hex_encode(&expected_cmx)
            )));
        }

        // parse merkle path
        let mp = &merkle_paths[i];
        if mp.path.len() != 32 {
            return Err(JsError::new(&format!(
                "merkle path must have 32 elements, got {} for note {}",
                mp.path.len(),
                i
            )));
        }

        let mut auth_path = [[0u8; 32]; 32];
        for (j, hash_hex) in mp.path.iter().enumerate() {
            let hash_bytes = hex_decode(hash_hex)
                .ok_or_else(|| JsError::new(&format!("invalid merkle path hash at {}/{}", i, j)))?;
            if hash_bytes.len() != 32 {
                return Err(JsError::new(&format!(
                    "merkle path hash must be 32 bytes at {}/{}",
                    i, j
                )));
            }
            auth_path[j].copy_from_slice(&hash_bytes);
        }

        // Decode each sibling positionally. The previous `filter_map` +
        // `len() != 32` form silently dropped a non-canonical sibling and
        // then reported a generic "invalid merkle path hashes" - which
        // erased *which* sibling and *why*, exactly when someone is
        // debugging an anchor mismatch on hardware. A wrong path is still
        // caught downstream by orchard's `has_matching_anchor`
        // (AnchorMismatch), so this was never a silent-corruption hole, but
        // the lossy collapse made the failure undiagnosable. Fail precisely.
        let mut merkle_hashes_arr: [MerkleHashOrchard; 32] =
            [MerkleHashOrchard::from_bytes(&[0u8; 32]).unwrap(); 32];
        for (j, bytes) in auth_path.iter().enumerate() {
            merkle_hashes_arr[j] =
                Option::from(MerkleHashOrchard::from_bytes(bytes)).ok_or_else(|| {
                    JsError::new(&format!(
                        "merkle sibling {}/{} is not a canonical Pallas base element: {}",
                        i,
                        j,
                        hex_encode(bytes),
                    ))
                })?;
        }
        let merkle_hashes: Vec<MerkleHashOrchard> = merkle_hashes_arr.to_vec();

        let merkle_path = OrchardMerklePath::from_parts(
            u32::try_from(mp.position).map_err(|_| {
                JsError::new(&format!("tree position {} exceeds u32 max", mp.position))
            })?,
            merkle_hashes
                .try_into()
                .map_err(|_| JsError::new("merkle path conversion"))?,
        );

        builder
            .add_spend(fvk.clone(), note, merkle_path)
            .map_err(|e| JsError::new(&format!("add_spend for note {}: {:?}", i, e)))?;
    }

    // decode memo from hex if provided, otherwise empty (all zeros).
    // only the recipient output carries the memo — change outputs MUST
    // have empty memos per zcash convention (prevents memo correlation
    // between the recipient note and the change note).
    let recipient_memo = decode_memo_hex(memo_hex.as_deref())?;

    // OVK for outputs: bind out_ciphertext to the wallet's own OVK so the
    // FVK holder (every FROST co-signer in multisig, the user in single-key)
    // can OVK-decrypt and recover (recipient, amount). This unlocks the
    // multisig verifier on co-signers and outgoing-tx history on the
    // sending wallet. Network-layer privacy is unchanged — the ciphertext
    // is still opaque to anyone without the FVK.
    let ovk_external = fvk.to_ovk(Scope::External);
    let ovk_internal = fvk.to_ovk(Scope::Internal);

    // add recipient output (orchard only — transparent outputs are added to the tx directly)
    if let Some(ref addr) = recipient_addr {
        builder
            .add_output(
                Some(ovk_external.clone()),
                *addr,
                NoteValue::from_raw(amount),
                recipient_memo,
            )
            .map_err(|e| JsError::new(&format!("add_output (recipient): {:?}", e)))?;
    }

    // add change output if needed (for z→t, all orchard value minus amount+fee goes to change)
    if change > 0 {
        builder
            .add_output(
                Some(ovk_internal.clone()),
                change_addr,
                NoteValue::from_raw(change),
                // canonical ZIP-302 no-memo, not 512 zero bytes (see ZIP302_NO_MEMO)
                ZIP302_NO_MEMO,
            )
            .map_err(|e| JsError::new(&format!("add_output (change): {:?}", e)))?;
    }

    // --- build PCZT bundle (gives us access to alphas) ---
    let mut rng = OsRng;
    let (mut pczt_bundle, _meta) = builder
        .build_for_pczt(&mut rng)
        .map_err(|e| JsError::new(&format!("pczt bundle build: {:?}", e)))?;

    // --- create proof (Halo 2 — expensive) ---
    with_proving_key(|pk| pczt_bundle.create_proof(pk, rng))
        .map_err(|e| JsError::new(&format!("create_proof: {}", e)))?;

    // --- extract effects bundle for sighash computation ---
    let effects_bundle: orchard::Bundle<orchard::bundle::EffectsOnly, ZatBalance> = pczt_bundle
        .extract_effects()
        .map_err(|e| JsError::new(&format!("extract_effects: {}", e)))?
        .ok_or_else(|| JsError::new("extract_effects produced no bundle"))?;

    // --- compute ZIP-244 sighash (branch id resolved+gated at entry) ---
    let expiry_height: u32 = 0;

    let header_data = {
        let mut d = Vec::new();
        d.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
        d.extend_from_slice(&0x26A7270Au32.to_le_bytes());
        d.extend_from_slice(&branch_id.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
        d.extend_from_slice(&expiry_height.to_le_bytes());
        d
    };
    let header_digest = blake2b_256_personal(b"ZTxIdHeadersHash", &header_data);

    // transparent digest (includes outputs for z→t)
    let transparent_digest = if let Some(ref script) = t_output_script {
        let prevouts_digest = blake2b_256_personal(b"ZTxIdPrevoutHash", &[]);
        let sequence_digest = blake2b_256_personal(b"ZTxIdSequencHash", &[]);
        let mut outputs_data = Vec::new();
        outputs_data.extend_from_slice(&amount.to_le_bytes());
        outputs_data.extend_from_slice(&compact_size(script.len() as u64));
        outputs_data.extend_from_slice(script);
        let outputs_digest = blake2b_256_personal(b"ZTxIdOutputsHash", &outputs_data);
        let mut d = Vec::new();
        d.extend_from_slice(&prevouts_digest);
        d.extend_from_slice(&sequence_digest);
        d.extend_from_slice(&outputs_digest);
        blake2b_256_personal(b"ZTxIdTranspaHash", &d)
    } else {
        blake2b_256_personal(b"ZTxIdTranspaHash", &[])
    };
    let sapling_digest = blake2b_256_personal(b"ZTxIdSaplingHash", &[]);
    let orchard_digest = compute_orchard_digest(&effects_bundle)?;

    let sighash_personal = {
        let mut p = [0u8; 16];
        p[..12].copy_from_slice(b"ZcashTxHash_");
        p[12..16].copy_from_slice(&branch_id.to_le_bytes());
        p
    };

    let mut sighash_input = Vec::new();
    sighash_input.extend_from_slice(&header_digest);
    sighash_input.extend_from_slice(&transparent_digest);
    sighash_input.extend_from_slice(&sapling_digest);
    sighash_input.extend_from_slice(&orchard_digest);

    let sighash = blake2b_256_personal(&sighash_personal, &sighash_input);

    // --- finalize IO (signs dummies, computes bsk) ---
    pczt_bundle
        .finalize_io(sighash, rng)
        .map_err(|e| JsError::new(&format!("finalize_io: {}", e)))?;

    // --- extract alphas for real (non-dummy) spend actions ---
    // After finalize_io, dummy spends have spend_auth_sig set, real spends do not.
    // We return alphas only for actions that need external signing.
    let mut alphas: Vec<String> = Vec::new();
    let mut spend_indices: Vec<u32> = Vec::new();

    for (i, action) in pczt_bundle.actions().iter().enumerate() {
        if action.spend().spend_auth_sig().is_none() {
            // This is a real spend that needs external signing
            let alpha = action
                .spend()
                .alpha()
                .ok_or_else(|| JsError::new(&format!("missing alpha for action {}", i)))?;
            alphas.push(hex_encode(&alpha.to_repr()));
            spend_indices.push(i as u32);
        }
    }

    // --- serialize v5 transaction from PCZT bundle ---
    // Get proof and bsk from the PCZT bundle
    let proof = pczt_bundle
        .zkproof()
        .as_ref()
        .ok_or_else(|| JsError::new("missing proof after create_proof"))?;
    let bsk = pczt_bundle
        .bsk()
        .as_ref()
        .ok_or_else(|| JsError::new("missing bsk after finalize_io"))?;

    // Compute binding signature
    let binding_sig = bsk.sign(rng, &sighash);

    let mut tx_bytes = Vec::new();

    // v5 header
    tx_bytes.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
    tx_bytes.extend_from_slice(&0x26A7270Au32.to_le_bytes());
    tx_bytes.extend_from_slice(&branch_id.to_le_bytes());
    tx_bytes.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
    tx_bytes.extend_from_slice(&expiry_height.to_le_bytes());

    // transparent inputs (none)
    tx_bytes.extend_from_slice(&compact_size(0)); // vin
                                                  // transparent outputs
    if let Some(ref script) = t_output_script {
        tx_bytes.extend_from_slice(&compact_size(1)); // 1 vout
        tx_bytes.extend_from_slice(&amount.to_le_bytes());
        tx_bytes.extend_from_slice(&compact_size(script.len() as u64));
        tx_bytes.extend_from_slice(script);
    } else {
        tx_bytes.extend_from_slice(&compact_size(0)); // 0 vout
    }

    // sapling (empty)
    tx_bytes.extend_from_slice(&compact_size(0)); // spends
    tx_bytes.extend_from_slice(&compact_size(0)); // outputs

    // --- orchard bundle ---
    let actions = pczt_bundle.actions();
    let n_actions = actions.len();
    tx_bytes.extend_from_slice(&compact_size(n_actions as u64));

    // each action (without auth sigs)
    for action in actions.iter() {
        tx_bytes.extend_from_slice(&action.cv_net().to_bytes()); // 32
        tx_bytes.extend_from_slice(&action.spend().nullifier().to_bytes()); // 32
        tx_bytes.extend_from_slice(&<[u8; 32]>::from(action.spend().rk())); // 32
        tx_bytes.extend_from_slice(&action.output().cmx().to_bytes()); // 32
        tx_bytes.extend_from_slice(&action.output().encrypted_note().epk_bytes); // 32
        tx_bytes.extend_from_slice(&action.output().encrypted_note().enc_ciphertext); // 580
        tx_bytes.extend_from_slice(&action.output().encrypted_note().out_ciphertext);
        // 80
    }

    // flags byte
    tx_bytes.push(
        pczt_bundle
            .flags()
            .to_byte(orchard::bundle::BundleVersion::orchard_v2())
            .ok_or_else(|| JsError::new("flags not representable in pre-NU6.3 format"))?,
    );

    // valueBalanceOrchard (i64 LE) — from the effects bundle
    tx_bytes.extend_from_slice(&effects_bundle.value_balance().to_i64_le_bytes());

    // anchor
    tx_bytes.extend_from_slice(&effects_bundle.anchor().to_bytes());

    // proof bytes (compactSize-prefixed)
    let proof_bytes = proof.as_ref();
    tx_bytes.extend_from_slice(&compact_size(proof_bytes.len() as u64));
    tx_bytes.extend_from_slice(proof_bytes);

    // spend auth signatures: real sigs for dummies, zero bytes for real spends
    for action in actions.iter() {
        if let Some(sig) = action.spend().spend_auth_sig() {
            tx_bytes.extend_from_slice(&<[u8; 64]>::from(sig));
        } else {
            // Dummy zero signature — will be patched by complete_transaction
            tx_bytes.extend_from_slice(&[0u8; 64]);
        }
    }

    // binding signature (64 bytes)
    tx_bytes.extend_from_slice(&<[u8; 64]>::from(&binding_sig));

    // Build summary
    let amount_zec = amount as f64 / 100_000_000.0;
    let fee_zec = fee as f64 / 100_000_000.0;
    let summary = format!(
        "Send {:.8} ZEC to {}\nFee: {:.8} ZEC\nSpending {} note(s)",
        amount_zec,
        &recipient[..recipient.len().min(20)],
        fee_zec,
        num_spends
    );

    #[derive(Serialize)]
    struct BuildResult {
        sighash: String,
        alphas: Vec<String>,
        unsigned_tx: String,
        spend_indices: Vec<u32>,
        summary: String,
    }

    let result = BuildResult {
        sighash: hex_encode(&sighash),
        alphas,
        unsigned_tx: hex_encode(&tx_bytes),
        spend_indices,
        summary,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("serialization failed: {}", e)))
}

/// Merkle path info for a spendable note
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerklePathInfo {
    /// The merkle path siblings (32 hashes of 32 bytes each, hex)
    pub path: Vec<String>,
    /// Position in the tree
    pub position: u64,
}

/// Complete a transaction by patching in spend auth signatures from cold wallet.
///
/// Takes the unsigned v5 tx hex (with zero spend auth sigs for real spends) and an
/// array of hex-encoded 64-byte RedPallas signatures. Patches them into the correct
/// offsets in the orchard bundle.
///
/// # Arguments
/// * `unsigned_tx_hex` - hex-encoded v5 transaction bytes from build_unsigned_transaction
/// * `signatures_json` - JSON array of hex-encoded 64-byte signatures, one per spend_index
/// * `spend_indices_json` - JSON array of action indices that need signatures (from build result)
///
/// # Returns
/// Hex-encoded signed v5 transaction bytes ready for broadcast
#[wasm_bindgen]
pub fn complete_transaction(
    unsigned_tx_hex: &str,
    signatures_json: JsValue,
    spend_indices_json: JsValue,
) -> Result<String, JsError> {
    let signatures: Vec<String> = serde_wasm_bindgen::from_value(signatures_json)
        .map_err(|e| JsError::new(&format!("invalid signatures: {}", e)))?;

    let spend_indices: Vec<u32> = serde_wasm_bindgen::from_value(spend_indices_json)
        .map_err(|e| JsError::new(&format!("invalid spend_indices: {}", e)))?;

    if signatures.len() != spend_indices.len() {
        return Err(JsError::new(&format!(
            "signature count {} != spend_indices count {}",
            signatures.len(),
            spend_indices.len()
        )));
    }

    let mut tx_bytes =
        hex_decode(unsigned_tx_hex).ok_or_else(|| JsError::new("invalid unsigned tx hex"))?;

    // Parse the v5 transaction to find the orchard bundle offsets.
    // v5 layout:
    //   header: 20 bytes (version(4) + versionGroupId(4) + branchId(4) + nLockTime(4) + expiryHeight(4))
    //   transparent: compactSize(vin_count) + vin... + compactSize(vout_count) + vout...
    //   sapling: compactSize(spends) + compactSize(outputs)
    //   orchard: compactSize(nActions) + actions[] + flags(1) + valueBalance(8)
    //            + anchor(32) + compactSize(proof_len) + proof + spend_auth_sigs(64*n) + binding_sig(64)

    let mut pos = 20usize; // skip header

    // skip transparent vin
    let (vin_count, cs_len) = read_compact_size(&tx_bytes, pos)?;
    pos += cs_len;
    for _ in 0..vin_count {
        pos += 36; // prevout (txid + vout)
        let (script_len, cs_len) = read_compact_size(&tx_bytes, pos)?;
        pos += cs_len + script_len as usize + 4; // script + sequence
    }

    // skip transparent vout
    let (vout_count, cs_len) = read_compact_size(&tx_bytes, pos)?;
    pos += cs_len;
    for _ in 0..vout_count {
        pos += 8; // value
        let (script_len, cs_len) = read_compact_size(&tx_bytes, pos)?;
        pos += cs_len + script_len as usize;
    }

    // skip sapling spends + outputs (both should be 0)
    let (_, cs_len) = read_compact_size(&tx_bytes, pos)?;
    pos += cs_len;
    let (_, cs_len) = read_compact_size(&tx_bytes, pos)?;
    pos += cs_len;

    // parse orchard nActions
    let (n_actions, cs_len) = read_compact_size(&tx_bytes, pos)?;
    pos += cs_len;

    if n_actions == 0 {
        return Err(JsError::new("no orchard actions in transaction"));
    }

    // skip action data: each action is 820 bytes
    // cv(32) + nf(32) + rk(32) + cmx(32) + epk(32) + enc(580) + out(80) = 820
    let _actions_start = pos;
    pos += n_actions as usize * 820;

    // skip flags(1) + valueBalance(8) + anchor(32) = 41
    pos += 41;

    // skip proof (compactSize + bytes)
    let (proof_len, cs_len) = read_compact_size(&tx_bytes, pos)?;
    pos += cs_len + proof_len as usize;

    // now pos points to the start of spend auth signatures
    let spend_auth_sigs_start = pos;

    // Patch each signature at the correct offset
    for (sig_idx, &action_idx) in spend_indices.iter().enumerate() {
        if action_idx as u64 >= n_actions {
            return Err(JsError::new(&format!(
                "spend_index {} out of range (n_actions={})",
                action_idx, n_actions
            )));
        }

        let sig_hex = &signatures[sig_idx];
        let sig_bytes = hex_decode(sig_hex)
            .ok_or_else(|| JsError::new(&format!("invalid signature hex at index {}", sig_idx)))?;
        if sig_bytes.len() != 64 {
            return Err(JsError::new(&format!(
                "signature must be 64 bytes, got {} at index {}",
                sig_bytes.len(),
                sig_idx
            )));
        }

        let offset = spend_auth_sigs_start + (action_idx as usize) * 64;
        if offset + 64 > tx_bytes.len() {
            return Err(JsError::new("signature offset exceeds tx length"));
        }

        tx_bytes[offset..offset + 64].copy_from_slice(&sig_bytes);
    }

    Ok(hex_encode(&tx_bytes))
}

// ============================================================================
// Cold-signer PCZT redaction
// ============================================================================

/// Strip fields the cold signer doesn't need before serializing the PCZT.
///
/// Mirrors zashi's `redactPcztForSigner` and matters for Keystone-class
/// hardware whose RAM budget can't fit an un-redacted PCZT. Zigner is
/// memory-rich and tolerates either form, but emitting the redacted form
/// unconditionally keeps the QR payload smaller (fewer animated frames)
/// and exercises the same code path for both targets.
///
/// **What we keep** (signer needs every one of these):
/// - `alpha` — spend-auth randomizer; signing requires it.
/// - `fvk` — signer derives the spend authorizing key against this FVK.
/// - `value`, `recipient` — UI display on cold device must come from PCZT
///   contents (not a separate "summary" field) to bind display to sighash.
/// - `nullifier` — signer cross-checks against owned-notes set.
/// - `zkproof`, `bsk` — TransactionExtractor needs both downstream of signing.
/// - `output_value`, `output_recipient`, `cv_net`, `cmx`, `enc/out_ciphertext`
///   — needed for display + sighash recomputation.
///
/// **What we drop**:
/// - `spend_witness` — light-client artifact; the binding into the anchor
///   is locked in once IoFinalizer runs, so the witness is no longer load-bearing.
/// - `spend_zip32_derivation` — signer derives via its own seed; the hint
///   is just metadata.
/// - `spend_dummy_sk` — zashi convention; the signer never uses it because
///   IoFinalizer already attached the dummy spend's auth sig.
/// - all proprietary fields — zafu doesn't carry any; defensive clear so
///   future code can't silently leak metadata into the signing payload.
///
/// Extracted as a standalone helper (rather than inlined in `build_unsigned_pczt`)
/// so behavioral tests can exercise it without spinning up the full Halo 2
/// proving pipeline.
pub fn redact_pczt_for_signer(pczt: pczt::Pczt) -> pczt::Pczt {
    let redactor = pczt::roles::redactor::Redactor::new(pczt)
        .redact_global_with(|mut g| {
            g.clear_proprietary();
        })
        .redact_orchard_with(|mut o| {
            o.redact_actions(|mut a| {
                a.clear_spend_witness();
                a.clear_spend_zip32_derivation();
                a.clear_spend_dummy_sk();
                a.clear_spend_proprietary();
                // R3: the spent-note plaintext (rseed/rho/recipient/value) is
                // NOT needed by the Signer - the Prover already ran and
                // IoFinalizer already bound the sighash. Leaving these ships the
                // note contents to the signing device, so strip them. The
                // signer's `verify_nullifier(None)` tolerates each of these being
                // absent (it maps MissingRecipient/Value/Rho/RandomSeed to Ok).
                a.clear_spend_rseed();
                a.clear_spend_rho();
                a.clear_spend_recipient();
                a.clear_spend_value();
                // R3 viewing-key leak fix: the spend `fvk` is the wallet's
                // 96-byte orchard FullViewingKey - it links every note the
                // account can receive, so shipping it over the untrusted QR
                // transport is a viewing-key leak. Strip it. This is now safe
                // because the coordinated signer (zigner
                // feat/ironwood-v6-signer) reconstructs the fvk from the seed
                // it already holds and drives the pczt low-level Signer role,
                // supplying the reconstructed fvk to
                // `Spend::verify_nullifier(Some(fvk))`
                // (`fvk_for_validation` returns the caller-supplied fvk when the
                // PCZT's own `fvk` field is absent - librustzcash orchard
                // pczt/verify.rs). The actual `Action::sign` never reads the
                // fvk (only `alpha` + `rk`), so signatures still land.
                a.clear_spend_fvk();
                // Output-side (master's hardening): change-output derivation
                // path, bound user address, proprietary - local-wallet
                // metadata; the cold signer decodes recipients from the raw
                // `recipient` bytes, so display still works.
                a.clear_output_zip32_derivation();
                a.clear_output_user_address();
                a.clear_output_proprietary();
            });
        });
    // The ironwood bundle (NU6.3 / V6) is orchard-shaped; apply the identical
    // redaction. In a turnstile migration every ironwood spend is a dummy
    // whose auth sig IoFinalizer already attached, so the same clears apply.
    let redactor = redactor.redact_ironwood_with(|mut o| {
        o.redact_actions(|mut a| {
            a.clear_spend_witness();
            a.clear_spend_zip32_derivation();
            a.clear_spend_dummy_sk();
            a.clear_spend_proprietary();
            // R3: same note-plaintext leak as the orchard bundle. The ironwood
            // spends in a turnstile migration are all dummies, but strip
            // unconditionally so no plaintext ever reaches the signer. Same fvk
            // caveat as the orchard bundle above (kept for signability; full
            // strip is a FIX-B signer change).
            a.clear_spend_rseed();
            a.clear_spend_rho();
            a.clear_spend_recipient();
            a.clear_spend_value();
            // R3 viewing-key leak fix (same as the orchard bundle above): strip
            // the spend fvk. Safe now that the coordinated signer reconstructs
            // it from the seed and supplies it to `verify_nullifier(Some(fvk))`.
            a.clear_spend_fvk();
        });
    });
    let redactor = redactor.redact_transparent_with(|mut t| {
        t.redact_outputs(|mut o| {
            o.clear_user_address();
            o.clear_proprietary();
        });
    });
    redactor.finish()
}

/// Turnstile-only redaction: strip the address-linking output metadata from the
/// **orchard** bundle's DUMMY outputs, while leaving the **ironwood** bundle's
/// real output metadata intact so the cold device can confirm the destination.
///
/// # Why this is a separate step (and only run for turnstile migrations)
///
/// [`redact_pczt_for_signer`] deliberately KEEPS `output.recipient`/`value`
/// because in an ordinary orchard *send* the orchard output IS the real
/// recipient the signer must display and confirm. Blanket-clearing it there
/// would break send confirmation.
///
/// A turnstile migration is different. Its orchard bundle contains **no real
/// outputs at all**: the builder only calls `add_orchard_spend` (never
/// `add_orchard_output`), and at NU6.3 orchard cross-address transfers are
/// DISABLED, so the orchard builder (zcash/orchard qleak branch,
/// `builder.rs` `pad_and_shuffle` / `OutputInfo::fabricated_for_spend`) pairs
/// every requested spend with a *fabricated zero-value dummy output addressed
/// to the spent note's own receiver* — i.e. the wallet's own external
/// diversified orchard address. That 43-byte `output.recipient` (plus
/// `user_address`, and the dummy's `value`/`rseed`/`ock`/`zip32_derivation`)
/// survives [`redact_pczt_for_signer`] and links the wallet's address over the
/// untrusted QR transport — the leak FIX-A/R3 flagged.
///
/// The value migrated by a turnstile tx exits **entirely** through the ironwood
/// output(s) (`add_ironwood_output` to `fvk.address_at(0, Scope::Internal)`).
/// The orchard side is spend-only. Therefore **every** orchard-bundle output is
/// a dummy and can be cleared wholesale, while **every** ironwood-bundle output
/// is the real destination and is left untouched for device confirmation. This
/// is the "distinguish dummy vs real" rule, and it is structurally guaranteed by
/// how `build_turnstile_migration_pczt_core` constructs the tx (orchard spends +
/// ironwood outputs only) — see the assertion in `turnstile_v6.rs` that the
/// wallet's own external address is absent from the redacted bytes.
///
/// The dummy outputs are zero-value and their commitments (`cmx`) plus
/// ciphertexts remain, so the sighash the signer recomputes is unchanged; the
/// signer's `verify` path does not require `output.recipient`/`value`/`rseed`
/// (they map to `Ok` when absent, same as the spend-side clears).
pub fn redact_turnstile_dummy_outputs(pczt: pczt::Pczt) -> pczt::Pczt {
    pczt::roles::redactor::Redactor::new(pczt)
        .redact_orchard_with(|mut o| {
            o.redact_actions(|mut a| {
                // The wallet's own external address, raw-encoded (43 bytes) —
                // the actual leak.
                a.clear_output_recipient();
                // Human-readable form of the same address, set by an Updater.
                a.clear_output_user_address();
                // Dummy is zero-value, but clear defensively so no per-output
                // value hint reaches the signer.
                a.clear_output_value();
                // Seed randomness / out-cipher key / derivation hint for the
                // dummy note — all wallet-linking metadata the signer does not
                // need.
                a.clear_output_rseed();
                a.clear_output_ock();
                a.clear_output_zip32_derivation();
                a.clear_output_proprietary();
            });
        })
        .finish()
}

// ============================================================================
// PCZT (Partially Created Zcash Transaction) signing flow.
//
// Trust binding rationale:
// Zigner's PCZT signing path recomputes the ZIP-244 sighash from the PCZT
// contents itself (`v5_signature_hash` over `pczt_to_tx_data(global,
// transparent, sapling, orchard)`). The displayed action set, the verified
// nullifier match, and the signed bytes all derive from the same byte stream.
// A compromised hot wallet cannot decouple "what the user sees" from "what
// gets signed" the way the legacy `[sighash][alphas][summary]` simple format
// permits.
//
// Producer (this side): build a real `pczt::Pczt` via the canonical
//   zcash_primitives::transaction::builder::Builder::build_for_pczt
//   → Creator::build_from_parts
//   → Prover::create_orchard_proof
//   → IoFinalizer::finalize_io
//   → Pczt::serialize.
// Consumer (zigner): Pczt::parse → verification gates (anchor, known spend,
//   value consistency) → Signer::sign_orchard → serialize.
// Extractor (this side, after sign): Pczt::parse →
//   TransactionExtractor::with_orchard(vk).extract → broadcast-ready v5 tx.
// ============================================================================

/// Reconstruct owned orchard notes (V2, legacy pool) and their merkle paths
/// from raw scan fields, verifying each note's cmx commitment. Verifying cmx
/// defends against a caller passing `value`/`rho` that don't actually commit
/// to the note they're claiming. Shared by the PCZT send producer and the
/// turnstile migration producer.
fn prepare_orchard_spends(
    fvk: &orchard::keys::FullViewingKey,
    notes: &[SpendableNote],
    merkle_paths: &[MerklePathInfo],
) -> Result<Vec<(orchard::Note, orchard::tree::MerklePath)>, JsError> {
    use orchard::note::{RandomSeed, Rho};
    use orchard::tree::{MerkleHashOrchard, MerklePath as OrchardMerklePath};
    use orchard::value::NoteValue;

    if notes.len() != merkle_paths.len() {
        return Err(JsError::new("notes and merkle paths count mismatch"));
    }

    let mut prepared: Vec<(orchard::Note, OrchardMerklePath)> = Vec::with_capacity(notes.len());
    for (i, n) in notes.iter().enumerate() {
        let rho = {
            let b = hex_decode(&n.rho_hex)
                .ok_or_else(|| JsError::new(&format!("invalid rho hex for note {}", i)))?;
            if b.len() != 32 {
                return Err(JsError::new(&format!(
                    "rho must be 32 bytes for note {}",
                    i
                )));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Option::from(Rho::from_bytes(&a))
                .ok_or_else(|| JsError::new(&format!("invalid rho for note {}", i)))?
        };
        let rseed = {
            let b = hex_decode(&n.rseed_hex)
                .ok_or_else(|| JsError::new(&format!("invalid rseed hex for note {}", i)))?;
            if b.len() != 32 {
                return Err(JsError::new(&format!(
                    "rseed must be 32 bytes for note {}",
                    i
                )));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Option::from(RandomSeed::from_bytes(a, &rho))
                .ok_or_else(|| JsError::new(&format!("invalid rseed for note {}", i)))?
        };
        let value = NoteValue::from_raw(n.value);
        let note: orchard::Note = if !n.recipient_hex.is_empty() {
            let b = hex_decode(&n.recipient_hex)
                .ok_or_else(|| JsError::new(&format!("invalid recipient hex for note {}", i)))?;
            let arr: [u8; 43] = b
                .try_into()
                .map_err(|_| JsError::new(&format!("recipient must be 43 bytes for note {}", i)))?;
            let addr = Option::from(orchard::Address::from_raw_address_bytes(&arr))
                .ok_or_else(|| JsError::new(&format!("invalid orchard address for note {}", i)))?;
            Option::from(orchard::Note::from_parts(
                addr,
                value,
                rho,
                rseed,
                orchard::note::NoteVersion::V2,
            ))
            .ok_or_else(|| JsError::new(&format!("note {} reconstruction failed", i)))?
        } else {
            let ext = fvk.to_ivk(Scope::External).address_at(0u64);
            let int = fvk.to_ivk(Scope::Internal).address_at(0u64);
            Option::from(orchard::Note::from_parts(
                ext,
                value,
                rho,
                rseed,
                orchard::note::NoteVersion::V2,
            ))
            .or_else(|| {
                Option::from(orchard::Note::from_parts(
                    int,
                    value,
                    rho,
                    rseed,
                    orchard::note::NoteVersion::V2,
                ))
            })
            .ok_or_else(|| {
                JsError::new(&format!(
                    "note {} reconstruction failed (rseed/rho/value)",
                    i
                ))
            })?
        };
        // Pool / note-version guard (defense-in-depth): the orchard spend path
        // is ONLY for legacy V2 orchard notes. A V3 (ironwood) note must never
        // enter here - spending an ironwood note as if it were orchard would
        // bind the wrong pool. Reconstruction above forces V2, so a mismatch
        // means the caller handed us note components that don't belong; reject
        // explicitly rather than relying on the cmx check to catch it.
        if note.version() != orchard::note::NoteVersion::V2 {
            return Err(JsError::new(&format!(
                "note {} is not a V2 orchard note (got {:?}); the orchard spend \
                 path rejects ironwood/V3 inputs",
                i,
                note.version()
            )));
        }

        let expected = hex_decode(&n.cmx)
            .ok_or_else(|| JsError::new(&format!("invalid cmx hex for note {}", i)))?;
        let computed = orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes();
        if computed[..] != expected[..] {
            return Err(JsError::new(&format!(
                "cmx mismatch for note {}: computed={} expected={}",
                i,
                hex_encode(&computed),
                hex_encode(&expected)
            )));
        }

        let mp = &merkle_paths[i];
        if mp.path.len() != 32 {
            return Err(JsError::new(&format!(
                "merkle path must have 32 elements, got {} for note {}",
                mp.path.len(),
                i
            )));
        }
        let mut hashes = [MerkleHashOrchard::from_bytes(&[0u8; 32]).unwrap(); 32];
        for (j, h_hex) in mp.path.iter().enumerate() {
            let b = hex_decode(h_hex)
                .ok_or_else(|| JsError::new(&format!("invalid merkle hash {}/{}", i, j)))?;
            if b.len() != 32 {
                return Err(JsError::new(&format!(
                    "merkle hash must be 32 bytes at {}/{}",
                    i, j
                )));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            hashes[j] = Option::from(MerkleHashOrchard::from_bytes(&a))
                .ok_or_else(|| JsError::new(&format!("invalid merkle hash at {}/{}", i, j)))?;
        }
        let merkle_path = OrchardMerklePath::from_parts(
            u32::try_from(mp.position)
                .map_err(|_| JsError::new(&format!("position {} exceeds u32 max", mp.position)))?,
            hashes,
        );
        prepared.push((note, merkle_path));
    }
    Ok(prepared)
}

/// Build a PCZT for cold-wallet signing via QR.
///
/// `target_height` selects the consensus branch; pass any height ≥ NU6.1
/// activation for current mainnet operations. The tx version is derived from
/// network upgrade rules (currently V5).
///
/// Returns JSON: `{ pczt_hex, summary, action_count }`.
/// The TS layer wraps `pczt_hex` in CBOR `{1: bytes}` and UR-encodes as
/// `zcash-pczt` for animated QR transport.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)] // mirrors the PCZT creator-role parameter surface
pub fn build_unsigned_pczt(
    ufvk_str: &str,
    notes_json: JsValue,
    recipient: &str,
    amount: u64,
    fee: u64,
    anchor_hex: &str,
    merkle_paths_json: JsValue,
    target_height: u32,
    mainnet: bool,
    memo_hex: Option<String>,
) -> Result<JsValue, JsError> {
    use ::zcash_transparent as transparent;
    use orchard::tree::Anchor;
    use rand::rngs::OsRng;
    use zcash_keys::encoding::AddressCodec;
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
    use zcash_primitives::transaction::fees::fixed::FeeRule as FixedFeeRule;
    use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork, TestNetwork};
    use zcash_protocol::memo::MemoBytes;
    use zcash_protocol::value::Zatoshis;

    // ── FAIL-CLOSED: orchard-V5 output creation is consensus-dead at NU6.3 ──
    // This builder always emits at least one orchard output (the recipient for
    // a z→z send, and/or the change note), and post-NU6.3 the orchard pool is
    // spend/migrate-only: creating any new orchard output makes the bundle's
    // value balance negative, which the node rejects ("Orchard value balance
    // must be non-negative from NU6.3 onward"). Refuse before proving rather
    // than mint an un-broadcastable PCZT. Unlike the hot builder this path
    // takes no live branch id, so derive it from `target_height` (the same
    // BranchId::for_height mapping the builder itself uses below).
    {
        let branch_id: u32 = if mainnet {
            BranchId::for_height(&MainNetwork, BlockHeight::from(target_height))
        } else {
            BranchId::for_height(&TestNetwork, BlockHeight::from(target_height))
        }
        .into();
        if branch_id == NU6_3_BRANCH_ID {
            return Err(JsError::new(
                "orchard-V5 output creation is consensus-dead post-NU6.3 (the \
                 orchard pool is spend/migrate-only; no new orchard outputs) - \
                 use the ironwood builder (build_ironwood_send_pczt); orchard \
                 funds must first cross the one-way turnstile \
                 (build_signed_turnstile_migration)",
            ));
        }
    }

    // ── decode FVK from UFVK ───────────────────────────────────────────────
    // zcash_keys 5333c01b uses the same orchard 0.12 we do, so no byte
    // round-trip is needed any more.
    let fvk = {
        let ufvk = if mainnet {
            UnifiedFullViewingKey::decode(&MainNetwork, ufvk_str)
        } else {
            UnifiedFullViewingKey::decode(&TestNetwork, ufvk_str)
        }
        .map_err(|e| JsError::new(&format!("invalid UFVK: {}", e)))?;
        ufvk.orchard()
            .ok_or_else(|| JsError::new("UFVK has no orchard component"))?
            .clone()
    };
    let change_addr = fvk.to_ivk(Scope::Internal).address_at(0u64);
    // OVK-encrypt outputs so the group FVK can recover them: the FROST joiner
    // OVK-decodes the bundle to verify (recipient, amount) before signing (gh #17),
    // and the sender keeps its own send history. `None` here (the old zigner
    // cold-sign default) left outputs unrecoverable → joiner derived 0 recipients.
    let ovk_external = fvk.to_ovk(Scope::External);
    let ovk_internal = fvk.to_ovk(Scope::Internal);

    // ── recipient parse ────────────────────────────────────────────────────
    let is_transparent = recipient.starts_with("t1") || recipient.starts_with("tm");
    let orchard_recipient = if is_transparent {
        None
    } else {
        Some(
            parse_orchard_address(recipient, mainnet)
                .map_err(|e| JsError::new(&format!("invalid recipient: {}", e)))?,
        )
    };

    // ── anchor ─────────────────────────────────────────────────────────────
    let anchor_bytes = hex_decode(anchor_hex).ok_or_else(|| JsError::new("invalid anchor hex"))?;
    if anchor_bytes.len() != 32 {
        return Err(JsError::new("anchor must be 32 bytes"));
    }
    let mut anchor_arr = [0u8; 32];
    anchor_arr.copy_from_slice(&anchor_bytes);
    let orchard_anchor = Option::from(Anchor::from_bytes(anchor_arr))
        .ok_or_else(|| JsError::new("invalid anchor"))?;

    // ── notes + paths ──────────────────────────────────────────────────────
    let notes: Vec<SpendableNote> = serde_wasm_bindgen::from_value(notes_json)
        .map_err(|e| JsError::new(&format!("invalid notes: {}", e)))?;
    let merkle_paths: Vec<MerklePathInfo> = serde_wasm_bindgen::from_value(merkle_paths_json)
        .map_err(|e| JsError::new(&format!("invalid merkle paths: {}", e)))?;
    if notes.len() != merkle_paths.len() {
        return Err(JsError::new("notes and merkle paths count mismatch"));
    }

    // ── balance check (also enforced by the builder, but earlier here) ─────
    let total_input: u64 = notes.iter().map(|n| n.value).sum();
    if total_input < amount + fee {
        return Err(JsError::new(&format!(
            "insufficient funds: {} < {} + {}",
            total_input, amount, fee
        )));
    }
    let change = total_input - amount - fee;
    let num_spends = notes.len();

    // ── memo (recipient only — change uses empty per zcash convention) ─────
    let memo_arr = decode_memo_hex(memo_hex.as_deref())?;
    let recipient_memo =
        MemoBytes::from_bytes(&memo_arr).map_err(|e| JsError::new(&format!("memo: {:?}", e)))?;

    // ── reconstruct each owned note from raw fields, verify cmx ────────────
    // Same logic as build_unsigned_transaction. Verifying cmx defends against
    // a caller passing `value`/`rho` that don't actually commit to the note
    // they're claiming.
    let prepared = prepare_orchard_spends(&fvk, &notes, &merkle_paths)?;

    // ── drive zcash_primitives Builder, branched on network ────────────────
    // Builder<P, ()> is monomorphic in P; we build_for_pczt inside each branch
    // and unify on the network-erased PcztParts via Creator. A macro avoids
    // duplicating ~30 lines.
    let build_config = BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: Some(orchard_anchor),
        ironwood_anchor: None,
        orchard_padding: BundlePadding::DEFAULT,
        ironwood_padding: BundlePadding::DEFAULT,
    };
    let fee_amount = Zatoshis::from_u64(fee).map_err(|_| JsError::new("invalid fee amount"))?;
    let amount_zat = Zatoshis::from_u64(amount).map_err(|_| JsError::new("invalid send amount"))?;
    let fee_rule = FixedFeeRule::non_standard(fee_amount);
    let target = BlockHeight::from(target_height);

    // The proving key must match the circuit the Builder selects for the
    // consensus branch at `target` (historical circuit before NU6.2, fixed
    // circuit from NU6.2, post-NU6.3 circuit from NU6.3).
    let orchard_circuit = {
        use zcash_protocol::consensus::BranchId;
        let branch = if mainnet {
            BranchId::for_height(&MainNetwork, target)
        } else {
            BranchId::for_height(&TestNetwork, target)
        };
        orchard_protocol_for_branch(branch).circuit_version()
    };

    macro_rules! build_pczt_for {
        ($params:expr) => {{
            let params = $params;
            let mut builder = Builder::new(params, target, build_config);
            for (note, mp) in &prepared {
                builder
                    .add_orchard_spend::<<FixedFeeRule as zcash_primitives::transaction::fees::FeeRule>::Error>(
                        fvk.clone(),
                        note.clone(),
                        mp.clone(),
                    )
                    .map_err(|e| JsError::new(&format!("add_orchard_spend: {:?}", e)))?;
            }
            if let Some(addr) = orchard_recipient {
                builder
                    .add_orchard_output::<<FixedFeeRule as zcash_primitives::transaction::fees::FeeRule>::Error>(
                        Some(ovk_external.clone()),
                        addr,
                        amount_zat,
                        recipient_memo.clone(),
                    )
                    .map_err(|e| JsError::new(&format!("add_orchard_output: {:?}", e)))?;
            }
            if change > 0 {
                let change_zat = Zatoshis::from_u64(change)
                    .map_err(|_| JsError::new("invalid change amount"))?;
                builder
                    .add_orchard_output::<<FixedFeeRule as zcash_primitives::transaction::fees::FeeRule>::Error>(
                        Some(ovk_internal.clone()),
                        change_addr,
                        change_zat,
                        MemoBytes::empty(),
                    )
                    .map_err(|e| JsError::new(&format!("add_orchard_output (change): {:?}", e)))?;
            }
            if is_transparent {
                let t_addr = transparent::address::TransparentAddress::decode(&params, recipient)
                    .map_err(|e| JsError::new(&format!("invalid transparent address: {:?}", e)))?;
                builder
                    .add_transparent_output(&t_addr, amount_zat)
                    .map_err(|e| JsError::new(&format!("add_transparent_output: {:?}", e)))?;
            }
            builder
                .build_for_pczt(OsRng, &fee_rule)
                .map_err(|e| JsError::new(&format!("build_for_pczt: {:?}", e)))?
                .pczt_parts
        }};
    }

    // Capture FROST signing data from the orchard parts BEFORE Creator consumes
    // them. `into_pczt` sets `alpha` + `dummy_sk` at build_for_pczt time, so real
    // spends (dummy_sk == None) carry their rerandomizer here. The pczt::Pczt that
    // Creator produces keeps these pub(crate), so this is the only public read.
    // Order = action order = the order host + joiner run the FROST rounds in.
    use group::ff::PrimeField;
    let extract_frost =
        |orchard: &Option<orchard::pczt::Bundle>| -> Result<(Vec<String>, Vec<u32>), JsError> {
            let mut alphas = Vec::new();
            let mut spend_indices = Vec::new();
            if let Some(b) = orchard.as_ref() {
                for (i, action) in b.actions().iter().enumerate() {
                    if action.spend().dummy_sk().is_none() {
                        let alpha = action.spend().alpha().ok_or_else(|| {
                            JsError::new(&format!("missing alpha for real spend action {}", i))
                        })?;
                        alphas.push(hex_encode(&alpha.to_repr()));
                        spend_indices.push(i as u32);
                    }
                }
            }
            Ok((alphas, spend_indices))
        };

    let (pczt, alphas, spend_indices) = if mainnet {
        let parts = build_pczt_for!(MainNetwork);
        let (alphas, spend_indices) = extract_frost(&parts.orchard)?;
        let pczt = pczt::roles::creator::Creator::build_from_parts(parts)
            .ok_or_else(|| JsError::new("Creator::build_from_parts: incompatible tx version"))?;
        (pczt, alphas, spend_indices)
    } else {
        let parts = build_pczt_for!(TestNetwork);
        let (alphas, spend_indices) = extract_frost(&parts.orchard)?;
        let pczt = pczt::roles::creator::Creator::build_from_parts(parts)
            .ok_or_else(|| JsError::new("Creator::build_from_parts: incompatible tx version"))?;
        (pczt, alphas, spend_indices)
    };

    // ── orchard Halo 2 proof (expensive — seconds on a phone CPU) ──────────
    let pczt = with_proving_key_for(orchard_circuit, |pk| {
        pczt::roles::prover::Prover::new(pczt)
            .create_orchard_proof(pk)
            .map(|p| p.finish())
    })
    .map_err(|e| JsError::new(&format!("create_orchard_proof: {:?}", e)))?;

    // ── finalize IO (canonical sighash → bsk + dummy spend auth sigs) ──────
    // After this step the orchard bundle is bound to a sighash that zigner
    // recomputes identically when it parses the PCZT.
    let pczt = pczt::roles::io_finalizer::IoFinalizer::new(pczt)
        .finalize_io()
        .map_err(|e| JsError::new(&format!("io_finalize: {:?}", e)))?;

    // ── redact for cold signer ────────────────────────────────────────────
    let pczt = redact_pczt_for_signer(pczt);

    let action_count = pczt.orchard().actions().len() as u32;
    let pczt_bytes = pczt
        .serialize()
        .map_err(|e| JsError::new(&format!("pczt serialize: {e:?}")))?;

    // ── canonical sighash for FROST signing ───────────────────────────────
    // Derive it from the serialized (redacted) PCZT — exactly the bytes the
    // joiner gets — so host + joiner sign the same message the joiner verified.
    let sighash = {
        let reparsed = pczt::Pczt::parse(&pczt_bytes)
            .map_err(|e| JsError::new(&format!("reparse pczt for sighash: {:?}", e)))?;
        pczt::roles::signer::Signer::new(reparsed)
            .map_err(|e| JsError::new(&format!("signer init: {:?}", e)))?
            .shielded_sighash()
    };

    let recipient_short = if recipient.len() > 20 {
        &recipient[..20]
    } else {
        recipient
    };
    let summary = format!(
        "Send {:.8} ZEC to {}\nFee: {:.8} ZEC\nSpending {} note(s)",
        amount as f64 / 100_000_000.0,
        recipient_short,
        fee as f64 / 100_000_000.0,
        num_spends
    );

    // `sighash`/`alphas`/`spend_indices` are additive: the zigner cold-sign
    // caller ignores them; the FROST host (mnemonic/escrow) needs them to drive
    // round1/round2 per real-spend action. See gh #17.
    #[derive(Serialize)]
    struct Out {
        pczt_hex: String,
        summary: String,
        action_count: u32,
        sighash: String,
        alphas: Vec<String>,
        spend_indices: Vec<u32>,
    }
    serde_wasm_bindgen::to_value(&Out {
        pczt_hex: hex_encode(&pczt_bytes),
        summary,
        action_count,
        sighash: hex_encode(&sighash),
        alphas,
        spend_indices,
    })
    .map_err(|e| JsError::new(&format!("serialization failed: {}", e)))
}

/// Cached Halo 2 verifying keys, one per circuit version (mirrors the
/// proving key cache above). Building a VK is cheap relative to proving but
/// worth amortizing across extract calls.
static VERIFYING_KEY_PRE_NU6_2: std::sync::OnceLock<orchard::circuit::VerifyingKey> =
    std::sync::OnceLock::new();
static VERIFYING_KEY_POST_NU6_2: std::sync::OnceLock<orchard::circuit::VerifyingKey> =
    std::sync::OnceLock::new();
static VERIFYING_KEY_POST_NU6_3: std::sync::OnceLock<orchard::circuit::VerifyingKey> =
    std::sync::OnceLock::new();

fn verifying_key_for(
    cv: orchard::circuit::OrchardCircuitVersion,
) -> &'static orchard::circuit::VerifyingKey {
    use orchard::circuit::OrchardCircuitVersion as Cv;
    let cell = match cv {
        Cv::InsecurePreNu6_2 => &VERIFYING_KEY_PRE_NU6_2,
        Cv::FixedPostNu6_2 => &VERIFYING_KEY_POST_NU6_2,
        Cv::PostNu6_3 => &VERIFYING_KEY_POST_NU6_3,
    };
    cell.get_or_init(|| orchard::circuit::VerifyingKey::build(cv))
}

/// Extract a broadcast-ready v5/v6 transaction from a signed PCZT.
///
/// This is the testable inner core: takes raw bytes, returns raw bytes, and
/// uses `String` for errors so it's callable from regular cargo tests
/// without dragging in `JsError`. The `#[wasm_bindgen]` wrapper below just
/// adds hex marshaling and JS error mapping.
///
/// Accepts both V5 (orchard) and, when built with the NU6.3 cfg, V6
/// (orchard + ironwood) PCZTs. The orchard verifying key is selected from
/// the PCZT's own tx version + consensus branch so that proofs made with
/// the historical circuit (pre-NU6.2 branches) still verify.
pub fn extract_signed_tx_from_pczt_bytes(pczt_bytes: &[u8]) -> Result<Vec<u8>, String> {
    use orchard::circuit::OrchardCircuitVersion;
    use zcash_protocol::consensus::BranchId;

    let pczt = pczt::Pczt::parse(pczt_bytes).map_err(|e| format!("pczt parse failed: {:?}", e))?;

    let branch = BranchId::try_from(*pczt.global().consensus_branch_id())
        .map_err(|e| format!("unknown consensus branch in pczt: {:?}", e))?;

    let is_v6 = *pczt.global().tx_version() == zcash_protocol::constants::V6_TX_VERSION;

    // Circuit selection mirrors upstream's rules: V6 orchard bundles use the
    // post-NU6.3 circuit; V5 bundles use the circuit for their branch.
    let orchard_cv = if is_v6 {
        OrchardCircuitVersion::PostNu6_3
    } else {
        orchard_protocol_for_branch(branch).circuit_version()
    };
    let _ = branch; // (used only for V5 circuit selection)

    let vk = verifying_key_for(orchard_cv);

    let extractor = pczt::roles::tx_extractor::TransactionExtractor::new(pczt).with_orchard(vk);

    let tx = extractor
        .extract()
        .map_err(|e| format!("tx extract failed: {:?}", e))?;

    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes)
        .map_err(|e| format!("tx serialize failed: {}", e))?;
    Ok(tx_bytes)
}

/// Extract a broadcast-ready v5 transaction from a signed PCZT returned by zigner.
///
/// Replaces the legacy `parse_signature_response` + `complete_transaction` pair.
/// Instead of patching raw signature bytes into a hand-serialized tx, we let the
/// pczt crate's `TransactionExtractor` reassemble the canonical v5 transaction
/// from the signed PCZT (collecting all auth sigs and validating the proof).
///
/// Returns hex-encoded transaction bytes ready for broadcast.
#[wasm_bindgen]
pub fn extract_signed_tx_from_pczt(pczt_hex: &str) -> Result<String, JsError> {
    let bytes = hex_decode(pczt_hex).ok_or_else(|| JsError::new("invalid pczt hex"))?;
    let tx_bytes = extract_signed_tx_from_pczt_bytes(&bytes).map_err(|e| JsError::new(&e))?;
    Ok(hex_encode(&tx_bytes))
}

// ============================================================================
// Turnstile migration (orchard -> ironwood, NU6.3 / V6)
// ============================================================================

/// Device-confirmation summary of a produced PCZT, recomputed from the
/// redacted PCZT bytes themselves (never from builder-side bookkeeping) so
/// what the consumer displays is bound to what gets signed.
///
/// Field-compatible with zigner's `pczt_signing::PcztSummary` so both ends
/// of the QR channel render the same shape. `outputs` entries are
/// `[label, zatoshis]` pairs where label is one of:
///   `t-script:<hex>`, `orchard:<43-byte-hex>`, `orchard:shielded`,
///   `ironwood:<43-byte-hex>`, `ironwood:shielded`.
#[derive(Debug, Clone, Serialize)]
pub struct PcztSummary {
    /// Number of orchard actions (spend side signable by the cold signer).
    pub orchard_actions: u32,
    /// Number of ironwood actions (NU6.3 / V6 pool). Always 0 when the
    /// artifact was built without the nu6.3 cfg.
    pub ironwood_actions: u32,
    /// Number of transparent inputs.
    pub transparent_inputs: u32,
    /// Visible outputs: (label, zatoshis). Serializes as [[label, value], ...].
    pub outputs: Vec<(String, u64)>,
    /// Declared fee in zatoshi when the producer knows it.
    pub fee_zat: Option<u64>,
}

/// Recompute a `PcztSummary` from a (redacted) PCZT. Mirrors zigner's
/// `summarize` extraction logic exactly - keep in sync.
// only the nu6.3-gated turnstile producers call this; without the cfg it is
// intentionally unused
fn summarize_pczt(pczt: &pczt::Pczt, fee_zat: Option<u64>) -> PcztSummary {
    let mut outputs: Vec<(String, u64)> = Vec::new();
    for out in pczt.transparent().outputs() {
        outputs.push((
            format!("t-script:{}", hex_encode(out.script_pubkey())),
            *out.value(),
        ));
    }
    for action in pczt.orchard().actions() {
        let out = action.output();
        let label = match out.recipient() {
            Some(r) => format!("orchard:{}", hex_encode(r)),
            None => "orchard:shielded".to_string(),
        };
        outputs.push((label, out.value().unwrap_or(0)));
    }
    let ironwood_actions = {
        for action in pczt.ironwood().actions() {
            let out = action.output();
            let label = match out.recipient() {
                Some(r) => format!("ironwood:{}", hex_encode(r)),
                None => "ironwood:shielded".to_string(),
            };
            outputs.push((label, out.value().unwrap_or(0)));
        }
        pczt.ironwood().actions().len() as u32
    };

    PcztSummary {
        orchard_actions: pczt.orchard().actions().len() as u32,
        ironwood_actions,
        transparent_inputs: pczt.transparent().inputs().len() as u32,
        outputs,
        fee_zat,
    }
}

/// Consensus parameters wrapper that reports NU6.3 as active from a given
/// height. The vendored librustzcash now carries the real NU6.3 activation
/// height (Main 3_428_143) and consensus branch id (0x37a5165b), so on
/// mainnet this wrapper is a no-op - the real height wins in the `.or()`
/// below. It remains only so tests / non-mainnet callers can declare NU6.3
/// active at an arbitrary `target_height`; the fail-closed guard in
/// `build_turnstile_migration_pczt_core` still refuses unless the bound
/// branch id equals the caller-supplied expected_branch_id.
#[derive(Clone, Copy, Debug)]
struct Nu63Activated<P> {
    inner: P,
    nu6_3_from: zcash_protocol::consensus::BlockHeight,
}

impl<P: zcash_protocol::consensus::Parameters> zcash_protocol::consensus::Parameters
    for Nu63Activated<P>
{
    fn network_type(&self) -> zcash_protocol::consensus::NetworkType {
        self.inner.network_type()
    }

    fn activation_height(
        &self,
        nu: zcash_protocol::consensus::NetworkUpgrade,
    ) -> Option<zcash_protocol::consensus::BlockHeight> {
        match nu {
            zcash_protocol::consensus::NetworkUpgrade::Nu6_3 => {
                // Respect a real upstream activation height once one exists.
                self.inner.activation_height(nu).or(Some(self.nu6_3_from))
            }
            _ => self.inner.activation_height(nu),
        }
    }
}

/// Result of building a turnstile migration PCZT (testable core output).
pub struct TurnstileBuild {
    /// Redacted-for-signer PCZT bytes (same redaction contract as
    /// `build_unsigned_pczt`).
    pub pczt_bytes: Vec<u8>,
    /// Confirmation summary recomputed from the redacted bytes.
    pub summary: PcztSummary,
    /// Total actions across the orchard and ironwood bundles.
    pub action_count: u32,
}

/// Build AND prove the turnstile migration PCZT, returning the *unredacted*
/// proven `pczt::Pczt` together with the declared `fee` and `migrated` value.
///
/// This is the shared money-path core for BOTH the cold flow
/// (`build_turnstile_migration_pczt_core`, which redacts this output for the
/// external signer) and the hot flow (`build_signed_turnstile_migration_core`,
/// which local-signs this output instead). It runs Creator -> IoFinalizer ->
/// Prover (orchard + ironwood proofs, both post-NU6.3 circuit). It does NOT
/// redact and does NOT sign the real orchard spends: after IoFinalizer every
/// DUMMY spend (all of the output-only ironwood bundle, plus any orchard
/// padding) is already spend-auth signed against the shared shielded sighash
/// and every bundle's `bsk` is stored; only the wallet-owned orchard spends
/// remain unsigned.
///
/// The FAIL-CLOSED branch-id guard lives here so neither flow can bind the
/// 0xffff_ffff placeholder or a branch other than the one the wallet believes
/// is active.
#[allow(clippy::too_many_arguments)]
pub fn build_turnstile_migration_pczt_proven<P>(
    params: P,
    fvk: &orchard::keys::FullViewingKey,
    prepared: Vec<(orchard::Note, orchard::tree::MerklePath)>,
    fee: u64,
    orchard_anchor: orchard::tree::Anchor,
    target_height: u32,
    expected_branch_id: u32,
    memo: zcash_protocol::memo::MemoBytes,
) -> Result<(pczt::Pczt, u64), String>
where
    P: zcash_protocol::consensus::Parameters,
{
    use orchard::circuit::OrchardCircuitVersion;
    use rand::rngs::OsRng;
    use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
    use zcash_primitives::transaction::fees::fixed::FeeRule as FixedFeeRule;
    use zcash_primitives::transaction::TxVersion;
    use zcash_protocol::consensus::{BlockHeight, BranchId};
    use zcash_protocol::value::Zatoshis;

    type FeError = <FixedFeeRule as zcash_primitives::transaction::fees::FeeRule>::Error;

    // FAIL-CLOSED branch-id guard (money path). The turnstile sighash binds the
    // consensus branch id selected by the network params at `target_height`.
    // The wallet reads the *real* active branch id from GetLightdInfo and passes
    // it here as `expected_branch_id`. We REFUSE to build unless the branch id
    // we would actually bind matches it, AND we refuse the placeholder value
    // outright. This makes it impossible to ever produce a tx that binds the
    // 0xffff_ffff placeholder (which would be invalid/unspendable on-chain) or
    // a branch other than the one the wallet believes is active.
    const NU6_3_PLACEHOLDER_BRANCH_ID: u32 = 0xffff_ffff;
    if expected_branch_id == NU6_3_PLACEHOLDER_BRANCH_ID {
        return Err(format!(
            "refusing to build turnstile migration: expected_branch_id is the \
             NU6.3 placeholder {:#010x}; the wallet must pass the real consensus \
             branch id read from GetLightdInfo",
            NU6_3_PLACEHOLDER_BRANCH_ID
        ));
    }
    let bound_branch_id: u32 =
        BranchId::for_height(&params, BlockHeight::from(target_height)).into();
    if bound_branch_id == NU6_3_PLACEHOLDER_BRANCH_ID {
        return Err(format!(
            "refusing to build turnstile migration: the network params would bind \
             the NU6.3 placeholder branch id {:#010x} at height {} - the \
             librustzcash fork has not been patched with the real NU6.3 branch id",
            NU6_3_PLACEHOLDER_BRANCH_ID, target_height
        ));
    }
    if bound_branch_id != expected_branch_id {
        return Err(format!(
            "refusing to build turnstile migration: branch id that would bind at \
             height {} is {:#010x} but the wallet expected {:#010x} (NU6.3 not \
             active at this height, or a branch-id mismatch)",
            target_height, bound_branch_id, expected_branch_id
        ));
    }

    if prepared.is_empty() {
        return Err("turnstile migration requires at least one orchard note".into());
    }
    let total_input: u64 = prepared.iter().map(|(n, _)| n.value().inner()).sum();
    if total_input <= fee {
        return Err(format!(
            "insufficient funds: inputs {} do not cover fee {}",
            total_input, fee
        ));
    }
    let migrated = total_input - fee;

    // Self-migration destination: the wallet's own address in the ironwood
    // pool. Internal scope (the change/shielding scope) so the funds read as
    // an internal movement, exactly like the zigner spike models it. The
    // internal OVK preserves outgoing visibility for the wallet itself.
    let recipient = fvk.address_at(0u32, Scope::Internal);
    let internal_ovk = Some(fvk.to_ovk(Scope::Internal));

    // Migration spends orchard and only OUTPUTS ironwood, so no real ironwood
    // anchor is involved - but the pinned rev only creates the ironwood
    // bundle builder when `ironwood_anchor` is Some (BuildConfig::
    // ironwood_builder returns None otherwise). The empty-tree anchor is the
    // output-only convention the zigner valar spike producer uses; it only
    // ever anchors dummy spends. (Deviation from contract section 1's
    // literal "ironwood_anchor: None" - flagged.)
    let mut builder = Builder::new(
        params,
        BlockHeight::from(target_height),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard_anchor),
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .propose_version::<FeError>(TxVersion::V6)
        .map_err(|e| format!("propose_version(V6): {:?}", e))?;
    for (note, mp) in &prepared {
        builder
            .add_orchard_spend::<FeError>(fvk.clone(), *note, mp.clone())
            .map_err(|e| format!("add_orchard_spend: {:?}", e))?;
    }
    let migrated_zat =
        Zatoshis::from_u64(migrated).map_err(|_| "invalid migrated amount".to_string())?;
    builder
        .add_ironwood_output::<FeError>(internal_ovk, recipient, migrated_zat, memo)
        .map_err(|e| format!("add_ironwood_output: {:?}", e))?;

    let fee_zat = Zatoshis::from_u64(fee).map_err(|_| "invalid fee amount".to_string())?;
    let fee_rule = FixedFeeRule::non_standard(fee_zat);
    let parts = builder
        .build_for_pczt(OsRng, &fee_rule)
        .map_err(|e| format!("build_for_pczt: {:?}", e))?
        .pczt_parts;

    let pczt = pczt::roles::creator::Creator::build_from_parts(parts)
        .ok_or_else(|| "Creator::build_from_parts: incompatible tx version".to_string())?;

    // Canonical role order for the turnstile (contract section 1):
    // IoFinalizer binds the sighash, then the Prover attaches both proofs.
    let pczt = pczt::roles::io_finalizer::IoFinalizer::new(pczt)
        .finalize_io()
        .map_err(|e| format!("finalize_io: {:?}", e))?;

    // Both bundles of a V6 tx prove against the post-NU6.3 circuit.
    let pczt = with_proving_key_for(OrchardCircuitVersion::PostNu6_3, |pk| {
        pczt::roles::prover::Prover::new(pczt)
            .create_orchard_proof(pk)
            .map_err(|e| format!("create_orchard_proof: {e:?}"))
            .and_then(|p| {
                p.create_ironwood_proof(pk)
                    .map_err(|e| format!("create_ironwood_proof: {e:?}"))
            })
            .map(|p| p.finish())
    })
    .map_err(|e| format!("create proofs: {:?}", e))?;

    Ok((pczt, migrated))
}

/// Core of the COLD turnstile migration builder, generic over consensus params
/// so native tests can drive it with a regtest-style network. Builds a single
/// `TxVersion::V6` transaction that spends the supplied orchard notes and
/// outputs their full value minus `fee` to the wallet's OWN ironwood-pool
/// address (internal scope, diversifier 0 - mirroring the zigner valar spike
/// producer). Roles: Creator -> IoFinalizer -> Prover (orchard + ironwood
/// proofs, both post-NU6.3 circuit) -> redact. The real orchard spends are
/// left UNSIGNED for the external cold signer.
#[allow(clippy::too_many_arguments)]
pub fn build_turnstile_migration_pczt_core<P>(
    params: P,
    fvk: &orchard::keys::FullViewingKey,
    prepared: Vec<(orchard::Note, orchard::tree::MerklePath)>,
    fee: u64,
    orchard_anchor: orchard::tree::Anchor,
    target_height: u32,
    expected_branch_id: u32,
    memo: zcash_protocol::memo::MemoBytes,
) -> Result<TurnstileBuild, String>
where
    P: zcash_protocol::consensus::Parameters,
{
    let (pczt, _migrated) = build_turnstile_migration_pczt_proven(
        params,
        fvk,
        prepared,
        fee,
        orchard_anchor,
        target_height,
        expected_branch_id,
        memo,
    )?;

    let pczt = redact_pczt_for_signer(pczt);
    // Money-path privacy fix: strip the wallet's own external orchard address
    // (and the rest of the dummy-output metadata) from the orchard bundle. In a
    // turnstile migration every orchard output is a fabricated dummy addressed to
    // the wallet itself; the real destination is the ironwood output, which this
    // step leaves intact for the cold device to confirm. See
    // `redact_turnstile_dummy_outputs` for the full rationale.
    let pczt = redact_turnstile_dummy_outputs(pczt);

    let summary = summarize_pczt(&pczt, Some(fee));
    let action_count = (pczt.orchard().actions().len() + pczt.ironwood().actions().len()) as u32;
    Ok(TurnstileBuild {
        pczt_bytes: pczt
            .serialize()
            .map_err(|e| format!("pczt serialize: {e:?}"))?,
        summary,
        action_count,
    })
}

/// Core of the HOT (local hot-wallet signing) turnstile migration builder,
/// generic over consensus params so native tests can drive it with a
/// regtest-style network.
///
/// Identical build+prove path to the cold core, but instead of redacting for an
/// external signer it applies the wallet-owned orchard spend-auth signatures
/// LOCALLY with the seed-derived key, then extracts a broadcast-ready V6
/// transaction. Returns the raw signed transaction bytes.
///
/// Signing model (matches the zigner cold signer
/// `pczt_signing::sign_redacted_pczt` and the `turnstile_v6` end-to-end test):
///  - The shared shielded sighash is read once from the proven PCZT via the
///    high-level `Signer::shielded_sighash` (a pure function of tx effects; it
///    binds the guarded NU6.3 consensus branch id 0x37a5165b).
///  - The output-only IRONWOOD bundle and any orchard PADDING dummies were
///    already spend-auth signed by IoFinalizer inside the build core, so the
///    only spends left are the wallet's REAL orchard notes.
///  - Those are signed per-action through the low-level `Signer` role: for each
///    orchard action we `verify_nullifier(Some(fvk))` (tolerating the four
///    Missing* variants that a fabricated/dummy spend surfaces) and then
///    `action.sign(sighash, ask, OsRng)`. Foreign/dummy spends whose key we do
///    not hold return Wrong/Missing and are skipped - "sign what is yours" -
///    and we require at least one real spend to land.
///  - The BINDING signatures for both the orchard and ironwood bundles are
///    created by the `TransactionExtractor` (from the `bsk` values IoFinalizer
///    stored), which then also verifies both proofs and every spend-auth +
///    binding signature against the sighash. There is no transparent input, so
///    the SpendFinalizer role is a no-op and is not run.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_turnstile_migration_core<P>(
    params: P,
    fvk: &orchard::keys::FullViewingKey,
    ask: &orchard::keys::SpendAuthorizingKey,
    prepared: Vec<(orchard::Note, orchard::tree::MerklePath)>,
    fee: u64,
    orchard_anchor: orchard::tree::Anchor,
    target_height: u32,
    expected_branch_id: u32,
    memo: zcash_protocol::memo::MemoBytes,
) -> Result<Vec<u8>, String>
where
    P: zcash_protocol::consensus::Parameters,
{
    use rand_core::OsRng;

    let (pczt, _migrated) = build_turnstile_migration_pczt_proven(
        params,
        fvk,
        prepared,
        fee,
        orchard_anchor,
        target_height,
        expected_branch_id,
        memo,
    )?;

    // The shielded sighash is a pure function of the tx effects (independent of
    // any spend-auth signature), so compute it once from the proven PCZT and
    // reuse it for every real orchard spend. This is the same value IoFinalizer
    // used to sign the dummy spends, and it binds the guarded NU6.3 branch id.
    let shielded_sighash = pczt::roles::signer::Signer::new(pczt.clone())
        .map_err(|e| format!("signer init: {:?}", e))?
        .shielded_sighash();

    // Sign the wallet's real orchard spends via the low-level Signer role,
    // supplying the reconstructed fvk to verify_nullifier ourselves (mirrors the
    // zigner cold signer, which must do this because its redacted PCZT strips the
    // fvk; we keep the same code path for a byte-identical signing model).
    let signed_real: usize;
    {
        let counter = core::cell::Cell::new(0usize);
        let low = pczt::roles::low_level_signer::Signer::new(pczt);
        let low = low
            .sign_orchard_with(
                |_pczt,
                 bundle,
                 _tx_modifiable|
                 -> Result<(), pczt::roles::low_level_signer::OrchardParseError> {
                    for action in bundle.actions_mut().iter_mut() {
                        match action.spend().verify_nullifier(Some(fvk)) {
                            Ok(())
                            | Err(
                                orchard::pczt::VerifyError::MissingRecipient
                                | orchard::pczt::VerifyError::MissingValue
                                | orchard::pczt::VerifyError::MissingRho
                                | orchard::pczt::VerifyError::MissingRandomSeed,
                            ) => {}
                            // A real mismatch on a spend we do not own (dummy /
                            // foreign): skip it, do not abort the batch.
                            Err(_) => continue,
                        }
                        if action.sign(shielded_sighash, ask, OsRng).is_ok() {
                            counter.set(counter.get() + 1);
                        }
                    }
                    Ok(())
                },
            )
            .map_err(|e| format!("orchard spend-auth signing: {:?}", e))?;
        // Ironwood is output-only: its dummy spends were signed by IoFinalizer,
        // so there is nothing here for the hot wallet to sign. (We deliberately
        // do NOT run sign_ironwood_with - the reconstructed-fvk nullifier check
        // does not apply to the fabricated ironwood dummy spends, and signing is
        // already complete for that bundle.)
        signed_real = counter.get();
        let pczt = low.finish();

        if signed_real == 0 {
            return Err(
                "no orchard spend accepted the seed-derived spend authorizing key: the seed \
                 does not own the supplied notes (nullifier/rk mismatch)"
                    .to_string(),
            );
        }

        // Extract the broadcast-ready V6 tx. This creates the orchard + ironwood
        // binding signatures and VERIFIES both proofs and every spend-auth +
        // binding signature against the sighash; a failure here means the signed
        // PCZT is not a valid transaction.
        extract_signed_tx_from_pczt_bytes(
            &pczt
                .serialize()
                .map_err(|e| format!("pczt serialize: {e:?}"))?,
        )
    }
}

/// Build the one-way turnstile migration PCZT: spend the supplied orchard
/// notes into the wallet's OWN ironwood address in a single V6 transaction.
///
/// The ironwood recipient is derived INTERNALLY from `ufvk_str` (self
/// migration); everything minus `fee` migrates. Returns a redacted-for-signer
/// PCZT (same redaction contract as `build_unsigned_pczt`) as JSON
/// `{ pczt_hex, summary, action_count }` where `summary` is a `PcztSummary`.
///
/// `account_index` is accepted for API parity with the worker call shape but
/// is not used for derivation - the UFVK is already account-scoped.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_turnstile_migration_pczt(
    ufvk_str: &str,
    orchard_notes_json: &str,
    fee: u64,
    orchard_anchor_hex: &str,
    orchard_merkle_paths_json: &str,
    account_index: u32,
    target_height: u32,
    expected_branch_id: u32,
    mainnet: bool,
    memo_hex: Option<String>,
) -> Result<JsValue, JsError> {
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_protocol::consensus::{BlockHeight, MainNetwork, TestNetwork};
    use zcash_protocol::memo::MemoBytes;

    let _ = account_index; // UFVK is already account-scoped; kept for parity.

    let fvk = {
        let ufvk = if mainnet {
            UnifiedFullViewingKey::decode(&MainNetwork, ufvk_str)
        } else {
            UnifiedFullViewingKey::decode(&TestNetwork, ufvk_str)
        }
        .map_err(|e| JsError::new(&format!("invalid UFVK: {}", e)))?;
        ufvk.orchard()
            .ok_or_else(|| JsError::new("UFVK has no orchard component"))?
            .clone()
    };

    let notes: Vec<SpendableNote> = serde_json::from_str(orchard_notes_json)
        .map_err(|e| JsError::new(&format!("invalid orchard_notes_json: {}", e)))?;
    let merkle_paths: Vec<MerklePathInfo> = serde_json::from_str(orchard_merkle_paths_json)
        .map_err(|e| JsError::new(&format!("invalid orchard_merkle_paths_json: {}", e)))?;
    let prepared = prepare_orchard_spends(&fvk, &notes, &merkle_paths)?;

    let anchor_bytes =
        hex_decode(orchard_anchor_hex).ok_or_else(|| JsError::new("invalid anchor hex"))?;
    let anchor_arr: [u8; 32] = anchor_bytes
        .try_into()
        .map_err(|_| JsError::new("anchor must be 32 bytes"))?;
    let orchard_anchor = Option::from(orchard::tree::Anchor::from_bytes(anchor_arr))
        .ok_or_else(|| JsError::new("invalid anchor"))?;

    let memo_arr = decode_memo_hex(memo_hex.as_deref())?;
    let memo =
        MemoBytes::from_bytes(&memo_arr).map_err(|e| JsError::new(&format!("memo: {:?}", e)))?;

    let built = if mainnet {
        build_turnstile_migration_pczt_core(
            Nu63Activated {
                inner: MainNetwork,
                nu6_3_from: BlockHeight::from(target_height),
            },
            &fvk,
            prepared,
            fee,
            orchard_anchor,
            target_height,
            expected_branch_id,
            memo,
        )
    } else {
        build_turnstile_migration_pczt_core(
            Nu63Activated {
                inner: TestNetwork,
                nu6_3_from: BlockHeight::from(target_height),
            },
            &fvk,
            prepared,
            fee,
            orchard_anchor,
            target_height,
            expected_branch_id,
            memo,
        )
    }
    .map_err(|e| JsError::new(&e))?;

    #[derive(Serialize)]
    struct Out {
        pczt_hex: String,
        summary: PcztSummary,
        action_count: u32,
    }
    serde_wasm_bindgen::to_value(&Out {
        pczt_hex: hex_encode(&built.pczt_bytes),
        summary: built.summary,
        action_count: built.action_count,
    })
    .map_err(|e| JsError::new(&format!("serialization failed: {}", e)))
}

/// HOT-WALLET sibling of `build_turnstile_migration_pczt`: build the one-way
/// turnstile migration (spend the supplied orchard notes into the wallet's OWN
/// ironwood address in a single V6 transaction), sign the wallet-owned orchard
/// spends LOCALLY with a seed-derived key, and return the hex-encoded, signed,
/// broadcast-ready V6 transaction.
///
/// Same parameter shape as `build_turnstile_migration_pczt`, except:
///  - `seed_phrase` is PREPENDED. The orchard `FullViewingKey` (for the
///    self-migration ironwood recipient) AND the `SpendAuthorizingKey` (for
///    local signing) are BOTH derived from it via ZIP-32
///    (`SpendingKey::from_zip32_seed(seed, coin_type, account_index)` - the
///    exact key `UnifiedSpendingKey::from_seed(...).orchard()` and
///    `build_signed_spend_transaction` derive), so there is no `ufvk_str`
///    parameter: the seed fully determines the account and cannot disagree with
///    a separately supplied viewing key.
///  - `account_index` selects the ZIP-32 account (it IS used here, unlike the
///    cold builder where the UFVK is already account-scoped).
///  - Returns the signed transaction hex `String`, not a redacted PCZT.
///
/// The FAIL-CLOSED NU6.3 branch-id guard is inherited unchanged from the shared
/// build core: the tx binds consensus branch id `expected_branch_id`, the
/// caller MUST pass the real 0x37a5165b (never the 0xffff_ffff placeholder).
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_signed_turnstile_migration(
    seed_phrase: &str,
    orchard_notes_json: &str,
    fee: u64,
    orchard_anchor_hex: &str,
    orchard_merkle_paths_json: &str,
    account_index: u32,
    target_height: u32,
    expected_branch_id: u32,
    mainnet: bool,
    memo_hex: Option<String>,
) -> Result<String, JsError> {
    use orchard::keys::SpendAuthorizingKey;
    use zcash_protocol::consensus::{BlockHeight, MainNetwork, TestNetwork};
    use zcash_protocol::memo::MemoBytes;

    // --- derive keys from mnemonic (same ZIP-32 path as
    //     build_signed_spend_transaction and UnifiedSpendingKey::from_seed) ---
    let mnemonic = bip39::Mnemonic::parse(seed_phrase)
        .map_err(|e| JsError::new(&format!("invalid mnemonic: {}", e)))?;
    let seed = mnemonic.to_seed("");
    let coin_type = if mainnet { 133 } else { 1 };
    let account_id = zip32::AccountId::try_from(account_index)
        .map_err(|_| JsError::new("invalid account index"))?;
    let sk = SpendingKey::from_zip32_seed(&seed, coin_type, account_id)
        .map_err(|e| JsError::new(&format!("spending key derivation failed: {:?}", e)))?;
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let ask = SpendAuthorizingKey::from(&sk);

    let notes: Vec<SpendableNote> = serde_json::from_str(orchard_notes_json)
        .map_err(|e| JsError::new(&format!("invalid orchard_notes_json: {}", e)))?;
    let merkle_paths: Vec<MerklePathInfo> = serde_json::from_str(orchard_merkle_paths_json)
        .map_err(|e| JsError::new(&format!("invalid orchard_merkle_paths_json: {}", e)))?;
    let prepared = prepare_orchard_spends(&fvk, &notes, &merkle_paths)?;

    let anchor_bytes =
        hex_decode(orchard_anchor_hex).ok_or_else(|| JsError::new("invalid anchor hex"))?;
    let anchor_arr: [u8; 32] = anchor_bytes
        .try_into()
        .map_err(|_| JsError::new("anchor must be 32 bytes"))?;
    let orchard_anchor = Option::from(orchard::tree::Anchor::from_bytes(anchor_arr))
        .ok_or_else(|| JsError::new("invalid anchor"))?;

    let memo_arr = decode_memo_hex(memo_hex.as_deref())?;
    let memo =
        MemoBytes::from_bytes(&memo_arr).map_err(|e| JsError::new(&format!("memo: {:?}", e)))?;

    let tx_bytes = if mainnet {
        build_signed_turnstile_migration_core(
            Nu63Activated {
                inner: MainNetwork,
                nu6_3_from: BlockHeight::from(target_height),
            },
            &fvk,
            &ask,
            prepared,
            fee,
            orchard_anchor,
            target_height,
            expected_branch_id,
            memo,
        )
    } else {
        build_signed_turnstile_migration_core(
            Nu63Activated {
                inner: TestNetwork,
                nu6_3_from: BlockHeight::from(target_height),
            },
            &fvk,
            &ask,
            prepared,
            fee,
            orchard_anchor,
            target_height,
            expected_branch_id,
            memo,
        )
    }
    .map_err(|e| JsError::new(&e))?;

    Ok(hex_encode(&tx_bytes))
}

// ============================================================================
// General Ironwood SEND builder (spends REAL ironwood notes -> arbitrary
// recipient + change to self). This is the ironwood analogue of a normal
// orchard send and the sibling of the turnstile migration: the migration
// spends ORCHARD and only OUTPUTS ironwood, while this spends IRONWOOD (V3
// notes) with a real ironwood tree anchor and signs the ironwood spends
// locally with the seed-derived key. Orchard sends are consensus-disabled
// post-NU6.3, so this is the only shielded-send path for ironwood funds.
// ============================================================================

/// Reconstruct + validate the wallet's REAL ironwood notes for spending.
///
/// Mirror of `prepare_orchard_spends`, but forces the Ironwood note plaintext
/// version [`orchard::note::NoteVersion::V3`] (the quantum-recoverable format)
/// and REFUSES any note that does not reconstruct as V3. Reconstruction is
/// mechanically identical to orchard (`Note::from_parts` with the stored
/// recipient/rho/rseed/value); the commitment derivation internally switches
/// to the V3 `qr_rcm` path, and the per-note `cmx` equality check catches any
/// component the caller got wrong. Error messages are deliberately free of
/// note values and recipient addresses.
fn prepare_ironwood_spends(
    fvk: &orchard::keys::FullViewingKey,
    notes: &[SpendableNote],
    merkle_paths: &[MerklePathInfo],
) -> Result<Vec<(orchard::Note, orchard::tree::MerklePath)>, JsError> {
    use orchard::note::{RandomSeed, Rho};
    use orchard::tree::{MerkleHashOrchard, MerklePath as OrchardMerklePath};
    use orchard::value::NoteValue;

    if notes.len() != merkle_paths.len() {
        return Err(JsError::new("notes and merkle paths count mismatch"));
    }

    let mut prepared: Vec<(orchard::Note, OrchardMerklePath)> = Vec::with_capacity(notes.len());
    for (i, n) in notes.iter().enumerate() {
        let rho = {
            let b = hex_decode(&n.rho_hex)
                .ok_or_else(|| JsError::new(&format!("invalid rho hex for note {}", i)))?;
            if b.len() != 32 {
                return Err(JsError::new(&format!(
                    "rho must be 32 bytes for note {}",
                    i
                )));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Option::from(Rho::from_bytes(&a))
                .ok_or_else(|| JsError::new(&format!("invalid rho for note {}", i)))?
        };
        let rseed = {
            let b = hex_decode(&n.rseed_hex)
                .ok_or_else(|| JsError::new(&format!("invalid rseed hex for note {}", i)))?;
            if b.len() != 32 {
                return Err(JsError::new(&format!(
                    "rseed must be 32 bytes for note {}",
                    i
                )));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Option::from(RandomSeed::from_bytes(a, &rho))
                .ok_or_else(|| JsError::new(&format!("invalid rseed for note {}", i)))?
        };
        let value = NoteValue::from_raw(n.value);
        let note: orchard::Note = if !n.recipient_hex.is_empty() {
            let b = hex_decode(&n.recipient_hex)
                .ok_or_else(|| JsError::new(&format!("invalid recipient hex for note {}", i)))?;
            let arr: [u8; 43] = b
                .try_into()
                .map_err(|_| JsError::new(&format!("recipient must be 43 bytes for note {}", i)))?;
            let addr = Option::from(orchard::Address::from_raw_address_bytes(&arr))
                .ok_or_else(|| JsError::new(&format!("invalid ironwood address for note {}", i)))?;
            Option::from(orchard::Note::from_parts(
                addr,
                value,
                rho,
                rseed,
                orchard::note::NoteVersion::V3,
            ))
            .ok_or_else(|| JsError::new(&format!("note {} reconstruction failed", i)))?
        } else {
            let ext = fvk.to_ivk(Scope::External).address_at(0u64);
            let int = fvk.to_ivk(Scope::Internal).address_at(0u64);
            Option::from(orchard::Note::from_parts(
                ext,
                value,
                rho,
                rseed,
                orchard::note::NoteVersion::V3,
            ))
            .or_else(|| {
                Option::from(orchard::Note::from_parts(
                    int,
                    value,
                    rho,
                    rseed,
                    orchard::note::NoteVersion::V3,
                ))
            })
            .ok_or_else(|| {
                JsError::new(&format!(
                    "note {} reconstruction failed (rseed/rho/value)",
                    i
                ))
            })?
        };
        // Pool / note-version guard (defense-in-depth): the ironwood spend path
        // is ONLY for V3 ironwood notes. A V2 (legacy orchard) note must never
        // enter here - spending an orchard note as if it were ironwood would
        // bind the wrong pool. Reconstruction above forces V3, so a mismatch
        // means the caller handed us note components that don't belong; reject
        // explicitly rather than relying on the cmx check to catch it.
        if note.version() != orchard::note::NoteVersion::V3 {
            return Err(JsError::new(&format!(
                "note {} is not a V3 ironwood note (got {:?}); the ironwood spend \
                 path rejects orchard/V2 inputs",
                i,
                note.version()
            )));
        }

        let expected = hex_decode(&n.cmx)
            .ok_or_else(|| JsError::new(&format!("invalid cmx hex for note {}", i)))?;
        let computed = orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes();
        if computed[..] != expected[..] {
            return Err(JsError::new(&format!("cmx mismatch for note {}", i)));
        }

        let mp = &merkle_paths[i];
        if mp.path.len() != 32 {
            return Err(JsError::new(&format!(
                "merkle path must have 32 elements, got {} for note {}",
                mp.path.len(),
                i
            )));
        }
        let mut hashes = [MerkleHashOrchard::from_bytes(&[0u8; 32]).unwrap(); 32];
        for (j, h_hex) in mp.path.iter().enumerate() {
            let b = hex_decode(h_hex)
                .ok_or_else(|| JsError::new(&format!("invalid merkle hash {}/{}", i, j)))?;
            if b.len() != 32 {
                return Err(JsError::new(&format!(
                    "merkle hash must be 32 bytes at {}/{}",
                    i, j
                )));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            hashes[j] = Option::from(MerkleHashOrchard::from_bytes(&a))
                .ok_or_else(|| JsError::new(&format!("invalid merkle hash at {}/{}", i, j)))?;
        }
        let merkle_path = OrchardMerklePath::from_parts(
            u32::try_from(mp.position)
                .map_err(|_| JsError::new(&format!("position {} exceeds u32 max", mp.position)))?,
            hashes,
        );
        prepared.push((note, merkle_path));
    }
    Ok(prepared)
}

/// Where the value of an ironwood send goes.
///
/// The ironwood pool shares the orchard address encoding, so a unified/orchard
/// recipient is an `orchard::Address`. A transparent recipient (`t1…`/`t3…` on
/// mainnet, `tm…`/`t2…` on testnet) becomes a real transparent output in the
/// same V6 transaction: the ironwood bundle supplies the value, the transparent
/// bundle spends it out. That z→t path is how funds leave the wallet for an
/// exchange, so it is not optional.
#[derive(Clone, Copy, Debug)]
pub enum IronwoodRecipient {
    /// Unified/orchard address — value stays shielded in the ironwood pool.
    Shielded(orchard::Address),
    /// Transparent address — value leaves the shielded pool.
    Transparent(zcash_transparent::address::TransparentAddress),
}

/// Parse a send recipient into an [`IronwoodRecipient`].
///
/// Transparent addresses are recognised by their base58 version bytes (via
/// `decode_transparent_address`), NOT by a `t1`/`tm` string prefix: prefix
/// sniffing misses `t3…`/`t2…` P2SH addresses, which is exactly what many
/// exchange deposit addresses are. Anything that is not a valid transparent
/// address is parsed as a unified/orchard address.
///
/// Errors never contain the address (they are logged and surfaced to JS).
fn parse_ironwood_recipient(recipient: &str, mainnet: bool) -> Result<IronwoodRecipient, String> {
    use zcash_keys::encoding::decode_transparent_address;
    use zcash_protocol::consensus::{NetworkConstants, NetworkType};

    let net = if mainnet {
        NetworkType::Main
    } else {
        NetworkType::Test
    };
    let (pubkey_prefix, script_prefix) = (
        net.b58_pubkey_address_prefix(),
        net.b58_script_address_prefix(),
    );

    if let Ok(Some(t)) = decode_transparent_address(&pubkey_prefix, &script_prefix, recipient) {
        return Ok(IronwoodRecipient::Transparent(t));
    }

    parse_orchard_address(recipient, mainnet)
        .map(IronwoodRecipient::Shielded)
        .map_err(|e| format!("invalid recipient: {}", e))
}

/// Build AND prove the general ironwood send PCZT, returning the *unredacted*
/// proven `pczt::Pczt`. Mirrors `build_turnstile_migration_pczt_proven` but:
///  - `orchard_anchor: None` (there are NO orchard spends), and
///    `ironwood_anchor: Some(real anchor)` - the REAL ironwood tree anchor.
///  - each selected note is added with `add_ironwood_spend` (V3 note), and
///  - the wallet outputs `amount` to `recipient` plus `change` back to its own
///    internal (change) address. Only the IRONWOOD bundle is proven (there is
///    no orchard bundle to prove).
///
/// `recipient` may be SHIELDED or TRANSPARENT:
///  - [`IronwoodRecipient::Shielded`] adds an `add_ironwood_output` carrying the
///    memo, exactly as before.
///  - [`IronwoodRecipient::Transparent`] adds a real `add_transparent_output` to
///    the same V6 transaction (z→t). The ironwood bundle then holds only the
///    spends plus the change output, and the transparent bundle is
///    outputs-only - no transparent inputs, so nothing here needs a transparent
///    signature. Without this the wallet could not withdraw to an exchange at
///    all once NU6.3 disabled the orchard spend path.
///
/// A memo is meaningless on a transparent output (there is nowhere to put it),
/// so pairing one with a transparent recipient is an ERROR rather than a
/// silently dropped memo - the user must not believe a payment reference was
/// delivered when it was not.
///
/// The FAIL-CLOSED branch-id guard is copied from the migration core AND
/// hardened: the tx must bind the NU6.3 consensus branch id `0x37a5165b`, the
/// caller-supplied `expected_branch_id` must equal it, and the placeholder
/// `0xffff_ffff` is refused outright. No value or recipient appears in any
/// error.
#[allow(clippy::too_many_arguments)]
/// A built+proven ironwood PCZT together with the FROST signing inputs captured
/// from the builder parts before `Creator` consumed them.
///
/// `alphas`/`spend_indices` are empty for a single-signature send; they are the
/// per-spend rerandomizers and action indices a FROST caller needs, in action
/// order, which is the order host and joiner run the signing rounds in.
pub struct IronwoodPcztWithFrost {
    pub pczt: pczt::Pczt,
    pub alphas: Vec<String>,
    pub spend_indices: Vec<u32>,
}

pub fn build_ironwood_send_pczt_proven<P>(
    params: P,
    fvk: &orchard::keys::FullViewingKey,
    prepared: Vec<(orchard::Note, orchard::tree::MerklePath)>,
    recipient: IronwoodRecipient,
    amount: u64,
    fee: u64,
    ironwood_anchor: orchard::tree::Anchor,
    target_height: u32,
    expected_branch_id: u32,
    memo: zcash_protocol::memo::MemoBytes,
) -> Result<IronwoodPcztWithFrost, String>
where
    P: zcash_protocol::consensus::Parameters,
{
    use orchard::circuit::OrchardCircuitVersion;
    use rand::rngs::OsRng;
    use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
    use zcash_primitives::transaction::fees::fixed::FeeRule as FixedFeeRule;
    use zcash_primitives::transaction::TxVersion;
    use zcash_protocol::consensus::{BlockHeight, BranchId};
    use zcash_protocol::memo::MemoBytes;
    use zcash_protocol::value::Zatoshis;

    type FeError = <FixedFeeRule as zcash_primitives::transaction::fees::FeeRule>::Error;

    // FAIL-CLOSED branch-id guard (money path), identical in spirit to the
    // turnstile migration but hardened to require the real NU6.3 branch id.
    // The ironwood sighash binds the consensus branch id selected by the
    // network params at `target_height`. We REFUSE unless: (a) it is not the
    // placeholder, (b) it is exactly the NU6.3 branch id 0x37a5165b, and (c) it
    // equals the branch id the wallet believes is active (read from
    // GetLightdInfo and passed as `expected_branch_id`). This makes it
    // impossible to bind the 0xffff_ffff placeholder (Nu7/ZFuture, invalid on
    // chain) or a branch other than NU6.3.
    const NU6_3_PLACEHOLDER_BRANCH_ID: u32 = 0xffff_ffff;
    const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;
    if expected_branch_id == NU6_3_PLACEHOLDER_BRANCH_ID {
        return Err(format!(
            "refusing to build ironwood send: expected_branch_id is the NU6.3 \
             placeholder {:#010x}; the wallet must pass the real consensus branch \
             id read from GetLightdInfo",
            NU6_3_PLACEHOLDER_BRANCH_ID
        ));
    }
    let bound_branch_id: u32 =
        BranchId::for_height(&params, BlockHeight::from(target_height)).into();
    if bound_branch_id == NU6_3_PLACEHOLDER_BRANCH_ID {
        return Err(format!(
            "refusing to build ironwood send: the network params would bind the \
             NU6.3 placeholder branch id {:#010x} at height {} - the librustzcash \
             fork has not been patched with the real NU6.3 branch id",
            NU6_3_PLACEHOLDER_BRANCH_ID, target_height
        ));
    }
    if bound_branch_id != NU6_3_BRANCH_ID {
        return Err(format!(
            "refusing to build ironwood send: branch id that would bind at height \
             {} is {:#010x} but ironwood spends require the NU6.3 branch id \
             {:#010x} (NU6.3 not active at this height)",
            target_height, bound_branch_id, NU6_3_BRANCH_ID
        ));
    }
    if bound_branch_id != expected_branch_id {
        return Err(format!(
            "refusing to build ironwood send: branch id that would bind at height \
             {} is {:#010x} but the wallet expected {:#010x} (branch-id mismatch)",
            target_height, bound_branch_id, expected_branch_id
        ));
    }

    if prepared.is_empty() {
        return Err("ironwood send requires at least one ironwood note".into());
    }
    let total_input: u64 = prepared.iter().map(|(n, _)| n.value().inner()).sum();
    // Value-free insufficient-funds check (no amounts leaked into the error).
    let needed = amount
        .checked_add(fee)
        .ok_or_else(|| "amount + fee overflows u64".to_string())?;
    if total_input < needed {
        return Err("insufficient funds: inputs do not cover amount + fee".into());
    }
    let change_value = total_input - needed;

    // Outgoing viewing keys: the recipient payment binds the EXTERNAL ovk so
    // the sender's own FVK can later recover its outgoing (recipient, amount)
    // history; change binds the INTERNAL ovk. Change returns to the wallet's
    // own internal (change) ironwood address, diversifier 0.
    let external_ovk = Some(fvk.to_ovk(Scope::External));
    let internal_ovk = Some(fvk.to_ovk(Scope::Internal));
    let change_addr = fvk.address_at(0u32, Scope::Internal);

    let mut builder = Builder::new(
        params,
        BlockHeight::from(target_height),
        BuildConfig::Standard {
            sapling_anchor: None,
            // No orchard spends in a general ironwood send.
            orchard_anchor: None,
            // REAL ironwood tree anchor (the migration used the empty-tree
            // anchor because it only output dummy ironwood spends).
            ironwood_anchor: Some(ironwood_anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .propose_version::<FeError>(TxVersion::V6)
        .map_err(|e| format!("propose_version(V6): {:?}", e))?;
    for (note, mp) in &prepared {
        builder
            .add_ironwood_spend::<FeError>(fvk.clone(), *note, mp.clone())
            .map_err(|e| format!("add_ironwood_spend: {:?}", e))?;
    }
    let amount_zat = Zatoshis::from_u64(amount).map_err(|_| "invalid amount".to_string())?;
    match recipient {
        IronwoodRecipient::Shielded(addr) => {
            builder
                .add_ironwood_output::<FeError>(external_ovk, addr, amount_zat, memo)
                .map_err(|e| format!("add_ironwood_output: {:?}", e))?;
        }
        IronwoodRecipient::Transparent(taddr) => {
            // A transparent output carries no memo field. Refuse rather than
            // drop one silently - see the doc comment.
            if memo != MemoBytes::empty() {
                return Err(
                    "a memo cannot be delivered to a transparent address: transparent \
                     outputs have no memo field. Send the memo to a shielded (unified) \
                     address, or send to the transparent address without one."
                        .to_string(),
                );
            }
            builder
                .add_transparent_output(&taddr, amount_zat)
                .map_err(|e| format!("add_transparent_output: {:?}", e))?;
        }
    }
    if change_value > 0 {
        let change_zat =
            Zatoshis::from_u64(change_value).map_err(|_| "invalid change amount".to_string())?;
        // Released zcash_primitives has no change-specific helper; a change
        // output IS an ironwood output to our own internal address bound to
        // the INTERNAL ovk, which is exactly what this produces. The fvk the
        // fork took was only used for its internal change bookkeeping.
        builder
            .add_ironwood_output::<FeError>(
                internal_ovk,
                change_addr,
                change_zat,
                MemoBytes::empty(),
            )
            .map_err(|e| format!("add_ironwood_output (change): {:?}", e))?;
    }

    let fee_zat = Zatoshis::from_u64(fee).map_err(|_| "invalid fee amount".to_string())?;
    let fee_rule = FixedFeeRule::non_standard(fee_zat);
    let parts = builder
        .build_for_pczt(OsRng, &fee_rule)
        .map_err(|e| format!("build_for_pczt: {:?}", e))?
        .pczt_parts;

    // Capture FROST signing data from the ironwood parts BEFORE Creator consumes
    // them. `into_pczt` sets `alpha` + `dummy_sk` at build_for_pczt time, so real
    // spends (dummy_sk == None) carry their rerandomizer here. The pczt::Pczt that
    // Creator produces keeps these pub(crate), so this is the only public read.
    // Same capture the orchard FROST path does; see `extract_frost` above.
    // Order = action order = the order host + joiner run the FROST rounds in.
    let (frost_alphas, frost_spend_indices) = {
        use group::ff::PrimeField;
        let mut alphas: Vec<String> = Vec::new();
        let mut spend_indices: Vec<u32> = Vec::new();
        if let Some(b) = parts.ironwood.as_ref() {
            for (i, action) in b.actions().iter().enumerate() {
                if action.spend().dummy_sk().is_none() {
                    let alpha = action
                        .spend()
                        .alpha()
                        .ok_or_else(|| format!("missing alpha for real ironwood spend {i}"))?;
                    alphas.push(hex_encode(&alpha.to_repr()));
                    spend_indices.push(i as u32);
                }
            }
        }
        (alphas, spend_indices)
    };

    let pczt = pczt::roles::creator::Creator::build_from_parts(parts)
        .ok_or_else(|| "Creator::build_from_parts: incompatible tx version".to_string())?;

    // IoFinalizer binds the shared shielded sighash and spend-auth signs every
    // DUMMY (padding) ironwood spend; only the wallet's REAL ironwood spends
    // remain unsigned for the hot signer below.
    let pczt = pczt::roles::io_finalizer::IoFinalizer::new(pczt)
        .finalize_io()
        .map_err(|e| format!("finalize_io: {:?}", e))?;

    // Only the ironwood bundle exists (orchard_anchor was None), so prove just
    // the ironwood bundle on the post-NU6.3 circuit.
    let pczt = with_proving_key_for(OrchardCircuitVersion::PostNu6_3, |pk| {
        pczt::roles::prover::Prover::new(pczt)
            .create_ironwood_proof(pk)
            .map(|p| p.finish())
    })
    .map_err(|e| format!("create ironwood proof: {:?}", e))?;

    Ok(IronwoodPcztWithFrost {
        pczt,
        alphas: frost_alphas,
        spend_indices: frost_spend_indices,
    })
}

/// Core of the HOT (local hot-wallet signing) general ironwood send builder,
/// generic over consensus params so native tests can drive it with a
/// regtest-style network.
///
/// Builds+proves via `build_ironwood_send_pczt_proven`, then applies the
/// wallet-owned IRONWOOD spend-auth signatures LOCALLY with the seed-derived
/// key and extracts a broadcast-ready V6 transaction. This is the direct
/// analogue of `build_signed_turnstile_migration_core`, except it signs the
/// IRONWOOD bundle (real ironwood spends) rather than the orchard bundle - in
/// the migration the ironwood bundle was output-only (all-dummy spends signed
/// by IoFinalizer), whereas here the ironwood bundle carries the wallet's real
/// spends.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_ironwood_send_core<P>(
    params: P,
    fvk: &orchard::keys::FullViewingKey,
    ask: &orchard::keys::SpendAuthorizingKey,
    prepared: Vec<(orchard::Note, orchard::tree::MerklePath)>,
    recipient: IronwoodRecipient,
    amount: u64,
    fee: u64,
    ironwood_anchor: orchard::tree::Anchor,
    target_height: u32,
    expected_branch_id: u32,
    memo: zcash_protocol::memo::MemoBytes,
) -> Result<Vec<u8>, String>
where
    P: zcash_protocol::consensus::Parameters,
{
    use rand_core::OsRng;

    let IronwoodPcztWithFrost { pczt, .. } = build_ironwood_send_pczt_proven(
        params,
        fvk,
        prepared,
        recipient,
        amount,
        fee,
        ironwood_anchor,
        target_height,
        expected_branch_id,
        memo,
    )?;

    // Shielded sighash is a pure function of tx effects; compute once and reuse
    // for every real ironwood spend. It binds the guarded NU6.3 branch id and
    // is the same value IoFinalizer used to sign the dummy spends.
    let shielded_sighash = pczt::roles::signer::Signer::new(pczt.clone())
        .map_err(|e| format!("signer init: {:?}", e))?
        .shielded_sighash();

    // Sign the wallet's real IRONWOOD spends via the low-level Signer role,
    // supplying the reconstructed fvk to verify_nullifier ourselves ("sign what
    // is yours"): dummy/foreign spends surface Missing*/Wrong and are skipped.
    let signed_real: usize;
    {
        let counter = core::cell::Cell::new(0usize);
        let low = pczt::roles::low_level_signer::Signer::new(pczt);
        let low = low
            .sign_ironwood_with(
                |_pczt,
                 bundle,
                 _tx_modifiable|
                 -> Result<(), pczt::roles::low_level_signer::OrchardParseError> {
                    for action in bundle.actions_mut().iter_mut() {
                        match action.spend().verify_nullifier(Some(fvk)) {
                            Ok(())
                            | Err(
                                orchard::pczt::VerifyError::MissingRecipient
                                | orchard::pczt::VerifyError::MissingValue
                                | orchard::pczt::VerifyError::MissingRho
                                | orchard::pczt::VerifyError::MissingRandomSeed,
                            ) => {}
                            // A real mismatch on a spend we do not own (dummy /
                            // foreign): skip it, do not abort the batch.
                            Err(_) => continue,
                        }
                        if action.sign(shielded_sighash, ask, OsRng).is_ok() {
                            counter.set(counter.get() + 1);
                        }
                    }
                    Ok(())
                },
            )
            .map_err(|e| format!("ironwood spend-auth signing: {:?}", e))?;
        signed_real = counter.get();
        let pczt = low.finish();

        if signed_real == 0 {
            return Err(
                "no ironwood spend accepted the seed-derived spend authorizing key: the seed \
                 does not own the supplied notes (nullifier/rk mismatch)"
                    .to_string(),
            );
        }

        // Extract the broadcast-ready V6 tx. This creates the ironwood binding
        // signature and VERIFIES the proof and every spend-auth + binding
        // signature against the sighash; a failure means the signed PCZT is not
        // a valid transaction.
        extract_signed_tx_from_pczt_bytes(
            &pczt
                .serialize()
                .map_err(|e| format!("pczt serialize: {e:?}"))?,
        )
    }
}

/// COLD (zigner / watch-only) sibling of `build_signed_ironwood_send`: build the
/// general ironwood send PCZT - spend the wallet's REAL ironwood notes to an
/// ARBITRARY `recipient` (plus change back to self) in a single V6 transaction -
/// and return a redacted-for-signer PCZT (same redaction contract as
/// `build_turnstile_migration_pczt`) as JSON `{ pczt_hex, summary, action_count }`
/// where `summary` is a `PcztSummary`.
///
/// The wallet-owned ironwood spends are left UNSIGNED for the external cold
/// signer (zigner), which already knows how to sign redacted ironwood spends
/// (`pczt_signing::sign_redacted_pczt` signs the orchard AND ironwood spends).
/// Mirrors `build_turnstile_migration_pczt`'s param shape exactly, except:
///  - `recipient` (unified address; its orchard-format receiver is the ironwood
///    recipient) and `amount` are added, and
///  - the anchor/notes/paths are the IRONWOOD tree's (real anchor + real
///    ironwood spends), not the orchard tree's.
///
/// `account_index` is accepted for API parity with the worker call shape but is
/// not used for derivation - the UFVK is already account-scoped.
///
/// FAIL-CLOSED: inherits the hardened NU6.3 branch-id guard from
/// `build_ironwood_send_pczt_proven` - the tx binds branch id 0x37a5165b, the
/// caller MUST pass that real id as `expected_branch_id`, and the 0xffff_ffff
/// placeholder is refused. No value or recipient appears in any error.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_ironwood_send_pczt(
    ufvk_str: &str,
    ironwood_notes_json: &str,
    recipient: &str,
    amount: u64,
    fee: u64,
    ironwood_anchor_hex: &str,
    ironwood_merkle_paths_json: &str,
    account_index: u32,
    target_height: u32,
    expected_branch_id: u32,
    mainnet: bool,
    memo_hex: Option<String>,
) -> Result<JsValue, JsError> {
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_protocol::consensus::{BlockHeight, MainNetwork, TestNetwork};
    use zcash_protocol::memo::MemoBytes;

    let _ = account_index; // UFVK is already account-scoped; kept for parity.

    // Ironwood shares the orchard key hierarchy: derive the orchard FVK from the
    // UFVK and use it for recipient/change scoping + nullifier verification.
    let fvk = {
        let ufvk = if mainnet {
            UnifiedFullViewingKey::decode(&MainNetwork, ufvk_str)
        } else {
            UnifiedFullViewingKey::decode(&TestNetwork, ufvk_str)
        }
        .map_err(|e| JsError::new(&format!("invalid UFVK: {}", e)))?;
        ufvk.orchard()
            .ok_or_else(|| JsError::new("UFVK has no orchard component"))?
            .clone()
    };

    // Recipient: a unified/orchard address (value stays in the ironwood pool)
    // OR a transparent address (z->t withdrawal, e.g. to an exchange), decided
    // by the address encoding. Error is address-free.
    let recipient_addr =
        parse_ironwood_recipient(recipient, mainnet).map_err(|e| JsError::new(&e))?;

    let notes: Vec<SpendableNote> = serde_json::from_str(ironwood_notes_json)
        .map_err(|e| JsError::new(&format!("invalid ironwood_notes_json: {}", e)))?;
    let merkle_paths: Vec<MerklePathInfo> = serde_json::from_str(ironwood_merkle_paths_json)
        .map_err(|e| JsError::new(&format!("invalid ironwood_merkle_paths_json: {}", e)))?;
    let prepared = prepare_ironwood_spends(&fvk, &notes, &merkle_paths)?;

    let anchor_bytes =
        hex_decode(ironwood_anchor_hex).ok_or_else(|| JsError::new("invalid anchor hex"))?;
    let anchor_arr: [u8; 32] = anchor_bytes
        .try_into()
        .map_err(|_| JsError::new("anchor must be 32 bytes"))?;
    let ironwood_anchor = Option::from(orchard::tree::Anchor::from_bytes(anchor_arr))
        .ok_or_else(|| JsError::new("invalid anchor"))?;

    let memo_arr = decode_memo_hex(memo_hex.as_deref())?;
    let memo =
        MemoBytes::from_bytes(&memo_arr).map_err(|e| JsError::new(&format!("memo: {:?}", e)))?;

    // Build+prove the UNREDACTED ironwood-send PCZT (Creator -> IoFinalizer ->
    // Prover, ironwood proof only). The fail-closed branch-id guard fires inside.
    let IronwoodPcztWithFrost {
        pczt,
        alphas,
        spend_indices,
    } = if mainnet {
        build_ironwood_send_pczt_proven(
            Nu63Activated {
                inner: MainNetwork,
                nu6_3_from: BlockHeight::from(target_height),
            },
            &fvk,
            prepared,
            recipient_addr,
            amount,
            fee,
            ironwood_anchor,
            target_height,
            expected_branch_id,
            memo,
        )
    } else {
        build_ironwood_send_pczt_proven(
            Nu63Activated {
                inner: TestNetwork,
                nu6_3_from: BlockHeight::from(target_height),
            },
            &fvk,
            prepared,
            recipient_addr,
            amount,
            fee,
            ironwood_anchor,
            target_height,
            expected_branch_id,
            memo,
        )
    }
    .map_err(|e| JsError::new(&e))?;

    // Redact for the external cold signer. `redact_pczt_for_signer` already
    // redacts the ironwood bundle's spend-side fields (witness/rseed/rho/
    // recipient/value/fvk); it does NOT touch output metadata, so the real
    // ironwood recipient + change outputs survive for the device to confirm.
    // Unlike the turnstile migration there is no orchard dummy-output bundle, so
    // `redact_turnstile_dummy_outputs` is deliberately NOT applied.
    let pczt = redact_pczt_for_signer(pczt);

    // Shielded sighash computed from the REDACTED bytes, for the same reason the
    // summary is: it must be the value bound to what the signer actually sees
    // and signs. Redaction touches only spend-side witness material, never
    // consensus-relevant effects, so this equals the value IoFinalizer bound.
    let shielded_sighash = pczt::roles::signer::Signer::new(pczt.clone())
        .map_err(|e| JsError::new(&format!("signer init: {:?}", e)))?
        .shielded_sighash();

    // Recompute the confirmation summary from the REDACTED bytes (never from
    // builder-side bookkeeping) so what the device displays is bound to what it
    // signs - identical to `build_turnstile_migration_pczt_core`.
    let summary = summarize_pczt(&pczt, Some(fee));
    let action_count = (pczt.orchard().actions().len() + pczt.ironwood().actions().len()) as u32;

    #[derive(Serialize)]
    struct Out {
        pczt_hex: String,
        summary: PcztSummary,
        action_count: u32,
        /// ZIP-244 shielded sighash - the message FROST signers commit to.
        sighash: String,
        /// Per-spend rerandomizers for the real ironwood spends, in action order.
        alphas: Vec<String>,
        /// Action indices those alphas correspond to.
        spend_indices: Vec<u32>,
    }
    serde_wasm_bindgen::to_value(&Out {
        pczt_hex: hex_encode(
            &pczt
                .serialize()
                .map_err(|e| JsError::new(&format!("pczt serialize: {e:?}")))?,
        ),
        summary,
        action_count,
        sighash: hex_encode(&shielded_sighash),
        alphas,
        spend_indices,
    })
    .map_err(|e| JsError::new(&format!("serialization failed: {}", e)))
}

/// HOT-WALLET general ironwood send: spend the wallet's REAL ironwood notes to
/// an ARBITRARY `recipient` (plus change back to self) in a single V6
/// transaction, sign the ironwood spends LOCALLY with a seed-derived key, and
/// return the hex-encoded, signed, broadcast-ready V6 transaction.
///
/// This is the ironwood analogue of a normal orchard send and the sibling of
/// `build_signed_turnstile_migration`. Parameters mirror that function's shape,
/// with `recipient`/`amount` added and the anchor/notes/paths being the
/// ironwood tree's:
///  - `seed_phrase` derives BOTH the orchard `FullViewingKey` (recipient/change
///    scoping + nullifier verification) AND the `SpendAuthorizingKey` (local
///    signing) via the exact ZIP-32 path `SpendingKey::from_zip32_seed`.
///  - `recipient` is a unified address; its orchard-format receiver is used as
///    the ironwood recipient (the ironwood pool shares the orchard address
///    format - the note VERSION, not the address, selects the pool).
///  - `ironwood_anchor_hex` is the REAL ironwood tree anchor;
///    `ironwood_merkle_paths_json` are ironwood-tree paths from
///    `build_merkle_paths_ironwood`.
///
/// FAIL-CLOSED: inherits the hardened NU6.3 branch-id guard from the build core
/// - the tx binds branch id 0x37a5165b, the caller MUST pass that real id as
/// `expected_branch_id`, and the 0xffff_ffff placeholder is refused. No value
/// or recipient appears in any error.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_signed_ironwood_send(
    seed_phrase: &str,
    ironwood_notes_json: &str,
    recipient: &str,
    amount: u64,
    fee: u64,
    ironwood_anchor_hex: &str,
    ironwood_merkle_paths_json: &str,
    account_index: u32,
    target_height: u32,
    expected_branch_id: u32,
    mainnet: bool,
    memo_hex: Option<String>,
) -> Result<String, JsError> {
    use orchard::keys::SpendAuthorizingKey;
    use zcash_protocol::consensus::{BlockHeight, MainNetwork, TestNetwork};
    use zcash_protocol::memo::MemoBytes;

    // --- derive keys from mnemonic (same ZIP-32 path as
    //     build_signed_turnstile_migration / UnifiedSpendingKey::from_seed) ---
    let mnemonic = bip39::Mnemonic::parse(seed_phrase)
        .map_err(|e| JsError::new(&format!("invalid mnemonic: {}", e)))?;
    let seed = mnemonic.to_seed("");
    let coin_type = if mainnet { 133 } else { 1 };
    let account_id = zip32::AccountId::try_from(account_index)
        .map_err(|_| JsError::new("invalid account index"))?;
    let sk = SpendingKey::from_zip32_seed(&seed, coin_type, account_id)
        .map_err(|e| JsError::new(&format!("spending key derivation failed: {:?}", e)))?;
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let ask = SpendAuthorizingKey::from(&sk);

    // Recipient: a unified/orchard address (value stays in the ironwood pool)
    // OR a transparent address (z->t withdrawal, e.g. to an exchange), decided
    // by the address encoding. Error is address-free.
    let recipient_addr =
        parse_ironwood_recipient(recipient, mainnet).map_err(|e| JsError::new(&e))?;

    let notes: Vec<SpendableNote> = serde_json::from_str(ironwood_notes_json)
        .map_err(|e| JsError::new(&format!("invalid ironwood_notes_json: {}", e)))?;
    let merkle_paths: Vec<MerklePathInfo> = serde_json::from_str(ironwood_merkle_paths_json)
        .map_err(|e| JsError::new(&format!("invalid ironwood_merkle_paths_json: {}", e)))?;
    let prepared = prepare_ironwood_spends(&fvk, &notes, &merkle_paths)?;

    let anchor_bytes =
        hex_decode(ironwood_anchor_hex).ok_or_else(|| JsError::new("invalid anchor hex"))?;
    let anchor_arr: [u8; 32] = anchor_bytes
        .try_into()
        .map_err(|_| JsError::new("anchor must be 32 bytes"))?;
    let ironwood_anchor = Option::from(orchard::tree::Anchor::from_bytes(anchor_arr))
        .ok_or_else(|| JsError::new("invalid anchor"))?;

    let memo_arr = decode_memo_hex(memo_hex.as_deref())?;
    let memo =
        MemoBytes::from_bytes(&memo_arr).map_err(|e| JsError::new(&format!("memo: {:?}", e)))?;

    let tx_bytes = if mainnet {
        build_signed_ironwood_send_core(
            Nu63Activated {
                inner: MainNetwork,
                nu6_3_from: BlockHeight::from(target_height),
            },
            &fvk,
            &ask,
            prepared,
            recipient_addr,
            amount,
            fee,
            ironwood_anchor,
            target_height,
            expected_branch_id,
            memo,
        )
    } else {
        build_signed_ironwood_send_core(
            Nu63Activated {
                inner: TestNetwork,
                nu6_3_from: BlockHeight::from(target_height),
            },
            &fvk,
            &ask,
            prepared,
            recipient_addr,
            amount,
            fee,
            ironwood_anchor,
            target_height,
            expected_branch_id,
            memo,
        )
    }
    .map_err(|e| JsError::new(&e))?;

    Ok(hex_encode(&tx_bytes))
}

/// Complete an orchard-only FROST multisig PCZT: inject the externally-aggregated
/// SpendAuth signatures (one per real spend, in `spend_indices` order, matching
/// what `build_unsigned_pczt` returned) into the PCZT, then extract the
/// broadcast-ready v5 tx. The mnemonic/zigner host and the poker escrow all
/// finish a FROST signing round this way (gh #17 PCZT migration).
#[wasm_bindgen]
pub fn complete_orchard_pczt(
    pczt_hex: &str,
    orchard_sigs_json: JsValue,
    spend_indices_json: JsValue,
) -> Result<String, JsError> {
    use orchard::primitives::redpallas;

    let sigs: Vec<String> = serde_wasm_bindgen::from_value(orchard_sigs_json)
        .map_err(|e| JsError::new(&format!("invalid orchard_sigs: {}", e)))?;
    let spend_indices: Vec<u32> = serde_wasm_bindgen::from_value(spend_indices_json)
        .map_err(|e| JsError::new(&format!("invalid spend_indices: {}", e)))?;
    if sigs.len() != spend_indices.len() {
        return Err(JsError::new(
            "orchard_sigs and spend_indices length mismatch",
        ));
    }

    let bytes = hex_decode(pczt_hex).ok_or_else(|| JsError::new("invalid pczt hex"))?;
    let pczt = pczt::Pczt::parse(&bytes)
        .map_err(|e| JsError::new(&format!("pczt parse failed: {:?}", e)))?;
    let mut signer = pczt::roles::signer::Signer::new(pczt)
        .map_err(|e| JsError::new(&format!("signer init: {:?}", e)))?;

    for (sig_hex, idx) in sigs.iter().zip(spend_indices.iter()) {
        let raw = hex_decode(sig_hex).ok_or_else(|| JsError::new("invalid orchard sig hex"))?;
        let arr: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("orchard sig must be 64 bytes"))?;
        let sig = redpallas::Signature::<redpallas::SpendAuth>::from(arr);
        signer
            .apply_orchard_signature(*idx as usize, sig)
            .map_err(|e| JsError::new(&format!("apply_orchard_signature[{}]: {:?}", idx, e)))?;
    }

    let signed = signer.finish();
    let tx_bytes = extract_signed_tx_from_pczt_bytes(
        &signed
            .serialize()
            .map_err(|e| JsError::new(&format!("pczt serialize: {e:?}")))?,
    )
    .map_err(|e| JsError::new(&e))?;
    Ok(hex_encode(&tx_bytes))
}

/// Does this PCZT carry ironwood (v6) actions?
///
/// Completion has to route to `complete_ironwood_pczt` or
/// `complete_orchard_pczt`, and the answer is a property of the artifact, not
/// of the caller. Deriving it here rather than threading a `pool` flag through
/// the relay means a caller that forgets the flag cannot silently apply
/// signatures to the wrong bundle.
#[wasm_bindgen]
pub fn pczt_has_ironwood_actions(pczt_hex: &str) -> Result<bool, JsError> {
    let bytes = hex_decode(pczt_hex).ok_or_else(|| JsError::new("invalid pczt hex"))?;
    let pczt = pczt::Pczt::parse(&bytes)
        .map_err(|e| JsError::new(&format!("pczt parse failed: {:?}", e)))?;
    Ok(!pczt.ironwood().actions().is_empty())
}

/// Ironwood (NU6.3 / v6) sibling of `complete_orchard_pczt`: inject the
/// externally-aggregated SpendAuth signatures - one per real ironwood spend, in
/// the `spend_indices` order `build_ironwood_send_pczt` returned - and extract
/// the broadcast-ready V6 tx.
///
/// FROST itself is pool-independent: a RedPallas spend-auth signature over the
/// shielded sighash is the same for an ironwood action as for an orchard one.
/// The only thing that differs here is which bundle the signature is applied
/// to, so this is `complete_orchard_pczt` with `apply_ironwood_signature`.
///
/// The sighash the signatures must commit to is the `sighash` field returned by
/// `build_ironwood_send_pczt`. `extract_signed_tx_from_pczt_bytes` re-verifies
/// every spend-auth and binding signature against it, so a signature aggregated
/// over the wrong message fails here rather than on the network.
#[wasm_bindgen]
pub fn complete_ironwood_pczt(
    pczt_hex: &str,
    ironwood_sigs_json: JsValue,
    spend_indices_json: JsValue,
) -> Result<String, JsError> {
    let sigs: Vec<String> = serde_wasm_bindgen::from_value(ironwood_sigs_json)
        .map_err(|e| JsError::new(&format!("invalid ironwood_sigs: {}", e)))?;
    let spend_indices: Vec<u32> = serde_wasm_bindgen::from_value(spend_indices_json)
        .map_err(|e| JsError::new(&format!("invalid spend_indices: {}", e)))?;

    let mut sig_bytes: Vec<[u8; 64]> = Vec::with_capacity(sigs.len());
    for s in &sigs {
        let raw = hex_decode(s).ok_or_else(|| JsError::new("invalid ironwood sig hex"))?;
        let arr: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("ironwood sig must be 64 bytes"))?;
        sig_bytes.push(arr);
    }

    let bytes = hex_decode(pczt_hex).ok_or_else(|| JsError::new("invalid pczt hex"))?;
    let tx = complete_ironwood_pczt_core(&bytes, &sig_bytes, &spend_indices)
        .map_err(|e| JsError::new(&e))?;
    Ok(hex_encode(&tx))
}

/// Native core of `complete_ironwood_pczt`, so the money path is reachable from
/// an integration test rather than only across the wasm boundary. Same split
/// the builder uses (`build_ironwood_send_pczt_proven` vs its wasm wrapper).
pub fn complete_ironwood_pczt_core(
    pczt_bytes: &[u8],
    sigs: &[[u8; 64]],
    spend_indices: &[u32],
) -> Result<Vec<u8>, String> {
    use orchard::primitives::redpallas;

    if sigs.len() != spend_indices.len() {
        return Err("ironwood_sigs and spend_indices length mismatch".to_string());
    }
    if sigs.is_empty() {
        // Guard the exact failure the wallet-side gate was protecting against:
        // zero signing rounds producing an empty signature set, which would
        // otherwise sail through into an unsignable extract.
        return Err(
            "no ironwood signatures supplied - refusing to extract an unsigned transaction"
                .to_string(),
        );
    }

    let pczt = pczt::Pczt::parse(pczt_bytes).map_err(|e| format!("pczt parse failed: {:?}", e))?;
    let mut signer =
        pczt::roles::signer::Signer::new(pczt).map_err(|e| format!("signer init: {:?}", e))?;

    for (sig, idx) in sigs.iter().zip(spend_indices.iter()) {
        let sig = redpallas::Signature::<redpallas::SpendAuth>::from(*sig);
        signer
            .apply_ironwood_signature(*idx as usize, sig)
            .map_err(|e| format!("apply_ironwood_signature[{}]: {:?}", idx, e))?;
    }

    let signed = signer.finish();
    extract_signed_tx_from_pczt_bytes(
        &signed
            .serialize()
            .map_err(|e| format!("pczt serialize: {e:?}"))?,
    )
}

/// Compact a PCZT for transmission to a signer by redacting per-action cv_net,
/// v6 bundle anchors, output cmx, and replacing enc_ciphertext with memo plaintext
/// (trimmed to last nonzero byte). Builds on the existing signer redaction.
///
/// This function is used to minimize the size of PCZT requests sent to a hardware
/// signer device. The signer can recompute the redacted fields from the remaining data.
///
/// # Arguments
/// * `pczt_hex` - hex-encoded PCZT (v2 format)
///
/// # Returns
/// Hex-encoded compact PCZT
#[wasm_bindgen]
pub fn redact_pczt_compact(pczt_hex: &str) -> Result<String, JsError> {
    let bytes = hex_decode(pczt_hex).ok_or_else(|| JsError::new("invalid pczt hex"))?;
    let pczt = pczt::Pczt::parse(&bytes)
        .map_err(|e| JsError::new(&format!("pczt parse failed: {:?}", e)))?;

    // Start with existing signer redaction
    let pczt = redact_pczt_for_signer(pczt);

    // Apply compact redaction on top
    let mut redactor = pczt::roles::redactor::Redactor::new(pczt);

    // Compact orchard bundle
    redactor = redactor.redact_orchard_with(|mut o| {
        o.redact_actions(|mut a| {
            // cv_net is deliberately NOT cleared. The signer rebuilds a redacted
            // cv_net in resolve_cv_net() from the SPEND value - but
            // redact_pczt_for_signer (applied above) has already stripped
            // spend.value for privacy, so a cleared cv_net is unrecoverable on
            // the device and it rejects the whole PCZT with
            // ParseError::InvalidValueCommitment. cv_net is public 32-byte
            // per-action data that appears in the final transaction regardless,
            // so retaining it leaks nothing; the large savings (cmx +
            // enc_ciphertext, both recoverable from retained output fields)
            // stay below.
            // Clear output cmx
            a.clear_cmx();
            // The 580-byte enc_ciphertext collapses to the memo trimmed to
            // its last nonzero byte - ONE byte for the empty memo a turnstile
            // migration uses. This is the single largest request-leg win
            // (measured: 2.53x smaller request on a v6 migration, vs 1.08x
            // without it). The signer re-encrypts it in `resolve_fields()`
            // from the retained recipient/value/rseed plus the spend
            // nullifier (rho), then runs every normal verification gate.
            //
            // MEMO_SIZE is crate-private upstream; it is 512 by spec.
            a.replace_enc_ciphertext_with_memo_plaintext([0u8; 512]);
        });
        // Clear v6 bundle anchor
        o.clear_anchor();
    });

    // Compact ironwood bundle (same compact redaction as orchard)
    redactor = redactor.redact_ironwood_with(|mut o| {
        o.redact_actions(|mut a| {
            // cv_net is deliberately NOT cleared. The signer rebuilds a redacted
            // cv_net in resolve_cv_net() from the SPEND value - but
            // redact_pczt_for_signer (applied above) has already stripped
            // spend.value for privacy, so a cleared cv_net is unrecoverable on
            // the device and it rejects the whole PCZT with
            // ParseError::InvalidValueCommitment. cv_net is public 32-byte
            // per-action data that appears in the final transaction regardless,
            // so retaining it leaks nothing; the large savings (cmx +
            // enc_ciphertext, both recoverable from retained output fields)
            // stay below.
            // Clear output cmx
            a.clear_cmx();
            // The 580-byte enc_ciphertext collapses to the memo trimmed to
            // its last nonzero byte - ONE byte for the empty memo a turnstile
            // migration uses. This is the single largest request-leg win
            // (measured: 2.53x smaller request on a v6 migration, vs 1.08x
            // without it). The signer re-encrypts it in `resolve_fields()`
            // from the retained recipient/value/rseed plus the spend
            // nullifier (rho), then runs every normal verification gate.
            //
            // MEMO_SIZE is crate-private upstream; it is 512 by spec.
            a.replace_enc_ciphertext_with_memo_plaintext([0u8; 512]);
        });
        // Clear v6 bundle anchor
        o.clear_anchor();
    });

    let pczt = redactor.finish();

    let serialized = pczt
        .serialize()
        .map_err(|e| JsError::new(&format!("pczt serialize failed: {:?}", e)))?;
    Ok(hex_encode(&serialized))
}

/// Apply spend-auth signatures to a compact PCZT received from a signer.
///
/// Signatures are supplied as a JSON array of objects with:
/// - `pool`: "orchard" or "ironwood"
/// - `action_index`: the action index in the corresponding bundle
/// - `signature_hex`: 64-byte spend-auth signature as hex
///
/// # Arguments
/// * `pczt_hex` - hex-encoded compact PCZT (typically from `redact_pczt_compact`)
/// * `contributions_json` - JSON array of signature contributions
///
/// # Returns
/// Hex-encoded PCZT with signatures applied
#[wasm_bindgen]
pub fn apply_signature_contributions(
    pczt_hex: &str,
    contributions_json: &str,
) -> Result<String, JsError> {
    use orchard::primitives::redpallas;

    let bytes = hex_decode(pczt_hex).ok_or_else(|| JsError::new("invalid pczt hex"))?;
    let pczt = pczt::Pczt::parse(&bytes)
        .map_err(|e| JsError::new(&format!("pczt parse failed: {:?}", e)))?;

    let contributions: Vec<serde_json::Value> = serde_json::from_str(contributions_json)
        .map_err(|e| JsError::new(&format!("failed to parse contributions JSON: {}", e)))?;

    let mut signer = pczt::roles::signer::Signer::new(pczt)
        .map_err(|e| JsError::new(&format!("signer init failed: {:?}", e)))?;

    for (i, contrib) in contributions.iter().enumerate() {
        let pool = contrib
            .get("pool")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsError::new(&format!("contribution[{}]: missing pool", i)))?;
        let action_index: usize = contrib
            .get("action_index")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .ok_or_else(|| JsError::new(&format!("contribution[{}]: missing action_index", i)))?;
        let signature_hex = contrib
            .get("signature_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsError::new(&format!("contribution[{}]: missing signature_hex", i)))?;

        let raw = hex_decode(signature_hex)
            .ok_or_else(|| JsError::new(&format!("contribution[{}]: invalid signature hex", i)))?;
        let arr: [u8; 64] = raw.as_slice().try_into().map_err(|_| {
            JsError::new(&format!("contribution[{}]: signature must be 64 bytes", i))
        })?;
        let sig = redpallas::Signature::<redpallas::SpendAuth>::from(arr);

        match pool {
            "orchard" => {
                signer
                    .apply_orchard_signature(action_index, sig)
                    .map_err(|e| {
                        JsError::new(&format!(
                            "apply_orchard_signature[{}]: {:?}",
                            action_index, e
                        ))
                    })?;
            }
            "ironwood" => {
                signer
                    .apply_ironwood_signature(action_index, sig)
                    .map_err(|e| {
                        JsError::new(&format!(
                            "apply_ironwood_signature[{}]: {:?}",
                            action_index, e
                        ))
                    })?;
            }
            _ => {
                return Err(JsError::new(&format!(
                    "contribution[{}]: unknown pool '{}'",
                    i, pool
                )));
            }
        }
    }

    let signed = signer.finish();
    let serialized = signed
        .serialize()
        .map_err(|e| JsError::new(&format!("pczt serialize failed: {:?}", e)))?;
    Ok(hex_encode(&serialized))
}

/// Estimate the size savings from compact PCZT redaction.
///
/// Returns JSON with `full_bytes` (original size) and `compact_bytes` (after redaction).
///
/// # Arguments
/// * `pczt_hex` - hex-encoded PCZT (v2 format)
///
/// # Returns
/// JSON string: `{"full_bytes": number, "compact_bytes": number}`
#[wasm_bindgen]
pub fn estimate_compact_savings(pczt_hex: &str) -> Result<String, JsError> {
    let bytes = hex_decode(pczt_hex).ok_or_else(|| JsError::new("invalid pczt hex"))?;
    let full_bytes = bytes.len();

    // Parse to validate before compact redaction
    let _pczt = pczt::Pczt::parse(&bytes)
        .map_err(|e| JsError::new(&format!("pczt parse failed: {:?}", e)))?;

    let compact_pczt = redact_pczt_compact(pczt_hex)?;
    let compact_bytes = hex_decode(&compact_pczt).map(|b| b.len()).unwrap_or(0);

    let result = serde_json::json!({
        "full_bytes": full_bytes,
        "compact_bytes": compact_bytes
    });

    Ok(result.to_string())
}

/// Canonical ZIP-244 txid for a raw signed v5 transaction.
///
/// Public lightwalletd's `SendResponse` carries no txid, so the wallet derives
/// it locally instead of trusting the server to echo it. This is the same value
/// zidecar computes server-side and the same bytes that appear as
/// `CompactTx.hash` during sync — returned as lowercase hex in internal/wire
/// byte order so the outgoing record reconciles on the next scan.
#[wasm_bindgen]
pub fn compute_txid(tx_hex: &str) -> Result<String, JsError> {
    use std::io::Cursor;
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::BranchId;

    let tx_bytes = hex_decode(tx_hex).ok_or_else(|| JsError::new("invalid tx hex"))?;
    // v5 reads its own consensus branch id from the header; the param only
    // matters for pre-v5 formats.
    let tx = Transaction::read(&mut Cursor::new(&tx_bytes), BranchId::Nu5)
        .map_err(|e| JsError::new(&format!("parse tx: {:?}", e)))?;
    let txid = tx.txid();
    let bytes: &[u8; 32] = txid.as_ref();
    Ok(hex_encode(bytes))
}

/// Get the commitment proof request data for a note
/// Returns the cmx that should be sent to zidecar's GetCommitmentProof
#[wasm_bindgen]
pub fn get_commitment_proof_request(note_cmx_hex: &str) -> Result<String, JsError> {
    // Just validate and return the cmx
    let cmx_bytes = hex_decode(note_cmx_hex).ok_or_else(|| JsError::new("Invalid cmx hex"))?;
    if cmx_bytes.len() != 32 {
        return Err(JsError::new("CMX must be 32 bytes"));
    }
    Ok(note_cmx_hex.to_string())
}

// ============================================================================
// Witness Building (merkle paths for orchard spends)
// ============================================================================

/// Build merkle paths for note positions by replaying compact blocks from a checkpoint.
///
/// # Arguments
/// * `tree_state_hex` - hex-encoded orchard frontier from GetTreeState
/// * `compact_blocks_json` - JSON array of `[{height, actions: [{cmx_hex}]}]`
/// * `note_positions_json` - JSON array of note positions `[position_u64, ...]`
/// * `anchor_height` - the block height to use as anchor
///
/// # Returns
/// JSON `{anchor_hex, paths: [{position, path: [{hash}]}]}`
#[wasm_bindgen]
pub fn build_merkle_paths(
    tree_state_hex: &str,
    compact_blocks_json: &str,
    note_positions_json: &str,
    anchor_height: u32,
) -> Result<JsValue, JsError> {
    let blocks: Vec<witness::CompactBlockData> = serde_json::from_str(compact_blocks_json)
        .map_err(|e| JsError::new(&format!("invalid compact_blocks_json: {}", e)))?;

    let positions: Vec<u64> = serde_json::from_str(note_positions_json)
        .map_err(|e| JsError::new(&format!("invalid note_positions_json: {}", e)))?;

    let result =
        witness::build_merkle_paths_inner(tree_state_hex, &blocks, &positions, anchor_height)
            .map_err(|e| JsError::new(&e.to_string()))?;

    let json = serde_json::to_string(&result)
        .map_err(|e| JsError::new(&format!("failed to serialize result: {}", e)))?;

    Ok(JsValue::from_str(&json))
}

/// Compute the tree size from a hex-encoded frontier.
#[wasm_bindgen]
pub fn frontier_tree_size(tree_state_hex: &str) -> Result<u64, JsError> {
    let data =
        hex::decode(tree_state_hex).map_err(|e| JsError::new(&format!("invalid hex: {}", e)))?;
    witness::compute_frontier_tree_size(&data).map_err(|e| JsError::new(&e.to_string()))
}

/// Compute the tree root from a hex-encoded frontier.
#[wasm_bindgen]
pub fn tree_root_hex(tree_state_hex: &str) -> Result<String, JsError> {
    let data =
        hex::decode(tree_state_hex).map_err(|e| JsError::new(&format!("invalid hex: {}", e)))?;
    let root = witness::compute_tree_root(&data).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(hex::encode(root))
}

/// Advance tracked witnesses over a range of compact blocks, optionally
/// seeding new ones. Returns JSON
/// `{end_frontier_hex, anchor_hex, witnesses: [{id, position, witness_hex}], seeded_ids: [...], end_position}`.
///
/// # Arguments
/// * `start_frontier_hex` - tree state BEFORE the first block
/// * `compact_blocks_json` - `[{height, actions: [{cmx_hex}]}]` in order
/// * `existing_witnesses_json` - `[{id, witness_hex}]` - witnesses to advance
/// * `new_notes_json` - `[{id, position}]` - witnesses to seed within this range
#[wasm_bindgen]
pub fn witness_sync_update(
    start_frontier_hex: &str,
    compact_blocks_json: &str,
    existing_witnesses_json: &str,
    new_notes_json: &str,
) -> Result<JsValue, JsError> {
    let blocks: Vec<witness::CompactBlockData> = serde_json::from_str(compact_blocks_json)
        .map_err(|e| JsError::new(&format!("invalid compact_blocks_json: {}", e)))?;
    let existing: Vec<witness::ExistingWitnessInput> =
        serde_json::from_str(existing_witnesses_json)
            .map_err(|e| JsError::new(&format!("invalid existing_witnesses_json: {}", e)))?;
    let new_notes: Vec<witness::NewNoteInput> = serde_json::from_str(new_notes_json)
        .map_err(|e| JsError::new(&format!("invalid new_notes_json: {}", e)))?;

    let result =
        witness::witness_sync_update_inner(start_frontier_hex, &blocks, &existing, &new_notes)
            .map_err(|e| JsError::new(&e.to_string()))?;

    let json = serde_json::to_string(&result)
        .map_err(|e| JsError::new(&format!("failed to serialize result: {}", e)))?;
    Ok(JsValue::from_str(&json))
}

/// Extract a merkle path from a stored per-note witness. Returns JSON
/// `{position, root_hex, path: [{hash}]}`. The caller must cross-check
/// `root_hex` against the anchor they intend to sign over.
#[wasm_bindgen]
pub fn witness_extract_path(witness_hex: &str) -> Result<JsValue, JsError> {
    let result = witness::witness_extract_path_inner(witness_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let json = serde_json::to_string(&result)
        .map_err(|e| JsError::new(&format!("failed to serialize result: {}", e)))?;
    Ok(JsValue::from_str(&json))
}

/// One-shot witness + path builder used for initial backfill: replays blocks
/// the same way `build_merkle_paths` does but also returns serialized
/// witnesses and the resulting frontier so the caller can cache them.
///
/// Returns JSON
/// `{anchor_hex, end_frontier_hex, entries: [{position, witness_hex, path: [{hash}]}]}`.
#[wasm_bindgen]
pub fn build_witnesses_and_paths(
    tree_state_hex: &str,
    compact_blocks_json: &str,
    note_positions_json: &str,
) -> Result<JsValue, JsError> {
    let blocks: Vec<witness::CompactBlockData> = serde_json::from_str(compact_blocks_json)
        .map_err(|e| JsError::new(&format!("invalid compact_blocks_json: {}", e)))?;
    let positions: Vec<u64> = serde_json::from_str(note_positions_json)
        .map_err(|e| JsError::new(&format!("invalid note_positions_json: {}", e)))?;

    let result = witness::build_witnesses_and_paths_inner(tree_state_hex, &blocks, &positions)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let json = serde_json::to_string(&result)
        .map_err(|e| JsError::new(&format!("failed to serialize result: {}", e)))?;
    Ok(JsValue::from_str(&json))
}

// ============================================================================
// Ironwood commitment tree / witnesses (NU6.3+)
//
// The ironwood pool keeps its OWN note commitment tree, but its node hash is
// the identical orchard sinsemilla hash (`MerkleHashOrchard::from_cmx` - see
// the fork's pczt/tests/end_to_end.rs ironwood tests). These exports are
// therefore thin delegates over the same witness machinery; the separation
// exists so the TS layer feeds ironwood tree state / ironwood bundle cmxs
// here and never mixes the two trees. Wire formats are identical to the
// orchard equivalents.
// ============================================================================

/// Ironwood-tree variant of `build_merkle_paths`. Same JSON contract; feed
/// the ironwood frontier from GetTreeState and cmxs from ironwood bundles.
#[wasm_bindgen]
pub fn build_merkle_paths_ironwood(
    tree_state_hex: &str,
    compact_blocks_json: &str,
    note_positions_json: &str,
    anchor_height: u32,
) -> Result<JsValue, JsError> {
    build_merkle_paths(
        tree_state_hex,
        compact_blocks_json,
        note_positions_json,
        anchor_height,
    )
}

/// Ironwood-tree variant of `witness_sync_update`. Same JSON contract.
#[wasm_bindgen]
pub fn witness_sync_update_ironwood(
    start_frontier_hex: &str,
    compact_blocks_json: &str,
    existing_witnesses_json: &str,
    new_notes_json: &str,
) -> Result<JsValue, JsError> {
    witness_sync_update(
        start_frontier_hex,
        compact_blocks_json,
        existing_witnesses_json,
        new_notes_json,
    )
}

/// Ironwood-tree variant of `witness_extract_path`. Same JSON contract.
#[wasm_bindgen]
pub fn witness_extract_path_ironwood(witness_hex: &str) -> Result<JsValue, JsError> {
    witness_extract_path(witness_hex)
}

/// Ironwood-tree variant of `frontier_tree_size`.
#[wasm_bindgen]
pub fn frontier_tree_size_ironwood(tree_state_hex: &str) -> Result<u64, JsError> {
    frontier_tree_size(tree_state_hex)
}

/// Ironwood-tree variant of `tree_root_hex`.
#[wasm_bindgen]
pub fn tree_root_hex_ironwood(tree_state_hex: &str) -> Result<String, JsError> {
    tree_root_hex(tree_state_hex)
}

// ============================================================================
// Note bundle encoding (CBOR for ur:zcash-notes)
// ============================================================================

/// Encode notes + merkle paths into CBOR bytes for ur:zcash-notes.
///
/// This produces the exact format zigner expects: CBOR map with anchor,
/// height, mainnet flag, notes array with merkle paths, and optional
/// attestation signature.
///
/// # Arguments
/// * `notes_json` - JSON array of `[{value, nullifier, cmx, position, block_height}]`
/// * `merkle_result_json` - JSON from build_merkle_paths: `{anchor_hex, paths: [{position, path: [{hash}]}]}`
/// * `anchor_height` - block height of the anchor
/// * `mainnet` - true for mainnet, false for testnet
/// * `attestation_hex` - optional hex-encoded 64-byte ed25519 anchor attestation
///   signature from a trusted verifier (zidecar SignAnchor). Verified on the
///   cold device against its anchor-verifier registry.
///
/// # Returns
/// `Uint8Array` of CBOR bytes ready for UR fountain encoding
#[wasm_bindgen]
pub fn encode_notes_bundle(
    notes_json: &str,
    merkle_result_json: &str,
    anchor_height: u32,
    mainnet: bool,
    attestation_hex: Option<String>,
) -> Result<Vec<u8>, JsError> {
    #[derive(serde::Deserialize)]
    struct NoteInput {
        value: u64,
        nullifier: String,
        cmx: String,
        position: u64,
        block_height: u32,
    }

    #[derive(serde::Deserialize)]
    struct PathElement {
        hash: String,
    }

    #[derive(serde::Deserialize)]
    struct MerklePath {
        #[allow(dead_code)]
        position: u64,
        path: Vec<PathElement>,
    }

    #[derive(serde::Deserialize)]
    struct MerkleResult {
        anchor_hex: String,
        paths: Vec<MerklePath>,
    }

    let notes: Vec<NoteInput> = serde_json::from_str(notes_json)
        .map_err(|e| JsError::new(&format!("bad notes JSON: {e}")))?;
    let merkle: MerkleResult = serde_json::from_str(merkle_result_json)
        .map_err(|e| JsError::new(&format!("bad merkle JSON: {e}")))?;

    if notes.len() != merkle.paths.len() {
        return Err(JsError::new(&format!(
            "notes ({}) and paths ({}) count mismatch",
            notes.len(),
            merkle.paths.len()
        )));
    }

    let anchor: [u8; 32] = hex::decode(&merkle.anchor_hex)
        .map_err(|e| JsError::new(&format!("bad anchor hex: {e}")))?
        .try_into()
        .map_err(|_| JsError::new("anchor must be 32 bytes"))?;

    let attestation: Option<[u8; 64]> = match attestation_hex {
        Some(h) if !h.is_empty() => {
            let bytes: [u8; 64] = hex::decode(&h)
                .map_err(|e| JsError::new(&format!("bad attestation hex: {e}")))?
                .try_into()
                .map_err(|_| JsError::new("attestation must be 64 bytes (ed25519 signature)"))?;
            Some(bytes)
        }
        _ => None,
    };

    // Build CBOR manually — same format as zcli's notes_export.rs
    let mut cbor = Vec::new();

    // map(5) or map(6): version + anchor + height + mainnet + notes [+ attestation]
    let map_len = 5 + if attestation.is_some() { 1 } else { 0 };
    cbor.push(0xa0 | map_len as u8);

    // key 0: version
    cbor.push(0x00);
    cbor.push(0x01); // version 1

    // key 1: anchor
    cbor.push(0x01);
    cbor.push(0x58);
    cbor.push(0x20);
    cbor.extend_from_slice(&anchor);

    // key 2: anchor_height
    cbor.push(0x02);
    cbor_uint(&mut cbor, anchor_height as u64);

    // key 3: mainnet
    cbor.push(0x03);
    cbor.push(if mainnet { 0xf5 } else { 0xf4 });

    // key 4: notes array
    cbor.push(0x04);
    cbor_array_len(&mut cbor, notes.len());

    for (note, mpath) in notes.iter().zip(merkle.paths.iter()) {
        // map(6) per note
        cbor.push(0xa6);

        // 1: value
        cbor.push(0x01);
        cbor_uint(&mut cbor, note.value);

        // 2: nullifier
        cbor.push(0x02);
        cbor.push(0x58);
        cbor.push(0x20);
        let nf = hex::decode(&note.nullifier)
            .map_err(|e| JsError::new(&format!("bad nullifier hex: {e}")))?;
        cbor.extend_from_slice(&nf);

        // 3: cmx
        cbor.push(0x03);
        cbor.push(0x58);
        cbor.push(0x20);
        let cm = hex::decode(&note.cmx).map_err(|e| JsError::new(&format!("bad cmx hex: {e}")))?;
        cbor.extend_from_slice(&cm);

        // 4: position
        cbor.push(0x04);
        cbor_uint(&mut cbor, note.position);

        // 5: block_height
        cbor.push(0x05);
        cbor_uint(&mut cbor, note.block_height as u64);

        // 6: merkle_path (array of 32 sibling hashes)
        cbor.push(0x06);
        cbor.push(0x98);
        cbor.push(0x20); // array(32)
        if mpath.path.len() != 32 {
            return Err(JsError::new(&format!(
                "merkle path must have 32 siblings, got {}",
                mpath.path.len()
            )));
        }
        for elem in &mpath.path {
            cbor.push(0x58);
            cbor.push(0x20);
            let hash = hex::decode(&elem.hash)
                .map_err(|e| JsError::new(&format!("bad path hash: {e}")))?;
            cbor.extend_from_slice(&hash);
        }
    }

    // key 5: attestation (optional, 64 bytes: ed25519 signature over the
    // anchor digest by a trusted verifier — matches zigner's decoder).
    if let Some(att) = attestation {
        cbor.push(0x05);
        cbor.push(0x58);
        cbor.push(0x40); // bytes(64)
        cbor.extend_from_slice(&att);
    }

    Ok(cbor)
}

/// Encode CBOR bytes as UR-encoded animated QR string frames.
/// Returns JSON array of UR strings suitable for QR display.
/// ur_type: e.g. "zcash-notes", "zigner-contacts", "zigner-backup"
/// fragment_size: max bytes per QR frame (200-500 typical, 0 = single QR)
#[wasm_bindgen]
pub fn ur_encode_frames(
    cbor_data: &[u8],
    ur_type: &str,
    fragment_size: u32,
) -> Result<String, JsError> {
    let frames = if fragment_size == 0 || cbor_data.len() <= fragment_size as usize {
        let single = ur::ur::encode(cbor_data, &ur::ur::Type::Custom(ur_type));
        vec![single]
    } else {
        let mut encoder = ur::ur::Encoder::new(cbor_data, fragment_size as usize, ur_type)
            .map_err(|e| JsError::new(&format!("UR encoder: {e:?}")))?;
        let count = encoder.fragment_count();
        let mut parts = Vec::with_capacity(count * 2);
        // Generate 2x fragments for fountain code redundancy
        for _ in 0..count * 2 {
            let part = encoder
                .next_part()
                .map_err(|e| JsError::new(&format!("UR part: {e:?}")))?;
            parts.push(part);
        }
        parts
    };
    serde_json::to_string(&frames).map_err(|e| JsError::new(&format!("JSON: {e}")))
}

/// Decode UR-encoded animated QR string frames back into CBOR bytes.
///
/// Accepts a JSON array of UR strings (each `ur:<type>/...`) collected from
/// successive scans of an animated QR. Returns the reconstructed payload bytes
/// once the fountain decoder has enough frames (deduplicated internally), or an
/// error if the parts are malformed or the fountain code can't yet reconstruct.
///
/// `expected_type` is a sanity check: if non-empty, parts whose UR type doesn't
/// match are rejected. Pass `""` to accept any type.
///
/// Returns hex-encoded payload bytes (caller can hex_decode if it wants raw).
/// We return hex (rather than `Vec<u8>` directly) to avoid a wasm-bindgen
/// `Uint8Array` allocation pattern that's been flaky for us in some browsers.
/// Maximum number of UR fountain parts accepted in a single call. Real PCZT
/// signing sessions need on the order of tens to low hundreds of parts;
/// adversarial inputs without a cap can OOM the wasm module since the host
/// hands us the raw JSON-deserialized `Vec<String>` before we touch any
/// fountain logic.
const MAX_UR_PARTS: usize = 256;

/// Maximum bytes per single UR fountain frame. The BC-UR spec doesn't pin
/// frame size, but real emitters use ~100-500 B; 8 KiB is comfortably above
/// real traffic and stops oversized adversarial payloads.
const MAX_UR_PART_BYTES: usize = 8 * 1024;

/// Generous upper bound on the raw JSON envelope. Each part is capped at
/// MAX_UR_PART_BYTES, so a worst-case legitimate envelope is roughly
/// MAX_UR_PARTS * (MAX_UR_PART_BYTES + JSON-quoting overhead). Doubling
/// MAX_UR_PART_BYTES per part covers JSON escaping of binary-ish bytes
/// without being so generous it negates the cap.
const MAX_UR_PARTS_JSON_BYTES: usize = MAX_UR_PARTS * (MAX_UR_PART_BYTES * 2 + 16);

#[wasm_bindgen]
pub fn ur_decode_frames(parts_json: &str, expected_type: &str) -> Result<String, JsError> {
    // Cap the raw input before serde_json::from_str allocates the Vec — a
    // 1 GiB JSON string would otherwise materialise in linear memory before
    // any post-parse length check fires.
    if parts_json.len() > MAX_UR_PARTS_JSON_BYTES {
        return Err(JsError::new(&format!(
            "UR parts JSON length {} exceeds cap {MAX_UR_PARTS_JSON_BYTES} B",
            parts_json.len()
        )));
    }
    let parts: Vec<String> = serde_json::from_str(parts_json)
        .map_err(|e| JsError::new(&format!("ur parts JSON: {e}")))?;
    if parts.is_empty() {
        return Err(JsError::new("no UR parts provided"));
    }
    if parts.len() > MAX_UR_PARTS {
        return Err(JsError::new(&format!(
            "UR parts count {} exceeds cap {MAX_UR_PARTS}",
            parts.len()
        )));
    }
    if let Some((i, p)) = parts
        .iter()
        .enumerate()
        .find(|(_, p)| p.len() > MAX_UR_PART_BYTES)
    {
        return Err(JsError::new(&format!(
            "UR part {i} length {} exceeds cap {MAX_UR_PART_BYTES} B",
            p.len()
        )));
    }
    let mut decoder = ur::ur::Decoder::default();
    for (i, p) in parts.iter().enumerate() {
        // Optional type guard. Reject parts whose `ur:<type>/...` doesn't match
        // the expected type — defends against scanner pulling in an unrelated
        // QR mid-stream and confusing the fountain decoder.
        if !expected_type.is_empty() {
            let lower = p.to_ascii_lowercase();
            let prefix = format!("ur:{}/", expected_type.to_ascii_lowercase());
            if !lower.starts_with(&prefix) {
                return Err(JsError::new(&format!(
                    "UR part {i} has wrong type (expected ur:{expected_type}/…)"
                )));
            }
        }
        decoder
            .receive(p)
            .map_err(|e| JsError::new(&format!("UR receive part {i}: {e:?}")))?;
    }
    if !decoder.complete() {
        return Err(JsError::new(
            "UR fountain decoder still incomplete — need more frames",
        ));
    }
    let bytes = decoder
        .message()
        .map_err(|e| JsError::new(&format!("UR message: {e:?}")))?
        .ok_or_else(|| JsError::new("UR decoder reported complete but produced no message"))?;
    Ok(hex_encode(&bytes))
}

/// Encode CBOR bytes as zoda transport QR frames (verified erasure coding).
/// Returns JSON array of `zt:type/hex` strings.
/// k = minimum frames to reconstruct, n = total frames.
#[wasm_bindgen]
pub fn zt_encode_frames(cbor_data: &[u8], zt_type: &str, k: u8, n: u8) -> Result<String, JsError> {
    let (frames, _) = zoda_vss::transport::Encoder::encode(cbor_data, k, n);
    let strings: Vec<String> = frames
        .iter()
        .map(|f| format!("zt:{}/{}", zt_type, hex::encode(f.to_bytes())))
        .collect();
    serde_json::to_string(&strings).map_err(|e| JsError::new(&format!("JSON: {e}")))
}

/// Encode CBOR bytes as zoda transport QR frames, auto-sizing `k`/`n` so each
/// hex-encoded `zt:` frame fits a scannable QR regardless of payload size.
/// Returns JSON array of `zt:type/hex` strings.
///
/// - `max_qr_bytes`: max *raw* frame bytes before hex encoding. The QR string
///   is `len("zt:type/") + 2 * frame_bytes`, so pick this from the target QR
///   capacity: roughly `qr_byte_capacity / 2 - prefix`. ~600 gives a ~1.2 KB
///   QR string (≈ v24 at ECC-L), comfortable for handheld scanning.
/// - `redundancy_pct`: extra parity frames as a percentage of `k` (e.g. 30).
#[wasm_bindgen]
pub fn zt_encode_frames_auto(
    cbor_data: &[u8],
    zt_type: &str,
    max_qr_bytes: usize,
    redundancy_pct: u8,
) -> Result<String, JsError> {
    let (frames, _) =
        zoda_vss::transport::Encoder::encode_auto(cbor_data, max_qr_bytes, redundancy_pct);
    let strings: Vec<String> = frames
        .iter()
        .map(|f| format!("zt:{}/{}", zt_type, hex::encode(f.to_bytes())))
        .collect();
    serde_json::to_string(&strings).map_err(|e| JsError::new(&format!("JSON: {e}")))
}

fn cbor_uint(out: &mut Vec<u8>, val: u64) {
    if val <= 23 {
        out.push(val as u8);
    } else if val <= 0xff {
        out.push(0x18);
        out.push(val as u8);
    } else if val <= 0xffff {
        out.push(0x19);
        out.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= 0xffff_ffff {
        out.push(0x1a);
        out.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        out.push(0x1b);
        out.extend_from_slice(&val.to_be_bytes());
    }
}

fn cbor_array_len(out: &mut Vec<u8>, len: usize) {
    if len <= 23 {
        out.push(0x80 | len as u8);
    } else if len <= 0xff {
        out.push(0x98);
        out.push(len as u8);
    } else {
        out.push(0x99);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

/// Authoritatively validate a Unified Full Viewing Key string.
///
/// Returns `true` iff the string decodes via the *same*
/// `zcash_keys::UnifiedFullViewingKey::decode` the signing path uses. This
/// is deliberately the one and only UFVK decoder: a separate hand-rolled
/// bech32m/checksum validator at the import boundary would be a second
/// implementation that can disagree with the authority, which is worse than
/// no check. Structural pre-screening (HRP/charset/length) still happens in
/// the pure `@repo/wallet` parser for cheap fail-fast and to keep that
/// package wasm-free; this is the cryptographic gate the import dispatch
/// calls before persisting a wallet record.
///
/// Network is inferred from the HRP (`uview1` = mainnet, else testnet),
/// matching every other UFVK entry point in this module.
#[wasm_bindgen]
pub fn validate_ufvk(ufvk_str: &str) -> bool {
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_protocol::consensus::{MainNetwork, TestNetwork};
    if ufvk_str.starts_with("uview1") {
        UnifiedFullViewingKey::decode(&MainNetwork, ufvk_str).is_ok()
    } else {
        UnifiedFullViewingKey::decode(&TestNetwork, ufvk_str).is_ok()
    }
}

/// Derive an Orchard receiving address from a UFVK string (uview1.../uviewtest1...)
#[wasm_bindgen]
pub fn address_from_ufvk(ufvk_str: &str, diversifier_index: u32) -> Result<String, JsError> {
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_protocol::consensus::{MainNetwork, TestNetwork};

    let ufvk = if ufvk_str.starts_with("uview1") {
        UnifiedFullViewingKey::decode(&MainNetwork, ufvk_str)
    } else {
        UnifiedFullViewingKey::decode(&TestNetwork, ufvk_str)
    }
    .map_err(|e| JsError::new(&format!("invalid UFVK: {}", e)))?;

    let mainnet = ufvk_str.starts_with("uview1") && !ufvk_str.starts_with("uviewtest");

    // get the orchard FVK from the UFVK
    let orchard_fvk_old = ufvk
        .orchard()
        .ok_or_else(|| JsError::new("UFVK has no orchard component"))?;

    // derive address at diversifier index
    let addr_old =
        orchard_fvk_old.address_at(diversifier_index as u64, orchard::keys::Scope::External);
    let raw = addr_old.to_raw_address_bytes();

    // encode as unified address string
    let addr = Option::from(orchard::Address::from_raw_address_bytes(&raw))
        .ok_or_else(|| JsError::new("invalid orchard address bytes"))?;

    Ok(encode_orchard_address(&addr, mainnet))
}

/// Derive a transparent (t1.../tm...) address from a UFVK string at a given address index.
/// Returns the base58check-encoded P2PKH address.
#[wasm_bindgen]
pub fn transparent_address_from_ufvk(
    ufvk_str: &str,
    address_index: u32,
) -> Result<String, JsError> {
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_protocol::consensus::{MainNetwork, TestNetwork};

    let mainnet = ufvk_str.starts_with("uview1") && !ufvk_str.starts_with("uviewtest");

    let ufvk = if mainnet {
        UnifiedFullViewingKey::decode(&MainNetwork, ufvk_str)
    } else {
        UnifiedFullViewingKey::decode(&TestNetwork, ufvk_str)
    }
    .map_err(|e| JsError::new(&format!("invalid UFVK: {}", e)))?;

    let account_pubkey = ufvk
        .transparent()
        .ok_or_else(|| JsError::new("UFVK has no transparent component"))?;

    let external_ivk = account_pubkey
        .derive_external_ivk()
        .map_err(|e| JsError::new(&format!("failed to derive external IVK: {}", e)))?;

    use zcash_transparent::keys::IncomingViewingKey;
    let child_index = zcash_transparent::keys::NonHardenedChildIndex::from_index(address_index)
        .ok_or_else(|| JsError::new("address index out of range"))?;

    let t_addr = external_ivk
        .derive_address(child_index)
        .map_err(|e| JsError::new(&format!("failed to derive transparent address: {}", e)))?;

    // extract pubkey hash
    let pkh = match t_addr {
        zcash_transparent::address::TransparentAddress::PublicKeyHash(hash) => hash,
        _ => return Err(JsError::new("unexpected transparent address type")),
    };

    // encode as base58check P2PKH
    let version = if mainnet { [0x1c, 0xb8] } else { [0x1d, 0x25] };
    let mut payload = Vec::with_capacity(26);
    payload.extend_from_slice(&version);
    payload.extend_from_slice(&pkh);
    use sha2::Digest;
    let checksum = sha2::Sha256::digest(sha2::Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);
    Ok(base58_encode(&payload))
}

/// Base58 encode (no checksum — caller provides full payload including checksum)
fn base58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // count leading zeros
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // convert to base58
    let mut digits: Vec<u8> = vec![0];
    for &byte in data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) * 256;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    // build string: leading '1's + reversed digits
    let mut result = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        result.push('1');
    }
    for &d in digits.iter().rev() {
        result.push(ALPHABET[d as usize] as char);
    }
    result
}

// ============================================================================
// Signed Spend Transaction (mnemonic wallets — no cold signing needed)
// ============================================================================

/// A spendable note with rseed and rho for reconstruction
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct SpendableNote {
    value: u64,
    nullifier: String,
    cmx: String,
    position: u64,
    rseed_hex: String,
    rho_hex: String,
    /// raw orchard recipient address bytes (hex, 43 bytes) — captured during scan
    #[serde(default)]
    recipient_hex: String,
}

/// Build a fully signed orchard spend transaction from a mnemonic wallet.
///
/// Unlike `build_unsigned_transaction` (for cold signing), this function
/// derives the spending key from the mnemonic, constructs the full orchard
/// bundle with Halo 2 proofs, and returns a broadcast-ready transaction.
///
/// # Arguments
/// * `seed_phrase` - BIP39 mnemonic for key derivation
/// * `notes_json` - JSON array of spendable notes with rseed/rho
/// * `recipient` - unified address string (u1... or utest1...)
/// * `amount` - zatoshis to send
/// * `fee` - transaction fee in zatoshis
/// * `anchor_hex` - merkle tree anchor (hex, 32 bytes)
/// * `merkle_paths_json` - JSON array of merkle paths from witness building
/// * `account_index` - ZIP-32 account index
/// * `mainnet` - true for mainnet, false for testnet
///
/// # Returns
/// Hex-encoded signed v5 transaction bytes ready for broadcast
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn build_signed_spend_transaction(
    seed_phrase: &str,
    notes_json: JsValue,
    recipient: &str,
    amount: u64,
    fee: u64,
    anchor_hex: &str,
    merkle_paths_json: JsValue,
    account_index: u32,
    mainnet: bool,
    memo_hex: Option<String>,
    // Live consensus branch id from GetLightdInfo.consensusBranchId, e.g.
    // "5437f330" (NU6.2) or "37a5165b" (NU6.3). Pass verbatim. REQUIRED: a
    // missing/unparseable value is a hard error, never a silent default.
    branch_id_hex: Option<String>,
) -> Result<String, JsError> {
    use orchard::builder::{Builder, BundleType};
    use orchard::keys::SpendAuthorizingKey;
    use orchard::note::{RandomSeed, Rho};
    use orchard::tree::{Anchor, MerkleHashOrchard, MerklePath as OrchardMerklePath};
    use orchard::value::NoteValue;
    use rand::rngs::OsRng;
    use zcash_protocol::value::ZatBalance;

    // FAIL-CLOSED, BEFORE any proving: see build_unsigned_transaction.
    let branch_id: u32 =
        resolve_branch_id(branch_id_hex.as_deref()).map_err(|e| JsError::new(&e))?;
    guard_orchard_spend_allowed(branch_id).map_err(|e| JsError::new(&e))?;

    // --- derive keys from mnemonic ---
    let mnemonic = bip39::Mnemonic::parse(seed_phrase)
        .map_err(|e| JsError::new(&format!("invalid mnemonic: {}", e)))?;
    let seed = mnemonic.to_seed("");

    let coin_type = if mainnet { 133 } else { 1 };
    let account_id = zip32::AccountId::try_from(account_index)
        .map_err(|_| JsError::new("invalid account index"))?;

    let sk = SpendingKey::from_zip32_seed(&seed, coin_type, account_id)
        .map_err(|e| JsError::new(&format!("spending key derivation failed: {:?}", e)))?;
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let ask = SpendAuthorizingKey::from(&sk);

    // derive change address (internal scope, diversifier 0)
    let change_addr = fvk.to_ivk(Scope::Internal).address_at(0u64);

    // --- parse recipient (orchard or transparent) ---
    let is_transparent = recipient.starts_with("t1") || recipient.starts_with("tm");
    let recipient_addr = if is_transparent {
        None // transparent recipient — no orchard output for the recipient
    } else {
        Some(
            parse_orchard_address(recipient, mainnet)
                .map_err(|e| JsError::new(&format!("invalid recipient: {}", e)))?,
        )
    };
    let t_output_script = if is_transparent {
        Some(
            decode_t_address_script(recipient, mainnet)
                .map_err(|e| JsError::new(&format!("invalid transparent address: {}", e)))?,
        )
    } else {
        None
    };

    // --- parse anchor ---
    let anchor_bytes = hex_decode(anchor_hex).ok_or_else(|| JsError::new("invalid anchor hex"))?;
    if anchor_bytes.len() != 32 {
        return Err(JsError::new("anchor must be 32 bytes"));
    }
    let mut anchor_arr = [0u8; 32];
    anchor_arr.copy_from_slice(&anchor_bytes);
    let anchor = Option::from(Anchor::from_bytes(anchor_arr))
        .ok_or_else(|| JsError::new("invalid anchor"))?;

    // --- parse notes and merkle paths ---
    let notes: Vec<SpendableNote> = serde_wasm_bindgen::from_value(notes_json)
        .map_err(|e| JsError::new(&format!("invalid notes: {}", e)))?;
    let merkle_paths: Vec<MerklePathInfo> = serde_wasm_bindgen::from_value(merkle_paths_json)
        .map_err(|e| JsError::new(&format!("invalid merkle paths: {}", e)))?;

    if notes.len() != merkle_paths.len() {
        return Err(JsError::new("notes and merkle paths count mismatch"));
    }

    // --- calculate totals ---
    let total_input: u64 = notes.iter().map(|n| n.value).sum();
    if total_input < amount + fee {
        return Err(JsError::new(&format!(
            "insufficient funds: {} < {} + {}",
            total_input, amount, fee
        )));
    }
    let change = total_input - amount - fee;

    // --- build orchard bundle ---
    // NU6.1-branch V5 tx: legacy orchard pool, pre-NU6.2 (historical) circuit.
    let bundle_type = BundleType::Transactional {
        bundle_required: true,
        pad_to_minimum: None,
    };
    let mut builder = Builder::new(
        bundle_type,
        orchard::bundle::BundleVersion::orchard_insecure_v1(),
        orchard::bundle::Flags::ENABLED,
        anchor,
    )
    .expect("flags are representable under this bundle version");

    // add spends
    for (i, note_info) in notes.iter().enumerate() {
        // reconstruct the orchard::Note from stored rseed + rho + value + address
        let rho_bytes = hex_decode(&note_info.rho_hex)
            .ok_or_else(|| JsError::new(&format!("invalid rho hex for note {}", i)))?;
        if rho_bytes.len() != 32 {
            return Err(JsError::new(&format!(
                "rho must be 32 bytes for note {}",
                i
            )));
        }
        let mut rho_arr = [0u8; 32];
        rho_arr.copy_from_slice(&rho_bytes);
        let rho = Option::from(Rho::from_bytes(&rho_arr))
            .ok_or_else(|| JsError::new(&format!("invalid rho for note {}", i)))?;

        let rseed_bytes = hex_decode(&note_info.rseed_hex)
            .ok_or_else(|| JsError::new(&format!("invalid rseed hex for note {}", i)))?;
        if rseed_bytes.len() != 32 {
            return Err(JsError::new(&format!(
                "rseed must be 32 bytes for note {}",
                i
            )));
        }
        let mut rseed_arr = [0u8; 32];
        rseed_arr.copy_from_slice(&rseed_bytes);
        let rseed = Option::from(RandomSeed::from_bytes(rseed_arr, &rho))
            .ok_or_else(|| JsError::new(&format!("invalid rseed for note {}", i)))?;

        let note_value = NoteValue::from_raw(note_info.value);

        // use stored recipient address from scan (handles diversified addresses correctly)
        let note: orchard::Note = if !note_info.recipient_hex.is_empty() {
            let addr_bytes = hex_decode(&note_info.recipient_hex)
                .ok_or_else(|| JsError::new(&format!("invalid recipient hex for note {}", i)))?;
            let addr_arr: [u8; 43] = addr_bytes
                .try_into()
                .map_err(|_| JsError::new(&format!("recipient must be 43 bytes for note {}", i)))?;
            let addr = Option::from(orchard::Address::from_raw_address_bytes(&addr_arr))
                .ok_or_else(|| JsError::new(&format!("invalid orchard address for note {}", i)))?;
            Option::from(orchard::Note::from_parts(
                addr,
                note_value,
                rho,
                rseed,
                orchard::note::NoteVersion::V2,
            ))
            .ok_or_else(|| {
                JsError::new(&format!(
                    "failed to reconstruct note {} from stored address",
                    i
                ))
            })?
        } else {
            // fallback: try default addresses (legacy notes without stored recipient)
            let ext_addr = fvk.to_ivk(Scope::External).address_at(0u64);
            let int_addr = fvk.to_ivk(Scope::Internal).address_at(0u64);
            Option::from(orchard::Note::from_parts(
                ext_addr,
                note_value,
                rho,
                rseed,
                orchard::note::NoteVersion::V2,
            ))
            .or_else(|| {
                Option::from(orchard::Note::from_parts(
                    int_addr,
                    note_value,
                    rho,
                    rseed,
                    orchard::note::NoteVersion::V2,
                ))
            })
            .ok_or_else(|| {
                JsError::new(&format!(
                    "failed to reconstruct note {} — rseed/rho/value mismatch",
                    i
                ))
            })?
        };

        // verify the reconstructed note matches the expected cmx
        let expected_cmx = hex_decode(&note_info.cmx)
            .ok_or_else(|| JsError::new(&format!("invalid cmx hex for note {}", i)))?;
        let reconstructed_cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
        if hex_encode(&reconstructed_cmx.to_bytes()) != hex_encode(&expected_cmx) {
            return Err(JsError::new(&format!(
                "cmx mismatch for note {}: reconstructed={} expected={}",
                i,
                hex_encode(&reconstructed_cmx.to_bytes()),
                hex_encode(&expected_cmx)
            )));
        }

        // parse merkle path
        let mp = &merkle_paths[i];
        if mp.path.len() != 32 {
            return Err(JsError::new(&format!(
                "merkle path must have 32 elements, got {} for note {}",
                mp.path.len(),
                i
            )));
        }

        let mut auth_path = [[0u8; 32]; 32];
        for (j, hash_hex) in mp.path.iter().enumerate() {
            let hash_bytes = hex_decode(hash_hex)
                .ok_or_else(|| JsError::new(&format!("invalid merkle path hash at {}/{}", i, j)))?;
            if hash_bytes.len() != 32 {
                return Err(JsError::new(&format!(
                    "merkle path hash must be 32 bytes at {}/{}",
                    i, j
                )));
            }
            auth_path[j].copy_from_slice(&hash_bytes);
        }

        // Positional decode with a precise per-sibling error. See the
        // matching comment at the other call site for the rationale (lossy
        // filter_map collapse erased which sibling failed, undiagnosable on
        // hardware; a wrong path is still caught downstream by orchard's
        // has_matching_anchor).
        let mut merkle_hashes_arr: [MerkleHashOrchard; 32] =
            [MerkleHashOrchard::from_bytes(&[0u8; 32]).unwrap(); 32];
        for (j, bytes) in auth_path.iter().enumerate() {
            merkle_hashes_arr[j] =
                Option::from(MerkleHashOrchard::from_bytes(bytes)).ok_or_else(|| {
                    JsError::new(&format!(
                        "merkle sibling {}/{} is not a canonical Pallas base element: {}",
                        i,
                        j,
                        hex_encode(bytes),
                    ))
                })?;
        }
        let merkle_hashes: Vec<MerkleHashOrchard> = merkle_hashes_arr.to_vec();

        let merkle_path = OrchardMerklePath::from_parts(
            u32::try_from(mp.position).map_err(|_| {
                JsError::new(&format!("tree position {} exceeds u32 max", mp.position))
            })?,
            merkle_hashes
                .try_into()
                .map_err(|_| JsError::new("merkle path conversion"))?,
        );

        builder
            .add_spend(fvk.clone(), note, merkle_path)
            .map_err(|e| JsError::new(&format!("add_spend for note {}: {:?}", i, e)))?;
    }

    // decode memo — recipient gets the memo, change output stays empty.
    let recipient_memo = decode_memo_hex(memo_hex.as_deref())?;

    // OVK for outputs: bind out_ciphertext to the wallet's OVK so the FVK
    // holder can recover (recipient, amount) — outgoing-tx history without
    // re-querying the chain. Network privacy unchanged.
    let ovk_external = fvk.to_ovk(Scope::External);
    let ovk_internal = fvk.to_ovk(Scope::Internal);

    // add recipient output (orchard only — transparent outputs are added to the tx directly)
    if let Some(ref addr) = recipient_addr {
        builder
            .add_output(
                Some(ovk_external.clone()),
                *addr,
                NoteValue::from_raw(amount),
                recipient_memo,
            )
            .map_err(|e| JsError::new(&format!("add_output (recipient): {:?}", e)))?;
    }

    // add change output if needed (for z→t, all orchard value minus amount+fee goes to change)
    if change > 0 {
        builder
            .add_output(
                Some(ovk_internal.clone()),
                change_addr,
                NoteValue::from_raw(change),
                // canonical ZIP-302 no-memo, not 512 zero bytes (see ZIP302_NO_MEMO)
                ZIP302_NO_MEMO,
            )
            .map_err(|e| JsError::new(&format!("add_output (change): {:?}", e)))?;
    }

    // --- build, prove, sign ---
    let mut rng = OsRng;
    let (unauthorized_bundle, _meta) = builder
        .build::<ZatBalance>(&mut rng)
        .map_err(|e| JsError::new(&format!("bundle build: {:?}", e)))?
        .ok_or_else(|| JsError::new("builder produced no bundle"))?;

    // Halo 2 proof generation (expensive)
    let proven_bundle = with_proving_key(|pk| unauthorized_bundle.create_proof(pk, &mut rng))
        .map_err(|e| JsError::new(&format!("create_proof: {:?}", e)))?;

    // --- compute ZIP-244 sighash (branch id resolved+gated at entry) ---
    let expiry_height: u32 = 0; // no expiry for orchard-only

    let header_data = {
        let mut d = Vec::new();
        d.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
        d.extend_from_slice(&0x26A7270Au32.to_le_bytes());
        d.extend_from_slice(&branch_id.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
        d.extend_from_slice(&expiry_height.to_le_bytes());
        d
    };
    let header_digest = blake2b_256_personal(b"ZTxIdHeadersHash", &header_data);

    // transparent digest (includes outputs for z→t)
    let transparent_digest = if let Some(ref script) = t_output_script {
        let prevouts_digest = blake2b_256_personal(b"ZTxIdPrevoutHash", &[]);
        let sequence_digest = blake2b_256_personal(b"ZTxIdSequencHash", &[]);
        let mut outputs_data = Vec::new();
        outputs_data.extend_from_slice(&amount.to_le_bytes());
        outputs_data.extend_from_slice(&compact_size(script.len() as u64));
        outputs_data.extend_from_slice(script);
        let outputs_digest = blake2b_256_personal(b"ZTxIdOutputsHash", &outputs_data);
        let mut d = Vec::new();
        d.extend_from_slice(&prevouts_digest);
        d.extend_from_slice(&sequence_digest);
        d.extend_from_slice(&outputs_digest);
        blake2b_256_personal(b"ZTxIdTranspaHash", &d)
    } else {
        blake2b_256_personal(b"ZTxIdTranspaHash", &[])
    };
    let sapling_digest = blake2b_256_personal(b"ZTxIdSaplingHash", &[]);

    let orchard_digest = compute_orchard_digest(&proven_bundle)?;

    let sighash_personal = {
        let mut p = [0u8; 16];
        p[..12].copy_from_slice(b"ZcashTxHash_");
        p[12..16].copy_from_slice(&branch_id.to_le_bytes());
        p
    };

    let mut sighash_input = Vec::new();
    sighash_input.extend_from_slice(&header_digest);
    sighash_input.extend_from_slice(&transparent_digest);
    sighash_input.extend_from_slice(&sapling_digest);
    sighash_input.extend_from_slice(&orchard_digest);

    let sighash = blake2b_256_personal(&sighash_personal, &sighash_input);

    // apply spend auth signatures + binding signature
    let authorized_bundle = proven_bundle
        .apply_signatures(rng, sighash, &[ask])
        .map_err(|e| JsError::new(&format!("apply_signatures: {:?}", e)))?;

    // --- serialize v5 transaction ---
    let mut tx_bytes = Vec::new();

    // header
    tx_bytes.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
    tx_bytes.extend_from_slice(&0x26A7270Au32.to_le_bytes());
    tx_bytes.extend_from_slice(&branch_id.to_le_bytes());
    tx_bytes.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
    tx_bytes.extend_from_slice(&expiry_height.to_le_bytes());

    // transparent inputs (none)
    tx_bytes.extend_from_slice(&compact_size(0)); // vin
                                                  // transparent outputs
    if let Some(ref script) = t_output_script {
        tx_bytes.extend_from_slice(&compact_size(1)); // 1 vout
        tx_bytes.extend_from_slice(&amount.to_le_bytes());
        tx_bytes.extend_from_slice(&compact_size(script.len() as u64));
        tx_bytes.extend_from_slice(script);
    } else {
        tx_bytes.extend_from_slice(&compact_size(0)); // 0 vout
    }

    // sapling (none)
    tx_bytes.extend_from_slice(&compact_size(0)); // spends
    tx_bytes.extend_from_slice(&compact_size(0)); // outputs

    // orchard bundle
    serialize_orchard_bundle(&authorized_bundle, &mut tx_bytes)?;

    Ok(hex_encode(&tx_bytes))
}

#[test]
fn test_user_seed_with_real_action() {
    let seed_phrase = "master bid journey tank since conduct fire picture medal toward dish trend army true cushion ramp yellow high once jealous van occur swamp liberty";
    let keys = WalletKeys::from_seed_phrase(seed_phrase).unwrap();
    let addr = keys.get_address();
    println!("User wallet address ID: {}", addr);

    // Real action from tx 23803f17eeaa1617fa26c910a4215f618a16f011bf18b81613b0436894f59d76
    // block 3128610 - this is the shielding tx that should have user's notes
    let nullifier =
        hex_decode("41291fa8172173e9cc0d205b064e781a4277ceb7736c52dcb9784d2665987438").unwrap();
    let cmx =
        hex_decode("72dc616c3019a39216dbf74a240ada0aeac4a5eebae409d46d32fac835848934").unwrap();
    let epk =
        hex_decode("9db06408843a4a34686b6d375ad88915eb387787f2a55c01f97e264161e505b5").unwrap();
    let enc_ciphertext = hex_decode("cf94455b13ad0d815492fecb913abc26eb9edbc5b06d1ca9d1d08959ad60b63d9267ad7d20c38ba9a323cdefabe8561a0edf2f59ef6cfdfe6927652c5793e3912a64175d27ec35254563a39a77a79075c30edb446ce040f77c73ce60de28ea21f191532e46110867a08f0ef69a37fd208d5f55a6e664c0065fb162c24d5fc906f8f5cddb898a34ffa4b0609d9b6d419dbc099808ee5f644fd619985326a781ed447e5bba88044d2f787bb1d68d186f9e089434b70e090cb18fc466e2949798b7c9363bd3be5411a5c4abfad3fac153565ce37b0db588b890e8f03afffcaa723b6eb2376bdfc1ffe0e64b9f6893229a8b290e05aa478b12841fba2b1c68c8e1ec8ba22b40c27523c67001b57fd426edf3d2180e2a2c6f9cc2b0c5155a1a27272fd58902c8b7eabca6a5e2a8c5597bfc33526ef5dac4db7f841e6d7aa3166e9e7c73b53da12896cfaa88b343ef8d90b7ca5bcdc39fee1609da41efeaefe05cbc2e10682691335c9c772c274b7da3607cf6235a01664d4c330f3fdabeee61216e543919b1216df86d5eb1e395be9afacd760b8ce05ea465cfe3c815cc67cbf96379772a1c71a77462077d096c75e43374aa98b6fa441bdfeb0c7109140303fd57e2470eedc71a0bb5dfdb540731b960d9e17c5cff5c29f228e0056e42c8c30aedac34eb812ddad91613c089a7f8c1ec21393fa5db2cb27dfaf9d0e59f41e4842f5f5d9401d2aec0ebec8e20807524e3c47076f86d945dea492fd0152f8edbf35b0df4cd1aa808eb2945d61ead63e364ceef9aacdd91d76e396da2f8fcb0486d0c89606582c6").unwrap();

    // Build compact action (first 52 bytes of ciphertext only)
    let mut ciphertext = [0u8; 52];
    ciphertext.copy_from_slice(&enc_ciphertext[..52]);

    let action = CompactActionBinary {
        nullifier: nullifier.try_into().unwrap(),
        cmx: cmx.try_into().unwrap(),
        epk: epk.try_into().unwrap(),
        ciphertext,
    };

    // Try to decrypt with both scopes via the shared scan helper
    let result = try_decrypt_compact_action(
        &keys.fvk,
        &keys.prepared_ivk_external,
        &keys.prepared_ivk_internal,
        &action,
        DomainChoice::Either,
    );
    println!(
        "Decryption result: {:?}",
        result.map(|d| (d.value, hex_encode(&d.nullifier), d.is_change))
    );

    // Also try Internal scope
    let mnemonic = bip39::Mnemonic::parse(seed_phrase).unwrap();
    let seed = mnemonic.to_seed("");
    let sk = SpendingKey::from_zip32_seed(&seed, 133, zip32::AccountId::ZERO).unwrap();
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let internal_ivk = fvk.to_ivk(Scope::Internal);
    let prepared_internal = internal_ivk.prepare();

    // Try decryption with internal IVK
    let nullifier_parsed = orchard::note::Nullifier::from_bytes(&action.nullifier).unwrap();
    let cmx_parsed = orchard::note::ExtractedNoteCommitment::from_bytes(&action.cmx).unwrap();
    let compact_action = orchard::note_encryption::CompactAction::from_parts(
        nullifier_parsed,
        cmx_parsed,
        EphemeralKeyBytes(action.epk),
        action.ciphertext,
    );
    let output = CompactShieldedOutput {
        epk: action.epk,
        cmx: action.cmx,
        ciphertext: action.ciphertext,
    };
    let internal_result =
        try_compact_decrypt_any_version(&compact_action, &prepared_internal, &output);
    println!(
        "Decryption result (Internal scope): {:?}",
        internal_result.map(|(n, _)| n.value().inner())
    );

    // Print the addresses for debugging
    let external_addr = fvk.to_ivk(Scope::External).address_at(0u64);
    let internal_addr = fvk.to_ivk(Scope::Internal).address_at(0u64);
    println!(
        "External address diversifier_index 0: {:?}",
        hex_encode(&external_addr.to_raw_address_bytes()[..16])
    );
    println!(
        "Internal address diversifier_index 0: {:?}",
        hex_encode(&internal_addr.to_raw_address_bytes()[..16])
    );
}

// ============================================================================
// Transparent Key Derivation & Shielding Transaction Builder
// ============================================================================

/// BIP32 extended key (private)
struct Bip32Key {
    key: [u8; 32],
    chain_code: [u8; 32],
}

/// Derive BIP32 master key from seed using HMAC-SHA512 with key "Bitcoin seed"
fn bip32_master_key(seed: &[u8]) -> Bip32Key {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    let mut mac =
        Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").expect("HMAC accepts any key length");
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    Bip32Key { key, chain_code }
}

/// BIP32 child key derivation (hardened or normal)
fn bip32_derive_child(parent: &Bip32Key, index: u32, hardened: bool) -> Result<Bip32Key, String> {
    use hmac::{Hmac, Mac};
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::elliptic_curve::PrimeField;
    use sha2::Sha512;

    let mut mac =
        Hmac::<Sha512>::new_from_slice(&parent.chain_code).expect("HMAC accepts any key length");

    let child_index = if hardened { index | 0x80000000 } else { index };

    if hardened {
        // Hardened: HMAC-SHA512(key=chain_code, data=0x00 || ser256(parent_key) || ser32(index))
        mac.update(&[0x00]);
        mac.update(&parent.key);
    } else {
        // Normal: HMAC-SHA512(key=chain_code, data=ser_P(parent_pubkey) || ser32(index))
        let secret_key = k256::SecretKey::from_slice(&parent.key)
            .map_err(|e| format!("invalid parent key: {}", e))?;
        let pubkey = secret_key.public_key();
        let compressed = pubkey.to_encoded_point(true);
        mac.update(compressed.as_bytes());
    }

    mac.update(&child_index.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // child_key = parse256(IL) + parent_key (mod n)
    let il = &result[..32];
    let ir = &result[32..];

    // Add IL to parent key modulo the secp256k1 curve order
    let mut parent_bytes = k256::FieldBytes::default();
    parent_bytes.copy_from_slice(&parent.key);
    let parent_scalar = k256::Scalar::from_repr(parent_bytes);
    if bool::from(parent_scalar.is_none()) {
        return Err("invalid parent scalar".into());
    }
    let parent_scalar = parent_scalar.unwrap();

    let mut il_bytes = k256::FieldBytes::default();
    il_bytes.copy_from_slice(il);
    let il_scalar = k256::Scalar::from_repr(il_bytes);
    if bool::from(il_scalar.is_none()) {
        return Err("invalid IL scalar".into());
    }
    let il_scalar = il_scalar.unwrap();

    let child_scalar = il_scalar + parent_scalar;

    let mut key = [0u8; 32];
    key.copy_from_slice(&child_scalar.to_repr());

    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(ir);

    Ok(Bip32Key { key, chain_code })
}

/// Derive transparent private key from mnemonic using BIP44 path m/44'/133'/account'/0/index
///
/// Returns hex-encoded 32-byte secp256k1 private key for signing transparent inputs.
/// Path components: purpose=44' (BIP44), coin_type=133' (ZEC), account', change=0, index
#[wasm_bindgen]
pub fn derive_transparent_privkey(
    seed_phrase: &str,
    account: u32,
    index: u32,
) -> Result<String, JsError> {
    let mnemonic = bip39::Mnemonic::parse(seed_phrase)
        .map_err(|e| JsError::new(&format!("invalid mnemonic: {}", e)))?;

    let seed = mnemonic.to_seed("");

    // BIP32 derivation: m/44'/133'/account'/0/index
    let master = bip32_master_key(&seed);

    let child_44h = bip32_derive_child(&master, 44, true)
        .map_err(|e| JsError::new(&format!("derivation failed at 44': {}", e)))?;
    let child_133h = bip32_derive_child(&child_44h, 133, true)
        .map_err(|e| JsError::new(&format!("derivation failed at 133': {}", e)))?;
    let child_account = bip32_derive_child(&child_133h, account, true)
        .map_err(|e| JsError::new(&format!("derivation failed at account': {}", e)))?;
    let child_change = bip32_derive_child(&child_account, 0, false)
        .map_err(|e| JsError::new(&format!("derivation failed at change: {}", e)))?;
    let child_index = bip32_derive_child(&child_change, index, false)
        .map_err(|e| JsError::new(&format!("derivation failed at index: {}", e)))?;

    Ok(hex_encode(&child_index.key))
}

/// Deserialize a u64 from either a JSON number or a string (for BigInt safety)
fn deserialize_u64_or_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u64, D::Error> {
    use serde::de;
    struct U64OrString;
    impl<'de> de::Visitor<'de> for U64OrString {
        type Value = u64;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a u64 or numeric string")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<u64, E> {
            Ok(v)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<u64, E> {
            u64::try_from(v).map_err(|_| de::Error::custom("negative value"))
        }
        fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<u64, E> {
            Ok(v as u64)
        }
        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<u64, E> {
            v.parse::<u64>().map_err(de::Error::custom)
        }
    }
    deserializer.deserialize_any(U64OrString)
}

/// UTXO input for shielding transaction
#[derive(Debug, Clone, Deserialize)]
struct TransparentUtxo {
    /// Transaction ID (hex, 32 bytes big-endian as displayed)
    txid: String,
    /// Output index within the transaction
    vout: u32,
    /// Value in zatoshis (accepts number or string for BigInt safety)
    #[serde(deserialize_with = "deserialize_u64_or_string")]
    value: u64,
    /// scriptPubKey (hex) - expected to be P2PKH
    script: String,
}

/// Personalized Blake2b-256 hash (ZIP-244 style)
pub(crate) fn blake2b_256_personal(personalization: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personalization)
        .hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

// ============================================================================
// Shielding (transparent -> shielded) pool selection and the post-NU6.3 gate
// ============================================================================

/// Real NU6.3 / Ironwood consensus branch id (from the live zebra). Mirrors
/// `BranchId::Nu6_3` in upstream `zcash_protocol`.
pub const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;

/// NU6.3 / Ironwood activation heights, mirroring upstream `zcash_protocol`
/// (`src/consensus.rs`): mainnet 3_428_143, testnet 4_134_000.
///
/// NOTE: the previously-pinned librustzcash fork activated NU6.3 on
/// test/regtest at height 1 so it could be exercised from genesis; upstream
/// uses the real testnet activation height. Only the testnet gate moves —
/// mainnet is unchanged.
///
/// Kept as plain constants (rather than reading `NetworkUpgrade::Nu6_3`) so
/// the gate is a compile-time value on the wasm hot path;
/// `nu6_3_activation_matches_upstream` asserts they stay in sync.
pub const NU6_3_ACTIVATION_HEIGHT_MAINNET: u32 = 3_428_143;
/// See [`NU6_3_ACTIVATION_HEIGHT_MAINNET`].
pub const NU6_3_ACTIVATION_HEIGHT_TESTNET: u32 = 4_134_000;

/// NU6.3 activation height for the selected network.
pub fn nu6_3_activation_height(mainnet: bool) -> u32 {
    if mainnet {
        NU6_3_ACTIVATION_HEIGHT_MAINNET
    } else {
        NU6_3_ACTIVATION_HEIGHT_TESTNET
    }
}

/// Which shielded pool a transparent→shielded transaction must target at
/// `target_height`: `"ironwood"` at/after NU6.3 activation, `"orchard"` before.
///
/// Callers that do not pick a pool explicitly MUST resolve it through this
/// function (or through [`build_shielding_transaction_auto`], which calls it)
/// rather than defaulting to orchard: from NU6.3 onwards an orchard output is
/// a stranded note (orchard sends are consensus-disabled, so the funds can only
/// be moved again by a turnstile migration that costs a second fee).
#[wasm_bindgen]
pub fn shielding_pool_for_height(target_height: u32, mainnet: bool) -> String {
    if target_height >= nu6_3_activation_height(mainnet) {
        "ironwood".to_string()
    } else {
        "orchard".to_string()
    }
}

/// FAIL-CLOSED gate for the legacy ORCHARD shielding builders.
///
/// Shielding into orchard at/after NU6.3 produces funds the user cannot spend:
/// orchard→orchard sends are consensus-disabled by the one-way turnstile, so
/// those notes are stranded until a turnstile migration (a second fee, a second
/// wait) moves them to ironwood. Offering that path silently costs the user
/// money, so it is refused outright — by height AND by consensus branch id, so
/// neither omission nor a stale/defaulted height can reach it.
///
/// Returns `String` errors (not `JsError`) so native unit tests can call it -
/// `JsError::new` panics off-wasm.
fn guard_orchard_shielding_allowed(
    anchor_height: u32,
    mainnet: bool,
    branch_id_hex: Option<&str>,
) -> Result<(), String> {
    let activation = nu6_3_activation_height(mainnet);
    if anchor_height >= activation {
        return Err(format!(
            "orchard shielding is disabled at NU6.3 (activation height {}, target \
             height {}): an orchard output created now is unspendable and would \
             need a turnstile migration - use build_shielding_transaction_ironwood \
             (or build_shielding_transaction_auto, which picks the pool from the \
             chain height) to shield into the ironwood pool instead",
            activation, anchor_height
        ));
    }
    // Independent of the height the caller supplied: if the live consensus
    // branch id is already NU6.3, the chain has activated and orchard outputs
    // are disabled no matter what height was passed in.
    if parse_branch_id(branch_id_hex.unwrap_or("")) == Some(NU6_3_BRANCH_ID) {
        return Err(
            "orchard shielding is disabled at NU6.3: the supplied consensus branch \
             id is 0x37a5165b (Ironwood is active), so an orchard output would be \
             unspendable and would need a turnstile migration - use \
             build_shielding_transaction_ironwood (or \
             build_shielding_transaction_auto) to shield into the ironwood pool"
                .to_string(),
        );
    }
    Ok(())
}

/// Build a shielding transaction (transparent → orchard) with real Halo 2 proofs.
///
/// PRE-NU6.3 ONLY. [`guard_orchard_shielding_allowed`] refuses to build at or
/// after the NU6.3 activation height (or when the supplied consensus branch id
/// is NU6.3), because orchard outputs are consensus-disabled from that point
/// and the resulting notes would be stranded. Use
/// [`build_shielding_transaction_ironwood`] there.
///
/// Spends transparent P2PKH UTXOs and creates an orchard output to the sender's
/// own shielded address. Uses `orchard::builder::Builder` for proper action
/// construction and zero-knowledge proof generation (client-side).
///
/// Returns hex-encoded signed v5 transaction bytes ready for broadcast.
///
/// # Arguments
/// * `utxos_json` - JSON array of `{txid, vout, value, script}` objects
/// * `privkey_hex` - hex-encoded 32-byte secp256k1 private key for transparent inputs
/// * `recipient` - unified address string (u1... or utest1...) for orchard output
/// * `amount` - total zatoshis to shield (all selected UTXO value minus fee)
/// * `fee` - transaction fee in zatoshis
/// * `anchor_height` - block height for expiry (expiry_height = anchor_height + 100)
/// * `mainnet` - true for mainnet, false for testnet
#[wasm_bindgen]
// wasm-bindgen surface mirrors the TS caller's argument list
#[allow(clippy::too_many_arguments)]
pub fn build_shielding_transaction(
    utxos_json: &str,
    privkey_hex: &str,
    recipient: &str,
    amount: u64,
    fee: u64,
    anchor_height: u32,
    mainnet: bool,
    // Live consensus branch id from GetLightdInfo.consensusBranchId, e.g.
    // "5437f330" (NU6.2) or "37a5165b" (NU6.3). Pass verbatim; None/empty falls
    // back to the compiled-in NU6.2 value (wrong post-NU6.3).
    branch_id_hex: Option<String>,
) -> Result<String, JsError> {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use orchard::builder::{Builder, BundleType};
    use orchard::tree::Anchor;
    use orchard::value::NoteValue;
    use rand::rngs::OsRng;
    use zcash_protocol::value::ZatBalance;

    // FAIL CLOSED: never build an orchard shielding tx at/after NU6.3.
    guard_orchard_shielding_allowed(anchor_height, mainnet, branch_id_hex.as_deref())
        .map_err(|e| JsError::new(&e))?;
    // FAIL-CLOSED, BEFORE proving: the ZIP-244 sighash below binds this branch
    // id; a missing/unparseable value is refused rather than defaulted.
    let branch_id: u32 =
        resolve_branch_id(branch_id_hex.as_deref()).map_err(|e| JsError::new(&e))?;

    // --- parse recipient orchard address ---
    let orchard_addr = parse_orchard_address(recipient, mainnet)
        .map_err(|e| JsError::new(&format!("invalid recipient: {}", e)))?;

    // --- parse transparent private key ---
    let privkey_bytes =
        hex_decode(privkey_hex).ok_or_else(|| JsError::new("invalid privkey hex"))?;
    if privkey_bytes.len() != 32 {
        return Err(JsError::new("privkey must be 32 bytes"));
    }

    let signing_key = SigningKey::from_slice(&privkey_bytes)
        .map_err(|e| JsError::new(&format!("invalid signing key: {}", e)))?;
    let pubkey = signing_key.verifying_key();
    let compressed_pubkey = pubkey.to_encoded_point(true);
    let pubkey_bytes = compressed_pubkey.as_bytes();
    let pubkey_hash = hash160(pubkey_bytes);
    let our_script_pubkey = make_p2pkh_script(&pubkey_hash);

    // --- parse and select UTXOs ---
    let mut utxos: Vec<TransparentUtxo> = serde_json::from_str(utxos_json)
        .map_err(|e| JsError::new(&format!("invalid utxos json: {}", e)))?;
    utxos.sort_by_key(|u| std::cmp::Reverse(u.value));

    let target = amount
        .checked_add(fee)
        .ok_or_else(|| JsError::new("amount + fee overflow"))?;

    let mut selected: Vec<TransparentUtxo> = Vec::new();
    let mut total_in: u64 = 0;
    for utxo in &utxos {
        selected.push(utxo.clone());
        total_in += utxo.value;
        if total_in >= target {
            break;
        }
    }
    if total_in < target {
        return Err(JsError::new(&format!(
            "insufficient funds: have {} zat, need {} zat",
            total_in, target
        )));
    }

    // all value goes to orchard (no transparent change output)
    let shielded_value = total_in - fee;

    // --- build orchard bundle with real Halo 2 proofs ---
    // NU6.1-branch V5 tx: legacy orchard pool, pre-NU6.2 (historical) circuit.
    let bundle_type = BundleType::Transactional {
        bundle_required: true,
        pad_to_minimum: None,
    };
    let mut builder = Builder::new(
        bundle_type,
        orchard::bundle::BundleVersion::orchard_insecure_v1(),
        orchard::bundle::Flags::SPENDS_DISABLED,
        Anchor::empty_tree(),
    )
    .expect("flags are representable under this bundle version");

    builder
        .add_output(
            None,
            orchard_addr,
            NoteValue::from_raw(shielded_value),
            // canonical ZIP-302 no-memo, not 512 zero bytes (see ZIP302_NO_MEMO)
            ZIP302_NO_MEMO,
        )
        .map_err(|e| JsError::new(&format!("add_output: {:?}", e)))?;

    let mut rng = OsRng;
    let (unauthorized_bundle, _meta) = builder
        .build::<ZatBalance>(&mut rng)
        .map_err(|e| JsError::new(&format!("bundle build: {:?}", e)))?
        .ok_or_else(|| JsError::new("builder produced no bundle"))?;

    // prove (Halo 2 — this is the expensive step, ~seconds in WASM)
    let proven_bundle = with_proving_key(|pk| unauthorized_bundle.create_proof(pk, &mut rng))
        .map_err(|e| JsError::new(&format!("create_proof: {:?}", e)))?;

    // --- compute transparent digests for ZIP-244 sighash ---
    let n_inputs = selected.len();
    let expiry_height = anchor_height.saturating_add(100);

    let mut prevout_data = Vec::new();
    let mut sequence_data = Vec::new();
    let mut amounts_data = Vec::new();
    let mut scripts_data = Vec::new();

    for utxo in &selected {
        let txid_be =
            hex_decode(&utxo.txid).ok_or_else(|| JsError::new("invalid utxo txid hex"))?;
        if txid_be.len() != 32 {
            return Err(JsError::new("txid must be 32 bytes"));
        }
        let mut txid_le = txid_be.clone();
        txid_le.reverse();

        prevout_data.extend_from_slice(&txid_le);
        prevout_data.extend_from_slice(&utxo.vout.to_le_bytes());
        sequence_data.extend_from_slice(&0xffffffffu32.to_le_bytes());
        amounts_data.extend_from_slice(&utxo.value.to_le_bytes());

        let script_bytes = hex_decode(&utxo.script).unwrap_or_else(|| our_script_pubkey.clone());
        scripts_data.extend_from_slice(&compact_size(script_bytes.len() as u64));
        scripts_data.extend_from_slice(&script_bytes);
    }

    // ZIP-244 digests
    let header_data = {
        let mut d = Vec::new();
        d.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
        d.extend_from_slice(&0x26A7270Au32.to_le_bytes());
        d.extend_from_slice(&branch_id.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&expiry_height.to_le_bytes());
        d
    };
    let header_digest = blake2b_256_personal(b"ZTxIdHeadersHash", &header_data);

    let prevouts_digest = blake2b_256_personal(b"ZTxIdPrevoutHash", &prevout_data);
    let sequence_digest = blake2b_256_personal(b"ZTxIdSequencHash", &sequence_data);
    let outputs_digest = blake2b_256_personal(b"ZTxIdOutputsHash", &[]);

    let sapling_digest = blake2b_256_personal(b"ZTxIdSaplingHash", &[]);

    // compute orchard_digest from the proven bundle's action data (ZIP-244)
    let orchard_digest = compute_orchard_digest(&proven_bundle)?;

    // per-input sighash needs amounts_digest and scriptpubkeys_digest
    let amounts_digest = blake2b_256_personal(b"ZTxTrAmountsHash", &amounts_data);
    let scriptpubkeys_digest = blake2b_256_personal(b"ZTxTrScriptsHash", &scripts_data);

    let sighash_personal = {
        let mut p = [0u8; 16];
        p[..12].copy_from_slice(b"ZcashTxHash_");
        p[12..16].copy_from_slice(&branch_id.to_le_bytes());
        p
    };

    // --- sign transparent inputs ---
    let mut signed_inputs: Vec<SignedTransparentInput> = Vec::new();

    for utxo in &selected[..n_inputs] {
        let txid_be = hex_decode(&utxo.txid).unwrap();
        let mut txid_le = txid_be.clone();
        txid_le.reverse();

        let script_bytes = hex_decode(&utxo.script).unwrap_or_else(|| our_script_pubkey.clone());

        let mut txin_data = Vec::new();
        txin_data.extend_from_slice(&txid_le);
        txin_data.extend_from_slice(&utxo.vout.to_le_bytes());
        txin_data.extend_from_slice(&utxo.value.to_le_bytes());
        txin_data.extend_from_slice(&compact_size(script_bytes.len() as u64));
        txin_data.extend_from_slice(&script_bytes);
        txin_data.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // ZIP-244 S.2g: hash per-input data separately
        let txin_sig_digest = blake2b_256_personal(b"Zcash___TxInHash", &txin_data);

        let mut sig_input = Vec::new();
        sig_input.push(0x01); // SIGHASH_ALL
        sig_input.extend_from_slice(&prevouts_digest);
        sig_input.extend_from_slice(&amounts_digest);
        sig_input.extend_from_slice(&scriptpubkeys_digest);
        sig_input.extend_from_slice(&sequence_digest);
        sig_input.extend_from_slice(&outputs_digest);
        sig_input.extend_from_slice(&txin_sig_digest);

        let transparent_sig_digest = blake2b_256_personal(b"ZTxIdTranspaHash", &sig_input);

        let mut sighash_input = Vec::new();
        sighash_input.extend_from_slice(&header_digest);
        sighash_input.extend_from_slice(&transparent_sig_digest);
        sighash_input.extend_from_slice(&sapling_digest);
        sighash_input.extend_from_slice(&orchard_digest);

        let sighash = blake2b_256_personal(&sighash_personal, &sighash_input);

        let sig: k256::ecdsa::Signature = signing_key
            .sign_prehash(&sighash)
            .map_err(|e| JsError::new(&format!("ECDSA signing failed: {}", e)))?;
        let sig_der = sig.to_der();

        let mut script_sig = Vec::new();
        let sig_with_hashtype_len = sig_der.as_bytes().len() + 1;
        script_sig.push(sig_with_hashtype_len as u8);
        script_sig.extend_from_slice(sig_der.as_bytes());
        script_sig.push(0x01); // SIGHASH_ALL
        script_sig.push(pubkey_bytes.len() as u8);
        script_sig.extend_from_slice(pubkey_bytes);

        signed_inputs.push(SignedTransparentInput {
            prevout_txid: utxo.txid.clone(),
            prevout_vout: utxo.vout,
            script_sig: hex_encode(&script_sig),
            sequence: 0xffffffff,
            value: utxo.value,
        });
    }

    // --- apply orchard binding signature ---
    // ZIP-244 S.2: when vin is non-empty, the verifier uses transparent_sig_digest
    // (not the txid transparent_digest) for the sighash. For the binding signature
    // (SignableInput::Shielded), hash_type=SIGHASH_ALL, no per-input data.
    let txin_sig_digest_empty = blake2b_256_personal(b"Zcash___TxInHash", &[]);
    let binding_transparent_digest = {
        let mut d = Vec::new();
        d.push(0x01); // SIGHASH_ALL
        d.extend_from_slice(&prevouts_digest);
        d.extend_from_slice(&amounts_digest);
        d.extend_from_slice(&scriptpubkeys_digest);
        d.extend_from_slice(&sequence_digest);
        d.extend_from_slice(&outputs_digest);
        d.extend_from_slice(&txin_sig_digest_empty);
        blake2b_256_personal(b"ZTxIdTranspaHash", &d)
    };

    let txid_sighash = {
        let mut d = Vec::new();
        d.extend_from_slice(&header_digest);
        d.extend_from_slice(&binding_transparent_digest);
        d.extend_from_slice(&sapling_digest);
        d.extend_from_slice(&orchard_digest);
        blake2b_256_personal(&sighash_personal, &d)
    };

    let authorized_bundle = proven_bundle
        .apply_signatures(rng, txid_sighash, &[])
        .map_err(|e| JsError::new(&format!("apply_signatures: {:?}", e)))?;

    // --- serialize v5 transaction ---
    let mut tx_bytes = Vec::new();

    // header
    tx_bytes.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
    tx_bytes.extend_from_slice(&0x26A7270Au32.to_le_bytes());
    tx_bytes.extend_from_slice(&branch_id.to_le_bytes());
    tx_bytes.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
    tx_bytes.extend_from_slice(&expiry_height.to_le_bytes());

    // transparent inputs
    tx_bytes.extend_from_slice(&compact_size(n_inputs as u64));
    for inp in &signed_inputs {
        let txid_be = hex_decode(&inp.prevout_txid).unwrap();
        let mut txid_le = txid_be.clone();
        txid_le.reverse();
        tx_bytes.extend_from_slice(&txid_le);
        tx_bytes.extend_from_slice(&inp.prevout_vout.to_le_bytes());

        let sig_bytes = hex_decode(&inp.script_sig).unwrap();
        tx_bytes.extend_from_slice(&compact_size(sig_bytes.len() as u64));
        tx_bytes.extend_from_slice(&sig_bytes);
        tx_bytes.extend_from_slice(&inp.sequence.to_le_bytes());
    }

    // transparent outputs (none)
    tx_bytes.extend_from_slice(&compact_size(0));

    // sapling (none)
    tx_bytes.extend_from_slice(&compact_size(0)); // spends
    tx_bytes.extend_from_slice(&compact_size(0)); // outputs

    // orchard bundle — serialize per ZIP-225 v5 format
    serialize_orchard_bundle(&authorized_bundle, &mut tx_bytes)?;

    Ok(hex_encode(&tx_bytes))
}

// ============================================================================
// IRONWOOD shielding builder (transparent -> ironwood, NU6.3 / V6)
//
// The post-NU6.3 replacement for `build_shielding_transaction`: orchard outputs
// are consensus-disabled from the Ironwood activation, so this is the ONLY way
// to shield transparent funds into a spendable shielded note on mainnet today.
//
// Shape: transparent P2PKH inputs only (no shielded spends) + exactly one
// ironwood output carrying `total_in - fee`. No transparent change output (the
// legacy orchard builder has none either - the caller picks UTXOs such that the
// remainder is acceptable to shield).
// ============================================================================

/// ZIP-317 marginal fee, in zatoshi per logical action.
pub const ZIP317_MARGINAL_FEE: u64 = 5_000;
/// ZIP-317 grace actions (the fee never drops below `MARGINAL_FEE *
/// GRACE_ACTIONS`).
pub const ZIP317_GRACE_ACTIONS: u64 = 2;
/// Every non-empty shielded bundle is padded to at least this many actions by
/// the builder, and ZIP-317 counts the PADDED actions.
pub const SHIELDED_BUNDLE_MIN_ACTIONS: u64 = 2;

/// Serialized size of one P2PKH `tx_in`: 32 (txid) + 4 (index) + 1 (script len)
/// + 107 (script_sig: 1 + 72 sig + 1 + 33 compressed pubkey) + 4 (sequence).
pub const P2PKH_TX_IN_SIZE: u64 = 148;
/// ZIP-317 divides the transparent byte total by this to get logical actions.
pub const ZIP317_TX_BYTES_PER_ACTION: u64 = 150;

/// ZIP-317 transparent-side logical actions for `n` P2PKH inputs:
/// `ceil(tx_in_total_size / 150)`.
///
/// NOT `n`. `ceil(148n/150) == n` only while `2n < 150`; at `n == 75` the byte
/// total is exactly `11_100 == 74 * 150`, so the true action count is 74 and
/// every count from 75 up is strictly below `n`. Using `n` overpays by a
/// marginal fee every ~75 inputs, which is safe from the network's point of
/// view (nodes only reject UNDER-payment) but is a wallet fingerprint: a
/// consolidation with 75+ UTXOs pays a fee no ZIP-317-correct wallet would.
pub fn zip317_transparent_actions(n_transparent_inputs: usize) -> u64 {
    (n_transparent_inputs as u64 * P2PKH_TX_IN_SIZE).div_ceil(ZIP317_TX_BYTES_PER_ACTION)
}

/// ZIP-317 conventional fee for a transparent→ironwood shielding transaction
/// with `n_transparent_inputs` P2PKH inputs.
///
/// logical_actions = ceil(tx_in_total_size / 150)          (transparent side)
///                 + max(sapling spends, sapling outputs)  (0 here)
///                 + orchard actions + ironwood actions    (padded, see below)
///
/// The transparent side is [`zip317_transparent_actions`] — `ceil(148n/150)`,
/// which equals `n` only up to n = 74 and is strictly smaller from n = 75 on.
/// The transparent OUTPUT side contributes nothing (there are none), and the
/// shielding tx has NO orchard bundle - only the ironwood one, which is padded
/// to 2 actions.
///
/// Logical actions SUM ACROSS BUNDLES. Under-fee'ing here is what zebra rejects
/// with "Unpaid actions is higher than the limit"; the builder therefore also
/// RE-CHECKS the fee against the actual padded action counts of the built PCZT
/// (see `build_shielding_transaction_ironwood_core`) rather than trusting this
/// estimate alone. The two must agree exactly, or a large consolidation would
/// pass the estimate and then be refused by the re-check.
pub fn zip317_shielding_fee(n_transparent_inputs: usize) -> u64 {
    let logical = zip317_transparent_actions(n_transparent_inputs) + SHIELDED_BUNDLE_MIN_ACTIONS;
    ZIP317_MARGINAL_FEE * logical.max(ZIP317_GRACE_ACTIONS)
}

/// ZIP-317 conventional fee for an ironwood shielding transaction with `n`
/// transparent P2PKH inputs (JS-visible; see [`zip317_shielding_fee`]).
#[wasm_bindgen]
pub fn zip317_shielding_fee_zat(n_transparent_inputs: u32) -> u64 {
    zip317_shielding_fee(n_transparent_inputs as usize)
}

/// Testable core of the ironwood shielding builder, generic over consensus
/// params so native tests can drive it with an NU6.3-active network.
///
/// Every input must be a P2PKH output locked to `sk`'s pubkey (all inputs are
/// signed with that one key, which is what the wallet's shielding flow does).
/// Returns raw broadcast-ready V6 transaction bytes.
///
/// Pipeline: `Builder` (V6) → `Creator` → `IoFinalizer` → `Prover` (ironwood,
/// post-NU6.3 circuit) → `Signer::sign_transparent` (once per input) →
/// `SpendFinalizer` (assembles the script_sigs) → `TransactionExtractor`
/// (creates the ironwood binding signature and re-verifies proof + every
/// signature). The last two steps are reached through
/// `extract_signed_tx_from_pczt_bytes`, mirroring the other hot paths.
///
/// FAIL CLOSED on the branch id, identical to `build_ironwood_send_pczt_proven`:
/// the tx must bind NU6.3 (0x37a5165b), `expected_branch_id` must equal it, and
/// the 0xffff_ffff placeholder is refused outright.
///
/// SHARED with the cold/unsigned path: everything from the fail-closed guards
/// through the ZIP-317 recheck and the ironwood proof lives in
/// [`build_shielding_pczt_proven`]; this signed builder differs only in the seam
/// AFTER the proof (Signer → SpendFinalizer → TransactionExtractor). Keeping the
/// guarded pipeline in one place is deliberate: an unsigned builder that copied
/// the guards would let them drift out of sync on a money path.
#[allow(clippy::too_many_arguments)]
pub fn build_shielding_transaction_ironwood_core<P>(
    params: P,
    sk: &secp256k1::SecretKey,
    inputs: &[(
        zcash_transparent::bundle::OutPoint,
        zcash_transparent::bundle::TxOut,
    )],
    recipient: orchard::Address,
    fee: u64,
    target_height: u32,
    expected_branch_id: u32,
    memo: zcash_protocol::memo::MemoBytes,
) -> Result<Vec<u8>, String>
where
    P: zcash_protocol::consensus::Parameters,
{
    // The pubkey the coins are locked to is DERIVED from the signing key, never
    // trusted from the caller; the shared helper cross-checks every input's
    // script against it.
    let secp = secp256k1::Secp256k1::signing_only();
    let pubkey = sk.public_key(&secp);

    // Guarded, proven, IO-finalized PCZT (branch-id guards + ZIP-317 recheck +
    // ironwood proof). This is the exact PCZT the cold path serializes and hands
    // to an external transparent signer; here we sign it ourselves.
    let pczt = build_shielding_pczt_proven(
        params,
        &pubkey,
        inputs,
        recipient,
        fee,
        target_height,
        expected_branch_id,
        memo,
    )?;

    // --- sign every transparent input ---------------------------------------
    // All inputs are locked to the same key (checked in the helper), so index
    // order is irrelevant to correctness: we sign all of them.
    let n_inputs = pczt.transparent().inputs().len();
    let mut signer =
        pczt::roles::signer::Signer::new(pczt).map_err(|e| format!("signer init: {:?}", e))?;
    for i in 0..n_inputs {
        signer
            .sign_transparent(i, sk)
            .map_err(|e| format!("sign_transparent[{}]: {:?}", i, e))?;
    }
    let pczt = signer.finish();

    // SpendFinalizer combines the partial transparent signatures into
    // script_sigs; without it the extractor has no spend authorization.
    let pczt = pczt::roles::spend_finalizer::SpendFinalizer::new(pczt)
        .finalize_spends()
        .map_err(|e| format!("finalize_spends: {:?}", e))?;

    // Extract the broadcast-ready V6 tx (creates the ironwood binding signature
    // and verifies the proof + every signature against the sighash).
    extract_signed_tx_from_pczt_bytes(
        &pczt
            .serialize()
            .map_err(|e| format!("pczt serialize: {e:?}"))?,
    )
}

/// Guarded + proven shielding PCZT, SHARED by the signed hot builder
/// ([`build_shielding_transaction_ironwood_core`]) and the unsigned cold builder
/// ([`build_unsigned_shielding_pczt_ironwood_core`]).
///
/// Runs the money-critical pipeline through the ironwood proof: the fail-closed
/// branch-id guards, the P2PKH-script cross-check of every input against
/// `pubkey`, the ZIP-317 fee floor, the V6 `Builder` → `Creator` → `IoFinalizer`
/// stages, the post-`IoFinalizer` ZIP-317 recheck against the real padded action
/// counts, and the post-NU6.3 ironwood proof. Returns the proven, IO-finalized
/// PCZT with NO transparent signatures yet — the single seam the two callers
/// diverge at.
///
/// Takes the transparent PUBKEY rather than a secret key: the cold path has no
/// secret key, and the hot path derives the pubkey from its key before calling
/// in. Every input's `script_pubkey` must be the P2PKH script for `pubkey`.
#[allow(clippy::too_many_arguments)]
pub fn build_shielding_pczt_proven<P>(
    params: P,
    pubkey: &secp256k1::PublicKey,
    inputs: &[(
        zcash_transparent::bundle::OutPoint,
        zcash_transparent::bundle::TxOut,
    )],
    recipient: orchard::Address,
    fee: u64,
    target_height: u32,
    expected_branch_id: u32,
    memo: zcash_protocol::memo::MemoBytes,
) -> Result<pczt::Pczt, String>
where
    P: zcash_protocol::consensus::Parameters,
{
    use orchard::circuit::OrchardCircuitVersion;
    use rand::rngs::OsRng;
    use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
    use zcash_primitives::transaction::fees::fixed::FeeRule as FixedFeeRule;
    use zcash_primitives::transaction::TxVersion;
    use zcash_protocol::consensus::{BlockHeight, BranchId};
    use zcash_protocol::value::Zatoshis;
    use zcash_transparent::address::TransparentAddress;

    type FeError = <FixedFeeRule as zcash_primitives::transaction::fees::FeeRule>::Error;

    // --- FAIL-CLOSED branch-id guard (money path) ---------------------------
    // Same structure as `build_ironwood_send_pczt_proven`: refuse the NU6.3
    // placeholder, require the real NU6.3 branch id, and require it to match
    // what the wallet read from GetLightdInfo. A shielding tx that binds the
    // wrong branch is rejected by the network AFTER the user has already
    // published their UTXOs, so this never silently proceeds.
    const NU6_3_PLACEHOLDER_BRANCH_ID: u32 = 0xffff_ffff;
    if expected_branch_id == NU6_3_PLACEHOLDER_BRANCH_ID {
        return Err(format!(
            "refusing to build ironwood shielding: expected_branch_id is the NU6.3 \
             placeholder {:#010x}; the wallet must pass the real consensus branch \
             id read from GetLightdInfo",
            NU6_3_PLACEHOLDER_BRANCH_ID
        ));
    }
    let bound_branch_id: u32 =
        BranchId::for_height(&params, BlockHeight::from(target_height)).into();
    if bound_branch_id == NU6_3_PLACEHOLDER_BRANCH_ID {
        return Err(format!(
            "refusing to build ironwood shielding: the network params would bind \
             the NU6.3 placeholder branch id {:#010x} at height {} - the \
             librustzcash fork has not been patched with the real NU6.3 branch id",
            NU6_3_PLACEHOLDER_BRANCH_ID, target_height
        ));
    }
    if bound_branch_id != NU6_3_BRANCH_ID {
        return Err(format!(
            "refusing to build ironwood shielding: branch id that would bind at \
             height {} is {:#010x} but ironwood outputs require the NU6.3 branch \
             id {:#010x} (NU6.3 not active at this height)",
            target_height, bound_branch_id, NU6_3_BRANCH_ID
        ));
    }
    if bound_branch_id != expected_branch_id {
        return Err(format!(
            "refusing to build ironwood shielding: branch id that would bind at \
             height {} is {:#010x} but the wallet expected {:#010x} (branch-id \
             mismatch)",
            target_height, bound_branch_id, expected_branch_id
        ));
    }

    if inputs.is_empty() {
        return Err("ironwood shielding requires at least one transparent input".into());
    }

    // --- transparent key / script consistency -------------------------------
    let expected_script: zcash_transparent::address::Script =
        TransparentAddress::from_pubkey(pubkey).script().into();
    for (i, (_, coin)) in inputs.iter().enumerate() {
        if coin.script_pubkey() != &expected_script {
            return Err(format!(
                "input {} is not a P2PKH output locked to the supplied signing key",
                i
            ));
        }
    }

    // --- value / ZIP-317 fee ------------------------------------------------
    let mut total_in: u64 = 0;
    for (_, coin) in inputs {
        total_in = total_in
            .checked_add(coin.value().into_u64())
            .ok_or_else(|| "transparent input total overflows u64".to_string())?;
    }
    let required_fee = zip317_shielding_fee(inputs.len());
    if fee < required_fee {
        return Err(format!(
            "fee {} zat is below the ZIP-317 conventional fee {} zat for {} \
             transparent input(s) + a padded 2-action ironwood bundle; the network \
             would reject the tx with \"Unpaid actions is higher than the limit\"",
            fee,
            required_fee,
            inputs.len()
        ));
    }
    if total_in <= fee {
        return Err("insufficient funds: transparent inputs do not cover the fee".into());
    }
    let shielded_value = total_in - fee;

    // --- build ---------------------------------------------------------------
    // orchard_anchor: None. Determined empirically (see the native test
    // `shielding_ironwood_v6.rs`): a shielding tx has NO orchard spends and NO
    // orchard outputs, so the fork's BuildConfig never needs an orchard bundle
    // builder and passing None produces a V6 tx with an EMPTY orchard bundle.
    // This matches `build_ironwood_send_pczt_proven` (also orchard-free) and
    // differs from the turnstile migration, which passes Some(anchor) precisely
    // because it SPENDS orchard notes.
    //
    // ironwood_anchor: Some(Anchor::empty_tree()). The pinned fork only creates
    // the ironwood bundle builder when this is Some, and the bundle here is
    // output-only, so the anchor only ever anchors the fabricated dummy spends
    // (which the circuit exempts from the merkle-path check). Empty tree is the
    // established output-only convention in this codebase and in the zigner
    // valar spike producer.
    let mut builder = Builder::new(
        params,
        BlockHeight::from(target_height),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .propose_version::<FeError>(TxVersion::V6)
        .map_err(|e| format!("propose_version(V6): {:?}", e))?;
    for (outpoint, coin) in inputs {
        builder
            .add_transparent_p2pkh_input(*pubkey, outpoint.clone(), coin.clone())
            .map_err(|e| format!("add_transparent_p2pkh_input: {:?}", e))?;
    }
    let shielded_zat =
        Zatoshis::from_u64(shielded_value).map_err(|_| "invalid shielded amount".to_string())?;
    // No ovk: shielding is a transparent→shielded move, and the sender's own
    // outgoing-view recovery of it adds nothing (the source is public anyway),
    // while an ovk-encrypted output ciphertext is one more thing to leak.
    builder
        .add_ironwood_output::<FeError>(None, recipient, shielded_zat, memo)
        .map_err(|e| format!("add_ironwood_output: {:?}", e))?;

    let fee_zat = Zatoshis::from_u64(fee).map_err(|_| "invalid fee amount".to_string())?;
    let fee_rule = FixedFeeRule::non_standard(fee_zat);
    let parts = builder
        .build_for_pczt(OsRng, &fee_rule)
        .map_err(|e| format!("build_for_pczt: {:?}", e))?
        .pczt_parts;

    let pczt = pczt::roles::creator::Creator::build_from_parts(parts)
        .ok_or_else(|| "Creator::build_from_parts: incompatible tx version".to_string())?;

    // IoFinalizer binds the shared sighash and spend-auth signs every dummy
    // ironwood spend (the whole output-only bundle), so no shielded signing is
    // left for us - only the transparent inputs.
    let pczt = pczt::roles::io_finalizer::IoFinalizer::new(pczt)
        .finalize_io()
        .map_err(|e| format!("finalize_io: {:?}", e))?;

    // --- re-check the fee against the ACTUAL padded action counts -----------
    // ZIP-317 logical actions sum across bundles and count the padding the
    // builder added, so verify against what was really built rather than
    // trusting the pre-build estimate. Done after IoFinalizer (padding is
    // final) and before the expensive proof.
    {
        let orchard_actions = pczt.orchard().actions().len() as u64;
        let ironwood_actions = pczt.ironwood().actions().len() as u64;
        // Transparent side is ceil(tx_in_total_size / 150), NOT the input count
        // - identical to `zip317_shielding_fee`, so the estimate and this
        // re-check can never disagree (they diverge from n = 75 inputs up).
        let tin = zip317_transparent_actions(pczt.transparent().inputs().len());
        let logical = tin + orchard_actions + ironwood_actions;
        let actual_required = ZIP317_MARGINAL_FEE * logical.max(ZIP317_GRACE_ACTIONS);
        if fee < actual_required {
            return Err(format!(
                "fee {} zat is below the ZIP-317 conventional fee {} zat for the tx \
                 as actually built ({} transparent input(s) + {} orchard + {} \
                 ironwood action(s) = {} logical actions)",
                fee, actual_required, tin, orchard_actions, ironwood_actions, logical
            ));
        }
    }

    // Only the ironwood bundle exists, so prove just that one, on the
    // post-NU6.3 circuit.
    let pczt = with_proving_key_for(OrchardCircuitVersion::PostNu6_3, |pk| {
        pczt::roles::prover::Prover::new(pczt)
            .create_ironwood_proof(pk)
            .map(|p| p.finish())
    })
    .map_err(|e| format!("create ironwood proof: {:?}", e))?;

    // The transparent inputs are unsigned: the hot caller signs with its key, the
    // cold caller serializes this and hands the per-input sighashes out.
    Ok(pczt)
}

/// Build a signed transparent→IRONWOOD shielding transaction (NU6.3 / V6).
///
/// The post-NU6.3 replacement for [`build_shielding_transaction`]: it spends the
/// selected transparent P2PKH UTXOs and creates ONE ironwood output for
/// `total_selected - fee` to `recipient`. Returns hex-encoded raw transaction
/// bytes, the same shape the legacy orchard builder returns, so the caller
/// broadcasts it unchanged.
///
/// # Arguments
/// * `utxos_json` - JSON array of `{txid, vout, value, script}` (same shape as
///   the orchard builder; `txid` is display/big-endian hex, `script` is the
///   P2PKH scriptPubKey hex)
/// * `privkey_hex` - hex-encoded 32-byte secp256k1 private key owning every UTXO
/// * `recipient` - unified address whose orchard-format receiver is the ironwood
///   recipient
/// * `amount` - UTXO-selection target (selection stops once `amount + fee` is
///   covered); the ironwood output always carries ALL selected value minus fee
/// * `fee` - fee in zatoshi; MUST be at least the ZIP-317 conventional fee
///   ([`zip317_shielding_fee`]) or the build is refused
/// * `target_height` - build height (must be at/after NU6.3 activation)
/// * `expected_branch_id` - branch id the wallet read from GetLightdInfo; must
///   be 0x37a5165b
/// * `mainnet` - true for mainnet, false for testnet
/// * `memo_hex` - optional memo (hex, ≤512 bytes); empty memo when omitted
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_shielding_transaction_ironwood(
    utxos_json: &str,
    privkey_hex: &str,
    recipient: &str,
    amount: u64,
    fee: u64,
    target_height: u32,
    expected_branch_id: u32,
    mainnet: bool,
    memo_hex: Option<String>,
) -> Result<String, JsError> {
    use zcash_protocol::consensus::{BlockHeight, MainNetwork, TestNetwork};
    use zcash_protocol::memo::MemoBytes;

    // --- recipient (orchard-format receiver = ironwood recipient) ---
    let recipient_addr = parse_orchard_address(recipient, mainnet)
        .map_err(|e| JsError::new(&format!("invalid recipient: {}", e)))?;

    // --- transparent signing key ---
    let privkey_bytes =
        hex_decode(privkey_hex).ok_or_else(|| JsError::new("invalid privkey hex"))?;
    if privkey_bytes.len() != 32 {
        return Err(JsError::new("privkey must be 32 bytes"));
    }
    let sk = secp256k1::SecretKey::from_slice(&privkey_bytes)
        .map_err(|e| JsError::new(&format!("invalid signing key: {}", e)))?;
    let secp = secp256k1::Secp256k1::signing_only();
    let pubkey = sk.public_key(&secp);

    // Parse + select + validate the UTXOs against the key's pubkey, identically
    // to the unsigned cold builder (shared helper, so selection cannot drift).
    let inputs = select_shielding_inputs(utxos_json, &pubkey, amount, fee)?;

    let memo_arr = decode_memo_hex(memo_hex.as_deref())?;
    let memo =
        MemoBytes::from_bytes(&memo_arr).map_err(|e| JsError::new(&format!("memo: {:?}", e)))?;

    let tx_bytes = if mainnet {
        build_shielding_transaction_ironwood_core(
            Nu63Activated {
                inner: MainNetwork,
                nu6_3_from: BlockHeight::from(target_height),
            },
            &sk,
            &inputs,
            recipient_addr,
            fee,
            target_height,
            expected_branch_id,
            memo,
        )
    } else {
        build_shielding_transaction_ironwood_core(
            Nu63Activated {
                inner: TestNetwork,
                nu6_3_from: BlockHeight::from(target_height),
            },
            &sk,
            &inputs,
            recipient_addr,
            fee,
            target_height,
            expected_branch_id,
            memo,
        )
    }
    .map_err(|e| JsError::new(&e))?;

    Ok(hex_encode(&tx_bytes))
}

/// Parse the `{txid, vout, value, script}` UTXO JSON, select largest-first until
/// `amount + fee` is covered, and cross-check every selected coin's scriptPubkey
/// against the P2PKH script derived from `pubkey`.
///
/// SHARED by the signed ([`build_shielding_transaction_ironwood`]) and unsigned
/// ([`build_unsigned_shielding_transaction_ironwood`]) ironwood shielding
/// wrappers so the two select and validate byte-for-byte identically. The coin's
/// `TxOut` script is DERIVED from `pubkey`, never trusted from the JSON; the JSON
/// `script` is only cross-checked so a non-P2PKH / foreign UTXO fails loudly.
fn select_shielding_inputs(
    utxos_json: &str,
    pubkey: &secp256k1::PublicKey,
    amount: u64,
    fee: u64,
) -> Result<
    Vec<(
        zcash_transparent::bundle::OutPoint,
        zcash_transparent::bundle::TxOut,
    )>,
    JsError,
> {
    use zcash_protocol::value::Zatoshis;
    use zcash_transparent::bundle::{OutPoint, TxOut};

    let our_script = make_p2pkh_script(&hash160(&pubkey.serialize()));
    let coin_script: zcash_transparent::address::Script =
        zcash_transparent::address::TransparentAddress::from_pubkey(pubkey)
            .script()
            .into();

    let mut utxos: Vec<TransparentUtxo> = serde_json::from_str(utxos_json)
        .map_err(|e| JsError::new(&format!("invalid utxos json: {}", e)))?;
    utxos.sort_by_key(|u| std::cmp::Reverse(u.value));

    let target = amount
        .checked_add(fee)
        .ok_or_else(|| JsError::new("amount + fee overflow"))?;

    let mut selected: Vec<TransparentUtxo> = Vec::new();
    let mut total_in: u64 = 0;
    for utxo in &utxos {
        selected.push(utxo.clone());
        total_in += utxo.value;
        if total_in >= target {
            break;
        }
    }
    if total_in < target {
        return Err(JsError::new(&format!(
            "insufficient funds: have {} zat, need {} zat",
            total_in, target
        )));
    }

    let mut inputs: Vec<(OutPoint, TxOut)> = Vec::with_capacity(selected.len());
    for utxo in &selected {
        let txid_be =
            hex_decode(&utxo.txid).ok_or_else(|| JsError::new("invalid utxo txid hex"))?;
        if txid_be.len() != 32 {
            return Err(JsError::new("txid must be 32 bytes"));
        }
        // OutPoint stores the txid in internal (little-endian) byte order, the
        // reverse of the displayed hex.
        let mut txid_le = [0u8; 32];
        txid_le.copy_from_slice(&txid_be);
        txid_le.reverse();

        let script_bytes =
            hex_decode(&utxo.script).ok_or_else(|| JsError::new("invalid utxo script hex"))?;
        if script_bytes != our_script {
            return Err(JsError::new(&format!(
                "utxo {}:{} is not a P2PKH output locked to the supplied key",
                utxo.txid, utxo.vout
            )));
        }
        let value =
            Zatoshis::from_u64(utxo.value).map_err(|_| JsError::new("utxo value out of range"))?;
        inputs.push((
            OutPoint::new(txid_le, utxo.vout),
            TxOut::new(value, coin_script.clone()),
        ));
    }
    Ok(inputs)
}

/// Testable core of the UNSIGNED ironwood shielding builder, generic over
/// consensus params so native tests can drive it with an NU6.3-active network.
///
/// Runs the shared, guarded, proven pipeline ([`build_shielding_pczt_proven`]),
/// records the compressed `pubkey` as the hash160 preimage on every transparent
/// input (so the cold completion's `append_transparent_signature` can recover
/// which pubkey an external ECDSA signature authorizes), serializes the PCZT, and
/// returns `(per-input transparent sighashes, serialized PCZT bytes)`.
///
/// The sighashes are derived from a RE-PARSE of the exact bytes returned, so they
/// can never disagree with the carrier the wallet keeps.
#[allow(clippy::too_many_arguments)]
pub fn build_unsigned_shielding_pczt_ironwood_core<P>(
    params: P,
    pubkey: &secp256k1::PublicKey,
    inputs: &[(
        zcash_transparent::bundle::OutPoint,
        zcash_transparent::bundle::TxOut,
    )],
    recipient: orchard::Address,
    fee: u64,
    target_height: u32,
    expected_branch_id: u32,
    memo: zcash_protocol::memo::MemoBytes,
) -> Result<(Vec<[u8; 32]>, Vec<u8>), String>
where
    P: zcash_protocol::consensus::Parameters,
{
    // Identical guards + ZIP-317 recheck + ironwood proof as the hot path.
    let pczt = build_shielding_pczt_proven(
        params,
        pubkey,
        inputs,
        recipient,
        fee,
        target_height,
        expected_branch_id,
        memo,
    )?;

    // Record the pubkey as the hash160 preimage on every transparent input. The
    // builder leaves `hash160_preimages` empty; the cold completion needs it to
    // match an external signature to its pubkey. Preimages are auxiliary PCZT
    // metadata committed to no digest, so this changes neither sighash nor proof.
    let pubkey_bytes = pubkey.serialize().to_vec();
    let n_inputs = pczt.transparent().inputs().len();
    let pczt = pczt::roles::updater::Updater::new(pczt)
        .update_transparent_with(|mut tu| {
            for i in 0..n_inputs {
                tu.update_input_with(i, |mut inp| {
                    inp.set_hash160_preimage(pubkey_bytes.clone());
                    Ok(())
                })?;
            }
            Ok(())
        })
        .map_err(|e| format!("updater set hash160 preimage: {:?}", e))?
        .finish();

    let pczt_bytes = pczt
        .serialize()
        .map_err(|e| format!("pczt serialize: {e:?}"))?;

    // Re-parse the exact bytes we return and take the sighashes from that copy,
    // so the sighashes provably correspond to the carrier.
    let reparsed =
        pczt::Pczt::parse(&pczt_bytes).map_err(|e| format!("pczt re-parse: {:?}", e))?;
    let signer = pczt::roles::signer::Signer::new(reparsed)
        .map_err(|e| format!("signer init: {:?}", e))?;
    let mut sighashes: Vec<[u8; 32]> = Vec::with_capacity(n_inputs);
    for i in 0..n_inputs {
        let sh = signer
            .transparent_sighash(i)
            .map_err(|e| format!("transparent_sighash[{}]: {:?}", i, e))?;
        sighashes.push(sh);
    }
    Ok((sighashes, pczt_bytes))
}

/// Build an UNSIGNED transparent→IRONWOOD shielding transaction (NU6.3 / V6) for
/// cold-wallet / watch-only / zigner signing.
///
/// The post-NU6.3 replacement for [`build_unsigned_shielding_transaction`] (which
/// builds a now-consensus-disabled orchard V5 bundle). It runs the full guarded
/// ironwood pipeline through the proof but stops BEFORE signing, and returns the
/// SAME JSON contract the orchard unsigned builder returns:
///   `{ sighashes: [hex_32b...], unsigned_tx_hex: hex, summary: string }`
/// so the existing zigner sighash encoder needs no change.
///
/// IMPORTANT: `unsigned_tx_hex` here is the serialized PCZT (magic `b"PCZT"`), NOT
/// a raw transaction - the canonical librustzcash cold-signing carrier. The
/// air-gapped signer only ever handles the 32-byte `sighashes`; completion must
/// route to [`complete_shielding_pczt`]. [`complete_shielding_transaction`]
/// sniffs the PCZT magic and delegates, so an unchanged completion call site also
/// works.
///
/// # Arguments
/// * `utxos_json` - JSON array of `{txid, vout, value, script}` (same shape as the
///   signed builder)
/// * `pubkey_hex` - 33-byte compressed secp256k1 pubkey owning every UTXO (from
///   e.g. [`transparent_pubkey_from_ufvk`])
/// * `recipient` - unified address whose orchard-format receiver is the ironwood
///   recipient
/// * `amount`, `fee`, `target_height`, `expected_branch_id`, `mainnet`, `memo_hex`
///   - identical semantics to [`build_shielding_transaction_ironwood`]
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_unsigned_shielding_transaction_ironwood(
    utxos_json: &str,
    pubkey_hex: &str,
    recipient: &str,
    amount: u64,
    fee: u64,
    target_height: u32,
    expected_branch_id: u32,
    mainnet: bool,
    memo_hex: Option<String>,
) -> Result<String, JsError> {
    use zcash_protocol::consensus::{BlockHeight, MainNetwork, TestNetwork};
    use zcash_protocol::memo::MemoBytes;

    // --- recipient (orchard-format receiver = ironwood recipient) ---
    let recipient_addr = parse_orchard_address(recipient, mainnet)
        .map_err(|e| JsError::new(&format!("invalid recipient: {}", e)))?;

    // --- transparent pubkey (no secret key on the cold path) ---
    let pubkey_bytes = hex_decode(pubkey_hex).ok_or_else(|| JsError::new("invalid pubkey hex"))?;
    if pubkey_bytes.len() != 33 {
        return Err(JsError::new("pubkey must be a 33-byte compressed secp256k1 key"));
    }
    let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| JsError::new(&format!("invalid pubkey: {}", e)))?;

    let inputs = select_shielding_inputs(utxos_json, &pubkey, amount, fee)?;
    let total_in: u64 = inputs.iter().map(|(_, c)| c.value().into_u64()).sum();

    let memo_arr = decode_memo_hex(memo_hex.as_deref())?;
    let memo =
        MemoBytes::from_bytes(&memo_arr).map_err(|e| JsError::new(&format!("memo: {:?}", e)))?;

    let (sighashes, pczt_bytes) = if mainnet {
        build_unsigned_shielding_pczt_ironwood_core(
            Nu63Activated {
                inner: MainNetwork,
                nu6_3_from: BlockHeight::from(target_height),
            },
            &pubkey,
            &inputs,
            recipient_addr,
            fee,
            target_height,
            expected_branch_id,
            memo,
        )
    } else {
        build_unsigned_shielding_pczt_ironwood_core(
            Nu63Activated {
                inner: TestNetwork,
                nu6_3_from: BlockHeight::from(target_height),
            },
            &pubkey,
            &inputs,
            recipient_addr,
            fee,
            target_height,
            expected_branch_id,
            memo,
        )
    }
    .map_err(|e| JsError::new(&e))?;

    let sighashes_hex: Vec<String> = sighashes.iter().map(|s| hex_encode(s)).collect();
    let shielded_zec = (total_in - fee) as f64 / 1e8;
    let fee_zec = fee as f64 / 1e8;
    let summary = format!(
        "shield {:.8} ZEC ({} utxos, fee {:.8} ZEC)",
        shielded_zec,
        inputs.len(),
        fee_zec
    );

    let result = serde_json::json!({
        "sighashes": sighashes_hex,
        "unsigned_tx_hex": hex_encode(&pczt_bytes),
        "summary": summary,
    });
    Ok(result.to_string())
}

/// Build a shielding transaction into whichever pool is CORRECT at
/// `target_height`, so a caller never has to (and never can) pick the stranded
/// one by omission.
///
/// At/after NU6.3 activation this is [`build_shielding_transaction_ironwood`]
/// (and `branch_id_hex` must be the live NU6.3 branch id - there is no
/// fallback); before it, the legacy orchard builder. Returns hex-encoded raw
/// transaction bytes either way.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_shielding_transaction_auto(
    utxos_json: &str,
    privkey_hex: &str,
    recipient: &str,
    amount: u64,
    fee: u64,
    target_height: u32,
    mainnet: bool,
    // Live consensus branch id from GetLightdInfo.consensusBranchId.
    branch_id_hex: Option<String>,
    memo_hex: Option<String>,
) -> Result<String, JsError> {
    if target_height >= nu6_3_activation_height(mainnet) {
        // Ironwood regime: the branch id is load-bearing, so require it rather
        // than falling back to a compiled-in default.
        let branch_id =
            parse_branch_id(branch_id_hex.as_deref().unwrap_or("")).ok_or_else(|| {
                JsError::new(
                    "ironwood shielding requires the live consensus branch id \
                 (GetLightdInfo.consensusBranchId); none was supplied",
                )
            })?;
        build_shielding_transaction_ironwood(
            utxos_json,
            privkey_hex,
            recipient,
            amount,
            fee,
            target_height,
            branch_id,
            mainnet,
            memo_hex,
        )
    } else {
        let _ = memo_hex; // the legacy orchard builder takes no memo
        build_shielding_transaction(
            utxos_json,
            privkey_hex,
            recipient,
            amount,
            fee,
            target_height,
            mainnet,
            branch_id_hex,
        )
    }
}

/// Derive compressed public key from UFVK transparent component for a given address index.
///
/// Uses BIP44 external path: `m/44'/133'/account'/0/<address_index>`
/// Returns hex-encoded 33-byte compressed secp256k1 public key.
#[wasm_bindgen]
pub fn transparent_pubkey_from_ufvk(ufvk_str: &str, address_index: u32) -> Result<String, JsError> {
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_protocol::consensus::{MainNetwork, TestNetwork};
    use zcash_transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};

    let mainnet = ufvk_str.starts_with("uview1") && !ufvk_str.starts_with("uviewtest");

    let ufvk = if mainnet {
        UnifiedFullViewingKey::decode(&MainNetwork, ufvk_str)
    } else {
        UnifiedFullViewingKey::decode(&TestNetwork, ufvk_str)
    }
    .map_err(|e| JsError::new(&format!("invalid UFVK: {}", e)))?;

    let account_pubkey = ufvk
        .transparent()
        .ok_or_else(|| JsError::new("UFVK has no transparent component"))?;

    let child_index = NonHardenedChildIndex::from_index(address_index)
        .ok_or_else(|| JsError::new("address index out of range"))?;

    let pubkey = account_pubkey
        .derive_address_pubkey(TransparentKeyScope::EXTERNAL, child_index)
        .map_err(|e| JsError::new(&format!("failed to derive pubkey: {}", e)))?;

    Ok(hex_encode(&pubkey.serialize()))
}

/// Build an unsigned shielding transaction (transparent → orchard) for cold-wallet signing.
///
/// Same as `build_shielding_transaction` but does NOT sign the transparent inputs.
/// Instead, returns the per-input sighashes so an external signer (e.g. Zigner) can sign them.
///
/// PRE-NU6.3 ONLY - same fail-closed gate as `build_shielding_transaction`.
///
/// Returns JSON: `{ sighashes: [hex], unsigned_tx_hex: hex, summary: string }`
#[wasm_bindgen]
pub fn build_unsigned_shielding_transaction(
    utxos_json: &str,
    recipient: &str,
    amount: u64,
    fee: u64,
    anchor_height: u32,
    mainnet: bool,
    // Live consensus branch id from GetLightdInfo.consensusBranchId, e.g.
    // "5437f330" (NU6.2) or "37a5165b" (NU6.3). Pass verbatim; None/empty falls
    // back to the compiled-in NU6.2 value (wrong post-NU6.3).
    branch_id_hex: Option<String>,
) -> Result<String, JsError> {
    use orchard::builder::{Builder, BundleType};
    use orchard::tree::Anchor;
    use orchard::value::NoteValue;
    use rand::rngs::OsRng;
    use zcash_protocol::value::ZatBalance;

    // FAIL CLOSED: never build an orchard shielding tx at/after NU6.3.
    guard_orchard_shielding_allowed(anchor_height, mainnet, branch_id_hex.as_deref())
        .map_err(|e| JsError::new(&e))?;
    // FAIL-CLOSED, BEFORE proving: the ZIP-244 sighash below binds this branch
    // id; a missing/unparseable value is refused rather than defaulted.
    let branch_id: u32 =
        resolve_branch_id(branch_id_hex.as_deref()).map_err(|e| JsError::new(&e))?;

    // --- parse recipient orchard address ---
    let orchard_addr = parse_orchard_address(recipient, mainnet)
        .map_err(|e| JsError::new(&format!("invalid recipient: {}", e)))?;

    // --- parse and select UTXOs ---
    let mut utxos: Vec<TransparentUtxo> = serde_json::from_str(utxos_json)
        .map_err(|e| JsError::new(&format!("invalid utxos json: {}", e)))?;
    utxos.sort_by_key(|u| std::cmp::Reverse(u.value));

    let target = amount
        .checked_add(fee)
        .ok_or_else(|| JsError::new("amount + fee overflow"))?;

    let mut selected: Vec<TransparentUtxo> = Vec::new();
    let mut total_in: u64 = 0;
    for utxo in &utxos {
        selected.push(utxo.clone());
        total_in += utxo.value;
        if total_in >= target {
            break;
        }
    }
    if total_in < target {
        return Err(JsError::new(&format!(
            "insufficient funds: have {} zat, need {} zat",
            total_in, target
        )));
    }

    let shielded_value = total_in - fee;

    // --- build orchard bundle with real Halo 2 proofs ---
    // NU6.1-branch V5 tx: legacy orchard pool, pre-NU6.2 (historical) circuit.
    let bundle_type = BundleType::Transactional {
        bundle_required: true,
        pad_to_minimum: None,
    };
    let mut builder = Builder::new(
        bundle_type,
        orchard::bundle::BundleVersion::orchard_insecure_v1(),
        orchard::bundle::Flags::SPENDS_DISABLED,
        Anchor::empty_tree(),
    )
    .expect("flags are representable under this bundle version");

    builder
        .add_output(
            None,
            orchard_addr,
            NoteValue::from_raw(shielded_value),
            // canonical ZIP-302 no-memo, not 512 zero bytes (see ZIP302_NO_MEMO)
            ZIP302_NO_MEMO,
        )
        .map_err(|e| JsError::new(&format!("add_output: {:?}", e)))?;

    let mut rng = OsRng;
    let (unauthorized_bundle, _meta) = builder
        .build::<ZatBalance>(&mut rng)
        .map_err(|e| JsError::new(&format!("bundle build: {:?}", e)))?
        .ok_or_else(|| JsError::new("builder produced no bundle"))?;

    let proven_bundle = with_proving_key(|pk| unauthorized_bundle.create_proof(pk, &mut rng))
        .map_err(|e| JsError::new(&format!("create_proof: {:?}", e)))?;

    // --- compute transparent digests for ZIP-244 sighash ---
    let n_inputs = selected.len();
    let expiry_height = anchor_height.saturating_add(100);

    let mut prevout_data = Vec::new();
    let mut sequence_data = Vec::new();
    let mut amounts_data = Vec::new();
    let mut scripts_data = Vec::new();

    for utxo in &selected {
        let txid_be =
            hex_decode(&utxo.txid).ok_or_else(|| JsError::new("invalid utxo txid hex"))?;
        if txid_be.len() != 32 {
            return Err(JsError::new("txid must be 32 bytes"));
        }
        let mut txid_le = txid_be.clone();
        txid_le.reverse();

        prevout_data.extend_from_slice(&txid_le);
        prevout_data.extend_from_slice(&utxo.vout.to_le_bytes());
        sequence_data.extend_from_slice(&0xffffffffu32.to_le_bytes());
        amounts_data.extend_from_slice(&utxo.value.to_le_bytes());

        let script_bytes =
            hex_decode(&utxo.script).ok_or_else(|| JsError::new("invalid utxo script hex"))?;
        scripts_data.extend_from_slice(&compact_size(script_bytes.len() as u64));
        scripts_data.extend_from_slice(&script_bytes);
    }

    // ZIP-244 digests
    let header_data = {
        let mut d = Vec::new();
        d.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
        d.extend_from_slice(&0x26A7270Au32.to_le_bytes());
        d.extend_from_slice(&branch_id.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&expiry_height.to_le_bytes());
        d
    };
    let header_digest = blake2b_256_personal(b"ZTxIdHeadersHash", &header_data);

    let prevouts_digest = blake2b_256_personal(b"ZTxIdPrevoutHash", &prevout_data);
    let sequence_digest = blake2b_256_personal(b"ZTxIdSequencHash", &sequence_data);
    let outputs_digest = blake2b_256_personal(b"ZTxIdOutputsHash", &[]);
    let sapling_digest = blake2b_256_personal(b"ZTxIdSaplingHash", &[]);
    let orchard_digest = compute_orchard_digest(&proven_bundle)?;

    let amounts_digest = blake2b_256_personal(b"ZTxTrAmountsHash", &amounts_data);
    let scriptpubkeys_digest = blake2b_256_personal(b"ZTxTrScriptsHash", &scripts_data);

    let sighash_personal = {
        let mut p = [0u8; 16];
        p[..12].copy_from_slice(b"ZcashTxHash_");
        p[12..16].copy_from_slice(&branch_id.to_le_bytes());
        p
    };

    // --- compute per-input sighashes (but do NOT sign) ---
    let mut sighashes: Vec<String> = Vec::new();

    for utxo in &selected[..n_inputs] {
        let txid_be = hex_decode(&utxo.txid).unwrap();
        let mut txid_le = txid_be.clone();
        txid_le.reverse();

        let script_bytes =
            hex_decode(&utxo.script).ok_or_else(|| JsError::new("invalid utxo script hex"))?;

        let mut txin_data = Vec::new();
        txin_data.extend_from_slice(&txid_le);
        txin_data.extend_from_slice(&utxo.vout.to_le_bytes());
        txin_data.extend_from_slice(&utxo.value.to_le_bytes());
        txin_data.extend_from_slice(&compact_size(script_bytes.len() as u64));
        txin_data.extend_from_slice(&script_bytes);
        txin_data.extend_from_slice(&0xffffffffu32.to_le_bytes());

        let txin_sig_digest = blake2b_256_personal(b"Zcash___TxInHash", &txin_data);

        let mut sig_input = Vec::new();
        sig_input.push(0x01); // SIGHASH_ALL
        sig_input.extend_from_slice(&prevouts_digest);
        sig_input.extend_from_slice(&amounts_digest);
        sig_input.extend_from_slice(&scriptpubkeys_digest);
        sig_input.extend_from_slice(&sequence_digest);
        sig_input.extend_from_slice(&outputs_digest);
        sig_input.extend_from_slice(&txin_sig_digest);

        let transparent_sig_digest = blake2b_256_personal(b"ZTxIdTranspaHash", &sig_input);

        let mut sighash_input = Vec::new();
        sighash_input.extend_from_slice(&header_digest);
        sighash_input.extend_from_slice(&transparent_sig_digest);
        sighash_input.extend_from_slice(&sapling_digest);
        sighash_input.extend_from_slice(&orchard_digest);

        let sighash = blake2b_256_personal(&sighash_personal, &sighash_input);
        sighashes.push(hex_encode(&sighash));
    }

    // --- apply orchard binding signature ---
    let txin_sig_digest_empty = blake2b_256_personal(b"Zcash___TxInHash", &[]);
    let binding_transparent_digest = {
        let mut d = Vec::new();
        d.push(0x01);
        d.extend_from_slice(&prevouts_digest);
        d.extend_from_slice(&amounts_digest);
        d.extend_from_slice(&scriptpubkeys_digest);
        d.extend_from_slice(&sequence_digest);
        d.extend_from_slice(&outputs_digest);
        d.extend_from_slice(&txin_sig_digest_empty);
        blake2b_256_personal(b"ZTxIdTranspaHash", &d)
    };

    let txid_sighash = {
        let mut d = Vec::new();
        d.extend_from_slice(&header_digest);
        d.extend_from_slice(&binding_transparent_digest);
        d.extend_from_slice(&sapling_digest);
        d.extend_from_slice(&orchard_digest);
        blake2b_256_personal(&sighash_personal, &d)
    };

    let authorized_bundle = proven_bundle
        .apply_signatures(rng, txid_sighash, &[])
        .map_err(|e| JsError::new(&format!("apply_signatures: {:?}", e)))?;

    // --- serialize v5 transaction with EMPTY scriptSigs ---
    let mut tx_bytes = Vec::new();

    // header
    tx_bytes.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
    tx_bytes.extend_from_slice(&0x26A7270Au32.to_le_bytes());
    tx_bytes.extend_from_slice(&branch_id.to_le_bytes());
    tx_bytes.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
    tx_bytes.extend_from_slice(&expiry_height.to_le_bytes());

    // transparent inputs (empty scriptSigs)
    tx_bytes.extend_from_slice(&compact_size(n_inputs as u64));
    for utxo in &selected {
        let txid_be = hex_decode(&utxo.txid).unwrap();
        let mut txid_le = txid_be.clone();
        txid_le.reverse();
        tx_bytes.extend_from_slice(&txid_le);
        tx_bytes.extend_from_slice(&utxo.vout.to_le_bytes());
        tx_bytes.extend_from_slice(&compact_size(0)); // empty scriptSig
        tx_bytes.extend_from_slice(&0xffffffffu32.to_le_bytes());
    }

    // transparent outputs (none)
    tx_bytes.extend_from_slice(&compact_size(0));

    // sapling (none)
    tx_bytes.extend_from_slice(&compact_size(0));
    tx_bytes.extend_from_slice(&compact_size(0));

    // orchard bundle
    serialize_orchard_bundle(&authorized_bundle, &mut tx_bytes)?;

    // summary
    let shielded_zec = shielded_value as f64 / 1e8;
    let fee_zec = fee as f64 / 1e8;
    let summary = format!(
        "shield {:.8} ZEC ({} utxos, fee {:.8} ZEC)",
        shielded_zec, n_inputs, fee_zec
    );

    // return JSON
    let result = serde_json::json!({
        "sighashes": sighashes,
        "unsigned_tx_hex": hex_encode(&tx_bytes),
        "summary": summary,
    });

    Ok(result.to_string())
}

/// Complete an unsigned shielding transaction by patching in transparent signatures.
///
/// Takes the unsigned tx hex (with empty scriptSigs) and an array of `{sig_hex, pubkey_hex}`
/// per transparent input. Constructs the P2PKH scriptSig for each input and returns the
/// final signed transaction hex.
#[wasm_bindgen]
pub fn complete_shielding_transaction(
    unsigned_tx_hex: &str,
    signatures_json: &str,
) -> Result<String, JsError> {
    let input_sigs: Vec<ShieldingInputSig> = serde_json::from_str(signatures_json)
        .map_err(|e| JsError::new(&format!("invalid signatures json: {}", e)))?;

    let tx_bytes =
        hex_decode(unsigned_tx_hex).ok_or_else(|| JsError::new("invalid unsigned tx hex"))?;

    // IRONWOOD (V6) cold path: the unsigned carrier is a serialized PCZT, not a
    // raw tx. Its 4-byte magic `b"PCZT"` (0x50 0x43 0x5a 0x54) can never collide
    // with a raw Zcash tx, whose first header byte is the tx version (0x05 orchard
    // / 0x06 ironwood). Sniff it so the completion call site stays unchanged while
    // routing to the PCZT signer/finalizer/extractor path.
    if tx_bytes.len() >= 4 && &tx_bytes[..4] == b"PCZT" {
        let tx = complete_shielding_pczt_inner(&tx_bytes, &input_sigs)?;
        return Ok(hex_encode(&tx));
    }

    if tx_bytes.len() < 20 {
        return Err(JsError::new("unsigned tx too short"));
    }

    // Parse: 20 bytes header, then compactSize input count
    let mut pos = 20usize;

    // read input count
    let (n_inputs, cs_len) = read_compact_size(&tx_bytes, pos)?;
    pos += cs_len;

    if input_sigs.len() != n_inputs as usize {
        return Err(JsError::new(&format!(
            "signature count {} != input count {}",
            input_sigs.len(),
            n_inputs
        )));
    }

    // Build new tx: header + patched inputs + remainder
    let mut out = Vec::new();
    out.extend_from_slice(&tx_bytes[..20]); // header
    out.extend_from_slice(&compact_size(n_inputs));

    // Parse each unsigned input (txid(32) + vout(4) + scriptSig_len(0=1byte) + seq(4) = 41 bytes)
    // and replace with signed scriptSig
    for sig in &input_sigs {
        if pos + 36 > tx_bytes.len() {
            return Err(JsError::new("tx truncated at input prevout"));
        }
        // copy prevout (txid + vout)
        out.extend_from_slice(&tx_bytes[pos..pos + 36]);
        pos += 36;

        // skip empty scriptSig (compactSize 0 = 1 byte)
        let (script_len, cs_len) = read_compact_size(&tx_bytes, pos)?;
        pos += cs_len + script_len as usize;

        // build P2PKH scriptSig: <sig+hashtype> <pubkey>
        let sig_bytes = hex_decode(&sig.sig_hex).ok_or_else(|| JsError::new("invalid sig hex"))?;
        let pubkey_bytes =
            hex_decode(&sig.pubkey_hex).ok_or_else(|| JsError::new("invalid pubkey hex"))?;

        // sig_bytes should be DER signature + SIGHASH_ALL byte (from zigner)
        let mut script_sig = Vec::new();
        script_sig.push(sig_bytes.len() as u8);
        script_sig.extend_from_slice(&sig_bytes);
        script_sig.push(pubkey_bytes.len() as u8);
        script_sig.extend_from_slice(&pubkey_bytes);

        out.extend_from_slice(&compact_size(script_sig.len() as u64));
        out.extend_from_slice(&script_sig);

        // copy sequence
        if pos + 4 > tx_bytes.len() {
            return Err(JsError::new("tx truncated at input sequence"));
        }
        out.extend_from_slice(&tx_bytes[pos..pos + 4]);
        pos += 4;
    }

    // copy everything after the inputs (outputs, sapling, orchard)
    out.extend_from_slice(&tx_bytes[pos..]);

    Ok(hex_encode(&out))
}

/// One external transparent signature: `{sig_hex, pubkey_hex}`, the shape the
/// zigner sig-response encoder already emits. `sig_hex` is DER || sighash-type
/// byte; `pubkey_hex` is the 33-byte compressed pubkey. Shared by the legacy raw
/// completion and the ironwood PCZT completion.
#[derive(Deserialize)]
struct ShieldingInputSig {
    sig_hex: String,
    #[allow(dead_code)]
    pubkey_hex: String,
}

/// Complete an UNSIGNED ironwood shielding PCZT by applying external transparent
/// signatures, finalizing the spends and extracting the broadcast-ready V6 tx.
///
/// This is the ironwood (V6) counterpart of [`complete_shielding_transaction`]'s
/// raw-tx scriptSig patching. Rather than splicing signature bytes into a
/// hand-serialized tx, it feeds each signature to the pczt `Signer`, which
/// CRYPTOGRAPHICALLY VERIFIES it against the input's sighash and its recorded
/// pubkey before storing it - so a wrong or malleated signature is rejected here
/// instead of by the network after the UTXOs are spent. The `SpendFinalizer` then
/// assembles the P2PKH scriptSigs and the `TransactionExtractor` creates the
/// ironwood binding signature and re-verifies the proof + every signature.
///
/// `signatures[i]` authorizes transparent input `i`; `sig_hex` is DER || a
/// SIGHASH_ALL (0x01) byte (what the zigner emits). The trailing byte is stripped
/// and REQUIRED to be 0x01: any other sighash type would authorize a different
/// commitment than the tx we built.
fn complete_shielding_pczt_inner(
    pczt_bytes: &[u8],
    input_sigs: &[ShieldingInputSig],
) -> Result<Vec<u8>, JsError> {
    let sigs: Vec<Vec<u8>> = input_sigs
        .iter()
        .map(|s| hex_decode(&s.sig_hex).ok_or_else(|| JsError::new("invalid sig hex")))
        .collect::<Result<_, _>>()?;
    complete_shielding_pczt_bytes(pczt_bytes, &sigs).map_err(|e| JsError::new(&e))
}

/// Testable core of the ironwood cold completion: apply external transparent
/// signatures to a serialized shielding PCZT and extract the broadcast-ready V6
/// tx. `sigs[i]` is the DER signature for input `i` with a trailing sighash-type
/// byte (as the zigner emits). Uses `String` errors so native tests can drive it.
///
/// See [`complete_shielding_pczt`] for the semantics and the consensus rationale
/// (SIGHASH_ALL enforcement, low-S normalization, verify-on-append).
pub fn complete_shielding_pczt_bytes(
    pczt_bytes: &[u8],
    sigs: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    let pczt = pczt::Pczt::parse(pczt_bytes)
        .map_err(|e| format!("invalid shielding pczt: {:?}", e))?;

    let n_inputs = pczt.transparent().inputs().len();
    if sigs.len() != n_inputs {
        return Err(format!(
            "signature count {} != transparent input count {}",
            sigs.len(),
            n_inputs
        ));
    }

    let mut signer =
        pczt::roles::signer::Signer::new(pczt).map_err(|e| format!("pczt signer init: {:?}", e))?;

    for (i, sig_bytes) in sigs.iter().enumerate() {
        // DER || sighash-type byte. The pczt Signer re-appends the input's
        // SighashType itself, so strip the trailing byte and fail closed unless
        // it is exactly SIGHASH_ALL.
        let (hashtype, der) = sig_bytes
            .split_last()
            .ok_or_else(|| format!("input {}: empty signature", i))?;
        if *hashtype != 0x01 {
            return Err(format!(
                "input {}: expected SIGHASH_ALL (0x01), got {:#04x}",
                i, hashtype
            ));
        }
        let mut signature = secp256k1::ecdsa::Signature::from_der(der)
            .map_err(|e| format!("input {}: invalid DER signature: {}", i, e))?;
        // Consensus requires low-S; normalize so a high-S external signer still
        // yields a valid, canonical scriptSig (append_transparent_signature also
        // verifies low-S via verify_ecdsa).
        signature.normalize_s();
        signer
            .append_transparent_signature(i, signature)
            .map_err(|e| format!("input {}: external signature rejected: {:?}", i, e))?;
    }

    let pczt = signer.finish();
    let pczt = pczt::roles::spend_finalizer::SpendFinalizer::new(pczt)
        .finalize_spends()
        .map_err(|e| format!("finalize_spends: {:?}", e))?;

    let pczt_bytes = pczt
        .serialize()
        .map_err(|e| format!("pczt serialize: {:?}", e))?;
    extract_signed_tx_from_pczt_bytes(&pczt_bytes)
}

/// Complete an unsigned ironwood shielding PCZT (from
/// [`build_unsigned_shielding_transaction_ironwood`]) into a broadcast-ready V6
/// transaction hex. See [`complete_shielding_pczt_inner`] for the semantics.
///
/// `signatures_json` is `[{sig_hex, pubkey_hex}, ...]`, one per transparent input
/// in index order - the exact shape [`complete_shielding_transaction`] accepts,
/// so a caller that always routes ironwood completions here (or one that reuses
/// `complete_shielding_transaction`, which sniffs the PCZT magic) is unchanged.
#[wasm_bindgen]
pub fn complete_shielding_pczt(
    pczt_hex: &str,
    signatures_json: &str,
) -> Result<String, JsError> {
    let pczt_bytes = hex_decode(pczt_hex).ok_or_else(|| JsError::new("invalid pczt hex"))?;
    let input_sigs: Vec<ShieldingInputSig> = serde_json::from_str(signatures_json)
        .map_err(|e| JsError::new(&format!("invalid signatures json: {}", e)))?;
    let tx_bytes = complete_shielding_pczt_inner(&pczt_bytes, &input_sigs)?;
    Ok(hex_encode(&tx_bytes))
}

/// Read a CompactSize value from a byte slice at the given position.
/// Returns (value, bytes_consumed).
fn read_compact_size(data: &[u8], pos: usize) -> Result<(u64, usize), JsError> {
    if pos >= data.len() {
        return Err(JsError::new("compact size: unexpected end of data"));
    }
    let first = data[pos];
    match first {
        0..=0xfc => Ok((first as u64, 1)),
        0xfd => {
            if pos + 3 > data.len() {
                return Err(JsError::new("compact size: truncated u16"));
            }
            let v = u16::from_le_bytes([data[pos + 1], data[pos + 2]]);
            Ok((v as u64, 3))
        }
        0xfe => {
            if pos + 5 > data.len() {
                return Err(JsError::new("compact size: truncated u32"));
            }
            let v =
                u32::from_le_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]);
            Ok((v as u64, 5))
        }
        0xff => {
            if pos + 9 > data.len() {
                return Err(JsError::new("compact size: truncated u64"));
            }
            let v = u64::from_le_bytes([
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
                data[pos + 8],
            ]);
            Ok((v, 9))
        }
    }
}

/// Parse an orchard address from a unified address string.
///
/// Because zcash_keys uses a different orchard crate version, we extract the raw
/// 43-byte address and reconstruct it with our orchard 0.12 types.
fn parse_orchard_address(addr_str: &str, mainnet: bool) -> Result<orchard::Address, String> {
    use zcash_keys::address::Address as ZkAddress;
    use zcash_protocol::consensus::{MainNetwork, TestNetwork};

    let decoded = if mainnet {
        ZkAddress::decode(&MainNetwork, addr_str)
    } else {
        ZkAddress::decode(&TestNetwork, addr_str)
    };

    match decoded {
        Some(ZkAddress::Unified(ua)) => {
            // get raw bytes from the zcash_keys orchard address (orchard 0.11)
            let orchard_addr_old = ua
                .orchard()
                .ok_or("unified address has no orchard receiver")?;
            let raw_bytes = orchard_addr_old.to_raw_address_bytes();
            // reconstruct as our orchard 0.12 Address
            Option::from(orchard::Address::from_raw_address_bytes(&raw_bytes))
                .ok_or_else(|| "invalid orchard address bytes".into())
        }
        Some(_) => Err("address is not a unified address".into()),
        None => Err("failed to decode address".into()),
    }
}

/// Compute ZIP-244 orchard_digest from a proven bundle's action data.
///
/// ZIP-244 §4.8:
///   actions_compact_digest = Blake2b-256("ZTxIdOrcActCHash", foreach: nf||cmx||epk||enc[0..52])
///   actions_memos_digest  = Blake2b-256("ZTxIdOrcActMHash", foreach: enc[52..564])
///   actions_noncompact_digest = Blake2b-256("ZTxIdOrcActNHash", foreach: cv||rk||enc[564..580]||out[0..80])
///   orchard_digest = Blake2b-256("ZTxIdOrchardHash",
///                      compact||memos||noncompact||flags(1)||value_balance(8)||anchor(32))
pub(crate) fn compute_orchard_digest<A: orchard::bundle::Authorization>(
    bundle: &orchard::Bundle<A, zcash_protocol::value::ZatBalance>,
) -> Result<[u8; 32], JsError> {
    let mut compact_data = Vec::new();
    let mut memos_data = Vec::new();
    let mut noncompact_data = Vec::new();

    for action in bundle.actions().iter() {
        // compact: nf(32) || cmx(32) || epk(32) || enc[0..52]
        compact_data.extend_from_slice(&action.nullifier().to_bytes());
        compact_data.extend_from_slice(&action.cmx().to_bytes());
        let enc = &action.encrypted_note().enc_ciphertext;
        let epk = &action.encrypted_note().epk_bytes;
        compact_data.extend_from_slice(epk);
        compact_data.extend_from_slice(&enc[..52]);

        // memos: enc[52..564]
        memos_data.extend_from_slice(&enc[52..564]);

        // noncompact: cv(32) || rk(32) || enc[564..580] || out(80)
        noncompact_data.extend_from_slice(&action.cv_net().to_bytes());
        noncompact_data.extend_from_slice(&<[u8; 32]>::from(action.rk()));
        noncompact_data.extend_from_slice(&enc[564..580]);
        noncompact_data.extend_from_slice(&action.encrypted_note().out_ciphertext);
    }

    let compact_digest = blake2b_256_personal(b"ZTxIdOrcActCHash", &compact_data);
    let memos_digest = blake2b_256_personal(b"ZTxIdOrcActMHash", &memos_data);
    let noncompact_digest = blake2b_256_personal(b"ZTxIdOrcActNHash", &noncompact_data);

    let mut orchard_data = Vec::new();
    orchard_data.extend_from_slice(&compact_digest);
    orchard_data.extend_from_slice(&memos_digest);
    orchard_data.extend_from_slice(&noncompact_digest);
    orchard_data.push(
        bundle
            .flags()
            .to_byte(orchard::bundle::BundleVersion::orchard_v2())
            .ok_or_else(|| JsError::new("flags not representable in pre-NU6.3 format"))?,
    );
    orchard_data.extend_from_slice(&bundle.value_balance().to_i64_le_bytes());
    orchard_data.extend_from_slice(&bundle.anchor().to_bytes());

    Ok(blake2b_256_personal(b"ZTxIdOrchardHash", &orchard_data))
}

/// Serialize an authorized orchard bundle into v5 transaction format (ZIP-225).
///
/// Layout: nActions(compactSize) || actions[] || flags(1) || valueBalance(8)
///         || anchor(32) || proof(compactSize+bytes) || spend_auth_sigs(64*n)
///         || binding_sig(64)
fn serialize_orchard_bundle(
    bundle: &orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>,
    out: &mut Vec<u8>,
) -> Result<(), JsError> {
    let actions = bundle.actions();
    let n = actions.len();

    // nActionsOrchard
    out.extend_from_slice(&compact_size(n as u64));

    // each action (without auth)
    for action in actions.iter() {
        out.extend_from_slice(&action.cv_net().to_bytes()); // 32
        out.extend_from_slice(&action.nullifier().to_bytes()); // 32
        out.extend_from_slice(&<[u8; 32]>::from(action.rk())); // 32
        out.extend_from_slice(&action.cmx().to_bytes()); // 32
        out.extend_from_slice(&action.encrypted_note().epk_bytes); // 32
        out.extend_from_slice(&action.encrypted_note().enc_ciphertext); // 580
        out.extend_from_slice(&action.encrypted_note().out_ciphertext); // 80
    }

    // flags byte
    out.push(
        bundle
            .flags()
            .to_byte(orchard::bundle::BundleVersion::orchard_v2())
            .ok_or_else(|| JsError::new("flags not representable in pre-NU6.3 format"))?,
    );

    // valueBalanceOrchard (i64 LE)
    out.extend_from_slice(&bundle.value_balance().to_i64_le_bytes());

    // anchor
    out.extend_from_slice(&bundle.anchor().to_bytes());

    // proof bytes (compactSize-prefixed vector)
    let proof_bytes = bundle.authorization().proof().as_ref();
    out.extend_from_slice(&compact_size(proof_bytes.len() as u64));
    out.extend_from_slice(proof_bytes);

    // spend auth signatures (64 bytes each)
    for action in actions.iter() {
        out.extend_from_slice(&<[u8; 64]>::from(action.authorization()));
    }

    // binding signature (64 bytes)
    out.extend_from_slice(&<[u8; 64]>::from(
        bundle.authorization().binding_signature(),
    ));

    Ok(())
}

/// HASH160 = RIPEMD160(SHA256(data))
fn hash160(data: &[u8]) -> [u8; 20] {
    use sha2::Digest;

    let sha = sha2::Sha256::digest(data);
    let ripe = ripemd::Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

/// Construct P2PKH scriptPubKey from pubkey hash
fn make_p2pkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    // OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
    let mut s = Vec::with_capacity(25);
    s.push(0x76); // OP_DUP
    s.push(0xa9); // OP_HASH160
    s.push(0x14); // push 20 bytes
    s.extend_from_slice(pubkey_hash);
    s.push(0x88); // OP_EQUALVERIFY
    s.push(0xac); // OP_CHECKSIG
    s
}

/// Bitcoin-style CompactSize encoding
pub(crate) fn compact_size(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffffffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

/// Base58check decode — returns version+payload (checksum verified)
fn base58_decode(s: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut num: Vec<u8> = vec![0];
    for &c in s.as_bytes() {
        let val = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| "invalid base58 character".to_string())? as u32;
        let mut carry = val;
        for byte in num.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let leading = s.bytes().take_while(|&b| b == b'1').count();
    let start = num.iter().position(|&b| b != 0).unwrap_or(num.len());
    let mut result = vec![0u8; leading];
    result.extend_from_slice(&num[start..]);

    if result.len() < 4 {
        return Err("base58check too short".into());
    }
    let (payload, checksum) = result.split_at(result.len() - 4);
    use sha2::Digest;
    let hash = sha2::Sha256::digest(sha2::Sha256::digest(payload));
    if &hash[..4] != checksum {
        return Err("base58check checksum mismatch".into());
    }
    Ok(payload.to_vec())
}

/// Decode a transparent t-address to a P2PKH scriptPubKey
fn decode_t_address_script(addr: &str, mainnet: bool) -> Result<Vec<u8>, String> {
    let decoded = base58_decode(addr)
        .map_err(|e| format!("invalid base58 in t-address: {} ({})", addr, e))?;
    let expected = if mainnet { [0x1c, 0xb8] } else { [0x1d, 0x25] };
    if decoded.len() != 22 || decoded[..2] != expected {
        return Err(format!("invalid transparent address: {}", addr));
    }
    let mut pkh = [0u8; 20];
    pkh.copy_from_slice(&decoded[2..]);
    Ok(make_p2pkh_script(&pkh))
}

/// A signed transparent input for serialization
#[derive(Debug, Clone)]
struct SignedTransparentInput {
    prevout_txid: String,
    prevout_vout: u32,
    script_sig: String,
    sequence: u32,
    #[allow(dead_code)]
    value: u64,
}

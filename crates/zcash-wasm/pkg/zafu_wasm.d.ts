/* tslint:disable */
/* eslint-disable */

/**
 * Wallet keys derived from seed phrase
 */
export class WalletKeys {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Calculate balance from found notes minus spent nullifiers
     */
    calculate_balance(notes_json: any, spent_nullifiers_json: any): bigint;
    /**
     * Decrypt full notes with memos from a raw transaction
     *
     * Takes the raw transaction bytes (from zidecar's get_transaction)
     * and returns any notes that belong to this wallet, including memos.
     */
    decrypt_transaction_memos(tx_bytes: Uint8Array): any;
    /**
     * Export Full Viewing Key as hex-encoded QR data
     * This is used to create a watch-only wallet on an online device
     */
    export_fvk_qr_hex(account_index: number, label: string | null | undefined, mainnet: boolean): string;
    /**
     * Derive wallet keys from a 24-word BIP39 seed phrase
     */
    constructor(seed_phrase: string);
    /**
     * Get the wallet's receiving address (identifier)
     */
    get_address(): string;
    /**
     * Get the Orchard FVK bytes (96 bytes) as hex
     */
    get_fvk_hex(): string;
    /**
     * Get the default receiving address as a Zcash unified address string
     */
    get_receiving_address(mainnet: boolean): string;
    /**
     * Get receiving address at specific diversifier index
     */
    get_receiving_address_at(diversifier_index: number, mainnet: boolean): string;
    /**
     * Scan actions from JSON (legacy compatibility, slower)
     */
    scan_actions(actions_json: any): any;
    /**
     * Scan a batch of IRONWOOD compact actions in PARALLEL (NU6.3+ pool).
     *
     * Same binary format and key material as `scan_actions_parallel` — the
     * ironwood pool shares orchard's key tree and note encryption; only the
     * bundle (and note plaintext version, V3) differ. The caller feeds the
     * actions from the tx's ironwood bundle here so returned notes carry
     * `pool: "ironwood"`.
     */
    scan_actions_ironwood_parallel(actions_bytes: Uint8Array): any;
    /**
     * Scan a batch of compact actions in PARALLEL and return found notes
     * This is the main entry point for high-performance scanning
     *
     * Binary format: [count: u32][action1][action2]...
     * Each action: [nullifier: 32][cmx: 32][epk: 32][ciphertext: 52] = 148 bytes
     */
    scan_actions_parallel(actions_bytes: Uint8Array): any;
}

/**
 * Watch-only wallet - holds only viewing keys, no spending capability
 * This is used by online wallets (Prax/Zafu) to track balances
 * and build unsigned transactions for cold signing.
 */
export class WatchOnlyWallet {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Decrypt full notes with memos from a raw transaction (watch-only version)
     */
    decrypt_transaction_memos(tx_bytes: Uint8Array): any;
    /**
     * Export FVK as hex bytes (for backup)
     */
    export_fvk_hex(): string;
    /**
     * Import a watch-only wallet from FVK bytes (96 bytes)
     */
    constructor(fvk_bytes: Uint8Array, account_index: number, mainnet: boolean);
    /**
     * Import from hex-encoded QR data
     */
    static from_qr_hex(qr_hex: string): WatchOnlyWallet;
    /**
     * Import from a UFVK string (uview1.../uviewtest1...)
     */
    static from_ufvk(ufvk_str: string): WatchOnlyWallet;
    /**
     * Get account index
     */
    get_account_index(): number;
    /**
     * Get default receiving address (diversifier index 0)
     */
    get_address(): string;
    /**
     * Get address at specific diversifier index
     */
    get_address_at(diversifier_index: number): string;
    /**
     * Is mainnet
     */
    is_mainnet(): boolean;
    /**
     * Scan a batch of IRONWOOD compact actions (NU6.3+ pool).
     *
     * Same binary format and key material as `scan_actions_parallel` — the
     * ironwood pool shares orchard's key tree and note encryption. Feed the
     * actions from a tx's ironwood bundle here so returned notes carry
     * `pool: "ironwood"`.
     */
    scan_actions_ironwood_parallel(actions_bytes: Uint8Array): any;
    /**
     * Scan compact actions (same interface as WalletKeys)
     */
    scan_actions_parallel(actions_bytes: Uint8Array): any;
}

/**
 * Derive an Orchard receiving address from a UFVK string (uview1.../uviewtest1...)
 */
export function address_from_ufvk(ufvk_str: string, diversifier_index: number): string;

/**
 * Apply spend-auth signatures to a compact PCZT received from a signer.
 *
 * Signatures are supplied as a JSON array of objects with:
 * - `pool`: "orchard" or "ironwood"
 * - `action_index`: the action index in the corresponding bundle
 * - `signature_hex`: 64-byte spend-auth signature as hex
 *
 * # Arguments
 * * `pczt_hex` - hex-encoded compact PCZT (typically from `redact_pczt_compact`)
 * * `contributions_json` - JSON array of signature contributions
 *
 * # Returns
 * Hex-encoded PCZT with signatures applied
 */
export function apply_signature_contributions(pczt_hex: string, contributions_json: string): string;

/**
 * COLD (zigner / watch-only) sibling of `build_signed_ironwood_send`: build the
 * general ironwood send PCZT - spend the wallet's REAL ironwood notes to an
 * ARBITRARY `recipient` (plus change back to self) in a single V6 transaction -
 * and return a redacted-for-signer PCZT (same redaction contract as
 * `build_turnstile_migration_pczt`) as JSON `{ pczt_hex, summary, action_count }`
 * where `summary` is a `PcztSummary`.
 *
 * The wallet-owned ironwood spends are left UNSIGNED for the external cold
 * signer (zigner), which already knows how to sign redacted ironwood spends
 * (`pczt_signing::sign_redacted_pczt` signs the orchard AND ironwood spends).
 * Mirrors `build_turnstile_migration_pczt`'s param shape exactly, except:
 *  - `recipient` (unified address; its orchard-format receiver is the ironwood
 *    recipient) and `amount` are added, and
 *  - the anchor/notes/paths are the IRONWOOD tree's (real anchor + real
 *    ironwood spends), not the orchard tree's.
 *
 * `account_index` is accepted for API parity with the worker call shape but is
 * not used for derivation - the UFVK is already account-scoped.
 *
 * FAIL-CLOSED: inherits the hardened NU6.3 branch-id guard from
 * `build_ironwood_send_pczt_proven` - the tx binds branch id 0x37a5165b, the
 * caller MUST pass that real id as `expected_branch_id`, and the 0xffff_ffff
 * placeholder is refused. No value or recipient appears in any error.
 */
export function build_ironwood_send_pczt(ufvk_str: string, ironwood_notes_json: string, recipient: string, amount: bigint, fee: bigint, ironwood_anchor_hex: string, ironwood_merkle_paths_json: string, account_index: number, target_height: number, expected_branch_id: number, mainnet: boolean, memo_hex?: string | null): any;

/**
 * Build merkle paths for note positions by replaying compact blocks from a checkpoint.
 *
 * # Arguments
 * * `tree_state_hex` - hex-encoded orchard frontier from GetTreeState
 * * `compact_blocks_json` - JSON array of `[{height, actions: [{cmx_hex}]}]`
 * * `note_positions_json` - JSON array of note positions `[position_u64, ...]`
 * * `anchor_height` - the block height to use as anchor
 *
 * # Returns
 * JSON `{anchor_hex, paths: [{position, path: [{hash}]}]}`
 */
export function build_merkle_paths(tree_state_hex: string, compact_blocks_json: string, note_positions_json: string, anchor_height: number): any;

/**
 * Ironwood-tree variant of `build_merkle_paths`. Same JSON contract; feed
 * the ironwood frontier from GetTreeState and cmxs from ironwood bundles.
 */
export function build_merkle_paths_ironwood(tree_state_hex: string, compact_blocks_json: string, note_positions_json: string, anchor_height: number): any;

/**
 * Build a shielding transaction (transparent → orchard) with real Halo 2 proofs.
 *
 * PRE-NU6.3 ONLY. [`guard_orchard_shielding_allowed`] refuses to build at or
 * after the NU6.3 activation height (or when the supplied consensus branch id
 * is NU6.3), because orchard outputs are consensus-disabled from that point
 * and the resulting notes would be stranded. Use
 * [`build_shielding_transaction_ironwood`] there.
 *
 * Spends transparent P2PKH UTXOs and creates an orchard output to the sender's
 * own shielded address. Uses `orchard::builder::Builder` for proper action
 * construction and zero-knowledge proof generation (client-side).
 *
 * Returns hex-encoded signed v5 transaction bytes ready for broadcast.
 *
 * # Arguments
 * * `utxos_json` - JSON array of `{txid, vout, value, script}` objects
 * * `privkey_hex` - hex-encoded 32-byte secp256k1 private key for transparent inputs
 * * `recipient` - unified address string (u1... or utest1...) for orchard output
 * * `amount` - total zatoshis to shield (all selected UTXO value minus fee)
 * * `fee` - transaction fee in zatoshis
 * * `anchor_height` - block height for expiry (expiry_height = anchor_height + 100)
 * * `mainnet` - true for mainnet, false for testnet
 */
export function build_shielding_transaction(utxos_json: string, privkey_hex: string, recipient: string, amount: bigint, fee: bigint, anchor_height: number, mainnet: boolean, branch_id_hex?: string | null): string;

/**
 * Build a shielding transaction into whichever pool is CORRECT at
 * `target_height`, so a caller never has to (and never can) pick the stranded
 * one by omission.
 *
 * At/after NU6.3 activation this is [`build_shielding_transaction_ironwood`]
 * (and `branch_id_hex` must be the live NU6.3 branch id - there is no
 * fallback); before it, the legacy orchard builder. Returns hex-encoded raw
 * transaction bytes either way.
 */
export function build_shielding_transaction_auto(utxos_json: string, privkey_hex: string, recipient: string, amount: bigint, fee: bigint, target_height: number, mainnet: boolean, branch_id_hex?: string | null, memo_hex?: string | null): string;

/**
 * Build a signed transparent→IRONWOOD shielding transaction (NU6.3 / V6).
 *
 * The post-NU6.3 replacement for [`build_shielding_transaction`]: it spends the
 * selected transparent P2PKH UTXOs and creates ONE ironwood output for
 * `total_selected - fee` to `recipient`. Returns hex-encoded raw transaction
 * bytes, the same shape the legacy orchard builder returns, so the caller
 * broadcasts it unchanged.
 *
 * # Arguments
 * * `utxos_json` - JSON array of `{txid, vout, value, script}` (same shape as
 *   the orchard builder; `txid` is display/big-endian hex, `script` is the
 *   P2PKH scriptPubKey hex)
 * * `privkey_hex` - hex-encoded 32-byte secp256k1 private key owning every UTXO
 * * `recipient` - unified address whose orchard-format receiver is the ironwood
 *   recipient
 * * `amount` - UTXO-selection target (selection stops once `amount + fee` is
 *   covered); the ironwood output always carries ALL selected value minus fee
 * * `fee` - fee in zatoshi; MUST be at least the ZIP-317 conventional fee
 *   ([`zip317_shielding_fee`]) or the build is refused
 * * `target_height` - build height (must be at/after NU6.3 activation)
 * * `expected_branch_id` - branch id the wallet read from GetLightdInfo; must
 *   be 0x37a5165b
 * * `mainnet` - true for mainnet, false for testnet
 * * `memo_hex` - optional memo (hex, ≤512 bytes); empty memo when omitted
 */
export function build_shielding_transaction_ironwood(utxos_json: string, privkey_hex: string, recipient: string, amount: bigint, fee: bigint, target_height: number, expected_branch_id: number, mainnet: boolean, memo_hex?: string | null): string;

/**
 * HOT-WALLET general ironwood send: spend the wallet's REAL ironwood notes to
 * an ARBITRARY `recipient` (plus change back to self) in a single V6
 * transaction, sign the ironwood spends LOCALLY with a seed-derived key, and
 * return the hex-encoded, signed, broadcast-ready V6 transaction.
 *
 * This is the ironwood analogue of a normal orchard send and the sibling of
 * `build_signed_turnstile_migration`. Parameters mirror that function's shape,
 * with `recipient`/`amount` added and the anchor/notes/paths being the
 * ironwood tree's:
 *  - `seed_phrase` derives BOTH the orchard `FullViewingKey` (recipient/change
 *    scoping + nullifier verification) AND the `SpendAuthorizingKey` (local
 *    signing) via the exact ZIP-32 path `SpendingKey::from_zip32_seed`.
 *  - `recipient` is a unified address; its orchard-format receiver is used as
 *    the ironwood recipient (the ironwood pool shares the orchard address
 *    format - the note VERSION, not the address, selects the pool).
 *  - `ironwood_anchor_hex` is the REAL ironwood tree anchor;
 *    `ironwood_merkle_paths_json` are ironwood-tree paths from
 *    `build_merkle_paths_ironwood`.
 *
 * FAIL-CLOSED: inherits the hardened NU6.3 branch-id guard from the build core
 * - the tx binds branch id 0x37a5165b, the caller MUST pass that real id as
 * `expected_branch_id`, and the 0xffff_ffff placeholder is refused. No value
 * or recipient appears in any error.
 */
export function build_signed_ironwood_send(seed_phrase: string, ironwood_notes_json: string, recipient: string, amount: bigint, fee: bigint, ironwood_anchor_hex: string, ironwood_merkle_paths_json: string, account_index: number, target_height: number, expected_branch_id: number, mainnet: boolean, memo_hex?: string | null): string;

/**
 * Build a fully signed orchard spend transaction from a mnemonic wallet.
 *
 * Unlike `build_unsigned_transaction` (for cold signing), this function
 * derives the spending key from the mnemonic, constructs the full orchard
 * bundle with Halo 2 proofs, and returns a broadcast-ready transaction.
 *
 * # Arguments
 * * `seed_phrase` - BIP39 mnemonic for key derivation
 * * `notes_json` - JSON array of spendable notes with rseed/rho
 * * `recipient` - unified address string (u1... or utest1...)
 * * `amount` - zatoshis to send
 * * `fee` - transaction fee in zatoshis
 * * `anchor_hex` - merkle tree anchor (hex, 32 bytes)
 * * `merkle_paths_json` - JSON array of merkle paths from witness building
 * * `account_index` - ZIP-32 account index
 * * `mainnet` - true for mainnet, false for testnet
 *
 * # Returns
 * Hex-encoded signed v5 transaction bytes ready for broadcast
 */
export function build_signed_spend_transaction(seed_phrase: string, notes_json: any, recipient: string, amount: bigint, fee: bigint, anchor_hex: string, merkle_paths_json: any, account_index: number, mainnet: boolean, memo_hex?: string | null, branch_id_hex?: string | null): string;

/**
 * HOT-WALLET sibling of `build_turnstile_migration_pczt`: build the one-way
 * turnstile migration (spend the supplied orchard notes into the wallet's OWN
 * ironwood address in a single V6 transaction), sign the wallet-owned orchard
 * spends LOCALLY with a seed-derived key, and return the hex-encoded, signed,
 * broadcast-ready V6 transaction.
 *
 * Same parameter shape as `build_turnstile_migration_pczt`, except:
 *  - `seed_phrase` is PREPENDED. The orchard `FullViewingKey` (for the
 *    self-migration ironwood recipient) AND the `SpendAuthorizingKey` (for
 *    local signing) are BOTH derived from it via ZIP-32
 *    (`SpendingKey::from_zip32_seed(seed, coin_type, account_index)` - the
 *    exact key `UnifiedSpendingKey::from_seed(...).orchard()` and
 *    `build_signed_spend_transaction` derive), so there is no `ufvk_str`
 *    parameter: the seed fully determines the account and cannot disagree with
 *    a separately supplied viewing key.
 *  - `account_index` selects the ZIP-32 account (it IS used here, unlike the
 *    cold builder where the UFVK is already account-scoped).
 *  - Returns the signed transaction hex `String`, not a redacted PCZT.
 *
 * The FAIL-CLOSED NU6.3 branch-id guard is inherited unchanged from the shared
 * build core: the tx binds consensus branch id `expected_branch_id`, the
 * caller MUST pass the real 0x37a5165b (never the 0xffff_ffff placeholder).
 */
export function build_signed_turnstile_migration(seed_phrase: string, orchard_notes_json: string, fee: bigint, orchard_anchor_hex: string, orchard_merkle_paths_json: string, account_index: number, target_height: number, expected_branch_id: number, mainnet: boolean, memo_hex?: string | null): string;

/**
 * Build the one-way turnstile migration PCZT: spend the supplied orchard
 * notes into the wallet's OWN ironwood address in a single V6 transaction.
 *
 * The ironwood recipient is derived INTERNALLY from `ufvk_str` (self
 * migration); everything minus `fee` migrates. Returns a redacted-for-signer
 * PCZT (same redaction contract as `build_unsigned_pczt`) as JSON
 * `{ pczt_hex, summary, action_count }` where `summary` is a `PcztSummary`.
 *
 * `account_index` is accepted for API parity with the worker call shape but
 * is not used for derivation - the UFVK is already account-scoped.
 */
export function build_turnstile_migration_pczt(ufvk_str: string, orchard_notes_json: string, fee: bigint, orchard_anchor_hex: string, orchard_merkle_paths_json: string, account_index: number, target_height: number, expected_branch_id: number, mainnet: boolean, memo_hex?: string | null): any;

/**
 * Build a PCZT for cold-wallet signing via QR.
 *
 * `target_height` selects the consensus branch; pass any height ≥ NU6.1
 * activation for current mainnet operations. The tx version is derived from
 * network upgrade rules (currently V5).
 *
 * Returns JSON: `{ pczt_hex, summary, action_count }`.
 * The TS layer wraps `pczt_hex` in CBOR `{1: bytes}` and UR-encodes as
 * `zcash-pczt` for animated QR transport.
 */
export function build_unsigned_pczt(ufvk_str: string, notes_json: any, recipient: string, amount: bigint, fee: bigint, anchor_hex: string, merkle_paths_json: any, target_height: number, mainnet: boolean, memo_hex?: string | null): any;

/**
 * Build an unsigned shielding transaction (transparent → orchard) for cold-wallet signing.
 *
 * Same as `build_shielding_transaction` but does NOT sign the transparent inputs.
 * Instead, returns the per-input sighashes so an external signer (e.g. Zigner) can sign them.
 *
 * PRE-NU6.3 ONLY - same fail-closed gate as `build_shielding_transaction`.
 *
 * Returns JSON: `{ sighashes: [hex], unsigned_tx_hex: hex, summary: string }`
 */
export function build_unsigned_shielding_transaction(utxos_json: string, recipient: string, amount: bigint, fee: bigint, anchor_height: number, mainnet: boolean, branch_id_hex?: string | null): string;

/**
 * Build an unsigned transaction and return the data needed for cold signing.
 * Uses the PCZT (Partially Constructed Zcash Transaction) flow from the orchard
 * crate to produce real v5 transaction bytes with Halo 2 proofs.
 *
 * Returns JSON with:
 * - sighash: the transaction sighash (hex, 32 bytes)
 * - alphas: array of alpha randomizers for real spend actions only (hex, 32 bytes each)
 * - unsigned_tx: the serialized v5 transaction with dummy spend auth sigs (hex)
 * - spend_indices: array of action indices that need external signatures
 * - summary: human-readable transaction summary
 */
export function build_unsigned_transaction(ufvk_str: string, notes_json: any, recipient: string, amount: bigint, fee: bigint, anchor_hex: string, merkle_paths_json: any, _account_index: number, mainnet: boolean, memo_hex?: string | null, branch_id_hex?: string | null): any;

/**
 * One-shot witness + path builder used for initial backfill: replays blocks
 * the same way `build_merkle_paths` does but also returns serialized
 * witnesses and the resulting frontier so the caller can cache them.
 *
 * Returns JSON
 * `{anchor_hex, end_frontier_hex, entries: [{position, witness_hex, path: [{hash}]}]}`.
 */
export function build_witnesses_and_paths(tree_state_hex: string, compact_blocks_json: string, note_positions_json: string): any;

/**
 * Complete an orchard-only FROST multisig PCZT: inject the externally-aggregated
 * SpendAuth signatures (one per real spend, in `spend_indices` order, matching
 * what `build_unsigned_pczt` returned) into the PCZT, then extract the
 * broadcast-ready v5 tx. The mnemonic/zigner host and the poker escrow all
 * finish a FROST signing round this way (gh #17 PCZT migration).
 */
export function complete_orchard_pczt(pczt_hex: string, orchard_sigs_json: any, spend_indices_json: any): string;

/**
 * Complete an unsigned shielding transaction by patching in transparent signatures.
 *
 * Takes the unsigned tx hex (with empty scriptSigs) and an array of `{sig_hex, pubkey_hex}`
 * per transparent input. Constructs the P2PKH scriptSig for each input and returns the
 * final signed transaction hex.
 */
export function complete_shielding_transaction(unsigned_tx_hex: string, signatures_json: string): string;

/**
 * Complete a transaction by patching in spend auth signatures from cold wallet.
 *
 * Takes the unsigned v5 tx hex (with zero spend auth sigs for real spends) and an
 * array of hex-encoded 64-byte RedPallas signatures. Patches them into the correct
 * offsets in the orchard bundle.
 *
 * # Arguments
 * * `unsigned_tx_hex` - hex-encoded v5 transaction bytes from build_unsigned_transaction
 * * `signatures_json` - JSON array of hex-encoded 64-byte signatures, one per spend_index
 * * `spend_indices_json` - JSON array of action indices that need signatures (from build result)
 *
 * # Returns
 * Hex-encoded signed v5 transaction bytes ready for broadcast
 */
export function complete_transaction(unsigned_tx_hex: string, signatures_json: any, spend_indices_json: any): string;

/**
 * Canonical ZIP-244 txid for a raw signed v5 transaction.
 *
 * Public lightwalletd's `SendResponse` carries no txid, so the wallet derives
 * it locally instead of trusting the server to echo it. This is the same value
 * zidecar computes server-side and the same bytes that appear as
 * `CompactTx.hash` during sync — returned as lowercase hex in internal/wire
 * byte order so the outgoing record reconciles on the next scan.
 */
export function compute_txid(tx_hex: string): string;

/**
 * Create a PCZT sign request from transaction parameters
 * This is called by the online wallet to create the data that will be
 * transferred to the cold wallet via QR code.
 */
export function create_sign_request(account_index: number, sighash_hex: string, alphas_json: any, summary: string): string;

/**
 * Derive transparent private key from mnemonic using BIP44 path m/44'/133'/account'/0/index
 *
 * Returns hex-encoded 32-byte secp256k1 private key for signing transparent inputs.
 * Path components: purpose=44' (BIP44), coin_type=133' (ZEC), account', change=0, index
 */
export function derive_transparent_privkey(seed_phrase: string, account: number, index: number): string;

/**
 * Encode notes + merkle paths into CBOR bytes for ur:zcash-notes.
 *
 * This produces the exact format zigner expects: CBOR map with anchor,
 * height, mainnet flag, notes array with merkle paths, and optional
 * attestation signature.
 *
 * # Arguments
 * * `notes_json` - JSON array of `[{value, nullifier, cmx, position, block_height}]`
 * * `merkle_result_json` - JSON from build_merkle_paths: `{anchor_hex, paths: [{position, path: [{hash}]}]}`
 * * `anchor_height` - block height of the anchor
 * * `mainnet` - true for mainnet, false for testnet
 * * `attestation_hex` - optional hex-encoded 64-byte ed25519 anchor attestation
 *   signature from a trusted verifier (zidecar SignAnchor). Verified on the
 *   cold device against its anchor-verifier registry.
 *
 * # Returns
 * `Uint8Array` of CBOR bytes ready for UR fountain encoding
 */
export function encode_notes_bundle(notes_json: string, merkle_result_json: string, anchor_height: number, mainnet: boolean, attestation_hex?: string | null): Uint8Array;

/**
 * Estimate the size savings from compact PCZT redaction.
 *
 * Returns JSON with `full_bytes` (original size) and `compact_bytes` (after redaction).
 *
 * # Arguments
 * * `pczt_hex` - hex-encoded PCZT (v2 format)
 *
 * # Returns
 * JSON string: `{"full_bytes": number, "compact_bytes": number}`
 */
export function estimate_compact_savings(pczt_hex: string): string;

/**
 * Extract a broadcast-ready v5 transaction from a signed PCZT returned by zigner.
 *
 * Replaces the legacy `parse_signature_response` + `complete_transaction` pair.
 * Instead of patching raw signature bytes into a hand-serialized tx, we let the
 * pczt crate's `TransactionExtractor` reassemble the canonical v5 transaction
 * from the signed PCZT (collecting all auth sigs and validating the proof).
 *
 * Returns hex-encoded transaction bytes ready for broadcast.
 */
export function extract_signed_tx_from_pczt(pczt_hex: string): string;

/**
 * Compute the tree size from a hex-encoded frontier.
 */
export function frontier_tree_size(tree_state_hex: string): bigint;

/**
 * Ironwood-tree variant of `frontier_tree_size`.
 */
export function frontier_tree_size_ironwood(tree_state_hex: string): bigint;

/**
 * coordinator: aggregate signed shares into final signature
 */
export function frost_aggregate_shares(public_key_package_hex: string, message_hex: string, commitments_json: string, shares_json: string, randomizer_hex: string): string;

/**
 * Compute the attestation digest for an anchor.
 * Returns hex-encoded 32-byte SHA-256 digest.
 */
export function frost_attestation_digest(public_key_package_hex: string, anchor_hex: string, anchor_height: number, mainnet: boolean): string;

/**
 * Verify an attestation (96 bytes: sig || randomizer).
 */
export function frost_attestation_verify(attestation_hex: string, public_key_package_hex: string, anchor_hex: string, anchor_height: number, mainnet: boolean): boolean;

/**
 * trusted dealer: generate key packages for all participants
 */
export function frost_dealer_keygen(min_signers: number, max_signers: number): string;

/**
 * derive the multisig wallet's Orchard address (raw 43-byte address, hex-encoded)
 * from the group public key package and a caller-supplied `sk`. deterministic —
 * every participant computing this with the same inputs lands on byte-identical
 * output. pair with `frost_derive_ufvk(pkg, sk, mainnet)` so the stored address
 * and stored UFVK share a single source of truth for nk/rivk.
 */
export function frost_derive_address_from_sk(public_key_package_hex: string, sk_hex: string, diversifier_index: number): string;

/**
 * derive the multisig wallet's Orchard address (raw 43-byte address, hex-encoded).
 * non-deterministic — internally generates a random nk/rivk. only safe when a
 * single party derives-and-broadcasts. interactive DKG should use
 * `frost_derive_address_from_sk` instead.
 */
export function frost_derive_address_raw(public_key_package_hex: string, diversifier_index: number): string;

/**
 * derive the Orchard-only UFVK string (`uview1…` / `uviewtest1…`) from a
 * caller-supplied 32-byte SpendingKey and a FROST public key package.
 * every participant, given the same `sk_hex` + `public_key_package_hex`,
 * lands on byte-identical output.
 */
export function frost_derive_ufvk(public_key_package_hex: string, sk_hex: string, mainnet: boolean): string;

/**
 * DKG round 1: generate ephemeral identity + signed commitment
 */
export function frost_dkg_part1(max_signers: number, min_signers: number): string;

/**
 * DKG round 2: process signed round1 broadcasts, produce per-peer packages
 */
export function frost_dkg_part2(secret_hex: string, peer_broadcasts_json: string): string;

/**
 * DKG round 3: finalize — returns key package + public key package
 */
export function frost_dkg_part3(secret_hex: string, round1_broadcasts_json: string, round2_packages_json: string): string;

/**
 * coordinator: generate signed randomizer
 */
export function frost_generate_randomizer(ephemeral_seed_hex: string, message_hex: string, commitments_json: string): string;

/**
 * Inspect a PCZT's orchard outputs + recompute its canonical ZIP-244 sighash,
 * for the FROST joiner's display↔sighash binding (gh #17). Returns the same
 * JSON shape as `frost_parse_tx_outputs`, but sources both the bundle and the
 * sighash from the PCZT itself via `Pczt::into_effects()` → `v5_signature_hash`.
 * So the value the joiner checks is the canonical message its signature will
 * commit to — never a host-supplied claim. The host publishes the (proven,
 * io-finalized, redacted) PCZT; `into_effects` needs neither proof nor sigs.
 */
export function frost_inspect_pczt_outputs(pczt_hex: string, orchard_fvk_uview: string): string;

/**
 * Parse the unsigned v5 transaction and recover what each Orchard action
 * is sending, using the FROST wallet's UFVK to OVK-decrypt outputs.
 *
 * The spender (= each FROST joiner) owns the OVK that was used to encrypt
 * every action's output, so OVK decryption yields:
 *   - external scope hits → real recipients of the spend
 *   - internal scope hits → change back to our own multisig
 *   - non-decryptable     → dummy padding action (zero value by construction)
 *
 * Each joiner runs this on the unsigned tx bytes the host claims to have
 * built and compares the derived summary to the host's claimed
 * (recipient, amount, fee). A mismatch means the host lied.
 *
 * `orchard_fvk_uview` is the ZIP-316 unified viewing key string
 * (`uview1…` / `uviewtest1…`) stored alongside the wallet.
 *
 * Returns JSON:
 * {
 *   "actions": [
 *     { "index": u32,
 *       "pool": "orchard" | "ironwood",
 *       "amount_zat": u64,
 *       "recipient_raw_hex": "<43-byte hex>" | null,
 *       "is_change": bool,
 *       "decrypted": bool }
 *   ],
 *   "summary": {
 *     "total_send_zat": u64,
 *     "total_change_zat": u64,
 *     "decrypted_count": u32,
 *     "action_count": u32
 *   }
 * }
 */
export function frost_parse_tx_outputs(unsigned_tx_hex: string, orchard_fvk_uview: string): string;

/**
 * host-only: sample a random 32-byte SpendingKey for nk/rivk derivation.
 * retries until the sampled bytes land in the Pallas scalar range.
 * returns hex-encoded 32-byte `sk` that the host broadcasts to peers in R1.
 */
export function frost_sample_fvk_sk(): string;

/**
 * signing round 1: generate nonces + signed commitments
 */
export function frost_sign_round1(ephemeral_seed_hex: string, key_package_hex: string): string;

/**
 * signing round 2: produce signed signature share
 */
export function frost_sign_round2(ephemeral_seed_hex: string, key_package_hex: string, nonces_hex: string, message_hex: string, commitments_json: string, randomizer_hex: string): string;

/**
 * coordinator: aggregate shares into Orchard SpendAuth signature (64 bytes hex)
 */
export function frost_spend_aggregate(public_key_package_hex: string, sighash_hex: string, alpha_hex: string, commitments_json: string, shares_json: string): string;

/**
 * sighash-bound round 2: produce FROST share for one Orchard action
 */
export function frost_spend_sign_round2(key_package_hex: string, nonces_hex: string, sighash_hex: string, alpha_hex: string, commitments_json: string): string;

/**
 * authenticated variant: wraps share in SignedMessage for relay transport
 */
export function frost_spend_sign_round2_signed(ephemeral_seed_hex: string, key_package_hex: string, nonces_hex: string, sighash_hex: string, alpha_hex: string, commitments_json: string): string;

/**
 * Generate a new 24-word seed phrase
 */
export function generate_seed_phrase(): string;

/**
 * Get the commitment proof request data for a note
 * Returns the cmx that should be sent to zidecar's GetCommitmentProof
 */
export function get_commitment_proof_request(note_cmx_hex: string): string;

/**
 * Initialize panic hook for better error messages
 */
export function init(): void;

/**
 * Get number of threads available (0 if single-threaded)
 */
export function num_threads(): number;

/**
 * Parse signatures from cold wallet QR response
 * Returns JSON with sighash and orchard_sigs array
 */
export function parse_signature_response(qr_hex: string): any;

/**
 * Compact a PCZT for transmission to a signer by redacting per-action cv_net,
 * v6 bundle anchors, output cmx, and replacing enc_ciphertext with memo plaintext
 * (trimmed to last nonzero byte). Builds on the existing signer redaction.
 *
 * This function is used to minimize the size of PCZT requests sent to a hardware
 * signer device. The signer can recompute the redacted fields from the remaining data.
 *
 * # Arguments
 * * `pczt_hex` - hex-encoded PCZT (v2 format)
 *
 * # Returns
 * Hex-encoded compact PCZT
 */
export function redact_pczt_compact(pczt_hex: string): string;

/**
 * Which shielded pool a transparent→shielded transaction must target at
 * `target_height`: `"ironwood"` at/after NU6.3 activation, `"orchard"` before.
 *
 * Callers that do not pick a pool explicitly MUST resolve it through this
 * function (or through [`build_shielding_transaction_auto`], which calls it)
 * rather than defaulting to orchard: from NU6.3 onwards an orchard output is
 * a stranded note (orchard sends are consensus-disabled, so the funds can only
 * be moved again by a turnstile migration that costs a second fee).
 */
export function shielding_pool_for_height(target_height: number, mainnet: boolean): string;

/**
 * Derive a transparent (t1.../tm...) address from a UFVK string at a given address index.
 * Returns the base58check-encoded P2PKH address.
 */
export function transparent_address_from_ufvk(ufvk_str: string, address_index: number): string;

/**
 * Derive compressed public key from UFVK transparent component for a given address index.
 *
 * Uses BIP44 external path: `m/44'/133'/account'/0/<address_index>`
 * Returns hex-encoded 33-byte compressed secp256k1 public key.
 */
export function transparent_pubkey_from_ufvk(ufvk_str: string, address_index: number): string;

/**
 * Compute the tree root from a hex-encoded frontier.
 */
export function tree_root_hex(tree_state_hex: string): string;

/**
 * Ironwood-tree variant of `tree_root_hex`.
 */
export function tree_root_hex_ironwood(tree_state_hex: string): string;

export function ur_decode_frames(parts_json: string, expected_type: string): string;

/**
 * Encode CBOR bytes as UR-encoded animated QR string frames.
 * Returns JSON array of UR strings suitable for QR display.
 * ur_type: e.g. "zcash-notes", "zigner-contacts", "zigner-backup"
 * fragment_size: max bytes per QR frame (200-500 typical, 0 = single QR)
 */
export function ur_encode_frames(cbor_data: Uint8Array, ur_type: string, fragment_size: number): string;

/**
 * Validate a seed phrase
 */
export function validate_seed_phrase(seed_phrase: string): boolean;

/**
 * Authoritatively validate a Unified Full Viewing Key string.
 *
 * Returns `true` iff the string decodes via the *same*
 * `zcash_keys::UnifiedFullViewingKey::decode` the signing path uses. This
 * is deliberately the one and only UFVK decoder: a separate hand-rolled
 * bech32m/checksum validator at the import boundary would be a second
 * implementation that can disagree with the authority, which is worse than
 * no check. Structural pre-screening (HRP/charset/length) still happens in
 * the pure `@repo/wallet` parser for cheap fail-fast and to keep that
 * package wasm-free; this is the cryptographic gate the import dispatch
 * calls before persisting a wallet record.
 *
 * Network is inferred from the HRP (`uview1` = mainnet, else testnet),
 * matching every other UFVK entry point in this module.
 */
export function validate_ufvk(ufvk_str: string): boolean;

/**
 * Get library version
 */
export function version(): string;

/**
 * Extract a merkle path from a stored per-note witness. Returns JSON
 * `{position, root_hex, path: [{hash}]}`. The caller must cross-check
 * `root_hex` against the anchor they intend to sign over.
 */
export function witness_extract_path(witness_hex: string): any;

/**
 * Ironwood-tree variant of `witness_extract_path`. Same JSON contract.
 */
export function witness_extract_path_ironwood(witness_hex: string): any;

/**
 * Advance tracked witnesses over a range of compact blocks, optionally
 * seeding new ones. Returns JSON
 * `{end_frontier_hex, anchor_hex, witnesses: [{id, position, witness_hex}], seeded_ids: [...], end_position}`.
 *
 * # Arguments
 * * `start_frontier_hex` - tree state BEFORE the first block
 * * `compact_blocks_json` - `[{height, actions: [{cmx_hex}]}]` in order
 * * `existing_witnesses_json` - `[{id, witness_hex}]` - witnesses to advance
 * * `new_notes_json` - `[{id, position}]` - witnesses to seed within this range
 */
export function witness_sync_update(start_frontier_hex: string, compact_blocks_json: string, existing_witnesses_json: string, new_notes_json: string): any;

/**
 * Ironwood-tree variant of `witness_sync_update`. Same JSON contract.
 */
export function witness_sync_update_ironwood(start_frontier_hex: string, compact_blocks_json: string, existing_witnesses_json: string, new_notes_json: string): any;

/**
 * ZIP-317 conventional fee for an ironwood shielding transaction with `n`
 * transparent P2PKH inputs (JS-visible; see [`zip317_shielding_fee`]).
 */
export function zip317_shielding_fee_zat(n_transparent_inputs: number): bigint;

/**
 * Encode CBOR bytes as zoda transport QR frames (verified erasure coding).
 * Returns JSON array of `zt:type/hex` strings.
 * k = minimum frames to reconstruct, n = total frames.
 */
export function zt_encode_frames(cbor_data: Uint8Array, zt_type: string, k: number, n: number): string;

/**
 * Encode CBOR bytes as zoda transport QR frames, auto-sizing `k`/`n` so each
 * hex-encoded `zt:` frame fits a scannable QR regardless of payload size.
 * Returns JSON array of `zt:type/hex` strings.
 *
 * - `max_qr_bytes`: max *raw* frame bytes before hex encoding. The QR string
 *   is `len("zt:type/") + 2 * frame_bytes`, so pick this from the target QR
 *   capacity: roughly `qr_byte_capacity / 2 - prefix`. ~600 gives a ~1.2 KB
 *   QR string (≈ v24 at ECC-L), comfortable for handheld scanning.
 * - `redundancy_pct`: extra parity frames as a percentage of `k` (e.g. 30).
 */
export function zt_encode_frames_auto(cbor_data: Uint8Array, zt_type: string, max_qr_bytes: number, redundancy_pct: number): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly __wbg_walletkeys_free: (a: number, b: number) => void;
    readonly __wbg_watchonlywallet_free: (a: number, b: number) => void;
    readonly address_from_ufvk: (a: number, b: number, c: number) => [number, number, number, number];
    readonly apply_signature_contributions: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly build_ironwood_send_pczt: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number) => [number, number, number];
    readonly build_merkle_paths: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly build_shielding_transaction: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly build_shielding_transaction_auto: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number, m: number, n: number) => [number, number, number, number];
    readonly build_shielding_transaction_ironwood: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number, m: number) => [number, number, number, number];
    readonly build_signed_ironwood_send: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number) => [number, number, number, number];
    readonly build_signed_spend_transaction: (a: number, b: number, c: any, d: number, e: number, f: bigint, g: bigint, h: number, i: number, j: any, k: number, l: number, m: number, n: number, o: number, p: number) => [number, number, number, number];
    readonly build_signed_turnstile_migration: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => [number, number, number, number];
    readonly build_turnstile_migration_pczt: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => [number, number, number];
    readonly build_unsigned_pczt: (a: number, b: number, c: any, d: number, e: number, f: bigint, g: bigint, h: number, i: number, j: any, k: number, l: number, m: number, n: number) => [number, number, number];
    readonly build_unsigned_shielding_transaction: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly build_unsigned_transaction: (a: number, b: number, c: any, d: number, e: number, f: bigint, g: bigint, h: number, i: number, j: any, k: number, l: number, m: number, n: number, o: number, p: number) => [number, number, number];
    readonly build_witnesses_and_paths: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly complete_orchard_pczt: (a: number, b: number, c: any, d: any) => [number, number, number, number];
    readonly complete_shielding_transaction: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly complete_transaction: (a: number, b: number, c: any, d: any) => [number, number, number, number];
    readonly compute_txid: (a: number, b: number) => [number, number, number, number];
    readonly create_sign_request: (a: number, b: number, c: number, d: any, e: number, f: number) => [number, number, number, number];
    readonly derive_transparent_privkey: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly encode_notes_bundle: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly estimate_compact_savings: (a: number, b: number) => [number, number, number, number];
    readonly extract_signed_tx_from_pczt: (a: number, b: number) => [number, number, number, number];
    readonly frontier_tree_size: (a: number, b: number) => [bigint, number, number];
    readonly generate_seed_phrase: () => [number, number, number, number];
    readonly get_commitment_proof_request: (a: number, b: number) => [number, number, number, number];
    readonly num_threads: () => number;
    readonly parse_signature_response: (a: number, b: number) => [number, number, number];
    readonly redact_pczt_compact: (a: number, b: number) => [number, number, number, number];
    readonly shielding_pool_for_height: (a: number, b: number) => [number, number];
    readonly transparent_address_from_ufvk: (a: number, b: number, c: number) => [number, number, number, number];
    readonly transparent_pubkey_from_ufvk: (a: number, b: number, c: number) => [number, number, number, number];
    readonly tree_root_hex: (a: number, b: number) => [number, number, number, number];
    readonly ur_decode_frames: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly ur_encode_frames: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly validate_seed_phrase: (a: number, b: number) => number;
    readonly validate_ufvk: (a: number, b: number) => number;
    readonly version: () => [number, number];
    readonly walletkeys_calculate_balance: (a: number, b: any, c: any) => [bigint, number, number];
    readonly walletkeys_decrypt_transaction_memos: (a: number, b: number, c: number) => [number, number, number];
    readonly walletkeys_export_fvk_qr_hex: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly walletkeys_from_seed_phrase: (a: number, b: number) => [number, number, number];
    readonly walletkeys_get_address: (a: number) => [number, number];
    readonly walletkeys_get_fvk_hex: (a: number) => [number, number];
    readonly walletkeys_get_receiving_address: (a: number, b: number) => [number, number];
    readonly walletkeys_get_receiving_address_at: (a: number, b: number, c: number) => [number, number];
    readonly walletkeys_scan_actions: (a: number, b: any) => [number, number, number];
    readonly walletkeys_scan_actions_ironwood_parallel: (a: number, b: number, c: number) => [number, number, number];
    readonly walletkeys_scan_actions_parallel: (a: number, b: number, c: number) => [number, number, number];
    readonly watchonlywallet_decrypt_transaction_memos: (a: number, b: number, c: number) => [number, number, number];
    readonly watchonlywallet_export_fvk_hex: (a: number) => [number, number];
    readonly watchonlywallet_from_fvk_bytes: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly watchonlywallet_from_qr_hex: (a: number, b: number) => [number, number, number];
    readonly watchonlywallet_from_ufvk: (a: number, b: number) => [number, number, number];
    readonly watchonlywallet_get_account_index: (a: number) => number;
    readonly watchonlywallet_get_address: (a: number) => [number, number];
    readonly watchonlywallet_get_address_at: (a: number, b: number) => [number, number];
    readonly watchonlywallet_is_mainnet: (a: number) => number;
    readonly watchonlywallet_scan_actions_ironwood_parallel: (a: number, b: number, c: number) => [number, number, number];
    readonly watchonlywallet_scan_actions_parallel: (a: number, b: number, c: number) => [number, number, number];
    readonly witness_extract_path: (a: number, b: number) => [number, number, number];
    readonly witness_sync_update: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly zip317_shielding_fee_zat: (a: number) => bigint;
    readonly zt_encode_frames: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly zt_encode_frames_auto: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly witness_extract_path_ironwood: (a: number, b: number) => [number, number, number];
    readonly init: () => void;
    readonly witness_sync_update_ironwood: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly build_merkle_paths_ironwood: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly tree_root_hex_ironwood: (a: number, b: number) => [number, number, number, number];
    readonly frontier_tree_size_ironwood: (a: number, b: number) => [bigint, number, number];
    readonly frost_aggregate_shares: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly frost_attestation_digest: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly frost_attestation_verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly frost_dealer_keygen: (a: number, b: number) => [number, number, number, number];
    readonly frost_derive_address_from_sk: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly frost_derive_address_raw: (a: number, b: number, c: number) => [number, number, number, number];
    readonly frost_derive_ufvk: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly frost_dkg_part1: (a: number, b: number) => [number, number, number, number];
    readonly frost_dkg_part2: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly frost_dkg_part3: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly frost_generate_randomizer: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly frost_inspect_pczt_outputs: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly frost_parse_tx_outputs: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly frost_sample_fvk_sk: () => [number, number];
    readonly frost_sign_round1: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly frost_sign_round2: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly frost_spend_aggregate: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly frost_spend_sign_round2: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly frost_spend_sign_round2_signed: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly rustsecp256k1_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_context_destroy: (a: number) => void;
    readonly rustsecp256k1_v0_10_0_context_create: (a: number) => number;
    readonly memory: WebAssembly.Memory;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_thread_destroy: (a?: number, b?: number, c?: number) => void;
    readonly __wbindgen_start: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput, memory?: WebAssembly.Memory, thread_stack_size?: number }} module - Passing `SyncInitInput` directly is deprecated.
 * @param {WebAssembly.Memory} memory - Deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput, memory?: WebAssembly.Memory, thread_stack_size?: number } | SyncInitInput, memory?: WebAssembly.Memory): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput>, memory?: WebAssembly.Memory, thread_stack_size?: number }} module_or_path - Passing `InitInput` directly is deprecated.
 * @param {WebAssembly.Memory} memory - Deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput>, memory?: WebAssembly.Memory, thread_stack_size?: number } | InitInput | Promise<InitInput>, memory?: WebAssembly.Memory): Promise<InitOutput>;

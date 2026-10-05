/* tslint:disable */
/* eslint-disable */

/**
 * A relay session's ciphers, held across the whole session.
 */
export class FrostRelayCipher {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Decrypt from one peer. Authenticates the sender: Noise_K mixes the
     * sender's static key into the key schedule, so a message relabelled as
     * coming from somebody else does not decrypt.
     */
    decrypt(sender_hex: string, msg_hex: string): Uint8Array;
    /**
     * Encrypt for one peer. Returns hex.
     */
    encrypt(recipient_hex: string, msg: Uint8Array): string;
    /**
     * `peers_hex` is a JSON array of hex-encoded 32-byte public keys.
     */
    constructor(private_key_hex: string, peers_hex: string);
}

/**
 * One pool's note commitment tree (orchard or ironwood: same hash, same
 * shape). See `NoteTreeCore` for each method's contract.
 */
export class NoteTree {
    free(): void;
    [Symbol.dispose](): void;
    append_blocks(start_position: number, blocks: Uint8Array, marked: Uint32Array, checkpoint_from: number): void;
    checkpoint_at_or_below(height: number): number | undefined;
    insert_frontier(frontier_hex: string, height: number): void;
    /**
     * returns how many roots were taken (resume from start_index + n)
     */
    insert_subtree_roots(start_index: number, roots: Uint8Array): number;
    insert_witness(witness_hex: string, height: number): void;
    is_marked(position: number): boolean;
    latest_checkpoint(): number | undefined;
    load_cap(bytes: Uint8Array): void;
    load_checkpoints(bytes: Uint8Array): void;
    load_shard(index: number, bytes: Uint8Array): void;
    constructor(max_checkpoints: number);
    /**
     * tree size at the newest checkpoint, or undefined before seeding
     */
    next_position(): number | undefined;
    oldest_checkpoint(): number | undefined;
    /**
     * witnesses for `positions` by replaying `blocks` from `frontier_hex` up to
     * the checkpoint at `height`; returns how many were inserted
     */
    recover(frontier_hex: string, blocks: Uint8Array, positions: Uint32Array, height: number): number;
    /**
     * hex root at the checkpoint, or undefined if it is not retained
     */
    root_at(height: number): string | undefined;
    /**
     * `{rewrite, shards: [[index, Uint8Array]], cap?: Uint8Array, checkpoints?: Uint8Array}`
     */
    take_changes(): any;
    truncate(height: number): boolean;
    /**
     * JSON `{position, root_hex, path: [{hash}]}`, as `witness_extract_path`
     */
    witness(position: number, height: number): string;
}

/**
 * The spend authority of one ZIP-32 account, held only inside the zcash worker
 * for the length of one send. Holds the 64-byte BIP39 seed in a zeroizing
 * buffer and derives each key at the moment of use; JS must call `free()` when
 * the send ends so the seed is wiped.
 */
export class SpendKeys {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Parse the phrase once and keep only its seed. The error never quotes the
     * phrase.
     */
    constructor(seed_phrase: string, account: number, mainnet: boolean);
    /**
     * The account's default receive address exactly as the scanner derives it
     * (`WalletKeys::get_receiving_address`): where transparent funds shield to.
     */
    receiving_address(): string;
    /**
     * Sign a proven PCZT from the prover and return the signed tx hex.
     */
    sign_pczt(pczt_hex: string): string;
    /**
     * Sign an unsigned tx with transparent inputs (a shielding tx as raw V5 or
     * PCZT, or a t->t PCZT from `build_unsigned_transparent_transaction`) whose
     * every input is locked to transparent address `index`, and return the
     * signed tx hex.
     * `sighashes_json` is the builder's `sighashes` array; the PCZT completion
     * re-verifies each signature against the carrier's own sighash.
     */
    sign_shielding(index: number, unsigned_tx_hex: string, sighashes_json: string): string;
    /**
     * Compressed pubkey of transparent address `index` (m/44'/133'/account'/0/index).
     */
    transparent_pubkey(index: number): string;
    /**
     * The account's unified full viewing key: what the prover builds from.
     * Derived at coin type 133 like every other zafu key; `mainnet` picks
     * only the encoding.
     */
    ufvk(): string;
}

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
     * Derive wallet keys for ZIP 32 account `account` (m/32'/133'/account').
     * Account 0 is identical to the constructor. Used by zafu "pockets".
     */
    static from_seed_phrase_account(seed_phrase: string, account: number): WalletKeys;
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
     * Get receiving address at a full 11-byte diversifier index (22 hex chars, LE)
     */
    get_receiving_address_at_index(index_hex: string, mainnet: boolean): string;
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
     * Get address at a full 11-byte diversifier index (22 hex chars, LE)
     */
    get_address_at_index(index_hex: string): string;
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
 * Derive an Orchard receiving address from a UFVK string at a full 11-byte
 * diversifier index (22 hex chars, LE).
 */
export function address_from_ufvk_at_index(ufvk_str: string, index_hex: string): string;

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
 * Build the governance delegation PCZT for one bundle (phase 1 of 2).
 *
 * Args:
 * * `fvk_hex` — 96-byte Orchard FVK of the voter's account.
 * * `seed_fingerprint_hex` — 32-byte ZIP-32 seed fingerprint.
 * * `account_index` — ZIP-32 account index.
 * * `hotkey_pubkey_hex` — 43-byte hotkey raw Orchard address (from
 *   `generate_voting_hotkey`); the governance output target.
 * * `notes_json` — `[NoteInfoDto]` (the delegated notes).
 * * `round_params_json` — `RoundParamsDto`.
 * * `consensus_branch_id` — branch id the host's node reports (lightwalletd).
 *   It must have the Ironwood pool (NU6.3 or later, NU7 included), and so
 *   must the snapshot height. It only selects the note protocol: the PCZT is
 *   always built under TX1 v1's V6 / NU6.3 profile, the one the vote chain
 *   rebuilds the signed digest under.
 * * `round_name` — display memo text.
 * * `network` — "mainnet" | "testnet" | "regtest".
 * * `bundle_index` — delegation bundle index (echoed into `delegation_state`).
 *
 * Returns `{ redacted_pczt_hex, pczt_sighash_hex, rk_hex, action_index,
 * delegated_weight, display_memo, real_note_nullifiers_hex, dummy_note_
 * nullifiers_hex, delegation_context_json, delegation_state_json }`.
 */
export function build_delegation_pczt(fvk_hex: string, seed_fingerprint_hex: string, account_index: number, hotkey_pubkey_hex: string, notes_json: string, round_params_json: string, consensus_branch_id: number, round_name: string, network: string, bundle_index: number): string;

/**
 * Seed-free general ironwood send builder (zigner, watch-only and, signed in the
 * worker by [`SpendKeys`], hot wallets): build the
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
 *
 * `expiry_delta` (optional, last argument): blocks after `target_height` at
 * which the transaction expires. Omitted means [`LEGACY_PCZT_EXPIRY_DELTA`]
 * (40), exactly what this builder produced before the argument existed.
 * Validated by [`resolve_pczt_expiry_height`]. The resolved height is returned
 * as `expiry_height`.
 */
export function build_ironwood_send_pczt(ufvk_str: string, ironwood_notes_json: string, recipient: string, amount: bigint, fee: bigint, ironwood_anchor_hex: string, ironwood_merkle_paths_json: string, account_index: number, target_height: number, expected_branch_id: number, mainnet: boolean, memo_hex?: string | null, expiry_delta?: number | null): any;

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
 * `expiry_delta` (optional, last argument): blocks after `target_height` at
 * which the transaction expires. Omitted means the legacy default of
 * [`LEGACY_PCZT_EXPIRY_DELTA`] (40), exactly what this builder produced before
 * the argument existed. Validated by [`resolve_pczt_expiry_height`].
 *
 * Returns JSON: `{ pczt_hex, summary, action_count, sighash, alphas,
 * spend_indices, expiry_height }`.
 * The TS layer wraps `pczt_hex` in CBOR `{1: bytes}` and UR-encodes as
 * `zcash-pczt` for animated QR transport.
 */
export function build_unsigned_pczt(ufvk_str: string, notes_json: any, recipient: string, amount: bigint, fee: bigint, anchor_hex: string, merkle_paths_json: any, target_height: number, mainnet: boolean, memo_hex?: string | null, expiry_delta?: number | null): any;

/**
 * Build an unsigned shielding transaction (transparent → orchard) for cold-wallet signing.
 *
 * Does NOT sign the transparent inputs. Returns the per-input sighashes so an external signer (e.g. Zigner) can sign them.
 *
 * PRE-NU6.3 ONLY - [`guard_orchard_shielding_allowed`] refuses at or after activation.
 *
 * Returns JSON: `{ sighashes: [hex], unsigned_tx_hex: hex, summary: string }`
 */
export function build_unsigned_shielding_transaction(utxos_json: string, recipient: string, amount: bigint, fee: bigint, anchor_height: number, mainnet: boolean, branch_id_hex?: string | null): string;

/**
 * Build an UNSIGNED transparent→IRONWOOD shielding transaction (NU6.3 / V6) for
 * cold-wallet / watch-only / zigner signing.
 *
 * The post-NU6.3 replacement for [`build_unsigned_shielding_transaction`] (which
 * builds a now-consensus-disabled orchard V5 bundle). It runs the full guarded
 * ironwood pipeline through the proof but stops BEFORE signing, and returns the
 * SAME JSON contract the orchard unsigned builder returns:
 *   `{ sighashes: [hex_32b...], unsigned_tx_hex: hex, summary: string }`
 * so the existing zigner sighash encoder needs no change.
 *
 * IMPORTANT: `unsigned_tx_hex` here is the serialized PCZT (magic `b"PCZT"`), NOT
 * a raw transaction - the canonical librustzcash cold-signing carrier. The
 * air-gapped signer only ever handles the 32-byte `sighashes`; completion must
 * route to [`complete_shielding_pczt`]. [`complete_shielding_transaction`]
 * sniffs the PCZT magic and delegates, so an unchanged completion call site also
 * works.
 *
 * # Arguments
 * * `utxos_json` - JSON array of `{txid, vout, value, script}` (same shape as the
 *   signed builder)
 * * `pubkey_hex` - 33-byte compressed secp256k1 pubkey owning every UTXO (from
 *   e.g. [`transparent_pubkey_from_ufvk`])
 * * `recipient` - unified address whose orchard-format receiver is the ironwood
 *   recipient
 * * `amount`, `fee`, `target_height`, `expected_branch_id`, `mainnet`, `memo_hex`
 *   - identical semantics to [`build_shielding_transaction_ironwood_core`]
 */
export function build_unsigned_shielding_transaction_ironwood(utxos_json: string, pubkey_hex: string, recipient: string, amount: bigint, fee: bigint, target_height: number, expected_branch_id: number, mainnet: boolean, memo_hex?: string | null, ovk_from_ufvk?: string | null): string;

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
 * Build an UNSIGNED t->t transaction from public data only: the UTXOs of one
 * address and its 33-byte compressed `pubkey_hex`. Outputs are
 * [recipient, OP_RETURN(`null_data_hex`, at most 80 bytes), change to the same
 * address]. Returns JSON
 * `{sighashes, unsigned_tx_hex, inputs, total_in, fee, change, short}`, where
 * `unsigned_tx_hex` is a PCZT for `SpendKeys.sign_shielding`.
 */
export function build_unsigned_transparent_transaction(utxos_json: string, pubkey_hex: string, recipient: string, amount: bigint, target_height: number, expected_branch_id: number, mainnet: boolean, null_data_hex?: string | null): string;

/**
 * Build the `POST /cast-vote` body ([`VoteCommitmentWire`]) for one HOT vote.
 *
 * Binary fields are base64 STANDARD; `vote_round_id` is hex-decoded then
 * base64-encoded (matching `wire_codec`). Runs the ZKP #2 proof.
 */
export function build_vote_commitment_wire(hotkey_secret_hex: string, round_params_json: string, delegation_state_json: string, van_witness_json: string, vote_json: string, network: string): string;

/**
 * Build the helper-share payloads (`[VoteShareWire]`, `POST {helper}/shielded-vote/v1/shares`)
 * for a vote that is already on chain.
 *
 * `commitment_bundle_json` is the recovery bundle `cast_vote_hot_wire`
 * returned for this vote; `vc_tree_position` is the vote commitment's leaf
 * index in the round's commitment tree, known once the cast-vote transaction
 * is included. No proof runs here, so the shares match the submitted
 * commitment.
 */
export function build_vote_shares_from_recovery(commitment_bundle_json: string, vc_tree_position: bigint, submit_at: bigint): string;

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
 * Build the `POST /cast-vote` body plus what the host keeps for after it lands.
 *
 * Runs ZKP #2 once. Returns
 * `{ proposal_id, wire, commitment_bundle_json, next_delegation_state_json }`.
 *
 * No helper shares come back from here: a share commits to the vote's leaf
 * index in the round's commitment tree (`vc_tree_position`), which only
 * exists once the cast-vote transaction is included. Shares built before
 * that carry a guessed position, and the helper's reveal for them never
 * matches the tree, so the vote silently drops out of the tally. Build them
 * with [`build_vote_shares_from_recovery`] from `commitment_bundle_json` and
 * the included position.
 *
 * `commitment_bundle_json` holds the share secrets (it can rebuild shares,
 * which carry `vote_decision`): store it encrypted.
 *
 * `next_delegation_state_json` is this bundle's state for its next cast
 * (this proposal's authority bit cleared). Store it only after the cast is
 * on chain: if the cast never lands, the old state is still the valid one,
 * and a cleared bit would lock the proposal out of a retry.
 */
export function cast_vote_hot_wire(hotkey_secret_hex: string, round_params_json: string, delegation_state_json: string, van_witness_json: string, vote_json: string, network: string): string;

/**
 * Ironwood (NU6.3 / v6) sibling of `complete_orchard_pczt`: inject the
 * externally-aggregated SpendAuth signatures - one per real ironwood spend, in
 * the `spend_indices` order `build_ironwood_send_pczt` returned - and extract
 * the broadcast-ready V6 tx.
 *
 * FROST itself is pool-independent: a RedPallas spend-auth signature over the
 * shielded sighash is the same for an ironwood action as for an orchard one.
 * The only thing that differs here is which bundle the signature is applied
 * to, so this is `complete_orchard_pczt` with `apply_ironwood_signature`.
 *
 * The sighash the signatures must commit to is the `sighash` field returned by
 * `build_ironwood_send_pczt`. `extract_signed_tx_from_pczt_bytes` re-verifies
 * every spend-auth and binding signature against it, so a signature aggregated
 * over the wrong message fails here rather than on the network.
 */
export function complete_ironwood_pczt(pczt_hex: string, ironwood_sigs_json: any, spend_indices_json: any): string;

/**
 * Complete an orchard-only FROST multisig PCZT: inject the externally-aggregated
 * SpendAuth signatures (one per real spend, in `spend_indices` order, matching
 * what `build_unsigned_pczt` returned) into the PCZT, then extract the
 * broadcast-ready v5 tx. The mnemonic/zigner host and the poker escrow all
 * finish a FROST signing round this way (gh #17 PCZT migration).
 */
export function complete_orchard_pczt(pczt_hex: string, orchard_sigs_json: any, spend_indices_json: any): string;

/**
 * Complete an unsigned ironwood shielding PCZT (from
 * [`build_unsigned_shielding_transaction_ironwood`]) into a broadcast-ready V6
 * transaction hex. See [`complete_shielding_pczt_inner`] for the semantics.
 *
 * `signatures_json` is `[{sig_hex, pubkey_hex}, ...]`, one per transparent input
 * in index order - the exact shape [`complete_shielding_transaction`] accepts,
 * so a caller that always routes ironwood completions here (or one that reuses
 * `complete_shielding_transaction`, which sniffs the PCZT magic) is unchanged.
 */
export function complete_shielding_pczt(pczt_hex: string, signatures_json: string): string;

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

export function describe_pczt_for_ledger(pczt_hex: string, mainnet: boolean): string;

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
 * Finalize delegation (phase 2 of 2): run ZKP #1 with host-injected IMT proofs
 * and attach the cold signer's spend-auth signature into the submission wire.
 *
 * Args:
 * * `delegation_context_json` — the opaque blob from `build_delegation_pczt`.
 * * `merkle_witnesses_json` — `[WitnessDto]`, one per note, in note order.
 * * `imt_proofs_json` — `[ImtProofDto]` covering BOTH the real note nullifiers
 *   and the `dummy_note_nullifiers_hex` reported by phase 1 (keyed by nullifier).
 * * `spend_auth_sig_hex` — 64-byte SpendAuth signature from the cold signer.
 * * `sighash_hex` — 32-byte sighash the signer signed (must equal the PCZT sighash).
 *
 * Returns `{ delegation_submission_wire_json }` — the `POST /delegate-vote` body.
 */
export function finalize_delegation(delegation_context_json: string, merkle_witnesses_json: string, imt_proofs_json: string, spend_auth_sig_hex: string, sighash_hex: string): string;

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
 *
 * ADDITIVE fields for intent verification (older consumers ignore them):
 *
 * per action:
 *   - `committed_value_zat` / `committed_recipient_raw_hex`: the output note's
 *     value and recipient as carried in the PCZT, reported ONLY when
 *     `cmx_verified` is true, i.e. when `(recipient, value, rho, rseed)`
 *     recompute the action's `cmx`. `cmx` is sighash-bound, so these are the
 *     values the chain will actually record, independent of whether the
 *     output is OVK-decryptable. (`null` when the PCZT lacks the fields or they
 *     do not match.)
 *   - `cmx_verified`: bool, as above.
 *   - `recipient_scope`: `"external" | "internal" | null` - which scope of the
 *     inspecting UFVK's orchard key the committed recipient belongs to
 *     (`FullViewingKey::scope_for_address`), `null` for a foreign address.
 *     This is a key-derivation fact, unlike `is_change`, which only says which
 *     OVK decrypted the output.
 *
 * transaction level:
 *   - `expiry_height`, `tx_version`, `consensus_branch_id` (from the global).
 *   - `value_balance_zat`: `{ orchard, ironwood, sapling }` (i64 each, the
 *     value the sighash binds; 0 when the bundle is absent).
 *   - `sapling_present`: bool.
 *   - `transparent_input_count`, `transparent_input_total_zat`.
 *   - `transparent_outputs`: `[{ value_zat, script_pubkey_hex, address }]`,
 *     `address` = encoded P2PKH/P2SH t-address or `null` for any other script.
 *   - `fee_zat`: `orchard + ironwood + sapling value balances + transparent
 *     inputs - transparent outputs`; `null` when negative or out of range.
 *   - `committed_outputs_error`: `null`, or why the per-action committed view
 *     could not be produced (the committed fields are then all null/false).
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
 * Generate a relay keypair. Returns JSON `{ "private": hex, "public": hex }`.
 *
 * The public key is what other participants address messages to, and what
 * frostd authenticates you by.
 */
export function frost_relay_generate_keypair(): string;

/**
 * Sign a frostd login challenge with a relay private key.
 *
 * frostd authenticates by verifying XEdDSA over the participant's X25519
 * key - the same key Noise uses. This exists because without it the browser
 * can generate keys and encrypt, but cannot log in at all, which is how the
 * gap was found: by trying to wire the client up.
 */
export function frost_relay_sign_challenge(private_key_hex: string, challenge: string): string;

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
 * Generate a fresh app-owned voting hotkey.
 *
 * Returns `{ hotkey_secret_hex, hotkey_pubkey_hex }` where `hotkey_secret_hex`
 * is the 64-byte stored secret (persist in secure storage) and
 * `hotkey_pubkey_hex` is the 43-byte raw Orchard address that the delegation
 * PCZT targets as the hotkey output (the hotkey's public identity).
 */
export function generate_voting_hotkey(network: string): string;

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
 * Validates one response per plan command (status words stripped), verifies
 * every signature, and returns the signed PCZT bytes.
 */
export function ledger_finalize_pczt_signing(pczt: Uint8Array, responses: Array<any>): Uint8Array;

/**
 * Reassembles and validates the UFVK export. Returns
 * `{ ufvk: string, seedFingerprint: Uint8Array(32), accountIndex: number }`.
 */
export function ledger_parse_ufvk(responses: Array<any>, network: string, account_index: number): any;

/**
 * The full ordered APDU exchange that has the device review the PCZT once
 * and sign every transparent input and real Orchard / Ironwood spend.
 * `memo_hash_supported` comes from the app version (3.9.4+).
 */
export function ledger_pczt_signing_plan(pczt: Uint8Array, memo_hash_supported: boolean): any;

/**
 * Stamps the Ledger account's derivations onto a zafu-built PCZT so the
 * signing plan can serialize it. `transparent_paths` is an array of
 * `{ input_index, scope, address_index, pubkey: Uint8Array(33) }`, one per
 * transparent input. Idempotent; refuses to overwrite a different derivation.
 */
export function ledger_stamp_derivations(pczt: Uint8Array, seed_fingerprint: Uint8Array, account_index: number, transparent_paths: any): Uint8Array;

/**
 * APDUs that export the UFVK for `account_index`: `[first, continuation]`.
 * Send `first`, then repeat `continuation` while
 * [`ledger_ufvk_remaining_bytes`] reports bytes still owed.
 */
export function ledger_ufvk_plan(account_index: number): any;

/**
 * UFVK bytes the device still owes after `responses` (status words
 * stripped). `0` means stop sending continuations and call
 * [`ledger_parse_ufvk`].
 */
export function ledger_ufvk_remaining_bytes(responses: Array<any>): number;

/**
 * Throws `unsupported_transaction: ...` when the Ledger Zcash app cannot sign
 * this PCZT (limits: 32 transparent inputs, 10 transparent outputs, 32 actions
 * per shielded pool; legacy Orchard into Ironwood; unsupported shapes).
 */
export function ledger_validate_pczt(pczt: Uint8Array): void;

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
 * Does this PCZT carry ironwood (v6) actions?
 *
 * Completion has to route to `complete_ironwood_pczt` or
 * `complete_orchard_pczt`, and the answer is a property of the artifact, not
 * of the caller. Deriving it here rather than threading a `pool` flag through
 * the relay means a caller that forgets the flag cannot silently apply
 * signatures to the wrong bundle.
 */
export function pczt_has_ironwood_actions(pczt_hex: string): boolean;

/**
 * Fetch circuit-ready IMT non-membership proofs for a set of nullifiers.
 *
 * `nullifiers_json` is a JSON array of 32-byte LE hex strings — the host passes
 * the UNION of the real-note nullifiers and the dummy-note nullifiers reported
 * by `build_delegation_pczt`. Resolves to a JSON `[ImtProofDto]` exactly as
 * `finalize_delegation` consumes it: `[{nullifier_hex, root_hex,
 * nf_bounds_hex[3], leaf_pos, path_hex[29]}]`.
 */
export function pir_fetch_imt_proofs(pir_base_url: string, nullifiers_json: string, js_fetch: Function): Promise<string>;

/**
 * Plan a t->t spend from an address's UTXOs (`[{txid, vout, value, script}]`)
 * without any key: what the review shows. Returns JSON
 * `{inputs, total_in, fee, change, short}`; `short > 0` means the address
 * needs that much more first.
 */
export function plan_transparent_transaction(utxos_json: string, amount: bigint, null_data_hex?: string | null): string;

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
 * function rather than defaulting to orchard: from NU6.3 onwards an orchard output is
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
    readonly __wbg_frostrelaycipher_free: (a: number, b: number) => void;
    readonly __wbg_notetree_free: (a: number, b: number) => void;
    readonly __wbg_spendkeys_free: (a: number, b: number) => void;
    readonly __wbg_walletkeys_free: (a: number, b: number) => void;
    readonly __wbg_watchonlywallet_free: (a: number, b: number) => void;
    readonly address_from_ufvk: (a: number, b: number, c: number) => [number, number, number, number];
    readonly address_from_ufvk_at_index: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly apply_signature_contributions: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly build_delegation_pczt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number) => [number, number, number, number];
    readonly build_ironwood_send_pczt: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number) => [number, number, number];
    readonly build_merkle_paths: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly build_turnstile_migration_pczt: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => [number, number, number];
    readonly build_unsigned_pczt: (a: number, b: number, c: any, d: number, e: number, f: bigint, g: bigint, h: number, i: number, j: any, k: number, l: number, m: number, n: number, o: number) => [number, number, number];
    readonly build_unsigned_shielding_transaction: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly build_unsigned_shielding_transaction_ironwood: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: bigint, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => [number, number, number, number];
    readonly build_unsigned_transaction: (a: number, b: number, c: any, d: number, e: number, f: bigint, g: bigint, h: number, i: number, j: any, k: number, l: number, m: number, n: number, o: number, p: number) => [number, number, number];
    readonly build_unsigned_transparent_transaction: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly build_vote_commitment_wire: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly build_vote_shares_from_recovery: (a: number, b: number, c: bigint, d: bigint) => [number, number, number, number];
    readonly build_witnesses_and_paths: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly cast_vote_hot_wire: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly complete_ironwood_pczt: (a: number, b: number, c: any, d: any) => [number, number, number, number];
    readonly complete_orchard_pczt: (a: number, b: number, c: any, d: any) => [number, number, number, number];
    readonly complete_shielding_pczt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly complete_shielding_transaction: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly complete_transaction: (a: number, b: number, c: any, d: any) => [number, number, number, number];
    readonly compute_txid: (a: number, b: number) => [number, number, number, number];
    readonly create_sign_request: (a: number, b: number, c: number, d: any, e: number, f: number) => [number, number, number, number];
    readonly describe_pczt_for_ledger: (a: number, b: number, c: number) => [number, number, number, number];
    readonly encode_notes_bundle: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly estimate_compact_savings: (a: number, b: number) => [number, number, number, number];
    readonly extract_signed_tx_from_pczt: (a: number, b: number) => [number, number, number, number];
    readonly finalize_delegation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly frontier_tree_size: (a: number, b: number) => [bigint, number, number];
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
    readonly frost_relay_generate_keypair: () => [number, number, number, number];
    readonly frost_relay_sign_challenge: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly frost_sample_fvk_sk: () => [number, number];
    readonly frost_sign_round1: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly frost_sign_round2: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly frost_spend_aggregate: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly frost_spend_sign_round2: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly frost_spend_sign_round2_signed: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly frostrelaycipher_decrypt: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly frostrelaycipher_encrypt: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly frostrelaycipher_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly generate_seed_phrase: () => [number, number, number, number];
    readonly generate_voting_hotkey: (a: number, b: number) => [number, number, number, number];
    readonly get_commitment_proof_request: (a: number, b: number) => [number, number, number, number];
    readonly ledger_finalize_pczt_signing: (a: number, b: number, c: any) => [number, number, number, number];
    readonly ledger_parse_ufvk: (a: any, b: number, c: number, d: number) => [number, number, number];
    readonly ledger_pczt_signing_plan: (a: number, b: number, c: number) => [number, number, number];
    readonly ledger_stamp_derivations: (a: number, b: number, c: number, d: number, e: number, f: any) => [number, number, number, number];
    readonly ledger_ufvk_plan: (a: number) => [number, number, number];
    readonly ledger_ufvk_remaining_bytes: (a: any) => [number, number, number];
    readonly ledger_validate_pczt: (a: number, b: number) => [number, number];
    readonly notetree_append_blocks: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
    readonly notetree_checkpoint_at_or_below: (a: number, b: number) => number;
    readonly notetree_insert_frontier: (a: number, b: number, c: number, d: number) => [number, number];
    readonly notetree_insert_subtree_roots: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly notetree_insert_witness: (a: number, b: number, c: number, d: number) => [number, number];
    readonly notetree_is_marked: (a: number, b: number) => number;
    readonly notetree_latest_checkpoint: (a: number) => number;
    readonly notetree_load_cap: (a: number, b: number, c: number) => [number, number];
    readonly notetree_load_checkpoints: (a: number, b: number, c: number) => [number, number];
    readonly notetree_load_shard: (a: number, b: number, c: number, d: number) => [number, number];
    readonly notetree_new: (a: number) => number;
    readonly notetree_next_position: (a: number) => [number, number];
    readonly notetree_oldest_checkpoint: (a: number) => number;
    readonly notetree_recover: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly notetree_root_at: (a: number, b: number) => [number, number, number, number];
    readonly notetree_take_changes: (a: number) => [number, number, number];
    readonly notetree_truncate: (a: number, b: number) => [number, number, number];
    readonly notetree_witness: (a: number, b: number, c: number) => [number, number, number, number];
    readonly num_threads: () => number;
    readonly parse_signature_response: (a: number, b: number) => [number, number, number];
    readonly pczt_has_ironwood_actions: (a: number, b: number) => [number, number, number];
    readonly pir_fetch_imt_proofs: (a: number, b: number, c: number, d: number, e: any) => any;
    readonly plan_transparent_transaction: (a: number, b: number, c: bigint, d: number, e: number) => [number, number, number, number];
    readonly redact_pczt_compact: (a: number, b: number) => [number, number, number, number];
    readonly shielding_pool_for_height: (a: number, b: number) => [number, number];
    readonly spendkeys_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly spendkeys_receiving_address: (a: number) => [number, number, number, number];
    readonly spendkeys_sign_pczt: (a: number, b: number, c: number) => [number, number, number, number];
    readonly spendkeys_sign_shielding: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly spendkeys_transparent_pubkey: (a: number, b: number) => [number, number, number, number];
    readonly spendkeys_ufvk: (a: number) => [number, number, number, number];
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
    readonly walletkeys_from_seed_phrase_account: (a: number, b: number, c: number) => [number, number, number];
    readonly walletkeys_get_address: (a: number) => [number, number];
    readonly walletkeys_get_fvk_hex: (a: number) => [number, number];
    readonly walletkeys_get_receiving_address: (a: number, b: number) => [number, number];
    readonly walletkeys_get_receiving_address_at: (a: number, b: number, c: number) => [number, number];
    readonly walletkeys_get_receiving_address_at_index: (a: number, b: number, c: number, d: number) => [number, number, number, number];
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
    readonly watchonlywallet_get_address_at_index: (a: number, b: number, c: number) => [number, number, number, number];
    readonly watchonlywallet_is_mainnet: (a: number) => number;
    readonly watchonlywallet_scan_actions_ironwood_parallel: (a: number, b: number, c: number) => [number, number, number];
    readonly watchonlywallet_scan_actions_parallel: (a: number, b: number, c: number) => [number, number, number];
    readonly witness_extract_path: (a: number, b: number) => [number, number, number];
    readonly witness_sync_update: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly zip317_shielding_fee_zat: (a: number) => bigint;
    readonly zt_encode_frames: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly zt_encode_frames_auto: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly build_merkle_paths_ironwood: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly init: () => void;
    readonly witness_extract_path_ironwood: (a: number, b: number) => [number, number, number];
    readonly frontier_tree_size_ironwood: (a: number, b: number) => [bigint, number, number];
    readonly witness_sync_update_ironwood: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly tree_root_hex_ironwood: (a: number, b: number) => [number, number, number, number];
    readonly rustsecp256k1_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_context_destroy: (a: number) => void;
    readonly rustsecp256k1_v0_10_0_context_create: (a: number) => number;
    readonly wasm_bindgen_aeea2c632802c019___convert__closures_____invoke___wasm_bindgen_aeea2c632802c019___JsValue__core_8266185441cb29e1___result__Result_____wasm_bindgen_aeea2c632802c019___JsError___true_: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen_aeea2c632802c019___convert__closures_____invoke___js_sys_74738dcabc251f8d___Function_fn_wasm_bindgen_aeea2c632802c019___JsValue_____wasm_bindgen_aeea2c632802c019___sys__Undefined___js_sys_74738dcabc251f8d___Function_fn_wasm_bindgen_aeea2c632802c019___JsValue_____wasm_bindgen_aeea2c632802c019___sys__Undefined_______true_: (a: number, b: number, c: any, d: any) => void;
    readonly wasm_bindgen_aeea2c632802c019___convert__closures_____invoke___wasm_bindgen_aeea2c632802c019___JsValue______true_: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen_aeea2c632802c019___convert__closures_____invoke___js_sys_74738dcabc251f8d___futures__task__wait_async_polyfill__MessageEvent______true_: (a: number, b: number, c: any) => void;
    readonly memory: WebAssembly.Memory;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
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

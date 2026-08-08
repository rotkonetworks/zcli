/* @ts-self-types="./zafu_wasm.d.ts" */

/**
 * Wallet keys derived from seed phrase
 */
export class WalletKeys {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WalletKeysFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_walletkeys_free(ptr, 0);
    }
    /**
     * Calculate balance from found notes minus spent nullifiers
     * @param {any} notes_json
     * @param {any} spent_nullifiers_json
     * @returns {bigint}
     */
    calculate_balance(notes_json, spent_nullifiers_json) {
        const ret = wasm.walletkeys_calculate_balance(this.__wbg_ptr, notes_json, spent_nullifiers_json);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BigInt.asUintN(64, ret[0]);
    }
    /**
     * Decrypt full notes with memos from a raw transaction
     *
     * Takes the raw transaction bytes (from zidecar's get_transaction)
     * and returns any notes that belong to this wallet, including memos.
     * @param {Uint8Array} tx_bytes
     * @returns {any}
     */
    decrypt_transaction_memos(tx_bytes) {
        const ptr0 = passArray8ToWasm0(tx_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.walletkeys_decrypt_transaction_memos(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Export Full Viewing Key as hex-encoded QR data
     * This is used to create a watch-only wallet on an online device
     * @param {number} account_index
     * @param {string | null | undefined} label
     * @param {boolean} mainnet
     * @returns {string}
     */
    export_fvk_qr_hex(account_index, label, mainnet) {
        let deferred2_0;
        let deferred2_1;
        try {
            var ptr0 = isLikeNone(label) ? 0 : passStringToWasm0(label, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            const ret = wasm.walletkeys_export_fvk_qr_hex(this.__wbg_ptr, account_index, ptr0, len0, mainnet);
            deferred2_0 = ret[0];
            deferred2_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Derive wallet keys from a 24-word BIP39 seed phrase
     * @param {string} seed_phrase
     */
    constructor(seed_phrase) {
        const ptr0 = passStringToWasm0(seed_phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.walletkeys_from_seed_phrase(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        WalletKeysFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Get the wallet's receiving address (identifier)
     * @returns {string}
     */
    get_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.walletkeys_get_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get the Orchard FVK bytes (96 bytes) as hex
     * @returns {string}
     */
    get_fvk_hex() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.walletkeys_get_fvk_hex(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get the default receiving address as a Zcash unified address string
     * @param {boolean} mainnet
     * @returns {string}
     */
    get_receiving_address(mainnet) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.walletkeys_get_receiving_address(this.__wbg_ptr, mainnet);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get receiving address at specific diversifier index
     * @param {number} diversifier_index
     * @param {boolean} mainnet
     * @returns {string}
     */
    get_receiving_address_at(diversifier_index, mainnet) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.walletkeys_get_receiving_address_at(this.__wbg_ptr, diversifier_index, mainnet);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Scan actions from JSON (legacy compatibility, slower)
     * @param {any} actions_json
     * @returns {any}
     */
    scan_actions(actions_json) {
        const ret = wasm.walletkeys_scan_actions(this.__wbg_ptr, actions_json);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Scan a batch of IRONWOOD compact actions in PARALLEL (NU6.3+ pool).
     *
     * Same binary format and key material as `scan_actions_parallel` — the
     * ironwood pool shares orchard's key tree and note encryption; only the
     * bundle (and note plaintext version, V3) differ. The caller feeds the
     * actions from the tx's ironwood bundle here so returned notes carry
     * `pool: "ironwood"`.
     * @param {Uint8Array} actions_bytes
     * @returns {any}
     */
    scan_actions_ironwood_parallel(actions_bytes) {
        const ptr0 = passArray8ToWasm0(actions_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.walletkeys_scan_actions_ironwood_parallel(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Scan a batch of compact actions in PARALLEL and return found notes
     * This is the main entry point for high-performance scanning
     *
     * Binary format: [count: u32][action1][action2]...
     * Each action: [nullifier: 32][cmx: 32][epk: 32][ciphertext: 52] = 148 bytes
     * @param {Uint8Array} actions_bytes
     * @returns {any}
     */
    scan_actions_parallel(actions_bytes) {
        const ptr0 = passArray8ToWasm0(actions_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.walletkeys_scan_actions_parallel(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
}
if (Symbol.dispose) WalletKeys.prototype[Symbol.dispose] = WalletKeys.prototype.free;

/**
 * Watch-only wallet - holds only viewing keys, no spending capability
 * This is used by online wallets (Prax/Zafu) to track balances
 * and build unsigned transactions for cold signing.
 */
export class WatchOnlyWallet {
    static __wrap(ptr) {
        const obj = Object.create(WatchOnlyWallet.prototype);
        obj.__wbg_ptr = ptr;
        WatchOnlyWalletFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WatchOnlyWalletFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_watchonlywallet_free(ptr, 0);
    }
    /**
     * Decrypt full notes with memos from a raw transaction (watch-only version)
     * @param {Uint8Array} tx_bytes
     * @returns {any}
     */
    decrypt_transaction_memos(tx_bytes) {
        const ptr0 = passArray8ToWasm0(tx_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.watchonlywallet_decrypt_transaction_memos(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Export FVK as hex bytes (for backup)
     * @returns {string}
     */
    export_fvk_hex() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.watchonlywallet_export_fvk_hex(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Import a watch-only wallet from FVK bytes (96 bytes)
     * @param {Uint8Array} fvk_bytes
     * @param {number} account_index
     * @param {boolean} mainnet
     */
    constructor(fvk_bytes, account_index, mainnet) {
        const ptr0 = passArray8ToWasm0(fvk_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.watchonlywallet_from_fvk_bytes(ptr0, len0, account_index, mainnet);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        WatchOnlyWalletFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Import from hex-encoded QR data
     * @param {string} qr_hex
     * @returns {WatchOnlyWallet}
     */
    static from_qr_hex(qr_hex) {
        const ptr0 = passStringToWasm0(qr_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.watchonlywallet_from_qr_hex(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WatchOnlyWallet.__wrap(ret[0]);
    }
    /**
     * Import from a UFVK string (uview1.../uviewtest1...)
     * @param {string} ufvk_str
     * @returns {WatchOnlyWallet}
     */
    static from_ufvk(ufvk_str) {
        const ptr0 = passStringToWasm0(ufvk_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.watchonlywallet_from_ufvk(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WatchOnlyWallet.__wrap(ret[0]);
    }
    /**
     * Get account index
     * @returns {number}
     */
    get_account_index() {
        const ret = wasm.watchonlywallet_get_account_index(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Get default receiving address (diversifier index 0)
     * @returns {string}
     */
    get_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.watchonlywallet_get_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get address at specific diversifier index
     * @param {number} diversifier_index
     * @returns {string}
     */
    get_address_at(diversifier_index) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.watchonlywallet_get_address_at(this.__wbg_ptr, diversifier_index);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Is mainnet
     * @returns {boolean}
     */
    is_mainnet() {
        const ret = wasm.watchonlywallet_is_mainnet(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Scan a batch of IRONWOOD compact actions (NU6.3+ pool).
     *
     * Same binary format and key material as `scan_actions_parallel` — the
     * ironwood pool shares orchard's key tree and note encryption. Feed the
     * actions from a tx's ironwood bundle here so returned notes carry
     * `pool: "ironwood"`.
     * @param {Uint8Array} actions_bytes
     * @returns {any}
     */
    scan_actions_ironwood_parallel(actions_bytes) {
        const ptr0 = passArray8ToWasm0(actions_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.watchonlywallet_scan_actions_ironwood_parallel(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Scan compact actions (same interface as WalletKeys)
     * @param {Uint8Array} actions_bytes
     * @returns {any}
     */
    scan_actions_parallel(actions_bytes) {
        const ptr0 = passArray8ToWasm0(actions_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.watchonlywallet_scan_actions_parallel(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
}
if (Symbol.dispose) WatchOnlyWallet.prototype[Symbol.dispose] = WatchOnlyWallet.prototype.free;

/**
 * Derive an Orchard receiving address from a UFVK string (uview1.../uviewtest1...)
 * @param {string} ufvk_str
 * @param {number} diversifier_index
 * @returns {string}
 */
export function address_from_ufvk(ufvk_str, diversifier_index) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(ufvk_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.address_from_ufvk(ptr0, len0, diversifier_index);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

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
 * @param {string} pczt_hex
 * @param {string} contributions_json
 * @returns {string}
 */
export function apply_signature_contributions(pczt_hex, contributions_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(pczt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(contributions_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.apply_signature_contributions(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

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
 * @param {string} ufvk_str
 * @param {string} ironwood_notes_json
 * @param {string} recipient
 * @param {bigint} amount
 * @param {bigint} fee
 * @param {string} ironwood_anchor_hex
 * @param {string} ironwood_merkle_paths_json
 * @param {number} account_index
 * @param {number} target_height
 * @param {number} expected_branch_id
 * @param {boolean} mainnet
 * @param {string | null} [memo_hex]
 * @returns {any}
 */
export function build_ironwood_send_pczt(ufvk_str, ironwood_notes_json, recipient, amount, fee, ironwood_anchor_hex, ironwood_merkle_paths_json, account_index, target_height, expected_branch_id, mainnet, memo_hex) {
    const ptr0 = passStringToWasm0(ufvk_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(ironwood_notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(recipient, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(ironwood_anchor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(ironwood_merkle_paths_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    var ptr5 = isLikeNone(memo_hex) ? 0 : passStringToWasm0(memo_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len5 = WASM_VECTOR_LEN;
    const ret = wasm.build_ironwood_send_pczt(ptr0, len0, ptr1, len1, ptr2, len2, amount, fee, ptr3, len3, ptr4, len4, account_index, target_height, expected_branch_id, mainnet, ptr5, len5);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

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
 * @param {string} tree_state_hex
 * @param {string} compact_blocks_json
 * @param {string} note_positions_json
 * @param {number} anchor_height
 * @returns {any}
 */
export function build_merkle_paths(tree_state_hex, compact_blocks_json, note_positions_json, anchor_height) {
    const ptr0 = passStringToWasm0(tree_state_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(compact_blocks_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(note_positions_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.build_merkle_paths(ptr0, len0, ptr1, len1, ptr2, len2, anchor_height);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Ironwood-tree variant of `build_merkle_paths`. Same JSON contract; feed
 * the ironwood frontier from GetTreeState and cmxs from ironwood bundles.
 * @param {string} tree_state_hex
 * @param {string} compact_blocks_json
 * @param {string} note_positions_json
 * @param {number} anchor_height
 * @returns {any}
 */
export function build_merkle_paths_ironwood(tree_state_hex, compact_blocks_json, note_positions_json, anchor_height) {
    const ptr0 = passStringToWasm0(tree_state_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(compact_blocks_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(note_positions_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.build_merkle_paths_ironwood(ptr0, len0, ptr1, len1, ptr2, len2, anchor_height);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

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
 * @param {string} utxos_json
 * @param {string} privkey_hex
 * @param {string} recipient
 * @param {bigint} amount
 * @param {bigint} fee
 * @param {number} anchor_height
 * @param {boolean} mainnet
 * @param {string | null} [branch_id_hex]
 * @returns {string}
 */
export function build_shielding_transaction(utxos_json, privkey_hex, recipient, amount, fee, anchor_height, mainnet, branch_id_hex) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(utxos_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(privkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(recipient, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(branch_id_hex) ? 0 : passStringToWasm0(branch_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len3 = WASM_VECTOR_LEN;
        const ret = wasm.build_shielding_transaction(ptr0, len0, ptr1, len1, ptr2, len2, amount, fee, anchor_height, mainnet, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * Build a shielding transaction into whichever pool is CORRECT at
 * `target_height`, so a caller never has to (and never can) pick the stranded
 * one by omission.
 *
 * At/after NU6.3 activation this is [`build_shielding_transaction_ironwood`]
 * (and `branch_id_hex` must be the live NU6.3 branch id - there is no
 * fallback); before it, the legacy orchard builder. Returns hex-encoded raw
 * transaction bytes either way.
 * @param {string} utxos_json
 * @param {string} privkey_hex
 * @param {string} recipient
 * @param {bigint} amount
 * @param {bigint} fee
 * @param {number} target_height
 * @param {boolean} mainnet
 * @param {string | null} [branch_id_hex]
 * @param {string | null} [memo_hex]
 * @returns {string}
 */
export function build_shielding_transaction_auto(utxos_json, privkey_hex, recipient, amount, fee, target_height, mainnet, branch_id_hex, memo_hex) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(utxos_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(privkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(recipient, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(branch_id_hex) ? 0 : passStringToWasm0(branch_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len3 = WASM_VECTOR_LEN;
        var ptr4 = isLikeNone(memo_hex) ? 0 : passStringToWasm0(memo_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len4 = WASM_VECTOR_LEN;
        const ret = wasm.build_shielding_transaction_auto(ptr0, len0, ptr1, len1, ptr2, len2, amount, fee, target_height, mainnet, ptr3, len3, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

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
 * @param {string} utxos_json
 * @param {string} privkey_hex
 * @param {string} recipient
 * @param {bigint} amount
 * @param {bigint} fee
 * @param {number} target_height
 * @param {number} expected_branch_id
 * @param {boolean} mainnet
 * @param {string | null} [memo_hex]
 * @returns {string}
 */
export function build_shielding_transaction_ironwood(utxos_json, privkey_hex, recipient, amount, fee, target_height, expected_branch_id, mainnet, memo_hex) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(utxos_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(privkey_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(recipient, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(memo_hex) ? 0 : passStringToWasm0(memo_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len3 = WASM_VECTOR_LEN;
        const ret = wasm.build_shielding_transaction_ironwood(ptr0, len0, ptr1, len1, ptr2, len2, amount, fee, target_height, expected_branch_id, mainnet, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

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
 * @param {string} seed_phrase
 * @param {string} ironwood_notes_json
 * @param {string} recipient
 * @param {bigint} amount
 * @param {bigint} fee
 * @param {string} ironwood_anchor_hex
 * @param {string} ironwood_merkle_paths_json
 * @param {number} account_index
 * @param {number} target_height
 * @param {number} expected_branch_id
 * @param {boolean} mainnet
 * @param {string | null} [memo_hex]
 * @returns {string}
 */
export function build_signed_ironwood_send(seed_phrase, ironwood_notes_json, recipient, amount, fee, ironwood_anchor_hex, ironwood_merkle_paths_json, account_index, target_height, expected_branch_id, mainnet, memo_hex) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passStringToWasm0(seed_phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(ironwood_notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(recipient, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(ironwood_anchor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(ironwood_merkle_paths_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        var ptr5 = isLikeNone(memo_hex) ? 0 : passStringToWasm0(memo_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len5 = WASM_VECTOR_LEN;
        const ret = wasm.build_signed_ironwood_send(ptr0, len0, ptr1, len1, ptr2, len2, amount, fee, ptr3, len3, ptr4, len4, account_index, target_height, expected_branch_id, mainnet, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}

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
 * @param {string} seed_phrase
 * @param {any} notes_json
 * @param {string} recipient
 * @param {bigint} amount
 * @param {bigint} fee
 * @param {string} anchor_hex
 * @param {any} merkle_paths_json
 * @param {number} account_index
 * @param {boolean} mainnet
 * @param {string | null} [memo_hex]
 * @param {string | null} [branch_id_hex]
 * @returns {string}
 */
export function build_signed_spend_transaction(seed_phrase, notes_json, recipient, amount, fee, anchor_hex, merkle_paths_json, account_index, mainnet, memo_hex, branch_id_hex) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(seed_phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(recipient, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(anchor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(memo_hex) ? 0 : passStringToWasm0(memo_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len3 = WASM_VECTOR_LEN;
        var ptr4 = isLikeNone(branch_id_hex) ? 0 : passStringToWasm0(branch_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len4 = WASM_VECTOR_LEN;
        const ret = wasm.build_signed_spend_transaction(ptr0, len0, notes_json, ptr1, len1, amount, fee, ptr2, len2, merkle_paths_json, account_index, mainnet, ptr3, len3, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

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
 * @param {string} seed_phrase
 * @param {string} orchard_notes_json
 * @param {bigint} fee
 * @param {string} orchard_anchor_hex
 * @param {string} orchard_merkle_paths_json
 * @param {number} account_index
 * @param {number} target_height
 * @param {number} expected_branch_id
 * @param {boolean} mainnet
 * @param {string | null} [memo_hex]
 * @returns {string}
 */
export function build_signed_turnstile_migration(seed_phrase, orchard_notes_json, fee, orchard_anchor_hex, orchard_merkle_paths_json, account_index, target_height, expected_branch_id, mainnet, memo_hex) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(seed_phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(orchard_notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(orchard_anchor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(orchard_merkle_paths_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        var ptr4 = isLikeNone(memo_hex) ? 0 : passStringToWasm0(memo_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len4 = WASM_VECTOR_LEN;
        const ret = wasm.build_signed_turnstile_migration(ptr0, len0, ptr1, len1, fee, ptr2, len2, ptr3, len3, account_index, target_height, expected_branch_id, mainnet, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

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
 * @param {string} ufvk_str
 * @param {string} orchard_notes_json
 * @param {bigint} fee
 * @param {string} orchard_anchor_hex
 * @param {string} orchard_merkle_paths_json
 * @param {number} account_index
 * @param {number} target_height
 * @param {number} expected_branch_id
 * @param {boolean} mainnet
 * @param {string | null} [memo_hex]
 * @returns {any}
 */
export function build_turnstile_migration_pczt(ufvk_str, orchard_notes_json, fee, orchard_anchor_hex, orchard_merkle_paths_json, account_index, target_height, expected_branch_id, mainnet, memo_hex) {
    const ptr0 = passStringToWasm0(ufvk_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(orchard_notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(orchard_anchor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(orchard_merkle_paths_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    var ptr4 = isLikeNone(memo_hex) ? 0 : passStringToWasm0(memo_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len4 = WASM_VECTOR_LEN;
    const ret = wasm.build_turnstile_migration_pczt(ptr0, len0, ptr1, len1, fee, ptr2, len2, ptr3, len3, account_index, target_height, expected_branch_id, mainnet, ptr4, len4);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

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
 * @param {string} ufvk_str
 * @param {any} notes_json
 * @param {string} recipient
 * @param {bigint} amount
 * @param {bigint} fee
 * @param {string} anchor_hex
 * @param {any} merkle_paths_json
 * @param {number} target_height
 * @param {boolean} mainnet
 * @param {string | null} [memo_hex]
 * @returns {any}
 */
export function build_unsigned_pczt(ufvk_str, notes_json, recipient, amount, fee, anchor_hex, merkle_paths_json, target_height, mainnet, memo_hex) {
    const ptr0 = passStringToWasm0(ufvk_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(recipient, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(anchor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(memo_hex) ? 0 : passStringToWasm0(memo_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.build_unsigned_pczt(ptr0, len0, notes_json, ptr1, len1, amount, fee, ptr2, len2, merkle_paths_json, target_height, mainnet, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Build an unsigned shielding transaction (transparent → orchard) for cold-wallet signing.
 *
 * Same as `build_shielding_transaction` but does NOT sign the transparent inputs.
 * Instead, returns the per-input sighashes so an external signer (e.g. Zigner) can sign them.
 *
 * PRE-NU6.3 ONLY - same fail-closed gate as `build_shielding_transaction`.
 *
 * Returns JSON: `{ sighashes: [hex], unsigned_tx_hex: hex, summary: string }`
 * @param {string} utxos_json
 * @param {string} recipient
 * @param {bigint} amount
 * @param {bigint} fee
 * @param {number} anchor_height
 * @param {boolean} mainnet
 * @param {string | null} [branch_id_hex]
 * @returns {string}
 */
export function build_unsigned_shielding_transaction(utxos_json, recipient, amount, fee, anchor_height, mainnet, branch_id_hex) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(utxos_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(recipient, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(branch_id_hex) ? 0 : passStringToWasm0(branch_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.build_unsigned_shielding_transaction(ptr0, len0, ptr1, len1, amount, fee, anchor_height, mainnet, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

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
 * @param {string} ufvk_str
 * @param {any} notes_json
 * @param {string} recipient
 * @param {bigint} amount
 * @param {bigint} fee
 * @param {string} anchor_hex
 * @param {any} merkle_paths_json
 * @param {number} _account_index
 * @param {boolean} mainnet
 * @param {string | null} [memo_hex]
 * @param {string | null} [branch_id_hex]
 * @returns {any}
 */
export function build_unsigned_transaction(ufvk_str, notes_json, recipient, amount, fee, anchor_hex, merkle_paths_json, _account_index, mainnet, memo_hex, branch_id_hex) {
    const ptr0 = passStringToWasm0(ufvk_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(recipient, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(anchor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(memo_hex) ? 0 : passStringToWasm0(memo_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    var ptr4 = isLikeNone(branch_id_hex) ? 0 : passStringToWasm0(branch_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len4 = WASM_VECTOR_LEN;
    const ret = wasm.build_unsigned_transaction(ptr0, len0, notes_json, ptr1, len1, amount, fee, ptr2, len2, merkle_paths_json, _account_index, mainnet, ptr3, len3, ptr4, len4);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * One-shot witness + path builder used for initial backfill: replays blocks
 * the same way `build_merkle_paths` does but also returns serialized
 * witnesses and the resulting frontier so the caller can cache them.
 *
 * Returns JSON
 * `{anchor_hex, end_frontier_hex, entries: [{position, witness_hex, path: [{hash}]}]}`.
 * @param {string} tree_state_hex
 * @param {string} compact_blocks_json
 * @param {string} note_positions_json
 * @returns {any}
 */
export function build_witnesses_and_paths(tree_state_hex, compact_blocks_json, note_positions_json) {
    const ptr0 = passStringToWasm0(tree_state_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(compact_blocks_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(note_positions_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.build_witnesses_and_paths(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Complete an orchard-only FROST multisig PCZT: inject the externally-aggregated
 * SpendAuth signatures (one per real spend, in `spend_indices` order, matching
 * what `build_unsigned_pczt` returned) into the PCZT, then extract the
 * broadcast-ready v5 tx. The mnemonic/zigner host and the poker escrow all
 * finish a FROST signing round this way (gh #17 PCZT migration).
 * @param {string} pczt_hex
 * @param {any} orchard_sigs_json
 * @param {any} spend_indices_json
 * @returns {string}
 */
export function complete_orchard_pczt(pczt_hex, orchard_sigs_json, spend_indices_json) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(pczt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.complete_orchard_pczt(ptr0, len0, orchard_sigs_json, spend_indices_json);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Complete an unsigned shielding transaction by patching in transparent signatures.
 *
 * Takes the unsigned tx hex (with empty scriptSigs) and an array of `{sig_hex, pubkey_hex}`
 * per transparent input. Constructs the P2PKH scriptSig for each input and returns the
 * final signed transaction hex.
 * @param {string} unsigned_tx_hex
 * @param {string} signatures_json
 * @returns {string}
 */
export function complete_shielding_transaction(unsigned_tx_hex, signatures_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(unsigned_tx_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(signatures_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.complete_shielding_transaction(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

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
 * @param {string} unsigned_tx_hex
 * @param {any} signatures_json
 * @param {any} spend_indices_json
 * @returns {string}
 */
export function complete_transaction(unsigned_tx_hex, signatures_json, spend_indices_json) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(unsigned_tx_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.complete_transaction(ptr0, len0, signatures_json, spend_indices_json);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Canonical ZIP-244 txid for a raw signed v5 transaction.
 *
 * Public lightwalletd's `SendResponse` carries no txid, so the wallet derives
 * it locally instead of trusting the server to echo it. This is the same value
 * zidecar computes server-side and the same bytes that appear as
 * `CompactTx.hash` during sync — returned as lowercase hex in internal/wire
 * byte order so the outgoing record reconciles on the next scan.
 * @param {string} tx_hex
 * @returns {string}
 */
export function compute_txid(tx_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(tx_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.compute_txid(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Create a PCZT sign request from transaction parameters
 * This is called by the online wallet to create the data that will be
 * transferred to the cold wallet via QR code.
 * @param {number} account_index
 * @param {string} sighash_hex
 * @param {any} alphas_json
 * @param {string} summary
 * @returns {string}
 */
export function create_sign_request(account_index, sighash_hex, alphas_json, summary) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(sighash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(summary, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.create_sign_request(account_index, ptr0, len0, alphas_json, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Derive transparent private key from mnemonic using BIP44 path m/44'/133'/account'/0/index
 *
 * Returns hex-encoded 32-byte secp256k1 private key for signing transparent inputs.
 * Path components: purpose=44' (BIP44), coin_type=133' (ZEC), account', change=0, index
 * @param {string} seed_phrase
 * @param {number} account
 * @param {number} index
 * @returns {string}
 */
export function derive_transparent_privkey(seed_phrase, account, index) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(seed_phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.derive_transparent_privkey(ptr0, len0, account, index);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

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
 * @param {string} notes_json
 * @param {string} merkle_result_json
 * @param {number} anchor_height
 * @param {boolean} mainnet
 * @param {string | null} [attestation_hex]
 * @returns {Uint8Array}
 */
export function encode_notes_bundle(notes_json, merkle_result_json, anchor_height, mainnet, attestation_hex) {
    const ptr0 = passStringToWasm0(notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(merkle_result_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    var ptr2 = isLikeNone(attestation_hex) ? 0 : passStringToWasm0(attestation_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len2 = WASM_VECTOR_LEN;
    const ret = wasm.encode_notes_bundle(ptr0, len0, ptr1, len1, anchor_height, mainnet, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

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
 * @param {string} pczt_hex
 * @returns {string}
 */
export function estimate_compact_savings(pczt_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(pczt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.estimate_compact_savings(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Extract a broadcast-ready v5 transaction from a signed PCZT returned by zigner.
 *
 * Replaces the legacy `parse_signature_response` + `complete_transaction` pair.
 * Instead of patching raw signature bytes into a hand-serialized tx, we let the
 * pczt crate's `TransactionExtractor` reassemble the canonical v5 transaction
 * from the signed PCZT (collecting all auth sigs and validating the proof).
 *
 * Returns hex-encoded transaction bytes ready for broadcast.
 * @param {string} pczt_hex
 * @returns {string}
 */
export function extract_signed_tx_from_pczt(pczt_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(pczt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.extract_signed_tx_from_pczt(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Compute the tree size from a hex-encoded frontier.
 * @param {string} tree_state_hex
 * @returns {bigint}
 */
export function frontier_tree_size(tree_state_hex) {
    const ptr0 = passStringToWasm0(tree_state_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.frontier_tree_size(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return BigInt.asUintN(64, ret[0]);
}

/**
 * Ironwood-tree variant of `frontier_tree_size`.
 * @param {string} tree_state_hex
 * @returns {bigint}
 */
export function frontier_tree_size_ironwood(tree_state_hex) {
    const ptr0 = passStringToWasm0(tree_state_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.frontier_tree_size_ironwood(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return BigInt.asUintN(64, ret[0]);
}

/**
 * coordinator: aggregate signed shares into final signature
 * @param {string} public_key_package_hex
 * @param {string} message_hex
 * @param {string} commitments_json
 * @param {string} shares_json
 * @param {string} randomizer_hex
 * @returns {string}
 */
export function frost_aggregate_shares(public_key_package_hex, message_hex, commitments_json, shares_json, randomizer_hex) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(public_key_package_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(message_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(commitments_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(shares_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(randomizer_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.frost_aggregate_shares(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * Compute the attestation digest for an anchor.
 * Returns hex-encoded 32-byte SHA-256 digest.
 * @param {string} public_key_package_hex
 * @param {string} anchor_hex
 * @param {number} anchor_height
 * @param {boolean} mainnet
 * @returns {string}
 */
export function frost_attestation_digest(public_key_package_hex, anchor_hex, anchor_height, mainnet) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(public_key_package_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(anchor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.frost_attestation_digest(ptr0, len0, ptr1, len1, anchor_height, mainnet);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Verify an attestation (96 bytes: sig || randomizer).
 * @param {string} attestation_hex
 * @param {string} public_key_package_hex
 * @param {string} anchor_hex
 * @param {number} anchor_height
 * @param {boolean} mainnet
 * @returns {boolean}
 */
export function frost_attestation_verify(attestation_hex, public_key_package_hex, anchor_hex, anchor_height, mainnet) {
    const ptr0 = passStringToWasm0(attestation_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(public_key_package_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(anchor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.frost_attestation_verify(ptr0, len0, ptr1, len1, ptr2, len2, anchor_height, mainnet);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

/**
 * trusted dealer: generate key packages for all participants
 * @param {number} min_signers
 * @param {number} max_signers
 * @returns {string}
 */
export function frost_dealer_keygen(min_signers, max_signers) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.frost_dealer_keygen(min_signers, max_signers);
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * derive the multisig wallet's Orchard address (raw 43-byte address, hex-encoded)
 * from the group public key package and a caller-supplied `sk`. deterministic —
 * every participant computing this with the same inputs lands on byte-identical
 * output. pair with `frost_derive_ufvk(pkg, sk, mainnet)` so the stored address
 * and stored UFVK share a single source of truth for nk/rivk.
 * @param {string} public_key_package_hex
 * @param {string} sk_hex
 * @param {number} diversifier_index
 * @returns {string}
 */
export function frost_derive_address_from_sk(public_key_package_hex, sk_hex, diversifier_index) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(public_key_package_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(sk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.frost_derive_address_from_sk(ptr0, len0, ptr1, len1, diversifier_index);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * derive the multisig wallet's Orchard address (raw 43-byte address, hex-encoded).
 * non-deterministic — internally generates a random nk/rivk. only safe when a
 * single party derives-and-broadcasts. interactive DKG should use
 * `frost_derive_address_from_sk` instead.
 * @param {string} public_key_package_hex
 * @param {number} diversifier_index
 * @returns {string}
 */
export function frost_derive_address_raw(public_key_package_hex, diversifier_index) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(public_key_package_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.frost_derive_address_raw(ptr0, len0, diversifier_index);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * derive the Orchard-only UFVK string (`uview1…` / `uviewtest1…`) from a
 * caller-supplied 32-byte SpendingKey and a FROST public key package.
 * every participant, given the same `sk_hex` + `public_key_package_hex`,
 * lands on byte-identical output.
 * @param {string} public_key_package_hex
 * @param {string} sk_hex
 * @param {boolean} mainnet
 * @returns {string}
 */
export function frost_derive_ufvk(public_key_package_hex, sk_hex, mainnet) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(public_key_package_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(sk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.frost_derive_ufvk(ptr0, len0, ptr1, len1, mainnet);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * DKG round 1: generate ephemeral identity + signed commitment
 * @param {number} max_signers
 * @param {number} min_signers
 * @returns {string}
 */
export function frost_dkg_part1(max_signers, min_signers) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.frost_dkg_part1(max_signers, min_signers);
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * DKG round 2: process signed round1 broadcasts, produce per-peer packages
 * @param {string} secret_hex
 * @param {string} peer_broadcasts_json
 * @returns {string}
 */
export function frost_dkg_part2(secret_hex, peer_broadcasts_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(peer_broadcasts_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.frost_dkg_part2(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * DKG round 3: finalize — returns key package + public key package
 * @param {string} secret_hex
 * @param {string} round1_broadcasts_json
 * @param {string} round2_packages_json
 * @returns {string}
 */
export function frost_dkg_part3(secret_hex, round1_broadcasts_json, round2_packages_json) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(secret_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(round1_broadcasts_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(round2_packages_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.frost_dkg_part3(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * coordinator: generate signed randomizer
 * @param {string} ephemeral_seed_hex
 * @param {string} message_hex
 * @param {string} commitments_json
 * @returns {string}
 */
export function frost_generate_randomizer(ephemeral_seed_hex, message_hex, commitments_json) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(ephemeral_seed_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(message_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(commitments_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.frost_generate_randomizer(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Inspect a PCZT's orchard outputs + recompute its canonical ZIP-244 sighash,
 * for the FROST joiner's display↔sighash binding (gh #17). Returns the same
 * JSON shape as `frost_parse_tx_outputs`, but sources both the bundle and the
 * sighash from the PCZT itself via `Pczt::into_effects()` → `v5_signature_hash`.
 * So the value the joiner checks is the canonical message its signature will
 * commit to — never a host-supplied claim. The host publishes the (proven,
 * io-finalized, redacted) PCZT; `into_effects` needs neither proof nor sigs.
 * @param {string} pczt_hex
 * @param {string} orchard_fvk_uview
 * @returns {string}
 */
export function frost_inspect_pczt_outputs(pczt_hex, orchard_fvk_uview) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(pczt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(orchard_fvk_uview, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.frost_inspect_pczt_outputs(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

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
 * @param {string} unsigned_tx_hex
 * @param {string} orchard_fvk_uview
 * @returns {string}
 */
export function frost_parse_tx_outputs(unsigned_tx_hex, orchard_fvk_uview) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(unsigned_tx_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(orchard_fvk_uview, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.frost_parse_tx_outputs(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * host-only: sample a random 32-byte SpendingKey for nk/rivk derivation.
 * retries until the sampled bytes land in the Pallas scalar range.
 * returns hex-encoded 32-byte `sk` that the host broadcasts to peers in R1.
 * @returns {string}
 */
export function frost_sample_fvk_sk() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.frost_sample_fvk_sk();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * signing round 1: generate nonces + signed commitments
 * @param {string} ephemeral_seed_hex
 * @param {string} key_package_hex
 * @returns {string}
 */
export function frost_sign_round1(ephemeral_seed_hex, key_package_hex) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(ephemeral_seed_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(key_package_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.frost_sign_round1(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * signing round 2: produce signed signature share
 * @param {string} ephemeral_seed_hex
 * @param {string} key_package_hex
 * @param {string} nonces_hex
 * @param {string} message_hex
 * @param {string} commitments_json
 * @param {string} randomizer_hex
 * @returns {string}
 */
export function frost_sign_round2(ephemeral_seed_hex, key_package_hex, nonces_hex, message_hex, commitments_json, randomizer_hex) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passStringToWasm0(ephemeral_seed_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(key_package_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(nonces_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(message_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(commitments_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(randomizer_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.frost_sign_round2(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}

/**
 * coordinator: aggregate shares into Orchard SpendAuth signature (64 bytes hex)
 * @param {string} public_key_package_hex
 * @param {string} sighash_hex
 * @param {string} alpha_hex
 * @param {string} commitments_json
 * @param {string} shares_json
 * @returns {string}
 */
export function frost_spend_aggregate(public_key_package_hex, sighash_hex, alpha_hex, commitments_json, shares_json) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(public_key_package_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(sighash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(alpha_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(commitments_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(shares_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.frost_spend_aggregate(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * sighash-bound round 2: produce FROST share for one Orchard action
 * @param {string} key_package_hex
 * @param {string} nonces_hex
 * @param {string} sighash_hex
 * @param {string} alpha_hex
 * @param {string} commitments_json
 * @returns {string}
 */
export function frost_spend_sign_round2(key_package_hex, nonces_hex, sighash_hex, alpha_hex, commitments_json) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(key_package_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(nonces_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(sighash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(alpha_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(commitments_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.frost_spend_sign_round2(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * authenticated variant: wraps share in SignedMessage for relay transport
 * @param {string} ephemeral_seed_hex
 * @param {string} key_package_hex
 * @param {string} nonces_hex
 * @param {string} sighash_hex
 * @param {string} alpha_hex
 * @param {string} commitments_json
 * @returns {string}
 */
export function frost_spend_sign_round2_signed(ephemeral_seed_hex, key_package_hex, nonces_hex, sighash_hex, alpha_hex, commitments_json) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passStringToWasm0(ephemeral_seed_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(key_package_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(nonces_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(sighash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(alpha_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(commitments_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.frost_spend_sign_round2_signed(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}

/**
 * Generate a new 24-word seed phrase
 * @returns {string}
 */
export function generate_seed_phrase() {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.generate_seed_phrase();
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Get the commitment proof request data for a note
 * Returns the cmx that should be sent to zidecar's GetCommitmentProof
 * @param {string} note_cmx_hex
 * @returns {string}
 */
export function get_commitment_proof_request(note_cmx_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(note_cmx_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.get_commitment_proof_request(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Initialize panic hook for better error messages
 */
export function init() {
    wasm.init();
}

/**
 * Get number of threads available (0 if single-threaded)
 * @returns {number}
 */
export function num_threads() {
    const ret = wasm.num_threads();
    return ret >>> 0;
}

/**
 * Parse signatures from cold wallet QR response
 * Returns JSON with sighash and orchard_sigs array
 * @param {string} qr_hex
 * @returns {any}
 */
export function parse_signature_response(qr_hex) {
    const ptr0 = passStringToWasm0(qr_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parse_signature_response(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

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
 * @param {string} pczt_hex
 * @returns {string}
 */
export function redact_pczt_compact(pczt_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(pczt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.redact_pczt_compact(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Which shielded pool a transparent→shielded transaction must target at
 * `target_height`: `"ironwood"` at/after NU6.3 activation, `"orchard"` before.
 *
 * Callers that do not pick a pool explicitly MUST resolve it through this
 * function (or through [`build_shielding_transaction_auto`], which calls it)
 * rather than defaulting to orchard: from NU6.3 onwards an orchard output is
 * a stranded note (orchard sends are consensus-disabled, so the funds can only
 * be moved again by a turnstile migration that costs a second fee).
 * @param {number} target_height
 * @param {boolean} mainnet
 * @returns {string}
 */
export function shielding_pool_for_height(target_height, mainnet) {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.shielding_pool_for_height(target_height, mainnet);
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Derive a transparent (t1.../tm...) address from a UFVK string at a given address index.
 * Returns the base58check-encoded P2PKH address.
 * @param {string} ufvk_str
 * @param {number} address_index
 * @returns {string}
 */
export function transparent_address_from_ufvk(ufvk_str, address_index) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(ufvk_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.transparent_address_from_ufvk(ptr0, len0, address_index);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Derive compressed public key from UFVK transparent component for a given address index.
 *
 * Uses BIP44 external path: `m/44'/133'/account'/0/<address_index>`
 * Returns hex-encoded 33-byte compressed secp256k1 public key.
 * @param {string} ufvk_str
 * @param {number} address_index
 * @returns {string}
 */
export function transparent_pubkey_from_ufvk(ufvk_str, address_index) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(ufvk_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.transparent_pubkey_from_ufvk(ptr0, len0, address_index);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Compute the tree root from a hex-encoded frontier.
 * @param {string} tree_state_hex
 * @returns {string}
 */
export function tree_root_hex(tree_state_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(tree_state_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.tree_root_hex(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Ironwood-tree variant of `tree_root_hex`.
 * @param {string} tree_state_hex
 * @returns {string}
 */
export function tree_root_hex_ironwood(tree_state_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(tree_state_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.tree_root_hex_ironwood(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * @param {string} parts_json
 * @param {string} expected_type
 * @returns {string}
 */
export function ur_decode_frames(parts_json, expected_type) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(parts_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(expected_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.ur_decode_frames(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Encode CBOR bytes as UR-encoded animated QR string frames.
 * Returns JSON array of UR strings suitable for QR display.
 * ur_type: e.g. "zcash-notes", "zigner-contacts", "zigner-backup"
 * fragment_size: max bytes per QR frame (200-500 typical, 0 = single QR)
 * @param {Uint8Array} cbor_data
 * @param {string} ur_type
 * @param {number} fragment_size
 * @returns {string}
 */
export function ur_encode_frames(cbor_data, ur_type, fragment_size) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passArray8ToWasm0(cbor_data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(ur_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.ur_encode_frames(ptr0, len0, ptr1, len1, fragment_size);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Validate a seed phrase
 * @param {string} seed_phrase
 * @returns {boolean}
 */
export function validate_seed_phrase(seed_phrase) {
    const ptr0 = passStringToWasm0(seed_phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.validate_seed_phrase(ptr0, len0);
    return ret !== 0;
}

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
 * @param {string} ufvk_str
 * @returns {boolean}
 */
export function validate_ufvk(ufvk_str) {
    const ptr0 = passStringToWasm0(ufvk_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.validate_ufvk(ptr0, len0);
    return ret !== 0;
}

/**
 * Get library version
 * @returns {string}
 */
export function version() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.version();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Extract a merkle path from a stored per-note witness. Returns JSON
 * `{position, root_hex, path: [{hash}]}`. The caller must cross-check
 * `root_hex` against the anchor they intend to sign over.
 * @param {string} witness_hex
 * @returns {any}
 */
export function witness_extract_path(witness_hex) {
    const ptr0 = passStringToWasm0(witness_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.witness_extract_path(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Ironwood-tree variant of `witness_extract_path`. Same JSON contract.
 * @param {string} witness_hex
 * @returns {any}
 */
export function witness_extract_path_ironwood(witness_hex) {
    const ptr0 = passStringToWasm0(witness_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.witness_extract_path_ironwood(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

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
 * @param {string} start_frontier_hex
 * @param {string} compact_blocks_json
 * @param {string} existing_witnesses_json
 * @param {string} new_notes_json
 * @returns {any}
 */
export function witness_sync_update(start_frontier_hex, compact_blocks_json, existing_witnesses_json, new_notes_json) {
    const ptr0 = passStringToWasm0(start_frontier_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(compact_blocks_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(existing_witnesses_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(new_notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.witness_sync_update(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Ironwood-tree variant of `witness_sync_update`. Same JSON contract.
 * @param {string} start_frontier_hex
 * @param {string} compact_blocks_json
 * @param {string} existing_witnesses_json
 * @param {string} new_notes_json
 * @returns {any}
 */
export function witness_sync_update_ironwood(start_frontier_hex, compact_blocks_json, existing_witnesses_json, new_notes_json) {
    const ptr0 = passStringToWasm0(start_frontier_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(compact_blocks_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(existing_witnesses_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(new_notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.witness_sync_update_ironwood(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * ZIP-317 conventional fee for an ironwood shielding transaction with `n`
 * transparent P2PKH inputs (JS-visible; see [`zip317_shielding_fee`]).
 * @param {number} n_transparent_inputs
 * @returns {bigint}
 */
export function zip317_shielding_fee_zat(n_transparent_inputs) {
    const ret = wasm.zip317_shielding_fee_zat(n_transparent_inputs);
    return BigInt.asUintN(64, ret);
}

/**
 * Encode CBOR bytes as zoda transport QR frames (verified erasure coding).
 * Returns JSON array of `zt:type/hex` strings.
 * k = minimum frames to reconstruct, n = total frames.
 * @param {Uint8Array} cbor_data
 * @param {string} zt_type
 * @param {number} k
 * @param {number} n
 * @returns {string}
 */
export function zt_encode_frames(cbor_data, zt_type, k, n) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passArray8ToWasm0(cbor_data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(zt_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.zt_encode_frames(ptr0, len0, ptr1, len1, k, n);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

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
 * @param {Uint8Array} cbor_data
 * @param {string} zt_type
 * @param {number} max_qr_bytes
 * @param {number} redundancy_pct
 * @returns {string}
 */
export function zt_encode_frames_auto(cbor_data, zt_type, max_qr_bytes, redundancy_pct) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passArray8ToWasm0(cbor_data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(zt_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.zt_encode_frames_auto(ptr0, len0, ptr1, len1, max_qr_bytes, redundancy_pct);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}
function __wbg_get_imports(memory) {
    const import0 = {
        __proto__: null,
        __wbg_Error_92b29b0548f8b746: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_Number_9a4e0ecb0fa16705: function(arg0) {
            const ret = Number(arg0);
            return ret;
        },
        __wbg_String_8564e559799eccda: function(arg0, arg1) {
            const ret = String(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_bigint_get_as_i64_d968e41184ae354f: function(arg0, arg1) {
            const v = arg1;
            const ret = typeof(v) === 'bigint' ? v : undefined;
            getDataViewMemory0().setBigInt64(arg0 + 8 * 1, isLikeNone(ret) ? BigInt(0) : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_boolean_get_fa956cfa2d1bd751: function(arg0) {
            const v = arg0;
            const ret = typeof(v) === 'boolean' ? v : undefined;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_c25d447a39f5578f: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_in_aca499c5de7ff5e5: function(arg0, arg1) {
            const ret = arg0 in arg1;
            return ret;
        },
        __wbg___wbindgen_is_bigint_2f76dc55065b4273: function(arg0) {
            const ret = typeof(arg0) === 'bigint';
            return ret;
        },
        __wbg___wbindgen_is_function_1ff95bcc5517c252: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_a27215656b807791: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_ea5e6cc2e4141dfe: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_c05833b95a3cf397: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_jsval_eq_e659fcf7b0e32763: function(arg0, arg1) {
            const ret = arg0 === arg1;
            return ret;
        },
        __wbg___wbindgen_jsval_loose_eq_db4c3b15f63fc170: function(arg0, arg1) {
            const ret = arg0 == arg1;
            return ret;
        },
        __wbg___wbindgen_number_get_394265ed1e1b84ee: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'number' ? obj : undefined;
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_string_get_b0ca35b86a603356: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_344f42d3211c4765: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_8a2dd23819f8a60a: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_call_a6e5c5dce5018821: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_done_89b2b13e91a60321: function(arg0) {
            const ret = arg0.done;
            return ret;
        },
        __wbg_entries_015dc610cd81ede0: function(arg0) {
            const ret = Object.entries(arg0);
            return ret;
        },
        __wbg_error_a6fa202b58aa1cd3: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_get_507a50627bffa49b: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_c7eb1f358a7654df: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_unchecked_6e0ad6d2a41b06f6: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_with_ref_key_6412cf3094599694: function(arg0, arg1) {
            const ret = arg0[arg1];
            return ret;
        },
        __wbg_instanceof_ArrayBuffer_4480b9e0068a8adb: function(arg0) {
            let result;
            try {
                result = arg0 instanceof ArrayBuffer;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Uint8Array_309b927aaf7a3fc7: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_isArray_0677c962b281d01a: function(arg0) {
            const ret = Array.isArray(arg0);
            return ret;
        },
        __wbg_isSafeInteger_04f36e4056f1b851: function(arg0) {
            const ret = Number.isSafeInteger(arg0);
            return ret;
        },
        __wbg_iterator_6f722e4a93058b71: function() {
            const ret = Symbol.iterator;
            return ret;
        },
        __wbg_length_1f0964f4a5e2c6d8: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_370319915dc99107: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_log_5bad81a8c5e4232f: function(arg0, arg1) {
            console.log(getStringFromWasm0(arg0, arg1));
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_32b398fb48b6d94a: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_cd45aabdf6073e84: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_da52cf8fe3429cb2: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_with_length_e6785c33c8e4cce8: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_next_6dbf2c0ac8cde20f: function(arg0) {
            const ret = arg0.next;
            return ret;
        },
        __wbg_next_71f2aa1cb3d1e37e: function() { return handleError(function (arg0) {
            const ret = arg0.next();
            return ret;
        }, arguments); },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_4770620bbe4688a0: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_set_6be42768c690e380: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_set_8a16b38e4805b298: function(arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_static_accessor_GLOBAL_4ef717fb391d88b7: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_146583524fe1469b: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_f2829a2234d7819e: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_subarray_3ed232c8a6baee09: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_value_a5d5488a9589444a: function(arg0) {
            const ret = arg0.value;
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
        memory: memory || new WebAssembly.Memory({initial:51,maximum:32768,shared:true}),
    };
    return {
        __proto__: null,
        "./zafu_wasm_bg.js": import0,
    };
}

const WalletKeysFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_walletkeys_free(ptr, 1));
const WatchOnlyWalletFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_watchonlywallet_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer !== wasm.memory.buffer) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.buffer !== wasm.memory.buffer) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : undefined);
if (cachedTextDecoder) cachedTextDecoder.decode();

const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().slice(ptr, ptr + len));
}

const cachedTextEncoder = (typeof TextEncoder !== 'undefined' ? new TextEncoder() : undefined);

if (cachedTextEncoder) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module, thread_stack_size) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    if (typeof thread_stack_size !== 'undefined' && (typeof thread_stack_size !== 'number' || thread_stack_size === 0 || thread_stack_size % 65536 !== 0)) {
        throw new Error('invalid stack size');
    }

    wasm.__wbindgen_start(thread_stack_size);
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module, memory) {
    if (wasm !== undefined) return wasm;

    let thread_stack_size
    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module, memory, thread_stack_size} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports(memory);
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module, thread_stack_size);
}

async function __wbg_init(module_or_path, memory) {
    if (wasm !== undefined) return wasm;

    let thread_stack_size
    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path, memory, thread_stack_size} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('zafu_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports(memory);

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module, thread_stack_size);
}

export { initSync, __wbg_init as default };

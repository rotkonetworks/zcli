// transaction building - ported from zafu-wasm without wasm_bindgen
// supports: shielding (t→z) and orchard spend (z→z, z→t)

use orchard::builder::{Builder, BundleType};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::tree::Anchor;
use orchard::value::NoteValue;
use zcash_protocol::value::ZatBalance;

use crate::error::Error;
use crate::key::WalletSeed;

/// rand_core 0.10 RNG backed by the OS entropy source (`rand::rngs::OsRng`).
///
/// Zakura Common 1.0's Orchard builders (`Builder::build` / `build_for_pczt`)
/// and the PCZT binding-signature step take `impl rand_core::Rng` from
/// rand_core 0.10, which is a pure-trait crate with no bundled `OsRng`. This
/// zero-sized adapter bridges rand 0.8's `OsRng` to rand_core 0.10's
/// `TryRng`/`TryCryptoRng`, whose blanket impls promote it to `Rng` +
/// `CryptoRng`. Mirrors the `OsRng10` adapter in crates/zcash-wasm.
/// `pub` rather than `pub(crate)` so `zclid` can sign with the same adapter
/// instead of keeping a third copy of it.
#[derive(Clone, Copy, Default)]
pub struct OsRng10;

impl rand_core_10::TryRng for OsRng10 {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(dst);
        Ok(())
    }
}
impl rand_core_10::TryCryptoRng for OsRng10 {}

// -- from zafu-wasm --

fn blake2b_256_personal(personalization: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personalization)
        .hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Test-only: the non-test builders derive P2PKH scripts through
/// `make_p2pkh_script` from a pubkey hash they already hold.
#[cfg(test)]
fn hash160(data: &[u8]) -> [u8; 20] {
    use sha2::Digest;
    let sha = sha2::Sha256::digest(data);
    let ripe = ripemd::Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

fn make_p2pkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(0x76); // OP_DUP
    s.push(0xa9); // OP_HASH160
    s.push(0x14); // push 20 bytes
    s.extend_from_slice(pubkey_hash);
    s.push(0x88); // OP_EQUALVERIFY
    s.push(0xac); // OP_CHECKSIG
    s
}

pub fn compact_size(n: u64) -> Vec<u8> {
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

pub fn serialize_orchard_bundle(
    bundle: &orchard::Bundle<orchard::bundle::Authorized, ZatBalance>,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    let actions = bundle.actions();
    let n = actions.len();

    out.extend_from_slice(&compact_size(n as u64));

    for action in actions.iter() {
        out.extend_from_slice(&action.cv_net().to_bytes());
        out.extend_from_slice(&action.nullifier().to_bytes());
        out.extend_from_slice(&<[u8; 32]>::from(action.rk()));
        out.extend_from_slice(&action.cmx().to_bytes());
        out.extend_from_slice(&action.encrypted_note().epk_bytes);
        out.extend_from_slice(&action.encrypted_note().enc_ciphertext);
        out.extend_from_slice(&action.encrypted_note().out_ciphertext);
    }

    // TODO(ironwood correctness): NU6.3 fork's Flags::to_byte takes a
    // BundleFormat and returns Option; PreNu6_3 preserves the V5 wire format.
    out.push(
        bundle
            .flags()
            .to_byte(orchard::bundle::BundleVersion::orchard_v2())
            .ok_or_else(|| {
                Error::Transaction("orchard flags not representable in pre-NU6.3 format".into())
            })?,
    );
    out.extend_from_slice(&bundle.value_balance().to_i64_le_bytes());
    out.extend_from_slice(&bundle.anchor().to_bytes());

    let proof_bytes = bundle.authorization().proof().as_ref();
    out.extend_from_slice(&compact_size(proof_bytes.len() as u64));
    out.extend_from_slice(proof_bytes);

    for action in actions.iter() {
        out.extend_from_slice(&<[u8; 64]>::from(action.authorization()));
    }

    out.extend_from_slice(&<[u8; 64]>::from(
        bundle.authorization().binding_signature(),
    ));

    Ok(())
}

fn compute_orchard_digest<A: orchard::bundle::Authorization>(
    bundle: &orchard::Bundle<A, ZatBalance>,
) -> Result<[u8; 32], Error> {
    let mut compact_data = Vec::new();
    let mut memos_data = Vec::new();
    let mut noncompact_data = Vec::new();

    for action in bundle.actions().iter() {
        compact_data.extend_from_slice(&action.nullifier().to_bytes());
        compact_data.extend_from_slice(&action.cmx().to_bytes());
        let enc = &action.encrypted_note().enc_ciphertext;
        let epk = &action.encrypted_note().epk_bytes;
        compact_data.extend_from_slice(epk);
        compact_data.extend_from_slice(&enc[..52]);

        memos_data.extend_from_slice(&enc[52..564]);

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
    // TODO(ironwood correctness): PreNu6_3 flag byte preserves the V5 sighash;
    // post-activation this must select BundleFormat::Nu6_3.
    orchard_data.push(
        bundle
            .flags()
            .to_byte(orchard::bundle::BundleVersion::orchard_v2())
            .ok_or_else(|| {
                Error::Transaction("orchard flags not representable in pre-NU6.3 format".into())
            })?,
    );
    orchard_data.extend_from_slice(&bundle.value_balance().to_i64_le_bytes());
    orchard_data.extend_from_slice(&bundle.anchor().to_bytes());

    Ok(blake2b_256_personal(b"ZTxIdOrchardHash", &orchard_data))
}

// -- memo encoding (ZIP-302) --

/// The ZIP-302 "no memo" memo: first byte `0xF6`, remaining 511 bytes zero.
///
/// This is what `MemoBytes::empty()` encodes and what every other Zcash wallet
/// puts in an output the user left without a memo. It is NOT the same as 512
/// zero bytes: `0x00…` decodes as a zero-length *text* memo, a distinguishable
/// minority encoding, so a wallet emitting it fingerprints itself to the
/// recipient (and to anyone holding the OVK) on every no-memo output.
pub const ZIP302_NO_MEMO: [u8; 512] = {
    let mut m = [0u8; 512];
    m[0] = 0xF6;
    m
};

/// Encode an optional user memo into ZIP-302 512-byte form.
///
/// `None` or an empty string yields [`ZIP302_NO_MEMO`], not zeros. A memo that
/// does not fit is a hard ERROR rather than a silent truncation: truncating
/// UTF-8 at 512 bytes can split a codepoint, so the recipient would see a
/// corrupt memo with no indication anything was dropped.
pub fn encode_memo(memo: Option<&str>) -> Result<[u8; 512], Error> {
    let Some(text) = memo.filter(|t| !t.is_empty()) else {
        return Ok(ZIP302_NO_MEMO);
    };
    let bytes = text.as_bytes();
    if bytes.len() > 512 {
        return Err(Error::Transaction(format!(
            "memo is {} bytes; the ZIP-302 limit is 512",
            bytes.len()
        )));
    }
    let mut out = [0u8; 512];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

// -- transparent UTXO for shielding --

#[derive(Debug, Clone)]
pub struct TransparentUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub script: String,
}

// -- shielding transaction (t→z) --

/// Real NU6.3 / Ironwood consensus branch id and activation heights, mirroring
/// upstream `zcash_protocol::consensus` (mainnet 3_428_143, testnet 4_134_000).
///
/// NOTE: the previously-pinned librustzcash fork activated NU6.3 on
/// test/regtest at height 1; upstream uses the real testnet activation. Only
/// the testnet gate below moves as a result — mainnet is unchanged.
pub(crate) const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;
pub(crate) const NU6_3_ACTIVATION_HEIGHT_MAINNET: u32 = 3_428_143;
const NU6_3_ACTIVATION_HEIGHT_TESTNET: u32 = 4_134_000;

/// FAIL CLOSED: orchard SPENDS are disabled from NU6.3.
///
/// The sibling of [`guard_orchard_shielding_allowed`] for the z→z / z→t builder.
/// Orchard→orchard is consensus-disabled by the one-way turnstile, and
/// [`build_orchard_spend_tx`] hardcodes the pre-NU6.2 bundle protocol and
/// proving key, so at/after activation it burns ~2 minutes of Halo 2 proving and
/// is then rejected by the node. Checked by BOTH the target height and the live
/// consensus branch id, so neither a stale height nor a node that has already
/// upgraded can open the door on its own.
pub(crate) fn guard_pre_nu6_2_orchard_builder_allowed(
    anchor_height: u32,
    branch_id: u32,
    mainnet: bool,
) -> Result<(), Error> {
    let activation = if mainnet {
        NU6_3_ACTIVATION_HEIGHT_MAINNET
    } else {
        NU6_3_ACTIVATION_HEIGHT_TESTNET
    };
    if anchor_height >= activation || branch_id == NU6_3_BRANCH_ID {
        return Err(Error::Transaction(format!(
            "this builder cannot produce a valid transaction at NU6.3 \
             (activation height {}, chain height {}, branch id {:#010x}): it \
             pins the pre-NU6.2 orchard bundle protocol, so the transaction \
             would prove for minutes and then be rejected.\n\
             \n\
             To be precise about what NU6.3 disables: orchard SPENDS are still \
             valid - the turnstile migration spends orchard notes and is mined \
             on mainnet. What is disabled is creating new orchard OUTPUTS; the \
             turnstile is one-way, so value may leave the orchard pool but not \
             enter it. orchard->transparent is therefore a legal shape that \
             this builder simply does not implement.\n\
             \n\
             Options: migrate to ironwood via the turnstile and spend from \
             there (zafu-wasm build_signed_ironwood_send / \
             build_ironwood_send_pczt). zcli's own ironwood spend path is not \
             implemented yet.",
            activation, anchor_height, branch_id
        )));
    }
    Ok(())
}

/// Shield transparent UTXOs into the IRONWOOD pool (t->z, NU6.3).
///
/// The orchard builder below is fail-closed post-activation because an orchard
/// output created now is unspendable and would need a turnstile migration plus
/// a second fee to recover. This is the path that is actually correct at NU6.3,
/// and it calls the same core the extension uses rather than duplicating it.
///
/// Recipient is the wallet's own orchard address — ironwood reuses orchard
/// addresses and note encryption, it only has its own commitment tree.
///
/// `source_index` selects the transparent address the UTXOs must belong to:
/// they are signed with the key at m/44'/133'/0'/0/{source_index}, and a UTXO
/// whose reported scriptPubKey is not that key's P2PKH script is refused.
#[allow(clippy::too_many_arguments)]
pub fn build_ironwood_shielding_tx(
    seed: &WalletSeed,
    utxos: &[TransparentUtxo],
    source_index: u32,
    recipient_addr: &orchard::Address,
    fee: u64,
    target_height: u32,
    branch_id: u32,
    mainnet: bool,
) -> Result<Vec<u8>, Error> {
    use zcash_protocol::consensus::MainNetwork;
    use zync_core::consensus::TestNetwork;
    use zcash_protocol::memo::MemoBytes;

    // FAIL CLOSED before proving: a V6 ironwood tx is only a valid shape once
    // NU6.3 is live, and proving first would waste minutes to learn that.
    if branch_id != NU6_3_BRANCH_ID {
        return Err(Error::Transaction(format!(
            "ironwood shielding requires the NU6.3 consensus branch id \
             {:#010x}, but the node reports {:#010x}",
            NU6_3_BRANCH_ID, branch_id
        )));
    }

    let privkey = crate::address::derive_transparent_key_at(seed, source_index)?;
    let sk = secp256k1::SecretKey::from_slice(&privkey)
        .map_err(|e| Error::Transaction(format!("invalid transparent key: {e}")))?;

    // our own p2pkh key hash, used to rebuild each UTXO's script locally
    let secp = secp256k1::Secp256k1::signing_only();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let pubkey_hash: [u8; 20] = {
        use ripemd::Digest as _;
        let sha = sha2::Sha256::digest(pubkey.serialize());
        ripemd::Ripemd160::digest(sha).into()
    };
    let addr = zcash_transparent::address::TransparentAddress::PublicKeyHash(pubkey_hash);
    // our own scriptPubKey for this source index, in the same bytes the
    // `zcash_transparent` encoder produces (pinned by a unit test)
    let our_script = make_p2pkh_script(&pubkey_hash);

    let mut inputs = Vec::with_capacity(utxos.len());
    for u in utxos {
        let txid_bytes = hex::decode(&u.txid)
            .map_err(|e| Error::Transaction(format!("bad utxo txid: {e}")))?;
        let txid: [u8; 32] = txid_bytes
            .try_into()
            .map_err(|_| Error::Transaction("utxo txid must be 32 bytes".into()))?;
        // Reject a UTXO the endpoint attributed to some other script: the
        // signature below commits to OUR script, so a mismatch means the
        // outpoint does not hold funds this key can spend. Refuse here rather
        // than after minutes of proving. A UTXO reported without a script
        // (empty) is accepted - the builder derives the script itself and
        // never signs a server-supplied one.
        if !u.script.is_empty() {
            let reported = hex::decode(&u.script)
                .map_err(|e| Error::Transaction(format!("utxo script is not hex: {e}")))?;
            if reported != our_script {
                return Err(Error::Transaction(format!(
                    "utxo {}:{} is not spendable by transparent address index {} \
                     (scriptPubKey mismatch)",
                    u.txid, u.vout, source_index
                )));
            }
        }
        // Derive the scriptPubKey from OUR OWN key rather than trusting the
        // bytes the server returned for this UTXO. The signature commits to
        // this script, so accepting a server-supplied one would let a hostile
        // endpoint steer what we sign over. Same reason the builder re-derives
        // rather than echoing.
        let outpoint = zcash_transparent::bundle::OutPoint::new(txid, u.vout);
        #[allow(deprecated)]
        let coin = zcash_transparent::bundle::TxOut {
            value: zcash_protocol::value::Zatoshis::from_u64(u.value)
                .map_err(|_| Error::Transaction("utxo value out of range".into()))?,
            script_pubkey: addr.script().into(),
        };
        inputs.push((outpoint, coin));
    }

    // `mainnet` picks the consensus params TYPE, so the call is duplicated
    // rather than parameterised; only one arm ever runs.
    let res = if mainnet {
        zafu_wasm::build_shielding_transaction_ironwood_core(
            MainNetwork,
            &sk,
            &inputs,
            *recipient_addr,
            fee,
            target_height,
            branch_id,
            MemoBytes::empty(),
        )
    } else {
        zafu_wasm::build_shielding_transaction_ironwood_core(
            TestNetwork,
            &sk,
            &inputs,
            *recipient_addr,
            fee,
            target_height,
            branch_id,
            MemoBytes::empty(),
        )
    };
    res.map_err(Error::Transaction)
}

// -- orchard spend transaction (z→t, z→z) --

#[allow(clippy::too_many_arguments)]
pub fn build_orchard_spend_tx(
    seed: &WalletSeed,
    spends: &[(orchard::Note, orchard::tree::MerklePath)],
    t_outputs: &[(String, u64)], // z→t: (t-address, amount)
    z_outputs: &[(orchard::Address, u64, [u8; 512])], // z→z: (addr, amount, memo)
    fee: u64,
    anchor: Anchor,
    anchor_height: u32,
    branch_id: u32,
    mainnet: bool,
) -> Result<Vec<u8>, Error> {
    // FAIL CLOSED: never build an orchard SPEND the network rejects post-NU6.3.
    // Same shape of height+branch-id gate as the ironwood shielding builder:
    // this builder pins `BundleProtocol::OrchardPreNu6_2` and the pre-NU6.2
    // proving key while binding the live branch id, so at the mainnet tip it
    // proves for ~2 minutes
    // and is then rejected. `zclid`'s merchant payout/sweep loops retry that
    // forever without ever marking the notes spent, so the gate must be here in
    // the builder rather than in each caller.
    guard_pre_nu6_2_orchard_builder_allowed(anchor_height, branch_id, mainnet)?;

    let coin_type = if mainnet { 133 } else { 1 };
    let sk = SpendingKey::from_zip32_seed(seed.as_bytes(), coin_type, zip32::AccountId::ZERO)
        .map_err(|_| Error::Transaction("failed to derive spending key".into()))?;
    let fvk = FullViewingKey::from(&sk);
    let ask = orchard::keys::SpendAuthorizingKey::from(&sk);

    // compute change
    let total_in: u64 = spends.iter().map(|(n, _)| n.value().inner()).sum();
    let total_t: u64 = t_outputs.iter().map(|(_, v)| *v).sum();
    let total_z: u64 = z_outputs.iter().map(|(_, v, _)| *v).sum();
    let total_out = total_t + total_z + fee;
    if total_in < total_out {
        return Err(Error::InsufficientFunds {
            have: total_in,
            need: total_out,
        });
    }
    let change = total_in - total_out;

    // build orchard bundle
    // NU6.3 fork: explicit spends/outputs bools + BundleProtocol on Builder.
    // orchard::bundle::Flags::ENABLED == spends on, outputs on.
    // TODO(ironwood correctness): OrchardPreNu6_2 keeps the historical V5 spend
    // circuit/format; post-activation this becomes a NU6.3 protocol.
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

    let n_spends = spends.len();
    for (note, path) in spends {
        builder
            .add_spend(fvk.clone(), *note, path.clone())
            .map_err(|e| Error::Transaction(format!("add_spend: {:?}", e)))?;
    }

    // z→z outputs
    for (addr, amount, memo) in z_outputs {
        let ovk = Some(fvk.to_ovk(Scope::External));
        builder
            .add_output(ovk, *addr, NoteValue::from_raw(*amount), *memo)
            .map_err(|e| Error::Transaction(format!("add_output: {:?}", e)))?;
    }

    // change output (back to self, internal scope)
    if change > 0 {
        let change_addr = fvk.address_at(0u64, Scope::Internal);
        let ovk = Some(fvk.to_ovk(Scope::Internal));
        builder
            .add_output(ovk, change_addr, NoteValue::from_raw(change), ZIP302_NO_MEMO)
            .map_err(|e| Error::Transaction(format!("add_output (change): {:?}", e)))?;
    }

    let mut rng = OsRng10;
    let (unauthorized, _meta) = builder
        .build::<ZatBalance>(&mut rng)
        .map_err(|e| Error::Transaction(format!("bundle build: {:?}", e)))?
        .ok_or_else(|| Error::Transaction("builder produced no bundle".into()))?;

    // halo 2 proving (rayon parallelism is automatic via halo2's multicore feature)
    // TODO(ironwood correctness): InsecurePreNu6_2 matches the V5 verifying key
    // (branch 0x4DEC4DF0); NU6.3 proving needs PostNu6_3.
    let pk = orchard::circuit::ProvingKey::build(
        orchard::circuit::OrchardCircuitVersion::InsecurePreNu6_2,
    );
    let proven = unauthorized
        .create_proof(&pk, &mut rng)
        .map_err(|e| Error::Transaction(format!("create_proof: {:?}", e)))?;

    // serialize transparent outputs for z→t
    let t_output_scripts: Vec<Vec<u8>> = t_outputs
        .iter()
        .map(|(addr, _)| decode_t_address_script(addr, mainnet))
        .collect::<Result<_, _>>()?;

    // ZIP-244 sighash
    // branch_id comes from the live chain (GetLightdInfo.consensus_branch_id)
    let expiry_height = anchor_height.saturating_add(100);

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

    let transparent_digest = if t_outputs.is_empty() {
        blake2b_256_personal(b"ZTxIdTranspaHash", &[])
    } else {
        let prevouts_digest = blake2b_256_personal(b"ZTxIdPrevoutHash", &[]);
        let sequence_digest = blake2b_256_personal(b"ZTxIdSequencHash", &[]);
        let mut outputs_data = Vec::new();
        for (i, (_, amount)) in t_outputs.iter().enumerate() {
            outputs_data.extend_from_slice(&amount.to_le_bytes());
            outputs_data.extend_from_slice(&compact_size(t_output_scripts[i].len() as u64));
            outputs_data.extend_from_slice(&t_output_scripts[i]);
        }
        let outputs_digest = blake2b_256_personal(b"ZTxIdOutputsHash", &outputs_data);
        let mut d = Vec::new();
        d.extend_from_slice(&prevouts_digest);
        d.extend_from_slice(&sequence_digest);
        d.extend_from_slice(&outputs_digest);
        blake2b_256_personal(b"ZTxIdTranspaHash", &d)
    };

    let sapling_digest = blake2b_256_personal(b"ZTxIdSaplingHash", &[]);
    let orchard_digest = compute_orchard_digest(&proven)?;

    let sighash_personal = {
        let mut p = [0u8; 16];
        p[..12].copy_from_slice(b"ZcashTxHash_");
        p[12..16].copy_from_slice(&branch_id.to_le_bytes());
        p
    };
    let sighash = {
        let mut d = Vec::new();
        d.extend_from_slice(&header_digest);
        d.extend_from_slice(&transparent_digest);
        d.extend_from_slice(&sapling_digest);
        d.extend_from_slice(&orchard_digest);
        blake2b_256_personal(&sighash_personal, &d)
    };

    // sign orchard spends
    let signing_keys: Vec<orchard::keys::SpendAuthorizingKey> =
        (0..n_spends).map(|_| ask.clone()).collect();
    let authorized = proven
        .apply_signatures(rng, sighash, &signing_keys)
        .map_err(|e| Error::Transaction(format!("apply_signatures: {:?}", e)))?;

    // serialize v5 transaction
    let mut tx = Vec::new();

    // header
    tx.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
    tx.extend_from_slice(&0x26A7270Au32.to_le_bytes());
    tx.extend_from_slice(&branch_id.to_le_bytes());
    tx.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
    tx.extend_from_slice(&expiry_height.to_le_bytes());

    // transparent inputs (none for orchard spend)
    tx.extend_from_slice(&compact_size(0));

    // transparent outputs
    if t_outputs.is_empty() {
        tx.extend_from_slice(&compact_size(0));
    } else {
        tx.extend_from_slice(&compact_size(t_outputs.len() as u64));
        for (i, (_, amount)) in t_outputs.iter().enumerate() {
            tx.extend_from_slice(&amount.to_le_bytes());
            tx.extend_from_slice(&compact_size(t_output_scripts[i].len() as u64));
            tx.extend_from_slice(&t_output_scripts[i]);
        }
    }

    // sapling (none)
    tx.extend_from_slice(&compact_size(0));
    tx.extend_from_slice(&compact_size(0));

    // orchard bundle
    serialize_orchard_bundle(&authorized, &mut tx)?;

    Ok(tx)
}

/// decode a t-address to a P2PKH scriptPubKey
pub fn decode_t_address_script(addr: &str, mainnet: bool) -> Result<Vec<u8>, Error> {
    let decoded = base58_decode(addr)
        .map_err(|_| Error::Address(format!("invalid base58 in t-address: {}", addr)))?;
    let expected = if mainnet { [0x1c, 0xb8] } else { [0x1d, 0x25] };
    if decoded.len() != 22 || decoded[..2] != expected {
        return Err(Error::Address(format!(
            "invalid transparent address: {}",
            addr
        )));
    }
    let mut pkh = [0u8; 20];
    pkh.copy_from_slice(&decoded[2..]);
    Ok(make_p2pkh_script(&pkh))
}

/// base58check decode (returns version + payload, checksum verified)
fn base58_decode(s: &str) -> Result<Vec<u8>, Error> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // decode base58 to big integer (as byte vec)
    let mut num: Vec<u8> = vec![0];
    for &c in s.as_bytes() {
        let val = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| Error::Address("invalid base58 character".into()))?
            as u32;
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

    // leading '1's → leading 0x00 bytes
    let leading = s.bytes().take_while(|&b| b == b'1').count();
    // strip leading zeros from num
    let start = num.iter().position(|&b| b != 0).unwrap_or(num.len());
    let mut result = vec![0u8; leading];
    result.extend_from_slice(&num[start..]);

    // verify checksum (last 4 bytes)
    if result.len() < 4 {
        return Err(Error::Address("base58check too short".into()));
    }
    let (payload, checksum) = result.split_at(result.len() - 4);
    use sha2::Digest;
    let hash = sha2::Sha256::digest(sha2::Sha256::digest(payload));
    if &hash[..4] != checksum {
        return Err(Error::Address("base58check checksum mismatch".into()));
    }
    Ok(payload.to_vec())
}

/// parse an orchard address from a unified address string (from zafu-wasm)
pub fn parse_orchard_address(addr_str: &str, mainnet: bool) -> Result<orchard::Address, Error> {
    use zcash_keys::address::Address as ZkAddress;
    use zcash_protocol::consensus::MainNetwork;
    use zync_core::consensus::TestNetwork;

    let decoded = if mainnet {
        ZkAddress::decode(&MainNetwork, addr_str)
    } else {
        ZkAddress::decode(&TestNetwork, addr_str)
    };

    match decoded {
        Some(ZkAddress::Unified(ua)) => {
            let orchard_addr = ua
                .orchard()
                .ok_or_else(|| Error::Address("unified address has no orchard receiver".into()))?;
            let raw_bytes = orchard_addr.to_raw_address_bytes();
            Option::from(orchard::Address::from_raw_address_bytes(&raw_bytes))
                .ok_or_else(|| Error::Address("invalid orchard address bytes".into()))
        }
        Some(_) => Err(Error::Address("not a unified address".into())),
        None => Err(Error::Address("failed to decode address".into())),
    }
}

/// derive the orchard recipient address from seed (for self-shielding)
pub fn self_shielding_address(seed: &WalletSeed, mainnet: bool) -> Result<orchard::Address, Error> {
    let coin_type = if mainnet { 133 } else { 1 };
    let sk = SpendingKey::from_zip32_seed(seed.as_bytes(), coin_type, zip32::AccountId::ZERO)
        .map_err(|_| Error::Address("failed to derive spending key".into()))?;
    let fvk = FullViewingKey::from(&sk);
    Ok(fvk.address_at(0u64, Scope::External))
}

#[cfg(test)]
mod orchard_gate_tests {
    use super::*;

    /// Orchard SPENDS (z→z, z→t: `zcli send`, `zcli merchant`, `zclid`'s payout
    /// and sweep loops) must be gated exactly like shielding. Before this gate
    /// `build_orchard_spend_tx` proved at the mainnet tip and broadcast a tx
    /// zebra rejects, and zclid retried it forever.
    #[test]
    fn orchard_spends_are_gated_at_nu6_3() {
        const NU6_2: u32 = 0x5437_f330;
        assert!(
            guard_pre_nu6_2_orchard_builder_allowed(NU6_3_ACTIVATION_HEIGHT_MAINNET - 1, NU6_2, true).is_ok()
        );
        assert!(
            guard_pre_nu6_2_orchard_builder_allowed(NU6_3_ACTIVATION_HEIGHT_MAINNET, NU6_2, true).is_err()
        );
        assert!(guard_pre_nu6_2_orchard_builder_allowed(
            NU6_3_ACTIVATION_HEIGHT_MAINNET + 10_000,
            NU6_2,
            true
        )
        .is_err());
        // stale/wrong height but the node already reports NU6.3: refused
        assert!(guard_pre_nu6_2_orchard_builder_allowed(1_000_000, NU6_3_BRANCH_ID, true).is_err());
        // testnet: same boundary at the real upstream activation height.
        assert!(guard_pre_nu6_2_orchard_builder_allowed(
            NU6_3_ACTIVATION_HEIGHT_TESTNET - 1,
            NU6_2,
            false
        )
        .is_ok());
        assert!(guard_pre_nu6_2_orchard_builder_allowed(
            NU6_3_ACTIVATION_HEIGHT_TESTNET,
            NU6_2,
            false
        )
        .is_err());
    }

    /// The builder itself must refuse, not just the guard - callers
    /// (ops/send.rs, ops/merchant.rs, zclid/service.rs) do not gate.
    #[test]
    fn build_orchard_spend_tx_refuses_post_activation() {
        let seed = WalletSeed::from_bytes([7u8; 64]);
        let err = build_orchard_spend_tx(
            &seed,
            &[],
            &[],
            &[],
            10_000,
            Anchor::empty_tree(),
            NU6_3_ACTIVATION_HEIGHT_MAINNET,
            NU6_3_BRANCH_ID,
            true,
        )
        .unwrap_err();
        // Assert on BEHAVIOUR (it refuses, and names the real reason) rather
        // than on prose. The previous assertion pinned the exact sentence
        // "orchard spends are disabled", which was both brittle and untrue —
        // orchard spends are valid at NU6.3; the turnstile does it on mainnet.
        let msg = err.to_string();
        assert!(
            msg.contains("pre-NU6.2 orchard bundle protocol"),
            "error should name the real cause (the pinned bundle protocol), got: {err}"
        );
        assert!(
            !msg.contains("orchard spends are disabled"),
            "error repeats the untrue claim that orchard spends are disabled: {err}"
        );
    }
}

#[cfg(test)]
mod shielding_script_tests {
    use super::*;

    /// The scriptPubKey the shielding builder signs over is built locally; it
    /// must be byte-identical to what the `zcash_transparent` encoder derives
    /// from the same pubkey hash, and it must follow the requested transparent
    /// index (m/44'/133'/0'/0/N).
    #[test]
    fn p2pkh_script_matches_upstream_encoder_per_index() {
        let seed = WalletSeed::from_bytes([3u8; 64]);
        let secp = secp256k1::Secp256k1::signing_only();
        let mut scripts = Vec::new();
        for index in 0..3u32 {
            let key = crate::address::derive_transparent_key_at(&seed, index).unwrap();
            let sk = secp256k1::SecretKey::from_slice(&key).unwrap();
            let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
            let hash = hash160(&pk.serialize());
            let addr = zcash_transparent::address::TransparentAddress::PublicKeyHash(hash);
            let upstream: Vec<u8> = zcash_transparent::address::Script::from(addr.script()).0 .0;
            assert_eq!(make_p2pkh_script(&hash), upstream);
            assert_eq!(upstream.len(), 25);
            scripts.push(upstream);
        }
        assert_ne!(scripts[0], scripts[1]);
        assert_ne!(scripts[1], scripts[2]);
    }

    /// A UTXO the endpoint attributes to a foreign scriptPubKey cannot be
    /// signed by the requested index's key, so the builder must refuse it
    /// before starting the (minutes-long) halo 2 proof.
    #[test]
    fn ironwood_builder_refuses_foreign_utxo_script() {
        let seed = WalletSeed::from_bytes([9u8; 64]);
        let recipient = self_shielding_address(&seed, true).unwrap();
        let utxos = [TransparentUtxo {
            txid: "11".repeat(32),
            vout: 0,
            value: 100_000,
            script: hex::encode(make_p2pkh_script(&[0xcd; 20])),
        }];
        let err = build_ironwood_shielding_tx(
            &seed,
            &utxos,
            0,
            &recipient,
            10_000,
            3_500_000,
            NU6_3_BRANCH_ID,
            true,
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::Transaction(m) if m.contains("scriptPubKey mismatch")),
            "unexpected error: {err:?}"
        );
    }
}

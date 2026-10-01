//! Transparent -> transparent with an OP_RETURN payload: the THORChain deposit.
//!
//! THORChain's zcash observer is transparent only. A swap out of ZEC is a t->t
//! payment to the current vault with the swap instruction in an OP_RETURN, and
//! any refund goes back to the address that funded vin[0]. So every input here
//! comes from ONE transparent address and change returns to that same address.
//!
//! Split like every other hot send: [`build_unsigned_transparent_core`] gets the
//! pubkey and the address's UTXOs (public data only) and returns a PCZT plus its
//! per-input sighashes; the zcash worker signs those with `SpendKeys` (via
//! `sign_shielding`, whose PCZT completion verifies each signature against the
//! carrier's own sighash) and broadcasts.

use wasm_bindgen::prelude::*;

use crate::{
    hex_decode, hex_encode, Nu63Activated, TransparentUtxo, P2PKH_TX_IN_SIZE, ZIP317_GRACE_ACTIONS,
    ZIP317_MARGINAL_FEE, ZIP317_TX_BYTES_PER_ACTION,
};

/// Serialized size of a P2PKH `tx_out`: value(8) + compactsize(1) + script(25).
/// ZIP-317 counts transparent output bytes in units of exactly this.
pub const P2PKH_TX_OUT_SIZE: u64 = 34;

/// Relay limit for null-data payloads, and what THORChain's observers read.
pub const MAX_NULL_DATA_BYTES: usize = 80;

/// Change below this costs about as much to spend as it is worth, so it goes to
/// the fee instead of becoming an output.
pub const TRANSPARENT_CHANGE_DUST_ZAT: u64 = ZIP317_MARGINAL_FEE;

/// Serialized size of the `tx_out` carrying a `len`-byte OP_RETURN payload:
/// value(8) + compactsize(1) + OP_RETURN(1) + push (1, or 2 for OP_PUSHDATA1
/// past 75 bytes) + data.
pub fn null_data_tx_out_size(len: usize) -> u64 {
    let push = if len <= 75 { 1 } else { 2 };
    8 + 1 + 1 + push + len as u64
}

/// ZIP-317 conventional fee for a transparent-only tx:
/// `5000 * max(2, ceil(in_bytes / 150), ceil(out_bytes / 34))`.
/// The OP_RETURN is paid for byte by byte: a 67-byte memo is 3 actions alone.
pub fn zip317_transparent_fee(n_inputs: usize, out_sizes: &[u64]) -> u64 {
    let tin = (n_inputs as u64 * P2PKH_TX_IN_SIZE).div_ceil(ZIP317_TX_BYTES_PER_ACTION);
    let tout = out_sizes.iter().sum::<u64>().div_ceil(P2PKH_TX_OUT_SIZE);
    ZIP317_MARGINAL_FEE * tin.max(tout).max(ZIP317_GRACE_ACTIONS)
}

/// Output sizes in tx order: payment, OP_RETURN (when there is a payload), change.
fn out_sizes(null_data_len: usize, with_change: bool) -> Vec<u64> {
    let mut v = vec![P2PKH_TX_OUT_SIZE];
    if null_data_len > 0 {
        v.push(null_data_tx_out_size(null_data_len));
    }
    if with_change {
        v.push(P2PKH_TX_OUT_SIZE);
    }
    v
}

/// What a t->t spend of these coins costs, decided before any key is touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransparentPlan {
    /// the largest `inputs` coins are spent
    pub inputs: usize,
    pub total_in: u64,
    pub fee: u64,
    /// back to the funding address; 0 means no change output
    pub change: u64,
    /// zatoshi missing from the address; 0 when the spend is covered. Sending
    /// exactly this much more to the address as one coin covers it.
    pub short: u64,
}

/// Plan a spend of `amount` from coins worth `values`, largest first. The
/// caller reviews this plan; the builder rebuilds it from the same coins and
/// gets the same answer.
pub fn plan_transparent_spend(
    values: &[u64],
    amount: u64,
    null_data_len: usize,
) -> Result<TransparentPlan, String> {
    if null_data_len > MAX_NULL_DATA_BYTES {
        return Err(format!(
            "OP_RETURN payload is {null_data_len} bytes; the relay limit is {MAX_NULL_DATA_BYTES}"
        ));
    }
    if amount == 0 {
        return Err("amount must be positive".into());
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    let fee = |n: usize, change: bool| zip317_transparent_fee(n, &out_sizes(null_data_len, change));
    let mut total_in: u64 = 0;
    for (i, v) in sorted.iter().enumerate() {
        total_in = total_in
            .checked_add(*v)
            .ok_or("transparent input total overflows u64")?;
        let n = i + 1;
        let with_change = fee(n, true);
        if total_in >= amount.saturating_add(with_change + TRANSPARENT_CHANGE_DUST_ZAT) {
            return Ok(TransparentPlan {
                inputs: n,
                total_in,
                fee: with_change,
                change: total_in - amount - with_change,
                short: 0,
            });
        }
        if total_in >= amount.saturating_add(fee(n, false)) {
            return Ok(TransparentPlan {
                inputs: n,
                total_in,
                fee: total_in - amount,
                change: 0,
                short: 0,
            });
        }
    }
    let n = sorted.len() + 1;
    Ok(TransparentPlan {
        inputs: 0,
        total_in,
        fee: fee(n, true),
        change: 0,
        short: amount.saturating_add(fee(n, true)).saturating_sub(total_in),
    })
}

/// An unsigned t->t transaction: the PCZT carrier, the sighash of each input
/// (taken from a re-parse of exactly these bytes) and the plan it was built to.
#[derive(Debug)]
pub struct UnsignedTransparent {
    pub pczt_bytes: Vec<u8>,
    pub sighashes: Vec<[u8; 32]>,
    pub plan: TransparentPlan,
}

type Coin = (
    zcash_transparent::bundle::OutPoint,
    zcash_transparent::bundle::TxOut,
);

/// Build the unsigned deposit: pay `amount` to `recipient` at vout 0, then the
/// OP_RETURN carrying `null_data` (when non-empty), then change back to the
/// pubkey's own address. Spends the largest of `coins`, every one of which must
/// be locked to `pubkey`, so vin[0] (THORChain's refund target) is that address.
///
/// V5, not the NU6.3 default V6: nothing here needs V6, and V5 is what every
/// transparent parser (THORChain's observer included) reads.
#[allow(clippy::too_many_arguments)]
pub fn build_unsigned_transparent_core<P>(
    params: P,
    pubkey: &secp256k1::PublicKey,
    coins: &[Coin],
    recipient: zcash_transparent::address::TransparentAddress,
    amount: u64,
    null_data: &[u8],
    target_height: u32,
    expected_branch_id: u32,
) -> Result<UnsignedTransparent, String>
where
    P: zcash_protocol::consensus::Parameters,
{
    use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
    use zcash_primitives::transaction::fees::fixed::FeeRule as FixedFeeRule;
    use zcash_primitives::transaction::TxVersion;
    use zcash_protocol::consensus::{BlockHeight, BranchId};
    use zcash_protocol::value::Zatoshis;
    use zcash_transparent::address::TransparentAddress;

    type FeError = <FixedFeeRule as zcash_primitives::transaction::fees::FeeRule>::Error;

    let bound: u32 = BranchId::for_height(&params, BlockHeight::from(target_height)).into();
    if bound == 0xffff_ffff || bound != expected_branch_id {
        return Err(format!(
            "refusing to build: branch id at height {target_height} is {bound:#010x}, \
             the wallet expected {expected_branch_id:#010x}"
        ));
    }

    let own = TransparentAddress::from_pubkey(pubkey);
    let own_script: zcash_transparent::address::Script = own.script().into();
    if let Some(i) = coins
        .iter()
        .position(|(_, c)| c.script_pubkey() != &own_script)
    {
        return Err(format!(
            "input {i} is not a P2PKH output of this address; a deposit spends one address only"
        ));
    }

    // largest first, ties by outpoint, so the review's plan and this build pick
    // the same coins
    let mut sorted: Vec<&Coin> = coins.iter().collect();
    sorted.sort_by(|(oa, a), (ob, b)| {
        b.value()
            .cmp(&a.value())
            .then_with(|| (oa.hash(), oa.n()).cmp(&(ob.hash(), ob.n())))
    });
    let values: Vec<u64> = sorted.iter().map(|(_, c)| c.value().into_u64()).collect();
    let plan = plan_transparent_spend(&values, amount, null_data.len())?;
    if plan.short > 0 {
        return Err(format!(
            "insufficient funds: have {} zat, need {} zat more",
            plan.total_in, plan.short
        ));
    }

    let mut builder = Builder::new(
        params,
        BlockHeight::from(target_height),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .propose_version::<FeError>(TxVersion::V5)
        .map_err(|e| format!("propose_version(V5): {e:?}"))?;
    for (outpoint, coin) in &sorted[..plan.inputs] {
        builder
            .add_transparent_p2pkh_input(*pubkey, outpoint.clone(), coin.clone())
            .map_err(|e| format!("add_transparent_p2pkh_input: {e:?}"))?;
    }
    let zat = |v: u64| Zatoshis::from_u64(v).map_err(|_| format!("invalid amount {v}"));
    builder
        .add_transparent_output(&recipient, zat(amount)?)
        .map_err(|e| format!("add_transparent_output: {e:?}"))?;
    if !null_data.is_empty() {
        builder
            .add_transparent_null_data_output::<FeError>(null_data)
            .map_err(|e| format!("add_transparent_null_data_output: {e:?}"))?;
    }
    if plan.change > 0 {
        builder
            .add_transparent_output(&own, zat(plan.change)?)
            .map_err(|e| format!("add_transparent_output (change): {e:?}"))?;
    }

    let parts = builder
        .build_for_pczt(crate::OsRng10, &FixedFeeRule::non_standard(zat(plan.fee)?))
        .map_err(|e| format!("build_for_pczt: {e:?}"))?
        .pczt_parts;
    let pczt = pczt::roles::creator::Creator::build_from_parts(parts)
        .ok_or("Creator::build_from_parts: incompatible tx version")?;
    let pczt = pczt::roles::io_finalizer::IoFinalizer::new(pczt)
        .finalize_io()
        .map_err(|e| format!("finalize_io: {e:?}"))?;

    // the pubkey as each input's hash160 preimage: the completion needs it to
    // match a signature to its key. It is committed to no digest.
    let pubkey_bytes = pubkey.serialize().to_vec();
    let n = pczt.transparent().inputs().len();
    let pczt = pczt::roles::updater::Updater::new(pczt)
        .update_transparent_with(|mut tu| {
            for i in 0..n {
                tu.update_input_with(i, |mut inp| {
                    inp.set_hash160_preimage(pubkey_bytes.clone());
                    Ok(())
                })?;
            }
            Ok(())
        })
        .map_err(|e| format!("updater set hash160 preimage: {e:?}"))?
        .finish();
    let pczt_bytes = pczt
        .serialize()
        .map_err(|e| format!("pczt serialize: {e:?}"))?;

    let signer = pczt::roles::signer::Signer::new(
        pczt::Pczt::parse(&pczt_bytes).map_err(|e| format!("pczt re-parse: {e:?}"))?,
    )
    .map_err(|e| format!("signer init: {e:?}"))?;
    let sighashes = (0..n)
        .map(|i| {
            signer
                .transparent_sighash(i)
                .map_err(|e| format!("transparent_sighash[{i}]: {e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(UnsignedTransparent {
        pczt_bytes,
        sighashes,
        plan,
    })
}

fn parse_utxos(utxos_json: &str) -> Result<Vec<TransparentUtxo>, JsError> {
    serde_json::from_str(utxos_json).map_err(|e| JsError::new(&format!("invalid utxos json: {e}")))
}

fn null_data_bytes(hex: Option<&str>) -> Result<Vec<u8>, JsError> {
    match hex {
        None | Some("") => Ok(Vec::new()),
        Some(h) => hex_decode(h).ok_or_else(|| JsError::new("invalid null data hex")),
    }
}

fn plan_json(p: &TransparentPlan) -> serde_json::Value {
    serde_json::json!({
        "inputs": p.inputs,
        "total_in": p.total_in,
        "fee": p.fee,
        "change": p.change,
        "short": p.short,
    })
}

/// Plan a t->t spend from an address's UTXOs (`[{txid, vout, value, script}]`)
/// without any key: what the review shows. Returns JSON
/// `{inputs, total_in, fee, change, short}`; `short > 0` means the address
/// needs that much more first.
#[wasm_bindgen]
pub fn plan_transparent_transaction(
    utxos_json: &str,
    amount: u64,
    null_data_hex: Option<String>,
) -> Result<String, JsError> {
    let values: Vec<u64> = parse_utxos(utxos_json)?.iter().map(|u| u.value).collect();
    let null_data = null_data_bytes(null_data_hex.as_deref())?;
    let plan =
        plan_transparent_spend(&values, amount, null_data.len()).map_err(|e| JsError::new(&e))?;
    Ok(plan_json(&plan).to_string())
}

/// Build an UNSIGNED t->t transaction from public data only: the UTXOs of one
/// address and its 33-byte compressed `pubkey_hex`. Outputs are
/// [recipient, OP_RETURN(`null_data_hex`, at most 80 bytes), change to the same
/// address]. Returns JSON
/// `{sighashes, unsigned_tx_hex, inputs, total_in, fee, change, short}`, where
/// `unsigned_tx_hex` is a PCZT for `SpendKeys.sign_shielding`.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_unsigned_transparent_transaction(
    utxos_json: &str,
    pubkey_hex: &str,
    recipient: &str,
    amount: u64,
    target_height: u32,
    expected_branch_id: u32,
    mainnet: bool,
    null_data_hex: Option<String>,
) -> Result<String, JsError> {
    use zcash_keys::encoding::AddressCodec;
    use zcash_protocol::consensus::{BlockHeight, MainNetwork, TestNetwork};
    use zcash_protocol::value::Zatoshis;
    use zcash_transparent::address::TransparentAddress;
    use zcash_transparent::bundle::{OutPoint, TxOut};

    let pubkey = hex_decode(pubkey_hex)
        .filter(|b| b.len() == 33)
        .and_then(|b| secp256k1::PublicKey::from_slice(&b).ok())
        .ok_or_else(|| JsError::new("pubkey must be a 33-byte compressed secp256k1 key"))?;
    let script: zcash_transparent::address::Script =
        TransparentAddress::from_pubkey(&pubkey).script().into();
    let coins = parse_utxos(utxos_json)?
        .iter()
        .map(|u| {
            let mut txid: [u8; 32] = hex_decode(&u.txid)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| JsError::new("utxo txid must be 32 bytes of hex"))?;
            // display order is big-endian; an outpoint holds it little-endian
            txid.reverse();
            if hex_decode(&u.script).as_deref() != Some(&script.0 .0[..]) {
                return Err(JsError::new(&format!(
                    "utxo {}:{} is not a P2PKH output of this key",
                    u.txid, u.vout
                )));
            }
            let value =
                Zatoshis::from_u64(u.value).map_err(|_| JsError::new("utxo value out of range"))?;
            Ok((
                OutPoint::new(txid, u.vout),
                TxOut::new(value, script.clone()),
            ))
        })
        .collect::<Result<Vec<Coin>, JsError>>()?;
    let null_data = null_data_bytes(null_data_hex.as_deref())?;

    macro_rules! build {
        ($net:expr) => {{
            let params = Nu63Activated {
                inner: $net,
                nu6_3_from: BlockHeight::from(target_height),
            };
            let to = TransparentAddress::decode(&params, recipient)
                .map_err(|e| JsError::new(&format!("invalid transparent recipient: {e:?}")))?;
            build_unsigned_transparent_core(
                params,
                &pubkey,
                &coins,
                to,
                amount,
                &null_data,
                target_height,
                expected_branch_id,
            )
        }};
    }
    let built = if mainnet {
        build!(MainNetwork)
    } else {
        build!(TestNetwork)
    }
    .map_err(|e| JsError::new(&e))?;

    let mut out = plan_json(&built.plan);
    out["sighashes"] = built.sighashes.iter().map(|s| hex_encode(s)).collect();
    out["unsigned_tx_hex"] = hex_encode(&built.pczt_bytes).into();
    Ok(out.to_string())
}

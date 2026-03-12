// pure PCZT (Partially Created Zcash Transaction) functions
// no filesystem, no async, no wallet — suitable for wasm compilation
//
// extracted from ops/airgap.rs for reuse in zafu-wasm

use ff::PrimeField;
use orchard::builder::{Builder, BundleType};
use orchard::bundle::Flags;
use orchard::keys::{FullViewingKey, Scope};
use orchard::tree::Anchor;
use orchard::value::NoteValue;
use rand::rngs::OsRng;
use zcash_protocol::value::ZatBalance;

use crate::error::Error;
use crate::tx;

// -- FVK parsing --

/// parse zigner FVK export QR
/// supports:
/// - raw binary: [0x53][0x04][0x01] + flags + account(4 LE) + label_len(1) + label + fvk(96)
/// - UR string: "ur:zcash-fvk/..." (as exported by zigner android app)
pub fn parse_fvk_export(data: &[u8]) -> Result<([u8; 96], bool, u32, String), Error> {
    // check if data is a UR string (starts with "ur:")
    if let Ok(text) = std::str::from_utf8(data) {
        let text = text.trim();
        if text.starts_with("ur:") {
            return parse_fvk_from_ur(text);
        }
    }

    if data.len() < 3 {
        return Err(Error::Other("FVK export too short".into()));
    }
    if data[0] != 0x53 || data[1] != 0x04 || data[2] != 0x01 {
        return Err(Error::Other(format!(
            "not a zigner FVK export: {:02x}{:02x}{:02x}",
            data[0], data[1], data[2]
        )));
    }

    let mut offset = 3;

    // flags: bit0=mainnet, bit1=has_orchard, bit2=has_transparent
    if offset >= data.len() {
        return Err(Error::Other("FVK export truncated at flags".into()));
    }
    let flags = data[offset];
    let mainnet = flags & 0x01 != 0;
    offset += 1;

    // account index (4 bytes LE)
    if offset + 4 > data.len() {
        return Err(Error::Other("FVK export truncated at account".into()));
    }
    let account = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;

    // label length + label
    if offset >= data.len() {
        return Err(Error::Other("FVK export truncated at label_len".into()));
    }
    let label_len = data[offset] as usize;
    offset += 1;
    if offset + label_len > data.len() {
        return Err(Error::Other("FVK export truncated at label".into()));
    }
    let label = String::from_utf8_lossy(&data[offset..offset + label_len]).to_string();
    offset += label_len;

    // orchard FVK (96 bytes)
    if offset + 96 > data.len() {
        return Err(Error::Other(format!(
            "FVK export truncated at fvk: need {} more bytes, have {}",
            96,
            data.len() - offset
        )));
    }
    let mut fvk = [0u8; 96];
    fvk.copy_from_slice(&data[offset..offset + 96]);

    Ok((fvk, mainnet, account, label))
}

/// parse FVK from UR string: "ur:zcash-accounts/<bytewords>"
fn parse_fvk_from_ur(ur_str: &str) -> Result<([u8; 96], bool, u32, String), Error> {
    let rest = ur_str.strip_prefix("ur:").unwrap_or(ur_str);
    let ur_type = rest.split('/').next().unwrap_or("");

    if !ur_type.starts_with("zcash") {
        return Err(Error::Other(format!(
            "wrong UR type '{}' — expected a zcash account export. \
             make sure zigner is showing the Zcash account QR, not {}",
            ur_type, ur_type
        )));
    }

    let (_kind, payload) =
        ur::ur::decode(ur_str).map_err(|e| Error::Other(format!("UR decode: {}", e)))?;

    // try parsing as zcash-accounts CBOR (Keystone/Zashi format from zigner)
    if payload.first() == Some(&0xa2) {
        return parse_zcash_accounts_cbor(&payload);
    }

    // try stripping CBOR byte string wrapper
    let inner = strip_cbor_bytes(&payload)?;

    // try as raw FVK export (0x53 0x04 0x01 header)
    if inner.len() >= 3 && inner[0] == 0x53 && inner[1] == 0x04 && inner[2] == 0x01 {
        return parse_fvk_raw(inner);
    }

    // raw 96-byte FVK
    if inner.len() == 96 {
        let mut fvk = [0u8; 96];
        fvk.copy_from_slice(inner);
        return Ok((fvk, true, 0, String::new()));
    }

    Err(Error::Other(format!(
        "UR payload not recognized: {} bytes, starts with {:02x?}",
        inner.len(),
        &inner[..inner.len().min(6)]
    )))
}

/// parse zcash-accounts CBOR (Keystone/Zashi format)
fn parse_zcash_accounts_cbor(data: &[u8]) -> Result<([u8; 96], bool, u32, String), Error> {
    let mut offset = 0;

    if data.get(offset) != Some(&0xa2) {
        return Err(Error::Other("expected CBOR map(2)".into()));
    }
    offset += 1;

    // key 1: seed fingerprint (skip it)
    if data.get(offset) != Some(&0x01) {
        return Err(Error::Other("expected CBOR key 1".into()));
    }
    offset += 1;
    if data.get(offset) != Some(&0x50) {
        return Err(Error::Other(
            "expected bytes(16) for seed fingerprint".into(),
        ));
    }
    offset += 1 + 16;

    // key 2: accounts array
    if data.get(offset) != Some(&0x02) {
        return Err(Error::Other("expected CBOR key 2".into()));
    }
    offset += 1;
    if data.get(offset) != Some(&0x81) {
        return Err(Error::Other("expected CBOR array(1)".into()));
    }
    offset += 1;

    // tag 49203 = d9 c0 33
    if data.get(offset..offset + 3) != Some(&[0xd9, 0xc0, 0x33]) {
        return Err(Error::Other("expected CBOR tag 49203".into()));
    }
    offset += 3;

    let map_size = match data.get(offset) {
        Some(&0xa2) => 2,
        Some(&0xa3) => 3,
        _ => return Err(Error::Other("expected CBOR map for account".into())),
    };
    offset += 1;

    // key 1: UFVK string
    if data.get(offset) != Some(&0x01) {
        return Err(Error::Other("expected CBOR key 1 (ufvk)".into()));
    }
    offset += 1;

    let ufvk_str = cbor_read_text(data, &mut offset)?;

    // key 2: account index
    let account = if data.get(offset) == Some(&0x02) {
        offset += 1;
        cbor_read_uint(data, &mut offset)?
    } else {
        0
    };

    // key 3: label (optional)
    let label = if map_size >= 3 && data.get(offset) == Some(&0x03) {
        offset += 1;
        cbor_read_text(data, &mut offset)?
    } else {
        String::new()
    };

    let (fvk_bytes, mainnet) = decode_ufvk(&ufvk_str)?;
    Ok((fvk_bytes, mainnet, account, label))
}

fn cbor_read_text(data: &[u8], offset: &mut usize) -> Result<String, Error> {
    let header = *data
        .get(*offset)
        .ok_or_else(|| Error::Other("CBOR truncated".into()))?;
    let major = header >> 5;
    let additional = header & 0x1f;
    if major != 3 {
        return Err(Error::Other(format!(
            "expected CBOR text string, got major {}",
            major
        )));
    }
    *offset += 1;

    let len = match additional {
        n @ 0..=23 => n as usize,
        24 => {
            let l = *data
                .get(*offset)
                .ok_or_else(|| Error::Other("CBOR truncated".into()))? as usize;
            *offset += 1;
            l
        }
        25 => {
            if *offset + 2 > data.len() {
                return Err(Error::Other("CBOR truncated".into()));
            }
            let l = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as usize;
            *offset += 2;
            l
        }
        _ => return Err(Error::Other("CBOR: unsupported text length".into())),
    };

    if *offset + len > data.len() {
        return Err(Error::Other("CBOR text extends beyond data".into()));
    }
    let s = std::str::from_utf8(&data[*offset..*offset + len])
        .map_err(|_| Error::Other("CBOR text not valid UTF-8".into()))?
        .to_string();
    *offset += len;
    Ok(s)
}

fn cbor_read_uint(data: &[u8], offset: &mut usize) -> Result<u32, Error> {
    let header = *data
        .get(*offset)
        .ok_or_else(|| Error::Other("CBOR truncated".into()))?;
    let major = header >> 5;
    let additional = header & 0x1f;
    if major != 0 {
        return Err(Error::Other(format!(
            "expected CBOR uint, got major {}",
            major
        )));
    }
    *offset += 1;

    match additional {
        n @ 0..=23 => Ok(n as u32),
        24 => {
            let v = *data
                .get(*offset)
                .ok_or_else(|| Error::Other("CBOR truncated".into()))? as u32;
            *offset += 1;
            Ok(v)
        }
        25 => {
            if *offset + 2 > data.len() {
                return Err(Error::Other("CBOR truncated".into()));
            }
            let v = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as u32;
            *offset += 2;
            Ok(v)
        }
        _ => Err(Error::Other("CBOR: unsupported uint size".into())),
    }
}

fn decode_ufvk(ufvk: &str) -> Result<([u8; 96], bool), Error> {
    use zcash_address::unified::{Container, Encoding, Ufvk};

    let (network, ufvk) =
        Ufvk::decode(ufvk).map_err(|e| Error::Other(format!("UFVK decode: {}", e)))?;

    #[allow(deprecated)]
    let mainnet = matches!(network, zcash_address::Network::Main);

    for item in ufvk.items() {
        if let zcash_address::unified::Fvk::Orchard(bytes) = item {
            return Ok((bytes, mainnet));
        }
    }

    Err(Error::Other("UFVK contains no orchard key".into()))
}

fn parse_fvk_raw(data: &[u8]) -> Result<([u8; 96], bool, u32, String), Error> {
    if data.len() < 3 || data[0] != 0x53 || data[1] != 0x04 || data[2] != 0x01 {
        return Err(Error::Other("not raw FVK export".into()));
    }

    let mut offset = 3;

    if offset >= data.len() {
        return Err(Error::Other("FVK export truncated at flags".into()));
    }
    let flags = data[offset];
    let mainnet = flags & 0x01 != 0;
    offset += 1;

    if offset + 4 > data.len() {
        return Err(Error::Other("FVK export truncated at account".into()));
    }
    let account = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;

    if offset >= data.len() {
        return Err(Error::Other("FVK export truncated at label_len".into()));
    }
    let label_len = data[offset] as usize;
    offset += 1;
    if offset + label_len > data.len() {
        return Err(Error::Other("FVK export truncated at label".into()));
    }
    let label = String::from_utf8_lossy(&data[offset..offset + label_len]).to_string();
    offset += label_len;

    if offset + 96 > data.len() {
        return Err(Error::Other(format!(
            "FVK export truncated at fvk: need {} more bytes, have {}",
            96,
            data.len() - offset
        )));
    }
    let mut fvk = [0u8; 96];
    fvk.copy_from_slice(&data[offset..offset + 96]);

    Ok((fvk, mainnet, account, label))
}

fn strip_cbor_bytes(data: &[u8]) -> Result<&[u8], Error> {
    if data.is_empty() {
        return Err(Error::Other("empty CBOR data".into()));
    }

    let mut offset = 0;

    // skip CBOR tag if present (major type 6)
    if data[offset] >> 5 == 6 {
        let additional = data[offset] & 0x1f;
        offset += 1;
        match additional {
            0..=23 => {}
            24 => offset += 1,
            25 => offset += 2,
            26 => offset += 4,
            _ => {}
        }
    }

    if offset >= data.len() {
        return Err(Error::Other("CBOR: truncated after tag".into()));
    }

    let major = data[offset] >> 5;
    let additional = data[offset] & 0x1f;
    offset += 1;

    if major == 2 {
        let len = match additional {
            n @ 0..=23 => n as usize,
            24 => {
                if offset >= data.len() {
                    return Err(Error::Other("CBOR: truncated length".into()));
                }
                let l = data[offset] as usize;
                offset += 1;
                l
            }
            25 => {
                if offset + 2 > data.len() {
                    return Err(Error::Other("CBOR: truncated length".into()));
                }
                let l = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                l
            }
            _ => return Err(Error::Other("CBOR: unsupported length encoding".into())),
        };
        if offset + len > data.len() {
            return Err(Error::Other("CBOR: byte string extends beyond data".into()));
        }
        return Ok(&data[offset..offset + len]);
    }

    Ok(data)
}

// -- zigner QR protocol --

/// encode a sign request for zigner QR scanning
pub fn encode_sign_request(
    sighash: &[u8; 32],
    alphas: &[[u8; 32]],
    mainnet: bool,
    summary: &str,
) -> Vec<u8> {
    let mut data = Vec::new();

    // prelude: [0x53][0x04][0x02]
    data.push(0x53);
    data.push(0x04);
    data.push(0x02);

    // flags: bit 0 = mainnet
    data.push(if mainnet { 0x01 } else { 0x00 });

    // account index (always 0 for now)
    data.extend_from_slice(&0u32.to_le_bytes());

    // sighash
    data.extend_from_slice(sighash);

    // action count
    data.extend_from_slice(&(alphas.len() as u16).to_le_bytes());

    // alpha values
    for alpha in alphas {
        data.extend_from_slice(alpha);
    }

    // summary
    let summary_bytes = summary.as_bytes();
    data.extend_from_slice(&(summary_bytes.len() as u16).to_le_bytes());
    data.extend_from_slice(summary_bytes);

    data
}

/// parse zigner QR signature response
pub fn parse_sign_response(data: &[u8]) -> Result<(Vec<[u8; 64]>, [u8; 32]), Error> {
    if data.len() < 37 {
        return Err(Error::Transaction("response too short".into()));
    }
    if data[0] != 0x53 || data[1] != 0x04 || data[2] != 0x03 {
        return Err(Error::Transaction(format!(
            "invalid response prelude: {:02x}{:02x}{:02x}",
            data[0], data[1], data[2]
        )));
    }

    let mut offset = 3;

    // sighash
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    // transparent sigs (skip)
    if offset + 2 > data.len() {
        return Err(Error::Transaction("response truncated at t_count".into()));
    }
    let t_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    for _ in 0..t_count {
        if offset + 2 > data.len() {
            return Err(Error::Transaction("response truncated at t_sig len".into()));
        }
        let sig_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + sig_len;
    }

    // orchard sigs
    if offset + 2 > data.len() {
        return Err(Error::Transaction("response truncated at o_count".into()));
    }
    let o_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    let mut sigs = Vec::with_capacity(o_count);
    for _ in 0..o_count {
        if offset + 64 > data.len() {
            return Err(Error::Transaction(
                "response truncated at orchard sig".into(),
            ));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[offset..offset + 64]);
        sigs.push(sig);
        offset += 64;
    }

    Ok((sigs, sighash))
}

// -- PCZT build/complete --

fn blake2b_personal(personalization: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personalization)
        .hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

fn compute_pczt_orchard_digest(bundle: &orchard::pczt::Bundle) -> Result<[u8; 32], Error> {
    let mut compact_data = Vec::new();
    let mut memos_data = Vec::new();
    let mut noncompact_data = Vec::new();

    for action in bundle.actions() {
        compact_data.extend_from_slice(&action.spend().nullifier().to_bytes());
        compact_data.extend_from_slice(&action.output().cmx().to_bytes());
        let enc = &action.output().encrypted_note().enc_ciphertext;
        let epk = &action.output().encrypted_note().epk_bytes;
        compact_data.extend_from_slice(epk);
        compact_data.extend_from_slice(&enc[..52]);

        memos_data.extend_from_slice(&enc[52..564]);

        noncompact_data.extend_from_slice(&action.cv_net().to_bytes());
        noncompact_data.extend_from_slice(&<[u8; 32]>::from(action.spend().rk()));
        noncompact_data.extend_from_slice(&enc[564..580]);
        noncompact_data.extend_from_slice(&action.output().encrypted_note().out_ciphertext);
    }

    let compact_digest = blake2b_personal(b"ZTxIdOrcActCHash", &compact_data);
    let memos_digest = blake2b_personal(b"ZTxIdOrcActMHash", &memos_data);
    let noncompact_digest = blake2b_personal(b"ZTxIdOrcActNHash", &noncompact_data);

    let value_balance = i64::try_from(*bundle.value_sum())
        .map_err(|_| Error::Transaction("value_sum overflow".into()))?;

    let mut orchard_data = Vec::new();
    orchard_data.extend_from_slice(&compact_digest);
    orchard_data.extend_from_slice(&memos_digest);
    orchard_data.extend_from_slice(&noncompact_digest);
    orchard_data.push(bundle.flags().to_byte());
    orchard_data.extend_from_slice(&value_balance.to_le_bytes());
    orchard_data.extend_from_slice(&bundle.anchor().to_bytes());

    Ok(blake2b_personal(b"ZTxIdOrchardHash", &orchard_data))
}

/// state needed between prepare and complete phases
pub struct PcztState {
    pub pczt_bundle: orchard::pczt::Bundle,
    pub sighash: [u8; 32],
    pub alphas: Vec<[u8; 32]>,
    pub branch_id: u32,
    pub expiry_height: u32,
    pub t_output_scripts: Vec<(Vec<u8>, u64)>,
}

/// build PCZT bundle, prove, compute sighash, encode zigner QR
/// accepts FVK bytes (96) directly — no spending key needed
#[allow(clippy::too_many_arguments)]
pub fn build_pczt_and_qr(
    fvk_bytes: &[u8; 96],
    spends: &[(orchard::Note, orchard::tree::MerklePath)],
    z_outputs: &[(orchard::Address, u64, [u8; 512])],
    t_outputs: &[(String, u64)],
    change: u64,
    anchor: Anchor,
    anchor_height: u32,
    mainnet: bool,
) -> Result<(Vec<u8>, PcztState), Error> {
    let fvk: FullViewingKey = FullViewingKey::from_bytes(fvk_bytes)
        .ok_or_else(|| Error::Transaction("invalid FVK bytes".into()))?;

    let bundle_type = BundleType::Transactional {
        flags: Flags::ENABLED,
        bundle_required: true,
    };
    let mut builder = Builder::new(bundle_type, anchor);

    for (note, path) in spends {
        builder
            .add_spend(fvk.clone(), *note, path.clone())
            .map_err(|e| Error::Transaction(format!("add_spend: {:?}", e)))?;
    }

    for (addr, amount, memo) in z_outputs {
        let ovk = Some(fvk.to_ovk(Scope::External));
        builder
            .add_output(ovk, *addr, NoteValue::from_raw(*amount), *memo)
            .map_err(|e| Error::Transaction(format!("add_output: {:?}", e)))?;
    }

    if change > 0 {
        let change_addr = fvk.address_at(0u64, Scope::Internal);
        let ovk = Some(fvk.to_ovk(Scope::Internal));
        builder
            .add_output(ovk, change_addr, NoteValue::from_raw(change), [0u8; 512])
            .map_err(|e| Error::Transaction(format!("add_output (change): {:?}", e)))?;
    }

    let mut rng = OsRng;

    let (mut pczt_bundle, _meta) = builder
        .build_for_pczt(&mut rng)
        .map_err(|e| Error::Transaction(format!("build_for_pczt: {:?}", e)))?;

    let branch_id: u32 = 0x4DEC4DF0; // NU6.1
    let expiry_height = anchor_height.saturating_add(100);

    let t_output_scripts: Vec<(Vec<u8>, u64)> = t_outputs
        .iter()
        .map(|(addr, amount)| {
            let script = tx::decode_t_address_script(addr, mainnet)?;
            Ok((script, *amount))
        })
        .collect::<Result<_, Error>>()?;

    let orchard_digest = compute_pczt_orchard_digest(&pczt_bundle)?;

    let header_data = {
        let mut d = Vec::new();
        d.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
        d.extend_from_slice(&0x26A7270Au32.to_le_bytes());
        d.extend_from_slice(&branch_id.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&expiry_height.to_le_bytes());
        d
    };
    let header_digest = blake2b_personal(b"ZTxIdHeadersHash", &header_data);

    let transparent_digest = if t_output_scripts.is_empty() {
        blake2b_personal(b"ZTxIdTranspaHash", &[])
    } else {
        let prevouts_digest = blake2b_personal(b"ZTxIdPrevoutHash", &[]);
        let sequence_digest = blake2b_personal(b"ZTxIdSequencHash", &[]);
        let mut outputs_data = Vec::new();
        for (script, amount) in &t_output_scripts {
            outputs_data.extend_from_slice(&amount.to_le_bytes());
            outputs_data.extend_from_slice(&tx::compact_size(script.len() as u64));
            outputs_data.extend_from_slice(script);
        }
        let outputs_digest = blake2b_personal(b"ZTxIdOutputsHash", &outputs_data);
        let mut d = Vec::new();
        d.extend_from_slice(&prevouts_digest);
        d.extend_from_slice(&sequence_digest);
        d.extend_from_slice(&outputs_digest);
        blake2b_personal(b"ZTxIdTranspaHash", &d)
    };

    let sapling_digest = blake2b_personal(b"ZTxIdSaplingHash", &[]);

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
        blake2b_personal(&sighash_personal, &d)
    };

    pczt_bundle
        .finalize_io(sighash, rng)
        .map_err(|e| Error::Transaction(format!("finalize_io: {}", e)))?;

    let pk = orchard::circuit::ProvingKey::build();
    pczt_bundle
        .create_proof(&pk, rng)
        .map_err(|e| Error::Transaction(format!("create_proof: {}", e)))?;

    // extract alphas for non-dummy actions
    let mut alphas = Vec::new();
    for action in pczt_bundle.actions() {
        if action.spend().spend_auth_sig().is_none() {
            let alpha =
                action.spend().alpha().as_ref().ok_or_else(|| {
                    Error::Transaction("missing alpha on non-dummy action".into())
                })?;
            alphas.push(alpha.to_repr());
        }
    }

    let summary = if !z_outputs.is_empty() {
        let total_z: u64 = z_outputs.iter().map(|(_, v, _)| *v).sum();
        format!("Send {:.8} ZEC (shielded)", total_z as f64 / 1e8)
    } else {
        let total_t: u64 = t_outputs.iter().map(|(_, v)| *v).sum();
        format!("Send {:.8} ZEC → transparent", total_t as f64 / 1e8)
    };

    let qr_data = encode_sign_request(&sighash, &alphas, mainnet, &summary);

    let state = PcztState {
        pczt_bundle,
        sighash,
        alphas,
        branch_id,
        expiry_height,
        t_output_scripts,
    };

    Ok((qr_data, state))
}

/// apply external signatures, extract authorized bundle, serialize v5 tx
pub fn complete_pczt_tx(mut state: PcztState, orchard_sigs: &[[u8; 64]]) -> Result<Vec<u8>, Error> {
    // apply signatures to non-dummy actions
    let mut sig_idx = 0;
    for action in state.pczt_bundle.actions_mut() {
        if action.spend().spend_auth_sig().is_none() {
            let sig = orchard::primitives::redpallas::Signature::<
                orchard::primitives::redpallas::SpendAuth,
            >::from(orchard_sigs[sig_idx]);
            action
                .apply_signature(state.sighash, sig)
                .map_err(|e| Error::Transaction(format!("apply_signature: {}", e)))?;
            sig_idx += 1;
        }
    }

    // extract to Bundle<Unbound>
    let bundle = state
        .pczt_bundle
        .extract::<ZatBalance>()
        .map_err(|e| Error::Transaction(format!("extract: {}", e)))?
        .ok_or_else(|| Error::Transaction("extract returned None".into()))?;

    // apply binding signature
    let rng = OsRng;
    let authorized = bundle
        .apply_binding_signature(state.sighash, rng)
        .ok_or_else(|| Error::Transaction("binding signature verification failed".into()))?;

    // serialize v5 transaction
    let mut tx_bytes = Vec::new();

    // header
    tx_bytes.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
    tx_bytes.extend_from_slice(&0x26A7270Au32.to_le_bytes());
    tx_bytes.extend_from_slice(&state.branch_id.to_le_bytes());
    tx_bytes.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
    tx_bytes.extend_from_slice(&state.expiry_height.to_le_bytes());

    // transparent inputs (none for orchard spend)
    tx_bytes.extend_from_slice(&tx::compact_size(0));

    // transparent outputs
    if state.t_output_scripts.is_empty() {
        tx_bytes.extend_from_slice(&tx::compact_size(0));
    } else {
        tx_bytes.extend_from_slice(&tx::compact_size(state.t_output_scripts.len() as u64));
        for (script, amount) in &state.t_output_scripts {
            tx_bytes.extend_from_slice(&amount.to_le_bytes());
            tx_bytes.extend_from_slice(&tx::compact_size(script.len() as u64));
            tx_bytes.extend_from_slice(script);
        }
    }

    // sapling (none)
    tx_bytes.extend_from_slice(&tx::compact_size(0));
    tx_bytes.extend_from_slice(&tx::compact_size(0));

    // orchard bundle
    tx::serialize_orchard_bundle(&authorized, &mut tx_bytes)?;

    Ok(tx_bytes)
}

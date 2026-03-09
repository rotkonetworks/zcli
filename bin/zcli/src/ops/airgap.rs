// airgap signing via zigner QR protocol
//
// flow:
// 1. build PCZT bundle (with ZK proof) on hot machine
// 2. display QR: sighash + alphas for zigner to scan
// 3. zigner signs on cold device, displays response QR
// 4. user pastes response hex into zcli
// 5. apply external signatures, finalize, broadcast

use ff::PrimeField;
use orchard::builder::{Builder, BundleType};
use orchard::bundle::Flags;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::tree::Anchor;
use orchard::value::NoteValue;
use rand::rngs::OsRng;
use zcash_protocol::value::ZatBalance;

use crate::client::ZidecarClient;
use crate::error::Error;
use crate::key::WalletSeed;
use crate::ops::send::{compute_fee, select_notes};
use crate::tx;
use crate::wallet::Wallet;
use crate::witness;

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
    // extract UR type for validation
    let rest = ur_str.strip_prefix("ur:").unwrap_or(ur_str);
    let ur_type = rest.split('/').next().unwrap_or("");
    eprintln!("UR type: {}", ur_type);

    if !ur_type.starts_with("zcash") {
        return Err(Error::Other(format!(
            "wrong UR type '{}' — expected a zcash account export. \
             make sure zigner is showing the Zcash account QR, not {}",
            ur_type, ur_type
        )));
    }

    // decode using the ur crate (handles bytewords + CRC)
    let (_kind, payload) =
        ur::ur::decode(ur_str).map_err(|e| Error::Other(format!("UR decode: {}", e)))?;

    eprintln!("UR payload: {} bytes", payload.len());

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
/// structure: map(2) { 1: seed_fingerprint(bytes16), 2: array[ tag(49203) map { 1: ufvk_string, 2: index, 3?: label } ] }
fn parse_zcash_accounts_cbor(data: &[u8]) -> Result<([u8; 96], bool, u32, String), Error> {
    let mut offset = 0;

    // a2 = map(2)
    if data.get(offset) != Some(&0xa2) {
        return Err(Error::Other("expected CBOR map(2)".into()));
    }
    offset += 1;

    // key 1: seed fingerprint (skip it)
    if data.get(offset) != Some(&0x01) {
        return Err(Error::Other("expected CBOR key 1".into()));
    }
    offset += 1;
    // 0x50 = bytes(16)
    if data.get(offset) != Some(&0x50) {
        return Err(Error::Other(
            "expected bytes(16) for seed fingerprint".into(),
        ));
    }
    offset += 1 + 16; // skip 16 bytes

    // key 2: accounts array
    if data.get(offset) != Some(&0x02) {
        return Err(Error::Other("expected CBOR key 2".into()));
    }
    offset += 1;
    // 0x81 = array(1)
    if data.get(offset) != Some(&0x81) {
        return Err(Error::Other("expected CBOR array(1)".into()));
    }
    offset += 1;

    // tag 49203 = d9 c0 33
    if data.get(offset..offset + 3) != Some(&[0xd9, 0xc0, 0x33]) {
        return Err(Error::Other("expected CBOR tag 49203".into()));
    }
    offset += 3;

    // map(2 or 3)
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

    eprintln!("UFVK: {}...", &ufvk_str[..ufvk_str.len().min(40)]);
    eprintln!("account: {}, label: {}", account, label);

    // decode UFVK to extract orchard FVK bytes
    let (fvk_bytes, mainnet) = decode_ufvk(&ufvk_str)?;

    Ok((fvk_bytes, mainnet, account, label))
}

/// read CBOR text string at offset, advance offset
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

/// read CBOR unsigned int at offset, advance offset
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

/// decode a UFVK (unified full viewing key) bech32 string to extract 96-byte orchard FVK
fn decode_ufvk(ufvk: &str) -> Result<([u8; 96], bool), Error> {
    use zcash_address::unified::{Container, Encoding, Ufvk};

    let (network, ufvk) =
        Ufvk::decode(ufvk).map_err(|e| Error::Other(format!("UFVK decode: {}", e)))?;

    #[allow(deprecated)]
    let mainnet = matches!(network, zcash_address::Network::Main);

    // find the orchard item
    for item in ufvk.items() {
        if let zcash_address::unified::Fvk::Orchard(bytes) = item {
            return Ok((bytes, mainnet));
        }
    }

    Err(Error::Other("UFVK contains no orchard key".into()))
}

/// parse raw FVK export bytes (after 0x53 0x04 0x01 validated externally or here)
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

/// strip CBOR byte string wrapper if present
/// CBOR: tag(304) + bstr or just bstr
fn strip_cbor_bytes(data: &[u8]) -> Result<&[u8], Error> {
    if data.is_empty() {
        return Err(Error::Other("empty CBOR data".into()));
    }

    let mut offset = 0;

    // skip CBOR tag if present (major type 6)
    if data[offset] >> 5 == 6 {
        // tag
        let additional = data[offset] & 0x1f;
        offset += 1;
        match additional {
            0..=23 => {} // 1-byte tag value
            24 => offset += 1,
            25 => offset += 2,
            26 => offset += 4,
            _ => {}
        }
    }

    if offset >= data.len() {
        return Err(Error::Other("CBOR: truncated after tag".into()));
    }

    // expect byte string (major type 2)
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

    // not a byte string wrapper, return as-is
    Ok(data)
}

/// zigner QR sign request encoding
fn encode_sign_request(
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
fn parse_sign_response(data: &[u8]) -> Result<(Vec<[u8; 64]>, [u8; 32]), Error> {
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

/// compute orchard digest from pczt bundle (ZIP-244)
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

fn blake2b_personal(personalization: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personalization)
        .hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// display QR code on terminal using unicode half-blocks
fn display_qr(data: &[u8]) {
    use qrcode::QrCode;
    let code = match QrCode::new(hex::encode(data).as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("qr encode failed: {}", e);
            return;
        }
    };
    let width = code.width();
    let modules = code.into_colors();

    let dark = |r: usize, c: usize| -> bool {
        if r < width && c < width {
            modules[r * width + c] == qrcode::Color::Dark
        } else {
            false
        }
    };

    let quiet = 1;
    let total = width + quiet * 2;
    for row in (0..total).step_by(2) {
        for col in 0..total {
            let r0 = row.wrapping_sub(quiet);
            let c0 = col.wrapping_sub(quiet);
            let r1 = r0.wrapping_add(1);
            let top = dark(r0, c0);
            let bot = dark(r1, c0);
            match (top, bot) {
                (true, true) => print!("\u{2588}"),
                (true, false) => print!("\u{2580}"),
                (false, true) => print!("\u{2584}"),
                (false, false) => print!(" "),
            }
        }
        println!();
    }
    println!();
}

/// read response: try webcam QR scan, fall back to hex paste
fn read_response() -> Result<Vec<u8>, Error> {
    // try webcam first on linux
    #[cfg(target_os = "linux")]
    {
        let cam_device = std::env::var("ZCLI_CAM").unwrap_or_else(|_| "/dev/video0".into());
        if std::path::Path::new(&cam_device).exists() {
            eprintln!("hold zigner QR up to camera ({})...", cam_device);
            eprintln!("(press Ctrl+C to cancel, or set ZCLI_CAM=none to skip)");
            if cam_device != "none" {
                match crate::cam::scan_qr(&cam_device, 60) {
                    Ok(data) => {
                        eprintln!("\rQR decoded ({} bytes)                    ", data.len());
                        return Ok(data);
                    }
                    Err(e) => {
                        eprintln!("\rcamera scan failed: {}                    ", e);
                        eprintln!("falling back to manual input...");
                    }
                }
            }
        }
    }

    read_response_manual()
}

/// manual response input: hex string or file path
fn read_response_manual() -> Result<Vec<u8>, Error> {
    use std::io::{self, BufRead};

    eprintln!("enter zigner response (hex or file path):");
    let stdin = io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .ok_or_else(|| Error::Other("no input".into()))?
        .map_err(|e| Error::Other(format!("read stdin: {}", e)))?;

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(Error::Other("empty response".into()));
    }

    // if it looks like a file path, read the file
    if trimmed.starts_with('/') || trimmed.starts_with('.') || trimmed.starts_with('~') {
        let path = if let Some(rest) = trimmed.strip_prefix("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                format!("{}/{}", home.to_string_lossy(), rest)
            } else {
                trimmed.to_string()
            }
        } else {
            trimmed.to_string()
        };
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| Error::Other(format!("read {}: {}", path, e)))?;
        hex::decode(contents.trim())
            .map_err(|e| Error::Other(format!("invalid hex in file: {}", e)))
    } else {
        hex::decode(trimmed).map_err(|e| Error::Other(format!("invalid hex: {}", e)))
    }
}

/// send airgap with seed (hot wallet has spending key)
#[allow(clippy::too_many_arguments)]
pub async fn send_airgap(
    seed: &WalletSeed,
    amount_str: &str,
    recipient: &str,
    memo: Option<&str>,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    let coin_type = if mainnet { 133 } else { 1 };
    let sk = SpendingKey::from_zip32_seed(seed.as_bytes(), coin_type, zip32::AccountId::ZERO)
        .map_err(|_| Error::Transaction("failed to derive spending key".into()))?;
    let fvk = FullViewingKey::from(&sk);
    send_airgap_with_fvk(&fvk, amount_str, recipient, memo, endpoint, mainnet, json).await
}

/// send airgap with FVK only (watch-only wallet, signing delegated to zigner)
#[allow(clippy::too_many_arguments)]
pub async fn send_airgap_with_fvk(
    fvk: &FullViewingKey,
    amount_str: &str,
    recipient: &str,
    memo: Option<&str>,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    if recipient.starts_with("t1") || recipient.starts_with("tm") {
        return send_airgap_to_transparent_fvk(fvk, amount_str, recipient, endpoint, mainnet, json)
            .await;
    }
    if !(recipient.starts_with("u1") || recipient.starts_with("utest1")) {
        return Err(Error::Address(format!(
            "unrecognized address format: {}",
            recipient
        )));
    }

    send_airgap_shielded_fvk(fvk, amount_str, recipient, memo, endpoint, mainnet, json).await
}

/// z→z airgap send (FVK-based, works for both hot and watch-only)
async fn send_airgap_shielded_fvk(
    fvk: &FullViewingKey,
    amount_str: &str,
    recipient: &str,
    memo: Option<&str>,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    let amount_zat = crate::ops::send::parse_amount(amount_str)?;
    let recipient_addr = tx::parse_orchard_address(recipient, mainnet)?;

    let selected = {
        let wallet = Wallet::open(&Wallet::default_path())?;
        let (balance, notes) = wallet.shielded_balance()?;
        let est_fee = compute_fee(1, 1, 0, true);
        let needed = amount_zat + est_fee;
        if balance < needed {
            return Err(Error::InsufficientFunds {
                have: balance,
                need: needed,
            });
        }
        select_notes(&notes, needed)?
    };

    let total_in: u64 = selected.iter().map(|n| n.value).sum();
    let has_change = total_in > amount_zat + compute_fee(selected.len(), 1, 0, true);
    let fee = compute_fee(selected.len(), 1, 0, has_change);
    if total_in < amount_zat + fee {
        return Err(Error::InsufficientFunds {
            have: total_in,
            need: amount_zat + fee,
        });
    }
    let change = total_in - amount_zat - fee;

    if !json {
        eprintln!(
            "airgap: {:.8} ZEC → {}... ({} notes, fee {:.8} ZEC)",
            amount_zat as f64 / 1e8,
            &recipient[..20.min(recipient.len())],
            selected.len(),
            fee as f64 / 1e8
        );
    }

    let orchard_notes: Vec<orchard::Note> = selected
        .iter()
        .map(|n| n.reconstruct_note())
        .collect::<Result<_, _>>()?;

    let client = ZidecarClient::connect(endpoint).await?;
    let (tip, _) = client.get_tip().await?;

    if !json {
        eprintln!("building merkle witnesses...");
    }
    let (anchor, paths) = witness::build_witnesses(&client, &selected, tip, mainnet, json).await?;

    let spends: Vec<(orchard::Note, orchard::tree::MerklePath)> =
        orchard_notes.into_iter().zip(paths).collect();

    let mut memo_bytes = [0u8; 512];
    if let Some(text) = memo {
        let bytes = text.as_bytes();
        let len = bytes.len().min(512);
        memo_bytes[..len].copy_from_slice(&bytes[..len]);
    }

    if !json {
        eprintln!("building PCZT bundle (halo 2 proving)...");
    }

    let fvk_bytes = fvk.to_bytes();
    let anchor_height = tip;
    let recipient_str = recipient.to_string();

    let (qr_data, pczt_state) = tokio::task::spawn_blocking(move || {
        build_pczt_and_qr(
            &fvk_bytes,
            &spends,
            &[(recipient_addr, amount_zat, memo_bytes)],
            &[],
            change,
            anchor,
            anchor_height,
            mainnet,
        )
    })
    .await
    .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "action": "sign_request",
                "qr_hex": hex::encode(&qr_data),
                "sighash": hex::encode(pczt_state.sighash),
                "actions": pczt_state.alphas.len(),
            })
        );
    } else {
        eprintln!("scan this QR with zigner:");
        display_qr(&qr_data);
        eprintln!("sighash: {}", hex::encode(pczt_state.sighash));
        eprintln!("{} action(s) require signing", pczt_state.alphas.len());
    }

    let response_bytes = if json {
        use std::io::{self, Read};
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| Error::Other(format!("read stdin: {}", e)))?;
        hex::decode(buf.trim()).map_err(|e| Error::Other(format!("invalid hex: {}", e)))?
    } else {
        read_response()?
    };

    let (orchard_sigs, resp_sighash) = parse_sign_response(&response_bytes)?;

    if resp_sighash != pczt_state.sighash {
        return Err(Error::Transaction("response sighash does not match".into()));
    }

    if orchard_sigs.len() != pczt_state.alphas.len() {
        return Err(Error::Transaction(format!(
            "expected {} orchard signatures, got {}",
            pczt_state.alphas.len(),
            orchard_sigs.len()
        )));
    }

    if !json {
        eprintln!("applying signatures and finalizing...");
    }

    let tx_bytes = tokio::task::spawn_blocking(move || complete_pczt_tx(pczt_state, &orchard_sigs))
        .await
        .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    let result = client.send_transaction(tx_bytes).await?;

    if result.is_success() {
        let w = Wallet::open(&Wallet::default_path())?;
        let _ = w.insert_sent_tx(&crate::wallet::SentTx {
            txid: result.txid.clone(),
            amount: amount_zat,
            fee,
            recipient: recipient_str.clone(),
            tx_type: "z\u{2192}z (airgap)".into(),
            block_height: 0,
            memo: memo.map(String::from),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        });
    }

    if json {
        println!(
            "{}",
            serde_json::json!({
                "txid": result.txid,
                "amount_zat": amount_zat,
                "fee_zat": fee,
                "recipient": recipient_str,
                "type": "z→z (airgap)",
                "success": result.is_success(),
                "error": result.error_message,
            })
        );
    } else if result.is_success() {
        println!("txid: {}", result.txid);
    } else {
        return Err(Error::Transaction(format!(
            "broadcast failed ({}): {}",
            result.error_code, result.error_message
        )));
    }

    Ok(())
}

/// z→t airgap send (FVK-based)
async fn send_airgap_to_transparent_fvk(
    fvk: &FullViewingKey,
    amount_str: &str,
    recipient: &str,
    endpoint: &str,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    let amount_zat = crate::ops::send::parse_amount(amount_str)?;

    let selected = {
        let wallet = Wallet::open(&Wallet::default_path())?;
        let (balance, notes) = wallet.shielded_balance()?;
        let est_fee = compute_fee(1, 0, 1, true);
        let needed = amount_zat + est_fee;
        if balance < needed {
            return Err(Error::InsufficientFunds {
                have: balance,
                need: needed,
            });
        }
        select_notes(&notes, needed)?
    };

    let total_in: u64 = selected.iter().map(|n| n.value).sum();
    let has_change = total_in > amount_zat + compute_fee(selected.len(), 0, 1, true);
    let fee = compute_fee(selected.len(), 0, 1, has_change);
    if total_in < amount_zat + fee {
        return Err(Error::InsufficientFunds {
            have: total_in,
            need: amount_zat + fee,
        });
    }
    let change = total_in - amount_zat - fee;

    if !json {
        eprintln!(
            "airgap: {:.8} ZEC → {} ({} notes, fee {:.8} ZEC)",
            amount_zat as f64 / 1e8,
            recipient,
            selected.len(),
            fee as f64 / 1e8
        );
    }

    let orchard_notes: Vec<orchard::Note> = selected
        .iter()
        .map(|n| n.reconstruct_note())
        .collect::<Result<_, _>>()?;

    let client = ZidecarClient::connect(endpoint).await?;
    let (tip, _) = client.get_tip().await?;

    if !json {
        eprintln!("building merkle witnesses...");
    }
    let (anchor, paths) = witness::build_witnesses(&client, &selected, tip, mainnet, json).await?;

    let spends: Vec<(orchard::Note, orchard::tree::MerklePath)> =
        orchard_notes.into_iter().zip(paths).collect();

    if !json {
        eprintln!("building PCZT bundle (halo 2 proving)...");
    }

    let fvk_bytes = fvk.to_bytes();
    let t_recipient = recipient.to_string();
    let recipient_str = recipient.to_string();

    let (qr_data, pczt_state) = tokio::task::spawn_blocking(move || {
        build_pczt_and_qr(
            &fvk_bytes,
            &spends,
            &[],
            &[(t_recipient, amount_zat)],
            change,
            anchor,
            tip,
            mainnet,
        )
    })
    .await
    .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "action": "sign_request",
                "qr_hex": hex::encode(&qr_data),
                "sighash": hex::encode(pczt_state.sighash),
                "actions": pczt_state.alphas.len(),
            })
        );
    } else {
        eprintln!("scan this QR with zigner:");
        display_qr(&qr_data);
        eprintln!("sighash: {}", hex::encode(pczt_state.sighash));
        eprintln!("{} action(s) require signing", pczt_state.alphas.len());
    }

    let response_bytes = if json {
        use std::io::{self, Read};
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| Error::Other(format!("read stdin: {}", e)))?;
        hex::decode(buf.trim()).map_err(|e| Error::Other(format!("invalid hex: {}", e)))?
    } else {
        read_response()?
    };

    let (orchard_sigs, resp_sighash) = parse_sign_response(&response_bytes)?;

    if resp_sighash != pczt_state.sighash {
        return Err(Error::Transaction("response sighash does not match".into()));
    }

    if orchard_sigs.len() != pczt_state.alphas.len() {
        return Err(Error::Transaction(format!(
            "expected {} orchard signatures, got {}",
            pczt_state.alphas.len(),
            orchard_sigs.len()
        )));
    }

    if !json {
        eprintln!("applying signatures and finalizing...");
    }

    let tx_bytes = tokio::task::spawn_blocking(move || complete_pczt_tx(pczt_state, &orchard_sigs))
        .await
        .map_err(|e| Error::Other(format!("spawn_blocking: {}", e)))??;

    let result = client.send_transaction(tx_bytes).await?;

    if result.is_success() {
        let w = Wallet::open(&Wallet::default_path())?;
        let _ = w.insert_sent_tx(&crate::wallet::SentTx {
            txid: result.txid.clone(),
            amount: amount_zat,
            fee,
            recipient: recipient_str.clone(),
            tx_type: "z\u{2192}t (airgap)".into(),
            block_height: 0,
            memo: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        });
    }

    if json {
        println!(
            "{}",
            serde_json::json!({
                "txid": result.txid,
                "amount_zat": amount_zat,
                "fee_zat": fee,
                "recipient": recipient_str,
                "type": "z→t (airgap)",
                "success": result.is_success(),
                "error": result.error_message,
            })
        );
    } else if result.is_success() {
        println!("txid: {}", result.txid);
    } else {
        return Err(Error::Transaction(format!(
            "broadcast failed ({}): {}",
            result.error_code, result.error_message
        )));
    }

    Ok(())
}

/// state needed between prepare and complete phases
struct PcztState {
    pczt_bundle: orchard::pczt::Bundle,
    sighash: [u8; 32],
    alphas: Vec<[u8; 32]>,
    // for v5 tx serialization
    branch_id: u32,
    expiry_height: u32,
    t_output_scripts: Vec<(Vec<u8>, u64)>, // (scriptPubKey, amount)
}

/// build PCZT bundle, prove, compute sighash, encode zigner QR
/// accepts FVK bytes (96) directly — no spending key needed
#[allow(clippy::too_many_arguments)]
fn build_pczt_and_qr(
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

    // build orchard bundle
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

    // build PCZT bundle
    let (mut pczt_bundle, _meta) = builder
        .build_for_pczt(&mut rng)
        .map_err(|e| Error::Transaction(format!("build_for_pczt: {:?}", e)))?;

    // compute orchard digest BEFORE finalize_io (actions are already set)
    let branch_id: u32 = 0x4DEC4DF0;
    let expiry_height = anchor_height.saturating_add(100);

    // parse t_output scripts
    let t_output_scripts: Vec<(Vec<u8>, u64)> = t_outputs
        .iter()
        .map(|(addr, amount)| {
            let script = tx::decode_t_address_script(addr, mainnet)?;
            Ok((script, *amount))
        })
        .collect::<Result<_, Error>>()?;

    let orchard_digest = compute_pczt_orchard_digest(&pczt_bundle)?;

    // compute ZIP-244 sighash
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

    // finalize IO (computes bsk, signs dummy spends)
    pczt_bundle
        .finalize_io(sighash, rng)
        .map_err(|e| Error::Transaction(format!("finalize_io: {}", e)))?;

    // create ZK proof
    let pk = orchard::circuit::ProvingKey::build();
    pczt_bundle
        .create_proof(&pk, rng)
        .map_err(|e| Error::Transaction(format!("create_proof: {}", e)))?;

    // extract alphas for non-dummy actions (those still needing signatures)
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

    // build summary for zigner display
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
fn complete_pczt_tx(mut state: PcztState, orchard_sigs: &[[u8; 64]]) -> Result<Vec<u8>, Error> {
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
    let mut tx = Vec::new();

    // header
    tx.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
    tx.extend_from_slice(&0x26A7270Au32.to_le_bytes());
    tx.extend_from_slice(&state.branch_id.to_le_bytes());
    tx.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
    tx.extend_from_slice(&state.expiry_height.to_le_bytes());

    // transparent inputs (none for orchard spend)
    tx.extend_from_slice(&tx::compact_size(0));

    // transparent outputs
    if state.t_output_scripts.is_empty() {
        tx.extend_from_slice(&tx::compact_size(0));
    } else {
        tx.extend_from_slice(&tx::compact_size(state.t_output_scripts.len() as u64));
        for (script, amount) in &state.t_output_scripts {
            tx.extend_from_slice(&amount.to_le_bytes());
            tx.extend_from_slice(&tx::compact_size(script.len() as u64));
            tx.extend_from_slice(script);
        }
    }

    // sapling (none)
    tx.extend_from_slice(&tx::compact_size(0));
    tx.extend_from_slice(&tx::compact_size(0));

    // orchard bundle
    tx::serialize_orchard_bundle(&authorized, &mut tx)?;

    Ok(tx)
}

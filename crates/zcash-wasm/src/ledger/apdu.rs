// Portions adapted from vizor-wallet (chainapsis/vizor-wallet, Apache-2.0), modified.
// See crates/zcash-wasm/LICENSE-APACHE-vizor.
//
//! APDU command shapes and UFVK export for the Ledger Zcash app.
//!
//! Responses handed to this module are PAYLOADS with the two-byte status word
//! already stripped: the transport (zafu's WebHID layer) owns status words and
//! turns a non-0x9000 status into its own failure kind before we ever see it.

use super::serializer::pack_derivation_path;

pub(crate) const ZCASH_CLA: u8 = 0xe0;
pub(crate) const GET_VK: u8 = 0x50;
pub(crate) const GET_VK_FIRST: u8 = 0x00;
pub(crate) const GET_VK_CONTINUE: u8 = 0x80;
pub(crate) const GET_VK_UFVK: u8 = 0x00;
const UFVK_RESPONSE_LIMIT: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApduCommand {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

/// The first GET_VK request (UFVK for ZIP-32 `m/32'/133'/account'` and BIP-44
/// `m/44'/133'/account'`) and the continuation request the host repeats until
/// the declared UFVK length has arrived.
pub(crate) fn ufvk_commands(account_index: u32) -> Result<(ApduCommand, ApduCommand), String> {
    if account_index >= 0x8000_0000 {
        return Err("Ledger account index must be below 2^31".into());
    }

    let account = 0x8000_0000 | account_index;
    let mut request = pack_derivation_path(&[0x8000_0020, 0x8000_0085, account])?;
    request.extend_from_slice(&pack_derivation_path(&[0x8000_002c, 0x8000_0085, account])?);
    Ok((
        ApduCommand {
            cla: ZCASH_CLA,
            ins: GET_VK,
            p1: GET_VK_FIRST,
            p2: GET_VK_UFVK,
            data: request,
        },
        ApduCommand {
            cla: ZCASH_CLA,
            ins: GET_VK,
            p1: GET_VK_CONTINUE,
            p2: GET_VK_UFVK,
            data: Vec::new(),
        },
    ))
}

/// How many UFVK bytes the device still owes after `chunks`. `0` means the
/// declared length has arrived and no further continuation should be sent.
pub(crate) fn ufvk_remaining_bytes(chunks: &[Vec<u8>]) -> Result<usize, String> {
    let first = chunks.first().ok_or("Ledger UFVK response is missing")?;
    if first.len() < 2 {
        return Err("Ledger UFVK response is missing its length prefix".into());
    }
    let expected_len = 2 + u16::from_be_bytes([first[0], first[1]]) as usize;
    if expected_len > UFVK_RESPONSE_LIMIT {
        return Err(format!(
            "Ledger UFVK response declares an unreasonable length: {} bytes",
            expected_len - 2
        ));
    }
    let received: usize = chunks.iter().map(Vec::len).sum();
    Ok(expected_len.saturating_sub(received))
}

/// Reassembles length-prefixed UFVK chunks (status words already stripped).
///
/// Empty trailing chunks after the declared length are tolerated: a host that
/// sends a fixed `[first, continuation]` plan can receive an empty payload for
/// a continuation it did not need. Non-empty trailing data is rejected.
pub(crate) fn decode_ufvk_chunks(chunks: &[Vec<u8>]) -> Result<String, String> {
    let mut response = chunks.first().cloned().unwrap_or_default();
    if response.len() < 2 {
        return Err("Ledger UFVK response is missing its length prefix".into());
    }

    let key_len = u16::from_be_bytes([response[0], response[1]]) as usize;
    let expected_len = 2 + key_len;
    if expected_len > UFVK_RESPONSE_LIMIT {
        return Err(format!(
            "Ledger UFVK response declares an unreasonable length: {key_len} bytes"
        ));
    }

    for chunk in chunks.iter().skip(1) {
        if response.len() >= expected_len {
            if chunk.is_empty() {
                continue;
            }
            return Err("Ledger UFVK response contains trailing chunks".into());
        }
        if chunk.is_empty() {
            return Err("Ledger UFVK response ended before the declared length".into());
        }
        response.extend_from_slice(chunk);
    }
    if response.len() < expected_len {
        return Err("Ledger UFVK response ended before the declared length".into());
    }
    if response.len() != expected_len {
        return Err("Ledger UFVK response contains trailing bytes".into());
    }

    String::from_utf8(response[2..].to_vec())
        .map_err(|_| "Ledger UFVK response is not valid UTF-8".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ufvk_plan_matches_the_zcash_app_protocol() {
        let (first, continuation) = ufvk_commands(7).unwrap();
        assert_eq!(
            (first.cla, first.ins, first.p1, first.p2),
            (0xe0, 0x50, 0, 0)
        );
        assert_eq!(
            first.data,
            hex::decode("03800000208000008580000007038000002c8000008580000007").unwrap()
        );
        assert_eq!(
            (
                continuation.cla,
                continuation.ins,
                continuation.p1,
                continuation.p2
            ),
            (0xe0, 0x50, 0x80, 0)
        );
        assert!(continuation.data.is_empty());
        assert!(ufvk_commands(0x8000_0000).is_err());
    }

    #[test]
    fn ufvk_chunks_are_reassembled() {
        let chunks = vec![vec![0, 5, b'u', b'v'], vec![b'i', b'e', b'w']];
        assert_eq!(decode_ufvk_chunks(&chunks).unwrap(), "uview");
        assert!(decode_ufvk_chunks(&[vec![0, 5, b'u']])
            .unwrap_err()
            .contains("before the declared length"));
        assert!(decode_ufvk_chunks(&[vec![0, 5, b'u'], vec![]])
            .unwrap_err()
            .contains("before the declared length"));
        assert!(decode_ufvk_chunks(&[vec![0]])
            .unwrap_err()
            .contains("length prefix"));
        assert!(decode_ufvk_chunks(&[vec![0, 1, 0xff]])
            .unwrap_err()
            .contains("UTF-8"));
    }

    #[test]
    fn ufvk_trailing_empty_chunks_are_tolerated_but_data_is_not() {
        assert_eq!(
            decode_ufvk_chunks(&[vec![0, 2, b'u', b'v'], vec![]]).unwrap(),
            "uv"
        );
        assert!(decode_ufvk_chunks(&[vec![0, 2, b'u', b'v'], vec![b'x']])
            .unwrap_err()
            .contains("trailing chunks"));
        assert!(decode_ufvk_chunks(&[vec![0, 2, b'u', b'v', b'x']])
            .unwrap_err()
            .contains("trailing bytes"));
    }

    #[test]
    fn ufvk_remaining_bytes_drives_the_continuation_loop() {
        assert_eq!(ufvk_remaining_bytes(&[vec![0, 5, b'u']]).unwrap(), 4);
        assert_eq!(
            ufvk_remaining_bytes(&[vec![0, 5, b'u', b'v'], vec![b'i', b'e', b'w']]).unwrap(),
            0
        );
        assert!(ufvk_remaining_bytes(&[]).is_err());
        assert!(ufvk_remaining_bytes(&[vec![0xff, 0xff]])
            .unwrap_err()
            .contains("unreasonable"));
    }
}

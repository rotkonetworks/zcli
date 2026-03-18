// export wallet notes + merkle paths as ur:zcash-notes animated QR
//
// CBOR format matches zigner's ZcashNotesBundle (transaction_signing/src/zcash.rs):
// map(4) { 1: anchor, 2: height, 3: mainnet, 4: [note_with_path...] }
// where each note is map(6) { 1: value, 2: nullifier, 3: cmx, 4: position, 5: height, 6: path }

use crate::error::Error;
use crate::wallet::WalletNote;
use orchard::tree::{Anchor, MerklePath};

/// Encode notes bundle to CBOR matching zigner's ZcashNotesBundle format
pub fn encode_notes_cbor(
    anchor: &Anchor,
    anchor_height: u32,
    mainnet: bool,
    notes: &[WalletNote],
    paths: &[MerklePath],
) -> Vec<u8> {
    let mut cbor = Vec::new();

    // map(4)
    cbor.push(0xa4);

    // key 1: anchor (bstr 32)
    cbor.push(0x01);
    cbor.push(0x58);
    cbor.push(0x20);
    cbor.extend_from_slice(&anchor.to_bytes());

    // key 2: anchor_height (uint)
    cbor.push(0x02);
    cbor_uint(&mut cbor, anchor_height as u64);

    // key 3: mainnet (bool)
    cbor.push(0x03);
    cbor.push(if mainnet { 0xf5 } else { 0xf4 });

    // key 4: notes array
    cbor.push(0x04);
    cbor_array_len(&mut cbor, notes.len());

    for (note, path) in notes.iter().zip(paths.iter()) {
        // map(6)
        cbor.push(0xa6);

        // 1: value
        cbor.push(0x01);
        cbor_uint(&mut cbor, note.value);

        // 2: nullifier
        cbor.push(0x02);
        cbor.push(0x58);
        cbor.push(0x20);
        cbor.extend_from_slice(&note.nullifier);

        // 3: cmx
        cbor.push(0x03);
        cbor.push(0x58);
        cbor.push(0x20);
        cbor.extend_from_slice(&note.cmx);

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
        let auth = path.auth_path();
        for hash in &auth {
            cbor.push(0x58);
            cbor.push(0x20);
            cbor.extend_from_slice(&hash.to_bytes());
        }
    }

    cbor
}

/// Generate UR-encoded parts for the CBOR payload
pub fn generate_ur_parts(cbor: &[u8], fragment_size: usize) -> Result<Vec<String>, Error> {
    if cbor.len() <= fragment_size {
        let single = ur::ur::encode(cbor, &ur::ur::Type::Custom("zcash-notes"));
        return Ok(vec![single]);
    }

    let mut encoder = ur::Encoder::new(cbor, fragment_size, "zcash-notes")
        .map_err(|e| Error::Other(format!("UR encoder: {}", e)))?;

    let count = encoder.fragment_count();
    let mut parts = Vec::with_capacity(count);
    for _ in 0..count {
        let part = encoder
            .next_part()
            .map_err(|e| Error::Other(format!("UR encode part: {}", e)))?;
        parts.push(part);
    }

    Ok(parts)
}

/// Display animated QR codes in the terminal, cycling through UR frames.
/// Rewrites the QR in-place using ANSI escape codes.
/// Loops until the process is killed (ctrl+c).
pub fn display_animated_qr(
    ur_parts: &[String],
    interval_ms: u64,
    status_line: &str,
) -> Result<(), Error> {
    use qrcode::QrCode;

    let frame_count = ur_parts.len();

    // hide cursor
    print!("\x1b[?25l");

    let mut last_height: usize = 0;
    let mut frame_idx: usize = 0;

    loop {
        let ur_string = &ur_parts[frame_idx % frame_count];

        let code = QrCode::new(ur_string.as_bytes())
            .map_err(|e| Error::Other(format!("qr encode: {}", e)))?;
        let width = code.width();
        let modules = code.into_colors();

        let dark = |r: usize, c: usize| -> bool {
            if r < width && c < width {
                modules[r * width + c] == qrcode::Color::Dark
            } else {
                false
            }
        };

        // move cursor up to overwrite previous frame
        if last_height > 0 {
            print!("\x1b[{}A", last_height);
        }

        let quiet = 1;
        let total = width + quiet * 2;
        let mut lines = 0;
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
            print!("\x1b[K"); // clear rest of line
            println!();
            lines += 1;
        }

        // status line
        print!(
            "\x1b[K[{}/{}] {}",
            (frame_idx % frame_count) + 1,
            frame_count,
            status_line,
        );
        println!();
        lines += 1;
        last_height = lines;

        frame_idx += 1;
        std::thread::sleep(std::time::Duration::from_millis(interval_ms));
    }
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
    } else if len <= 0xffff {
        out.push(0x99);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x9a);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor_uint_encoding() {
        let mut buf = Vec::new();
        cbor_uint(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);

        buf.clear();
        cbor_uint(&mut buf, 23);
        assert_eq!(buf, vec![23]);

        buf.clear();
        cbor_uint(&mut buf, 24);
        assert_eq!(buf, vec![0x18, 24]);

        buf.clear();
        cbor_uint(&mut buf, 1000);
        assert_eq!(buf, vec![0x19, 0x03, 0xe8]);

        buf.clear();
        cbor_uint(&mut buf, 100_000);
        assert_eq!(buf, vec![0x1a, 0x00, 0x01, 0x86, 0xa0]);
    }

    #[test]
    fn test_generate_ur_parts_single() {
        let small_cbor = vec![0xa0]; // empty map
        let parts = generate_ur_parts(&small_cbor, 200).unwrap();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].starts_with("ur:zcash-notes/"));
    }

    #[test]
    fn test_generate_ur_parts_multi() {
        // large enough to need multiple fragments
        let big_cbor = vec![0x42; 500];
        let parts = generate_ur_parts(&big_cbor, 100).unwrap();
        assert!(parts.len() > 1);
        for part in &parts {
            assert!(part.starts_with("ur:zcash-notes/"));
        }
    }
}

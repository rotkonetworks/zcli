// frost_qr.rs — FROST multisig QR display for air-gapped zigner interaction
//
// Generates JSON QR codes that zigner can scan to participate in DKG and signing.
// Uses the same terminal QR rendering as notes_export and airgap.

/// Display a text string as a QR code in the terminal
pub fn display_text_qr(text: &str) {
    use qrcode::QrCode;
    let code = match QrCode::new(text.as_bytes()) {
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

/// Generate DKG init QR JSON for zigner to scan
pub fn dkg_init_qr(n: u16, t: u16, label: &str, mainnet: bool) -> String {
    serde_json::json!({
        "frost": "dkg1",
        "n": n,
        "t": t,
        "label": label,
        "mainnet": mainnet,
    })
    .to_string()
}

/// Generate sign init QR JSON for zigner to scan
pub fn sign_init_qr(wallet_id: &str) -> String {
    serde_json::json!({
        "frost": "sign1",
        "wallet": wallet_id,
    })
    .to_string()
}

/// Generate sign request QR JSON (round 2) for zigner to scan
pub fn sign_request_qr(
    sighash: &str,
    alphas: &[String],
    commitments: &[String],
) -> String {
    serde_json::json!({
        "frost": "sign2",
        "sighash": sighash,
        "alphas": alphas,
        "commitments": commitments,
    })
    .to_string()
}

/// Generate DKG round 2 QR JSON for zigner to scan
pub fn dkg_round2_qr(broadcasts: &[String]) -> String {
    serde_json::json!({
        "frost": "dkg2",
        "broadcasts": broadcasts,
    })
    .to_string()
}

/// Generate DKG round 3 QR JSON for zigner to scan
pub fn dkg_round3_qr(round1: &[String], round2: &[String]) -> String {
    serde_json::json!({
        "frost": "dkg3",
        "round1": round1,
        "round2": round2,
    })
    .to_string()
}

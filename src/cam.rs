// webcam QR scanner via zbarcam

use crate::error::Error;

/// scan a QR code from the webcam via zbarcam
pub fn scan_qr(device: &str, timeout_secs: u64) -> Result<Vec<u8>, Error> {
    use std::process::{Command, Stdio};

    // check zbarcam exists
    let which = Command::new("which")
        .arg("zbarcam")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(which, Ok(ref s) if s.success()) {
        return Err(Error::Other(
            "zbarcam not found — install zbar-tools".into(),
        ));
    }

    eprintln!("scanning with zbarcam ({}s timeout)...", timeout_secs);

    // zbarcam doesn't flush stdout when piped, so use script(1) to force a pty
    // or just run via shell with timeout and capture
    let output = Command::new("timeout")
        .args([
            &format!("{}s", timeout_secs),
            "zbarcam",
            "--nodisplay",
            "--oneshot",
            "--raw",
            "--prescale=1920x1080",
            "-Sdisable",
            "-Sqrcode.enable",
            device,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| Error::Other(format!("spawn zbarcam: {}", e)))?;

    let text = String::from_utf8_lossy(&output.stdout);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(Error::Other("zbarcam: no QR detected".into()));
    }

    let line = trimmed.lines().next().unwrap_or("");
    eprintln!("QR decoded ({} bytes)", line.len());

    // try hex decode first (zigner binary QR data)
    if let Ok(bytes) = hex::decode(line) {
        return Ok(bytes);
    }

    // return raw bytes (e.g. UR strings)
    Ok(line.as_bytes().to_vec())
}

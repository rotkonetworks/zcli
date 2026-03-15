use zeroize::Zeroize;

use crate::error::Error;

/// 64-byte wallet seed derived from ssh key or mnemonic
pub struct WalletSeed {
    bytes: [u8; 64],
}

impl WalletSeed {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self { bytes }
    }
}

impl Drop for WalletSeed {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// load wallet seed from bip39 mnemonic
///
/// derivation: mnemonic.to_seed("") → 64-byte seed (standard bip39)
pub fn load_mnemonic_seed(phrase: &str) -> Result<WalletSeed, Error> {
    let mnemonic = bip39::Mnemonic::parse(phrase)
        .map_err(|e| Error::Key(format!("invalid mnemonic: {}", e)))?;

    let seed = mnemonic.to_seed("");
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&seed);
    Ok(WalletSeed { bytes })
}

/// generate a new 24-word BIP-39 mnemonic
pub fn generate_mnemonic() -> String {
    let mnemonic = bip39::Mnemonic::generate(24).expect("valid word count");
    mnemonic.to_string()
}

/// validate a BIP-39 mnemonic phrase, returns Ok(()) or error
pub fn validate_mnemonic(phrase: &str) -> Result<(), Error> {
    bip39::Mnemonic::parse(phrase).map_err(|e| Error::Key(format!("invalid mnemonic: {}", e)))?;
    Ok(())
}

// -- SSH key functions (not available on wasm) --

#[cfg(feature = "cli")]
use blake2::{Blake2b512, Digest};

/// parse an openssh ed25519 private key, returning (seed_32, pubkey_32)
#[cfg(feature = "cli")]
fn parse_ssh_ed25519(path: &str) -> Result<([u8; 32], [u8; 32]), Error> {
    let key_data = std::fs::read_to_string(path)
        .map_err(|e| Error::Key(format!("cannot read {}: {}", path, e)))?;
    let passphrase = ssh_passphrase(&key_data)?;

    let private_key = if let Some(pw) = &passphrase {
        ssh_key::PrivateKey::from_openssh(&key_data)
            .and_then(|k| k.decrypt(pw))
            .map_err(|e| Error::Key(format!("cannot decrypt ssh key: {}", e)))?
    } else {
        ssh_key::PrivateKey::from_openssh(&key_data)
            .map_err(|e| Error::Key(format!("cannot parse ssh key: {}", e)))?
    };

    let ed25519_keypair = match private_key.key_data() {
        ssh_key::private::KeypairData::Ed25519(kp) => kp,
        ssh_key::private::KeypairData::Encrypted(_) => {
            return Err(Error::Key(
                "key is encrypted — set ZCLI_PASSPHRASE env var or use an unencrypted ed25519 key (-i path)".into(),
            ));
        }
        other => {
            let algo = match other {
                ssh_key::private::KeypairData::Rsa(_) => "RSA",
                ssh_key::private::KeypairData::Ecdsa(_) => "ECDSA",
                ssh_key::private::KeypairData::Dsa(_) => "DSA",
                _ => "unknown",
            };
            return Err(Error::Key(format!(
                "key is {} — zcli requires ed25519 (use -i to specify a different key)",
                algo,
            )));
        }
    };

    let seed_bytes = ed25519_keypair.private.as_ref();
    if seed_bytes.len() < 32 {
        return Err(Error::Key("ed25519 seed too short".into()));
    }

    let pub_bytes = ed25519_keypair.public.as_ref();
    if pub_bytes.len() != 32 {
        return Err(Error::Key("ed25519 pubkey wrong length".into()));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes[..32]);
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(pub_bytes);
    Ok((seed, pubkey))
}

/// load wallet seed from ed25519 ssh private key
///
/// derivation: BLAKE2b-512("ZcliWalletSeed" || ed25519_seed_32bytes)
#[cfg(feature = "cli")]
pub fn load_ssh_seed(path: &str) -> Result<WalletSeed, Error> {
    let (seed32, _) = parse_ssh_ed25519(path)?;

    let mut hasher = Blake2b512::new();
    hasher.update(b"ZcliWalletSeed");
    hasher.update(seed32);
    let hash = hasher.finalize();

    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&hash);
    Ok(WalletSeed { bytes })
}

/// load raw ed25519 keypair from ssh key (for QUIC cert generation)
#[cfg(feature = "cli")]
pub fn load_ssh_ed25519_keypair(path: &str) -> Result<([u8; 32], [u8; 32]), Error> {
    parse_ssh_ed25519(path)
}

/// decrypt a .age file using an ssh identity key, return contents as string
#[cfg(feature = "cli")]
pub fn decrypt_age_file(age_path: &str, identity_path: &str) -> Result<String, Error> {
    let output = std::process::Command::new("age")
        .args(["-d", "-i", identity_path, age_path])
        .output()
        .map_err(|e| Error::Key(format!("age not found: {}", e)))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Key(format!("age decrypt failed: {}", stderr.trim())));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_string())
        .map_err(|e| Error::Key(format!("age output not utf8: {}", e)))
}

/// check if openssh key is encrypted by trying to parse it
#[cfg(feature = "cli")]
fn is_openssh_encrypted(key_data: &str) -> bool {
    match ssh_key::PrivateKey::from_openssh(key_data) {
        Ok(k) => k.is_encrypted(),
        Err(_) => false,
    }
}

/// prompt for ssh key passphrase if needed
#[cfg(feature = "cli")]
fn ssh_passphrase(key_data: &str) -> Result<Option<String>, Error> {
    // check if key is encrypted:
    // - older PEM format: "ENCRYPTED" in header
    // - OpenSSH format: cipher name in binary payload (aes256-ctr, aes256-gcm, etc)
    let is_encrypted = key_data.contains("ENCRYPTED") || is_openssh_encrypted(key_data);
    if !is_encrypted {
        return Ok(None);
    }

    // try env var first (non-interactive)
    if let Ok(pw) = std::env::var("ZCLI_PASSPHRASE") {
        return Ok(Some(pw));
    }

    // if stdin is not a tty, we can't prompt
    if !is_terminal::is_terminal(std::io::stdin()) {
        return Err(Error::Key(
            "encrypted key requires passphrase (set ZCLI_PASSPHRASE or use a terminal)".into(),
        ));
    }

    let pw = rpassword::prompt_password("ssh key passphrase: ")
        .map_err(|e| Error::Key(format!("cannot read passphrase: {}", e)))?;
    Ok(Some(pw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_seed_deterministic() {
        let seed1 = load_mnemonic_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon art",
        )
        .unwrap();
        let seed2 = load_mnemonic_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon art",
        )
        .unwrap();
        assert_eq!(seed1.as_bytes(), seed2.as_bytes());
    }

    #[test]
    fn mnemonic_seed_is_standard_bip39() {
        // mnemonic.to_seed("") should match standard bip39 derivation
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon art";
        let seed = load_mnemonic_seed(phrase).unwrap();
        let mnemonic = bip39::Mnemonic::parse(phrase).unwrap();
        let expected = mnemonic.to_seed("");
        assert_eq!(seed.as_bytes(), &expected);
    }
}

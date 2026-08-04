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

    // Zcash requires 24-word mnemonics (256 bits entropy, ZIP-339)
    let word_count = mnemonic.word_count();
    if word_count != 24 {
        return Err(Error::Key(format!(
            "Zcash requires a 24-word mnemonic, got {} words",
            word_count,
        )));
    }

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

/// load raw ed25519 seed from ssh private key (for FROST identity)
#[cfg(feature = "cli")]
pub fn load_ed25519_seed(path: &str) -> Result<[u8; 32], Error> {
    let (seed, _) = parse_ssh_ed25519(path)?;
    Ok(seed)
}

/// load wallet seed from ed25519 ssh private key — LEGACY derivation.
///
/// derivation: BLAKE2b-512("ZcliWalletSeed" || ed25519_seed_32bytes)
///
/// Kept only for wallets created before the mnemonic-canonical path
/// existed (marker `legacy-ssh`); `zcli init migrate` sweeps funds off it.
/// The seed this produces has no corresponding recovery phrase.
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

/// derive the deterministic 24-word BIP-39 mnemonic backing an ssh-key wallet.
///
/// entropy = BLAKE2b-256("ZcliWalletMnemonic-v1" || ed25519_seed_32bytes)
///
/// This is the pure core — same ed25519 seed always yields the same phrase.
/// The phrase is a full-strength standard mnemonic: it can be imported into
/// any ZIP-339 wallet (or zigner) and recovers the wallet without the ssh key.
pub fn mnemonic_from_ed25519_seed(seed32: &[u8; 32]) -> String {
    use blake2::digest::consts::U32;
    type Blake2b256 = blake2::Blake2b<U32>;
    use blake2::Digest as _;

    let mut hasher = Blake2b256::new();
    hasher.update(b"ZcliWalletMnemonic-v1");
    hasher.update(seed32);
    let entropy: [u8; 32] = hasher.finalize().into();

    bip39::Mnemonic::from_entropy(&entropy)
        .expect("32 bytes of entropy is always a valid 24-word mnemonic")
        .to_string()
}

/// derive the BIP-39 mnemonic backing an ssh-key wallet (see
/// [`mnemonic_from_ed25519_seed`] for the derivation).
#[cfg(feature = "cli")]
pub fn derive_ssh_mnemonic(path: &str) -> Result<String, Error> {
    let (seed32, _) = parse_ssh_ed25519(path)?;
    Ok(mnemonic_from_ed25519_seed(&seed32))
}

/// load wallet seed from an ssh key via the mnemonic-canonical path:
/// ssh ed25519 seed → deterministic 24-word mnemonic → bip39 seed.
///
/// Identical to `load_mnemonic_seed(derive_ssh_mnemonic(path))`, so the
/// wallet is fully recoverable from the phrase alone.
#[cfg(feature = "cli")]
pub fn load_ssh_mnemonic_seed(path: &str) -> Result<WalletSeed, Error> {
    let phrase = derive_ssh_mnemonic(path)?;
    load_mnemonic_seed(&phrase)
}

/// which seed derivation an ssh-key wallet uses
#[cfg(feature = "cli")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshDerivation {
    /// pre-mnemonic wallets: BLAKE2b-512("ZcliWalletSeed" || ed25519_seed)
    Legacy,
    /// mnemonic-canonical: ssh → 24-word phrase → bip39 seed
    MnemonicV1,
}

/// Resolve which derivation to use for an ssh-key wallet, persisting the
/// decision in a marker file so it never silently changes:
/// - marker present → use it
/// - no marker, wallet db already exists → it predates the mnemonic path →
///   `legacy-ssh` (funds stay visible; `zcli init migrate` moves them)
/// - no marker, no wallet db → fresh setup → `mnemonic-v1`
#[cfg(feature = "cli")]
pub fn resolve_ssh_derivation(
    marker_path: &str,
    wallet_db_path: &str,
) -> Result<SshDerivation, Error> {
    if let Ok(contents) = std::fs::read_to_string(marker_path) {
        return match contents.trim() {
            "legacy-ssh" => Ok(SshDerivation::Legacy),
            "mnemonic-v1" => Ok(SshDerivation::MnemonicV1),
            other => Err(Error::Key(format!(
                "unknown seed derivation marker {:?} in {}",
                other, marker_path
            ))),
        };
    }

    let derivation = if std::path::Path::new(wallet_db_path).exists() {
        SshDerivation::Legacy
    } else {
        SshDerivation::MnemonicV1
    };
    write_ssh_derivation(marker_path, derivation)?;
    Ok(derivation)
}

/// persist the ssh-wallet derivation marker
#[cfg(feature = "cli")]
pub fn write_ssh_derivation(marker_path: &str, derivation: SshDerivation) -> Result<(), Error> {
    let value = match derivation {
        SshDerivation::Legacy => "legacy-ssh",
        SshDerivation::MnemonicV1 => "mnemonic-v1",
    };
    if let Some(parent) = std::path::Path::new(marker_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Key(format!("cannot create {}: {}", parent.display(), e)))?;
    }
    std::fs::write(marker_path, value)
        .map_err(|e| Error::Key(format!("cannot write {}: {}", marker_path, e)))
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

    /// same ed25519 seed always yields the same 24-word phrase, different
    /// seeds yield different phrases, and the phrase is a valid mnemonic
    /// accepted by the normal loading path.
    #[test]
    fn ssh_mnemonic_deterministic_and_valid() {
        let a = mnemonic_from_ed25519_seed(&[0x42u8; 32]);
        let b = mnemonic_from_ed25519_seed(&[0x42u8; 32]);
        let c = mnemonic_from_ed25519_seed(&[0x43u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.split_whitespace().count(), 24);
        load_mnemonic_seed(&a).expect("derived phrase must be a valid 24-word mnemonic");
    }

    /// the mnemonic path must NOT collide with the legacy direct derivation —
    /// they are different wallets by design (domain separation).
    #[cfg(feature = "cli")]
    #[test]
    fn ssh_mnemonic_seed_differs_from_legacy() {
        use blake2::Digest as _;
        let ed_seed = [0x42u8; 32];

        // legacy: BLAKE2b-512("ZcliWalletSeed" || seed)
        let mut hasher = Blake2b512::new();
        hasher.update(b"ZcliWalletSeed");
        hasher.update(ed_seed);
        let legacy: [u8; 64] = hasher.finalize().into();

        let mnemonic_seed = load_mnemonic_seed(&mnemonic_from_ed25519_seed(&ed_seed)).unwrap();
        assert_ne!(&legacy, mnemonic_seed.as_bytes());
    }

    /// marker resolution: existing wallet db without a marker resolves to
    /// legacy (and persists that), fresh setup resolves to mnemonic-v1, and
    /// an existing marker always wins.
    #[cfg(feature = "cli")]
    #[test]
    fn ssh_derivation_marker_resolution() {
        let dir = std::env::temp_dir().join(format!("zcli-marker-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("seed_derivation");
        let marker = marker.to_str().unwrap();
        let wallet_db = dir.join("wallet");
        let wallet_db_str = wallet_db.to_str().unwrap();

        // fresh: no wallet db, no marker → mnemonic-v1, marker written
        let d = resolve_ssh_derivation(marker, wallet_db_str).unwrap();
        assert_eq!(d, SshDerivation::MnemonicV1);
        assert_eq!(std::fs::read_to_string(marker).unwrap().trim(), "mnemonic-v1");

        // marker wins even if a wallet db appears later
        std::fs::create_dir_all(&wallet_db).unwrap();
        let d = resolve_ssh_derivation(marker, wallet_db_str).unwrap();
        assert_eq!(d, SshDerivation::MnemonicV1);

        // no marker + existing wallet db → legacy, marker written
        std::fs::remove_file(marker).unwrap();
        let d = resolve_ssh_derivation(marker, wallet_db_str).unwrap();
        assert_eq!(d, SshDerivation::Legacy);
        assert_eq!(std::fs::read_to_string(marker).unwrap().trim(), "legacy-ssh");

        // garbage marker is an error, not a silent fallback
        std::fs::write(marker, "wat").unwrap();
        assert!(resolve_ssh_derivation(marker, wallet_db_str).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! Hot (seed) signing, split from proving.
//!
//! Every hot transaction is built and proven by the same seed-free builders the
//! cold signers use (`build_ironwood_send_pczt`, `build_turnstile_migration_pczt`,
//! `build_unsigned_pczt`, the unsigned shielding builders), in the offscreen
//! prover, from viewing material only. The zcash worker then signs the proven
//! result here with a [`SpendKeys`] it builds from the phrase it has just
//! unsealed, so the phrase never rides the prover relay and the prover holds no
//! spend authority.

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{
    complete_shielding_transaction, extract_signed_tx_from_pczt_bytes, hex_decode, hex_encode,
    transparent_secret_key, OsRng10,
};

/// Sign every orchard and ironwood spend `ask` authorizes in a proven PCZT and
/// extract the broadcast-ready transaction.
///
/// "Sign what is yours": each spend is checked against `fvk` with
/// `verify_nullifier` (a redacted PCZT has no note plaintext, which surfaces as
/// one of the four `Missing*` errors and is tolerated) and then signed; the
/// orchard Signer refuses unless `ask` randomized by the spend's `alpha` equals
/// its `rk`, so dummy and foreign spends are skipped, never signed. At least one
/// spend must accept the key. Extraction then creates the binding signatures and
/// verifies the proofs and every signature against the sighash, so a spend left
/// unsigned (a note of another account) fails here rather than on the network.
pub fn sign_pczt_spends(
    pczt_bytes: &[u8],
    fvk: &orchard::keys::FullViewingKey,
    ask: &orchard::keys::SpendAuthorizingKey,
) -> Result<Vec<u8>, String> {
    use pczt::roles::low_level_signer::{OrchardParseError, Signer};

    let pczt = pczt::Pczt::parse(pczt_bytes).map_err(|e| format!("pczt parse: {e:?}"))?;
    let sighash = pczt::roles::signer::Signer::new(pczt.clone())
        .map_err(|e| format!("signer init: {e:?}"))?
        .shielded_sighash();
    let (has_orchard, has_ironwood) = (
        !pczt.orchard().actions().is_empty(),
        !pczt.ironwood().actions().is_empty(),
    );

    let signed = core::cell::Cell::new(0usize);
    let sign = |bundle: &mut orchard::pczt::Bundle| -> Result<(), OrchardParseError> {
        use orchard::pczt::VerifyError::*;
        for action in bundle.actions_mut().iter_mut() {
            match action.spend().verify_nullifier(Some(fvk)) {
                Ok(()) | Err(MissingRecipient | MissingValue | MissingRho | MissingRandomSeed) => {}
                Err(_) => continue,
            }
            if action.sign(sighash, ask, OsRng10).is_ok() {
                signed.set(signed.get() + 1);
            }
        }
        Ok(())
    };

    let mut low = Signer::new(pczt);
    if has_orchard {
        low = low
            .sign_orchard_with(|_, b, _| sign(b))
            .map_err(|e| format!("orchard spend-auth signing: {e:?}"))?;
    }
    if has_ironwood {
        low = low
            .sign_ironwood_with(|_, b, _| sign(b))
            .map_err(|e| format!("ironwood spend-auth signing: {e:?}"))?;
    }
    if signed.get() == 0 {
        return Err(
            "no spend accepted this account's spend authorizing key: these notes belong \
             to another account"
                .into(),
        );
    }
    extract_signed_tx_from_pczt_bytes(
        &low.finish()
            .serialize()
            .map_err(|e| format!("pczt serialize: {e:?}"))?,
    )
}

/// ECDSA over a 32-byte transparent sighash: DER with a trailing SIGHASH_ALL
/// byte, the `sig_hex` shape `complete_shielding_transaction` takes from zigner.
pub fn sign_transparent_sighash(sk: &secp256k1::SecretKey, sighash: [u8; 32]) -> Vec<u8> {
    let secp = secp256k1::Secp256k1::signing_only();
    let mut sig = secp.sign_ecdsa(&secp256k1::Message::from_digest(sighash), sk);
    sig.normalize_s();
    let mut out = sig.serialize_der().to_vec();
    out.push(0x01);
    out
}

/// The spend authority of one ZIP-32 account, held only inside the zcash worker
/// for the length of one send. Holds the 64-byte BIP39 seed in a zeroizing
/// buffer and derives each key at the moment of use; JS must call `free()` when
/// the send ends so the seed is wiped.
#[wasm_bindgen]
pub struct SpendKeys {
    seed: Zeroizing<[u8; 64]>,
    account: zip32::AccountId,
    mainnet: bool,
}

impl SpendKeys {
    pub fn from_seed_bytes(seed: [u8; 64], account: u32, mainnet: bool) -> Result<Self, String> {
        Ok(Self {
            seed: Zeroizing::new(seed),
            account: zip32::AccountId::try_from(account).map_err(|_| "invalid account index")?,
            mainnet,
        })
    }

    /// The orchard/ironwood FVK and spend authorizing key of the keys the
    /// scanner found the notes with: coin type 133 on every network, as
    /// `WalletKeys` and the transparent branch derive. (The removed in-prover
    /// builders used coin type 1 on testnet, so a testnet hot send never owned
    /// the notes it had scanned.)
    pub fn orchard_keys(
        &self,
    ) -> Result<
        (
            orchard::keys::FullViewingKey,
            orchard::keys::SpendAuthorizingKey,
        ),
        String,
    > {
        let sk = orchard::keys::SpendingKey::from_zip32_seed(&*self.seed, 133, self.account)
            .map_err(|e| format!("spending key derivation failed: {e:?}"))?;
        Ok((
            orchard::keys::FullViewingKey::from(&sk),
            orchard::keys::SpendAuthorizingKey::from(&sk),
        ))
    }

    fn transparent_key(&self, index: u32) -> Result<secp256k1::SecretKey, JsError> {
        transparent_secret_key(&*self.seed, self.account.into(), index)
            .map_err(|e| JsError::new(&e))
    }
}

#[wasm_bindgen]
impl SpendKeys {
    /// Parse the phrase once and keep only its seed. The error never quotes the
    /// phrase.
    #[wasm_bindgen(constructor)]
    pub fn new(seed_phrase: &str, account: u32, mainnet: bool) -> Result<SpendKeys, JsError> {
        let mnemonic = bip39::Mnemonic::parse(seed_phrase)
            .map_err(|_| JsError::new("the recovery phrase could not be read"))?;
        Self::from_seed_bytes(mnemonic.to_seed(""), account, mainnet).map_err(|e| JsError::new(&e))
    }

    /// The account's unified full viewing key: what the prover builds from.
    /// Derived at coin type 133 like every other zafu key; `mainnet` picks
    /// only the encoding.
    pub fn ufvk(&self) -> Result<String, JsError> {
        use zcash_keys::keys::UnifiedSpendingKey;
        use zcash_protocol::consensus::MainNetwork;
        use crate::consensus::TestNetwork;
        let ufvk = UnifiedSpendingKey::from_seed(&MainNetwork, &*self.seed, self.account)
            .map_err(|e| JsError::new(&format!("account key derivation failed: {e:?}")))?
            .to_unified_full_viewing_key();
        Ok(if self.mainnet {
            ufvk.encode(&MainNetwork)
        } else {
            ufvk.encode(&TestNetwork)
        })
    }

    /// The account's default receive address exactly as the scanner derives it
    /// (`WalletKeys::get_receiving_address`): where transparent funds shield to.
    pub fn receiving_address(&self) -> Result<String, JsError> {
        let (fvk, _, _) = crate::derive_orchard_keys(&*self.seed, self.account.into())
            .map_err(|e| JsError::new(&e))?;
        Ok(crate::encode_orchard_address(
            &fvk.to_ivk(orchard::keys::Scope::External).address_at(0u64),
            self.mainnet,
        ))
    }

    /// Sign a proven PCZT from the prover and return the signed tx hex.
    pub fn sign_pczt(&self, pczt_hex: &str) -> Result<String, JsError> {
        let bytes = hex_decode(pczt_hex).ok_or_else(|| JsError::new("invalid pczt hex"))?;
        let (fvk, ask) = self.orchard_keys().map_err(|e| JsError::new(&e))?;
        sign_pczt_spends(&bytes, &fvk, &ask)
            .map(|tx| hex_encode(&tx))
            .map_err(|e| JsError::new(&e))
    }

    /// Compressed pubkey of transparent address `index` (m/44'/133'/account'/0/index).
    pub fn transparent_pubkey(&self, index: u32) -> Result<String, JsError> {
        let sk = self.transparent_key(index)?;
        let secp = secp256k1::Secp256k1::signing_only();
        Ok(hex_encode(&sk.public_key(&secp).serialize()))
    }

    /// Sign an unsigned tx with transparent inputs (a shielding tx as raw V5 or
    /// PCZT, or a t->t PCZT from `build_unsigned_transparent_transaction`) whose
    /// every input is locked to transparent address `index`, and return the
    /// signed tx hex.
    /// `sighashes_json` is the builder's `sighashes` array; the PCZT completion
    /// re-verifies each signature against the carrier's own sighash.
    pub fn sign_shielding(
        &self,
        index: u32,
        unsigned_tx_hex: &str,
        sighashes_json: &str,
    ) -> Result<String, JsError> {
        let sk = self.transparent_key(index)?;
        let secp = secp256k1::Secp256k1::signing_only();
        let pubkey_hex = hex_encode(&sk.public_key(&secp).serialize());
        let sighashes: Vec<String> = serde_json::from_str(sighashes_json)
            .map_err(|e| JsError::new(&format!("invalid sighashes json: {e}")))?;
        let sigs = sighashes
            .iter()
            .map(|h| {
                let digest: [u8; 32] = hex_decode(h)
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| JsError::new("sighash must be 32 bytes of hex"))?;
                Ok(serde_json::json!({
                    "sig_hex": hex_encode(&sign_transparent_sighash(&sk, digest)),
                    "pubkey_hex": pubkey_hex,
                }))
            })
            .collect::<Result<Vec<_>, JsError>>()?;
        complete_shielding_transaction(unsigned_tx_hex, &serde_json::Value::from(sigs).to_string())
    }
}

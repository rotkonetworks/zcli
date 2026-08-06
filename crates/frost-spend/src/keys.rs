// keys.rs — FROST group key → Orchard FullViewingKey → addresses
//
// after DKG, the group verifying key is a RedPallas SpendValidatingKey.
// combined with a random SpendingKey (for nk/rivk derivation), this
// produces a FullViewingKey that can receive funds and scan notes.
// spending requires t-of-n FROST signatures.

use orchard::keys::{FullViewingKey, SpendValidatingKey, SpendingKey};
use rand_core::{CryptoRng, RngCore};

use crate::frost_keys::PublicKeyPackage;

/// derive an Orchard FullViewingKey from the FROST group verifying key.
///
/// the group key becomes the SpendValidatingKey (ak). a random SpendingKey
/// is used to derive nk and rivk (these don't affect spend authorization,
/// only note scanning and address derivation).
///
/// this uses orchard's `from_sk_ak` (unstable-frost feature) which is
/// the ZF's official approach for FROST+Orchard integration.
pub fn derive_fvk(
    rng: &mut (impl RngCore + CryptoRng),
    pubkey_package: &PublicKeyPackage,
) -> Option<FullViewingKey> {
    let ak_bytes = pubkey_package.verifying_key().serialize().ok()?;
    let ak = SpendValidatingKey::from_bytes(&ak_bytes)?;

    // generate a random SpendingKey for nk/rivk derivation.
    // this is safe because nk/rivk don't participate in spend authorization —
    // only ak (the FROST group key) controls spending.
    let sk = loop {
        let mut random_bytes = [0u8; 32];
        rng.fill_bytes(&mut random_bytes);
        if let Some(sk) = SpendingKey::from_bytes(random_bytes).into() {
            break sk;
        }
    };

    frost_fvk(&sk, &ak)
}

/// Build the Orchard FVK for a FROST-controlled address using ONLY orchard's
/// public API.
///
/// `ak` is the FROST group verifying key; `nk`/`rivk` are derived from `sk`.
/// Upstream has no constructor for this shape: the obvious
/// `FullViewingKey::from_sk_ak(sk, ak)` lives only in a fork, and the upstream
/// PR for it (zcash/orchard#475) has been open since 2025-12 under the name
/// `from_sk_ak_incompatible_with_quantum_recoverability_and_will_be_removed`,
/// blocked on <https://zips.z.cash/draft-ecc-quantum-recoverability>.
///
/// So we go through the spec-defined raw encoding instead
/// (Zcash Protocol Spec §5.6.4.4 — `ak ‖ nk ‖ rivk`, 96 bytes): take the FVK
/// that `sk` implies and splice the group `ak` over its first 32 bytes. The
/// result is field-for-field identical to `from_sk_ak(sk, ak)` while needing
/// no fork, no vendored crate, and no patched dependency.
///
/// It is also STRICTER than the fork: `from_bytes` runs orchard's validity
/// check (rejecting an FVK whose ivk is 0 or ⊥), which direct struct
/// construction silently skips.
///
/// CAVEAT (documented, not fixable here): an FVK of this shape is not derivable
/// from a single spending key, so FROST-controlled addresses are NOT quantum-
/// recoverable under the draft ZIP above. That is a property of the
/// construction, not of how we reach it. When upstream lands a real derivation,
/// this function is the single place to change.
fn frost_fvk(sk: &SpendingKey, ak: &SpendValidatingKey) -> Option<FullViewingKey> {
    let mut bytes = FullViewingKey::from(sk).to_bytes();
    bytes[..32].copy_from_slice(&ak.to_bytes());
    FullViewingKey::from_bytes(&bytes)
}

/// derive an Orchard FullViewingKey from a caller-supplied SpendingKey and
/// the FROST group verifying key.
///
/// this is the interactive-DKG counterpart to `derive_fvk`: instead of
/// sampling fresh randomness (which would leave every participant with a
/// different FVK), a single party rolls the SpendingKey and broadcasts its
/// 32 bytes to peers, and every participant reconstructs the same FVK via
/// this function. safety identical to `derive_fvk` — nk/rivk don't
/// participate in spend authorization.
///
/// returns `None` if the supplied `sk_bytes` is outside the Pallas scalar
/// range, or if `pubkey_package`'s verifying key isn't a valid ak. callers
/// that control sk generation should retry with fresh bytes on `None`.
pub fn derive_fvk_from_sk(
    sk_bytes: [u8; 32],
    pubkey_package: &PublicKeyPackage,
) -> Option<FullViewingKey> {
    let ak_bytes = pubkey_package.verifying_key().serialize().ok()?;
    let ak = SpendValidatingKey::from_bytes(&ak_bytes)?;
    let sk: SpendingKey = Option::from(SpendingKey::from_bytes(sk_bytes))?;
    frost_fvk(&sk, &ak)
}

/// extract the SpendValidatingKey (ak) from a FROST key package.
/// this is the participant's view of the group public key.
pub fn group_ak(pubkey_package: &PublicKeyPackage) -> Option<SpendValidatingKey> {
    let ak_bytes = pubkey_package.verifying_key().serialize().ok()?;
    SpendValidatingKey::from_bytes(&ak_bytes)
}

/// derive an Orchard receiving address from the FROST group FVK.
pub fn derive_address(fvk: &FullViewingKey, diversifier_index: u32) -> orchard::Address {
    let diversifier = orchard::keys::Diversifier::from_bytes(
        diversifier_index
            .to_le_bytes()
            .iter()
            .copied()
            .chain(std::iter::repeat(0))
            .take(11)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );
    fvk.address(diversifier, orchard::keys::Scope::External)
}

use orchard::{
    Bundle,
    bundle::Authorized,
    circuit::{OrchardCircuitVersion, VerifyingKey},
};
use rand_core::OsRng;
use zcash_protocol::value::ZatBalance;

pub(super) fn verify_bundle(
    bundle: &Bundle<Authorized, ZatBalance>,
    orchard_vk: Option<&VerifyingKey>,
    circuit_version: OrchardCircuitVersion,
    sighash: [u8; 32],
) -> Result<(), OrchardError> {
    if let Some(vk) = orchard_vk {
        verify_bundle_with_key(bundle, vk, sighash)
    } else {
        let vk = VerifyingKey::build(circuit_version);
        verify_bundle_with_key(bundle, &vk, sighash)
    }
}

fn verify_bundle_with_key(
    bundle: &Bundle<Authorized, ZatBalance>,
    vk: &VerifyingKey,
    sighash: [u8; 32],
) -> Result<(), OrchardError> {
    let mut validator = orchard::bundle::BatchValidator::new(vk);
    validator
        .add_bundle(bundle, sighash)
        .map_err(|_| OrchardError::InvalidProof)?;

    if validator.validate(OsRng) {
        Ok(())
    } else {
        Err(OrchardError::InvalidProof)
    }
}

#[derive(Debug)]
pub enum OrchardError {
    Extract(orchard::pczt::TxExtractorError),
    InvalidProof,
}

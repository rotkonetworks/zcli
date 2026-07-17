use orchard::circuit::ProvingKey;
use rand_core::OsRng;

use crate::Pczt;

impl super::Prover {
    pub fn create_orchard_proof(self, pk: &ProvingKey) -> Result<Self, OrchardError> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood,
        } = self.pczt;

        let bundle_format = crate::orchard_bundle_format(&global);
        let mut bundle = orchard
            .into_parsed_orchard(bundle_format)
            .map_err(OrchardError::Parser)?;

        bundle
            .create_proof(pk, OsRng)
            .map_err(OrchardError::Prover)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard: crate::orchard::Bundle::serialize_from(bundle, bundle_format),
                #[cfg(zcash_unstable = "nu6.3")]
                ironwood,
            },
        })
    }

    /// Creates an Ironwood proof.
    ///
    /// Returns an error before proof creation if the PCZT is not version 6 on NU6.3.
    #[cfg(zcash_unstable = "nu6.3")]
    pub fn create_ironwood_proof(self, pk: &ProvingKey) -> Result<Self, OrchardError> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;

        crate::common::ensure_v6_consensus_branch(&global)
            .map_err(crate::orchard::BundleParseError::from)
            .map_err(OrchardError::Parser)?;

        let mut bundle = ironwood
            .into_parsed_ironwood()
            .map_err(OrchardError::Parser)?;

        bundle
            .create_proof(pk, OsRng)
            .map_err(OrchardError::Prover)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard,
                ironwood: crate::orchard::Bundle::serialize_from(
                    bundle,
                    orchard::bundle::BundleFormat::Nu6_3,
                ),
            },
        })
    }
}

/// Errors that can occur while creating Orchard proofs for a PCZT.
#[derive(Debug)]
pub enum OrchardError {
    Parser(crate::orchard::BundleParseError),
    Prover(orchard::pczt::ProverError),
}

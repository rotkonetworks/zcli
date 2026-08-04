use orchard::pczt::{Updater, UpdaterError};

use crate::Pczt;

impl super::Updater {
    /// Updates the Orchard bundle with information in the given closure.
    pub fn update_orchard_with<F>(self, f: F) -> Result<Self, OrchardError>
    where
        F: FnOnce(Updater<'_>) -> Result<(), UpdaterError>,
    {
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

        bundle.update_with(f).map_err(OrchardError::Updater)?;

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

    /// Updates the Ironwood bundle with information in the given closure.
    ///
    /// Returns an error without invoking the closure if the PCZT is not version 6 on
    /// NU6.3.
    #[cfg(zcash_unstable = "nu6.3")]
    pub fn update_ironwood_with<F>(self, f: F) -> Result<Self, OrchardError>
    where
        F: FnOnce(Updater<'_>) -> Result<(), UpdaterError>,
    {
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

        bundle.update_with(f).map_err(OrchardError::Updater)?;

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

/// Errors that can occur while updating the Orchard bundle of a PCZT.
#[derive(Debug)]
pub enum OrchardError {
    Parser(crate::orchard::BundleParseError),
    Updater(UpdaterError),
}

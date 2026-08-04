use crate::Pczt;

impl super::Verifier {
    /// Parses the Orchard bundle and then verifies it in the given closure.
    pub fn with_orchard<E, F>(self, f: F) -> Result<Self, OrchardError<E>>
    where
        F: FnOnce(&orchard::pczt::Bundle) -> Result<(), OrchardError<E>>,
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
        let bundle = orchard
            .into_parsed_orchard(bundle_format)
            .map_err(OrchardError::Parse)?;

        f(&bundle)?;

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

    /// Parses the Ironwood bundle and then verifies it in the given closure.
    ///
    /// Returns an error without invoking the closure if the PCZT is not version 6 on
    /// NU6.3.
    #[cfg(zcash_unstable = "nu6.3")]
    pub fn with_ironwood<E, F>(self, f: F) -> Result<Self, OrchardError<E>>
    where
        F: FnOnce(&orchard::pczt::Bundle) -> Result<(), OrchardError<E>>,
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
            .map_err(OrchardError::Parse)?;

        let bundle = ironwood
            .into_parsed_ironwood()
            .map_err(OrchardError::Parse)?;

        f(&bundle)?;

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

/// Errors that can occur while verifying the Orchard bundle of a PCZT.
#[derive(Debug)]
pub enum OrchardError<E> {
    Parse(crate::orchard::BundleParseError),
    Verify(orchard::pczt::VerifyError),
    Custom(E),
}

impl<E> From<orchard::pczt::VerifyError> for OrchardError<E> {
    fn from(e: orchard::pczt::VerifyError) -> Self {
        OrchardError::Verify(e)
    }
}

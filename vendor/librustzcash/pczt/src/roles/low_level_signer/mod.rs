//! A low-level variant of the Signer role, for dependency-constrained environments.

use crate::Pczt;

pub struct Signer {
    pczt: Pczt,
}

impl Signer {
    /// Instantiates the low-level Signer role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Exposes the capability to sign the Orchard spends.
    #[cfg(feature = "orchard")]
    pub fn sign_orchard_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<crate::orchard::BundleParseError>,
        F: FnOnce(&Pczt, &mut orchard::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;
        let bundle_format = crate::orchard_bundle_format(&pczt.global);

        let mut bundle = pczt.orchard.clone().into_parsed_orchard(bundle_format)?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.orchard = crate::orchard::Bundle::serialize_from(bundle, bundle_format);

        Ok(Self { pczt })
    }

    /// Exposes the capability to sign the Ironwood spends.
    ///
    /// Returns an error without invoking the closure if the PCZT is not version 6 on
    /// NU6.3.
    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    pub fn sign_ironwood_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<crate::orchard::BundleParseError>,
        F: FnOnce(&Pczt, &mut orchard::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        crate::common::ensure_v6_consensus_branch(&pczt.global)
            .map_err(crate::orchard::BundleParseError::from)?;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let mut bundle = pczt.ironwood.clone().into_parsed_ironwood()?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.ironwood =
            crate::orchard::Bundle::serialize_from(bundle, orchard::bundle::BundleFormat::Nu6_3);

        Ok(Self { pczt })
    }

    /// Exposes the capability to sign the Sapling spends.
    #[cfg(feature = "sapling")]
    pub fn sign_sapling_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<sapling::pczt::ParseError>,
        F: FnOnce(&Pczt, &mut sapling::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let mut bundle = pczt.sapling.clone().into_parsed()?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.sapling = crate::sapling::Bundle::serialize_from(bundle);

        Ok(Self { pczt })
    }

    /// Exposes the capability to sign the transparent spends.
    #[cfg(feature = "transparent")]
    pub fn sign_transparent_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<transparent::pczt::ParseError>,
        F: FnOnce(&Pczt, &mut transparent::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let mut bundle = pczt.transparent.clone().into_parsed()?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.transparent = crate::transparent::Bundle::serialize_from(bundle);

        Ok(Self { pczt })
    }

    /// Finishes the low-level Signer role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}

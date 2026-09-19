//! Test-only RNG adapter.
//!
//! osst's own APIs take rand_core 0.6's `RngCore`, so `rand::rngs::OsRng` is
//! fine for them. Zakura Common 1.0's ff 0.14, however, bounds
//! `Field::random` on rand_core 0.10's `Rng` — a pure-trait crate with no
//! bundled `OsRng`. This zero-sized adapter bridges rand 0.8's `OsRng` to
//! rand_core 0.10's `TryRng`/`TryCryptoRng`, whose blanket impls promote it
//! to `Rng` + `CryptoRng`. Mirrors the `OsRng10` adapters in zecli and
//! zafu-wasm.
//!
//! Only the pallas backend needs it; the ristretto255 tests never reach an
//! ff 0.14 bound.

#[derive(Clone, Copy, Default)]
pub(crate) struct OsRng10;

impl rand_core_10::TryRng for OsRng10 {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(dst);
        Ok(())
    }
}

impl rand_core_10::TryCryptoRng for OsRng10 {}

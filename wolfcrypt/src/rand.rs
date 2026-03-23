use crate::error::{check, len_as_u32, WolfCryptError};
use wolfcrypt_rs::{wc_FreeRng, wc_InitRng, wc_RNG_GenerateBlock, WC_RNG};

/// A wolfCrypt-backed random number generator that implements
/// [`rand_core::TryRng`] and [`rand_core::TryCryptoRng`] with
/// `Error = Infallible`, giving [`rand_core::Rng`] and
/// [`rand_core::CryptoRng`] via blanket impls.
pub struct WolfRng {
    pub(crate) rng: WC_RNG,
}

impl WolfRng {
    /// Create a new `WolfRng`, initialising the underlying wolfCrypt DRBG.
    pub fn new() -> Result<Self, WolfCryptError> {
        let mut rng = WC_RNG::zeroed();
        // SAFETY: `rng` is zero-initialised and `wc_InitRng` will fully
        // initialise it. The pointer is valid for the duration of the call.
        let rc = unsafe { wc_InitRng(&mut rng) };
        check(rc, "wc_InitRng")?;
        Ok(Self { rng })
    }

}

impl Drop for WolfRng {
    fn drop(&mut self) {
        // SAFETY: `self.rng` was successfully initialised by `wc_InitRng`
        // in `new()`. We free it exactly once here.
        unsafe {
            wc_FreeRng(&mut self.rng);
        }
    }
}

// SAFETY: Each `WC_RNG` instance owns its own independent DRBG state with no
// shared mutable globals, so it is safe to move between threads.
unsafe impl Send for WolfRng {}

impl rand_core::TryCryptoRng for WolfRng {}

impl rand_core::TryRng for WolfRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        rand_core::utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        rand_core::utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        // wolfCrypt may have per-call size limits, so chunk large requests.
        // Error = Infallible, so wolfCrypt failures panic (same as the old
        // 0.6 `fill_bytes` behaviour — RNG failure is unrecoverable).
        const CHUNK: usize = 65536; // 64 KB per call
        for chunk in dest.chunks_mut(CHUNK) {
            // SAFETY: `self.rng` is initialised, `chunk` is a valid mutable
            // slice, and we pass its exact length.
            let rc = unsafe {
                wc_RNG_GenerateBlock(&mut self.rng, chunk.as_mut_ptr(), len_as_u32(chunk.len()))
            };
            assert!(rc == 0, "wolfCrypt wc_RNG_GenerateBlock failed: {rc}");
        }
        Ok(())
    }
}

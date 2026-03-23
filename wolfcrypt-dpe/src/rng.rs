//! RNG via wolfcrypt.

use caliptra_dpe_crypto::CryptoError;
use rand_core::Rng;

use crate::error::ERR_RNG_FAILURE;

/// Fill a buffer with cryptographically secure random bytes using a
/// cached RNG instance.
///
/// The RNG is lazily initialized on first use and reused for subsequent
/// calls, avoiding the cost of `wc_InitRng` (DRBG init + OS entropy
/// reseed) on every call.
pub(crate) fn rand_bytes(
    rng: &mut Option<wolfcrypt::WolfRng>,
    dst: &mut [u8],
) -> Result<(), CryptoError> {
    let rng = match rng.as_mut() {
        Some(r) => r,
        None => {
            *rng = Some(
                wolfcrypt::WolfRng::new()
                    .map_err(|_| CryptoError::CryptoLibError(ERR_RNG_FAILURE))?,
            );
            rng.as_mut().unwrap()
        }
    };
    rng.fill_bytes(dst);
    Ok(())
}

//! RNG via wolfcrypt.

use caliptra_dpe_crypto::CryptoError;
use rand_core::Rng;

use crate::error::ERR_RNG_FAILURE;

/// Fill a buffer with cryptographically secure random bytes using a
/// cached RNG instance.
///
/// The RNG is lazily initialized on first use and reused for subsequent
/// calls, avoiding the cost of `wc_InitRng_ex` (DRBG init + entropy
/// reseed) on every call.
///
/// `rng_dev_id` is passed to `wc_InitRng_ex` on first use.  Pass
/// `wolfcrypt_rs::INVALID_DEVID` for the software DRBG path, or a
/// registered CryptoCb device ID (e.g. `wolfcrypt_dpe_hw::HW_DEVICE_ID`)
/// to route every `wc_RNG_GenerateBlock` call through the hardware ITRNG.
pub(crate) fn rand_bytes(
    rng: &mut Option<wolfcrypt::WolfRng>,
    rng_dev_id: i32,
    dst: &mut [u8],
) -> Result<(), CryptoError> {
    let rng = match rng.as_mut() {
        Some(r) => r,
        None => {
            *rng = Some(
                wolfcrypt::WolfRng::new_with_dev_id(rng_dev_id)
                    .map_err(|_| CryptoError::CryptoLibError(ERR_RNG_FAILURE))?,
            );
            rng.as_mut().unwrap()
        }
    };
    rng.fill_bytes(dst);
    Ok(())
}

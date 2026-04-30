//! Error conversion: wolfcrypt errors -> CryptoError.
//!
//! Error code convention for `CryptoError::CryptoLibError(u32)`:
//!
//! | Code        | Meaning                                      |
//! |-------------|----------------------------------------------|
//! | `0x01_0000` | General crypto error (no wolfCrypt detail)    |
//! | `0x03_0000` | Random number generation failure              |
//! | `0x04_0000` | Alias key not set                             |
//! | `0x05_0000` | Invalid public key format                     |
//! | `0x06_0000` | Unsupported curve size                        |
//! | `0x07_0000` | Invalid signature format                      |
//! | `0x01_NNNN` | wolfCrypt FFI error: low 16 bits = `(-code) & 0xFFFF` |
//!
//! When a wolfCrypt FFI call fails, the error code is packed as:
//! `(ERR_GENERAL << 16) | ((-wolfcrypt_code) & 0xFFFF)`.
//! For example, wolfCrypt `BAD_FUNC_ARG` (-170) becomes `0x0100AA`.
//! The high byte identifies the error category, the low 16 bits carry
//! the wolfCrypt-specific code for debugging.

use caliptra_dpe_crypto::CryptoError;

pub(crate) const ERR_GENERAL: u32 = 0x01_0000;
pub(crate) const ERR_RNG_FAILURE: u32 = 0x03_0000;
pub(crate) const ERR_ALIAS_NOT_SET: u32 = 0x04_0000;
pub(crate) const ERR_INVALID_PUBKEY: u32 = 0x05_0000;
pub(crate) const ERR_UNSUPPORTED_CURVE: u32 = 0x06_0000;
pub(crate) const ERR_INVALID_SIGNATURE: u32 = 0x07_0000;

/// Convert a wolfcrypt error to CryptoError, preserving the wolfCrypt
/// error code in the low 16 bits for diagnostics.
pub(crate) fn from_wolfcrypt(e: wolfcrypt::WolfCryptError) -> CryptoError {
    let wc_code = match e {
        wolfcrypt::WolfCryptError::Ffi { code, .. } => ((-code) as u32) & 0xFFFF,
        _ => 0,
    };
    CryptoError::CryptoLibError(ERR_GENERAL | wc_code)
}

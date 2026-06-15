//! AES-EAX authenticated encryption (wolfCrypt native one-shot API).
//!
//! EAX is an AEAD mode built from CMAC and CTR.  wolfCrypt exposes it as a
//! pair of one-shot functions; there is no persistent cipher state.

use crate::error::{check, WolfCryptError};

/// Encrypt and authenticate with AES-EAX.
///
/// - `key`: 16, 24, or 32 bytes (AES-128, AES-192, AES-256).
/// - `nonce`: arbitrary-length nonce.
/// - `aad`: additional authenticated data (may be empty).
/// - `plaintext`: data to encrypt.
/// - `ciphertext`: output buffer, must be at least `plaintext.len()` bytes.
/// - `tag`: output buffer for the authentication tag (typically 16 bytes).
pub fn aes_eax_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8],
) -> Result<(), WolfCryptError> {
    if ciphertext.len() < plaintext.len() {
        return Err(WolfCryptError::InvalidInput);
    }
    if tag.is_empty() {
        return Err(WolfCryptError::InvalidInput);
    }

    // SAFETY: All pointers/lengths derive from valid slices; one-shot stateless call.
    let rc = unsafe {
        wolfcrypt_rs::wc_AesEaxEncryptAuth(
            key.as_ptr(),
            key.len() as u32,
            ciphertext.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len() as u32,
            nonce.as_ptr(),
            nonce.len() as u32,
            tag.as_mut_ptr(),
            tag.len() as u32,
            aad.as_ptr(),
            aad.len() as u32,
        )
    };
    check(rc, "wc_AesEaxEncryptAuth")?;
    Ok(())
}

/// Decrypt and verify with AES-EAX.
///
/// - `key`: 16, 24, or 32 bytes.
/// - `nonce`: the nonce used during encryption.
/// - `aad`: additional authenticated data (must match what was used for encryption).
/// - `ciphertext`: data to decrypt.
/// - `plaintext`: output buffer, must be at least `ciphertext.len()` bytes.
/// - `tag`: the authentication tag to verify.
///
/// Returns `Err` if the tag does not verify (authentication failure).
pub fn aes_eax_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
    tag: &[u8],
) -> Result<(), WolfCryptError> {
    if plaintext.len() < ciphertext.len() {
        return Err(WolfCryptError::InvalidInput);
    }
    if tag.is_empty() {
        return Err(WolfCryptError::InvalidInput);
    }

    // SAFETY: All pointers/lengths derive from valid slices; one-shot stateless call.
    let rc = unsafe {
        wolfcrypt_rs::wc_AesEaxDecryptAuth(
            key.as_ptr(),
            key.len() as u32,
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            nonce.as_ptr(),
            nonce.len() as u32,
            tag.as_ptr(),
            tag.len() as u32,
            aad.as_ptr(),
            aad.len() as u32,
        )
    };
    check(rc, "wc_AesEaxDecryptAuth")?;
    Ok(())
}

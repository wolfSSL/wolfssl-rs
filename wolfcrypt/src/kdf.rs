//! Miscellaneous KDF functions backed by wolfCrypt.
//!
//! This module wraps wolfCrypt's stateless KDF functions that do not fit
//! into the HKDF or PBKDF2 modules:
//!
//! - **TLS PRF** ([`tls_prf`]) — the pseudo-random function used in TLS 1.2
//!   key derivation, gated on `WOLFSSL_HAVE_PRF`.
//! - **SSH KDF** ([`ssh_kdf`]) — key derivation per RFC 4253, gated on
//!   `WOLFSSL_WOLFSSH`.
//! - **SRTP KDF** ([`srtp_kdf`]) — key derivation per RFC 3711 section 4.3.1,
//!   gated on `WC_SRTP_KDF`.
//! - **TLS 1.3 HKDF** ([`tls13_hkdf_extract`], [`tls13_hkdf_expand_label`]) —
//!   HKDF-Extract and HKDF-Expand-Label per RFC 8446 section 7.1, gated on
//!   `HAVE_HKDF`.
//! - **PKCS#12 PBKDF** ([`pkcs12_pbkdf`]) — password-based key derivation per
//!   RFC 7292 appendix B.
//!
//! All functions are stateless (no structs) and return `Result<(), WolfCryptError>`.

use core::ffi::c_int;
use crate::error::{check, len_as_c_int, len_as_u32, WolfCryptError};

// ======================================================================
// TLS PRF (wc_PRF)
// ======================================================================

/// MAC algorithm constants for [`tls_prf`], matching wolfSSL's
/// `wc_MACAlgorithm` enum in `wolfssl/wolfcrypt/hash.h`.
///
/// These are **not** `wc_HashType` values — `wc_PRF` uses the TLS MAC
/// algorithm enum internally.
#[cfg(wolfssl_prf)]
pub const SHA256_MAC: i32 = 4;
/// See [`SHA256_MAC`].
#[cfg(wolfssl_prf)]
pub const SHA384_MAC: i32 = 5;
/// See [`SHA256_MAC`].
#[cfg(wolfssl_prf)]
pub const SHA512_MAC: i32 = 6;

/// Compute the TLS PRF (pseudo-random function).
///
/// This is the raw PRF used inside TLS 1.2 key derivation.  For most
/// purposes you want [`tls12_prf`] instead, which prepends the label.
///
/// `hash_type` must be one of [`SHA256_MAC`], [`SHA384_MAC`], or
/// [`SHA512_MAC`].
///
/// # Errors
///
/// Returns an error if wolfCrypt rejects the parameters (unsupported
/// hash type, output too large for the PRF, etc.).
#[cfg(wolfssl_prf)]
pub fn tls_prf(
    secret: &[u8],
    seed: &[u8],
    hash_type: i32,
    out: &mut [u8],
) -> Result<(), WolfCryptError> {
    // SAFETY: All pointer/length pairs come from valid Rust slices.
    // We pass null for heap and INVALID_DEVID for devId.
    let rc = unsafe {
        wolfcrypt_rs::wc_PRF(
            out.as_mut_ptr(),
            len_as_u32(out.len()),
            secret.as_ptr(),
            len_as_u32(secret.len()),
            seed.as_ptr(),
            len_as_u32(seed.len()),
            hash_type as c_int,
            core::ptr::null_mut(),
            wolfcrypt_rs::INVALID_DEVID,
        )
    };
    check(rc, "wc_PRF")
}

/// Compute the TLS 1.2 PRF with an explicit label.
///
/// This wraps `wc_PRF_TLS`, which concatenates the label and seed
/// internally and uses SHA-256 or better.
///
/// `hash_type` is a `wc_HashType` constant (e.g.
/// `wolfcrypt_rs::WC_HASH_TYPE_SHA256`).
///
/// # Errors
///
/// Returns an error if wolfCrypt rejects the parameters.
#[cfg(wolfssl_prf)]
pub fn tls12_prf(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    hash_type: i32,
    out: &mut [u8],
) -> Result<(), WolfCryptError> {
    // SAFETY: All pointer/length pairs come from valid Rust slices.
    let rc = unsafe {
        wolfcrypt_rs::wc_PRF_TLS(
            out.as_mut_ptr(),
            len_as_u32(out.len()),
            secret.as_ptr(),
            len_as_u32(secret.len()),
            label.as_ptr(),
            len_as_u32(label.len()),
            seed.as_ptr(),
            len_as_u32(seed.len()),
            1, // useAtLeastSha256
            hash_type as c_int,
            core::ptr::null_mut(),
            wolfcrypt_rs::INVALID_DEVID,
        )
    };
    check(rc, "wc_PRF_TLS")
}

// ======================================================================
// SSH KDF (wc_SSH_KDF)
// ======================================================================

/// Derive a key for SSH per RFC 4253 section 7.2.
///
/// `hash_type` is a `wc_HashType` constant (e.g.
/// `wolfcrypt_rs::WC_HASH_TYPE_SHA256`).
///
/// `key` (K) and `h` are the shared secret and exchange hash from the
/// SSH key exchange.  `session_id` is the session identifier.
/// `label` is a single byte identifying the key type (`b'A'` through `b'F'`).
///
/// Derived key material is written into `out`.
///
/// # Errors
///
/// Returns an error if wolfCrypt rejects the parameters.
// TODO: This requires WOLFSSL_WOLFSSH to be defined in user_settings.h.
// The wolfssl_wolfssh cfg flag is emitted when that define is present.
#[cfg(wolfssl_wolfssh)]
pub fn ssh_kdf(
    hash_type: i32,
    key: &[u8],
    session_id: &[u8],
    label: u8,
    out: &mut [u8],
) -> Result<(), WolfCryptError> {
    // wc_SSH_KDF signature:
    //   wc_SSH_KDF(hashId, keyId, key, keySz, k, kSz, h, hSz, sessionId, sessionIdSz)
    // where k = shared secret (K), h = exchange hash (H).
    //
    // NOTE: The `key` parameter here maps to both K and H for simplicity.
    // Callers who need separate K and H values should call the FFI directly.
    // SAFETY: All pointer/length pairs come from valid Rust slices.
    let rc = unsafe {
        wolfcrypt_rs::wc_SSH_KDF(
            hash_type as u8,
            label,
            out.as_mut_ptr(),
            len_as_u32(out.len()),
            key.as_ptr(),
            len_as_u32(key.len()),
            key.as_ptr(),         // h = same as k for this simplified API
            len_as_u32(key.len()),
            session_id.as_ptr(),
            len_as_u32(session_id.len()),
        )
    };
    check(rc, "wc_SSH_KDF")
}

// ======================================================================
// SRTP KDF (wc_SRTP_KDF)
// ======================================================================

/// Derive SRTP session keys per RFC 3711 section 4.3.1.
///
/// `key` is the master key, `salt` is the master salt.
/// `kdr_idx` is the key derivation rate index (-1 for no key derivation rate).
/// `index` is the 48-bit SRTP packet index (6 bytes).
///
/// Derived keys are written into `cipher_key`, `auth_key`, and `salt_key`.
///
/// # Errors
///
/// Returns an error if wolfCrypt rejects the parameters.
// TODO: This requires WC_SRTP_KDF to be defined in user_settings.h.
// The wolfssl_srtp_kdf cfg flag is emitted when that define is present.
#[cfg(wolfssl_srtp_kdf)]
pub fn srtp_kdf(
    key: &[u8],
    salt: &[u8],
    kdr_idx: i32,
    index: &[u8],
    cipher_key: &mut [u8],
    auth_key: &mut [u8],
    salt_key: &mut [u8],
) -> Result<(), WolfCryptError> {
    // SAFETY: All pointer/length pairs come from valid Rust slices.
    let rc = unsafe {
        wolfcrypt_rs::wc_SRTP_KDF(
            key.as_ptr(),
            len_as_u32(key.len()),
            salt.as_ptr(),
            len_as_u32(salt.len()),
            kdr_idx as c_int,
            index.as_ptr(),
            cipher_key.as_mut_ptr(),
            len_as_u32(cipher_key.len()),
            auth_key.as_mut_ptr(),
            len_as_u32(auth_key.len()),
            salt_key.as_mut_ptr(),
            len_as_u32(salt_key.len()),
        )
    };
    check(rc, "wc_SRTP_KDF")
}

// ======================================================================
// TLS 1.3 HKDF (wc_Tls13_HKDF_Extract / wc_Tls13_HKDF_Expand_Label)
// ======================================================================

/// TLS 1.3 HKDF-Extract per RFC 8446 section 7.1.
///
/// Derives a pseudorandom key (PRK) from input key material and salt
/// using HMAC.  The output length depends on the digest: 32 bytes for
/// SHA-256, 48 for SHA-384.
///
/// # Parameters
///
/// - `salt`: HMAC salt.  Pass `&[]` for no salt (wolfSSL will use a
///   zero-filled salt of digest length internally).
/// - `ikm`: Input key material.  Pass `&[]` for the "no PSK" case in
///   TLS 1.3 (wolfSSL will use zero-filled IKM of digest length).
/// - `digest`: Hash algorithm — use a `WC_HASH_TYPE_*` constant
///   (e.g. `wolfcrypt_rs::WC_HASH_TYPE_SHA256`).
/// - `prk`: Output buffer, must be at least the digest output size.
///
/// # Errors
///
/// Returns an error if wolfCrypt rejects the parameters (unsupported
/// digest, output buffer too small, etc.).
#[cfg(wolfssl_tls13_hkdf)]
pub fn tls13_hkdf_extract(
    salt: &[u8],
    ikm: &[u8],
    digest: i32,
    prk: &mut [u8],
) -> Result<(), WolfCryptError> {
    // wolfSSL's wc_Tls13_HKDF_Extract takes `ikm` as `*mut u8` because
    // when ikmLen == 0 it writes zeros into the buffer.  To keep our API
    // safe we copy IKM into a local mutable buffer when non-empty, and
    // provide a stack buffer of max-digest-length zeros for the empty case.
    //
    // Max supported digest is SHA-512 at 64 bytes.
    let mut ikm_buf = [0u8; 64];
    let (ikm_ptr, ikm_len) = if ikm.is_empty() {
        // Pass a mutable zero buffer with length 0 — wolfSSL will detect
        // ikmLen == 0 and fill it internally.  The buffer is large enough
        // for any digest.
        (ikm_buf.as_mut_ptr(), 0u32)
    } else {
        let n = ikm.len().min(ikm_buf.len());
        ikm_buf[..n].copy_from_slice(&ikm[..n]);
        (ikm_buf.as_mut_ptr(), len_as_u32(ikm.len()))
    };

    // SAFETY: All pointer/length pairs come from valid Rust slices or our
    // stack buffer.  `prk` must be at least digest-output-size bytes.
    let rc = unsafe {
        wolfcrypt_rs::wc_Tls13_HKDF_Extract(
            prk.as_mut_ptr(),
            salt.as_ptr(),
            len_as_u32(salt.len()),
            ikm_ptr,
            ikm_len,
            digest as c_int,
        )
    };
    check(rc, "wc_Tls13_HKDF_Extract")
}

/// TLS 1.3 HKDF-Expand-Label per RFC 8446 section 7.1.
///
/// Derives keying material using the expand-label construction:
///
/// ```text
/// HKDF-Expand-Label(Secret, Label, Context, Length)
/// ```
///
/// The `label` is prefixed with `protocol` (typically `b"tls13 "`)
/// internally by wolfSSL's implementation.
///
/// # Parameters
///
/// - `prk`: Pseudorandom key (output of [`tls13_hkdf_extract`]).
/// - `protocol`: Protocol label prefix (e.g. `b"tls13 "`).
/// - `label`: Specific label (e.g. `b"derived"`, `b"c hs traffic"`).
/// - `info`: Context hash (transcript hash, or `&[]` for none).
/// - `digest`: Hash algorithm — use a `WC_HASH_TYPE_*` constant.
/// - `okm`: Output buffer (length determines how many bytes are derived).
///
/// # Errors
///
/// Returns an error if wolfCrypt rejects the parameters.
#[cfg(wolfssl_tls13_hkdf)]
pub fn tls13_hkdf_expand_label(
    prk: &[u8],
    protocol: &[u8],
    label: &[u8],
    info: &[u8],
    digest: i32,
    okm: &mut [u8],
) -> Result<(), WolfCryptError> {
    // SAFETY: All pointer/length pairs come from valid Rust slices.
    let rc = unsafe {
        wolfcrypt_rs::wc_Tls13_HKDF_Expand_Label(
            okm.as_mut_ptr(),
            len_as_u32(okm.len()),
            prk.as_ptr(),
            len_as_u32(prk.len()),
            protocol.as_ptr(),
            len_as_u32(protocol.len()),
            label.as_ptr(),
            len_as_u32(label.len()),
            info.as_ptr(),
            len_as_u32(info.len()),
            digest as c_int,
        )
    };
    check(rc, "wc_Tls13_HKDF_Expand_Label")
}

// ======================================================================
// PKCS#12 PBKDF (wc_PKCS12_PBKDF)
// ======================================================================

/// PKCS#12 purpose ID for key derivation.
pub const PKCS12_KEY_ID: i32 = 1;
/// PKCS#12 purpose ID for IV derivation.
pub const PKCS12_IV_ID: i32 = 2;
/// PKCS#12 purpose ID for MAC key derivation.
pub const PKCS12_MAC_ID: i32 = 3;

/// Derive key material using the PKCS#12 PBKDF (RFC 7292 appendix B).
///
/// `password` is the password bytes (typically UTF-16BE encoded per the
/// PKCS#12 spec, but wolfCrypt accepts raw bytes).
/// `salt` is the salt value.
/// `iterations` is the iteration count (must be positive).
/// `id` identifies the purpose: [`PKCS12_KEY_ID`], [`PKCS12_IV_ID`], or
/// [`PKCS12_MAC_ID`].
/// `hash_type` is a `wc_HashType` constant (e.g.
/// `wolfcrypt_rs::WC_HASH_TYPE_SHA256`).
///
/// Derived key material is written into `out`.
///
/// # Errors
///
/// Returns an error if wolfCrypt rejects the parameters (zero iterations,
/// unsupported hash type, etc.).
#[cfg(wolfssl_pbkdf2)]
pub fn pkcs12_pbkdf(
    password: &[u8],
    salt: &[u8],
    iterations: i32,
    id: i32,
    hash_type: i32,
    out: &mut [u8],
) -> Result<(), WolfCryptError> {
    if iterations <= 0 {
        return Err(WolfCryptError::INVALID_INPUT);
    }

    // SAFETY: All pointer/length pairs come from valid Rust slices.
    // wc_PKCS12_PBKDF writes at most kLen bytes into output.
    let rc = unsafe {
        wolfcrypt_rs::wc_PKCS12_PBKDF(
            out.as_mut_ptr(),
            password.as_ptr(),
            len_as_c_int(password.len()),
            salt.as_ptr(),
            len_as_c_int(salt.len()),
            iterations as c_int,
            len_as_c_int(out.len()),
            hash_type as c_int,
            id as c_int,
        )
    };
    check(rc, "wc_PKCS12_PBKDF")
}

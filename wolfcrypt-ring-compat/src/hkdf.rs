// Copyright 2015 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright wolfSSL Inc.
// SPDX-License-Identifier: MIT

//! HMAC-based Extract-and-Expand Key Derivation Function.
//!
//! HKDF is specified in [RFC 5869].
//!
//! [RFC 5869]: https://tools.ietf.org/html/rfc5869
//!
//! # Example
//! ```
//! use ring::{aead, hkdf, hmac, rand};
//!
//! // Generate a (non-secret) salt value
//! let mut salt_bytes = [0u8; 32];
//! rand::fill(&mut salt_bytes).unwrap();
//!
//! // Extract pseudo-random key from secret keying materials
//! let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_bytes);
//! let pseudo_random_key = salt.extract(b"secret input keying material");
//!
//! // Derive HMAC key
//! let hmac_key_material = pseudo_random_key
//!     .expand(
//!         &[b"hmac contextual info"],
//!         hkdf::HKDF_SHA256.hmac_algorithm(),
//!     )
//!     .unwrap();
//! let hmac_key = hmac::Key::from(hmac_key_material);
//!
//! // Derive UnboundKey for AES-128-GCM
//! let aes_keying_material = pseudo_random_key
//!     .expand(&[b"aes contextual info"], &aead::AES_128_GCM)
//!     .unwrap();
//! let aead_unbound_key = aead::UnboundKey::from(aes_keying_material);
//! ```

use crate::wolfcrypt_rs::{wc_HKDF, wc_HKDF_Expand};
use crate::error::Unspecified;
use crate::fips::indicator_check;
use crate::{digest, hmac};
use alloc::sync::Arc;
use core::fmt;
use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
use crate::prelude::*;

/// An HKDF algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Algorithm(hmac::Algorithm);

impl Algorithm {
    /// The underlying HMAC algorithm.
    #[inline]
    #[must_use]
    pub fn hmac_algorithm(&self) -> hmac::Algorithm {
        self.0
    }
}

/// HKDF using HMAC-SHA-1. Obsolete.
pub const HKDF_SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY);

/// HKDF using HMAC-SHA-256.
pub const HKDF_SHA256: Algorithm = Algorithm(hmac::HMAC_SHA256);

/// HKDF using HMAC-SHA-384.
pub const HKDF_SHA384: Algorithm = Algorithm(hmac::HMAC_SHA384);

/// HKDF using HMAC-SHA-512.
pub const HKDF_SHA512: Algorithm = Algorithm(hmac::HMAC_SHA512);

/// General Info length's for HKDF don't normally exceed 256 bits.
/// We set the default capacity to a value larger than should be needed
/// so that the value passed to |`HKDF_expand`| is only allocated once.
const HKDF_INFO_DEFAULT_CAPACITY_LEN: usize = 80;

/// The maximum output size of a PRK computed by |`HKDF_extract`| is the maximum digest
/// size that can be outputted by wolfSSL.
const MAX_HKDF_PRK_LEN: usize = digest::MAX_OUTPUT_LEN;

impl KeyType for Algorithm {
    fn len(&self) -> usize {
        self.0.digest_algorithm().output_len
    }
}

/// A salt for HKDF operations.
pub struct Salt {
    algorithm: Algorithm,
    bytes: Arc<[u8]>,
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("hkdf::Salt")
            .field("algorithm", &self.algorithm.0)
            .finish()
    }
}

impl Salt {
    /// Constructs a new `Salt` with the given value based on the given digest
    /// algorithm.
    ///
    /// Constructing a `Salt` is relatively expensive so it is good to reuse a
    /// `Salt` object instead of re-constructing `Salt`s with the same value.
    ///
    // # FIPS
    // The following conditions must be met:
    // * Algorithm is one of the following:
    //   * `HKDF_SHA1_FOR_LEGACY_USE_ONLY`
    //   * `HKDF_SHA256`
    //   * `HKDF_SHA384`
    //   * `HKDF_SHA512`
    // * `value.len() > 0` is true
    //
    /// # Panics
    /// `new` panics if salt creation fails
    #[must_use]
    pub fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        Self {
            algorithm,
            bytes: Arc::from(value),
        }
    }

    /// The [HKDF-Extract] operation.
    ///
    /// [HKDF-Extract]: https://tools.ietf.org/html/rfc5869#section-2.2
    ///
    /// # Panics
    /// Panics if the extract operation is unable to be performed
    #[inline]
    #[must_use]
    pub fn extract(&self, secret: &[u8]) -> Prk {
        Prk {
            algorithm: self.algorithm,
            mode: PrkMode::ExtractExpand {
                secret: Arc::new(ZeroizeBoxSlice::from(secret)),
                salt: Arc::clone(&self.bytes),
            },
        }
    }

    /// The algorithm used to derive this salt.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm(self.algorithm.hmac_algorithm())
    }
}

#[cfg(feature = "std")]
impl From<Okm<'_, Algorithm>> for Salt {
    fn from(okm: Okm<'_, Algorithm>) -> Self {
        let algorithm = okm.prk.algorithm;
        let salt_len = okm.len().len();
        let mut salt_bytes = vec![0u8; salt_len];
        okm.fill(&mut salt_bytes).unwrap();
        Self {
            algorithm,
            bytes: Arc::from(salt_bytes.as_slice()),
        }
    }
}

#[cfg(not(feature = "std"))]
impl TryFrom<Okm<'_, Algorithm>> for Salt {
    type Error = Unspecified;

    fn try_from(okm: Okm<'_, Algorithm>) -> Result<Self, Unspecified> {
        let algorithm = okm.prk.algorithm;
        let salt_len = okm.len().len();
        let mut salt_bytes = vec![0u8; salt_len];
        okm.fill(&mut salt_bytes)?;
        Ok(Self {
            algorithm,
            bytes: Arc::from(salt_bytes.as_slice()),
        })
    }
}

/// The length of the OKM (Output Keying Material) for a `Prk::expand()` call.
#[allow(clippy::len_without_is_empty)]
pub trait KeyType {
    /// The length that `Prk::expand()` should expand its input to.
    fn len(&self) -> usize;
}

#[derive(Clone)]
enum PrkMode {
    Expand {
        key_bytes: [u8; MAX_HKDF_PRK_LEN],
        key_len: usize,
    },
    ExtractExpand {
        secret: Arc<ZeroizeBoxSlice<u8>>,
        salt: Arc<[u8]>,
    },
}

impl PrkMode {
    fn fill(&self, algorithm: Algorithm, out: &mut [u8], info: &[u8]) -> Result<(), Unspecified> {
        let hash_type = digest::match_wc_hash_type(&algorithm.0.digest_algorithm().id);

        match &self {
            // SAFETY: pointer and length derived from valid Rust slices.
            PrkMode::Expand { key_bytes, key_len } => unsafe {
                let ret = indicator_check!(wc_HKDF_Expand(
                    hash_type,
                    key_bytes.as_ptr(),
                    *key_len as u32,
                    info.as_ptr(),
                    info.len() as u32,
                    out.as_mut_ptr(),
                    out.len() as u32,
                ));
                if ret != 0 {
                    return Err(Unspecified);
                }
            },
            PrkMode::ExtractExpand { secret, salt } => {
                // SAFETY: pointer and length derived from valid Rust slices.
                let ret = indicator_check!(unsafe {
                    wc_HKDF(
                        hash_type,
                        secret.as_ptr(),
                        secret.len() as u32,
                        salt.as_ptr(),
                        salt.len() as u32,
                        info.as_ptr(),
                        info.len() as u32,
                        out.as_mut_ptr(),
                        out.len() as u32,
                    )
                });
                if ret != 0 {
                    return Err(Unspecified);
                }
            }
        }

        Ok(())
    }
}

impl fmt::Debug for PrkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expand { .. } => f.debug_struct("Expand").finish_non_exhaustive(),
            Self::ExtractExpand { .. } => f.debug_struct("ExtractExpand").finish_non_exhaustive(),
        }
    }
}

struct ZeroizeBoxSlice<T: Zeroize>(Box<[T]>);

impl<T: Zeroize> core::ops::Deref for ZeroizeBoxSlice<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Clone + Zeroize> From<&[T]> for ZeroizeBoxSlice<T> {
    fn from(value: &[T]) -> Self {
        Self(Vec::from(value).into_boxed_slice())
    }
}

impl<T: Zeroize> Drop for ZeroizeBoxSlice<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A HKDF PRK (pseudorandom key).
#[derive(Clone)]
pub struct Prk {
    algorithm: Algorithm,
    mode: PrkMode,
}

impl Drop for Prk {
    fn drop(&mut self) {
        if let PrkMode::Expand {
            ref mut key_bytes, ..
        } = self.mode
        {
            key_bytes.zeroize();
        }
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for Prk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("hkdf::Prk")
            .field("algorithm", &self.algorithm.0)
            .field("mode", &self.mode)
            .finish()
    }
}

impl Prk {
    /// Construct a new `Prk` directly with the given value.
    ///
    /// Usually one can avoid using this. It is useful when the application
    /// intentionally wants to leak the PRK secret, e.g. to implement
    /// `SSLKEYLOGFILE` functionality.
    ///
    // # FIPS
    // The following conditions must be met:
    // * Algorithm is one of the following:
    //   * `HKDF_SHA1_FOR_LEGACY_USE_ONLY`
    //   * `HKDF_SHA256`
    //   * `HKDF_SHA384`
    //   * `HKDF_SHA512`
    // * The `info_len` from [`Prk::expand`] is non-zero.
    //
    /// # Panics
    /// Panics if the given Prk length exceeds the limit
    #[must_use]
    pub fn new_less_safe(algorithm: Algorithm, value: &[u8]) -> Self {
        // PANIC-SAFETY: Documented panic; use try_new_less_safe for fallible variant
        Prk::try_new_less_safe(algorithm, value).expect("Prk length limit exceeded.")
    }

    fn try_new_less_safe(algorithm: Algorithm, value: &[u8]) -> Result<Prk, Unspecified> {
        let key_len = value.len();
        if key_len > MAX_HKDF_PRK_LEN {
            return Err(Unspecified);
        }
        let mut key_bytes = [0u8; MAX_HKDF_PRK_LEN];
        key_bytes[0..key_len].copy_from_slice(value);
        Ok(Self {
            algorithm,
            mode: PrkMode::Expand { key_bytes, key_len },
        })
    }

    /// The [HKDF-Expand] operation.
    ///
    /// [HKDF-Expand]: https://tools.ietf.org/html/rfc5869#section-2.3
    ///
    /// # Errors
    /// Returns `error::Unspecified` if:
    ///   * `len` is more than 255 times the digest algorithm's output length.
    // # FIPS
    // The following conditions must be met:
    // * `Prk` must be constructed using `Salt::extract` prior to calling
    // this method.
    // * After concatination of the `info` slices the resulting `[u8].len() > 0` is true.
    #[inline]
    pub fn expand<'a, L: KeyType>(
        &'a self,
        info: &'a [&'a [u8]],
        len: L,
    ) -> Result<Okm<'a, L>, Unspecified> {
        let len_cached = len.len();
        if len_cached > 255 * self.algorithm.0.digest_algorithm().output_len {
            return Err(Unspecified);
        }
        Ok(Okm {
            prk: self,
            info,
            len,
        })
    }
}

#[cfg(feature = "std")]
impl From<Okm<'_, Algorithm>> for Prk {
    fn from(okm: Okm<Algorithm>) -> Self {
        let algorithm = okm.len;
        let key_len = okm.len.len();
        let mut key_bytes = [0u8; MAX_HKDF_PRK_LEN];
        okm.fill(&mut key_bytes[0..key_len]).unwrap();

        Self {
            algorithm,
            mode: PrkMode::Expand { key_bytes, key_len },
        }
    }
}

#[cfg(not(feature = "std"))]
impl TryFrom<Okm<'_, Algorithm>> for Prk {
    type Error = Unspecified;

    fn try_from(okm: Okm<Algorithm>) -> Result<Self, Unspecified> {
        let algorithm = okm.len;
        let key_len = okm.len.len();
        let mut key_bytes = [0u8; MAX_HKDF_PRK_LEN];
        okm.fill(&mut key_bytes[0..key_len])?;

        Ok(Self {
            algorithm,
            mode: PrkMode::Expand { key_bytes, key_len },
        })
    }
}

/// An HKDF OKM (Output Keying Material)
///
/// Intentionally not `Clone` or `Copy` as an OKM is generally only safe to
/// use once.
pub struct Okm<'a, L: KeyType> {
    prk: &'a Prk,
    info: &'a [&'a [u8]],
    len: L,
}

impl<L: KeyType> fmt::Debug for Okm<'_, L> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("hkdf::Okm").field("prk", &self.prk).finish()
    }
}

/// Concatenates info slices into a contiguous buffer for HKDF operations.
/// Uses stack allocation for typical cases, heap allocation for large info.
/// Info is public context data per RFC 5869, so no zeroization is needed.
#[inline]
fn concatenate_info<F, R>(info: &[&[u8]], f: F) -> R
where
    F: FnOnce(&[u8]) -> R,
{
    let info_len: usize = info.iter().map(|s| s.len()).sum();

    // Info is public; no need to zeroize.
    if info_len <= HKDF_INFO_DEFAULT_CAPACITY_LEN {
        // Use stack buffer for typical case (avoids heap allocation)
        let mut stack_buf = [0u8; HKDF_INFO_DEFAULT_CAPACITY_LEN];
        let mut pos = 0;
        for &slice in info {
            stack_buf[pos..pos + slice.len()].copy_from_slice(slice);
            pos += slice.len();
        }

        f(&stack_buf[..info_len])
    } else {
        // Heap allocation for rare large info case
        let mut heap_buf = Vec::with_capacity(info_len);
        for &slice in info {
            heap_buf.extend_from_slice(slice);
        }

        f(&heap_buf)
    }
}

impl<L: KeyType> Okm<'_, L> {
    /// The `OkmLength` given to `Prk::expand()`.
    #[inline]
    pub fn len(&self) -> &L {
        &self.len
    }

    /// Fills `out` with the output of the HKDF-Expand operation for the given
    /// inputs.
    ///
    // # FIPS
    // The following conditions must be met:
    // * Algorithm is one of the following:
    //    * `HKDF_SHA1_FOR_LEGACY_USE_ONLY`
    //    * `HKDF_SHA256`
    //    * `HKDF_SHA384`
    //    * `HKDF_SHA512`
    // * The [`Okm`] was constructed from a [`Prk`] created with [`Salt::extract`] and:
    //    * The `value.len()` passed to [`Salt::new`] was non-zero.
    //    * The `info_len` from [`Prk::expand`] was non-zero.
    //
    /// # Errors
    /// `error::Unspecified` if the requested output length differs from the length specified by
    /// `L: KeyType`.
    #[inline]
    pub fn fill(self, out: &mut [u8]) -> Result<(), Unspecified> {
        if out.len() != self.len.len() {
            return Err(Unspecified);
        }

        concatenate_info(self.info, |info_bytes| {
            self.prk.mode.fill(self.prk.algorithm, out, info_bytes)
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::hkdf::{Salt, HKDF_SHA256, HKDF_SHA384};

    #[cfg(feature = "fips")]
    mod fips;

    #[test]
    fn hkdf_coverage() {
        // Something would have gone horribly wrong for this to not pass, but we test this so our
        // coverage reports will look better.
        assert_ne!(HKDF_SHA256, HKDF_SHA384);
        assert_eq!("Algorithm(Algorithm(SHA256))", format!("{HKDF_SHA256:?}"));
    }

    #[test]
    fn test_debug() {
        const SALT: &[u8; 32] = &[
            29, 113, 120, 243, 11, 202, 39, 222, 206, 81, 163, 184, 122, 153, 52, 192, 98, 195,
            240, 32, 34, 19, 160, 128, 178, 111, 97, 232, 113, 101, 221, 143,
        ];
        const SECRET1: &[u8; 32] = &[
            157, 191, 36, 107, 110, 131, 193, 6, 175, 226, 193, 3, 168, 133, 165, 181, 65, 120,
            194, 152, 31, 92, 37, 191, 73, 222, 41, 112, 207, 236, 196, 174,
        ];

        const INFO1: &[&[u8]] = &[
            &[
                2, 130, 61, 83, 192, 248, 63, 60, 211, 73, 169, 66, 101, 160, 196, 212, 250, 113,
            ],
            &[
                80, 46, 248, 123, 78, 204, 171, 178, 67, 204, 96, 27, 131, 24,
            ],
        ];

        let alg = HKDF_SHA256;
        let salt = Salt::new(alg, SALT);
        let prk = salt.extract(SECRET1);
        let okm = prk.expand(INFO1, alg).unwrap();

        assert_eq!(
            "hkdf::Salt { algorithm: Algorithm(SHA256) }",
            format!("{salt:?}")
        );
        assert_eq!(
            "hkdf::Prk { algorithm: Algorithm(SHA256), mode: ExtractExpand { .. } }",
            format!("{prk:?}")
        );
        assert_eq!(
            "hkdf::Okm { prk: hkdf::Prk { algorithm: Algorithm(SHA256), mode: ExtractExpand { .. } } }",
            format!("{okm:?}")
        );
    }

    // --- RFC 5869 Known Answer Tests ---
    // These validate the HKDF primitive against the official test vectors.

    #[test]
    fn hkdf_sha256_rfc5869_test_case_1() {
        // RFC 5869 Appendix A, Test Case 1
        // IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
        // salt = 0x000102030405060708090a0b0c (13 octets)
        // info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
        // L    = 42
        use super::{KeyType, Salt, HKDF_SHA256};

        let ikm: [u8; 22] = [0x0b; 22];
        let salt_bytes: [u8; 13] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                     0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let info_bytes: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                                     0xf8, 0xf9];
        let expected_okm: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
            0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
            0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
            0x58, 0x65,
        ];

        let salt = Salt::new(HKDF_SHA256, &salt_bytes);
        let prk = salt.extract(&ikm);

        struct Len42;
        impl KeyType for Len42 { fn len(&self) -> usize { 42 } }

        let info_slices: &[&[u8]] = &[&info_bytes];
        let okm = prk.expand(info_slices, Len42).unwrap();
        let mut output = [0u8; 42];
        okm.fill(&mut output).unwrap();

        assert_eq!(&output[..], &expected_okm[..]);
    }

    #[test]
    fn hkdf_sha256_rfc5869_test_case_2() {
        // RFC 5869 Appendix A, Test Case 2
        // IKM  = 0x000102...4f (80 octets)
        // salt = 0x606162...af (80 octets)
        // info = 0xb0b1b2...ff (80 octets)
        // L    = 82
        use super::{KeyType, Salt, HKDF_SHA256};

        let ikm: Vec<u8> = (0x00u8..=0x4f).collect();
        let salt_bytes: Vec<u8> = (0x60u8..=0xaf).collect();
        let info_bytes: Vec<u8> = (0xb0u8..=0xff).collect();
        let expected_okm: [u8; 82] = [
            0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
            0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
            0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
            0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
            0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
            0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
            0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
            0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
            0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
            0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
            0x1d, 0x87,
        ];

        let salt = Salt::new(HKDF_SHA256, &salt_bytes);
        let prk = salt.extract(&ikm);

        struct Len82;
        impl KeyType for Len82 { fn len(&self) -> usize { 82 } }

        let info_arr = [info_bytes.as_slice()];
        let okm = prk.expand(&info_arr, Len82).unwrap();
        let mut output = [0u8; 82];
        okm.fill(&mut output).unwrap();

        assert_eq!(&output[..], &expected_okm[..]);
    }

    #[test]
    fn hkdf_sha256_rfc5869_test_case_3() {
        // RFC 5869 Appendix A, Test Case 3
        // IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
        // salt = "" (empty)
        // info = "" (empty)
        // L    = 42
        use super::{KeyType, Salt, HKDF_SHA256};

        let ikm: [u8; 22] = [0x0b; 22];
        let expected_okm: [u8; 42] = [
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
            0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
            0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
            0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
            0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
            0x96, 0xc8,
        ];

        // Empty salt: HKDF spec says to use a string of HashLen zeros
        let salt = Salt::new(HKDF_SHA256, &[0u8; 32]);
        let prk = salt.extract(&ikm);

        struct Len42;
        impl KeyType for Len42 { fn len(&self) -> usize { 42 } }

        let okm = prk.expand(&[b""], Len42).unwrap();
        let mut output = [0u8; 42];
        okm.fill(&mut output).unwrap();

        assert_eq!(&output[..], &expected_okm[..]);
    }

    #[test]
    fn test_long_salt() {
        // Test with a salt longer than the previous 80-byte limit
        let long_salt = vec![0x42u8; 100];

        // This should work now that we removed the MAX_HKDF_SALT_LEN restriction
        let salt = Salt::new(HKDF_SHA256, &long_salt);

        // Test the extract operation still works
        let secret = b"test secret key material";
        let prk = salt.extract(secret);

        // Test expand operation
        let info_data = b"test context info";
        let info = [info_data.as_slice()];
        let okm = prk.expand(&info, HKDF_SHA256).unwrap();

        // Fill output buffer
        let mut output = [0u8; 32];
        okm.fill(&mut output).unwrap();

        // Test with an even longer salt to demonstrate flexibility
        let very_long_salt = vec![0x55u8; 500];
        let very_long_salt_obj = Salt::new(HKDF_SHA256, &very_long_salt);
        let prk2 = very_long_salt_obj.extract(secret);
        let okm2 = prk2.expand(&info, HKDF_SHA256).unwrap();
        let mut output2 = [0u8; 32];
        okm2.fill(&mut output2).unwrap();

        // Verify outputs are different (they should be due to different salts)
        assert_ne!(output, output2);
    }
}

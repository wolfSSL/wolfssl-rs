//! RSA signing/verification and encryption/decryption backed by wolfCrypt.
//!
//! Provides [`RsaPrivateKey`] and [`RsaPublicKey`] that implement the
//! RustCrypto [`signature::Signer`] and [`signature::Verifier`] traits for
//! both PKCS#1v1.5 ([`RsaPkcs1v15Signature`]) and PSS ([`RsaPssSignature`])
//! schemes. The trait impls default to SHA-256; the `_with_digest` methods
//! accept an [`RsaDigest`] to select SHA-256, SHA-384, or SHA-512.
//!
//! The same key types also provide RSA encryption (OAEP and PKCS#1v1.5
//! padding) because RSA uses the same keypair for both operations:
//! the private key signs and decrypts, the public key verifies and encrypts.
//!
//! Key generation, signing, and verification use native wolfCrypt `wc_*` shims
//! via the `wolfcrypt_rsa_*` C helpers in `wolfcrypt-rs/src/compat_shim.c`.
//! No OpenSSL-compat EVP layer is required.
//!
//! # Example
//!
//! ```ignore
//! use wolfcrypt::rsa::{RsaPrivateKey, RsaPkcs1v15Signature};
//! use signature_trait::{Signer, Verifier};
//!
//! let sk = RsaPrivateKey::generate(2048).unwrap();
//! let pk = sk.public_key();
//! let sig: RsaPkcs1v15Signature = sk.sign(b"hello world");
//! pk.verify(b"hello world", &sig).unwrap();
//! ```

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::{len_as_u32, WolfCryptError};
#[cfg(feature = "rsa-direct")]
use crate::error::check;
use wolfcrypt_rs::{
    wolfcrypt_rsa_export_private_pkcs1, wolfcrypt_rsa_export_public_spki, wolfcrypt_rsa_free,
    wolfcrypt_rsa_generate, wolfcrypt_rsa_import_private_pkcs1, wolfcrypt_rsa_import_public_spki,
    wolfcrypt_rsa_key_size_bytes, wolfcrypt_rsa_new, wolfcrypt_rsa_oaep_decrypt_sha256,
    wolfcrypt_rsa_oaep_encrypt_sha256, wolfcrypt_rsa_pkcs1v15_decrypt,
    wolfcrypt_rsa_pkcs1v15_encrypt, wolfcrypt_rsa_pkcs1v15_sign, wolfcrypt_rsa_pkcs1v15_verify,
    wolfcrypt_rsa_pss_sign, wolfcrypt_rsa_pss_verify,
};

// ---------------------------------------------------------------------------
// Signature types
// ---------------------------------------------------------------------------

/// Minimum RSA signature length in bytes. Corresponds to a 512-bit modulus,
/// which is the smallest wolfSSL can be configured to support (`RSA_MIN_SIZE`).
/// Any signature shorter than this is not a valid RSA signature.
const RSA_MIN_SIG_BYTES: usize = 64;

/// An RSA PKCS#1v1.5 signature (RFC 8017 Section 8.2).
///
/// Variable-length: the size equals the RSA modulus size in bytes (e.g. 256
/// bytes for a 2048-bit key).
#[derive(Clone, Debug)]
pub struct RsaPkcs1v15Signature(Vec<u8>);

impl AsRef<[u8]> for RsaPkcs1v15Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl signature_trait::SignatureEncoding for RsaPkcs1v15Signature {
    type Repr = Box<[u8]>;
}

impl TryFrom<&[u8]> for RsaPkcs1v15Signature {
    type Error = signature_trait::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < RSA_MIN_SIG_BYTES {
            return Err(signature_trait::Error::new());
        }
        Ok(Self(bytes.to_vec()))
    }
}

impl From<RsaPkcs1v15Signature> for Box<[u8]> {
    fn from(sig: RsaPkcs1v15Signature) -> Box<[u8]> {
        sig.0.into_boxed_slice()
    }
}

/// An RSA-PSS signature (RFC 8017 Section 8.1).
///
/// Variable-length: the size equals the RSA modulus size in bytes.
#[derive(Clone, Debug)]
pub struct RsaPssSignature(Vec<u8>);

impl AsRef<[u8]> for RsaPssSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl signature_trait::SignatureEncoding for RsaPssSignature {
    type Repr = Box<[u8]>;
}

impl TryFrom<&[u8]> for RsaPssSignature {
    type Error = signature_trait::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < RSA_MIN_SIG_BYTES {
            return Err(signature_trait::Error::new());
        }
        Ok(Self(bytes.to_vec()))
    }
}

impl From<RsaPssSignature> for Box<[u8]> {
    fn from(sig: RsaPssSignature) -> Box<[u8]> {
        sig.0.into_boxed_slice()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Hash algorithm used for RSA signing/verification.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaDigest {
    /// SHA-1 (20-byte digest). Required for legacy SSH `ssh-rsa` signatures.
    Sha1,
    /// SHA-256 (32-byte digest).
    Sha256,
    /// SHA-384 (48-byte digest).
    Sha384,
    /// SHA-512 (64-byte digest).
    Sha512,
}

impl RsaDigest {
    /// Return the hash bit-width code used by the native wolfCrypt shims.
    ///
    /// SHA-1 → 160, SHA-256 → 256, SHA-384 → 384, SHA-512 → 512.
    /// The C helper `wolfcrypt_rsa_hash_wc_type(hash_bits)` maps these to
    /// the appropriate `wc_HashType` enum value.
    fn hash_bits(self) -> i32 {
        match self {
            Self::Sha1 => 160,
            Self::Sha256 => 256,
            Self::Sha384 => 384,
            Self::Sha512 => 512,
        }
    }
}

// ---------------------------------------------------------------------------
// Native OAEP helpers (wc_RsaPublicEncrypt_ex / wc_RsaPrivateDecrypt_ex)
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` using OAEP SHA-256 / MGF1-SHA256.
///
/// `ctx` must be a valid, non-null `wolfcrypt_rsa_ctx *` holding a public
/// key (or a private key, which contains both components).
unsafe fn native_oaep_encrypt_sha256(
    ctx: *mut c_void,
    plaintext: &[u8],
) -> Result<Vec<u8>, WolfCryptError> {
    // SAFETY: ctx is a valid wolfcrypt_rsa_ctx pointer; plaintext slice provides valid pointer and length
    unsafe {
        let key_size = wolfcrypt_rsa_key_size_bytes(ctx as *const _);
        if key_size <= 0 {
            return Err(WolfCryptError::Ffi {
                code: key_size,
                func: "wolfcrypt_rsa_key_size_bytes",
            });
        }
        let mut out = vec![0u8; key_size as usize];
        let rc = wolfcrypt_rsa_oaep_encrypt_sha256(
            ctx,
            plaintext.as_ptr(),
            len_as_u32(plaintext.len()),
            out.as_mut_ptr(),
            key_size as u32,
        );
        if rc <= 0 {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wolfcrypt_rsa_oaep_encrypt_sha256",
            });
        }
        out.truncate(rc as usize);
        Ok(out)
    }
}

/// Decrypt `ciphertext` using OAEP SHA-256 / MGF1-SHA256.
///
/// `ctx` must be a valid, non-null `wolfcrypt_rsa_ctx *` holding a private key.
unsafe fn native_oaep_decrypt_sha256(
    ctx: *mut c_void,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WolfCryptError> {
    // SAFETY: ctx is a valid wolfcrypt_rsa_ctx pointer holding a private key; output buffer is properly sized
    unsafe {
        let key_size = wolfcrypt_rsa_key_size_bytes(ctx as *const _);
        if key_size <= 0 {
            return Err(WolfCryptError::Ffi {
                code: key_size,
                func: "wolfcrypt_rsa_key_size_bytes",
            });
        }
        let mut out = vec![0u8; key_size as usize];
        let rc = wolfcrypt_rsa_oaep_decrypt_sha256(
            ctx,
            ciphertext.as_ptr(),
            len_as_u32(ciphertext.len()),
            out.as_mut_ptr(),
            key_size as u32,
        );
        if rc <= 0 {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wolfcrypt_rsa_oaep_decrypt_sha256",
            });
        }
        out.truncate(rc as usize);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Native PKCS#1v1.5 helpers (wc_RsaSSL_Sign / wc_RsaSSL_VerifyInline)
// ---------------------------------------------------------------------------

/// Sign `msg` using RSA-PKCS#1v1.5 with the given hash via the native shim.
///
/// `ctx` must be a valid, non-null `wolfcrypt_rsa_ctx *` holding a private key.
/// `hash_bits` must be 160, 256, 384, or 512.
/// Returns the raw signature bytes (length == key modulus size).
unsafe fn native_pkcs1v15_sign(
    ctx: *mut c_void,
    msg: &[u8],
    hash_bits: i32,
) -> Result<Vec<u8>, WolfCryptError> {
    // SAFETY: ctx is a valid wolfcrypt_rsa_ctx pointer holding a private key; sig buffer is key-size bytes
    unsafe {
        let key_size = wolfcrypt_rsa_key_size_bytes(ctx as *const _);
        if key_size <= 0 {
            return Err(WolfCryptError::Ffi {
                code: key_size,
                func: "wolfcrypt_rsa_key_size_bytes",
            });
        }
        let mut sig = vec![0u8; key_size as usize];
        let mut sig_len = key_size as u32;
        let rc = wolfcrypt_rsa_pkcs1v15_sign(
            ctx,
            hash_bits,
            msg.as_ptr(),
            len_as_u32(msg.len()),
            sig.as_mut_ptr(),
            &mut sig_len,
        );
        if rc != 0 {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wolfcrypt_rsa_pkcs1v15_sign",
            });
        }
        sig.truncate(sig_len as usize);
        Ok(sig)
    }
}

/// Verify an RSA-PKCS#1v1.5 signature using the native shim.
///
/// `ctx` must be a valid, non-null `wolfcrypt_rsa_ctx *`.
/// `hash_bits` must be 160, 256, 384, or 512.
/// Returns `Ok(())` if valid, `Err` if invalid or on error.
unsafe fn native_pkcs1v15_verify(
    ctx: *mut c_void,
    msg: &[u8],
    sig: &[u8],
    hash_bits: i32,
) -> Result<(), WolfCryptError> {
    // SAFETY: ctx is a valid wolfcrypt_rsa_ctx pointer; msg and sig slices provide valid pointers and lengths
    unsafe {
        let rc = wolfcrypt_rsa_pkcs1v15_verify(
            ctx,
            hash_bits,
            msg.as_ptr(),
            len_as_u32(msg.len()),
            sig.as_ptr(),
            len_as_u32(sig.len()),
        );
        if rc != 0 {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wolfcrypt_rsa_pkcs1v15_verify",
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Native PSS helpers (wc_RsaPSS_Sign_ex / wc_RsaPSS_VerifyCheck)
// ---------------------------------------------------------------------------

/// Sign `msg` using RSA-PSS with the given hash via the native shim.
///
/// `ctx` must be a valid, non-null `wolfcrypt_rsa_ctx *` holding a private key.
/// `hash_bits` must be 256, 384, or 512 (SHA-1 PSS is not supported).
/// Salt length equals the hash length. PSS is randomised.
unsafe fn native_pss_sign(
    ctx: *mut c_void,
    msg: &[u8],
    hash_bits: i32,
) -> Result<Vec<u8>, WolfCryptError> {
    // SAFETY: ctx is a valid wolfcrypt_rsa_ctx pointer holding a private key; sig buffer is key-size bytes
    unsafe {
        let key_size = wolfcrypt_rsa_key_size_bytes(ctx as *const _);
        if key_size <= 0 {
            return Err(WolfCryptError::Ffi {
                code: key_size,
                func: "wolfcrypt_rsa_key_size_bytes",
            });
        }
        let mut sig = vec![0u8; key_size as usize];
        let mut sig_len = key_size as u32;
        let rc = wolfcrypt_rsa_pss_sign(
            ctx,
            hash_bits,
            msg.as_ptr(),
            len_as_u32(msg.len()),
            sig.as_mut_ptr(),
            &mut sig_len,
        );
        if rc != 0 {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wolfcrypt_rsa_pss_sign",
            });
        }
        sig.truncate(sig_len as usize);
        Ok(sig)
    }
}

/// Verify an RSA-PSS signature using the native shim.
///
/// `ctx` must be a valid, non-null `wolfcrypt_rsa_ctx *`.
/// `hash_bits` must be 256, 384, or 512. Salt length equals the hash length.
unsafe fn native_pss_verify(
    ctx: *mut c_void,
    msg: &[u8],
    sig: &[u8],
    hash_bits: i32,
) -> Result<(), WolfCryptError> {
    // SAFETY: ctx is a valid wolfcrypt_rsa_ctx pointer; msg and sig slices provide valid pointers and lengths
    unsafe {
        let rc = wolfcrypt_rsa_pss_verify(
            ctx,
            hash_bits,
            msg.as_ptr(),
            len_as_u32(msg.len()),
            sig.as_ptr(),
            len_as_u32(sig.len()),
        );
        if rc != 0 {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wolfcrypt_rsa_pss_verify",
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Native PKCS#1v1.5 encrypt/decrypt helpers
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` using RSA PKCS#1v1.5 padding via the native shim.
///
/// `ctx` must be a valid, non-null `wolfcrypt_rsa_ctx *` holding a public key.
unsafe fn native_pkcs1v15_encrypt(
    ctx: *mut c_void,
    plaintext: &[u8],
) -> Result<Vec<u8>, WolfCryptError> {
    // SAFETY: ctx is a valid wolfcrypt_rsa_ctx pointer; output buffer is properly sized to key size
    unsafe {
        let key_size = wolfcrypt_rsa_key_size_bytes(ctx as *const _);
        if key_size <= 0 {
            return Err(WolfCryptError::Ffi {
                code: key_size,
                func: "wolfcrypt_rsa_key_size_bytes",
            });
        }
        let mut out = vec![0u8; key_size as usize];
        let rc = wolfcrypt_rsa_pkcs1v15_encrypt(
            ctx,
            plaintext.as_ptr(),
            len_as_u32(plaintext.len()),
            out.as_mut_ptr(),
            key_size as u32,
        );
        if rc <= 0 {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wolfcrypt_rsa_pkcs1v15_encrypt",
            });
        }
        out.truncate(rc as usize);
        Ok(out)
    }
}

/// Decrypt `ciphertext` using RSA PKCS#1v1.5 padding via the native shim.
///
/// `ctx` must be a valid, non-null `wolfcrypt_rsa_ctx *` holding a private key.
///
/// Checks `rc <= 0` for failure: wolfSSL returns 0 for invalid PKCS#1v1.5
/// padding when `WOLFSSL_RSA_DECRYPT_TO_0_LEN` is set (constant-time failure
/// path), and negative for other errors.
unsafe fn native_pkcs1v15_decrypt(
    ctx: *mut c_void,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WolfCryptError> {
    // SAFETY: ctx is a valid wolfcrypt_rsa_ctx pointer holding a private key; output buffer is properly sized
    unsafe {
        let key_size = wolfcrypt_rsa_key_size_bytes(ctx as *const _);
        if key_size <= 0 {
            return Err(WolfCryptError::Ffi {
                code: key_size,
                func: "wolfcrypt_rsa_key_size_bytes",
            });
        }
        let mut out = vec![0u8; key_size as usize];
        let rc = wolfcrypt_rsa_pkcs1v15_decrypt(
            ctx,
            ciphertext.as_ptr(),
            len_as_u32(ciphertext.len()),
            out.as_mut_ptr(),
            key_size as u32,
        );
        if rc <= 0 {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wolfcrypt_rsa_pkcs1v15_decrypt",
            });
        }
        out.truncate(rc as usize);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// RsaPrivateKey
// ---------------------------------------------------------------------------

/// An RSA private key backed by a native `wolfcrypt_rsa_ctx`.
///
/// Supports PKCS#1v1.5 and PSS signing/verification, and OAEP / PKCS#1v1.5
/// encryption/decryption. Uses the native `wc_*` wolfCrypt API directly with
/// no EVP OpenSSL-compat layer.
pub struct RsaPrivateKey {
    /// Opaque heap-allocated `wolfcrypt_rsa_ctx *`.
    ///
    /// `UnsafeCell` makes the type `!Sync`, which is the correct contract
    /// (wolfCrypt contexts are not thread-safe for concurrent access).
    ctx: UnsafeCell<*mut c_void>,
}

// SAFETY: `wolfcrypt_rsa_ctx` is a self-contained heap object. The struct
// can safely be moved between threads (Send), but not shared (not Sync).
unsafe impl Send for RsaPrivateKey {}

impl RsaPrivateKey {
    /// Import an RSA private key from a PKCS#1 DER-encoded `RSAPrivateKey`
    /// (RFC 8017 Appendix A.1.2).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, WolfCryptError> {
        // SAFETY: wolfcrypt_rsa_new allocates a fresh ctx; import uses valid DER slice; ctx freed on error
        unsafe {
            let ctx = wolfcrypt_rsa_new();
            if ctx.is_null() {
                return Err(WolfCryptError::ALLOC_FAILED);
            }
            let rc = wolfcrypt_rsa_import_private_pkcs1(ctx, der.as_ptr(), len_as_u32(der.len()));
            if rc != 0 {
                wolfcrypt_rsa_free(ctx);
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wolfcrypt_rsa_import_private_pkcs1",
                });
            }
            Ok(Self {
                ctx: UnsafeCell::new(ctx),
            })
        }
    }

    /// Export the private key as a PKCS#1 DER-encoded `RSAPrivateKey`.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, WolfCryptError> {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer; buf is a 4096-byte output buffer
        unsafe {
            let ctx = *self.ctx.get();
            // 4096 bytes is sufficient for any RSA key up to 4096 bits.
            let mut buf = vec![0u8; 4096];
            let mut len = len_as_u32(buf.len());
            let rc = wolfcrypt_rsa_export_private_pkcs1(ctx, buf.as_mut_ptr(), &mut len);
            if rc != 0 {
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wolfcrypt_rsa_export_private_pkcs1",
                });
            }
            buf.truncate(len as usize);
            Ok(buf)
        }
    }

    /// Generate an RSA keypair of the given bit size (e.g. 2048, 3072, 4096).
    pub fn generate(bits: u32) -> Result<Self, WolfCryptError> {
        // SAFETY: wolfcrypt_rsa_new allocates a fresh ctx; generate initializes it; ctx freed on error
        unsafe {
            let ctx = wolfcrypt_rsa_new();
            if ctx.is_null() {
                return Err(WolfCryptError::ALLOC_FAILED);
            }
            let rc = wolfcrypt_rsa_generate(ctx, bits as i32);
            if rc != 0 {
                wolfcrypt_rsa_free(ctx);
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wolfcrypt_rsa_generate",
                });
            }
            Ok(Self {
                ctx: UnsafeCell::new(ctx),
            })
        }
    }

    /// Return the corresponding public key.
    ///
    /// Exports the public component as SPKI DER and imports it into a fresh,
    /// independent `wolfcrypt_rsa_ctx` with no shared state with this key.
    /// Panics if the export/import fails (should not happen for a valid key).
    pub fn public_key(&self) -> RsaPublicKey {
        // SAFETY: self.ctx is valid; export/import create an independent ctx with no shared state
        unsafe {
            let ctx = *self.ctx.get();

            // Export the public component as SPKI DER.
            let mut spki = vec![0u8; 4096];
            let mut spki_len = len_as_u32(spki.len());
            let rc = wolfcrypt_rsa_export_public_spki(ctx, spki.as_mut_ptr(), &mut spki_len);
            assert!(rc == 0, "wolfcrypt_rsa_export_public_spki failed: {rc}");
            spki.truncate(spki_len as usize);

            // Import into a fresh, independent ctx.
            let new_ctx = wolfcrypt_rsa_new();
            assert!(!new_ctx.is_null(), "wolfcrypt_rsa_new returned null");
            let rc = wolfcrypt_rsa_import_public_spki(new_ctx, spki.as_ptr(), spki_len);
            assert!(rc == 0, "wolfcrypt_rsa_import_public_spki failed: {rc}");

            RsaPublicKey {
                ctx: UnsafeCell::new(new_ctx),
            }
        }
    }

    /// Sign `msg` with PKCS#1v1.5 padding (RFC 8017 Section 8.2) and SHA-256.
    pub fn sign_pkcs1v15(&self, msg: &[u8]) -> Result<RsaPkcs1v15Signature, WolfCryptError> {
        self.sign_pkcs1v15_with_digest(msg, RsaDigest::Sha256)
    }

    /// Sign `msg` with PKCS#1v1.5 padding using the specified digest.
    pub fn sign_pkcs1v15_with_digest(
        &self,
        msg: &[u8],
        digest: RsaDigest,
    ) -> Result<RsaPkcs1v15Signature, WolfCryptError> {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer with a private key
        let sig = unsafe { native_pkcs1v15_sign(*self.ctx.get(), msg, digest.hash_bits())? };
        Ok(RsaPkcs1v15Signature(sig))
    }

    /// Sign `msg` with PSS padding (RFC 8017 Section 8.1) and SHA-256.
    ///
    /// Salt length equals the digest length (32 bytes for SHA-256). MGF1 hash
    /// is SHA-256.
    pub fn sign_pss(&self, msg: &[u8]) -> Result<RsaPssSignature, WolfCryptError> {
        self.sign_pss_with_digest(msg, RsaDigest::Sha256)
    }

    /// Sign `msg` with PSS padding using the specified digest.
    ///
    /// Salt length equals the digest length. MGF1 hash matches the digest.
    /// SHA-1 PSS is not supported and will return an error.
    pub fn sign_pss_with_digest(
        &self,
        msg: &[u8],
        digest: RsaDigest,
    ) -> Result<RsaPssSignature, WolfCryptError> {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer with a private key
        let sig = unsafe { native_pss_sign(*self.ctx.get(), msg, digest.hash_bits())? };
        Ok(RsaPssSignature(sig))
    }

    /// Encrypt `plaintext` with OAEP SHA-256/MGF1-SHA256 (RFC 8017 Section 7.1).
    ///
    /// For a 2048-bit key the maximum plaintext size is 190 bytes
    /// (256 - 2*32 - 2).
    pub fn encrypt_oaep(&self, plaintext: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer
        unsafe { native_oaep_encrypt_sha256(*self.ctx.get(), plaintext) }
    }

    /// Decrypt `ciphertext` with OAEP SHA-256/MGF1-SHA256 (RFC 8017 Section 7.1).
    pub fn decrypt_oaep(&self, ciphertext: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer with a private key
        unsafe { native_oaep_decrypt_sha256(*self.ctx.get(), ciphertext) }
    }

    /// Encrypt `plaintext` with PKCS#1 v1.5 padding (RFC 8017 Section 7.2).
    ///
    /// For a 2048-bit key the maximum plaintext size is 245 bytes
    /// (256 - 11).
    pub fn encrypt_pkcs1v15(&self, plaintext: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer
        unsafe { native_pkcs1v15_encrypt(*self.ctx.get(), plaintext) }
    }

    /// Decrypt `ciphertext` with PKCS#1 v1.5 padding (RFC 8017 Section 7.2).
    pub fn decrypt_pkcs1v15(&self, ciphertext: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer with a private key
        unsafe { native_pkcs1v15_decrypt(*self.ctx.get(), ciphertext) }
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer allocated by wolfcrypt_rsa_new
        unsafe {
            wolfcrypt_rsa_free(*self.ctx.get());
        }
    }
}

/// Signs with PKCS#1v1.5 / SHA-256.
impl signature_trait::Signer<RsaPkcs1v15Signature> for RsaPrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<RsaPkcs1v15Signature, signature_trait::Error> {
        self.sign_pkcs1v15(msg)
            .map_err(|_| signature_trait::Error::new())
    }
}

/// Signs with PSS / SHA-256.
impl signature_trait::Signer<RsaPssSignature> for RsaPrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<RsaPssSignature, signature_trait::Error> {
        self.sign_pss(msg)
            .map_err(|_| signature_trait::Error::new())
    }
}

// ---------------------------------------------------------------------------
// RsaPublicKey
// ---------------------------------------------------------------------------

/// An RSA public key backed by a native `wolfcrypt_rsa_ctx`.
///
/// Obtained from [`RsaPrivateKey::public_key()`] or [`RsaPublicKey::from_der`].
/// Owns an independent `wolfcrypt_rsa_ctx` with no shared state with the private
/// key, so it is safe to move to another thread.
pub struct RsaPublicKey {
    /// Opaque heap-allocated `wolfcrypt_rsa_ctx *` (public-key component only).
    ///
    /// `UnsafeCell` provides `!Sync` — same rationale as `RsaPrivateKey::ctx`.
    ctx: UnsafeCell<*mut c_void>,
}

// SAFETY: same reasoning as RsaPrivateKey — Send but not Sync.
unsafe impl Send for RsaPublicKey {}

impl RsaPublicKey {
    /// Import a public key from a DER-encoded SubjectPublicKeyInfo (SPKI) blob.
    ///
    /// This is the standard format used by Wycheproof test vectors
    /// (`publicKeyDer` field) and produced by `wolfcrypt_rsa_export_public_spki`.
    pub fn from_der(der: &[u8]) -> Result<Self, WolfCryptError> {
        // SAFETY: wolfcrypt_rsa_new allocates a fresh ctx; import uses valid DER slice; ctx freed on error
        unsafe {
            let ctx = wolfcrypt_rsa_new();
            if ctx.is_null() {
                return Err(WolfCryptError::ALLOC_FAILED);
            }
            let rc = wolfcrypt_rsa_import_public_spki(ctx, der.as_ptr(), len_as_u32(der.len()));
            if rc != 0 {
                wolfcrypt_rsa_free(ctx);
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wolfcrypt_rsa_import_public_spki",
                });
            }
            Ok(Self {
                ctx: UnsafeCell::new(ctx),
            })
        }
    }

    /// Encrypt `plaintext` with OAEP SHA-256/MGF1-SHA256 (RFC 8017 Section 7.1).
    ///
    /// RSA encryption only requires the public key. Decryption requires the
    /// private key held by [`RsaPrivateKey`].
    pub fn encrypt_oaep(&self, plaintext: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer
        unsafe { native_oaep_encrypt_sha256(*self.ctx.get(), plaintext) }
    }

    /// Encrypt `plaintext` with PKCS#1 v1.5 padding (RFC 8017 Section 7.2).
    pub fn encrypt_pkcs1v15(&self, plaintext: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer
        unsafe { native_pkcs1v15_encrypt(*self.ctx.get(), plaintext) }
    }

    /// Verify a PKCS#1v1.5 signature (RFC 8017 Section 8.2) with SHA-256.
    pub fn verify_pkcs1v15(
        &self,
        msg: &[u8],
        sig: &RsaPkcs1v15Signature,
    ) -> Result<(), WolfCryptError> {
        self.verify_pkcs1v15_with_digest(msg, sig, RsaDigest::Sha256)
    }

    /// Verify a PKCS#1v1.5 signature using the specified digest.
    pub fn verify_pkcs1v15_with_digest(
        &self,
        msg: &[u8],
        sig: &RsaPkcs1v15Signature,
        digest: RsaDigest,
    ) -> Result<(), WolfCryptError> {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer
        unsafe { native_pkcs1v15_verify(*self.ctx.get(), msg, &sig.0, digest.hash_bits()) }
    }

    /// Verify a PSS signature (RFC 8017 Section 8.1) with SHA-256.
    pub fn verify_pss(&self, msg: &[u8], sig: &RsaPssSignature) -> Result<(), WolfCryptError> {
        self.verify_pss_with_digest(msg, sig, RsaDigest::Sha256)
    }

    /// Verify a PSS signature using the specified digest.
    ///
    /// Salt length equals the digest length. MGF1 hash matches the digest.
    /// SHA-1 PSS is not supported and will return an error.
    pub fn verify_pss_with_digest(
        &self,
        msg: &[u8],
        sig: &RsaPssSignature,
        digest: RsaDigest,
    ) -> Result<(), WolfCryptError> {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer
        unsafe { native_pss_verify(*self.ctx.get(), msg, &sig.0, digest.hash_bits()) }
    }
}

impl Drop for RsaPublicKey {
    fn drop(&mut self) {
        // SAFETY: self.ctx is a valid wolfcrypt_rsa_ctx pointer allocated by wolfcrypt_rsa_new
        unsafe {
            wolfcrypt_rsa_free(*self.ctx.get());
        }
    }
}

/// Verifies PKCS#1v1.5 / SHA-256.
impl signature_trait::Verifier<RsaPkcs1v15Signature> for RsaPublicKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &RsaPkcs1v15Signature,
    ) -> Result<(), signature_trait::Error> {
        self.verify_pkcs1v15(msg, signature)
            .map_err(|_| signature_trait::Error::new())
    }
}

/// Verifies PSS / SHA-256.
impl signature_trait::Verifier<RsaPssSignature> for RsaPublicKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &RsaPssSignature,
    ) -> Result<(), signature_trait::Error> {
        self.verify_pss(msg, signature)
            .map_err(|_| signature_trait::Error::new())
    }
}

// ===========================================================================
// RSA direct (no-padding) operations via native wolfCrypt API
// ===========================================================================

/// The `type_` parameter for [`wc_RsaFunction`].
///
/// wolfSSL defines these in `wolfssl/wolfcrypt/rsa.h`:
/// ```c
/// #define RSA_PUBLIC_ENCRYPT  0
/// #define RSA_PUBLIC_DECRYPT  1
/// #define RSA_PRIVATE_ENCRYPT 2
/// #define RSA_PRIVATE_DECRYPT 3
/// ```
#[cfg(feature = "rsa-direct")]
const RSA_TYPE_PUBLIC_ENCRYPT: i32 = 0;
#[cfg(feature = "rsa-direct")]
const RSA_TYPE_PUBLIC_DECRYPT: i32 = 1;
#[cfg(feature = "rsa-direct")]
const RSA_TYPE_PRIVATE_ENCRYPT: i32 = 2;
#[cfg(feature = "rsa-direct")]
const RSA_TYPE_PRIVATE_DECRYPT: i32 = 3;

/// Selects which RSA primitive operation [`NativeRsaKey::rsa_direct`] performs.
///
/// These map 1:1 to wolfCrypt's `RSA_PUBLIC_ENCRYPT`, etc.  "Encrypt" and
/// "decrypt" are misnomers inherited from PKCS#1 — they really mean
/// "apply the public exponent" and "apply the private exponent".
#[cfg(feature = "rsa-direct")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaDirectType {
    /// Apply the public exponent (m^e mod n).
    PublicEncrypt,
    /// Apply the public exponent to recover a signature (m^e mod n).
    PublicDecrypt,
    /// Apply the private exponent (m^d mod n).
    PrivateEncrypt,
    /// Apply the private exponent to recover plaintext (m^d mod n).
    PrivateDecrypt,
}

#[cfg(feature = "rsa-direct")]
impl RsaDirectType {
    fn as_c_int(self) -> i32 {
        match self {
            Self::PublicEncrypt => RSA_TYPE_PUBLIC_ENCRYPT,
            Self::PublicDecrypt => RSA_TYPE_PUBLIC_DECRYPT,
            Self::PrivateEncrypt => RSA_TYPE_PRIVATE_ENCRYPT,
            Self::PrivateDecrypt => RSA_TYPE_PRIVATE_DECRYPT,
        }
    }
}

/// An RSA key using the **native** wolfCrypt `RsaKey` type (not the
/// native `wolfcrypt_rsa_ctx` wrapper used by [`RsaPrivateKey`]).
///
/// This is needed for raw / no-padding RSA operations via
/// [`wc_RsaFunction`], which operates directly on the modulus without
/// applying PKCS#1, OAEP, or PSS padding.  The caller is responsible
/// for any padding or encoding applied before calling [`rsa_direct`].
///
/// # Construction
///
/// - [`NativeRsaKey::from_private_der`] — import a DER-encoded PKCS#1
///   RSA private key (`RSAPrivateKey` ASN.1 structure).
/// - [`NativeRsaKey::from_public_der`] — import a DER-encoded PKCS#1
///   RSA public key (`RSAPublicKey` ASN.1 structure).
/// - [`NativeRsaKey::generate`] — generate a new keypair.
///
/// [`rsa_direct`]: NativeRsaKey::rsa_direct
#[cfg(feature = "rsa-direct")]
pub struct NativeRsaKey {
    key: *mut wolfcrypt_rs::RsaKey,
}

// SAFETY: The RsaKey is a self-contained heap object. Safe to move
// between threads, but not safe to share (not Sync).
#[cfg(feature = "rsa-direct")]
unsafe impl Send for NativeRsaKey {}

#[cfg(feature = "rsa-direct")]
impl NativeRsaKey {
    /// Allocate a new, empty `RsaKey` via `wc_NewRsaKey`.
    fn alloc() -> Result<*mut wolfcrypt_rs::RsaKey, WolfCryptError> {
        let mut rc: core::ffi::c_int = 0;
        // SAFETY: wc_NewRsaKey allocates and initializes a new RsaKey; null heap uses default allocator
        let key = unsafe {
            wolfcrypt_rs::wc_NewRsaKey(ptr::null_mut(), wolfcrypt_rs::INVALID_DEVID, &mut rc)
        };
        if key.is_null() {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_NewRsaKey",
            });
        }
        Ok(key)
    }

    /// Deprecated alias for [`Self::generate`].
    #[deprecated(note = "use `generate` instead")]
    pub fn generate_native(
        bits: u32,
        rng: &mut crate::rand::WolfRng,
    ) -> Result<Self, WolfCryptError> {
        Self::generate(bits, rng)
    }

    /// Export the key to PKCS#1 DER format (`RSAPrivateKey`).
    ///
    /// The returned buffer contains the full ASN.1 structure including
    /// n, e, d, p, q, dp, dq, and iqmp.
    pub fn to_pkcs1_der(&self) -> Result<alloc::vec::Vec<u8>, WolfCryptError> {
        // Start with a generous buffer; typical 2048-bit key DER is ~1200 bytes.
        let mut buf = alloc::vec![0u8; 4096];
        // SAFETY: self.key is a valid RsaKey pointer; buf is a properly sized output buffer
        let rc = unsafe {
            wolfcrypt_rs::wc_RsaKeyToDer(self.key, buf.as_mut_ptr(), len_as_u32(buf.len()))
        };
        if rc < 0 {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_RsaKeyToDer",
            });
        }
        buf.truncate(rc as usize);
        Ok(buf)
    }

    /// Import a DER-encoded PKCS#1 RSA private key (`RSAPrivateKey`).
    ///
    /// This is the "traditional" private-key format (not wrapped in
    /// PKCS#8 `PrivateKeyInfo`).
    pub fn from_private_der(der: &[u8]) -> Result<Self, WolfCryptError> {
        let key = Self::alloc()?;
        let mut idx: u32 = 0;
        // SAFETY: key is a valid RsaKey pointer; der slice provides valid pointer and length
        let rc = unsafe {
            wolfcrypt_rs::wc_RsaPrivateKeyDecode(der.as_ptr(), &mut idx, key, len_as_u32(der.len()))
        };
        if rc != 0 {
            // SAFETY: key is a valid RsaKey pointer that must be freed on error
            // Clean up on failure.
            unsafe {
                wolfcrypt_rs::wc_DeleteRsaKey(key, ptr::null_mut());
            }
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_RsaPrivateKeyDecode",
            });
        }
        Ok(Self { key })
    }

    /// Import a DER-encoded PKCS#1 RSA public key (`RSAPublicKey`).
    ///
    /// Also accepts SubjectPublicKeyInfo (SPKI) DER — wolfCrypt's
    /// `wc_RsaPublicKeyDecode` handles both formats.
    pub fn from_public_der(der: &[u8]) -> Result<Self, WolfCryptError> {
        let key = Self::alloc()?;
        let mut idx: u32 = 0;
        // SAFETY: key is a valid RsaKey pointer; der slice provides valid pointer and length
        let rc = unsafe {
            wolfcrypt_rs::wc_RsaPublicKeyDecode(der.as_ptr(), &mut idx, key, len_as_u32(der.len()))
        };
        if rc != 0 {
            // SAFETY: key is a valid RsaKey pointer that must be freed on error
            unsafe {
                wolfcrypt_rs::wc_DeleteRsaKey(key, ptr::null_mut());
            }
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_RsaPublicKeyDecode",
            });
        }
        Ok(Self { key })
    }

    /// Generate a new RSA keypair of the given bit size.
    ///
    /// `bits` is typically 2048, 3072, or 4096.  `rng` provides the
    /// randomness source.
    pub fn generate(bits: u32, rng: &mut crate::rand::WolfRng) -> Result<Self, WolfCryptError> {
        let key = Self::alloc()?;
        // SAFETY: key is a valid RsaKey pointer from alloc(); rng is a valid WC_RNG
        let rc = unsafe {
            wolfcrypt_rs::wc_MakeRsaKey(
                key,
                bits as core::ffi::c_int,
                65537, // standard public exponent
                &mut rng.rng,
            )
        };
        if rc != 0 {
            // SAFETY: key is a valid RsaKey pointer that must be freed on error
            unsafe {
                wolfcrypt_rs::wc_DeleteRsaKey(key, ptr::null_mut());
            }
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_MakeRsaKey",
            });
        }
        Ok(Self { key })
    }

    /// Return the RSA modulus size in bytes (i.e. the output size of
    /// `rsa_direct`).
    pub fn encrypt_size(&self) -> Result<usize, WolfCryptError> {
        // SAFETY: self.key is a valid RsaKey pointer
        let sz = unsafe { wolfcrypt_rs::wc_RsaEncryptSize(self.key as *const _) };
        if sz <= 0 {
            return Err(WolfCryptError::Ffi {
                code: sz,
                func: "wc_RsaEncryptSize",
            });
        }
        Ok(sz as usize)
    }

    /// Perform a raw RSA operation (no padding) via `wc_RsaFunction`.
    ///
    /// `input` must be exactly [`encrypt_size()`](Self::encrypt_size)
    /// bytes — the raw modular-exponentiation input.  Returns a
    /// buffer of the same size containing the result.
    ///
    /// `rng` is required by wolfCrypt for blinding during private-key
    /// operations.  For public-key operations it may still be passed
    /// (wolfCrypt ignores it if not needed).
    pub fn rsa_direct(
        &mut self,
        input: &[u8],
        type_: RsaDirectType,
        rng: &mut crate::rand::WolfRng,
    ) -> Result<Vec<u8>, WolfCryptError> {
        let key_sz = self.encrypt_size()?;
        if input.len() != key_sz {
            return Err(WolfCryptError::InvalidInput);
        }

        let mut out = vec![0u8; key_sz];
        let mut out_len: u32 = key_sz as u32;

        // SAFETY: self.key is a valid RsaKey; input/out are properly sized to key modulus; rng is valid
        let rc = unsafe {
            wolfcrypt_rs::wc_RsaFunction(
                input.as_ptr(),
                len_as_u32(input.len()),
                out.as_mut_ptr(),
                &mut out_len,
                type_.as_c_int(),
                self.key,
                &mut rng.rng,
            )
        };
        check(rc, "wc_RsaFunction")?;

        out.truncate(out_len as usize);
        Ok(out)
    }

    /// Import an RSA private key from raw big-endian component byte arrays.
    ///
    /// This calls `wc_RsaPrivateKeyDecodeRaw` which accepts the components
    /// directly, avoiding the need to construct a PKCS#1 DER encoding.
    /// wolfCrypt will compute dp and dq internally if not provided.
    ///
    /// # Parameters
    /// - `n`: modulus
    /// - `e`: public exponent
    /// - `d`: private exponent
    /// - `p`, `q`: prime factors
    /// - `iqmp`: CRT coefficient (q^{-1} mod p)
    pub fn from_raw_components(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        p: &[u8],
        q: &[u8],
        iqmp: &[u8],
    ) -> Result<Self, WolfCryptError> {
        let key = Self::alloc()?;
        // SAFETY: key is a valid RsaKey pointer; all component slices provide valid pointers and lengths
        let rc = unsafe {
            wolfcrypt_rs::wc_RsaPrivateKeyDecodeRaw(
                n.as_ptr(),
                len_as_u32(n.len()),
                e.as_ptr(),
                len_as_u32(e.len()),
                d.as_ptr(),
                len_as_u32(d.len()),
                iqmp.as_ptr(),
                len_as_u32(iqmp.len()),
                p.as_ptr(),
                len_as_u32(p.len()),
                q.as_ptr(),
                len_as_u32(q.len()),
                ptr::null(),
                0, // dp — let wolfCrypt compute
                ptr::null(),
                0, // dq — let wolfCrypt compute
                key,
            )
        };
        if rc != 0 {
            // SAFETY: key is a valid RsaKey pointer that must be freed on error
            unsafe { wolfcrypt_rs::wc_DeleteRsaKey(key, ptr::null_mut()) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_RsaPrivateKeyDecodeRaw",
            });
        }
        Ok(Self { key })
    }

    /// Get the RSA key size (modulus size in bytes).
    pub fn key_size(&self) -> Result<usize, WolfCryptError> {
        // SAFETY: self.key is a valid RsaKey pointer
        let rc = unsafe { wolfcrypt_rs::wc_RsaEncryptSize(self.key) };
        if rc < 0 {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_RsaEncryptSize",
            });
        }
        Ok(rc as usize)
    }

    /// PKCS#1v1.5 sign: applies type-1 block padding and RSA private-key
    /// operation.  `digest_info` must already contain the DER-encoded
    /// `DigestInfo` (OID + hash), as specified in RFC 8017 §9.2.
    ///
    /// Returns the raw signature bytes (length = key size).
    pub fn sign_pkcs1v15_raw(
        &self,
        digest_info: &[u8],
        rng: &mut crate::rand::WolfRng,
    ) -> Result<alloc::vec::Vec<u8>, WolfCryptError> {
        let key_sz = self.key_size()?;
        let mut out = alloc::vec![0u8; key_sz];
        // SAFETY: self.key is a valid RsaKey; digest_info/out are properly sized; rng is valid
        let rc = unsafe {
            wolfcrypt_rs::wc_RsaSSL_Sign(
                digest_info.as_ptr(),
                len_as_u32(digest_info.len()),
                out.as_mut_ptr(),
                len_as_u32(out.len()),
                self.key,
                &mut rng.rng,
            )
        };
        if rc < 0 {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_RsaSSL_Sign",
            });
        }
        out.truncate(rc as usize);
        Ok(out)
    }

    /// PKCS#1v1.5 verify: applies RSA public-key operation and checks
    /// type-1 block padding.  Returns the recovered `DigestInfo` bytes.
    pub fn verify_pkcs1v15_raw(
        &self,
        signature: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, WolfCryptError> {
        let key_sz = self.key_size()?;
        let mut out = alloc::vec![0u8; key_sz];
        // SAFETY: self.key is a valid RsaKey; signature/out are properly sized buffers
        let rc = unsafe {
            wolfcrypt_rs::wc_RsaSSL_Verify(
                signature.as_ptr(),
                len_as_u32(signature.len()),
                out.as_mut_ptr(),
                len_as_u32(out.len()),
                self.key,
            )
        };
        if rc < 0 {
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_RsaSSL_Verify",
            });
        }
        out.truncate(rc as usize);
        Ok(out)
    }

    /// Export all RSA key components as raw big-endian byte vectors.
    ///
    /// Uses `wc_RsaExportKey` for (e, n, d, p, q) and extracts iqmp from
    /// the PKCS#1 DER via `wc_RsaKeyToDer` (the only way to get iqmp out
    /// of wolfCrypt's opaque `RsaKey`).
    pub fn export_raw_components(&mut self) -> Result<RsaRawComponents, WolfCryptError> {
        // Use key_size as a conservative upper bound for all component buffers.
        let sz = self.key_size()?;
        let mut e = alloc::vec![0u8; sz];
        let mut n = alloc::vec![0u8; sz];
        let mut d = alloc::vec![0u8; sz];
        let mut p = alloc::vec![0u8; sz];
        let mut q = alloc::vec![0u8; sz];
        let mut e_sz = len_as_u32(e.len());
        let mut n_sz = len_as_u32(n.len());
        let mut d_sz = len_as_u32(d.len());
        let mut p_sz = len_as_u32(p.len());
        let mut q_sz = len_as_u32(q.len());

        // SAFETY: self.key is a valid RsaKey; output buffers are sized to key_size upper bound
        let rc = unsafe {
            wolfcrypt_rs::wc_RsaExportKey(
                self.key,
                e.as_mut_ptr(),
                &mut e_sz,
                n.as_mut_ptr(),
                &mut n_sz,
                d.as_mut_ptr(),
                &mut d_sz,
                p.as_mut_ptr(),
                &mut p_sz,
                q.as_mut_ptr(),
                &mut q_sz,
            )
        };
        check(rc, "wc_RsaExportKey")?;

        e.truncate(e_sz as usize);
        n.truncate(n_sz as usize);
        d.truncate(d_sz as usize);
        p.truncate(p_sz as usize);
        q.truncate(q_sz as usize);

        // wc_RsaExportKey doesn't export iqmp. Extract it from the PKCS#1
        // DER which contains all 9 fields: version, n, e, d, p, q, dp, dq, iqmp.
        let der = self.to_pkcs1_der()?;
        let iqmp = extract_iqmp_from_pkcs1_der(&der)?;

        Ok(RsaRawComponents {
            e,
            n,
            d,
            p,
            q,
            iqmp,
        })
    }

    /// Import an RSA public key from raw big-endian (n, e) byte arrays.
    ///
    /// Uses wolfCrypt's `wc_RsaFlattenPublicKey` in reverse: we first
    /// allocate a key, then call `from_raw_components` with only the
    /// public components — but that requires private key fields too.
    /// Instead we build a minimal PKCS#1 DER and use `from_public_der`.
    pub fn from_raw_public(n: &[u8], e: &[u8]) -> Result<Self, WolfCryptError> {
        let der = build_pkcs1_public_key_der(n, e);
        Self::from_public_der(&der)
    }
}

/// Raw RSA key components exported from a [`NativeRsaKey`].
#[cfg(feature = "rsa-direct")]
pub struct RsaRawComponents {
    /// Public exponent (e), big-endian.
    pub e: alloc::vec::Vec<u8>,
    /// Modulus (n), big-endian.
    pub n: alloc::vec::Vec<u8>,
    /// Private exponent (d), big-endian.
    pub d: alloc::vec::Vec<u8>,
    /// First prime factor (p), big-endian.
    pub p: alloc::vec::Vec<u8>,
    /// Second prime factor (q), big-endian.
    pub q: alloc::vec::Vec<u8>,
    /// CRT coefficient: (inverse of q) mod p, big-endian.
    pub iqmp: alloc::vec::Vec<u8>,
}

/// Build a minimal PKCS#1 DER-encoded `RSAPublicKey` from raw (n, e).
///
/// ```text
/// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
/// ```
#[cfg(feature = "rsa-direct")]
fn build_pkcs1_public_key_der(n: &[u8], e: &[u8]) -> alloc::vec::Vec<u8> {
    let n_der = der_encode_unsigned_integer(n);
    let e_der = der_encode_unsigned_integer(e);
    let content_len = n_der.len() + e_der.len();

    let mut der = alloc::vec::Vec::with_capacity(content_len + 10);
    der.push(0x30); // SEQUENCE tag
    der_push_length(content_len, &mut der);
    der.extend_from_slice(&n_der);
    der.extend_from_slice(&e_der);
    der
}

/// DER-encode a non-negative integer with tag 0x02.
#[cfg(feature = "rsa-direct")]
fn der_encode_unsigned_integer(bytes: &[u8]) -> alloc::vec::Vec<u8> {
    if bytes.is_empty() {
        return alloc::vec![0x02, 0x01, 0x00];
    }
    // Strip leading zeros (keep at least one byte)
    let significant = match bytes.iter().position(|&b| b != 0) {
        Some(i) => &bytes[i..],
        None => &bytes[bytes.len() - 1..], // all zeros → keep one 0x00
    };
    let needs_pad = significant[0] & 0x80 != 0;
    let value_len = significant.len() + usize::from(needs_pad);

    let mut out = alloc::vec::Vec::with_capacity(value_len + 4);
    out.push(0x02); // INTEGER tag
    der_push_length(value_len, &mut out);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(significant);
    out
}

/// Push a DER length encoding into `out`.
///
/// # Panics
/// Panics if `len` exceeds 0xFF_FFFF (16 MiB), which cannot occur for
/// any valid RSA key component.
#[cfg(feature = "rsa-direct")]
fn der_push_length(len: usize, out: &mut alloc::vec::Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else if len < 0x100_0000 {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        panic!("DER length {len} exceeds maximum supported (0xFFFFFF)");
    }
}

// ---------------------------------------------------------------------------
// Minimal DER helpers for iqmp extraction
// ---------------------------------------------------------------------------
//
// `wc_RsaExportKey` exports (e, n, d, p, q) but NOT iqmp. The only way to
// get iqmp out of wolfCrypt's opaque `RsaKey` is via `wc_RsaKeyToDer`, which
// produces a PKCS#1 DER containing all 9 fields. We skip the first 8
// INTEGERs and return the 9th (iqmp).

/// Extract the iqmp (CRT coefficient) from a PKCS#1 `RSAPrivateKey` DER.
///
/// PKCS#1 layout (RFC 8017 A.1.2):
///   SEQUENCE { version, n, e, d, p, q, dp, dq, iqmp }
#[cfg(feature = "rsa-direct")]
fn extract_iqmp_from_pkcs1_der(der: &[u8]) -> Result<alloc::vec::Vec<u8>, WolfCryptError> {
    let err = || WolfCryptError::Ffi {
        code: -1,
        func: "extract_iqmp_from_pkcs1_der",
    };
    let mut pos = 0;

    // SEQUENCE tag
    if pos >= der.len() || der[pos] != 0x30 {
        return Err(err());
    }
    pos = pos.checked_add(1).ok_or_else(err)?;
    let (_seq_len, hdr) = der_read_len(der, pos).ok_or_else(err)?;
    pos = pos.checked_add(hdr).ok_or_else(err)?;

    // Skip 8 INTEGERs: version, n, e, d, p, q, dp, dq
    for _ in 0..8 {
        pos = der_skip_int(der, pos).ok_or_else(err)?;
    }

    // 9th INTEGER is iqmp
    let val = der_read_int(der, pos).ok_or_else(err)?;
    Ok(val.to_vec())
}

/// Read a DER length at `pos`. Returns `Some((value, bytes_consumed))`.
#[cfg(feature = "rsa-direct")]
fn der_read_len(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let b = *data.get(pos)?;
    if b < 0x80 {
        Some((b as usize, 1))
    } else {
        let n = (b & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let end = pos.checked_add(1)?.checked_add(n)?;
        if end > data.len() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = len.checked_shl(8)? | (*data.get(pos + 1 + i)? as usize);
        }
        Some((len, 1 + n))
    }
}

/// Read a DER INTEGER at `pos`, stripping leading zero padding.
/// Returns the unsigned value bytes.
#[cfg(feature = "rsa-direct")]
fn der_read_int(data: &[u8], pos: usize) -> Option<&[u8]> {
    if *data.get(pos)? != 0x02 {
        return None;
    }
    let (len, hdr) = der_read_len(data, pos.checked_add(1)?)?;
    let start = pos.checked_add(1)?.checked_add(hdr)?;
    let end = start.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    let mut val = &data[start..end];
    while val.len() > 1 && val[0] == 0 {
        val = &val[1..];
    }
    Some(val)
}

/// Skip a DER INTEGER at `pos`, returning the position after it.
#[cfg(feature = "rsa-direct")]
fn der_skip_int(data: &[u8], pos: usize) -> Option<usize> {
    if *data.get(pos)? != 0x02 {
        return None;
    }
    let (len, hdr) = der_read_len(data, pos.checked_add(1)?)?;
    let end = pos.checked_add(1)?.checked_add(hdr)?.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some(end)
}

#[cfg(feature = "rsa-direct")]
impl Drop for NativeRsaKey {
    fn drop(&mut self) {
        if !self.key.is_null() {
            // SAFETY: self.key is a valid non-null RsaKey pointer allocated by wc_NewRsaKey
            unsafe {
                wolfcrypt_rs::wc_DeleteRsaKey(self.key, ptr::null_mut());
            }
        }
    }
}

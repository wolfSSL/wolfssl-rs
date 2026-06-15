//! HPKE (Hybrid Public Key Encryption) per RFC 9180, backed by wolfCrypt.
//!
//! Supports Base mode with DHKEM (P-256, P-384, P-521, X25519, X448),
//! HKDF-SHA256/384/512, and AES-128-GCM / AES-256-GCM.
//!
//! # Example
//!
//! ```ignore
//! use wolfcrypt::hpke::{Hpke, HpkeSuite};
//! use wolfcrypt::rand::WolfRng;
//!
//! let mut hpke = Hpke::new(HpkeSuite::X25519_SHA256_AES128).unwrap();
//! let mut rng = WolfRng::new().unwrap();
//!
//! // Receiver generates a long-term key pair.
//! let mut receiver_kp = hpke.generate_keypair(&mut rng).unwrap();
//!
//! // Sender generates an ephemeral key pair, seals a message.
//! let mut ephemeral_kp = hpke.generate_keypair(&mut rng).unwrap();
//! let (enc, ct) = hpke.seal_base(
//!     &mut ephemeral_kp, &mut receiver_kp,
//!     b"app-info", b"associated-data", b"hello world",
//! ).unwrap();
//!
//! // Receiver opens the message.
//! let pt = hpke.open_base(&mut receiver_kp, &enc, b"app-info", b"associated-data", &ct).unwrap();
//! assert_eq!(pt, b"hello world");
//! ```
//!
//! # Key lifetime
//!
//! [`HpkeKeyPair`] is self-contained: it shares ownership of the underlying
//! `WcHpke` context via `Arc`, so key pairs can safely outlive the [`Hpke`]
//! that created them.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;

use crate::error::{check, len_as_u32, WolfCryptError};
use crate::rand::WolfRng;
use wolfcrypt_rs::{
    wc_HpkeDeserializePublicKey, wc_HpkeFreeKey, wc_HpkeGenerateKeyPair, wc_HpkeInit,
    wc_HpkeOpenBase, wc_HpkeSealBase, wc_HpkeSerializePublicKey, HPKE_Nt_MAX, WcHpke,
    DHKEM_P256_ENC_LEN, DHKEM_P256_HKDF_SHA256, DHKEM_P384_ENC_LEN, DHKEM_P384_HKDF_SHA384,
    DHKEM_P521_ENC_LEN, DHKEM_P521_HKDF_SHA512, DHKEM_X25519_ENC_LEN, DHKEM_X25519_HKDF_SHA256,
    DHKEM_X448_ENC_LEN, DHKEM_X448_HKDF_SHA512, HPKE_AES_128_GCM, HPKE_AES_256_GCM,
    HPKE_HKDF_SHA256, HPKE_HKDF_SHA384, HPKE_HKDF_SHA512,
};

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

/// HPKE cipher suite specifying KEM, KDF, and AEAD algorithms.
///
/// Construct via named constants (e.g. [`HpkeSuite::X25519_SHA256_AES128`])
/// to ensure only valid RFC 9180 algorithm combinations are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpkeSuite {
    kem: i32,
    kdf: i32,
    aead: i32,
}

impl HpkeSuite {
    /// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM — the most common suite.
    pub const P256_SHA256_AES128: Self = Self {
        kem: DHKEM_P256_HKDF_SHA256,
        kdf: HPKE_HKDF_SHA256,
        aead: HPKE_AES_128_GCM,
    };

    /// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
    pub const P256_SHA256_AES256: Self = Self {
        kem: DHKEM_P256_HKDF_SHA256,
        kdf: HPKE_HKDF_SHA256,
        aead: HPKE_AES_256_GCM,
    };

    /// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
    pub const X25519_SHA256_AES128: Self = Self {
        kem: DHKEM_X25519_HKDF_SHA256,
        kdf: HPKE_HKDF_SHA256,
        aead: HPKE_AES_128_GCM,
    };

    /// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
    pub const X25519_SHA256_AES256: Self = Self {
        kem: DHKEM_X25519_HKDF_SHA256,
        kdf: HPKE_HKDF_SHA256,
        aead: HPKE_AES_256_GCM,
    };

    /// DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM.
    pub const P384_SHA384_AES256: Self = Self {
        kem: DHKEM_P384_HKDF_SHA384,
        kdf: HPKE_HKDF_SHA384,
        aead: HPKE_AES_256_GCM,
    };

    /// DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM.
    pub const P521_SHA512_AES256: Self = Self {
        kem: DHKEM_P521_HKDF_SHA512,
        kdf: HPKE_HKDF_SHA512,
        aead: HPKE_AES_256_GCM,
    };

    /// DHKEM(X448, HKDF-SHA512), HKDF-SHA512, AES-256-GCM.
    pub const X448_SHA512_AES256: Self = Self {
        kem: DHKEM_X448_HKDF_SHA512,
        kdf: HPKE_HKDF_SHA512,
        aead: HPKE_AES_256_GCM,
    };

    /// Returns the serialized public key ("enc") length for this suite's KEM.
    ///
    /// This is the number of bytes produced by [`HpkeKeyPair::serialize_public_key`]
    /// and expected by [`Hpke::open_base`] as the `enc` parameter.
    pub fn enc_len(&self) -> usize {
        match self.kem {
            DHKEM_P256_HKDF_SHA256 => DHKEM_P256_ENC_LEN,
            DHKEM_P384_HKDF_SHA384 => DHKEM_P384_ENC_LEN,
            DHKEM_P521_HKDF_SHA512 => DHKEM_P521_ENC_LEN,
            DHKEM_X25519_HKDF_SHA256 => DHKEM_X25519_ENC_LEN,
            DHKEM_X448_HKDF_SHA512 => DHKEM_X448_ENC_LEN,
            _ => 0,
        }
    }

    /// Returns the AEAD tag length for this suite's AEAD algorithm.
    ///
    /// Both AES-128-GCM and AES-256-GCM use a 16-byte tag.
    pub fn tag_len(&self) -> usize {
        // HPKE_Nt_MAX is 16 for all currently defined AEAD algorithms.
        HPKE_Nt_MAX
    }
}

// ---------------------------------------------------------------------------
// Key pair
// ---------------------------------------------------------------------------

/// An opaque HPKE key pair (public + private) allocated by wolfCrypt.
///
/// Created via [`Hpke::generate_keypair`] or [`Hpke::deserialize_public_key`].
/// Self-contained: shares ownership of the parent `WcHpke` context via `Arc`,
/// so it can safely outlive the [`Hpke`] that created it.
pub struct HpkeKeyPair {
    key: *mut c_void,
    kem: i32,
    suite: HpkeSuite,
    /// Shared ownership of the `WcHpke` context — guarantees the context
    /// is alive for `wc_HpkeFreeKey` and `wc_HpkeSerializePublicKey`.
    hpke: Arc<UnsafeCell<WcHpke>>,
}

impl HpkeKeyPair {
    /// Serialize the public key to bytes.
    ///
    /// The output length matches [`HpkeSuite::enc_len`] for the KEM that
    /// generated this key pair.
    pub fn serialize_public_key(&mut self) -> Result<Vec<u8>, WolfCryptError> {
        let enc_len = self.suite.enc_len();
        if enc_len == 0 {
            return Err(WolfCryptError::InvalidInput);
        }
        let mut buf = vec![0u8; enc_len];
        let mut out_sz: u16 = enc_len as u16;

        // SAFETY: `self.hpke` is initialised (Arc guarantees it's alive),
        // `self.key` is a valid keypair, and `buf` is large enough.
        let rc = unsafe {
            wc_HpkeSerializePublicKey(
                &mut *self.hpke.get(),
                self.key,
                buf.as_mut_ptr(),
                &mut out_sz,
            )
        };
        check(rc, "wc_HpkeSerializePublicKey")?;
        buf.truncate(out_sz as usize);
        Ok(buf)
    }
}

impl Drop for HpkeKeyPair {
    fn drop(&mut self) {
        if !self.key.is_null() {
            // SAFETY: `self.key` was allocated by `wc_HpkeGenerateKeyPair` or
            // `wc_HpkeDeserializePublicKey`. The Arc guarantees the WcHpke
            // context is still alive. Freed exactly once.
            unsafe {
                wc_HpkeFreeKey(self.hpke.get(), self.kem as u16, self.key, ptr::null_mut());
            }
        }
    }
}

// SAFETY: The opaque key handle is owned exclusively by this struct and
// wolfCrypt's key data has no thread affinity.
unsafe impl Send for HpkeKeyPair {}

// ---------------------------------------------------------------------------
// HPKE context
// ---------------------------------------------------------------------------

/// HPKE context managing a wolfCrypt `WcHpke` instance.
///
/// The `WcHpke` is reference-counted (`Arc`) so that [`HpkeKeyPair`]s
/// created from this context are self-contained and can safely outlive
/// the `Hpke` that created them.
///
/// Provides one-shot Base-mode seal (encrypt) and open (decrypt) operations.
pub struct Hpke {
    hpke: Arc<UnsafeCell<WcHpke>>,
    suite: HpkeSuite,
}

impl Hpke {
    /// Create a new HPKE context for the given cipher suite.
    pub fn new(suite: HpkeSuite) -> Result<Self, WolfCryptError> {
        let hpke = Arc::new(UnsafeCell::new(WcHpke::zeroed()));
        // SAFETY: `hpke` is zero-initialised and `wc_HpkeInit` will fully
        // initialise it.  We pass NULL for the heap (use default allocator).
        let rc = unsafe {
            wc_HpkeInit(
                &mut *hpke.get(),
                suite.kem,
                suite.kdf,
                suite.aead,
                ptr::null_mut(),
            )
        };
        check(rc, "wc_HpkeInit")?;
        Ok(Self { hpke, suite })
    }

    /// Returns the cipher suite this context was created with.
    pub fn suite(&self) -> HpkeSuite {
        self.suite
    }

    /// Generate a KEM key pair using the provided RNG.
    pub fn generate_keypair(&mut self, rng: &mut WolfRng) -> Result<HpkeKeyPair, WolfCryptError> {
        let mut key: *mut c_void = ptr::null_mut();
        // SAFETY: `self.hpke` is initialised, `rng.rng` is initialised,
        // and `key` is a valid out-pointer.
        let rc =
            unsafe { wc_HpkeGenerateKeyPair(&mut *self.hpke.get(), &mut key, &mut rng.rng) };
        check(rc, "wc_HpkeGenerateKeyPair")?;
        if key.is_null() {
            return Err(WolfCryptError::AllocFailed);
        }
        Ok(HpkeKeyPair {
            key,
            kem: self.suite.kem,
            suite: self.suite,
            hpke: Arc::clone(&self.hpke),
        })
    }

    /// Deserialize a public key from bytes, returning an [`HpkeKeyPair`]
    /// suitable for use as a receiver public key in [`seal_base`](Self::seal_base).
    ///
    /// The deserialized key pair contains only the public component.
    pub fn deserialize_public_key(&mut self, enc: &[u8]) -> Result<HpkeKeyPair, WolfCryptError> {
        let mut key: *mut c_void = ptr::null_mut();
        // SAFETY: `self.hpke` is initialised, `enc` is a valid byte slice.
        let rc = unsafe {
            wc_HpkeDeserializePublicKey(
                &mut *self.hpke.get(),
                &mut key,
                enc.as_ptr(),
                enc.len() as u16,
            )
        };
        check(rc, "wc_HpkeDeserializePublicKey")?;
        if key.is_null() {
            return Err(WolfCryptError::AllocFailed);
        }
        Ok(HpkeKeyPair {
            key,
            kem: self.suite.kem,
            suite: self.suite,
            hpke: Arc::clone(&self.hpke),
        })
    }

    /// One-shot Base-mode seal (encrypt).
    ///
    /// Returns `(enc, ciphertext)` where:
    /// - `enc` is the serialized ephemeral public key (encapsulated key)
    /// - `ciphertext` is the encrypted plaintext with an appended AEAD tag
    ///
    /// The caller must transmit both `enc` and `ciphertext` to the receiver.
    pub fn seal_base(
        &mut self,
        ephemeral: &mut HpkeKeyPair,
        receiver_pub: &mut HpkeKeyPair,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), WolfCryptError> {
        // 1. Serialize the ephemeral public key to produce `enc`.
        let enc = ephemeral.serialize_public_key()?;

        // 2. Allocate ciphertext buffer: plaintext + AEAD tag.
        let ct_len = plaintext.len() + self.suite.tag_len();
        let mut ciphertext = vec![0u8; ct_len];

        // We need mutable copies of info, aad, and plaintext because the FFI
        // declares them as `*mut u8` (wolfSSL quirk — they are read-only).
        let mut info_buf = Vec::from(info);
        let mut aad_buf = Vec::from(aad);
        let mut pt_buf = Vec::from(plaintext);

        // SAFETY: All pointers are valid, buffers are correctly sized, and
        // the hpke context is initialised.
        let rc = unsafe {
            wc_HpkeSealBase(
                &mut *self.hpke.get(),
                ephemeral.key,
                receiver_pub.key,
                info_buf.as_mut_ptr(),
                len_as_u32(info_buf.len()),
                aad_buf.as_mut_ptr(),
                len_as_u32(aad_buf.len()),
                pt_buf.as_mut_ptr(),
                len_as_u32(pt_buf.len()),
                ciphertext.as_mut_ptr(),
            )
        };
        check(rc, "wc_HpkeSealBase")?;

        Ok((enc, ciphertext))
    }

    /// One-shot Base-mode open (decrypt).
    ///
    /// - `receiver` — the receiver's key pair (must include the private key)
    /// - `enc` — the encapsulated key (serialized sender ephemeral public key)
    /// - `info` — the info string used during sealing
    /// - `aad` — the associated data used during sealing
    /// - `ciphertext` — the ciphertext with appended AEAD tag
    ///
    /// Returns the decrypted plaintext.
    pub fn open_base(
        &mut self,
        receiver: &mut HpkeKeyPair,
        enc: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, WolfCryptError> {
        let tag_len = self.suite.tag_len();
        if ciphertext.len() < tag_len {
            return Err(WolfCryptError::InvalidInput);
        }
        let pt_len = ciphertext.len() - tag_len;
        let mut plaintext = vec![0u8; pt_len];

        // Mutable copies for the `*mut u8` FFI parameters.
        let mut info_buf = Vec::from(info);
        let mut aad_buf = Vec::from(aad);
        let mut ct_buf = Vec::from(ciphertext);

        // SAFETY: All pointers are valid, buffers are correctly sized, and
        // the hpke context is initialised.
        let rc = unsafe {
            wc_HpkeOpenBase(
                &mut *self.hpke.get(),
                receiver.key,
                enc.as_ptr(),
                enc.len() as u16,
                info_buf.as_mut_ptr(),
                len_as_u32(info_buf.len()),
                aad_buf.as_mut_ptr(),
                len_as_u32(aad_buf.len()),
                ct_buf.as_mut_ptr(),
                len_as_u32(ct_buf.len()),
                plaintext.as_mut_ptr(),
            )
        };
        check(rc, "wc_HpkeOpenBase")?;

        Ok(plaintext)
    }
}

// SAFETY: `WcHpke` is a self-contained context with no thread affinity.
unsafe impl Send for Hpke {}

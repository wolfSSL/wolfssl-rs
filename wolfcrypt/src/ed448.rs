//! Ed448 signing and verification backed by wolfCrypt.
//!
//! Provides [`Ed448SigningKey`] and [`Ed448VerifyingKey`] that implement the
//! RustCrypto [`signature::Signer`] and [`signature::Verifier`] traits
//! respectively, using a custom [`Ed448Signature`] type (there is no upstream
//! `ed448` trait crate in the RustCrypto ecosystem).

use core::cell::UnsafeCell;

use crate::error::{check, len_as_u32, WolfCryptError};
use wolfcrypt_rs::{
    wc_FreeRng, wc_InitRng, wc_ed448_export_public, wc_ed448_free, wc_ed448_import_private_key,
    wc_ed448_import_private_only, wc_ed448_import_public, wc_ed448_init, wc_ed448_key,
    wc_ed448_make_key, wc_ed448_make_public, wc_ed448_sign_msg, wc_ed448_verify_msg, WC_RNG,
};

/// Ed448 key size in bytes (seed = 57 bytes).
const ED448_KEY_SIZE: usize = 57;
/// Ed448 signature size in bytes.
const ED448_SIG_SIZE: usize = 114;

// ---------------------------------------------------------------------------
// Ed448Signature
// ---------------------------------------------------------------------------

/// An Ed448 signature (114 bytes).
#[derive(Clone, Debug)]
pub struct Ed448Signature([u8; ED448_SIG_SIZE]);

impl Ed448Signature {
    /// Create an `Ed448Signature` from a 114-byte array.
    pub fn from_bytes(bytes: &[u8; ED448_SIG_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Return the signature as a byte array.
    pub fn to_bytes(&self) -> [u8; ED448_SIG_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for Ed448Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Ed448Signature {
    type Error = signature_trait::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; ED448_SIG_SIZE] = bytes
            .try_into()
            .map_err(|_| signature_trait::Error::new())?;
        Ok(Self(arr))
    }
}

impl signature_trait::SignatureEncoding for Ed448Signature {
    type Repr = [u8; ED448_SIG_SIZE];
}

impl From<Ed448Signature> for [u8; ED448_SIG_SIZE] {
    fn from(sig: Ed448Signature) -> Self {
        sig.0
    }
}

impl From<[u8; ED448_SIG_SIZE]> for Ed448Signature {
    fn from(bytes: [u8; ED448_SIG_SIZE]) -> Self {
        Self(bytes)
    }
}

// ---------------------------------------------------------------------------
// Ed448SigningKey
// ---------------------------------------------------------------------------

/// An Ed448 signing key (private key) backed by wolfCrypt.
///
/// Holds both the private and public components so that it can produce
/// signatures and derive the corresponding [`Ed448VerifyingKey`].
pub struct Ed448SigningKey {
    /// Interior mutability: wolfCrypt sign requires `*mut` even though
    /// the `Signer` trait provides only `&self`.
    key: UnsafeCell<wc_ed448_key>,
    /// wolfCrypt RNG needed internally by `wc_ed448_sign_msg`.
    rng: UnsafeCell<WC_RNG>,
}

// SAFETY: `wc_ed448_key` and `WC_RNG` own independent state with no shared
// mutable globals, so the struct can safely be moved between threads.
unsafe impl Send for Ed448SigningKey {}

impl Ed448SigningKey {
    /// Create a signing key from a 57-byte seed (private key).
    ///
    /// This imports the seed, derives the public key, and initialises an
    /// internal RNG for future sign operations.
    pub fn from_seed(seed: &[u8; ED448_KEY_SIZE]) -> Result<Self, WolfCryptError> {
        let mut key = wc_ed448_key::zeroed();

        // SAFETY: `key` is zeroed and `wc_ed448_init` will fully initialise it.
        let rc = unsafe { wc_ed448_init(&mut key) };
        check(rc, "wc_ed448_init")?;

        // Import the seed so that `wc_ed448_make_public` (below) can
        // derive the public key — it checks `privKeySet` and fails without
        // this.  `import_private_key` later overwrites `key->k`, but this
        // step is load-bearing, not redundant.
        //
        // SAFETY: `key` is initialised. We import exactly 57 bytes of seed.
        let rc =
            unsafe { wc_ed448_import_private_only(seed.as_ptr(), ED448_KEY_SIZE as u32, &mut key) };
        check(rc, "wc_ed448_import_private_only")?;

        // Derive the public key from the imported seed.
        //
        // `wc_ed448_make_public` writes the public key to its output
        // buffer but does NOT copy it into `key->p` — it only sets the
        // `pubKeySet` flag.  If we wrote to a stack buffer and stopped
        // here, the signing function would read zeros from `key->p` and
        // produce wrong signatures.
        //
        // To properly populate all internal fields (`key->p` and
        // `key->k[57..113]`), we re-import both the seed and the derived
        // public key via `wc_ed448_import_private_key`, which mirrors
        // the setup that `wc_ed448_make_key` performs internally.
        let mut pub_buf = [0u8; ED448_KEY_SIZE];
        // SAFETY: `key` has a private key set. `pub_buf` is exactly
        // ED448_KEY_SIZE (57) bytes as required by `make_public`.
        let rc =
            unsafe { wc_ed448_make_public(&mut key, pub_buf.as_mut_ptr(), ED448_KEY_SIZE as u32) };
        check(rc, "wc_ed448_make_public")?;

        // SAFETY: `seed` is 57 bytes, `pub_buf` is 57 bytes of the just-
        // derived public key. This copies seed → key->k[0..56], pub →
        // key->p, pub → key->k[57..113], and sets both privKeySet and
        // pubKeySet.
        let rc = unsafe {
            wc_ed448_import_private_key(
                seed.as_ptr(),
                ED448_KEY_SIZE as u32,
                pub_buf.as_ptr(),
                ED448_KEY_SIZE as u32,
                &mut key,
            )
        };
        check(rc, "wc_ed448_import_private_key")?;

        // Initialise the internal RNG for signing.
        let mut rng = WC_RNG::zeroed();
        // SAFETY: `rng` is zeroed and will be fully initialised by `wc_InitRng`.
        let rc = unsafe { wc_InitRng(&mut rng) };
        check(rc, "wc_InitRng")?;

        Ok(Self {
            key: UnsafeCell::new(key),
            rng: UnsafeCell::new(rng),
        })
    }

    /// Generate a random Ed448 keypair using the provided RNG.
    pub fn generate(rng: &mut crate::rand::WolfRng) -> Result<Self, WolfCryptError> {
        let mut key = wc_ed448_key::zeroed();

        // SAFETY: `key` is zeroed and `wc_ed448_init` will fully initialise it.
        let rc = unsafe { wc_ed448_init(&mut key) };
        check(rc, "wc_ed448_init")?;

        // SAFETY: `key` is initialised, `rng.rng` is a valid WC_RNG.
        // Key size is 57 for Ed448.
        let rc = unsafe { wc_ed448_make_key(&mut rng.rng, ED448_KEY_SIZE as i32, &mut key) };
        check(rc, "wc_ed448_make_key")?;

        // Initialise an internal RNG owned by this signing key for future sign calls.
        let mut own_rng = WC_RNG::zeroed();
        // SAFETY: `own_rng` is zeroed and will be fully initialised.
        let rc = unsafe { wc_InitRng(&mut own_rng) };
        check(rc, "wc_InitRng")?;

        Ok(Self {
            key: UnsafeCell::new(key),
            rng: UnsafeCell::new(own_rng),
        })
    }

    /// Return the corresponding verifying (public) key.
    pub fn verifying_key(&self) -> Ed448VerifyingKey {
        let mut pub_buf = [0u8; ED448_KEY_SIZE];
        let mut pub_len: u32 = ED448_KEY_SIZE as u32;

        // SAFETY: the key is fully initialised with both private and public
        // components. `wc_ed448_export_public` takes `*const` so no
        // mutation occurs.
        let rc = unsafe {
            wc_ed448_export_public(
                self.key.get() as *const _,
                pub_buf.as_mut_ptr(),
                &mut pub_len,
            )
        };
        assert_eq!(rc, 0, "wc_ed448_export_public failed (key not initialized)");

        Ed448VerifyingKey::from_bytes(&pub_buf).expect("exported public key must be valid")
    }
}

impl Drop for Ed448SigningKey {
    fn drop(&mut self) {
        // SAFETY: the key and RNG were successfully initialised during
        // construction. We free each exactly once.
        unsafe {
            wc_ed448_free(self.key.get_mut());
            wc_FreeRng(self.rng.get_mut());
        }
    }
}

impl signature_trait::Signer<Ed448Signature> for Ed448SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Ed448Signature, signature_trait::Error> {
        let mut sig_buf = [0u8; ED448_SIG_SIZE];
        let mut sig_len: u32 = ED448_SIG_SIZE as u32;

        // SAFETY: `self.key` and `self.rng` are initialised. The key has both
        // private and public components. `sig_buf` is 114 bytes, enough for an
        // Ed448 signature. For standard Ed448 (not Ed448ph), we pass null
        // context and zero contextLen.
        let rc = unsafe {
            wc_ed448_sign_msg(
                msg.as_ptr(),
                len_as_u32(msg.len()),
                sig_buf.as_mut_ptr(),
                &mut sig_len,
                self.key.get(),
                core::ptr::null(),
                0,
            )
        };

        if rc != 0 {
            return Err(signature_trait::Error::new());
        }

        Ok(Ed448Signature(sig_buf))
    }
}

// ---------------------------------------------------------------------------
// Ed448VerifyingKey
// ---------------------------------------------------------------------------

/// An Ed448 verifying key (public key) backed by wolfCrypt.
pub struct Ed448VerifyingKey {
    /// Interior mutability: `wc_ed448_verify_msg` requires `*mut`.
    key: UnsafeCell<wc_ed448_key>,
    /// Cached copy of the 57-byte public key for cheap `as_bytes()` access.
    pub_bytes: [u8; ED448_KEY_SIZE],
}

// SAFETY: `wc_ed448_key` owns independent state with no shared mutable
// globals, so the struct can safely be moved between threads.
unsafe impl Send for Ed448VerifyingKey {}

impl Ed448VerifyingKey {
    /// Construct a verifying key from 57 raw public key bytes.
    pub fn from_bytes(bytes: &[u8; ED448_KEY_SIZE]) -> Result<Self, WolfCryptError> {
        let mut key = wc_ed448_key::zeroed();

        // SAFETY: `key` is zeroed and `wc_ed448_init` will fully initialise it.
        let rc = unsafe { wc_ed448_init(&mut key) };
        check(rc, "wc_ed448_init")?;

        // SAFETY: `key` is initialised. We import exactly 57 bytes of public key.
        let rc = unsafe { wc_ed448_import_public(bytes.as_ptr(), ED448_KEY_SIZE as u32, &mut key) };
        check(rc, "wc_ed448_import_public")?;

        Ok(Self {
            key: UnsafeCell::new(key),
            pub_bytes: *bytes,
        })
    }

    /// Return a reference to the raw 57-byte public key.
    pub fn as_bytes(&self) -> &[u8; ED448_KEY_SIZE] {
        &self.pub_bytes
    }
}

impl Drop for Ed448VerifyingKey {
    fn drop(&mut self) {
        // SAFETY: `self.key` was successfully initialised during construction.
        // We free it exactly once.
        unsafe {
            wc_ed448_free(self.key.get_mut());
        }
    }
}

impl signature_trait::Verifier<Ed448Signature> for Ed448VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Ed448Signature) -> Result<(), signature_trait::Error> {
        let sig_bytes = signature.to_bytes();
        let mut result: i32 = 0;

        // SAFETY: `self.key` is initialised with a valid public key.
        // `sig_bytes` is exactly 114 bytes. `result` receives 1 if the
        // signature is valid, 0 otherwise. For standard Ed448 (not Ed448ph),
        // we pass null context and zero contextLen.
        let rc = unsafe {
            wc_ed448_verify_msg(
                sig_bytes.as_ptr(),
                len_as_u32(sig_bytes.len()),
                msg.as_ptr(),
                len_as_u32(msg.len()),
                &mut result,
                self.key.get(),
                core::ptr::null(),
                0,
            )
        };

        if rc != 0 || result != 1 {
            return Err(signature_trait::Error::new());
        }

        Ok(())
    }
}

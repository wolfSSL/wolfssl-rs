//! Ed25519 signing and verification backed by wolfCrypt.
//!
//! Provides [`Ed25519SigningKey`] and [`Ed25519VerifyingKey`] that implement the
//! RustCrypto [`signature::Signer`] and [`signature::Verifier`] traits
//! respectively, using the `ed25519` crate's [`ed25519::Signature`] type.

use core::cell::UnsafeCell;

use crate::error::{check, len_as_u32, WolfCryptError};
use wolfcrypt_rs::{
    wc_FreeRng, wc_InitRng, wc_ed25519_check_key, wc_ed25519_export_public, wc_ed25519_free,
    wc_ed25519_import_private_key, wc_ed25519_import_private_only, wc_ed25519_import_public,
    wc_ed25519_init, wc_ed25519_key, wc_ed25519_make_key, wc_ed25519_make_public,
    wc_ed25519_sign_msg, wc_ed25519_verify_msg, WC_RNG,
};

/// Ed25519 key size in bytes (seed = 32 bytes).
const ED25519_KEY_SIZE: usize = 32;
/// Ed25519 signature size in bytes.
const ED25519_SIG_SIZE: usize = 64;

/// An Ed25519 signing key (private key) backed by wolfCrypt.
///
/// Holds both the private and public components so that it can produce
/// signatures and derive the corresponding [`Ed25519VerifyingKey`].
pub struct Ed25519SigningKey {
    /// Interior mutability: wolfCrypt sign requires `*mut` even though
    /// the `Signer` trait provides only `&self`.
    key: UnsafeCell<wc_ed25519_key>,
    /// wolfCrypt RNG needed internally by `wc_ed25519_sign_msg`.
    rng: UnsafeCell<WC_RNG>,
}

// SAFETY: `wc_ed25519_key` and `WC_RNG` own independent state with no shared
// mutable globals, so the struct can safely be moved between threads.
unsafe impl Send for Ed25519SigningKey {}

impl Ed25519SigningKey {
    /// Create a signing key from a 32-byte seed (private key).
    ///
    /// This imports the seed, derives the public key, and initialises an
    /// internal RNG for future sign operations.
    pub fn from_seed(seed: &[u8; ED25519_KEY_SIZE]) -> Result<Self, WolfCryptError> {
        let mut key = wc_ed25519_key::zeroed();

        // SAFETY: `key` is zeroed and `wc_ed25519_init` will fully initialise it.
        let rc = unsafe { wc_ed25519_init(&mut key) };
        check(rc, "wc_ed25519_init")?;

        // Import the seed so that `wc_ed25519_make_public` (below) can
        // derive the public key — it checks `privKeySet` and fails without
        // this.  `import_private_key` later overwrites `key->k`, but this
        // step is load-bearing, not redundant.
        //
        // SAFETY: `key` is initialised. We import exactly 32 bytes of seed.
        let rc = unsafe {
            wc_ed25519_import_private_only(seed.as_ptr(), ED25519_KEY_SIZE as u32, &mut key)
        };
        check(rc, "wc_ed25519_import_private_only")?;

        // Derive the public key from the imported seed.
        //
        // `wc_ed25519_make_public` writes the public key to its output
        // buffer but does NOT copy it into `key->p` — it only sets the
        // `pubKeySet` flag.  If we wrote to a stack buffer and stopped
        // here, the signing function would read zeros from `key->p` and
        // produce wrong signatures.
        //
        // To properly populate all internal fields (`key->p` and
        // `key->k[32..63]`), we re-import both the seed and the derived
        // public key via `wc_ed25519_import_private_key`, which mirrors
        // the setup that `wc_ed25519_make_key` performs internally.
        let mut pub_buf = [0u8; ED25519_KEY_SIZE];
        // SAFETY: `key` has a private key set. `pub_buf` is exactly
        // ED25519_KEY_SIZE (32) bytes as required by `make_public`.
        let rc = unsafe {
            wc_ed25519_make_public(&mut key, pub_buf.as_mut_ptr(), ED25519_KEY_SIZE as u32)
        };
        check(rc, "wc_ed25519_make_public")?;

        // SAFETY: `seed` is 32 bytes, `pub_buf` is 32 bytes of the just-
        // derived public key. This copies seed → key->k[0..31], pub →
        // key->p, pub → key->k[32..63], and sets both privKeySet and
        // pubKeySet.
        let rc = unsafe {
            wc_ed25519_import_private_key(
                seed.as_ptr(),
                ED25519_KEY_SIZE as u32,
                pub_buf.as_ptr(),
                ED25519_KEY_SIZE as u32,
                &mut key,
            )
        };
        check(rc, "wc_ed25519_import_private_key")?;

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

    /// Generate a random Ed25519 keypair using the provided RNG.
    pub fn generate(rng: &mut crate::rand::WolfRng) -> Result<Self, WolfCryptError> {
        let mut key = wc_ed25519_key::zeroed();

        // SAFETY: `key` is zeroed and `wc_ed25519_init` will fully initialise it.
        let rc = unsafe { wc_ed25519_init(&mut key) };
        check(rc, "wc_ed25519_init")?;

        // SAFETY: `key` is initialised, `rng.rng` is a valid WC_RNG.
        // Key size is 32 for Ed25519.
        let rc = unsafe { wc_ed25519_make_key(&mut rng.rng, ED25519_KEY_SIZE as i32, &mut key) };
        check(rc, "wc_ed25519_make_key")?;

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
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        let mut pub_buf = [0u8; ED25519_KEY_SIZE];
        let mut pub_len: u32 = ED25519_KEY_SIZE as u32;

        // SAFETY: the key is fully initialised with both private and public
        // components. `wc_ed25519_export_public` takes `*const` so no
        // mutation occurs.
        let rc = unsafe {
            wc_ed25519_export_public(
                self.key.get() as *const _,
                pub_buf.as_mut_ptr(),
                &mut pub_len,
            )
        };
        assert_eq!(
            rc, 0,
            "wc_ed25519_export_public failed (key not initialized)"
        );

        Ed25519VerifyingKey::from_bytes(&pub_buf).expect("exported public key must be valid")
    }
}

impl Drop for Ed25519SigningKey {
    fn drop(&mut self) {
        // SAFETY: the key and RNG were successfully initialised during
        // construction. We free each exactly once.
        unsafe {
            wc_ed25519_free(self.key.get_mut());
            wc_FreeRng(self.rng.get_mut());
        }
    }
}

impl signature_trait::Signer<ed25519_trait::Signature> for Ed25519SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519_trait::Signature, signature_trait::Error> {
        let mut sig_buf = [0u8; ED25519_SIG_SIZE];
        let mut sig_len: u32 = ED25519_SIG_SIZE as u32;

        // SAFETY: `self.key` and `self.rng` are initialised. The key has both
        // private and public components. `sig_buf` is 64 bytes, enough for an
        // Ed25519 signature. We use `UnsafeCell::get()` to obtain `*mut`
        // pointers because wolfCrypt's C API requires mutable pointers even
        // though the logical key material is not modified. This is safe
        // because we do not alias these pointers and Ed25519 signing is
        // deterministic (the RNG pointer is carried in the struct but not
        // used for Ed25519 pure signing in wolfCrypt).
        let rc = unsafe {
            wc_ed25519_sign_msg(
                msg.as_ptr(),
                len_as_u32(msg.len()),
                sig_buf.as_mut_ptr(),
                &mut sig_len,
                self.key.get(),
            )
        };

        if rc != 0 {
            return Err(signature_trait::Error::new());
        }

        Ok(ed25519_trait::Signature::from_bytes(&sig_buf))
    }
}

// ---------------------------------------------------------------------------
// Ed25519VerifyingKey
// ---------------------------------------------------------------------------

/// An Ed25519 verifying key (public key) backed by wolfCrypt.
pub struct Ed25519VerifyingKey {
    /// Interior mutability: `wc_ed25519_verify_msg` requires `*mut`.
    key: UnsafeCell<wc_ed25519_key>,
    /// Cached copy of the 32-byte public key for cheap `as_bytes()` access.
    pub_bytes: [u8; ED25519_KEY_SIZE],
}

// SAFETY: `wc_ed25519_key` owns independent state with no shared mutable
// globals, so the struct can safely be moved between threads.
unsafe impl Send for Ed25519VerifyingKey {}

impl Ed25519VerifyingKey {
    /// Construct a verifying key from 32 raw public key bytes.
    pub fn from_bytes(bytes: &[u8; ED25519_KEY_SIZE]) -> Result<Self, WolfCryptError> {
        let mut key = wc_ed25519_key::zeroed();

        // SAFETY: `key` is zeroed and `wc_ed25519_init` will fully initialise it.
        let rc = unsafe { wc_ed25519_init(&mut key) };
        check(rc, "wc_ed25519_init")?;

        // SAFETY: `key` is initialised. We import exactly 32 bytes of public key.
        let rc =
            unsafe { wc_ed25519_import_public(bytes.as_ptr(), ED25519_KEY_SIZE as u32, &mut key) };
        check(rc, "wc_ed25519_import_public")?;

        Ok(Self {
            key: UnsafeCell::new(key),
            pub_bytes: *bytes,
        })
    }

    /// Return a reference to the raw 32-byte public key.
    pub fn as_bytes(&self) -> &[u8; ED25519_KEY_SIZE] {
        &self.pub_bytes
    }

    /// Validate that the imported public key is a valid point on the Ed25519
    /// curve.
    ///
    /// `from_bytes` imports the raw bytes into wolfCrypt but does not call
    /// `wc_ed25519_check_key`. Call this method when the bytes come from an
    /// untrusted source (e.g. a hardware device response) to reject invalid or
    /// low-order points before using the key for verification.
    ///
    /// # Errors
    ///
    /// Returns `Err(WolfCryptError)` if wolfCrypt reports the key is invalid.
    pub fn check_key(&mut self) -> Result<(), WolfCryptError> {
        // SAFETY: `self.key` is initialised and has a public key set.
        // `wc_ed25519_check_key` reads the key but takes `*mut` per the C API
        // convention; no mutation occurs in practice.
        let rc = unsafe { wc_ed25519_check_key(self.key.get()) };
        check(rc, "wc_ed25519_check_key")
    }
}

impl Drop for Ed25519VerifyingKey {
    fn drop(&mut self) {
        // SAFETY: `self.key` was successfully initialised during construction.
        // We free it exactly once.
        unsafe {
            wc_ed25519_free(self.key.get_mut());
        }
    }
}

impl signature_trait::Verifier<ed25519_trait::Signature> for Ed25519VerifyingKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &ed25519_trait::Signature,
    ) -> Result<(), signature_trait::Error> {
        let sig_bytes = signature.to_bytes();
        let mut result: i32 = 0;

        // SAFETY: `self.key` is initialised with a valid public key.
        // `sig_bytes` is exactly 64 bytes. `result` receives 1 if the
        // signature is valid, 0 otherwise. We use `UnsafeCell::get()` for
        // the mutable pointer required by wolfCrypt's C API; the public key
        // material is not logically modified.
        let rc = unsafe {
            wc_ed25519_verify_msg(
                sig_bytes.as_ptr(),
                len_as_u32(sig_bytes.len()),
                msg.as_ptr(),
                len_as_u32(msg.len()),
                &mut result,
                self.key.get(),
            )
        };

        if rc != 0 || result != 1 {
            return Err(signature_trait::Error::new());
        }

        Ok(())
    }
}

// -----------------------------------------------------------------------
// Standalone sign/verify functions (trait-version-independent)
// -----------------------------------------------------------------------

/// Sign a message with an Ed25519 key using wolfCrypt directly.
///
/// This is a standalone function that does not go through the `signature`
/// crate's traits, making it usable regardless of which `signature` crate
/// version the caller depends on.
///
/// - `seed`: 32-byte private key seed
/// - `pub_key`: 32-byte public key
/// - `message`: arbitrary-length message
///
/// Returns the 64-byte Ed25519 signature.
pub fn ed25519_sign_raw(
    seed: &[u8],
    pub_key: &[u8],
    message: &[u8],
) -> Result<[u8; 64], WolfCryptError> {
    let mut key = wc_ed25519_key::zeroed();

    // SAFETY: `key` is zeroed; `wc_ed25519_init` will fully initialise it.
    let rc = unsafe { wc_ed25519_init(&mut key) };
    check(rc, "wc_ed25519_init")?;

    // SAFETY: `key` is initialised. `seed` and `pub_key` are valid slices
    // with lengths passed via `len_as_u32`.
    let rc = unsafe {
        wc_ed25519_import_private_key(
            seed.as_ptr(),
            len_as_u32(seed.len()),
            pub_key.as_ptr(),
            len_as_u32(pub_key.len()),
            &mut key,
        )
    };
    if rc != 0 {
        // SAFETY: `key` was successfully initialised; freed exactly once.
        unsafe { wc_ed25519_free(&mut key) };
        return Err(WolfCryptError::Ffi {
            code: rc,
            func: "wc_ed25519_import_private_key",
        });
    }

    let mut sig = [0u8; 64];
    let mut sig_len: u32 = 64;
    // SAFETY: `key` has both private and public components imported.
    // `message` is a valid slice; `sig` is a 64-byte output buffer.
    let rc = unsafe {
        wc_ed25519_sign_msg(
            message.as_ptr(),
            len_as_u32(message.len()),
            sig.as_mut_ptr(),
            &mut sig_len,
            &mut key,
        )
    };
    // SAFETY: `key` was successfully initialised; freed exactly once.
    unsafe { wc_ed25519_free(&mut key) };
    check(rc, "wc_ed25519_sign_msg")?;

    Ok(sig)
}

/// Verify an Ed25519 signature using wolfCrypt directly.
///
/// This is a standalone function that does not go through the `signature`
/// crate's traits.
///
/// - `pub_key`: 32-byte public key
/// - `message`: the signed message
/// - `sig`: 64-byte signature
///
/// Returns `Ok(())` if valid, `Err` if invalid or on error.
pub fn ed25519_verify_raw(
    pub_key: &[u8],
    message: &[u8],
    sig: &[u8],
) -> Result<(), WolfCryptError> {
    let mut key = wc_ed25519_key::zeroed();

    // SAFETY: `key` is zeroed; `wc_ed25519_init` will fully initialise it.
    let rc = unsafe { wc_ed25519_init(&mut key) };
    check(rc, "wc_ed25519_init")?;

    // SAFETY: `key` is initialised. `pub_key` is a valid slice with length passed via `len_as_u32`.
    let rc =
        unsafe { wc_ed25519_import_public(pub_key.as_ptr(), len_as_u32(pub_key.len()), &mut key) };
    if rc != 0 {
        // SAFETY: `key` was successfully initialised; freed exactly once.
        unsafe { wc_ed25519_free(&mut key) };
        return Err(WolfCryptError::Ffi {
            code: rc,
            func: "wc_ed25519_import_public",
        });
    }

    let mut result: core::ffi::c_int = 0;
    // SAFETY: `key` has a valid public key imported. `sig` and `message`
    // are valid slices. `result` receives 1 if valid, 0 otherwise.
    let rc = unsafe {
        wc_ed25519_verify_msg(
            sig.as_ptr(),
            len_as_u32(sig.len()),
            message.as_ptr(),
            len_as_u32(message.len()),
            &mut result,
            &mut key,
        )
    };
    // SAFETY: `key` was successfully initialised; freed exactly once.
    unsafe { wc_ed25519_free(&mut key) };
    check(rc, "wc_ed25519_verify_msg")?;

    if result == 1 {
        Ok(())
    } else {
        Err(WolfCryptError::SigInvalid)
    }
}

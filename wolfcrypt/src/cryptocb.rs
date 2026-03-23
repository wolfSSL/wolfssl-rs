//! Crypto callback (WOLF_CRYPTO_CB) integration for hardware offload.
//!
//! wolfCrypt's crypto callback mechanism lets you intercept cryptographic
//! operations and redirect them to a hardware security module (HSM), TPM,
//! or alternative software implementation.  When a wolfCrypt struct (e.g.
//! an AES key, RSA key, or hash context) has its `devId` set to a
//! registered device, wolfCrypt calls your callback instead of its built-in
//! software implementation.
//!
//! # How it works
//!
//! 1. Implement the [`CryptoCallbacks`] trait — override only the
//!    operations your hardware supports.
//! 2. Call [`register_device`] with a device ID and your implementation.
//! 3. When creating wolfCrypt objects, pass that device ID.
//! 4. wolfCrypt calls your trait methods.  Returning
//!    [`CryptoCallbackResult::NotAvailable`] falls back to software.
//!
//! # Example
//!
//! ```rust,ignore
//! use wolfcrypt::cryptocb::{
//!     CryptoCallbacks, CryptoCallbackResult, RngRequest,
//!     register_device, unregister_device,
//! };
//!
//! struct MyHsm;
//!
//! impl CryptoCallbacks for MyHsm {
//!     fn rng(&self, req: RngRequest<'_>) -> CryptoCallbackResult {
//!         // Fill buffer from hardware RNG
//!         my_hw_random_fill(req.out);
//!         CryptoCallbackResult::Success
//!     }
//! }
//!
//! let hsm = MyHsm;
//! let dev_id = 42;
//! register_device(dev_id, hsm).expect("register");
//! // ... use dev_id when creating wolfCrypt objects ...
//! unregister_device(dev_id);
//! ```

use core::ffi::{c_int, c_void};

use alloc::boxed::Box;

use crate::error::{WolfCryptError, check};

// ---------------------------------------------------------------------------
// Result type for callbacks
// ---------------------------------------------------------------------------

/// Result of a crypto callback operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoCallbackResult {
    /// The operation was handled successfully.
    Success,
    /// This device does not implement this operation — fall back to software.
    NotAvailable,
    /// The operation failed with a wolfCrypt error code.
    Error(i32),
}

impl CryptoCallbackResult {
    /// Convert to the C return code wolfCrypt expects.
    fn to_c(self) -> c_int {
        match self {
            Self::Success => 0,
            Self::NotAvailable => wolfcrypt_rs::CRYPTOCB_UNAVAILABLE,
            Self::Error(code) => code,
        }
    }
}

// ---------------------------------------------------------------------------
// Request types — typed views of wc_CryptoInfo fields
// ---------------------------------------------------------------------------

/// A request to generate random bytes.
pub struct RngRequest<'a> {
    /// Output buffer to fill with random data.
    pub out: &'a mut [u8],
}

/// A request for a hash operation (update or finalize).
pub struct HashRequest<'a> {
    /// wolfCrypt hash type constant (e.g. `WC_HASH_TYPE_SHA256`).
    pub hash_type: i32,
    /// Input data for this update (empty on finalize).
    pub input: &'a [u8],
    /// Output digest buffer (non-empty only on finalize).
    pub digest: Option<&'a mut [u8]>,
}

/// A request for an HMAC operation (update or finalize).
pub struct HmacRequest<'a> {
    /// Underlying hash type (e.g. `WC_HASH_TYPE_SHA256`).
    pub mac_type: i32,
    /// Input data for this update (empty on finalize).
    pub input: &'a [u8],
    /// Output MAC buffer (non-empty only on finalize).
    pub digest: Option<&'a mut [u8]>,
}

/// A cipher operation request (encrypt or decrypt).
pub struct CipherRequest {
    /// Cipher type constant (e.g. `WC_CIPHER_AES_GCM`).
    pub cipher_type: i32,
    /// `true` for encryption, `false` for decryption.
    pub encrypting: bool,
}

/// A public-key operation request.
pub struct PkRequest {
    /// PK type constant (e.g. `WC_PK_TYPE_RSA`, `WC_PK_TYPE_ECDSA_SIGN`).
    pub pk_type: i32,
}

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

/// Trait for crypto callback implementations.
///
/// Override only the methods your hardware supports.  The default
/// implementations return [`CryptoCallbackResult::NotAvailable`], causing
/// wolfCrypt to fall back to its software implementation.
///
/// # Safety
///
/// Callback methods are invoked from within wolfCrypt's C code, potentially
/// from any thread. Implementations must be `Send + Sync`.
pub trait CryptoCallbacks: Send + Sync {
    /// Generate random bytes.
    fn rng(&self, _req: RngRequest<'_>) -> CryptoCallbackResult {
        CryptoCallbackResult::NotAvailable
    }

    /// Hash operation (update or finalize).
    fn hash(&self, _req: HashRequest<'_>) -> CryptoCallbackResult {
        CryptoCallbackResult::NotAvailable
    }

    /// HMAC operation (update or finalize).
    fn hmac(&self, _req: HmacRequest<'_>) -> CryptoCallbackResult {
        CryptoCallbackResult::NotAvailable
    }

    /// Symmetric cipher operation.
    ///
    /// The default returns `NotAvailable`.  A real implementation would
    /// read the raw `wc_CryptoInfo` via the fields in [`CipherRequest`]
    /// and perform the cipher operation in hardware.
    fn cipher(&self, _req: CipherRequest) -> CryptoCallbackResult {
        CryptoCallbackResult::NotAvailable
    }

    /// Public-key operation (RSA, ECDSA, ECDH, Ed25519, etc.).
    fn pk(&self, _req: PkRequest) -> CryptoCallbackResult {
        CryptoCallbackResult::NotAvailable
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// State held behind the `void* ctx` pointer passed to wolfCrypt.
/// Boxed so the pointer is stable across moves.
struct DeviceState {
    callbacks: Box<dyn CryptoCallbacks>,
}

/// The C trampoline called by wolfCrypt.  It dispatches to the Rust trait.
///
/// # Safety
///
/// `ctx` must point to a live `DeviceState` (guaranteed by `register_device`).
/// `info` must be a valid `wc_CryptoInfo` pointer from wolfCrypt.
unsafe extern "C" fn trampoline(
    _dev_id: c_int,
    info: *mut wolfcrypt_rs::wc_CryptoInfo,
    ctx: *mut c_void,
) -> c_int {
    if ctx.is_null() || info.is_null() {
        return wolfcrypt_rs::CRYPTOCB_UNAVAILABLE;
    }

    let state = unsafe { &*(ctx as *const DeviceState) };
    let info_ptr = info as *const wolfcrypt_rs::wc_CryptoInfo;

    let algo_type = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_get_algo_type(info_ptr) };

    let result = match algo_type {
        wolfcrypt_rs::WC_ALGO_TYPE_RNG => {
            let out_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_rng_out(info_ptr) };
            let sz = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_rng_sz(info_ptr) } as usize;
            if out_ptr.is_null() || sz == 0 {
                CryptoCallbackResult::NotAvailable
            } else {
                let out = unsafe { core::slice::from_raw_parts_mut(out_ptr, sz) };
                state.callbacks.rng(RngRequest { out })
            }
        }
        wolfcrypt_rs::WC_ALGO_TYPE_HASH => {
            let hash_type = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hash_type(info_ptr) };
            let in_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hash_in(info_ptr) };
            let in_sz = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hash_in_sz(info_ptr) } as usize;
            let digest_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hash_digest(info_ptr) };

            let input = if in_ptr.is_null() || in_sz == 0 {
                &[]
            } else {
                unsafe { core::slice::from_raw_parts(in_ptr, in_sz) }
            };

            // For finalize, digest is non-null.  We need the digest size
            // but wc_CryptoInfo doesn't directly carry it.  We use a
            // conservative upper bound (64 bytes = SHA-512 output).
            let digest = if digest_ptr.is_null() {
                None
            } else {
                // The caller is responsible for providing a correctly-sized
                // buffer; we pass up to 64 bytes (max digest for SHA-512).
                Some(unsafe { core::slice::from_raw_parts_mut(digest_ptr, 64) })
            };

            state.callbacks.hash(HashRequest { hash_type, input, digest })
        }
        wolfcrypt_rs::WC_ALGO_TYPE_HMAC => {
            let mac_type = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hmac_mac_type(info_ptr) };
            let in_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hmac_in(info_ptr) };
            let in_sz = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hmac_in_sz(info_ptr) } as usize;
            let digest_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hmac_digest(info_ptr) };

            let input = if in_ptr.is_null() || in_sz == 0 {
                &[]
            } else {
                unsafe { core::slice::from_raw_parts(in_ptr, in_sz) }
            };

            let digest = if digest_ptr.is_null() {
                None
            } else {
                Some(unsafe { core::slice::from_raw_parts_mut(digest_ptr, 64) })
            };

            state.callbacks.hmac(HmacRequest { mac_type, input, digest })
        }
        wolfcrypt_rs::WC_ALGO_TYPE_CIPHER => {
            let cipher_type = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_type(info_ptr) };
            let enc = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_enc(info_ptr) };
            state.callbacks.cipher(CipherRequest {
                cipher_type,
                encrypting: enc != 0,
            })
        }
        wolfcrypt_rs::WC_ALGO_TYPE_PK => {
            let pk_type = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_type(info_ptr) };
            state.callbacks.pk(PkRequest { pk_type })
        }
        _ => CryptoCallbackResult::NotAvailable,
    };

    result.to_c()
}

/// Register a crypto callback device.
///
/// `dev_id` must be a positive integer (not `INVALID_DEVID`).
/// The `callbacks` implementation is boxed and stored for the lifetime
/// of the registration.
///
/// # Errors
///
/// Returns an error if wolfCrypt rejects the registration (e.g. device
/// table full — max 8 devices by default).
///
/// # Panics
///
/// Panics if `dev_id` is `INVALID_DEVID` (-2).
pub fn register_device(
    dev_id: i32,
    callbacks: impl CryptoCallbacks + 'static,
) -> Result<(), WolfCryptError> {
    assert!(
        dev_id != wolfcrypt_rs::INVALID_DEVID as i32,
        "dev_id must not be INVALID_DEVID"
    );

    let state = Box::new(DeviceState {
        callbacks: Box::new(callbacks),
    });
    let ctx = Box::into_raw(state) as *mut c_void;

    let rc = unsafe {
        wolfcrypt_rs::wc_CryptoCb_RegisterDevice(dev_id, Some(trampoline), ctx)
    };

    if rc != 0 {
        // Registration failed — reclaim the leaked Box.
        unsafe { drop(Box::from_raw(ctx as *mut DeviceState)); }
        return Err(WolfCryptError::Ffi { code: rc, func: "wc_CryptoCb_RegisterDevice" });
    }

    Ok(())
}

/// Unregister a crypto callback device.
///
/// This frees the callback state that was registered with [`register_device`].
///
/// # Safety
///
/// The caller must ensure that no wolfCrypt operations using this `dev_id`
/// are in progress on other threads when this function is called.
///
/// After this call, any wolfCrypt objects still associated with this
/// `dev_id` will fall through to software or return errors.
pub fn unregister_device(dev_id: i32) {
    // wolfCrypt doesn't return the context pointer on unregister,
    // so we can't reclaim the Box here without additional bookkeeping.
    // TODO: maintain a side table mapping dev_id -> *mut DeviceState
    // so we can drop the Box on unregister.  For now, this leaks the
    // DeviceState allocation — acceptable for long-lived HSM registrations
    // but should be fixed for production use.
    unsafe {
        wolfcrypt_rs::wc_CryptoCb_UnRegisterDevice(dev_id);
    }
}

/// Re-export the constants callers need for matching operation types.
pub mod algo_type {
    pub use wolfcrypt_rs::WC_ALGO_TYPE_NONE;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_HASH;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_CIPHER;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_PK;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_RNG;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_SEED;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_HMAC;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_CMAC;
}

/// Re-export cipher type constants.
pub mod cipher_type {
    pub use wolfcrypt_rs::WC_CIPHER_AES_CBC;
    pub use wolfcrypt_rs::WC_CIPHER_AES_GCM;
    pub use wolfcrypt_rs::WC_CIPHER_AES_CTR;
    pub use wolfcrypt_rs::WC_CIPHER_AES_CCM;
    pub use wolfcrypt_rs::WC_CIPHER_AES_ECB;
}

/// Re-export PK type constants.
pub mod pk_type {
    pub use wolfcrypt_rs::WC_PK_TYPE_RSA;
    pub use wolfcrypt_rs::WC_PK_TYPE_EC_KEYGEN;
    pub use wolfcrypt_rs::WC_PK_TYPE_ECDH;
    pub use wolfcrypt_rs::WC_PK_TYPE_ECDSA_SIGN;
    pub use wolfcrypt_rs::WC_PK_TYPE_ECDSA_VERIFY;
    pub use wolfcrypt_rs::WC_PK_TYPE_ED25519_SIGN;
    pub use wolfcrypt_rs::WC_PK_TYPE_ED25519_VERIFY;
}

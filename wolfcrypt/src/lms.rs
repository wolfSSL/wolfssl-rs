//! LMS/HSS hash-based signatures backed by wolfCrypt.
//!
//! LMS (Leighton-Micali Signatures) is a stateful hash-based signature scheme
//! defined in RFC 8554. Each private key has a limited number of signatures
//! it can produce; after exhaustion, the key MUST NOT be used again.
//!
//! # Signing
//!
//! LMS is *stateful*: the private key changes with every signature.
//! [`LmsSigningKey`] stores private key state in memory via wolfCrypt's
//! write/read callbacks. For production use the caller is responsible for
//! persisting the private key externally (e.g. to a file or HSM) — losing
//! the updated state after signing means reusing a one-time leaf, which
//! breaks the security guarantee.

use core::cell::UnsafeCell;
use core::ffi::c_void;

use alloc::vec;
use alloc::vec::Vec;

use crate::error::{check, len_as_c_int, WolfCryptError};
use wolfcrypt_rs::{
    wc_LmsKey_ExportPubRaw, wc_LmsKey_Free, wc_LmsKey_GetPrivLen, wc_LmsKey_GetPubLen,
    wc_LmsKey_GetSigLen, wc_LmsKey_ImportPubRaw, wc_LmsKey_Init, wc_LmsKey_MakeKey,
    wc_LmsKey_SetContext, wc_LmsKey_SetParameters, wc_LmsKey_SetReadCb, wc_LmsKey_SetWriteCb,
    wc_LmsKey_Sign, wc_LmsKey_SigsLeft, wc_LmsKey_Verify, WcLmsKey,
};

// ---------------------------------------------------------------------------
// LmsParams — parameter set selection
// ---------------------------------------------------------------------------

/// LMS parameter set specifying the HSS tree structure.
///
/// - `levels`: number of HSS levels (1..=8)
/// - `height`: Merkle tree height per level (e.g. 5, 10, 15, 20, 25)
/// - `winternitz`: Winternitz parameter (1, 2, 4, or 8)
///
/// Smaller heights allow fewer signatures but faster key generation.
/// Larger Winternitz values produce smaller signatures but slower operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LmsParams {
    pub levels: u32,
    pub height: u32,
    pub winternitz: u32,
}

impl LmsParams {
    /// LMS with 1 level, height 5, Winternitz 8 — 32 signatures.
    ///
    /// Fastest key generation; useful for testing.
    pub const L1_H5_W8: Self = Self {
        levels: 1,
        height: 5,
        winternitz: 8,
    };

    /// LMS with 1 level, height 10, Winternitz 4 — 1024 signatures.
    pub const L1_H10_W4: Self = Self {
        levels: 1,
        height: 10,
        winternitz: 4,
    };

    /// LMS with 2 levels, height 5, Winternitz 8 — 1024 signatures.
    pub const L2_H5_W8: Self = Self {
        levels: 2,
        height: 5,
        winternitz: 8,
    };

    /// LMS with 2 levels, height 10, Winternitz 4 — 1048576 signatures.
    pub const L2_H10_W4: Self = Self {
        levels: 2,
        height: 10,
        winternitz: 4,
    };
}

// ---------------------------------------------------------------------------
// LmsVerifyingKey — public-key verification only
// ---------------------------------------------------------------------------

/// An LMS/HSS verifying key (public key) backed by wolfCrypt.
///
/// This type can verify signatures produced by an LMS signing key with
/// matching parameters. It does not require private-key persistence
/// callbacks.
///
/// # Interior mutability
///
/// wolfCrypt's `wc_LmsKey_Verify` requires a mutable pointer even though
/// verification does not logically modify the key. We use `UnsafeCell` to
/// satisfy this requirement while presenting an `&self` API.
pub struct LmsVerifyingKey {
    key: UnsafeCell<WcLmsKey>,
    params: LmsParams,
    /// Cached copy of the raw public key bytes.
    pub_bytes: Vec<u8>,
}

// SAFETY: `WcLmsKey` owns independent state with no shared mutable globals,
// so the struct can safely be moved between threads.
unsafe impl Send for LmsVerifyingKey {}

impl LmsVerifyingKey {
    /// Construct a verifying key from raw public key bytes and the
    /// corresponding parameter set.
    ///
    /// The byte length must match what wolfCrypt expects for the given
    /// parameters (queried via `wc_LmsKey_GetPubLen`).
    pub fn from_public_bytes(params: LmsParams, pub_key: &[u8]) -> Result<Self, WolfCryptError> {
        let mut key = WcLmsKey::zeroed();

        // SAFETY: `key` is zeroed; `wc_LmsKey_Init` fully initialises it.
        let rc = unsafe { wc_LmsKey_Init(&mut key, core::ptr::null_mut(), -1) };
        check(rc, "wc_LmsKey_Init")?;

        // SAFETY: `key` is initialised.
        let rc = unsafe {
            wc_LmsKey_SetParameters(
                &mut key,
                params.levels as i32,
                params.height as i32,
                params.winternitz as i32,
            )
        };
        check(rc, "wc_LmsKey_SetParameters")?;

        // Validate that the supplied public key has the expected length.
        let mut expected_len: u32 = 0;
        // SAFETY: `key` has parameters set.
        let rc = unsafe { wc_LmsKey_GetPubLen(&key, &mut expected_len) };
        check(rc, "wc_LmsKey_GetPubLen")?;

        if pub_key.len() != expected_len as usize {
            // Clean up before returning the error.
            // SAFETY: key was initialised by wc_LmsKey_Init above.
            unsafe { wc_LmsKey_Free(&mut key) };
            return Err(WolfCryptError::InvalidInput);
        }

        // SAFETY: `key` has parameters set, `pub_key` has the correct length.
        let rc = unsafe { wc_LmsKey_ImportPubRaw(&mut key, pub_key.as_ptr(), expected_len) };
        if rc != 0 {
            // SAFETY: key was initialised by wc_LmsKey_Init above.
            unsafe { wc_LmsKey_Free(&mut key) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_LmsKey_ImportPubRaw",
            });
        }

        Ok(Self {
            key: UnsafeCell::new(key),
            params,
            pub_bytes: pub_key.to_vec(),
        })
    }

    /// Return the parameter set this key was created with.
    pub fn params(&self) -> LmsParams {
        self.params
    }

    /// Return a reference to the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.pub_bytes
    }

    /// Return the expected signature length for this key's parameter set.
    pub fn sig_len(&self) -> Result<usize, WolfCryptError> {
        let mut len: u32 = 0;
        // SAFETY: `self.key` is fully initialised with parameters set.
        let rc = unsafe { wc_LmsKey_GetSigLen(&*self.key.get(), &mut len) };
        check(rc, "wc_LmsKey_GetSigLen")?;
        Ok(len as usize)
    }

    /// Return the expected public key length for this key's parameter set.
    pub fn pub_len(&self) -> Result<usize, WolfCryptError> {
        let mut len: u32 = 0;
        // SAFETY: `self.key` is fully initialised with parameters set.
        let rc = unsafe { wc_LmsKey_GetPubLen(&*self.key.get(), &mut len) };
        check(rc, "wc_LmsKey_GetPubLen")?;
        Ok(len as usize)
    }

    /// Verify an LMS/HSS signature over `msg`.
    ///
    /// Returns `Ok(())` if the signature is valid, or an error otherwise.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), WolfCryptError> {
        let sig_len = len_as_c_int(sig.len()) as u32;
        let msg_len = len_as_c_int(msg.len());

        // SAFETY: `self.key` is initialised with a valid public key.
        // wolfCrypt requires `*mut` for verify but does not logically modify
        // the key. `sig` and `msg` are valid slices.
        let rc = unsafe {
            wc_LmsKey_Verify(self.key.get(), sig.as_ptr(), sig_len, msg.as_ptr(), msg_len)
        };
        check(rc, "wc_LmsKey_Verify")
    }

    /// Export the raw public key bytes into a new `Vec`.
    pub fn export_public(&self) -> Result<Vec<u8>, WolfCryptError> {
        let pub_len = self.pub_len()?;
        let mut buf = vec![0u8; pub_len];
        let mut out_len = pub_len as u32;

        // SAFETY: `self.key` is initialised with a valid public key.
        let rc =
            unsafe { wc_LmsKey_ExportPubRaw(&*self.key.get(), buf.as_mut_ptr(), &mut out_len) };
        check(rc, "wc_LmsKey_ExportPubRaw")?;
        buf.truncate(out_len as usize);
        Ok(buf)
    }
}

impl Drop for LmsVerifyingKey {
    fn drop(&mut self) {
        // SAFETY: `self.key` was successfully initialised during construction.
        // We free it exactly once.
        unsafe {
            wc_LmsKey_Free(self.key.get_mut());
        }
    }
}

// ---------------------------------------------------------------------------
// LmsSigningKey — stateful signing with in-memory private key storage
// ---------------------------------------------------------------------------

/// In-memory private-key storage used by the wolfCrypt write/read callbacks.
///
/// Boxed so the pointer is stable across moves of `LmsSigningKey`.
struct PrivKeyStore {
    data: Vec<u8>,
}

/// C callback: write private key bytes into `PrivKeyStore`.
///
/// # Safety
///
/// `context` must point to a live `PrivKeyStore` (guaranteed by
/// `LmsSigningKey`'s invariant).
unsafe extern "C" fn lms_write_cb(priv_: *const u8, priv_sz: u32, context: *mut c_void) -> c_int {
    // SAFETY: context points to a live PrivKeyStore, guaranteed by LmsSigningKey's invariant.
    let store = unsafe { &mut *(context as *mut PrivKeyStore) };
    // SAFETY: priv_ is a valid pointer to priv_sz bytes, provided by wolfCrypt.
    let src = unsafe { core::slice::from_raw_parts(priv_, priv_sz as usize) };
    store.data.resize(src.len(), 0);
    store.data.copy_from_slice(src);
    0 // success
}

/// C callback: read private key bytes from `PrivKeyStore`.
///
/// # Safety
///
/// `context` must point to a live `PrivKeyStore`.
unsafe extern "C" fn lms_read_cb(priv_: *mut u8, priv_sz: u32, context: *mut c_void) -> c_int {
    // SAFETY: context points to a live PrivKeyStore, guaranteed by LmsSigningKey's invariant.
    let store = unsafe { &*(context as *const PrivKeyStore) };
    if store.data.len() != priv_sz as usize {
        return -1; // size mismatch
    }
    // SAFETY: priv_ is a valid pointer to priv_sz bytes, provided by wolfCrypt.
    let dst = unsafe { core::slice::from_raw_parts_mut(priv_, priv_sz as usize) };
    dst.copy_from_slice(&store.data);
    0 // success
}

/// An LMS/HSS signing key with in-memory private-key persistence.
///
/// **LMS is stateful.** Every call to [`sign`](LmsSigningKey::sign) mutates
/// the private key. Once all one-time leaves are exhausted,
/// [`remaining_signatures`](LmsSigningKey::remaining_signatures) returns 0 and
/// further signing attempts will fail.
///
/// For production use, export the private key after each signature and persist
/// it to durable storage.
pub struct LmsSigningKey {
    key: UnsafeCell<WcLmsKey>,
    params: LmsParams,
    /// Heap-allocated so the pointer stays stable when `LmsSigningKey` moves.
    store: alloc::boxed::Box<PrivKeyStore>,
}

// SAFETY: all state is owned and not shared.
unsafe impl Send for LmsSigningKey {}

impl LmsSigningKey {
    /// Generate a new LMS/HSS signing key.
    ///
    /// `rng` must be a valid, initialised `WolfRng`.
    pub fn generate(
        params: LmsParams,
        rng: &mut crate::rand::WolfRng,
    ) -> Result<Self, WolfCryptError> {
        let mut key = WcLmsKey::zeroed();

        // SAFETY: key is zeroed; wc_LmsKey_Init fully initialises it.
        let rc = unsafe { wc_LmsKey_Init(&mut key, core::ptr::null_mut(), -1) };
        check(rc, "wc_LmsKey_Init")?;

        // SAFETY: key is initialised; parameter values are caller-specified constants.
        let rc = unsafe {
            wc_LmsKey_SetParameters(
                &mut key,
                params.levels as i32,
                params.height as i32,
                params.winternitz as i32,
            )
        };
        if rc != 0 {
            // SAFETY: key was initialised above; freed on error path.
            unsafe { wc_LmsKey_Free(&mut key) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_LmsKey_SetParameters",
            });
        }

        // Allocate stable storage for the private key callbacks.
        let mut store = alloc::boxed::Box::new(PrivKeyStore { data: Vec::new() });

        // Register callbacks before MakeKey.
        let ctx_ptr: *mut c_void = &mut *store as *mut PrivKeyStore as *mut c_void;
        // SAFETY: key is initialised; lms_write_cb has the correct C ABI signature.
        let rc = unsafe { wc_LmsKey_SetWriteCb(&mut key, Some(lms_write_cb)) };
        if rc != 0 {
            // SAFETY: key was initialised above; freed on error path.
            unsafe { wc_LmsKey_Free(&mut key) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_LmsKey_SetWriteCb",
            });
        }
        // SAFETY: key is initialised; lms_read_cb has the correct C ABI signature.
        let rc = unsafe { wc_LmsKey_SetReadCb(&mut key, Some(lms_read_cb)) };
        if rc != 0 {
            // SAFETY: key was initialised above; freed on error path.
            unsafe { wc_LmsKey_Free(&mut key) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_LmsKey_SetReadCb",
            });
        }
        // SAFETY: key is initialised; ctx_ptr points to a Box-pinned PrivKeyStore that outlives key.
        let rc = unsafe { wc_LmsKey_SetContext(&mut key, ctx_ptr) };
        if rc != 0 {
            // SAFETY: key was initialised above; freed on error path.
            unsafe { wc_LmsKey_Free(&mut key) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_LmsKey_SetContext",
            });
        }

        // Generate the key pair.
        // SAFETY: key has params + callbacks set; rng is a valid initialised WolfRng.
        let rc = unsafe { wc_LmsKey_MakeKey(&mut key, &mut rng.rng) };
        if rc != 0 {
            // SAFETY: key was initialised above; freed on error path.
            unsafe { wc_LmsKey_Free(&mut key) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_LmsKey_MakeKey",
            });
        }

        Ok(Self {
            key: UnsafeCell::new(key),
            params,
            store,
        })
    }

    /// Sign a message, consuming one one-time leaf.
    ///
    /// # State mutation
    ///
    /// LMS is **stateful**: this call advances the internal one-time signature
    /// index. The caller **must** persist the updated private key state (via
    /// the write callback) before calling `sign` again. Failure to persist
    /// means a one-time leaf may be reused, breaking the security guarantee.
    ///
    /// Use [`remaining_signatures`](Self::remaining_signatures) to check how
    /// many signatures remain. When the key is exhausted, this method returns
    /// [`WolfCryptError::Ffi`] with the wolfCrypt `KEY_EXHAUSTED_E` code.
    ///
    /// Returns the LMS/HSS signature bytes.
    pub fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
        let mut sig_len: u32 = 0;
        // SAFETY: self.key is fully initialised with parameters set.
        let rc = unsafe { wc_LmsKey_GetSigLen(&*self.key.get(), &mut sig_len) };
        check(rc, "wc_LmsKey_GetSigLen")?;

        let mut sig = vec![0u8; sig_len as usize];
        let msg_len = len_as_c_int(msg.len());

        // SAFETY: self.key is initialised with a generated private key; sig is sig_len bytes.
        let rc = unsafe {
            wc_LmsKey_Sign(
                self.key.get(),
                sig.as_mut_ptr(),
                &mut sig_len,
                msg.as_ptr(),
                msg_len,
            )
        };
        check(rc, "wc_LmsKey_Sign")?;
        sig.truncate(sig_len as usize);
        Ok(sig)
    }

    /// Export the public key bytes.
    pub fn export_public(&self) -> Result<Vec<u8>, WolfCryptError> {
        let mut pub_len: u32 = 0;
        // SAFETY: self.key is fully initialised with parameters set.
        let rc = unsafe { wc_LmsKey_GetPubLen(&*self.key.get(), &mut pub_len) };
        check(rc, "wc_LmsKey_GetPubLen")?;

        let mut buf = vec![0u8; pub_len as usize];
        let mut out_len = pub_len;
        // SAFETY: self.key has a valid public key; buf is pub_len bytes.
        let rc =
            unsafe { wc_LmsKey_ExportPubRaw(&*self.key.get(), buf.as_mut_ptr(), &mut out_len) };
        check(rc, "wc_LmsKey_ExportPubRaw")?;
        buf.truncate(out_len as usize);
        Ok(buf)
    }

    /// Return the number of signatures remaining (0 = exhausted).
    pub fn remaining_signatures(&self) -> i32 {
        // wc_LmsKey_SigsLeft returns >0 for yes, 0 for no, negative on error.
        // SAFETY: self.key is fully initialised with a generated key.
        unsafe { wc_LmsKey_SigsLeft(self.key.get()) }
    }

    /// Return the parameter set this key was created with.
    pub fn params(&self) -> LmsParams {
        self.params
    }
}

impl Drop for LmsSigningKey {
    fn drop(&mut self) {
        // SAFETY: self.key was initialised during construction; freed exactly once.
        unsafe { wc_LmsKey_Free(self.key.get_mut()) };
    }
}

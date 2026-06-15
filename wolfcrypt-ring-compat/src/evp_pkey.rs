use crate::digest;
use crate::digest::digest_ctx::DigestContext;
use crate::digest::Digest;
use crate::error::{KeyRejected, Unspecified};
use crate::fips::indicator_check;
use crate::pkcs8::Version;
use crate::ptr::{ConstPointer, LcPtr};
use crate::wolfcrypt_rs::{
    d2i_PUBKEY, d2i_PrivateKey, i2d_PUBKEY, i2d_PrivateKey, wc_EccPublicKeyDerSize,
    wc_EccPublicKeyToDer, wc_Ed25519KeyToDer, wc_Ed25519PrivateKeyDecode,
    wc_Ed25519PrivateKeyToDer, wc_ForceZero, wc_FreeRng, wc_InitRng,
    wc_curve25519_export_key_raw_ex, wc_curve25519_free, wc_curve25519_import_private_ex,
    wc_curve25519_import_private_raw_ex, wc_curve25519_import_public_ex, wc_curve25519_init,
    wc_curve25519_key, wc_curve25519_make_key, wc_curve25519_set_rng,
    wc_curve25519_shared_secret_ex, wc_ed25519_export_private_only, wc_ed25519_export_public,
    wc_ed25519_free, wc_ed25519_import_private_key, wc_ed25519_import_private_only,
    wc_ed25519_import_public, wc_ed25519_init, wc_ed25519_key, wc_ed25519_make_key,
    wc_ed25519_make_public, wc_ed25519_sign_msg, wc_ed25519_verify_msg,
    wolfcrypt_evp_pkey_ctx_get_op, wolfcrypt_evp_pkey_ctx_get_peer_key,
    wolfcrypt_evp_pkey_ctx_get_pkey, wolfcrypt_evp_pkey_ctx_set_op,
    wolfcrypt_evp_pkey_ctx_set_peer_key, wolfcrypt_evp_pkey_get_ecc,
    wolfcrypt_evp_pkey_get_ecc_internal, wolfcrypt_evp_pkey_get_pkey_ptr,
    wolfcrypt_evp_pkey_get_pkey_sz, wolfcrypt_evp_pkey_get_type, wolfcrypt_evp_pkey_set_raw,
    wolfcrypt_evp_pkey_set_type, CRYPTO_memcmp, EVP_DigestSignFinal, EVP_DigestSignInit,
    EVP_DigestSignUpdate, EVP_DigestUpdate, EVP_DigestVerifyFinal, EVP_DigestVerifyInit,
    EVP_PKEY_CTX_new, EVP_PKEY_bits, EVP_PKEY_cmp, EVP_PKEY_free, EVP_PKEY_get0_RSA, EVP_PKEY_id,
    EVP_PKEY_new, EVP_PKEY_new_mac_key, EVP_PKEY_set1_EC_KEY, EVP_PKEY_sign, EVP_PKEY_sign_init,
    EVP_PKEY_up_ref, EVP_PKEY_verify, EVP_PKEY_verify_init, OPENSSL_free, OPENSSL_malloc,
    EC25519_LITTLE_ENDIAN, ED25519_KEY_SIZE, ENGINE, EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_EC,
    EVP_PKEY_ED25519, EVP_PKEY_RSA, NID_ED25519, NID_X25519, RSA, WC_CURVE25519_KEY_ALLOC_SIZE,
    WC_ED25519_KEY_ALLOC_SIZE, WC_EVP_PKEY_OP_DERIVE, WC_RNG,
};
use core::ffi::{c_int, c_long, c_void};
use core::ptr::{null, null_mut};
use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
use crate::prelude::*;

// ================================================================
// Thread-local RNG
//
// wolfCrypt keygen functions (wc_ed25519_make_key, wc_curve25519_make_key)
// require a WC_RNG* parameter. Initializing a WC_RNG is expensive (OS
// entropy gathering + DRBG seeding), so we cache one per thread.
// ================================================================

// ----------------------------------------------------------------
// Per-thread (std) or global (no_std) RNG for wolfCrypt keygen
// ----------------------------------------------------------------

#[cfg(feature = "std")]
mod rng_cache {
    use super::*;
    use std::cell::UnsafeCell;

    struct ThreadRng {
        rng: WC_RNG,
        initialized: bool,
    }

    impl ThreadRng {
        const fn new() -> Self {
            Self {
                rng: WC_RNG::zeroed(),
                initialized: false,
            }
        }
    }

    impl Drop for ThreadRng {
        fn drop(&mut self) {
            if self.initialized {
                // SAFETY: rng was fully initialized by a successful wc_InitRng call.
                unsafe {
                    wc_FreeRng(&mut self.rng);
                }
                self.initialized = false;
            }
        }
    }

    std::thread_local! {
        static THREAD_RNG: UnsafeCell<ThreadRng> = const { UnsafeCell::new(ThreadRng::new()) };
    }

    pub(super) fn get_rng() -> *mut WC_RNG {
        THREAD_RNG.with(|cell| {
            // SAFETY: thread_local guarantees no aliasing; UnsafeCell access is single-threaded.
            let rng = unsafe { &mut *cell.get() };
            if !rng.initialized {
                // SAFETY: rng.rng is zeroed and uninitialized; wc_InitRng initializes it.
                if unsafe { wc_InitRng(&mut rng.rng) } != 0 {
                    return core::ptr::null_mut();
                }
                rng.initialized = true;
            }
            &mut rng.rng as *mut WC_RNG
        })
    }
}

#[cfg(not(feature = "std"))]
mod rng_cache {
    use super::*;

    struct GlobalRng {
        rng: WC_RNG,
        initialized: bool,
    }

    // Safety: no_std targets are assumed single-threaded (e.g. embedded/Caliptra).
    // If used in a multi-threaded no_std environment, external synchronization
    // is required around all wolfcrypt-ring keygen/ECDH operations.
    unsafe impl Send for GlobalRng {}
    unsafe impl Sync for GlobalRng {}

    static GLOBAL_RNG: spin::Mutex<GlobalRng> = spin::Mutex::new(GlobalRng {
        rng: WC_RNG::zeroed(),
        initialized: false,
    });

    pub(super) fn get_rng() -> *mut WC_RNG {
        let mut guard = GLOBAL_RNG.lock();
        if !guard.initialized {
            // SAFETY: guard.rng is zeroed and uninitialized; wc_InitRng initializes it.
            if unsafe { wc_InitRng(&mut guard.rng) } != 0 {
                return core::ptr::null_mut();
            }
            guard.initialized = true;
        }
        // Safety: the Mutex ensures exclusive access during init. The returned
        // pointer is used briefly for a single wolfCrypt operation. On no_std
        // targets (single-threaded), there is no concurrent access.
        &mut guard.rng as *mut WC_RNG
    }
}

fn get_thread_rng() -> *mut WC_RNG {
    rng_cache::get_rng()
}

impl PartialEq<Self> for LcPtr<EVP_PKEY> {
    /// Only compares params and public key
    fn eq(&self, other: &Self) -> bool {
        // wolfSSL returns 0 on match, but we need 1 on match (BoringSSL convention).
        // SAFETY: both pointers are valid EVP_PKEYs owned by their respective LcPtr wrappers.
        let ret = unsafe { EVP_PKEY_cmp(self.as_const_ptr(), other.as_const_ptr()) };
        ret == 0
    }
}

#[allow(non_camel_case_types)]
pub(crate) trait EVP_PKEY_CTX_consumer: Fn(*mut EVP_PKEY_CTX) -> Result<(), ()> {}

impl<T> EVP_PKEY_CTX_consumer for T where T: Fn(*mut EVP_PKEY_CTX) -> Result<(), ()> {}

#[allow(non_upper_case_globals, clippy::type_complexity)]
pub(crate) const No_EVP_PKEY_CTX_consumer: Option<fn(*mut EVP_PKEY_CTX) -> Result<(), ()>> = None;

impl ConstPointer<'_, EVP_PKEY> {
    pub(crate) fn validate_as_ed25519(&self) -> Result<(), KeyRejected> {
        const ED25519_KEY_TYPE: c_int = EVP_PKEY_ED25519;
        const ED25519_MIN_BITS: c_int = 253;
        const ED25519_MAX_BITS: c_int = 256;

        let key_type = self.id();
        if key_type != ED25519_KEY_TYPE {
            return Err(KeyRejected::wrong_algorithm());
        }

        let bits: c_int = self
            .key_size_bits()
            .try_into()
            .map_err(|_| KeyRejected::too_large())?;
        if bits < ED25519_MIN_BITS {
            return Err(KeyRejected::too_small());
        }

        if bits > ED25519_MAX_BITS {
            return Err(KeyRejected::too_large());
        }
        Ok(())
    }

    // EVP_PKEY_NONE = 0;
    // EVP_PKEY_RSA = 6;
    // EVP_PKEY_RSA_PSS = 912;
    // EVP_PKEY_DSA = 116;
    // EVP_PKEY_EC = 408;
    // EVP_PKEY_ED25519 = 949;
    // EVP_PKEY_X25519 = 948;
    // EVP_PKEY_KYBER512 = 970;
    // EVP_PKEY_HKDF = 969;
    // EVP_PKEY_DH = 28;
    // EVP_PKEY_RSA2 = 19;
    // EVP_PKEY_X448 = 961;
    // EVP_PKEY_ED448 = 960;
    pub(crate) fn id(&self) -> i32 {
        // SAFETY: self is a valid EVP_PKEY; EVP_PKEY_id is a read-only accessor.
        unsafe { EVP_PKEY_id(self.as_const_ptr()) }
    }

    pub(crate) fn key_size_bytes(&self) -> usize {
        self.key_size_bits() / 8
    }

    pub(crate) fn key_size_bits(&self) -> usize {
        // wolfSSL's EVP_PKEY_bits does not support Ed25519/X25519
        let id = self.id();
        if id == EVP_PKEY_ED25519 {
            return 256;
        }
        if id == crate::wolfcrypt_rs::EVP_PKEY_X25519 {
            return 253;
        }
        // PANIC-SAFETY: EVP_PKEY_bits can return a negative value for unsupported key types.
        // Cannot propagate the error because this function returns usize, not Result.
        // Callers that need to handle unsupported key types should check the key type
        // before calling this.
        // SAFETY: self is a valid EVP_PKEY; EVP_PKEY_bits is a read-only accessor.
        unsafe { EVP_PKEY_bits(self.as_const_ptr()) }
            .try_into()
            .unwrap()
    }

    pub(crate) fn get_rsa(&self) -> Result<ConstPointer<'_, RSA>, KeyRejected> {
        // SAFETY: self is a valid EVP_PKEY; EVP_PKEY_get0_RSA returns a borrowed pointer.
        self.project_const_lifetime(unsafe {
            |evp_pkey| EVP_PKEY_get0_RSA(evp_pkey.as_const_ptr())
        })
        .map_err(|()| KeyRejected::wrong_algorithm())
    }

    pub(crate) fn marshal_rfc5280_public_key(&self) -> Result<Vec<u8>, Unspecified> {
        // Data shows that the SubjectPublicKeyInfo is roughly 356% to 375% increase in size compared to the RSA key
        // size in bytes for keys ranging from 2048-bit to 4096-bit. So size the initial capacity to be roughly
        // 500% as a conservative estimate to avoid needing to reallocate for any key in that range.
        let mut buf = Vec::with_capacity(self.key_size_bytes() * 5);
        // SAFETY: self is a valid EVP_PKEY; buf is a valid Vec that evp_marshal_public_key appends to.
        unsafe { evp_marshal_public_key(&mut buf, self.as_const_ptr())? };
        Ok(buf)
    }

    pub(crate) fn marshal_rfc5208_private_key(
        &self,
        version: Version,
    ) -> Result<Vec<u8>, Unspecified> {
        // SAFETY: self is a valid EVP_PKEY; EVP_PKEY_bits is a read-only accessor.
        let key_size_bytes =
            TryInto::<usize>::try_into(unsafe { EVP_PKEY_bits(self.as_const_ptr()) })
                .map_err(|_| Unspecified)?
                / 8;
        let mut buf = Vec::with_capacity(key_size_bytes * 5);
        match version {
            Version::V1 => {
                // SAFETY: self is a valid EVP_PKEY; buf is a valid Vec.
                unsafe { evp_marshal_private_key(&mut buf, self.as_const_ptr())? };
            }
            Version::V2 => {
                // SAFETY: self is a valid EVP_PKEY; buf is a valid Vec.
                unsafe { evp_marshal_private_key_v2(&mut buf, self.as_const_ptr())? };
            }
        }
        Ok(buf)
    }

    pub(crate) fn marshal_raw_private_key(&self) -> Result<Vec<u8>, Unspecified> {
        let mut size = 0;
        // SAFETY: self is a valid EVP_PKEY; null out buffer queries the required size.
        if 1 != unsafe { EVP_PKEY_get_raw_private_key(self.as_const_ptr(), null_mut(), &mut size) }
        {
            return Err(Unspecified);
        }
        let mut buffer = vec![0u8; size];
        let buffer_size = self.marshal_raw_private_to_buffer(&mut buffer)?;
        debug_assert_eq!(buffer_size, size);
        Ok(buffer)
    }

    pub(crate) fn marshal_raw_private_to_buffer(
        &self,
        buffer: &mut [u8],
    ) -> Result<usize, Unspecified> {
        let mut key_len = buffer.len();
        // SAFETY: pointer and length derived from a valid Rust slice; self is a valid EVP_PKEY.
        if 1 == unsafe {
            EVP_PKEY_get_raw_private_key(self.as_const_ptr(), buffer.as_mut_ptr(), &mut key_len)
        } {
            Ok(key_len)
        } else {
            Err(Unspecified)
        }
    }

    pub(crate) fn marshal_raw_public_to_buffer(
        &self,
        buffer: &mut [u8],
    ) -> Result<usize, Unspecified> {
        let mut key_len = buffer.len();
        // SAFETY: pointer and length derived from a valid Rust slice; self is a valid EVP_PKEY.
        if 1 == unsafe {
            // `EVP_PKEY_get_raw_public_key` writes the total length
            // to `encapsulate_key_size` in the event that the buffer we provide is larger then
            // required.
            EVP_PKEY_get_raw_public_key(self.as_const_ptr(), buffer.as_mut_ptr(), &mut key_len)
        } {
            Ok(key_len)
        } else {
            Err(Unspecified)
        }
    }
}

impl LcPtr<EVP_PKEY> {
    #[inline]
    pub unsafe fn as_mut_unsafe_ptr(&self) -> *mut EVP_PKEY {
        self.as_const_ptr().cast_mut()
    }

    pub(crate) fn parse_rfc5280_public_key(
        bytes: &[u8],
        evp_pkey_type: c_int,
    ) -> Result<Self, KeyRejected> {
        // Also checks the validity of the key
        // SAFETY: pointer and length derived from a valid Rust slice.
        let evp_pkey = LcPtr::new(unsafe { evp_parse_public_key(bytes) })
            .map_err(|()| KeyRejected::invalid_encoding())?;
        evp_pkey
            .as_const()
            .id()
            .eq(&evp_pkey_type)
            .then_some(evp_pkey)
            .ok_or(KeyRejected::wrong_algorithm())
    }

    pub(crate) fn parse_rfc5208_private_key(
        bytes: &[u8],
        evp_pkey_type: c_int,
    ) -> Result<Self, KeyRejected> {
        // Also checks the validity of the key
        // SAFETY: pointer and length derived from a valid Rust slice.
        let evp_pkey = LcPtr::new(unsafe { evp_parse_private_key(bytes) })
            .map_err(|()| KeyRejected::invalid_encoding())?;
        evp_pkey
            .as_const()
            .id()
            .eq(&evp_pkey_type)
            .then_some(evp_pkey)
            .ok_or(KeyRejected::wrong_algorithm())
    }

    #[allow(non_snake_case)]
    pub(crate) fn create_EVP_PKEY_CTX(&self) -> Result<LcPtr<EVP_PKEY_CTX>, ()> {
        // The only modification made by EVP_PKEY_CTX_new to `priv_key` is to increment its
        // refcount. The modification is made while holding a global lock.
        // SAFETY: self is a valid EVP_PKEY managed by LcPtr; refcount increment is thread-safe.
        LcPtr::new(unsafe { EVP_PKEY_CTX_new(self.as_mut_unsafe_ptr(), null_mut()) })
    }

    pub(crate) fn parse_raw_private_key(
        bytes: &[u8],
        evp_pkey_type: c_int,
    ) -> Result<Self, KeyRejected> {
        // SAFETY: pointer and length derived from a valid Rust slice.
        Self::new(unsafe {
            EVP_PKEY_new_raw_private_key(evp_pkey_type, null_mut(), bytes.as_ptr(), bytes.len())
        })
        .map_err(|()| KeyRejected::unspecified())
    }

    pub(crate) fn parse_raw_public_key(
        bytes: &[u8],
        evp_pkey_type: c_int,
    ) -> Result<Self, KeyRejected> {
        // SAFETY: pointer and length derived from a valid Rust slice.
        Self::new(unsafe {
            EVP_PKEY_new_raw_public_key(evp_pkey_type, null_mut(), bytes.as_ptr(), bytes.len())
        })
        .map_err(|()| KeyRejected::invalid_encoding())
    }

    pub(crate) fn sign<F>(
        &self,
        message: &[u8],
        digest: Option<&'static digest::Algorithm>,
        padding_fn: Option<F>,
    ) -> Result<Box<[u8]>, Unspecified>
    where
        F: EVP_PKEY_CTX_consumer,
    {
        // Ed25519: use wolfCrypt directly (wolfSSL EVP does not support Ed25519 sign)
        if self.as_const().id() == EVP_PKEY_ED25519 {
            // Extract raw private seed (32 bytes) and public key (32 bytes)
            let mut priv_seed = [0u8; 32];
            let mut pub_key = [0u8; 32];
            self.as_const()
                .marshal_raw_private_to_buffer(&mut priv_seed)?;
            self.as_const().marshal_raw_public_to_buffer(&mut pub_key)?;

            let mut signature = vec![0u8; 64];
            // SAFETY: all slices are valid Rust references with correct lengths.
            let sig_len = unsafe {
                wc_ed25519_sign_msg_wrapper(&priv_seed, &pub_key, message, &mut signature)
            };
            // SAFETY: pointer and length derived from a valid stack array.
            unsafe {
                wc_ForceZero(priv_seed.as_mut_ptr() as *mut c_void, priv_seed.len());
            }
            if sig_len == 0 {
                return Err(Unspecified);
            }
            signature.truncate(sig_len);
            return Ok(signature.into_boxed_slice());
        }

        let mut md_ctx = DigestContext::new_uninit()?;
        let evp_md = if let Some(alg) = digest {
            digest::match_digest_type(&alg.id).as_const_ptr()
        } else {
            null()
        };
        let mut pctx = null_mut::<EVP_PKEY_CTX>();
        // SAFETY: md_ctx, evp_md, and pkey are valid; EVP_DigestSignInit only increments pkey refcount.
        if 1 != unsafe {
            // EVP_DigestSignInit does not mutate |pkey| for thread-safety purposes and may be
            // used concurrently with other non-mutating functions on |pkey|.
            EVP_DigestSignInit(
                md_ctx.as_mut_ptr(),
                &mut pctx,
                evp_md,
                null_mut(),
                self.as_mut_unsafe_ptr(),
            )
        } {
            return Err(Unspecified);
        }

        if let Some(pad_fn) = padding_fn {
            pad_fn(pctx)?;
        }

        // Determine the maximum length of the signature.
        let mut sig_len = 0;
        // SAFETY: md_ctx is valid; null output queries the required signature length.
        if 1 != unsafe { EVP_DigestSignFinal(md_ctx.as_mut_ptr(), null_mut(), &mut sig_len) } {
            return Err(Unspecified);
        }
        if sig_len == 0 {
            return Err(Unspecified);
        }

        // Update with the message data then finalize
        // SAFETY: pointer and length derived from a valid Rust slice; md_ctx is initialized.
        if 1 != unsafe {
            EVP_DigestSignUpdate(
                md_ctx.as_mut_ptr(),
                message.as_ptr() as *const core::ffi::c_void,
                message.len() as core::ffi::c_uint,
            )
        } {
            return Err(Unspecified);
        }
        let mut signature = vec![0u8; sig_len];
        // SAFETY: signature buffer is sized to sig_len from the query above; md_ctx is valid.
        if 1 != indicator_check!(unsafe {
            EVP_DigestSignFinal(md_ctx.as_mut_ptr(), signature.as_mut_ptr(), &mut sig_len)
        }) {
            signature.zeroize();
            return Err(Unspecified);
        }
        signature.truncate(sig_len);
        Ok(signature.into_boxed_slice())
    }

    pub(crate) fn sign_digest<F>(
        &self,
        digest: &Digest,
        padding_fn: Option<F>,
    ) -> Result<Box<[u8]>, Unspecified>
    where
        F: EVP_PKEY_CTX_consumer,
    {
        let mut pctx = self.create_EVP_PKEY_CTX()?;

        // SAFETY: pctx was just created from a valid EVP_PKEY via create_EVP_PKEY_CTX.
        if 1 != unsafe { EVP_PKEY_sign_init(pctx.as_mut_ptr()) } {
            return Err(Unspecified);
        }

        if let Some(pad_fn) = padding_fn {
            pad_fn(pctx.as_mut_ptr())?;
        }

        let msg_digest = digest.as_ref();
        let mut sig_len = 0;
        // SAFETY: pctx is initialized; null output queries the required signature length.
        if 1 != unsafe {
            EVP_PKEY_sign(
                pctx.as_mut_ptr(),
                null_mut(),
                &mut sig_len,
                msg_digest.as_ptr(),
                msg_digest.len(),
            )
        } {
            return Err(Unspecified);
        }

        let mut signature = vec![0u8; sig_len];
        // SAFETY: signature buffer is sized to sig_len; digest pointer/length from valid slice.
        if 1 != indicator_check!(unsafe {
            EVP_PKEY_sign(
                pctx.as_mut_ptr(),
                signature.as_mut_ptr(),
                &mut sig_len,
                msg_digest.as_ptr(),
                msg_digest.len(),
            )
        }) {
            signature.zeroize();
            return Err(Unspecified);
        }
        signature.truncate(sig_len);

        Ok(signature.into_boxed_slice())
    }

    pub(crate) fn verify<F>(
        &self,
        msg: &[u8],
        digest: Option<&'static digest::Algorithm>,
        padding_fn: Option<F>,
        signature: &[u8],
    ) -> Result<(), Unspecified>
    where
        F: EVP_PKEY_CTX_consumer,
    {
        // Ed25519: use wolfCrypt directly (wolfSSL EVP does not support Ed25519 verify)
        if self.as_const().id() == EVP_PKEY_ED25519 {
            let mut pub_key = [0u8; 32];
            self.as_const().marshal_raw_public_to_buffer(&mut pub_key)?;

            // SAFETY: all arguments are valid Rust slices with correct lengths.
            if unsafe { wc_ed25519_verify_msg_wrapper(&pub_key, msg, signature) } {
                return Ok(());
            } else {
                return Err(Unspecified);
            }
        }

        let mut md_ctx = DigestContext::new_uninit()?;

        let evp_md = if let Some(alg) = digest {
            digest::match_digest_type(&alg.id).as_const_ptr()
        } else {
            null()
        };

        let mut pctx = null_mut::<EVP_PKEY_CTX>();

        // SAFETY: md_ctx, evp_md, and pkey are valid; EVP_DigestVerifyInit only increments pkey refcount.
        if 1 != unsafe {
            EVP_DigestVerifyInit(
                md_ctx.as_mut_ptr(),
                &mut pctx,
                evp_md,
                null_mut(),
                self.as_mut_unsafe_ptr(),
            )
        } {
            return Err(Unspecified);
        }
        if let Some(pad_fn) = padding_fn {
            pad_fn(pctx)?;
        }

        // SAFETY: pointer and length derived from a valid Rust slice; md_ctx is initialized.
        if 1 != unsafe {
            EVP_DigestUpdate(
                md_ctx.as_mut_ptr(),
                msg.as_ptr() as *const core::ffi::c_void,
                msg.len(),
            )
        } {
            return Err(Unspecified);
        }
        // SAFETY: pointer and length derived from a valid Rust slice; md_ctx is initialized.
        if 1 != indicator_check!(unsafe {
            EVP_DigestVerifyFinal(md_ctx.as_mut_ptr(), signature.as_ptr(), signature.len())
        }) {
            return Err(Unspecified);
        }

        Ok(())
    }

    pub(crate) fn verify_digest_sig<F>(
        &self,
        digest: &Digest,
        padding_fn: Option<F>,
        signature: &[u8],
    ) -> Result<(), Unspecified>
    where
        F: EVP_PKEY_CTX_consumer,
    {
        let mut pctx = self.create_EVP_PKEY_CTX()?;

        // SAFETY: pctx was just created from a valid EVP_PKEY via create_EVP_PKEY_CTX.
        if 1 != unsafe { EVP_PKEY_verify_init(pctx.as_mut_ptr()) } {
            return Err(Unspecified);
        }

        if let Some(pad_fn) = padding_fn {
            pad_fn(pctx.as_mut_ptr())?;
        }

        let msg_digest = digest.as_ref();

        // SAFETY: pctx is initialized; signature and digest pointers from valid Rust slices.
        if 1 == unsafe {
            indicator_check!(EVP_PKEY_verify(
                pctx.as_mut_ptr(),
                signature.as_ptr(),
                signature.len(),
                msg_digest.as_ptr(),
                msg_digest.len(),
            ))
        } {
            Ok(())
        } else {
            Err(Unspecified)
        }
    }

    pub(crate) fn agree(&self, peer_key: &mut Self) -> Result<Box<[u8]>, Unspecified> {
        let mut pctx = self.create_EVP_PKEY_CTX()?;

        // SAFETY: pctx was just created from a valid EVP_PKEY via create_EVP_PKEY_CTX.
        if 1 != unsafe { EVP_PKEY_derive_init(pctx.as_mut_ptr()) } {
            return Err(Unspecified);
        }

        let mut secret_len = 0;
        // SAFETY: pctx and peer_key are valid; derive_init was called above.
        if 1 != unsafe { EVP_PKEY_derive_set_peer(pctx.as_mut_ptr(), peer_key.as_mut_ptr()) } {
            return Err(Unspecified);
        }

        // SAFETY: pctx is initialized with peer; null output queries the required length.
        if 1 != unsafe { EVP_PKEY_derive(pctx.as_mut_ptr(), null_mut(), &mut secret_len) } {
            return Err(Unspecified);
        }

        let mut secret = vec![0u8; secret_len];
        // SAFETY: secret buffer is sized to secret_len from the query above; pctx is valid.
        if 1 != indicator_check!(unsafe {
            EVP_PKEY_derive(pctx.as_mut_ptr(), secret.as_mut_ptr(), &mut secret_len)
        }) {
            return Err(Unspecified);
        }
        secret.truncate(secret_len);

        Ok(secret.into_boxed_slice())
    }

    pub(crate) fn generate<F>(pkey_type: c_int, params_fn: Option<F>) -> Result<Self, Unspecified>
    where
        F: EVP_PKEY_CTX_consumer,
    {
        // SAFETY: pkey_type is a valid EVP_PKEY type constant; engine is null.
        let mut pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new_id(pkey_type, null_mut()) })?;

        // SAFETY: pkey_ctx was just created above and is valid.
        if 1 != unsafe { EVP_PKEY_keygen_init(pkey_ctx.as_mut_ptr()) } {
            return Err(Unspecified);
        }

        if let Some(pad_fn) = params_fn {
            pad_fn(pkey_ctx.as_mut_ptr())?;
        }

        let mut pkey = null_mut::<EVP_PKEY>();

        // SAFETY: pkey_ctx is initialized; pkey is a valid out-pointer for the new key.
        if 1 != indicator_check!(unsafe { EVP_PKEY_keygen(pkey_ctx.as_mut_ptr(), &mut pkey) }) {
            return Err(Unspecified);
        }

        Ok(LcPtr::new(pkey)?)
    }
}

impl Clone for LcPtr<EVP_PKEY> {
    fn clone(&self) -> Self {
        // EVP_PKEY_up_ref increments the refcount while holding a global lock.
        // SAFETY: self is a valid EVP_PKEY managed by LcPtr; refcount increment is thread-safe.
        assert_eq!(
            1,
            unsafe { EVP_PKEY_up_ref(self.as_mut_unsafe_ptr()) },
            "infallible wolfSSL function"
        );
        // PANIC-SAFETY: Clone trait is infallible; EVP_PKEY_up_ref succeeded (asserted above), pointer is non-null
        // SAFETY: pointer is non-null and refcount was just incremented.
        Self::new(unsafe { self.as_mut_unsafe_ptr() }).expect("non-null wolfSSL EVP_PKEY pointer")
    }
}

// ================================================================
// EVP marshal/parse functions (moved from wolfcrypt-rs)
// ================================================================

/// SubjectPublicKeyInfo prefix for X25519/Ed25519 (12 bytes).
/// The last OID byte (offset 8) differs: 0x6e for X25519, 0x70 for Ed25519.
/// The 32-byte public key follows immediately after this prefix.
const SPKI_25519_PREFIX_LEN: usize = 12;

/// Ed25519 OID bytes (1.3.101.112) used for OID sniffing in DER parsing.
const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

/// Helper: serialize an Ed25519 private key to PKCS#8 DER using wolfCrypt's
/// ASN.1 engine. When `include_public` is false, uses wc_Ed25519PrivateKeyToDer
/// (v1, private-only). When true, uses wc_Ed25519KeyToDer (v2, includes public key).
unsafe fn marshal_ed25519_private_key(
    buf: &mut Vec<u8>,
    key: *const EVP_PKEY,
    include_public: bool,
) -> Result<(), Unspecified> {
    // SAFETY: caller must provide a valid EVP_PKEY pointer; all FFI calls
    // operate on wolfCrypt objects whose lifetimes are managed within this
    // function (allocated, used, freed before return).
    unsafe {
        let pkey_sz = wolfcrypt_evp_pkey_get_pkey_sz(key);
        let pkey_ptr = wolfcrypt_evp_pkey_get_pkey_ptr(key);
        if pkey_ptr.is_null() || pkey_sz != 64 {
            return Err(Unspecified);
        }

        // Create a temporary ed25519_key and import our [seed(32)|pub(32)] material
        let ed_key = OPENSSL_malloc(WC_ED25519_KEY_ALLOC_SIZE) as *mut wc_ed25519_key;
        if ed_key.is_null() {
            return Err(Unspecified);
        }
        core::ptr::write_bytes(ed_key as *mut u8, 0, WC_ED25519_KEY_ALLOC_SIZE);

        if wc_ed25519_init(ed_key) != 0 {
            OPENSSL_free(ed_key as *mut c_void);
            return Err(Unspecified);
        }

        // Import private seed (first 32 bytes) + public key (last 32 bytes)
        if wc_ed25519_import_private_key(pkey_ptr, 32, pkey_ptr.add(32), 32, ed_key) != 0 {
            wc_ed25519_free(ed_key);
            OPENSSL_free(ed_key as *mut c_void);
            return Err(Unspecified);
        }

        // Get required DER output size (pass NULL output)
        let der_func = if include_public {
            wc_Ed25519KeyToDer
                as unsafe extern "C" fn(*const wc_ed25519_key, *mut u8, u32) -> c_int
        } else {
            wc_Ed25519PrivateKeyToDer
                as unsafe extern "C" fn(*const wc_ed25519_key, *mut u8, u32) -> c_int
        };

        let der_len = der_func(ed_key, core::ptr::null_mut(), 0);
        if der_len <= 0 {
            wc_ed25519_free(ed_key);
            OPENSSL_free(ed_key as *mut c_void);
            return Err(Unspecified);
        }

        // Encode into a temporary buffer, then extend buf
        let mut tmp = vec![0u8; der_len as usize];
        let actual = der_func(ed_key, tmp.as_mut_ptr(), der_len as u32);

        wc_ed25519_free(ed_key);
        OPENSSL_free(ed_key as *mut c_void);

        if actual <= 0 {
            return Err(Unspecified);
        }
        buf.extend_from_slice(&tmp[..actual as usize]);
        Ok(())
    }
}

/// evp_marshal_private_key: serialize a private key to PKCS#8 v1 DER.
pub(crate) unsafe fn evp_marshal_private_key(
    buf: &mut Vec<u8>,
    key: *const EVP_PKEY,
) -> Result<(), Unspecified> {
    // SAFETY: caller must provide a valid, non-null EVP_PKEY pointer.
    // FFI calls use wolfSSL's EVP layer; returned DER buffers are freed
    // before returning.
    unsafe {
        if key.is_null() {
            return Err(Unspecified);
        }
        let type_ = wolfcrypt_evp_pkey_get_type(key);

        // Ed25519: produce PKCS#8 v1 PrivateKeyInfo via wolfCrypt's ASN.1 engine
        if type_ == NID_ED25519 {
            return marshal_ed25519_private_key(buf, key, false);
        }

        // EC keys: use i2d_PrivateKey via a temp EVP_PKEY
        if type_ == EVP_PKEY_EC {
            let ecc = wolfcrypt_evp_pkey_get_ecc(key);
            if !ecc.is_null() {
                let tmp_pkey = EVP_PKEY_new();
                if !tmp_pkey.is_null() {
                    if EVP_PKEY_set1_EC_KEY(tmp_pkey, ecc) == 1 {
                        let mut pkcs8_der: *mut u8 = core::ptr::null_mut();
                        let pkcs8_len = i2d_PrivateKey(tmp_pkey, &mut pkcs8_der);
                        if pkcs8_len > 0 && !pkcs8_der.is_null() {
                            let slice =
                                core::slice::from_raw_parts(pkcs8_der, pkcs8_len as usize);
                            buf.extend_from_slice(slice);
                            OPENSSL_free(pkcs8_der as *mut c_void);
                            EVP_PKEY_free(tmp_pkey);
                            return Ok(());
                        }
                    }
                    EVP_PKEY_free(tmp_pkey);
                }
            }
        }

        // Default: use i2d_PrivateKey
        let mut der: *mut u8 = core::ptr::null_mut();
        let der_len = i2d_PrivateKey(key, &mut der);
        if der_len <= 0 || der.is_null() {
            return Err(Unspecified);
        }
        let slice = core::slice::from_raw_parts(der, der_len as usize);
        buf.extend_from_slice(slice);
        OPENSSL_free(der as *mut c_void);
        Ok(())
    }
}

/// evp_marshal_private_key_v2: PKCS#8 v2 (RFC 5958 OneAsymmetricKey) with
/// public key for Ed25519. v2 differs from v1 by setting version=1 and
/// appending the optional publicKey field.
pub(crate) unsafe fn evp_marshal_private_key_v2(
    buf: &mut Vec<u8>,
    key: *const EVP_PKEY,
) -> Result<(), Unspecified> {
    // SAFETY: caller must provide a valid EVP_PKEY pointer; delegates to
    // marshal_ed25519_private_key or evp_marshal_private_key which manage
    // their own FFI object lifetimes.
    unsafe {
        if key.is_null() {
            return Err(Unspecified);
        }
        let type_ = wolfcrypt_evp_pkey_get_type(key);

        // Ed25519: produce PKCS#8 v2 OneAsymmetricKey (with embedded public key)
        // via wolfCrypt's wc_Ed25519KeyToDer which includes the public key.
        if type_ == NID_ED25519 {
            return marshal_ed25519_private_key(buf, key, true);
        }

        // Non-Ed25519: same as v1
        evp_marshal_private_key(buf, key)
    }
}

/// evp_marshal_public_key: serialize a public key to SubjectPublicKeyInfo DER.
pub(crate) unsafe fn evp_marshal_public_key(
    buf: &mut Vec<u8>,
    key: *const EVP_PKEY,
) -> Result<(), Unspecified> {
    // SAFETY: caller must provide a valid EVP_PKEY pointer. Pointer
    // arithmetic on pkey_ptr is bounded by the 64- or 32-byte allocation
    // checked via pkey_sz. DER buffers from OPENSSL_malloc/i2d_PUBKEY
    // are freed before returning.
    unsafe {
        if key.is_null() {
            return Err(Unspecified);
        }
        let type_ = wolfcrypt_evp_pkey_get_type(key);

        // X25519/Ed25519: build SubjectPublicKeyInfo manually
        if type_ == NID_X25519 || type_ == NID_ED25519 {
            let pkey_sz = wolfcrypt_evp_pkey_get_pkey_sz(key);
            let pkey_ptr = wolfcrypt_evp_pkey_get_pkey_ptr(key);
            if pkey_ptr.is_null() {
                return Err(Unspecified);
            }

            let pub_raw = if pkey_sz == 64 {
                pkey_ptr.add(32)
            } else if pkey_sz == 32 {
                pkey_ptr
            } else {
                return Err(Unspecified);
            };

            // OID last byte: X25519=0x6e, Ed25519=0x70
            let oid_byte: u8 = if type_ == NID_X25519 { 0x6e } else { 0x70 };
            let spki: [u8; SPKI_25519_PREFIX_LEN] = [
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, oid_byte, 0x03, 0x21, 0x00,
            ];
            buf.extend_from_slice(&spki);
            buf.extend_from_slice(core::slice::from_raw_parts(pub_raw, 32));
            return Ok(());
        }

        // EC keys: use wc_EccPublicKeyToDer via the internal ecc_key
        if type_ == EVP_PKEY_EC {
            let ecc = wolfcrypt_evp_pkey_get_ecc(key);
            if !ecc.is_null() {
                let ecc_internal = wolfcrypt_evp_pkey_get_ecc_internal(ecc);
                if !ecc_internal.is_null() {
                    let der_len = wc_EccPublicKeyDerSize(ecc_internal, 1);
                    if der_len > 0 {
                        let der = OPENSSL_malloc(der_len as usize) as *mut u8;
                        if !der.is_null() {
                            let actual =
                                wc_EccPublicKeyToDer(ecc_internal, der, der_len as u32, 1);
                            if actual > 0 {
                                let slice = core::slice::from_raw_parts(der, actual as usize);
                                buf.extend_from_slice(slice);
                                OPENSSL_free(der as *mut c_void);
                                return Ok(());
                            }
                            OPENSSL_free(der as *mut c_void);
                        }
                    }
                }
            }
        }

        // RSA: use i2d_PUBKEY
        let mut der: *mut u8 = core::ptr::null_mut();
        let der_len = i2d_PUBKEY(key, &mut der);
        if der_len <= 0 || der.is_null() {
            return Err(Unspecified);
        }
        let slice = core::slice::from_raw_parts(der, der_len as usize);
        buf.extend_from_slice(slice);
        OPENSSL_free(der as *mut c_void);
        Ok(())
    }
}

/// evp_parse_private_key: parse PKCS#8 DER private key from a byte slice.
#[allow(non_snake_case)]
pub(crate) unsafe fn evp_parse_private_key(data: &[u8]) -> *mut EVP_PKEY {
    // SAFETY: caller provides a valid byte slice. FFI calls (d2i_PrivateKey)
    // read at most data.len() bytes from the slice pointer.
    unsafe {
        if data.is_empty() {
            return core::ptr::null_mut();
        }

        // Try Ed25519 via wolfCrypt's ASN.1 decoder (handles v1 and standard v2).
        if let Some(pkey) = parse_ed25519_pkcs8_wc(data) {
            return pkey;
        }

        // Fallback for Ed25519 v2 PKCS#8 (OneAsymmetricKey) encodings that
        // wolfCrypt rejects due to a BIT STRING encoding bug.
        //
        // WOLFSSL BUG: RFC 5958 §2 defines publicKey as "[1] IMPLICIT BIT STRING".
        // BIT STRING content starts with an unused-bits byte, so the correct
        // encoding is: 81 21 00 <32-byte key> (tag=0x81, length=33, content=00+key).
        // wolfSSL's SetAsymKeyDer writes 81 20 <32-byte key> (missing the 00 byte),
        // and DecodeAsymKey reads the raw [1] content without stripping the
        // unused-bits byte, so it passes 33 bytes to wc_ed25519_import_private_key
        // which rejects the key because Ed25519 public keys are 32 bytes.
        //
        // WHEN TO REMOVE: when wolfSSL's SetAsymKeyDer / DecodeAsymKey correctly
        // handles BIT STRING encoding for the [1] publicKey field. At that point
        // parse_ed25519_pkcs8_wc will handle all cases and this can be deleted.
        if let Some(pkey) = parse_ed25519_pkcs8_seed(data) {
            return pkey;
        }

        // Try EC then RSA
        let mut p = data.as_ptr();
        let mut pkey = d2i_PrivateKey(
            EVP_PKEY_EC,
            core::ptr::null_mut(),
            &mut p,
            data.len() as c_long,
        );
        if pkey.is_null() {
            p = data.as_ptr();
            pkey = d2i_PrivateKey(
                EVP_PKEY_RSA,
                core::ptr::null_mut(),
                &mut p,
                data.len() as c_long,
            );
        }
        pkey
    }
}

/// Parse Ed25519 PKCS#8 v1 PrivateKeyInfo (version=0, no embedded public key)
/// using wolfCrypt's wc_Ed25519PrivateKeyDecode.
///
/// Restricted to v1 because wolfCrypt has a BIT STRING encoding bug in v2 keys:
/// it treats the [1] publicKey field as raw bytes instead of as a BIT STRING,
/// so it chokes on the unused-bits prefix byte that BoringSSL/ring include per
/// RFC 5958. It also doesn't validate BIT STRING structure, accepting malformed
/// encodings. v2 keys fall through to parse_ed25519_pkcs8_seed.
unsafe fn parse_ed25519_pkcs8_wc(data: &[u8]) -> Option<*mut EVP_PKEY> {
    // SAFETY: caller provides a valid byte slice containing DER-encoded PKCS#8.
    // Pointer arithmetic on `d` is bounded by `dlen`. The temporary ed25519_key
    // is heap-allocated, initialized, and freed within this function.
    unsafe {
        let d = data.as_ptr();
        let dlen = data.len();

        // Allocate and initialize a temporary ed25519_key for decoding
        let ed_key = OPENSSL_malloc(WC_ED25519_KEY_ALLOC_SIZE) as *mut wc_ed25519_key;
        if ed_key.is_null() {
            return None;
        }
        core::ptr::write_bytes(ed_key as *mut u8, 0, WC_ED25519_KEY_ALLOC_SIZE);

        if wc_ed25519_init(ed_key) != 0 {
            OPENSSL_free(ed_key as *mut c_void);
            return None;
        }

        // Only use wolfCrypt for v1 keys (version=0, no embedded public key).
        // wolfCrypt's decoder is too permissive for v2 keys — it doesn't validate
        // the BIT STRING structure of the [1] public key field. v2 keys are
        // handled by parse_ed25519_pkcs8_seed which validates the structure.
        // v1: 30 2e 02 01 00 ... → version byte at offset content_start + 2
        let (content_start, _) = read_der_length(d, 1, dlen)?;
        if content_start + 3 > dlen {
            return None;
        }
        if *d.add(content_start + 2) != 0x00 {
            // version != 0 → not v1, fall through to seed-extraction fallback
            OPENSSL_free(ed_key as *mut c_void);
            return None;
        }

        let mut idx: u32 = 0;
        let ret = wc_Ed25519PrivateKeyDecode(d, &mut idx, ed_key, dlen as u32);
        if ret != 0 {
            wc_ed25519_free(ed_key);
            OPENSSL_free(ed_key as *mut c_void);
            return None;
        }

        // Export the private seed. v1 has no embedded public key, so we derive it.
        let mut priv_seed = [0u8; 32];
        let mut priv_len: u32 = 32;
        if wc_ed25519_export_private_only(ed_key, priv_seed.as_mut_ptr(), &mut priv_len) != 0
            || priv_len != 32
        {
            wc_ed25519_free(ed_key);
            OPENSSL_free(ed_key as *mut c_void);
            return None;
        }

        wc_ed25519_free(ed_key);
        OPENSSL_free(ed_key as *mut c_void);

        // Build EVP_PKEY — derives the public key from the seed
        let pkey = EVP_PKEY_new_raw_private_key(
            NID_ED25519,
            core::ptr::null_mut(),
            priv_seed.as_ptr(),
            32,
        );
        // Securely wipe private seed (resists dead-store elimination)
        wc_ForceZero(priv_seed.as_mut_ptr() as *mut c_void, priv_seed.len());
        if pkey.is_null() {
            return None;
        }

        Some(pkey)
    }
}

/// Fallback Ed25519 PKCS#8 parser for v2 (OneAsymmetricKey) encodings that
/// wolfCrypt's wc_Ed25519PrivateKeyDecode rejects.
///
/// WHY THIS EXISTS: wolfSSL has a BIT STRING encoding bug in the [1] publicKey
/// field of OneAsymmetricKey (RFC 5958 §2). The field is defined as
/// "[1] IMPLICIT BIT STRING", so the content should include an unused-bits
/// prefix byte: `81 21 00 <32-byte key>`. wolfSSL's SetAsymKeyDer omits
/// this byte (writes `81 20 <key>`), and DecodeAsymKey doesn't strip it
/// on read, causing wc_ed25519_import_private_key to get 33 bytes and fail.
/// BoringSSL and ring encode it correctly per the RFC.
///
/// Additionally, wolfSSL doesn't validate the BIT STRING structure, so it
/// accepts malformed encodings (e.g., truncated public keys) that should
/// be rejected per RFC 5958.
///
/// WHAT IT DOES: sniffs the Ed25519 OID at a known offset, extracts the
/// 32-byte seed, re-derives the public key, and validates any embedded
/// public key (including BIT STRING structure). ~50 lines because Ed25519
/// PKCS#8 has a fixed structure (no variable-length algorithm parameters).
///
/// WHEN TO REMOVE: when wolfSSL correctly encodes/decodes BIT STRING content
/// for the [1] publicKey field in SetAsymKeyDer / DecodeAsymKey.
unsafe fn parse_ed25519_pkcs8_seed(data: &[u8]) -> Option<*mut EVP_PKEY> {
    // SAFETY: caller provides a valid byte slice. All pointer arithmetic on
    // `d` is bounds-checked against `total_consumed` / `dlen` before each
    // dereference. FFI calls (EVP_PKEY_new_raw_private_key, etc.) receive
    // pointers within the validated DER region.
    unsafe {
        let d = data.as_ptr();
        let dlen = data.len();

        // Must start with SEQUENCE
        if dlen < 16 || *d != 0x30 {
            return None;
        }

        // Read outer SEQUENCE length to determine total consumed bytes
        let (content_start, seq_len) = read_der_length(d, 1, dlen)?;
        let total_consumed = content_start + seq_len;
        if total_consumed > dlen {
            return None;
        }

        // Find the Ed25519 OID. It's in the AlgorithmIdentifier after the version.
        // Version is 3 bytes (02 01 xx), AlgID starts with SEQUENCE (30 05).
        // OID offset varies with the SEQUENCE length encoding.
        let oid_off = content_start + 3 + 2; // past version + AlgID SEQUENCE header
        if oid_off + ED25519_OID.len() > total_consumed {
            return None;
        }
        if !ED25519_OID
            .iter()
            .enumerate()
            .all(|(i, &b)| *d.add(oid_off + i) == b)
        {
            return None;
        }

        // Seed is after the OID: OCTET STRING(34) { OCTET STRING(32) { seed } }
        // That's: 04 22 04 20 <32 bytes seed>
        let priv_off = oid_off + ED25519_OID.len();
        if priv_off + 4 + 32 > total_consumed {
            return None;
        }
        if *d.add(priv_off) != 0x04 {
            return None;
        } // outer OCTET STRING
        if *d.add(priv_off + 2) != 0x04 {
            return None;
        } // inner OCTET STRING
        if *d.add(priv_off + 3) != 0x20 {
            return None;
        } // inner length = 32
        let seed = d.add(priv_off + 4);

        // Check for optional fields after the private key OCTET STRING.
        // The private key OCTET STRING is 36 bytes (04 22 04 20 + 32 bytes seed).
        let mut pos = priv_off + 36;
        let mut embedded_pub: *const u8 = core::ptr::null();

        // Skip optional [0] attributes (RFC 5958 §2)
        if pos < total_consumed && *d.add(pos) == 0xa0 {
            let (after_len, attr_len) = read_der_length(d, pos + 1, total_consumed)?;
            pos = after_len + attr_len;
        }

        // Check for optional [1] public key
        if pos < total_consumed {
            let tag = *d.add(pos);
            if tag == 0x81 {
                // Implicit [1]: 81 21 00 <32 bytes> (total 35 bytes)
                if pos + 35 != total_consumed {
                    return None;
                }
                if *d.add(pos + 1) != 0x21 {
                    return None;
                }
                if *d.add(pos + 2) != 0x00 {
                    return None;
                } // BIT STRING unused-bits
                embedded_pub = d.add(pos + 3);
            } else if tag == 0xa1 {
                // Explicit [1] { BIT STRING }: a1 23 03 21 00 <32 bytes> (total 37 bytes)
                if pos + 37 != total_consumed {
                    return None;
                }
                if *d.add(pos + 2) != 0x03 {
                    return None;
                } // BIT STRING tag
                if *d.add(pos + 3) != 0x21 {
                    return None;
                }
                if *d.add(pos + 4) != 0x00 {
                    return None;
                } // unused-bits
                embedded_pub = d.add(pos + 5);
            } else {
                return None; // unknown trailing data
            }
        }

        let pkey = EVP_PKEY_new_raw_private_key(NID_ED25519, core::ptr::null_mut(), seed, 32);
        if pkey.is_null() {
            return None;
        }

        // If an embedded public key is present, verify it matches the derived key.
        if !embedded_pub.is_null() {
            let mut derived_pub = [0u8; 32];
            let mut derived_len: usize = 32;
            if EVP_PKEY_get_raw_public_key(pkey, derived_pub.as_mut_ptr(), &mut derived_len) != 1
                || derived_len != 32
                || CRYPTO_memcmp(
                    derived_pub.as_ptr() as *const c_void,
                    embedded_pub as *const c_void,
                    32,
                ) != 0
            {
                EVP_PKEY_free(pkey);
                return None;
            }
        }

        Some(pkey)
    }
}

/// Read a DER length at the given position. Returns (new_pos, length) or None.
unsafe fn read_der_length(d: *const u8, pos: usize, limit: usize) -> Option<(usize, usize)> {
    // SAFETY: caller must ensure `d` points to at least `limit` readable
    // bytes. All offsets are bounds-checked against `limit` before dereference.
    unsafe {
        if pos >= limit {
            return None;
        }
        let b = *d.add(pos);
        if b < 0x80 {
            Some((pos + 1, b as usize))
        } else if b == 0x81 {
            if pos + 1 >= limit {
                return None;
            }
            Some((pos + 2, *d.add(pos + 1) as usize))
        } else if b == 0x82 {
            if pos + 2 >= limit {
                return None;
            }
            let len = (*d.add(pos + 1) as usize) << 8 | *d.add(pos + 2) as usize;
            Some((pos + 3, len))
        } else {
            None
        }
    }
}

/// evp_parse_public_key: parse SubjectPublicKeyInfo DER public key from a byte slice.
#[allow(non_snake_case)]
pub(crate) unsafe fn evp_parse_public_key(data: &[u8]) -> *mut EVP_PKEY {
    // SAFETY: caller provides a valid byte slice. Pointer offsets are
    // guarded by the `dlen >= 44` length checks. d2i_PUBKEY reads at
    // most data.len() bytes from the slice pointer.
    unsafe {
        if data.is_empty() {
            return core::ptr::null_mut();
        }

        let d = data.as_ptr();
        let dlen = data.len();

        // Check for X25519 SPKI (OID 2b 65 6e): 30 2a 30 05 06 03 2b 65 6e 03 21 00 <32>
        if dlen >= 44
            && *d == 0x30
            && *d.add(1) == 0x2a
            && *d.add(2) == 0x30
            && *d.add(4) == 0x06
            && *d.add(5) == 0x03
            && *d.add(6) == 0x2b
            && *d.add(7) == 0x65
            && *d.add(8) == 0x6e
        {
            if *d.add(9) != 0x03 || *d.add(10) != 0x21 || *d.add(11) != 0x00 {
                return core::ptr::null_mut();
            }
            return EVP_PKEY_new_raw_public_key(NID_X25519, core::ptr::null_mut(), d.add(12), 32);
        }

        // Check for Ed25519 SPKI (OID 2b 65 70): 30 2a 30 05 06 03 2b 65 70 03 21 00 <32>
        if dlen >= 44
            && *d == 0x30
            && *d.add(1) == 0x2a
            && *d.add(2) == 0x30
            && *d.add(4) == 0x06
            && *d.add(5) == 0x03
            && *d.add(6) == 0x2b
            && *d.add(7) == 0x65
            && *d.add(8) == 0x70
        {
            return EVP_PKEY_new_raw_public_key(
                NID_ED25519,
                core::ptr::null_mut(),
                d.add(12),
                32,
            );
        }

        // EC/RSA: use d2i_PUBKEY
        let mut p = data.as_ptr();
        d2i_PUBKEY(core::ptr::null_mut(), &mut p, data.len() as c_long)
    }
}

/// EVP_PKEY_new_raw_private_key: create an EVP_PKEY from raw private key bytes.
/// For Ed25519/X25519, derives the public key and stores [priv(32) | pub(32)]
/// in pkey.ptr. For other types, delegates to wolfSSL_EVP_PKEY_new_mac_key.
///
/// # Safety
/// `key` must be valid for `keylen` bytes.
#[allow(non_snake_case)]
pub(crate) unsafe fn EVP_PKEY_new_raw_private_key(
    type_: c_int,
    _e: *mut ENGINE,
    key: *const u8,
    keylen: usize,
) -> *mut EVP_PKEY {
    // SAFETY: caller must ensure `key` is valid for `keylen` bytes.
    // Temporary wolfCrypt key objects are heap-allocated, used, and freed
    // within each branch. Private key material is securely wiped via
    // wc_ForceZero before returning.
    unsafe {
        if type_ == NID_X25519 && keylen == 32 {
            // Use wolfCrypt's import path which handles RFC 7748 clamping
            // internally (curve25519_priv_clamp in wc_curve25519_import_private_ex).
            let c25519 = OPENSSL_malloc(WC_CURVE25519_KEY_ALLOC_SIZE) as *mut wc_curve25519_key;
            if c25519.is_null() {
                return core::ptr::null_mut();
            }
            core::ptr::write_bytes(c25519 as *mut u8, 0, WC_CURVE25519_KEY_ALLOC_SIZE);

            if wc_curve25519_init(c25519) != 0 {
                OPENSSL_free(c25519 as *mut c_void);
                return core::ptr::null_mut();
            }

            // Import private key only — wolfSSL clamps it and sets pubSet=0.
            // The export call below triggers public key derivation.
            if wc_curve25519_import_private_ex(key, 32, c25519, EC25519_LITTLE_ENDIAN) != 0 {
                wc_curve25519_free(c25519);
                OPENSSL_free(c25519 as *mut c_void);
                return core::ptr::null_mut();
            }

            // Set the RNG for blinding (required by WOLFSSL_CURVE25519_BLINDING,
            // which is auto-enabled). The export call below computes the public
            // key via wc_curve25519_make_pub_blind when pubSet=0.
            let rng = get_thread_rng();
            if rng.is_null() {
                wc_curve25519_free(c25519);
                OPENSSL_free(c25519 as *mut c_void);
                return core::ptr::null_mut();
            }
            wc_curve25519_set_rng(c25519, rng);

            let mut priv_key = [0u8; 32];
            let mut pub_key = [0u8; 32];
            let mut priv_len: u32 = 32;
            let mut pub_len: u32 = 32;
            let ret = wc_curve25519_export_key_raw_ex(
                c25519,
                priv_key.as_mut_ptr(),
                &mut priv_len,
                pub_key.as_mut_ptr(),
                &mut pub_len,
                EC25519_LITTLE_ENDIAN,
            );
            wc_curve25519_free(c25519);
            OPENSSL_free(c25519 as *mut c_void);
            if ret != 0 || priv_len != 32 || pub_len != 32 {
                wc_ForceZero(priv_key.as_mut_ptr() as *mut c_void, priv_key.len());
                return core::ptr::null_mut();
            }

            let pkey = EVP_PKEY_new();
            if pkey.is_null() {
                wc_ForceZero(priv_key.as_mut_ptr() as *mut c_void, priv_key.len());
                return core::ptr::null_mut();
            }
            wolfcrypt_evp_pkey_set_type(pkey, NID_X25519);

            // Store clamped private (32) + public (32) = 64 bytes
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&priv_key);
            combined[32..].copy_from_slice(&pub_key);
            wolfcrypt_evp_pkey_set_raw(pkey, combined.as_ptr(), 64);
            // Securely wipe private key material from stack (resists dead-store elimination)
            wc_ForceZero(priv_key.as_mut_ptr() as *mut c_void, priv_key.len());
            wc_ForceZero(combined.as_mut_ptr() as *mut c_void, combined.len());

            return pkey;
        }

        if type_ == NID_ED25519 && keylen == 32 {
            // Use wolfCrypt to compute public key from seed
            let ed_key = OPENSSL_malloc(WC_ED25519_KEY_ALLOC_SIZE) as *mut wc_ed25519_key;
            if ed_key.is_null() {
                return core::ptr::null_mut();
            }
            core::ptr::write_bytes(ed_key as *mut u8, 0, WC_ED25519_KEY_ALLOC_SIZE);

            if wc_ed25519_init(ed_key) != 0 {
                OPENSSL_free(ed_key as *mut c_void);
                return core::ptr::null_mut();
            }

            if wc_ed25519_import_private_only(key, 32, ed_key) != 0 {
                wc_ed25519_free(ed_key);
                OPENSSL_free(ed_key as *mut c_void);
                return core::ptr::null_mut();
            }

            let mut pub_key = [0u8; 32];
            if wc_ed25519_make_public(ed_key, pub_key.as_mut_ptr(), 32) != 0 {
                wc_ed25519_free(ed_key);
                OPENSSL_free(ed_key as *mut c_void);
                return core::ptr::null_mut();
            }

            wc_ed25519_free(ed_key);
            OPENSSL_free(ed_key as *mut c_void);

            let pkey = EVP_PKEY_new();
            if pkey.is_null() {
                return core::ptr::null_mut();
            }
            wolfcrypt_evp_pkey_set_type(pkey, NID_ED25519);

            // Store seed (32) + public (32) = 64 bytes
            let mut combined = [0u8; 64];
            core::ptr::copy_nonoverlapping(key, combined.as_mut_ptr(), 32);
            combined[32..].copy_from_slice(&pub_key);
            wolfcrypt_evp_pkey_set_raw(pkey, combined.as_ptr(), 64);
            // Securely wipe private key material from stack (resists dead-store elimination)
            wc_ForceZero(combined.as_mut_ptr() as *mut c_void, combined.len());

            return pkey;
        }

        // Fallback for HMAC and other types
        EVP_PKEY_new_mac_key(type_, core::ptr::null_mut(), key, keylen as c_int)
    }
}

/// EVP_PKEY_new_raw_public_key: create an EVP_PKEY from raw public key bytes.
/// For Ed25519/X25519, stores the 32-byte public key in pkey.ptr.
///
/// # Safety
/// `key` must be valid for `keylen` bytes.
#[allow(non_snake_case)]
pub(crate) unsafe fn EVP_PKEY_new_raw_public_key(
    type_: c_int,
    _e: *mut ENGINE,
    key: *const u8,
    keylen: usize,
) -> *mut EVP_PKEY {
    // SAFETY: caller must ensure `key` is valid for `keylen` bytes.
    // EVP_PKEY_new allocates a new key; wolfcrypt_evp_pkey_set_raw copies
    // 32 bytes from `key` into the EVP_PKEY's internal buffer.
    unsafe {
        if (type_ == NID_X25519 || type_ == NID_ED25519) && keylen == 32 {
            let pkey = EVP_PKEY_new();
            if pkey.is_null() {
                return core::ptr::null_mut();
            }
            wolfcrypt_evp_pkey_set_type(pkey, type_);
            wolfcrypt_evp_pkey_set_raw(pkey, key, 32);
            return pkey;
        }
        core::ptr::null_mut()
    }
}

/// EVP_PKEY_get_raw_private_key: extract raw private key bytes.
/// For Ed25519/X25519 with 64-byte storage, returns the first 32 bytes (private key).
///
/// # Safety
/// `pkey` must be a valid EVP_PKEY. `out` (if non-null) must be valid for `*out_len` bytes.
#[allow(non_snake_case)]
pub(crate) unsafe fn EVP_PKEY_get_raw_private_key(
    pkey: *const EVP_PKEY,
    out: *mut u8,
    out_len: *mut usize,
) -> c_int {
    // SAFETY: caller must provide a valid EVP_PKEY. `out` (if non-null) must
    // be valid for at least `*out_len` bytes; we verify `*out_len >= 32`
    // before writing.
    unsafe {
        if pkey.is_null() || out_len.is_null() {
            return 0;
        }
        let type_ = wolfcrypt_evp_pkey_get_type(pkey);
        let pkey_sz = wolfcrypt_evp_pkey_get_pkey_sz(pkey);

        if (type_ == NID_X25519 || type_ == NID_ED25519) && pkey_sz == 64 {
            let ptr = wolfcrypt_evp_pkey_get_pkey_ptr(pkey);
            if ptr.is_null() {
                return 0;
            }
            if out.is_null() {
                *out_len = 32;
                return 1;
            }
            if *out_len < 32 {
                return 0;
            }
            core::ptr::copy_nonoverlapping(ptr, out, 32);
            *out_len = 32;
            return 1;
        }
        0
    }
}

/// EVP_PKEY_get_raw_public_key: extract raw public key bytes.
/// For Ed25519/X25519 with 64-byte storage, returns the last 32 bytes (public key).
/// For 32-byte storage (public-only key), returns all 32 bytes.
///
/// # Safety
/// `pkey` must be a valid EVP_PKEY. `out` (if non-null) must be valid for `*out_len` bytes.
#[allow(non_snake_case)]
pub(crate) unsafe fn EVP_PKEY_get_raw_public_key(
    pkey: *const EVP_PKEY,
    out: *mut u8,
    out_len: *mut usize,
) -> c_int {
    // SAFETY: caller must provide a valid EVP_PKEY. `out` (if non-null) must
    // be valid for at least `*out_len` bytes. For 64-byte storage the public
    // key is at offset 32; for 32-byte storage it starts at offset 0.
    unsafe {
        if pkey.is_null() || out_len.is_null() {
            return 0;
        }
        let type_ = wolfcrypt_evp_pkey_get_type(pkey);
        let pkey_sz = wolfcrypt_evp_pkey_get_pkey_sz(pkey);
        let ptr = wolfcrypt_evp_pkey_get_pkey_ptr(pkey);

        if (type_ == NID_X25519 || type_ == NID_ED25519) && pkey_sz == 64 {
            if ptr.is_null() {
                return 0;
            }
            if out.is_null() {
                *out_len = 32;
                return 1;
            }
            if *out_len < 32 {
                return 0;
            }
            core::ptr::copy_nonoverlapping(ptr.add(32), out, 32);
            *out_len = 32;
            return 1;
        }

        if (type_ == NID_X25519 || type_ == NID_ED25519) && pkey_sz == 32 {
            if ptr.is_null() {
                return 0;
            }
            if out.is_null() {
                *out_len = 32;
                return 1;
            }
            if *out_len < 32 {
                return 0;
            }
            core::ptr::copy_nonoverlapping(ptr, out, 32);
            *out_len = 32;
            return 1;
        }
        0
    }
}

/// EVP_PKEY_keygen_init: returns success for Ed25519/X25519.
#[allow(non_snake_case)]
pub(crate) unsafe fn EVP_PKEY_keygen_init(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: caller must provide a valid EVP_PKEY_CTX. Accessor FFI calls
    // only read from the context; the wolfSSL fallback is called for
    // non-Ed25519/X25519 key types.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        let pkey = wolfcrypt_evp_pkey_ctx_get_pkey(ctx);
        if !pkey.is_null() {
            let t = wolfcrypt_evp_pkey_get_type(pkey);
            if t == NID_ED25519 || t == NID_X25519 {
                return 1;
            }
        }
        crate::wolfcrypt_rs::EVP_PKEY_keygen_init(ctx)
    }
}

/// EVP_PKEY_keygen: for Ed25519/X25519 uses wolfCrypt directly.
#[allow(non_snake_case)]
pub(crate) unsafe fn EVP_PKEY_keygen(ctx: *mut EVP_PKEY_CTX, ppkey: *mut *mut EVP_PKEY) -> c_int {
    // SAFETY: caller must provide valid EVP_PKEY_CTX and output pointer.
    // Temporary wolfCrypt key objects are heap-allocated, used for keygen,
    // and freed within each branch. Private key material is wiped via
    // wc_ForceZero. The generated EVP_PKEY is written to *ppkey on success.
    unsafe {
        if ctx.is_null() || ppkey.is_null() {
            return 0;
        }
        let ctx_pkey = wolfcrypt_evp_pkey_ctx_get_pkey(ctx);
        if ctx_pkey.is_null() {
            return 0;
        }
        let type_ = wolfcrypt_evp_pkey_get_type(ctx_pkey);

        if type_ == NID_X25519 {
            let c25519 = OPENSSL_malloc(WC_CURVE25519_KEY_ALLOC_SIZE) as *mut wc_curve25519_key;
            if c25519.is_null() {
                return 0;
            }
            core::ptr::write_bytes(c25519 as *mut u8, 0, WC_CURVE25519_KEY_ALLOC_SIZE);
            let rng = get_thread_rng();
            if rng.is_null() {
                OPENSSL_free(c25519 as *mut c_void);
                return 0;
            }
            if wc_curve25519_init(c25519) != 0 {
                OPENSSL_free(c25519 as *mut c_void);
                return 0;
            }
            if wc_curve25519_make_key(rng, 32, c25519) != 0 {
                wc_curve25519_free(c25519);
                OPENSSL_free(c25519 as *mut c_void);
                return 0;
            }
            let mut priv_key = [0u8; 32];
            let mut pub_key = [0u8; 32];
            let mut priv_len: u32 = 32;
            let mut pub_len: u32 = 32;
            let ret = wc_curve25519_export_key_raw_ex(
                c25519,
                priv_key.as_mut_ptr(),
                &mut priv_len,
                pub_key.as_mut_ptr(),
                &mut pub_len,
                EC25519_LITTLE_ENDIAN,
            );
            wc_curve25519_free(c25519);
            OPENSSL_free(c25519 as *mut c_void);
            if ret != 0 {
                wc_ForceZero(priv_key.as_mut_ptr() as *mut c_void, priv_key.len());
                return 0;
            }
            let pkey = EVP_PKEY_new();
            if pkey.is_null() {
                wc_ForceZero(priv_key.as_mut_ptr() as *mut c_void, priv_key.len());
                return 0;
            }
            wolfcrypt_evp_pkey_set_type(pkey, NID_X25519);
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&priv_key);
            combined[32..].copy_from_slice(&pub_key);
            wolfcrypt_evp_pkey_set_raw(pkey, combined.as_ptr(), 64);
            // Securely wipe private key material from stack
            wc_ForceZero(priv_key.as_mut_ptr() as *mut c_void, priv_key.len());
            wc_ForceZero(combined.as_mut_ptr() as *mut c_void, combined.len());
            *ppkey = pkey;
            return 1;
        }

        if type_ == NID_ED25519 {
            let ed_key = OPENSSL_malloc(WC_ED25519_KEY_ALLOC_SIZE) as *mut wc_ed25519_key;
            if ed_key.is_null() {
                return 0;
            }
            core::ptr::write_bytes(ed_key as *mut u8, 0, WC_ED25519_KEY_ALLOC_SIZE);
            let rng = get_thread_rng();
            if rng.is_null() {
                OPENSSL_free(ed_key as *mut c_void);
                return 0;
            }
            if wc_ed25519_init(ed_key) != 0 {
                OPENSSL_free(ed_key as *mut c_void);
                return 0;
            }
            if wc_ed25519_make_key(rng, ED25519_KEY_SIZE as c_int, ed_key) != 0 {
                wc_ed25519_free(ed_key);
                OPENSSL_free(ed_key as *mut c_void);
                return 0;
            }
            let mut priv_seed = [0u8; 32];
            let mut pub_key = [0u8; 32];
            let mut priv_len: u32 = 32;
            let mut pub_len: u32 = 32;
            let mut ret =
                wc_ed25519_export_private_only(ed_key, priv_seed.as_mut_ptr(), &mut priv_len);
            if ret == 0 {
                ret = wc_ed25519_export_public(ed_key, pub_key.as_mut_ptr(), &mut pub_len);
            }
            wc_ed25519_free(ed_key);
            OPENSSL_free(ed_key as *mut c_void);
            if ret != 0 {
                wc_ForceZero(priv_seed.as_mut_ptr() as *mut c_void, priv_seed.len());
                return 0;
            }
            let pkey = EVP_PKEY_new();
            if pkey.is_null() {
                wc_ForceZero(priv_seed.as_mut_ptr() as *mut c_void, priv_seed.len());
                return 0;
            }
            wolfcrypt_evp_pkey_set_type(pkey, NID_ED25519);
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&priv_seed);
            combined[32..].copy_from_slice(&pub_key);
            wolfcrypt_evp_pkey_set_raw(pkey, combined.as_ptr(), 64);
            // Securely wipe private key material from stack
            wc_ForceZero(priv_seed.as_mut_ptr() as *mut c_void, priv_seed.len());
            wc_ForceZero(combined.as_mut_ptr() as *mut c_void, combined.len());
            *ppkey = pkey;
            return 1;
        }

        crate::wolfcrypt_rs::EVP_PKEY_keygen(ctx, ppkey)
    }
}

/// EVP_PKEY_derive_init: for X25519 manually sets the op type.
#[allow(non_snake_case)]
pub(crate) unsafe fn EVP_PKEY_derive_init(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: caller must provide a valid EVP_PKEY_CTX. For X25519, we
    // clear the peer key and set the op type; otherwise we delegate to
    // wolfSSL's EVP_PKEY_derive_init.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        let pkey = wolfcrypt_evp_pkey_ctx_get_pkey(ctx);
        if !pkey.is_null() && wolfcrypt_evp_pkey_get_type(pkey) == NID_X25519 {
            wolfcrypt_evp_pkey_ctx_set_peer_key(ctx, core::ptr::null_mut());
            wolfcrypt_evp_pkey_ctx_set_op(ctx, WC_EVP_PKEY_OP_DERIVE);
            return 1;
        }
        crate::wolfcrypt_rs::EVP_PKEY_derive_init(ctx)
    }
}

/// EVP_PKEY_derive_set_peer: for X25519 manually manages the peer key.
#[allow(non_snake_case)]
pub(crate) unsafe fn EVP_PKEY_derive_set_peer(
    ctx: *mut EVP_PKEY_CTX,
    peer: *mut EVP_PKEY,
) -> c_int {
    // SAFETY: caller must provide valid EVP_PKEY_CTX and peer EVP_PKEY.
    // For X25519, the peer key is stored in the context; otherwise we
    // delegate to wolfSSL's EVP_PKEY_derive_set_peer.
    unsafe {
        if ctx.is_null() || peer.is_null() {
            return 0;
        }
        let pkey = wolfcrypt_evp_pkey_ctx_get_pkey(ctx);
        if !pkey.is_null() && wolfcrypt_evp_pkey_get_type(pkey) == NID_X25519 {
            if wolfcrypt_evp_pkey_ctx_get_op(ctx) != WC_EVP_PKEY_OP_DERIVE {
                return 0;
            }
            wolfcrypt_evp_pkey_ctx_set_peer_key(ctx, peer);
            return 1;
        }
        crate::wolfcrypt_rs::EVP_PKEY_derive_set_peer(ctx, peer)
    }
}

/// EVP_PKEY_derive: for X25519 uses wc_curve25519_shared_secret_ex.
#[allow(non_snake_case)]
pub(crate) unsafe fn EVP_PKEY_derive(
    ctx: *mut EVP_PKEY_CTX,
    key: *mut u8,
    keylen: *mut usize,
) -> c_int {
    // SAFETY: caller must provide a valid EVP_PKEY_CTX with derive op
    // initialized and peer key set. `key` (if non-null) must be valid for
    // `*keylen` bytes. Temporary curve25519 key objects are heap-allocated,
    // used for the shared-secret computation, and freed via the cleanup
    // closure before returning.
    unsafe {
        if ctx.is_null() || keylen.is_null() {
            return 0;
        }
        let pkey = wolfcrypt_evp_pkey_ctx_get_pkey(ctx);
        if pkey.is_null() {
            return 0;
        }
        if wolfcrypt_evp_pkey_get_type(pkey) != NID_X25519 {
            return crate::wolfcrypt_rs::EVP_PKEY_derive(ctx, key, keylen);
        }

        let peer_key = wolfcrypt_evp_pkey_ctx_get_peer_key(ctx);
        if peer_key.is_null() {
            return 0;
        }
        let peer_ptr = wolfcrypt_evp_pkey_get_pkey_ptr(peer_key);
        if peer_ptr.is_null() {
            return 0;
        }
        if key.is_null() {
            *keylen = 32;
            return 1;
        }
        if *keylen < 32 {
            return 0;
        }

        let pkey_sz = wolfcrypt_evp_pkey_get_pkey_sz(pkey);
        let pkey_ptr = wolfcrypt_evp_pkey_get_pkey_ptr(pkey);
        if pkey_sz != 64 || pkey_ptr.is_null() {
            return 0;
        }

        let peer_sz = wolfcrypt_evp_pkey_get_pkey_sz(peer_key);
        let peer_pub_raw = if peer_sz == 64 {
            peer_ptr.add(32)
        } else if peer_sz == 32 {
            peer_ptr
        } else {
            return 0;
        };

        let priv_c25519 = OPENSSL_malloc(WC_CURVE25519_KEY_ALLOC_SIZE) as *mut wc_curve25519_key;
        let peer_c25519 = OPENSSL_malloc(WC_CURVE25519_KEY_ALLOC_SIZE) as *mut wc_curve25519_key;
        if priv_c25519.is_null() || peer_c25519.is_null() {
            if !priv_c25519.is_null() {
                OPENSSL_free(priv_c25519 as *mut c_void);
            }
            if !peer_c25519.is_null() {
                OPENSSL_free(peer_c25519 as *mut c_void);
            }
            return 0;
        }
        core::ptr::write_bytes(priv_c25519 as *mut u8, 0, WC_CURVE25519_KEY_ALLOC_SIZE);
        core::ptr::write_bytes(peer_c25519 as *mut u8, 0, WC_CURVE25519_KEY_ALLOC_SIZE);

        let cleanup = || {
            wc_curve25519_free(priv_c25519);
            wc_curve25519_free(peer_c25519);
            OPENSSL_free(priv_c25519 as *mut c_void);
            OPENSSL_free(peer_c25519 as *mut c_void);
        };

        if wc_curve25519_init(priv_c25519) != 0 || wc_curve25519_init(peer_c25519) != 0 {
            cleanup();
            return 0;
        }

        let mut ret = wc_curve25519_import_private_raw_ex(
            pkey_ptr,
            32,
            pkey_ptr.add(32),
            32,
            priv_c25519,
            EC25519_LITTLE_ENDIAN,
        );
        if ret == 0 {
            let mut peer_pub_masked = [0u8; 32];
            core::ptr::copy_nonoverlapping(peer_pub_raw, peer_pub_masked.as_mut_ptr(), 32);
            peer_pub_masked[31] &= 0x7f;
            ret = wc_curve25519_import_public_ex(
                peer_pub_masked.as_ptr(),
                32,
                peer_c25519,
                EC25519_LITTLE_ENDIAN,
            );
        }
        if ret == 0 {
            let derive_rng = get_thread_rng();
            if derive_rng.is_null() {
                ret = -1;
            } else {
                // Set RNG for blinding (required when WOLFSSL_CURVE25519_BLINDING is enabled)
                wc_curve25519_set_rng(priv_c25519, derive_rng);
                let mut out_len: u32 = 32;
                ret = wc_curve25519_shared_secret_ex(
                    priv_c25519,
                    peer_c25519,
                    key,
                    &mut out_len,
                    EC25519_LITTLE_ENDIAN,
                );
                if ret == 0 {
                    *keylen = out_len as usize;
                }
            }
        }
        cleanup();
        if ret == 0 {
            1
        } else {
            0
        }
    }
}

#[allow(non_snake_case)]
pub(crate) unsafe fn EVP_PKEY_CTX_new_id(id: c_int, e: *mut ENGINE) -> *mut EVP_PKEY_CTX {
    // SAFETY: caller must provide a valid algorithm id. The wolfSSL
    // EVP_PKEY_CTX_new_id allocates the context; we then set the key type
    // for X25519/Ed25519 so subsequent operations dispatch correctly.
    unsafe {
        let ctx = crate::wolfcrypt_rs::EVP_PKEY_CTX_new_id(id, e);
        if !ctx.is_null() {
            let pkey = wolfcrypt_evp_pkey_ctx_get_pkey(ctx);
            if !pkey.is_null() && (id == NID_X25519 || id == NID_ED25519) {
                wolfcrypt_evp_pkey_set_type(pkey, id);
            }
        }
        ctx
    }
}

/// Helper: sign an Ed25519 message via wolfCrypt directly.
/// Heap-allocates ed25519_key, imports key material, calls wc_ed25519_sign_msg, frees.
/// Returns signature length or 0.
unsafe fn wc_ed25519_sign_msg_wrapper(
    priv_seed: &[u8],
    pub_key: &[u8],
    msg: &[u8],
    sig_out: &mut [u8],
) -> usize {
    // SAFETY: caller must provide 32-byte seed/pubkey slices and a sig_out
    // buffer of at least 64 bytes. The temporary ed25519_key is heap-
    // allocated, initialized, used for signing, and freed before returning.
    unsafe {
        if priv_seed.len() != 32 || pub_key.len() != 32 || sig_out.len() < 64 {
            return 0;
        }
        // Heap-allocate the ed25519_key to avoid stack overflow with large wolfCrypt structs
        let ed_key = OPENSSL_malloc(WC_ED25519_KEY_ALLOC_SIZE) as *mut wc_ed25519_key;
        if ed_key.is_null() {
            return 0;
        }
        core::ptr::write_bytes(ed_key as *mut u8, 0, WC_ED25519_KEY_ALLOC_SIZE);

        if wc_ed25519_init(ed_key) != 0 {
            OPENSSL_free(ed_key as *mut c_void);
            return 0;
        }

        if wc_ed25519_import_private_key(priv_seed.as_ptr(), 32, pub_key.as_ptr(), 32, ed_key)
            != 0
        {
            wc_ed25519_free(ed_key);
            OPENSSL_free(ed_key as *mut c_void);
            return 0;
        }

        let mut sig_len: u32 = sig_out.len() as u32;
        let ret = wc_ed25519_sign_msg(
            msg.as_ptr(),
            msg.len() as u32,
            sig_out.as_mut_ptr(),
            &mut sig_len,
            ed_key,
        );

        wc_ed25519_free(ed_key);
        OPENSSL_free(ed_key as *mut c_void);

        if ret != 0 {
            0
        } else {
            sig_len as usize
        }
    }
}

/// Helper: verify an Ed25519 signature via wolfCrypt directly.
/// Heap-allocates ed25519_key, imports public key, calls wc_ed25519_verify_msg, frees.
/// Returns true if the signature is valid.
unsafe fn wc_ed25519_verify_msg_wrapper(pub_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    // SAFETY: caller must provide a 32-byte public key slice. The temporary
    // ed25519_key is heap-allocated, initialized, used for verification,
    // and freed before returning.
    unsafe {
        if pub_key.len() != 32 {
            return false;
        }
        let ed_key = OPENSSL_malloc(WC_ED25519_KEY_ALLOC_SIZE) as *mut wc_ed25519_key;
        if ed_key.is_null() {
            return false;
        }
        core::ptr::write_bytes(ed_key as *mut u8, 0, WC_ED25519_KEY_ALLOC_SIZE);

        if wc_ed25519_init(ed_key) != 0 {
            OPENSSL_free(ed_key as *mut c_void);
            return false;
        }

        if wc_ed25519_import_public(pub_key.as_ptr(), 32, ed_key) != 0 {
            wc_ed25519_free(ed_key);
            OPENSSL_free(ed_key as *mut c_void);
            return false;
        }

        let mut verified: c_int = 0;
        let ret = wc_ed25519_verify_msg(
            sig.as_ptr(),
            sig.len() as u32,
            msg.as_ptr(),
            msg.len() as u32,
            &mut verified,
            ed_key,
        );

        wc_ed25519_free(ed_key);
        OPENSSL_free(ed_key as *mut c_void);

        ret == 0 && verified != 0
    }
}

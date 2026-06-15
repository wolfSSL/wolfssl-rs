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
//! # Opaque pointers
//!
//! Some request fields (e.g. `EcdsaSignRequest::key`, `AesGcmEncRequest::aes`)
//! are raw `*mut c_void` pointers to wolfCrypt C structs.  To call wolfCrypt
//! helper functions on them (e.g. `wc_ecc_export_private_only`, reading
//! `aes->keylen`), use the accessor shims in `wolfcrypt_rs` or cast to
//! `wolfcrypt_sys` types.  All pointer dereferences require `unsafe`.
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
//!         my_hw_random_fill(req.out);
//!         CryptoCallbackResult::Success
//!     }
//! }
//!
//! let dev_id = 42;
//! register_device(dev_id, MyHsm).expect("register");
//! // ... use dev_id when creating wolfCrypt objects ...
//! unregister_device(dev_id);
//! ```

use core::ffi::{c_int, c_void};

use alloc::boxed::Box;

use crate::error::{check, WolfCryptError};

// ---------------------------------------------------------------------------
// Result type for callbacks
// ---------------------------------------------------------------------------

/// Result of a crypto callback operation.
#[non_exhaustive]
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
    fn to_c(self) -> c_int {
        match self {
            Self::Success => 0,
            Self::NotAvailable => wolfcrypt_rs::CRYPTOCB_UNAVAILABLE,
            Self::Error(code) => code,
        }
    }
}

// ---------------------------------------------------------------------------
// Request types — RNG and hash (data fully exposed as slices)
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

// ---------------------------------------------------------------------------
// Request types — cipher
// ---------------------------------------------------------------------------

/// AES-GCM encrypt request.
///
/// `aes` is an opaque `Aes*` pointer.  Use [`wolfcrypt_rs::wolfcrypt_aes_keylen`]
/// and [`wolfcrypt_rs::wolfcrypt_aes_devkey`] to extract the key length and key
/// bytes for hardware programming.
pub struct AesGcmEncRequest<'a> {
    /// Opaque `Aes*` pointer — use wolfcrypt_rs Aes accessors for key/reg.
    pub aes: *mut c_void,
    /// Plaintext input.
    pub input: &'a [u8],
    /// Ciphertext output (same length as `input`).
    pub out: &'a mut [u8],
    /// IV / nonce.
    pub iv: &'a [u8],
    /// Authentication tag output (written by the callback).
    pub auth_tag: &'a mut [u8],
    /// Additional authenticated data.
    pub auth_in: &'a [u8],
}

/// AES-GCM decrypt request.
///
/// On authentication failure return [`CryptoCallbackResult::Error`] with the
/// wolfCrypt `AES_GCM_AUTH_E` error code (`-180`).
pub struct AesGcmDecRequest<'a> {
    /// Opaque `Aes*` pointer.
    pub aes: *mut c_void,
    /// Ciphertext input.
    pub input: &'a [u8],
    /// Plaintext output (same length as `input`).
    pub out: &'a mut [u8],
    /// IV / nonce.
    pub iv: &'a [u8],
    /// Authentication tag to verify (read-only on decrypt).
    pub auth_tag: &'a [u8],
    /// Additional authenticated data.
    pub auth_in: &'a [u8],
}

/// AES-CBC encrypt or decrypt request.
///
/// The `encrypting` flag distinguishes the direction.  Both share the same
/// struct layout because the underlying `wc_CryptoInfo.cipher.aescbc` struct
/// does not duplicate fields for enc/dec.
///
/// The IV for CBC is stored in `aes->reg`.  Use
/// [`wolfcrypt_rs::wolfcrypt_aes_reg`] to read it and
/// [`wolfcrypt_rs::wolfcrypt_aes_reg_mut`] to update it after the operation
/// (wolfCrypt expects the chaining register to be updated in-place).
pub struct AesCbcRequest<'a> {
    /// Opaque `Aes*` pointer.
    pub aes: *mut c_void,
    /// `true` for encryption, `false` for decryption.
    pub encrypting: bool,
    /// Input data (must be a multiple of 16 bytes for CBC).
    pub input: &'a [u8],
    /// Output buffer (same length as `input`).
    pub out: &'a mut [u8],
}

/// A symmetric cipher callback request.
#[non_exhaustive]
pub enum CipherRequest<'a> {
    /// AES-GCM encryption.
    AesGcmEncrypt(AesGcmEncRequest<'a>),
    /// AES-GCM decryption.
    AesGcmDecrypt(AesGcmDecRequest<'a>),
    /// AES-CBC encryption or decryption (direction in `AesCbcRequest::encrypting`).
    AesCbc(AesCbcRequest<'a>),
    /// Any cipher type not covered by the variants above.
    Unknown {
        /// `cipher_type` field of `wc_CryptoInfo.cipher`.
        cipher_type: i32,
        /// `enc` field of `wc_CryptoInfo.cipher`.
        encrypting: bool,
    },
}

// ---------------------------------------------------------------------------
// Request types — public key
// ---------------------------------------------------------------------------

/// ECDSA sign request.
///
/// `key` is an opaque `ecc_key*` pointer.  Call wolfCrypt helpers such as
/// `wc_ecc_export_private_only` to extract the key material for hardware.
///
/// On success: write the DER-encoded signature to `out[..n]` and set
/// `*out_len = n`.  `out` is pre-sized to the initial value of `*out_len`.
pub struct EcdsaSignRequest<'a> {
    /// Opaque `ecc_key*` pointer.
    pub key: *mut c_void,
    /// Pre-computed hash (digest) to sign.
    pub hash: &'a [u8],
    /// Output buffer for the DER-encoded signature.
    pub out: &'a mut [u8],
    /// Initially the capacity of `out`; callback must set to bytes written.
    pub out_len: *mut u32,
    /// Opaque `WC_RNG*` pointer.
    pub rng: *mut c_void,
}

/// ECDSA verify request.
///
/// On success set `*result = 1`.  On signature mismatch return
/// [`CryptoCallbackResult::Error`] with `VERIFY_SIGN_ERROR` (-330) and set
/// `*result = 0`.
pub struct EcdsaVerifyRequest<'a> {
    /// Opaque `ecc_key*` pointer.
    pub key: *mut c_void,
    /// DER-encoded signature to verify.
    pub sig: &'a [u8],
    /// Pre-computed hash (digest) to verify against.
    pub hash: &'a [u8],
    /// Set to `1` on success, `0` on failure.
    pub result: *mut c_int,
}

/// ECDH shared-secret request.
///
/// On success: write the 48-byte shared secret to `out[..48]` and set
/// `*out_len = 48`.
pub struct EcdhRequest<'a> {
    /// Opaque private `ecc_key*` pointer.
    pub private_key: *mut c_void,
    /// Opaque public `ecc_key*` pointer (peer's key).
    pub public_key: *mut c_void,
    /// Output buffer for the shared secret.
    pub out: &'a mut [u8],
    /// Initially the capacity of `out`; callback must set to bytes written.
    pub out_len: *mut u32,
}

/// EC key generation request.
pub struct EcKeyGenRequest {
    /// Opaque `ecc_key*` pointer — the callback must fill this key.
    pub key: *mut c_void,
    /// Requested key size in bits.
    pub size: i32,
    /// Curve ID (e.g. `ECC_SECP384R1 = 15`).
    pub curve_id: i32,
    /// Opaque `WC_RNG*` pointer.
    pub rng: *mut c_void,
}

/// A public-key callback request.
#[non_exhaustive]
pub enum PkRequest<'a> {
    /// ECDSA sign.
    EcdsaSign(EcdsaSignRequest<'a>),
    /// ECDSA verify.
    EcdsaVerify(EcdsaVerifyRequest<'a>),
    /// ECDH shared secret.
    Ecdh(EcdhRequest<'a>),
    /// EC key generation.
    EcKeyGen(EcKeyGenRequest),
    /// Any PK type not covered by the variants above.
    Unknown(i32),
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
/// Callback methods are invoked from within wolfCrypt's C code.
/// Implementations must be `Send + Sync`.  Methods receive raw `*mut c_void`
/// pointers for opaque C types; dereferencing them requires `unsafe`.
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
    fn cipher(&self, _req: CipherRequest<'_>) -> CryptoCallbackResult {
        CryptoCallbackResult::NotAvailable
    }

    /// Public-key operation (ECDSA sign/verify, ECDH, EC key generation, etc.).
    fn pk(&self, _req: PkRequest<'_>) -> CryptoCallbackResult {
        CryptoCallbackResult::NotAvailable
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

struct DeviceState {
    callbacks: Box<dyn CryptoCallbacks>,
}

/// The C trampoline called by wolfCrypt.  Dispatches to the Rust trait.
///
/// # Safety
///
/// `ctx` must point to a live `DeviceState`.
/// `info` must be a valid `wc_CryptoInfo` pointer.
unsafe extern "C" fn trampoline(
    _dev_id: c_int,
    info: *mut wolfcrypt_rs::wc_CryptoInfo,
    ctx: *mut c_void,
) -> c_int {
    if ctx.is_null() || info.is_null() {
        return wolfcrypt_rs::CRYPTOCB_UNAVAILABLE;
    }

    // SAFETY: ctx was checked non-null above and points to a live DeviceState allocated in register_device
    let state = unsafe { &*(ctx as *const DeviceState) };
    let info_c = info as *const wolfcrypt_rs::wc_CryptoInfo;
    let info_m = info;

    // SAFETY: info_c was checked non-null and is a valid wc_CryptoInfo pointer from wolfCrypt
    let algo_type = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_get_algo_type(info_c) };

    let result = match algo_type {
        wolfcrypt_rs::WC_ALGO_TYPE_RNG => {
            // SAFETY: info_c is a valid wc_CryptoInfo pointer; accessor returns the RNG output pointer and size
            let out_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_rng_out(info_c) };
            let sz = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_rng_sz(info_c) } as usize;
            if out_ptr.is_null() || sz == 0 {
                return wolfcrypt_rs::CRYPTOCB_UNAVAILABLE;
            }
            // SAFETY: out_ptr is non-null (checked above) and sz bytes are allocated by wolfCrypt
            let out = unsafe { core::slice::from_raw_parts_mut(out_ptr, sz) };
            state.callbacks.rng(RngRequest { out })
        }

        wolfcrypt_rs::WC_ALGO_TYPE_HASH => {
            // SAFETY: info_c is a valid wc_CryptoInfo pointer; accessors extract hash fields
            let hash_type = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hash_type(info_c) };
            let in_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hash_in(info_c) };
            let in_sz =
                unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hash_in_sz(info_c) } as usize;
            let digest_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hash_digest(info_c) };

            // SAFETY: in_ptr/digest_ptr are checked non-null; sizes come from wolfCrypt's wc_CryptoInfo
            let input = if !in_ptr.is_null() && in_sz > 0 {
                unsafe { core::slice::from_raw_parts(in_ptr, in_sz) }
            } else {
                &[]
            };
            // SAFETY: digest_ptr is non-null (checked below); 64 bytes covers SHA-512 (conservative upper bound)
            let digest = if digest_ptr.is_null() {
                None
            } else {
                Some(unsafe { core::slice::from_raw_parts_mut(digest_ptr, 64) })
            };
            state.callbacks.hash(HashRequest {
                hash_type,
                input,
                digest,
            })
        }

        wolfcrypt_rs::WC_ALGO_TYPE_HMAC => {
            // SAFETY: info_c is a valid wc_CryptoInfo pointer; accessors extract HMAC fields
            let mac_type = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hmac_mac_type(info_c) };
            let in_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hmac_in(info_c) };
            let in_sz =
                unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hmac_in_sz(info_c) } as usize;
            let digest_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_hmac_digest(info_c) };

            // SAFETY: in_ptr/digest_ptr are checked non-null; sizes come from wolfCrypt's wc_CryptoInfo
            let input = if !in_ptr.is_null() && in_sz > 0 {
                unsafe { core::slice::from_raw_parts(in_ptr, in_sz) }
            } else {
                &[]
            };
            // SAFETY: digest_ptr is non-null (checked below); 64 bytes covers SHA-512 (conservative upper bound)
            let digest = if digest_ptr.is_null() {
                None
            } else {
                Some(unsafe { core::slice::from_raw_parts_mut(digest_ptr, 64) })
            };
            state.callbacks.hmac(HmacRequest {
                mac_type,
                input,
                digest,
            })
        }

        wolfcrypt_rs::WC_ALGO_TYPE_CIPHER => {
            // SAFETY: info_c is a valid wc_CryptoInfo pointer; accessors extract cipher fields
            let cipher_type = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_type(info_c) };
            let enc = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_enc(info_c) };

            #[cfg(wolfssl_aes_gcm)]
            if cipher_type == wolfcrypt_rs::WC_CIPHER_AES_GCM {
                return build_cipher_aesgcm(state, info_c, info_m, enc != 0);
            }
            if cipher_type == wolfcrypt_rs::WC_CIPHER_AES_CBC {
                return build_cipher_aescbc(state, info_c, info_m, enc != 0);
            }
            state.callbacks.cipher(CipherRequest::Unknown {
                cipher_type,
                encrypting: enc != 0,
            })
        }

        wolfcrypt_rs::WC_ALGO_TYPE_PK => {
            // SAFETY: info_c is a valid wc_CryptoInfo pointer; accessor extracts PK type field
            let pk_type = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_type(info_c) };

            #[cfg(wolfssl_ecc)]
            {
                if pk_type == wolfcrypt_rs::WC_PK_TYPE_ECDSA_SIGN {
                    return build_pk_ecdsasign(state, info_c, info_m);
                }
                if pk_type == wolfcrypt_rs::WC_PK_TYPE_ECDSA_VERIFY {
                    return build_pk_ecdsaverify(state, info_c, info_m);
                }
                if pk_type == wolfcrypt_rs::WC_PK_TYPE_ECDH {
                    return build_pk_ecdh(state, info_c, info_m);
                }
                if pk_type == wolfcrypt_rs::WC_PK_TYPE_EC_KEYGEN {
                    return build_pk_eckg(state, info_c);
                }
            }
            state.callbacks.pk(PkRequest::Unknown(pk_type))
        }

        _ => CryptoCallbackResult::NotAvailable,
    };

    result.to_c()
}

// ---------------------------------------------------------------------------
// Trampoline helpers — build typed requests and call the trait
// ---------------------------------------------------------------------------

#[cfg(wolfssl_aes_gcm)]
unsafe fn build_cipher_aesgcm(
    state: &DeviceState,
    info_c: *const wolfcrypt_rs::wc_CryptoInfo,
    info_m: *mut wolfcrypt_rs::wc_CryptoInfo,
    encrypting: bool,
) -> c_int {
    if encrypting {
        // SAFETY: info_c/info_m are valid wc_CryptoInfo pointers; accessors extract AES-GCM encrypt fields
        let aes = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_enc_aes(info_c) };
        let out = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_enc_out(info_m) };
        let inp = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_enc_in(info_c) };
        let sz =
            unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_enc_sz(info_c) } as usize;
        // SAFETY: info_c is a valid wc_CryptoInfo pointer; accessors extract IV, tag, and AAD fields
        let iv = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_enc_iv(info_c) };
        let ivsz = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_enc_iv_sz(info_c) }
            as usize;
        // SAFETY: info_c/info_m are valid wc_CryptoInfo pointers; accessors extract tag and AAD fields
        let tag =
            unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_enc_auth_tag(info_m) };
        let tagsz =
            unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_enc_auth_tag_sz(info_c) }
                as usize;
        // SAFETY: info_c is a valid wc_CryptoInfo pointer; accessors extract AAD pointer and size
        let ain =
            unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_enc_auth_in(info_c) };
        let ainsz =
            unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_enc_auth_in_sz(info_c) }
                as usize;

        // SAFETY: each pointer is checked non-null and size comes from the corresponding wc_CryptoInfo field
        let input = if !inp.is_null() && sz > 0 {
            unsafe { core::slice::from_raw_parts(inp, sz) }
        } else {
            &[]
        };
        // SAFETY: out is non-null (checked); sz bytes are allocated by wolfCrypt for ciphertext output
        let out_sl = if !out.is_null() && sz > 0 {
            unsafe { core::slice::from_raw_parts_mut(out, sz) }
        } else {
            &mut []
        };
        // SAFETY: iv is non-null (checked); ivsz bytes are the IV/nonce from wc_CryptoInfo
        let iv_sl = if !iv.is_null() && ivsz > 0 {
            unsafe { core::slice::from_raw_parts(iv, ivsz) }
        } else {
            &[]
        };
        // SAFETY: tag/ain are non-null (checked); tagsz/ainsz from wc_CryptoInfo fields
        let tag_sl = if !tag.is_null() && tagsz > 0 {
            unsafe { core::slice::from_raw_parts_mut(tag, tagsz) }
        } else {
            &mut []
        };
        // SAFETY: ain is non-null (checked); ainsz bytes from wc_CryptoInfo AAD field
        let auth_in = if !ain.is_null() && ainsz > 0 {
            unsafe { core::slice::from_raw_parts(ain, ainsz) }
        } else {
            &[]
        };

        state
            .callbacks
            .cipher(CipherRequest::AesGcmEncrypt(AesGcmEncRequest {
                aes,
                input,
                out: out_sl,
                iv: iv_sl,
                auth_tag: tag_sl,
                auth_in,
            }))
            .to_c()
    } else {
        // SAFETY: info_c/info_m are valid wc_CryptoInfo pointers; accessors extract AES-GCM decrypt fields
        let aes = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_dec_aes(info_c) };
        let out = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_dec_out(info_m) };
        let inp = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_dec_in(info_c) };
        let sz =
            unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_dec_sz(info_c) } as usize;
        // SAFETY: info_c is a valid wc_CryptoInfo pointer; accessors extract IV, tag, and AAD fields
        let iv = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_dec_iv(info_c) };
        let ivsz = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_dec_iv_sz(info_c) }
            as usize;
        // SAFETY: info_c is a valid wc_CryptoInfo pointer; accessors extract tag and AAD fields
        let tag =
            unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_dec_auth_tag(info_c) };
        let tagsz =
            unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_dec_auth_tag_sz(info_c) }
                as usize;
        // SAFETY: info_c is a valid wc_CryptoInfo pointer; accessors extract AAD pointer and size
        let ain =
            unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_dec_auth_in(info_c) };
        let ainsz =
            unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aesgcm_dec_auth_in_sz(info_c) }
                as usize;

        // SAFETY: each pointer is checked non-null and size comes from the corresponding wc_CryptoInfo field
        let input = if !inp.is_null() && sz > 0 {
            unsafe { core::slice::from_raw_parts(inp, sz) }
        } else {
            &[]
        };
        // SAFETY: out is non-null (checked); sz bytes are allocated by wolfCrypt for plaintext output
        let out_sl = if !out.is_null() && sz > 0 {
            unsafe { core::slice::from_raw_parts_mut(out, sz) }
        } else {
            &mut []
        };
        // SAFETY: iv is non-null (checked); ivsz bytes are the IV/nonce from wc_CryptoInfo
        let iv_sl = if !iv.is_null() && ivsz > 0 {
            unsafe { core::slice::from_raw_parts(iv, ivsz) }
        } else {
            &[]
        };
        // SAFETY: tag/ain are non-null (checked); tagsz/ainsz from wc_CryptoInfo fields
        let tag_sl = if !tag.is_null() && tagsz > 0 {
            unsafe { core::slice::from_raw_parts(tag, tagsz) }
        } else {
            &[]
        };
        // SAFETY: ain is non-null (checked); ainsz bytes from wc_CryptoInfo AAD field
        let auth_in = if !ain.is_null() && ainsz > 0 {
            unsafe { core::slice::from_raw_parts(ain, ainsz) }
        } else {
            &[]
        };

        state
            .callbacks
            .cipher(CipherRequest::AesGcmDecrypt(AesGcmDecRequest {
                aes,
                input,
                out: out_sl,
                iv: iv_sl,
                auth_tag: tag_sl,
                auth_in,
            }))
            .to_c()
    }
}

unsafe fn build_cipher_aescbc(
    state: &DeviceState,
    info_c: *const wolfcrypt_rs::wc_CryptoInfo,
    info_m: *mut wolfcrypt_rs::wc_CryptoInfo,
    encrypting: bool,
) -> c_int {
    // SAFETY: info_c/info_m are valid wc_CryptoInfo pointers; accessors extract AES-CBC fields
    let aes = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aescbc_aes(info_c) };
    let out = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aescbc_out(info_m) };
    let inp = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aescbc_in(info_c) };
    let sz = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_cipher_aescbc_sz(info_c) } as usize;

    // SAFETY: each pointer is checked non-null and sz comes from the wc_CryptoInfo field
    let input = if !inp.is_null() && sz > 0 {
        unsafe { core::slice::from_raw_parts(inp, sz) }
    } else {
        &[]
    };
    // SAFETY: out is non-null (checked) and sz bytes are allocated by wolfCrypt
    let out_sl = if !out.is_null() && sz > 0 {
        unsafe { core::slice::from_raw_parts_mut(out, sz) }
    } else {
        &mut []
    };

    state
        .callbacks
        .cipher(CipherRequest::AesCbc(AesCbcRequest {
            aes,
            encrypting,
            input,
            out: out_sl,
        }))
        .to_c()
}

#[cfg(wolfssl_ecc)]
unsafe fn build_pk_ecdsasign(
    state: &DeviceState,
    info_c: *const wolfcrypt_rs::wc_CryptoInfo,
    info_m: *mut wolfcrypt_rs::wc_CryptoInfo,
) -> c_int {
    // SAFETY: info_c/info_m are valid wc_CryptoInfo pointers; accessors extract ECDSA sign fields
    let key = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eccsign_key(info_c) };
    let in_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eccsign_in(info_c) };
    let inlen = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eccsign_inlen(info_c) } as usize;
    let out_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eccsign_out(info_m) };
    let out_len = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eccsign_outlen(info_m) };
    // SAFETY: info_c is a valid wc_CryptoInfo pointer; accessor extracts the RNG field
    let rng = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eccsign_rng(info_c) };

    // SAFETY: pointers are checked non-null; sizes come from wolfCrypt's wc_CryptoInfo fields
    let hash = if !in_ptr.is_null() && inlen > 0 {
        unsafe { core::slice::from_raw_parts(in_ptr, inlen) }
    } else {
        &[]
    };
    let cap = if out_len.is_null() {
        0
    } else {
        // SAFETY: out_len is non-null (checked above) and points to a valid u32 in wc_CryptoInfo
        (unsafe { *out_len }) as usize
    };
    let out = if !out_ptr.is_null() && cap > 0 {
        unsafe { core::slice::from_raw_parts_mut(out_ptr, cap) }
    } else {
        &mut []
    };

    state
        .callbacks
        .pk(PkRequest::EcdsaSign(EcdsaSignRequest {
            key,
            hash,
            out,
            out_len,
            rng,
        }))
        .to_c()
}

#[cfg(wolfssl_ecc)]
unsafe fn build_pk_ecdsaverify(
    state: &DeviceState,
    info_c: *const wolfcrypt_rs::wc_CryptoInfo,
    info_m: *mut wolfcrypt_rs::wc_CryptoInfo,
) -> c_int {
    // SAFETY: info_c/info_m are valid wc_CryptoInfo pointers; accessors extract ECDSA verify fields
    let key = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eccverify_key(info_c) };
    let sig_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eccverify_sig(info_c) };
    let siglen =
        unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eccverify_siglen(info_c) } as usize;
    // SAFETY: info_c/info_m are valid wc_CryptoInfo pointers; accessors extract hash, hashlen, and result
    let hash_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eccverify_hash(info_c) };
    let hashlen =
        unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eccverify_hashlen(info_c) } as usize;
    let result = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eccverify_res(info_m) };

    // SAFETY: pointers are checked non-null; sizes come from wolfCrypt's wc_CryptoInfo fields
    let sig = if !sig_ptr.is_null() && siglen > 0 {
        unsafe { core::slice::from_raw_parts(sig_ptr, siglen) }
    } else {
        &[]
    };
    // SAFETY: hash_ptr is non-null (checked); hashlen bytes from wc_CryptoInfo
    let hash = if !hash_ptr.is_null() && hashlen > 0 {
        unsafe { core::slice::from_raw_parts(hash_ptr, hashlen) }
    } else {
        &[]
    };

    state
        .callbacks
        .pk(PkRequest::EcdsaVerify(EcdsaVerifyRequest {
            key,
            sig,
            hash,
            result,
        }))
        .to_c()
}

#[cfg(wolfssl_ecc)]
unsafe fn build_pk_ecdh(
    state: &DeviceState,
    info_c: *const wolfcrypt_rs::wc_CryptoInfo,
    info_m: *mut wolfcrypt_rs::wc_CryptoInfo,
) -> c_int {
    // SAFETY: info_c/info_m are valid wc_CryptoInfo pointers; accessors extract ECDH fields
    let private_key = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_ecdh_private_key(info_c) };
    let public_key = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_ecdh_public_key(info_c) };
    let out_ptr = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_ecdh_out(info_m) };
    let out_len = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_ecdh_outlen(info_m) };

    // SAFETY: pointers are checked non-null; cap read from valid u32 in wc_CryptoInfo
    let cap = if out_len.is_null() {
        0
    } else {
        // SAFETY: out_len is non-null (checked above) and points to a valid u32 in wc_CryptoInfo
        (unsafe { *out_len }) as usize
    };
    let out = if !out_ptr.is_null() && cap > 0 {
        unsafe { core::slice::from_raw_parts_mut(out_ptr, cap) }
    } else {
        &mut []
    };

    state
        .callbacks
        .pk(PkRequest::Ecdh(EcdhRequest {
            private_key,
            public_key,
            out,
            out_len,
        }))
        .to_c()
}

#[cfg(wolfssl_ecc)]
unsafe fn build_pk_eckg(state: &DeviceState, info_c: *const wolfcrypt_rs::wc_CryptoInfo) -> c_int {
    // SAFETY: info_c is a valid wc_CryptoInfo pointer; accessors extract EC key generation fields
    let key = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eckg_key(info_c) };
    let size = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eckg_size(info_c) };
    let curve_id = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eckg_curve_id(info_c) };
    let rng = unsafe { wolfcrypt_rs::wolfcrypt_cryptocb_info_pk_eckg_rng(info_c) };

    state
        .callbacks
        .pk(PkRequest::EcKeyGen(EcKeyGenRequest {
            key,
            size,
            curve_id,
            rng,
        }))
        .to_c()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

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

    // SAFETY: ctx is a valid heap pointer from Box::into_raw; trampoline matches the expected C signature
    let rc = unsafe { wolfcrypt_rs::wc_CryptoCb_RegisterDevice(dev_id, Some(trampoline), ctx) };

    if rc != 0 {
        // SAFETY: ctx was created by Box::into_raw above and has not been consumed
        unsafe {
            drop(Box::from_raw(ctx as *mut DeviceState));
        }
        return Err(WolfCryptError::Ffi {
            code: rc,
            func: "wc_CryptoCb_RegisterDevice",
        });
    }

    Ok(())
}

/// Unregister a crypto callback device.
///
/// # Safety
///
/// The caller must ensure no wolfCrypt operations using this `dev_id` are
/// in progress on other threads when this is called.
pub fn unregister_device(dev_id: i32) {
    // wolfCrypt doesn't return the ctx pointer on unregister, so we cannot
    // reclaim the DeviceState Box here.  This leaks the allocation — acceptable
    // for long-lived HSM registrations but should be fixed with a side-table
    // mapping dev_id -> *mut DeviceState for production use.
    // SAFETY: dev_id was previously registered; caller ensures no concurrent operations use this device
    unsafe {
        wolfcrypt_rs::wc_CryptoCb_UnRegisterDevice(dev_id);
    }
}

// ---------------------------------------------------------------------------
// Re-exported constants
// ---------------------------------------------------------------------------

/// Re-export the constants callers need for matching operation types.
pub mod algo_type {
    pub use wolfcrypt_rs::WC_ALGO_TYPE_CIPHER;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_CMAC;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_HASH;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_HMAC;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_NONE;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_PK;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_RNG;
    pub use wolfcrypt_rs::WC_ALGO_TYPE_SEED;
}

/// Re-export cipher type constants.
pub mod cipher_type {
    pub use wolfcrypt_rs::WC_CIPHER_AES_CBC;
    pub use wolfcrypt_rs::WC_CIPHER_AES_CCM;
    pub use wolfcrypt_rs::WC_CIPHER_AES_CTR;
    pub use wolfcrypt_rs::WC_CIPHER_AES_ECB;
    pub use wolfcrypt_rs::WC_CIPHER_AES_GCM;
}

/// Re-export PK type constants.
pub mod pk_type {
    pub use wolfcrypt_rs::WC_PK_TYPE_ECDH;
    pub use wolfcrypt_rs::WC_PK_TYPE_ECDSA_SIGN;
    pub use wolfcrypt_rs::WC_PK_TYPE_ECDSA_VERIFY;
    pub use wolfcrypt_rs::WC_PK_TYPE_EC_KEYGEN;
    pub use wolfcrypt_rs::WC_PK_TYPE_ED25519_SIGN;
    pub use wolfcrypt_rs::WC_PK_TYPE_ED25519_VERIFY;
    pub use wolfcrypt_rs::WC_PK_TYPE_RSA;
}

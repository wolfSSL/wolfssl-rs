//! wolfcrypt-rs: Low-level FFI bindings for wolfSSL/wolfCrypt
//!
//! This crate compiles wolfSSL from source and provides Rust FFI bindings.
//! Most functions are direct FFI calls via `#[link_name]` to wolfSSL symbols.
//! A small C shim (compat_shim.c) provides struct field accessors for
//! opaque wolfSSL types whose layouts Rust cannot know.
//!
//! # Naming convention
//!
//! Type, function, and constant names mirror the upstream C identifiers so
//! that grep works across both codebases.  wolfSSL itself is inconsistent
//! (`Aes` vs `wc_ed25519_key`), so this crate inherits that mix of
//! CamelCase and snake\_case.  The `non_camel_case_types` /
//! `non_snake_case` lints are suppressed crate-wide for this reason.

#![no_std]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![allow(clippy::upper_case_acronyms)]

use core::ffi::c_void;
use core::ffi::c_char;
use core::ffi::c_int;
// Used only in OpenSSL compat FFI declarations (cfg-gated below).
#[cfg(wolfssl_openssl_extra)]
use core::ffi::{c_uint, c_long, c_ulong};

// Sizing policy for stack-allocated opaque structs: pick a round size
// at or above the actual wolfSSL struct size. Sizes are verified at
// compile time by _Static_assert in compat_shim.c — if the actual
// struct outgrows the allocation, the build fails.
//
// All allocation sizes are defined here as named constants.

/// Allocation size for wolfSSL's `WOLFSSL_AES_KEY` (OpenSSL compat).
#[cfg(wolfssl_openssl_extra)]
pub const AES_KEY_ALLOC_SIZE: usize = 352;
/// Allocation size for wolfCrypt's `Aes` struct.
pub const WC_AES_ALLOC_SIZE: usize = 512;
/// Allocation size for wolfCrypt's `WC_RNG` struct.
pub const WC_RNG_ALLOC_SIZE: usize = 64;
/// Allocation size for wolfCrypt's `Poly1305` struct.
#[cfg(wolfssl_poly1305)]
pub const POLY1305_ALLOC_SIZE: usize = 512;
/// Allocation size for wolfCrypt's `ChaCha` struct.
#[cfg(wolfssl_chacha)]
pub const CHACHA_ALLOC_SIZE: usize = 128;
/// Allocation size for wolfCrypt's `ChaChaPoly_Aead` struct.
#[cfg(wolfssl_chacha20_poly1305)]
pub const CHACHA_POLY_AEAD_ALLOC_SIZE: usize = 192;

/// Version string of the linked wolfSSL C library (e.g. `"5.7.4"`).
///
/// Set at compile time from `LIBWOLFSSL_VERSION_STRING` in `wolfssl/version.h`.
/// Returns `"unknown"` if the header was not found during the build.
pub const WOLFSSL_VERSION: &str = env!("WOLFSSL_VERSION");

// ================================================================
// Opaque types (used behind pointers)
// ================================================================

/// Opaque EVP_MD (message digest algorithm descriptor)
#[cfg(wolfssl_openssl_extra)]
#[repr(C)]
pub struct EVP_MD {
    _opaque: [u8; 0],
}

/// Opaque EVP_MD_CTX (message digest context)
/// Heap-allocated via EVP_MD_CTX_new / EVP_MD_CTX_free.
#[cfg(wolfssl_openssl_extra)]
#[repr(C)]
pub struct EVP_MD_CTX {
    _opaque: [u8; 0],
}

/// Opaque EVP_CIPHER (cipher algorithm descriptor)
#[cfg(wolfssl_openssl_extra)]
#[repr(C)]
pub struct EVP_CIPHER {
    _opaque: [u8; 0],
}

/// Opaque EVP_CIPHER_CTX
#[cfg(wolfssl_openssl_extra)]
#[repr(C)]
pub struct EVP_CIPHER_CTX {
    _opaque: [u8; 0],
}

/// Opaque EVP_PKEY
#[cfg(wolfssl_openssl_extra)]
#[repr(C)]
pub struct EVP_PKEY {
    _opaque: [u8; 0],
}

/// Opaque EVP_PKEY_CTX
#[cfg(wolfssl_openssl_extra)]
#[repr(C)]
pub struct EVP_PKEY_CTX {
    _opaque: [u8; 0],
}

/// Opaque BIGNUM
#[cfg(wolfssl_openssl_extra)]
#[repr(C)]
pub struct BIGNUM {
    _opaque: [u8; 0],
}

/// Opaque EC_GROUP
#[cfg(wolfssl_ecc)]
#[repr(C)]
pub struct EC_GROUP {
    _opaque: [u8; 0],
}

/// Opaque EC_KEY
#[cfg(wolfssl_ecc)]
#[repr(C)]
pub struct EC_KEY {
    _opaque: [u8; 0],
}

/// Opaque EC_POINT
#[cfg(wolfssl_ecc)]
#[repr(C)]
pub struct EC_POINT {
    _opaque: [u8; 0],
}

/// Opaque ECDSA_SIG
#[cfg(wolfssl_ecc)]
#[repr(C)]
pub struct ECDSA_SIG {
    _opaque: [u8; 0],
}

/// Opaque RSA
#[cfg(wolfssl_rsa)]
#[repr(C)]
pub struct RSA {
    _opaque: [u8; 0],
}

/// Opaque DH
#[cfg(wolfssl_dh)]
#[repr(C)]
pub struct DH {
    _opaque: [u8; 0],
}

/// Opaque HMAC_CTX (message authentication context)
/// Heap-allocated via HMAC_CTX_new / HMAC_CTX_free.
#[cfg(wolfssl_hmac)]
#[repr(C)]
pub struct HMAC_CTX {
    _opaque: [u8; 0],
}

/// Opaque CMAC_CTX (CMAC authentication context)
/// Heap-allocated via CMAC_CTX_new / CMAC_CTX_free.
#[cfg(wolfssl_cmac)]
#[repr(C)]
pub struct CMAC_CTX {
    _opaque: [u8; 0],
}

/// Opaque ENGINE (always NULL in our usage)
#[cfg(wolfssl_openssl_extra)]
#[repr(C)]
pub struct ENGINE {
    _opaque: [u8; 0],
}

/// AES_KEY structure — sized to hold wolfSSL's WOLFSSL_AES_KEY.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_openssl_extra)]
#[repr(C)]
pub struct AES_KEY {
    _opaque: [u8; AES_KEY_ALLOC_SIZE],
}

#[cfg(wolfssl_openssl_extra)]
impl AES_KEY {
    /// Create a zero-initialized `AES_KEY`. Must be passed to
    /// `AES_set_encrypt_key` or `AES_set_decrypt_key` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; AES_KEY_ALLOC_SIZE] }
    }
}

/// wolfCrypt Aes struct (for native wc_Aes* functions).
/// Distinct from AES_KEY which is the OpenSSL-compat WOLFSSL_AES_KEY.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[repr(C, align(16))]
pub struct WcAes {
    _opaque: [u8; WC_AES_ALLOC_SIZE],
}

impl WcAes {
    /// Create a zero-initialized `WcAes`. Must be passed to `wc_AesInit`
    /// before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_AES_ALLOC_SIZE] }
    }
}

/// wolfCrypt ed25519_key — sized to hold wolfSSL's ed25519_key struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_ed25519)]
#[repr(C, align(8))]
pub struct wc_ed25519_key {
    _opaque: [u8; WC_ED25519_KEY_ALLOC_SIZE],
}

#[cfg(wolfssl_ed25519)]
impl wc_ed25519_key {
    /// Create a zero-initialized `wc_ed25519_key`. Must be passed to
    /// `wc_ed25519_init` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_ED25519_KEY_ALLOC_SIZE] }
    }
}

/// wolfCrypt curve25519_key — sized to hold wolfSSL's curve25519_key struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_curve25519)]
#[repr(C, align(8))]
pub struct wc_curve25519_key {
    _opaque: [u8; WC_CURVE25519_KEY_ALLOC_SIZE],
}

#[cfg(wolfssl_curve25519)]
impl wc_curve25519_key {
    /// Create a zero-initialized `wc_curve25519_key`. Must be passed to
    /// `wc_curve25519_init` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_CURVE25519_KEY_ALLOC_SIZE] }
    }
}

/// wolfCrypt ed448_key — sized to hold wolfSSL's ed448_key struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_ed448)]
#[repr(C, align(8))]
pub struct wc_ed448_key {
    _opaque: [u8; WC_ED448_KEY_ALLOC_SIZE],
}

#[cfg(wolfssl_ed448)]
impl wc_ed448_key {
    /// Create a zero-initialized `wc_ed448_key`. Must be passed to
    /// `wc_ed448_init` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_ED448_KEY_ALLOC_SIZE] }
    }
}

/// wolfCrypt curve448_key — sized to hold wolfSSL's curve448_key struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_curve448)]
#[repr(C, align(8))]
pub struct wc_curve448_key {
    _opaque: [u8; WC_CURVE448_KEY_ALLOC_SIZE],
}

#[cfg(wolfssl_curve448)]
impl wc_curve448_key {
    /// Create a zero-initialized `wc_curve448_key`. Must be passed to
    /// `wc_curve448_init` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_CURVE448_KEY_ALLOC_SIZE] }
    }
}

/// Allocation size for wolfCrypt's `dilithium_key` struct.
/// Verified by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_dilithium)]
pub const WC_DILITHIUM_KEY_ALLOC_SIZE: usize = 8192;

/// wolfCrypt dilithium_key — sized to hold wolfSSL's dilithium_key struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_dilithium)]
#[repr(C, align(8))]
pub struct wc_dilithium_key {
    _opaque: [u8; WC_DILITHIUM_KEY_ALLOC_SIZE],
}

#[cfg(wolfssl_dilithium)]
impl wc_dilithium_key {
    /// Create a zero-initialized `wc_dilithium_key`. Must be passed to
    /// `wc_dilithium_init` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_DILITHIUM_KEY_ALLOC_SIZE] }
    }
}

/// wolfCrypt WC_RNG (random number generator context).
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[repr(C, align(8))]
pub struct WC_RNG {
    _opaque: [u8; WC_RNG_ALLOC_SIZE],
}

impl WC_RNG {
    /// Create a zero-initialized `WC_RNG`. Must be passed to `wc_InitRng`
    /// before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_RNG_ALLOC_SIZE] }
    }
}

/// Opaque wolfCrypt ecc_key (internal, behind EC_KEY).
/// Used only behind pointers — never stack-allocated. ECC keys are managed
/// through the OpenSSL compat layer (EC_KEY), unlike ed25519/curve25519/etc.
/// which are stack-allocated with known sizes.
#[cfg(wolfssl_ecc)]
#[repr(C)]
pub struct wc_ecc_key {
    _opaque: [u8; 0],
}

/// Poly1305 state — sized to hold wolfSSL's Poly1305 struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_poly1305)]
#[repr(C, align(64))]
pub struct poly1305_state {
    _opaque: [u8; POLY1305_ALLOC_SIZE],
}

#[cfg(wolfssl_poly1305)]
impl poly1305_state {
    /// Create a zero-initialized `poly1305_state`. Must be passed to
    /// `wc_Poly1305SetKey` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; POLY1305_ALLOC_SIZE] }
    }
}

/// ChaCha state — sized to hold wolfSSL's ChaCha struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_chacha)]
#[repr(C, align(16))]
pub struct ChaCha {
    _opaque: [u8; CHACHA_ALLOC_SIZE],
}

#[cfg(wolfssl_chacha)]
impl ChaCha {
    /// Create a zero-initialized `ChaCha`. Must be passed to
    /// `wc_Chacha_SetKey` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; CHACHA_ALLOC_SIZE] }
    }
}

/// ChaChaPoly_Aead state — sized to hold wolfSSL's streaming
/// ChaCha20-Poly1305 AEAD struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_chacha20_poly1305)]
#[repr(C, align(8))]
pub struct ChaChaPoly_Aead {
    _opaque: [u8; CHACHA_POLY_AEAD_ALLOC_SIZE],
}

#[cfg(wolfssl_chacha20_poly1305)]
impl ChaChaPoly_Aead {
    /// Create a zero-initialized `ChaChaPoly_Aead`. Must be passed to
    /// `wc_ChaCha20Poly1305_Init` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; CHACHA_POLY_AEAD_ALLOC_SIZE] }
    }
}

// ================================================================
// Constants
// ================================================================

// ---- AES constants ----

/// wolfSSL `AES_ENCRYPTION` from `wolfssl/wolfcrypt/aes.h`.
/// Verified at compile time by `_Static_assert` in compat_shim.c.
pub const AES_ENCRYPT: c_int = 0;
/// wolfSSL `AES_DECRYPTION` from `wolfssl/wolfcrypt/aes.h`.
/// Verified at compile time by `_Static_assert` in compat_shim.c.
pub const AES_DECRYPT: c_int = 1;
/// AES-GCM tag length
#[cfg(wolfssl_aes_gcm)]
pub const AES_GCM_TAG_LEN: usize = 16;
/// AES-GCM / ChaCha20 nonce length
pub const AEAD_NONCE_LEN: usize = 12;

// ---- EVP_PKEY type constants ----

#[cfg(wolfssl_rsa)]
pub const EVP_PKEY_RSA: c_int = 16;
#[cfg(wolfssl_ecc)]
pub const EVP_PKEY_EC: c_int = 18;
/// wolfSSL does not distinguish RSA-PSS from RSA at the EVP_PKEY type level.
#[cfg(wolfssl_rsa)]
pub const EVP_PKEY_RSA_PSS: c_int = EVP_PKEY_RSA;
/// wolfSSL uses the NID as the EVP_PKEY type for Ed25519.
#[cfg(wolfssl_ed25519)]
pub const EVP_PKEY_ED25519: c_int = NID_ED25519;
/// wolfSSL uses the NID as the EVP_PKEY type for X25519.
#[cfg(wolfssl_curve25519)]
pub const EVP_PKEY_X25519: c_int = NID_X25519;
/// WC_EVP_PKEY_OP_DERIVE (1 << 8) from wolfSSL
#[cfg(wolfssl_openssl_extra)]
pub const WC_EVP_PKEY_OP_DERIVE: c_int = 1 << 8;

// ---- RSA padding constants ----

#[cfg(wolfssl_rsa)]
pub const RSA_PKCS1_PADDING: c_int = 0;
#[cfg(wolfssl_rsa)]
pub const RSA_PKCS1_OAEP_PADDING: c_int = 1;
#[cfg(wolfssl_rsa)]
pub const RSA_PKCS1_PSS_PADDING: c_int = 2;
#[cfg(wolfssl_rsa)]
pub const RSA_PSS_SALTLEN_DIGEST: c_int = -1;

// ---- Ed25519 / Curve25519 constants ----

#[cfg(wolfssl_ed25519)]
pub const ED25519_PUBLIC_KEY_LEN: u32 = 32;
#[cfg(wolfssl_ed25519)]
pub const ED25519_SIGNATURE_LEN: u32 = 64;
#[cfg(wolfssl_ed25519)]
pub const ED25519_KEY_SIZE: u32 = 32;
#[cfg(wolfssl_ed25519)]
pub const ED25519_PUB_KEY_SIZE: u32 = 32;
/// Allocation size for wolfCrypt's ed25519_key. Verified by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_ed25519)]
pub const WC_ED25519_KEY_ALLOC_SIZE: usize = 256;
/// Allocation size for wolfCrypt's curve25519_key. Verified by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_curve25519)]
pub const WC_CURVE25519_KEY_ALLOC_SIZE: usize = 256;
/// EC25519_LITTLE_ENDIAN constant from wolfSSL
#[cfg(any(wolfssl_ed25519, wolfssl_curve25519))]
pub const EC25519_LITTLE_ENDIAN: c_int = 0;

// ---- Ed448 / Curve448 constants ----

#[cfg(wolfssl_ed448)]
pub const ED448_PUBLIC_KEY_LEN: u32 = 57;
#[cfg(wolfssl_ed448)]
pub const ED448_SIGNATURE_LEN: u32 = 114;
/// Alias for `ED448_SIGNATURE_LEN`.
#[cfg(wolfssl_ed448)]
pub const ED448_SIG_SIZE: u32 = 114;
#[cfg(wolfssl_ed448)]
pub const ED448_KEY_SIZE: u32 = 57;
#[cfg(wolfssl_ed448)]
pub const ED448_PUB_KEY_SIZE: u32 = 57;
/// Allocation size for wolfCrypt's ed448_key. Verified by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_ed448)]
pub const WC_ED448_KEY_ALLOC_SIZE: usize = 256;
/// Allocation size for wolfCrypt's curve448_key. Verified by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_curve448)]
pub const WC_CURVE448_KEY_ALLOC_SIZE: usize = 256;
/// EC448_LITTLE_ENDIAN constant from wolfSSL
#[cfg(any(wolfssl_ed448, wolfssl_curve448))]
pub const EC448_LITTLE_ENDIAN: c_int = 0;

// ---- ML-DSA (Dilithium) constants ----

/// ML-DSA-44 security level parameter (passed to `wc_dilithium_set_level`).
#[cfg(wolfssl_dilithium)]
pub const WC_ML_DSA_44: u8 = 2;
/// ML-DSA-65 security level parameter.
#[cfg(wolfssl_dilithium)]
pub const WC_ML_DSA_65: u8 = 3;
/// ML-DSA-87 security level parameter.
#[cfg(wolfssl_dilithium)]
pub const WC_ML_DSA_87: u8 = 5;

/// ML-DSA-44 public key size in bytes.
#[cfg(wolfssl_dilithium)]
pub const DILITHIUM_ML_DSA_44_PUB_KEY_SIZE: usize = 1312;
/// ML-DSA-44 private key size in bytes (private seed, not including public key).
#[cfg(wolfssl_dilithium)]
pub const DILITHIUM_ML_DSA_44_KEY_SIZE: usize = 2560;
/// ML-DSA-44 signature size in bytes.
#[cfg(wolfssl_dilithium)]
pub const DILITHIUM_ML_DSA_44_SIG_SIZE: usize = 2420;

/// ML-DSA-65 public key size in bytes.
#[cfg(wolfssl_dilithium)]
pub const DILITHIUM_ML_DSA_65_PUB_KEY_SIZE: usize = 1952;
/// ML-DSA-65 private key size in bytes.
#[cfg(wolfssl_dilithium)]
pub const DILITHIUM_ML_DSA_65_KEY_SIZE: usize = 4032;
/// ML-DSA-65 signature size in bytes.
#[cfg(wolfssl_dilithium)]
pub const DILITHIUM_ML_DSA_65_SIG_SIZE: usize = 3309;

/// ML-DSA-87 public key size in bytes.
#[cfg(wolfssl_dilithium)]
pub const DILITHIUM_ML_DSA_87_PUB_KEY_SIZE: usize = 2592;
/// ML-DSA-87 private key size in bytes.
#[cfg(wolfssl_dilithium)]
pub const DILITHIUM_ML_DSA_87_KEY_SIZE: usize = 4896;
/// ML-DSA-87 signature size in bytes.
#[cfg(wolfssl_dilithium)]
pub const DILITHIUM_ML_DSA_87_SIG_SIZE: usize = 4627;

/// ML-DSA seed size in bytes (all levels use 32-byte seeds per FIPS 204).
#[cfg(wolfssl_dilithium)]
pub const DILITHIUM_SEED_SIZE: usize = 32;

// ---- NID constants ----
// NIST curve NIDs: hardcoded WC_NID_* values from wolfssl/openssl/ec.h.
// These are OpenSSL-compatible assigned integers, NOT OID sums — wolfSSL
// uses wc_oid_sum() only for Ed/X curves (below), not for NIST curves.

#[cfg(wolfssl_ecc)]
pub const NID_X9_62_prime256v1: c_int = 415; // WC_NID_X9_62_prime256v1
#[cfg(wolfssl_ecc)]
pub const NID_secp224r1: c_int = 713; // WC_NID_secp224r1
#[cfg(wolfssl_ecc)]
pub const NID_secp256k1: c_int = 714; // WC_NID_secp256k1
#[cfg(wolfssl_ecc)]
pub const NID_secp384r1: c_int = 715; // WC_NID_secp384r1
#[cfg(wolfssl_ecc)]
pub const NID_secp521r1: c_int = 716; // WC_NID_secp521r1

// Ed/X curve NIDs: wolfSSL uses wc_oid_sum() (wolfcrypt/src/asn.c) to hash
// DER-encoded OID bytes into a u32 NID. We reproduce that algorithm here as
// a const fn so the values are computed from the OIDs, not hardcoded.
// Verified at compile time by _Static_assert in compat_shim.c.
//
// The `u32 as c_int` wrapping cast is intentional: wolfSSL stores these as
// unsigned OID sums but uses int-typed NIDs. Values exceed i32::MAX, so the
// cast wraps to negative — matching what wolfSSL does in C.

/// Compute wolfSSL's `wc_oid_sum` hash from DER-encoded OID bytes.
/// Mirrors the non-`WOLFSSL_OLD_OID_SUM` algorithm in wolfcrypt/src/asn.c:
/// XOR each bitwise-inverted byte into a 32-bit accumulator at a rotating
/// 8-bit shift position (0, 8, 16, 24, 0, …), then mask to 31 bits.
const fn wc_oid_sum(oid_der: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;
    while i < oid_der.len() {
        sum ^= (!(oid_der[i] as u32)) << shift;
        shift = (shift + 8) & 0x1f; // rotate through 32-bit positions
        i += 1;
    }
    sum & 0x7fff_ffff // clear sign bit — wolfSSL uses signed int for OID sums
}

#[cfg(wolfssl_curve25519)]
pub const NID_X25519: c_int = wc_oid_sum(&[0x2b, 0x65, 0x6e]) as c_int;   // OID 1.3.101.110
#[cfg(wolfssl_ed25519)]
pub const NID_ED25519: c_int = wc_oid_sum(&[0x2b, 0x65, 0x70]) as c_int;  // OID 1.3.101.112
#[cfg(wolfssl_ed448)]
pub const NID_ED448: c_int = wc_oid_sum(&[0x2b, 0x65, 0x71]) as c_int;    // OID 1.3.101.113
#[cfg(wolfssl_curve448)]
pub const NID_X448: c_int = wc_oid_sum(&[0x2b, 0x65, 0x6f]) as c_int;     // OID 1.3.101.111

// ---- DH FFDHE NIDs (RFC 7919) ----
// Values from wolfssl/openssl/evp.h: WC_NID_ffdhe2048 etc.
#[cfg(wolfssl_dh)]
pub const NID_ffdhe2048: c_int = 1126;
#[cfg(wolfssl_dh)]
pub const NID_ffdhe3072: c_int = 1127;
#[cfg(wolfssl_dh)]
pub const NID_ffdhe4096: c_int = 1128;

// ---- wolfCrypt hash type constants ----
// (from wolfssl/wolfcrypt/hash.h; used by wc_HKDF, wc_HKDF_Expand, etc.)

pub const WC_HASH_TYPE_SHA: c_int = 4;
pub const WC_HASH_TYPE_SHA256: c_int = 6;
#[cfg(wolfssl_sha384)]
pub const WC_HASH_TYPE_SHA384: c_int = 7;
#[cfg(wolfssl_sha512)]
pub const WC_HASH_TYPE_SHA512: c_int = 8;

// ---- Miscellaneous ----

/// INVALID_DEVID for wolfCrypt
pub const INVALID_DEVID: c_int = -2;

// Point conversion form
#[cfg(wolfssl_ecc)]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum point_conversion_form_t {
    POINT_CONVERSION_COMPRESSED = 2,
    POINT_CONVERSION_UNCOMPRESSED = 4,
    POINT_CONVERSION_HYBRID = 6,
}

// ================================================================
// Extern "C" function declarations
// ================================================================

// ============================================================
// Unconditional: RNG, AES init/free
// ============================================================

extern "C" {
    // wolfCrypt RNG
    pub fn wc_InitRng(rng: *mut WC_RNG) -> c_int;
    pub fn wc_RNG_GenerateBlock(rng: *mut WC_RNG, output: *mut u8, sz: u32) -> c_int;
    pub fn wc_FreeRng(rng: *mut WC_RNG) -> c_int;

    // AES init/free (unconditional since WcAes is unconditional)
    pub fn wc_AesInit(aes: *mut WcAes, heap: *mut c_void, devId: c_int) -> c_int;
    pub fn wc_AesFree(aes: *mut WcAes);
    pub fn wc_AesNew(heap: *mut c_void, devId: c_int, result_code: *mut c_int) -> *mut WcAes;
    pub fn wc_AesDelete(aes: *mut WcAes, aes_p: *mut *mut WcAes) -> c_int;
    pub fn wc_AesSetIV(aes: *mut WcAes, iv: *const u8) -> c_int;
    pub fn wc_AesSetKey(
        aes: *mut WcAes,
        key: *const u8,
        len: u32,
        iv: *const u8,
        dir: c_int,
    ) -> c_int;

    // Error strings
    pub fn wc_GetErrorString(error: c_int) -> *const c_char;

    // Secure zeroing
    pub fn wc_ForceZero(mem: *mut c_void, len: usize);
}

// ============================================================
// SHA one-shot functions (OpenSSL compat layer)
//
// These link to wolfSSL_SHA* symbols in ssl_crypto.c, which is
// only compiled when OPENSSL_EXTRA is active.
// ============================================================

#[cfg(wolfssl_openssl_extra)]
extern "C" {
    #[link_name = "wolfSSL_SHA1"]
    pub fn SHA1(data: *const u8, len: usize, md: *mut u8) -> *mut u8;

    #[link_name = "wolfSSL_SHA256"]
    pub fn SHA256(data: *const u8, len: usize, md: *mut u8) -> *mut u8;
}

#[cfg(all(wolfssl_openssl_extra, wolfssl_sha224))]
extern "C" {
    #[link_name = "wolfSSL_SHA224"]
    pub fn SHA224(data: *const u8, len: usize, md: *mut u8) -> *mut u8;
}

#[cfg(all(wolfssl_openssl_extra, wolfssl_sha384))]
extern "C" {
    #[link_name = "wolfSSL_SHA384"]
    pub fn SHA384(data: *const u8, len: usize, md: *mut u8) -> *mut u8;
}

#[cfg(all(wolfssl_openssl_extra, wolfssl_sha512))]
extern "C" {
    #[link_name = "wolfSSL_SHA512"]
    pub fn SHA512(data: *const u8, len: usize, md: *mut u8) -> *mut u8;
}

// ============================================================
// OpenSSL compat layer: EVP, BN, ERR, CRYPTO, RAND, etc.
// ============================================================

#[cfg(wolfssl_openssl_extra)]
extern "C" {
    // ---- RAND ----

    #[link_name = "wolfSSL_RAND_bytes"]
    pub fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;

    // ---- EVP_MD (digest algorithm descriptors) ----

    #[link_name = "wolfSSL_EVP_sha1"]
    pub fn EVP_sha1() -> *const EVP_MD;

    #[link_name = "wolfSSL_EVP_sha256"]
    pub fn EVP_sha256() -> *const EVP_MD;

    #[link_name = "wolfSSL_EVP_MD_size"]
    pub fn EVP_MD_size(md: *const EVP_MD) -> c_int;

    // ---- EVP_MD_CTX (digest context operations) ----

    #[link_name = "wolfSSL_EVP_MD_CTX_new"]
    pub fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;

    #[link_name = "wolfSSL_EVP_MD_CTX_free"]
    pub fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);

    #[link_name = "wolfSSL_EVP_MD_CTX_init"]
    pub fn EVP_MD_CTX_init(ctx: *mut EVP_MD_CTX);

    #[link_name = "wolfSSL_EVP_MD_CTX_cleanup"]
    pub fn EVP_MD_CTX_cleanup(ctx: *mut EVP_MD_CTX) -> c_int;

    #[link_name = "wolfSSL_EVP_MD_CTX_copy"]
    pub fn EVP_MD_CTX_copy(out: *mut EVP_MD_CTX, in_: *const EVP_MD_CTX) -> c_int;

    #[link_name = "wolfSSL_EVP_DigestInit_ex"]
    pub fn EVP_DigestInit_ex(
        ctx: *mut EVP_MD_CTX,
        type_: *const EVP_MD,
        impl_: *mut ENGINE,
    ) -> c_int;

    #[link_name = "wolfSSL_EVP_DigestUpdate"]
    pub fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, d: *const c_void, cnt: usize) -> c_int;

    #[link_name = "wolfSSL_EVP_DigestFinal"]
    pub fn EVP_DigestFinal(ctx: *mut EVP_MD_CTX, md: *mut u8, s: *mut c_uint) -> c_int;

    #[link_name = "wolfSSL_EVP_MD_CTX_md"]
    pub fn EVP_MD_CTX_md(ctx: *const EVP_MD_CTX) -> *const EVP_MD;

    // ---- EVP_DigestSign / EVP_DigestVerify ----
    // NOTE: wolfSSL declares SignUpdate with `unsigned int cnt` but
    // VerifyUpdate with `size_t cnt`. OpenSSL uses `size_t` for both.
    // This is a wolfSSL bug; the mismatch below matches upstream as-is.

    #[link_name = "wolfSSL_EVP_DigestSignInit"]
    pub fn EVP_DigestSignInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> c_int;

    #[link_name = "wolfSSL_EVP_DigestSignUpdate"]
    pub fn EVP_DigestSignUpdate(
        ctx: *mut EVP_MD_CTX,
        data: *const c_void,
        cnt: c_uint,
    ) -> c_int;

    #[link_name = "wolfSSL_EVP_DigestSignFinal"]
    pub fn EVP_DigestSignFinal(
        ctx: *mut EVP_MD_CTX,
        sig: *mut u8,
        siglen: *mut usize,
    ) -> c_int;

    #[link_name = "wolfSSL_EVP_DigestVerifyInit"]
    pub fn EVP_DigestVerifyInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> c_int;

    #[link_name = "wolfSSL_EVP_DigestVerifyUpdate"]
    pub fn EVP_DigestVerifyUpdate(
        ctx: *mut EVP_MD_CTX,
        data: *const c_void,
        cnt: usize,
    ) -> c_int;

    #[link_name = "wolfSSL_EVP_DigestVerifyFinal"]
    pub fn EVP_DigestVerifyFinal(
        ctx: *mut EVP_MD_CTX,
        sig: *const u8,
        siglen: usize,
    ) -> c_int;

    // ---- EVP_CIPHER context operations ----

    #[link_name = "wolfSSL_EVP_CIPHER_CTX_new"]
    pub fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    #[link_name = "wolfSSL_EVP_CIPHER_CTX_free"]
    pub fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);

    #[link_name = "wolfSSL_EVP_Cipher_key_length"]
    pub fn EVP_CIPHER_key_length(cipher: *const EVP_CIPHER) -> c_int;
    // Named `_raw` because wolfcrypt-ring-compat wraps this with a
    // CFB128 bug workaround (see cipher/streaming.rs:674).
    #[link_name = "wolfSSL_EVP_CIPHER_iv_length"]
    pub fn EVP_CIPHER_iv_length_raw(cipher: *const EVP_CIPHER) -> c_int;

    #[link_name = "wolfSSL_EVP_CIPHER_CTX_ctrl"]
    pub fn EVP_CIPHER_CTX_ctrl(
        ctx: *mut EVP_CIPHER_CTX,
        type_: c_int,
        arg: c_int,
        ptr: *mut c_void,
    ) -> c_int;

    #[link_name = "wolfSSL_EVP_CIPHER_CTX_set_padding"]
    pub fn EVP_CIPHER_CTX_set_padding(ctx: *mut EVP_CIPHER_CTX, padding: c_int) -> c_int;

    #[link_name = "wolfSSL_EVP_EncryptInit_ex"]
    pub fn EVP_EncryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        type_: *const EVP_CIPHER,
        impl_: *mut ENGINE,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;

    // wolfSSL uses a single wolfSSL_EVP_CipherUpdate for both encrypt and decrypt.
    // Both EVP_EncryptUpdate and EVP_DecryptUpdate link to the same symbol;
    // the direction is determined by how the context was initialized.
    #[link_name = "wolfSSL_EVP_CipherUpdate"]
    pub fn EVP_EncryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut u8,
        outl: *mut c_int,
        in_: *const u8,
        inl: c_int,
    ) -> c_int;

    #[link_name = "wolfSSL_EVP_EncryptFinal_ex"]
    pub fn EVP_EncryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut u8,
        outl: *mut c_int,
    ) -> c_int;

    #[link_name = "wolfSSL_EVP_DecryptInit_ex"]
    pub fn EVP_DecryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        type_: *const EVP_CIPHER,
        impl_: *mut ENGINE,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;

    // Same underlying symbol as EVP_EncryptUpdate — see comment above.
    #[link_name = "wolfSSL_EVP_CipherUpdate"]
    pub fn EVP_DecryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut u8,
        outl: *mut c_int,
        in_: *const u8,
        inl: c_int,
    ) -> c_int;

    #[link_name = "wolfSSL_EVP_DecryptFinal_ex"]
    pub fn EVP_DecryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut u8,
        outl: *mut c_int,
    ) -> c_int;

    // ---- EVP AES-CBC cipher descriptors (always available with AES) ----

    #[link_name = "wolfSSL_EVP_aes_128_cbc"]
    pub fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    #[link_name = "wolfSSL_EVP_aes_192_cbc"]
    pub fn EVP_aes_192_cbc() -> *const EVP_CIPHER;
    #[link_name = "wolfSSL_EVP_aes_256_cbc"]
    pub fn EVP_aes_256_cbc() -> *const EVP_CIPHER;

    // ---- BIGNUM ----

    #[link_name = "wolfSSL_BN_new"]
    pub fn BN_new() -> *mut BIGNUM;
    #[link_name = "wolfSSL_BN_free"]
    pub fn BN_free(bn: *mut BIGNUM);
    #[link_name = "wolfSSL_BN_num_bytes"]
    pub fn BN_num_bytes(bn: *const BIGNUM) -> c_int;
    #[link_name = "wolfSSL_BN_bin2bn"]
    pub fn BN_bin2bn(s: *const u8, len: c_int, ret: *mut BIGNUM) -> *mut BIGNUM;
    #[link_name = "wolfSSL_BN_bn2bin"]
    pub fn BN_bn2bin(a: *const BIGNUM, to: *mut u8) -> c_int;
    #[link_name = "wolfSSL_BN_set_word"]
    pub fn BN_set_word(bn: *mut BIGNUM, value: c_ulong) -> c_int;

    // ---- OPENSSL_malloc / OPENSSL_free ----

    #[link_name = "wolfSSL_OPENSSL_malloc"]
    pub fn OPENSSL_malloc(size: usize) -> *mut c_void;
    #[link_name = "wolfSSL_OPENSSL_free"]
    pub fn OPENSSL_free(ptr: *mut c_void);

    // ---- ERR functions ----

    #[link_name = "wolfSSL_ERR_get_error"]
    pub fn ERR_get_error() -> c_ulong;
    #[link_name = "wolfSSL_ERR_error_string"]
    pub fn ERR_error_string(e: c_ulong, buf: *mut c_char) -> *mut c_char;
    #[link_name = "wolfSSL_ERR_GET_LIB"]
    pub fn ERR_GET_LIB(e: c_ulong) -> c_int;
    #[link_name = "wolfSSL_ERR_GET_REASON"]
    pub fn ERR_GET_REASON(e: c_ulong) -> c_int;

    // ---- CRYPTO helpers ----

    #[link_name = "wolfSSL_CRYPTO_memcmp"]
    pub fn CRYPTO_memcmp(a: *const c_void, b: *const c_void, len: usize) -> c_int;

    #[link_name = "wolfSSL_Init"]
    pub fn CRYPTO_library_init() -> c_int;

    // ---- FIPS ----

    #[link_name = "wolfSSL_FIPS_mode"]
    pub fn FIPS_mode() -> c_int;

    // ---- EVP_PKEY ----

    #[link_name = "wolfSSL_EVP_PKEY_new"]
    pub fn EVP_PKEY_new() -> *mut EVP_PKEY;
    #[link_name = "wolfSSL_EVP_PKEY_free"]
    pub fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    #[link_name = "wolfSSL_EVP_PKEY_up_ref"]
    pub fn EVP_PKEY_up_ref(pkey: *mut EVP_PKEY) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_id"]
    pub fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_bits"]
    pub fn EVP_PKEY_bits(pkey: *const EVP_PKEY) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_size"]
    pub fn EVP_PKEY_size(pkey: *const EVP_PKEY) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_cmp"]
    pub fn EVP_PKEY_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int;

    // ---- EVP_PKEY_CTX operations ----

    #[link_name = "wolfSSL_EVP_PKEY_CTX_new"]
    pub fn EVP_PKEY_CTX_new(pkey: *mut EVP_PKEY, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;
    #[link_name = "wolfSSL_EVP_PKEY_CTX_new_id"]
    pub fn EVP_PKEY_CTX_new_id(id: c_int, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;
    #[link_name = "wolfSSL_EVP_PKEY_CTX_free"]
    pub fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);

    #[link_name = "wolfSSL_EVP_PKEY_keygen_init"]
    pub fn EVP_PKEY_keygen_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_keygen"]
    pub fn EVP_PKEY_keygen(ctx: *mut EVP_PKEY_CTX, ppkey: *mut *mut EVP_PKEY) -> c_int;

    #[link_name = "wolfSSL_EVP_PKEY_derive_init"]
    pub fn EVP_PKEY_derive_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_derive_set_peer"]
    pub fn EVP_PKEY_derive_set_peer(ctx: *mut EVP_PKEY_CTX, peer: *mut EVP_PKEY) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_derive"]
    pub fn EVP_PKEY_derive(ctx: *mut EVP_PKEY_CTX, key: *mut u8, keylen: *mut usize) -> c_int;

    #[link_name = "wolfSSL_EVP_PKEY_sign_init"]
    pub fn EVP_PKEY_sign_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_sign"]
    pub fn EVP_PKEY_sign(
        ctx: *mut EVP_PKEY_CTX,
        sig: *mut u8,
        siglen: *mut usize,
        tbs: *const u8,
        tbslen: usize,
    ) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_verify_init"]
    pub fn EVP_PKEY_verify_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_verify"]
    pub fn EVP_PKEY_verify(
        ctx: *mut EVP_PKEY_CTX,
        sig: *const u8,
        siglen: usize,
        tbs: *const u8,
        tbslen: usize,
    ) -> c_int;

    #[link_name = "wolfSSL_EVP_PKEY_encrypt_init"]
    pub fn EVP_PKEY_encrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_encrypt"]
    pub fn EVP_PKEY_encrypt(
        ctx: *mut EVP_PKEY_CTX,
        out: *mut u8,
        outlen: *mut usize,
        in_: *const u8,
        inlen: usize,
    ) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_decrypt_init"]
    pub fn EVP_PKEY_decrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_decrypt"]
    pub fn EVP_PKEY_decrypt(
        ctx: *mut EVP_PKEY_CTX,
        out: *mut u8,
        outlen: *mut usize,
        in_: *const u8,
        inlen: usize,
    ) -> c_int;

    #[link_name = "wolfSSL_EVP_PKEY_CTX_set_signature_md"]
    pub fn EVP_PKEY_CTX_set_signature_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;

    // ---- DER i2d/d2i functions ----

    #[link_name = "wolfSSL_i2d_PrivateKey"]
    pub fn i2d_PrivateKey(pkey: *const EVP_PKEY, out: *mut *mut u8) -> c_int;
    #[link_name = "wolfSSL_d2i_PrivateKey"]
    pub fn d2i_PrivateKey(type_: c_int, pkey: *mut *mut EVP_PKEY, in_: *mut *const u8, len: c_long) -> *mut EVP_PKEY;
    #[link_name = "wolfSSL_i2d_PUBKEY"]
    pub fn i2d_PUBKEY(pkey: *const EVP_PKEY, out: *mut *mut u8) -> c_int;
    #[link_name = "wolfSSL_d2i_PUBKEY"]
    pub fn d2i_PUBKEY(pkey: *mut *mut EVP_PKEY, in_: *mut *const u8, len: c_long) -> *mut EVP_PKEY;

    // ---- EVP_PKEY field accessors (defined in compat_shim.c) ----

    pub fn wolfcrypt_evp_pkey_set_type(pkey: *mut EVP_PKEY, type_: c_int);
    pub fn wolfcrypt_evp_pkey_get_type(pkey: *const EVP_PKEY) -> c_int;
    /// Copy raw key material into `pkey`.
    /// Returns 1 on success, 0 on failure.
    pub fn wolfcrypt_evp_pkey_set_raw(pkey: *mut EVP_PKEY, data: *const u8, sz: c_int) -> c_int;
    pub fn wolfcrypt_evp_pkey_get_pkey_sz(pkey: *const EVP_PKEY) -> c_int;
    pub fn wolfcrypt_evp_pkey_get_pkey_ptr(pkey: *const EVP_PKEY) -> *const u8;

    // ---- EVP_PKEY_CTX field accessors (defined in compat_shim.c) ----

    pub fn wolfcrypt_evp_pkey_ctx_get_pkey(ctx: *mut EVP_PKEY_CTX) -> *mut EVP_PKEY;
    /// Frees the old peer key (if any) and takes a new reference to `peer`.
    pub fn wolfcrypt_evp_pkey_ctx_set_peer_key(ctx: *mut EVP_PKEY_CTX, peer: *mut EVP_PKEY);
    pub fn wolfcrypt_evp_pkey_ctx_get_peer_key(ctx: *mut EVP_PKEY_CTX) -> *mut EVP_PKEY;
    pub fn wolfcrypt_evp_pkey_ctx_set_op(ctx: *mut EVP_PKEY_CTX, op: c_int);
    pub fn wolfcrypt_evp_pkey_ctx_get_op(ctx: *mut EVP_PKEY_CTX) -> c_int;

    // ---- AES low-level compat ----

    #[link_name = "wolfSSL_AES_set_encrypt_key"]
    pub fn AES_set_encrypt_key(userKey: *const u8, bits: c_uint, key: *mut AES_KEY) -> c_int;

    #[link_name = "wolfSSL_AES_set_decrypt_key"]
    pub fn AES_set_decrypt_key(userKey: *const u8, bits: c_uint, key: *mut AES_KEY) -> c_int;

    #[link_name = "wolfSSL_AES_cbc_encrypt"]
    pub fn AES_cbc_encrypt(
        in_: *const u8,
        out: *mut u8,
        length: usize,
        key: *const AES_KEY,
        ivec: *mut u8,
        enc: c_int,
    );
}

// ============================================================
// EVP AES-CTR cipher descriptors
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_aes_ctr))]
extern "C" {
    #[link_name = "wolfSSL_EVP_aes_128_ctr"]
    pub fn EVP_aes_128_ctr() -> *const EVP_CIPHER;
    #[link_name = "wolfSSL_EVP_aes_192_ctr"]
    pub fn EVP_aes_192_ctr() -> *const EVP_CIPHER;
    #[link_name = "wolfSSL_EVP_aes_256_ctr"]
    pub fn EVP_aes_256_ctr() -> *const EVP_CIPHER;
}

// ============================================================
// EVP AES-ECB cipher descriptors + low-level AES-ECB
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_aes_ecb))]
extern "C" {
    #[link_name = "wolfSSL_EVP_aes_128_ecb"]
    pub fn EVP_aes_128_ecb() -> *const EVP_CIPHER;
    #[link_name = "wolfSSL_EVP_aes_192_ecb"]
    pub fn EVP_aes_192_ecb() -> *const EVP_CIPHER;
    #[link_name = "wolfSSL_EVP_aes_256_ecb"]
    pub fn EVP_aes_256_ecb() -> *const EVP_CIPHER;

    #[link_name = "wolfSSL_AES_ecb_encrypt"]
    pub fn AES_ecb_encrypt(in_: *const u8, out: *mut u8, key: *const AES_KEY, enc: c_int);
}

// ============================================================
// EVP AES-CFB cipher descriptors + low-level AES-CFB128
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_aes_cfb))]
extern "C" {
    #[link_name = "wolfSSL_EVP_aes_128_cfb128"]
    pub fn EVP_aes_128_cfb128() -> *const EVP_CIPHER;
    #[link_name = "wolfSSL_EVP_aes_192_cfb128"]
    pub fn EVP_aes_192_cfb128() -> *const EVP_CIPHER;
    #[link_name = "wolfSSL_EVP_aes_256_cfb128"]
    pub fn EVP_aes_256_cfb128() -> *const EVP_CIPHER;

    #[link_name = "wolfSSL_AES_cfb128_encrypt"]
    pub fn AES_cfb128_encrypt(
        in_: *const u8,
        out: *mut u8,
        length: usize,
        key: *const AES_KEY,
        ivec: *mut u8,
        num: *mut c_int,
        enc: c_int,
    );
}

// ============================================================
// 3DES EVP cipher descriptor
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_des3))]
extern "C" {
    #[link_name = "wolfSSL_EVP_des_ede3_cbc"]
    pub fn EVP_des_ede3_cbc() -> *const EVP_CIPHER;
}

// ============================================================
// EVP_sha224
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_sha224))]
extern "C" {
    #[link_name = "wolfSSL_EVP_sha224"]
    pub fn EVP_sha224() -> *const EVP_MD;
}

// ============================================================
// EVP_sha384
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_sha384))]
extern "C" {
    #[link_name = "wolfSSL_EVP_sha384"]
    pub fn EVP_sha384() -> *const EVP_MD;
}

// ============================================================
// EVP_sha512, EVP_sha512_256
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_sha512))]
extern "C" {
    #[link_name = "wolfSSL_EVP_sha512"]
    pub fn EVP_sha512() -> *const EVP_MD;

    #[link_name = "wolfSSL_EVP_sha512_256"]
    pub fn EVP_sha512_256() -> *const EVP_MD;
}

// ============================================================
// EVP SHA3 digests
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_sha3))]
extern "C" {
    #[link_name = "wolfSSL_EVP_sha3_256"]
    pub fn EVP_sha3_256() -> *const EVP_MD;

    #[link_name = "wolfSSL_EVP_sha3_384"]
    pub fn EVP_sha3_384() -> *const EVP_MD;

    #[link_name = "wolfSSL_EVP_sha3_512"]
    pub fn EVP_sha3_512() -> *const EVP_MD;
}

// ============================================================
// EVP AES-GCM cipher descriptors
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_aes_gcm))]
extern "C" {
    #[link_name = "wolfSSL_EVP_aes_128_gcm"]
    pub fn EVP_aes_128_gcm() -> *const EVP_CIPHER;
    #[link_name = "wolfSSL_EVP_aes_192_gcm"]
    pub fn EVP_aes_192_gcm() -> *const EVP_CIPHER;
    #[link_name = "wolfSSL_EVP_aes_256_gcm"]
    pub fn EVP_aes_256_gcm() -> *const EVP_CIPHER;
}

// ============================================================
// EVP ChaCha20-Poly1305 cipher descriptor
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_chacha20_poly1305))]
extern "C" {
    #[link_name = "wolfSSL_EVP_chacha20_poly1305"]
    pub fn EVP_chacha20_poly1305() -> *const EVP_CIPHER;
}

// ============================================================
// EVP ChaCha20 cipher descriptor
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_chacha))]
extern "C" {
    #[link_name = "wolfSSL_EVP_chacha20"]
    pub fn EVP_chacha20() -> *const EVP_CIPHER;
}

// ============================================================
// AES key-wrap (OpenSSL compat)
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_aes_keywrap))]
extern "C" {
    #[link_name = "wolfSSL_AES_wrap_key"]
    pub fn AES_wrap_key(
        key: *const AES_KEY,
        iv: *const u8,
        out: *mut u8,
        in_: *const u8,
        inlen: usize,
    ) -> c_int;

    #[link_name = "wolfSSL_AES_unwrap_key"]
    pub fn AES_unwrap_key(
        key: *const AES_KEY,
        iv: *const u8,
        out: *mut u8,
        in_: *const u8,
        inlen: usize,
    ) -> c_int;
}

// AES Key Wrap with Padding (RFC 5649) — C shims in compat_shim.c
// wolfSSL does not provide the padded variants natively.

#[cfg(all(wolfssl_openssl_extra, wolfssl_aes_keywrap, wolfssl_aes_ecb))]
extern "C" {
    #[link_name = "wolfcrypt_AES_wrap_key_padded"]
    pub fn AES_wrap_key_padded(
        key: *const AES_KEY,
        out: *mut u8,
        out_len: *mut usize,
        max_out: usize,
        in_: *const u8,
        in_len: usize,
    ) -> c_int;

    #[link_name = "wolfcrypt_AES_unwrap_key_padded"]
    pub fn AES_unwrap_key_padded(
        key: *const AES_KEY,
        out: *mut u8,
        out_len: *mut usize,
        max_out: usize,
        in_: *const u8,
        in_len: usize,
    ) -> c_int;
}

// ============================================================
// HMAC (OpenSSL compat)
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_hmac))]
extern "C" {
    #[link_name = "wolfSSL_HMAC_CTX_new"]
    pub fn HMAC_CTX_new() -> *mut HMAC_CTX;

    #[link_name = "wolfSSL_HMAC_CTX_free"]
    pub fn HMAC_CTX_free(ctx: *mut HMAC_CTX);

    #[link_name = "wolfSSL_HMAC_CTX_Init"]
    pub fn HMAC_CTX_init(ctx: *mut HMAC_CTX);
    #[link_name = "wolfSSL_HMAC_CTX_cleanup"]
    pub fn HMAC_CTX_cleanup(ctx: *mut HMAC_CTX);
    #[link_name = "wolfSSL_HMAC_CTX_copy"]
    pub fn HMAC_CTX_copy(dest: *mut HMAC_CTX, src: *mut HMAC_CTX) -> c_int;

    #[link_name = "wolfSSL_HMAC_Init_ex"]
    pub fn HMAC_Init_ex(
        ctx: *mut HMAC_CTX,
        key: *const c_void,
        key_len: c_int,
        md: *const EVP_MD,
        impl_: *mut ENGINE,
    ) -> c_int;

    #[link_name = "wolfSSL_HMAC_Update"]
    pub fn HMAC_Update(ctx: *mut HMAC_CTX, data: *const u8, len: usize) -> c_int;

    #[link_name = "wolfSSL_HMAC_Final"]
    pub fn HMAC_Final(ctx: *mut HMAC_CTX, md: *mut u8, len: *mut c_uint) -> c_int;

    // HMAC key constructor
    #[link_name = "wolfSSL_EVP_PKEY_new_mac_key"]
    pub fn EVP_PKEY_new_mac_key(
        type_: c_int,
        e: *mut ENGINE,
        key: *const u8,
        keylen: c_int,
    ) -> *mut EVP_PKEY;
}

// ============================================================
// CMAC (OpenSSL compat)
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_cmac))]
extern "C" {
    #[link_name = "wolfSSL_CMAC_CTX_new"]
    pub fn CMAC_CTX_new() -> *mut CMAC_CTX;

    #[link_name = "wolfSSL_CMAC_CTX_free"]
    pub fn CMAC_CTX_free(ctx: *mut CMAC_CTX);

    #[link_name = "wolfSSL_CMAC_Init"]
    pub fn CMAC_Init(
        ctx: *mut CMAC_CTX,
        key: *const c_void,
        key_len: usize,
        cipher: *const EVP_CIPHER,
        engine: *mut ENGINE,
    ) -> c_int;

    #[link_name = "wolfSSL_CMAC_Update"]
    pub fn CMAC_Update(ctx: *mut CMAC_CTX, data: *const u8, len: usize) -> c_int;

    #[link_name = "wolfSSL_CMAC_Final"]
    pub fn CMAC_Final(ctx: *mut CMAC_CTX, out: *mut u8, len: *mut usize) -> c_int;
}

// ============================================================
// EC_GROUP / EC_KEY / EC_POINT / ECDSA / ECDH (OpenSSL compat)
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_ecc))]
extern "C" {
    #[link_name = "wolfSSL_EC_KEY_new"]
    pub fn EC_KEY_new() -> *mut EC_KEY;
    #[link_name = "wolfSSL_EC_KEY_free"]
    pub fn EC_KEY_free(key: *mut EC_KEY);
    #[link_name = "wolfSSL_EC_KEY_get0_group"]
    pub fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;
    #[link_name = "wolfSSL_EC_KEY_get0_private_key"]
    pub fn EC_KEY_get0_private_key(key: *const EC_KEY) -> *const BIGNUM;
    #[link_name = "wolfSSL_EC_KEY_get0_public_key"]
    pub fn EC_KEY_get0_public_key(key: *const EC_KEY) -> *const EC_POINT;
    #[link_name = "wolfSSL_EC_KEY_set_group"]
    pub fn EC_KEY_set_group(key: *mut EC_KEY, group: *const EC_GROUP) -> c_int;
    #[link_name = "wolfSSL_EC_KEY_set_private_key"]
    pub fn EC_KEY_set_private_key(key: *mut EC_KEY, prv: *const BIGNUM) -> c_int;
    #[link_name = "wolfSSL_EC_KEY_set_public_key"]
    pub fn EC_KEY_set_public_key(key: *mut EC_KEY, pub_: *const EC_POINT) -> c_int;
    #[link_name = "wolfSSL_EC_KEY_check_key"]
    pub fn EC_KEY_check_key(key: *const EC_KEY) -> c_int;
    #[link_name = "wolfSSL_d2i_ECPrivateKey"]
    pub fn d2i_ECPrivateKey(
        key: *mut *mut EC_KEY,
        in_: *mut *const u8,
        len: c_long,
    ) -> *mut EC_KEY;

    // WORKAROUND for wolfSSL bug: d2i_ECPrivateKey doesn't compute the public
    // point when RFC 5915 publicKey field is absent. This shim derives it from
    // the private scalar. Remove once wolfSSL fixes d2i_ECPrivateKey.
    pub fn wolfcrypt_fix_ec_privatekey_only(key: *mut EC_KEY) -> c_int;

    #[link_name = "wolfSSL_EC_GROUP_free"]
    pub fn EC_GROUP_free(group: *mut EC_GROUP);
    #[link_name = "wolfSSL_EC_GROUP_get_curve_name"]
    pub fn EC_GROUP_get_curve_name(group: *const EC_GROUP) -> c_int;

    #[link_name = "wolfSSL_EC_POINT_new"]
    pub fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    #[link_name = "wolfSSL_EC_POINT_free"]
    pub fn EC_POINT_free(point: *mut EC_POINT);
    #[link_name = "wolfSSL_EC_POINT_mul"]
    pub fn EC_POINT_mul(
        group: *const EC_GROUP,
        r: *mut EC_POINT,
        n: *const BIGNUM,
        q: *const EC_POINT,
        m: *const BIGNUM,
        ctx: *mut c_void,
    ) -> c_int;
    #[link_name = "wolfSSL_EC_POINT_oct2point"]
    pub fn EC_POINT_oct2point(
        group: *const EC_GROUP,
        p: *mut EC_POINT,
        buf: *const u8,
        len: usize,
        ctx: *mut c_void,
    ) -> c_int;
    #[link_name = "wolfSSL_EC_POINT_point2oct"]
    pub fn EC_POINT_point2oct(
        group: *const EC_GROUP,
        point: *const EC_POINT,
        form: point_conversion_form_t,
        buf: *mut u8,
        len: usize,
        ctx: *mut c_void,
    ) -> usize;

    // EC_GROUP_new_by_curve_name (direct wolfSSL FFI)
    #[link_name = "wolfSSL_EC_GROUP_new_by_curve_name"]
    pub fn EC_GROUP_new_by_curve_name(nid: c_int) -> *mut EC_GROUP;

    #[link_name = "wolfSSL_EC_KEY_generate_key"]
    pub fn EC_KEY_generate_key(key: *mut EC_KEY) -> c_int;

    // ---- ECDSA_SIG ----

    #[link_name = "wolfSSL_ECDSA_SIG_new"]
    pub fn ECDSA_SIG_new() -> *mut ECDSA_SIG;
    #[link_name = "wolfSSL_ECDSA_SIG_free"]
    pub fn ECDSA_SIG_free(sig: *mut ECDSA_SIG);
    #[link_name = "wolfSSL_ECDSA_SIG_set0"]
    pub fn ECDSA_SIG_set0(sig: *mut ECDSA_SIG, r: *mut BIGNUM, s: *mut BIGNUM) -> c_int;
    #[link_name = "wolfSSL_ECDSA_SIG_get0"]
    pub fn ECDSA_SIG_get0(
        sig: *const ECDSA_SIG,
        r: *mut *const BIGNUM,
        s: *mut *const BIGNUM,
    );
    #[link_name = "wolfSSL_d2i_ECDSA_SIG"]
    pub fn d2i_ECDSA_SIG(
        sig: *mut *mut ECDSA_SIG,
        in_: *mut *const u8,
        len: c_int,
    ) -> *mut ECDSA_SIG;
    #[link_name = "wolfSSL_i2d_ECDSA_SIG"]
    pub fn i2d_ECDSA_SIG(sig: *const ECDSA_SIG, out: *mut *mut u8) -> c_int;
    #[link_name = "wolfSSL_ECDSA_do_sign"]
    pub fn ECDSA_do_sign(dgst: *const u8, dgst_len: c_int, eckey: *mut EC_KEY) -> *mut ECDSA_SIG;
    #[link_name = "wolfSSL_ECDSA_do_verify"]
    pub fn ECDSA_do_verify(dgst: *const u8, dgst_len: c_int, sig: *const ECDSA_SIG, eckey: *mut EC_KEY) -> c_int;

    // ---- ECDH ----

    #[link_name = "wolfSSL_ECDH_compute_key"]
    pub fn ECDH_compute_key(out: *mut c_void, outlen: usize, pub_key: *const EC_POINT, ecdh: *mut EC_KEY, kdf: *mut c_void) -> c_int;

    // ---- EVP_PKEY EC integration ----

    #[link_name = "wolfSSL_EVP_PKEY_assign_EC_KEY"]
    pub fn EVP_PKEY_assign_EC_KEY(pkey: *mut EVP_PKEY, eckey: *mut EC_KEY) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_get0_EC_KEY"]
    pub fn EVP_PKEY_get0_EC_KEY(pkey: *const EVP_PKEY) -> *mut EC_KEY;
    #[link_name = "wolfSSL_EVP_PKEY_set1_EC_KEY"]
    pub fn EVP_PKEY_set1_EC_KEY(pkey: *mut EVP_PKEY, eckey: *mut EC_KEY) -> c_int;

    #[link_name = "wolfSSL_EVP_PKEY_CTX_set_ec_paramgen_curve_nid"]
    pub fn EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx: *mut EVP_PKEY_CTX, nid: c_int) -> c_int;

    #[link_name = "wolfSSL_i2d_ECPrivateKey"]
    pub fn i2d_ECPrivateKey(key: *const EC_KEY, out: *mut *mut u8) -> c_int;

    // wolfCrypt ECC DER functions
    pub fn wc_EccPublicKeyDerSize(key: *const wc_ecc_key, with_AlgCurve: c_int) -> c_int;
    pub fn wc_EccPublicKeyToDer(key: *const wc_ecc_key, output: *mut u8, outLen: u32, with_AlgCurve: c_int) -> c_int;

    // wolfcrypt_evp_pkey_get_ecc: get the ecc key pointer (opaque, for DER encoding)
    pub fn wolfcrypt_evp_pkey_get_ecc(pkey: *const EVP_PKEY) -> *mut EC_KEY;
    pub fn wolfcrypt_evp_pkey_get_ecc_internal(ec: *const EC_KEY) -> *const wc_ecc_key;
}

// ============================================================
// RSA (OpenSSL compat)
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_rsa))]
extern "C" {
    #[link_name = "wolfSSL_RSA_new"]
    pub fn RSA_new() -> *mut RSA;
    #[link_name = "wolfSSL_RSA_free"]
    pub fn RSA_free(rsa: *mut RSA);
    #[link_name = "wolfSSL_RSA_bits"]
    pub fn RSA_bits(rsa: *const RSA) -> c_int;
    #[link_name = "wolfSSL_RSA_size"]
    pub fn RSA_size(rsa: *const RSA) -> c_int;
    #[link_name = "wolfSSL_RSA_set0_key"]
    pub fn RSA_set0_key(
        r: *mut RSA,
        n: *mut BIGNUM,
        e: *mut BIGNUM,
        d: *mut BIGNUM,
    ) -> c_int;
    #[link_name = "wolfSSL_RSA_get0_key"]
    pub fn RSA_get0_key(
        rsa: *const RSA,
        n: *mut *const BIGNUM,
        e: *mut *const BIGNUM,
        d: *mut *const BIGNUM,
    );
    #[link_name = "wolfSSL_RSA_check_key"]
    pub fn RSA_check_key(rsa: *const RSA) -> c_int;
    #[link_name = "wolfSSL_d2i_RSAPrivateKey"]
    pub fn d2i_RSAPrivateKey(
        rsa: *mut *mut RSA,
        in_: *mut *const u8,
        len: c_long,
    ) -> *mut RSA;
    #[link_name = "wolfSSL_d2i_RSAPublicKey"]
    pub fn d2i_RSAPublicKey(
        rsa: *mut *mut RSA,
        in_: *mut *const u8,
        len: c_long,
    ) -> *mut RSA;
    #[link_name = "wolfSSL_i2d_RSAPublicKey"]
    pub fn i2d_RSAPublicKey(rsa: *const RSA, out: *mut *mut u8) -> c_int;

    // ---- EVP_PKEY RSA integration ----

    #[link_name = "wolfSSL_EVP_PKEY_assign_RSA"]
    pub fn EVP_PKEY_assign_RSA(pkey: *mut EVP_PKEY, rsa: *mut RSA) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_get0_RSA"]
    pub fn EVP_PKEY_get0_RSA(pkey: *const EVP_PKEY) -> *mut RSA;

    #[link_name = "wolfSSL_EVP_PKEY_CTX_set_rsa_padding"]
    pub fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut EVP_PKEY_CTX, pad: c_int) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_CTX_set_rsa_mgf1_md"]
    pub fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_CTX_set_rsa_oaep_md"]
    pub fn EVP_PKEY_CTX_set_rsa_oaep_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_CTX_set_rsa_pss_saltlen"]
    pub fn EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: *mut EVP_PKEY_CTX, saltlen: c_int) -> c_int;
    #[link_name = "wolfSSL_EVP_PKEY_CTX_set_rsa_keygen_bits"]
    pub fn EVP_PKEY_CTX_set_rsa_keygen_bits(ctx: *mut EVP_PKEY_CTX, bits: c_int) -> c_int;
}

// ============================================================
// DH (OpenSSL compat)
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_dh))]
extern "C" {
    #[link_name = "wolfSSL_DH_new"]
    pub fn DH_new() -> *mut DH;
    #[link_name = "wolfSSL_DH_free"]
    pub fn DH_free(dh: *mut DH);
    #[link_name = "wolfSSL_DH_up_ref"]
    pub fn DH_up_ref(dh: *mut DH) -> c_int;
    #[link_name = "wolfSSL_DH_size"]
    pub fn DH_size(dh: *mut DH) -> c_int;
    #[link_name = "wolfSSL_DH_generate_key"]
    pub fn DH_generate_key(dh: *mut DH) -> c_int;
    #[link_name = "wolfSSL_DH_compute_key"]
    pub fn DH_compute_key(key: *mut u8, pub_key: *const BIGNUM, dh: *mut DH) -> c_int;
    #[link_name = "wolfSSL_DH_compute_key_padded"]
    pub fn DH_compute_key_padded(key: *mut u8, pub_key: *const BIGNUM, dh: *mut DH) -> c_int;
    #[link_name = "wolfSSL_DH_set0_pqg"]
    pub fn DH_set0_pqg(dh: *mut DH, p: *mut BIGNUM, q: *mut BIGNUM, g: *mut BIGNUM) -> c_int;
    #[link_name = "wolfSSL_DH_get0_pqg"]
    pub fn DH_get0_pqg(
        dh: *const DH,
        p: *mut *const BIGNUM,
        q: *mut *const BIGNUM,
        g: *mut *const BIGNUM,
    );
    #[link_name = "wolfSSL_DH_set0_key"]
    pub fn DH_set0_key(dh: *mut DH, pub_key: *mut BIGNUM, priv_key: *mut BIGNUM) -> c_int;
    #[link_name = "wolfSSL_DH_get0_key"]
    pub fn DH_get0_key(
        dh: *const DH,
        pub_key: *mut *const BIGNUM,
        priv_key: *mut *const BIGNUM,
    );
    #[link_name = "wolfSSL_DH_check"]
    pub fn DH_check(dh: *const DH, codes: *mut c_int) -> c_int;
    #[link_name = "wolfSSL_DH_generate_parameters_ex"]
    pub fn DH_generate_parameters_ex(
        dh: *mut DH,
        prime_len: c_int,
        generator: c_int,
        cb: Option<unsafe extern "C" fn(c_int, c_int, *mut c_void)>,
    ) -> c_int;
    #[link_name = "wolfSSL_DH_new_by_nid"]
    pub fn DH_new_by_nid(nid: c_int) -> *mut DH;
}

// ============================================================
// Ed25519 (wolfCrypt native)
// ============================================================

#[cfg(wolfssl_ed25519)]
extern "C" {
    pub fn wc_ed25519_init(key: *mut wc_ed25519_key) -> c_int;
    pub fn wc_ed25519_free(key: *mut wc_ed25519_key);
    pub fn wc_ed25519_import_private_key(
        priv_: *const u8, privSz: u32,
        pub_: *const u8, pubSz: u32,
        key: *mut wc_ed25519_key,
    ) -> c_int;
    pub fn wc_ed25519_import_public(
        in_: *const u8, inLen: u32,
        key: *mut wc_ed25519_key,
    ) -> c_int;
    pub fn wc_ed25519_import_private_only(
        priv_: *const u8, privSz: u32,
        key: *mut wc_ed25519_key,
    ) -> c_int;
    pub fn wc_ed25519_sign_msg(
        in_: *const u8, inlen: u32,
        out: *mut u8, outlen: *mut u32,
        key: *mut wc_ed25519_key,
    ) -> c_int;
    pub fn wc_ed25519_verify_msg(
        sig: *const u8, siglen: u32,
        msg: *const u8, msglen: u32,
        res: *mut c_int,
        key: *mut wc_ed25519_key,
    ) -> c_int;
    pub fn wc_ed25519_make_public(
        key: *mut wc_ed25519_key,
        pubKey: *mut u8, pubKeySz: u32,
    ) -> c_int;
    pub fn wc_ed25519_export_private_only(
        key: *const wc_ed25519_key,
        out: *mut u8, outLen: *mut u32,
    ) -> c_int;
    pub fn wc_ed25519_export_public(
        key: *const wc_ed25519_key,
        out: *mut u8, outLen: *mut u32,
    ) -> c_int;
    pub fn wc_ed25519_make_key(rng: *mut WC_RNG, keysize: c_int, key: *mut wc_ed25519_key) -> c_int;

    // Ed25519 DER encode/decode (PKCS#8 / SubjectPublicKeyInfo)
    // These use wolfCrypt's ASN.1 engine rather than hand-rolled parsing.
    pub fn wc_Ed25519PrivateKeyDecode(
        input: *const u8, inOutIdx: *mut u32,
        key: *mut wc_ed25519_key, inSz: u32,
    ) -> c_int;
    pub fn wc_Ed25519PrivateKeyToDer(
        key: *const wc_ed25519_key, output: *mut u8, inLen: u32,
    ) -> c_int;
    pub fn wc_Ed25519KeyToDer(
        key: *const wc_ed25519_key, output: *mut u8, inLen: u32,
    ) -> c_int;
}

// ============================================================
// Ed448 (wolfCrypt native)
// ============================================================

#[cfg(wolfssl_ed448)]
extern "C" {
    pub fn wc_ed448_init(key: *mut wc_ed448_key) -> c_int;
    pub fn wc_ed448_free(key: *mut wc_ed448_key);
    pub fn wc_ed448_import_private_key(
        priv_: *const u8, privSz: u32,
        pub_: *const u8, pubSz: u32,
        key: *mut wc_ed448_key,
    ) -> c_int;
    pub fn wc_ed448_import_public(
        in_: *const u8, inLen: u32,
        key: *mut wc_ed448_key,
    ) -> c_int;
    pub fn wc_ed448_import_private_only(
        priv_: *const u8, privSz: u32,
        key: *mut wc_ed448_key,
    ) -> c_int;
    pub fn wc_ed448_sign_msg(
        in_: *const u8, inlen: u32,
        out: *mut u8, outlen: *mut u32,
        key: *mut wc_ed448_key,
        context: *const u8, contextLen: u8,
    ) -> c_int;
    pub fn wc_ed448_verify_msg(
        sig: *const u8, siglen: u32,
        msg: *const u8, msglen: u32,
        res: *mut c_int,
        key: *mut wc_ed448_key,
        context: *const u8, contextLen: u8,
    ) -> c_int;
    pub fn wc_ed448_make_public(
        key: *mut wc_ed448_key,
        pubKey: *mut u8, pubKeySz: u32,
    ) -> c_int;
    pub fn wc_ed448_export_private_only(
        key: *const wc_ed448_key,
        out: *mut u8, outLen: *mut u32,
    ) -> c_int;
    pub fn wc_ed448_export_public(
        key: *const wc_ed448_key,
        out: *mut u8, outLen: *mut u32,
    ) -> c_int;
    pub fn wc_ed448_make_key(rng: *mut WC_RNG, keysize: c_int, key: *mut wc_ed448_key) -> c_int;

    // Ed448 DER encode/decode (PKCS#8 / SubjectPublicKeyInfo)
    // NOTE: Ed448 DER functions take non-const key pointers, unlike their
    // Ed25519 counterparts which take `const`. This matches the upstream
    // wolfSSL API (asn_public.h) — the inconsistency is in wolfSSL itself.
    pub fn wc_Ed448PrivateKeyDecode(
        input: *const u8, inOutIdx: *mut u32,
        key: *mut wc_ed448_key, inSz: u32,
    ) -> c_int;
    pub fn wc_Ed448PrivateKeyToDer(
        key: *mut wc_ed448_key, output: *mut u8, inLen: u32,
    ) -> c_int;
    pub fn wc_Ed448KeyToDer(
        key: *mut wc_ed448_key, output: *mut u8, inLen: u32,
    ) -> c_int;
}

// ============================================================
// Curve25519 (wolfCrypt native)
// ============================================================

#[cfg(wolfssl_curve25519)]
extern "C" {
    pub fn wc_curve25519_init(key: *mut wc_curve25519_key) -> c_int;
    pub fn wc_curve25519_free(key: *mut wc_curve25519_key);
    // NOTE: wolfSSL signature has output params before input params
    pub fn wc_curve25519_make_pub(
        pubSz: c_int,
        pub_: *mut u8,
        privSz: c_int,
        priv_: *const u8,
    ) -> c_int;
    pub fn wc_curve25519_make_key(
        rng: *mut WC_RNG,
        keysize: c_int,
        key: *mut wc_curve25519_key,
    ) -> c_int;
    pub fn wc_curve25519_import_private_ex(
        priv_: *const u8, privSz: u32,
        key: *mut wc_curve25519_key,
        endian: c_int,
    ) -> c_int;
    pub fn wc_curve25519_import_private_raw_ex(
        priv_: *const u8, privSz: u32,
        pub_: *const u8, pubSz: u32,
        key: *mut wc_curve25519_key,
        endian: c_int,
    ) -> c_int;
    pub fn wc_curve25519_import_public_ex(
        in_: *const u8, inLen: u32,
        key: *mut wc_curve25519_key,
        endian: c_int,
    ) -> c_int;
    pub fn wc_curve25519_export_key_raw_ex(
        key: *mut wc_curve25519_key,
        priv_: *mut u8, privSz: *mut u32,
        pub_: *mut u8, pubSz: *mut u32,
        endian: c_int,
    ) -> c_int;
    pub fn wc_curve25519_shared_secret_ex(
        priv_: *mut wc_curve25519_key,
        pub_: *mut wc_curve25519_key,
        out: *mut u8, outLen: *mut u32,
        endian: c_int,
    ) -> c_int;
    pub fn wc_curve25519_set_rng(key: *mut wc_curve25519_key, rng: *mut WC_RNG) -> c_int;
}

// ============================================================
// Curve448 (wolfCrypt native)
// ============================================================

#[cfg(wolfssl_curve448)]
extern "C" {
    pub fn wc_curve448_init(key: *mut wc_curve448_key) -> c_int;
    pub fn wc_curve448_free(key: *mut wc_curve448_key);
    pub fn wc_curve448_make_key(
        rng: *mut WC_RNG,
        keysize: c_int,
        key: *mut wc_curve448_key,
    ) -> c_int;
    pub fn wc_curve448_import_private_ex(
        priv_: *const u8, privSz: u32,
        key: *mut wc_curve448_key,
        endian: c_int,
    ) -> c_int;
    pub fn wc_curve448_import_public_ex(
        in_: *const u8, inLen: u32,
        key: *mut wc_curve448_key,
        endian: c_int,
    ) -> c_int;
    pub fn wc_curve448_import_private_raw_ex(
        priv_: *const u8, privSz: u32,
        pub_: *const u8, pubSz: u32,
        key: *mut wc_curve448_key,
        endian: c_int,
    ) -> c_int;
    pub fn wc_curve448_export_key_raw_ex(
        key: *mut wc_curve448_key,
        priv_: *mut u8, privSz: *mut u32,
        pub_: *mut u8, pubSz: *mut u32,
        endian: c_int,
    ) -> c_int;
    pub fn wc_curve448_shared_secret_ex(
        priv_: *mut wc_curve448_key,
        pub_: *mut wc_curve448_key,
        out: *mut u8, outLen: *mut u32,
        endian: c_int,
    ) -> c_int;
    pub fn wc_curve448_make_pub(
        pubSz: c_int,
        pub_: *mut u8,
        privSz: c_int,
        priv_: *const u8,
    ) -> c_int;
}

// ============================================================
// HKDF (wolfCrypt native)
// ============================================================

#[cfg(wolfssl_hkdf)]
extern "C" {
    pub fn wc_HKDF(
        hash_type: c_int,
        inKey: *const u8,
        inKeySz: u32,
        salt: *const u8,
        saltSz: u32,
        info: *const u8,
        infoSz: u32,
        out: *mut u8,
        outSz: u32,
    ) -> c_int;

    pub fn wc_HKDF_Extract(
        hash_type: c_int,
        salt: *const u8,
        saltSz: u32,
        inKey: *const u8,
        inKeySz: u32,
        out: *mut u8,
    ) -> c_int;

    pub fn wc_HKDF_Expand(
        hash_type: c_int,
        prk: *const u8,
        prkSz: u32,
        info: *const u8,
        infoSz: u32,
        out: *mut u8,
        outSz: u32,
    ) -> c_int;
}

// ============================================================
// PBKDF2 (OpenSSL compat)
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_pbkdf2))]
extern "C" {
    #[link_name = "wolfSSL_PKCS5_PBKDF2_HMAC"]
    pub fn PKCS5_PBKDF2_HMAC(
        pass: *const c_char,
        passlen: c_int,
        salt: *const u8,
        saltlen: c_int,
        iter: c_int,
        digest: *const EVP_MD,
        keylen: c_int,
        out: *mut u8,
    ) -> c_int;
}

// ============================================================
// PBKDF2 (native wolfCrypt API)
// ============================================================

#[cfg(wolfssl_pbkdf2)]
extern "C" {
    pub fn wc_PBKDF2(
        output: *mut u8,
        passwd: *const u8,
        p_len: c_int,
        salt: *const u8,
        s_len: c_int,
        iterations: c_int,
        k_len: c_int,
        hash_type: c_int,
    ) -> c_int;
}

// ============================================================
// TLS 1.2 PRF (shim in compat_shim.c)
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_hmac))]
extern "C" {
    /// TLS 1.2 PRF per RFC 5246 §5, implemented in compat_shim.c.
    /// No `#[link_name]` needed — the symbol is defined in our own shim.
    pub fn CRYPTO_tls1_prf(
        md: *const EVP_MD,
        out: *mut u8,
        out_len: usize,
        secret: *const u8,
        secret_len: usize,
        label: *const c_char,
        label_len: usize,
        seed1: *const u8,
        seed1_len: usize,
        seed2: *const u8,
        seed2_len: usize,
    ) -> c_int;
}

// ============================================================
// KDF shims (in compat_shim.c)
// ============================================================

#[cfg(all(wolfssl_openssl_extra, wolfssl_hmac))]
extern "C" {
    /// KBKDF Counter Mode with HMAC per NIST SP 800-108r1 §4.1.
    /// Implemented in compat_shim.c — no `#[link_name]` needed.
    pub fn KBKDF_ctr_hmac(
        out: *mut u8,
        out_len: usize,
        digest: *const EVP_MD,
        key: *const u8,
        key_len: usize,
        info: *const u8,
        info_len: usize,
    ) -> c_int;

    /// SSKDF with digest per NIST SP 800-56Cr2 §4.1.
    /// Implemented in compat_shim.c — no `#[link_name]` needed.
    pub fn SSKDF_digest(
        out: *mut u8,
        out_len: usize,
        digest: *const EVP_MD,
        secret: *const u8,
        secret_len: usize,
        info: *const u8,
        info_len: usize,
    ) -> c_int;

    /// SSKDF with HMAC per NIST SP 800-56Cr2 §4.2.
    /// Implemented in compat_shim.c — no `#[link_name]` needed.
    pub fn SSKDF_hmac(
        out: *mut u8,
        out_len: usize,
        digest: *const EVP_MD,
        secret: *const u8,
        secret_len: usize,
        info: *const u8,
        info_len: usize,
        salt: *const u8,
        salt_len: usize,
    ) -> c_int;
}

// ============================================================
// Poly1305 (wolfCrypt native)
// ============================================================

#[cfg(wolfssl_poly1305)]
extern "C" {
    pub fn wc_Poly1305SetKey(
        ctx: *mut poly1305_state,
        key: *const u8,
        keySz: u32,
    ) -> c_int;

    pub fn wc_Poly1305Update(
        ctx: *mut poly1305_state,
        input: *const u8,
        sz: u32,
    ) -> c_int;

    pub fn wc_Poly1305Final(
        ctx: *mut poly1305_state,
        mac: *mut u8,
    ) -> c_int;
}

// ============================================================
// ChaCha20 (wolfCrypt native)
// ============================================================

#[cfg(wolfssl_chacha)]
extern "C" {
    pub fn wc_Chacha_SetKey(
        ctx: *mut ChaCha,
        key: *const u8,
        keySz: u32,
    ) -> c_int;

    pub fn wc_Chacha_SetIV(
        ctx: *mut ChaCha,
        iv: *const u8,
        counter: u32,
    ) -> c_int;

    pub fn wc_Chacha_Process(
        ctx: *mut ChaCha,
        output: *mut u8,
        input: *const u8,
        msglen: u32,
    ) -> c_int;
}

// ============================================================
// AES CTR (wolfCrypt native)
// ============================================================

#[cfg(wolfssl_aes_ctr)]
extern "C" {
    pub fn wc_AesCtrEncrypt(aes: *mut WcAes, out: *mut u8, in_: *const u8, sz: u32) -> c_int;
}

// ============================================================
// AES-GCM (wolfCrypt native)
// ============================================================

#[cfg(wolfssl_aes_gcm)]
extern "C" {
    pub fn wc_AesGcmSetKey(aes: *mut WcAes, key: *const u8, len: u32) -> c_int;
    pub fn wc_AesGcmEncrypt(
        aes: *mut WcAes, out: *mut u8, in_: *const u8, sz: u32,
        iv: *const u8, ivSz: u32,
        authTag: *mut u8, authTagSz: u32,
        authIn: *const u8, authInSz: u32,
    ) -> c_int;
    pub fn wc_AesGcmDecrypt(
        aes: *mut WcAes, out: *mut u8, in_: *const u8, sz: u32,
        iv: *const u8, ivSz: u32,
        authTag: *const u8, authTagSz: u32,
        authIn: *const u8, authInSz: u32,
    ) -> c_int;
}

// ============================================================
// AES-CCM (wolfCrypt native)
// ============================================================

/// AES-CCM nonce minimum size (7 bytes).
#[cfg(wolfssl_aes_ccm)]
pub const CCM_NONCE_MIN_SZ: usize = 7;
/// AES-CCM nonce maximum size (13 bytes).
#[cfg(wolfssl_aes_ccm)]
pub const CCM_NONCE_MAX_SZ: usize = 13;

#[cfg(wolfssl_aes_ccm)]
extern "C" {
    /// Set the encryption key for AES-CCM.
    #[link_name = "wc_AesCcmSetKey"]
    pub fn wc_AesCcmSetKey(aes: *mut WcAes, key: *const u8, keySz: u32) -> c_int;

    /// AES-CCM encrypt with authentication.
    #[link_name = "wc_AesCcmEncrypt"]
    pub fn wc_AesCcmEncrypt(
        aes: *mut WcAes, out: *mut u8,
        in_: *const u8, inSz: u32,
        nonce: *const u8, nonceSz: u32,
        authTag: *mut u8, authTagSz: u32,
        authIn: *const u8, authInSz: u32,
    ) -> c_int;

    /// AES-CCM decrypt with authentication verification.
    #[link_name = "wc_AesCcmDecrypt"]
    pub fn wc_AesCcmDecrypt(
        aes: *mut WcAes, out: *mut u8,
        in_: *const u8, inSz: u32,
        nonce: *const u8, nonceSz: u32,
        authTag: *const u8, authTagSz: u32,
        authIn: *const u8, authInSz: u32,
    ) -> c_int;
}

// ============================================================
// AES-GCM Streaming (wolfCrypt native)
// ============================================================

#[cfg(wolfssl_aes_gcm_stream)]
extern "C" {
    /// Initialize AES-GCM streaming context with key and IV.
    #[link_name = "wc_AesGcmInit"]
    pub fn wc_AesGcmInit(
        aes: *mut WcAes, key: *const u8, len: u32,
        iv: *const u8, ivSz: u32,
    ) -> c_int;

    /// Start AES-GCM streaming encryption (set key + IV).
    #[link_name = "wc_AesGcmEncryptInit"]
    pub fn wc_AesGcmEncryptInit(
        aes: *mut WcAes, key: *const u8, len: u32,
        iv: *const u8, ivSz: u32,
    ) -> c_int;

    /// Feed plaintext and/or AAD into the streaming GCM encryption.
    /// Either `out`/`in_`/`sz` or `authIn`/`authInSz` may be zero-length.
    #[link_name = "wc_AesGcmEncryptUpdate"]
    pub fn wc_AesGcmEncryptUpdate(
        aes: *mut WcAes, out: *mut u8,
        in_: *const u8, sz: u32,
        authIn: *const u8, authInSz: u32,
    ) -> c_int;

    /// Finalize streaming GCM encryption, producing the authentication tag.
    #[link_name = "wc_AesGcmEncryptFinal"]
    pub fn wc_AesGcmEncryptFinal(
        aes: *mut WcAes, authTag: *mut u8, authTagSz: u32,
    ) -> c_int;

    /// Start AES-GCM streaming decryption (set key + IV).
    #[link_name = "wc_AesGcmDecryptInit"]
    pub fn wc_AesGcmDecryptInit(
        aes: *mut WcAes, key: *const u8, len: u32,
        iv: *const u8, ivSz: u32,
    ) -> c_int;

    /// Feed ciphertext and/or AAD into the streaming GCM decryption.
    #[link_name = "wc_AesGcmDecryptUpdate"]
    pub fn wc_AesGcmDecryptUpdate(
        aes: *mut WcAes, out: *mut u8,
        in_: *const u8, sz: u32,
        authIn: *const u8, authInSz: u32,
    ) -> c_int;

    /// Finalize streaming GCM decryption, verifying the authentication tag.
    /// Returns 0 on success (tag matches), negative on failure.
    #[link_name = "wc_AesGcmDecryptFinal"]
    pub fn wc_AesGcmDecryptFinal(
        aes: *mut WcAes, authTag: *const u8, authTagSz: u32,
    ) -> c_int;
}

// ============================================================
// TLS 1.3 HKDF (wolfCrypt native)
// ============================================================

#[cfg(wolfssl_tls13_hkdf)]
extern "C" {
    /// TLS 1.3 HKDF-Extract: derive a PRK from salt + IKM.
    /// `digest` is a `WC_HASH_TYPE_*` constant (e.g. SHA256=4).
    #[link_name = "wc_Tls13_HKDF_Extract"]
    pub fn wc_Tls13_HKDF_Extract(
        prk: *mut u8,
        salt: *const u8, saltLen: u32,
        ikm: *mut u8, ikmLen: u32,
        digest: c_int,
    ) -> c_int;

    /// TLS 1.3 HKDF-Extract (extended, with heap/devId).
    #[link_name = "wc_Tls13_HKDF_Extract_ex"]
    pub fn wc_Tls13_HKDF_Extract_ex(
        prk: *mut u8,
        salt: *const u8, saltLen: u32,
        ikm: *mut u8, ikmLen: u32,
        digest: c_int,
        heap: *mut c_void, devId: c_int,
    ) -> c_int;

    /// TLS 1.3 HKDF-Expand-Label per RFC 8446 §7.1.
    /// `protocol` is typically b"tls13 " or b"dtls13".
    #[link_name = "wc_Tls13_HKDF_Expand_Label"]
    pub fn wc_Tls13_HKDF_Expand_Label(
        okm: *mut u8, okmLen: u32,
        prk: *const u8, prkLen: u32,
        protocol: *const u8, protocolLen: u32,
        label: *const u8, labelLen: u32,
        info: *const u8, infoLen: u32,
        digest: c_int,
    ) -> c_int;

    /// TLS 1.3 HKDF-Expand-Label (extended, with heap/devId).
    #[link_name = "wc_Tls13_HKDF_Expand_Label_ex"]
    pub fn wc_Tls13_HKDF_Expand_Label_ex(
        okm: *mut u8, okmLen: u32,
        prk: *const u8, prkLen: u32,
        protocol: *const u8, protocolLen: u32,
        label: *const u8, labelLen: u32,
        info: *const u8, infoLen: u32,
        digest: c_int,
        heap: *mut c_void, devId: c_int,
    ) -> c_int;
}

// ============================================================
// ChaCha20-Poly1305 (wolfCrypt native)
// ============================================================

#[cfg(wolfssl_chacha20_poly1305)]
extern "C" {
    pub fn wc_ChaCha20Poly1305_Encrypt(
        inKey: *const u8, inIV: *const u8,
        inAAD: *const u8, inAADLen: u32,
        inPlaintext: *const u8, inPlaintextLen: u32,
        outCiphertext: *mut u8,
        outAuthTag: *mut u8,
    ) -> c_int;
    pub fn wc_ChaCha20Poly1305_Decrypt(
        inKey: *const u8, inIV: *const u8,
        inAAD: *const u8, inAADLen: u32,
        inCiphertext: *const u8, inCiphertextLen: u32,
        inAuthTag: *const u8,
        outPlaintext: *mut u8,
    ) -> c_int;

    // Streaming API
    pub fn wc_ChaCha20Poly1305_Init(
        aead: *mut ChaChaPoly_Aead,
        inKey: *const u8, inIV: *const u8,
        isEncrypt: c_int,
    ) -> c_int;
    pub fn wc_ChaCha20Poly1305_UpdateAad(
        aead: *mut ChaChaPoly_Aead,
        inAAD: *const u8, inAADLen: u32,
    ) -> c_int;
    pub fn wc_ChaCha20Poly1305_UpdateData(
        aead: *mut ChaChaPoly_Aead,
        inData: *const u8, outData: *mut u8, dataLen: u32,
    ) -> c_int;
    pub fn wc_ChaCha20Poly1305_Final(
        aead: *mut ChaChaPoly_Aead,
        outAuthTag: *mut u8,
    ) -> c_int;
    pub fn wc_ChaCha20Poly1305_CheckTag(
        authTag: *const u8, authTagChk: *const u8,
    ) -> c_int;
}

// ============================================================
// ML-DSA (Dilithium) — native wolfCrypt API
// ============================================================

#[cfg(wolfssl_dilithium)]
extern "C" {
    #[link_name = "wc_dilithium_init"]
    pub fn wc_dilithium_init(key: *mut wc_dilithium_key) -> c_int;

    #[link_name = "wc_dilithium_free"]
    pub fn wc_dilithium_free(key: *mut wc_dilithium_key);

    #[link_name = "wc_dilithium_set_level"]
    pub fn wc_dilithium_set_level(key: *mut wc_dilithium_key, level: u8) -> c_int;

    #[link_name = "wc_dilithium_make_key"]
    pub fn wc_dilithium_make_key(key: *mut wc_dilithium_key, rng: *mut WC_RNG) -> c_int;

    #[link_name = "wc_dilithium_make_key_from_seed"]
    pub fn wc_dilithium_make_key_from_seed(
        key: *mut wc_dilithium_key,
        seed: *const u8,
    ) -> c_int;

    #[link_name = "wc_dilithium_sign_msg"]
    pub fn wc_dilithium_sign_msg(
        msg: *const u8,
        msgLen: u32,
        sig: *mut u8,
        sigLen: *mut u32,
        key: *mut wc_dilithium_key,
        rng: *mut WC_RNG,
    ) -> c_int;

    #[link_name = "wc_dilithium_verify_msg"]
    pub fn wc_dilithium_verify_msg(
        sig: *const u8,
        sigLen: u32,
        msg: *const u8,
        msgLen: u32,
        res: *mut c_int,
        key: *mut wc_dilithium_key,
    ) -> c_int;

    /// FIPS 204 context-aware verification (Algorithm 3).
    /// Uses internal message format: M' = 0x00 || ctxLen || ctx || msg.
    #[link_name = "wc_dilithium_verify_ctx_msg"]
    pub fn wc_dilithium_verify_ctx_msg(
        sig: *const u8,
        sigLen: u32,
        ctx: *const u8,
        ctxLen: u32,
        msg: *const u8,
        msgLen: u32,
        res: *mut c_int,
        key: *mut wc_dilithium_key,
    ) -> c_int;

    /// FIPS 204 context-aware signing (Algorithm 2).
    /// Uses internal message format: M' = 0x00 || ctxLen || ctx || msg.
    #[link_name = "wc_dilithium_sign_ctx_msg"]
    pub fn wc_dilithium_sign_ctx_msg(
        ctx: *const u8,
        ctxLen: u8,
        msg: *const u8,
        msgLen: u32,
        sig: *mut u8,
        sigLen: *mut u32,
        key: *mut wc_dilithium_key,
        rng: *mut WC_RNG,
    ) -> c_int;

    #[link_name = "wc_dilithium_import_public"]
    pub fn wc_dilithium_import_public(
        input: *const u8,
        inLen: u32,
        key: *mut wc_dilithium_key,
    ) -> c_int;

    #[link_name = "wc_dilithium_import_private"]
    pub fn wc_dilithium_import_private(
        priv_key: *const u8,
        privSz: u32,
        key: *mut wc_dilithium_key,
    ) -> c_int;

    #[link_name = "wc_dilithium_export_public"]
    pub fn wc_dilithium_export_public(
        key: *mut wc_dilithium_key,
        out: *mut u8,
        outLen: *mut u32,
    ) -> c_int;

    #[link_name = "wc_dilithium_export_private"]
    pub fn wc_dilithium_export_private(
        key: *mut wc_dilithium_key,
        out: *mut u8,
        outLen: *mut u32,
    ) -> c_int;

    #[link_name = "wc_dilithium_import_key"]
    pub fn wc_dilithium_import_key(
        priv_key: *const u8,
        privSz: u32,
        pub_key: *const u8,
        pubSz: u32,
        key: *mut wc_dilithium_key,
    ) -> c_int;

    #[link_name = "wc_dilithium_export_key"]
    pub fn wc_dilithium_export_key(
        key: *mut wc_dilithium_key,
        priv_out: *mut u8,
        privSz: *mut u32,
        pub_out: *mut u8,
        pubSz: *mut u32,
    ) -> c_int;
}

// ============================================================
// ML-KEM (FIPS 203) — native wolfCrypt API
// ============================================================

/// Opaque ML-KEM key (heap-allocated via `wc_MlKemKey_New`).
#[cfg(wolfssl_mlkem)]
#[repr(C)]
pub struct MlKemKey {
    _opaque: [u8; 0],
}

// ---- ML-KEM type constants (from wolfssl/wolfcrypt/mlkem.h enum) ----
/// ML-KEM-512 type parameter.
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_512: c_int = 0;
/// ML-KEM-768 type parameter.
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_768: c_int = 1;
/// ML-KEM-1024 type parameter.
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_1024: c_int = 2;

// ---- ML-KEM sizes (from wolfssl/wolfcrypt/mlkem.h) ----
/// Shared secret size (all ML-KEM levels).
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_SS_SZ: usize = 32;

/// ML-KEM-512 public key size in bytes.
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_512_PUBLIC_KEY_SIZE: usize = 800;
/// ML-KEM-512 private key size in bytes.
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_512_PRIVATE_KEY_SIZE: usize = 1632;
/// ML-KEM-512 ciphertext size in bytes.
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_512_CIPHER_TEXT_SIZE: usize = 768;

/// ML-KEM-768 public key size in bytes.
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;
/// ML-KEM-768 private key size in bytes.
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_768_PRIVATE_KEY_SIZE: usize = 2400;
/// ML-KEM-768 ciphertext size in bytes.
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_768_CIPHER_TEXT_SIZE: usize = 1088;

/// ML-KEM-1024 public key size in bytes.
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_1024_PUBLIC_KEY_SIZE: usize = 1568;
/// ML-KEM-1024 private key size in bytes.
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_1024_PRIVATE_KEY_SIZE: usize = 3168;
/// ML-KEM-1024 ciphertext size in bytes.
#[cfg(wolfssl_mlkem)]
pub const WC_ML_KEM_1024_CIPHER_TEXT_SIZE: usize = 1568;

#[cfg(wolfssl_mlkem)]
extern "C" {
    /// Allocate a new ML-KEM key on the heap.
    /// `type_` is one of `WC_ML_KEM_512`, `WC_ML_KEM_768`, `WC_ML_KEM_1024`.
    /// `heap` and `devId` are typically null/`INVALID_DEVID`.
    /// Returns null on failure.
    #[link_name = "wc_MlKemKey_New"]
    pub fn wc_MlKemKey_New(type_: c_int, heap: *mut c_void, devId: c_int) -> *mut MlKemKey;

    /// Free (deallocate) an ML-KEM key previously created by `wc_MlKemKey_New`.
    /// `key_p` can be null; if non-null, `*key_p` is set to null after freeing.
    #[link_name = "wc_MlKemKey_Delete"]
    pub fn wc_MlKemKey_Delete(key: *mut MlKemKey, key_p: *mut *mut MlKemKey) -> c_int;

    /// Generate a new ML-KEM key pair.
    #[link_name = "wc_MlKemKey_MakeKey"]
    pub fn wc_MlKemKey_MakeKey(key: *mut MlKemKey, rng: *mut WC_RNG) -> c_int;

    /// Get the ciphertext size for this key's algorithm.
    #[link_name = "wc_MlKemKey_CipherTextSize"]
    pub fn wc_MlKemKey_CipherTextSize(key: *mut MlKemKey, len: *mut u32) -> c_int;

    /// Get the shared secret size for this key's algorithm.
    #[link_name = "wc_MlKemKey_SharedSecretSize"]
    pub fn wc_MlKemKey_SharedSecretSize(key: *mut MlKemKey, len: *mut u32) -> c_int;

    /// Encapsulate: produce ciphertext and shared secret from an encapsulation key.
    #[link_name = "wc_MlKemKey_Encapsulate"]
    pub fn wc_MlKemKey_Encapsulate(
        key: *mut MlKemKey,
        ct: *mut u8,
        ss: *mut u8,
        rng: *mut WC_RNG,
    ) -> c_int;

    /// Decapsulate: derive shared secret from ciphertext using a decapsulation key.
    #[link_name = "wc_MlKemKey_Decapsulate"]
    pub fn wc_MlKemKey_Decapsulate(
        key: *mut MlKemKey,
        ss: *mut u8,
        ct: *const u8,
        len: u32,
    ) -> c_int;

    /// Decode (import) a private key from raw bytes.
    #[link_name = "wc_MlKemKey_DecodePrivateKey"]
    pub fn wc_MlKemKey_DecodePrivateKey(
        key: *mut MlKemKey,
        input: *const u8,
        len: u32,
    ) -> c_int;

    /// Decode (import) a public key from raw bytes.
    #[link_name = "wc_MlKemKey_DecodePublicKey"]
    pub fn wc_MlKemKey_DecodePublicKey(
        key: *mut MlKemKey,
        input: *const u8,
        len: u32,
    ) -> c_int;

    /// Get the private key size for this key's algorithm.
    #[link_name = "wc_MlKemKey_PrivateKeySize"]
    pub fn wc_MlKemKey_PrivateKeySize(key: *mut MlKemKey, len: *mut u32) -> c_int;

    /// Get the public key size for this key's algorithm.
    #[link_name = "wc_MlKemKey_PublicKeySize"]
    pub fn wc_MlKemKey_PublicKeySize(key: *mut MlKemKey, len: *mut u32) -> c_int;

    /// Encode (export) the private key to raw bytes.
    #[link_name = "wc_MlKemKey_EncodePrivateKey"]
    pub fn wc_MlKemKey_EncodePrivateKey(
        key: *mut MlKemKey,
        out: *mut u8,
        len: u32,
    ) -> c_int;

    /// Encode (export) the public key to raw bytes.
    #[link_name = "wc_MlKemKey_EncodePublicKey"]
    pub fn wc_MlKemKey_EncodePublicKey(
        key: *mut MlKemKey,
        out: *mut u8,
        len: u32,
    ) -> c_int;
}

// ============================================================
// Blake2b (wolfCrypt native)
// ============================================================

/// Allocation size for wolfCrypt's `Blake2b` struct.
/// Verified by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_blake2b)]
pub const WC_BLAKE2B_ALLOC_SIZE: usize = 512;

/// wolfCrypt Blake2b state — sized to hold wolfSSL's `Blake2b` struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_blake2b)]
#[repr(C, align(8))]
pub struct WcBlake2b {
    _opaque: [u8; WC_BLAKE2B_ALLOC_SIZE],
}

#[cfg(wolfssl_blake2b)]
impl WcBlake2b {
    /// Create a zero-initialized `WcBlake2b`. Must be passed to
    /// `wc_InitBlake2b` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_BLAKE2B_ALLOC_SIZE] }
    }
}

#[cfg(wolfssl_blake2b)]
extern "C" {
    #[link_name = "wc_InitBlake2b"]
    pub fn wc_InitBlake2b(b2b: *mut WcBlake2b, digestSz: u32) -> c_int;
    #[link_name = "wc_InitBlake2b_WithKey"]
    pub fn wc_InitBlake2b_WithKey(
        b2b: *mut WcBlake2b, digestSz: u32,
        key: *const u8, keySz: u32,
    ) -> c_int;
    #[link_name = "wc_Blake2bUpdate"]
    pub fn wc_Blake2bUpdate(b2b: *mut WcBlake2b, data: *const u8, len: u32) -> c_int;
    #[link_name = "wc_Blake2bFinal"]
    pub fn wc_Blake2bFinal(b2b: *mut WcBlake2b, out: *mut u8, outSz: u32) -> c_int;
}

// ============================================================
// Blake2s (wolfCrypt native)
// ============================================================

/// Allocation size for wolfCrypt's `Blake2s` struct.
/// Verified by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_blake2s)]
pub const WC_BLAKE2S_ALLOC_SIZE: usize = 256;

/// wolfCrypt Blake2s state — sized to hold wolfSSL's `Blake2s` struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_blake2s)]
#[repr(C, align(4))]
pub struct WcBlake2s {
    _opaque: [u8; WC_BLAKE2S_ALLOC_SIZE],
}

#[cfg(wolfssl_blake2s)]
impl WcBlake2s {
    /// Create a zero-initialized `WcBlake2s`. Must be passed to
    /// `wc_InitBlake2s` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_BLAKE2S_ALLOC_SIZE] }
    }
}

#[cfg(wolfssl_blake2s)]
extern "C" {
    #[link_name = "wc_InitBlake2s"]
    pub fn wc_InitBlake2s(b2s: *mut WcBlake2s, digestSz: u32) -> c_int;
    #[link_name = "wc_InitBlake2s_WithKey"]
    pub fn wc_InitBlake2s_WithKey(
        b2s: *mut WcBlake2s, digestSz: u32,
        key: *const u8, keySz: u32,
    ) -> c_int;
    #[link_name = "wc_Blake2sUpdate"]
    pub fn wc_Blake2sUpdate(b2s: *mut WcBlake2s, data: *const u8, len: u32) -> c_int;
    #[link_name = "wc_Blake2sFinal"]
    pub fn wc_Blake2sFinal(b2s: *mut WcBlake2s, out: *mut u8, outSz: u32) -> c_int;
}

// ============================================================
// SHAKE128 / SHAKE256 (wolfCrypt native)
// ============================================================

/// Allocation size for wolfCrypt's `wc_Shake` struct.
/// Verified by `_Static_assert` in compat_shim.c.
#[cfg(any(wolfssl_shake128, wolfssl_shake256))]
pub const WC_SHAKE_ALLOC_SIZE: usize = 512;

/// wolfCrypt wc_Shake state — sized to hold wolfSSL's `wc_Shake` struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(any(wolfssl_shake128, wolfssl_shake256))]
#[repr(C, align(8))]
pub struct WcShake {
    _opaque: [u8; WC_SHAKE_ALLOC_SIZE],
}

#[cfg(any(wolfssl_shake128, wolfssl_shake256))]
impl WcShake {
    /// Create a zero-initialized `WcShake`. Must be passed to
    /// `wc_InitShake128` or `wc_InitShake256` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_SHAKE_ALLOC_SIZE] }
    }
}

#[cfg(wolfssl_shake128)]
extern "C" {
    #[link_name = "wc_InitShake128"]
    pub fn wc_InitShake128(shake: *mut WcShake, heap: *mut c_void, devId: c_int) -> c_int;
    #[link_name = "wc_Shake128_Update"]
    pub fn wc_Shake128_Update(shake: *mut WcShake, data: *const u8, len: u32) -> c_int;
    #[link_name = "wc_Shake128_Final"]
    pub fn wc_Shake128_Final(shake: *mut WcShake, out: *mut u8, outSz: u32) -> c_int;
    #[link_name = "wc_Shake128_Absorb"]
    pub fn wc_Shake128_Absorb(shake: *mut WcShake, data: *const u8, len: u32) -> c_int;
    #[link_name = "wc_Shake128_SqueezeBlocks"]
    pub fn wc_Shake128_SqueezeBlocks(shake: *mut WcShake, out: *mut u8, blockCnt: u32) -> c_int;
    #[link_name = "wc_Shake128_Free"]
    pub fn wc_Shake128_Free(shake: *mut WcShake);
}

#[cfg(wolfssl_shake256)]
extern "C" {
    #[link_name = "wc_InitShake256"]
    pub fn wc_InitShake256(shake: *mut WcShake, heap: *mut c_void, devId: c_int) -> c_int;
    #[link_name = "wc_Shake256_Update"]
    pub fn wc_Shake256_Update(shake: *mut WcShake, data: *const u8, len: u32) -> c_int;
    #[link_name = "wc_Shake256_Final"]
    pub fn wc_Shake256_Final(shake: *mut WcShake, out: *mut u8, outSz: u32) -> c_int;
    #[link_name = "wc_Shake256_Absorb"]
    pub fn wc_Shake256_Absorb(shake: *mut WcShake, data: *const u8, len: u32) -> c_int;
    #[link_name = "wc_Shake256_SqueezeBlocks"]
    pub fn wc_Shake256_SqueezeBlocks(shake: *mut WcShake, out: *mut u8, blockCnt: u32) -> c_int;
    #[link_name = "wc_Shake256_Free"]
    pub fn wc_Shake256_Free(shake: *mut WcShake);
}

// ============================================================
// AES-XTS (wolfCrypt native)
// ============================================================

/// Allocation size for wolfCrypt's `XtsAes` struct.
/// Verified by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_aes_xts)]
pub const WC_XTS_AES_ALLOC_SIZE: usize = 3072;

/// wolfCrypt XtsAes state — sized to hold wolfSSL's `XtsAes` struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_aes_xts)]
#[repr(C, align(16))]
pub struct XtsAes {
    _opaque: [u8; WC_XTS_AES_ALLOC_SIZE],
}

#[cfg(wolfssl_aes_xts)]
impl XtsAes {
    /// Create a zero-initialized `XtsAes`. Must be passed to
    /// `wc_AesXtsInit` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_XTS_AES_ALLOC_SIZE] }
    }
}

#[cfg(wolfssl_aes_xts)]
extern "C" {
    #[link_name = "wc_AesXtsInit"]
    pub fn wc_AesXtsInit(xts: *mut XtsAes, heap: *mut c_void, devId: c_int) -> c_int;
    #[link_name = "wc_AesXtsSetKeyNoInit"]
    pub fn wc_AesXtsSetKeyNoInit(xts: *mut XtsAes, key: *const u8, len: u32, dir: c_int) -> c_int;
    #[link_name = "wc_AesXtsEncrypt"]
    pub fn wc_AesXtsEncrypt(
        xts: *mut XtsAes, out: *mut u8, in_: *const u8, sz: u32,
        tweak: *const u8, tweakSz: u32,
    ) -> c_int;
    #[link_name = "wc_AesXtsDecrypt"]
    pub fn wc_AesXtsDecrypt(
        xts: *mut XtsAes, out: *mut u8, in_: *const u8, sz: u32,
        tweak: *const u8, tweakSz: u32,
    ) -> c_int;
    #[link_name = "wc_AesXtsFree"]
    pub fn wc_AesXtsFree(xts: *mut XtsAes) -> c_int;
}

// ============================================================
// AES-OFB (wolfCrypt native, uses existing WcAes struct)
// ============================================================

#[cfg(wolfssl_aes_ofb)]
extern "C" {
    #[link_name = "wc_AesOfbEncrypt"]
    pub fn wc_AesOfbEncrypt(aes: *mut WcAes, out: *mut u8, in_: *const u8, sz: u32) -> c_int;
    #[link_name = "wc_AesOfbDecrypt"]
    pub fn wc_AesOfbDecrypt(aes: *mut WcAes, out: *mut u8, in_: *const u8, sz: u32) -> c_int;
}

// ============================================================
// AES-CTS (wolfCrypt native)
// One-shot API takes raw key+IV; incremental API uses WcAes.
// ============================================================

#[cfg(wolfssl_aes_cts)]
extern "C" {
    // One-shot API
    #[link_name = "wc_AesCtsEncrypt"]
    pub fn wc_AesCtsEncrypt(
        key: *const u8, keySz: u32, out: *mut u8,
        in_: *const u8, inSz: u32, iv: *const u8,
    ) -> c_int;
    #[link_name = "wc_AesCtsDecrypt"]
    pub fn wc_AesCtsDecrypt(
        key: *const u8, keySz: u32, out: *mut u8,
        in_: *const u8, inSz: u32, iv: *const u8,
    ) -> c_int;

    // Incremental API
    #[link_name = "wc_AesCtsEncryptUpdate"]
    pub fn wc_AesCtsEncryptUpdate(
        aes: *mut WcAes, out: *mut u8, outSz: *mut u32,
        in_: *const u8, inSz: u32,
    ) -> c_int;
    #[link_name = "wc_AesCtsDecryptUpdate"]
    pub fn wc_AesCtsDecryptUpdate(
        aes: *mut WcAes, out: *mut u8, outSz: *mut u32,
        in_: *const u8, inSz: u32,
    ) -> c_int;
    #[link_name = "wc_AesCtsEncryptFinal"]
    pub fn wc_AesCtsEncryptFinal(aes: *mut WcAes, out: *mut u8, outSz: *mut u32) -> c_int;
    #[link_name = "wc_AesCtsDecryptFinal"]
    pub fn wc_AesCtsDecryptFinal(aes: *mut WcAes, out: *mut u8, outSz: *mut u32) -> c_int;
}

// ============================================================
// AES-EAX (wolfCrypt native, one-shot standalone functions)
// ============================================================

#[cfg(wolfssl_aes_eax)]
extern "C" {
    #[link_name = "wc_AesEaxEncryptAuth"]
    pub fn wc_AesEaxEncryptAuth(
        key: *const u8, keySz: u32,
        out: *mut u8, in_: *const u8, inSz: u32,
        nonce: *const u8, nonceSz: u32,
        authTag: *mut u8, authTagSz: u32,
        authIn: *const u8, authInSz: u32,
    ) -> c_int;
    #[link_name = "wc_AesEaxDecryptAuth"]
    pub fn wc_AesEaxDecryptAuth(
        key: *const u8, keySz: u32,
        out: *mut u8, in_: *const u8, inSz: u32,
        nonce: *const u8, nonceSz: u32,
        authTag: *const u8, authTagSz: u32,
        authIn: *const u8, authInSz: u32,
    ) -> c_int;
}

// ============================================================
// ECC (wolfCrypt native API)
// ============================================================

// ---- ECC curve ID constants (from wolfssl/wolfcrypt/ecc.h enum) ----

/// ECC_SECP256R1 curve ID (NIST P-256).
#[cfg(wolfssl_ecc)]
pub const ECC_SECP256R1: c_int = 7;
/// ECC_SECP384R1 curve ID (NIST P-384).
#[cfg(wolfssl_ecc)]
pub const ECC_SECP384R1: c_int = 15;
/// ECC_SECP521R1 curve ID (NIST P-521).
#[cfg(wolfssl_ecc)]
pub const ECC_SECP521R1: c_int = 16;
/// ECC_SECP256K1 curve ID (secp256k1 / Bitcoin curve).
#[cfg(wolfssl_ecc)]
pub const ECC_SECP256K1: c_int = 20;

#[cfg(wolfssl_ecc)]
extern "C" {
    #[link_name = "wc_ecc_key_new"]
    pub fn wc_ecc_key_new(heap: *mut c_void) -> *mut wc_ecc_key;
    #[link_name = "wc_ecc_key_free"]
    pub fn wc_ecc_key_free(key: *mut wc_ecc_key);
    #[link_name = "wc_ecc_init_ex"]
    pub fn wc_ecc_init_ex(key: *mut wc_ecc_key, heap: *mut c_void, devId: c_int) -> c_int;
    #[link_name = "wc_ecc_free"]
    pub fn wc_ecc_free(key: *mut wc_ecc_key) -> c_int;
    #[link_name = "wc_ecc_set_curve"]
    pub fn wc_ecc_set_curve(key: *mut wc_ecc_key, keySize: c_int, curveId: c_int) -> c_int;
    #[link_name = "wc_ecc_make_key_ex"]
    pub fn wc_ecc_make_key_ex(
        rng: *mut WC_RNG, keySize: c_int,
        key: *mut wc_ecc_key, curveId: c_int,
    ) -> c_int;
    #[link_name = "wc_ecc_shared_secret"]
    pub fn wc_ecc_shared_secret(
        privKey: *mut wc_ecc_key, pubKey: *mut wc_ecc_key,
        out: *mut u8, outSz: *mut u32,
    ) -> c_int;
    #[link_name = "wc_ecc_sign_hash"]
    pub fn wc_ecc_sign_hash(
        in_: *const u8, inSz: u32,
        out: *mut u8, outSz: *mut u32,
        rng: *mut WC_RNG, key: *mut wc_ecc_key,
    ) -> c_int;
    #[link_name = "wc_ecc_verify_hash"]
    pub fn wc_ecc_verify_hash(
        sig: *const u8, sigSz: u32,
        hash: *const u8, hashSz: u32,
        res: *mut c_int, key: *mut wc_ecc_key,
    ) -> c_int;
    #[link_name = "wc_ecc_export_x963"]
    pub fn wc_ecc_export_x963(key: *mut wc_ecc_key, out: *mut u8, outSz: *mut u32) -> c_int;
    #[link_name = "wc_ecc_import_x963"]
    pub fn wc_ecc_import_x963(in_: *const u8, inSz: u32, key: *mut wc_ecc_key) -> c_int;
    #[link_name = "wc_ecc_import_private_key"]
    pub fn wc_ecc_import_private_key(
        priv_: *const u8, privSz: u32,
        pub_: *const u8, pubSz: u32,
        key: *mut wc_ecc_key,
    ) -> c_int;
    #[link_name = "wc_ecc_import_private_key_ex"]
    pub fn wc_ecc_import_private_key_ex(
        priv_: *const u8, privSz: u32,
        pub_: *const u8, pubSz: u32,
        key: *mut wc_ecc_key,
        curve_id: c_int,
    ) -> c_int;
    #[link_name = "wc_ecc_export_private_only"]
    pub fn wc_ecc_export_private_only(key: *mut wc_ecc_key, out: *mut u8, outSz: *mut u32) -> c_int;
    #[link_name = "wc_ecc_check_key"]
    pub fn wc_ecc_check_key(key: *mut wc_ecc_key) -> c_int;
    #[link_name = "wc_ecc_get_curve_size_from_id"]
    pub fn wc_ecc_get_curve_size_from_id(curveId: c_int) -> c_int;

    /// Convert DER-encoded ECDSA signature to raw (r, s) byte arrays.
    #[link_name = "wc_ecc_sig_to_rs"]
    pub fn wc_ecc_sig_to_rs(
        sig: *const u8, sigLen: u32,
        r: *mut u8, rLen: *mut u32,
        s: *mut u8, sLen: *mut u32,
    ) -> c_int;

    /// Convert raw (r, s) byte arrays to DER-encoded ECDSA signature.
    #[link_name = "wc_ecc_rs_raw_to_sig"]
    pub fn wc_ecc_rs_raw_to_sig(
        r: *const u8, rSz: u32,
        s: *const u8, sSz: u32,
        out: *mut u8, outSz: *mut u32,
    ) -> c_int;
}

// ============================================================
// LMS/HSS (wolfCrypt native)
// ============================================================

/// Allocation size for wolfCrypt's `LmsKey` struct.
/// Verified by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_lms)]
pub const WC_LMS_KEY_ALLOC_SIZE: usize = 1024;

/// wolfCrypt LmsKey — sized to hold wolfSSL's `LmsKey` struct.
/// Size verified at compile time by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_lms)]
#[repr(C, align(16))]
pub struct WcLmsKey {
    _opaque: [u8; WC_LMS_KEY_ALLOC_SIZE],
}

#[cfg(wolfssl_lms)]
impl WcLmsKey {
    /// Create a zero-initialized `WcLmsKey`. Must be passed to
    /// `wc_LmsKey_Init` before use.
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_LMS_KEY_ALLOC_SIZE] }
    }
}

#[cfg(wolfssl_lms)]
extern "C" {
    #[link_name = "wc_LmsKey_Init"]
    pub fn wc_LmsKey_Init(key: *mut WcLmsKey, heap: *mut c_void, devId: c_int) -> c_int;
    #[link_name = "wc_LmsKey_SetParameters"]
    pub fn wc_LmsKey_SetParameters(
        key: *mut WcLmsKey, levels: c_int,
        height: c_int, winternitz: c_int,
    ) -> c_int;
    #[link_name = "wc_LmsKey_GetParameters"]
    pub fn wc_LmsKey_GetParameters(
        key: *const WcLmsKey, levels: *mut c_int,
        height: *mut c_int, winternitz: *mut c_int,
    ) -> c_int;
    #[link_name = "wc_LmsKey_MakeKey"]
    pub fn wc_LmsKey_MakeKey(key: *mut WcLmsKey, rng: *mut WC_RNG) -> c_int;
    #[link_name = "wc_LmsKey_Sign"]
    pub fn wc_LmsKey_Sign(
        key: *mut WcLmsKey, sig: *mut u8, sigSz: *mut u32,
        msg: *const u8, msgSz: c_int,
    ) -> c_int;
    #[link_name = "wc_LmsKey_Verify"]
    pub fn wc_LmsKey_Verify(
        key: *mut WcLmsKey, sig: *const u8, sigSz: u32,
        msg: *const u8, msgSz: c_int,
    ) -> c_int;
    #[link_name = "wc_LmsKey_Free"]
    pub fn wc_LmsKey_Free(key: *mut WcLmsKey);
    #[link_name = "wc_LmsKey_GetSigLen"]
    pub fn wc_LmsKey_GetSigLen(key: *const WcLmsKey, len: *mut u32) -> c_int;
    #[link_name = "wc_LmsKey_GetPubLen"]
    pub fn wc_LmsKey_GetPubLen(key: *const WcLmsKey, len: *mut u32) -> c_int;
    #[link_name = "wc_LmsKey_GetPrivLen"]
    pub fn wc_LmsKey_GetPrivLen(key: *const WcLmsKey, len: *mut u32) -> c_int;
    #[link_name = "wc_LmsKey_ExportPub"]
    pub fn wc_LmsKey_ExportPub(keyDst: *mut WcLmsKey, keySrc: *const WcLmsKey) -> c_int;
    #[link_name = "wc_LmsKey_ExportPubRaw"]
    pub fn wc_LmsKey_ExportPubRaw(
        key: *const WcLmsKey, out: *mut u8, outSz: *mut u32,
    ) -> c_int;
    #[link_name = "wc_LmsKey_ImportPubRaw"]
    pub fn wc_LmsKey_ImportPubRaw(
        key: *mut WcLmsKey, in_: *const u8, inLen: u32,
    ) -> c_int;

    /// Register callback for writing the private key to persistent storage.
    #[link_name = "wc_LmsKey_SetWriteCb"]
    pub fn wc_LmsKey_SetWriteCb(
        key: *mut WcLmsKey,
        write_cb: Option<unsafe extern "C" fn(priv_: *const u8, privSz: u32, context: *mut c_void) -> c_int>,
    ) -> c_int;

    /// Register callback for reading the private key from persistent storage.
    #[link_name = "wc_LmsKey_SetReadCb"]
    pub fn wc_LmsKey_SetReadCb(
        key: *mut WcLmsKey,
        read_cb: Option<unsafe extern "C" fn(priv_: *mut u8, privSz: u32, context: *mut c_void) -> c_int>,
    ) -> c_int;

    /// Set the opaque context pointer passed to read/write callbacks.
    #[link_name = "wc_LmsKey_SetContext"]
    pub fn wc_LmsKey_SetContext(key: *mut WcLmsKey, context: *mut c_void) -> c_int;

    /// Reload an LMS key from persistent storage (calls the read callback).
    #[link_name = "wc_LmsKey_Reload"]
    pub fn wc_LmsKey_Reload(key: *mut WcLmsKey) -> c_int;

    /// Return the number of signatures remaining for this key (0 = exhausted).
    #[link_name = "wc_LmsKey_SigsLeft"]
    pub fn wc_LmsKey_SigsLeft(key: *mut WcLmsKey) -> c_int;
}

// ============================================================
// KDF functions (wolfCrypt native, no structs)
// ============================================================

extern "C" {
    /// TLS PRF per wolfSSL's implementation.
    /// `hash` is a `wc_HashType` constant (e.g., `WC_HASH_TYPE_SHA256`).
    #[link_name = "wc_PRF"]
    pub fn wc_PRF(
        result: *mut u8, resLen: u32,
        secret: *const u8, secLen: u32,
        seed: *const u8, seedLen: u32,
        hash: c_int,
        heap: *mut c_void, devId: c_int,
    ) -> c_int;

    /// TLS 1.0/1.1 PRF (HMAC-MD5 + HMAC-SHA1 split).
    #[link_name = "wc_PRF_TLSv1"]
    pub fn wc_PRF_TLSv1(
        digest: *mut u8, digLen: u32,
        secret: *const u8, secLen: u32,
        label: *const u8, labLen: u32,
        seed: *const u8, seedLen: u32,
        heap: *mut c_void, devId: c_int,
    ) -> c_int;

    /// TLS 1.2 PRF.
    /// `useAtLeastSha256`: 1 to require SHA-256 minimum.
    /// `hash_type`: a `wc_HashType` constant.
    #[link_name = "wc_PRF_TLS"]
    pub fn wc_PRF_TLS(
        digest: *mut u8, digLen: u32,
        secret: *const u8, secLen: u32,
        label: *const u8, labLen: u32,
        seed: *const u8, seedLen: u32,
        useAtLeastSha256: c_int, hash_type: c_int,
        heap: *mut c_void, devId: c_int,
    ) -> c_int;

    /// SSH KDF per RFC 4253.
    /// `hashId`: WC_HASH_TYPE_* constant.
    /// `keyId`: single ASCII character identifying the key (e.g., b'A'..b'F').
    #[link_name = "wc_SSH_KDF"]
    pub fn wc_SSH_KDF(
        hashId: u8, keyId: u8,
        key: *mut u8, keySz: u32,
        k: *const u8, kSz: u32,
        h: *const u8, hSz: u32,
        sessionId: *const u8, sessionIdSz: u32,
    ) -> c_int;

    /// SRTP KDF per RFC 3711 §4.3.1.
    #[link_name = "wc_SRTP_KDF"]
    pub fn wc_SRTP_KDF(
        key: *const u8, keySz: u32,
        salt: *const u8, saltSz: u32,
        kdrIdx: c_int,
        idx: *const u8,
        key1: *mut u8, key1Sz: u32,
        key2: *mut u8, key2Sz: u32,
        key3: *mut u8, key3Sz: u32,
    ) -> c_int;

    /// PKCS#12 PBKDF per RFC 7292 appendix B.
    #[link_name = "wc_PKCS12_PBKDF"]
    pub fn wc_PKCS12_PBKDF(
        output: *mut u8, passwd: *const u8, passLen: c_int,
        salt: *const u8, saltLen: c_int, iterations: c_int,
        kLen: c_int, hashType: c_int, id: c_int,
    ) -> c_int;

    /// PKCS#12 PBKDF (extended, with heap parameter).
    #[link_name = "wc_PKCS12_PBKDF_ex"]
    pub fn wc_PKCS12_PBKDF_ex(
        output: *mut u8, passwd: *const u8, passLen: c_int,
        salt: *const u8, saltLen: c_int, iterations: c_int,
        kLen: c_int, hashType: c_int, id: c_int,
        heap: *mut c_void,
    ) -> c_int;
}

// ============================================================
// RSA (wolfCrypt native API)
// ============================================================

/// Opaque wolfCrypt RsaKey (internal, used for native wc_Rsa* functions).
/// Heap-allocated via `wc_NewRsaKey` / `wc_DeleteRsaKey`.
#[cfg(wolfssl_rsa)]
#[repr(C)]
pub struct RsaKey {
    _opaque: [u8; 0],
}

#[cfg(wolfssl_rsa)]
extern "C" {
    #[link_name = "wc_NewRsaKey"]
    pub fn wc_NewRsaKey(
        heap: *mut c_void, devId: c_int, result_code: *mut c_int,
    ) -> *mut RsaKey;
    #[link_name = "wc_DeleteRsaKey"]
    pub fn wc_DeleteRsaKey(key: *mut RsaKey, key_p: *mut *mut RsaKey) -> c_int;
    #[link_name = "wc_InitRsaKey"]
    pub fn wc_InitRsaKey(key: *mut RsaKey, heap: *mut c_void) -> c_int;
    #[link_name = "wc_InitRsaKey_ex"]
    pub fn wc_InitRsaKey_ex(key: *mut RsaKey, heap: *mut c_void, devId: c_int) -> c_int;
    #[link_name = "wc_FreeRsaKey"]
    pub fn wc_FreeRsaKey(key: *mut RsaKey) -> c_int;
    #[link_name = "wc_RsaFunction"]
    pub fn wc_RsaFunction(
        in_: *const u8, inLen: u32,
        out: *mut u8, outLen: *mut u32,
        type_: c_int, key: *mut RsaKey, rng: *mut WC_RNG,
    ) -> c_int;
    #[link_name = "wc_RsaPublicEncrypt"]
    pub fn wc_RsaPublicEncrypt(
        in_: *const u8, inLen: u32,
        out: *mut u8, outLen: u32,
        key: *mut RsaKey, rng: *mut WC_RNG,
    ) -> c_int;
    #[link_name = "wc_RsaPrivateDecrypt"]
    pub fn wc_RsaPrivateDecrypt(
        in_: *const u8, inLen: u32,
        out: *mut u8, outLen: u32,
        key: *mut RsaKey,
    ) -> c_int;
    #[link_name = "wc_RsaSSL_Sign"]
    pub fn wc_RsaSSL_Sign(
        in_: *const u8, inLen: u32,
        out: *mut u8, outLen: u32,
        key: *mut RsaKey, rng: *mut WC_RNG,
    ) -> c_int;
    #[link_name = "wc_RsaSSL_Verify"]
    pub fn wc_RsaSSL_Verify(
        in_: *const u8, inLen: u32,
        out: *mut u8, outLen: u32,
        key: *mut RsaKey,
    ) -> c_int;
    #[link_name = "wc_RsaEncryptSize"]
    pub fn wc_RsaEncryptSize(key: *const RsaKey) -> c_int;
    #[link_name = "wc_RsaPrivateKeyDecode"]
    pub fn wc_RsaPrivateKeyDecode(
        input: *const u8, inOutIdx: *mut u32,
        key: *mut RsaKey, inSz: u32,
    ) -> c_int;
    #[link_name = "wc_RsaPublicKeyDecode"]
    pub fn wc_RsaPublicKeyDecode(
        input: *const u8, inOutIdx: *mut u32,
        key: *mut RsaKey, inSz: u32,
    ) -> c_int;
    #[link_name = "wc_CheckRsaKey"]
    pub fn wc_CheckRsaKey(key: *mut RsaKey) -> c_int;
    #[link_name = "wc_MakeRsaKey"]
    pub fn wc_MakeRsaKey(key: *mut RsaKey, size: c_int, e: core::ffi::c_long, rng: *mut WC_RNG) -> c_int;
    #[link_name = "wc_RsaSetRNG"]
    pub fn wc_RsaSetRNG(key: *mut RsaKey, rng: *mut WC_RNG) -> c_int;

    /// Export an RSA private key to PKCS#1 DER format.
    /// Returns the number of bytes written, or negative on error.
    #[link_name = "wc_RsaKeyToDer"]
    pub fn wc_RsaKeyToDer(key: *mut RsaKey, output: *mut u8, inLen: u32) -> c_int;

    /// Import an RSA private key from raw component byte arrays.
    /// `dP` and `dQ` may be NULL with size 0 — wolfCrypt will compute them.
    /// `u` is the CRT coefficient (iqmp), required when WOLFSSL_KEY_GEN or OPENSSL_EXTRA.
    #[link_name = "wc_RsaPrivateKeyDecodeRaw"]
    pub fn wc_RsaPrivateKeyDecodeRaw(
        n: *const u8, nSz: u32,
        e: *const u8, eSz: u32,
        d: *const u8, dSz: u32,
        u: *const u8, uSz: u32,
        p: *const u8, pSz: u32,
        q: *const u8, qSz: u32,
        dP: *const u8, dPSz: u32,
        dQ: *const u8, dQSz: u32,
        key: *mut RsaKey,
    ) -> c_int;

    /// Export RSA key components (e, n, d, p, q) from an initialized RsaKey.
    ///
    /// Each output buffer must be pre-allocated; the corresponding `*Sz`
    /// parameter is both input (buffer capacity) and output (bytes written).
    #[link_name = "wc_RsaExportKey"]
    pub fn wc_RsaExportKey(
        key: *mut RsaKey,
        e: *mut u8, eSz: *mut u32,
        n: *mut u8, nSz: *mut u32,
        d: *mut u8, dSz: *mut u32,
        p: *mut u8, pSz: *mut u32,
        q: *mut u8, qSz: *mut u32,
    ) -> c_int;

    /// Export just the public components (e, n) from an initialized RsaKey.
    #[link_name = "wc_RsaFlattenPublicKey"]
    pub fn wc_RsaFlattenPublicKey(
        key: *mut RsaKey,
        e: *mut u8, eSz: *mut u32,
        n: *mut u8, nSz: *mut u32,
    ) -> c_int;
}

// ============================================================
// Crypto Callbacks (WOLF_CRYPTO_CB)
// ============================================================

/// Return value indicating the callback does not handle this operation.
/// wolfCrypt will fall back to the software implementation.
#[cfg(wolfssl_cryptocb)]
pub const CRYPTOCB_UNAVAILABLE: c_int = -271;

/// Opaque `wc_CryptoInfo` struct — passed to crypto callbacks.
/// This is a large C union; we treat it as opaque and provide
/// accessor shims in compat_shim.c for the fields Rust needs.
#[cfg(wolfssl_cryptocb)]
#[repr(C)]
pub struct wc_CryptoInfo {
    _opaque: [u8; 0],
}

/// Algorithm type constants from `enum wc_AlgoType`.
#[cfg(wolfssl_cryptocb)]
pub const WC_ALGO_TYPE_NONE: c_int = 0;
#[cfg(wolfssl_cryptocb)]
pub const WC_ALGO_TYPE_HASH: c_int = 1;
#[cfg(wolfssl_cryptocb)]
pub const WC_ALGO_TYPE_CIPHER: c_int = 2;
#[cfg(wolfssl_cryptocb)]
pub const WC_ALGO_TYPE_PK: c_int = 3;
#[cfg(wolfssl_cryptocb)]
pub const WC_ALGO_TYPE_RNG: c_int = 4;
#[cfg(wolfssl_cryptocb)]
pub const WC_ALGO_TYPE_SEED: c_int = 5;
#[cfg(wolfssl_cryptocb)]
pub const WC_ALGO_TYPE_HMAC: c_int = 6;
#[cfg(wolfssl_cryptocb)]
pub const WC_ALGO_TYPE_CMAC: c_int = 7;

/// Cipher type constants from `enum wc_CipherType`.
#[cfg(wolfssl_cryptocb)]
pub const WC_CIPHER_AES_CBC: c_int = 2;
#[cfg(wolfssl_cryptocb)]
pub const WC_CIPHER_AES_GCM: c_int = 3;
#[cfg(wolfssl_cryptocb)]
pub const WC_CIPHER_AES_CTR: c_int = 4;
#[cfg(wolfssl_cryptocb)]
pub const WC_CIPHER_AES_CCM: c_int = 12;
#[cfg(wolfssl_cryptocb)]
pub const WC_CIPHER_AES_ECB: c_int = 13;

/// PK type constants from `enum wc_PkType`.
#[cfg(wolfssl_cryptocb)]
pub const WC_PK_TYPE_RSA: c_int = 0;
#[cfg(wolfssl_cryptocb)]
pub const WC_PK_TYPE_EC_KEYGEN: c_int = 5;
#[cfg(wolfssl_cryptocb)]
pub const WC_PK_TYPE_ECDH: c_int = 6;
#[cfg(wolfssl_cryptocb)]
pub const WC_PK_TYPE_ECDSA_SIGN: c_int = 7;
#[cfg(wolfssl_cryptocb)]
pub const WC_PK_TYPE_ECDSA_VERIFY: c_int = 8;
#[cfg(wolfssl_cryptocb)]
pub const WC_PK_TYPE_ED25519_SIGN: c_int = 12;
#[cfg(wolfssl_cryptocb)]
pub const WC_PK_TYPE_ED25519_VERIFY: c_int = 13;

#[cfg(wolfssl_cryptocb)]
extern "C" {
    /// Register a crypto callback for a given device ID.
    ///
    /// `devId` must not be `INVALID_DEVID`. `cb` is the C callback function.
    /// `ctx` is an opaque user context passed to every callback invocation.
    #[link_name = "wc_CryptoCb_RegisterDevice"]
    pub fn wc_CryptoCb_RegisterDevice(
        devId: c_int,
        cb: Option<unsafe extern "C" fn(devId: c_int, info: *mut wc_CryptoInfo, ctx: *mut c_void) -> c_int>,
        ctx: *mut c_void,
    ) -> c_int;

    /// Unregister a crypto callback for a device ID.
    #[link_name = "wc_CryptoCb_UnRegisterDevice"]
    pub fn wc_CryptoCb_UnRegisterDevice(devId: c_int);

    // Accessor shims for wc_CryptoInfo fields (defined in compat_shim.c)

    /// Get the algorithm type from a wc_CryptoInfo struct.
    pub fn wolfcrypt_cryptocb_info_get_algo_type(info: *const wc_CryptoInfo) -> c_int;

    // RNG accessors
    pub fn wolfcrypt_cryptocb_info_rng_out(info: *const wc_CryptoInfo) -> *mut u8;
    pub fn wolfcrypt_cryptocb_info_rng_sz(info: *const wc_CryptoInfo) -> u32;

    // Hash accessors
    pub fn wolfcrypt_cryptocb_info_hash_type(info: *const wc_CryptoInfo) -> c_int;
    pub fn wolfcrypt_cryptocb_info_hash_in(info: *const wc_CryptoInfo) -> *const u8;
    pub fn wolfcrypt_cryptocb_info_hash_in_sz(info: *const wc_CryptoInfo) -> u32;
    pub fn wolfcrypt_cryptocb_info_hash_digest(info: *const wc_CryptoInfo) -> *mut u8;

    // HMAC accessors
    pub fn wolfcrypt_cryptocb_info_hmac_mac_type(info: *const wc_CryptoInfo) -> c_int;
    pub fn wolfcrypt_cryptocb_info_hmac_in(info: *const wc_CryptoInfo) -> *const u8;
    pub fn wolfcrypt_cryptocb_info_hmac_in_sz(info: *const wc_CryptoInfo) -> u32;
    pub fn wolfcrypt_cryptocb_info_hmac_digest(info: *const wc_CryptoInfo) -> *mut u8;

    // Cipher accessors
    pub fn wolfcrypt_cryptocb_info_cipher_type(info: *const wc_CryptoInfo) -> c_int;
    pub fn wolfcrypt_cryptocb_info_cipher_enc(info: *const wc_CryptoInfo) -> c_int;

    // PK (public key) accessors
    pub fn wolfcrypt_cryptocb_info_pk_type(info: *const wc_CryptoInfo) -> c_int;
}

// ============================================================
// HPKE (Hybrid Public Key Encryption, RFC 9180)
// ============================================================

/// Allocation size for wolfCrypt's `Hpke` struct.
/// Verified by `_Static_assert` in compat_shim.c.
#[cfg(wolfssl_hpke)]
pub const WC_HPKE_ALLOC_SIZE: usize = 128;

/// Allocation size for wolfCrypt's `HpkeBaseContext` struct.
#[cfg(wolfssl_hpke)]
pub const WC_HPKE_BASE_CONTEXT_ALLOC_SIZE: usize = 128;

/// wolfCrypt Hpke context.
#[cfg(wolfssl_hpke)]
#[repr(C, align(8))]
pub struct WcHpke {
    _opaque: [u8; WC_HPKE_ALLOC_SIZE],
}

#[cfg(wolfssl_hpke)]
impl WcHpke {
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_HPKE_ALLOC_SIZE] }
    }
}

/// wolfCrypt HpkeBaseContext (encryption/decryption state).
#[cfg(wolfssl_hpke)]
#[repr(C, align(4))]
pub struct WcHpkeBaseContext {
    _opaque: [u8; WC_HPKE_BASE_CONTEXT_ALLOC_SIZE],
}

#[cfg(wolfssl_hpke)]
impl WcHpkeBaseContext {
    pub const fn zeroed() -> Self {
        Self { _opaque: [0u8; WC_HPKE_BASE_CONTEXT_ALLOC_SIZE] }
    }
}

// HPKE KEM identifiers (RFC 9180 §7.1)
#[cfg(wolfssl_hpke)]
pub const DHKEM_P256_HKDF_SHA256: c_int = 0x0010;
#[cfg(wolfssl_hpke)]
pub const DHKEM_P384_HKDF_SHA384: c_int = 0x0011;
#[cfg(wolfssl_hpke)]
pub const DHKEM_P521_HKDF_SHA512: c_int = 0x0012;
#[cfg(wolfssl_hpke)]
pub const DHKEM_X25519_HKDF_SHA256: c_int = 0x0020;
#[cfg(wolfssl_hpke)]
pub const DHKEM_X448_HKDF_SHA512: c_int = 0x0021;

// HPKE KDF identifiers (RFC 9180 §7.2)
#[cfg(wolfssl_hpke)]
pub const HPKE_HKDF_SHA256: c_int = 0x0001;
#[cfg(wolfssl_hpke)]
pub const HPKE_HKDF_SHA384: c_int = 0x0002;
#[cfg(wolfssl_hpke)]
pub const HPKE_HKDF_SHA512: c_int = 0x0003;

// HPKE AEAD identifiers (RFC 9180 §7.3)
#[cfg(wolfssl_hpke)]
pub const HPKE_AES_128_GCM: c_int = 0x0001;
#[cfg(wolfssl_hpke)]
pub const HPKE_AES_256_GCM: c_int = 0x0002;

// HPKE encapsulated-key sizes per KEM
#[cfg(wolfssl_hpke)]
pub const DHKEM_P256_ENC_LEN: usize = 65;
#[cfg(wolfssl_hpke)]
pub const DHKEM_P384_ENC_LEN: usize = 97;
#[cfg(wolfssl_hpke)]
pub const DHKEM_P521_ENC_LEN: usize = 133;
#[cfg(wolfssl_hpke)]
pub const DHKEM_X25519_ENC_LEN: usize = 32;
#[cfg(wolfssl_hpke)]
pub const DHKEM_X448_ENC_LEN: usize = 56;

// HPKE max sizes
#[cfg(wolfssl_hpke)]
pub const HPKE_Npk_MAX: usize = 133;
#[cfg(wolfssl_hpke)]
pub const HPKE_Nt_MAX: usize = 16;

#[cfg(wolfssl_hpke)]
extern "C" {
    /// Initialize an HPKE context with the given suite.
    #[link_name = "wc_HpkeInit"]
    pub fn wc_HpkeInit(
        hpke: *mut WcHpke, kem: c_int, kdf: c_int, aead: c_int, heap: *mut c_void,
    ) -> c_int;

    /// Generate a KEM key pair.
    #[link_name = "wc_HpkeGenerateKeyPair"]
    pub fn wc_HpkeGenerateKeyPair(
        hpke: *mut WcHpke, keypair: *mut *mut c_void, rng: *mut WC_RNG,
    ) -> c_int;

    /// Serialize a public key to bytes.
    #[link_name = "wc_HpkeSerializePublicKey"]
    pub fn wc_HpkeSerializePublicKey(
        hpke: *mut WcHpke, key: *mut c_void, out: *mut u8, outSz: *mut u16,
    ) -> c_int;

    /// Deserialize a public key from bytes.
    #[link_name = "wc_HpkeDeserializePublicKey"]
    pub fn wc_HpkeDeserializePublicKey(
        hpke: *mut WcHpke, key: *mut *mut c_void, in_: *const u8, inSz: u16,
    ) -> c_int;

    /// Free a KEM key pair.
    #[link_name = "wc_HpkeFreeKey"]
    pub fn wc_HpkeFreeKey(
        hpke: *mut WcHpke, kem: u16, keypair: *mut c_void, heap: *mut c_void,
    );

    /// One-shot HPKE Base-mode seal (encrypt).
    /// `ciphertext` output is plaintext_len + tag_len bytes.
    #[link_name = "wc_HpkeSealBase"]
    pub fn wc_HpkeSealBase(
        hpke: *mut WcHpke, ephemeralKey: *mut c_void, receiverKey: *mut c_void,
        info: *mut u8, infoSz: u32,
        aad: *mut u8, aadSz: u32,
        plaintext: *mut u8, ptSz: u32,
        ciphertext: *mut u8,
    ) -> c_int;

    /// One-shot HPKE Base-mode open (decrypt).
    #[link_name = "wc_HpkeOpenBase"]
    pub fn wc_HpkeOpenBase(
        hpke: *mut WcHpke, receiverKey: *mut c_void,
        pubKey: *const u8, pubKeySz: u16,
        info: *mut u8, infoSz: u32,
        aad: *mut u8, aadSz: u32,
        ciphertext: *mut u8, ctSz: u32,
        plaintext: *mut u8,
    ) -> c_int;

    /// Initialize a seal (encryption) context for multi-message use.
    #[link_name = "wc_HpkeInitSealContext"]
    pub fn wc_HpkeInitSealContext(
        hpke: *mut WcHpke, context: *mut WcHpkeBaseContext,
        ephemeralKey: *mut c_void, receiverKey: *mut c_void,
        info: *mut u8, infoSz: u32,
    ) -> c_int;

    /// Encrypt one message using a seal context.
    #[link_name = "wc_HpkeContextSealBase"]
    pub fn wc_HpkeContextSealBase(
        hpke: *mut WcHpke, context: *mut WcHpkeBaseContext,
        aad: *mut u8, aadSz: u32,
        plaintext: *mut u8, ptSz: u32,
        out: *mut u8,
    ) -> c_int;

    /// Initialize an open (decryption) context for multi-message use.
    #[link_name = "wc_HpkeInitOpenContext"]
    pub fn wc_HpkeInitOpenContext(
        hpke: *mut WcHpke, context: *mut WcHpkeBaseContext,
        receiverKey: *mut c_void,
        pubKey: *const u8, pubKeySz: u16,
        info: *mut u8, infoSz: u32,
    ) -> c_int;

    /// Decrypt one message using an open context.
    #[link_name = "wc_HpkeContextOpenBase"]
    pub fn wc_HpkeContextOpenBase(
        hpke: *mut WcHpke, context: *mut WcHpkeBaseContext,
        aad: *mut u8, aadSz: u32,
        ciphertext: *mut u8, ctSz: u32,
        out: *mut u8,
    ) -> c_int;
}

// ================================================================
// Tests
// ================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify our `wc_oid_sum` const fn produces the same values as wolfSSL's
    /// `ECC_*_OID` constants from `wolfssl/wolfcrypt/oid_sum.h` (new algorithm,
    /// i.e. `WOLFSSL_OLD_OID_SUM` is NOT defined).
    ///
    /// These expected values are independently sourced from wolfSSL's oid_sum.h.
    /// The _Static_asserts in compat_shim.c also verify these against the C
    /// constants at compile time, but this Rust-side test catches regressions
    /// even if the C asserts are accidentally guarded away.
    #[test]
    fn wc_oid_sum_matches_wolfssl_oid_constants() {
        // ED25519: OID 1.3.101.112 → DER {0x2b, 0x65, 0x70}
        // wolfSSL: ECC_ED25519_OID = 0x7f8f65d4
        assert_eq!(wc_oid_sum(&[0x2b, 0x65, 0x70]), 0x7f8f_65d4);

        // X25519: OID 1.3.101.110 → DER {0x2b, 0x65, 0x6e}
        // wolfSSL: ECC_X25519_OID = 0x7f9165d4
        assert_eq!(wc_oid_sum(&[0x2b, 0x65, 0x6e]), 0x7f91_65d4);

        // ED448: OID 1.3.101.113 → DER {0x2b, 0x65, 0x71}
        // wolfSSL: ECC_ED448_OID = 0x7f8e65d4
        assert_eq!(wc_oid_sum(&[0x2b, 0x65, 0x71]), 0x7f8e_65d4);

        // X448: OID 1.3.101.111 → DER {0x2b, 0x65, 0x6f}
        // wolfSSL: ECC_X448_OID = 0x7f9065d4
        assert_eq!(wc_oid_sum(&[0x2b, 0x65, 0x6f]), 0x7f90_65d4);
    }

    /// Verify that the NID constants computed by wc_oid_sum (and cast to c_int)
    /// match the expected values. This catches any issue with the u32→c_int cast.
    #[test]
    fn nid_constants_have_expected_values() {
        // The u32 values from wc_oid_sum are > i32::MAX, so the `as c_int` cast
        // wraps to negative on platforms where c_int is i32. Verify the actual
        // constant values match what wolfSSL uses.
        assert_eq!(NID_ED25519, 0x7f8f_65d4_u32 as core::ffi::c_int);
        assert_eq!(NID_X25519, 0x7f91_65d4_u32 as core::ffi::c_int);
        assert_eq!(NID_ED448, 0x7f8e_65d4_u32 as core::ffi::c_int);
        assert_eq!(NID_X448, 0x7f90_65d4_u32 as core::ffi::c_int);
    }

    /// Sanity: different OIDs must produce different sums.
    #[test]
    fn wc_oid_sum_distinct_for_different_oids() {
        let ed25519 = wc_oid_sum(&[0x2b, 0x65, 0x70]);
        let x25519 = wc_oid_sum(&[0x2b, 0x65, 0x6e]);
        let ed448 = wc_oid_sum(&[0x2b, 0x65, 0x71]);
        let x448 = wc_oid_sum(&[0x2b, 0x65, 0x6f]);

        assert_ne!(ed25519, x25519);
        assert_ne!(ed25519, ed448);
        assert_ne!(ed25519, x448);
        assert_ne!(x25519, ed448);
        assert_ne!(x25519, x448);
        assert_ne!(ed448, x448);
    }

    /// Empty OID produces zero.
    #[test]
    fn wc_oid_sum_empty_input() {
        assert_eq!(wc_oid_sum(&[]), 0);
    }
}

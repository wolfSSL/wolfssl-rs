//! Elliptic-Curve Diffie-Hellman key agreement (X25519 and X448).
//!
//! Provides [`X25519StaticSecret`], [`X25519PublicKey`], and [`SharedSecret`]
//! types backed by wolfCrypt's native Curve25519 implementation (RFC 7748).
//!
//! When the `wolfssl_curve448` cfg is active, also provides [`X448StaticSecret`],
//! [`X448PublicKey`], and [`X448SharedSecret`] backed by wolfCrypt's Curve448
//! implementation (RFC 7748).

use wolfcrypt_rs::{
    wc_curve25519_export_key_raw_ex, wc_curve25519_free, wc_curve25519_import_private_raw_ex,
    wc_curve25519_import_public_ex, wc_curve25519_init, wc_curve25519_key,
    wc_curve25519_make_key, wc_curve25519_make_pub, wc_curve25519_set_rng,
    wc_curve25519_shared_secret_ex, wc_FreeRng, wc_InitRng, EC25519_LITTLE_ENDIAN, WC_RNG,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const KEY_LEN: usize = 32;

/// Apply the X25519 scalar clamping from RFC 7748 Section 5.
///
/// wolfSSL expects keys to be pre-clamped when calling `wc_curve25519_make_pub`
/// and stores the clamped form in the key struct.
fn clamp(scalar: &mut [u8; KEY_LEN]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// An X25519 static secret (private key).
///
/// Contains a fully-initialized wolfCrypt `curve25519_key` with both
/// private and public components.
pub struct X25519StaticSecret {
    key: wc_curve25519_key,
}

/// An X25519 public key (the u-coordinate on Curve25519).
pub struct X25519PublicKey {
    bytes: [u8; KEY_LEN],
}

/// The shared secret resulting from an X25519 Diffie-Hellman exchange.
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret(#[zeroize(drop)] [u8; KEY_LEN]);

// ---------------------------------------------------------------------------
// X25519StaticSecret
// ---------------------------------------------------------------------------

impl X25519StaticSecret {
    /// Import a private key from raw bytes and derive the corresponding
    /// public key.
    ///
    /// The bytes are interpreted in little-endian order per RFC 7748.
    pub fn from_bytes(private: &[u8; KEY_LEN]) -> Self {
        let mut key = wc_curve25519_key::zeroed();

        // SAFETY: `key` is zero-initialized; `wc_curve25519_init` will
        // fully initialize the struct. Pointer is valid for the call.
        let rc = unsafe { wc_curve25519_init(&mut key) };
        assert_eq!(rc, 0, "wc_curve25519_init failed (OOM)");

        // Clamp the private scalar per RFC 7748 Section 5.
        // wolfSSL requires clamped keys for `wc_curve25519_make_pub`.
        let mut clamped = *private;
        clamp(&mut clamped);

        // Derive the public key from the clamped private key.
        let mut pub_bytes = [0u8; KEY_LEN];

        // SAFETY: `wc_curve25519_make_pub` derives a public key from
        // the given private key bytes. Both buffers are KEY_LEN and valid.
        let rc = unsafe {
            wc_curve25519_make_pub(
                KEY_LEN as i32,
                pub_bytes.as_mut_ptr(),
                KEY_LEN as i32,
                clamped.as_ptr(),
            )
        };
        assert_eq!(rc, 0, "wc_curve25519_make_pub failed (invalid private key)");

        // Import both clamped private and derived public into the key struct.
        // SAFETY: `key` is initialized, both slices are KEY_LEN bytes,
        // and we use little-endian encoding per RFC 7748.
        let rc = unsafe {
            wc_curve25519_import_private_raw_ex(
                clamped.as_ptr(),
                KEY_LEN as u32,
                pub_bytes.as_ptr(),
                KEY_LEN as u32,
                &mut key,
                EC25519_LITTLE_ENDIAN,
            )
        };
        assert_eq!(rc, 0, "wc_curve25519_import_private_raw_ex failed (invalid key bytes)");

        clamped.zeroize();

        Self { key }
    }

    /// Generate a random X25519 keypair using the provided RNG.
    #[cfg(feature = "rand")]
    pub fn random(rng: &mut crate::rand::WolfRng) -> Self {
        let mut key = wc_curve25519_key::zeroed();

        // SAFETY: `key` is zero-initialized; `wc_curve25519_init` will
        // fully initialize the struct.
        let rc = unsafe { wc_curve25519_init(&mut key) };
        assert_eq!(rc, 0, "wc_curve25519_init failed (OOM)");

        // SAFETY: `key` is initialized, `rng.rng` is an initialized WC_RNG.
        // wolfCrypt generates a full 32-byte keypair.
        let rc = unsafe {
            wc_curve25519_make_key(&mut rng.rng, KEY_LEN as i32, &mut key)
        };
        assert_eq!(rc, 0, "wc_curve25519_make_key failed (RNG failure)");

        Self { key }
    }

    /// Derive the public key corresponding to this secret.
    pub fn public_key(&self) -> X25519PublicKey {
        let mut priv_bytes = [0u8; KEY_LEN];
        let mut pub_bytes = [0u8; KEY_LEN];
        let mut priv_sz = KEY_LEN as u32;
        let mut pub_sz = KEY_LEN as u32;

        // SAFETY: `self.key` is a fully-initialized curve25519_key.
        // The output buffers and their size pointers are valid.
        // We cast away const because the FFI signature requires `*mut`
        // but `export_key_raw_ex` does not mutate the key.
        let rc = unsafe {
            wc_curve25519_export_key_raw_ex(
                &self.key as *const wc_curve25519_key as *mut wc_curve25519_key,
                priv_bytes.as_mut_ptr(),
                &mut priv_sz,
                pub_bytes.as_mut_ptr(),
                &mut pub_sz,
                EC25519_LITTLE_ENDIAN,
            )
        };
        assert_eq!(rc, 0, "wc_curve25519_export_key_raw_ex failed (buffer too small)");

        // Zeroize private bytes — we only need the public portion.
        priv_bytes.zeroize();

        X25519PublicKey { bytes: pub_bytes }
    }

    /// Perform X25519 Diffie-Hellman with the given peer public key.
    ///
    /// Consumes `self` so the private key is freed after use.
    pub fn diffie_hellman(mut self, peer_public: &X25519PublicKey) -> SharedSecret {
        // wolfSSL enables Curve25519 blinding by default, which requires
        // an RNG attached to the private key for scalar multiplication.
        // Create a temporary RNG for this operation.
        let mut rng = WC_RNG::zeroed();

        // SAFETY: `rng` is zero-initialized; `wc_InitRng` initialises it.
        let rc = unsafe { wc_InitRng(&mut rng) };
        assert_eq!(rc, 0, "wc_InitRng failed (entropy source unavailable)");

        // SAFETY: `self.key` is initialized, `rng` is initialized.
        // This sets the RNG pointer inside the key struct for blinding.
        let rc = unsafe { wc_curve25519_set_rng(&mut self.key, &mut rng) };
        assert_eq!(rc, 0, "wc_curve25519_set_rng failed (null RNG)");

        // Build a temporary key struct holding the peer's public key.
        let mut peer_key = wc_curve25519_key::zeroed();

        // SAFETY: `peer_key` is zero-initialized; init will set it up.
        let rc = unsafe { wc_curve25519_init(&mut peer_key) };
        assert_eq!(rc, 0, "wc_curve25519_init (peer) failed (OOM)");

        // SAFETY: `peer_key` is initialized, peer bytes are KEY_LEN.
        let rc = unsafe {
            wc_curve25519_import_public_ex(
                peer_public.bytes.as_ptr(),
                KEY_LEN as u32,
                &mut peer_key,
                EC25519_LITTLE_ENDIAN,
            )
        };
        assert_eq!(rc, 0, "wc_curve25519_import_public_ex failed (invalid public key)");

        let mut out = [0u8; KEY_LEN];
        let mut out_len = KEY_LEN as u32;

        // SAFETY: Both keys are fully-initialized curve25519_key structs.
        // `out` is KEY_LEN bytes and `out_len` reflects its capacity.
        // The private key has an RNG set for blinding.
        let rc = unsafe {
            wc_curve25519_shared_secret_ex(
                &mut self.key,
                &mut peer_key,
                out.as_mut_ptr(),
                &mut out_len,
                EC25519_LITTLE_ENDIAN,
            )
        };
        assert_eq!(rc, 0, "wc_curve25519_shared_secret_ex failed (invalid key or buffer)");

        // SAFETY: `peer_key` and `rng` were initialized; free them now.
        unsafe {
            wc_curve25519_free(&mut peer_key);
            wc_FreeRng(&mut rng);
        }

        SharedSecret(out)
    }
}

impl Drop for X25519StaticSecret {
    fn drop(&mut self) {
        // SAFETY: `self.key` was initialized by `wc_curve25519_init` in
        // all constructors. Freed exactly once here.
        unsafe { wc_curve25519_free(&mut self.key) };
    }
}

// SAFETY: `wc_curve25519_key` owns its own memory with no shared
// mutable globals; safe to move between threads.
unsafe impl Send for X25519StaticSecret {}

// ---------------------------------------------------------------------------
// X25519PublicKey
// ---------------------------------------------------------------------------

impl X25519PublicKey {
    /// Construct a public key from raw 32-byte u-coordinate.
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        Self { bytes: *bytes }
    }

    /// Return the raw 32-byte u-coordinate.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl From<[u8; KEY_LEN]> for X25519PublicKey {
    fn from(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }
}

// SAFETY: Plain byte array, no interior mutability.
unsafe impl Send for X25519PublicKey {}
unsafe impl Sync for X25519PublicKey {}

// ---------------------------------------------------------------------------
// SharedSecret
// ---------------------------------------------------------------------------

impl SharedSecret {
    /// Return the raw 32-byte shared secret.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

// ===========================================================================
// X448 Elliptic-Curve Diffie-Hellman (RFC 7748)
// ===========================================================================

#[cfg(wolfssl_curve448)]
use wolfcrypt_rs::{
    wc_curve448_export_key_raw_ex, wc_curve448_free,
    wc_curve448_import_private_raw_ex,
    wc_curve448_import_public_ex, wc_curve448_init, wc_curve448_key,
    wc_curve448_make_key, wc_curve448_make_pub,
    wc_curve448_shared_secret_ex, EC448_LITTLE_ENDIAN,
};

#[cfg(wolfssl_curve448)]
const X448_KEY_LEN: usize = 56;

/// An X448 static secret (private key).
///
/// Contains a fully-initialized wolfCrypt `curve448_key` with both
/// private and public components.
#[cfg(wolfssl_curve448)]
pub struct X448StaticSecret {
    key: wc_curve448_key,
}

/// An X448 public key (the u-coordinate on Curve448).
#[cfg(wolfssl_curve448)]
pub struct X448PublicKey {
    bytes: [u8; X448_KEY_LEN],
}

/// The shared secret resulting from an X448 Diffie-Hellman exchange.
#[cfg(wolfssl_curve448)]
#[derive(ZeroizeOnDrop)]
pub struct X448SharedSecret(#[zeroize(drop)] [u8; X448_KEY_LEN]);

// ---------------------------------------------------------------------------
// X448StaticSecret
// ---------------------------------------------------------------------------

#[cfg(wolfssl_curve448)]
impl X448StaticSecret {
    /// Import a private key from raw bytes and derive the corresponding
    /// public key.
    ///
    /// The bytes are interpreted in little-endian order per RFC 7748.
    pub fn from_bytes(private: &[u8; X448_KEY_LEN]) -> Self {
        let mut key = wc_curve448_key::zeroed();

        // SAFETY: `key` is zero-initialized; `wc_curve448_init` will
        // fully initialize the struct. Pointer is valid for the call.
        let rc = unsafe { wc_curve448_init(&mut key) };
        assert_eq!(rc, 0, "wc_curve448_init failed (OOM)");

        // Clamp the private scalar per RFC 7748 Section 5:
        //   k[0]  &= 252   (clear two least-significant bits)
        //   k[55] |= 128   (set most-significant bit)
        let mut clamped = *private;
        clamped[0] &= 252;
        clamped[55] |= 128;

        // Derive the public key from the clamped private key.
        let mut pub_bytes = [0u8; X448_KEY_LEN];

        // SAFETY: `wc_curve448_make_pub` derives a public key from
        // the given private key bytes. Both buffers are X448_KEY_LEN.
        let rc = unsafe {
            wc_curve448_make_pub(
                X448_KEY_LEN as i32,
                pub_bytes.as_mut_ptr(),
                X448_KEY_LEN as i32,
                clamped.as_ptr(),
            )
        };
        assert_eq!(rc, 0, "wc_curve448_make_pub failed (invalid private key)");

        // Import both clamped private and derived public into the key struct.
        // SAFETY: `key` is initialized, both slices are X448_KEY_LEN bytes,
        // and we use little-endian encoding per RFC 7748.
        let rc = unsafe {
            wc_curve448_import_private_raw_ex(
                clamped.as_ptr(),
                X448_KEY_LEN as u32,
                pub_bytes.as_ptr(),
                X448_KEY_LEN as u32,
                &mut key,
                EC448_LITTLE_ENDIAN,
            )
        };
        assert_eq!(rc, 0, "wc_curve448_import_private_raw_ex failed (invalid key bytes)");

        clamped.zeroize();

        Self { key }
    }

    /// Generate a random X448 keypair using the provided RNG.
    #[cfg(feature = "rand")]
    pub fn random(rng: &mut crate::rand::WolfRng) -> Self {
        let mut key = wc_curve448_key::zeroed();

        // SAFETY: `key` is zero-initialized; `wc_curve448_init` will
        // fully initialize the struct.
        let rc = unsafe { wc_curve448_init(&mut key) };
        assert_eq!(rc, 0, "wc_curve448_init failed (OOM)");

        // SAFETY: `key` is initialized, `rng.rng` is an initialized WC_RNG.
        // wolfCrypt generates a full 56-byte keypair.
        let rc = unsafe {
            wc_curve448_make_key(&mut rng.rng, X448_KEY_LEN as i32, &mut key)
        };
        assert_eq!(rc, 0, "wc_curve448_make_key failed (RNG failure)");

        Self { key }
    }

    /// Derive the public key corresponding to this secret.
    pub fn public_key(&self) -> X448PublicKey {
        let mut priv_bytes = [0u8; X448_KEY_LEN];
        let mut pub_bytes = [0u8; X448_KEY_LEN];
        let mut priv_sz = X448_KEY_LEN as u32;
        let mut pub_sz = X448_KEY_LEN as u32;

        // SAFETY: `self.key` is a fully-initialized curve448_key.
        // The output buffers and their size pointers are valid.
        // We cast away const because the FFI signature requires `*mut`
        // but `export_key_raw_ex` does not mutate the key.
        let rc = unsafe {
            wc_curve448_export_key_raw_ex(
                &self.key as *const wc_curve448_key as *mut wc_curve448_key,
                priv_bytes.as_mut_ptr(),
                &mut priv_sz,
                pub_bytes.as_mut_ptr(),
                &mut pub_sz,
                EC448_LITTLE_ENDIAN,
            )
        };
        assert_eq!(rc, 0, "wc_curve448_export_key_raw_ex failed (buffer too small)");

        // Zeroize private bytes — we only need the public portion.
        priv_bytes.zeroize();

        X448PublicKey { bytes: pub_bytes }
    }

    /// Perform X448 Diffie-Hellman with the given peer public key.
    ///
    /// Consumes `self` so the private key is freed after use.
    pub fn diffie_hellman(mut self, peer_public: &X448PublicKey) -> X448SharedSecret {
        // Build a temporary key struct holding the peer's public key.
        let mut peer_key = wc_curve448_key::zeroed();

        // SAFETY: `peer_key` is zero-initialized; init will set it up.
        let rc = unsafe { wc_curve448_init(&mut peer_key) };
        assert_eq!(rc, 0, "wc_curve448_init (peer) failed (OOM)");

        // SAFETY: `peer_key` is initialized, peer bytes are X448_KEY_LEN.
        let rc = unsafe {
            wc_curve448_import_public_ex(
                peer_public.bytes.as_ptr(),
                X448_KEY_LEN as u32,
                &mut peer_key,
                EC448_LITTLE_ENDIAN,
            )
        };
        assert_eq!(rc, 0, "wc_curve448_import_public_ex failed (invalid public key)");

        let mut out = [0u8; X448_KEY_LEN];
        let mut out_len = X448_KEY_LEN as u32;

        // SAFETY: Both keys are fully-initialized curve448_key structs.
        // `out` is X448_KEY_LEN bytes and `out_len` reflects its capacity.
        // Curve448 does not use blinding, so no RNG is needed.
        let rc = unsafe {
            wc_curve448_shared_secret_ex(
                &mut self.key,
                &mut peer_key,
                out.as_mut_ptr(),
                &mut out_len,
                EC448_LITTLE_ENDIAN,
            )
        };
        assert_eq!(rc, 0, "wc_curve448_shared_secret_ex failed (invalid key or buffer)");

        // SAFETY: `peer_key` was initialized; free it now.
        unsafe {
            wc_curve448_free(&mut peer_key);
        }

        X448SharedSecret(out)
    }
}

#[cfg(wolfssl_curve448)]
impl Drop for X448StaticSecret {
    fn drop(&mut self) {
        // SAFETY: `self.key` was initialized by `wc_curve448_init` in
        // all constructors. Freed exactly once here.
        unsafe { wc_curve448_free(&mut self.key) };
    }
}

// SAFETY: `wc_curve448_key` owns its own memory with no shared
// mutable globals; safe to move between threads.
#[cfg(wolfssl_curve448)]
unsafe impl Send for X448StaticSecret {}

// ---------------------------------------------------------------------------
// X448PublicKey
// ---------------------------------------------------------------------------

#[cfg(wolfssl_curve448)]
impl X448PublicKey {
    /// Construct a public key from raw 56-byte u-coordinate.
    pub fn from_bytes(bytes: &[u8; X448_KEY_LEN]) -> Self {
        Self { bytes: *bytes }
    }

    /// Return the raw 56-byte u-coordinate.
    pub fn as_bytes(&self) -> &[u8; X448_KEY_LEN] {
        &self.bytes
    }
}

#[cfg(wolfssl_curve448)]
impl From<[u8; X448_KEY_LEN]> for X448PublicKey {
    fn from(bytes: [u8; X448_KEY_LEN]) -> Self {
        Self { bytes }
    }
}

// SAFETY: Plain byte array, no interior mutability.
#[cfg(wolfssl_curve448)]
unsafe impl Send for X448PublicKey {}
#[cfg(wolfssl_curve448)]
unsafe impl Sync for X448PublicKey {}

// ---------------------------------------------------------------------------
// X448SharedSecret
// ---------------------------------------------------------------------------

#[cfg(wolfssl_curve448)]
impl X448SharedSecret {
    /// Return the raw 56-byte shared secret.
    pub fn as_bytes(&self) -> &[u8; X448_KEY_LEN] {
        &self.0
    }
}

// ===========================================================================
// NIST curve ECDH (P-256, P-384) via OpenSSL compat layer
// ===========================================================================
//
// Uses wolfSSL's OpenSSL-compatible EC_KEY / ECDH_compute_key API to perform
// elliptic-curve Diffie-Hellman on NIST prime curves.

#[cfg(all(wolfssl_openssl_extra, wolfssl_ecc))]
mod nist_ecdh {
    use core::ffi::{c_int, c_void};
    use core::marker::PhantomData;
    use core::ptr;

    use alloc::vec;
    use alloc::vec::Vec;

    use zeroize::ZeroizeOnDrop;

    use crate::error::WolfCryptError;

    use wolfcrypt_rs::{
        EC_GROUP_free, EC_GROUP_new_by_curve_name,
        EC_KEY_free, EC_KEY_generate_key, EC_KEY_get0_public_key, EC_KEY_new,
        EC_KEY_set_group,
        EC_POINT_free, EC_POINT_new, EC_POINT_oct2point, EC_POINT_point2oct,
        ECDH_compute_key,
        NID_X9_62_prime256v1,
        EC_GROUP, EC_KEY,
        point_conversion_form_t,
    };

    #[cfg(wolfssl_ecc_p384)]
    use wolfcrypt_rs::NID_secp384r1;

    #[cfg(wolfssl_ecc_p521)]
    use wolfcrypt_rs::NID_secp521r1;

    // ================================================================
    // Sealed trait pattern
    // ================================================================

    mod sealed {
        pub trait Sealed {}
    }

    /// Trait describing a NIST prime curve's ECDH parameters.
    ///
    /// Sealed so that only [`NistP256`], [`NistP384`], and [`NistP521`]
    /// can implement it.
    ///
    /// This is intentionally separate from [`ecdsa::EcdsaCurve`] — ECDSA
    /// needs hash parameters (`evp_md()`, `HASH_LEN`, `SigSize`) that ECDH
    /// never uses. Merging would couple the `ecdh` and `ecdsa` feature
    /// gates and pollute ECDH with unused hash concerns.
    pub trait NistCurve: sealed::Sealed + 'static {
        /// The OpenSSL NID for this curve.
        const NID: c_int;
        /// Size of one field element in bytes (= shared secret length).
        const FIELD_SIZE: usize;
        /// Size of the uncompressed public point: `1 + 2 * FIELD_SIZE`.
        const POINT_SIZE: usize;
    }

    /// NIST P-256 (secp256r1 / prime256v1) curve marker for ECDH.
    pub struct NistP256;

    impl sealed::Sealed for NistP256 {}

    impl NistCurve for NistP256 {
        const NID: c_int = NID_X9_62_prime256v1;
        const FIELD_SIZE: usize = 32;
        const POINT_SIZE: usize = 65; // 1 + 2*32
    }

    /// NIST P-384 (secp384r1) curve marker for ECDH.
    #[cfg(wolfssl_ecc_p384)]
    pub struct NistP384;

    #[cfg(wolfssl_ecc_p384)]
    impl sealed::Sealed for NistP384 {}

    #[cfg(wolfssl_ecc_p384)]
    impl NistCurve for NistP384 {
        const NID: c_int = NID_secp384r1;
        const FIELD_SIZE: usize = 48;
        const POINT_SIZE: usize = 97; // 1 + 2*48
    }

    // ================================================================
    // NistEcdhPublicKey<C>
    // ================================================================

    /// An uncompressed public point for NIST curve ECDH.
    ///
    /// Stored as the standard uncompressed encoding: `0x04 || x || y`.
    pub struct NistEcdhPublicKey<C: NistCurve> {
        bytes: Vec<u8>,
        _curve: PhantomData<C>,
    }

    impl<C: NistCurve> NistEcdhPublicKey<C> {
        /// Import a public key from its uncompressed point encoding.
        ///
        /// The first byte must be `0x04` and the total length must be
        /// `1 + 2 * FIELD_SIZE`.
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, WolfCryptError> {
            if bytes.len() != C::POINT_SIZE {
                return Err(WolfCryptError::INVALID_INPUT);
            }
            if bytes[0] != 0x04 {
                return Err(WolfCryptError::INVALID_INPUT);
            }
            Ok(Self {
                bytes: bytes.to_vec(),
                _curve: PhantomData,
            })
        }

        /// Return the raw uncompressed point bytes (`0x04 || x || y`).
        pub fn as_bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    // SAFETY: Plain byte vector, no interior mutability.
    unsafe impl<C: NistCurve> Send for NistEcdhPublicKey<C> {}
    unsafe impl<C: NistCurve> Sync for NistEcdhPublicKey<C> {}

    // ================================================================
    // NistEcdhSharedSecret<C>
    // ================================================================

    /// The shared secret resulting from a NIST curve ECDH exchange.
    #[derive(ZeroizeOnDrop)]
    pub struct NistEcdhSharedSecret<C: NistCurve> {
        #[zeroize(drop)]
        bytes: Vec<u8>,
        _curve: PhantomData<C>,
    }

    impl<C: NistCurve> NistEcdhSharedSecret<C> {
        /// Return the raw shared secret bytes.
        ///
        /// Length is [`NistCurve::FIELD_SIZE`] (32 for P-256, 48 for P-384).
        pub fn as_bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    // ================================================================
    // NistEcdhSecret<C>
    // ================================================================

    /// A NIST curve ECDH private key.
    ///
    /// Wraps a wolfSSL `EC_KEY` with the curve's group set. The key
    /// is freed on drop.
    pub struct NistEcdhSecret<C: NistCurve> {
        /// Owned EC_KEY pointer. Non-null while the struct is alive.
        ec_key: *mut EC_KEY,
        /// Owned EC_GROUP pointer. Non-null while the struct is alive.
        group: *mut EC_GROUP,
        _curve: PhantomData<C>,
    }

    impl<C: NistCurve> NistEcdhSecret<C> {
        /// Generate a random ECDH keypair on this curve.
        #[cfg(feature = "rand")]
        pub fn generate() -> Result<Self, WolfCryptError> {
            // SAFETY: EC_GROUP_new_by_curve_name returns a heap-allocated
            // group or null on failure.
            let group = unsafe { EC_GROUP_new_by_curve_name(C::NID) };
            if group.is_null() {
                return Err(WolfCryptError::ALLOC_FAILED);
            }

            // SAFETY: EC_KEY_new returns a heap-allocated key or null.
            let ec_key = unsafe { EC_KEY_new() };
            if ec_key.is_null() {
                unsafe { EC_GROUP_free(group) };
                return Err(WolfCryptError::ALLOC_FAILED);
            }

            // SAFETY: Both pointers are valid, non-null.
            let rc = unsafe { EC_KEY_set_group(ec_key, group) };
            if rc != 1 {
                unsafe {
                    EC_KEY_free(ec_key);
                    EC_GROUP_free(group);
                }
                return Err(WolfCryptError::Ffi { code: rc, func: "EC_KEY_set_group" });
            }

            // SAFETY: ec_key has a group set; generate_key fills in
            // private scalar and public point.
            let rc = unsafe { EC_KEY_generate_key(ec_key) };
            if rc != 1 {
                unsafe {
                    EC_KEY_free(ec_key);
                    EC_GROUP_free(group);
                }
                return Err(WolfCryptError::Ffi { code: rc, func: "EC_KEY_generate_key" });
            }

            Ok(Self {
                ec_key,
                group,
                _curve: PhantomData,
            })
        }

        /// Export the public key as an uncompressed point.
        pub fn public_key(&self) -> NistEcdhPublicKey<C> {
            // SAFETY: ec_key is valid and has a generated keypair.
            let point = unsafe { EC_KEY_get0_public_key(self.ec_key) };
            assert!(!point.is_null(), "EC_KEY_get0_public_key returned null");

            let mut buf = vec![0u8; C::POINT_SIZE];

            // SAFETY: group and point are valid. The buffer is large enough
            // for the uncompressed encoding. Returns the number of bytes
            // written, or 0 on failure.
            let n = unsafe {
                EC_POINT_point2oct(
                    self.group,
                    point,
                    point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
                    buf.as_mut_ptr(),
                    buf.len(),
                    ptr::null_mut(),
                )
            };
            assert_eq!(
                n, C::POINT_SIZE,
                "EC_POINT_point2oct returned unexpected size: {n}"
            );

            NistEcdhPublicKey {
                bytes: buf,
                _curve: PhantomData,
            }
        }

        /// Perform ECDH with the given peer public key.
        ///
        /// Consumes `self` so the private key is freed after use.
        pub fn diffie_hellman(
            self,
            peer_public: &NistEcdhPublicKey<C>,
        ) -> NistEcdhSharedSecret<C> {
            // Parse the peer's uncompressed point into an EC_POINT.
            //
            // SAFETY: group is valid; EC_POINT_new returns a heap-allocated
            // point or null.
            let peer_point = unsafe { EC_POINT_new(self.group) };
            assert!(!peer_point.is_null(), "EC_POINT_new failed");

            // SAFETY: group and peer_point are valid, peer bytes encode a
            // valid uncompressed point for this curve.
            let rc = unsafe {
                EC_POINT_oct2point(
                    self.group,
                    peer_point,
                    peer_public.bytes.as_ptr(),
                    peer_public.bytes.len(),
                    ptr::null_mut(),
                )
            };
            assert_eq!(rc, 1, "EC_POINT_oct2point failed (invalid point encoding)");

            // Compute the shared secret.
            let mut out = vec![0u8; C::FIELD_SIZE];

            // SAFETY: ec_key holds a valid private key, peer_point is a
            // valid point on the same curve. `out` is FIELD_SIZE bytes.
            // KDF is null → raw x-coordinate is returned.
            let rc = unsafe {
                ECDH_compute_key(
                    out.as_mut_ptr() as *mut c_void,
                    C::FIELD_SIZE,
                    peer_point,
                    self.ec_key,
                    ptr::null_mut(),
                )
            };
            assert_eq!(
                rc as usize, C::FIELD_SIZE,
                "ECDH_compute_key failed (invalid key or point)"
            );

            // SAFETY: peer_point was allocated above; free it now.
            unsafe { EC_POINT_free(peer_point) };

            NistEcdhSharedSecret {
                bytes: out,
                _curve: PhantomData,
            }
        }
    }

    impl<C: NistCurve> Drop for NistEcdhSecret<C> {
        fn drop(&mut self) {
            // SAFETY: ec_key and group were allocated in `generate` and
            // are non-null. Freed exactly once here.
            unsafe {
                EC_KEY_free(self.ec_key);
                EC_GROUP_free(self.group);
            }
        }
    }

    // SAFETY: EC_KEY / EC_GROUP are self-contained heap objects with no
    // shared mutable globals; safe to move between threads.
    unsafe impl<C: NistCurve> Send for NistEcdhSecret<C> {}

    /// NIST P-521 (secp521r1) curve marker for ECDH.
    #[cfg(wolfssl_ecc_p521)]
    pub struct NistP521;

    #[cfg(wolfssl_ecc_p521)]
    impl sealed::Sealed for NistP521 {}

    #[cfg(wolfssl_ecc_p521)]
    impl NistCurve for NistP521 {
        const NID: c_int = NID_secp521r1;
        const FIELD_SIZE: usize = 66;
        const POINT_SIZE: usize = 133; // 1 + 2*66
    }

    /// Type alias: P-256 ECDH secret key.
    pub type P256EcdhSecret = NistEcdhSecret<NistP256>;
    /// Type alias: P-384 ECDH secret key.
    #[cfg(wolfssl_ecc_p384)]
    pub type P384EcdhSecret = NistEcdhSecret<NistP384>;
    /// Type alias: P-521 ECDH secret key.
    #[cfg(wolfssl_ecc_p521)]
    pub type P521EcdhSecret = NistEcdhSecret<NistP521>;
}

// Re-export NIST ECDH types at module level.
#[cfg(all(wolfssl_openssl_extra, wolfssl_ecc))]
pub use nist_ecdh::{
    NistCurve, NistEcdhPublicKey, NistEcdhSecret, NistEcdhSharedSecret,
    NistP256, P256EcdhSecret,
};
#[cfg(all(wolfssl_openssl_extra, wolfssl_ecc, wolfssl_sha384))]
pub use nist_ecdh::{NistP384, P384EcdhSecret};
#[cfg(all(wolfssl_openssl_extra, wolfssl_ecc, wolfssl_sha512))]
pub use nist_ecdh::{NistP521, P521EcdhSecret};

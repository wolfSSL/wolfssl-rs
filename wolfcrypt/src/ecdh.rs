//! Elliptic-Curve Diffie-Hellman key agreement (X25519 and X448).
//!
//! Provides [`X25519StaticSecret`], [`X25519PublicKey`], and [`SharedSecret`]
//! types backed by wolfCrypt's native Curve25519 implementation (RFC 7748).
//!
//! When the `wolfssl_curve448` cfg is active, also provides [`X448StaticSecret`],
//! [`X448PublicKey`], and [`X448SharedSecret`] backed by wolfCrypt's Curve448
//! implementation (RFC 7748).

use wolfcrypt_rs::{
    wc_FreeRng, wc_InitRng, wc_curve25519_export_key_raw_ex, wc_curve25519_free,
    wc_curve25519_import_private_raw_ex, wc_curve25519_import_public_ex, wc_curve25519_init,
    wc_curve25519_key, wc_curve25519_make_key, wc_curve25519_make_pub, wc_curve25519_set_rng,
    wc_curve25519_shared_secret_ex, EC25519_LITTLE_ENDIAN, WC_RNG,
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
        assert_eq!(
            rc, 0,
            "wc_curve25519_import_private_raw_ex failed (invalid key bytes)"
        );

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
        let rc = unsafe { wc_curve25519_make_key(&mut rng.rng, KEY_LEN as i32, &mut key) };
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
        assert_eq!(
            rc, 0,
            "wc_curve25519_export_key_raw_ex failed (buffer too small)"
        );

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
        assert_eq!(
            rc, 0,
            "wc_curve25519_import_public_ex failed (invalid public key)"
        );

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
        assert_eq!(
            rc, 0,
            "wc_curve25519_shared_secret_ex failed (invalid key or buffer)"
        );

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
    wc_curve448_export_key_raw_ex, wc_curve448_free, wc_curve448_import_private_raw_ex,
    wc_curve448_import_public_ex, wc_curve448_init, wc_curve448_key, wc_curve448_make_key,
    wc_curve448_make_pub, wc_curve448_shared_secret_ex, EC448_LITTLE_ENDIAN,
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
        assert_eq!(
            rc, 0,
            "wc_curve448_import_private_raw_ex failed (invalid key bytes)"
        );

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
        let rc = unsafe { wc_curve448_make_key(&mut rng.rng, X448_KEY_LEN as i32, &mut key) };
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
        assert_eq!(
            rc, 0,
            "wc_curve448_export_key_raw_ex failed (buffer too small)"
        );

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
        assert_eq!(
            rc, 0,
            "wc_curve448_import_public_ex failed (invalid public key)"
        );

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
        assert_eq!(
            rc, 0,
            "wc_curve448_shared_secret_ex failed (invalid key or buffer)"
        );

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
// NIST curve ECDH — native wc_ecc_* implementation
// ===========================================================================
//
// Uses wolfCrypt's native wc_ecc_* API.  No OPENSSL_EXTRA required.
// The old EVP-based `nist_ecdh` module is retained below but no longer
// re-exported; it will be deleted in a follow-up cleanup.

#[cfg(wolfssl_ecc)]
pub(crate) mod nist_ecdh_native {
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;
    use core::ffi::c_int;
    use core::marker::PhantomData;
    use core::ptr;

    use zeroize::ZeroizeOnDrop;

    use crate::error::WolfCryptError;

    use wolfcrypt_rs::{
        wc_FreeRng, wc_InitRng, wc_ecc_check_key, wc_ecc_export_x963, wc_ecc_import_private_key_ex,
        wc_ecc_import_x963, wc_ecc_key, wc_ecc_key_free, wc_ecc_key_new, wc_ecc_make_key_ex,
        wc_ecc_set_rng, wc_ecc_shared_secret, ECC_SECP256R1, WC_RNG,
    };

    #[cfg(wolfssl_ecc_p384)]
    use wolfcrypt_rs::ECC_SECP384R1;

    #[cfg(wolfssl_ecc_p521)]
    use wolfcrypt_rs::ECC_SECP521R1;

    // ================================================================
    // Sealed trait pattern
    // ================================================================

    mod sealed {
        pub trait Sealed {}
    }

    /// Parameters for a NIST prime curve ECDH operation.
    ///
    /// Sealed so that only [`NistP256`], [`NistP384`], and [`NistP521`]
    /// can implement it.
    pub trait NistCurve: sealed::Sealed + 'static {
        /// wolfCrypt curve ID (e.g. `ECC_SECP256R1`).
        const CURVE_ID: c_int;
        /// Size of one field element in bytes (= shared secret length).
        const FIELD_SIZE: usize;
        /// Size of an uncompressed public point: `1 + 2 * FIELD_SIZE`.
        const POINT_SIZE: usize;
    }

    /// NIST P-256 curve marker.
    pub struct NistP256;
    impl sealed::Sealed for NistP256 {}
    impl NistCurve for NistP256 {
        const CURVE_ID: c_int = ECC_SECP256R1;
        const FIELD_SIZE: usize = 32;
        const POINT_SIZE: usize = 65; // 1 + 2*32
    }

    /// NIST P-384 curve marker.
    #[cfg(wolfssl_ecc_p384)]
    pub struct NistP384;
    #[cfg(wolfssl_ecc_p384)]
    impl sealed::Sealed for NistP384 {}
    #[cfg(wolfssl_ecc_p384)]
    impl NistCurve for NistP384 {
        const CURVE_ID: c_int = ECC_SECP384R1;
        const FIELD_SIZE: usize = 48;
        const POINT_SIZE: usize = 97; // 1 + 2*48
    }

    /// NIST P-521 curve marker.
    #[cfg(wolfssl_ecc_p521)]
    pub struct NistP521;
    #[cfg(wolfssl_ecc_p521)]
    impl sealed::Sealed for NistP521 {}
    #[cfg(wolfssl_ecc_p521)]
    impl NistCurve for NistP521 {
        const CURVE_ID: c_int = ECC_SECP521R1;
        const FIELD_SIZE: usize = 66;
        const POINT_SIZE: usize = 133; // 1 + 2*66
    }

    // ================================================================
    // NistEcdhPublicKey<C>
    // ================================================================

    /// An uncompressed NIST curve public key: `0x04 || x || y`.
    pub struct NistEcdhPublicKey<C: NistCurve> {
        bytes: Vec<u8>,
        _curve: PhantomData<C>,
    }

    impl<C: NistCurve> NistEcdhPublicKey<C> {
        /// Import from uncompressed point bytes (`0x04 || x || y`).
        ///
        /// Validates that the bytes encode a point that lies on curve `C`
        /// by importing into a temporary wolfCrypt key and calling
        /// `wc_ecc_check_key`.  Returns an error for points that fail
        /// curve membership (small subgroup, not on curve, etc.).
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, WolfCryptError> {
            if bytes.len() != C::POINT_SIZE {
                return Err(WolfCryptError::INVALID_INPUT);
            }
            if bytes[0] != 0x04 {
                return Err(WolfCryptError::INVALID_INPUT);
            }
            // Cryptographically validate the point: import into a temporary
            // key and check that it lies on the curve.  This matches the
            // contract of EcdsaVerifyingKey::from_uncompressed_point and
            // ensures callers get a type that is already validated, not one
            // that can only fail later inside diffie_hellman.
            //
            // SAFETY: wc_ecc_key_new returns a heap-allocated key or null.
            let tmp = unsafe { wc_ecc_key_new(ptr::null_mut()) };
            if tmp.is_null() {
                return Err(WolfCryptError::ALLOC_FAILED);
            }
            // SAFETY: tmp is non-null and initialised; bytes is a valid uncompressed point.
            let rc = unsafe { wc_ecc_import_x963(bytes.as_ptr(), bytes.len() as u32, tmp) };
            if rc != 0 {
                // SAFETY: tmp is non-null and was allocated above; freed on error path.
                unsafe { wc_ecc_key_free(tmp) };
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wc_ecc_import_x963",
                });
            }
            // SAFETY: tmp holds an imported public point; check validates curve membership.
            let rc = unsafe { wc_ecc_check_key(tmp) };
            // SAFETY: tmp is non-null and was allocated above; freed after validation.
            unsafe { wc_ecc_key_free(tmp) };
            if rc != 0 {
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wc_ecc_check_key",
                });
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

    /// The shared secret from a NIST curve ECDH exchange.
    ///
    /// Zeroized on drop.
    #[derive(ZeroizeOnDrop)]
    pub struct NistEcdhSharedSecret<C: NistCurve> {
        #[zeroize(drop)]
        bytes: Vec<u8>,
        _curve: PhantomData<C>,
    }

    impl<C: NistCurve> NistEcdhSharedSecret<C> {
        /// Return the raw shared secret bytes (length = `C::FIELD_SIZE`).
        pub fn as_bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    // ================================================================
    // NistEcdhSecret<C>
    // ================================================================

    /// A NIST curve ECDH private key backed by native wolfCrypt `wc_ecc_*`.
    ///
    /// `UnsafeCell` makes this type `!Sync`, which is correct: wolfCrypt
    /// contexts are not thread-safe.
    pub struct NistEcdhSecret<C: NistCurve> {
        /// Heap-allocated wc_ecc_key (via wc_ecc_key_new). Non-null while alive.
        key: UnsafeCell<*mut wc_ecc_key>,
        _curve: PhantomData<C>,
    }

    // SAFETY: wc_ecc_key owns independent heap state; safe to move across threads.
    unsafe impl<C: NistCurve> Send for NistEcdhSecret<C> {}

    impl<C: NistCurve> Drop for NistEcdhSecret<C> {
        fn drop(&mut self) {
            let key = *self.key.get_mut();
            if !key.is_null() {
                // SAFETY: key was allocated by wc_ecc_key_new in all constructors.
                unsafe {
                    wc_ecc_key_free(key);
                }
            }
        }
    }

    impl<C: NistCurve> NistEcdhSecret<C> {
        /// Generate a random ECDH keypair on this curve.
        pub fn generate() -> Result<Self, WolfCryptError> {
            // SAFETY: wc_ecc_key_new returns a heap-allocated key or null.
            let key = unsafe { wc_ecc_key_new(ptr::null_mut()) };
            if key.is_null() {
                return Err(WolfCryptError::ALLOC_FAILED);
            }

            let mut rng = WC_RNG::zeroed();
            // SAFETY: rng is zero-initialised; wc_InitRng completes setup.
            let rc = unsafe { wc_InitRng(&mut rng) };
            if rc != 0 {
                // SAFETY: key is non-null and was allocated above; freed on error path.
                unsafe {
                    wc_ecc_key_free(key);
                }
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wc_InitRng",
                });
            }

            // SAFETY: key and rng are both initialised; FIELD_SIZE matches CURVE_ID.
            let rc =
                unsafe { wc_ecc_make_key_ex(&mut rng, C::FIELD_SIZE as i32, key, C::CURVE_ID) };
            // Free RNG regardless of outcome.
            // SAFETY: rng was successfully initialised above.
            unsafe {
                wc_FreeRng(&mut rng);
            }
            if rc != 0 {
                // SAFETY: key is non-null and was allocated above; freed on error path.
                unsafe {
                    wc_ecc_key_free(key);
                }
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wc_ecc_make_key_ex",
                });
            }

            Ok(Self {
                key: UnsafeCell::new(key),
                _curve: PhantomData,
            })
        }

        /// Import a private key from its raw scalar bytes (big-endian,
        /// exactly `C::FIELD_SIZE` bytes).
        ///
        /// The public key component is **not** set on the resulting key struct;
        /// `public_key()` will return an error if called on this key.  Use this
        /// constructor when you only need `diffie_hellman()` (e.g. in tests).
        pub fn from_private_scalar(scalar: &[u8]) -> Result<Self, WolfCryptError> {
            if scalar.len() != C::FIELD_SIZE {
                return Err(WolfCryptError::INVALID_INPUT);
            }
            // SAFETY: null heap hint is valid; returns heap-allocated key or null.
            let key = unsafe { wc_ecc_key_new(ptr::null_mut()) };
            if key.is_null() {
                return Err(WolfCryptError::ALLOC_FAILED);
            }
            // SAFETY: key is initialised; scalar is FIELD_SIZE bytes.
            // Passing null public key is valid — wolfCrypt accepts private-only import.
            let rc = unsafe {
                wc_ecc_import_private_key_ex(
                    scalar.as_ptr(),
                    scalar.len() as u32,
                    ptr::null(),
                    0,
                    key,
                    C::CURVE_ID,
                )
            };
            if rc != 0 {
                // SAFETY: key is non-null and was allocated above; freed on error path.
                unsafe {
                    wc_ecc_key_free(key);
                }
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wc_ecc_import_private_key_ex",
                });
            }
            Ok(Self {
                key: UnsafeCell::new(key),
                _curve: PhantomData,
            })
        }

        /// Export the public key as an uncompressed point (`0x04 || x || y`).
        ///
        /// Returns an error if the key was created with `from_private_scalar`
        /// (public component not available without a separate derivation step).
        pub fn public_key(&self) -> Result<NistEcdhPublicKey<C>, WolfCryptError> {
            // SAFETY: self.key is non-null and initialised; dereferencing the UnsafeCell pointer.
            let key = unsafe { *self.key.get() };
            let mut buf = vec![0u8; C::POINT_SIZE];
            let mut sz = buf.len() as u32;
            // SAFETY: key is initialised and has a public component (generate path).
            let rc = unsafe { wc_ecc_export_x963(key, buf.as_mut_ptr(), &mut sz) };
            if rc != 0 {
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wc_ecc_export_x963",
                });
            }
            if sz as usize != C::POINT_SIZE {
                return Err(WolfCryptError::INVALID_INPUT);
            }
            NistEcdhPublicKey::from_bytes(&buf)
        }

        /// Perform ECDH with the given peer public key.
        ///
        /// Validates the peer point before use (`wc_ecc_check_key`).
        /// Attaches a fresh RNG to the private key for ECC_TIMING_RESISTANT
        /// scalar-multiplication blinding.
        pub fn diffie_hellman(
            self,
            peer_public: &NistEcdhPublicKey<C>,
        ) -> Result<NistEcdhSharedSecret<C>, WolfCryptError> {
            // ── Import peer public key ──────────────────────────────────────
            // SAFETY: null heap hint is valid; returns heap-allocated key or null.
            let peer_key = unsafe { wc_ecc_key_new(ptr::null_mut()) };
            if peer_key.is_null() {
                return Err(WolfCryptError::ALLOC_FAILED);
            }

            // SAFETY: peer_key is initialised; peer_public.bytes is a validated uncompressed point.
            let rc = unsafe {
                wc_ecc_import_x963(
                    peer_public.bytes.as_ptr(),
                    peer_public.bytes.len() as u32,
                    peer_key,
                )
            };
            if rc != 0 {
                // SAFETY: peer_key is non-null and was allocated above; freed on error path.
                unsafe {
                    wc_ecc_key_free(peer_key);
                }
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wc_ecc_import_x963",
                });
            }

            // ── Paranoid: validate peer point is on the curve ───────────────
            // SAFETY: peer_key holds an imported public point.
            let rc = unsafe { wc_ecc_check_key(peer_key) };
            if rc != 0 {
                // SAFETY: peer_key is non-null and was allocated above; freed on error path.
                unsafe {
                    wc_ecc_key_free(peer_key);
                }
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wc_ecc_check_key",
                });
            }

            // ── Attach RNG to private key for blinding ──────────────────────
            // Required when ECC_TIMING_RESISTANT is defined (default).
            // wc_ecc_shared_secret returns MISSING_RNG_E without this.
            // SAFETY: self.key is non-null and initialised; dereferencing the UnsafeCell pointer.
            let priv_key = unsafe { *self.key.get() };
            let mut rng = WC_RNG::zeroed();
            // SAFETY: rng is zero-initialised; wc_InitRng completes setup.
            let rc = unsafe { wc_InitRng(&mut rng) };
            if rc != 0 {
                // SAFETY: peer_key is non-null; freed on error path.
                unsafe {
                    wc_ecc_key_free(peer_key);
                }
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wc_InitRng",
                });
            }
            // SAFETY: priv_key is initialised and non-null; rng is live.
            let rc = unsafe { wc_ecc_set_rng(priv_key, &mut rng) };
            if rc != 0 {
                // SAFETY: peer_key and rng were initialised; freed on error path.
                unsafe {
                    wc_ecc_key_free(peer_key);
                    wc_FreeRng(&mut rng);
                }
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wc_ecc_set_rng",
                });
            }

            // ── Compute shared secret ───────────────────────────────────────
            let mut out = vec![0u8; C::FIELD_SIZE];
            let mut out_len = out.len() as u32;
            // SAFETY: priv_key has private scalar + RNG; peer_key has public point.
            let rc =
                unsafe { wc_ecc_shared_secret(priv_key, peer_key, out.as_mut_ptr(), &mut out_len) };

            // Always clean up peer key and RNG.
            // SAFETY: peer_key and rng were both initialised; freed regardless of outcome.
            unsafe {
                wc_ecc_key_free(peer_key);
                wc_FreeRng(&mut rng);
            }

            if rc != 0 {
                return Err(WolfCryptError::Ffi {
                    code: rc,
                    func: "wc_ecc_shared_secret",
                });
            }
            if out_len as usize != C::FIELD_SIZE {
                return Err(WolfCryptError::INVALID_INPUT);
            }

            Ok(NistEcdhSharedSecret {
                bytes: out,
                _curve: PhantomData,
            })
        }
    }

    /// P-256 ECDH secret key.
    pub type P256EcdhSecret = NistEcdhSecret<NistP256>;
    /// P-384 ECDH secret key.
    #[cfg(wolfssl_ecc_p384)]
    pub type P384EcdhSecret = NistEcdhSecret<NistP384>;
    /// P-521 ECDH secret key.
    #[cfg(wolfssl_ecc_p521)]
    pub type P521EcdhSecret = NistEcdhSecret<NistP521>;
}

// Re-export native NIST ECDH types at module level.
// No wolfssl_openssl_extra required — native wc_ecc_* only.
#[cfg(wolfssl_ecc)]
pub use nist_ecdh_native::{
    NistCurve, NistEcdhPublicKey, NistEcdhSecret, NistEcdhSharedSecret, NistP256, P256EcdhSecret,
};
#[cfg(all(wolfssl_ecc, wolfssl_ecc_p384))]
pub use nist_ecdh_native::{NistP384, P384EcdhSecret};
#[cfg(all(wolfssl_ecc, wolfssl_ecc_p521))]
pub use nist_ecdh_native::{NistP521, P521EcdhSecret};

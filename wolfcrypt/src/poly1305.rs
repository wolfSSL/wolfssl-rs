//! Poly1305 one-time authenticator backed by wolfCrypt.
//!
//! Implements the RustCrypto [`digest`](digest_trait) 0.10 MAC traits
//! (`OutputSizeUser`, `KeySizeUser`, `KeyInit`, `Update`, `FixedOutput`,
//! `MacMarker`) so the blanket `Mac` impl is available automatically.
//!
//! Callers should `use digest_trait::Mac` for the full API:
//! `new_from_slice()`, `update()`, `finalize()`, `verify_slice()`.

use digest_trait::{FixedOutput, KeyInit, OutputSizeUser, Update};
use generic_array::GenericArray;
use typenum::{U16, U32};

use crate::error::len_as_u32;

/// Poly1305 one-time authenticator (256-bit key, 128-bit tag).
///
/// Uses wolfCrypt's native `wc_Poly1305SetKey` / `wc_Poly1305Update` /
/// `wc_Poly1305Final`.
///
/// **Warning:** Poly1305 is a one-time authenticator. Each key must be used
/// with at most one message. Reusing a key is a fatal security error.
#[cfg(wolfssl_poly1305)]
pub struct WolfPoly1305 {
    ctx: wolfcrypt_rs::poly1305_state,
}

// SAFETY: poly1305_state contains no thread-local state; it is safe to move
// the whole struct to another thread.
#[cfg(wolfssl_poly1305)]
unsafe impl Send for WolfPoly1305 {}

#[cfg(wolfssl_poly1305)]
impl Drop for WolfPoly1305 {
    fn drop(&mut self) {
        // poly1305_state is stack-allocated with no wc_Free equivalent.
        // Zero the state for defence-in-depth.
        use zeroize::Zeroize;
        // SAFETY: poly1305_state is repr(C); zeroing its raw bytes is safe.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut self.ctx as *mut wolfcrypt_rs::poly1305_state as *mut u8,
                core::mem::size_of_val(&self.ctx),
            )
        };
        bytes.zeroize();
    }
}

#[cfg(wolfssl_poly1305)]
impl OutputSizeUser for WolfPoly1305 {
    type OutputSize = U16; // 128-bit tag
}

#[cfg(wolfssl_poly1305)]
impl crypto_common::KeySizeUser for WolfPoly1305 {
    type KeySize = U32; // 256-bit key
}

#[cfg(wolfssl_poly1305)]
impl KeyInit for WolfPoly1305 {
    fn new(key: &GenericArray<u8, U32>) -> Self {
        let mut ctx = wolfcrypt_rs::poly1305_state::zeroed();

        // SAFETY: `ctx` is zero-initialized, `key` points to exactly 32
        // valid bytes.
        let rc = unsafe {
            wolfcrypt_rs::wc_Poly1305SetKey(
                &mut ctx as *mut wolfcrypt_rs::poly1305_state,
                key.as_ptr(),
                32,
            )
        };
        assert_eq!(rc, 0, "wc_Poly1305SetKey failed (invalid key)");

        Self { ctx }
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, crypto_common::InvalidLength> {
        if key.len() != 32 {
            return Err(crypto_common::InvalidLength);
        }
        Ok(Self::new(GenericArray::from_slice(key)))
    }
}

#[cfg(wolfssl_poly1305)]
impl Update for WolfPoly1305 {
    fn update(&mut self, data: &[u8]) {
        // SAFETY: `self.ctx` is valid (keyed). `data` pointer and length
        // are guaranteed correct by the slice reference.
        let rc = unsafe {
            wolfcrypt_rs::wc_Poly1305Update(
                &mut self.ctx as *mut wolfcrypt_rs::poly1305_state,
                data.as_ptr(),
                len_as_u32(data.len()),
            )
        };
        assert_eq!(rc, 0, "wc_Poly1305Update failed (context not initialized)");
    }
}

#[cfg(wolfssl_poly1305)]
impl FixedOutput for WolfPoly1305 {
    fn finalize_into(mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        // SAFETY: `self.ctx` is valid. `out` is exactly 16 bytes.
        // After this call, Drop will zero the context.
        let rc = unsafe {
            wolfcrypt_rs::wc_Poly1305Final(
                &mut self.ctx as *mut wolfcrypt_rs::poly1305_state,
                out.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "wc_Poly1305Final failed (context not initialized)");
    }
}

#[cfg(wolfssl_poly1305)]
impl digest_trait::MacMarker for WolfPoly1305 {}

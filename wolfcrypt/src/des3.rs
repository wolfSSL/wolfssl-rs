//! Triple-DES (3DES / DES-EDE3) CBC encryption and decryption.
//!
//! Provides [`DesEde3CbcEnc`] and [`DesEde3CbcDec`] implementing the
//! RustCrypto `BlockEncryptMut`/`BlockDecryptMut` and `KeyIvInit` traits.
//!
//! Uses wolfCrypt's native wc_Des3* API with padding disabled, so
//! callers must provide data in exact multiples of the 8-byte block size.
//!
//! Gated on `cfg(wolfssl_des3)`.

use cipher_trait::generic_array::GenericArray;
use cipher_trait::inout::InOut;
use cipher_trait::{
    Block, BlockBackend, BlockClosure, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, IvSizeUser,
    KeyIvInit, KeySizeUser, ParBlocksSizeUser,
};
use typenum::{U1, U24, U8};

pub use cipher_trait;

// ---------------------------------------------------------------------------
// 3DES-CBC encrypt
// ---------------------------------------------------------------------------

/// Triple-DES CBC encryption using the native wolfCrypt wc_Des3* API.
///
/// Key: 24 bytes (3 x 8-byte DES keys).
/// Block size: 8 bytes.
/// IV: 8 bytes.
#[cfg(wolfssl_des3)]
pub struct DesEde3CbcEnc {
    ctx: *mut core::ffi::c_void,
}

#[cfg(wolfssl_des3)]
// SAFETY: Des3 context is heap-allocated and self-contained.
unsafe impl Send for DesEde3CbcEnc {}

#[cfg(wolfssl_des3)]
impl Drop for DesEde3CbcEnc {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // SAFETY: ctx was allocated by wolfcrypt_des3_enc_new.
            unsafe { wolfcrypt_rs::wolfcrypt_des3_free(self.ctx) };
        }
    }
}

#[cfg(wolfssl_des3)]
impl KeySizeUser for DesEde3CbcEnc {
    type KeySize = U24;
}

#[cfg(wolfssl_des3)]
impl IvSizeUser for DesEde3CbcEnc {
    type IvSize = U8;
}

#[cfg(wolfssl_des3)]
impl BlockSizeUser for DesEde3CbcEnc {
    type BlockSize = U8;
}

#[cfg(wolfssl_des3)]
impl KeyIvInit for DesEde3CbcEnc {
    fn new(key: &GenericArray<u8, U24>, iv: &GenericArray<u8, U8>) -> Self {
        // SAFETY: key is 24 bytes, iv is 8 bytes.
        let ctx = unsafe { wolfcrypt_rs::wolfcrypt_des3_enc_new(key.as_ptr(), iv.as_ptr()) };
        assert!(!ctx.is_null(), "wolfcrypt_des3_enc_new returned null");
        Self { ctx }
    }
}

#[cfg(wolfssl_des3)]
struct DesEde3CbcEncBackend(*mut core::ffi::c_void);

#[cfg(wolfssl_des3)]
impl BlockSizeUser for DesEde3CbcEncBackend {
    type BlockSize = U8;
}

#[cfg(wolfssl_des3)]
impl ParBlocksSizeUser for DesEde3CbcEncBackend {
    type ParBlocksSize = U1;
}

#[cfg(wolfssl_des3)]
impl BlockBackend for DesEde3CbcEncBackend {
    #[inline]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut tmp = [0u8; 8];
        // SAFETY: block.get_in() is a valid 8-byte input; tmp is a valid 8-byte output.
        let rc = unsafe {
            wolfcrypt_rs::wolfcrypt_des3_cbc_encrypt(
                self.0,
                block.get_in().as_ptr(),
                tmp.as_mut_ptr(),
                8,
            )
        };
        assert_eq!(rc, 0, "wolfcrypt_des3_cbc_encrypt failed");
        block.get_out().copy_from_slice(&tmp);
    }
}

#[cfg(wolfssl_des3)]
impl BlockEncryptMut for DesEde3CbcEnc {
    fn encrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut DesEde3CbcEncBackend(self.ctx));
    }
}

// ---------------------------------------------------------------------------
// 3DES-CBC decrypt
// ---------------------------------------------------------------------------

/// Triple-DES CBC decryption using the native wolfCrypt wc_Des3* API.
///
/// Key: 24 bytes (3 x 8-byte DES keys).
/// Block size: 8 bytes.
/// IV: 8 bytes.
#[cfg(wolfssl_des3)]
pub struct DesEde3CbcDec {
    ctx: *mut core::ffi::c_void,
}

#[cfg(wolfssl_des3)]
// SAFETY: Des3 context is heap-allocated and self-contained.
unsafe impl Send for DesEde3CbcDec {}

#[cfg(wolfssl_des3)]
impl Drop for DesEde3CbcDec {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // SAFETY: ctx was allocated by wolfcrypt_des3_dec_new.
            unsafe { wolfcrypt_rs::wolfcrypt_des3_free(self.ctx) };
        }
    }
}

#[cfg(wolfssl_des3)]
impl KeySizeUser for DesEde3CbcDec {
    type KeySize = U24;
}

#[cfg(wolfssl_des3)]
impl IvSizeUser for DesEde3CbcDec {
    type IvSize = U8;
}

#[cfg(wolfssl_des3)]
impl BlockSizeUser for DesEde3CbcDec {
    type BlockSize = U8;
}

#[cfg(wolfssl_des3)]
impl KeyIvInit for DesEde3CbcDec {
    fn new(key: &GenericArray<u8, U24>, iv: &GenericArray<u8, U8>) -> Self {
        // SAFETY: key is 24 bytes, iv is 8 bytes.
        let ctx = unsafe { wolfcrypt_rs::wolfcrypt_des3_dec_new(key.as_ptr(), iv.as_ptr()) };
        assert!(!ctx.is_null(), "wolfcrypt_des3_dec_new returned null");
        Self { ctx }
    }
}

#[cfg(wolfssl_des3)]
struct DesEde3CbcDecBackend(*mut core::ffi::c_void);

#[cfg(wolfssl_des3)]
impl BlockSizeUser for DesEde3CbcDecBackend {
    type BlockSize = U8;
}

#[cfg(wolfssl_des3)]
impl ParBlocksSizeUser for DesEde3CbcDecBackend {
    type ParBlocksSize = U1;
}

#[cfg(wolfssl_des3)]
impl BlockBackend for DesEde3CbcDecBackend {
    #[inline]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut tmp = [0u8; 8];
        // SAFETY: block.get_in() is a valid 8-byte input; tmp is a valid 8-byte output.
        let rc = unsafe {
            wolfcrypt_rs::wolfcrypt_des3_cbc_decrypt(
                self.0,
                block.get_in().as_ptr(),
                tmp.as_mut_ptr(),
                8,
            )
        };
        assert_eq!(rc, 0, "wolfcrypt_des3_cbc_decrypt failed");
        block.get_out().copy_from_slice(&tmp);
    }
}

#[cfg(wolfssl_des3)]
impl BlockDecryptMut for DesEde3CbcDec {
    fn decrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut DesEde3CbcDecBackend(self.ctx));
    }
}

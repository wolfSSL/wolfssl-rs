//! Triple-DES (3DES / DES-EDE3) CBC encryption and decryption.
//!
//! Provides [`DesEde3CbcEnc`] and [`DesEde3CbcDec`] implementing the
//! RustCrypto `BlockEncryptMut`/`BlockDecryptMut` and `KeyIvInit` traits.
//!
//! Uses wolfSSL's EVP API (`EVP_des_ede3_cbc`) with padding disabled, so
//! callers must provide data in exact multiples of the 8-byte block size.
//!
//! Gated on `cfg(wolfssl_openssl_extra)` and `cfg(wolfssl_des3)`.

use cipher_trait::generic_array::GenericArray;
use cipher_trait::inout::InOut;
use cipher_trait::{
    Block, BlockBackend, BlockClosure, BlockDecryptMut, BlockEncryptMut,
    BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, ParBlocksSizeUser,
};
use core::ffi::c_int;
use typenum::{U1, U8, U24};

pub use cipher_trait;

// ---------------------------------------------------------------------------
// 3DES-CBC encrypt
// ---------------------------------------------------------------------------

/// Triple-DES CBC encryption using the EVP API.
///
/// Key: 24 bytes (3 x 8-byte DES keys).
/// Block size: 8 bytes.
/// IV: 8 bytes.
pub struct DesEde3CbcEnc {
    ctx: *mut wolfcrypt_rs::EVP_CIPHER_CTX,
}

// SAFETY: EVP_CIPHER_CTX is heap-allocated, self-contained, and thread-safe.
unsafe impl Send for DesEde3CbcEnc {}

impl Drop for DesEde3CbcEnc {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // SAFETY: `self.ctx` was allocated by `EVP_CIPHER_CTX_new`.
            unsafe { wolfcrypt_rs::EVP_CIPHER_CTX_free(self.ctx) };
        }
    }
}

impl KeySizeUser for DesEde3CbcEnc {
    type KeySize = U24; // 192-bit key (3 x 64-bit DES keys)
}

impl IvSizeUser for DesEde3CbcEnc {
    type IvSize = U8; // 64-bit IV
}

impl BlockSizeUser for DesEde3CbcEnc {
    type BlockSize = U8; // 64-bit block
}

impl KeyIvInit for DesEde3CbcEnc {
    fn new(key: &GenericArray<u8, U24>, iv: &GenericArray<u8, U8>) -> Self {
        // SAFETY: `EVP_CIPHER_CTX_new` allocates a new context.
        let ctx = unsafe { wolfcrypt_rs::EVP_CIPHER_CTX_new() };
        assert!(!ctx.is_null(), "EVP_CIPHER_CTX_new returned null");

        // SAFETY: `ctx` is valid. `EVP_des_ede3_cbc()` returns a static
        // cipher descriptor. key is 24 bytes, iv is 8 bytes.
        let rc = unsafe {
            wolfcrypt_rs::EVP_EncryptInit_ex(
                ctx,
                wolfcrypt_rs::EVP_des_ede3_cbc(),
                core::ptr::null_mut(),
                key.as_ptr(),
                iv.as_ptr(),
            )
        };
        assert_eq!(rc, 1, "EVP_EncryptInit_ex failed (OOM or invalid cipher)");

        // Disable padding — we operate at the block level.
        // SAFETY: `ctx` is initialized.
        let rc = unsafe { wolfcrypt_rs::EVP_CIPHER_CTX_set_padding(ctx, 0) };
        assert_eq!(rc, 1, "EVP_CIPHER_CTX_set_padding failed (context not initialized)");

        Self { ctx }
    }
}

/// Backend that encrypts one 8-byte block via EVP_EncryptUpdate.
struct DesEde3CbcEncBackend(*mut wolfcrypt_rs::EVP_CIPHER_CTX);

impl BlockSizeUser for DesEde3CbcEncBackend {
    type BlockSize = U8;
}

impl ParBlocksSizeUser for DesEde3CbcEncBackend {
    type ParBlocksSize = U1;
}

impl BlockBackend for DesEde3CbcEncBackend {
    #[inline]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut tmp = [0u8; 8];
        let mut outl: c_int = 0;
        // SAFETY: `self.0` is a valid EVP_CIPHER_CTX initialized for
        // 3DES-CBC encryption. Input and output are 8-byte blocks.
        let rc = unsafe {
            wolfcrypt_rs::EVP_EncryptUpdate(
                self.0,
                tmp.as_mut_ptr(),
                &mut outl,
                block.get_in().as_ptr(),
                8,
            )
        };
        assert_eq!(rc, 1, "EVP_EncryptUpdate failed (context not initialized)");
        block.get_out().copy_from_slice(&tmp);
    }
}

impl BlockEncryptMut for DesEde3CbcEnc {
    fn encrypt_with_backend_mut(
        &mut self,
        f: impl BlockClosure<BlockSize = Self::BlockSize>,
    ) {
        f.call(&mut DesEde3CbcEncBackend(self.ctx));
    }
}

// ---------------------------------------------------------------------------
// 3DES-CBC decrypt
// ---------------------------------------------------------------------------

/// Triple-DES CBC decryption using the EVP API.
///
/// Key: 24 bytes (3 x 8-byte DES keys).
/// Block size: 8 bytes.
/// IV: 8 bytes.
pub struct DesEde3CbcDec {
    ctx: *mut wolfcrypt_rs::EVP_CIPHER_CTX,
}

// SAFETY: EVP_CIPHER_CTX is heap-allocated, self-contained, and thread-safe.
unsafe impl Send for DesEde3CbcDec {}

impl Drop for DesEde3CbcDec {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // SAFETY: `self.ctx` was allocated by `EVP_CIPHER_CTX_new`.
            unsafe { wolfcrypt_rs::EVP_CIPHER_CTX_free(self.ctx) };
        }
    }
}

impl KeySizeUser for DesEde3CbcDec {
    type KeySize = U24; // 192-bit key
}

impl IvSizeUser for DesEde3CbcDec {
    type IvSize = U8; // 64-bit IV
}

impl BlockSizeUser for DesEde3CbcDec {
    type BlockSize = U8; // 64-bit block
}

impl KeyIvInit for DesEde3CbcDec {
    fn new(key: &GenericArray<u8, U24>, iv: &GenericArray<u8, U8>) -> Self {
        // SAFETY: `EVP_CIPHER_CTX_new` allocates a new context.
        let ctx = unsafe { wolfcrypt_rs::EVP_CIPHER_CTX_new() };
        assert!(!ctx.is_null(), "EVP_CIPHER_CTX_new returned null");

        // SAFETY: `ctx` is valid. `EVP_des_ede3_cbc()` returns a static
        // cipher descriptor. key is 24 bytes, iv is 8 bytes.
        let rc = unsafe {
            wolfcrypt_rs::EVP_DecryptInit_ex(
                ctx,
                wolfcrypt_rs::EVP_des_ede3_cbc(),
                core::ptr::null_mut(),
                key.as_ptr(),
                iv.as_ptr(),
            )
        };
        assert_eq!(rc, 1, "EVP_DecryptInit_ex failed (OOM or invalid cipher)");

        // Disable padding — we operate at the block level.
        let rc = unsafe { wolfcrypt_rs::EVP_CIPHER_CTX_set_padding(ctx, 0) };
        assert_eq!(rc, 1, "EVP_CIPHER_CTX_set_padding failed (context not initialized)");

        Self { ctx }
    }
}

/// Backend that decrypts one 8-byte block via EVP_DecryptUpdate.
struct DesEde3CbcDecBackend(*mut wolfcrypt_rs::EVP_CIPHER_CTX);

impl BlockSizeUser for DesEde3CbcDecBackend {
    type BlockSize = U8;
}

impl ParBlocksSizeUser for DesEde3CbcDecBackend {
    type ParBlocksSize = U1;
}

impl BlockBackend for DesEde3CbcDecBackend {
    #[inline]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut tmp = [0u8; 8];
        let mut outl: c_int = 0;
        // SAFETY: `self.0` is a valid EVP_CIPHER_CTX initialized for
        // 3DES-CBC decryption. Input and output are 8-byte blocks.
        let rc = unsafe {
            wolfcrypt_rs::EVP_DecryptUpdate(
                self.0,
                tmp.as_mut_ptr(),
                &mut outl,
                block.get_in().as_ptr(),
                8,
            )
        };
        assert_eq!(rc, 1, "EVP_DecryptUpdate failed (context not initialized)");
        block.get_out().copy_from_slice(&tmp);
    }
}

impl BlockDecryptMut for DesEde3CbcDec {
    fn decrypt_with_backend_mut(
        &mut self,
        f: impl BlockClosure<BlockSize = Self::BlockSize>,
    ) {
        f.call(&mut DesEde3CbcDecBackend(self.ctx));
    }
}

//! AES-CBC block cipher (OpenSSL compat API: AES_cbc_encrypt).

use super::*;

// ---------------------------------------------------------------------------
// CBC encrypt backend
// ---------------------------------------------------------------------------

struct AesCbcEncBackend<'a> {
    key: &'a wolfcrypt_rs::AES_KEY,
    iv: &'a mut [u8; 16],
}

impl<'a> BlockSizeUser for AesCbcEncBackend<'a> {
    type BlockSize = U16;
}

impl<'a> ParBlocksSizeUser for AesCbcEncBackend<'a> {
    type ParBlocksSize = U1;
}

impl<'a> BlockBackend for AesCbcEncBackend<'a> {
    #[inline]
    fn proc_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        let (in_ptr, out_ptr) = block.into_raw();
        unsafe {
            wolfcrypt_rs::AES_cbc_encrypt(
                in_ptr as *const u8,
                out_ptr as *mut u8,
                16,
                self.key as *const wolfcrypt_rs::AES_KEY,
                self.iv.as_mut_ptr(),
                wolfcrypt_rs::AES_ENCRYPT,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// CBC decrypt backend
// ---------------------------------------------------------------------------

struct AesCbcDecBackend<'a> {
    key: &'a wolfcrypt_rs::AES_KEY,
    iv: &'a mut [u8; 16],
}

impl<'a> BlockSizeUser for AesCbcDecBackend<'a> {
    type BlockSize = U16;
}

impl<'a> ParBlocksSizeUser for AesCbcDecBackend<'a> {
    type ParBlocksSize = U1;
}

impl<'a> BlockBackend for AesCbcDecBackend<'a> {
    #[inline]
    fn proc_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        let (in_ptr, out_ptr) = block.into_raw();
        unsafe {
            wolfcrypt_rs::AES_cbc_encrypt(
                in_ptr as *const u8,
                out_ptr as *mut u8,
                16,
                self.key as *const wolfcrypt_rs::AES_KEY,
                self.iv.as_mut_ptr(),
                wolfcrypt_rs::AES_DECRYPT,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Macro + concrete types: encrypt
// ---------------------------------------------------------------------------

macro_rules! impl_aes_cbc_enc {
    ($name:ident, $key_size:ty, $key_bits:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            key: wolfcrypt_rs::AES_KEY,
            iv: [u8; 16],
        }

        unsafe impl Send for $name {}

        impl KeySizeUser for $name { type KeySize = $key_size; }
        impl IvSizeUser for $name { type IvSize = U16; }

        impl KeyIvInit for $name {
            fn new(key: &GenericArray<u8, $key_size>, iv: &GenericArray<u8, U16>) -> Self {
                let mut aes_key = wolfcrypt_rs::AES_KEY::zeroed();
                let rc = unsafe {
                    wolfcrypt_rs::AES_set_encrypt_key(
                        key.as_ptr(), $key_bits,
                        &mut aes_key as *mut wolfcrypt_rs::AES_KEY,
                    )
                };
                assert_eq!(rc, 0, "AES_set_encrypt_key failed (invalid key length)");
                let mut iv_buf = [0u8; 16];
                iv_buf.copy_from_slice(iv.as_slice());
                Self { key: aes_key, iv: iv_buf }
            }
        }

        impl BlockSizeUser for $name { type BlockSize = U16; }

        impl BlockEncryptMut for $name {
            fn encrypt_with_backend_mut(
                &mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>,
            ) {
                f.call(&mut AesCbcEncBackend { key: &self.key, iv: &mut self.iv });
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                unsafe { zeroize_aes_key(&mut self.key) };
                self.iv.zeroize();
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Macro + concrete types: decrypt
// ---------------------------------------------------------------------------

macro_rules! impl_aes_cbc_dec {
    ($name:ident, $key_size:ty, $key_bits:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            key: wolfcrypt_rs::AES_KEY,
            iv: [u8; 16],
        }

        unsafe impl Send for $name {}

        impl KeySizeUser for $name { type KeySize = $key_size; }
        impl IvSizeUser for $name { type IvSize = U16; }

        impl KeyIvInit for $name {
            fn new(key: &GenericArray<u8, $key_size>, iv: &GenericArray<u8, U16>) -> Self {
                let mut aes_key = wolfcrypt_rs::AES_KEY::zeroed();
                let rc = unsafe {
                    wolfcrypt_rs::AES_set_decrypt_key(
                        key.as_ptr(), $key_bits,
                        &mut aes_key as *mut wolfcrypt_rs::AES_KEY,
                    )
                };
                assert_eq!(rc, 0, "AES_set_decrypt_key failed (invalid key length)");
                let mut iv_buf = [0u8; 16];
                iv_buf.copy_from_slice(iv.as_slice());
                Self { key: aes_key, iv: iv_buf }
            }
        }

        impl BlockSizeUser for $name { type BlockSize = U16; }

        impl BlockDecryptMut for $name {
            fn decrypt_with_backend_mut(
                &mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>,
            ) {
                f.call(&mut AesCbcDecBackend { key: &self.key, iv: &mut self.iv });
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                unsafe { zeroize_aes_key(&mut self.key) };
                self.iv.zeroize();
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Concrete CBC types
// ---------------------------------------------------------------------------

impl_aes_cbc_enc!(Aes128CbcEnc, typenum::U16, 128,
    "AES-128 CBC encryption, implementing `BlockEncryptMut` and `KeyIvInit`.");
impl_aes_cbc_dec!(Aes128CbcDec, typenum::U16, 128,
    "AES-128 CBC decryption, implementing `BlockDecryptMut` and `KeyIvInit`.");

#[cfg(wolfssl_aes_192)]
impl_aes_cbc_enc!(Aes192CbcEnc, typenum::U24, 192,
    "AES-192 CBC encryption, implementing `BlockEncryptMut` and `KeyIvInit`.");
#[cfg(wolfssl_aes_192)]
impl_aes_cbc_dec!(Aes192CbcDec, typenum::U24, 192,
    "AES-192 CBC decryption, implementing `BlockDecryptMut` and `KeyIvInit`.");

impl_aes_cbc_enc!(Aes256CbcEnc, typenum::U32, 256,
    "AES-256 CBC encryption, implementing `BlockEncryptMut` and `KeyIvInit`.");
impl_aes_cbc_dec!(Aes256CbcDec, typenum::U32, 256,
    "AES-256 CBC decryption, implementing `BlockDecryptMut` and `KeyIvInit`.");

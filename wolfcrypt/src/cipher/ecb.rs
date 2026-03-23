//! AES-ECB block cipher (OpenSSL compat API).

use super::*;

// ---------------------------------------------------------------------------
// Shared backends — call AES_ecb_encrypt in the appropriate direction.
// ---------------------------------------------------------------------------

struct AesEcbEncBackend<'a>(&'a wolfcrypt_rs::AES_KEY);

impl<'a> BlockSizeUser for AesEcbEncBackend<'a> {
    type BlockSize = U16;
}

impl<'a> ParBlocksSizeUser for AesEcbEncBackend<'a> {
    type ParBlocksSize = U1;
}

impl<'a> BlockBackend for AesEcbEncBackend<'a> {
    #[inline]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut tmp = [0u8; 16];
        // SAFETY: `block.get_in()` is a valid 16-byte input, `tmp` is a valid
        // 16-byte output, and `self.0` was initialised by `AES_set_encrypt_key`.
        // `AES_ENCRYPT` (0) selects the encryption direction.
        unsafe {
            wolfcrypt_rs::AES_ecb_encrypt(
                block.get_in().as_ptr(),
                tmp.as_mut_ptr(),
                self.0 as *const wolfcrypt_rs::AES_KEY,
                wolfcrypt_rs::AES_ENCRYPT,
            );
        }
        block.get_out().copy_from_slice(&tmp);
    }
}

struct AesEcbDecBackend<'a>(&'a wolfcrypt_rs::AES_KEY);

impl<'a> BlockSizeUser for AesEcbDecBackend<'a> {
    type BlockSize = U16;
}

impl<'a> ParBlocksSizeUser for AesEcbDecBackend<'a> {
    type ParBlocksSize = U1;
}

impl<'a> BlockBackend for AesEcbDecBackend<'a> {
    #[inline]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut tmp = [0u8; 16];
        // SAFETY: `block.get_in()` is a valid 16-byte input, `tmp` is a valid
        // 16-byte output, and `self.0` was initialised by `AES_set_decrypt_key`.
        // `AES_DECRYPT` (1) selects the decryption direction.
        unsafe {
            wolfcrypt_rs::AES_ecb_encrypt(
                block.get_in().as_ptr(),
                tmp.as_mut_ptr(),
                self.0 as *const wolfcrypt_rs::AES_KEY,
                wolfcrypt_rs::AES_DECRYPT,
            );
        }
        block.get_out().copy_from_slice(&tmp);
    }
}

// ---------------------------------------------------------------------------
// Macro + concrete types
// ---------------------------------------------------------------------------

macro_rules! impl_aes_ecb_enc {
    ($name:ident, $key_size:ty, $key_bits:expr) => {
        /// AES-ECB encryption cipher.
        pub struct $name {
            key: wolfcrypt_rs::AES_KEY,
        }

        unsafe impl Send for $name {}

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                let mut aes_key = wolfcrypt_rs::AES_KEY::zeroed();
                let rc = unsafe {
                    wolfcrypt_rs::AES_set_encrypt_key(
                        key.as_ptr(),
                        $key_bits,
                        &mut aes_key as *mut wolfcrypt_rs::AES_KEY,
                    )
                };
                assert_eq!(rc, 0, "AES_set_encrypt_key failed (invalid key length)");
                Self { key: aes_key }
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = U16;
        }

        impl BlockCipher for $name {}

        impl BlockEncrypt for $name {
            fn encrypt_with_backend(
                &self,
                f: impl BlockClosure<BlockSize = Self::BlockSize>,
            ) {
                f.call(&mut AesEcbEncBackend(&self.key));
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe { zeroize_aes_key(&mut self.key) };
            }
        }
    };
}

macro_rules! impl_aes_ecb_dec {
    ($name:ident, $key_size:ty, $key_bits:expr) => {
        /// AES-ECB decryption cipher.
        pub struct $name {
            key: wolfcrypt_rs::AES_KEY,
        }

        unsafe impl Send for $name {}

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                let mut aes_key = wolfcrypt_rs::AES_KEY::zeroed();
                let rc = unsafe {
                    wolfcrypt_rs::AES_set_decrypt_key(
                        key.as_ptr(),
                        $key_bits,
                        &mut aes_key as *mut wolfcrypt_rs::AES_KEY,
                    )
                };
                assert_eq!(rc, 0, "AES_set_decrypt_key failed (invalid key length)");
                Self { key: aes_key }
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = U16;
        }

        impl BlockCipher for $name {}

        impl BlockDecrypt for $name {
            fn decrypt_with_backend(
                &self,
                f: impl BlockClosure<BlockSize = Self::BlockSize>,
            ) {
                f.call(&mut AesEcbDecBackend(&self.key));
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe { zeroize_aes_key(&mut self.key) };
            }
        }
    };
}

impl_aes_ecb_enc!(Aes128EcbEnc, typenum::U16, 128);
impl_aes_ecb_dec!(Aes128EcbDec, typenum::U16, 128);

#[cfg(wolfssl_aes_192)]
impl_aes_ecb_enc!(Aes192EcbEnc, typenum::U24, 192);
#[cfg(wolfssl_aes_192)]
impl_aes_ecb_dec!(Aes192EcbDec, typenum::U24, 192);

impl_aes_ecb_enc!(Aes256EcbEnc, typenum::U32, 256);
impl_aes_ecb_dec!(Aes256EcbDec, typenum::U32, 256);

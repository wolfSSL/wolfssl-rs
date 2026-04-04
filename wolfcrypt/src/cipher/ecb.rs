//! AES-ECB block cipher (native wolfCrypt wc_Aes* API).

use super::*;

struct AesEcbEncBackend<'a>(&'a wolfcrypt_rs::WcAes);

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
        // SAFETY: wc_AesEcbEncrypt does not modify the key schedule in self.0;
        // the *mut cast is required by the C API signature only.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesEcbEncrypt(
                self.0 as *const wolfcrypt_rs::WcAes as *mut wolfcrypt_rs::WcAes,
                tmp.as_mut_ptr(),
                block.get_in().as_ptr(),
                16,
            )
        };
        assert_eq!(rc, 0, "wc_AesEcbEncrypt failed");
        block.get_out().copy_from_slice(&tmp);
    }
}

struct AesEcbDecBackend<'a>(&'a wolfcrypt_rs::WcAes);

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
        // SAFETY: wc_AesEcbDecrypt does not modify the key schedule in self.0;
        // the *mut cast is required by the C API signature only.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesEcbDecrypt(
                self.0 as *const wolfcrypt_rs::WcAes as *mut wolfcrypt_rs::WcAes,
                tmp.as_mut_ptr(),
                block.get_in().as_ptr(),
                16,
            )
        };
        assert_eq!(rc, 0, "wc_AesEcbDecrypt failed");
        block.get_out().copy_from_slice(&tmp);
    }
}

macro_rules! impl_aes_ecb_enc {
    ($name:ident, $key_size:ty, $key_bytes:expr) => {
        /// AES-ECB encryption cipher.
        pub struct $name {
            aes: wolfcrypt_rs::WcAes,
        }

        unsafe impl Send for $name {}

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                let mut aes = wolfcrypt_rs::WcAes::zeroed();
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesInit(
                        &mut aes as *mut wolfcrypt_rs::WcAes,
                        core::ptr::null_mut(),
                        wolfcrypt_rs::INVALID_DEVID,
                    )
                };
                assert_eq!(rc, 0, "wc_AesInit failed");
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesSetKey(
                        &mut aes as *mut wolfcrypt_rs::WcAes,
                        key.as_ptr(),
                        $key_bytes,
                        core::ptr::null(),
                        wolfcrypt_rs::AES_ENCRYPT,
                    )
                };
                assert_eq!(rc, 0, "wc_AesSetKey failed (invalid key length)");
                Self { aes }
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
                f.call(&mut AesEcbEncBackend(&self.aes));
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: self.aes was initialised by wc_AesInit.
                unsafe {
                    wolfcrypt_rs::wc_AesFree(&mut self.aes as *mut wolfcrypt_rs::WcAes);
                }
            }
        }
    };
}

macro_rules! impl_aes_ecb_dec {
    ($name:ident, $key_size:ty, $key_bytes:expr) => {
        /// AES-ECB decryption cipher.
        pub struct $name {
            aes: wolfcrypt_rs::WcAes,
        }

        unsafe impl Send for $name {}

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                let mut aes = wolfcrypt_rs::WcAes::zeroed();
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesInit(
                        &mut aes as *mut wolfcrypt_rs::WcAes,
                        core::ptr::null_mut(),
                        wolfcrypt_rs::INVALID_DEVID,
                    )
                };
                assert_eq!(rc, 0, "wc_AesInit failed");
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesSetKey(
                        &mut aes as *mut wolfcrypt_rs::WcAes,
                        key.as_ptr(),
                        $key_bytes,
                        core::ptr::null(),
                        wolfcrypt_rs::AES_DECRYPT,
                    )
                };
                assert_eq!(rc, 0, "wc_AesSetKey failed (invalid key length)");
                Self { aes }
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
                f.call(&mut AesEcbDecBackend(&self.aes));
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: self.aes was initialised by wc_AesInit.
                unsafe {
                    wolfcrypt_rs::wc_AesFree(&mut self.aes as *mut wolfcrypt_rs::WcAes);
                }
            }
        }
    };
}

impl_aes_ecb_enc!(Aes128EcbEnc, typenum::U16, 16u32);
impl_aes_ecb_dec!(Aes128EcbDec, typenum::U16, 16u32);

#[cfg(wolfssl_aes_192)]
impl_aes_ecb_enc!(Aes192EcbEnc, typenum::U24, 24u32);
#[cfg(wolfssl_aes_192)]
impl_aes_ecb_dec!(Aes192EcbDec, typenum::U24, 24u32);

impl_aes_ecb_enc!(Aes256EcbEnc, typenum::U32, 32u32);
impl_aes_ecb_dec!(Aes256EcbDec, typenum::U32, 32u32);

//! AES-CBC block cipher (native wolfCrypt wc_Aes* API).

use super::*;

struct AesCbcEncBackend<'a>(&'a mut wolfcrypt_rs::WcAes);

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
        // SAFETY: in_ptr and out_ptr are valid 16-byte block pointers.
        // wc_AesCbcEncrypt updates the IV state inside self.0 after each block.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesCbcEncrypt(self.0, out_ptr as *mut u8, in_ptr as *const u8, 16)
        };
        assert_eq!(rc, 0, "wc_AesCbcEncrypt failed");
    }
}

struct AesCbcDecBackend<'a>(&'a mut wolfcrypt_rs::WcAes);

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
        // SAFETY: in_ptr and out_ptr are valid 16-byte block pointers.
        // wc_AesCbcDecrypt updates the IV state inside self.0 after each block.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesCbcDecrypt(self.0, out_ptr as *mut u8, in_ptr as *const u8, 16)
        };
        assert_eq!(rc, 0, "wc_AesCbcDecrypt failed");
    }
}

macro_rules! impl_aes_cbc_enc {
    ($name:ident, $key_size:ty, $key_bytes:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            aes: wolfcrypt_rs::WcAes,
        }

        unsafe impl Send for $name {}

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl IvSizeUser for $name {
            type IvSize = U16;
        }

        impl KeyIvInit for $name {
            fn new(key: &GenericArray<u8, $key_size>, iv: &GenericArray<u8, U16>) -> Self {
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
                        iv.as_ptr(),
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

        impl BlockEncryptMut for $name {
            fn encrypt_with_backend_mut(
                &mut self,
                f: impl BlockClosure<BlockSize = Self::BlockSize>,
            ) {
                f.call(&mut AesCbcEncBackend(&mut self.aes));
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

macro_rules! impl_aes_cbc_dec {
    ($name:ident, $key_size:ty, $key_bytes:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            aes: wolfcrypt_rs::WcAes,
        }

        unsafe impl Send for $name {}

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl IvSizeUser for $name {
            type IvSize = U16;
        }

        impl KeyIvInit for $name {
            fn new(key: &GenericArray<u8, $key_size>, iv: &GenericArray<u8, U16>) -> Self {
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
                        iv.as_ptr(),
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

        impl BlockDecryptMut for $name {
            fn decrypt_with_backend_mut(
                &mut self,
                f: impl BlockClosure<BlockSize = Self::BlockSize>,
            ) {
                f.call(&mut AesCbcDecBackend(&mut self.aes));
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

impl_aes_cbc_enc!(Aes128CbcEnc, typenum::U16, 16u32,
    "AES-128 CBC encryption, implementing `BlockEncryptMut` and `KeyIvInit`.");
impl_aes_cbc_dec!(Aes128CbcDec, typenum::U16, 16u32,
    "AES-128 CBC decryption, implementing `BlockDecryptMut` and `KeyIvInit`.");

#[cfg(wolfssl_aes_192)]
impl_aes_cbc_enc!(Aes192CbcEnc, typenum::U24, 24u32,
    "AES-192 CBC encryption, implementing `BlockEncryptMut` and `KeyIvInit`.");
#[cfg(wolfssl_aes_192)]
impl_aes_cbc_dec!(Aes192CbcDec, typenum::U24, 24u32,
    "AES-192 CBC decryption, implementing `BlockDecryptMut` and `KeyIvInit`.");

impl_aes_cbc_enc!(Aes256CbcEnc, typenum::U32, 32u32,
    "AES-256 CBC encryption, implementing `BlockEncryptMut` and `KeyIvInit`.");
impl_aes_cbc_dec!(Aes256CbcDec, typenum::U32, 32u32,
    "AES-256 CBC decryption, implementing `BlockDecryptMut` and `KeyIvInit`.");

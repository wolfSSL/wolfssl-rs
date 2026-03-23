//! AES-CFB128 stream cipher (OpenSSL compat API: AES_cfb128_encrypt).
//!
//! CFB128 is a self-synchronizing stream cipher mode. Unlike CTR, encrypt and
//! decrypt are NOT the same operation — the feedback loop differs — so we
//! define separate Enc and Dec types.
//!
//! We always use `AES_set_encrypt_key` regardless of direction, because CFB
//! mode only uses the AES-encrypt primitive internally.

use super::*;

// ---------------------------------------------------------------------------
// CFB encrypt
// ---------------------------------------------------------------------------

macro_rules! impl_aes_cfb_enc {
    ($name:ident, $key_size:ty, $key_bits:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            key: wolfcrypt_rs::AES_KEY,
            iv: [u8; 16],
            num: core::ffi::c_int,
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
                Self { key: aes_key, iv: iv_buf, num: 0 }
            }
        }

        impl StreamCipher for $name {
            fn try_apply_keystream_inout(
                &mut self, buf: cipher_trait::inout::InOutBuf<'_, '_, u8>,
            ) -> Result<(), StreamCipherError> {
                let len = buf.len();
                let (in_ptr, out_ptr) = buf.into_raw();
                unsafe {
                    wolfcrypt_rs::AES_cfb128_encrypt(
                        in_ptr, out_ptr, len,
                        &self.key as *const wolfcrypt_rs::AES_KEY,
                        self.iv.as_mut_ptr(), &mut self.num,
                        wolfcrypt_rs::AES_ENCRYPT,
                    );
                }
                Ok(())
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                unsafe { zeroize_aes_key(&mut self.key) };
                self.iv.zeroize();
                self.num = 0;
            }
        }
    };
}

// ---------------------------------------------------------------------------
// CFB decrypt
// ---------------------------------------------------------------------------

macro_rules! impl_aes_cfb_dec {
    ($name:ident, $key_size:ty, $key_bits:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            key: wolfcrypt_rs::AES_KEY,
            iv: [u8; 16],
            num: core::ffi::c_int,
        }

        unsafe impl Send for $name {}

        impl KeySizeUser for $name { type KeySize = $key_size; }
        impl IvSizeUser for $name { type IvSize = U16; }

        impl KeyIvInit for $name {
            fn new(key: &GenericArray<u8, $key_size>, iv: &GenericArray<u8, U16>) -> Self {
                let mut aes_key = wolfcrypt_rs::AES_KEY::zeroed();
                // CFB mode always uses the AES-encrypt key schedule, even for
                // decryption.
                let rc = unsafe {
                    wolfcrypt_rs::AES_set_encrypt_key(
                        key.as_ptr(), $key_bits,
                        &mut aes_key as *mut wolfcrypt_rs::AES_KEY,
                    )
                };
                assert_eq!(rc, 0, "AES_set_encrypt_key failed (invalid key length)");
                let mut iv_buf = [0u8; 16];
                iv_buf.copy_from_slice(iv.as_slice());
                Self { key: aes_key, iv: iv_buf, num: 0 }
            }
        }

        impl StreamCipher for $name {
            fn try_apply_keystream_inout(
                &mut self, buf: cipher_trait::inout::InOutBuf<'_, '_, u8>,
            ) -> Result<(), StreamCipherError> {
                let len = buf.len();
                let (in_ptr, out_ptr) = buf.into_raw();
                unsafe {
                    wolfcrypt_rs::AES_cfb128_encrypt(
                        in_ptr, out_ptr, len,
                        &self.key as *const wolfcrypt_rs::AES_KEY,
                        self.iv.as_mut_ptr(), &mut self.num,
                        wolfcrypt_rs::AES_DECRYPT,
                    );
                }
                Ok(())
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                unsafe { zeroize_aes_key(&mut self.key) };
                self.iv.zeroize();
                self.num = 0;
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Concrete types
// ---------------------------------------------------------------------------

impl_aes_cfb_enc!(Aes128CfbEnc, typenum::U16, 128,
    "AES-128 CFB128 encryption, implementing `StreamCipher` and `KeyIvInit`.");
impl_aes_cfb_dec!(Aes128CfbDec, typenum::U16, 128,
    "AES-128 CFB128 decryption, implementing `StreamCipher` and `KeyIvInit`.");

#[cfg(wolfssl_aes_192)]
impl_aes_cfb_enc!(Aes192CfbEnc, typenum::U24, 192,
    "AES-192 CFB128 encryption, implementing `StreamCipher` and `KeyIvInit`.");
#[cfg(wolfssl_aes_192)]
impl_aes_cfb_dec!(Aes192CfbDec, typenum::U24, 192,
    "AES-192 CFB128 decryption, implementing `StreamCipher` and `KeyIvInit`.");

impl_aes_cfb_enc!(Aes256CfbEnc, typenum::U32, 256,
    "AES-256 CFB128 encryption, implementing `StreamCipher` and `KeyIvInit`.");
impl_aes_cfb_dec!(Aes256CfbDec, typenum::U32, 256,
    "AES-256 CFB128 decryption, implementing `StreamCipher` and `KeyIvInit`.");

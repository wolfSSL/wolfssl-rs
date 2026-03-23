//! AES-OFB stream cipher (wolfCrypt native API).
//!
//! OFB (Output Feedback) is a stream cipher mode that generates a keystream
//! by repeatedly encrypting the IV/feedback value.  The keystream is XORed
//! with plaintext to produce ciphertext, making encrypt and decrypt the same
//! operation.  We use `wc_AesOfbEncrypt` for the `StreamCipher` impl since
//! OFB encryption and decryption are symmetric.

use super::*;
use crate::error::len_as_u32;

macro_rules! impl_aes_ofb {
    ($name:ident, $key_size:ty, $key_bytes:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            aes: wolfcrypt_rs::WcAes,
        }

        unsafe impl Send for $name {}

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe {
                    wolfcrypt_rs::wc_AesFree(&mut self.aes as *mut wolfcrypt_rs::WcAes);
                }
            }
        }

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
                assert_eq!(rc, 0, "wc_AesInit failed (OOM or invalid device)");

                let rc = unsafe {
                    wolfcrypt_rs::wc_AesSetKey(
                        &mut aes as *mut wolfcrypt_rs::WcAes,
                        key.as_ptr(),
                        $key_bytes,
                        iv.as_ptr(),
                        wolfcrypt_rs::AES_ENCRYPT,
                    )
                };
                assert_eq!(rc, 0, "wc_AesSetKey failed (invalid key length or IV)");

                Self { aes }
            }
        }

        impl StreamCipher for $name {
            fn try_apply_keystream_inout(
                &mut self,
                buf: cipher_trait::inout::InOutBuf<'_, '_, u8>,
            ) -> Result<(), StreamCipherError> {
                let len = buf.len();
                let (in_ptr, out_ptr) = buf.into_raw();

                let rc = unsafe {
                    wolfcrypt_rs::wc_AesOfbEncrypt(
                        &mut self.aes as *mut wolfcrypt_rs::WcAes,
                        out_ptr,
                        in_ptr,
                        len_as_u32(len),
                    )
                };
                if rc == 0 {
                    Ok(())
                } else {
                    Err(StreamCipherError)
                }
            }
        }
    };
}

impl_aes_ofb!(
    Aes128Ofb,
    typenum::U16,
    16u32,
    "AES-128 in OFB mode, implementing `StreamCipher` and `KeyIvInit`."
);

#[cfg(wolfssl_aes_192)]
impl_aes_ofb!(
    Aes192Ofb,
    typenum::U24,
    24u32,
    "AES-192 in OFB mode, implementing `StreamCipher` and `KeyIvInit`."
);

impl_aes_ofb!(
    Aes256Ofb,
    typenum::U32,
    32u32,
    "AES-256 in OFB mode, implementing `StreamCipher` and `KeyIvInit`."
);

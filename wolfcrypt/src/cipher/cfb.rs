//! AES-CFB-128 stream cipher backed by native wolfCrypt `wc_AesCfbEncrypt` /
//! `wc_AesCfbDecrypt`.
//!
//! CFB is a self-synchronizing stream cipher.  Unlike OFB or CTR, the feedback
//! path differs between encryption and decryption, so separate `Enc` and `Dec`
//! types are required.  Both directions use the **AES encrypt key schedule**
//! (there is no CFB decrypt schedule).
//!
//! IV state and the partial-block counter are maintained **inside the `WcAes`
//! struct** by wolfCrypt; callers do not need to manage them.

use super::*;
use crate::error::len_as_u32;

// ---------------------------------------------------------------------------
// CFB encrypt
// ---------------------------------------------------------------------------

macro_rules! impl_aes_cfb_enc {
    ($name:ident, $key_size:ty, $key_bytes:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            aes: wolfcrypt_rs::WcAes,
        }

        unsafe impl Send for $name {}

        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: `aes` was successfully initialised in `new`.
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

                // SAFETY: `aes` is zero-initialised; INVALID_DEVID selects
                // software-only operation.
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesInit(
                        &mut aes as *mut wolfcrypt_rs::WcAes,
                        core::ptr::null_mut(),
                        wolfcrypt_rs::INVALID_DEVID,
                    )
                };
                assert_eq!(rc, 0, "wc_AesInit failed (OOM or invalid device)");

                // CFB always uses the AES encrypt key schedule, even for
                // decryption.
                // SAFETY: `aes` is initialised; key and IV buffers are valid.
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

                // SAFETY: `aes` is live; in/out pointers are valid for `len`
                // bytes; in-place aliasing is safe because CFB processes bytes
                // sequentially.
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesCfbEncrypt(
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

// ---------------------------------------------------------------------------
// CFB decrypt
// ---------------------------------------------------------------------------

macro_rules! impl_aes_cfb_dec {
    ($name:ident, $key_size:ty, $key_bytes:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            aes: wolfcrypt_rs::WcAes,
        }

        unsafe impl Send for $name {}

        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: `aes` was successfully initialised in `new`.
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

                // SAFETY: `aes` is zero-initialised.
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesInit(
                        &mut aes as *mut wolfcrypt_rs::WcAes,
                        core::ptr::null_mut(),
                        wolfcrypt_rs::INVALID_DEVID,
                    )
                };
                assert_eq!(rc, 0, "wc_AesInit failed (OOM or invalid device)");

                // CFB decryption also uses the AES encrypt key schedule.
                // SAFETY: `aes` is initialised; key and IV buffers are valid.
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

                // SAFETY: `aes` is live; in/out pointers are valid for `len`
                // bytes.  CFB decrypt uses a different feedback path than
                // encrypt but is otherwise identical at the call level.
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesCfbDecrypt(
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

// ---------------------------------------------------------------------------
// Concrete types
// ---------------------------------------------------------------------------

impl_aes_cfb_enc!(
    Aes128CfbEnc,
    typenum::U16,
    16u32,
    "AES-128 CFB-128 encryption, implementing `StreamCipher` and `KeyIvInit`."
);
impl_aes_cfb_dec!(
    Aes128CfbDec,
    typenum::U16,
    16u32,
    "AES-128 CFB-128 decryption, implementing `StreamCipher` and `KeyIvInit`."
);

#[cfg(wolfssl_aes_192)]
impl_aes_cfb_enc!(
    Aes192CfbEnc,
    typenum::U24,
    24u32,
    "AES-192 CFB-128 encryption, implementing `StreamCipher` and `KeyIvInit`."
);
#[cfg(wolfssl_aes_192)]
impl_aes_cfb_dec!(
    Aes192CfbDec,
    typenum::U24,
    24u32,
    "AES-192 CFB-128 decryption, implementing `StreamCipher` and `KeyIvInit`."
);

impl_aes_cfb_enc!(
    Aes256CfbEnc,
    typenum::U32,
    32u32,
    "AES-256 CFB-128 encryption, implementing `StreamCipher` and `KeyIvInit`."
);
impl_aes_cfb_dec!(
    Aes256CfbDec,
    typenum::U32,
    32u32,
    "AES-256 CFB-128 decryption, implementing `StreamCipher` and `KeyIvInit`."
);

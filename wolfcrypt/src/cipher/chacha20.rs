//! ChaCha20 stream cipher (wolfCrypt native API).

use super::*;
use crate::error::len_as_u32;

/// ChaCha20 stream cipher (256-bit key, 96-bit nonce), implementing
/// `StreamCipher` and `KeyIvInit`.
///
/// Uses wolfCrypt's native `wc_Chacha_Process`, which XORs the input with the
/// ChaCha20 keystream. Because XOR is self-inverse, the same operation handles
/// both encryption and decryption.
pub struct WolfChaCha20 {
    ctx: wolfcrypt_rs::ChaCha,
}

// SAFETY: ChaCha contains no thread-local state; it is safe to move to
// another thread.
unsafe impl Send for WolfChaCha20 {}

impl Drop for WolfChaCha20 {
    fn drop(&mut self) {
        // ChaCha is stack-allocated with no wc_Free equivalent, but we zero
        // the state for defence-in-depth.
        // SAFETY: We have exclusive access (&mut self). We zero the raw bytes
        // of the struct using write_bytes, which does not read the memory and
        // thus avoids UB from padding or uninitialized bytes.
        unsafe {
            core::ptr::write_bytes(
                &mut self.ctx as *mut wolfcrypt_rs::ChaCha as *mut u8,
                0,
                core::mem::size_of::<wolfcrypt_rs::ChaCha>(),
            );
        }
    }
}

impl KeySizeUser for WolfChaCha20 {
    type KeySize = typenum::U32; // 256-bit key
}

impl IvSizeUser for WolfChaCha20 {
    type IvSize = typenum::U12; // 96-bit nonce
}

impl KeyIvInit for WolfChaCha20 {
    fn new(key: &GenericArray<u8, typenum::U32>, nonce: &GenericArray<u8, typenum::U12>) -> Self {
        let mut ctx = wolfcrypt_rs::ChaCha::zeroed();

        let rc = unsafe {
            wolfcrypt_rs::wc_Chacha_SetKey(&mut ctx as *mut wolfcrypt_rs::ChaCha, key.as_ptr(), 32)
        };
        assert_eq!(rc, 0, "wc_Chacha_SetKey failed (invalid key length)");

        let rc = unsafe {
            wolfcrypt_rs::wc_Chacha_SetIV(&mut ctx as *mut wolfcrypt_rs::ChaCha, nonce.as_ptr(), 0)
        };
        assert_eq!(rc, 0, "wc_Chacha_SetIV failed (invalid IV)");

        Self { ctx }
    }
}

impl StreamCipher for WolfChaCha20 {
    fn try_apply_keystream_inout(
        &mut self,
        buf: cipher_trait::inout::InOutBuf<'_, '_, u8>,
    ) -> Result<(), StreamCipherError> {
        let len = buf.len();
        let (in_ptr, out_ptr) = buf.into_raw();

        let rc = unsafe {
            wolfcrypt_rs::wc_Chacha_Process(
                &mut self.ctx as *mut wolfcrypt_rs::ChaCha,
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

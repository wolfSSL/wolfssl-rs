use crate::wolfcrypt_rs::{BN_bin2bn, BN_bn2bin, BN_new, BN_num_bytes, BN_set_word, BIGNUM};
use crate::ptr::{ConstPointer, DetachableLcPtr, LcPtr};
use core::ffi::c_int;
use core::ptr::null_mut;

#[cfg(not(feature = "std"))]
use crate::prelude::*;

impl TryFrom<&[u8]> for LcPtr<BIGNUM> {
    type Error = ();

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // SAFETY: pointer and length derived from a valid Rust slice; null_mut for output alloc.
        unsafe { LcPtr::new(BN_bin2bn(bytes.as_ptr(), bytes.len() as c_int, null_mut())) }
    }
}

impl TryFrom<&[u8]> for DetachableLcPtr<BIGNUM> {
    type Error = ();

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // SAFETY: pointer and length derived from a valid Rust slice; null_mut for output alloc.
        unsafe { DetachableLcPtr::new(BN_bin2bn(bytes.as_ptr(), bytes.len() as c_int, null_mut())) }
    }
}

impl TryFrom<u64> for DetachableLcPtr<BIGNUM> {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        // SAFETY: BN_new allocates a new BIGNUM; BN_set_word sets its value.
        unsafe {
            let mut bn = DetachableLcPtr::new(BN_new())?;
            if 1 != BN_set_word(bn.as_mut_ptr(), value as core::ffi::c_ulong) {
                return Err(());
            }
            Ok(bn)
        }
    }
}

impl ConstPointer<'_, BIGNUM> {
    pub(crate) fn to_be_bytes(&self) -> Vec<u8> {
        // SAFETY: BIGNUM pointer is valid; BN_num_bytes/BN_bn2bin read from it.
        unsafe {
            let bn_bytes = BN_num_bytes(self.as_const_ptr()) as usize;
            let mut byte_vec = Vec::with_capacity(bn_bytes);
            let out_bytes = BN_bn2bin(self.as_const_ptr(), byte_vec.as_mut_ptr()) as usize;
            debug_assert_eq!(out_bytes, bn_bytes);
            byte_vec.set_len(out_bytes);
            byte_vec
        }
    }
}

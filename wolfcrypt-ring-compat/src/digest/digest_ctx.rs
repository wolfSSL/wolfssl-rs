use crate::digest::{match_digest_type, Algorithm};
use crate::error::Unspecified;
use crate::ptr::LcPtr;
use crate::wolfcrypt_rs::{EVP_DigestInit_ex, EVP_MD_CTX_copy, EVP_MD_CTX_new, EVP_MD_CTX};
use core::ptr::null_mut;

pub(crate) struct DigestContext(LcPtr<EVP_MD_CTX>);

impl DigestContext {
    pub fn new(algorithm: &'static Algorithm) -> Result<DigestContext, Unspecified> {
        let evp_md_type = match_digest_type(&algorithm.id);
        // SAFETY: EVP_MD_CTX_new returns a heap-allocated context or null (checked by LcPtr::new).
        let mut ctx = LcPtr::new(unsafe { EVP_MD_CTX_new() }).map_err(|_| Unspecified)?;
        // SAFETY: ctx is valid (just allocated); evp_md_type is a valid static pointer.
        unsafe {
            if 1 != EVP_DigestInit_ex(ctx.as_mut_ptr(), evp_md_type.as_const_ptr(), null_mut()) {
                return Err(Unspecified);
            }
        }
        Ok(DigestContext(ctx))
    }

    /// Allocate a new context without binding it to a digest algorithm.
    /// Used by EVP_DigestSignInit / EVP_DigestVerifyInit which do their own init.
    pub fn new_uninit() -> Result<DigestContext, Unspecified> {
        // SAFETY: EVP_MD_CTX_new returns a heap-allocated context or null (checked by LcPtr::new).
        let ctx = LcPtr::new(unsafe { EVP_MD_CTX_new() }).map_err(|_| Unspecified)?;
        Ok(DigestContext(ctx))
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut EVP_MD_CTX {
        self.0.as_mut_ptr()
    }

    pub(crate) fn as_ptr(&self) -> *const EVP_MD_CTX {
        self.0.as_const_ptr()
    }
}

unsafe impl Send for DigestContext {}
unsafe impl Sync for DigestContext {}

impl Clone for DigestContext {
    fn clone(&self) -> Self {
        // PANIC-SAFETY: Clone trait is infallible; try_clone only fails on OOM which aborts on alloc-error-is-abort targets
        self.try_clone().expect("Unable to clone DigestContext")
    }
}

impl DigestContext {
    fn try_clone(&self) -> Result<Self, &'static str> {
        // SAFETY: EVP_MD_CTX_new returns a heap-allocated context or null (checked by LcPtr::new).
        let mut dc =
            LcPtr::new(unsafe { EVP_MD_CTX_new() }).map_err(|_| "EVP_MD_CTX_new failed")?;
        // SAFETY: both contexts are valid; EVP_MD_CTX_copy performs a deep copy.
        unsafe {
            if 1 != EVP_MD_CTX_copy(dc.as_mut_ptr(), self.as_ptr()) {
                return Err("EVP_MD_CTX_copy failed");
            }
        }
        Ok(Self(dc))
    }
}

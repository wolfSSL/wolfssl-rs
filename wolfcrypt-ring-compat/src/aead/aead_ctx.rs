use crate::cipher::chacha;
use crate::cipher::aes::{AES_128_KEY_LEN, AES_192_KEY_LEN, AES_256_KEY_LEN};
use crate::error::Unspecified;
use crate::wolfcrypt_rs::{
    wc_AesDelete, wc_AesGcmDecrypt, wc_AesGcmEncrypt, wc_AesGcmSetKey, wc_AesNew,
    wc_ChaCha20Poly1305_Decrypt, wc_ChaCha20Poly1305_Encrypt, INVALID_DEVID,
};

#[cfg(not(feature = "std"))]
use crate::prelude::*;

const AES_GCM_TAG_LEN: usize = 16;
const MAX_KEY_LEN: usize = 32;

#[allow(
    clippy::large_enum_variant,
    variant_size_differences,
    non_camel_case_types
)]
pub(crate) enum AeadCtx {
    AES_128_GCM(AeadKey),
    AES_192_GCM(AeadKey),
    AES_256_GCM(AeadKey),
    CHACHA20_POLY1305(AeadKey),
}

/// Holds the raw key material and tag length for an AEAD context.
pub(crate) struct AeadKey {
    key: [u8; MAX_KEY_LEN],
    key_len: usize,
    tag_len: usize,
}

unsafe impl Send for AeadCtx {}
unsafe impl Sync for AeadCtx {}

impl AeadCtx {
    pub(crate) fn aes_128_gcm(key_bytes: &[u8], tag_len: usize) -> Result<Self, Unspecified> {
        if AES_128_KEY_LEN != key_bytes.len() || tag_len > AES_GCM_TAG_LEN {
            return Err(Unspecified);
        }
        Ok(AeadCtx::AES_128_GCM(AeadKey::new(key_bytes, tag_len)))
    }

    pub(crate) fn aes_192_gcm(key_bytes: &[u8], tag_len: usize) -> Result<Self, Unspecified> {
        if AES_192_KEY_LEN != key_bytes.len() || tag_len > AES_GCM_TAG_LEN {
            return Err(Unspecified);
        }
        Ok(AeadCtx::AES_192_GCM(AeadKey::new(key_bytes, tag_len)))
    }

    pub(crate) fn aes_256_gcm(key_bytes: &[u8], tag_len: usize) -> Result<Self, Unspecified> {
        if AES_256_KEY_LEN != key_bytes.len() || tag_len > AES_GCM_TAG_LEN {
            return Err(Unspecified);
        }
        Ok(AeadCtx::AES_256_GCM(AeadKey::new(key_bytes, tag_len)))
    }

    pub(crate) fn chacha20(key_bytes: &[u8], tag_len: usize) -> Result<Self, Unspecified> {
        if chacha::KEY_LEN != key_bytes.len() || tag_len > 16 {
            return Err(Unspecified);
        }
        Ok(AeadCtx::CHACHA20_POLY1305(AeadKey::new(key_bytes, tag_len)))
    }

    #[inline]
    pub(crate) fn key(&self) -> &AeadKey {
        match self {
            AeadCtx::AES_128_GCM(k) | AeadCtx::AES_192_GCM(k) | AeadCtx::AES_256_GCM(k) | AeadCtx::CHACHA20_POLY1305(k) => k,
        }
    }

    #[inline]
    pub(crate) fn tag_len(&self) -> usize {
        self.key().tag_len
    }

    /// AES-GCM seal: encrypts `in_out[..plaintext_len]` in place, writes tag to `tag_out`.
    pub(crate) fn aes_gcm_seal(
        &self,
        nonce: &[u8],
        in_out: &mut [u8],
        plaintext_len: usize,
        ad: &[u8],
        tag_out: &mut [u8],
    ) -> Result<(), Unspecified> {
        let k = self.key();
        // SAFETY: wc_AesNew allocates an AES context; all pointers from valid Rust slices.
        unsafe {
            let aes = wc_AesNew(core::ptr::null_mut(), INVALID_DEVID, core::ptr::null_mut());
            if aes.is_null() { return Err(Unspecified); }
            if wc_AesGcmSetKey(aes, k.key.as_ptr(), k.key_len as u32) != 0 {
                wc_AesDelete(aes, core::ptr::null_mut()); return Err(Unspecified);
            }
            let mut full_tag = [0u8; AES_GCM_TAG_LEN];
            let ret = wc_AesGcmEncrypt(
                aes,
                in_out.as_mut_ptr(),
                in_out.as_ptr(),
                plaintext_len as u32,
                nonce.as_ptr(),
                nonce.len() as u32,
                full_tag.as_mut_ptr(),
                AES_GCM_TAG_LEN as u32,
                ad.as_ptr(),
                ad.len() as u32,
            );
            wc_AesDelete(aes, core::ptr::null_mut());
            if ret != 0 { return Err(Unspecified); }
            let copy_len = core::cmp::min(k.tag_len, tag_out.len());
            tag_out[..copy_len].copy_from_slice(&full_tag[..copy_len]);
            Ok(())
        }
    }

    /// AES-GCM open: decrypts `ciphertext` in place, verifying the tag.
    pub(crate) fn aes_gcm_open(
        &self,
        nonce: &[u8],
        in_out: &mut [u8],
        ciphertext_len: usize,
        tag: &[u8],
        ad: &[u8],
    ) -> Result<(), Unspecified> {
        let k = self.key();
        // SAFETY: wc_AesNew allocates an AES context; all pointers from valid Rust slices.
        unsafe {
            let aes = wc_AesNew(core::ptr::null_mut(), INVALID_DEVID, core::ptr::null_mut());
            if aes.is_null() { return Err(Unspecified); }
            if wc_AesGcmSetKey(aes, k.key.as_ptr(), k.key_len as u32) != 0 {
                wc_AesDelete(aes, core::ptr::null_mut()); return Err(Unspecified);
            }
            let mut full_tag = [0u8; AES_GCM_TAG_LEN];
            let copy_len = core::cmp::min(tag.len(), AES_GCM_TAG_LEN);
            full_tag[..copy_len].copy_from_slice(&tag[..copy_len]);
            let ret = wc_AesGcmDecrypt(
                aes,
                in_out.as_mut_ptr(),
                in_out.as_ptr(),
                ciphertext_len as u32,
                nonce.as_ptr(),
                nonce.len() as u32,
                full_tag.as_ptr(),
                copy_len as u32,
                ad.as_ptr(),
                ad.len() as u32,
            );
            wc_AesDelete(aes, core::ptr::null_mut());
            if ret != 0 { Err(Unspecified) } else { Ok(()) }
        }
    }

    /// ChaCha20-Poly1305 seal: encrypts in place, writes 16-byte tag to `tag_out`.
    pub(crate) fn chacha_seal(
        &self,
        nonce: &[u8],
        in_out: &mut [u8],
        plaintext_len: usize,
        ad: &[u8],
        tag_out: &mut [u8],
    ) -> Result<(), Unspecified> {
        let k = self.key();
        let mut full_tag = [0u8; 16];
        // SAFETY: all pointers derived from valid Rust slices; key is valid.
        let ret = unsafe {
            wc_ChaCha20Poly1305_Encrypt(
                k.key.as_ptr(),
                nonce.as_ptr(),
                ad.as_ptr(),
                ad.len() as u32,
                in_out.as_ptr(),
                plaintext_len as u32,
                in_out.as_mut_ptr(),
                full_tag.as_mut_ptr(),
            )
        };
        if ret != 0 { return Err(Unspecified); }
        let copy_len = core::cmp::min(k.tag_len, tag_out.len());
        tag_out[..copy_len].copy_from_slice(&full_tag[..copy_len]);
        Ok(())
    }

    /// ChaCha20-Poly1305 open: decrypts in place, verifying the tag.
    pub(crate) fn chacha_open(
        &self,
        nonce: &[u8],
        in_out: &mut [u8],
        ciphertext_len: usize,
        tag: &[u8],
        ad: &[u8],
    ) -> Result<(), Unspecified> {
        let k = self.key();
        // SAFETY: all pointers derived from valid Rust slices; key is valid.
        let ret = unsafe {
            wc_ChaCha20Poly1305_Decrypt(
                k.key.as_ptr(),
                nonce.as_ptr(),
                ad.as_ptr(),
                ad.len() as u32,
                in_out.as_ptr(),
                ciphertext_len as u32,
                tag.as_ptr(),
                in_out.as_mut_ptr(),
            )
        };
        if ret != 0 { Err(Unspecified) } else { Ok(()) }
    }

    /// Seal (encrypt + authenticate) dispatching on algorithm.
    pub(crate) fn seal(
        &self,
        nonce: &[u8],
        in_out: &mut [u8],
        plaintext_len: usize,
        ad: &[u8],
        tag_out: &mut [u8],
    ) -> Result<(), Unspecified> {
        match self {
            AeadCtx::AES_128_GCM(_) | AeadCtx::AES_192_GCM(_) | AeadCtx::AES_256_GCM(_) => {
                self.aes_gcm_seal(nonce, in_out, plaintext_len, ad, tag_out)
            }
            AeadCtx::CHACHA20_POLY1305(_) => {
                self.chacha_seal(nonce, in_out, plaintext_len, ad, tag_out)
            }
        }
    }

    /// Open (decrypt + verify) dispatching on algorithm.
    pub(crate) fn open(
        &self,
        nonce: &[u8],
        in_out: &mut [u8],
        ciphertext_len: usize,
        tag: &[u8],
        ad: &[u8],
    ) -> Result<(), Unspecified> {
        match self {
            AeadCtx::AES_128_GCM(_) | AeadCtx::AES_192_GCM(_) | AeadCtx::AES_256_GCM(_) => {
                self.aes_gcm_open(nonce, in_out, ciphertext_len, tag, ad)
            }
            AeadCtx::CHACHA20_POLY1305(_) => {
                self.chacha_open(nonce, in_out, ciphertext_len, tag, ad)
            }
        }
    }

    /// Seal with scatter: encrypt `in_out` in place, encrypt `extra_in` into
    /// `extra_out_and_tag` (which must be `extra_in.len() + tag_len` bytes).
    pub(crate) fn seal_scatter(
        &self,
        nonce: &[u8],
        in_out: &mut [u8],
        extra_in: &[u8],
        extra_out_and_tag: &mut [u8],
        ad: &[u8],
    ) -> Result<(), Unspecified> {
        let tag_len = self.tag_len();
        if extra_in.is_empty() {
            // No extra input — seal in_out, write tag to extra_out_and_tag
            self.seal(nonce, in_out, in_out.len(), ad, &mut extra_out_and_tag[..tag_len])
        } else {
            // Combine [in_out || extra_in], encrypt together, split output
            let total = in_out.len() + extra_in.len();
            let mut combined = vec![0u8; total];
            combined[..in_out.len()].copy_from_slice(in_out);
            combined[in_out.len()..].copy_from_slice(extra_in);
            let mut tag = [0u8; 16];
            self.seal(nonce, &mut combined, total, ad, &mut tag[..tag_len])?;
            in_out.copy_from_slice(&combined[..in_out.len()]);
            let extra_ct_len = extra_in.len();
            extra_out_and_tag[..extra_ct_len].copy_from_slice(&combined[in_out.len()..]);
            extra_out_and_tag[extra_ct_len..extra_ct_len + tag_len]
                .copy_from_slice(&tag[..tag_len]);
            Ok(())
        }
    }

    /// Open with gather: decrypt `in_ciphertext` using separate `in_tag`,
    /// writing plaintext to `out_plaintext`.
    pub(crate) fn open_gather(
        &self,
        nonce: &[u8],
        in_ciphertext: &[u8],
        in_tag: &[u8],
        out_plaintext: &mut [u8],
        ad: &[u8],
    ) -> Result<(), Unspecified> {
        // Copy ciphertext to output, then decrypt in place
        out_plaintext.copy_from_slice(in_ciphertext);
        self.open(nonce, out_plaintext, in_ciphertext.len(), in_tag, ad)
    }
}

impl AeadKey {
    fn new(key_bytes: &[u8], tag_len: usize) -> Self {
        let mut key = [0u8; MAX_KEY_LEN];
        key[..key_bytes.len()].copy_from_slice(key_bytes);
        Self {
            key,
            key_len: key_bytes.len(),
            tag_len,
        }
    }
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        // Zeroize key material on drop.
        // Use write_volatile to prevent the compiler from optimizing this away.
        for byte in self.key.iter_mut() {
            // SAFETY: byte points to a valid element within the key array.
            unsafe { core::ptr::write_volatile(byte, 0); }
        }
        self.key_len = 0;
    }
}

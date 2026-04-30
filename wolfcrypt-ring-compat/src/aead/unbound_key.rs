use super::aead_ctx::AeadCtx;
use super::{
    Algorithm, Nonce, Tag, AES_128_GCM, AES_192_GCM, AES_256_GCM, CHACHA20_POLY1305, MAX_KEY_LEN,
    MAX_TAG_LEN,
};
use crate::error::Unspecified;
use crate::fips::indicator_check;
use crate::hkdf;
use core::fmt::Debug;
use core::ops::RangeFrom;

/// An AEAD key without a designated role or nonce sequence.
pub struct UnboundKey {
    ctx: AeadCtx,
    algorithm: &'static Algorithm,
}

#[allow(clippy::missing_fields_in_debug)]
impl Debug for UnboundKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("UnboundKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl UnboundKey {
    /// Constructs an `UnboundKey`.
    /// # Errors
    /// `error::Unspecified` if `key_bytes.len() != algorithm.key_len()`.
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, Unspecified> {
        Ok(Self {
            ctx: (algorithm.init)(key_bytes, algorithm.tag_len())?,
            algorithm,
        })
    }

    #[inline]
    pub(crate) fn open_within<'in_out>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], Unspecified> {
        let in_prefix_len = ciphertext_and_tag.start;
        let ciphertext_and_tag_len = in_out.len().checked_sub(in_prefix_len).ok_or(Unspecified)?;
        let ciphertext_len = ciphertext_and_tag_len
            .checked_sub(self.algorithm().tag_len())
            .ok_or(Unspecified)?;
        self.check_per_nonce_max_bytes(ciphertext_len)?;

        self.open_combined(nonce, aad.as_ref(), &mut in_out[in_prefix_len..])?;

        // shift the plaintext to the left
        in_out.copy_within(in_prefix_len..in_prefix_len + ciphertext_len, 0);

        // `ciphertext_len` is also the plaintext length.
        Ok(&mut in_out[..ciphertext_len])
    }

    #[inline]
    pub(crate) fn open_separate_gather(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        in_ciphertext: &[u8],
        in_tag: &[u8],
        out_plaintext: &mut [u8],
    ) -> Result<(), Unspecified> {
        self.check_per_nonce_max_bytes(in_ciphertext.len())?;

        {
            let actual = in_ciphertext.len();
            let expected = out_plaintext.len();
            if actual != expected {
                return Err(Unspecified);
            }
        }

        let nonce = nonce.as_ref();
        indicator_check!(self.ctx.open_gather(
            nonce.as_ref(),
            in_ciphertext,
            in_tag,
            out_plaintext,
            aad,
        ))
    }

    #[inline]
    pub(crate) fn seal_in_place_append_tag<'a, InOut>(
        &self,
        nonce: Option<Nonce>,
        aad: &[u8],
        in_out: &'a mut InOut,
    ) -> Result<Nonce, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.check_per_nonce_max_bytes(in_out.as_mut().len())?;
        match nonce {
            Some(nonce) => self.seal_combined(nonce, aad, in_out),
            None => Err(Unspecified),
        }
    }

    #[inline]
    pub(crate) fn seal_in_place_separate_tag(
        &self,
        nonce: Option<Nonce>,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(Nonce, Tag), Unspecified> {
        self.check_per_nonce_max_bytes(in_out.len())?;
        match nonce {
            Some(nonce) => self.seal_separate(nonce, aad, in_out),
            None => Err(Unspecified),
        }
    }

    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn seal_in_place_separate_scatter(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut [u8],
        extra_in: &[u8],
        extra_out_and_tag: &mut [u8],
    ) -> Result<(), Unspecified> {
        self.check_per_nonce_max_bytes(in_out.len())?;
        {
            let actual = extra_in.len() + self.algorithm().tag_len();
            let expected = extra_out_and_tag.len();
            if actual != expected {
                return Err(Unspecified);
            }
        }

        let nonce_ref = nonce.as_ref();
        indicator_check!(self.ctx.seal_scatter(
            nonce_ref.as_ref(),
            in_out,
            extra_in,
            extra_out_and_tag,
            aad,
        ))
    }

    /// The key's AEAD algorithm.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    #[inline]
    pub(crate) fn check_per_nonce_max_bytes(&self, in_out_len: usize) -> Result<(), Unspecified> {
        if in_out_len as u64 > self.algorithm().max_input_len {
            return Err(Unspecified);
        }
        Ok(())
    }

    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    fn open_combined(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(), Unspecified> {
        let nonce_bytes = nonce.as_ref();
        debug_assert_eq!(nonce_bytes.len(), self.algorithm().nonce_len());

        let tag_len = self.algorithm().tag_len();
        let ciphertext_len = in_out.len() - tag_len;
        let tag = in_out[ciphertext_len..].to_vec();

        indicator_check!(self.ctx.open(
            nonce_bytes.as_ref(),
            &mut in_out[..ciphertext_len],
            ciphertext_len,
            &tag,
            aad,
        ))
    }

    #[inline]
    fn seal_combined<InOut>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut InOut,
    ) -> Result<Nonce, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        let plaintext_len = in_out.as_mut().len();
        let alg_tag_len = self.algorithm().tag_len();

        debug_assert!(alg_tag_len <= MAX_TAG_LEN);

        let tag_buffer = [0u8; MAX_TAG_LEN];
        in_out.extend(tag_buffer[..alg_tag_len].iter());

        let nonce_bytes = nonce.as_ref();
        debug_assert_eq!(nonce_bytes.len(), self.algorithm().nonce_len());

        // Seal in place: encrypt plaintext_len bytes, write tag after
        let mut tag = [0u8; MAX_TAG_LEN];
        let buf = in_out.as_mut();
        indicator_check!(self.ctx.seal(
            nonce_bytes.as_ref(),
            &mut buf[..plaintext_len],
            plaintext_len,
            aad,
            &mut tag[..alg_tag_len],
        ))?;
        buf[plaintext_len..plaintext_len + alg_tag_len].copy_from_slice(&tag[..alg_tag_len]);

        Ok(nonce)
    }

    #[inline]
    fn seal_separate(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(Nonce, Tag), Unspecified> {
        let mut tag = [0u8; MAX_TAG_LEN];
        let nonce_bytes = nonce.as_ref();
        debug_assert_eq!(nonce_bytes.len(), self.algorithm().nonce_len());

        let tag_len = self.algorithm().tag_len();
        indicator_check!(self.ctx.seal(
            nonce_bytes.as_ref(),
            in_out,
            in_out.len(),
            aad,
            &mut tag[..tag_len],
        ))?;
        Ok((nonce, Tag(tag, tag_len)))
    }
}

impl From<AeadCtx> for UnboundKey {
    fn from(value: AeadCtx) -> Self {
        let algorithm = match value {
            AeadCtx::AES_128_GCM(_) => &AES_128_GCM,
            AeadCtx::AES_192_GCM(_) => &AES_192_GCM,
            AeadCtx::AES_256_GCM(_) => &AES_256_GCM,
            AeadCtx::CHACHA20_POLY1305(_) => &CHACHA20_POLY1305,
        };
        Self {
            ctx: value,
            algorithm,
        }
    }
}

#[cfg(feature = "std")]
impl From<hkdf::Okm<'_, &'static Algorithm>> for UnboundKey {
    fn from(okm: hkdf::Okm<&'static Algorithm>) -> Self {
        let mut key_bytes = [0; MAX_KEY_LEN];
        let key_bytes = &mut key_bytes[..okm.len().key_len];
        let algorithm = *okm.len();
        okm.fill(key_bytes).unwrap();
        Self::new(algorithm, key_bytes).unwrap()
    }
}

#[cfg(not(feature = "std"))]
impl TryFrom<hkdf::Okm<'_, &'static Algorithm>> for UnboundKey {
    type Error = Unspecified;

    fn try_from(okm: hkdf::Okm<&'static Algorithm>) -> Result<Self, Unspecified> {
        let mut key_bytes = [0; MAX_KEY_LEN];
        let key_bytes = &mut key_bytes[..okm.len().key_len];
        let algorithm = *okm.len();
        okm.fill(key_bytes)?;
        Ok(Self::new(algorithm, key_bytes)?)
    }
}

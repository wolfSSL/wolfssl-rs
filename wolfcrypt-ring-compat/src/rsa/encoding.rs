/// [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html)
///
/// PKCS #1: RSA Cryptography Specifications Version 2.2
pub(in crate::rsa) mod rfc8017 {
    use crate::wolfcrypt_rs::{
        EVP_PKEY_assign_RSA, EVP_PKEY_new, d2i_RSAPrivateKey, d2i_RSAPublicKey,
        i2d_RSAPublicKey, EVP_PKEY,
    };
    use crate::error::{KeyRejected, Unspecified};
    use crate::ptr::{DetachableLcPtr, LcPtr};
    use core::ptr::null_mut;

    #[cfg(not(feature = "std"))]
    use crate::prelude::*;

    /// DER encode a RSA public key to `RSAPublicKey` structure.
    pub(in crate::rsa) fn encode_public_key_der(
        pubkey: &LcPtr<EVP_PKEY>,
    ) -> Result<Box<[u8]>, Unspecified> {
        let mut pubkey_bytes = null_mut::<u8>();
        let pubkey_const = pubkey.as_const();
        let rsa = pubkey_const.get_rsa()?;
        // SAFETY: rsa is a valid RSA key; pubkey_bytes is an out-param for the DER buffer.
        let len = unsafe { i2d_RSAPublicKey(rsa.as_const_ptr(), &mut pubkey_bytes) };
        if len <= 0 {
            return Err(Unspecified);
        }
        let pubkey_ptr = LcPtr::new(pubkey_bytes)?;
        // SAFETY: pubkey_ptr points to `len` bytes allocated by i2d_RSAPublicKey above.
        let pubkey_slice = unsafe { pubkey_ptr.as_slice(len as usize) };
        let pubkey_vec = Vec::from(pubkey_slice);
        Ok(pubkey_vec.into_boxed_slice())
    }

    /// Decode a DER encoded `RSAPublicKey` structure.
    #[inline]
    pub(in crate::rsa) fn decode_public_key_der(
        public_key: &[u8],
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let mut p = public_key.as_ptr();
        // SAFETY: pointer and length derived from a valid Rust slice.
        let mut rsa = DetachableLcPtr::new(unsafe {
            d2i_RSAPublicKey(null_mut(), &mut p, public_key.len() as core::ffi::c_long)
        })?;

        // SAFETY: EVP_PKEY_new allocates a fresh EVP_PKEY; null-checked by LcPtr::new.
        let mut pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

        // SAFETY: pkey and rsa are valid; on success RSA ownership transfers to EVP_PKEY.
        if 1 != unsafe { EVP_PKEY_assign_RSA(pkey.as_mut_ptr(), rsa.as_mut_ptr()) } {
            return Err(KeyRejected::unspecified());
        }

        rsa.detach();

        Ok(pkey)
    }

    /// Decodes a DER encoded `RSAPrivateKey` structure.
    #[inline]
    pub(in crate::rsa) fn decode_private_key_der(
        private_key: &[u8],
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let mut p = private_key.as_ptr();
        // SAFETY: pointer and length derived from a valid Rust slice.
        let mut rsa = DetachableLcPtr::new(unsafe {
            d2i_RSAPrivateKey(null_mut(), &mut p, private_key.len() as core::ffi::c_long)
        })?;

        // SAFETY: EVP_PKEY_new allocates a fresh EVP_PKEY; null-checked by LcPtr::new.
        let mut pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

        // SAFETY: pkey and rsa are valid; on success RSA ownership transfers to EVP_PKEY.
        if 1 != unsafe { EVP_PKEY_assign_RSA(pkey.as_mut_ptr(), rsa.as_mut_ptr()) } {
            return Err(KeyRejected::unspecified());
        }

        rsa.detach();

        Ok(pkey)
    }
}

/// [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html)
///
/// Encodings that use the `SubjectPublicKeyInfo` structure.
pub(in crate::rsa) mod rfc5280 {
    use crate::wolfcrypt_rs::{EVP_PKEY, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS};
    use crate::buffer::Buffer;
    use crate::encoding::PublicKeyX509Der;
    use crate::error::{KeyRejected, Unspecified};
    use crate::ptr::LcPtr;

    pub(in crate::rsa) fn encode_public_key_der(
        key: &LcPtr<EVP_PKEY>,
    ) -> Result<PublicKeyX509Der<'static>, Unspecified> {
        let der = key.as_const().marshal_rfc5280_public_key()?;
        Ok(PublicKeyX509Der::from(Buffer::new(der)))
    }

    pub(in crate::rsa) fn decode_public_key_der(
        value: &[u8],
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        LcPtr::<EVP_PKEY>::parse_rfc5280_public_key(value, EVP_PKEY_RSA).or(
            // Does anyone encode with this OID?
            LcPtr::<EVP_PKEY>::parse_rfc5280_public_key(value, EVP_PKEY_RSA_PSS),
        )
    }
}

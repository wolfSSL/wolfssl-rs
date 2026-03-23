use crate::wolfcrypt_rs::{EVP_PKEY, EVP_PKEY_EC};
use crate::ec::encoding::sec1::parse_sec1_public_point;
use crate::ec::validate_ec_evp_key;

use crate::error::KeyRejected;
use crate::ptr::LcPtr;


// [SEC 1](https://secg.org/sec1-v2.pdf)
//
// SEC 1: Elliptic Curve Cryptography, Version 2.0
pub(crate) mod sec1 {
    #[cfg(not(feature = "std"))]
    use crate::prelude::*;
    use crate::wolfcrypt_rs::{
        point_conversion_form_t, BN_num_bytes, BN_bn2bin, EC_GROUP_get_curve_name, EC_KEY_get0_group,
        EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_KEY_new, EC_KEY_set_group,
        EC_KEY_set_private_key, EC_KEY_set_public_key, EC_POINT_mul, EC_POINT_new,
        EC_POINT_oct2point, EC_POINT_point2oct,
        EVP_PKEY_assign_EC_KEY, EVP_PKEY_get0_EC_KEY,
        EVP_PKEY_new, NID_X9_62_prime256v1, NID_secp256k1, NID_secp384r1, NID_secp521r1, BIGNUM,
        EC_GROUP, EC_POINT, EVP_PKEY,
    };
    use crate::cbb::LcCBB;
    use crate::ec::{
        compressed_public_key_size_bytes, ec_group_from_nid, uncompressed_public_key_size_bytes,
        validate_ec_evp_key, KeyRejected,
    };
    use crate::error::Unspecified;
    use crate::ptr::{ConstPointer, DetachableLcPtr, LcPtr};
    use core::ptr::{null, null_mut};

    pub(crate) fn parse_sec1_public_point(
        key_bytes: &[u8],
        expected_curve_nid: i32,
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let ec_group = ec_group_from_nid(expected_curve_nid)?;
        // SAFETY: ec_group is a valid EC_GROUP from ec_group_from_nid.
        let mut ec_point = LcPtr::new(unsafe { EC_POINT_new(ec_group.as_const_ptr()) })?;

        // SAFETY: pointer and length derived from a valid Rust slice.
        if 1 != unsafe {
            EC_POINT_oct2point(
                ec_group.as_const_ptr(),
                ec_point.as_mut_ptr(),
                key_bytes.as_ptr(),
                key_bytes.len(),
                null_mut(),
            )
        } {
            return Err(KeyRejected::invalid_encoding());
        }
        from_ec_public_point(&ec_group, &ec_point)
    }

    #[inline]
    fn from_ec_public_point(
        ec_group: &ConstPointer<EC_GROUP>,
        public_ec_point: &LcPtr<EC_POINT>,
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        // SAFETY: ec_group is a valid EC_GROUP pointer.
        let nid = unsafe { EC_GROUP_get_curve_name(ec_group.as_const_ptr()) };
        // SAFETY: EC_KEY_new returns a new key or null (checked by LcPtr).
        let mut ec_key = DetachableLcPtr::new(unsafe { EC_KEY_new() })?;
        // SAFETY: ec_key and ec_group are valid pointers managed by LcPtr.
        if 1 != unsafe { EC_KEY_set_group(ec_key.as_mut_ptr(), ec_group.as_const_ptr()) } {
            return Err(KeyRejected::unexpected_error());
        }
        // SAFETY: ec_key and public_ec_point are valid pointers managed by LcPtr.
        if 1 != unsafe {
            EC_KEY_set_public_key(ec_key.as_mut_ptr(), public_ec_point.as_const_ptr())
        } {
            return Err(KeyRejected::inconsistent_components());
        }

        // SAFETY: EVP_PKEY_new returns a new key or null (checked by LcPtr).
        let mut pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

        // SAFETY: pkey and ec_key are valid; ec_key is detached after to transfer ownership.
        if 1 != unsafe { EVP_PKEY_assign_EC_KEY(pkey.as_mut_ptr(), ec_key.as_mut_ptr()) } {
            return Err(KeyRejected::unexpected_error());
        }

        ec_key.detach();

        validate_ec_evp_key(&pkey.as_const(), nid)?;

        Ok(pkey)
    }

    pub(crate) fn parse_sec1_private_bn(
        priv_key: &[u8],
        nid: i32,
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let ec_group = ec_group_from_nid(nid)?;
        let priv_key = LcPtr::<BIGNUM>::try_from(priv_key)?;

        let pkey = from_ec_private_bn(&ec_group, &priv_key.as_const())?;

        Ok(pkey)
    }

    fn from_ec_private_bn(
        ec_group: &ConstPointer<EC_GROUP>,
        private_big_num: &ConstPointer<BIGNUM>,
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        // SAFETY: EC_KEY_new returns a new key or null (checked by LcPtr).
        let mut ec_key = DetachableLcPtr::new(unsafe { EC_KEY_new() })?;
        // SAFETY: ec_key and ec_group are valid pointers managed by LcPtr.
        if 1 != unsafe { EC_KEY_set_group(ec_key.as_mut_ptr(), ec_group.as_const_ptr()) } {
            return Err(KeyRejected::unexpected_error());
        }
        // SAFETY: ec_key and private_big_num are valid pointers managed by LcPtr.
        if 1 != unsafe {
            EC_KEY_set_private_key(ec_key.as_mut_ptr(), private_big_num.as_const_ptr())
        } {
            return Err(KeyRejected::invalid_encoding());
        }
        // SAFETY: ec_group is a valid EC_GROUP pointer.
        let mut pub_key = LcPtr::new(unsafe { EC_POINT_new(ec_group.as_const_ptr()) })?;
        // SAFETY: all pointers are valid; computes public key from private scalar.
        if 1 != unsafe {
            EC_POINT_mul(
                ec_group.as_const_ptr(),
                pub_key.as_mut_ptr(),
                private_big_num.as_const_ptr(),
                null(),
                null(),
                null_mut(),
            )
        } {
            return Err(KeyRejected::unexpected_error());
        }
        // SAFETY: ec_key and pub_key are valid pointers managed by LcPtr.
        if 1 != unsafe { EC_KEY_set_public_key(ec_key.as_mut_ptr(), pub_key.as_const_ptr()) } {
            return Err(KeyRejected::unexpected_error());
        }
        // SAFETY: ec_group is a valid EC_GROUP pointer.
        let expected_curve_nid = unsafe { EC_GROUP_get_curve_name(ec_group.as_const_ptr()) };

        // SAFETY: EVP_PKEY_new returns a new key or null (checked by LcPtr).
        let mut pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

        // SAFETY: pkey and ec_key are valid; ec_key is detached after to transfer ownership.
        if 1 != unsafe { EVP_PKEY_assign_EC_KEY(pkey.as_mut_ptr(), ec_key.as_mut_ptr()) } {
            return Err(KeyRejected::unexpected_error());
        }
        ec_key.detach();

        // Validate the EC_KEY before returning it.
        validate_ec_evp_key(&pkey.as_const(), expected_curve_nid)?;

        Ok(pkey)
    }
    pub(crate) fn marshal_sec1_public_point(
        evp_pkey: &LcPtr<EVP_PKEY>,
        compressed: bool,
    ) -> Result<Vec<u8>, Unspecified> {
        let pub_key_size = if compressed {
            compressed_public_key_size_bytes(evp_pkey.as_const().key_size_bits())
        } else {
            uncompressed_public_key_size_bytes(evp_pkey.as_const().key_size_bits())
        };
        let mut cbb = LcCBB::new(pub_key_size);
        marshal_sec1_public_point_into_cbb(&mut cbb, evp_pkey, compressed)?;
        cbb.into_vec()
    }

    pub(crate) fn marshal_sec1_public_point_into_buffer(
        buffer: &mut [u8],
        evp_pkey: &LcPtr<EVP_PKEY>,
        compressed: bool,
    ) -> Result<usize, Unspecified> {
        let point_bytes = marshal_sec1_public_point(evp_pkey, compressed)?;
        if point_bytes.len() > buffer.len() {
            return Err(Unspecified);
        }
        buffer[..point_bytes.len()].copy_from_slice(&point_bytes);
        Ok(point_bytes.len())
    }

    fn marshal_sec1_public_point_into_cbb(
        cbb: &mut LcCBB,
        evp_pkey: &LcPtr<EVP_PKEY>,
        compressed: bool,
    ) -> Result<(), Unspecified> {
        // SAFETY: evp_pkey is valid; returns a non-owning pointer into the key.
        let ec_key = evp_pkey.project_const_lifetime(unsafe {
            |evp_pkey| EVP_PKEY_get0_EC_KEY(evp_pkey.as_const_ptr())
        })?;
        // SAFETY: ec_key is valid; returns a non-owning pointer to its group.
        let ec_group = ec_key
            .project_const_lifetime(unsafe { |ec_key| EC_KEY_get0_group(ec_key.as_const_ptr()) })?;
        // SAFETY: ec_key is valid; returns a non-owning pointer to its public point.
        let ec_point = ec_key.project_const_lifetime(unsafe {
            |ec_key| EC_KEY_get0_public_key(ec_key.as_const_ptr())
        })?;

        let form = if compressed {
            point_conversion_form_t::POINT_CONVERSION_COMPRESSED
        } else {
            point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED
        };

        // SAFETY: ec_group and ec_point are valid const pointers from the key.
        unsafe {
            ec_point_to_vec(
                cbb,
                ec_group.as_const_ptr(),
                ec_point.as_const_ptr(),
                form,
            )?;
        }
        Ok(())
    }

    /// Serialize an EC point into an LcCBB.
    unsafe fn ec_point_to_vec(
        cbb: &mut LcCBB,
        group: *const EC_GROUP,
        point: *const EC_POINT,
        form: point_conversion_form_t,
    ) -> Result<(), Unspecified> {
        if group.is_null() || point.is_null() {
            return Err(Unspecified);
        }
        let len = EC_POINT_point2oct(
            group, point, form,
            core::ptr::null_mut(), 0, null_mut(),
        );
        if len == 0 {
            return Err(Unspecified);
        }
        let buf = cbb.reserve_uninit(len);
        let written = EC_POINT_point2oct(group, point, form, buf, len, null_mut());
        if written == 0 {
            return Err(Unspecified);
        }
        Ok(())
    }

    pub(crate) fn marshal_sec1_private_key(
        evp_pkey: &LcPtr<EVP_PKEY>,
    ) -> Result<Vec<u8>, Unspecified> {
        // SAFETY: evp_pkey is valid; returns a non-owning pointer into the key.
        let ec_key = evp_pkey.project_const_lifetime(unsafe {
            |evp_pkey| EVP_PKEY_get0_EC_KEY(evp_pkey.as_const_ptr())
        })?;
        // SAFETY: ec_key is valid; returns a non-owning pointer to its group.
        let ec_group = ec_key
            .project_const_lifetime(unsafe { |ec_key| EC_KEY_get0_group(ec_key.as_const_ptr()) })?;
        // SAFETY: ec_group is a valid EC_GROUP pointer.
        let nid = unsafe { EC_GROUP_get_curve_name(ec_group.as_const_ptr()) };
        #[allow(non_upper_case_globals)]
        let key_size: usize = match nid {
            NID_X9_62_prime256v1 | NID_secp256k1 => Ok(32usize),
            NID_secp384r1 => Ok(48usize),
            NID_secp521r1 => Ok(66usize),
            _ => Err(Unspecified),
        }?;
        // SAFETY: ec_key is valid; returns a non-owning pointer to the private BIGNUM.
        let private_bn = ec_key.project_const_lifetime(unsafe {
            |ec_key| EC_KEY_get0_private_key(ec_key.as_const_ptr())
        })?;

        bn_to_padded_vec(&private_bn, key_size)
    }

    /// Convert a BIGNUM to a zero-padded big-endian byte vector of exactly `len` bytes.
    fn bn_to_padded_vec(bn: &ConstPointer<BIGNUM>, len: usize) -> Result<Vec<u8>, Unspecified> {
        // SAFETY: bn is a valid BIGNUM pointer.
        let bn_len = unsafe { BN_num_bytes(bn.as_const_ptr()) } as usize;
        if bn_len > len { return Err(Unspecified); }
        let mut buf = vec![0u8; len];
        // BN_bn2bin writes big-endian at the start; we offset to right-align (zero-pad on left).
        // SAFETY: pointer offset is within the allocated buf; bn is valid.
        unsafe { BN_bn2bin(bn.as_const_ptr(), buf.as_mut_ptr().add(len - bn_len)) };
        Ok(buf)
    }
}

pub(crate) mod rfc5915 {
    #[cfg(not(feature = "std"))]
    use crate::prelude::*;
    use crate::wolfcrypt_rs::{
        d2i_ECPrivateKey, i2d_ECPrivateKey, wolfcrypt_fix_ec_privatekey_only,
        EC_GROUP_get_curve_name, EC_KEY_get0_group,
        EC_KEY_set_group, EC_KEY_free, OPENSSL_malloc, OPENSSL_free,
        EVP_PKEY_get0_EC_KEY, EVP_PKEY_new, EVP_PKEY_set1_EC_KEY, EVP_PKEY,
        EC_GROUP, EC_KEY,
    };
    use crate::ec::ec_group_from_nid;
    use crate::error::{KeyRejected, Unspecified};
    use crate::ptr::LcPtr;
    use core::ffi::{c_long, c_void};

    /// ec_key_parse_private_key: parse an EC private key from a byte slice.
    unsafe fn ec_key_parse_private_key(data: &[u8], group: *const EC_GROUP) -> *mut EC_KEY {
        if data.is_empty() {
            return core::ptr::null_mut();
        }
        let mut p = data.as_ptr();
        let key = d2i_ECPrivateKey(core::ptr::null_mut(), &mut p, data.len() as c_long);
        if key.is_null() {
            return core::ptr::null_mut();
        }

        if !group.is_null() {
            let expected_nid = EC_GROUP_get_curve_name(group);
            let key_group = EC_KEY_get0_group(key);
            if !key_group.is_null() {
                let key_nid = EC_GROUP_get_curve_name(key_group);
                if key_nid != expected_nid {
                    if key_nid == 0 {
                        EC_KEY_set_group(key, group);
                    } else {
                        EC_KEY_free(key);
                        return core::ptr::null_mut();
                    }
                }
            } else {
                EC_KEY_set_group(key, group);
            }
        }

        if wolfcrypt_fix_ec_privatekey_only(key) != 1 {
            EC_KEY_free(key);
            return core::ptr::null_mut();
        }

        key
    }

    /// ec_key_marshal_private_key: serialize an EC private key to DER.
    unsafe fn ec_key_marshal_private_key(
        buf: &mut Vec<u8>,
        key: *const EC_KEY,
    ) -> Result<(), Unspecified> {
        if key.is_null() {
            return Err(Unspecified);
        }
        let der_len = i2d_ECPrivateKey(key, core::ptr::null_mut());
        if der_len <= 0 {
            return Err(Unspecified);
        }
        let tmp = OPENSSL_malloc(der_len as usize) as *mut u8;
        if tmp.is_null() {
            return Err(Unspecified);
        }
        let mut p = tmp;
        let actual_len = i2d_ECPrivateKey(key, &mut p);
        if actual_len <= 0 {
            OPENSSL_free(tmp as *mut c_void);
            return Err(Unspecified);
        }
        let slice = core::slice::from_raw_parts(tmp, actual_len as usize);
        buf.extend_from_slice(slice);
        OPENSSL_free(tmp as *mut c_void);
        Ok(())
    }

    pub(crate) fn parse_rfc5915_private_key(
        key_bytes: &[u8],
        expected_curve_nid: i32,
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let ec_group = ec_group_from_nid(expected_curve_nid)?;
        // SAFETY: key_bytes is a valid slice; ec_group is a valid EC_GROUP pointer.
        let mut ec_key =
            LcPtr::new(unsafe { ec_key_parse_private_key(key_bytes, ec_group.as_const_ptr()) })?;
        // SAFETY: EVP_PKEY_new returns a new key or null (checked by LcPtr).
        let mut evp_pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;
        // SAFETY: evp_pkey and ec_key are valid pointers managed by LcPtr.
        if 1 != unsafe { EVP_PKEY_set1_EC_KEY(evp_pkey.as_mut_ptr(), ec_key.as_mut_ptr()) } {
            return Err(KeyRejected::unexpected_error());
        }
        Ok(evp_pkey)
    }

    pub(crate) fn marshal_rfc5915_private_key(
        evp_pkey: &LcPtr<EVP_PKEY>,
    ) -> Result<Vec<u8>, Unspecified> {
        // SAFETY: evp_pkey is valid; returns a non-owning pointer into the key.
        let ec_key = evp_pkey.project_const_lifetime(unsafe {
            |evp_pkey| EVP_PKEY_get0_EC_KEY(evp_pkey.as_const_ptr())
        })?;
        let mut buf = Vec::with_capacity(evp_pkey.as_const().key_size_bytes());
        // SAFETY: ec_key is a valid EC_KEY pointer managed by the EVP_PKEY.
        unsafe { ec_key_marshal_private_key(&mut buf, ec_key.as_const_ptr())? };
        Ok(buf)
    }
}

pub(crate) fn parse_ec_public_key(
    key_bytes: &[u8],
    expected_curve_nid: i32,
) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
    LcPtr::<EVP_PKEY>::parse_rfc5280_public_key(key_bytes, EVP_PKEY_EC)
        .or(parse_sec1_public_point(key_bytes, expected_curve_nid))
        .and_then(|key| validate_ec_evp_key(&key.as_const(), expected_curve_nid).map(|()| key))
}

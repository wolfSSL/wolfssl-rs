//! Integration tests for compat_shim.c accessor functions.

#[cfg(wolfssl_openssl_extra)]
mod evp_pkey_tests {
    use core::ffi::c_int;
    use core::slice;
    use wolfcrypt_rs::*;

    /// Helper: create a fresh EVP_PKEY via the wolfSSL allocator.
    /// Panics if allocation fails.
    unsafe fn new_pkey() -> *mut EVP_PKEY {
        let pkey = EVP_PKEY_new();
        assert!(!pkey.is_null(), "EVP_PKEY_new returned NULL");
        pkey
    }

    #[test]
    fn set_raw_basic_roundtrip() {
        unsafe {
            let pkey = new_pkey();
            let data: [u8; 5] = [0xDE, 0xAD, 0xBE, 0xEF, 0x42];

            let ret = wolfcrypt_evp_pkey_set_raw(pkey, data.as_ptr(), data.len() as c_int);
            assert_eq!(ret, 1, "set_raw should return 1 on success");

            assert_eq!(
                wolfcrypt_evp_pkey_get_pkey_sz(pkey),
                data.len() as c_int
            );

            let ptr = wolfcrypt_evp_pkey_get_pkey_ptr(pkey);
            assert!(!ptr.is_null());
            let stored = slice::from_raw_parts(ptr, data.len());
            assert_eq!(stored, &data);

            EVP_PKEY_free(pkey);
        }
    }

    #[test]
    fn set_raw_overwrite_replaces_data() {
        unsafe {
            let pkey = new_pkey();

            let first: [u8; 4] = [1, 2, 3, 4];
            assert_eq!(
                wolfcrypt_evp_pkey_set_raw(pkey, first.as_ptr(), first.len() as c_int),
                1
            );

            let second: [u8; 8] = [10, 20, 30, 40, 50, 60, 70, 80];
            assert_eq!(
                wolfcrypt_evp_pkey_set_raw(pkey, second.as_ptr(), second.len() as c_int),
                1
            );

            assert_eq!(
                wolfcrypt_evp_pkey_get_pkey_sz(pkey),
                second.len() as c_int
            );
            let ptr = wolfcrypt_evp_pkey_get_pkey_ptr(pkey);
            let stored = slice::from_raw_parts(ptr, second.len());
            assert_eq!(stored, &second);

            EVP_PKEY_free(pkey);
        }
    }

    #[test]
    fn set_raw_null_data_returns_zero_and_clears() {
        unsafe {
            let pkey = new_pkey();

            // First set valid data
            let data: [u8; 3] = [0xAA, 0xBB, 0xCC];
            wolfcrypt_evp_pkey_set_raw(pkey, data.as_ptr(), data.len() as c_int);

            // Now set NULL — should fail and clear the buffer
            let ret = wolfcrypt_evp_pkey_set_raw(pkey, core::ptr::null(), 0);
            assert_eq!(ret, 0, "set_raw with NULL data should return 0");
            assert_eq!(wolfcrypt_evp_pkey_get_pkey_sz(pkey), 0);

            EVP_PKEY_free(pkey);
        }
    }

    #[test]
    fn set_raw_zero_length_returns_zero() {
        unsafe {
            let pkey = new_pkey();

            let data: [u8; 1] = [0xFF];
            let ret = wolfcrypt_evp_pkey_set_raw(pkey, data.as_ptr(), 0);
            assert_eq!(ret, 0, "set_raw with sz=0 should return 0");
            assert_eq!(wolfcrypt_evp_pkey_get_pkey_sz(pkey), 0);

            EVP_PKEY_free(pkey);
        }
    }

    #[test]
    fn set_raw_negative_length_returns_zero() {
        unsafe {
            let pkey = new_pkey();

            let data: [u8; 1] = [0xFF];
            let ret = wolfcrypt_evp_pkey_set_raw(pkey, data.as_ptr(), -1);
            assert_eq!(ret, 0, "set_raw with sz=-1 should return 0");
            assert_eq!(wolfcrypt_evp_pkey_get_pkey_sz(pkey), 0);

            EVP_PKEY_free(pkey);
        }
    }

    #[test]
    fn type_roundtrip() {
        unsafe {
            let pkey = new_pkey();

            wolfcrypt_evp_pkey_set_type(pkey, EVP_PKEY_RSA);
            assert_eq!(wolfcrypt_evp_pkey_get_type(pkey), EVP_PKEY_RSA);

            EVP_PKEY_free(pkey);
        }
    }

    #[test]
    fn peer_key_set_and_get() {
        unsafe {
            let pkey = new_pkey();
            let peer = new_pkey();
            let ctx = EVP_PKEY_CTX_new(pkey, core::ptr::null_mut());
            assert!(!ctx.is_null(), "EVP_PKEY_CTX_new returned NULL");

            // Initially no peer key.
            assert!(wolfcrypt_evp_pkey_ctx_get_peer_key(ctx).is_null());

            // Set a peer key and verify it's stored.
            wolfcrypt_evp_pkey_ctx_set_peer_key(ctx, peer);
            assert_eq!(wolfcrypt_evp_pkey_ctx_get_peer_key(ctx), peer);

            // Clear peer key by setting NULL.
            wolfcrypt_evp_pkey_ctx_set_peer_key(ctx, core::ptr::null_mut());
            assert!(wolfcrypt_evp_pkey_ctx_get_peer_key(ctx).is_null());

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer);
            EVP_PKEY_free(pkey);
        }
    }

    /// Regression test: setting the same peer key that is already set must
    /// not use-after-free. The fix is to up-ref the new key before freeing
    /// the old one.
    #[test]
    fn peer_key_set_same_key_twice_no_uaf() {
        unsafe {
            let pkey = new_pkey();
            let peer = new_pkey();
            let ctx = EVP_PKEY_CTX_new(pkey, core::ptr::null_mut());
            assert!(!ctx.is_null());

            // Set peer key the first time.
            wolfcrypt_evp_pkey_ctx_set_peer_key(ctx, peer);
            assert_eq!(wolfcrypt_evp_pkey_ctx_get_peer_key(ctx), peer);

            // Set the SAME peer key again. Before the fix, this was a
            // use-after-free when the refcount was 1 (free then up-ref
            // on deallocated memory). With the fix (up-ref before free),
            // this is safe: refcount goes 1→2→1.
            wolfcrypt_evp_pkey_ctx_set_peer_key(ctx, peer);
            assert_eq!(wolfcrypt_evp_pkey_ctx_get_peer_key(ctx), peer);

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer);
            EVP_PKEY_free(pkey);
        }
    }
}

#[cfg(all(wolfssl_openssl_extra, wolfssl_ecc))]
mod ec_fix_tests {
    use core::ffi::c_long;
    use wolfcrypt_rs::*;

    /// Minimal RFC 5915 ECPrivateKey DER for P-256 WITHOUT the optional
    /// publicKey field. This triggers the wolfSSL bug where
    /// d2i_ECPrivateKey sets type = ECC_PRIVATEKEY_ONLY and leaves the
    /// public point uninitialised.
    ///
    /// Structure:
    ///   SEQUENCE {
    ///     INTEGER 1                              -- version
    ///     OCTET STRING (32 bytes)                -- privateKey (scalar = 1)
    ///     [0] OID 1.2.840.10045.3.1.7            -- P-256 parameters
    ///   }
    const P256_PRIVKEY_ONLY_DER: [u8; 51] = [
        0x30, 0x31, // SEQUENCE, length 49
        0x02, 0x01, 0x01, // INTEGER 1 (version)
        0x04, 0x20, // OCTET STRING, length 32
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // private key = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xA0, 0x0A, // context [0], length 10
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID P-256
    ];

    #[test]
    fn fix_privatekey_only_derives_public_point() {
        unsafe {
            let mut der_ptr: *const u8 = P256_PRIVKEY_ONLY_DER.as_ptr();
            let ec_key = d2i_ECPrivateKey(
                core::ptr::null_mut(),
                &mut der_ptr,
                P256_PRIVKEY_ONLY_DER.len() as c_long,
            );
            assert!(!ec_key.is_null(), "d2i_ECPrivateKey failed to parse DER");

            // Before fix: key should work but may lack a public point.
            // wolfcrypt_fix_ec_privatekey_only handles both cases
            // (already-has-public and needs-derivation).
            let ret = wolfcrypt_fix_ec_privatekey_only(ec_key);
            assert_eq!(ret, 1, "wolfcrypt_fix_ec_privatekey_only should return 1");

            // After fix: the public key should be accessible.
            let pub_point = EC_KEY_get0_public_key(ec_key);
            assert!(!pub_point.is_null(), "public point should exist after fix");

            // Verify the key passes validation (private + public consistent).
            let check = EC_KEY_check_key(ec_key);
            assert_eq!(check, 1, "EC_KEY_check_key should pass after fix");

            EC_KEY_free(ec_key);
        }
    }

    #[test]
    fn fix_null_key_returns_success() {
        unsafe {
            // NULL key: nothing to fix, should return 1.
            let ret = wolfcrypt_fix_ec_privatekey_only(core::ptr::null_mut());
            assert_eq!(ret, 1, "NULL key should be a no-op returning 1");
        }
    }

    #[test]
    fn fix_already_has_public_key_is_noop() {
        unsafe {
            // Generate a full key pair — it already has a public key.
            let ec_key = EC_KEY_new();
            assert!(!ec_key.is_null());

            let group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            assert!(!group.is_null());
            assert_eq!(EC_KEY_set_group(ec_key, group), 1);
            assert_eq!(EC_KEY_generate_key(ec_key), 1);

            // Fix should be a no-op since the key already has a public point.
            let ret = wolfcrypt_fix_ec_privatekey_only(ec_key);
            assert_eq!(ret, 1);

            // Key should still be valid.
            assert_eq!(EC_KEY_check_key(ec_key), 1);

            EC_GROUP_free(group);
            EC_KEY_free(ec_key);
        }
    }

    #[test]
    fn fix_then_export_public_point() {
        unsafe {
            let mut der_ptr: *const u8 = P256_PRIVKEY_ONLY_DER.as_ptr();
            let ec_key = d2i_ECPrivateKey(
                core::ptr::null_mut(),
                &mut der_ptr,
                P256_PRIVKEY_ONLY_DER.len() as c_long,
            );
            assert!(!ec_key.is_null());

            assert_eq!(wolfcrypt_fix_ec_privatekey_only(ec_key), 1);

            // Export the public point as uncompressed SEC1.
            let group = EC_KEY_get0_group(ec_key);
            assert!(!group.is_null());
            let pub_point = EC_KEY_get0_public_key(ec_key);
            assert!(!pub_point.is_null());

            // Query the required buffer size.
            let needed = EC_POINT_point2oct(
                group,
                pub_point,
                point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
            );
            // Uncompressed P-256 point: 1 + 32 + 32 = 65 bytes.
            assert_eq!(needed, 65, "P-256 uncompressed point should be 65 bytes");

            let mut buf = [0u8; 65];
            let written = EC_POINT_point2oct(
                group,
                pub_point,
                point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
                buf.as_mut_ptr(),
                buf.len(),
                core::ptr::null_mut(),
            );
            assert_eq!(written, 65);
            // First byte of uncompressed point is 0x04.
            assert_eq!(buf[0], 0x04, "uncompressed point must start with 0x04");

            EC_KEY_free(ec_key);
        }
    }
}

/// Verify that build.rs correctly emits `cargo:rustc-cfg` flags based on
/// the defines in user_settings.h. These tests use `#[cfg]` attributes —
/// if the cfg is absent at compile time, the test function doesn't exist
/// and `cargo test` won't find it, which would show up as a missing test
/// in CI.
///
/// Each flag tested here corresponds to a define in user_settings.h that
/// our default configuration enables.
mod cfg_flag_tests {
    // Our user_settings.h defines OPENSSL_EXTRA and OPENSSL_ALL.
    #[test]
    #[cfg(wolfssl_openssl_extra)]
    fn cfg_openssl_extra_is_active() {}

    #[test]
    #[cfg(wolfssl_openssl_all)]
    fn cfg_openssl_all_is_active() {}

    // AES variants: user_settings.h defines WOLFSSL_AES_128/192/256, HAVE_AESGCM,
    // WOLFSSL_AES_COUNTER, WOLFSSL_AES_CFB, HAVE_AES_ECB, WOLFSSL_AES_DIRECT,
    // HAVE_AES_KEYWRAP.
    #[test]
    #[cfg(wolfssl_aes_128)]
    fn cfg_aes_128_is_active() {}

    #[test]
    #[cfg(wolfssl_aes_256)]
    fn cfg_aes_256_is_active() {}

    #[test]
    #[cfg(wolfssl_aes_gcm)]
    fn cfg_aes_gcm_is_active() {}

    #[test]
    #[cfg(wolfssl_aes_ctr)]
    fn cfg_aes_ctr_is_active() {}

    // ChaCha20-Poly1305: user_settings.h defines HAVE_CHACHA and HAVE_POLY1305.
    #[test]
    #[cfg(wolfssl_chacha)]
    fn cfg_chacha_is_active() {}

    #[test]
    #[cfg(wolfssl_poly1305)]
    fn cfg_poly1305_is_active() {}

    #[test]
    #[cfg(wolfssl_chacha20_poly1305)]
    fn cfg_chacha20_poly1305_is_active() {}

    // ECC: user_settings.h defines HAVE_ECC.
    #[test]
    #[cfg(wolfssl_ecc)]
    fn cfg_ecc_is_active() {}

    // Ed25519/X25519: user_settings.h defines HAVE_ED25519, HAVE_CURVE25519.
    #[test]
    #[cfg(wolfssl_ed25519)]
    fn cfg_ed25519_is_active() {}

    #[test]
    #[cfg(wolfssl_curve25519)]
    fn cfg_curve25519_is_active() {}

    // SHA variants: user_settings.h defines WOLFSSL_SHA224/384/512, WOLFSSL_SHA3.
    // SHA-1 and SHA-256 are on by default (no NO_SHA / NO_SHA256).
    #[test]
    #[cfg(wolfssl_sha1)]
    fn cfg_sha1_is_active() {}

    #[test]
    #[cfg(wolfssl_sha256)]
    fn cfg_sha256_is_active() {}

    #[test]
    #[cfg(wolfssl_sha384)]
    fn cfg_sha384_is_active() {}

    #[test]
    #[cfg(wolfssl_sha512)]
    fn cfg_sha512_is_active() {}

    #[test]
    #[cfg(wolfssl_sha3)]
    fn cfg_sha3_is_active() {}

    // HKDF/PBKDF2: user_settings.h defines HAVE_HKDF, HAVE_PBKDF2.
    #[test]
    #[cfg(wolfssl_hkdf)]
    fn cfg_hkdf_is_active() {}

    #[test]
    #[cfg(wolfssl_pbkdf2)]
    fn cfg_pbkdf2_is_active() {}

    // RSA/DH/HMAC/DES3: on by default (no NO_RSA, NO_DH, NO_HMAC, NO_DES3).
    #[test]
    #[cfg(wolfssl_rsa)]
    fn cfg_rsa_is_active() {}

    #[test]
    #[cfg(wolfssl_dh)]
    fn cfg_dh_is_active() {}

    #[test]
    #[cfg(wolfssl_hmac)]
    fn cfg_hmac_is_active() {}

    // FIPS should NOT be active in the default (non-FIPS) build.
    #[test]
    #[cfg(not(wolfssl_fips))]
    fn cfg_fips_is_not_active_by_default() {}
}

/// Tests for the SetErrorString stub in compat_shim.c.
/// Our stub converts the error code to a decimal string, since we don't
/// compile internal.c (where the real SetErrorString lives).
#[cfg(wolfssl_openssl_extra)]
mod error_string_stub_tests {
    use core::ffi::{c_char, c_ulong};
    use wolfcrypt_rs::*;

    /// Helper: call ERR_error_string with a caller-provided buffer and
    /// return the result as a &str.
    unsafe fn error_string_for(code: c_ulong) -> alloc::string::String {
        let mut buf = [0u8; 120]; // WOLFSSL_MAX_ERROR_SZ is 80, but be safe
        let ptr = ERR_error_string(code, buf.as_mut_ptr() as *mut c_char);
        assert!(!ptr.is_null());
        let cstr = core::ffi::CStr::from_ptr(ptr);
        cstr.to_string_lossy().into_owned()
    }

    extern crate alloc;

    #[test]
    fn positive_error_code() {
        unsafe {
            let s = error_string_for(42);
            assert_eq!(s, "42");
        }
    }

    #[test]
    fn zero_error_code() {
        unsafe {
            let s = error_string_for(0);
            assert_eq!(s, "0");
        }
    }

    #[test]
    fn negative_error_code_via_cast() {
        unsafe {
            // -42 as i32, then cast to unsigned long — mirrors how wolfSSL
            // internally casts back to int in ERR_error_string.
            let code = (-42i32) as c_ulong;
            let s = error_string_for(code);
            assert_eq!(s, "-42");
        }
    }

    #[test]
    fn int_min_safe_negation() {
        // Tests the safe negation trick: -(error + 1) + 1u avoids UB on INT_MIN.
        unsafe {
            let code = (i32::MIN) as c_ulong;
            let s = error_string_for(code);
            assert_eq!(s, "-2147483648");
        }
    }
}

/// Smoke tests for wolfcrypt native FFI functions.
/// These verify that the extern "C" signatures in lib.rs actually link
/// and produce correct results, not just that the shim accessors work.
mod wolfcrypt_native_tests {
    use wolfcrypt_rs::*;

    #[test]
    fn rng_init_generate_free() {
        unsafe {
            let mut rng = WC_RNG::zeroed();
            let ret = wc_InitRng(&mut rng);
            assert_eq!(ret, 0, "wc_InitRng failed: {ret}");

            let mut buf = [0u8; 32];
            let ret = wc_RNG_GenerateBlock(&mut rng, buf.as_mut_ptr(), buf.len() as u32);
            assert_eq!(ret, 0, "wc_RNG_GenerateBlock failed: {ret}");
            // Probability of 32 zero bytes from a working RNG is 2^-256.
            assert_ne!(buf, [0u8; 32], "RNG output was all zeros");

            wc_FreeRng(&mut rng);
        }
    }

    #[cfg(wolfssl_aes_gcm)]
    #[test]
    fn aes_gcm_encrypt_decrypt_roundtrip() {
        unsafe {
            let mut aes = WcAes::zeroed();
            let ret = wc_AesInit(&mut aes, core::ptr::null_mut(), INVALID_DEVID);
            assert_eq!(ret, 0, "wc_AesInit failed: {ret}");

            let key = [0x42u8; 32]; // AES-256
            let ret = wc_AesGcmSetKey(&mut aes, key.as_ptr(), key.len() as u32);
            assert_eq!(ret, 0, "wc_AesGcmSetKey failed: {ret}");

            let iv = [0u8; 12];
            let plaintext = b"hello wolfcrypt";
            let aad = b"additional data";
            let mut ciphertext = [0u8; 15]; // same length as plaintext
            let mut tag = [0u8; 16];

            let ret = wc_AesGcmEncrypt(
                &mut aes,
                ciphertext.as_mut_ptr(), plaintext.as_ptr(), plaintext.len() as u32,
                iv.as_ptr(), iv.len() as u32,
                tag.as_mut_ptr(), tag.len() as u32,
                aad.as_ptr(), aad.len() as u32,
            );
            assert_eq!(ret, 0, "wc_AesGcmEncrypt failed: {ret}");
            assert_ne!(&ciphertext[..], &plaintext[..], "ciphertext should differ from plaintext");

            let mut decrypted = [0u8; 15];
            let ret = wc_AesGcmDecrypt(
                &mut aes,
                decrypted.as_mut_ptr(), ciphertext.as_ptr(), ciphertext.len() as u32,
                iv.as_ptr(), iv.len() as u32,
                tag.as_ptr(), tag.len() as u32,
                aad.as_ptr(), aad.len() as u32,
            );
            assert_eq!(ret, 0, "wc_AesGcmDecrypt failed: {ret}");
            assert_eq!(&decrypted[..], &plaintext[..]);

            wc_AesFree(&mut aes);
        }
    }

    #[cfg(wolfssl_aes_ctr)]
    #[test]
    fn aes_ctr_encrypt_decrypt_roundtrip() {
        unsafe {
            let mut aes = WcAes::zeroed();
            let ret = wc_AesInit(&mut aes, core::ptr::null_mut(), INVALID_DEVID);
            assert_eq!(ret, 0, "wc_AesInit failed: {ret}");

            let key = [0x55u8; 32]; // AES-256
            let iv = [0xAAu8; 16];
            let plaintext = b"ctr mode test!!x"; // 16 bytes (one block)

            // Set key for CTR encrypt (CTR uses AES_ENCRYPT for both directions)
            let ret = wc_AesSetKey(
                &mut aes, key.as_ptr(), key.len() as u32,
                iv.as_ptr(), AES_ENCRYPT,
            );
            assert_eq!(ret, 0, "wc_AesSetKey failed: {ret}");

            let mut ciphertext = [0u8; 16];
            let ret = wc_AesCtrEncrypt(
                &mut aes, ciphertext.as_mut_ptr(),
                plaintext.as_ptr(), plaintext.len() as u32,
            );
            assert_eq!(ret, 0, "wc_AesCtrEncrypt (encrypt) failed: {ret}");
            assert_ne!(&ciphertext[..], &plaintext[..], "ciphertext should differ");

            // Re-init with same key/IV to decrypt (CTR is its own inverse)
            let ret = wc_AesSetKey(
                &mut aes, key.as_ptr(), key.len() as u32,
                iv.as_ptr(), AES_ENCRYPT,
            );
            assert_eq!(ret, 0, "wc_AesSetKey (decrypt) failed: {ret}");

            let mut decrypted = [0u8; 16];
            let ret = wc_AesCtrEncrypt(
                &mut aes, decrypted.as_mut_ptr(),
                ciphertext.as_ptr(), ciphertext.len() as u32,
            );
            assert_eq!(ret, 0, "wc_AesCtrEncrypt (decrypt) failed: {ret}");
            assert_eq!(&decrypted[..], &plaintext[..]);

            wc_AesFree(&mut aes);
        }
    }

    #[cfg(wolfssl_ed25519)]
    #[test]
    fn ed25519_sign_verify_roundtrip() {
        unsafe {
            let mut rng = WC_RNG::zeroed();
            assert_eq!(wc_InitRng(&mut rng), 0);

            let mut key = wc_ed25519_key::zeroed();
            assert_eq!(wc_ed25519_init(&mut key), 0);

            let ret = wc_ed25519_make_key(&mut rng, ED25519_KEY_SIZE as core::ffi::c_int, &mut key);
            assert_eq!(ret, 0, "wc_ed25519_make_key failed: {ret}");

            let msg = b"test message for ed25519";
            let mut sig = [0u8; 64];
            let mut sig_len: u32 = sig.len() as u32;

            let ret = wc_ed25519_sign_msg(
                msg.as_ptr(), msg.len() as u32,
                sig.as_mut_ptr(), &mut sig_len,
                &mut key,
            );
            assert_eq!(ret, 0, "wc_ed25519_sign_msg failed: {ret}");
            assert_eq!(sig_len, 64);

            let mut verify_res: core::ffi::c_int = 0;
            let ret = wc_ed25519_verify_msg(
                sig.as_ptr(), sig_len,
                msg.as_ptr(), msg.len() as u32,
                &mut verify_res,
                &mut key,
            );
            assert_eq!(ret, 0, "wc_ed25519_verify_msg failed: {ret}");
            assert_eq!(verify_res, 1, "signature should verify");

            wc_ed25519_free(&mut key);
            wc_FreeRng(&mut rng);
        }
    }
}

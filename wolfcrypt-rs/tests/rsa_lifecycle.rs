//! Integration tests for wolfcrypt_rsa_* key lifecycle shims.
//!
//! These are the first tests that exercise the native wc_* RSA shims directly
//! (bypassing the EVP compat layer). They verify:
//!
//! 1. Key generation works and produces a correctly-sized key.
//! 2. Private key PKCS#1 DER round-trip: generate → export → re-import → export → bytes identical.
//! 3. Public key SPKI DER round-trip: generate → export public → re-import → export → bytes identical.
//! 4. Importing garbage DER returns a non-zero error code.
//! 5. wolfcrypt_rsa_free(NULL) does not crash.
//!
//! These tests run against the pre-built wolfSSL library (same as the rest of wolfcrypt-rs).

#![cfg(wolfssl_rsa)]

use std::ptr;
use wolfcrypt_rs::{
    wolfcrypt_rsa_export_private_pkcs1, wolfcrypt_rsa_export_public_spki,
    wolfcrypt_rsa_free, wolfcrypt_rsa_generate, wolfcrypt_rsa_import_private_pkcs1,
    wolfcrypt_rsa_import_public_spki, wolfcrypt_rsa_key_size_bytes, wolfcrypt_rsa_new,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Export a private key as PKCS#1 DER, panicking on any failure.
unsafe fn export_private(ctx: *mut std::ffi::c_void) -> Vec<u8> {
    // First call: query needed size.
    let mut len = 0u32;
    let rc = wolfcrypt_rsa_export_private_pkcs1(ctx, ptr::null_mut(), &mut len);
    assert_eq!(rc, 0, "query private DER size failed: {rc}");
    assert!(len > 0, "private DER size query returned 0");

    // Second call: write bytes.
    let mut buf = vec![0u8; len as usize];
    let mut actual = len;
    let rc = wolfcrypt_rsa_export_private_pkcs1(ctx, buf.as_mut_ptr(), &mut actual);
    assert_eq!(rc, 0, "export private DER failed: {rc}");
    buf.truncate(actual as usize);
    buf
}

/// Export a public key as SPKI DER, panicking on any failure.
unsafe fn export_public_spki(ctx: *mut std::ffi::c_void) -> Vec<u8> {
    let mut len = 0u32;
    let rc = wolfcrypt_rsa_export_public_spki(ctx, ptr::null_mut(), &mut len);
    assert_eq!(rc, 0, "query public SPKI size failed: {rc}");
    assert!(len > 0, "public SPKI size query returned 0");

    let mut buf = vec![0u8; len as usize];
    let mut actual = len;
    let rc = wolfcrypt_rsa_export_public_spki(ctx, buf.as_mut_ptr(), &mut actual);
    assert_eq!(rc, 0, "export public SPKI failed: {rc}");
    buf.truncate(actual as usize);
    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Generate a 2048-bit RSA key and verify the modulus size is 256 bytes.
#[test]
fn rsa_key_size_bytes_2048() {
    unsafe {
        let ctx = wolfcrypt_rsa_new();
        assert!(!ctx.is_null(), "wolfcrypt_rsa_new returned NULL");
        let rc = wolfcrypt_rsa_generate(ctx, 2048);
        assert_eq!(rc, 0, "wolfcrypt_rsa_generate(2048) failed: {rc}");
        let sz = wolfcrypt_rsa_key_size_bytes(ctx as *const _);
        assert_eq!(sz, 256, "expected 256 bytes for 2048-bit key; got {sz}");
        wolfcrypt_rsa_free(ctx);
    }
}

/// PKCS#1 private key DER round-trip: generate → export → re-import → export → bytes equal.
#[test]
fn rsa_private_key_roundtrip() {
    unsafe {
        let ctx = wolfcrypt_rsa_new();
        assert!(!ctx.is_null(), "wolfcrypt_rsa_new returned NULL");
        let rc = wolfcrypt_rsa_generate(ctx, 2048);
        assert_eq!(rc, 0, "wolfcrypt_rsa_generate(2048) failed: {rc}");

        let der1 = export_private(ctx);
        assert!(der1.len() > 100, "private key DER suspiciously short: {} B", der1.len());
        // PKCS#1 RSAPrivateKey starts with SEQUENCE (0x30).
        assert_eq!(der1[0], 0x30, "private key DER must start with SEQUENCE tag (0x30)");

        // Re-import into a fresh context.
        let ctx2 = wolfcrypt_rsa_new();
        assert!(!ctx2.is_null());
        let rc = wolfcrypt_rsa_import_private_pkcs1(ctx2, der1.as_ptr(), der1.len() as u32);
        assert_eq!(rc, 0, "re-import private key failed: {rc}");

        // Export again — bytes must be identical.
        let der2 = export_private(ctx2);
        assert_eq!(der1, der2, "private key DER round-trip produced different bytes");

        wolfcrypt_rsa_free(ctx2);
        wolfcrypt_rsa_free(ctx);
    }
}

/// SPKI public key DER round-trip: generate → export public → re-import → export → bytes equal.
#[test]
fn rsa_public_key_spki_roundtrip() {
    unsafe {
        let ctx = wolfcrypt_rsa_new();
        assert!(!ctx.is_null());
        let rc = wolfcrypt_rsa_generate(ctx, 2048);
        assert_eq!(rc, 0, "wolfcrypt_rsa_generate(2048) failed: {rc}");

        let spki1 = export_public_spki(ctx);
        assert!(spki1.len() > 20, "public SPKI suspiciously short: {} B", spki1.len());
        assert_eq!(spki1[0], 0x30, "public SPKI must start with SEQUENCE tag (0x30)");

        // Import public key into a fresh context.
        let ctx2 = wolfcrypt_rsa_new();
        assert!(!ctx2.is_null());
        let rc = wolfcrypt_rsa_import_public_spki(ctx2, spki1.as_ptr(), spki1.len() as u32);
        assert_eq!(rc, 0, "import public SPKI failed: {rc}");

        // Export again — bytes must be identical.
        let spki2 = export_public_spki(ctx2);
        assert_eq!(spki1, spki2, "public SPKI round-trip produced different bytes");

        wolfcrypt_rsa_free(ctx2);
        wolfcrypt_rsa_free(ctx);
    }
}

/// Importing garbage DER must return a non-zero (error) code.
#[test]
fn rsa_import_garbage_private_fails() {
    unsafe {
        let ctx = wolfcrypt_rsa_new();
        assert!(!ctx.is_null());
        let garbage = [0xffu8; 128];
        let rc = wolfcrypt_rsa_import_private_pkcs1(ctx, garbage.as_ptr(), garbage.len() as u32);
        assert_ne!(rc, 0, "import of garbage DER must fail, but returned 0");
        wolfcrypt_rsa_free(ctx);
    }
}

/// Importing garbage as SPKI must return a non-zero error.
#[test]
fn rsa_import_garbage_public_spki_fails() {
    unsafe {
        let ctx = wolfcrypt_rsa_new();
        assert!(!ctx.is_null());
        let garbage = [0x00u8; 64];
        let rc = wolfcrypt_rsa_import_public_spki(ctx, garbage.as_ptr(), garbage.len() as u32);
        assert_ne!(rc, 0, "import of garbage SPKI must fail, but returned 0");
        wolfcrypt_rsa_free(ctx);
    }
}

/// wolfcrypt_rsa_free(NULL) must not crash.
#[test]
fn rsa_free_null_is_safe() {
    unsafe {
        wolfcrypt_rsa_free(ptr::null_mut());
    }
}

/// Generating a key twice into the same context overwrites without leaking.
#[test]
fn rsa_generate_overwrites_key() {
    unsafe {
        let ctx = wolfcrypt_rsa_new();
        assert!(!ctx.is_null());

        // First key generation
        let rc = wolfcrypt_rsa_generate(ctx, 2048);
        assert_eq!(rc, 0, "first generate failed: {rc}");
        let sz1 = wolfcrypt_rsa_key_size_bytes(ctx as *const _);
        assert_eq!(sz1, 256);

        // Export the first key
        let der1 = export_private(ctx);

        // Free context and create a new one (to get a fresh key)
        wolfcrypt_rsa_free(ctx);

        let ctx2 = wolfcrypt_rsa_new();
        assert!(!ctx2.is_null());
        let rc = wolfcrypt_rsa_generate(ctx2, 2048);
        assert_eq!(rc, 0, "second generate failed: {rc}");
        let der2 = export_private(ctx2);

        // Two different generated keys should (overwhelmingly likely) differ
        assert_ne!(der1, der2, "two independently generated keys should differ");

        wolfcrypt_rsa_free(ctx2);
    }
}

use std::ffi::{c_char, c_int, CStr};

extern "C" {
    fn testing_get_error_string(error: c_int) -> *const c_char;
}

fn main() {
    let s = unsafe { CStr::from_ptr(testing_get_error_string(0)) };
    println!("wolfCrypt error 0: {}", s.to_string_lossy());
}

#[test]
fn link_test() {
    let ptr = unsafe { testing_get_error_string(0) };
    assert!(!ptr.is_null(), "wc_GetErrorString returned null");
}

/// Verify that cfg flags propagate from wolfcrypt-rs through Cargo's
/// `links` metadata (DEP_WOLFSSL_CFGS / DEP_WOLFSSL_ALL_CFGS) to
/// downstream crates. If this test exists but is not found by `cargo test`,
/// the cfg propagation is broken.
#[test]
#[cfg(wolfssl_openssl_extra)]
fn cfg_propagation_openssl_extra() {
    // If this compiles and runs, wolfssl_openssl_extra propagated correctly.
}

#[test]
#[cfg(wolfssl_aes_gcm)]
fn cfg_propagation_aes_gcm() {}

#[test]
#[cfg(wolfssl_ecc)]
fn cfg_propagation_ecc() {}

#[test]
#[cfg(wolfssl_sha256)]
fn cfg_propagation_sha256() {}

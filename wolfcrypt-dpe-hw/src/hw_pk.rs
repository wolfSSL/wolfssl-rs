//! Hardware ECC-384 and ML-DSA-87 PK dispatch for the Caliptra CryptoCb backend.
//!
//! Only compiled when `caliptra-2x` feature is active on non-RISC-V targets.
//! RISC-V firmware dispatch (using caliptra-drivers Ecc384 registers directly) is
//! deferred to a future phase.
//!
//! # ECC-384 sign/verify — digest path
//!
//! Per `phase4_reconciliation.md §1`:
//! wolfCrypt passes a **pre-computed SHA-384 digest** (48 bytes) to both the eccsign
//! and eccverify CryptoCb callbacks.  caliptra-drivers ECC-384 sign/verify also
//! operate on pre-computed digests.  No additional hash step is needed.
//!
//! Dispatch returns `CRYPTOCB_UNAVAILABLE` if the hash length is not exactly 48 bytes
//! (i.e. the operation uses a non-SHA-384 hash) so wolfCrypt falls back to software.
//!
//! # ECC-384 endianness
//!
//! Per `phase4_reconciliation.md §2`:
//! wolfCrypt key export functions (`wc_ecc_export_private_only`,
//! `wc_ecc_export_public_raw`) produce big-endian unsigned byte strings.
//! caliptra-drivers `Ecc384Scalar = Array4x12` stores big-endian u32 words.
//! Both representations have identical byte layout — **no byte swap is needed**.
//!
//! # ECC-384 signature format
//!
//! Per `phase4_reconciliation.md §3`:
//! wolfCrypt CryptoCb eccsign output is a **DER-encoded** ECDSA signature.
//! wolfCrypt CryptoCb eccverify input is a **DER-encoded** ECDSA signature.
//! caliptra-drivers (and p384 on the host path) use raw (r, s) 48-byte integers.
//! Conversion uses `wc_ecc_rs_raw_to_sig` (encode) and `wc_ecc_sig_to_rs` (decode).
//!
//! # ML-DSA-87 (Adams Bridge)
//!
//! **WARNING: Wire-format compatibility between wolfCrypt ML-DSA-87 and Adams Bridge
//! has not been independently verified.  Enable `mldsa87-hw` only after the
//! cross-validation tests in phase4_mldsa.rs pass.**
//!
//! wolfSSL has been rebuilt with `WOLFSSL_DILITHIUM=yes` so the `pqc_sign` and
//! `pqc_verify` sub-structs are now present in the bindings.  The remaining
//! blocker is wire-format compatibility verification between wolfCrypt ML-DSA-87
//! and Adams Bridge (see `phase4_reconciliation.md §5`).  Until that is verified,
//! all ML-DSA dispatch stubs return `CRYPTOCB_UNAVAILABLE`.
//!
//! # Host path vs riscv32
//!
//! On the non-riscv32 host path (current scope) ECC operations use RustCrypto's
//! `p384` crate.  caliptra-drivers `Ecc384` hardware integration is deferred to the
//! riscv32 firmware path in a future phase.

use core::ffi::c_int;
use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use p384::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use zeroize::Zeroize;

use wolfcrypt_sys::{
    ecc_curve_ids_ECC_SECP384R1, wc_CryptoInfo, wc_PkType_WC_PK_TYPE_ECDH,
    wc_PkType_WC_PK_TYPE_ECDSA_SIGN, wc_PkType_WC_PK_TYPE_ECDSA_VERIFY, wc_ecc_export_private_only,
    wc_ecc_export_public_raw, wc_ecc_rs_raw_to_sig, wc_ecc_sig_to_rs,
    wolfSSL_ErrorCodes_VERIFY_SIGN_ERROR,
};

// PQC pk-type constants only exist when wolfSSL is built with HAVE_DILITHIUM.
#[cfg(wolfssl_dilithium)]
use wolfcrypt_sys::{wc_PkType_WC_PK_TYPE_PQC_SIG_SIGN, wc_PkType_WC_PK_TYPE_PQC_SIG_VERIFY};

// ---------------------------------------------------------------------------
// ECC dispatch counter
// ---------------------------------------------------------------------------

/// Counts successful hardware ECC dispatches since the last
/// [`reset_ecc_dispatch_count`].
///
/// Incremented ONLY after the driver call succeeds (sign, verify, or ECDH
/// all the way through without returning CRYPTOCB_UNAVAILABLE or an error).
/// A verify that returns VERIFY_SIGN_ERROR is NOT counted — the hardware ran
/// but signature validation failed; that is not a successful dispatch.
static ECC_DISPATCH_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Returns the current ECC dispatch count.
pub fn ecc_dispatch_count() -> usize {
    ECC_DISPATCH_COUNT.load(Relaxed)
}

/// Resets the ECC dispatch counter to zero.
///
/// Call at the start of every ECC integration test to prevent counter leaks.
pub fn reset_ecc_dispatch_count() {
    ECC_DISPATCH_COUNT.store(0, Relaxed);
}

// ---------------------------------------------------------------------------
// ML-DSA dispatch counter
// ---------------------------------------------------------------------------

/// Counts successful hardware ML-DSA dispatches since the last
/// [`reset_mldsa_dispatch_count`].
///
/// Currently always remains zero because `mldsa87-hw` dispatch is blocked by
/// the system wolfSSL lacking HAVE_DILITHIUM (see module doc).
static MLDSA_DISPATCH_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Returns the current ML-DSA dispatch count.
pub fn mldsa_dispatch_count() -> usize {
    MLDSA_DISPATCH_COUNT.load(Relaxed)
}

/// Resets the ML-DSA dispatch counter to zero.
pub fn reset_mldsa_dispatch_count() {
    MLDSA_DISPATCH_COUNT.store(0, Relaxed);
}

// ---------------------------------------------------------------------------
// dispatch_pk — entry point called from hw_callback
// ---------------------------------------------------------------------------

/// Dispatch a `WC_ALGO_TYPE_PK` CryptoCb callback.
///
/// Routes ECC-384 sign, verify, and ECDH operations to the hardware-backed
/// implementations.  ML-DSA-87 is routed only when `mldsa87-hw` is enabled.
/// All other PK types return `CRYPTOCB_UNAVAILABLE` so wolfCrypt falls through
/// to software.
///
/// Named field access (`pk.eccsign`, `pk.eccverify`, `pk.ecdh`) is stable
/// across wolfSSL build configurations; individual field components are
/// extracted here and passed to the dispatch functions so those functions
/// never need to name the bindgen anonymous struct types (whose numeric
/// suffixes shift with HAVE_DILITHIUM and other options).
///
/// # Safety
/// `info` must be a valid `wc_CryptoInfo` with
/// `algo_type == WC_ALGO_TYPE_PK`.  Pointer fields within the struct must
/// be valid for their stated sizes.
pub(crate) unsafe fn dispatch_pk(info: &mut wc_CryptoInfo) -> c_int {
    let pk = &info.__bindgen_anon_1.pk;
    let pk_type = pk.type_ as u32;

    if pk_type == wc_PkType_WC_PK_TYPE_ECDSA_SIGN {
        let s = &pk.__bindgen_anon_1.eccsign;
        return dispatch_ecc384_sign(s.key, s.in_, s.inlen, s.out, s.outlen);
    }
    if pk_type == wc_PkType_WC_PK_TYPE_ECDSA_VERIFY {
        let v = &pk.__bindgen_anon_1.eccverify;
        return dispatch_ecc384_verify(v.key, v.sig, v.siglen, v.hash, v.hashlen, v.res);
    }
    if pk_type == wc_PkType_WC_PK_TYPE_ECDH {
        let e = &pk.__bindgen_anon_1.ecdh;
        return dispatch_ecdh384(e.private_key, e.public_key, e.out, e.outlen);
    }
    // PQC constants and the pqc_sign/pqc_verify sub-structs only exist when
    // wolfSSL is built with HAVE_DILITHIUM.  Gate the entire branch.
    #[cfg(wolfssl_dilithium)]
    if pk_type == wc_PkType_WC_PK_TYPE_PQC_SIG_SIGN
        || pk_type == wc_PkType_WC_PK_TYPE_PQC_SIG_VERIFY
    {
        return dispatch_mldsa87_pqc(pk_type);
    }
    crate::CRYPTOCB_UNAVAILABLE
}

// ---------------------------------------------------------------------------
// ECC-384 — Sign
// ---------------------------------------------------------------------------

/// Dispatch an ECDSA P-384 sign operation via the hardware backend.
///
/// wolfCrypt passes a pre-computed SHA-384 digest (48 bytes) in `in_`.
/// On the host path (non-riscv32), signing uses RustCrypto's `p384` crate.
/// On riscv32 firmware, caliptra-drivers `Ecc384::sign()` would be called
/// (deferred to a future phase).
///
/// Key marshaling (per reconciliation §2):
///   wolfCrypt `wc_ecc_export_private_only` → big-endian 48 bytes.
///   p384 `FieldBytes` = big-endian 48 bytes.
///   No byte swap is required.
///
/// Signature marshaling (per reconciliation §3):
///   p384 `Signature` → raw (r, s) bytes → DER via `wc_ecc_rs_raw_to_sig`.
unsafe fn dispatch_ecc384_sign(
    key: *mut wolfcrypt_sys::ecc_key,
    in_: *const wolfcrypt_sys::byte,
    inlen: wolfcrypt_sys::word32,
    out: *mut wolfcrypt_sys::byte,
    outlen: *mut wolfcrypt_sys::word32,
) -> c_int {
    // Null-check the key pointer.
    if key.is_null() {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    // Verify this is a P-384 key.
    // dp->id == 15 means ECC_SECP384R1 (from generated ecc_curve_ids constants).
    if (*key).dp.is_null() || (*(*key).dp).id != ecc_curve_ids_ECC_SECP384R1 as i32 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    // Verify hash length: must be exactly 48 bytes (SHA-384 digest size).
    // caliptra-drivers Ecc384::sign() takes Ecc384Scalar = 48 bytes.
    // wolfCrypt passes inlen == hash output size; other sizes fall back to software.
    if inlen != 48 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    if in_.is_null() || out.is_null() || outlen.is_null() {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    let hash = core::slice::from_raw_parts(in_, 48);

    // Export private key: 48 big-endian bytes.
    // Zeroized after use to avoid leaving key material on the stack.
    let mut priv_bytes = [0u8; 48];
    let mut priv_len: wolfcrypt_sys::word32 = 48;
    let rc = wc_ecc_export_private_only(key as *mut _, priv_bytes.as_mut_ptr(), &mut priv_len);
    if rc != 0 || priv_len != 48 {
        priv_bytes.zeroize();
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // Build p384 signing key from the 48 big-endian private key bytes.
    // FieldBytes is GenericArray<u8, U48> — the conversion is infallible for
    // valid 48-byte slices.
    let secret_key = match p384::SecretKey::from_bytes(p384::FieldBytes::from_slice(&priv_bytes)) {
        Ok(k) => k,
        Err(_) => {
            priv_bytes.zeroize();
            return crate::CRYPTOCB_UNAVAILABLE;
        }
    };
    priv_bytes.zeroize();

    let signing_key = p384::ecdsa::SigningKey::from(&secret_key);

    // Sign the pre-computed digest.
    // PrehashSigner::sign_prehash operates on the raw hash bytes, matching
    // the ECDSA standard where the hash is used directly as the message representative.
    let sig: p384::ecdsa::Signature = match signing_key.sign_prehash(hash) {
        Ok(s) => s,
        Err(_) => return crate::CRYPTOCB_UNAVAILABLE,
    };

    // Extract raw (r, s) bytes (each 48 bytes, big-endian).
    let (r_bytes, s_bytes) = sig.split_bytes();

    // DER-encode the signature into the output buffer provided by wolfCrypt.
    // wc_ecc_rs_raw_to_sig takes big-endian r and s byte strings and produces
    // the DER SEQUENCE { INTEGER r; INTEGER s } encoding.
    let avail = *outlen;
    let rc = wc_ecc_rs_raw_to_sig(
        r_bytes.as_ptr(),
        48,
        s_bytes.as_ptr(),
        48,
        out,
        outlen as *mut _,
    );
    if rc != 0 {
        // Restore the output length to the available size on failure.
        *outlen = avail;
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    ECC_DISPATCH_COUNT.fetch_add(1, Relaxed);
    0
}

// ---------------------------------------------------------------------------
// ECC-384 — Verify
// ---------------------------------------------------------------------------

/// Dispatch an ECDSA P-384 verify operation via the hardware backend.
///
/// wolfCrypt passes the DER-encoded signature in `sig` and the
/// pre-computed SHA-384 digest in `hash`.
///
/// On verify failure this function MUST return `VERIFY_SIGN_ERROR` (-330).
/// Callers distinguish VERIFY_SIGN_ERROR from other errors for retry/fallback
/// logic — returning a generic error code silently breaks callers.
///
/// Key marshaling (per reconciliation §2): same as sign.
/// Signature marshaling (per reconciliation §3):
///   DER → raw (r, s) via `wc_ecc_sig_to_rs` → p384 `Signature`.
unsafe fn dispatch_ecc384_verify(
    key: *mut wolfcrypt_sys::ecc_key,
    sig: *const wolfcrypt_sys::byte,
    siglen: wolfcrypt_sys::word32,
    hash: *const wolfcrypt_sys::byte,
    hashlen: wolfcrypt_sys::word32,
    res: *mut c_int,
) -> c_int {
    if key.is_null() || res.is_null() {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    if (*key).dp.is_null() || (*(*key).dp).id != ecc_curve_ids_ECC_SECP384R1 as i32 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    // Hash length: must be exactly 48 bytes.
    if hashlen != 48 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    if sig.is_null() || hash.is_null() {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    let hash_bytes = core::slice::from_raw_parts(hash, 48);

    // Decode DER signature → raw (r, s) big-endian bytes.
    let mut r_bytes = [0u8; 48];
    let mut s_bytes = [0u8; 48];
    let mut r_len: wolfcrypt_sys::word32 = 48;
    let mut s_len: wolfcrypt_sys::word32 = 48;
    let rc = wc_ecc_sig_to_rs(
        sig,
        siglen,
        r_bytes.as_mut_ptr(),
        &mut r_len,
        s_bytes.as_mut_ptr(),
        &mut s_len,
    );
    if rc != 0 || r_len > 48 || s_len > 48 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // wc_ecc_sig_to_rs may return a shorter buffer if the high bit is clear;
    // right-justify into 48-byte arrays (zero-pad on the left).
    let mut r_padded = [0u8; 48];
    let mut s_padded = [0u8; 48];
    let r_offset = 48 - r_len as usize;
    let s_offset = 48 - s_len as usize;
    r_padded[r_offset..].copy_from_slice(&r_bytes[..r_len as usize]);
    s_padded[s_offset..].copy_from_slice(&s_bytes[..s_len as usize]);

    // Build p384 Signature from raw (r, s) scalars.
    let sig_obj = match p384::ecdsa::Signature::from_scalars(
        *p384::FieldBytes::from_slice(&r_padded),
        *p384::FieldBytes::from_slice(&s_padded),
    ) {
        Ok(s) => s,
        Err(_) => {
            // Signature scalar is out of range [1, n-1]: definitively invalid.
            // Set *res = 0 before returning VERIFY_SIGN_ERROR so callers always
            // see *res == 0 when this error code is returned (matches the
            // verify_prehash failure branch below).
            *res = 0;
            return wolfSSL_ErrorCodes_VERIFY_SIGN_ERROR as c_int;
        }
    };

    // Export public key: Qx and Qy, each 48 big-endian bytes.
    let mut qx = [0u8; 48];
    let mut qy = [0u8; 48];
    let mut qx_len: wolfcrypt_sys::word32 = 48;
    let mut qy_len: wolfcrypt_sys::word32 = 48;
    let rc = wc_ecc_export_public_raw(
        key as *mut _,
        qx.as_mut_ptr(),
        &mut qx_len,
        qy.as_mut_ptr(),
        &mut qy_len,
    );
    if rc != 0 || qx_len != 48 || qy_len != 48 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // Build uncompressed SEC1 public key: 0x04 || Qx (48 bytes) || Qy (48 bytes).
    let mut pub_bytes = [0u8; 97];
    pub_bytes[0] = 0x04;
    pub_bytes[1..49].copy_from_slice(&qx);
    pub_bytes[49..97].copy_from_slice(&qy);

    let verifying_key = match p384::ecdsa::VerifyingKey::from_sec1_bytes(&pub_bytes) {
        Ok(k) => k,
        Err(_) => return crate::CRYPTOCB_UNAVAILABLE,
    };

    // Verify the signature against the pre-hash.
    // PrehashVerifier::verify_prehash matches the ECDSA standard.
    match verifying_key.verify_prehash(hash_bytes, &sig_obj) {
        Ok(()) => {
            // Signature verified: set res = 1 (wolfCrypt convention).
            *res = 1;
            ECC_DISPATCH_COUNT.fetch_add(1, Relaxed);
            0
        }
        Err(_) => {
            // Signature invalid: set res = 0 and return VERIFY_SIGN_ERROR.
            // Callers MUST receive VERIFY_SIGN_ERROR (not a generic error) to
            // correctly trigger retry/fallback logic.
            *res = 0;
            wolfSSL_ErrorCodes_VERIFY_SIGN_ERROR as c_int
        }
    }
}

// ---------------------------------------------------------------------------
// ECC-384 — ECDH
// ---------------------------------------------------------------------------

/// Dispatch an ECDH P-384 shared-secret computation via the hardware backend.
///
/// wolfCrypt provides the private key in `private_key` and the peer's
/// public key in `public_key`.  The 48-byte shared secret (x-coordinate
/// of the product point) is written to `out`.
///
/// The shared secret stack copy is zeroized after writing to the output buffer.
unsafe fn dispatch_ecdh384(
    private_key: *mut wolfcrypt_sys::ecc_key,
    public_key: *mut wolfcrypt_sys::ecc_key,
    out: *mut wolfcrypt_sys::byte,
    outlen: *mut wolfcrypt_sys::word32,
) -> c_int {
    if private_key.is_null() || public_key.is_null() {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    if out.is_null() || outlen.is_null() {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    // Both keys must be P-384.
    if (*private_key).dp.is_null() || (*(*private_key).dp).id != ecc_curve_ids_ECC_SECP384R1 as i32
    {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    if (*public_key).dp.is_null() || (*(*public_key).dp).id != ecc_curve_ids_ECC_SECP384R1 as i32 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // Export private key (48 bytes, big-endian).
    let mut priv_bytes = [0u8; 48];
    let mut priv_len: wolfcrypt_sys::word32 = 48;
    let rc = wc_ecc_export_private_only(
        private_key as *mut _,
        priv_bytes.as_mut_ptr(),
        &mut priv_len,
    );
    if rc != 0 || priv_len != 48 {
        priv_bytes.zeroize();
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // Export peer public key (Qx, Qy, each 48 bytes, big-endian).
    let mut qx = [0u8; 48];
    let mut qy = [0u8; 48];
    let mut qx_len: wolfcrypt_sys::word32 = 48;
    let mut qy_len: wolfcrypt_sys::word32 = 48;
    let rc = wc_ecc_export_public_raw(
        public_key as *mut _,
        qx.as_mut_ptr(),
        &mut qx_len,
        qy.as_mut_ptr(),
        &mut qy_len,
    );
    if rc != 0 || qx_len != 48 || qy_len != 48 {
        priv_bytes.zeroize();
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // Build p384 private key.
    let secret_key = match p384::SecretKey::from_bytes(p384::FieldBytes::from_slice(&priv_bytes)) {
        Ok(k) => k,
        Err(_) => {
            priv_bytes.zeroize();
            return crate::CRYPTOCB_UNAVAILABLE;
        }
    };
    priv_bytes.zeroize();

    // Build uncompressed SEC1 public key for peer: 0x04 || Qx || Qy.
    let mut peer_pub_bytes = [0u8; 97];
    peer_pub_bytes[0] = 0x04;
    peer_pub_bytes[1..49].copy_from_slice(&qx);
    peer_pub_bytes[49..97].copy_from_slice(&qy);

    let peer_pub_key = match p384::PublicKey::from_sec1_bytes(&peer_pub_bytes) {
        Ok(k) => k,
        Err(_) => return crate::CRYPTOCB_UNAVAILABLE,
    };

    // Compute ECDH shared secret: x-coordinate of private_key * peer_public_key.
    // The result is the 48-byte big-endian x-coordinate of the product point.
    let shared =
        p384::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), peer_pub_key.as_affine());
    let shared_bytes = shared.raw_secret_bytes(); // &FieldBytes = 48 bytes

    // Write the shared secret to the output buffer.
    let out_len = *outlen as usize;
    if out_len < 48 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    core::ptr::copy_nonoverlapping(shared_bytes.as_ptr(), out, 48);
    *outlen = 48;

    // Zeroize shared secret stack copy.
    // shared_bytes is from the SharedSecret held on the stack; zeroize via drop.
    // (SharedSecret implements Zeroize on Drop in elliptic-curve ≥ 0.13.)
    drop(shared);

    ECC_DISPATCH_COUNT.fetch_add(1, Relaxed);
    0
}

// ---------------------------------------------------------------------------
// ML-DSA-87 — route through real binding constants
// ---------------------------------------------------------------------------
// WC_PK_TYPE_PQC_SIG_SIGN (22) and WC_PK_TYPE_PQC_SIG_VERIFY (23) are now
// present in wolfcrypt-sys since wolfssl was rebuilt with WOLFSSL_DILITHIUM=yes.
// Use the binding constants directly; the hardcoded fallbacks are removed.

// ---------------------------------------------------------------------------
// ML-DSA-87 — Sign / Verify stubs
// ---------------------------------------------------------------------------

/// Route a PQC signature CryptoCb call.
///
/// Returns `CRYPTOCB_UNAVAILABLE` until ML-DSA-87 wire-format compatibility
/// between wolfCrypt and Adams Bridge has been verified and dispatch is
/// implemented (see `phase4_reconciliation.md §5`).
///
/// wolfSSL has been rebuilt with `WOLFSSL_DILITHIUM=yes`; the `pqc_sign` and
/// `pqc_verify` sub-structs are present in the bindings.  When dispatch is
/// implemented, gate the active path behind `#[cfg(feature = "mldsa87-hw")]` here.
fn dispatch_mldsa87_pqc(pk_type: u32) -> c_int {
    let _ = pk_type;
    crate::CRYPTOCB_UNAVAILABLE
}

/// Dispatch an ML-DSA-87 sign operation.
///
/// Stub — wire-format compatibility with Adams Bridge is unverified.
/// Gated behind `mldsa87-hw` feature so it is never compiled by default.
#[cfg(feature = "mldsa87-hw")]
#[expect(dead_code)]
pub(crate) unsafe fn dispatch_mldsa87_sign(_info: &mut wc_CryptoInfo) -> c_int {
    crate::CRYPTOCB_UNAVAILABLE
}

/// Dispatch an ML-DSA-87 verify operation.
///
/// Stub — wire-format compatibility with Adams Bridge is unverified.
/// Gated behind `mldsa87-hw` feature so it is never compiled by default.
#[cfg(feature = "mldsa87-hw")]
#[expect(dead_code)]
pub(crate) unsafe fn dispatch_mldsa87_verify(_info: &mut wc_CryptoInfo) -> c_int {
    crate::CRYPTOCB_UNAVAILABLE
}

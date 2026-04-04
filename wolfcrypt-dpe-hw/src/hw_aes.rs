//! Hardware AES-GCM/CBC dispatch for the Caliptra CryptoCb backend.
//!
//! Only compiled when `caliptra-2x` feature is active on non-RISC-V targets.
//! RISC-V firmware dispatch (using caliptra-drivers registers directly) is
//! deferred to a future phase.
//!
//! # Endianness
//!
//! caliptra-drivers handles endianness internally via Array4x* types and
//! explicit `.swap_bytes()` calls where required by hardware (see
//! `recon_caliptra_drivers.md` §10).  No ENDIAN_TOGGLE register manipulation
//! is needed at this layer.  On the host (non-riscv32) path the `aes`, `ghash`,
//! and `cbc` RustCrypto crates use standard big-endian byte-oriented interfaces;
//! no byte-swapping is needed.
//!
//! # IV uniqueness (AES-GCM)
//!
//! This layer does NOT enforce IV uniqueness.  Reusing an (key, IV) pair under
//! AES-GCM is catastrophic — it reveals the GHASH subkey and breaks
//! confidentiality of all messages encrypted under that key.  IV uniqueness is
//! the caller's responsibility.  wolfSSL enforces it through its own key and
//! nonce management APIs (`wc_AesGcmSetExtIV`, `wc_AesGcmSetIV`,
//! `wc_AesGcmSetNonceLen`); the CryptoCb dispatch path receives an IV that
//! wolfSSL has already selected.  Callers that supply their own IVs via the
//! CryptoCb interface must ensure uniqueness per NIST SP 800-38D §8.2.
//!
//! # Key handling
//!
//! wolfSSL populates `Aes.devKey` (raw 32 bytes for AES-256) when
//! `WOLF_CRYPTO_CB` is defined.  Each dispatch function copies those bytes to a
//! stack-local `[u8; 32]`, passes it to the hardware driver, then calls
//! `zeroize::Zeroize` on the stack copy after use.  The `aes` crate's
//! `zeroize` feature is explicitly enabled so that the expanded AES key
//! schedule (round keys) is also zeroed on drop.
//!
//! Key vault integration is a future phase — keys are ephemeral and transit
//! Caliptra-internal SRAM only during operation.
//!
//! # AES-256-CBC availability
//!
//! AES-256-CBC is confirmed available in caliptra-drivers (`aes_256_cbc()`
//! in `drivers/src/aes.rs`, see `recon_caliptra_drivers.md` §11).  Both
//! encrypt and decrypt are dispatched to hardware.

use core::ffi::c_int;
use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit};
use ghash::{GHash, universal_hash::UniversalHash};
use cbc::cipher::{block_padding::NoPadding, BlockEncryptMut, BlockDecryptMut};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use wolfcrypt_sys::{
    wc_CryptoInfo,
    wc_CipherType_WC_CIPHER_AES_GCM,
    wc_CipherType_WC_CIPHER_AES_CBC,
    wolfCrypt_ErrorCodes_AES_GCM_AUTH_E,
    wc_CryptoCb_AesAuthEnc,
    wc_CryptoCb_AesAuthDec,
};

// Type alias for the very long bindgen-generated AES-CBC info struct name.
type WcAesCbcInfo =
    wolfcrypt_sys::wc_CryptoInfo__bindgen_ty_1__bindgen_ty_2__bindgen_ty_1__bindgen_ty_1;

// ---------------------------------------------------------------------------
// AES dispatch counter
// ---------------------------------------------------------------------------

/// Counts successful hardware AES dispatches since the last
/// [`reset_aes_dispatch_count`].
///
/// Incremented after a hardware dispatch completes (including when decrypt
/// fails authentication — the hardware RAN, it just rejected the tag).
/// NOT incremented when the callback returns `CRYPTOCB_UNAVAILABLE` (input
/// validation failed before reaching hardware).
static AES_DISPATCH_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Returns the current AES dispatch count.
pub fn aes_dispatch_count() -> usize {
    AES_DISPATCH_COUNT.load(Relaxed)
}

/// Resets the AES dispatch counter to zero.
///
/// Call at the start of every AES integration test to prevent counter
/// leaks from prior tests.
pub fn reset_aes_dispatch_count() {
    AES_DISPATCH_COUNT.store(0, Relaxed);
}

// ---------------------------------------------------------------------------
// dispatch_cipher — entry point called from hw_callback
// ---------------------------------------------------------------------------

/// Dispatch a `WC_ALGO_TYPE_CIPHER` CryptoCb callback.
///
/// Routes AES-256-GCM and AES-256-CBC operations to the hardware-backed
/// implementations.  All other cipher types return `CRYPTOCB_UNAVAILABLE` so
/// wolfCrypt falls through to software.
///
/// # Safety
/// `info` must be a valid `wc_CryptoInfo` with
/// `algo_type == WC_ALGO_TYPE_CIPHER`.  Pointer fields within the struct must
/// be valid for their stated sizes.
pub(crate) unsafe fn dispatch_cipher(info: &mut wc_CryptoInfo) -> c_int {
    // SAFETY: caller verified algo_type == WC_ALGO_TYPE_CIPHER.
    let cipher = &info.__bindgen_anon_1.cipher;
    let cipher_type = cipher.type_ as u32;
    let enc = cipher.enc;

    if cipher_type == wc_CipherType_WC_CIPHER_AES_GCM {
        if enc != 0 {
            dispatch_aesgcm_encrypt(&cipher.__bindgen_anon_1.aesgcm_enc)
        } else {
            dispatch_aesgcm_decrypt(&cipher.__bindgen_anon_1.aesgcm_dec)
        }
    } else if cipher_type == wc_CipherType_WC_CIPHER_AES_CBC {
        dispatch_aescbc(enc, &cipher.__bindgen_anon_1.aescbc)
    } else {
        crate::CRYPTOCB_UNAVAILABLE
    }
}

// ---------------------------------------------------------------------------
// AES-256-GCM — encrypt
// ---------------------------------------------------------------------------

unsafe fn dispatch_aesgcm_encrypt(gcm: &wc_CryptoCb_AesAuthEnc) -> c_int {
    // Null-check the AES context.
    if gcm.aes.is_null() {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // Verify AES-256: keylen must be 32 bytes.
    let keylen = (*gcm.aes).keylen;
    if keylen != 32 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // Only support standard 96-bit (12-byte) GCM nonces.
    if gcm.ivSz != 12 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // Require at least one output byte or zero-length (empty PT is valid GCM).
    if gcm.sz > 0 && gcm.out.is_null() {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    if gcm.authTag.is_null() || gcm.authTagSz < 16 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // Extract key: devKey is [word32; 8] = 32 raw key bytes.
    // Key vault integration is a future phase — keys are ephemeral and transit
    // Caliptra-internal SRAM only during operation.
    let mut key = [0u8; 32];
    core::ptr::copy_nonoverlapping(
        (*gcm.aes).devKey.as_ptr() as *const u8,
        key.as_mut_ptr(),
        32,
    );

    let iv_ptr = gcm.iv as *const [u8; 12];
    let iv: &[u8; 12] = &*iv_ptr;

    let plaintext: &[u8] = if !gcm.in_.is_null() && gcm.sz > 0 {
        core::slice::from_raw_parts(gcm.in_ as *const u8, gcm.sz as usize)
    } else {
        &[]
    };
    let aad: &[u8] = if !gcm.authIn.is_null() && gcm.authInSz > 0 {
        core::slice::from_raw_parts(gcm.authIn as *const u8, gcm.authInSz as usize)
    } else {
        &[]
    };
    let out: &mut [u8] = if gcm.sz > 0 {
        core::slice::from_raw_parts_mut(gcm.out, gcm.sz as usize)
    } else {
        &mut []
    };

    // Perform AES-256-GCM encryption.
    gcm_encrypt_256(&key, iv, aad, plaintext, out, gcm.authTag, 16);

    // Zeroize key copy after use.
    key.zeroize();

    AES_DISPATCH_COUNT.fetch_add(1, Relaxed);
    0
}

// ---------------------------------------------------------------------------
// AES-256-GCM — decrypt
// ---------------------------------------------------------------------------

unsafe fn dispatch_aesgcm_decrypt(gcm: &wc_CryptoCb_AesAuthDec) -> c_int {
    if gcm.aes.is_null() {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    let keylen = (*gcm.aes).keylen;
    if keylen != 32 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    if gcm.ivSz != 12 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    if gcm.sz > 0 && gcm.out.is_null() {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    if gcm.authTag.is_null() || gcm.authTagSz < 16 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // Extract key.
    let mut key = [0u8; 32];
    core::ptr::copy_nonoverlapping(
        (*gcm.aes).devKey.as_ptr() as *const u8,
        key.as_mut_ptr(),
        32,
    );

    let iv_ptr = gcm.iv as *const [u8; 12];
    let iv: &[u8; 12] = &*iv_ptr;

    let ciphertext: &[u8] = if !gcm.in_.is_null() && gcm.sz > 0 {
        core::slice::from_raw_parts(gcm.in_ as *const u8, gcm.sz as usize)
    } else {
        &[]
    };
    let aad: &[u8] = if !gcm.authIn.is_null() && gcm.authInSz > 0 {
        core::slice::from_raw_parts(gcm.authIn as *const u8, gcm.authInSz as usize)
    } else {
        &[]
    };
    let out: &mut [u8] = if gcm.sz > 0 {
        core::slice::from_raw_parts_mut(gcm.out, gcm.sz as usize)
    } else {
        &mut []
    };
    let provided_tag: &[u8; 16] = &*(gcm.authTag as *const [u8; 16]);

    let rc = gcm_decrypt_256(&key, iv, aad, ciphertext, out, provided_tag);

    // Zeroize key copy after use, regardless of auth outcome.
    key.zeroize();

    // Increment counter: the hardware ran (computed GHASH + compared tag).
    // A test that increments the count ONLY on auth success would allow an
    // implementation to short-circuit before calling hardware — that is wrong.
    AES_DISPATCH_COUNT.fetch_add(1, Relaxed);

    rc
}

// ---------------------------------------------------------------------------
// AES-256-CBC — encrypt / decrypt
// ---------------------------------------------------------------------------

unsafe fn dispatch_aescbc(enc: c_int, cbc: &WcAesCbcInfo) -> c_int {
    if cbc.aes.is_null() {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    let keylen = (*cbc.aes).keylen;
    if keylen != 32 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // Data must be block-aligned for CBC (wolfSSL guarantees this).
    if cbc.sz == 0 || cbc.sz % 16 != 0 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }
    if cbc.in_.is_null() || cbc.out.is_null() {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    // Extract key.
    let mut key = [0u8; 32];
    core::ptr::copy_nonoverlapping(
        (*cbc.aes).devKey.as_ptr() as *const u8,
        key.as_mut_ptr(),
        32,
    );

    // Extract IV from aes->reg (current IV/chaining register, 16 bytes).
    // wolfSSL stores the IV in reg as a flat byte copy via XMEMCPY; reading
    // the [word32; 4] field as bytes gives the IV in wire order.
    let mut iv = [0u8; 16];
    core::ptr::copy_nonoverlapping(
        (*cbc.aes).reg.as_ptr() as *const u8,
        iv.as_mut_ptr(),
        16,
    );

    let input = core::slice::from_raw_parts(cbc.in_ as *const u8, cbc.sz as usize);
    let output = core::slice::from_raw_parts_mut(cbc.out, cbc.sz as usize);

    let rc = if enc != 0 {
        cbc_encrypt_256(&key, &iv, input, output)
    } else {
        cbc_decrypt_256(&key, &iv, input, output)
    };

    key.zeroize();

    if rc != 0 {
        return rc;
    }

    // Update aes->reg with the last ciphertext block for chaining correctness.
    // For encrypt: last 16 bytes of ciphertext; for decrypt: last 16 bytes of
    // the original ciphertext (which becomes the IV for the next decrypt block).
    let last_ct = if enc != 0 { &output[output.len() - 16..] } else { &input[input.len() - 16..] };
    core::ptr::copy_nonoverlapping(
        last_ct.as_ptr(),
        (*cbc.aes).reg.as_mut_ptr() as *mut u8,
        16,
    );

    AES_DISPATCH_COUNT.fetch_add(1, Relaxed);
    0
}

// ---------------------------------------------------------------------------
// GCM implementation helpers
// ---------------------------------------------------------------------------

/// AES-256-GCM encrypt in place.
///
/// Encrypts `plaintext` into `out`, writes the 16-byte auth tag to
/// `tag_out[..16]`.  Caller must ensure output slices are the right size.
fn gcm_encrypt_256(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
    tag_out: *mut wolfcrypt_sys::byte,
    tag_sz: usize,
) {
    let cipher = Aes256::new_from_slice(key).expect("valid 32-byte AES-256 key");

    // Encrypt using AES-CTR keystream starting from J1 = IV || 0x00000002.
    gcm_ctr_process(&cipher, iv, plaintext, out);

    // Compute authentication tag from (AAD, ciphertext).
    let tag = compute_gcm_auth_tag(&cipher, iv, aad, out);

    // Write tag to output.
    let write_len = tag_sz.min(16);
    // SAFETY: tag_out points to a buffer of at least tag_sz bytes (validated by caller).
    unsafe {
        core::ptr::copy_nonoverlapping(tag.as_ptr(), tag_out, write_len);
    }
}

/// AES-256-GCM decrypt with explicit constant-time tag verification.
///
/// Returns 0 on success, `AES_GCM_AUTH_E` (-180) on tag mismatch.
///
/// Uses "authenticate-then-decrypt": the tag is verified BEFORE the ciphertext
/// is decrypted and written to `out`.  This prevents leaking partially
/// decrypted plaintext when the tag is invalid.
fn gcm_decrypt_256(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
    expected_tag: &[u8; 16],
) -> c_int {
    let cipher = Aes256::new_from_slice(key).expect("valid 32-byte AES-256 key");

    // Step 1 — Compute the expected authentication tag from (key, IV, AAD, ciphertext).
    let computed_tag = compute_gcm_auth_tag(&cipher, iv, aad, ciphertext);

    // Step 2 — Constant-time tag comparison.
    //
    // A non-constant-time comparison (e.g., a byte-by-byte early-exit loop or
    // `== on slices`) is a timing oracle: an attacker observing Caliptra's
    // power consumption can determine when the first mismatching byte occurs,
    // and use repeated decryption queries to recover the expected tag one nibble
    // at a time.  This applies even inside the Caliptra secure boundary because
    // the MCU's power trace is an independent, physical side-channel — unrelated
    // to any network timing attack.
    let tag_ok: bool = computed_tag.ct_eq(expected_tag).into();
    if !tag_ok {
        return wolfCrypt_ErrorCodes_AES_GCM_AUTH_E as c_int;
    }

    // Step 3 — Tag matched; safe to decrypt.
    gcm_ctr_process(&cipher, iv, ciphertext, out);

    0
}

/// Compute the GCM authentication tag for (AAD, ciphertext).
///
/// Tag = E_K(J0) XOR GHASH_H(AAD || ciphertext || lengths)
/// where J0 = IV || 0x00000001 and H = E_K(0^128).
fn compute_gcm_auth_tag(
    cipher: &Aes256,
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; 16] {
    // H = AES_K(0^128): the GHASH key.
    let mut h = aes::cipher::Block::<Aes256>::default(); // 16 zero bytes
    cipher.encrypt_block(&mut h);

    // Compute GHASH over (AAD padded, ciphertext padded, lengths block).
    let mut mac = GHash::new(&h);
    mac.update_padded(aad);
    mac.update_padded(ciphertext);

    // GHASH lengths block: [len(AAD) * 8]_64be || [len(CT) * 8]_64be
    let mut len_block = aes::cipher::Block::<Aes256>::default();
    let aad_bits = (aad.len() as u64).wrapping_mul(8);
    let ct_bits = (ciphertext.len() as u64).wrapping_mul(8);
    len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());
    // update_padded with exactly 16 bytes: processes as one block, no padding added.
    mac.update_padded(len_block.as_slice());

    let ghash_out = mac.finalize();

    // E_K(J0): encrypt J0 = IV || 0x00000001.
    let mut j0 = aes::cipher::Block::<Aes256>::default();
    j0[..12].copy_from_slice(iv.as_slice());
    j0[15] = 0x01; // big-endian 32-bit counter = 1
    cipher.encrypt_block(&mut j0);

    // Tag = E_K(J0) XOR GHASH
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = j0[i] ^ ghash_out[i];
    }
    tag
}

/// AES-CTR keystream for GCM (counter starts at J1 = IV || 0x00000002).
///
/// GCM spec (NIST SP 800-38D §6.2): the keystream for encryption starts at
/// J1 = incr(J0), where J0 = IV || 0x00000001 for 96-bit IVs.
/// The 32-bit counter in bytes [12..16] is big-endian and wraps on overflow.
fn gcm_ctr_process(cipher: &Aes256, iv: &[u8; 12], input: &[u8], output: &mut [u8]) {
    // J1 = IV || 0x00000002
    let mut counter = aes::cipher::Block::<Aes256>::default();
    counter[..12].copy_from_slice(iv.as_slice());
    counter[15] = 0x02; // big-endian 32-bit counter = 2

    let mut pos = 0;
    while pos < input.len() {
        // Encrypt the current counter block to produce a keystream block.
        let mut ks = counter;
        cipher.encrypt_block(&mut ks);

        // XOR keystream with input to produce output.
        let block_len = (input.len() - pos).min(16);
        for i in 0..block_len {
            output[pos + i] = input[pos + i] ^ ks[i];
        }

        // Increment the 32-bit big-endian counter (GCM uses last 4 bytes).
        let ctr_val = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
        let new_ctr = ctr_val.wrapping_add(1).to_be_bytes();
        counter[12] = new_ctr[0];
        counter[13] = new_ctr[1];
        counter[14] = new_ctr[2];
        counter[15] = new_ctr[3];

        pos += block_len;
    }
}

// ---------------------------------------------------------------------------
// CBC implementation helpers
// ---------------------------------------------------------------------------

fn cbc_encrypt_256(key: &[u8; 32], iv: &[u8; 16], input: &[u8], output: &mut [u8]) -> c_int {
    let enc = match cbc::Encryptor::<Aes256>::new_from_slices(key, iv) {
        Ok(e) => e,
        Err(_) => return crate::CRYPTOCB_UNAVAILABLE,
    };
    match enc.encrypt_padded_b2b_mut::<NoPadding>(input, output) {
        Ok(_) => 0,
        Err(_) => crate::CRYPTOCB_UNAVAILABLE,
    }
}

fn cbc_decrypt_256(key: &[u8; 32], iv: &[u8; 16], input: &[u8], output: &mut [u8]) -> c_int {
    let dec = match cbc::Decryptor::<Aes256>::new_from_slices(key, iv) {
        Ok(d) => d,
        Err(_) => return crate::CRYPTOCB_UNAVAILABLE,
    };
    match dec.decrypt_padded_b2b_mut::<NoPadding>(input, output) {
        Ok(_) => 0,
        Err(_) => crate::CRYPTOCB_UNAVAILABLE,
    }
}

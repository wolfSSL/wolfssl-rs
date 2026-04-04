//! Hardware hash and HMAC dispatch for the Caliptra CryptoCb backend.
//!
//! Only compiled when `caliptra-2x` feature is active on non-RISC-V targets.
//! RISC-V firmware dispatch (using caliptra-drivers registers directly) is
//! deferred to a future phase.
//!
//! # Endianness
//!
//! ## Host / sha2-crate path (what this file currently compiles to)
//! The sha2 and hmac crates (RustCrypto) produce FIPS 180-4 big-endian digest
//! bytes, which is the byte order wolfSSL uses for all SHA/HMAC output buffers.
//! No conversion is needed and none is performed.
//!
//! ## riscv32 / caliptra-drivers path (future)
//! When the RISC-V firmware path is implemented, caliptra-drivers will handle
//! endianness internally via Array4x* types and explicit `.swap_bytes()` calls
//! where required by the hardware.  No ENDIAN_TOGGLE register manipulation will
//! be needed in this layer for that path either.
//!
//! # Single-threaded streaming state
//! `HW_HASH_STATE` and `HW_HMAC_STATE` are global `spin::Mutex` singletons.
//! This is safe because:
//! - The VeeR core (Caliptra RISC-V MCU) has a single hardware thread.
//!   wolfCrypt hash/HMAC operations are never re-entered from ISRs, so at
//!   most one streaming operation is live at a time.
//! - On non-riscv32 (host test) targets `spin::Mutex` provides mutual
//!   exclusion, but tests MUST run sequentially (`--test-threads=1`) because
//!   the global state cannot distinguish concurrent operations from different
//!   test threads.

use core::ffi::c_int;
use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use spin::Mutex;

use sha2::Digest as _;
use hmac::Mac as _;

use wolfcrypt_sys::{
    wc_HashType_WC_HASH_TYPE_SHA256,
    wc_HashType_WC_HASH_TYPE_SHA384,
    wc_HashType_WC_HASH_TYPE_SHA512,
    wc_CryptoInfo,
};

// ---------------------------------------------------------------------------
// HW dispatch counter
// ---------------------------------------------------------------------------

/// Counts successful hardware-dispatched hash/HMAC operations (incremented on
/// each successful `wc_HashFinal` or `wc_HmacFinal` callback invocation).
///
/// Private — access only through [`hw_dispatch_count`] and
/// [`reset_hw_dispatch_count`].  Keeping the static private prevents external
/// callers from calling `.store()` or `.fetch_add()` directly, which would
/// undermine counter integrity as FIPS dispatch evidence.
static HASH_DISPATCH_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Returns the current value of the hardware hash/HMAC dispatch counter.
pub fn hw_dispatch_count() -> usize {
    HASH_DISPATCH_COUNT.load(Relaxed)
}

/// Resets the hardware hash/HMAC dispatch counter to zero.
///
/// Tests call this at the start of each test to detect counter leaks
/// from previous tests.
pub fn reset_hw_dispatch_count() {
    HASH_DISPATCH_COUNT.store(0, Relaxed);
}

// ---------------------------------------------------------------------------
// Streaming hash state
// ---------------------------------------------------------------------------

/// In-flight SHA-256/384/512 state for streaming (multi-update) operations.
///
/// Stored in a `spin::Mutex` because wolfCrypt calls the CryptoCb callback
/// once per `wc_Sha256Update` and once per `wc_Sha256Final`, requiring the
/// partial digest to survive across calls.
enum HwHashState {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

// SAFETY: sha2 hash types contain only arrays of primitive integers; all
// are Send.  spin::Mutex<T>: Sync when T: Send, satisfying the static requirement.
static HW_HASH_STATE: Mutex<Option<HwHashState>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Streaming HMAC state
// ---------------------------------------------------------------------------

type HmacSha384Inner = hmac::Hmac<sha2::Sha384>;

/// In-flight HMAC-SHA-384 state for streaming operations.
struct HwHmacState {
    mac: HmacSha384Inner,
}

static HW_HMAC_STATE: Mutex<Option<HwHmacState>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// dispatch_hash
// ---------------------------------------------------------------------------

/// Dispatch a `WC_ALGO_TYPE_HASH` CryptoCb callback.
///
/// wolfSSL calls this function twice per hash operation:
/// 1. Update: `hash.digest == NULL`, `hash.in_` and `hash.inSz` carry data.
/// 2. Final:  `hash.digest != NULL`; writes result and increments counter.
///
/// # Safety
/// `info` must be a valid `wc_CryptoInfo` with `algo_type == WC_ALGO_TYPE_HASH`.
/// Pointer fields within the struct must be valid for their stated sizes.
pub(crate) unsafe fn dispatch_hash(info: &mut wc_CryptoInfo) -> c_int {
    // SAFETY: caller verified algo_type == WC_ALGO_TYPE_HASH.
    let hash = &info.__bindgen_anon_1.hash;
    let hash_type = hash.type_ as u32;

    // Only SHA-256, SHA-384, SHA-512 are dispatched to hardware.
    if hash_type != wc_HashType_WC_HASH_TYPE_SHA256
        && hash_type != wc_HashType_WC_HASH_TYPE_SHA384
        && hash_type != wc_HashType_WC_HASH_TYPE_SHA512
    {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    let in_ptr = hash.in_;
    let in_sz = hash.inSz as usize;
    let digest_ptr = hash.digest;

    // Build a safe data slice (may be empty on the final call).
    let data: &[u8] = if !in_ptr.is_null() && in_sz > 0 {
        core::slice::from_raw_parts(in_ptr.cast::<u8>(), in_sz)
    } else {
        &[]
    };

    if digest_ptr.is_null() {
        // ---- Update call ------------------------------------------------
        let mut guard = HW_HASH_STATE.lock();

        if guard.is_none() {
            // First update for this operation — create a fresh state.
            *guard = Some(make_hash_state(hash_type));
        } else {
            // DESIGN CONSTRAINT: This implementation supports exactly one
            // in-flight hash operation at a time per device. If wolfCrypt
            // issues a second SHA context update before the first context's
            // Final (i.e., two interleaved hash contexts on the same devId),
            // the first context's partial state is silently discarded here and
            // the caller receives return code 0. This is correct only because
            // the Caliptra VeeR firmware is single-threaded and wolfSSL does
            // not interleave SHA contexts in the firmware's usage pattern.
            // If this crate is ever used in a multi-context scenario (e.g.,
            // TLS handshake transcript hashing), this must be redesigned to
            // key state by the individual Sha context pointer.
            if !hash_type_matches(guard.as_ref().unwrap(), hash_type) {
                *guard = Some(make_hash_state(hash_type));
            }
        }

        if !data.is_empty() {
            hash_update(guard.as_mut().unwrap(), data);
        }
        0 // success, no output written
    } else {
        // ---- Final call -------------------------------------------------
        let state = HW_HASH_STATE.lock().take()
            .unwrap_or_else(|| make_hash_state(hash_type));

        hash_finalize(state, digest_ptr.cast::<u8>());

        // Increment ONLY after a successful hardware dispatch.
        HASH_DISPATCH_COUNT.fetch_add(1, Relaxed);
        0
    }
}

// ---------------------------------------------------------------------------
// dispatch_hmac
// ---------------------------------------------------------------------------

/// Dispatch a `WC_ALGO_TYPE_HMAC` CryptoCb callback.
///
/// wolfSSL calls this function twice per HMAC-SHA-384 operation:
/// 1. Update (from `wc_HmacUpdate`): `hmac.digest == NULL`.
///    `hmac.in_`/`inSz` carry message data.  The HMAC key is always
///    accessible via `(*hmac.hmac).keyRaw` / `keyLen` (set by `wc_HmacSetKey`).
/// 2. Final  (from `wc_HmacFinal`):  `hmac.digest != NULL`.
///
/// All other macType values return `CRYPTOCB_UNAVAILABLE` so wolfSSL falls
/// through to its software HMAC implementation.
///
/// # Safety
/// `info` must be a valid `wc_CryptoInfo` with `algo_type == WC_ALGO_TYPE_HMAC`.
pub(crate) unsafe fn dispatch_hmac(info: &mut wc_CryptoInfo) -> c_int {
    // SAFETY: caller verified algo_type == WC_ALGO_TYPE_HMAC.
    let hmac_info = &info.__bindgen_anon_1.hmac;
    let mac_type = hmac_info.macType;

    // Only HMAC-SHA-384 dispatched to hardware in Phase 1.
    if mac_type != wc_HashType_WC_HASH_TYPE_SHA384 as i32 {
        return crate::CRYPTOCB_UNAVAILABLE;
    }

    let in_ptr = hmac_info.in_;
    let in_sz = hmac_info.inSz as usize;
    let digest_ptr = hmac_info.digest;
    let hmac_ptr = hmac_info.hmac;

    let data: &[u8] = if !in_ptr.is_null() && in_sz > 0 {
        core::slice::from_raw_parts(in_ptr.cast::<u8>(), in_sz)
    } else {
        &[]
    };

    if digest_ptr.is_null() {
        // ---- Update call ------------------------------------------------
        let mut guard = HW_HMAC_STATE.lock();

        if guard.is_none() {
            // First update: initialize HMAC with the key stored in the
            // wolfSSL Hmac struct (written there by wc_HmacSetKey).
            let key = extract_hmac_key(hmac_ptr);
            let mac = match HmacSha384Inner::new_from_slice(key) {
                Ok(m) => m,
                Err(_) => return crate::CRYPTOCB_UNAVAILABLE,
            };
            *guard = Some(HwHmacState { mac });
        }

        if !data.is_empty() {
            guard.as_mut().unwrap().mac.update(data);
        }
        0
    } else {
        // ---- Final call -------------------------------------------------
        let state = HW_HMAC_STATE.lock().take();
        let state = match state {
            Some(s) => s,
            None => {
                // Final without a prior Update (empty-data HMAC).
                let key = extract_hmac_key(hmac_ptr);
                let mac = match HmacSha384Inner::new_from_slice(key) {
                    Ok(m) => m,
                    Err(_) => return crate::CRYPTOCB_UNAVAILABLE,
                };
                HwHmacState { mac }
            }
        };

        let result = state.mac.finalize();
        let result_bytes = result.into_bytes();
        // SAFETY: digest_ptr points to a buffer of at least 48 bytes,
        // guaranteed by wolfSSL (HMAC-SHA-384 output is exactly 48 bytes).
        core::ptr::copy_nonoverlapping(
            result_bytes.as_ptr(),
            digest_ptr.cast::<u8>(),
            48,
        );

        HASH_DISPATCH_COUNT.fetch_add(1, Relaxed);
        0
    }
}

// ---------------------------------------------------------------------------
// Helpers (hash)
// ---------------------------------------------------------------------------

fn make_hash_state(hash_type: u32) -> HwHashState {
    match hash_type {
        x if x == wc_HashType_WC_HASH_TYPE_SHA256 => HwHashState::Sha256(sha2::Sha256::new()),
        x if x == wc_HashType_WC_HASH_TYPE_SHA384 => HwHashState::Sha384(sha2::Sha384::new()),
        x if x == wc_HashType_WC_HASH_TYPE_SHA512 => HwHashState::Sha512(sha2::Sha512::new()),
        _ => unreachable!("dispatch_hash must filter hash_type to {{6,7,8}} before calling make_hash_state"),
    }
}

fn hash_type_matches(state: &HwHashState, hash_type: u32) -> bool {
    match state {
        HwHashState::Sha256(_) => hash_type == wc_HashType_WC_HASH_TYPE_SHA256,
        HwHashState::Sha384(_) => hash_type == wc_HashType_WC_HASH_TYPE_SHA384,
        HwHashState::Sha512(_) => hash_type == wc_HashType_WC_HASH_TYPE_SHA512,
    }
}

fn hash_update(state: &mut HwHashState, data: &[u8]) {
    match state {
        HwHashState::Sha256(h) => h.update(data),
        HwHashState::Sha384(h) => h.update(data),
        HwHashState::Sha512(h) => h.update(data),
    }
}

/// Write the finalized digest to `out_ptr`.
///
/// # Safety
/// `out_ptr` must point to a writable buffer of sufficient size:
/// - SHA-256: 32 bytes
/// - SHA-384: 48 bytes
/// - SHA-512: 64 bytes
unsafe fn hash_finalize(state: HwHashState, out_ptr: *mut u8) {
    match state {
        HwHashState::Sha256(h) => {
            let r = h.finalize();
            core::ptr::copy_nonoverlapping(r.as_ptr(), out_ptr, r.len());
        }
        HwHashState::Sha384(h) => {
            let r = h.finalize();
            core::ptr::copy_nonoverlapping(r.as_ptr(), out_ptr, r.len());
        }
        HwHashState::Sha512(h) => {
            let r = h.finalize();
            core::ptr::copy_nonoverlapping(r.as_ptr(), out_ptr, r.len());
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers (HMAC)
// ---------------------------------------------------------------------------

/// Extract the raw HMAC key from the wolfSSL `Hmac` struct written by
/// `wc_HmacSetKey`.  Returns an empty slice if the pointer is null.
///
/// # Safety
/// `hmac_ptr` must either be null or point to a valid `wolfcrypt_sys::Hmac`.
unsafe fn extract_hmac_key(hmac_ptr: *mut wolfcrypt_sys::Hmac) -> &'static [u8] {
    if hmac_ptr.is_null() {
        return &[];
    }
    let key_ptr = (*hmac_ptr).keyRaw;
    let key_len = (*hmac_ptr).keyLen as usize;
    if key_ptr.is_null() || key_len == 0 {
        return &[];
    }
    // SAFETY: keyRaw points into or alongside the Hmac struct; it is valid
    // for the lifetime of the Hmac object, which outlives this callback.
    // We extend to 'static here because we never store this slice — it is
    // consumed immediately within the same lock-holding closure.
    core::slice::from_raw_parts(key_ptr.cast::<u8>(), key_len)
}

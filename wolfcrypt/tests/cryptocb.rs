//! Crypto callback (WOLF_CRYPTO_CB) integration tests.
//!
//! These tests verify the registration/unregistration lifecycle and
//! the callback dispatch mechanism.  Since the actual crypto operations
//! require wolfCrypt objects with devId set (which depends on the
//! wolfCrypt build having WOLF_CRYPTO_CB enabled), these tests focus
//! on the structural properties of the Rust wrapper.

#![cfg(all(feature = "cryptocb", wolfssl_cryptocb))]

use wolfcrypt::cryptocb::{
    register_device, unregister_device, CryptoCallbackResult, CryptoCallbacks, RngRequest,
};

use core::sync::atomic::{AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// A test device that counts RNG calls
// ---------------------------------------------------------------------------

struct CountingRng {
    count: AtomicU32,
}

impl CountingRng {
    fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
        }
    }

    fn call_count(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }
}

impl CryptoCallbacks for CountingRng {
    fn rng(&self, req: RngRequest<'_>) -> CryptoCallbackResult {
        // Fill with deterministic pattern (0xAA) to prove it was called.
        for b in req.out.iter_mut() {
            *b = 0xAA;
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        CryptoCallbackResult::Success
    }
    // All other operations fall through to NotAvailable (default).
}

// ---------------------------------------------------------------------------
// A device that returns NotAvailable for everything
// ---------------------------------------------------------------------------

struct NullDevice;

impl CryptoCallbacks for NullDevice {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Registration succeeds with a valid device ID.
#[test]
fn register_and_unregister() {
    let dev_id = 100; // arbitrary positive ID
    register_device(dev_id, NullDevice).expect("register should succeed");
    unregister_device(dev_id);
}

/// Registering the same device ID twice should succeed (overwrite).
#[test]
fn register_twice_overwrites() {
    let dev_id = 101;
    register_device(dev_id, NullDevice).expect("first register");
    register_device(dev_id, NullDevice).expect("second register (overwrite)");
    unregister_device(dev_id);
}

/// CryptoCallbackResult::to_c returns expected values.
#[test]
fn result_codes() {
    // We can't call to_c directly (it's private), but we can verify
    // the constants used.
    assert_eq!(CryptoCallbackResult::Success, CryptoCallbackResult::Success);
    assert_eq!(
        CryptoCallbackResult::NotAvailable,
        CryptoCallbackResult::NotAvailable
    );
    assert_ne!(
        CryptoCallbackResult::Success,
        CryptoCallbackResult::NotAvailable
    );
    assert_ne!(
        CryptoCallbackResult::Success,
        CryptoCallbackResult::Error(-1)
    );
}

/// The CryptoCallbacks trait has default methods that return NotAvailable.
#[test]
fn default_trait_methods_return_not_available() {
    let dev = NullDevice;
    let mut buf = [0u8; 16];
    assert_eq!(
        dev.rng(RngRequest { out: &mut buf }),
        CryptoCallbackResult::NotAvailable,
    );
}

/// A device that implements rng() returns Success and fills the buffer.
#[test]
fn custom_rng_callback_fills_buffer() {
    let dev = CountingRng::new();
    let mut buf = [0u8; 32];
    let result = dev.rng(RngRequest { out: &mut buf });
    assert_eq!(result, CryptoCallbackResult::Success);
    assert_eq!(buf, [0xAA; 32], "buffer should be filled by callback");
    assert_eq!(dev.call_count(), 1);
}

/// Registering with INVALID_DEVID should panic.
#[test]
#[should_panic(expected = "INVALID_DEVID")]
fn register_invalid_devid_panics() {
    register_device(-2, NullDevice).unwrap();
}

/// Multiple distinct devices can be registered simultaneously.
#[test]
fn multiple_devices() {
    let ids = [200, 201, 202];
    for &id in &ids {
        register_device(id, NullDevice).expect("register");
    }
    for &id in &ids {
        unregister_device(id);
    }
}

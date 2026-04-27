use std::sync::atomic::{AtomicBool, Ordering};

use wolfhsm_sys::{wc_CryptoInfo, wh_Client_CryptoCb};

use crate::client::Client;
use crate::error::WolfHsmError;

/// wolfHSM CryptoCb device ID ("WHSM" = 0x5748534D).
///
/// Pass this constant to wolfCrypt `_ex` init variants (e.g. `wc_InitRsaKey_ex`,
/// `wc_ecc_init_ex`) to route crypto operations to the wolfHSM server.
pub const DEV_ID: i32 = 0x5748534Du32 as i32;

// The wolfcrypt-sys bindings for wolfhsm may be built from a wolfSSL variant
// that does not enable WOLF_CRYPTO_CB, so wc_CryptoCb_RegisterDevice and
// wc_CryptoCb_UnRegisterDevice may not be re-exported from wolfcrypt_sys.
// Declare them directly; they are always present in the linked wolfSSL library
// when wolfhsm-sys is in the dependency graph (its shims.c is compiled with
// -DWOLF_CRYPTO_CB, which requires the underlying wolfSSL to expose these
// symbols).
unsafe extern "C" {
    fn wc_CryptoCb_RegisterDevice(
        dev_id: core::ffi::c_int,
        cb: Option<
            unsafe extern "C" fn(
                dev_id: core::ffi::c_int,
                info: *mut wc_CryptoInfo,
                ctx: *mut core::ffi::c_void,
            ) -> core::ffi::c_int,
        >,
        ctx: *mut core::ffi::c_void,
    ) -> core::ffi::c_int;

    fn wc_CryptoCb_UnRegisterDevice(devId: core::ffi::c_int);
}

static REGISTERED: AtomicBool = AtomicBool::new(false);

/// RAII guard for the wolfHSM CryptoCb registration.
///
/// When dropped, unregisters the wolfHSM CryptoCb device from the wolfCrypt
/// global table and allows a new registration.  Only one `CryptoCbGuard` can
/// exist at a time per process; [`Client::register_cryptocb`] returns an error
/// if one is already live.
pub struct CryptoCbGuard(());

impl Client {
    /// Register this wolfHSM client as a wolfCrypt CryptoCb device.
    ///
    /// Routes all wolfCrypt operations tagged with [`DEV_ID`] to this wolfHSM
    /// server.  Only one registration is permitted per process.  Returns an
    /// error if a registration is already live.
    ///
    /// Drop the returned [`CryptoCbGuard`] to unregister.
    pub fn register_cryptocb(&mut self) -> Result<CryptoCbGuard, WolfHsmError> {
        // Claim the global registration slot; fail if already taken.
        REGISTERED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| WolfHsmError::Wh { code: -2000 })?;

        // SAFETY: ctx_ptr() returns a valid pointer to the pinned whClientContext
        // for the lifetime of `self`.  wc_CryptoCb_RegisterDevice stores it in
        // the wolfCrypt global table; it must remain valid until we unregister
        // (i.e. until CryptoCbGuard is dropped, which must happen before Client
        // is dropped — the caller is responsible for this ordering).
        let rc = unsafe {
            wc_CryptoCb_RegisterDevice(DEV_ID, Some(wh_Client_CryptoCb), self.ctx_ptr().cast())
        };

        if rc != 0 {
            // Registration failed; release the slot so a future call can retry.
            REGISTERED.store(false, Ordering::SeqCst);
            return Err(WolfHsmError::Ffi { code: rc, func: "wc_CryptoCb_RegisterDevice" });
        }

        Ok(CryptoCbGuard(()))
    }
}

impl Drop for CryptoCbGuard {
    fn drop(&mut self) {
        // SAFETY: DEV_ID was registered in register_cryptocb; unregistering it
        // removes the entry from the wolfCrypt global table.
        unsafe { wc_CryptoCb_UnRegisterDevice(DEV_ID) };
        REGISTERED.store(false, Ordering::SeqCst);
    }
}

use crate::error::Error;

/// Serialises concurrent swtpm initialisations so that two threads do not
/// corrupt each other's environment variables.
///
/// NOTE: This does not protect against unrelated threads calling
/// `std::env::var()` or other `setenv`/`unsetenv` calls concurrently.
#[cfg(feature = "swtpm")]
static SWTPM_INIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Safe handle to a wolfTPM device context.
///
/// The context is heap-allocated to give the C library a stable address.
/// `Device` is `Send` (can be moved across threads) but not `Sync`.
pub struct Device {
    dev: Box<wolftpm_sys::WOLFTPM2_DEV>,
}

// SAFETY: WOLFTPM2_DEV holds no thread-local state and no raw pointers
// shared across threads. The Box gives it a stable address.
unsafe impl Send for Device {}

impl Device {
    /// Open a connection to the TPM via the Linux kernel driver.
    ///
    /// wolfTPM opens `/dev/tpm0` (direct character device) or `/dev/tpmrm0`
    /// (resource manager, preferred on Linux 4.12+) depending on how wolfTPM
    /// was compiled and what is available on the system.
    ///
    /// Requires wolfTPM built with `--enable-devtpm` (the default on Linux).
    pub fn open() -> Result<Self, Error> {
        // SAFETY: zeroed WOLFTPM2_DEV is the correct initial state per
        // the wolfTPM documentation; wolfTPM2_Init fills it in.
        let mut dev = Box::new(unsafe { std::mem::zeroed::<wolftpm_sys::WOLFTPM2_DEV>() });
        let rc = unsafe {
            wolftpm_sys::wolfTPM2_Init(dev.as_mut() as *mut _, None, std::ptr::null_mut())
        };
        Error::check(rc)?;
        Ok(Self { dev })
    }

    /// Connect to a software TPM at `host:port` (swtpm or IBM TPM2 simulator).
    ///
    /// NOTE: The setenv/init/unsetenv sequence here is mirrored in
    /// `wolftpm_tss::connection::WolfTpmSwtpm::connect`.  Any bug fix to this
    /// function must also be applied there.
    ///
    /// Requires wolfTPM compiled with `--enable-swtpm`. When that flag is set,
    /// wolfTPM reads `SWTPM_SERVER_NAME` and `SWTPM_SERVER_PORT` from the
    /// environment; the `host` and `port` arguments are forwarded by temporarily
    /// setting those variables before calling `wolfTPM2_Init`.
    ///
    /// # Thread safety
    ///
    /// A process-wide mutex serialises concurrent calls to this function so
    /// that two threads do not corrupt each other's `SWTPM_SERVER_NAME` /
    /// `SWTPM_SERVER_PORT` environment variables.
    ///
    /// **This mutex does not protect against unrelated threads that read or
    /// write `SWTPM_SERVER_NAME`/`SWTPM_SERVER_PORT` outside this API.**  If
    /// your process sets those variables for other purposes, or runs parallel
    /// test cases that each call `open_swtpm`, those other paths must not touch
    /// the two variables while this function may be executing.  The safest
    /// approach is to set `SWTPM_SERVER_*` exclusively through this API and
    /// never read them from the environment directly.
    #[cfg(feature = "swtpm")]
    pub fn open_swtpm(host: &str, port: u16) -> Result<Self, Error> {
        use std::ffi::CString;

        let host_c =
            CString::new(host).map_err(|_| Error::InvalidArg("host contains null byte"))?;
        let port_c = CString::new(port.to_string())
            .map_err(|_| Error::InvalidArg("port string invalid"))?;

        // unwrap: if the mutex is poisoned a previous thread panicked mid-init,
        // leaving the process env in an unknown state.  Panic here is correct —
        // there is no safe recovery path.
        let _guard = SWTPM_INIT_LOCK.lock().unwrap();

        // SAFETY: setenv/unsetenv are POSIX; the strings are valid C strings.
        // The lock above serialises access to the process-global environment.
        let rc = unsafe { libc_setenv(b"SWTPM_SERVER_NAME\0".as_ptr(), host_c.as_ptr()) };
        if rc != 0 {
            return Err(Error::InvalidArg("setenv failed for SWTPM_SERVER_NAME"));
        }
        let rc = unsafe { libc_setenv(b"SWTPM_SERVER_PORT\0".as_ptr(), port_c.as_ptr()) };
        if rc != 0 {
            // Best-effort rollback; if unsetenv fails (EINVAL), SWTPM_SERVER_NAME
            // is left in the environment but that is a benign stale value —
            // wolfTPM2_Init will not be called, so no incorrect connection is made.
            let _ = unsafe { libc_unsetenv(b"SWTPM_SERVER_NAME\0".as_ptr()) };
            return Err(Error::InvalidArg("setenv failed for SWTPM_SERVER_PORT"));
        }

        let mut dev = Box::new(unsafe { std::mem::zeroed::<wolftpm_sys::WOLFTPM2_DEV>() });
        let rc = unsafe {
            wolftpm_sys::wolfTPM2_Init(dev.as_mut() as *mut _, None, std::ptr::null_mut())
        };

        // Clear env vars regardless of success/failure.  EINVAL is impossible
        // here because the names are hard-coded valid ASCII strings.
        unsafe {
            let _ = libc_unsetenv(b"SWTPM_SERVER_NAME\0".as_ptr());
            let _ = libc_unsetenv(b"SWTPM_SERVER_PORT\0".as_ptr());
        }

        Error::check(rc)?;
        Ok(Self { dev })
    }

    /// Return a raw mutable pointer to the inner `WOLFTPM2_DEV`.
    ///
    /// For internal use by sibling modules (e.g. `key`) that need to pass the
    /// device pointer to C API functions.
    pub(crate) fn dev_ptr_mut(&mut self) -> *mut wolftpm_sys::WOLFTPM2_DEV {
        self.dev.as_mut() as *mut _
    }

    /// Run a closure with a transient ECC P-256 signing key.
    ///
    /// A fresh key is created on the TPM, the closure is called, and the key
    /// is always flushed from transient object memory — even if the closure
    /// returns `Err`.
    ///
    /// The closure may use any error type `E` provided it implements
    /// `From<Error>`, so callers can use their own error types without
    /// manually mapping.
    pub fn with_ecc_key<F, T, E>(&mut self, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut crate::key::EccKey<'_>) -> Result<T, E>,
        E: From<Error>,
    {
        let mut key = crate::key::EccKey::create(self).map_err(E::from)?;
        let result = f(&mut key);
        // key is dropped here, which triggers EccKey::Drop and unloads both
        // the signing key and the SRK from transient object memory.
        result
    }

    /// Request `n` bytes of TPM-sourced random data.
    ///
    /// `n` must fit in a `u32`; if it does not, `Error::InvalidArg` is returned.
    pub fn get_random(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        let len =
            u32::try_from(n).map_err(|_| Error::InvalidArg("requested length exceeds u32"))?;
        let mut buf = vec![0u8; n];
        let rc =
            unsafe { wolftpm_sys::wolfTPM2_GetRandom(self.dev_ptr_mut(), buf.as_mut_ptr(), len) };
        Error::check(rc)?;
        Ok(buf)
    }

    /// Read the SHA-256 PCR bank for the given index (0–23).
    ///
    /// Returns the 32-byte PCR value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPcrIndex`] immediately if `index` is outside 0–23,
    /// rather than forwarding an opaque TPM_RC_VALUE to the caller.
    pub fn pcr_read(&mut self, index: u8) -> Result<[u8; 32], Error> {
        if index > 23 {
            return Err(Error::InvalidPcrIndex(index));
        }
        // TPM_MAX_DIGEST_SIZE = 64; allocate the largest possible digest buffer.
        let mut digest = [0u8; 64];
        // 64 is a compile-time constant that trivially fits in c_int.
        let mut digest_len: std::ffi::c_int = 64;
        let rc = unsafe {
            wolftpm_sys::wolfTPM2_ReadPCR(
                self.dev_ptr_mut(),
                std::ffi::c_int::from(index),
                wolftpm_sys::TPM_ALG_ID_T_TPM_ALG_SHA256 as std::ffi::c_int,
                digest.as_mut_ptr(),
                &mut digest_len as *mut _,
            )
        };
        Error::check(rc)?;

        if digest_len != 32 {
            return Err(Error::UnexpectedResponse);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..32]);
        Ok(out)
    }
}

impl core::fmt::Debug for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // WOLFTPM2_DEV is an opaque C struct; only the pointer address is
        // meaningful from the Rust side.
        f.debug_struct("Device")
            .field("dev", &format_args!("{:p}", self.dev.as_ref()))
            .finish()
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: dev was initialised by wolfTPM2_Init; cleanup is idempotent.
        unsafe {
            wolftpm_sys::wolfTPM2_Cleanup(self.dev_ptr_mut());
        }
    }
}

#[cfg(feature = "swtpm")]
unsafe fn libc_setenv(name: *const u8, value: *const std::ffi::c_char) -> std::ffi::c_int {
    libc::setenv(name as *const _, value, 1)
}

#[cfg(feature = "swtpm")]
unsafe fn libc_unsetenv(name: *const u8) -> std::ffi::c_int {
    // POSIX unsetenv returns 0 on success, -1 on error (EINVAL = invalid name).
    // The caller decides whether to propagate or ignore the error.
    libc::unsetenv(name as *const _)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Device::open is expected to fail (return Error::Tpm) when /dev/tpm0
    /// is absent. It must not panic.
    #[test]
    #[ignore = "requires /dev/tpm0"]
    fn open_and_get_random() {
        let mut dev = Device::open().expect("open");
        let rand = dev.get_random(32).expect("get_random");
        assert_eq!(rand.len(), 32);
    }

    #[test]
    #[ignore = "requires /dev/tpm0"]
    fn pcr_read_bank0() {
        let mut dev = Device::open().expect("open");
        let pcr = dev.pcr_read(0).expect("pcr_read");
        assert_eq!(pcr.len(), 32);
    }
}

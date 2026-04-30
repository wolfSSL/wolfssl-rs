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
    /// Open a connection to the TPM via the Linux kernel driver (`/dev/tpm0`).
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
    /// Requires wolfTPM compiled with `--enable-swtpm`. When that flag is set,
    /// wolfTPM reads `SWTPM_SERVER_NAME` and `SWTPM_SERVER_PORT` from the
    /// environment; the `host` and `port` arguments are forwarded by temporarily
    /// setting those variables before calling `wolfTPM2_Init`.
    ///
    /// # Thread safety
    ///
    /// A process-wide mutex serialises concurrent swtpm initialisations so that
    /// two threads do not corrupt each other's environment variables. This does
    /// **not** protect against unrelated threads calling `std::env::var()` or
    /// other `setenv`/`unsetenv` calls concurrently.
    #[cfg(feature = "swtpm")]
    pub fn open_swtpm(host: &str, port: u16) -> Result<Self, Error> {
        use std::ffi::CString;

        let host_c =
            CString::new(host).map_err(|_| Error::InvalidArg("host contains null byte"))?;
        let port_str = port.to_string();
        let port_c = CString::new(port_str.as_str())
            .map_err(|_| Error::InvalidArg("port string invalid"))?;

        let _guard = SWTPM_INIT_LOCK.lock().unwrap();

        // SAFETY: setenv/unsetenv are POSIX; the strings are valid C strings.
        // The lock above serialises access to the process-global environment.
        let rc = unsafe { libc_setenv(b"SWTPM_SERVER_NAME\0".as_ptr(), host_c.as_ptr()) };
        if rc != 0 {
            return Err(Error::InvalidArg("setenv failed for SWTPM_SERVER_NAME"));
        }
        let rc = unsafe { libc_setenv(b"SWTPM_SERVER_PORT\0".as_ptr(), port_c.as_ptr()) };
        if rc != 0 {
            unsafe { libc_unsetenv(b"SWTPM_SERVER_NAME\0".as_ptr()) };
            return Err(Error::InvalidArg("setenv failed for SWTPM_SERVER_PORT"));
        }

        let mut dev = Box::new(unsafe { std::mem::zeroed::<wolftpm_sys::WOLFTPM2_DEV>() });
        let rc = unsafe {
            wolftpm_sys::wolfTPM2_Init(dev.as_mut() as *mut _, None, std::ptr::null_mut())
        };

        // Clear env vars regardless of success/failure.
        unsafe {
            libc_unsetenv(b"SWTPM_SERVER_NAME\0".as_ptr());
            libc_unsetenv(b"SWTPM_SERVER_PORT\0".as_ptr());
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
    pub fn with_ecc_key<F, T>(&mut self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut crate::key::EccKey<'_>) -> Result<T, Error>,
    {
        let mut key = crate::key::EccKey::create(self)?;
        let result = f(&mut key);
        // Drop flushes the key via EccKey::drop; no explicit flush needed.
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
    pub fn pcr_read(&mut self, index: u8) -> Result<[u8; 32], Error> {
        // TPM_MAX_DIGEST_SIZE = 64; allocate the largest possible digest buffer.
        let mut digest = [0u8; 64];
        let mut digest_len: std::ffi::c_int = digest.len() as std::ffi::c_int;
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

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: dev was initialised by wolfTPM2_Init; cleanup is idempotent.
        unsafe {
            wolftpm_sys::wolfTPM2_Cleanup(self.dev_ptr_mut());
        }
    }
}

// ── POSIX env helpers (avoids a libc dep just for two calls) ─────────────────
// NOTE: identical helpers exist in wolftpm-tss/src/connection.rs.
// Kept separate to avoid a shared internal crate dependency.

#[cfg(feature = "swtpm")]
unsafe fn libc_setenv(name: *const u8, value: *const std::ffi::c_char) -> std::ffi::c_int {
    extern "C" {
        fn setenv(
            name: *const std::ffi::c_char,
            value: *const std::ffi::c_char,
            overwrite: std::ffi::c_int,
        ) -> std::ffi::c_int;
    }
    setenv(name as *const _, value, 1)
}

#[cfg(feature = "swtpm")]
unsafe fn libc_unsetenv(name: *const u8) {
    extern "C" {
        fn unsetenv(name: *const std::ffi::c_char) -> std::ffi::c_int;
    }
    unsetenv(name as *const _);
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

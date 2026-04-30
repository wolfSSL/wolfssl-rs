use crate::error::Error;

/// Safe handle to a wolfTPM device context.
///
/// The context is heap-allocated to give the C library a stable address.
/// `Device` is `Send` (can be moved across threads) but not `Sync`.
pub struct Device {
    dev: Box<wolftpm_sys::WOLFTPM2_DEV>,
}

// SAFETY: WOLFTPM2_DEV is safe to send across threads because:
// 1. All internal state (context buffers, session handles) lives inside the
//    struct itself — wolfTPM uses no process-global mutable state that is
//    keyed to the calling thread.  Verified against wolfTPM src/tpm2.c and
//    tpm2_wrap.c: global variables are compile-time constants or statistics
//    counters, not per-call state.
// 2. The Box gives the struct a stable heap address; no internal pointer
//    points back to the stack of the creating thread.
// 3. `Device` is NOT `Sync` — concurrent calls through a shared reference
//    are prevented.  Callers must use `&mut Device` (exclusive access) for
//    every operation.
// NOTE: if a future wolfTPM version introduces thread-local state (e.g. for
// async I/O or per-thread error buffers), this impl must be revisited.
// Re-check when upgrading wolfTPM past the tested version (v4.0.0 / fbbf6fe).
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

        // Delegate to the shared init helper in wolftpm-sys (also used by
        // wolftpm-tss::WolfTpmSwtpm::connect) so the two callers share a
        // single copy of the setenv/init/unsetenv sequence.
        let dev = wolftpm_sys::swtpm::init_swtpm(&host_c, &port_c)
            .map_err(|e| match e {
                wolftpm_sys::swtpm::InitError::Env => {
                    Error::InvalidArg("setenv failed (ENOMEM?); cannot set swtpm connection vars")
                }
                wolftpm_sys::swtpm::InitError::WolfTpm(rc) => {
                    Error::Tpm { rc: crate::error::TpmRc::from_raw(rc as u32) }
                }
            })?;
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

//! [`Connection`](tpm2_rs_client::connection::Connection) implementations
//! backed by wolfTPM transports.

use crate::error::Error;
#[cfg(feature = "tss")]
use tpm2_rs_client::connection::Connection;

/// Serialises concurrent swtpm initialisations so that two threads do not
/// corrupt each other's environment variables.
///
/// NOTE: This does not protect against unrelated threads calling
/// `std::env::var()` or other `setenv`/`unsetenv` calls concurrently.
#[cfg(feature = "swtpm")]
static SWTPM_INIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── shared transact helper ────────────────────────────────────────────────────

/// Call the raw-bytes shim and write the TPM2 response into `rsp`.
///
/// Returns a sub-slice of `rsp` containing exactly the response bytes on
/// success, or an appropriate `Error` on failure.
#[cfg(feature = "tss")]
fn do_transact<'a>(
    dev: &mut wolftpm_sys::WOLFTPM2_DEV,
    cmd: &[u8],
    rsp: &'a mut [u8],
) -> Result<&'a mut [u8], Error> {
    use std::os::raw::c_int;

    // cmd.len() not fitting in c_int means the command exceeds the transport's
    // maximum message size — treated as the same category as ResponseBufferTooSmall.
    let cmd_sz = c_int::try_from(cmd.len()).map_err(|_| Error::ResponseBufferTooSmall)?;
    let rsp_buf_sz = c_int::try_from(rsp.len()).map_err(|_| Error::ResponseBufferTooSmall)?;
    let mut rsp_sz: c_int = 0;

    let rc = unsafe {
        wolftpm_sys::wolftpm_rs_transact(
            dev as *mut _,
            cmd.as_ptr(),
            cmd_sz,
            rsp.as_mut_ptr(),
            rsp_buf_sz,
            &mut rsp_sz as *mut _,
        )
    };

    // TPM_RC_SIZE means the caller's buffer was too small
    if rc == wolftpm_sys::TPM_RC_T_TPM_RC_SIZE as c_int {
        return Err(Error::ResponseBufferTooSmall);
    }
    Error::check(rc)?;

    let n = usize::try_from(rsp_sz).map_err(|_| Error::MalformedResponse)?;
    if n > rsp.len() {
        return Err(Error::MalformedResponse);
    }
    Ok(&mut rsp[..n])
}

// ── Shared private device wrapper ────────────────────────────────────────────

/// Private type holding the raw wolfTPM device context.
///
/// Both public transport types wrap this so that the Drop cleanup lives in
/// exactly one place.
struct WolfTpmDev {
    dev: Box<wolftpm_sys::WOLFTPM2_DEV>,
}

impl WolfTpmDev {
    fn new(dev: Box<wolftpm_sys::WOLFTPM2_DEV>) -> Self {
        Self { dev }
    }
}

impl Drop for WolfTpmDev {
    fn drop(&mut self) {
        // SAFETY: dev was initialised by wolfTPM2_Init; cleanup is idempotent.
        unsafe {
            wolftpm_sys::wolfTPM2_Cleanup(self.dev.as_mut() as *mut _);
        }
    }
}

// ── Linux /dev/tpm0 ──────────────────────────────────────────────────────────

/// wolfTPM transport using the Linux kernel TPM driver (`/dev/tpm0` or
/// `/dev/tpmrm0`).
///
/// Implements [`Connection`] so that any tpm-rs client code can use a
/// hardware TPM via wolfTPM on Linux without any additional dependencies.
///
/// # Construction
///
/// ```no_run
/// use wolftpm_tss::connection::WolfTpmLinuxDev;
/// let mut transport = WolfTpmLinuxDev::open().unwrap();
/// ```
pub struct WolfTpmLinuxDev {
    // Accessed by the `tss` feature's Connection impl and by Drop propagation.
    #[allow(dead_code)]
    inner: WolfTpmDev,
}

impl WolfTpmLinuxDev {
    /// Open a connection to the TPM via the Linux kernel driver.
    ///
    /// Calls `wolfTPM2_Init` with the `WOLFTPM_LINUX_DEV` transport.
    /// When wolfTPM is built with `--enable-devtpm`, `ioCb` is not used
    /// and must be `None`; wolfTPM handles the `/dev/tpm0` I/O internally.
    ///
    /// Fails if `/dev/tpm0` is not present or not accessible.
    pub fn open() -> Result<Self, Error> {
        // SAFETY: zeroed WOLFTPM2_DEV is the correct initial state per
        // the wolfTPM documentation; wolfTPM2_Init fills it in.
        let mut dev = Box::new(unsafe { std::mem::zeroed::<wolftpm_sys::WOLFTPM2_DEV>() });
        let rc = unsafe {
            wolftpm_sys::wolfTPM2_Init(
                dev.as_mut() as *mut _,
                None,                 // ioCb — not used with devtpm
                std::ptr::null_mut(), // userCtx
            )
        };
        Error::check(rc)?;
        Ok(Self { inner: WolfTpmDev::new(dev) })
    }
}

#[cfg(feature = "tss")]
impl Connection for WolfTpmLinuxDev {
    type Error = Error;

    fn transact<'a>(&mut self, cmd: &[u8], rsp: &'a mut [u8]) -> Result<&'a mut [u8], Self::Error> {
        do_transact(self.inner.dev.as_mut(), cmd, rsp)
    }
}

// ── Software TPM (swtpm / IBM simulator) ─────────────────────────────────────

/// wolfTPM transport using a software TPM over a TCP socket.
///
/// Compatible with [swtpm](https://github.com/stefanberger/swtpm) and the
/// [IBM TPM2 simulator](https://sourceforge.net/projects/ibmswtpm2/).
///
/// # Construction
///
/// ```no_run
/// use wolftpm_tss::connection::WolfTpmSwtpm;
/// let mut transport = WolfTpmSwtpm::connect("127.0.0.1", 2321).unwrap();
/// ```
#[cfg(feature = "swtpm")]
pub struct WolfTpmSwtpm {
    // Accessed by the `tss` feature's Connection impl and by Drop propagation.
    #[allow(dead_code)]
    inner: WolfTpmDev,
}

#[cfg(feature = "swtpm")]
impl WolfTpmSwtpm {
    /// Connect to a software TPM at `host:port`.
    ///
    /// The default swtpm port is `2321`; the IBM simulator uses `2321` for
    /// the TPM command port and `2322` for the platform port.
    ///
    /// Requires wolfTPM compiled with `--enable-swtpm`.  When that flag is
    /// set, wolfTPM reads `SWTPM_SERVER_NAME` and `SWTPM_SERVER_PORT`
    /// environment variables; the `host` and `port` arguments are forwarded
    /// by temporarily setting those variables before calling `wolfTPM2_Init`.
    ///
    /// # Errors
    ///
    /// Returns `Error::Transport` if the swtpm socket cannot be reached or
    /// if wolfTPM was not compiled with `--enable-swtpm`.
    ///
    /// # Thread safety
    ///
    /// A process-wide mutex serialises concurrent swtpm initialisations so that
    /// two threads do not corrupt each other's environment variables. This does
    /// **not** protect against unrelated threads calling `std::env::var()` or
    /// other `setenv`/`unsetenv` calls concurrently.
    pub fn connect(host: &str, port: u16) -> Result<Self, Error> {
        use std::ffi::CString;

        // wolfTPM swtpm reads SWTPM_SERVER_NAME / SWTPM_SERVER_PORT from
        // the environment.  Set them for the duration of Init, then clear.
        let host_c = CString::new(host).map_err(|_| Error::MalformedResponse)?;
        let port_str = port.to_string();
        let port_c = CString::new(port_str.as_str()).map_err(|_| Error::MalformedResponse)?;

        let _guard = SWTPM_INIT_LOCK.lock().unwrap();

        // SAFETY: setenv/unsetenv are POSIX; the strings are valid C strings.
        // The lock above serialises access to the process-global environment.
        let rc = unsafe { libc_setenv(b"SWTPM_SERVER_NAME\0".as_ptr(), host_c.as_ptr()) };
        if rc != 0 {
            return Err(Error::Transport { code: rc });
        }
        let rc = unsafe { libc_setenv(b"SWTPM_SERVER_PORT\0".as_ptr(), port_c.as_ptr()) };
        if rc != 0 {
            unsafe { libc_unsetenv(b"SWTPM_SERVER_NAME\0".as_ptr()) };
            return Err(Error::Transport { code: rc });
        }

        let mut dev = Box::new(unsafe { std::mem::zeroed::<wolftpm_sys::WOLFTPM2_DEV>() });
        let rc = unsafe {
            wolftpm_sys::wolfTPM2_Init(dev.as_mut() as *mut _, None, std::ptr::null_mut())
        };

        // Clean up env vars regardless of success/failure.
        unsafe {
            libc_unsetenv(b"SWTPM_SERVER_NAME\0".as_ptr());
            libc_unsetenv(b"SWTPM_SERVER_PORT\0".as_ptr());
        }

        Error::check(rc)?;
        Ok(Self { inner: WolfTpmDev::new(dev) })
    }
}

#[cfg(all(feature = "tss", feature = "swtpm"))]
impl Connection for WolfTpmSwtpm {
    type Error = Error;

    fn transact<'a>(&mut self, cmd: &[u8], rsp: &'a mut [u8]) -> Result<&'a mut [u8], Self::Error> {
        do_transact(self.inner.dev.as_mut(), cmd, rsp)
    }
}

// ── POSIX env helpers (avoids a libc dep just for two calls) ─────────────────
// NOTE: identical helpers exist in wolftpm/src/device.rs.
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

    /// Verify the Error variants exist and produce non-empty Display strings.
    /// Does not require a real TPM.
    #[test]
    fn error_display_non_empty() {
        let cases = [
            Error::ResponseBufferTooSmall,
            Error::MalformedResponse,
            Error::Transport { code: -1 },
        ];
        for e in &cases {
            assert!(!format!("{e}").is_empty(), "Display for {e:?} was empty");
        }
    }

    /// Smoke-test that WolfTpmLinuxDev::open returns an error when /dev/tpm0
    /// is absent, rather than panicking.  Ignored in CI where /dev/tpm0 may
    /// not be present.
    #[test]
    #[ignore = "requires /dev/tpm0"]
    fn linux_dev_open_requires_dev_tpm0() {
        let result = WolfTpmLinuxDev::open();
        // Either Ok (if /dev/tpm0 is accessible) or a Transport error.
        match result {
            Ok(_) => {}
            Err(Error::Transport { .. }) => {}
            Err(e) => panic!("unexpected error variant: {e}"),
        }
    }
}

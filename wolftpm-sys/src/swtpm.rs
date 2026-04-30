/// Shared swtpm initialisation helper used by both `wolftpm` and `wolftpm-tss`.
///
/// Having a single copy here prevents the two callers from diverging.

/// Error returned by [`init_swtpm`].
#[derive(Debug, Clone, Copy)]
pub enum InitError {
    /// A POSIX `setenv` call failed (e.g. `ENOMEM`).  The return value from
    /// `libc::setenv` is always `-1`; the specific cause is in `errno` but
    /// that is not captured here because this failure mode is essentially
    /// unrecoverable.
    Env,
    /// `wolfTPM2_Init` returned a nonzero error code.
    WolfTpm(i32),
}

/// Serialises concurrent swtpm initialisations so that two threads do not
/// corrupt each other's environment variables.
///
/// NOTE: This does not protect against unrelated threads calling
/// `std::env::var()` or other `setenv`/`unsetenv` calls concurrently.
static SWTPM_INIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Initialise a `WOLFTPM2_DEV` connected to a software TPM at `host:port`.
///
/// Temporarily sets `SWTPM_SERVER_NAME` and `SWTPM_SERVER_PORT` in the
/// process environment, calls `wolfTPM2_Init`, then removes them.
/// A process-wide mutex (shared across both `wolftpm` and `wolftpm-tss`)
/// serialises concurrent calls.
///
/// Returns `Ok(Box<WOLFTPM2_DEV>)` on success, or an [`InitError`] on failure.
///
/// The caller is responsible for:
/// - Ensuring `host` contains no embedded NUL bytes (pass a validated `&CStr`)
/// - Mapping the [`InitError`] to the crate's own error type
///
/// # Thread safety
///
/// The `SWTPM_INIT_LOCK` mutex is held for the duration of this call.
/// This protects against concurrent calls through this API but not against
/// unrelated threads that read/write `SWTPM_SERVER_NAME`/`SWTPM_SERVER_PORT`
/// directly.
pub fn init_swtpm(
    host: &std::ffi::CStr,
    port: &std::ffi::CStr,
) -> Result<Box<crate::WOLFTPM2_DEV>, InitError> {
    // unwrap: if the mutex is poisoned a previous thread panicked mid-init,
    // leaving the process env in an unknown state.  Panic here is correct —
    // there is no safe recovery path.
    let _guard = SWTPM_INIT_LOCK.lock().unwrap();

    // SAFETY: setenv/unsetenv are POSIX; the strings are valid C strings.
    // The lock above serialises access to the process-global environment.
    let rc = unsafe { libc_setenv(b"SWTPM_SERVER_NAME\0".as_ptr(), host.as_ptr()) };
    if rc != 0 {
        return Err(InitError::Env);
    }
    let rc = unsafe { libc_setenv(b"SWTPM_SERVER_PORT\0".as_ptr(), port.as_ptr()) };
    if rc != 0 {
        // Best-effort rollback; if unsetenv fails (EINVAL), SWTPM_SERVER_NAME
        // is left in the environment but that is a benign stale value —
        // wolfTPM2_Init will not be called, so no incorrect connection is made.
        unsafe { let _ = libc_unsetenv(b"SWTPM_SERVER_NAME\0".as_ptr()); }
        return Err(InitError::Env);
    }

    // SAFETY: zeroed WOLFTPM2_DEV is the correct initial state per wolfTPM
    // documentation; wolfTPM2_Init fills it in.
    let mut dev = Box::new(unsafe { std::mem::zeroed::<crate::WOLFTPM2_DEV>() });
    let rc = unsafe {
        crate::wolfTPM2_Init(dev.as_mut() as *mut _, None, std::ptr::null_mut())
    };

    // Clear env vars regardless of success/failure.  EINVAL is impossible
    // here because the names are hard-coded valid ASCII strings.
    unsafe {
        let _ = libc_unsetenv(b"SWTPM_SERVER_NAME\0".as_ptr());
        let _ = libc_unsetenv(b"SWTPM_SERVER_PORT\0".as_ptr());
    }

    if rc != 0 {
        return Err(InitError::WolfTpm(rc));
    }
    Ok(dev)
}

unsafe fn libc_setenv(name: *const u8, value: *const std::ffi::c_char) -> std::ffi::c_int {
    libc::setenv(name as *const _, value, 1)
}

unsafe fn libc_unsetenv(name: *const u8) -> std::ffi::c_int {
    // POSIX unsetenv returns 0 on success, -1 on error (EINVAL = invalid name).
    libc::unsetenv(name as *const _)
}

use core::fmt;

/// Error type for wolfTPM operations.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A wolfTPM / TPM2 error code (nonzero return from a wolfTPM2_* function).
    ///
    /// `func` is the C function name (e.g. `"wolfTPM2_Init"`) so error
    /// messages identify the failing call without grepping headers.
    Tpm {
        /// The wolfTPM error code (typically negative or a TPM_RC value).
        code: i32,
        /// Name of the C function that returned the error.
        func: &'static str,
    },
    /// A caller-supplied argument failed validation before any FFI call.
    BadArgs {
        /// Human-readable description of the invalid argument.
        msg: &'static str,
    },
    /// The device is already initialized.
    AlreadyInit,
}

impl Error {
    /// Map a wolfTPM C return code to a `Result`.
    ///
    /// - `0` → `Ok(())`
    /// - Any other value → `Err(Error::Tpm { code, func })`
    #[inline]
    pub fn check(rc: i32, func: &'static str) -> Result<(), Error> {
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::Tpm { code: rc, func })
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Tpm { code, func } => {
                write!(f, "{func} failed: wolfTPM error {code:#010x}")
            }
            Error::BadArgs { msg } => write!(f, "invalid argument: {msg}"),
            Error::AlreadyInit => write!(f, "wolfTPM device already initialized"),
        }
    }
}

impl core::error::Error for Error {}

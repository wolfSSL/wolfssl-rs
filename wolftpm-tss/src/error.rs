use core::fmt;

/// Error type for wolfTPM TSS transport operations.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// wolfTPM returned a nonzero error code from a transport operation.
    ///
    /// This represents a failure at the transport layer (e.g. socket error,
    /// device not found).  For TPM-layer protocol errors returned inside a
    /// well-formed TPM2 response, see [`Error::TpmLayer`].
    Transport {
        /// The wolfTPM / wolfSSL internal error code.
        code: i32,
    },
    /// The TPM returned a protocol-layer error code in the response header.
    ///
    /// This is distinct from a transport failure: the bytes were delivered
    /// successfully, but the TPM's `responseCode` field was nonzero
    /// (e.g. `TPM_RC_AUTH_FAIL`, `TPM_RC_DISABLED`).
    TpmLayer {
        /// The raw TPM_RC value (big-endian u32 from the response header,
        /// extracted by tpm2-rs-base).
        rc: u32,
    },
    /// A caller-supplied argument failed validation before any FFI call.
    ///
    /// `msg` is a `'static` description of what was invalid.
    InvalidArg(&'static str),
    /// The response buffer supplied to [`Connection::transact`] is too small
    /// to hold the TPM response.
    ResponseBufferTooSmall,
    /// The response buffer supplied to [`Connection::transact`] is too large
    /// to express as a `c_int` (> 2 GiB).  The C transport shim uses `int`
    /// for buffer sizes; pass a smaller buffer.
    ResponseBufferTooLarge,
    /// The command buffer passed to [`Connection::transact`] is too large to
    /// fit in a `c_int`; the TPM transport has a maximum command size.
    CommandTooLarge,
    /// The TPM response header is malformed (size field is zero or truncated).
    MalformedResponse,
}

impl Error {
    /// Map a wolfTPM C return code to a `Result`.
    #[inline]
    pub(crate) fn check(rc: i32) -> Result<(), Error> {
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::Transport { code: rc })
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport { code } => {
                write!(f, "wolfTPM transport error 0x{:08x}", *code as u32)?;
                if let Some(name) = wolftpm_sys::tpm_rc::tpm_rc_name(*code as u32) {
                    write!(f, " ({name})")?;
                }
                Ok(())
            }
            Error::TpmLayer { rc } => {
                write!(f, "TPM error 0x{rc:08x}")?;
                if let Some(name) = wolftpm_sys::tpm_rc::tpm_rc_name(*rc) {
                    write!(f, " ({name})")?;
                }
                Ok(())
            }
            Error::InvalidArg(msg) => write!(f, "invalid argument: {msg}"),
            Error::ResponseBufferTooSmall => {
                write!(f, "response buffer too small for TPM response")
            }
            Error::ResponseBufferTooLarge => {
                write!(f, "response buffer exceeds c_int range (> 2 GiB); use a smaller buffer")
            }
            Error::CommandTooLarge => {
                write!(f, "command buffer too large for TPM transport")
            }
            Error::MalformedResponse => {
                write!(f, "TPM returned a malformed response header")
            }
        }
    }
}

impl std::error::Error for Error {}

// tpm2-rs-client requires Connection::Error: From<tpm2_rs_base::errors::TssError>.
#[cfg(feature = "tss")]
impl From<tpm2_rs_base::errors::TssError> for Error {
    /// Convert a [`tpm2_rs_base::errors::TssError`] into this crate's [`Error`].
    ///
    /// `TssError` is a TPM-layer protocol error (a TPM_RC code returned in a
    /// response header).  It maps to [`Error::TpmLayer`], which is distinct
    /// from [`Error::Transport`] (transport-layer failures such as a missing
    /// device or a broken socket).
    fn from(e: tpm2_rs_base::errors::TssError) -> Self {
        Error::TpmLayer { rc: e.get() }
    }
}

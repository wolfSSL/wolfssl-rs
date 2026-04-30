use core::fmt;

/// Error type for wolfTPM TSS transport operations.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// wolfTPM returned a nonzero error code from a transport operation.
    Transport {
        /// The wolfTPM / TPM_RC error code.
        code: i32,
    },
    /// The response buffer supplied to [`Connection::transact`] is too small
    /// to hold the TPM response.
    ResponseBufferTooSmall,
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
                write!(f, "wolfTPM transport error {code:#010x}")
            }
            Error::ResponseBufferTooSmall => {
                write!(f, "response buffer too small for TPM response")
            }
            Error::MalformedResponse => {
                write!(f, "TPM returned a malformed response header")
            }
        }
    }
}

impl std::error::Error for Error {}

// tpm2-rs-client requires Connection::Error: From<tpm2_rs_base::errors::TssError>.
impl From<tpm2_rs_base::errors::TssError> for Error {
    fn from(e: tpm2_rs_base::errors::TssError) -> Self {
        // TssError is a TPM-layer error, not a transport error.
        // Encode it as a transport code so callers can distinguish.
        Error::Transport { code: e.get() as i32 }
    }
}

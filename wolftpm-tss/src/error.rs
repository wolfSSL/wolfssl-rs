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
    /// A caller-supplied argument failed validation before any FFI call.
    ///
    /// `msg` is a `'static` description of what was invalid.
    InvalidArg(&'static str),
    /// The response buffer supplied to [`Connection::transact`] is too small
    /// to hold the TPM response, or its length overflows `c_int` (> 2 GiB) and
    /// therefore cannot be expressed to the C transport shim.  Both cases mean
    /// the caller must supply a correctly-sized buffer.
    ResponseBufferTooSmall,
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
                // `code` is a TPM_RC value (TPM2 Part 2 §6.6) or a wolfTPM
                // internal code (negative i32 cast to u32 → values >= 0x8000_0000).
                // Symbolic names for the codes most likely to appear at the
                // transport layer:
                let name = match *code as u32 {
                    // FMT1 base codes  (TPM2 Part 2 §6.6.3)
                    0x0081 => Some("TPM_RC_ASYMMETRIC"),
                    0x0083 => Some("TPM_RC_HASH"),
                    0x0084 => Some("TPM_RC_VALUE"),
                    0x008e => Some("TPM_RC_AUTH_FAIL"),
                    0x0095 => Some("TPM_RC_SIZE"),
                    0x0096 => Some("TPM_RC_SYMMETRIC"),
                    // VER1 codes  (TPM2 Part 2 §6.6.2)
                    0x0101 => Some("TPM_RC_FAILURE"),
                    0x0120 => Some("TPM_RC_DISABLED"),
                    0x0142 => Some("TPM_RC_COMMAND_SIZE"),
                    0x0143 => Some("TPM_RC_COMMAND_CODE"),
                    // WARN codes  (TPM2 Part 2 §6.6.4)
                    0x0904 => Some("TPM_RC_MEMORY"),
                    0x0922 => Some("TPM_RC_RETRY"),
                    // wolfTPM-internal codes (negative i32 cast to u32)
                    0xffffff9c => Some("wolfTPM:TIMEOUT(-100)"),
                    0xffffff53 => Some("wolfTPM:BAD_FUNC_ARG(-173)"),
                    0xffffff57 => Some("wolfTPM:BAD_STATE_E(-169)"),
                    _ => None,
                };
                write!(f, "wolfTPM transport error 0x{code:08x}")?;
                if let Some(n) = name {
                    write!(f, " ({n})")?;
                }
                Ok(())
            }
            Error::InvalidArg(msg) => write!(f, "invalid argument: {msg}"),
            Error::ResponseBufferTooSmall => {
                write!(f, "response buffer too small for TPM response")
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
    /// # Note on error mapping
    ///
    /// `TssError` is a TPM-layer protocol error (a TPM_RC code returned in a
    /// response header), not a transport-layer error.  It is mapped to
    /// `Error::Transport { code }` only because `tpm2-rs-client` requires
    /// `Connection::Error: From<TssError>` and this crate has no dedicated
    /// TPM-layer variant.
    ///
    /// This is a known limitation: callers that need to distinguish TPM-layer
    /// errors from transport failures must inspect the `code` field.  Adding a
    /// dedicated `Tpm { rc }` variant would require a breaking change to this
    /// error type.
    fn from(e: tpm2_rs_base::errors::TssError) -> Self {
        Error::Transport {
            code: e.get() as i32,
        }
    }
}

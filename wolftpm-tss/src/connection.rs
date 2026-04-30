//! [`Connection`](tpm2_rs_client::connection::Connection) implementations
//! backed by wolfTPM transports.
//!
//! # Status
//!
//! Stub — `open()` constructors and `transact()` bodies are not yet
//! implemented.  The types and trait impls are declared so that downstream
//! code can be written and type-checked against them.

use crate::error::Error;
use tpm2_rs_client::connection::Connection;

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
    // wolfTPM device context — heap-allocated to keep a stable address
    // for the C library, which may store a self-pointer inside WOLFTPM2_DEV.
    // TODO: allocate and initialise via wolfTPM2_Init when implementing open().
    _private: (),
}

impl WolfTpmLinuxDev {
    /// Open a connection to the TPM via the Linux kernel driver.
    ///
    /// Calls `wolfTPM2_Init` with the `WOLFTPM_LINUX_DEV` transport.
    /// Fails if `/dev/tpm0` is not present or not accessible.
    pub fn open() -> Result<Self, Error> {
        // TODO: wolfTPM2_Init + WOLFTPM_LINUX_DEV
        unimplemented!("WolfTpmLinuxDev::open — not yet implemented")
    }
}

impl Connection for WolfTpmLinuxDev {
    type Error = Error;

    fn transact<'a>(
        &mut self,
        _cmd: &[u8],
        _rsp: &'a mut [u8],
    ) -> Result<&'a mut [u8], Self::Error> {
        // TODO: call TPM2_CTX::ioCb directly to send _cmd and receive into _rsp.
        // Parse response length from _rsp[2..6] (big-endian u32, TCG spec).
        unimplemented!("WolfTpmLinuxDev::transact — not yet implemented")
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
pub struct WolfTpmSwtpm {
    // TODO: allocate and initialise via wolfTPM2_Init + WOLFTPM_SWTPM.
    _private: (),
}

impl WolfTpmSwtpm {
    /// Connect to a software TPM at `host:port`.
    ///
    /// The default swtpm port is `2321`; the IBM simulator uses `2321` for
    /// the TPM command port and `2322` for the platform port.
    pub fn connect(_host: &str, _port: u16) -> Result<Self, Error> {
        // TODO: wolfTPM2_Init + WOLFTPM_SWTPM
        unimplemented!("WolfTpmSwtpm::connect — not yet implemented")
    }
}

impl Connection for WolfTpmSwtpm {
    type Error = Error;

    fn transact<'a>(
        &mut self,
        _cmd: &[u8],
        _rsp: &'a mut [u8],
    ) -> Result<&'a mut [u8], Self::Error> {
        // TODO: call TPM2_CTX::ioCb directly to send _cmd and receive into _rsp.
        unimplemented!("WolfTpmSwtpm::transact — not yet implemented")
    }
}

use digest::{FixedOutput, HashMarker, Output, OutputSizeUser, Update};
use digest::typenum::{U32, U48, U64};
use wolfhsm_sys::{wolfhsm_sha256, wolfhsm_sha384, wolfhsm_sha512};

use crate::client::Client;
use crate::error::Error;

impl Client {
    /// One-shot SHA-256 hash via the HSM server.
    pub fn sha256(&mut self, data: &[u8]) -> Result<[u8; 32], Error> {
        let in_len = u32::try_from(data.len()).map_err(|_| Error::InvalidInput {
            msg: "input exceeds u32::MAX bytes",
        })?;
        let mut out = [0u8; 32];
        // SAFETY: all pointers are valid stack/heap allocations for this call.
        let rc = unsafe { wolfhsm_sha256(self.ctx_ptr(), data.as_ptr(), in_len, out.as_mut_ptr()) };
        Error::check(rc, "wolfhsm_sha256")?;
        Ok(out)
    }

    /// One-shot SHA-384 hash via the HSM server.
    pub fn sha384(&mut self, data: &[u8]) -> Result<[u8; 48], Error> {
        let in_len = u32::try_from(data.len()).map_err(|_| Error::InvalidInput {
            msg: "input exceeds u32::MAX bytes",
        })?;
        let mut out = [0u8; 48];
        // SAFETY: all pointers are valid stack/heap allocations for this call.
        let rc = unsafe { wolfhsm_sha384(self.ctx_ptr(), data.as_ptr(), in_len, out.as_mut_ptr()) };
        Error::check(rc, "wolfhsm_sha384")?;
        Ok(out)
    }

    /// One-shot SHA-512 hash via the HSM server.
    pub fn sha512(&mut self, data: &[u8]) -> Result<[u8; 64], Error> {
        let in_len = u32::try_from(data.len()).map_err(|_| Error::InvalidInput {
            msg: "input exceeds u32::MAX bytes",
        })?;
        let mut out = [0u8; 64];
        // SAFETY: all pointers are valid stack/heap allocations for this call.
        let rc = unsafe { wolfhsm_sha512(self.ctx_ptr(), data.as_ptr(), in_len, out.as_mut_ptr()) };
        Error::check(rc, "wolfhsm_sha512")?;
        Ok(out)
    }
}

/// SHA-256 hasher backed by the wolfHSM server.
///
/// Buffers the entire message in RAM; the hash is computed by the HSM in a
/// single one-shot call when [`FixedOutput::finalize_into`] is called.
///
/// # Error handling
///
/// [`digest::FixedOutput`] cannot propagate errors. If the HSM call fails,
/// `finalize_into` writes **all-zero bytes** to the output buffer and emits a
/// `log::error!` entry. There is no other signal — callers that require
/// reliable detection of HSM failures must use [`Client::sha256`] directly.
pub struct HsmSha256<'a> {
    client: &'a mut Client,
    buf: Vec<u8>,
}

impl<'a> HsmSha256<'a> {
    /// Create a new `HsmSha256` hasher using `client` for the final HSM call.
    pub fn new(client: &'a mut Client) -> Self {
        HsmSha256 {
            client,
            buf: Vec::new(),
        }
    }
}

impl Update for HsmSha256<'_> {
    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
}

impl OutputSizeUser for HsmSha256<'_> {
    type OutputSize = U32;
}

impl FixedOutput for HsmSha256<'_> {
    fn finalize_into(self, out: &mut Output<Self>) {
        match self.client.sha256(&self.buf) {
            Ok(digest) => out.copy_from_slice(&digest),
            Err(e) => {
                log::error!("HsmSha256: HSM error during finalize: {e}");
                out.iter_mut().for_each(|b| *b = 0);
            }
        }
    }
}

impl HashMarker for HsmSha256<'_> {}

/// SHA-384 hasher backed by the wolfHSM server.
///
/// Buffers the entire message in RAM; the hash is computed by the HSM in a
/// single one-shot call when [`FixedOutput::finalize_into`] is called.
///
/// # Error handling
///
/// [`digest::FixedOutput`] cannot propagate errors. If the HSM call fails,
/// `finalize_into` writes **all-zero bytes** to the output buffer and emits a
/// `log::error!` entry. There is no other signal — callers that require
/// reliable detection of HSM failures must use [`Client::sha384`] directly.
pub struct HsmSha384<'a> {
    client: &'a mut Client,
    buf: Vec<u8>,
}

impl<'a> HsmSha384<'a> {
    /// Create a new `HsmSha384` hasher using `client` for the final HSM call.
    pub fn new(client: &'a mut Client) -> Self {
        HsmSha384 {
            client,
            buf: Vec::new(),
        }
    }
}

impl Update for HsmSha384<'_> {
    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
}

impl OutputSizeUser for HsmSha384<'_> {
    type OutputSize = U48;
}

impl FixedOutput for HsmSha384<'_> {
    fn finalize_into(self, out: &mut Output<Self>) {
        match self.client.sha384(&self.buf) {
            Ok(digest) => out.copy_from_slice(&digest),
            Err(e) => {
                log::error!("HsmSha384: HSM error during finalize: {e}");
                out.iter_mut().for_each(|b| *b = 0);
            }
        }
    }
}

impl HashMarker for HsmSha384<'_> {}

/// SHA-512 hasher backed by the wolfHSM server.
///
/// Buffers the entire message in RAM; the hash is computed by the HSM in a
/// single one-shot call when [`FixedOutput::finalize_into`] is called.
///
/// # Error handling
///
/// [`digest::FixedOutput`] cannot propagate errors. If the HSM call fails,
/// `finalize_into` writes **all-zero bytes** to the output buffer and emits a
/// `log::error!` entry. There is no other signal — callers that require
/// reliable detection of HSM failures must use [`Client::sha512`] directly.
pub struct HsmSha512<'a> {
    client: &'a mut Client,
    buf: Vec<u8>,
}

impl<'a> HsmSha512<'a> {
    /// Create a new `HsmSha512` hasher using `client` for the final HSM call.
    pub fn new(client: &'a mut Client) -> Self {
        HsmSha512 {
            client,
            buf: Vec::new(),
        }
    }
}

impl Update for HsmSha512<'_> {
    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
}

impl OutputSizeUser for HsmSha512<'_> {
    type OutputSize = U64;
}

impl FixedOutput for HsmSha512<'_> {
    fn finalize_into(self, out: &mut Output<Self>) {
        match self.client.sha512(&self.buf) {
            Ok(digest) => out.copy_from_slice(&digest),
            Err(e) => {
                log::error!("HsmSha512: HSM error during finalize: {e}");
                out.iter_mut().for_each(|b| *b = 0);
            }
        }
    }
}

impl HashMarker for HsmSha512<'_> {}

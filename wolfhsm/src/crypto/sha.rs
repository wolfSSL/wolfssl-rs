use wolfhsm_sys::wolfhsm_sha256;

use crate::client::Client;
use crate::error::WolfHsmError;

/// One-shot SHA-256 hash via the HSM server.
#[deprecated(since = "0.1.0", note = "use `client.sha256(data)` instead")]
pub fn sha256(client: &mut Client, data: &[u8]) -> Result<[u8; 32], WolfHsmError> {
    client.sha256(data)
}

impl Client {
    /// One-shot SHA-256 hash via the HSM server.
    pub fn sha256(&mut self, data: &[u8]) -> Result<[u8; 32], WolfHsmError> {
        let in_len = u32::try_from(data.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "sha256: input too large",
        })?;
        let mut out = [0u8; 32];
        // SAFETY: all pointers are valid stack/heap allocations for this call.
        let rc = unsafe {
            wolfhsm_sha256(
                self.ctx_ptr(),
                data.as_ptr(),
                in_len,
                out.as_mut_ptr(),
            )
        };
        WolfHsmError::check(rc, "wolfhsm_sha256")?;
        Ok(out)
    }
}

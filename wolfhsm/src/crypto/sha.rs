use wolfhsm_sys::wolfhsm_sha256;

use crate::client::Client;
use crate::error::WolfHsmError;

impl Client {
    /// One-shot SHA-256 hash via the HSM server.
    pub fn sha256(&mut self, data: &[u8]) -> Result<[u8; 32], WolfHsmError> {
        let in_len = u32::try_from(data.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "input exceeds u32::MAX bytes",
        })?;
        let mut out = [0u8; 32];
        // SAFETY: all pointers are valid stack/heap allocations for this call.
        let rc = unsafe { wolfhsm_sha256(self.ctx_ptr(), data.as_ptr(), in_len, out.as_mut_ptr()) };
        WolfHsmError::check(rc, "wolfhsm_sha256")?;
        Ok(out)
    }
}

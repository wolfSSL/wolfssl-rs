use wolfhsm_sys::wh_Client_RngGenerate;

use crate::client::Client;
use crate::error::Error;

impl Client {
    /// Generate `size` random bytes using the wolfHSM server's RNG.
    pub fn rng_generate(&mut self, size: usize) -> Result<Vec<u8>, Error> {
        let size_u32 = u32::try_from(size).map_err(|_| Error::BadArgs {
            msg: "size exceeds u32::MAX",
        })?;
        let mut buf = vec![0u8; size];
        // SAFETY: buf is a valid heap allocation for the duration of this call.
        let rc = unsafe { wh_Client_RngGenerate(self.ctx_ptr(), buf.as_mut_ptr(), size_u32) };
        Error::check(rc, "wh_Client_RngGenerate")?;
        Ok(buf)
    }
}

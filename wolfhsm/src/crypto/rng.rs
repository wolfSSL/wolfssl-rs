use wolfhsm_sys::wh_Client_RngGenerate;

use crate::client::Client;
use crate::error::WolfHsmError;

/// Generate `size` random bytes using the wolfHSM server's RNG.
pub fn generate(client: &mut Client, size: usize) -> Result<Vec<u8>, WolfHsmError> {
    let size_u32 = u32::try_from(size).map_err(|_| WolfHsmError::Ffi {
        code: -1,
        func: "rng::generate: size too large",
    })?;
    let mut buf = vec![0u8; size];
    // SAFETY: buf is a valid heap allocation for the duration of this call.
    let rc = unsafe { wh_Client_RngGenerate(client.ctx_ptr(), buf.as_mut_ptr(), size_u32) };
    WolfHsmError::check(rc, "wh_Client_RngGenerate")?;
    Ok(buf)
}

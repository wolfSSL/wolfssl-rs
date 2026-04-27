use wolfhsm_sys::wolfhsm_cmac;

use crate::client::Client;
use crate::error::WolfHsmError;
use crate::key::KeyId;

/// CMAC-AES key handle. Key lives in HSM cache.
///
/// # Resource management
///
/// The key occupies a slot in the HSM RAM key cache for its entire lifetime.
/// You **must** call [`evict`][CmacKey::evict] when done; dropping the handle
/// without evicting silently leaks the cache slot and will eventually cause
/// `wh_Client_*` calls to fail with a "cache full" error.
pub struct CmacKey {
    pub(crate) id: KeyId,
}

impl CmacKey {
    /// Cache raw AES key bytes for CMAC. Key must be 16, 24, or 32 bytes.
    pub fn cache(client: &mut Client, key_bytes: &[u8]) -> Result<Self, WolfHsmError> {
        match key_bytes.len() {
            16 | 24 | 32 => {}
            _ => {
                return Err(WolfHsmError::Ffi {
                    code: -1,
                    func: "CmacKey::cache: key must be 16, 24, or 32 bytes",
                });
            }
        }
        let id = client.key_cache(key_bytes, b"cmac")?;
        Ok(CmacKey { id })
    }

    /// Evict this key from the HSM key cache.
    pub fn evict(self, client: &mut Client) -> Result<(), WolfHsmError> {
        client.key_evict(self.id)
    }

    /// Compute a 16-byte CMAC tag over data.
    pub fn compute(&self, client: &mut Client, data: &[u8]) -> Result<[u8; 16], WolfHsmError> {
        let in_len = u32::try_from(data.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_cmac: data too large",
        })?;
        let mut out = [0u8; 16];
        let mut out_len: u32 = 16;
        // SAFETY: all pointers are valid stack/heap allocations for this call.
        let rc = unsafe {
            wolfhsm_cmac(
                client.ctx_ptr(),
                self.id.0,
                data.as_ptr(),
                in_len,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_cmac")?;
        if out_len != 16 {
            return Err(WolfHsmError::Ffi {
                code: -1,
                func: "wolfhsm_cmac: unexpected output length",
            });
        }
        Ok(out)
    }
}

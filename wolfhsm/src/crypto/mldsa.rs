use core::ffi::c_int;

use wolfhsm_sys::{wolfhsm_mldsa_make_key, wolfhsm_mldsa_sign, wolfhsm_mldsa_verify};

use crate::client::Client;
use crate::error::WolfHsmError;
use crate::key::KeyId;

/// Exact ML-DSA signature sizes per level (FIPS 204, Table 2).
fn mldsa_sig_len(level: u8) -> usize {
    match level {
        44 => 2420,
        65 => 3309,
        _  => 4627, // level 87
    }
}

/// ML-DSA (Dilithium) key handle. Level is 44, 65, or 87.
///
/// # Resource management
///
/// The key occupies a slot in the HSM RAM key cache for its entire lifetime.
/// You **must** call [`evict`][MlDsaKey::evict] when done; dropping the handle
/// without evicting silently leaks the cache slot and will eventually cause
/// `wh_Client_*` calls to fail with a "cache full" error.
pub struct MlDsaKey {
    pub(crate) id: KeyId,
    pub level: u8,
}

impl MlDsaKey {
    /// Generate an ML-DSA key at the given level (44, 65, or 87).
    pub fn generate(client: &mut Client, level: u8) -> Result<Self, WolfHsmError> {
        if !matches!(level, 44 | 65 | 87) {
            return Err(WolfHsmError::Ffi {
                code: -1,
                func: "MlDsaKey::generate: level must be 44, 65, or 87",
            });
        }
        let mut key_id: u16 = 0;
        // SAFETY: ctx_ptr is valid for the duration of this call; key_id is a
        // valid stack allocation.
        let rc = unsafe {
            wolfhsm_mldsa_make_key(client.ctx_ptr(), level as c_int, &mut key_id)
        };
        WolfHsmError::check(rc, "wolfhsm_mldsa_make_key")?;
        Ok(MlDsaKey { id: KeyId(key_id), level })
    }

    /// Evict this key from the HSM key cache.
    pub fn evict(self, client: &mut Client) -> Result<(), WolfHsmError> {
        client.key_evict(self.id)
    }

    /// Sign a message. Signature size depends on level:
    /// level 44 → 2420 bytes, level 65 → 3309 bytes, level 87 → 4627 bytes.
    pub fn sign(&self, client: &mut Client, msg: &[u8]) -> Result<Vec<u8>, WolfHsmError> {
        let msg_len = u32::try_from(msg.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_mldsa_sign: message too large",
        })?;
        let cap = mldsa_sig_len(self.level);
        let mut sig = vec![0u8; cap];
        let mut sig_len: u32 = cap as u32;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wolfhsm_mldsa_sign(
                client.ctx_ptr(),
                self.id.0,
                self.level as c_int,
                msg.as_ptr(),
                msg_len,
                sig.as_mut_ptr(),
                &mut sig_len,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_mldsa_sign")?;
        sig.truncate(sig_len as usize);
        Ok(sig)
    }

    /// Verify a signature. Returns `Ok(())` if valid.
    pub fn verify(
        &self,
        client: &mut Client,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), WolfHsmError> {
        let mut result: c_int = 0;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wolfhsm_mldsa_verify(
                client.ctx_ptr(),
                self.id.0,
                self.level as c_int,
                sig.as_ptr(),
                sig.len() as u32,
                msg.as_ptr(),
                msg.len() as u32,
                &mut result,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_mldsa_verify")?;
        if result != 1 {
            return Err(WolfHsmError::Ffi {
                code: -1,
                func: "mldsa_verify: invalid signature",
            });
        }
        Ok(())
    }
}

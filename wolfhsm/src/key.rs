use wolfhsm_sys::{
    wh_Client_KeyCache, wh_Client_KeyCommit, wh_Client_KeyErase, wh_Client_KeyEvict,
};

use crate::client::Client;
use crate::error::WolfHsmError;

/// A wolfHSM key identifier (wraps `whKeyId` = `u16`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub u16);

impl KeyId {
    /// The erased/invalid key ID (`WH_KEYID_ERASED` = 0).
    pub const ERASED: Self = KeyId(0);
}

impl From<u16> for KeyId {
    fn from(v: u16) -> Self {
        KeyId(v)
    }
}

impl From<KeyId> for u16 {
    fn from(k: KeyId) -> Self {
        k.0
    }
}

// WH_NVM_LABEL_LEN as defined in the wolfHSM C headers.
const WH_NVM_LABEL_LEN: usize = 24;

impl Client {
    /// Store key bytes in the server's RAM key cache.
    ///
    /// `label` is truncated to `WH_NVM_LABEL_LEN` (24) bytes.
    /// `flags` is 0 (default).
    /// Returns the server-assigned [`KeyId`].
    pub fn key_cache(&mut self, data: &[u8], label: &[u8]) -> Result<KeyId, WolfHsmError> {
        if data.len() > u16::MAX as usize {
            return Err(WolfHsmError::Ffi {
                code: -1,
                func: "key_cache: data exceeds u16::MAX bytes",
            });
        }

        // Truncate label to WH_NVM_LABEL_LEN; pad remainder with zeros.
        let mut label_buf = [0u8; WH_NVM_LABEL_LEN];
        let copy_len = label.len().min(WH_NVM_LABEL_LEN);
        label_buf[..copy_len].copy_from_slice(&label[..copy_len]);

        let mut key_id: u16 = 0; // WH_KEYID_ERASED — server assigns a new ID

        // SAFETY: pointers are valid for the duration of this call.
        let rc = unsafe {
            wh_Client_KeyCache(
                self.ctx_ptr(),
                0, // flags
                label_buf.as_mut_ptr(),
                WH_NVM_LABEL_LEN as u16,
                data.as_ptr(),
                data.len() as u16,
                &mut key_id,
            )
        };
        WolfHsmError::check(rc, "wh_Client_KeyCache")?;
        Ok(KeyId(key_id))
    }

    /// Remove a key from the server's RAM cache.
    ///
    /// This does NOT erase the key from NVM if it has been committed.
    pub fn key_evict(&mut self, id: KeyId) -> Result<(), WolfHsmError> {
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wh_Client_KeyEvict(self.ctx_ptr(), id.0) };
        WolfHsmError::check(rc, "wh_Client_KeyEvict")
    }

    /// Write a cached key from RAM to persistent NVM storage.
    pub fn key_commit(&mut self, id: KeyId) -> Result<(), WolfHsmError> {
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wh_Client_KeyCommit(self.ctx_ptr(), id.0) };
        WolfHsmError::check(rc, "wh_Client_KeyCommit")
    }

    /// Permanently erase a key from NVM.
    pub fn key_erase(&mut self, id: KeyId) -> Result<(), WolfHsmError> {
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wh_Client_KeyErase(self.ctx_ptr(), id.0) };
        WolfHsmError::check(rc, "wh_Client_KeyErase")
    }
}

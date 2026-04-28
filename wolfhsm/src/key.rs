use wolfhsm_sys::{
    wh_Client_KeyCache, wh_Client_KeyCommit, wh_Client_KeyErase, wh_Client_KeyEvict,
};

use crate::client::Client;
use crate::error::Error;

/// A wolfHSM key identifier (wraps `whKeyId` = `u16`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub(crate) u16);

impl KeyId {
    /// The erased/invalid key ID (`WH_KEYID_ERASED` = 0).
    pub const ERASED: Self = KeyId(0);

    /// Wrap a raw `whKeyId` value.
    ///
    /// Prefer the [`From<u16>`] impl in non-`const` contexts.
    pub const fn new(id: u16) -> Self {
        Self(id)
    }
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
    pub fn key_cache(&mut self, data: &[u8], label: impl AsRef<[u8]>) -> Result<KeyId, Error> {
        let label = label.as_ref();
        if data.len() > u16::MAX as usize {
            return Err(Error::BadArgs {
                msg: "key data exceeds u16::MAX bytes",
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
        Error::check(rc, "wh_Client_KeyCache")?;
        if key_id == 0 {
            return Err(Error::ProtocolError {
                msg: "wh_Client_KeyCache: server returned WH_KEYID_ERASED (0); \
                      server-side cache may be full or the key was rejected",
            });
        }
        Ok(KeyId(key_id))
    }

    /// Remove a key from the server's RAM cache.
    ///
    /// This does NOT erase the key from NVM if it has been committed.
    pub fn key_evict(&mut self, id: KeyId) -> Result<(), Error> {
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wh_Client_KeyEvict(self.ctx_ptr(), id.0) };
        Error::check(rc, "wh_Client_KeyEvict")
    }

    /// Write a cached key from RAM to persistent NVM storage.
    pub fn key_commit(&mut self, id: KeyId) -> Result<(), Error> {
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wh_Client_KeyCommit(self.ctx_ptr(), id.0) };
        Error::check(rc, "wh_Client_KeyCommit")
    }

    /// Permanently erase a key from NVM.
    pub fn key_erase(&mut self, id: KeyId) -> Result<(), Error> {
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wh_Client_KeyErase(self.ctx_ptr(), id.0) };
        Error::check(rc, "wh_Client_KeyErase")
    }
}

/// Internal macro: run a closure with a key handle, always evicting afterward.
///
/// Usage: `with_key!(key_expr, client_ref, closure)`
/// - `key_expr`: an expression producing the key (already constructed)
/// - `client_ref`: `&mut Client`
/// - `closure`: `FnOnce(&Key, &mut Client) -> Result<R, Error>`
///
/// The macro silences the drop warning by clearing `key.id` to `KeyId::ERASED`
/// before eviction. On the success path, an eviction error is propagated. On
/// the error path, eviction is best-effort (failure is printed but original
/// error returned).
macro_rules! with_key {
    ($key:expr, $client:expr, $f:expr) => {{
        let mut key = $key;
        let id = key.id;
        let result = $f(&key, $client);
        key.id = $crate::key::KeyId::ERASED; // prevent drop warning
        let evict = $client.key_evict(id);
        match result {
            Ok(v) => {
                evict?;
                Ok(v)
            }
            Err(e) => {
                if let Err(evict_err) = evict {
                    log::warn!("wolfhsm: key eviction failed during error cleanup: {evict_err}");
                }
                Err(e)
            }
        }
    }};
}

pub(crate) use with_key;

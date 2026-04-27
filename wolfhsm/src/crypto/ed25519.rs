use wolfhsm_sys::{wolfhsm_ed25519_make_key, wolfhsm_ed25519_sign, wolfhsm_ed25519_verify};

use crate::client::Client;
use crate::error::WolfHsmError;
use crate::key::{with_key, KeyId};

/// Ed25519 key handle. The private key lives in the HSM key cache.
///
/// # Resource management
///
/// The key occupies a slot in the HSM RAM key cache for its entire lifetime.
/// You **must** call [`evict`][Ed25519Key::evict] when done; dropping the handle
/// without evicting silently leaks the cache slot and will eventually cause
/// `wh_Client_*` calls to fail with a "cache full" error.
pub struct Ed25519Key {
    pub(crate) id: KeyId,
}

impl Ed25519Key {
    /// Generate an ephemeral Ed25519 key on the HSM (cached, not committed to NVM).
    pub fn generate(client: &mut Client) -> Result<Self, WolfHsmError> {
        let mut key_id: u16 = KeyId::ERASED.0;
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wolfhsm_ed25519_make_key(client.ctx_ptr(), &mut key_id) };
        WolfHsmError::check(rc, "wolfhsm_ed25519_make_key")?;
        if key_id == KeyId::ERASED.0 {
            return Err(WolfHsmError::Ffi {
                code: -1,
                func: "wolfhsm_ed25519_make_key: server returned WH_KEYID_ERASED (0)",
            });
        }
        Ok(Ed25519Key { id: KeyId(key_id) })
    }

    /// Evict this key from the HSM key cache.
    pub fn evict(mut self, client: &mut Client) -> Result<(), WolfHsmError> {
        let id = core::mem::replace(&mut self.id, KeyId::ERASED);
        client.key_evict(id)
    }

    /// Export the 32-byte Ed25519 public key.
    pub fn public_key(&self, client: &mut Client) -> Result<[u8; 32], WolfHsmError> {
        let mut buf = [0u8; 32];
        let rc = unsafe {
            wolfhsm_sys::wolfhsm_ed25519_export_public(
                client.ctx_ptr(),
                self.id.0,
                buf.as_mut_ptr(),
            )
        };
        WolfHsmError::check(rc, "wolfhsm_ed25519_export_public")?;
        Ok(buf)
    }

    /// Sign a message. Returns a 64-byte Ed25519 signature.
    pub fn sign(&self, client: &mut Client, msg: &[u8]) -> Result<[u8; 64], WolfHsmError> {
        let msg_len = u32::try_from(msg.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "message exceeds u32::MAX bytes",
        })?;
        let mut buf = [0u8; 64];
        let mut sig_len: u32 = 64;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wolfhsm_ed25519_sign(
                client.ctx_ptr(),
                self.id.0,
                msg.as_ptr(),
                msg_len,
                buf.as_mut_ptr(),
                &mut sig_len,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_ed25519_sign")?;
        if sig_len != 64 {
            return Err(WolfHsmError::Ffi {
                code: -1,
                func: "wolfhsm_ed25519_sign: unexpected signature length",
            });
        }
        Ok(buf)
    }

    /// Verify a signature. Returns `Ok(())` if valid.
    pub fn verify(
        &self,
        client: &mut Client,
        msg: &[u8],
        sig: &[u8; 64],
    ) -> Result<(), WolfHsmError> {
        let msg_len = u32::try_from(msg.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "message exceeds u32::MAX bytes",
        })?;
        let mut result: core::ffi::c_int = 0;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wolfhsm_ed25519_verify(
                client.ctx_ptr(),
                self.id.0,
                sig.as_ptr(),
                64u32,
                msg.as_ptr(),
                msg_len,
                &mut result,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_ed25519_verify")?;
        if result != 1 {
            return Err(WolfHsmError::Ffi {
                code: -1,
                func: "ed25519_verify: invalid signature",
            });
        }
        Ok(())
    }
}

impl Drop for Ed25519Key {
    fn drop(&mut self) {
        if self.id != KeyId::ERASED {
            log::warn!(
                "wolfhsm: Ed25519Key (id={}) dropped without eviction — \
                 HSM cache slot leaked. Use with_ed25519_key() or call .evict().",
                self.id.0
            );
        }
    }
}

impl Client {
    /// Generate an Ed25519 key, run `f`, then always evict.
    ///
    /// Guarantees the HSM cache slot is released even when `f` returns `Err`.
    pub fn with_ed25519_key<F, R>(&mut self, f: F) -> Result<R, WolfHsmError>
    where
        F: FnOnce(&Ed25519Key, &mut Client) -> Result<R, WolfHsmError>,
    {
        let key = Ed25519Key::generate(self)?;
        with_key!(key, self, f)
    }
}

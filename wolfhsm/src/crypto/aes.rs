use wolfhsm_sys::{wolfhsm_aes_gcm_decrypt, wolfhsm_aes_gcm_encrypt};

use crate::client::Client;
use crate::error::WolfHsmError;
use crate::key::KeyId;

/// AES key handle (GCM mode). Key lives in HSM cache.
///
/// # Resource management
///
/// The key occupies a slot in the HSM RAM key cache for its entire lifetime.
/// You **must** call [`evict`][AesKey::evict] when done; dropping the handle
/// without evicting silently leaks the cache slot and will eventually cause
/// `wh_Client_*` calls to fail with a "cache full" error.
pub struct AesKey {
    pub(crate) id: KeyId,
}

impl AesKey {
    /// Cache raw key bytes in the HSM. `key_bytes` must be 16, 24, or 32 bytes.
    pub fn cache(client: &mut Client, key_bytes: &[u8]) -> Result<Self, WolfHsmError> {
        if !matches!(key_bytes.len(), 16 | 24 | 32) {
            return Err(WolfHsmError::Ffi {
                code: -1,
                func: "AesKey::cache: key must be 16, 24, or 32 bytes",
            });
        }
        let id = client.key_cache(key_bytes, b"aes")?;
        Ok(AesKey { id })
    }

    /// Evict this key from the HSM key cache.
    pub fn evict(mut self, client: &mut Client) -> Result<(), WolfHsmError> {
        let id = core::mem::replace(&mut self.id, KeyId::ERASED);
        client.key_evict(id)
    }

    /// AES-GCM encrypt. Returns (ciphertext, 16-byte auth tag).
    /// `iv` must be exactly 12 bytes (96-bit GCM IV); other lengths will cause
    /// the server to return an error.
    pub fn gcm_encrypt(
        &self,
        client: &mut Client,
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), WolfHsmError> {
        let iv_len = u32::try_from(iv.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_aes_gcm_encrypt: iv too large",
        })?;
        let aad_len = u32::try_from(aad.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_aes_gcm_encrypt: aad too large",
        })?;
        let in_len = u32::try_from(plaintext.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_aes_gcm_encrypt: plaintext too large",
        })?;
        let mut out = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        // SAFETY: all pointers are valid heap/stack allocations for this call.
        let rc = unsafe {
            wolfhsm_aes_gcm_encrypt(
                client.ctx_ptr(),
                self.id.0,
                iv.as_ptr(),
                iv_len,
                aad.as_ptr(),
                aad_len,
                plaintext.as_ptr(),
                in_len,
                out.as_mut_ptr(),
                tag.as_mut_ptr(),
                16,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_aes_gcm_encrypt")?;
        Ok((out, tag))
    }

    /// AES-GCM decrypt. Verifies the auth tag. Returns plaintext.
    pub fn gcm_decrypt(
        &self,
        client: &mut Client,
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, WolfHsmError> {
        let iv_len = u32::try_from(iv.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_aes_gcm_decrypt: iv too large",
        })?;
        let aad_len = u32::try_from(aad.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_aes_gcm_decrypt: aad too large",
        })?;
        let in_len = u32::try_from(ciphertext.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_aes_gcm_decrypt: ciphertext too large",
        })?;
        let mut out = vec![0u8; ciphertext.len()];
        // SAFETY: all pointers are valid heap/stack allocations for this call.
        let rc = unsafe {
            wolfhsm_aes_gcm_decrypt(
                client.ctx_ptr(),
                self.id.0,
                iv.as_ptr(),
                iv_len,
                aad.as_ptr(),
                aad_len,
                ciphertext.as_ptr(),
                in_len,
                out.as_mut_ptr(),
                tag.as_ptr(),
                16,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_aes_gcm_decrypt")?;
        Ok(out)
    }
}

impl Drop for AesKey {
    fn drop(&mut self) {
        if self.id != KeyId::ERASED {
            eprintln!(
                "wolfhsm: AesKey (id={}) dropped without eviction — \
                 HSM cache slot leaked. Use with_aes_key() or call .evict().",
                self.id.0
            );
        }
    }
}

impl Client {
    /// Cache an AES key, run `f` with it, then always evict it.
    pub fn with_aes_key<F, R>(&mut self, key_bytes: &[u8], f: F) -> Result<R, WolfHsmError>
    where
        F: FnOnce(&AesKey, &mut Client) -> Result<R, WolfHsmError>,
    {
        let mut key = AesKey::cache(self, key_bytes)?;
        let id = key.id;
        let result = f(&key, self);
        key.id = KeyId::ERASED; // prevent drop warning; eviction below handles cleanup
        let evict = self.key_evict(id);
        match result {
            Ok(v) => { evict?; Ok(v) }
            Err(e) => {
                if let Err(evict_err) = evict {
                    eprintln!(
                        "wolfhsm: key eviction failed during error cleanup: {evict_err}"
                    );
                }
                Err(e)
            }
        }
    }
}

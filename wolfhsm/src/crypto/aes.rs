use wolfhsm_sys::{wolfhsm_aes_gcm_decrypt, wolfhsm_aes_gcm_encrypt};

use crate::client::Client;
use crate::error::WolfHsmError;
use crate::key::{with_key, KeyId};

/// AES key handle (GCM mode). Key lives in HSM cache.
///
/// Keys are accessed exclusively through [`Client::with_aes_key`], which
/// caches the key bytes, runs the provided closure, and always evicts it on exit —
/// including when the closure returns `Err`.
pub struct AesKey {
    pub(crate) id: KeyId,
}

impl AesKey {
    /// Cache raw key bytes in the HSM. `key_bytes` must be 16, 24, or 32 bytes.
    pub(crate) fn cache(client: &mut Client, key_bytes: &[u8]) -> Result<Self, WolfHsmError> {
        if !matches!(key_bytes.len(), 16 | 24 | 32) {
            return Err(WolfHsmError::BadArgs {
                msg: "key must be 16, 24, or 32 bytes",
            });
        }
        let id = client.key_cache(key_bytes, b"aes")?;
        Ok(AesKey { id })
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
        let iv_len = u32::try_from(iv.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "iv exceeds u32::MAX bytes",
        })?;
        let aad_len = u32::try_from(aad.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "aad exceeds u32::MAX bytes",
        })?;
        let in_len = u32::try_from(plaintext.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "plaintext exceeds u32::MAX bytes",
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
        let iv_len = u32::try_from(iv.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "iv exceeds u32::MAX bytes",
        })?;
        let aad_len = u32::try_from(aad.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "aad exceeds u32::MAX bytes",
        })?;
        let in_len = u32::try_from(ciphertext.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "ciphertext exceeds u32::MAX bytes",
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
            log::warn!(
                "wolfhsm: AesKey (id={}) dropped without eviction — \
                 HSM cache slot leaked. Use with_aes_key().",
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
        let key = AesKey::cache(self, key_bytes)?;
        with_key!(key, self, f)
    }
}

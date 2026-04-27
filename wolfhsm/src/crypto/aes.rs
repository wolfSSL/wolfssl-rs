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
    /// Key length in bits (128, 192, or 256).
    pub bits: u32,
}

impl AesKey {
    /// Cache raw key bytes in the HSM. `key_bytes` must be 16, 24, or 32 bytes.
    pub fn cache(client: &mut Client, key_bytes: &[u8]) -> Result<Self, WolfHsmError> {
        let bits = match key_bytes.len() {
            16 => 128u32,
            24 => 192u32,
            32 => 256u32,
            _ => {
                return Err(WolfHsmError::Ffi {
                    code: -1,
                    func: "AesKey::cache: key must be 16, 24, or 32 bytes",
                });
            }
        };
        let id = client.key_cache(key_bytes, b"aes")?;
        Ok(AesKey { id, bits })
    }

    /// Evict this key from the HSM key cache.
    pub fn evict(self, client: &mut Client) -> Result<(), WolfHsmError> {
        client.key_evict(self.id)
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

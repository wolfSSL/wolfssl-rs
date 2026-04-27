use wolfhsm_sys::{wolfhsm_curve25519_make_key, wolfhsm_curve25519_shared_secret};

use crate::client::Client;
use crate::error::WolfHsmError;
use crate::key::KeyId;

/// Curve25519 key handle. The private key lives in the HSM key cache.
///
/// # Resource management
///
/// The key occupies a slot in the HSM RAM key cache for its entire lifetime.
/// You **must** call [`evict`][Curve25519Key::evict] when done; dropping the handle
/// without evicting silently leaks the cache slot and will eventually cause
/// `wh_Client_*` calls to fail with a "cache full" error.
pub struct Curve25519Key {
    pub(crate) id: KeyId,
}

impl Curve25519Key {
    /// Generate an ephemeral Curve25519 key on the HSM (cached, not committed to NVM).
    pub fn generate(client: &mut Client) -> Result<Self, WolfHsmError> {
        let mut key_id: u16 = KeyId::ERASED.0;
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wolfhsm_curve25519_make_key(client.ctx_ptr(), &mut key_id) };
        WolfHsmError::check(rc, "wolfhsm_curve25519_make_key")?;
        Ok(Curve25519Key { id: KeyId(key_id) })
    }

    /// Evict this key from the HSM key cache.
    pub fn evict(self, client: &mut Client) -> Result<(), WolfHsmError> {
        client.key_evict(self.id)
    }

    /// X25519 DH. `peer_public` is a 32-byte little-endian public key.
    /// Returns the 32-byte shared secret.
    pub fn diffie_hellman(
        &self,
        client: &mut Client,
        peer_public: &[u8; 32],
    ) -> Result<[u8; 32], WolfHsmError> {
        let mut buf = [0u8; 32];
        let mut out_len: u32 = 32;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wolfhsm_curve25519_shared_secret(
                client.ctx_ptr(),
                self.id.0,
                peer_public.as_ptr(),
                32u32,
                buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_curve25519_shared_secret")?;
        if out_len != 32 {
            return Err(WolfHsmError::Ffi {
                code: -1,
                func: "wolfhsm_curve25519_shared_secret: unexpected output length",
            });
        }
        Ok(buf)
    }
}

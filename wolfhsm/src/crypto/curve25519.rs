use wolfhsm_sys::{wolfhsm_curve25519_make_key, wolfhsm_curve25519_shared_secret};

use crate::client::Client;
use crate::error::WolfHsmError;
use crate::key::{with_key, KeyId};

/// Curve25519 key handle. The private key lives in the HSM key cache.
///
/// Keys are accessed exclusively through [`Client::with_curve25519_key`], which
/// generates a key, runs the provided closure, and always evicts it on exit —
/// including when the closure returns `Err`.
pub struct Curve25519Key {
    pub(crate) id: KeyId,
}

impl Curve25519Key {
    /// Generate an ephemeral Curve25519 key on the HSM (cached, not committed to NVM).
    pub(crate) fn generate(client: &mut Client) -> Result<Self, WolfHsmError> {
        let mut key_id: u16 = KeyId::ERASED.0;
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wolfhsm_curve25519_make_key(client.ctx_ptr(), &mut key_id) };
        WolfHsmError::check(rc, "wolfhsm_curve25519_make_key")?;
        if key_id == KeyId::ERASED.0 {
            return Err(WolfHsmError::Ffi {
                code: -1,
                func: "wolfhsm_curve25519_make_key: server returned WH_KEYID_ERASED (0)",
            });
        }
        Ok(Curve25519Key { id: KeyId(key_id) })
    }

    /// Export the 32-byte Curve25519 public key (little-endian).
    pub fn public_key(&self, client: &mut Client) -> Result<[u8; 32], WolfHsmError> {
        let mut buf = [0u8; 32];
        let rc = unsafe {
            wolfhsm_sys::wolfhsm_curve25519_export_public(
                client.ctx_ptr(),
                self.id.0,
                buf.as_mut_ptr(),
            )
        };
        WolfHsmError::check(rc, "wolfhsm_curve25519_export_public")?;
        Ok(buf)
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

impl Drop for Curve25519Key {
    fn drop(&mut self) {
        if self.id != KeyId::ERASED {
            log::warn!(
                "wolfhsm: Curve25519Key (id={}) dropped without eviction — \
                 HSM cache slot leaked. Use with_curve25519_key().",
                self.id.0
            );
        }
    }
}

impl Client {
    /// Generate a Curve25519 key, run `f`, then always evict.
    ///
    /// Guarantees the HSM cache slot is released even when `f` returns `Err`.
    pub fn with_curve25519_key<F, R>(&mut self, f: F) -> Result<R, WolfHsmError>
    where
        F: FnOnce(&Curve25519Key, &mut Client) -> Result<R, WolfHsmError>,
    {
        let key = Curve25519Key::generate(self)?;
        with_key!(key, self, f)
    }
}

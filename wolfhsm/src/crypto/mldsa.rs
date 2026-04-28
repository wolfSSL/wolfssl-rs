use core::ffi::c_int;

use wolfhsm_sys::{wolfhsm_mldsa_make_key, wolfhsm_mldsa_sign, wolfhsm_mldsa_verify};

use crate::client::Client;
use crate::error::Error;
use crate::key::{with_key, KeyId};

/// Exact ML-DSA signature sizes per level (FIPS 204, Table 2).
fn mldsa_sig_len(level: u8) -> usize {
    match level {
        44 => 2420,
        65 => 3309,
        _ => 4627, // level 87
    }
}

/// ML-DSA (Dilithium) key handle. Level is 44, 65, or 87.
///
/// Keys are accessed exclusively through [`Client::with_mldsa_key`], which
/// generates a key, runs the provided closure, and always evicts it on exit —
/// including when the closure returns `Err`.
pub struct MlDsaKey {
    pub(crate) id: KeyId,
    level: u8,
}

impl MlDsaKey {
    /// Return the ML-DSA level (44, 65, or 87).
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Generate an ML-DSA key at the given level (44, 65, or 87).
    pub(crate) fn generate(client: &mut Client, level: u8) -> Result<Self, Error> {
        if !matches!(level, 44 | 65 | 87) {
            return Err(Error::BadArgs {
                msg: "MlDsaKey::generate: level must be 44, 65, or 87",
            });
        }
        let mut key_id: u16 = 0;
        // SAFETY: ctx_ptr is valid for the duration of this call; key_id is a
        // valid stack allocation.
        let rc = unsafe { wolfhsm_mldsa_make_key(client.ctx_ptr(), level as c_int, &mut key_id) };
        Error::check(rc, "wolfhsm_mldsa_make_key")?;
        if key_id == 0 {
            return Err(Error::ProtocolError {
                msg: "wolfhsm_mldsa_make_key: server returned WH_KEYID_ERASED (0)",
            });
        }
        Ok(MlDsaKey {
            id: KeyId(key_id),
            level,
        })
    }

    /// Sign a message. Signature size depends on level:
    /// level 44 → 2420 bytes, level 65 → 3309 bytes, level 87 → 4627 bytes.
    pub fn sign(&self, client: &mut Client, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let msg_len = u32::try_from(msg.len()).map_err(|_| Error::BadArgs {
            msg: "mldsa sign: message exceeds u32::MAX bytes",
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
        Error::check(rc, "wolfhsm_mldsa_sign")?;
        sig.truncate(sig_len as usize);
        Ok(sig)
    }

    /// Verify a signature. Returns `Ok(())` if valid.
    pub fn verify(&self, client: &mut Client, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let sig_len = u32::try_from(sig.len()).map_err(|_| Error::BadArgs {
            msg: "mldsa verify: signature exceeds u32::MAX bytes",
        })?;
        let msg_len = u32::try_from(msg.len()).map_err(|_| Error::BadArgs {
            msg: "mldsa verify: message exceeds u32::MAX bytes",
        })?;
        let mut result: c_int = 0;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wolfhsm_mldsa_verify(
                client.ctx_ptr(),
                self.id.0,
                self.level as c_int,
                sig.as_ptr(),
                sig_len,
                msg.as_ptr(),
                msg_len,
                &mut result,
            )
        };
        Error::check(rc, "wolfhsm_mldsa_verify")?;
        if result != 1 {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

impl Drop for MlDsaKey {
    fn drop(&mut self) {
        if self.id != KeyId::ERASED {
            log::warn!(
                "wolfhsm: MlDsaKey (id={}) dropped without eviction — \
                 HSM cache slot leaked. Use with_mldsa_key().",
                self.id.0
            );
        }
    }
}

impl Client {
    /// Generate an ML-DSA key, run `f` with it, then always evict it.
    pub fn with_mldsa_key<F, R>(&mut self, level: u8, f: F) -> Result<R, Error>
    where
        F: FnOnce(&MlDsaKey, &mut Client) -> Result<R, Error>,
    {
        let key = MlDsaKey::generate(self, level)?;
        with_key!(key, self, f)
    }
}

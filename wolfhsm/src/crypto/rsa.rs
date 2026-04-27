use core::ffi::{c_int, c_long};

use wolfhsm_sys::{
    wolfhsm_rsa_export_public_der, wolfhsm_rsa_get_size, wolfhsm_rsa_make_key, wolfhsm_rsa_sign,
};

use crate::client::Client;
use crate::error::WolfHsmError;
use crate::key::KeyId;

/// Selects the RSA primitive operation passed to [`RsaKey::perform`].
///
/// These correspond to wolfCrypt's `RSA_*` constants.  For typical use:
/// - signing:     [`PrivateEncrypt`][RsaOperation::PrivateEncrypt]
/// - verification: [`PublicDecrypt`][RsaOperation::PublicDecrypt]
/// - encryption:  [`PublicEncrypt`][RsaOperation::PublicEncrypt]
/// - decryption:  [`PrivateDecrypt`][RsaOperation::PrivateDecrypt]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RsaOperation {
    PrivateEncrypt = 0,
    PrivateDecrypt = 1,
    PublicEncrypt  = 2,
    PublicDecrypt  = 3,
}

/// RSA key handle. Private key lives in HSM.
///
/// # Resource management
///
/// The key occupies a slot in the HSM RAM key cache for its entire lifetime.
/// You **must** call [`evict`][RsaKey::evict] when done; dropping the handle
/// without evicting silently leaks the cache slot and will eventually cause
/// `wh_Client_*` calls to fail with a "cache full" error.
pub struct RsaKey {
    pub(crate) id: KeyId,
    pub bits: u32,
}

impl RsaKey {
    /// Generate an RSA key. `bits` is key size (1024/2048/3072/4096).
    /// `e` is the public exponent (typically 65537).
    pub fn generate(client: &mut Client, bits: u32, e: u64) -> Result<Self, WolfHsmError> {
        let mut key_id: u16 = 0;
        // SAFETY: ctx_ptr is valid for the duration of this call; key_id is a
        // valid stack allocation.
        let rc = unsafe {
            wolfhsm_rsa_make_key(
                client.ctx_ptr(),
                bits as c_int,
                e as c_long,
                &mut key_id,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_rsa_make_key")?;
        Ok(RsaKey { id: KeyId(key_id), bits })
    }

    /// Evict this key from the HSM key cache.
    pub fn evict(self, client: &mut Client) -> Result<(), WolfHsmError> {
        client.key_evict(self.id)
    }

    /// Raw RSA primitive. See [`RsaOperation`] for available operations.
    ///
    /// The output buffer is sized from `self.bits` without a server round-trip.
    /// Call [`key_size_bytes`][RsaKey::key_size_bytes] if you need an authoritative
    /// server-side size.
    pub fn perform(
        &self,
        client: &mut Client,
        op: RsaOperation,
        in_buf: &[u8],
    ) -> Result<Vec<u8>, WolfHsmError> {
        let in_len = u32::try_from(in_buf.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_rsa_sign: input too large",
        })?;
        // RSA output is always exactly key_bits/8 bytes; avoid a server round-trip.
        let out_size = (self.bits / 8) as usize;
        let mut out = vec![0u8; out_size];
        let mut out_len: u32 = out_size as u32;

        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wolfhsm_rsa_sign(
                client.ctx_ptr(),
                self.id.0,
                op as c_int,
                in_buf.as_ptr(),
                in_len,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_rsa_sign")?;
        out.truncate(out_len as usize);
        Ok(out)
    }

    /// Query the key size in bytes from the server.
    pub fn key_size_bytes(&self, client: &mut Client) -> Result<u32, WolfHsmError> {
        let mut out_size: c_int = 0;
        // SAFETY: ctx_ptr is valid for the duration of this call; out_size is a
        // valid stack allocation.
        let rc = unsafe {
            wolfhsm_rsa_get_size(client.ctx_ptr(), self.id.0, &mut out_size)
        };
        WolfHsmError::check(rc, "wolfhsm_rsa_get_size")?;
        Ok(out_size as u32)
    }

    /// Export the public key as DER SubjectPublicKeyInfo.
    pub fn public_key_der(&self, client: &mut Client) -> Result<Vec<u8>, WolfHsmError> {
        // 512 bytes is sufficient for keys up to 4096-bit SPKI DER.
        let mut buf = vec![0u8; 512];
        let mut out_len: u32 = 512;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wolfhsm_rsa_export_public_der(
                client.ctx_ptr(),
                self.id.0,
                buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_rsa_export_public_der")?;
        buf.truncate(out_len as usize);
        Ok(buf)
    }
}

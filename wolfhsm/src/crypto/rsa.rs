use core::ffi::{c_int, c_long};

use wolfhsm_sys::{
    wolfhsm_rsa_export_public_der, wolfhsm_rsa_get_size, wolfhsm_rsa_make_key, wolfhsm_rsa_sign,
};

use crate::client::Client;
use crate::error::WolfHsmError;
use crate::key::{with_key, KeyId};

/// Raw RSA primitive operation passed to [`RsaKey::raw_op`].
///
/// This selects the direction of the raw modular exponentiation — it does NOT
/// apply any padding (PKCS#1, PSS, OAEP). Callers are responsible for all
/// padding and unpadding.
///
/// These correspond to wolfCrypt's `RSA_*` constants.  For typical use:
/// - signing:     [`PrivateEncrypt`][RsaRawOp::PrivateEncrypt]
/// - verification: [`PublicDecrypt`][RsaRawOp::PublicDecrypt]
/// - encryption:  [`PublicEncrypt`][RsaRawOp::PublicEncrypt]
/// - decryption:  [`PrivateDecrypt`][RsaRawOp::PrivateDecrypt]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RsaRawOp {
    PublicEncrypt = 0,  // RSA_PUBLIC_ENCRYPT
    PublicDecrypt = 1,  // RSA_PUBLIC_DECRYPT
    PrivateEncrypt = 2, // RSA_PRIVATE_ENCRYPT
    PrivateDecrypt = 3, // RSA_PRIVATE_DECRYPT
}

/// RSA key handle. Private key lives in HSM.
///
/// Keys are accessed exclusively through [`Client::with_rsa_key`], which
/// generates a key, runs the provided closure, and always evicts it on exit —
/// including when the closure returns `Err`.
pub struct RsaKey {
    pub(crate) id: KeyId,
    key_size_bytes: u32,
}

impl RsaKey {
    /// Generate an RSA key. `bits` is key size (1024/2048/3072/4096).
    /// `e` is the public exponent (typically 65537).
    pub(crate) fn generate(client: &mut Client, bits: u32, e: u64) -> Result<Self, WolfHsmError> {
        let mut key_id: u16 = 0;
        // SAFETY: ctx_ptr is valid for the duration of this call; key_id is a
        // valid stack allocation.
        let rc = unsafe {
            wolfhsm_rsa_make_key(client.ctx_ptr(), bits as c_int, e as c_long, &mut key_id)
        };
        WolfHsmError::check(rc, "wolfhsm_rsa_make_key")?;
        if key_id == 0 {
            return Err(WolfHsmError::ProtocolError {
                msg: "wolfhsm_rsa_make_key: server returned WH_KEYID_ERASED (0)",
            });
        }
        // Fetch the server-confirmed key size immediately after generation.
        let mut out_size: c_int = 0;
        // SAFETY: ctx_ptr is valid for the duration of this call; out_size is a
        // valid stack allocation.
        let rc = unsafe { wolfhsm_rsa_get_size(client.ctx_ptr(), key_id, &mut out_size) };
        WolfHsmError::check(rc, "wolfhsm_rsa_get_size")?;
        if out_size <= 0 {
            return Err(WolfHsmError::ProtocolError {
                msg: "wolfhsm_rsa_get_size: returned non-positive key size",
            });
        }
        Ok(RsaKey {
            id: KeyId(key_id),
            key_size_bytes: out_size as u32,
        })
    }

    /// Raw RSA primitive. See [`RsaRawOp`] for available operations.
    ///
    /// ⚠ This performs raw modular exponentiation (no PKCS#1 or PSS padding).
    /// For signature use, wolfHSM's `wh_Client_RsaFunction` applies no padding
    /// scheme — it is the caller's responsibility to pad the input before calling
    /// PrivateEncrypt and to verify/strip padding after calling PublicDecrypt.
    pub fn raw_op(
        &self,
        client: &mut Client,
        op: RsaRawOp,
        in_buf: &[u8],
    ) -> Result<Vec<u8>, WolfHsmError> {
        let in_len = u32::try_from(in_buf.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "input exceeds u32::MAX bytes",
        })?;
        let out_size = self.key_size_bytes as usize;
        let mut out = vec![0u8; out_size];
        let mut out_len: u32 = out_size as u32;

        // wolfhsm_rsa_sign is the wolfHSM shim for the raw RSA modular-exponentiation
        // primitive — it dispatches all four RsaRawOp variants, not just signing.
        // The name matches the underlying C shim; no separate decrypt function exists.
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

    /// Returns the server-confirmed key size in bytes, fetched at key generation time.
    pub fn key_size_bytes(&self) -> u32 {
        self.key_size_bytes
    }

    /// Export the public key as DER SubjectPublicKeyInfo.
    pub fn public_key_der(&self, client: &mut Client) -> Result<Vec<u8>, WolfHsmError> {
        // 600 bytes covers keys up to 4096-bit SPKI DER (~549 bytes for RSA-4096).
        let mut buf = vec![0u8; 600];
        let mut out_len: u32 = 600;
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

impl Drop for RsaKey {
    fn drop(&mut self) {
        if self.id != KeyId::ERASED {
            log::warn!(
                "wolfhsm: RsaKey (id={}) dropped without eviction — \
                 HSM cache slot leaked. Use with_rsa_key().",
                self.id.0
            );
        }
    }
}

impl Client {
    /// Generate an RSA key, run `f` with it, then always evict it.
    ///
    /// Guarantees the HSM cache slot is released even when `f` returns `Err`.
    /// The eviction error (if any) is surfaced only when `f` returns `Ok`; on
    /// an error path the eviction is best-effort and the original error is returned.
    pub fn with_rsa_key<F, R>(&mut self, bits: u32, e: u64, f: F) -> Result<R, WolfHsmError>
    where
        F: FnOnce(&RsaKey, &mut Client) -> Result<R, WolfHsmError>,
    {
        let key = RsaKey::generate(self, bits, e)?;
        with_key!(key, self, f)
    }
}

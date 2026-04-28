use wolfhsm_sys::{
    wolfhsm_ecc_export_public_der, wolfhsm_ecc_make_key, wolfhsm_ecc_shared_secret,
    wolfhsm_ecc_sign, wolfhsm_ecc_verify,
};

use crate::client::Client;
use crate::error::WolfHsmError;
use crate::key::{with_key, KeyId};

// ECC_SECP256R1 = 1 (wolfcrypt ecc.h enum ecc_curve_id)
const ECC_SECP256R1: core::ffi::c_int = 1;

/// ECC P-256 key handle. The private key lives in the HSM key cache.
///
/// Keys are accessed exclusively through [`Client::with_ecc_p256_key`], which
/// generates a key, runs the provided closure, and always evicts it on exit —
/// including when the closure returns `Err`.
pub struct EccP256Key {
    pub(crate) id: KeyId,
}

impl EccP256Key {
    /// Generate an ephemeral P-256 key on the HSM (cached, not committed to NVM).
    pub(crate) fn generate(client: &mut Client) -> Result<Self, WolfHsmError> {
        let mut key_id: u16 = KeyId::ERASED.0;
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wolfhsm_ecc_make_key(client.ctx_ptr(), ECC_SECP256R1, &mut key_id) };
        WolfHsmError::check(rc, "wolfhsm_ecc_make_key")?;
        if key_id == KeyId::ERASED.0 {
            return Err(WolfHsmError::ProtocolError {
                msg: "wolfhsm_ecc_make_key: server returned WH_KEYID_ERASED (0)",
            });
        }
        Ok(EccP256Key { id: KeyId(key_id) })
    }

    /// Sign a pre-hashed digest (≤ 32 bytes for P-256 SHA-256).
    /// Returns DER-encoded ECDSA signature (up to 72 bytes for P-256).
    pub fn sign_digest(&self, client: &mut Client, digest: &[u8]) -> Result<Vec<u8>, WolfHsmError> {
        let hash_len = u16::try_from(digest.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "digest exceeds u16::MAX bytes",
        })?;
        let mut buf = Vec::<u8>::with_capacity(128);
        let mut sig_len: u16 = 128;
        // SAFETY: buf has capacity 128; wolfhsm_ecc_sign writes at most sig_len bytes.
        let rc = unsafe {
            wolfhsm_ecc_sign(
                client.ctx_ptr(),
                self.id.0,
                digest.as_ptr(),
                hash_len,
                buf.as_mut_ptr(),
                &mut sig_len,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_ecc_sign")?;
        // SAFETY: wolfhsm_ecc_sign succeeded and initialized exactly sig_len bytes.
        // sig_len <= 128 (the value we passed as the buffer capacity).
        unsafe { buf.set_len(sig_len as usize) };
        Ok(buf)
    }

    /// Verify a DER-encoded ECDSA signature against a pre-hashed digest.
    pub fn verify_digest(
        &self,
        client: &mut Client,
        digest: &[u8],
        sig: &[u8],
    ) -> Result<(), WolfHsmError> {
        let hash_len = u16::try_from(digest.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "digest exceeds u16::MAX bytes",
        })?;
        let sig_len = u16::try_from(sig.len()).map_err(|_| WolfHsmError::BadArgs {
            msg: "signature exceeds u16::MAX bytes",
        })?;
        let mut result: core::ffi::c_int = 0;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wolfhsm_ecc_verify(
                client.ctx_ptr(),
                self.id.0,
                digest.as_ptr(),
                hash_len,
                sig.as_ptr(),
                sig_len,
                &mut result,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_ecc_verify")?;
        if result != 1 {
            return Err(WolfHsmError::InvalidSignature);
        }
        Ok(())
    }

    /// Export the public key as DER SubjectPublicKeyInfo.
    pub fn public_key_der(&self, client: &mut Client) -> Result<Vec<u8>, WolfHsmError> {
        let mut buf = Vec::<u8>::with_capacity(91);
        let mut out_len: u32 = 91;
        // SAFETY: buf has capacity 91; wolfhsm_ecc_export_public_der writes at most out_len bytes.
        let rc = unsafe {
            wolfhsm_ecc_export_public_der(
                client.ctx_ptr(),
                self.id.0,
                buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_ecc_export_public_der")?;
        // SAFETY: wolfhsm_ecc_export_public_der succeeded and initialized exactly out_len bytes.
        // out_len <= 91 (the value we passed as the buffer capacity).
        unsafe { buf.set_len(out_len as usize) };
        Ok(buf)
    }

    /// ECDH: compute shared secret with a peer DER SubjectPublicKeyInfo.
    ///
    /// `peer_public_der` must be the 91-byte DER `SubjectPublicKeyInfo` for a
    /// P-256 public key — the same format returned by [`public_key_der`][EccP256Key::public_key_der].
    /// Raw uncompressed EC points (65-byte `04||x||y`) are not accepted.
    pub fn ecdh(
        &self,
        client: &mut Client,
        peer_public_der: &[u8],
    ) -> Result<Vec<u8>, WolfHsmError> {
        let peer_der_len =
            u32::try_from(peer_public_der.len()).map_err(|_| WolfHsmError::BadArgs {
                msg: "peer public key exceeds u32::MAX bytes",
            })?;
        let mut buf = Vec::<u8>::with_capacity(32);
        let mut out_len: u32 = 32;
        // SAFETY: buf has capacity 32; wolfhsm_ecc_shared_secret writes at most out_len bytes.
        let rc = unsafe {
            wolfhsm_ecc_shared_secret(
                client.ctx_ptr(),
                self.id.0,
                peer_public_der.as_ptr(),
                peer_der_len,
                buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_ecc_shared_secret")?;
        // SAFETY: wolfhsm_ecc_shared_secret succeeded and initialized exactly out_len bytes.
        // out_len <= 32 (the value we passed as the buffer capacity).
        unsafe { buf.set_len(out_len as usize) };
        Ok(buf)
    }
}

impl Drop for EccP256Key {
    fn drop(&mut self) {
        if self.id != KeyId::ERASED {
            log::warn!(
                "wolfhsm: EccP256Key (id={}) dropped without eviction — \
                 HSM cache slot leaked. Use with_ecc_p256_key().",
                self.id.0
            );
        }
    }
}

impl Client {
    /// Generate an ephemeral P-256 key, run `f`, then always evict.
    ///
    /// Guarantees the HSM cache slot is released even when `f` returns `Err`.
    pub fn with_ecc_p256_key<F, R>(&mut self, f: F) -> Result<R, WolfHsmError>
    where
        F: FnOnce(&EccP256Key, &mut Client) -> Result<R, WolfHsmError>,
    {
        let key = EccP256Key::generate(self)?;
        with_key!(key, self, f)
    }
}

use wolfhsm_sys::{
    wolfhsm_ecc_export_public_der, wolfhsm_ecc_make_key, wolfhsm_ecc_shared_secret,
    wolfhsm_ecc_sign, wolfhsm_ecc_verify,
};

use crate::client::Client;
use crate::error::WolfHsmError;
use crate::key::KeyId;

// ECC_SECP256R1 = 1 (wolfcrypt ecc.h enum ecc_curve_id)
const ECC_SECP256R1: core::ffi::c_int = 1;

/// ECC P-256 key handle. The private key lives in the HSM key cache.
pub struct EccP256Key {
    pub(crate) id: KeyId,
}

impl EccP256Key {
    /// Generate an ephemeral P-256 key on the HSM (cached, not committed to NVM).
    pub fn generate(client: &mut Client) -> Result<Self, WolfHsmError> {
        let mut key_id: u16 = KeyId::ERASED.0;
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wolfhsm_ecc_make_key(client.ctx_ptr(), ECC_SECP256R1, &mut key_id) };
        WolfHsmError::check(rc, "wolfhsm_ecc_make_key")?;
        Ok(EccP256Key { id: KeyId(key_id) })
    }

    /// Evict this key from the HSM key cache.
    pub fn evict(self, client: &mut Client) -> Result<(), WolfHsmError> {
        client.key_evict(self.id)
    }

    /// Sign a pre-hashed digest (≤ 32 bytes for P-256 SHA-256).
    /// Returns DER-encoded ECDSA signature (up to 72 bytes for P-256).
    pub fn sign_digest(
        &self,
        client: &mut Client,
        digest: &[u8],
    ) -> Result<Vec<u8>, WolfHsmError> {
        let hash_len = u16::try_from(digest.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_ecc_sign: digest too large",
        })?;
        let mut buf = [0u8; 128];
        let mut sig_len: u16 = 128;
        // SAFETY: all pointers are valid stack/heap allocations for this call.
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
        Ok(buf[..sig_len as usize].to_vec())
    }

    /// Verify a DER-encoded ECDSA signature against a pre-hashed digest.
    pub fn verify_digest(
        &self,
        client: &mut Client,
        digest: &[u8],
        sig: &[u8],
    ) -> Result<(), WolfHsmError> {
        let hash_len = u16::try_from(digest.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_ecc_verify: digest too large",
        })?;
        let sig_len = u16::try_from(sig.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_ecc_verify: signature too large",
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
            return Err(WolfHsmError::Ffi {
                code: -1,
                func: "ecc_verify: invalid signature",
            });
        }
        Ok(())
    }

    /// Export the public key as DER SubjectPublicKeyInfo.
    pub fn public_key_der(&self, client: &mut Client) -> Result<Vec<u8>, WolfHsmError> {
        let mut buf = [0u8; 91];
        let mut out_len: u32 = 91;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wolfhsm_ecc_export_public_der(
                client.ctx_ptr(),
                self.id.0,
                buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        WolfHsmError::check(rc, "wolfhsm_ecc_export_public_der")?;
        Ok(buf[..out_len as usize].to_vec())
    }

    /// ECDH: compute shared secret with a peer DER SubjectPublicKeyInfo.
    pub fn ecdh(
        &self,
        client: &mut Client,
        peer_public_der: &[u8],
    ) -> Result<Vec<u8>, WolfHsmError> {
        let peer_der_len = u32::try_from(peer_public_der.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "wolfhsm_ecc_shared_secret: peer key too large",
        })?;
        let mut buf = [0u8; 32];
        let mut out_len: u32 = 32;
        // SAFETY: all pointers are valid for the duration of this call.
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
        Ok(buf[..out_len as usize].to_vec())
    }
}

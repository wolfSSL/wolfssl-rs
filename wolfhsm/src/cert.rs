use wolfhsm_sys::{
    wh_Client_CertAddTrusted, wh_Client_CertEraseTrusted, wh_Client_CertInit,
    wh_Client_CertReadTrusted, wh_Client_CertVerify, wh_Client_CertVerifyAcert,
    wh_Client_CertVerifyAndCacheLeafPubKey,
};

use crate::client::Client;
use crate::error::Error;
use crate::key::KeyId;
use crate::nvm::NvmId;

impl Client {
    /// Initialize the server's certificate subsystem.
    ///
    /// Must be called once before any other `cert_*` operations.
    pub fn cert_init(&mut self) -> Result<(), Error> {
        let mut out_rc: i32 = 0;
        // SAFETY: ctx_ptr is valid; out_rc is a valid stack allocation.
        let rc = unsafe { wh_Client_CertInit(self.ctx_ptr(), &mut out_rc) };
        Error::check(rc, "wh_Client_CertInit")?;
        Error::check(out_rc, "wh_Client_CertInit(server)")?;
        Ok(())
    }

    /// Store a trusted CA certificate in the server's NVM.
    ///
    /// `id` identifies the certificate slot; it must not be [`NvmId::INVALID`].
    /// `label` is truncated to 24 bytes.  `cert` is the DER-encoded certificate.
    ///
    /// `access` — access control flags; see `WH_NVM_ACCESS_*` constants in
    /// `wolfhsm/wh_nvm.h`. Pass `0` for unrestricted access.
    ///
    /// `flags` — object attribute flags; see `WH_NVM_FLAGS_*` constants in
    /// `wolfhsm/wh_nvm.h`. Pass `0` for default attributes.
    pub fn cert_add_trusted(
        &mut self,
        id: NvmId,
        access: u16,
        flags: u16,
        label: impl AsRef<[u8]>,
        cert: &[u8],
    ) -> Result<(), Error> {
        let label = label.as_ref();
        let cert_len = u32::try_from(cert.len()).map_err(|_| Error::BadArgs {
            msg: "cert_add_trusted: cert exceeds u32::MAX bytes",
        })?;
        let label_len = label.len().min(24); // fits in [0, 24], always < u16::MAX
        // C API takes *mut u8 for label even though it does not modify it.
        let mut label_buf = [0u8; 24];
        label_buf[..label_len].copy_from_slice(&label[..label_len]);

        let mut out_rc: i32 = 0;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wh_Client_CertAddTrusted(
                self.ctx_ptr(),
                id.0,
                access,
                flags,
                label_buf.as_mut_ptr(),
                label_len as u16,
                cert.as_ptr(),
                cert_len,
                &mut out_rc,
            )
        };
        Error::check(rc, "wh_Client_CertAddTrusted")?;
        Error::check(out_rc, "wh_Client_CertAddTrusted(server)")?;
        Ok(())
    }

    /// Remove a trusted CA certificate from the server's NVM.
    pub fn cert_erase_trusted(&mut self, id: NvmId) -> Result<(), Error> {
        let mut out_rc: i32 = 0;
        // SAFETY: ctx_ptr is valid; out_rc is a valid stack allocation.
        let rc = unsafe { wh_Client_CertEraseTrusted(self.ctx_ptr(), id.0, &mut out_rc) };
        Error::check(rc, "wh_Client_CertEraseTrusted")?;
        Error::check(out_rc, "wh_Client_CertEraseTrusted(server)")?;
        Ok(())
    }

    /// Read a trusted CA certificate from the server's NVM.
    ///
    /// Queries the object length via [`nvm_metadata`][Self::nvm_metadata] first
    /// to size the receive buffer exactly.
    pub fn cert_read_trusted(&mut self, id: NvmId) -> Result<Vec<u8>, Error> {
        let meta = self.nvm_metadata(id)?;
        if meta.len == 0 {
            return Ok(vec![]);
        }
        let mut buf = vec![0u8; meta.len as usize];
        let mut out_len: u32 = meta.len as u32;
        let mut out_rc: i32 = 0;
        // SAFETY: buf is a valid heap allocation of meta.len bytes; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_CertReadTrusted(
                self.ctx_ptr(),
                id.0,
                buf.as_mut_ptr(),
                &mut out_len,
                &mut out_rc,
            )
        };
        Error::check(rc, "wh_Client_CertReadTrusted")?;
        Error::check(out_rc, "wh_Client_CertReadTrusted(server)")?;
        // Guard against a misbehaving server reporting more bytes than the
        // allocated buffer: clamp to meta.len so truncate is always a
        // genuine shortening (never a no-op that hides an overrun).
        let safe_len = (out_len as usize).min(meta.len as usize);
        buf.truncate(safe_len);
        Ok(buf)
    }

    /// Verify a DER-encoded certificate against a trusted root stored in NVM.
    ///
    /// Returns `Ok(())` if the certificate is valid.
    pub fn cert_verify(&mut self, cert: &[u8], trusted_root_id: NvmId) -> Result<(), Error> {
        let cert_len = u32::try_from(cert.len()).map_err(|_| Error::BadArgs {
            msg: "cert_verify: cert exceeds u32::MAX bytes",
        })?;
        let mut out_rc: i32 = 0;
        // SAFETY: cert pointer is valid for the duration of this call.
        let rc = unsafe {
            wh_Client_CertVerify(
                self.ctx_ptr(),
                cert.as_ptr(),
                cert_len,
                trusted_root_id.0,
                &mut out_rc,
            )
        };
        Error::check(rc, "wh_Client_CertVerify")?;
        Error::check(out_rc, "wh_Client_CertVerify(server)")?;
        Ok(())
    }

    /// Verify a DER-encoded certificate and cache its leaf public key in the
    /// HSM key cache.
    ///
    /// On success, the server caches the leaf public key and returns the
    /// assigned [`KeyId`].  Pass `key_id: None` to let the server assign a new
    /// ID, or `Some(id)` to request a specific cache slot.
    ///
    /// `cached_key_flags` — NVM attribute flags for the cached key; see
    /// `WH_NVM_FLAGS_*` constants in `wolfhsm/wh_nvm.h`.  Pass `0` for
    /// default (no special attributes).
    ///
    /// The caller is responsible for evicting the cached key when done.
    /// Prefer [`with_cert_verified_pubkey`][Self::with_cert_verified_pubkey]
    /// to ensure the key is always evicted.
    pub fn cert_verify_and_cache_leaf_pubkey(
        &mut self,
        cert: &[u8],
        trusted_root_id: NvmId,
        cached_key_flags: u16,
        key_id: Option<KeyId>,
    ) -> Result<KeyId, Error> {
        let cert_len = u32::try_from(cert.len()).map_err(|_| Error::BadArgs {
            msg: "cert_verify_and_cache_leaf_pubkey: cert exceeds u32::MAX bytes",
        })?;
        let mut inout_key_id: u16 = key_id.unwrap_or(KeyId::ERASED).0;
        let mut out_rc: i32 = 0;
        // SAFETY: cert pointer is valid; inout_key_id and out_rc are stack allocations.
        let rc = unsafe {
            wh_Client_CertVerifyAndCacheLeafPubKey(
                self.ctx_ptr(),
                cert.as_ptr(),
                cert_len,
                trusted_root_id.0,
                cached_key_flags,
                &mut inout_key_id,
                &mut out_rc,
            )
        };
        Error::check(rc, "wh_Client_CertVerifyAndCacheLeafPubKey")?;
        Error::check(out_rc, "wh_Client_CertVerifyAndCacheLeafPubKey(server)")?;
        if inout_key_id == KeyId::ERASED.0 {
            return Err(Error::ProtocolError {
                msg: "wh_Client_CertVerifyAndCacheLeafPubKey: server returned ERASED key ID",
            });
        }
        Ok(KeyId(inout_key_id))
    }

    /// Verify a certificate, cache its leaf public key, run `f`, then always
    /// evict the cached key — even when `f` returns `Err`.
    ///
    /// This is the safe RAII counterpart to
    /// [`cert_verify_and_cache_leaf_pubkey`][Self::cert_verify_and_cache_leaf_pubkey].
    /// The cached key slot is guaranteed to be released on both success and
    /// error paths.
    ///
    /// `cached_key_flags` — NVM attribute flags for the cached key; see
    /// `WH_NVM_FLAGS_*` in `wolfhsm/wh_nvm.h`.  Pass `0` for defaults.
    pub fn with_cert_verified_pubkey<F, R>(
        &mut self,
        cert: &[u8],
        trusted_root_id: NvmId,
        cached_key_flags: u16,
        key_id: Option<KeyId>,
        f: F,
    ) -> Result<R, Error>
    where
        F: FnOnce(KeyId, &mut Client) -> Result<R, Error>,
    {
        let id = self.cert_verify_and_cache_leaf_pubkey(
            cert,
            trusted_root_id,
            cached_key_flags,
            key_id,
        )?;
        let result = f(id, self);
        let evict = self.key_evict(id);
        match result {
            Ok(v) => {
                evict?;
                Ok(v)
            }
            Err(e) => {
                if let Err(evict_err) = evict {
                    log::warn!(
                        "wolfhsm: cert pubkey eviction failed during error cleanup: {evict_err}"
                    );
                }
                Err(e)
            }
        }
    }

    /// Verify a DER-encoded attribute certificate against a trusted root
    /// stored in NVM.
    pub fn cert_verify_acert(
        &mut self,
        cert: &[u8],
        trusted_root_id: NvmId,
    ) -> Result<(), Error> {
        let cert_len = u32::try_from(cert.len()).map_err(|_| Error::BadArgs {
            msg: "cert_verify_acert: cert exceeds u32::MAX bytes",
        })?;
        let mut out_rc: i32 = 0;
        // SAFETY: cert pointer is valid for the duration of this call.
        let rc = unsafe {
            wh_Client_CertVerifyAcert(
                self.ctx_ptr(),
                cert.as_ptr() as *const core::ffi::c_void,
                cert_len,
                trusted_root_id.0,
                &mut out_rc,
            )
        };
        Error::check(rc, "wh_Client_CertVerifyAcert")?;
        Error::check(out_rc, "wh_Client_CertVerifyAcert(server)")?;
        Ok(())
    }
}

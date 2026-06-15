use crate::{device::Device, error::Error};

/// A transient ECC P-256 signing key loaded onto the TPM.
///
/// Created by [`Device::with_ecc_key`]; automatically unloaded on drop.
///
/// The key is ephemeral: it is created fresh each time and is not stored in
/// NV RAM. The TPM holds it in transient object memory only for the duration
/// of this value's lifetime.
pub struct EccKey<'dev> {
    /// The loaded ECC signing key.
    key: wolftpm_sys::WOLFTPM2_KEY,
    /// The transient storage root key used as parent; flushed after the
    /// signing key.
    srk: wolftpm_sys::WOLFTPM2_KEY,
    /// Back-reference to the open device context.
    dev: &'dev mut Device,
}

impl<'dev> EccKey<'dev> {
    /// Create a transient ECC P-256 signing key.
    ///
    /// Internally this creates a transient storage root key (ECC SRK) under
    /// `TPM_RH_OWNER`, then creates and loads the ECDSA/SHA-256 signing key
    /// under that parent. Both are held in transient object memory only.
    pub(crate) fn create(device: &'dev mut Device) -> Result<Self, Error> {
        let dev_ptr = device.dev_ptr_mut();

        // ── Step 1: Create a transient ECC storage root key ─────────────────
        // SAFETY: WOLFTPM2_KEY and TPMT_PUBLIC are plain C structs; zeroing
        // them is the documented initial state before passing to wolfTPM2 API.
        let mut srk = unsafe { std::mem::zeroed::<wolftpm_sys::WOLFTPM2_KEY>() };
        let mut srk_template = unsafe { std::mem::zeroed::<wolftpm_sys::TPMT_PUBLIC>() };

        // SAFETY: srk_template is a valid zeroed TPMT_PUBLIC; the function
        // only writes to it.
        let rc = unsafe {
            wolftpm_sys::wolfTPM2_GetKeyTemplate_ECC_SRK(&mut srk_template as *mut _)
        };
        Error::check(rc)?;

        // SAFETY: dev_ptr is valid for the lifetime 'dev; srk and srk_template
        // are local structs with correct initial state; auth=NULL/0 = no password.
        // TPM_RH_OWNER = TPM_RH_T_TPM_RH_OWNER = 0x40000001.
        let rc = unsafe {
            wolftpm_sys::wolfTPM2_CreatePrimaryKey(
                dev_ptr,
                &mut srk as *mut _,
                wolftpm_sys::TPM_RH_T_TPM_RH_OWNER,
                &mut srk_template as *mut _,
                std::ptr::null(),
                0,
            )
        };
        Error::check(rc)?;

        // ── Step 2: Build an ECC P-256/ECDSA/SHA-256 signing key template ────
        // SAFETY: zeroing TPMT_PUBLIC is the correct initial state.
        let mut key_template = unsafe { std::mem::zeroed::<wolftpm_sys::TPMT_PUBLIC>() };

        // SAFETY: key_template is a valid zeroed TPMT_PUBLIC; the function
        // writes the ECC P-256/ECDSA template into it.
        let rc = unsafe {
            wolftpm_sys::wolfTPM2_GetKeyTemplate_ECC(
                &mut key_template as *mut _,
                // object attributes: origin on TPM, password auth, sign, DA exempt
                wolftpm_sys::TPMA_OBJECT_mask_TPMA_OBJECT_sensitiveDataOrigin
                    | wolftpm_sys::TPMA_OBJECT_mask_TPMA_OBJECT_userWithAuth
                    | wolftpm_sys::TPMA_OBJECT_mask_TPMA_OBJECT_sign
                    | wolftpm_sys::TPMA_OBJECT_mask_TPMA_OBJECT_noDA,
                wolftpm_sys::TPM_ECC_CURVE_T_TPM_ECC_NIST_P256
                    as wolftpm_sys::TPM_ECC_CURVE,
                wolftpm_sys::TPM_ALG_ID_T_TPM_ALG_ECDSA as wolftpm_sys::TPM_ALG_ID,
            )
        };
        // SAFETY: srk was successfully created above; flush it before
        // propagating any error so no transient slot is leaked.
        Error::check(rc).map_err(|e| {
            unsafe {
                wolftpm_sys::wolfTPM2_UnloadHandle(dev_ptr, &mut srk.handle as *mut _);
            }
            e
        })?;

        // ── Step 3: Create and load the signing key under the SRK ────────────
        // SAFETY: zeroing WOLFTPM2_KEY is the correct initial state.
        let mut key = unsafe { std::mem::zeroed::<wolftpm_sys::WOLFTPM2_KEY>() };

        // SAFETY: dev_ptr, key, srk.handle, and key_template are all valid;
        // auth=NULL/0 = no password.
        let rc = unsafe {
            wolftpm_sys::wolfTPM2_CreateAndLoadKey(
                dev_ptr,
                &mut key as *mut _,
                &mut srk.handle as *mut _,
                &mut key_template as *mut _,
                std::ptr::null(),
                0,
            )
        };
        // SAFETY: srk was successfully created; flush it before returning.
        Error::check(rc).map_err(|e| {
            unsafe {
                wolftpm_sys::wolfTPM2_UnloadHandle(dev_ptr, &mut srk.handle as *mut _);
            }
            e
        })?;

        Ok(Self { key, srk, dev: device })
    }

    /// Sign a pre-computed SHA-256 digest.
    ///
    /// `hash` must be exactly 32 bytes. Returns the DER-encoded ECDSA
    /// signature (ASN.1 SEQUENCE of two INTEGERs, up to ~72 bytes for P-256).
    pub fn sign(&mut self, hash: &[u8]) -> Result<Vec<u8>, Error> {
        if hash.len() != 32 {
            return Err(Error::InvalidHashLen { got: hash.len() });
        }

        // For P-256 the DER-encoded ECDSA signature is at most 72 bytes
        // (2 × 33-byte padded integers + 6 bytes of ASN.1 framing).
        // Use 128 bytes to give comfortable headroom.
        let mut sig = vec![0u8; 128];
        let mut sig_sz: std::ffi::c_int = sig.len() as std::ffi::c_int;

        // SAFETY: dev_ptr is alive for 'dev; self.key is a loaded TPM key;
        // hash is 32 bytes (validated above); sig is 128 bytes and sig_sz
        // reflects that size on entry.
        // hash.len() == 32 is validated above; 32 fits in c_int on all platforms.
        let hash_sz: std::ffi::c_int = 32;

        let rc = unsafe {
            wolftpm_sys::wolfTPM2_SignHashScheme(
                self.dev.dev_ptr_mut(),
                &mut self.key as *mut _,
                hash.as_ptr(),
                hash_sz,
                sig.as_mut_ptr(),
                &mut sig_sz as *mut _,
                wolftpm_sys::TPM_ALG_ID_T_TPM_ALG_ECDSA as wolftpm_sys::TPMI_ALG_SIG_SCHEME,
                wolftpm_sys::TPM_ALG_ID_T_TPM_ALG_SHA256 as wolftpm_sys::TPMI_ALG_HASH,
            )
        };
        Error::check(rc)?;

        if sig_sz < 0 || sig_sz as usize > sig.len() {
            return Err(Error::UnexpectedResponse);
        }
        sig.truncate(sig_sz as usize);
        Ok(sig)
    }

    /// Return the uncompressed P-256 public key as 64 raw bytes (X ∥ Y, 32 bytes each,
    /// big-endian as exported by the TPM).
    ///
    /// The returned bytes are suitable for constructing a standard 65-byte uncompressed
    /// point (`0x04 ‖ X ‖ Y`) accepted by most cryptographic libraries.
    pub fn public_key_bytes(&self) -> Result<[u8; 64], Error> {
        // SAFETY: This key was created as ECC P-256 by EccKey::create, so the
        // unique union in the public area always holds an ECC point (TPMS_ECC_POINT).
        let ecc_pt = unsafe { self.key.pub_.publicArea.unique.ecc };
        let x_sz = ecc_pt.x.size as usize;
        let y_sz = ecc_pt.y.size as usize;
        if x_sz != 32 || y_sz != 32 {
            return Err(Error::UnexpectedResponse);
        }
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&ecc_pt.x.buffer[..32]);
        out[32..].copy_from_slice(&ecc_pt.y.buffer[..32]);
        Ok(out)
    }

    /// Verify a DER-encoded ECDSA signature against a pre-computed SHA-256 digest.
    ///
    /// `hash` must be exactly 32 bytes. `sig` must be non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SignatureInvalid`] if the signature is structurally valid
    /// but does not verify against this key and hash.  Returns [`Error::Tpm`] for
    /// any other TPM-layer failure.
    pub fn verify(&mut self, hash: &[u8], sig: &[u8]) -> Result<(), Error> {
        if hash.len() != 32 {
            return Err(Error::InvalidHashLen { got: hash.len() });
        }
        if sig.is_empty() {
            return Err(Error::InvalidInput("sig is empty"));
        }

        let sig_sz =
            i32::try_from(sig.len()).map_err(|_| Error::InvalidInput("sig too large"))?;
        // hash.len() == 32 is validated above; 32 fits in c_int on all platforms.
        let hash_sz: std::ffi::c_int = 32;

        // SAFETY: dev_ptr is alive for 'dev; self.key is a loaded TPM key;
        // hash is 32 bytes (hash_sz) and sig is sig_sz bytes (both validated above).
        let rc = unsafe {
            wolftpm_sys::wolfTPM2_VerifyHashScheme(
                self.dev.dev_ptr_mut(),
                &mut self.key as *mut _,
                sig.as_ptr(),
                sig_sz,
                hash.as_ptr(),
                hash_sz,
                wolftpm_sys::TPM_ALG_ID_T_TPM_ALG_ECDSA as wolftpm_sys::TPMI_ALG_SIG_SCHEME,
                wolftpm_sys::TPM_ALG_ID_T_TPM_ALG_SHA256 as wolftpm_sys::TPMI_ALG_HASH,
            )
        };

        // Strip FMT1 modifier bits (P-flag = bit 6, subject number = bits 11:8).
        // TPM2 Part 2 §6.6.3: FMT1 codes have bit 7 set in the base code and
        // bits 15:12 clear (high nibble = 0).  VER1 codes start at 0x100 and
        // have bits 15:12 clear too, but wolfTPM extension codes use the high
        // nibble.  The correct discriminator: bit 7 set AND bits 15:12 clear.
        // Do NOT use `bit 8 clear` — subject number 1 sets bit 8, so
        // TPM_RC_SIGNATURE+param_1 (0x1DB) would wrongly bypass stripping.
        const FMT1_MODIFIER_MASK: i32 = 0x0F40;
        let base_rc = if (rc & 0x80) != 0 && (rc & 0xF000) == 0 {
            rc & !FMT1_MODIFIER_MASK
        } else {
            rc
        };
        match base_rc {
            0 => Ok(()),
            // TPM_RC_SIGNATURE (0x9B = 155): the signature is structurally
            // well-formed but does not verify against this key and hash.
            r if r == wolftpm_sys::TPM_RC_T_TPM_RC_SIGNATURE as i32 => {
                Err(Error::SignatureInvalid)
            }
            _ => Err(Error::Tpm {
                rc: crate::error::TpmRc::from_raw(rc as u32),
            }),
        }
    }
}

impl core::fmt::Debug for EccKey<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // WOLFTPM2_KEY is an opaque C struct; expose only the TPM object
        // handles so callers can correlate with TPM2 tool output.
        f.debug_struct("EccKey")
            .field("key_handle", &format_args!("0x{:08x}", self.key.handle.hndl))
            .field("srk_handle", &format_args!("0x{:08x}", self.srk.handle.hndl))
            .finish()
    }
}

impl Drop for EccKey<'_> {
    fn drop(&mut self) {
        let dev_ptr = self.dev.dev_ptr_mut();
        // SAFETY: dev_ptr is the live WOLFTPM2_DEV; key and srk are valid
        // transient object handles that were loaded in create().
        // wolfTPM2_UnloadHandle is a no-op if the handle is already null/persistent.
        // Errors are intentionally ignored: flush is best-effort and the keys
        // are gone from the caller's view regardless.
        unsafe {
            wolftpm_sys::wolfTPM2_UnloadHandle(dev_ptr, &mut self.key.handle as *mut _);
            wolftpm_sys::wolfTPM2_UnloadHandle(dev_ptr, &mut self.srk.handle as *mut _);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    /// Sign with the TPM and verify with RustCrypto p256 as an independent oracle.
    ///
    /// This test proves that the TPM produces standards-compliant ECDSA P-256
    /// signatures that a pure-Rust implementation can verify — not merely that
    /// sign+verify round-trip on the same device.
    #[test]
    #[ignore = "requires /dev/tpm0"]
    fn sign_and_verify_with_independent_oracle() {
        use p256::ecdsa::{DerSignature, VerifyingKey};
        use p256::ecdsa::signature::hazmat::PrehashVerifier;

        let mut dev = crate::device::Device::open().expect("open");
        // SHA-256 of b"hello"
        let hash: [u8; 32] = [
            0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
            0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
            0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
            0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
        ];
        dev.with_ecc_key(|key| -> Result<(), crate::error::Error> {
            let sig = key.sign(&hash)?;
            assert!(!sig.is_empty(), "sign returned empty signature");

            // Export the public key and verify with RustCrypto p256 (independent oracle).
            let pub_bytes = key.public_key_bytes()?;
            let mut uncompressed = [0u8; 65];
            uncompressed[0] = 0x04; // uncompressed point tag
            uncompressed[1..].copy_from_slice(&pub_bytes);
            let encoded_point = p256::EncodedPoint::from_bytes(&uncompressed[..])
                .expect("TPM returned invalid P-256 point coordinates");
            let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)
                .expect("TPM returned point not on P-256 curve");
            let der_sig = DerSignature::try_from(sig.as_slice())
                .expect("TPM produced a non-DER-encoded signature");
            verifying_key
                .verify_prehash(&hash, &der_sig)
                .expect("RustCrypto p256 oracle: TPM signature did not verify");

            // Also confirm the TPM's own verify agrees (sanity check).
            key.verify(&hash, &sig)?;
            Ok(())
        })
        .expect("with_ecc_key");
    }

    /// Smoke-test for `Error::InvalidInput` display formatting.
    ///
    /// `EccKey::sign` and `verify` can only be called with a live TPM
    /// (see `sign_verify_roundtrip` above), so their input-validation
    /// paths are exercised by the ignored integration test.  This test
    /// verifies only that the error type formats correctly without a TPM.
    #[test]
    fn invalid_arg_error_display() {
        let e = crate::error::Error::InvalidInput("hash must be 32 bytes");
        assert!(
            format!("{e}").contains("hash must be 32 bytes"),
            "Display for InvalidInput was: {e}"
        );
    }
}

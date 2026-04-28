use wolfhsm_sys::{
    wh_Client_SheDecCbc, wh_Client_SheDecEcb, wh_Client_SheEncCbc, wh_Client_SheEncEcb,
    wh_Client_SheExportRamKey, wh_Client_SheExtendSeed, wh_Client_SheGenerateMac,
    wh_Client_SheGetStatus, wh_Client_SheInitRnd, wh_Client_SheLoadKey, wh_Client_SheLoadPlainKey,
    wh_Client_ShePreProgramKey, wh_Client_SheRnd, wh_Client_SheSecureBoot, wh_Client_SheSetUid,
    wh_Client_SheVerifyMac,
};

use crate::client::Client;
use crate::error::Error;
use crate::nvm::NvmId;

/// A SHE (Secure Hardware Extension) key slot identifier.
///
/// Corresponds to the `KEY_ID` field in the SHE AutoSAR specification
/// (AUTOSAR_SWS_CryptoServiceManager).  The SHE spec mandates slots
/// `SECRET_KEY` (0x00) through `RAM_KEY` (0x0E); values above 0x0E are
/// implementation-defined extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SheKeyId(pub u8);

impl SheKeyId {
    /// `SECRET_KEY` (slot 0x00) — the SHE master secret (write-protected).
    pub const SECRET_KEY: Self = SheKeyId(0x00);
    /// `MASTER_ECU_KEY` (slot 0x01) — used in CMD_LOAD_KEY derivation.
    pub const MASTER_ECU_KEY: Self = SheKeyId(0x01);
    /// `BOOT_MAC_KEY` (slot 0x02) — used for secure-boot MAC generation/verification.
    pub const BOOT_MAC_KEY: Self = SheKeyId(0x02);
    /// `BOOT_MAC` (slot 0x03) — stored boot MAC result.
    pub const BOOT_MAC: Self = SheKeyId(0x03);
    /// User key slot 1 (slot 0x04).
    pub const KEY_1: Self = SheKeyId(0x04);
    /// User key slot 2 (slot 0x05).
    pub const KEY_2: Self = SheKeyId(0x05);
    /// User key slot 3 (slot 0x06).
    pub const KEY_3: Self = SheKeyId(0x06);
    /// User key slot 4 (slot 0x07).
    pub const KEY_4: Self = SheKeyId(0x07);
    /// User key slot 5 (slot 0x08).
    pub const KEY_5: Self = SheKeyId(0x08);
    /// User key slot 6 (slot 0x09).
    pub const KEY_6: Self = SheKeyId(0x09);
    /// User key slot 7 (slot 0x0A).
    pub const KEY_7: Self = SheKeyId(0x0A);
    /// User key slot 8 (slot 0x0B).
    pub const KEY_8: Self = SheKeyId(0x0B);
    /// User key slot 9 (slot 0x0C).
    pub const KEY_9: Self = SheKeyId(0x0C);
    /// User key slot 10 (slot 0x0D).
    pub const KEY_10: Self = SheKeyId(0x0D);
    /// `RAM_KEY` (slot 0x0E) — volatile, non-persistent key slot.
    pub const RAM_KEY: Self = SheKeyId(0x0E);
}

impl From<u8> for SheKeyId {
    fn from(v: u8) -> Self {
        SheKeyId(v)
    }
}

impl From<SheKeyId> for u8 {
    fn from(k: SheKeyId) -> Self {
        k.0
    }
}

// Fixed sizes from the SHE AutoSAR specification (wh_she_common.h).
/// SHE symmetric key size in bytes (AES-128).
pub const SHE_KEY_SZ: usize = 16;
/// SHE unique identifier size in bytes.
pub const SHE_UID_SZ: usize = 15;
/// SHE key-loading protocol message M1 size in bytes.
pub const SHE_M1_SZ: usize = 16;
/// SHE key-loading protocol message M2 size in bytes.
pub const SHE_M2_SZ: usize = 32;
/// SHE key-loading protocol message M3 size in bytes.
pub const SHE_M3_SZ: usize = 16;
/// SHE key-loading protocol message M4 size in bytes.
pub const SHE_M4_SZ: usize = 32;
/// SHE key-loading protocol message M5 size in bytes.
pub const SHE_M5_SZ: usize = 16;

impl Client {
    /// Pre-program a key into the SHE NVM key store.
    ///
    /// `key_nvm_id` is the wolfHSM NVM ID for the slot.  `flags` controls
    /// NVM access.  `key` must be exactly [`SHE_KEY_SZ`] (16) bytes.
    pub fn she_pre_program_key(
        &mut self,
        key_nvm_id: NvmId,
        flags: u16,
        key: &[u8; SHE_KEY_SZ],
    ) -> Result<(), Error> {
        // C API takes *mut u8 even though it does not modify the key.
        let mut key_buf = *key;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wh_Client_ShePreProgramKey(
                self.ctx_ptr(),
                key_nvm_id.0,
                flags,
                key_buf.as_mut_ptr(),
                SHE_KEY_SZ as u16,
            )
        };
        Error::check(rc, "wh_Client_ShePreProgramKey")
    }

    /// Set the SHE unique identifier on the server.
    ///
    /// `uid` must be exactly [`SHE_UID_SZ`] (15) bytes.
    pub fn she_set_uid(&mut self, uid: &[u8; SHE_UID_SZ]) -> Result<(), Error> {
        let mut uid_buf = *uid;
        // SAFETY: uid_buf is a valid 15-byte array; ctx_ptr is valid.
        let rc =
            unsafe { wh_Client_SheSetUid(self.ctx_ptr(), uid_buf.as_mut_ptr(), SHE_UID_SZ as u32) };
        Error::check(rc, "wh_Client_SheSetUid")
    }

    /// Perform SHE secure boot: compute a CMAC over `bootloader` using the
    /// BOOT_MAC_KEY slot and verify against the stored boot MAC.
    pub fn she_secure_boot(&mut self, bootloader: &[u8]) -> Result<(), Error> {
        let len = u32::try_from(bootloader.len()).map_err(|_| Error::BadArgs {
            msg: "she_secure_boot: bootloader exceeds u32::MAX bytes",
        })?;
        // SAFETY: wh_Client_SheSecureBoot reads `bootloader` but does not write
        // through it; the *mut u8 in the C signature is a historical API wart.
        let rc = unsafe {
            wh_Client_SheSecureBoot(
                self.ctx_ptr(),
                bootloader.as_ptr() as *mut u8,
                len,
            )
        };
        Error::check(rc, "wh_Client_SheSecureBoot")
    }

    /// Read the SHE status register (SREG) byte.
    ///
    /// The returned byte encodes the following status bits per the SHE AutoSAR
    /// specification (Table 7 — Status Register):
    ///
    /// | Bit | Name          | Meaning                                        |
    /// |-----|---------------|------------------------------------------------|
    /// |   0 | BUSY          | SHE is processing a command                    |
    /// |   1 | SECURE_BOOT   | SHE has executed secure boot                   |
    /// |   2 | BOOT_INIT     | `CMD_INIT_RNG` has completed                   |
    /// |   3 | BOOT_FINISHED | `CMD_SECURE_BOOT` has completed                |
    /// |   4 | BOOT_OK       | Secure-boot MAC verification succeeded         |
    /// |   5 | RND_INIT      | Random number generator has been initialized   |
    /// |   6 | EXT_DEBUGGER  | External debugger is connected                 |
    /// |   7 | INT_DEBUGGER  | Internal debugger is enabled                   |
    pub fn she_get_status(&mut self) -> Result<u8, Error> {
        let mut sreg: u8 = 0;
        // SAFETY: ctx_ptr is valid; sreg is a valid stack allocation.
        let rc = unsafe { wh_Client_SheGetStatus(self.ctx_ptr(), &mut sreg) };
        Error::check(rc, "wh_Client_SheGetStatus")?;
        Ok(sreg)
    }

    /// Load a key into a SHE key slot using the M1–M5 cryptographic protocol
    /// (SHE AutoSAR CMD_LOAD_KEY command).
    ///
    /// The caller must compute M1, M2, and M3 externally using the SHE
    /// key-update protocol (AUTOSAR_SWS_CryptoServiceManager §8.3.3):
    ///
    /// - **M1** (16 bytes): `UID || ID || AuthID` — identifies the target key
    ///   slot and the authorizing key slot.
    /// - **M2** (32 bytes): `enc(MASTER_ECU_KEY, ⌊counter‖flags‖key⌋)` —
    ///   the new key material encrypted under the authorizing key.
    /// - **M3** (16 bytes): `CMAC(MASTER_ECU_KEY, M1‖M2)` — authentication
    ///   MAC over M1 and M2.
    ///
    /// On success, the server returns:
    ///
    /// - **M4** (32 bytes): `UID || ID || AuthID || enc(new_key, counter)` —
    ///   proof that the key was updated (used by the host for verification).
    /// - **M5** (16 bytes): `CMAC(new_key, M4)` — authentication MAC over M4.
    pub fn she_load_key(
        &mut self,
        m1: &[u8; SHE_M1_SZ],
        m2: &[u8; SHE_M2_SZ],
        m3: &[u8; SHE_M3_SZ],
    ) -> Result<([u8; SHE_M4_SZ], [u8; SHE_M5_SZ]), Error> {
        let mut m1_buf = *m1;
        let mut m2_buf = *m2;
        let mut m3_buf = *m3;
        let mut m4 = [0u8; SHE_M4_SZ];
        let mut m5 = [0u8; SHE_M5_SZ];
        // SAFETY: all buffers are valid stack allocations; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_SheLoadKey(
                self.ctx_ptr(),
                m1_buf.as_mut_ptr(),
                m2_buf.as_mut_ptr(),
                m3_buf.as_mut_ptr(),
                m4.as_mut_ptr(),
                m5.as_mut_ptr(),
            )
        };
        Error::check(rc, "wh_Client_SheLoadKey")?;
        Ok((m4, m5))
    }

    /// Load a plaintext AES-128 key into the RAM_KEY slot.
    ///
    /// `key` must be exactly [`SHE_KEY_SZ`] (16) bytes.
    pub fn she_load_plain_key(&mut self, key: &[u8; SHE_KEY_SZ]) -> Result<(), Error> {
        let mut key_buf = *key;
        // SAFETY: key_buf is a valid 16-byte stack array; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_SheLoadPlainKey(self.ctx_ptr(), key_buf.as_mut_ptr(), SHE_KEY_SZ as u32)
        };
        Error::check(rc, "wh_Client_SheLoadPlainKey")
    }

    /// Export the RAM_KEY slot as M1–M5 protocol messages for backup.
    pub fn she_export_ram_key(
        &mut self,
    ) -> Result<
        (
            [u8; SHE_M1_SZ],
            [u8; SHE_M2_SZ],
            [u8; SHE_M3_SZ],
            [u8; SHE_M4_SZ],
            [u8; SHE_M5_SZ],
        ),
        Error,
    > {
        let mut m1 = [0u8; SHE_M1_SZ];
        let mut m2 = [0u8; SHE_M2_SZ];
        let mut m3 = [0u8; SHE_M3_SZ];
        let mut m4 = [0u8; SHE_M4_SZ];
        let mut m5 = [0u8; SHE_M5_SZ];
        // SAFETY: all buffers are valid stack allocations; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_SheExportRamKey(
                self.ctx_ptr(),
                m1.as_mut_ptr(),
                m2.as_mut_ptr(),
                m3.as_mut_ptr(),
                m4.as_mut_ptr(),
                m5.as_mut_ptr(),
            )
        };
        Error::check(rc, "wh_Client_SheExportRamKey")?;
        Ok((m1, m2, m3, m4, m5))
    }

    /// Initialize the SHE PRNG (seed it from the PRNG_SEED NVM slot).
    pub fn she_init_rnd(&mut self) -> Result<(), Error> {
        // SAFETY: ctx_ptr is valid.
        let rc = unsafe { wh_Client_SheInitRnd(self.ctx_ptr()) };
        Error::check(rc, "wh_Client_SheInitRnd")
    }

    /// Generate 16 bytes of pseudo-random data using the SHE PRNG.
    ///
    /// The output is random bytes — not key material.  The array size is 16
    /// because the SHE PRNG always produces exactly 16 bytes per call.
    pub fn she_rnd(&mut self) -> Result<[u8; 16], Error> {
        let mut out = [0u8; 16];
        let mut out_sz: u32 = 16;
        // SAFETY: out is a valid 16-byte stack array; ctx_ptr is valid.
        let rc = unsafe { wh_Client_SheRnd(self.ctx_ptr(), out.as_mut_ptr(), &mut out_sz) };
        Error::check(rc, "wh_Client_SheRnd")?;
        // Verify the server produced exactly 16 bytes; any other length means
        // the tail of `out` is uninitialized zeros, not random data.
        if out_sz != 16 {
            return Err(Error::ProtocolError {
                msg: "wh_Client_SheRnd: unexpected output length",
            });
        }
        Ok(out)
    }

    /// Mix `entropy` into the SHE PRNG state (extend the seed).
    pub fn she_extend_seed(&mut self, entropy: &[u8]) -> Result<(), Error> {
        let len = u32::try_from(entropy.len()).map_err(|_| Error::BadArgs {
            msg: "she_extend_seed: entropy exceeds u32::MAX bytes",
        })?;
        // SAFETY: wh_Client_SheExtendSeed reads `entropy` but does not write
        // through it; the *mut u8 in the C signature is a historical API wart.
        let rc = unsafe {
            wh_Client_SheExtendSeed(self.ctx_ptr(), entropy.as_ptr() as *mut u8, len)
        };
        Error::check(rc, "wh_Client_SheExtendSeed")
    }

    /// AES-128 ECB encryption using SHE key slot `key_id`.
    ///
    /// `plaintext` length must be a non-zero multiple of 16 bytes.
    /// Returns the ciphertext (same length as `plaintext`).
    pub fn she_enc_ecb(&mut self, key_id: SheKeyId, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let sz = validate_she_block_size(plaintext.len())?;
        let mut output = vec![0u8; plaintext.len()];
        // SAFETY: wh_Client_SheEncEcb reads `plaintext` and writes `output`;
        // the *mut u8 for the input is a historical API wart — it is not modified.
        let rc = unsafe {
            wh_Client_SheEncEcb(
                self.ctx_ptr(),
                key_id.0,
                plaintext.as_ptr() as *mut u8,
                output.as_mut_ptr(),
                sz,
            )
        };
        Error::check(rc, "wh_Client_SheEncEcb")?;
        Ok(output)
    }

    /// AES-128 ECB decryption using SHE key slot `key_id`.
    ///
    /// `ciphertext` length must be a non-zero multiple of 16 bytes.
    /// Returns the plaintext (same length as `ciphertext`).
    pub fn she_dec_ecb(&mut self, key_id: SheKeyId, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let sz = validate_she_block_size(ciphertext.len())?;
        let mut output = vec![0u8; ciphertext.len()];
        // SAFETY: wh_Client_SheDecEcb reads `ciphertext` and writes `output`;
        // the *mut u8 for the input is a historical API wart — it is not modified.
        let rc = unsafe {
            wh_Client_SheDecEcb(
                self.ctx_ptr(),
                key_id.0,
                ciphertext.as_ptr() as *mut u8,
                output.as_mut_ptr(),
                sz,
            )
        };
        Error::check(rc, "wh_Client_SheDecEcb")?;
        Ok(output)
    }

    /// AES-128 CBC encryption using SHE key slot `key_id`.
    ///
    /// `iv` must be exactly 16 bytes.  `plaintext` length must be a non-zero
    /// multiple of 16 bytes.  Returns the ciphertext.
    pub fn she_enc_cbc(
        &mut self,
        key_id: SheKeyId,
        iv: &[u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let sz = validate_she_block_size(plaintext.len())?;
        let mut iv_buf = *iv;
        let mut output = vec![0u8; plaintext.len()];
        // SAFETY: wh_Client_SheEncCbc reads `plaintext` and writes `output`;
        // `iv_buf` is a mutable local copy (the C function may consume it).
        // The *mut u8 for `plaintext` is a historical API wart — it is not modified.
        let rc = unsafe {
            wh_Client_SheEncCbc(
                self.ctx_ptr(),
                key_id.0,
                iv_buf.as_mut_ptr(),
                iv_buf.len() as u32,
                plaintext.as_ptr() as *mut u8,
                output.as_mut_ptr(),
                sz,
            )
        };
        Error::check(rc, "wh_Client_SheEncCbc")?;
        Ok(output)
    }

    /// AES-128 CBC decryption using SHE key slot `key_id`.
    ///
    /// `iv` must be exactly 16 bytes.  `ciphertext` length must be a non-zero
    /// multiple of 16 bytes.  Returns the plaintext.
    pub fn she_dec_cbc(
        &mut self,
        key_id: SheKeyId,
        iv: &[u8; 16],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let sz = validate_she_block_size(ciphertext.len())?;
        let mut iv_buf = *iv;
        let mut output = vec![0u8; ciphertext.len()];
        // SAFETY: wh_Client_SheDecCbc reads `ciphertext` and writes `output`;
        // `iv_buf` is a mutable local copy (the C function may consume it).
        // The *mut u8 for `ciphertext` is a historical API wart — it is not modified.
        let rc = unsafe {
            wh_Client_SheDecCbc(
                self.ctx_ptr(),
                key_id.0,
                iv_buf.as_mut_ptr(),
                iv_buf.len() as u32,
                ciphertext.as_ptr() as *mut u8,
                output.as_mut_ptr(),
                sz,
            )
        };
        Error::check(rc, "wh_Client_SheDecCbc")?;
        Ok(output)
    }

    /// Compute an AES-CMAC tag over `data` using SHE key slot `key_id`.
    ///
    /// Returns a 16-byte MAC tag.
    pub fn she_generate_mac(
        &mut self,
        key_id: SheKeyId,
        data: &[u8],
    ) -> Result<[u8; SHE_KEY_SZ], Error> {
        let in_sz = u32::try_from(data.len()).map_err(|_| Error::BadArgs {
            msg: "she_generate_mac: data exceeds u32::MAX bytes",
        })?;
        let mut mac = [0u8; SHE_KEY_SZ];
        // SAFETY: wh_Client_SheGenerateMac reads `data` and writes `mac`;
        // the *mut u8 for `data` is a historical API wart — it is not modified.
        let rc = unsafe {
            wh_Client_SheGenerateMac(
                self.ctx_ptr(),
                key_id.0,
                data.as_ptr() as *mut u8,
                in_sz,
                mac.as_mut_ptr(),
                SHE_KEY_SZ as u32,
            )
        };
        Error::check(rc, "wh_Client_SheGenerateMac")?;
        Ok(mac)
    }

    /// Verify an AES-CMAC tag over `message` using SHE key slot `key_id`.
    ///
    /// `mac` must be exactly [`SHE_KEY_SZ`] (16) bytes — the SHE specification
    /// mandates a fixed-size 128-bit CMAC.
    ///
    /// Returns `Ok(())` if the MAC is valid, or `Err` if the MAC does not match
    /// or a transport/server error occurred.
    pub fn she_verify_mac(
        &mut self,
        key_id: SheKeyId,
        message: &[u8],
        mac: &[u8; SHE_KEY_SZ],
    ) -> Result<(), Error> {
        let msg_len = u32::try_from(message.len()).map_err(|_| Error::BadArgs {
            msg: "she_verify_mac: message exceeds u32::MAX bytes",
        })?;
        let mut mac_buf = *mac;
        let mut status: u8 = 1; // non-zero = invalid; server sets to 0 on success
        // SAFETY: wh_Client_SheVerifyMac reads `message` and `mac_buf` (the
        // local copy); it writes only to `status`.  The *mut u8 for `message`
        // is a historical API wart — it is not modified.
        let rc = unsafe {
            wh_Client_SheVerifyMac(
                self.ctx_ptr(),
                key_id.0,
                message.as_ptr() as *mut u8,
                msg_len,
                mac_buf.as_mut_ptr(),
                SHE_KEY_SZ as u32,
                &mut status,
            )
        };
        Error::check(rc, "wh_Client_SheVerifyMac")?;
        if status != 0 {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

/// Validate that `len` is a non-zero multiple of the AES block size (16).
fn validate_she_block_size(len: usize) -> Result<u32, Error> {
    if len == 0 || len % 16 != 0 {
        return Err(Error::BadArgs {
            msg: "length must be a non-zero multiple of 16 bytes (AES block size)",
        });
    }
    u32::try_from(len).map_err(|_| Error::BadArgs {
        msg: "she: data length exceeds u32::MAX bytes",
    })
}

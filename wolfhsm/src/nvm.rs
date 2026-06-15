use wolfhsm_sys::{
    wh_Client_NvmAddObject, wh_Client_NvmDestroyObjects, wh_Client_NvmGetAvailable,
    wh_Client_NvmGetMetadata, wh_Client_NvmList, wh_Client_NvmRead,
};

use crate::client::Client;
use crate::error::Error;

// WH_ERROR_NOTFOUND — signals end-of-list in NvmList, not a real error.
const WH_ERROR_NOTFOUND: i32 = -2104;

/// Maximum NVM label length in bytes (wolfHSM `whNvmMetadata.label` field).
const NVM_LABEL_LEN: usize = 24;

/// Truncate `label` to [`NVM_LABEL_LEN`] bytes and copy into a fixed-size
/// mutable buffer.  Returns the buffer and the number of bytes copied.
///
/// Used by `nvm_add`, `nvm_overwrite`, and `cert_add_trusted`, which all
/// share the same label-truncation requirement.
pub(crate) fn truncate_label(label: &[u8]) -> ([u8; NVM_LABEL_LEN], usize) {
    let len = label.len().min(NVM_LABEL_LEN);
    let mut buf = [0u8; NVM_LABEL_LEN];
    buf[..len].copy_from_slice(&label[..len]);
    (buf, len)
}

/// NVM access control flags (corresponds to `WH_NVM_ACCESS_*` in `wh_common.h`).
///
/// Bitfield — combine with `|`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmAccess(pub u16);

impl NvmAccess {
    /// No access restrictions.
    pub const NONE: Self = Self(0);
    /// Allow all access (owner + other + user).
    pub const ANY: Self = Self(0xFFFF);
    /// Owner-read permission.
    pub const READ: Self = Self(1 << 0);
    /// Owner-write permission.
    pub const WRITE: Self = Self(1 << 1);
    /// Owner-execute permission.
    pub const EXEC: Self = Self(1 << 2);
}

impl core::ops::BitOr for NvmAccess {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// NVM object attribute flags (corresponds to `WH_NVM_FLAGS_*` in `wh_common.h`).
///
/// Bitfield — combine with `|`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmFlags(pub u16);

impl NvmFlags {
    /// No special attributes (default).
    pub const NONE: Self = Self(0);
    /// Object cannot be modified after creation.
    pub const NON_MODIFIABLE: Self = Self(1 << 0);
    /// Object contains sensitive material (key, secret).
    pub const SENSITIVE: Self = Self(1 << 1);
    /// Object cannot be exported from the HSM.
    pub const NON_EXPORTABLE: Self = Self(1 << 2);
    /// Object was generated locally (not imported).
    pub const LOCAL: Self = Self(1 << 3);
    /// Object is ephemeral (not persisted across reboots).
    pub const EPHEMERAL: Self = Self(1 << 4);
    /// Permit encrypt operations.
    pub const USAGE_ENCRYPT: Self = Self(1 << 5);
    /// Permit decrypt operations.
    pub const USAGE_DECRYPT: Self = Self(1 << 6);
    /// Permit sign operations.
    pub const USAGE_SIGN: Self = Self(1 << 7);
    /// Permit verify operations.
    pub const USAGE_VERIFY: Self = Self(1 << 8);
    /// Permit wrap operations.
    pub const USAGE_WRAP: Self = Self(1 << 9);
    /// Permit derive operations.
    pub const USAGE_DERIVE: Self = Self(1 << 10);
    /// Object cannot be destroyed.
    pub const NON_DESTROYABLE: Self = Self(1 << 11);
    /// Allow all flags.
    pub const ANY: Self = Self(0xFFFF);
}

impl core::ops::BitOr for NvmFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Available and reclaimable NVM space reported by the wolfHSM server.
#[derive(Debug, Clone, Copy)]
pub struct NvmAvailability {
    /// Bytes available for new objects.
    pub avail_size: u32,
    /// Number of object slots available.
    pub avail_objects: u16,
    /// Bytes that can be recovered by compaction.
    pub reclaim_size: u32,
    /// Object slots that can be recovered by compaction.
    pub reclaim_objects: u16,
}

/// A wolfHSM NVM object identifier (wraps `whNvmId` = `u16`).
///
/// Used to identify counters and other NVM objects on the wolfHSM server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NvmId(pub(crate) u16);

impl NvmId {
    /// The invalid/unset NVM ID (`WH_NVM_ID_INVALID` = 0).
    pub const INVALID: Self = NvmId(0);

    /// Wrap a raw `whNvmId` value.
    ///
    /// Prefer the [`From<u16>`] impl in non-`const` contexts.
    pub const fn new(id: u16) -> Self {
        Self(id)
    }
}

impl From<u16> for NvmId {
    fn from(v: u16) -> Self {
        NvmId(v)
    }
}

impl From<NvmId> for u16 {
    fn from(n: NvmId) -> Self {
        n.0
    }
}

/// Metadata about an NVM object.
#[derive(Debug, Clone)]
pub struct NvmMetadata {
    /// Unique NVM object identifier.
    pub id: NvmId,
    /// Access control flags.
    pub access: NvmAccess,
    /// Object attribute flags.
    pub flags: NvmFlags,
    /// Data length in bytes as reported by the wolfHSM server.
    pub len: u16,
    /// Raw label bytes (NUL-padded to 24 bytes). Use [`label_str`][NvmMetadata::label_str] for a `&str` view.
    pub label: [u8; 24],
}

impl NvmMetadata {
    /// Return the label as a UTF-8 string slice, trimming trailing null bytes.
    ///
    /// Returns `None` if the label bytes are not valid UTF-8.
    pub fn label_str(&self) -> Option<&str> {
        let trimmed = match self.label.iter().position(|&b| b == 0) {
            Some(n) => &self.label[..n],
            None => &self.label[..],
        };
        core::str::from_utf8(trimmed).ok()
    }
}

impl Client {
    /// Query available and reclaimable NVM space on the server.
    pub fn nvm_available(&mut self) -> Result<NvmAvailability, Error> {
        let mut out_rc: i32 = 0;
        let mut avail_size: u32 = 0;
        let mut avail_objects: u16 = 0;
        let mut reclaim_size: u32 = 0;
        let mut reclaim_objects: u16 = 0;

        // SAFETY: all output pointers are valid stack allocations; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_NvmGetAvailable(
                self.ctx_ptr(),
                &mut out_rc,
                &mut avail_size,
                &mut avail_objects,
                &mut reclaim_size,
                &mut reclaim_objects,
            )
        };
        Error::check(rc, "wh_Client_NvmGetAvailable")?;
        Error::check(out_rc, "wh_Client_NvmGetAvailable(server)")?;

        Ok(NvmAvailability {
            avail_size,
            avail_objects,
            reclaim_size,
            reclaim_objects,
        })
    }

    /// List all NVM object IDs stored on the server.
    ///
    /// Calls `wh_Client_NvmList` in a loop.  The `start_id` parameter is the
    /// **cursor**: pass 0 (WH_NVM_ID_INVALID) to start from the beginning, or
    /// pass the last-seen ID to resume.  The server locates that exact ID in
    /// its directory and returns the *next* object after it, together with the
    /// count of remaining objects including the one just returned.  End of
    /// list is signalled by `out_id == 0` (WH_NVM_ID_INVALID) with
    /// `out_rc == WH_ERROR_OK`, or by `out_rc == WH_ERROR_NOTFOUND` on some
    /// backend variants.
    ///
    /// Confirmed against wolfHSM C source (`wh_NvmFlash_List`,
    /// `wh_NvmFlashLog_List`, and the upstream test suite in
    /// `wh_test_clientserver.c`): the cursor must be the last-seen ID, not
    /// last-seen + 1.  Passing last-seen + 1 causes a spurious "not found"
    /// result for non-contiguous ID spaces because the server does an
    /// exact-match lookup, not a lower-bound search.
    pub fn nvm_list(&mut self) -> Result<Vec<NvmId>, Error> {
        let mut ids = Vec::new();
        // 0 == WH_NVM_ID_INVALID: tells the server to start from the first object.
        let mut start_id: u16 = 0;

        loop {
            let mut out_rc: i32 = 0;
            let mut out_count: u16 = 0;
            let mut out_id: u16 = 0;

            // SAFETY: all output pointers are valid stack allocations; ctx_ptr is valid.
            let rc = unsafe {
                wh_Client_NvmList(
                    self.ctx_ptr(),
                    0, // access: any
                    0, // flags: any
                    start_id,
                    &mut out_rc,
                    &mut out_count,
                    &mut out_id,
                )
            };
            Error::check(rc, "wh_Client_NvmList")?;

            // WH_ERROR_NOTFOUND in out_rc is the end-of-list signal on some
            // backend variants.
            if out_rc == WH_ERROR_NOTFOUND {
                break;
            }
            Error::check(out_rc, "wh_Client_NvmList(server)")?;

            // out_id == 0 (WH_NVM_ID_INVALID) with WH_ERROR_OK is the
            // end-of-list signal used by wh_NvmFlash_List and
            // wh_NvmFlashLog_List.
            if out_id == 0 {
                break;
            }

            // out_count is the number of remaining objects including out_id.
            // Use it as a capacity hint on the first successful call.
            if ids.is_empty() {
                ids.reserve(out_count as usize);
            }

            // Guard against a misbehaving server that returns the same ID as
            // the cursor without advancing (would otherwise loop forever).
            if out_id == start_id && start_id != 0 {
                return Err(Error::ProtocolError {
                    msg: "wh_Client_NvmList: server returned out_id == start_id; cursor stuck",
                });
            }

            ids.push(NvmId(out_id));

            // Pass the last-seen ID back as the cursor.  The server does an
            // exact-match on start_id and returns the next object after it, so
            // the correct advance is start_id = out_id, not out_id + 1.
            start_id = out_id;
        }

        Ok(ids)
    }

    /// Retrieve metadata for the NVM object identified by `id`.
    pub fn nvm_metadata(&mut self, id: NvmId) -> Result<NvmMetadata, Error> {
        let mut out_rc: i32 = 0;
        let mut out_id: u16 = 0;
        let mut out_access: u16 = 0;
        let mut out_flags: u16 = 0;
        let mut out_len: u16 = 0;
        let mut label = [0u8; 24];

        // SAFETY: all output pointers are valid stack allocations; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_NvmGetMetadata(
                self.ctx_ptr(),
                id.0,
                &mut out_rc,
                &mut out_id,
                &mut out_access,
                &mut out_flags,
                &mut out_len,
                label.len() as u16,
                label.as_mut_ptr(),
            )
        };
        Error::check(rc, "wh_Client_NvmGetMetadata")?;
        Error::check(out_rc, "wh_Client_NvmGetMetadata(server)")?;

        Ok(NvmMetadata {
            id: NvmId(out_id),
            access: NvmAccess(out_access),
            flags: NvmFlags(out_flags),
            len: out_len,
            label,
        })
    }

    /// Read the contents of the NVM object identified by `id`.
    ///
    /// Fetches the object length via `nvm_metadata` first, then reads the
    /// bytes from `offset` to the end of the object.  Returns `Ok(vec![])`
    /// when `offset >= meta.len` (nothing left to read).
    pub fn nvm_read(&mut self, id: NvmId, offset: u16) -> Result<Vec<u8>, Error> {
        let meta = self.nvm_metadata(id)?;
        // Request only the bytes that remain after `offset`.  Without this,
        // `data_len` would exceed the object length, causing the server to
        // return an error.
        let data_len = meta.len.saturating_sub(offset);
        if data_len == 0 {
            return Ok(vec![]);
        }

        let mut out_rc: i32 = 0;
        let mut out_len: u16 = 0;
        let mut data = vec![0u8; data_len as usize];

        // SAFETY: `data` is a valid heap allocation of `data_len` bytes; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_NvmRead(
                self.ctx_ptr(),
                id.0,
                offset,
                data_len,
                &mut out_rc,
                &mut out_len,
                data.as_mut_ptr(),
            )
        };
        Error::check(rc, "wh_Client_NvmRead")?;
        Error::check(out_rc, "wh_Client_NvmRead(server)")?;
        if out_len as usize > data.len() {
            return Err(Error::ProtocolError {
                msg: "wh_Client_NvmRead: server reported out_len > requested length",
            });
        }
        data.truncate(out_len as usize);
        Ok(data)
    }

    /// Read exactly `len` bytes from NVM object `id` starting at `offset`,
    /// without issuing a prior metadata round-trip.
    ///
    /// Use this when you already know the object length and want to avoid
    /// the extra [`nvm_metadata`][Self::nvm_metadata] call that
    /// [`nvm_read`][Self::nvm_read] issues unconditionally.  The server
    /// returns an error if `offset + len` exceeds the object length.
    pub fn nvm_read_raw(
        &mut self,
        id: NvmId,
        offset: u16,
        len: u16,
    ) -> Result<Vec<u8>, Error> {
        if len == 0 {
            return Ok(vec![]);
        }
        let mut out_rc: i32 = 0;
        let mut out_len: u16 = 0;
        let mut data = vec![0u8; len as usize];
        // SAFETY: `data` is a valid heap allocation of `len` bytes; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_NvmRead(
                self.ctx_ptr(),
                id.0,
                offset,
                len,
                &mut out_rc,
                &mut out_len,
                data.as_mut_ptr(),
            )
        };
        Error::check(rc, "wh_Client_NvmRead")?;
        Error::check(out_rc, "wh_Client_NvmRead(server)")?;
        if out_len as usize > data.len() {
            return Err(Error::ProtocolError {
                msg: "wh_Client_NvmRead: server reported out_len > requested length",
            });
        }
        data.truncate(out_len as usize);
        Ok(data)
    }

    /// Create a new NVM object.
    ///
    /// Fails if an object with `id` already exists (the server returns an
    /// error in that case).  Use [`nvm_overwrite`][Self::nvm_overwrite] when
    /// you need to replace an existing object.
    ///
    /// `id` must not be [`NvmId::INVALID`].  `label` is truncated to 24
    /// bytes.  `data` must fit in a `u16` (≤ 65535 bytes).
    ///
    /// `access` — access control flags; see `WH_NVM_ACCESS_*` constants in
    /// `wolfhsm/wh_nvm.h`. Pass `0` for unrestricted access.
    ///
    /// `flags` — object attribute flags; see `WH_NVM_FLAGS_*` constants in
    /// `wolfhsm/wh_nvm.h`. Pass `0` for default attributes.
    pub fn nvm_add(
        &mut self,
        id: NvmId,
        access: NvmAccess,
        flags: NvmFlags,
        label: impl AsRef<[u8]>,
        data: &[u8],
    ) -> Result<(), Error> {
        let label = label.as_ref();
        if id == NvmId::INVALID {
            return Err(Error::InvalidInput {
                msg: "id must not be NvmId::INVALID (0)",
            });
        }
        let data_len = u16::try_from(data.len()).map_err(|_| Error::InvalidInput {
            msg: "nvm_add data exceeds u16::MAX bytes",
        })?;
        let (mut label_buf, label_len) = truncate_label(label);
        let mut out_rc: i32 = 0;
        // SAFETY: all pointers are valid for the duration of this call; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_NvmAddObject(
                self.ctx_ptr(),
                id.0,
                access.0,
                flags.0,
                label_len as u16,
                label_buf.as_mut_ptr(),
                data_len,
                data.as_ptr(),
                &mut out_rc,
            )
        };
        Error::check(rc, "wh_Client_NvmAddObject")?;
        Error::check(out_rc, "wh_Client_NvmAddObject(server)")?;
        Ok(())
    }

    /// Overwrite an NVM object with new data. **Not atomic — see warning below.**
    ///
    /// **Warning — data loss hazard**: the existing object is deleted first,
    /// then the new object is added.  If the add fails after a successful
    /// delete, the original object is **permanently lost** and
    /// [`Error::DataLost`] is returned carrying the affected ID.  The
    /// NVM protocol has no rollback facility.
    ///
    /// The `id` must not be [`NvmId::INVALID`] — the server's auto-assign
    /// path is not supported because it does not return the assigned ID.
    /// Choose an explicit non-zero ID.
    ///
    /// `label` is truncated to 24 bytes if longer.  `data` must fit in a
    /// `u16` (≤ 65535 bytes).
    ///
    /// `access` — access control flags; see `WH_NVM_ACCESS_*` constants in
    /// `wolfhsm/wh_nvm.h`. Pass `0` for unrestricted access.
    ///
    /// `flags` — object attribute flags; see `WH_NVM_FLAGS_*` constants in
    /// `wolfhsm/wh_nvm.h`. Pass `0` for default attributes.
    pub fn nvm_overwrite(
        &mut self,
        id: NvmId,
        access: NvmAccess,
        flags: NvmFlags,
        label: impl AsRef<[u8]>,
        data: &[u8],
    ) -> Result<(), Error> {
        let label = label.as_ref();
        if id == NvmId::INVALID {
            return Err(Error::InvalidInput {
                msg: "id must not be NvmId::INVALID (0); wolfHSM auto-assign does not return the assigned ID",
            });
        }
        let data_len = u16::try_from(data.len()).map_err(|_| Error::InvalidInput {
            msg: "nvm_overwrite data exceeds u16::MAX bytes",
        })?;

        // Treat NOTFOUND as success: the object may not yet exist (initial write).
        match self.nvm_delete(id) {
            Ok(()) => {}
            Err(Error::Wh { code }) if code == WH_ERROR_NOTFOUND => {}
            Err(e) => return Err(e),
        }

        let (mut label_buf, label_len) = truncate_label(label);

        let mut out_rc: i32 = 0;

        // SAFETY: all pointers are valid for the duration of this call; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_NvmAddObject(
                self.ctx_ptr(),
                id.0,
                access.0,
                flags.0,
                label_len as u16,
                label_buf.as_mut_ptr(),
                data_len,
                data.as_ptr(),
                &mut out_rc,
            )
        };

        // If the add fails the prior delete has already run; report data loss
        // so the caller knows the old object is gone and cannot be recovered.
        let map_add_err = |_: Error| Error::DataLost { id: id.0 };
        Error::check(rc, "wh_Client_NvmAddObject").map_err(map_add_err)?;
        Error::check(out_rc, "wh_Client_NvmAddObject(server)").map_err(map_add_err)?;

        Ok(())
    }

    /// Delete the NVM object identified by `id`.
    pub fn nvm_delete(&mut self, id: NvmId) -> Result<(), Error> {
        let id_list = [id.0];
        let mut out_rc: i32 = 0;

        // SAFETY: id_list is a valid single-element array on the stack; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_NvmDestroyObjects(self.ctx_ptr(), 1, id_list.as_ptr(), &mut out_rc)
        };
        Error::check(rc, "wh_Client_NvmDestroyObjects")?;
        Error::check(out_rc, "wh_Client_NvmDestroyObjects(server)")?;

        Ok(())
    }
}

use wolfhsm_sys::{
    wh_Client_NvmAddObject, wh_Client_NvmDestroyObjects, wh_Client_NvmGetAvailable,
    wh_Client_NvmGetMetadata, wh_Client_NvmList, wh_Client_NvmRead,
};

use crate::client::Client;
use crate::error::WolfHsmError;

// WH_ERROR_NOTFOUND — signals end-of-list in NvmList, not a real error.
const WH_ERROR_NOTFOUND: i32 = -2104;

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
pub struct NvmId(pub u16);

impl NvmId {
    /// The invalid/unset NVM ID (`WH_NVM_ID_INVALID` = 0).
    pub const INVALID: Self = NvmId(0);
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
    pub id: NvmId,
    pub access: u16,
    pub flags: u16,
    pub len: u16,
    pub label: [u8; 24],
}

impl Client {
    /// Query available and reclaimable NVM space on the server.
    pub fn nvm_available(&mut self) -> Result<NvmAvailability, WolfHsmError> {
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
        WolfHsmError::check(rc, "wh_Client_NvmGetAvailable")?;
        WolfHsmError::check(out_rc, "wh_Client_NvmGetAvailable(server)")?;

        Ok(NvmAvailability { avail_size, avail_objects, reclaim_size, reclaim_objects })
    }

    /// List all NVM object IDs stored on the server.
    ///
    /// Calls `wh_Client_NvmList` in a loop until the server returns
    /// `WH_ERROR_NOTFOUND` in `out_rc`, which is the normal end-of-list signal.
    pub fn nvm_list(&mut self) -> Result<Vec<NvmId>, WolfHsmError> {
        let mut ids = Vec::new();
        let mut start_id: u16 = 0; // WH_NVM_ID_INVALID

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
            WolfHsmError::check(rc, "wh_Client_NvmList")?;

            // WH_ERROR_NOTFOUND in out_rc is the normal end-of-list signal.
            if out_rc == WH_ERROR_NOTFOUND {
                break;
            }
            WolfHsmError::check(out_rc, "wh_Client_NvmList(server)")?;

            if out_id == 0 {
                // Safety guard against an infinite loop: if the server returns
                // id 0 after a success response, start_id would not advance
                // and the next iteration would send the same query forever.
                break;
            }
            ids.push(NvmId(out_id));

            start_id = match out_id.checked_add(1) {
                Some(next) => next,
                None => break, // ID space exhausted; no further objects possible
            };
        }

        Ok(ids)
    }

    /// Retrieve metadata for the NVM object identified by `id`.
    pub fn nvm_metadata(&mut self, id: NvmId) -> Result<NvmMetadata, WolfHsmError> {
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
        WolfHsmError::check(rc, "wh_Client_NvmGetMetadata")?;
        WolfHsmError::check(out_rc, "wh_Client_NvmGetMetadata(server)")?;

        Ok(NvmMetadata {
            id: NvmId(out_id),
            access: out_access,
            flags: out_flags,
            len: out_len,
            label,
        })
    }

    /// Read the contents of the NVM object identified by `id`.
    ///
    /// Fetches the object length via `nvm_metadata` first, then reads the
    /// bytes from `offset` to the end of the object.  Returns `Ok(vec![])`
    /// when `offset >= meta.len` (nothing left to read).
    pub fn nvm_read(&mut self, id: NvmId, offset: u16) -> Result<Vec<u8>, WolfHsmError> {
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
        WolfHsmError::check(rc, "wh_Client_NvmRead")?;
        WolfHsmError::check(out_rc, "wh_Client_NvmRead(server)")?;

        data.truncate(out_len as usize);
        Ok(data)
    }

    /// Write (or overwrite) an NVM object.
    ///
    /// If `id` is not [`NvmId::INVALID`], the existing object with that ID is
    /// deleted first via [`nvm_delete`][Self::nvm_delete], then the new data
    /// is added.  This delete-then-add sequence is **not atomic**: if the add
    /// fails after a successful delete, the original object is permanently
    /// lost and [`WolfHsmError::DataLost`] is returned, carrying the affected
    /// ID.  The NVM protocol has no rollback facility.
    ///
    /// If `id` is [`NvmId::INVALID`] (0), the deletion step is skipped and
    /// `0` is passed directly to `wh_Client_NvmAddObject`.  wolfHSM treats
    /// `id == 0` as an **auto-assign** request: the server selects a new ID
    /// and the caller cannot retrieve it from this call.  Use
    /// [`nvm_list`][Self::nvm_list] to discover the assigned ID afterward.
    ///
    /// `label` is truncated to 24 bytes if longer.  `data` must fit in a
    /// `u16` (≤ 65535 bytes).
    pub fn nvm_write(
        &mut self,
        id: NvmId,
        access: u16,
        flags: u16,
        label: &[u8],
        data: &[u8],
    ) -> Result<(), WolfHsmError> {
        let data_len = u16::try_from(data.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "nvm_write: data too large for u16",
        })?;

        let deleted = if id != NvmId::INVALID {
            self.nvm_delete(id)?;
            true
        } else {
            false
        };

        // Truncate label to 24 bytes; copy into a local mutable buffer as the
        // C API takes *mut u8 even though it does not modify the label.
        let label_len = label.len().min(24);
        let mut label_buf = [0u8; 24];
        label_buf[..label_len].copy_from_slice(&label[..label_len]);

        let mut out_rc: i32 = 0;

        // SAFETY: all pointers are valid for the duration of this call; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_NvmAddObject(
                self.ctx_ptr(),
                id.0,
                access,
                flags,
                label_len as u16,
                label_buf.as_mut_ptr(),
                data_len,
                data.as_ptr(),
                &mut out_rc,
            )
        };

        // If the add fails after we already deleted, report data loss so the
        // caller knows the old object is gone and cannot be recovered.
        let map_add_err = |e: WolfHsmError| {
            if deleted {
                WolfHsmError::DataLost { id: id.0 }
            } else {
                e
            }
        };
        WolfHsmError::check(rc, "wh_Client_NvmAddObject").map_err(map_add_err)?;
        WolfHsmError::check(out_rc, "wh_Client_NvmAddObject(server)").map_err(map_add_err)?;

        Ok(())
    }

    /// Delete the NVM object identified by `id`.
    pub fn nvm_delete(&mut self, id: NvmId) -> Result<(), WolfHsmError> {
        let id_list = [id.0];
        let mut out_rc: i32 = 0;

        // SAFETY: id_list is a valid single-element array on the stack; ctx_ptr is valid.
        let rc = unsafe {
            wh_Client_NvmDestroyObjects(self.ctx_ptr(), 1, id_list.as_ptr(), &mut out_rc)
        };
        WolfHsmError::check(rc, "wh_Client_NvmDestroyObjects")?;
        WolfHsmError::check(out_rc, "wh_Client_NvmDestroyObjects(server)")?;

        Ok(())
    }
}

use std::ffi::CString;

use wolfhsm_sys::{
    wh_Client_AuthLogin, wh_Client_AuthLogout, wh_Client_AuthUserAdd, wh_Client_AuthUserDelete,
    wh_Client_AuthUserGet, wh_Client_AuthUserSetCredentials, wh_Client_AuthUserSetPermissions,
    whAuthPermissions,
};

use crate::client::Client;
use crate::error::WolfHsmError;

/// wolfHSM authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthMethod {
    None        = 0, // WH_AUTH_METHOD_NONE
    Pin         = 1, // WH_AUTH_METHOD_PIN
    Certificate = 2, // WH_AUTH_METHOD_CERTIFICATE
}

/// A wolfHSM user identifier.
pub type UserId = u16;

/// wolfHSM user permission set (opaque mirror of `whAuthPermissions`).
///
/// Construct a zeroed instance with [`AuthPermissions::none`] and pass it to
/// the admin functions.  The internal layout is an opaque C struct; use the
/// wolfHSM C macros to inspect or set individual group/action bits.
pub type AuthPermissions = whAuthPermissions;

impl Client {
    /// Authenticate to the server and open a session.
    ///
    /// `auth_data` is the PIN bytes for [`AuthMethod::Pin`], or the DER client
    /// certificate for [`AuthMethod::Certificate`].
    ///
    /// On success returns the server-assigned [`UserId`] for the session.
    pub fn auth_login(
        &mut self,
        method: AuthMethod,
        username: &str,
        auth_data: &[u8],
    ) -> Result<UserId, WolfHsmError> {
        let cname = CString::new(username).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "auth_login: username contains interior NUL",
        })?;
        let auth_len = u16::try_from(auth_data.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "auth_login: auth_data too large for u16",
        })?;
        let mut out_rc: i32 = 0;
        let mut out_user_id: UserId = 0;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wh_Client_AuthLogin(
                self.ctx_ptr(),
                method as u32,
                cname.as_ptr(),
                auth_data.as_ptr() as *const core::ffi::c_void,
                auth_len,
                &mut out_rc,
                &mut out_user_id,
            )
        };
        WolfHsmError::check(rc, "wh_Client_AuthLogin")?;
        WolfHsmError::check(out_rc, "wh_Client_AuthLogin(server)")?;
        Ok(out_user_id)
    }

    /// Close a session identified by `user_id`.
    pub fn auth_logout(&mut self, user_id: UserId) -> Result<(), WolfHsmError> {
        let mut out_rc: i32 = 0;
        // SAFETY: ctx_ptr is valid; out_rc is a valid stack allocation.
        let rc = unsafe { wh_Client_AuthLogout(self.ctx_ptr(), user_id, &mut out_rc) };
        WolfHsmError::check(rc, "wh_Client_AuthLogout")?;
        WolfHsmError::check(out_rc, "wh_Client_AuthLogout(server)")?;
        Ok(())
    }

    /// Create a new user on the server.
    ///
    /// `credentials` is the initial PIN bytes or certificate DER.
    ///
    /// Returns the server-assigned [`UserId`] for the new account.
    pub fn auth_user_add(
        &mut self,
        username: &str,
        permissions: AuthPermissions,
        method: AuthMethod,
        credentials: &[u8],
    ) -> Result<UserId, WolfHsmError> {
        let cname = CString::new(username).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "auth_user_add: username contains interior NUL",
        })?;
        let cred_len = u16::try_from(credentials.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "auth_user_add: credentials too large for u16",
        })?;
        let mut out_rc: i32 = 0;
        let mut out_user_id: UserId = 0;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wh_Client_AuthUserAdd(
                self.ctx_ptr(),
                cname.as_ptr(),
                permissions,
                method as u32,
                credentials.as_ptr() as *const core::ffi::c_void,
                cred_len,
                &mut out_rc,
                &mut out_user_id,
            )
        };
        WolfHsmError::check(rc, "wh_Client_AuthUserAdd")?;
        WolfHsmError::check(out_rc, "wh_Client_AuthUserAdd(server)")?;
        Ok(out_user_id)
    }

    /// Look up a user by name and return their `(UserId, AuthPermissions)`.
    pub fn auth_user_get(
        &mut self,
        username: &str,
    ) -> Result<(UserId, AuthPermissions), WolfHsmError> {
        let cname = CString::new(username).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "auth_user_get: username contains interior NUL",
        })?;
        let mut out_rc: i32 = 0;
        let mut out_user_id: UserId = 0;
        // SAFETY: zeroed whAuthPermissions is a valid C struct initialisation.
        let mut out_permissions: AuthPermissions = unsafe { core::mem::zeroed() };
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wh_Client_AuthUserGet(
                self.ctx_ptr(),
                cname.as_ptr(),
                &mut out_rc,
                &mut out_user_id,
                &mut out_permissions,
            )
        };
        WolfHsmError::check(rc, "wh_Client_AuthUserGet")?;
        WolfHsmError::check(out_rc, "wh_Client_AuthUserGet(server)")?;
        Ok((out_user_id, out_permissions))
    }

    /// Delete the user identified by `user_id`.
    pub fn auth_user_delete(&mut self, user_id: UserId) -> Result<(), WolfHsmError> {
        let mut out_rc: i32 = 0;
        // SAFETY: ctx_ptr is valid; out_rc is a valid stack allocation.
        let rc = unsafe { wh_Client_AuthUserDelete(self.ctx_ptr(), user_id, &mut out_rc) };
        WolfHsmError::check(rc, "wh_Client_AuthUserDelete")?;
        WolfHsmError::check(out_rc, "wh_Client_AuthUserDelete(server)")?;
        Ok(())
    }

    /// Replace the permissions for user `user_id`.
    pub fn auth_user_set_permissions(
        &mut self,
        user_id: UserId,
        permissions: AuthPermissions,
    ) -> Result<(), WolfHsmError> {
        let mut out_rc: i32 = 0;
        // SAFETY: ctx_ptr is valid; all other args are by-value or stack allocations.
        let rc = unsafe {
            wh_Client_AuthUserSetPermissions(
                self.ctx_ptr(),
                user_id,
                permissions,
                &mut out_rc,
            )
        };
        WolfHsmError::check(rc, "wh_Client_AuthUserSetPermissions")?;
        WolfHsmError::check(out_rc, "wh_Client_AuthUserSetPermissions(server)")?;
        Ok(())
    }

    /// Change the credentials for user `user_id`.
    ///
    /// `current_credentials` is the existing PIN/certificate (used for
    /// authorisation).  `new_credentials` replaces it.
    pub fn auth_user_set_credentials(
        &mut self,
        user_id: UserId,
        method: AuthMethod,
        current_credentials: &[u8],
        new_credentials: &[u8],
    ) -> Result<(), WolfHsmError> {
        let cur_len = u16::try_from(current_credentials.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "auth_user_set_credentials: current_credentials too large for u16",
        })?;
        let new_len = u16::try_from(new_credentials.len()).map_err(|_| WolfHsmError::Ffi {
            code: -1,
            func: "auth_user_set_credentials: new_credentials too large for u16",
        })?;
        let mut out_rc: i32 = 0;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wh_Client_AuthUserSetCredentials(
                self.ctx_ptr(),
                user_id,
                method as u32,
                current_credentials.as_ptr() as *const core::ffi::c_void,
                cur_len,
                new_credentials.as_ptr() as *const core::ffi::c_void,
                new_len,
                &mut out_rc,
            )
        };
        WolfHsmError::check(rc, "wh_Client_AuthUserSetCredentials")?;
        WolfHsmError::check(out_rc, "wh_Client_AuthUserSetCredentials(server)")?;
        Ok(())
    }
}

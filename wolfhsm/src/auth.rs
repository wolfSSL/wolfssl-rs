use std::ffi::CString;

use wolfhsm_sys::{
    whAuthPermissions, wh_Client_AuthLogin, wh_Client_AuthLogout, wh_Client_AuthUserAdd,
    wh_Client_AuthUserDelete, wh_Client_AuthUserGet, wh_Client_AuthUserSetCredentials,
    wh_Client_AuthUserSetPermissions,
};

use crate::client::Client;
use crate::error::Error;

/// wolfHSM authentication method.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthMethod {
    None = 0,        // WH_AUTH_METHOD_NONE
    Pin = 1,         // WH_AUTH_METHOD_PIN
    Certificate = 2, // WH_AUTH_METHOD_CERTIFICATE
}

/// A wolfHSM user identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(pub(crate) u16);

impl UserId {
    /// Wrap a raw user identifier value.
    ///
    /// Prefer the [`From<u16>`] impl in non-`const` contexts.
    pub const fn new(id: u16) -> Self {
        Self(id)
    }
}

impl From<u16> for UserId {
    fn from(v: u16) -> Self {
        UserId(v)
    }
}

impl From<UserId> for u16 {
    fn from(u: UserId) -> Self {
        u.0
    }
}

/// wolfHSM user permission set.
///
/// Construct a zeroed (no-permissions) instance with [`AuthPermissions::none`].
/// To set specific permission bits, use the wolfHSM C macros via
/// [`AuthPermissions::as_raw_mut`] or build from a raw value with
/// `AuthPermissions::from(raw)` / `.into()`.
///
/// The internal layout mirrors `whAuthPermissions` from the wolfHSM C library.
///
/// `PartialEq`/`Eq` are not derived because bindgen does not generate them for
/// `whAuthPermissions` (it only derives `Debug, Copy, Clone`). The fields are
/// all integer types so there is no soundness obstacle, but we do not implement
/// them manually to avoid silent breakage if the C struct gains a field that
/// makes byte-equality wrong. Use [`AuthPermissions::as_raw_mut`] for
/// field-level comparisons if needed.
#[derive(Debug, Clone, Copy)]
pub struct AuthPermissions(whAuthPermissions);

impl AuthPermissions {
    /// Create an `AuthPermissions` with no permissions granted.
    pub fn none() -> Self {
        // SAFETY: zero-initialising a C POD struct is valid.
        Self(unsafe { core::mem::zeroed() })
    }

    /// Return a mutable reference to the inner `whAuthPermissions` for use
    /// with wolfHSM C macros that set individual permission bits.
    /// Key macros from `wolfhsm/wh_auth.h`:
    /// `WH_AUTH_SET_ALLOWED_GROUP`, `WH_AUTH_SET_ALLOWED_ACTION`,
    /// `WH_AUTH_CLEAR_ALLOWED_GROUP`, `WH_AUTH_CLEAR_ALLOWED_ACTION`,
    /// `WH_AUTH_SET_IS_ADMIN`.
    pub fn as_raw_mut(&mut self) -> &mut whAuthPermissions {
        &mut self.0
    }
}

impl From<whAuthPermissions> for AuthPermissions {
    fn from(raw: whAuthPermissions) -> Self {
        Self(raw)
    }
}

impl From<AuthPermissions> for whAuthPermissions {
    fn from(p: AuthPermissions) -> Self {
        p.0
    }
}

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
    ) -> Result<UserId, Error> {
        let cname = CString::new(username).map_err(|_| Error::BadArgs {
            msg: "username contains an interior NUL byte",
        })?;
        let auth_len = u16::try_from(auth_data.len()).map_err(|_| Error::BadArgs {
            msg: "auth_data exceeds u16::MAX bytes",
        })?;
        let mut out_rc: i32 = 0;
        let mut out_user_id: u16 = 0;
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
        Error::check(rc, "wh_Client_AuthLogin")?;
        Error::check(out_rc, "wh_Client_AuthLogin(server)")?;
        Ok(UserId(out_user_id))
    }

    /// Close a session identified by `user_id`.
    pub fn auth_logout(&mut self, user_id: UserId) -> Result<(), Error> {
        let mut out_rc: i32 = 0;
        // SAFETY: ctx_ptr is valid; out_rc is a valid stack allocation.
        let rc = unsafe { wh_Client_AuthLogout(self.ctx_ptr(), user_id.0, &mut out_rc) };
        Error::check(rc, "wh_Client_AuthLogout")?;
        Error::check(out_rc, "wh_Client_AuthLogout(server)")?;
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
    ) -> Result<UserId, Error> {
        let cname = CString::new(username).map_err(|_| Error::BadArgs {
            msg: "username contains an interior NUL byte",
        })?;
        let cred_len = u16::try_from(credentials.len()).map_err(|_| Error::BadArgs {
            msg: "credentials exceed u16::MAX bytes",
        })?;
        let mut out_rc: i32 = 0;
        let mut out_user_id: u16 = 0;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wh_Client_AuthUserAdd(
                self.ctx_ptr(),
                cname.as_ptr(),
                permissions.into(),
                method as u32,
                credentials.as_ptr() as *const core::ffi::c_void,
                cred_len,
                &mut out_rc,
                &mut out_user_id,
            )
        };
        Error::check(rc, "wh_Client_AuthUserAdd")?;
        Error::check(out_rc, "wh_Client_AuthUserAdd(server)")?;
        Ok(UserId(out_user_id))
    }

    /// Look up a user by name and return their `(UserId, AuthPermissions)`.
    pub fn auth_user_get(
        &mut self,
        username: &str,
    ) -> Result<(UserId, AuthPermissions), Error> {
        let cname = CString::new(username).map_err(|_| Error::BadArgs {
            msg: "username contains an interior NUL byte",
        })?;
        let mut out_rc: i32 = 0;
        let mut out_user_id: u16 = 0;
        let mut out_permissions = AuthPermissions::none();
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wh_Client_AuthUserGet(
                self.ctx_ptr(),
                cname.as_ptr(),
                &mut out_rc,
                &mut out_user_id,
                &mut out_permissions.0,
            )
        };
        Error::check(rc, "wh_Client_AuthUserGet")?;
        Error::check(out_rc, "wh_Client_AuthUserGet(server)")?;
        Ok((UserId(out_user_id), out_permissions))
    }

    /// Delete the user identified by `user_id`.
    pub fn auth_user_delete(&mut self, user_id: UserId) -> Result<(), Error> {
        let mut out_rc: i32 = 0;
        // SAFETY: ctx_ptr is valid; out_rc is a valid stack allocation.
        let rc = unsafe { wh_Client_AuthUserDelete(self.ctx_ptr(), user_id.0, &mut out_rc) };
        Error::check(rc, "wh_Client_AuthUserDelete")?;
        Error::check(out_rc, "wh_Client_AuthUserDelete(server)")?;
        Ok(())
    }

    /// Replace the permissions for user `user_id`.
    pub fn auth_user_set_permissions(
        &mut self,
        user_id: UserId,
        permissions: AuthPermissions,
    ) -> Result<(), Error> {
        let mut out_rc: i32 = 0;
        // SAFETY: ctx_ptr is valid; all other args are by-value or stack allocations.
        let rc = unsafe {
            wh_Client_AuthUserSetPermissions(
                self.ctx_ptr(),
                user_id.0,
                permissions.into(),
                &mut out_rc,
            )
        };
        Error::check(rc, "wh_Client_AuthUserSetPermissions")?;
        Error::check(out_rc, "wh_Client_AuthUserSetPermissions(server)")?;
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
    ) -> Result<(), Error> {
        let cur_len =
            u16::try_from(current_credentials.len()).map_err(|_| Error::BadArgs {
                msg: "current_credentials exceed u16::MAX bytes",
            })?;
        let new_len = u16::try_from(new_credentials.len()).map_err(|_| Error::BadArgs {
            msg: "new_credentials exceed u16::MAX bytes",
        })?;
        let mut out_rc: i32 = 0;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wh_Client_AuthUserSetCredentials(
                self.ctx_ptr(),
                user_id.0,
                method as u32,
                current_credentials.as_ptr() as *const core::ffi::c_void,
                cur_len,
                new_credentials.as_ptr() as *const core::ffi::c_void,
                new_len,
                &mut out_rc,
            )
        };
        Error::check(rc, "wh_Client_AuthUserSetCredentials")?;
        Error::check(out_rc, "wh_Client_AuthUserSetCredentials(server)")?;
        Ok(())
    }
}

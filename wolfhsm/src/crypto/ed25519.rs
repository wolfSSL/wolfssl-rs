use wolfhsm_sys::{wolfhsm_ed25519_make_key, wolfhsm_ed25519_sign, wolfhsm_ed25519_verify};

use crate::client::Client;
use crate::error::Error;
use crate::key::{with_key, KeyId};

/// Ed25519 key handle. The private key lives in the HSM key cache.
///
/// Keys are accessed exclusively through [`Client::with_ed25519_key`], which
/// generates a key, runs the provided closure, and always evicts it on exit —
/// including when the closure returns `Err`.
pub struct Ed25519Key {
    pub(crate) id: KeyId,
}

impl Ed25519Key {
    /// Generate an ephemeral Ed25519 key on the HSM (cached, not committed to NVM).
    pub(crate) fn generate(client: &mut Client) -> Result<Self, Error> {
        let mut key_id: u16 = KeyId::ERASED.0;
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wolfhsm_ed25519_make_key(client.ctx_ptr(), &mut key_id) };
        Error::check(rc, "wolfhsm_ed25519_make_key")?;
        if key_id == KeyId::ERASED.0 {
            return Err(Error::ProtocolError {
                msg: "wolfhsm_ed25519_make_key: server returned WH_KEYID_ERASED (0)",
            });
        }
        Ok(Ed25519Key { id: KeyId(key_id) })
    }

    /// Export the 32-byte Ed25519 public key.
    pub fn public_key(&self, client: &mut Client) -> Result<[u8; 32], Error> {
        let mut buf = [0u8; 32];
        let rc = unsafe {
            wolfhsm_sys::wolfhsm_ed25519_export_public(
                client.ctx_ptr(),
                self.id.0,
                buf.as_mut_ptr(),
            )
        };
        Error::check(rc, "wolfhsm_ed25519_export_public")?;
        Ok(buf)
    }

    /// Sign a message. Returns a 64-byte Ed25519 signature.
    pub fn sign(&self, client: &mut Client, msg: &[u8]) -> Result<[u8; 64], Error> {
        let msg_len = u32::try_from(msg.len()).map_err(|_| Error::BadArgs {
            msg: "message exceeds u32::MAX bytes",
        })?;
        let mut buf = [0u8; 64];
        let mut sig_len: u32 = 64;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wolfhsm_ed25519_sign(
                client.ctx_ptr(),
                self.id.0,
                msg.as_ptr(),
                msg_len,
                buf.as_mut_ptr(),
                &mut sig_len,
            )
        };
        Error::check(rc, "wolfhsm_ed25519_sign")?;
        if sig_len != 64 {
            return Err(Error::ProtocolError {
                msg: "wolfhsm_ed25519_sign: unexpected signature length",
            });
        }
        Ok(buf)
    }

    /// Verify a signature. Returns `Ok(())` if valid.
    pub fn verify(
        &self,
        client: &mut Client,
        msg: &[u8],
        sig: &[u8; 64],
    ) -> Result<(), Error> {
        let msg_len = u32::try_from(msg.len()).map_err(|_| Error::BadArgs {
            msg: "message exceeds u32::MAX bytes",
        })?;
        let mut result: core::ffi::c_int = 0;
        // SAFETY: all pointers are valid for the duration of this call.
        let rc = unsafe {
            wolfhsm_ed25519_verify(
                client.ctx_ptr(),
                self.id.0,
                sig.as_ptr(),
                64u32,
                msg.as_ptr(),
                msg_len,
                &mut result,
            )
        };
        Error::check(rc, "wolfhsm_ed25519_verify")?;
        if result != 1 {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

impl Drop for Ed25519Key {
    fn drop(&mut self) {
        if self.id != KeyId::ERASED {
            log::warn!(
                "wolfhsm: Ed25519Key (id={}) dropped without eviction — \
                 HSM cache slot leaked. Use with_ed25519_key().",
                self.id.0
            );
        }
    }
}

impl Client {
    /// Generate an Ed25519 key, run `f`, then always evict.
    ///
    /// Guarantees the HSM cache slot is released even when `f` returns `Err`.
    pub fn with_ed25519_key<F, R>(&mut self, f: F) -> Result<R, Error>
    where
        F: FnOnce(&Ed25519Key, &mut Client) -> Result<R, Error>,
    {
        let key = Ed25519Key::generate(self)?;
        with_key!(key, self, f)
    }
}

/// A [`signature::Signer`] adapter for [`Ed25519Key`].
///
/// Borrows both the key handle and the HSM client for its lifetime `'a`.
/// Passes the message directly to the HSM for signing (Ed25519 does not
/// pre-hash; the HSM handles the internal SHA-512 steps).
///
/// # Interior mutability
///
/// `signature::Signer::try_sign` only receives `&self`, but HSM operations
/// require `&mut Client`.  This wrapper uses `RefCell<&'a mut Client>` to
/// provide interior mutability safely within a single-threaded context.
/// `Ed25519Signer` is deliberately `!Sync` so it cannot be shared across
/// threads.
///
/// Create via [`Ed25519Key::signer`].
pub struct Ed25519Signer<'a> {
    key: &'a Ed25519Key,
    client: std::cell::RefCell<&'a mut Client>,
}

impl Ed25519Key {
    /// Wrap this key and a mutable client reference in an [`Ed25519Signer`].
    ///
    /// The returned signer implements [`signature::Signer<ed25519::Signature>`]
    /// and can be passed to any API that accepts that trait.
    pub fn signer<'a>(&'a self, client: &'a mut Client) -> Ed25519Signer<'a> {
        Ed25519Signer {
            key: self,
            client: std::cell::RefCell::new(client),
        }
    }
}

impl<'a> signature::Signer<ed25519::Signature> for Ed25519Signer<'a> {
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519::Signature, signature::Error> {
        let mut client = self.client.borrow_mut();
        let sig_bytes = self
            .key
            .sign(&mut **client, msg)
            .map_err(|_| signature::Error::new())?;
        Ok(ed25519::Signature::from_bytes(&sig_bytes))
    }
}

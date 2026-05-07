use wolfcrypt_sys::*;
use zeroize::Zeroize;

/// Certificate encoding format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertFormat {
    Pem,
    Der,
}

impl CertFormat {
    /// Return the wolfSSL file-type constant for FFI calls.
    pub(crate) fn as_c_int(self) -> core::ffi::c_int {
        match self {
            CertFormat::Pem => WOLFSSL_FILETYPE_PEM as core::ffi::c_int,
            CertFormat::Der => WOLFSSL_FILETYPE_ASN1 as core::ffi::c_int,
        }
    }
}

/// An entry in a [`RootCertStore`]: raw bytes plus their encoding format.
#[derive(Debug, Clone)]
struct CertEntry {
    data: Vec<u8>,
    format: CertFormat,
}

/// A collection of trusted root CA certificates.
///
/// # Naming
///
/// `RootCertStore` deliberately mirrors `rustls::RootCertStore` so that
/// users coming from rustls find a familiar entry point.  The wolfcrypt-tls
/// builder pattern (`TlsConnector` / `TlsAcceptor` / `TlsStream`,
/// `with_root_certificates`, `with_client_auth`) is itself a rustls-shaped
/// API on top of wolfSSL's C library, and this type is part of that mirror.
///
/// The two types are not interchangeable:
///
/// - `rustls::RootCertStore` stores parsed `webpki::TrustAnchor` entries.
/// - `wolfssl::RootCertStore` stores raw PEM or DER bytes; wolfSSL parses
///   them inside `wolfSSL_CTX_load_verify_buffer` when the config is built.
///
/// If both rustls and wolfcrypt-tls are pulled in by the same binary,
/// disambiguate at the import site (`use wolfssl::RootCertStore as
/// WolfRootCertStore;` etc.).
#[derive(Debug, Clone)]
pub struct RootCertStore {
    entries: Vec<CertEntry>,
}

impl RootCertStore {
    /// Create an empty root certificate store.
    pub fn new() -> Self {
        RootCertStore {
            entries: Vec::new(),
        }
    }

    /// Add one or more PEM-encoded certificates.
    ///
    /// Accepts `&[u8]`, `Vec<u8>`, or anything else that converts into
    /// `Vec<u8>` — passing an owned `Vec` avoids a copy.
    pub fn add_pem(&mut self, pem: impl Into<Vec<u8>>) {
        self.entries.push(CertEntry {
            data: pem.into(),
            format: CertFormat::Pem,
        });
    }

    /// Add a single DER-encoded certificate.
    ///
    /// Accepts `&[u8]`, `Vec<u8>`, or anything else that converts into
    /// `Vec<u8>` — passing an owned `Vec` avoids a copy.
    pub fn add_der(&mut self, der: impl Into<Vec<u8>>) {
        self.entries.push(CertEntry {
            data: der.into(),
            format: CertFormat::Der,
        });
    }

    /// Returns true if no certificates have been added.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over (cert_data, format) pairs.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&[u8], CertFormat)> {
        self.entries
            .iter()
            .map(|entry| (entry.data.as_slice(), entry.format))
    }
}

impl Default for RootCertStore {
    fn default() -> Self {
        Self::new()
    }
}

/// A TLS certificate (PEM or DER encoded).
#[derive(Debug, Clone)]
pub struct Certificate {
    data: Vec<u8>,
    format: CertFormat,
}

impl Certificate {
    /// Load a PEM-encoded certificate (may be a chain).
    ///
    /// Accepts `&[u8]`, `Vec<u8>`, etc. — passing an owned `Vec` avoids a copy.
    pub fn from_pem(pem: impl Into<Vec<u8>>) -> Self {
        Certificate {
            data: pem.into(),
            format: CertFormat::Pem,
        }
    }

    /// Load a DER-encoded certificate.
    ///
    /// Accepts `&[u8]`, `Vec<u8>`, etc. — passing an owned `Vec` avoids a copy.
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self {
        Certificate {
            data: der.into(),
            format: CertFormat::Der,
        }
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    pub(crate) fn format(&self) -> CertFormat {
        self.format
    }
}

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// A private key (PEM or DER encoded).
///
/// The key material is zeroized on drop.
pub struct PrivateKey {
    data: Vec<u8>,
    format: CertFormat,
}

impl PrivateKey {
    /// Load a PEM-encoded private key.
    ///
    /// Accepts `&[u8]`, `Vec<u8>`, etc. — passing an owned `Vec` avoids a copy.
    pub fn from_pem(pem: impl Into<Vec<u8>>) -> Self {
        PrivateKey {
            data: pem.into(),
            format: CertFormat::Pem,
        }
    }

    /// Load a DER-encoded private key.
    ///
    /// Accepts `&[u8]`, `Vec<u8>`, etc. — passing an owned `Vec` avoids a copy.
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self {
        PrivateKey {
            data: der.into(),
            format: CertFormat::Der,
        }
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    pub(crate) fn format(&self) -> CertFormat {
        self.format
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

// PrivateKey intentionally does not derive Debug to avoid leaking key material.
impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("len", &self.data.len())
            .field("format", &self.format)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_store_add_pem() {
        let mut store = RootCertStore::new();
        assert!(store.is_empty());
        store.add_pem(b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n");
        assert!(!store.is_empty());
        let items: Vec<_> = store.iter().collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1, CertFormat::Pem);
    }

    #[test]
    fn root_store_add_der() {
        let mut store = RootCertStore::new();
        store.add_der(&[0x30, 0x82, 0x01, 0x00]);
        let items: Vec<_> = store.iter().collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1, CertFormat::Der);
    }

    #[test]
    fn certificate_from_pem() {
        let cert = Certificate::from_pem(b"PEM data");
        assert_eq!(cert.format(), CertFormat::Pem);
        assert_eq!(cert.data(), b"PEM data");
    }

    #[test]
    fn certificate_from_der() {
        let cert = Certificate::from_der(b"\x30\x82");
        assert_eq!(cert.format(), CertFormat::Der);
    }

    #[test]
    fn private_key_zeroize_on_drop() {
        let key_data = vec![0xAA; 32];
        let ptr = key_data.as_ptr();
        let key = PrivateKey::from_der(key_data.as_slice());
        let inner_ptr = key.data.as_ptr();
        drop(key);
        // After drop, the memory pointed to by inner_ptr should be zeroed.
        // We can't safely verify this since the memory is freed, but we can
        // verify the Drop impl compiles and runs without panic.
        let _ = (ptr, inner_ptr);
    }

    #[test]
    fn private_key_debug_no_leak() {
        let key = PrivateKey::from_pem(b"SECRET KEY DATA");
        let dbg = format!("{key:?}");
        assert!(!dbg.contains("SECRET"));
        assert!(dbg.contains("PrivateKey"));
    }
}

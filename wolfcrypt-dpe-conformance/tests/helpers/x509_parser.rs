//! Minimal X.509 certificate parser for conformance tests.
//! Uses the `x509-cert` and `der` crates for ASN.1 parsing,
//! and `p384`/`p256` for independent signature verification.

use der::{Decode, Encode};
use x509_cert::Certificate;

/// Parsed certificate fields for test assertions.
pub struct ParsedCert {
    pub version: u8,
    pub serial_number: Vec<u8>,
    pub issuer_der: Vec<u8>,
    pub subject_der: Vec<u8>,
    pub public_key_bytes: Vec<u8>,
    pub signature_algorithm_oid: String,
    pub signature_bytes: Vec<u8>,
    pub tbs_der: Vec<u8>,
    pub is_ca: bool,
    pub extensions: Vec<ParsedExtension>,
}

pub struct ParsedExtension {
    pub oid: String,
    pub critical: bool,
    pub value: Vec<u8>,
}

// Well-known OIDs
pub const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
pub const OID_KEY_USAGE: &str = "2.5.29.15";
pub const OID_EXT_KEY_USAGE: &str = "2.5.29.37";
pub const OID_SUBJECT_KEY_ID: &str = "2.5.29.14";
pub const OID_AUTHORITY_KEY_ID: &str = "2.5.29.35";
pub const OID_SUBJECT_ALT_NAME: &str = "2.5.29.17";
pub const OID_DICE_MULTI_TCB_INFO: &str = "2.23.133.5.4.5";
pub const OID_DICE_UEID: &str = "2.23.133.5.4.4";

/// Parse a DER-encoded X.509 certificate.
pub fn parse_cert(der_bytes: &[u8]) -> Result<ParsedCert, String> {
    let cert = Certificate::from_der(der_bytes)
        .map_err(|e| format!("Certificate DER parse failed: {e}"))?;

    let tbs = &cert.tbs_certificate;

    // Version (0 = v1, 2 = v3)
    let version = tbs.version as u8;

    // Serial number
    let serial_number = tbs.serial_number.as_bytes().to_vec();

    // Issuer and Subject as raw DER
    let issuer_der = tbs
        .issuer
        .to_der()
        .map_err(|e| format!("Issuer DER encode: {e}"))?;
    let subject_der = tbs
        .subject
        .to_der()
        .map_err(|e| format!("Subject DER encode: {e}"))?;

    // Public key (raw BIT STRING value)
    let public_key_bytes = tbs
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec();

    // Signature algorithm OID
    let signature_algorithm_oid = cert.signature_algorithm.oid.to_string();

    // Signature value
    let signature_bytes = cert.signature.raw_bytes().to_vec();

    // TBS certificate DER
    let tbs_der = tbs.to_der().map_err(|e| format!("TBS DER encode: {e}"))?;

    // Basic Constraints: CA flag
    let mut is_ca = false;
    let mut extensions = Vec::new();

    if let Some(exts) = &tbs.extensions {
        for ext in exts.iter() {
            let oid_str = ext.extn_id.to_string();
            let critical = ext.critical;
            let value = ext.extn_value.as_bytes().to_vec();

            if oid_str == OID_BASIC_CONSTRAINTS {
                // Parse BasicConstraints: SEQUENCE { BOOLEAN ca, ... }
                // Simple: if value contains 0xFF byte after SEQUENCE tag, CA=true
                if value.len() >= 4 && value.contains(&0xFF) {
                    is_ca = true;
                }
            }

            extensions.push(ParsedExtension {
                oid: oid_str,
                critical,
                value,
            });
        }
    }

    Ok(ParsedCert {
        version,
        serial_number,
        issuer_der,
        subject_der,
        public_key_bytes,
        signature_algorithm_oid,
        signature_bytes,
        tbs_der,
        is_ca,
        extensions,
    })
}

/// Check if cert has extension with given OID.
pub fn has_extension(cert: &ParsedCert, oid: &str) -> bool {
    cert.extensions.iter().any(|e| e.oid == oid)
}

/// Get extension by OID, if present.
pub fn get_extension<'a>(cert: &'a ParsedCert, oid: &str) -> Option<&'a ParsedExtension> {
    cert.extensions.iter().find(|e| e.oid == oid)
}

/// Verify the ECDSA signature on a certificate using an issuer public key.
/// `issuer_pubkey` is SEC1 uncompressed format (04 || x || y).
pub fn verify_cert_signature_p384(cert: &ParsedCert, issuer_pubkey: &[u8]) -> Result<(), String> {
    use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    use sha2::{Digest, Sha384};

    let vk = VerifyingKey::from_sec1_bytes(issuer_pubkey)
        .map_err(|e| format!("P384 VerifyingKey: {e}"))?;

    // Hash the TBS certificate with SHA-384
    let tbs_hash = Sha384::digest(&cert.tbs_der);

    let sig = Signature::from_der(&cert.signature_bytes)
        .map_err(|e| format!("P384 Signature DER: {e}"))?;

    vk.verify_prehash(&tbs_hash, &sig)
        .map_err(|e| format!("P384 cert verify: {e}"))
}

/// Verify ECDSA-P256-SHA256 cert signature.
pub fn verify_cert_signature_p256(cert: &ParsedCert, issuer_pubkey: &[u8]) -> Result<(), String> {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    use sha2::{Digest, Sha256};

    let vk = VerifyingKey::from_sec1_bytes(issuer_pubkey)
        .map_err(|e| format!("P256 VerifyingKey: {e}"))?;

    let tbs_hash = Sha256::digest(&cert.tbs_der);

    let sig = Signature::from_der(&cert.signature_bytes)
        .map_err(|e| format!("P256 Signature DER: {e}"))?;

    vk.verify_prehash(&tbs_hash, &sig)
        .map_err(|e| format!("P256 cert verify: {e}"))
}

/// Check for DICE MultiTcbInfo extension.
pub fn has_dice_tcb_info(cert: &ParsedCert) -> bool {
    has_extension(cert, OID_DICE_MULTI_TCB_INFO)
}

/// Check for DICE UEID extension.
pub fn has_dice_ueid(cert: &ParsedCert) -> bool {
    has_extension(cert, OID_DICE_UEID)
}

//! Certificate ASN.1 structure validation tests.
//! Generate a cert from DPE via CertifyKey, then parse and validate its structure.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{
    CertifyKeyFlags, CertifyKeyP384Cmd, CommandExecution, DeriveContextCmd, DeriveContextFlags,
};
use caliptra_dpe::context::ContextHandle;
use caliptra_dpe::dpe_instance::DpeInstance;
use caliptra_dpe::response::{CertifyKeyResp, Response};
use caliptra_dpe::tci::TciMeasurement;
use caliptra_dpe::{DpeProfile, State};

/// Helper: create a DPE instance, derive a child, certify the child, return cert bytes.
fn generate_test_cert() -> Vec<u8> {
    CfiCounter::reset_for_test();
    let support = helpers::dpe_harness::DEFAULT_SUPPORT;
    let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
    let mut env = helpers::dpe_harness::make_ref_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384)
        .expect("DPE init should succeed");

    let derive_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0x42; 48]),
        flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
        tci_type: 0,
        target_locality: helpers::dpe_harness::LOCALITY,
        svn: 0,
    };
    match derive_cmd
        .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
        .expect("DeriveContext should succeed")
    {
        Response::DeriveContext(r) => r.handle,
        _ => panic!("Expected DeriveContext response"),
    };

    let certify_cmd = CertifyKeyP384Cmd {
        handle: ContextHandle::default(),
        format: 0, // X.509
        label: [0xAA; 48],
        flags: CertifyKeyFlags::empty(),
    };
    match certify_cmd
        .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
        .expect("CertifyKey should succeed")
    {
        Response::CertifyKey(CertifyKeyResp::P384(r)) => {
            r.cert[..r.cert_size as usize].to_vec()
        }
        _ => panic!("Expected CertifyKey P384 response"),
    }
}

#[test]
fn cert_is_valid_der() {
    let cert_bytes = generate_test_cert();
    let result = helpers::x509_parser::parse_cert(&cert_bytes);
    assert!(
        result.is_ok(),
        "CertifyKey output should parse as valid DER: {:?}",
        result.err()
    );
}

#[test]
fn cert_has_version_3() {
    let cert_bytes = generate_test_cert();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    assert_eq!(
        parsed.version, 2,
        "X.509 v3 encodes version as 2, got {}",
        parsed.version
    );
}

#[test]
fn cert_has_serial_number() {
    let cert_bytes = generate_test_cert();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    assert!(
        !parsed.serial_number.is_empty(),
        "Certificate serial number must be non-empty"
    );
}

#[test]
fn cert_has_signature_algorithm() {
    let cert_bytes = generate_test_cert();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    assert!(
        parsed.signature_algorithm_oid.contains("1.2.840.10045.4.3"),
        "Signature algorithm OID should contain ECDSA prefix '1.2.840.10045.4.3', got '{}'",
        parsed.signature_algorithm_oid
    );
}

#[test]
fn cert_has_issuer() {
    let cert_bytes = generate_test_cert();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    assert!(
        !parsed.issuer_der.is_empty(),
        "Certificate issuer DER must be non-empty"
    );
}

#[test]
fn cert_has_subject() {
    let cert_bytes = generate_test_cert();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    assert!(
        !parsed.subject_der.is_empty(),
        "Certificate subject DER must be non-empty"
    );
}

#[test]
fn cert_has_public_key() {
    let cert_bytes = generate_test_cert();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    assert!(
        !parsed.public_key_bytes.is_empty(),
        "Certificate public key bytes must be non-empty"
    );
}

#[test]
fn cert_has_extensions() {
    let cert_bytes = generate_test_cert();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    assert!(
        !parsed.extensions.is_empty(),
        "Certificate must have at least one extension"
    );
}

#[test]
fn cert_public_key_parseable() {
    let cert_bytes = generate_test_cert();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    let pk_bytes = &parsed.public_key_bytes;
    assert_eq!(
        pk_bytes.len(),
        97,
        "P-384 uncompressed public key should be 97 bytes (04 + 48 + 48), got {}",
        pk_bytes.len()
    );
    assert_eq!(
        pk_bytes[0], 0x04,
        "P-384 uncompressed public key should start with 0x04, got 0x{:02x}",
        pk_bytes[0]
    );
    let result = p384::PublicKey::from_sec1_bytes(pk_bytes);
    assert!(
        result.is_ok(),
        "Public key bytes should parse as valid P-384 point: {:?}",
        result.err()
    );
}

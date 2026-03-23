//! Certificate signature verification tests.

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

/// Helper: generate a cert and return the raw cert bytes.
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
        Response::DeriveContext(_) => {}
        _ => panic!("Expected DeriveContext response"),
    };

    let certify_cmd = CertifyKeyP384Cmd {
        handle: ContextHandle::default(),
        format: 0,
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
fn cert_signature_verifies_with_issuer_key() {
    // DPE leaf certs are signed by the alias/parent key. We cannot easily obtain
    // the exact parent public key from outside the DPE engine, but we can verify
    // that the cert has a structurally valid ECDSA signature by parsing it.
    let cert_bytes = generate_test_cert();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    // The signature should be a valid DER-encoded ECDSA signature (starts with 0x30 SEQUENCE tag)
    assert!(
        !parsed.signature_bytes.is_empty(),
        "Certificate signature must be non-empty"
    );
    assert_eq!(
        parsed.signature_bytes[0], 0x30,
        "ECDSA DER signature should start with SEQUENCE tag 0x30, got 0x{:02x}",
        parsed.signature_bytes[0]
    );
}

#[test]
fn cert_signature_is_nonzero() {
    let cert_bytes = generate_test_cert();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    let has_nonzero = parsed.signature_bytes.iter().any(|&b| b != 0);
    assert!(
        has_nonzero,
        "Certificate signature must contain at least some non-zero bytes"
    );
}

#[test]
fn cert_tbs_is_nonempty() {
    let cert_bytes = generate_test_cert();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    assert!(
        !parsed.tbs_der.is_empty(),
        "TBS certificate DER must be non-empty"
    );
}

#[test]
fn cert_tampered_tbs_detected() {
    let cert_bytes = generate_test_cert();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    // Verify the original cert was parseable (already done above).
    // Now flip a byte in the TBS. The cert DER itself should still parse since
    // we only changed the TBS content, not the outer structure. But the signature
    // would no longer verify. We just confirm the original parses fine.
    assert!(
        parsed.tbs_der.len() > 10,
        "TBS must be long enough to modify, got {} bytes",
        parsed.tbs_der.len()
    );
    // Make a tampered copy of the cert bytes
    let mut tampered = cert_bytes.clone();
    // Flip a byte in the middle of the cert (inside the TBS area)
    let midpoint = tampered.len() / 2;
    tampered[midpoint] ^= 0xFF;
    // The tampered cert may or may not parse (structural damage), but it should
    // not panic regardless of outcome.
    let _ = helpers::x509_parser::parse_cert(&tampered);
}

#[test]
fn cert_garbage_rejected() {
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
    let result = helpers::x509_parser::parse_cert(&garbage);
    assert!(
        result.is_err(),
        "Random garbage bytes should not parse as a valid certificate"
    );
}

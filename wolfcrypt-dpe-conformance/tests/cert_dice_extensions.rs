//! DICE-specific X.509 extension tests.

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
use helpers::x509_parser::{
    has_dice_tcb_info, has_dice_ueid, has_extension, parse_cert, OID_BASIC_CONSTRAINTS,
    OID_KEY_USAGE,
};

/// Helper: generate a cert with a derived context.
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
fn multi_tcb_info_present() {
    let cert_bytes = generate_test_cert();
    let parsed = parse_cert(&cert_bytes).expect("cert should parse");
    assert!(
        has_dice_tcb_info(&parsed),
        "Certificate must contain DICE MultiTcbInfo extension (OID 2.23.133.5.4.5)"
    );
}

#[test]
fn ueid_present() {
    let cert_bytes = generate_test_cert();
    let parsed = parse_cert(&cert_bytes).expect("cert should parse");
    assert!(
        has_dice_ueid(&parsed),
        "Certificate must contain DICE UEID extension (OID 2.23.133.5.4.4)"
    );
}

#[test]
fn basic_constraints_present() {
    let cert_bytes = generate_test_cert();
    let parsed = parse_cert(&cert_bytes).expect("cert should parse");
    assert!(
        has_extension(&parsed, OID_BASIC_CONSTRAINTS),
        "Certificate must contain BasicConstraints extension (OID 2.5.29.19)"
    );
}

#[test]
fn key_usage_present() {
    let cert_bytes = generate_test_cert();
    let parsed = parse_cert(&cert_bytes).expect("cert should parse");
    assert!(
        has_extension(&parsed, OID_KEY_USAGE),
        "Certificate must contain KeyUsage extension (OID 2.5.29.15)"
    );
}

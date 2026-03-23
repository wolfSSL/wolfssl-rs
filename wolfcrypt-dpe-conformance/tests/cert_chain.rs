//! Certificate chain validation tests.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{
    CertifyKeyFlags, CertifyKeyP384Cmd, CommandExecution, DeriveContextCmd, DeriveContextFlags,
    GetCertificateChainCmd,
};
use caliptra_dpe::context::ContextHandle;
use caliptra_dpe::dpe_instance::DpeInstance;
use caliptra_dpe::response::{CertifyKeyResp, Response};
use caliptra_dpe::tci::TciMeasurement;
use caliptra_dpe::{DpeProfile, State};

/// Helper: set up DPE, derive a child, certify it, return (cert_bytes, parsed_cert).
fn setup_and_certify() -> Vec<u8> {
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
fn get_chain_returns_cert_data() {
    CfiCounter::reset_for_test();
    let support = helpers::dpe_harness::DEFAULT_SUPPORT;
    let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
    let mut env = helpers::dpe_harness::make_ref_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384)
        .expect("DPE init should succeed");

    let chain_cmd = GetCertificateChainCmd {
        offset: 0,
        size: 2048,
    };
    let resp = chain_cmd
        .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
        .expect("GetCertificateChain should succeed");
    match resp {
        Response::GetCertificateChain(r) => {
            assert!(
                r.certificate_size > 0,
                "GetCertificateChain should return non-empty certificate data, got size={}",
                r.certificate_size
            );
        }
        _ => panic!("Expected GetCertificateChain response"),
    }
}

#[test]
fn chain_data_is_valid_der() {
    CfiCounter::reset_for_test();
    let support = helpers::dpe_harness::DEFAULT_SUPPORT;
    let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
    let mut env = helpers::dpe_harness::make_ref_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384)
        .expect("DPE init should succeed");

    let chain_cmd = GetCertificateChainCmd {
        offset: 0,
        size: 2048,
    };
    let resp = chain_cmd
        .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
        .expect("GetCertificateChain should succeed");
    match resp {
        Response::GetCertificateChain(r) => {
            let data = &r.certificate_chain[..r.certificate_size as usize];
            // Check that it contains at least one SEQUENCE tag (0x30) at the start
            assert!(
                !data.is_empty() && data[0] == 0x30,
                "Chain data should start with DER SEQUENCE tag 0x30, got 0x{:02x}",
                if data.is_empty() { 0x00 } else { data[0] }
            );
        }
        _ => panic!("Expected GetCertificateChain response"),
    }
}

#[test]
fn leaf_cert_not_ca() {
    let cert_bytes = setup_and_certify();
    let parsed = helpers::x509_parser::parse_cert(&cert_bytes)
        .expect("cert should parse");
    assert!(
        !parsed.is_ca,
        "Leaf certificate from CertifyKey must not have CA=true in BasicConstraints"
    );
}

#[test]
fn certify_after_derive_different_pubkey() {
    // Derive with measurement A, certify -> pk_A
    CfiCounter::reset_for_test();
    let support = helpers::dpe_harness::DEFAULT_SUPPORT;

    let pk_a = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_ref_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384)
            .expect("DPE init should succeed");

        let derive_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: TciMeasurement([0xAA; 48]),
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        match derive_cmd
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap()
        {
            Response::DeriveContext(_) => {}
            _ => panic!("Expected DeriveContext response"),
        };

        let certify_cmd = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            format: 0,
            label: [0xCC; 48],
            flags: CertifyKeyFlags::empty(),
        };
        match certify_cmd
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap()
        {
            Response::CertifyKey(CertifyKeyResp::P384(r)) => {
                let mut pk = Vec::with_capacity(97);
                pk.push(0x04);
                pk.extend_from_slice(&r.derived_pubkey_x);
                pk.extend_from_slice(&r.derived_pubkey_y);
                pk
            }
            _ => panic!("Expected CertifyKey P384 response"),
        }
    };

    // Derive with measurement B, certify -> pk_B
    CfiCounter::reset_for_test();
    let pk_b = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_ref_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384)
            .expect("DPE init should succeed");

        let derive_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: TciMeasurement([0xBB; 48]),
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        match derive_cmd
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap()
        {
            Response::DeriveContext(_) => {}
            _ => panic!("Expected DeriveContext response"),
        };

        let certify_cmd = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            format: 0,
            label: [0xCC; 48],
            flags: CertifyKeyFlags::empty(),
        };
        match certify_cmd
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap()
        {
            Response::CertifyKey(CertifyKeyResp::P384(r)) => {
                let mut pk = Vec::with_capacity(97);
                pk.push(0x04);
                pk.extend_from_slice(&r.derived_pubkey_x);
                pk.extend_from_slice(&r.derived_pubkey_y);
                pk
            }
            _ => panic!("Expected CertifyKey P384 response"),
        }
    };

    assert_ne!(
        pk_a, pk_b,
        "Different measurements must produce different public keys after CertifyKey"
    );
}

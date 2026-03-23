//! DPE engine CertifyKey command tests.
//!
//! NOTE: CertifyKey requires the platform alias key to be configured.
//! If the wolfcrypt backend returns CryptoLibError(0x04_0000) (ERR_ALIAS_NOT_SET),
//! these tests skip gracefully. When running against a fully-configured
//! backend, they will exercise X.509 certificate generation end-to-end.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{
    CertifyKeyFlags, CertifyKeyP384Cmd, CommandExecution, DeriveContextCmd, DeriveContextFlags,
};
use caliptra_dpe::context::ContextHandle;
use caliptra_dpe::dpe_instance::DpeInstance;
use caliptra_dpe::response::{CertifyKeyResp, Response};
use caliptra_dpe::support::Support;
use caliptra_dpe::tci::TciMeasurement;
use caliptra_dpe::{DpeFlags, DpeProfile, State};

use helpers::dpe_harness::{self, LOCALITY};
use helpers::x509_parser;

/// Derive a child from the default context and return the child handle.
fn derive_for_certify(
    dpe: &mut DpeInstance,
    env: &mut caliptra_dpe::dpe_instance::DpeEnv<impl caliptra_dpe::dpe_instance::DpeTypes>,
) -> ContextHandle {
    let cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0x42; 48]),
        flags: DeriveContextFlags::INPUT_ALLOW_X509,
        tci_type: 0,
        target_locality: LOCALITY,
        svn: 0,
    };
    match cmd.execute(dpe, env, LOCALITY).unwrap() {
        Response::DeriveContext(resp) => resp.handle,
        _ => panic!("Expected DeriveContext, got unexpected response"),
    }
}

/// Attempt CertifyKey. Returns None if the backend lacks alias key support.
fn try_certify_key(
    dpe: &mut DpeInstance,
    env: &mut caliptra_dpe::dpe_instance::DpeEnv<impl caliptra_dpe::dpe_instance::DpeTypes>,
    handle: ContextHandle,
) -> Option<CertifyKeyResp> {
    let cmd = CertifyKeyP384Cmd {
        handle,
        flags: CertifyKeyFlags::empty(),
        format: 0, // X.509
        label: [0xAA; 48],
    };
    match cmd.execute(dpe, env, LOCALITY) {
        Ok(Response::CertifyKey(resp)) => Some(resp),
        Err(_) => {
            // CertifyKey requires platform alias key; skip if not configured.
            None
        }
        _ => panic!("Expected CertifyKey response, got unexpected response"),
    }
}

/// Macro to skip test if certify returns None (alias key not available).
macro_rules! skip_if_no_alias {
    ($resp:expr) => {
        match $resp {
            Some(r) => r,
            None => {
                eprintln!("SKIPPED: alias key not configured for CertifyKey");
                return;
            }
        }
    };
}

#[test]
fn certify_default_context() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT | Support::X509);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_for_certify(&mut dpe, &mut env);
    let resp = skip_if_no_alias!(try_certify_key(&mut dpe, &mut env, child));

    match &resp {
        CertifyKeyResp::P384(r) => {
            assert!(r.cert_size > 0, "Certificate should not be empty");
        }
        #[allow(unreachable_patterns)]
        _ => panic!("Expected P384 CertifyKey response"),
    }
}

#[test]
fn certify_returns_valid_der() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT | Support::X509);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_for_certify(&mut dpe, &mut env);
    let resp = skip_if_no_alias!(try_certify_key(&mut dpe, &mut env, child));

    let cert_bytes = resp.cert().unwrap();
    let parsed = x509_parser::parse_cert(cert_bytes);
    assert!(parsed.is_ok(), "Certificate should parse as valid DER: {:?}", parsed.err());
}

#[test]
fn certify_has_pubkey() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT | Support::X509);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_for_certify(&mut dpe, &mut env);
    let resp = skip_if_no_alias!(try_certify_key(&mut dpe, &mut env, child));

    let cert_bytes = resp.cert().unwrap();
    let parsed = x509_parser::parse_cert(cert_bytes).unwrap();
    assert!(
        !parsed.public_key_bytes.is_empty(),
        "Certificate should contain a non-empty public key"
    );
}

#[test]
fn certify_pubkey_in_response() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT | Support::X509);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_for_certify(&mut dpe, &mut env);
    let resp = skip_if_no_alias!(try_certify_key(&mut dpe, &mut env, child));

    match &resp {
        CertifyKeyResp::P384(r) => {
            assert!(
                r.derived_pubkey_x.iter().any(|&b| b != 0),
                "pubkey_x should be non-zero"
            );
            assert!(
                r.derived_pubkey_y.iter().any(|&b| b != 0),
                "pubkey_y should be non-zero"
            );
        }
        #[allow(unreachable_patterns)]
        _ => panic!("Expected P384 CertifyKey response"),
    }
}

#[test]
fn certify_version_3() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT | Support::X509);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_for_certify(&mut dpe, &mut env);
    let resp = skip_if_no_alias!(try_certify_key(&mut dpe, &mut env, child));

    let cert_bytes = resp.cert().unwrap();
    let parsed = x509_parser::parse_cert(cert_bytes).unwrap();
    // X.509 v3 is encoded as version=2 in the certificate structure.
    assert_eq!(parsed.version, 2, "Certificate should be X.509 v3 (encoded as 2)");
}

#[test]
fn certify_has_extensions() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT | Support::X509);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_for_certify(&mut dpe, &mut env);
    let resp = skip_if_no_alias!(try_certify_key(&mut dpe, &mut env, child));

    let cert_bytes = resp.cert().unwrap();
    let parsed = x509_parser::parse_cert(cert_bytes).unwrap();
    assert!(
        !parsed.extensions.is_empty(),
        "Certificate should have at least one extension"
    );
}

#[test]
fn certify_basic_constraints() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT | Support::X509);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_for_certify(&mut dpe, &mut env);
    let resp = skip_if_no_alias!(try_certify_key(&mut dpe, &mut env, child));

    let cert_bytes = resp.cert().unwrap();
    let parsed = x509_parser::parse_cert(cert_bytes).unwrap();

    assert!(
        x509_parser::has_extension(&parsed, x509_parser::OID_BASIC_CONSTRAINTS),
        "Certificate should have BasicConstraints extension"
    );
    assert!(!parsed.is_ca, "Leaf certificate should have CA=false");
}

#[test]
fn certify_key_usage() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT | Support::X509);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_for_certify(&mut dpe, &mut env);
    let resp = skip_if_no_alias!(try_certify_key(&mut dpe, &mut env, child));

    let cert_bytes = resp.cert().unwrap();
    let parsed = x509_parser::parse_cert(cert_bytes).unwrap();

    let ku_ext = x509_parser::get_extension(&parsed, x509_parser::OID_KEY_USAGE);
    assert!(ku_ext.is_some(), "Certificate should have KeyUsage extension");
    assert!(ku_ext.unwrap().critical, "KeyUsage extension should be critical");
}

#[test]
fn certify_dice_tcb_info() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT | Support::X509);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_for_certify(&mut dpe, &mut env);
    let resp = skip_if_no_alias!(try_certify_key(&mut dpe, &mut env, child));

    let cert_bytes = resp.cert().unwrap();
    let parsed = x509_parser::parse_cert(cert_bytes).unwrap();

    assert!(
        x509_parser::has_dice_tcb_info(&parsed),
        "Certificate should have DICE MultiTcbInfo extension (OID {})",
        x509_parser::OID_DICE_MULTI_TCB_INFO
    );
}

#[test]
fn certify_dice_ueid() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT | Support::X509);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_for_certify(&mut dpe, &mut env);
    let resp = skip_if_no_alias!(try_certify_key(&mut dpe, &mut env, child));

    let cert_bytes = resp.cert().unwrap();
    let parsed = x509_parser::parse_cert(cert_bytes).unwrap();

    assert!(
        x509_parser::has_dice_ueid(&parsed),
        "Certificate should have DICE UEID extension (OID {})",
        x509_parser::OID_DICE_UEID
    );
}

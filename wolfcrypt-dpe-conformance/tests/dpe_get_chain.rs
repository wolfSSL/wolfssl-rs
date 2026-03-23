//! DPE engine GetCertificateChain command tests.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{CommandExecution, GetCertificateChainCmd};
use caliptra_dpe::response::Response;
use caliptra_dpe::support::Support;

use helpers::dpe_harness::{self, LOCALITY};

#[test]
fn get_chain_returns_data() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(dpe_harness::DEFAULT_SUPPORT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let cmd = GetCertificateChainCmd {
        offset: 0,
        size: 2048,
    };
    let result = cmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "GetCertificateChain failed: {:?}", result.err());
    match result.unwrap() {
        Response::GetCertificateChain(resp) => {
            assert!(
                resp.certificate_size > 0,
                "Certificate chain should contain data"
            );
        }
        _ => panic!("Expected GetCertificateChain response, got unexpected response"),
    }
}

#[test]
fn get_chain_valid_offset() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(dpe_harness::DEFAULT_SUPPORT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let cmd = GetCertificateChainCmd {
        offset: 0,
        size: 2048,
    };
    let result = cmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "GetCertificateChain with offset=0 failed: {:?}", result.err());
    match result.unwrap() {
        Response::GetCertificateChain(resp) => {
            // Should return some certificate data.
            assert!(
                resp.certificate_chain[..resp.certificate_size as usize]
                    .iter()
                    .any(|&b| b != 0),
                "Chain data should not be all zeros"
            );
        }
        _ => panic!("Expected GetCertificateChain response, got unexpected response"),
    }
}

#[test]
fn get_chain_zero_size() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(dpe_harness::DEFAULT_SUPPORT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let cmd = GetCertificateChainCmd {
        offset: 0,
        size: 0,
    };
    let result = cmd.execute(&mut dpe, &mut env, LOCALITY);
    // Size=0 should either succeed with empty data or return an error -- both are acceptable.
    // We just ensure it does not panic.
    match result {
        Ok(Response::GetCertificateChain(resp)) => {
            assert_eq!(resp.certificate_size, 0, "Zero-size request should return zero bytes");
        }
        Ok(_) => panic!("Unexpected response type"),
        Err(_) => {
            // Some implementations may reject size=0; that is acceptable.
        }
    }
}

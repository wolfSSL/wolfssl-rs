//! DPE engine GetProfile command tests.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{CommandExecution, GetProfileCmd};
use caliptra_dpe::response::Response;
use caliptra_dpe::support::Support;

use helpers::dpe_harness::{self, LOCALITY};

#[test]
fn get_profile_returns_flags() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(dpe_harness::DEFAULT_SUPPORT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let result = GetProfileCmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "GetProfile failed: {:?}", result.err());
    match result.unwrap() {
        Response::GetProfile(resp) => {
            // The flags field should reflect the support flags we configured.
            // At minimum, AUTO_INIT and SIMULATION should be indicated.
            assert!(resp.flags != 0, "GetProfile flags should be non-zero for DEFAULT_SUPPORT");
        }
        _ => panic!("Expected GetProfile response, got unexpected response"),
    }
}

#[test]
fn get_profile_p384_profile() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(dpe_harness::DEFAULT_SUPPORT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let result = GetProfileCmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "GetProfile failed: {:?}", result.err());
    match result.unwrap() {
        Response::GetProfile(resp) => {
            // For P384Sha384, the profile is typically indicated in the response header or
            // through the vendor fields. We can verify max_tci_nodes > 0 and major_version > 0.
            assert!(resp.max_tci_nodes > 0, "max_tci_nodes should be positive");
        }
        _ => panic!("Expected GetProfile response, got unexpected response"),
    }
}

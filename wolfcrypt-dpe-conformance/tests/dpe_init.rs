//! DPE engine initialization tests.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{CommandExecution, GetProfileCmd, InitCtxCmd};
use caliptra_dpe::context::ContextHandle;
use caliptra_dpe::dpe_instance::{DpeEnv, DpeInstance};
use caliptra_dpe::response::Response;
use caliptra_dpe::support::Support;
use caliptra_dpe::{DpeFlags, DpeProfile, State};

use helpers::dpe_harness::{self, LOCALITY};

#[test]
fn auto_init_creates_default_context() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(dpe_harness::DEFAULT_SUPPORT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    // GetProfile should succeed on an auto-initialized instance.
    let result = GetProfileCmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "GetProfile failed: {:?}", result.err());
    match result.unwrap() {
        Response::GetProfile(resp) => {
            assert!(resp.max_tci_nodes > 0, "max_tci_nodes should be > 0");
        }
        _ => panic!("Expected GetProfile response, got unexpected response"),
    }
}

#[test]
fn manual_init_simulation() {
    CfiCounter::reset_for_test();
    let support = Support::SIMULATION;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    let result = InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "InitCtxCmd simulation failed: {:?}", result.err());
    match result.unwrap() {
        Response::InitCtx(resp) => {
            // Simulation contexts get non-default handles.
            assert_ne!(resp.handle.0, [0u8; 16], "simulation handle should not be all zeros");
        }
        _ => panic!("Expected InitCtx response, got unexpected response"),
    }
}

#[test]
fn init_default_context_fails_when_already_initialized() {
    CfiCounter::reset_for_test();
    let support = Support::AUTO_INIT;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    // AUTO_INIT already created the default context. Trying to initialize again should fail.
    let result = InitCtxCmd::new_use_default().execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_err(), "Expected error when re-initializing default context");
}

#[test]
fn double_simulation_init() {
    CfiCounter::reset_for_test();
    let support = Support::SIMULATION;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    let result1 = InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, LOCALITY);
    assert!(result1.is_ok(), "First simulation init failed: {:?}", result1.err());

    let result2 = InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, LOCALITY);
    assert!(result2.is_ok(), "Second simulation init failed: {:?}", result2.err());
}

#[test]
fn init_response_has_handle() {
    CfiCounter::reset_for_test();
    let support = Support::SIMULATION;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    let result = InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "InitCtxCmd failed: {:?}", result.err());
    match result.unwrap() {
        Response::InitCtx(resp) => {
            assert!(
                resp.handle.0.iter().any(|&b| b != 0),
                "Simulation context handle should have at least one non-zero byte"
            );
        }
        _ => panic!("Expected InitCtx response, got unexpected response"),
    }
}

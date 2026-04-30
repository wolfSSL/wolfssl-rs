//! DPE engine DestroyContext command tests.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{
    CommandExecution, DeriveContextCmd, DeriveContextFlags, DestroyCtxCmd, InitCtxCmd, SignFlags,
    SignP384Cmd,
};
use caliptra_dpe::context::ContextHandle;
use caliptra_dpe::dpe_instance::DpeInstance;
use caliptra_dpe::response::Response;
use caliptra_dpe::support::Support;
use caliptra_dpe::tci::TciMeasurement;
use caliptra_dpe::{DpeFlags, DpeProfile, State};

use helpers::dpe_harness::{self, LOCALITY};

/// Derive a child from default, returning child handle.
fn derive_child(
    dpe: &mut DpeInstance,
    env: &mut caliptra_dpe::dpe_instance::DpeEnv<impl caliptra_dpe::dpe_instance::DpeTypes>,
) -> ContextHandle {
    let cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0x42; 48]),
        flags: DeriveContextFlags::empty(),
        tci_type: 0,
        target_locality: LOCALITY,
        svn: 0,
    };
    match cmd.execute(dpe, env, LOCALITY).unwrap() {
        Response::DeriveContext(resp) => resp.handle,
        _ => panic!("Expected DeriveContext, got unexpected response"),
    }
}

#[test]
fn destroy_makes_handle_invalid() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_child(&mut dpe, &mut env);

    // Destroy the context.
    let destroy = DestroyCtxCmd { handle: child };
    let result = destroy.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "Destroy should succeed: {:?}", result.err());

    // Signing with the destroyed handle should fail.
    let sign_cmd = SignP384Cmd {
        handle: child,
        label: [0; 48],
        flags: SignFlags::empty(),
        digest: [0xBB; 48],
    };
    assert!(
        sign_cmd.execute(&mut dpe, &mut env, LOCALITY).is_err(),
        "Destroyed handle should be invalid for signing"
    );
}

#[test]
fn destroy_frees_slot() {
    CfiCounter::reset_for_test();
    let support = Support::AUTO_INIT | Support::SIMULATION;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    let child = derive_child(&mut dpe, &mut env);

    // Destroy the child context.
    DestroyCtxCmd { handle: child }
        .execute(&mut dpe, &mut env, LOCALITY)
        .unwrap();

    // After destroying, we should be able to create a new simulation context.
    let result = InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, LOCALITY);
    assert!(
        result.is_ok(),
        "Should be able to init after destroy frees slot: {:?}",
        result.err()
    );
}

#[test]
fn destroy_invalid_handle_fails() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let bad_handle = ContextHandle([0xDE; 16]);
    let destroy = DestroyCtxCmd { handle: bad_handle };
    let result = destroy.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_err(), "Destroying invalid handle should fail");
}

#[test]
fn destroy_twice_fails() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_child(&mut dpe, &mut env);

    // First destroy succeeds.
    DestroyCtxCmd { handle: child }
        .execute(&mut dpe, &mut env, LOCALITY)
        .unwrap();

    // Second destroy with same handle should fail.
    let result = DestroyCtxCmd { handle: child }.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_err(), "Second destroy of same handle should fail");
}

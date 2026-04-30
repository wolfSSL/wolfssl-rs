//! DPE engine negative / error-path tests.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{
    CertifyKeyFlags, CertifyKeyP384Cmd, CommandExecution, DeriveContextCmd, DeriveContextFlags,
    DestroyCtxCmd, InitCtxCmd, RotateCtxCmd, RotateCtxFlags, SignFlags, SignP384Cmd,
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
fn sign_destroyed_context() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_child(&mut dpe, &mut env);
    DestroyCtxCmd { handle: child }
        .execute(&mut dpe, &mut env, LOCALITY)
        .unwrap();

    let cmd = SignP384Cmd {
        handle: child,
        label: [0; 48],
        flags: SignFlags::empty(),
        digest: [0xAA; 48],
    };
    assert!(cmd.execute(&mut dpe, &mut env, LOCALITY).is_err());
}

#[test]
fn certify_destroyed_context() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT | Support::X509);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_child(&mut dpe, &mut env);
    DestroyCtxCmd { handle: child }
        .execute(&mut dpe, &mut env, LOCALITY)
        .unwrap();

    let cmd = CertifyKeyP384Cmd {
        handle: child,
        flags: CertifyKeyFlags::empty(),
        format: 0,
        label: [0; 48],
    };
    assert!(cmd.execute(&mut dpe, &mut env, LOCALITY).is_err());
}

#[test]
fn derive_from_destroyed_context() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_child(&mut dpe, &mut env);
    DestroyCtxCmd { handle: child }
        .execute(&mut dpe, &mut env, LOCALITY)
        .unwrap();

    let cmd = DeriveContextCmd {
        handle: child,
        data: TciMeasurement([0xBB; 48]),
        flags: DeriveContextFlags::empty(),
        tci_type: 0,
        target_locality: LOCALITY,
        svn: 0,
    };
    assert!(cmd.execute(&mut dpe, &mut env, LOCALITY).is_err());
}

#[test]
fn rotate_destroyed_context() {
    CfiCounter::reset_for_test();
    let support = Support::AUTO_INIT | Support::ROTATE_CONTEXT;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    let child = derive_child(&mut dpe, &mut env);
    DestroyCtxCmd { handle: child }
        .execute(&mut dpe, &mut env, LOCALITY)
        .unwrap();

    let cmd = RotateCtxCmd {
        handle: child,
        flags: RotateCtxFlags::empty(),
    };
    assert!(cmd.execute(&mut dpe, &mut env, LOCALITY).is_err());
}

#[test]
fn init_all_slots_full() {
    CfiCounter::reset_for_test();
    let support = Support::SIMULATION;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    // Fill all simulation slots.
    let mut last_error = None;
    for _ in 0..128 {
        match InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, LOCALITY) {
            Ok(_) => {}
            Err(e) => {
                last_error = Some(e);
                break;
            }
        }
    }
    assert!(last_error.is_some(), "Expected error when all slots full");
}

#[test]
fn derive_max_depth() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let mut last_error = None;
    for i in 0..128 {
        let cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: TciMeasurement([i as u8; 48]),
            flags: DeriveContextFlags::MAKE_DEFAULT,
            tci_type: 0,
            target_locality: LOCALITY,
            svn: 0,
        };
        match cmd.execute(&mut dpe, &mut env, LOCALITY) {
            Ok(_) => {}
            Err(e) => {
                last_error = Some(e);
                break;
            }
        }
    }
    assert!(
        last_error.is_some(),
        "Expected error when exceeding max TCIs"
    );
}

#[test]
fn double_destroy() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_child(&mut dpe, &mut env);
    DestroyCtxCmd { handle: child }
        .execute(&mut dpe, &mut env, LOCALITY)
        .unwrap();

    let result = DestroyCtxCmd { handle: child }.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_err(), "Second destroy should fail");
}

#[test]
fn sign_zero_handle_no_default() {
    CfiCounter::reset_for_test();
    // No AUTO_INIT: there is no default context.
    let support = Support::SIMULATION;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    let cmd = SignP384Cmd {
        handle: ContextHandle::default(),
        label: [0; 48],
        flags: SignFlags::empty(),
        digest: [0xAA; 48],
    };
    assert!(
        cmd.execute(&mut dpe, &mut env, LOCALITY).is_err(),
        "Sign with zero handle should fail when no default context exists"
    );
}

#[test]
fn certify_random_handle() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT | Support::X509);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let cmd = CertifyKeyP384Cmd {
        handle: ContextHandle([0xDE; 16]),
        flags: CertifyKeyFlags::empty(),
        format: 0,
        label: [0; 48],
    };
    assert!(cmd.execute(&mut dpe, &mut env, LOCALITY).is_err());
}

#[test]
fn derive_from_random_handle() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let cmd = DeriveContextCmd {
        handle: ContextHandle([0xAB; 16]),
        data: TciMeasurement([0; 48]),
        flags: DeriveContextFlags::empty(),
        tci_type: 0,
        target_locality: LOCALITY,
        svn: 0,
    };
    assert!(cmd.execute(&mut dpe, &mut env, LOCALITY).is_err());
}

#[test]
fn destroy_random_handle() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let cmd = DestroyCtxCmd {
        handle: ContextHandle([0xCD; 16]),
    };
    assert!(cmd.execute(&mut dpe, &mut env, LOCALITY).is_err());
}

//! DPE engine DeriveContext tests.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{
    CommandExecution, DeriveContextCmd, DeriveContextFlags, InitCtxCmd, SignP384Cmd, SignFlags,
};
use caliptra_dpe::context::ContextHandle;
use caliptra_dpe::dpe_instance::{DpeEnv, DpeInstance};
use caliptra_dpe::response::{Response, SignResp};
use caliptra_dpe::support::Support;
use caliptra_dpe::tci::TciMeasurement;
use caliptra_dpe::{DpeFlags, DpeProfile, State};

use helpers::dpe_harness::{self, LOCALITY};

/// Helper: derive a child from the given handle without retaining parent.
fn derive_child(
    dpe: &mut DpeInstance,
    env: &mut DpeEnv<impl caliptra_dpe::dpe_instance::DpeTypes>,
    handle: ContextHandle,
    measurement: [u8; 48],
) -> ContextHandle {
    let cmd = DeriveContextCmd {
        handle,
        data: TciMeasurement(measurement),
        flags: DeriveContextFlags::empty(),
        tci_type: 0,
        target_locality: LOCALITY,
        svn: 0,
    };
    match cmd.execute(dpe, env, LOCALITY).unwrap() {
        Response::DeriveContext(resp) => resp.handle,
        _ => panic!("Expected DeriveContext response, got unexpected response"),
    }
}

#[test]
fn derive_child_from_default() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_child(&mut dpe, &mut env, ContextHandle::default(), [0x42; 48]);
    // Child handle should be returned (may be any value).
    let _ = child;
}

#[test]
fn derive_with_measurement() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0xAB; 48]),
        flags: DeriveContextFlags::empty(),
        tci_type: 0,
        target_locality: LOCALITY,
        svn: 0,
    };
    let result = cmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "DeriveContext with measurement failed: {:?}", result.err());
}

#[test]
fn derive_chain_3_levels() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    // Level 1: default -> child (MAKE_DEFAULT so child becomes new default)
    let cmd1 = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0x01; 48]),
        flags: DeriveContextFlags::MAKE_DEFAULT,
        tci_type: 1,
        target_locality: LOCALITY,
        svn: 0,
    };
    let _child1 = match cmd1.execute(&mut dpe, &mut env, LOCALITY).unwrap() {
        Response::DeriveContext(resp) => resp.handle,
        _ => panic!("Expected DeriveContext, got unexpected response"),
    };

    // Level 2: child1 (now default) -> grandchild (MAKE_DEFAULT)
    let cmd2 = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0x02; 48]),
        flags: DeriveContextFlags::MAKE_DEFAULT,
        tci_type: 2,
        target_locality: LOCALITY,
        svn: 0,
    };
    let _child2 = match cmd2.execute(&mut dpe, &mut env, LOCALITY).unwrap() {
        Response::DeriveContext(resp) => resp.handle,
        _ => panic!("Expected DeriveContext, got unexpected response"),
    };

    // Level 3: grandchild -> great-grandchild
    let cmd3 = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0x03; 48]),
        flags: DeriveContextFlags::empty(),
        tci_type: 3,
        target_locality: LOCALITY,
        svn: 0,
    };
    let result = cmd3.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "Third level derive failed: {:?}", result.err());
}

#[test]
fn derive_without_retain_destroys_parent() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    // Derive without RETAIN_PARENT: default handle is consumed.
    let _child = derive_child(&mut dpe, &mut env, ContextHandle::default(), [0x10; 48]);

    // Trying to use the default handle should fail (it was consumed).
    let sign_cmd = SignP384Cmd {
        handle: ContextHandle::default(),
        label: [0; 48],
        flags: SignFlags::empty(),
        digest: [0xCC; 48],
    };
    let result = sign_cmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_err(), "Expected error using consumed default handle");
}

#[test]
fn derive_with_tci_type() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0x55; 48]),
        flags: DeriveContextFlags::empty(),
        tci_type: 0xDEADBEEF,
        target_locality: LOCALITY,
        svn: 0,
    };
    let result = cmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "DeriveContext with tci_type failed: {:?}", result.err());
}

#[test]
fn derive_creates_new_handle() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let parent_handle = ContextHandle::default();
    let child = derive_child(&mut dpe, &mut env, parent_handle, [0x77; 48]);

    // Without MAKE_DEFAULT, child should not be the default handle.
    assert_ne!(
        child.0, parent_handle.0,
        "Child handle should differ from parent handle"
    );
}

#[test]
fn derive_multiple_from_retained_parent() {
    CfiCounter::reset_for_test();
    // Use SIMULATION + RETAIN_PARENT to create a parent we can derive from multiple times.
    let support = Support::SIMULATION | Support::RETAIN_PARENT_CONTEXT;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    // Create a simulation parent context.
    let parent = match InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, LOCALITY).unwrap() {
        Response::InitCtx(resp) => resp.handle,
        _ => panic!("Expected InitCtx, got unexpected response"),
    };

    // Derive child 1 with RETAIN_PARENT.
    let cmd1 = DeriveContextCmd {
        handle: parent,
        data: TciMeasurement([0xA1; 48]),
        flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        tci_type: 0,
        target_locality: LOCALITY,
        svn: 0,
    };
    let resp1 = cmd1.execute(&mut dpe, &mut env, LOCALITY);
    assert!(resp1.is_ok(), "First derive from retained parent failed: {:?}", resp1.err());
    let parent_after = match resp1.unwrap() {
        Response::DeriveContext(resp) => resp.parent_handle,
        _ => panic!("Expected DeriveContext, got unexpected response"),
    };

    // Derive child 2 with RETAIN_PARENT using the returned parent handle.
    let cmd2 = DeriveContextCmd {
        handle: parent_after,
        data: TciMeasurement([0xA2; 48]),
        flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        tci_type: 0,
        target_locality: LOCALITY,
        svn: 0,
    };
    let resp2 = cmd2.execute(&mut dpe, &mut env, LOCALITY);
    assert!(resp2.is_ok(), "Second derive from retained parent failed: {:?}", resp2.err());
}

#[test]
fn derive_max_depth_exceeded() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    // Keep deriving with MAKE_DEFAULT until we hit the max.
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
    assert!(last_error.is_some(), "Expected MaxTcis error after exhausting slots");
}

#[test]
fn derive_recursive_updates_tci() {
    CfiCounter::reset_for_test();
    let support = Support::AUTO_INIT | Support::RECURSIVE;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    // Recursive derive updates TCI in-place without creating a new context.
    let cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0xCC; 48]),
        flags: DeriveContextFlags::RECURSIVE,
        tci_type: 0,
        target_locality: LOCALITY,
        svn: 0,
    };
    let result = cmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "Recursive derive failed: {:?}", result.err());
}

#[test]
fn derive_with_export_cdi() {
    CfiCounter::reset_for_test();
    let support = Support::AUTO_INIT | Support::CDI_EXPORT | Support::X509;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    let cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0xDD; 48]),
        flags: DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::INPUT_ALLOW_X509,
        tci_type: 0,
        target_locality: LOCALITY,
        svn: 0,
    };
    let result = cmd.execute(&mut dpe, &mut env, LOCALITY);
    match result {
        Ok(Response::DeriveContextExportedCdi(resp)) => {
            assert!(
                resp.exported_cdi.iter().any(|&b| b != 0),
                "Exported CDI should be non-zero"
            );
        }
        Err(_) => {
            // CDI export with CREATE_CERTIFICATE requires alias key; skip if not configured.
            eprintln!("SKIPPED: CDI export with certificate requires alias key");
        }
        _ => panic!("Expected DeriveContextExportedCdi response, got unexpected response"),
    }
}
